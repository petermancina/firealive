// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GD Push Signing Keys Service
//
// Manages the Ed25519 keypair this MC uses to sign every outbound push to
// its connected GD. Public keys are stored plaintext (the GD needs to
// verify with them; no confidentiality concern); private keys are Tier-1
// AES-256-GCM-encrypted via encryptConfig and decrypted just-in-time
// only when the gd-push-signer service needs to sign a request. The raw
// private key is never cached at module scope — every signing operation
// decrypts from the DB.
//
// DELIBERATELY SEPARATE FROM chain-signing-keys.js AND backup-signing-keys.js
//
// The MC-to-GD trust channel is a distinct cryptographic concern from
// backup integrity and chain audit. A compromise of the GD-push key
// MUST NOT compromise backup signatures or chain entries. The three
// services share no state, no in-memory KeyObject instances, no DB
// tables. They are intentional duplicates (~150 lines of boilerplate
// each) — the security separation justifies the duplication. Same
// rationale as the chain vs backup signing-key separation in R3d-2.
//
// All three services use the SAME Tier-1 KEK (TIER1_ENCRYPTION_KEY) for
// at-rest encryption of private keys. Cryptographic key separation comes
// from the Ed25519 keypairs being distinct, not from at-rest key
// separation.
//
// Schema lives in db/init.js -> gd_push_signing_keys table. Same
// rotation model as chain_signing_keys / backup_signing_keys: one
// active keypair at a time (is_active = 1), old keypairs retained with
// is_active = 0 + rotated_out_at so a brief verification grace window
// exists across rotations.
//
// FINGERPRINTS
//
// Each key row carries a public_key_fingerprint — SHA-256 hex of the
// SPKI DER bytes, lowercase, 64 chars. Same format as
// backup_signing_keys.public_key_fingerprint. Used as the
// X-FA-Key-Fingerprint header value on every outbound push so the GD
// can resolve which row in its signing_keys trust registry to verify
// against.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { encryptConfig, decryptConfig } = require('./encryption');

// ── Keypair generation + fingerprint ──────────────────────────────────────

/**
 * Generate a fresh Ed25519 keypair. Returns:
 *   {
 *     publicKeyPem:           string  (PEM-encoded SPKI, safe to store plaintext)
 *     privateKeyPem:          string  (PEM-encoded PKCS#8, MUST be encrypted before storage)
 *     publicKeyFingerprint:   string  (SHA-256 hex of SPKI DER bytes, 64 chars)
 *   }
 *
 * Ed25519 key sizes are fixed: public 32 bytes raw, private 32 bytes raw.
 * PEM wrapping adds the SPKI/PKCS8 envelope plus base64 + header lines.
 * The fingerprint hashes the DER bytes (not the PEM text) so it's stable
 * across deployments regardless of PEM whitespace or line-ending quirks.
 */
function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKeyFingerprint = computePublicKeyFingerprint(publicKeyPem);
  return { publicKeyPem, privateKeyPem, publicKeyFingerprint };
}

/**
 * computePublicKeyFingerprint(publicKeyPem)
 *
 * Compute the universal content-addressed identifier for a public key:
 * SHA-256 hex of the SPKI DER bytes. 64 hex chars (lowercase). Stable
 * across deployments and across PEM normalization (line endings, trailing
 * newlines, header whitespace) because it hashes the DER, not the PEM.
 *
 * Same format as backup-signing-keys.computePublicKeyFingerprint so an
 * operator can grep across MC and GD logs for a single fingerprint and
 * see the full key history (registration, rotation, verification events)
 * across both sides of the trust channel.
 *
 * Throws if the PEM doesn't parse — callers should pre-validate or
 * catch.
 */
function computePublicKeyFingerprint(publicKeyPem) {
  if (typeof publicKeyPem !== 'string' || !publicKeyPem.trim()) {
    throw new Error('computePublicKeyFingerprint: publicKeyPem must be a non-empty string');
  }
  let keyObj;
  try {
    keyObj = crypto.createPublicKey(publicKeyPem);
  } catch (err) {
    throw new Error(`computePublicKeyFingerprint: failed to parse public key PEM: ${err.message}`);
  }
  const der = keyObj.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// ── DB-level helpers (private) ────────────────────────────────────────────

function getActiveRow(db) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, private_key_encrypted,
           is_active, created_at
    FROM gd_push_signing_keys
    WHERE is_active = 1
    LIMIT 1
  `).get();
}

function getRowById(db, id) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, is_active,
           created_at, rotated_out_at, notes
    FROM gd_push_signing_keys
    WHERE id = ?
  `).get(id);
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * ensureActivePushKeypair(db)
 *
 * Boot-time idempotent helper. If no row in gd_push_signing_keys has
 * is_active = 1, generate a fresh Ed25519 keypair and insert it.
 * Returns the active row's { id, publicKeyPem, publicKeyFingerprint,
 * isNewlyCreated }.
 *
 * Safe to call on every server start. Called from db/init.js initDb()
 * after the schema exec, alongside the equivalent boot helpers from
 * chain-signing-keys.js and backup-signing-keys.js.
 *
 * The keypair is generated lazily — only when the MC first decides it
 * needs to sign pushes. Most installs that never configure GD-push will
 * never generate this keypair; the table stays empty.
 */
function ensureActivePushKeypair(db) {
  const existing = getActiveRow(db);
  if (existing) {
    return {
      id: existing.id,
      publicKeyPem: existing.public_key,
      publicKeyFingerprint: existing.public_key_fingerprint,
      isNewlyCreated: false,
    };
  }

  const { publicKeyPem, privateKeyPem, publicKeyFingerprint } = generateKeypair();
  const privateKeyEncrypted = encryptConfig({ pem: privateKeyPem });

  const result = db.prepare(`
    INSERT INTO gd_push_signing_keys
      (public_key, public_key_fingerprint, private_key_encrypted,
       is_active, notes)
    VALUES (?, ?, ?, 1, 'auto-generated on first GD-push setup')
  `).run(publicKeyPem, publicKeyFingerprint, privateKeyEncrypted);

  return {
    id: result.lastInsertRowid,
    publicKeyPem,
    publicKeyFingerprint,
    isNewlyCreated: true,
  };
}

/**
 * getActivePushKey(db)
 *
 * Return everything the gd-push-signer service needs to sign a fresh
 * outbound push. Decrypts the private key just-in-time. The KeyObject
 * returned for privateKey can be passed directly to crypto.sign().
 *
 * Throws if no active keypair exists — callers should call
 * ensureActivePushKeypair(db) before the first push (typically as part
 * of the GD-config handshake flow, not at server boot, since most MCs
 * never enable GD-push).
 *
 * Returns: {
 *   id,
 *   publicKey: KeyObject,
 *   privateKey: KeyObject,
 *   publicKeyPem,
 *   publicKeyFingerprint
 * }
 */
function getActivePushKey(db) {
  const row = getActiveRow(db);
  if (!row) {
    throw new Error('no active GD-push signing key exists; call ensureActivePushKeypair(db) before signing');
  }
  const { pem: privateKeyPem } = decryptConfig(row.private_key_encrypted);
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    privateKey: crypto.createPrivateKey(privateKeyPem),
    publicKeyPem: row.public_key,
    publicKeyFingerprint: row.public_key_fingerprint,
  };
}

/**
 * getActiveFingerprint(db)
 *
 * Convenience accessor returning ONLY the active key's fingerprint
 * string — no private-key decrypt, no KeyObject construction. Used by
 * code paths that need to display or log the current key identity
 * without invoking the signer (e.g. the gd-config status endpoint, the
 * admin signing-key inspection UI, audit-log entries about which key
 * was used).
 *
 * Returns the fingerprint string or null if no active key exists.
 */
function getActiveFingerprint(db) {
  const row = db.prepare(`
    SELECT public_key_fingerprint
    FROM gd_push_signing_keys
    WHERE is_active = 1
    LIMIT 1
  `).get();
  return row ? row.public_key_fingerprint : null;
}

/**
 * rotatePushKeypair(db, options)
 *
 * Generate a new keypair, demote the previous active keypair to
 * is_active=0 with rotated_out_at = now, insert the new keypair as
 * is_active=1.
 *
 * Atomic — wrapped in a SQLite transaction so the rotation either fully
 * succeeds or leaves the existing active key in place.
 *
 * After rotation, the MC must register the new public key with its GD
 * before the next push will verify (POST /api/mc/:id/signing-key,
 * exercised by the handshake flow added in Commit 13). The caller is
 * responsible for the handshake; this function only manages local
 * state.
 *
 * options:
 *   notes (string, optional) — stored in the new row's notes column
 *
 * Returns: {
 *   newId,
 *   newPublicKeyPem,
 *   newPublicKeyFingerprint,
 *   oldId | null,
 *   oldPublicKeyFingerprint | null
 * }
 */
function rotatePushKeypair(db, options = {}) {
  const { notes = 'rotation' } = options;

  return db.transaction(() => {
    const old = getActiveRow(db);

    // Demote any existing active key. There SHOULD be at most one;
    // defensively handle the multi-active edge case by demoting all.
    db.prepare(`
      UPDATE gd_push_signing_keys
      SET is_active = 0,
          rotated_out_at = datetime('now')
      WHERE is_active = 1
    `).run();

    const { publicKeyPem, privateKeyPem, publicKeyFingerprint } = generateKeypair();
    const privateKeyEncrypted = encryptConfig({ pem: privateKeyPem });

    const result = db.prepare(`
      INSERT INTO gd_push_signing_keys
        (public_key, public_key_fingerprint, private_key_encrypted,
         is_active, notes)
      VALUES (?, ?, ?, 1, ?)
    `).run(publicKeyPem, publicKeyFingerprint, privateKeyEncrypted, notes);

    return {
      newId: result.lastInsertRowid,
      newPublicKeyPem: publicKeyPem,
      newPublicKeyFingerprint: publicKeyFingerprint,
      oldId: old ? old.id : null,
      oldPublicKeyFingerprint: old ? old.public_key_fingerprint : null,
    };
  })();
}

/**
 * listPushKeys(db)
 *
 * Admin UI listing — returns every keypair's public-side metadata.
 * Never returns private keys (they're not even SELECTed).
 *
 * Returns: array of {
 *   id, publicKeyPem, publicKeyFingerprint, isActive, createdAt,
 *   rotatedOutAt, notes
 * }
 */
function listPushKeys(db) {
  const rows = db.prepare(`
    SELECT
      id,
      public_key,
      public_key_fingerprint,
      is_active,
      created_at,
      rotated_out_at,
      notes
    FROM gd_push_signing_keys
    ORDER BY created_at DESC
  `).all();

  return rows.map(r => ({
    id: r.id,
    publicKeyPem: r.public_key,
    publicKeyFingerprint: r.public_key_fingerprint,
    isActive: r.is_active === 1,
    createdAt: r.created_at,
    rotatedOutAt: r.rotated_out_at,
    notes: r.notes,
  }));
}

module.exports = {
  generateKeypair,
  computePublicKeyFingerprint,
  ensureActivePushKeypair,
  getActivePushKey,
  getActiveFingerprint,
  rotatePushKeypair,
  listPushKeys,
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Chain Signing Keys Service
//
// Manages the Ed25519 keypair used to sign backup_chain entries. Public
// keys are stored plaintext (no confidentiality concern); private keys
// are Tier-1 AES-256-GCM-encrypted via encryptConfig and decrypted
// just-in-time only when the chain service needs to append an entry.
// The raw private key is never cached at module scope -- every signing
// operation decrypts from the DB.
//
// DELIBERATELY SEPARATE FROM backup-signing-keys.js
//
// Chain integrity is a distinct cryptographic concern from backup
// integrity. A compromise of the backup-signing key MUST NOT
// compromise the chain audit trail. The two services share no state,
// no in-memory KeyObject instances, no DB tables. They are intentional
// duplicates (~150 lines of boilerplate) -- the security separation
// justifies the duplication.
//
// Both services use the SAME Tier-1 KEK (TIER1_ENCRYPTION_KEY) for at-
// rest encryption of private keys. Cryptographic key separation comes
// from the Ed25519 keypairs being distinct, not from at-rest key
// separation. R3d-4 introduces true key separation via KMS-managed
// signing keys.
//
// Schema lives in db/init.js -> chain_signing_keys table. Same
// rotation model as backup_signing_keys: one active keypair at a time
// (is_active = 1), old keypairs retained with is_active = 0 +
// rotated_out_at so historical chain entries stay verifiable.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { sealTier1, openTier1 } = require('./tier1-seal');

// ── Keypair generation ────────────────────────────────────────────────────

/**
 * Generate a fresh Ed25519 keypair. Returns:
 *   {
 *     publicKeyPem:   string  (PEM-encoded SPKI, safe to store plaintext)
 *     privateKeyPem:  string  (PEM-encoded PKCS#8, MUST be encrypted before storage)
 *   }
 *
 * Ed25519 key sizes are fixed: public 32 bytes raw, private 32 bytes raw.
 * PEM wrapping adds the SPKI/PKCS8 envelope plus base64 + header lines.
 */
function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  return { publicKeyPem, privateKeyPem };
}

// ── DB-level helpers (private) ────────────────────────────────────────────

function getActiveRow(db) {
  return db.prepare(`
    SELECT id, public_key, private_key_encrypted, is_active, created_at
    FROM chain_signing_keys
    WHERE is_active = 1
    LIMIT 1
  `).get();
}

function getRowById(db, id) {
  return db.prepare(`
    SELECT id, public_key, is_active, created_at, rotated_out_at, notes
    FROM chain_signing_keys
    WHERE id = ?
  `).get(id);
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * ensureActiveChainKeypair(db)
 *
 * Boot-time idempotent helper. If no row in chain_signing_keys has
 * is_active = 1, generate a fresh Ed25519 keypair and insert it.
 * Returns the active row's { id, publicKeyPem, isNewlyCreated }.
 *
 * Safe to call on every server start. Called from db/init.js initDb()
 * after the schema exec, alongside the equivalent boot helper from
 * backup-signing-keys.js.
 */
function ensureActiveChainKeypair(db) {
  const existing = getActiveRow(db);
  if (existing) {
    return {
      id: existing.id,
      publicKeyPem: existing.public_key,
      isNewlyCreated: false,
    };
  }

  const { publicKeyPem, privateKeyPem } = generateKeypair();
  const privateKeyEncrypted = sealTier1('chain_signing_keys.private_key_encrypted', { pem: privateKeyPem });

  const result = db.prepare(`
    INSERT INTO chain_signing_keys
      (public_key, private_key_encrypted, is_active, notes)
    VALUES (?, ?, 1, 'auto-generated at server boot')
  `).run(publicKeyPem, privateKeyEncrypted);

  return {
    id: result.lastInsertRowid,
    publicKeyPem,
    isNewlyCreated: true,
  };
}

/**
 * getActiveChainKey(db)
 *
 * Return everything the chain service needs to sign a fresh entry.
 * Decrypts the private key just-in-time. The KeyObject returned for
 * privateKey can be passed directly to crypto.sign().
 *
 * Throws if no active keypair exists -- callers should call
 * ensureActiveChainKeypair(db) at server boot so this never fires in
 * normal operation.
 *
 * Returns: { id, publicKey: KeyObject, privateKey: KeyObject, publicKeyPem }
 */
function getActiveChainKey(db) {
  const row = getActiveRow(db);
  if (!row) {
    throw new Error('no active chain signing key exists; call ensureActiveChainKeypair(db) at server boot');
  }
  const { pem: privateKeyPem } = openTier1('chain_signing_keys.private_key_encrypted', row.private_key_encrypted);
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    privateKey: crypto.createPrivateKey(privateKeyPem),
    publicKeyPem: row.public_key,
  };
}

/**
 * getChainVerificationKey(db, signingKeyId)
 *
 * Return the public key needed to verify a chain entry signed by
 * signing_key_id. Used by the chain verifier to verify entries
 * regardless of whether the key is currently active or has been
 * rotated out.
 *
 * Public-only -- never decrypts the private key (and never needs to).
 *
 * Returns: { id, publicKey: KeyObject, publicKeyPem, isActive } or null
 * if no key with that id exists.
 */
function getChainVerificationKey(db, signingKeyId) {
  const row = getRowById(db, signingKeyId);
  if (!row) return null;
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    publicKeyPem: row.public_key,
    isActive: row.is_active === 1,
  };
}

/**
 * rotateChainKeypair(db, options)
 *
 * Generate a new keypair, demote the previous active keypair to
 * is_active=0 with rotated_out_at = now, insert the new keypair as
 * is_active=1.
 *
 * Atomic -- wrapped in a SQLite transaction so the rotation either
 * fully succeeds or leaves the existing active key in place.
 *
 * options:
 *   notes (string, optional) - stored in the new row's notes column
 *
 * Returns: { newId, newPublicKeyPem, oldId | null }
 */
function rotateChainKeypair(db, options = {}) {
  const { notes = 'rotation' } = options;

  return db.transaction(() => {
    const old = getActiveRow(db);

    // Demote any existing active key. There SHOULD be at most one;
    // defensively handle the multi-active edge case by demoting all.
    db.prepare(`
      UPDATE chain_signing_keys
      SET is_active = 0,
          rotated_out_at = datetime('now')
      WHERE is_active = 1
    `).run();

    const { publicKeyPem, privateKeyPem } = generateKeypair();
    const privateKeyEncrypted = sealTier1('chain_signing_keys.private_key_encrypted', { pem: privateKeyPem });

    const result = db.prepare(`
      INSERT INTO chain_signing_keys
        (public_key, private_key_encrypted, is_active, notes)
      VALUES (?, ?, 1, ?)
    `).run(publicKeyPem, privateKeyEncrypted, notes);

    return {
      newId: result.lastInsertRowid,
      newPublicKeyPem: publicKeyPem,
      oldId: old ? old.id : null,
    };
  })();
}

/**
 * listChainKeys(db)
 *
 * Admin UI listing -- returns every keypair's public-side metadata.
 * Never returns private keys (they're not even SELECTed).
 *
 * Returns: array of {
 *   id, publicKeyPem, isActive, createdAt, rotatedOutAt, notes,
 *   chainEntriesSignedCount   (count of backup_chain entries that
 *                              reference this key)
 * }
 */
function listChainKeys(db) {
  const rows = db.prepare(`
    SELECT
      csk.id,
      csk.public_key,
      csk.is_active,
      csk.created_at,
      csk.rotated_out_at,
      csk.notes,
      (SELECT COUNT(*) FROM backup_chain WHERE signing_key_id = csk.id) AS chain_entries_signed_count
    FROM chain_signing_keys csk
    ORDER BY csk.created_at DESC
  `).all();

  return rows.map(r => ({
    id: r.id,
    publicKeyPem: r.public_key,
    isActive: r.is_active === 1,
    createdAt: r.created_at,
    rotatedOutAt: r.rotated_out_at,
    notes: r.notes,
    chainEntriesSignedCount: r.chain_entries_signed_count,
  }));
}

// ── Sign / verify wrappers ───────────────────────────────────────────────

/**
 * signChainEntry(db, hashBytes)
 *
 * Sign the given hash bytes (typically the this_hash of a chain entry,
 * computed as SHA-256(prev_hash || canonicalized_payload || created_at))
 * with the current active chain-signing key.
 *
 * Returns: { signature: Buffer, signingKeyId: number }
 *
 * The signature is 64 bytes (Ed25519 fixed size). Caller stores the
 * signature in the backup_chain.signature column (base64-encoded) and
 * records signingKeyId in the row so verification can find the right
 * public key later.
 *
 * NOTE: signs HASH bytes, not the raw payload. The chain commits the
 * payload via prev_hash chaining + the SHA-256 in this_hash. The
 * Ed25519 signature attests to the hash itself -- proving non-
 * repudiation of the chain entry without requiring the verifier to
 * re-canonicalize the payload during signature check.
 */
function signChainEntry(db, hashBytes) {
  if (!Buffer.isBuffer(hashBytes) && typeof hashBytes !== 'string') {
    throw new Error('signChainEntry: hashBytes must be Buffer or string');
  }
  const bytes = Buffer.isBuffer(hashBytes) ? hashBytes : Buffer.from(hashBytes);
  if (bytes.length !== 32) {
    // SHA-256 hashes are always 32 bytes; reject other sizes early.
    throw new Error(`signChainEntry: expected 32-byte SHA-256 hash, got ${bytes.length} bytes`);
  }
  const { id, privateKey } = getActiveChainKey(db);
  const signature = crypto.sign(null, bytes, privateKey);
  return { signature, signingKeyId: id };
}

/**
 * verifyChainEntry(db, hashBytes, signature, signingKeyId)
 *
 * Verify that signature is a valid Ed25519 signature over hashBytes by
 * the keypair identified by signingKeyId.
 *
 * Returns: true if valid; false if the signature is invalid OR the
 * signing key id doesn't exist (treated the same -- caller can't trust
 * a chain entry signed by a key we've never seen).
 *
 * Does NOT throw on signature mismatch -- returns false. Throws only on
 * malformed inputs.
 */
function verifyChainEntry(db, hashBytes, signature, signingKeyId) {
  if (!Buffer.isBuffer(signature)) {
    throw new Error('verifyChainEntry: signature must be a Buffer');
  }
  if (signature.length !== 64) {
    // Ed25519 signatures are always 64 bytes; reject other sizes early.
    return false;
  }
  if (!Buffer.isBuffer(hashBytes) && typeof hashBytes !== 'string') {
    throw new Error('verifyChainEntry: hashBytes must be Buffer or string');
  }
  const bytes = Buffer.isBuffer(hashBytes) ? hashBytes : Buffer.from(hashBytes);
  if (bytes.length !== 32) return false;
  const verKey = getChainVerificationKey(db, signingKeyId);
  if (!verKey) return false;
  return crypto.verify(null, bytes, verKey.publicKey, signature);
}

module.exports = {
  ensureActiveChainKeypair,
  getActiveChainKey,
  getChainVerificationKey,
  rotateChainKeypair,
  listChainKeys,
  signChainEntry,
  verifyChainEntry,
};

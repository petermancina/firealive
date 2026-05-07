// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Signing Keys Service
//
// Manages the Ed25519 keypair used to sign v2 backup manifests. Public keys
// are stored plaintext (no confidentiality concern); private keys are
// Tier-1 AES-256-GCM-encrypted via encryptConfig and decrypted just-in-
// time only when the backup engine needs to sign a fresh manifest. The
// raw private key is never cached at module scope — every signing
// operation decrypts from the DB.
//
// Schema lives in db/init.js -> backup_signing_keys table. See the
// ROTATION MODEL block in init.js for the contract: one active keypair
// at a time (is_active = 1), old keypairs retained with is_active = 0
// + rotated_out_at so historical manifests stay verifiable.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { encryptConfig, decryptConfig } = require('./encryption');

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
    FROM backup_signing_keys
    WHERE is_active = 1
    LIMIT 1
  `).get();
}

function getRowById(db, id) {
  return db.prepare(`
    SELECT id, public_key, is_active, created_at, rotated_out_at, notes
    FROM backup_signing_keys
    WHERE id = ?
  `).get(id);
}

function getRowByIdWithPrivate(db, id) {
  return db.prepare(`
    SELECT id, public_key, private_key_encrypted, is_active, created_at, rotated_out_at, notes
    FROM backup_signing_keys
    WHERE id = ?
  `).get(id);
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * ensureActiveKeypair(db)
 *
 * Boot-time idempotent helper. If no row in backup_signing_keys has
 * is_active = 1, generate a fresh Ed25519 keypair and insert it.
 * Returns the active row's { id, publicKeyPem, isNewlyCreated }.
 *
 * Safe to call on every server start.
 */
function ensureActiveKeypair(db) {
  const existing = getActiveRow(db);
  if (existing) {
    return {
      id: existing.id,
      publicKeyPem: existing.public_key,
      isNewlyCreated: false,
    };
  }

  const { publicKeyPem, privateKeyPem } = generateKeypair();
  const privateKeyEncrypted = encryptConfig({ pem: privateKeyPem });

  const result = db.prepare(`
    INSERT INTO backup_signing_keys
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
 * getActiveSigningKey(db)
 *
 * Return everything the backup engine needs to sign a fresh manifest.
 * Decrypts the private key just-in-time. The KeyObject returned for
 * privateKey can be passed directly to crypto.sign().
 *
 * Throws if no active keypair exists — callers should call
 * ensureActiveKeypair(db) at server start so this never fires in
 * normal operation.
 *
 * Returns: { id, publicKey: KeyObject, privateKey: KeyObject, publicKeyPem }
 */
function getActiveSigningKey(db) {
  const row = getActiveRow(db);
  if (!row) {
    throw new Error('no active backup signing key exists; call ensureActiveKeypair(db) at server boot');
  }
  const { pem: privateKeyPem } = decryptConfig(row.private_key_encrypted);
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    privateKey: crypto.createPrivateKey(privateKeyPem),
    publicKeyPem: row.public_key,
  };
}

/**
 * getVerificationKey(db, signingKeyId)
 *
 * Return the public key needed to verify a manifest signed by signing_key_id.
 * Used by the restore service to verify backups regardless of whether the
 * key is currently active or has been rotated out.
 *
 * Public-only — never decrypts the private key (and never needs to).
 *
 * Returns: { id, publicKey: KeyObject, publicKeyPem, isActive } or null
 * if no key with that id exists.
 */
function getVerificationKey(db, signingKeyId) {
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
 * rotateKeypair(db, options)
 *
 * Generate a new keypair, demote the previous active keypair to is_active=0
 * with rotated_out_at = now, insert the new keypair as is_active=1.
 *
 * Atomic — wrapped in a SQLite transaction so the rotation either fully
 * succeeds or leaves the existing active key in place.
 *
 * options:
 *   notes (string, optional) - stored in the new row's notes column
 *
 * Returns: { newId, newPublicKeyPem, oldId | null }
 */
function rotateKeypair(db, options = {}) {
  const { notes = 'rotation' } = options;

  return db.transaction(() => {
    const old = getActiveRow(db);

    // Demote any existing active key. There SHOULD be at most one;
    // defensively handle the multi-active edge case by demoting all.
    db.prepare(`
      UPDATE backup_signing_keys
      SET is_active = 0,
          rotated_out_at = datetime('now')
      WHERE is_active = 1
    `).run();

    const { publicKeyPem, privateKeyPem } = generateKeypair();
    const privateKeyEncrypted = encryptConfig({ pem: privateKeyPem });

    const result = db.prepare(`
      INSERT INTO backup_signing_keys
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
 * listKeys(db)
 *
 * Admin UI listing — returns every keypair's public-side metadata.
 * Never returns private keys (they're not even SELECTed).
 *
 * Returns: array of {
 *   id, publicKeyPem, isActive, createdAt, rotatedOutAt, notes,
 *   backupsSignedCount   (count of backups in the backups table that
 *                         reference this key)
 * }
 */
function listKeys(db) {
  const rows = db.prepare(`
    SELECT
      bsk.id,
      bsk.public_key,
      bsk.is_active,
      bsk.created_at,
      bsk.rotated_out_at,
      bsk.notes,
      (SELECT COUNT(*) FROM backups WHERE signing_key_id = bsk.id) AS backups_signed_count
    FROM backup_signing_keys bsk
    ORDER BY bsk.created_at DESC
  `).all();

  return rows.map(r => ({
    id: r.id,
    publicKeyPem: r.public_key,
    isActive: r.is_active === 1,
    createdAt: r.created_at,
    rotatedOutAt: r.rotated_out_at,
    notes: r.notes,
    backupsSignedCount: r.backups_signed_count,
  }));
}

// ── Sign / verify wrappers ───────────────────────────────────────────────

/**
 * signManifest(db, manifestBytes)
 *
 * Sign the given manifest bytes (typically the canonical JSON serialization
 * of a manifest object) with the current active signing key.
 *
 * Returns: { signature: Buffer, signingKeyId: number }
 *
 * The signature is 64 bytes (Ed25519 fixed size). Caller is responsible
 * for storing the signature alongside the manifest and recording
 * signingKeyId in the backups row so verification can find the right
 * public key later.
 */
function signManifest(db, manifestBytes) {
  if (!Buffer.isBuffer(manifestBytes) && typeof manifestBytes !== 'string') {
    throw new Error('signManifest: manifestBytes must be Buffer or string');
  }
  const { id, privateKey } = getActiveSigningKey(db);
  const signature = crypto.sign(null, Buffer.isBuffer(manifestBytes) ? manifestBytes : Buffer.from(manifestBytes), privateKey);
  return { signature, signingKeyId: id };
}

/**
 * verifyManifest(db, manifestBytes, signature, signingKeyId)
 *
 * Verify that signature is a valid Ed25519 signature over manifestBytes
 * by the keypair identified by signingKeyId.
 *
 * Returns: true if valid; false if the signature is invalid OR the
 * signing key id doesn't exist (treated the same — caller can't trust
 * a manifest signed by a key we've never seen).
 *
 * Does NOT throw on signature mismatch — returns false. Throws only on
 * malformed inputs.
 */
function verifyManifest(db, manifestBytes, signature, signingKeyId) {
  if (!Buffer.isBuffer(signature)) {
    throw new Error('verifyManifest: signature must be a Buffer');
  }
  if (signature.length !== 64) {
    // Ed25519 signatures are always 64 bytes; reject other sizes early.
    return false;
  }
  const verKey = getVerificationKey(db, signingKeyId);
  if (!verKey) return false;
  const bytes = Buffer.isBuffer(manifestBytes) ? manifestBytes : Buffer.from(manifestBytes);
  return crypto.verify(null, bytes, verKey.publicKey, signature);
}

module.exports = {
  ensureActiveKeypair,
  getActiveSigningKey,
  getVerificationKey,
  rotateKeypair,
  listKeys,
  signManifest,
  verifyManifest,
};

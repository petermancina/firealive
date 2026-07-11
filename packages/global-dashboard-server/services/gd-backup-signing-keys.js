// =============================================================================
// FIREALIVE GD -- Backup Signing Keys Service
//
// The dedicated GD backup Ed25519 signing family. Separate from the GD's
// archive-chain, audit-chain, report, and MC-trust key families -- this family
// signs v3 backup manifests AND the backup attestation chain. Twins the Regional
// backup-signing-keys service. Because the GD is new (no v2-legacy backups ever
// existed), keys are fingerprint-addressed from the start; there is no v2 id-only
// fallback to migrate.
//
// Two categories of Ed25519 keys live in backup_signing_keys, distinguished by
// the key_origin column:
//
//   key_origin = 'local-generated'
//       This deployment's own keypair, used to sign backup manifests and chain
//       entries created here. Public key stored plaintext; private key GD Tier-1
//       AES-256-GCM-wrapped via gd-encryption and decrypted just-in-time only
//       when signing. The raw private key is never cached at module scope.
//       Rotated via rotateKeypair(); old rows retained with is_active=0 and
//       rotated_out_at set so historical manifests stay verifiable.
//
//   key_origin = 'external-registered'
//       A foreign deployment's public key, registered by an admin so that
//       backups created by that deployment can be cross-verified here for
//       cross-deployment external restore. Verification-only -- never active,
//       never holds a private key. Revoked by setting rotated_out_at; revoked
//       external keys are filtered out of the verification helpers (a revoked
//       key MUST NOT verify a manifest).
//
// Each key row carries a public_key_fingerprint -- SHA-256 hex of the SPKI DER
// bytes -- the universal cross-deployment identifier embedded in v3 manifests
// and chain entries.
// =============================================================================

const crypto = require('crypto');
const { sealTier1, openTier1 } = require('./gd-tier1-seal');

// -- Typed errors -------------------------------------------------------------

const CODES = {
  INVALID_PEM: 'INVALID_PEM',
  WRONG_KEY_TYPE: 'WRONG_KEY_TYPE',
  WRONG_KEY_USAGE: 'WRONG_KEY_USAGE',
  DUPLICATE_FINGERPRINT: 'DUPLICATE_FINGERPRINT',
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  NOT_EXTERNAL_KEY: 'NOT_EXTERNAL_KEY',
  ALREADY_REVOKED: 'ALREADY_REVOKED',
  INVALID_INPUT: 'INVALID_INPUT',
};

class SigningKeyError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'SigningKeyError';
    this.code = code;
    this.details = details;
  }
}

// -- Keypair generation + fingerprint -----------------------------------------

/**
 * Generate a fresh Ed25519 keypair. Returns { publicKeyPem (SPKI, plaintext-safe),
 * privateKeyPem (PKCS#8, MUST be wrapped before storage), publicKeyFingerprint
 * (SHA-256 hex of SPKI DER bytes, 64 chars) }. The fingerprint hashes the DER,
 * not the PEM, so it is stable across deployments regardless of PEM whitespace.
 */
function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKeyFingerprint = computePublicKeyFingerprint(publicKeyPem);
  return { publicKeyPem, privateKeyPem, publicKeyFingerprint };
}

/**
 * Compute the content-addressed identifier for a public key: SHA-256 hex of the
 * SPKI DER bytes (64 lowercase hex chars). Throws SigningKeyError(INVALID_PEM)
 * if the PEM doesn't parse.
 */
function computePublicKeyFingerprint(publicKeyPem) {
  if (typeof publicKeyPem !== 'string' || !publicKeyPem.trim()) {
    throw new SigningKeyError(CODES.INVALID_PEM, 'publicKeyPem must be a non-empty string');
  }
  let keyObj;
  try {
    keyObj = crypto.createPublicKey(publicKeyPem);
  } catch (err) {
    throw new SigningKeyError(CODES.INVALID_PEM, `failed to parse public key PEM: ${err.message}`);
  }
  const der = keyObj.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

/**
 * Parse and sanity-check a foreign deployment's public key before accepting it
 * for registration. Enforces: parses as SPKI, is Ed25519, is a public key (not a
 * private-key paste). Returns { publicKeyPem (canonicalized), publicKeyFingerprint }.
 * Throws SigningKeyError on any validation failure.
 */
function validateExternalPublicKey(pem) {
  if (typeof pem !== 'string' || !pem.trim()) {
    throw new SigningKeyError(CODES.INVALID_PEM, 'public key PEM must be a non-empty string');
  }
  // Explicit private-key-paste guard (a GD hardening beyond the type check
  // below): crypto.createPublicKey() silently DERIVES the public key from a
  // private-key PEM, so the keyObj.type check alone cannot catch an operator
  // pasting a private key. Reject a PEM that carries a PRIVATE KEY header up
  // front so registration never quietly accepts private-key material.
  if (/-----BEGIN[A-Z ]*PRIVATE KEY-----/.test(pem)) {
    throw new SigningKeyError(
      CODES.WRONG_KEY_USAGE,
      'expected a public key, but a private key PEM was provided; paste only the SPKI public key',
    );
  }
  let keyObj;
  try {
    keyObj = crypto.createPublicKey(pem);
  } catch (err) {
    throw new SigningKeyError(CODES.INVALID_PEM, `failed to parse public key PEM: ${err.message}`);
  }
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new SigningKeyError(
      CODES.WRONG_KEY_TYPE,
      `expected Ed25519 public key, got ${keyObj.asymmetricKeyType || 'unknown'}`,
    );
  }
  if (keyObj.type !== 'public') {
    throw new SigningKeyError(
      CODES.WRONG_KEY_USAGE,
      `expected a public key, got ${keyObj.type}`,
    );
  }
  const canonicalPem = keyObj.export({ type: 'spki', format: 'pem' });
  const der = keyObj.export({ type: 'spki', format: 'der' });
  const publicKeyFingerprint = crypto.createHash('sha256').update(der).digest('hex');
  return { publicKeyPem: canonicalPem, publicKeyFingerprint };
}

// -- DB-level helpers (private) -----------------------------------------------

function getActiveRow(db) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, private_key_encrypted,
           is_active, key_origin, created_at
    FROM backup_signing_keys
    WHERE is_active = 1
    LIMIT 1
  `).get();
}

function getRowById(db, id) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, is_active, key_origin,
           registered_by_user_id, registered_at, key_label,
           created_at, rotated_out_at, notes
    FROM backup_signing_keys
    WHERE id = ?
  `).get(id);
}

function getRowByFingerprint(db, fingerprint) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, is_active, key_origin,
           registered_by_user_id, registered_at, key_label,
           created_at, rotated_out_at, notes
    FROM backup_signing_keys
    WHERE public_key_fingerprint = ? AND public_key_fingerprint IS NOT NULL
    ORDER BY id ASC
    LIMIT 1
  `).get(fingerprint);
}

// -- Public API ---------------------------------------------------------------

/**
 * Boot-time idempotent helper. If no row has is_active=1, generate a fresh
 * Ed25519 keypair and insert it. Returns { id, publicKeyPem, publicKeyFingerprint,
 * isNewlyCreated }. Safe to call on every server start.
 */
function ensureActiveKeypair(db) {
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
  const privateKeyEncrypted = sealTier1('backup_signing_keys.private_key_encrypted', { pem: privateKeyPem });

  const result = db.prepare(`
    INSERT INTO backup_signing_keys
      (public_key, public_key_fingerprint, private_key_encrypted,
       is_active, key_origin, notes)
    VALUES (?, ?, ?, 1, 'local-generated', 'auto-generated at server boot')
  `).run(publicKeyPem, publicKeyFingerprint, privateKeyEncrypted);

  return {
    id: result.lastInsertRowid,
    publicKeyPem,
    publicKeyFingerprint,
    isNewlyCreated: true,
  };
}

/**
 * Return everything the backup engine needs to sign a fresh manifest. Decrypts
 * the private key just-in-time. Throws if no active keypair exists, if the active
 * row isn't local-generated, or if it has no private_key_encrypted.
 *
 * Returns { id, publicKey (KeyObject), privateKey (KeyObject), publicKeyPem,
 * publicKeyFingerprint }.
 */
function getActiveSigningKey(db) {
  const row = getActiveRow(db);
  if (!row) {
    throw new Error('no active backup signing key exists; call ensureActiveKeypair(db) at server boot');
  }
  if (row.key_origin !== 'local-generated') {
    throw new Error(`active backup signing key is not local-generated (origin=${row.key_origin}); refusing to use for signing`);
  }
  if (!row.private_key_encrypted) {
    throw new Error('active local-generated signing key has no private_key_encrypted (database inconsistency)');
  }
  const { pem: privateKeyPem } = openTier1('backup_signing_keys.private_key_encrypted', row.private_key_encrypted);
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    privateKey: crypto.createPrivateKey(privateKeyPem),
    publicKeyPem: row.public_key,
    publicKeyFingerprint: row.public_key_fingerprint,
  };
}

/**
 * Return the public key needed to verify a manifest signed by signingKeyId.
 * Public-only. Returns null if no key with that id exists, or if the key is an
 * external-registered key that has been revoked (revoked external keys MUST NOT
 * verify). Rotated-out local keys are still returned so old backups stay
 * verifiable.
 *
 * Returns { id, publicKey (KeyObject), publicKeyPem, publicKeyFingerprint,
 * isActive, keyOrigin, rotatedOutAt } or null.
 */
function getVerificationKey(db, signingKeyId) {
  const row = getRowById(db, signingKeyId);
  if (!row) return null;
  if (row.key_origin === 'external-registered' && row.rotated_out_at) {
    return null;
  }
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    publicKeyPem: row.public_key,
    publicKeyFingerprint: row.public_key_fingerprint,
    isActive: row.is_active === 1,
    keyOrigin: row.key_origin,
    rotatedOutAt: row.rotated_out_at,
  };
}

/**
 * Return the verification key matching a content-addressed fingerprint -- the
 * lookup path for v3 manifests and chain entries. Works across deployments
 * because the fingerprint is a property of the public key bytes. Same revocation
 * semantics as getVerificationKey. Returns null on an invalid fingerprint, no
 * match, or a revoked external key.
 */
function getVerificationKeyByFingerprint(db, fingerprint) {
  if (typeof fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(fingerprint)) {
    return null;
  }
  const row = getRowByFingerprint(db, fingerprint);
  if (!row) return null;
  if (row.key_origin === 'external-registered' && row.rotated_out_at) {
    return null;
  }
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    publicKeyPem: row.public_key,
    publicKeyFingerprint: row.public_key_fingerprint,
    isActive: row.is_active === 1,
    keyOrigin: row.key_origin,
    rotatedOutAt: row.rotated_out_at,
  };
}

/**
 * Generate a new local-generated keypair, demote the previous active local
 * keypair to is_active=0 with rotated_out_at=now, insert the new keypair as
 * is_active=1. Atomic (SQLite transaction). External-registered rows are always
 * inactive (CHECK-enforced) and never rotated.
 *
 * Returns { newId, newPublicKeyPem, newPublicKeyFingerprint, oldId | null }.
 */
function rotateKeypair(db, options = {}) {
  const { notes = 'rotation' } = options;

  return db.transaction(() => {
    const old = getActiveRow(db);

    // Demote any existing active key. The CHECK constraint prevents
    // external-registered rows from being active, so no key_origin filter is
    // needed here.
    db.prepare(`
      UPDATE backup_signing_keys
      SET is_active = 0,
          rotated_out_at = datetime('now')
      WHERE is_active = 1
    `).run();

    const { publicKeyPem, privateKeyPem, publicKeyFingerprint } = generateKeypair();
    const privateKeyEncrypted = sealTier1('backup_signing_keys.private_key_encrypted', { pem: privateKeyPem });

    const result = db.prepare(`
      INSERT INTO backup_signing_keys
        (public_key, public_key_fingerprint, private_key_encrypted,
         is_active, key_origin, notes)
      VALUES (?, ?, ?, 1, 'local-generated', ?)
    `).run(publicKeyPem, publicKeyFingerprint, privateKeyEncrypted, notes);

    return {
      newId: result.lastInsertRowid,
      newPublicKeyPem: publicKeyPem,
      newPublicKeyFingerprint: publicKeyFingerprint,
      oldId: old ? old.id : null,
    };
  })();
}

/**
 * Register a foreign deployment's Ed25519 public key for verification of
 * cross-deployment external-restore backups. Inserts key_origin='external-registered',
 * is_active=0, private_key_encrypted=NULL, plus registration metadata.
 *
 * args: publicKeyPem (required), registeredByUserId (required), keyLabel
 * (optional), notes (optional). Returns { id, publicKeyFingerprint, registeredAt }.
 * Throws SigningKeyError (INVALID_PEM / WRONG_KEY_TYPE / WRONG_KEY_USAGE /
 * DUPLICATE_FINGERPRINT / INVALID_INPUT).
 */
function registerExternalKey(db, args = {}) {
  const { publicKeyPem, registeredByUserId, keyLabel = null, notes = null } = args;

  if (typeof registeredByUserId !== 'string' || !registeredByUserId.trim()) {
    throw new SigningKeyError(CODES.INVALID_INPUT, 'registeredByUserId is required');
  }
  if (keyLabel !== null && (typeof keyLabel !== 'string' || keyLabel.length > 200)) {
    throw new SigningKeyError(CODES.INVALID_INPUT, 'keyLabel must be a string up to 200 chars or null');
  }

  // Validate + canonicalize. Throws SigningKeyError on bad input.
  const { publicKeyPem: canonicalPem, publicKeyFingerprint } = validateExternalPublicKey(publicKeyPem);

  // Refuse a duplicate fingerprint -- the same key bytes shouldn't exist as
  // multiple rows, whether the existing row is local, active external, or revoked.
  const existing = getRowByFingerprint(db, publicKeyFingerprint);
  if (existing) {
    throw new SigningKeyError(
      CODES.DUPLICATE_FINGERPRINT,
      `a key with fingerprint ${publicKeyFingerprint} is already registered (id=${existing.id}, origin=${existing.key_origin})`,
      { existingId: existing.id, existingOrigin: existing.key_origin },
    );
  }

  const registeredAt = new Date().toISOString().replace('T', ' ').replace(/\..+$/, '');
  const result = db.prepare(`
    INSERT INTO backup_signing_keys
      (public_key, public_key_fingerprint, private_key_encrypted,
       is_active, key_origin,
       registered_by_user_id, registered_at, key_label, notes)
    VALUES (?, ?, NULL, 0, 'external-registered', ?, ?, ?, ?)
  `).run(canonicalPem, publicKeyFingerprint, registeredByUserId, registeredAt, keyLabel, notes);

  return {
    id: result.lastInsertRowid,
    publicKeyFingerprint,
    registeredAt,
  };
}

/**
 * Revoke trust in a previously registered external key by setting
 * rotated_out_at=now. Does not delete the row (audit trail preserved). After
 * revocation, getVerificationKey* return null for this key. Refuses to revoke
 * local-generated keys (use rotateKeypair).
 *
 * Returns { id, publicKeyFingerprint, rotatedOutAt }. Throws SigningKeyError
 * (KEY_NOT_FOUND / NOT_EXTERNAL_KEY / ALREADY_REVOKED).
 */
function revokeExternalKey(db, id) {
  const row = getRowById(db, id);
  if (!row) {
    throw new SigningKeyError(CODES.KEY_NOT_FOUND, `no backup signing key with id ${id}`);
  }
  if (row.key_origin !== 'external-registered') {
    throw new SigningKeyError(
      CODES.NOT_EXTERNAL_KEY,
      `key id ${id} is ${row.key_origin}, not external-registered; use rotateKeypair() to retire local-generated keys`,
      { keyOrigin: row.key_origin },
    );
  }
  if (row.rotated_out_at) {
    throw new SigningKeyError(
      CODES.ALREADY_REVOKED,
      `external key id ${id} is already revoked (at ${row.rotated_out_at})`,
      { rotatedOutAt: row.rotated_out_at },
    );
  }

  const rotatedOutAt = new Date().toISOString().replace('T', ' ').replace(/\..+$/, '');
  db.prepare(`
    UPDATE backup_signing_keys
    SET rotated_out_at = ?
    WHERE id = ? AND key_origin = 'external-registered' AND rotated_out_at IS NULL
  `).run(rotatedOutAt, id);

  return {
    id: row.id,
    publicKeyFingerprint: row.public_key_fingerprint,
    rotatedOutAt,
  };
}

/**
 * Admin UI listing -- every key row's public-side metadata. Never returns
 * private keys. options.origin optionally filters to 'local-generated' or
 * 'external-registered'. Each row includes backupsSignedCount (backups
 * referencing the key by id; only meaningful for local-generated rows).
 */
function listKeys(db, options = {}) {
  const { origin = null } = options;

  let query = `
    SELECT
      bsk.id,
      bsk.public_key,
      bsk.public_key_fingerprint,
      bsk.is_active,
      bsk.key_origin,
      bsk.registered_by_user_id,
      bsk.registered_at,
      bsk.key_label,
      bsk.created_at,
      bsk.rotated_out_at,
      bsk.notes,
      (SELECT COUNT(*) FROM backups WHERE signing_key_id = bsk.id) AS backups_signed_count
    FROM backup_signing_keys bsk
  `;
  const params = [];
  if (origin) {
    if (!['local-generated', 'external-registered'].includes(origin)) {
      throw new SigningKeyError(CODES.INVALID_INPUT, `origin must be 'local-generated' or 'external-registered', got '${origin}'`);
    }
    query += ` WHERE bsk.key_origin = ?`;
    params.push(origin);
  }
  query += ` ORDER BY bsk.created_at DESC`;

  const rows = db.prepare(query).all(...params);

  return rows.map(r => ({
    id: r.id,
    publicKeyPem: r.public_key,
    publicKeyFingerprint: r.public_key_fingerprint,
    isActive: r.is_active === 1,
    keyOrigin: r.key_origin,
    registeredByUserId: r.registered_by_user_id,
    registeredAt: r.registered_at,
    keyLabel: r.key_label,
    createdAt: r.created_at,
    rotatedOutAt: r.rotated_out_at,
    notes: r.notes,
    backupsSignedCount: r.backups_signed_count,
  }));
}

// -- Sign / verify wrappers ---------------------------------------------------

/**
 * Sign the given manifest bytes (typically the canonical JSON serialization of a
 * manifest object) with the current active local-generated signing key. Returns
 * { signature (Buffer, 64 bytes), signingKeyId, signingKeyFingerprint }. The
 * caller stores the signature and records both the id and the fingerprint so
 * verification can find the right public key later.
 */
function signManifest(db, manifestBytes) {
  if (!Buffer.isBuffer(manifestBytes) && typeof manifestBytes !== 'string') {
    throw new Error('signManifest: manifestBytes must be Buffer or string');
  }
  const { id, privateKey, publicKeyFingerprint } = getActiveSigningKey(db);
  const bytes = Buffer.isBuffer(manifestBytes) ? manifestBytes : Buffer.from(manifestBytes);
  const signature = crypto.sign(null, bytes, privateKey);
  return {
    signature,
    signingKeyId: id,
    signingKeyFingerprint: publicKeyFingerprint,
  };
}

/**
 * Shared verification primitive. Returns true if signature is a valid Ed25519
 * signature over manifestBytes by publicKey, false otherwise. Throws on a
 * non-Buffer signature.
 */
function _verifyAgainstKey(manifestBytes, signature, publicKey) {
  if (!Buffer.isBuffer(signature)) {
    throw new Error('verify: signature must be a Buffer');
  }
  if (signature.length !== 64) {
    // Ed25519 signatures are always 64 bytes; reject other sizes early.
    return false;
  }
  const bytes = Buffer.isBuffer(manifestBytes) ? manifestBytes : Buffer.from(manifestBytes);
  return crypto.verify(null, bytes, publicKey, signature);
}

/**
 * Verify by local key id. Returns true if valid; false if the signature is
 * invalid, the id doesn't exist, or the key is a revoked external key. Does NOT
 * throw on signature mismatch.
 */
function verifyManifest(db, manifestBytes, signature, signingKeyId) {
  const verKey = getVerificationKey(db, signingKeyId);
  if (!verKey) return false;
  return _verifyAgainstKey(manifestBytes, signature, verKey.publicKey);
}

/**
 * Verify by content-addressed fingerprint -- the lookup path for v3 manifests
 * and chain entries; works across deployments. Returns true if valid; false if
 * the signature is invalid, the fingerprint matches no key, or the matched key
 * is a revoked external key.
 */
function verifyManifestByFingerprint(db, manifestBytes, signature, fingerprint) {
  const verKey = getVerificationKeyByFingerprint(db, fingerprint);
  if (!verKey) return false;
  return _verifyAgainstKey(manifestBytes, signature, verKey.publicKey);
}

module.exports = {
  // Errors
  SigningKeyError,
  CODES,

  // Keypair lifecycle (local-generated)
  ensureActiveKeypair,
  getActiveSigningKey,
  rotateKeypair,

  // External-registered keys
  validateExternalPublicKey,
  registerExternalKey,
  revokeExternalKey,

  // Verification key lookup
  getVerificationKey,
  getVerificationKeyByFingerprint,

  // Listing
  listKeys,

  // Sign / verify
  signManifest,
  verifyManifest,
  verifyManifestByFingerprint,

  // Utility (exported for tests + the manifest service)
  computePublicKeyFingerprint,
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Signing Keys Service
//
// Manages two distinct categories of Ed25519 verification keys, both stored
// in backup_signing_keys but distinguished by the key_origin column:
//
//   key_origin = 'local-generated'
//       This deployment's own Ed25519 keypair, used to sign v2/v3 backup
//       manifests created here. Public key plaintext (no confidentiality
//       concern); private key Tier-1 AES-256-GCM-encrypted via encryptConfig
//       and decrypted just-in-time only when the backup engine needs to
//       sign a fresh manifest. The raw private key is never cached at
//       module scope -- every signing operation decrypts from the DB.
//       Rotated via rotateKeypair(); old rows retained with is_active=0
//       and rotated_out_at set so historical manifests stay verifiable.
//
//   key_origin = 'external-registered'  (R3d-5-pt2)
//       A foreign deployment's public key, registered by an admin so that
//       backups created by that deployment can be cross-verified here for
//       cross-deployment external restore. Verification-only -- never
//       active, never holds a private key. Revoked by setting
//       rotated_out_at; revoked external keys are filtered out of the
//       verification helpers (a revoked key MUST NOT verify a manifest).
//
// Each key row carries a public_key_fingerprint -- SHA-256 hex of the
// SPKI DER bytes -- which is the universal cross-deployment identifier
// embedded in v3 manifests. v2 manifests reference keys by local id only,
// so cross-deployment verification of v2 backups is not supported and the
// orchestrator must fall back to id-based lookup for legacy manifests.
//
// Schema lives in db/init.js -> backup_signing_keys table. See the
// ROTATION MODEL block + the R3d-5-pt2 migration block in init.js for
// the full contract.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { sealTier1, openTier1 } = require('./tier1-seal');

// ── Typed errors ──────────────────────────────────────────────────────────

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
 * Throws SigningKeyError(INVALID_PEM) if the PEM doesn't parse.
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
 * validateExternalPublicKey(pem)
 *
 * Parse and sanity-check a foreign deployment's public key before
 * accepting it for registration. Enforces:
 *   - parses as a valid SPKI public key
 *   - is an Ed25519 key (matching what FireAlive's backup signer uses)
 *   - is a public key (not a private key paste)
 *
 * Returns { publicKeyPem, publicKeyFingerprint } on success, where
 * publicKeyPem is the canonicalized form.
 *
 * Throws SigningKeyError on any validation failure.
 */
function validateExternalPublicKey(pem) {
  if (typeof pem !== 'string' || !pem.trim()) {
    throw new SigningKeyError(CODES.INVALID_PEM, 'public key PEM must be a non-empty string');
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
  // Re-export to canonical PEM so the stored form is normalized regardless
  // of how the operator pasted it.
  const canonicalPem = keyObj.export({ type: 'spki', format: 'pem' });
  const der = keyObj.export({ type: 'spki', format: 'der' });
  const publicKeyFingerprint = crypto.createHash('sha256').update(der).digest('hex');
  return { publicKeyPem: canonicalPem, publicKeyFingerprint };
}

// ── DB-level helpers (private) ────────────────────────────────────────────

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

function getRowByIdWithPrivate(db, id) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, private_key_encrypted,
           is_active, key_origin,
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

// ── Public API ────────────────────────────────────────────────────────────

/**
 * ensureActiveKeypair(db)
 *
 * Boot-time idempotent helper. If no row in backup_signing_keys has
 * is_active = 1, generate a fresh Ed25519 keypair and insert it.
 * Returns the active row's { id, publicKeyPem, publicKeyFingerprint,
 * isNewlyCreated }.
 *
 * Safe to call on every server start.
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
 * getActiveSigningKey(db)
 *
 * Return everything the backup engine needs to sign a fresh manifest.
 * Decrypts the private key just-in-time. The KeyObject returned for
 * privateKey can be passed directly to crypto.sign().
 *
 * Throws if no active keypair exists -- callers should call
 * ensureActiveKeypair(db) at server start so this never fires in
 * normal operation. Also throws if the active row isn't local-generated
 * or has no private_key_encrypted (DB inconsistency; the CHECK constraint
 * should prevent both, but defensive).
 *
 * Returns: { id, publicKey: KeyObject, privateKey: KeyObject,
 *            publicKeyPem, publicKeyFingerprint }
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
 * getVerificationKey(db, signingKeyId)
 *
 * Return the public key needed to verify a manifest signed by signing_key_id.
 * Used by the restore service to verify v2 (legacy id-based) manifests.
 * Public-only -- never decrypts the private key.
 *
 * Returns null if:
 *   - no key with that id exists, OR
 *   - the key is external-registered AND has been revoked (rotated_out_at
 *     set). Revoked external keys MUST NOT verify foreign manifests; once
 *     trust is withdrawn, even backups created before revocation cannot be
 *     auto-verified.
 *
 * Local-generated keys with rotated_out_at set are still returned -- old
 * backups signed by a since-rotated local key MUST stay verifiable.
 *
 * Returns: { id, publicKey: KeyObject, publicKeyPem, publicKeyFingerprint,
 *            isActive, keyOrigin, rotatedOutAt } or null
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
 * getVerificationKeyByFingerprint(db, fingerprint)  (R3d-5-pt2)
 *
 * Return the verification key matching a content-addressed fingerprint.
 * This is the lookup path for v3 manifests, which embed the signing key's
 * fingerprint rather than (or alongside) the local id. It works across
 * deployments: the fingerprint is a property of the public key bytes
 * themselves, not of any database row.
 *
 * Same revocation semantics as getVerificationKey: revoked external keys
 * return null; rotated-out local keys are still returned for verifying
 * historical backups.
 *
 * Returns null on any of:
 *   - fingerprint isn't a valid 64-char lowercase hex string
 *   - no key matches
 *   - the matched key is external-registered AND revoked
 *
 * Returns: same shape as getVerificationKey or null.
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
 * rotateKeypair(db, options)
 *
 * Generate a new local-generated keypair, demote the previous active local
 * keypair to is_active=0 with rotated_out_at = now, insert the new keypair
 * as is_active=1.
 *
 * Atomic -- wrapped in a SQLite transaction so the rotation either fully
 * succeeds or leaves the existing active key in place.
 *
 * Only operates on local-generated rows. External-registered rows are
 * always inactive (CHECK constraint enforced) and never rotated.
 *
 * options:
 *   notes (string, optional) - stored in the new row's notes column
 *
 * Returns: { newId, newPublicKeyPem, newPublicKeyFingerprint, oldId | null }
 */
function rotateKeypair(db, options = {}) {
  const { notes = 'rotation' } = options;

  return db.transaction(() => {
    const old = getActiveRow(db);

    // Demote any existing active key. There SHOULD be at most one;
    // defensively handle the multi-active edge case by demoting all.
    // The CHECK constraint already prevents external-registered rows from
    // having is_active=1 so we don't need to filter by key_origin here.
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
 * registerExternalKey(db, args)  (R3d-5-pt2)
 *
 * Register a foreign deployment's Ed25519 public key for verification of
 * cross-deployment external-restore backups. Inserts a new row with
 * key_origin='external-registered', is_active=0 (verification-only),
 * private_key_encrypted=NULL, and the provided registration metadata.
 *
 * The DB CHECK constraint enforces these invariants; this function is
 * also responsible for application-level validation (key parses as
 * Ed25519, fingerprint isn't already registered).
 *
 * args:
 *   publicKeyPem        (string, required) - foreign deployment's pubkey
 *   registeredByUserId  (string, required) - admin performing registration
 *   keyLabel            (string, optional) - operator-friendly description
 *   notes               (string, optional)
 *
 * Returns: { id, publicKeyFingerprint, registeredAt }
 *
 * Throws SigningKeyError with one of:
 *   - INVALID_PEM            PEM doesn't parse
 *   - WRONG_KEY_TYPE         not Ed25519
 *   - WRONG_KEY_USAGE        not a public key
 *   - DUPLICATE_FINGERPRINT  same fingerprint already registered (with id)
 *   - INVALID_INPUT          missing required arg
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

  // Refuse to insert a duplicate fingerprint -- whether the existing row
  // is local-generated, active external-registered, or revoked external.
  // The same key bytes shouldn't exist as multiple rows.
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
 * revokeExternalKey(db, id)  (R3d-5-pt2)
 *
 * Revoke trust in a previously registered external key by setting
 * rotated_out_at = now. Does not delete the row -- the audit trail
 * (registered_by_user_id, registered_at, key_label) is preserved, and any
 * historical references from chain entries remain intact.
 *
 * After revocation, getVerificationKey* return null for this key, so any
 * future restore attempt against a manifest signed by it will fail
 * verification.
 *
 * Refuses to revoke local-generated keys (rotation is via rotateKeypair).
 *
 * Returns: { id, publicKeyFingerprint, rotatedOutAt }
 *
 * Throws SigningKeyError with one of:
 *   - KEY_NOT_FOUND     no row with that id
 *   - NOT_EXTERNAL_KEY  row is local-generated; use rotateKeypair instead
 *   - ALREADY_REVOKED   rotated_out_at already set
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
 * listKeys(db, options)
 *
 * Admin UI listing -- returns every key row's public-side metadata. Never
 * returns private keys (they're not even SELECTed).
 *
 * options:
 *   origin (string, optional) - filter to 'local-generated' or
 *                                'external-registered'
 *
 * Returns: array of {
 *   id, publicKeyPem, publicKeyFingerprint,
 *   isActive, keyOrigin,
 *   registeredByUserId, registeredAt, keyLabel,
 *   createdAt, rotatedOutAt, notes,
 *   backupsSignedCount   (count of local backups in the backups table
 *                         that reference this key by id; only meaningful
 *                         for local-generated rows)
 * }
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

// ── Sign / verify wrappers ───────────────────────────────────────────────

/**
 * signManifest(db, manifestBytes)
 *
 * Sign the given manifest bytes (typically the canonical JSON serialization
 * of a manifest object) with the current active local-generated signing key.
 *
 * Returns: { signature: Buffer, signingKeyId: number,
 *            signingKeyFingerprint: string }
 *
 * The signature is 64 bytes (Ed25519 fixed size). Caller is responsible
 * for storing the signature alongside the manifest and recording both
 * signingKeyId (legacy v2 lookup) and signingKeyFingerprint (v3 universal
 * lookup) in the manifest so verification can find the right public key
 * later.
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
 * _verifyAgainstKey(manifestBytes, signature, publicKey)  (private)
 *
 * Shared verification primitive. Returns true if signature is a valid
 * Ed25519 signature over manifestBytes by publicKey, false otherwise.
 * Throws on malformed inputs (non-Buffer signature).
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
 * verifyManifest(db, manifestBytes, signature, signingKeyId)
 *
 * Verify by local key id. The legacy lookup path used by v2 manifests.
 * Returns true if valid; false if the signature is invalid OR the
 * signing key id doesn't exist OR the key is a revoked external key.
 *
 * Does NOT throw on signature mismatch -- returns false. Throws only on
 * malformed inputs.
 */
function verifyManifest(db, manifestBytes, signature, signingKeyId) {
  const verKey = getVerificationKey(db, signingKeyId);
  if (!verKey) return false;
  return _verifyAgainstKey(manifestBytes, signature, verKey.publicKey);
}

/**
 * verifyManifestByFingerprint(db, manifestBytes, signature, fingerprint)  (R3d-5-pt2)
 *
 * Verify by content-addressed fingerprint. The lookup path for v3
 * manifests; works across deployments because the fingerprint is a
 * property of the public key bytes, not of any local row id.
 *
 * Returns true if valid; false if the signature is invalid OR the
 * fingerprint matches no local key OR the matched key is a revoked
 * external key.
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

  // External-registered keys (R3d-5-pt2)
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

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Report Signing Keys Service (Global Dashboard server)
//
// Manages the Ed25519 keypair family used to sign every FireAlive-generated
// exportable report: the GD's compliance reports and executive (Report
// Engine) output. (helper-pay and abuse-flag report types are MC/AC-only and
// do not exist on the GD.) Public keys are stored
// plaintext (no confidentiality concern); private keys are Tier-1
// AES-256-GCM-encrypted via encryptConfig and decrypted just-in-time only
// when a report is signed. The raw private key is never cached at module
// scope -- every signing operation decrypts from the DB.
//
// DELIBERATELY SEPARATE FROM the other signing-key families
//
// Report attestation is a distinct cryptographic concern from backup
// integrity, chain integrity, forensic export, gd-push
// transport, and cloud-iac signing. A compromise of any one signing family
// MUST NOT compromise the others. report_signing_keys shares no state, no
// in-memory KeyObject instances, and no DB tables with the other families.
// The intentional duplicated boilerplate is justified by the security
// separation. All families share the GD's Tier-1 KEK (via gd-encryption) for
// at-rest encryption of private keys;
// cryptographic separation comes from the distinct Ed25519 keypairs.
//
// INSTANCE IDENTITY
//
// The active key's public_key_fingerprint (SHA-256 hex of the SPKI DER
// bytes, 64 lowercase chars) is the cryptographic instance identity rendered
// alongside the human-readable config 'instance_label' on every report
// watermark. report_verifications rows reference the key by fingerprint (not
// row id), so a recorded signature stays verifiable across key rotation and
// is content-addressed rather than tied to an autoincrement id.
//
// Schema lives in db/init.js -> report_signing_keys table. Same rotation
// model as the other families: one active keypair at a time (is_active = 1),
// old keypairs retained with is_active = 0 + rotated_out_at so historical
// report signatures stay verifiable forever.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { encryptConfig, decryptConfig } = require('./gd-encryption');

// -- Typed errors (used by the external-registration trust API) --------------

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
 *     publicKeyPem:        string  (PEM-encoded SPKI, safe to store plaintext)
 *     privateKeyPem:       string  (PEM-encoded PKCS#8, MUST be encrypted before storage)
 *     publicKeyFingerprint string  (SHA-256 hex of SPKI DER, 64 lowercase chars)
 *   }
 *
 * Ed25519 key sizes are fixed: public 32 bytes raw, private 32 bytes raw.
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
 * SHA-256 hex of the SPKI DER bytes. 64 hex chars (lowercase). Stable across
 * deployments and across PEM normalization (line endings, trailing newlines,
 * header whitespace) because it hashes the DER, not the PEM text. Same format
 * as gd-push-signing-keys / backup-signing-keys fingerprints.
 *
 * Throws if the PEM doesn't parse.
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

// ── DB-level helpers (private) ─────────────────────────────────────────────

function getActiveRow(db) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, private_key_encrypted,
           is_active, key_origin, created_at
    FROM report_signing_keys
    WHERE is_active = 1
    LIMIT 1
  `).get();
}

function getRowByFingerprint(db, fingerprint) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, is_active, key_origin,
           registered_by_user_id, registered_at, key_label,
           created_at, rotated_out_at, notes
    FROM report_signing_keys
    WHERE public_key_fingerprint = ?
  `).get(fingerprint);
}

function getRowById(db, id) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, is_active, key_origin,
           registered_by_user_id, registered_at, key_label,
           created_at, rotated_out_at, notes
    FROM report_signing_keys
    WHERE id = ?
  `).get(id);
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * ensureActiveReportKeypair(db)
 *
 * Boot-time idempotent helper. If no row in report_signing_keys has
 * is_active = 1, generate a fresh Ed25519 keypair and insert it. Returns the
 * active row's { id, publicKeyPem, publicKeyFingerprint, isNewlyCreated }.
 *
 * Safe to call on every server start; called from db/init.js initDb() after
 * the schema exec, alongside the equivalent boot helpers from the other
 * signing-key families.
 */
function ensureActiveReportKeypair(db) {
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
    INSERT INTO report_signing_keys
      (public_key, public_key_fingerprint, private_key_encrypted, is_active, notes)
    VALUES (?, ?, ?, 1, 'auto-generated at server boot')
  `).run(publicKeyPem, publicKeyFingerprint, privateKeyEncrypted);

  return {
    id: result.lastInsertRowid,
    publicKeyPem,
    publicKeyFingerprint,
    isNewlyCreated: true,
  };
}

/**
 * getActiveReportKey(db)
 *
 * Return everything the report signer needs to sign a fresh report.
 * Decrypts the private key just-in-time. Throws if no active keypair exists
 * -- callers should call ensureActiveReportKeypair(db) at server boot so this
 * never fires in normal operation.
 *
 * Returns: { id, publicKey: KeyObject, privateKey: KeyObject, publicKeyPem,
 *            publicKeyFingerprint }
 */
function getActiveReportKey(db) {
  const row = getActiveRow(db);
  if (!row) {
    throw new Error('no active report signing key exists; call ensureActiveReportKeypair(db) at server boot');
  }
  // Defense in depth: the schema CHECK already forbids an external-registered
  // key from being active, but never sign with anything but a local keypair.
  if (row.key_origin && row.key_origin !== 'local-generated') {
    throw new Error(`active report signing key is not local-generated (origin=${row.key_origin}); refusing to sign`);
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
 * getReportVerificationKey(db, fingerprint)
 *
 * Return the public key needed to verify a report signature recorded with the
 * given key_fingerprint. A local-generated key resolves regardless of whether
 * it is currently active or has been rotated out, so historical report
 * signatures stay verifiable forever. An external-registered key that has been
 * revoked (rotated_out_at set) resolves to null and fails closed -- once trust
 * in a foreign deployment's key is revoked, signatures by it are untrusted.
 * Public-only -- never decrypts the private key.
 *
 * Returns: { id, publicKey: KeyObject, publicKeyPem, publicKeyFingerprint,
 *            isActive, keyOrigin } or null if no usable key with that
 *            fingerprint exists.
 */
function getReportVerificationKey(db, fingerprint) {
  const row = getRowByFingerprint(db, fingerprint);
  if (!row) return null;
  if (row.key_origin === 'external-registered' && row.rotated_out_at) return null;
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    publicKeyPem: row.public_key,
    publicKeyFingerprint: row.public_key_fingerprint,
    isActive: row.is_active === 1,
    keyOrigin: row.key_origin,
  };
}

/**
 * rotateReportKeypair(db, options)
 *
 * Generate a new keypair, demote the previous active keypair to is_active=0
 * with rotated_out_at = now, insert the new keypair as is_active=1. Atomic --
 * wrapped in a SQLite transaction so the rotation either fully succeeds or
 * leaves the existing active key in place.
 *
 * options:
 *   notes (string, optional) - stored in the new row's notes column
 *
 * Returns: { newId, newPublicKeyPem, newPublicKeyFingerprint, oldId | null }
 */
function rotateReportKeypair(db, options = {}) {
  const { notes = 'rotation' } = options;

  return db.transaction(() => {
    const old = getActiveRow(db);

    // Demote any existing active key. There SHOULD be at most one; defensively
    // handle the multi-active edge case by demoting all.
    db.prepare(`
      UPDATE report_signing_keys
      SET is_active = 0,
          rotated_out_at = datetime('now')
      WHERE is_active = 1
    `).run();

    const { publicKeyPem, privateKeyPem, publicKeyFingerprint } = generateKeypair();
    const privateKeyEncrypted = encryptConfig({ pem: privateKeyPem });

    const result = db.prepare(`
      INSERT INTO report_signing_keys
        (public_key, public_key_fingerprint, private_key_encrypted, is_active, notes)
      VALUES (?, ?, ?, 1, ?)
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
 * listReportKeys(db)
 *
 * Admin UI listing -- returns every keypair's public-side metadata plus the
 * count of report_verifications signed by each key. Never returns private
 * keys (they're not even SELECTed).
 *
 * Returns: array of {
 *   id, publicKeyPem, publicKeyFingerprint, isActive, createdAt,
 *   rotatedOutAt, notes, reportsSignedCount
 * }
 */
function listReportKeys(db, options = {}) {
  let query = `
    SELECT
      rsk.id,
      rsk.public_key,
      rsk.public_key_fingerprint,
      rsk.is_active,
      rsk.key_origin,
      rsk.registered_by_user_id,
      rsk.registered_at,
      rsk.key_label,
      rsk.created_at,
      rsk.rotated_out_at,
      rsk.notes,
      (SELECT COUNT(*) FROM report_verifications
        WHERE key_fingerprint = rsk.public_key_fingerprint) AS reports_signed_count
    FROM report_signing_keys rsk
  `;
  const params = [];
  if (options.origin) {
    if (!['local-generated', 'external-registered'].includes(options.origin)) {
      throw new SigningKeyError(CODES.INVALID_INPUT, `origin must be 'local-generated' or 'external-registered', got '${options.origin}'`);
    }
    query += ` WHERE rsk.key_origin = ?`;
    params.push(options.origin);
  }
  query += ` ORDER BY rsk.created_at DESC`;
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
    reportsSignedCount: r.reports_signed_count,
  }));
}

// ── Sign / verify wrappers ─────────────────────────────────────────────────

/**
 * signReportDigest(db, digestBytes)
 *
 * Sign a 32-byte SHA-256 digest of the report material with the current
 * active report-signing key. The report-signer module computes the digest
 * over the produced PDF/DOCX bytes (server-side reports) or over the
 * canonical data payload (client-side abuse reports), and stores the hex of
 * that digest in report_verifications.signed_payload_sha256.
 *
 * Signs the HASH (not the raw material) so verification needs only the
 * recorded digest, never the original bytes -- which is what preserves zero
 * access for abuse reports (the server only ever holds the hash).
 *
 * Returns: { signature: Buffer (64 bytes), keyFingerprint: string }
 */
function signReportDigest(db, digestBytes) {
  if (!Buffer.isBuffer(digestBytes) && typeof digestBytes !== 'string') {
    throw new Error('signReportDigest: digestBytes must be Buffer or string');
  }
  const bytes = Buffer.isBuffer(digestBytes) ? digestBytes : Buffer.from(digestBytes, 'hex');
  if (bytes.length !== 32) {
    throw new Error(`signReportDigest: expected 32-byte SHA-256 digest, got ${bytes.length} bytes`);
  }
  const { privateKey, publicKeyFingerprint } = getActiveReportKey(db);
  const signature = crypto.sign(null, bytes, privateKey);
  return { signature, keyFingerprint: publicKeyFingerprint };
}

/**
 * verifyReportDigest(db, digestBytes, signature, keyFingerprint)
 *
 * Verify that signature is a valid Ed25519 signature over digestBytes by the
 * keypair identified by keyFingerprint. Returns true if valid; false if the
 * signature is invalid OR the fingerprint doesn't resolve to a known key
 * (treated the same -- a signature by a key we've never seen is untrusted).
 *
 * Does NOT throw on signature mismatch -- returns false. Throws only on
 * malformed inputs.
 */
function verifyReportDigest(db, digestBytes, signature, keyFingerprint) {
  if (!Buffer.isBuffer(signature)) {
    throw new Error('verifyReportDigest: signature must be a Buffer');
  }
  if (signature.length !== 64) {
    // Ed25519 signatures are always 64 bytes; reject other sizes early.
    return false;
  }
  if (!Buffer.isBuffer(digestBytes) && typeof digestBytes !== 'string') {
    throw new Error('verifyReportDigest: digestBytes must be Buffer or string');
  }
  const bytes = Buffer.isBuffer(digestBytes) ? digestBytes : Buffer.from(digestBytes, 'hex');
  if (bytes.length !== 32) return false;
  const verKey = getReportVerificationKey(db, keyFingerprint);
  if (!verKey) return false;
  return crypto.verify(null, bytes, verKey.publicKey, signature);
}

// -- External-registered key trust (cross-deployment verification) -----------

/**
 * validateExternalPublicKey(pem)
 *
 * Parse and validate a foreign deployment's report-signing PUBLIC key PEM.
 * Rejects a private-key paste outright (crypto.createPublicKey would silently
 * derive the public half from a private key, so without this an operator could
 * accidentally submit -- and expose -- their own private key). Requires an
 * Ed25519 public key. Returns the canonical SPKI PEM plus the SHA-256 DER
 * fingerprint.
 *
 * Returns: { publicKeyPem, publicKeyFingerprint }
 *
 * Throws SigningKeyError on any validation failure.
 */
function validateExternalPublicKey(pem) {
  if (typeof pem !== 'string' || !pem.trim()) {
    throw new SigningKeyError(CODES.INVALID_PEM, 'public key PEM must be a non-empty string');
  }
  // Reject a private-key paste outright. Public keys cannot be loaded as private
  // keys, so this only ever rejects actual private-key input.
  let looksPrivate = false;
  try {
    crypto.createPrivateKey(pem);
    looksPrivate = true;
  } catch (err) {
    looksPrivate = false;
  }
  if (looksPrivate) {
    throw new SigningKeyError(CODES.WRONG_KEY_USAGE, 'this looks like a private key; paste the PUBLIC key only');
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

/**
 * registerExternalKey(db, args)
 *
 * Register a foreign deployment's Ed25519 report-signing PUBLIC key so this
 * deployment can verify golden-baseline bundles exported by it. Inserts a row
 * with key_origin='external-registered', is_active=0 (verification-only),
 * private_key_encrypted=NULL, and the registration metadata. The schema CHECK
 * enforces those invariants; this function adds the application-level checks
 * (key parses as Ed25519, fingerprint not already present).
 *
 * args:
 *   publicKeyPem        (string, required) - foreign deployment's pubkey
 *   registeredByUserId  (string, required) - admin performing registration
 *                                            (audit trail; required by CHECK)
 *   keyLabel            (string, optional) - operator-friendly description
 *   notes               (string, optional)
 *
 * Returns: { id, publicKeyFingerprint, registeredAt }
 *
 * Throws SigningKeyError: INVALID_PEM | WRONG_KEY_TYPE | WRONG_KEY_USAGE |
 *   DUPLICATE_FINGERPRINT | INVALID_INPUT.
 */
function registerExternalKey(db, args = {}) {
  const { publicKeyPem, registeredByUserId, keyLabel = null, notes = null } = args;

  if (typeof registeredByUserId !== 'string' || !registeredByUserId.trim()) {
    throw new SigningKeyError(CODES.INVALID_INPUT, 'registeredByUserId is required');
  }
  if (keyLabel !== null && (typeof keyLabel !== 'string' || keyLabel.length > 200)) {
    throw new SigningKeyError(CODES.INVALID_INPUT, 'keyLabel must be a string up to 200 chars or null');
  }

  const { publicKeyPem: canonicalPem, publicKeyFingerprint } = validateExternalPublicKey(publicKeyPem);

  // The same key bytes must not exist as multiple rows, whether the existing
  // row is local-generated, active external, or revoked external.
  const existing = getRowByFingerprint(db, publicKeyFingerprint);
  if (existing) {
    throw new SigningKeyError(
      CODES.DUPLICATE_FINGERPRINT,
      `a key with fingerprint ${publicKeyFingerprint} is already registered (id=${existing.id}, origin=${existing.key_origin})`,
      { existingId: existing.id, existingOrigin: existing.key_origin },
    );
  }

  const result = db.prepare(`
    INSERT INTO report_signing_keys
      (public_key, public_key_fingerprint, private_key_encrypted,
       is_active, key_origin,
       registered_by_user_id, registered_at, key_label, notes)
    VALUES (?, ?, NULL, 0, 'external-registered', ?, datetime('now'), ?, ?)
  `).run(canonicalPem, publicKeyFingerprint, registeredByUserId, keyLabel, notes);

  const inserted = db.prepare(
    'SELECT registered_at FROM report_signing_keys WHERE id = ?'
  ).get(result.lastInsertRowid);

  return {
    id: result.lastInsertRowid,
    publicKeyFingerprint,
    registeredAt: inserted ? inserted.registered_at : null,
  };
}

/**
 * revokeExternalKey(db, id)
 *
 * Revoke trust in a previously registered external key by setting
 * rotated_out_at = now. The row is preserved (audit trail), but
 * getReportVerificationKey then returns null for it, so any future baseline
 * signed by it fails verification. Refuses to touch local-generated keys
 * (those retire via rotateReportKeypair).
 *
 * Returns: { id, publicKeyFingerprint, rotatedOutAt }
 *
 * Throws SigningKeyError: KEY_NOT_FOUND | NOT_EXTERNAL_KEY | ALREADY_REVOKED.
 */
function revokeExternalKey(db, id) {
  const row = getRowById(db, id);
  if (!row) {
    throw new SigningKeyError(CODES.KEY_NOT_FOUND, `no report signing key with id ${id}`);
  }
  if (row.key_origin !== 'external-registered') {
    throw new SigningKeyError(
      CODES.NOT_EXTERNAL_KEY,
      `key id ${id} is ${row.key_origin}, not external-registered; use rotateReportKeypair() to retire local-generated keys`,
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

  db.prepare(`
    UPDATE report_signing_keys
    SET rotated_out_at = datetime('now')
    WHERE id = ? AND key_origin = 'external-registered' AND rotated_out_at IS NULL
  `).run(id);

  const updated = db.prepare(
    'SELECT rotated_out_at FROM report_signing_keys WHERE id = ?'
  ).get(id);

  return {
    id: row.id,
    publicKeyFingerprint: row.public_key_fingerprint,
    rotatedOutAt: updated ? updated.rotated_out_at : null,
  };
}

module.exports = {
  // Errors
  SigningKeyError,
  CODES,

  generateKeypair,
  computePublicKeyFingerprint,
  ensureActiveReportKeypair,
  getActiveReportKey,
  getReportVerificationKey,
  rotateReportKeypair,
  listReportKeys,
  signReportDigest,
  verifyReportDigest,

  // External-registered key trust (cross-deployment verification)
  validateExternalPublicKey,
  registerExternalKey,
  revokeExternalKey,
};

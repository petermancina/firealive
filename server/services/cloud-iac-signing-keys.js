// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Cloud & IaC Signing Keys Lifecycle Service (R3k C11)
//
// Manages the per-install Sigstore-compatible signing key used by the
// Cloud & IaC generator (Sub-phase 4 / C12) to sign output bundle
// archives via cosign-signer.signBlob (R3k C10).
//
// PARALLEL TO backup-signing-keys, NOT MULTIPLEXED
// ================================================
//
// Per the cross-cutting Sigstore decision in R3K-DETAILED-BUILD-PLAN-v1
// (BUILD-PLAN-v23 R3k cross-cutting locked decisions):
//
//   "one signing key per signing concern, no multiplexing"
//
// The cloud_iac_signing_keys table (R3k C2) is intentionally distinct
// from backup_signing_keys. Different threat models, different
// rotation cadences, different signature consumers; conflating the
// two would force coordinated rotation across both concerns and
// expand blast radius on compromise. This service mirrors the SHAPE
// of backup-signing-keys but operates against its own table.
//
// ALGORITHM
// =========
//
// ECDSA P-256, cosign-compatible default. Stored under
// algorithm='cosign-ecdsa-p256' (schema default in R3k C2). Cosign's
// own keygen produces ECDSA P-256 keys by default, and `cosign sign-
// blob --key <pkcs8-pem>` accepts standard PKCS#8 PEM directly.
// Future rotations may emit other algorithms — the algorithm column
// records what each row holds so verification still works after
// rotation crosses algorithm boundaries.
//
// PRIVATE KEY AT REST
// ===================
//
// Private key bytes are stored in private_key_wrapped using the same
// Tier-1 encryption used by backup_signing_keys (encryptConfig /
// decryptConfig from services/encryption.js, AES-256-GCM via the KMS-
// or env-var-supplied KEK). The unwrap step happens just-in-time
// during signing; PEM bytes never persist on disk outside the cosign-
// signer's 0600-perm temp file (R3k C10) which is unlinked
// immediately after the signing call returns or throws.
//
// PUBLIC API
// ==========
//
//   ensureActiveKey(db)
//     If no row with status='active' exists, generate a new keypair
//     and INSERT it as active. Idempotent — safe to call on every
//     boot or lazily on first generator invocation. Returns
//     {id, created}.
//
//   getActiveSigningKey(db)
//     Returns the active key with its private PEM unwrapped, suitable
//     for passing to cosign-signer.signBlob. Throws if no active key
//     (caller should ensureActiveKey first or be the lazy path).
//     Returns {id, publicKeyPem, privateKeyPem, algorithm,
//              publicKeyFingerprint, createdAt}.
//
//   getVerificationKey(db, signingKeyId)
//     Returns just the public key for verifying a signature produced
//     by a specific signing_key_id. Works for keys in any status
//     (active, rotated, revoked) so historical bundles remain
//     verifiable after rotation. Returns null if the id doesn't
//     exist. Returns {id, publicKeyPem, algorithm, status,
//                     publicKeyFingerprint, createdAt, rotatedAt}.
//
//   rotateActiveKey(db)
//     Generate a new keypair, INSERT as active, mark the prior active
//     row as status='rotated' with rotated_at=now. Atomic via SQLite
//     transaction. Returns {oldId, newId}.
//
//   revokeKey(db, id)
//     Mark a specific key as status='revoked'. Distinct from rotation:
//     revoked keys MUST NOT verify any future signature. Existing
//     verifications against a revoked key are a security event —
//     callers should treat verify-against-revoked as an integrity
//     failure rather than a pass. Returns {id, prior_status}.
//
//   listKeys(db)
//     Admin-facing listing for the eventual route handler. Returns
//     all rows minus the private_key_wrapped column. Public keys and
//     fingerprints are surfaced; private material never leaves the
//     service.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { sealTier1, openTier1 } = require('./tier1-seal');
const { logger } = require('./logger');

const DEFAULT_ALGORITHM = 'cosign-ecdsa-p256';

// ── Helpers ────────────────────────────────────────────────────────────

function generateEcdsaP256Pair() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function fingerprintPublicKey(publicKeyPem) {
  // Hash the SPKI DER bytes to produce a stable fingerprint
  // independent of PEM whitespace variations.
  const publicKeyObj = crypto.createPublicKey(publicKeyPem);
  const der = publicKeyObj.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

function rowToVerificationView(row) {
  if (!row) return null;
  return {
    id: row.id,
    publicKeyPem: row.public_key,
    algorithm: row.algorithm,
    status: row.status,
    publicKeyFingerprint: fingerprintPublicKey(row.public_key),
    createdAt: row.created_at,
    rotatedAt: row.rotated_at,
  };
}

function rowToListView(row) {
  if (!row) return null;
  return {
    id: row.id,
    publicKeyPem: row.public_key,
    publicKeyFingerprint: fingerprintPublicKey(row.public_key),
    algorithm: row.algorithm,
    status: row.status,
    createdAt: row.created_at,
    rotatedAt: row.rotated_at,
  };
}

// ── Internal: persist a fresh keypair as the active row ────────────────

function insertActiveKey(db, algorithm = DEFAULT_ALGORITHM) {
  const { publicKey, privateKey } = generateEcdsaP256Pair();
  const wrapped = sealTier1('cloud_iac_signing_keys.private_key_wrapped', { pem: privateKey });
  const result = db
    .prepare(
      `INSERT INTO cloud_iac_signing_keys
         (public_key, private_key_wrapped, algorithm, status)
       VALUES (?, ?, ?, 'active')`,
    )
    .run(publicKey, wrapped, algorithm);
  const newRow = db
    .prepare('SELECT * FROM cloud_iac_signing_keys WHERE rowid = ?')
    .get(result.lastInsertRowid);
  return newRow;
}

// ── Public API ─────────────────────────────────────────────────────────

function ensureActiveKey(db) {
  const existing = db
    .prepare("SELECT id FROM cloud_iac_signing_keys WHERE status = 'active' LIMIT 1")
    .get();
  if (existing) {
    return { id: existing.id, created: false };
  }
  const row = insertActiveKey(db);
  logger.info('cloud-iac-signing-keys: generated initial active key', {
    id: row.id,
    algorithm: row.algorithm,
    fingerprint: fingerprintPublicKey(row.public_key),
  });
  return { id: row.id, created: true };
}

function getActiveSigningKey(db) {
  const row = db
    .prepare(
      `SELECT id, public_key, private_key_wrapped, algorithm, created_at
         FROM cloud_iac_signing_keys
         WHERE status = 'active'
         LIMIT 1`,
    )
    .get();
  if (!row) {
    throw new Error(
      'no active cloud_iac_signing_keys row; call ensureActiveKey(db) before signing',
    );
  }
  if (!row.private_key_wrapped) {
    throw new Error(
      `active signing key id=${row.id} has no private_key_wrapped (database inconsistency)`,
    );
  }
  const { pem: privateKeyPem } = openTier1('cloud_iac_signing_keys.private_key_wrapped', row.private_key_wrapped);
  return {
    id: row.id,
    publicKeyPem: row.public_key,
    privateKeyPem,
    algorithm: row.algorithm,
    publicKeyFingerprint: fingerprintPublicKey(row.public_key),
    createdAt: row.created_at,
  };
}

function getVerificationKey(db, signingKeyId) {
  const row = db
    .prepare(
      `SELECT id, public_key, algorithm, status, created_at, rotated_at
         FROM cloud_iac_signing_keys
         WHERE id = ?`,
    )
    .get(signingKeyId);
  if (!row) return null;
  return rowToVerificationView(row);
}

function rotateActiveKey(db) {
  const tx = db.transaction(() => {
    const priorActive = db
      .prepare("SELECT id FROM cloud_iac_signing_keys WHERE status = 'active' LIMIT 1")
      .get();
    if (priorActive) {
      db.prepare(
        `UPDATE cloud_iac_signing_keys
           SET status = 'rotated',
               rotated_at = datetime('now')
         WHERE id = ?`,
      ).run(priorActive.id);
    }
    const newRow = insertActiveKey(db);
    return { oldId: priorActive ? priorActive.id : null, newId: newRow.id };
  });
  const result = tx();
  logger.info('cloud-iac-signing-keys: rotated active key', result);
  return result;
}

function revokeKey(db, id) {
  const tx = db.transaction(() => {
    const row = db
      .prepare("SELECT status FROM cloud_iac_signing_keys WHERE id = ?")
      .get(id);
    if (!row) {
      throw new Error(`cloud_iac_signing_keys row not found: ${id}`);
    }
    if (row.status === 'revoked') {
      return { id, prior_status: 'revoked' };
    }
    db.prepare(
      `UPDATE cloud_iac_signing_keys
         SET status = 'revoked',
             rotated_at = COALESCE(rotated_at, datetime('now'))
       WHERE id = ?`,
    ).run(id);
    return { id, prior_status: row.status };
  });
  const result = tx();
  logger.info('cloud-iac-signing-keys: revoked key', result);
  return result;
}

function listKeys(db) {
  const rows = db
    .prepare(
      `SELECT id, public_key, algorithm, status, created_at, rotated_at
         FROM cloud_iac_signing_keys
         ORDER BY created_at DESC`,
    )
    .all();
  return rows.map(rowToListView);
}

module.exports = {
  ensureActiveKey,
  getActiveSigningKey,
  getVerificationKey,
  rotateActiveKey,
  revokeKey,
  listKeys,
  DEFAULT_ALGORITHM,
};

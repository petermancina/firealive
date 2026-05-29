// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Abuse-Export CISO Approval Keys + Decision Mint (GD side, U4 PR 5-C)
//
// The CISO's approval (or denial) of a two-person legal-hold export is an
// Ed25519-signed decision token, not a database flag. This service owns the
// approval key family (abuse_export_approval_keys) and mints those tokens.
//
// The regional server and the reviewer's device verify a minted token against
// the CISO public key they pinned out-of-band. So the authorization cannot be
// forged by a hostile regional server, MC admin, MITM, or rogue reviewer — only
// the holder of this private key (the CISO realm) can produce a valid decision.
//
// Private keys are AES-256-GCM-encrypted at rest via gd-encryption and decrypted
// just-in-time only when minting; never module-cached. One active key at a time
// (is_active = 1); rotation retains old keys for historical verification. In
// production this key SHOULD be HSM/hardware-backed so the private half never
// resides on the GD host. Distinct family from the GD report-signing keys.
//
// CANONICAL DECISION PAYLOAD (the exact bytes signed) — fixed field order:
//   {"request_id","flag_id","mc_id","requested_by","decision","decided_at","nonce"}
// The reviewer's device rebuilds this same string in this same order (or verifies
// over the stored decision_payload_canonical) and checks each field binds the
// request before producing an export.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { encryptConfig, decryptConfig } = require('./gd-encryption');

const VALID_DECISIONS = ['approved', 'denied'];

function computeFingerprint(publicKeyPemOrKey) {
  const key = typeof publicKeyPemOrKey === 'string'
    ? crypto.createPublicKey(publicKeyPemOrKey)
    : publicKeyPemOrKey;
  const der = key.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

/**
 * Build the canonical decision payload string with a FIXED field order. Nulls
 * are explicit (never undefined) so the serialization is deterministic and
 * reproducible by the verifier.
 */
function buildDecisionCanonical({ requestId, flagId, mcId, requestedBy, decision, decidedAt, nonce }) {
  return JSON.stringify({
    request_id: requestId == null ? null : String(requestId),
    flag_id: flagId == null ? null : String(flagId),
    mc_id: mcId == null ? null : String(mcId),
    requested_by: requestedBy == null ? null : String(requestedBy),
    decision: decision,
    decided_at: decidedAt,
    nonce: nonce,
  });
}

/**
 * ensureActiveApprovalKey(db) — idempotent. Generate + store an active Ed25519
 * key if none exists. Returns { id, publicKeyPem, fingerprint, isNewlyCreated }.
 * The GD server does not run initDb on boot, so callers (the approve endpoint)
 * invoke this defensively at request time.
 */
function ensureActiveApprovalKey(db) {
  const existing = db
    .prepare('SELECT id, public_key, fingerprint FROM abuse_export_approval_keys WHERE is_active = 1 LIMIT 1')
    .get();
  if (existing) {
    return { id: existing.id, publicKeyPem: existing.public_key, fingerprint: existing.fingerprint, isNewlyCreated: false };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privateKeyEncrypted = encryptConfig({ pem: privateKeyPem });
  const fingerprint = computeFingerprint(publicKey);
  const id = 'aeak-' + crypto.randomUUID();
  db.prepare(
    'INSERT INTO abuse_export_approval_keys (id, public_key, private_key_encrypted, fingerprint, is_active) VALUES (?, ?, ?, ?, 1)'
  ).run(id, publicKeyPem, privateKeyEncrypted, fingerprint);
  return { id, publicKeyPem, fingerprint, isNewlyCreated: true };
}

/** loadActiveApprovalKey(db) — JIT-decrypt the active private key for minting. Throws if none. */
function loadActiveApprovalKey(db) {
  const row = db
    .prepare('SELECT id, public_key, private_key_encrypted, fingerprint FROM abuse_export_approval_keys WHERE is_active = 1 LIMIT 1')
    .get();
  if (!row) {
    throw new Error('no active abuse-export approval key; call ensureActiveApprovalKey(db) first');
  }
  const { pem } = decryptConfig(row.private_key_encrypted);
  return {
    id: row.id,
    fingerprint: row.fingerprint,
    publicKeyPem: row.public_key,
    privateKey: crypto.createPrivateKey(pem),
  };
}

/** getApprovalPublicKey(db) — the active public key + fingerprint, for out-of-band pinning. Null if none. */
function getApprovalPublicKey(db) {
  const row = db
    .prepare('SELECT public_key, fingerprint FROM abuse_export_approval_keys WHERE is_active = 1 LIMIT 1')
    .get();
  if (!row) return null;
  return { publicKeyPem: row.public_key, fingerprint: row.fingerprint };
}

/**
 * mintDecision(db, { requestId, flagId, mcId, requestedBy, decision, nonce? })
 *
 * Build the canonical decision payload and Ed25519-sign it with the active
 * approval key. Returns the artifacts to persist + relay:
 *   { decisionPayloadCanonical, signature (hex), keyFingerprint, nonce, decidedAt, decision }
 * Ensures an active key exists first.
 */
function mintDecision(db, { requestId, flagId, mcId, requestedBy = null, decision, nonce } = {}) {
  if (!VALID_DECISIONS.includes(decision)) {
    throw new Error(`mintDecision: decision must be one of ${VALID_DECISIONS.join('/')}`);
  }
  if (!requestId || !flagId || !mcId) {
    throw new Error('mintDecision: requestId, flagId and mcId are required');
  }
  ensureActiveApprovalKey(db);
  const key = loadActiveApprovalKey(db);
  const decidedAt = new Date().toISOString();
  const theNonce = nonce || crypto.randomUUID();
  const decisionPayloadCanonical = buildDecisionCanonical({
    requestId, flagId, mcId, requestedBy, decision, decidedAt, nonce: theNonce,
  });
  const signature = crypto.sign(null, Buffer.from(decisionPayloadCanonical, 'utf8'), key.privateKey).toString('hex');
  return {
    decision,
    decisionPayloadCanonical,
    signature,
    keyFingerprint: key.fingerprint,
    nonce: theNonce,
    decidedAt,
  };
}

module.exports = {
  VALID_DECISIONS,
  computeFingerprint,
  buildDecisionCanonical,
  ensureActiveApprovalKey,
  loadActiveApprovalKey,
  getApprovalPublicKey,
  mintDecision,
};

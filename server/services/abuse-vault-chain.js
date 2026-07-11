// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Abuse-Vault Chain Service (U4 PR 5-C)
//
// Append-only, hash-chained, Ed25519-signed lifecycle ledger for the abuse
// evidence vault, plus the dedicated signing-key family that signs it. The
// chain records VAULT_SEALED for every sealed case plus CHAIN_VERIFIED checks.
//
// REVIEW MODEL
//
// Sealed abuse cases are reviewed by the Team Lead in the Management Console
// (Peer Conduct tab); the content is decrypted only on the lead's device with
// the lead's key. This service only writes the immutable lifecycle record and
// never sees decrypted content.
//
// KEY SEPARATION
//
// abuse_vault_chain_signing_keys is its own Ed25519 family, distinct from the
// report-signing, forensic, backup, chain, gd-push, and cloud-iac
// families — a compromise of any one must not taint the others. Public keys
// are stored plaintext; private keys are Tier-1 (AES-256-GCM) encrypted via
// encryptConfig and decrypted just-in-time at sign time, never cached at
// module scope.
//
// RE-VERIFIABILITY
//
// Each entry's hashed payload is built only from columns persisted on the row
// (event_type, flag_id, request_ref, actor_user_id, created_at), so the chain
// can be re-derived and verified later from the table alone. created_at is set
// explicitly at append time (not via the column DEFAULT) so the hashed value
// and the stored value are identical. The signing key is identified at verify
// time by trying the known public keys against the signature, so historical
// entries stay verifiable across key rotation without storing a fingerprint
// column.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { sealTier1, openTier1 } = require('./tier1-seal');
const { canonicalSerialize } = require('./audit-export-shared');

const VALID_EVENTS = [
  'VAULT_SEALED',
  'CHAIN_VERIFIED',
];

// ── Signing-key family ──────────────────────────────────────────────────────

function computeFingerprint(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

/**
 * ensureActiveKey(db) — boot-time idempotent. If no active key exists, generate
 * an Ed25519 keypair, Tier-1-encrypt the private half, and insert it. Returns
 * { id, publicKeyPem, fingerprint, isNewlyCreated }. Safe to call on every boot.
 */
function ensureActiveKey(db) {
  const existing = db
    .prepare('SELECT id, public_key, fingerprint FROM abuse_vault_chain_signing_keys WHERE active = 1 LIMIT 1')
    .get();
  if (existing) {
    return { id: existing.id, publicKeyPem: existing.public_key, fingerprint: existing.fingerprint, isNewlyCreated: false };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privateKeyEncrypted = sealTier1('abuse_vault_chain_signing_keys.private_key_encrypted', { pem: privateKeyPem });
  const fingerprint = computeFingerprint(publicKey);
  const id = 'avsk-' + crypto.randomUUID();
  db.prepare(
    'INSERT INTO abuse_vault_chain_signing_keys (id, public_key, private_key_encrypted, fingerprint, active) VALUES (?, ?, ?, ?, 1)'
  ).run(id, publicKeyPem, privateKeyEncrypted, fingerprint);
  return { id, publicKeyPem, fingerprint, isNewlyCreated: true };
}

/**
 * loadActiveKey(db) — JIT-decrypt the active private key for signing. Throws if
 * none exists (call ensureActiveKey at boot). Never caches the private key.
 */
function loadActiveKey(db) {
  const row = db
    .prepare('SELECT id, public_key, private_key_encrypted, fingerprint FROM abuse_vault_chain_signing_keys WHERE active = 1 LIMIT 1')
    .get();
  if (!row) {
    throw new Error('no active abuse_vault_chain signing key; call ensureActiveKey(db) at server boot');
  }
  const { pem } = openTier1('abuse_vault_chain_signing_keys.private_key_encrypted', row.private_key_encrypted);
  return {
    id: row.id,
    fingerprint: row.fingerprint,
    publicKeyPem: row.public_key,
    privateKey: crypto.createPrivateKey({ key: pem, format: 'pem' }),
  };
}

/**
 * getVerificationKey(db, fingerprint) — public-only lookup for verifying a
 * recorded signature, active or rotated-out. Returns null if unknown.
 */
function getVerificationKey(db, fingerprint) {
  const row = db
    .prepare('SELECT public_key, fingerprint, active FROM abuse_vault_chain_signing_keys WHERE fingerprint = ?')
    .get(fingerprint);
  if (!row) return null;
  return {
    publicKey: crypto.createPublicKey(row.public_key),
    publicKeyPem: row.public_key,
    fingerprint: row.fingerprint,
    active: row.active === 1,
  };
}

// ── Chain append + verify ─────────────────────────────────────────────────

function buildPayload(row) {
  // The hashed payload is reconstructable from persisted columns alone.
  return {
    event_type: row.event_type,
    flag_id: row.flag_id === undefined ? null : row.flag_id,
    request_ref: row.request_ref === undefined ? null : row.request_ref,
    actor_user_id: row.actor_user_id === undefined ? null : row.actor_user_id,
    created_at: row.created_at,
  };
}

function computeThisHash(prevHash, payload) {
  const payloadBytes = canonicalSerialize(payload);
  const linkInput = prevHash ? Buffer.concat([Buffer.from(prevHash, 'hex'), payloadBytes]) : payloadBytes;
  return crypto.createHash('sha256').update(linkInput).digest('hex');
}

/**
 * appendEntry(db, { eventType, flagId, requestRef, actorUserId }) — append a
 * signed entry to the chain. this_hash = SHA-256(prev_hash || canonical(payload));
 * signature = Ed25519 over the this_hash bytes with the active key. Returns
 * { id, prevHash, thisHash, signature, keyFingerprint, createdAt }.
 */
function appendEntry(db, opts) {
  const { eventType, flagId = null, requestRef = null, actorUserId = null } = opts || {};
  if (!VALID_EVENTS.includes(eventType)) {
    throw new Error(`appendEntry: invalid eventType '${eventType}'`);
  }
  const key = loadActiveKey(db);
  const createdAt = new Date().toISOString();
  const prevRow = db.prepare('SELECT this_hash FROM abuse_vault_chain ORDER BY id DESC LIMIT 1').get();
  const prevHash = prevRow ? prevRow.this_hash : null;
  const payload = buildPayload({ event_type: eventType, flag_id: flagId, request_ref: requestRef, actor_user_id: actorUserId, created_at: createdAt });
  const thisHash = computeThisHash(prevHash, payload);
  const signature = crypto.sign(null, Buffer.from(thisHash, 'hex'), key.privateKey).toString('hex');
  const result = db
    .prepare(
      'INSERT INTO abuse_vault_chain (prev_hash, this_hash, signature, event_type, flag_id, request_ref, actor_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    )
    .run(prevHash, thisHash, signature, eventType, flagId, requestRef, actorUserId, createdAt);
  return { id: result.lastInsertRowid, prevHash, thisHash, signature, keyFingerprint: key.fingerprint, createdAt };
}

/**
 * verifyChain(db) — re-derive the whole chain from the table and verify each
 * link and signature. Returns { valid: true, entries } or
 * { valid: false, brokenAt, reason }. Tries all known public keys against each
 * signature so rotated-out keys still verify their historical entries.
 */
function verifyChain(db) {
  const rows = db
    .prepare('SELECT id, prev_hash, this_hash, signature, event_type, flag_id, request_ref, actor_user_id, created_at FROM abuse_vault_chain ORDER BY id ASC')
    .all();
  const pubKeys = db
    .prepare('SELECT public_key FROM abuse_vault_chain_signing_keys')
    .all()
    .map((r) => crypto.createPublicKey(r.public_key));
  let prevHash = null;
  for (const row of rows) {
    if ((row.prev_hash || null) !== prevHash) {
      return { valid: false, brokenAt: row.id, reason: 'prev_hash does not link to previous entry' };
    }
    const computed = computeThisHash(prevHash, buildPayload(row));
    if (computed !== row.this_hash) {
      return { valid: false, brokenAt: row.id, reason: 'this_hash does not match recomputed payload hash' };
    }
    let sigBuf;
    try {
      sigBuf = Buffer.from(row.signature, 'hex');
    } catch (e) {
      return { valid: false, brokenAt: row.id, reason: 'signature is not valid hex' };
    }
    const thisHashBytes = Buffer.from(row.this_hash, 'hex');
    const sigOk = pubKeys.some((pk) => {
      try {
        return crypto.verify(null, thisHashBytes, pk, sigBuf);
      } catch (e) {
        return false;
      }
    });
    if (!sigOk) {
      return { valid: false, brokenAt: row.id, reason: 'signature does not verify against any known key' };
    }
    prevHash = row.this_hash;
  }
  return { valid: true, entries: rows.length };
}

module.exports = {
  VALID_EVENTS,
  computeFingerprint,
  ensureActiveKey,
  loadActiveKey,
  getVerificationKey,
  appendEntry,
  verifyChain,
};

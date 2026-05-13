// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Signing Keys Service (R3g PR3 Phase 5)
//
// Encapsulates every trust-state transition on the signing_keys table.
// All read/write paths for MC public-key trust go through this module:
// the registration endpoint (Commit 18), the admin approve/reject
// endpoints (Commit 19), the admin list endpoints (Commit 20), the
// MC-facing status-query endpoint (Commit 21), and the inbound-push
// verifier's lookup (Commit 22).
//
// WHY A SERVICE INSTEAD OF INLINE QUERIES
//
// The trust-state machine has three transitions (submit, approve,
// reject) plus a number of query paths, all of which need to enforce
// the same invariants:
//   - Approval_status moves only along the legal arrows
//     pending_approval -> approved | rejected (never the reverse)
//   - approve() atomically demotes any current is_active=1 row for the
//     same mc and promotes the target row
//   - Demoted rows retain approval_status='approved' so the verifier's
//     grace-window query can still match them within the configured
//     window
//   - rejected_reason is INTERNAL ONLY — never surfaced through the
//     MC-facing status endpoint
//   - Fingerprints are scoped per-mc; the SAME fingerprint can validly
//     exist across different MCs but cannot be re-submitted within one
//     MC after rotation or rejection (forces fresh keys for fresh trust)
//
// Centralising these rules in one module means the routes are thin
// shells around audit logging and HTTP response shaping, and any
// future code path that mutates signing_keys (admin tool, CLI,
// migration) calls into the same enforcement.
//
// PRIVACY OF REJECTION DETAILS
//
// The rejected_reason column captures detail for the GD audit trail and
// for CISO inspection via the admin list endpoints. The MC-facing
// status-query endpoint (getStatusForMc / used by Commit 21) returns
// ONLY the bare status string with no timestamps, no reason, no
// approver identity. An attacker with a stolen api_key probing the
// status endpoint cannot learn anything about the CISO's operational
// reasoning. Constant-time response shape across pending / approved /
// rejected states plus rate limiting (below) prevent the endpoint
// from being a reconnaissance surface.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

// ── Error codes (stable strings, suitable for audit log values) ────────────
const CODES = Object.freeze({
  INVALID_INPUT:              'INVALID_INPUT',
  INVALID_PEM:                'INVALID_PEM',
  FINGERPRINT_MISMATCH:       'FINGERPRINT_MISMATCH',
  MC_NOT_FOUND:               'MC_NOT_FOUND',
  KEY_NOT_FOUND:              'KEY_NOT_FOUND',
  KEY_MC_MISMATCH:            'KEY_MC_MISMATCH',
  KEY_PREVIOUSLY_ROTATED:     'KEY_PREVIOUSLY_ROTATED',
  KEY_PREVIOUSLY_REJECTED:    'KEY_PREVIOUSLY_REJECTED',
  INVALID_STATE:              'INVALID_STATE',
  INVALID_REASON:             'INVALID_REASON',
  RATE_LIMITED:               'RATE_LIMITED',
});

class SigningKeysError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'SigningKeysError';
    this.code = code;
    this.details = details;
  }
}

const FINGERPRINT_RE = /^[0-9a-f]{64}$/;
const REASON_MAX_LEN = 500;
const VALID_ROLES = Object.freeze(['ciso', 'signing_key_approver']);

// ── Public-key utilities ──────────────────────────────────────────────────

/**
 * computePublicKeyFingerprint(publicKeyPem)
 *
 * SHA-256 hex of the SPKI DER bytes. 64 lowercase hex chars. Stable
 * across PEM whitespace and line-ending normalization. Mirrors the
 * MC's gd-push-signing-keys.computePublicKeyFingerprint so an operator
 * can grep one fingerprint string across both sides of the trust
 * channel.
 *
 * Throws SigningKeysError(INVALID_PEM) on bad input.
 */
function computePublicKeyFingerprint(publicKeyPem) {
  if (typeof publicKeyPem !== 'string' || !publicKeyPem.trim()) {
    throw new SigningKeysError(CODES.INVALID_PEM, 'public_key must be a non-empty PEM string');
  }
  let keyObj;
  try {
    keyObj = crypto.createPublicKey(publicKeyPem);
  } catch (err) {
    throw new SigningKeysError(CODES.INVALID_PEM, `failed to parse public_key PEM: ${err.message}`);
  }
  const der = keyObj.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// ── DB-level helpers (private) ────────────────────────────────────────────

function getMcRow(db, mcId) {
  return db.prepare(
    "SELECT id, name, status FROM management_consoles WHERE id = ? AND status = 'active'"
  ).get(mcId);
}

function getKeyRow(db, keyId) {
  return db.prepare(`
    SELECT id, mc_id, public_key, public_key_fingerprint, is_active,
           registered_at, rotated_out_at, notes, approval_status,
           approved_at, approved_by_user_id, approved_by_role,
           rejected_at, rejected_reason
    FROM signing_keys
    WHERE id = ?
  `).get(keyId);
}

function getKeyByFingerprintForMc(db, mcId, fingerprint) {
  return db.prepare(`
    SELECT id, mc_id, public_key_fingerprint, is_active, rotated_out_at,
           approval_status
    FROM signing_keys
    WHERE mc_id = ? AND public_key_fingerprint = ?
  `).get(mcId, fingerprint);
}

// ── Public API: state transitions ─────────────────────────────────────────

/**
 * submitPending(db, { mcId, publicKey, publicKeyFingerprint })
 *
 * Register a new public key for an MC, landing it as pending_approval.
 * Server-side recomputes the fingerprint from publicKey and rejects
 * any mismatch with the supplied publicKeyFingerprint (prevents the
 * caller from claiming a fingerprint that doesn't match the key bytes
 * — which would silently work here but fail later at verification
 * time when the GD verifier hashes the actual key bytes).
 *
 * Idempotency:
 *   - Same fingerprint already pending for this MC: returns
 *     { ok: true, action: 'idempotent_pending', id }
 *   - Same fingerprint already approved (currently active) for this
 *     MC: returns { ok: true, action: 'idempotent_approved', id }
 *
 * Rejects:
 *   - Same fingerprint exists but was previously rotated out (a key
 *     can't be re-resurrected from the dead — operator must generate
 *     a fresh keypair): KEY_PREVIOUSLY_ROTATED
 *   - Same fingerprint exists but was previously rejected: a rejected
 *     key has been deemed untrustworthy by the CISO, re-submitting
 *     the same bytes would imply re-trying the same trust decision:
 *     KEY_PREVIOUSLY_REJECTED. The operator must rotate to a fresh
 *     keypair locally and re-submit that.
 *
 * Returns: {
 *   ok: true,
 *   action: 'submitted' | 'idempotent_pending' | 'idempotent_approved',
 *   id: keyId,
 *   fingerprint: <computed fingerprint, always set>,
 * }
 *
 * Throws SigningKeysError on validation or DB errors.
 */
function submitPending(db, { mcId, publicKey, publicKeyFingerprint }) {
  if (!mcId || typeof mcId !== 'string') {
    throw new SigningKeysError(CODES.INVALID_INPUT, 'mcId is required');
  }
  if (!publicKey || typeof publicKey !== 'string') {
    throw new SigningKeysError(CODES.INVALID_INPUT, 'publicKey is required');
  }
  if (!publicKeyFingerprint || typeof publicKeyFingerprint !== 'string') {
    throw new SigningKeysError(CODES.INVALID_INPUT, 'publicKeyFingerprint is required');
  }
  if (!FINGERPRINT_RE.test(publicKeyFingerprint)) {
    throw new SigningKeysError(
      CODES.INVALID_INPUT,
      'publicKeyFingerprint must be 64 lowercase hex chars'
    );
  }

  const computed = computePublicKeyFingerprint(publicKey);
  if (computed !== publicKeyFingerprint) {
    throw new SigningKeysError(
      CODES.FINGERPRINT_MISMATCH,
      'publicKeyFingerprint does not match computed fingerprint of public_key',
      { computed }
    );
  }

  const mc = getMcRow(db, mcId);
  if (!mc) {
    throw new SigningKeysError(
      CODES.MC_NOT_FOUND,
      'mcId does not resolve to an active management console'
    );
  }

  // Look for any existing row with this fingerprint for this MC.
  const existing = getKeyByFingerprintForMc(db, mcId, computed);

  if (existing) {
    if (existing.approval_status === 'pending_approval') {
      return {
        ok: true,
        action: 'idempotent_pending',
        id: existing.id,
        fingerprint: computed,
      };
    }
    if (existing.approval_status === 'approved' && existing.is_active === 1) {
      return {
        ok: true,
        action: 'idempotent_approved',
        id: existing.id,
        fingerprint: computed,
      };
    }
    if (existing.approval_status === 'approved' && existing.rotated_out_at) {
      throw new SigningKeysError(
        CODES.KEY_PREVIOUSLY_ROTATED,
        'this key was previously approved for this MC and has been rotated out; generate a fresh keypair and re-submit'
      );
    }
    if (existing.approval_status === 'rejected') {
      throw new SigningKeysError(
        CODES.KEY_PREVIOUSLY_REJECTED,
        'this key was previously rejected for this MC; generate a fresh keypair and re-submit'
      );
    }
    // Defensive: unknown approval_status combination.
    throw new SigningKeysError(
      CODES.INVALID_STATE,
      `existing key with fingerprint ${computed} is in unexpected state`,
      { existingId: existing.id, status: existing.approval_status, isActive: existing.is_active }
    );
  }

  // No existing row — insert as pending_approval.
  const result = db.prepare(`
    INSERT INTO signing_keys
      (mc_id, public_key, public_key_fingerprint, is_active,
       approval_status, notes)
    VALUES (?, ?, ?, 0, 'pending_approval', 'submitted via /api/mc/:id/signing-key')
  `).run(mcId, publicKey, computed);

  return {
    ok: true,
    action: 'submitted',
    id: result.lastInsertRowid,
    fingerprint: computed,
  };
}

/**
 * approve(db, { keyId, userId, userRole })
 *
 * Approve a pending signing-key registration. Atomically demotes any
 * currently-active key for the same MC (sets is_active=0,
 * rotated_out_at=now, KEEPS approval_status='approved' so the
 * verifier's grace-window query can match the demoted row during the
 * configured window) and promotes the target row (sets is_active=1,
 * approval_status='approved', approved_at, approved_by_user_id,
 * approved_by_role).
 *
 * Returns: {
 *   ok: true,
 *   action: 'approved_initial' | 'approved_replacement',
 *   keyId,
 *   fingerprint,
 *   mcId,
 *   priorKeyId: number | null,
 *   priorFingerprint: string | null,
 * }
 *
 * Throws SigningKeysError on validation failure or state mismatch.
 */
function approve(db, { keyId, userId, userRole }) {
  if (!Number.isInteger(keyId) || keyId <= 0) {
    throw new SigningKeysError(CODES.INVALID_INPUT, 'keyId must be a positive integer');
  }
  if (!userId || typeof userId !== 'string') {
    throw new SigningKeysError(CODES.INVALID_INPUT, 'userId is required');
  }
  if (!VALID_ROLES.includes(userRole)) {
    throw new SigningKeysError(
      CODES.INVALID_INPUT,
      `userRole must be one of: ${VALID_ROLES.join(', ')}`
    );
  }

  const row = getKeyRow(db, keyId);
  if (!row) {
    throw new SigningKeysError(CODES.KEY_NOT_FOUND, `signing_keys.id=${keyId} not found`);
  }
  if (row.approval_status !== 'pending_approval') {
    throw new SigningKeysError(
      CODES.INVALID_STATE,
      `cannot approve row in state '${row.approval_status}' (only pending_approval is approvable)`
    );
  }
  const mc = getMcRow(db, row.mc_id);
  if (!mc) {
    throw new SigningKeysError(
      CODES.MC_NOT_FOUND,
      `signing_keys.mc_id=${row.mc_id} does not resolve to an active management console`
    );
  }

  // Atomic: demote prior + promote target. Both happen or neither.
  const txn = db.transaction(() => {
    const prior = db.prepare(`
      SELECT id, public_key_fingerprint
      FROM signing_keys
      WHERE mc_id = ? AND is_active = 1 AND id != ?
    `).get(row.mc_id, keyId);

    if (prior) {
      db.prepare(`
        UPDATE signing_keys
        SET is_active = 0,
            rotated_out_at = datetime('now')
        WHERE id = ?
      `).run(prior.id);
    }

    db.prepare(`
      UPDATE signing_keys
      SET is_active = 1,
          approval_status = 'approved',
          approved_at = datetime('now'),
          approved_by_user_id = ?,
          approved_by_role = ?
      WHERE id = ?
    `).run(userId, userRole, keyId);

    return {
      priorKeyId: prior ? prior.id : null,
      priorFingerprint: prior ? prior.public_key_fingerprint : null,
    };
  });

  const { priorKeyId, priorFingerprint } = txn();

  return {
    ok: true,
    action: priorKeyId ? 'approved_replacement' : 'approved_initial',
    keyId,
    fingerprint: row.public_key_fingerprint,
    mcId: row.mc_id,
    priorKeyId,
    priorFingerprint,
  };
}

/**
 * reject(db, { keyId, userId, userRole, reason })
 *
 * Reject a pending signing-key registration. Sets approval_status to
 * 'rejected', records rejected_at and rejected_reason (INTERNAL ONLY —
 * never surfaced to the MC). Does NOT touch is_active (it stays at 0,
 * the row never becomes verifiable).
 *
 * reason is required and ≤500 chars. The reason is captured for the
 * audit trail but the MC-facing status-query endpoint returns only
 * the bare 'rejected' status with no reason — see getStatusForMc.
 *
 * Returns: { ok: true, keyId, fingerprint, mcId }
 *
 * Throws SigningKeysError on validation failure or state mismatch.
 */
function reject(db, { keyId, userId, userRole, reason }) {
  if (!Number.isInteger(keyId) || keyId <= 0) {
    throw new SigningKeysError(CODES.INVALID_INPUT, 'keyId must be a positive integer');
  }
  if (!userId || typeof userId !== 'string') {
    throw new SigningKeysError(CODES.INVALID_INPUT, 'userId is required');
  }
  if (!VALID_ROLES.includes(userRole)) {
    throw new SigningKeysError(
      CODES.INVALID_INPUT,
      `userRole must be one of: ${VALID_ROLES.join(', ')}`
    );
  }
  if (!reason || typeof reason !== 'string') {
    throw new SigningKeysError(CODES.INVALID_REASON, 'reason is required');
  }
  const trimmedReason = reason.trim();
  if (!trimmedReason) {
    throw new SigningKeysError(CODES.INVALID_REASON, 'reason cannot be empty after trimming');
  }
  if (trimmedReason.length > REASON_MAX_LEN) {
    throw new SigningKeysError(
      CODES.INVALID_REASON,
      `reason exceeds maximum length of ${REASON_MAX_LEN} characters`
    );
  }

  const row = getKeyRow(db, keyId);
  if (!row) {
    throw new SigningKeysError(CODES.KEY_NOT_FOUND, `signing_keys.id=${keyId} not found`);
  }
  if (row.approval_status !== 'pending_approval') {
    throw new SigningKeysError(
      CODES.INVALID_STATE,
      `cannot reject row in state '${row.approval_status}' (only pending_approval is rejectable)`
    );
  }

  db.prepare(`
    UPDATE signing_keys
    SET approval_status = 'rejected',
        rejected_at = datetime('now'),
        rejected_reason = ?
    WHERE id = ?
  `).run(trimmedReason, keyId);

  return {
    ok: true,
    keyId,
    fingerprint: row.public_key_fingerprint,
    mcId: row.mc_id,
  };
}

// ── Public API: query paths ───────────────────────────────────────────────

/**
 * listPending(db)
 *
 * All signing-key submissions across all active MCs that are awaiting
 * approval. For the CISO/signing_key_approver dashboard view.
 *
 * Returns: array of {
 *   id, mcId, mcName, fingerprint, submittedAt
 * }
 * ordered by submittedAt DESC (newest first).
 */
function listPending(db) {
  const rows = db.prepare(`
    SELECT sk.id,
           sk.mc_id,
           mc.name AS mc_name,
           sk.public_key_fingerprint,
           sk.registered_at
    FROM signing_keys sk
    INNER JOIN management_consoles mc ON mc.id = sk.mc_id
    WHERE sk.approval_status = 'pending_approval'
      AND mc.status = 'active'
    ORDER BY sk.registered_at DESC
  `).all();

  return rows.map(r => ({
    id: r.id,
    mcId: r.mc_id,
    mcName: r.mc_name,
    fingerprint: r.public_key_fingerprint,
    submittedAt: r.registered_at,
  }));
}

/**
 * listForMc(db, mcId, statusFilter)
 *
 * All signing keys for a specific MC, optionally filtered by status.
 * Includes the per-row approval / rejection metadata (suitable for
 * admin display, not MC-facing — rejected_reason IS included here).
 *
 * Returns: array of {
 *   id, fingerprint, isActive, approvalStatus,
 *   registeredAt, rotatedOutAt,
 *   approvedAt, approvedByUserId, approvedByRole,
 *   rejectedAt, rejectedReason,
 *   notes,
 * }
 */
function listForMc(db, mcId, statusFilter) {
  const mc = getMcRow(db, mcId);
  if (!mc) {
    throw new SigningKeysError(CODES.MC_NOT_FOUND, 'mcId does not resolve to an active MC');
  }

  let rows;
  if (statusFilter) {
    if (!['pending_approval', 'approved', 'rejected'].includes(statusFilter)) {
      throw new SigningKeysError(
        CODES.INVALID_INPUT,
        `statusFilter must be one of: pending_approval, approved, rejected`
      );
    }
    rows = db.prepare(`
      SELECT id, public_key_fingerprint, is_active, approval_status,
             registered_at, rotated_out_at,
             approved_at, approved_by_user_id, approved_by_role,
             rejected_at, rejected_reason, notes
      FROM signing_keys
      WHERE mc_id = ? AND approval_status = ?
      ORDER BY registered_at DESC
    `).all(mcId, statusFilter);
  } else {
    rows = db.prepare(`
      SELECT id, public_key_fingerprint, is_active, approval_status,
             registered_at, rotated_out_at,
             approved_at, approved_by_user_id, approved_by_role,
             rejected_at, rejected_reason, notes
      FROM signing_keys
      WHERE mc_id = ?
      ORDER BY registered_at DESC
    `).all(mcId);
  }

  return rows.map(r => ({
    id: r.id,
    fingerprint: r.public_key_fingerprint,
    isActive: r.is_active === 1,
    approvalStatus: r.approval_status,
    registeredAt: r.registered_at,
    rotatedOutAt: r.rotated_out_at,
    approvedAt: r.approved_at,
    approvedByUserId: r.approved_by_user_id,
    approvedByRole: r.approved_by_role,
    rejectedAt: r.rejected_at,
    rejectedReason: r.rejected_reason,
    notes: r.notes,
  }));
}

/**
 * getStatusForMc(db, { mcId, keyId })
 *
 * MC-facing minimal status query. Returns ONLY the bare approval_status
 * string (or null if not found). No timestamps, no reasons, no approver
 * identity, no notes. The route that wraps this (Commit 21) collapses
 * "not found" and "rejected" into the same response shape so the
 * endpoint can't be used to enumerate keyIds across MCs.
 *
 * Validates that keyId belongs to mcId — a stolen api_key for MC-A
 * cannot probe the status of keys registered against MC-B.
 *
 * Returns: { status: 'pending_approval' | 'approved' | 'rejected' } or
 * { status: null } if the keyId doesn't belong to this mc.
 */
function getStatusForMc(db, { mcId, keyId }) {
  if (!mcId || typeof mcId !== 'string') {
    throw new SigningKeysError(CODES.INVALID_INPUT, 'mcId is required');
  }
  if (!Number.isInteger(keyId) || keyId <= 0) {
    throw new SigningKeysError(CODES.INVALID_INPUT, 'keyId must be a positive integer');
  }
  const row = db.prepare(`
    SELECT approval_status
    FROM signing_keys
    WHERE id = ? AND mc_id = ?
  `).get(keyId, mcId);
  return { status: row ? row.approval_status : null };
}

// ── Status-query rate limiter (in-memory token bucket) ────────────────────
//
// The MC polls /api/mc/me/signing-key-status on every push tick. To
// prevent an attacker who has a stolen api_key from using the
// endpoint to enumerate key state at high frequency, we cap the rate
// per (mcId, keyId) tuple.
//
// Token bucket parameters:
//   capacity = 5 tokens (allows brief burst from a restart or retry)
//   refill   = 1 token / 60 seconds (sustained rate of 1 query/min)
//
// One bucket per (mcId, keyId). Buckets are kept in-process; map keys
// expire after 1 hour of inactivity to bound memory.
//
// In a multi-replica deployment, this is per-replica. For v1.0.33 the
// GD is single-replica; multi-replica handling is deferred to PR4+.
//
// The limiter is exposed via `checkRateLimit(mcId, keyId)` returning
// { allowed: bool, retryAfterSeconds?: number }. Callers (Commit 21
// route) translate this into 429 + Retry-After header.

const BUCKET_CAPACITY = 5;
const BUCKET_REFILL_MS = 60_000;       // 1 token per minute
const BUCKET_EXPIRY_MS = 60 * 60_000;  // drop unused buckets after 1 hour
const __buckets = new Map();
let __lastCleanup = Date.now();

function _cleanupBuckets(nowMs) {
  if (nowMs - __lastCleanup < BUCKET_EXPIRY_MS / 4) return;
  __lastCleanup = nowMs;
  for (const [key, bucket] of __buckets.entries()) {
    if (nowMs - bucket.lastTouchMs > BUCKET_EXPIRY_MS) {
      __buckets.delete(key);
    }
  }
}

function checkRateLimit(mcId, keyId, nowMs) {
  const ts = nowMs || Date.now();
  _cleanupBuckets(ts);

  const key = `${mcId}:${keyId}`;
  let bucket = __buckets.get(key);
  if (!bucket) {
    bucket = { tokens: BUCKET_CAPACITY, lastRefillMs: ts, lastTouchMs: ts };
    __buckets.set(key, bucket);
  } else {
    const elapsed = ts - bucket.lastRefillMs;
    const refill = Math.floor(elapsed / BUCKET_REFILL_MS);
    if (refill > 0) {
      bucket.tokens = Math.min(BUCKET_CAPACITY, bucket.tokens + refill);
      bucket.lastRefillMs += refill * BUCKET_REFILL_MS;
    }
    bucket.lastTouchMs = ts;
  }

  if (bucket.tokens > 0) {
    bucket.tokens -= 1;
    return { allowed: true };
  }

  // Compute retry-after: time until next refill produces a token.
  const msSinceLastRefill = ts - bucket.lastRefillMs;
  const msUntilNextToken = BUCKET_REFILL_MS - msSinceLastRefill;
  return { allowed: false, retryAfterSeconds: Math.ceil(msUntilNextToken / 1000) };
}

// Test-only helper — resets all buckets. Not exported by default.
function _resetRateLimiter() {
  __buckets.clear();
  __lastCleanup = Date.now();
}

module.exports = {
  CODES,
  SigningKeysError,
  computePublicKeyFingerprint,
  submitPending,
  approve,
  reject,
  listPending,
  listForMc,
  getStatusForMc,
  checkRateLimit,
  // exported for tests:
  _resetRateLimiter,
};

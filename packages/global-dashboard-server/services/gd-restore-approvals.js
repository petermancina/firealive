// ===============================================================================
// FIREALIVE -- Restore Approvals Service
//
// Per-request workflow for two-person restore approval. Companion to
// services/restore-approval-policy.js (which holds the global mode and
// window configuration). This service handles individual approval
// records: create, look up, approve, deny, expire, and consume.
//
// LIFECYCLE
//
//   pending  -> approved -> consumed   (happy path)
//   pending  -> denied                 (admin rejection -- terminal)
//   pending  -> expired                (sweeper passed expiry -- terminal)
//   approved -> expired                (sweeper: approved but never consumed)
//
//   In 'disabled' policy mode, createApprovalRequest creates a record
//   already in 'approved' status with method='disabled-mode-bypass'
//   and approver==requester. The record exists for audit; the restore
//   route can immediately consume it. This keeps the API contract
//   uniform: every restore goes through the same approval-then-consume
//   flow regardless of policy mode.
//
// MODE SEMANTICS (validated in approve())
//
//   strict
//     approver_user_id MUST differ from requested_by_user_id.
//     a passkey (WebAuthn) assertion must be verified before this method is called (route's
//     responsibility -- this service trusts the mfa_verified flag).
//     approval_method = 'second-person-passkey'.
//
//   delayed-self-approval
//     Either a different admin approves any time within the window
//     (method='second-person-passkey'), OR the original requester
//     self-approves AFTER expires_at (method='delayed-self-passkey').
//     Self-approval before the window has elapsed is rejected with
//     code WINDOW_NOT_ELAPSED -- the window IS the security property.
//
//   disabled
//     Manual approve() calls are rejected with
//     DISABLED_MODE_NO_MANUAL_APPROVE -- disabled-mode requests are
//     auto-approved at creation time, so calling approve() is a
//     route-level bug.
//
// HARD EXPIRY RULES (SOC-grade bounded lifetime)
//
// All three rules are enforced by expirePending() and re-checked at
// read time by findUsableForBackup() (defense in depth):
//
//   strict pending
//     Expires at expires_at (= requested_at + approval_window_hours).
//     Past this, the request must be re-filed.
//
//   delayed-self-approval pending
//     Self-approval becomes available at expires_at; the row continues
//     to be 'pending' so the original requester can self-approve.
//     Hard expiry kicks in at expires_at + approval_window_hours
//     (= requested_at + 2 * window). Past this, the request must be
//     re-filed.
//
//   approved (any mode)
//     Must be consumed within approval_window_hours of approved_at.
//     Past this deadline, the row is swept to 'expired' and the
//     restore route refuses to consume it. This bounds the "stolen
//     approval" attack surface: a compromised admin session cannot
//     sit on an approved-but-unused approval for days/weeks before
//     using it.
//
// Total lifetime ceiling (default 24h window):
//
//   strict        : up to 1*window pending + 1*window approved = 2*window
//   delayed-self  : up to 2*window pending + 1*window approved = 3*window
//   disabled      : auto-approved at creation; up to 1*window approved
//
// Operators wanting different lifetimes adjust restore_approval_window_hours
// in the policy service. Acceptable range is policy-enforced (1 hour to
// 30 days).
//
// CONCURRENCY
//
// Mutating operations (approve, deny, expirePending, consumeApproval)
// gate on the row's current status inside the UPDATE WHERE clause and
// verify rows-affected > 0. This guards against concurrent approve+deny
// or double-consume without explicit row locking. Failures throw
// ApprovalError with code CONCURRENT_MUTATION which the caller should
// surface as 409 Conflict.
//
// AUDIT EXPECTATIONS
//
// This service does not write to audit_log. The route layer is
// responsible for emitting audit events on every state transition.
// To make audit detail construction straightforward, every mutating
// function returns an object with the relevant before/after state
// (status, actor, method, etc.) so the route can include it in the
// audit payload. expirePending separates its expired-id list by class
// (strict-pending vs delayed-self-pending-hard vs approved-consumption)
// so the scheduler can emit distinct audit event types per class.
//
// All timestamps are SQLite-format 'YYYY-MM-DD HH:MM:SS' UTC, matching
// the rest of FireAlive's schema convention. Date arithmetic in the
// SQL uses datetime(col, '+N hours') and works correctly because the
// format's lexicographic ordering coincides with chronological order.
// ===============================================================================

const crypto = require('crypto');
const policy = require('./gd-restore-approval-policy');
const keyOpPolicy = require('./gd-key-op-approval-policy');

const VALID_STATUSES = ['pending', 'approved', 'denied', 'expired', 'consumed'];
const TERMINAL_STATUSES = ['denied', 'expired', 'consumed'];

const VALID_APPROVAL_METHODS = [
  'second-person-passkey',   // mfa-stepup verifies a user-verified WebAuthn assertion
  'delayed-self-passkey',
  'disabled-mode-bypass',
];

const REASON_MAX_LENGTH = 1024;
const DENIAL_REASON_MAX_LENGTH = 1024;
const CLIENT_IP_MAX_LENGTH = 64;     // IPv6 + brackets headroom

// -- Error class ----------------------------------------------------------

/**
 * Error thrown by this service. Carries a stable string code and an
 * optional field name so the route layer can translate into precise
 * HTTP responses without string matching.
 *
 *   code        stable string (see CODES below)
 *   field       optional column / argument name when error is per-field
 *   validation  true => caller sent bad input (4xx territory)
 *   conflict    true => row was in the wrong state for this op (409)
 *   forbidden   true => mode/policy refused the operation (403)
 */
class ApprovalError extends Error {
  constructor(code, message, options = {}) {
    super(message);
    this.name = 'ApprovalError';
    this.code = code;
    this.field = options.field || null;
    this.validation = options.validation === true;
    this.conflict = options.conflict === true;
    this.forbidden = options.forbidden === true;
    this.detail = options.detail || null;
  }
}

const CODES = {
  // 4xx - bad input
  INVALID_INPUT: 'INVALID_INPUT',

  // 404 - not found
  APPROVAL_NOT_FOUND: 'APPROVAL_NOT_FOUND',

  // 409 - state conflict
  APPROVAL_NOT_PENDING: 'APPROVAL_NOT_PENDING',
  APPROVAL_NOT_APPROVED: 'APPROVAL_NOT_APPROVED',
  APPROVAL_TERMINAL: 'APPROVAL_TERMINAL',
  APPROVAL_CONSUMPTION_DEADLINE_PASSED: 'APPROVAL_CONSUMPTION_DEADLINE_PASSED',
  CONCURRENT_MUTATION: 'CONCURRENT_MUTATION',

  // 403 - mode / policy refusal
  APPROVER_SAME_AS_REQUESTER: 'APPROVER_SAME_AS_REQUESTER',
  WINDOW_NOT_ELAPSED: 'WINDOW_NOT_ELAPSED',
  DISABLED_MODE_NO_MANUAL_APPROVE: 'DISABLED_MODE_NO_MANUAL_APPROVE',
  MFA_NOT_VERIFIED: 'MFA_NOT_VERIFIED',
};

// -- Helpers --------------------------------------------------------------

/**
 * SQLite-style 'YYYY-MM-DD HH:MM:SS' UTC. Matches the format produced
 * by datetime('now') in DEFAULT clauses, which keeps string ordering
 * consistent with chronological ordering (used by the expiry sweeper).
 */
function nowSqlite() {
  const d = new Date();
  const pad = n => String(n).padStart(2, '0');
  return (
    d.getUTCFullYear() + '-' +
    pad(d.getUTCMonth() + 1) + '-' +
    pad(d.getUTCDate()) + ' ' +
    pad(d.getUTCHours()) + ':' +
    pad(d.getUTCMinutes()) + ':' +
    pad(d.getUTCSeconds())
  );
}

/**
 * Compute expires_at = now + windowHours, in SQLite format. Used for
 * the row's expires_at column at creation time. The semantic of
 * expires_at differs by mode (window-elapsed point vs hard expiry);
 * see HARD EXPIRY RULES in the header for the mode-specific
 * interpretation.
 */
function computeExpiresAt(windowHours) {
  const d = new Date(Date.now() + windowHours * 60 * 60 * 1000);
  const pad = n => String(n).padStart(2, '0');
  return (
    d.getUTCFullYear() + '-' +
    pad(d.getUTCMonth() + 1) + '-' +
    pad(d.getUTCDate()) + ' ' +
    pad(d.getUTCHours()) + ':' +
    pad(d.getUTCMinutes()) + ':' +
    pad(d.getUTCSeconds())
  );
}

/**
 * Compute a SQLite-format timestamp = base + hours. JS-side mirror of
 * the SQL datetime(base, '+N hours') call, used wherever the service
 * does deadline arithmetic outside SQL:
 *   - approve()'s consumption_deadline return value
 *   - approve()'s defense-in-depth hard-expiry check on
 *     delayed-self-approval rows
 *   - consumeApproval()'s defense-in-depth deadline check
 */
function computeAddHours(baseSqliteTimestamp, hours) {
  // Parse 'YYYY-MM-DD HH:MM:SS' as UTC. JS's Date constructor treats a
  // bare 'YYYY-MM-DD HH:MM:SS' string differently across engines, so
  // explicit conversion to ISO 8601 with 'T' and 'Z' is the safe path.
  const isoUtc = baseSqliteTimestamp.replace(' ', 'T') + 'Z';
  const baseMs = Date.parse(isoUtc);
  if (Number.isNaN(baseMs)) {
    throw new Error(`computeAddHours: cannot parse SQLite timestamp '${baseSqliteTimestamp}'`);
  }
  const d = new Date(baseMs + hours * 60 * 60 * 1000);
  const pad = n => String(n).padStart(2, '0');
  return (
    d.getUTCFullYear() + '-' +
    pad(d.getUTCMonth() + 1) + '-' +
    pad(d.getUTCDate()) + ' ' +
    pad(d.getUTCHours()) + ':' +
    pad(d.getUTCMinutes()) + ':' +
    pad(d.getUTCSeconds())
  );
}

function generateApprovalId() {
  // Match the schema's randomblob(16) entropy: 32 hex chars, no dashes.
  // We generate client-side rather than relying on the DEFAULT so we
  // can return the id from the create call without a follow-up SELECT.
  return crypto.randomBytes(16).toString('hex');
}

function requireNonEmptyString(value, name) {
  if (typeof value !== 'string' || value === '') {
    throw new ApprovalError(
      CODES.INVALID_INPUT,
      `${name} required (must be non-empty string)`,
      { field: name, validation: true },
    );
  }
}

function optionalString(value, name, maxLength) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') {
    throw new ApprovalError(
      CODES.INVALID_INPUT,
      `${name} must be string or null`,
      { field: name, validation: true },
    );
  }
  if (maxLength !== undefined && value.length > maxLength) {
    throw new ApprovalError(
      CODES.INVALID_INPUT,
      `${name} exceeds ${maxLength} chars`,
      { field: name, validation: true },
    );
  }
  return value;
}

// -- Read API -------------------------------------------------------------

/**
 * Look up a single approval row by its id. Returns the raw row or null.
 * Routes are responsible for shaping the public response.
 */
function getApproval(db, id) {
  if (typeof id !== 'string' || id === '') return null;
  return db.prepare(`
    SELECT * FROM restore_approvals WHERE id = ?
  `).get(id);
}

/**
 * List pending approvals. Default order: oldest first (FIFO display in
 * the admin queue UI).
 *
 * Options:
 *   requested_by_user_id  string  filter to one requester
 *   limit                 int     default 100
 *   offset                int     default 0
 */
function listPending(db, options = {}) {
  const limit = Number.isInteger(options.limit) && options.limit > 0
    ? Math.min(options.limit, 1000) : 100;
  const offset = Number.isInteger(options.offset) && options.offset >= 0
    ? options.offset : 0;

  const filters = ["status = 'pending'"];
  const params = [];
  if (options.requested_by_user_id) {
    filters.push('requested_by_user_id = ?');
    params.push(options.requested_by_user_id);
  }
  params.push(limit, offset);
  return db.prepare(`
    SELECT * FROM restore_approvals
    WHERE ${filters.join(' AND ')}
    ORDER BY requested_at ASC
    LIMIT ? OFFSET ?
  `).all(...params);
}

/**
 * List all approvals for one backup_id. Used by the audit / history
 * view in the admin UI: "show me every approval ever requested for
 * this backup". Returns rows ordered newest-first.
 */
function listForBackup(db, backupId, options = {}) {
  if (typeof backupId !== 'string' || backupId === '') return [];
  const limit = Number.isInteger(options.limit) && options.limit > 0
    ? Math.min(options.limit, 1000) : 100;
  const offset = Number.isInteger(options.offset) && options.offset >= 0
    ? options.offset : 0;
  return db.prepare(`
    SELECT * FROM restore_approvals
    WHERE backup_id = ?
    ORDER BY requested_at DESC
    LIMIT ? OFFSET ?
  `).all(backupId, limit, offset);
}

/**
 * R3d-5: list approvals targeting a specific (source_id, external_backup_id)
 * pair. Mirror of listForBackup for external-restore approvals.
 *
 * Returns [] for malformed input rather than throwing -- routes layer
 * has already validated the path parameters.
 */
function listForExternal(db, sourceId, externalBackupId, options = {}) {
  if (typeof sourceId !== 'string' || sourceId === '') return [];
  if (typeof externalBackupId !== 'string' || externalBackupId === '') return [];
  const limit = Number.isInteger(options.limit) && options.limit > 0
    ? Math.min(options.limit, 1000) : 100;
  const offset = Number.isInteger(options.offset) && options.offset >= 0
    ? options.offset : 0;
  return db.prepare(`
    SELECT * FROM restore_approvals
    WHERE source_id = ?
      AND external_backup_id = ?
    ORDER BY requested_at DESC
    LIMIT ? OFFSET ?
  `).all(sourceId, externalBackupId, limit, offset);
}

/**
 * Full paginated list across all statuses. Used for compliance audit
 * exports.
 *
 * Options:
 *   status      string  filter to one status (must be a VALID_STATUS)
 *   limit       int     default 100, max 1000
 *   offset      int     default 0
 */
function listAll(db, options = {}) {
  const limit = Number.isInteger(options.limit) && options.limit > 0
    ? Math.min(options.limit, 1000) : 100;
  const offset = Number.isInteger(options.offset) && options.offset >= 0
    ? options.offset : 0;

  const filters = [];
  const params = [];
  if (options.status !== undefined) {
    if (!VALID_STATUSES.includes(options.status)) {
      throw new ApprovalError(
        CODES.INVALID_INPUT,
        `status filter must be one of: ${VALID_STATUSES.join(', ')}`,
        { field: 'status', validation: true },
      );
    }
    filters.push('status = ?');
    params.push(options.status);
  }
  const whereClause = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  params.push(limit, offset);
  return db.prepare(`
    SELECT * FROM restore_approvals
    ${whereClause}
    ORDER BY requested_at DESC
    LIMIT ? OFFSET ?
  `).all(...params);
}

/**
 * Find an approval that is ready to be consumed for a given backup +
 * requester. Returns the most-recent matching row, or null.
 *
 * Used by routes/restore.js (commit 22) to look up the approval the
 * caller intends to consume in the same transaction as the chain
 * RESTORE_REQUEST entry append. The route should pass
 * requested_by_user_id = the user attempting the restore (typically
 * the original requester resuming after a separate admin's approve).
 *
 * Defense-in-depth: this function enforces the same hard-expiry rules
 * that expirePending() enforces, in case the sweeper hasn't run since
 * the deadline passed. Specifically, it requires:
 *   - status = 'approved'
 *   - consumed_at IS NULL
 *   - approved_at + approval_window_hours > now (consumption deadline
 *     has not yet passed)
 *
 * Returns the most recent matching row (ordered by approved_at DESC)
 * so that if a fresh approval exists alongside an older one, the
 * fresh one is used.
 */
function findUsableForBackup(db, args) {
  if (!args || typeof args !== 'object') return null;
  if (typeof args.backup_id !== 'string' || args.backup_id === '') return null;
  if (typeof args.requested_by_user_id !== 'string' || args.requested_by_user_id === '') return null;

  return db.prepare(`
    SELECT * FROM restore_approvals
    WHERE backup_id = ?
      AND requested_by_user_id = ?
      AND status = 'approved'
      AND consumed_at IS NULL
      AND datetime(approved_at, '+' || approval_window_hours || ' hours') > ?
    ORDER BY approved_at DESC
    LIMIT 1
  `).get(args.backup_id, args.requested_by_user_id, nowSqlite());
}

/**
 * R3d-5: find the most-recent usable approved row targeting an external
 * (source_id, external_backup_id) pair for the given requester. Mirror of
 * findUsableForBackup. Same defense-in-depth re-check inside the SQL of
 * the consumption deadline (approved_at + window > now).
 */
function findUsableForExternal(db, args) {
  if (!args || typeof args !== 'object') return null;
  if (typeof args.source_id !== 'string' || args.source_id === '') return null;
  if (typeof args.external_backup_id !== 'string' || args.external_backup_id === '') return null;
  if (typeof args.requested_by_user_id !== 'string' || args.requested_by_user_id === '') return null;

  return db.prepare(`
    SELECT * FROM restore_approvals
    WHERE source_id = ?
      AND external_backup_id = ?
      AND requested_by_user_id = ?
      AND status = 'approved'
      AND consumed_at IS NULL
      AND datetime(approved_at, '+' || approval_window_hours || ' hours') > ?
    ORDER BY approved_at DESC
    LIMIT 1
  `).get(args.source_id, args.external_backup_id, args.requested_by_user_id, nowSqlite());
}

/**
 * B6h B-3: find the most-recent usable approved row targeting a KEY OPERATION
 * (the two-person gate for a KOA). Mirror of findUsableForBackup -- approved,
 * not consumed, still within the consumption window, most recent first.
 */
function findUsableForKeyOp(db, args) {
  if (!args || typeof args !== 'object') return null;
  if (typeof args.key_op_ref !== 'string' || args.key_op_ref === '') return null;
  if (typeof args.requested_by_user_id !== 'string' || args.requested_by_user_id === '') return null;

  return db.prepare(`
    SELECT * FROM restore_approvals
    WHERE key_op_ref = ?
      AND requested_by_user_id = ?
      AND status = 'approved'
      AND consumed_at IS NULL
      AND datetime(approved_at, '+' || approval_window_hours || ' hours') > ?
    ORDER BY approved_at DESC
    LIMIT 1
  `).get(args.key_op_ref, args.requested_by_user_id, nowSqlite());
}

// -- Create ---------------------------------------------------------------

/**
 * Create a new approval request.
 *
 * Args:
 *   backup_id             string (required)
 *   requested_by_user_id  string (required)
 *   request_reason        string (optional, <=1024 chars)
 *   client_ip             string (optional, <=64 chars) -- forensic only
 *
 * Reads current policy (mode + window_hours). In strict and delayed-
 * self-approval modes, the new row starts in 'pending' status and
 * needs an approve() call to advance.
 *
 * In 'disabled' mode the new row starts in 'approved' status with
 * approval_method='disabled-mode-bypass' and approver=requester.
 * The record exists for audit; the restore route can immediately
 * call consumeApproval on it (subject to the consumption deadline).
 *
 * Returns the inserted row (full SELECT). Caller emits an audit
 * event with eventType RESTORE_APPROVAL_REQUESTED (or
 * RESTORE_APPROVAL_AUTO_APPROVED for disabled mode).
 */
function createApprovalRequest(db, args) {
  if (!args || typeof args !== 'object') {
    throw new ApprovalError(CODES.INVALID_INPUT, 'args object required', { validation: true });
  }
  requireNonEmptyString(args.requested_by_user_id, 'requested_by_user_id');

  // R3d-5: accept either a local backup_id OR an external (source_id,
  // external_backup_id) pair. The DB-level CHECK constraint enforces
  // local-XOR-external too, but service-layer validation gives the
  // route a clear typed error rather than a SqliteError.
  const hasBackupId = typeof args.backup_id === 'string' && args.backup_id !== '';
  const hasSource = typeof args.source_id === 'string' && args.source_id !== '';
  const hasExternalBackupId = typeof args.external_backup_id === 'string' && args.external_backup_id !== '';
  const hasKeyOpRef = typeof args.key_op_ref === 'string' && args.key_op_ref !== '';
  const isLocal = hasBackupId && !hasSource && !hasExternalBackupId && !hasKeyOpRef;
  const isExternal = !hasBackupId && hasSource && hasExternalBackupId && !hasKeyOpRef;
  const isKeyOp = !hasBackupId && !hasSource && !hasExternalBackupId && hasKeyOpRef;
  if (!isLocal && !isExternal && !isKeyOp) {
    throw new ApprovalError(
      CODES.INVALID_INPUT,
      'must provide exactly one of: backup_id (local restore) ' +
      'OR (source_id AND external_backup_id) (external restore) ' +
      'OR key_op_ref (key operation)',
      { validation: true },
    );
  }
  const backupId = isLocal ? args.backup_id : null;
  const sourceId = isExternal ? args.source_id : null;
  const externalBackupId = isExternal ? args.external_backup_id : null;
  const keyOpRef = isKeyOp ? args.key_op_ref : null;

  const requestReason = optionalString(args.request_reason, 'request_reason', REASON_MAX_LENGTH);
  const clientIp = optionalString(args.client_ip, 'client_ip', CLIENT_IP_MAX_LENGTH);

  // Key operations use their own approval policy (strict / delayed-self-approval
  // only -- there is no 'disabled' mode for a destructive key operation).
  const cfg = isKeyOp
    ? { mode: keyOpPolicy.getMode(db), window_hours: keyOpPolicy.getWindowHours(db) }
    : policy.getConfig(db);
  const id = generateApprovalId();
  const requestedAt = nowSqlite();
  const expiresAt = computeExpiresAt(cfg.window_hours);

  if (cfg.mode === 'disabled') {
    db.prepare(`
      INSERT INTO restore_approvals (
        id, backup_id, source_id, external_backup_id, key_op_ref,
        requested_by_user_id, requested_at, request_reason,
        status, approval_mode_at_creation, approval_window_hours,
        approved_by_user_id, approved_at, approval_method,
        expires_at, client_ip_at_request, client_ip_at_approval
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'approved', 'disabled', ?, ?, ?, 'disabled-mode-bypass', ?, ?, ?)
    `).run(
      id,
      backupId,
      sourceId,
      externalBackupId,
      keyOpRef,
      args.requested_by_user_id,
      requestedAt,
      requestReason,
      cfg.window_hours,
      args.requested_by_user_id,
      requestedAt,
      expiresAt,
      clientIp,
      clientIp,
    );
  } else {
    // strict or delayed-self-approval -- create pending row.
    db.prepare(`
      INSERT INTO restore_approvals (
        id, backup_id, source_id, external_backup_id, key_op_ref,
        requested_by_user_id, requested_at, request_reason,
        status, approval_mode_at_creation, approval_window_hours,
        expires_at, client_ip_at_request
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
    `).run(
      id,
      backupId,
      sourceId,
      externalBackupId,
      keyOpRef,
      args.requested_by_user_id,
      requestedAt,
      requestReason,
      cfg.mode,
      cfg.window_hours,
      expiresAt,
      clientIp,
    );
  }

  return getApproval(db, id);
}

// -- Approve --------------------------------------------------------------

/**
 * Approve a pending request. Validates per-mode rules:
 *
 *   strict:
 *     - approver MUST differ from requester
 *     - mfa_verified MUST be true (route's job to actually verify)
 *
 *   delayed-self-approval:
 *     - if approver == requester, expires_at MUST already be in the past
 *       (window elapsed). Otherwise WINDOW_NOT_ELAPSED.
 *     - approver may be a different admin at any time within the window
 *     - mfa_verified MUST be true
 *
 *   disabled:
 *     - this method is REJECTED with DISABLED_MODE_NO_MANUAL_APPROVE.
 *       Disabled-mode rows are auto-approved at creation; the route
 *       should not be calling approve on them.
 *
 * Defense-in-depth: also refuses approval of a row past its hard
 * expiry, even if the sweeper hasn't yet rewritten its status.
 *
 * Args:
 *   id                     string (required)
 *   approver_user_id       string (required)
 *   mfa_verified          bool   (required, must be true)
 *   client_ip              string (optional)
 *
 * Returns: { id, previous_status, new_status, approval_method,
 *            approver_user_id, approved_at, approval_mode_at_creation,
 *            requested_by_user_id, expires_at, consumption_deadline }
 *
 * consumption_deadline is the approved_at + window_hours timestamp,
 * surfaced for the route to include in audit detail and to render in
 * the admin UI ("This approval must be consumed by...").
 *
 * Throws ApprovalError with appropriate code for the route layer to
 * map to 4xx/5xx codes.
 */
function approve(db, args) {
  if (!args || typeof args !== 'object') {
    throw new ApprovalError(CODES.INVALID_INPUT, 'args object required', { validation: true });
  }
  requireNonEmptyString(args.id, 'id');
  requireNonEmptyString(args.approver_user_id, 'approver_user_id');
  if (args.mfa_verified !== true) {
    throw new ApprovalError(
      CODES.MFA_NOT_VERIFIED,
      'a passkey (WebAuthn) assertion must be verified before approval can be recorded',
      { field: 'mfa_verified', forbidden: true },
    );
  }
  const clientIp = optionalString(args.client_ip, 'client_ip', CLIENT_IP_MAX_LENGTH);

  const row = getApproval(db, args.id);
  if (!row) {
    throw new ApprovalError(CODES.APPROVAL_NOT_FOUND, `approval ${args.id} not found`);
  }
  if (row.status !== 'pending') {
    throw new ApprovalError(
      CODES.APPROVAL_NOT_PENDING,
      `approval is in '${row.status}' state, not 'pending'`,
      { conflict: true, detail: { current_status: row.status } },
    );
  }

  const now = nowSqlite();

  // Defense-in-depth hard-expiry check: refuse approval of a row past
  // its hard expiry even if the sweeper hasn't yet rewritten its
  // status. The hard expiry differs by mode -- see HARD EXPIRY RULES
  // in the header.
  if (row.approval_mode_at_creation === 'strict') {
    if (row.expires_at <= now) {
      throw new ApprovalError(
        CODES.APPROVAL_TERMINAL,
        'strict-mode approval has passed its window; submit a fresh request',
        { conflict: true, detail: { expires_at: row.expires_at, current_time: now, mode: 'strict' } },
      );
    }
  } else if (row.approval_mode_at_creation === 'delayed-self-approval') {
    // Hard expiry = expires_at + approval_window_hours from creation.
    const hardExpiry = computeAddHours(row.expires_at, row.approval_window_hours);
    if (hardExpiry <= now) {
      throw new ApprovalError(
        CODES.APPROVAL_TERMINAL,
        'delayed-self-approval row has passed its hard expiry; submit a fresh request',
        { conflict: true, detail: { hard_expires_at: hardExpiry, current_time: now, mode: 'delayed-self-approval' } },
      );
    }
  }

  const sameUser = (args.approver_user_id === row.requested_by_user_id);
  let approvalMethod;

  switch (row.approval_mode_at_creation) {
    case 'strict':
      if (sameUser) {
        throw new ApprovalError(
          CODES.APPROVER_SAME_AS_REQUESTER,
          'strict mode requires a different admin to approve',
          { forbidden: true, detail: { mode: 'strict' } },
        );
      }
      approvalMethod = 'second-person-passkey';
      break;

    case 'delayed-self-approval':
      if (sameUser) {
        if (row.expires_at > now) {
          throw new ApprovalError(
            CODES.WINDOW_NOT_ELAPSED,
            'self-approval is allowed only after the window has elapsed',
            { forbidden: true, detail: { expires_at: row.expires_at, current_time: now } },
          );
        }
        approvalMethod = 'delayed-self-passkey';
      } else {
        approvalMethod = 'second-person-passkey';
      }
      break;

    case 'disabled':
      // Disabled-mode rows are auto-approved at creation; this method
      // should not be called for them. If it is, that's a route bug.
      throw new ApprovalError(
        CODES.DISABLED_MODE_NO_MANUAL_APPROVE,
        'disabled-mode requests are auto-approved at creation; manual approve() is not applicable',
        { conflict: true, detail: { mode: 'disabled' } },
      );

    default:
      // Schema CHECK should prevent this; defensive throw.
      throw new ApprovalError(
        CODES.INVALID_INPUT,
        `unrecognized approval_mode_at_creation '${row.approval_mode_at_creation}' on row ${row.id}`,
        { detail: { row_id: row.id } },
      );
  }

  const update = db.prepare(`
    UPDATE restore_approvals
    SET status = 'approved',
        approved_by_user_id = ?,
        approved_at = ?,
        approval_method = ?,
        client_ip_at_approval = ?
    WHERE id = ? AND status = 'pending'
  `).run(args.approver_user_id, now, approvalMethod, clientIp, args.id);

  if (update.changes !== 1) {
    // Someone raced us: row was approved/denied/expired between our
    // SELECT and our UPDATE. Surface as conflict.
    throw new ApprovalError(
      CODES.CONCURRENT_MUTATION,
      'approval row changed state during approval; retry the operation',
      { conflict: true },
    );
  }

  return {
    id: row.id,
    previous_status: 'pending',
    new_status: 'approved',
    approval_method: approvalMethod,
    approver_user_id: args.approver_user_id,
    approved_at: now,
    approval_mode_at_creation: row.approval_mode_at_creation,
    requested_by_user_id: row.requested_by_user_id,
    expires_at: row.expires_at,
    consumption_deadline: computeAddHours(now, row.approval_window_hours),
  };
}

// -- Deny -----------------------------------------------------------------

/**
 * Deny a pending request. Any admin can deny (including the original
 * requester, e.g. cancelling their own request before someone else
 * approves).
 *
 * Args:
 *   id                string (required)
 *   denier_user_id    string (required)
 *   denial_reason     string (optional, <=1024 chars) -- recommended
 *                     when denying someone else's request
 *
 * Returns: { id, previous_status, new_status: 'denied',
 *            denier_user_id, denied_at, denial_reason,
 *            requested_by_user_id }
 */
function deny(db, args) {
  if (!args || typeof args !== 'object') {
    throw new ApprovalError(CODES.INVALID_INPUT, 'args object required', { validation: true });
  }
  requireNonEmptyString(args.id, 'id');
  requireNonEmptyString(args.denier_user_id, 'denier_user_id');
  const denialReason = optionalString(args.denial_reason, 'denial_reason', DENIAL_REASON_MAX_LENGTH);

  const row = getApproval(db, args.id);
  if (!row) {
    throw new ApprovalError(CODES.APPROVAL_NOT_FOUND, `approval ${args.id} not found`);
  }
  if (row.status !== 'pending') {
    throw new ApprovalError(
      CODES.APPROVAL_NOT_PENDING,
      `approval is in '${row.status}' state, not 'pending'`,
      { conflict: true, detail: { current_status: row.status } },
    );
  }

  const now = nowSqlite();
  const update = db.prepare(`
    UPDATE restore_approvals
    SET status = 'denied',
        denied_by_user_id = ?,
        denied_at = ?,
        denial_reason = ?
    WHERE id = ? AND status = 'pending'
  `).run(args.denier_user_id, now, denialReason, args.id);

  if (update.changes !== 1) {
    throw new ApprovalError(
      CODES.CONCURRENT_MUTATION,
      'approval row changed state during deny; retry the operation',
      { conflict: true },
    );
  }

  return {
    id: row.id,
    previous_status: 'pending',
    new_status: 'denied',
    denier_user_id: args.denier_user_id,
    denied_at: now,
    denial_reason: denialReason,
    requested_by_user_id: row.requested_by_user_id,
  };
}

// -- Expire (sweeper) -----------------------------------------------------

/**
 * Sweep expired approval records. Three classes of expiry, each
 * tracked separately so the scheduler / route can emit distinct
 * audit event types per class:
 *
 *   strict_pending_expired_ids
 *     'pending' rows in strict mode whose expires_at has passed.
 *     The window ran out without a second admin approving.
 *
 *   delayed_self_hard_expired_ids
 *     'pending' rows in delayed-self-approval mode whose hard expiry
 *     has passed. Hard expiry = expires_at + approval_window_hours
 *     (= 2 * window from creation). The requester had a window for
 *     a second admin to approve, then their own self-approval
 *     window after that, and used neither.
 *
 *   approved_consumption_expired_ids
 *     'approved' rows (any mode) that were never consumed before
 *     approved_at + approval_window_hours. The approval became
 *     stale before the requester ran the restore.
 *
 * All three transition to status='expired'. The class is preserved
 * via the sweeper's return value so the audit trail records the
 * specific reason an approval expired.
 *
 * Returns:
 *   {
 *     expired_count: int,
 *     strict_pending_expired_ids: string[],
 *     delayed_self_hard_expired_ids: string[],
 *     approved_consumption_expired_ids: string[]
 *   }
 *
 * Sweep is wrapped in a single transaction so partial failures don't
 * leave the database half-swept. SQLite's WAL mode tolerates the
 * brief write lock for the typical sweep size (<100 rows).
 */
function expirePending(db) {
  const now = nowSqlite();

  // Class 1: strict-mode pending past expires_at
  const strictPendingCandidates = db.prepare(`
    SELECT id FROM restore_approvals
    WHERE status = 'pending'
      AND approval_mode_at_creation = 'strict'
      AND expires_at <= ?
  `).all(now);

  // Class 2: delayed-self-approval pending past hard expiry
  // (= expires_at + approval_window_hours)
  const delayedSelfHardCandidates = db.prepare(`
    SELECT id FROM restore_approvals
    WHERE status = 'pending'
      AND approval_mode_at_creation = 'delayed-self-approval'
      AND datetime(expires_at, '+' || approval_window_hours || ' hours') <= ?
  `).all(now);

  // Class 3: approved rows past consumption deadline
  // (= approved_at + approval_window_hours)
  const approvedConsumptionCandidates = db.prepare(`
    SELECT id FROM restore_approvals
    WHERE status = 'approved'
      AND consumed_at IS NULL
      AND datetime(approved_at, '+' || approval_window_hours || ' hours') <= ?
  `).all(now);

  if (strictPendingCandidates.length === 0
      && delayedSelfHardCandidates.length === 0
      && approvedConsumptionCandidates.length === 0) {
    return {
      expired_count: 0,
      strict_pending_expired_ids: [],
      delayed_self_hard_expired_ids: [],
      approved_consumption_expired_ids: [],
    };
  }

  const txn = db.transaction(() => {
    const stmtPending = db.prepare(`
      UPDATE restore_approvals
      SET status = 'expired'
      WHERE id = ? AND status = 'pending'
    `);
    const stmtApproved = db.prepare(`
      UPDATE restore_approvals
      SET status = 'expired'
      WHERE id = ? AND status = 'approved' AND consumed_at IS NULL
    `);

    const out = {
      strict_pending_expired_ids: [],
      delayed_self_hard_expired_ids: [],
      approved_consumption_expired_ids: [],
    };
    for (const { id } of strictPendingCandidates) {
      if (stmtPending.run(id).changes === 1) out.strict_pending_expired_ids.push(id);
    }
    for (const { id } of delayedSelfHardCandidates) {
      if (stmtPending.run(id).changes === 1) out.delayed_self_hard_expired_ids.push(id);
    }
    for (const { id } of approvedConsumptionCandidates) {
      if (stmtApproved.run(id).changes === 1) out.approved_consumption_expired_ids.push(id);
    }
    return out;
  });
  const out = txn();
  return {
    expired_count: out.strict_pending_expired_ids.length
                 + out.delayed_self_hard_expired_ids.length
                 + out.approved_consumption_expired_ids.length,
    strict_pending_expired_ids: out.strict_pending_expired_ids,
    delayed_self_hard_expired_ids: out.delayed_self_hard_expired_ids,
    approved_consumption_expired_ids: out.approved_consumption_expired_ids,
  };
}

// -- Consume --------------------------------------------------------------

/**
 * Mark an approved approval as 'consumed' to record that a restore
 * has actually used it. Called from routes/restore.js (commit 22)
 * inside the same transaction as the chain RESTORE_REQUEST entry
 * append. The chain_request_entry_id forensic anchor links the
 * approval to the chain entry that documents the destructive
 * operation that ran under it.
 *
 * Defense-in-depth: also refuses consumption past the consumption
 * deadline (= approved_at + approval_window_hours), even if the
 * sweeper hasn't yet rewritten the row's status. Surfaces as
 * APPROVAL_CONSUMPTION_DEADLINE_PASSED so the route can emit a
 * specific audit event before refusing the restore.
 *
 * Idempotency rules:
 *   - If status='approved' and within deadline: transition to
 *     'consumed', record consumed_at and chain_request_entry_id.
 *     Returns success.
 *   - If status='approved' but past deadline: refuses with
 *     APPROVAL_CONSUMPTION_DEADLINE_PASSED. The route should fail
 *     the restore.
 *   - If status='consumed': throw APPROVAL_TERMINAL (single-use).
 *   - If 'denied' / 'expired' / 'pending': throw
 *     APPROVAL_NOT_APPROVED.
 *
 * Args:
 *   id                       string (required)
 *   chain_request_entry_id   integer (required, positive)
 *
 * Returns: { id, previous_status, new_status: 'consumed', consumed_at,
 *            chain_request_entry_id, requested_by_user_id, backup_id }
 */
function consumeApproval(db, args) {
  if (!args || typeof args !== 'object') {
    throw new ApprovalError(CODES.INVALID_INPUT, 'args object required', { validation: true });
  }
  requireNonEmptyString(args.id, 'id');
  if (!Number.isInteger(args.chain_request_entry_id) || args.chain_request_entry_id <= 0) {
    throw new ApprovalError(
      CODES.INVALID_INPUT,
      'chain_request_entry_id required (must be positive integer)',
      { field: 'chain_request_entry_id', validation: true },
    );
  }

  const row = getApproval(db, args.id);
  if (!row) {
    throw new ApprovalError(CODES.APPROVAL_NOT_FOUND, `approval ${args.id} not found`);
  }
  if (row.status === 'consumed') {
    throw new ApprovalError(
      CODES.APPROVAL_TERMINAL,
      'approval has already been consumed; each approval is single-use',
      { conflict: true, detail: { current_status: row.status } },
    );
  }
  if (row.status !== 'approved') {
    throw new ApprovalError(
      CODES.APPROVAL_NOT_APPROVED,
      `approval is in '${row.status}' state, not 'approved'`,
      { conflict: true, detail: { current_status: row.status } },
    );
  }

  const now = nowSqlite();

  // Defense-in-depth: refuse consume past deadline even if the sweeper
  // hasn't yet caught the row. The route should treat this as a hard
  // failure and require a fresh approval.
  const consumptionDeadline = computeAddHours(row.approved_at, row.approval_window_hours);
  if (consumptionDeadline <= now) {
    throw new ApprovalError(
      CODES.APPROVAL_CONSUMPTION_DEADLINE_PASSED,
      'consumption deadline has passed; the approval is stale, submit a fresh request',
      { conflict: true, detail: {
        approved_at: row.approved_at,
        consumption_deadline: consumptionDeadline,
        current_time: now,
      } },
    );
  }

  const update = db.prepare(`
    UPDATE restore_approvals
    SET status = 'consumed',
        consumed_at = ?,
        chain_request_entry_id = ?
    WHERE id = ? AND status = 'approved' AND consumed_at IS NULL
  `).run(now, args.chain_request_entry_id, args.id);

  if (update.changes !== 1) {
    throw new ApprovalError(
      CODES.CONCURRENT_MUTATION,
      'approval row changed state during consume; refusing restore',
      { conflict: true },
    );
  }

  return {
    id: row.id,
    previous_status: 'approved',
    new_status: 'consumed',
    consumed_at: now,
    chain_request_entry_id: args.chain_request_entry_id,
    requested_by_user_id: row.requested_by_user_id,
    backup_id: row.backup_id,
  };
}

// -- Module exports -------------------------------------------------------

module.exports = {
  // Read API
  getApproval,
  listPending,
  listForBackup,
  listForExternal,
  listAll,
  findUsableForBackup,
  findUsableForExternal,
  findUsableForKeyOp,

  // Write API
  createApprovalRequest,
  approve,
  deny,
  expirePending,
  consumeApproval,

  // Error class + codes
  ApprovalError,
  CODES,

  // Constants exposed for routes / tests
  VALID_STATUSES,
  TERMINAL_STATUSES,
  VALID_APPROVAL_METHODS,
  REASON_MAX_LENGTH,
  DENIAL_REASON_MAX_LENGTH,

  // Helpers exposed for tests only -- not for production callers
  _internal: {
    nowSqlite,
    computeExpiresAt,
    computeAddHours,
    generateApprovalId,
  },
};

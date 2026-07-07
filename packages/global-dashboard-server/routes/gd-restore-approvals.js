// ============================================================================
// FIREALIVE GLOBAL DASHBOARD -- Restore Approval Admin Routes
//
// HTTP API in front of services/gd-restore-approvals.js. The destructive
// restore paths (POST /api/restore/execute/:id and /execute-chain/:id in
// routes/gd-restore.js, and POST /api/external-restore/restore-execute/
// :approvalId) consume approval rows; this file lets CISO admins create,
// review, approve, and deny them. Without it the delayed-self-approval and
// strict approval modes have no way to obtain an approval_id, so the
// destructive restore paths are only reachable in disabled mode.
//
// Endpoints:
//   POST   /api/restore-approvals                       create request
//   GET    /api/restore-approvals/pending               queue
//   GET    /api/restore-approvals/by-backup/:backupId   history per backup
//   GET    /api/restore-approvals                       list w/ filters
//   GET    /api/restore-approvals/:id                   single
//   POST   /api/restore-approvals/:id/approve           step-up required
//   POST   /api/restore-approvals/:id/deny              deny
//
// Auth model:
//   Mounted with authMiddleware(['ciso']) in index.js, matching the rest of
//   the GD restore family, so every reachable caller is a CISO admin and
//   there are no per-endpoint role gates. The two-person guarantee is
//   enforced by the service, not by roles: approve() rejects an approver
//   equal to the requester in strict mode, and permits requester
//   self-approval only after the window elapses in the single-CISO
//   delayed-self-approval default.
//
// Step-up gate (approve only):
//   approvalsSvc.approve() requires totp_verified=true. This route satisfies
//   it with a fresh, user-verified WebAuthn assertion via the gdMfaStepUp
//   middleware (body.stepup = { challengeToken, response }) BEFORE delegating
//   to the service. A step-up failure short-circuits in the middleware and
//   never touches the approval row -- exactly how the MC restore-approvals
//   route treats its own mfaStepUp gate.
//
// AGPL-3.0-or-later
// ============================================================================

const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const approvalsSvc = require('../services/gd-restore-approvals');
const { gdMfaStepUp } = require('../services/gd-mfa-stepup');

const MAX_LIMIT = 1000;
const DEFAULT_LIMIT = 100;
const REASON_MAX_LENGTH = approvalsSvc.REASON_MAX_LENGTH || 1024;
const DENIAL_REASON_MAX_LENGTH = approvalsSvc.DENIAL_REASON_MAX_LENGTH || 1024;

// Local audit helper mirroring routes/gd-restore.js: append a tamper-evident
// entry to the GD audit chain. Read-only endpoints rely on the global audit
// middleware and do not log here to avoid duplicate entries.
function auditLog(userId, eventType, detail, ip) {
  try {
    appendGdAuditEntry(getDb(), { userId, eventType, detail, ip });
  } catch (e) {
    console.error('restore-approval audit append failed:', e.message);
  }
}

function parseIntOrDefault(value, defaultValue, min, max) {
  if (value === undefined || value === null || value === '') return defaultValue;
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return defaultValue;
  if (typeof min === 'number' && n < min) return min;
  if (typeof max === 'number' && n > max) return max;
  return n;
}

// Map ApprovalError code -> HTTP status. Mirrors the table in
// services/gd-restore-approvals.js and routes/gd-restore.js; kept duplicated
// because the mapping is part of this route's API contract.
function approvalCodeToHttpStatus(code) {
  switch (code) {
    case approvalsSvc.CODES.INVALID_INPUT:
      return 400;
    case approvalsSvc.CODES.APPROVAL_NOT_FOUND:
      return 404;
    case approvalsSvc.CODES.APPROVAL_NOT_PENDING:
    case approvalsSvc.CODES.APPROVAL_NOT_APPROVED:
    case approvalsSvc.CODES.APPROVAL_TERMINAL:
    case approvalsSvc.CODES.APPROVAL_CONSUMPTION_DEADLINE_PASSED:
    case approvalsSvc.CODES.CONCURRENT_MUTATION:
    case approvalsSvc.CODES.DISABLED_MODE_NO_MANUAL_APPROVE:
      return 409;
    case approvalsSvc.CODES.APPROVER_SAME_AS_REQUESTER:
    case approvalsSvc.CODES.WINDOW_NOT_ELAPSED:
    case approvalsSvc.CODES.TOTP_NOT_VERIFIED:
      return 403;
    default:
      return 500;
  }
}

function sendApprovalError(res, err) {
  const status = approvalCodeToHttpStatus(err.code);
  const body = { error: err.message, code: err.code };
  if (err.detail !== undefined) body.detail = err.detail;
  res.status(status).json(body);
}

// -- POST /api/restore-approvals -- create approval request ------------------
//
// Body: { backup_id: string (required), request_reason?: string (<=1024) }
// The requester is taken from req.user.id; the body cannot override it. In
// disabled mode the created row is already status='approved'; in
// delayed-self-approval / strict it is 'pending'. Response: 201 with the row.
router.post('/', (req, res) => {
  const body = req.body || {};
  const backupId = body.backup_id;
  const requestReason = body.request_reason;

  if (typeof backupId !== 'string' || backupId === '') {
    return res.status(400).json({ error: 'backup_id is required and must be a non-empty string', code: 'INVALID_INPUT' });
  }
  if (requestReason !== undefined && requestReason !== null) {
    if (typeof requestReason !== 'string') {
      return res.status(400).json({ error: 'request_reason must be a string when provided', code: 'INVALID_INPUT' });
    }
    if (requestReason.length > REASON_MAX_LENGTH) {
      return res.status(400).json({ error: `request_reason must be <= ${REASON_MAX_LENGTH} chars`, code: 'INVALID_INPUT' });
    }
  }

  const db = getDb();
  try {
    // Verify the backup exists before creating an approval for it. The
    // service doesn't enforce this -- it is a route-layer concern.
    const backup = db.prepare('SELECT id FROM backups WHERE id = ?').get(backupId);
    if (!backup) {
      return res.status(404).json({ error: `backup ${backupId} not found`, code: 'BACKUP_NOT_FOUND' });
    }
    const row = approvalsSvc.createApprovalRequest(db, {
      backup_id: backupId,
      requested_by_user_id: req.user.id,
      request_reason: requestReason || null,
      client_ip: req.ip || null,
    });
    auditLog(req.user.id, 'RESTORE_APPROVAL_CREATED',
      `id=${row.id} backup_id=${backupId} mode=${row.approval_mode_at_creation}`, req.ip);
    return res.status(201).json(row);
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) return sendApprovalError(res, err);
    console.error('Restore approval create failed:', err.message);
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// -- GET /api/restore-approvals/pending -- approval queue --------------------
router.get('/pending', (req, res) => {
  const limit = parseIntOrDefault(req.query.limit, DEFAULT_LIMIT, 1, MAX_LIMIT);
  const offset = parseIntOrDefault(req.query.offset, 0, 0);
  const requestedBy = (typeof req.query.requested_by_user_id === 'string' && req.query.requested_by_user_id)
    ? req.query.requested_by_user_id : undefined;
  try {
    const rows = approvalsSvc.listPending(getDb(), { limit, offset, requested_by_user_id: requestedBy });
    return res.json({ items: rows, count: rows.length, limit, offset });
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) return sendApprovalError(res, err);
    console.error('Restore approval list-pending failed:', err.message);
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// -- GET /api/restore-approvals/by-backup/:backupId --------------------------
router.get('/by-backup/:backupId', (req, res) => {
  const limit = parseIntOrDefault(req.query.limit, DEFAULT_LIMIT, 1, MAX_LIMIT);
  const offset = parseIntOrDefault(req.query.offset, 0, 0);
  try {
    const rows = approvalsSvc.listForBackup(getDb(), req.params.backupId, { limit, offset });
    return res.json({ items: rows, count: rows.length, limit, offset });
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) return sendApprovalError(res, err);
    console.error('Restore approval list-for-backup failed:', err.message);
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// -- GET /api/restore-approvals -- list across all statuses ------------------
router.get('/', (req, res) => {
  const limit = parseIntOrDefault(req.query.limit, DEFAULT_LIMIT, 1, MAX_LIMIT);
  const offset = parseIntOrDefault(req.query.offset, 0, 0);
  const statusFilter = (typeof req.query.status === 'string' && req.query.status) ? req.query.status : undefined;
  try {
    const rows = approvalsSvc.listAll(getDb(), { limit, offset, status: statusFilter });
    return res.json({ items: rows, count: rows.length, limit, offset });
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) return sendApprovalError(res, err);
    console.error('Restore approval list-all failed:', err.message);
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// -- GET /api/restore-approvals/:id -- single approval -----------------------
router.get('/:id', (req, res) => {
  try {
    const row = approvalsSvc.getApproval(getDb(), req.params.id);
    if (!row) {
      return res.status(404).json({ error: `approval ${req.params.id} not found`, code: 'APPROVAL_NOT_FOUND' });
    }
    return res.json(row);
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) return sendApprovalError(res, err);
    console.error('Restore approval get failed:', err.message);
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// -- POST /api/restore-approvals/:id/approve -- step-up required -------------
//
// A fresh user-verified WebAuthn step-up (gdMfaStepUp) satisfies the
// service's totp_verified=true guard. The service enforces the per-mode
// rules: strict requires approver != requester; delayed-self-approval permits
// requester self-approval only after the window elapses; disabled always
// rejects (rows are auto-approved at creation).
router.post('/:id/approve', gdMfaStepUp(), (req, res) => {
  const db = getDb();
  const ip = req.ip || null;
  try {
    const result = approvalsSvc.approve(db, {
      id: req.params.id,
      approver_user_id: req.user.id,
      totp_verified: true,
      client_ip: ip,
    });
    auditLog(req.user.id, 'RESTORE_APPROVAL_APPROVED',
      `id=${result.id} requester=${result.requested_by_user_id} ` +
      `mode=${result.approval_mode_at_creation} method=${result.approval_method}`, ip);
    return res.json(result);
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) {
      auditLog(req.user.id, 'RESTORE_APPROVAL_APPROVE_REJECTED',
        `approval_id=${req.params.id} reason=${err.code}`, ip);
      return sendApprovalError(res, err);
    }
    console.error('Restore approval approve failed:', err.message);
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// -- POST /api/restore-approvals/:id/deny ------------------------------------
//
// Body: { denial_reason?: string (<=1024) }
router.post('/:id/deny', (req, res) => {
  const body = req.body || {};
  const denialReason = body.denial_reason;
  if (denialReason !== undefined && denialReason !== null) {
    if (typeof denialReason !== 'string') {
      return res.status(400).json({ error: 'denial_reason must be a string when provided', code: 'INVALID_INPUT' });
    }
    if (denialReason.length > DENIAL_REASON_MAX_LENGTH) {
      return res.status(400).json({ error: `denial_reason must be <= ${DENIAL_REASON_MAX_LENGTH} chars`, code: 'INVALID_INPUT' });
    }
  }
  const db = getDb();
  const ip = req.ip || null;
  try {
    const result = approvalsSvc.deny(db, {
      id: req.params.id,
      denier_user_id: req.user.id,
      denial_reason: denialReason || null,
      client_ip: ip,
    });
    auditLog(req.user.id, 'RESTORE_APPROVAL_DENIED', `id=${result.id}`, ip);
    return res.json(result);
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) return sendApprovalError(res, err);
    console.error('Restore approval deny failed:', err.message);
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

module.exports = router;

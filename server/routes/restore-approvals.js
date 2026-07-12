// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Restore Approval Admin Routes
//
// HTTP API in front of services/restore-approvals.js. The destructive restore
// path (POST /api/restore/execute/:id, in routes/restore.js) consumes approval
// rows; this file lets admins manage them.
//
// Endpoints:
//   POST   /api/restore-approvals                        create request
//   GET    /api/restore-approvals/pending                queue (admin/lead)
//   GET    /api/restore-approvals/by-backup/:backupId    history per backup
//   GET    /api/restore-approvals                        list w/ filters
//   GET    /api/restore-approvals/:id                    single (admin/lead OR
//                                                         original requester)
//   POST   /api/restore-approvals/:id/approve            admin + step-up required
//   POST   /api/restore-approvals/:id/deny               admin/lead
//
// Auth model:
//   This file is mounted with authMiddleware(['analyst', 'lead', 'admin'])
//   in server/index.js -- any authenticated app user can reach the namespace.
//   Per-endpoint role enforcement happens here via checkRole(). Pattern
//   matches how routes/team.js etc. are scoped at mount but tighten per-
//   handler when needed.
//
// Step-up gate (approve only):
//   The service contract for approvalsSvc.approve() requires
//   mfa_verified=true. This route satisfies it with a fresh,
//   user-verified WebAuthn step-up assertion (the mfaStepUp middleware)
//   supplied in body.stepup BEFORE delegating to the service. A step-up
//   failure short-circuits in the middleware (401/400) and never touches
//   the approval row.
//
// Audit log:
//   Every state-changing operation writes a RESTORE_APPROVAL_* event via
//   middleware/audit's auditLog. Read-only operations (list/get) are
//   covered by the global auditMiddleware in index.js and do not log
//   here to avoid duplicate entries.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const approvalsSvc = require('../services/restore-approvals');
const { mfaStepUp } = require('../middleware/mfa-stepup');
const { quarantineGuard } = require('../middleware/quarantine-guard');

// ── Validation + helpers ─────────────────────────────────────────────────────

const MAX_LIMIT = 1000;
const DEFAULT_LIMIT = 100;
const REASON_MAX_LENGTH = approvalsSvc.REASON_MAX_LENGTH || 1024;
const DENIAL_REASON_MAX_LENGTH = approvalsSvc.DENIAL_REASON_MAX_LENGTH || 1024;

function parseIntOrDefault(value, defaultValue, min, max) {
  if (value === undefined || value === null || value === '') return defaultValue;
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return defaultValue;
  if (typeof min === 'number' && n < min) return min;
  if (typeof max === 'number' && n > max) return max;
  return n;
}

function checkRole(req, res, allowedRoles) {
  if (!req.user || !allowedRoles.includes(req.user.role)) {
    res.status(403).json({
      error: 'insufficient permissions for this operation',
      code: 'FORBIDDEN',
      detail: { required_roles: allowedRoles },
    });
    return false;
  }
  return true;
}

// Map ApprovalError code -> HTTP status. Mirrors the table in
// services/restore-approvals.js header and routes/restore.js. Kept
// duplicated rather than extracted to a shared util because the
// mapping is part of each route's API contract; one file's choices
// shouldn't silently change another's response codes.
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
    case approvalsSvc.CODES.MFA_NOT_VERIFIED:
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

// ── POST /api/restore-approvals — create approval request ────────────────────
//
// Body:
//   { backup_id: string (required), request_reason?: string (<=1024) }
//
// Auth: any authenticated user (analyst/lead/admin). The requester is
// taken from req.user.id; the body cannot override it.
//
// Response: 201 with the new approval row.
router.post('/', (req, res) => {
  const body = req.body || {};
  const backupId = body.backup_id;
  const requestReason = body.request_reason;

  if (typeof backupId !== 'string' || backupId === '') {
    return res.status(400).json({
      error: 'backup_id is required and must be a non-empty string',
      code: 'INVALID_INPUT',
    });
  }
  if (requestReason !== undefined && requestReason !== null) {
    if (typeof requestReason !== 'string') {
      return res.status(400).json({
        error: 'request_reason must be a string when provided',
        code: 'INVALID_INPUT',
      });
    }
    if (requestReason.length > REASON_MAX_LENGTH) {
      return res.status(400).json({
        error: `request_reason must be <= ${REASON_MAX_LENGTH} chars`,
        code: 'INVALID_INPUT',
      });
    }
  }

  const db = getDb();
  try {
    // Verify the backup exists before creating an approval for it.
    // The service doesn't enforce this -- it's a route-layer concern.
    const backup = db.prepare('SELECT id FROM backups WHERE id = ?').get(backupId);
    if (!backup) {
      return res.status(404).json({
        error: `backup ${backupId} not found`,
        code: 'BACKUP_NOT_FOUND',
      });
    }

    const row = approvalsSvc.createApprovalRequest(db, {
      backup_id: backupId,
      requested_by_user_id: req.user.id,
      request_reason: requestReason || null,
      client_ip: req.ip || null,
    });

    auditLog(
      req.user.id,
      'RESTORE_APPROVAL_CREATED',
      `id=${row.id} backup_id=${backupId} mode=${row.approval_mode_at_creation}`,
      req.ip,
    );
    logger.info('Restore approval created', {
      id: row.id,
      backup_id: backupId,
      requested_by_user_id: req.user.id,
      mode: row.approval_mode_at_creation,
    });

    return res.status(201).json(row);
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) {
      return sendApprovalError(res, err);
    }
    logger.error('Restore approval create failed', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── GET /api/restore-approvals/pending — admin queue ─────────────────────────
//
// Auth: admin or lead.
// Query: ?limit=N (1-1000, default 100), ?offset=N (default 0),
//        ?requested_by_user_id=ID (optional filter)
router.get('/pending', (req, res) => {
  if (!checkRole(req, res, ['admin', 'lead'])) return;

  const limit = parseIntOrDefault(req.query.limit, DEFAULT_LIMIT, 1, MAX_LIMIT);
  const offset = parseIntOrDefault(req.query.offset, 0, 0);
  const requestedBy = (typeof req.query.requested_by_user_id === 'string' && req.query.requested_by_user_id)
    ? req.query.requested_by_user_id : undefined;

  try {
    const rows = approvalsSvc.listPending(getDb(), {
      limit,
      offset,
      requested_by_user_id: requestedBy,
    });
    return res.json({ items: rows, count: rows.length, limit, offset });
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) return sendApprovalError(res, err);
    logger.error('Restore approval list-pending failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── GET /api/restore-approvals/by-backup/:backupId ──────────────────────────
//
// Auth: admin or lead.
// Returns all approvals (any status) for one backup, newest first. Used
// by the audit / history view.
router.get('/by-backup/:backupId', (req, res) => {
  if (!checkRole(req, res, ['admin', 'lead'])) return;

  const limit = parseIntOrDefault(req.query.limit, DEFAULT_LIMIT, 1, MAX_LIMIT);
  const offset = parseIntOrDefault(req.query.offset, 0, 0);

  try {
    const rows = approvalsSvc.listForBackup(getDb(), req.params.backupId, { limit, offset });
    return res.json({ items: rows, count: rows.length, limit, offset });
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) return sendApprovalError(res, err);
    logger.error('Restore approval list-for-backup failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── GET /api/restore-approvals — list across all statuses ───────────────────
//
// Auth: admin or lead.
// Query: ?status=pending|approved|denied|expired|consumed (optional),
//        ?limit=N, ?offset=N
router.get('/', (req, res) => {
  if (!checkRole(req, res, ['admin', 'lead'])) return;

  const limit = parseIntOrDefault(req.query.limit, DEFAULT_LIMIT, 1, MAX_LIMIT);
  const offset = parseIntOrDefault(req.query.offset, 0, 0);
  const statusFilter = (typeof req.query.status === 'string' && req.query.status)
    ? req.query.status : undefined;

  try {
    const rows = approvalsSvc.listAll(getDb(), {
      limit,
      offset,
      status: statusFilter,
    });
    return res.json({ items: rows, count: rows.length, limit, offset });
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) return sendApprovalError(res, err);
    logger.error('Restore approval list-all failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── GET /api/restore-approvals/:id — single approval ────────────────────────
//
// Auth: admin/lead OR the original requester (analysts can poll their
// own request's status). Anyone else gets 403 even if authenticated.
router.get('/:id', (req, res) => {
  try {
    const row = approvalsSvc.getApproval(getDb(), req.params.id);
    if (!row) {
      return res.status(404).json({
        error: `approval ${req.params.id} not found`,
        code: 'APPROVAL_NOT_FOUND',
      });
    }

    const isAdminOrLead = req.user.role === 'admin' || req.user.role === 'lead';
    const isRequester = row.requested_by_user_id === req.user.id;
    if (!isAdminOrLead && !isRequester) {
      return res.status(403).json({
        error: 'insufficient permissions to view this approval',
        code: 'FORBIDDEN',
      });
    }

    return res.json(row);
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) return sendApprovalError(res, err);
    logger.error('Restore approval get failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/restore-approvals/:id/approve — admin + step-up ────────────
//
// Auth: admin only, plus a fresh WebAuthn step-up assertion.
// Body: { stepup: { challengeToken, response } }  (verified by mfaStepUp)
//
// Flow:
//   1. approveAdminGate -- refuse non-admins (403) before any step-up
//      processing, so the step-up surface is admin-only
//   2. mfaStepUp() -- require a fresh user-verified WebAuthn assertion; a
//      failure short-circuits in the middleware (401/400) and never
//      touches the approval row
//   3. Delegate to approvalsSvc.approve() with mfa_verified=true -- the
//      service's "a second factor was verified" guard, now satisfied by
//      the step-up middleware
//   4. Audit log RESTORE_APPROVAL_APPROVED on success
//
// The service enforces the per-mode rules:
//   strict                 approver must differ from requester
//   delayed-self-approval  approver may be requester only after window elapsed
//   disabled               this method always rejects (auto-approved at creation)

// Admin-gate middleware: 403 before any step-up processing, so non-admins
// never reach (or can probe) the step-up verification.
function approveAdminGate(req, res, next) {
  if (!checkRole(req, res, ['admin'])) return;
  next();
}

router.post('/:id/approve', approveAdminGate, quarantineGuard(), mfaStepUp(), (req, res) => {
  const db = getDb();
  const ip = req.ip || null;

  // The step-up middleware already verified a fresh user-verified assertion,
  // so delegate straight to the service.
  try {
    const result = approvalsSvc.approve(db, {
      id: req.params.id,
      approver_user_id: req.user.id,
      mfa_verified: true,
      client_ip: ip,
    });

    auditLog(
      req.user.id,
      'RESTORE_APPROVAL_APPROVED',
      `id=${result.id} requester=${result.requested_by_user_id} ` +
      `mode=${result.approval_mode_at_creation} method=${result.approval_method} ` +
      `consumption_deadline=${result.consumption_deadline}`,
      ip,
    );
    logger.info('Restore approval approved', {
      id: result.id,
      approver_user_id: req.user.id,
      requested_by_user_id: result.requested_by_user_id,
      mode: result.approval_mode_at_creation,
    });

    return res.json(result);
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) {
      auditLog(
        req.user.id,
        'RESTORE_APPROVAL_APPROVE_REJECTED',
        `approval_id=${req.params.id} reason=${err.code}`,
        ip,
      );
      return sendApprovalError(res, err);
    }
    logger.error('Restore approval approve failed', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});


// ── POST /api/restore-approvals/:id/deny ────────────────────────────────────
//
// Auth: admin or lead.
// Body: { denial_reason?: string (<=1024) }
router.post('/:id/deny', (req, res) => {
  if (!checkRole(req, res, ['admin', 'lead'])) return;

  const body = req.body || {};
  const denialReason = body.denial_reason;
  if (denialReason !== undefined && denialReason !== null) {
    if (typeof denialReason !== 'string') {
      return res.status(400).json({
        error: 'denial_reason must be a string when provided',
        code: 'INVALID_INPUT',
      });
    }
    if (denialReason.length > DENIAL_REASON_MAX_LENGTH) {
      return res.status(400).json({
        error: `denial_reason must be <= ${DENIAL_REASON_MAX_LENGTH} chars`,
        code: 'INVALID_INPUT',
      });
    }
  }

  try {
    const result = approvalsSvc.deny(getDb(), {
      id: req.params.id,
      denier_user_id: req.user.id,
      denial_reason: denialReason || null,
    });

    auditLog(
      req.user.id,
      'RESTORE_APPROVAL_DENIED',
      `id=${result.id} requester=${result.requested_by_user_id} ` +
      (denialReason ? `reason_provided=true` : `reason_provided=false`),
      req.ip,
    );
    logger.info('Restore approval denied', {
      id: result.id,
      denier_user_id: req.user.id,
      requested_by_user_id: result.requested_by_user_id,
    });

    return res.json(result);
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) {
      return sendApprovalError(res, err);
    }
    logger.error('Restore approval deny failed', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

module.exports = router;

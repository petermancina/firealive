'use strict';

// FIREALIVE (Global Dashboard) -- /api/key-ops routes (B6h B-3)
//
// GD twin of server/routes/key-ops.js. It authorizes a destructive key operation
// on the GD, reusing the two-person gd-restore-approvals engine (key_op_ref target)
// and the gd-key-op-authorization primitive.
//
// Role separation (two-person via distinct roles, stronger than user-id alone):
//   - request / authorize require 'ciso'
//   - approve requires 'signing_key_approver' (the role segregated for signing-key
//     approval), so the approver is not the same principal that requested.
// The engine also rejects approver == requester by user id. The router is mounted
// with authMiddleware(['ciso', 'signing_key_approver']) and the GD's global
// /api config-lock chokepoint gates writes; /api/key-ops is in the GD config-write
// list. Every mutating endpoint additionally requires a fresh WebAuthn step-up.

const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const approvalsSvc = require('../services/gd-restore-approvals');
const koaSvc = require('../services/gd-key-op-authorization');
const { gdMfaStepUp } = require('../services/gd-mfa-stepup');

function auditLog(userId, eventType, detail, ip) {
  try { appendGdAuditEntry(getDb(), { userId: userId, eventType: eventType, detail: detail, ip: ip }); }
  catch (e) { console.error('key-op audit append failed:', e.message); }
}

function requireRole(role) {
  return function (req, res, next) {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: role + ' role required', code: 'FORBIDDEN' });
    }
    next();
  };
}
const cisoGate = requireRole('ciso');
const signingApproverGate = requireRole('signing_key_approver');

function nonEmpty(v) { return typeof v === 'string' && v !== ''; }

// POST /api/key-ops/request  { op, key_op_ref }  -- ciso + step-up
router.post('/request', cisoGate, gdMfaStepUp(), (req, res) => {
  const db = getDb();
  const ip = req.ip || null;
  const op = req.body && req.body.op;
  const keyOpRef = req.body && req.body.key_op_ref;
  if (!nonEmpty(op) || !koaSvc.VALID_OPS.includes(op)) {
    return res.status(400).json({ error: 'op must be one of: ' + koaSvc.VALID_OPS.join(', '), code: 'INVALID_INPUT' });
  }
  if (!nonEmpty(keyOpRef)) {
    return res.status(400).json({ error: 'key_op_ref required', code: 'INVALID_INPUT' });
  }
  try {
    const row = approvalsSvc.createApprovalRequest(db, {
      key_op_ref: keyOpRef,
      requested_by_user_id: req.user.id,
      request_reason: nonEmpty(req.body.request_reason) ? req.body.request_reason : null,
      client_ip: ip,
    });
    auditLog(req.user.id, 'KEY_OP_APPROVAL_REQUESTED', `id=${row.id} op=${op} ref=${keyOpRef} mode=${row.approval_mode_at_creation}`, ip);
    return res.status(201).json({ approval: row, op: op });
  } catch (e) {
    if (e instanceof approvalsSvc.ApprovalError) return res.status(e.code === approvalsSvc.CODES.INVALID_INPUT ? 400 : 500).json({ error: e.message, code: e.code });
    return res.status(500).json({ error: e.message, code: 'ERROR' });
  }
});

// POST /api/key-ops/:id/approve  -- signing_key_approver + step-up
router.post('/:id/approve', signingApproverGate, gdMfaStepUp(), (req, res) => {
  const db = getDb();
  const ip = req.ip || null;
  try {
    const result = approvalsSvc.approve(db, {
      id: req.params.id,
      approver_user_id: req.user.id,
      mfa_verified: true,
      client_ip: ip,
    });
    auditLog(req.user.id, 'KEY_OP_APPROVAL_APPROVED', `id=${result.id} requester=${result.requested_by_user_id} method=${result.approval_method}`, ip);
    return res.json({ approval: result });
  } catch (e) {
    if (e instanceof approvalsSvc.ApprovalError) return res.status(mapApprovalStatus(e)).json({ error: e.message, code: e.code });
    return res.status(500).json({ error: e.message, code: 'ERROR' });
  }
});

// POST /api/key-ops/authorize  { op, key_op_ref, approval_id }  -- ciso + step-up
router.post('/authorize', cisoGate, gdMfaStepUp(), (req, res) => {
  const db = getDb();
  const ip = req.ip || null;
  const b = req.body || {};
  if (!nonEmpty(b.op) || !nonEmpty(b.key_op_ref) || !nonEmpty(b.approval_id)) {
    return res.status(400).json({ error: 'op, key_op_ref, and approval_id required', code: 'INVALID_INPUT' });
  }
  try {
    const koa = koaSvc.mintKoa(db, {
      op: b.op,
      key_op_ref: b.key_op_ref,
      approval_id: b.approval_id,
      requested_by_user_id: req.user.id,
      ttl_ms: typeof b.ttl_ms === 'number' ? b.ttl_ms : undefined,
    });
    auditLog(req.user.id, 'KEY_OP_AUTHORIZED', `koa=${koa.id} op=${koa.op} ref=${koa.key_op_ref} approval=${koa.approval_id} expires=${koa.expires_at}`, ip);
    return res.status(201).json({ koa: koa });
  } catch (e) {
    const status = (e && (e.code === 'NO_APPROVAL' || e.code === 'APPROVAL_MISMATCH')) ? 409
      : (e && e.code === 'INVALID_INPUT') ? 400 : 500;
    return res.status(status).json({ error: e.message, code: (e && e.code) || 'ERROR' });
  }
});

// GET /api/key-ops/:id  -- ciso, read-only
router.get('/:id', cisoGate, (req, res) => {
  const db = getDb();
  const koa = koaSvc.getKoa(db, req.params.id);
  if (!koa) return res.status(404).json({ error: 'KOA not found', code: 'NOT_FOUND' });
  return res.json({ koa: koa });
});

function mapApprovalStatus(e) {
  if (!e || !e.code) return 500;
  switch (e.code) {
    case approvalsSvc.CODES.INVALID_INPUT: return 400;
    case approvalsSvc.CODES.APPROVAL_NOT_FOUND: return 404;
    case approvalsSvc.CODES.APPROVAL_NOT_PENDING:
    case approvalsSvc.CODES.APPROVAL_TERMINAL:
    case approvalsSvc.CODES.APPROVAL_CONSUMPTION_DEADLINE_PASSED:
    case approvalsSvc.CODES.CONCURRENT_MUTATION: return 409;
    case approvalsSvc.CODES.APPROVER_SAME_AS_REQUESTER:
    case approvalsSvc.CODES.WINDOW_NOT_ELAPSED:
    case approvalsSvc.CODES.MFA_NOT_VERIFIED: return 403;
    default: return 500;
  }
}

module.exports = router;

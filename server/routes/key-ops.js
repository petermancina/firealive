'use strict';

// FIREALIVE -- /api/key-ops routes (B6h B-3)
//
// The operator surface for authorizing a destructive key operation (a rekey, a
// migration-import re-seal, a deployment reset). It reuses the two-person
// restore-approvals engine (key_op_ref target) for the request/approve gate and
// the key-op-authorization primitive to mint the anchor-signed, single-use KOA
// the offline rekey tool consumes.
//
// Gating (defence in depth): this router is mounted with authMiddleware(['admin'])
// AND configLockChokepoint() in index.js, and /api/key-ops is in
// CONFIG_WRITE_MOUNTS -- so a key operation can only be authorized by an admin,
// with the configuration lock open. Every mutating endpoint additionally requires
// a fresh user-verified WebAuthn step-up (mfaStepUp). The engine's second-person
// rule enforces that the approver differs from the requester.

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const approvalsSvc = require('../services/restore-approvals');
const koaSvc = require('../services/key-op-authorization');
const { mfaStepUp } = require('../middleware/mfa-stepup');

function adminGate(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'admin role required', code: 'FORBIDDEN' });
  }
  next();
}

function nonEmpty(v) { return typeof v === 'string' && v !== ''; }

// POST /api/key-ops/request  { op, key_op_ref }
// Create the two-person approval that gates a key operation. admin + step-up.
router.post('/request', adminGate, mfaStepUp(), (req, res) => {
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
    logger.info('Key-op approval requested', { id: row.id, op: op, requester: req.user.id });
    return res.status(201).json({ approval: row, op: op });
  } catch (e) {
    return res.status(e && e.code === 'INVALID_INPUT' ? 400 : 500).json({ error: e.message, code: (e && e.code) || 'ERROR' });
  }
});

// POST /api/key-ops/:id/approve
// A SECOND admin approves the pending request. admin + step-up; the engine rejects
// approver === requester.
router.post('/:id/approve', adminGate, mfaStepUp(), (req, res) => {
  const db = getDb();
  const ip = req.ip || null;
  try {
    const result = approvalsSvc.approve(db, {
      id: req.params.id,
      approver_user_id: req.user.id,
      stepup_verified: true,
      client_ip: ip,
    });
    auditLog(req.user.id, 'KEY_OP_APPROVAL_APPROVED', `id=${result.id} requester=${result.requested_by_user_id} method=${result.approval_method}`, ip);
    logger.info('Key-op approval approved', { id: result.id, approver: req.user.id });
    return res.json({ approval: result });
  } catch (e) {
    return res.status(mapApprovalStatus(e)).json({ error: e.message, code: (e && e.code) || 'ERROR' });
  }
});

// POST /api/key-ops/authorize  { op, key_op_ref, approval_id }
// Mint the anchor-signed, single-use KOA once the approval is approved. admin +
// step-up. mintKoa refuses without a usable approval whose id matches.
router.post('/authorize', adminGate, mfaStepUp(), (req, res) => {
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
    logger.info('Key operation authorized (KOA minted)', { koa: koa.id, op: koa.op, by: req.user.id });
    return res.status(201).json({ koa: koa });
  } catch (e) {
    const status = (e && (e.code === 'NO_APPROVAL' || e.code === 'APPROVAL_MISMATCH')) ? 409
      : (e && e.code === 'INVALID_INPUT') ? 400 : 500;
    return res.status(status).json({ error: e.message, code: (e && e.code) || 'ERROR' });
  }
});

// GET /api/key-ops/:id
// Retrieve a minted KOA (e.g., to hand to the offline rekey tool). admin, read-only.
router.get('/:id', adminGate, (req, res) => {
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
    case approvalsSvc.CODES.STEPUP_NOT_VERIFIED: return 403;
    default: return 500;
  }
}

module.exports = router;

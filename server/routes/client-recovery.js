// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Per-Client AC Recovery Routes (B5d4)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The admin HTTP surface for tearing down and re-provisioning a single
// compromised analyst client. Mounted at /api/client-recovery under
// authMiddleware(['admin']) (server/index.js). Destructive recovery is
// two-operator (dual-control): one operator REQUESTS the action and a
// different operator -- or the GD -- APPROVES it before anything executes, so
// a single compromised MC cannot evict an analyst on its own. Every request
// and approval is signed by the operator's hardware device key
// (mc-device-action) on top of the admin session + a restore-class MFA
// step-up, and every action is audited. All identity here is pseudonym-only
// -- a userId is an opaque UUID used to target the action, never a name.
//
//   POST /teardown              request eviction of one AC; recorded as a
//                               pending dual-control action. Body:
//                               { userId, reason? }. Returns 202 + approval id.
//   POST /reprovision           request a single-use re-provision token for one
//                               analyst; recorded as pending. Body: { userId }.
//   GET  /approvals             pending requests awaiting co-approval.
//   POST /approvals/:id/approve a DISTINCT second operator co-signs and the
//                               action runs (reprovision returns the plaintext
//                               token ONCE for secure delivery).
//   POST /approvals/:id/reject  decline a pending request.
//   GET  /connected             connected analyst clients (recovery targets)
//                               mapped to pseudonym + liveness.
//   GET  /runs                  recovery-run history (paginated).
//   GET  /runs/:id              a single recovery run.
//
// Teardown/reprovision execution lives in services/client-recovery.js; the
// dual-control lifecycle lives in services/recovery-approvals.js. This layer
// validates input, maps service error codes to HTTP, and writes the audit
// trail.
// ─────────────────────────────────────────────────────────────────────────────

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { mfaStepUp } = require('../middleware/mfa-stepup');
const { requireDeviceAction } = require('../middleware/mc-device-action');
const { recoveryRateLimit } = require('../middleware/recovery-rate-limit');
const recovery = require('../services/client-recovery');
const approvals = require('../services/recovery-approvals');

const RUN_COLUMNS =
  'id, user_id, pseudonym_at_run, status, initiated_by, reason, ' +
  'certs_revoked_json, device_key_retired, passkey_deleted, wipe_dispatched, ' +
  'enrollment_token_id, created_at, updated_at, completed_at';

function mapServiceError(res, err, fallback) {
  const code = err && err.code;
  if (code === 'USER_NOT_FOUND') return res.status(404).json({ error: 'analyst not found' });
  if (code === 'NOT_AN_ANALYST') return res.status(400).json({ error: err.message });
  if (code === 'INVALID_ACTION' || code === 'INVALID_APPROVAL_KIND') return res.status(400).json({ error: err.message });
  if (code === 'PENDING_EXISTS') return res.status(409).json({ error: err.message });
  if (code === 'NOT_FOUND') return res.status(404).json({ error: 'approval request not found' });
  if (code === 'ALREADY_DECIDED' || code === 'CONFLICT') return res.status(409).json({ error: err.message });
  if (code === 'EXPIRED') return res.status(410).json({ error: err.message });
  if (code === 'SELF_APPROVAL') return res.status(403).json({ error: err.message });
  logger.error(fallback.log, { error: err && err.message });
  return res.status(500).json({ error: fallback.msg });
}

// ── POST /teardown ───────────────────────────────────────────────────────────
router.post('/teardown', mfaStepUp(), requireDeviceAction('recovery.teardown', (req) => req.body && req.body.userId), recoveryRateLimit('teardown'), (req, res) => {
  const userId = req.body && req.body.userId;
  const reason = (req.body && req.body.reason) || null;
  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ error: 'userId (string) required' });
  }
  const db = getDb();
  try {
    const pending = approvals.createPending(db, {
      action: 'teardown',
      targetUserId: userId,
      requestedBy: req.user.id,
      requesterFingerprint: req.deviceAction && req.deviceAction.fingerprint,
      reason: reason
    });
    auditLog(
      req.user.id,
      'AC_TEARDOWN_REQUESTED',
      'teardown requested for ' + userId + ' (approval ' + pending.id +
        '); awaiting second-operator co-approval',
      req.ip
    );
    return res.status(202).json({ ok: true, status: 'pending', approval: pending });
  } catch (err) {
    return mapServiceError(res, err, { log: 'AC teardown request failed', msg: 'teardown request failed' });
  } finally {
    db.close();
  }
});

// ── POST /reprovision ────────────────────────────────────────────────────────
router.post('/reprovision', mfaStepUp(), requireDeviceAction('recovery.reprovision', (req) => req.body && req.body.userId), recoveryRateLimit('reprovision'), (req, res) => {
  const userId = req.body && req.body.userId;
  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ error: 'userId (string) required' });
  }
  const db = getDb();
  try {
    const pending = approvals.createPending(db, {
      action: 'reprovision',
      targetUserId: userId,
      requestedBy: req.user.id,
      requesterFingerprint: req.deviceAction && req.deviceAction.fingerprint
    });
    auditLog(
      req.user.id,
      'AC_REPROVISION_REQUESTED',
      'reprovision requested for ' + userId + ' (approval ' + pending.id +
        '); awaiting second-operator co-approval',
      req.ip
    );
    return res.status(202).json({ ok: true, status: 'pending', approval: pending });
  } catch (err) {
    return mapServiceError(res, err, { log: 'AC reprovision request failed', msg: 'reprovision request failed' });
  } finally {
    db.close();
  }
});

// ── GET /approvals ──────────────────────────────────────────────────────────
router.get('/approvals', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const db = getDb();
  try {
    approvals.expireStale(db);
    const pending = approvals.listPending(db, { limit: limit });
    return res.json({ pending: pending });
  } catch (err) {
    logger.error('recovery approvals list failed', { error: err.message });
    return res.status(500).json({ error: 'could not list pending approvals' });
  } finally {
    db.close();
  }
});

// ── POST /approvals/:id/approve ─────────────────────────────────────────────
// A DISTINCT second operator co-signs the pending request with their hardware
// device key; on success the underlying recovery action executes.
router.post('/approvals/:id/approve', mfaStepUp(), requireDeviceAction('recovery.approve', (req) => req.params.id), (req, res) => {
  const db = getDb();
  try {
    const wsServer = req.app && req.app.locals && req.app.locals.wsServer;
    const outcome = approvals.approve(db, {
      id: req.params.id,
      approverId: req.user.id,
      approverFingerprint: req.deviceAction && req.deviceAction.fingerprint,
      approvalKind: 'operator',
      wsServer: wsServer
    });
    auditLog(
      req.user.id,
      'AC_RECOVERY_APPROVED',
      outcome.action + ' approved for ' + outcome.targetUserId + ' (approval ' +
        outcome.id + ', run ' + outcome.result.recoveryRunId + ')',
      req.ip
    );
    // For reprovision, outcome.result carries the plaintext token, returned once.
    return res.json(Object.assign({ ok: true, action: outcome.action }, outcome.result));
  } catch (err) {
    return mapServiceError(res, err, { log: 'AC recovery approval failed', msg: 'approval failed' });
  } finally {
    db.close();
  }
});

// ── POST /approvals/:id/reject ──────────────────────────────────────────────
router.post('/approvals/:id/reject', mfaStepUp(), requireDeviceAction('recovery.reject', (req) => req.params.id), (req, res) => {
  const db = getDb();
  try {
    const outcome = approvals.reject(db, { id: req.params.id, decidedBy: req.user.id });
    auditLog(req.user.id, 'AC_RECOVERY_REJECTED', 'approval ' + outcome.id + ' rejected', req.ip);
    return res.json({ ok: true, status: outcome.status });
  } catch (err) {
    return mapServiceError(res, err, { log: 'AC recovery rejection failed', msg: 'rejection failed' });
  } finally {
    db.close();
  }
});

// ── GET /connected ───────────────────────────────────────────────────────────
router.get('/connected', (req, res) => {
  const wsServer = req.app && req.app.locals && req.app.locals.wsServer;
  if (!wsServer || !wsServer.clients || typeof wsServer.clients.entries !== 'function') {
    return res.json({ initialized: false, count: 0, clients: [] });
  }
  const sessions = [];
  for (const [userId, ws] of wsServer.clients.entries()) {
    sessions.push({ userId: userId, isAlive: !!ws.isAlive });
  }
  if (sessions.length === 0) {
    return res.json({ initialized: true, count: 0, clients: [] });
  }
  const db = getDb();
  try {
    const ids = sessions.map((s) => s.userId);
    const placeholders = ids.map(() => '?').join(',');
    const rows = db
      .prepare('SELECT id, role, pseudonym FROM users WHERE id IN (' + placeholders + ')')
      .all(...ids);
    const byId = new Map(rows.map((r) => [r.id, r]));
    // Recovery targets analyst clients; lead/admin sessions are excluded.
    const clients = [];
    for (const s of sessions) {
      const u = byId.get(s.userId);
      if (!u || u.role !== 'analyst') continue;
      clients.push({ userId: s.userId, pseudonym: u.pseudonym || null, isAlive: s.isAlive });
    }
    return res.json({ initialized: true, count: clients.length, clients: clients });
  } catch (err) {
    logger.error('client-recovery connected list failed', { error: err.message });
    return res.status(500).json({ error: 'could not list connected clients' });
  } finally {
    db.close();
  }
});

// ── GET /runs ────────────────────────────────────────────────────────────────
router.get('/runs', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const db = getDb();
  try {
    const runs = db
      .prepare('SELECT ' + RUN_COLUMNS + ' FROM client_recovery_runs ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?')
      .all(limit, offset);
    return res.json({ runs: runs });
  } catch (err) {
    logger.error('client-recovery runs list failed', { error: err.message });
    return res.status(500).json({ error: 'could not list recovery runs' });
  } finally {
    db.close();
  }
});

// ── GET /runs/:id ────────────────────────────────────────────────────────────
router.get('/runs/:id', (req, res) => {
  const db = getDb();
  try {
    const run = db
      .prepare('SELECT ' + RUN_COLUMNS + ' FROM client_recovery_runs WHERE id = ?')
      .get(req.params.id);
    if (!run) return res.status(404).json({ error: 'recovery run not found' });
    return res.json({ run: run });
  } catch (err) {
    logger.error('client-recovery run fetch failed', { error: err.message });
    return res.status(500).json({ error: 'could not fetch recovery run' });
  } finally {
    db.close();
  }
});

module.exports = router;

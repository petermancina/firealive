// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Per-Client AC Recovery Routes (B5d4)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The admin HTTP surface for tearing down and re-provisioning a single
// compromised analyst client. Mounted at /api/client-recovery under
// authMiddleware(['admin']) (server/index.js). The two destructive endpoints
// additionally require a fresh MFA step-up (restore-class), and every action is
// audited. All identity in this surface is pseudonym-only -- a userId is an
// opaque UUID used to target the action, never a name; the MC renders the
// pseudonym ("Pseudonym X's AC is compromised ...").
//
//   POST /teardown        server-side eviction of one AC (revoke cert(s),
//                         retire device key, delete passkey) + best-effort
//                         local wipe. MFA step-up. Body: { userId, reason? }.
//   POST /reprovision     mint a single-use 're-provision' enrollment token
//                         for the same analyst and advance the recovery run.
//                         MFA step-up. Body: { userId }. Returns the plaintext
//                         token ONCE for secure delivery.
//   GET  /connected       connected analyst clients (recovery targets) mapped
//                         to pseudonym + liveness; lead/admin sessions excluded.
//   GET  /runs            recovery-run history (paginated).
//   GET  /runs/:id        a single recovery run.
//
// The heavy lifting lives in services/client-recovery.js; this layer validates
// input, maps service error codes to HTTP, and writes the audit trail.
// ─────────────────────────────────────────────────────────────────────────────

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { mfaStepUp } = require('../middleware/mfa-stepup');
const { requireDeviceAction } = require('../middleware/mc-device-action');
const recovery = require('../services/client-recovery');

const RUN_COLUMNS =
  'id, user_id, pseudonym_at_run, status, initiated_by, reason, ' +
  'certs_revoked_json, device_key_retired, passkey_deleted, wipe_dispatched, ' +
  'enrollment_token_id, created_at, updated_at, completed_at';

function mapServiceError(res, err, fallback) {
  if (err && err.code === 'USER_NOT_FOUND') return res.status(404).json({ error: 'analyst not found' });
  if (err && err.code === 'NOT_AN_ANALYST') return res.status(400).json({ error: err.message });
  logger.error(fallback.log, { error: err && err.message });
  return res.status(500).json({ error: fallback.msg });
}

// ── POST /teardown ───────────────────────────────────────────────────────────
router.post('/teardown', mfaStepUp(), requireDeviceAction('recovery.teardown', (req) => req.body && req.body.userId), (req, res) => {
  const userId = req.body && req.body.userId;
  const reason = (req.body && req.body.reason) || null;
  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ error: 'userId (string) required' });
  }
  const db = getDb();
  try {
    const wsServer = req.app && req.app.locals && req.app.locals.wsServer;
    const result = recovery.teardownAc(db, userId, {
      initiatedBy: req.user.id,
      reason: reason,
      wsServer: wsServer,
    });
    auditLog(
      req.user.id,
      'AC_TEARDOWN',
      'recovery run ' + result.recoveryRunId + ': revoked ' + result.certsRevoked.length +
        ' cert(s), device key retired=' + result.deviceKeyRetired +
        ', passkey(s) deleted=' + result.passkeysDeleted +
        ', wipe dispatched=' + result.wipeDispatched,
      req.ip
    );
    return res.json(Object.assign({ ok: true }, result));
  } catch (err) {
    return mapServiceError(res, err, { log: 'AC teardown failed', msg: 'teardown failed' });
  } finally {
    db.close();
  }
});

// ── POST /reprovision ────────────────────────────────────────────────────────
router.post('/reprovision', mfaStepUp(), requireDeviceAction('recovery.reprovision', (req) => req.body && req.body.userId), (req, res) => {
  const userId = req.body && req.body.userId;
  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ error: 'userId (string) required' });
  }
  const db = getDb();
  try {
    const result = recovery.reprovisionAc(db, userId, { initiatedBy: req.user.id });
    auditLog(
      req.user.id,
      'AC_REPROVISION_TOKEN_ISSUED',
      'recovery run ' + result.recoveryRunId +
        ': re-provision enrollment token issued (expires ' + result.expiresAt + ')',
      req.ip
    );
    // enrollmentToken is the plaintext, returned once for secure delivery.
    return res.json(Object.assign({ ok: true }, result));
  } catch (err) {
    return mapServiceError(res, err, { log: 'AC reprovision failed', msg: 'reprovision failed' });
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

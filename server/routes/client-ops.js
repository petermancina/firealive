// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Per-Client Fleet Operations Routes (B5d4)
//
// The lead/admin HTTP surface for fleet operations across analyst clients,
// dispatched on the B4 WebSocket substrate. Operational (not configuration), so
// mounted under authMiddleware(['lead', 'admin']) without the config lock --
// the same posture as the compromise-scan orchestration. The orchestration
// itself lives in services/client-ops.js; this layer validates, audits, and
// reports. Identity is pseudonym-only (results carry pseudonym_at_op).
//
// Endpoints (mounted at /api/client-ops; per-endpoint roles):
//   POST /dispatch          lead/admin — { op_type, targets?: 'all'|[id,...], params? }
//   GET  /runs              lead/admin — recent run history
//   GET  /runs/:id          lead/admin — one run + per-client results + queue
//   GET  /retention         admin      — read result retention window
//   PUT  /retention         admin      — set result retention window
//
// The AC's device signing key is registered once via POST /api/compromise/
// device-key and signs both compromise-scan and fleet-op results, so this
// surface has no device-key endpoint of its own.
// ═══════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const clientOps = require('../services/client-ops');

function requireRole(req, res, roles) {
  if (!req.user || !roles.includes(req.user.role)) {
    res.status(403).json({ error: 'Insufficient permissions' });
    return false;
  }
  return true;
}

const DISPATCH_ERROR_CODES = new Set(['INVALID_OP_TYPE', 'INVALID_TARGETS', 'NO_TARGETS', 'INVALID_INPUT']);

// ── POST /dispatch ───────────────────────────────────────────────────────────
router.post('/dispatch', (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) return;
  const body = req.body || {};
  const opType = body.op_type || body.opType;
  const targets = body.targets === undefined ? 'all' : body.targets;
  const params = body.params && typeof body.params === 'object' ? body.params : null;

  const db = getDb();
  try {
    const wsServer = req.app && req.app.locals && req.app.locals.wsServer;
    const result = clientOps.dispatchClientOp(db, {
      opType: opType,
      targets: targets,
      params: params,
      initiatedBy: req.user.id,
      trigger: 'manual',
      wsServer: wsServer,
    });
    auditLog(
      req.user.id,
      'CLIENT_OP_DISPATCHED',
      'op=' + result.opType + ' run=' + result.runId + ' targets=' + result.targetCount +
        ' dispatched=' + result.dispatched + ' queued=' + result.unreachable.length,
      req.ip
    );
    return res.json(Object.assign({ ok: true }, result));
  } catch (err) {
    if (err && DISPATCH_ERROR_CODES.has(err.code)) {
      return res.status(400).json({ error: err.message, code: err.code });
    }
    logger.error('client-op dispatch failed', { error: err && err.message });
    return res.status(500).json({ error: 'dispatch failed' });
  } finally {
    db.close();
  }
});

// ── GET /runs ────────────────────────────────────────────────────────────────
router.get('/runs', (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) return;
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const db = getDb();
  try {
    const runs = db
      .prepare(
        'SELECT id, op_type, trigger, initiated_by, target_count, completed_count, unreachable_count, status, created_at, completed_at ' +
          'FROM client_ops_runs ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?'
      )
      .all(limit, offset);
    return res.json({ runs: runs });
  } catch (err) {
    logger.error('client-op runs list failed', { error: err.message });
    return res.status(500).json({ error: 'failed to list runs' });
  } finally {
    db.close();
  }
});

// ── GET /runs/:id ────────────────────────────────────────────────────────────
router.get('/runs/:id', (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) return;
  const db = getDb();
  try {
    const run = db.prepare('SELECT * FROM client_ops_runs WHERE id = ?').get(req.params.id);
    if (!run) return res.status(404).json({ error: 'run not found' });
    const results = db
      .prepare(
        'SELECT id, user_id, pseudonym_at_op, op_type, status, detail_json, signature_verified, ' +
          'signed_at, started_at, duration_ms, received_at ' +
          'FROM client_ops_results WHERE run_id = ? ORDER BY received_at DESC, rowid DESC'
      )
      .all(req.params.id);
    const queue = db
      .prepare('SELECT user_id, status, queued_at, expires_at, delivered_at FROM client_ops_queue WHERE run_id = ?')
      .all(req.params.id);
    return res.json({ run: run, results: results, queue: queue });
  } catch (err) {
    logger.error('client-op run fetch failed', { error: err.message });
    return res.status(500).json({ error: 'failed to fetch run' });
  } finally {
    db.close();
  }
});

// ── GET /retention ───────────────────────────────────────────────────────────
router.get('/retention', (req, res) => {
  if (!requireRole(req, res, ['admin'])) return;
  const db = getDb();
  try {
    const row = db.prepare("SELECT value FROM team_config WHERE key = 'client_ops_retention_days'").get();
    let v = null;
    try {
      v = JSON.parse(row ? row.value : 'null');
    } catch (_e) {
      v = null;
    }
    return res.json({ retention_days: v });
  } finally {
    db.close();
  }
});

// ── PUT /retention ───────────────────────────────────────────────────────────
router.put('/retention', (req, res) => {
  if (!requireRole(req, res, ['admin'])) return;
  const retentionDays = (req.body || {}).retention_days;
  if (retentionDays !== null && (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650)) {
    return res.status(400).json({ error: 'retention_days must be null (indefinite) or an integer 1..3650' });
  }
  const db = getDb();
  try {
    db.prepare(
      "INSERT INTO team_config (key, value, updated_by) VALUES ('client_ops_retention_days', ?, ?) " +
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')"
    ).run(JSON.stringify(retentionDays), req.user.id);
    return res.json({ ok: true, retention_days: retentionDays });
  } catch (err) {
    logger.error('client-op retention update failed', { error: err.message });
    return res.status(500).json({ error: 'failed to set retention' });
  } finally {
    db.close();
  }
});

module.exports = router;

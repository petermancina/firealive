// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compromise Scan Orchestration (B4)
//
// Lets a lead/admin orchestrate the analyst-client 10-point self-scan across
// connected clients, registers per-AC device signing keys, and reports run
// status. The server never fabricates results: it dispatches an orchestrate
// command to connected ACs over the WebSocket channel and stores the signed
// reports they return (ingestion + signature verification live in the
// websocket-server). Offline targets are queued for delivery on reconnect
// within a TTL and reported as unreachable in the meantime.
//
// Endpoints (mounted at /api/compromise; auth required, per-endpoint roles):
//   POST /orchestrate       lead/admin — { targets: 'all' | [userId,...] }
//   GET  /runs              lead/admin — recent run history
//   GET  /runs/:id          lead/admin — one run + per-client results + queue
//   POST /device-key        any auth   — register/rotate the caller's AC key
//   GET  /retention         admin      — read result retention window
//   PUT  /retention         admin      — set result retention window
// ═══════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

const QUEUE_TTL_MINUTES = 15;

function requireRole(req, res, roles) {
  if (!req.user || !roles.includes(req.user.role)) {
    res.status(403).json({ error: 'Insufficient permissions' });
    return false;
  }
  return true;
}

// ── POST /orchestrate ────────────────────────────────────────────────────────
router.post('/orchestrate', (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) return;
  const body = req.body || {};
  const targets = body.targets;
  const manifest = body.manifest && typeof body.manifest === 'object' ? body.manifest : null;
  const expectedConfig = body.expectedConfig && typeof body.expectedConfig === 'object' ? body.expectedConfig : null;

  const db = getDb();
  try {
    let targetIds = [];
    if (targets === 'all') {
      targetIds = db.prepare("SELECT id FROM users WHERE role = 'analyst' AND active = 1").all().map((r) => r.id);
    } else if (Array.isArray(targets)) {
      if (targets.length === 0 || targets.length > 1000) {
        return res.status(400).json({ error: 'targets must be a non-empty list (max 1000) or "all"' });
      }
      const placeholders = targets.map(() => '?').join(',');
      targetIds = db
        .prepare("SELECT id FROM users WHERE id IN (" + placeholders + ") AND role = 'analyst' AND active = 1")
        .all(...targets)
        .map((r) => r.id);
    } else {
      return res.status(400).json({ error: 'targets must be "all" or an array of analyst ids' });
    }
    if (targetIds.length === 0) return res.status(400).json({ error: 'no valid analyst targets' });

    const wsServer = req.app && req.app.locals && req.app.locals.wsServer;
    const connected = [];
    const unreachable = [];
    for (const id of targetIds) {
      if (wsServer && wsServer.clients && wsServer.clients.has(id)) connected.push(id);
      else unreachable.push(id);
    }

    const mode = targets === 'all' ? 'all' : 'list';
    const run = db
      .prepare(
        "INSERT INTO compromise_scan_runs (trigger, initiated_by, targets_json, target_count, unreachable_count, status) " +
          "VALUES ('manual', ?, ?, ?, ?, 'in_progress') RETURNING id"
      )
      .get(req.user.id, JSON.stringify({ mode, ids: targetIds }), targetIds.length, unreachable.length);
    const runId = run.id;

    // Queue offline targets for delivery on reconnect within the TTL.
    if (unreachable.length) {
      const expiresAt = new Date(Date.now() + QUEUE_TTL_MINUTES * 60000).toISOString();
      const q = db.prepare("INSERT INTO compromise_scan_queue (run_id, user_id, expires_at) VALUES (?, ?, ?)");
      const enqueue = db.transaction((ids) => { for (const id of ids) q.run(runId, id, expiresAt); });
      enqueue(unreachable);
    }

    // Dispatch to connected ACs. The websocket-server fans out the command and
    // ingests the signed results; guard so this route stays sound if real-time
    // features are unavailable.
    if (connected.length && wsServer && typeof wsServer.dispatchCompromiseScan === 'function') {
      try { wsServer.dispatchCompromiseScan(runId, connected, { manifest, expectedConfig }); }
      catch (e) { logger.warn('compromise dispatch failed', { runId, error: e.message }); }
    }

    res.json({ runId, targetCount: targetIds.length, dispatched: connected.length, unreachable });
  } catch (err) {
    logger.error('compromise orchestrate failed', { error: err.message });
    res.status(500).json({ error: 'orchestration failed' });
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
        "SELECT id, trigger, initiated_by, target_count, completed_count, unreachable_count, status, created_at, completed_at " +
          "FROM compromise_scan_runs ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?"
      )
      .all(limit, offset);
    res.json({ runs });
  } catch (err) {
    logger.error('compromise runs list failed', { error: err.message });
    res.status(500).json({ error: 'failed to list runs' });
  } finally {
    db.close();
  }
});

// ── GET /runs/:id ──────────────────────────────────────────────────────────—
router.get('/runs/:id', (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) return;
  const db = getDb();
  try {
    const run = db.prepare("SELECT * FROM compromise_scan_runs WHERE id = ?").get(req.params.id);
    if (!run) return res.status(404).json({ error: 'run not found' });
    const results = db
      .prepare(
        "SELECT id, user_id, pseudonym_at_scan, status, tests_total, tests_passed, tests_failed, tests_inconclusive, " +
          "details_json, signature_verified, signed_at, scan_duration_ms, received_at " +
          "FROM compromise_scan_results WHERE run_id = ? ORDER BY received_at DESC, rowid DESC"
      )
      .all(req.params.id);
    const queue = db
      .prepare("SELECT user_id, status, queued_at, expires_at, delivered_at FROM compromise_scan_queue WHERE run_id = ?")
      .all(req.params.id);
    res.json({ run, results, queue });
  } catch (err) {
    logger.error('compromise run fetch failed', { error: err.message });
    res.status(500).json({ error: 'failed to fetch run' });
  } finally {
    db.close();
  }
});

// ── POST /device-key ──────────────────────────────────────────────────────—
// The caller registers/rotates ITS OWN device public key. The client-supplied
// identity is ignored; the key binds to the authenticated user.
router.post('/device-key', (req, res) => {
  const { publicKey, fingerprint } = req.body || {};
  if (typeof publicKey !== 'string' || !publicKey || typeof fingerprint !== 'string' || !fingerprint) {
    return res.status(400).json({ error: 'publicKey and fingerprint required' });
  }
  if (!/-----BEGIN PUBLIC KEY-----/.test(publicKey) || !/^[a-f0-9]{64}$/.test(fingerprint)) {
    return res.status(400).json({ error: 'invalid key material' });
  }
  const db = getDb();
  try {
    const uid = req.user.id;
    const existing = db.prepare("SELECT id, public_key FROM ac_device_signing_keys WHERE user_id = ? AND active = 1").get(uid);
    if (existing && existing.public_key === publicKey) {
      return res.json({ ok: true, rotated: false });
    }
    const rotate = db.transaction(() => {
      db.prepare("UPDATE ac_device_signing_keys SET active = 0, retired_at = datetime('now') WHERE user_id = ? AND active = 1").run(uid);
      db.prepare("INSERT INTO ac_device_signing_keys (user_id, public_key, fingerprint) VALUES (?, ?, ?)").run(uid, publicKey, fingerprint);
    });
    rotate();
    res.json({ ok: true, rotated: !!existing });
  } catch (err) {
    logger.error('device-key registration failed', { error: err.message });
    res.status(500).json({ error: 'registration failed' });
  } finally {
    db.close();
  }
});

// ── GET /retention ─────────────────────────────────────────────────────────—
router.get('/retention', (req, res) => {
  if (!requireRole(req, res, ['admin'])) return;
  const db = getDb();
  try {
    const row = db.prepare("SELECT value FROM team_config WHERE key = 'compromise_scan_retention_days'").get();
    let v = null;
    try { v = JSON.parse(row ? row.value : 'null'); } catch (_e) { v = null; }
    res.json({ retention_days: v });
  } finally {
    db.close();
  }
});

// ── PUT /retention ─────────────────────────────────────────────────────────—
router.put('/retention', (req, res) => {
  if (!requireRole(req, res, ['admin'])) return;
  let { retention_days } = req.body || {};
  if (retention_days !== null && (!Number.isInteger(retention_days) || retention_days < 1 || retention_days > 3650)) {
    return res.status(400).json({ error: 'retention_days must be null (indefinite) or an integer 1..3650' });
  }
  const db = getDb();
  try {
    db.prepare(
      "INSERT INTO team_config (key, value, updated_by) VALUES ('compromise_scan_retention_days', ?, ?) " +
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')"
    ).run(JSON.stringify(retention_days), req.user.id);
    res.json({ ok: true, retention_days });
  } catch (err) {
    logger.error('retention update failed', { error: err.message });
    res.status(500).json({ error: 'failed to set retention' });
  } finally {
    db.close();
  }
});

module.exports = router;

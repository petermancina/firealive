// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Reduced-Routing Tripwire (B4)
//
// Configuration, status, history, manual evaluation, and lockout resolution for
// the reduced-routing tripwire. The detector and the fail-open response live in
// services/tripwire-detector.js and services/tripwire-scheduler.js; this route
// is the management surface.
//
// Mounted at /api/tripwire (lead/admin). Endpoints:
//   GET  /config    lead/admin — current config + defaults
//   PUT  /config    admin      — update config
//   GET  /status    lead/admin — live read-only verdict + lockout state
//   GET  /events    lead/admin — trip history (paginated)
//   POST /evaluate  lead/admin — manual read-only evaluation (no response fires)
//   POST /resolve   lead/admin — clear an active lockout (gated on a clean scan;
//                                admin may force after out-of-band investigation)
// ═══════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const detector = require('../services/tripwire-detector');
const { CONFIG_KEY, LOCKOUT_KEY } = require('../services/tripwire-scheduler');

function requireRole(req, res, roles) {
  if (!req.user || !roles.includes(req.user.role)) {
    res.status(403).json({ error: 'Insufficient permissions' });
    return false;
  }
  return true;
}

function readConfig(db) {
  const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(CONFIG_KEY);
  try { return row ? JSON.parse(row.value) : {}; } catch (_e) { return {}; }
}

// ── GET /config ───────────────────────────────────────────────────────────—
router.get('/config', (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) return;
  const db = getDb();
  try { res.json({ config: readConfig(db), defaults: detector.DEFAULTS }); }
  finally { db.close(); }
});

// ── PUT /config (admin) ──────────────────────────────────────────────────────
router.put('/config', (req, res) => {
  if (!requireRole(req, res, ['admin'])) return;
  const cfg = req.body && req.body.config;
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) return res.status(400).json({ error: 'config object required' });
  const out = { ...cfg };
  const numChecks = [
    ['threshold_pct', 0, 100, false],
    ['reduced_capacity_threshold', 0, 100, false],
    ['trip_score', 0, 20, false],
    ['window_minutes', 1, 1440, true],
  ];
  for (const [k, lo, hi, intOnly] of numChecks) {
    if (out[k] == null) continue;
    const n = Number(out[k]);
    if (!Number.isFinite(n) || n < lo || n > hi || (intOnly && !Number.isInteger(n))) {
      return res.status(400).json({ error: `${k} must be ${intOnly ? 'an integer ' : ''}${lo}..${hi}` });
    }
    out[k] = n;
  }
  const db = getDb();
  try {
    db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')")
      .run(CONFIG_KEY, JSON.stringify(out), req.user.id);
    res.json({ ok: true, config: out });
  } catch (err) {
    logger.error('tripwire config save failed', { error: err.message });
    res.status(500).json({ error: 'failed to save config' });
  } finally { db.close(); }
});

// ── GET /status — live read-only verdict + lockout ───────────────────────────
router.get('/status', (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) return;
  const db = getDb();
  try {
    const cfg = readConfig(db);
    let verdict = null;
    try { verdict = detector.evaluate(db, cfg); } catch (e) { verdict = { error: e.message }; }
    const lockRow = db.prepare("SELECT value FROM team_config WHERE key = ?").get(LOCKOUT_KEY);
    let lockout = null;
    try { lockout = lockRow ? JSON.parse(lockRow.value) : null; } catch (_e) {}
    const activeEvent = db.prepare("SELECT id, tripped_at, segment, pct_in_reduced, scan_run_id FROM tripwire_events WHERE lockout_active = 1 AND resolved_at IS NULL ORDER BY tripped_at DESC, rowid DESC LIMIT 1").get() || null;
    res.json({ enabled: cfg.enabled !== false, verdict, lockout, active_event: activeEvent });
  } finally { db.close(); }
});

// ── GET /events — trip history ───────────────────────────────────────────────
router.get('/events', (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) return;
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const db = getDb();
  try {
    const events = db.prepare("SELECT id, tripped_at, pct_in_reduced, segment, verdict, scan_run_id, lockout_active, resolved_at, resolved_by FROM tripwire_events ORDER BY tripped_at DESC, rowid DESC LIMIT ? OFFSET ?").all(limit, offset);
    res.json({ events });
  } finally { db.close(); }
});

// ── POST /evaluate — manual, read-only (no response fires) ────────────────────
router.post('/evaluate', (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) return;
  const db = getDb();
  try {
    const verdict = detector.evaluate(db, readConfig(db));
    res.json({ verdict, note: 'read-only evaluation; no response executed' });
  } catch (err) {
    logger.error('tripwire evaluate failed', { error: err.message });
    res.status(500).json({ error: 'evaluation failed' });
  } finally { db.close(); }
});

// ── POST /resolve — clear an active lockout, gated on a clean scan ────────────
router.post('/resolve', (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) return;
  const force = !!(req.body && req.body.force === true);
  if (force && req.user.role !== 'admin') return res.status(403).json({ error: 'only an admin can force-resolve without a clean scan' });
  const db = getDb();
  try {
    const ev = db.prepare("SELECT id, scan_run_id FROM tripwire_events WHERE lockout_active = 1 AND resolved_at IS NULL ORDER BY tripped_at DESC, rowid DESC LIMIT 1").get();
    if (!ev) return res.status(404).json({ error: 'no active tripwire lockout to resolve' });
    if (!force) {
      if (!ev.scan_run_id) return res.status(409).json({ error: 'no scan linked to this lockout; an admin may force-resolve after investigating' });
      const run = db.prepare("SELECT target_count, unreachable_count FROM compromise_scan_runs WHERE id = ?").get(ev.scan_run_id);
      if (!run) return res.status(409).json({ error: 'linked scan run not found; an admin may force-resolve' });
      const bad = db.prepare("SELECT COUNT(*) AS c FROM compromise_scan_results WHERE run_id = ? AND (status = 'fail' OR signature_verified = 0)").get(ev.scan_run_id).c;
      if (bad > 0) return res.status(409).json({ error: `scan is not clean: ${bad} failed/unverified result(s). Resolve is blocked until the fleet is confirmed clean (an admin may force-resolve).` });
      const verifiedClean = db.prepare("SELECT COUNT(*) AS c FROM compromise_scan_results WHERE run_id = ? AND signature_verified = 1 AND status IN ('clean', 'warning')").get(ev.scan_run_id).c;
      const reachable = (run.target_count || 0) - (run.unreachable_count || 0);
      if (verifiedClean < reachable) return res.status(409).json({ error: `scan incomplete: ${verifiedClean}/${reachable} reachable clients reported clean. Wait for completion or force-resolve as an admin.` });
    }
    const resolve = db.transaction(() => {
      db.prepare("UPDATE tripwire_events SET lockout_active = 0, resolved_at = datetime('now'), resolved_by = ? WHERE id = ?").run(req.user.id, ev.id);
      db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')")
        .run(LOCKOUT_KEY, JSON.stringify({ active: false, resolved_event: ev.id, resolved_at: new Date().toISOString() }), req.user.id);
    });
    resolve();
    res.json({ ok: true, resolved_event: ev.id, forced: force });
  } catch (err) {
    logger.error('tripwire resolve failed', { error: err.message });
    res.status(500).json({ error: 'resolve failed' });
  } finally { db.close(); }
});

module.exports = router;

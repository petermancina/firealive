// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Reduced-Routing Tripwire Scheduler & Response (B4)
//
// Runs the tripwire detector on a cadence and, on a trip, executes the
// fail-open incident response. Detection logic lives in tripwire-detector.js;
// this module is the actor that consumes a verdict and changes state.
//
// Response (each action is independently gated by the admin's tripwire_config
// response block, defaulting ON):
//   1. Fail-open routing  — deactivate active reduced_load overrides and raise
//      a lockout flag the routing layer honors, so a (possibly injected)
//      reduced state can no longer throttle incident response. Burnout-derived
//      capacity_score is never altered — only routing's treatment of it.
//   2. Auto compromise scan — orchestrate a signed self-scan across all active
//      analysts (trigger = 'tripwire'), reusing the WebSocket fan-out + queue.
//   3. Record a tripwire_events row with an active investigation lockout.
//   4. Raise the lockout flag (team_config) for the routing layer / console.
//   5. Raise a critical TRIPWIRE_TRIPPED alert through the B3 alert router
//      (SOAR + lead notification + SIEM + email + webhook per the matrix).
//
// While a lockout is active and unresolved, further trips are suppressed so the
// response does not storm; clearing the lockout is a deliberate operator action
// (the tripwire route's resolve endpoint, gated on a clean scan).
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

const { logger } = require('./logger');
const detector = require('./tripwire-detector');

const DEFAULT_INTERVAL_MS = 60000;
const CONFIG_KEY = 'tripwire_config';
const LOCKOUT_KEY = 'tripwire_lockout';

function _loadConfig(db) {
  try {
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(CONFIG_KEY);
    return row ? JSON.parse(row.value) : {};
  } catch (_e) { return {}; }
}

function _activeLockout(db) {
  try {
    return db.prepare("SELECT id FROM tripwire_events WHERE lockout_active = 1 AND resolved_at IS NULL ORDER BY tripped_at DESC, rowid DESC LIMIT 1").get() || null;
  } catch (_e) { return null; }
}

// Orchestrate a compromise self-scan across all active analysts (system-
// initiated, trigger = 'tripwire'). Mirrors the manual orchestration path.
function _launchScanAll(db, deps) {
  const targets = db.prepare("SELECT id FROM users WHERE role = 'analyst' AND active = 1").all().map((r) => r.id);
  if (!targets.length) return null;
  const wsServer = deps && typeof deps.getWsServer === 'function' ? deps.getWsServer() : null;
  const connected = [];
  const unreachable = [];
  for (const id of targets) {
    if (wsServer && wsServer.clients && wsServer.clients.has(id)) connected.push(id);
    else unreachable.push(id);
  }
  const run = db
    .prepare("INSERT INTO compromise_scan_runs (trigger, initiated_by, targets_json, target_count, unreachable_count, status) VALUES ('tripwire', NULL, ?, ?, ?, 'in_progress') RETURNING id")
    .get(JSON.stringify({ mode: 'all', ids: targets }), targets.length, unreachable.length);
  if (unreachable.length) {
    const exp = new Date(Date.now() + 15 * 60000).toISOString();
    const q = db.prepare("INSERT INTO compromise_scan_queue (run_id, user_id, expires_at) VALUES (?, ?, ?)");
    for (const id of unreachable) q.run(run.id, id, exp);
  }
  if (connected.length && wsServer && typeof wsServer.dispatchCompromiseScan === 'function') {
    try { wsServer.dispatchCompromiseScan(run.id, connected, {}); } catch (_e) {}
  }
  return run.id;
}

function executeTripResponse(db, verdict, config, deps) {
  const resp = (config && config.response) || {};
  const actions = { fail_open: false, overrides_cleared: 0, scan_run_id: null, alert: false, lockout: false };

  // 1. Fail-open routing.
  if (resp.auto_disable_routing !== false) {
    try {
      const r = db.prepare("UPDATE routing_overrides SET active = 0 WHERE type = 'reduced_load' AND active = 1").run();
      actions.fail_open = true;
      actions.overrides_cleared = r.changes || 0;
    } catch (e) { logger.warn('tripwire fail-open failed', { error: e.message }); }
  }

  // 2. Auto orchestrated compromise scan across all active analysts.
  if (resp.trigger_compromise_scan !== false) {
    try { actions.scan_run_id = _launchScanAll(db, deps); }
    catch (e) { logger.warn('tripwire auto-scan failed', { error: e.message }); }
  }

  // 3. Record the event with an active investigation lockout.
  let eventId = null;
  try {
    const ins = db
      .prepare("INSERT INTO tripwire_events (trigger_signals_json, pct_in_reduced, segment, verdict, response_json, scan_run_id, lockout_active) VALUES (?, ?, ?, ?, ?, ?, 1) RETURNING id")
      .get(JSON.stringify(verdict.signals || {}), verdict.pct_in_reduced, verdict.segment, verdict.verdict, JSON.stringify(actions), actions.scan_run_id);
    eventId = ins.id;
    actions.lockout = true;
  } catch (e) { logger.warn('tripwire event insert failed', { error: e.message }); }

  // 4. Raise the lockout flag for the routing layer / console.
  try {
    db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, NULL) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')")
      .run(LOCKOUT_KEY, JSON.stringify({ active: true, event_id: eventId, segment: verdict.segment, since: new Date().toISOString() }));
  } catch (e) { logger.warn('tripwire lockout flag failed', { error: e.message }); }

  // 5. Raise a critical alert (SOAR + notification + SIEM + email + webhook per matrix).
  if (resp.notify_lead !== false || resp.trigger_soar !== false) {
    try {
      const routeAlert = (deps && deps.routeAlert) || require('./alert-router').routeAlert;
      const msg = `Reduced-routing tripwire tripped in segment "${verdict.segment}" — ${verdict.pct_in_reduced}% in reduced routing. ${verdict.verdict}`;
      Promise.resolve(routeAlert(db, { type: 'TRIPWIRE_TRIPPED', severity: 'critical', message: msg, timestamp: new Date().toISOString() })).catch(() => {});
      actions.alert = true;
    } catch (e) { logger.warn('tripwire alert failed', { error: e.message }); }
  }

  return { eventId, actions };
}

// One detection+response cycle. Returns a small status object (used by tests
// and the manual evaluate endpoint).
function runTripwireCycle(db, deps) {
  const config = _loadConfig(db);
  if (config && config.enabled === false) return { skipped: 'disabled' };
  let verdict;
  try { verdict = detector.evaluate(db, config); }
  catch (e) { logger.warn('tripwire detector error', { error: e.message }); return { error: e.message }; }
  if (!verdict.tripped) return { tripped: false, verdict };
  if (_activeLockout(db)) return { tripped: true, suppressed: 'lockout_active', verdict };
  const result = executeTripResponse(db, verdict, config, deps);
  logger.warn('Reduced-routing tripwire tripped', { segment: verdict.segment, score: verdict.score, eventId: result.eventId });
  return { tripped: true, executed: true, verdict, eventId: result.eventId, actions: result.actions };
}

// Start the periodic scheduler. No-op cycles when the tripwire is disabled.
function startTripwireScheduler(getDb, deps = {}) {
  const intervalMs = deps.intervalMs || DEFAULT_INTERVAL_MS;
  const handle = setInterval(() => {
    let db;
    try { db = getDb(); runTripwireCycle(db, deps); }
    catch (e) { logger.warn('tripwire cycle error', { error: e.message }); }
    finally { if (db) { try { db.close(); } catch (_e) {} } }
  }, intervalMs);
  if (handle && typeof handle.unref === 'function') handle.unref();
  return handle;
}

module.exports = { startTripwireScheduler, runTripwireCycle, executeTripResponse, CONFIG_KEY, LOCKOUT_KEY };

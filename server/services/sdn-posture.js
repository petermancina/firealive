// FIREALIVE -- SDN posture state machine (B5i SDN Mode, D-B5i-5)
//
// The graduated, hysteretic, severity-weighted detector behind FireAlive's
// posture-degradation response. Posture is a state machine -- healthy ->
// uncertain -> degraded -- not a binary.
//
// Per-integration probe debounce counters (consecutive_failures /
// consecutive_successes on sdn_integrations) supply hysteresis in BOTH
// directions:
//
//   - Onset is debounced: an integration is only "down" after a run of failed
//     probes, so a single missed probe never trips the gate. Failure TYPE is
//     weighted -- an authentication failure or an error response (possible
//     tampering) confirms "down" at a lower threshold than a plain unreachable
//     (a network blip / management-plane down).
//   - Recovery is debounced at the aggregate: once degraded, FireAlive stays
//     degraded until EVERY enabled integration is confirmed back up (a sustained
//     run of successful probes). A single good probe cannot lift the lockdown,
//     and a flapping controller settles into "uncertain" -- which does not lock
//     anything down -- rather than oscillating the gate.
//
// Staleness (a probe overdue) drops an otherwise-OK integration to "watch":
// fresh assurance has been lost. The aggregate is a roll-up of the per-
// integration classifications; the persisted sdn_posture_state row records the
// current state (for transition detection and for the fail-safe gate to read)
// but is NOT the source of hysteresis -- the counters are.
//
// This module records what FireAlive OBSERVED and how its own posture changed;
// it never acts on the SDN. The fail-safe gate (sdn-fail-safe) reads the state
// via currentPosture; the probe scheduler (Block G) drives recordProbeResult /
// evaluatePosture.
//
// ASCII only; no template literals.

const { logger } = require('./logger');
const sdnMode = require('./sdn-mode');

const STATE_ID = 'default';
const STATES = ['healthy', 'uncertain', 'degraded'];
const PROBE_STATUSES = ['unknown', 'reachable', 'unreachable', 'unauthenticated', 'error'];

// Per-integration debounce thresholds.
const FAILURE_THRESHOLD = 3;        // consecutive plain failures to confirm "down"
const AUTH_FAILURE_THRESHOLD = 2;   // consecutive auth/error failures to confirm "down" (weighted)
const SUCCESS_THRESHOLD = 3;        // consecutive successes to confirm an integration is back up

// A probe result older than this is stale -- the scheduler should have refreshed
// it, so its absence is itself a loss of assurance.
const STALENESS_MS = 15 * 60 * 1000;

// Short cache for the gate's per-request currentPosture() read.
const CACHE_TTL_MS = 5 * 1000;
let postureCache = { state: 'healthy', loadedAt: 0 };

function nowMs() { return Date.now(); }

function setCache(state) { postureCache = { state: state, loadedAt: nowMs() }; }

function fail(code, message) {
  const e = new Error(message || code);
  e.code = code;
  return e;
}

// Parse a SQLite datetime('now') value ('YYYY-MM-DD HH:MM:SS', UTC) or an ISO
// timestamp to epoch ms. Returns null on a missing or unparseable value.
function parseTs(ts) {
  if (!ts) return null;
  let s = String(ts).trim();
  if (!/[zZ]|[+-]\d\d:?\d\d$/.test(s)) {
    s = s.replace(' ', 'T') + 'Z';
  }
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

// Classify one enabled integration: 'up' | 'watch' | 'down'.
function classifyIntegration(integ, now) {
  const status = integ.last_probe_status || 'unknown';
  const cf = integ.consecutive_failures || 0;
  const cs = integ.consecutive_successes || 0;
  const probedAt = parseTs(integ.last_probe_at);
  const stale = probedAt !== null && (now - probedAt > STALENESS_MS);

  const weighted = (status === 'unauthenticated' || status === 'error');
  const downThreshold = weighted ? AUTH_FAILURE_THRESHOLD : FAILURE_THRESHOLD;

  if (cf >= downThreshold) return 'down';
  if (cf >= 1) return 'watch';             // onset debounce: failures seen, not yet confirmed
  // cf === 0 here: the last probe succeeded, or the integration was never probed.
  if (probedAt === null) return 'up';      // never probed -> neutral; no evidence of trouble
  if (stale) return 'watch';               // fresh assurance lost
  if (status === 'reachable' && cs >= SUCCESS_THRESHOLD) return 'up';
  return 'watch';                          // reachable but not yet confirmed (recovery / baseline)
}

function latestEventId(db) {
  const r = db.prepare('SELECT id FROM sdn_posture_events ORDER BY rowid DESC LIMIT 1').get();
  return r ? r.id : null;
}

// Re-derive the aggregate posture from the current per-integration debounce
// state, persist any transition, and emit operator-meaningful events. Returns
// the current state. Safe to call after every probe and on a periodic timer.
// Dispatch an operator/security alert for an operator-meaningful posture
// transition through the shared alert router (audit + SIEM + SOAR + notification
// + email + webhook per the severity matrix; a critical also nudges connected
// clients). Best-effort and fire-and-forget on its own connection, closed once
// the router's async channels settle -- an alerting failure must never block
// posture evaluation.
function dispatchPostureAlert(type, severity, message) {
  try {
    const { routeAlert } = require('./alert-router');
    const { getDb } = require('../db/init');
    const adb = getDb();
    Promise.resolve(
      routeAlert(adb, {
        type: type,
        severity: severity,
        message: message,
        timestamp: new Date().toISOString(),
      })
    )
      .catch((e) => logger.error('SDN posture alert dispatch failed', { error: e.message }))
      .finally(() => { try { adb.close(); } catch (_e) { /* already closed */ } });
  } catch (e) {
    logger.error('SDN posture alert dispatch failed', { error: e.message });
  }
}

function evaluatePosture(db) {
  const now = nowMs();
  db.prepare('INSERT OR IGNORE INTO sdn_posture_state (id) VALUES (?)').run(STATE_ID);

  const integrations = db.prepare(
    'SELECT id, last_probe_status, last_probe_at, consecutive_failures, consecutive_successes FROM sdn_integrations WHERE enabled = 1'
  ).all();

  const down = [];
  const watch = [];
  for (let i = 0; i < integrations.length; i++) {
    const c = classifyIntegration(integrations[i], now);
    if (c === 'down') down.push(integrations[i].id);
    else if (c === 'watch') watch.push(integrations[i].id);
  }
  const raw = down.length ? 'degraded' : (watch.length ? 'uncertain' : 'healthy');

  const prevRow = db.prepare('SELECT current_state FROM sdn_posture_state WHERE id = ?').get(STATE_ID);
  const prev = (prevRow && prevRow.current_state) ? prevRow.current_state : 'healthy';

  // Recovery hysteresis: once degraded, clear only on sustained recovery (raw
  // fully healthy -- every integration confirmed back up). While recovering,
  // raw is 'uncertain', and we stay degraded.
  let next;
  if (prev === 'degraded') {
    next = (raw === 'healthy') ? 'healthy' : 'degraded';
  } else {
    next = raw;
  }

  if (next === prev) {
    db.prepare("UPDATE sdn_posture_state SET last_eval_at = datetime('now') WHERE id = ?").run(STATE_ID);
    setCache(next);
    return next;
  }

  // Transition. Only the degraded boundary is operator-meaningful, so only it
  // emits a posture event (healthy<->uncertain transitions are silent).
  let transitionEventId;
  if (next === 'degraded') {
    sdnMode.recordPostureEvent(db, {
      eventType: 'posture_degraded',
      severity: 'critical',
      detail: { down: down, watch: watch, downCount: down.length, watchCount: watch.length },
    });
    transitionEventId = latestEventId(db);
    logger.warn('SDN posture degraded; the API surface is locked down until posture is restored', {
      down: down.length, watch: watch.length,
    });
    dispatchPostureAlert(
      'SDN_POSTURE_DEGRADED',
      'critical',
      'SDN posture degraded: ' + down.length + ' integration(s) unreachable or unauthenticated. FireAlive API surface is locked down (assume-breach) until SDN segmentation assurance is restored.'
    );
  } else if (prev === 'degraded') {
    sdnMode.recordPostureEvent(db, {
      eventType: 'posture_restored',
      severity: 'info',
      detail: { from: prev },
    });
    transitionEventId = latestEventId(db);
    logger.info('SDN posture restored; operations resume');
    dispatchPostureAlert(
      'SDN_POSTURE_RESTORED',
      'info',
      'SDN posture restored; FireAlive API lockdown lifted.'
    );
  }

  if (transitionEventId !== undefined) {
    db.prepare(
      "UPDATE sdn_posture_state SET current_state = ?, state_since = datetime('now'), last_eval_at = datetime('now'), last_transition_event_id = ? WHERE id = ?"
    ).run(next, transitionEventId, STATE_ID);
  } else {
    db.prepare(
      "UPDATE sdn_posture_state SET current_state = ?, state_since = datetime('now'), last_eval_at = datetime('now') WHERE id = ?"
    ).run(next, STATE_ID);
  }
  setCache(next);
  return next;
}

// Fold a single probe result into the per-integration debounce counters, record
// the observation, and re-evaluate. Called by the Block-G probe scheduler with
// the adapter's reachability status. Read-only toward the SDN.
function recordProbeResult(db, opts) {
  const o = opts || {};
  if (!o.integrationId) throw fail('INVALID_PROBE', 'integrationId is required');
  const status = PROBE_STATUSES.indexOf(o.status) === -1 ? 'error' : o.status;
  const success = (status === 'reachable');
  let detail = null;
  if (o.detail !== undefined && o.detail !== null) {
    detail = (typeof o.detail === 'string') ? o.detail : JSON.stringify(o.detail);
  }

  if (success) {
    db.prepare(
      "UPDATE sdn_integrations SET last_probe_status = ?, last_probe_at = datetime('now'), last_probe_detail = ?, consecutive_successes = consecutive_successes + 1, consecutive_failures = 0 WHERE id = ?"
    ).run(status, detail, o.integrationId);
  } else {
    db.prepare(
      "UPDATE sdn_integrations SET last_probe_status = ?, last_probe_at = datetime('now'), last_probe_detail = ?, consecutive_failures = consecutive_failures + 1, consecutive_successes = 0 WHERE id = ?"
    ).run(status, detail, o.integrationId);
  }

  sdnMode.recordPostureEvent(db, {
    integrationId: o.integrationId,
    eventType: 'probe',
    severity: success ? 'info' : 'warning',
    detail: { status: status },
  });

  return evaluatePosture(db);
}

// The current aggregate posture for the fail-safe gate. Cached briefly so the
// gate does not hit the database per request. Propagates a read fault so the
// gate can apply its bounded-grace fail-secure logic rather than assuming
// healthy.
function currentPosture(db) {
  const now = nowMs();
  if (now - postureCache.loadedAt <= CACHE_TTL_MS) return postureCache.state;
  const row = db.prepare('SELECT current_state FROM sdn_posture_state WHERE id = ?').get(STATE_ID);
  const state = (row && row.current_state) ? row.current_state : 'healthy';
  setCache(state);
  return state;
}

module.exports = {
  evaluatePosture,
  recordProbeResult,
  currentPosture,
  classifyIntegration,
  STATES,
  STATE_ID,
  FAILURE_THRESHOLD,
  AUTH_FAILURE_THRESHOLD,
  SUCCESS_THRESHOLD,
  STALENESS_MS,
  _cacheTtlMs: CACHE_TTL_MS,
};

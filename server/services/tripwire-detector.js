// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Reduced-Routing Tripwire Detector (B4)
//
// Detects a coordinated attack in which compromised analyst clients weaponize
// FireAlive's legitimate reduced-routing mechanism to throttle the SOC's
// incident-response capacity: by synchronously driving many analysts into
// reduced routing (low capacity_score and/or reduced_load overrides), an
// attacker can quietly shrink the team's ticket throughput.
//
// This module is PURE DETECTION. evaluate(db, config) reads server-side state
// and returns a verdict. It does NOT change routing, notify anyone, or fire a
// scan — the scheduler/response wiring (B4 C8) consumes the verdict and acts.
//
// Six signals (each yields a strength in [0,1]; the linchpin is weighted x2):
//   1. velocity        — how many analysts entered reduced routing in the window
//   2. breadth         — share of the segment currently in reduced routing
//   3. slope           — acceleration of entries vs the prior window
//   4. signal_justification (LINCHPIN) — are the reductions justified by the
//      server's INDEPENDENT workload record? reduced-but-idle = injection
//   5. uniformity      — low variance of capacity values / entry timing = scripted
//   6. corroboration   — co-occurring security events lower the trip bar
//
// Trip when the weighted sum reaches trip_score, OR a single extreme signal
// fires. Evaluated globally and per tier/shift segment. Privacy: the verdict
// is team/segment level only — no per-analyst identity, no burnout data.
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

const { logger } = require('./logger');

const DEFAULTS = {
  window_minutes: 10,
  threshold_pct: 60, // breadth: share of a segment in reduced routing that starts to count
  reduced_capacity_threshold: 60, // capacity_score below this counts as reduced (stressed-or-worse)
  trip_score: 3,
  signal_weights: { velocity: 1, breadth: 1, slope: 1, signal_justification: 2, uniformity: 1, corroboration: 1 },
  velocity_ref_fraction: 0.5, // velocity hits full strength when this share of the segment enters in-window
  slope_ref_fraction: 0.4,
  uniformity_capacity_stddev_max: 8, // capacity stddev below this (within reduced cohort) looks scripted
  uniformity_timing_stddev_sec_max: 30, // entry-gap stddev below this looks replayed
  uniformity_min_cohort: 3,
  fire_threshold: 0.5,
  extreme_threshold: 0.9,
  min_population: 4, // below this, the segment runs in degraded mode (population signals disabled)
  min_segment_size: 4, // per-segment evaluation requires at least this many analysts
  workload_window_minutes: 60,
  low_workload_actions: 2, // <= this many recent ticket actions = not workload-justified
  low_open_assignments: 1, // <= this many open/in-progress assignments = not workload-justified
  corroboration_window_factor: 2,
  corroboration_ref_count: 3,
  per_segment: true,
};

function _mean(a) { return a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0; }
function _stddev(a) { if (a.length < 2) return 0; const m = _mean(a); return Math.sqrt(_mean(a.map((x) => (x - m) * (x - m)))); }
function _clamp(x, lo, hi) { return Math.max(lo, Math.min(hi, x)); }
function _round(x) { return Math.round(x * 1000) / 1000; }

function _mergeConfig(raw) {
  let cfg = raw;
  if (typeof raw === 'string') { try { cfg = JSON.parse(raw); } catch (_e) { cfg = {}; } }
  if (!cfg || typeof cfg !== 'object') cfg = {};
  const merged = { ...DEFAULTS, ...cfg };
  merged.signal_weights = { ...DEFAULTS.signal_weights, ...(cfg.signal_weights || {}) };
  return merged;
}

function _evaluateSegment(db, cfg, rows, label, now, winMs, overrideSet) {
  const activeCount = rows.length;
  const degraded = activeCount < cfg.min_population;
  const ids = rows.map((a) => a.id);

  const reduced = rows.filter(
    (a) => (a.capacity_score != null && a.capacity_score < cfg.reduced_capacity_threshold) || overrideSet.has(a.id)
  );
  const reducedCount = reduced.length;
  const pct = activeCount ? (reducedCount / activeCount) * 100 : 0;

  const nowIso = new Date(now).toISOString();
  const winStart = new Date(now - winMs).toISOString();
  const priorStart = new Date(now - 2 * winMs).toISOString();

  let entries = [];
  let priorCount = 0;
  if (ids.length) {
    const ph = ids.map(() => '?').join(',');
    try {
      entries = db
        .prepare(`SELECT analyst_id, created_at FROM routing_overrides WHERE type = 'reduced_load' AND created_at >= ? AND created_at <= ? AND analyst_id IN (${ph})`)
        .all(winStart, nowIso, ...ids);
      priorCount = db
        .prepare(`SELECT COUNT(*) AS c FROM routing_overrides WHERE type = 'reduced_load' AND created_at >= ? AND created_at < ? AND analyst_id IN (${ph})`)
        .get(priorStart, winStart, ...ids).c;
    } catch (_e) { entries = []; priorCount = 0; }
  }
  const entryCount = entries.length;

  // 1. velocity
  const velRef = Math.max(1, Math.ceil(cfg.velocity_ref_fraction * activeCount));
  const velocity = _clamp(entryCount / velRef, 0, 1);

  // 2. breadth (population signal — disabled in degraded mode)
  let breadth = 0;
  if (!degraded && activeCount) breadth = _clamp((pct - cfg.threshold_pct) / Math.max(1, 100 - cfg.threshold_pct), 0, 1);

  // 3. slope (population signal)
  let slope = 0;
  if (!degraded) {
    const slopeRef = Math.max(1, Math.ceil(cfg.slope_ref_fraction * activeCount));
    slope = _clamp((entryCount - priorCount) / slopeRef, 0, 1);
  }

  // 4. signal_justification (LINCHPIN): cross-check each reduction against the
  // server's independent workload record. A genuinely reduced analyst is busy
  // (recent ticket actions and/or open assignments). Reduced-but-idle implies
  // the reduction was injected rather than earned. A single idle analyst is
  // damped; coordinated idle reductions reach full strength.
  let unjustified = 0;
  let justification = 0;
  if (reducedCount) {
    const wWinStart = new Date(now - cfg.workload_window_minutes * 60000).toISOString();
    for (const a of reduced) {
      let actions = 0;
      let openA = 0;
      try { actions = db.prepare("SELECT COUNT(*) AS c FROM ticket_actions WHERE analyst_id = ? AND created_at >= ?").get(a.id, wWinStart).c; } catch (_e) {}
      try { openA = db.prepare("SELECT COUNT(*) AS c FROM ticket_assignments WHERE analyst_id = ? AND status IN ('open', 'in_progress')").get(a.id).c; } catch (_e) {}
      const justifiedByWorkload = actions > cfg.low_workload_actions || openA > cfg.low_open_assignments;
      if (!justifiedByWorkload) unjustified++;
    }
    justification = (unjustified / reducedCount) * _clamp(unjustified / 2, 0, 1);
  }

  // 5. uniformity / replay (population signal)
  let uniformity = 0;
  let capStd = null;
  if (reducedCount >= cfg.uniformity_min_cohort) {
    const caps = reduced.map((a) => (a.capacity_score == null ? cfg.reduced_capacity_threshold : a.capacity_score));
    capStd = _stddev(caps);
    const capUni = _clamp((cfg.uniformity_capacity_stddev_max - capStd) / cfg.uniformity_capacity_stddev_max, 0, 1);
    let timeUni = 0;
    if (entryCount >= cfg.uniformity_min_cohort) {
      const ts = entries.map((e) => Date.parse(e.created_at)).filter((n) => !Number.isNaN(n)).sort((x, y) => x - y);
      if (ts.length >= cfg.uniformity_min_cohort) {
        const gaps = [];
        for (let i = 1; i < ts.length; i++) gaps.push((ts[i] - ts[i - 1]) / 1000);
        const gStd = _stddev(gaps);
        timeUni = _clamp((cfg.uniformity_timing_stddev_sec_max - gStd) / cfg.uniformity_timing_stddev_sec_max, 0, 1);
      }
    }
    uniformity = Math.max(capUni, timeUni);
  }

  // 6. corroboration (global security context — same across segments)
  let corrCount = 0;
  let corroboration = 0;
  try {
    const corrStart = new Date(now - cfg.corroboration_window_factor * winMs).toISOString();
    corrCount = db
      .prepare(
        "SELECT COUNT(*) AS c FROM audit_log WHERE timestamp >= ? AND (event_type LIKE '%FAIL%' OR event_type LIKE '%COMPROMISE%' OR event_type LIKE '%UNVERIFIED%' OR event_type LIKE '%INTRUSION%' OR event_type LIKE '%FUSE%' OR event_type LIKE '%FIM%' OR event_type LIKE '%TAMPER%' OR event_type LIKE '%BREACH%')"
      )
      .get(corrStart).c;
    corroboration = _clamp(corrCount / cfg.corroboration_ref_count, 0, 1);
  } catch (_e) { corroboration = 0; }

  const strengths = { velocity, breadth, slope, signal_justification: justification, uniformity, corroboration };
  const meta = {
    velocity: { entries_in_window: entryCount, ref: velRef },
    breadth: { pct_in_reduced: _round(pct), threshold_pct: cfg.threshold_pct, reduced: reducedCount, active: activeCount },
    slope: { entries_in_window: entryCount, prior_window: priorCount },
    signal_justification: { unjustified, reduced: reducedCount },
    uniformity: { cohort: reducedCount, capacity_stddev: capStd == null ? null : _round(capStd) },
    corroboration: { security_events: corrCount },
  };

  const signals = {};
  let score = 0;
  for (const k of Object.keys(strengths)) {
    const strength = strengths[k];
    const weight = cfg.signal_weights[k] != null ? cfg.signal_weights[k] : 1;
    const contribution = weight * strength;
    score += contribution;
    signals[k] = { strength: _round(strength), weight, contribution: _round(contribution), fired: strength >= cfg.fire_threshold, meta: meta[k] };
  }

  const extreme = justification >= cfg.extreme_threshold || breadth >= 0.95 || velocity >= 0.95;
  const tripped = score >= cfg.trip_score || extreme;

  return {
    label,
    score: _round(score),
    tripped,
    extreme,
    degraded,
    pct_in_reduced: _round(pct),
    reduced_count: reducedCount,
    active_count: activeCount,
    signals,
  };
}

// evaluate(db, config) -> verdict
function evaluate(db, rawConfig) {
  const cfg = _mergeConfig(rawConfig);
  const now = Date.now();
  const nowIso = new Date(now).toISOString();
  const winMs = cfg.window_minutes * 60000;

  let analysts;
  try {
    analysts = db.prepare("SELECT id, capacity_score, tier, shift FROM users WHERE role = 'analyst' AND active = 1").all();
  } catch (e) {
    logger.warn('tripwire-detector population query failed', { error: e.message });
    return { tripped: false, score: 0, trip_score: cfg.trip_score, pct_in_reduced: 0, segment: null, signals: {}, degraded: true, verdict: 'evaluation unavailable', evaluated_at: nowIso, segments_evaluated: [] };
  }

  let overrides = [];
  try {
    overrides = db
      .prepare("SELECT analyst_id FROM routing_overrides WHERE type = 'reduced_load' AND active = 1 AND (expires_at IS NULL OR expires_at > ?)")
      .all(nowIso);
  } catch (_e) { overrides = []; }
  const overrideSet = new Set(overrides.map((o) => o.analyst_id));

  const segments = [{ label: 'global', rows: analysts }];
  if (cfg.per_segment) {
    for (const t of [1, 2, 3]) {
      const rows = analysts.filter((a) => a.tier === t);
      if (rows.length >= cfg.min_segment_size) segments.push({ label: 'tier:' + t, rows });
    }
    for (const sh of ['day', 'swing', 'night']) {
      const rows = analysts.filter((a) => a.shift === sh);
      if (rows.length >= cfg.min_segment_size) segments.push({ label: 'shift:' + sh, rows });
    }
  }

  const results = segments.map((seg) => _evaluateSegment(db, cfg, seg.rows, seg.label, now, winMs, overrideSet));
  const trippedResults = results.filter((r) => r.tripped);
  const pool = trippedResults.length ? trippedResults : results;
  const rep = pool.slice().sort((a, b) => b.score - a.score)[0] || { label: null, score: 0, pct_in_reduced: 0, signals: {}, degraded: true };

  const anyTripped = trippedResults.length > 0;
  let verdict;
  if (anyTripped) {
    const fired = Object.keys(rep.signals).filter((k) => rep.signals[k].fired);
    verdict = `Tripwire condition met in segment "${rep.label}" (score ${rep.score} >= ${cfg.trip_score}${rep.extreme ? ', extreme single-signal' : ''}). ${rep.pct_in_reduced}% in reduced routing. Contributing signals: ${fired.join(', ') || 'none above fire threshold'}.`;
  } else {
    verdict = `No tripwire condition. Highest segment "${rep.label}" scored ${rep.score} (trip at ${cfg.trip_score}); ${rep.pct_in_reduced}% in reduced routing.`;
  }

  return {
    tripped: anyTripped,
    score: rep.score,
    trip_score: cfg.trip_score,
    pct_in_reduced: rep.pct_in_reduced,
    segment: rep.label,
    extreme: !!rep.extreme,
    degraded: !!rep.degraded,
    signals: rep.signals,
    verdict,
    evaluated_at: nowIso,
    segments_evaluated: results.map((r) => ({ segment: r.label, score: r.score, tripped: r.tripped, pct_in_reduced: r.pct_in_reduced, degraded: r.degraded })),
  };
}

module.exports = { evaluate, DEFAULTS };

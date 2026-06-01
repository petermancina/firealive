// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Integration Health Periodic Scheduler
//
// Self-rescheduling, jittered cycle that runs the integration-health probes on
// the admin-configured interval. It is a no-op until an admin enables BOTH the
// master toggle and the periodic toggle; while disabled it simply re-checks for
// the toggle on a short cadence. Each enabled cycle:
//   1. runs probeAll (honoring per-integration flags),
//   2. caches the result to config 'integration_health_last_results' (the same
//      cache the metrics feed and the /results endpoint read),
//   3. routes any genuine failures through the alert router (so a SOAR/SIEM/EDR
//      outage surfaces operationally). EDR failures are critical; others high.
//
// Cycles never overlap (the next run is scheduled only after the current one
// finishes) and the cycle never throws — a probe error must not kill the timer.
// ═══════════════════════════════════════════════════════════════════════════════

const LAST_RESULTS_KEY = 'integration_health_last_results';
const DEFAULT_DISABLED_RECHECK_MS = 5 * 60 * 1000; // re-check the toggle every 5 min while off
const CYCLE_JITTER_MS = 30 * 1000;                 // stagger cycle starts up to 30s
const DEFAULT_INITIAL_DELAY_MS = 60 * 1000;        // first check ~1 min after boot

// statuses that represent a real problem worth alerting on (benign/expected
// states — disabled / not_configured / not_implemented / deep_skipped — are not)
const FAILURE_STATUSES = new Set(['unreachable', 'auth_failed', 'permission_denied', 'timeout', 'error']);

async function routeFailures(db, result, routeAlert) {
  for (const r of (result && result.results) || []) {
    if (!r || !FAILURE_STATUSES.has(r.status)) continue;
    const severity = r.integration === 'edr' ? 'critical' : 'high';
    try {
      await routeAlert(db, {
        type: `INTEGRATION_HEALTH_${String(r.integration).toUpperCase()}`,
        severity,
        message: `${r.label || r.integration} health probe: ${r.status}${r.detail ? ' — ' + r.detail : ''}`,
        timestamp: new Date().toISOString(),
      });
    } catch (_) { /* best-effort; one failed alert must not block the others */ }
  }
}

async function runProbeCycle(db, deps) {
  const result = await deps.probeAll(db);
  try {
    db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(LAST_RESULTS_KEY, JSON.stringify(result));
  } catch (_) { /* caching is best-effort */ }
  await routeFailures(db, result, deps.routeAlert);
  return result;
}

function startIntegrationHealthScheduler(getDb, opts = {}) {
  const deps = {
    probeAll: opts.probeAll || require('./integration-health').probeAll,
    routeAlert: opts.routeAlert || require('./alert-router').routeAlert,
  };
  const ihCfg = opts.ihCfg || require('./integration-health-config');
  const disabledRecheckMs = opts.disabledRecheckMs || DEFAULT_DISABLED_RECHECK_MS;
  let timer = null;
  let stopped = false;

  function schedule(baseMs) {
    if (stopped) return;
    const jitter = Math.floor(Math.random() * Math.min(CYCLE_JITTER_MS, baseMs * 0.5));
    timer = setTimeout(cycle, Math.max(1000, baseMs + jitter));
    if (timer && timer.unref) timer.unref();
  }

  async function cycle() {
    if (stopped) return;
    let delayMs = disabledRecheckMs;
    let db = null;
    try { db = getDb(); } catch (_) { db = null; }
    try {
      if (db) {
        let enabled = false;
        let intervalMin = 60;
        try { enabled = ihCfg.isPeriodicEnabled(db); intervalMin = ihCfg.getIntervalMinutes(db); } catch (_) {}
        if (enabled) {
          await runProbeCycle(db, deps);
          delayMs = intervalMin * 60000;
        } else {
          delayMs = Math.min(disabledRecheckMs, intervalMin * 60000);
        }
      }
    } catch (_) {
      // swallow — the timer must survive a bad cycle
    } finally {
      if (db) { try { db.close(); } catch (_) {} }
    }
    if (!stopped) schedule(delayMs);
  }

  schedule(opts.initialDelayMs != null ? opts.initialDelayMs : DEFAULT_INITIAL_DELAY_MS);
  return { stop() { stopped = true; if (timer) clearTimeout(timer); } };
}

module.exports = { startIntegrationHealthScheduler, runProbeCycle, routeFailures, LAST_RESULTS_KEY, FAILURE_STATUSES };

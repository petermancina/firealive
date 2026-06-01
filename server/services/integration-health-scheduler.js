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

// ── On-update smoke test ────────────────────────────────────────────────────
// Detects a build change (via lib/version buildId, recorded in config) and, when
// probing is enabled, runs a single probe cycle shortly after boot so config
// drift introduced by a deploy/update surfaces immediately rather than waiting
// for the first periodic cycle. Runs at most once per build. Never throws.
const LAST_PROBED_BUILD_KEY = 'integration_health_last_probed_build';

function runUpdateSmokeTest(getDb, opts = {}) {
  const deps = {
    probeAll: opts.probeAll || require('./integration-health').probeAll,
    routeAlert: opts.routeAlert || require('./alert-router').routeAlert,
  };
  const ihCfg = opts.ihCfg || require('./integration-health-config');
  const versionMod = opts.version || require('../lib/version');
  const currentBuild = String(versionMod.buildId || versionMod.versionLabel || 'unknown');
  const delayMs = opts.delayMs != null ? opts.delayMs : 30000;

  let db = null;
  try { db = getDb(); } catch (_) { db = null; }
  if (!db) return { ran: false, reason: 'no_db' };

  let master = false;
  try {
    const r = db.prepare('SELECT value FROM config WHERE key = ?').get(LAST_PROBED_BUILD_KEY);
    if (r && r.value === currentBuild) { try { db.close(); } catch (_) {} return { ran: false, reason: 'already_probed_build', build: currentBuild }; }
    // record now so subsequent boots of the same build do not re-trigger
    db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(LAST_PROBED_BUILD_KEY, currentBuild);
    master = ihCfg.isMasterEnabled(db);
  } catch (_) { /* fall through */ }
  try { db.close(); } catch (_) {}

  if (!master) return { ran: false, reason: 'master_disabled', build: currentBuild };

  const timer = setTimeout(async () => {
    let d = null;
    try { d = getDb(); } catch (_) { d = null; }
    if (!d) return;
    try { await runProbeCycle(d, deps); } catch (_) { /* best-effort smoke test */ }
    finally { try { d.close(); } catch (_) {} }
  }, Math.max(0, delayMs));
  if (timer && timer.unref) timer.unref();

  return { ran: true, scheduled: true, build: currentBuild };
}

module.exports = { startIntegrationHealthScheduler, runUpdateSmokeTest, runProbeCycle, routeFailures, LAST_RESULTS_KEY, LAST_PROBED_BUILD_KEY, FAILURE_STATUSES };

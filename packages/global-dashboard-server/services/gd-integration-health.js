// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Integration Health Orchestrator (B6a)
//
// GD-server twin of the regional integration-health harness. Runs read-only,
// non-mutating health probes against the GD's own external dependencies (its
// KMS / keystore, its backup storage destination, and inbound-MC signing-key
// trust freshness). This module is the generic harness; the concrete probe
// descriptors live in gd-integration-health-probes.js and are lazy-loaded, so
// this harness is stable.
//
// Gating order for every integration:
//   1. global master toggle off            -> 'disabled'
//   2. per-integration health-probe off     -> 'disabled'
//   3. integration not configured           -> 'not_configured'
//   4. no probe wired yet                    -> 'not_implemented'
//   5. otherwise run the probe (bounded by a timeout)
//
// Probe contract -- a descriptor's probe(db, entry) resolves to:
//   { ok, status?, detail? }
//   status (when set) in ok | unreachable | auth_failed | permission_denied
//                       | deep_skipped     (the harness adds disabled /
//                       not_configured / not_implemented / timeout / error)
//
// SOC-grade guardrails: opt-in (default off) at both the master and per-
// integration level; every probe bounded by a timeout (default 5s); bounded
// concurrency so a batch never floods external systems at once; jitter to
// stagger periodic runs; and probeAll NEVER throws -- health monitoring must not
// be able to crash a caller. The last run is cached to the config key
// integration_health_last_results, which the metrics-collector and the self-
// protection status endpoint read without re-probing.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const MASTER_KEY = 'integration_health_probes_enabled';
const CACHE_KEY = 'integration_health_last_results';
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_CONCURRENCY = 4;
const DEFAULT_JITTER_MS = 250;

// Statuses a probe (or the harness) may report.
const STATUSES = [
  'ok', 'unreachable', 'auth_failed', 'permission_denied', 'deep_skipped',
  'disabled', 'not_configured', 'not_implemented', 'timeout', 'error',
];

function isMasterEnabled(db) {
  try {
    const r = db.prepare('SELECT value FROM config WHERE key = ?').get(MASTER_KEY);
    return !!r && (r.value === 'true' || r.value === '1');
  } catch { return false; }
}

function _safe(fn, dflt) {
  try { return fn(); } catch { return dflt; }
}

function _sleep(ms) {
  return new Promise((resolve) => { const t = setTimeout(resolve, ms); if (t.unref) t.unref(); });
}

// Race a probe against a timeout. Never rejects.
async function _withTimeout(fn, ms) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ status: 'timeout', detail: `probe exceeded ${ms}ms` }), ms);
    if (timer.unref) timer.unref();
  });
  try {
    return await Promise.race([Promise.resolve().then(fn), timeout]);
  } catch (e) {
    return { status: 'error', detail: e && e.message };
  } finally {
    clearTimeout(timer);
  }
}

function _normalize(r) {
  if (!r || typeof r !== 'object') return { status: 'error', detail: 'probe returned no result' };
  if (r.status && STATUSES.includes(r.status)) return { status: r.status, detail: r.detail || null };
  if (r.ok === true) return { status: 'ok', detail: r.detail || null };
  return { status: 'error', detail: r.detail || 'probe failed' };
}

// Concurrency-bounded task pool. tasks: array of () => Promise<result>.
async function _runBounded(tasks, n) {
  const results = new Array(tasks.length);
  let next = 0;
  async function worker() {
    while (next < tasks.length) {
      const idx = next++;
      results[idx] = await tasks[idx]();
    }
  }
  const count = Math.min(Math.max(1, n), tasks.length || 1);
  const workers = [];
  for (let w = 0; w < count; w++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

function _loadRegistry() {
  try {
    const m = require('./gd-integration-health-probes');
    return Array.isArray(m.registry) ? m.registry : [];
  } catch { return []; }
}

async function _evalEntry(db, entry, master, timeoutMs, jitterMs) {
  try {
    if (!master) return { status: 'disabled', detail: 'health-probe master toggle off' };
    if (!_safe(() => entry.enabled(db), false)) return { status: 'disabled', detail: 'not enabled for this integration' };
    if (!_safe(() => entry.configured(db), false)) return { status: 'not_configured' };
    if (typeof entry.probe !== 'function') return { status: 'not_implemented' };
    if (jitterMs > 0) await _sleep(Math.random() * jitterMs);
    const r = await _withTimeout(() => entry.probe(db, entry), timeoutMs);
    return _normalize(r);
  } catch (e) {
    return { status: 'error', detail: e && e.message };
  }
}

// ── Public entry ──────────────────────────────────────────────────────────────
//
// probeAll(db, opts?) -> {
//   ranAt, masterEnabled,
//   results: [{ integration, label, status, ok, detail, latencyMs }],
//   summary: { total, ok, byStatus }
// }
// opts: { registry, timeoutMs, concurrency, jitterMs, master }  (all optional;
//        registry/master overridable for testing or for a forced run)
//
async function probeAll(db, opts = {}) {
  const out = { ranAt: new Date().toISOString(), masterEnabled: false, results: [], summary: { total: 0, ok: 0, byStatus: {} } };
  try {
    const registry = opts.registry || _loadRegistry();
    const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
    const concurrency = opts.concurrency || DEFAULT_CONCURRENCY;
    const jitterMs = opts.jitterMs != null ? opts.jitterMs : DEFAULT_JITTER_MS;
    const master = (opts.master != null) ? !!opts.master : isMasterEnabled(db);
    out.masterEnabled = master;

    const tasks = registry.map((entry) => async () => {
      const started = Date.now();
      const r = await _evalEntry(db, entry, master, timeoutMs, jitterMs);
      return {
        integration: entry.key,
        label: entry.label || entry.key,
        status: r.status,
        ok: r.status === 'ok',
        detail: r.detail || null,
        latencyMs: Date.now() - started,
      };
    });

    out.results = await _runBounded(tasks, concurrency);
    const by = {};
    for (const r of out.results) by[r.status] = (by[r.status] || 0) + 1;
    out.summary = { total: out.results.length, ok: out.results.filter((r) => r.ok).length, byStatus: by };
  } catch (e) {
    out.error = e && e.message;
  }
  return out;
}

// ── Result caching (read by the metrics-collector + self-protection status) ──
// Best-effort: caching must not break a probe run.
function cacheResults(db, result) {
  try {
    db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(CACHE_KEY, JSON.stringify(result));
    return true;
  } catch { return false; }
}

function getCachedResults(db) {
  try {
    const row = db.prepare('SELECT value FROM config WHERE key = ?').get(CACHE_KEY);
    return row && row.value ? JSON.parse(row.value) : null;
  } catch { return null; }
}

// Run the probes and persist the run. Used by the boot scheduler and the
// run-now endpoint; returns the same shape as probeAll.
async function runAndCache(db, opts = {}) {
  const r = await probeAll(db, opts);
  cacheResults(db, r);
  return r;
}

module.exports = {
  probeAll, runAndCache, cacheResults, getCachedResults, isMasterEnabled,
  MASTER_KEY, CACHE_KEY, STATUSES, DEFAULT_TIMEOUT_MS, DEFAULT_CONCURRENCY,
};

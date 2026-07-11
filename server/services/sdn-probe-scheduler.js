// FIREALIVE -- SDN posture probe scheduler (B5i SDN Mode)
//
// Mode-gated, self-rescheduling cycle that drives the SDN posture state machine.
// A no-op outside sdn mode (it simply re-checks the mode on a short cadence).
// In sdn mode each cycle:
//   1. lists the enabled SDN integrations,
//   2. for each, decrypts the Tier-1 credential blob, resolves the read-only
//      adapter via the registry, and runs its probe(),
//   3. folds the result into recordProbeResult, which updates the debounce
//      counters and re-evaluates aggregate posture -- emitting the degraded /
//      restored transition and the operator alert when the boundary is crossed.
//
// Cycles never overlap (the next run is scheduled only after the current one
// finishes), the cycle never throws (a probe error must not kill the timer),
// and the timer is unref'd so it never holds the process open. Every probe is
// read-only toward the controller.
//
// ASCII only; no template literals.

const { logger } = require('./logger');
const { openTier1 } = require('./tier1-seal');
const deploymentMode = require('./deployment-mode');
const sdnRegistry = require('./sdn');
const sdnPosture = require('./sdn-posture');

const DEFAULT_PROBE_INTERVAL_MS = 60 * 1000;       // probe enabled integrations every 60s
const DEFAULT_DISABLED_RECHECK_MS = 5 * 60 * 1000; // re-check the mode every 5 min while not sdn
const CYCLE_JITTER_MS = 15 * 1000;                 // stagger cycle starts up to 15s
const DEFAULT_INITIAL_DELAY_MS = 45 * 1000;        // first cycle ~45s after boot

// Decrypt + parse a Tier-1 credential blob (a BLOB column or a base64 string).
function decryptCredentials(blob) {
  if (!blob) return {};
  return openTier1('sdn_integrations.api_credentials_encrypted', blob);
}

// Probe one integration row and fold the result into the posture machine. Never
// throws -- a single integration's failure is recorded as a failed probe, not a
// scheduler crash. A credential-decrypt or adapter-resolution failure is itself
// recorded as an error probe (FireAlive cannot verify that integration).
async function probeIntegration(db, row, deps) {
  let status = 'error';
  let detail = null;
  try {
    let credentials;
    try {
      credentials = deps.decryptCredentials(row.api_credentials_encrypted) || {};
    } catch (e) {
      deps.recordProbeResult(db, { integrationId: row.id, status: 'error', detail: 'credential decrypt failed' });
      return;
    }
    const adapter = deps.getAdapter(row.platform);
    const config = {
      apiEndpoint: row.api_endpoint,
      endpointFingerprint: row.endpoint_fingerprint,
      credentials: credentials,
    };
    const result = await adapter.probe(config);
    status = (result && result.status) || 'error';
    detail = (result && result.detail) || null;
  } catch (e) {
    status = 'error';
    detail = e.message;
  }
  try {
    deps.recordProbeResult(db, { integrationId: row.id, status: status, detail: detail });
  } catch (e) {
    logger.warn('SDN probe scheduler could not record a probe result', { integrationId: row.id, error: e.message });
  }
}

// Run one full probe cycle across all enabled integrations.
async function runProbeCycle(db, deps) {
  const rows = db.prepare(
    'SELECT id, platform, api_endpoint, endpoint_fingerprint, api_credentials_encrypted FROM sdn_integrations WHERE enabled = 1'
  ).all();
  for (let i = 0; i < rows.length; i++) {
    await probeIntegration(db, rows[i], deps);
  }
  return rows.length;
}

function startSdnProbeScheduler(getDb, opts) {
  opts = opts || {};
  const deps = {
    getAdapter: opts.getAdapter || sdnRegistry.getAdapter,
    recordProbeResult: opts.recordProbeResult || sdnPosture.recordProbeResult,
    decryptCredentials: opts.decryptCredentials || decryptCredentials,
  };
  const probeIntervalMs = opts.probeIntervalMs || DEFAULT_PROBE_INTERVAL_MS;
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
    try { db = getDb(); } catch (_e) { db = null; }
    try {
      if (db) {
        let sdn = false;
        try { sdn = deploymentMode.getMode(db) === 'sdn'; } catch (_e) { sdn = false; }
        if (sdn) {
          await runProbeCycle(db, deps);
          delayMs = probeIntervalMs;
        } else {
          delayMs = disabledRecheckMs;
        }
      }
    } catch (_e) {
      // swallow -- the timer must survive a bad cycle
    } finally {
      if (db) { try { db.close(); } catch (_e2) { /* ignore */ } }
    }
    if (!stopped) schedule(delayMs);
  }

  schedule(opts.initialDelayMs != null ? opts.initialDelayMs : DEFAULT_INITIAL_DELAY_MS);
  return { stop() { stopped = true; if (timer) clearTimeout(timer); } };
}

module.exports = { startSdnProbeScheduler, runProbeCycle, probeIntegration, decryptCredentials };

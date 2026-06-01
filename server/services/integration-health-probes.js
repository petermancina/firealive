// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Integration Health Probe Registry
//
// Concrete, read-only health probes consumed by the integration-health
// orchestrator (B3-C6). Each descriptor exposes:
//   { key, label, enabled(db), configured(db), probe(db, entry) }
// and probe() resolves to { ok, status?, detail? } per the harness contract.
//
// This commit (B3-C8) registers the first batch: KMS and cloud storage. Later
// commits append LDAP/AD + SIEM (C9) and SOAR + EDR (C10).
//
//   kms      — by default a lightweight, read-only check (enabled providers
//              configured + credentials present + last known live-probe status);
//              when the admin enables the KMS deep-probe flag it performs a live
//              wrap/unwrap round-trip per enabled provider (the existing
//              probeProvider path, which records last_probe_*).
//   storage  — live reachability probe per enabled backup destination, reusing
//              the destination adapters' own probe() via probeDestination.
// ═══════════════════════════════════════════════════════════════════════════════

const kms = require('./kms-providers');
const destinations = require('./backup-destinations');
const ihCfg = require('./integration-health-config');

function _list(fn) {
  try { const v = fn(); return Array.isArray(v) ? v : []; } catch { return []; }
}

function _isGoodProbeStatus(s) {
  return s === 'ok' || s === 'success' || s === 'passed';
}

// ── KMS ─────────────────────────────────────────────────────────────────────
async function kmsProbe(db) {
  const providers = _list(() => kms.listProviders(db, { enabled: true }));
  if (!providers.length) return { status: 'not_configured' };

  if (!ihCfg.getKmsDeep(db)) {
    // Lightweight, read-only: credentials present + last known live-probe status.
    const noCreds = providers.filter((p) => !p.has_credentials);
    if (noCreds.length) {
      return { ok: false, status: 'auth_failed', detail: `${noCreds.length} of ${providers.length} provider(s) missing credentials` };
    }
    const priorFail = providers
      .map((p) => p.last_probe_status)
      .find((s) => s && !_isGoodProbeStatus(s));
    let detail = `metadata check: ${providers.length} provider(s) configured with credentials; live round-trip skipped (enable the KMS deep-probe flag for that)`;
    if (priorFail) detail += `; note: a prior live probe reported '${priorFail}'`;
    return { ok: true, status: 'ok', detail };
  }

  // Deep: live wrap/unwrap round-trip per enabled provider.
  const ctx = { user_id: 'system:integration-health' };
  let okCount = 0;
  const errs = [];
  for (const p of providers) {
    try {
      const r = await kms.probeProvider(db, p.id, ctx);
      if (r && r.ok) okCount++;
      else errs.push(`${p.name || p.id}: ${(r && r.error) || 'failed'}`);
    } catch (e) {
      errs.push(`${p.name || p.id}: ${e.message}`);
    }
  }
  if (okCount === providers.length) return { ok: true, status: 'ok', detail: `deep round-trip ok on ${okCount} provider(s)` };
  if (okCount === 0) return { ok: false, status: 'unreachable', detail: errs.join('; ') };
  return { ok: false, status: 'error', detail: `${okCount}/${providers.length} ok; ${errs.join('; ')}` };
}

// ── Cloud storage ─────────────────────────────────────────────────────────────
async function storageProbe(db) {
  const dests = _list(() => destinations.listDestinations(db, { enabledOnly: true }));
  if (!dests.length) return { status: 'not_configured' };

  let okCount = 0;
  const errs = [];
  for (const d of dests) {
    try {
      const r = await destinations.probeDestination(db, d.id);
      if (r && r.ok) okCount++;
      else errs.push(`${d.name || d.id}: ${(r && r.error) || 'failed'}`);
    } catch (e) {
      errs.push(`${d.name || d.id}: ${e.message}`);
    }
  }
  if (okCount === dests.length) return { ok: true, status: 'ok', detail: `${okCount} destination(s) reachable` };
  if (okCount === 0) return { ok: false, status: 'unreachable', detail: errs.join('; ') };
  return { ok: false, status: 'error', detail: `${okCount}/${dests.length} reachable; ${errs.join('; ')}` };
}

const registry = [
  {
    key: 'kms',
    label: 'KMS / Key-Wrapping Providers',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'kms'),
    configured: (db) => _list(() => kms.listProviders(db, { enabled: true })).length > 0,
    probe: (db) => kmsProbe(db),
  },
  {
    key: 'storage',
    label: 'Cloud Backup Storage',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'storage'),
    configured: (db) => _list(() => destinations.listDestinations(db, { enabledOnly: true })).length > 0,
    probe: (db) => storageProbe(db),
  },
];

module.exports = { registry, kmsProbe, storageProbe };

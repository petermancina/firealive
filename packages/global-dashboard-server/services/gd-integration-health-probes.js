// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Integration Health Probe Registry (B6a)
//
// Concrete, read-only health probes consumed by the GD integration-health
// orchestrator. Each descriptor exposes:
//   { key, label, enabled(db), configured(db), probe(db, entry) }
// and probe() resolves to { ok, status?, detail? } per the harness contract.
//
// Scoped to the GD's OWN dependencies (the GD holds no analyst data, so there is
// nothing analyst-scoped to probe):
//
//   kms       — the GD's key-management posture: an active audit-chain signing
//               key is present (the key whose private half is wrapped at rest and
//               which signs the audit checkpoints), plus the hardware-keystore /
//               instance-anchor availability. Read-only; no wrap/unwrap.
//   storage   — the GD backup destination is reachable/writable. Until B6b adds
//               external destination routing, the destination is the built-in
//               local path (GD_BACKUPS_DIR or <gd-root>/data/backups); the probe
//               does a read-only writability check, no write.
//   mc_trust  — inbound-MC signing-key trust freshness: active MCs have approved
//               active signing keys, and those keys are fresh (rotation not
//               overdue); surfaces pending-approval backlog and stale keys.
//
// Per-integration enablement is read from the integration_health_config map
// (config key); the harness separately enforces the global master toggle.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const gdDataRoot = require('../lib/gd-data-root');

const HEALTH_CONFIG_KEY = 'integration_health_config';
const FRESHNESS_DAYS = 365; // an approved active MC signing key older than this is "rotation due"

// ── per-integration enable gate (reads the integration_health_config map) ─────
function _isIntegrationEnabled(db, key) {
  try {
    const row = db.prepare('SELECT value FROM config WHERE key = ?').get(HEALTH_CONFIG_KEY);
    if (!row || !row.value) return false;
    const cfg = JSON.parse(row.value);
    return !!(cfg && cfg[key] && cfg[key].enabled === true);
  } catch { return false; }
}

function _count(db, sql, ...args) {
  try { const r = db.prepare(sql).get(...args); return r ? (r.n || 0) : 0; } catch { return 0; }
}

// ── kms: GD KEK / keystore + signing-key wrap posture (read-only) ─────────────
async function kmsProbe(db) {
  const activeKeys = _count(db, 'SELECT COUNT(*) AS n FROM audit_chain_signing_keys WHERE is_active = 1');
  if (activeKeys < 1) {
    return { ok: false, status: 'error', detail: 'no active audit-chain signing key present (GD key posture degraded)' };
  }
  let hwAvailable = false, anchorAvailable = false, backend = 'n/a', platform = 'n/a';
  try {
    const ks = require('./gd-hardware-keystore');
    const d = ks.describe() || {};
    hwAvailable = d.available === true;
    backend = d.backend || 'n/a';
    platform = d.platform || 'n/a';
  } catch { /* keystore module unavailable in this context */ }
  try {
    const anchor = require('./gd-instance-anchor');
    anchorAvailable = anchor.isAvailable() === true;
  } catch { /* anchor module unavailable in this context */ }
  const detail = `active signing key(s): ${activeKeys}; hardware keystore: ${hwAvailable ? 'available' : 'unavailable'} ` +
    `(${backend}/${platform}); instance anchor: ${anchorAvailable ? 'available' : 'unavailable'}`;
  return { ok: true, status: 'ok', detail };
}

// ── storage: GD backup destination reachability (built-in local until B6b) ────
async function storageProbe() {
  // P1-1: the same resolver the backup engine uses, so the probe cannot report
  // on a directory the backups do not go to.
  const backupsDir = gdDataRoot.backupsDir();
  try {
    // Check the dir itself; if absent, walk up to the nearest existing ancestor
    // (the backup path is created on demand by the backup job). Read-only: an
    // access check only, never a write.
    let target = backupsDir;
    for (let i = 0; i < 4 && !fs.existsSync(target); i++) target = path.dirname(target);
    fs.accessSync(target, fs.constants.W_OK);
    return { ok: true, status: 'ok', detail: `built-in backup destination writable: ${backupsDir}` };
  } catch (e) {
    return { ok: false, status: 'permission_denied', detail: `backup destination not writable (${backupsDir}): ${(e && e.code) || (e && e.message)}` };
  }
}

// ── mc_trust: inbound-MC signing-key trust freshness (read-only) ──────────────
async function mcTrustProbe(db) {
  const activeMcs = _count(db, "SELECT COUNT(*) AS n FROM management_consoles WHERE status = 'active'");
  if (activeMcs === 0) return { status: 'not_configured', detail: 'no active management consoles to trust' };

  const approvedActive = _count(db, "SELECT COUNT(*) AS n FROM signing_keys WHERE is_active = 1 AND approval_status = 'approved'");
  const trustedMcs = _count(db, "SELECT COUNT(DISTINCT mc_id) AS n FROM signing_keys WHERE is_active = 1 AND approval_status = 'approved'");
  const pending = _count(db, "SELECT COUNT(*) AS n FROM signing_keys WHERE approval_status = 'pending_approval'");
  const stale = _count(db, "SELECT COUNT(*) AS n FROM signing_keys WHERE is_active = 1 AND approval_status = 'approved' AND registered_at < datetime('now', ?)", `-${FRESHNESS_DAYS} days`);

  const notes = [];
  if (pending > 0) notes.push(`${pending} key(s) pending CISO approval`);
  if (stale > 0) notes.push(`${stale} active key(s) older than ${FRESHNESS_DAYS}d (rotation due)`);

  if (approvedActive === 0) {
    return { ok: false, status: 'permission_denied', detail: [`${activeMcs} active MC(s) but no approved active signing keys`, ...notes].join('; ') };
  }
  const untrusted = activeMcs - trustedMcs;
  if (untrusted > 0) {
    return { ok: false, status: 'permission_denied', detail: [`${untrusted} of ${activeMcs} active MC(s) without an approved active key`, ...notes].join('; ') };
  }
  return { ok: true, status: 'ok', detail: [`${trustedMcs}/${activeMcs} MC(s) trusted with approved active keys`, ...notes].join('; ') };
}

const registry = [
  {
    key: 'kms',
    label: 'GD key management (KEK / keystore / signing-key posture)',
    enabled: (db) => _isIntegrationEnabled(db, 'kms'),
    configured: (db) => _count(db, 'SELECT COUNT(*) AS n FROM audit_chain_signing_keys') > 0,
    probe: kmsProbe,
  },
  {
    key: 'storage',
    label: 'GD backup destination (built-in local)',
    enabled: (db) => _isIntegrationEnabled(db, 'storage'),
    configured: () => true, // the built-in local destination is always present until B6b adds external routing
    probe: storageProbe,
  },
  {
    key: 'mc_trust',
    label: 'Inbound-MC signing-key trust freshness',
    enabled: (db) => _isIntegrationEnabled(db, 'mc_trust'),
    configured: (db) => _count(db, 'SELECT COUNT(*) AS n FROM signing_keys') > 0,
    probe: mcTrustProbe,
  },
];

module.exports = { registry, kmsProbe, storageProbe, mcTrustProbe };

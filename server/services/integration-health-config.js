// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Integration Health Config
//
// Canonical read/write surface for the integration-health feature flags, used by
// the probe descriptors (B3-C8..C10), the on-demand route (B3-C11), and the
// periodic scheduler (B3-C13).
//
// Two stores:
//   config key 'integration_health_probes_enabled'  — the master toggle (the
//       same standalone key the orchestrator harness reads). Default OFF.
//   config key 'integration_health_settings' (JSON)  — everything else:
//       { intervalMinutes, periodicEnabled, integrations:{<key>:bool}, kmsDeep }
//
// Everything defaults OFF / safe: nothing is probed until an admin opts in at
// both the master and the per-integration level. The per-integration flag is
// the flag only — the harness owns the master gate — so a descriptor's
// enabled(db) is just isIntegrationEnabled(db, key).
// ═══════════════════════════════════════════════════════════════════════════════

const MASTER_KEY = 'integration_health_probes_enabled';
const SETTINGS_KEY = 'integration_health_settings';

// Canonical set of probe-able integrations.
const INTEGRATION_KEYS = ['soar', 'siem', 'ticketing', 'iam', 'kms', 'storage', 'edr', 'sdn', 'sase', 'cloud', 'backup', 'notifications', 'scheduling', 'cicd'];

const DEFAULT_INTERVAL_MIN = 60;
const MIN_INTERVAL_MIN = 5;
const MAX_INTERVAL_MIN = 1440;

function _readJson(db, key) {
  try {
    const r = db.prepare('SELECT value FROM config WHERE key = ?').get(key);
    return r && r.value ? JSON.parse(r.value) : null;
  } catch { return null; }
}

function _clampInterval(n) {
  const v = parseInt(n, 10);
  if (!Number.isFinite(v)) return DEFAULT_INTERVAL_MIN;
  return Math.max(MIN_INTERVAL_MIN, Math.min(MAX_INTERVAL_MIN, v));
}

function isMasterEnabled(db) {
  try {
    const r = db.prepare('SELECT value FROM config WHERE key = ?').get(MASTER_KEY);
    return !!r && (r.value === 'true' || r.value === '1');
  } catch { return false; }
}

// Full, normalized settings snapshot (always returns every integration key).
function getSettings(db) {
  const raw = _readJson(db, SETTINGS_KEY) || {};
  const integrations = {};
  for (const k of INTEGRATION_KEYS) {
    integrations[k] = !!(raw.integrations && raw.integrations[k] === true);
  }
  return {
    master: isMasterEnabled(db),
    intervalMinutes: _clampInterval(raw.intervalMinutes),
    periodicEnabled: raw.periodicEnabled === true,
    integrations,
    kmsDeep: raw.kmsDeep === true,
  };
}

// Per-integration flag only (NOT ANDed with master — the harness gates master).
function isIntegrationEnabled(db, key) {
  return getSettings(db).integrations[key] === true;
}

function getKmsDeep(db) { return getSettings(db).kmsDeep === true; }
function getIntervalMinutes(db) { return getSettings(db).intervalMinutes; }

// Periodic probing runs only when the master is on AND periodic is enabled.
function isPeriodicEnabled(db) {
  const s = getSettings(db);
  return s.master && s.periodicEnabled;
}

function setMaster(db, on) {
  db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(MASTER_KEY, on ? 'true' : 'false');
}

// Merge a validated patch over the current settings; returns the new snapshot.
// patch may include: master(bool), intervalMinutes(num), periodicEnabled(bool),
// kmsDeep(bool), integrations({<key>:bool}). Unknown keys/types are ignored.
function updateSettings(db, patch) {
  const cur = getSettings(db);
  const next = {
    intervalMinutes: cur.intervalMinutes,
    periodicEnabled: cur.periodicEnabled,
    integrations: { ...cur.integrations },
    kmsDeep: cur.kmsDeep,
  };
  if (patch && typeof patch === 'object') {
    if (patch.intervalMinutes != null) next.intervalMinutes = _clampInterval(patch.intervalMinutes);
    if (typeof patch.periodicEnabled === 'boolean') next.periodicEnabled = patch.periodicEnabled;
    if (typeof patch.kmsDeep === 'boolean') next.kmsDeep = patch.kmsDeep;
    if (patch.integrations && typeof patch.integrations === 'object') {
      for (const k of INTEGRATION_KEYS) {
        if (typeof patch.integrations[k] === 'boolean') next.integrations[k] = patch.integrations[k];
      }
    }
  }
  db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(SETTINGS_KEY, JSON.stringify(next));
  if (patch && typeof patch.master === 'boolean') setMaster(db, patch.master);
  return getSettings(db);
}

module.exports = {
  MASTER_KEY, SETTINGS_KEY, INTEGRATION_KEYS,
  DEFAULT_INTERVAL_MIN, MIN_INTERVAL_MIN, MAX_INTERVAL_MIN,
  isMasterEnabled, getSettings, isIntegrationEnabled, getKmsDeep,
  getIntervalMinutes, isPeriodicEnabled, setMaster, updateSettings,
};

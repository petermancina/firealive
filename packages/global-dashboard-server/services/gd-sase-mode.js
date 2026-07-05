// FIREALIVE GD -- SASE Mode configuration and posture (B6c PR-4, read-only twin)
//
// Holds the operational state that accompanies the anchor-sealed sase deployment
// mode (the mode value itself is owned by deployment-mode.js):
//
//   - The operator-declared CONNECTOR SOURCES -- the source IP/CIDR allow-list of
//     the ZTNA App Connector that fronts FireAlive. In connector-tunneled SASE the
//     connector is the only network peer FireAlive should ever see, so this list
//     is the dark-app perimeter the admission gate enforces. It is stored as one
//     field in the sase_config blob (the config key 'sase_config'),
//     alongside the provider and ZTNA endpoint; it is topology, not a secret, and
//     has a single writer (the /api/sase/config route).
//
//   - The read-only POSTURE log -- an append-only record in gd_sase_posture_events of
//     dark-app / passthrough admission refusals and how FireAlive's own posture
//     changed (degraded / restored). SASE posture is event-driven: a direct (non-
//     connector) connection or a TLS-terminated (clientless) connection reaching
//     FireAlive is a definitive boundary failure, so posture LATCHES degraded on
//     the first such event and clears only on an explicit host-side restore -- it
//     never auto-recovers and never flaps. FireAlive never calls the SASE provider.
//
// Read-only twin of the Regional sase-mode.js. SASE has no controller layer, so
// this is a near-verbatim twin: only the config store (the GD's 'config' key/value
// table) and the posture table (gd_sase_posture_events) change. All
// functions take db as a parameter, matching the Regional service.
//
// ASCII only; no template literals.

const SASE_CONFIG_KEY = 'sase_config';

const EVENT_TYPES = [
  'direct_exposure_refused', 'passthrough_violation_refused',
  'posture_degraded', 'posture_restored'
];
const SEVERITIES = ['info', 'warning', 'critical'];

// Shape-only check for a connector source (hex digits, dots, colons, slash --
// covers IPv4/IPv6 addresses and CIDRs). Built from a string so the source has
// no escaped regex delimiters. Membership testing happens in the admission gate.
const CONNECTOR_SOURCE_SHAPE = new RegExp('^[0-9a-f:./]+$');

// The providers the wizard offers; kept in sync with the sase_config route. Used
// only to normalize the stored value for display, never to dial the provider.
const PROVIDERS = ['zscaler', 'netskope', 'palo_alto_prisma', 'cato', 'cloudflare', 'fortinet'];

function fail(code, message) {
  const e = new Error(message || code);
  e.code = code;
  return e;
}

function parseJson(value, fallback) {
  if (value == null) return fallback;
  try {
    const v = JSON.parse(value);
    return v == null ? fallback : v;
  } catch (e) {
    return fallback;
  }
}

// ---- Connector sources / config --------------------------------------------

// A connector source is a non-empty IPv4/IPv6 address or CIDR. Validate only the
// shape here, so a malformed entry is caught at configuration time; duplicates
// are dropped and values are lowercased. Capped in count and length so a stored
// value can never grow unbounded or smuggle in non-address characters.
function normalizeConnectorSources(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) throw fail('INVALID_CONNECTOR_SOURCES', 'connector sources must be an array');
  if (value.length > 64) throw fail('INVALID_CONNECTOR_SOURCES', 'too many connector sources (max 64)');
  const out = [];
  for (let i = 0; i < value.length; i++) {
    const s = value[i];
    if (typeof s !== 'string') throw fail('INVALID_CONNECTOR_SOURCES', 'each connector source must be a string');
    const t = s.trim().toLowerCase();
    if (t.length === 0) continue;
    if (t.length > 49) throw fail('INVALID_CONNECTOR_SOURCES', 'connector source is too long: ' + s);
    if (!CONNECTOR_SOURCE_SHAPE.test(t)) throw fail('INVALID_CONNECTOR_SOURCES', 'connector source has invalid characters: ' + s);
    if (out.indexOf(t) === -1) out.push(t);
  }
  return out;
}

// Read the sase_config blob. Returns sane defaults when it has not been configured
// yet, so callers never special-case null. connectorSources is normalized on read
// so a malformed stored value can never widen the dark-app perimeter -- a value
// that fails validation collapses to the empty (admit-while-unconfigured) list.
function getSaseConfig(db) {
  const row = db.prepare("SELECT value FROM config WHERE key = ?").get(SASE_CONFIG_KEY);
  const cfg = row ? parseJson(row.value, {}) : {};
  let connectorSources = [];
  try { connectorSources = normalizeConnectorSources(cfg.connectorSources); } catch (e) { connectorSources = []; }
  const provider = (typeof cfg.provider === 'string' && PROVIDERS.indexOf(cfg.provider) !== -1) ? cfg.provider : null;
  return {
    enabled: cfg.enabled === true,
    provider: provider,
    ztnaEndpoint: (typeof cfg.ztnaEndpoint === 'string') ? cfg.ztnaEndpoint : null,
    connectorSources: connectorSources,
    casbEnabled: cfg.casbEnabled === true,
    deployedAsSECaaS: cfg.deployedAsSECaaS === true,
  };
}

// Convenience: the normalized connector-source allow-list (the dark-app perimeter
// the admission gate enforces).
function getConnectorSources(db) {
  return getSaseConfig(db).connectorSources;
}

// ---- Posture ---------------------------------------------------------------

// Append a refusal observation or a posture transition. eventType must be one of
// EVENT_TYPES; detail is any JSON-serializable value (stored as TEXT). SASE posture
// is not per-integration, so there is no integration_id column.
function recordPostureEvent(db, opts) {
  const o = opts || {};
  if (EVENT_TYPES.indexOf(o.eventType) === -1) throw fail('INVALID_EVENT_TYPE', 'event type must be one of ' + EVENT_TYPES.join(', '));
  const severity = o.severity || 'info';
  if (SEVERITIES.indexOf(severity) === -1) throw fail('INVALID_SEVERITY', 'severity must be one of ' + SEVERITIES.join(', '));
  let detail = null;
  if (o.detail !== undefined && o.detail !== null) {
    detail = (typeof o.detail === 'string') ? o.detail : JSON.stringify(o.detail);
  }
  db.prepare('INSERT INTO gd_sase_posture_events (event_type, severity, detail) VALUES (?, ?, ?)').run(
    o.eventType,
    severity,
    detail
  );
}

// Derive the current posture from the append-only log. Posture LATCHES degraded:
// it is degraded while any boundary-failure event (a direct-exposure or a
// passthrough-violation refusal, or an explicit posture_degraded) has been
// recorded since the last posture_restored. A single observed breach is enough
// (assume-breach), and it never auto-recovers -- recovery is an explicit
// host-side posture_restored, recorded only after the operator has closed the
// exposure out of band. Returns the flag, when it last changed, and recent events.
function getPosture(db, opts) {
  const o = opts || {};
  const limit = (typeof o.recentLimit === 'number' && o.recentLimit > 0) ? o.recentLimit : 20;
  const lastRestore = db.prepare("SELECT observed_at FROM gd_sase_posture_events WHERE event_type = 'posture_restored' ORDER BY observed_at DESC, rowid DESC LIMIT 1").get();
  // The three boundary-failure events; degraded while one exists after the restore.
  let breach;
  if (lastRestore) {
    breach = db.prepare("SELECT event_type, observed_at FROM gd_sase_posture_events WHERE event_type IN ('direct_exposure_refused', 'passthrough_violation_refused', 'posture_degraded') AND observed_at > ? ORDER BY observed_at DESC, rowid DESC LIMIT 1").get(lastRestore.observed_at);
  } else {
    breach = db.prepare("SELECT event_type, observed_at FROM gd_sase_posture_events WHERE event_type IN ('direct_exposure_refused', 'passthrough_violation_refused', 'posture_degraded') ORDER BY observed_at DESC, rowid DESC LIMIT 1").get();
  }
  const degraded = !!breach;
  const recent = db.prepare('SELECT event_type, severity, detail, observed_at FROM gd_sase_posture_events ORDER BY observed_at DESC, rowid DESC LIMIT ?').all(limit);
  return {
    degraded: degraded,
    since: breach ? breach.observed_at : null,
    lastEvent: breach ? breach.event_type : null,
    restoredAt: lastRestore ? lastRestore.observed_at : null,
    recent: recent,
  };
}

module.exports = {
  getSaseConfig,
  getConnectorSources,
  normalizeConnectorSources,
  recordPostureEvent,
  getPosture,
  EVENT_TYPES,
  SEVERITIES,
  PROVIDERS,
  SASE_CONFIG_KEY,
};

// FIREALIVE GD -- SDN Mode configuration and posture (B6c PR-4, read-only twin)
//
// Read-only-tailored twin of the Regional server's sdn-mode.js. Holds the
// operational state that accompanies the anchor-sealed sdn deployment mode (the
// mode value itself is owned by gd-deployment-mode.js):
//
//   - The operator-declared NETWORK MAP -- the permitted segments the GD's own
//     components may connect from, stored as a single row in gd_sdn_network_map.
//     This is the admission allow-list; it is network topology, not a secret, so
//     it is kept unencrypted. The GD is read-only with respect to the SDN: it
//     holds no controller-integration credentials and drives no controller, so
//     the Regional tier-segment map and SD-WAN site fields are omitted here.
//
//   - The read-only POSTURE log -- an append-only record in gd_sdn_posture_events
//     of admission refusals and the GD's own posture transitions (degraded /
//     restored). The GD never acts on the SDN; these are observations and self-
//     protection transitions only. The Regional probe / topology_read /
//     segmentation_read events belong to the controller-integration role, which
//     the read-only GD does not have.
//
// ASCII only; no template literals.

const NETWORK_MAP_ID = 'default';

// Admission-scoped event types (matches the gd_sdn_posture_events CHECK).
const EVENT_TYPES = ['admission_refused', 'posture_degraded', 'posture_restored'];
const SEVERITIES = ['info', 'warning', 'critical'];

// Shape-only check for a permitted segment (hex digits, dots, colons, slash --
// covers IPv4/IPv6 addresses and CIDRs). Built from a string so the source has
// no escaped regex delimiters. Membership testing happens in the admission gate.
const SEGMENT_SHAPE = new RegExp('^[0-9a-f:./]+$');

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

// ---- Network map -----------------------------------------------------------

// Read the operator-declared admission allow-list. Returns an empty list when it
// has not been configured yet, so callers never have to special-case null.
function getNetworkMap(db) {
  const row = db.prepare('SELECT permitted_segments, updated_at FROM gd_sdn_network_map WHERE id = ?').get(NETWORK_MAP_ID);
  if (!row) {
    return { permittedSegments: [], updatedAt: null };
  }
  return {
    permittedSegments: parseJson(row.permitted_segments, []),
    updatedAt: row.updated_at || null,
  };
}

// A permitted segment is a non-empty IPv4/IPv6 address or CIDR. Validate only
// the shape here, so a malformed entry is caught at configuration time;
// duplicates are dropped and values are lowercased.
function normalizeSegments(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) throw fail('INVALID_SEGMENTS', 'permitted segments must be an array');
  const out = [];
  for (let i = 0; i < value.length; i++) {
    const s = value[i];
    if (typeof s !== 'string') throw fail('INVALID_SEGMENTS', 'each permitted segment must be a string');
    const t = s.trim().toLowerCase();
    if (t.length === 0) continue;
    if (t.length > 49) throw fail('INVALID_SEGMENTS', 'permitted segment is too long: ' + s);
    if (!SEGMENT_SHAPE.test(t)) throw fail('INVALID_SEGMENTS', 'permitted segment has invalid characters: ' + s);
    if (out.indexOf(t) === -1) out.push(t);
  }
  return out;
}

// Admin: replace the permitted-segment admission allow-list. permittedSegments
// left undefined keeps the current value. Records who updated it.
function setNetworkMap(db, opts) {
  const o = opts || {};
  const current = getNetworkMap(db);
  const permittedSegments = (o.permittedSegments === undefined) ? current.permittedSegments : normalizeSegments(o.permittedSegments);
  db.prepare('INSERT OR REPLACE INTO gd_sdn_network_map (id, permitted_segments, updated_by) VALUES (?, ?, ?)').run(
    NETWORK_MAP_ID,
    JSON.stringify(permittedSegments),
    o.updatedBy || null
  );
  return getNetworkMap(db);
}

// ---- Posture ---------------------------------------------------------------

// Append a read-only observation or a posture transition. eventType must be one
// of EVENT_TYPES; detail is any JSON-serializable value (stored as TEXT).
function recordPostureEvent(db, opts) {
  const o = opts || {};
  if (EVENT_TYPES.indexOf(o.eventType) === -1) throw fail('INVALID_EVENT_TYPE', 'event type must be one of ' + EVENT_TYPES.join(', '));
  const severity = o.severity || 'info';
  if (SEVERITIES.indexOf(severity) === -1) throw fail('INVALID_SEVERITY', 'severity must be one of ' + SEVERITIES.join(', '));
  let detail = null;
  if (o.detail !== undefined && o.detail !== null) {
    detail = (typeof o.detail === 'string') ? o.detail : JSON.stringify(o.detail);
  }
  db.prepare('INSERT INTO gd_sdn_posture_events (event_type, severity, detail) VALUES (?, ?, ?)').run(
    o.eventType,
    severity,
    detail
  );
}

// Derive the current posture from the append-only log: posture is degraded when
// the most recent degraded/restored transition is a degradation. Returns the
// flag, when it last changed, and the most recent events for display.
function getPosture(db, opts) {
  const o = opts || {};
  const limit = (typeof o.recentLimit === 'number' && o.recentLimit > 0) ? o.recentLimit : 20;
  const last = db.prepare("SELECT event_type, observed_at FROM gd_sdn_posture_events WHERE event_type IN ('posture_degraded', 'posture_restored') ORDER BY observed_at DESC, rowid DESC LIMIT 1").get();
  const degraded = !!last && last.event_type === 'posture_degraded';
  const recent = db.prepare('SELECT event_type, severity, detail, observed_at FROM gd_sdn_posture_events ORDER BY observed_at DESC, rowid DESC LIMIT ?').all(limit);
  return {
    degraded: degraded,
    since: last ? last.observed_at : null,
    lastTransition: last ? last.event_type : null,
    recent: recent,
  };
}

module.exports = {
  getNetworkMap,
  setNetworkMap,
  recordPostureEvent,
  getPosture,
  normalizeSegments,
  EVENT_TYPES,
  SEVERITIES,
  NETWORK_MAP_ID,
};

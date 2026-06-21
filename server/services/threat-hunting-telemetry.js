// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Telemetry Query Framework (B5m)
//
// The bounded query layer over the D2 domain collectors. It validates and clamps
// every request parameter, paginates with an opaque domain-bound cursor, and
// shapes the response envelope the formatters consume. It also computes the
// summary: aggregate, actor-free resource counts plus compromise indicators.
//
//   query(db, domain, params) -> { ok, domain, count, events, next_cursor, ... }
//                                or { ok:false, reason } for an invalid query, so
//                                the route can log a rejected_query outcome.
//   summary(db)               -> resource_metrics + integrity rollups. All counts
//                                are aggregates; no per-actor data and no burnout
//                                signal is read.
//
// The cursor encodes only (version, domain, rowid); it is bound to its domain so
// a cursor from one domain is rejected on another, and an out-of-range or
// malformed cursor is rejected rather than silently coerced.
// ═══════════════════════════════════════════════════════════════════════════════

const collectors = require('./threat-hunting-collectors');

const CURSOR_VERSION = 'v1';

// ── opaque, domain-bound cursor ──────────────────────────────────────────────
function encodeCursor(domain, rowid) {
  if (typeof domain !== 'string' || !domain) return null;
  if (!Number.isInteger(rowid) || rowid < 0) return null;
  const raw = CURSOR_VERSION + ':' + domain + ':' + rowid;
  return Buffer.from(raw, 'utf8').toString('base64')
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// Returns the afterRowid: 0 for an absent cursor (start), a positive integer for
// a valid one, or null for a malformed / wrong-domain / out-of-range cursor.
function decodeCursor(domain, cursor) {
  if (cursor === undefined || cursor === null || cursor === '') return 0;
  if (typeof cursor !== 'string' || cursor.length > 256) return null;
  let raw;
  try {
    const b64 = cursor.replace(/-/g, '+').replace(/_/g, '/');
    raw = Buffer.from(b64, 'base64').toString('utf8');
  } catch (_) {
    return null;
  }
  const parts = raw.split(':');
  if (parts.length !== 3 || parts[0] !== CURSOR_VERSION || parts[1] !== domain) return null;
  const rowid = Number(parts[2]);
  if (!Number.isInteger(rowid) || rowid < 0) return null;
  return rowid;
}

// ── bounded filter validation ────────────────────────────────────────────────
function isValidTimestamp(v) {
  if (typeof v !== 'string' || v.length > 40) return false;
  return /^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?Z?)?$/.test(v);
}

function dbNow(db) {
  try {
    const r = db.prepare("SELECT datetime('now') AS t").get();
    return r && r.t ? r.t : null;
  } catch (_) {
    return null;
  }
}

// Query one domain. Invalid parameters return { ok:false, reason } so the caller
// can record rejected_query; the data path is otherwise unchanged.
function query(db, domain, params) {
  if (!collectors.isDomain(domain)) return { ok: false, reason: 'unknown domain' };
  const p = params || {};

  let limit;
  if (p.limit !== undefined && p.limit !== null && p.limit !== '') {
    const n = Number(p.limit);
    if (!Number.isInteger(n) || n <= 0) return { ok: false, reason: 'invalid limit' };
    limit = n; // the collector clamps the upper bound
  }
  if (p.since !== undefined && p.since !== null && p.since !== '' && !isValidTimestamp(p.since)) {
    return { ok: false, reason: 'invalid since timestamp' };
  }
  if (p.until !== undefined && p.until !== null && p.until !== '' && !isValidTimestamp(p.until)) {
    return { ok: false, reason: 'invalid until timestamp' };
  }
  const afterRowid = decodeCursor(domain, p.cursor);
  if (afterRowid === null) return { ok: false, reason: 'invalid cursor' };

  const result = collectors.runCollector(db, domain, {
    afterRowid: afterRowid,
    limit: limit,
    since: (p.since || undefined),
    until: (p.until || undefined),
  });
  const nextCursor = result.hasMore ? encodeCursor(domain, result.lastRowid) : null;
  return {
    ok: true,
    domain: result.domain,
    label: result.label,
    count: result.rows.length,
    events: result.rows,
    has_more: result.hasMore,
    next_cursor: nextCursor,
  };
}

// ── summary: aggregate, actor-free counts + compromise indicators ────────────
function safeScalar(db, sql) {
  try {
    const r = db.prepare(sql).get();
    return r && typeof r.c === 'number' ? r.c : 0;
  } catch (_) {
    return 0;
  }
}

function summary(db) {
  const resource_metrics = {
    active_sessions: safeScalar(db, "SELECT COUNT(*) AS c FROM sessions WHERE expires_at > datetime('now')"),
    total_sessions: safeScalar(db, 'SELECT COUNT(*) AS c FROM sessions'),
    auth_events_24h: safeScalar(db, "SELECT COUNT(*) AS c FROM auth_log WHERE timestamp >= datetime('now', '-1 day')"),
    auth_events_7d: safeScalar(db, "SELECT COUNT(*) AS c FROM auth_log WHERE timestamp >= datetime('now', '-7 days')"),
    audit_events_24h: safeScalar(db, "SELECT COUNT(*) AS c FROM audit_log WHERE timestamp >= datetime('now', '-1 day')"),
    audit_events_7d: safeScalar(db, "SELECT COUNT(*) AS c FROM audit_log WHERE timestamp >= datetime('now', '-7 days')"),
  };

  const self_scan_7d = { clean: 0, warning: 0, fail: 0, inconclusive: 0, unreachable: 0 };
  try {
    const rows = db.prepare(
      "SELECT status, COUNT(*) AS c FROM compromise_scan_results "
        + "WHERE received_at >= datetime('now', '-7 days') GROUP BY status"
    ).all();
    for (const r of rows) {
      if (Object.prototype.hasOwnProperty.call(self_scan_7d, r.status)) self_scan_7d[r.status] = r.c;
    }
  } catch (_) { /* leave zeros */ }

  const integrity = {
    self_scan_7d: self_scan_7d,
    active_tamper_lockouts: safeScalar(db, 'SELECT COUNT(*) AS c FROM tripwire_events WHERE lockout_active = 1 AND resolved_at IS NULL'),
    tripwire_events_7d: safeScalar(db, "SELECT COUNT(*) AS c FROM tripwire_events WHERE tripped_at >= datetime('now', '-7 days')"),
  };

  return {
    generated_at: dbNow(db),
    resource_metrics: resource_metrics,
    integrity: integrity,
  };
}

module.exports = {
  query,
  summary,
  encodeCursor,
  decodeCursor,
  isValidTimestamp,
  listDomains: collectors.listDomains,
  isDomain: collectors.isDomain,
  DOMAINS: collectors.DOMAINS,
};

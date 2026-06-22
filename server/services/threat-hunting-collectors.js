// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Domain Collectors (B5m)
//
// Read-only access to FireAlive's own security telemetry for an authorized
// hunter, one collector per domain. Each collector queries a single source table
// with a forward rowid cursor and an optional time window (all parameterized,
// structurally read-only) and projects every row through the D1 fail-closed
// allow-list for that domain, so actors are pseudonymized and only the named
// fields are ever emitted.
//
// Domains:
//   auth_events  <- auth_log               (logins, lockouts, method/reason)
//   sessions     <- sessions               (active/expired sessions; never the
//                                            refresh_token_hash)
//   audit_trail  <- audit_log              (privileged actions)
//   integrity    <- compromise_scan_results (endpoint self-scan tri-state +)
//
// DELIBERATELY EXCLUDED: analyst_metrics_deidentified is the burnout / pressure
// signal store (cognitive_load, dismiss rate, investigation time, ...). It is
// never a source here. The XDR "resource consumption metrics" option is served
// by safe aggregate counts in the telemetry summary, not by any burnout signal.
// ═══════════════════════════════════════════════════════════════════════════════

const ps = require('./threat-hunting-pseudonymize');

const MAX_PAGE = 500;
const DEFAULT_PAGE = 100;

function clampLimit(n) {
  const x = Number(n);
  if (!Number.isInteger(x) || x <= 0) return DEFAULT_PAGE;
  return Math.min(x, MAX_PAGE);
}

// Each descriptor names a single source table, the timestamp column the optional
// window filters on, the exact columns to read (rowid aliased to _rowid drives
// the cursor and is never emitted), and the D1 allow-list. Table/column names
// here are fixed constants; only the cursor, window, and limit are bound params.
const COLLECTORS = {
  auth_events: {
    key: 'auth_events',
    label: 'Authentication events',
    table: 'auth_log',
    tsColumn: 'timestamp',
    columns: 'rowid AS _rowid, timestamp, user, action, ip, method, reason, user_agent',
    allowList: [
      { from: 'timestamp' },
      { from: 'user', to: 'actor', pseudonym: true },
      { from: 'action' },
      { from: 'ip', to: 'source_ip' },
      { from: 'method' },
      { from: 'reason' },
      { from: 'user_agent' },
    ],
  },
  sessions: {
    key: 'sessions',
    label: 'Sessions',
    table: 'sessions',
    tsColumn: 'created_at',
    columns: 'rowid AS _rowid, id, user_id, ip_address, user_agent, created_at, expires_at',
    allowList: [
      { from: 'id', to: 'session_ref', pseudonym: 'session' },
      { from: 'user_id', to: 'actor', pseudonym: true },
      { from: 'ip_address', to: 'source_ip' },
      { from: 'user_agent' },
      { from: 'created_at' },
      { from: 'expires_at' },
    ],
  },
  audit_trail: {
    key: 'audit_trail',
    label: 'Audit trail',
    table: 'audit_log',
    tsColumn: 'timestamp',
    columns: 'rowid AS _rowid, timestamp, user_id, event_type, detail, ip_address',
    allowList: [
      { from: 'timestamp' },
      { from: 'user_id', to: 'actor', pseudonym: true },
      { from: 'event_type' },
      { from: 'detail' },
      { from: 'ip_address', to: 'source_ip' },
    ],
  },
  integrity: {
    key: 'integrity',
    label: 'Endpoint integrity self-scans',
    table: 'compromise_scan_results',
    tsColumn: 'received_at',
    columns: 'rowid AS _rowid, received_at, user_id, status, tests_total, tests_passed, '
      + 'tests_failed, tests_inconclusive, signature_verified, scan_started_at, scan_duration_ms',
    allowList: [
      { from: 'received_at' },
      { from: 'user_id', to: 'actor', pseudonym: true },
      { from: 'status' },
      { from: 'tests_total' },
      { from: 'tests_passed' },
      { from: 'tests_failed' },
      { from: 'tests_inconclusive' },
      { from: 'signature_verified', transform: (v) => v === 1 },
      { from: 'scan_started_at' },
      { from: 'scan_duration_ms' },
    ],
  },
};

function isDomain(key) {
  return Object.prototype.hasOwnProperty.call(COLLECTORS, key);
}

function listDomains() {
  return Object.keys(COLLECTORS).map((k) => ({ key: k, label: COLLECTORS[k].label }));
}

// Run one domain collector. opts: { afterRowid, limit, since, until }. Returns
// { domain, label, rows (projected), lastRowid, hasMore } or null for an unknown
// domain. since / until are compared against the domain's timestamp column.
function runCollector(db, key, opts) {
  const c = COLLECTORS[key];
  if (!c) return null;
  const o = opts || {};
  const limit = clampLimit(o.limit);
  const afterRowid = (Number.isInteger(o.afterRowid) && o.afterRowid > 0) ? o.afterRowid : 0;

  const params = [afterRowid];
  let where = 'rowid > ?';
  if (o.since) { where += ' AND ' + c.tsColumn + ' >= ?'; params.push(String(o.since)); }
  if (o.until) { where += ' AND ' + c.tsColumn + ' <= ?'; params.push(String(o.until)); }
  params.push(limit);

  const sql = 'SELECT ' + c.columns + ' FROM ' + c.table
    + ' WHERE ' + where + ' ORDER BY rowid ASC LIMIT ?';
  const stmt = db.prepare(sql);
  const rows = stmt.all.apply(stmt, params);

  let lastRowid = afterRowid;
  const projected = [];
  for (const row of rows) {
    if (typeof row._rowid === 'number') lastRowid = row._rowid;
    projected.push(ps.projectAllowed(db, row, c.allowList));
  }
  return {
    domain: key,
    label: c.label,
    rows: projected,
    lastRowid: lastRowid,
    hasMore: rows.length === limit,
  };
}

module.exports = {
  runCollector,
  listDomains,
  isDomain,
  DOMAINS: Object.keys(COLLECTORS),
  MAX_PAGE,
  DEFAULT_PAGE,
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD SERVER — Database Initialization
// Independent backend for the CISO Global Dashboard. 
// Stores: regional MC data, users, sessions, audit logs, configs, backups,
// notifications, compliance data, system health metrics.
// ═══════════════════════════════════════════════════════════════════════════════

const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const DB_PATH = process.env.GD_DB_PATH || path.join(__dirname, 'data', 'global-dashboard.db');

const SCHEMA = `
-- Users (CISOs, VPs, read-only analysts)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  role TEXT NOT NULL CHECK (role IN ('ciso', 'vp', 'readonly')),
  name TEXT NOT NULL,
  mfa_secret TEXT,
  mfa_enabled INTEGER DEFAULT 0,
  auth_method TEXT DEFAULT 'local' CHECK (auth_method IN ('local', 'saml', 'oidc', 'ldap')),
  created_at TEXT DEFAULT (datetime('now')),
  last_login TEXT
);

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  ip TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Connected Management Consoles (regional)
CREATE TABLE IF NOT EXISTS management_consoles (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  name TEXT NOT NULL,
  region TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  api_key TEXT NOT NULL,
  country TEXT,
  regulatory_framework TEXT DEFAULT 'none',
  status TEXT DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'offboarded')),
  analyst_count INTEGER DEFAULT 0,
  last_sync TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  offboarded_at TEXT
);

-- ── R3g PR3: MC SIGNING-KEY REGISTRY ─────────────────────────────────────
-- Per-MC Ed25519 public-key trust registry. Populated via the MC handshake
-- on first GD-push config setup (MC POSTs its just-generated public key to
-- POST /api/mc/:id/signing-key). Every inbound MC push verifies its
-- X-FA-Signature against an active row here, looked up by mc_id +
-- public_key_fingerprint.
--
-- TRUST MODEL: One active key per MC at a time (is_active = 1). When an MC
-- rotates its keypair, it registers the new public key and the GD demotes
-- the prior row (is_active = 0, sets rotated_out_at). Old rows are retained
-- so historical pushes signed under prior keys can still be verified during
-- the rotation grace window.
--
-- FINGERPRINT FORMAT: SHA-256 hex of the Ed25519 SPKI DER encoding
-- (64 lowercase hex chars). Matches the format used by the MC's
-- backup_signing_keys.public_key_fingerprint column so operators see a
-- consistent identifier across MC and GD logs.
--
-- ON DELETE CASCADE: removing an MC row (hard-delete, not the usual
-- status='offboarded' soft-delete) drops its trust rows; orphan keys
-- shouldn't outlive the MC they were registered for.
CREATE TABLE IF NOT EXISTS signing_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mc_id TEXT NOT NULL,
  public_key TEXT NOT NULL,                         -- PEM-encoded Ed25519 SPKI
  public_key_fingerprint TEXT NOT NULL,             -- SHA-256 hex of SPKI DER (64 chars)
  is_active INTEGER NOT NULL DEFAULT 1
    CHECK (is_active IN (0, 1)),
  registered_at TEXT DEFAULT (datetime('now')),
  rotated_out_at TEXT,                              -- when is_active flipped 1 -> 0
  notes TEXT,
  FOREIGN KEY (mc_id) REFERENCES management_consoles(id) ON DELETE CASCADE
);

-- Hot path for signature verification on every inbound push: look up
-- (mc_id, fingerprint) tuple and confirm is_active = 1.
CREATE INDEX IF NOT EXISTS idx_signing_keys_mc_fingerprint
  ON signing_keys(mc_id, public_key_fingerprint);

-- Partial index for the "find the active key for this MC" query path
-- used during MC re-handshake / admin inspection.
CREATE INDEX IF NOT EXISTS idx_signing_keys_active
  ON signing_keys(mc_id) WHERE is_active = 1;

-- ── R3g PR3: MC COMPLIANCE REPORT SUMMARIES ──────────────────────────────
-- Per-MC, per-framework compliance push summaries. Receives the daily
-- (or admin-tunable cadence) summary push from each connected MC. Each
-- row is one framework's compressed result: passed/total counts, top
-- failing controls, generated-at timestamp, digest hash of the full
-- report. The full report itself lives in mc_compliance_report_fulls
-- (mailbox-fulfilled on CISO request, not pushed continuously).
--
-- RETENTION: Rows accumulate over time as MCs continue pushing. The
-- materialized cross_region_rollup table reads the latest row per
-- (mc_id, framework) for O(1) CISO-side queries. Historical rows
-- preserve trend visibility but a future retention policy may prune
-- entries older than N days.
--
-- SIGNATURE_FINGERPRINT: identifies which signing_keys row verified the
-- push that delivered this report. Useful for forensic correlation if a
-- key rotation overlapped a reporting window.
CREATE TABLE IF NOT EXISTS mc_compliance_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mc_id TEXT NOT NULL,
  framework TEXT NOT NULL,                          -- e.g. 'hipaa', 'soc2', 'nist_csf'
  summary_json TEXT NOT NULL,                       -- JSON: {passed, total, perCategoryCounts,
                                                    --        topFailingControls[3], generatedAt, digestHash}
  signature_fingerprint TEXT NOT NULL,              -- which signing_keys.public_key_fingerprint
                                                    -- verified the delivering push
  received_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (mc_id) REFERENCES management_consoles(id) ON DELETE CASCADE
);

-- Hot path for CISO interactive queries and rollup updates: latest
-- summary per (mc_id, framework) ordered by received_at DESC.
CREATE INDEX IF NOT EXISTS idx_mc_compliance_reports_lookup
  ON mc_compliance_reports(mc_id, framework, received_at DESC);

-- ── R3g PR3: MC COMPLIANCE FULL REPORTS (mailbox-fulfilled) ──────────────
-- Storage for full compliance reports delivered via the mailbox pattern
-- (Foundational Rule 21). When a CISO requests a full report for a
-- specific (mc_id, framework), a row is written to mc_report_requests
-- below. The MC sees the pending request on its next push tick (via the
-- GET /api/mc/me/pending-requests poll), generates a fresh full report,
-- and POSTs it back to /api/ingest/compliance-reports?full=true. The
-- handler stores the report here and marks the request fulfilled.
--
-- 30-DAY TTL: full reports are large (tens of KB per framework × 16
-- frameworks × N MCs adds up); they're retained 30 days from receipt and
-- pruned by a periodic cleanup job that queries on the expires_at index.
-- CISOs who want a long-lived archived copy export from the UI before
-- expiry. TTL is currently hard-coded for v1.0.33; an open question in
-- the build plan tracks possible future operator configurability.
--
-- expires_at is materialized at insert time as received_at + 30 days via
-- SQLite date arithmetic in the DEFAULT clause; no background scheduler
-- needed to compute it.
CREATE TABLE IF NOT EXISTS mc_compliance_report_fulls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mc_id TEXT NOT NULL,
  framework TEXT NOT NULL,
  report_json TEXT NOT NULL,                        -- full generateComplianceReport output
  signature_fingerprint TEXT NOT NULL,              -- signing_keys row that verified the fulfilling push
  received_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL DEFAULT (datetime('now', '+30 days')),
  FOREIGN KEY (mc_id) REFERENCES management_consoles(id) ON DELETE CASCADE
);

-- Hot path: CISO retrieval of latest full report per (mc_id, framework).
CREATE INDEX IF NOT EXISTS idx_mc_full_reports_lookup
  ON mc_compliance_report_fulls(mc_id, framework, received_at DESC);

-- Background cleanup path: DELETE WHERE expires_at < datetime('now').
CREATE INDEX IF NOT EXISTS idx_mc_full_reports_expiry
  ON mc_compliance_report_fulls(expires_at);

-- ── R3g PR3: CISO FULL-REPORT REQUEST MAILBOX ────────────────────────────
-- The mailbox half of the mailbox pattern (Foundational Rule 21). A CISO
-- clicking "Request full report for Framework X from MC Y" in the GD UI
-- writes a pending row here. The MC reads pending rows for itself on its
-- next push tick (GET /api/mc/me/pending-requests, signature-
-- authenticated so an MC can only see its own requests). On fulfillment,
-- status flips 'pending' -> 'fulfilled' and fulfilled_report_id points
-- to the resulting mc_compliance_report_fulls row.
--
-- STATUS MACHINE:
--   pending    - written by CISO action, not yet fetched by MC
--   fulfilled  - MC delivered the full report; fulfilled_report_id is set
--   failed     - MC reported an error during report generation; error_detail
--                describes the cause (rare)
--   expired    - MC didn't fulfill within the timeout window (e.g. MC
--                offline for an extended period); cleanup job marks these
--
-- ON DELETE SET NULL on fulfilled_report_id: if the linked full report is
-- pruned by TTL cleanup, the request row survives as a historical record
-- but loses its pointer. The status field still reads 'fulfilled' so the
-- historical fact is preserved.
--
-- Concurrent CISO requests for the same (mc_id, framework) currently
-- result in two fulfilled rows (idempotent, slightly wasteful). An open
-- question in the build plan tracks dedup-at-request-time if scale ever
-- warrants it.
CREATE TABLE IF NOT EXISTS mc_report_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mc_id TEXT NOT NULL,
  framework TEXT NOT NULL,
  requested_by_user_id TEXT NOT NULL,
  requested_at TEXT DEFAULT (datetime('now')),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'fulfilled', 'failed', 'expired')),
  fulfilled_at TEXT,
  fulfilled_report_id INTEGER,
  error_detail TEXT,
  FOREIGN KEY (mc_id) REFERENCES management_consoles(id) ON DELETE CASCADE,
  FOREIGN KEY (requested_by_user_id) REFERENCES users(id),
  FOREIGN KEY (fulfilled_report_id) REFERENCES mc_compliance_report_fulls(id) ON DELETE SET NULL
);

-- Hot path for the MC's pending-request poll: pending rows for a
-- specific MC.
CREATE INDEX IF NOT EXISTS idx_mc_report_requests_pending
  ON mc_report_requests(mc_id) WHERE status = 'pending';

-- ── R3g PR3: CROSS-REGION COMPLIANCE ROLLUP (materialized aggregator) ────
-- Materialized per-(framework, MC) compliance state, updated as a side
-- effect of every successful compliance-summary ingest. Read-side stays
-- O(1) for CISO interactive queries regardless of MC count: 500 MCs ×
-- 16 frameworks = ~8000 rows, indexed lookups, no fan-out aggregation.
--
-- This is the standard SOC dashboard pattern: Splunk summary indexes,
-- Datadog rollups, Grafana recording rules. Write cost is paid at push
-- time (already a write transaction); read cost stays flat at any scale.
--
-- POPULATION: the compliance-reports ingest handler (added later in PR3)
-- upserts a row here for every (mc_id, framework) tuple in an incoming
-- push. Existing row gets last_push_at + passed + total + per_control_status
-- replaced; new (mc_id, framework) tuples get an insert. No background
-- recomputation; the table is always current as of the last push.
--
-- The materialized table doubles as a historical record of state-at-
-- push-time per region — useful audit trail for "what did Region X look
-- like on Date Y" queries (the last_push_at + a periodic snapshot
-- archive would extend this; out of scope for v1.0.33).
--
-- PRIMARY KEY (framework, mc_id) enforces one row per tuple and makes
-- the upsert pattern (INSERT ... ON CONFLICT DO UPDATE) efficient.
CREATE TABLE IF NOT EXISTS cross_region_rollup (
  framework TEXT NOT NULL,
  mc_id TEXT NOT NULL,
  passed INTEGER NOT NULL DEFAULT 0,                -- verifiedControls passing for this (mc, framework)
  total INTEGER NOT NULL DEFAULT 0,                 -- total verifiedControls for this (mc, framework)
  per_control_status TEXT,                          -- JSON {controlId: 'pass'|'warn'|'fail'} for drill-down
                                                    -- without joining back to mc_compliance_reports
  last_push_at TEXT NOT NULL,                       -- when the latest push for this tuple landed
  PRIMARY KEY (framework, mc_id),
  FOREIGN KEY (mc_id) REFERENCES management_consoles(id) ON DELETE CASCADE
);

-- "Show me all MCs' status for Framework X" query path.
CREATE INDEX IF NOT EXISTS idx_cross_region_rollup_framework
  ON cross_region_rollup(framework);

-- Regional aggregate data (received from MCs)
CREATE TABLE IF NOT EXISTS regional_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mc_id TEXT NOT NULL,
  timestamp TEXT DEFAULT (datetime('now')),
  health_score INTEGER,
  utilization_pct INTEGER,
  automation_rate INTEGER,
  cert_coverage_pct INTEGER,
  sla_compliance_pct INTEGER,
  turnover_risk TEXT CHECK (turnover_risk IN ('low', 'medium', 'high', 'critical')),
  analyst_count INTEGER,
  active_incidents INTEGER DEFAULT 0,
  burnout_routing_active INTEGER DEFAULT 1,
  proactive_breaks_given INTEGER DEFAULT 0,
  upskilling_hours_used INTEGER DEFAULT 0,
  FOREIGN KEY (mc_id) REFERENCES management_consoles(id)
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT DEFAULT (datetime('now')),
  user_id TEXT,
  event_type TEXT NOT NULL,
  detail TEXT,
  ip TEXT,
  severity TEXT DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'error', 'critical'))
);

-- Auth log (login attempts)
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT DEFAULT (datetime('now')),
  username TEXT,
  action TEXT NOT NULL,
  ip TEXT,
  method TEXT,
  reason TEXT
);

-- Configuration store
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Backup records
CREATE TABLE IF NOT EXISTS backups (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  type TEXT NOT NULL CHECK (type IN ('full', 'incremental', 'differential', 'snapshot')),
  status TEXT DEFAULT 'completed',
  size_bytes INTEGER,
  hash TEXT,
  destination TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  retention_until TEXT
);

-- Backup schedules
CREATE TABLE IF NOT EXISTS backup_schedules (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  type TEXT NOT NULL,
  frequency TEXT NOT NULL,
  time TEXT,
  day TEXT,
  destination TEXT,
  retention_days INTEGER DEFAULT 90,
  encrypted INTEGER DEFAULT 1,
  regulatory_preset TEXT DEFAULT 'none',
  active INTEGER DEFAULT 1
);

-- Notification config and history
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  mc_id TEXT,
  message TEXT NOT NULL,
  severity TEXT DEFAULT 'info',
  acknowledged INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

-- System health metrics (self-monitoring)
CREATE TABLE IF NOT EXISTS system_health (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT DEFAULT (datetime('now')),
  cpu_pct REAL,
  memory_mb INTEGER,
  heap_mb INTEGER,
  db_reads_per_min INTEGER,
  uptime_sec INTEGER,
  connected_mcs INTEGER
);

-- Generated reports
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  type TEXT NOT NULL,
  generated_at TEXT DEFAULT (datetime('now')),
  data TEXT NOT NULL,
  format TEXT DEFAULT 'json'
);

-- System metadata
CREATE TABLE IF NOT EXISTS system_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

function getDb() {
  const fs = require('fs');
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return new Database(DB_PATH);
}

function initDb() {
  const db = getDb();
  db.exec(SCHEMA);

  const setMeta = db.prepare('INSERT OR IGNORE INTO system_meta (key, value) VALUES (?, ?)');
  setMeta.run('fuse_counter', '31');
  setMeta.run('app_version', '0.0.31');
  setMeta.run('app_type', 'global_dashboard_server');
  setMeta.run('schema_version', '1');
  setMeta.run('installed_at', new Date().toISOString());

  // Default configs
  const setCfg = db.prepare('INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)');
  setCfg.run('notification_config', JSON.stringify({
    burnout_threshold: 65,
    turnover_risk_high: true,
    sla_below: 85,
    email: true,
    sms: false,
    recipients: ''
  }));
  setCfg.run('ha_config', JSON.stringify({ enabled: false, mode: 'active_passive' }));
  setCfg.run('posture_config', JSON.stringify({ enabled: true, require_on_connect: true }));
  setCfg.run('wifi_policy', JSON.stringify({ minimum_protocol: 'wpa2_enterprise' }));

  console.log('Global Dashboard database initialized at', DB_PATH);
  db.close();
}

if (require.main === module) {
  require('dotenv').config();
  initDb();
}

module.exports = { getDb, initDb, DB_PATH };

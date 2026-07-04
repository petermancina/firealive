// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD SERVER — Database Initialization
// Independent backend for the CISO Global Dashboard. 
// Stores: regional MC data, users, sessions, audit logs, configs, backups,
// notifications, compliance data, system health metrics.
// ═══════════════════════════════════════════════════════════════════════════════

const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const { ensureActiveReportKeypair } = require('./services/report-signing-keys');

const DB_PATH = process.env.GD_DB_PATH || path.join(__dirname, 'data', 'global-dashboard.db');

const SCHEMA = `
-- Users (CISOs, VPs, signing-key approvers, read-only analysts)
--
-- ROLE SEGREGATION (R3g PR3 Phase 5, C15):
-- 'signing_key_approver' is a new role distinct from 'ciso', segregated
-- per ISO 27001 A.6.1.2 (segregation of duties) and NIST 800-53 AC-5.
-- The user who registers an MC (must hold 'ciso' to call
-- POST /api/mc/register) should not be the same user who approves that
-- MC's signing keys (requires 'ciso' OR 'signing_key_approver'). An
-- organization with smaller ops can assign both roles to one human; the
-- audit log records each action with its acting role distinctly so
-- reviewers can see whether segregation was actually exercised.
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  role TEXT NOT NULL CHECK (role IN ('ciso', 'vp', 'readonly', 'signing_key_approver')),
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

-- GD app device keys (B5e Block K, D20/D28): the hardware-bound device key each GD
-- operator's app mints in its TPM / Secure Enclave. A direct mirror of the regional
-- server's ac_device_signing_keys: one active row per operator, sign-only, the public
-- half registered at enrollment. The GD session token is bound to the active key's
-- thumbprint and every /api/ request must prove possession of it (D28). The partial
-- unique index enforces at most one active key per operator at the DB layer
-- (registration retires the old active row before inserting a new one), matching the
-- audit_chain_signing_keys active-key pattern.
CREATE TABLE IF NOT EXISTS gd_device_signing_keys (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  registered_at TEXT NOT NULL DEFAULT (datetime('now')),
  retired_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gd_device_signing_keys_active ON gd_device_signing_keys(user_id) WHERE active = 1;

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
-- TRUST MODEL: One approved active key per MC at a time (approval_status =
-- 'approved' AND is_active = 1). Under R3g PR3 Phase 5 the trust path is
-- manual CISO approval: a new row is submitted by an MC handshake with
-- approval_status='pending_approval' and is_active=0; a user holding the
-- 'ciso' or 'signing_key_approver' role reviews the fingerprint out-of-
-- band with the MC operator and clicks approve, which atomically demotes
-- any prior approved active row (is_active=0, rotated_out_at=now, the
-- prior row's approval_status STAYS 'approved' so the verifier's
-- grace-window query can match it during the configured grace period)
-- and promotes the new row (is_active=1, approved_at=now,
-- approved_by_user_id, approved_by_role recorded for audit segregation
-- per ISO 27001 A.6.1.2 / NIST 800-53 AC-5).
--
-- FINGERPRINT FORMAT: SHA-256 hex of the Ed25519 SPKI DER encoding
-- (64 lowercase hex chars). Matches the format used by the MC's
-- backup_signing_keys.public_key_fingerprint column so operators see a
-- consistent identifier across MC and GD logs.
--
-- ON DELETE CASCADE: removing an MC row (hard-delete, not the usual
-- status='offboarded' soft-delete) drops its trust rows; orphan keys
-- shouldn't outlive the MC they were registered for.
--
-- APPROVAL COLUMNS (R3g PR3 Phase 5, C14): the manual-approval workflow
-- adds approval_status, approved_at, approved_by_user_id,
-- approved_by_role, rejected_at, and rejected_reason. The rejected_*
-- columns capture audit detail; rejected_reason is INTERNAL ONLY and is
-- never surfaced through the MC-facing status-query endpoint (the MC
-- sees only the bare status string with no reason — minimal signal so
-- the endpoint is not a recon surface for an attacker probing the
-- CISO's operational habits).
CREATE TABLE IF NOT EXISTS signing_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mc_id TEXT NOT NULL,
  public_key TEXT NOT NULL,                         -- PEM-encoded Ed25519 SPKI
  public_key_fingerprint TEXT NOT NULL,             -- SHA-256 hex of SPKI DER (64 chars)
  is_active INTEGER NOT NULL DEFAULT 0              -- R3g PR3 Phase 5: default 0 (was 1 in C1).
    CHECK (is_active IN (0, 1)),                    -- Approval flow promotes to 1 on CISO approve.
  registered_at TEXT DEFAULT (datetime('now')),
  rotated_out_at TEXT,                              -- when is_active flipped 1 -> 0
  notes TEXT,
  -- R3g PR3 Phase 5 approval columns (C14)
  approval_status TEXT NOT NULL DEFAULT 'pending_approval'
    CHECK (approval_status IN ('pending_approval', 'approved', 'rejected')),
  approved_at TEXT,                                 -- ISO 8601, set on CISO approve
  approved_by_user_id TEXT,                         -- users.id (no FK; soft reference for audit)
  approved_by_role TEXT                             -- which role approved — segregation audit
    CHECK (approved_by_role IS NULL
           OR approved_by_role IN ('ciso', 'signing_key_approver')),
  rejected_at TEXT,                                 -- ISO 8601, set on CISO reject
  rejected_reason TEXT,                             -- INTERNAL ONLY — never returned to MC
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

-- ── R3h: REGIONAL LEADERBOARD AGGREGATION ───────────────────────────────
-- One row per (mc_id, analyst_pseudonym) representing this MC's most recent
-- leaderboard push for that analyst. The GD's _leaderboardTick push from
-- the MC (server/services/gd-push.js _performLeaderboardPush) sends a
-- complete top-50 list every cadence; the ingest handler at
-- POST /api/ingest/leaderboard atomically REPLACES this MC's rows with
-- the new push entries (so an analyst who falls out of the top 50 or
-- opts out of the leaderboard disappears from this table on the next
-- push within one cadence).
--
-- PRIVACY INVARIANT I3 (OPT-IN PROPAGATION)
-- Each row's analyst_pseudonym corresponds to an MC analyst who has
-- explicitly opted in to the leaderboard via their AC toggle. The MC's
-- helperPay.getLeaderboard query enforces leaderboard_opt_in = 1 at the
-- source; opt-out analysts never appear in any push payload, so they
-- never appear in this table.
--
-- PRIVACY INVARIANT I4 (PSEUDONYM-ONLY)
-- analyst_pseudonym is a string. Real names, user_ids, and emails are
-- intentionally NOT carried in this table. A team that hasn't enabled
-- pseudonyms on its MC will see empty leaderboard pushes (the MC push
-- layer strips entries without a pseudonym) and therefore an empty
-- view in the GD's Helper Recognition tab — by design.
--
-- ATOMIC REPLACEMENT
-- The ingest handler runs DELETE FROM regional_leaderboard WHERE mc_id=?
-- followed by INSERTs for the new push entries inside a single SQLite
-- transaction. This avoids a race where the matrix render could observe
-- partial state (some old rows + some new) during the swap.
--
-- pushed_at carries the MC's timestamp at push build time; received_at
-- carries the GD's receipt timestamp. Both are useful for forensic
-- review and for detecting clock drift between MC and GD.
CREATE TABLE IF NOT EXISTS regional_leaderboard (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mc_id TEXT NOT NULL,
  analyst_pseudonym TEXT NOT NULL,                  -- pseudonym only; never real name
  points INTEGER NOT NULL,
  sessions_count INTEGER NOT NULL,
  avg_rating REAL,                                  -- nullable when analyst has no ratings yet
  pushed_at TEXT NOT NULL,                          -- MC-supplied push timestamp
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  signature_fingerprint TEXT NOT NULL,              -- signing_keys row that verified the push
  FOREIGN KEY (mc_id) REFERENCES management_consoles(id) ON DELETE CASCADE
);

-- Hot path: matrix view fetches all rows for the cross-MC roll-up.
CREATE INDEX IF NOT EXISTS idx_regional_leaderboard_mc
  ON regional_leaderboard(mc_id);

-- Drilldown: per-MC view sorts by points DESC for top-N display.
CREATE INDEX IF NOT EXISTS idx_regional_leaderboard_mc_points
  ON regional_leaderboard(mc_id, points DESC);

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

-- ── B5a: Audit log integrity (hash chain + Ed25519-signed checkpoints) ──
-- Signed checkpoints notarize the audit_log chain head; an attacker who edits a
-- row and recomputes every downstream hash still cannot forge a signed head.
-- Both tables are append-only. The audit_log hash/prev_hash columns and the
-- audit_log append-only triggers are installed by migrateGdAuditChain (after
-- the baseline backfill), not here.
CREATE TABLE IF NOT EXISTS audit_chain_checkpoint (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  head_id INTEGER NOT NULL,
  head_hash TEXT NOT NULL,
  entry_count INTEGER NOT NULL,
  signature TEXT NOT NULL,
  signing_key_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_chain_checkpoint_head ON audit_chain_checkpoint(head_id);
CREATE TRIGGER IF NOT EXISTS audit_chain_checkpoint_no_update
BEFORE UPDATE ON audit_chain_checkpoint
BEGIN
  SELECT RAISE(ABORT, 'audit_chain_checkpoint is append-only: UPDATE is not permitted');
END;
CREATE TRIGGER IF NOT EXISTS audit_chain_checkpoint_no_delete
BEFORE DELETE ON audit_chain_checkpoint
BEGIN
  SELECT RAISE(ABORT, 'audit_chain_checkpoint is append-only: DELETE is not permitted');
END;

-- Ed25519 signing key family dedicated to the audit chain (separate from the
-- report / MC-trust families). Private keys are AES-256-GCM
-- encrypted at rest via gd-encryption.
CREATE TABLE IF NOT EXISTS audit_chain_signing_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_key TEXT NOT NULL,
  private_key_encrypted TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_out_at TEXT,
  notes TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_signing_keys_active ON audit_chain_signing_keys(is_active) WHERE is_active = 1;

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
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  type TEXT NOT NULL CHECK (type IN ('scheduled', 'on-demand', 'snapshot')),
  size_bytes INTEGER,
  file_path TEXT,                                   -- v1 only; NULL for v2
  sha256_hash TEXT,                                 -- v1: hash of the .db file; v2: hash of manifest.json
  status TEXT DEFAULT 'running'
    CHECK (status IN ('running', 'verified', 'failed')),
  created_at TEXT DEFAULT (datetime('now')),
  format_version INTEGER NOT NULL DEFAULT 1
    CHECK (format_version IN (1, 2)),
  manifest_path TEXT,                               -- v2 only: manifest.json path
  archive_path TEXT,                                -- v2 only: archive.tar.gz.enc path
  manifest_sig_path TEXT,                           -- v2 only: manifest.sig path
  wrapped_key_path TEXT,                            -- v2 only: wrapped-key.bin path
  signing_key_id INTEGER REFERENCES backup_signing_keys(id) ON DELETE RESTRICT,
  backup_strategy TEXT NOT NULL DEFAULT 'full'
    CHECK (backup_strategy IN ('full', 'incremental', 'differential', 'snapshot')),
  parent_backup_id TEXT REFERENCES backups(id),         -- immediate predecessor in the chain
  parent_full_backup_id TEXT REFERENCES backups(id),    -- anchor full backup (O(1) short-circuit)
  wal_start_position TEXT,                          -- serialized WAL frame ref
  wal_end_position TEXT,                            -- serialized WAL frame ref (next backup's start)
  page_count INTEGER,                               -- integrity verification anchor
  kind TEXT NOT NULL DEFAULT 'single-db'
    CHECK (kind IN ('single-db', 'full-suite'))
);

-- Backup manifest signing keys (dedicated GD backup Ed25519 family; separate
-- from the archive-chain / audit / report / MC-trust families). Signs v3 backup
-- manifests and the backup attestation chain. Fingerprint-addressed so historical
-- manifests stay verifiable across rotation. Also holds external-registered
-- foreign public keys (verification-only) for cross-deployment restore.
CREATE TABLE IF NOT EXISTS backup_signing_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_key TEXT NOT NULL,                         -- PEM Ed25519 public key (SPKI)
  public_key_fingerprint TEXT,                      -- SHA-256 hex of SPKI DER (64 chars); set on every insert
  private_key_encrypted TEXT,                       -- GD Tier-1 wrapped {v,iv,tag,ciphertext}; NULL for external-registered
  is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
  key_origin TEXT NOT NULL DEFAULT 'local-generated' CHECK (key_origin IN ('local-generated', 'external-registered')),
  key_label TEXT,                                   -- operator description for external-registered keys
  registered_by_user_id TEXT,                       -- who registered a foreign public key (NULL for local)
  registered_at TEXT,                               -- when registered (NULL for local)
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_out_at TEXT,                              -- when is_active flipped 1->0, or external key revoked
  notes TEXT,
  -- Local-generated keys MUST have a private key; external-registered MUST NOT,
  -- MUST be inactive (verification-only), and MUST carry registration metadata.
  CHECK (
    (key_origin = 'local-generated' AND private_key_encrypted IS NOT NULL)
    OR
    (key_origin = 'external-registered' AND private_key_encrypted IS NULL AND is_active = 0
     AND registered_by_user_id IS NOT NULL AND registered_at IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS idx_backup_signing_keys_active ON backup_signing_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_backup_signing_keys_fp ON backup_signing_keys(public_key_fingerprint);

-- Backup attestation chain: Ed25519-signed, prev-hash-linked log of backup
-- operations (append-only, forward-tamper-evident). Signed by the active backup
-- signing key (fingerprint-addressed, survives rotation).
CREATE TABLE IF NOT EXISTS backup_chain (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  prev_hash TEXT,                                   -- prior entry's this_hash; NULL at genesis
  this_hash TEXT NOT NULL,                          -- SHA-256(prev_hash || canonical_payload || created_at)
  signature TEXT NOT NULL,                          -- Ed25519 over this_hash bytes (base64)
  signing_key_fingerprint TEXT NOT NULL,            -- backup_signing_keys fingerprint that signed this entry
  event_type TEXT NOT NULL CHECK (event_type IN ('CREATE', 'VERIFY', 'RESTORE_REQUEST', 'RESTORE_COMPLETE', 'DELETE_DENIED')),
  backup_id TEXT,                                   -- soft reference; chain persists even if the backup row is gone
  payload TEXT NOT NULL,                            -- canonicalized JSON
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_backup_chain_id ON backup_chain(id);
CREATE INDEX IF NOT EXISTS idx_backup_chain_backup ON backup_chain(backup_id);
CREATE INDEX IF NOT EXISTS idx_backup_chain_event ON backup_chain(event_type);
CREATE TRIGGER IF NOT EXISTS backup_chain_no_update BEFORE UPDATE ON backup_chain BEGIN SELECT RAISE(ABORT, 'backup_chain is append-only'); END;
CREATE TRIGGER IF NOT EXISTS backup_chain_no_delete BEFORE DELETE ON backup_chain BEGIN SELECT RAISE(ABORT, 'backup_chain is append-only'); END;

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
  active INTEGER DEFAULT 1,
  last_status TEXT,
  last_run TEXT,
  last_error TEXT
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

-- ── Config Lock state (B6a — GD twin of the MC config-lock chokepoint) ──────
-- Singleton (id = 1). When lock_active = 1 the GD config-lock chokepoint
-- refuses every config-write request with 423 Locked until an admin clears
-- the lock with a fresh hardware-passkey assertion (the gold-standard re-auth;
-- GD login is already FIDO2). auto_relock_at / idle_minutes drive a sliding
-- idle auto-relock so a walked-away-from admin session cannot leave the GD
-- configuration writable indefinitely. The singleton is seeded below so the
-- chokepoint always has a row to read (fail-safe if it is ever missing).
CREATE TABLE IF NOT EXISTS config_lock_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  lock_active INTEGER NOT NULL DEFAULT 0 CHECK (lock_active IN (0, 1)),
  locked_at INTEGER,
  auto_relock_at INTEGER,
  idle_minutes INTEGER NOT NULL DEFAULT 15,
  locked_by_user_id TEXT
);
INSERT OR IGNORE INTO config_lock_state (id, lock_active, idle_minutes) VALUES (1, 0, 15);

-- ── EDR / endpoint-monitoring integrations (B6a — GD self-protection) ───────
-- The GD-side EDR / integration-manager seam: in-platform host/endpoint-
-- monitoring integrations registered against the GD server ITSELF (the GD as a
-- protected asset). Replaces the prior compliance "host EDR operator-managed
-- off-platform" posture. The GD integration-health probing and the regression
-- EDR/endpoint check read this registry. Kept lean for the GD's role (no file-
-- scan stats — the GD scans no uploaded files); the vendor enum spans modern
-- endpoint-protection / EDR platforms. credentials_encrypted is nullable
-- (agent-based integrations may report to a console without GD-stored creds).
CREATE TABLE IF NOT EXISTS malware_scanner_integrations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  provider_type TEXT NOT NULL CHECK (provider_type IN (
    'clamav',
    'virustotal',
    'crowdstrike_falcon',
    'microsoft_defender',
    'sentinelone',
    'cisco_amp',
    'fortinet_fortisandbox',
    'trellix_atd',
    'sophos_intelix',
    'joe_sandbox',
    'hybrid_analysis',
    'palo_alto_wildfire',
    'blackberry_cylance',
    'trend_micro_ddan',
    'kaspersky_sandbox'
  )),
  display_name TEXT NOT NULL,
  credentials_encrypted TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 100 CHECK (priority BETWEEN 1 AND 1000),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  configured_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  configured_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_test_at TEXT,
  last_test_status TEXT CHECK (last_test_status IS NULL OR last_test_status IN ('success', 'failed')),
  last_test_error TEXT,
  last_scan_at TEXT,
  total_scans INTEGER NOT NULL DEFAULT 0,
  total_threats_detected INTEGER NOT NULL DEFAULT 0,
  total_failures INTEGER NOT NULL DEFAULT 0
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

-- ── Forensic Export (R3l C30 — GD parity of MC C20) ────────────────────────
--
-- GD-side forensic export tables. Mirrors the MC schema verbatim so a CISO
-- operating the GD console can produce SOC-grade forensic export bundles
-- from the GD's own audit_log and other slice sources. The export bundle
-- is signed with Ed25519 (and optionally Cosign), with archive SHA-256
-- captured.
--
-- The forensic_export_chain is an append-only hash chain of every operation
-- against an export (CREATE, COMPLETE, DOWNLOAD, DELETE, VERIFY). Triggers
-- enforce append-only at the engine level — UPDATE and DELETE both throw.
-- DELETE on a forensic_export row requires a separate actor from the
-- requester (enforced at the route layer in C32; the chain records who
-- acted). On GD, the natural separate-actor mapping is vp (creator) vs
-- ciso (deletor), but the schema is role-agnostic — the route layer
-- enforces the role policy.
--
-- forensic_export_chain_signing_keys stores Ed25519 keypairs used to sign
-- chain entries. private_key_encrypted is encrypted at rest (Tier-1 KMS).

CREATE TABLE IF NOT EXISTS forensic_exports (
  id TEXT PRIMARY KEY,
  requested_by_user_id TEXT NOT NULL REFERENCES users(id),
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  rationale TEXT,
  time_window_start TEXT,
  time_window_end TEXT,
  event_type_filter TEXT,
  output_formats TEXT NOT NULL,
  include_audit_log INTEGER DEFAULT 1,
  include_backup_chain INTEGER DEFAULT 1,
  include_incident_records INTEGER DEFAULT 1,
  include_authentication_logs INTEGER DEFAULT 1,
  include_user_access_logs INTEGER DEFAULT 1,
  manifest_path TEXT,
  archive_path TEXT,
  manifest_sig_path TEXT,
  manifest_signing_key_id TEXT,
  manifest_signing_key_fingerprint TEXT,
  cosign_signature_path TEXT,
  archive_sha256 TEXT,
  size_bytes INTEGER,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','in_progress','complete','failed')),
  error_message TEXT,
  completed_at TEXT,
  downloaded_at TEXT,
  downloaded_by_user_id TEXT REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_forensic_exports_requested_by ON forensic_exports(requested_by_user_id);
CREATE INDEX IF NOT EXISTS idx_forensic_exports_status ON forensic_exports(status);
CREATE INDEX IF NOT EXISTS idx_forensic_exports_requested_at ON forensic_exports(requested_at DESC);

CREATE TABLE IF NOT EXISTS forensic_export_chain (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  prev_hash TEXT,
  this_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('EXPORT_CREATED','EXPORT_COMPLETED','EXPORT_DOWNLOADED','EXPORT_DELETED','CHAIN_VERIFIED')),
  export_ref TEXT NOT NULL REFERENCES forensic_exports(id),
  actor_user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_forensic_export_chain_export_ref ON forensic_export_chain(export_ref);
CREATE INDEX IF NOT EXISTS idx_forensic_export_chain_created_at ON forensic_export_chain(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_forensic_export_chain_event_type ON forensic_export_chain(event_type);

CREATE TRIGGER IF NOT EXISTS forensic_export_chain_no_update
  BEFORE UPDATE ON forensic_export_chain
  BEGIN SELECT RAISE(ABORT, 'forensic_export_chain is append-only'); END;

CREATE TRIGGER IF NOT EXISTS forensic_export_chain_no_delete
  BEFORE DELETE ON forensic_export_chain
  BEGIN SELECT RAISE(ABORT, 'forensic_export_chain is append-only'); END;

CREATE TABLE IF NOT EXISTS forensic_export_chain_signing_keys (
  id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  private_key_encrypted TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_forensic_export_chain_signing_keys_active ON forensic_export_chain_signing_keys(active) WHERE active = 1;

-- ═══════════════════════════════════════════════════════════════════════════
-- U4: REPORT SIGNING + VERIFICATION (GD-server)
--
-- Ports the MC report-signing foundation to the Global Dashboard so the GD's
-- own compliance and executive reports export as signed, watermarked PDF/DOCX.
-- The GD's report-signing key is a DISTINCT instance identity from any MC's: a
-- GD-signed report is attributable to the GD itself, by design. report_type is
-- limited to the GD's report classes (no helper_pay, no abuse_flag -- those are
-- MC/AC-only). The schema is intentionally identical to the MC server's
-- report_signing_keys / report_verifications so the ported services
-- (report-signing-keys.js, report-signer.js, report-watermark.js,
-- report-doc-builder.js) run unchanged. report signing keys are a DISTINCT key
-- family from the GD's forensic / signing_keys families.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS report_signing_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_key TEXT NOT NULL,                         -- PEM-encoded Ed25519 public key (SPKI)
  public_key_fingerprint TEXT NOT NULL,             -- SHA-256 hex of SPKI DER bytes (64 chars)
  private_key_encrypted TEXT,                       -- Tier-1 AES-256-GCM JSON {iv, tag, ciphertext};
                                                    -- NULL for key_origin='external-registered'
                                                    -- (only the public part of a foreign key).
  is_active INTEGER NOT NULL DEFAULT 0
    CHECK (is_active IN (0, 1)),
  key_origin TEXT NOT NULL DEFAULT 'local-generated'
    CHECK (key_origin IN ('local-generated', 'external-registered')),
  registered_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  registered_at TEXT,
  key_label TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_out_at TEXT,
  notes TEXT,
  -- Local-generated keys MUST have a private key (we created it). External-
  -- registered keys MUST NOT (we hold only a foreign deployment's public part),
  -- MUST be inactive (verification-only), and MUST carry registration metadata.
  CHECK (
    (key_origin = 'local-generated'
     AND private_key_encrypted IS NOT NULL)
    OR
    (key_origin = 'external-registered'
     AND private_key_encrypted IS NULL
     AND is_active = 0
     AND registered_at IS NOT NULL
     AND registered_by_user_id IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_report_signing_keys_active
  ON report_signing_keys(is_active) WHERE is_active = 1;
CREATE INDEX IF NOT EXISTS idx_report_signing_keys_fingerprint
  ON report_signing_keys(public_key_fingerprint);
CREATE INDEX IF NOT EXISTS idx_report_signing_keys_origin
  ON report_signing_keys(key_origin);

CREATE TABLE IF NOT EXISTS report_verifications (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  report_type TEXT NOT NULL
    CHECK (report_type IN ('compliance', 'report_engine')),
  subject_ref TEXT NOT NULL,
  signed_payload_sha256 TEXT NOT NULL,              -- 64-char SHA-256 hex of the signed material
  signature TEXT NOT NULL,                          -- base64 Ed25519 signature
  key_fingerprint TEXT NOT NULL,                    -- report_signing_keys.public_key_fingerprint
  instance_label TEXT NOT NULL,                     -- snapshot of config 'instance_label' at sign time
  signed_at TEXT NOT NULL DEFAULT (datetime('now')),
  metadata_json TEXT                                -- content-blind metadata only
);

CREATE INDEX IF NOT EXISTS idx_report_verifications_hash
  ON report_verifications(signed_payload_sha256);
CREATE INDEX IF NOT EXISTS idx_report_verifications_subject
  ON report_verifications(report_type, subject_ref);

CREATE TRIGGER IF NOT EXISTS report_verifications_no_update
  BEFORE UPDATE ON report_verifications
  BEGIN SELECT RAISE(ABORT, 'report_verifications is append-only'); END;

CREATE TRIGGER IF NOT EXISTS report_verifications_no_delete
  BEFORE DELETE ON report_verifications
  BEGIN SELECT RAISE(ABORT, 'report_verifications is permanent (no delete)'); END;

-- ── B1: Cloud Vulnerability Scan (GD-server's own duplicated authorization
-- config). Authorizes cloud-posture / IaC scanners to scan the GD-server in the
-- cloud and logs every scan access in an append-only hash chain. The GD-server
-- holds its OWN authorizations (independent of the MC); this is NOT a vulnerability
-- aggregate/dashboard — it is the same EDR-style authorization + audit integration
-- as on the main server, scoped to the GD-server.
CREATE TABLE IF NOT EXISTS cloud_vuln_scanner_authorizations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  scanner_type TEXT NOT NULL CHECK (scanner_type IN (
    'scoutsuite', 'prowler', 'pacu', 'cloudbrute', 'checkov'
  )),
  display_name TEXT NOT NULL,
  allowed_cidrs TEXT NOT NULL DEFAULT '[]',
  scope_components TEXT NOT NULL DEFAULT '[]',
  token_hash TEXT NOT NULL,
  token_salt TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_scan_at TEXT,
  last_scan_source_ip TEXT,
  notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_cloud_vuln_auth_enabled
  ON cloud_vuln_scanner_authorizations(enabled, scanner_type);

CREATE TABLE IF NOT EXISTS cloud_vuln_scan_access_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  prev_hash TEXT,
  this_hash TEXT NOT NULL,
  authorization_id TEXT REFERENCES cloud_vuln_scanner_authorizations(id) ON DELETE SET NULL,
  scanner_type TEXT,
  source_ip TEXT NOT NULL,
  component TEXT NOT NULL CHECK (component IN (
    'mc', 'ac', 'arc', 'main_server', 'gd_server'
  )),
  outcome TEXT NOT NULL CHECK (outcome IN (
    'authorized', 'rejected_ip', 'rejected_token', 'rejected_disabled', 'rejected_unknown'
  )),
  request_path TEXT,
  user_agent TEXT,
  detail TEXT,
  accessed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cloud_vuln_access_accessed_at
  ON cloud_vuln_scan_access_log(accessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_cloud_vuln_access_outcome
  ON cloud_vuln_scan_access_log(outcome);
CREATE INDEX IF NOT EXISTS idx_cloud_vuln_access_auth
  ON cloud_vuln_scan_access_log(authorization_id);

CREATE TRIGGER IF NOT EXISTS cloud_vuln_scan_access_log_no_update
  BEFORE UPDATE ON cloud_vuln_scan_access_log
  BEGIN SELECT RAISE(ABORT, 'cloud_vuln_scan_access_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS cloud_vuln_scan_access_log_no_delete
  BEFORE DELETE ON cloud_vuln_scan_access_log
  BEGIN SELECT RAISE(ABORT, 'cloud_vuln_scan_access_log is append-only'); END;

-- ── B5b: IAM & SOC-grade authentication (the GD runs its own CA trust realm) ──
-- ca_authority: the GD's built-in CA (encrypted key, cert, serial; one active).
-- issued_certs: certs the GD CA issues to CISO/VP users, with a local revocation
--   list (no OCSP) checked at the mTLS handshake.
-- webauthn_credentials: FIDO2 passkeys (is_passwordless=1 = discoverable login).
-- auth_recovery: the one-time break-glass recovery credential (hash only).
-- (No offboarding_candidates here — the offboarding detector is analyst-side on
-- the MC; the GD's users are a small fixed CISO/VP set.)
CREATE TABLE IF NOT EXISTS ca_authority (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  subject TEXT NOT NULL,
  key_algo TEXT NOT NULL DEFAULT 'ec-p256',
  ca_cert_pem TEXT NOT NULL,
  ca_private_key_encrypted TEXT NOT NULL,
  serial_counter INTEGER NOT NULL DEFAULT 1,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_out_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ca_authority_one_active
  ON ca_authority(is_active) WHERE is_active = 1;

CREATE TABLE IF NOT EXISTS issued_certs (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  serial TEXT NOT NULL UNIQUE,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  external_id TEXT,
  subject TEXT NOT NULL,
  fingerprint256 TEXT NOT NULL,
  cert_pem TEXT NOT NULL,
  issued_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
  revoked_at TEXT,
  revoked_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_issued_certs_user ON issued_certs(user_id, status);
CREATE INDEX IF NOT EXISTS idx_issued_certs_fingerprint ON issued_certs(fingerprint256);
CREATE INDEX IF NOT EXISTS idx_issued_certs_revoked ON issued_certs(status) WHERE status = 'revoked';

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  aaguid TEXT,
  is_passwordless INTEGER NOT NULL DEFAULT 0 CHECK (is_passwordless IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_passwordless
  ON webauthn_credentials(is_passwordless) WHERE is_passwordless = 1;

CREATE TABLE IF NOT EXISTS auth_recovery (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  credential_hash TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  use_count INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_recovery_one_active
  ON auth_recovery(is_active) WHERE is_active = 1;

-- ── B5e: GD SERVER OWN INSTANCE IDENTITY (HARDWARE-SEALED) ───────────────
-- The GD Server hardware-bound instance identity (decision D26), mirroring
-- the regional server instance_identity. The signing key is sealed to this
-- host TPM 2.0 / Secure Enclave; anchor_public is the SPKI public key (PEM),
-- anchor_seal is a non-secret marker (the backend kind and the key label), and
-- fingerprint is the SHA-256 hex of the anchor SPKI DER. Exactly one row, the
-- GD identity. Hardware-only by construction: the CHECK admits only hardware.
CREATE TABLE IF NOT EXISTS gd_instance_identity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  instance_id TEXT NOT NULL,
  anchor_kind TEXT NOT NULL DEFAULT 'hardware'
    CHECK (anchor_kind IN ('hardware')),
  anchor_public TEXT NOT NULL,
  anchor_seal TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  ratchet_counter INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'quarantined')),
  established_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_attested_at TEXT
);

-- ── B5e: PER-MC INSTANCE-IDENTITY BINDING (ANTI-CLONING) ─────────────────
-- Binds each MC instance-anchor fingerprint (the MC
-- instance_identity.fingerprint, SHA-256 hex of the anchor SPKI DER) to its
-- mc_id. One instance identity must map to exactly one MC. The same
-- fingerprint presented under a different mc_id means two deployments share
-- one identity -- a clone. An mc_id presenting a fingerprint different from
-- the one on file means its instance identity changed (a re-provision, or a
-- clone that minted a fresh identity).
CREATE TABLE IF NOT EXISTS mc_instance_bindings (
  mc_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  first_seen_at TEXT DEFAULT (datetime('now')),
  last_seen_at TEXT DEFAULT (datetime('now')),
  status TEXT DEFAULT 'bound' CHECK (status IN ('bound', 'collision', 'rebound')),
  FOREIGN KEY (mc_id) REFERENCES management_consoles(id) ON DELETE CASCADE
);
-- Reverse lookup: every mc_id a fingerprint is bound to (collision check).
CREATE INDEX IF NOT EXISTS idx_mc_instance_bindings_fingerprint
  ON mc_instance_bindings(fingerprint);

-- Append-only log of instance-fingerprint anomalies seen at ingest (audit
-- trail for the collision/rebind detector; the live binding is the table
-- above). conflicting_mc_id is the OTHER mc_id when a fingerprint is reused.
CREATE TABLE IF NOT EXISTS mc_instance_collisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mc_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  conflicting_mc_id TEXT,
  kind TEXT NOT NULL CHECK (kind IN ('fingerprint-reused', 'fingerprint-changed')),
  detail TEXT,
  seen_at TEXT DEFAULT (datetime('now'))
);


-- B6b: STORAGE DESTINATION ROUTING + SEALED ARCHIVE SEGMENTS (GD twin of B5q)
-- The GD's own storage subsystem: a generalized destinations registry, a
-- per-data-type routing map, the guaranteed dual-write push-tracking tables,
-- and the shared sealed archive-segment chain used by the GD audit-log and
-- CEF archival writers. The GD routes its own artifacts under its own
-- anchor/KEK; it is never a write-path into the Regional Server's
-- destinations. Routes/pushes are operational state (NOT golden-baseline).

CREATE TABLE IF NOT EXISTS storage_destinations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  adapter TEXT NOT NULL
    CHECK (adapter IN ('local', 'sftp', 's3', 'azure-blob', 'gcs')),
  config TEXT NOT NULL,
  credentials_encrypted TEXT,
  enabled INTEGER NOT NULL DEFAULT 1
    CHECK (enabled IN (0, 1)),
  immutability_mode TEXT NOT NULL DEFAULT 'unknown'
    CHECK (immutability_mode IN ('none', 'append-only', 'object-lock', 'unknown')),
  retention_days INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_storage_destinations_enabled
  ON storage_destinations(enabled) WHERE enabled = 1;
CREATE INDEX IF NOT EXISTS idx_storage_destinations_adapter
  ON storage_destinations(adapter);

-- Routing map: one row per routed data type. destination_ref is a SOFT ref to
-- storage_destinations.id (NULL = unconfigured; for 'snapshot', NULL means
-- inherit the 'backup' route). options carries per-type JSON (cadence,
-- immutability_required, ...). The PRIMARY KEY on data_type encodes the
-- one-destination-per-type rule -- there is no fan-out.
CREATE TABLE IF NOT EXISTS storage_destination_routes (
  data_type TEXT PRIMARY KEY
    CHECK (data_type IN ('backup', 'audit_log', 'forensic_export', 'snapshot', 'cef_archive')),
  destination_ref TEXT,
  secondary_destination_ref TEXT,
  path_prefix TEXT,
  options TEXT,
  enabled INTEGER NOT NULL DEFAULT 0
    CHECK (enabled IN (0, 1)),
  updated_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Per-push tracking for backups (primary + secondary), with retry state.
CREATE TABLE IF NOT EXISTS backup_pushes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  backup_id TEXT NOT NULL,
  destination_id TEXT NOT NULL
    REFERENCES storage_destinations(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
  pushed_at TEXT,
  size_pushed_bytes INTEGER,
  destination_path TEXT,
  error_message TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  last_attempt_at TEXT,
  next_retry_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_backup_pushes_backup
  ON backup_pushes(backup_id);
CREATE INDEX IF NOT EXISTS idx_backup_pushes_destination
  ON backup_pushes(destination_id);
CREATE INDEX IF NOT EXISTS idx_backup_pushes_retry_scan
  ON backup_pushes(status, next_retry_at);

-- Sealed archive-segment chain (audit_log + cef_archive). Each segment
-- references the prior segment's hash, so the series is tamper-evident (a
-- changed segment breaks this_hash) and gap-evident (a removed segment breaks
-- the prev_hash link). Append-only, mirroring the GD audit / forensic chains.
CREATE TABLE IF NOT EXISTS storage_archive_segments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL
    CHECK (category IN ('audit_log', 'cef_archive')),
  sequence INTEGER NOT NULL,
  prev_hash TEXT,
  this_hash TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  range_start TEXT,
  range_end TEXT,
  bytes INTEGER,
  manifest_signature TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_storage_archive_segments_category_seq
  ON storage_archive_segments(category, sequence DESC);

CREATE TRIGGER IF NOT EXISTS storage_archive_segments_no_update
  BEFORE UPDATE ON storage_archive_segments
  BEGIN SELECT RAISE(ABORT, 'storage_archive_segments is append-only'); END;

CREATE TRIGGER IF NOT EXISTS storage_archive_segments_no_delete
  BEFORE DELETE ON storage_archive_segments
  BEGIN SELECT RAISE(ABORT, 'storage_archive_segments is append-only'); END;

-- Per-push tracking for archive segments (mirrors backup_pushes). The
-- append-only segment row carries the integrity chain only; this mutable
-- table records every push (primary + secondary) and its retry state.
-- source_artifact_path is the retained pending copy to re-push from.
CREATE TABLE IF NOT EXISTS archive_segment_pushes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  segment_id INTEGER NOT NULL
    REFERENCES storage_archive_segments(id) ON DELETE RESTRICT,
  destination_id TEXT NOT NULL
    REFERENCES storage_destinations(id) ON DELETE RESTRICT,
  role TEXT NOT NULL
    CHECK (role IN ('primary', 'secondary')),
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
  pushed_at TEXT,
  size_pushed_bytes INTEGER,
  destination_path TEXT,
  error_message TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  last_attempt_at TEXT,
  next_retry_at TEXT,
  source_artifact_path TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (segment_id, role)
);

CREATE INDEX IF NOT EXISTS idx_archive_segment_pushes_retry
  ON archive_segment_pushes(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_archive_segment_pushes_segment
  ON archive_segment_pushes(segment_id);

-- Per-push tracking for forensic exports (same shape), keyed by forensic_exports.
CREATE TABLE IF NOT EXISTS forensic_export_pushes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  export_id TEXT NOT NULL
    REFERENCES forensic_exports(id) ON DELETE RESTRICT,
  destination_id TEXT NOT NULL
    REFERENCES storage_destinations(id) ON DELETE RESTRICT,
  role TEXT NOT NULL
    CHECK (role IN ('primary', 'secondary')),
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
  pushed_at TEXT,
  size_pushed_bytes INTEGER,
  destination_path TEXT,
  error_message TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  last_attempt_at TEXT,
  next_retry_at TEXT,
  source_artifact_path TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (export_id, role)
);

CREATE INDEX IF NOT EXISTS idx_forensic_export_pushes_retry
  ON forensic_export_pushes(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_forensic_export_pushes_export
  ON forensic_export_pushes(export_id);

-- Dedicated Ed25519 family signing the GD archive-segment manifests. Private
-- material is GD-Tier-1-KEK-wrapped; one active key at a time (partial index).
CREATE TABLE IF NOT EXISTS archive_chain_signing_keys (
  id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  private_key_encrypted TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_archive_chain_signing_keys_active
  ON archive_chain_signing_keys(active) WHERE active = 1;


-- B6b: DATA RESIDENCY (GD twin of B5n2 -- jurisdiction declarations + register)
-- Per-destination jurisdiction declarations for the GD's own routed-artifact
-- destinations, plus the derived cross-border transfer register. The GD
-- residency policy itself lives in the config table under 'gd_residency'
-- (the gd-data-residency service defaults it when the key is absent, mirroring
-- the Regional). The transfer register also records the MC -> GD aggregate-
-- metric-push cross-border flows (reconciled from management_consoles): the GD
-- records these flows, it never blocks an MC push on residency grounds. Both
-- tables are operational state (NOT golden-baseline). storage_destinations
-- carries no region column, so declarations are keyed by destination_ref.
CREATE TABLE IF NOT EXISTS data_residency_destinations (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  destination_kind  TEXT NOT NULL,
  destination_ref   TEXT NOT NULL,
  declared_country  TEXT,
  declared_region   TEXT,
  provider_domicile TEXT,
  key_custody       TEXT,
  auto_detected     INTEGER NOT NULL DEFAULT 0
    CHECK (auto_detected IN (0, 1)),
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_residency_dest
  ON data_residency_destinations(destination_kind, destination_ref);

CREATE TABLE IF NOT EXISTS data_residency_transfers (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  transfer_key         TEXT NOT NULL UNIQUE,
  data_category        TEXT NOT NULL,
  source_jurisdiction  TEXT,
  dest_jurisdiction    TEXT,
  destination_ref      TEXT,
  provider_domicile    TEXT,
  foreign_law_exposure TEXT,
  key_custody          TEXT,
  mechanism            TEXT NOT NULL DEFAULT 'unset'
    CHECK (mechanism IN ('adequacy', 'scc', 'bcr', 'derogation', 'none', 'unset')),
  mechanism_notes      TEXT,
  status               TEXT NOT NULL DEFAULT 'undocumented'
    CHECK (status IN ('documented', 'undocumented', 'blocked')),
  detected_at          TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at          TEXT,
  reviewed_by          TEXT,
  next_review_at       TEXT
);

INSERT OR IGNORE INTO config (key, value)
  VALUES ('instance_label', 'FireAlive Global Dashboard (unconfigured)');

-- ==========================================================================
-- B6c: GD deployment-mode subsystem tables. The mode record itself is a signed
-- config row (key 'deployment_mode'); it needs no table. These cover SDN posture
-- and the operator-declared self-protection admission allow-list, SASE posture
-- (latched, no uncertain band), and the Virtualization Mode migration bundler.
-- Scoped to the GD's read-only role: no SDN controller-integration tables. Each
-- trust realm keeps its own posture/bundles; the GD is never a write-path into
-- the Regional Server.
-- ==========================================================================
CREATE TABLE IF NOT EXISTS gd_sdn_posture_events (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type TEXT NOT NULL CHECK (event_type IN (
    'admission_refused', 'posture_degraded', 'posture_restored'
  )),
  severity TEXT DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  detail TEXT,
  observed_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS gd_sdn_posture_state (
  id TEXT PRIMARY KEY DEFAULT 'default',
  current_state TEXT NOT NULL DEFAULT 'healthy'
    CHECK (current_state IN ('healthy', 'uncertain', 'degraded')),
  state_since TEXT DEFAULT (datetime('now')),
  last_eval_at TEXT,
  last_transition_event_id TEXT REFERENCES gd_sdn_posture_events(id)
);

CREATE TABLE IF NOT EXISTS gd_sdn_segments (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  cidr TEXT NOT NULL,
  label TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS gd_sase_posture_events (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type TEXT NOT NULL CHECK (event_type IN (
    'direct_exposure_refused', 'passthrough_violation_refused',
    'posture_degraded', 'posture_restored'
  )),
  severity TEXT DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  detail TEXT,
  observed_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS gd_sase_posture_state (
  id TEXT PRIMARY KEY DEFAULT 'default',
  current_state TEXT NOT NULL DEFAULT 'healthy'
    CHECK (current_state IN ('healthy', 'degraded')),
  state_since TEXT DEFAULT (datetime('now')),
  last_eval_at TEXT,
  last_transition_event_id TEXT REFERENCES gd_sase_posture_events(id)
);

CREATE TABLE IF NOT EXISTS gd_migration_bundles (
  id TEXT PRIMARY KEY,
  created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  format TEXT NOT NULL DEFAULT 'FA-GDMIG1',
  bundle_schema_version INTEGER NOT NULL DEFAULT 1,
  app_version TEXT,
  status TEXT NOT NULL DEFAULT 'building'
    CHECK (status IN ('building', 'complete', 'failed')),
  bundle_path TEXT,
  manifest_path TEXT,
  manifest_sig_path TEXT,
  bundle_sha256 TEXT,
  size_bytes INTEGER,
  baseline_sha256 TEXT,
  backup_ref TEXT,
  signing_key_fingerprint TEXT,
  completed_at TEXT,
  error_message TEXT
);

-- Golden-baseline config snapshots (the GD config-baseline snapshot store).
-- Origins: manual saves, plus the automatic pre-revert / pre-import safety
-- snapshots. payload is the canonical-JSON golden-baseline domain; sha256 binds
-- it. Mirrors the Regional Server's config_snapshots.
CREATE TABLE IF NOT EXISTS config_snapshots (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  origin TEXT NOT NULL DEFAULT 'manual'
    CHECK (origin IN ('manual', 'pre-revert', 'pre-import')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  app_version TEXT,
  baseline_schema_version INTEGER NOT NULL DEFAULT 1,
  payload TEXT NOT NULL,
  sha256 TEXT NOT NULL
);

-- Restore approvals: the lifecycle ledger for a restore request, targeting a
-- local backup OR an external source (XOR, enforced below). The approval mode
-- and window are captured at creation from system_meta; chain_request_entry_id
-- is a forensic anchor to the chain entry documenting the destructive restore.
CREATE TABLE IF NOT EXISTS restore_approvals (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  backup_id TEXT,
  source_id TEXT,
  external_backup_id TEXT,
  requested_by_user_id TEXT NOT NULL,
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  request_reason TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
  approval_mode_at_creation TEXT NOT NULL
    CHECK (approval_mode_at_creation IN ('strict', 'delayed-self-approval', 'disabled')),
  approval_window_hours INTEGER NOT NULL,
  approved_by_user_id TEXT,
  approved_at TEXT,
  approval_method TEXT
    CHECK (approval_method IS NULL OR approval_method IN
      ('second-person-totp', 'delayed-self-totp', 'disabled-mode-bypass')),
  denied_by_user_id TEXT,
  denied_at TEXT,
  denial_reason TEXT,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  chain_request_entry_id INTEGER,
  client_ip_at_request TEXT,
  client_ip_at_approval TEXT,
  CHECK (
    (backup_id IS NOT NULL AND source_id IS NULL AND external_backup_id IS NULL)
    OR
    (backup_id IS NULL AND source_id IS NOT NULL AND external_backup_id IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS idx_restore_approvals_backup
  ON restore_approvals(backup_id);
CREATE INDEX IF NOT EXISTS idx_restore_approvals_source
  ON restore_approvals(source_id, external_backup_id);
CREATE INDEX IF NOT EXISTS idx_restore_approvals_status
  ON restore_approvals(status);
CREATE INDEX IF NOT EXISTS idx_restore_approvals_expiry_scan
  ON restore_approvals(expires_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_restore_approvals_requested_by
  ON restore_approvals(requested_by_user_id);

-- External restore sources: registered off-box locations (network share, NAS,
-- S3, Azure blob, SFTP) a backup can be pulled from for a restore. Credentials
-- and the optional backup decryption key are Tier-1 encrypted at rest.
CREATE TABLE IF NOT EXISTS external_restore_sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  source_type TEXT NOT NULL
    CHECK (source_type IN ('network_share', 'nas', 's3', 'azure_blob', 'sftp')),
  path TEXT NOT NULL,
  credentials_encrypted TEXT NOT NULL,
  backup_decryption_key_encrypted TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL
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

  // B6b: add backup-run status columns to backup_schedules.
  // The canonical CREATE TABLE above includes last_status / last_run /
  // last_error for fresh installs. Deploys that ran an earlier GD build have
  // backup_schedules without them; add via ALTER TABLE ADD COLUMN. Guarded by
  // PRAGMA table_info so the block is skipped (and never re-runs) once present.
  try {
    const bsCols = db.prepare("PRAGMA table_info(backup_schedules)").all();
    if (!bsCols.some(c => c.name === 'last_status')) {
      db.exec(`ALTER TABLE backup_schedules ADD COLUMN last_status TEXT;`);
      db.exec(`ALTER TABLE backup_schedules ADD COLUMN last_run TEXT;`);
      db.exec(`ALTER TABLE backup_schedules ADD COLUMN last_error TEXT;`);
      console.log('Migrated backup_schedules: added last_status / last_run / last_error columns');
    }
  } catch (e) {
    console.error('backup_schedules status-column migration failed:', e.message);
  }

  // v2 encrypted-backup + WAL/chain columns on `backups` (MC-grade parity).
  // Existing GD installs created `backups` without them; add via guarded ALTER
  // TABLE ADD COLUMN. backup_signing_keys already exists (created by the SCHEMA
  // exec above), so the signing_key_id FK resolves. Idempotent: guarded by
  // PRAGMA table_info so the block is skipped once the columns are present.
  try {
    const bCols = db.prepare("PRAGMA table_info(backups)").all();
    if (!bCols.some(c => c.name === 'format_version')) {
      db.exec(`ALTER TABLE backups ADD COLUMN format_version INTEGER NOT NULL DEFAULT 1 CHECK (format_version IN (1, 2));`);
      db.exec(`ALTER TABLE backups ADD COLUMN manifest_path TEXT;`);
      db.exec(`ALTER TABLE backups ADD COLUMN archive_path TEXT;`);
      db.exec(`ALTER TABLE backups ADD COLUMN manifest_sig_path TEXT;`);
      db.exec(`ALTER TABLE backups ADD COLUMN wrapped_key_path TEXT;`);
      db.exec(`ALTER TABLE backups ADD COLUMN signing_key_id INTEGER REFERENCES backup_signing_keys(id);`);
      db.exec(`ALTER TABLE backups ADD COLUMN parent_backup_id TEXT REFERENCES backups(id);`);
      db.exec(`ALTER TABLE backups ADD COLUMN parent_full_backup_id TEXT REFERENCES backups(id);`);
      db.exec(`ALTER TABLE backups ADD COLUMN wal_start_position TEXT;`);
      db.exec(`ALTER TABLE backups ADD COLUMN wal_end_position TEXT;`);
      db.exec(`ALTER TABLE backups ADD COLUMN page_count INTEGER;`);
      console.log('Migrated backups: added v2 encrypted-backup + WAL/chain columns');
    }
  } catch (gdBackupV2ColsErr) {
    console.error('GD v2 backup columns migration failed:', gdBackupV2ColsErr.message);
  }

  // EDR scan engine: bring malware_scanner_integrations to the anti-malware
  // engine's schema. The GD's pre-engine table (11 EDR-endpoint providers, an
  // endpoint column, no priority/telemetry) had no scan engine behind it and
  // holds no rows, so it is safe to recreate. SQLite cannot ALTER a CHECK
  // constraint, so the provider-set and constraint change needs a recreate, not
  // an ALTER. Guarded by PRAGMA table_info so it runs once and never re-runs.
  try {
    const msCols = db.prepare("PRAGMA table_info(malware_scanner_integrations)").all().map((c) => c.name);
    const preEngine = msCols.length > 0 && (msCols.includes('endpoint') || !msCols.includes('priority'));
    if (preEngine) {
      db.exec('DROP TABLE IF EXISTS malware_scanner_integrations');
      db.exec(`CREATE TABLE IF NOT EXISTS malware_scanner_integrations (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        provider_type TEXT NOT NULL CHECK (provider_type IN (
          'clamav', 'virustotal', 'crowdstrike_falcon', 'microsoft_defender',
          'sentinelone', 'cisco_amp', 'fortinet_fortisandbox', 'trellix_atd',
          'sophos_intelix', 'joe_sandbox', 'hybrid_analysis', 'palo_alto_wildfire',
          'blackberry_cylance', 'trend_micro_ddan', 'kaspersky_sandbox'
        )),
        display_name TEXT NOT NULL,
        credentials_encrypted TEXT NOT NULL,
        priority INTEGER NOT NULL DEFAULT 100 CHECK (priority BETWEEN 1 AND 1000),
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        configured_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        configured_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_test_at TEXT,
        last_test_status TEXT CHECK (last_test_status IS NULL OR last_test_status IN ('success', 'failed')),
        last_test_error TEXT,
        last_scan_at TEXT,
        total_scans INTEGER NOT NULL DEFAULT 0,
        total_threats_detected INTEGER NOT NULL DEFAULT 0,
        total_failures INTEGER NOT NULL DEFAULT 0
      )`);
    }
  } catch (msScannerErr) {
    console.error('malware_scanner_integrations engine-schema migration failed:', msScannerErr.message);
  }

  // Extend report_signing_keys for cross-deployment golden-baseline verification:
  // relax private_key_encrypted to NULL for external-registered keys and add
  // key_origin / registered_by_user_id / registered_at / key_label, with a
  // table-level CHECK enforcing the local-vs-external XOR. SQLite cannot ALTER a
  // NOT NULL or add a CHECK, so the table is recreated and existing rows (all
  // local-generated) are copied. Guarded by the key_origin column so it runs
  // once and is idempotent. Mirrors the Regional Server.
  try {
    const rskCols = db.prepare("PRAGMA table_info(report_signing_keys)").all().map((c) => c.name);
    if (rskCols.length && !rskCols.includes('key_origin')) {
      const existingRskRows = db.prepare("SELECT * FROM report_signing_keys").all();
      db.pragma('foreign_keys = OFF');
      try {
        const migrateRsk = db.transaction(() => {
          db.exec(`
            CREATE TABLE report_signing_keys_new (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              public_key TEXT NOT NULL,
              public_key_fingerprint TEXT NOT NULL,
              private_key_encrypted TEXT,
              is_active INTEGER NOT NULL DEFAULT 0
                CHECK (is_active IN (0, 1)),
              key_origin TEXT NOT NULL DEFAULT 'local-generated'
                CHECK (key_origin IN ('local-generated', 'external-registered')),
              registered_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
              registered_at TEXT,
              key_label TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              rotated_out_at TEXT,
              notes TEXT,
              CHECK (
                (key_origin = 'local-generated'
                 AND private_key_encrypted IS NOT NULL)
                OR
                (key_origin = 'external-registered'
                 AND private_key_encrypted IS NULL
                 AND is_active = 0
                 AND registered_at IS NOT NULL
                 AND registered_by_user_id IS NOT NULL)
              )
            );
          `);
          const insertRsk = db.prepare(`
            INSERT INTO report_signing_keys_new
              (id, public_key, public_key_fingerprint, private_key_encrypted,
               is_active, key_origin, registered_by_user_id, registered_at,
               key_label, created_at, rotated_out_at, notes)
            VALUES (?, ?, ?, ?, ?, 'local-generated', NULL, NULL, NULL, ?, ?, ?)
          `);
          for (const row of existingRskRows) {
            insertRsk.run(
              row.id,
              row.public_key,
              row.public_key_fingerprint,
              row.private_key_encrypted,
              row.is_active,
              row.created_at,
              row.rotated_out_at,
              row.notes
            );
          }
          db.exec(`
            DROP TABLE report_signing_keys;
            ALTER TABLE report_signing_keys_new RENAME TO report_signing_keys;
            CREATE INDEX IF NOT EXISTS idx_report_signing_keys_active
              ON report_signing_keys(is_active) WHERE is_active = 1;
            CREATE INDEX IF NOT EXISTS idx_report_signing_keys_fingerprint
              ON report_signing_keys(public_key_fingerprint);
            CREATE INDEX IF NOT EXISTS idx_report_signing_keys_origin
              ON report_signing_keys(key_origin);
          `);
        });
        migrateRsk();
      } finally {
        db.pragma('foreign_keys = ON');
      }
    }
  } catch (rskErr) {
    console.error('report_signing_keys external-key migration failed:', rskErr.message);
  }

  // Bring the backups table to exact Regional Server schema parity: type becomes
  // the trigger (daily-auto/on-demand/snapshot), the strategy moves to a new
  // backup_strategy column, hash -> sha256_hash, destination -> file_path, and
  // kind + the Regional status CHECK are added, so the restore chain and all
  // backup code are byte-for-byte twins of the Regional Server. SQLite cannot
  // rename a column or alter a CHECK, so the table is rebuilt and existing rows
  // are mapped over (their old type -> backup_strategy; trigger defaults to
  // on-demand, or snapshot; status 'completed' -> 'verified'). Guarded by the
  // backup_strategy column so it runs once and is idempotent.
  try {
    const bkCols = db.prepare("PRAGMA table_info(backups)").all().map((c) => c.name);
    if (bkCols.length && !bkCols.includes('backup_strategy')) {
      const existingBackups = db.prepare("SELECT * FROM backups").all();
      db.pragma('foreign_keys = OFF');
      try {
        const migrateBackups = db.transaction(() => {
          db.exec(`
            CREATE TABLE backups_new (
              id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
              type TEXT NOT NULL CHECK (type IN ('daily-auto', 'on-demand', 'snapshot')),
              size_bytes INTEGER,
              file_path TEXT,
              sha256_hash TEXT,
              status TEXT DEFAULT 'running'
                CHECK (status IN ('running', 'verified', 'failed')),
              created_at TEXT DEFAULT (datetime('now')),
              format_version INTEGER NOT NULL DEFAULT 1
                CHECK (format_version IN (1, 2)),
              manifest_path TEXT,
              archive_path TEXT,
              manifest_sig_path TEXT,
              wrapped_key_path TEXT,
              signing_key_id INTEGER REFERENCES backup_signing_keys(id) ON DELETE RESTRICT,
              backup_strategy TEXT NOT NULL DEFAULT 'full'
                CHECK (backup_strategy IN ('full', 'incremental', 'differential', 'snapshot')),
              parent_backup_id TEXT REFERENCES backups(id),
              parent_full_backup_id TEXT REFERENCES backups(id),
              wal_start_position TEXT,
              wal_end_position TEXT,
              page_count INTEGER,
              kind TEXT NOT NULL DEFAULT 'single-db'
                CHECK (kind IN ('single-db', 'full-suite'))
            );
          `);
          const insertBk = db.prepare(`
            INSERT INTO backups_new
              (id, type, size_bytes, file_path, sha256_hash, status, created_at,
               format_version, manifest_path, archive_path, manifest_sig_path,
               wrapped_key_path, signing_key_id, backup_strategy, parent_backup_id,
               parent_full_backup_id, wal_start_position, wal_end_position, page_count,
               kind)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
          for (const r of existingBackups) {
            const oldType = r.type || 'full';
            const triggerType = (oldType === 'snapshot') ? 'snapshot' : 'on-demand';
            const strategy = ['full', 'incremental', 'differential', 'snapshot'].includes(oldType) ? oldType : 'full';
            const status = (r.status === 'completed' || r.status == null) ? 'verified'
              : (['running', 'verified', 'failed'].includes(r.status) ? r.status : 'verified');
            insertBk.run(
              r.id,
              triggerType,
              r.size_bytes != null ? r.size_bytes : null,
              r.destination != null ? r.destination : (r.file_path != null ? r.file_path : null),
              r.hash != null ? r.hash : (r.sha256_hash != null ? r.sha256_hash : null),
              status,
              r.created_at,
              r.format_version != null ? r.format_version : 1,
              r.manifest_path != null ? r.manifest_path : null,
              r.archive_path != null ? r.archive_path : null,
              r.manifest_sig_path != null ? r.manifest_sig_path : null,
              r.wrapped_key_path != null ? r.wrapped_key_path : null,
              r.signing_key_id != null ? r.signing_key_id : null,
              strategy,
              r.parent_backup_id != null ? r.parent_backup_id : null,
              r.parent_full_backup_id != null ? r.parent_full_backup_id : null,
              r.wal_start_position != null ? r.wal_start_position : null,
              r.wal_end_position != null ? r.wal_end_position : null,
              r.page_count != null ? r.page_count : null,
              'single-db'
            );
          }
          db.exec(`
            DROP TABLE backups;
            ALTER TABLE backups_new RENAME TO backups;
          `);
        });
        migrateBackups();
      } finally {
        db.pragma('foreign_keys = ON');
      }
    }
  } catch (bkErr) {
    console.error('backups schema-parity migration failed:', bkErr.message);
  }


  // ── B6c PR-post3 — rename backups.type value 'daily-auto' -> 'scheduled' ──
  //
  // Same rationale and derive-from-live-DDL approach as the Regional Server:
  // the auto-backup trigger renames to 'scheduled' so the label is accurate
  // once schedules can fire sub-daily. SQLite cannot ALTER a CHECK, so backups
  // is rebuilt from the live table's stored SQL (every column, default, FK, and
  // CHECK preserved byte-identically; only the type CHECK's enum values change),
  // copying rows with type='daily-auto' mapped to 'scheduled'. Guarded on the
  // live CHECK still naming 'daily-auto', so it no-ops on fresh installs and
  // already-migrated databases. Idempotent and data-preserving.
  try {
    const backupsTableRow = db
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'backups'")
      .get();
    if (backupsTableRow && backupsTableRow.sql && backupsTableRow.sql.indexOf('daily-auto') !== -1) {
      console.log('backups migration (B6c post-3): renaming type value daily-auto -> scheduled');
      let newBackupsDdl = backupsTableRow.sql.replace(/daily-auto/g, 'scheduled');
      newBackupsDdl = newBackupsDdl.replace(
        /CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?("backups"|backups)/i,
        'CREATE TABLE backups_new'
      );
      db.pragma('foreign_keys = OFF');
      try {
        const renameBackups = db.transaction(() => {
          db.exec(newBackupsDdl);
          const backupColNames = db
            .prepare("PRAGMA table_info(backups)")
            .all()
            .map((c) => '"' + c.name + '"');
          const colList = backupColNames.join(', ');
          const selectList = backupColNames
            .map((c) => (c === '"type"'
              ? "CASE WHEN type = 'daily-auto' THEN 'scheduled' ELSE type END"
              : c))
            .join(', ');
          db.exec('INSERT INTO backups_new (' + colList + ') SELECT ' + selectList + ' FROM backups');
          db.exec('DROP TABLE backups');
          db.exec('ALTER TABLE backups_new RENAME TO backups');
        });
        renameBackups();
        console.log('backups migration (B6c post-3): renamed daily-auto rows to scheduled');
      } finally {
        db.pragma('foreign_keys = ON');
      }
    }
  } catch (backupsRenameMigrationErr) {
    console.error('backups migration (B6c post-3) failed (non-fatal):', backupsRenameMigrationErr.message);
  }
  // ── R3g PR3 Phase 5 migration: add approval workflow columns to signing_keys ──
  //
  // The canonical CREATE TABLE above includes approval_status, approved_at,
  // approved_by_user_id, approved_by_role, rejected_at, and rejected_reason
  // for fresh installs. For deploys that ran any of C1-C13 before this
  // commit, signing_keys has the original schema (no approval columns).
  // This block detects that case and applies ALTER TABLE ADD COLUMN for
  // each new column, then backfills any existing rows.
  //
  // Backfill rationale: any existing row from a C1-C13 deploy was either
  //   (a) created by C12 (which auto-activated rows with is_active=1), or
  //   (b) was never created at all (C13 hot-fix blocks all writes via this
  //       endpoint and no other code path writes to signing_keys before
  //       C18).
  // Case (a) rows were considered trusted under the old design, so we
  // mark them approval_status='approved' on migration so the verifier
  // continues to accept their signatures uninterrupted. New rows from
  // C18+ explicitly set approval_status='pending_approval' (and the
  // canonical CREATE TABLE's DEFAULT is also 'pending_approval' for
  // belt-and-suspenders safety against future code paths that forget to
  // specify it).
  //
  // Idempotency: guarded by PRAGMA table_info — if approval_status
  // column already exists, the entire block is skipped, so the backfill
  // never runs twice (which would clobber real pending_approval rows
  // created by C18+).
  try {
    const skCols = db.prepare("PRAGMA table_info(signing_keys)").all();
    const hasApprovalStatus = skCols.some(c => c.name === 'approval_status');
    if (!hasApprovalStatus) {
      db.exec(`
        ALTER TABLE signing_keys
          ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'pending_approval'
            CHECK (approval_status IN ('pending_approval', 'approved', 'rejected'));
      `);
      db.exec(`ALTER TABLE signing_keys ADD COLUMN approved_at TEXT;`);
      db.exec(`ALTER TABLE signing_keys ADD COLUMN approved_by_user_id TEXT;`);
      db.exec(`
        ALTER TABLE signing_keys
          ADD COLUMN approved_by_role TEXT
            CHECK (approved_by_role IS NULL
                   OR approved_by_role IN ('ciso', 'signing_key_approver'));
      `);
      db.exec(`ALTER TABLE signing_keys ADD COLUMN rejected_at TEXT;`);
      db.exec(`ALTER TABLE signing_keys ADD COLUMN rejected_reason TEXT;`);

      // Backfill: every existing row (pre-Phase-5) gets approval_status =
      // 'approved' since it was considered trusted under the C12 design.
      // The ALTER above set every existing row to 'pending_approval' via
      // the column DEFAULT; this UPDATE corrects them.
      const backfill = db.prepare(`
        UPDATE signing_keys
        SET approval_status = 'approved'
        WHERE approval_status = 'pending_approval'
      `).run();

      console.log(
        `Migrated signing_keys: added approval workflow columns; ${backfill.changes} pre-existing row(s) backfilled to approved`
      );
    }
  } catch (e) {
    // Don't mask other initDb work if the migration fails; log and continue.
    // A failed migration leaves the table in its prior state — the next
    // initDb() call will retry.
    console.error('signing_keys approval migration failed:', e.message);
  }

  // ── R3g PR3 Phase 5 migration: add 'signing_key_approver' role to users CHECK ──
  //
  // SQLite cannot ALTER CHECK constraints directly; they're stored in the
  // table's CREATE TABLE SQL, captured in sqlite_master at table-creation
  // time and immutable thereafter. To extend the role check from
  //   CHECK (role IN ('ciso', 'vp', 'readonly'))
  // to
  //   CHECK (role IN ('ciso', 'vp', 'readonly', 'signing_key_approver'))
  // we use the SQLite "12-step table rebuild" pattern documented at
  // https://www.sqlite.org/lang_altertable.html#otheralter.
  //
  // FK PRESERVATION: sessions.user_id and mc_report_requests.requested_by_
  // user_id both reference users(id). FK references are stored by table
  // NAME (not by row pointer), so renaming users_new -> users preserves
  // the FK targets correctly. PRAGMA foreign_keys is disabled during the
  // rebuild to prevent FK enforcement from rejecting the intermediate
  // DROP TABLE; PRAGMA foreign_key_check after the rebuild confirms no
  // dangling references resulted.
  //
  // IDEMPOTENCY: the guard reads the actual stored CREATE TABLE SQL from
  // sqlite_master and checks whether 'signing_key_approver' appears in
  // the CHECK clause. If the canonical CREATE TABLE (fresh-install path)
  // already produced a table with the new constraint, sqlite_master.sql
  // will contain the new role string, and the rebuild block is skipped.
  // For migrated deploys from C1-C14, the stored SQL still has the old
  // three-role constraint, and the rebuild runs once.
  try {
    const usersSchema = db.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'"
    ).get();
    const needsRoleMigration =
      usersSchema && !usersSchema.sql.includes("'signing_key_approver'");

    if (needsRoleMigration) {
      // Disable FK enforcement during the rebuild. sessions(user_id) and
      // mc_report_requests(requested_by_user_id) both reference users(id)
      // — we DON'T want SQLite rejecting the DROP TABLE users mid-rebuild.
      db.exec('PRAGMA foreign_keys = OFF');

      db.exec('BEGIN TRANSACTION');
      try {
        // Create users_new with the extended CHECK constraint. Schema
        // mirrors the canonical CREATE TABLE above EXACTLY (column order,
        // defaults, secondary constraints) so the rebuild preserves all
        // pre-existing column semantics.
        db.exec(`
          CREATE TABLE users_new (
            id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            role TEXT NOT NULL CHECK (role IN ('ciso', 'vp', 'readonly', 'signing_key_approver')),
            name TEXT NOT NULL,
            mfa_secret TEXT,
            mfa_enabled INTEGER DEFAULT 0,
            auth_method TEXT DEFAULT 'local' CHECK (auth_method IN ('local', 'saml', 'oidc', 'ldap')),
            created_at TEXT DEFAULT (datetime('now')),
            last_login TEXT
          );
        `);

        // Transfer all rows. Existing roles are all in the old check set
        // ('ciso', 'vp', 'readonly') which is a strict subset of the new
        // check set, so every row passes the new CHECK on insert.
        const transferred = db.prepare(`
          INSERT INTO users_new
            (id, username, password_hash, role, name, mfa_secret,
             mfa_enabled, auth_method, created_at, last_login)
          SELECT id, username, password_hash, role, name, mfa_secret,
                 mfa_enabled, auth_method, created_at, last_login
          FROM users
        `).run();

        db.exec('DROP TABLE users');
        db.exec('ALTER TABLE users_new RENAME TO users');

        db.exec('COMMIT');

        // FK validity check after the rebuild. Any FK that didn't resolve
        // back to the renamed users table would surface here.
        const fkIssues = db.prepare('PRAGMA foreign_key_check').all();
        if (fkIssues.length > 0) {
          console.error('users role migration left FK issues:', fkIssues);
        } else {
          console.log(
            `Migrated users table: added 'signing_key_approver' to role CHECK; ${transferred.changes} user row(s) preserved`
          );
        }
      } catch (rebuildErr) {
        // ROLLBACK if any step inside the transaction failed.
        db.exec('ROLLBACK');
        throw rebuildErr;
      } finally {
        // Re-enable FK enforcement regardless of success/failure.
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  } catch (e) {
    console.error('users role migration failed:', e.message);
  }

  const setMeta = db.prepare('INSERT OR IGNORE INTO system_meta (key, value) VALUES (?, ?)');
  setMeta.run('fuse_counter', '31');
  setMeta.run('app_version', '0.0.31');
  setMeta.run('app_type', 'global_dashboard_server');
  setMeta.run('schema_version', '1');
  setMeta.run('installed_at', new Date().toISOString());
  // Restore approval policy (single-CISO model): default to delayed-self-approval
  // with a 24-hour window. Managed by gd-restore-approval-policy.
  setMeta.run('restore_approval_mode', 'delayed-self-approval');
  setMeta.run('restore_approval_window_hours', '24');

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
  setCfg.run('signing_key_grace_period_minutes', '60');

  // ── B6a — GD self-protection config defaults ───────────────────────────
  // alert_routing_matrix: the SOC-grade per-severity channel matrix the GD
  // alert-router fans out by (audit is always-on and NOT part of the matrix).
  // Locked defaults: warning -> +siem; high -> +soar +siem +notification;
  // critical -> all channels. Admin-overridable from the Monitoring tab.
  setCfg.run('alert_routing_matrix', JSON.stringify({
    info:     { soar: false, siem: false, email: false, notification: false, webhook: false },
    warning:  { soar: false, siem: true,  email: false, notification: false, webhook: false },
    high:     { soar: true,  siem: true,  email: false, notification: true,  webhook: false },
    critical: { soar: true,  siem: true,  email: true,  notification: true,  webhook: true  }
  }));
  setCfg.run('alert_webhook_url', '');
  // Integration-health probing: opt-in (default OFF) at the master and per-
  // integration level, scoped to the GD's real dependencies (kms / storage /
  // mc_trust). Mirrors the MC's default-off posture.
  setCfg.run('integration_health_probes_enabled', 'false');
  setCfg.run('integration_health_config', JSON.stringify({
    kms:      { enabled: false },
    storage:  { enabled: false },
    mc_trust: { enabled: false }
  }));
  // Runtime-monitor sustained-load threshold overrides (empty object = use the
  // SOC-grade defaults baked into services/gd-runtime-monitor.js).
  setCfg.run('runtime_monitor_thresholds', JSON.stringify({}));

  // ── R3k C27 — Sub-phase 6 GD-side schema mirrors ──────────────────────
  //
  // Adds the GD-server's own state tables for Cloud & IaC generator
  // (Sub-phase 7 / C28) and CI/CD generator (Sub-phase 7 / C29).
  // Schemas mirror the MC-side tables created in R3k C1 + C2 + C12 so
  // the route handlers can share semantics across MC and GD, while
  // remaining independent at the database layer (each side has its
  // own deployment-bundle history; GD doesn't aggregate MC bundles).
  //
  // FK note: GD's users.id is INTEGER (vs MC's id which is also
  // INTEGER); generated_by / created_by columns FK to GD's users(id)
  // without ON DELETE CASCADE so bundle history is preserved across
  // user deletion (CISO accounts may rotate while bundle audit
  // history must survive).
  //
  // Idempotent CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT
  // EXISTS. Single try/catch around all four migrations is sufficient
  // here (vs MC's per-table isolation) because all four are net-new
  // tables with no prior data dependencies — a failure mode would
  // indicate a fundamental DB issue affecting everything, not a
  // surgical-migration concern.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS cloud_iac_signing_keys (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        public_key TEXT NOT NULL,
        private_key_wrapped TEXT NOT NULL,
        algorithm TEXT NOT NULL DEFAULT 'cosign-ecdsa-p256',
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (status IN ('active', 'rotated', 'revoked')),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        rotated_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_gd_cloud_iac_signing_keys_status
        ON cloud_iac_signing_keys (status);
    `);

    db.exec(`
      CREATE TABLE IF NOT EXISTS cloud_packages (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        provider TEXT NOT NULL
          CHECK (provider IN ('aws', 'azure', 'gcp', 'hetzner', 'ovhcloud', 'exoscale')),
        iac_tool TEXT NOT NULL
          CHECK (iac_tool IN (
            'terraform', 'pulumi', 'cloudformation', 'docker-compose',
            'docker-manifest', 'kubernetes', 'helm', 'bicep', 'gcp-dm'
          )),
        generated_at TEXT NOT NULL DEFAULT (datetime('now')),
        generated_by INTEGER NOT NULL REFERENCES users(id),
        bundle_dir_path TEXT NOT NULL,
        bundle_archive_path TEXT NOT NULL,
        manifest_sha256 TEXT NOT NULL,
        sbom_path TEXT NOT NULL,
        sbom_sha256 TEXT NOT NULL,
        signature_path TEXT NOT NULL,
        signature_sha256 TEXT NOT NULL,
        signing_key_id TEXT NOT NULL REFERENCES cloud_iac_signing_keys(id),
        install_snapshot_json TEXT NOT NULL,
        size_bytes INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_gd_cloud_packages_provider_tool
        ON cloud_packages (provider, iac_tool);

      CREATE INDEX IF NOT EXISTS idx_gd_cloud_packages_generated_at
        ON cloud_packages (generated_at);
    `);

    db.exec(`
      CREATE TABLE IF NOT EXISTS cicd_configs (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        platform TEXT NOT NULL
          CHECK (platform IN ('github-actions', 'gitlab-ci', 'jenkins', 'circleci')),
        purpose TEXT NOT NULL
          CHECK (purpose IN ('custom-build', 'upstream-contribution')),
        generated_at TEXT NOT NULL DEFAULT (datetime('now')),
        generated_yaml_path TEXT NOT NULL,
        current_install_snapshot_json TEXT NOT NULL,
        created_by INTEGER NOT NULL REFERENCES users(id)
      );

      CREATE INDEX IF NOT EXISTS idx_gd_cicd_configs_platform
        ON cicd_configs (platform);

      CREATE INDEX IF NOT EXISTS idx_gd_cicd_configs_generated_at
        ON cicd_configs (generated_at);
    `);

    db.exec(`
      CREATE TABLE IF NOT EXISTS cicd_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        external_run_id TEXT NOT NULL,
        platform TEXT NOT NULL
          CHECK (platform IN ('github-actions', 'gitlab-ci', 'jenkins', 'circleci')),
        config_id TEXT REFERENCES cicd_configs(id),
        status TEXT NOT NULL
          CHECK (status IN ('queued', 'running', 'passed', 'failed', 'cancelled')),
        started_at TEXT NOT NULL,
        finished_at TEXT,
        commit_sha TEXT,
        branch TEXT,
        step_results_json TEXT,
        ci_metadata_json TEXT,
        received_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (platform, external_run_id)
      );

      CREATE INDEX IF NOT EXISTS idx_gd_cicd_runs_received_at
        ON cicd_runs (received_at);
    `);

    const pkgCount = db.prepare('SELECT COUNT(*) AS n FROM cloud_packages').get().n;
    const cfgCount = db.prepare('SELECT COUNT(*) AS n FROM cicd_configs').get().n;
    console.log(`R3k C27 GD migration: cloud_packages=${pkgCount}, cicd_configs=${cfgCount} (Sub-phase 6 ready)`);
  } catch (r3kGdMigrationErr) {
    console.error('R3k C27 GD migration FAILED:', r3kGdMigrationErr.message);
    console.error(
      'The GD-server will start, but the Sub-phase-6 routes (/api/cloud/* added in C28, /api/cicd/* added in C29) will return 500 until this migration completes successfully. The existing /api/regression-test (C26) and all v1.0.36 GD surfaces are independent of these tables and continue to function.'
    );
  }

  // U4: ensure this GD instance has an active Ed25519 report-signing keypair,
  // so its compliance and executive reports can be signed at generation time.
  // Idempotent -- only generates when no active key exists. Provisioned here as
  // part of database setup (`npm run init-db`); the report exporters also call
  // ensureActiveReportKeypair defensively at request time, since the server
  // process (index.js) does not run initDb on startup.
  try {
    const reportKey = ensureActiveReportKeypair(db);
    if (reportKey.isNewlyCreated) {
      console.log('U4: generated GD report-signing keypair (' + reportKey.publicKeyFingerprint.slice(0, 16) + '\u2026)');
    }
  } catch (reportKeyErr) {
    console.error('U4: report-signing keypair init FAILED:', reportKeyErr.message);
    console.error('Signed report exports (PDF/DOCX) will fail until an active report-signing key exists; re-run `npm run init-db` after setting the Tier-1 encryption key.');
  }

  // ── B5a: establish the audit-log hash chain + signed-checkpoint baseline ──
  // Adds the hash/prev_hash columns, chains and notarizes existing rows as the
  // tamper-evident baseline (without altering their content), then installs the
  // audit_log append-only triggers. Run-once and guarded (idempotent on
  // re-init). Like the other migrations above, this applies during
  // `npm run init-db`.
  try {
    const { migrateGdAuditChain } = require('./services/gd-audit-chain');
    const acRes = migrateGdAuditChain(db);
    if (acRes.migrated) {
      console.log(`B5a: audit log hash chain established (${acRes.backfilled} row(s) chained as baseline)`);
    }
  } catch (acErr) {
    console.error('B5a audit chain migration failed:', acErr.message);
    console.error('Audit log integrity verification will be unavailable until this succeeds; re-run `npm run init-db` after setting the Tier-1 encryption key.');
  }

  // B5g: forensic_exports at-rest encryption columns.
  // Records, per artifact, which KEK scheme (gd-tier1 on the GD) and reference
  // protect the on-disk archive. at_rest_scheme is the canonical "encrypted at
  // rest" signal: NULL means a legacy plaintext archive (pre-B5g) that the boot
  // migration will re-seal. Guarded by PRAGMA table_info so re-running initDb is
  // a no-op; its own try/catch keeps a failure from masking other migrations.
  try {
    const addAtRestCols = (table) => {
      const cols = db.prepare(`PRAGMA table_info(${table})`).all();
      if (!cols.some(c => c.name === 'at_rest_scheme')) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN at_rest_scheme TEXT;`);
        console.log(`${table} migration (B5g): added at_rest_scheme column`);
      }
      if (!cols.some(c => c.name === 'at_rest_kek_ref')) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN at_rest_kek_ref TEXT;`);
        console.log(`${table} migration (B5g): added at_rest_kek_ref column`);
      }
    };
    addAtRestCols('forensic_exports');
  } catch (b5gExportAtRestMigrationErr) {
    console.error('B5g export-at-rest column migration failed:', b5gExportAtRestMigrationErr.message);
    console.error('The GD will start, but forensic-export artifacts cannot be sealed or re-encrypted at rest until the at_rest_scheme / at_rest_kek_ref columns exist. Recovery: run the two ALTER TABLE ADD COLUMN statements in a SQLite shell against the GD DB, then restart.');
  }

  // ── B5n3 migration: hardware-credential login hardening ───────────────────
  // Login becomes a hardware FIDO2 key + PIN (user verification) only; a soft
  // certificate is no longer a login credential. Enrollment must prove the
  // passkey is genuine hardware (its attestation chains to a trusted vendor
  // root), non-syncable (backed_up = 0), and UV-gated. These additive columns
  // record that verdict per credential. The two new tables hold the bundled +
  // admin-added trusted attestation roots and the optional AAGUID model
  // allow-list. All idempotent: new columns are guarded by PRAGMA table_info,
  // tables are CREATE IF NOT EXISTS. The bundled roots are loaded from
  // packages/global-dashboard-server/data/fido-attestation-roots.json by
  // gd-seed-fido-roots.js, called below.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS fido_trusted_roots (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        vendor TEXT NOT NULL,
        label TEXT NOT NULL,
        root_pem TEXT NOT NULL,
        seeded INTEGER NOT NULL DEFAULT 1 CHECK (seeded IN (0, 1)),
        added_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(root_pem)
      );
      CREATE INDEX IF NOT EXISTS idx_fido_trusted_roots_vendor
        ON fido_trusted_roots(vendor);

      CREATE TABLE IF NOT EXISTS fido_aaguid_allowlist (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        aaguid TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL,
        added_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    // Additive hardware-attestation columns on webauthn_credentials. ADD COLUMN
    // is idempotent here: each runs only when the column is missing, so an
    // existing deployment upgrades in place without a table rebuild. Pre-B5n3
    // credentials default to hardware_verified = 0; login requires
    // hardware_verified = 1, so any legacy soft credential is refused at login
    // and the user re-enrolls a hardware key -- no migration path weakens the
    // bar.
    const wacCols = db.prepare("PRAGMA table_info(webauthn_credentials)").all().map((c) => c.name);
    if (!wacCols.includes('backed_up')) {
      db.exec("ALTER TABLE webauthn_credentials ADD COLUMN backed_up INTEGER NOT NULL DEFAULT 0");
    }
    if (!wacCols.includes('device_type')) {
      db.exec("ALTER TABLE webauthn_credentials ADD COLUMN device_type TEXT");
    }
    if (!wacCols.includes('attestation_fmt')) {
      db.exec("ALTER TABLE webauthn_credentials ADD COLUMN attestation_fmt TEXT");
    }
    if (!wacCols.includes('hardware_verified')) {
      db.exec("ALTER TABLE webauthn_credentials ADD COLUMN hardware_verified INTEGER NOT NULL DEFAULT 0 CHECK (hardware_verified IN (0, 1))");
    }
    if (!wacCols.includes('trusted_root_id')) {
      db.exec("ALTER TABLE webauthn_credentials ADD COLUMN trusted_root_id TEXT");
    }

    const fidoRootCount = db.prepare("SELECT COUNT(*) AS c FROM fido_trusted_roots").get().c;
    console.log(`B5n3 migration: fido_trusted_roots + fido_aaguid_allowlist + webauthn_credentials hardware columns ready (${fidoRootCount} trusted root(s) present pre-seed)`);
  } catch (b5n3HwAuthMigrationErr) {
    console.error('B5n3 hardware-auth migration FAILED:', b5n3HwAuthMigrationErr.message);
    console.error('The GD will start, but hardware-credential login hardening is not in place: the trusted-root tables or the webauthn_credentials hardware columns may be missing, so hardware-gated passkey enrollment and login cannot function. Recovery: run the CREATE TABLE / ALTER TABLE statements above in a SQLite shell against the production DB.');
  }

  // ── B5r: automated update-detection check log (GD) ────────────────────────
  // Append-only evidence trail for the GD's update-detection feature. Each row
  // records one update check -- scheduled (the GD-server's periodic checker) or
  // manual ("check now") -- capturing when it ran, the running GD version at the
  // time, the outcome, the latest release tag + URL when one was found, whether
  // a notice has fired for that version, and the trigger. Detect-and-notify
  // only: the GD never downloads, routes, or installs an update; this backs the
  // App Updates tab last-/next-check display and the update-available banner.
  // result is a closed enum: 'none' (running the latest, or no stable release
  // published yet -- a 404 during the pre-release era), 'available' (a strictly-
  // newer stable release exists -- never a downgrade), or 'source_unreachable'
  // (network/timeout/unexpected response -- never reported as up-to-date).
  // Idempotent.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS auto_update_check_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        checked_at      TEXT    NOT NULL DEFAULT (datetime('now')),
        current_version TEXT    NOT NULL,
        result          TEXT    NOT NULL CHECK (result IN ('none', 'available', 'source_unreachable')),
        latest_version  TEXT,
        release_url     TEXT,
        notified        INTEGER NOT NULL DEFAULT 0 CHECK (notified IN (0, 1)),
        trigger_kind    TEXT    NOT NULL DEFAULT 'scheduled' CHECK (trigger_kind IN ('scheduled', 'manual'))
      );
      CREATE INDEX IF NOT EXISTS idx_auto_update_check_log_checked_at
        ON auto_update_check_log (checked_at DESC);
    `);
    const auGdUpdateLogPresent = db.prepare("SELECT COUNT(*) AS c FROM sqlite_master WHERE type = 'table' AND name = 'auto_update_check_log'").get().c;
    console.log(`B5r migration: GD automated update-check log ready (${auGdUpdateLogPresent} table present)`);
  } catch (b5rGdUpdateLogMigrationErr) {
    console.error('B5r GD update-check log migration FAILED:', b5rGdUpdateLogMigrationErr.message);
    console.error('The GD will start, but the automated update-detection feature cannot record check results: the auto_update_check_log table may be missing, so the App Updates tab last-check display and the update-available banner have no data source. Recovery: run the CREATE TABLE / CREATE INDEX statements above in a SQLite shell against the production DB.');
  }

  console.log('Global Dashboard database initialized at', DB_PATH);
  require('./services/gd-seed-fido-roots').seedFidoRoots(db);
  db.close();
}

if (require.main === module) {
  require('dotenv').config();
  initDb();
}

module.exports = { getDb, initDb, DB_PATH };

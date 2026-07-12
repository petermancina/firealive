// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Database Schema & Initialization
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../../data/firealive.db');

function ensureDataDir() {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function getDb() {
  ensureDataDir();
  const db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  return db;
}

// ── Schema ───────────────────────────────────────────────────────────────────

const SCHEMA = `
-- ═══════════════════════════════════════════════════════════════════════════
-- TIER-1: Team-level data (visible to management console)
-- No individual burnout indicators. Aggregates only.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  username TEXT UNIQUE NOT NULL,
  email TEXT,  -- R3c: SILENT join key for HR scheduling sync ONLY. Populated by SSO claim at login; never typed by leads, never displayed in MC/AC/GD, never written to burnout/metrics/audit tables. See ANONYMITY MODEL note in migration block below.
  role TEXT NOT NULL CHECK (role IN ('analyst', 'lead', 'admin', 'anon_author')),  -- anon_author: a rights-less system role (in no route allow-list) held only by the lazily-created legacy-anonymous post-author sentinel
  name TEXT NOT NULL,
  pseudonym TEXT,  -- v0.0.25: burnout data keyed to this, not name
  pseudonym_rotated_at TEXT,  -- R0: timestamp of last pseudonym rotation
  tier INTEGER CHECK (tier IN (1, 2, 3)),
  shift TEXT CHECK (shift IN ('day', 'swing', 'night')),
  available INTEGER DEFAULT 1,
  active INTEGER DEFAULT 1,  -- R0: account active flag (distinct from the available shift status); offboarding sets to 0
  capacity_score INTEGER DEFAULT 50,  -- R0: 0-100, higher = more capacity for new tickets; consumed by routing/SOAR feature
  last_heartbeat TEXT,  -- R0: last AC heartbeat ping timestamp; consumed by /api/system/connected-clients (R3l C9)
  last_iam_check TEXT,  -- R0: last time IAM offboarding detector saw this user in the IdP
  offboarded_at TEXT,  -- R0: timestamp of offboarding; pairs with active=0
  auth_method TEXT DEFAULT 'local' CHECK (auth_method IN ('local', 'saml', 'oidc', 'ldap')),
  external_id TEXT,  -- SSO subject identifier
  geo_country TEXT,  -- v0.0.25: assigned country for geo-fencing
  totp_secret TEXT,  -- v1.0.30: TOTP shared secret (Tier-3 encrypted base32). NULL = not enrolled.
  totp_enrolled_at TEXT,  -- v1.0.30: timestamp of TOTP enrollment confirmation
  totp_last_used_step INTEGER,  -- v1.0.30: replay protection -- last accepted TOTP time-step counter
  -- ── R3f (v1.0.31): MFA enforcement + recovery codes ─────────────────────
  mfa_enrollment_required INTEGER NOT NULL DEFAULT 1
    CHECK (mfa_enrollment_required IN (0, 1)),  -- 1 = login refuses to issue JWT
                                                -- when totp_enrolled_at IS NULL.
                                                -- DEFAULT 1: SOC-grade policy
                                                -- requires MFA for all roles.
  totp_recovery_codes_hashed TEXT,              -- JSON array of bcrypt hashes of
                                                -- single-use 14-char alphanumeric
                                                -- recovery codes. Generated at
                                                -- enrollment, displayed once,
                                                -- never stored plaintext.
                                                -- Consumption removes the matched
                                                -- hash from the array.
  totp_recovery_codes_remaining INTEGER,        -- cached count for UI display so
                                                -- the JSON array doesn't have to
                                                -- be parsed for status reads.
  -- ── R3h (v1.0.34): Helper Recognition Leaderboard opt-in ─────────────────
  leaderboard_opt_in INTEGER NOT NULL DEFAULT 0
    CHECK (leaderboard_opt_in IN (0, 1)),       -- 1 = analyst's name + points
                                                -- appear on the Helper
                                                -- Recognition leaderboard
                                                -- reviewed by the lead.
                                                -- DEFAULT 0: opt-out by
                                                -- default for privacy.
                                                -- Earning, accruing, and
                                                -- redeeming Helper Pay
                                                -- points are independent
                                                -- of this flag.
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  last_login TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

-- ── Team Configuration ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS team_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS routing_caps (
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  max_complexity INTEGER NOT NULL DEFAULT 2,
  is_override INTEGER DEFAULT 0,
  override_reason TEXT,
  override_by TEXT REFERENCES users(id),
  updated_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (analyst_id)
);

-- ── Shift Handoffs ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS handoffs (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  from_shift TEXT NOT NULL,
  to_shift TEXT NOT NULL,
  notes TEXT NOT NULL,
  auto_summary TEXT,  -- auto-generated team state snapshot
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT DEFAULT (datetime('now'))
);

-- ── Incident Retrospectives ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS retro_protocols (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  incident TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('P1', 'P2', 'P3')),
  phase TEXT DEFAULT '0-24hr active',
  queue_reduction_duration TEXT,
  initiated_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT DEFAULT (datetime('now')),
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS retro_analysts (
  retro_id TEXT NOT NULL REFERENCES retro_protocols(id) ON DELETE CASCADE,
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (retro_id, analyst_id)
);

CREATE TABLE IF NOT EXISTS retro_actions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  retro_id TEXT NOT NULL REFERENCES retro_protocols(id) ON DELETE CASCADE,
  action_text TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

-- ── Skills & Assessments ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  tier INTEGER NOT NULL,
  status TEXT DEFAULT 'active' CHECK (status IN ('active', 'archived')),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS assessment_skills (
  assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  skill_id TEXT NOT NULL,
  is_custom INTEGER DEFAULT 0,
  custom_name TEXT,
  custom_desc TEXT,
  PRIMARY KEY (assessment_id, skill_id)
);

CREATE TABLE IF NOT EXISTS assessment_assignees (
  assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (assessment_id, analyst_id)
);

CREATE TABLE IF NOT EXISTS assessment_results (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  skill_id TEXT NOT NULL,
  score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
  completed_at TEXT DEFAULT (datetime('now'))
);

-- ── Curated Training Library (R3l) ───────────────────────────────────────
-- ANALYST EDUCATION PIPELINE — curated, read-only at runtime
--
-- These tables hold the curated training library that drives the AC's
-- Training tab + the canonical /api/training-recommendations/me endpoint.
-- The library is seeded at install time from data/training-modules-seed.json
-- via server/db/seed-training-library.js. The tables are READ-ONLY at
-- runtime:
--   • No POST/PUT/DELETE API endpoints write to these tables.
--   • The seed loader at boot is the only writer.
--   • New training modules ship via canonical FireAlive version upgrades
--     (PR review of the seed file by upstream maintainers, who verify each
--     URL's legitimacy against the target platform's official course
--     catalog before merge).
--   • Organizations needing internal/org-specific training URLs fork the
--     AGPL-3.0 repository and customize their fork's seed file.
--
-- The URL legitimacy CHECK constraint on training_modules.url is
-- defense-in-depth, NOT the primary control. The primary control is
-- "no write paths exist." See docs/training-library.md (R3l C18) for
-- the full design rationale.

CREATE TABLE IF NOT EXISTS training_platforms (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  domain_pattern TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS training_modules (
  id TEXT PRIMARY KEY,
  platform_id TEXT NOT NULL REFERENCES training_platforms(id),
  skill_id TEXT NOT NULL,
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  difficulty TEXT CHECK (difficulty IN ('beginner', 'intermediate', 'advanced', 'expert')),
  free_or_paid TEXT CHECK (free_or_paid IN ('free', 'paid', 'subscription', 'enterprise')),
  estimated_hours INTEGER,
  description TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  CONSTRAINT url_legitimacy CHECK (
    url LIKE 'https://tryhackme.com/%'
    OR url LIKE 'https://academy.hackthebox.com/%'
    OR url LIKE 'https://app.letsdefend.io/%'
    OR url LIKE 'https://cyberdefenders.org/%'
    OR url LIKE 'https://www.sans.org/cyber-security-courses/%'
    OR url LIKE 'https://www.immersivelabs.com/%'
    OR url LIKE '/training/internal/%'
  )
);

CREATE INDEX IF NOT EXISTS idx_training_modules_skill ON training_modules(skill_id) WHERE active = 1;
CREATE INDEX IF NOT EXISTS idx_training_modules_platform ON training_modules(platform_id);

-- ── R3l Workstream 2a: Forensic Export ──────────────────────────────────
--
-- SOC-grade forensic export package generator. Operators (admin role) request
-- a time-windowed export of platform audit records across multiple structured
-- forensic formats (Sleuth Kit bodyfile, JSON Lines, plaso L2T CSV, CEF, EVTX,
-- STIX 2.1, DFXML, CSV). Each export produces a tar.gz archive plus a manifest
-- signed with Ed25519 (and optionally Cosign), with archive SHA-256 captured.
--
-- The forensic_export_chain is an append-only hash chain of every operation
-- against an export (CREATE, COMPLETE, DOWNLOAD, DELETE, VERIFY). Triggers
-- enforce append-only at the engine level — UPDATE and DELETE both throw.
-- DELETE on a forensic_export row requires the ciso role (separate-actor
-- enforcement is checked at the route layer; the chain records who acted).
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

-- ── Custom Recovery Resources ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS custom_resources (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('professional', 'self-help', 'peer', 'training')),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT DEFAULT (datetime('now'))
);

-- ── Lighter Queue Requests (Tier-1: anonymous aggregate only) ────────────

CREATE TABLE IF NOT EXISTS lighter_queue_requests (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  duration TEXT NOT NULL,
  max_complexity INTEGER NOT NULL DEFAULT 2,
  status TEXT DEFAULT 'active' CHECK (status IN ('active', 'expired', 'cancelled')),
  created_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT
);

-- ── Automation Systems ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS automation_systems (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  handles_l1 INTEGER DEFAULT 0,
  handles_l2 INTEGER DEFAULT 0,
  handles_l3 INTEGER DEFAULT 0,
  max_capacity INTEGER NOT NULL,
  capacity_unit TEXT DEFAULT 'alerts/hr',
  api_endpoint TEXT,
  api_key_encrypted BLOB,
  status TEXT DEFAULT 'configuring' CHECK (status IN ('operational', 'degraded', 'offline', 'configuring')),
  created_at TEXT DEFAULT (datetime('now'))
);

-- ── Delegations ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS delegations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  pattern_description TEXT NOT NULL,
  target_system_id TEXT NOT NULL REFERENCES automation_systems(id),
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected', 'expired')),
  submitted_by TEXT NOT NULL REFERENCES users(id),
  reviewed_by TEXT REFERENCES users(id),
  created_at TEXT DEFAULT (datetime('now')),
  resolved_at TEXT
);

-- ═══════════════════════════════════════════════════════════════════════════
-- TIER-3: Analyst private data (encrypted, never visible to management)
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS analyst_consent_log (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  detail TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

-- ── Peer Messaging (E2EE — server stores only ciphertext) ────────────────

-- Phase U3: ordered, session-scoped Signal-protocol ciphertext relay.
-- The server stores opaque libsignal messages plus routing/ordering metadata
-- only — it holds no keys and cannot read content. Identities are known to the
-- server for delivery (the same pairing it already tracks in peer_sessions);
-- analyst-to-analyst pseudonymity is enforced at the application layer, not by
-- hiding routing from the relay. The Double Ratchet is order-sensitive, so rows
-- are sequenced per session by the counter column.
CREATE TABLE IF NOT EXISTS peer_messages (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  session_id TEXT NOT NULL,
  sender_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_type INTEGER NOT NULL,  -- libsignal CiphertextMessageType (PreKey=3, Whisper=2)
  ciphertext BLOB NOT NULL,       -- opaque serialized libsignal message
  counter INTEGER NOT NULL,       -- per-session ordering
  created_at TEXT DEFAULT (datetime('now')),
  delivered_at TEXT,
  read_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_peer_messages_session ON peer_messages (session_id, counter);
CREATE INDEX IF NOT EXISTS idx_peer_messages_recipient ON peer_messages (recipient_user_id);
CREATE INDEX IF NOT EXISTS idx_peer_messages_created ON peer_messages (created_at);


-- ── Lead Messaging (E2EE — server stores only ciphertext) ────────────────

-- Phase U3: ordered, thread-scoped Signal-protocol ciphertext relay for the
-- pseudonymous analyst<->team-lead chat. Mirrors peer_messages exactly: the
-- server stores opaque libsignal messages plus routing/ordering metadata only,
-- holds no keys, and cannot read content. The chat uses the separate 'lead'
-- key domain (see the e2ee_* pre-key store below), so its key material never
-- mixes with peer chat. A thread is one analyst/lead pairing; rows are
-- sequenced per thread by the counter column for the order-sensitive Double
-- Ratchet. analyst_id and lead_id stamp every row so a later abuse flag
-- attributes to the exact lead. The analyst is pseudonymous to the lead (the
-- UUID->pseudonym->real-name map lives only in the lead's offline export);
-- leads are not pseudonymized. sender_role drives display; kind separates
-- ordinary chat from an in-person 1-on-1 request. The 5-minute-after-close
-- purge clock lives on the lead-chat thread record (closed_at), not per
-- message, so there is no retention column here.
CREATE TABLE IF NOT EXISTS lead_messages (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  thread_id TEXT NOT NULL,
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  lead_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_role TEXT NOT NULL CHECK (sender_role IN ('analyst', 'lead')),
  kind TEXT NOT NULL DEFAULT 'chat' CHECK (kind IN ('chat', 'inperson_1on1_request')),
  message_type INTEGER NOT NULL,  -- libsignal CiphertextMessageType (PreKey=3, Whisper=2)
  ciphertext BLOB NOT NULL,       -- opaque serialized libsignal message
  counter INTEGER NOT NULL,       -- per-thread ordering
  created_at TEXT DEFAULT (datetime('now')),
  delivered_at TEXT,
  read_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_lead_messages_thread ON lead_messages (thread_id, counter);
CREATE INDEX IF NOT EXISTS idx_lead_messages_recipient ON lead_messages (recipient_user_id);
CREATE INDEX IF NOT EXISTS idx_lead_messages_created ON lead_messages (created_at);


-- ── Lead-chat threads (pairing + retention clock) ────────────────────────

-- Phase U3: one persistent thread per (analyst_id, lead_id) pairing for the
-- pseudonymous analyst<->team-lead chat. The thread id is the stable libsignal
-- addressing key (stamped on lead_messages.thread_id) and survives across
-- conversations, so the Double Ratchet session is reused rather than
-- re-established on each open. A conversation opens (status 'active'); the
-- analyst closes it (status 'closed', closed_at set); the shared retention
-- sweep then deletes the thread's lead_messages five minutes after closed_at.
-- The thread record itself persists as the reusable pairing anchor -- the
-- messages are gone but the pair can reopen later. UNIQUE (analyst_id,
-- lead_id) enforces one thread per pairing; a different lead (e.g. a new
-- shift) is a different pairing and therefore a new thread. Identities are
-- present for routing only; the analyst stays pseudonymous in the system
-- (the UUID->pseudonym->real-name map is the lead's offline export, and leads
-- are not pseudonymized).
CREATE TABLE IF NOT EXISTS lead_chat_threads (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  lead_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'closed')),
  message_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  last_message_at TEXT,
  closed_at TEXT,
  UNIQUE (analyst_id, lead_id)
);

CREATE INDEX IF NOT EXISTS idx_lead_chat_threads_lead ON lead_chat_threads (lead_id, status);
CREATE INDEX IF NOT EXISTS idx_lead_chat_threads_analyst ON lead_chat_threads (analyst_id, status);
CREATE INDEX IF NOT EXISTS idx_lead_chat_threads_closed ON lead_chat_threads (closed_at);


-- ═══════════════════════════════════════════════════════════════════════════
-- Phase U3: Signal-protocol (X3DH/PQXDH) public pre-key store.
-- Public key material ONLY. Every private key and all Double-Ratchet session
-- state lives client-side (Electron main, sealed with the OS keychain). Rows
-- are namespaced by (user_id, domain) with domain IN ('peer','lead') so the two
-- chat key domains never share key material.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS e2ee_identity_keys (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain TEXT NOT NULL CHECK (domain IN ('peer', 'lead')),
  identity_pubkey BLOB NOT NULL,
  registration_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, domain)
);

-- One current EC signed pre-key and one current Kyber (PQXDH) pre-key per
-- (user_id, domain), distinguished by the kind column. Both carry an
-- identity-key signature over the public key.
CREATE TABLE IF NOT EXISTS e2ee_signed_prekeys (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain TEXT NOT NULL CHECK (domain IN ('peer', 'lead')),
  kind TEXT NOT NULL CHECK (kind IN ('signed', 'kyber')),
  key_id INTEGER NOT NULL,
  pubkey BLOB NOT NULL,
  signature BLOB NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, domain, kind)
);

-- Replenishable batch of one-time EC pre-keys; a bundle fetch consumes one
-- (sets consumed_at). Anonymity-preserving fetch resolves the peer via the
-- session record (see peers.js) and returns key material only.
CREATE TABLE IF NOT EXISTS e2ee_one_time_prekeys (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain TEXT NOT NULL CHECK (domain IN ('peer', 'lead')),
  key_id INTEGER NOT NULL,
  pubkey BLOB NOT NULL,
  consumed_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, domain, key_id)
);

CREATE INDEX IF NOT EXISTS idx_e2ee_otp_available
  ON e2ee_one_time_prekeys (user_id, domain, consumed_at);

-- ═══════════════════════════════════════════════════════════════════════════
-- SHARED: Configuration, audit, integrations
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Integration Configuration ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS integration_config (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  integration_type TEXT NOT NULL CHECK (integration_type IN (
    'soar', 'siem', 'ticketing', 'iam_saml', 'iam_oidc', 'iam_ldap', 'iam_cloud',
    'sdn', 'cloud_aws', 'cloud_gcp', 'cloud_azure',
    'training_htb', 'training_thm', 'training_letsdefend', 'training_cyberdefenders',
    'training_sans', 'training_immersive',
    'notifications', 'backup'
  )),
  config_encrypted BLOB NOT NULL,  -- all integration configs are encrypted at rest
  status TEXT DEFAULT 'not_configured' CHECK (status IN ('not_configured', 'configured', 'testing', 'operational', 'error')),
  last_test_at TEXT,
  last_test_result TEXT,
  created_by TEXT REFERENCES users(id),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- ── SDN (Software-Defined Networking) mode + controller integration (B5i) ──
-- Read-only controller integration plus the operator-declared network map that
-- sdn deployment mode uses for self-protection (connection admission), policy
-- generation, and posture-degradation detection. FireAlive never writes to the
-- controller; these tables hold only what it reads, observes, and configures.

CREATE TABLE IF NOT EXISTS sdn_integrations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  platform TEXT NOT NULL CHECK (platform IN (
    'cisco-aci', 'vmware-nsx', 'openflow', 'arista-cv',
    'juniper-cn2', 'calico', 'cilium', 'custom'
  )),
  api_endpoint TEXT NOT NULL,
  api_credentials_encrypted BLOB,         -- Tier-1 KEK wrap of the per-platform credential blob (token/cert/user+pass/API key)
  endpoint_fingerprint TEXT,              -- pinned controller certificate fingerprint for mTLS
  enabled INTEGER DEFAULT 1,
  created_by TEXT REFERENCES users(id),
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  last_probe_at TEXT,
  last_probe_status TEXT CHECK (last_probe_status IN ('unknown', 'reachable', 'unreachable', 'unauthenticated', 'error')),
  last_probe_detail TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,   -- B5i posture debounce: consecutive failed probes (feeds the degraded threshold)
  consecutive_successes INTEGER NOT NULL DEFAULT 0   -- B5i posture debounce: consecutive successful probes (feeds recovery hysteresis)
);

-- Singleton operator-declared topology (one row, keyed 'default').
CREATE TABLE IF NOT EXISTS sdn_network_map (
  id TEXT PRIMARY KEY DEFAULT 'default',
  permitted_segments TEXT DEFAULT '[]',   -- JSON array of CIDRs/segments FireAlive's own components may use
  tier_segment_map TEXT DEFAULT '{}',     -- JSON object mapping FireAlive tier -> segment/VLAN
  sdwan_sites TEXT DEFAULT '{}',          -- JSON object: primary/secondary site CIDRs + overlay
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Append-only audit of read-only observations and posture transitions.
CREATE TABLE IF NOT EXISTS sdn_posture_events (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  integration_id TEXT REFERENCES sdn_integrations(id),
  event_type TEXT NOT NULL CHECK (event_type IN (
    'probe', 'topology_read', 'segmentation_read',
    'admission_refused', 'posture_degraded', 'posture_restored'
  )),
  severity TEXT DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  detail TEXT,                            -- JSON observation/transition detail
  observed_at TEXT DEFAULT (datetime('now'))
);

-- Singleton aggregate posture state machine (one row, keyed 'default') so the
-- graduated/hysteretic degradation detector survives restart (B5i, D-B5i-5).
CREATE TABLE IF NOT EXISTS sdn_posture_state (
  id TEXT PRIMARY KEY DEFAULT 'default',
  current_state TEXT NOT NULL DEFAULT 'healthy' CHECK (current_state IN ('healthy', 'uncertain', 'degraded')),
  state_since TEXT DEFAULT (datetime('now')),
  last_eval_at TEXT,
  last_transition_event_id TEXT REFERENCES sdn_posture_events(id)
);

-- B5k SASE posture: append-only audit of dark-app / passthrough admission
-- refusals and posture transitions. SASE degradation is event-driven (discrete
-- security events), not probe-noise, so there is no separate hysteresis state
-- table; posture is re-derived from this log and so survives restart.
CREATE TABLE IF NOT EXISTS sase_posture_events (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  event_type TEXT NOT NULL CHECK (event_type IN (
    'direct_exposure_refused', 'passthrough_violation_refused',
    'posture_degraded', 'posture_restored'
  )),
  severity TEXT DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  detail TEXT,                            -- JSON observation/transition detail
  observed_at TEXT DEFAULT (datetime('now'))
);

-- ── API Keys ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,  -- bcrypt hash of the key (key itself is shown once)
  key_prefix TEXT NOT NULL,      -- first 8 chars for identification (e.g., "scr-a3f8")
  scopes TEXT NOT NULL,          -- comma-separated: health:read,siem:read,reports:generate
  expires_at TEXT,
  revoked INTEGER DEFAULT 0,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT DEFAULT (datetime('now')),
  last_used_at TEXT
);

-- ── Reports ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS report_config (
  id TEXT PRIMARY KEY DEFAULT 'default',
  schedule TEXT DEFAULT 'weekly',
  day_of_week TEXT DEFAULT 'monday',
  time_of_day TEXT DEFAULT '08:00',
  format TEXT DEFAULT 'json' CHECK (format IN ('json', 'html', 'pdf', 'txt')),
  recipients TEXT DEFAULT '',
  siem_feed INTEGER DEFAULT 1,
  sections TEXT DEFAULT '{"teamHealth":true,"utilization":true,"tierBreakdown":true,"automationRate":true,"trendAnalysis":true,"kbInsights":true,"skillProgress":true,"upskillingGaps":true}',
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  type TEXT NOT NULL CHECK (type IN ('scheduled', 'on-demand')),
  format TEXT NOT NULL,
  content BLOB NOT NULL,  -- the generated report
  sections_count INTEGER,
  generated_by TEXT REFERENCES users(id),
  generated_at TEXT DEFAULT (datetime('now'))
);

-- ── SLA Configuration ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sla_config (
  id TEXT PRIMARY KEY DEFAULT 'default',
  p1_mtta TEXT DEFAULT '5m',
  p1_mttr TEXT DEFAULT '60m',
  p2_mtta TEXT DEFAULT '15m',
  p2_mttr TEXT DEFAULT '4h',
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sla_measurements (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  priority TEXT NOT NULL CHECK (priority IN ('P1', 'P2', 'P3')),
  mtta_seconds INTEGER,
  mttr_seconds INTEGER,
  ticket_ref TEXT,
  measured_at TEXT DEFAULT (datetime('now'))
);

-- ── Notification Configuration ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS notification_config (
  id TEXT PRIMARY KEY DEFAULT 'default',
  threshold TEXT DEFAULT 'watch' CHECK (threshold IN ('watch', 'stressed', 'critical')),
  email_enabled INTEGER DEFAULT 0,
  email_address TEXT,
  sms_enabled INTEGER DEFAULT 0,
  sms_number TEXT,
  webhook_enabled INTEGER DEFAULT 0,
  webhook_url TEXT,
  pagerduty_enabled INTEGER DEFAULT 0,
  pagerduty_key TEXT,
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- ── Backups ──────────────────────────────────────────────────────────────
-- Two backup format versions are supported:
--   format_version = 1 — legacy raw SQLite .db file copy (v1.0.29 and
--     earlier). Stored at file_path; verified by sha256_hash. Internal
--     restore reads this directly via fs.copyFileSync.
--   format_version = 2 — encrypted, signed directory layout (v1.0.30+).
--     Each backup is a folder containing four files:
--       archive.tar.zst.enc   — tar archive, zstd-compressed, AES-256-GCM
--       manifest.json         — cleartext manifest with per-file SHA-256
--       manifest.sig          — Ed25519 signature of manifest.json
--       wrapped-key.bin       — per-backup data key wrapped with KEK
--     Each file has its own *_path column. file_path is NULL for v2 rows.
--
-- file_path is nullable to accommodate v2 rows. For v1 rows it remains
-- the canonical pointer to the .db copy. Old installs that started on
-- v1.0.29's NOT NULL constraint get rebuilt by the migration block below.

CREATE TABLE IF NOT EXISTS backups (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  type TEXT NOT NULL CHECK (type IN ('scheduled', 'on-demand', 'snapshot')),
  size_bytes INTEGER,
  file_path TEXT,                                   -- v1 only; NULL for v2
  sha256_hash TEXT,                                 -- v1: hash of the .db file; v2: hash of manifest.json
  status TEXT DEFAULT 'running' CHECK (status IN ('running', 'verified', 'failed')),
  created_at TEXT DEFAULT (datetime('now')),
  -- ── R3d-1: v2 encrypted-format columns ────────────────────────────────
  format_version INTEGER NOT NULL DEFAULT 1
    CHECK (format_version IN (1, 2)),
  manifest_path TEXT,                               -- v2 only
  archive_path TEXT,                                -- v2 only
  manifest_sig_path TEXT,                           -- v2 only
  wrapped_key_path TEXT,                            -- v2 only
  signing_key_id INTEGER REFERENCES backup_signing_keys(id) ON DELETE RESTRICT
);

-- ── R3d-1: BACKUP SIGNING KEYS ───────────────────────────────────────────
-- Ed25519 keypair per install. Public key plaintext (used by verifiers,
-- no confidentiality concern). Private key Tier-1 AES-256-GCM encrypted
-- (used by the backup engine when signing manifests).
--
-- ROTATION MODEL: One active keypair at a time (is_active = 1); old
-- keypairs are retained with is_active = 0 so manifests signed under
-- them stay verifiable. Rotation creates a new active keypair and demotes
-- the previous one. Never delete a row — backups signed under that key
-- become unverifiable. The backups.signing_key_id FK uses ON DELETE
-- RESTRICT to enforce this at the DB level.
--
-- KEY GENERATION: at server startup, if no rows exist OR no row has
-- is_active = 1, the backup-keys service generates a new keypair and
-- inserts a row with is_active = 1. This bootstraps fresh installs and
-- recovers from accidental deactivation.
CREATE TABLE IF NOT EXISTS backup_signing_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_key TEXT NOT NULL,                         -- PEM-encoded Ed25519 public key (SPKI)
  public_key_fingerprint TEXT,                      -- SHA-256 hex of SPKI DER bytes (64 chars).
                                                    -- Universal cross-deployment key identifier
                                                    -- carried in v3 manifests; service layer
                                                    -- ensures this is set on every insert.
                                                    -- NULL only on legacy rows pre-R3d-5-pt2
                                                    -- where the migration couldn't parse the key.
  private_key_encrypted TEXT,                       -- Tier-1 AES-256-GCM JSON {iv, tag, ciphertext}.
                                                    -- NULL for key_origin='external-registered'
                                                    -- (we have only the public part of foreign
                                                    -- deployments' keys).
  is_active INTEGER NOT NULL DEFAULT 0
    CHECK (is_active IN (0, 1)),
  key_origin TEXT NOT NULL DEFAULT 'local-generated'
    CHECK (key_origin IN ('local-generated', 'external-registered')),
  registered_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
                                                    -- who pasted/registered the foreign public
                                                    -- key (NULL for local-generated rows).
  registered_at TEXT,                               -- when registered (NULL for local-generated).
  key_label TEXT,                                   -- operator-friendly description for
                                                    -- external-registered keys (e.g.
                                                    -- "prod-east deployment, key from
                                                    -- 2026-04-15").
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_out_at TEXT,                              -- when is_active flipped 1 -> 0
                                                    -- OR when an external-registered key
                                                    -- was revoked.
  notes TEXT,
  -- Local-generated keys MUST have a private key (we created it ourselves).
  -- External-registered keys MUST NOT have a private key (we only have the
  -- public part of a foreign deployment's keypair), MUST be inactive
  -- (verification-only, never used for signing), and MUST carry registration
  -- metadata (who/when, for audit).
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

CREATE INDEX IF NOT EXISTS idx_backup_signing_keys_active
  ON backup_signing_keys(is_active) WHERE is_active = 1;
CREATE INDEX IF NOT EXISTS idx_backup_signing_keys_fingerprint
  ON backup_signing_keys(public_key_fingerprint)
  WHERE public_key_fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_backup_signing_keys_origin
  ON backup_signing_keys(key_origin);


-- ── R3d-2: CHAIN SIGNING KEYS ────────────────────────────────────────────
-- Ed25519 keypair per install used to sign backup_chain entries. Public
-- key plaintext (used by chain verifiers, no confidentiality concern).
-- Private key Tier-1 AES-256-GCM encrypted (used by the chain service
-- when appending entries).
--
-- DELIBERATELY SEPARATE FROM backup_signing_keys. Chain integrity is a
-- distinct cryptographic concern from backup integrity -- a compromise
-- of the backup-signing key MUST NOT compromise the chain audit trail.
-- The keys never share storage, never share the same in-memory KeyObject
-- instance, never share a service module. Cost is ~150 lines of
-- duplicated keypair-management boilerplate; the security separation
-- justifies it.
--
-- ROTATION MODEL: same as backup_signing_keys -- one active keypair at
-- a time (is_active = 1), old keypairs retained with is_active = 0 +
-- rotated_out_at so historical chain entries stay verifiable.
CREATE TABLE IF NOT EXISTS chain_signing_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_key TEXT NOT NULL,                         -- base64 Ed25519 public key
  private_key_encrypted TEXT NOT NULL,              -- Tier-1 AES-256-GCM JSON {iv, tag, ciphertext}
  is_active INTEGER NOT NULL DEFAULT 0
    CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_out_at TEXT,                              -- when is_active flipped 1 -> 0
  notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_chain_signing_keys_active
  ON chain_signing_keys(is_active) WHERE is_active = 1;


-- ── R3d-2: BACKUP CHAIN (cryptographic chain of custody) ─────────────────
-- Append-only hash-chained audit log of backup operations. Detects
-- backup deletion, modification, substitution, and replay against the
-- audit trail itself.
--
-- HASH CHAIN FORMAT
--
--   prev_hash    SHA-256 hex of the previous entry's this_hash
--                NULL for the genesis entry (the first one ever)
--
--   this_hash    SHA-256 hex of:
--                  prev_hash || canonicalized_payload || created_at
--                where || is byte concatenation. canonicalized_payload
--                is the canonical-JSON serialization of the payload
--                column (same canonicalization rules as
--                backup-manifest.js).
--
--   signature    base64 of Ed25519 signature over this_hash bytes
--                Signed by the active chain_signing_keys keypair at
--                append time. signing_key_id records which keypair
--                signed this entry so historical entries stay
--                verifiable across rotations.
--
-- EVENT TYPES
--
--   CREATE              backup created (manifest_sha256 in payload)
--   VERIFY              backup integrity check ran (result in payload)
--   RESTORE_REQUEST     restore initiated for a backup
--   RESTORE_COMPLETE    restore applied
--   DELETE_DENIED       attempted backup deletion that was refused
--                       (e.g. retention attempting to delete a
--                       backup still within its retention window; the
--                       attempt itself is logged for auditability)
--
-- backup_id is nullable for events not tied to a specific backup
-- (e.g. periodic chain self-verifications). It is NOT a foreign key
-- because the chain must persist even if a backup row is later
-- deleted -- the audit trail is the source of truth, not the
-- backups table.
--
-- APPEND-ONLY ENFORCEMENT
--
-- Two SQLite triggers reject UPDATE and DELETE on this table. Defeats
-- in-app tampering paths. OS-level protection (filesystem permissions,
-- immutable storage, OS-level audit) is a separate higher layer
-- outside the scope of these triggers but matters for true
-- append-only guarantees -- triggers are the first line of defense,
-- not the last.
CREATE TABLE IF NOT EXISTS backup_chain (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  prev_hash TEXT,
  this_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  signing_key_id INTEGER NOT NULL REFERENCES chain_signing_keys(id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL
    CHECK (event_type IN ('CREATE', 'VERIFY', 'RESTORE_REQUEST', 'RESTORE_COMPLETE', 'DELETE_DENIED')),
  backup_id TEXT,                                   -- soft reference; chain persists even if backup row is deleted
  payload TEXT NOT NULL,                            -- canonicalized JSON
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_backup_chain_id
  ON backup_chain(id DESC);
CREATE INDEX IF NOT EXISTS idx_backup_chain_backup
  ON backup_chain(backup_id);
CREATE INDEX IF NOT EXISTS idx_backup_chain_event
  ON backup_chain(event_type);

CREATE TRIGGER IF NOT EXISTS backup_chain_no_update
  BEFORE UPDATE ON backup_chain
  BEGIN SELECT RAISE(ABORT, 'backup_chain is append-only'); END;

CREATE TRIGGER IF NOT EXISTS backup_chain_no_delete
  BEFORE DELETE ON backup_chain
  BEGIN SELECT RAISE(ABORT, 'backup_chain is append-only'); END;


-- ── R3d-3: BACKUP DESTINATIONS (off-host push targets) ───────────────────
-- Each row defines a configured destination where backups are pushed
-- after creation. The push happens automatically per services/backup-push.js
-- (the push orchestrator) -- backups created with no enabled destinations
-- stay on-host only (BACKUP_DIR), which is the v1.0.30 R3d-1/R3d-2
-- baseline behavior.
--
-- ADAPTER COLUMN
--
-- 'local'        push to a separate local mount path (NAS, off-host
--                filesystem mount). Configured via config.path.
--                Immutability is the OS's responsibility.
-- 'sftp'         push to an SFTP server using the existing ssh2 dep.
--                Configured via config.host/port/username/path; auth
--                via credentials_encrypted (key OR password).
-- 's3'           cloud object storage. NOT IMPLEMENTED in R3d-3 --
--                rejected by the destination service with a clear
--                'lands in R3d-4' message. The CHECK constraint
--                accepts the value so future adapters add without
--                schema migration.
-- 'azure-blob'   Azure Blob Storage. NOT IMPLEMENTED in R3d-3 -- R3d-4.
-- 'gcs'          GCP Cloud Storage. NOT IMPLEMENTED in R3d-3 -- R3d-4.
--
-- IMMUTABILITY_MODE COLUMN
--
-- 'none'           operator declares no immutability protection
-- 'append-only'    SFTP append-only directory or local-mount
--                  with chattr +i applied by the operator outside
--                  FireAlive's control
-- 'object-lock'    S3 Object Lock (probed by adapter when
--                  implemented in R3d-4). Refused by the local
--                  and SFTP adapters in R3d-3.
-- 'unknown'        operator hasn't declared; FireAlive does not
--                  attempt to probe and does not refuse pushes
--
-- FireAlive does NOT enforce immutability itself (R3d-3); it
-- trusts the operator's declaration. R3d-4 will add probes for
-- destinations where they are programmatically verifiable
-- (S3 GetObjectLockConfiguration).
-- B5q: generalized storage-destination registry (renamed from
-- backup_destinations -- backups were its first consumer, but it is the
-- shared registry of physical targets for every routed artifact type:
-- backups, audit-log archives, forensic exports, snapshots, and CEF-stream
-- archives). Existing databases are migrated by the guarded rename block in
-- initDb (preserving all rows, the R3l C54 tags column, and the backup_pushes
-- foreign key, which SQLite rewrites on RENAME).
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


-- ── B5n2: DATA RESIDENCY (jurisdiction declarations + transfer register) ──
-- Per-destination jurisdiction declarations and the derived-and-annotated
-- cross-border transfer register backing the data-residency policy. The
-- policy itself lives in the config table under 'data_residency_config'.
-- Both tables are operational state (NOT golden-baseline). storage_destinations
-- carries no region column, so the declaration is a side table keyed by
-- destination_ref (the storage_destinations.id). B5q adds the routed kinds.
CREATE TABLE IF NOT EXISTS data_residency_destinations (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  destination_kind  TEXT NOT NULL,        -- 'backup' (B5q adds the routed kinds)
  destination_ref   TEXT NOT NULL,        -- storage_destinations.id
  declared_country  TEXT,                 -- ISO 3166-1 alpha-2
  declared_region   TEXT,                 -- provider region string, if known
  provider_domicile TEXT,                 -- legal home of the provider (e.g. 'US')
  key_custody       TEXT,                 -- jurisdiction of the encryption keys
  auto_detected     INTEGER NOT NULL DEFAULT 0
    CHECK (auto_detected IN (0, 1)),
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_residency_dest
  ON data_residency_destinations(destination_kind, destination_ref);

CREATE TABLE IF NOT EXISTS data_residency_transfers (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  transfer_key         TEXT NOT NULL UNIQUE,  -- category + destination_ref fingerprint
  data_category        TEXT NOT NULL,
  source_jurisdiction  TEXT,
  dest_jurisdiction    TEXT,
  destination_ref      TEXT,
  provider_domicile    TEXT,
  foreign_law_exposure TEXT,                  -- e.g. 'US CLOUD Act'
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


-- ── R3d-3: BACKUP PUSHES (per-backup-per-destination push status) ────────
-- Tracks the status of every push attempt. One row per (backup,
-- destination) pair, updated as the push progresses through:
--
--   queued    → just created; orchestrator will pick it up
--   running   → adapter is currently uploading
--   succeeded → upload completed; pushed_at and size set
--   failed    → upload failed; error_message set; next_retry_at
--               populated for the scheduler to retry with
--               exponential backoff
--
-- backup_id is a SOFT reference (no FK) so push-audit records
-- persist even if backups rows are later removed by retention or
-- admin operations. The push history itself is part of the audit
-- trail, not the backups table.
--
-- destination_id IS a foreign key with ON DELETE RESTRICT --
-- destinations cannot be deleted while push records reference
-- them. Operators wanting to retire a destination should mark
-- it disabled (enabled=0); the destination row stays for audit
-- continuity.
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


-- ── B5q: STORAGE DESTINATION ROUTING + SEALED ARCHIVE SEGMENTS ───────────
-- Per-data-type routing map plus the shared sealed archive-segment chain
-- used by the audit-log and CEF archival writers. The routes table is
-- operational state (NOT golden-baseline). The segment chain is append-only
-- (tamper- AND gap-evident) and its manifests are signed by a dedicated
-- Ed25519 family so one custody chain's key compromise cannot forge another.

-- Routing map: one row per routed data type. destination_ref is a SOFT ref to
-- storage_destinations.id (NULL = unconfigured; for 'snapshot', NULL means
-- inherit the 'backup' route). options carries per-type JSON (cadence,
-- immutability_required, ...). The PRIMARY KEY on data_type encodes the
-- one-destination-per-type rule -- there is no fan-out.
CREATE TABLE IF NOT EXISTS storage_destination_routes (
  data_type TEXT PRIMARY KEY
    CHECK (data_type IN ('backup', 'audit_log', 'forensic_export', 'snapshot', 'cef_archive')),
  destination_ref TEXT,                    -- soft ref to storage_destinations.id (primary)
  secondary_destination_ref TEXT,          -- optional secondary; soft ref to storage_destinations.id
  path_prefix TEXT,
  options TEXT,                            -- JSON: cadence, immutability_required, ...
  enabled INTEGER NOT NULL DEFAULT 0
    CHECK (enabled IN (0, 1)),
  updated_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Sealed archive-segment chain (audit_log + cef_archive). Each segment
-- references the prior segment's hash, so the series is tamper-evident (a
-- changed segment breaks this_hash) and gap-evident (a removed segment breaks
-- the prev_hash link). Append-only, mirroring the audit / forensic chains.
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

-- B5q Revision v4: per-push tracking for archive segments. Mirrors backup_pushes.
-- The append-only storage_archive_segments row carries the integrity chain only;
-- this mutable table is the single record of every push (primary + secondary) and
-- its retry state. The primary row is written 'succeeded' when the segment is
-- committed (the segment commits only after the primary push lands); the secondary
-- row is retried until it lands. source_artifact_path is the retained pending copy
-- to re-push the secondary from (NULL once replicated/cleaned up).
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

-- B5q Revision v4: per-push tracking for forensic exports. Same shape as
-- archive_segment_pushes, keyed by the forensic_exports row. Both the primary and
-- secondary rows are retried (neither push gates the export, which succeeds on the
-- local seal); re-staged from the already-retained export files, so there is no
-- separate pending directory for forensic.
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

-- Dedicated Ed25519 family signing the archive-segment manifests. Private
-- material is Tier-1-KEK-wrapped; one active key at a time (the partial
-- index). Mirrors forensic_export_chain_signing_keys et al.
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


-- ── R3d-4: KMS PROVIDERS (key encryption key sources) ────────────────────
-- Each row defines a configured KEK source. The DEFAULT row (is_default=1)
-- is used for new backups; old backups remember their original provider
-- via the manifest's key_wrapping.scheme + kek_reference fields, so old
-- providers stay reachable for restore as long as their row is enabled.
--
-- PROVIDER TYPES
--
-- 'env-var'         TIER1_ENCRYPTION_KEY env var (existing R3d-1 behavior).
--                   Always available. Auto-seeded as the initial default
--                   on first boot if no rows exist (boot path in init.js).
--                   Tier 3 security (KEK in process memory).
--
-- 'aws-kms'         AWS KMS via @aws-sdk/client-kms. Tier 2 security
--                   (KEK in AWS HSM, FIPS 140-2 Level 3 in eligible
--                   regions). config: {region, key_id|key_arn,
--                   encryption_context?}. credentials: {access_key_id,
--                   secret_access_key, session_token?} OR rely on
--                   instance profile / env-var-based AWS auth (no
--                   credentials_encrypted needed).
--
-- 'azure-keyvault'  Azure Key Vault via @azure/keyvault-keys. Tier 2.
--                   config: {vault_url, key_name, key_version?}.
--                   credentials: {tenant_id, client_id, client_secret}
--                   OR rely on managed identity.
--
-- 'gcp-kms'         GCP Cloud KMS via @google-cloud/kms. Tier 2.
--                   config: {project_id, location, key_ring, key_name,
--                   key_version?}. credentials: {service_account_json}
--                   OR rely on GCE metadata service.
--
-- 'hashicorp-vault' Vault transit engine via HTTPS API (no SDK; raw
--                   HTTP client). Tier 2. config: {vault_addr,
--                   transit_path, key_name, namespace?}. credentials:
--                   {token, token_renewable?} -- typically AppRole-
--                   issued. Critical for on-prem and EU privacy-first
--                   deployments (Hetzner / OVHcloud / Scaleway hosts).
--
-- PKCS#11 HSM (YubiHSM, Thales, Entrust) is intentionally NOT in this
-- list for R3d-4. The provider interface (services/key-wrapping-providers/
-- base.js, commit 4 of this phase) is designed so PKCS#11 plugs in
-- cleanly later. Adding it requires native bindings and hardware
-- verification not feasible in this phase's scope.
--
-- IS_DEFAULT
--
-- Exactly one row at a time can have is_default = 1, enforced by the
-- partial UNIQUE index below. New backups use the default. Operators
-- rotating the default to a new provider should mark the new row
-- is_default=1 and clear the old row's flag in the same transaction;
-- the existing row stays in the table (enabled=1 typically) so old
-- backups can still unwrap their DEKs.
--
-- ENABLED
--
-- Disabling a provider (enabled=0) prevents it from being used for
-- new wrapping operations. Old backups whose key_wrapping.kek_reference
-- points at a disabled provider can still be UNWRAPPED for restore --
-- the provider row stays in the table; only new wraps are gated.
--
-- CREDENTIALS_ENCRYPTED
--
-- Same on-disk format as storage_destinations.credentials_encrypted:
-- AES-256-GCM (iv + tag + ciphertext) base64-encoded for TEXT column.
-- TIER1_ENCRYPTION_KEY is the wrapping key for THIS table too --
-- which creates a chicken-and-egg: env-var rows don't need credentials
-- (they ARE the env var), so they store NULL. Cloud rows store the
-- cloud auth credentials encrypted under TIER1_ENCRYPTION_KEY.
--
-- For air-gapped operators who want to eliminate TIER1_ENCRYPTION_KEY
-- entirely, the migration path is: cloud-KMS-encrypted DEKs only,
-- and cloud SDK auth via instance metadata (no credentials in DB).
-- That removes TIER1_ENCRYPTION_KEY from the security boundary
-- entirely. Documented in the R3d-4 PR description.
CREATE TABLE IF NOT EXISTS kms_providers (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL UNIQUE,
  provider_type TEXT NOT NULL CHECK (provider_type IN
    ('env-var', 'aws-kms', 'azure-keyvault', 'gcp-kms', 'hashicorp-vault')),
  config TEXT NOT NULL,
  credentials_encrypted TEXT,
  enabled INTEGER NOT NULL DEFAULT 1
    CHECK (enabled IN (0, 1)),
  is_default INTEGER NOT NULL DEFAULT 0
    CHECK (is_default IN (0, 1)),
  last_probe_at TEXT,
  last_probe_status TEXT
    CHECK (last_probe_status IS NULL OR last_probe_status IN ('ok', 'failed')),
  last_probe_error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_kms_providers_default
  ON kms_providers(is_default) WHERE is_default = 1;
CREATE INDEX IF NOT EXISTS idx_kms_providers_enabled
  ON kms_providers(enabled) WHERE enabled = 1;
CREATE INDEX IF NOT EXISTS idx_kms_providers_type
  ON kms_providers(provider_type);


-- ── R3d-4: RESTORE APPROVALS (two-person approval workflow) ──────────────
-- Implements operator-configurable two-person approval for v2 restore
-- operations. Three modes (configured in system_meta):
--
--   strict (default)            second admin must POST approval w/ a passkey (WebAuthn) assertion
--                                before the restore can execute
--
--   delayed-self-approval       second admin POST approval, OR the same
--                                admin can approve their own request
--                                after a configured window has elapsed
--                                (system_meta.restore_approval_window_hours,
--                                default 24)
--
--   disabled                    no two-person approval; first admin
--                                proceeds directly. R3d-2 chain integrity
--                                precondition still enforced. Intended
--                                for SOCs with single-admin operations
--                                where two-person would block all recovery.
--
-- LIFECYCLE
--
--   pending     just created; awaiting approval or expiration
--   approved    second admin (or self in delayed mode) approved
--   denied      explicitly denied by an admin
--   expired     pending past expires_at; never approved
--   consumed    restore actually executed using this approval
--
-- One approval record per restore request. After consumption, the same
-- approval record cannot be used again -- a re-restore requires a fresh
-- request. The chain_request_entry_id column links to the backup_chain
-- RESTORE_REQUEST entry once the restore consumes the approval, providing
-- a forensic chain anchor.
--
-- AUDIT NOTES
--
-- Soft references to user IDs (no FK to users table) -- consistent
-- with audit-trail tables that should persist even if user accounts
-- are later removed. Reason: SOC compliance reviews must reconstruct
-- "who approved what" even years later, regardless of personnel turnover.
--
-- client_ip_at_request and client_ip_at_approval are recorded for
-- forensic value (correlate against VPN logs, etc.); not used for
-- authorization.
-- R3d-5: backup_id is now nullable; an approval row targets EITHER a
-- local backup_id (the R3d-4-pt2 case) OR an external (source_id,
-- external_backup_id) pair (the R3d-5 external-restore case). The
-- table-level CHECK constraint enforces local-XOR-external at the
-- database layer so neither column combination can ever be in an
-- ambiguous or null/null state.
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
      ('second-person-passkey', 'delayed-self-passkey', 'disabled-mode-bypass')),
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

-- B6h B-3: Key-Operation Authorizations (KOA). An anchor-signed, single-use token
-- authorizing ONE destructive key operation (a rekey, a migration-import re-seal, or
-- a deployment reset). The running server mints it behind role + config-lock + a
-- hardware step-up, and the restore-approvals two-person gate (approval_id) must be
-- approved first. The offline rekey tool verifies the signature against
-- instance_identity.anchor_public alone -- no hardware, no running server -- then
-- consumes it in the same transaction as the operation (consumed_at is single-use).
-- The signature covers the canonical payload
-- id|op|key_op_ref|approval_id|requested_by_user_id|created_at|expires_at, so none of
-- those fields can be altered without invalidating it.
CREATE TABLE IF NOT EXISTS key_op_authorizations (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  op TEXT NOT NULL
    CHECK (op IN ('rekey', 'migration-import', 'deployment-reset')),
  key_op_ref TEXT NOT NULL,
  approval_id TEXT NOT NULL,
  requested_by_user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  anchor_public_fingerprint TEXT NOT NULL,
  signature TEXT NOT NULL,
  consumed_at TEXT,
  consumed_context TEXT,
  CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX IF NOT EXISTS idx_key_op_authorizations_approval
  ON key_op_authorizations(approval_id);
CREATE INDEX IF NOT EXISTS idx_key_op_authorizations_unconsumed
  ON key_op_authorizations(op, key_op_ref) WHERE consumed_at IS NULL;

-- Data-subject erasure requests (dual control: an admin requests, a second
-- admin approves, and on approval the erasure executes). Mirrors the
-- restore_approvals idiom -- plain user-id columns, no FK -- so a user row that
-- is later tombstoned by an erasure does not cascade this request away. Status
-- lifecycle: pending -> approved/rejected, and approved -> executed.
CREATE TABLE IF NOT EXISTS data_subject_erasure_requests (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  subject_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected', 'executed')),
  approved_by TEXT,
  approved_at TEXT,
  executed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_data_subject_erasure_requests_subject
  ON data_subject_erasure_requests(subject_id);
CREATE INDEX IF NOT EXISTS idx_data_subject_erasure_requests_status
  ON data_subject_erasure_requests(status);


-- ── Audit Trail (immutable) ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT DEFAULT (datetime('now')),
  user_id TEXT REFERENCES users(id),
  event_type TEXT NOT NULL,
  detail TEXT,
  ip_address TEXT,
  -- CEF formatted version for SIEM streaming
  cef_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);

-- ── Audit Log Integrity: signed checkpoints (B5a) ────────────────────────
-- The audit_log hash chain (audit_log.hash / .prev_hash) is established and
-- backfilled by audit-chain.migrateAuditChain() during initDb, which also
-- installs the audit_log append-only triggers AFTER the backfill. The two
-- tables below are created here (always-run, never backfilled): the signed
-- checkpoint ledger that notarizes the chain head, and the dedicated Ed25519
-- key family that signs it (kept separate from the backup/forensic chain keys
-- so one custody chain's key compromise cannot affect another).

CREATE TABLE IF NOT EXISTS audit_chain_checkpoint (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  head_id INTEGER NOT NULL,
  head_hash TEXT NOT NULL,
  entry_count INTEGER NOT NULL,
  signature TEXT NOT NULL,
  signing_key_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Append-only: the checkpoint ledger is never updated or deleted.
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

CREATE INDEX IF NOT EXISTS idx_audit_chain_checkpoint_head ON audit_chain_checkpoint(head_id);

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

-- ── Fuse Counter (anti-rollback) ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS system_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- B6h A-7: node-local state that must NOT replicate to standbys (excluded in
-- ha-cdc DEFAULT_EXCLUDE_TABLES). Holds shared_kek_sealed -- the replicated-domain
-- KEK sealed to THIS node's hardware, reloaded fail-closed on boot. fuse_high_water
-- and deployment_mode relocate here in later B6h phases.
CREATE TABLE IF NOT EXISTS node_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- v0.0.24 tables
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  user TEXT,
  action TEXT NOT NULL,
  ip TEXT,
  method TEXT,
  reason TEXT,
  user_agent TEXT
);

CREATE TABLE IF NOT EXISTS general_certifications (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  issuer TEXT,
  earned_date TEXT,
  expires_date TEXT,
  analyst_id TEXT,
  verification_url TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS routing_overrides (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analyst_id TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'reduced_load',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT
);

CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- ticket_actions and ticket_assignments are defined further down with the
-- canonical richer shape (FK CASCADE, status CHECK constraint, indexes).
-- See the "R0: ROUTING / SOAR / SOC TICKET FLOW" section.

CREATE TABLE IF NOT EXISTS peer_sessions (
  id TEXT PRIMARY KEY,
  helper_id TEXT,
  seeker_id TEXT,
  duration_min INTEGER,
  rating INTEGER,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS analyst_baselines (
  analyst_id TEXT PRIMARY KEY,
  cognitive_load REAL,
  task_switching REAL,
  queue_pressure REAL,
  response_latency REAL,
  break_compliance REAL,
  shift_overtime REAL,
  established_at TEXT,
  sample_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS analyst_impacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analyst_id TEXT,
  type TEXT,
  description TEXT,
  recorded_at TEXT DEFAULT (datetime('now'))
);

-- B5d1: analyst-private data architecture --------------------------------
-- Per-analyst burnout detail is sealed to the analyst's own public key so
-- the server can write it but never read it back. The server's aggregate
-- and routing needs are met by the de-identified store and the metric-free
-- routing cap, not by reading the sealed per-analyst data.

CREATE TABLE IF NOT EXISTS analyst_keys (
  analyst_id TEXT PRIMARY KEY REFERENCES users(id),
  public_key TEXT NOT NULL,
  algo TEXT NOT NULL DEFAULT 'x25519-sealedbox',
  key_version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'erased')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS analyst_key_recovery_wraps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analyst_id TEXT NOT NULL REFERENCES users(id),
  factor TEXT NOT NULL CHECK (factor IN ('prf_primary', 'prf_backup', 'recovery_code')),
  wrapped_sk BLOB NOT NULL,
  label TEXT,
  key_version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_analyst_key_recovery_wraps_analyst
  ON analyst_key_recovery_wraps (analyst_id);

CREATE TABLE IF NOT EXISTS analyst_private_data (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analyst_id TEXT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL CHECK (kind IN ('reading', 'interpretation')),
  ciphertext BLOB NOT NULL,
  key_version INTEGER NOT NULL DEFAULT 1,
  recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_analyst_private_data_owner
  ON analyst_private_data (analyst_id, kind, recorded_at);

CREATE TABLE IF NOT EXISTS analyst_metrics_deidentified (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  team_tag TEXT,
  shift_tag TEXT,
  signal TEXT NOT NULL,
  value REAL NOT NULL,
  recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_analyst_metrics_deid_group
  ON analyst_metrics_deidentified (team_tag, shift_tag, signal, recorded_at);

-- Enrollment reconciliation: analysts the Lead/Admin has explicitly excluded
-- from the "scheduled but not enrolled" prompt (someone in the HR schedule who
-- is intentionally not monitored by FireAlive, e.g. not a SOC analyst). A row
-- here suppresses the prompt for that user and confirms they are never
-- aggregated; removing the row re-includes them. Enrollment itself remains the
-- monitoring gate -- this table only governs the reconciliation alert.
CREATE TABLE IF NOT EXISTS analyst_enrollment_exclusions (
  analyst_id TEXT PRIMARY KEY REFERENCES users(id),
  excluded_by TEXT REFERENCES users(id),
  reason TEXT,
  excluded_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- end B5d1 ----------------------------------------------------------------

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT,
  link_tab TEXT,
  link_params TEXT,
  read_at TEXT,
  delivered_in_app INTEGER NOT NULL DEFAULT 1,
  delivered_email INTEGER NOT NULL DEFAULT 0,
  email_delivery_status TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_notifications_recipient_unread
  ON notifications(recipient_id, read_at)
  WHERE read_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_notifications_recipient_created
  ON notifications(recipient_id, created_at DESC);

CREATE TABLE IF NOT EXISTS notification_preferences (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  in_app INTEGER NOT NULL DEFAULT 1,
  email INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, event_type)
);

CREATE TABLE IF NOT EXISTS peer_abuse_flags (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  -- target_type/target_id make a flag polymorphic (U2): a peer session uses
  -- session_id, a board post uses target_id, so session_id is now nullable.
  target_type TEXT NOT NULL DEFAULT 'peer_session' CHECK (target_type IN ('peer_session', 'board_post', 'lead_chat')),
  session_id TEXT,
  target_id TEXT,
  flagger_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  flagged_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  tier INTEGER NOT NULL CHECK (tier IN (1, 2, 3)),
  content_encrypted BLOB NOT NULL,
  flagger_ip TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at TEXT,
  resolved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  resolution_note TEXT,
  -- determination: the lead's structured verdict, recorded once at resolve
  -- alongside the rationale note. One-shot -- the resolve route 409-locks any
  -- second attempt, and there is no re-determination path by design (U4 PR 5).
  determination TEXT CHECK (determination IS NULL OR determination IN ('substantiated', 'not_substantiated', 'inconclusive'))
);

CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_unresolved
  ON peer_abuse_flags(tier, created_at DESC)
  WHERE resolved_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_flagged_user
  ON peer_abuse_flags(flagged_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_flagger
  ON peer_abuse_flags(flagger_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_target
  ON peer_abuse_flags(target_type, target_id);

-- Evidence Vault (U2). When a peer session or board post is flagged for abuse,
-- the flagged content plus surrounding context is sealed here, together with
-- BOTH parties' UUIDs and their pseudonyms captured at seal time (pseudonyms
-- rotate). This is the permanent forensic record: it has NO expiry and is not
-- swept, so it survives the board post being removed, expired, or deleted, and
-- it survives a flag being resolved. flagger_user_id and accused_user_id are
-- deliberately plain TEXT, NOT foreign keys, so the snapshot is immune to a
-- user later being deactivated or deleted. flag_id uses ON DELETE RESTRICT so
-- a flag that has sealed evidence cannot be deleted out from under it. The
-- tiered identity-reveal policy is applied at read time in the review API;
-- the vault itself always retains everything.
CREATE TABLE IF NOT EXISTS peer_abuse_evidence_vault (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  flag_id TEXT NOT NULL REFERENCES peer_abuse_flags(id) ON DELETE RESTRICT,
  target_type TEXT NOT NULL CHECK (target_type IN ('peer_session', 'board_post', 'lead_chat')),
  target_id TEXT,
  sealed_content_encrypted BLOB NOT NULL,
  context_encrypted BLOB,
  flagger_user_id TEXT NOT NULL,
  accused_user_id TEXT NOT NULL,
  flagger_pseudonym_at_seal TEXT,
  accused_pseudonym_at_seal TEXT,
  tier_at_seal INTEGER NOT NULL CHECK (tier_at_seal IN (1, 2, 3)),
  sealed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_evidence_vault_flag
  ON peer_abuse_evidence_vault(flag_id);

CREATE INDEX IF NOT EXISTS idx_evidence_vault_accused
  ON peer_abuse_evidence_vault(accused_user_id, sealed_at DESC);

CREATE INDEX IF NOT EXISTS idx_evidence_vault_target
  ON peer_abuse_evidence_vault(target_type, target_id);

-- peer_abuse_evidence_vault holds the only server-side copy of sealed abuse
-- evidence and is retained indefinitely. The vault is append-only with no delete
-- path of any kind, so evidence cannot be erased by any actor. A Team-Lead
-- review reads a case; it never removes the row. (U4 PR 5: eternal
-- retention.)
CREATE TRIGGER IF NOT EXISTS peer_abuse_evidence_vault_no_update
  BEFORE UPDATE ON peer_abuse_evidence_vault
  BEGIN SELECT RAISE(ABORT, 'peer_abuse_evidence_vault is append-only'); END;

CREATE TRIGGER IF NOT EXISTS peer_abuse_evidence_vault_no_delete
  BEFORE DELETE ON peer_abuse_evidence_vault
  BEGIN SELECT RAISE(ABORT, 'peer_abuse_evidence_vault is retained indefinitely (no delete)'); END;

-- ── Abuse-vault lifecycle chain (U4 PR 5-C) ──────────────────────────────────
-- Append-only, hash-chained, Ed25519-signed lifecycle ledger for the abuse
-- evidence vault. Records VAULT_SEALED for every sealed case plus
-- CHAIN_VERIFIED checks. Sealed cases are reviewed
-- by the Team Lead in the Management Console (Peer Conduct tab); the content
-- is decrypted only on the lead's device. The chain writes only the immutable
-- record and never holds decrypted content; the vault row itself is never
-- modified or deleted (see the vault's append-only triggers above), so eternal
-- retention holds.
--
-- Refs are plain TEXT (not foreign keys) so a ledger entry stands
-- independently of the rows it describes.
CREATE TABLE IF NOT EXISTS abuse_vault_chain (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  prev_hash TEXT,
  this_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('VAULT_SEALED','CHAIN_VERIFIED')),
  flag_id TEXT,
  request_ref TEXT,
  actor_user_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_abuse_vault_chain_flag ON abuse_vault_chain(flag_id);
CREATE INDEX IF NOT EXISTS idx_abuse_vault_chain_request ON abuse_vault_chain(request_ref);

CREATE TRIGGER IF NOT EXISTS abuse_vault_chain_no_update
  BEFORE UPDATE ON abuse_vault_chain
  BEGIN SELECT RAISE(ABORT, 'abuse_vault_chain is append-only'); END;

CREATE TRIGGER IF NOT EXISTS abuse_vault_chain_no_delete
  BEFORE DELETE ON abuse_vault_chain
  BEGIN SELECT RAISE(ABORT, 'abuse_vault_chain is append-only'); END;

-- Dedicated Ed25519 signing-key family for the chain (key separation -- distinct
-- from the report-signing, backup, and forensic families). Public keys are
-- stored plaintext, private Tier-1 encrypted and JIT-decrypted at sign time.
CREATE TABLE IF NOT EXISTS abuse_vault_chain_signing_keys (
  id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  private_key_encrypted TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_at TEXT
);

-- Abuse pattern detections (U2). The statistical detector writes one row per
-- detected pattern (repeat offender, retaliation, escalation) over flag
-- METADATA only: it keys entirely on user UUIDs and flag ids and never reads
-- decrypted content. subject_user_id and counterpart_user_id are plain TEXT
-- (not foreign keys) so a detection survives a user being deactivated, and
-- involved_flag_ids is a JSON array of the flag ids that make up the pattern.
-- The tiered identity-reveal policy is applied at read time in the review API.
CREATE TABLE IF NOT EXISTS peer_abuse_patterns (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  pattern_type TEXT NOT NULL CHECK (pattern_type IN ('repeat_offender', 'retaliation', 'escalation')),
  subject_user_id TEXT NOT NULL,
  counterpart_user_id TEXT,
  involved_flag_ids TEXT NOT NULL DEFAULT '[]',
  flag_count INTEGER NOT NULL DEFAULT 0,
  max_tier INTEGER NOT NULL CHECK (max_tier IN (1, 2, 3)),
  window_start TEXT NOT NULL,
  window_end TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'watch', 'urgent')),
  acknowledged_by TEXT,
  acknowledged_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_peer_abuse_patterns_subject
  ON peer_abuse_patterns(subject_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_peer_abuse_patterns_type
  ON peer_abuse_patterns(pattern_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_peer_abuse_patterns_unack
  ON peer_abuse_patterns(severity, created_at DESC) WHERE acknowledged_at IS NULL;

-- Abuse-review public-key registry (U3 PR D, repurposed for Team-Lead review).
-- Holds ONLY public keys. Each ACTIVE row is one Team Lead's public key, and
-- together the active rows form the recipient SET: flag content (peer, board)
-- is sealed to ALL active public keys at once by the flagger's client before
-- it leaves the device, so the server stores only opaque ciphertext it cannot
-- open, and any one lead can open a flag with their own private key. The
-- matching private keys live solely on each lead's device (in the Management
-- Console), never here. At least one active row is the gate that enables
-- flagging across the AC/MC: with no active key there is no one who could
-- decrypt a flag, so flagging stays disabled. Public material only -- no secret
-- is ever stored in this table. label is a human name for the key; fingerprint
-- is the 8-byte public-key fingerprint (hex) used for display and duplicate
-- rejection. registered_by is the admin or lead who registered the key (SET
-- NULL if that user is later removed).
CREATE TABLE IF NOT EXISTS abuse_review_keys (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  public_key BLOB NOT NULL,
  algo TEXT NOT NULL DEFAULT 'x25519-hkdf-sha256-aes256gcm',
  label TEXT,
  fingerprint TEXT,
  registered_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

-- The flagging gate and seal path read ALL active keys (the recipient set),
-- ordered newest first; this partial index serves that lookup.
CREATE INDEX IF NOT EXISTS idx_abuse_review_keys_active
  ON abuse_review_keys(created_at DESC)
  WHERE active = 1;

-- Peer Message Board (U2). Replaces the prototype team_config key-value board.
-- author_id is ALWAYS stored (the user UUID) even when the post is shown
-- anonymously — display_anonymous governs the UI only, never what is retained,
-- so a flagged post can always be attributed on the backend per the tier policy.
-- content_encrypted holds the post body under Tier-3 AES-256-GCM at rest.
-- Threading: a top-level post has parent_id IS NULL and thread_root_id IS NULL;
-- a reply sets parent_id to its immediate parent and thread_root_id to the
-- top-level ancestor, so a full thread is (id = :root OR thread_root_id = :root).
-- expires_at is stored (created_at + 7 days); the expiry sweep deletes expired
-- posts EXCEPT those with removed_pending_review = 1 or a vault seal. Deleting a
-- root cascades its replies via the thread_root_id self-reference.
CREATE TABLE IF NOT EXISTS peer_board_messages (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  display_anonymous INTEGER NOT NULL DEFAULT 1 CHECK (display_anonymous IN (0, 1)),
  category TEXT,
  content_encrypted BLOB NOT NULL,
  parent_id TEXT REFERENCES peer_board_messages(id) ON DELETE CASCADE,
  thread_root_id TEXT REFERENCES peer_board_messages(id) ON DELETE CASCADE,
  depth INTEGER NOT NULL DEFAULT 0,
  reactions TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  removed_pending_review INTEGER NOT NULL DEFAULT 0 CHECK (removed_pending_review IN (0, 1)),
  removed_at TEXT,
  restored_at TEXT,
  deleted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_peer_board_messages_thread
  ON peer_board_messages(thread_root_id, created_at);

CREATE INDEX IF NOT EXISTS idx_peer_board_messages_expiry
  ON peer_board_messages(expires_at)
  WHERE removed_pending_review = 0 AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_peer_board_messages_author
  ON peer_board_messages(author_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_peer_board_messages_removed
  ON peer_board_messages(removed_pending_review)
  WHERE removed_pending_review = 1;

CREATE TABLE IF NOT EXISTS ir_policies (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  policy_type TEXT NOT NULL CHECK (policy_type IN ('incident_response', 'playbook', 'runbook', 'policy', 'procedure')),
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  scenario_tags TEXT NOT NULL DEFAULT '[]',
  version INTEGER NOT NULL DEFAULT 1,
  uploaded_by TEXT NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT,
  -- Phase F4c: per-policy scenario replenishment configuration. JSON blob:
  --   { "mode": "threshold" | "scheduled" | "manual" | "disabled",
  --     "threshold_x": 1-50,             unplayed-pool floor that fires
  --                                       a replenishment job when crossed
  --                                       (only for mode=threshold)
  --     "batch_size": 1-20,              target_count_per_difficulty for
  --                                       replenishment jobs
  --     "scheduled_hour": 0-23,          required for mode=scheduled; the
  --                                       hour-of-day at which the cron
  --                                       fires the policy's batch
  --     "scheduled_days": ["sun"..."sat"], optional for mode=scheduled;
  --                                       array of 3-letter lowercase day
  --                                       codes. Empty/missing means every
  --                                       day. Server canonicalizes to
  --                                       sun-through-sat sequence and
  --                                       deduplicates.
  --     "auto_initial_upload": bool      whether to auto-enqueue an
  --                                       initial-batch generation job at
  --                                       policy upload time (storage in
  --                                       place; upload-time hook is a
  --                                       future F4c task)
  --   }
  -- Application layer validates the JSON shape (PATCH /api/ooda/policies/
  -- :id/replenishment-config in routes/ooda.js does the canonical
  -- validation); SQLite stores the blob verbatim. The hour+days schedule
  -- format was chosen over full cron expressions because SOC leads
  -- typically don't write cron and the daily/weekly schedules they
  -- actually want all map cleanly to (hour, optional days) — avoiding a
  -- cron-parser dependency and keeping the wizard UI a checkbox grid.
  -- Defaults represent "threshold mode, refill when <2 unplayed remain,
  -- batch size 5 per difficulty, auto-generate on upload" — the
  -- recommended setup that matches the F4c product brief.
  replenishment_config TEXT NOT NULL DEFAULT '{"mode":"threshold","threshold_x":2,"batch_size":5,"auto_initial_upload":true}'
);

CREATE INDEX IF NOT EXISTS idx_ir_policies_active
  ON ir_policies(uploaded_at DESC)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ir_policies_type
  ON ir_policies(policy_type, uploaded_at DESC)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ir_policies_hash
  ON ir_policies(content_hash);

-- ── OODA After-Action Reports ────────────────────────────────────────────
-- Real incident reports uploaded by leads/admins. Used as context for
-- LLM-driven scenario generation in F4b. Phase F4b precursor: was stored
-- as JSON blobs in team_config rows with key prefix 'ooda_aar_'.

CREATE TABLE IF NOT EXISTS ooda_aars (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  incident_date TEXT,
  lessons_learned TEXT,
  uploaded_by TEXT NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
  deleted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_ooda_aars_active
  ON ooda_aars(uploaded_at DESC)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ooda_aars_uploader
  ON ooda_aars(uploaded_by, uploaded_at DESC)
  WHERE deleted_at IS NULL;

-- ── OODA Generated Scenarios ─────────────────────────────────────────────
-- Decision-tree training scenarios. F4a generated these from hardcoded
-- templates; F4b generates them by calling aiProvider.generate() with
-- policy + AAR context. Phase F4b precursor: stored as JSON blobs in
-- team_config rows with key prefix 'ooda_scenario_'.
--
-- The full scenario JSON (nodes, choices, explanations) lives in 'tree'.
-- Scalar fields are denormalized for indexed listing/filtering.

CREATE TABLE IF NOT EXISTS ooda_scenarios (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  scenario_type TEXT NOT NULL CHECK (scenario_type IN (
    'ransomware', 'phishing', 'data_exfil', 'insider_threat',
    'apt', 'ddos', 'supply_chain', 'credential_compromise'
  )),
  difficulty TEXT NOT NULL CHECK (difficulty IN ('beginner', 'intermediate', 'advanced')),
  tree TEXT NOT NULL,
  node_count INTEGER NOT NULL DEFAULT 0,
  generated_by_provider TEXT,
  source_policy_ids TEXT NOT NULL DEFAULT '[]',
  created_by TEXT NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  archived_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_ooda_scenarios_active
  ON ooda_scenarios(created_at DESC)
  WHERE archived_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ooda_scenarios_type
  ON ooda_scenarios(scenario_type, difficulty, created_at DESC)
  WHERE archived_at IS NULL;

-- ── OODA Analyst Progress ────────────────────────────────────────────────
-- Per-analyst progress through individual scenarios. One row per
-- (user, scenario) pair. Phase F4b precursor: stored as JSON blobs in
-- team_config rows with key prefix 'ooda_progress_<userId>_<scenarioId>'.
--
-- nodes_completed is a JSON array of node IDs the analyst correctly
-- advanced through. Length gives completion percentage when divided by
-- the parent scenario's node_count.

CREATE TABLE IF NOT EXISTS ooda_progress (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scenario_id TEXT NOT NULL REFERENCES ooda_scenarios(id) ON DELETE CASCADE,
  nodes_completed TEXT NOT NULL DEFAULT '[]',
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  PRIMARY KEY (user_id, scenario_id)
);

CREATE INDEX IF NOT EXISTS idx_ooda_progress_user
  ON ooda_progress(user_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_ooda_progress_completed
  ON ooda_progress(user_id, completed_at DESC)
  WHERE completed_at IS NOT NULL;

-- ── OODA Scenario Generation Jobs (Phase F4c) ────────────────────────────
-- Background scenario-generation jobs for the IR Simulator. The lead's
-- policy upload triggers a multi-scenario generation (5 per difficulty by
-- default, configurable up to 20). Each LLM call takes 30-90s on the
-- internal model (Phi-4), so a 15-scenario job runs ~15 minutes — too long
-- for a foreground HTTP request. Jobs are persisted here so:
--   - The MC can poll job status to render a progress meter.
--   - A server restart mid-job recovers the job state and resumes
--     from where the worker left off (lead never has to manually
--     re-trigger).
--   - The audit trail records who enqueued each job, when, and via
--     which mode (initial_upload / manual / threshold / scheduled).
--
-- progress_json holds an array of per-difficulty progress entries:
--   [{"difficulty": "beginner", "completed": 4, "target": 5},
--    {"difficulty": "intermediate", "completed": 3, "target": 5},
--    {"difficulty": "advanced", "completed": 1, "target": 5}]
-- Updated incrementally as each scenario completes. completed counts
-- only successfully-generated-and-validated scenarios; if the LLM
-- produces malformed output for one slot, the worker retries up to
-- 3 times before marking the slot abandoned and moving on.
--
-- The mode column captures provenance:
--   initial_upload — auto-fired when a policy is uploaded
--   manual         — lead pressed "Generate more" on the policy
--   threshold      — analyst dipped below the configured threshold
--   scheduled      — daily scheduler tick fired this job

CREATE TABLE IF NOT EXISTS ooda_generation_jobs (
  id TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL REFERENCES ir_policies(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled')),
  mode TEXT NOT NULL CHECK (mode IN ('initial_upload', 'manual', 'threshold', 'scheduled')),
  target_count_per_difficulty INTEGER NOT NULL CHECK (target_count_per_difficulty BETWEEN 1 AND 20),
  progress_json TEXT NOT NULL DEFAULT '[]',
  enqueued_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  enqueued_at TEXT NOT NULL DEFAULT (datetime('now')),
  started_at TEXT,
  completed_at TEXT,
  error_message TEXT,
  provider TEXT
);

-- Worker reads this index to find next job to pick up: oldest queued first.
CREATE INDEX IF NOT EXISTS idx_ooda_generation_jobs_queued
  ON ooda_generation_jobs(enqueued_at ASC)
  WHERE status = 'queued';

-- MC's per-policy progress meter reads recent jobs by policy.
CREATE INDEX IF NOT EXISTS idx_ooda_generation_jobs_policy
  ON ooda_generation_jobs(policy_id, enqueued_at DESC);

-- Restart resumption: server start-up reads any rows still in 'running'
-- status (these were running when the server crashed/restarted) and
-- transitions them back to 'queued' so the worker picks them up again.
CREATE INDEX IF NOT EXISTS idx_ooda_generation_jobs_running
  ON ooda_generation_jobs(started_at)
  WHERE status = 'running';

-- ── Malware Scanner Integrations (Phase F4c) ─────────────────────────────
-- Multi-provider malware scanner integration table. Each row represents one
-- configured scanner. Multiple scanners can be configured simultaneously;
-- the dispatcher (services/integration-manager.js) selects which to call
-- based on the global scan_mode setting in team_config.
--
-- Phase F4c gates the IR Simulator (and any future LLM-input upload feature)
-- behind at least one configured-and-enabled scanner. Without a scanner the
-- upload routes return 503 MALWARE_SCANNER_REQUIRED.
--
-- Provider catalog (15 vendors):
--   On-prem signature:     clamav
--   Cloud reputation:      virustotal
--   Standalone analysis:   joe_sandbox, hybrid_analysis
--   Network sandbox:       fortinet_fortisandbox, palo_alto_wildfire
--   Vendor sandbox:        trellix_atd, trend_micro_ddan, kaspersky_sandbox
--   Cloud reputation/AI:   sophos_intelix, blackberry_cylance
--   Enterprise EDR:        crowdstrike_falcon, microsoft_defender, sentinelone,
--                          cisco_amp
--
-- Credentials are stored ENCRYPTED. The credentials_encrypted column holds a
-- JSON blob encrypted via services/encryption.js (AES-256-GCM with the same
-- master key the rest of the platform uses). The shape of the decrypted JSON
-- is provider-specific:
--   clamav:           {"host":"localhost","port":3310}
--   virustotal:       {"apiKey":"...","tier":"public"|"premium"}
--   crowdstrike:      {"clientId":"...","clientSecret":"...","baseUrl":"..."}
--   microsoft_defender:{"tenantId":"...","clientId":"...","clientSecret":"..."}
--   sentinelone:      {"siteUrl":"...","apiToken":"..."}
--   cisco_amp:        {"clientId":"...","apiKey":"...","region":"..."}
--   trellix_atd:      {"baseUrl":"...","apiKey":"..."}
--   sophos_intelix:   {"clientId":"...","clientSecret":"..."}
--   trend_micro_ddan: {"baseUrl":"...","apiKey":"..."}
--   kaspersky_sandbox:{"baseUrl":"...","apiKey":"..."}
--   ...
-- Provider modules in services/malware-scanners/<provider>.js are responsible
-- for parsing their own credential shape after decryption.
--
-- last_test_*  fields are touched by the MC's "Test Connection" button and
-- by each successful or failed inspection call. Lets the operations
-- dashboard show "last successful test: 3 minutes ago" without polling
-- the live integration.

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

-- Dispatcher reads this index to find the next scanner to try (lowest
-- priority value first; ties broken by configured_at). Partial index
-- excludes disabled rows so we never even consider them.
CREATE INDEX IF NOT EXISTS idx_malware_scanner_active
  ON malware_scanner_integrations(priority ASC, configured_at ASC)
  WHERE enabled = 1;

-- MC's status panel reads scanners by provider_type for "is CrowdStrike
-- configured?" checks.
CREATE INDEX IF NOT EXISTS idx_malware_scanner_provider
  ON malware_scanner_integrations(provider_type, enabled);

-- ── AI Provider Configuration ────────────────────────────────────────────
-- Per-feature routing for AI calls. One row per AI-using feature.
-- The dispatcher reads this to run each call on the internal local LLM.
--
-- Adding a new AI feature requires updating the feature_id CHECK list
-- below BEFORE any code calls aiProvider.generate('new_feature', ...).
-- Order of operations:
--
--   1. Add the new feature_id literal to the CHECK list below. SQLite
--      cannot drop or amend a CHECK constraint in place, so for a live
--      database the change ships as an idempotent migration block (see
--      the migration helper later in this file for the pattern: a
--      transactional rename-rebuild of ai_provider_config that copies
--      existing rows into a new table with the expanded CHECK).
--   2. Then add the code path that calls aiProvider.generate with the
--      new feature_id.
--
-- Reversing the order produces a hard error at the first generate()
-- call, because the dispatcher will try to upsert a row whose
-- feature_id violates the constraint and SQLite will reject it.

CREATE TABLE IF NOT EXISTS ai_provider_config (
  feature_id TEXT PRIMARY KEY CHECK (feature_id IN (
    'ir_simulator',
    'burnout_messages',
    'kb_synthesis',
    'ttx_enhancement',
    'troubleshooter',
    'kb_chat'
  )),
  provider TEXT NOT NULL DEFAULT 'internal' CHECK (provider IN (
    'internal'
  )),
  model_name TEXT,
  config_encrypted BLOB,
  max_tokens INTEGER NOT NULL DEFAULT 1024,
  temperature REAL NOT NULL DEFAULT 0.7,
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed both internal-LLM features to the internal (local) provider by
-- default, so the app's own AI is the out-of-box engine. INSERT OR IGNORE
-- never clobbers an admin's later choice. model_name records the local
-- default; internal-llm reports the actually-loaded model at runtime.
INSERT OR IGNORE INTO ai_provider_config (feature_id, provider, model_name)
  VALUES ('burnout_messages', 'internal', 'phi-4-Q4_K.gguf');
INSERT OR IGNORE INTO ai_provider_config (feature_id, provider, model_name)
  VALUES ('ir_simulator', 'internal', 'phi-4-Q4_K.gguf');

-- ── AI Inference Log ─────────────────────────────────────────────────────
-- Audit trail of every model call. Compliance requirement (GDPR + DORA).
-- Records token counts and metadata only; prompt/response content is NOT
-- stored here to avoid leaking Tier-3 burnout data into plain audit logs.

CREATE TABLE IF NOT EXISTS ai_inference_log (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  feature_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  model_name TEXT,
  user_id TEXT REFERENCES users(id),
  input_token_count INTEGER,
  output_token_count INTEGER,
  latency_ms INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('success', 'error', 'timeout', 'rate_limited')),
  error_message TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ai_inference_feature
  ON ai_inference_log(feature_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_inference_user
  ON ai_inference_log(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_inference_status
  ON ai_inference_log(status, created_at DESC);

-- ── AI Burnout-Message Caches (Phase N1b) ────────────────────────────────
-- Cache tables for background-precomputed AI burnout messages. The scheduler
-- generates these via aiProvider.generate('burnout_messages', ...) and the
-- read endpoints serve cached rows only — no inference in the request path.
-- A failed generation deletes the affected row, so a missing or expired row
-- is the signal that AI is currently unavailable for that item; the read path
-- then reports the reason from ai_inference_log. Rows are AI-generated only —
-- there is no template/source column because no canned content is ever stored.

-- Team intervention prompts (Tier-1 aggregate; not encrypted). Keyed by team
-- condition. Generated from team-level aggregates only — no individual analyst
-- is named or referenced. Which conditions are currently active is recomputed
-- live from team-health at read time, not stored here.
CREATE TABLE IF NOT EXISTS team_intervention_prompts (
  prompt_key TEXT PRIMARY KEY CHECK (prompt_key IN (
    'team_stressed', 'equity', 'automation', 'one_on_one', 'sustained_overcap'
  )),
  severity TEXT NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
  -- Factual condition label, e.g. "Team capacity strained"
  label TEXT NOT NULL,
  -- AI-generated advice as JSON:
  -- {full:{title,body,cite}, compact:{title,body,cite}, minimal:{title,body,cite}}
  content TEXT NOT NULL,
  model_name TEXT NOT NULL,
  kb_refs TEXT,
  generated_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

-- ── Helper Pay (Phase F5) ────────────────────────────────────────────────
-- Recognition system for analysts who help peers via skill-share, mentoring,
-- or knowledge-base contributions. Points accrue from peer ratings on real
-- sessions and can be redeemed for org-configured rewards (time off, gift
-- cards, donations). The ledger is append-only — reversals are negative
-- entries, never DELETEs — so the audit trail is preserved end to end.
--
-- Anti-gaming protections live in the helper-pay service (validation that
-- the rated session has real message activity, daily accrual caps, the
-- max_per_user_per_year cap on redemption_options below) rather than in
-- pure schema constraints, because they require cross-table queries that
-- CHECK clauses cannot express.

-- Append-only points ledger. Every accrual, redemption, reversal, and
-- admin adjustment lands here as a new row. balance_after is cached at
-- insert time so a per-user balance read is O(1) on the latest row.
CREATE TABLE IF NOT EXISTS helper_points_ledger (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL REFERENCES users(id),
  delta INTEGER NOT NULL,
  reason TEXT NOT NULL CHECK (reason IN (
    'rating_received',
    'mentor_session',
    'kb_contribution',
    'redemption',
    'reversal_fraud',
    'reversal_admin',
    'admin_adjustment'
  )),
  ref_type TEXT,                          -- 'peer_session_rating', 'redemption', etc.
  ref_id TEXT,                            -- id of the referenced entity
  balance_after INTEGER NOT NULL,
  notes TEXT,
  created_by TEXT REFERENCES users(id),   -- NULL for automatic accruals
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_helper_ledger_user
  ON helper_points_ledger(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_helper_ledger_reason
  ON helper_points_ledger(reason, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_helper_ledger_ref
  ON helper_points_ledger(ref_type, ref_id);

-- Peer-session ratings. The recipient of help rates the helper after a
-- session ends. UNIQUE on (session_id, rated_by_id) prevents double-rating.
-- Ratings drive Helper Pay accruals via the helper-pay service's
-- recordRating() handler, which writes a corresponding ledger entry.
CREATE TABLE IF NOT EXISTS peer_session_ratings (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  session_id TEXT NOT NULL REFERENCES peer_sessions(id) ON DELETE RESTRICT,
  rated_by_id TEXT NOT NULL REFERENCES users(id),
  rated_user_id TEXT NOT NULL REFERENCES users(id),
  stars INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
  comment TEXT,
  helpfulness_tags TEXT NOT NULL DEFAULT '[]',  -- JSON array, e.g. ["clear","patient"]
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  -- ── R3h (v1.0.34): anti-gaming fingerprint capture ──────────────────────
  rater_ip_hash TEXT,            -- SHA-256(req.ip), first 16 hex chars.
                                 -- NULL for rows inserted pre-R3h. The
                                 -- short hash supports clustering against
                                 -- the same rated_user_id without storing
                                 -- raw IPs in this table.
  rater_device_hash TEXT,        -- SHA-256(req.headers['user-agent']),
                                 -- first 16 hex chars. NULL pre-R3h.
                                 -- Coarse device fingerprint that
                                 -- complements IP for shared-network
                                 -- scenarios (multiple devices behind
                                 -- one NAT).
  flagged_sockpuppet INTEGER NOT NULL DEFAULT 0
    CHECK (flagged_sockpuppet IN (0, 1)),  -- set by detection logic in
                                           -- C8 when a rater hash cluster
                                           -- exceeds threshold for the
                                           -- same rated_user_id within
                                           -- a recent window.
  flagged_at TEXT,               -- timestamp when flagged_sockpuppet
                                 -- flipped to 1; null pre-flag.
  flagged_reason TEXT,           -- 'ip_cluster' | 'device_cluster' | 'both'
                                 -- — set in tandem with flagged_at; null
                                 -- pre-flag.
  UNIQUE (session_id, rated_by_id)
);

CREATE INDEX IF NOT EXISTS idx_peer_ratings_helper
  ON peer_session_ratings(rated_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_peer_ratings_session
  ON peer_session_ratings(session_id);

-- Per-org redemption catalog. Lead/admin configures what points can be
-- redeemed for and at what cost. max_per_user_per_year is an anti-gaming
-- cap so a single analyst cannot drain the budget by redeeming the same
-- option dozens of times.
CREATE TABLE IF NOT EXISTS helper_redemption_options (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  name TEXT NOT NULL,
  description TEXT,
  cost_points INTEGER NOT NULL CHECK (cost_points > 0),
  redemption_type TEXT NOT NULL CHECK (redemption_type IN (
    'time_off', 'gift_card', 'donation', 'other'
  )),
  approval_required INTEGER NOT NULL DEFAULT 1,
  active INTEGER NOT NULL DEFAULT 1,
  max_per_user_per_year INTEGER,                 -- NULL = unlimited
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_by TEXT REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_redemption_options_active
  ON helper_redemption_options(active, redemption_type);

-- Redemption requests. cost_points is copied from the option at request
-- time so a later catalog price change does not retroactively alter the
-- redemption cost. ledger_id points at the ledger entry that debited the
-- points; NULL until approval (lazy debit — points stay liquid in the
-- analyst's balance until a lead approves the redemption, at which point
-- the service writes the ledger entry and stamps ledger_id here).
CREATE TABLE IF NOT EXISTS helper_redemptions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL REFERENCES users(id),
  option_id TEXT NOT NULL REFERENCES helper_redemption_options(id) ON DELETE RESTRICT,
  cost_points INTEGER NOT NULL CHECK (cost_points > 0),
  ledger_id TEXT REFERENCES helper_points_ledger(id),
  status TEXT NOT NULL CHECK (status IN (
    'requested', 'approved', 'denied', 'fulfilled', 'cancelled'
  )),
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  decided_at TEXT,
  decided_by TEXT REFERENCES users(id),
  decision_note TEXT,
  fulfilled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_redemptions_user
  ON helper_redemptions(user_id, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_redemptions_status
  ON helper_redemptions(status, requested_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════
-- R0: ROUTING / SOAR / SOC TICKET FLOW
-- Tables consumed by signal-collector (behavioral metrics) and the
-- Routing & SOAR feature (per-analyst capacity-aware ticket distribution).
-- Populated by the SOAR/ticketing platform integrations described in
-- FEATURE-GUIDE.md "Routing & SOAR" — write path lands when those
-- integrations connect.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ticket_actions (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ticket_id TEXT NOT NULL,
  action_type TEXT NOT NULL,  -- triage, comment, close, escalate, etc.
  category TEXT,              -- malware, phishing, intrusion, etc. (used by signal-collector for task-switching metric)
  response_time_min REAL,     -- minutes from ticket arrival to first action
  notes TEXT,
  external_action_id TEXT,    -- B5d1-F: stable id of the source platform's action event (via the activity-events push); NULL for internally-generated actions. Deduped by the partial UNIQUE index created in the initDb migration block.
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ticket_actions_analyst
  ON ticket_actions(analyst_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ticket_actions_ticket
  ON ticket_actions(ticket_id);

CREATE TABLE IF NOT EXISTS ticket_assignments (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  ticket_id TEXT NOT NULL,
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'closed', 'reassigned')),
  priority TEXT,
  category TEXT,
  capacity_score_at_assign INTEGER,  -- Snapshot of analyst's capacity_score at assignment time (audit trail for routing decisions)
  assigned_at TEXT DEFAULT (datetime('now')),
  closed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_ticket_assignments_analyst
  ON ticket_assignments(analyst_id, status);

CREATE INDEX IF NOT EXISTS idx_ticket_assignments_ticket
  ON ticket_assignments(ticket_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- R0: COMPLIANCE CONTROLS CATALOG
-- Framework-keyed catalog of compliance controls referenced by the
-- Compliance Report feature (FEATURE-GUIDE.md "Compliance"). Populated
-- by framework metadata loaders or the org's compliance team. Empty by
-- default — the report endpoint falls back to hardcoded defaults when
-- the table is empty for a queried framework.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS compliance_controls (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  framework TEXT NOT NULL,    -- 'NIST_CSF', 'ISO_27001', 'SOC_2', 'HIPAA', etc.
  control_id TEXT NOT NULL,   -- e.g. 'AC-1', 'A.5.1.1'; unique within framework
  name TEXT NOT NULL,
  description TEXT,
  category TEXT,              -- 'access_control', 'audit', 'incident_response', etc.
  required INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(framework, control_id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_controls_framework
  ON compliance_controls(framework);

-- ═══════════════════════════════════════════════════════════════════════════
-- R3a: TRAINING COMPLETIONS
-- Analyst-side submission of external training-module completions, per
-- FEATURE-GUIDE.md training section: "submits a completion report (link,
-- score, date) back into the AC". Distinct from the certificate workflow
-- (POST /api/training/certificates) — certificates are formal credential
-- documents (PDF uploads with verification codes) tracked per skill, while
-- completions are module-completion reports for external training platforms
-- (LetsDefend, HackTheBox, TryHackMe, CyberDefenders, SANS, Immersive Labs,
-- internal training). Both feed the analyst's gap display and contribute
-- to team-aggregate training metrics surfaced via the metrics collector.
-- Lead verification updates status from 'pending' to 'verified' or
-- 'rejected' the same way certificate verification works.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS training_completions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  module TEXT NOT NULL,
  platform TEXT NOT NULL,
  url TEXT,
  completion_date TEXT,
  score INTEGER,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'verified', 'rejected')),
  submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
  verified_at TEXT,
  verified_by TEXT REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_training_completions_user
  ON training_completions(user_id);
CREATE INDEX IF NOT EXISTS idx_training_completions_status
  ON training_completions(status);

-- ═══════════════════════════════════════════════════════════════════════════
-- R3b: GLOBAL DASHBOARD PUSH CONFIGURATION
-- Stores the configuration this Regional MC uses to push aggregate metrics
-- to a Global Dashboard Server (GD-Server). The GD-Server runs as a separate
-- backend (typically on port 4001) operated by the customer's CISO/VP, and
-- it receives aggregate region-level data from one or more MCs across the
-- enterprise. The MC-side data flow is push-only — the GD-Server NEVER
-- writes back to the MC.
--
-- Single-row table by convention (id=1), since each MC pushes to at most
-- one GD-Server. The CISO obtains the API key by calling POST /api/mc/register
-- on the GD-Server, then provides the key plus the GD endpoint URL to the
-- MC admin who fills it into the MC's Global Dashboard Push settings.
--
-- Push behavior: an MC-side service (services/gd-push.js, added in a later
-- commit) wakes on the configured interval, calls the canonical metrics
-- collector to get a fresh snapshot, transforms it into the shape the
-- GD-Server's /api/ingest/metrics endpoint expects, and posts it with the
-- API key. Result of each push is recorded in last_push_at, last_push_status,
-- and last_push_error so the admin can see whether pushes are succeeding.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS gd_push_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  endpoint_url TEXT,
  api_key_encrypted TEXT,
  push_interval_minutes INTEGER NOT NULL DEFAULT 15
    CHECK (push_interval_minutes >= 1 AND push_interval_minutes <= 1440),
  compliance_push_cadence_hours INTEGER NOT NULL DEFAULT 24
    CHECK (compliance_push_cadence_hours >= 1 AND compliance_push_cadence_hours <= 720),  -- R3g PR3: cadence for the separate _complianceTick(); default daily, 30 days max
  leaderboard_push_cadence_minutes INTEGER NOT NULL DEFAULT 15
    CHECK (leaderboard_push_cadence_minutes >= 1 AND leaderboard_push_cadence_minutes <= 1440),  -- R3h: cadence for the separate _leaderboardTick(); default 15 min, 24h max
  retry_max INTEGER NOT NULL DEFAULT 3 CHECK (retry_max >= 0 AND retry_max <= 10),
  retry_backoff_seconds INTEGER NOT NULL DEFAULT 30
    CHECK (retry_backoff_seconds >= 1 AND retry_backoff_seconds <= 3600),
  last_push_at TEXT,
  last_push_status TEXT
    CHECK (last_push_status IS NULL OR last_push_status IN ('success', 'failure', 'pending')),
  last_push_error TEXT,
  last_push_duration_ms INTEGER,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  -- R3g PR3 Phase 5 (C23): manual-CISO-approval handshake state
  --
  -- mc_id is the identifier the GD knows this MC by (UUID assigned at
  -- /api/mc/register time). The MC stores it locally so it can construct
  -- the path-bound URL /api/mc/<mc_id>/signing-key when submitting a key
  -- and so its push tick can correlate audit events on both sides.
  -- Required when api_key_encrypted is set; enforced by the gd-config.js
  -- PUT handler in C24, NOT by the schema (NULL allowed at the table
  -- level so an initial PUT that's only setting endpoint_url doesn't
  -- have to provide mc_id yet).
  --
  -- handshake_status tracks where the MC believes its trust relationship
  -- with the GD stands. 'none' on first install or after a wipe;
  -- 'pending_approval' the moment a stage+submit succeeds against the
  -- GD's C18 endpoint; 'approved' or 'rejected' after the C28 push tick
  -- polls the GD's C21 status endpoint and observes a transition. The
  -- value here is the MC's locally-observed status — a CISO who
  -- approves and then immediately rejects might see this column lag the
  -- real GD state by one push interval.
  --
  -- last_handshake_at is the timestamp of the most recent submit OR poll
  -- transition. Used for the MC operator UI to show "waiting since X"
  -- so the operator can chase out-of-band if approval is taking unusually
  -- long.
  --
  -- pending_signing_key_id is a SOFT reference to gd_push_signing_keys.id
  -- (not a hard FK, matching the rest of this codebase's
  -- cross-table-reference convention). NULL when no submission is in
  -- flight; populated with the staged key's local row id when C26's
  -- /rotate or C27's first-handshake stages a new key. C28's push tick
  -- polls the GD's status for THIS keyId and commits or rolls back
  -- locally. Application code (C25's gd-push-signing-keys.js stage/
  -- commit/rollback) is responsible for keeping this in sync with the
  -- underlying gd_push_signing_keys table.
  mc_id TEXT,
  handshake_status TEXT NOT NULL DEFAULT 'none'
    CHECK (handshake_status IN ('none', 'pending_approval', 'approved', 'rejected')),
  last_handshake_at TEXT,
  pending_signing_key_id INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed the singleton row in disabled state on first init. The singleton
-- pattern is enforced by the CHECK (id = 1) constraint above. PUTs to
-- /api/gd-config update this row in place.
INSERT OR IGNORE INTO gd_push_config (id, enabled, push_interval_minutes)
  VALUES (1, 0, 15);

-- ── R3g PR3: GD-PUSH SIGNING KEYS ────────────────────────────────────────
-- Ed25519 keypair used by this MC to sign every outbound push to its
-- connected GD. The signing payload format is the request body bytes
-- (canonical JSON) prefixed by the request timestamp, mirroring the
-- X-FA-Signature wire format documented in R3G-DETAILED-PLAN-v5.
--
-- Public key is plaintext (the GD needs to verify with it; no
-- confidentiality concern). Private key Tier-1 AES-256-GCM encrypted via
-- encryptConfig — same envelope used by chain_signing_keys and
-- gd_push_config.api_key_encrypted on this side, and by
-- backup_signing_keys for its private material.
--
-- DELIBERATELY SEPARATE FROM chain_signing_keys AND backup_signing_keys.
-- The MC-to-GD trust channel is a distinct cryptographic concern from
-- backup integrity or chain audit — a compromise of the GD-push key
-- MUST NOT compromise backup signatures or chain entries. Each key
-- lives in its own table, its own service module, its own in-memory
-- KeyObject. The cost is duplicated keypair-management boilerplate; the
-- security separation justifies it (same rationale as the chain vs
-- backup signing-key separation in R3d-2).
--
-- public_key_fingerprint mirrors backup_signing_keys.public_key_fingerprint
-- in format: SHA-256 hex of the Ed25519 SPKI DER encoding (64 chars).
-- Used both as the X-FA-Key-Fingerprint header value on outbound pushes
-- and as a lookup key on the GD side (signing_keys.public_key_fingerprint).
-- Same identifier appears in MC and GD logs.
--
-- ROTATION MODEL: same as chain_signing_keys / backup_signing_keys — one
-- active keypair at a time (is_active = 1), old keypairs retained with
-- is_active = 0 + rotated_out_at so a brief verification grace window
-- exists across rotations. Manual rotation only in v1.0.33; an automatic
-- schedule is an open question for a later phase.
CREATE TABLE IF NOT EXISTS gd_push_signing_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_key TEXT NOT NULL,                         -- PEM-encoded Ed25519 public key (SPKI)
  public_key_fingerprint TEXT NOT NULL,             -- SHA-256 hex of SPKI DER bytes (64 chars)
  private_key_encrypted TEXT NOT NULL,              -- Tier-1 AES-256-GCM JSON {iv, tag, ciphertext}
  is_active INTEGER NOT NULL DEFAULT 0
    CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_out_at TEXT,                              -- when is_active flipped 1 -> 0
  notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_gd_push_signing_keys_active
  ON gd_push_signing_keys(is_active) WHERE is_active = 1;

CREATE INDEX IF NOT EXISTS idx_gd_push_signing_keys_fingerprint
  ON gd_push_signing_keys(public_key_fingerprint);

-- ═══════════════════════════════════════════════════════════════════════════
-- U4: REPORT SIGNING + VERIFICATION
--
-- SOC-grade signing for every FireAlive-generated exportable report
-- (compliance reports, Report Engine output, helper-pay statements, and
-- abuse-flag submission reports). One instance-level Ed25519 keypair family
-- signs all report types: the public-key fingerprint is the cryptographic
-- instance identity and the config row 'instance_label' is the human-readable
-- one rendered on the watermark. report_verifications is a PERMANENT,
-- append-only record that backs the authenticated verify endpoint and the
-- abuse-report appeal path — an independent reviewer can confirm an accuser's
-- exported report is genuine and corresponds to a real submission, without the
-- server ever holding plaintext.
--
-- Mirrors the gd_push_signing_keys / chain_signing_keys key-management pattern.
-- report signing keys are a DISTINCT family from the forensic, backup,
-- chain, gd-push, and cloud-iac signing keys: a compromise of any one
-- family taints none of the others.
-- ═══════════════════════════════════════════════════════════════════════════

-- B5d3: gains the backup_signing_keys cross-deployment registration shape
-- (key_origin + registration metadata, private key relaxed nullable with an
-- XOR CHECK) so a foreign deployment's report-signing PUBLIC key can be
-- registered here and used to verify imported golden-baseline bundles.
CREATE TABLE IF NOT EXISTS report_signing_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_key TEXT NOT NULL,                         -- PEM-encoded Ed25519 public key (SPKI)
  public_key_fingerprint TEXT NOT NULL,             -- SHA-256 hex of SPKI DER bytes (64 chars)
  private_key_encrypted TEXT,                       -- Tier-1 AES-256-GCM JSON {iv, tag, ciphertext}.
                                                    -- NULL for key_origin='external-registered'
                                                    -- (we have only the public part of foreign
                                                    -- deployments' keys).
  is_active INTEGER NOT NULL DEFAULT 0
    CHECK (is_active IN (0, 1)),
  key_origin TEXT NOT NULL DEFAULT 'local-generated'
    CHECK (key_origin IN ('local-generated', 'external-registered')),
  registered_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
                                                    -- who pasted/registered the foreign public
                                                    -- key (NULL for local-generated rows).
  registered_at TEXT,                               -- when registered (NULL for local-generated).
  key_label TEXT,                                   -- operator-friendly description for
                                                    -- external-registered keys (e.g.
                                                    -- "prod-east deployment, key from
                                                    -- 2026-06-09").
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  rotated_out_at TEXT,                              -- when is_active flipped 1 -> 0
                                                    -- OR when an external-registered key
                                                    -- was revoked.
  notes TEXT,
  -- Local-generated keys MUST have a private key (we created it ourselves).
  -- External-registered keys MUST NOT have a private key (we only have the
  -- public part of a foreign deployment's keypair), MUST be inactive
  -- (verification-only, never used for signing), and MUST carry registration
  -- metadata (who/when, for audit).
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

-- Permanent, append-only verification record. One row per signed report.
-- subject_ref is the report's own id (compliance / report_engine / helper_pay)
-- or the flag_id (abuse_flag). signed_payload_sha256 is the SHA-256 of the
-- signed material: the produced PDF/DOCX bytes for server-side reports, or the
-- canonical data payload for client-side abuse reports (which never contains
-- plaintext — only a content hash binding the export to the sealed vault
-- entry). metadata_json holds content-blind metadata only.
CREATE TABLE IF NOT EXISTS report_verifications (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  report_type TEXT NOT NULL
    CHECK (report_type IN ('compliance', 'report_engine', 'helper_pay', 'abuse_flag')),
  subject_ref TEXT NOT NULL,
  signed_payload_sha256 TEXT NOT NULL,              -- 64-char SHA-256 hex of the signed material
  signature TEXT NOT NULL,                          -- base64 Ed25519 signature
  key_fingerprint TEXT NOT NULL,                    -- report_signing_keys.public_key_fingerprint
  instance_label TEXT NOT NULL,                     -- snapshot of config 'instance_label' at sign time
  signed_at TEXT NOT NULL DEFAULT (datetime('now')),
  metadata_json TEXT                                -- content-blind metadata only (never plaintext)
);

CREATE INDEX IF NOT EXISTS idx_report_verifications_hash
  ON report_verifications(signed_payload_sha256);

CREATE INDEX IF NOT EXISTS idx_report_verifications_subject
  ON report_verifications(report_type, subject_ref);

-- report_verifications is PERMANENT and append-only: it backs the abuse-report
-- appeal/verify path and must outlive every other record. No update, no delete.
CREATE TRIGGER IF NOT EXISTS report_verifications_no_update
  BEFORE UPDATE ON report_verifications
  BEGIN SELECT RAISE(ABORT, 'report_verifications is append-only'); END;

CREATE TRIGGER IF NOT EXISTS report_verifications_no_delete
  BEFORE DELETE ON report_verifications
  BEGIN SELECT RAISE(ABORT, 'report_verifications is permanent (no delete)'); END;

-- Human-readable instance label rendered on report watermarks. Set at
-- provisioning time; the report-signing public-key fingerprint is the
-- cryptographic identity, this is the human one.
INSERT OR IGNORE INTO config (key, value)
  VALUES ('instance_label', 'FireAlive Instance (unconfigured)');

-- ═══════════════════════════════════════════════════════════════════════════
-- R3c: HR SCHEDULING PLATFORM CONFIGURATION
-- Stores the configuration this MC uses to sync analyst work-schedule data
-- with an external HR scheduling platform — UKG/Kronos, Workday, ADP,
-- BambooHR, or Manual mode where FireAlive itself is the system of record.
--
-- The MC is the master controller of upskilling hour scheduling. The HR
-- platform supplies each analyst's weekly work hours; the MC then schedules
-- upskilling time into the gaps and pushes the upskilling assignments
-- back to the HR platform as calendar events. Analysts have NO surface
-- on which to manipulate this — credentials are admin/lead-only and
-- this table never appears on the AC side.
--
-- Single-row table by convention (id=1) following the gd_push_config
-- pattern. One platform credential set serves the whole tenant; each
-- adapter under server/services/scheduling-platforms/ uses these
-- credentials as a service account that can read every analyst's schedule
-- and write upskilling events back. Per-analyst tokens were considered
-- and rejected — analysts could revoke or alter their own tokens to
-- dodge upskilling assignments, which would defeat the lead's authority
-- over the schedule.
--
-- Sync behavior: an MC-side service (services/scheduling-platforms/*,
-- added in later commits) wakes on the configured interval, calls the
-- selected adapter's pullAvailability() to refresh per-analyst hours,
-- and calls pushSchedule() to send back any newly-assigned upskilling
-- events. Result of each sync recorded in last_sync_at, last_sync_status,
-- and last_sync_error so the lead can see whether syncs are succeeding.
-- consecutive_failures backs a circuit breaker that auto-disables the
-- sync after sustained failure (matching the gd-push.js pattern).
--
-- credentials_encrypted is a Tier-1 encrypted blob (AES-256-GCM, key
-- from FIREALIVE_DB_KEY env var). Its plaintext shape varies per
-- platform — for Workday it is JSON {tenantUrl, clientId, clientSecret,
-- refreshToken}; for BambooHR it is {subdomain, apiKey}; for UKG it is
-- {tenantUrl, username, password}; for ADP it is {clientId, clientSecret,
-- certPem, certKeyPem}; for Manual it is null. The adapter modules
-- understand their own credential shape; the table treats it opaquely.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS scheduling_platform_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  platform TEXT
    CHECK (platform IS NULL OR platform IN ('ukg_kronos', 'workday', 'adp', 'bamboohr', 'manual')),
  endpoint_url TEXT,
  credentials_encrypted TEXT,
  sync_interval_minutes INTEGER NOT NULL DEFAULT 60
    CHECK (sync_interval_minutes >= 5 AND sync_interval_minutes <= 1440),
  retry_max INTEGER NOT NULL DEFAULT 3 CHECK (retry_max >= 0 AND retry_max <= 10),
  retry_backoff_seconds INTEGER NOT NULL DEFAULT 30
    CHECK (retry_backoff_seconds >= 1 AND retry_backoff_seconds <= 3600),
  last_sync_at TEXT,
  last_sync_status TEXT
    CHECK (last_sync_status IS NULL OR last_sync_status IN ('success', 'failure', 'pending')),
  last_sync_error TEXT,
  last_sync_duration_ms INTEGER,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed the singleton row in disabled state on first init. The singleton
-- pattern is enforced by the CHECK (id = 1) constraint above. PUTs to
-- /api/scheduling/config update this row in place.
INSERT OR IGNORE INTO scheduling_platform_config (id, enabled, sync_interval_minutes)
  VALUES (1, 0, 60);

-- ═══════════════════════════════════════════════════════════════════════════
-- R3c: ANALYST AVAILABILITY (per-week, per-user)
-- The output of HR scheduling sync. Each row records one analyst's
-- availability for one week, expressed as a JSON slots map keyed by
-- day-of-week. The auto-assigner reads these rows to find gaps where
-- it can schedule upskilling blocks for that analyst that week.
--
-- slots_json shape:
--   {
--     "monday":    [{"start":"09:00","end":"17:00"}],
--     "tuesday":   [{"start":"09:00","end":"12:00"},{"start":"13:00","end":"17:00"}],
--     "wednesday": [{"start":"09:00","end":"17:00"}],
--     "thursday":  [{"start":"09:00","end":"17:00"}],
--     "friday":    []
--   }
--
-- An empty array for a day means the analyst is unavailable that day.
-- A missing day key means the same as an empty array. Times are local
-- to the analyst's working timezone (the auto-assigner stays in that
-- timezone — no UTC conversion).
--
-- UNIQUE (user_id, week_start) lets the sync service upsert via
-- ON CONFLICT DO UPDATE. One availability row per user per week,
-- replaced wholesale on each successful sync rather than incrementally
-- merged. Wholesale replacement is the right semantics: the HR
-- platform is the source of truth, so if an analyst's schedule
-- changes there, the next sync reflects it fully.
--
-- source_platform records which adapter wrote the row, so the lead
-- can audit "where did this availability data come from" via the
-- per-row metadata. Manual mode rows have source_platform='manual'
-- and are written by the route layer's PUT /api/scheduling/availability
-- handler rather than by an adapter pull.
--
-- last_synced_at is the wall-clock timestamp of the most recent
-- write to this row, distinct from updated_at (SQLite trigger-managed)
-- so the lead's status panel can show "last synced 23 minutes ago"
-- without confusion if a manual edit also touched the row.
--
-- ANONYMITY MODEL: This table is keyed by user_id (the UUID FK to
-- users.id). It does NOT carry email, real name, or any direct-identity
-- field. Email is used only at sync time as a silent join key by the HR
-- adapters to translate a Workday/UKG/ADP/BambooHR employee record into
-- a users.id; once that translation happens, every downstream flow
-- (auto-assigner, lead's status panel, GD aggregate views) operates on
-- user_id and pseudonym only. Availability data thus lives behind the
-- same pseudonym wall as burnout metrics — an attacker who somehow
-- exfiltrated this table would learn schedules-by-UUID, not
-- schedules-by-person. See the email column ANONYMITY MODEL note in
-- the initDb() migration block for the full contract on email handling.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS analyst_availability (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  week_start TEXT NOT NULL,
  slots_json TEXT NOT NULL,
  source_platform TEXT
    CHECK (source_platform IS NULL OR source_platform IN ('ukg_kronos', 'workday', 'adp', 'bamboohr', 'manual')),
  last_synced_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (user_id, week_start)
);

CREATE INDEX IF NOT EXISTS idx_analyst_availability_week_start
  ON analyst_availability(week_start);
CREATE INDEX IF NOT EXISTS idx_analyst_availability_user
  ON analyst_availability(user_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- R3d: EXTERNAL RESTORE SOURCES (compromise-recovery backup sources)
-- One row per configured external backup source. The lead/admin sets up
-- sources at deployment time (e.g. "Production NAS", "DR S3 bucket",
-- "SFTP failover") and picks one per restore operation. Each row holds
-- two distinct encrypted blobs:
--
--   credentials_encrypted     — Tier-1 AES-256-GCM JSON object holding
--                               per-source-type AUTHENTICATION credentials
--                               (how to reach the source). Per-type shape:
--
--     network_share (SMB):    {host, share, username, password, domain?}
--     nas (NFS):              {host, export_path, mount_options?}
--                              (NFS commonly has no auth; can be empty {})
--     s3:                     {region, bucket, accessKeyId, secretAccessKey,
--                              sessionToken?}
--     azure_blob:             {accountName, accountKey OR sasToken,
--                              containerName}
--     sftp:                   {host, port?, username, password OR privateKey}
--
--   backup_decryption_key_encrypted
--                             — Tier-1 AES-256-GCM blob holding the
--                               BACKUP-PAYLOAD decryption key. Distinct
--                               from credentials_encrypted because the
--                               source's auth credentials are unrelated
--                               to the encryption key on the backup
--                               archive itself. Nullable for environments
--                               that store unencrypted backups (dev/test
--                               only — production deployments should set
--                               this); a NULL key means the orchestrator
--                               attempts to decompress without decryption.
--
-- Multi-row by design (multi-source). UNIQUE(name) so leads pick
-- distinct names. enabled flag allows soft-disable without deletion.
-- last_used_at lets the UI sort sources by recency.
--
-- The credentials decrypt only at adapter-call time inside the route
-- handler; the per-tick service path used for HR sync does not apply
-- to External Restore (restores are interactive, lead-triggered, never
-- recurring).
-- ═══════════════════════════════════════════════════════════════════════════

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

CREATE INDEX IF NOT EXISTS idx_external_restore_sources_enabled
  ON external_restore_sources(enabled);
CREATE INDEX IF NOT EXISTS idx_external_restore_sources_type
  ON external_restore_sources(source_type);

-- ────────────────────────────────────────────────────────────────────
-- B5D3: CONFIGURATION SNAPSHOTS (GOLDEN BASELINE)
-- Dedicated store for configuration snapshots, replacing the legacy
-- config_snapshot_% JSON rows that lived inside team_config (moved by the
-- B5d3 migration in initDb). A snapshot's payload is the canonical JSON
-- produced by services/golden-baseline.js captureBaseline(): the explicit
-- allowlisted config domain with secret material stripped. Signing keys,
-- identities, credentials, pseudonym mappings, analyst data, audit rows,
-- and operational state are never captured.
--
-- origin records why the snapshot exists:
--   manual      operator pressed Save Current
--   pre-revert  automatic safety snapshot taken before a revert
--   pre-import  automatic safety snapshot taken before a baseline import
-- Retention (config key config_snapshot_retention, default 20) prunes the
-- oldest auto-origin snapshots first and refuses a manual save when only
-- manual snapshots remain.
--
-- baseline_schema_version is the shape version of payload:
--   0   legacy team_config-era snapshot shape ({teamConfig, reportConfig,
--       slaConfig, notifConfig}) migrated out of team_config rows
--   1+  the golden-baseline domain shape (BASELINE_SCHEMA_VERSION in
--       services/golden-baseline.js)
-- sha256 is the SHA-256 hex of the stored payload bytes.
-- ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS config_snapshots (
  id TEXT PRIMARY KEY,                              -- short base36 id
  name TEXT NOT NULL,
  origin TEXT NOT NULL DEFAULT 'manual'
    CHECK (origin IN ('manual', 'pre-revert', 'pre-import')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  app_version TEXT,                                 -- app version at capture time
  baseline_schema_version INTEGER NOT NULL DEFAULT 1,
  payload TEXT NOT NULL,                            -- canonical JSON (see header above)
  sha256 TEXT NOT NULL                              -- SHA-256 hex of payload bytes
);

CREATE INDEX IF NOT EXISTS idx_config_snapshots_created
  ON config_snapshots(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_config_snapshots_origin
  ON config_snapshots(origin);

-- Retention cap consumed by the snapshot save path.
INSERT OR IGNORE INTO config (key, value)
  VALUES ('config_snapshot_retention', '20');

-- Migration bundle ledger (B5e Stage 4, FA-MIG1). One row per exported
-- deployment-migration bundle. The bundle itself is a file on disk (a composed
-- golden-baseline plus full-suite backup); this table records its metadata,
-- hashes, signing-key fingerprint, and lifecycle. Identity is NOT carried in
-- the ledger: a migration re-establishes instance identity fresh on import.
CREATE TABLE IF NOT EXISTS migration_bundles (
  id TEXT PRIMARY KEY,                              -- 'mig-' + uuid
  created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  format TEXT NOT NULL DEFAULT 'FA-MIG1',
  bundle_schema_version INTEGER NOT NULL DEFAULT 1,
  app_version TEXT,                                 -- app version at export time
  status TEXT NOT NULL DEFAULT 'building'
    CHECK (status IN ('building', 'complete', 'failed')),
  bundle_path TEXT,                                 -- composed FA-MIG1 archive on disk
  manifest_path TEXT,
  manifest_sig_path TEXT,
  bundle_sha256 TEXT,                               -- SHA-256 hex of the composed archive
  size_bytes INTEGER,
  baseline_sha256 TEXT,                             -- FA-GB1 golden-baseline component hash
  backup_ref TEXT,                                  -- full-suite backup component (dir or id)
  signing_key_fingerprint TEXT,                     -- Ed25519 signer fingerprint
  completed_at TEXT,
  error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_migration_bundles_created
  ON migration_bundles(created_at DESC);

`;

function initDb() {
  const { version, fuseCounter } = require('../lib/version');
  const db = getDb();

  // Execute schema
  db.exec(SCHEMA);

  // Migration (B5q): rename backup_destinations -> storage_destinations to
  // generalize the destination registry (it now holds the routing targets for
  // every artifact type, not just backups). The SCHEMA above creates an empty
  // storage_destinations shell on an upgraded database; this block moves the
  // real rows across by dropping that shell and renaming the old table, which
  // preserves every column (including the R3l C54 tags column) and lets SQLite
  // rewrite the backup_pushes foreign key on RENAME. PRAGMA-guarded and
  // count-guarded so a fresh database (no backup_destinations) and an
  // already-migrated database both no-op. foreign_keys is toggled off around
  // the rename, matching the peer_abuse_flags rebuild idiom below.
  try {
    const hasLegacyDestinations = db
      .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='backup_destinations'")
      .get();
    if (hasLegacyDestinations) {
      const migratedCount = db.prepare('SELECT COUNT(*) AS c FROM storage_destinations').get().c;
      if (migratedCount === 0) {
        db.exec('PRAGMA foreign_keys = OFF');
        db.exec('BEGIN TRANSACTION');
        try {
          db.exec('DROP TABLE storage_destinations');
          db.exec('ALTER TABLE backup_destinations RENAME TO storage_destinations');
          db.exec('DROP INDEX IF EXISTS idx_backup_destinations_enabled');
          db.exec('DROP INDEX IF EXISTS idx_backup_destinations_adapter');
          db.exec('CREATE INDEX IF NOT EXISTS idx_storage_destinations_enabled ON storage_destinations(enabled) WHERE enabled = 1');
          db.exec('CREATE INDEX IF NOT EXISTS idx_storage_destinations_adapter ON storage_destinations(adapter)');
          db.exec('COMMIT');
          console.log('B5q migration: renamed backup_destinations -> storage_destinations');
        } catch (renameTxnErr) {
          db.exec('ROLLBACK');
          throw renameTxnErr;
        } finally {
          db.exec('PRAGMA foreign_keys = ON');
        }
      } else {
        // storage_destinations already populated; drop the now-redundant legacy
        // table if it somehow lingers alongside it (defensive, should not occur).
        console.log('B5q migration: storage_destinations already present, leaving legacy backup_destinations untouched for manual review');
      }
    }
  } catch (b5qRenameErr) {
    console.error('B5q backup_destinations -> storage_destinations rename migration failed:', b5qRenameErr.message);
  }

  // Migration (B5q v3): storage_destination_routes gains an optional secondary
  // destination (a route stores a primary plus an optional secondary, both written
  // on every run). PRAGMA-guarded so a fresh database (which already has the column
  // from the CREATE above) no-ops, while a database created under the single-
  // destination schema (commit 20) is patched.
  try {
    const routeCols = db.prepare("PRAGMA table_info(storage_destination_routes)").all().map((c) => c.name);
    if (!routeCols.includes('secondary_destination_ref')) {
      db.exec('ALTER TABLE storage_destination_routes ADD COLUMN secondary_destination_ref TEXT');
    }
  } catch (b5qSecondaryErr) {
    console.error('B5q secondary route column migration failed:', b5qSecondaryErr.message);
  }

  // Migration (B5q Revision v4): storage_archive_segments is now artifact +
  // integrity-chain only; per-destination push state lives in the mutable
  // archive_segment_pushes table (created above). Drop the segment's destination
  // columns and pushed_at if an earlier schema (commits 20/24/28) created them.
  // DROP COLUMN is DDL and is permitted by the append-only triggers, which block
  // only UPDATE and DELETE. PRAGMA-guarded and idempotent.
  try {
    const segCols = db.prepare("PRAGMA table_info(storage_archive_segments)").all().map((c) => c.name);
    for (const col of ['destination_ref', 'dest_path', 'secondary_destination_ref', 'secondary_dest_path', 'pushed_at']) {
      if (segCols.includes(col)) {
        db.exec(`ALTER TABLE storage_archive_segments DROP COLUMN ${col}`);
      }
    }
  } catch (b5qSegPruneErr) {
    console.error('B5q Revision v4 segment-column prune failed:', b5qSegPruneErr.message);
  }

  // Migration (B5i): SDN posture debounce counters. The sdn_integrations table
  // gains per-integration probe debounce counters feeding the posture state
  // machine. PRAGMA-guarded so a fresh database (which already has them from the
  // CREATE above) no-ops; an upgraded database that predates them is patched.
  try {
    const sdnCols = db.prepare("PRAGMA table_info(sdn_integrations)").all().map((c) => c.name);
    if (!sdnCols.includes('consecutive_failures')) {
      db.exec('ALTER TABLE sdn_integrations ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0');
    }
    if (!sdnCols.includes('consecutive_successes')) {
      db.exec('ALTER TABLE sdn_integrations ADD COLUMN consecutive_successes INTEGER NOT NULL DEFAULT 0');
    }
  } catch (e) {
    console.error('B5i sdn posture-counter migration failed:', e.message);
  }

  // Migration (B5d1): drop retired analyst-private burnout tables. The
  // server-decryptable per-analyst burnout path is fully retired -- behavioral
  // detail now lives sealed on the analyst's own device (analyst_private_data)
  // and the only server-side views are the de-identified team aggregates.
  // analyst_signals, signal_readings, and analyst_interpretations are no longer
  // written or read by any code path, so they are dropped here. DROP IF EXISTS
  // is a no-op on fresh installs (the SCHEMA above no longer creates them) and
  // removes them from upgraded databases. The write-only analyst_id_encrypted
  // column on lighter_queue_requests is also retired: a lighter-queue request
  // stores no analyst identifier. PRAGMA-guarded so re-running initDb no-ops.
  try {
    db.exec('DROP TABLE IF EXISTS analyst_signals');
    db.exec('DROP TABLE IF EXISTS signal_readings');
    db.exec('DROP TABLE IF EXISTS analyst_interpretations');
    const lqCols = db.prepare("PRAGMA table_info(lighter_queue_requests)").all().map((c) => c.name);
    if (lqCols.includes('analyst_id_encrypted')) {
      db.exec('ALTER TABLE lighter_queue_requests DROP COLUMN analyst_id_encrypted');
      console.log('lighter_queue_requests migration (B5d1): dropped analyst_id_encrypted column');
    }
  } catch (e) {
    console.error('B5d1 retired-table drop migration failed:', e.message);
  }

  // ── Migration: peer board KV → peer_board_messages (U2) ──────────────────
  // The prototype board (retired v022-features route) stored each post as a
  // JSON blob in team_config under keys "peer_board_<id>". U2 introduces the
  // real peer_board_messages table; this one-time, idempotent backfill moves
  // existing posts into it (encrypting the body at rest) and removes the KV
  // rows. Once the rows are gone the block is a no-op on every later startup.
  //
  // Legacy posts marked anonymous stored no author id, so they cannot be
  // attributed if later flagged. To satisfy the NOT NULL author_id foreign key
  // while preserving the post content, those posts (and any whose recorded
  // author no longer exists) are assigned to a reserved, inactive
  // "legacy-anonymous" system account, created lazily only if needed. Only
  // pre-U2 anonymous posts are affected — every post created through the new
  // board carries the real UUID. Already-expired posts are dropped rather than
  // migrated, matching the old board's 7-day visibility window.
  try {
    const kvBoardRows = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'peer_board_%'").all();
    if (kvBoardRows.length > 0) {
      const { encryptTier3 } = require('../services/encryption');
      const SENTINEL_ID = 'legacy-anonymous';
      let sentinelEnsured = false;
      const ensureSentinel = () => {
        if (sentinelEnsured) return;
        db.prepare(
          "INSERT OR IGNORE INTO users (id, username, role, name, active, mfa_enrollment_required) " +
          "VALUES (?, ?, 'anon_author', 'Legacy Anonymous (system)', 0, 0)"
        ).run(SENTINEL_ID, SENTINEL_ID);
        sentinelEnsured = true;
      };
      const insertPost = db.prepare(
        "INSERT OR IGNORE INTO peer_board_messages " +
        "(id, author_id, display_anonymous, category, content_encrypted, parent_id, thread_root_id, depth, reactions, created_at, expires_at) " +
        "VALUES (?, ?, ?, ?, ?, NULL, NULL, 0, ?, ?, ?)"
      );
      const deleteKv = db.prepare("DELETE FROM team_config WHERE key = ?");
      const userExists = db.prepare("SELECT 1 FROM users WHERE id = ?");

      let migrated = 0;
      const runBoardMigration = db.transaction(() => {
        for (const row of kvBoardRows) {
          let msg = null;
          try { msg = JSON.parse(row.value); } catch (parseErr) { msg = null; }
          // Drop unreadable or contentless rows — they were never displayable.
          if (!msg || typeof msg.content !== 'string') { deleteKv.run(row.key); continue; }

          const createdAt = (typeof msg.createdAt === 'string' && msg.createdAt)
            ? msg.createdAt : new Date().toISOString();
          const expiresAt = new Date(new Date(createdAt).getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
          // Already past its 7-day window — drop like the old board did.
          if (new Date(expiresAt).getTime() <= Date.now()) { deleteKv.run(row.key); continue; }

          const anon = (msg.anonymous === undefined) ? true : !!msg.anonymous;
          let authorId = (!anon && typeof msg.authorId === 'string' && msg.authorId) ? msg.authorId : SENTINEL_ID;
          if (authorId !== SENTINEL_ID && !userExists.get(authorId)) authorId = SENTINEL_ID;
          if (authorId === SENTINEL_ID) ensureSentinel();

          const id = (typeof msg.id === 'string' && msg.id) ? msg.id : crypto.randomBytes(16).toString('hex');
          const category = (typeof msg.category === 'string') ? msg.category : null;
          const reactions = (msg.reactions && typeof msg.reactions === 'object')
            ? JSON.stringify(msg.reactions) : '{}';
          const ciphertext = encryptTier3(String(msg.content).slice(0, 4096));

          insertPost.run(id, authorId, anon ? 1 : 0, category, ciphertext, reactions, createdAt, expiresAt);
          deleteKv.run(row.key);
          migrated++;
        }
      });
      runBoardMigration();
      if (migrated > 0) {
        console.log(`peer board migration: moved ${migrated} KV post(s) into peer_board_messages`);
      }
    }
  } catch (boardMigErr) {
    // Non-fatal: leave the KV rows in place for a future attempt rather than
    // losing data. The transaction above rolls back on any error.
    console.error('peer board KV migration failed (non-fatal):', boardMigErr.message);
  }

  // ── Migration: peer_abuse_flags polymorphic targets (U2) ──────────
  // U2 lets a flag target a board post as well as a peer session, which means
  // adding target_type/target_id and relaxing session_id from NOT NULL (board
  // flags have no session). SQLite has no ALTER COLUMN, so existing pre-U2
  // tables are rebuilt: CREATE the canonical shape, copy rows (defaulting
  // target_type to 'peer_session'), DROP, RENAME, and recreate the indexes.
  // Foreign keys are toggled OFF for the rebuild and back ON afterward. Gated
  // on the target_type column being absent, so it is a no-op on fresh installs
  // (which already get the new shape from SCHEMA) and on migrated databases.
  try {
    const flagCols = db.prepare("PRAGMA table_info(peer_abuse_flags)").all();
    const hasTargetType = flagCols.some(c => c.name === 'target_type');
    if (!hasTargetType) {
      console.log('peer_abuse_flags migration (U2): rebuilding for polymorphic targets');
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        db.exec(`
          CREATE TABLE peer_abuse_flags_new (
            id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
            target_type TEXT NOT NULL DEFAULT 'peer_session' CHECK (target_type IN ('peer_session', 'board_post')),
            session_id TEXT,
            target_id TEXT,
            flagger_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            flagged_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
            tier INTEGER NOT NULL CHECK (tier IN (1, 2, 3)),
            content_encrypted BLOB NOT NULL,
            flagger_ip TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            resolved_at TEXT,
            resolved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
            resolution_note TEXT
          )
        `);
        const copied = db.prepare('SELECT COUNT(*) AS n FROM peer_abuse_flags').get().n;
        db.exec(`
          INSERT INTO peer_abuse_flags_new
            (id, target_type, session_id, target_id, flagger_user_id, flagged_user_id,
             tier, content_encrypted, flagger_ip, created_at, resolved_at, resolved_by, resolution_note)
          SELECT
            id, 'peer_session', session_id, NULL, flagger_user_id, flagged_user_id,
            tier, content_encrypted, flagger_ip, created_at, resolved_at, resolved_by, resolution_note
          FROM peer_abuse_flags
        `);
        db.exec('DROP TABLE peer_abuse_flags');
        db.exec('ALTER TABLE peer_abuse_flags_new RENAME TO peer_abuse_flags');
        // Recreate indexes (dropped with the old table), faithful to SCHEMA.
        db.exec('CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_unresolved ON peer_abuse_flags(tier, created_at DESC) WHERE resolved_at IS NULL');
        db.exec('CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_flagged_user ON peer_abuse_flags(flagged_user_id, created_at DESC)');
        db.exec('CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_flagger ON peer_abuse_flags(flagger_user_id, created_at DESC)');
        db.exec('CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_target ON peer_abuse_flags(target_type, target_id)');
        db.exec('COMMIT');
        console.log(`peer_abuse_flags migration (U2): rebuilt, preserved ${copied} flag(s)`);
      } catch (rebuildErr) {
        db.exec('ROLLBACK');
        throw rebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  } catch (flagMigErr) {
    console.error('peer_abuse_flags migration (U2) failed (non-fatal):', flagMigErr.message);
  }

  // ── Migration: peer_abuse_flags lead_chat target (U3 PR D) ──────────
  // U3 lets a flag target a lead-chat message in addition to a peer session or
  // board post. SQLite cannot ALTER a CHECK constraint, so an existing table is
  // rebuilt to widen target_type's CHECK to include 'lead_chat'. Gated on the
  // table's stored SQL already mentioning lead_chat, so it is a no-op on fresh
  // installs (whose canonical shape from SCHEMA already has it) and on already-
  // migrated databases. Rows are copied verbatim (their target_type is already
  // valid). Foreign keys toggle OFF for the rebuild and back ON afterward.
  try {
    const fRow = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='peer_abuse_flags'").get();
    if (fRow && fRow.sql && !fRow.sql.includes('lead_chat')) {
      console.log('peer_abuse_flags migration (U3): widening target_type to include lead_chat');
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        db.exec(`
          CREATE TABLE peer_abuse_flags_new (
            id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
            target_type TEXT NOT NULL DEFAULT 'peer_session' CHECK (target_type IN ('peer_session', 'board_post', 'lead_chat')),
            session_id TEXT,
            target_id TEXT,
            flagger_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            flagged_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
            tier INTEGER NOT NULL CHECK (tier IN (1, 2, 3)),
            content_encrypted BLOB NOT NULL,
            flagger_ip TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            resolved_at TEXT,
            resolved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
            resolution_note TEXT
          )
        `);
        const copied = db.prepare('SELECT COUNT(*) AS n FROM peer_abuse_flags').get().n;
        db.exec(`
          INSERT INTO peer_abuse_flags_new
            (id, target_type, session_id, target_id, flagger_user_id, flagged_user_id,
             tier, content_encrypted, flagger_ip, created_at, resolved_at, resolved_by, resolution_note)
          SELECT
            id, target_type, session_id, target_id, flagger_user_id, flagged_user_id,
            tier, content_encrypted, flagger_ip, created_at, resolved_at, resolved_by, resolution_note
          FROM peer_abuse_flags
        `);
        db.exec('DROP TABLE peer_abuse_flags');
        db.exec('ALTER TABLE peer_abuse_flags_new RENAME TO peer_abuse_flags');
        db.exec('CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_unresolved ON peer_abuse_flags(tier, created_at DESC) WHERE resolved_at IS NULL');
        db.exec('CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_flagged_user ON peer_abuse_flags(flagged_user_id, created_at DESC)');
        db.exec('CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_flagger ON peer_abuse_flags(flagger_user_id, created_at DESC)');
        db.exec('CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_target ON peer_abuse_flags(target_type, target_id)');
        db.exec('COMMIT');
        console.log(`peer_abuse_flags migration (U3): rebuilt, preserved ${copied} flag(s)`);
      } catch (rebuildErr) {
        db.exec('ROLLBACK');
        throw rebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  } catch (flagU3MigErr) {
    console.error('peer_abuse_flags migration (U3) failed (non-fatal):', flagU3MigErr.message);
  }

  // ── Migration: ai_provider_config provider CHECK (B5c2) ─────────────
  // FireAlive uses internal AI only. The provider CHECK is tightened to
  // 'internal' so no row can name an external provider. SQLite cannot ALTER a
  // CHECK constraint, so an existing table is rebuilt. Gated on the table's
  // stored SQL still naming an external provider ('anthropic'), so it is a
  // no-op on fresh installs (whose canonical shape from SCHEMA already has the
  // tightened CHECK) and on already-migrated databases. The feature_id CHECK
  // is preserved unchanged. Any row that named an external provider is reset
  // to 'internal' and its config_encrypted cleared (internal rows never had
  // one). Foreign keys toggle OFF for the rebuild and back ON afterward.
  try {
    const apRow = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='ai_provider_config'").get();
    if (apRow && apRow.sql && apRow.sql.includes('anthropic')) {
      console.log('ai_provider_config migration (B5c2): tightening provider CHECK to internal only');
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        db.exec(`
          CREATE TABLE ai_provider_config_new (
            feature_id TEXT PRIMARY KEY CHECK (feature_id IN (
              'ir_simulator',
              'burnout_messages',
              'kb_synthesis',
              'ttx_enhancement',
              'troubleshooter',
              'kb_chat'
            )),
            provider TEXT NOT NULL DEFAULT 'internal' CHECK (provider IN ('internal')),
            model_name TEXT,
            config_encrypted BLOB,
            max_tokens INTEGER NOT NULL DEFAULT 1024,
            temperature REAL NOT NULL DEFAULT 0.7,
            updated_by TEXT REFERENCES users(id),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
          )
        `);
        const copied = db.prepare('SELECT COUNT(*) AS n FROM ai_provider_config').get().n;
        db.exec(`
          INSERT INTO ai_provider_config_new
            (feature_id, provider, model_name, config_encrypted, max_tokens, temperature, updated_by, updated_at)
          SELECT
            feature_id, 'internal', model_name, NULL, max_tokens, temperature, updated_by, updated_at
          FROM ai_provider_config
        `);
        db.exec('DROP TABLE ai_provider_config');
        db.exec('ALTER TABLE ai_provider_config_new RENAME TO ai_provider_config');
        db.exec('COMMIT');
        console.log(`ai_provider_config migration (B5c2): rebuilt, preserved ${copied} feature row(s)`);
      } catch (apRebuildErr) {
        db.exec('ROLLBACK');
        throw apRebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  } catch (apMigErr) {
    console.error('ai_provider_config migration (B5c2) failed (non-fatal):', apMigErr.message);
  }

  // ── Migration: peer_abuse_flags.determination column (U4 PR 5) ──────
  // Adds the lead's structured verdict to existing databases. ALTER TABLE
  // ADD COLUMN is idempotent here: it runs only when the column is missing, so
  // it is a no-op on fresh installs (which get it from SCHEMA) and on already-
  // migrated databases. The column is nullable (NULL until a case is resolved);
  // allowed values are enforced by the SCHEMA CHECK on fresh installs and by the
  // resolve route on every database.
  try {
    const flagDetCols = db.prepare("PRAGMA table_info(peer_abuse_flags)").all().map(c => c.name);
    if (!flagDetCols.includes('determination')) {
      db.exec("ALTER TABLE peer_abuse_flags ADD COLUMN determination TEXT");
      console.log('peer_abuse_flags migration (U4): added determination column');
    }
  } catch (flagDetMigErr) {
    console.error('peer_abuse_flags determination migration (U4) failed (non-fatal):', flagDetMigErr.message);
  }

  // ── Migration: peer_abuse_evidence_vault lead_chat target (U3 PR D) ──
  // The vault mirrors a flag's target_type, so it must also accept 'lead_chat'
  // before lead-chat evidence can be sealed. Same widen-the-CHECK rebuild,
  // gated on the stored SQL already mentioning lead_chat. flag_id keeps its
  // ON DELETE RESTRICT; rows are copied verbatim; foreign keys toggle OFF.
  try {
    const vRow = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='peer_abuse_evidence_vault'").get();
    if (vRow && vRow.sql && !vRow.sql.includes('lead_chat')) {
      console.log('peer_abuse_evidence_vault migration (U3): widening target_type to include lead_chat');
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        db.exec(`
          CREATE TABLE peer_abuse_evidence_vault_new (
            id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
            flag_id TEXT NOT NULL REFERENCES peer_abuse_flags(id) ON DELETE RESTRICT,
            target_type TEXT NOT NULL CHECK (target_type IN ('peer_session', 'board_post', 'lead_chat')),
            target_id TEXT,
            sealed_content_encrypted BLOB NOT NULL,
            context_encrypted BLOB,
            flagger_user_id TEXT NOT NULL,
            accused_user_id TEXT NOT NULL,
            flagger_pseudonym_at_seal TEXT,
            accused_pseudonym_at_seal TEXT,
            tier_at_seal INTEGER NOT NULL CHECK (tier_at_seal IN (1, 2, 3)),
            sealed_at TEXT NOT NULL DEFAULT (datetime('now'))
          )
        `);
        const vCopied = db.prepare('SELECT COUNT(*) AS n FROM peer_abuse_evidence_vault').get().n;
        db.exec(`
          INSERT INTO peer_abuse_evidence_vault_new
            (id, flag_id, target_type, target_id, sealed_content_encrypted, context_encrypted,
             flagger_user_id, accused_user_id, flagger_pseudonym_at_seal, accused_pseudonym_at_seal,
             tier_at_seal, sealed_at)
          SELECT
            id, flag_id, target_type, target_id, sealed_content_encrypted, context_encrypted,
            flagger_user_id, accused_user_id, flagger_pseudonym_at_seal, accused_pseudonym_at_seal,
            tier_at_seal, sealed_at
          FROM peer_abuse_evidence_vault
        `);
        db.exec('DROP TABLE peer_abuse_evidence_vault');
        db.exec('ALTER TABLE peer_abuse_evidence_vault_new RENAME TO peer_abuse_evidence_vault');
        db.exec('CREATE INDEX IF NOT EXISTS idx_evidence_vault_flag ON peer_abuse_evidence_vault(flag_id)');
        db.exec('CREATE INDEX IF NOT EXISTS idx_evidence_vault_accused ON peer_abuse_evidence_vault(accused_user_id, sealed_at DESC)');
        db.exec('CREATE INDEX IF NOT EXISTS idx_evidence_vault_target ON peer_abuse_evidence_vault(target_type, target_id)');
        db.exec('COMMIT');
        console.log(`peer_abuse_evidence_vault migration (U3): rebuilt, preserved ${vCopied} record(s)`);
      } catch (vRebuildErr) {
        db.exec('ROLLBACK');
        throw vRebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  } catch (vaultU3MigErr) {
    console.error('peer_abuse_evidence_vault migration (U3) failed (non-fatal):', vaultU3MigErr.message);
  }

  // ── Migration: users role CHECK narrow -- retire abuse_reviewer (B5h3) ──
  // The independent 'abuse_reviewer' role is retired; abuse review returns to
  // the Team Lead on the MC. Any account still holding the role is reassigned
  // to 'lead', then the role CHECK is narrowed back to the four core roles.
  // SQLite cannot ALTER a CHECK, so the users table is rebuilt by DERIVING the
  // new DDL from the LIVE users CREATE and replacing only the table name and
  // the role CHECK -- no column or constraint drift. Foreign keys toggle OFF
  // for the rebuild and back ON afterward; foreign_key_check verifies no
  // orphaned child rows before COMMIT. The reassignment and the rebuild run in
  // one transaction. Gated on the stored users SQL STILL containing
  // 'abuse_reviewer' -- a no-op on fresh installs and already-narrowed bases.
  try {
    const uRow = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get();
    if (uRow && uRow.sql && uRow.sql.includes('abuse_reviewer')) {
      const wideCheck = "role IN ('analyst', 'lead', 'admin', 'developer', 'abuse_reviewer')";
      const narrowCheck = "role IN ('analyst', 'lead', 'admin', 'developer')";
      if (!uRow.sql.includes(wideCheck)) {
        throw new Error('users role CHECK clause not found in live schema; aborting rebuild to avoid corruption');
      }
      const ifNotExists = 'CREATE TABLE IF NOT EXISTS users';
      const plain = 'CREATE TABLE users';
      let newDdl;
      if (uRow.sql.startsWith(ifNotExists)) {
        newDdl = 'CREATE TABLE users_new' + uRow.sql.slice(ifNotExists.length);
      } else if (uRow.sql.startsWith(plain)) {
        newDdl = 'CREATE TABLE users_new' + uRow.sql.slice(plain.length);
      } else {
        throw new Error('unexpected users CREATE statement; aborting rebuild to avoid corruption');
      }
      newDdl = newDdl.replace(wideCheck, narrowCheck);
      console.log('users migration (B5h3): narrowing role CHECK to retire abuse_reviewer');
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        const reassigned = db.prepare("UPDATE users SET role = 'lead' WHERE role = 'abuse_reviewer'").run().changes;
        if (reassigned) console.log('users migration (B5h3): reassigned ' + reassigned + ' abuse_reviewer account(s) to lead');
        db.exec(newDdl);
        const copied = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
        db.exec('INSERT INTO users_new SELECT * FROM users');
        db.exec('DROP TABLE users');
        db.exec('ALTER TABLE users_new RENAME TO users');
        const fkViolations = db.prepare('PRAGMA foreign_key_check').all();
        if (fkViolations.length > 0) {
          throw new Error('foreign_key_check reported ' + fkViolations.length + ' violation(s) after users rebuild');
        }
        db.exec('COMMIT');
        console.log('users migration (B5h3): rebuilt, preserved ' + copied + ' user(s)');
      } catch (rebuildErr) {
        db.exec('ROLLBACK');
        throw rebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  } catch (userRoleMigErr) {
    console.error('users migration (B5h3) failed (non-fatal):', userRoleMigErr.message);
  }

  // ── Migration: users role CHECK swap -- retire developer for anon_author (B5h3) ──
  // The 'developer' role is retired. The only account that ever held it is the
  // lazily-created 'legacy-anonymous' system sentinel (the FK author-of-record
  // for anonymized posts); the seed never creates developers and no directory
  // group maps to one. Any row still on 'developer' is rewritten to 'anon_author'
  // -- a rights-less role that is in no route allow-list, so it can authorize
  // nothing. SQLite cannot ALTER a CHECK, so the table is rebuilt by DERIVING the
  // new DDL from the LIVE users CREATE and replacing only the table name and the
  // role CHECK. The role is remapped DURING the copy into the new table (a plain
  // UPDATE on the old table would violate its CHECK, which still forbids
  // 'anon_author', and SELECT * would carry the forbidden value across), so the
  // column list is taken from PRAGMA table_info and the role column is rewritten
  // in flight. Foreign keys toggle OFF for the rebuild and back ON afterward;
  // foreign_key_check verifies no orphaned child rows before COMMIT. Gated on the
  // live users SQL still containing 'developer' in the CHECK -- a no-op on fresh
  // installs and on already-swapped bases. Runs BEFORE the password_hash drop so
  // it derives the DDL from a schema SQLite has not yet rewritten.
  try {
    const uDevRow = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get();
    if (uDevRow && uDevRow.sql && uDevRow.sql.includes('developer')) {
      const devWideCheck = "role IN ('analyst', 'lead', 'admin', 'developer')";
      const devNarrowCheck = "role IN ('analyst', 'lead', 'admin', 'anon_author')";
      if (!uDevRow.sql.includes(devWideCheck)) {
        throw new Error('users role CHECK clause not found in live schema; aborting rebuild to avoid corruption');
      }
      const devPrefixes = [
        'CREATE TABLE IF NOT EXISTS "users"',
        'CREATE TABLE IF NOT EXISTS users',
        'CREATE TABLE "users"',
        'CREATE TABLE users',
      ];
      let devNewDdl = null;
      for (const pfx of devPrefixes) {
        if (uDevRow.sql.startsWith(pfx)) { devNewDdl = 'CREATE TABLE users_new' + uDevRow.sql.slice(pfx.length); break; }
      }
      if (devNewDdl === null) {
        throw new Error('unexpected users CREATE statement; aborting rebuild to avoid corruption');
      }
      devNewDdl = devNewDdl.replace(devWideCheck, devNarrowCheck);
      const devCols = db.prepare("PRAGMA table_info(users)").all().map((c) => c.name);
      const devColList = devCols.map((c) => '"' + c + '"').join(', ');
      const devSelectList = devCols.map((c) =>
        c === 'role' ? "CASE WHEN role = 'developer' THEN 'anon_author' ELSE role END" : '"' + c + '"'
      ).join(', ');
      console.log('users migration (B5h3): swapping role CHECK to retire developer');
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        db.exec(devNewDdl);
        const devTotal = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
        const devMoved = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'developer'").get().n;
        db.exec('INSERT INTO users_new (' + devColList + ') SELECT ' + devSelectList + ' FROM users');
        db.exec('DROP TABLE users');
        db.exec('ALTER TABLE users_new RENAME TO users');
        const devFkViolations = db.prepare('PRAGMA foreign_key_check').all();
        if (devFkViolations.length > 0) {
          throw new Error('foreign_key_check reported ' + devFkViolations.length + ' violation(s) after users rebuild');
        }
        db.exec('COMMIT');
        if (devMoved) console.log('users migration (B5h3): reassigned ' + devMoved + ' developer account(s) to anon_author');
        console.log('users migration (B5h3): rebuilt, preserved ' + devTotal + ' user(s)');
      } catch (devRebuildErr) {
        db.exec('ROLLBACK');
        throw devRebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  } catch (userDevMigErr) {
    console.error('users migration (B5h3) developer swap failed (non-fatal):', userDevMigErr.message);
  }

  // ── Migration: drop the unused password_hash column (B5h3) ──
  // Password login was removed -- a session now comes only from a client
  // certificate or a passkey -- so password_hash is dead. No index, foreign
  // key, CHECK, or trigger references it, so a plain DROP COLUMN suffices
  // (SQLite 3.35+; better-sqlite3 12.x bundles a newer engine). Gated on the
  // column still being present, so this is a no-op on fresh installs and on
  // bases where it has already been dropped.
  try {
    const usersCols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
    if (usersCols.includes('password_hash')) {
      db.exec('ALTER TABLE users DROP COLUMN password_hash');
      console.log('users migration (B5h3): dropped unused password_hash column');
    }
  } catch (pwHashMigErr) {
    console.error('users migration (B5h3) drop password_hash failed (non-fatal):', pwHashMigErr.message);
  }

  // ── Migration: ir_policies phantom → canonical (Phase 1.4c precursor) ──
  // The pre-1.4c-precursor codebase had two problems with IR policy storage:
  //   1. assessment-service.js created a phantom ir_policies table with only
  //      5 columns and no FKs. CREATE TABLE IF NOT EXISTS in the canonical
  //      schema above will not modify an existing table, so on existing
  //      deploys we may now have a phantom-shaped ir_policies sitting where
  //      the canonical schema expects 13 columns.
  //   2. The OODA route stored real policy data as JSON blobs in team_config
  //      rows with the key prefix "ooda_policy_". Existing deploys may have
  //      uploaded policies sitting in that key/value soup.
  //
  // This migration detects each case and remediates it. Idempotent — safe
  // to run on every startup.
  try {
    // Detect phantom shape: canonical has 'policy_type' column, phantom has 'name' column.
    const cols = db.prepare("PRAGMA table_info(ir_policies)").all();
    const colNames = cols.map(c => c.name);
    const isPhantom = colNames.includes('name') && !colNames.includes('policy_type');

    if (isPhantom) {
      console.log('ir_policies migration: phantom table detected, rebuilding to canonical');
      // Read any existing rows (likely empty since the phantom was never written to,
      // but we preserve anything just in case some deploy diverged).
      const phantomRows = db.prepare("SELECT id, name, content, uploaded_by, uploaded_at FROM ir_policies").all();

      // Drop the phantom and re-create from the canonical schema. We re-execute
      // the canonical CREATE TABLE for ir_policies + its indexes by extracting
      // them from SCHEMA. Cleaner: drop and rely on CREATE TABLE IF NOT EXISTS
      // in the SCHEMA above to recreate. But db.exec already ran, so the
      // canonical CREATE was a no-op. We need to drop then run the canonical
      // CREATEs explicitly here.
      db.exec('DROP TABLE ir_policies');
      db.exec(`
        CREATE TABLE ir_policies (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          policy_type TEXT NOT NULL CHECK (policy_type IN ('incident_response', 'playbook', 'runbook', 'policy', 'procedure')),
          content TEXT NOT NULL,
          content_hash TEXT NOT NULL,
          scenario_tags TEXT NOT NULL DEFAULT '[]',
          version INTEGER NOT NULL DEFAULT 1,
          uploaded_by TEXT NOT NULL REFERENCES users(id) ON DELETE SET NULL,
          uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now')),
          deleted_at TEXT,
          replenishment_config TEXT NOT NULL DEFAULT '{"mode":"threshold","threshold_x":2,"batch_size":5,"auto_initial_upload":true}'
        );
        CREATE INDEX idx_ir_policies_active ON ir_policies(uploaded_at DESC) WHERE deleted_at IS NULL;
        CREATE INDEX idx_ir_policies_type ON ir_policies(policy_type, uploaded_at DESC) WHERE deleted_at IS NULL;
        CREATE INDEX idx_ir_policies_hash ON ir_policies(content_hash);
      `);

      // Restore any phantom rows under the canonical schema. The phantom had
      // 'name' where canonical has 'title'; everything else maps directly.
      // policy_type defaults to 'policy' since the phantom didn't track it.
      // content_hash is computed; uploaded_at falls back to now if missing.
      const insertCanonical = db.prepare(`
        INSERT INTO ir_policies (id, title, policy_type, content, content_hash, scenario_tags, version, uploaded_by, uploaded_at, updated_at)
        VALUES (?, ?, 'policy', ?, ?, '[]', 1, ?, ?, ?)
      `);
      const crypto = require('crypto');
      for (const row of phantomRows) {
        const safeContent = row.content || '';
        const hash = crypto.createHash('sha256').update(safeContent).digest('hex');
        const ts = row.uploaded_at || new Date().toISOString();
        insertCanonical.run(row.id, row.name || '(untitled)', safeContent, hash, row.uploaded_by, ts, ts);
      }
      console.log(`ir_policies migration: rebuilt to canonical, restored ${phantomRows.length} phantom row(s)`);
    }

    // Now copy team_config rows with key prefix 'ooda_policy_' into ir_policies.
    // These are the real policy uploads from the pre-precursor OODA route.
    const teamConfigPolicies = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'ooda_policy_%'").all();
    if (teamConfigPolicies.length > 0) {
      const cryptoLib = require('crypto');
      const insertFromTeamConfig = db.prepare(`
        INSERT OR IGNORE INTO ir_policies (id, title, policy_type, content, content_hash, scenario_tags, version, uploaded_by, uploaded_at, updated_at)
        VALUES (?, ?, ?, ?, ?, '[]', 1, ?, ?, ?)
      `);
      let copied = 0;
      for (const row of teamConfigPolicies) {
        try {
          const d = JSON.parse(row.value);
          if (!d.id || !d.title || !d.content) continue;
          const validTypes = ['incident_response', 'playbook', 'runbook', 'policy', 'procedure'];
          const safeType = validTypes.includes(d.type) ? d.type : 'policy';
          const hash = cryptoLib.createHash('sha256').update(d.content).digest('hex');
          const ts = d.uploadedAt || new Date().toISOString();
          const result = insertFromTeamConfig.run(d.id, d.title, safeType, d.content, hash, d.uploadedBy || 'unknown', ts, ts);
          if (result.changes > 0) copied++;
        } catch (parseErr) {
          // Skip rows with bad JSON — they were never readable anyway
          continue;
        }
      }
      if (copied > 0) {
        console.log(`ir_policies migration: copied ${copied} policy/policies from team_config into ir_policies`);
        // Delete the team_config rows we successfully copied. We do this in a
        // second pass so a partial failure above doesn't lose data — anything
        // not copied stays in team_config for a future migration attempt.
        db.prepare("DELETE FROM team_config WHERE key LIKE 'ooda_policy_%'").run();
      }
    }

    // ── Migration: ooda_aar_* team_config rows → ooda_aars table ──
    // Phase F4a stored AARs as JSON blobs in team_config with key prefix
    // 'ooda_aar_<id>'. Phase F4b moves them to a canonical table.
    // Idempotent: each row is copied with INSERT OR IGNORE on the AAR id,
    // and only rows that copy successfully are deleted from team_config.
    {
      const aarRows = db.prepare("SELECT key, value, updated_by FROM team_config WHERE key LIKE 'ooda_aar_%'").all();
      if (aarRows.length > 0) {
        const insertAar = db.prepare(`
          INSERT OR IGNORE INTO ooda_aars (id, title, content, incident_date, lessons_learned, uploaded_by, uploaded_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        const copiedAarKeys = [];
        for (const row of aarRows) {
          try {
            const d = JSON.parse(row.value);
            if (!d.id || !d.title || !d.content) continue;
            const ts = d.uploadedAt || new Date().toISOString();
            const result = insertAar.run(
              d.id,
              d.title,
              d.content,
              d.incidentDate || null,
              d.lessonsLearned || null,
              row.updated_by || 'unknown',
              ts
            );
            if (result.changes > 0) copiedAarKeys.push(row.key);
          } catch (parseErr) {
            continue;
          }
        }
        if (copiedAarKeys.length > 0) {
          console.log(`ooda_aars migration: copied ${copiedAarKeys.length} AAR(s) from team_config`);
          const deleteAar = db.prepare("DELETE FROM team_config WHERE key = ?");
          for (const k of copiedAarKeys) deleteAar.run(k);
        }
      }
    }

    // ── Migration: ooda_scenario_* team_config rows → ooda_scenarios table ──
    // Phase F4a stored generated scenarios as JSON blobs in team_config with
    // key prefix 'ooda_scenario_<id>'. The full decision tree (nodes/choices)
    // is preserved in the `tree` column verbatim; scalar fields (title,
    // scenario_type, difficulty, node_count) are denormalized for indexed
    // queries. The legacy F4a scenarios were generated from hardcoded
    // templates, so generated_by_provider is recorded as 'legacy_template'.
    {
      const scenarioRows = db.prepare("SELECT key, value, updated_by FROM team_config WHERE key LIKE 'ooda_scenario_%'").all();
      if (scenarioRows.length > 0) {
        const validTypes = ['ransomware', 'phishing', 'data_exfil', 'insider_threat', 'apt', 'ddos', 'supply_chain', 'credential_compromise'];
        const validDiffs = ['beginner', 'intermediate', 'advanced'];
        const insertScenario = db.prepare(`
          INSERT OR IGNORE INTO ooda_scenarios (id, title, scenario_type, difficulty, tree, node_count, generated_by_provider, source_policy_ids, created_by, created_at)
          VALUES (?, ?, ?, ?, ?, ?, 'legacy_template', '[]', ?, ?)
        `);
        const copiedScenarioKeys = [];
        for (const row of scenarioRows) {
          try {
            const d = JSON.parse(row.value);
            if (!d.id || !d.title || !Array.isArray(d.nodes)) continue;
            const safeType = validTypes.includes(d.type) ? d.type : 'ransomware';
            const safeDiff = validDiffs.includes(d.difficulty) ? d.difficulty : 'intermediate';
            const ts = d.createdAt || new Date().toISOString();
            const createdBy = d.createdBy || row.updated_by || 'unknown';
            const result = insertScenario.run(
              d.id,
              d.title,
              safeType,
              safeDiff,
              row.value,
              d.nodes.length,
              createdBy,
              ts
            );
            if (result.changes > 0) copiedScenarioKeys.push(row.key);
          } catch (parseErr) {
            continue;
          }
        }
        if (copiedScenarioKeys.length > 0) {
          console.log(`ooda_scenarios migration: copied ${copiedScenarioKeys.length} scenario(s) from team_config`);
          const deleteScenario = db.prepare("DELETE FROM team_config WHERE key = ?");
          for (const k of copiedScenarioKeys) deleteScenario.run(k);
        }
      }
    }

    // ── Migration: ooda_progress_* team_config rows → ooda_progress table ──
    // Phase F4a stored per-analyst progress as JSON blobs in team_config
    // with key prefix 'ooda_progress_<userId>_<scenarioId>'. The composite
    // PRIMARY KEY (user_id, scenario_id) on the canonical table requires
    // both pieces, which we extract from the legacy key by splitting on
    // the second underscore.
    //
    // Critical ordering: this migration runs AFTER ooda_scenarios is
    // populated, because ooda_progress.scenario_id has a foreign-key
    // constraint into ooda_scenarios. A progress row whose scenario was
    // never migrated (because the scenario JSON was malformed, or the
    // scenario was deleted before migration) is silently skipped — the
    // FK enforcement returns SQLITE_CONSTRAINT and INSERT OR IGNORE
    // converts that into a no-op.
    {
      const progressRows = db.prepare("SELECT key, value, updated_by FROM team_config WHERE key LIKE 'ooda_progress_%'").all();
      if (progressRows.length > 0) {
        const insertProgress = db.prepare(`
          INSERT OR IGNORE INTO ooda_progress (user_id, scenario_id, nodes_completed, started_at, completed_at)
          VALUES (?, ?, ?, ?, ?)
        `);
        const copiedProgressKeys = [];
        for (const row of progressRows) {
          try {
            // Key shape: 'ooda_progress_<userId>_<scenarioId>'.
            // userId and scenarioId are both hex strings from
            // crypto.randomBytes(16).toString('hex'), so they have no
            // underscores — split on the first underscore after the prefix.
            const stripped = row.key.replace(/^ooda_progress_/, '');
            const firstUnderscore = stripped.indexOf('_');
            if (firstUnderscore === -1) continue;
            const userId = stripped.slice(0, firstUnderscore);
            const scenarioId = stripped.slice(firstUnderscore + 1);
            if (!userId || !scenarioId) continue;
            const d = JSON.parse(row.value);
            const nodesCompleted = JSON.stringify(Array.isArray(d.nodesCompleted) ? d.nodesCompleted : []);
            const startedAt = d.startedAt || new Date().toISOString();
            const result = insertProgress.run(
              userId,
              scenarioId,
              nodesCompleted,
              startedAt,
              d.completedAt || null
            );
            if (result.changes > 0) copiedProgressKeys.push(row.key);
          } catch (parseErr) {
            continue;
          }
        }
        if (copiedProgressKeys.length > 0) {
          console.log(`ooda_progress migration: copied ${copiedProgressKeys.length} progress row(s) from team_config`);
          const deleteProgress = db.prepare("DELETE FROM team_config WHERE key = ?");
          for (const k of copiedProgressKeys) deleteProgress.run(k);
        }
      }
    }
  } catch (migrationErr) {
    // Migration failures must not block server startup. Log loudly so the
    // operator notices, but continue.
    console.error('ir_policies migration FAILED:', migrationErr.message);
    console.error('The server will start, but IR policies may be unavailable until the migration is investigated.');
  }


  // ── Migration: Phase F4c — replenishment_config column on ir_policies ──
  //
  // Existing deploys (v1.0.17 and earlier) have ir_policies without the
  // replenishment_config column added in this PR. ALTER TABLE ADD COLUMN
  // is idempotent here: we only run it when the column is missing. The
  // SQL adds the column with the same default JSON as the canonical
  // CREATE TABLE so existing rows immediately get sensible defaults
  // without needing application-side fallbacks.
  //
  // This migration is independent of the phantom remediation above —
  // separate try/catch so a failure here doesn't mask one there and
  // vice versa.
  try {
    const irPolCols = db.prepare("PRAGMA table_info(ir_policies)").all().map(c => c.name);
    if (!irPolCols.includes('replenishment_config')) {
      db.exec(
        `ALTER TABLE ir_policies ADD COLUMN replenishment_config TEXT NOT NULL DEFAULT '{"mode":"threshold","threshold_x":2,"batch_size":5,"auto_initial_upload":true}'`
      );
      console.log('ir_policies migration (F4c): added replenishment_config column');
    }
  } catch (replenishMigrationErr) {
    console.error('ir_policies F4c migration FAILED:', replenishMigrationErr.message);
    console.error('The server will start, but per-policy replenishment configuration may use defaults until the migration is investigated.');
  }


  // ── Migration: R3g PR3 — compliance_push_cadence_hours on gd_push_config ──
  //
  // Existing deploys (pre-R3g-PR3) have a gd_push_config singleton that
  // predates the separate compliance push tick added in R3g PR3. The
  // metrics tick keeps its existing 15-minute default via
  // push_interval_minutes; the new compliance tick runs on a daily
  // default via compliance_push_cadence_hours.
  //
  // ALTER TABLE ADD COLUMN with a literal-constant DEFAULT is supported
  // on SQLite even for NOT NULL columns: existing rows get the default
  // value at ALTER time (no application-side fallback needed). The CHECK
  // constraint on the new column matches the canonical CREATE TABLE
  // above: 1-720 hours (max 30 days).
  //
  // Guarded by PRAGMA table_info so re-running initDb on an already-
  // migrated DB is a no-op. Own try/catch so a failure here does not
  // mask the R0 users migration below.
  try {
    const gdPushCols = db.prepare("PRAGMA table_info(gd_push_config)").all().map(c => c.name);
    if (!gdPushCols.includes('compliance_push_cadence_hours')) {
      db.exec(
        `ALTER TABLE gd_push_config ADD COLUMN compliance_push_cadence_hours INTEGER NOT NULL DEFAULT 24 CHECK (compliance_push_cadence_hours >= 1 AND compliance_push_cadence_hours <= 720)`
      );
      console.log('gd_push_config migration (R3g PR3): added compliance_push_cadence_hours column');
    }
  } catch (compliancePushCadenceMigrationErr) {
    console.error('gd_push_config R3g PR3 migration FAILED:', compliancePushCadenceMigrationErr.message);
    console.error('The server will start, but compliance push cadence will be unavailable until the migration is investigated.');
  }


  // ── Migration: R3h — leaderboard_push_cadence_minutes on gd_push_config ───
  //
  // Existing deploys (v1.0.33 and earlier) have a gd_push_config singleton
  // that predates the separate leaderboard push tick added in R3h. The
  // tick uses its own cadence column so cadence is independently tunable
  // from the metrics push (push_interval_minutes) and the compliance push
  // (compliance_push_cadence_hours). Default 15 min matches the build
  // plan; range 1-1440 (24h) gives operators flexibility without allowing
  // pathologically long cadences that would let stale leaderboard data
  // sit on the GD.
  //
  // Independent try/catch so a failure here doesn't mask the compliance
  // cadence migration above and vice versa.
  try {
    const gdPushCols = db.prepare("PRAGMA table_info(gd_push_config)").all().map(c => c.name);
    if (!gdPushCols.includes('leaderboard_push_cadence_minutes')) {
      db.exec(
        `ALTER TABLE gd_push_config ADD COLUMN leaderboard_push_cadence_minutes INTEGER NOT NULL DEFAULT 15 CHECK (leaderboard_push_cadence_minutes >= 1 AND leaderboard_push_cadence_minutes <= 1440)`
      );
      console.log('gd_push_config migration (R3h): added leaderboard_push_cadence_minutes column');
    }
  } catch (leaderboardPushCadenceMigrationErr) {
    console.error('gd_push_config R3h migration FAILED:', leaderboardPushCadenceMigrationErr.message);
    console.error('The server will start, but leaderboard push cadence will be unavailable until the migration is investigated.');
  }


  // ── Migration: R3g PR3 Phase 5 — handshake state on gd_push_config ──────
  //
  // Adds four columns backing the manual-CISO-approval handshake the MC
  // tracks locally. Counterpart to the GD's C14 signing_keys schema
  // additions: the MC needs to know which submission is awaiting GD-side
  // approval (pending_signing_key_id), whether the operator has heard
  // back yet (handshake_status), when the last transition happened
  // (last_handshake_at), and what the GD calls this MC (mc_id, so the
  // MC can construct the path-bound URL /api/mc/<mc_id>/signing-key when
  // submitting).
  //
  // PRAGMA-guarded so re-running initDb after the first migration is a
  // no-op. Each ALTER TABLE adds one column (SQLite limitation) with
  // any DEFAULT applied to existing rows at ALTER time.
  //
  // For existing deploys, the gd_push_config singleton (row id=1) was
  // seeded by the original INSERT OR IGNORE at table-creation time.
  // After this migration it has:
  //   mc_id                  NULL       (operator must set via C24
  //                                      gd-config PUT before re-enabling
  //                                      push; the PUT handler will
  //                                      reject api_key changes without
  //                                      a paired mc_id)
  //   handshake_status       'none'     (default applies; the next
  //                                      gd-config PUT in C27 will stage
  //                                      and submit, advancing this to
  //                                      'pending_approval')
  //   last_handshake_at      NULL
  //   pending_signing_key_id NULL
  //
  // Own try/catch so a failure here does not mask any subsequent
  // migration in this initDb call.
  try {
    const cols = db.prepare("PRAGMA table_info(gd_push_config)").all().map(c => c.name);
    if (!cols.includes('mc_id')) {
      db.exec(`ALTER TABLE gd_push_config ADD COLUMN mc_id TEXT`);
    }
    if (!cols.includes('handshake_status')) {
      db.exec(
        `ALTER TABLE gd_push_config ADD COLUMN handshake_status TEXT NOT NULL DEFAULT 'none' CHECK (handshake_status IN ('none', 'pending_approval', 'approved', 'rejected'))`
      );
    }
    if (!cols.includes('last_handshake_at')) {
      db.exec(`ALTER TABLE gd_push_config ADD COLUMN last_handshake_at TEXT`);
    }
    if (!cols.includes('pending_signing_key_id')) {
      db.exec(`ALTER TABLE gd_push_config ADD COLUMN pending_signing_key_id INTEGER`);
    }
    const added = ['mc_id', 'handshake_status', 'last_handshake_at', 'pending_signing_key_id'].filter(c => !cols.includes(c));
    if (added.length > 0) {
      console.log('gd_push_config migration (R3g PR3 Phase 5): added columns', added.join(', '));
    }
  } catch (handshakeMigrationErr) {
    console.error('gd_push_config Phase 5 handshake migration FAILED:', handshakeMigrationErr.message);
    console.error('The server will start, but the GD-push handshake state will be unavailable until the migration is investigated.');
  }


  // ── Migration: abuse_review_keys label + fingerprint (U3 PR I) ─────────────
  // The single active lead key becomes a recipient SET: each active row is
  // one Team Lead's public key, and flag content is sealed to all of
  // them at once. label (a human name for the key) and fingerprint (the 8-byte
  // public-key fingerprint, hex) identify each key in the admin UI and let the
  // register endpoint reject duplicates. Both are nullable so rows from the
  // single-key era migrate cleanly. PRAGMA-guarded, so re-running initDb is a
  // no-op on fresh installs (which get the columns from SCHEMA) and on migrated
  // databases.
  try {
    const arkCols = db.prepare("PRAGMA table_info(abuse_review_keys)").all().map(c => c.name);
    const addArkCol = (col, ddl) => {
      if (!arkCols.includes(col)) {
        db.exec(`ALTER TABLE abuse_review_keys ADD COLUMN ${ddl}`);
        console.log(`abuse_review_keys migration (U3 PR I): added ${col} column`);
      }
    };
    addArkCol('label', 'label TEXT');
    addArkCol('fingerprint', 'fingerprint TEXT');
  } catch (arkMigErr) {
    console.error('abuse_review_keys label/fingerprint migration failed (non-fatal):', arkMigErr.message);
  }


  // ── Migration: Phase R0 — six new columns on users ─────────────────────────
  //
  // Existing deploys (v1.0.23 and earlier) have a users table that predates
  // the phantom-reference resolution in R0. Each of the six new columns is
  // referenced by code paths that fired against missing columns and now have
  // canonical schema homes:
  //
  //   active                 — soft-delete flag for offboarding workflow
  //                            (FEATURE-GUIDE Offboarding step 4); referenced
  //                            by signal-collector, metrics-collector,
  //                            /api/system/version + /api/system/connected-clients,
  //                            iam.js
  //   capacity_score         — 0-100 capacity rating consumed by
  //                            Routing & SOAR; referenced by metrics-
  //                            collector and the routing distribute endpoint
  //   last_heartbeat         — last AC heartbeat ping; referenced by
  //                            /api/system/connected-clients for the connected-clients view
  //   last_iam_check         — IAM offboarding detector watermark;
  //                            referenced by iam.js
  //   offboarded_at          — timestamp of offboarding; pairs with active=0
  //   pseudonym_rotated_at   — last pseudonym rotation timestamp;
  //                            referenced by the pseudonym-rotate endpoint
  //
  // Each ALTER is guarded by a PRAGMA table_info check so the migration is
  // idempotent and re-running initDb on an already-migrated DB is a no-op.
  // The block runs in its own try/catch so a failure here does not mask
  // the F4c migration above and vice versa.
  try {
    const usersCols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
    const addCol = (col, ddl) => {
      if (!usersCols.includes(col)) {
        db.exec(`ALTER TABLE users ADD COLUMN ${ddl}`);
        console.log(`users migration (R0): added ${col} column`);
      }
    };
    addCol('active', 'active INTEGER DEFAULT 1');
    addCol('capacity_score', 'capacity_score INTEGER DEFAULT 50');
    addCol('last_heartbeat', 'last_heartbeat TEXT');
    addCol('last_iam_check', 'last_iam_check TEXT');
    addCol('offboarded_at', 'offboarded_at TEXT');
    addCol('pseudonym_rotated_at', 'pseudonym_rotated_at TEXT');
    addCol('totp_secret', 'totp_secret TEXT');
    addCol('totp_enrolled_at', 'totp_enrolled_at TEXT');
    addCol('totp_last_used_step', 'totp_last_used_step INTEGER');

    // ─────────────────────────────────────────────────────────────────────
    // R3c — ANONYMITY MODEL note for the email column added below
    //
    // The four real-platform HR scheduling adapters (BambooHR, Workday,
    // ADP, UKG/Kronos) need to translate "Workday says employee
    // jane.doe@acme.com works Mon-Thu 9-5" into "schedule upskilling
    // for users.id UUID xyz...". Email is the only stable identifier
    // shared between an external HR record and our user record, so it
    // serves as the join key.
    //
    // Email is treated as a SILENT join key. The contract:
    //
    //   - Populated automatically by SSO (SAML/OIDC/LDAP) attribute
    //     claim at login. B5b (IAM real IdP integration) handles this
    //     in a later phase; for v1.0.29 most users will have NULL
    //     email and HR sync silently skips them.
    //
    //   - NEVER typed by a lead, admin, or analyst. The MC has no UI
    //     surface that captures or displays email.
    //
    //   - NEVER displayed in MC/AC/GD. The lead sees the pseudonym
    //     (users.pseudonym) for burnout-related surfaces, and the
    //     username for IAM/admin surfaces, never the email.
    //
    //   - NEVER written to burnout, metrics, audit, GD aggregate, or
    //     any other downstream table. Email lives only on users.email.
    //
    //   - NEVER logged. Audit middleware does not include email in
    //     event detail. Adapter log lines reference users.id, not
    //     email (see scheduling-platforms/*.js).
    //
    // The HR adapter reads users.email to find the matching users.id,
    // and after that translation everything downstream (auto-assigner,
    // analyst_availability rows, lead's status panel, GD aggregates)
    // operates on UUID + pseudonym only. Availability data thus lives
    // behind the same pseudonym wall as burnout metrics. An attacker
    // who exfiltrated the analyst_availability table would learn
    // schedules-by-UUID, not schedules-by-person.
    //
    // Nullable on purpose: legacy local accounts predating SSO carry
    // NULL email; HR sync's WHERE email IS NOT NULL guard handles
    // those rows by skipping them.
    // ─────────────────────────────────────────────────────────────────────
    addCol('email', 'email TEXT');  // R3c: HR scheduling sync silent join key (see note above)
  } catch (r0MigrationErr) {
    console.error('users R0 migration FAILED:', r0MigrationErr.message);
    console.error('The server will start, but routing, IAM offboarding detection, system observability endpoints, and pseudonym rotation may misbehave until the migration is investigated.');
  }


  // ── Migration: Phase R1 — rebuild ticket_actions and ticket_assignments ───
  //
  // v1.0.24 and earlier shipped two definitions of ticket_actions and
  // ticket_assignments in init.js: the original simple shape near line 430
  // (INTEGER AUTOINCREMENT id, plain TEXT analyst_id, "action" column on
  // ticket_actions, plain TEXT status on ticket_assignments with no CHECK)
  // and the richer R0 shape near line 1020 (TEXT GUID id, FK CASCADE to
  // users(id), "action_type" column, status CHECK constraint, capacity
  // snapshot column, indexes). Because both used IF NOT EXISTS, the
  // simpler original shape won on every install — the richer shape
  // declared in init.js never actually landed in the database.
  //
  // R1 removes the original definitions from the SCHEMA constant above
  // (so fresh installs land directly on the canonical richer shape) and
  // this migration block rebuilds existing v1.0.24 deploys by:
  //
  //   1. Detecting the simple-shape signature (column "action" present,
  //      column "action_type" absent on ticket_actions).
  //   2. Building a *_new table with the canonical shape.
  //   3. Copying rows over, mapping old `action` -> new `action_type`
  //      (defaulting NULL or empty values to 'unknown' since action_type
  //      is NOT NULL in the canonical shape) and casting INTEGER ids to
  //      TEXT.
  //   4. Dropping the simple-shape table and renaming *_new in its place.
  //   5. Creating the canonical indexes.
  //
  // Foreign keys are toggled off for the swap (SQLite requirement) then
  // back on. Wrapped in a transaction so a partial failure doesn't leave
  // a half-rebuilt schema. Idempotent — re-running initDb on an already-
  // migrated database is a no-op because the action_type column is
  // already present.
  try {
    const taCols = db.prepare("PRAGMA table_info(ticket_actions)").all().map(c => c.name);
    if (taCols.length && !taCols.includes('action_type')) {
      db.exec(`
        PRAGMA foreign_keys = OFF;
        BEGIN TRANSACTION;
        CREATE TABLE ticket_actions_new (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          ticket_id TEXT NOT NULL,
          action_type TEXT NOT NULL,
          category TEXT,
          response_time_min REAL,
          notes TEXT,
          created_at TEXT DEFAULT (datetime('now'))
        );
        INSERT INTO ticket_actions_new (id, analyst_id, ticket_id, action_type, category, response_time_min, created_at)
          SELECT
            CAST(id AS TEXT),
            COALESCE(analyst_id, ''),
            COALESCE(ticket_id, ''),
            COALESCE(NULLIF(action, ''), 'unknown'),
            category,
            response_time_min,
            COALESCE(created_at, datetime('now'))
          FROM ticket_actions
          WHERE analyst_id IS NOT NULL AND ticket_id IS NOT NULL;
        DROP TABLE ticket_actions;
        ALTER TABLE ticket_actions_new RENAME TO ticket_actions;
        CREATE INDEX IF NOT EXISTS idx_ticket_actions_analyst ON ticket_actions(analyst_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ticket_actions_ticket ON ticket_actions(ticket_id);
        COMMIT;
        PRAGMA foreign_keys = ON;
      `);
      console.log('ticket_actions migration (R1): rebuilt with canonical shape');
    }
  } catch (r1TaMigrationErr) {
    console.error('ticket_actions R1 migration FAILED:', r1TaMigrationErr.message);
    console.error('The server will start, but ticket_actions may retain the legacy shape (action column instead of action_type) until the migration is investigated.');
  }

  // ── Migration: Phase B5d1-F — ticket_actions.external_action_id + dedup index ──
  //
  // The burnout-signal data feed ingests analyst ticket actions by push
  // (POST /api/integrations/ticketing/activity-events). external_action_id holds
  // the stable id the source platform assigns each action event, so a re-
  // delivered event is idempotently ignored rather than double-counted.
  //
  // ALTER TABLE ADD COLUMN is idempotent here: it runs only when the column is
  // missing, so it is a no-op on fresh installs (which get it from SCHEMA) and on
  // already-migrated databases. It runs after the R1 rebuild above so the table
  // is already in its canonical shape when the column is added.
  //
  // The UNIQUE index is PARTIAL (WHERE external_action_id IS NOT NULL): it
  // enforces one row per source action id for pushed events while allowing any
  // number of NULL rows (existing rows and internally-generated actions that
  // carry no external id). It is created in this migration block rather than in
  // SCHEMA because SCHEMA is exec'd before the migration block, so on an existing
  // database the column would not yet exist at the time SCHEMA ran.
  try {
    const taExtCols = db.prepare("PRAGMA table_info(ticket_actions)").all().map(c => c.name);
    if (!taExtCols.includes('external_action_id')) {
      db.exec("ALTER TABLE ticket_actions ADD COLUMN external_action_id TEXT");
      console.log('ticket_actions migration (B5d1-F): added external_action_id column');
    }
    db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_ticket_actions_external ON ticket_actions(external_action_id) WHERE external_action_id IS NOT NULL");
  } catch (taExtMigErr) {
    console.error('ticket_actions external_action_id migration (B5d1-F) failed (non-fatal):', taExtMigErr.message);
  }

  try {
    const tasCols = db.prepare("PRAGMA table_info(ticket_assignments)").all().map(c => c.name);
    if (tasCols.length && !tasCols.includes('capacity_score_at_assign')) {
      db.exec(`
        PRAGMA foreign_keys = OFF;
        BEGIN TRANSACTION;
        CREATE TABLE ticket_assignments_new (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          ticket_id TEXT NOT NULL,
          analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'closed', 'reassigned')),
          priority TEXT,
          category TEXT,
          capacity_score_at_assign INTEGER,
          assigned_at TEXT DEFAULT (datetime('now')),
          closed_at TEXT
        );
        INSERT INTO ticket_assignments_new (id, ticket_id, analyst_id, status, priority, assigned_at, closed_at)
          SELECT
            CAST(id AS TEXT),
            COALESCE(ticket_id, ''),
            COALESCE(analyst_id, ''),
            CASE
              WHEN status IN ('open', 'in_progress', 'closed', 'reassigned') THEN status
              ELSE 'open'
            END,
            priority,
            COALESCE(assigned_at, datetime('now')),
            closed_at
          FROM ticket_assignments
          WHERE analyst_id IS NOT NULL AND ticket_id IS NOT NULL;
        DROP TABLE ticket_assignments;
        ALTER TABLE ticket_assignments_new RENAME TO ticket_assignments;
        CREATE INDEX IF NOT EXISTS idx_ticket_assignments_analyst ON ticket_assignments(analyst_id, status);
        CREATE INDEX IF NOT EXISTS idx_ticket_assignments_ticket ON ticket_assignments(ticket_id);
        COMMIT;
        PRAGMA foreign_keys = ON;
      `);
      console.log('ticket_assignments migration (R1): rebuilt with canonical shape');
    }
  } catch (r1TasMigrationErr) {
    console.error('ticket_assignments R1 migration FAILED:', r1TasMigrationErr.message);
    console.error('The server will start, but ticket_assignments may retain the legacy shape (no FK, no status CHECK, no capacity_score_at_assign) until the migration is investigated.');
  }


  // ── Migration: Phase R3d-1 — backups table v2-format columns ──────────────
  //
  // v1.0.29 and earlier shipped a backups table with file_path NOT NULL and
  // no v2-format columns. v1.0.30 introduces the encrypted-signed backup
  // format which lives in a directory of four files (manifest.json,
  // archive.tar.zst.enc, manifest.sig, wrapped-key.bin) rather than a single
  // .db file copy. v2 rows carry NULL in file_path and populate the new
  // *_path columns instead.
  //
  // Two distinct migrations run here:
  //
  //   1. Add the v2 columns to the existing backups table via idempotent
  //      ALTER TABLE ADD COLUMN. SQLite supports this in-place for nullable
  //      columns and for NOT NULL columns that have a non-NULL DEFAULT
  //      (format_version qualifies; defaults to 1 = legacy).
  //
  //   2. Relax the file_path NOT NULL constraint so v2 INSERTs that omit
  //      file_path can succeed. SQLite has no ALTER COLUMN; the only path
  //      is a table rebuild — CREATE backups_new with the canonical shape,
  //      copy data, DROP old, RENAME. Foreign keys are toggled OFF for
  //      the rebuild and back ON afterward (audit_log has no FK to backups
  //      so this is straightforward; the only FK from backups is OUTGOING
  //      to backup_signing_keys which itself was just created above and
  //      is empty in old installs).
  //
  // Idempotent — safe to re-run on every startup. The check for a NOT NULL
  // file_path column gates the rebuild; the column-presence check gates
  // the ALTERs. Both are no-ops on already-migrated databases.
  try {
    const backupsCols = db.prepare("PRAGMA table_info(backups)").all();
    const hasFormatVersion = backupsCols.some(c => c.name === 'format_version');
    const filePathCol = backupsCols.find(c => c.name === 'file_path');
    const filePathStillNotNull = filePathCol && filePathCol.notnull === 1;

    // Step 1: rebuild if file_path is still NOT NULL.
    if (filePathStillNotNull) {
      console.log('backups migration (R3d-1): rebuilding to relax file_path NOT NULL constraint');
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        // Build the column list dynamically — old installs may or may not
        // already have the v2 columns from a prior partial migration.
        const colNames = backupsCols.map(c => c.name);
        const hasV2 = (n) => colNames.includes(n);

        // CREATE the new table with the canonical R3d-1 schema.
        db.exec(`
          CREATE TABLE backups_new (
            id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
            type TEXT NOT NULL CHECK (type IN ('daily-auto', 'on-demand', 'snapshot')),
            size_bytes INTEGER,
            file_path TEXT,
            sha256_hash TEXT,
            status TEXT DEFAULT 'running' CHECK (status IN ('running', 'verified', 'failed')),
            created_at TEXT DEFAULT (datetime('now')),
            format_version INTEGER NOT NULL DEFAULT 1
              CHECK (format_version IN (1, 2)),
            manifest_path TEXT,
            archive_path TEXT,
            manifest_sig_path TEXT,
            wrapped_key_path TEXT,
            signing_key_id INTEGER REFERENCES backup_signing_keys(id) ON DELETE RESTRICT
          )
        `);

        // Copy data. For columns that exist in the old table, copy directly;
        // for v2 columns missing on the old table, NULL them in the new one
        // (they get format_version = 1 from the DEFAULT, which is correct
        // since these are legacy v1 rows).
        const selectCols = [
          'id', 'type', 'size_bytes', 'file_path', 'sha256_hash', 'status', 'created_at',
          hasV2('format_version') ? 'format_version' : '1 AS format_version',
          hasV2('manifest_path') ? 'manifest_path' : 'NULL AS manifest_path',
          hasV2('archive_path') ? 'archive_path' : 'NULL AS archive_path',
          hasV2('manifest_sig_path') ? 'manifest_sig_path' : 'NULL AS manifest_sig_path',
          hasV2('wrapped_key_path') ? 'wrapped_key_path' : 'NULL AS wrapped_key_path',
          hasV2('signing_key_id') ? 'signing_key_id' : 'NULL AS signing_key_id',
        ].join(', ');

        const copied = db.prepare(`SELECT COUNT(*) AS n FROM backups`).get().n;
        db.exec(`
          INSERT INTO backups_new
            (id, type, size_bytes, file_path, sha256_hash, status, created_at,
             format_version, manifest_path, archive_path, manifest_sig_path,
             wrapped_key_path, signing_key_id)
          SELECT ${selectCols} FROM backups
        `);

        db.exec('DROP TABLE backups');
        db.exec('ALTER TABLE backups_new RENAME TO backups');
        db.exec('COMMIT');
        console.log(`backups migration (R3d-1): rebuilt to canonical, preserved ${copied} legacy v1 row(s)`);
      } catch (rebuildErr) {
        db.exec('ROLLBACK');
        throw rebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    } else if (!hasFormatVersion) {
      // Step 2: file_path was already nullable (fresh install on a partial
      // schema, or some unusual migration history) but the v2 columns are
      // missing. Add them via ALTER. Idempotent column-presence checks.
      const recheckCols = db.prepare("PRAGMA table_info(backups)").all().map(c => c.name);
      const addCol = (name, ddl) => {
        if (!recheckCols.includes(name)) {
          db.exec(`ALTER TABLE backups ADD COLUMN ${ddl}`);
          console.log(`backups migration (R3d-1): added column ${name}`);
        }
      };
      addCol('format_version',
        `format_version INTEGER NOT NULL DEFAULT 1 CHECK (format_version IN (1, 2))`);
      addCol('manifest_path',     'manifest_path TEXT');
      addCol('archive_path',      'archive_path TEXT');
      addCol('manifest_sig_path', 'manifest_sig_path TEXT');
      addCol('wrapped_key_path',  'wrapped_key_path TEXT');
      addCol('signing_key_id',
        `signing_key_id INTEGER REFERENCES backup_signing_keys(id) ON DELETE RESTRICT`);
    }
  } catch (r3d1MigrationErr) {
    console.error('backups R3d-1 migration FAILED:', r3d1MigrationErr.message);
    console.error('The server will start, but the backups table may retain the v1 shape (file_path NOT NULL, no v2 columns) until the migration is investigated.');
  }


  // Set initial system metadata
  const setMeta = db.prepare('INSERT OR IGNORE INTO system_meta (key, value) VALUES (?, ?)');
  setMeta.run('fuse_counter', String(fuseCounter));
  setMeta.run('app_version', version);
  setMeta.run('schema_version', '1');
  setMeta.run('installed_at', new Date().toISOString());

  // Insert default configs if not exist
  db.prepare('INSERT OR IGNORE INTO report_config (id) VALUES (?)').run('default');
  db.prepare('INSERT OR IGNORE INTO sla_config (id) VALUES (?)').run('default');
  db.prepare('INSERT OR IGNORE INTO notification_config (id) VALUES (?)').run('default');

  // ── Phase R3d-1: ensure an active backup-manifest signing keypair ──────
  //
  // Generates a fresh Ed25519 keypair on first boot of any install (fresh
  // or upgrade from v1.0.29). Idempotent on subsequent starts -- only
  // creates a row when no row has is_active = 1.
  //
  // Wrapped in try/catch so a key-gen failure (e.g. missing
  // TIER1_ENCRYPTION_KEY env var) loudly surfaces in logs without
  // bricking server startup. v2 backups will fail with a clear error
  // message at backup-creation time until the underlying issue is
  // resolved; existing v1 .db backups via internal restore are
  // unaffected.
  //
  // Lazy-required so init.js does not pull the encryption service at
  // module-load time; only at initDb() call time.
  try {
    const { ensureActiveKeypair } = require('../services/backup-signing-keys');
    const keyResult = ensureActiveKeypair(db);
    if (keyResult.isNewlyCreated) {
      console.log(`backup-signing-keys: generated new active Ed25519 keypair (id=${keyResult.id})`);
    }
  } catch (signingKeyErr) {
    console.error('backup-signing-keys initialization FAILED:', signingKeyErr.message);
    console.error('The server will start, but v2 backups cannot be created until this is investigated. Check that TIER1_ENCRYPTION_KEY is set in the environment.');
  }

  // ── R3d-2: Ensure an active chain signing keypair exists ────────────────
  //
  // Same lifecycle pattern as backup-signing-keys above. Distinct keypair
  // for chain integrity (separate concern from backup integrity -- a
  // compromise of the backup-signing key MUST NOT compromise the chain
  // audit trail).
  //
  // Failure here is logged but non-fatal: the server still starts. If the
  // chain keypair is missing when a backup is attempted, the chain entry
  // append will throw with a clear message; the backup itself can still
  // be created without a chain entry as a degraded mode (the operator
  // sees the chain-keypair failure in logs and addresses it). This
  // matches the v1.0.29 -> v1.0.30 upgrade tolerance pattern.
  try {
    const { ensureActiveChainKeypair } = require('../services/chain-signing-keys');
    const chainKeyResult = ensureActiveChainKeypair(db);
    if (chainKeyResult.isNewlyCreated) {
      console.log(`chain-signing-keys: generated new active Ed25519 keypair (id=${chainKeyResult.id})`);
    }
  } catch (chainKeyErr) {
    console.error('chain-signing-keys initialization FAILED:', chainKeyErr.message);
    console.error('The server will start, but backup_chain entries cannot be appended until this is investigated. Check that TIER1_ENCRYPTION_KEY is set in the environment.');
  }

  // ── U4: report-signing keypair ──────────────────────────────────────────
  //
  // Same lifecycle pattern as the chain/backup signing families above.
  // Distinct keypair family that signs every exportable report (compliance,
  // Report Engine, helper-pay, abuse-flag). On a fresh instance this
  // auto-generates the active keypair on first boot; existing instances keep
  // their key. A failure is non-fatal: the server starts, but reports cannot
  // be signed until TIER1_ENCRYPTION_KEY is available and this is resolved.
  try {
    const { ensureActiveReportKeypair } = require('../services/report-signing-keys');
    const reportKeyResult = ensureActiveReportKeypair(db);
    if (reportKeyResult.isNewlyCreated) {
      console.log(`report-signing-keys: generated new active Ed25519 keypair (id=${reportKeyResult.id}, fp=${reportKeyResult.publicKeyFingerprint.slice(0, 16)}\u2026)`);
    }
  } catch (reportKeyErr) {
    console.error('report-signing-keys initialization FAILED:', reportKeyErr.message);
    console.error('The server will start, but exportable reports cannot be signed until this is investigated. Check that TIER1_ENCRYPTION_KEY is set in the environment.');
  }

  // ── Migration: narrow abuse_vault_chain event_type CHECK (drop LEGAL_HOLD_*) ──
  // The legal-hold export flow is gone, so its lifecycle events are no longer a
  // valid chain event. SQLite cannot ALTER a CHECK, so the table is rebuilt by
  // DERIVING the new DDL from the LIVE CREATE and replacing only the table name
  // and the event_type CHECK -- no column drift. The chain's two append-only
  // triggers and two indexes drop with the old table and are recreated from
  // their stored DDL after the rename. The ledger is append-only, so the
  // rebuild ABORTS if it finds any LEGAL_HOLD_* row rather than silently
  // dropping it (none exist on any base -- the chain has never been written).
  // Gated on the stored CHECK still containing 'LEGAL_HOLD'; a no-op on fresh
  // installs and on re-runs.
  try {
    const avcRow = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='abuse_vault_chain'").get();
    if (avcRow && avcRow.sql && avcRow.sql.includes('LEGAL_HOLD')) {
      const wideCheck = "CHECK (event_type IN ('VAULT_SEALED','LEGAL_HOLD_REQUESTED','LEGAL_HOLD_APPROVED','LEGAL_HOLD_DENIED','LEGAL_HOLD_PRODUCED','CHAIN_VERIFIED'))";
      const narrowCheck = "CHECK (event_type IN ('VAULT_SEALED','CHAIN_VERIFIED'))";
      if (!avcRow.sql.includes(wideCheck)) {
        throw new Error('abuse_vault_chain event_type CHECK clause not found in live schema; aborting rebuild to avoid corruption');
      }
      const stragglers = db.prepare("SELECT COUNT(*) AS n FROM abuse_vault_chain WHERE event_type LIKE 'LEGAL_HOLD_%'").get().n;
      if (stragglers > 0) {
        throw new Error('abuse_vault_chain holds ' + stragglers + ' LEGAL_HOLD_* row(s); refusing to narrow the CHECK on an append-only ledger');
      }
      const ifNotExists = 'CREATE TABLE IF NOT EXISTS abuse_vault_chain';
      const quoted = 'CREATE TABLE "abuse_vault_chain"';
      const plain = 'CREATE TABLE abuse_vault_chain';
      let newDdl;
      if (avcRow.sql.startsWith(ifNotExists)) {
        newDdl = 'CREATE TABLE abuse_vault_chain_new' + avcRow.sql.slice(ifNotExists.length);
      } else if (avcRow.sql.startsWith(quoted)) {
        newDdl = 'CREATE TABLE abuse_vault_chain_new' + avcRow.sql.slice(quoted.length);
      } else if (avcRow.sql.startsWith(plain)) {
        newDdl = 'CREATE TABLE abuse_vault_chain_new' + avcRow.sql.slice(plain.length);
      } else {
        throw new Error('unexpected abuse_vault_chain CREATE statement; aborting rebuild to avoid corruption');
      }
      newDdl = newDdl.replace(wideCheck, narrowCheck);
      const auxDdl = db.prepare("SELECT sql FROM sqlite_master WHERE tbl_name='abuse_vault_chain' AND type IN ('index','trigger') AND sql IS NOT NULL").all();
      console.log('abuse_vault_chain migration (B5h3): narrowing event_type CHECK to drop LEGAL_HOLD_* options');
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        db.exec(newDdl);
        const copied = db.prepare('SELECT COUNT(*) AS n FROM abuse_vault_chain').get().n;
        db.exec('INSERT INTO abuse_vault_chain_new SELECT * FROM abuse_vault_chain');
        db.exec('DROP TABLE abuse_vault_chain');
        db.exec('ALTER TABLE abuse_vault_chain_new RENAME TO abuse_vault_chain');
        for (const aux of auxDdl) { db.exec(aux.sql); }
        const fkViolations = db.prepare('PRAGMA foreign_key_check').all();
        if (fkViolations.length > 0) {
          throw new Error('foreign_key_check reported ' + fkViolations.length + ' violation(s) after abuse_vault_chain rebuild');
        }
        db.exec('COMMIT');
        console.log('abuse_vault_chain migration (B5h3): rebuilt, preserved ' + copied + ' ledger entr' + (copied === 1 ? 'y' : 'ies'));
      } catch (avcRebuildErr) {
        db.exec('ROLLBACK');
        throw avcRebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  } catch (avcMigErr) {
    console.error('abuse_vault_chain migration (B5h3) failed (non-fatal):', avcMigErr.message);
  }

  // ── U4 PR 5-C: abuse-vault chain signing key + VAULT_SEALED backfill ─────
  //
  // The abuse-vault ledger has its own Ed25519 signing-key family (key
  // separation). Generate the active key on first boot; existing instances
  // keep theirs. Then backfill a VAULT_SEALED entry for every already-sealed
  // case that lacks one so the ledger is complete on upgrade. The backfill
  // entry is recorded now (its created_at is this boot, not the original seal
  // time); the authoritative seal time stays on the vault row the entry points
  // to. Both steps are idempotent and non-fatal: a failure lets the server
  // start, but recording new sealed cases stays unavailable until resolved.
  try {
    const avChain = require('../services/abuse-vault-chain');
    const avKey = avChain.ensureActiveKey(db);
    if (avKey.isNewlyCreated) {
      console.log(`abuse-vault-chain: generated new active Ed25519 keypair (fp=${avKey.fingerprint.slice(0, 16)}\u2026)`);
    }
    const toBackfill = db.prepare(`
      SELECT v.flag_id, v.flagger_user_id
      FROM peer_abuse_evidence_vault v
      WHERE NOT EXISTS (
        SELECT 1 FROM abuse_vault_chain c
        WHERE c.event_type = 'VAULT_SEALED' AND c.flag_id = v.flag_id
      )
      ORDER BY v.sealed_at ASC, v.id ASC
    `).all();
    let backfilled = 0;
    for (const row of toBackfill) {
      avChain.appendEntry(db, { eventType: 'VAULT_SEALED', flagId: row.flag_id, actorUserId: row.flagger_user_id });
      backfilled++;
    }
    if (backfilled > 0) {
      console.log(`abuse-vault-chain: backfilled ${backfilled} VAULT_SEALED entr${backfilled === 1 ? 'y' : 'ies'}`);
    }
  } catch (avErr) {
    console.error('abuse-vault-chain initialization FAILED:', avErr.message);
    console.error('The server will start, but recording new sealed abuse cases stays unavailable until this is investigated. Check that TIER1_ENCRYPTION_KEY is set.');
  }

  // ── R3d-4: KMS providers + restore approval defaults ────────────────────
  //
  // Seed the env-var KMS provider as the initial default if no providers
  // exist. This preserves backward compatibility with R3d-1/R3d-2/R3d-3
  // installs (which used TIER1_ENCRYPTION_KEY directly without a row).
  // Operators upgrading to R3d-4 keep the env-var path; they can add
  // cloud KMS providers later via /api/kms-providers (commit 24+ of this
  // phase) and rotate the default to the new provider.
  //
  // If kms_providers already has rows (mid-upgrade re-init or similar),
  // do NOT seed -- the operator's configured providers stay authoritative.
  try {
    const existingProvidersCount = db.prepare('SELECT COUNT(*) AS c FROM kms_providers').get().c;
    if (existingProvidersCount === 0) {
      db.prepare(`
        INSERT INTO kms_providers (name, provider_type, config, credentials_encrypted, enabled, is_default)
        VALUES (?, 'env-var', ?, NULL, 1, 1)
      `).run(
        'env-var-default',
        JSON.stringify({ env_var_name: 'TIER1_ENCRYPTION_KEY' }),
      );
      console.log("kms-providers: seeded env-var-default provider as the initial default (uses TIER1_ENCRYPTION_KEY)");
    }
  } catch (kmsErr) {
    console.error('kms-providers initialization FAILED:', kmsErr.message);
    console.error('The server will start, but backup creation may fail until kms_providers has at least one default-enabled row.');
  }

  // Seed restore approval policy defaults if not already set.
  try {
    const ensureMeta = (key, defaultValue) => {
      const existing = db.prepare("SELECT value FROM system_meta WHERE key = ?").get(key);
      if (!existing) {
        db.prepare("INSERT INTO system_meta (key, value) VALUES (?, ?)").run(key, defaultValue);
        console.log(`system_meta: seeded ${key} = ${defaultValue}`);
      }
    };
    ensureMeta('restore_approval_mode', 'strict');
    ensureMeta('restore_approval_window_hours', '24');
  } catch (metaErr) {
    console.error('restore approval defaults initialization FAILED:', metaErr.message);
  }

  // ── R3d-5 migration: extend restore_approvals for external restore ───────
  //
  // Adds source_id and external_backup_id columns to the existing
  // restore_approvals table and relaxes backup_id NOT NULL so an
  // approval row can target either:
  //   (1) a local backup_id (the R3d-4 part 2 case), or
  //   (2) an external (source_id, external_backup_id) pair (new in R3d-5
  //       — approvals for restoring from a remote backup source).
  //
  // The new table-level CHECK constraint enforces local-XOR-external at
  // the database layer; neither both-null nor both-populated rows are
  // accepted.
  //
  // SQLite does not support ALTER TABLE ... DROP NOT NULL, so we rebuild
  // per the standard pattern used elsewhere in this file (CREATE *_new,
  // INSERT ... SELECT, DROP, RENAME, recreate indexes). Wrapped in a
  // transaction with foreign keys briefly disabled. Idempotent — re-
  // running on an already-migrated database is a no-op because the
  // source_id column is already present.
  //
  // Existing R3d-4-pt2 rows (all of which have backup_id populated and
  // source_id / external_backup_id NULL) satisfy the new CHECK and are
  // copied verbatim. No data loss.
  try {
    const raCols = db.prepare("PRAGMA table_info(restore_approvals)").all().map(c => c.name);
    if (raCols.length && !raCols.includes('source_id')) {
      db.exec(`
        PRAGMA foreign_keys = OFF;
        BEGIN TRANSACTION;
        CREATE TABLE restore_approvals_new (
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
              ('second-person-passkey', 'delayed-self-passkey', 'disabled-mode-bypass')),
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
        INSERT INTO restore_approvals_new (
          id, backup_id, source_id, external_backup_id,
          requested_by_user_id, requested_at, request_reason, status,
          approval_mode_at_creation, approval_window_hours,
          approved_by_user_id, approved_at, approval_method,
          denied_by_user_id, denied_at, denial_reason,
          expires_at, consumed_at, chain_request_entry_id,
          client_ip_at_request, client_ip_at_approval
        )
          SELECT
            id, backup_id, NULL, NULL,
            requested_by_user_id, requested_at, request_reason, status,
            approval_mode_at_creation, approval_window_hours,
            approved_by_user_id, approved_at, approval_method,
            denied_by_user_id, denied_at, denial_reason,
            expires_at, consumed_at, chain_request_entry_id,
            client_ip_at_request, client_ip_at_approval
          FROM restore_approvals;
        DROP TABLE restore_approvals;
        ALTER TABLE restore_approvals_new RENAME TO restore_approvals;
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
        COMMIT;
        PRAGMA foreign_keys = ON;
      `);
      console.log('restore_approvals R3d-5 migration: rebuilt with source_id + external_backup_id columns and XOR check');
    }
  } catch (r3d5MigrationErr) {
    console.error('restore_approvals R3d-5 migration FAILED:', r3d5MigrationErr.message);
    console.error('The server will start, but external-restore approvals may fail until the migration is investigated.');
  }

  // ── R3d-5-pt2 migration: extend backup_signing_keys for cross-
  //    deployment external restore ─────────────────────────────────
  //
  // Adds these columns to backup_signing_keys:
  //   public_key_fingerprint  - SHA-256 of the SPKI DER bytes; the
  //                              content-addressed key identifier
  //                              that travels in v3 manifests so a
  //                              backup signed by a foreign
  //                              deployment can be verified against
  //                              the right registered key on a
  //                              completely different deployment.
  //   key_origin              - 'local-generated' (this deployment's
  //                              own keypair) or 'external-registered'
  //                              (a foreign deployment's public key
  //                              we trust for verification only).
  //   registered_by_user_id   - admin who pasted the foreign key
  //                              (audit trail for trust establishment).
  //   registered_at           - when registered.
  //   key_label               - operator-friendly description
  //                              (e.g. "prod-east, key from 2026-04-15").
  //
  // Relaxes private_key_encrypted to NULL for external-registered
  // keys; we have only the public part of a foreign keypair. The new
  // table-level CHECK enforces XOR: local-generated rows MUST have a
  // private key; external-registered rows MUST NOT, MUST be inactive,
  // and MUST carry registration metadata.
  //
  // Computes public_key_fingerprint for all existing rows during
  // migration. SQLite can't compute SHA-256 of DER bytes natively,
  // so we read each row's PEM in JS, re-export to DER, and hash.
  // Rows whose PEM fails to parse keep fingerprint NULL and surface
  // a warning -- migration doesn't block on a single corrupt row.
  //
  // Idempotent: re-running on an already-migrated database is a
  // no-op (the column-presence check returns true).
  try {
    const bskCols = db.prepare("PRAGMA table_info(backup_signing_keys)").all().map(c => c.name);
    if (bskCols.length && !bskCols.includes('public_key_fingerprint')) {
      const existingRows = db.prepare("SELECT * FROM backup_signing_keys").all();
      const fingerprintById = new Map();
      for (const row of existingRows) {
        try {
          const keyObj = crypto.createPublicKey(row.public_key);
          const der = keyObj.export({ type: 'spki', format: 'der' });
          const fp = crypto.createHash('sha256').update(der).digest('hex');
          fingerprintById.set(row.id, fp);
        } catch (parseErr) {
          console.warn(`backup_signing_keys row ${row.id} fingerprint computation skipped during R3d-5-pt2 migration: ${parseErr.message}`);
          fingerprintById.set(row.id, null);
        }
      }

      db.pragma('foreign_keys = OFF');
      try {
        const migrate = db.transaction(() => {
          db.exec(`
            CREATE TABLE backup_signing_keys_new (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              public_key TEXT NOT NULL,
              public_key_fingerprint TEXT,
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

          const insertStmt = db.prepare(`
            INSERT INTO backup_signing_keys_new
              (id, public_key, public_key_fingerprint, private_key_encrypted,
               is_active, key_origin, registered_by_user_id, registered_at,
               key_label, created_at, rotated_out_at, notes)
            VALUES (?, ?, ?, ?, ?, 'local-generated', NULL, NULL, NULL, ?, ?, ?)
          `);
          for (const row of existingRows) {
            insertStmt.run(
              row.id,
              row.public_key,
              fingerprintById.get(row.id),
              row.private_key_encrypted,
              row.is_active,
              row.created_at,
              row.rotated_out_at,
              row.notes,
            );
          }

          db.exec(`
            DROP TABLE backup_signing_keys;
            ALTER TABLE backup_signing_keys_new RENAME TO backup_signing_keys;
            CREATE INDEX IF NOT EXISTS idx_backup_signing_keys_active
              ON backup_signing_keys(is_active) WHERE is_active = 1;
            CREATE INDEX IF NOT EXISTS idx_backup_signing_keys_fingerprint
              ON backup_signing_keys(public_key_fingerprint)
              WHERE public_key_fingerprint IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_backup_signing_keys_origin
              ON backup_signing_keys(key_origin);
          `);
        });
        migrate();
      } finally {
        db.pragma('foreign_keys = ON');
      }
      console.log(`backup_signing_keys R3d-5-pt2 migration: rebuilt with public_key_fingerprint, key_origin, and registration columns; backfilled fingerprints for ${existingRows.length} existing row(s)`);
    }
  } catch (r3d5pt2MigrationErr) {
    console.error('backup_signing_keys R3d-5-pt2 migration FAILED:', r3d5pt2MigrationErr.message);
    console.error('The server will start, but cross-deployment external restore (verifying manifests against external-registered keys) may not work until the migration is investigated.');
  }

  // ── B5d3 migration: extend report_signing_keys for cross-
  //    deployment golden-baseline verification ──
  //
  // Mirrors the R3d-5-pt2 backup_signing_keys shape. Adds:
  //   key_origin              - 'local-generated' (this deployment's
  //                              own report-signing keypair) or
  //                              'external-registered' (a foreign
  //                              deployment's PUBLIC key we trust to
  //                              verify imported golden-baseline
  //                              bundles -- verification only).
  //   registered_by_user_id   - admin who pasted the foreign key
  //                              (audit trail for trust establishment,
  //                              Foundational Rule 22).
  //   registered_at           - when registered.
  //   key_label               - operator-friendly description.
  //
  // Relaxes private_key_encrypted to NULL for external-registered
  // keys. The table-level CHECK enforces XOR: local-generated rows
  // MUST have a private key; external-registered rows MUST NOT, MUST
  // be inactive, and MUST carry registration metadata.
  //
  // No fingerprint backfill is needed (unlike backup_signing_keys):
  // public_key_fingerprint has been NOT NULL since this table shipped
  // and is computed by report-signing-keys.js on every insert.
  //
  // Idempotent: re-running on an already-migrated database is a no-op
  // (the column-presence check returns true).
  try {
    const rskCols = db.prepare("PRAGMA table_info(report_signing_keys)").all().map(c => c.name);
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
              row.notes,
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
      console.log(`report_signing_keys B5d3 migration: rebuilt with key_origin and registration columns (${existingRskRows.length} existing row(s) carried over as local-generated)`);
    }
  } catch (b5d3RskMigrationErr) {
    console.error('report_signing_keys B5d3 migration FAILED:', b5d3RskMigrationErr.message);
    console.error('The server will start, but registering external report-signing keys (cross-deployment golden-baseline verification) will not work until the migration is investigated. Local report signing and verification are unaffected.');
  }

  // ── B5d3 migration: config snapshots move out of team_config ──
  //
  // Legacy config snapshots were stored as JSON blobs in team_config
  // under key prefix 'config_snapshot_<id>'. B5d3 moves them into the
  // dedicated config_snapshots table so they stop accumulating as
  // unbounded team_config rows and gain origin + retention semantics.
  //
  // Legacy payloads keep their original shape and are marked
  // baseline_schema_version 0 so the revert path can distinguish them
  // from golden-baseline-domain snapshots (version 1+). origin is
  // inferred: the auto-save rows the old config-revert created are
  // 'pre-revert'; everything else is 'manual'.
  //
  // Idempotent: INSERT OR IGNORE on the snapshot id; only rows that
  // copy successfully are deleted from team_config. Unparseable rows
  // are left in place rather than dropped.
  try {
    const snapRows = db.prepare("SELECT key, value, updated_by FROM team_config WHERE key LIKE 'config_snapshot_%'").all();
    if (snapRows.length > 0) {
      const insertSnap = db.prepare(`
        INSERT OR IGNORE INTO config_snapshots
          (id, name, origin, created_at, created_by, app_version,
           baseline_schema_version, payload, sha256)
        VALUES (?, ?, ?, ?, ?, NULL, 0, ?, ?)
      `);
      const copiedSnapKeys = [];
      for (const row of snapRows) {
        try {
          const d = JSON.parse(row.value);
          const snapId = row.key.replace('config_snapshot_', '');
          if (!snapId) continue;
          const snapName = (typeof d.name === 'string' && d.name) ? d.name : `Legacy snapshot ${snapId}`;
          const snapOrigin = snapName === 'Auto-save before revert' ? 'pre-revert' : 'manual';
          const snapCreatedAt = d.createdAt || new Date().toISOString();
          const snapCreatedBy = d.createdBy || row.updated_by || null;
          const snapSha = crypto.createHash('sha256').update(row.value).digest('hex');
          const result = insertSnap.run(snapId, snapName, snapOrigin, snapCreatedAt, snapCreatedBy, row.value, snapSha);
          if (result.changes > 0) copiedSnapKeys.push(row.key);
        } catch (parseErr) {
          continue;
        }
      }
      if (copiedSnapKeys.length > 0) {
        console.log(`config_snapshots migration: moved ${copiedSnapKeys.length} snapshot(s) out of team_config`);
        const deleteSnap = db.prepare("DELETE FROM team_config WHERE key = ?");
        for (const k of copiedSnapKeys) deleteSnap.run(k);
      }
    }
  } catch (b5d3SnapMigrationErr) {
    console.error('config_snapshots B5d3 migration FAILED:', b5d3SnapMigrationErr.message);
    console.error('The server will start, but legacy config snapshots may remain in team_config until the migration is investigated. New snapshots are unaffected.');
  }

  // ── R3f migration: MFA enforcement + recovery codes ──────────────────
  //
  // Adds three columns to users for SOC-grade MFA enforcement at login,
  // and a new mfa_consumed_jtis table for the two-step login flow:
  //
  //   mfa_enrollment_required        Set to 1 for all roles. Login
  //                                  refuses to issue a JWT when this
  //                                  is set and totp_enrolled_at IS
  //                                  NULL.
  //   totp_recovery_codes_hashed     JSON array of bcrypt hashes of
  //                                  single-use recovery codes.
  //   totp_recovery_codes_remaining  Cached count for UI display.
  //
  // The two-step login flow uses a short-lived signed JWT (5-minute
  // TTL, mfa_pending claim) as the bridge token between password
  // verification and the second factor. The JWT is HMAC-SHA256 signed
  // with the existing JWT_SECRET; verification at /api/auth/login-mfa
  // and /api/auth/login-enroll-confirm is by signature check (not by
  // hash-then-DB-lookup). The mfa_consumed_jtis table is a denylist
  // of JTIs that have been spent, ensuring single-use semantics: once
  // a JWT's JTI is in the denylist, that token cannot be replayed
  // even if the signature still verifies and the exp has not passed.
  // Rows are pruned by expires_at on a periodic basis.
  //
  // This design eliminates the "plaintext credential token hashed for
  // DB lookup" pattern entirely. There is no plaintext-token sink
  // flowing into a hash function in the verification path: the bridge
  // token IS its signature, and verification is signature-validation.
  // No keyed HMAC of user-supplied input, no indexed-lookup-by-hash,
  // no input that a static analyzer could mistake for a password
  // hash. Single-use enforcement happens at INSERT-time on the JTI
  // denylist with ON CONFLICT DO NOTHING + changes() check; this is
  // race-safe and replay-safe.
  //
  // Idempotent: column-presence checks for each ALTER TABLE; CREATE
  // TABLE IF NOT EXISTS for the new table; DROP TABLE IF EXISTS for
  // the legacy mfa_login_sessions table that R3f preview installs
  // may have created.
  try {
    const usersCols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
    if (!usersCols.includes('mfa_enrollment_required')) {
      db.exec(`
        ALTER TABLE users
          ADD COLUMN mfa_enrollment_required INTEGER NOT NULL DEFAULT 1
          CHECK (mfa_enrollment_required IN (0, 1));
      `);
      // Set the flag for ALL existing user rows. Per R3f-pt2, MFA is
      // required for every account (admin, lead, analyst).
      // SOC-grade environments universally require MFA per NIST SP
      // 800-63B, SOC 2, PCI-DSS. The original R3f carve-out for the
      // analyst role was UX deference; SOC security policy wins.
      const setResult = db.prepare(`
        UPDATE users
        SET mfa_enrollment_required = 1
        WHERE role IN ('admin', 'lead', 'analyst')
      `).run();
      console.log(`R3f migration: added users.mfa_enrollment_required and set it for ${setResult.changes} user row(s)`);
    }
    // R3f-pt2 idempotent backfill: catches databases that ran the
    // original R3f migration under the analyst-carve-out policy
    // (analyst rows stuck at value 0). Safe to re-run; only updates
    // rows that still have the old value. Fresh installs hit no rows
    // here because DEFAULT 1 already covered everyone.
    const r3fPt2Backfill = db.prepare(`
      UPDATE users SET mfa_enrollment_required = 1
      WHERE mfa_enrollment_required = 0
    `).run();
    if (r3fPt2Backfill.changes > 0) {
      console.log(`R3f-pt2 backfill: ${r3fPt2Backfill.changes} previously-carved-out row(s) now require MFA`);
    }
    if (!usersCols.includes('totp_recovery_codes_hashed')) {
      db.exec(`ALTER TABLE users ADD COLUMN totp_recovery_codes_hashed TEXT;`);
      console.log('R3f migration: added users.totp_recovery_codes_hashed');
    }
    if (!usersCols.includes('totp_recovery_codes_remaining')) {
      db.exec(`ALTER TABLE users ADD COLUMN totp_recovery_codes_remaining INTEGER;`);
      console.log('R3f migration: added users.totp_recovery_codes_remaining');
    }
  } catch (r3fUsersErr) {
    console.error('R3f users migration FAILED:', r3fUsersErr.message);
    console.error('The server will start, but MFA enforcement at login may not work until investigated.');
  }

  // ── Migration: Phase R3h — leaderboard opt-in flag ─────────────────────────
  //
  // R3h adds a Helper Recognition Leaderboard surface (peersupport tab on
  // the MC, regional aggregation on the GD). Analysts opt in to be
  // displayed on the leaderboard; the default is opt-out for privacy.
  //
  // Earning points, accruing balances, and redeeming rewards are entirely
  // independent of this flag — leaderboard_opt_in solely controls whether
  // the analyst's name + points are rendered in the recognition ranking.
  // The lead's operational view (per-analyst Helper Score full-roster on
  // the peersupport tab, the Helper Pay administrative tab) is not gated
  // by this flag; it's a payroll/compensation surface for the lead and
  // reads from the ledger directly.
  //
  // Idempotent ALTER guarded by a PRAGMA table_info check matching the
  // R0 / R3c / R3f patterns above. The migration runs in its own
  // try/catch so a failure here doesn't mask the R3f block above and
  // vice versa.
  try {
    const usersCols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
    if (!usersCols.includes('leaderboard_opt_in')) {
      db.exec(`ALTER TABLE users ADD COLUMN leaderboard_opt_in INTEGER NOT NULL DEFAULT 0
        CHECK (leaderboard_opt_in IN (0, 1));`);
      console.log('R3h migration: added users.leaderboard_opt_in (default 0 = opt-out)');
    }
  } catch (r3hMigrationErr) {
    console.error('R3h leaderboard_opt_in migration FAILED:', r3hMigrationErr.message);
    console.error('The server will start, but the leaderboard opt-in toggle may not function until investigated.');
  }

  // ── Migration: Phase R3h-pt2 — anti-gaming fingerprint columns ────────────
  //
  // Adds five columns to peer_session_ratings for sock-puppet detection
  // (C7 establishes the data foundation; C8 adds the detection logic and
  // the lead review queue UI):
  //
  //   rater_ip_hash       SHA-256 hash of req.ip, first 16 hex chars
  //   rater_device_hash   SHA-256 hash of User-Agent, first 16 hex chars
  //   flagged_sockpuppet  0/1 flag set by C8 detection
  //   flagged_at          timestamp of flag-flip
  //   flagged_reason      'ip_cluster' | 'device_cluster' | 'both'
  //
  // Hash truncation rationale: 16 hex chars = 64 bits, ample for the
  // clustering use case (false-collision probability << threshold needed
  // to flag a sock-puppet). Storing full 64-char hashes would bloat the
  // row size with no detection benefit at v1.0.34's scale.
  //
  // Existing rows (pre-R3h-pt2) get NULL for all five columns. The
  // detection logic in C8 treats NULL ip/device hashes as "no data" and
  // does not flag rows lacking fingerprints — pre-migration ratings are
  // grandfathered and not retroactively scrutinized.
  //
  // Idempotent ALTER guarded by PRAGMA table_info check matching the
  // R0/R3c/R3f/R3h-pt1 patterns above. Each ALTER runs only if its
  // column is missing.
  try {
    const ratingsCols = db.prepare("PRAGMA table_info(peer_session_ratings)").all().map(c => c.name);
    const addRatingsCol = (col, ddl) => {
      if (!ratingsCols.includes(col)) {
        db.exec(`ALTER TABLE peer_session_ratings ADD COLUMN ${ddl}`);
        console.log(`R3h-pt2 migration: added peer_session_ratings.${col}`);
      }
    };
    addRatingsCol('rater_ip_hash', 'rater_ip_hash TEXT');
    addRatingsCol('rater_device_hash', 'rater_device_hash TEXT');
    addRatingsCol('flagged_sockpuppet',
      `flagged_sockpuppet INTEGER NOT NULL DEFAULT 0
        CHECK (flagged_sockpuppet IN (0, 1))`);
    addRatingsCol('flagged_at', 'flagged_at TEXT');
    addRatingsCol('flagged_reason', 'flagged_reason TEXT');
  } catch (r3hPt2MigrationErr) {
    console.error('R3h-pt2 peer_session_ratings migration FAILED:',
      r3hPt2MigrationErr.message);
    console.error('The server will start, but sock-puppet detection (C8) cannot operate until investigated.');
  }

  // mfa_consumed_jtis: denylist of MFA-bridge JWT IDs (jti claim) that
  // have already been spent. Single-use enforcement: when /api/auth/
  // login-mfa or /api/auth/login-enroll-confirm successfully verifies
  // an MFA-bridge JWT and is ready to issue the real auth JWT, it
  // INSERTs the JTI here under ON CONFLICT DO NOTHING; if the row
  // already existed, that's a replay attempt and the request fails.
  //
  // expires_at mirrors the JWT's exp claim (Unix-ms epoch). Once
  // expires_at < now(), the JWT itself would no longer verify (jwt
  // library throws TokenExpiredError), so the denylist row no longer
  // adds value; periodic pruning removes expired rows to keep the
  // table small.
  //
  // The legacy mfa_login_sessions table from R3f preview installs is
  // dropped here. Production never saw v1.0.31 with that table; only
  // dev / test environments that ran the preview migrations have it.
  // DROP IF EXISTS is a no-op on installs that never had it.
  db.exec(`
    DROP TABLE IF EXISTS mfa_login_sessions;

    CREATE TABLE IF NOT EXISTS mfa_consumed_jtis (
      jti TEXT PRIMARY KEY,                    -- JWT ID claim, hex-encoded random bytes
      consumed_at INTEGER NOT NULL,            -- ms-epoch when single-use was spent
      expires_at INTEGER NOT NULL              -- ms-epoch == JWT's exp claim * 1000; row prunable after this
    );
    CREATE INDEX IF NOT EXISTS idx_mfa_consumed_jtis_expires_at
      ON mfa_consumed_jtis(expires_at);
  `);

  // R3e schema additions (v1.0.32) -- Config Lock with MFA.
  //
  // config_lock_state: SOC-grade gate over all platform-config-modifying
  // routes (KMS provider switch, GD push config, HR integration creds,
  // IAM role changes, audit log purges, integration onboarding). When
  // lock_active=1, those routes refuse with 423 Locked until an admin
  // unlocks via POST /api/config/lock with a fresh MFA proof (TOTP or
  // single-use recovery code, per the R3f mfa-stepup middleware factory).
  //
  // Design properties:
  //
  //   1. SINGLETON. Exactly one row, enforced at the storage layer via
  //      PRIMARY KEY CHECK (id = 1). Application code never inserts new
  //      rows; it UPDATEs the singleton or reads it. No race window for
  //      "which row is authoritative" -- there's only ever one.
  //
  //   2. DEFAULT UNLOCKED. Fresh installs seed lock_active=0 so initial
  //      operator setup (configuring KMS, registering signing keys,
  //      onboarding the first IAM integration, etc.) is not blocked
  //      before MFA is even enrolled. Locking is an explicit hardening
  //      step the operator performs once the platform reaches steady
  //      state. Documented in setup docs as a "lock once production-
  //      ready" action.
  //
  //   3. MFA REQUIRED IN BOTH DIRECTIONS. Lock and unlock both require
  //      a fresh TOTP / recovery code via the mfa-stepup middleware.
  //      Symmetric -- no escape hatch where an attacker with a stolen
  //      session could lock the legitimate admin out without proving
  //      possession of the second factor.
  //
  //   4. ADMIN ROLE ONLY. POST /api/config/lock authorized for users
  //      with role='admin'. Lead and below cannot toggle. This matches
  //      SOC 2 Separation of Duties (SoD) norms: the role that runs
  //      shifts (lead) is distinct from the role that configures the
  //      platform (admin). Smaller SOCs where one person wears both
  //      hats assign the admin role to that user at user-setup time;
  //      the codebase does not collapse the role boundary.
  //
  //   5. AUDIT TRAIL. last_mfa_verified_at records the ms-epoch of the
  //      most recent successful lock/unlock action. CONFIG_LOCK_ENABLED
  //      / CONFIG_LOCK_DISABLED / CONFIG_LOCK_GATE_HIT /
  //      CONFIG_LOCK_BYPASS_ATTEMPT audit events written from the
  //      route handler + middleware. Forensic reconstructability:
  //      every lock-state transition is attributable to a user_id +
  //      timestamp with MFA proof, and every gated-route call while
  //      locked is logged.
  //
  // Columns:
  //
  //   id                     Always 1. Singleton enforcement.
  //   lock_active            0 = unlocked (default), 1 = locked.
  //                          CHECK constraint pins to {0, 1}.
  //   locked_by_user_id      The user who most recently set
  //                          lock_active=1. NULL when unlocked. Set by
  //                          the route handler on successful lock.
  //                          ON DELETE SET NULL so user deletion does
  //                          not cascade into the lock state.
  //   locked_at              ms-epoch when lock_active flipped to 1.
  //                          NULL when unlocked. Set/cleared atomically
  //                          with lock_active.
  //   last_mfa_verified_at   ms-epoch of the most recent successful
  //                          lock OR unlock action. NULL on fresh
  //                          install (no MFA-gated action has occurred
  //                          yet); set on first POST /api/config/lock
  //                          success.
  //   auto_relock_at         ms-epoch at which an idle unlocked platform
  //                          automatically re-locks. Set on unlock and slid
  //                          forward on each config write; NULL while locked.
  //   idle_minutes           Admin-configurable sliding idle window in
  //                          minutes before auto-relock (default 15).
  //
  // Idempotent: CREATE TABLE IF NOT EXISTS for fresh installs; INSERT
  // ... ON CONFLICT DO NOTHING for the singleton seed so server
  // restarts do not reset lock state.
  db.exec(`
    CREATE TABLE IF NOT EXISTS config_lock_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      lock_active INTEGER NOT NULL DEFAULT 0 CHECK (lock_active IN (0, 1)),
      locked_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      locked_at INTEGER,
      last_mfa_verified_at INTEGER,
      auto_relock_at INTEGER,
      idle_minutes INTEGER NOT NULL DEFAULT 15
    );
    INSERT INTO config_lock_state (id, lock_active)
      VALUES (1, 0)
      ON CONFLICT(id) DO NOTHING;
  `);

  // v1.0.57 (B5d2): idle auto-relock columns. Idempotent ADD COLUMN for
  // databases created before this release. auto_relock_at is the ms-epoch at
  // which an idle unlocked platform automatically re-locks; idle_minutes is
  // the admin-configurable sliding idle window (default 15).
  {
    const clsCols = db.prepare("PRAGMA table_info(config_lock_state)").all().map((c) => c.name);
    if (!clsCols.includes('auto_relock_at')) {
      db.exec('ALTER TABLE config_lock_state ADD COLUMN auto_relock_at INTEGER');
    }
    if (!clsCols.includes('idle_minutes')) {
      db.exec('ALTER TABLE config_lock_state ADD COLUMN idle_minutes INTEGER NOT NULL DEFAULT 15');
    }
  }

  // ── R3i schema additions (v1.0.35) — Backup Multi-Schedule with Regulatory Presets ──
  //
  // Phase R3i ships multi-schedule backup with regulatory framework
  // presets (HIPAA, SOX, PCI-DSS, GDPR, NIST CSF, ISO 27001, SOC 2).
  // The full architecture lives across two new tables introduced in
  // this phase:
  //
  //   regulatory_presets   (this commit, C1)
  //     stores framework-specific compliance floors (min retention,
  //     required encryption, recommended frequency / destination
  //     type, framework citation). The UI uses these to pre-fill new
  //     schedules with the framework's defaults; the API uses them
  //     to enforce the floors on schedule create / update.
  //
  //   backup_schedules     (commit C2)
  //     promotes the existing class-managed table from
  //     server/services/backup-service.js into init.js migration
  //     discipline, extending with name / regulatory_preset_id /
  //     time / day_of_week / day_of_month / next_run / last_status /
  //     last_error columns.
  //
  // Floor-enforcement model (hybrid floor + upward flexibility):
  //
  //   When a schedule is created or updated with a non-null
  //   regulatory_preset_id, the API validates that:
  //
  //     - retention_days >= preset.min_retention_days
  //     - encrypted == 1 if preset.required_encryption == 'AES-256'
  //
  //   Recommended fields (frequency, destination_type) are pre-filled
  //   on preset selection in the UI but NOT enforced by the API.
  //   The operator may set retention HIGHER than the floor (longer
  //   compliance or retention windows) but may NOT go below.
  //   Switching presets re-applies the new floor. The 'None' preset is
  //   the absence of a regulatory_preset_id (NULL foreign-key value);
  //   no floor enforcement runs in that case.
  //
  // Schema notes:
  //
  //   id                              Stable lowercase-snake-case slug
  //                                   used as a foreign key target from
  //                                   backup_schedules.regulatory_preset_id.
  //                                   Examples: 'hipaa', 'sox',
  //                                   'pci_dss', 'gdpr', 'nist_csf',
  //                                   'iso_27001', 'soc_2'.
  //
  //   name                            Display name surfaced in the UI
  //                                   (e.g. 'HIPAA', 'PCI-DSS').
  //
  //   description                     One-line operator-facing
  //                                   description of the preset's
  //                                   purpose. Surfaced in the preset
  //                                   selector tooltip.
  //
  //   min_retention_days              Lower bound for retention. The
  //                                   API rejects schedules below this
  //                                   value with 400
  //                                   RETENTION_BELOW_FLOOR when the
  //                                   preset is selected.
  //
  //   required_encryption             'AES-256' = enforced on schedule
  //                                   create/update (encrypted column
  //                                   MUST be 1). 'none' = not enforced
  //                                   (operator chooses).
  //
  //   recommended_frequency           Suggested frequency. Pre-fills
  //                                   the UI dropdown on preset
  //                                   selection but is not enforced.
  //
  //   recommended_destination_type    Suggested destination class
  //                                   ('local', 's3', 'offsite',
  //                                   'air_gapped'). Pre-fills the UI
  //                                   destination selector but is not
  //                                   enforced. NULL when no specific
  //                                   destination class is recommended.
  //
  //   framework_citation              Authoritative citation for the
  //                                   floor (e.g. '45 CFR 164.316(b)(2)(i)'
  //                                   for HIPAA). Surfaced in the
  //                                   preset selector metadata for
  //                                   operator transparency.
  //
  //   created_at                      ISO timestamp of preset row
  //                                   creation. Useful when future
  //                                   phases add updated_at and want
  //                                   to track which presets are
  //                                   originals vs operator-edited.
  //
  // Idempotent: CREATE TABLE IF NOT EXISTS. Re-running migrations
  // against an existing database is a no-op. The seven seed rows ship
  // in C3 (in this same migration block, after the table create); this
  // commit (C1) just establishes the table shape.
  //
  // Runs in its own try/catch for fault isolation; a failure here
  // does not mask any prior R3e / R3g / R3h migration block.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS regulatory_presets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        min_retention_days INTEGER NOT NULL,
        required_encryption TEXT NOT NULL
          CHECK (required_encryption IN ('AES-256', 'none')),
        recommended_frequency TEXT NOT NULL,
        recommended_destination_type TEXT,
        framework_citation TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    // R3i C3 — Seed 7 regulatory framework presets ────────────────
    //
    // Seeds the regulatory_presets table with the seven frameworks
    // declared in scope for R3i: HIPAA, SOX, PCI-DSS, GDPR, NIST
    // CSF, ISO 27001, SOC 2.
    //
    // Floor values per framework:
    //
    //   HIPAA       6 years (2190 days)  PHI retention requirement
    //               45 CFR 164.316(b)(2)(i)
    //
    //   SOX         7 years (2555 days)  Auditor record retention
    //               17 CFR 210.2-06 / 18 USC 1520
    //
    //   PCI-DSS     1 year (365 days)    Audit log retention floor
    //               PCI DSS v4.0 Requirement 10.7.1
    //
    //   GDPR        30 days              Storage limitation
    //               Articles 5(1)(e), 25, 32, Chapter V
    //               (operational floor for incident recovery; the
    //                storage-limitation upper bound is operator-
    //                managed via retention review, not encoded here)
    //
    //   NIST CSF    365 days (default)   Backup data protection
    //               NIST CSF 2.0 PR.DS-11
    //               (framework specifies HAVING a backup policy,
    //                not a specific retention; 1-year sensible
    //                default that operator can adjust per policy)
    //
    //   ISO 27001   365 days (default)   Information backup
    //               ISO/IEC 27001:2022 Annex A.8.13
    //               (framework specifies HAVING a backup policy,
    //                not a specific retention; 1-year default)
    //
    //   SOC 2       365 days (default)   Trust Services Criteria
    //               TSC CC9.1 / CC6.1
    //               (framework specifies backup controls, not a
    //                specific retention; 1-year default)
    //
    // All seven presets require AES-256 encryption per current
    // SOC-grade default. Operators wanting legacy un-encrypted
    // backups select the 'None' preset (no regulatory_preset_id)
    // which releases this constraint.
    //
    // Recommended destination types:
    //
    //   HIPAA / SOX                  'offsite'    secure offsite
    //   PCI-DSS                      'air_gapped' cardholder isolation
    //   GDPR                         'offsite'    (with EU-region
    //                                             constraint applied
    //                                             via destination
    //                                             config; not encoded
    //                                             at preset level)
    //   NIST CSF / ISO 27001 / SOC 2  NULL        no specific class;
    //                                             operator chooses
    //                                             per policy
    //
    // Recommended frequency is 'daily' for all seven presets. This
    // is the standard operational cadence for SOC-grade backup
    // posture. Operators are free to set higher (hourly) or
    // different cadences per their specific risk profile via the
    // upward-flexibility model.
    //
    // Idempotency:
    //
    //   INSERT OR IGNORE on the primary-key id slug. Re-running
    //   migrations against an already-seeded DB is a no-op.
    //   Operators who want to override a preset's floor values can
    //   UPDATE the row directly; the seed on subsequent boots
    //   will NOT overwrite their changes (INSERT OR IGNORE skips
    //   the row entirely if the id already exists).
    //
    // Framework citation format:
    //
    //   Plain-text ASCII-only citations. Section symbols avoided
    //   for cross-environment rendering reliability.
    const seedPresets = [
      {
        id: 'hipaa',
        name: 'HIPAA',
        description: 'Protected health information - 6-year retention, AES-256, daily backup',
        min_retention_days: 2190,
        required_encryption: 'AES-256',
        recommended_frequency: 'daily',
        recommended_destination_type: 'offsite',
        framework_citation: '45 CFR 164.316(b)(2)(i)',
      },
      {
        id: 'sox',
        name: 'SOX',
        description: 'Financial audit trails - 7-year retention, AES-256, daily backup',
        min_retention_days: 2555,
        required_encryption: 'AES-256',
        recommended_frequency: 'daily',
        recommended_destination_type: 'offsite',
        framework_citation: '17 CFR 210.2-06 / 18 USC 1520',
      },
      {
        id: 'pci_dss',
        name: 'PCI-DSS',
        description: 'Cardholder data - 1-year retention, AES-256, daily backup',
        min_retention_days: 365,
        required_encryption: 'AES-256',
        recommended_frequency: 'daily',
        recommended_destination_type: 'air_gapped',
        framework_citation: 'PCI DSS v4.0 Requirement 10.7.1',
      },
      {
        id: 'gdpr',
        name: 'GDPR',
        description: 'EU personal data - 30-day minimum, AES-256, EU-region destination',
        min_retention_days: 30,
        required_encryption: 'AES-256',
        recommended_frequency: 'daily',
        recommended_destination_type: 'offsite',
        framework_citation: 'Articles 5(1)(e), 25, 32, Chapter V',
      },
      {
        id: 'nist_csf',
        name: 'NIST CSF',
        description: 'Cybersecurity Framework 2.0 - flexible retention, AES-256 required',
        min_retention_days: 365,
        required_encryption: 'AES-256',
        recommended_frequency: 'daily',
        recommended_destination_type: null,
        framework_citation: 'NIST CSF 2.0 PR.DS-11',
      },
      {
        id: 'iso_27001',
        name: 'ISO 27001',
        description: 'Information security management - flexible retention, AES-256 required',
        min_retention_days: 365,
        required_encryption: 'AES-256',
        recommended_frequency: 'daily',
        recommended_destination_type: null,
        framework_citation: 'ISO/IEC 27001:2022 Annex A.8.13',
      },
      {
        id: 'soc_2',
        name: 'SOC 2',
        description: 'Trust Services Criteria - flexible retention, AES-256 required',
        min_retention_days: 365,
        required_encryption: 'AES-256',
        recommended_frequency: 'daily',
        recommended_destination_type: null,
        framework_citation: 'TSC CC9.1 / CC6.1',
      },
    ];
    const insertPreset = db.prepare(`
      INSERT OR IGNORE INTO regulatory_presets
        (id, name, description, min_retention_days, required_encryption,
         recommended_frequency, recommended_destination_type, framework_citation)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    let seededCount = 0;
    for (const preset of seedPresets) {
      const result = insertPreset.run(
        preset.id,
        preset.name,
        preset.description,
        preset.min_retention_days,
        preset.required_encryption,
        preset.recommended_frequency,
        preset.recommended_destination_type,
        preset.framework_citation,
      );
      if (result.changes > 0) seededCount += 1;
    }
    if (seededCount > 0) {
      console.log(`R3i migration: seeded ${seededCount} regulatory_presets row(s)`);
    }

    const presetCount = db.prepare('SELECT COUNT(*) AS n FROM regulatory_presets').get().n;
    console.log(`R3i migration: regulatory_presets table ready (${presetCount} preset(s) present)`);
  } catch (r3iPresetsMigrationErr) {
    console.error('R3i regulatory_presets migration FAILED:', r3iPresetsMigrationErr.message);
    console.error('The server will start, but multi-schedule backup with regulatory presets will not function until investigated.');
  }

  // ── R3i schema additions (v1.0.35) — backup_schedules promotion + extend ──
  //
  // Phase R3i second schema commit (C2). Promotes the existing
  // backup_schedules table from the legacy BackupService class
  // (server/services/backup-service.js, removed in R3m C5, where it
  // was lazily created in BackupService._initTables() on class
  // construction) into init.js migration discipline, and
  // extends with eight new columns to support multi-schedule
  // backup with regulatory framework presets.
  //
  // The legacy lazy-create pattern was an artifact of the v1.0.0
  // baseline (the v100 stub router, removed in R3m C3, POST
  // /api/v1/backup/schedule/add path). It worked but lived outside the
  // canonical init-time migration discipline: schema changes
  // happened on first BackupService construction, with no
  // guaranteed ordering relative to other init steps and no
  // visibility in the central init.js migration log.
  //
  // After this commit, the table:
  //
  //   1. Is created at init.js boot time if missing (fresh installs)
  //   2. Has its eight new columns added via idempotent ALTER if
  //      missing (upgrade from v1.0.34 where the legacy lazy create
  //      ran but only knew the original 9 columns)
  //
  // The BackupService._initTables() call in backup-service.js is
  // left in place for now. Its CREATE TABLE IF NOT EXISTS is a
  // no-op after this migration runs (init.js owns the schema).
  // C10 (BackupService.addSchedule delegation) is the commit that
  // removes the lazy _initTables call and migrates the legacy v100-shape
  // route to use the new persistence layer.
  //
  // Column inventory:
  //
  //   LEGACY (preserved from BackupService._initTables, original
  //   v1.0.0 shape — preserved for any existing rows from the
  //   pre-R3i v100-shape callers; the v100 stub router itself was
  //   removed in R3m C3):
  //
  //     id              INTEGER PRIMARY KEY AUTOINCREMENT
  //     type            TEXT          'full' | 'incremental' |
  //                                   'differential' | 'snapshot'
  //     interval        TEXT          legacy free-form string
  //                                   e.g. 'Every 4hr' — preserved
  //                                   for legacy v100-shape rows; new rows
  //                                   created via the modern
  //                                   service leave this NULL
  //     retention       TEXT          legacy free-form string
  //                                   e.g. '30 days' — new rows
  //                                   use retention_days (INTEGER)
  //                                   on a follow-up cleanup phase
  //                                   could deprecate this column
  //     destination     TEXT          destination identifier
  //                                   (matches storage_destinations
  //                                   row id when modern shape)
  //     encrypted       INTEGER       DEFAULT 1 (encryption is
  //                                   the strong default)
  //     active          INTEGER       DEFAULT 1 (schedule is on
  //                                   until explicitly paused)
  //     last_run        TEXT          ISO timestamp of most recent
  //                                   run (success or failure)
  //     created_at      TEXT          ISO timestamp of row create
  //
  //   NEW (R3i additions for multi-schedule + regulatory presets):
  //
  //     name                  TEXT          operator-supplied label
  //                                         surfaced in the UI list
  //                                         e.g. 'Daily HIPAA backup
  //                                         to S3'
  //
  //     regulatory_preset_id  TEXT          FK to regulatory_presets
  //                                         (id) ON DELETE SET NULL.
  //                                         NULL = 'None' preset
  //                                         (full operator
  //                                         flexibility, no floor
  //                                         enforcement).
  //
  //     time                  TEXT          'HH:MM' 24-hour format
  //                                         for the daily/weekly/
  //                                         monthly fire time.
  //                                         NULL for hourly or
  //                                         legacy schedules using
  //                                         interval.
  //
  //     day_of_week           INTEGER       0-6 (Sunday=0) for
  //                                         weekly schedules. NULL
  //                                         otherwise.
  //
  //     day_of_month          INTEGER       1-31 for monthly
  //                                         schedules. NULL
  //                                         otherwise. Schedules
  //                                         set to day_of_month=31
  //                                         on a 30-day month
  //                                         fire on the last day
  //                                         (scheduler logic).
  //
  //     next_run              TEXT          ISO timestamp of the
  //                                         next scheduled fire.
  //                                         Computed by the
  //                                         scheduler on register
  //                                         and after each run.
  //                                         NULL when paused
  //                                         (active=0).
  //
  //     last_status           TEXT          'success' | 'failed' |
  //                                         'running' | NULL.
  //                                         Surfaced inline in the
  //                                         schedules list UI.
  //
  //     last_error            TEXT          Error message captured
  //                                         from the most recent
  //                                         failure. NULL on
  //                                         success or never-run.
  //
  // Foreign-key behavior:
  //
  //   regulatory_preset_id REFERENCES regulatory_presets(id)
  //   ON DELETE SET NULL — if a preset is somehow removed in a
  //   future operation (not currently exposed via any UI; theoretical
  //   only), affected schedules survive with no preset (full
  //   flexibility). Schedules are NEVER cascade-deleted by preset
  //   removal — the operator's schedule definition outlives the
  //   preset metadata.
  //
  // Idempotency:
  //
  //   CREATE TABLE IF NOT EXISTS handles fresh installs. For
  //   upgrades from v1.0.34 where BackupService._initTables already
  //   created the table with the legacy 9 columns, the PRAGMA
  //   table_info check + per-column ALTER pattern (matching
  //   R3h-pt2's peer_session_ratings approach) adds only the
  //   missing new columns. Re-running migrations against a
  //   fully-migrated database is a no-op.
  //
  // Column ordering note:
  //
  //   The CREATE TABLE places new columns AFTER the legacy
  //   columns. Fresh installs get this ordering. Upgrades end up
  //   with the same final column ordering after ALTER ADD
  //   COLUMNs append in the same order. PRAGMA table_info on
  //   fresh-install and upgraded deployments produces identical
  //   output, eliminating cross-deployment schema drift.
  //
  // Fault isolation:
  //
  //   Wrapped in its own try/catch so a failure here does not
  //   mask the C1 regulatory_presets block above or any prior
  //   R3e / R3g / R3h migration. On failure the server still
  //   starts; the operator sees an explicit console error
  //   pointing to multi-schedule backup as the affected surface.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS backup_schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT,
        interval TEXT,
        retention TEXT,
        destination TEXT,
        encrypted INTEGER DEFAULT 1,
        active INTEGER DEFAULT 1,
        last_run TEXT,
        created_at TEXT,
        name TEXT,
        regulatory_preset_id TEXT
          REFERENCES regulatory_presets(id) ON DELETE SET NULL,
        time TEXT,
        day_of_week INTEGER,
        day_of_month INTEGER,
        next_run TEXT,
        last_status TEXT,
        last_error TEXT
      );
    `);
    const schedulesCols = db.prepare("PRAGMA table_info(backup_schedules)").all().map(c => c.name);
    const addScheduleCol = (col, ddl) => {
      if (!schedulesCols.includes(col)) {
        db.exec(`ALTER TABLE backup_schedules ADD COLUMN ${ddl}`);
        console.log(`R3i migration: added backup_schedules.${col}`);
        schedulesCols.push(col);
      }
    };
    addScheduleCol('name', 'name TEXT');
    addScheduleCol('regulatory_preset_id',
      `regulatory_preset_id TEXT REFERENCES regulatory_presets(id) ON DELETE SET NULL`);
    addScheduleCol('time', 'time TEXT');
    addScheduleCol('day_of_week', 'day_of_week INTEGER');
    addScheduleCol('day_of_month', 'day_of_month INTEGER');
    addScheduleCol('next_run', 'next_run TEXT');
    addScheduleCol('last_status', 'last_status TEXT');
    addScheduleCol('last_error', 'last_error TEXT');
    const scheduleCount = db.prepare('SELECT COUNT(*) AS n FROM backup_schedules').get().n;
    console.log(`R3i migration: backup_schedules table ready (${scheduleCount} schedule(s) present)`);
  } catch (r3iSchedulesMigrationErr) {
    console.error('R3i backup_schedules migration FAILED:', r3iSchedulesMigrationErr.message);
    console.error('The server will start, but multi-schedule backup will not function until investigated.');
  }

  // ── R3l C53: backup_schedules.backup_kind column for Workstream 3 ─────
  //
  // Workstream 3 introduces real incremental + differential backups with
  // per-schedule strategy and destination-subset support. The first step
  // is splitting `backup_kind` from `backup_strategy` at the schema layer:
  //
  //   backup_kind     — what is being backed up: 'full-suite' (entire
  //                     FireAlive deploy including configs, audit, signing
  //                     keys, integrations) vs 'single-db' (just the SQLite
  //                     file). Plan default is 'full-suite' because
  //                     FEATURE-GUIDE line 605 documents full-suite as the
  //                     operator-intended default; pre-R3l scheduler
  //                     dispatch unconditionally called performBackup
  //                     (DB-only), silently defaulting to single-db
  //                     regardless of operator intent (R3l plan decision
  //                     #6).
  //
  //   backup_strategy — how the backup is taken: 'full' / 'incremental' /
  //                     'differential' / 'snapshot'. Added in C55.
  //
  // This commit (C53) adds backup_kind only. The DEFAULT 'full-suite'
  // clause populates all existing rows automatically per SQLite's ALTER
  // TABLE ADD COLUMN semantics. The audit-log backfill below emits one
  // BACKUP_KIND_MIGRATION_v24 entry per migrated row so operators have
  // visibility into exactly which schedules the upgrade touched.
  //
  // The CHECK constraint enforces enum semantics at the schema layer —
  // backup_kind must be 'single-db' or 'full-suite'. Future kinds would
  // require a table rebuild (covered in a future C if/when needed).
  //
  // Idempotent — PRAGMA table_info gate detects column presence before
  // ALTER. The audit-log backfill only emits entries on the first run
  // (when the column is being added); subsequent runs find the column
  // present and skip both the ALTER and the backfill.
  try {
    const r3lC53Cols = db.prepare("PRAGMA table_info(backup_schedules)").all().map(c => c.name);
    if (!r3lC53Cols.includes('backup_kind')) {
      db.exec(`
        ALTER TABLE backup_schedules ADD COLUMN backup_kind TEXT NOT NULL DEFAULT 'full-suite'
          CHECK (backup_kind IN ('single-db','full-suite'))
      `);
      console.log('R3l C53 migration: added backup_schedules.backup_kind column with full-suite default');

      // Backfill audit-log entries — one per existing schedule. The
      // DEFAULT clause already populated each row's backup_kind to
      // 'full-suite'; these audit entries record that the migration
      // touched each row so operators can see in the audit log which
      // schedules were affected by the v1.0.38 upgrade.
      const existingSchedules = db.prepare('SELECT id, name FROM backup_schedules').all();
      const insertAuditEntry = db.prepare(
        "INSERT INTO audit_log (event_type, detail) VALUES (?, ?)"
      );
      for (const row of existingSchedules) {
        insertAuditEntry.run(
          'BACKUP_KIND_MIGRATION_v24',
          'backup_schedules.id=' + row.id + ' name=' + (row.name || '(unnamed)') + ' backup_kind=full-suite'
        );
      }
      console.log(`R3l C53 migration: emitted ${existingSchedules.length} BACKUP_KIND_MIGRATION_v24 audit log entries`);
    } else {
      console.log('R3l C53 migration: backup_schedules.backup_kind column already present, skipping');
    }
  } catch (r3lC53MigrationErr) {
    console.error('R3l C53 backup_kind migration FAILED:', r3lC53MigrationErr.message);
    console.error('The server will start, but Workstream 3 scheduler dispatch will not work until investigated.');
  }

  // ── R3l C54: per-schedule destination subset (Workstream 3 decision #5) ──
  //
  // C54 adds two complementary columns enabling per-schedule destination
  // subset filtering by tag — operator UX improvement covered in the
  // Workstream 3 plan decision #5:
  //
  //   backup_schedules.destination_filter   JSON array of REQUIRED tags
  //                                         that a destination must carry
  //                                         to receive this schedule's
  //                                         backups. NULL = no filter (push
  //                                         to all enabled destinations,
  //                                         which is the pre-R3l behavior
  //                                         and the legacy default).
  //                                         Example: ["offsite","encrypted"]
  //
  //   storage_destinations.tags             JSON array of tags this
  //                                         destination carries. NULL =
  //                                         no tags (passes no filters).
  //                                         Example: ["offsite","geo-redundant"]
  //
  // Semantic: at push time (C58 will implement this), a backup created
  // for schedule S pushes to destination D if AND ONLY IF
  // S.destination_filter is NULL OR S.destination_filter has at least one
  // tag matching D.tags. NULL on either side means "no filter" — backward-
  // compatible legacy behavior preserved.
  //
  // Stored as TEXT (raw JSON) rather than separate normalized tables for
  // schema simplicity. Route-layer code validates JSON shape on POST/PUT;
  // the schema accepts any TEXT so a malformed JSON string at write time
  // is the route layer's concern, not the schema's. The push-time matcher
  // (C58) uses JSON_EXTRACT for tag-set intersection — also a route/service
  // layer concern, not schema.
  //
  // Both columns nullable, no DEFAULT — existing schedules and destinations
  // remain unchanged; new schedules/destinations default to NULL (no
  // filter / no tags). No audit-log backfill needed because NULL is the
  // semantically correct legacy value, not a placeholder requiring
  // operator visibility.
  //
  // Idempotent — PRAGMA table_info gate per table detects column presence
  // before ALTER. Two independent gates so partial failures (e.g., one
  // column added but the other failed in a prior run) can be reconciled
  // on the next start.
  try {
    const r3lC54SchedCols = db.prepare("PRAGMA table_info(backup_schedules)").all().map(c => c.name);
    if (!r3lC54SchedCols.includes('destination_filter')) {
      db.exec(`ALTER TABLE backup_schedules ADD COLUMN destination_filter TEXT`);
      console.log('R3l C54 migration: added backup_schedules.destination_filter column (NULL = no filter)');
    } else {
      console.log('R3l C54 migration: backup_schedules.destination_filter column already present, skipping');
    }

    const r3lC54DestCols = db.prepare("PRAGMA table_info(storage_destinations)").all().map(c => c.name);
    if (!r3lC54DestCols.includes('tags')) {
      db.exec(`ALTER TABLE storage_destinations ADD COLUMN tags TEXT`);
      console.log('R3l C54 migration: added storage_destinations.tags column (NULL = no tags)');
    } else {
      console.log('R3l C54 migration: storage_destinations.tags column already present, skipping');
    }
  } catch (r3lC54MigrationErr) {
    console.error('R3l C54 destination subset migration FAILED:', r3lC54MigrationErr.message);
    console.error('The server will start, but per-schedule destination filtering will not work until investigated.');
  }

  // ── R3l C55: incremental/differential support columns (Workstream 3) ──
  //
  // C55 closes out the Workstream 3 schema layer. Adds 7 columns across
  // two tables to support real WAL-based incremental + differential
  // backups with parent-chain linkage and page-level integrity:
  //
  //   backup_schedules.backup_strategy   Enum: 'full' / 'incremental' /
  //                                      'differential' / 'snapshot'. Default
  //                                      'full' preserves pre-R3l behavior
  //                                      for any schedule the operator
  //                                      hasn't explicitly opted into a
  //                                      different strategy. NOT NULL with
  //                                      DEFAULT means SQLite backfills
  //                                      existing rows automatically.
  //
  //   backups.backup_strategy            Same enum on the per-backup row.
  //                                      The scheduler dispatches off the
  //                                      schedule's strategy (C56) and the
  //                                      created backup row records its
  //                                      actual strategy here. Schedule and
  //                                      backup can diverge if an operator
  //                                      takes a manual override or if a
  //                                      chain-depth limit (C74) forces a
  //                                      scheduled incremental to a full.
  //
  //   backups.parent_backup_id           Self-referential FK pointing to
  //                                      the immediate predecessor in the
  //                                      chain. NULL for 'full' rows (no
  //                                      parent). For 'incremental': points
  //                                      to the previous backup of any kind.
  //                                      For 'differential': points to the
  //                                      anchor full backup.
  //
  //   backups.parent_full_backup_id      Self-referential FK pointing to
  //                                      the most-recent full anchor in
  //                                      the chain. NULL for 'full' rows.
  //                                      Allows the restore-chain walker
  //                                      (C65) to short-circuit to the
  //                                      anchor in O(1) instead of walking
  //                                      parent_backup_id N times.
  //
  //   backups.wal_start_position         TEXT — serialized
  //                                      {wal_file_offset, frame_no} as
  //                                      e.g. "0:1234". The WAL extractor
  //                                      (C61) records the start point of
  //                                      the WAL frames included in this
  //                                      backup. NULL for 'full' / 'snapshot'.
  //
  //   backups.wal_end_position           TEXT — same shape. The WAL frame
  //                                      position immediately after the
  //                                      last frame included; equals the
  //                                      next backup's wal_start_position
  //                                      for contiguous chains.
  //
  //   backups.page_count                 INTEGER — total page count
  //                                      included in the backup's archive.
  //                                      Used by the chain validator (C65)
  //                                      to verify all pages from manifest
  //                                      are present before any restore.
  //
  // ALTER TABLE ADD COLUMN constraints we navigate around in SQLite:
  //   - REFERENCES columns added via ALTER must have NULL default; both
  //     parent_*_id columns have no DEFAULT clause so they're NULL.
  //   - NOT NULL added via ALTER must have a non-NULL DEFAULT; backup_
  //     strategy uses DEFAULT 'full' to satisfy this.
  //   - CHECK constraints are allowed on ADD COLUMN in SQLite 3.31+
  //     (better-sqlite3 ships ≥ 3.40); the enum CHECK fires as expected.
  //
  // Idempotent — each column gated independently by PRAGMA table_info so
  // partial failures (one column added, another failed) reconcile on the
  // next start. Logs both "added" and "already present" cases per column.

  try {
    // Helper for per-table PRAGMA-gated ALTER TABLE ADD COLUMN
    const addColIfMissing = (table, colName, ddl) => {
      const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
      if (!cols.includes(colName)) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
        console.log(`R3l C55 migration: added ${table}.${colName}`);
      } else {
        console.log(`R3l C55 migration: ${table}.${colName} already present, skipping`);
      }
    };

    // backup_schedules.backup_strategy (the schedule's intended strategy)
    addColIfMissing(
      'backup_schedules', 'backup_strategy',
      `backup_strategy TEXT NOT NULL DEFAULT 'full' CHECK (backup_strategy IN ('full','incremental','differential','snapshot'))`
    );

    // backups.backup_strategy (the actual strategy used for this backup row)
    addColIfMissing(
      'backups', 'backup_strategy',
      `backup_strategy TEXT NOT NULL DEFAULT 'full' CHECK (backup_strategy IN ('full','incremental','differential','snapshot'))`
    );

    // backups.parent_backup_id (immediate predecessor in chain)
    addColIfMissing(
      'backups', 'parent_backup_id',
      `parent_backup_id TEXT REFERENCES backups(id)`
    );

    // backups.parent_full_backup_id (anchor full backup; O(1) short-circuit)
    addColIfMissing(
      'backups', 'parent_full_backup_id',
      `parent_full_backup_id TEXT REFERENCES backups(id)`
    );

    // backups.wal_start_position / wal_end_position (TEXT — serialized frame ref)
    addColIfMissing('backups', 'wal_start_position', 'wal_start_position TEXT');
    addColIfMissing('backups', 'wal_end_position', 'wal_end_position TEXT');

    // backups.page_count (integrity verification anchor)
    addColIfMissing('backups', 'page_count', 'page_count INTEGER');
  } catch (r3lC55MigrationErr) {
    console.error('R3l C55 incremental/differential columns migration FAILED:', r3lC55MigrationErr.message);
    console.error('The server will start, but Workstream 3 strategy dispatch and chain restore will not work until investigated.');
  }

  // ── R3l C73: chain-depth limit ───────────────────────────────────────
  //
  // Long incremental chains have two failure modes:
  //   1. Restore cost grows linearly with chain length — a 1000-link
  //      chain takes ~1000x longer to restore than a 1-link chain
  //      because every intermediate has to be decrypted, parsed, and
  //      replayed in order.
  //   2. Chain fragility grows linearly too — if ANY link is corrupted,
  //      missing, or unverifiable, the entire chain past that point is
  //      unrecoverable. A 1000-link chain has ~1000x more single points
  //      of failure than a 1-link chain.
  //
  // C73 adds a configurable depth limit so the system forces a full
  // backup once a chain reaches some operator-defined length. Two
  // sources of truth:
  //
  //   1. backup_schedules.max_chain_depth (INTEGER, nullable per row)
  //      Per-schedule override. NULL = use the global default.
  //
  //   2. system_meta.max_chain_depth (TEXT, default '100')
  //      Global default applied when a schedule doesn't override.
  //
  // The enforcement logic lives in backup-incremental.js (C73 follow-up
  // commit) and counts the existing chain depth before producing a new
  // incremental. If the would-be chain length would exceed the limit,
  // the function escalates to a full backup with reason='depth-limit'.
  //
  // Default of 100 is a defensible starting point: long enough to
  // amortize the daily-cost-of-fulls benefit of incremental, short
  // enough to bound restore time and single-points-of-failure to a
  // tolerable level. Operators with stricter SLAs can lower it; those
  // running very tight storage budgets can raise it (at their own risk).
  try {
    // Per-schedule override column. ALTER COLUMN with no default keeps
    // existing rows at NULL, which the enforcement reads as "use the
    // global default" — zero-disruption migration.
    const r3lC73SchedCols = db.prepare("PRAGMA table_info(backup_schedules)").all().map(c => c.name);
    if (!r3lC73SchedCols.includes('max_chain_depth')) {
      db.exec(`ALTER TABLE backup_schedules ADD COLUMN max_chain_depth INTEGER`);
      console.log('R3l C73 migration: added backup_schedules.max_chain_depth column (NULL = use global default)');
    } else {
      console.log('R3l C73 migration: backup_schedules.max_chain_depth column already present, skipping');
    }

    // Global default in system_meta. Same ensureMeta pattern used for
    // restore_approval_mode defaults earlier in this file (idempotent;
    // existing operators with their own value are not overwritten).
    const ensureMetaForChainDepth = (key, defaultValue) => {
      const existing = db.prepare("SELECT value FROM system_meta WHERE key = ?").get(key);
      if (!existing) {
        db.prepare("INSERT INTO system_meta (key, value) VALUES (?, ?)").run(key, defaultValue);
        console.log(`R3l C73 migration: seeded system_meta.${key} = ${defaultValue}`);
      } else {
        console.log(`R3l C73 migration: system_meta.${key} already set to ${existing.value}, leaving as-is`);
      }
    };
    ensureMetaForChainDepth('max_chain_depth', '100');
  } catch (r3lC73MigrationErr) {
    console.error('R3l C73 chain-depth limit migration FAILED:', r3lC73MigrationErr.message);
    console.error('The server will start, but per-schedule depth overrides will not work until investigated.');
    console.error('The hard-coded MAX_CHAIN_DEPTH=1000 in restore-chain.js still protects against runaway walks.');
  }

  // ── B6c PR-post3: backup_schedules.interval_minutes column ────────────
  //
  // Carries the sub-daily cadence (minutes) for frequency='interval'
  // schedules -- the arbitrary-interval auto-backup capability for data-
  // recovery policies with an RPO under 24h. Nullable INTEGER; NULL for
  // non-interval schedules. The [15, 1440] bound is enforced in
  // backup-schedules.js (not a DB CHECK) so the floor/ceiling live in one
  // place and can be tuned without a schema rebuild. Guarded ADD COLUMN
  // keeps existing rows at NULL -- zero-disruption migration.
  try {
    const post3SchedCols = db.prepare("PRAGMA table_info(backup_schedules)").all().map(c => c.name);
    if (!post3SchedCols.includes('interval_minutes')) {
      db.exec(`ALTER TABLE backup_schedules ADD COLUMN interval_minutes INTEGER`);
      console.log('B6c post-3 migration: added backup_schedules.interval_minutes column (NULL = non-interval schedule)');
    } else {
      console.log('B6c post-3 migration: backup_schedules.interval_minutes column already present, skipping');
    }
  } catch (post3IntervalColErr) {
    console.error('B6c post-3 migration (interval_minutes) failed (non-fatal):', post3IntervalColErr.message);
  }

  // ── R3i C11: legacy backup_config singleton backfill ─────────────────
  //
  // Pre-R3i installs stored a single backup config as a JSON blob in
  // team_config.backup_config:
  //
  //   { schedule: 'daily'|'weekly'|'monthly',
  //     time: 'HH:MM',
  //     retentionDays: int }
  //
  // /api/backup/config GET/POST read/wrote this singleton; the
  // scheduler ignored it and ran off process.env.BACKUP_SCHEDULE
  // instead. C11 closes that gap by promoting the singleton (if
  // present) into a row in the canonical backup_schedules table
  // — the same table the new scheduler reads from (C6) and the
  // new UI manages (C7+C8+C9). After C11, the singleton at
  // team_config.backup_config becomes informational; the
  // /api/backup/config endpoints get rewritten in the same C11
  // commit pair (server/routes/backup.js) to read/write the
  // first row of backup_schedules and surface a deprecation
  // hint to callers.
  //
  // Migration safety:
  //
  //   - Only runs when the legacy singleton actually exists. A
  //     fresh install (no team_config.backup_config row) skips
  //     the entire block silently.
  //
  //   - Only runs when backup_schedules has zero rows. An install
  //     that has been editing schedules via the new UI (or the
  //     legacy v100-shape callers, now removed in R3m, via
  //     BackupService.addSchedule) is left
  //     alone — the operator has already moved past the singleton
  //     and any backfill could create a confusing duplicate.
  //
  //   - JSON.parse wrapped in try/catch; a malformed singleton
  //     (e.g. legacy migration artifact) is logged and skipped
  //     rather than crashing the boot sequence.
  //
  //   - team_config table existence check: very old installs
  //     might not have team_config yet. PRAGMA-style existence
  //     check guards the SELECT.
  //
  //   - Backfilled row name: 'Legacy default'. Operator can
  //     rename via the modern UI without losing the schedule.
  //
  // Column mapping from singleton -> canonical row:
  //
  //   schedule       -> frequency        (validated 'daily'|'weekly'|'monthly')
  //   time           -> time             (validated 'HH:MM')
  //   retentionDays  -> retention        ('N days' legacy string)
  //   (implicit)     -> type             'full'
  //   (implicit)     -> destination      'local'
  //   (implicit)     -> encrypted        1
  //   (implicit)     -> active           1
  //   (implicit)     -> name             'Legacy default'
  //
  //   day_of_week and day_of_month are left NULL. Weekly schedules
  //   backfilled this way will not fire (the scheduler skips
  //   weekly rows without day_of_week per the C6 cron expression
  //   builder); operators upgrading from a weekly singleton see
  //   the 'Legacy default' row in the UI and configure day_of_week
  //   explicitly. This is intentional — the singleton never
  //   carried day_of_week, so the migration has no value to
  //   propagate. Daily schedules backfill cleanly without this
  //   gap.
  //
  // Idempotent: re-running the migration against an already-
  // migrated database hits the "backup_schedules has rows" guard
  // and skips. The team_config.backup_config row itself is left
  // in place for backwards compat with any external tooling that
  // still reads it directly (deprecated path; the /api/backup/
  // config endpoints are rewritten in C11 to read from the
  // canonical table instead).
  try {
    const teamConfigExists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='team_config'"
    ).get();
    if (teamConfigExists) {
      const legacyConfig = db.prepare(
        "SELECT value FROM team_config WHERE key = 'backup_config'"
      ).get();
      if (legacyConfig && legacyConfig.value) {
        const existingSchedules = db.prepare(
          'SELECT COUNT(*) AS n FROM backup_schedules'
        ).get();
        if (existingSchedules.n === 0) {
          let parsed = null;
          try {
            parsed = JSON.parse(legacyConfig.value);
          } catch (parseErr) {
            console.warn('R3i migration: legacy backup_config exists but is unparseable JSON; skipping backfill:', parseErr.message);
          }
          if (parsed) {
            const validFrequencies = ['daily', 'weekly', 'monthly'];
            const frequency = validFrequencies.includes(parsed.schedule)
              ? parsed.schedule
              : 'daily';
            const time = /^\d{1,2}:\d{2}$/.test(parsed.time)
              ? parsed.time
              : '02:00';
            const retentionDays = (
              typeof parsed.retentionDays === 'number'
              && Number.isInteger(parsed.retentionDays)
              && parsed.retentionDays > 0
            ) ? parsed.retentionDays : 30;
            db.prepare(`
              INSERT INTO backup_schedules
                (type, interval, retention, destination, encrypted,
                 active, last_run, created_at, name, regulatory_preset_id,
                 time, day_of_week, day_of_month, next_run,
                 last_status, last_error)
              VALUES
                ('full', NULL, ?, 'local', 1,
                 1, NULL, ?, 'Legacy default', NULL,
                 ?, NULL, NULL, NULL,
                 NULL, NULL)
            `).run(
              `${retentionDays} days`,
              new Date().toISOString(),
              time,
            );
            // Update frequency column separately since the legacy
            // v100-shape rows use interval, not frequency. The modern
            // service reads frequency first when present.
            const lastInsertedId = db.prepare(
              'SELECT id FROM backup_schedules ORDER BY id DESC LIMIT 1'
            ).get();
            if (lastInsertedId) {
              db.prepare(
                'UPDATE backup_schedules SET interval = ? WHERE id = ?'
              ).run(frequency, lastInsertedId.id);
            }
            console.log(
              `R3i migration: backfilled legacy team_config.backup_config singleton into backup_schedules as "Legacy default" (frequency: ${frequency}, time: ${time}, retention: ${retentionDays} days)`
            );
          }
        } else {
          console.log(
            `R3i migration: legacy team_config.backup_config singleton present but backup_schedules already has ${existingSchedules.n} row(s); skipping backfill (operator already migrated)`
          );
        }
      }
    }
  } catch (r3iLegacyMigrationErr) {
    console.error('R3i legacy backup_config migration FAILED:', r3iLegacyMigrationErr.message);
    console.error('The server will start, but operators upgrading from a singleton-config install may need to manually re-create their schedule via the Backup Schedules UI.');
  }

  // ── R3j schema additions (v1.0.36) — SOAR Routing Events ──────────────
  //
  // Phase R3j wires the SOAR (Security Orchestration, Automation, and
  // Response) integration end-to-end. The architectural contract is:
  //
  //   - FireAlive PUBLISHES routing variables (per-analyst capacity,
  //     complexity caps, equity weights, skill matrix, aggregate burnout
  //     risk tier, shift handoff state) via:
  //
  //         GET /api/routing/variables (api-key auth, routing:read scope)
  //
  //     The SOAR polls this at its own cadence.
  //
  //   - The SOAR uses those variables in its own playbook logic to make
  //     ticket-routing decisions. FireAlive does NOT distribute tickets.
  //
  //   - The SOAR reports its routing decisions BACK to FireAlive via:
  //
  //         POST /api/routing/soar-events (api-key auth, routing:events scope)
  //
  //     FireAlive persists each event into this table. The persisted row
  //     is also INSERTed into ticket_assignments (status=open) or used to
  //     UPDATE ticket_assignments (status=closed) depending on event_type,
  //     which closes the capacity-feedback loop: signal-collector.js reads
  //     from ticket_assignments on its next tick and the SOAR-reported
  //     assignment volume influences capacity_score automatically. No
  //     code changes in signal-collector are needed.
  //
  // C1 ships ONLY the soar_routing_events table + indexes. The
  // routing_enabled global toggle backfill row lands in C2 (separate
  // commit, same file).
  //
  // Schema notes:
  //
  //   id                              16-byte random hex slug. SQLite's
  //                                   randomblob() + hex() pattern
  //                                   matches the existing convention
  //                                   for opaque IDs in this database.
  //
  //   soar_source                     Operator-defined identifier for
  //                                   the SOAR instance (e.g.
  //                                   'splunk_soar_prod',
  //                                   'cortex_xsoar_lab'). Nullable for
  //                                   SOARs that don't supply one;
  //                                   strongly recommended for
  //                                   multi-SOAR deployments.
  //
  //   external_event_id               The SOAR's own event identifier.
  //                                   Used as the right half of the
  //                                   UNIQUE idempotency index. Nullable
  //                                   for SOARs that don't supply one;
  //                                   strongly recommended.
  //
  //   event_type                      One of:
  //                                     'ticket_assigned'
  //                                     'ticket_reassigned'
  //                                     'ticket_closed'
  //                                   CHECK constraint pins the
  //                                   vocabulary.
  //
  //   ticket_id                       SOAR-side or ticketing-platform-
  //                                   side ticket identifier. Not a FK
  //                                   into any local table — tickets
  //                                   live in the external system.
  //
  //   analyst_pseudonym               Snapshot of the analyst's
  //                                   pseudonym at event-receipt time.
  //                                   Stored verbatim so subsequent
  //                                   pseudonym rotation (controlled by
  //                                   pseudonym_rotated_at) does not
  //                                   retroactively rewrite history.
  //                                   This is the ONLY analyst
  //                                   identifier the SOAR ever sees per
  //                                   the privacy invariant
  //                                   "FireAlive does not leak analyst
  //                                   identifiers to external systems."
  //
  //   analyst_id                      Resolved at event-receipt time via
  //                                   pseudonym lookup. ON DELETE SET
  //                                   NULL so analyst offboarding does
  //                                   not cascade-delete historical
  //                                   routing data (the pseudonym
  //                                   snapshot above still preserves
  //                                   the audit trail anonymously).
  //
  //   priority                        SOAR-side priority string ('P1',
  //                                   'P2', etc.). Free-form because
  //                                   different SOARs use different
  //                                   priority vocabularies; not
  //                                   constrained at the schema layer.
  //
  //   complexity                      1-5 integer typically, but
  //                                   nullable for closed events that
  //                                   don't carry complexity context.
  //
  //   reason                          Free-text rationale supplied by
  //                                   the SOAR (e.g. "auto-routing via
  //                                   FireAlive capacity variables",
  //                                   "manual reassignment by SOC
  //                                   lead"). Optional but useful for
  //                                   audit clarity.
  //
  //   soar_metadata                   JSON blob, stored verbatim.
  //                                   FireAlive does NOT interpret this
  //                                   field; SOAR vendors use it to
  //                                   carry vendor-specific context
  //                                   (playbook IDs, enrichment results,
  //                                   severity scoring path). Storing
  //                                   verbatim future-proofs the
  //                                   contract against vendor-specific
  //                                   extensions without schema
  //                                   migrations.
  //
  //   assigned_at                     SOAR's timestamp from the request
  //                                   body. ISO 8601 string per
  //                                   convention with the rest of this
  //                                   schema.
  //
  //   received_at                     ISO 8601 timestamp of FireAlive
  //                                   receipt. May differ from
  //                                   assigned_at if the SOAR batches
  //                                   webhooks or there's network
  //                                   delay.
  //
  // Index strategy:
  //
  //   idx_soar_routing_events_external (UNIQUE, partial)
  //     Composite UNIQUE on (soar_source, external_event_id). Partial
  //     WHERE external_event_id IS NOT NULL so SOARs that don't supply
  //     an external_event_id are not constrained (each NULL row is
  //     unique by SQL NULL semantics anyway, but the partial index makes
  //     this explicit and avoids index bloat for NULL rows). This is
  //     the idempotency backbone: a SOAR retry of the same webhook
  //     POSTs again with the same external_event_id; the route handler
  //     detects the duplicate via lookup against this index and returns
  //     200 {idempotent: true} without double-counting.
  //
  //   idx_soar_routing_events_analyst (composite)
  //     (analyst_id, received_at). Supports per-analyst rollups (e.g.
  //     "how many tickets did this analyst receive in the last 24h").
  //     received_at ordering supports time-windowed queries without an
  //     additional sort step.
  //
  //   idx_soar_routing_events_ticket (single-column)
  //     (ticket_id). Supports the ticket_closed event flow: when the
  //     SOAR reports a closure, the handler needs to find any prior
  //     assignment events for the same ticket to compute close-time
  //     metrics.
  //
  // Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
  // Re-running migrations against an existing database is a no-op.
  //
  // Runs in its own try/catch for fault isolation; a failure here does
  // not mask any prior R3e / R3g / R3h / R3i migration block.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS soar_routing_events (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        soar_source TEXT,
        external_event_id TEXT,
        event_type TEXT NOT NULL
          CHECK (event_type IN ('ticket_assigned', 'ticket_reassigned', 'ticket_closed')),
        ticket_id TEXT NOT NULL,
        analyst_pseudonym TEXT NOT NULL,
        analyst_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        priority TEXT,
        complexity INTEGER,
        reason TEXT,
        soar_metadata TEXT,
        assigned_at TEXT NOT NULL,
        received_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    db.exec(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_soar_routing_events_external
        ON soar_routing_events (soar_source, external_event_id)
        WHERE external_event_id IS NOT NULL;
    `);

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_soar_routing_events_analyst
        ON soar_routing_events (analyst_id, received_at);
    `);

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_soar_routing_events_ticket
        ON soar_routing_events (ticket_id);
    `);

    const eventCount = db
      .prepare('SELECT COUNT(*) AS n FROM soar_routing_events')
      .get().n;
    console.log(
      `R3j migration: soar_routing_events table ready (${eventCount} event(s) present)`
    );
  } catch (r3jSoarEventsMigrationErr) {
    console.error(
      'R3j soar_routing_events migration FAILED:',
      r3jSoarEventsMigrationErr.message
    );
    console.error(
      'The server will start, but the SOAR webhook receiver (POST /api/routing/soar-events) will fail until this migration completes successfully. The polling endpoint (GET /api/routing/variables) does not depend on this table and continues to function.'
    );
  }

  // ── Migration: Phase B5d1-F — proactive_break_events (break_compliance feed) ──
  //
  // One row per proactive break OFFERED to an analyst, with its outcome
  // lifecycle (offered -> taken | declined | expired). This is the authoritative
  // source for the break_compliance behavioral signal: the signal collector
  // computes compliance directly from this table at collection time (taken vs
  // decided over a trailing window), so there is no config['break_compliance_*']
  // cache to keep fresh. analyst_id (not pseudonym) is stored for clean
  // per-analyst aggregation; ON DELETE CASCADE drops an offboarded analyst's
  // rows with them.
  //
  // Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
  //
  // Runs in its own try/catch for fault isolation; a failure here does not mask
  // any prior migration block.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS proactive_break_events (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        offered_at TEXT NOT NULL DEFAULT (datetime('now')),
        duration_min INTEGER,
        hours_context REAL,
        outcome TEXT NOT NULL DEFAULT 'offered'
          CHECK (outcome IN ('offered', 'taken', 'declined', 'expired')),
        outcome_at TEXT
      );
    `);

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_proactive_break_events_analyst
        ON proactive_break_events (analyst_id, offered_at DESC);
    `);

    const pbeCount = db
      .prepare('SELECT COUNT(*) AS n FROM proactive_break_events')
      .get().n;
    console.log(
      `B5d1-F migration: proactive_break_events table ready (${pbeCount} event(s) present)`
    );
  } catch (pbeMigrationErr) {
    console.error(
      'B5d1-F proactive_break_events migration FAILED:',
      pbeMigrationErr.message
    );
    console.error(
      'The server will start, but proactive break outcomes will not be recorded and the break_compliance signal will be skipped until this migration completes successfully.'
    );
  }

  // ── R3j C2 — routing_enabled global toggle backfill row ──────────────
  //
  // Seeds a single row in team_config keyed 'routing_enabled' with
  // value 'true' (JSON-encoded boolean). This is the silent-pause
  // toggle for FireAlive's outbound SOAR variable publishing, distinct
  // from panic_mode.
  //
  // Semantics:
  //
  //   routing_enabled = true   FireAlive publishes routing variables
  //                            to the SOAR on the normal cadence.
  //                            Default state.
  //
  //   routing_enabled = false  Silent pause. FireAlive stops pushing
  //                            SOAR variables on the next scheduled
  //                            push. Analysts are NOT notified
  //                            (contrast with panic_mode which
  //                            broadcasts an emergency notification).
  //                            Used for scheduled maintenance,
  //                            integration troubleshooting, or
  //                            non-business hours where the SOAR
  //                            doesn't need fresh variables.
  //
  //   panic_mode = active      Emergency override (separate key).
  //                            Disables ALL wellness-aware routing,
  //                            sets all caps to maximum complexity,
  //                            broadcasts notification to every active
  //                            analyst, and writes panic_saved_caps so
  //                            the prior state can be restored on
  //                            deactivation. Always takes precedence
  //                            over routing_enabled.
  //
  // Storage format matches the team_config convention used by
  // routing.js:
  //
  //   value column is JSON-stringified. 'true' is the JSON encoding
  //   of boolean true (4 characters: t, r, u, e). Consumers run
  //   JSON.parse(row.value) and get a JS boolean. This mirrors the
  //   existing pattern where panic_mode stores '"active"' (the JSON
  //   string "active") and soar_burnout_risk_tier stores e.g.
  //   '"bypassed"' (string) or a JSON-stringified object.
  //
  // C4 (routing.js) adds the matching surface endpoints:
  //
  //   GET  /api/routing/enabled   reads this row, returns
  //                               {enabled, updated_at, updated_by}
  //
  //   PUT  /api/routing/enabled   upserts this row, audit-logs
  //                               ROUTING_ENABLED_TOGGLED
  //
  //   GET  /api/routing/variables also surfaces routing_enabled as a
  //                               top-level field in the polling
  //                               response so the SOAR knows whether
  //                               to honor the variables it's about
  //                               to fetch.
  //
  // Idempotent: INSERT OR IGNORE against the PRIMARY KEY 'key'.
  // Re-running this migration against an already-seeded database is
  // a no-op. If an operator has already manually toggled
  // routing_enabled to false (via the UI in C8 or directly via SQL),
  // the existing row is preserved — the seed never overwrites.
  //
  // Fault isolation: separate try/catch from C1. A failure here does
  // not mask the C1 soar_routing_events migration or any prior
  // R3e/R3g/R3h/R3i migration.
  try {
    const insertResult = db
      .prepare(
        "INSERT OR IGNORE INTO team_config (key, value, updated_by) VALUES ('routing_enabled', 'true', NULL)"
      )
      .run();

    if (insertResult.changes > 0) {
      console.log('R3j migration: seeded routing_enabled = true in team_config');
    } else {
      const current = db
        .prepare("SELECT value FROM team_config WHERE key = 'routing_enabled'")
        .get();
      console.log(
        `R3j migration: routing_enabled row already present in team_config (current value: ${current ? current.value : 'unknown'})`
      );
    }
  } catch (r3jRoutingEnabledMigrationErr) {
    console.error(
      'R3j routing_enabled migration FAILED:',
      r3jRoutingEnabledMigrationErr.message
    );
    console.error(
      'The server will start, but GET /api/routing/enabled will return {enabled: true} as the default (the route handler in C4 treats absence-of-row as enabled). The PUT endpoint will still be able to create the row on first toggle.'
    );
  }

  // ── R3k C1 — cicd_configs + cicd_runs tables ─────────────────────────
  //
  // R3k's CI/CD pipeline-config generator (Sub-phase 4) needs two
  // persistence surfaces:
  //
  //   cicd_configs   one row per generated pipeline configuration.
  //                  Stores: which platform was targeted (GitHub
  //                  Actions, GitLab CI, Jenkinsfile, CircleCI),
  //                  what purpose (custom-build for an org's fork or
  //                  upstream-contribution targeting the public
  //                  FireAlive repo), when generated, where the
  //                  output YAML lives on disk, and a JSON snapshot
  //                  of the current install at generation time (used
  //                  by the generator to bake the install's
  //                  integration list + encryption mode + KMS
  //                  provider + data volume into the pipeline as the
  //                  build baseline).
  //
  //   cicd_runs      one row per external CI run reported back via
  //                  the webhook receiver (POST /api/cicd/runs).
  //                  Idempotency on (platform, external_run_id): the
  //                  same CI vendor reporting the same run id twice
  //                  collapses to the same row. Two different
  //                  vendors can independently use overlapping
  //                  external_run_id values (e.g., both GitLab and
  //                  Jenkins emitting numeric counters starting at 1)
  //                  because the platform discriminator is part of
  //                  the composite key.
  //
  // Schema conventions match the canonical patterns established in
  // R3d (backups), R3i (backup_schedules, regulatory_presets), and
  // R3j (soar_routing_events):
  //
  //   - TEXT PRIMARY KEY with DEFAULT (lower(hex(randomblob(16))))
  //     for application-level UUIDv4-shape ids when the row's id is
  //     not derived from external state. R3k C1 follows this for
  //     both cicd_configs.id and cicd_runs.id.
  //
  //   - CHECK constraints on enum columns (platform, purpose,
  //     status) so SQLite rejects unknown values at INSERT time. The
  //     route handler in C13 (routes/cicd.js) also validates against
  //     the same enums in JS for friendlier error messages, but the
  //     DB CHECK is the load-bearing invariant.
  //
  //   - FOREIGN KEY (created_by → users.id) without ON DELETE
  //     CASCADE: if a user is deleted, their generated pipeline
  //     configs are preserved for audit. The CI/CD listing endpoint
  //     in C15 surfaces "user deleted" instead of dropping the row.
  //
  //   - FOREIGN KEY (config_id → cicd_configs.id) is NULLABLE
  //     because external CI runs can arrive before any operator has
  //     registered a generated config — the webhook receiver in
  //     C11 records them anyway with config_id NULL so the audit
  //     trail captures every signal. Operators can retroactively
  //     associate runs with configs later if needed.
  //
  //   - received_at on cicd_runs uses DEFAULT (datetime('now')) so
  //     the webhook handler doesn't need to pass an explicit
  //     timestamp. started_at, finished_at come from the CI payload
  //     and are application-supplied.
  //
  // Webhook idempotency design (matches R3j C1 soar_routing_events):
  //
  //   The UNIQUE INDEX on (platform, external_run_id) means SQLite
  //   raises SQLITE_CONSTRAINT_UNIQUE on duplicate INSERTs. The
  //   webhook handler in C11 catches that error and returns
  //   {idempotent: true, run_id: <existing row's id>} 200 OK rather
  //   than 409 — retried webhooks from a CI vendor that lost its
  //   ack should not error.
  //
  // Indexes:
  //
  //   idx_cicd_configs_platform     speeds the "show me all GitHub
  //                                 Actions configs" filter on the
  //                                 MC CI/CD tab listing.
  //
  //   idx_cicd_runs_external        UNIQUE composite enforcing
  //                                 idempotency; also serves the
  //                                 "look up this specific external
  //                                 run" query path.
  //
  //   idx_cicd_runs_config          speeds the "show me runs for
  //                                 this saved config in reverse
  //                                 chronological order" query
  //                                 issued by the MC CI/CD tab's
  //                                 history sub-card (C19).
  //
  // Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT
  // EXISTS. Re-running migrations against an existing database is a
  // no-op.
  //
  // Runs in its own try/catch for fault isolation; a failure here
  // does not mask any prior R3e/R3g/R3h/R3i/R3j migration block.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS cicd_configs (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        platform TEXT NOT NULL
          CHECK (platform IN ('github-actions', 'gitlab-ci', 'jenkins', 'circleci')),
        purpose TEXT NOT NULL
          CHECK (purpose IN ('custom-build', 'upstream-contribution')),
        generated_at TEXT NOT NULL,
        generated_yaml_path TEXT NOT NULL,
        current_install_snapshot_json TEXT NOT NULL,
        created_by INTEGER NOT NULL REFERENCES users(id)
      );
    `);

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_cicd_configs_platform
        ON cicd_configs (platform);
    `);

    db.exec(`
      CREATE TABLE IF NOT EXISTS cicd_runs (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
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
        received_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    db.exec(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_cicd_runs_external
        ON cicd_runs (platform, external_run_id);
    `);

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_cicd_runs_config
        ON cicd_runs (config_id, received_at);
    `);

    const configCount = db
      .prepare('SELECT COUNT(*) AS n FROM cicd_configs')
      .get().n;
    const runCount = db
      .prepare('SELECT COUNT(*) AS n FROM cicd_runs')
      .get().n;
    console.log(
      `R3k migration: cicd_configs + cicd_runs tables ready (${configCount} config(s), ${runCount} run(s) present)`
    );
  } catch (r3kCicdSchemaMigrationErr) {
    console.error(
      'R3k cicd_configs + cicd_runs migration FAILED:',
      r3kCicdSchemaMigrationErr.message
    );
    console.error(
      'The server will start, but the CI/CD generator (POST /api/cicd/generate) and webhook receiver (POST /api/cicd/runs) will fail until this migration completes successfully. All other surfaces (routing, integrations, backup, regression) are independent of this table and continue to function.'
    );
  }

  // ── R3k C2 — cloud_iac_signing_keys table + backups.kind column ──
  //
  // R3k's Cloud & IaC artifact generator (Sub-phase 4) signs every
  // generated bundle archive with a FireAlive-managed signing key.
  // This is a SEPARATE signing concern from the backup signing keys
  // (one signing key per signing concern, no multiplexing) per the
  // R3K-DETAILED-BUILD-PLAN cross-cutting Sigstore decision. The new
  // table holds the key material:
  //
  //   cloud_iac_signing_keys
  //     id                    PK, UUID-shape
  //     public_key            PEM-encoded cosign public key
  //     private_key_wrapped   KMS-wrapped private key (encrypted at
  //                           rest via the active KMS DEK; never
  //                           plaintext on disk)
  //     algorithm             defaults to 'cosign-ecdsa-p256', the
  //                           Sigstore-compatible default. Future
  //                           rotations may emit other algorithms.
  //     status                'active' on creation; flips to
  //                           'rotated' when a successor key takes
  //                           over (with rotated_at set); flips to
  //                           'revoked' for emergency invalidation.
  //                           Index serves the "find the active
  //                           key" hot-path query issued every time
  //                           the generator signs a new bundle.
  //     created_at            ISO 8601 timestamp, DEFAULT now().
  //     rotated_at            ISO 8601 timestamp when this key was
  //                           rotated out; NULL while active.
  //
  // The 'cloud_iac_signing_keys' name parallels 'backup_signing_keys'
  // for operator predictability — both manage signing key lifecycle
  // (generate, rotate, revoke); both expose admin-side CRUD via a
  // dedicated route file (in R3k Sub-phase 4 / C10 for cloud_iac).
  // They are intentionally NOT a single shared table because:
  //
  //   - Different threat models. A backup-key compromise affects
  //     past backup integrity; a cloud-iac-key compromise affects
  //     supply-chain trust in deployment artifacts. Conflating the
  //     two means a single rotation event has to be coordinated
  //     across both concerns, and a compromise of one forces
  //     rotation of the other.
  //
  //   - Different rotation cadences. Backup keys rotate on an
  //     audit-driven schedule (typically annual). Cloud & IaC
  //     signing keys may rotate per major release if the operator
  //     wants per-release attestation chains.
  //
  //   - Different signature consumers. Backup signatures are
  //     verified by FireAlive's own restore path. Cloud & IaC
  //     signatures are verified by third-party cosign clients in
  //     operator deployment pipelines.
  //
  // Also extends the existing backups table with a new column:
  //
  //   backups.kind            'single-db' or 'full-suite'. Existing
  //                           rows backfill to 'single-db' via the
  //                           DEFAULT, which preserves the current
  //                           backup history without manual data
  //                           migration. R3k's full-suite backup
  //                           service (Sub-phase 6) writes rows
  //                           with kind='full-suite'; the canonical
  //                           single-DB backup path (existing
  //                           /api/backup) continues to write rows
  //                           with the default 'single-db'. The
  //                           CHECK constraint enforces these are
  //                           the only two values.
  //
  // The ALTER TABLE ADD COLUMN is guarded by a PRAGMA table_info
  // check matching the canonical pattern established for backups
  // column additions earlier in this file (R3d-1 + later phases).
  //
  // Two independent try/catch blocks for fault isolation between
  // the table-creation migration and the column-addition migration.
  // A failure in one does not mask the other, and neither masks
  // any prior R3e/R3g/R3h/R3i/R3j/R3k-C1 migration.
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
    `);

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_cloud_iac_signing_keys_status
        ON cloud_iac_signing_keys (status);
    `);

    const keyCount = db
      .prepare('SELECT COUNT(*) AS n FROM cloud_iac_signing_keys')
      .get().n;
    console.log(
      `R3k migration: cloud_iac_signing_keys table ready (${keyCount} key(s) present)`
    );
  } catch (r3kCloudIacKeysMigrationErr) {
    console.error(
      'R3k cloud_iac_signing_keys migration FAILED:',
      r3kCloudIacKeysMigrationErr.message
    );
    console.error(
      'The server will start, but the Cloud & IaC generator (POST /api/cloud/package) will fail until this migration completes successfully — the generator requires an active signing key from this table to sign output bundles. All other R3k surfaces (CI/CD, backup full-suite, regression) are independent and continue to function.'
    );
  }

  try {
    const backupsCols = db
      .prepare("PRAGMA table_info(backups)")
      .all()
      .map(c => c.name);
    if (!backupsCols.includes('kind')) {
      db.exec(
        `ALTER TABLE backups ADD COLUMN kind TEXT NOT NULL DEFAULT 'single-db' CHECK (kind IN ('single-db', 'full-suite'))`
      );
      console.log(
        "R3k migration: added column kind to backups (default 'single-db' backfills existing rows)"
      );
    } else {
      console.log(
        'R3k migration: backups.kind column already present (no-op)'
      );
    }
  } catch (r3kBackupsKindMigrationErr) {
    console.error(
      'R3k backups.kind column migration FAILED:',
      r3kBackupsKindMigrationErr.message
    );
    console.error(
      'The server will start, but the comprehensive backup path (POST /api/backup/full-suite) will fail to record kind=full-suite rows until this migration completes successfully. The canonical single-DB backup path (existing /api/backup) continues to function — its INSERTs omit kind and rely on the DEFAULT, which works once the column is added.'
    );
  }

  // ── B6c PR-post3 — rename backups.type value 'daily-auto' -> 'scheduled' ──
  //
  // The auto-backup trigger enum renames 'daily-auto' to 'scheduled' so the
  // label stays accurate once schedules can fire sub-daily (an hourly or
  // 15-minute backup is not "daily"). The strategy already lives in
  // backup_strategy; type carries only the trigger.
  //
  // SQLite cannot ALTER a CHECK, so backups is rebuilt. The new-table DDL is
  // DERIVED from the live table's stored SQL so every column, default, foreign
  // key, and CHECK is preserved byte-identically -- only the type CHECK's enum
  // values change. Rows are copied with type='daily-auto' mapped to 'scheduled'.
  // Foreign keys OFF for the rebuild (backups has only self-referential FKs).
  // Guarded on the live CHECK still naming 'daily-auto' (from sqlite_master), so
  // it is a no-op on fresh installs and already-migrated databases. Idempotent.
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
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        db.exec(newBackupsDdl);
        const backupColNames = db
          .prepare("PRAGMA table_info(backups)")
          .all()
          .map(c => '"' + c.name + '"');
        const colList = backupColNames.join(', ');
        const selectList = backupColNames
          .map(c => (c === '"type"'
            ? "CASE WHEN type = 'daily-auto' THEN 'scheduled' ELSE type END"
            : c))
          .join(', ');
        const copiedCount = db.prepare('SELECT COUNT(*) AS n FROM backups').get().n;
        db.exec('INSERT INTO backups_new (' + colList + ') SELECT ' + selectList + ' FROM backups');
        db.exec('DROP TABLE backups');
        db.exec('ALTER TABLE backups_new RENAME TO backups');
        db.exec('COMMIT');
        console.log('backups migration (B6c post-3): renamed, preserved ' + copiedCount + ' backup row(s)');
      } catch (renameRebuildErr) {
        db.exec('ROLLBACK');
        throw renameRebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  } catch (backupsRenameMigrationErr) {
    console.error('backups migration (B6c post-3) failed (non-fatal):', backupsRenameMigrationErr.message);
  }

  // ── R3k C12 — cloud_packages table ────────────────────────────────────
  //
  // Persistence layer for the Cloud & IaC generator (Sub-phase 4 / C13).
  // One row per generated deployment bundle, capturing the manifest +
  // SBOM + signature paths and SHA-256 hashes, the signing key id that
  // produced the signature, and a JSON snapshot of the current install
  // at generation time (users count, integrations list with platform
  // names but no credentials, encryption mode, KMS provider, data
  // volume — per the locked Q1 decision; the snapshot lets the bundle
  // be regenerated or audited later without re-inspecting the install).
  //
  // SCHEMA NOTES
  //
  //   id                       UUID-shape, matching the R3j/R3k C1
  //                            convention.
  //   provider, iac_tool       CHECK-constrained enums covering the
  //                            6 providers and 9 IaC output formats
  //                            from the Q1/Q2 locked decisions. Not
  //                            every (provider, iac_tool) combination
  //                            is valid (CloudFormation is AWS-only,
  //                            Bicep is Azure-only, GCP Deployment
  //                            Manager is GCP-only); the route handler
  //                            in C19 validates the combination
  //                            before invoking the generator. The
  //                            CHECK constraints are the load-bearing
  //                            invariant at the DB layer.
  //   generated_by             FK to users(id) without ON DELETE
  //                            CASCADE — deleting the originating
  //                            user preserves their generated
  //                            bundles for audit (C19 listing
  //                            surfaces "user deleted" instead of
  //                            hiding the row).
  //   signing_key_id           FK to cloud_iac_signing_keys(id) —
  //                            preserved even after key rotation so
  //                            the verification path can fetch the
  //                            public key for any historical signed
  //                            bundle.
  //   install_snapshot_json    JSON blob with the at-generation-time
  //                            install posture summary. Does NOT
  //                            contain credentials.
  //
  // Indexes:
  //
  //   idx_cloud_packages_provider_tool   filters the listing by
  //                                       (provider, iac_tool) — the
  //                                       MC Cloud tab will surface
  //                                       this filter once C20 wires
  //                                       the showIaC modal to the
  //                                       canonical listing endpoint.
  //   idx_cloud_packages_generated_at    reverse-chronological listing
  //                                       sort, the default order in
  //                                       the lead's "recent bundles"
  //                                       view.
  //
  // Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT
  // EXISTS. Own try/catch for fault isolation; a failure here does
  // not mask any prior R3e/R3g/R3h/R3i/R3j/R3k-C1/R3k-C2 migration.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS cloud_packages (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        provider TEXT NOT NULL
          CHECK (provider IN ('aws', 'azure', 'gcp')),
        iac_tool TEXT NOT NULL
          CHECK (iac_tool IN (
            'terraform', 'pulumi', 'cloudformation', 'bicep', 'gcp-dm'
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
    `);

    // Cloud Mode (B5h): tighten the cloud_packages provider/iac_tool CHECKs.
    // The provider/format matrix was narrowed to the three confidential-VM
    // clouds (aws/azure/gcp) with VM IaC formats only; SQLite cannot ALTER a
    // CHECK, so an existing table that still carries the old constraint is
    // rebuilt with the tight schema. Pre-release, bundles are regenerable, so
    // any row with a now-dropped provider or format is not carried over.
    // Idempotent: only runs when an old constraint token is present, and the
    // rebuilt table contains none of them so it never re-triggers. Mirrors the
    // foreign_keys-off + transactional rebuild pattern used above.
    const cpRow = db
      .prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='cloud_packages'")
      .get();
    const cpNeedsRebuild = !!(cpRow && cpRow.sql && (
      cpRow.sql.indexOf('hetzner') !== -1
      || cpRow.sql.indexOf('ovhcloud') !== -1
      || cpRow.sql.indexOf('exoscale') !== -1
      || cpRow.sql.indexOf('docker-compose') !== -1
      || cpRow.sql.indexOf('docker-manifest') !== -1
      || cpRow.sql.indexOf('kubernetes') !== -1
    ));
    if (cpNeedsRebuild) {
      console.log('cloud_packages migration (B5h): rebuilding for cloud-mode provider/format CHECKs');
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        db.exec(`
          CREATE TABLE cloud_packages_new (
            id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
            provider TEXT NOT NULL
              CHECK (provider IN ('aws', 'azure', 'gcp')),
            iac_tool TEXT NOT NULL
              CHECK (iac_tool IN (
                'terraform', 'pulumi', 'cloudformation', 'bicep', 'gcp-dm'
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
        `);
        const cpKept = db
          .prepare("SELECT COUNT(*) AS n FROM cloud_packages WHERE provider IN ('aws', 'azure', 'gcp') AND iac_tool IN ('terraform', 'pulumi', 'cloudformation', 'bicep', 'gcp-dm')")
          .get().n;
        db.exec(`
          INSERT INTO cloud_packages_new
            (id, provider, iac_tool, generated_at, generated_by, bundle_dir_path,
             bundle_archive_path, manifest_sha256, sbom_path, sbom_sha256,
             signature_path, signature_sha256, signing_key_id, install_snapshot_json, size_bytes)
          SELECT
            id, provider, iac_tool, generated_at, generated_by, bundle_dir_path,
            bundle_archive_path, manifest_sha256, sbom_path, sbom_sha256,
            signature_path, signature_sha256, signing_key_id, install_snapshot_json, size_bytes
          FROM cloud_packages
          WHERE provider IN ('aws', 'azure', 'gcp')
            AND iac_tool IN ('terraform', 'pulumi', 'cloudformation', 'bicep', 'gcp-dm');
        `);
        db.exec('DROP TABLE cloud_packages');
        db.exec('ALTER TABLE cloud_packages_new RENAME TO cloud_packages');
        db.exec('CREATE INDEX IF NOT EXISTS idx_cloud_packages_provider_tool ON cloud_packages (provider, iac_tool)');
        db.exec('CREATE INDEX IF NOT EXISTS idx_cloud_packages_generated_at ON cloud_packages (generated_at)');
        db.exec('COMMIT');
        console.log(`cloud_packages migration (B5h): rebuilt, preserved ${cpKept} package(s)`);
      } catch (cpRebuildErr) {
        db.exec('ROLLBACK');
        throw cpRebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_cloud_packages_provider_tool
        ON cloud_packages (provider, iac_tool);
    `);

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_cloud_packages_generated_at
        ON cloud_packages (generated_at);
    `);

    const pkgCount = db
      .prepare('SELECT COUNT(*) AS n FROM cloud_packages')
      .get().n;
    console.log(
      `R3k migration: cloud_packages table ready (${pkgCount} package(s) present)`
    );
  } catch (r3kCloudPackagesMigrationErr) {
    console.error(
      'R3k cloud_packages migration FAILED:',
      r3kCloudPackagesMigrationErr.message
    );
    console.error(
      'The server will start, but the Cloud & IaC generator (POST /api/cloud/package) will fail until this migration completes successfully — generated bundles need a row in this table for the manifest + signature + SBOM tracking and for download-by-id retrieval. All other R3k surfaces (CI/CD, backup full-suite, regression) are independent and continue to function.'
    );
  }

  // ── R3n: default config rows for helper_pay_config + peer_share_exclusion_cap ─
  //
  // Both rows live in the team_config key-value store (PRIMARY KEY = key).
  // Idempotent INSERT OR IGNORE pattern matches the R3j routing_enabled
  // backfill above: re-running this migration against an already-seeded
  // database is a no-op; if the lead has already saved a non-default
  // value via the MC UI, the existing row is preserved.
  //
  // Fault isolation: separate try/catch from R3k cloud_packages. A
  // failure here does not mask preceding migrations.
  try {
    const helperPayDefaults = JSON.stringify({
      enabled: true,
      pointsThreshold: 50,
      payDifferentialPct: 5,
      designatedHelperThreshold: 100,
    });
    const insertResult = db
      .prepare(
        "INSERT OR IGNORE INTO team_config (key, value, updated_by) VALUES ('helper_pay_config', ?, NULL)"
      )
      .run(helperPayDefaults);

    if (insertResult.changes > 0) {
      console.log('R3n migration: seeded helper_pay_config defaults in team_config');
    } else {
      console.log('R3n migration: helper_pay_config row already present in team_config');
    }
  } catch (r3nHelperPayConfigMigrationErr) {
    console.error(
      'R3n helper_pay_config migration FAILED:',
      r3nHelperPayConfigMigrationErr.message
    );
    console.error(
      'The server will start, but the Helper Pay Configuration card in the MC will fall back to defaults via the GET /api/helper-pay/config _source:"default" path. Saving from the MC will succeed and create the row via UPSERT.'
    );
  }

  try {
    const peerCapDefaults = JSON.stringify({
      maxExcludedFraction: 0.5,
    });
    const insertResult = db
      .prepare(
        "INSERT OR IGNORE INTO team_config (key, value, updated_by) VALUES ('peer_share_exclusion_cap', ?, NULL)"
      )
      .run(peerCapDefaults);

    if (insertResult.changes > 0) {
      console.log('R3n migration: seeded peer_share_exclusion_cap default in team_config');
    } else {
      console.log('R3n migration: peer_share_exclusion_cap row already present in team_config');
    }
  } catch (r3nPeerCapMigrationErr) {
    console.error(
      'R3n peer_share_exclusion_cap migration FAILED:',
      r3nPeerCapMigrationErr.message
    );
    console.error(
      'The server will start, but the peer-share submission endpoint (POST /api/peers/requests) hardcodes 0.5 as the cap in C10 — the team_config row is informational at v1.0.40 and only consulted by a future UI for cap-editing. No functional impact.'
    );
  }

  // ── N1a: Multi-Channel Notification Delivery schema extensions ──────────────
  //
  // Five schema migrations needed before N1a can wire SMS + desktop channels:
  //   (1) notification_preferences gains sms + desktop columns (per-user opt-in)
  //   (2) notifications gains sms_delivery_status + desktop_delivery_status
  //   (3) notification_config gains sms_provider + sms_account_sid +
  //       sms_auth_token_encrypted + sms_from_number (the SMS provider config
  //       columns; sms_enabled + sms_number are already present from earlier
  //       partial staging)
  //   (4) New notification_delivery_log table for per-attempt audit
  //   (5) New lead_notification_contacts table — per-lead phone + email storage
  //       for SMS + email notification channels. Structurally restricted to
  //       non-anonymous roles (lead, admin) via API role-gating;
  //       analyst-role users NEVER have rows here. Anonymity-preservation by
  //       design (see anonymity-preservation note below + N1a C7).
  //
  // All five migrations are idempotent. The ALTER TABLE adds use PRAGMA
  // table_info() to check column presence before adding — avoids the "duplicate
  // column name" error on re-run. The CREATE TABLE uses IF NOT EXISTS. Each
  // migration has its own try/catch for fault isolation; one failure does not
  // mask another or block subsequent migrations.
  //
  // Privacy note on notification_delivery_log: recipient handles (email
  // addresses, phone numbers) are SHA-256 hashed before storage in the
  // recipient_handle_hash column — never plaintext. Forensic investigations
  // join via notification_id → notifications.recipient_id to identify the user.
  // This is consistent with FireAlive's Tier-3 protection principles for
  // PII-in-audit-logs.
  //
  // Anonymity-preservation note on lead_notification_contacts: this table is
  // structurally restricted to non-anonymous roles (lead, admin).
  // Analyst-role users NEVER have rows here — three layers of defense:
  //   (a) AC preference UI hides email + SMS channel checkboxes entirely
  //   (b) API PUT /api/users/me/lead-contacts rejects analyst-role callers
  //       with HTTP 403 + code ANALYST_CONTACT_STORAGE_BLOCKED
  //   (c) Dispatch path resolvePreference() forces email + sms to false for
  //       analyst-role lookups regardless of stored notification_preferences
  //       values (see N1a C7 — defense against compromised DB tampering)
  // The table NAME itself signals "identified users only." ON DELETE CASCADE
  // on user_id ensures clean offboarding wipes contact info atomically with
  // user deletion. Storage is plaintext (not encrypted at rest) because these
  // are identifying info for non-anonymous users — consistent with existing
  // users.name + users.username plaintext storage. The columns are NOT
  // credentials (unlike sms_auth_token_encrypted) and do not warrant the
  // encryption-at-rest treatment applied to provider auth tokens.

  try {
    const cols = db
      .prepare("PRAGMA table_info(notification_preferences)")
      .all()
      .map((c) => c.name);
    let added = 0;
    if (!cols.includes('sms')) {
      db.prepare(
        "ALTER TABLE notification_preferences ADD COLUMN sms INTEGER NOT NULL DEFAULT 0"
      ).run();
      added++;
    }
    if (!cols.includes('desktop')) {
      db.prepare(
        "ALTER TABLE notification_preferences ADD COLUMN desktop INTEGER NOT NULL DEFAULT 1"
      ).run();
      added++;
    }
    if (added > 0) {
      console.log(
        `N1a migration: added ${added} column(s) to notification_preferences (sms, desktop)`
      );
    } else {
      console.log(
        'N1a migration: notification_preferences already has sms + desktop columns'
      );
    }
  } catch (n1aPrefsMigrationErr) {
    console.error(
      'N1a notification_preferences migration FAILED:',
      n1aPrefsMigrationErr.message
    );
    console.error(
      'The server will start, but SMS and desktop notification preferences will not be persisted. Users will see the UI checkboxes but their selections will not save. Email + in-app channels continue to work normally.'
    );
  }

  try {
    const cols = db
      .prepare("PRAGMA table_info(notifications)")
      .all()
      .map((c) => c.name);
    let added = 0;
    if (!cols.includes('sms_delivery_status')) {
      db.prepare(
        "ALTER TABLE notifications ADD COLUMN sms_delivery_status TEXT"
      ).run();
      added++;
    }
    if (!cols.includes('desktop_delivery_status')) {
      db.prepare(
        "ALTER TABLE notifications ADD COLUMN desktop_delivery_status TEXT"
      ).run();
      added++;
    }
    if (added > 0) {
      console.log(
        `N1a migration: added ${added} column(s) to notifications (sms_delivery_status, desktop_delivery_status)`
      );
    } else {
      console.log(
        'N1a migration: notifications already has sms_delivery_status + desktop_delivery_status columns'
      );
    }
  } catch (n1aNotifsMigrationErr) {
    console.error(
      'N1a notifications migration FAILED:',
      n1aNotifsMigrationErr.message
    );
    console.error(
      'The server will start, but the SMS and desktop notification pipelines will be unable to track per-row delivery status on this table. New notifications will still be created via the in-app channel; SMS/desktop dispatch will fall back to the notification_delivery_log table for status tracking. Recovery: drop and recreate the notifications table from a fresh DB OR manually run the ALTER TABLE statements once.'
    );
  }

  try {
    const cols = db
      .prepare("PRAGMA table_info(notification_config)")
      .all()
      .map((c) => c.name);
    let added = 0;
    if (!cols.includes('sms_provider')) {
      db.prepare(
        "ALTER TABLE notification_config ADD COLUMN sms_provider TEXT"
      ).run();
      added++;
    }
    if (!cols.includes('sms_account_sid')) {
      db.prepare(
        "ALTER TABLE notification_config ADD COLUMN sms_account_sid TEXT"
      ).run();
      added++;
    }
    if (!cols.includes('sms_auth_token_encrypted')) {
      db.prepare(
        "ALTER TABLE notification_config ADD COLUMN sms_auth_token_encrypted BLOB"
      ).run();
      added++;
    }
    if (!cols.includes('sms_from_number')) {
      db.prepare(
        "ALTER TABLE notification_config ADD COLUMN sms_from_number TEXT"
      ).run();
      added++;
    }
    if (added > 0) {
      console.log(
        `N1a migration: added ${added} SMS provider column(s) to notification_config (sms_provider, sms_account_sid, sms_auth_token_encrypted, sms_from_number)`
      );
    } else {
      console.log(
        'N1a migration: notification_config already has all 4 SMS provider columns'
      );
    }
  } catch (n1aConfigMigrationErr) {
    console.error(
      'N1a notification_config migration FAILED:',
      n1aConfigMigrationErr.message
    );
    console.error(
      'The server will start, but SMS provider configuration cannot be persisted. The MC SMS Provider Config Card will fail to save. SMS delivery will be unavailable. Email + webhook + PagerDuty channels continue to work via the existing notification_config columns. Recovery: manually run the four ALTER TABLE statements in a SQLite shell against the production DB.'
    );
  }

  try {
    db.prepare(
      `CREATE TABLE IF NOT EXISTS notification_delivery_log (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        notification_id TEXT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
        channel TEXT NOT NULL CHECK (channel IN ('in_app', 'email', 'sms', 'desktop', 'webhook', 'pagerduty')),
        attempt_number INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL CHECK (status IN ('queued', 'sending', 'sent', 'failed', 'bounced', 'timeout', 'skipped')),
        transport_provider TEXT,
        transport_message_id TEXT,
        recipient_handle_hash TEXT,
        error_message TEXT,
        latency_ms INTEGER,
        attempted_at TEXT NOT NULL DEFAULT (datetime('now')),
        completed_at TEXT
      )`
    ).run();
    db.prepare(
      "CREATE INDEX IF NOT EXISTS idx_notification_delivery_log_notification ON notification_delivery_log(notification_id)"
    ).run();
    db.prepare(
      "CREATE INDEX IF NOT EXISTS idx_notification_delivery_log_status ON notification_delivery_log(status, attempted_at) WHERE status IN ('failed', 'bounced', 'timeout')"
    ).run();

    const rowCount = db
      .prepare("SELECT COUNT(*) as c FROM notification_delivery_log")
      .get().c;
    console.log(
      `N1a migration: notification_delivery_log table ready (${rowCount} row(s) present)`
    );
  } catch (n1aDeliveryLogMigrationErr) {
    console.error(
      'N1a notification_delivery_log migration FAILED:',
      n1aDeliveryLogMigrationErr.message
    );
    console.error(
      'The server will start, but per-attempt delivery audit trail (DORA Article 14 compliance) will be unavailable. Notification pipelines will continue to deliver, but each attempt will not be logged with retry metadata, transport provider, or message IDs. Forensic investigation of delivery failures will rely on the per-row *_delivery_status fields on the notifications table only. Recovery: manually run the CREATE TABLE + CREATE INDEX statements in a SQLite shell.'
    );
  }

  try {
    db.prepare(
      `CREATE TABLE IF NOT EXISTS lead_notification_contacts (
        user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        email TEXT,
        phone TEXT,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )`
    ).run();
    db.prepare(
      "CREATE INDEX IF NOT EXISTS idx_lead_notification_contacts_updated ON lead_notification_contacts(updated_at)"
    ).run();

    const rowCount = db
      .prepare("SELECT COUNT(*) as c FROM lead_notification_contacts")
      .get().c;
    console.log(
      `N1a migration: lead_notification_contacts table ready (${rowCount} row(s) present)`
    );
  } catch (n1aLeadContactsMigrationErr) {
    console.error(
      'N1a lead_notification_contacts migration FAILED:',
      n1aLeadContactsMigrationErr.message
    );
    console.error(
      'The server will start, but lead/admin users cannot register personal phone or email for SMS/email notifications. The MC "Your Contact Info" Card (Notification Preferences tab) will fail to save; PUT /api/users/me/lead-contacts will return 500. SMS and email dispatch attempts for lead users will skip with audit reason="no_lead_phone_registered" or "no_lead_email_registered". In-app + desktop channels continue to function normally for all roles. Analyst-role users are unaffected (this table never holds analyst rows by design — anonymity preservation). Recovery: manually run the CREATE TABLE + CREATE INDEX statements in a SQLite shell against the production DB.'
    );
  }

  // ── B1: Cloud Vulnerability Scan — scanner authorization registry +
  // tamper-evident scan-access log ─────────────────────────────────────────────
  // Authorizes external cloud-posture / IaC scanners (ScoutSuite, Prowler, Pacu,
  // CloudBrute, Checkov) to scan FireAlive's cloud deployment. FireAlive does NOT
  // run scans and does NOT ingest/parse/store findings — those live in the
  // scanner's own application. This integration records WHICH scanners are
  // authorized (per-authorization bearer token stored hashed + source-IP/CIDR
  // allow-list) and logs EVERY scan access (authorized or rejected) in an
  // append-only, hash-chained log so the SOC has a tamper-evident record of when
  // FireAlive was scanned. Coverage spans the deployed suite (MC / AC / ARC /
  // main server / GD-server); the GD-server keeps its own duplicated config.
  // Application-layer enforcement only — network-layer blocking remains the
  // operator's firewall responsibility.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS cloud_vuln_scanner_authorizations (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        scanner_type TEXT NOT NULL CHECK (scanner_type IN (
          'scoutsuite',
          'prowler',
          'pacu',
          'cloudbrute',
          'checkov'
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
          'authorized',
          'rejected_ip',
          'rejected_token',
          'rejected_disabled',
          'rejected_unknown'
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
    `);
    const cloudVulnAuthCount = db
      .prepare("SELECT COUNT(*) as c FROM cloud_vuln_scanner_authorizations")
      .get().c;
    console.log(
      `B1 migration: cloud_vuln_scanner_authorizations + cloud_vuln_scan_access_log ready (${cloudVulnAuthCount} authorization(s) present)`
    );
  } catch (b1CloudVulnMigrationErr) {
    console.error(
      'B1 cloud_vuln_scan migration FAILED:',
      b1CloudVulnMigrationErr.message
    );
    console.error(
      'The server will start, but the Cloud Vulnerability Scan tab cannot register scanner authorizations or record scan access: GET/POST/PUT/DELETE /api/cloud-vuln/* will return 500, and authorized scans will not be logged. No other feature is affected. Recovery: manually run the CREATE TABLE / CREATE INDEX / CREATE TRIGGER statements above in a SQLite shell against the production DB.'
    );
  }

  // B5p: Vulnerability Scanner Integration -- on-prem scanner authorization +
  // tamper-evident scan-access log. The on-prem peer of cloud_vuln (B1).
  // Authorizes the org's approved on-prem / network vulnerability scanners
  // (Nessus, OpenVAS, Qualys, Rapid7, Tenable.io, Nuclei) to scan the FireAlive
  // instance itself. FireAlive does NOT run scans and does NOT ingest/parse/store
  // findings -- those live in the scanner's own application. This integration
  // records WHICH scanners are authorized (per-authorization bearer token stored
  // hashed + source-IP/CIDR allow-list) and logs EVERY scan access (authorized
  // or rejected) in an append-only, hash-chained log so the SOC has a
  // tamper-evident record of when FireAlive was scanned. Application-layer
  // enforcement only -- network-layer blocking remains the operator's firewall
  // responsibility.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS vuln_scan_scanner_authorizations (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        scanner_type TEXT NOT NULL CHECK (scanner_type IN (
          'nessus',
          'openvas',
          'qualys',
          'rapid7',
          'tenable_io',
          'nuclei'
        )),
        display_name TEXT NOT NULL,
        allowed_cidrs TEXT NOT NULL DEFAULT '[]',
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

      CREATE INDEX IF NOT EXISTS idx_vuln_scan_auth_enabled
        ON vuln_scan_scanner_authorizations(enabled, scanner_type);

      CREATE TABLE IF NOT EXISTS vuln_scan_access_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prev_hash TEXT,
        this_hash TEXT NOT NULL,
        authorization_id TEXT REFERENCES vuln_scan_scanner_authorizations(id) ON DELETE SET NULL,
        scanner_type TEXT,
        source_ip TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK (outcome IN (
          'authorized',
          'rejected_ip',
          'rejected_token',
          'rejected_disabled',
          'rejected_unknown'
        )),
        request_path TEXT,
        user_agent TEXT,
        detail TEXT,
        accessed_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_vuln_scan_access_accessed_at
        ON vuln_scan_access_log(accessed_at DESC);
      CREATE INDEX IF NOT EXISTS idx_vuln_scan_access_outcome
        ON vuln_scan_access_log(outcome);
      CREATE INDEX IF NOT EXISTS idx_vuln_scan_access_auth
        ON vuln_scan_access_log(authorization_id);

      CREATE TRIGGER IF NOT EXISTS vuln_scan_access_log_no_update
        BEFORE UPDATE ON vuln_scan_access_log
        BEGIN SELECT RAISE(ABORT, 'vuln_scan_access_log is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS vuln_scan_access_log_no_delete
        BEFORE DELETE ON vuln_scan_access_log
        BEGIN SELECT RAISE(ABORT, 'vuln_scan_access_log is append-only'); END;
    `);
    const vulnScanAuthCount = db
      .prepare("SELECT COUNT(*) as c FROM vuln_scan_scanner_authorizations")
      .get().c;
    console.log(
      `B5p migration: vuln_scan_scanner_authorizations + vuln_scan_access_log ready (${vulnScanAuthCount} authorization(s) present)`
    );
  } catch (b5pVulnScanMigrationErr) {
    console.error(
      'B5p vuln_scan migration FAILED:',
      b5pVulnScanMigrationErr.message
    );
    console.error(
      'The server will start, but the Vulnerability Scan tab cannot register scanner authorizations or record scan access: GET/POST/PUT/DELETE /api/vuln-scan/* will return 500, and authorized scans will not be logged. No other feature is affected. Recovery: manually run the CREATE TABLE / CREATE INDEX / CREATE TRIGGER statements above in a SQLite shell against the production DB.'
    );
  }


  // ── B5m: threat-hunting consumer authorizations + access log ────────────────
  // The read-only exposure surface that lets the org's EDR / XDR / ATP / NGAV /
  // MSP tooling pull FireAlive's own security telemetry to hunt for an attacker
  // inside a FireAlive instance. Per authorization: a FireAlive-CA-issued
  // consumer client cert (fingerprint bound here), a hashed bearer token, and a
  // CIDR allow-list -- all three required at the gate. Every access (allow or
  // deny) is written to the append-only, hash-chained access log. New tables via
  // CREATE IF NOT EXISTS (safe on existing DBs).
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS threat_hunting_consumer_authorizations (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        consumer_type TEXT NOT NULL CHECK (consumer_type IN (
          'xdr',
          'atp',
          'ngav',
          'msp'
        )),
        display_name TEXT NOT NULL,
        allowed_cidrs TEXT NOT NULL DEFAULT '[]',
        cert_fingerprint TEXT NOT NULL,
        cert_serial TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        token_salt TEXT NOT NULL,
        default_format TEXT NOT NULL DEFAULT 'json' CHECK (default_format IN (
          'json',
          'cef',
          'ocsf',
          'stix'
        )),
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_access_at TEXT,
        last_access_source_ip TEXT,
        revoked_at TEXT,
        notes TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_threat_hunting_auth_enabled
        ON threat_hunting_consumer_authorizations(enabled, consumer_type);
      CREATE INDEX IF NOT EXISTS idx_threat_hunting_auth_fingerprint
        ON threat_hunting_consumer_authorizations(cert_fingerprint);

      CREATE TABLE IF NOT EXISTS threat_hunting_access_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prev_hash TEXT,
        this_hash TEXT NOT NULL,
        authorization_id TEXT REFERENCES threat_hunting_consumer_authorizations(id) ON DELETE SET NULL,
        consumer_type TEXT,
        source_ip TEXT NOT NULL,
        cert_fingerprint TEXT,
        endpoint TEXT NOT NULL,
        format TEXT,
        query_summary TEXT,
        outcome TEXT NOT NULL CHECK (outcome IN (
          'authorized',
          'rejected_cert',
          'rejected_token',
          'rejected_ip',
          'rejected_disabled',
          'rejected_category',
          'rejected_query'
        )),
        result_count INTEGER,
        accessed_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_threat_hunting_access_accessed_at
        ON threat_hunting_access_log(accessed_at DESC);
      CREATE INDEX IF NOT EXISTS idx_threat_hunting_access_outcome
        ON threat_hunting_access_log(outcome);
      CREATE INDEX IF NOT EXISTS idx_threat_hunting_access_auth
        ON threat_hunting_access_log(authorization_id);

      CREATE TRIGGER IF NOT EXISTS threat_hunting_access_log_no_update
        BEFORE UPDATE ON threat_hunting_access_log
        BEGIN SELECT RAISE(ABORT, 'threat_hunting_access_log is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS threat_hunting_access_log_no_delete
        BEFORE DELETE ON threat_hunting_access_log
        BEGIN SELECT RAISE(ABORT, 'threat_hunting_access_log is append-only'); END;
    `);
    const threatHuntingAuthCount = db
      .prepare("SELECT COUNT(*) as c FROM threat_hunting_consumer_authorizations")
      .get().c;
    console.log(
      'B5m migration: threat_hunting_consumer_authorizations + threat_hunting_access_log ready (' +
        threatHuntingAuthCount + ' authorization(s) present)'
    );
  } catch (b5mThreatHuntingMigrationErr) {
    console.error(
      'B5m threat_hunting migration FAILED:',
      b5mThreatHuntingMigrationErr.message
    );
    console.error(
      'The server will start, but the Threat Hunting Integrations tab cannot register consumer authorizations or record telemetry access: GET/POST/PUT/DELETE /api/threat-hunting/* will return 500, and the threat-hunting feed and TAXII endpoints will reject all access. No other feature is affected. Recovery: manually run the CREATE TABLE / CREATE INDEX / CREATE TRIGGER statements above in a SQLite shell against the production DB.'
    );
  }

  // ── B1 (W2): model-file integrity & safety gate — server-side scan log ──────
  // Append-only, per-layer record of every server-side model-file gate decision
  // (hash-pin / signature / GGUF format / malware scan) made before a model is
  // loaded. New table via CREATE IF NOT EXISTS (safe on existing DBs).
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS model_file_scan_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_id TEXT NOT NULL,
        file_name TEXT,
        sha256 TEXT,
        hash_pin_ok INTEGER CHECK (hash_pin_ok IN (0, 1)),
        signature_checked INTEGER NOT NULL DEFAULT 0 CHECK (signature_checked IN (0, 1)),
        signature_ok INTEGER CHECK (signature_ok IN (0, 1)),
        format_ok INTEGER CHECK (format_ok IN (0, 1)),
        malware_scanner TEXT,
        malware_outcome TEXT CHECK (malware_outcome IN ('clean', 'threat', 'error', 'skipped')),
        threats TEXT NOT NULL DEFAULT '[]',
        overall_outcome TEXT NOT NULL CHECK (overall_outcome IN (
          'loaded', 'blocked_hash', 'blocked_signature', 'blocked_format',
          'blocked_malware', 'blocked_no_scanner', 'error'
        )),
        detail TEXT,
        actor TEXT,
        scanned_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_model_file_scan_log_scanned_at
        ON model_file_scan_log(scanned_at DESC);
      CREATE INDEX IF NOT EXISTS idx_model_file_scan_log_model
        ON model_file_scan_log(model_id, overall_outcome);

      CREATE TRIGGER IF NOT EXISTS model_file_scan_log_no_update
        BEFORE UPDATE ON model_file_scan_log
        BEGIN SELECT RAISE(ABORT, 'model_file_scan_log is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS model_file_scan_log_no_delete
        BEFORE DELETE ON model_file_scan_log
        BEGIN SELECT RAISE(ABORT, 'model_file_scan_log is append-only'); END;
    `);
    const modelScanRows = db
      .prepare("SELECT COUNT(*) as c FROM model_file_scan_log")
      .get().c;
    console.log(
      `B1 migration: model_file_scan_log ready (${modelScanRows} scan record(s) present)`
    );
  } catch (b1ModelScanMigrationErr) {
    console.error(
      'B1 model_file_scan migration FAILED:',
      b1ModelScanMigrationErr.message
    );
    console.error(
      'The server will start, but server-side model-file gate decisions cannot be recorded: the integrity & safety gate still runs and fail-closes, only its audit log is unavailable. No other feature is affected. Recovery: run the CREATE TABLE / CREATE INDEX / CREATE TRIGGER statements above in a SQLite shell against the production DB.'
    );
  }

  // ── B4: Compromise Scan Orchestration + Reduced-Routing Tripwire schema ─────
  // MC-orchestrated compromise scans across analyst clients (each AC runs a
  // 10-point self-scan and returns an Ed25519 device-signed result), the
  // offline-target delivery queue, per-AC device signing keys (public key only
  // server-side; the private key never leaves the AC), and the reduced-routing
  // tripwire detector's trip-event ledger. Config defaults seed into team_config.
  // All idempotent (CREATE IF NOT EXISTS / INSERT OR IGNORE), safe on existing DBs.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS compromise_scan_runs (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        trigger TEXT NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'tripwire', 'api')),
        initiated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        targets_json TEXT NOT NULL DEFAULT '"all"',
        target_count INTEGER NOT NULL DEFAULT 0,
        completed_count INTEGER NOT NULL DEFAULT 0,
        unreachable_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'complete', 'partial')),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        completed_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_compromise_scan_runs_created_at
        ON compromise_scan_runs(created_at DESC);

      CREATE TABLE IF NOT EXISTS compromise_scan_results (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        run_id TEXT NOT NULL REFERENCES compromise_scan_runs(id) ON DELETE CASCADE,
        user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        pseudonym_at_scan TEXT,
        status TEXT NOT NULL CHECK (status IN ('clean', 'warning', 'fail', 'inconclusive', 'unreachable')),
        tests_total INTEGER NOT NULL DEFAULT 0,
        tests_passed INTEGER NOT NULL DEFAULT 0,
        tests_failed INTEGER NOT NULL DEFAULT 0,
        tests_inconclusive INTEGER NOT NULL DEFAULT 0,
        details_json TEXT NOT NULL DEFAULT '[]',
        signature TEXT,
        signature_verified INTEGER NOT NULL DEFAULT 0 CHECK (signature_verified IN (0, 1)),
        signed_at TEXT,
        scan_started_at TEXT,
        scan_duration_ms INTEGER,
        received_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_compromise_scan_results_run
        ON compromise_scan_results(run_id);
      CREATE INDEX IF NOT EXISTS idx_compromise_scan_results_user
        ON compromise_scan_results(user_id, received_at DESC);

      CREATE TABLE IF NOT EXISTS ac_device_signing_keys (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        public_key TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
        registered_at TEXT NOT NULL DEFAULT (datetime('now')),
        retired_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_ac_device_signing_keys_user
        ON ac_device_signing_keys(user_id, active);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_ac_device_signing_keys_one_active
        ON ac_device_signing_keys(user_id) WHERE active = 1;

      CREATE TABLE IF NOT EXISTS mc_device_signing_keys (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        public_key TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
        registered_at TEXT NOT NULL DEFAULT (datetime('now')),
        retired_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_mc_device_signing_keys_user
        ON mc_device_signing_keys(user_id, active);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_mc_device_signing_keys_one_active
        ON mc_device_signing_keys(user_id) WHERE active = 1;

      CREATE TABLE IF NOT EXISTS recovery_action_approvals (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        action TEXT NOT NULL CHECK (action IN ('teardown', 'reprovision')),
        target_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        reason TEXT,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'approved', 'executed', 'rejected', 'expired', 'cancelled')),
        requested_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        requester_fingerprint TEXT NOT NULL,
        requested_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        approval_kind TEXT CHECK (approval_kind IN ('operator', 'gd')),
        approved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        approver_fingerprint TEXT,
        decided_at TEXT,
        recovery_run_id TEXT REFERENCES client_recovery_runs(id) ON DELETE SET NULL,
        executed_at TEXT,
        error TEXT,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_recovery_action_approvals_status
        ON recovery_action_approvals(status, expires_at);
      CREATE INDEX IF NOT EXISTS idx_recovery_action_approvals_target
        ON recovery_action_approvals(target_user_id, status);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_action_approvals_one_pending
        ON recovery_action_approvals(target_user_id, action) WHERE status = 'pending';

      CREATE TABLE IF NOT EXISTS compromise_scan_queue (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        run_id TEXT NOT NULL REFERENCES compromise_scan_runs(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'delivered', 'expired')),
        queued_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        delivered_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_compromise_scan_queue_user
        ON compromise_scan_queue(user_id, status);

      CREATE TABLE IF NOT EXISTS tripwire_events (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        tripped_at TEXT NOT NULL DEFAULT (datetime('now')),
        trigger_signals_json TEXT NOT NULL DEFAULT '{}',
        pct_in_reduced REAL,
        segment TEXT NOT NULL DEFAULT 'global',
        verdict TEXT,
        response_json TEXT NOT NULL DEFAULT '{}',
        scan_run_id TEXT REFERENCES compromise_scan_runs(id) ON DELETE SET NULL,
        lockout_active INTEGER NOT NULL DEFAULT 0 CHECK (lockout_active IN (0, 1)),
        resolved_at TEXT,
        resolved_by TEXT REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE INDEX IF NOT EXISTS idx_tripwire_events_tripped_at
        ON tripwire_events(tripped_at DESC);
      CREATE INDEX IF NOT EXISTS idx_tripwire_events_lockout
        ON tripwire_events(lockout_active);
    `);
    const tripwireDefaults = JSON.stringify({
      enabled: true,
      threshold_pct: 60,
      window_minutes: 10,
      signal_weights: {
        velocity: 1.0,
        breadth: 1.0,
        slope: 1.0,
        signal_justification: 2.0,
        uniformity: 1.0,
        corroboration: 1.0
      },
      trip_score: 3.0,
      response: {
        auto_disable_routing: true,
        notify_lead: true,
        trigger_compromise_scan: true,
        trigger_soar: true
      },
      per_segment: true
    });
    db.prepare(
      "INSERT OR IGNORE INTO team_config (key, value, updated_by) VALUES ('tripwire_config', ?, NULL)"
    ).run(tripwireDefaults);
    db.prepare(
      "INSERT OR IGNORE INTO team_config (key, value, updated_by) VALUES ('compromise_scan_retention_days', 'null', NULL)"
    ).run();
    const compromiseRunCount = db
      .prepare("SELECT COUNT(*) as c FROM compromise_scan_runs")
      .get().c;
    console.log(
      `B4 migration: compromise_scan_runs + compromise_scan_results + ac_device_signing_keys + compromise_scan_queue + tripwire_events ready (${compromiseRunCount} run(s) present)`
    );
  } catch (b4CompromiseScanMigrationErr) {
    console.error(
      'B4 compromise_scan migration FAILED:',
      b4CompromiseScanMigrationErr.message
    );
    console.error(
      'The server will start, but compromise-scan orchestration and the reduced-routing tripwire cannot persist state: POST /api/compromise/* will return 500 and the tripwire detector will not run. No other feature is affected. Recovery: run the CREATE TABLE / CREATE INDEX statements above in a SQLite shell against the production DB.'
    );
  }

  // ── B5a migration: audit log hash chain + signed checkpoints ──────────────
  // Establishes audit_log.hash / .prev_hash, backfills existing rows into the
  // chain (their stored content is unchanged), writes a baseline signed
  // checkpoint, and installs the audit_log append-only triggers. One-time and
  // idempotent (guarded by the audit_chain_backfilled marker). Runs LAST so
  // every row written earlier in initDb (e.g. the R3l C53 backup_kind audit
  // entries) is captured in the baseline.
  try {
    const auditChain = require('../services/audit-chain');
    const acResult = auditChain.migrateAuditChain(db);
    const acEntries = db.prepare('SELECT COUNT(*) AS c FROM audit_log').get().c;
    if (acResult.migrated) {
      console.log(`B5a migration: audit_log hash chain established (backfilled ${acResult.backfilled} row(s), ${acEntries} total); audit_chain_checkpoint + audit_chain_signing_keys ready; append-only triggers installed`);
    } else {
      console.log(`B5a migration: audit_log hash chain already established (${acEntries} entries)`);
    }
  } catch (b5aAuditChainMigrationErr) {
    console.error('B5a audit-chain migration FAILED:', b5aAuditChainMigrationErr.message);
    console.error('The server will start, but the audit log hash chain is not active: GET /api/audit/integrity will report unavailable and audit tamper-evidence falls back to SIEM ship-out only. No other feature is affected. Recovery: ensure the audit_chain_checkpoint and audit_chain_signing_keys tables exist, then restart to re-run the migration.');
  }

  // ── B5b migration: IAM & SOC-grade authentication ─────────────────────────
  // The built-in Certificate Authority (ca_authority), the certs it issues
  // (issued_certs, with a local revocation list — no OCSP), passwordless FIDO2
  // credentials (webauthn_credentials; is_passwordless=1 marks discoverable
  // login keys), the offboarding detector's surfaced candidates
  // (offboarding_candidates — surface-only, never auto-deactivated), and the
  // one-time break-glass recovery credential (auth_recovery, hash only —
  // plaintext shown once at CA init). All idempotent (CREATE IF NOT EXISTS).
  // The default auth posture is passwordless and is enforced in the auth layer
  // when iam_config is absent, so no config row is seeded here.
  try {
    db.exec(`
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

      CREATE TABLE IF NOT EXISTS offboarding_candidates (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        source TEXT NOT NULL CHECK (source IN ('ldap_absent', 'cert_revoked', 'cert_expired', 'stale')),
        detail TEXT,
        detected_at TEXT NOT NULL DEFAULT (datetime('now')),
        status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed_active', 'offboarded')),
        resolved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        resolved_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_offboarding_candidates_status
        ON offboarding_candidates(status, detected_at DESC);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_offboarding_candidates_open
        ON offboarding_candidates(user_id) WHERE status = 'pending';

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

      -- Bootstrap & recovery enrollment tokens. A single-use, expiring,
      -- revocable token (SHA-256 hash at rest; plaintext shown once at mint)
      -- that authorizes a session-less caller to enroll their FIRST credential
      -- (passkey or client cert). Issued by admin provisioning; redeemed at an
      -- unauthenticated endpoint. Break-glass uses its own signed token, not
      -- this table.
      CREATE TABLE IF NOT EXISTS enrollment_tokens (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL,
        scope TEXT NOT NULL DEFAULT 'first-credential'
          CHECK (scope IN ('first-credential', 're-provision')),
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        used_at TEXT,
        revoked_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_user ON enrollment_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON enrollment_tokens(token_hash);
    `);
    const caCount = db.prepare("SELECT COUNT(*) AS c FROM ca_authority").get().c;
    console.log(`B5b migration: ca_authority + issued_certs + webauthn_credentials + offboarding_candidates + auth_recovery + enrollment_tokens ready (${caCount} CA present)`);
  } catch (b5bIamMigrationErr) {
    console.error('B5b IAM/auth migration FAILED:', b5bIamMigrationErr.message);
    console.error('The server will start, but client-certificate and FIDO2 passkey authentication cannot be provisioned: cert enrollment, passkey registration, the offboarding detector, and break-glass recovery will be unavailable. No other feature is affected. Recovery: run the CREATE TABLE / CREATE INDEX statements above in a SQLite shell against the production DB.');
  }

  // ── B5d4: Per-Client AC Recovery + Fleet Operations schema ─────────────────
  // The per-AC recovery lifecycle (tear-down + re-provision-and-rebind of a
  // single compromised analyst client) and the per-client fleet operations that
  // ride the same B4 WebSocket dispatch substrate (config re-sync, refresh
  // metrics, log integrity, regression, vuln scan, staged update push). One row
  // per recovery (updated as it progresses), a runs table + an offline-delivery
  // queue + device-signed result rows for the fleet ops, all mirroring the B4
  // compromise-scan tables. Idempotent (CREATE IF NOT EXISTS), safe on existing
  // DBs. enrollment_token_id is a plain reference id (no FK) because tokens are
  // single-use and pruned; the recovery run keeps the linkage for audit only.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS client_recovery_runs (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        pseudonym_at_run TEXT,
        status TEXT NOT NULL DEFAULT 'initiated'
          CHECK (status IN ('initiated', 'torn_down', 'token_issued', 'complete', 'cancelled')),
        initiated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        reason TEXT,
        certs_revoked_json TEXT,
        device_key_retired INTEGER NOT NULL DEFAULT 0 CHECK (device_key_retired IN (0, 1)),
        passkey_deleted INTEGER NOT NULL DEFAULT 0 CHECK (passkey_deleted IN (0, 1)),
        wipe_dispatched INTEGER NOT NULL DEFAULT 0 CHECK (wipe_dispatched IN (0, 1)),
        enrollment_token_id TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        completed_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_client_recovery_runs_user
        ON client_recovery_runs(user_id, status);

      CREATE TABLE IF NOT EXISTS client_ops_runs (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        op_type TEXT NOT NULL
          CHECK (op_type IN ('config_resync', 'refresh_metrics', 'log_integrity', 'regression', 'vuln_scan', 'update_push')),
        trigger TEXT NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'api')),
        initiated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        targets_json TEXT NOT NULL DEFAULT '"all"',
        target_count INTEGER NOT NULL DEFAULT 0,
        completed_count INTEGER NOT NULL DEFAULT 0,
        unreachable_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'complete', 'partial')),
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        completed_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_client_ops_runs_created_at
        ON client_ops_runs(created_at DESC);

      CREATE TABLE IF NOT EXISTS client_ops_queue (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        run_id TEXT NOT NULL REFERENCES client_ops_runs(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'delivered', 'expired')),
        queued_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        delivered_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_client_ops_queue_user
        ON client_ops_queue(user_id, status);

      CREATE TABLE IF NOT EXISTS client_ops_results (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        run_id TEXT NOT NULL REFERENCES client_ops_runs(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        pseudonym_at_op TEXT,
        op_type TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('ok', 'warning', 'fail', 'inconclusive', 'ack')),
        detail_json TEXT,
        signature TEXT,
        signature_verified INTEGER NOT NULL DEFAULT 0 CHECK (signature_verified IN (0, 1)),
        signed_at TEXT,
        started_at TEXT,
        duration_ms INTEGER,
        received_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_client_ops_results_run
        ON client_ops_results(run_id);
    `);
    console.log('B5d4 migration: client_recovery_runs + client_ops_runs + client_ops_queue + client_ops_results ready');
  } catch (b5d4SchemaErr) {
    console.error('B5d4 per-client recovery/ops schema migration FAILED:', b5d4SchemaErr.message);
  }

  // ── Migration: widen enrollment_tokens.scope CHECK (B5d4) ──────────────────
  // Per-client recovery (B5d4) mints a re-enrollment token under a new
  // 're-provision' scope. Fresh DBs get the widened CHECK from the B5b block
  // above; existing DBs (v1.0.58 and earlier) carry the single-value CHECK and
  // are rebuilt here. SQLite cannot ALTER a CHECK in place, so the table is
  // recreated with the widened constraint and rows copied verbatim. Foreign
  // keys toggle OFF for the rebuild and back ON afterward. Idempotent: skipped
  // once the stored CHECK already lists 're-provision'.
  try {
    const etRow = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='enrollment_tokens'").get();
    if (etRow && etRow.sql && !etRow.sql.includes('re-provision')) {
      console.log('enrollment_tokens migration (B5d4): widening scope CHECK to include re-provision');
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN TRANSACTION');
      try {
        db.exec(`
          CREATE TABLE enrollment_tokens_new (
            id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT 'first-credential'
              CHECK (scope IN ('first-credential', 're-provision')),
            created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            used_at TEXT,
            revoked_at TEXT
          )
        `);
        const copied = db.prepare('SELECT COUNT(*) AS n FROM enrollment_tokens').get().n;
        db.exec(`
          INSERT INTO enrollment_tokens_new
            (id, user_id, token_hash, scope, created_by, created_at, expires_at, used_at, revoked_at)
          SELECT
            id, user_id, token_hash, scope, created_by, created_at, expires_at, used_at, revoked_at
          FROM enrollment_tokens
        `);
        db.exec('DROP TABLE enrollment_tokens');
        db.exec('ALTER TABLE enrollment_tokens_new RENAME TO enrollment_tokens');
        db.exec('CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_user ON enrollment_tokens(user_id)');
        db.exec('CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON enrollment_tokens(token_hash)');
        db.exec('COMMIT');
        console.log(`enrollment_tokens migration (B5d4): rebuilt, preserved ${copied} token(s)`);
      } catch (rebuildErr) {
        db.exec('ROLLBACK');
        throw rebuildErr;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  } catch (etMigErr) {
    console.error('enrollment_tokens migration (B5d4) failed (non-fatal):', etMigErr.message);
  }

  // ── B5e migration: instance identity + anti-cloning + deployment mode ──────
  // Creates instance_identity / instance_observations (migration_bundles is
  // created by the schema above; this block only rebuilds it when an older
  // database carries the pre-c139 placeholder shape), adds the per-AC ratchet
  // columns to ac_device_signing_keys, and seeds the deployment_mode +
  // fuse_high_water system_meta rows. All idempotent.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS instance_identity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        instance_id TEXT NOT NULL,
        anchor_kind TEXT NOT NULL DEFAULT 'software'
          CHECK (anchor_kind IN ('software', 'vtpm', 'hardware')),
        anchor_public TEXT NOT NULL,
        anchor_seal TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        ratchet_counter INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (status IN ('active', 'quarantined')),
        established_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_attested_at TEXT
      );
      CREATE TABLE IF NOT EXISTS instance_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        observer_kind TEXT NOT NULL
          CHECK (observer_kind IN ('ac', 'gd', 'peer-beacon')),
        observed_instance_fingerprint TEXT,
        observed_from TEXT,
        verdict TEXT NOT NULL
          CHECK (verdict IN ('ok', 'fork', 'clone', 'rollback')),
        detail_json TEXT,
        seen_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_instance_identity_fingerprint
        ON instance_identity(fingerprint);
      CREATE INDEX IF NOT EXISTS idx_instance_observations_verdict
        ON instance_observations(verdict, seen_at);
    `);
    // Widen the anchor_kind CHECK to include 'hardware' (D26) on databases
    // created before this migration. SQLite cannot ALTER a CHECK, so rebuild the
    // table when its recorded schema lacks 'hardware'. Idempotent: once the table
    // carries 'hardware' (rebuilt here, or freshly created above), this is a
    // no-op. Existing rows ('software' / 'vtpm') all satisfy the wider CHECK.
    const instanceIdentitySchema = db
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'instance_identity'")
      .get();
    if (instanceIdentitySchema && instanceIdentitySchema.sql && instanceIdentitySchema.sql.indexOf('hardware') === -1) {
      const rebuildInstanceIdentity = db.transaction(() => {
        db.exec(`
          CREATE TABLE instance_identity_b5e_hw (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instance_id TEXT NOT NULL,
            anchor_kind TEXT NOT NULL DEFAULT 'software'
              CHECK (anchor_kind IN ('software', 'vtpm', 'hardware')),
            anchor_public TEXT NOT NULL,
            anchor_seal TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            ratchet_counter INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active'
              CHECK (status IN ('active', 'quarantined')),
            established_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_attested_at TEXT
          );
          INSERT INTO instance_identity_b5e_hw
            (id, instance_id, anchor_kind, anchor_public, anchor_seal, fingerprint, ratchet_counter, status, established_at, last_attested_at)
            SELECT id, instance_id, anchor_kind, anchor_public, anchor_seal, fingerprint, ratchet_counter, status, established_at, last_attested_at
            FROM instance_identity;
          DROP TABLE instance_identity;
          ALTER TABLE instance_identity_b5e_hw RENAME TO instance_identity;
          CREATE INDEX IF NOT EXISTS idx_instance_identity_fingerprint
            ON instance_identity(fingerprint);
        `);
      });
      rebuildInstanceIdentity();
      console.log('B5e migration: instance_identity anchor_kind CHECK widened to include hardware (existing table rebuilt)');
    }
    // migration_bundles predates c139 on some databases with a placeholder
    // shape (INTEGER id, direction / manifest_json). The canonical FA-MIG1
    // ledger created by the schema uses a TEXT 'mig-' id and per-component
    // columns. When the recorded schema lacks the canonical bundle_path column,
    // replace it. The ledger holds only local export / import bookkeeping (no
    // analyst data, no cross-table references), so the stale table is dropped
    // and recreated in canonical shape.
    const migrationBundlesSchema = db
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'migration_bundles'")
      .get();
    if (migrationBundlesSchema && migrationBundlesSchema.sql && migrationBundlesSchema.sql.indexOf('bundle_path') === -1) {
      const rebuildMigrationBundles = db.transaction(() => {
        db.exec(`
          DROP TABLE migration_bundles;
          CREATE TABLE migration_bundles (
            id TEXT PRIMARY KEY,
            created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            format TEXT NOT NULL DEFAULT 'FA-MIG1',
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
          CREATE INDEX IF NOT EXISTS idx_migration_bundles_created
            ON migration_bundles(created_at DESC);
        `);
      });
      rebuildMigrationBundles();
      console.log('B5e migration: migration_bundles rebuilt to canonical FA-MIG1 ledger shape (stale placeholder replaced)');
    }
    const acDeviceCols = db
      .prepare("PRAGMA table_info(ac_device_signing_keys)")
      .all()
      .map((c) => c.name);
    if (!acDeviceCols.includes('ratchet_counter')) {
      db.exec("ALTER TABLE ac_device_signing_keys ADD COLUMN ratchet_counter INTEGER NOT NULL DEFAULT 0");
    }
    if (!acDeviceCols.includes('ratchet_updated_at')) {
      db.exec("ALTER TABLE ac_device_signing_keys ADD COLUMN ratchet_updated_at TEXT");
    }
    // B6h A-8: relocate fuse_high_water from the replicating system_meta to the
    // excluded node_state. fuse_high_water is node-local anti-rollback state -- a
    // standby must not inherit the active's mark (P3). PRESERVE the recorded high-
    // water: if node_state does not yet have it, copy the existing system_meta value
    // (NEVER the current fuse -- resetting to a lower current fuse would silently
    // re-open the rollback window); only a genuinely fresh DB with no prior value
    // seeds the current fuse. Then DELETE the stale system_meta row so it stops
    // replicating and cannot be re-read. Idempotent.
    const nsFuseHw = db.prepare("SELECT value FROM node_state WHERE key = 'fuse_high_water'").get();
    if (!nsFuseHw) {
      const smFuseHw = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_high_water'").get();
      let relocatedHw;
      if (smFuseHw && smFuseHw.value !== null && smFuseHw.value !== undefined) {
        relocatedHw = String(smFuseHw.value); // preserve the recorded anti-rollback high-water
      } else {
        const fcRow = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
        relocatedHw = (fcRow && fcRow.value !== null && fcRow.value !== undefined) ? String(fcRow.value) : '0';
      }
      db.prepare("INSERT INTO node_state (key, value) VALUES ('fuse_high_water', ?)").run(relocatedHw);
    }
    db.prepare("DELETE FROM system_meta WHERE key = 'fuse_high_water'").run();
    // B6h A-9: relocate the sealed deployment-mode record from the replicating config
    // to the excluded node_state. The record is node-local (anchor-bound); a replicated
    // table let the active's record clobber a standby's and fail verification against the
    // standby's anchor (the paired-standby bare-metal defect). Copy the existing config
    // record into node_state if absent (preserve the active's own sealed mode), then
    // DELETE the config row. Also drop the dead system_meta.deployment_mode seed (no
    // readers). Idempotent. A standby whose config record was clobbered pre-A-9 relocates
    // a non-verifying record and fails safe to bare-metal until re-provisioned.
    const nsMode = db.prepare("SELECT value FROM node_state WHERE key = 'deployment_mode'").get();
    if (!nsMode) {
      const cfgMode = db.prepare("SELECT value FROM config WHERE key = 'deployment_mode'").get();
      if (cfgMode && cfgMode.value !== null && cfgMode.value !== undefined) {
        db.prepare("INSERT INTO node_state (key, value) VALUES ('deployment_mode', ?)").run(String(cfgMode.value));
      }
    }
    db.prepare("DELETE FROM config WHERE key = 'deployment_mode'").run();
    db.prepare("DELETE FROM system_meta WHERE key = 'deployment_mode'").run();
    const instanceIdentityCount = db.prepare("SELECT COUNT(*) AS c FROM instance_identity").get().c;
    console.log(`B5e migration: instance_identity + instance_observations + migration_bundles ready; ac_device_signing_keys ratchet columns ensured; fuse_high_water + deployment_mode relocated to node_state (${instanceIdentityCount} identity row(s) present)`);
  } catch (b5eInstanceIdentityMigrationErr) {
    console.error('B5e instance-identity migration FAILED:', b5eInstanceIdentityMigrationErr.message);
    console.error('The server will start, but anti-cloning hardening cannot persist state: instance identity establishment, duplicate/fork detection, and the anti-rollback high-water mark are inactive. No other feature is affected. Recovery: run the CREATE TABLE / ALTER TABLE statements above in a SQLite shell against the production DB, then restart.');
  }

  // ── B5g: forensic_exports at-rest encryption columns ──────────────────────────
  // FA-ENC1 export-at-rest sealing records, per artifact, which KEK scheme and
  // reference protect the on-disk archive. at_rest_scheme is the canonical
  // "this artifact is encrypted at rest" signal: NULL means a legacy plaintext
  // archive (pre-B5g) that the boot migration will re-seal; a non-NULL scheme
  // (env-var, or a cloud-KMS scheme) means the archive and its manifest sidecar
  // are sealed. at_rest_kek_ref is the env var name for env-var, the
  // kms_providers row id for cloud schemes, or NULL. Each ALTER is guarded by a
  // PRAGMA table_info check, so the migration is idempotent and re-running
  // initDb on an already-migrated DB is a no-op. Its own try/catch keeps a
  // failure here from masking earlier migrations and vice versa.
  try {
    const addAtRestCols = (table) => {
      const cols = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
      if (!cols.includes('at_rest_scheme')) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN at_rest_scheme TEXT`);
        console.log(`${table} migration (B5g): added at_rest_scheme column`);
      }
      if (!cols.includes('at_rest_kek_ref')) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN at_rest_kek_ref TEXT`);
        console.log(`${table} migration (B5g): added at_rest_kek_ref column`);
      }
    };
    addAtRestCols('forensic_exports');
  } catch (b5gExportAtRestMigrationErr) {
    console.error('B5g export-at-rest column migration FAILED:', b5gExportAtRestMigrationErr.message);
    console.error('The server will start, but forensic-export artifacts cannot be sealed or re-encrypted at rest until the at_rest_scheme / at_rest_kek_ref columns exist. Recovery: run the two ALTER TABLE ADD COLUMN statements in a SQLite shell against the production DB, then restart.');
  }

  // ── Migration: backfill identity handles + analyst pseudonyms (B5h3) ──────────
  // Identity minimization for rows that predate the directory-sync refactor.
  // Such ldap rows may still carry the real displayName / sAMAccountName in
  // name/username; overwrite both with the deterministic non-identifying handle
  // derived from the stored objectGUID (external_id) -- the SAME derivation the
  // sync now uses, so the values match and a later sync leaves them untouched.
  // Separately, assign a unique pseudonym to any analyst lacking one so the team
  // views have a non-identifying label. Idempotent: handles are deterministic and
  // analysts that already have a pseudonym are skipped, so re-running is a no-op.
  try {
    const { handleForGuid } = require('../lib/identity-handle');
    const { generateUniquePseudonym } = require('../lib/pseudonym');

    const ldapRows = db.prepare("SELECT id, external_id, name, username FROM users WHERE auth_method = 'ldap'").all();
    const setHandle = db.prepare('UPDATE users SET name = ?, username = ? WHERE id = ?');
    let handlesFixed = 0;
    for (const r of ldapRows) {
      if (typeof r.external_id !== 'string' || r.external_id.length === 0) continue;
      const handle = handleForGuid(r.external_id);
      if (r.name !== handle || r.username !== handle) {
        setHandle.run(handle, handle, r.id);
        handlesFixed++;
      }
    }

    const noPseudonym = db.prepare("SELECT id FROM users WHERE role = 'analyst' AND (pseudonym IS NULL OR pseudonym = '')").all();
    const pseudonymTaken = db.prepare('SELECT 1 FROM users WHERE pseudonym = ?');
    const setPseudonym = db.prepare('UPDATE users SET pseudonym = ?, pseudonym_rotated_at = ? WHERE id = ?');
    let pseudonymsAssigned = 0;
    const nowIso = new Date().toISOString();
    for (const r of noPseudonym) {
      const pseudonym = generateUniquePseudonym((candidate) => !!pseudonymTaken.get(candidate));
      setPseudonym.run(pseudonym, nowIso, r.id);
      pseudonymsAssigned++;
    }

    if (handlesFixed || pseudonymsAssigned) {
      console.log('identity backfill (B5h3): ' + handlesFixed + ' directory row(s) handled, ' + pseudonymsAssigned + ' analyst pseudonym(s) assigned');
    }
  } catch (idBackfillErr) {
    console.error('identity backfill (B5h3) failed (non-fatal):', idBackfillErr.message);
  }

  // ── B5n migration: login geo-fencing tables ──────────────────────────
  // geoip_database records the operator-provisioned MaxMind GeoLite2-Country
  // database currently active for IP -> country resolution: its SHA-256, declared
  // type, and build/size metadata, plus who uploaded it and when. One row is
  // active at a time (active = 1); superseded uploads are retained for audit.
  // geo_login_exceptions holds per-user country allowances (e.g. approved travel)
  // that suppress a geo-fence block for a specific user + country, with an
  // optional expiry. Both are operational state, not analyst data. Idempotent:
  // CREATE TABLE / CREATE INDEX IF NOT EXISTS make re-running initDb a no-op.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS geoip_database (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sha256 TEXT NOT NULL,
        db_type TEXT NOT NULL,
        build_epoch INTEGER,
        node_count INTEGER,
        ip_version INTEGER,
        record_count INTEGER,
        uploaded_by TEXT,
        uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
        active INTEGER NOT NULL DEFAULT 1
      );
      CREATE TABLE IF NOT EXISTS geo_login_exceptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        country TEXT NOT NULL,
        reason TEXT,
        added_by TEXT,
        added_at TEXT NOT NULL DEFAULT (datetime('now')),
        expires_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_geo_exc_user
        ON geo_login_exceptions(user_id);
    `);
  } catch (b5nGeoFenceMigrationErr) {
    console.error('B5n geo-fence table migration failed (non-fatal):', b5nGeoFenceMigrationErr.message);
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
  // server/data/fido-attestation-roots.json by seed-fido-roots.js, called below
  // after the training-library seed.
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
    console.error('The server will start, but hardware-credential login hardening is not in place: the trusted-root tables or the webauthn_credentials hardware columns may be missing, so hardware-gated passkey enrollment and login cannot function. Recovery: run the CREATE TABLE / ALTER TABLE statements above in a SQLite shell against the production DB.');
  }

  // ── B5o migration: High Availability / failover control plane ─────
  // B5o builds active/passive HA: a sole-writer active replicates to a warm,
  // sealed passive that auto-promotes on active failure. These tables are the
  // HA control plane and are inert until HA is enabled and the node is paired.
  // ha_node holds this node's HA role plus its X25519 replication key-agreement
  // keypair (public in the clear, private sealed to local hardware) and the
  // shared Tier-1 KEK pre-wrapped to this node, unsealed only at promotion.
  // ha_peer pins the single paired peer (its anchor, its anchor-signed wrap key,
  // and its mTLS client-cert thumbprint). ha_lease carries the monotonic epoch:
  // only the current-epoch lease holder may write, and a BEFORE UPDATE trigger
  // forbids the epoch from ever decreasing (the fence against a stale active).
  // ha_replication_journal is the logical change-log produced on the active by
  // change-data-capture triggers (added in a later commit) and shipped to the
  // passive; it is transport, never itself replicated. ha_replication_state is
  // the ship/apply cursor plus lag. None of these tables are replicated to the
  // peer -- they are node-local control plane. All idempotent: CREATE TABLE /
  // CREATE TRIGGER / CREATE INDEX IF NOT EXISTS make re-running initDb a no-op.
  try {
    db.exec(`
      CREATE TABLE IF NOT EXISTS ha_node (
        id TEXT PRIMARY KEY DEFAULT 'self' CHECK (id = 'self'),
        role TEXT NOT NULL DEFAULT 'standalone' CHECK (role IN ('standalone', 'active', 'passive')),
        wrap_public_pem TEXT,
        wrap_private_sealed TEXT,
        wrap_pubkey_anchor_sig TEXT,
        sealed_promotion_kek TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS ha_peer (
        id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
        peer_endpoint TEXT NOT NULL,
        peer_anchor_fingerprint TEXT NOT NULL,
        peer_anchor_public_pem TEXT NOT NULL,
        peer_wrap_public_pem TEXT NOT NULL,
        peer_cert_fingerprint TEXT NOT NULL,
        peer_ca_pem TEXT,
        status TEXT NOT NULL DEFAULT 'pairing' CHECK (status IN ('pairing', 'paired', 'revoked')),
        paired_at TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(peer_anchor_fingerprint)
      );

      CREATE TABLE IF NOT EXISTS ha_lease (
        id TEXT PRIMARY KEY DEFAULT 'current' CHECK (id = 'current'),
        epoch INTEGER NOT NULL DEFAULT 0,
        holder TEXT NOT NULL DEFAULT 'none' CHECK (holder IN ('self', 'peer', 'none')),
        lease_expires_at TEXT,
        last_heartbeat_at TEXT,
        term_started_at TEXT,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TRIGGER IF NOT EXISTS ha_lease_epoch_monotonic
        BEFORE UPDATE ON ha_lease
        WHEN NEW.epoch < OLD.epoch
        BEGIN SELECT RAISE(ABORT, 'ha_lease epoch must not decrease'); END;

      CREATE TABLE IF NOT EXISTS ha_replication_journal (
        lsn INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch INTEGER NOT NULL,
        txn_marker TEXT,
        table_name TEXT NOT NULL,
        op TEXT NOT NULL CHECK (op IN ('INSERT', 'UPDATE', 'DELETE')),
        pk_json TEXT NOT NULL,
        row_json TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        shipped INTEGER NOT NULL DEFAULT 0 CHECK (shipped IN (0, 1))
      );

      CREATE INDEX IF NOT EXISTS idx_ha_repl_journal_unshipped
        ON ha_replication_journal(shipped, lsn);

      CREATE TABLE IF NOT EXISTS ha_replication_state (
        id TEXT PRIMARY KEY DEFAULT 'self' CHECK (id = 'self'),
        last_journaled_lsn INTEGER NOT NULL DEFAULT 0,
        last_shipped_lsn INTEGER NOT NULL DEFAULT 0,
        last_acked_lsn INTEGER NOT NULL DEFAULT 0,
        last_applied_lsn INTEGER NOT NULL DEFAULT 0,
        last_apply_at TEXT,
        lag_seconds REAL NOT NULL DEFAULT 0,
        baseline_at TEXT
      );
    `);

    // Additive column for B5o cert hardening: the paired peer's CA certificate,
    // pinned (with the leaf fingerprint) so the peer links validate the chain
    // instead of disabling certificate validation. Idempotent so an already-
    // migrated ha_peer gains the column without a table rebuild.
    const haPeerCols = db.prepare('PRAGMA table_info(ha_peer)').all().map(function (c) { return c.name; });
    if (haPeerCols.indexOf('peer_ca_pem') === -1) {
      db.exec('ALTER TABLE ha_peer ADD COLUMN peer_ca_pem TEXT');
    }
    const haTableCount = db.prepare("SELECT COUNT(*) AS c FROM sqlite_master WHERE type = 'table' AND name IN ('ha_node', 'ha_peer', 'ha_lease', 'ha_replication_journal', 'ha_replication_state')").get().c;
    console.log(`B5o migration: HA control-plane tables ready (${haTableCount} ha_* table(s) present)`);
  } catch (b5oHaMigrationErr) {
    console.error('B5o HA control-plane migration FAILED:', b5oHaMigrationErr.message);
    console.error('The server will start, but High Availability is not in place: the ha_node / ha_peer / ha_lease / ha_replication_journal / ha_replication_state tables may be missing, so pairing, replication, and automated failover cannot function. Recovery: run the CREATE TABLE / CREATE TRIGGER statements above in a SQLite shell against the production DB.');
  }

  // ── B5r: automated update-detection check log ──────────────────────────────
  // Append-only evidence trail for the automated update-detection feature. Each
  // row records one update check -- scheduled (the HA-gated scheduler tick) or
  // manual ("check now") -- capturing when it ran, the running version at the
  // time, the outcome, the latest release tag + URL when one was found, and
  // whether a channel notice has already fired for that version (so the lead is
  // notified once per new version, not once per check). Detect-and-notify only:
  // FireAlive never downloads, routes, or installs an update; this table backs
  // the Updates tab's last-/next-check display and the update-available banner.
  //
  // result is a closed enum: 'none' (running the latest, or no stable release
  // published yet -- a 404 from /releases/latest during the pre-release era),
  // 'available' (a strictly-newer stable release exists -- anti-rollback never
  // reports a downgrade), or 'source_unreachable' (network/timeout/unexpected
  // response -- recorded as unreachable, never as up-to-date, so the operator is
  // never given a false "current"). Idempotent.
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
    const auUpdateLogPresent = db.prepare("SELECT COUNT(*) AS c FROM sqlite_master WHERE type = 'table' AND name = 'auto_update_check_log'").get().c;
    console.log(`B5r migration: automated update-check log ready (${auUpdateLogPresent} table present)`);
  } catch (b5rUpdateLogMigrationErr) {
    console.error('B5r update-check log migration FAILED:', b5rUpdateLogMigrationErr.message);
    console.error('The server will start, but the automated update-detection feature cannot record check results: the auto_update_check_log table may be missing, so the Updates tab last-check display and the update-available banner have no data source. Recovery: run the CREATE TABLE / CREATE INDEX statements above in a SQLite shell against the production DB.');
  }

  console.log('Database initialized at', DB_PATH);
  require('./seed-training-library').seedTrainingLibrary(db);
  require('./seed-fido-roots').seedFidoRoots(db);
  db.close();
}

// Run if called directly
if (require.main === module) {
  require('dotenv').config({ path: path.join(__dirname, '../../.env') });
  initDb();
}

module.exports = { getDb, initDb, DB_PATH };

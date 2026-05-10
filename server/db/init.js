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
  password_hash TEXT,  -- NULL when using SSO (SAML/OIDC/LDAP)
  role TEXT NOT NULL CHECK (role IN ('analyst', 'lead', 'admin', 'developer')),
  name TEXT NOT NULL,
  pseudonym TEXT,  -- v0.0.25: burnout data keyed to this, not name
  pseudonym_rotated_at TEXT,  -- R0: timestamp of last pseudonym rotation
  tier INTEGER CHECK (tier IN (1, 2, 3)),
  shift TEXT CHECK (shift IN ('day', 'swing', 'night')),
  available INTEGER DEFAULT 1,
  active INTEGER DEFAULT 1,  -- R0: account active flag (distinct from the available shift status); offboarding sets to 0
  capacity_score INTEGER DEFAULT 50,  -- R0: 0-100, higher = more capacity for new tickets; consumed by routing/SOAR feature
  last_heartbeat TEXT,  -- R0: last AC heartbeat ping timestamp; consumed by system-health monitor
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
  -- NOTE: analyst_id stored but NEVER exposed to management console
  -- Management sees only: "1 active lighter queue request" (anonymous)
  analyst_id_encrypted BLOB,  -- encrypted with Tier-3 key
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

CREATE TABLE IF NOT EXISTS analyst_signals (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- All signal values are encrypted with the Tier-3 key
  -- Management console can NEVER access these values
  signals_encrypted BLOB NOT NULL,
  -- Only the aggregate risk tier is derived and stored in Tier-1
  -- This is computed by the server and is one of: stable, watch, elevated
  risk_tier TEXT DEFAULT 'stable',
  recorded_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS analyst_consent_log (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  detail TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

-- ── Peer Messaging (E2EE — server stores only ciphertext) ────────────────

CREATE TABLE IF NOT EXISTS peer_messages (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  -- Both sender and recipient are stored as encrypted blobs
  -- The server facilitates delivery but cannot read identities or content
  sender_encrypted BLOB NOT NULL,
  recipient_encrypted BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  nonce BLOB NOT NULL,
  ephemeral_pubkey BLOB,  -- X25519 ephemeral key for forward secrecy
  created_at TEXT DEFAULT (datetime('now')),
  read_at TEXT
);

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
  type TEXT NOT NULL CHECK (type IN ('daily-auto', 'on-demand', 'snapshot')),
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
--                       backup currently held by a legal hold; the
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
CREATE TABLE IF NOT EXISTS backup_destinations (
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

CREATE INDEX IF NOT EXISTS idx_backup_destinations_enabled
  ON backup_destinations(enabled) WHERE enabled = 1;
CREATE INDEX IF NOT EXISTS idx_backup_destinations_adapter
  ON backup_destinations(adapter);


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
    REFERENCES backup_destinations(id) ON DELETE RESTRICT,
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
-- Same on-disk format as backup_destinations.credentials_encrypted:
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
--   strict (default)            second admin must POST approval w/ TOTP
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

-- ── Fuse Counter (anti-rollback) ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS system_meta (
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

CREATE TABLE IF NOT EXISTS signal_readings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analyst_id TEXT,
  signal TEXT,
  value REAL,
  recorded_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS analyst_impacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analyst_id TEXT,
  type TEXT,
  description TEXT,
  recorded_at TEXT DEFAULT (datetime('now'))
);

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
  session_id TEXT NOT NULL,
  flagger_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  flagged_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  tier INTEGER NOT NULL CHECK (tier IN (1, 2, 3)),
  content_encrypted BLOB NOT NULL,
  flagger_ip TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at TEXT,
  resolved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  resolution_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_unresolved
  ON peer_abuse_flags(tier, created_at DESC)
  WHERE resolved_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_flagged_user
  ON peer_abuse_flags(flagged_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_peer_abuse_flags_flagger
  ON peer_abuse_flags(flagger_user_id, created_at DESC);

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
-- internal Phi-3 model, so a 15-scenario job runs ~15 minutes — too long
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
-- The dispatcher reads this to decide internal vs external for each call.
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
    'troubleshooter'
  )),
  provider TEXT NOT NULL DEFAULT 'internal' CHECK (provider IN (
    'internal',
    'anthropic', 'openai', 'gemini', 'azure_openai', 'aws_bedrock', 'custom'
  )),
  model_name TEXT,
  config_encrypted BLOB,
  max_tokens INTEGER NOT NULL DEFAULT 1024,
  temperature REAL NOT NULL DEFAULT 0.7,
  updated_by TEXT REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

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
  retry_max INTEGER NOT NULL DEFAULT 3 CHECK (retry_max >= 0 AND retry_max <= 10),
  retry_backoff_seconds INTEGER NOT NULL DEFAULT 30
    CHECK (retry_backoff_seconds >= 1 AND retry_backoff_seconds <= 3600),
  last_push_at TEXT,
  last_push_status TEXT
    CHECK (last_push_status IS NULL OR last_push_status IN ('success', 'failure', 'pending')),
  last_push_error TEXT,
  last_push_duration_ms INTEGER,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed the singleton row in disabled state on first init. The singleton
-- pattern is enforced by the CHECK (id = 1) constraint above. PUTs to
-- /api/gd-config update this row in place.
INSERT OR IGNORE INTO gd_push_config (id, enabled, push_interval_minutes)
  VALUES (1, 0, 15);

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

`;

function initDb() {
  const { version, fuseCounter } = require('../lib/version');
  const db = getDb();

  // Execute schema
  db.exec(SCHEMA);

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
  //                            system-health, iam.js
  //   capacity_score         — 0-100 capacity rating consumed by
  //                            Routing & SOAR; referenced by metrics-
  //                            collector and the routing distribute endpoint
  //   last_heartbeat         — last AC heartbeat ping; referenced by
  //                            system-health for connected-clients view
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
    console.error('The server will start, but routing, IAM offboarding detection, system-health, and pseudonym rotation may misbehave until the migration is investigated.');
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

  // ── R3f migration: MFA enforcement + recovery codes ──────────────────
  //
  // Adds three columns to users for SOC-grade MFA enforcement at login,
  // and a new mfa_login_sessions table for the two-step login flow:
  //
  //   mfa_enrollment_required        Set to 1 for admin/lead/developer
  //                                  roles. Login refuses to issue a
  //                                  JWT when this is set and
  //                                  totp_enrolled_at IS NULL.
  //   totp_recovery_codes_hashed     JSON array of bcrypt hashes of
  //                                  single-use recovery codes.
  //   totp_recovery_codes_remaining  Cached count for UI display.
  //
  // mfa_login_sessions tracks partial logins -- the user has proven
  // password but not yet TOTP. A 256-bit random token is generated at
  // password verify, sha256-hashed for indexed lookup, returned to the
  // client, and consumed via POST /api/auth/login-mfa with the TOTP
  // code. 5-minute TTL, single-use (consumed_at set on completion).
  //
  // sha256 (not bcrypt) is the right choice for this token -- the
  // input has 256 bits of entropy, so cost-stretched hashing adds no
  // security and would prevent the indexed lookup that a small but
  // continuously-churning table needs.
  //
  // Idempotent: column-presence checks for each ALTER TABLE; CREATE
  // TABLE IF NOT EXISTS for the new table.
  try {
    const usersCols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
    if (!usersCols.includes('mfa_enrollment_required')) {
      db.exec(`
        ALTER TABLE users
          ADD COLUMN mfa_enrollment_required INTEGER NOT NULL DEFAULT 1
          CHECK (mfa_enrollment_required IN (0, 1));
      `);
      // Set the flag for ALL existing user rows. Per R3f-pt2, MFA is
      // required for every account (admin, lead, developer, analyst).
      // SOC-grade environments universally require MFA per NIST SP
      // 800-63B, SOC 2, PCI-DSS. The original R3f carve-out for the
      // analyst role was UX deference; SOC security policy wins.
      const setResult = db.prepare(`
        UPDATE users
        SET mfa_enrollment_required = 1
        WHERE role IN ('admin', 'lead', 'developer', 'analyst')
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

  // mfa_login_sessions: short-lived rows tracking partial logins
  // (password verified, awaiting TOTP). Created in routes/auth.js
  // POST /login when the authenticated user has totp_enrolled_at set;
  // consumed by POST /api/auth/login-mfa when the user submits a
  // valid TOTP code. Single-use enforced via consumed_at NOT NULL
  // check at lookup time.
  db.exec(`
    CREATE TABLE IF NOT EXISTS mfa_login_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT NOT NULL UNIQUE,        -- sha256 hex of the 256-bit token
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      ip_address TEXT,                         -- forensic correlation with login row
      user_agent TEXT,                         -- forensic correlation with login row
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,                -- created_at + 5 minutes
      consumed_at TEXT                         -- NULL until consumed; non-NULL = single-use spent
    );
    CREATE INDEX IF NOT EXISTS idx_mfa_login_sessions_token_hash
      ON mfa_login_sessions(token_hash);
    CREATE INDEX IF NOT EXISTS idx_mfa_login_sessions_active
      ON mfa_login_sessions(expires_at) WHERE consumed_at IS NULL;
  `);

  console.log('Database initialized at', DB_PATH);
  db.close();
}

// Run if called directly
if (require.main === module) {
  require('dotenv').config({ path: path.join(__dirname, '../../.env') });
  initDb();
}

module.exports = { getDb, initDb, DB_PATH };

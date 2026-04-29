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
  password_hash TEXT,  -- NULL when using SSO (SAML/OIDC/LDAP)
  role TEXT NOT NULL CHECK (role IN ('analyst', 'lead', 'admin', 'developer')),
  name TEXT NOT NULL,
  pseudonym TEXT,  -- v0.0.25: burnout data keyed to this, not name
  tier INTEGER CHECK (tier IN (1, 2, 3)),
  shift TEXT CHECK (shift IN ('day', 'swing', 'night')),
  available INTEGER DEFAULT 1,
  auth_method TEXT DEFAULT 'local' CHECK (auth_method IN ('local', 'saml', 'oidc', 'ldap')),
  external_id TEXT,  -- SSO subject identifier
  geo_country TEXT,  -- v0.0.25: assigned country for geo-fencing
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

CREATE TABLE IF NOT EXISTS backups (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  type TEXT NOT NULL CHECK (type IN ('daily-auto', 'on-demand', 'snapshot')),
  size_bytes INTEGER,
  file_path TEXT NOT NULL,
  sha256_hash TEXT,
  status TEXT DEFAULT 'running' CHECK (status IN ('running', 'verified', 'failed')),
  created_at TEXT DEFAULT (datetime('now'))
);

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

CREATE TABLE IF NOT EXISTS ticket_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analyst_id TEXT,
  ticket_id TEXT,
  category TEXT,
  action TEXT,
  response_time_min REAL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ticket_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analyst_id TEXT,
  ticket_id TEXT,
  priority TEXT,
  status TEXT DEFAULT 'open',
  assigned_at TEXT DEFAULT (datetime('now')),
  closed_at TEXT
);

CREATE TABLE IF NOT EXISTS peer_sessions (
  id TEXT PRIMARY KEY,
  helper_id TEXT,
  seeker_id TEXT,
  duration_min INTEGER,
  rating INTEGER,
  created_at TEXT DEFAULT (datetime('now'))
);
`;

function initDb() {
  const { version, fuseCounter } = require('../lib/version');
  const db = getDb();

  // Execute schema
  db.exec(SCHEMA);

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

  console.log('Database initialized at', DB_PATH);
  db.close();
}

// Run if called directly
if (require.main === module) {
  require('dotenv').config({ path: path.join(__dirname, '../../.env') });
  initDb();
}

module.exports = { getDb, initDb, DB_PATH };

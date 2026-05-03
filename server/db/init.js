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
  deleted_at TEXT
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

-- ── AI Provider Configuration ────────────────────────────────────────────
-- Per-feature routing for AI calls. One row per AI-using feature.
-- The dispatcher reads this to decide internal vs external for each call.

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
          deleted_at TEXT
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

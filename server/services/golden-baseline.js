// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Golden-Baseline Configuration Domain (capture / apply / diff)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// THE GOLDEN BASELINE (B5d3, decisions D19/D20/D21)
//
// A golden baseline is the portable, secrets-free, reviewable image of this
// Management Console's configuration: everything an org needs to restore its
// settings or stand up a freshly-deployed MC to its approved state. It is
// captured here as one canonical-JSON payload, stored in config_snapshots,
// exported as a signed FA-GB1 bundle, and applied back as a transactional
// full-replace of the domain.
//
// WHAT IS IN THE DOMAIN (the explicit allowlist below)
//   - team_config configuration keys (TEAM_CONFIG_KEYS)
//   - config-table configuration keys (CONFIG_TABLE_KEYS)
//   - the dedicated configuration tables (TABLE_SECTIONS): KMS providers,
//     backup destinations + schedules, the HR scheduling platform config,
//     the GD push config, the per-feature internal-AI settings, and the
//     report / SLA / notification singletons
//
// WHAT IS NEVER IN A BASELINE (hard exclusions, D20)
//   - secret material of any kind: encrypted credential blobs
//     (kms_providers.credentials_encrypted, integration_config.
//     config_encrypted, storage_destinations.credentials_encrypted,
//     scheduling_platform_config.credentials_encrypted,
//     gd_push_config.api_key_encrypted, external_restore_sources.*,
//     notification_config.pagerduty_key / sms_auth_token_encrypted,
//     the cicd_webhook_secret config key)
//   - every signing-key table (backup / chain / report / cloud-iac /
//     gd-push / forensic): keys are deployment identity,
//     not configuration
//   - users, api keys, enrollment tokens, WebAuthn + certificate
//     enrollments, break-glass credentials
//   - pseudonym mappings and all analyst data
//   - audit logs, backup/snapshot history, evidence vaults
//   - operational state: panic_mode / panic_deactivated_at /
//     panic_saved_caps, routing_enabled / routing_paused,
//     soar_burnout_risk_tier, probe + sync + push status columns,
//     integration_health_last_results / _last_probed_build caches,
//     automation_rate / cert_coverage_pct / last_backup metrics,
//     dynamic team_config families (pending_user_% / lockout_% /
//     reset_% / peer_request_% / peer_session_%), per-analyst
//     overtime_* keys, posture/tripwire/threat-hunting runtime state
//   - instance_label (the human deployment identity that pairs with
//     the signing-key fingerprint)
//   - peer_disclaimer (a non-editable management invariant; an import
//     must not be a path to modify it)
//   - backup_config (legacy v100 team_config shim; the canonical
//     schedule configuration is the backup_schedules table) and the
//     legacy 'backup_schedules' config-table mirror key
//   - regulatory_presets (code-seeded reference data)
//
// SECRETS MODEL (D20 + the R3n omission rule)
//   Capture records WHICH secret columns held a value via per-entry
//   secretsPresent markers, never the values. Apply preserves an
//   identity-matched existing row's stored secret (same name / same
//   singleton) when the baseline marks it present -- the R3n
//   sensitive-field omission rule -- so importing a baseline onto a
//   deployment that already holds working credentials does not wipe
//   them. Where no secret can be preserved, the dependent capability
//   lands disabled-pending-credentials (enabled=0 / pagerduty_enabled=0
//   / sms_enabled=0) and is reported in requiresCredentials for the
//   operator to re-enter.
//
//   integration_config and external_restore_sources are MANIFEST-ONLY:
//   their secret column is NOT NULL (the whole config is the secret),
//   so the baseline carries only an inventory of what existed; apply
//   leaves the deployment's existing rows untouched and reports the
//   listed entries for manual re-configuration.
//
// APPLY SEMANTICS (D20)
//   Version-1 payloads apply as a transactional FULL-REPLACE of the
//   domain: allowlisted keys/rows present in the baseline are written,
//   allowlisted keys/rows absent from it are removed. Nothing outside
//   the allowlist is ever touched -- apply iterates the allowlist, not
//   the payload, so an unknown key in a payload can never reach the
//   database. The route layer takes an automatic pre-import snapshot
//   first and gates the whole surface behind the config-lock plus a
//   fresh MFA step-up (D21).
//
//   Version-0 payloads are the legacy team_config-era snapshots moved
//   in by the B5d3 init.js migration ({teamConfig, reportConfig,
//   slaConfig, notifConfig}). They apply with the legacy semantics --
//   upsert the captured team_config rows, no deletions -- and now also
//   restore the SLA + notification singletons, closing the old
//   config-revert bug that silently dropped them (D6).
//
// CONSUMERS
//   routes/config-baseline.js   list / save / revert / delete / export /
//                               import / diff (B5d3 commit 7)
//   golden-baseline-validate.js the D17 import normalizer (commit 3)
//   regression-runner.js        domain sanity checks (commit 12)
// ─────────────────────────────────────────────────────────────────────────────

const { canonicalize, sha256Hex } = require('./report-signer');
const { version: APP_VERSION } = require('../lib/version');

const BASELINE_SCHEMA_VERSION = 1;
const SNAPSHOT_ORIGINS = ['manual', 'pre-revert', 'pre-import'];
const RETENTION_CONFIG_KEY = 'config_snapshot_retention';
const RETENTION_DEFAULT = 20;
const RETENTION_MAX = 500;

// ── Typed errors ────────────────────────────────────────────────────

const CODES = {
  INVALID_INPUT: 'INVALID_INPUT',
  RETENTION_CAP_REACHED: 'RETENTION_CAP_REACHED',
  SNAPSHOT_NOT_FOUND: 'SNAPSHOT_NOT_FOUND',
  UNSUPPORTED_SCHEMA_VERSION: 'UNSUPPORTED_SCHEMA_VERSION',
  LEGACY_DIFF_UNSUPPORTED: 'LEGACY_DIFF_UNSUPPORTED',
};

class GBError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'GBError';
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}

// ── The domain allowlists (D20) ─────────────────────────────────────

// team_config keys that are configuration. Everything else in team_config
// (panic state, routing switches, dynamic per-user/session families, the
// legacy backup_config shim, the non-editable peer_disclaimer, the
// soar_burnout_risk_tier published variable) is deliberately absent --
// see the hard-exclusion list in the file header.
const TEAM_CONFIG_KEYS = [
  'access_control_config',
  'client_notif_config',
  'compromise_scan_retention_days',
  'edr_config',
  'feature_toggles',
  'helper_pay_config',
  'iam_config',
  'kms_config',
  'peer_schedule_config',
  'peer_share_exclusion_cap',
  'recert_config',
  'retention_config',
  'sase_config',
  'siem_config',
  'soar_config',
  'tripwire_config',
  'vuln_scan_config',
  'wifi_policy',
];

// config-table keys that are configuration. Excluded siblings (state,
// caches, metrics, identity, secrets): integration_health_last_results,
// integration_health_last_probed_build, integration_health, last_backup,
// automation_rate, cert_coverage_pct, routing_paused, routing_enabled,
// panic_mode, per-analyst overtime_* keys, instance_label (deployment
// identity), cicd_webhook_secret (a secret), and the legacy
// 'backup_schedules' JSON mirror (the canonical store is the table).
// GD-server-only keys (gd_residency, signing_key_grace_period_minutes)
// live in the GD's own database and are not an MC concern.
const CONFIG_TABLE_KEYS = [
  'alert_routing_matrix',
  'alert_webhook_url',
  'auth_log_notif_config',
  'auto_disable_routing_config',
  'config_snapshot_retention',
  'fail_open_config',
  'gd_push_schedule',
  'geo_fence_config',
  'global_dashboard_config',
  'ha_config',
  'integration_health_probes_enabled',
  'integration_health_settings',
  'key_erase_grace_days',
  'malware_scan_mode',
  'mfa_config',
  'notification_config',
  'overtime_full_time_hours',
  'posture_config',
  'proactive_config',
  'pseudonym_config',
  'runtime_monitor_thresholds',
  'siem_config',
  'soar_config',
  'soc_timezone',
  'sync_interval_config',
  'team_aggregate_min_cohort',
  'threat_hunting_config',
  'ticketing_config',
  'tripwire_config',
  'upskilling_hour_config',
  'webauthn_config',
];

// The dedicated configuration tables. Each section declares exactly which
// columns are configuration (configCols), which are secrets that are
// stripped at capture and preserved-or-disabled at apply (secretCols +
// secretDisables), and which probe/sync/trust state columns are dropped
// entirely (their DEFAULTs refill on apply; resetCols force a value).
//
//   mode 'rows'      multi-row table; full-replace; rows matched to the
//                    pre-replace table by matchKey for secret preservation
//   mode 'singleton' one fixed-id row; INSERT OR REPLACE; null row in the
//                    baseline removes the row (back to virgin defaults)
//   mode 'manifest'  inventory only -- the secret column is NOT NULL so
//                    rows cannot be created without credentials; apply
//                    leaves existing rows untouched and reports the list
//
// noIdCarry skips the primary key on insert (AUTOINCREMENT tables).
// Column lists are intersected with PRAGMA table_info at runtime so a
// column added or absent in a given install degrades gracefully instead
// of crashing capture or apply.
const TABLE_SECTIONS = [
  {
    table: 'kms_providers', mode: 'rows', matchKey: 'name', orderBy: 'name',
    configCols: ['id', 'name', 'provider_type', 'config', 'enabled', 'is_default'],
    secretCols: ['credentials_encrypted'],
    secretDisables: { credentials_encrypted: 'enabled' },
  },
  {
    table: 'integration_config', mode: 'manifest', orderBy: 'integration_type',
    manifestCols: ['integration_type'],
    secretCols: ['config_encrypted'],
  },
  {
    table: 'storage_destinations', mode: 'rows', matchKey: 'name', orderBy: 'name',
    configCols: ['id', 'name', 'adapter', 'config', 'enabled', 'retention_days', 'tags'],
    secretCols: ['credentials_encrypted'],
    secretDisables: { credentials_encrypted: 'enabled' },
    resetCols: { immutability_mode: 'unknown' },
  },
  {
    table: 'backup_schedules', mode: 'rows', matchKey: 'name', orderBy: 'name',
    noIdCarry: true,
    configCols: ['name', 'type', 'interval', 'retention', 'destination', 'encrypted',
      'active', 'regulatory_preset_id', 'time', 'day_of_week', 'day_of_month',
      'backup_kind', 'backup_strategy', 'destination_filter', 'max_chain_depth'],
    secretCols: [],
  },
  {
    table: 'external_restore_sources', mode: 'manifest', orderBy: 'name',
    manifestCols: ['name', 'source_type', 'path', 'enabled'],
    secretCols: ['credentials_encrypted'],
  },
  {
    table: 'scheduling_platform_config', mode: 'singleton', idCol: 'id', singletonId: 1,
    configCols: ['enabled', 'platform', 'endpoint_url', 'sync_interval_minutes',
      'retry_max', 'retry_backoff_seconds'],
    secretCols: ['credentials_encrypted'],
    secretDisables: { credentials_encrypted: 'enabled' },
  },
  {
    table: 'gd_push_config', mode: 'singleton', idCol: 'id', singletonId: 1,
    configCols: ['enabled', 'endpoint_url', 'push_interval_minutes',
      'compliance_push_cadence_hours', 'leaderboard_push_cadence_minutes',
      'retry_max', 'retry_backoff_seconds'],
    secretCols: ['api_key_encrypted'],
    secretDisables: { api_key_encrypted: 'enabled' },
  },
  {
    table: 'ai_provider_config', mode: 'rows', matchKey: 'feature_id', orderBy: 'feature_id',
    configCols: ['feature_id', 'provider', 'model_name', 'max_tokens', 'temperature'],
    secretCols: [],
  },
  {
    table: 'report_config', mode: 'singleton', idCol: 'id', singletonId: 'default',
    configCols: ['schedule', 'day_of_week', 'time_of_day', 'format', 'recipients',
      'siem_feed', 'sections'],
    secretCols: [],
  },
  {
    table: 'sla_config', mode: 'singleton', idCol: 'id', singletonId: 'default',
    configCols: ['p1_mtta', 'p1_mttr', 'p2_mtta', 'p2_mttr'],
    secretCols: [],
  },
  {
    table: 'notification_config', mode: 'singleton', idCol: 'id', singletonId: 'default',
    configCols: ['threshold', 'email_enabled', 'email_address', 'sms_enabled',
      'sms_number', 'webhook_enabled', 'webhook_url', 'pagerduty_enabled',
      'sms_provider', 'sms_account_sid', 'sms_from_number'],
    secretCols: ['pagerduty_key', 'sms_auth_token_encrypted'],
    secretDisables: { pagerduty_key: 'pagerduty_enabled', sms_auth_token_encrypted: 'sms_enabled' },
  },
];

// ── Small helpers ───────────────────────────────────────────────────

// Table names below come exclusively from the TABLE_SECTIONS constant /
// fixed literals in this module -- never from user input -- so identifier
// interpolation into SQL here is safe by construction.
function tableColumns(db, table) {
  return new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name));
}

function pickCols(row, cols, present) {
  const out = {};
  for (const c of cols) {
    if (!present.has(c)) continue;
    out[c] = row[c] === undefined ? null : row[c];
  }
  return out;
}

function hasOwn(obj, key) {
  return !!obj && Object.prototype.hasOwnProperty.call(obj, key);
}

function readRetention(db) {
  try {
    const row = db.prepare('SELECT value FROM config WHERE key = ?').get(RETENTION_CONFIG_KEY);
    const n = row ? parseInt(row.value, 10) : NaN;
    if (!Number.isFinite(n) || n < 1) return RETENTION_DEFAULT;
    return Math.min(n, RETENTION_MAX);
  } catch (err) {
    return RETENTION_DEFAULT;
  }
}

// ── Capture ─────────────────────────────────────────────────────────

function captureKv(db, table, keys) {
  const stmt = db.prepare(`SELECT value FROM ${table} WHERE key = ?`);
  const out = {};
  for (const k of keys) {
    const row = stmt.get(k);
    if (row) out[k] = row.value;
  }
  return out;
}

function captureSection(db, sec, secretsSummary) {
  const present = tableColumns(db, sec.table);
  if (present.size === 0) return null; // table absent in this install

  const markSecrets = (row, identifier) => {
    const found = [];
    for (const scol of sec.secretCols || []) {
      if (present.has(scol) && row[scol] !== null && row[scol] !== undefined && row[scol] !== '') {
        found.push(scol);
      }
    }
    if (found.length) {
      secretsSummary.push({ section: sec.table, identifier: String(identifier), columns: found });
    }
    return found;
  };

  if (sec.mode === 'singleton') {
    const row = db.prepare(`SELECT * FROM ${sec.table} WHERE ${sec.idCol} = ?`).get(sec.singletonId);
    if (!row) return { mode: 'singleton', row: null };
    const out = pickCols(row, sec.configCols, present);
    const found = markSecrets(row, sec.singletonId);
    if (found.length) out.secretsPresent = found;
    return { mode: 'singleton', row: out };
  }

  const orderCol = present.has(sec.orderBy) ? sec.orderBy : (sec.matchKey && present.has(sec.matchKey) ? sec.matchKey : 'rowid');
  const rows = db.prepare(`SELECT * FROM ${sec.table} ORDER BY ${orderCol}`).all();

  if (sec.mode === 'manifest') {
    const entries = rows.map((r) => {
      const out = pickCols(r, sec.manifestCols, present);
      const found = markSecrets(r, out[sec.manifestCols[0]]);
      if (found.length) out.secretsPresent = found;
      return out;
    });
    return { mode: 'manifest', entries };
  }

  // mode 'rows'
  const outRows = rows.map((r) => {
    const out = pickCols(r, sec.configCols, present);
    const found = markSecrets(r, sec.matchKey ? r[sec.matchKey] : '');
    if (found.length) out.secretsPresent = found;
    return out;
  });
  return { mode: 'rows', rows: outRows };
}

/**
 * Capture the full golden-baseline domain from the live database.
 * Returns { payload, canonical, sha256, appVersion, secretsPresent } where
 * canonical is the canonical-JSON string of payload (the bytes that are
 * stored, hashed, and signed) and secretsPresent summarizes every secret
 * column that held a value and was stripped.
 */
function captureBaseline(db) {
  const secretsPresent = [];
  const payload = {
    teamConfig: captureKv(db, 'team_config', TEAM_CONFIG_KEYS),
    configTable: captureKv(db, 'config', CONFIG_TABLE_KEYS),
    tables: {},
  };
  for (const sec of TABLE_SECTIONS) {
    const section = captureSection(db, sec, secretsPresent);
    if (section) payload.tables[sec.table] = section;
  }
  const canonical = canonicalize(payload);
  return {
    payload,
    canonical,
    sha256: sha256Hex(canonical),
    appVersion: APP_VERSION,
    secretsPresent,
  };
}

// ── Snapshot store (config_snapshots) + retention (D21) ─────────────

/**
 * Capture the current domain and store it as a config_snapshots row.
 * Retention (config_snapshot_retention, default 20): when at the cap,
 * the oldest non-manual snapshots are pruned first; a MANUAL save with
 * only manual snapshots remaining is refused (RETENTION_CAP_REACHED).
 * The automatic pre-revert / pre-import safety snapshots are never
 * refused -- protecting a destructive operation outranks the cap, so
 * they may transiently exceed it (later prunes trim back down).
 * Returns { id, name, origin, sha256, appVersion, secretsPresent, pruned }.
 * The caller audits the save and each pruned id.
 */
function saveSnapshot(db, { name, origin = 'manual', userId = null } = {}) {
  const nm = typeof name === 'string' ? name.trim() : '';
  if (!nm || nm.length > 100) {
    throw new GBError(CODES.INVALID_INPUT, 'name required (max 100 chars)');
  }
  if (!SNAPSHOT_ORIGINS.includes(origin)) {
    throw new GBError(CODES.INVALID_INPUT, `origin must be one of ${SNAPSHOT_ORIGINS.join(', ')}`);
  }

  const cap = readRetention(db);
  const pruned = [];
  const countStmt = db.prepare('SELECT COUNT(*) AS c FROM config_snapshots');
  const victimStmt = db.prepare(
    "SELECT id FROM config_snapshots WHERE origin != 'manual' ORDER BY created_at ASC, id ASC LIMIT 1"
  );
  const deleteStmt = db.prepare('DELETE FROM config_snapshots WHERE id = ?');
  while (countStmt.get().c >= cap) {
    const victim = victimStmt.get();
    if (!victim) break;
    deleteStmt.run(victim.id);
    pruned.push(victim.id);
  }
  if (countStmt.get().c >= cap && origin === 'manual') {
    throw new GBError(
      CODES.RETENTION_CAP_REACHED,
      `Snapshot retention cap (${cap}) reached and only manual snapshots remain; delete one or raise ${RETENTION_CONFIG_KEY}.`
    );
  }

  const captured = captureBaseline(db);
  const insert = db.prepare(`
    INSERT INTO config_snapshots
      (id, name, origin, created_at, created_by, app_version,
       baseline_schema_version, payload, sha256)
    VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?)
  `);
  let id = Date.now().toString(36);
  try {
    insert.run(id, nm, origin, userId, captured.appVersion,
      BASELINE_SCHEMA_VERSION, captured.canonical, captured.sha256);
  } catch (err) {
    if (err && String(err.code || '').startsWith('SQLITE_CONSTRAINT')) {
      // same-millisecond id collision; retry once with a random suffix
      id = id + Math.floor(Math.random() * 1296).toString(36).padStart(2, '0');
      insert.run(id, nm, origin, userId, captured.appVersion,
        BASELINE_SCHEMA_VERSION, captured.canonical, captured.sha256);
    } else {
      throw err;
    }
  }
  return {
    id, name: nm, origin,
    sha256: captured.sha256,
    appVersion: captured.appVersion,
    secretsPresent: captured.secretsPresent,
    pruned,
  };
}

function listSnapshots(db) {
  return db.prepare(`
    SELECT id, name, origin, created_at, created_by, app_version,
           baseline_schema_version, sha256, length(payload) AS payload_bytes
    FROM config_snapshots
    ORDER BY created_at DESC, id DESC
  `).all();
}

function getSnapshot(db, id) {
  const row = db.prepare('SELECT * FROM config_snapshots WHERE id = ?').get(String(id));
  if (!row) throw new GBError(CODES.SNAPSHOT_NOT_FOUND, 'Snapshot not found');
  return row;
}

function deleteSnapshot(db, id) {
  const res = db.prepare('DELETE FROM config_snapshots WHERE id = ?').run(String(id));
  if (res.changes === 0) throw new GBError(CODES.SNAPSHOT_NOT_FOUND, 'Snapshot not found');
  return { deleted: String(id) };
}

// ── Apply (transactional full-replace, D20) ─────────────────────────

function applyKvStore(db, table, allowlist, obj, userId, report) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    report.warnings.push(`${table}: section absent from the baseline; existing keys left unchanged.`);
    return { skipped: true };
  }
  const upsert = table === 'team_config'
    ? db.prepare('INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES (?, ?, ?)')
    : db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)');
  const remove = db.prepare(`DELETE FROM ${table} WHERE key = ?`);
  let upserts = 0;
  let deletes = 0;
  // Iterate the ALLOWLIST, never the payload: an unknown key in a payload
  // can never reach the database through this function.
  for (const key of allowlist) {
    if (hasOwn(obj, key)) {
      const value = obj[key] === null || obj[key] === undefined ? '' : String(obj[key]);
      if (table === 'team_config') upsert.run(key, value, userId);
      else upsert.run(key, value);
      upserts += 1;
    } else {
      deletes += remove.run(key).changes;
    }
  }
  return { upserts, deletes };
}

function applyRowsSection(db, sec, sectionPayload, report, userId) {
  const present = tableColumns(db, sec.table);
  if (present.size === 0) {
    report.warnings.push(`${sec.table}: table not present in this install; section skipped.`);
    return { skipped: true };
  }
  if (!sectionPayload || !Array.isArray(sectionPayload.rows)) {
    report.warnings.push(`${sec.table}: section absent from the baseline; existing rows left unchanged.`);
    return { skipped: true };
  }
  const cols = sec.configCols.filter((c) => present.has(c));
  const secretCols = (sec.secretCols || []).filter((c) => present.has(c));
  const resetCols = sec.resetCols
    ? Object.keys(sec.resetCols).filter(
        (c) => present.has(c) && !cols.includes(c) && !secretCols.includes(c)
      )
    : [];
  const existing = secretCols.length ? db.prepare(`SELECT * FROM ${sec.table}`).all() : [];
  const existingByMatch = new Map(existing.map((r) => [r[sec.matchKey], r]));

  db.prepare(`DELETE FROM ${sec.table}`).run();

  const allCols = cols.concat(resetCols, secretCols);
  const insert = db.prepare(
    `INSERT INTO ${sec.table} (${allCols.join(', ')}) VALUES (${allCols.map(() => '?').join(', ')})`
  );
  let inserted = 0;
  for (const raw of sectionPayload.rows) {
    if (!raw || typeof raw !== 'object') continue;
    const working = pickCols(raw, cols, present);
    if (sec.resetCols) {
      for (const [rc, rv] of Object.entries(sec.resetCols)) {
        if (present.has(rc)) working[rc] = rv;
      }
    }
    const wanted = Array.isArray(raw.secretsPresent) ? raw.secretsPresent : [];
    const secretValues = {};
    const match = sec.matchKey ? existingByMatch.get(raw[sec.matchKey]) : undefined;
    for (const scol of secretCols) {
      const wants = wanted.includes(scol);
      const preserved = wants && match && match[scol] !== null && match[scol] !== undefined
        ? match[scol] : null;
      secretValues[scol] = preserved;
      if (wants && preserved === null) {
        const disableCol = sec.secretDisables ? sec.secretDisables[scol] : null;
        if (disableCol && present.has(disableCol)) working[disableCol] = 0;
        report.requiresCredentials.push({
          section: sec.table,
          identifier: String(sec.matchKey ? raw[sec.matchKey] : ''),
          column: scol,
        });
      }
    }
    insert.run(...allCols.map((c) => {
      if (secretCols.includes(c)) return secretValues[c];
      return working[c] === undefined ? null : working[c];
    }));
    inserted += 1;
  }
  return { replacedWith: inserted };
}

function applySingletonSection(db, sec, sectionPayload, report) {
  const present = tableColumns(db, sec.table);
  if (present.size === 0) {
    report.warnings.push(`${sec.table}: table not present in this install; section skipped.`);
    return { skipped: true };
  }
  if (!sectionPayload || !('row' in sectionPayload)) {
    report.warnings.push(`${sec.table}: section absent from the baseline; existing row left unchanged.`);
    return { skipped: true };
  }
  if (sectionPayload.row === null) {
    const removed = db.prepare(`DELETE FROM ${sec.table} WHERE ${sec.idCol} = ?`).run(sec.singletonId).changes;
    return { removed: removed > 0 };
  }
  const raw = sectionPayload.row;
  if (typeof raw !== 'object') {
    report.warnings.push(`${sec.table}: malformed singleton row in baseline; left unchanged.`);
    return { skipped: true };
  }
  const cols = sec.configCols.filter((c) => present.has(c));
  const secretCols = (sec.secretCols || []).filter((c) => present.has(c));
  const existing = db.prepare(`SELECT * FROM ${sec.table} WHERE ${sec.idCol} = ?`).get(sec.singletonId);

  const working = pickCols(raw, cols, present);
  const wanted = Array.isArray(raw.secretsPresent) ? raw.secretsPresent : [];
  const secretValues = {};
  for (const scol of secretCols) {
    const wants = wanted.includes(scol);
    const preserved = wants && existing && existing[scol] !== null && existing[scol] !== undefined
      ? existing[scol] : null;
    secretValues[scol] = preserved;
    if (wants && preserved === null) {
      const disableCol = sec.secretDisables ? sec.secretDisables[scol] : null;
      if (disableCol && present.has(disableCol)) working[disableCol] = 0;
      report.requiresCredentials.push({
        section: sec.table,
        identifier: String(sec.singletonId),
        column: scol,
      });
    }
  }
  const allCols = cols.concat(secretCols);
  db.prepare(
    `INSERT OR REPLACE INTO ${sec.table} (${sec.idCol}, ${allCols.join(', ')}) ` +
    `VALUES (?, ${allCols.map(() => '?').join(', ')})`
  ).run(sec.singletonId, ...allCols.map((c) => {
    if (secretCols.includes(c)) return secretValues[c];
    return working[c] === undefined ? null : working[c];
  }));
  return { restored: true };
}

function applyManifestSection(sec, sectionPayload, report) {
  const entries = sectionPayload && Array.isArray(sectionPayload.entries) ? sectionPayload.entries : [];
  if (sec.table === 'integration_config') {
    report.skippedIntegrations = entries
      .map((e) => (e && e.integration_type ? String(e.integration_type) : null))
      .filter(Boolean);
    if (report.skippedIntegrations.length) {
      report.warnings.push(
        `integration_config: ${report.skippedIntegrations.length} integration(s) listed in the baseline carry encrypted configuration that cannot travel in a baseline; existing integrations were left untouched -- configure the listed types manually.`
      );
    }
    return { manifestEntries: entries.length };
  }
  if (entries.length) {
    report.warnings.push(
      `${sec.table}: ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'} listed in the baseline carry credentials that cannot travel in a baseline; existing rows were left untouched -- re-create the listed entries manually.`
    );
  }
  return { manifestEntries: entries.length };
}

// ── Legacy (schema version 0) apply ─────────────────────────────────

function restoreLegacySingleton(db, table, id, row, report) {
  if (!row || typeof row !== 'object') return;
  const present = tableColumns(db, table);
  const cols = Object.keys(row).filter(
    (c) => c !== 'id' && c !== 'updated_at' && c !== 'updated_by' && present.has(c)
  );
  if (!cols.length) return;
  db.prepare(
    `INSERT OR REPLACE INTO ${table} (id, ${cols.join(', ')}) ` +
    `VALUES (?, ${cols.map(() => '?').join(', ')})`
  ).run(id, ...cols.map((c) => (row[c] === undefined ? null : row[c])));
  report.applied[table] = 'restored';
}

function applyLegacySnapshot(db, payload, userId, report) {
  const rows = payload && Array.isArray(payload.teamConfig) ? payload.teamConfig : [];
  const upsert = db.prepare('INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES (?, ?, ?)');
  let upserts = 0;
  for (const r of rows) {
    if (!r || typeof r.key !== 'string') continue;
    if (r.key.startsWith('config_snapshot_')) continue;
    upsert.run(r.key, r.value === null || r.value === undefined ? '' : String(r.value), userId);
    upserts += 1;
  }
  report.applied.teamConfig = { upserts, deletes: 0 };
  restoreLegacySingleton(db, 'report_config', 'default', payload ? payload.reportConfig : null, report);
  restoreLegacySingleton(db, 'sla_config', 'default', payload ? payload.slaConfig : null, report);
  restoreLegacySingleton(db, 'notification_config', 'default', payload ? payload.notifConfig : null, report);
}

// ── applyBaseline entry point ───────────────────────────────────────

/**
 * Apply a baseline payload to the live database inside one transaction.
 * schemaVersion 1 = the golden-baseline domain full-replace; 0 = a legacy
 * team_config-era snapshot (upsert-only + report/SLA/notification restore).
 * Returns a report: { schemaVersion, applied, requiresCredentials,
 * skippedIntegrations, warnings }. The route layer is responsible for the
 * pre-apply safety snapshot, the D17 import gate, and auditing.
 */
function applyBaseline(db, { schemaVersion, payload } = {}, userId = null) {
  const report = {
    schemaVersion,
    applied: {},
    requiresCredentials: [],
    skippedIntegrations: [],
    warnings: [],
  };

  if (schemaVersion === 0) {
    const tx = db.transaction(() => applyLegacySnapshot(db, payload, userId, report));
    tx();
    report.warnings.push(
      'Legacy snapshot shape (schema version 0): team_config entries were upserted with no deletions, and the report, SLA, and notification settings were restored. The full golden-baseline domain replace applies to version 1 snapshots.'
    );
    return report;
  }

  if (schemaVersion !== BASELINE_SCHEMA_VERSION) {
    throw new GBError(
      CODES.UNSUPPORTED_SCHEMA_VERSION,
      `Baseline schema version ${schemaVersion} is not supported by this build (supported: 0, ${BASELINE_SCHEMA_VERSION}).`
    );
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new GBError(CODES.INVALID_INPUT, 'Baseline payload must be an object.');
  }

  const tables = payload.tables && typeof payload.tables === 'object' ? payload.tables : {};
  const tx = db.transaction(() => {
    report.applied.teamConfig = applyKvStore(db, 'team_config', TEAM_CONFIG_KEYS, payload.teamConfig, userId, report);
    report.applied.configTable = applyKvStore(db, 'config', CONFIG_TABLE_KEYS, payload.configTable, null, report);
    for (const sec of TABLE_SECTIONS) {
      const sectionPayload = tables[sec.table];
      if (sec.mode === 'manifest') {
        report.applied[sec.table] = applyManifestSection(sec, sectionPayload, report);
      } else if (sec.mode === 'rows') {
        report.applied[sec.table] = applyRowsSection(db, sec, sectionPayload, report, userId);
      } else {
        report.applied[sec.table] = applySingletonSection(db, sec, sectionPayload, report);
      }
    }
  });
  tx();
  return report;
}

// ── Diff (the Change Report) ────────────────────────────────────────

function shortValue(v) {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'object' ? canonicalize(v) : String(v);
  return s.length > 200 ? s.slice(0, 200) + '...' : s;
}

/**
 * Compare the live configuration against a version-1 baseline payload.
 * Direction: "added" means the baseline contains it and the live config
 * does not (applying the baseline would ADD it); "removed" means the live
 * config has it and the baseline does not (applying would REMOVE it).
 */
function diffBaseline(db, { schemaVersion, payload } = {}) {
  if (schemaVersion === 0) {
    throw new GBError(
      CODES.LEGACY_DIFF_UNSUPPORTED,
      'Change reports are not available for legacy (schema version 0) snapshots.'
    );
  }
  if (schemaVersion !== BASELINE_SCHEMA_VERSION) {
    throw new GBError(
      CODES.UNSUPPORTED_SCHEMA_VERSION,
      `Baseline schema version ${schemaVersion} is not supported by this build (supported: 0, ${BASELINE_SCHEMA_VERSION}).`
    );
  }
  const current = captureBaseline(db).payload;
  const base = payload && typeof payload === 'object' ? payload : {};
  const out = { added: [], removed: [], changed: [] };

  const diffMaps = (label, curMap, balMap) => {
    const keys = Array.from(new Set(
      Object.keys(curMap || {}).concat(Object.keys(balMap || {}))
    )).sort();
    for (const k of keys) {
      const inCur = hasOwn(curMap, k);
      const inBal = hasOwn(balMap, k);
      if (inBal && !inCur) out.added.push({ path: `${label}.${k}`, baseline: shortValue(balMap[k]) });
      else if (inCur && !inBal) out.removed.push({ path: `${label}.${k}`, current: shortValue(curMap[k]) });
      else if (inCur && inBal && canonicalize(curMap[k]) !== canonicalize(balMap[k])) {
        out.changed.push({ path: `${label}.${k}`, current: shortValue(curMap[k]), baseline: shortValue(balMap[k]) });
      }
    }
  };

  diffMaps('team_config', current.teamConfig, base.teamConfig || {});
  diffMaps('config', current.configTable, base.configTable || {});

  const balTables = base.tables && typeof base.tables === 'object' ? base.tables : {};
  for (const sec of TABLE_SECTIONS) {
    const curSection = current.tables[sec.table];
    const balSection = balTables[sec.table];
    if (sec.mode === 'singleton') {
      const curRow = curSection ? curSection.row : null;
      const balRow = balSection && 'row' in balSection ? balSection.row : null;
      if (balRow && !curRow) out.added.push({ path: sec.table, baseline: shortValue(balRow) });
      else if (curRow && !balRow) out.removed.push({ path: sec.table, current: shortValue(curRow) });
      else if (curRow && balRow) diffMaps(sec.table, curRow, balRow);
      continue;
    }
    const keyOf = (e) => String(e && (sec.matchKey ? e[sec.matchKey] : e[(sec.manifestCols || [])[0]]));
    const curList = curSection ? (curSection.rows || curSection.entries || []) : [];
    const balList = balSection ? (balSection.rows || balSection.entries || []) : [];
    const curMap = {};
    for (const e of curList) curMap[keyOf(e)] = e;
    const balMap = {};
    for (const e of balList) balMap[keyOf(e)] = e;
    diffMaps(sec.table, curMap, balMap);
  }
  return out;
}

// ── Exports ─────────────────────────────────────────────────────────

module.exports = {
  BASELINE_SCHEMA_VERSION,
  SNAPSHOT_ORIGINS,
  RETENTION_CONFIG_KEY,
  RETENTION_DEFAULT,
  TEAM_CONFIG_KEYS,
  CONFIG_TABLE_KEYS,
  TABLE_SECTIONS,
  GBError,
  CODES,
  readRetention,
  captureBaseline,
  saveSnapshot,
  listSnapshots,
  getSnapshot,
  deleteSnapshot,
  applyBaseline,
  diffBaseline,
};

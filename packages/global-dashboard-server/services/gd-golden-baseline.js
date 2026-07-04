// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- Golden-Baseline Configuration Domain
// (capture / apply / diff)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// THE GD GOLDEN BASELINE (the GD twin of the Regional Server's golden-baseline)
//
// A golden baseline is the portable, secrets-free, reviewable image of this
// Global Dashboard's configuration: everything an operator needs to restore its
// settings or stand up a freshly-deployed GD to its approved state. It is
// captured here as one canonical-JSON payload, stored in config_snapshots,
// exported as a signed bundle, and applied back as a transactional full-replace
// of the domain.
//
// WHAT IS IN THE DOMAIN (the explicit allowlist below)
//   - config-table configuration keys (CONFIG_TABLE_KEYS)
//   - the dedicated configuration tables (TABLE_SECTIONS): storage
//     destinations + their routing, data-residency destinations, and backup
//     schedules
//
// The GD has no team_config table, so unlike the Regional Server there is no
// team_config KV section and no legacy (schema version 0) snapshot shape; every
// baseline is schema version 1.
//
// WHAT IS NEVER IN A BASELINE (hard exclusions)
//   - secret material of any kind: encrypted credential blobs
//     (storage_destinations.credentials_encrypted) and the cicd_webhook_secret
//     config key
//   - the EDR / malware-scanner integrations table
//     (malware_scanner_integrations): its whole configuration is a NOT NULL
//     encrypted-credentials secret, so it cannot travel in a secrets-free
//     baseline; it is reconfigured directly or restored from a backup, matching
//     the Regional Server (which also excludes its scanner table)
//   - every signing-key table (backup / archive-chain / audit / report /
//     forensic / MC-trust) and the CA: keys are deployment identity, not
//     configuration
//   - the sealed deployment_mode record (re-established on the target, never
//     carried), instance_label, and the anti-rollback fuse / schema / app
//     version state
//   - config_lock_state and system_meta (identity / lock / operational state)
//   - integration_health_last_results (a cache)
//   - all operational data -- registered management-console bindings and
//     collisions, MC compliance reports and requests, residency transfer
//     records, storage archive segments, the notifications log -- which rides
//     in the full-suite backup, not the curated baseline
//
// SECRETS MODEL (the sensitive-field omission rule)
//   Capture records WHICH secret columns held a value via per-entry
//   secretsPresent markers, never the values. Apply preserves an
//   identity-matched existing row's stored secret (matched by matchKey) when the
//   baseline marks it present, so importing a baseline onto a deployment that
//   already holds working credentials does not wipe them. Where no secret can be
//   preserved, the dependent capability lands disabled-pending-credentials
//   (enabled=0) and is reported in requiresCredentials for the operator to
//   re-enter.
//
// APPLY SEMANTICS
//   Payloads apply as a transactional FULL-REPLACE of the domain: allowlisted
//   keys/rows present in the baseline are written, allowlisted keys/rows absent
//   from it are removed. Nothing outside the allowlist is ever touched -- apply
//   iterates the allowlist, not the payload, so an unknown key in a payload can
//   never reach the database. The route layer takes an automatic pre-import
//   snapshot first and gates the whole surface behind the config-lock plus a
//   fresh MFA step-up.
// -----------------------------------------------------------------------------

const { canonicalize, sha256Hex } = require('./report-signer');
const APP_VERSION = require('../package.json').version;

const BASELINE_SCHEMA_VERSION = 1;
const SNAPSHOT_ORIGINS = ['manual', 'pre-revert', 'pre-import'];
const RETENTION_CONFIG_KEY = 'config_snapshot_retention';
const RETENTION_DEFAULT = 20;
const RETENTION_MAX = 500;

// -- Typed errors --------------------------------------------------------------

const CODES = {
  INVALID_INPUT: 'INVALID_INPUT',
  RETENTION_CAP_REACHED: 'RETENTION_CAP_REACHED',
  SNAPSHOT_NOT_FOUND: 'SNAPSHOT_NOT_FOUND',
  UNSUPPORTED_SCHEMA_VERSION: 'UNSUPPORTED_SCHEMA_VERSION',
};

class GBError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'GBError';
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}

// -- The domain allowlists -----------------------------------------------------

// config-table keys that are configuration. Excluded siblings (secret, identity,
// anti-rollback, cache, sealed mode): cicd_webhook_secret (a secret),
// instance_label (deployment identity), deployment_mode (the sealed mode -- never
// carried), schema_version / app_version / fuse_counter / fuse_high_water
// (identity / anti-rollback state), integration_health_last_results (a cache).
const CONFIG_TABLE_KEYS = [
  'alert_routing_matrix',
  'auto_update_schedule_config',
  'data_residency_config',
  'integration_health_probes_enabled',
  'max_chain_depth',
  'notification_config',
  'runtime_monitor_thresholds',
  'siem_config',
  'signing_key_grace_period_minutes',
  'soar_config',
];

// The dedicated configuration tables. Each section declares exactly which columns
// are configuration (configCols), which are secrets stripped at capture and
// preserved-or-disabled at apply (secretCols + secretDisables), and which state
// columns are dropped (resetCols force a value on apply; their DEFAULTs refill
// otherwise). Column lists are intersected with PRAGMA table_info at runtime so a
// column added or absent in a given install degrades gracefully.
//
//   mode 'rows'      multi-row table; full-replace; rows matched to the
//                    pre-replace table by matchKey for secret preservation
// noIdCarry skips a generated/AUTOINCREMENT primary key on insert.
const TABLE_SECTIONS = [
  {
    table: 'storage_destinations', mode: 'rows', matchKey: 'name', orderBy: 'name',
    configCols: ['id', 'name', 'adapter', 'config', 'enabled', 'retention_days'],
    secretCols: ['credentials_encrypted'],
    secretDisables: { credentials_encrypted: 'enabled' },
    resetCols: { immutability_mode: 'unknown' },
  },
  {
    table: 'storage_destination_routes', mode: 'rows', matchKey: 'data_type', orderBy: 'data_type',
    configCols: ['data_type', 'destination_ref', 'secondary_destination_ref',
      'path_prefix', 'options', 'enabled'],
    secretCols: [],
  },
  {
    table: 'data_residency_destinations', mode: 'rows', matchKey: 'destination_ref',
    orderBy: 'destination_ref', noIdCarry: true,
    configCols: ['destination_kind', 'destination_ref', 'declared_country',
      'declared_region', 'provider_domicile', 'key_custody'],
    secretCols: [],
  },
  {
    table: 'backup_schedules', mode: 'rows', orderBy: 'type', noIdCarry: true,
    configCols: ['type', 'frequency', 'time', 'day', 'destination', 'retention_days',
      'encrypted', 'regulatory_preset', 'active'],
    secretCols: [],
  },
];

// -- Small helpers -------------------------------------------------------------

// Table names below come exclusively from TABLE_SECTIONS / fixed literals in this
// module -- never from user input -- so identifier interpolation into SQL here is
// safe by construction.
function tableColumns(db, table) {
  return new Set(db.prepare('PRAGMA table_info(' + table + ')').all().map((c) => c.name));
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

// -- Capture -------------------------------------------------------------------

function captureKv(db, table, keys) {
  const stmt = db.prepare('SELECT value FROM ' + table + ' WHERE key = ?');
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

  const orderCol = present.has(sec.orderBy) ? sec.orderBy : (sec.matchKey && present.has(sec.matchKey) ? sec.matchKey : 'rowid');
  const rows = db.prepare('SELECT * FROM ' + sec.table + ' ORDER BY ' + orderCol).all();

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
 * canonical is the canonical-JSON string of payload (the bytes that are stored,
 * hashed, and signed) and secretsPresent summarizes every secret column that
 * held a value and was stripped.
 */
function captureBaseline(db) {
  const secretsPresent = [];
  const payload = {
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

// -- Snapshot store (config_snapshots) + retention -----------------------------

/**
 * Capture the current domain and store it as a config_snapshots row.
 * Retention (config_snapshot_retention, default 20): when at the cap, the oldest
 * non-manual snapshots are pruned first; a MANUAL save with only manual snapshots
 * remaining is refused (RETENTION_CAP_REACHED). The automatic pre-revert /
 * pre-import safety snapshots are never refused -- protecting a destructive
 * operation outranks the cap, so they may transiently exceed it.
 * Returns { id, name, origin, sha256, appVersion, secretsPresent, pruned }.
 */
function saveSnapshot(db, { name, origin = 'manual', userId = null } = {}) {
  const nm = typeof name === 'string' ? name.trim() : '';
  if (!nm || nm.length > 100) {
    throw new GBError(CODES.INVALID_INPUT, 'name required (max 100 chars)');
  }
  if (!SNAPSHOT_ORIGINS.includes(origin)) {
    throw new GBError(CODES.INVALID_INPUT, 'origin must be one of ' + SNAPSHOT_ORIGINS.join(', '));
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
      'Snapshot retention cap (' + cap + ') reached and only manual snapshots remain; delete one or raise ' + RETENTION_CONFIG_KEY + '.'
    );
  }

  const captured = captureBaseline(db);
  const insert = db.prepare(
    'INSERT INTO config_snapshots '
    + '(id, name, origin, created_at, created_by, app_version, '
    + 'baseline_schema_version, payload, sha256) '
    + "VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?)"
  );
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
  return db.prepare(
    'SELECT id, name, origin, created_at, created_by, app_version, '
    + 'baseline_schema_version, sha256, length(payload) AS payload_bytes '
    + 'FROM config_snapshots '
    + 'ORDER BY created_at DESC, id DESC'
  ).all();
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

// -- Apply (transactional full-replace) ----------------------------------------

function applyKvStore(db, table, allowlist, obj, report) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    report.warnings.push(table + ': section absent from the baseline; existing keys left unchanged.');
    return { skipped: true };
  }
  const upsert = db.prepare('INSERT OR REPLACE INTO ' + table + ' (key, value) VALUES (?, ?)');
  const remove = db.prepare('DELETE FROM ' + table + ' WHERE key = ?');
  let upserts = 0;
  let deletes = 0;
  // Iterate the ALLOWLIST, never the payload: an unknown key in a payload can
  // never reach the database through this function.
  for (const key of allowlist) {
    if (hasOwn(obj, key)) {
      const value = obj[key] === null || obj[key] === undefined ? '' : String(obj[key]);
      upsert.run(key, value);
      upserts += 1;
    } else {
      deletes += remove.run(key).changes;
    }
  }
  return { upserts, deletes };
}

function applyRowsSection(db, sec, sectionPayload, report) {
  const present = tableColumns(db, sec.table);
  if (present.size === 0) {
    report.warnings.push(sec.table + ': table not present in this install; section skipped.');
    return { skipped: true };
  }
  if (!sectionPayload || !Array.isArray(sectionPayload.rows)) {
    report.warnings.push(sec.table + ': section absent from the baseline; existing rows left unchanged.');
    return { skipped: true };
  }
  const cols = sec.configCols.filter((c) => present.has(c) && !(sec.noIdCarry && c === 'id'));
  const secretCols = (sec.secretCols || []).filter((c) => present.has(c));
  const resetCols = sec.resetCols
    ? Object.keys(sec.resetCols).filter(
        (c) => present.has(c) && !cols.includes(c) && !secretCols.includes(c)
      )
    : [];
  const existing = secretCols.length ? db.prepare('SELECT * FROM ' + sec.table).all() : [];
  const existingByMatch = new Map(existing.map((r) => [r[sec.matchKey], r]));

  db.prepare('DELETE FROM ' + sec.table).run();

  const allCols = cols.concat(resetCols, secretCols);
  const insert = db.prepare(
    'INSERT INTO ' + sec.table + ' (' + allCols.join(', ') + ') VALUES (' + allCols.map(() => '?').join(', ') + ')'
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

// -- applyBaseline entry point -------------------------------------------------

/**
 * Apply a baseline payload to the live database inside one transaction. Only
 * schema version 1 (the golden-baseline domain full-replace) is supported; the
 * GD has no legacy team_config-era snapshot shape. Returns a report:
 * { schemaVersion, applied, requiresCredentials, warnings }. The route layer is
 * responsible for the pre-apply safety snapshot, the import gate, and auditing.
 */
function applyBaseline(db, { schemaVersion, payload } = {}) {
  const report = {
    schemaVersion,
    applied: {},
    requiresCredentials: [],
    warnings: [],
  };

  if (schemaVersion !== BASELINE_SCHEMA_VERSION) {
    throw new GBError(
      CODES.UNSUPPORTED_SCHEMA_VERSION,
      'Baseline schema version ' + schemaVersion + ' is not supported by this build (supported: ' + BASELINE_SCHEMA_VERSION + ').'
    );
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new GBError(CODES.INVALID_INPUT, 'Baseline payload must be an object.');
  }

  const tx = db.transaction(() => {
    report.applied.configTable = applyKvStore(db, 'config', CONFIG_TABLE_KEYS, payload.configTable, report);
    const tables = payload.tables && typeof payload.tables === 'object' ? payload.tables : {};
    for (const sec of TABLE_SECTIONS) {
      report.applied[sec.table] = applyRowsSection(db, sec, tables[sec.table], report);
    }
  });
  tx();
  return report;
}

// -- Diff (the Change Report) --------------------------------------------------

function shortValue(v) {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'object' ? canonicalize(v) : String(v);
  return s.length > 200 ? s.slice(0, 200) + '...' : s;
}

/**
 * Compare the live configuration against a version-1 baseline payload.
 * Direction: "added" means the baseline contains it and the live config does not
 * (applying the baseline would ADD it); "removed" means the live config has it
 * and the baseline does not (applying would REMOVE it).
 */
function diffBaseline(db, { schemaVersion, payload } = {}) {
  if (schemaVersion !== BASELINE_SCHEMA_VERSION) {
    throw new GBError(
      CODES.UNSUPPORTED_SCHEMA_VERSION,
      'Baseline schema version ' + schemaVersion + ' is not supported by this build (supported: ' + BASELINE_SCHEMA_VERSION + ').'
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
      if (inBal && !inCur) out.added.push({ path: label + '.' + k, baseline: shortValue(balMap[k]) });
      else if (inCur && !inBal) out.removed.push({ path: label + '.' + k, current: shortValue(curMap[k]) });
      else if (inCur && inBal && canonicalize(curMap[k]) !== canonicalize(balMap[k])) {
        out.changed.push({ path: label + '.' + k, current: shortValue(curMap[k]), baseline: shortValue(balMap[k]) });
      }
    }
  };

  diffMaps('config', current.configTable, base.configTable || {});

  const balTables = base.tables && typeof base.tables === 'object' ? base.tables : {};
  for (const sec of TABLE_SECTIONS) {
    const curSection = current.tables[sec.table];
    const balSection = balTables[sec.table];
    const keyOf = (e) => String(e && (sec.matchKey ? e[sec.matchKey] : e[sec.configCols[0]]));
    const curList = curSection ? (curSection.rows || []) : [];
    const balList = balSection ? (balSection.rows || []) : [];
    const curMap = {};
    for (const e of curList) curMap[keyOf(e)] = e;
    const balMap = {};
    for (const e of balList) balMap[keyOf(e)] = e;
    diffMaps(sec.table, curMap, balMap);
  }
  return out;
}

// -- Exports -------------------------------------------------------------------

module.exports = {
  BASELINE_SCHEMA_VERSION,
  SNAPSHOT_ORIGINS,
  RETENTION_CONFIG_KEY,
  RETENTION_DEFAULT,
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

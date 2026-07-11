// FIREALIVE -- HA change-data-capture (B5o)
//
// Trigger-based logical CDC for active/passive replication. On the active, an
// AFTER INSERT/UPDATE/DELETE trigger on every replicated table appends the
// committed row change to ha_replication_journal (table, op, primary key, and
// the full row as JSON). ha-replication ships those rows to the passive, which
// applies them by primary key. The triggers are WHEN-gated on the active role,
// so they are completely inert when this node is standalone or passive -- no
// journal rows, no overhead beyond one indexed singleton lookup per write.
//
// Why trigger-based (decided in the B5o pre-flight, proven in the build harness):
//   - It captures COMMITTED values, so it is deterministic -- unlike statement-
//     based replication it does not re-evaluate datetime('now') / randomblob() on
//     the passive, and unlike WAL-frame shipping it is logical (no byte-identical
//     page-layout requirement).
//   - It needs no interception of application write code (the SQLite session /
//     changeset extension is not bundled by better-sqlite3; an app-level write
//     chokepoint does not exist until the O2 connection manager).
//
// BLOB columns cannot be serialized by json_object, so they are captured with
// hex() and decoded back to blobs on apply using the DESTINATION column types
// (the schema is the metadata -- no per-row markers needed). Integer values pass
// through JSON; FireAlive uses TEXT ids and small/epoch integers, all well under
// JSON's 2^53 safe range. Primary-key columns are assumed immutable (FireAlive
// never updates a PK), so an UPDATE captures the NEW key.
//
// The baseline snapshot uses VACUUM INTO -- a single synchronous statement that
// writes a fully consistent copy (a plain file copy of a live WAL database is
// not safe). It is used for initial sync at pairing and periodic drift
// correction; ha-replication ships it and the passive restores it.
//
// ASCII-only strings; SQL is built by concatenation (no template literals).

const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');

const TRIGGER_PREFIX = 'fa_ha_cdc_';

// Node-local tables that must NEVER be replicated to the peer. The 'ha_' prefix
// covers the HA control plane; instance_* is per-hardware identity that must not
// be overwritten on the passive; the audit / auth logs and their hash-chain and
// signing-key tables are kept local to avoid forking per-node chains (reconciled
// at the GD -- see the B5o plan, section 3.6). Everything else (operational,
// burnout, config, ticket, training data the passive must serve after promotion)
// is replicated. Callers may pass additional exclusions; the precise operational-
// vs-local boundary for chain tables is finalized with the replication engine.
const DEFAULT_EXCLUDE_TABLES = [
  'ha_node', 'ha_peer', 'ha_lease', 'ha_replication_journal', 'ha_replication_state',
  'instance_identity', 'instance_observations', 'node_state',
  'audit_log', 'auth_log', 'audit_chain_checkpoint', 'audit_chain_signing_keys',
];
const DEFAULT_EXCLUDE_PREFIXES = ['ha_', 'sqlite_'];
const DEFAULT_EXCLUDE_SUFFIXES = ['_signing_keys']; // per-node signing key material

function quoteIdent(name) {
  return '"' + String(name).replace(/"/g, '""') + '"';
}

function sqlStrLiteral(s) {
  return "'" + String(s).replace(/'/g, "''") + "'";
}

function isExcluded(name, opts) {
  const exTables = (opts && opts.excludeTables) || DEFAULT_EXCLUDE_TABLES;
  const exPrefixes = (opts && opts.excludePrefixes) || DEFAULT_EXCLUDE_PREFIXES;
  const exSuffixes = (opts && opts.excludeSuffixes) || DEFAULT_EXCLUDE_SUFFIXES;
  if (exTables.indexOf(name) !== -1) {
    return true;
  }
  for (let i = 0; i < exPrefixes.length; i++) {
    if (name.indexOf(exPrefixes[i]) === 0) {
      return true;
    }
  }
  for (let j = 0; j < exSuffixes.length; j++) {
    const suf = exSuffixes[j];
    if (name.length >= suf.length && name.slice(-suf.length) === suf) {
      return true;
    }
  }
  return false;
}

// Every replicated base table: all user tables minus the exclude set and minus
// SQLite internal tables.
function listReplicatedTables(db, opts) {
  const rows = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all();
  const out = [];
  for (let i = 0; i < rows.length; i++) {
    if (!isExcluded(rows[i].name, opts)) {
      out.push(rows[i].name);
    }
  }
  return out;
}

function isBlobType(declType) {
  return typeof declType === 'string' && declType.toUpperCase().indexOf('BLOB') !== -1;
}

// Column metadata for a table: { name, type, isBlob, pk }.
function tableColumns(db, table) {
  const info = db.prepare('PRAGMA table_info(' + quoteIdent(table) + ')').all();
  return info.map(function (c) {
    return { name: c.name, type: c.type, isBlob: isBlobType(c.type), pk: c.pk };
  });
}

// The primary-key columns of a table, ordered by their position in the key.
function tableKeyColumns(db, table) {
  return tableColumns(db, table)
    .filter(function (c) { return c.pk > 0; })
    .sort(function (a, b) { return a.pk - b.pk; });
}

// Build a json_object(...) expression over the given columns using the NEW/OLD
// row alias. BLOB columns are hex()-encoded so the JSON stays valid text.
function jsonObjectExpr(cols, rowAlias) {
  const parts = [];
  for (let i = 0; i < cols.length; i++) {
    const c = cols[i];
    const valueExpr = c.isBlob
      ? ('CASE WHEN ' + rowAlias + '.' + quoteIdent(c.name) + ' IS NULL THEN NULL ELSE hex(' + rowAlias + '.' + quoteIdent(c.name) + ') END')
      : (rowAlias + '.' + quoteIdent(c.name));
    parts.push(sqlStrLiteral(c.name) + ', ' + valueExpr);
  }
  return 'json_object(' + parts.join(', ') + ')';
}

function epochExpr() {
  return "COALESCE((SELECT epoch FROM ha_lease WHERE id = 'current'), 0)";
}

// Only journal when this node is the active writer; inert otherwise.
function activeGuard() {
  return "COALESCE((SELECT role FROM ha_node WHERE id = 'self'), 'standalone') = 'active'";
}

function triggerName(table, op) {
  return TRIGGER_PREFIX + table + '_' + op;
}

// Build one AFTER trigger. event is the trigger event AND the journal op string
// ('INSERT' | 'UPDATE' | 'DELETE'). body = { pk: <expr>, row: <expr or 'NULL'> }.
function oneTrigger(name, event, table, body) {
  const lines = [];
  lines.push('DROP TRIGGER IF EXISTS ' + quoteIdent(name) + ';');
  lines.push('CREATE TRIGGER ' + quoteIdent(name) + ' AFTER ' + event + ' ON ' + quoteIdent(table));
  lines.push('WHEN ' + activeGuard());
  lines.push('BEGIN');
  lines.push('  INSERT INTO ha_replication_journal (epoch, table_name, op, pk_json, row_json) VALUES (');
  lines.push('    ' + epochExpr() + ', ' + sqlStrLiteral(table) + ', ' + sqlStrLiteral(event) + ',');
  lines.push('    ' + body.pk + ',');
  lines.push('    ' + body.row);
  lines.push('  );');
  lines.push('END;');
  return lines.join('\n');
}

// The three CDC triggers (insert / update / delete) for one table.
function triggerSqlForTable(db, table) {
  const cols = tableColumns(db, table);
  const pkCols = tableKeyColumns(db, table);
  const keyCols = pkCols.length ? pkCols : cols; // no PK-less table in this schema; safe fallback
  const ins = oneTrigger(triggerName(table, 'ins'), 'INSERT', table, {
    pk: jsonObjectExpr(keyCols, 'NEW'),
    row: jsonObjectExpr(cols, 'NEW'),
  });
  const upd = oneTrigger(triggerName(table, 'upd'), 'UPDATE', table, {
    pk: jsonObjectExpr(keyCols, 'NEW'),
    row: jsonObjectExpr(cols, 'NEW'),
  });
  const del = oneTrigger(triggerName(table, 'del'), 'DELETE', table, {
    pk: jsonObjectExpr(keyCols, 'OLD'),
    row: 'NULL',
  });
  return [ins, upd, del].join('\n');
}

function listCdcTriggers(db) {
  return db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger'").all()
    .map(function (r) { return r.name; })
    .filter(function (n) { return typeof n === 'string' && n.indexOf(TRIGGER_PREFIX) === 0; });
}

// Drop every fa_ha_cdc_* trigger (so a removed/renamed table leaves no orphan).
function dropTriggers(db) {
  const trigs = listCdcTriggers(db);
  for (let i = 0; i < trigs.length; i++) {
    db.exec('DROP TRIGGER IF EXISTS ' + quoteIdent(trigs[i]));
  }
  return { dropped: trigs.length };
}

// (Re)generate the CDC triggers for all replicated tables. Idempotent: drops the
// current set first, then recreates it. Call when HA is enabled and after any
// schema change. Inert until this node holds the active role (WHEN-gated).
function regenerateTriggers(db, opts) {
  dropTriggers(db);
  const tables = listReplicatedTables(db, opts);
  for (let i = 0; i < tables.length; i++) {
    db.exec(triggerSqlForTable(db, tables[i]));
  }
  return { tables: tables.length, triggers: tables.length * 3 };
}

// Produce a consistent on-disk snapshot for initial sync or drift correction.
// Returns { path, bytes }. ha-replication ships it; the passive restores it.
function createBaselineSnapshot(db, outPath) {
  const dest = outPath || path.join(
    os.tmpdir(),
    'firealive-ha-baseline-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + '.sqlite'
  );
  db.exec('VACUUM INTO ' + sqlStrLiteral(dest));
  let bytes = 0;
  try { bytes = fs.statSync(dest).size; } catch (err) { bytes = 0; }
  return { path: dest, bytes: bytes };
}

module.exports = {
  TRIGGER_PREFIX,
  DEFAULT_EXCLUDE_TABLES,
  DEFAULT_EXCLUDE_PREFIXES,
  DEFAULT_EXCLUDE_SUFFIXES,
  listReplicatedTables,
  tableColumns,
  tableKeyColumns,
  triggerSqlForTable,
  regenerateTriggers,
  dropTriggers,
  listCdcTriggers,
  createBaselineSnapshot,
};

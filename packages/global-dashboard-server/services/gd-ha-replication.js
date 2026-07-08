// FIREALIVE GLOBAL DASHBOARD -- HA replication engine (B6d)
//
// The GD twin of server/services/ha/ha-replication.js. The active is the sole
// writer. gd-ha-cdc triggers append each committed row change to
// gd_ha_replication_journal; this module ships those rows to the passive and
// applies them there. The split:
//
//   ACTIVE  -- collectBatch -> shipOnce(sendFn) -> recordAck/prune/computeLag.
//             A cadence tick (the scheduler) ships journal rows with lsn beyond
//             the last acked, then advances the cursor on the peer's ack.
//   PASSIVE -- applyBatch (called from the inbound /ha/peer/replicate route).
//             Applies a received batch in ONE transaction, fenced on the epoch.
//
// Fencing: every row carries the writing epoch. If a batch's minimum epoch is
// below this node's current lease epoch, the active that sent it is stale (a
// newer active exists, or this node has promoted), so the whole batch is
// rejected -- the no-split-brain guarantee. The sender then steps down.
//
// Apply uses an UPSERT (INSERT ... ON CONFLICT(pk) DO UPDATE), never INSERT OR
// REPLACE: REPLACE does a DELETE+INSERT, which would fire ON DELETE CASCADE and
// silently drop FK children. BLOB columns arrive hex-encoded (gd-ha-cdc) and are
// decoded back to blobs using the destination column types. The batch runs with
// PRAGMA defer_foreign_keys=ON so rows can apply regardless of FK order.
//
// shipOnce takes the send function by injection (the peer link is a separate
// module), so this module has no transport dependency. ASCII-only; no template
// literals.

const gdHaCdc = require('./gd-ha-cdc');

const DEFAULT_BATCH = 500;
const DEFAULT_RETAIN_ACKED = 1000; // keep this many acked journal rows for diagnostics before pruning

function qi(name) {
  return '"' + String(name).replace(/"/g, '""') + '"';
}

function ensureStateRow(db) {
  db.prepare("INSERT OR IGNORE INTO gd_ha_replication_state (id) VALUES ('self')").run();
}

function getState(db) {
  ensureStateRow(db);
  return db.prepare("SELECT * FROM gd_ha_replication_state WHERE id = 'self'").get();
}

function currentEpoch(db) {
  const r = db.prepare("SELECT epoch FROM gd_ha_lease WHERE id = 'current'").get();
  return r ? r.epoch : 0;
}

// ---------------------------------------------------------------------------
// ACTIVE side
// ---------------------------------------------------------------------------

// Collect the next batch of unshipped journal rows (lsn beyond last_shipped_lsn).
// Returns { rows, fromLsn, toLsn } or null when there is nothing to ship.
function collectBatch(db, maxRows) {
  const st = getState(db);
  const limit = maxRows || DEFAULT_BATCH;
  const rows = db.prepare(
    "SELECT lsn, epoch, table_name, op, pk_json, row_json FROM gd_ha_replication_journal WHERE lsn > ? ORDER BY lsn LIMIT ?"
  ).all(st.last_shipped_lsn, limit);
  if (!rows.length) {
    return null;
  }
  return { rows: rows, fromLsn: rows[0].lsn, toLsn: rows[rows.length - 1].lsn };
}

// Record the peer's ack: advance the shipped/acked cursors, mark rows shipped,
// and prune old acked rows.
function recordAck(db, ackedLsn, opts) {
  ensureStateRow(db);
  db.prepare(
    "UPDATE gd_ha_replication_state SET last_shipped_lsn = MAX(last_shipped_lsn, ?), last_acked_lsn = MAX(last_acked_lsn, ?) WHERE id = 'self'"
  ).run(ackedLsn, ackedLsn);
  db.prepare("UPDATE gd_ha_replication_journal SET shipped = 1 WHERE lsn <= ?").run(ackedLsn);
  pruneJournal(db, opts);
}

// Delete acked journal rows older than the retain window (keep the most recent
// retainAcked acked rows for diagnostics).
function pruneJournal(db, opts) {
  const retain = (opts && opts.retainAcked != null) ? opts.retainAcked : DEFAULT_RETAIN_ACKED;
  const st = getState(db);
  db.prepare("DELETE FROM gd_ha_replication_journal WHERE shipped = 1 AND lsn <= (? - ?)").run(st.last_acked_lsn, retain);
}

// Replication lag = age of the oldest journal row the passive has not yet acked.
// 0 when the passive is fully caught up. Also refreshes last_journaled_lsn.
function computeLag(db) {
  ensureStateRow(db);
  const st = getState(db);
  let lag = 0;
  const oldest = db.prepare(
    "SELECT created_at FROM gd_ha_replication_journal WHERE lsn > ? ORDER BY lsn LIMIT 1"
  ).get(st.last_acked_lsn);
  if (oldest && oldest.created_at) {
    const ageRow = db.prepare("SELECT (julianday('now') - julianday(?)) * 86400.0 AS secs").get(oldest.created_at);
    lag = (ageRow && ageRow.secs > 0) ? ageRow.secs : 0;
  }
  db.prepare(
    "UPDATE gd_ha_replication_state SET lag_seconds = ?, last_journaled_lsn = (SELECT COALESCE(MAX(lsn), 0) FROM gd_ha_replication_journal) WHERE id = 'self'"
  ).run(lag);
  return lag;
}

// Ship one batch via the injected sendFn(payload) -> { ok, lastAppliedLsn }.
// On a peer rejection (stale epoch) throws with .peerRejection set, so the
// caller (failover logic) can step this node down. Returns a small summary.
async function shipOnce(db, sendFn, opts) {
  const batch = collectBatch(db, opts && opts.maxRows);
  if (!batch) {
    const lag0 = computeLag(db);
    return { shipped: 0, ackedLsn: getState(db).last_acked_lsn, lag: lag0 };
  }
  const epoch = currentEpoch(db);
  const ack = await sendFn({ epoch: epoch, fromLsn: batch.fromLsn, toLsn: batch.toLsn, rows: batch.rows });
  if (!ack || ack.ok === false) {
    const err = new Error('gd-ha-replication: peer rejected batch' + (ack && ack.reason ? ' (' + ack.reason + ')' : ''));
    err.peerRejection = ack || null;
    throw err;
  }
  const reported = (ack.lastAppliedLsn != null) ? ack.lastAppliedLsn : batch.toLsn;
  const ackedLsn = Math.min(reported, batch.toLsn);
  recordAck(db, ackedLsn, opts);
  const lag = computeLag(db);
  return { shipped: batch.rows.length, ackedLsn: ackedLsn, lag: lag };
}

// ---------------------------------------------------------------------------
// PASSIVE side
// ---------------------------------------------------------------------------

function tableMeta(db, cache, table) {
  if (cache[table]) {
    return cache[table];
  }
  const cols = db.prepare('PRAGMA table_info(' + qi(table) + ')').all();
  const pk = cols.filter(function (c) { return c.pk > 0; }).sort(function (a, b) { return a.pk - b.pk; });
  const colNames = cols.map(function (c) { return c.name; });
  const pkNames = (pk.length ? pk : cols).map(function (c) { return c.name; });
  const blob = {};
  cols.forEach(function (c) { if (/BLOB/i.test(c.type)) { blob[c.name] = true; } });
  const nonPk = colNames.filter(function (n) { return pkNames.indexOf(n) === -1; });
  let upsert = 'INSERT INTO ' + qi(table) + ' (' + colNames.map(qi).join(', ') + ') VALUES ('
    + colNames.map(function () { return '?'; }).join(', ') + ') ON CONFLICT(' + pkNames.map(qi).join(', ') + ') DO ';
  upsert += nonPk.length
    ? ('UPDATE SET ' + nonPk.map(function (n) { return qi(n) + ' = excluded.' + qi(n); }).join(', '))
    : 'NOTHING';
  const del = 'DELETE FROM ' + qi(table) + ' WHERE ' + pkNames.map(function (n) { return qi(n) + ' = ?'; }).join(' AND ');
  const m = {
    colNames: colNames,
    pkNames: pkNames,
    blob: blob,
    upsertStmt: db.prepare(upsert),
    delStmt: db.prepare(del),
  };
  cache[table] = m;
  return m;
}

function decodeVal(m, name, v) {
  return (m.blob[name] && v != null) ? Buffer.from(String(v), 'hex') : v;
}

// Apply a received batch under the epoch fence, in one transaction. Returns
// { ok: true, lastAppliedLsn, applied } or, on a stale-epoch batch,
// { ok: false, reason: 'stale_epoch', localEpoch, batchEpoch } without applying.
function applyBatch(db, batch) {
  const rows = (batch && batch.rows) || [];
  ensureStateRow(db);
  if (!rows.length) {
    return { ok: true, lastAppliedLsn: getState(db).last_applied_lsn, applied: 0 };
  }
  const localEpoch = currentEpoch(db);
  let minEpoch = Infinity;
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].epoch < minEpoch) {
      minEpoch = rows[i].epoch;
    }
  }
  if (minEpoch < localEpoch) {
    return { ok: false, reason: 'stale_epoch', localEpoch: localEpoch, batchEpoch: minEpoch };
  }

  // Allow-list the destination tables. table_name arrives from the peer batch, so
  // each row is checked against the set this node actually replicates (derived
  // from the schema by gd-ha-cdc), and the canonical schema name -- an element of
  // that trusted list, never the peer's string -- is what reaches the SQL in
  // tableMeta. A row targeting any other table (identity, audit, the HA control
  // plane, or anything unexpected) is refused before the batch is applied.
  const replicated = gdHaCdc.listReplicatedTables(db);
  for (let i = 0; i < rows.length; i++) {
    if (replicated.indexOf(rows[i].table_name) === -1) {
      return { ok: false, reason: 'unreplicated_table', table: String(rows[i].table_name) };
    }
  }

  const cache = {};
  db.exec('BEGIN');
  db.exec('PRAGMA defer_foreign_keys = ON');
  try {
    let lastLsn = getState(db).last_applied_lsn;
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      const safeName = replicated[replicated.indexOf(r.table_name)];
      const m = tableMeta(db, cache, safeName);
      if (r.op === 'DELETE') {
        const pk = JSON.parse(r.pk_json);
        m.delStmt.run.apply(m.delStmt, m.pkNames.map(function (n) { return decodeVal(m, n, pk[n]); }));
      } else {
        const obj = JSON.parse(r.row_json);
        m.upsertStmt.run.apply(m.upsertStmt, m.colNames.map(function (n) { return decodeVal(m, n, obj[n]); }));
      }
      if (r.lsn > lastLsn) {
        lastLsn = r.lsn;
      }
    }
    db.prepare("UPDATE gd_ha_replication_state SET last_applied_lsn = ?, last_apply_at = datetime('now') WHERE id = 'self'").run(lastLsn);
    db.exec('COMMIT');
    return { ok: true, lastAppliedLsn: lastLsn, applied: rows.length };
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch (rollbackErr) { /* ignore */ }
    throw err;
  }
}

module.exports = {
  ensureStateRow,
  getState,
  currentEpoch,
  collectBatch,
  recordAck,
  pruneJournal,
  computeLag,
  shipOnce,
  applyBatch,
};

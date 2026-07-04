// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Replication Status (B5q)
//
// Read-only, per-data-type replication health for the routing console: for each
// routed data type, is the copy actually landing on BOTH of its destinations?
// This is the operational proof that the guaranteed dual-write is in fact
// guaranteed. Backups already expose push state via /api/backup-push; this
// service brings the archive (audit_log, cef_archive), forensic, and snapshot
// push tables to a single per-type view.
//
// Three things this gets right rather than cheaply:
//
//   1. Per-type mapping is via the PARENT artifact, not the push table. The push
//      tables do not store the data type, and two data types share one table:
//      backup vs snapshot both live in backup_pushes (split by backups.type), and
//      audit_log vs cef_archive both live in archive_segment_pushes (split by the
//      segment category). A naive one-table-per-type summary would merge them.
//
//   2. Role (primary/secondary) is resolved by the CURRENT route's destination
//      refs, not by array position or a stored role. backup_pushes has no role
//      column, and push rows outlive route changes, so a push counts toward a
//      role's health only if its destination_id equals that role's current ref.
//      Stale pushes to a former destination do not pollute current-role health.
//      (Secondary must differ from primary, so a destination maps to <=1 role.)
//
//   3. Permanent vs transient failure is explicit. Status is
//      queued|running|succeeded|failed with no permanent state; a permanent
//      failure is status='failed' AND attempt_count >= MAX_ATTEMPTS. Permanent
//      failures drive the 'failing' health -- the signal that a copy is not
//      protected and an operator must act.
//
// Pure read. No credentials are touched. Missing tables degrade to zero counts
// (a fresh or partially-migrated database stays green rather than throwing).
// ═══════════════════════════════════════════════════════════════════════════════

const storageRouting = require('./storage-routing');
const storageDestinations = require('./storage-destinations');

// MUST match the push services' retry ceiling: backup-push.js (MAX_ATTEMPTS),
// archive-segment.js (MAX_ATTEMPTS), forensic-export.js (FORENSIC_MAX_ATTEMPTS),
// all currently 5. It is not yet a shared export; if any of those change, change
// this with them. A push at or past this attempt count with status='failed' has
// exhausted its retries (next_retry_at NULL) and is a permanent failure.
const MAX_ATTEMPTS = 5;

// Per-data-type source: which push table holds its pushes, how to reach the
// parent artifact that identifies the type, and the parent predicate. dataType
// is always one of storageRouting.VALID_DATA_TYPES (a fixed allow-list), so these
// fragments are constants -- no external input is interpolated into SQL.
const SOURCES = {
  backup: { table: 'backup_pushes', fk: 'backup_id', parent: 'backups', parentKey: 'id', join: 'JOIN backups b ON b.id = p.backup_id', filter: "b.type IN ('scheduled', 'on-demand')" },
  snapshot: { table: 'backup_pushes', fk: 'backup_id', parent: 'backups', parentKey: 'id', join: 'JOIN backups b ON b.id = p.backup_id', filter: "b.type = 'snapshot'" },
  audit_log: { table: 'archive_segment_pushes', fk: 'segment_id', parent: 'storage_archive_segments', parentKey: 'id', join: 'JOIN storage_archive_segments s ON s.id = p.segment_id', filter: "s.category = 'audit_log'" },
  cef_archive: { table: 'archive_segment_pushes', fk: 'segment_id', parent: 'storage_archive_segments', parentKey: 'id', join: 'JOIN storage_archive_segments s ON s.id = p.segment_id', filter: "s.category = 'cef_archive'" },
  forensic_export: { table: 'forensic_export_pushes', fk: 'export_id', parent: 'forensic_exports', parentKey: 'id', join: '', filter: '' },
};

const SEVERITY = { failing: 4, degraded: 3, pending: 2, idle: 1, healthy: 0, unconfigured: -1 };

function tableExists(db, name) {
  try {
    return !!db.prepare("SELECT 1 AS x FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
  } catch (e) {
    return false;
  }
}

function zeroCounts() {
  return { queued: 0, running: 0, succeeded: 0, failedRetrying: 0, failedPermanent: 0, total: 0 };
}

function emptyAggregate() {
  return { counts: zeroCounts(), lastSuccessAt: null, oldestPendingAt: null, lastErrorAt: null, lastError: null };
}

// Aggregate the push history for one (dataType, destinationRef) pair: the rows in
// the type's push table that targeted this destination and whose parent artifact
// is of this type. MAX_ATTEMPTS is interpolated as a trusted integer constant;
// the destination ref is bound.
function aggregate(db, dataType, destinationRef) {
  const src = SOURCES[dataType];
  if (!src || !destinationRef) return emptyAggregate();
  // A missing push table or parent table (old / partial schema) -> zero, not throw.
  if (!tableExists(db, src.table)) return emptyAggregate();
  if (src.join && !tableExists(db, src.parent)) return emptyAggregate();

  const where = ['p.destination_id = ?'];
  if (src.filter) where.push(src.filter);
  const whereSql = where.join(' AND ');

  let row;
  try {
    row = db.prepare(
      'SELECT'
      + " COALESCE(SUM(CASE WHEN p.status = 'queued' THEN 1 ELSE 0 END), 0) AS queued,"
      + " COALESCE(SUM(CASE WHEN p.status = 'running' THEN 1 ELSE 0 END), 0) AS running,"
      + " COALESCE(SUM(CASE WHEN p.status = 'succeeded' THEN 1 ELSE 0 END), 0) AS succeeded,"
      + ` COALESCE(SUM(CASE WHEN p.status = 'failed' AND p.attempt_count < ${MAX_ATTEMPTS} THEN 1 ELSE 0 END), 0) AS failedRetrying,`
      + ` COALESCE(SUM(CASE WHEN p.status = 'failed' AND p.attempt_count >= ${MAX_ATTEMPTS} THEN 1 ELSE 0 END), 0) AS failedPermanent,`
      + ' COUNT(*) AS total,'
      + " MAX(CASE WHEN p.status = 'succeeded' THEN p.pushed_at END) AS lastSuccessAt,"
      + ` MIN(CASE WHEN p.status IN ('queued', 'running') OR (p.status = 'failed' AND p.attempt_count < ${MAX_ATTEMPTS}) THEN p.created_at END) AS oldestPendingAt,`
      + " MAX(CASE WHEN p.status = 'failed' THEN p.last_attempt_at END) AS lastErrorAt"
      + ` FROM ${src.table} p ${src.join} WHERE ${whereSql}`,
    ).get(destinationRef);
  } catch (e) {
    return emptyAggregate();
  }
  if (!row) return emptyAggregate();

  const counts = {
    queued: row.queued || 0,
    running: row.running || 0,
    succeeded: row.succeeded || 0,
    failedRetrying: row.failedRetrying || 0,
    failedPermanent: row.failedPermanent || 0,
    total: row.total || 0,
  };

  // The most recent permanent-failure message, only when one exists.
  let lastError = null;
  if (counts.failedPermanent > 0) {
    try {
      const er = db.prepare(
        `SELECT p.error_message AS msg FROM ${src.table} p ${src.join}`
        + ` WHERE ${whereSql} AND p.status = 'failed' AND p.attempt_count >= ${MAX_ATTEMPTS}`
        + ' AND p.last_attempt_at IS NOT NULL ORDER BY p.last_attempt_at DESC LIMIT 1',
      ).get(destinationRef);
      if (er && er.msg) lastError = er.msg;
    } catch (e) {
      lastError = null;
    }
  }

  return { counts, lastSuccessAt: row.lastSuccessAt || null, oldestPendingAt: row.oldestPendingAt || null, lastErrorAt: row.lastErrorAt || null, lastError };
}

// idle (nothing pushed) < healthy (caught up) < pending (in flight) <
// degraded (transient failures retrying) < failing (permanent failures).
function deriveHealth(c) {
  if (!c || c.total === 0) return 'idle';
  if (c.failedPermanent > 0) return 'failing';
  if (c.failedRetrying > 0) return 'degraded';
  if ((c.queued + c.running) > 0) return 'pending';
  return 'healthy';
}

// The data-type health is the most severe of its roles. No roles -> unconfigured.
function rollup(entries) {
  if (!entries || entries.length === 0) return 'unconfigured';
  let worst = 'healthy';
  for (const e of entries) {
    if ((SEVERITY[e.health] || 0) > (SEVERITY[worst] || 0)) worst = e.health;
  }
  return worst;
}

/**
 * getReplicationStatus(db)
 *
 * Returns an array, one entry per routed data type (in VALID_DATA_TYPES order):
 *   {
 *     dataType,
 *     configured,        true when the route resolves to >= 1 usable destination
 *     inheritedFrom,     'backup' when snapshot falls back to the backup route, else null
 *     destinations: [    one per configured role (primary first, then secondary)
 *       {
 *         role,                 'primary' | 'secondary'
 *         destinationRef,       the current route's destination id for this role
 *         destinationName,      resolved name, or null
 *         destinationEnabled,   whether that destination is currently enabled
 *         counts: { queued, running, succeeded, failedRetrying, failedPermanent, total },
 *         lastSuccessAt, oldestPendingAt, lastErrorAt, lastError,
 *         health,               idle | healthy | pending | degraded | failing
 *       }
 *     ],
 *     health,            rollup of the role healths (worst), or 'unconfigured'
 *   }
 */
function getReplicationStatus(db) {
  return storageRouting.VALID_DATA_TYPES.map((dataType) => {
    let resolved;
    try {
      resolved = storageRouting.getRouteForType(db, dataType);
    } catch (e) {
      resolved = { configured: false, inheritedFrom: null };
    }
    const inheritedFrom = (resolved && resolved.inheritedFrom) || null;
    // For snapshot that inherits the backup route, read the EFFECTIVE source's
    // raw refs so role -> destination mapping is stable (not position-based).
    const sourceType = inheritedFrom || dataType;
    let srcRoute;
    try {
      srcRoute = storageRouting.readRoute(db, sourceType) || {};
    } catch (e) {
      srcRoute = {};
    }

    const roleRefs = [];
    if (srcRoute.destinationRef) roleRefs.push({ role: 'primary', ref: srcRoute.destinationRef });
    if (srcRoute.secondaryDestinationRef) roleRefs.push({ role: 'secondary', ref: srcRoute.secondaryDestinationRef });

    const destinations = roleRefs.map(({ role, ref }) => {
      let destinationName = null;
      let destinationEnabled = null;
      try {
        const d = storageDestinations.getDestinationById(db, ref);
        if (d) { destinationName = d.name; destinationEnabled = d.enabled === true || d.enabled === 1; }
      } catch (e) { /* leave nulls */ }
      const agg = aggregate(db, dataType, ref);
      return {
        role,
        destinationRef: ref,
        destinationName,
        destinationEnabled,
        counts: agg.counts,
        lastSuccessAt: agg.lastSuccessAt,
        oldestPendingAt: agg.oldestPendingAt,
        lastErrorAt: agg.lastErrorAt,
        lastError: agg.lastError,
        health: deriveHealth(agg.counts),
      };
    });

    return {
      dataType,
      configured: !!(resolved && resolved.configured),
      inheritedFrom,
      destinations,
      health: rollup(destinations),
    };
  });
}

module.exports = {
  getReplicationStatus,
  MAX_ATTEMPTS,
};

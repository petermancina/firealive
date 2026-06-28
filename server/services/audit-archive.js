// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Audit-Log Archival Writer (B5q)
//
// Continuously seals new audit_log rows into the audit_log segment chain via the
// shared archive-segment primitive, so the audit trail is archived to the routed
// destination(s) -- FA-ENC1-encrypted, gap-evident, tamper-evident, and
// dual-written -- in addition to the live DB table. One scheduled call seals the
// next batch of un-archived rows.
//
// Self-describing cursor: the last archived audit_log id is MAX(range_end) across
// recorded audit_log segments (range_end holds the last id a segment covers).
// There is no separate cursor state to drift or corrupt, and the append-only
// segment table forbids deleting a segment, so the cursor cannot move backward.
// Each run reads audit_log rows with id > cursor in id order, canonical-
// serializes them, and calls sealAndPush(db, 'audit_log', payload, { rangeStart,
// rangeEnd }) -- which advances the chain, encrypts, pushes to the primary +
// secondary, and retries the secondary until it lands. If sealAndPush throws (a
// primary seal/push failure) the cursor is unchanged (no segment recorded), so
// the same rows are re-covered next run; the live audit_log row is never touched.
//
// cef_message is intentionally excluded from the sealed record: it is a
// pre-formatted SIEM-stream representation, not a canonical audit record (the
// CEF stream is archived separately by the cef-archive writer). This mirrors the
// forensic-export audit selection.
// ═══════════════════════════════════════════════════════════════════════════════

const archiveSegment = require('./archive-segment');
const { canonicalSerialize } = require('./audit-export-shared');

const AUDIT_CATEGORY = 'audit_log';

// Safety bound on rows sealed into a single segment, so one run stays bounded
// even when draining a large backlog (e.g., the first run after archival is
// enabled, or after downtime). A backlog larger than this drains over successive
// runs; the scheduler may call this repeatedly until it reports nothing new.
const DEFAULT_MAX_ROWS = 50000;

function tableExists(db, name) {
  return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?").get(name);
}

// The last archived audit_log id = MAX(range_end) over recorded audit_log
// segments. range_end is TEXT (it can hold an id or a timestamp depending on the
// category); for audit_log it always holds the last covered id, so CAST to
// INTEGER before MAX to avoid lexicographic ordering. 0 before the first run.
function lastArchivedId(db) {
  const row = db.prepare(
    'SELECT MAX(CAST(range_end AS INTEGER)) AS maxId FROM storage_archive_segments WHERE category = ?'
  ).get(AUDIT_CATEGORY);
  return row && row.maxId != null ? Number(row.maxId) : 0;
}

// Read up to maxRows new audit_log rows (id > cursor), oldest first. Enumerates
// the canonical columns; cef_message is excluded (see file header).
function fetchNewRows(db, cursor, maxRows) {
  return db.prepare(
    'SELECT id, timestamp, user_id, event_type, detail, ip_address FROM audit_log ' +
    'WHERE id > ? ORDER BY id ASC LIMIT ?'
  ).all(cursor, maxRows);
}

/**
 * archiveNewAuditEntries(db, options)
 *
 * Seal the next batch of un-archived audit_log rows into the chain. Returns one
 * of:
 *   { archived: false, reason: 'no audit_log table' }
 *   { archived: false, reason: 'nothing new' }              cursor is current
 *   { archived: false, configured: false, reason }          no destination routed
 *   { archived: false, blocked: true, reason }              primary residency refused
 *   { archived: true, sequence, rangeStart, rangeEnd, rows, secondaryReplicated }
 *
 * options: { logger, maxRows, timeoutMs }. Throws only if sealAndPush throws (a
 * primary seal/push failure); the cursor is unchanged and the batch is retried
 * next run.
 */
async function archiveNewAuditEntries(db, options = {}) {
  const logger = options.logger || console;

  if (!tableExists(db, 'audit_log')) {
    return { archived: false, reason: 'no audit_log table' };
  }

  const cursor = lastArchivedId(db);
  const maxRows = options.maxRows || DEFAULT_MAX_ROWS;
  const rows = fetchNewRows(db, cursor, maxRows);
  if (rows.length === 0) {
    return { archived: false, reason: 'nothing new' };
  }

  const rangeStart = rows[0].id;
  const rangeEnd = rows[rows.length - 1].id;

  // Canonical, deterministic serialization of the batch (the same primitive the
  // forensic export uses), so the sealed plaintext is reproducible from the rows.
  // The metadata makes the decrypted artifact self-describing.
  const payload = canonicalSerialize({
    category: AUDIT_CATEGORY,
    range_start: rangeStart,
    range_end: rangeEnd,
    count: rows.length,
    rows: rows,
  });

  const result = await archiveSegment.sealAndPush(
    db,
    AUDIT_CATEGORY,
    payload,
    { rangeStart: String(rangeStart), rangeEnd: String(rangeEnd) },
    { logger: logger, timeoutMs: options.timeoutMs }
  );

  // Nothing was sealed (no route, empty, or residency-blocked). The cursor is
  // unchanged; surface why. None of these is an error.
  if (!result.pushed) {
    if (result.configured === false) {
      return { archived: false, configured: false, reason: 'no destination configured' };
    }
    if (result.blocked) {
      return { archived: false, blocked: true, reason: result.reason || 'blocked by residency' };
    }
    return { archived: false, reason: result.reason || 'not pushed' };
  }

  logger.info('audit-archive: sealed audit_log segment', {
    sequence: result.sequence,
    rangeStart: rangeStart,
    rangeEnd: rangeEnd,
    rows: rows.length,
    secondaryReplicated: result.secondaryReplicated,
  });

  return {
    archived: true,
    sequence: result.sequence,
    rangeStart: rangeStart,
    rangeEnd: rangeEnd,
    rows: rows.length,
    secondaryReplicated: result.secondaryReplicated,
  };
}

module.exports = {
  archiveNewAuditEntries,
  AUDIT_CATEGORY,
  // exposed for tests
  lastArchivedId,
  fetchNewRows,
};

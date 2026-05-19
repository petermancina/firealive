// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Forensic Format: Plaso L2T CSV (R3l C25)
//
// Emits an audit-event slice set as a log2timeline L2T CSV — the native
// CSV output of the plaso forensic timeline framework. L2T is one of the
// most common timeline formats consumed by Autopsy, Splunk SIEM dashboards
// configured for log2timeline, and forensic analysts using plaso's own
// psort utility for timeline reduction.
//
// L2T CSV FORMAT (17 columns)
//
//   date,time,timezone,MACB,source,sourcetype,type,user,host,
//   short,desc,version,filename,inode,notes,format,extra
//
// Column semantics per the plaso L2T spec:
//
//    1. date         MM/DD/YYYY (US date order — plaso convention, not ISO)
//    2. time         HH:MM:SS (24-hour, second precision)
//    3. timezone     "UTC" (always — we normalize all timestamps to UTC)
//    4. MACB         "MACB" or subset string indicating which timestamps
//                    the row represents. For point-in-time audit events
//                    all four are set: "MACB". For backup_chain CREATE we
//                    use "...B" (birth only). For VERIFY we use "M..."
//                    (modified only).
//    5. source       Short source tag: "FIREALIVE-AUDIT", "FIREALIVE-BACKUP",
//                    "FIREALIVE-AUTH", "FIREALIVE-SESSIONS", etc.
//    6. sourcetype   Longer source description for the analyst's UI
//    7. type         Event classification (event_type / action / etc.)
//    8. user         User identifier from the row (user_id or user)
//    9. host         Hostname placeholder — audit events do not carry
//                    a hostname; we use a fixed "firealive" sentinel so
//                    plaso filters on host correctly group all rows
//   10. short        One-line summary (slice + type + id)
//   11. desc         Full event detail (canonical-JSON of the row)
//   12. version      "2" (plaso L2T schema version)
//   13. filename     Synthetic path: "<sliceId>/<id>"
//   14. inode        Numeric event id (string ids hashed to int)
//   15. notes        Empty (reserved for verifier annotations)
//   16. format       Parser name: "firealive_audit_v1"
//   17. extra        Empty (reserved; not used in this emitter)
//
// RFC 4180 CSV ESCAPING
//
// Fields containing commas, double-quotes, CR, or LF MUST be double-
// quoted; internal double-quotes are escaped by doubling. The desc
// field (canonical-JSON of the row) reliably contains commas and
// quotes, so it is always double-quoted in practice. The escape logic
// applies to every emitted field to be robust against any column
// containing a delimiter character.
//
// LINE ORDERING
//
// epoch ASC, ties broken by (sliceId ASC, id ASC). Same deterministic
// sort as C23/C24 — the export bundle uses one ordering convention
// across all formats so an auditor can correlate rows by line position.
//
// MACB MAPPING FOR AUDIT EVENTS
//
//   audit_log              "MACB"  (point-in-time observation)
//   backup_chain CREATE    "...B"  (birth of a new chain entry)
//   backup_chain VERIFY    "M..."  (state-change verification)
//   backup_chain RESTORE_* "MA.."  (access + modify implied)
//   backup_chain DELETE_*  "MAC."  (modify + access + change)
//   authentication_logs    "M.C."  (modify-and-change of session state)
//   user_access_logs       "MA.."  (session created + accessed)
//   incident_records       "...B"  (incident retro represents birth of
//                                    the response protocol)
//
// These are reasonable defaults; a future commit can refine if
// downstream tooling expects different MACB conventions per event
// classification.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');

const { canonicalSerialize } = require('../audit-export-shared');

const FORMAT_ID = 'plaso-l2t-csv';
const FILE_EXTENSION = '.csv';
const FORMAT_VERSION = '2';
const PARSER_NAME = 'firealive_audit_v1';
const HOST_SENTINEL = 'firealive';

// Per-slice metadata. timestampField is which column carries the row's
// canonical timestamp. discriminatorField is which column the L2T `type`
// column reads from. source/sourcetype are the L2T classification.
const SLICE_CONFIG = {
  audit_log: {
    timestampField: 'timestamp',
    discriminatorField: 'event_type',
    source: 'FIREALIVE-AUDIT',
    sourcetype: 'FireAlive Audit Log',
  },
  backup_chain: {
    timestampField: 'created_at',
    discriminatorField: 'event_type',
    source: 'FIREALIVE-BACKUP',
    sourcetype: 'FireAlive Backup Chain',
  },
  incident_records: {
    timestampField: 'created_at',
    discriminatorField: 'incident',
    source: 'FIREALIVE-INCIDENT',
    sourcetype: 'FireAlive Incident Retro',
  },
  authentication_logs: {
    timestampField: 'timestamp',
    discriminatorField: 'action',
    source: 'FIREALIVE-AUTH',
    sourcetype: 'FireAlive Authentication Log',
  },
  user_access_logs: {
    timestampField: 'created_at',
    discriminatorField: null,
    source: 'FIREALIVE-SESSIONS',
    sourcetype: 'FireAlive Session Log',
  },
};

const USER_FIELD_BY_SLICE = {
  audit_log: 'user_id',
  user_access_logs: 'user_id',
  authentication_logs: 'user',
  backup_chain: null,
  incident_records: 'initiated_by',
};

const L2T_HEADER =
  'date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra';

/**
 * Parse the row timestamp into a Date in UTC. Same flavors supported
 * as C23/C24 (SQLite default + ISO 8601). Throws with slice/row context
 * if unparseable.
 */
function parseTimestampUtc(raw, sliceId, rowId) {
  if (raw === null || raw === undefined || raw === '') {
    throw new Error(
      'plaso-l2t-csv: ' +
        sliceId +
        ' row ' +
        (rowId || '?') +
        ': timestamp required'
    );
  }
  let normalized = String(raw);
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(normalized)) {
    normalized = normalized.replace(' ', 'T') + 'Z';
  }
  const ms = Date.parse(normalized);
  if (Number.isNaN(ms)) {
    throw new Error(
      'plaso-l2t-csv: ' +
        sliceId +
        ' row ' +
        (rowId || '?') +
        ': unparseable timestamp: ' +
        raw
    );
  }
  return new Date(ms);
}

/**
 * Format date/time fields per L2T convention (US date order).
 */
function formatDateField(d) {
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const yyyy = d.getUTCFullYear();
  return mm + '/' + dd + '/' + yyyy;
}

function formatTimeField(d) {
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mi = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  return hh + ':' + mi + ':' + ss;
}

/**
 * Map a slice + discriminator value to a MACB string. Defaults to "MACB"
 * (all four set) if no specific mapping applies.
 */
function deriveMacb(sliceId, discriminator) {
  if (sliceId === 'backup_chain') {
    const d = String(discriminator || '').toUpperCase();
    if (d === 'CREATE') return '...B';
    if (d === 'VERIFY') return 'M...';
    if (d.startsWith('RESTORE_')) return 'MA..';
    if (d.startsWith('DELETE_')) return 'MAC.';
    return 'MACB';
  }
  if (sliceId === 'authentication_logs') return 'M.C.';
  if (sliceId === 'user_access_logs') return 'MA..';
  if (sliceId === 'incident_records') return '...B';
  // audit_log and any other: point-in-time observation
  return 'MACB';
}

/**
 * Coerce an inode value to a non-negative integer. Numeric inputs pass
 * through; string ids are hashed via SHA-256 prefix to a stable 32-bit
 * unsigned int.
 */
function coerceInode(raw) {
  if (raw === null || raw === undefined || raw === '') return 0;
  if (typeof raw === 'number' && Number.isInteger(raw)) return raw;
  if (typeof raw === 'string' && /^\d+$/.test(raw)) {
    const n = parseInt(raw, 10);
    if (Number.isSafeInteger(n)) return n;
  }
  const hex = crypto
    .createHash('sha256')
    .update(String(raw))
    .digest('hex')
    .slice(0, 8);
  return parseInt(hex, 16);
}

/**
 * Escape a CSV field per RFC 4180:
 *   - If field contains comma, double-quote, CR, or LF: wrap in double-
 *     quotes and double any internal double-quote
 *   - Otherwise: return as-is
 *
 * Null/undefined become empty string. Numbers and booleans are coerced
 * to their string form first.
 */
function escapeCsvField(raw) {
  if (raw === null || raw === undefined) return '';
  const s = String(raw);
  if (/[",\r\n]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

/**
 * Build a single L2T CSV row (no trailing newline).
 */
function buildRow(sliceId, row) {
  const config = SLICE_CONFIG[sliceId];
  if (!config) {
    throw new Error('plaso-l2t-csv: unknown slice id: ' + sliceId);
  }
  const ts = parseTimestampUtc(row[config.timestampField], sliceId, row.id);
  const discriminator = config.discriminatorField
    ? row[config.discriminatorField] || 'unknown'
    : 'SESSION';
  const userField = USER_FIELD_BY_SLICE[sliceId];
  const user = userField ? row[userField] || '' : '';
  const idPart =
    row.id !== undefined && row.id !== null ? String(row.id) : '0';
  const inode = coerceInode(row.id);
  const short =
    sliceId +
    ':' +
    String(discriminator).substring(0, 60) +
    ':' +
    idPart;
  const desc = canonicalSerialize(row).toString('utf-8');
  const macb = deriveMacb(sliceId, discriminator);
  const filename = sliceId + '/' + idPart;

  const fields = [
    formatDateField(ts),     // 1. date
    formatTimeField(ts),     // 2. time
    'UTC',                   // 3. timezone
    macb,                    // 4. MACB
    config.source,           // 5. source
    config.sourcetype,       // 6. sourcetype
    discriminator,           // 7. type
    user,                    // 8. user
    HOST_SENTINEL,           // 9. host
    short,                   // 10. short
    desc,                    // 11. desc (canonical JSON)
    FORMAT_VERSION,          // 12. version
    filename,                // 13. filename
    inode,                   // 14. inode
    '',                      // 15. notes
    PARSER_NAME,             // 16. format
    '',                      // 17. extra
  ];
  return fields.map(escapeCsvField).join(',');
}

/**
 * serialize(slices) — orchestrator entry point.
 *
 * Returns: Buffer (UTF-8 encoding of the L2T CSV; header line followed
 * by one row per event; CRLF line terminators per RFC 4180; final line
 * also CRLF-terminated).
 *
 * Total ordering: timestamp ASC, ties (sliceId ASC, id ASC).
 */
function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('plaso-l2t-csv: slices object required');
  }

  // Collect tuples for sort.
  const tuples = [];
  for (const sliceId of Object.keys(slices)) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    const config = SLICE_CONFIG[sliceId];
    if (!config) continue; // forward-compat: skip unknown slices
    for (const row of rows) {
      const ts = parseTimestampUtc(
        row[config.timestampField],
        sliceId,
        row.id
      );
      tuples.push({ sliceId, row, epoch: ts.getTime() });
    }
  }

  tuples.sort((a, b) => {
    if (a.epoch !== b.epoch) return a.epoch - b.epoch;
    if (a.sliceId !== b.sliceId) {
      return a.sliceId < b.sliceId ? -1 : 1;
    }
    const aid = String(a.row.id || '');
    const bid = String(b.row.id || '');
    if (aid !== bid) return aid < bid ? -1 : 1;
    return 0;
  });

  // Header line + one row per event. CRLF per RFC 4180.
  const lines = [L2T_HEADER];
  for (const t of tuples) {
    lines.push(buildRow(t.sliceId, t.row));
  }
  return Buffer.from(lines.join('\r\n') + '\r\n', 'utf-8');
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: true,
  serialize,
  // Internal helpers exposed for unit tests
  L2T_HEADER,
  FORMAT_VERSION,
  parseTimestampUtc,
  formatDateField,
  formatTimeField,
  deriveMacb,
  coerceInode,
  escapeCsvField,
  buildRow,
};

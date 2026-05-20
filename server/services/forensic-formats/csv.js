// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Forensic Format: Flat CSV (R3l C28b)
//
// The universal CSV fallback. Where C25 (plaso-l2t-csv) emits the specific
// 17-column log2timeline L2T format for analyst-grade timeline tools, this
// serializer emits a simple 8-column flat CSV suitable for any consumer
// that just wants tabular data — spreadsheet apps (Excel, LibreOffice,
// Numbers), pandas/R DataFrames, generic SQL imports, basic SIEM file
// ingestion paths, and the analyst who just wants to look at the events
// in a spreadsheet before reaching for specialized tooling.
//
// SCHEMA (8 columns)
//
//   timestamp     ISO 8601 UTC with milliseconds (e.g., 2026-01-15T12:34:56.000Z)
//   slice         source slice id (audit_log, backup_chain, etc.)
//   event_type    discriminator (event_type / action / "SESSION")
//   event_id      original DB id, string-typed to preserve non-numeric ids
//   user          user_id / user / initiated_by, empty when not applicable
//   ip            ip_address / ip, empty when not applicable
//   chain_hash    this_hash for backup_chain events, empty otherwise
//   canonical_json
//                 canonical-JSON of the full row, RFC-4180-escaped — the
//                 byte-exact event content for any consumer that wants
//                 the full data beyond the eight cross-slice columns
//
// The cross-slice column set covers the common-denominator forensic
// pivot keys (when, where, who, what); the canonical_json column
// preserves the full data so no information is lost. Spreadsheet apps
// will show the JSON as a long cell; for analysts who don't need the
// JSON, the first seven columns are sufficient for most timeline review.
//
// RFC 4180 ESCAPING
//
// Same logic as C25 plaso-l2t-csv:
//   - Fields containing comma, double-quote, CR, or LF: wrap in double-
//     quotes; internal double-quotes are doubled
//   - Null/undefined: empty string
//   - CRLF line terminators throughout, including the final line
//
// ORDERING
//
// epoch ASC, ties (sliceId ASC, id ASC). Same as all other format
// serializers. Header line first, then one row per event.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const { canonicalSerialize } = require('../audit-export-shared');

const FORMAT_ID = 'csv';
const FILE_EXTENSION = '.csv';

const HEADER =
  'timestamp,slice,event_type,event_id,user,ip,chain_hash,canonical_json';

const SLICE_CONFIG = {
  audit_log: {
    timestampField: 'timestamp',
    discriminatorField: 'event_type',
    userField: 'user_id',
    ipField: 'ip_address',
  },
  backup_chain: {
    timestampField: 'created_at',
    discriminatorField: 'event_type',
    userField: null,
    ipField: null,
  },
  incident_records: {
    timestampField: 'created_at',
    discriminatorField: 'incident',
    userField: 'initiated_by',
    ipField: null,
  },
  authentication_logs: {
    timestampField: 'timestamp',
    discriminatorField: 'action',
    userField: 'user',
    ipField: 'ip',
  },
  user_access_logs: {
    timestampField: 'created_at',
    discriminatorField: null,
    userField: 'user_id',
    ipField: 'ip_address',
  },
};

/**
 * Parse a timestamp into ISO 8601 UTC with milliseconds. Same dual-format
 * handling as the other format serializers (SQLite default + ISO 8601).
 * Throws with slice/row context.
 */
function parseTimestampIso(raw, sliceId, rowId) {
  if (raw === null || raw === undefined || raw === '') {
    throw new Error(
      'csv: ' + sliceId + ' row ' + (rowId || '?') + ': timestamp required'
    );
  }
  let normalized = String(raw);
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(normalized)) {
    normalized = normalized.replace(' ', 'T') + 'Z';
  }
  const ms = Date.parse(normalized);
  if (Number.isNaN(ms)) {
    throw new Error(
      'csv: ' +
        sliceId +
        ' row ' +
        (rowId || '?') +
        ': unparseable timestamp: ' +
        raw
    );
  }
  return new Date(ms).toISOString();
}

/**
 * Escape a CSV field per RFC 4180. Same logic as C25 plaso-l2t-csv:
 *   - Fields with comma, double-quote, CR, or LF: wrap in quotes and
 *     double internal quotes
 *   - Null/undefined become empty string
 *   - Numbers/booleans coerced to string
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
 * Build a single CSV row (no trailing newline) for one audit event.
 */
function buildRow(sliceId, row) {
  const config = SLICE_CONFIG[sliceId];
  if (!config) {
    throw new Error('csv: unknown slice id: ' + sliceId);
  }
  const iso = parseTimestampIso(row[config.timestampField], sliceId, row.id);
  const discriminator = config.discriminatorField
    ? row[config.discriminatorField] || 'unknown'
    : 'SESSION';
  const eventId =
    row.id !== undefined && row.id !== null ? String(row.id) : '';
  const user = config.userField ? row[config.userField] || '' : '';
  const ip = config.ipField ? row[config.ipField] || '' : '';
  const chainHash =
    sliceId === 'backup_chain' && row.this_hash ? row.this_hash : '';
  const canonical = canonicalSerialize(row).toString('utf-8');

  return [
    iso,
    sliceId,
    discriminator,
    eventId,
    user,
    ip,
    chainHash,
    canonical,
  ]
    .map(escapeCsvField)
    .join(',');
}

/**
 * serialize(slices) — orchestrator entry point.
 *
 * Returns: Buffer (UTF-8 encoding of the flat CSV; header line followed
 * by one row per event; CRLF line terminators per RFC 4180).
 *
 * Total ordering: epoch ASC, (sliceId ASC, id ASC).
 */
function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('csv: slices object required');
  }
  const tuples = [];
  for (const sliceId of Object.keys(slices)) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    const config = SLICE_CONFIG[sliceId];
    if (!config) continue;
    for (const row of rows) {
      const iso = parseTimestampIso(
        row[config.timestampField],
        sliceId,
        row.id
      );
      tuples.push({ sliceId, row, ms: Date.parse(iso) });
    }
  }

  tuples.sort((a, b) => {
    if (a.ms !== b.ms) return a.ms - b.ms;
    if (a.sliceId !== b.sliceId) {
      return a.sliceId < b.sliceId ? -1 : 1;
    }
    const aid = String(a.row.id || '');
    const bid = String(b.row.id || '');
    if (aid !== bid) return aid < bid ? -1 : 1;
    return 0;
  });

  const lines = [HEADER];
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
  HEADER,
  parseTimestampIso,
  escapeCsvField,
  buildRow,
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Legal Hold Format: Concordance DAT (R3l C42)
//
// Emits a legal-hold slice set as a Concordance DAT load file — the
// canonical metadata-load format from kCura/LexisNexis Concordance, still
// the dominant ingest path across legacy e-discovery review platforms.
// Consumed by:
//
//   - LexisNexis Concordance (native)
//   - kCura Relativity (Concordance DAT is a first-class import path
//     alongside native EDRM XML and Relativity load files)
//   - iCONECT, Ringtail, Summation (legacy ESI platforms)
//   - Brainspace, Catalyst Insight (analytics tools that ingest DAT)
//   - Custom litigation-tech tooling — DAT parsing is straightforward
//     enough that bespoke scripts often handle it
//
// FORMAT
//
// Pipe-delimited text with thorn (þ, U+00FE) as the text qualifier. Each
// field value is wrapped in thorn quotes. The first row is a header row
// naming the fields; subsequent rows carry data. Encoded as UTF-8 with
// BOM (0xEF 0xBB 0xBF) for modern Concordance/Relativity compatibility.
// Line ending is CRLF.
//
//   þDOCIDþ|þCUSTODIANþ|þFROMþ|þTOþ|þSUBJECTþ|þDATESENTþ|...
//   þLH-audit_log-1þ|þu-janeþ|þaudit@firealive.localþ|...
//
// FIELD SET
//
// Standard Concordance email fields plus FireAlive extensions (FA_*):
//
//   DOCID                   "LH-<slice>-<id>" — unique within the load
//   CUSTODIAN               row.user_id / row.user / 'system'
//   FROM                    synthetic "audit@firealive.local"
//   TO                      synthetic "legal-hold@firealive.local"
//   CC                      empty
//   BCC                     empty
//   SUBJECT                 derived subject ("[<slice>] <event_type> by <user>")
//   DATESENT                YYYYMMDD from the event timestamp
//   TIMESENT                HH:MM:SS from the event timestamp
//   BODY                    human-readable summary (preserves newlines)
//   FA_SLICE                source slice id
//   FA_EVENTID              original DB id
//   FA_EVENTTYPE            event_type / action
//   FA_ORIGINALTIMESTAMP    ISO 8601 normalized
//   FA_IPADDRESS            ip_address / ip when present
//   FA_DETAIL               detail / reason when present
//   FA_USERAGENT            user_agent when present
//   FA_CHAINHASH            backup_chain.this_hash when present
//   FA_PREVHASH             backup_chain.prev_hash when present
//   FA_SIGNINGKEY           backup_chain.signing_key_id when present
//   FA_BACKUPID             backup_chain.backup_id when present
//   FA_CANONICALSHA256      SHA-256 hex of canonical JSON
//   FA_CANONICALJSON        canonical JSON of the row
//
// All fields are emitted on every row even when empty — Concordance
// expects consistent column counts across all rows. Empty fields are
// thorn-thorn (þþ) between pipes.
//
// THORN-INSIDE-VALUE HANDLING
//
// Concordance has no standardized escape for thorn characters that appear
// inside field values. The pragmatic convention is to strip them — they
// would corrupt the load if present, and they're vanishingly rare in real
// data (audit-event content is overwhelmingly ASCII). sanitizeValue()
// strips thorn bytes as a defensive measure.
//
// NEWLINE HANDLING
//
// Newlines within field values are PRESERVED as LF characters (not CRLF —
// CRLF would terminate the row). Concordance treats embedded LF as cell-
// internal line breaks. This matters for the BODY field which carries
// the multiline human-readable summary.
//
// OPT FILE
//
// Concordance pipelines may also accept an OPT (opticon) file linking
// native images to documents. For audit-event holds there are no native
// images (those are produced by C45's pdf-bates / tiff-bates serializers
// when imaged review is required). This serializer produces the DAT only;
// receivers wanting OPT can include both legal-hold formats in their
// export request and the C45 output supplies the image references.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const { canonicalSerialize, sliceSha256 } = require('../audit-export-shared');

const FORMAT_ID = 'concordance';
const FILE_EXTENSION = '.dat';
const THORN = '\u00FE';                  // þ — text qualifier
const PIPE = '|';                         // field delimiter
const ROW_SEP = '\r\n';                   // CRLF line terminator
const UTF8_BOM = Buffer.from([0xEF, 0xBB, 0xBF]);
const SYNTHETIC_FROM = 'audit@firealive.local';
const SYNTHETIC_TO = 'legal-hold@firealive.local';

const FIELDS = [
  'DOCID',
  'CUSTODIAN',
  'FROM',
  'TO',
  'CC',
  'BCC',
  'SUBJECT',
  'DATESENT',
  'TIMESENT',
  'BODY',
  'FA_SLICE',
  'FA_EVENTID',
  'FA_EVENTTYPE',
  'FA_ORIGINALTIMESTAMP',
  'FA_IPADDRESS',
  'FA_DETAIL',
  'FA_USERAGENT',
  'FA_CHAINHASH',
  'FA_PREVHASH',
  'FA_SIGNINGKEY',
  'FA_BACKUPID',
  'FA_CANONICALSHA256',
  'FA_CANONICALJSON',
];

const SLICE_ORDER = ['audit_log', 'backup_chain', 'authentication_logs', 'user_access_logs', 'incident_records'];

// ── Value sanitization ────────────────────────────────────────────────────

function sanitizeValue(s) {
  // Strip thorn chars (no standard escape in Concordance DAT) and ASCII
  // control chars except LF (cell-internal line breaks are preserved).
  // Specifically remove: 0x00-0x09, 0x0B-0x0C, 0x0E-0x1F, 0x7F, 0xFE (thorn).
  if (s == null) return '';
  return String(s).replace(/[\x00-\x09\x0B\x0C\x0E-\x1F\x7F\u00FE]/g, '');
}

function wrapField(s) {
  return THORN + sanitizeValue(s) + THORN;
}

// ── Date/time helpers ─────────────────────────────────────────────────────

function parseSourceTimestamp(raw) {
  if (raw == null) return null;
  const s = String(raw).trim();
  if (!s) return null;
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) {
    return new Date(s.replace(' ', 'T') + 'Z');
  }
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function pad2(n) { return n < 10 ? '0' + n : String(n); }

function formatDateSent(d) {
  // YYYYMMDD — Concordance's preferred date format for DATESENT
  if (!d || isNaN(d.getTime())) return '';
  return String(d.getUTCFullYear()) + pad2(d.getUTCMonth() + 1) + pad2(d.getUTCDate());
}

function formatTimeSent(d) {
  // HH:MM:SS — Concordance's preferred time format for TIMESENT
  if (!d || isNaN(d.getTime())) return '';
  return pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds());
}

function formatIsoTimestamp(d) {
  if (!d || isNaN(d.getTime())) return '';
  return d.toISOString();
}

// ── Subject derivation per slice (matches C40 / C41 for cross-format
//    correlation in review platforms) ───────────────────────────────────────

function deriveSubject(sliceId, row) {
  switch (sliceId) {
    case 'audit_log': return '[audit_log] ' + (row.event_type || '?') + (row.user_id ? ' by ' + row.user_id : '');
    case 'backup_chain': return '[backup_chain] ' + (row.event_type || '?') + (row.backup_id ? ' for ' + row.backup_id : '');
    case 'authentication_logs': return '[auth] ' + (row.action || '?') + (row.user ? ' by ' + row.user : '');
    case 'user_access_logs': return '[session] SESSION_OPENED' + (row.user_id ? ' by ' + row.user_id : '');
    case 'incident_records': return '[incident] ' + (row.event_type || '?');
    default: return '[' + sliceId + '] event';
  }
}

function deriveTimestamp(sliceId, row) {
  switch (sliceId) {
    case 'audit_log':
    case 'authentication_logs':
      return row.timestamp;
    case 'backup_chain':
    case 'user_access_logs':
      return row.created_at;
    case 'incident_records':
      return row.created_at || row.timestamp;
    default:
      return null;
  }
}

function deriveCustodian(row) {
  // Custodian is the person the data concerns. For audit events with a
  // user_id, that's the actor. For auth events with a username, that's
  // the username. Falls back to 'system' if no per-user attribution.
  return row.user_id || row.user || 'system';
}

function deriveEventType(row) {
  return row.event_type || row.action || '';
}

function deriveIp(row) {
  return row.ip_address || row.ip || '';
}

function deriveDetail(row) {
  return row.detail || row.reason || '';
}

// ── Body summary (multi-line, preserves LF within the cell) ───────────────

function buildBody(sliceId, row, isoTimestamp) {
  const lines = [];
  lines.push('Audit Event from FireAlive Legal Hold Export');
  lines.push('');
  lines.push('Slice:       ' + sliceId);
  lines.push('Original ID: ' + (row.id != null ? row.id : ''));
  if (isoTimestamp) lines.push('Timestamp:   ' + isoTimestamp);
  if (row.event_type) lines.push('Event Type:  ' + row.event_type);
  if (row.action) lines.push('Action:      ' + row.action);
  if (row.user_id) lines.push('User ID:     ' + row.user_id);
  if (row.user) lines.push('Username:    ' + row.user);
  if (row.ip_address) lines.push('IP Address:  ' + row.ip_address);
  if (row.ip) lines.push('IP Address:  ' + row.ip);
  if (row.method) lines.push('Auth Method: ' + row.method);
  if (row.user_agent) lines.push('User Agent:  ' + row.user_agent);
  if (row.detail) lines.push('Detail:      ' + row.detail);
  if (row.reason) lines.push('Reason:      ' + row.reason);
  if (row.this_hash) lines.push('Chain Hash:  ' + row.this_hash);
  if (row.prev_hash) lines.push('Prev Hash:   ' + row.prev_hash);
  if (row.signing_key_id) lines.push('Signing Key: ' + row.signing_key_id);
  if (row.backup_id) lines.push('Backup ID:   ' + row.backup_id);
  // LF (not CRLF) between body lines so Concordance treats them as
  // cell-internal breaks rather than row terminators.
  return lines.join('\n');
}

// ── Row builder ───────────────────────────────────────────────────────────

function buildRow(sliceId, row) {
  const id = row.id != null ? row.id : '';
  const docId = 'LH-' + sliceId + '-' + id;
  const rawTimestamp = deriveTimestamp(sliceId, row);
  const date = parseSourceTimestamp(rawTimestamp);
  const isoTimestamp = formatIsoTimestamp(date);
  const dateSent = formatDateSent(date);
  const timeSent = formatTimeSent(date);
  const subject = deriveSubject(sliceId, row);
  const custodian = deriveCustodian(row);
  const eventType = deriveEventType(row);
  const ip = deriveIp(row);
  const detail = deriveDetail(row);
  const body = buildBody(sliceId, row, isoTimestamp);
  const canonicalBytes = canonicalSerialize(row);
  const canonicalSha256 = sliceSha256(canonicalBytes);
  const canonicalJsonStr = canonicalBytes.toString('utf-8');

  const values = {
    DOCID: docId,
    CUSTODIAN: custodian,
    FROM: SYNTHETIC_FROM,
    TO: SYNTHETIC_TO,
    CC: '',
    BCC: '',
    SUBJECT: subject,
    DATESENT: dateSent,
    TIMESENT: timeSent,
    BODY: body,
    FA_SLICE: sliceId,
    FA_EVENTID: String(id),
    FA_EVENTTYPE: eventType,
    FA_ORIGINALTIMESTAMP: isoTimestamp,
    FA_IPADDRESS: ip,
    FA_DETAIL: detail,
    FA_USERAGENT: row.user_agent || '',
    FA_CHAINHASH: row.this_hash || '',
    FA_PREVHASH: row.prev_hash || '',
    FA_SIGNINGKEY: row.signing_key_id || '',
    FA_BACKUPID: row.backup_id || '',
    FA_CANONICALSHA256: canonicalSha256,
    FA_CANONICALJSON: canonicalJsonStr,
  };

  return FIELDS.map((f) => wrapField(values[f] == null ? '' : values[f])).join(PIPE);
}

// ── Main serializer ───────────────────────────────────────────────────────

function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('concordance: slices object required');
  }

  const headerRow = FIELDS.map((f) => wrapField(f)).join(PIPE);
  const dataRows = [];

  for (const sliceId of SLICE_ORDER) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    for (const row of rows) {
      dataRows.push(buildRow(sliceId, row));
    }
  }

  const body = headerRow + ROW_SEP + dataRows.join(ROW_SEP) + (dataRows.length > 0 ? ROW_SEP : '');
  return Buffer.concat([UTF8_BOM, Buffer.from(body, 'utf-8')]);
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: false,
  serialize,
  // Internal helpers exposed for unit tests
  THORN,
  PIPE,
  ROW_SEP,
  FIELDS,
  SLICE_ORDER,
  SYNTHETIC_FROM,
  SYNTHETIC_TO,
  sanitizeValue,
  wrapField,
  parseSourceTimestamp,
  formatDateSent,
  formatTimeSent,
  formatIsoTimestamp,
  deriveSubject,
  deriveTimestamp,
  deriveCustodian,
  deriveEventType,
  deriveIp,
  deriveDetail,
  buildBody,
  buildRow,
};

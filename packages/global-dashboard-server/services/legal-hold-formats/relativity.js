// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Legal Hold Format: Relativity Load Bundle (R3l C43)
//
// Emits a legal-hold slice set as a Relativity-compatible load bundle —
// the canonical native+load-file format for kCura Relativity and Relativity
// One (the dominant modern e-discovery review platform). Consumed by:
//
//   - kCura Relativity (native ingest via the Load File wizard)
//   - Relativity One (cloud Relativity — same load file format)
//   - Reveal, Everlaw (Relativity-shaped DAT/OPT/LFP is broadly accepted)
//   - DISCO, Logikcull (accept Relativity load bundles in their ingest)
//
// FORMAT — 3-FILE BUNDLE + NATIVES DIRECTORY
//
// Relativity's full load convention uses three companion files plus a
// folder of native files. This serializer produces all four as a single
// ZIP archive (fileExtension '.zip'):
//
//   loadfile.dat               Metadata load file (pipe-delimited, thorn-
//                              qualified — same lexical shape as Concordance
//                              DAT but with Relativity column naming)
//   loadfile.opt               Opticon load file — page-level image refs
//                              (sparse for audit-event holds since no
//                              native images exist; C45's pdf-bates /
//                              tiff-bates output populates this when
//                              imaged review is included)
//   loadfile.lfp               Native File Load File — links each
//                              ControlNumber to its native file inside
//                              the NATIVES/ directory
//   NATIVES/<ControlNumber>.json
//                              One canonical JSON per event, the native
//                              file that loadfile.lfp references
//   README.txt                 Explains the bundle layout + how to import
//                              into Relativity
//
// RELATIVITY DAT COLUMN CONVENTIONS
//
// Relativity accepts the Concordance DAT lexical shape (pipe-delimited,
// thorn-qualified, UTF-8 with BOM, CRLF) but uses different column names
// by convention:
//
//   ControlNumber          unique document identifier (DOCID in Concordance)
//   Custodian
//   From, To, CC, BCC, Subject
//   DateSent, TimeSent
//   DateReceived           same as DateSent for audit events (no separate
//                          receive timestamp)
//   EmailThreadID          empty for audit events (no threading)
//   HasAttachments         "Y" — each event has a canonical.json attachment
//   BeginBates, EndBates   empty until C45 imaging populates Bates ranges
//   NativeFilePath         "NATIVES\<ControlNumber>.json" — Relativity
//                          uses Windows-style backslashes by convention
//   ExtractedText          the human-readable summary body (preserved
//                          across review platforms as the search target)
//   FA_*                   FireAlive extension fields, same set as C42
//                          (Concordance) for cross-platform correlation
//
// OPT (OPTICON) FORMAT
//
// Comma-separated, one line per page:
//
//   imageKey,volume,fullPath,documentBreak,folderBreak,boxBreak,pageCount
//
// For audit-event holds with no native images, the OPT records reference
// notional paths under IMAGES\<ControlNumber>.tif as placeholders that
// C45's pdf-bates / tiff-bates output will materialize. Setting
// documentBreak=Y on every row tells Relativity each "image" is a single-
// page document.
//
// LFP (NATIVE FILE LOAD FILE) FORMAT
//
// Comma-separated:
//
//   controlNumber,volume,nativeFilePath
//
// Each row links a Document in the DAT to its native file in the
// NATIVES/ directory. Relativity uses this to render the native viewer
// or to extract text for searching.
//
// CHAIN OF INTEGRITY
//
// Native files inside NATIVES/ contain the canonical JSON of each event —
// the same bytes hashed in FA_CANONICALSHA256 in the DAT and in the
// archive-level manifest from C38. A receiver verifies by extracting a
// NATIVES/<id>.json, computing SHA-256, and comparing against the DAT's
// FA_CANONICALSHA256 column. Cryptographic chain runs: Ed25519 manifest
// signature → archive slice hash → DAT FA_CANONICALSHA256 → NATIVES file.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const { canonicalSerialize, sliceSha256 } = require('../audit-export-shared');
const { ZipFile } = require('./pst');

const FORMAT_ID = 'relativity';
const FILE_EXTENSION = '.zip';
const THORN = '\u00FE';
const PIPE = '|';
const ROW_SEP = '\r\n';
const UTF8_BOM = Buffer.from([0xEF, 0xBB, 0xBF]);
const SYNTHETIC_FROM = 'audit@firealive.local';
const SYNTHETIC_TO = 'legal-hold@firealive.local';
const VOLUME = 'VOL001';
const NATIVES_DIR = 'NATIVES';
const IMAGES_DIR = 'IMAGES';

// 25 fields — Relativity standard columns + FA_* extensions
const FIELDS = [
  'ControlNumber',
  'Custodian',
  'From',
  'To',
  'CC',
  'BCC',
  'Subject',
  'DateSent',
  'TimeSent',
  'DateReceived',
  'EmailThreadID',
  'HasAttachments',
  'BeginBates',
  'EndBates',
  'NativeFilePath',
  'ExtractedText',
  'FA_SLICE',
  'FA_EVENTID',
  'FA_EVENTTYPE',
  'FA_ORIGINALTIMESTAMP',
  'FA_IPADDRESS',
  'FA_DETAIL',
  'FA_USERAGENT',
  'FA_CANONICALSHA256',
  'FA_NATIVESIZE',
];

const SLICE_ORDER = ['audit_log', 'backup_chain', 'authentication_logs', 'user_access_logs', 'incident_records'];

// ── DAT cell sanitization (same conventions as Concordance — Relativity
//    accepts the same lexical shape) ─────────────────────────────────────────

function sanitizeValue(s) {
  if (s == null) return '';
  return String(s).replace(/[\x00-\x09\x0B\x0C\x0E-\x1F\x7F\u00FE]/g, '');
}

function wrapField(s) {
  return THORN + sanitizeValue(s) + THORN;
}

// ── OPT / LFP cell sanitization — these are CSV-like, comma is the
//    delimiter, so strip commas and CR/LF defensively ───────────────────────

function sanitizeCsv(s) {
  if (s == null) return '';
  return String(s).replace(/[,\r\n\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

// ── Date/time helpers ────────────────────────────────────────────────────

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
  if (!d || isNaN(d.getTime())) return '';
  return String(d.getUTCFullYear()) + pad2(d.getUTCMonth() + 1) + pad2(d.getUTCDate());
}

function formatTimeSent(d) {
  if (!d || isNaN(d.getTime())) return '';
  return pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds());
}

function formatIsoTimestamp(d) {
  if (!d || isNaN(d.getTime())) return '';
  return d.toISOString();
}

// ── Slice-specific derivation (matches C40 / C41 / C42 for cross-format
//    correlation in review platforms) ─────────────────────────────────────────

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

function deriveCustodian(row) { return row.user_id || row.user || 'system'; }
function deriveEventType(row) { return row.event_type || row.action || ''; }
function deriveIp(row) { return row.ip_address || row.ip || ''; }
function deriveDetail(row) { return row.detail || row.reason || ''; }

function buildExtractedText(sliceId, row, isoTimestamp) {
  // The human-readable summary, preserved across review platforms as the
  // primary search target. LF-separated within the cell so Relativity
  // treats embedded LF as cell-internal breaks rather than row terminators.
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
  return lines.join('\n');
}

// ── DAT row builder ──────────────────────────────────────────────────────

function buildDatRow(sliceId, row) {
  const id = row.id != null ? row.id : '';
  const controlNumber = 'LH-' + sliceId + '-' + id;
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
  const extractedText = buildExtractedText(sliceId, row, isoTimestamp);
  const canonicalBytes = canonicalSerialize(row);
  const canonicalSha256 = sliceSha256(canonicalBytes);
  // Relativity convention: NativeFilePath uses Windows-style backslashes
  const nativeFilePath = NATIVES_DIR + '\\' + controlNumber + '.json';

  const values = {
    ControlNumber: controlNumber,
    Custodian: custodian,
    From: SYNTHETIC_FROM,
    To: SYNTHETIC_TO,
    CC: '',
    BCC: '',
    Subject: subject,
    DateSent: dateSent,
    TimeSent: timeSent,
    DateReceived: dateSent,
    EmailThreadID: '',
    HasAttachments: 'Y',
    BeginBates: '',
    EndBates: '',
    NativeFilePath: nativeFilePath,
    ExtractedText: extractedText,
    FA_SLICE: sliceId,
    FA_EVENTID: String(id),
    FA_EVENTTYPE: eventType,
    FA_ORIGINALTIMESTAMP: isoTimestamp,
    FA_IPADDRESS: ip,
    FA_DETAIL: detail,
    FA_USERAGENT: row.user_agent || '',
    FA_CANONICALSHA256: canonicalSha256,
    FA_NATIVESIZE: String(canonicalBytes.length),
  };

  return {
    controlNumber,
    canonicalBytes,
    datLine: FIELDS.map((f) => wrapField(values[f] == null ? '' : values[f])).join(PIPE),
    nativeFilePath,
  };
}

// ── DAT file builder ─────────────────────────────────────────────────────

function buildDatFile(rows) {
  const headerRow = FIELDS.map((f) => wrapField(f)).join(PIPE);
  const dataRows = rows.map((r) => r.datLine);
  const body = headerRow + ROW_SEP + dataRows.join(ROW_SEP) + (dataRows.length > 0 ? ROW_SEP : '');
  return Buffer.concat([UTF8_BOM, Buffer.from(body, 'utf-8')]);
}

// ── OPT file builder ─────────────────────────────────────────────────────

function buildOptFile(rows) {
  // imageKey,volume,fullPath,documentBreak,folderBreak,boxBreak,pageCount
  // For audit events the page count is 1 and documentBreak=Y; image paths
  // are notional placeholders that C45's imaging output will materialize.
  const lines = rows.map((r) => {
    const imagePath = IMAGES_DIR + '\\' + r.controlNumber + '.tif';
    return [
      sanitizeCsv(r.controlNumber),
      sanitizeCsv(VOLUME),
      sanitizeCsv(imagePath),
      'Y', '', '', '1',
    ].join(',');
  });
  return Buffer.from(lines.join(ROW_SEP) + (lines.length > 0 ? ROW_SEP : ''), 'utf-8');
}

// ── LFP file builder ─────────────────────────────────────────────────────

function buildLfpFile(rows) {
  // controlNumber,volume,nativeFilePath
  const lines = rows.map((r) => {
    return [
      sanitizeCsv(r.controlNumber),
      sanitizeCsv(VOLUME),
      sanitizeCsv(r.nativeFilePath),
    ].join(',');
  });
  return Buffer.from(lines.join(ROW_SEP) + (lines.length > 0 ? ROW_SEP : ''), 'utf-8');
}

// ── README ───────────────────────────────────────────────────────────────

function buildReadme() {
  return [
    'FIREALIVE LEGAL HOLD EXPORT — Relativity Load Bundle',
    '',
    'CONTENTS',
    '',
    '  loadfile.dat                 Metadata load file (UTF-8 BOM, pipe-delimited,',
    '                               thorn-qualified, CRLF — Concordance lexical shape',
    '                               with Relativity column naming)',
    '  loadfile.opt                 Opticon image load file (sparse placeholders;',
    '                               populated by pdf-bates/tiff-bates output if',
    '                               imaged review is included in the export)',
    '  loadfile.lfp                 Native file load file linking each ControlNumber',
    '                               to its native JSON in NATIVES/',
    '  NATIVES/                     One canonical .json file per audit event',
    '  README.txt                   This file',
    '',
    'HOW TO IMPORT INTO RELATIVITY',
    '',
    '  1. Extract this ZIP to a local directory.',
    '  2. In Relativity, open the target Workspace and navigate to the Documents tab.',
    '  3. Open the Load File wizard (Add Documents > Load File).',
    '  4. Point the DAT field to loadfile.dat.',
    '  5. Point the OPT field to loadfile.opt (or skip if imaged review is not needed).',
    '  6. Point the LFP field to loadfile.lfp.',
    '  7. Set the native file root directory to the extracted NATIVES/ folder.',
    '  8. Map columns — Relativity will auto-detect ControlNumber, From, To, Subject, etc.',
    '  9. Run the load. The FA_* columns surface as custom fields.',
    '',
    'CHAIN OF INTEGRITY',
    '',
    '  Every row in loadfile.dat carries an FA_CANONICALSHA256 column. The native',
    '  file at NATIVES/<ControlNumber>.json contains the canonical JSON bytes',
    '  whose SHA-256 matches that column. To verify integrity:',
    '',
    '    1. Open loadfile.dat in a thorn-delimited parser (Relativity does this',
    '       natively; Python: pandas.read_csv with sep="|", quotechar="\u00FE")',
    '    2. For a given row, read the FA_CANONICALSHA256 value',
    '    3. Open NATIVES/<ControlNumber>.json',
    '    4. Compute SHA-256 of the file bytes',
    '    5. Compare against FA_CANONICALSHA256 (must match exactly)',
    '',
    '  This is the same hash recorded in the archive-level manifest signed by',
    '  Ed25519 in the parent legal hold export.',
    '',
    'COLUMN REFERENCE',
    '',
    '  Standard Relativity columns:',
    '    ControlNumber, Custodian, From, To, CC, BCC, Subject,',
    '    DateSent, TimeSent, DateReceived, EmailThreadID, HasAttachments,',
    '    BeginBates, EndBates, NativeFilePath, ExtractedText',
    '',
    '  FireAlive extension columns:',
    '    FA_SLICE, FA_EVENTID, FA_EVENTTYPE, FA_ORIGINALTIMESTAMP,',
    '    FA_IPADDRESS, FA_DETAIL, FA_USERAGENT, FA_CANONICALSHA256,',
    '    FA_NATIVESIZE',
    '',
    '  BeginBates and EndBates are empty in this load. They are populated by',
    '  the pdf-bates / tiff-bates serializers when imaged review is included.',
    '',
  ].join(ROW_SEP);
}

// ── Main serializer ───────────────────────────────────────────────────────

function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('relativity: slices object required');
  }

  // First pass: build all DAT rows + collect native file contents
  const rows = [];
  for (const sliceId of SLICE_ORDER) {
    const slice = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    for (const row of slice) {
      rows.push(buildDatRow(sliceId, row));
    }
  }

  // Second pass: assemble the ZIP
  const zip = new ZipFile();
  zip.addFile('README.txt', buildReadme());
  zip.addFile('loadfile.dat', buildDatFile(rows));
  zip.addFile('loadfile.opt', buildOptFile(rows));
  zip.addFile('loadfile.lfp', buildLfpFile(rows));

  // Add NATIVES/<ControlNumber>.json files. Forward slashes inside the ZIP
  // entry names per ZIP spec; Relativity normalizes to OS-native separators
  // at extraction time.
  for (const r of rows) {
    zip.addFile(NATIVES_DIR + '/' + r.controlNumber + '.json', r.canonicalBytes);
  }

  return zip.toBuffer();
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
  VOLUME,
  NATIVES_DIR,
  IMAGES_DIR,
  SYNTHETIC_FROM,
  SYNTHETIC_TO,
  sanitizeValue,
  sanitizeCsv,
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
  buildExtractedText,
  buildDatRow,
  buildDatFile,
  buildOptFile,
  buildLfpFile,
  buildReadme,
};

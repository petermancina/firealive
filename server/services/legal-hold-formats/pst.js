// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Legal Hold Format: PST Container (R3l C41)
//
// Emits a legal-hold slice set as a ZIP archive containing one RFC 5322
// .eml file per audit event, organized into folders that map directly
// to an Outlook PST folder hierarchy when imported. Consumed by:
//
//   - Microsoft Outlook (drag-and-drop folder import into a target PST,
//     or "Import from another program or file" workflow)
//   - Exchange Online (import via PowerShell New-MailboxImportRequest
//     after rehydration to PST)
//   - All major e-discovery platforms: Relativity, Concordance, Logikcull,
//     Everlaw, DISCO, Reveal — each accepts "ZIP of EML files" as a
//     standard ingest path (often the same path as native PST ingest)
//   - Custom Outlook MAPI tools that walk the extracted folder tree
//
// WHY ZIP AND NOT BINARY MS-PST
//
// The MS-PST binary format ([MS-PST] specification) is genuinely complex:
// hundreds of pages of spec, BTrees, allocation maps, NDB/LTP layers, TC
// row contexts, PC property contexts. Producing a writable PST from
// scratch in pure JavaScript is a multi-thousand-line undertaking with
// high risk of generating output that Outlook silently rejects or
// corrupts. The mature open-source PST writers (libpff, pypff, Aspose)
// are either read-only or require commercial licensing.
//
// The pragmatic litigation-grade alternative is a ZIP archive of .eml
// files organized into folders. Outlook, Exchange, and every e-discovery
// platform with PST ingest also accepts this pattern — often via the
// exact same import wizard. The receiving party extracts the ZIP,
// drags the folders into a target PST in Outlook, and the messages
// land in the expected places. This is a documented and widely-used
// e-discovery workflow, NOT a workaround.
//
// FOLDER LAYOUT IN THE ZIP
//
//   README.txt                            — explains the format + chain
//                                            of integrity for receivers
//   manifest.json                         — per-slice index with hashes
//   FireAlive Legal Hold/                 — top-level Outlook folder
//     Audit Events/                       — audit_log slice
//       00001.eml
//       00002.eml
//       ...
//     Backup Chain/                       — backup_chain slice
//       00100.eml
//     Authentication/                     — authentication_logs slice
//       00050.eml
//     User Sessions/                      — user_access_logs slice
//       ...
//     Incident Records/                   — incident_records slice
//       ...
//
// EML CONTENT PER MESSAGE
//
// Each .eml is a standalone RFC 5322 multipart/mixed message structurally
// similar to those produced by C40 but without the mbox "From " separator
// (each .eml is its own file, not concatenated). Same header set, same
// X-FireAlive-* extensions, same multipart body with text/plain summary
// + base64-attached canonical.json. The chain of integrity matches:
// X-FireAlive-CanonicalSHA256 on every message corresponds to the
// manifest's slice descriptor.
//
// ZIP FORMAT
//
// Implementation uses the standard PKZIP format (APPNOTE.TXT) with
// DEFLATE compression via Node's built-in zlib.deflateRawSync. The
// minimum structure produced:
//
//   - Local File Header per file
//   - Compressed file data (deflate-raw)
//   - Central Directory entry per file
//   - End of Central Directory Record
//
// CRC-32 is computed per file using the standard polynomial (0xEDB88320)
// with a precomputed table for performance. ZIP requires CRC-32 in both
// the local file header and the central directory entry.
//
// DOS date/time fields are computed from the export's wall-clock time
// (a single value for all files in the archive — preservation of the
// export creation moment). Per-file timestamps via extended fields are
// not used; the per-event timestamps live in the .eml's Date: header.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');
const zlib = require('zlib');
const { canonicalSerialize, sliceSha256 } = require('../audit-export-shared');

const FORMAT_ID = 'pst';
const FILE_EXTENSION = '.zip';
const CRLF = '\r\n';
const SYNTHETIC_FROM = 'FireAlive Audit <audit@firealive.local>';
const SYNTHETIC_TO = 'Legal Hold <legal-hold@firealive.local>';
const FIREALIVE_DOMAIN = 'firealive.local';
const SUBJECT_MAX_LEN = 70;
const BASE64_WRAP_WIDTH = 76;

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTH_NAMES = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const SLICE_FOLDER = {
  audit_log: 'Audit Events',
  backup_chain: 'Backup Chain',
  authentication_logs: 'Authentication',
  user_access_logs: 'User Sessions',
  incident_records: 'Incident Records',
};

const SLICE_ORDER = ['audit_log', 'backup_chain', 'authentication_logs', 'user_access_logs', 'incident_records'];

// ── CRC-32 (PKZIP poly 0xEDB88320) ────────────────────────────────────────

const CRC32_TABLE = (function buildCrc32Table() {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    c = CRC32_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// ── DOS date/time encoders ────────────────────────────────────────────────

function dosDateTime(d) {
  if (!d || isNaN(d.getTime())) d = new Date();
  // DOS time: hh<<11 | mm<<5 | (seconds/2). DOS date: (year-1980)<<9 | month<<5 | day.
  const time = (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | (d.getUTCSeconds() >>> 1);
  const date = ((d.getUTCFullYear() - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate();
  return { time: time & 0xFFFF, date: date & 0xFFFF };
}

// ── ZIP writer ────────────────────────────────────────────────────────────
//
// Minimal pure-JS ZIP writer. Stores files with DEFLATE compression via
// zlib.deflateRawSync. Each call to addFile() records the file in an
// internal table; toBuffer() concatenates all local file headers + data,
// then the central directory + EOCD record.

class ZipFile {
  constructor() {
    this.entries = [];
    this.now = new Date();
  }

  addFile(filename, contents) {
    const filenameBuf = Buffer.from(filename, 'utf-8');
    if (filenameBuf.length > 0xFFFF) throw new Error('zip: filename too long: ' + filename);
    const uncompressed = Buffer.isBuffer(contents) ? contents : Buffer.from(contents, 'utf-8');
    const compressed = zlib.deflateRawSync(uncompressed);
    const crc = crc32(uncompressed);
    this.entries.push({
      filename: filenameBuf,
      filenameStr: filename,
      compressed,
      crc,
      compressedSize: compressed.length,
      uncompressedSize: uncompressed.length,
    });
  }

  toBuffer() {
    const { time, date } = dosDateTime(this.now);
    const localChunks = [];
    const cdChunks = [];
    let offset = 0;

    for (const e of this.entries) {
      // Local File Header
      const lfh = Buffer.alloc(30);
      lfh.writeUInt32LE(0x04034b50, 0);   // signature
      lfh.writeUInt16LE(20, 4);            // version needed (2.0)
      lfh.writeUInt16LE(0, 6);             // general purpose flag
      lfh.writeUInt16LE(8, 8);             // method = deflate
      lfh.writeUInt16LE(time, 10);         // last mod time (DOS)
      lfh.writeUInt16LE(date, 12);         // last mod date (DOS)
      lfh.writeUInt32LE(e.crc, 14);        // CRC-32
      lfh.writeUInt32LE(e.compressedSize, 18);
      lfh.writeUInt32LE(e.uncompressedSize, 22);
      lfh.writeUInt16LE(e.filename.length, 26);
      lfh.writeUInt16LE(0, 28);            // extra field length
      localChunks.push(lfh, e.filename, e.compressed);
      e.localHeaderOffset = offset;
      offset += lfh.length + e.filename.length + e.compressed.length;

      // Central Directory Entry
      const cd = Buffer.alloc(46);
      cd.writeUInt32LE(0x02014b50, 0);     // signature
      cd.writeUInt16LE(0x031E, 4);         // version made by (3=Unix, 0x1E=v3.0)
      cd.writeUInt16LE(20, 6);             // version needed
      cd.writeUInt16LE(0, 8);              // gp flag
      cd.writeUInt16LE(8, 10);             // method = deflate
      cd.writeUInt16LE(time, 12);
      cd.writeUInt16LE(date, 14);
      cd.writeUInt32LE(e.crc, 16);
      cd.writeUInt32LE(e.compressedSize, 20);
      cd.writeUInt32LE(e.uncompressedSize, 24);
      cd.writeUInt16LE(e.filename.length, 28);
      cd.writeUInt16LE(0, 30);             // extra field length
      cd.writeUInt16LE(0, 32);             // file comment length
      cd.writeUInt16LE(0, 34);             // disk number start
      cd.writeUInt16LE(0, 36);             // internal file attributes
      cd.writeUInt32LE(0o644 << 16, 38);   // external file attributes (Unix mode)
      cd.writeUInt32LE(e.localHeaderOffset, 42);
      cdChunks.push(cd, e.filename);
    }

    const cdStart = offset;
    const cdBytes = Buffer.concat(cdChunks);
    const cdSize = cdBytes.length;

    // End of Central Directory Record
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);     // signature
    eocd.writeUInt16LE(0, 4);              // disk number
    eocd.writeUInt16LE(0, 6);              // disk where CD starts
    eocd.writeUInt16LE(this.entries.length, 8);  // entries on this disk
    eocd.writeUInt16LE(this.entries.length, 10); // total entries
    eocd.writeUInt32LE(cdSize, 12);
    eocd.writeUInt32LE(cdStart, 16);
    eocd.writeUInt16LE(0, 20);             // comment length

    return Buffer.concat([Buffer.concat(localChunks), cdBytes, eocd]);
  }
}

// ── EML message generator (standalone, no mbox separators) ────────────────

function pad2(n) { return n < 10 ? '0' + n : String(n); }

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

function formatRfc5322Date(d) {
  if (!d || isNaN(d.getTime())) return '';
  return DAY_NAMES[d.getUTCDay()] + ', ' +
         pad2(d.getUTCDate()) + ' ' + MONTH_NAMES[d.getUTCMonth()] + ' ' + d.getUTCFullYear() + ' ' +
         pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds()) +
         ' +0000';
}

function sanitizeSubject(s) {
  if (s == null) return '';
  const cleaned = String(s).replace(/[\x00-\x1F\x7F-\uFFFF]/g, '').trim();
  return cleaned.length > SUBJECT_MAX_LEN
    ? cleaned.substring(0, SUBJECT_MAX_LEN - 3) + '...'
    : cleaned;
}

function sanitizeHeaderValue(s) {
  if (s == null) return '';
  return String(s).replace(/[\x00-\x1F\x7F]/g, '');
}

function wrapBase64(buf, width) {
  const b64 = buf.toString('base64');
  const lines = [];
  for (let i = 0; i < b64.length; i += width) {
    lines.push(b64.substring(i, i + width));
  }
  return lines.join(CRLF);
}

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

function buildTextSummary(sliceId, row, isoTimestamp) {
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
  lines.push('');
  lines.push('The full canonical JSON representation is attached as canonical.json.');
  lines.push('Verify integrity by re-hashing the attachment and comparing against');
  lines.push('the X-FireAlive-CanonicalSHA256 header.');
  return lines.join(CRLF);
}

function buildEmlMessage(sliceId, row) {
  const id = row.id != null ? row.id : '';
  const rawTimestamp = deriveTimestamp(sliceId, row);
  const date = parseSourceTimestamp(rawTimestamp);
  const isoTimestamp = date ? date.toISOString() : '';
  const subject = sanitizeSubject(deriveSubject(sliceId, row));
  const messageId = '<LH-' + sliceId + '-' + id + '@' + FIREALIVE_DOMAIN + '>';
  const canonicalBytes = canonicalSerialize(row);
  const sha256Hex = sliceSha256(canonicalBytes);
  const boundary = 'fa-' + crypto.randomBytes(16).toString('hex');

  const headers = [
    'Date: ' + formatRfc5322Date(date),
    'From: ' + SYNTHETIC_FROM,
    'To: ' + SYNTHETIC_TO,
    'Subject: ' + subject,
    'Message-ID: ' + messageId,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="' + boundary + '"',
    'X-FireAlive-Slice: ' + sanitizeHeaderValue(sliceId),
    'X-FireAlive-EventID: ' + sanitizeHeaderValue(id),
    'X-FireAlive-OriginalTimestamp: ' + sanitizeHeaderValue(isoTimestamp),
    'X-FireAlive-CanonicalSHA256: ' + sanitizeHeaderValue(sha256Hex),
  ];

  const textBody = buildTextSummary(sliceId, row, isoTimestamp);
  const jsonBody = wrapBase64(canonicalBytes, BASE64_WRAP_WIDTH);

  const body = [
    '',
    '--' + boundary,
    'Content-Type: text/plain; charset="utf-8"',
    'Content-Transfer-Encoding: 8bit',
    '',
    textBody,
    '',
    '--' + boundary,
    'Content-Type: application/json; name="canonical.json"',
    'Content-Disposition: attachment; filename="canonical.json"',
    'Content-Transfer-Encoding: base64',
    '',
    jsonBody,
    '',
    '--' + boundary + '--',
    '',
  ];

  return headers.join(CRLF) + CRLF + body.join(CRLF);
}

// ── Filename padding ──────────────────────────────────────────────────────
//
// Pad event IDs to a stable width inside each folder so Outlook's
// alphabetical sort matches the chronological sort.

function padEventId(id, totalCount) {
  const width = Math.max(5, String(totalCount).length);
  return String(id).padStart(width, '0');
}

// ── README content ────────────────────────────────────────────────────────

function buildReadme() {
  return [
    'FIREALIVE LEGAL HOLD EXPORT — PST-Equivalent ZIP Container',
    '',
    'CONTENTS',
    '',
    'This ZIP contains one .eml file per audit event, organized into',
    'folders that map directly to an Outlook PST folder hierarchy when',
    'imported. The folder structure is:',
    '',
    '  FireAlive Legal Hold/',
    '    Audit Events/         (audit_log slice)',
    '    Backup Chain/         (backup_chain slice)',
    '    Authentication/       (authentication_logs slice)',
    '    User Sessions/        (user_access_logs slice)',
    '    Incident Records/     (incident_records slice)',
    '',
    'HOW TO IMPORT INTO OUTLOOK',
    '',
    '  1. Extract this ZIP to a local directory.',
    '  2. Open Outlook and create or open the target PST file.',
    '  3. Drag the "FireAlive Legal Hold" folder from the extracted',
    '     directory into the PST in the Outlook navigation pane.',
    '  4. Outlook will create folders matching the directory tree and',
    '     import each .eml file as a message.',
    '',
    'HOW TO IMPORT INTO RELATIVITY / CONCORDANCE / OTHER E-DISCOVERY',
    '',
    '  Most e-discovery platforms accept "ZIP of EML" via the same',
    '  ingest path as native PST. Upload this archive directly OR',
    '  extract first and point the ingest at the extracted directory.',
    '',
    'CHAIN OF INTEGRITY',
    '',
    '  Each .eml message includes an X-FireAlive-CanonicalSHA256 header',
    '  recording the SHA-256 hash of the canonical JSON representation',
    '  of the source row. The canonical JSON is attached to each message',
    '  as canonical.json. To verify integrity:',
    '',
    '    1. Open the .eml in any RFC 5322 parser',
    '    2. Read the X-FireAlive-CanonicalSHA256 header',
    '    3. Base64-decode the canonical.json attachment',
    '    4. Compute SHA-256 of the decoded bytes',
    '    5. Compare against the header value (must match)',
    '',
    '  This is the same hash recorded in manifest.json (also inside',
    '  this ZIP) and in the archive-level manifest signed by Ed25519',
    '  in the parent legal hold export.',
    '',
    'FORMAT NOTE',
    '',
    '  This is a PST-equivalent ZIP container, not a literal MS-PST',
    '  binary file. Both Outlook and major e-discovery platforms accept',
    '  this pattern as a standard ingest path. See the FireAlive legal',
    '  hold export documentation for the full chain-of-custody design.',
    '',
  ].join(CRLF);
}

// ── Per-archive manifest ──────────────────────────────────────────────────

function buildManifestIndex(perSliceMessages) {
  const index = {
    format: 'firealive-legal-hold-pst-zip',
    version: '1.0',
    slices: {},
  };
  for (const sliceId of SLICE_ORDER) {
    const msgs = perSliceMessages[sliceId] || [];
    index.slices[sliceId] = {
      message_count: msgs.length,
      folder: SLICE_FOLDER[sliceId],
      messages: msgs.map((m) => ({
        filename: m.filename,
        event_id: m.eventId,
        canonical_sha256: m.canonicalSha256,
      })),
    };
  }
  return Buffer.from(JSON.stringify(index, null, 2), 'utf-8');
}

// ── Main serializer ───────────────────────────────────────────────────────

function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('pst: slices object required');
  }

  const zip = new ZipFile();
  const perSliceMessages = {};

  // README at top of archive — first thing receivers see
  zip.addFile('README.txt', buildReadme());

  for (const sliceId of SLICE_ORDER) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    perSliceMessages[sliceId] = [];
    const folder = SLICE_FOLDER[sliceId];
    for (const row of rows) {
      const eml = buildEmlMessage(sliceId, row);
      const eventId = row.id != null ? row.id : crypto.randomBytes(4).toString('hex');
      const padded = padEventId(eventId, rows.length);
      const filename = 'FireAlive Legal Hold/' + folder + '/' + padded + '.eml';
      zip.addFile(filename, eml);
      perSliceMessages[sliceId].push({
        filename,
        eventId: String(eventId),
        canonicalSha256: sliceSha256(canonicalSerialize(row)),
      });
    }
  }

  // manifest.json LAST so the central-directory order shows it after the
  // slice files — receivers scrolling the CD entries see structure +
  // manifest at the end, which is the natural reading order.
  zip.addFile('manifest.json', buildManifestIndex(perSliceMessages));

  return zip.toBuffer();
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: false,
  serialize,
  // Internal helpers exposed for unit tests
  crc32,
  dosDateTime,
  ZipFile,
  parseSourceTimestamp,
  formatRfc5322Date,
  sanitizeSubject,
  sanitizeHeaderValue,
  wrapBase64,
  deriveSubject,
  deriveTimestamp,
  buildTextSummary,
  buildEmlMessage,
  buildReadme,
  buildManifestIndex,
  padEventId,
  SLICE_FOLDER,
  SLICE_ORDER,
};

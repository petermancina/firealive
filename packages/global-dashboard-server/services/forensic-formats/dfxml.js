// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Forensic Format: Digital Forensics XML (DFXML) (R3l C28a)
//
// Emits an audit-event slice set as Digital Forensics XML (DFXML) — the
// open standard developed by Simson Garfinkel and the OSS forensic tools
// community (DFXML Working Group) for representing filesystem and
// forensic metadata in a structured, tool-portable way. Consumed by:
//
//   - fiwalk (the reference DFXML producer; also reads DFXML for cross-
//     run comparison)
//   - Autopsy (via the DFXML ingest module)
//   - bulk_extractor (for cross-referencing extracted artifacts to a
//     filesystem timeline)
//   - SleuthKit ecosystem analysts using the dfxml_python or dfxml_cpp
//     bindings for custom timeline analysis
//
// The schema is published at https://github.com/dfxml-working-group/dfxml_schema
// and the namespace URI is the de facto industry standard for DFXML.
//
// AUDIT-EVENT-TO-FILEOBJECT MAPPING
//
// DFXML's primary content type is <fileobject> — a representation of a
// filesystem object with timestamps, hashes, and extended metadata.
// Audit events fit naturally as virtual fileobjects where:
//
//   filename       "<sliceId>/<discriminator>:<id>"
//   inode          numeric event id (string ids SHA-256-prefix hashed)
//   mtime, atime, ctime, crtime
//                  all four set to the event timestamp (point-in-time
//                  event; MACB equal — same convention as C23 bodyfile)
//   filesize       byte length of canonical-JSON of the row
//   hashdigest sha256
//                  SHA-256 of canonical-JSON (the same value the manifest
//                  records for forensic_export slice integrity — when the
//                  same event lands in DFXML, this hash lines up with
//                  manifest entries for cross-verification)
//   hashdigest md5
//                  MD5 of canonical-JSON (matches C23 bodyfile's MD5
//                  field for cross-format event identification)
//
// Plus FireAlive extension elements in the `fa:` namespace:
//
//   fa:slice          source slice id
//   fa:event_type     discriminator
//   fa:event_id       original DB id (string-typed to preserve
//                       non-numeric ids unchanged)
//   fa:user           user_id / user when present
//   fa:ip             ip_address / ip when present
//   fa:chain_hash     this_hash (backup_chain only)
//   fa:canonical      canonical-JSON of the full row for byte-exact
//                       round-trip verification
//
// SCHEMA
//
//   <?xml version="1.0" encoding="UTF-8"?>
//   <dfxml xmlns="http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML"
//          xmlns:dc="http://purl.org/dc/elements/1.1/"
//          xmlns:fa="https://firealive.io/dfxml-extensions/v1"
//          version="1.2.0">
//     <metadata>
//       <dc:type>FireAlive forensic audit export</dc:type>
//       <dc:format>DFXML 1.2.0</dc:format>
//     </metadata>
//     <creator version="1.0">
//       <program>FireAlive-AuditExport</program>
//       <version>r3l-v1</version>
//     </creator>
//     <fileobject>...</fileobject>
//     <fileobject>...</fileobject>
//     ...
//   </dfxml>
//
// ORDERING
//
// epoch ASC, ties (sliceId ASC, id ASC). Same deterministic sort as the
// other format serializers.
//
// XML ESCAPING
//
// Same logic as C27a (evtx-xml): stripInvalidXmlChars first, then the
// 5 XML 1.0 entity escapes. Pretty-printed 2-space indent for human
// readability.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');

const { canonicalSerialize } = require('../audit-export-shared');

const FORMAT_ID = 'dfxml';
const FILE_EXTENSION = '.xml';

const DFXML_NS = 'http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML';
const DC_NS = 'http://purl.org/dc/elements/1.1/';
const FA_NS = 'https://firealive.io/dfxml-extensions/v1';
const DFXML_VERSION = '1.2.0';
const PROGRAM_NAME = 'FireAlive-AuditExport';
const PROGRAM_VERSION = 'r3l-v1';

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
 * Parse a timestamp value into a Date object (UTC). Same dual-format
 * handling as the other format serializers (SQLite default + ISO 8601).
 */
function parseTimestampDate(raw, sliceId, rowId) {
  if (raw === null || raw === undefined || raw === '') {
    throw new Error(
      'dfxml: ' +
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
      'dfxml: ' +
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
 * Coerce a value to a non-negative integer inode. Numeric inputs pass
 * through; string ids hash to a stable 32-bit unsigned int. Matches
 * the same coercion idiom from C23/C25.
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
 * Strip XML 1.0-invalid control characters (matches C27a evtx-xml
 * implementation).
 */
function stripInvalidXmlChars(s) {
  if (s === null || s === undefined) return '';
  // eslint-disable-next-line no-control-regex
  return String(s).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
}

/**
 * Escape XML 1.0 reserved characters (matches C27a evtx-xml
 * implementation).
 */
function escapeXml(s) {
  return stripInvalidXmlChars(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * DFXML standard time format: ISO 8601 with timezone. We use UTC with
 * the standard 'Z' suffix.
 */
function formatDfxmlTime(d) {
  return d.toISOString();
}

/**
 * Build the <fileobject> element for one audit event. seq parameter is
 * unused at this level (DFXML doesn't require record numbering inside
 * fileobject), but accepted for symmetry with the EVTX builder.
 */
function buildFileObject(sliceId, row) {
  const config = SLICE_CONFIG[sliceId];
  if (!config) {
    throw new Error('dfxml: unknown slice id: ' + sliceId);
  }
  const ts = parseTimestampDate(
    row[config.timestampField],
    sliceId,
    row.id
  );
  const discriminator = config.discriminatorField
    ? row[config.discriminatorField] || 'unknown'
    : 'SESSION';
  const idPart =
    row.id !== undefined && row.id !== null ? String(row.id) : '0';
  const filename = sliceId + '/' + discriminator + ':' + idPart;
  const inode = coerceInode(row.id);

  const canonical = canonicalSerialize(row).toString('utf-8');
  const filesize = Buffer.byteLength(canonical, 'utf-8');
  const sha256 = crypto.createHash('sha256').update(canonical).digest('hex');
  const md5 = crypto.createHash('md5').update(canonical).digest('hex');
  const tsIso = formatDfxmlTime(ts);

  const lines = [];
  lines.push('  <fileobject>');
  lines.push('    <filename>' + escapeXml(filename) + '</filename>');
  lines.push('    <inode>' + inode + '</inode>');
  lines.push('    <filesize>' + filesize + '</filesize>');
  // All four MACB timestamps equal (point-in-time event)
  lines.push('    <mtime>' + escapeXml(tsIso) + '</mtime>');
  lines.push('    <atime>' + escapeXml(tsIso) + '</atime>');
  lines.push('    <ctime>' + escapeXml(tsIso) + '</ctime>');
  lines.push('    <crtime>' + escapeXml(tsIso) + '</crtime>');
  lines.push(
    '    <hashdigest type="md5">' + md5 + '</hashdigest>'
  );
  lines.push(
    '    <hashdigest type="sha256">' + sha256 + '</hashdigest>'
  );
  // FireAlive extension elements (fa: namespace)
  lines.push('    <fa:slice>' + escapeXml(sliceId) + '</fa:slice>');
  lines.push(
    '    <fa:event_type>' + escapeXml(discriminator) + '</fa:event_type>'
  );
  lines.push('    <fa:event_id>' + escapeXml(idPart) + '</fa:event_id>');
  if (config.userField && row[config.userField]) {
    lines.push(
      '    <fa:user>' + escapeXml(row[config.userField]) + '</fa:user>'
    );
  }
  if (config.ipField && row[config.ipField]) {
    lines.push('    <fa:ip>' + escapeXml(row[config.ipField]) + '</fa:ip>');
  }
  if (sliceId === 'backup_chain' && row.this_hash) {
    lines.push(
      '    <fa:chain_hash>' + escapeXml(row.this_hash) + '</fa:chain_hash>'
    );
  }
  lines.push(
    '    <fa:canonical>' + escapeXml(canonical) + '</fa:canonical>'
  );
  lines.push('  </fileobject>');
  return lines.join('\n');
}

/**
 * serialize(slices) — orchestrator entry point.
 *
 * Returns: Buffer (UTF-8 encoding of a well-formed DFXML 1.2.0 document
 * with a <fileobject> for each audit event).
 *
 * Total ordering: epoch ASC, ties (sliceId ASC, id ASC).
 */
function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('dfxml: slices object required');
  }
  const tuples = [];
  for (const sliceId of Object.keys(slices)) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    const config = SLICE_CONFIG[sliceId];
    if (!config) continue;
    for (const row of rows) {
      const ts = parseTimestampDate(
        row[config.timestampField],
        sliceId,
        row.id
      );
      tuples.push({ sliceId, row, ms: ts.getTime() });
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

  const out = [];
  out.push('<?xml version="1.0" encoding="UTF-8"?>');
  out.push(
    '<dfxml xmlns="' +
      DFXML_NS +
      '" xmlns:dc="' +
      DC_NS +
      '" xmlns:fa="' +
      FA_NS +
      '" version="' +
      DFXML_VERSION +
      '">'
  );
  out.push('  <metadata>');
  out.push(
    '    <dc:type>FireAlive forensic audit export</dc:type>'
  );
  out.push('    <dc:format>DFXML ' + DFXML_VERSION + '</dc:format>');
  out.push('  </metadata>');
  out.push('  <creator version="1.0">');
  out.push('    <program>' + escapeXml(PROGRAM_NAME) + '</program>');
  out.push('    <version>' + escapeXml(PROGRAM_VERSION) + '</version>');
  out.push('  </creator>');
  for (const { sliceId, row } of tuples) {
    out.push(buildFileObject(sliceId, row));
  }
  out.push('</dfxml>');
  return Buffer.from(out.join('\n') + '\n', 'utf-8');
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: false,
  serialize,
  // Internal helpers exposed for unit tests
  DFXML_NS,
  FA_NS,
  DFXML_VERSION,
  PROGRAM_NAME,
  PROGRAM_VERSION,
  parseTimestampDate,
  coerceInode,
  stripInvalidXmlChars,
  escapeXml,
  formatDfxmlTime,
  buildFileObject,
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Legal Hold Format: EDRM XML 1.2 (R3l C39)
//
// Emits a legal-hold slice set as EDRM (Electronic Discovery Reference
// Model) XML version 1.2 — the open standard for ESI (Electronically
// Stored Information) data interchange between e-discovery platforms.
// Consumed by:
//
//   - Relativity (kCura) via the EDRM XML import path
//   - Concordance ESI loaders (with EDRM-to-Concordance conversion in the
//     ingest pipeline)
//   - Logikcull, Everlaw, DISCO, Reveal, and most modern review platforms
//     that advertise "EDRM XML import" or "ESI load file import"
//   - Custom litigation-tech tooling that parses the EDRM schema
//
// The EDRM XML schema is maintained at https://edrm.net/resources/frameworks-and-standards/edrm-xml/
// and is the de-facto interchange format for the ESI ecosystem. v1.2 is
// the most widely-supported version in production litigation workflows;
// v2.x added optional enhancements but most consuming tools target 1.2.
//
// AUDIT-EVENT-TO-DOCUMENT MAPPING
//
// EDRM XML's primary content type is <Document>, a representation of an
// ESI item with metadata tags and optional file references. Audit events
// fit naturally as Documents where:
//
//   DocID         "LH-<slice>-<id>" (unique within the batch)
//   MimeType      "application/json" (the canonical representation)
//   Tags          all event fields surfaced as <Tag> elements with
//                 typed values (Text or DateTime)
//   Files         empty <Files/> — content is inline via the
//                 CanonicalJSON tag rather than external files
//   Locations     empty <Locations/>
//   Relationships empty <Relationships/>
//
// Mandatory tags on every Document:
//
//   Slice              source slice id (audit_log, backup_chain, etc.)
//   OriginalID         the row's primary key from the source table
//   EventTimestamp     ISO 8601 datetime (typed DateTime per EDRM spec)
//   ContentHashSHA256  SHA-256 hex of the canonical-JSON representation
//   CanonicalJSON      the canonical-JSON serialization, for byte-exact
//                      round-trip verification by the receiving platform
//
// Optional tags per slice (when the source row has them):
//
//   EventType   audit_log.event_type, backup_chain.event_type,
//               auth_log.action
//   UserID      audit_log.user_id, sessions.user_id
//   Username    auth_log.user
//   IPAddress   audit_log.ip_address, auth_log.ip, sessions.ip_address
//   Detail      audit_log.detail, auth_log.reason
//   UserAgent   auth_log.user_agent, sessions.user_agent
//   ChainHash   backup_chain.this_hash
//   PrevHash    backup_chain.prev_hash
//   SigningKey  backup_chain.signing_key_id
//   BackupID    backup_chain.backup_id
//
// SCHEMA OUTPUT
//
//   <?xml version="1.0" encoding="UTF-8"?>
//   <Root MajorVersion="1" MinorVersion="2"
//         Description="FireAlive Legal Hold Export — EDRM XML 1.2"
//         DataInterchangeType="Update">
//     <Batch>
//       <Documents>
//         <Document DocID="LH-audit_log-12345" MimeType="application/json">
//           <Tags>
//             <Tag TagName="Slice" TagDataType="Text" TagValue="audit_log"/>
//             <Tag TagName="OriginalID" TagDataType="Text" TagValue="12345"/>
//             <Tag TagName="EventTimestamp" TagDataType="DateTime"
//                  TagValue="2026-05-15T14:30:00Z"/>
//             <Tag TagName="EventType" TagDataType="Text" TagValue="LOGIN"/>
//             <Tag TagName="UserID" TagDataType="Text" TagValue="user-123"/>
//             <Tag TagName="IPAddress" TagDataType="Text" TagValue="10.0.0.5"/>
//             <Tag TagName="ContentHashSHA256" TagDataType="Text"
//                  TagValue="a1b2c3..."/>
//             <Tag TagName="CanonicalJSON" TagDataType="Text"
//                  TagValue="{&quot;id&quot;:12345,...}"/>
//           </Tags>
//           <Files/>
//           <Locations/>
//           <Relationships/>
//         </Document>
//         ...
//       </Documents>
//       <Relationships/>
//     </Batch>
//   </Root>
//
// XML ESCAPING
//
// TagValue attributes contain arbitrary user data (event details, IPs,
// usernames). XML 1.0 attribute values must escape five characters:
// & < > " '  — mapped to &amp; &lt; &gt; &quot; &apos;. Control
// characters below 0x20 (except tab, LF, CR) are forbidden in XML 1.0
// and must be stripped (not escaped — there is no valid encoding for
// them in XML 1.0). The escapeXmlAttr() and stripInvalidXmlChars()
// helpers handle both.
//
// INTEROPERABILITY NOTES
//
// Relativity's EDRM XML import requires DocID values to be globally
// unique within a workspace. The "LH-{slice}-{id}" format provides
// uniqueness within a single hold export. If multiple holds are
// imported into the same workspace, prepend the hold_id (which is a
// UUID) as a batch prefix — that's a workflow concern for the
// importing analyst, not a format concern.
//
// Concordance/Relativity often expect DateTime values in MM/DD/YYYY
// HH:MM:SS format rather than ISO 8601. The schema permits ISO 8601
// (TagDataType="DateTime"), and modern Relativity versions parse it
// natively. For older Concordance pipelines, downstream conversion is
// typically scripted; ISO 8601 here keeps the export semantically
// correct and lets the receiving party normalize.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const { canonicalSerialize, sliceSha256 } = require('../audit-export-shared');

const FORMAT_ID = 'edrm-xml';
const FILE_EXTENSION = '.xml';
const EDRM_MAJOR = '1';
const EDRM_MINOR = '2';

// ── XML escaping ──────────────────────────────────────────────────────────

function escapeXmlAttr(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function stripInvalidXmlChars(str) {
  // XML 1.0 allowed chars: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
  // Drop the rest. Most common offenders: 0x00 (null byte), 0x1B (escape),
  // other C0 control chars in legacy log content.
  if (str == null) return '';
  return String(str).replace(/[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]/g, '');
}

function safeAttr(str) {
  return escapeXmlAttr(stripInvalidXmlChars(str));
}

// ── DateTime normalization for EDRM TagDataType="DateTime" ────────────────
//
// EDRM XML 1.2 accepts ISO 8601 datetime strings. Source timestamps from
// SQLite are either ISO 8601 (auth_log, sessions) or 'YYYY-MM-DD HH:MM:SS'
// (audit_log default). Normalize to ISO 8601 with 'T' separator and
// trailing 'Z' to indicate UTC. Invalid/null input returns empty string;
// EDRM consumers treat absence as the data being unavailable.

function normalizeIsoTimestamp(raw) {
  if (raw == null) return '';
  const s = String(raw).trim();
  if (!s) return '';
  // Already ISO 8601 with timezone? Pass through.
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/.test(s)) {
    return s.endsWith('Z') ? s : s.replace(/([+-]\d{2}):?(\d{2})$/, '$1:$2');
  }
  // 'YYYY-MM-DD HH:MM:SS' → 'YYYY-MM-DDTHH:MM:SSZ'
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) {
    return s.replace(' ', 'T') + 'Z';
  }
  // 'YYYY-MM-DDTHH:MM:SS' (no timezone) → assume UTC
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(s)) {
    return s + 'Z';
  }
  // Try Date.parse fallback for anything else
  const parsed = Date.parse(s);
  if (!isNaN(parsed)) return new Date(parsed).toISOString();
  return '';
}

// ── Slice-to-Document mapping ─────────────────────────────────────────────
//
// Each slice has its own column set. Build the per-slice tag list as a
// function of (row, sliceId), so the Document body construction is
// uniform across slices.

function tagsForAuditLogRow(row) {
  const tags = [];
  tags.push({ name: 'EventType', type: 'Text', value: row.event_type });
  tags.push({ name: 'UserID', type: 'Text', value: row.user_id });
  if (row.ip_address) tags.push({ name: 'IPAddress', type: 'Text', value: row.ip_address });
  if (row.detail) tags.push({ name: 'Detail', type: 'Text', value: row.detail });
  return tags;
}

function tagsForBackupChainRow(row) {
  const tags = [];
  tags.push({ name: 'EventType', type: 'Text', value: row.event_type });
  if (row.this_hash) tags.push({ name: 'ChainHash', type: 'Text', value: row.this_hash });
  if (row.prev_hash) tags.push({ name: 'PrevHash', type: 'Text', value: row.prev_hash });
  if (row.signing_key_id) tags.push({ name: 'SigningKey', type: 'Text', value: row.signing_key_id });
  if (row.backup_id) tags.push({ name: 'BackupID', type: 'Text', value: row.backup_id });
  return tags;
}

function tagsForAuthLogRow(row) {
  const tags = [];
  tags.push({ name: 'EventType', type: 'Text', value: row.action });
  if (row.user) tags.push({ name: 'Username', type: 'Text', value: row.user });
  if (row.ip) tags.push({ name: 'IPAddress', type: 'Text', value: row.ip });
  if (row.method) tags.push({ name: 'AuthMethod', type: 'Text', value: row.method });
  if (row.reason) tags.push({ name: 'Detail', type: 'Text', value: row.reason });
  if (row.user_agent) tags.push({ name: 'UserAgent', type: 'Text', value: row.user_agent });
  return tags;
}

function tagsForSessionsRow(row) {
  const tags = [];
  tags.push({ name: 'EventType', type: 'Text', value: 'SESSION_OPENED' });
  if (row.user_id) tags.push({ name: 'UserID', type: 'Text', value: row.user_id });
  if (row.ip_address) tags.push({ name: 'IPAddress', type: 'Text', value: row.ip_address });
  if (row.user_agent) tags.push({ name: 'UserAgent', type: 'Text', value: row.user_agent });
  if (row.expires_at) tags.push({ name: 'ExpiresAt', type: 'DateTime', value: normalizeIsoTimestamp(row.expires_at) });
  return tags;
}

// Each entry in this map describes how to extract (id, timestamp,
// extra-tags) from a row of the given slice.
const SLICE_HANDLERS = {
  audit_log: {
    getId: (r) => r.id,
    getTimestamp: (r) => r.timestamp,
    getTags: tagsForAuditLogRow,
  },
  backup_chain: {
    getId: (r) => r.id,
    getTimestamp: (r) => r.created_at,
    getTags: tagsForBackupChainRow,
  },
  authentication_logs: {
    getId: (r) => r.id,
    getTimestamp: (r) => r.timestamp,
    getTags: tagsForAuthLogRow,
  },
  user_access_logs: {
    getId: (r) => r.id,
    getTimestamp: (r) => r.created_at,
    getTags: tagsForSessionsRow,
  },
  incident_records: {
    getId: (r) => r.id,
    getTimestamp: (r) => r.created_at || r.timestamp,
    getTags: () => [],
  },
};

// ── Document builder ──────────────────────────────────────────────────────

function buildTag(name, type, value) {
  return '        <Tag TagName="' + safeAttr(name) + '" TagDataType="' + safeAttr(type) + '" TagValue="' + safeAttr(value) + '"/>';
}

function buildDocument(sliceId, row, canonicalBytes, sha256Hex) {
  const handler = SLICE_HANDLERS[sliceId];
  if (!handler) return null;
  const id = handler.getId(row);
  const ts = normalizeIsoTimestamp(handler.getTimestamp(row));
  const docId = 'LH-' + sliceId + '-' + (id != null ? id : '');
  const extraTags = handler.getTags(row).filter((t) => t.value != null && String(t.value) !== '');

  const lines = [];
  lines.push('      <Document DocID="' + safeAttr(docId) + '" MimeType="application/json">');
  lines.push('        <Tags>');
  lines.push(buildTag('Slice', 'Text', sliceId));
  lines.push(buildTag('OriginalID', 'Text', id != null ? String(id) : ''));
  if (ts) lines.push(buildTag('EventTimestamp', 'DateTime', ts));
  for (const t of extraTags) {
    lines.push(buildTag(t.name, t.type, t.value));
  }
  lines.push(buildTag('ContentHashSHA256', 'Text', sha256Hex));
  // CanonicalJSON tag carries the byte-exact representation for round-trip
  // verification. The receiver can hash the CanonicalJSON value (after
  // un-escaping XML entities) and confirm it matches ContentHashSHA256.
  lines.push(buildTag('CanonicalJSON', 'Text', canonicalBytes.toString('utf-8')));
  lines.push('        </Tags>');
  lines.push('        <Files/>');
  lines.push('        <Locations/>');
  lines.push('        <Relationships/>');
  lines.push('      </Document>');
  return lines.join('\n');
}

// ── Main serializer ───────────────────────────────────────────────────────

function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('edrm-xml: slices object required');
  }

  const documentLines = [];
  for (const sliceId of Object.keys(SLICE_HANDLERS)) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    for (const row of rows) {
      // Canonical-JSON of the row; SHA-256 of the canonical bytes
      const canonicalBytes = canonicalSerialize(row);
      const sha256Hex = sliceSha256(canonicalBytes);
      const docXml = buildDocument(sliceId, row, canonicalBytes, sha256Hex);
      if (docXml) documentLines.push(docXml);
    }
  }

  const headerLines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<Root MajorVersion="' + EDRM_MAJOR + '" MinorVersion="' + EDRM_MINOR + '" Description="FireAlive Legal Hold Export — EDRM XML 1.2" DataInterchangeType="Update">',
    '  <Batch>',
    '    <Documents>',
  ];
  const footerLines = [
    '    </Documents>',
    '    <Relationships/>',
    '  </Batch>',
    '</Root>',
    '', // trailing newline for POSIX text-file convention
  ];

  const xml = headerLines.join('\n') + '\n' + documentLines.join('\n') + (documentLines.length > 0 ? '\n' : '') + footerLines.join('\n');
  return Buffer.from(xml, 'utf-8');
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: false,
  serialize,
  // Internal helpers exposed for unit tests
  escapeXmlAttr,
  stripInvalidXmlChars,
  safeAttr,
  normalizeIsoTimestamp,
  buildTag,
  buildDocument,
  SLICE_HANDLERS,
  EDRM_MAJOR,
  EDRM_MINOR,
};

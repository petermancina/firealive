// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Legal Hold Format: EML/MIME (RFC 5322 mbox) (R3l C40)
//
// Emits a legal-hold slice set as a stream of RFC 5322 messages in mbox
// format. Consumed by:
//
//   - Mozilla Thunderbird (.mbox is its native folder storage)
//   - Apple Mail (Import from mbox file)
//   - mutt, alpine, claws-mail (Unix mail clients)
//   - All major e-discovery platforms: Relativity, Concordance, Logikcull,
//     Everlaw, DISCO, Reveal (mbox ingest is a standard pipeline)
//   - Custom litigation-tech tooling that parses mbox via Python's mailbox
//     module, Go's net/mail, Ruby's mail gem, etc.
//
// MBOX FORMAT
//
// Multiple RFC 5322 messages concatenated, each preceded by a "From " line
// (literal "From " — note trailing space — NOT a header). Format:
//
//   From <envelope-sender> <asctime-timestamp>
//   <RFC 5322 headers>
//   <empty line>
//   <body>
//   <empty line>
//   From <envelope-sender> <asctime-timestamp>
//   ...
//
// The asctime timestamp is "Day Mon DD HH:MM:SS YYYY" (e.g., "Thu May 15
// 14:30:00 2026") — a quirk of mbox that distinguishes it from the RFC
// 5322 Date: header format. Standardized by Unix mail spool conventions.
//
// AUDIT-EVENT-TO-MESSAGE MAPPING
//
// Each audit event becomes one RFC 5322 multipart/mixed message:
//
//   Date:         RFC 5322 datetime derived from the event timestamp
//   From:         "FireAlive Audit <audit@firealive.local>" (synthetic)
//   To:           "Legal Hold <legal-hold@firealive.local>" (synthetic)
//   Subject:      "[<slice>] <event_type> by <user>" (or similar; truncated
//                 to fit 78-char SHOULD limit)
//   Message-ID:   <LH-<slice>-<id>@firealive.local>
//   MIME-Version: 1.0
//   Content-Type: multipart/mixed; boundary="..."
//   X-FireAlive-Slice:               <slice id>
//   X-FireAlive-EventID:             <original DB id>
//   X-FireAlive-OriginalTimestamp:   ISO 8601 normalized timestamp
//   X-FireAlive-CanonicalSHA256:     SHA-256 hex of canonical JSON
//
//   --boundary
//   Content-Type: text/plain; charset="utf-8"
//   Content-Transfer-Encoding: 8bit
//
//   <human-readable summary of the event>
//
//   --boundary
//   Content-Type: application/json; name="canonical.json"
//   Content-Disposition: attachment; filename="canonical.json"
//   Content-Transfer-Encoding: base64
//
//   <base64-wrapped canonical JSON>
//
//   --boundary--
//
// CASE CONTEXT
//
// Per the C38 manifest design, case_id lives in manifest.json (which
// travels alongside this format in the archive). Individual EML records
// do NOT carry case_id in headers. The manifest is the authoritative
// case-context source; messages are slice records. This keeps the
// serializer signature consistent with forensic-format serializers
// (serialize(slices) -> Buffer) without breaking the orchestrator
// contract.
//
// LINE WRAPPING + ENCODING
//
// RFC 5322 specifies lines SHOULD be ≤78 chars and MUST be ≤998. For our
// headers:
//   - Subject is truncated to ~70 chars + "…" if longer
//   - X-FireAlive-* values are ASCII (event ids, slice ids, hash hex) so
//     they don't need encoding
//   - Body text is UTF-8 with 8bit Content-Transfer-Encoding
//   - Canonical JSON attachment is always base64 (binary-safe)
//
// Non-ASCII chars in Subject are stripped (synthetic Subject, not
// user-authored). For body content, UTF-8 8bit is used; modern mail
// parsers accept this. Receiving platforms that strict-parse against
// 7-bit ASCII can re-encode on ingest.
//
// LINE ENDINGS
//
// RFC 5322 requires CRLF. mbox parsers accept either CRLF or LF; this
// implementation emits CRLF for spec compliance.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');
const { canonicalSerialize, sliceSha256 } = require('../audit-export-shared');

const FORMAT_ID = 'eml-mime';
const FILE_EXTENSION = '.mbox';
const CRLF = '\r\n';
const SYNTHETIC_FROM = 'FireAlive Audit <audit@firealive.local>';
const SYNTHETIC_FROM_ENVELOPE = 'audit@firealive.local';
const SYNTHETIC_TO = 'Legal Hold <legal-hold@firealive.local>';
const FIREALIVE_DOMAIN = 'firealive.local';
const SUBJECT_MAX_LEN = 70;
const BASE64_WRAP_WIDTH = 76; // RFC 2045 §6.8 recommends ≤76 chars

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTH_NAMES = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// ── Date formatting ───────────────────────────────────────────────────────

function pad2(n) {
  return n < 10 ? '0' + n : String(n);
}

function parseSourceTimestamp(raw) {
  if (raw == null) return null;
  const s = String(raw).trim();
  if (!s) return null;
  // 'YYYY-MM-DD HH:MM:SS' → treat as UTC
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) {
    return new Date(s.replace(' ', 'T') + 'Z');
  }
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function formatRfc5322Date(d) {
  // "Day, DD Mon YYYY HH:MM:SS +0000"
  if (!d || isNaN(d.getTime())) return '';
  return DAY_NAMES[d.getUTCDay()] + ', ' +
         pad2(d.getUTCDate()) + ' ' + MONTH_NAMES[d.getUTCMonth()] + ' ' + d.getUTCFullYear() + ' ' +
         pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds()) +
         ' +0000';
}

function formatAsctime(d) {
  // "Day Mon DD HH:MM:SS YYYY" — mbox "From " line timestamp format
  if (!d || isNaN(d.getTime())) d = new Date();
  return DAY_NAMES[d.getUTCDay()] + ' ' + MONTH_NAMES[d.getUTCMonth()] + ' ' +
         pad2(d.getUTCDate()) + ' ' +
         pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds()) + ' ' +
         d.getUTCFullYear();
}

function formatIsoTimestamp(d) {
  if (!d || isNaN(d.getTime())) return '';
  return d.toISOString();
}

// ── Header sanitization ───────────────────────────────────────────────────

function sanitizeSubject(s) {
  // Strip non-ASCII, control chars, line breaks; truncate to SUBJECT_MAX_LEN.
  if (s == null) return '';
  const cleaned = String(s).replace(/[\x00-\x1F\x7F-\uFFFF]/g, '').trim();
  return cleaned.length > SUBJECT_MAX_LEN
    ? cleaned.substring(0, SUBJECT_MAX_LEN - 3) + '...'
    : cleaned;
}

function sanitizeHeaderValue(s) {
  // For X-* extension headers: strip ASCII control chars + CRLF (header
  // injection defense), keep the rest. Preserves hex hash chars, slice
  // ids, timestamps.
  if (s == null) return '';
  return String(s).replace(/[\x00-\x1F\x7F]/g, '');
}

function escapeMboxFromLine(bodyLine) {
  // RFC 4155 (mbox): lines starting with literal "From " inside a message
  // body must be escaped (prefixed with ">") to avoid being misparsed as
  // a new message separator. Standard mbox quoting convention.
  if (bodyLine.startsWith('From ')) return '>' + bodyLine;
  return bodyLine;
}

// ── Base64 line-wrapping ──────────────────────────────────────────────────

function wrapBase64(buf, width) {
  const b64 = buf.toString('base64');
  const lines = [];
  for (let i = 0; i < b64.length; i += width) {
    lines.push(b64.substring(i, i + width));
  }
  return lines.join(CRLF);
}

// ── Subject derivation per slice ──────────────────────────────────────────

function deriveSubject(sliceId, row) {
  switch (sliceId) {
    case 'audit_log':
      return '[audit_log] ' + (row.event_type || '?') + (row.user_id ? ' by ' + row.user_id : '');
    case 'backup_chain':
      return '[backup_chain] ' + (row.event_type || '?') + (row.backup_id ? ' for ' + row.backup_id : '');
    case 'authentication_logs':
      return '[auth] ' + (row.action || '?') + (row.user ? ' by ' + row.user : '');
    case 'user_access_logs':
      return '[session] SESSION_OPENED' + (row.user_id ? ' by ' + row.user_id : '');
    case 'incident_records':
      return '[incident] ' + (row.event_type || '?');
    default:
      return '[' + sliceId + '] event';
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

// ── Human-readable summary body ───────────────────────────────────────────

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
  lines.push('The full canonical JSON representation of this event is');
  lines.push('attached as canonical.json. The X-FireAlive-CanonicalSHA256');
  lines.push('header records the SHA-256 of the canonical bytes — recipients');
  lines.push('can verify the attachment is unmodified by re-hashing.');
  return lines.map(escapeMboxFromLine).join(CRLF);
}

// ── Message builder ───────────────────────────────────────────────────────

function buildMessage(sliceId, row) {
  const id = row.id != null ? row.id : '';
  const rawTimestamp = deriveTimestamp(sliceId, row);
  const date = parseSourceTimestamp(rawTimestamp);
  const isoTimestamp = formatIsoTimestamp(date);
  const subject = sanitizeSubject(deriveSubject(sliceId, row));
  const messageId = '<LH-' + sliceId + '-' + id + '@' + FIREALIVE_DOMAIN + '>';
  const canonicalBytes = canonicalSerialize(row);
  const sha256Hex = sliceSha256(canonicalBytes);
  // Boundary uses a fresh random hex string per message to guarantee no
  // collision with any byte sequence in the body. 32 hex chars = 128
  // bits of entropy — astronomically unlikely to match real content.
  const boundary = 'fa-' + crypto.randomBytes(16).toString('hex');

  // mbox "From " separator
  const mboxFrom = 'From ' + SYNTHETIC_FROM_ENVELOPE + ' ' + formatAsctime(date);

  // RFC 5322 headers
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

  // multipart/mixed body
  const textBody = buildTextSummary(sliceId, row, isoTimestamp);
  const jsonBody = wrapBase64(canonicalBytes, BASE64_WRAP_WIDTH);

  const bodyLines = [
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
  ];

  return mboxFrom + CRLF + headers.join(CRLF) + CRLF + bodyLines.join(CRLF);
}

// ── Slice ordering ────────────────────────────────────────────────────────
//
// Emit slices in stable, predictable order so the output is deterministic
// across runs given the same input.

const SLICE_ORDER = ['audit_log', 'backup_chain', 'authentication_logs', 'user_access_logs', 'incident_records'];

// ── Main serializer ───────────────────────────────────────────────────────

function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('eml-mime: slices object required');
  }

  const messages = [];
  for (const sliceId of SLICE_ORDER) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    for (const row of rows) {
      messages.push(buildMessage(sliceId, row));
    }
  }

  // Each message is fully self-contained; concatenate with a CRLF between.
  // Trailing CRLF after the final message is standard mbox convention.
  return Buffer.from(messages.join(CRLF) + (messages.length > 0 ? CRLF : ''), 'utf-8');
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: false,
  serialize,
  // Internal helpers exposed for unit tests
  CRLF,
  SYNTHETIC_FROM,
  SYNTHETIC_TO,
  FIREALIVE_DOMAIN,
  parseSourceTimestamp,
  formatRfc5322Date,
  formatAsctime,
  formatIsoTimestamp,
  sanitizeSubject,
  sanitizeHeaderValue,
  escapeMboxFromLine,
  wrapBase64,
  deriveSubject,
  deriveTimestamp,
  buildTextSummary,
  buildMessage,
  SLICE_ORDER,
};

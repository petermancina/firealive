// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Legal Hold Format: PDF with Bates Numbering (R3l C45 pt1)
//
// Emits a legal-hold slice set as a single multi-page PDF 1.4 document with
// each event rendered as one page, Bates-numbered for legal citation in
// the footer ("FIREALIVE_LH_000001" format). Consumed by:
//
//   - Any PDF reader: Adobe Acrobat, Preview, browsers, Foxit, Sumatra
//   - Every e-discovery review platform with native PDF import
//   - Legal counsel reviewing locally without specialized tooling
//   - Court filings where Bates-numbered pages must be cited unambiguously
//
// WHY BATES NUMBERING
//
// Bates numbering is the standardized legal-discovery practice of marking
// each page of a production with a unique, sequential identifier. Allows
// opposing counsel and the court to reference specific pages without
// ambiguity ("see Plaintiff's Exhibit 4 at FIREALIVE_LH_000847"). Without
// Bates numbers, large productions become impossible to discuss precisely
// in depositions, motions, or at trial.
//
// FORMAT
//
// PDF 1.4 (the lowest version with full Unicode text support; readable
// by every PDF tool from 2001 onward). Single multi-page document, one
// page per event. Page layout:
//
//   ┌─────────────────────────────────────────────────────┐
//   │  Title bar (event slice + event type)               │
//   │                                                     │
//   │  Field: value                                       │
//   │  Field: value                                       │
//   │  ...                                                │
//   │                                                     │
//   │  Canonical SHA-256: <hex>                           │
//   │                                                     │
//   │                                                     │
//   │                                FIREALIVE_LH_000001  │
//   └─────────────────────────────────────────────────────┘
//
// Standard letter-size page (612×792 pt at 72 DPI). 1-inch (72pt) margins.
// Helvetica throughout — a standard PDF base font, no embedding required.
//
// MINIMAL PDF WRITER
//
// Pure JavaScript, no external dependencies. Implements the subset of PDF
// 1.4 needed for text-only output:
//
//   - PDF object syntax (numbered indirect objects)
//   - Text content streams (BT/ET, Tf, Td, Tj operators)
//   - xref table (cross-reference table mapping object IDs to byte offsets)
//   - Trailer with /Root reference and /Size
//   - startxref pointer
//   - %%EOF terminator
//
// PDF text strings use parentheses as delimiters; parens and backslashes
// inside content must be escaped with backslash. escapePdfString() handles
// both, plus stripping non-ASCII (Helvetica is a single-byte WinAnsi
// encoding; Unicode would require CIDFont + ToUnicode CMap, far beyond
// scope here).
//
// CHAIN OF INTEGRITY
//
// Each rendered page displays its canonical SHA-256 hex hash near the
// bottom of the content area. A receiver can cross-reference this hash
// against the archive manifest from C38 — same value, same byte source.
// The Bates number is the human-citable identifier; the SHA-256 is the
// cryptographic identifier; both appear on every page.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const { canonicalSerialize, sliceSha256 } = require('../audit-export-shared');

const FORMAT_ID = 'pdf-bates';
const FILE_EXTENSION = '.pdf';
const LF = '\n';

// US Letter page dimensions in PDF points (1 pt = 1/72 inch)
const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
const MARGIN = 72;
const TITLE_SIZE = 14;
const BODY_SIZE = 10;
const FOOTER_SIZE = 9;
const LINE_HEIGHT = 13;
const BATES_PREFIX = 'FIREALIVE_LH_';
const BATES_WIDTH = 6;

const SLICE_ORDER = ['audit_log', 'backup_chain', 'authentication_logs', 'user_access_logs', 'incident_records'];
const SLICE_LABEL = {
  audit_log: 'Audit Log',
  backup_chain: 'Backup Chain',
  authentication_logs: 'Authentication Log',
  user_access_logs: 'User Session',
  incident_records: 'Incident Record',
};

// ── PDF string escaping ───────────────────────────────────────────────────

function escapePdfString(s) {
  // PDF strings: parens are delimiters, backslash is escape. Non-ASCII
  // stripped because Helvetica uses WinAnsi single-byte encoding;
  // displaying Unicode would require CIDFont machinery beyond this scope.
  if (s == null) return '';
  return String(s)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\uFFFF]/g, '?')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

// ── Bates number formatter ────────────────────────────────────────────────

function formatBates(seq) {
  return BATES_PREFIX + String(seq).padStart(BATES_WIDTH, '0');
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

function formatIsoTimestamp(d) {
  if (!d || isNaN(d.getTime())) return '';
  return d.toISOString();
}

// ── Slice-specific page content ──────────────────────────────────────────

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

function buildPageFields(sliceId, row, isoTimestamp) {
  const fields = [];
  fields.push(['Slice', sliceId]);
  fields.push(['Original ID', row.id != null ? String(row.id) : '']);
  if (isoTimestamp) fields.push(['Timestamp', isoTimestamp]);
  if (row.event_type) fields.push(['Event Type', row.event_type]);
  if (row.action) fields.push(['Action', row.action]);
  if (row.user_id) fields.push(['User ID', row.user_id]);
  if (row.user) fields.push(['Username', row.user]);
  if (row.ip_address) fields.push(['IP Address', row.ip_address]);
  if (row.ip) fields.push(['IP Address', row.ip]);
  if (row.method) fields.push(['Auth Method', row.method]);
  if (row.user_agent) fields.push(['User Agent', row.user_agent]);
  if (row.detail) fields.push(['Detail', row.detail]);
  if (row.reason) fields.push(['Reason', row.reason]);
  if (row.this_hash) fields.push(['Chain Hash', row.this_hash]);
  if (row.prev_hash) fields.push(['Previous Hash', row.prev_hash]);
  if (row.signing_key_id) fields.push(['Signing Key', row.signing_key_id]);
  if (row.backup_id) fields.push(['Backup ID', row.backup_id]);
  return fields;
}

// ── Page content stream builder ──────────────────────────────────────────

function buildPageContentStream(sliceId, row, batesNumber, sha256Hex) {
  const isoTimestamp = formatIsoTimestamp(parseSourceTimestamp(deriveTimestamp(sliceId, row)));
  const fields = buildPageFields(sliceId, row, isoTimestamp);
  const title = SLICE_LABEL[sliceId] || sliceId;

  // PDF content stream operators. Coordinate origin is bottom-left.
  // Title at top, fields stack downward, footer at bottom.
  const ops = [];
  ops.push('BT');

  // Title (top of page, large bold-ish via larger size)
  ops.push('/F1 ' + TITLE_SIZE + ' Tf');
  ops.push(MARGIN + ' ' + (PAGE_HEIGHT - MARGIN) + ' Td');
  ops.push('(' + escapePdfString('FireAlive Legal Hold - ' + title) + ') Tj');

  // Body — fields rendered as "Label: value" lines below the title
  ops.push('/F1 ' + BODY_SIZE + ' Tf');
  // Move down 1.5 line heights from title baseline to start of body
  ops.push('0 ' + (-LINE_HEIGHT * 2) + ' Td');
  for (let i = 0; i < fields.length; i++) {
    if (i > 0) ops.push('0 ' + (-LINE_HEIGHT) + ' Td');
    const line = fields[i][0] + ': ' + truncateForLine(fields[i][1], 80);
    ops.push('(' + escapePdfString(line) + ') Tj');
  }

  // SHA-256 line (a couple lines below the last field)
  ops.push('0 ' + (-LINE_HEIGHT * 2) + ' Td');
  ops.push('(' + escapePdfString('Canonical SHA-256: ' + sha256Hex) + ') Tj');

  ops.push('ET');

  // Footer: Bates number right-aligned at the bottom of the page.
  // Approximate width per character at 9pt Helvetica: ~5pt. Compute
  // approximate text width to position right-aligned.
  ops.push('BT');
  ops.push('/F1 ' + FOOTER_SIZE + ' Tf');
  const batesWidth = batesNumber.length * 5;
  const footerX = PAGE_WIDTH - MARGIN - batesWidth;
  const footerY = MARGIN / 2;
  ops.push(footerX + ' ' + footerY + ' Td');
  ops.push('(' + escapePdfString(batesNumber) + ') Tj');
  ops.push('ET');

  return ops.join(LF);
}

function truncateForLine(value, maxLen) {
  if (value == null) return '';
  const s = String(value);
  if (s.length <= maxLen) return s;
  return s.substring(0, maxLen - 3) + '...';
}

// ── PDF document builder ──────────────────────────────────────────────────

function buildPdfDocument(pages) {
  // pages: [{ contentStream: string }, ...]
  //
  // Object layout:
  //   1: Catalog
  //   2: Pages root
  //   3: Font (Helvetica)
  //   For each page i (zero-based):
  //     4 + 2*i: Page object
  //     5 + 2*i: Page content stream
  //
  // Build all object bodies first, then assemble the byte buffer while
  // tracking xref offsets.

  const objects = [];

  // Object 1: Catalog
  objects.push({
    id: 1,
    body: '<< /Type /Catalog /Pages 2 0 R >>',
  });

  // Object 2: Pages root — fill in /Kids and /Count after we know page IDs
  const pageObjIds = [];
  for (let i = 0; i < pages.length; i++) {
    pageObjIds.push(4 + 2 * i);
  }
  objects.push({
    id: 2,
    body: '<< /Type /Pages /Kids [' + pageObjIds.map((id) => id + ' 0 R').join(' ') + '] /Count ' + pages.length + ' >>',
  });

  // Object 3: Font
  objects.push({
    id: 3,
    body: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
  });

  // Object 4..: Page + Content stream pairs
  for (let i = 0; i < pages.length; i++) {
    const pageId = 4 + 2 * i;
    const contentId = 5 + 2 * i;
    const cs = pages[i].contentStream;
    const csBytes = Buffer.from(cs, 'binary');
    objects.push({
      id: pageId,
      body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' + PAGE_WIDTH + ' ' + PAGE_HEIGHT + '] /Contents ' + contentId + ' 0 R /Resources << /Font << /F1 3 0 R >> >> >>',
    });
    objects.push({
      id: contentId,
      body: '<< /Length ' + csBytes.length + ' >>' + LF + 'stream' + LF + cs + LF + 'endstream',
    });
  }

  // Assemble bytes with xref tracking
  const parts = [];
  const offsets = {};
  let offset = 0;

  function push(text) {
    const b = Buffer.from(text, 'binary');
    parts.push(b);
    offset += b.length;
  }

  // Header — PDF 1.4 + binary marker (4 high-bit bytes signal binary file
  // to viewers / FTP clients that might otherwise mangle line endings)
  push('%PDF-1.4' + LF);
  push('%\xE2\xE3\xCF\xD3' + LF);

  // Object bodies
  for (const obj of objects) {
    offsets[obj.id] = offset;
    push(obj.id + ' 0 obj' + LF + obj.body + LF + 'endobj' + LF);
  }

  // xref table
  const xrefOffset = offset;
  const maxId = Math.max(...objects.map((o) => o.id));
  const entries = [];
  // Free object 0
  entries.push('0000000000 65535 f ');
  for (let id = 1; id <= maxId; id++) {
    const off = offsets[id] != null ? offsets[id] : 0;
    entries.push(String(off).padStart(10, '0') + ' 00000 n ');
  }
  push('xref' + LF);
  push('0 ' + (maxId + 1) + LF);
  push(entries.join(LF) + LF);

  // Trailer
  push('trailer' + LF);
  push('<< /Size ' + (maxId + 1) + ' /Root 1 0 R >>' + LF);
  push('startxref' + LF);
  push(xrefOffset + LF);
  push('%%EOF' + LF);

  return Buffer.concat(parts);
}

// ── Main serializer ───────────────────────────────────────────────────────

function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('pdf-bates: slices object required');
  }

  // Assemble pages in stable slice order. Bates counter is sequential
  // across the whole document — every page gets a unique number.
  const pages = [];
  let batesSeq = 1;

  for (const sliceId of SLICE_ORDER) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    for (const row of rows) {
      const canonicalBytes = canonicalSerialize(row);
      const sha256Hex = sliceSha256(canonicalBytes);
      const batesNumber = formatBates(batesSeq);
      const cs = buildPageContentStream(sliceId, row, batesNumber, sha256Hex);
      pages.push({ contentStream: cs, batesNumber, sha256Hex });
      batesSeq++;
    }
  }

  // Empty production: still emit a valid one-page PDF with a notice. Some
  // discovery pipelines reject 0-page documents.
  if (pages.length === 0) {
    const notice = [
      'BT',
      '/F1 ' + TITLE_SIZE + ' Tf',
      MARGIN + ' ' + (PAGE_HEIGHT - MARGIN) + ' Td',
      '(' + escapePdfString('FireAlive Legal Hold - Empty Production') + ') Tj',
      '/F1 ' + BODY_SIZE + ' Tf',
      '0 ' + (-LINE_HEIGHT * 2) + ' Td',
      '(' + escapePdfString('No events matched the hold criteria.') + ') Tj',
      'ET',
    ].join(LF);
    pages.push({ contentStream: notice, batesNumber: formatBates(1), sha256Hex: '' });
  }

  return buildPdfDocument(pages);
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: false,
  serialize,
  // Internal helpers exposed for unit tests
  PAGE_WIDTH,
  PAGE_HEIGHT,
  MARGIN,
  BATES_PREFIX,
  BATES_WIDTH,
  SLICE_ORDER,
  SLICE_LABEL,
  escapePdfString,
  formatBates,
  parseSourceTimestamp,
  formatIsoTimestamp,
  deriveTimestamp,
  buildPageFields,
  buildPageContentStream,
  buildPdfDocument,
  truncateForLine,
};

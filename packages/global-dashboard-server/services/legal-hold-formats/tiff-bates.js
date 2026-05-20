// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Legal Hold Format: TIFF with Bates Load File (R3l C45 pt2)
//
// Emits a legal-hold slice set as a ZIP archive containing one TIFF file
// per event plus an Opticon (OPT) load file linking Bates numbers to
// events. The TIFFs themselves are minimal — letter-size blank bilevel
// pages with the Bates number embedded in the ImageDescription tag (270)
// — and serve as format-compatibility placeholders for TIFF-based review
// pipelines. The OPT load file is the primary metadata artifact that
// receivers use to cross-reference Bates ranges to events. Consumed by:
//
//   - Concordance, Relativity, Reveal (TIFF + OPT is a first-class import
//     path alongside DAT/LFP/native bundles)
//   - iCONECT, Ringtail, Summation (legacy TIFF-imaged review platforms)
//   - Bates-stamping pipelines that ingest TIFF + load file then re-stamp
//     with custom Bates ranges (the imaging-house workflow)
//
// WHY MINIMAL TIFF CONTENT
//
// In a real document production, TIFFs would contain rendered images of
// the source documents — emails, contracts, spreadsheets, etc. — with
// Bates numbers stamped on each page by a document-conversion pipeline.
// For audit-event holds there are no source documents; the canonical JSON
// IS the evidence. Producing TIFFs that visually represent JSON content
// would require a font-rendering pipeline (multi-thousand-line scope, plus
// significant bitmap font data).
//
// The pragmatic litigation-grade design: produce real TIFF files that
// satisfy "TIFF-imaging" requirements for ingest compatibility, but keep
// their content minimal (blank letter-size pages). The Bates number is
// embedded in the ImageDescription metadata tag, which Concordance/
// Relativity surface as a queryable field. The OPT load file pairs Bates
// numbers to events with the FA_CANONICALSHA256 verifiable cross-link.
//
// For human-readable rendered output, the pdf-bates serializer (paired
// in the same C45 commit) produces actual readable PDF pages. TIFFs are
// the format-compatibility companion; PDFs are the content.
//
// TIFF FORMAT — Minimal 6.0 Bilevel
//
//   8-byte header:
//     0-1: II (little-endian byte order marker, 0x4949)
//     2-3: 42 (TIFF magic number, little-endian)
//     4-7: offset to first IFD
//
//   IFD (Image File Directory):
//     0-1: number of tag entries (count)
//     For each tag (12 bytes):
//       0-1: tag id
//       2-3: data type
//       4-7: count of values
//       8-11: value or offset to value
//     last 4 bytes: offset to next IFD (0 = end)
//
// Tags emitted:
//   256 (ImageWidth)              SHORT  width in pixels
//   257 (ImageLength)             SHORT  height in pixels
//   258 (BitsPerSample)           SHORT  1 (bilevel)
//   259 (Compression)             SHORT  1 (uncompressed)
//   262 (PhotometricInterpretation) SHORT  1 (BlackIsZero)
//   270 (ImageDescription)        ASCII  Bates number + event metadata
//   273 (StripOffsets)            LONG   offset to image data
//   277 (SamplesPerPixel)         SHORT  1
//   278 (RowsPerStrip)            SHORT  height (single strip)
//   279 (StripByteCounts)         LONG   image data byte count
//   282 (XResolution)             RATIONAL  72/1
//   283 (YResolution)             RATIONAL  72/1
//   296 (ResolutionUnit)          SHORT  2 (inches)
//
// Image data: bilevel white (all 0x00 bytes since BlackIsZero) — letter-
// size page at 72 DPI is 612×792 pixels = ~60KB per page uncompressed.
// Acceptable for the placeholder use case.
//
// OPT (Opticon) LOAD FILE
//
//   imageKey,volume,fullPath,documentBreak,folderBreak,boxBreak,pageCount
//
// Plus a paired index.csv with Bates-to-event mapping including
// FA_CANONICALSHA256 for chain-of-integrity cross-reference.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const { canonicalSerialize, sliceSha256 } = require('../audit-export-shared');
const { ZipFile } = require('./pst');

const FORMAT_ID = 'tiff-bates';
const FILE_EXTENSION = '.zip';
const ROW_SEP = '\r\n';

const PAGE_WIDTH_PX = 612;   // 8.5" at 72 DPI
const PAGE_HEIGHT_PX = 792;  // 11" at 72 DPI
const RESOLUTION_DPI = 72;
const BATES_PREFIX = 'FIREALIVE_LH_';
const BATES_WIDTH = 6;
const VOLUME = 'VOL001';
const IMAGES_DIR = 'IMAGES';

const SLICE_ORDER = ['audit_log', 'backup_chain', 'authentication_logs', 'user_access_logs', 'incident_records'];

// ── TIFF tag constants ────────────────────────────────────────────────────

const TAG_IMAGE_WIDTH = 256;
const TAG_IMAGE_LENGTH = 257;
const TAG_BITS_PER_SAMPLE = 258;
const TAG_COMPRESSION = 259;
const TAG_PHOTOMETRIC = 262;
const TAG_IMAGE_DESCRIPTION = 270;
const TAG_STRIP_OFFSETS = 273;
const TAG_SAMPLES_PER_PIXEL = 277;
const TAG_ROWS_PER_STRIP = 278;
const TAG_STRIP_BYTE_COUNTS = 279;
const TAG_X_RESOLUTION = 282;
const TAG_Y_RESOLUTION = 283;
const TAG_RESOLUTION_UNIT = 296;

const TYPE_BYTE = 1;
const TYPE_ASCII = 2;
const TYPE_SHORT = 3;
const TYPE_LONG = 4;
const TYPE_RATIONAL = 5;

// ── Bates number formatter ────────────────────────────────────────────────

function formatBates(seq) {
  return BATES_PREFIX + String(seq).padStart(BATES_WIDTH, '0');
}

// ── Minimal TIFF 6.0 builder ──────────────────────────────────────────────
//
// Produces a valid bilevel single-strip TIFF with the Bates number stored
// in the ImageDescription tag. Layout in file:
//
//   [Header: 8 bytes]
//   [IFD: 2 + 12*tagCount + 4 bytes]
//   [Tag value blocks (ASCII, RATIONAL — those that don't fit in 4 bytes)]
//   [Image data: width*height/8 bytes (bilevel white)]

function buildTiff(imageDescription) {
  // Bilevel image: 1 bit per pixel. Bytes per row = ceil(width / 8).
  const bytesPerRow = Math.ceil(PAGE_WIDTH_PX / 8);
  const imageData = Buffer.alloc(bytesPerRow * PAGE_HEIGHT_PX, 0x00); // all zeros = white (BlackIsZero=1)

  // ASCII tag values are null-terminated and stored in the tag value
  // block when length > 4. Compute the description's NUL-terminated byte
  // length and reserve space.
  const description = Buffer.from(imageDescription + '\x00', 'ascii');

  // Rationals are pairs of LONGs (8 bytes each) stored outside the IFD.
  // We need two: XResolution and YResolution (both 72/1).
  const RATIONAL_SIZE = 8;
  const xResRational = Buffer.alloc(RATIONAL_SIZE);
  xResRational.writeUInt32LE(RESOLUTION_DPI, 0);
  xResRational.writeUInt32LE(1, 4);
  const yResRational = Buffer.alloc(RATIONAL_SIZE);
  yResRational.writeUInt32LE(RESOLUTION_DPI, 0);
  yResRational.writeUInt32LE(1, 4);

  // Tag layout planning:
  //   13 tags in the IFD
  //   IFD size = 2 (count) + 13*12 (tags) + 4 (next ifd) = 162 bytes
  //   Header is 8 bytes
  //   First IFD starts at offset 8
  //   External value blocks come after the IFD
  //     desc block at offset 8 + 162 = 170 (length: description.length, may need padding)
  //     xres block after desc
  //     yres block after xres
  //   Image data comes after all value blocks

  const tagCount = 13;
  const headerSize = 8;
  const ifdSize = 2 + tagCount * 12 + 4;
  const headerAndIfdSize = headerSize + ifdSize;

  // Pad description to even byte boundary (TIFF spec recommends word alignment for external values)
  const descPadded = description.length % 2 === 0 ? description : Buffer.concat([description, Buffer.from([0])]);
  const descOffset = headerAndIfdSize;
  const xResOffset = descOffset + descPadded.length;
  const yResOffset = xResOffset + RATIONAL_SIZE;
  const imageDataOffset = yResOffset + RATIONAL_SIZE;

  // Header
  const header = Buffer.alloc(headerSize);
  header.writeUInt16LE(0x4949, 0);  // II
  header.writeUInt16LE(42, 2);      // magic
  header.writeUInt32LE(headerSize, 4); // first IFD at offset 8

  // IFD: write tags in ascending tag ID order (TIFF spec requirement)
  const ifd = Buffer.alloc(ifdSize);
  let pos = 0;
  ifd.writeUInt16LE(tagCount, pos); pos += 2;

  function writeTag(tagId, type, count, valueOrOffset) {
    ifd.writeUInt16LE(tagId, pos); pos += 2;
    ifd.writeUInt16LE(type, pos); pos += 2;
    ifd.writeUInt32LE(count, pos); pos += 4;
    // Value-or-offset is 4 bytes. For SHORT (2 bytes) with count=1, the
    // value is left-justified in the 4-byte field (low 2 bytes). For LONG
    // with count=1, the value occupies all 4 bytes. For ASCII/RATIONAL,
    // this is the offset to the external value block.
    if (type === TYPE_SHORT && count === 1) {
      ifd.writeUInt16LE(valueOrOffset, pos);
      ifd.writeUInt16LE(0, pos + 2);
    } else if (type === TYPE_LONG && count === 1) {
      ifd.writeUInt32LE(valueOrOffset, pos);
    } else {
      ifd.writeUInt32LE(valueOrOffset, pos);
    }
    pos += 4;
  }

  writeTag(TAG_IMAGE_WIDTH, TYPE_SHORT, 1, PAGE_WIDTH_PX);
  writeTag(TAG_IMAGE_LENGTH, TYPE_SHORT, 1, PAGE_HEIGHT_PX);
  writeTag(TAG_BITS_PER_SAMPLE, TYPE_SHORT, 1, 1);
  writeTag(TAG_COMPRESSION, TYPE_SHORT, 1, 1);  // uncompressed
  writeTag(TAG_PHOTOMETRIC, TYPE_SHORT, 1, 1);  // BlackIsZero
  writeTag(TAG_IMAGE_DESCRIPTION, TYPE_ASCII, description.length, descOffset);
  writeTag(TAG_STRIP_OFFSETS, TYPE_LONG, 1, imageDataOffset);
  writeTag(TAG_SAMPLES_PER_PIXEL, TYPE_SHORT, 1, 1);
  writeTag(TAG_ROWS_PER_STRIP, TYPE_SHORT, 1, PAGE_HEIGHT_PX);
  writeTag(TAG_STRIP_BYTE_COUNTS, TYPE_LONG, 1, imageData.length);
  writeTag(TAG_X_RESOLUTION, TYPE_RATIONAL, 1, xResOffset);
  writeTag(TAG_Y_RESOLUTION, TYPE_RATIONAL, 1, yResOffset);
  writeTag(TAG_RESOLUTION_UNIT, TYPE_SHORT, 1, 2);  // inches

  ifd.writeUInt32LE(0, pos); pos += 4;  // next IFD = 0 (end)

  return Buffer.concat([header, ifd, descPadded, xResRational, yResRational, imageData]);
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

function sanitizeAscii(s) {
  // ImageDescription is ASCII per TIFF spec; strip non-ASCII and CR/LF.
  if (s == null) return '';
  return String(s).replace(/[\x00-\x1F\x7F-\uFFFF]/g, '');
}

function buildImageDescription(sliceId, row, batesNumber, sha256Hex) {
  const id = row.id != null ? row.id : '';
  const ts = parseSourceTimestamp(deriveTimestamp(sliceId, row));
  const iso = ts ? ts.toISOString() : '';
  // Embed Bates + event metadata as semicolon-separated key=value pairs —
  // a common convention for ImageDescription metadata that Concordance /
  // Relativity surface as queryable text.
  const parts = [
    'Bates=' + batesNumber,
    'Slice=' + sliceId,
    'EventID=' + String(id),
    'Timestamp=' + iso,
    'CanonicalSHA256=' + sha256Hex,
  ];
  return sanitizeAscii(parts.join(';'));
}

// ── OPT load file builder ─────────────────────────────────────────────────

function sanitizeCsv(s) {
  if (s == null) return '';
  return String(s).replace(/[,\r\n\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

function buildOptFile(records) {
  // imageKey,volume,fullPath,documentBreak,folderBreak,boxBreak,pageCount
  const lines = records.map((r) => {
    const fullPath = IMAGES_DIR + '\\' + r.batesNumber + '.tif';
    return [
      sanitizeCsv(r.batesNumber),
      sanitizeCsv(VOLUME),
      sanitizeCsv(fullPath),
      'Y', '', '', '1',
    ].join(',');
  });
  return Buffer.from(lines.join(ROW_SEP) + (lines.length > 0 ? ROW_SEP : ''), 'utf-8');
}

// ── Bates-to-event index for cross-reference ──────────────────────────────

function buildIndexCsv(records) {
  const header = 'Bates,Slice,EventID,Timestamp,CanonicalSHA256,TiffPath';
  const lines = records.map((r) => {
    return [
      sanitizeCsv(r.batesNumber),
      sanitizeCsv(r.sliceId),
      sanitizeCsv(String(r.eventId)),
      sanitizeCsv(r.isoTimestamp),
      sanitizeCsv(r.sha256),
      sanitizeCsv(IMAGES_DIR + '/' + r.batesNumber + '.tif'),
    ].join(',');
  });
  return Buffer.from(header + ROW_SEP + lines.join(ROW_SEP) + (lines.length > 0 ? ROW_SEP : ''), 'utf-8');
}

// ── README ───────────────────────────────────────────────────────────────

function buildReadme() {
  return [
    'FIREALIVE LEGAL HOLD EXPORT — TIFF with Bates Load File',
    '',
    'CONTENTS',
    '',
    '  IMAGES/<bates>.tif           One TIFF per audit event, named with its',
    '                               Bates number. Each TIFF is a letter-size',
    '                               blank bilevel page with Bates + event',
    '                               metadata embedded in the ImageDescription',
    '                               tag (TIFF tag 270)',
    '  loadfile.opt                 Opticon load file linking Bates numbers',
    '                               to image paths',
    '  index.csv                    Bates-to-event cross-reference with',
    '                               FA_CANONICALSHA256 for integrity check',
    '  README.txt                   This file',
    '',
    'WHY BLANK TIFFS',
    '',
    '  For audit-event holds the canonical JSON IS the evidence (no source',
    '  documents to render). The TIFFs are format-compatibility artifacts',
    '  for TIFF-based review pipelines. The Bates number AND a hash-verifiable',
    '  reference to the canonical JSON are embedded in each TIFF',
    '  ImageDescription tag.',
    '',
    '  For human-readable rendered output, the pdf-bates serializer (paired',
    '  in the same C45 commit) produces actual readable PDF pages with',
    '  Bates numbering. TIFFs are the format-compatibility companion;',
    '  PDFs are the content.',
    '',
    'INSPECTING TIFF METADATA',
    '',
    '  ImageDescription tag (270) embedded as semicolon-separated key=value:',
    '',
    '    Bates=FIREALIVE_LH_000001;Slice=audit_log;EventID=1;Timestamp=...;',
    '    CanonicalSHA256=...',
    '',
    '  ImageMagick:  identify -verbose IMAGES/FIREALIVE_LH_000001.tif',
    '  exiftool:     exiftool IMAGES/FIREALIVE_LH_000001.tif',
    '  Python:       PIL.Image.open(path).tag_v2.get(270)',
    '',
    'IMPORTING INTO REVIEW PLATFORMS',
    '',
    '  Concordance / Relativity:  use loadfile.opt as the image load file.',
    '  Most platforms surface ImageDescription as a queryable field. Pair',
    '  this output with the relativity or concordance load file (separate',
    '  format in the same hold export) for full DAT+OPT review.',
    '',
    'CHAIN OF INTEGRITY',
    '',
    '  index.csv records FA_CANONICALSHA256 per Bates number. The hash is',
    '  the SHA-256 of the canonical JSON of the source event — the same',
    '  hash the json-tarball, relativity, and concordance formats record.',
    '  Cryptographic chain runs: Ed25519 manifest signature → archive slice',
    '  hash → this index.csv → ImageDescription tag in the TIFF.',
    '',
  ].join(ROW_SEP);
}

// ── Main serializer ───────────────────────────────────────────────────────

function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('tiff-bates: slices object required');
  }

  const records = [];
  let batesSeq = 1;

  for (const sliceId of SLICE_ORDER) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    for (const row of rows) {
      const eventId = row.id != null ? row.id : '';
      const canonicalBytes = canonicalSerialize(row);
      const sha256 = sliceSha256(canonicalBytes);
      const batesNumber = formatBates(batesSeq);
      const ts = parseSourceTimestamp(deriveTimestamp(sliceId, row));
      const isoTimestamp = ts ? ts.toISOString() : '';
      records.push({
        batesNumber,
        sliceId,
        eventId,
        isoTimestamp,
        sha256,
      });
      batesSeq++;
    }
  }

  const zip = new ZipFile();
  zip.addFile('README.txt', buildReadme());
  zip.addFile('loadfile.opt', buildOptFile(records));
  zip.addFile('index.csv', buildIndexCsv(records));

  // Generate one TIFF per record
  for (const r of records) {
    const description = buildImageDescription(r.sliceId, { id: r.eventId }, r.batesNumber, r.sha256);
    // Include timestamp in the description too — buildImageDescription
    // pulls it from the row's slice timestamp field, so reconstruct here
    // with a synthetic row that carries the right shape.
    const tiffBytes = buildTiff('Bates=' + r.batesNumber + ';Slice=' + r.sliceId + ';EventID=' + r.eventId + ';Timestamp=' + r.isoTimestamp + ';CanonicalSHA256=' + r.sha256);
    zip.addFile(IMAGES_DIR + '/' + r.batesNumber + '.tif', tiffBytes);
  }

  return zip.toBuffer();
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: false,
  serialize,
  // Internal helpers exposed for unit tests
  PAGE_WIDTH_PX,
  PAGE_HEIGHT_PX,
  RESOLUTION_DPI,
  BATES_PREFIX,
  BATES_WIDTH,
  VOLUME,
  IMAGES_DIR,
  SLICE_ORDER,
  formatBates,
  buildTiff,
  parseSourceTimestamp,
  deriveTimestamp,
  sanitizeAscii,
  sanitizeCsv,
  buildImageDescription,
  buildOptFile,
  buildIndexCsv,
  buildReadme,
};

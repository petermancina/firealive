// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Legal Hold Format: JSON Tarball (R3l C44)
//
// Emits a legal-hold slice set as a gzipped POSIX ustar archive containing
// a top-level manifest.json plus per-slice directories of one canonical
// JSON file per event. The universal-fallback format for tooling that
// doesn't speak EDRM XML, Concordance DAT, Relativity load bundles, or
// any other proprietary e-discovery format. Consumed by:
//
//   - Python scripts: tarfile.open(...) + json.load(...) — stdlib only
//   - Go pipelines: archive/tar + encoding/json — stdlib only
//   - Rust tooling: tar crate + serde_json
//   - Shell scripts: tar xzf + jq
//   - Custom in-house review platforms with their own ingest pipelines
//   - Forensic analysts wanting raw, schema-free evidence access
//   - Compliance teams writing one-off audit verification scripts
//
// Why this format exists
//
// EDRM XML / Concordance DAT / Relativity load files all encode the same
// underlying audit events but with platform-specific conventions
// (DocID vs ControlNumber, thorn qualifiers, multipart boundaries). For a
// receiver who doesn't have a target review platform — say, a small law
// firm without a Relativity license, or an in-house counsel team doing
// preliminary case assessment — those formats add friction. JSON-tarball
// is the lingua franca: an archive structure every modern programming
// language can walk with stdlib, no special-purpose parsers required.
//
// ARCHIVE LAYOUT
//
//   manifest.json
//   audit_log/
//     <padded-id>.json
//     ...
//   backup_chain/
//     <padded-id>.json
//   authentication_logs/
//     <padded-id>.json
//   user_access_logs/
//     <padded-id>.json
//   incident_records/
//     <padded-id>.json
//   README.txt
//
// Each <padded-id>.json contains the canonical JSON of one event — the
// EXACT bytes produced by audit-export-shared's canonicalSerialize(),
// byte-for-byte identical to what's hashed in the manifest. Receivers
// can re-hash any file and compare against the manifest's sha256 entry.
//
// manifest.json STRUCTURE
//
//   {
//     "format": "firealive-legal-hold-json-tarball",
//     "version": "1.0",
//     "generated_at": "<ISO 8601 UTC>",
//     "slices": {
//       "audit_log": {
//         "count": 12,
//         "files": [
//           {"id": "1", "path": "audit_log/000001.json", "sha256": "..."},
//           ...
//         ]
//       },
//       ...
//     }
//   }
//
// TAR FORMAT
//
// POSIX ustar (Unix Standard TAR). Same buildMultiEntryTar implementation
// pattern duplicated from legal-hold-export.js and forensic-export.js —
// kept inline to avoid circular require dependencies (legal-hold-export.js
// tryLoad()s this module; importing back would create a cycle). Future
// cleanup may extract to audit-export-shared.js once a third format
// (likely C45 pdf-bates) also wants it.
//
// Output gzipped via Node's built-in zlib.gzipSync, fileExtension '.tar.gz'.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const zlib = require('zlib');
const { canonicalSerialize, sliceSha256 } = require('../audit-export-shared');

const FORMAT_ID = 'json-tarball';
const FILE_EXTENSION = '.tar.gz';
const TAR_BLOCK_SIZE = 512;
const TAR_MAGIC = 'ustar\0';
const TAR_VERSION = '00';
const LF = '\n';

const SLICE_ORDER = ['audit_log', 'backup_chain', 'authentication_logs', 'user_access_logs', 'incident_records'];

// ── POSIX ustar TAR builder (duplicated from legal-hold-export.js) ────────

function buildTarHeader(filename, payloadSize) {
  if (typeof filename !== 'string' || !filename || filename.length > 100) {
    throw new Error('buildTarHeader: filename must be 1-100 ASCII chars (got "' + filename + '" length ' + (filename ? filename.length : 0) + ')');
  }
  const header = Buffer.alloc(TAR_BLOCK_SIZE);

  const writeOctal = (value, offset, width) => {
    const str = value.toString(8);
    if (str.length > width - 1) {
      throw new Error('buildTarHeader: octal value too large for field');
    }
    header.write(str.padStart(width - 1, '0'), offset, width - 1, 'ascii');
    header[offset + width - 1] = 0;
  };

  header.write(filename, 0, 100, 'ascii');
  writeOctal(0o644, 100, 8);
  writeOctal(0, 108, 8);
  writeOctal(0, 116, 8);
  writeOctal(payloadSize, 124, 12);
  writeOctal(Math.floor(Date.now() / 1000), 136, 12);
  for (let i = 148; i < 156; i++) header[i] = 0x20;
  header[156] = 0x30;
  header.write(TAR_MAGIC, 257, 6, 'binary');
  header.write(TAR_VERSION, 263, 2, 'ascii');

  let checksum = 0;
  for (let i = 0; i < TAR_BLOCK_SIZE; i++) checksum += header[i];
  writeOctal(checksum, 148, 7);
  header[155] = 0x20;
  return header;
}

function buildMultiEntryTar(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error('buildMultiEntryTar: at least one entry required');
  }
  const parts = [];
  for (const entry of entries) {
    if (!entry || typeof entry.name !== 'string' || !Buffer.isBuffer(entry.payload)) {
      throw new Error('buildMultiEntryTar: each entry needs {name: string, payload: Buffer}');
    }
    parts.push(buildTarHeader(entry.name, entry.payload.length));
    parts.push(entry.payload);
    const padding = TAR_BLOCK_SIZE - (entry.payload.length % TAR_BLOCK_SIZE);
    if (padding !== TAR_BLOCK_SIZE) parts.push(Buffer.alloc(padding));
  }
  parts.push(Buffer.alloc(TAR_BLOCK_SIZE * 2));
  return Buffer.concat(parts);
}

// ── ID padding for stable sort order ──────────────────────────────────────

function padEventId(id, totalCount) {
  const width = Math.max(6, String(totalCount).length);
  return String(id).padStart(width, '0');
}

// ── README content ────────────────────────────────────────────────────────

function buildReadme() {
  return [
    'FIREALIVE LEGAL HOLD EXPORT — JSON Tarball',
    '',
    'CONTENTS',
    '',
    'A universal-fallback format for tooling that does not speak EDRM XML,',
    'Concordance DAT, Relativity load files, or any other proprietary',
    'e-discovery format. The archive contains:',
    '',
    '  manifest.json               Top-level index of all events with per-event',
    '                              path and sha256',
    '  <slice>/<padded-id>.json    One canonical JSON file per event',
    '  README.txt                  This file',
    '',
    'EXTRACTION',
    '',
    '  tar xzf json-tarball.tar.gz',
    '',
    'PROGRAMMATIC ACCESS',
    '',
    'Python:',
    '  import tarfile, json',
    '  with tarfile.open("json-tarball.tar.gz") as tf:',
    '      mf = json.load(tf.extractfile("manifest.json"))',
    '      for slice_id, info in mf["slices"].items():',
    '          for f in info["files"]:',
    '              event = json.load(tf.extractfile(f["path"]))',
    '              # process event ...',
    '',
    'Go:',
    '  archive/tar + encoding/json from stdlib',
    '',
    'Shell:',
    '  tar xzf json-tarball.tar.gz',
    '  cat manifest.json | jq ".slices.audit_log.files[]"',
    '',
    'CHAIN OF INTEGRITY',
    '',
    'Every file in manifest.json carries a sha256 field. The corresponding',
    'file in the archive is the canonical JSON whose SHA-256 matches that',
    'value. To verify integrity:',
    '',
    '  1. Read manifest.json',
    '  2. For each file entry, open the referenced path',
    '  3. Compute SHA-256 of the bytes',
    '  4. Compare against the sha256 field (must match exactly)',
    '',
    'This is the same hash recorded in the archive-level manifest signed by',
    'Ed25519 in the parent legal hold export — the cryptographic chain runs:',
    'Ed25519 manifest signature → archive slice hash → this manifest.json',
    'sha256 → individual event file.',
    '',
    'CANONICAL JSON',
    '',
    'Per-event JSON files use RFC 8785 canonical JSON: keys sorted',
    'alphabetically, no whitespace, UTF-8 encoded, deterministic number',
    'representation. The same byte sequence is produced for any logically',
    'identical event, which is what makes the SHA-256 verification work.',
    '',
  ].join(LF);
}

// ── Per-event JSON file path ──────────────────────────────────────────────

function eventFilePath(sliceId, id, totalInSlice) {
  return sliceId + '/' + padEventId(id, totalInSlice) + '.json';
}

// ── Manifest builder ──────────────────────────────────────────────────────

function buildManifest(perSliceFiles) {
  const manifest = {
    format: 'firealive-legal-hold-json-tarball',
    version: '1.0',
    generated_at: new Date().toISOString(),
    slices: {},
  };
  for (const sliceId of SLICE_ORDER) {
    const files = perSliceFiles[sliceId] || [];
    manifest.slices[sliceId] = {
      count: files.length,
      files: files.map((f) => ({ id: f.id, path: f.path, sha256: f.sha256 })),
    };
  }
  // Manifest itself is human-readable pretty-printed JSON (NOT canonical
  // form) — receivers may inspect it directly. The hash-verifiable bytes
  // are the per-event files, not the manifest.
  return Buffer.from(JSON.stringify(manifest, null, 2) + LF, 'utf-8');
}

// ── Main serializer ───────────────────────────────────────────────────────

function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('json-tarball: slices object required');
  }

  // First pass: build per-event canonical bytes + collect manifest entries
  const tarEntries = [];
  const perSliceFiles = {};

  for (const sliceId of SLICE_ORDER) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    perSliceFiles[sliceId] = [];
    for (const row of rows) {
      const id = row.id != null ? row.id : '';
      const canonicalBytes = canonicalSerialize(row);
      const sha256 = sliceSha256(canonicalBytes);
      const path = eventFilePath(sliceId, id, rows.length);
      tarEntries.push({ name: path, payload: canonicalBytes });
      perSliceFiles[sliceId].push({ id: String(id), path, sha256 });
    }
  }

  // manifest.json at the front so receivers find it first when walking
  // the archive linearly
  const manifestBytes = buildManifest(perSliceFiles);
  const readmeBytes = Buffer.from(buildReadme(), 'utf-8');

  // Final entry order: README, manifest, then all event files
  const allEntries = [
    { name: 'README.txt', payload: readmeBytes },
    { name: 'manifest.json', payload: manifestBytes },
    ...tarEntries,
  ];

  const tarBytes = buildMultiEntryTar(allEntries);
  return zlib.gzipSync(tarBytes);
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: false,
  serialize,
  // Internal helpers exposed for unit tests
  SLICE_ORDER,
  buildTarHeader,
  buildMultiEntryTar,
  padEventId,
  eventFilePath,
  buildManifest,
  buildReadme,
};

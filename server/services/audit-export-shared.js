// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Shared Audit Export Utilities (R3l C21)
//
// Pure-function utilities shared by both the forensic-export orchestrator
// (server/services/forensic-export.js, R3l C22) and the legal-hold-export
// orchestrator (server/services/legal-hold-export.js, R3l C38). Three
// responsibilities:
//
//   1. canonicalize() / canonicalSerialize() — Stable JSON representation
//      of any manifest or sub-structure, so the same data hashes and signs
//      identically regardless of the order keys were inserted into the
//      object. The bytes produced by canonicalSerialize() are what get
//      hashed and signed; the same bytes must be reproducible at
//      verification time for the Ed25519 signature to remain valid.
//
//   2. sliceSha256() — SHA-256 of a single export slice (one format file:
//      bodyfile, JSON Lines, CEF, etc.). Returned as a lowercase hex string,
//      stable across platforms and Node versions. Each format serializer
//      (C23-C28) computes the SHA-256 of its output and pushes a slice
//      entry into the manifest so an auditor can verify each component
//      independently of the others.
//
//   3. buildManifestSkeleton() / addSlice() — A normalized starting shape
//      for the manifest, populated from the export request, with empty
//      slices/signing/archive/cosign sections that the orchestrator fills
//      in as the export proceeds. The skeleton's keys and structure are
//      stable across both forensic and legal-hold exports so verification
//      tooling treats them uniformly.
//
// DELIBERATELY SEPARATE FROM backup-manifest.js
//
// backup-manifest.js has a structurally identical canonicalize() function.
// The duplication is intentional: backup integrity and forensic-export
// integrity are distinct cryptographic concerns. A future change to the
// backup canonicalization (e.g., new normalization rule, BigInt handling)
// should NOT silently propagate into the forensic/legal-hold signing chain,
// because that would change what a previously-issued export's manifest
// hashes to and break verification of historical exports. Each subsystem
// owns its own canonicalization contract.
//
// CANONICAL SERIALIZATION CONTRACT
//
// The bytes produced by canonicalSerialize() must be reproducible. Three
// things JSON.stringify alone does not guarantee:
//
//   1. Stable key ordering — JS engines preserve insertion order for
//      string keys, but a manifest assembled in a different code path
//      could insert keys in a different order. canonicalize() sorts keys
//      recursively before serialization.
//
//   2. No insignificant whitespace — JSON.stringify with no indent
//      argument produces compact JSON with no whitespace. Always called
//      without indent here.
//
//   3. UTF-8 byte form — Buffer.from(str, 'utf-8') gives stable bytes
//      across platforms and Node versions. Different encodings (utf-16,
//      latin1) would produce different byte sequences for the same string.
//
// What canonicalize() does NOT handle, because they cannot appear in valid
// export manifests:
//   - Floating-point numbers (timestamps are ISO 8601 strings; counts are
//     integers; never floats)
//   - BigInt (would throw on JSON.stringify; no integer in this codebase
//     exceeds 2^53)
//   - undefined (JSON.stringify silently drops these; all manifest fields
//     should have explicit null or empty-array defaults)
//   - Date objects (ISO 8601 strings explicitly)
//   - Non-string object keys (JSON only supports string keys)
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');

// Bump on incompatible manifest shape changes. Verifiers reject older or
// newer versions explicitly rather than silently accepting them.
const MANIFEST_FORMAT_VERSION = 1;

// Allowed values for the export_type discriminator in the skeleton. The
// orchestrators each pass one of these; anything else throws so a typo
// can't produce a manifest claiming an unsupported export type.
const ALLOWED_EXPORT_TYPES = new Set(['forensic', 'legal_hold']);

/**
 * Recursively sort object keys so the same data produces the same bytes
 * regardless of insertion order. Returns a NEW value; does not mutate the
 * input.
 *
 *   canonicalize({b: 1, a: 2}) -> {a: 2, b: 1}
 *   canonicalize([{b: 1, a: 2}]) -> [{a: 2, b: 1}]
 *   canonicalize(null) -> null
 *   canonicalize('x') -> 'x'
 */
function canonicalize(value) {
  if (value === null) return null;
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(canonicalize);

  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = canonicalize(value[key]);
  }
  return sorted;
}

/**
 * Serialize a manifest (or sub-structure) to canonical JSON bytes. The
 * returned Buffer is what gets signed by the Ed25519 chain key and what
 * gets hashed for the chain entry's this_hash field.
 *
 * Throws if input is null/undefined or non-object.
 *
 * Returns: Buffer (UTF-8 encoding of the canonical JSON string)
 */
function canonicalSerialize(value) {
  if (value === null || value === undefined) {
    throw new Error('canonicalSerialize: input required');
  }
  if (typeof value !== 'object') {
    throw new Error('canonicalSerialize: input must be an object or array');
  }
  const canonical = canonicalize(value);
  const json = JSON.stringify(canonical);
  return Buffer.from(json, 'utf-8');
}

/**
 * Compute the SHA-256 hex digest of an export slice. Accepts Buffer or
 * string; strings are UTF-8 encoded before hashing so the same string
 * produces the same digest regardless of how the caller passed it in.
 *
 *   sliceSha256('hello') === sliceSha256(Buffer.from('hello', 'utf-8'))
 *
 * Returns: lowercase hex string (64 chars for SHA-256)
 */
function sliceSha256(input) {
  if (input === null || input === undefined) {
    throw new Error('sliceSha256: input required');
  }
  const buf = Buffer.isBuffer(input)
    ? input
    : typeof input === 'string'
      ? Buffer.from(input, 'utf-8')
      : null;
  if (buf === null) {
    throw new Error('sliceSha256: input must be Buffer or string');
  }
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * Build the manifest skeleton for an export. The orchestrator (C22 for
 * forensic, C38 for legal hold) fills in the empty fields as the export
 * proceeds:
 *
 *   slices       — populated by addSlice() as each format file is produced
 *   signing      — populated after canonicalSerialize() + Ed25519 sign
 *   archive      — populated after tar.gz creation and archive SHA-256
 *   cosign       — populated if FIREALIVE_FORENSIC_USE_COSIGN=true and
 *                  the cosign binary call succeeded (forensic only;
 *                  always null for legal_hold)
 *
 * opts: {
 *   exportType: 'forensic' | 'legal_hold' (required)
 *   exportId: string (required, matches forensic_exports.id or
 *             legal_hold_exports.id)
 *   requestedByUserId: string (required)
 *   rationale: string | null
 *   timeWindowStart: string | null (ISO 8601)
 *   timeWindowEnd: string | null (ISO 8601)
 *   eventTypeFilter: string | null
 *   outputFormats: string[] (one or more of the supported format ids)
 *   includeAuditLog, includeBackupChain, includeIncidentRecords,
 *     includeAuthenticationLogs, includeUserAccessLogs: bool
 * }
 *
 * Throws if exportType is unsupported or required fields are missing.
 */
function buildManifestSkeleton(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new Error('buildManifestSkeleton: opts object required');
  }
  if (!ALLOWED_EXPORT_TYPES.has(opts.exportType)) {
    throw new Error(
      'buildManifestSkeleton: exportType must be one of: ' +
        Array.from(ALLOWED_EXPORT_TYPES).join(', ')
    );
  }
  if (!opts.exportId || typeof opts.exportId !== 'string') {
    throw new Error('buildManifestSkeleton: exportId (string) required');
  }
  if (!opts.requestedByUserId || typeof opts.requestedByUserId !== 'string') {
    throw new Error(
      'buildManifestSkeleton: requestedByUserId (string) required'
    );
  }

  return {
    format_version: MANIFEST_FORMAT_VERSION,
    export_type: opts.exportType,
    export_id: opts.exportId,
    created_at: new Date().toISOString(),
    requested_by_user_id: opts.requestedByUserId,
    rationale: opts.rationale || null,
    time_window: {
      start: opts.timeWindowStart || null,
      end: opts.timeWindowEnd || null,
    },
    event_type_filter: opts.eventTypeFilter || null,
    output_formats: Array.isArray(opts.outputFormats)
      ? opts.outputFormats.slice()
      : [],
    includes: {
      audit_log: opts.includeAuditLog !== false,
      backup_chain: opts.includeBackupChain !== false,
      incident_records: opts.includeIncidentRecords !== false,
      authentication_logs: opts.includeAuthenticationLogs !== false,
      user_access_logs: opts.includeUserAccessLogs !== false,
    },
    slices: [],
    signing: null,
    archive: null,
    cosign: null,
  };
}

/**
 * Append a slice descriptor to a manifest's slices array. Each slice
 * describes one format file inside the export archive: its filename in
 * the archive, the format identifier, its SHA-256, its size in bytes, and
 * (optionally) its line count for line-oriented formats like JSON Lines
 * and CEF.
 *
 * Mutates the manifest in place. Returns the manifest for chaining.
 *
 * slice: {
 *   name: string (filename in archive, e.g., 'audit.bodyfile')
 *   format: string (format id, e.g., 'sleuth-kit-bodyfile')
 *   sha256: string (lowercase hex, from sliceSha256())
 *   size_bytes: integer
 *   line_count: integer | null (optional; line-oriented formats only)
 * }
 */
function addSlice(manifest, slice) {
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('addSlice: manifest object required');
  }
  if (!slice || typeof slice !== 'object') {
    throw new Error('addSlice: slice object required');
  }
  if (!slice.name || typeof slice.name !== 'string') {
    throw new Error('addSlice: slice.name (string) required');
  }
  if (!slice.format || typeof slice.format !== 'string') {
    throw new Error('addSlice: slice.format (string) required');
  }
  if (!slice.sha256 || typeof slice.sha256 !== 'string') {
    throw new Error('addSlice: slice.sha256 (string) required');
  }
  if (!Number.isInteger(slice.size_bytes) || slice.size_bytes < 0) {
    throw new Error('addSlice: slice.size_bytes (non-negative integer) required');
  }

  if (!Array.isArray(manifest.slices)) manifest.slices = [];
  manifest.slices.push({
    name: slice.name,
    format: slice.format,
    sha256: slice.sha256,
    size_bytes: slice.size_bytes,
    line_count:
      Number.isInteger(slice.line_count) && slice.line_count >= 0
        ? slice.line_count
        : null,
  });
  return manifest;
}

module.exports = {
  MANIFEST_FORMAT_VERSION,
  ALLOWED_EXPORT_TYPES,
  canonicalize,
  canonicalSerialize,
  sliceSha256,
  buildManifestSkeleton,
  addSlice,
};

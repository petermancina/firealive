// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Manifest Module
//
// A v2 backup is a directory containing four files:
//   archive.tar.zst.enc    — encrypted, compressed tar archive of the data
//   wrapped-key.bin        — per-backup AES-256-GCM key wrapped with KEK
//   manifest.json          — cleartext metadata about the backup (this module)
//   manifest.sig           — Ed25519 signature of manifest.json bytes
//
// This module produces and parses manifest.json. It does NOT touch the
// signing keys themselves (that's backup-signing-keys.js) and does NOT
// touch encryption (that's the backup engine in a later commit). It is
// the data-shaping layer between the backup engine and the on-disk file.
//
// CANONICAL SERIALIZATION CONTRACT
//
// The bytes produced by serialize() are what get signed. The same bytes
// must be reproducible at verification time so the signature still
// verifies. Three things JSON.stringify alone does not guarantee:
//
//   1. Stable key ordering — JS engines preserve insertion order for
//      string keys, but a manifest assembled in a different code path
//      could insert keys in a different order. canonicalize() sorts
//      keys recursively before serialization.
//
//   2. No insignificant whitespace — JSON.stringify with no indent
//      argument produces compact JSON with no whitespace. Always
//      called without indent here.
//
//   3. UTF-8 byte form — Buffer.from(str, 'utf-8') gives stable bytes
//      across platforms. Different encodings (utf-16, latin1) would
//      produce different byte sequences for the same string.
//
// What canonicalize() does NOT need to handle, because they cannot
// appear in valid manifests:
//   - Floating-point numbers (we use integer counts and string
//     timestamps; never floats)
//   - BigInt (would throw on JSON.stringify)
//   - undefined (JSON.stringify silently drops these — manifest fields
//     should always have explicit values)
//   - Date objects (we use ISO 8601 strings explicitly)
//   - Non-string object keys (JSON only supports string keys)
// ═══════════════════════════════════════════════════════════════════════════════

// Current manifest format. v2 is unsupported (a 1.0.29-pre-release
// shape that never reached operators); only v3 manifests created on
// 1.0.30+ are valid for verification and restore.
const MANIFEST_FORMAT_VERSION = 3;

const SIGNATURE_FILENAME      = 'manifest.sig';
const ARCHIVE_FILENAME        = 'archive.tar.zst.enc';
const WRAPPED_KEY_FILENAME    = 'wrapped-key.bin';
const MANIFEST_FILENAME       = 'manifest.json';

// Files that the manifest enumerates and hashes. The manifest itself
// and its signature file are NOT in this list — the manifest can't
// hash itself, and the signature file IS the signature of this manifest.
const TRACKED_FILENAMES = [ARCHIVE_FILENAME, WRAPPED_KEY_FILENAME];

const crypto = require('crypto');
// Domain separation for the salted per-backup KEK fingerprint (D-R2-4).
const KEK_FP_DOMAIN = 'fa-backup-kekfp:v1';

// ── Canonical serialization ───────────────────────────────────────────────

/**
 * Recursively sort object keys alphabetically. Arrays preserve order
 * (ordering of items in an array is semantically meaningful — sorting
 * would change the data, not just the encoding). Primitives are
 * returned unchanged.
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
 * Serialize a manifest object to canonical JSON bytes. These bytes are
 * what get signed and what get hashed for the backup_chain entry.
 *
 * Returns: Buffer (UTF-8)
 */
function serialize(manifest) {
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('serialize: manifest must be a non-null object');
  }
  const canonical = canonicalize(manifest);
  const json = JSON.stringify(canonical);
  return Buffer.from(json, 'utf-8');
}

/**
 * Parse manifest bytes back into an object. Strict JSON parsing — any
 * malformed input throws. Caller should run validateStructure() on the
 * result before trusting any field.
 *
 * Accepts Buffer or string.
 */
function parse(manifestBytes) {
  let text;
  if (Buffer.isBuffer(manifestBytes)) {
    text = manifestBytes.toString('utf-8');
  } else if (typeof manifestBytes === 'string') {
    text = manifestBytes;
  } else {
    throw new Error('parse: manifestBytes must be Buffer or string');
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`parse: malformed JSON: ${err.message}`);
  }
}

// ── Manifest construction ────────────────────────────────────────────────

/**
 * Build a manifest object from backup metadata. Caller is responsible
 * for hashing the archive and wrapped-key files first and passing the
 * hashes in via opts.fileHashes.
 *
 * opts:
 *   backupId            (string, required)  — UUID or random hex; the
 *                                              backup directory name
 *                                              suffix
 *   backupType          (string, required)  — 'scheduled' | 'on-demand'
 *                                              | 'snapshot'
 *   createdAt           (string, optional)  — ISO 8601; defaults to now
 *   fileHashes          (object, required)  — { archive: { sizeBytes,
 *                                              sha256 }, wrappedKey:
 *                                              { sizeBytes, sha256 } }
 *   compression         (string, optional)  — 'zstd' | 'gzip'; defaults
 *                                              to 'zstd'
 *   compressionLevel    (number, optional)  — integer compression level;
 *                                              defaults to 3 for zstd
 *   keyWrappingScheme   (string, optional)  — 'env-var' | 'aws-kms' |
 *                                              'azure-key-vault' |
 *                                              'gcp-kms'; defaults to
 *                                              'env-var' (R3d-4 expands
 *                                              this)
 *   kekReference        (string, optional)  — env var name or KMS ARN /
 *                                              key URI; defaults to
 *                                              'TIER1_ENCRYPTION_KEY'
 *   signingKeyId        (number, required)  — id of the
 *                                              backup_signing_keys row
 *                                              that signed this manifest
 *                                              on the originating
 *                                              deployment. Useful for
 *                                              same-deployment audit
 *                                              cross-references; not
 *                                              meaningful across
 *                                              deployments (use
 *                                              fingerprint for that).
 *   signingKeyFingerprint (string, required) — SHA-256 hex (64 chars)
 *                                              of the signer's public
 *                                              key SPKI DER. The v3
 *                                              cross-deployment universal
 *                                              key identifier; verifiers
 *                                              look up keys by this.
 *   sourceFuseCounter   (number, required)  — fuseCounter at creation
 *                                              time; consumed during
 *                                              restore for anti-rollback
 *   sourceSchemaVersion (string, optional)  — system_meta.schema_version
 *                                              at creation time
 *
 * Returns the constructed manifest object (NOT serialized bytes — call
 * serialize() on the result to get bytes for signing).
 */
// A per-backup, non-correlatable fingerprint of the KEK that wrapped this backup's key.
// Salted by backup_id so the same KEK yields a DIFFERENT value in every backup (no stable
// cross-backup identifier), and domain-separated. Written into the manifest at creation, so it
// is covered by manifest.sig (tamper-evident) and never rewritten. It lets a restore confirm
// the target's KEK matches the one this backup was wrapped under -- WITHOUT unwrapping anything
// -- and refuse a foreign-KEK backup before the swap.
function saltedKekFingerprint(kekFingerprintHex, backupId) {
  if (typeof kekFingerprintHex !== 'string' || !/^[0-9a-f]+$/.test(kekFingerprintHex)) {
    throw new Error('saltedKekFingerprint: kekFingerprintHex must be lowercase hex');
  }
  return crypto.createHash('sha256')
    .update(KEK_FP_DOMAIN + '|' + kekFingerprintHex + '|' + String(backupId), 'utf-8')
    .digest('hex');
}

// Does the manifest's kek_fingerprint match the target's KEK fingerprint (recomputed with the
// manifest's OWN backup_id)? Returns true / false, or null for a legacy manifest that has no
// kek_fingerprint (a pre-D-R2-4 backup -- the caller decides how to treat that). Constant-time.
function verifyKekFingerprint(manifest, targetKekFingerprintHex) {
  if (!manifest || typeof manifest !== 'object' || typeof manifest.kek_fingerprint !== 'string') {
    return null;
  }
  const expected = saltedKekFingerprint(targetKekFingerprintHex, manifest.backup_id);
  const a = Buffer.from(manifest.kek_fingerprint, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function buildManifest(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new Error('buildManifest: opts object required');
  }
  for (const required of ['backupId', 'backupType', 'fileHashes', 'signingKeyId', 'signingKeyFingerprint', 'sourceFuseCounter']) {
    if (opts[required] === undefined || opts[required] === null) {
      throw new Error(`buildManifest: opts.${required} required`);
    }
  }
  if (!['scheduled', 'on-demand', 'snapshot'].includes(opts.backupType)) {
    throw new Error(`buildManifest: backupType must be scheduled|on-demand|snapshot, got '${opts.backupType}'`);
  }
  if (!opts.fileHashes.archive || !opts.fileHashes.wrappedKey) {
    throw new Error('buildManifest: fileHashes.archive and fileHashes.wrappedKey both required');
  }
  for (const slot of ['archive', 'wrappedKey']) {
    const fh = opts.fileHashes[slot];
    if (typeof fh.sizeBytes !== 'number' || fh.sizeBytes < 0) {
      throw new Error(`buildManifest: fileHashes.${slot}.sizeBytes must be a non-negative number`);
    }
    if (typeof fh.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(fh.sha256)) {
      throw new Error(`buildManifest: fileHashes.${slot}.sha256 must be 64 lowercase hex chars`);
    }
  }
  if (typeof opts.signingKeyId !== 'number' || !Number.isInteger(opts.signingKeyId) || opts.signingKeyId < 1) {
    throw new Error('buildManifest: signingKeyId must be a positive integer');
  }
  if (typeof opts.signingKeyFingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(opts.signingKeyFingerprint)) {
    throw new Error('buildManifest: signingKeyFingerprint must be 64 lowercase hex chars (SHA-256 of SPKI DER)');
  }
  if (typeof opts.sourceFuseCounter !== 'number' || !Number.isInteger(opts.sourceFuseCounter) || opts.sourceFuseCounter < 0) {
    throw new Error('buildManifest: sourceFuseCounter must be a non-negative integer');
  }

  const compression = opts.compression || 'zstd';
  if (!['zstd', 'gzip'].includes(compression)) {
    throw new Error(`buildManifest: compression must be zstd|gzip, got '${compression}'`);
  }

  const keyWrappingScheme = opts.keyWrappingScheme || 'env-var';
  if (!['env-var', 'aws-kms', 'azure-key-vault', 'gcp-kms'].includes(keyWrappingScheme)) {
    throw new Error(`buildManifest: keyWrappingScheme must be env-var|aws-kms|azure-key-vault|gcp-kms, got '${keyWrappingScheme}'`);
  }

  return {
    format_version: MANIFEST_FORMAT_VERSION,
    backup_id: String(opts.backupId),
    backup_type: opts.backupType,
    created_at: opts.createdAt || new Date().toISOString(),
    files: [
      {
        name: ARCHIVE_FILENAME,
        size_bytes: opts.fileHashes.archive.sizeBytes,
        sha256: opts.fileHashes.archive.sha256,
      },
      {
        name: WRAPPED_KEY_FILENAME,
        size_bytes: opts.fileHashes.wrappedKey.sizeBytes,
        sha256: opts.fileHashes.wrappedKey.sha256,
      },
    ],
    encryption: {
      algorithm: 'AES-256-GCM',
    },
    compression: {
      algorithm: compression,
      level: opts.compressionLevel != null ? opts.compressionLevel : (compression === 'zstd' ? 3 : 6),
    },
    key_wrapping: {
      scheme: keyWrappingScheme,
      kek_reference: opts.kekReference || (keyWrappingScheme === 'env-var' ? 'TIER1_ENCRYPTION_KEY' : ''),
    },
    source_db: {
      fuse_counter_at_creation: opts.sourceFuseCounter,
      schema_version: opts.sourceSchemaVersion || '1',
    },
    signing_key_id: opts.signingKeyId,
    signing_key_fingerprint: opts.signingKeyFingerprint,
    // D-R2-4: the salted, non-correlatable KEK fingerprint (dropped by serialize when the
    // caller supplies no kekFingerprint, so legacy manifests are unchanged).
    kek_fingerprint: (opts.kekFingerprint !== undefined && opts.kekFingerprint !== null)
      ? saltedKekFingerprint(opts.kekFingerprint, opts.backupId)
      : undefined,
  };
}

// ── Validation ───────────────────────────────────────────────────────────

/**
 * Validate the structure of a parsed manifest. Returns:
 *   { ok: true } on success
 *   { ok: false, error: 'human-readable reason' } on failure
 *
 * Does NOT verify the cryptographic signature (that's
 * backup-signing-keys.verifyManifest). Does NOT verify file hashes
 * (the restore service does that against the actual archive bytes).
 *
 * This catches structural problems before crypto verification so the
 * error messages a SOC operator sees are precise: "manifest is missing
 * field X" rather than just "signature verification failed."
 */
function validateStructure(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { ok: false, error: 'manifest must be a non-null object' };
  }
  if (manifest.format_version !== MANIFEST_FORMAT_VERSION) {
    return {
      ok: false,
      error: `unsupported manifest format_version: expected ${MANIFEST_FORMAT_VERSION}, got ${manifest.format_version}`,
    };
  }
  for (const required of ['backup_id', 'backup_type', 'created_at', 'files', 'encryption', 'compression', 'key_wrapping', 'source_db', 'signing_key_id', 'signing_key_fingerprint']) {
    if (manifest[required] === undefined) {
      return { ok: false, error: `missing required field: ${required}` };
    }
  }
  if (typeof manifest.backup_id !== 'string' || !manifest.backup_id) {
    return { ok: false, error: 'backup_id must be a non-empty string' };
  }
  if (!['scheduled', 'on-demand', 'snapshot'].includes(manifest.backup_type)) {
    return { ok: false, error: `backup_type must be scheduled|on-demand|snapshot, got '${manifest.backup_type}'` };
  }
  if (!Array.isArray(manifest.files) || manifest.files.length !== TRACKED_FILENAMES.length) {
    return { ok: false, error: `files must be an array of ${TRACKED_FILENAMES.length} entries` };
  }
  for (const expected of TRACKED_FILENAMES) {
    const f = manifest.files.find(x => x && x.name === expected);
    if (!f) {
      return { ok: false, error: `files[] missing entry for ${expected}` };
    }
    if (typeof f.size_bytes !== 'number' || f.size_bytes < 0) {
      return { ok: false, error: `files[${expected}].size_bytes must be a non-negative number` };
    }
    if (typeof f.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(f.sha256)) {
      return { ok: false, error: `files[${expected}].sha256 must be 64 lowercase hex chars` };
    }
  }
  if (manifest.encryption.algorithm !== 'AES-256-GCM') {
    return { ok: false, error: `encryption.algorithm must be AES-256-GCM, got '${manifest.encryption.algorithm}'` };
  }
  if (!['zstd', 'gzip'].includes(manifest.compression.algorithm)) {
    return { ok: false, error: `compression.algorithm must be zstd|gzip, got '${manifest.compression.algorithm}'` };
  }
  if (!['env-var', 'aws-kms', 'azure-key-vault', 'gcp-kms'].includes(manifest.key_wrapping.scheme)) {
    return { ok: false, error: `key_wrapping.scheme unsupported: '${manifest.key_wrapping.scheme}'` };
  }
  if (typeof manifest.signing_key_id !== 'number' || !Number.isInteger(manifest.signing_key_id) || manifest.signing_key_id < 1) {
    return { ok: false, error: 'signing_key_id must be a positive integer' };
  }
  if (typeof manifest.signing_key_fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(manifest.signing_key_fingerprint)) {
    return { ok: false, error: 'signing_key_fingerprint must be 64 lowercase hex chars (SHA-256 of SPKI DER)' };
  }
  if (typeof manifest.source_db.fuse_counter_at_creation !== 'number' || !Number.isInteger(manifest.source_db.fuse_counter_at_creation) || manifest.source_db.fuse_counter_at_creation < 0) {
    return { ok: false, error: 'source_db.fuse_counter_at_creation must be a non-negative integer' };
  }
  return { ok: true };
}

/**
 * Find a file's hash + size in the manifest by name. Convenience helper
 * for the restore service when it wants to verify a specific file.
 * Returns { sizeBytes, sha256 } or null if not found.
 */
function getFileEntry(manifest, name) {
  if (!manifest || !Array.isArray(manifest.files)) return null;
  const f = manifest.files.find(x => x && x.name === name);
  if (!f) return null;
  return { sizeBytes: f.size_bytes, sha256: f.sha256 };
}

module.exports = {
  // constants
  MANIFEST_FORMAT_VERSION,
  ARCHIVE_FILENAME,
  WRAPPED_KEY_FILENAME,
  MANIFEST_FILENAME,
  SIGNATURE_FILENAME,
  TRACKED_FILENAMES,

  // serialization
  canonicalize,
  serialize,
  parse,

  // construction
  buildManifest,

  // KEK fingerprint (D-R2-4)
  saltedKekFingerprint,
  verifyKekFingerprint,

  // validation
  validateStructure,
  getFileEntry,
};

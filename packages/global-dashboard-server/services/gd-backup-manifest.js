// =============================================================================
// FIREALIVE GD -- Backup Manifest Module
//
// A GD v2 backup is a directory containing four files:
//   archive.tar.gz.enc     -- encrypted, gzip-compressed tar archive of the data
//   wrapped-key.bin        -- per-backup AES-256-GCM key wrapped with the GD KEK
//   manifest.json          -- cleartext metadata about the backup (this module)
//   manifest.sig           -- Ed25519 signature of manifest.json bytes
//
// This module produces and parses manifest.json. It does NOT touch the signing
// keys (gd-backup-signing-keys) and does NOT touch encryption (gd-backup-archive
// / the backup engine). It is the data-shaping layer between the backup engine
// and the on-disk file. Twins the Regional backup-manifest, adapted for the GD:
// gzip compression, the gd-tier1 key-wrapping scheme, and the GD backup-type
// enum (full/incremental/differential/snapshot).
//
// CANONICAL SERIALIZATION CONTRACT
//
// The bytes produced by serialize() are what get signed. The same bytes must be
// reproducible at verification time so the signature still verifies. Three
// things JSON.stringify alone does not guarantee:
//
//   1. Stable key ordering -- canonicalize() sorts keys recursively before
//      serialization (a manifest assembled in a different code path could
//      insert keys in a different order).
//   2. No insignificant whitespace -- JSON.stringify with no indent argument
//      produces compact JSON with no whitespace. Always called without indent.
//   3. UTF-8 byte form -- Buffer.from(str, 'utf-8') gives stable bytes across
//      platforms.
//
// canonicalize() does NOT need to handle floats, BigInt, undefined, Date
// objects, or non-string keys, because none of those can appear in a valid
// manifest (integer counts, ISO 8601 string timestamps, string keys only).
// =============================================================================

// Current manifest format. The GD is new, so every manifest is v3 from the
// start; there is no v2 legacy shape to support.
const MANIFEST_FORMAT_VERSION = 3;

const SIGNATURE_FILENAME      = 'manifest.sig';
const ARCHIVE_FILENAME        = 'archive.tar.gz.enc';
const WRAPPED_KEY_FILENAME    = 'wrapped-key.bin';
const MANIFEST_FILENAME       = 'manifest.json';

// Manifest backup_type enum = the trigger (scheduled/on-demand/snapshot), a twin
// of the Regional manifest. The strategy (full/incremental/differential/snapshot)
// is carried by backups.backup_strategy and, on incremental/differential manifests,
// by a backup_strategy field.
const BACKUP_TYPES = ['scheduled', 'on-demand', 'snapshot'];

// Files the manifest enumerates and hashes. The manifest itself and its
// signature file are NOT in this list -- the manifest can't hash itself, and
// the signature file IS the signature of this manifest.
const TRACKED_FILENAMES = [ARCHIVE_FILENAME, WRAPPED_KEY_FILENAME];

// -- Canonical serialization --------------------------------------------------

/**
 * Recursively sort object keys alphabetically. Arrays preserve order (item
 * order is semantically meaningful). Primitives are returned unchanged.
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
 * Serialize a manifest object to canonical JSON bytes. These bytes are what get
 * signed and what get hashed for the backup_chain entry. Returns Buffer (UTF-8).
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
 * Parse manifest bytes back into an object. Strict JSON parsing. Accepts Buffer
 * or string. Caller should run validateStructure() on the result before
 * trusting any field.
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

// -- Manifest construction ----------------------------------------------------

/**
 * Build a manifest object from backup metadata. Caller hashes the archive and
 * wrapped-key files first and passes the hashes in via opts.fileHashes.
 *
 * opts:
 *   backupId              (string, required)  -- the backup directory name suffix
 *   backupType            (string, required)  -- scheduled|on-demand|snapshot
 *   createdAt             (string, optional)  -- ISO 8601; defaults to now
 *   fileHashes            (object, required)  -- { archive: { sizeBytes, sha256 },
 *                                                 wrappedKey: { sizeBytes, sha256 } }
 *   compressionLevel      (number, optional)  -- gzip level; defaults to 6
 *   keyWrappingScheme     (string, optional)  -- defaults to 'gd-tier1'
 *   kekReference          (string, optional)  -- defaults to 'GD_ENCRYPTION_KEY'
 *   signingKeyId          (number, required)  -- backup_signing_keys row id that
 *                                                 signed this manifest (local audit
 *                                                 cross-reference; not meaningful
 *                                                 across deployments)
 *   signingKeyFingerprint (string, required)  -- SHA-256 hex (64 chars) of the
 *                                                 signer's SPKI DER; the v3
 *                                                 cross-deployment key identifier
 *   sourceFuseCounter     (number, required)  -- fuseCounter at creation (restore
 *                                                 anti-rollback anchor)
 *   sourceSchemaVersion   (string, optional)  -- schema version at creation
 *
 * Returns the constructed manifest object (call serialize() to get bytes for
 * signing).
 */
function buildManifest(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new Error('buildManifest: opts object required');
  }
  for (const required of ['backupId', 'backupType', 'fileHashes', 'signingKeyId', 'signingKeyFingerprint', 'sourceFuseCounter']) {
    if (opts[required] === undefined || opts[required] === null) {
      throw new Error(`buildManifest: opts.${required} required`);
    }
  }
  if (!BACKUP_TYPES.includes(opts.backupType)) {
    throw new Error(`buildManifest: backupType must be ${BACKUP_TYPES.join('|')}, got '${opts.backupType}'`);
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

  const keyWrappingScheme = opts.keyWrappingScheme || 'gd-tier1';
  if (keyWrappingScheme !== 'gd-tier1') {
    throw new Error(`buildManifest: keyWrappingScheme must be gd-tier1, got '${keyWrappingScheme}'`);
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
      algorithm: 'gzip',
      level: opts.compressionLevel != null ? opts.compressionLevel : 6,
    },
    key_wrapping: {
      scheme: keyWrappingScheme,
      kek_reference: opts.kekReference || 'GD_ENCRYPTION_KEY',
    },
    source_db: {
      fuse_counter_at_creation: opts.sourceFuseCounter,
      schema_version: opts.sourceSchemaVersion || '1',
    },
    signing_key_id: opts.signingKeyId,
    signing_key_fingerprint: opts.signingKeyFingerprint,
  };
}

// -- Validation ---------------------------------------------------------------

/**
 * Validate the structure of a parsed manifest. Returns { ok: true } on success
 * or { ok: false, error } on failure. Does NOT verify the cryptographic
 * signature (gd-backup-signing-keys.verifyManifest*) or the file hashes (the
 * restore service does that against the actual archive bytes). Catches
 * structural problems before crypto verification so operator-facing errors are
 * precise.
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
  if (!BACKUP_TYPES.includes(manifest.backup_type)) {
    return { ok: false, error: `backup_type must be ${BACKUP_TYPES.join('|')}, got '${manifest.backup_type}'` };
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
  if (manifest.compression.algorithm !== 'gzip') {
    return { ok: false, error: `compression.algorithm must be gzip, got '${manifest.compression.algorithm}'` };
  }
  if (manifest.key_wrapping.scheme !== 'gd-tier1') {
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
 * Find a file's hash + size in the manifest by name. Returns { sizeBytes,
 * sha256 } or null if not found.
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
  BACKUP_TYPES,

  // serialization
  canonicalize,
  serialize,
  parse,

  // construction
  buildManifest,

  // validation
  validateStructure,
  getFileEntry,
};

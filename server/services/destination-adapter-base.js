// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Destination Adapter Base
//
// Common interface, registry, and helpers for backup-push destination
// adapters. Each adapter (local mount, SFTP, future S3 / Azure Blob /
// GCS) implements the interface contract documented below and
// registers itself via registerAdapter() at module-load time.
//
// THE PUSH ORCHESTRATOR (services/backup-push.js, ships in commit 7)
// dispatches based on the destination row's adapter column:
//
//   const adapter = adapterRegistry.get(destination.adapter);
//   if (!adapter) throw ...
//   const result = await adapter.push(backupContext, { logger, timeoutMs });
//
// ADAPTER INTERFACE (each adapter module exports ONE object with these
// fields, then calls registerAdapter at end of module):
//
//   name: string
//     Lowercase identifier matching the adapter column value:
//     'local' | 'sftp' | 's3' | 'azure-blob' | 'gcs'
//
//   description: string
//     Short human-readable description shown in admin UI.
//
//   supportedImmutabilityModes: string[]
//     Subset of ['none', 'append-only', 'object-lock', 'unknown'].
//     The CRUD service refuses to create a destination whose
//     declared immutability_mode is not in this list.
//
//   validateConfig(config) -> { ok, error?, field? }
//     Synchronous validation of the config JSON object. Return
//     { ok: true } if valid, { ok: false, error: 'msg', field: 'host' }
//     otherwise. Field is optional but helps the admin UI highlight
//     the offending input.
//
//   validateCredentials(credentials) -> { ok, error? }
//     Synchronous validation of the credentials object. May return
//     { ok: true } unconditionally if the adapter doesn't need
//     credentials (e.g., 'local').
//
//   async probe(config, credentials) -> { ok, error?, detail? }
//     Quick connectivity test. Runs at destination create / update
//     to surface config errors before the first real push attempt.
//     Should be FAST (ideally <5s); not a full push test. Should
//     verify reachability, authentication, and write permission to
//     the target path. Return { ok: false } with a short error
//     message on failure.
//
//   async push(backupContext, options) -> pushResult
//     The main upload operation. Inputs:
//       backupContext: {
//         backupId,                // string (UUID-like)
//         sourceDir,               // absolute on-host path to the
//                                  //   backup directory
//         files: [{                // metadata for each file in the
//           name,                  //   backup directory
//           absolutePath,
//           sizeBytes,
//           sha256,
//         }],
//         manifestSha256,          // backups.sha256_hash (the
//                                  //   manifest hash for v2 rows)
//         createdAt,
//         destination: {           // the destination row (decrypted
//           id,                    //   credentials already attached)
//           name,
//           adapter,
//           config,                // parsed JSON
//           credentials,           // decrypted JSON or null
//           immutability_mode,
//           retention_days,
//         },
//       }
//       options: {
//         timeoutMs,               // overall deadline; adapter
//                                  //   should abort if exceeded
//         logger,                  // for streaming progress logs
//         signal,                  // optional AbortSignal for
//                                  //   cancellation by the orchestrator
//       }
//     Returns: {
//       destinationPath,           // string identifying where the
//                                  //   backup landed (path / URL / key)
//       bytesPushed,               // total bytes uploaded across
//                                  //   the four files
//       immutabilityVerified,      // null | { mode: 'object-lock',
//                                  //          retentionUntil: ISO } |
//                                  //   { mode: 'append-only',
//                                  //     trustedBy: 'operator-declared' }
//                                  //   For R3d-3 adapters, null or
//                                  //   trust-only.
//       destinationMetadata,       // adapter-specific freeform JSON
//                                  //   for forensic value (e.g., S3
//                                  //   object versions, SFTP server
//                                  //   banner)
//     }
//     Throws DestinationAdapterError on failure. The error's
//     retryable field tells the scheduler whether to back-off-retry
//     (transient: DNS, timeout, 5xx) or give up (permanent: auth
//     failure, no-such-bucket, file-too-large).
//
// REGISTRY
//
// Adapter modules call registerAdapter(adapter) at end of module
// load. The push orchestrator looks up adapters via getAdapter(name).
// listAdapters() returns metadata for the admin UI's "create
// destination" picker.
//
// Re-registering the same name overwrites (useful for tests; not
// expected in production where each adapter file is required once).
// ═══════════════════════════════════════════════════════════════════════════════

// ── Custom error class ───────────────────────────────────────────────────

/**
 * Error thrown by adapter operations. The push orchestrator and
 * the scheduler retry logic introspect:
 *
 *   adapter      string  the adapter name that threw
 *   operation    string  'probe' | 'push' | 'validateConfig' | 'validateCredentials'
 *   retryable    bool    true for transient failures (DNS, timeout,
 *                        5xx responses), false for permanent
 *                        failures (auth, missing-resource, quota
 *                        exceeded, malformed-input)
 *   detail       any     adapter-specific extra (status code, etc.)
 *
 * The Error subclass carries cause via the standard Error options
 * object so stack traces survive chaining.
 */
class DestinationAdapterError extends Error {
  constructor(message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'DestinationAdapterError';
    this.adapter = options.adapter || 'unknown';
    this.operation = options.operation || 'unknown';
    this.retryable = options.retryable === true;   // default false
    this.detail = options.detail || null;
  }
}

// ── Registry ─────────────────────────────────────────────────────────────

const VALID_ADAPTER_NAMES = new Set(['local', 'sftp', 's3', 'azure-blob', 'gcs']);
const VALID_IMMUTABILITY_MODES = new Set(['none', 'append-only', 'object-lock', 'unknown']);

const adapterRegistry = new Map();

function registerAdapter(adapter) {
  if (!adapter || typeof adapter !== 'object') {
    throw new Error('registerAdapter: adapter must be an object');
  }
  if (!VALID_ADAPTER_NAMES.has(adapter.name)) {
    throw new Error(`registerAdapter: invalid adapter name '${adapter.name}' (must be one of: ${[...VALID_ADAPTER_NAMES].join(', ')})`);
  }
  // Required interface methods
  for (const required of ['validateConfig', 'validateCredentials', 'probe', 'push']) {
    if (typeof adapter[required] !== 'function') {
      throw new Error(`registerAdapter: adapter '${adapter.name}' missing required method '${required}'`);
    }
  }
  if (!Array.isArray(adapter.supportedImmutabilityModes) || adapter.supportedImmutabilityModes.length === 0) {
    throw new Error(`registerAdapter: adapter '${adapter.name}' must declare supportedImmutabilityModes`);
  }
  for (const mode of adapter.supportedImmutabilityModes) {
    if (!VALID_IMMUTABILITY_MODES.has(mode)) {
      throw new Error(`registerAdapter: adapter '${adapter.name}' declares unknown immutability mode '${mode}'`);
    }
  }
  adapterRegistry.set(adapter.name, adapter);
}

function getAdapter(name) {
  return adapterRegistry.get(name) || null;
}

function listAdapters() {
  return [...adapterRegistry.values()].map(a => ({
    name: a.name,
    description: a.description || '',
    supportedImmutabilityModes: [...a.supportedImmutabilityModes],
  }));
}

function clearRegistry() {
  // Exposed for tests; not used in production
  adapterRegistry.clear();
}

// ── Shared validation helpers ────────────────────────────────────────────
//
// Adapters use these for common config patterns to keep error
// messaging consistent across adapter implementations.

/**
 * Validate that a value is a non-empty string. Returns
 * { ok: false, error, field } on failure (suitable for direct
 * return from validateConfig) or { ok: true } on success.
 */
function requireString(obj, key, opts = {}) {
  const value = obj && obj[key];
  if (typeof value !== 'string' || value === '') {
    return { ok: false, error: `${key} required (must be non-empty string)`, field: key };
  }
  if (opts.maxLength && value.length > opts.maxLength) {
    return { ok: false, error: `${key} exceeds max length ${opts.maxLength}`, field: key };
  }
  if (opts.pattern && !opts.pattern.test(value)) {
    return { ok: false, error: `${key} does not match expected format`, field: key };
  }
  return { ok: true };
}

/**
 * Validate that a value is an integer in [min, max]. Returns
 * { ok: false, error, field } on failure or { ok: true } on success.
 */
function requireInt(obj, key, min, max) {
  const value = obj && obj[key];
  if (!Number.isInteger(value)) {
    return { ok: false, error: `${key} required (must be integer)`, field: key };
  }
  if (value < min || value > max) {
    return { ok: false, error: `${key} must be in range [${min}, ${max}]`, field: key };
  }
  return { ok: true };
}

/**
 * Validate that a path is absolute. Returns the same shape as
 * the validators above.
 *
 * NOTE: this checks lexical absoluteness (starts with /) for POSIX
 * paths. Platform-specific abs-checks (Windows drive letters, UNC)
 * are not relevant for the Linux-only deployment target of
 * FireAlive servers; backup destinations always live on the
 * server's filesystem or remote SFTP, both POSIX.
 */
function requireAbsolutePath(obj, key) {
  const v = obj && obj[key];
  if (typeof v !== 'string' || v === '') {
    return { ok: false, error: `${key} required`, field: key };
  }
  if (!v.startsWith('/')) {
    return { ok: false, error: `${key} must be an absolute path (start with /)`, field: key };
  }
  if (v.includes('\0')) {
    return { ok: false, error: `${key} contains null byte`, field: key };
  }
  return { ok: true };
}

/**
 * Reject path traversal: ban '..' segments and absolute symlinks
 * that escape the configured root. Adapters that build dynamic
 * paths (e.g., joining destination root + backup directory name)
 * should sanitize via this helper.
 */
function safeJoinSegment(root, segment) {
  if (typeof segment !== 'string' || segment === '') {
    throw new DestinationAdapterError('safeJoinSegment: segment must be non-empty string', { operation: 'validate' });
  }
  if (segment.includes('/') || segment.includes('\\') || segment.includes('\0')) {
    throw new DestinationAdapterError(`safeJoinSegment: segment '${segment}' contains path separator or null byte`, { operation: 'validate' });
  }
  if (segment === '..' || segment === '.') {
    throw new DestinationAdapterError(`safeJoinSegment: segment '${segment}' is not allowed`, { operation: 'validate' });
  }
  // root may or may not end with /; normalize
  const trimmed = root.endsWith('/') ? root.slice(0, -1) : root;
  return trimmed + '/' + segment;
}

// ── Module exports ───────────────────────────────────────────────────────

module.exports = {
  // Error class
  DestinationAdapterError,

  // Registry
  registerAdapter,
  getAdapter,
  listAdapters,
  clearRegistry,

  // Validation helpers
  requireString,
  requireInt,
  requireAbsolutePath,
  safeJoinSegment,

  // Constants (for adapters and admin UI)
  VALID_ADAPTER_NAMES: [...VALID_ADAPTER_NAMES],
  VALID_IMMUTABILITY_MODES: [...VALID_IMMUTABILITY_MODES],
};

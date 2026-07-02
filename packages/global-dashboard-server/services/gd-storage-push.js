// =============================================================================
// FIREALIVE GD -- Storage Push Engine
//
// The Global Dashboard's generic artifact-push engine. Every GD artifact
// writer (full-suite backup, snapshot, sealed audit-log / CEF segment,
// forensic export) pushes through this one engine: it dispatches to the
// destination adapter, records per-destination status with retry state, and
// retries transient failures with exponential backoff. Permanent failures
// (auth, host-key mismatch, missing-resource, non-immutable bucket) are not
// retried.
//
// GENERIC OVER ARTIFACT TYPE
//
// The GD routes five artifact types into three push tables (backup_pushes,
// archive_segment_pushes, forensic_export_pushes). The push executor only
// touches the columns common to all three -- status, attempt_count,
// last_attempt_at, error_message, next_retry_at, pushed_at, size_pushed_bytes,
// destination_path -- keyed by the row's integer id. The artifact-specific key
// and role columns are set at row-creation time by each writer through the
// insertRow callback, and each artifact is re-materialized for a retry through
// the rebuildContext callback. So one engine serves every artifact type
// without duplicating the retry mechanics.
//
// GUARANTEED DUAL-WRITE
//
// A route may name a primary and a distinct secondary destination. pushToDestinations
// runs each in order (primary first) and records an independent push row per
// destination, so a primary failure never skips the secondary -- both are
// attempted and retried on their own schedule. Writers that need to gate a
// commit on the primary landing (e.g. the immutability-required audit-log
// segment) compose pushOneDestination directly.
//
// SUCCESS / FAILURE LIFECYCLE (per push row)
//
//   Initial attempt:
//     1. insertRow -> row (status='queued', attempt_count=0)
//     2. UPDATE status='running', attempt_count+1, last_attempt_at=now
//     3. await adapter.push(...)
//     4a. success: status='succeeded', pushed_at, size_pushed_bytes,
//         destination_path, error_message=NULL, next_retry_at=NULL
//     4b. failure (retryable): status='failed', error_message,
//         next_retry_at=now+backoff
//     4c. failure (permanent): status='failed', error_message,
//         next_retry_at=NULL
//
//   Retry (scheduler, hourly): retryDuePushes scans a push table for rows with
//   status='failed' AND next_retry_at <= now, re-resolves the destination,
//   rebuilds the artifact context, and re-runs the attempt on the same row.
//   After MAX_ATTEMPTS the row is marked permanent (next_retry_at=NULL).
//
// EXPONENTIAL BACKOFF: attempt 2 at +5min, 3 at +30min, 4 at +2hr, 5 at +12hr,
// then permanent.
//
// IDEMPOTENCY: adapters that observe an already-complete upload during a retry
// (their alreadyPresent / _complete.flag path) return success without redoing
// the transfer.
// =============================================================================

const fs = require('fs');
const crypto = require('crypto');

const base = require('./gd-destination-adapter-base');
// Requiring the destinations registry pulls in all five adapters (each
// self-registers on require), so the adapter registry is populated.
const storageDestinations = require('./gd-storage-destinations');

// --- Constants ---------------------------------------------------------------

/**
 * Backoff schedule indexed by attempt count just completed.
 * RETRY_DELAYS_SEC[0] = wait after attempt 1 fails (before attempt 2), etc.
 * After MAX_ATTEMPTS attempts, no more retries are scheduled.
 */
const RETRY_DELAYS_SEC = [
  5 * 60,         // 5 min  -> attempt 2
  30 * 60,        // 30 min -> attempt 3
  2 * 60 * 60,    // 2 hr   -> attempt 4
  12 * 60 * 60,   // 12 hr  -> attempt 5
];

const MAX_ATTEMPTS = 5;

const DEFAULT_PUSH_TIMEOUT_MS = 30 * 60 * 1000;  // 30 minutes overall per-destination
const RETRY_SCAN_BATCH_SIZE = 100;
const MAX_ERROR_MESSAGE_LEN = 1000;
const HASH_BUFFER_SIZE = 64 * 1024;

// The three artifact push tables this engine can drive. Interpolated into SQL
// only after an allow-list check, never from external input.
const PUSH_TABLES = new Set(['backup_pushes', 'archive_segment_pushes', 'forensic_export_pushes']);

function assertPushTable(pushTable) {
  if (!PUSH_TABLES.has(pushTable)) {
    throw new Error(`gd-storage-push: unknown push table '${pushTable}'`);
  }
}

// --- Helpers -----------------------------------------------------------------

/**
 * Compute SHA-256 of a file by streaming. Used to populate the sha256 field of
 * each file in an artifact context (adapters verify-after-copy).
 */
function sha256OfFile(filePath) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(HASH_BUFFER_SIZE);
    let bytes;
    while ((bytes = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
      hash.update(buf.subarray(0, bytes));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

/**
 * Build the files[] array an artifact context needs from a list of
 * { name, absolutePath } specs: verifies each exists, stats its size, and
 * hashes it. Returns { ok: true, files } or { ok: false, error }.
 */
function hashFilesForContext(fileSpecs) {
  const files = [];
  for (const f of fileSpecs) {
    if (!f.absolutePath) return { ok: false, error: `missing path for ${f.name}` };
    if (!fs.existsSync(f.absolutePath)) return { ok: false, error: `file not found on disk: ${f.absolutePath}` };
    let stat;
    try { stat = fs.statSync(f.absolutePath); } catch (err) { return { ok: false, error: `cannot stat ${f.absolutePath}: ${err.message}` }; }
    let sha256;
    try { sha256 = sha256OfFile(f.absolutePath); } catch (err) { return { ok: false, error: `cannot hash ${f.absolutePath}: ${err.message}` }; }
    files.push({ name: f.name, absolutePath: f.absolutePath, sizeBytes: stat.size, sha256 });
  }
  return { ok: true, files };
}

/**
 * Calculate next_retry_at as a SQLite-friendly 'YYYY-MM-DD HH:MM:SS' UTC
 * string, or null if MAX_ATTEMPTS has been reached.
 * justCompletedAttempt: the attempt number that just failed (1, 2, 3, ...).
 */
function calculateNextRetryAt(justCompletedAttempt) {
  if (justCompletedAttempt >= MAX_ATTEMPTS) return null;
  const delaySec = RETRY_DELAYS_SEC[justCompletedAttempt - 1];
  if (delaySec === undefined) return null;
  const next = new Date(Date.now() + delaySec * 1000);
  return next.toISOString().slice(0, 19).replace('T', ' ');
}

/**
 * Truncate an error message for storage in the error_message column.
 */
function truncateError(msg) {
  if (typeof msg !== 'string') msg = String(msg);
  if (msg.length <= MAX_ERROR_MESSAGE_LEN) return msg;
  return msg.slice(0, MAX_ERROR_MESSAGE_LEN - 3) + '...';
}

/**
 * Adapter context = artifactContext with the destination row attached (with
 * credentials decrypted by the caller). The adapter's push() receives this.
 */
function buildAdapterContext(artifactContext, destinationWithCredentials) {
  return {
    ...artifactContext,
    destination: {
      id: destinationWithCredentials.id,
      name: destinationWithCredentials.name,
      adapter: destinationWithCredentials.adapter,
      config: destinationWithCredentials.config,
      credentials: destinationWithCredentials.credentials,
      immutability_mode: destinationWithCredentials.immutability_mode,
      retention_days: destinationWithCredentials.retention_days,
    },
  };
}

/**
 * Map an ordered list of public destination views (as returned by the routing
 * resolver) to credentialed views for the push, skipping any that have since
 * vanished or been disabled, and de-duplicating by id.
 */
function attachCredentials(db, publicDestinations) {
  const out = [];
  for (const pub of publicDestinations || []) {
    const dest = storageDestinations.getDestinationWithCredentials(db, pub.id);
    if (!dest || !dest.enabled) continue;
    if (out.some((d) => d.id === dest.id)) continue;
    out.push(dest);
  }
  return out;
}

// --- Core push attempt (generic by table) ------------------------------------

/**
 * Run ONE push attempt for an existing push row in pushTable. Updates the row
 * to 'running' (incrementing attempt_count), runs the adapter, and updates the
 * row with success or failure state. Used by both the initial push and retry.
 */
async function runPushAttempt(db, pushTable, pushId, adapterContext, options = {}) {
  assertPushTable(pushTable);
  const logger = options.logger || console;
  const adapter = base.getAdapter(adapterContext.destination.adapter);

  if (!adapter) {
    const errMsg = `adapter '${adapterContext.destination.adapter}' not loaded in registry`;
    db.prepare(`
      UPDATE ${pushTable}
      SET status = 'failed', attempt_count = attempt_count + 1,
          last_attempt_at = datetime('now'), error_message = ?, next_retry_at = NULL
      WHERE id = ?
    `).run(truncateError(errMsg), pushId);
    return { pushId, ok: false, error: errMsg, retryable: false, nextRetryAt: null };
  }

  // Mark running + increment attempt_count atomically
  db.prepare(`
    UPDATE ${pushTable}
    SET status = 'running', attempt_count = attempt_count + 1, last_attempt_at = datetime('now')
    WHERE id = ?
  `).run(pushId);

  const currentAttempt = db.prepare(`SELECT attempt_count FROM ${pushTable} WHERE id = ?`).get(pushId).attempt_count;

  let result, error;
  try {
    result = await adapter.push(adapterContext, {
      logger,
      timeoutMs: options.timeoutMs || DEFAULT_PUSH_TIMEOUT_MS,
    });
  } catch (err) {
    error = err;
  }

  if (error) {
    const isRetryable = error instanceof base.DestinationAdapterError ? error.retryable : true;
    const nextRetryAt = isRetryable ? calculateNextRetryAt(currentAttempt) : null;
    db.prepare(`
      UPDATE ${pushTable}
      SET status = 'failed', error_message = ?, next_retry_at = ?
      WHERE id = ?
    `).run(truncateError(error.message), nextRetryAt, pushId);
    logger.warn('gd-storage-push: push attempt failed', {
      pushTable, pushId,
      artifactId: adapterContext.artifactId,
      destinationId: adapterContext.destination.id,
      destinationName: adapterContext.destination.name,
      attemptCount: currentAttempt, retryable: isRetryable, nextRetryAt, error: error.message,
    });
    return { pushId, ok: false, error: error.message, retryable: isRetryable, attemptCount: currentAttempt, nextRetryAt };
  }

  // Success
  db.prepare(`
    UPDATE ${pushTable}
    SET status = 'succeeded', pushed_at = datetime('now'), size_pushed_bytes = ?,
        destination_path = ?, error_message = NULL, next_retry_at = NULL
    WHERE id = ?
  `).run(result.bytesPushed, result.destinationPath, pushId);
  logger.info('gd-storage-push: push succeeded', {
    pushTable, pushId,
    artifactId: adapterContext.artifactId,
    destinationId: adapterContext.destination.id,
    destinationName: adapterContext.destination.name,
    attemptCount: currentAttempt, bytesPushed: result.bytesPushed,
    destinationPath: result.destinationPath, immutabilityVerified: result.immutabilityVerified,
  });
  return {
    pushId, ok: true,
    bytesPushed: result.bytesPushed,
    destinationPath: result.destinationPath,
    immutabilityVerified: result.immutabilityVerified,
    destinationMetadata: result.destinationMetadata,
    attemptCount: currentAttempt,
  };
}

// --- Dual-write orchestration ------------------------------------------------

/**
 * Push an artifact to a single destination: the writer-provided insertRow
 * creates the table-specific push row (setting the artifact key / role /
 * source_artifact_path columns) and returns the new pushId; the engine then
 * runs the attempt. insertRow(db, destination, role) -> pushId.
 *
 * Returns { destinationId, destinationName, role, pushId, ...attemptResult }.
 */
async function pushOneDestination(db, { pushTable, artifactContext, destination, role, insertRow, options = {} }) {
  assertPushTable(pushTable);
  const logger = options.logger || console;
  const pushId = insertRow(db, destination, role);
  const adapterContext = buildAdapterContext(artifactContext, destination);
  let attemptResult;
  try {
    attemptResult = await runPushAttempt(db, pushTable, pushId, adapterContext, options);
  } catch (err) {
    logger.error('gd-storage-push: unexpected error in runPushAttempt', { pushTable, pushId, error: err.message });
    db.prepare(`
      UPDATE ${pushTable}
      SET status = 'failed', error_message = ?, next_retry_at = ?
      WHERE id = ?
    `).run(truncateError(`unexpected: ${err.message}`), calculateNextRetryAt(1), pushId);
    attemptResult = { pushId, ok: false, error: err.message, retryable: true, attemptCount: 1, nextRetryAt: calculateNextRetryAt(1) };
  }
  return { destinationId: destination.id, destinationName: destination.name, role, ...attemptResult };
}

/**
 * Guaranteed dual-write: push the artifact to each destination in order
 * (primary first, then secondary), recording an independent push row per
 * destination. Each push is independent -- a primary failure does not skip the
 * secondary. destinations is an ordered array of credentialed destination
 * views (use attachCredentials on a route's resolved destinations).
 *
 * Returns { ok: true, destinations: [results] }.
 */
async function pushToDestinations(db, { pushTable, artifactContext, destinations, insertRow, options = {} }) {
  assertPushTable(pushTable);
  const results = [];
  for (let i = 0; i < destinations.length; i += 1) {
    const role = i === 0 ? 'primary' : 'secondary';
    const r = await pushOneDestination(db, { pushTable, artifactContext, destination: destinations[i], role, insertRow, options });
    results.push(r);
  }
  return { ok: true, destinations: results };
}

// --- Retry -------------------------------------------------------------------

/**
 * Retry a single failed push row by id. Re-resolves the destination and
 * re-materializes the artifact via the writer-provided rebuildContext, then
 * re-runs the attempt on the same row.
 *   rebuildContext(db, pushRow) -> { ok: true, artifactContext } |
 *                                  { ok: false, error, fatal? }
 * Returns the attempt result, or { ok, skipped } / { ok: false, fatal }.
 */
async function retrySinglePush(db, { pushTable, pushId, rebuildContext, options = {} }) {
  assertPushTable(pushTable);
  const pushRow = db.prepare(`SELECT * FROM ${pushTable} WHERE id = ?`).get(pushId);
  if (!pushRow) return { ok: false, error: 'push row not found', fatal: true };
  if (pushRow.status === 'succeeded') return { ok: true, skipped: 'already-succeeded', pushId };
  if (pushRow.attempt_count >= MAX_ATTEMPTS) {
    db.prepare(`UPDATE ${pushTable} SET next_retry_at = NULL WHERE id = ?`).run(pushId);
    return { ok: false, skipped: 'max-attempts-reached', error: 'maximum retry attempts reached', pushId };
  }

  const destination = storageDestinations.getDestinationWithCredentials(db, pushRow.destination_id);
  if (!destination) {
    const errMsg = 'destination no longer exists';
    db.prepare(`UPDATE ${pushTable} SET status = 'failed', error_message = ?, next_retry_at = NULL WHERE id = ?`).run(errMsg, pushId);
    return { ok: false, error: errMsg, fatal: true, pushId };
  }
  if (!destination.enabled) return { ok: false, skipped: 'destination-disabled', pushId };

  const ctx = rebuildContext(db, pushRow);
  if (!ctx || !ctx.ok) {
    const errMsg = (ctx && ctx.error) || 'cannot rebuild artifact context';
    db.prepare(`UPDATE ${pushTable} SET status = 'failed', error_message = ?, next_retry_at = NULL WHERE id = ?`).run(truncateError(errMsg), pushId);
    return { ok: false, error: errMsg, fatal: true, pushId };
  }

  const adapterContext = buildAdapterContext(ctx.artifactContext, destination);
  return runPushAttempt(db, pushTable, pushId, adapterContext, options);
}

/**
 * Find all pushes in pushTable whose retry time has passed and run them.
 * Called by the scheduler. rebuildContext is the writer's artifact-rebuilder.
 * Returns { retried: <count>, results: [...] }.
 */
async function retryDuePushes(db, { pushTable, rebuildContext, options = {} }) {
  assertPushTable(pushTable);
  const logger = options.logger || console;
  const dueRows = db.prepare(`
    SELECT id FROM ${pushTable}
    WHERE status = 'failed' AND next_retry_at IS NOT NULL AND next_retry_at <= datetime('now')
    ORDER BY next_retry_at ASC
    LIMIT ?
  `).all(RETRY_SCAN_BATCH_SIZE);
  if (dueRows.length === 0) return { retried: 0, results: [] };
  logger.info(`gd-storage-push: retrying ${dueRows.length} due push(es) in ${pushTable}`);
  const results = [];
  for (const row of dueRows) {
    const r = await retrySinglePush(db, { pushTable, pushId: row.id, rebuildContext, options });
    results.push({ pushId: row.id, ...r });
  }
  return { retried: dueRows.length, results };
}

// --- Status ------------------------------------------------------------------

function getPushStatus(db, pushTable, pushId) {
  assertPushTable(pushTable);
  return db.prepare(`SELECT * FROM ${pushTable} WHERE id = ?`).get(pushId) || null;
}

// --- Module exports ----------------------------------------------------------

module.exports = {
  // Push API (writers call these)
  pushOneDestination,
  pushToDestinations,
  retrySinglePush,
  retryDuePushes,
  getPushStatus,

  // Shared helpers for writers
  hashFilesForContext,
  attachCredentials,
  buildAdapterContext,

  // Constants
  MAX_ATTEMPTS,
  RETRY_DELAYS_SEC,
  DEFAULT_PUSH_TIMEOUT_MS,
  PUSH_TABLES: [...PUSH_TABLES],
};

// Internals exposed for tests
module.exports.__test__ = {
  calculateNextRetryAt,
  truncateError,
  sha256OfFile,
  runPushAttempt,
  assertPushTable,
  RETRY_SCAN_BATCH_SIZE,
};

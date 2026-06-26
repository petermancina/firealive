// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Push Orchestrator
//
// After every successful backup creation, push the v2 backup files
// (archive.tar.zst.enc, wrapped-key.bin, manifest.json, manifest.sig)
// to every enabled destination. Track per-destination status in
// backup_pushes. Retry transient failures with exponential backoff
// via the scheduler. Permanent failures (auth, host-key mismatch,
// missing-resource) are not retried.
//
// PUSH HAPPENS IN SERIES, ONE DESTINATION AT A TIME
//
// Pushes run sequentially across destinations. Parallel would be
// faster for installs with many destinations, but complicates error
// handling and resource management. Each adapter opens its own
// connection (SSH / filesystem) and runs to completion. Defer
// parallelism until a real customer hits the limit.
//
// SUCCESS / FAILURE LIFECYCLE
//
//   Initial attempt:
//     1. INSERT row (backup_id, destination_id, status='queued',
//        attempt_count=0)
//     2. UPDATE status='running', attempt_count=attempt_count+1,
//        last_attempt_at=now
//     3. await adapter.push(...)
//     4a. On success: UPDATE status='succeeded', pushed_at=now,
//         size_pushed_bytes, destination_path,
//         error_message=NULL, next_retry_at=NULL
//     4b. On failure (retryable): UPDATE status='failed',
//         error_message, next_retry_at=now+backoff
//     4c. On failure (permanent): UPDATE status='failed',
//         error_message, next_retry_at=NULL
//
//   Retry (called by scheduler hourly):
//     1. retryAllDuePushes scans for rows where status='failed' AND
//        next_retry_at <= now
//     2. For each: re-run from step 2 above, reusing the pushId,
//        incrementing attempt_count
//     3. After MAX_ATTEMPTS attempts, mark permanent (next_retry_at=NULL).
//        Operators can manually trigger retry via the routes layer
//        (commit 11 of this phase) if they want to override.
//
// EXPONENTIAL BACKOFF SCHEDULE
//
//   Attempt 1: immediate (after backup creation)
//   Attempt 2: +5 min after attempt 1 failed
//   Attempt 3: +30 min after attempt 2 failed
//   Attempt 4: +2 hr after attempt 3 failed
//   Attempt 5: +12 hr after attempt 4 failed
//   Attempt 6+: never; permanent failure
//
// CRASH RECOVERY EDGE CASE
//
// If the process crashes while a row says 'running', it stays in
// that state until manual intervention. R3d-3 does NOT auto-recover
// stale 'running' rows. A future scheduler enhancement could add a
// "running for >1hr → mark failed-retryable" sweep. Operators
// noticing stuck rows can use the routes-layer manual-retry endpoint.
//
// IDEMPOTENCY
//
// pushBackup creates a new row per (backup, destination) pair on
// each invocation. Caller (services/backup.js) calls pushBackup
// once per successful backup creation -- no dedup at this layer.
// Re-pushing a backup explicitly creates new rows.
//
// retryPush reuses the existing pushId, incrementing attempt_count.
// Adapters that observe a successful upload during a retry
// (idempotency check, e.g. the local adapter's "alreadyPresent"
// path) return success without redoing the upload.
//
// CHAIN INTEGRATION
//
// Per R3d-3 architectural decision, push events are NOT recorded
// in backup_chain. They live only in backup_pushes. This avoids a
// schema migration to add new event_type values to the chain's
// CHECK constraint. SOC compliance reviews can correlate
// backup_pushes timestamps with chain CREATE entries via backup_id.
// Future phases can add DESTINATION_PUSH chain events via a
// rebuild migration if compliance demands it.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const base = require('./destination-adapter-base');

// Force adapter self-registration on require
require('./destination-adapter-local');
require('./destination-adapter-sftp');

const storageDestinations = require('./storage-destinations');

// ── Constants ────────────────────────────────────────────────────────────

/**
 * Backoff schedule indexed by attempt count just completed.
 * RETRY_DELAYS_SEC[0] = wait time after attempt 1 fails (before attempt 2)
 * RETRY_DELAYS_SEC[1] = wait time after attempt 2 fails (before attempt 3)
 * etc.
 *
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

// ── Helpers ──────────────────────────────────────────────────────────────

/**
 * Compute SHA-256 of a file by streaming. Used to populate the
 * sha256 field of each file in backupContext.files[]. Adapters
 * (local, sftp) use this to verify-after-copy.
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
 * Calculate next_retry_at as an ISO-format SQLite-friendly string.
 *
 * justCompletedAttempt: the attempt number that just failed (1, 2, 3, ...)
 *
 * Returns: 'YYYY-MM-DD HH:MM:SS' UTC-format string for the next
 * retry time, or null if MAX_ATTEMPTS has been reached.
 */
function calculateNextRetryAt(justCompletedAttempt) {
  if (justCompletedAttempt >= MAX_ATTEMPTS) return null;
  // Index 0 in RETRY_DELAYS_SEC is the wait after attempt 1
  const delaySec = RETRY_DELAYS_SEC[justCompletedAttempt - 1];
  if (delaySec === undefined) return null;  // safety; shouldn't fire given MAX_ATTEMPTS check
  const next = new Date(Date.now() + delaySec * 1000);
  return next.toISOString().slice(0, 19).replace('T', ' ');
}

/**
 * R3l C58: matcher for per-schedule destination subset filtering.
 *
 * The schedule may carry a destination_filter array (e.g.
 * ["offsite","encrypted"]) added in C54. Each destination may carry
 * a tags array (e.g. ["offsite","geo-redundant"]) also added in C54.
 *
 * Semantic: a backup pushes to a destination if AND ONLY IF
 *   filter is null                                         (no filter active)
 *   OR
 *   the intersection of filter and destination.tags is non-empty
 *
 * NULL on the schedule side or NULL/missing on the destination side
 * are handled per the contract documented in init.js around the C54
 * migration block. Malformed JSON in destination.tags is treated as
 * "no tags" (the destination fails the match if a filter is active)
 * so that schedules with explicit filters never silently push to
 * untaggable legacy destinations.
 *
 * Inputs:
 *   filter:         array of tag strings, or null
 *   destinationTags: raw TEXT from storage_destinations.tags column
 *                    (JSON-encoded array of strings, or null)
 *
 * Returns: true if the destination matches; false otherwise.
 */
function destinationMatchesFilter(filter, destinationTags) {
  // Null filter means "no filter active" — every destination matches.
  if (filter == null) return true;
  // Defensive: filter must be an array. Anything else => no match.
  if (!Array.isArray(filter)) return false;
  // Empty filter array means "match nothing" — explicit operator choice
  // to pause pushes on this schedule without disabling it entirely.
  if (filter.length === 0) return false;

  // Parse destination tags. Malformed JSON => treat as no tags.
  let tags = [];
  if (destinationTags != null && destinationTags !== '') {
    try {
      const parsed = JSON.parse(destinationTags);
      if (Array.isArray(parsed)) {
        tags = parsed.filter(t => typeof t === 'string');
      }
    } catch (_) {
      // malformed JSON in tags column — treat as no tags
      tags = [];
    }
  }

  // Set-intersection: at least one tag in common.
  return filter.some(f => tags.includes(f));
}

/**
 * Build the backupContext object that adapters consume. Reads the
 * four backup files (v2 format) from disk, hashes each, returns
 * the assembled context.
 *
 * Returns { ok: true, context } on success, { ok: false, error }
 * if any file is missing or unreadable.
 */
function buildBackupContext(backup) {
  if (backup.format_version !== 2) {
    return { ok: false, error: `backup ${backup.id} is format_version=${backup.format_version}; only v2 backups can be pushed` };
  }

  const filePaths = [
    { name: 'manifest.json',         absolutePath: backup.manifest_path },
    { name: 'archive.tar.zst.enc',   absolutePath: backup.archive_path },
    { name: 'manifest.sig',          absolutePath: backup.manifest_sig_path },
    { name: 'wrapped-key.bin',       absolutePath: backup.wrapped_key_path },
  ];

  const files = [];
  for (const f of filePaths) {
    if (!f.absolutePath) {
      return { ok: false, error: `backup ${backup.id} missing path for ${f.name}` };
    }
    if (!fs.existsSync(f.absolutePath)) {
      return { ok: false, error: `backup ${backup.id} file not found on disk: ${f.absolutePath}` };
    }
    let stat;
    try { stat = fs.statSync(f.absolutePath); } catch (err) {
      return { ok: false, error: `cannot stat ${f.absolutePath}: ${err.message}` };
    }
    let sha256;
    try { sha256 = sha256OfFile(f.absolutePath); } catch (err) {
      return { ok: false, error: `cannot hash ${f.absolutePath}: ${err.message}` };
    }
    files.push({
      name: f.name,
      absolutePath: f.absolutePath,
      sizeBytes: stat.size,
      sha256,
    });
  }

  // Source dir is the parent of the manifest (all four files share a parent)
  const sourceDir = path.dirname(backup.manifest_path);

  return {
    ok: true,
    context: {
      backupId: backup.id,
      sourceDir,
      files,
      manifestSha256: backup.sha256_hash,
      createdAt: backup.created_at,
    },
  };
}

/**
 * Adapter context = backupContext with the destination row attached
 * (with credentials decrypted by the caller). The adapter's push()
 * receives this whole object.
 */
function buildAdapterContext(backupContext, destinationWithCredentials) {
  return {
    ...backupContext,
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
 * Truncate an error message for storage in error_message column
 * (TEXT but practically limited; 1000 chars covers stack-free
 * messages while preventing pathological growth).
 */
function truncateError(msg) {
  if (typeof msg !== 'string') msg = String(msg);
  if (msg.length <= MAX_ERROR_MESSAGE_LEN) return msg;
  return msg.slice(0, MAX_ERROR_MESSAGE_LEN - 3) + '...';
}

// ── Core push attempt ────────────────────────────────────────────────────

/**
 * Run ONE push attempt for an existing backup_pushes row. Updates
 * the row to 'running' (incrementing attempt_count), runs the
 * adapter, and updates the row with success or failure state.
 *
 * Used by both pushBackup (initial attempt) and retryPush (re-attempt).
 */
async function runPushAttempt(db, pushId, adapterContext, options = {}) {
  const logger = options.logger || console;
  const adapter = base.getAdapter(adapterContext.destination.adapter);

  if (!adapter) {
    const errMsg = `adapter '${adapterContext.destination.adapter}' not loaded in registry`;
    db.prepare(`
      UPDATE backup_pushes
      SET status = 'failed',
          attempt_count = attempt_count + 1,
          last_attempt_at = datetime('now'),
          error_message = ?,
          next_retry_at = NULL
      WHERE id = ?
    `).run(truncateError(errMsg), pushId);
    return { pushId, ok: false, error: errMsg, retryable: false, nextRetryAt: null };
  }

  // Mark running + increment attempt_count atomically
  db.prepare(`
    UPDATE backup_pushes
    SET status = 'running',
        attempt_count = attempt_count + 1,
        last_attempt_at = datetime('now')
    WHERE id = ?
  `).run(pushId);

  // Read the just-incremented attempt_count for backoff calculation
  const currentAttempt = db.prepare('SELECT attempt_count FROM backup_pushes WHERE id = ?').get(pushId).attempt_count;

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
    // Adapter error: classify retryable
    const isRetryable = error instanceof base.DestinationAdapterError
      ? error.retryable
      : true;  // unknown error type: default retryable, scheduler eventually escalates

    const nextRetryAt = isRetryable ? calculateNextRetryAt(currentAttempt) : null;

    db.prepare(`
      UPDATE backup_pushes
      SET status = 'failed',
          error_message = ?,
          next_retry_at = ?
      WHERE id = ?
    `).run(truncateError(error.message), nextRetryAt, pushId);

    logger.warn(`backup-push: push attempt failed`, {
      pushId,
      backupId: adapterContext.backupId,
      destinationId: adapterContext.destination.id,
      destinationName: adapterContext.destination.name,
      attemptCount: currentAttempt,
      retryable: isRetryable,
      nextRetryAt,
      error: error.message,
    });

    return {
      pushId,
      ok: false,
      error: error.message,
      retryable: isRetryable,
      attemptCount: currentAttempt,
      nextRetryAt,
    };
  }

  // Success
  db.prepare(`
    UPDATE backup_pushes
    SET status = 'succeeded',
        pushed_at = datetime('now'),
        size_pushed_bytes = ?,
        destination_path = ?,
        error_message = NULL,
        next_retry_at = NULL
    WHERE id = ?
  `).run(result.bytesPushed, result.destinationPath, pushId);

  logger.info(`backup-push: push succeeded`, {
    pushId,
    backupId: adapterContext.backupId,
    destinationId: adapterContext.destination.id,
    destinationName: adapterContext.destination.name,
    attemptCount: currentAttempt,
    bytesPushed: result.bytesPushed,
    destinationPath: result.destinationPath,
    immutabilityVerified: result.immutabilityVerified,
  });

  return {
    pushId,
    ok: true,
    bytesPushed: result.bytesPushed,
    destinationPath: result.destinationPath,
    immutabilityVerified: result.immutabilityVerified,
    destinationMetadata: result.destinationMetadata,
    attemptCount: currentAttempt,
  };
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Orchestrate push of a backup to all enabled destinations.
 *
 * Called by services/backup.js after a successful v2 backup creation
 * (commits 8-9 of this phase). Failures don't propagate -- the
 * function records per-destination status in backup_pushes and
 * returns. Backup creation is independent of push success.
 */
async function pushBackup(db, backupId, options = {}) {
  const logger = options.logger || console;

  const backup = db.prepare('SELECT * FROM backups WHERE id = ?').get(backupId);
  if (!backup) {
    logger.warn(`backup-push: backup ${backupId} not found; skipping push`);
    return { ok: false, error: 'backup not found', destinations: [] };
  }
  if (backup.format_version !== 2) {
    logger.info(`backup-push: backup ${backupId} is v${backup.format_version}; only v2 backups support push`);
    return { ok: true, skipped: 'v1-format', destinations: [] };
  }
  if (backup.status !== 'verified') {
    logger.warn(`backup-push: backup ${backupId} status=${backup.status}; only verified backups push`);
    return { ok: false, error: `backup status is ${backup.status}, not verified`, destinations: [] };
  }

  const enabledDestinations = storageDestinations.listEnabledDestinations(db);
  if (enabledDestinations.length === 0) {
    logger.info(`backup-push: no enabled destinations; backup ${backupId} stays on-host only`);
    return { ok: true, destinations: [] };
  }

  // R3l C58: apply schedule's destination_filter if present.
  // options.destinationFilter is either an array (filter) or null/undefined
  // (no filter). The caller (services/backup.js performBackup) resolves
  // this from the originating schedule's destination_filter column.
  // Unfiltered callers (manual API pushes, retry paths) pass null and get
  // the pre-R3l behavior of pushing to all enabled destinations.
  const destinationFilter = options.destinationFilter == null ? null : options.destinationFilter;
  const matchingDestinations = destinationFilter == null
    ? enabledDestinations
    : enabledDestinations.filter(d => destinationMatchesFilter(destinationFilter, d.tags));

  if (destinationFilter != null) {
    const filteredOut = enabledDestinations.length - matchingDestinations.length;
    logger.info(
      `backup-push: schedule destination_filter applied for backup ${backupId} ` +
      `(filter=${JSON.stringify(destinationFilter)}, matched=${matchingDestinations.length}, filtered_out=${filteredOut})`
    );
    if (matchingDestinations.length === 0) {
      logger.warn(
        `backup-push: schedule destination_filter excludes all enabled destinations; ` +
        `backup ${backupId} not pushed to any remote (on-host copy retained)`
      );
      return { ok: true, destinations: [], filter: destinationFilter, filtered_out: filteredOut };
    }
  }

  const ctxResult = buildBackupContext(backup);
  if (!ctxResult.ok) {
    logger.error(`backup-push: cannot build context for backup ${backupId}: ${ctxResult.error}`);
    return { ok: false, error: ctxResult.error, destinations: [] };
  }
  const backupContext = ctxResult.context;

  const results = [];
  for (const destination of matchingDestinations) {
    // Insert a fresh row in queued state
    const insert = db.prepare(`
      INSERT INTO backup_pushes (backup_id, destination_id, status, attempt_count)
      VALUES (?, ?, 'queued', 0)
    `).run(backupId, destination.id);
    const pushId = insert.lastInsertRowid;

    const adapterContext = buildAdapterContext(backupContext, destination);

    let attemptResult;
    try {
      attemptResult = await runPushAttempt(db, pushId, adapterContext, options);
    } catch (err) {
      // Should not happen -- runPushAttempt catches adapter errors
      // and surfaces them via DB updates. Wrapping defensively.
      logger.error(`backup-push: unexpected error in runPushAttempt`, { pushId, error: err.message });
      db.prepare(`
        UPDATE backup_pushes
        SET status = 'failed',
            error_message = ?,
            next_retry_at = ?
        WHERE id = ?
      `).run(truncateError(`unexpected: ${err.message}`), calculateNextRetryAt(1), pushId);
      attemptResult = { pushId, ok: false, error: err.message, retryable: true, attemptCount: 1, nextRetryAt: calculateNextRetryAt(1) };
    }

    results.push({
      destinationId: destination.id,
      destinationName: destination.name,
      ...attemptResult,
    });
  }

  return { ok: true, destinations: results };
}

/**
 * Retry a single failed push by id. Looks up the destination and
 * backup, rebuilds the context, runs runPushAttempt with the
 * existing pushId.
 *
 * Returns:
 *   { ok: true, ... }                   on success
 *   { ok: false, error, ... }           on failure (retryable scheduled, or permanent)
 *   { ok: true, skipped: '...' }        if already-succeeded or max-attempts-reached
 *   { ok: false, error, fatal: true }   if destination or backup no longer exist
 */
async function retryPush(db, pushId, options = {}) {
  const logger = options.logger || console;

  const pushRow = db.prepare('SELECT * FROM backup_pushes WHERE id = ?').get(pushId);
  if (!pushRow) return { ok: false, error: 'push row not found', fatal: true };

  if (pushRow.status === 'succeeded') {
    return { ok: true, skipped: 'already-succeeded', pushId };
  }
  if (pushRow.attempt_count >= MAX_ATTEMPTS) {
    // Cap reached; ensure next_retry_at is cleared and stop retrying
    db.prepare(`UPDATE backup_pushes SET next_retry_at = NULL WHERE id = ?`).run(pushId);
    return { ok: false, skipped: 'max-attempts-reached', error: 'maximum retry attempts reached', pushId };
  }

  const destination = storageDestinations.getDestinationWithCredentials(db, pushRow.destination_id);
  if (!destination) {
    const errMsg = 'destination no longer exists';
    db.prepare(`
      UPDATE backup_pushes
      SET status = 'failed', error_message = ?, next_retry_at = NULL
      WHERE id = ?
    `).run(errMsg, pushId);
    return { ok: false, error: errMsg, fatal: true, pushId };
  }
  if (!destination.enabled) {
    return { ok: false, skipped: 'destination-disabled', pushId };
  }

  const backup = db.prepare('SELECT * FROM backups WHERE id = ?').get(pushRow.backup_id);
  if (!backup) {
    const errMsg = 'backup row no longer exists';
    db.prepare(`
      UPDATE backup_pushes
      SET status = 'failed', error_message = ?, next_retry_at = NULL
      WHERE id = ?
    `).run(errMsg, pushId);
    return { ok: false, error: errMsg, fatal: true, pushId };
  }

  const ctxResult = buildBackupContext(backup);
  if (!ctxResult.ok) {
    db.prepare(`
      UPDATE backup_pushes
      SET status = 'failed', error_message = ?, next_retry_at = NULL
      WHERE id = ?
    `).run(truncateError(ctxResult.error), pushId);
    return { ok: false, error: ctxResult.error, fatal: true, pushId };
  }

  const adapterContext = buildAdapterContext(ctxResult.context, destination);
  return runPushAttempt(db, pushId, adapterContext, options);
}

/**
 * Find all pushes whose retry time has passed and run them.
 * Called by the scheduler hourly (commits 13-14 of this phase).
 *
 * Returns { retried: <count>, results: [...] }.
 */
async function retryAllDuePushes(db, options = {}) {
  const logger = options.logger || console;

  const dueRows = db.prepare(`
    SELECT id FROM backup_pushes
    WHERE status = 'failed'
      AND next_retry_at IS NOT NULL
      AND next_retry_at <= datetime('now')
    ORDER BY next_retry_at ASC
    LIMIT ?
  `).all(RETRY_SCAN_BATCH_SIZE);

  if (dueRows.length === 0) return { retried: 0, results: [] };

  logger.info(`backup-push: retrying ${dueRows.length} due push(es)`);

  const results = [];
  for (const row of dueRows) {
    const r = await retryPush(db, row.id, options);
    results.push({ pushId: row.id, ...r });
  }

  return { retried: dueRows.length, results };
}

/**
 * Read the current state of a push by id.
 */
function getPushStatus(db, pushId) {
  const row = db.prepare('SELECT * FROM backup_pushes WHERE id = ?').get(pushId);
  return row || null;
}

/**
 * List all push attempts for a given backup.
 */
function listPushesForBackup(db, backupId) {
  return db.prepare(`
    SELECT bp.*, bd.name AS destination_name, bd.adapter AS destination_adapter
    FROM backup_pushes bp
    LEFT JOIN storage_destinations bd ON bd.id = bp.destination_id
    WHERE bp.backup_id = ?
    ORDER BY bp.created_at ASC
  `).all(backupId);
}

// ── Module exports ───────────────────────────────────────────────────────

module.exports = {
  // Public API
  pushBackup,
  retryPush,
  retryAllDuePushes,
  getPushStatus,
  listPushesForBackup,

  // Constants exposed for routes / scheduler
  MAX_ATTEMPTS,
  RETRY_DELAYS_SEC,
  DEFAULT_PUSH_TIMEOUT_MS,
};

// Internals exposed for tests
module.exports.__test__ = {
  calculateNextRetryAt,
  buildBackupContext,
  buildAdapterContext,
  truncateError,
  sha256OfFile,
  runPushAttempt,
  RETRY_SCAN_BATCH_SIZE,
};

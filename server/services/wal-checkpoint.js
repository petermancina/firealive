// ============================================================================
// server/services/wal-checkpoint.js
//
// R3l C62 — Safe coordination of SQLite PRAGMA wal_checkpoint operations.
//
// SQLite's WAL mode keeps modified pages in a separate file (the WAL) until
// a "checkpoint" copies them back into the main database file. Workstream 3
// incremental and differential backups need to coordinate carefully with
// SQLite's checkpoint machinery:
//
//   1. Incremental backups MUST NOT take checkpoints while reading frames,
//      because a checkpoint re-salts the WAL header and would invalidate the
//      position tracking that wal-extractor (C61) depends on.
//
//   2. Full backups SHOULD take a checkpoint either before or after
//      capturing the database state, so the archive's DB file reflects all
//      committed data without requiring WAL replay at restore time.
//
//   3. The two SQLite checkpoint modes that matter most for backup work are:
//
//        PASSIVE  - flush as many WAL pages back to the DB as possible
//                   WITHOUT blocking writers. Returns busy=1 if any pages
//                   couldn't be flushed because a reader is using them.
//
//        FULL     - same as PASSIVE but waits for active writers/readers
//                   to release locks, then flushes EVERYTHING. Returns
//                   busy=1 only if it timed out waiting.
//
//        RESTART  - same as FULL but also waits for active readers to
//                   finish before returning. Future writes use the WAL
//                   from offset 0 (a "reset" without truncating the file).
//
//        TRUNCATE - same as RESTART but also truncates the WAL file to
//                   size 0 on disk after the restart. This is the only
//                   checkpoint mode that actually shrinks the file.
//
// This module provides:
//
//   - runCheckpoint(db, mode)            single checkpoint, returns result
//   - runCheckpointWithRetry(db, mode, options)
//                                        busy-retry with exponential backoff
//                                        and total-wallclock timeout
//   - getWalStatus(db)                   inspect WAL state without checkpointing
//   - withAutoCheckpointDisabled(db, fn) run an async block with SQLite's
//                                        automatic checkpoint disabled, then
//                                        restore the previous threshold
//
// Module is intentionally minimal. Logic about WHEN to checkpoint per
// backup strategy lives in backup-incremental.js (C63) and
// backup-differential.js (C64).
// ============================================================================

const CHECKPOINT_MODES = ['PASSIVE', 'FULL', 'RESTART', 'TRUNCATE'];

/**
 * Run a single SQLite wal_checkpoint(mode) pragma. Returns a structured
 * result object describing what happened.
 *
 * The SQLite pragma returns three values per row:
 *   busy          1 if the checkpoint couldn't complete because writers
 *                 or readers held pages; 0 otherwise
 *   log_size      number of frames in the WAL after the call (will be
 *                 0 after a successful TRUNCATE; smaller-or-equal to
 *                 the pre-call size after PASSIVE/FULL/RESTART)
 *   checkpointed  number of frames actually transferred to the DB file
 *
 * better-sqlite3's db.pragma returns an array of row objects for
 * pragmas that yield results; for wal_checkpoint that's a single-row
 * array like [{ busy: 0, log: 5, checkpointed: 5 }]. This function
 * handles both array-shape and direct-object returns defensively.
 *
 * Throws:
 *   Error if mode is not one of CHECKPOINT_MODES.
 *   Error if db.pragma is not a function.
 *
 * Does NOT throw on busy. Busy is a legitimate outcome that callers
 * may want to retry; use runCheckpointWithRetry to do that automatically.
 *
 * Returns:
 *   {
 *     mode,            // 'PASSIVE' | 'FULL' | 'RESTART' | 'TRUNCATE'
 *     busy,            // boolean: true iff pragma returned busy=1
 *     logSize,         // integer or null if not returned
 *     checkpointed,    // integer or null if not returned
 *     durationMs,      // wallclock time spent in the pragma call
 *   }
 */
function runCheckpoint(db, mode) {
  if (!db || typeof db.pragma !== 'function') {
    throw new Error('runCheckpoint: db must be a better-sqlite3 Database with a .pragma() method');
  }
  if (!CHECKPOINT_MODES.includes(mode)) {
    throw new Error(`runCheckpoint: invalid mode '${mode}'; expected one of ${CHECKPOINT_MODES.join(', ')}`);
  }

  const started = Date.now();
  const raw = db.pragma(`wal_checkpoint(${mode})`);
  const durationMs = Date.now() - started;

  // Defensive shape handling: better-sqlite3 returns an array of row
  // objects for this pragma; older versions or alternative bindings
  // might return a single object. Treat both shapes uniformly.
  let row;
  if (Array.isArray(raw)) {
    row = raw.length > 0 ? raw[0] : null;
  } else if (raw && typeof raw === 'object') {
    row = raw;
  } else {
    row = null;
  }

  // Some sqlite bindings expose the columns as { busy, log, checkpointed }
  // while others use { busy, log_size, checkpointed }. Accept either.
  const busyVal = row ? (row.busy != null ? row.busy : null) : null;
  const logVal = row ? (row.log != null ? row.log : (row.log_size != null ? row.log_size : null)) : null;
  const ckptVal = row ? (row.checkpointed != null ? row.checkpointed : null) : null;

  return {
    mode,
    busy: busyVal === 1 || busyVal === true,
    logSize: typeof logVal === 'number' ? logVal : null,
    checkpointed: typeof ckptVal === 'number' ? ckptVal : null,
    durationMs,
  };
}

/**
 * Run a checkpoint with retry-on-busy and an overall timeout. Useful
 * for FULL / RESTART / TRUNCATE modes which can return busy when a
 * reader or writer holds pages temporarily.
 *
 * Options:
 *   maxAttempts     default 5
 *   delayMs         default 250    initial delay between retries (ms)
 *   backoffFactor   default 2      multiplier applied per attempt
 *   maxDelayMs      default 5000   cap for any single retry delay
 *   timeoutMs       default 30000  total wallclock budget; aborts retries
 *                                  once exceeded
 *   logger          optional       object with .info/.warn methods
 *
 * Returns the final checkpoint result plus an attempts array describing
 * each call's outcome. The returned `success` boolean is true iff the
 * final attempt had busy=false.
 *
 * Async so callers can await the per-attempt delays without spinning
 * the event loop.
 */
async function runCheckpointWithRetry(db, mode, options = {}) {
  const maxAttempts = Number.isInteger(options.maxAttempts) && options.maxAttempts > 0 ? options.maxAttempts : 5;
  const initialDelay = Number.isInteger(options.delayMs) && options.delayMs >= 0 ? options.delayMs : 250;
  const backoffFactor = typeof options.backoffFactor === 'number' && options.backoffFactor > 0 ? options.backoffFactor : 2;
  const maxDelay = Number.isInteger(options.maxDelayMs) && options.maxDelayMs > 0 ? options.maxDelayMs : 5000;
  const totalTimeout = Number.isInteger(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : 30000;
  const logger = options.logger || null;

  const startedAt = Date.now();
  const attempts = [];

  for (let i = 1; i <= maxAttempts; i++) {
    if (Date.now() - startedAt >= totalTimeout) {
      if (logger && typeof logger.warn === 'function') {
        logger.warn(`wal-checkpoint: ${mode} retry budget exhausted after ${attempts.length} attempts (timeoutMs=${totalTimeout})`);
      }
      break;
    }

    const result = runCheckpoint(db, mode);
    attempts.push({ attempt: i, ...result });

    if (!result.busy) {
      if (logger && typeof logger.info === 'function' && i > 1) {
        logger.info(`wal-checkpoint: ${mode} succeeded on attempt ${i}/${maxAttempts}`);
      }
      return { mode, success: true, attempts, final: result };
    }

    if (logger && typeof logger.info === 'function') {
      logger.info(`wal-checkpoint: ${mode} returned busy on attempt ${i}/${maxAttempts} (logSize=${result.logSize}, checkpointed=${result.checkpointed})`);
    }

    if (i < maxAttempts) {
      let delay = Math.min(initialDelay * Math.pow(backoffFactor, i - 1), maxDelay);
      // Don't sleep past the total timeout.
      const remaining = totalTimeout - (Date.now() - startedAt);
      if (remaining <= 0) break;
      if (delay > remaining) delay = remaining;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  return {
    mode,
    success: false,
    attempts,
    final: attempts.length > 0 ? attempts[attempts.length - 1] : null,
  };
}

/**
 * Read WAL-related status without taking a checkpoint. Returns:
 *   {
 *     journalMode,                // 'wal' if WAL mode active
 *     walAutocheckpointFrames,    // threshold in frames (0 disables)
 *   }
 *
 * Used by incremental/differential backups to confirm WAL mode is
 * active before attempting WAL-based capture, and to read the current
 * autocheckpoint threshold before changing it.
 */
function getWalStatus(db) {
  if (!db || typeof db.pragma !== 'function') {
    throw new Error('getWalStatus: db must be a better-sqlite3 Database with a .pragma() method');
  }

  // journal_mode pragma without value reads current setting and
  // returns a string in some bindings, an array of row objects in
  // others. Try the simple form first.
  let journalMode = null;
  try {
    const jm = db.pragma('journal_mode', { simple: true });
    journalMode = typeof jm === 'string' ? jm.toLowerCase() : null;
  } catch (_) {
    // Older bindings may not support {simple:true}; fall back to array form.
    const jmArr = db.pragma('journal_mode');
    const row = Array.isArray(jmArr) && jmArr.length > 0 ? jmArr[0] : null;
    if (row && typeof row.journal_mode === 'string') {
      journalMode = row.journal_mode.toLowerCase();
    }
  }

  let walAutocheckpointFrames = null;
  try {
    const ac = db.pragma('wal_autocheckpoint', { simple: true });
    if (typeof ac === 'number') walAutocheckpointFrames = ac;
  } catch (_) {
    const acArr = db.pragma('wal_autocheckpoint');
    const row = Array.isArray(acArr) && acArr.length > 0 ? acArr[0] : null;
    if (row && typeof row.wal_autocheckpoint === 'number') {
      walAutocheckpointFrames = row.wal_autocheckpoint;
    }
  }

  return { journalMode, walAutocheckpointFrames };
}

/**
 * Disable WAL auto-checkpoint for the duration of an async callback,
 * then restore the previous threshold. Used by incremental backups so
 * SQLite doesn't checkpoint underneath us while we're reading frames
 * (which would change salts and invalidate position tracking).
 *
 * If the callback throws, the previous threshold is still restored
 * via a finally block. The thrown error is re-thrown after restore.
 *
 * Returns whatever the callback returns.
 *
 *   await withAutoCheckpointDisabled(db, async () => {
 *     const frames = walExtractor.readWalFrames('./data/db.sqlite-wal');
 *     // ... archive the frames ...
 *   });
 */
async function withAutoCheckpointDisabled(db, fn) {
  if (!db || typeof db.pragma !== 'function') {
    throw new Error('withAutoCheckpointDisabled: db must be a better-sqlite3 Database');
  }
  if (typeof fn !== 'function') {
    throw new Error('withAutoCheckpointDisabled: fn must be a function');
  }

  // Capture current threshold so we can restore. Use getWalStatus to
  // get the value defensively across binding shapes.
  const before = getWalStatus(db);
  const previousAutocheckpoint = before.walAutocheckpointFrames;

  // Setting wal_autocheckpoint=0 disables automatic checkpointing.
  // Manual checkpoints via runCheckpoint() still work; only the size-
  // triggered auto-checkpoints are suppressed.
  db.pragma('wal_autocheckpoint = 0');

  try {
    return await fn();
  } finally {
    // Restore the previous threshold. If we couldn't read it before
    // (e.g. binding shape changed mid-process), default back to
    // SQLite's standard 1000-frame threshold.
    const restoreValue = (typeof previousAutocheckpoint === 'number' && previousAutocheckpoint >= 0)
      ? previousAutocheckpoint
      : 1000;
    try {
      db.pragma(`wal_autocheckpoint = ${restoreValue}`);
    } catch (_) {
      // Best-effort. If the db closed in fn(), restoring is irrelevant.
    }
  }
}

module.exports = {
  CHECKPOINT_MODES,
  runCheckpoint,
  runCheckpointWithRetry,
  getWalStatus,
  withAutoCheckpointDisabled,
};

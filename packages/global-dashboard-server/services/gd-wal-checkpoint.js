// =============================================================================
// FIREALIVE GD -- WAL Checkpoint Coordination
//
// Safe coordination of SQLite PRAGMA wal_checkpoint operations for the GD's
// WAL-tracked backup strategies. Twins the Regional wal-checkpoint service.
//
// SQLite's WAL mode keeps modified pages in a separate file (the WAL) until a
// "checkpoint" copies them back into the main database file. The GD incremental
// and differential backups coordinate carefully with SQLite's checkpoint
// machinery:
//
//   1. Incremental / differential backups MUST NOT take checkpoints while
//      reading frames, because a checkpoint re-salts the WAL header and would
//      invalidate the position tracking that gd-wal-extractor depends on.
//
//   2. Full backups SHOULD take a checkpoint either before or after capturing
//      the database state, so the archive's DB file reflects all committed data
//      without requiring WAL replay at restore time.
//
//   3. The four SQLite checkpoint modes that matter for backup work:
//
//        PASSIVE  - flush as many WAL pages back to the DB as possible WITHOUT
//                   blocking writers. Returns busy=1 if any pages couldn't be
//                   flushed because a reader is using them.
//        FULL     - same as PASSIVE but waits for active writers/readers to
//                   release locks, then flushes EVERYTHING. Returns busy=1 only
//                   if it timed out waiting.
//        RESTART  - same as FULL but also waits for active readers to finish
//                   before returning. Future writes use the WAL from offset 0.
//        TRUNCATE - same as RESTART but also truncates the WAL file to size 0 on
//                   disk. The only mode that actually shrinks the file.
//
// This module provides:
//   - runCheckpoint(db, mode)                 single checkpoint, returns result
//   - runCheckpointWithRetry(db, mode, opts)  busy-retry w/ backoff + timeout
//   - getWalStatus(db)                        inspect WAL state, no checkpoint
//   - withAutoCheckpointDisabled(db, fn)      run an async block with SQLite's
//                                             automatic checkpoint disabled, then
//                                             restore the previous threshold
//
// Intentionally minimal. The logic about WHEN to checkpoint per backup strategy
// lives in gd-backup-incremental / gd-backup-differential.
// =============================================================================

const CHECKPOINT_MODES = ['PASSIVE', 'FULL', 'RESTART', 'TRUNCATE'];

/**
 * Run a single SQLite wal_checkpoint(mode) pragma. Returns a structured result.
 *
 * The pragma returns three values per row: busy (1 if writers/readers held
 * pages), log_size (frames in the WAL after the call), checkpointed (frames
 * transferred to the DB). Handles both array-shape and direct-object pragma
 * returns defensively.
 *
 * Throws on an invalid mode or a db without .pragma(). Does NOT throw on busy --
 * busy is a legitimate outcome; use runCheckpointWithRetry to retry it.
 *
 * Returns { mode, busy, logSize, checkpointed, durationMs }.
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

  let row;
  if (Array.isArray(raw)) {
    row = raw.length > 0 ? raw[0] : null;
  } else if (raw && typeof raw === 'object') {
    row = raw;
  } else {
    row = null;
  }

  // Some bindings expose { busy, log, checkpointed }, others { busy, log_size,
  // checkpointed }. Accept either.
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
 * Run a checkpoint with retry-on-busy and an overall timeout. Useful for FULL /
 * RESTART / TRUNCATE which can return busy when a reader or writer holds pages.
 *
 * Options: maxAttempts (5), delayMs (250), backoffFactor (2), maxDelayMs (5000),
 * timeoutMs (30000), logger (optional, .info/.warn). Returns the final result
 * plus an attempts array; `success` is true iff the final attempt had busy=false.
 * Async so callers can await the per-attempt delays.
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
        logger.warn(`gd-wal-checkpoint: ${mode} retry budget exhausted after ${attempts.length} attempts (timeoutMs=${totalTimeout})`);
      }
      break;
    }

    const result = runCheckpoint(db, mode);
    attempts.push({ attempt: i, ...result });

    if (!result.busy) {
      if (logger && typeof logger.info === 'function' && i > 1) {
        logger.info(`gd-wal-checkpoint: ${mode} succeeded on attempt ${i}/${maxAttempts}`);
      }
      return { mode, success: true, attempts, final: result };
    }

    if (logger && typeof logger.info === 'function') {
      logger.info(`gd-wal-checkpoint: ${mode} returned busy on attempt ${i}/${maxAttempts} (logSize=${result.logSize}, checkpointed=${result.checkpointed})`);
    }

    if (i < maxAttempts) {
      let delay = Math.min(initialDelay * Math.pow(backoffFactor, i - 1), maxDelay);
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
 * Read WAL-related status without taking a checkpoint. Returns
 * { journalMode, walAutocheckpointFrames }. Used to confirm WAL mode is active
 * before WAL-based capture and to read the autocheckpoint threshold before
 * changing it.
 */
function getWalStatus(db) {
  if (!db || typeof db.pragma !== 'function') {
    throw new Error('getWalStatus: db must be a better-sqlite3 Database with a .pragma() method');
  }

  let journalMode = null;
  try {
    const jm = db.pragma('journal_mode', { simple: true });
    journalMode = typeof jm === 'string' ? jm.toLowerCase() : null;
  } catch (_) {
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
 * Disable WAL auto-checkpoint for the duration of an async callback, then
 * restore the previous threshold. Used by incremental/differential backups so
 * SQLite doesn't checkpoint underneath us while we're reading frames (which
 * would change salts and invalidate position tracking). Restores in a finally
 * block even if the callback throws; the error is re-thrown after restore.
 *
 *   await withAutoCheckpointDisabled(db, async () => { ...read frames... });
 */
async function withAutoCheckpointDisabled(db, fn) {
  if (!db || typeof db.pragma !== 'function') {
    throw new Error('withAutoCheckpointDisabled: db must be a better-sqlite3 Database');
  }
  if (typeof fn !== 'function') {
    throw new Error('withAutoCheckpointDisabled: fn must be a function');
  }

  const before = getWalStatus(db);
  const previousAutocheckpoint = before.walAutocheckpointFrames;

  // Setting wal_autocheckpoint=0 disables automatic checkpointing. Manual
  // checkpoints via runCheckpoint() still work; only the size-triggered
  // auto-checkpoints are suppressed.
  db.pragma('wal_autocheckpoint = 0');

  try {
    return await fn();
  } finally {
    // Restore the previous threshold, defaulting to SQLite's standard 1000 if
    // it couldn't be read before.
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

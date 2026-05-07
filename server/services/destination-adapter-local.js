// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Destination Adapter: Local Filesystem Mount
//
// Pushes the four backup files (archive.tar.zst.enc, wrapped-key.bin,
// manifest.json, manifest.sig) to a separate local filesystem path --
// typical use case is an off-host NAS mount, a separate physical
// volume, or a distinct filesystem root from the primary BACKUP_DIR.
//
// OPERATOR RESPONSIBILITY: this adapter does not probe whether the
// destination path is "genuinely off-host" -- the operator must
// configure a path on different physical storage from BACKUP_DIR
// for the off-host property to hold. A misconfiguration that points
// the local destination at the same disk as BACKUP_DIR will work
// (no error) but defeats the purpose of multi-destination push.
//
// LAYOUT MIRRORS SOURCE
//
// On host: <BACKUP_DIR>/firealive-backup-<ts>/
//   archive.tar.zst.enc
//   wrapped-key.bin
//   manifest.json
//   manifest.sig
//
// On destination: <config.path>/firealive-backup-<ts>/
//   archive.tar.zst.enc
//   wrapped-key.bin
//   manifest.json
//   manifest.sig
//
// Restoring from a destination copy is operationally identical to
// restoring from the original on-host copy: point BACKUP_DIR at the
// destination path, take a fresh DB connection, and the existing
// restore route handler does the rest. No format transformation.
//
// ATOMICITY
//
// Each backup is written into a hidden `.firealive-backup-<ts>.tmp/`
// dir under config.path, then atomically renamed to the visible name
// once all four files are in place. POSIX rename of a directory is
// atomic on the same filesystem -- a crash mid-push leaves a hidden
// temp dir, never a partial visible backup directory. Stale temp
// dirs older than 1 hour are cleaned at the start of each push run.
//
// VERIFY-AFTER-COPY
//
// After each file is copied, the adapter re-hashes the destination
// file and compares to the source sha256 from backupContext.files[].
// Catches silent disk-write corruption (rare but real on consumer
// hardware). On mismatch, the push aborts with retryable=true --
// could be transient and worth retrying.
//
// RETRYABLE TAXONOMY
//
// Permanent (retryable=false):
//   ENOENT (path doesn't exist), EACCES (no permission),
//   EROFS (read-only filesystem), ENOTDIR (path not a directory),
//   EISDIR / similar misconfig
//
// Transient (retryable=true):
//   ENOSPC (out of space; operator may free), EIO (I/O error),
//   EBUSY, ETIMEDOUT, hash-mismatch (rare; could indicate
//   transient flaky storage)
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const base = require('./destination-adapter-base');

const ADAPTER_NAME = 'local';
const STALE_TEMP_AGE_MS = 60 * 60 * 1000;       // 1 hour
const PROBE_TIMEOUT_MS = 5000;

// ── Helpers ──────────────────────────────────────────────────────────────

/**
 * Classify an Errno error as transient or permanent. Centralized so
 * push and probe agree on the taxonomy.
 */
function isRetryableErrno(err) {
  if (!err || typeof err.code !== 'string') return true;  // unknown -> retry
  const PERMANENT = new Set([
    'ENOENT',    // path not found
    'EACCES',    // no permission
    'EROFS',     // read-only
    'ENOTDIR',   // not a directory
    'EISDIR',    // is a directory (write to file path that's a dir)
    'EPERM',     // operation not permitted
    'EINVAL',    // invalid argument (malformed path)
    'ENAMETOOLONG',
  ]);
  return !PERMANENT.has(err.code);
}

/**
 * Compute SHA-256 of a file by streaming. Used by verify-after-copy.
 * Sync because better-sqlite3 patterns are sync; for multi-GB files
 * this could block but the adapter is single-purpose and the push
 * orchestrator runs adapters sequentially per backup.
 */
function sha256OfFile(filePath) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(64 * 1024);
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
 * Best-effort cleanup of stale `.firealive-backup-*.tmp/` directories
 * left by crashed prior pushes. Runs at the start of each push.
 */
function cleanStaleTempDirs(rootPath, logger) {
  try {
    if (!fs.existsSync(rootPath)) return;
    const cutoff = Date.now() - STALE_TEMP_AGE_MS;
    for (const ent of fs.readdirSync(rootPath, { withFileTypes: true })) {
      if (!ent.isDirectory()) continue;
      if (!ent.name.startsWith('.firealive-backup-') || !ent.name.endsWith('.tmp')) continue;
      const fullPath = path.join(rootPath, ent.name);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.mtimeMs < cutoff) {
          fs.rmSync(fullPath, { recursive: true, force: true });
          if (logger) logger.info(`destination-adapter-local: removed stale temp dir ${ent.name}`);
        }
      } catch { /* swallow per-entry */ }
    }
  } catch (err) {
    if (logger) logger.warn(`destination-adapter-local: cleanStaleTempDirs failed: ${err.message}`);
  }
}

// ── validateConfig ───────────────────────────────────────────────────────

function validateConfig(config) {
  if (!config || typeof config !== 'object') {
    return { ok: false, error: 'config must be an object' };
  }
  const pathCheck = base.requireAbsolutePath(config, 'path');
  if (!pathCheck.ok) return pathCheck;
  // The path doesn't have to exist at validation time -- it might be
  // a not-yet-mounted NAS that the operator will mount before the
  // first push runs. Existence is checked in probe(). What we check
  // here is structural well-formedness.
  return { ok: true };
}

// ── validateCredentials ─────────────────────────────────────────────────

function validateCredentials(credentials) {
  // Local adapter does not use credentials. Accept anything (including
  // null / undefined / empty object) at validation time.
  if (credentials !== null && credentials !== undefined && Object.keys(credentials || {}).length > 0) {
    return { ok: false, error: 'local adapter does not accept credentials; leave the field empty' };
  }
  return { ok: true };
}

// ── probe ───────────────────────────────────────────────────────────────

/**
 * Verify the configured path exists, is a directory, and is writable.
 * Writes a probe file (`.firealive-probe-<rand>`), reads it back, and
 * deletes it. The probe is fast (<5s typically) and creates no
 * persistent state.
 */
async function probe(config, _credentials) {
  const targetPath = config.path;
  if (!fs.existsSync(targetPath)) {
    return { ok: false, error: `path '${targetPath}' does not exist` };
  }
  let stat;
  try {
    stat = fs.statSync(targetPath);
  } catch (err) {
    return { ok: false, error: `cannot stat '${targetPath}': ${err.message}` };
  }
  if (!stat.isDirectory()) {
    return { ok: false, error: `path '${targetPath}' is not a directory` };
  }
  // Write probe
  const probeName = `.firealive-probe-${crypto.randomBytes(8).toString('hex')}`;
  const probePath = path.join(targetPath, probeName);
  const probeBytes = Buffer.from('FireAlive probe ' + new Date().toISOString());
  try {
    fs.writeFileSync(probePath, probeBytes);
    const readBack = fs.readFileSync(probePath);
    if (!readBack.equals(probeBytes)) {
      return { ok: false, error: `probe write/read roundtrip failed at '${targetPath}'` };
    }
  } catch (err) {
    return {
      ok: false,
      error: `cannot write to '${targetPath}': ${err.message}`,
      detail: { errno: err.code },
    };
  } finally {
    try { fs.unlinkSync(probePath); } catch { /* swallow */ }
  }
  return { ok: true, detail: { path: targetPath } };
}

// ── push ────────────────────────────────────────────────────────────────

/**
 * Push the four backup files into a per-backup subdirectory under
 * config.path. Atomic via hidden-temp + rename. Verify-after-copy
 * via SHA-256 round trip.
 */
async function push(backupContext, options = {}) {
  const logger = options.logger || console;
  const { destination, sourceDir, files, backupId } = backupContext;
  const targetRoot = destination.config.path;

  // Validate that the source directory and all source files exist
  if (!fs.existsSync(sourceDir)) {
    throw new base.DestinationAdapterError(
      `source backup directory not found: ${sourceDir}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: false },
    );
  }
  for (const f of files) {
    if (!fs.existsSync(f.absolutePath)) {
      throw new base.DestinationAdapterError(
        `source file not found: ${f.absolutePath}`,
        { adapter: ADAPTER_NAME, operation: 'push', retryable: false },
      );
    }
  }

  // Verify target root exists and is a directory
  if (!fs.existsSync(targetRoot)) {
    throw new base.DestinationAdapterError(
      `destination path '${targetRoot}' does not exist (probe should have caught this)`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: false },
    );
  }

  cleanStaleTempDirs(targetRoot, logger);

  // Derive the backup directory name from the source. We mirror it
  // to the destination so restoring from the destination is symmetric.
  const sourceDirName = path.basename(sourceDir);

  // Defense-in-depth: refuse to write under a sourceDirName that
  // contains path-traversal vectors. The on-host backup engine produces
  // names like 'firealive-backup-<iso>' so this is paranoia, not
  // something we expect to see in practice.
  let finalDir, tempDir;
  try {
    finalDir = base.safeJoinSegment(targetRoot, sourceDirName);
    tempDir = base.safeJoinSegment(targetRoot, '.' + sourceDirName + '.tmp');
  } catch (err) {
    throw new base.DestinationAdapterError(
      `unsafe source directory name: ${err.message}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: false },
    );
  }

  // If the final dir already exists, the push is idempotent: an
  // earlier successful push of the same backup. Re-pushing is a
  // no-op success. (The push orchestrator should not be calling
  // us in this state, but be defensive.)
  if (fs.existsSync(finalDir)) {
    logger.info(`destination-adapter-local: ${sourceDirName} already exists at destination; treating as idempotent success`, { destination: destination.id });
    let totalSize = 0;
    for (const f of files) totalSize += f.sizeBytes;
    return {
      destinationPath: finalDir,
      bytesPushed: totalSize,
      immutabilityVerified: null,
      destinationMetadata: { idempotent: true, alreadyPresent: true },
    };
  }

  // Create the temp dir; copy files; verify hashes; atomic rename.
  let bytesPushed = 0;
  try {
    fs.mkdirSync(tempDir, { recursive: true });

    for (const f of files) {
      const destPath = path.join(tempDir, f.name);
      try {
        fs.copyFileSync(f.absolutePath, destPath);
      } catch (err) {
        throw new base.DestinationAdapterError(
          `copy failed for ${f.name}: ${err.message}`,
          { adapter: ADAPTER_NAME, operation: 'push', retryable: isRetryableErrno(err), detail: { errno: err.code, file: f.name }, cause: err },
        );
      }

      // Verify-after-copy: re-hash and compare to the source sha256
      const observedSha = sha256OfFile(destPath);
      if (observedSha !== f.sha256) {
        throw new base.DestinationAdapterError(
          `verify-after-copy failed for ${f.name}: source sha256=${f.sha256} dest sha256=${observedSha}`,
          { adapter: ADAPTER_NAME, operation: 'push', retryable: true, detail: { file: f.name, expectedSha256: f.sha256, actualSha256: observedSha } },
        );
      }

      bytesPushed += f.sizeBytes;
    }

    // Atomic rename
    try {
      fs.renameSync(tempDir, finalDir);
    } catch (err) {
      throw new base.DestinationAdapterError(
        `atomic rename failed: ${err.message}`,
        { adapter: ADAPTER_NAME, operation: 'push', retryable: isRetryableErrno(err), detail: { errno: err.code }, cause: err },
      );
    }

    logger.info(`destination-adapter-local: pushed ${sourceDirName} (${bytesPushed} bytes) to ${finalDir}`);

    return {
      destinationPath: finalDir,
      bytesPushed,
      immutabilityVerified: destination.immutability_mode === 'append-only'
        ? { mode: 'append-only', trustedBy: 'operator-declared' }
        : null,
      destinationMetadata: {
        backupId,
        sourceDirName,
        finalDir,
        immutabilityMode: destination.immutability_mode,
      },
    };
  } catch (err) {
    // Clean up the temp dir on any failure
    if (fs.existsSync(tempDir)) {
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch { /* swallow */ }
    }
    if (err instanceof base.DestinationAdapterError) throw err;
    // Wrap unexpected errors
    throw new base.DestinationAdapterError(
      `unexpected push failure: ${err.message}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: true, cause: err },
    );
  }
}

// ── Adapter export + self-registration ──────────────────────────────────

const adapter = {
  name: ADAPTER_NAME,
  description: 'Push backups to a separate local filesystem mount path (off-host NAS, separate volume).',
  supportedImmutabilityModes: ['none', 'append-only', 'unknown'],
  validateConfig,
  validateCredentials,
  probe,
  push,
};

base.registerAdapter(adapter);

module.exports = adapter;

// Also export internals for test use
module.exports.__test__ = {
  isRetryableErrno,
  sha256OfFile,
  cleanStaleTempDirs,
  ADAPTER_NAME,
  PROBE_TIMEOUT_MS,
  STALE_TEMP_AGE_MS,
};

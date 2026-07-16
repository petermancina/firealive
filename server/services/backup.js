// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Engine (v2 encrypted-signed format)
//
// Replaces the v1 raw-.db-file-copy backup with a SOC-grade format:
// each backup is a directory containing four files
// (archive.tar.zst.enc, wrapped-key.bin, manifest.json, manifest.sig)
// produced by orchestrating the building blocks shipped earlier in
// R3d-1:
//
//   backup-archive.js        — tar + zstd + AES-256-GCM with fresh
//                              ephemeral key
//   backup-key-wrapping.js   — wraps the ephemeral key under the KEK
//                              (env-var scheme in R3d-1; KMS schemes
//                              add in R3d-4)
//   backup-manifest.js       — canonical-JSON manifest with per-file
//                              SHA-256
//   backup-signing-keys.js   — Ed25519 signs the manifest
//   backup-chain.js          — appends the CREATE entry to the
//                              cryptographic chain of custody (R3d-2)
//
// PUBLIC API
//
//   performBackup(type, options)
//     async; returns {
//       id, format_version, backup_dir, manifest_path, archive_path,
//       manifest_sig_path, wrapped_key_path, size_bytes,
//       manifest_sha256, status,
//       chain_entry,            // R3d-2: { id, prev_hash, this_hash,
//                                  chain_signing_key_id, created_at }
//                                  or null if append failed
//       chain_error,            // R3d-2: error message if append failed,
//                                  null if succeeded
//     }
//     throws on any failure of the BACKUP itself (with 'failed' status
//     row already inserted by the engine for audit). Chain append
//     failure does NOT throw -- backup succeeds in degraded mode with
//     chain_error populated and a loud log line so operators address
//     the chain-keypair issue without losing recoverability.
//
// CALLERS
//
//   server/services/scheduler.js    — scheduled cron trigger
//   server/routes/backup.js         — POST /api/backup (after route
//                                     update in commit 12)
//
// COMPATIBILITY WITH v1
//
// v1 backups (raw .db files) on disk are NOT migrated. They remain
// readable through internal restore via routes/restore.js (which is
// updated in a later R3d-1 commit to handle both format versions).
// New backups taken on v1.0.30+ are always v2.
//
// FILE LAYOUT ON DISK
//
//   <BACKUP_DIR>/firealive-backup-<iso-timestamp>/
//     archive.tar.zst.enc
//     wrapped-key.bin
//     manifest.json
//     manifest.sig
//
// ATOMICITY
//
// All four files are written into a hidden temp directory
// (`.firealive-backup-<ts>.tmp/`) and atomically renamed to the final
// directory name only after every file has been written successfully.
// A crash mid-write leaves a hidden temp dir, never a partial visible
// backup directory. Hidden temp dirs older than 1 hour are cleaned at
// the start of each backup run.
//
// CONSISTENT SNAPSHOT
//
// Uses better-sqlite3's `.backup()` method for the source-DB snapshot
// rather than fs.copyFileSync. This holds a read transaction during
// the copy and coordinates correctly with WAL mode -- the v1
// fs.copyFileSync approach could miss writes on a WAL-mode database.
// This is a bug fix along the way.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const { logger } = require('./logger');
const { getDb, DB_PATH } = require('../db/init');
const archiveSvc = require('./backup-archive');
const keyWrapSvc = require('./backup-key-wrapping');
const manifestSvc = require('./backup-manifest');
const signingKeysSvc = require('./backup-signing-keys');
const chainSvc = require('./backup-chain');
const backupPushSvc = require('./backup-push');
const storageRouting = require('./storage-routing');
const dataRoot = require('../lib/data-root');

const STALE_TEMP_AGE_MS = 60 * 60 * 1000;        // 1 hour
const DEFAULT_RETENTION_DAYS = 35;

// ── Helpers ──────────────────────────────────────────────────────────────

function resolveBackupDir(override) {
  // P1-1: BACKUP_DIR then BACKUP_PATH, else the canonical data root. Backups
  // used to land inside the application bundle -- an installer replaced the
  // very artifacts meant to survive it.
  return dataRoot.backupsDir(override);
}

function ensureDir(dir) {
  // 0700, and refuses an already group- or world-accessible directory.
  return dataRoot.ensureDir(dir);
}

/**
 * Generate a backup directory name from a timestamp. Mirrors the v1
 * filename pattern (firealive-backup-<...>) so directory listings sort
 * v1 .db files and v2 directories together.
 */
function backupDirName(date = new Date()) {
  const stamp = date.toISOString().replace(/[:.]/g, '-');
  return `firealive-backup-${stamp}`;
}

/**
 * Remove temp directories left behind by crashed prior runs. Looks for
 * `.firealive-backup-*.tmp` entries in the backup dir and removes any
 * older than STALE_TEMP_AGE_MS. Best-effort; does not throw.
 */
function cleanStaleTempDirs(backupDir) {
  try {
    if (!fs.existsSync(backupDir)) return;
    const cutoff = Date.now() - STALE_TEMP_AGE_MS;
    for (const ent of fs.readdirSync(backupDir, { withFileTypes: true })) {
      if (!ent.isDirectory()) continue;
      if (!ent.name.startsWith('.firealive-backup-') || !ent.name.endsWith('.tmp')) continue;
      const fullPath = path.join(backupDir, ent.name);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.mtimeMs < cutoff) {
          fs.rmSync(fullPath, { recursive: true, force: true });
          logger.info(`backup: removed stale temp dir ${ent.name}`);
        }
      } catch { /* swallow per-entry errors */ }
    }
  } catch (err) {
    logger.warn('backup: cleanStaleTempDirs failed', { error: err.message });
  }
}

/**
 * Apply retention policy. Removes both v1 .db files and v2 directories
 * whose mtime is older than the retention window. The retention applies
 * uniformly across formats -- a v1 backup older than the cutoff gets
 * cleaned the same as an old v2 backup. Operators wanting to preserve
 * specific historical backups should move them out of the backup dir.
 */
function cleanOldBackups(backupDir) {
  const retentionDays = parseInt(process.env.BACKUP_RETENTION_DAYS || String(DEFAULT_RETENTION_DAYS), 10);
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  try {
    if (!fs.existsSync(backupDir)) return;
    for (const ent of fs.readdirSync(backupDir, { withFileTypes: true })) {
      if (!ent.name.startsWith('firealive-backup-')) continue;
      const fullPath = path.join(backupDir, ent.name);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.mtimeMs >= cutoff) continue;
        if (ent.isDirectory()) {
          fs.rmSync(fullPath, { recursive: true, force: true });
          logger.info(`backup: deleted old v2 directory ${ent.name}`);
        } else if (ent.isFile() && ent.name.endsWith('.db')) {
          fs.unlinkSync(fullPath);
          logger.info(`backup: deleted old v1 file ${ent.name}`);
        }
      } catch (err) {
        logger.warn(`backup: retention cleanup failed for ${ent.name}`, { error: err.message });
      }
    }
  } catch (err) {
    logger.warn('backup: cleanOldBackups failed', { error: err.message });
  }
}

/**
 * Compute the sum of file sizes inside a directory (one level deep --
 * we know the v2 layout has exactly four files at the top level, no
 * subdirectories).
 */
function directorySize(dir) {
  let total = 0;
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ent.isFile()) total += fs.statSync(path.join(dir, ent.name)).size;
  }
  return total;
}

// ── Source-DB consistent snapshot ─────────────────────────────────────────

/**
 * Use better-sqlite3's online backup API to snapshot the live DB to a
 * temp file. Handles WAL mode coordination correctly. The temp file is
 * read into memory and then deleted; the in-memory bytes feed the v2
 * archive builder.
 *
 * Opens its OWN sqlite connection (separate from any caller's `db`)
 * because better-sqlite3 .backup() works between two connections.
 */
async function snapshotSourceDb(snapshotPath) {
  const sourceDb = new Database(DB_PATH, { readonly: true });
  try {
    await sourceDb.backup(snapshotPath);
  } finally {
    sourceDb.close();
  }
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Perform a v2 backup. Orchestrates all building blocks and produces
 * the four-file backup directory plus a verified row in the backups
 * table.
 *
 * Inputs:
 *   type     'on-demand' | 'scheduled' | 'snapshot'
 *   options  optional overrides:
 *     backupDir            override BACKUP_DIR / BACKUP_PATH env var
 *     compressionLevel     zstd level (default 3)
 *     keyWrappingScheme    'env-var' (R3d-1 only); 'aws-kms' /
 *                          'azure-key-vault' / 'gcp-kms' in R3d-4
 *     kekReference         env var name (env-var scheme) or KMS
 *                          ARN/URI (KMS schemes); defaults to
 *                          TIER1_ENCRYPTION_KEY for env-var
 *
 * Returns: see header comment at top of file for the full result shape.
 *
 * Throws on any failure -- but the backups row is already updated to
 * status='failed' before the throw, so auditability is preserved.
 */
async function performBackup(type = 'on-demand', options = {}) {
  if (!['scheduled', 'on-demand', 'snapshot'].includes(type)) {
    throw new Error(`performBackup: invalid type '${type}'`);
  }

  const backupDir          = resolveBackupDir(options.backupDir);
  const compressionLevel   = options.compressionLevel != null ? options.compressionLevel : archiveSvc.DEFAULT_ZSTD_LEVEL;
  const keyWrappingScheme  = options.keyWrappingScheme || 'env-var';
  const kekReference       = options.kekReference || (keyWrappingScheme === 'env-var' ? 'TIER1_ENCRYPTION_KEY' : '');

  ensureDir(backupDir);
  cleanStaleTempDirs(backupDir);

  const backupId  = crypto.randomBytes(16).toString('hex');
  const dirName   = backupDirName();
  const tempDir   = path.join(backupDir, `.${dirName}.tmp`);
  const finalDir  = path.join(backupDir, dirName);

  // Open DB connection for metadata + backups table operations. This is
  // separate from the snapshot-source connection; better-sqlite3 .backup()
  // works between two connections, and keeping them separate avoids
  // tying transactions together.
  const db = getDb();

  // B5q (Revision v3): resolve the destinations for this backup's type via the
  // storage-routing resolver -- a primary plus an optional secondary,
  // capped at two. Backups go to the destinations an admin designates for the
  // 'backup' type (snapshots inherit the backup route unless a 'snapshot' route
  // is set), and nowhere else -- the legacy unbounded fan-out and the per-schedule
  // destination_filter (R3l C58/C59) are retired. If no route is configured the
  // backup is still created and chain-attested on-host; it simply is not pushed
  // (the existing graceful-degradation posture) until an admin configures the route.
  const backupCategory = type === 'snapshot' ? 'snapshot' : 'backup';
  let backupDestinationRefs = [];
  try {
    const route = storageRouting.getRouteForType(db, backupCategory);
    if (route.configured && Array.isArray(route.destinations)) {
      backupDestinationRefs = route.destinations.map((d) => d.id);
    }
  } catch (routeErr) {
    logger.warn('backup: failed to resolve storage route; backup will not be pushed', {
      category: backupCategory, error: routeErr.message,
    });
  }

  // Insert the running row up front so partial failures are auditable.
  // The signing key id is needed up front too -- we want the row to
  // record which key signs this backup even if the actual signing fails
  // later in the run.
  let signingKey;
  try {
    signingKey = signingKeysSvc.getActiveSigningKey(db);
  } catch (err) {
    db.close();
    throw new Error(`performBackup: no active backup signing key (commit-3 boot path may have failed): ${err.message}`);
  }

  const fuseRow         = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  const schemaVersionRow = db.prepare("SELECT value FROM system_meta WHERE key = 'schema_version'").get();
  const sourceFuseCounter   = fuseRow ? parseInt(fuseRow.value, 10) : 0;
  const sourceSchemaVersion = schemaVersionRow ? schemaVersionRow.value : '1';

  db.prepare(`
    INSERT INTO backups (id, type, status, format_version, signing_key_id)
    VALUES (?, ?, 'running', 2, ?)
  `).run(backupId, type, signingKey.id);

  // Wrap the rest in try/catch so on any failure we can mark the row
  // 'failed' and clean up the temp dir.
  try {
    // 1. Snapshot the live DB to a temp .db file (WAL-coordinated)
    const snapshotPath = path.join(backupDir, `.${dirName}.snap.tmp`);
    await snapshotSourceDb(snapshotPath);
    let dbBytes;
    try {
      dbBytes = fs.readFileSync(snapshotPath);
    } finally {
      // Always clean the snapshot file, even if the read threw
      try { fs.unlinkSync(snapshotPath); } catch { /* ignore */ }
    }

    // 2. Tar + zstd + AES-256-GCM
    const archive = await archiveSvc.buildArchive(dbBytes, 'firealive.db', { compressionLevel });

    // 3. Wrap the ephemeral key under the KEK
    const wrappedKey = await keyWrapSvc.wrapKey(archive.ephemeralKey, {
      scheme: keyWrappingScheme,
      kekReference,
    });
    const wrappedKeySha = crypto.createHash('sha256').update(wrappedKey).digest('hex');

    // 4. Build the canonical manifest
    const manifestObj = manifestSvc.buildManifest({
      backupId,
      backupType: type,
      fileHashes: {
        archive:    { sizeBytes: archive.sizeBytes,    sha256: archive.sha256 },
        wrappedKey: { sizeBytes: wrappedKey.length,    sha256: wrappedKeySha },
      },
      compression: 'zstd',
      compressionLevel,
      keyWrappingScheme,
      kekReference,
      signingKeyId: signingKey.id,
      signingKeyFingerprint: signingKey.publicKeyFingerprint,
      sourceFuseCounter,
      sourceSchemaVersion,
    });

    // 5. Serialize + sign
    const manifestBytes = manifestSvc.serialize(manifestObj);
    const { signature } = signingKeysSvc.signManifest(db, manifestBytes);

    // 6. Write to temp dir, atomic-rename to final
    fs.mkdirSync(tempDir, { recursive: true });
    fs.writeFileSync(path.join(tempDir, manifestSvc.ARCHIVE_FILENAME),     archive.encryptedArchive);
    fs.writeFileSync(path.join(tempDir, manifestSvc.WRAPPED_KEY_FILENAME), wrappedKey);
    fs.writeFileSync(path.join(tempDir, manifestSvc.MANIFEST_FILENAME),    manifestBytes);
    fs.writeFileSync(path.join(tempDir, manifestSvc.SIGNATURE_FILENAME),   signature);
    fs.renameSync(tempDir, finalDir);

    // 7. Verify-after-write: re-read the manifest from disk, compare bytes
    const manifestOnDisk = fs.readFileSync(path.join(finalDir, manifestSvc.MANIFEST_FILENAME));
    if (!manifestOnDisk.equals(manifestBytes)) {
      throw new Error('verify-after-write: manifest bytes on disk differ from in-memory bytes (disk corruption?)');
    }
    const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');

    // 8. Update the row with the final paths + status
    const totalSize = directorySize(finalDir);
    db.prepare(`
      UPDATE backups
      SET status = 'verified',
          size_bytes = ?,
          sha256_hash = ?,
          manifest_path = ?,
          archive_path = ?,
          manifest_sig_path = ?,
          wrapped_key_path = ?
      WHERE id = ?
    `).run(
      totalSize,
      manifestSha256,
      path.join(finalDir, manifestSvc.MANIFEST_FILENAME),
      path.join(finalDir, manifestSvc.ARCHIVE_FILENAME),
      path.join(finalDir, manifestSvc.SIGNATURE_FILENAME),
      path.join(finalDir, manifestSvc.WRAPPED_KEY_FILENAME),
      backupId,
    );

    logger.info('backup: v2 backup complete', {
      id: backupId,
      type,
      dir: finalDir,
      sizeBytes: totalSize,
      manifestSha: manifestSha256.slice(0, 16),
    });

    // 9. Append CREATE entry to the cryptographic chain of custody.
    //
    // This commits the manifest hash + backup metadata to the
    // append-only chain so any subsequent attempt to delete or
    // substitute this backup leaves a detectable gap in the audit
    // trail. The chain entry is appended AFTER the backups row is
    // updated to 'verified' so the chain attestation reflects
    // verified state, not running state.
    //
    // DEGRADED-MODE on chain failure. If the chain append throws
    // (e.g., chain keypair missing, transient KEK issue), the
    // backup is still considered successful: it exists on disk,
    // is verified, and the row is 'verified'. What's missing is
    // the chain attestation. The failure is logged loudly and
    // surfaced in the result + audit trail; operators address the
    // chain issue separately and subsequent backups get full
    // attestation. The alternative (refusing all backups when
    // chain is unavailable) creates a worse failure mode where a
    // chain-keypair config issue blocks all recoverability.
    let chainEntry = null;
    let chainError = null;
    try {
      const archiveEntry  = manifestSvc.getFileEntry(manifestObj, manifestSvc.ARCHIVE_FILENAME);
      const wrappedEntry  = manifestSvc.getFileEntry(manifestObj, manifestSvc.WRAPPED_KEY_FILENAME);
      const result = chainSvc.appendChainEntry(db, {
        eventType: 'CREATE',
        backupId,
        payload: {
          backup_type: type,
          format_version: 2,
          manifest_sha256: manifestSha256,
          archive_sha256:    archiveEntry ? archiveEntry.sha256 : null,
          archive_size_bytes: archiveEntry ? archiveEntry.sizeBytes : null,
          wrapped_key_sha256: wrappedEntry ? wrappedEntry.sha256 : null,
          backup_signing_key_id: signingKey.id,
          source_fuse_counter:   sourceFuseCounter,
          source_schema_version: sourceSchemaVersion,
          total_size_bytes: totalSize,
          backup_dir_name: path.basename(finalDir),
        },
      });
      chainEntry = {
        id: result.id,
        prev_hash: result.prevHash,
        this_hash: result.thisHash,
        chain_signing_key_id: result.signingKeyId,
        created_at: result.createdAt,
      };
      logger.info('backup: chain CREATE entry appended', {
        id: backupId,
        chain_entry_id: result.id,
        this_hash: result.thisHash.slice(0, 16),
      });
    } catch (chainErr) {
      chainError = chainErr.message;
      logger.error(
        'backup: CHAIN ENTRY APPEND FAILED -- backup created without chain attestation. ' +
        'Address chain-signing-keys configuration; subsequent backups will retry chain append.',
        { id: backupId, error: chainErr.message },
      );
    }

    // 10. R3d-3: push backup to enabled destinations.
    //
    // FIRE-AND-FORGET BY DEFAULT. The push runs in the background
    // with its own DB connection so performBackup can return
    // quickly even when pushes are slow (multi-GB archives over
    // slow SFTP, etc.). Push status lands in the backup_pushes
    // table; admins and the scheduler can query separately.
    //
    // OPT-IN SYNCHRONOUS via options.awaitPush=true. Tests and
    // CLI workflows that want synchronous push results should
    // pass this flag. The function awaits push completion and
    // includes push_result in the return value. The caller
    // accepts that the response time is bounded by the slowest
    // destination's push completion.
    //
    // DEGRADED-MODE on push failure (matches chain-append posture):
    // a backup with chain attestation but failed pushes is still
    // considered successful. The on-host backup files exist and
    // are verified. Push failures are logged and tracked in
    // backup_pushes; the scheduler retries transient failures
    // with exponential backoff (commits 13-14 of this phase).
    // Refusing to acknowledge backup creation when pushes fail
    // would create a worse failure mode where a destination
    // outage blocks all backup operations.
    let pushResult = null;
    let pushScheduled = false;
    if (options.awaitPush) {
      try {
        pushResult = await backupPushSvc.pushBackup(db, backupId, {
          logger,
          // B5q (Revision v3): push to the resolved destination(s) for this type
          // (primary + optional secondary). destinationRef carries the primary for
          // back-compat; destinationRefs carries the full ordered list.
          destinationRef: backupDestinationRefs[0] || null,
          destinationRefs: backupDestinationRefs,
        });
      } catch (pushErr) {
        logger.error('backup: synchronous push orchestration crashed', { id: backupId, error: pushErr.message });
        pushResult = { ok: false, error: pushErr.message, crashed: true };
      }
    } else {
      void (async () => {
        let pushDb;
        try {
          pushDb = getDb();
          const r = await backupPushSvc.pushBackup(pushDb, backupId, {
            logger,
            // B5q (Revision v3): same resolved destination(s) on background dispatch
            destinationRef: backupDestinationRefs[0] || null,
            destinationRefs: backupDestinationRefs,
          });
          logger.info('backup: background push completed', {
            id: backupId,
            destinations: r.destinations ? r.destinations.length : 0,
            succeeded: r.destinations ? r.destinations.filter(d => d.ok).length : 0,
            failed: r.destinations ? r.destinations.filter(d => !d.ok).length : 0,
          });
        } catch (err) {
          logger.error('backup: background push orchestration crashed', { id: backupId, error: err.message });
        } finally {
          if (pushDb) { try { pushDb.close(); } catch { /* swallow */ } }
        }
      })();
      pushScheduled = true;
    }

    // 11. Retention cleanup (uniform across v1 + v2)
    cleanOldBackups(backupDir);

    return {
      id: backupId,
      format_version: 2,
      backup_dir: finalDir,
      manifest_path:     path.join(finalDir, manifestSvc.MANIFEST_FILENAME),
      archive_path:      path.join(finalDir, manifestSvc.ARCHIVE_FILENAME),
      manifest_sig_path: path.join(finalDir, manifestSvc.SIGNATURE_FILENAME),
      wrapped_key_path:  path.join(finalDir, manifestSvc.WRAPPED_KEY_FILENAME),
      size_bytes: totalSize,
      manifest_sha256: manifestSha256,
      status: 'verified',
      chain_entry: chainEntry,
      chain_error: chainError,
      push_result: pushResult,        // populated when awaitPush=true; null otherwise
      push_scheduled: pushScheduled,  // true when fire-and-forget; false when awaitPush=true
    };
  } catch (err) {
    // Mark row failed + clean up partial output
    try {
      db.prepare(`UPDATE backups SET status = 'failed' WHERE id = ?`).run(backupId);
    } catch (updateErr) {
      logger.error('backup: failed to mark row failed', { id: backupId, error: updateErr.message });
    }
    if (fs.existsSync(tempDir)) {
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    if (fs.existsSync(finalDir)) {
      // Should be rare -- atomic rename happens late in the flow -- but
      // guard against the corner where rename succeeded and a later
      // step (verify-after-write) failed.
      try { fs.rmSync(finalDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    logger.error('backup: failed', { id: backupId, type, error: err.message });
    throw err;
  } finally {
    db.close();
  }
}

module.exports = {
  // public API
  performBackup,

  // exposed for testing and for downstream services that want to
  // share retention behavior
  cleanOldBackups,
  cleanStaleTempDirs,
  resolveBackupDir,
  backupDirName,
};

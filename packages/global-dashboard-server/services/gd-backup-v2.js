// =============================================================================
// FIREALIVE GD -- Backup Engine (v2 encrypted-signed format)
//
// The GD's SOC-grade backup writer. A v2 backup is a directory containing four
// files, produced by orchestrating the primitives shipped earlier in this phase:
//
//   archive.tar.gz.enc  -- tar + gzip + AES-256-GCM with a fresh ephemeral key
//                          (gd-backup-archive)
//   wrapped-key.bin     -- the ephemeral key wrapped under the GD Tier-1 KEK
//                          (gd-backup-key-wrapping)
//   manifest.json       -- canonical-JSON manifest with per-file SHA-256
//                          (gd-backup-manifest)
//   manifest.sig        -- Ed25519 signature of manifest.json bytes
//                          (gd-backup-signing-keys)
//
// plus a CREATE entry appended to the backup attestation chain
// (gd-backup-chain), and a routed push of all four files through the shared GD
// storage-push engine (gd-storage-routing + gd-storage-push). This twins the
// Regional backup engine, adapted for the GD: gzip, the gd-tier1 key-wrapping
// scheme, the GD backups schema (backup_strategy, kind, format_version=2, sha256_hash,
// columns), the passed-in DB connection (never self-opened/closed), and
// VACUUM INTO for the consistent snapshot.
//
// PUBLIC API
//   performV2Backup(db, options)   async; creates the four-file backup, records a
//                                  'verified' backups row (format_version=2), chain-
//                                  attests it, and routes+pushes it. Returns the
//                                  result shape documented on the function. Throws
//                                  only on failure of the BACKUP itself (the row is
//                                  marked 'failed' before the throw for audit). A
//                                  chain-append failure or a push failure does NOT
//                                  throw -- the backup succeeds in degraded mode.
//   cleanOldBackups(db, options)   retention: deletes backup artifacts older than the
//                                 window by filesystem mtime (Regional model; no DB prune).
//                                  a parent anchor for a non-expired incremental/
//                                  differential.
//   retryDueV2BackupPushes(db, options)  retry sweep for failed v2 backup pushes.
//
// ATOMICITY
//   The four files are written into a hidden temp dir (.<id>-v2.tmp) and atomically
//   renamed to the final <id>-v2 directory only after every file is written. A
//   crash mid-write leaves a hidden temp dir, never a partial visible backup. Stale
//   temp dirs older than one hour are cleaned at the start of each run.
//
// CONSISTENT SNAPSHOT
//   VACUUM INTO produces a transactionally-consistent copy of the live DB
//   (WAL-coordinated), read into memory to feed the archive builder, then deleted.
// =============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const archiveSvc = require('./gd-backup-archive');
const keyWrapSvc = require('./gd-backup-key-wrapping');
const manifestSvc = require('./gd-backup-manifest');
const signingKeysSvc = require('./gd-backup-signing-keys');
const chainSvc = require('./gd-backup-chain');
const storageRouting = require('./gd-storage-routing');
const storagePush = require('./gd-storage-push');
const walExtractor = require('./gd-wal-extractor');
const walCheckpoint = require('./gd-wal-checkpoint');

const STALE_TEMP_AGE_MS = 60 * 60 * 1000;        // 1 hour
const DEFAULT_RETENTION_DAYS = 35;

// -- Path resolution ----------------------------------------------------------

function resolveBackupsDir(options) {
  return (options && options.backupsDir)
    || process.env.GD_BACKUPS_DIR
    || path.join(__dirname, '..', 'data', 'backups');
}

function resolveDbPath(options) {
  return (options && options.dbPath)
    || process.env.GD_DB_PATH
    || path.join(__dirname, '..', 'data', 'global-dashboard.db');
}

function resolveWalPath(options) {
  return resolveDbPath(options) + '-wal';
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// -- Source metadata ----------------------------------------------------------

// The manifest records the source fuse counter (restore anti-rollback anchor)
// and schema version. Prefer explicit options, then a system_meta row, then the
// package.json build fuse, then a safe default.
function readSourceMeta(db, options = {}) {
  let fuse = options.sourceFuseCounter;
  if (fuse == null) {
    try {
      const r = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
      if (r && r.value != null) fuse = parseInt(r.value, 10);
    } catch (_e) { /* table/row may be absent */ }
  }
  if (fuse == null || Number.isNaN(fuse)) {
    try {
      const pkg = require('../package.json');
      fuse = typeof pkg.fuseCounter === 'number' ? pkg.fuseCounter : 0;
    } catch (_e) { fuse = 0; }
  }

  let schema = options.sourceSchemaVersion;
  if (schema == null) {
    try {
      const r = db.prepare("SELECT value FROM system_meta WHERE key = 'schema_version'").get();
      if (r && r.value != null) schema = String(r.value);
    } catch (_e) { /* absent */ }
  }
  if (schema == null) schema = '1';

  return { sourceFuseCounter: fuse, sourceSchemaVersion: schema };
}

// -- Consistent snapshot ------------------------------------------------------

// VACUUM INTO a temp file, read it into memory, delete the temp file. Falls back
// to a raw file copy only if VACUUM INTO is unavailable.
function snapshotDbBytes(db, backupsDir, tag, options) {
  const snapPath = path.join(backupsDir, `.gd-v2-${tag}.snap.tmp`);
  try { fs.rmSync(snapPath, { force: true }); } catch (_e) { /* ignore */ }
  try {
    db.prepare('VACUUM INTO ?').run(snapPath);
  } catch (vacErr) {
    const dbPath = resolveDbPath(options);
    if (!fs.existsSync(dbPath)) {
      throw new Error(`gd-backup-v2: VACUUM INTO failed and no DB file at ${dbPath}: ${vacErr.message}`);
    }
    fs.copyFileSync(dbPath, snapPath);
  }
  let bytes;
  try {
    bytes = fs.readFileSync(snapPath);
  } finally {
    try { fs.rmSync(snapPath, { force: true }); } catch (_e) { /* ignore */ }
  }
  return bytes;
}

// -- Temp-dir hygiene ---------------------------------------------------------

// Remove hidden temp dirs left by crashed prior runs (.<id>-v2.tmp older than
// STALE_TEMP_AGE_MS). Best-effort; never throws.
function cleanStaleTempDirs(backupsDir) {
  try {
    if (!fs.existsSync(backupsDir)) return;
    const cutoff = Date.now() - STALE_TEMP_AGE_MS;
    for (const ent of fs.readdirSync(backupsDir, { withFileTypes: true })) {
      if (!ent.isDirectory()) continue;
      if (!ent.name.startsWith('.') || !ent.name.endsWith('-v2.tmp')) continue;
      const fullPath = path.join(backupsDir, ent.name);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.mtimeMs < cutoff) {
          fs.rmSync(fullPath, { recursive: true, force: true });
          console.log(`gd-backup-v2: removed stale temp dir ${ent.name}`);
        }
      } catch (_e) { /* per-entry errors swallowed */ }
    }
  } catch (err) {
    console.warn('gd-backup-v2: cleanStaleTempDirs failed:', err.message);
  }
}

// -- Retention ----------------------------------------------------------------

// Delete backup artifacts whose mtime is older than the retention window --
// the Regional Server's filesystem retention model (Regional: cleanOldBackups in
// backup.js). Retention is disk-space cleanup by mtime, not a database operation:
// backup rows are not queried or deleted, and there is no per-backup retention
// column. Temp/work staging entries (handled by cleanStaleTempDirs) are skipped.
// Best-effort; per-entry failures are logged and skipped. Returns { deleted, checked }.
function cleanOldBackups(db, options = {}) {
  const retentionDays = options.retentionDays != null
    ? options.retentionDays
    : parseInt(process.env.GD_BACKUP_RETENTION_DAYS || String(DEFAULT_RETENTION_DAYS), 10);
  const backupsDir = path.resolve(resolveBackupsDir(options));
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;

  let checked = 0;
  let deleted = 0;
  try {
    if (!fs.existsSync(backupsDir)) return { deleted, checked };
    for (const ent of fs.readdirSync(backupsDir, { withFileTypes: true })) {
      // Skip temp (.<name>.tmp) and work (_work-*) staging entries.
      if (ent.name.startsWith('.') || ent.name.startsWith('_')) continue;
      const isDir = ent.isDirectory();
      const isBackupFile = ent.isFile()
        && (ent.name.endsWith('.db') || ent.name.endsWith('.db.gz') || ent.name.endsWith('.tar.gz'));
      if (!isDir && !isBackupFile) continue;
      const fullPath = path.join(backupsDir, ent.name);
      try {
        checked++;
        const stat = fs.statSync(fullPath);
        if (stat.mtimeMs >= cutoff) continue;
        if (isDir) {
          fs.rmSync(fullPath, { recursive: true, force: true });
        } else {
          fs.unlinkSync(fullPath);
        }
        deleted++;
        console.log(`gd-backup-v2: retention deleted ${ent.name}`);
      } catch (delErr) {
        console.warn(`gd-backup-v2: retention cleanup failed for ${ent.name}:`, delErr.message);
      }
    }
  } catch (err) {
    console.warn('gd-backup-v2: cleanOldBackups failed:', err.message);
  }
  return { deleted, checked };
}

// -- Push (four-file) ---------------------------------------------------------

// Route + push the four backup files through the storage-push engine. Records a
// backup_pushes row per destination (primary + optional secondary). A backup
// with no route stays on-host. Mirrors gd-backup.js's push wiring for the
// four-file artifact.
async function pushV2BackupArtifact(db, { backupId, sourceDir, files, manifestSha256, dataType = 'backup', options = {} }) {
  const route = storageRouting.getRouteForType(db, dataType);
  if (!route.configured || !route.destinations || route.destinations.length === 0) {
    return { pushed: false, configured: false, reason: 'no destination configured' };
  }
  const destinations = storagePush.attachCredentials(db, route.destinations);
  if (destinations.length === 0) {
    return { pushed: false, configured: false, reason: 'no usable destination' };
  }

  const artifactContext = {
    artifactId: backupId,
    sourceDir,
    files,
    manifestSha256: manifestSha256 || null,
    createdAt: new Date().toISOString(),
  };
  const insertRow = (dbh, destination) => dbh.prepare(
    `INSERT INTO backup_pushes (backup_id, destination_id, status, attempt_count) VALUES (?, ?, 'queued', 0)`
  ).run(backupId, destination.id).lastInsertRowid;

  const result = await storagePush.pushToDestinations(db, {
    pushTable: 'backup_pushes',
    artifactContext,
    destinations,
    insertRow,
    options,
  });
  return { pushed: true, configured: true, destinations: result.destinations };
}

// Rebuild a v2 backup's four-file artifact context for a retry, from its backups
// row's stored file paths. Used by the storage-push retry sweep.
function rebuildV2BackupContext(db, pushRow) {
  const backup = db.prepare(`
    SELECT id, sha256_hash, created_at,
           manifest_path, archive_path, manifest_sig_path, wrapped_key_path
    FROM backups WHERE id = ?
  `).get(pushRow.backup_id);
  if (!backup) return { ok: false, error: 'backup row no longer exists', fatal: true };

  const specs = [
    { name: manifestSvc.ARCHIVE_FILENAME,     absolutePath: backup.archive_path },
    { name: manifestSvc.WRAPPED_KEY_FILENAME, absolutePath: backup.wrapped_key_path },
    { name: manifestSvc.MANIFEST_FILENAME,    absolutePath: backup.manifest_path },
    { name: manifestSvc.SIGNATURE_FILENAME,   absolutePath: backup.manifest_sig_path },
  ];
  for (const s of specs) {
    if (!s.absolutePath || !fs.existsSync(s.absolutePath)) {
      return { ok: false, error: `backup artifact file missing on disk: ${s.name}`, fatal: true };
    }
  }
  const hashed = storagePush.hashFilesForContext(specs);
  if (!hashed.ok) return { ok: false, error: hashed.error, fatal: true };

  const sourceDir = path.dirname(backup.manifest_path);
  return {
    ok: true,
    artifactContext: {
      artifactId: backup.id,
      sourceDir,
      files: hashed.files,
      manifestSha256: backup.sha256_hash,
      createdAt: backup.created_at,
    },
  };
}

/**
 * Re-attempt every due v2 backup push (status=failed, next_retry_at past).
 * Called by the scheduler. Returns { retried, results }.
 */
async function retryDueV2BackupPushes(db, options = {}) {
  return storagePush.retryDuePushes(db, {
    pushTable: 'backup_pushes',
    rebuildContext: rebuildV2BackupContext,
    options,
  });
}

// -- Public: perform a v2 backup ----------------------------------------------

/**
 * performV2Backup(db, options)
 *
 * options:
 *   backupsDir          override GD_BACKUPS_DIR
 *   compressionLevel    gzip level (default gd-backup-archive.DEFAULT_GZIP_LEVEL)
 *   keyWrappingScheme   'gd-tier1' (default)
 *   kekReference        'GD_ENCRYPTION_KEY' (default)
 *   retentionDays       filesystem retention window (mtime) applied by cleanOldBackups
 *   sourceFuseCounter / sourceSchemaVersion  manifest source metadata overrides
 *
 * Returns { id, format_version: 2, type: 'full'|'snapshot', backup_dir, manifest_path,
 * archive_path, manifest_sig_path, wrapped_key_path, size_bytes, manifest_sha256,
 * status: 'verified', chain_entry, chain_error, push }.
 *
 * Throws on failure of the backup itself (row already marked 'failed').
 */
async function performV2Backup(db, options = {}) {
  const mode = options.mode === 'snapshot' ? 'snapshot' : 'full';
  // Regional parity: backup_strategy is the strategy (full/snapshot); type is the
  // trigger (snapshot for a snapshot, else on-demand/daily-auto); kind='single-db'.
  const backupStrategy = mode;
  const triggerType = mode === 'snapshot'
    ? 'snapshot'
    : (options.triggerType === 'daily-auto' ? 'daily-auto' : 'on-demand');
  const backupsDir = resolveBackupsDir(options);
  const compressionLevel = options.compressionLevel != null ? options.compressionLevel : archiveSvc.DEFAULT_GZIP_LEVEL;
  const keyWrappingScheme = options.keyWrappingScheme || keyWrapSvc.DEFAULT_SCHEME;
  const kekReference = options.kekReference || keyWrapSvc.DEFAULT_KEK_REFERENCE;
  const retentionDays = options.retentionDays != null
    ? options.retentionDays
    : parseInt(process.env.GD_BACKUP_RETENTION_DAYS || String(DEFAULT_RETENTION_DAYS), 10);

  ensureDir(backupsDir);
  cleanStaleTempDirs(backupsDir);

  const backupId = crypto.randomBytes(8).toString('hex');
  const dirName = `${backupId}-v2`;
  const tempDir = path.join(backupsDir, `.${dirName}.tmp`);
  const finalDir = path.join(backupsDir, dirName);

  // Resolve the active signing key up front so the row records which key signs
  // this backup even if a later step fails.
  let signingKey;
  try {
    signingKey = signingKeysSvc.getActiveSigningKey(db);
  } catch (err) {
    throw new Error(`gd-backup-v2: no active backup signing key (boot ensureActiveKeypair may have failed): ${err.message}`);
  }

  const { sourceFuseCounter, sourceSchemaVersion } = readSourceMeta(db, options);

  db.prepare(`
    INSERT INTO backups (id, type, backup_strategy, kind, status, format_version, signing_key_id, created_at)
    VALUES (?, ?, ?, 'single-db', 'running', 2, ?, datetime('now'))
  `).run(backupId, triggerType, backupStrategy, signingKey.id);

  try {
    // 1. Consistent snapshot -> bytes. A 'full' also captures the WAL baseline so it
    // can anchor incrementals: read the WAL tail BEFORE the VACUUM (so the recorded
    // position is at/behind the snapshot's consistent point -- an incremental
    // capturing from it overlaps safely and never gaps), holding autocheckpoint off
    // across both so the WAL isn't re-salted in between. A 'snapshot' is a standalone
    // point-in-time backup: it records no WAL baseline and never anchors an
    // incremental. A DB not in WAL mode records no baseline either (incrementals then
    // escalate).
    let walEndPosition = null;
    let dbBytes;
    await walCheckpoint.withAutoCheckpointDisabled(db, async () => {
      if (mode === 'full') {
        const walPath = resolveWalPath(options);
        if (fs.existsSync(walPath)) {
          const pos = walExtractor.getWalCurrentPosition(walPath);
          if (pos.exists) {
            walEndPosition = walExtractor.serializeWalPosition({ offset: pos.offset, frameNo: pos.frameNo });
          }
        }
      }
      dbBytes = snapshotDbBytes(db, backupsDir, backupId, options);
    });

    // 2. tar + gzip + AES-256-GCM
    const archive = await archiveSvc.buildArchive(dbBytes, 'global-dashboard.db', { compressionLevel });

    // 3. Wrap the ephemeral key under the GD Tier-1 KEK
    const wrappedKey = await keyWrapSvc.wrapKey(archive.ephemeralKey, {
      scheme: keyWrappingScheme,
      kekReference,
    });
    const wrappedKeySha = crypto.createHash('sha256').update(wrappedKey).digest('hex');

    // 4. Build the canonical manifest
    const manifestObj = manifestSvc.buildManifest({
      backupId,
      backupType: triggerType,
      fileHashes: {
        archive:    { sizeBytes: archive.sizeBytes, sha256: archive.sha256 },
        wrappedKey: { sizeBytes: wrappedKey.length,  sha256: wrappedKeySha },
      },
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

    // 7. Verify-after-write: re-read the manifest and compare bytes
    const manifestOnDisk = fs.readFileSync(path.join(finalDir, manifestSvc.MANIFEST_FILENAME));
    if (!manifestOnDisk.equals(manifestBytes)) {
      throw new Error('verify-after-write: manifest bytes on disk differ from in-memory bytes');
    }
    const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');

    const archivePath     = path.join(finalDir, manifestSvc.ARCHIVE_FILENAME);
    const wrappedKeyPath   = path.join(finalDir, manifestSvc.WRAPPED_KEY_FILENAME);
    const manifestPath     = path.join(finalDir, manifestSvc.MANIFEST_FILENAME);
    const manifestSigPath  = path.join(finalDir, manifestSvc.SIGNATURE_FILENAME);

    // 8. Update the row: verified + paths + size. file_path stays NULL (v2).
    const totalSize = [archivePath, wrappedKeyPath, manifestPath, manifestSigPath]
      .reduce((sum, p) => sum + fs.statSync(p).size, 0);
    db.prepare(`
      UPDATE backups
      SET status = 'verified',
          size_bytes = ?,
          sha256_hash = ?,
          manifest_path = ?,
          archive_path = ?,
          manifest_sig_path = ?,
          wrapped_key_path = ?,
          wal_end_position = ?
      WHERE id = ?
    `).run(
      totalSize,
      manifestSha256,
      manifestPath,
      archivePath,
      manifestSigPath,
      wrappedKeyPath,
      walEndPosition,
      backupId,
    );

    console.log(`gd-backup-v2: backup ${backupId} verified (${totalSize} bytes, manifest ${manifestSha256.slice(0, 16)})`);

    // 9. Append CREATE entry to the attestation chain. Degraded-mode on failure:
    // the backup still exists and is verified; only the chain attestation is
    // missing. Logged loudly; subsequent backups retry chain append.
    let chainEntry = null;
    let chainError = null;
    try {
      const archiveEntry = manifestSvc.getFileEntry(manifestObj, manifestSvc.ARCHIVE_FILENAME);
      const wrappedEntry = manifestSvc.getFileEntry(manifestObj, manifestSvc.WRAPPED_KEY_FILENAME);
      const result = chainSvc.appendChainEntry(db, {
        eventType: 'CREATE',
        backupId,
        payload: {
          backup_type: mode,
          format_version: 2,
          manifest_sha256: manifestSha256,
          archive_sha256: archiveEntry ? archiveEntry.sha256 : null,
          archive_size_bytes: archiveEntry ? archiveEntry.sizeBytes : null,
          wrapped_key_sha256: wrappedEntry ? wrappedEntry.sha256 : null,
          backup_signing_key_id: signingKey.id,
          source_fuse_counter: sourceFuseCounter,
          source_schema_version: sourceSchemaVersion,
          total_size_bytes: totalSize,
          backup_dir_name: path.basename(finalDir),
        },
      });
      chainEntry = {
        id: result.id,
        prev_hash: result.prevHash,
        this_hash: result.thisHash,
        signing_key_fingerprint: result.signingKeyFingerprint,
        created_at: result.createdAt,
      };
      console.log(`gd-backup-v2: chain CREATE entry appended (chain id ${result.id}, ${result.thisHash.slice(0, 16)})`);
    } catch (chainErr) {
      chainError = chainErr.message;
      console.error(
        'gd-backup-v2: CHAIN ENTRY APPEND FAILED -- backup created without chain attestation. ' +
        `Address gd-backup-signing-keys configuration; subsequent backups will retry. error=${chainErr.message}`,
      );
    }

    // 10. Route + push all four files (best-effort; failures are retried).
    const hashed = storagePush.hashFilesForContext([
      { name: manifestSvc.ARCHIVE_FILENAME,     absolutePath: archivePath },
      { name: manifestSvc.WRAPPED_KEY_FILENAME, absolutePath: wrappedKeyPath },
      { name: manifestSvc.MANIFEST_FILENAME,    absolutePath: manifestPath },
      { name: manifestSvc.SIGNATURE_FILENAME,   absolutePath: manifestSigPath },
    ]);
    let push = { pushed: false, configured: false, reason: 'hash failed' };
    if (hashed.ok) {
      try {
        push = await pushV2BackupArtifact(db, {
          backupId, sourceDir: finalDir, files: hashed.files, manifestSha256,
          dataType: mode === 'snapshot' ? 'snapshot' : 'backup', options,
        });
      } catch (pushErr) {
        console.error('gd-backup-v2: push orchestration crashed:', pushErr.message);
        push = { pushed: false, configured: true, error: pushErr.message, crashed: true };
      }
    }

    // 11. Retention cleanup
    cleanOldBackups(db, { ...options, retentionDays });

    return {
      id: backupId,
      format_version: 2,
      type: mode,
      backup_dir: finalDir,
      manifest_path: manifestPath,
      archive_path: archivePath,
      manifest_sig_path: manifestSigPath,
      wrapped_key_path: wrappedKeyPath,
      size_bytes: totalSize,
      manifest_sha256: manifestSha256,
      status: 'verified',
      wal_end_position: walEndPosition,
      chain_entry: chainEntry,
      chain_error: chainError,
      push,
    };
  } catch (err) {
    try {
      db.prepare(`UPDATE backups SET status = 'failed' WHERE id = ?`).run(backupId);
    } catch (updateErr) {
      console.error('gd-backup-v2: failed to mark row failed:', updateErr.message);
    }
    if (fs.existsSync(tempDir)) {
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    }
    if (fs.existsSync(finalDir)) {
      try { fs.rmSync(finalDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    }
    console.error(`gd-backup-v2: backup ${backupId} FAILED:`, err.message);
    throw err;
  }
}

// Convenience wrapper: a standalone point-in-time single-DB backup. Same encrypted
// four-file artifact as a full backup, recorded type='snapshot' and routed to the
// snapshot category, but with no WAL baseline -- a snapshot is never an incremental
// anchor.
async function performSnapshotBackup(db, options = {}) {
  return performV2Backup(db, { ...options, mode: 'snapshot' });
}

module.exports = {
  // public API
  performV2Backup,
  performSnapshotBackup,
  cleanOldBackups,
  retryDueV2BackupPushes,

  // exposed for tests / reuse
  cleanStaleTempDirs,
  resolveBackupsDir,
  snapshotDbBytes,
  pushV2BackupArtifact,
  rebuildV2BackupContext,
  readSourceMeta,
};

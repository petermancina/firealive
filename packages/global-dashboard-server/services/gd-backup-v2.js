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
// scheme, the GD backups schema (type='full', format_version=2, hash/destination
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
//   cleanOldBackups(db, options)   retention: removes expired backups (both files
//                                  and rows), protecting any backup still serving as
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

// Delete expired backups (files + rows). A backup is expired when its
// retention_until has passed, or (when retention_until is unset) when its
// created_at is older than the retention window. An expired backup is NOT
// deleted while it still serves as a parent anchor (parent_backup_id or
// parent_full_backup_id) for any non-expired backup, so a live incremental or
// differential never loses its base. The attestation chain is append-only, so a
// deleted backup's CREATE entry remains as immutable history. Best-effort;
// per-backup failures are logged and skipped. Returns { deleted, checked }.
function cleanOldBackups(db, options = {}) {
  const retentionDays = options.retentionDays != null
    ? options.retentionDays
    : parseInt(process.env.GD_BACKUP_RETENTION_DAYS || String(DEFAULT_RETENTION_DAYS), 10);
  const backupsDir = path.resolve(resolveBackupsDir(options));
  const modifier = `-${retentionDays} days`;

  let checked = 0;
  let deleted = 0;
  try {
    // Expired candidates: retention_until in the past, OR retention_until unset
    // and created_at older than the window.
    const candidates = db.prepare(`
      SELECT id, destination, manifest_path, archive_path, manifest_sig_path, wrapped_key_path
      FROM backups
      WHERE (retention_until IS NOT NULL AND retention_until < datetime('now'))
         OR (retention_until IS NULL AND created_at < datetime('now', ?))
    `).all(modifier);

    // Anchor guard: a backup id that is a parent of some NON-expired backup.
    const isLiveAnchor = db.prepare(`
      SELECT 1 FROM backups child
      WHERE (child.parent_backup_id = ? OR child.parent_full_backup_id = ?)
        AND NOT (
          (child.retention_until IS NOT NULL AND child.retention_until < datetime('now'))
          OR (child.retention_until IS NULL AND child.created_at < datetime('now', ?))
        )
      LIMIT 1
    `);

    // Compute the deletable set (expired candidates that do NOT still anchor a
    // non-expired backup).
    const deletable = [];
    for (const b of candidates) {
      checked++;
      if (isLiveAnchor.get(b.id, b.id, modifier)) {
        console.log(`gd-backup-v2: retention skip ${b.id} (still anchors a non-expired backup)`);
        continue;
      }
      deletable.push(b);
    }

    // Remove parent-reference FK edges among the deletable set BEFORE deleting,
    // so deletion order is irrelevant: a parent and its (also-expired) child can
    // both be removed without a self-referential FK failure, at any chain depth.
    // The anchor guard already guarantees no non-expired backup references any
    // deletable row.
    const nullParents = db.prepare(
      'UPDATE backups SET parent_backup_id = NULL, parent_full_backup_id = NULL WHERE id = ?'
    );
    for (const b of deletable) {
      try { nullParents.run(b.id); } catch (_e) { /* best-effort */ }
    }

    for (const b of deletable) {
      try {
        removeBackupArtifactDir(b, backupsDir);
        db.prepare('DELETE FROM backups WHERE id = ?').run(b.id);
        deleted++;
        console.log(`gd-backup-v2: retention deleted backup ${b.id}`);
      } catch (delErr) {
        console.warn(`gd-backup-v2: retention failed for ${b.id}:`, delErr.message);
      }
    }
  } catch (err) {
    console.warn('gd-backup-v2: cleanOldBackups failed:', err.message);
  }
  return { deleted, checked };
}

// Remove a backup's on-disk per-backup directory, derived from any of its stored
// file paths. Only removes a directory that resolves inside backupsDir (safety
// against a corrupted/absolute path escaping the backups tree).
function removeBackupArtifactDir(backupRow, backupsDir) {
  const anyPath = backupRow.destination
    || backupRow.manifest_path || backupRow.archive_path
    || backupRow.manifest_sig_path || backupRow.wrapped_key_path;
  if (!anyPath) return;
  const artifactDir = path.resolve(path.dirname(anyPath));
  const withSep = backupsDir.endsWith(path.sep) ? backupsDir : backupsDir + path.sep;
  if (artifactDir !== backupsDir && !artifactDir.startsWith(withSep)) {
    // Path escapes the backups tree; refuse to delete it.
    console.warn(`gd-backup-v2: retention refusing to delete out-of-tree dir ${artifactDir}`);
    return;
  }
  if (fs.existsSync(artifactDir)) {
    fs.rmSync(artifactDir, { recursive: true, force: true });
  }
}

// -- Push (four-file) ---------------------------------------------------------

// Route + push the four backup files through the storage-push engine. Records a
// backup_pushes row per destination (primary + optional secondary). A backup
// with no route stays on-host. Mirrors gd-backup.js's push wiring for the
// four-file artifact.
async function pushV2BackupArtifact(db, { backupId, sourceDir, files, manifestSha256, options = {} }) {
  const route = storageRouting.getRouteForType(db, 'backup');
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
    SELECT id, destination, hash, created_at,
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
      manifestSha256: backup.hash,
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
 *   retentionDays       retention window applied to this backup's retention_until
 *   sourceFuseCounter / sourceSchemaVersion  manifest source metadata overrides
 *
 * Returns { id, format_version: 2, type: 'full', backup_dir, manifest_path,
 * archive_path, manifest_sig_path, wrapped_key_path, size_bytes, manifest_sha256,
 * status: 'verified', chain_entry, chain_error, push }.
 *
 * Throws on failure of the backup itself (row already marked 'failed').
 */
async function performV2Backup(db, options = {}) {
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
    INSERT INTO backups (id, type, status, format_version, signing_key_id, created_at)
    VALUES (?, 'full', 'running', 2, ?, datetime('now'))
  `).run(backupId, signingKey.id);

  try {
    // 1. Consistent snapshot -> bytes
    const dbBytes = snapshotDbBytes(db, backupsDir, backupId, options);

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
      backupType: 'full',
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

    // 8. Update the row: verified + paths + size + retention_until
    const totalSize = [archivePath, wrappedKeyPath, manifestPath, manifestSigPath]
      .reduce((sum, p) => sum + fs.statSync(p).size, 0);
    db.prepare(`
      UPDATE backups
      SET status = 'verified',
          size_bytes = ?,
          hash = ?,
          manifest_path = ?,
          archive_path = ?,
          manifest_sig_path = ?,
          wrapped_key_path = ?,
          destination = ?,
          retention_until = datetime('now', ?)
      WHERE id = ?
    `).run(
      totalSize,
      manifestSha256,
      manifestPath,
      archivePath,
      manifestSigPath,
      wrappedKeyPath,
      archivePath,
      `+${retentionDays} days`,
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
          backup_type: 'full',
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
          backupId, sourceDir: finalDir, files: hashed.files, manifestSha256, options,
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
      type: 'full',
      backup_dir: finalDir,
      manifest_path: manifestPath,
      archive_path: archivePath,
      manifest_sig_path: manifestSigPath,
      wrapped_key_path: wrappedKeyPath,
      size_bytes: totalSize,
      manifest_sha256: manifestSha256,
      status: 'verified',
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

module.exports = {
  // public API
  performV2Backup,
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

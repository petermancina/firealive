// =============================================================================
// FIREALIVE GD -- Backup Strategy Writer
//
// The Global Dashboard's backup writers. Two strategies live here:
//
//   full-suite : a complete, self-describing archive -- a transactionally-
//                consistent DB snapshot (VACUUM INTO) plus a config snapshot and
//                a version manifest, tar+gzipped. The heavyweight, restore-ready
//                backup. (Extracted from the index.js gdPerformFullSuiteBackup
//                implementation and given routing + push.)
//
//   snapshot   : a lightweight point-in-time DB copy (VACUUM INTO + gzip) for
//                fast, frequent capture. Routes under the 'snapshot' data type,
//                which inherits the 'backup' route unless it has its own.
//
// Each artifact is created in its own per-backup directory under the GD backups
// dir (so the destination adapters, which mirror the source directory name, get
// a unique target per backup), a backups row is recorded, and the artifact is
// routed and pushed through the shared GD storage-push engine -- a primary plus
// an optional secondary, each recorded in backup_pushes and retried on failure.
// A backup is always created on-host even when no destination is routed or a
// push fails; the push is best-effort and independently retried.
//
// The incremental and differential strategies are added by the sibling
// gd-backup-incremental / gd-backup-differential writers.
//
// Schema: db-init.js -> backups (type IN full/incremental/differential/snapshot)
// + backup_pushes (per-push tracking). Routing via gd-storage-routing; push +
// retry via gd-storage-push.
// =============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { execFileSync } = require('child_process');
const { pipeline } = require('stream/promises');

const storageRouting = require('./gd-storage-routing');
const storagePush = require('./gd-storage-push');

// --- Path resolution ---------------------------------------------------------

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

// --- Version manifest --------------------------------------------------------

function buildVersionManifest(db, id) {
  const mcs = db.prepare('SELECT COUNT(*) AS n FROM management_consoles').get().n;
  const mcsActive = db.prepare("SELECT COUNT(*) AS n FROM management_consoles WHERE status='active'").get().n;
  const sks = db.prepare('SELECT COUNT(*) AS n FROM signing_keys').get().n;
  const sksActive = db.prepare("SELECT COUNT(*) AS n FROM signing_keys WHERE status='active'").get().n;
  let versionInfo = { version: 'unknown', fuse_counter: null, build_id: null };
  try {
    const pkg = require('../package.json');
    versionInfo = {
      version: pkg.version || 'unknown',
      fuse_counter: typeof pkg.fuseCounter === 'number' ? pkg.fuseCounter : null,
      build_id: pkg.buildId || null,
    };
  } catch (_e) { /* keep defaults */ }
  return {
    format: 'firealive-gd-full-suite-v1',
    backup_id: id,
    captured_at: new Date().toISOString(),
    version: versionInfo,
    management_consoles: { total: mcs, active: mcsActive },
    signing_keys: { total: sks, active: sksActive },
    side: 'gd',
  };
}

// --- Artifact builders (on-host, no push) ------------------------------------

// Consistent DB copy: VACUUM INTO is the SQLite-canonical hot-snapshot method
// (transactionally consistent, races nothing). Fall back to a raw file copy only
// if VACUUM INTO is unavailable.
function copyDbSnapshot(db, destPath, options) {
  try {
    db.prepare('VACUUM INTO ?').run(destPath);
  } catch (_vacErr) {
    const dbPath = resolveDbPath(options);
    if (!fs.existsSync(dbPath)) {
      throw new Error(`GD database not found at ${dbPath} (VACUUM INTO unavailable and no file to copy)`);
    }
    fs.copyFileSync(dbPath, destPath);
  }
}

// Build the full-suite tar.gz in a per-backup directory. Returns
// { id, artifactDir, archivePath, archiveFileName, manifest }.
function buildFullSuiteArtifact(db, options = {}) {
  const backupsDir = resolveBackupsDir(options);
  if (!fs.existsSync(backupsDir)) fs.mkdirSync(backupsDir, { recursive: true });

  const id = crypto.randomBytes(8).toString('hex');
  const artifactDir = path.join(backupsDir, `${id}-full`);
  const workDir = path.join(artifactDir, '_work');
  fs.mkdirSync(workDir, { recursive: true });

  try {
    // 1. Transactionally-consistent DB snapshot.
    copyDbSnapshot(db, path.join(workDir, 'global-dashboard.db'), options);

    // 2. config-snapshot.json (all config rows).
    const configRows = db.prepare('SELECT key, value FROM config').all();
    const configSnap = {};
    for (const r of configRows) configSnap[r.key] = r.value;
    fs.writeFileSync(path.join(workDir, 'config-snapshot.json'), JSON.stringify(configSnap, null, 2), 'utf8');

    // 3. version-manifest.json.
    const manifest = buildVersionManifest(db, id);
    fs.writeFileSync(path.join(workDir, 'version-manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');

    // 4. tar+gzip the workdir into a single archive inside the per-backup dir.
    const archiveFileName = 'firealive-gd-full-suite.tar.gz';
    const archivePath = path.join(artifactDir, archiveFileName);
    execFileSync('tar', ['-czf', archivePath, '-C', workDir, '.'], { stdio: ['ignore', 'ignore', 'pipe'] });

    // 5. Cleanup the workdir; the archive remains in artifactDir.
    fs.rmSync(workDir, { recursive: true, force: true });

    return { id, artifactDir, archivePath, archiveFileName, manifest };
  } catch (err) {
    try { if (fs.existsSync(artifactDir)) fs.rmSync(artifactDir, { recursive: true, force: true }); }
    catch (_cleanupErr) { /* swallow */ }
    throw err;
  }
}

// Build a lightweight gzipped DB snapshot in a per-snapshot directory. Returns
// { id, artifactDir, archivePath, archiveFileName }.
async function buildSnapshotArtifact(db, options = {}) {
  const backupsDir = resolveBackupsDir(options);
  if (!fs.existsSync(backupsDir)) fs.mkdirSync(backupsDir, { recursive: true });

  const id = crypto.randomBytes(8).toString('hex');
  const artifactDir = path.join(backupsDir, `${id}-snapshot`);
  fs.mkdirSync(artifactDir, { recursive: true });

  try {
    const dbCopyPath = path.join(artifactDir, 'global-dashboard-snapshot.db');
    copyDbSnapshot(db, dbCopyPath, options);

    // Compress via streaming gzip (handles large DBs without buffering).
    const archiveFileName = 'global-dashboard-snapshot.db.gz';
    const archivePath = path.join(artifactDir, archiveFileName);
    await pipeline(fs.createReadStream(dbCopyPath), zlib.createGzip(), fs.createWriteStream(archivePath));
    fs.rmSync(dbCopyPath, { force: true });

    return { id, artifactDir, archivePath, archiveFileName };
  } catch (err) {
    try { fs.rmSync(artifactDir, { recursive: true, force: true }); } catch (_cleanupErr) { /* swallow */ }
    throw err;
  }
}

// --- Push --------------------------------------------------------------------

// Route + push a built backup artifact through the storage-push engine. Records
// a backup_pushes row per destination (primary + optional secondary). Returns a
// push summary; a backup with no route stays on-host.
async function pushBackupArtifact(db, { backupId, dataType, sourceDir, files, options = {} }) {
  const route = storageRouting.getRouteForType(db, dataType);
  if (!route.configured || !route.destinations || route.destinations.length === 0) {
    return { pushed: false, configured: false, reason: 'no destination configured' };
  }
  const destinations = storagePush.attachCredentials(db, route.destinations);
  if (destinations.length === 0) {
    return { pushed: false, configured: false, reason: 'no usable destination' };
  }

  const manifestSha256 = files && files[0] ? files[0].sha256 : null;
  const artifactContext = {
    artifactId: backupId,
    sourceDir,
    files,
    manifestSha256,
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

// Rebuild a backup's artifact context for a retry, from its backups row. Used by
// the storage-push retry sweep. Returns { ok, artifactContext } | { ok:false,
// error, fatal }.
function rebuildBackupContext(db, pushRow) {
  const backup = db.prepare('SELECT id, destination, hash, created_at FROM backups WHERE id = ?').get(pushRow.backup_id);
  if (!backup) return { ok: false, error: 'backup row no longer exists', fatal: true };
  if (!backup.destination || !fs.existsSync(backup.destination)) {
    return { ok: false, error: 'backup artifact missing on disk', fatal: true };
  }
  const sourceDir = path.dirname(backup.destination);
  const fileName = path.basename(backup.destination);
  const hashed = storagePush.hashFilesForContext([{ name: fileName, absolutePath: backup.destination }]);
  if (!hashed.ok) return { ok: false, error: hashed.error, fatal: true };
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

// --- Public entrypoints ------------------------------------------------------

/**
 * performFullSuiteBackup(db, options)
 *
 * Create a full-suite backup on-host, record it, and route + push it. Returns
 * { id, type: 'full', kind: 'full-suite', destination, size_bytes, hash,
 *   manifest, status, push }. The push field is the push summary (or a
 *   not-configured marker); a push failure never fails the backup.
 */
async function performFullSuiteBackup(db, options = {}) {
  const art = buildFullSuiteArtifact(db, options);
  const hashed = storagePush.hashFilesForContext([{ name: art.archiveFileName, absolutePath: art.archivePath }]);
  if (!hashed.ok) throw new Error(`gd-backup: cannot hash full-suite archive: ${hashed.error}`);
  const file = hashed.files[0];

  db.prepare(
    `INSERT INTO backups (id, type, status, size_bytes, hash, destination, created_at)
     VALUES (?, 'full', 'completed', ?, ?, ?, datetime('now'))`
  ).run(art.id, file.sizeBytes, file.sha256, art.archivePath);

  const push = await pushBackupArtifact(db, {
    backupId: art.id, dataType: 'backup', sourceDir: art.artifactDir, files: hashed.files, options,
  });

  return {
    id: art.id, type: 'full', kind: 'full-suite', destination: art.archivePath,
    size_bytes: file.sizeBytes, hash: file.sha256, manifest: art.manifest, status: 'completed', push,
  };
}

/**
 * performSnapshot(db, options)
 *
 * Create a lightweight gzipped DB snapshot on-host, record it (type='snapshot'),
 * and route + push it under the 'snapshot' data type (which inherits the
 * 'backup' route unless configured). Returns { id, type: 'snapshot', kind:
 * 'db-snapshot', destination, size_bytes, hash, status, push }.
 */
async function performSnapshot(db, options = {}) {
  const art = await buildSnapshotArtifact(db, options);
  const hashed = storagePush.hashFilesForContext([{ name: art.archiveFileName, absolutePath: art.archivePath }]);
  if (!hashed.ok) throw new Error(`gd-backup: cannot hash snapshot archive: ${hashed.error}`);
  const file = hashed.files[0];

  db.prepare(
    `INSERT INTO backups (id, type, status, size_bytes, hash, destination, created_at)
     VALUES (?, 'snapshot', 'completed', ?, ?, ?, datetime('now'))`
  ).run(art.id, file.sizeBytes, file.sha256, art.archivePath);

  const push = await pushBackupArtifact(db, {
    backupId: art.id, dataType: 'snapshot', sourceDir: art.artifactDir, files: hashed.files, options,
  });

  return {
    id: art.id, type: 'snapshot', kind: 'db-snapshot', destination: art.archivePath,
    size_bytes: file.sizeBytes, hash: file.sha256, status: 'completed', push,
  };
}

/**
 * retryDueBackupPushes(db, options)
 *
 * Re-attempt every due backup push (status=failed, next_retry_at past). Called by
 * the scheduler. Returns { retried, results }.
 */
async function retryDueBackupPushes(db, options = {}) {
  return storagePush.retryDuePushes(db, {
    pushTable: 'backup_pushes',
    rebuildContext: rebuildBackupContext,
    options,
  });
}

module.exports = {
  performFullSuiteBackup,
  performSnapshot,
  retryDueBackupPushes,
  // exposed for tests / reuse
  buildVersionManifest,
  buildFullSuiteArtifact,
  buildSnapshotArtifact,
  pushBackupArtifact,
  rebuildBackupContext,
};

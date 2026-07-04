// ============================================================================
// server/services/backup-differential.js
//
// R3l C64 — performDifferentialBackup()
//
// A differential backup captures the SQLite WAL frames written since the
// last FULL backup (the "anchor"). Unlike incremental backups, which form
// a chain where each link captures only the delta from its immediate
// predecessor, differential backups are each independently restorable
// alongside the anchor: a restore needs only [anchor full + latest
// differential], never any intermediate differentials.
//
// Trade-off vs incremental:
//
//   - Differential archives grow over time (each one duplicates frames
//     archived by previous differentials since the anchor)
//   - Incremental archives stay small but require walking the whole chain
//     on restore
//   - Restoring from a differential is simpler and faster
//   - Differential is more resilient to losing any single intermediate
//     archive
//
// Implementation is nearly identical to backup-incremental.js (C63). The
// differences are:
//
//   1. Parent selection: findDifferentialAnchor finds the most recent
//      verified full backup, not the most recent backup of any kind.
//   2. Frame range: read [anchor.wal_end_position, current] instead of
//      [previous.wal_end_position, current]. This means each successive
//      differential captures progressively more frames since the anchor.
//   3. Insert columns: backup_strategy='differential', parent_backup_id
//      points to the anchor (same as parent_full_backup_id; differential
//      semantics make these two the same column value).
//
// The frames bundle binary format (INCR-v1) is REUSED unchanged from
// backup-incremental.js: differential and incremental archives have
// byte-equivalent payload format. Only the manifest's backup_strategy
// field and the chain columns in the backups row distinguish them.
//
// The encryption + signing + push pipeline is also identical to C63
// (and to full backups). Same archive.bin + wrapped-key.bin + manifest.json
// + manifest.sig on-disk layout.
// ============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { logger } = require('./logger');
const { getDb, DB_PATH } = require('../db/init');
const archiveSvc = require('./backup-archive');
const keyWrapSvc = require('./backup-key-wrapping');
const manifestSvc = require('./backup-manifest');
const signingKeysSvc = require('./backup-signing-keys');
const backupPushSvc = require('./backup-push');
const storageRouting = require('./storage-routing');
const walExtractor = require('./wal-extractor');
const walCheckpoint = require('./wal-checkpoint');
// Reuse the INCR binary format helpers from C63 — differential archives
// use the same bundle format as incremental archives byte-for-byte.
const incrementalSvc = require('./backup-incremental');

const ARCHIVE_FILENAME = 'archive.bin';
const WRAPPED_KEY_FILENAME = 'wrapped-key.bin';
const MANIFEST_FILENAME = 'manifest.json';
const MANIFEST_SIG_FILENAME = 'manifest.sig';

const DEFAULT_BACKUP_DIR_BASE = './data/backups';

function resolveBackupDir(override) {
  if (override) return path.resolve(override);
  if (process.env.FIREALIVE_BACKUP_DIR) return path.resolve(process.env.FIREALIVE_BACKUP_DIR);
  return path.resolve(DEFAULT_BACKUP_DIR_BASE);
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function backupDirName(date = new Date()) {
  const ts = date.toISOString().replace(/[-:.T]/g, '').slice(0, 14);
  return `${ts}-diff-${crypto.randomBytes(3).toString('hex')}`;
}

/**
 * Find the most recent eligible anchor full backup. Eligible means:
 *   - status='verified'
 *   - backup_strategy='full' (or NULL for pre-R3l backups that
 *     pre-date the strategy column; treated as full)
 *   - wal_end_position IS NOT NULL (v2 backup with WAL tracking)
 *   - format_version=2
 *
 * Returns the row or null if no anchor exists.
 *
 * Note: this query does NOT verify that the WAL salts still match the
 * anchor's recorded state. Salt change is detected later by the frame
 * read inside withAutoCheckpointDisabled. If the anchor's recorded
 * wal_end_position is stale, the read fails and the function escalates
 * to a full backup.
 */
function findDifferentialAnchor(db) {
  return db.prepare(`
    SELECT id, backup_strategy, parent_full_backup_id, wal_start_position, wal_end_position, page_count, created_at
      FROM backups
     WHERE status = 'verified'
       AND (backup_strategy = 'full' OR backup_strategy IS NULL)
       AND wal_end_position IS NOT NULL
       AND format_version = 2
     ORDER BY created_at DESC, id DESC
     LIMIT 1
  `).get() || null;
}

function readFuseCounter(db) {
  try {
    const row = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
    if (row && row.value != null) {
      const n = parseInt(row.value, 10);
      if (Number.isFinite(n) && n >= 0) return n;
    }
  } catch (_) { /* table may not exist yet */ }
  return 0;
}

/**
 * Build the differential manifest. Distinguishes itself from the C63
 * incremental manifest only in backup_strategy field and in parent_backup_id
 * semantics (anchor full backup, not immediate predecessor).
 */
function buildDifferentialManifest(args) {
  const required = ['backupId', 'backupType', 'anchorBackupId', 'walStartPosition',
    'walEndPosition', 'pageCount', 'archiveFile', 'wrappedKeyFile',
    'signingKeyId', 'signingKeyFingerprint', 'sourceFuseCounter', 'pageSize'];
  for (const k of required) {
    if (args[k] === undefined || args[k] === null) {
      throw new Error(`buildDifferentialManifest: ${k} required`);
    }
  }
  return {
    format_version: 2,
    backup_id: String(args.backupId),
    backup_strategy: 'differential',
    backup_type: args.backupType,
    created_at: args.createdAt || new Date().toISOString(),
    // For differentials, parent and anchor are the same.
    parent_backup_id: String(args.anchorBackupId),
    parent_full_backup_id: String(args.anchorBackupId),
    wal_start_position: args.walStartPosition,
    wal_end_position: args.walEndPosition,
    page_count: args.pageCount,
    page_size: args.pageSize,
    files: [
      { name: ARCHIVE_FILENAME, size_bytes: args.archiveFile.sizeBytes, sha256: args.archiveFile.sha256 },
      { name: WRAPPED_KEY_FILENAME, size_bytes: args.wrappedKeyFile.sizeBytes, sha256: args.wrappedKeyFile.sha256 },
    ],
    compression: 'zstd',
    key_wrapping_scheme: args.keyWrappingScheme || 'env-var',
    kek_reference: args.kekReference || 'TIER1_ENCRYPTION_KEY',
    signing_key_id: args.signingKeyId,
    signing_key_fingerprint: args.signingKeyFingerprint,
    source_fuse_counter: args.sourceFuseCounter,
    frames_format: 'INCR-v1',
  };
}

/**
 * Main entry. Returns the same shape family as performIncrementalBackup:
 *   { ok: true, escalated: false, backupId, anchorBackupId, walStartPosition,
 *     walEndPosition, pageCount, archivePath, manifestPath, manifestSha256,
 *     pushResult }
 *
 * Or escalation:
 *   { ok: true, escalated: true, reason, fullBackupResult }
 *
 * Or failure:
 *   { ok: false, error }
 */
async function performDifferentialBackup(options = {}) {
  const type = options.type || 'on-demand';
  if (!['scheduled', 'on-demand', 'snapshot'].includes(type)) {
    throw new Error(`performDifferentialBackup: invalid type '${type}'`);
  }

  const backupDirBase = resolveBackupDir(options.backupDir);
  const compressionLevel = options.compressionLevel != null ? options.compressionLevel : archiveSvc.DEFAULT_ZSTD_LEVEL;
  const keyWrappingScheme = options.keyWrappingScheme || 'env-var';
  const kekReference = options.kekReference || (keyWrappingScheme === 'env-var' ? 'TIER1_ENCRYPTION_KEY' : '');

  ensureDir(backupDirBase);

  const db = getDb();

  // Find the anchor full backup. This is the KEY difference from C63:
  // we want the latest FULL, not the latest of any strategy.
  const anchor = findDifferentialAnchor(db);
  if (!anchor) {
    logger.info('backup-differential: no eligible anchor full backup; escalating to full');
    return escalateToFull(type, options, 'no-anchor');
  }
  if (!anchor.wal_end_position) {
    logger.info('backup-differential: anchor has no wal_end_position; escalating to full', { anchorId: anchor.id });
    return escalateToFull(type, options, 'incompatible-anchor');
  }

  const anchorPos = walExtractor.parseWalPosition(anchor.wal_end_position);
  const walPath = DB_PATH + '-wal';

  if (!fs.existsSync(walPath)) {
    logger.info('backup-differential: no WAL file present; escalating to full');
    return escalateToFull(type, options, 'no-wal-file');
  }

  const signingKey = signingKeysSvc.getActiveSigningKey(db);

  let collectedFrames;
  let walHeader;
  let endOffset;
  let endFrameNo;
  let saltChanged = false;

  try {
    await walCheckpoint.withAutoCheckpointDisabled(db, async () => {
      const current = walExtractor.getWalCurrentPosition(walPath);
      if (!current.exists) {
        throw new Error('backup-differential: WAL disappeared after disabling autocheckpoint');
      }
      if (current.frameNo < anchorPos.frameNo) {
        saltChanged = true;
        return;
      }

      // Read frames from anchor.wal_end_position.frameNo + 1 to current.
      // Note: differential semantics — ALL frames since the anchor full,
      // regardless of how many differentials we've already taken.
      const frames = [];
      const result = walExtractor.streamWalPages(walPath, (entry) => {
        const pageCopy = Buffer.from(entry.pageBuf);
        frames.push({
          frameNo: entry.frameNo,
          pageNo: entry.pageNo,
          dbSizeAfterCommit: entry.dbSizeAfterCommit,
          sha256: entry.sha256,
          pageBuf: pageCopy,
        });
      }, { startFrameNo: anchorPos.frameNo + 1, endFrameNo: current.frameNo });

      if (result.invalidSaltAtFrame !== null && result.invalidSaltAtFrame <= anchorPos.frameNo) {
        saltChanged = true;
        return;
      }

      collectedFrames = frames;
      walHeader = result.header;
      endOffset = result.endOffset;
      endFrameNo = result.endFrameNo;
    });
  } catch (err) {
    logger.error('backup-differential: WAL read failed', { error: err.message });
    return { ok: false, error: err.message };
  }

  if (saltChanged) {
    logger.info('backup-differential: WAL salt changed since anchor (checkpoint occurred); escalating to full');
    return escalateToFull(type, options, 'salt-change');
  }

  collectedFrames = collectedFrames || [];

  const backupId = crypto.randomBytes(16).toString('hex');
  const dirName = backupDirName();
  const finalDir = path.join(backupDirBase, dirName);
  ensureDir(finalDir);

  const archivePathOnDisk = path.join(finalDir, ARCHIVE_FILENAME);
  const wrappedKeyPath = path.join(finalDir, WRAPPED_KEY_FILENAME);
  const manifestPath = path.join(finalDir, MANIFEST_FILENAME);
  const manifestSigPath = path.join(finalDir, MANIFEST_SIG_FILENAME);

  let archiveSha256 = null;
  let archiveSize = 0;
  let wrappedKeySha256 = null;
  let wrappedKeySize = 0;
  const pageSize = walHeader ? walHeader.pageSize : 0;

  if (collectedFrames.length > 0) {
    // Reuse the INCR-v1 binary format from C63 unchanged.
    const framesBundle = incrementalSvc.buildFramesBundle(pageSize, collectedFrames);
    const archived = await archiveSvc.buildArchive(framesBundle, 'frames.bin', { compressionLevel });
    fs.writeFileSync(archivePathOnDisk, archived.encryptedArchive);
    archiveSha256 = archived.sha256;
    archiveSize = archived.sizeBytes;

    const wrappedEnvelope = await keyWrapSvc.wrapKey(archived.ephemeralKey, {
      scheme: keyWrappingScheme,
      reference: kekReference,
    });
    fs.writeFileSync(wrappedKeyPath, wrappedEnvelope);
    wrappedKeySha256 = crypto.createHash('sha256').update(wrappedEnvelope).digest('hex');
    wrappedKeySize = wrappedEnvelope.length;
  } else {
    const sentinel = Buffer.from('EMPTY-DIFFERENTIAL\n', 'ascii');
    fs.writeFileSync(archivePathOnDisk, sentinel);
    archiveSha256 = crypto.createHash('sha256').update(sentinel).digest('hex');
    archiveSize = sentinel.length;

    const sentinelKey = Buffer.alloc(32);
    const wrappedEnvelope = await keyWrapSvc.wrapKey(sentinelKey, {
      scheme: keyWrappingScheme,
      reference: kekReference,
    });
    fs.writeFileSync(wrappedKeyPath, wrappedEnvelope);
    wrappedKeySha256 = crypto.createHash('sha256').update(wrappedEnvelope).digest('hex');
    wrappedKeySize = wrappedEnvelope.length;
  }

  const sourceFuseCounter = readFuseCounter(db);
  const manifest = buildDifferentialManifest({
    backupId,
    backupType: type,
    anchorBackupId: anchor.id,
    walStartPosition: anchor.wal_end_position,
    walEndPosition: walExtractor.serializeWalPosition({
      offset: endOffset || anchorPos.offset,
      frameNo: endFrameNo || anchorPos.frameNo,
    }),
    pageCount: collectedFrames.length,
    pageSize: pageSize || 0,
    archiveFile: { sizeBytes: archiveSize, sha256: archiveSha256 },
    wrappedKeyFile: { sizeBytes: wrappedKeySize, sha256: wrappedKeySha256 },
    signingKeyId: signingKey.id,
    signingKeyFingerprint: signingKey.fingerprint,
    sourceFuseCounter,
    keyWrappingScheme,
    kekReference,
  });

  const manifestBytes = manifestSvc.serialize(manifest);
  fs.writeFileSync(manifestPath, manifestBytes);
  const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');

  const sigBytes = signingKeysSvc.signManifest(db, manifestBytes);
  fs.writeFileSync(manifestSigPath, sigBytes);

  // Insert backups row. For differentials, parent_backup_id and
  // parent_full_backup_id both point to the anchor (these two columns
  // are equal for any differential, which is itself a quick way to
  // distinguish differentials from incrementals at the row level
  // without parsing backup_strategy).
  db.prepare(`
    INSERT INTO backups (id, type, size_bytes, sha256_hash, status, created_at,
                         format_version, manifest_path, archive_path,
                         manifest_sig_path, wrapped_key_path, signing_key_id,
                         backup_strategy, parent_backup_id, parent_full_backup_id,
                         wal_start_position, wal_end_position, page_count)
    VALUES (?, ?, ?, ?, 'verified', datetime('now'),
            2, ?, ?, ?, ?, ?,
            'differential', ?, ?, ?, ?, ?)
  `).run(
    backupId,
    type,
    archiveSize + wrappedKeySize + manifestBytes.length + sigBytes.length,
    manifestSha256,
    manifestPath,
    archivePathOnDisk,
    manifestSigPath,
    wrappedKeyPath,
    signingKey.id,
    anchor.id,
    anchor.id,
    manifest.wal_start_position,
    manifest.wal_end_position,
    collectedFrames.length,
  );

  logger.info('backup-differential: differential backup completed', {
    id: backupId,
    anchorId: anchor.id,
    pageCount: collectedFrames.length,
    walStart: manifest.wal_start_position,
    walEnd: manifest.wal_end_position,
  });

  let pushResult = null;
  if (options.awaitPush) {
    // B5q (Revision v3): resolve the backup route via the storage-routing
    // resolver -- a primary plus an optional secondary, capped at two. The
    // per-schedule destination_filter (R3l C58/C59) is retired; differential
    // backups push to the destinations an admin designates for the 'backup'
    // type, the same as full backups. If no route is configured the backup is
    // still created and chain-attested on-host; it simply is not pushed.
    let differentialDestinationRefs = [];
    try {
      const route = storageRouting.getRouteForType(db, 'backup');
      if (route.configured && Array.isArray(route.destinations)) {
        differentialDestinationRefs = route.destinations.map((d) => d.id);
      }
    } catch (routeErr) {
      logger.warn('backup-differential: failed to resolve storage route; backup will not be pushed', {
        error: routeErr.message,
      });
    }
    try {
      pushResult = await backupPushSvc.pushBackup(db, backupId, {
        logger,
        destinationRef: differentialDestinationRefs[0] || null,
        destinationRefs: differentialDestinationRefs,
      });
    } catch (pushErr) {
      logger.error('backup-differential: push orchestration crashed', { id: backupId, error: pushErr.message });
      pushResult = { ok: false, error: pushErr.message, crashed: true };
    }
  }

  return {
    ok: true,
    escalated: false,
    backupId,
    anchorBackupId: anchor.id,
    walStartPosition: manifest.wal_start_position,
    walEndPosition: manifest.wal_end_position,
    pageCount: collectedFrames.length,
    archivePath: archivePathOnDisk,
    manifestPath,
    manifestSha256,
    pushResult,
  };
}

async function escalateToFull(type, options, reason) {
  const { performBackup } = require('./backup');
  logger.info(`backup-differential: escalating to full backup (reason=${reason})`);
  const fullResult = await performBackup(type, options);
  return {
    ok: true,
    escalated: true,
    reason,
    fullBackupResult: fullResult,
  };
}

module.exports = {
  performDifferentialBackup,
  findDifferentialAnchor,
  buildDifferentialManifest,
};

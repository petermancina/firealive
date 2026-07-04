// ============================================================================
// server/services/backup-incremental.js
//
// R3l C63 — performIncrementalBackup()
//
// An incremental backup captures the SQLite WAL frames written since the
// previous backup in the chain. It is paired with an anchor full backup
// (parent_full_backup_id) and optionally with intermediate predecessors
// (parent_backup_id). A restore walks the chain from anchor through every
// intermediate incremental to reconstruct the database state at the time
// the final incremental was taken.
//
// Pipeline:
//
//   1. Validate inputs (type enum, optional scheduleId)
//   2. Open the management DB connection
//   3. Find the most recent eligible parent backup
//      - Must have status='verified'
//      - Must have wal_end_position set (i.e. is itself a v2 backup with
//        WAL tracking, full or incremental)
//      - If no eligible parent exists, escalate to a full backup
//   4. Read current WAL position via wal-extractor.getWalCurrentPosition
//      - If current position < parent's wal_end_position (negative delta),
//        the WAL was checkpointed/truncated since the parent was taken;
//        salt change is detected by frame read failures. Escalate to full.
//      - If current position == parent's wal_end_position (no new frames),
//        produce an empty incremental that still records the position so
//        the chain stays unbroken.
//   5. Wrap the WAL read in withAutoCheckpointDisabled (wal-checkpoint.js)
//      so SQLite cannot checkpoint underneath us mid-read.
//      - Inside: streamWalPages from parent.wal_end_position.frameNo
//        through the current end. For each frame, capture frameNo, pageNo,
//        dbSizeAfterCommit, sha256, and page bytes into the bundle.
//   6. Build the frames bundle Buffer (binary INCR format below).
//   7. Encrypt + compress via backup-archive.buildArchive
//   8. KEK-wrap the ephemeral key via backup-key-wrapping.wrapKey
//   9. Build the incremental manifest (custom shape with chain fields)
//  10. Sign manifest via backup-signing-keys.signManifest
//  11. Write 4 files to disk under the backup directory:
//      - manifest.json
//      - manifest.sig
//      - archive.bin       (encrypted+compressed frames bundle)
//      - wrapped-key.bin   (KEK-wrapped data key)
//  12. Insert backups row with:
//      - backup_strategy='incremental'
//      - parent_backup_id, parent_full_backup_id
//      - wal_start_position, wal_end_position
//      - page_count, file paths, sha256, status='verified'
//
// Frames bundle binary format (INCR v1):
//   header (16 bytes)
//     0-3:   magic 'INCR' (ASCII)
//     4-7:   format version (uint32 BE, currently 1)
//     8-11:  frame count (uint32 BE)
//    12-15:  page size (uint32 BE)
//   per frame (44 + page_size bytes):
//     0-3:   frame_no (uint32 BE)
//     4-7:   page_no  (uint32 BE)
//     8-11:  db_size_after_commit (uint32 BE)
//    12-43:  sha256 of page data (32 raw bytes)
//    44...:  raw page data (page_size bytes)
//
// Encryption + signing reuse the existing backup-archive pipeline so an
// incremental archive has the same on-disk structure as a v2 full backup:
// manifest.json + manifest.sig + archive.bin + wrapped-key.bin. The only
// differences are inside manifest.json (backup_strategy='incremental' plus
// parent linkage + WAL position fields) and inside archive.bin (encrypted
// frames bundle in INCR format rather than encrypted single DB file).
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

const INCR_MAGIC = Buffer.from('INCR', 'ascii');
const INCR_FORMAT_VERSION = 1;
const INCR_HEADER_SIZE = 16;
const INCR_PER_FRAME_OVERHEAD = 44;  // 4 + 4 + 4 + 32

const ARCHIVE_FILENAME = 'archive.bin';
const WRAPPED_KEY_FILENAME = 'wrapped-key.bin';
const MANIFEST_FILENAME = 'manifest.json';
const MANIFEST_SIG_FILENAME = 'manifest.sig';

const DEFAULT_BACKUP_DIR_BASE = './data/backups';

/**
 * Resolve the backup directory base path. Same convention as backup.js:
 * env override -> options override -> default.
 */
function resolveBackupDir(override) {
  if (override) return path.resolve(override);
  if (process.env.FIREALIVE_BACKUP_DIR) return path.resolve(process.env.FIREALIVE_BACKUP_DIR);
  return path.resolve(DEFAULT_BACKUP_DIR_BASE);
}

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function backupDirName(date = new Date()) {
  // YYYYMMDD-HHMMSS-incr-<6 hex>
  const ts = date.toISOString().replace(/[-:.T]/g, '').slice(0, 14);
  return `${ts}-incr-${crypto.randomBytes(3).toString('hex')}`;
}

/**
 * Find the most recent backup eligible to be an incremental parent.
 * Eligible means: status='verified', wal_end_position IS NOT NULL,
 * format_version=2, and ordered by created_at DESC.
 *
 * Returns the row or null if no eligible parent exists.
 */
function findIncrementalParent(db) {
  return db.prepare(`
    SELECT id, backup_strategy, parent_full_backup_id, wal_start_position, wal_end_position, page_count, created_at
      FROM backups
     WHERE status = 'verified'
       AND wal_end_position IS NOT NULL
       AND format_version = 2
     ORDER BY created_at DESC, id DESC
     LIMIT 1
  `).get() || null;
}

/**
 * Compute the parent_full_backup_id for an incremental whose immediate
 * parent is `parentRow`. If the parent is a full backup (no parent_full_
 * backup_id of its own), the parent IS the anchor. Otherwise, inherit
 * the parent's anchor.
 */
function resolveAnchorFullBackupId(parentRow) {
  if (!parentRow) return null;
  // A full backup is one with parent_full_backup_id=null AND backup_strategy='full'
  if (parentRow.parent_full_backup_id == null && parentRow.backup_strategy === 'full') {
    return parentRow.id;
  }
  return parentRow.parent_full_backup_id;
}

/**
 * Build the INCR-format binary bundle of WAL frames.
 *
 * Inputs:
 *   pageSize: int (must be set; the WAL header's pageSize)
 *   frames:   array of { frameNo, pageNo, dbSizeAfterCommit, sha256 (hex string), pageBuf (Buffer) }
 *
 * Returns: Buffer
 */
function buildFramesBundle(pageSize, frames) {
  if (!Number.isInteger(pageSize) || pageSize <= 0) {
    throw new Error(`buildFramesBundle: pageSize must be positive integer, got ${pageSize}`);
  }
  const totalSize = INCR_HEADER_SIZE + frames.length * (INCR_PER_FRAME_OVERHEAD + pageSize);
  const buf = Buffer.alloc(totalSize);

  // Header
  INCR_MAGIC.copy(buf, 0);
  buf.writeUInt32BE(INCR_FORMAT_VERSION, 4);
  buf.writeUInt32BE(frames.length, 8);
  buf.writeUInt32BE(pageSize, 12);

  let cursor = INCR_HEADER_SIZE;
  for (const f of frames) {
    buf.writeUInt32BE(f.frameNo, cursor); cursor += 4;
    buf.writeUInt32BE(f.pageNo, cursor); cursor += 4;
    buf.writeUInt32BE(f.dbSizeAfterCommit, cursor); cursor += 4;
    Buffer.from(f.sha256, 'hex').copy(buf, cursor); cursor += 32;
    if (!Buffer.isBuffer(f.pageBuf) || f.pageBuf.length !== pageSize) {
      throw new Error(`buildFramesBundle: frame ${f.frameNo} pageBuf must be a ${pageSize}-byte Buffer`);
    }
    f.pageBuf.copy(buf, cursor); cursor += pageSize;
  }

  if (cursor !== totalSize) {
    throw new Error(`buildFramesBundle: assembled ${cursor} bytes, expected ${totalSize}`);
  }
  return buf;
}

/**
 * Read the current fuse counter (anti-rollback) for inclusion in the
 * manifest. Same source as backup.js.
 */
function readFuseCounter(db) {
  try {
    const row = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
    if (row && row.value != null) {
      const n = parseInt(row.value, 10);
      if (Number.isFinite(n) && n >= 0) return n;
    }
  } catch (_) { /* table may not exist yet; default to 0 */ }
  return 0;
}

/**
 * Build the incremental backup's manifest. Distinct from the buildManifest
 * helper in backup-manifest.js (which is strict about the v2 full-backup
 * shape). This manifest extends the same canonical-JSON pattern with
 * incremental-specific fields.
 *
 * The signature path is the SAME: signingKeysSvc.signManifest(db, bytes).
 */
function buildIncrementalManifest(args) {
  const required = ['backupId', 'backupType', 'parentBackupId', 'parentFullBackupId',
    'walStartPosition', 'walEndPosition', 'pageCount', 'archiveFile', 'wrappedKeyFile',
    'signingKeyId', 'signingKeyFingerprint', 'sourceFuseCounter', 'pageSize'];
  for (const k of required) {
    if (args[k] === undefined || args[k] === null) {
      throw new Error(`buildIncrementalManifest: ${k} required`);
    }
  }
  return {
    format_version: 2,
    backup_id: String(args.backupId),
    backup_strategy: 'incremental',
    backup_type: args.backupType,
    created_at: args.createdAt || new Date().toISOString(),
    parent_backup_id: String(args.parentBackupId),
    parent_full_backup_id: String(args.parentFullBackupId),
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
 * R3l C73: resolve the effective max-chain-depth limit for this backup.
 *
 * Two sources of truth, in priority order:
 *   1. Per-schedule override: backup_schedules.max_chain_depth (INTEGER,
 *      nullable). Only consulted when scheduleId is provided. NULL means
 *      "fall through to global default".
 *   2. Global default: system_meta.max_chain_depth (TEXT, parsed as int).
 *      Seeded by the C73 migration to '100'.
 *
 * If neither source yields a positive integer (unexpected post-migration
 * but defensive against operator misconfiguration), returns 100 as a
 * hard fallback. The C65 restore-chain.js MAX_CHAIN_DEPTH=1000 still
 * caps runaway walks regardless.
 */
function resolveMaxChainDepth(db, scheduleId) {
  if (scheduleId != null) {
    try {
      const sched = db.prepare('SELECT max_chain_depth FROM backup_schedules WHERE id = ?').get(scheduleId);
      if (sched && typeof sched.max_chain_depth === 'number' && sched.max_chain_depth > 0) {
        return sched.max_chain_depth;
      }
    } catch (lookupErr) {
      logger.warn('backup-incremental: per-schedule max_chain_depth lookup failed', {
        scheduleId, error: lookupErr.message,
      });
    }
  }
  try {
    const meta = db.prepare("SELECT value FROM system_meta WHERE key = 'max_chain_depth'").get();
    if (meta && meta.value != null) {
      const n = parseInt(meta.value, 10);
      if (Number.isFinite(n) && n > 0) return n;
    }
  } catch (metaErr) {
    logger.warn('backup-incremental: global max_chain_depth lookup failed', { error: metaErr.message });
  }
  return 100;
}

/**
 * R3l C73: count the existing incrementals already in the chain rooted
 * at anchorFullBackupId. Used to determine whether adding one more
 * incremental would exceed the configured depth limit.
 *
 * Only counts backups with status='verified' and backup_strategy=
 * 'incremental'. Differentials are excluded (their semantic — each
 * captures all changes since the anchor — means depth-limit doesn't
 * apply to them; the anchor chain length stays at 2 regardless).
 *
 * O(1) via index on parent_full_backup_id (assuming SQLite optimizer
 * picks the right plan; worst case a full table scan on backups, which
 * is still fast at typical install sizes).
 */
function countExistingIncrementalsInChain(db, anchorFullBackupId) {
  try {
    const row = db.prepare(`
      SELECT COUNT(*) as cnt FROM backups
      WHERE parent_full_backup_id = ?
        AND backup_strategy = 'incremental'
        AND status = 'verified'
    `).get(anchorFullBackupId);
    return row && row.cnt != null ? row.cnt : 0;
  } catch (countErr) {
    logger.warn('backup-incremental: countExistingIncrementalsInChain failed', {
      anchorFullBackupId, error: countErr.message,
    });
    return 0;
  }
}

/**
 * Main entry. Called by scheduler.js _runBackupJob when a schedule's
 * backup_strategy='incremental'. Returns:
 *   {
 *     ok: true,
 *     backupId,
 *     escalated: false,           true if escalated to a full backup
 *     walStartPosition,
 *     walEndPosition,
 *     pageCount,
 *     archivePath,
 *     manifestPath,
 *     manifestSha256,
 *     pushResult,                 if awaitPush requested
 *   }
 *
 * Or on escalation:
 *   {
 *     ok: true,
 *     escalated: true,
 *     reason: 'no-parent' | 'incompatible-parent' | 'salt-change' | ...,
 *     fullBackupResult: <result of the escalated performBackup call>,
 *   }
 *
 * Or on failure:
 *   {
 *     ok: false,
 *     error: <string>,
 *   }
 */
async function performIncrementalBackup(options = {}) {
  const type = options.type || 'on-demand';
  if (!['scheduled', 'on-demand', 'snapshot'].includes(type)) {
    throw new Error(`performIncrementalBackup: invalid type '${type}'`);
  }

  const scheduleId = options.scheduleId != null ? options.scheduleId : null;
  const backupDirBase = resolveBackupDir(options.backupDir);
  const compressionLevel = options.compressionLevel != null ? options.compressionLevel : archiveSvc.DEFAULT_ZSTD_LEVEL;
  const keyWrappingScheme = options.keyWrappingScheme || 'env-var';
  const kekReference = options.kekReference || (keyWrappingScheme === 'env-var' ? 'TIER1_ENCRYPTION_KEY' : '');

  ensureDir(backupDirBase);

  const db = getDb();

  // Find the parent backup
  const parent = findIncrementalParent(db);
  if (!parent) {
    logger.info('backup-incremental: no eligible parent backup; escalating to full');
    return escalateToFull(type, options, 'no-parent');
  }
  if (!parent.wal_end_position) {
    logger.info('backup-incremental: parent backup has no wal_end_position; escalating to full', { parentId: parent.id });
    return escalateToFull(type, options, 'incompatible-parent');
  }

  const previousPos = walExtractor.parseWalPosition(parent.wal_end_position);
  const walPath = DB_PATH + '-wal';

  if (!fs.existsSync(walPath)) {
    logger.info('backup-incremental: no WAL file present; escalating to full');
    return escalateToFull(type, options, 'no-wal-file');
  }

  const anchorFullBackupId = resolveAnchorFullBackupId(parent);
  if (!anchorFullBackupId) {
    logger.warn('backup-incremental: cannot resolve anchor full backup; escalating to full', { parentId: parent.id });
    return escalateToFull(type, options, 'no-anchor');
  }

  // R3l C73: chain-depth limit. Resolve the effective limit (per-schedule
  // override or system_meta default), count how many incrementals are
  // already chained to this anchor, and escalate if adding one more would
  // exceed the limit. This is the operationally-tunable preference; the
  // C65 restore-chain.js MAX_CHAIN_DEPTH=1000 hard cap still applies as
  // a runaway-walk safety regardless.
  const maxChainDepth = resolveMaxChainDepth(db, scheduleId);
  const existingChainDepth = countExistingIncrementalsInChain(db, anchorFullBackupId);
  if (existingChainDepth + 1 > maxChainDepth) {
    logger.info('backup-incremental: chain depth limit reached; escalating to full', {
      anchorId: anchorFullBackupId,
      existingChainDepth,
      maxChainDepth,
      wouldBeDepth: existingChainDepth + 1,
    });
    return escalateToFull(type, options, 'depth-limit');
  }

  const signingKey = signingKeysSvc.getActiveSigningKey(db);

  // Read new frames. Wrap in withAutoCheckpointDisabled so SQLite doesn't
  // checkpoint mid-read (which would re-salt the WAL and break our
  // position tracking).
  let collectedFrames;
  let walHeader;
  let endOffset;
  let endFrameNo;
  let saltChanged = false;

  try {
    await walCheckpoint.withAutoCheckpointDisabled(db, async () => {
      // Re-read current position INSIDE the disabled-checkpoint scope so
      // we get a position that's stable for the duration of our read.
      const current = walExtractor.getWalCurrentPosition(walPath);
      if (!current.exists) {
        throw new Error('backup-incremental: WAL disappeared after disabling autocheckpoint');
      }

      if (current.frameNo < previousPos.frameNo) {
        // WAL was checkpointed since parent backup; frame counter reset.
        // Salt change will be detected by streamWalPages.
        saltChanged = true;
        return;
      }

      // Read frames from previousPos.frameNo + 1 to current.frameNo.
      // (frame numbers are 1-indexed; startFrameNo is inclusive.)
      const frames = [];
      const result = walExtractor.streamWalPages(walPath, (entry) => {
        // Copy pageBuf because streamWalPages reuses its buffer per call.
        const pageCopy = Buffer.from(entry.pageBuf);
        frames.push({
          frameNo: entry.frameNo,
          pageNo: entry.pageNo,
          dbSizeAfterCommit: entry.dbSizeAfterCommit,
          sha256: entry.sha256,
          pageBuf: pageCopy,
        });
      }, { startFrameNo: previousPos.frameNo + 1, endFrameNo: current.frameNo });

      if (result.invalidSaltAtFrame !== null && result.invalidSaltAtFrame <= previousPos.frameNo) {
        // Salt changed before our start position: the WAL was reset
        // entirely since the parent was taken. Escalate.
        saltChanged = true;
        return;
      }

      collectedFrames = frames;
      walHeader = result.header;
      endOffset = result.endOffset;
      endFrameNo = result.endFrameNo;
    });
  } catch (err) {
    logger.error('backup-incremental: WAL read failed', { error: err.message });
    return { ok: false, error: err.message };
  }

  if (saltChanged) {
    logger.info('backup-incremental: WAL salt changed since parent (checkpoint occurred); escalating to full');
    return escalateToFull(type, options, 'salt-change');
  }

  collectedFrames = collectedFrames || [];

  // Empty incremental (no new frames since parent): record an empty
  // archive so the chain stays unbroken. Skip the archive build entirely
  // by treating page_count=0 as a marker.
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
    // Build frames bundle, encrypt+compress, KEK-wrap.
    const framesBundle = buildFramesBundle(pageSize, collectedFrames);
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
    // Empty incremental: write a one-byte sentinel + matching wrapped key
    // so the manifest's file references aren't null. Restore code should
    // recognize page_count=0 and skip the actual archive read.
    const sentinel = Buffer.from('EMPTY-INCREMENTAL\n', 'ascii');
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

  // Build + sign manifest
  const sourceFuseCounter = readFuseCounter(db);
  const manifest = buildIncrementalManifest({
    backupId,
    backupType: type,
    parentBackupId: parent.id,
    parentFullBackupId: anchorFullBackupId,
    walStartPosition: parent.wal_end_position,
    walEndPosition: walExtractor.serializeWalPosition({ offset: endOffset || previousPos.offset, frameNo: endFrameNo || previousPos.frameNo }),
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

  // Insert backups row
  db.prepare(`
    INSERT INTO backups (id, type, size_bytes, sha256_hash, status, created_at,
                         format_version, manifest_path, archive_path,
                         manifest_sig_path, wrapped_key_path, signing_key_id,
                         backup_strategy, parent_backup_id, parent_full_backup_id,
                         wal_start_position, wal_end_position, page_count)
    VALUES (?, ?, ?, ?, 'verified', datetime('now'),
            2, ?, ?, ?, ?, ?,
            'incremental', ?, ?, ?, ?, ?)
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
    parent.id,
    anchorFullBackupId,
    manifest.wal_start_position,
    manifest.wal_end_position,
    collectedFrames.length,
  );

  logger.info('backup-incremental: incremental backup completed', {
    id: backupId,
    parentId: parent.id,
    anchorId: anchorFullBackupId,
    pageCount: collectedFrames.length,
    walStart: manifest.wal_start_position,
    walEnd: manifest.wal_end_position,
  });

  // Optional push
  let pushResult = null;
  if (options.awaitPush) {
    // B5q (Revision v3): resolve the backup route via the storage-routing
    // resolver -- a primary plus an optional secondary, capped at two. The
    // per-schedule destination_filter (R3l C58/C59) is retired; incremental
    // backups push to the destinations an admin designates for the 'backup'
    // type, the same as full backups. If no route is configured the backup is
    // still created and chain-attested on-host; it simply is not pushed.
    let incrementalDestinationRefs = [];
    try {
      const route = storageRouting.getRouteForType(db, 'backup');
      if (route.configured && Array.isArray(route.destinations)) {
        incrementalDestinationRefs = route.destinations.map((d) => d.id);
      }
    } catch (routeErr) {
      logger.warn('backup-incremental: failed to resolve storage route; backup will not be pushed', {
        error: routeErr.message,
      });
    }
    try {
      pushResult = await backupPushSvc.pushBackup(db, backupId, {
        logger,
        destinationRef: incrementalDestinationRefs[0] || null,
        destinationRefs: incrementalDestinationRefs,
      });
    } catch (pushErr) {
      logger.error('backup-incremental: push orchestration crashed', { id: backupId, error: pushErr.message });
      pushResult = { ok: false, error: pushErr.message, crashed: true };
    }
  }

  return {
    ok: true,
    escalated: false,
    backupId,
    parentBackupId: parent.id,
    parentFullBackupId: anchorFullBackupId,
    walStartPosition: manifest.wal_start_position,
    walEndPosition: manifest.wal_end_position,
    pageCount: collectedFrames.length,
    archivePath: archivePathOnDisk,
    manifestPath,
    manifestSha256,
    pushResult,
  };
}

/**
 * Escalate to a full backup. Loads ./backup lazily to avoid a circular
 * require (backup.js -> backup-incremental.js would not happen today, but
 * future cross-references could).
 */
async function escalateToFull(type, options, reason) {
  const { performBackup } = require('./backup');
  logger.info(`backup-incremental: escalating to full backup (reason=${reason})`);
  const fullResult = await performBackup(type, options);
  return {
    ok: true,
    escalated: true,
    reason,
    fullBackupResult: fullResult,
  };
}

module.exports = {
  performIncrementalBackup,
  // Exported for tests and for the restore-chain walker (C65) which
  // needs to read the INCR bundle format.
  INCR_MAGIC,
  INCR_FORMAT_VERSION,
  INCR_HEADER_SIZE,
  INCR_PER_FRAME_OVERHEAD,
  buildFramesBundle,
  findIncrementalParent,
  resolveAnchorFullBackupId,
};

// =============================================================================
// FIREALIVE GD -- Incremental Backup Writer (WAL-frame capture)
//
// An incremental backup captures the SQLite WAL frames written since the
// previous backup in the chain. It is paired with an anchor full backup
// (parent_full_backup_id) and its immediate predecessor (parent_backup_id). A
// restore walks the chain from the anchor through every intermediate incremental
// to reconstruct the database state at the time the final incremental was taken.
// Twins the Regional incremental writer, adapted for the GD.
//
// PIPELINE
//   1. Find the most recent eligible parent (status='verified', wal_end_position
//      set, format_version=2). If none, escalate to a full v2 backup.
//   2. Read the current WAL tail position. If it is behind the parent's
//      wal_end_position, the WAL was checkpointed/re-salted since the parent was
//      taken -> escalate. If it equals the parent's position, produce an empty
//      incremental (page_count=0) so the chain stays unbroken.
//   3. Wrap the WAL read in withAutoCheckpointDisabled so SQLite cannot
//      checkpoint mid-read (which would re-salt the WAL and break position
//      tracking). Stream frames from the parent's end position to the current
//      tail into the INCR-v1 bundle.
//   4. tar+gzip+AES-256-GCM the bundle, KEK-wrap the key, build + sign a manifest
//      (backup_type='incremental', with chain + WAL fields), and write the same
//      four-file layout as a v2 full backup (archive.tar.gz.enc holds the encrypted
//      bundle; its inner tar entry is frames.bin rather than the DB file).
//   5. Record a format_version=2 backups row (type='incremental', parent linkage,
//      WAL positions, page_count), append a CREATE entry to the attestation chain,
//      and route+push all four files -- reusing the shared v2 push engine.
//
// The GD unifies the archive filename with the full backup (archive.tar.gz.enc)
// because gd-backup-archive wraps any payload the same way; this lets the
// incremental reuse the v2 push + retry path unchanged. Unlike the Regional
// incremental, the GD incremental also chain-attests every incremental (matching
// the GD full writer) so the attestation chain covers all backup operations.
//
// INCR-v1 frames bundle binary format:
//   header (16 bytes): magic 'INCR' | format version (uint32 BE=1) | frame count
//                      (uint32 BE) | page size (uint32 BE)
//   per frame (44 + page_size): frame_no | page_no | db_size_after_commit
//                      (each uint32 BE) | sha256 of page (32 raw bytes) | page bytes
// =============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const archiveSvc = require('./gd-backup-archive');
const keyWrapSvc = require('./gd-backup-key-wrapping');
const manifestSvc = require('./gd-backup-manifest');
const signingKeysSvc = require('./gd-backup-signing-keys');
const chainSvc = require('./gd-backup-chain');
const walExtractor = require('./gd-wal-extractor');
const walCheckpoint = require('./gd-wal-checkpoint');
const storagePush = require('./gd-storage-push');
const backupV2 = require('./gd-backup-v2');
const gdDataRoot = require('../lib/gd-data-root');

const INCR_MAGIC = Buffer.from('INCR', 'ascii');
const INCR_FORMAT_VERSION = 1;
const INCR_HEADER_SIZE = 16;
const INCR_PER_FRAME_OVERHEAD = 44;   // 4 (frame_no) + 4 (page_no) + 4 (db_size) + 32 (sha256)

// Unified with the full backup: the outer encrypted archive filename is the same
// (archive.tar.gz.enc); only the inner tar entry name differs (frames.bin).
const ARCHIVE_FILENAME     = manifestSvc.ARCHIVE_FILENAME;
const WRAPPED_KEY_FILENAME = manifestSvc.WRAPPED_KEY_FILENAME;
const MANIFEST_FILENAME    = manifestSvc.MANIFEST_FILENAME;
const MANIFEST_SIG_FILENAME = manifestSvc.SIGNATURE_FILENAME;

const DEFAULT_MAX_CHAIN_DEPTH = 100;
const DEFAULT_RETENTION_DAYS = 35;

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function resolveWalPath(options) {
  // P1-1: one function answers for the database path across db-init.js,
  // gd-backup-v2.js, and both WAL resolvers -- they previously agreed only by
  // coincidence of maintenance.
  return gdDataRoot.dbPath(options && options.dbPath) + '-wal';
}

/**
 * Find the most recent backup eligible to be an incremental parent:
 * status='verified', wal_end_position set, format_version=2, newest first.
 * (backup_strategy carries the strategy; any v2 backup with a WAL end position --
 * full or incremental -- can be a parent.) Returns the row or null.
 */
function findIncrementalParent(db) {
  return db.prepare(`
    SELECT id, backup_strategy, parent_full_backup_id, wal_start_position, wal_end_position, page_count, created_at
      FROM backups
     WHERE status = 'verified'
       AND wal_end_position IS NOT NULL
       AND format_version = 2
     ORDER BY created_at DESC, rowid DESC
     LIMIT 1
  `).get() || null;
}

/**
 * Resolve the anchor full backup id for an incremental whose immediate parent is
 * parentRow. If the parent is a full backup (backup_strategy='full', no
 * parent_full_backup_id), the parent IS the anchor; otherwise inherit its anchor.
 */
function resolveAnchorFullBackupId(parentRow) {
  if (!parentRow) return null;
  if (parentRow.parent_full_backup_id == null && parentRow.backup_strategy === 'full') {
    return parentRow.id;
  }
  return parentRow.parent_full_backup_id;
}

/**
 * Build the INCR-v1 binary bundle of WAL frames. frames: array of { frameNo,
 * pageNo, dbSizeAfterCommit, sha256 (hex), pageBuf (Buffer) }. Returns Buffer.
 */
function buildFramesBundle(pageSize, frames) {
  if (!Number.isInteger(pageSize) || pageSize <= 0) {
    throw new Error(`buildFramesBundle: pageSize must be a positive integer, got ${pageSize}`);
  }
  const totalSize = INCR_HEADER_SIZE + frames.length * (INCR_PER_FRAME_OVERHEAD + pageSize);
  const buf = Buffer.alloc(totalSize);

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
 * Build the incremental manifest object. A v3-family manifest (same shape as the
 * full manifest) extended with incremental-specific fields: parent linkage, WAL
 * positions, page count/size, and frames_format. Serialized + signed via the
 * shared manifest/signing services.
 */
function buildIncrementalManifest(args) {
  const required = ['backupId', 'backupType', 'parentBackupId', 'parentFullBackupId', 'walStartPosition',
    'walEndPosition', 'pageCount', 'pageSize', 'archiveFile', 'wrappedKeyFile',
    'signingKeyId', 'signingKeyFingerprint', 'sourceFuseCounter'];
  for (const k of required) {
    if (args[k] === undefined || args[k] === null) {
      throw new Error(`buildIncrementalManifest: ${k} required`);
    }
  }
  return {
    format_version: manifestSvc.MANIFEST_FORMAT_VERSION,
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
    encryption: { algorithm: 'AES-256-GCM' },
    compression: { algorithm: 'gzip', level: args.compressionLevel != null ? args.compressionLevel : archiveSvc.DEFAULT_GZIP_LEVEL },
    key_wrapping: {
      scheme: args.keyWrappingScheme || keyWrapSvc.DEFAULT_SCHEME,
      kek_reference: args.kekReference || keyWrapSvc.DEFAULT_KEK_REFERENCE,
    },
    source_db: {
      fuse_counter_at_creation: args.sourceFuseCounter,
      schema_version: args.sourceSchemaVersion || '1',
    },
    signing_key_id: args.signingKeyId,
    signing_key_fingerprint: args.signingKeyFingerprint,
    frames_format: 'INCR-v1',
  };
}

/**
 * Resolve the effective max-chain-depth limit: options override, then a
 * system_meta 'max_chain_depth' value, then the default. Adding an incremental
 * that would exceed this escalates to a full backup, bounding restore-walk cost.
 */
function resolveMaxChainDepth(db, options = {}) {
  if (options.maxChainDepth != null && Number.isFinite(options.maxChainDepth) && options.maxChainDepth > 0) {
    return options.maxChainDepth;
  }
  try {
    const meta = db.prepare("SELECT value FROM system_meta WHERE key = 'max_chain_depth'").get();
    if (meta && meta.value != null) {
      const n = parseInt(meta.value, 10);
      if (Number.isFinite(n) && n > 0) return n;
    }
  } catch (_e) { /* absent */ }
  return DEFAULT_MAX_CHAIN_DEPTH;
}

/**
 * Count verified incrementals already chained to anchorFullBackupId. Differentials
 * are excluded (each captures all changes since the anchor, so they never extend
 * the incremental chain depth).
 */
function countExistingIncrementalsInChain(db, anchorFullBackupId) {
  try {
    const row = db.prepare(`
      SELECT COUNT(*) AS cnt FROM backups
      WHERE parent_full_backup_id = ?
        AND type = 'incremental'
        AND status = 'verified'
    `).get(anchorFullBackupId);
    return row && row.cnt != null ? row.cnt : 0;
  } catch (countErr) {
    console.warn('gd-backup-incremental: countExistingIncrementalsInChain failed:', countErr.message);
    return 0;
  }
}

/**
 * performIncrementalBackup(db, options)
 *
 * options: backupsDir, dbPath, compressionLevel, keyWrappingScheme, kekReference,
 * maxChainDepth, retentionDays, sourceFuseCounter/sourceSchemaVersion.
 *
 * Returns on success { ok:true, escalated:false, backupId, parentBackupId,
 * parentFullBackupId, walStartPosition, walEndPosition, pageCount, archivePath,
 * manifestPath, manifestSha256, chain_entry, chain_error, push }; on escalation
 * { ok:true, escalated:true, reason, fullBackupResult }; on failure { ok:false,
 * error }.
 */
async function performIncrementalBackup(db, options = {}) {
  const backupsDir = backupV2.resolveBackupsDir(options);
  const compressionLevel = options.compressionLevel != null ? options.compressionLevel : archiveSvc.DEFAULT_GZIP_LEVEL;
  const keyWrappingScheme = options.keyWrappingScheme || keyWrapSvc.DEFAULT_SCHEME;
  const kekReference = options.kekReference || keyWrapSvc.DEFAULT_KEK_REFERENCE;
  // Regional parity: backups.type is the trigger; backup_strategy is 'incremental'.
  const triggerType = options.triggerType === 'scheduled' ? 'scheduled' : 'on-demand';

  ensureDir(backupsDir);

  // 1. Parent selection
  const parent = findIncrementalParent(db);
  if (!parent) {
    console.log('gd-backup-incremental: no eligible parent; escalating to full');
    return escalateToFull(db, options, 'no-parent');
  }
  if (!parent.wal_end_position) {
    console.log('gd-backup-incremental: parent has no wal_end_position; escalating to full');
    return escalateToFull(db, options, 'incompatible-parent');
  }

  const previousPos = walExtractor.parseWalPosition(parent.wal_end_position);
  const walPath = resolveWalPath(options);
  if (!fs.existsSync(walPath)) {
    console.log('gd-backup-incremental: no WAL file present; escalating to full');
    return escalateToFull(db, options, 'no-wal-file');
  }

  const anchorFullBackupId = resolveAnchorFullBackupId(parent);
  if (!anchorFullBackupId) {
    console.warn('gd-backup-incremental: cannot resolve anchor full backup; escalating to full');
    return escalateToFull(db, options, 'no-anchor');
  }

  // Chain-depth limit
  const maxChainDepth = resolveMaxChainDepth(db, options);
  const existingChainDepth = countExistingIncrementalsInChain(db, anchorFullBackupId);
  if (existingChainDepth + 1 > maxChainDepth) {
    console.log(`gd-backup-incremental: chain depth limit reached (${existingChainDepth}/${maxChainDepth}); escalating to full`);
    return escalateToFull(db, options, 'depth-limit');
  }

  let signingKey;
  try {
    signingKey = signingKeysSvc.getActiveSigningKey(db);
  } catch (err) {
    return { ok: false, error: `no active backup signing key: ${err.message}` };
  }

  // 2-3. Read new frames with autocheckpoint disabled
  let collectedFrames = null;
  let walPageSize = 0;
  let endOffset = null;
  let endFrameNo = null;
  let saltChanged = false;

  try {
    await walCheckpoint.withAutoCheckpointDisabled(db, async () => {
      const current = walExtractor.getWalCurrentPosition(walPath);
      if (!current.exists) {
        throw new Error('WAL disappeared after disabling autocheckpoint');
      }
      if (current.frameNo < previousPos.frameNo) {
        // WAL checkpointed/reset since the parent: frame counter went backwards.
        saltChanged = true;
        return;
      }
      walPageSize = current.pageSize || 0;

      if (current.frameNo === previousPos.frameNo) {
        // No new frames: empty incremental. Record the position so the chain
        // stays unbroken.
        collectedFrames = [];
        endOffset = current.offset;
        endFrameNo = current.frameNo;
        return;
      }

      const frames = [];
      const result = walExtractor.streamWalPages(walPath, (entry) => {
        // Copy pageBuf: streamWalPages reuses its buffer per call.
        frames.push({
          frameNo: entry.frameNo,
          pageNo: entry.pageNo,
          dbSizeAfterCommit: entry.dbSizeAfterCommit,
          sha256: entry.sha256,
          pageBuf: Buffer.from(entry.pageBuf),
        });
      }, { startFrameNo: previousPos.frameNo + 1, endFrameNo: current.frameNo });

      if (result.invalidSaltAtFrame !== null && result.invalidSaltAtFrame <= previousPos.frameNo) {
        // Salt changed at/before our start: WAL was reset since the parent.
        saltChanged = true;
        return;
      }

      collectedFrames = frames;
      walPageSize = result.header ? result.header.pageSize : walPageSize;
      endOffset = result.endOffset;
      endFrameNo = result.endFrameNo;
    });
  } catch (err) {
    console.error('gd-backup-incremental: WAL read failed:', err.message);
    return { ok: false, error: err.message };
  }

  if (saltChanged) {
    console.log('gd-backup-incremental: WAL salt changed since parent (checkpoint occurred); escalating to full');
    return escalateToFull(db, options, 'salt-change');
  }

  collectedFrames = collectedFrames || [];

  // 4. Build the four files under a temp dir, atomic-rename to final
  const backupId = crypto.randomBytes(8).toString('hex');
  const dirName = `${backupId}-incr`;
  const tempDir = path.join(backupsDir, `.${dirName}.tmp`);
  const finalDir = path.join(backupsDir, dirName);

  const { sourceFuseCounter, sourceSchemaVersion } = backupV2.readSourceMeta(db, options);

  try {
    fs.mkdirSync(tempDir, { recursive: true });

    // The frames bundle (16-byte header even when empty) -> encrypted archive.
    const framesBundle = buildFramesBundle(walPageSize || 512, collectedFrames);
    const archived = await archiveSvc.buildArchive(framesBundle, 'frames.bin', { compressionLevel });
    const wrappedKey = await keyWrapSvc.wrapKey(archived.ephemeralKey, { scheme: keyWrappingScheme, kekReference });
    const wrappedKeySha = crypto.createHash('sha256').update(wrappedKey).digest('hex');

    const walEndPosition = walExtractor.serializeWalPosition({
      offset: endOffset != null ? endOffset : previousPos.offset,
      frameNo: endFrameNo != null ? endFrameNo : previousPos.frameNo,
    });

    const manifest = buildIncrementalManifest({
      backupId,
      backupType: triggerType,
      parentBackupId: parent.id,
      parentFullBackupId: anchorFullBackupId,
      walStartPosition: parent.wal_end_position,
      walEndPosition,
      pageCount: collectedFrames.length,
      pageSize: walPageSize || 0,
      archiveFile: { sizeBytes: archived.sizeBytes, sha256: archived.sha256 },
      wrappedKeyFile: { sizeBytes: wrappedKey.length, sha256: wrappedKeySha },
      signingKeyId: signingKey.id,
      signingKeyFingerprint: signingKey.publicKeyFingerprint,
      sourceFuseCounter,
      sourceSchemaVersion,
      compressionLevel,
      keyWrappingScheme,
      kekReference,
    });
    const manifestBytes = manifestSvc.serialize(manifest);
    const { signature } = signingKeysSvc.signManifest(db, manifestBytes);

    fs.writeFileSync(path.join(tempDir, ARCHIVE_FILENAME), archived.encryptedArchive);
    fs.writeFileSync(path.join(tempDir, WRAPPED_KEY_FILENAME), wrappedKey);
    fs.writeFileSync(path.join(tempDir, MANIFEST_FILENAME), manifestBytes);
    fs.writeFileSync(path.join(tempDir, MANIFEST_SIG_FILENAME), signature);
    fs.renameSync(tempDir, finalDir);

    const archivePath    = path.join(finalDir, ARCHIVE_FILENAME);
    const wrappedKeyPath  = path.join(finalDir, WRAPPED_KEY_FILENAME);
    const manifestPath    = path.join(finalDir, MANIFEST_FILENAME);
    const manifestSigPath = path.join(finalDir, MANIFEST_SIG_FILENAME);

    // Verify-after-write
    if (!fs.readFileSync(manifestPath).equals(manifestBytes)) {
      throw new Error('verify-after-write: manifest bytes on disk differ from in-memory bytes');
    }
    const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');
    const totalSize = [archivePath, wrappedKeyPath, manifestPath, manifestSigPath]
      .reduce((sum, p) => sum + fs.statSync(p).size, 0);

    // 5. Insert backups row (backup_strategy='incremental', v2, parent linkage, WAL)
    db.prepare(`
      INSERT INTO backups (id, type, backup_strategy, kind, size_bytes, sha256_hash, status, created_at,
                           format_version, manifest_path, archive_path,
                           manifest_sig_path, wrapped_key_path, signing_key_id,
                           parent_backup_id, parent_full_backup_id,
                           wal_start_position, wal_end_position, page_count)
      VALUES (?, ?, 'incremental', 'single-db', ?, ?, 'verified', datetime('now'),
              2, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?)
    `).run(
      backupId, triggerType, totalSize, manifestSha256,
      manifestPath, archivePath, manifestSigPath, wrappedKeyPath, signingKey.id,
      parent.id, anchorFullBackupId, parent.wal_end_position, walEndPosition, collectedFrames.length,
    );

    console.log(`gd-backup-incremental: incremental ${backupId} verified (parent ${parent.id}, anchor ${anchorFullBackupId}, ${collectedFrames.length} pages)`);

    // Append CREATE entry to the attestation chain (degraded-mode on failure).
    let chainEntry = null;
    let chainError = null;
    try {
      const result = chainSvc.appendChainEntry(db, {
        eventType: 'CREATE',
        backupId,
        payload: {
          backup_type: 'incremental',
          format_version: 2,
          manifest_sha256: manifestSha256,
          archive_sha256: archived.sha256,
          parent_backup_id: parent.id,
          parent_full_backup_id: anchorFullBackupId,
          wal_start_position: parent.wal_end_position,
          wal_end_position: walEndPosition,
          page_count: collectedFrames.length,
          backup_signing_key_id: signingKey.id,
          source_fuse_counter: sourceFuseCounter,
          total_size_bytes: totalSize,
          backup_dir_name: path.basename(finalDir),
        },
      });
      chainEntry = { id: result.id, prev_hash: result.prevHash, this_hash: result.thisHash, signing_key_fingerprint: result.signingKeyFingerprint, created_at: result.createdAt };
      console.log(`gd-backup-incremental: chain CREATE entry appended (chain id ${result.id})`);
    } catch (chainErr) {
      chainError = chainErr.message;
      console.error('gd-backup-incremental: CHAIN ENTRY APPEND FAILED -- incremental created without chain attestation. error=' + chainErr.message);
    }

    // Route + push all four files (best-effort; retried by the v2 sweep).
    const hashed = storagePush.hashFilesForContext([
      { name: ARCHIVE_FILENAME, absolutePath: archivePath },
      { name: WRAPPED_KEY_FILENAME, absolutePath: wrappedKeyPath },
      { name: MANIFEST_FILENAME, absolutePath: manifestPath },
      { name: MANIFEST_SIG_FILENAME, absolutePath: manifestSigPath },
    ]);
    let push = { pushed: false, configured: false, reason: 'hash failed' };
    if (hashed.ok) {
      try {
        push = await backupV2.pushV2BackupArtifact(db, {
          backupId, sourceDir: finalDir, files: hashed.files, manifestSha256, options,
        });
      } catch (pushErr) {
        console.error('gd-backup-incremental: push orchestration crashed:', pushErr.message);
        push = { pushed: false, configured: true, error: pushErr.message, crashed: true };
      }
    }

    return {
      ok: true,
      escalated: false,
      backupId,
      parentBackupId: parent.id,
      parentFullBackupId: anchorFullBackupId,
      walStartPosition: parent.wal_end_position,
      walEndPosition,
      pageCount: collectedFrames.length,
      archivePath,
      manifestPath,
      manifestSha256,
      chain_entry: chainEntry,
      chain_error: chainError,
      push,
    };
  } catch (err) {
    if (fs.existsSync(tempDir)) { try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ } }
    if (fs.existsSync(finalDir)) { try { fs.rmSync(finalDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ } }
    console.error(`gd-backup-incremental: incremental ${backupId} FAILED:`, err.message);
    return { ok: false, error: err.message };
  }
}

/**
 * Escalate to a full v2 backup. Returns { ok:true, escalated:true, reason,
 * fullBackupResult }.
 */
async function escalateToFull(db, options, reason) {
  console.log(`gd-backup-incremental: escalating to full backup (reason=${reason})`);
  const fullBackupResult = await backupV2.performV2Backup(db, options);
  return { ok: true, escalated: true, reason, fullBackupResult };
}

module.exports = {
  performIncrementalBackup,
  // exported for tests + the restore-chain walker (which reads the INCR bundle)
  INCR_MAGIC,
  INCR_FORMAT_VERSION,
  INCR_HEADER_SIZE,
  INCR_PER_FRAME_OVERHEAD,
  buildFramesBundle,
  buildIncrementalManifest,
  findIncrementalParent,
  resolveAnchorFullBackupId,
  resolveMaxChainDepth,
  countExistingIncrementalsInChain,
};

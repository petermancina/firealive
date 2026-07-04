// =============================================================================
// FIREALIVE GD -- Differential Backup Writer (anchor-relative WAL capture)
//
// A differential backup captures the SQLite WAL frames written since the most
// recent FULL backup (the "anchor"). Unlike incrementals -- which chain, each
// link capturing only the delta from its immediate predecessor -- differentials
// are each independently restorable alongside the anchor: a restore needs only
// [anchor full + latest differential], never any intermediate differential.
// Twins the Regional differential writer, adapted for the GD.
//
// Trade-off vs incremental: differential archives grow over time (each duplicates
// frames captured by earlier differentials since the anchor), but restore is
// simpler/faster and resilient to losing any single intermediate archive.
//
// The implementation mirrors gd-backup-incremental. The differences:
//   1. Anchor selection: findDifferentialAnchor finds the most recent verified
//      full (type='full') with a WAL baseline -- not the most recent backup of
//      any kind.
//   2. Frame range: always [anchor.wal_end_position, current], so each successive
//      differential captures progressively more frames since the anchor.
//   3. Row linkage: backup_strategy='differential', with parent_backup_id and
//      parent_full_backup_id both pointing at the anchor (equal for any
//      differential -- a quick row-level discriminator from incrementals).
//
// The INCR-v1 frames bundle format is reused byte-for-byte from
// gd-backup-incremental; the encryption + signing + four-file layout + chain +
// push pipeline is identical to the incremental and full writers (the outer
// archive is archive.tar.gz.enc with an inner frames.bin entry), so a differential
// reuses the shared v2 push + retry path unchanged. Only the manifest's
// backup_type and the row's linkage distinguish it.
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
// Reuse the INCR-v1 binary bundle format from the incremental writer -- a
// differential archive uses the same bundle format byte-for-byte.
const incrementalSvc = require('./gd-backup-incremental');

const ARCHIVE_FILENAME     = manifestSvc.ARCHIVE_FILENAME;
const WRAPPED_KEY_FILENAME = manifestSvc.WRAPPED_KEY_FILENAME;
const MANIFEST_FILENAME    = manifestSvc.MANIFEST_FILENAME;
const MANIFEST_SIG_FILENAME = manifestSvc.SIGNATURE_FILENAME;

const DEFAULT_RETENTION_DAYS = 35;

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function resolveWalPath(options) {
  const dbPath = (options && options.dbPath)
    || process.env.GD_DB_PATH
    || path.join(__dirname, '..', 'data', 'global-dashboard.db');
  return dbPath + '-wal';
}

/**
 * Find the most recent eligible anchor full backup: status='verified',
 * type='full', wal_end_position set, format_version=2. Newest by created_at then
 * rowid (insertion order) so ties resolve to the most recent. Returns row or null.
 *
 * Does not verify the WAL salts still match; a stale anchor is caught by the
 * frame read and escalates to a full backup.
 */
function findDifferentialAnchor(db) {
  return db.prepare(`
    SELECT id, backup_strategy, parent_full_backup_id, wal_start_position, wal_end_position, page_count, created_at
      FROM backups
     WHERE status = 'verified'
       AND backup_strategy = 'full'
       AND wal_end_position IS NOT NULL
       AND format_version = 2
     ORDER BY created_at DESC, rowid DESC
     LIMIT 1
  `).get() || null;
}

/**
 * Build the differential manifest object. Same v3-family shape as the incremental
 * manifest, distinguished by backup_type='differential' and by parent linkage
 * pointing at the anchor full (parent and anchor are the same for a differential).
 */
function buildDifferentialManifest(args) {
  const required = ['backupId', 'backupType', 'anchorBackupId', 'walStartPosition', 'walEndPosition',
    'pageCount', 'pageSize', 'archiveFile', 'wrappedKeyFile', 'signingKeyId',
    'signingKeyFingerprint', 'sourceFuseCounter'];
  for (const k of required) {
    if (args[k] === undefined || args[k] === null) {
      throw new Error(`buildDifferentialManifest: ${k} required`);
    }
  }
  return {
    format_version: manifestSvc.MANIFEST_FORMAT_VERSION,
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
 * performDifferentialBackup(db, options)
 *
 * options: backupsDir, dbPath, compressionLevel, keyWrappingScheme, kekReference,
 * retentionDays, sourceFuseCounter/sourceSchemaVersion.
 *
 * Returns on success { ok:true, escalated:false, backupId, anchorBackupId,
 * walStartPosition, walEndPosition, pageCount, archivePath, manifestPath,
 * manifestSha256, chain_entry, chain_error, push }; on escalation { ok:true,
 * escalated:true, reason, fullBackupResult }; on failure { ok:false, error }.
 */
async function performDifferentialBackup(db, options = {}) {
  const backupsDir = backupV2.resolveBackupsDir(options);
  const compressionLevel = options.compressionLevel != null ? options.compressionLevel : archiveSvc.DEFAULT_GZIP_LEVEL;
  const keyWrappingScheme = options.keyWrappingScheme || keyWrapSvc.DEFAULT_SCHEME;
  const kekReference = options.kekReference || keyWrapSvc.DEFAULT_KEK_REFERENCE;
  // Regional parity: backups.type is the trigger; backup_strategy is 'differential'.
  const triggerType = options.triggerType === 'scheduled' ? 'scheduled' : 'on-demand';

  ensureDir(backupsDir);

  // Anchor selection: the latest FULL, not the latest of any kind.
  const anchor = findDifferentialAnchor(db);
  if (!anchor) {
    console.log('gd-backup-differential: no eligible anchor full backup; escalating to full');
    return escalateToFull(db, options, 'no-anchor');
  }
  if (!anchor.wal_end_position) {
    console.log('gd-backup-differential: anchor has no wal_end_position; escalating to full');
    return escalateToFull(db, options, 'incompatible-anchor');
  }

  const anchorPos = walExtractor.parseWalPosition(anchor.wal_end_position);
  const walPath = resolveWalPath(options);
  if (!fs.existsSync(walPath)) {
    console.log('gd-backup-differential: no WAL file present; escalating to full');
    return escalateToFull(db, options, 'no-wal-file');
  }

  let signingKey;
  try {
    signingKey = signingKeysSvc.getActiveSigningKey(db);
  } catch (err) {
    return { ok: false, error: `no active backup signing key: ${err.message}` };
  }

  // Read all frames since the anchor, autocheckpoint disabled.
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
      if (current.frameNo < anchorPos.frameNo) {
        saltChanged = true;
        return;
      }
      walPageSize = current.pageSize || 0;

      if (current.frameNo === anchorPos.frameNo) {
        // No frames since the anchor: empty differential.
        collectedFrames = [];
        endOffset = current.offset;
        endFrameNo = current.frameNo;
        return;
      }

      const frames = [];
      const result = walExtractor.streamWalPages(walPath, (entry) => {
        frames.push({
          frameNo: entry.frameNo,
          pageNo: entry.pageNo,
          dbSizeAfterCommit: entry.dbSizeAfterCommit,
          sha256: entry.sha256,
          pageBuf: Buffer.from(entry.pageBuf),
        });
      }, { startFrameNo: anchorPos.frameNo + 1, endFrameNo: current.frameNo });

      if (result.invalidSaltAtFrame !== null && result.invalidSaltAtFrame <= anchorPos.frameNo) {
        saltChanged = true;
        return;
      }

      collectedFrames = frames;
      walPageSize = result.header ? result.header.pageSize : walPageSize;
      endOffset = result.endOffset;
      endFrameNo = result.endFrameNo;
    });
  } catch (err) {
    console.error('gd-backup-differential: WAL read failed:', err.message);
    return { ok: false, error: err.message };
  }

  if (saltChanged) {
    console.log('gd-backup-differential: WAL salt changed since anchor (checkpoint occurred); escalating to full');
    return escalateToFull(db, options, 'salt-change');
  }

  collectedFrames = collectedFrames || [];

  // Build the four files under a temp dir, atomic-rename to final.
  const backupId = crypto.randomBytes(8).toString('hex');
  const dirName = `${backupId}-diff`;
  const tempDir = path.join(backupsDir, `.${dirName}.tmp`);
  const finalDir = path.join(backupsDir, dirName);

  const { sourceFuseCounter, sourceSchemaVersion } = backupV2.readSourceMeta(db, options);

  try {
    fs.mkdirSync(tempDir, { recursive: true });

    // Reuse the INCR-v1 bundle format from the incremental writer.
    const framesBundle = incrementalSvc.buildFramesBundle(walPageSize || 512, collectedFrames);
    const archived = await archiveSvc.buildArchive(framesBundle, 'frames.bin', { compressionLevel });
    const wrappedKey = await keyWrapSvc.wrapKey(archived.ephemeralKey, { scheme: keyWrappingScheme, kekReference });
    const wrappedKeySha = crypto.createHash('sha256').update(wrappedKey).digest('hex');

    const walEndPosition = walExtractor.serializeWalPosition({
      offset: endOffset != null ? endOffset : anchorPos.offset,
      frameNo: endFrameNo != null ? endFrameNo : anchorPos.frameNo,
    });

    const manifest = buildDifferentialManifest({
      backupId,
      backupType: triggerType,
      anchorBackupId: anchor.id,
      walStartPosition: anchor.wal_end_position,
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

    if (!fs.readFileSync(manifestPath).equals(manifestBytes)) {
      throw new Error('verify-after-write: manifest bytes on disk differ from in-memory bytes');
    }
    const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');
    const totalSize = [archivePath, wrappedKeyPath, manifestPath, manifestSigPath]
      .reduce((sum, p) => sum + fs.statSync(p).size, 0);

    // Insert row: backup_strategy='differential', parent + anchor both the anchor full.
    db.prepare(`
      INSERT INTO backups (id, type, backup_strategy, kind, size_bytes, sha256_hash, status, created_at,
                           format_version, manifest_path, archive_path,
                           manifest_sig_path, wrapped_key_path, signing_key_id,
                           parent_backup_id, parent_full_backup_id,
                           wal_start_position, wal_end_position, page_count)
      VALUES (?, ?, 'differential', 'single-db', ?, ?, 'verified', datetime('now'),
              2, ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?)
    `).run(
      backupId, triggerType, totalSize, manifestSha256,
      manifestPath, archivePath, manifestSigPath, wrappedKeyPath, signingKey.id,
      anchor.id, anchor.id, anchor.wal_end_position, walEndPosition, collectedFrames.length,
    );

    console.log(`gd-backup-differential: differential ${backupId} verified (anchor ${anchor.id}, ${collectedFrames.length} pages)`);

    // Append CREATE entry to the attestation chain (degraded-mode on failure).
    let chainEntry = null;
    let chainError = null;
    try {
      const result = chainSvc.appendChainEntry(db, {
        eventType: 'CREATE',
        backupId,
        payload: {
          backup_type: 'differential',
          format_version: 2,
          manifest_sha256: manifestSha256,
          archive_sha256: archived.sha256,
          parent_backup_id: anchor.id,
          parent_full_backup_id: anchor.id,
          wal_start_position: anchor.wal_end_position,
          wal_end_position: walEndPosition,
          page_count: collectedFrames.length,
          backup_signing_key_id: signingKey.id,
          source_fuse_counter: sourceFuseCounter,
          total_size_bytes: totalSize,
          backup_dir_name: path.basename(finalDir),
        },
      });
      chainEntry = { id: result.id, prev_hash: result.prevHash, this_hash: result.thisHash, signing_key_fingerprint: result.signingKeyFingerprint, created_at: result.createdAt };
      console.log(`gd-backup-differential: chain CREATE entry appended (chain id ${result.id})`);
    } catch (chainErr) {
      chainError = chainErr.message;
      console.error('gd-backup-differential: CHAIN ENTRY APPEND FAILED -- differential created without chain attestation. error=' + chainErr.message);
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
        console.error('gd-backup-differential: push orchestration crashed:', pushErr.message);
        push = { pushed: false, configured: true, error: pushErr.message, crashed: true };
      }
    }

    return {
      ok: true,
      escalated: false,
      backupId,
      anchorBackupId: anchor.id,
      walStartPosition: anchor.wal_end_position,
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
    console.error(`gd-backup-differential: differential ${backupId} FAILED:`, err.message);
    return { ok: false, error: err.message };
  }
}

/**
 * Escalate to a full v2 backup. Returns { ok:true, escalated:true, reason,
 * fullBackupResult }.
 */
async function escalateToFull(db, options, reason) {
  console.log(`gd-backup-differential: escalating to full backup (reason=${reason})`);
  const fullBackupResult = await backupV2.performV2Backup(db, options);
  return { ok: true, escalated: true, reason, fullBackupResult };
}

module.exports = {
  performDifferentialBackup,
  findDifferentialAnchor,
  buildDifferentialManifest,
};

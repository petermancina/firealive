// FIREALIVE GD -- Full-Suite Backup (v2 encrypted-signed comprehensive backup)
//
// The complete-state DR backup: a transactionally-consistent DB snapshot + a
// config snapshot + a version manifest, bundled and then run through the SAME v2
// pipeline as the single-DB backup -- tar + gzip + AES-256-GCM archive, a
// GD-Tier-1-wrapped ephemeral key, an Ed25519-signed canonical manifest, an
// attestation-chain entry, routed + pushed as one artifact set. No plaintext ever
// leaves memory. Mirrors the Regional's backup-full-suite.js against the GD's own
// v2 crypto helpers.
//
// Distinct from gd-backup-v2's single-DB full only in what the archive payload
// contains (a multi-file bundle vs one DB) and in that it never records a WAL
// baseline -- a full-suite bundle is not a single-DB archive, so an incremental
// must never anchor on it. Recorded as backup_strategy='full', kind='full-suite', format_version=2.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const archiveSvc = require('./gd-backup-archive');
const keyWrapSvc = require('./gd-backup-key-wrapping');
const manifestSvc = require('./gd-backup-manifest');
const signingKeysSvc = require('./gd-backup-signing-keys');
const chainSvc = require('./gd-backup-chain');
const storagePush = require('./gd-storage-push');
const backupV2 = require('./gd-backup-v2');

const DEFAULT_RETENTION_DAYS = 35;
const BUNDLE_FILENAME = 'firealive-gd-full-suite.tar';
const MAX_BUNDLE_BYTES = 8 * 1024 * 1024 * 1024; // 8 GB, matches the v2 engine ceiling

// Version manifest captured inside the bundle: shipped version + fleet/signing-key
// counts at backup time. Self-contained so it does not depend on the retiring v1
// gd-backup module.
function buildVersionManifest(db, id) {
  const mcs = db.prepare('SELECT COUNT(*) AS n FROM management_consoles').get().n;
  const mcsActive = db.prepare("SELECT COUNT(*) AS n FROM management_consoles WHERE status='active'").get().n;
  const sks = db.prepare('SELECT COUNT(*) AS n FROM signing_keys').get().n;
  const sksActive = db.prepare("SELECT COUNT(*) AS n FROM signing_keys WHERE is_active = 1").get().n;
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

// Build the comprehensive bundle (DB snapshot + config snapshot + version manifest)
// into a single plain-tar Buffer, ready for the v2 archive layer to compress +
// encrypt. The workdir is always removed before returning.
function buildBundleBytes(db, backupsDir, backupId, options) {
  const workDir = path.join(backupsDir, `.gd-fullsuite-${backupId}.work`);
  try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  fs.mkdirSync(workDir, { recursive: true });
  try {
    // 1. Transactionally-consistent DB snapshot (VACUUM INTO, via the v2 engine).
    const dbBytes = backupV2.snapshotDbBytes(db, backupsDir, `fullsuite-${backupId}`, options);
    fs.writeFileSync(path.join(workDir, 'global-dashboard.db'), dbBytes);

    // 2. config-snapshot.json (all config rows).
    const configRows = db.prepare('SELECT key, value FROM config').all();
    const configSnap = {};
    for (const r of configRows) configSnap[r.key] = r.value;
    fs.writeFileSync(path.join(workDir, 'config-snapshot.json'), JSON.stringify(configSnap, null, 2), 'utf8');

    // 3. version-manifest.json.
    const vmanifest = buildVersionManifest(db, backupId);
    fs.writeFileSync(path.join(workDir, 'version-manifest.json'), JSON.stringify(vmanifest, null, 2), 'utf8');

    // 4. server/integrity-manifest.json -- the GD code-integrity baseline.
    // P1-6: twin of the Regional full-suite backup, which carries its own
    // integrity manifest. The manifest ships inside the GD server dir
    // (gd-integrity.js); capturing it means a restored install carries the
    // code-integrity baseline current at backup time. Skipped if absent (a dev
    // tree with no generated manifest). The dead config/electron-security.js
    // entry the Regional backup used to carry is deliberately NOT copied (S4).
    const gdIntegrityManifestPath = path.join(__dirname, '..', 'integrity-manifest.json');
    if (fs.existsSync(gdIntegrityManifestPath)) {
      fs.writeFileSync(path.join(workDir, 'integrity-manifest.json'), fs.readFileSync(gdIntegrityManifestPath));
    }

    // 5. Plain tar the workdir to a Buffer; compression + encryption are the v2
    // archive layer's job (this bundle rides through as the single archive payload).
    const bundleBytes = execFileSync('tar', ['-cf', '-', '-C', workDir, '.'], {
      maxBuffer: MAX_BUNDLE_BYTES,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { bundleBytes, versionManifest: vmanifest };
  } finally {
    try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

// performFullSuiteBackup(db, options) -- mirrors gd-backup-v2.performV2Backup with the
// comprehensive bundle as the archive payload. Produces the four-file encrypted
// artifact, records backup_strategy='full'/kind='full-suite'/format_version=2 (no WAL baseline), chain-attests,
// and routes + pushes.
async function performFullSuiteBackup(db, options = {}) {
  const backupsDir = backupV2.resolveBackupsDir(options);
  const compressionLevel = options.compressionLevel != null ? options.compressionLevel : archiveSvc.DEFAULT_GZIP_LEVEL;
  const keyWrappingScheme = options.keyWrappingScheme || keyWrapSvc.DEFAULT_SCHEME;
  const kekReference = options.kekReference || keyWrapSvc.DEFAULT_KEK_REFERENCE;
  const retentionDays = options.retentionDays != null
    ? options.retentionDays
    : parseInt(process.env.GD_BACKUP_RETENTION_DAYS || String(DEFAULT_RETENTION_DAYS), 10);
  // The backups.type column is the trigger (Regional parity); the strategy is
  // backup_strategy. A full-suite is an on-demand full unless a scheduler drives it.
  const triggerType = options.triggerType === 'scheduled' ? 'scheduled' : 'on-demand';

  // B6k: create through the engine's verifying helper, not a raw mkdirSync.
  // gdDataRoot.ensureDir creates 0700 and REFUSES an already group- or
  // world-accessible directory rather than writing backups into it. The v2
  // engine has always done this (gd-backup-v2 ensureDir); the full-suite path
  // was the one place that did not, so a directory the boot posture check
  // already refuses could still be written into here. One path, not two.
  backupV2.ensureDir(backupsDir);
  backupV2.cleanStaleTempDirs(backupsDir);

  const backupId = crypto.randomBytes(8).toString('hex');
  const dirName = `${backupId}-fullsuite`;
  const tempDir = path.join(backupsDir, `.${dirName}.tmp`);
  const finalDir = path.join(backupsDir, dirName);

  // Resolve the active signing key up front so the row records which key signs this
  // backup even if a later step fails.
  let signingKey;
  try {
    signingKey = signingKeysSvc.getActiveSigningKey(db);
  } catch (err) {
    throw new Error(`gd-backup-full-suite: no active backup signing key (boot ensureActiveKeypair may have failed): ${err.message}`);
  }

  const { sourceFuseCounter, sourceSchemaVersion } = backupV2.readSourceMeta(db, options);

  db.prepare(`
    INSERT INTO backups (id, type, backup_strategy, kind, status, format_version, signing_key_id, created_at)
    VALUES (?, ?, 'full', 'full-suite', 'running', 2, ?, datetime('now'))
  `).run(backupId, triggerType, signingKey.id);

  try {
    // 1. Build the comprehensive bundle -> bytes.
    const { bundleBytes } = buildBundleBytes(db, backupsDir, backupId, options);

    // 2. tar + gzip + AES-256-GCM (the bundle is the single archive payload).
    const archive = await archiveSvc.buildArchive(bundleBytes, BUNDLE_FILENAME, { compressionLevel });

    // 3. Wrap the ephemeral key under the GD Tier-1 KEK.
    const wrappedKey = await keyWrapSvc.wrapKey(archive.ephemeralKey, { scheme: keyWrappingScheme, kekReference });
    const wrappedKeySha = crypto.createHash('sha256').update(wrappedKey).digest('hex');

    // 4. Build the canonical manifest.
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
      // D-R2-4: stamp the salted fingerprint of the GD Tier-1 KEK this backup was wrapped under,
      // so a restore can refuse a foreign-KEK backup before the swap.
      kekFingerprint: keyWrapSvc.resolveKekFingerprint(keyWrappingScheme),
      signingKeyId: signingKey.id,
      signingKeyFingerprint: signingKey.publicKeyFingerprint,
      sourceFuseCounter,
      sourceSchemaVersion,
    });

    // 5. Serialize + sign.
    const manifestBytes = manifestSvc.serialize(manifestObj);
    const { signature } = signingKeysSvc.signManifest(db, manifestBytes);

    // 6. Write to temp dir, atomic-rename to final.
    fs.mkdirSync(tempDir, { recursive: true });
    fs.writeFileSync(path.join(tempDir, manifestSvc.ARCHIVE_FILENAME),     archive.encryptedArchive);
    fs.writeFileSync(path.join(tempDir, manifestSvc.WRAPPED_KEY_FILENAME), wrappedKey);
    fs.writeFileSync(path.join(tempDir, manifestSvc.MANIFEST_FILENAME),    manifestBytes);
    fs.writeFileSync(path.join(tempDir, manifestSvc.SIGNATURE_FILENAME),   signature);
    fs.renameSync(tempDir, finalDir);

    // 7. Verify-after-write: re-read the manifest and compare bytes.
    const manifestOnDisk = fs.readFileSync(path.join(finalDir, manifestSvc.MANIFEST_FILENAME));
    if (!manifestOnDisk.equals(manifestBytes)) {
      throw new Error('verify-after-write: manifest bytes on disk differ from in-memory bytes');
    }
    const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');

    const archivePath    = path.join(finalDir, manifestSvc.ARCHIVE_FILENAME);
    const wrappedKeyPath  = path.join(finalDir, manifestSvc.WRAPPED_KEY_FILENAME);
    const manifestPath    = path.join(finalDir, manifestSvc.MANIFEST_FILENAME);
    const manifestSigPath = path.join(finalDir, manifestSvc.SIGNATURE_FILENAME);

    // 8. Update the row: verified + paths + size. No wal_end_position -- a
    // full-suite bundle never anchors an incremental. file_path stays NULL (v2).
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
          wrapped_key_path = ?
      WHERE id = ?
    `).run(
      totalSize, manifestSha256, manifestPath, archivePath, manifestSigPath,
      wrappedKeyPath, backupId,
    );

    console.log(`gd-backup-full-suite: backup ${backupId} verified (${totalSize} bytes, manifest ${manifestSha256.slice(0, 16)})`);

    // 9. Append CREATE entry to the attestation chain. Degraded-mode on failure: the
    // backup still exists and is verified; only the attestation is missing.
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
          backup_kind: 'full-suite',
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
      console.log(`gd-backup-full-suite: chain CREATE entry appended (chain id ${result.id}, ${result.thisHash.slice(0, 16)})`);
    } catch (chainErr) {
      chainError = chainErr.message;
      console.error(
        'gd-backup-full-suite: CHAIN ENTRY APPEND FAILED -- backup created without chain attestation. ' +
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
        push = await backupV2.pushV2BackupArtifact(db, {
          backupId, sourceDir: finalDir, files: hashed.files, manifestSha256, options,
        });
      } catch (pushErr) {
        console.error('gd-backup-full-suite: push orchestration crashed:', pushErr.message);
        push = { pushed: false, configured: true, error: pushErr.message, crashed: true };
      }
    }

    // 11. Retention cleanup (shared with the v2 engine).
    backupV2.cleanOldBackups(db, { ...options, retentionDays });

    return {
      id: backupId,
      format_version: 2,
      type: 'full',
      kind: 'full-suite',
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
      console.error('gd-backup-full-suite: failed to mark row failed:', updateErr.message);
    }
    for (const d of [tempDir, finalDir]) {
      if (fs.existsSync(d)) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* ignore */ } }
    }
    console.error(`gd-backup-full-suite: backup ${backupId} FAILED:`, err.message);
    throw err;
  }
}

module.exports = {
  performFullSuiteBackup,
  buildVersionManifest,
};

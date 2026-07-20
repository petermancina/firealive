// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Full-Suite Backup Orchestrator (R3k C7)
//
// SOC-grade comprehensive backup that captures everything needed to
// restore this install after compromise without the Lead having to
// rebuild any integrations. Sits ON TOP OF the existing v2 backup
// engine (services/backup.js + the building blocks) rather than
// replacing it — same Ed25519 manifest signature, same AES-256-GCM
// archive encryption, same wrapped DEK pattern, same backups table,
// same /verify path.
//
// SCOPE (per R3k Q6 LOCKED decision, BUILD-PLAN-v23)
// ===================================================
//
// The full-suite payload includes:
//
//   firealive.db                       binary snapshot via better-
//                                      sqlite3 .backup() (WAL-coord),
//                                      same mechanism as canonical
//                                      single-DB backup. Captures
//                                      EVERY table in the regional
//                                      DB including:
//                                        - users (analyst/lead/admin
//                                          roster, AC provisioning,
//                                          MFA state, recovery codes)
//                                        - team_config (incl.
//                                          panic_mode, routing_enabled,
//                                          panic_saved_caps)
//                                        - integration_config (every
//                                          integration's encrypted
//                                          credential ciphertext —
//                                          captured verbatim, the
//                                          KMS-wrapped DEKs unwrap
//                                          after restore on the same
//                                          KEK)
//                                        - audit_log (chain hashes
//                                          preserved as stored)
//                                        - ir_policies, MFA tables,
//                                          backup_schedules,
//                                          backup_destinations,
//                                          backup_signing_keys,
//                                          chain_signing_keys,
//                                          notifications,
//                                          helper_points_ledger,
//                                          peer_*, analyst_*,
//                                          assessment_*, ooda_*,
//                                          retro_*, ticket_*,
//                                          soar_routing_events,
//                                          routing_caps,
//                                          routing_overrides,
//                                          cicd_configs, cicd_runs,
//                                          cloud_iac_signing_keys,
//                                          kms_providers, and every
//                                          other canonical table
//
//   server/integrity-manifest.json     file-integrity baseline used
//                                      by services/integrity.js at
//                                      boot to detect binary
//                                      tampering. Needed after
//                                      restore so the restored
//                                      install can verify itself.
//
//   version-manifest.json              backup-time {version,
//                                      fuse_counter, build_id,
//                                      taken_at}. Used by the
//                                      restore path to pull the
//                                      matching upstream signed
//                                      binary from GitHub Releases
//                                      onto which config + data
//                                      gets restored.
//
// EXPLICITLY EXCLUDED
// ===================
//
//   - The FireAlive binary itself. SOC-grade incident recovery never
//     restores a possibly-tampered binary; restore pulls verified
//     Ed25519-signed upstream binary from GitHub Releases at the
//     version recorded in version-manifest.json, then restores config
//     + data onto that clean binary.
//
//   - .env / .env.example. The KEK (env-var scheme) is the root of
//     trust for the backup's wrapped DEK; including it in the backup
//     creates a chicken-and-egg situation where you need the KEK to
//     decrypt the backup that contains the KEK. Operators using the
//     env-var key wrapping scheme preserve .env out-of-band. Operators
//     using KMS-based wrapping (R3d-4+) re-authenticate the restored
//     install to KMS by IAM identity.
//
//   - Old backups directory contents. The backup_signing_keys + the
//     backups table rows ARE in the DB (so the new install knows
//     which past backups existed), but the actual backup .tar.zst.enc
//     archives on disk are NOT bundled. Recovery of older backup
//     contents (forensics) is a separate concern requiring access to
//     the prior backup store; the new install can verify older
//     backups via /api/backup/:id/verify once they're staged.
//
// PAYLOAD FORMAT
// ==============
//
// The full-suite bundle is serialized as a single JSON envelope:
//
//   {
//     format: 'firealive-full-suite-v1',
//     taken_at: '<ISO 8601>',
//     files: [
//       { path, encoding: 'base64'|'utf8', size, sha256, content }, ...
//     ]
//   }
//
// Each file's content is base64-encoded (binary) or UTF-8 (text). The
// envelope is fed to the v2 archive pipeline as a SINGLE source
// payload with sourceName='full-suite-bundle.json'. From the
// perspective of buildArchive(), it's just one file going in; the
// v2 pipeline (tar -> zstd -> AES-256-GCM) handles it identically to
// a single-DB backup.
//
// Restore (Sub-phase 6, GD-side mirror C19) parses the JSON envelope
// and writes each file back to its recorded path. The per-file
// sha256 inside the envelope is a redundant integrity check on top
// of the manifest's sha256 over the full encrypted archive.
//
// Base64 inflation (binary 33% larger) is washed out by zstd
// compression of the surrounding JSON structure; final encrypted
// size is comparable to a single-DB backup for typical install
// volumes.
//
// INTEGRATION WITH CANONICAL ENGINE
// =================================
//
// performFullSuiteBackup() mirrors the structure of performBackup()
// in services/backup.js: same temp-dir + atomic-rename, same
// verify-after-write, same backups-row lifecycle (insert running,
// update verified/failed), same building blocks. It does NOT call
// performBackup() directly because performBackup is hardcoded to
// snapshot a single DB; the full-suite payload is a multi-file
// bundle. Each path's distinct enough to warrant its own
// orchestrator while sharing the cryptographic primitives.
//
// The only schema difference: the backups row inserted by this
// service sets kind='full-suite' (R3k C2 column addition). The
// canonical /api/backup path continues to write rows with
// kind='single-db' via the column DEFAULT.
//
// FAILURE SEMANTICS
// =================
//
// On any failure of the backup pipeline, the backups row is updated
// to status='failed' before the error propagates, so the audit
// trail captures the attempt. Temp directories are cleaned in the
// catch block. The signing key id is recorded in the row up front
// so even a failed backup attributes to the key that would have
// signed it.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { logger } = require('./logger');
const { getDb, DB_PATH } = require('../db/init');
const archiveSvc = require('./backup-archive');
const keyWrapSvc = require('./backup-key-wrapping');
const manifestSvc = require('./backup-manifest');
const signingKeysSvc = require('./backup-signing-keys');

const STALE_TEMP_AGE_MS = 60 * 60 * 1000;
const BUNDLE_FILENAME = 'full-suite-bundle.json';
const BUNDLE_FORMAT_VERSION = 'firealive-full-suite-v1';

const Database = require('better-sqlite3');
const dataRoot = require('../lib/data-root');

// ── Helpers ────────────────────────────────────────────────────────────

function resolveBackupDir(override) {
  // P1-1: same chain and same root as services/backup.js -- one answer.
  return dataRoot.backupsDir(override);
}

function ensureDir(dir) {
  // 0700, and refuses an already group- or world-accessible directory.
  return dataRoot.ensureDir(dir);
}

function backupDirName(date = new Date()) {
  const stamp = date.toISOString().replace(/[:.]/g, '-');
  return `firealive-backup-${stamp}`;
}

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
          logger.info(`backup-full-suite: removed stale temp dir ${ent.name}`);
        }
      } catch { /* swallow per-entry */ }
    }
  } catch (err) {
    logger.warn('backup-full-suite: cleanStaleTempDirs failed', { error: err.message });
  }
}

function directorySize(dir) {
  let total = 0;
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ent.isFile()) total += fs.statSync(path.join(dir, ent.name)).size;
  }
  return total;
}

// ── DB snapshot (WAL-coordinated) ──────────────────────────────────────

/**
 * better-sqlite3's online backup API. Opens a separate connection,
 * holds a read transaction for the duration of the copy, coordinates
 * correctly with WAL-mode source. Mirrors services/backup.js
 * snapshotSourceDb behavior — duplicated here to keep the full-suite
 * service self-contained.
 */
async function snapshotMainDb(targetPath) {
  const sourceDb = new Database(DB_PATH, { readonly: true, fileMustExist: true });
  try {
    await sourceDb.backup(targetPath);
  } finally {
    sourceDb.close();
  }
}

// ── Bundle assembly ────────────────────────────────────────────────────

function readOptionalFile(absPath) {
  try {
    if (fs.existsSync(absPath)) return fs.readFileSync(absPath);
  } catch (err) {
    logger.warn(`backup-full-suite: failed to read ${absPath}`, { error: err.message });
  }
  return null;
}

function fileEntry(relativePath, contentBuffer, encoding) {
  const enc = encoding || 'base64';
  const content =
    enc === 'utf8' ? contentBuffer.toString('utf8') : contentBuffer.toString('base64');
  return {
    path: relativePath,
    encoding: enc,
    size: contentBuffer.length,
    sha256: crypto.createHash('sha256').update(contentBuffer).digest('hex'),
    content,
  };
}

/**
 * Build the full-suite bundle envelope:
 *   - firealive.db          (binary, base64)
 *   - server/integrity-manifest.json   (if present, utf8)
 *   - version-manifest.json            (utf8, generated here)
 *
 * Returns a Buffer (UTF-8 JSON bytes) ready to feed the v2 pipeline.
 */
async function buildBundle(workDir) {
  const dbSnapshotPath = path.join(workDir, 'firealive.db.snap');
  await snapshotMainDb(dbSnapshotPath);

  let dbBytes;
  try {
    dbBytes = fs.readFileSync(dbSnapshotPath);
  } finally {
    try { fs.unlinkSync(dbSnapshotPath); } catch { /* ignore */ }
  }

  const serverRoot = path.join(__dirname, '..');

  // P1-6: the code-integrity manifest now ships inside server/ (FATAL 5a
  // relocation). The dead config/electron-security.js baseline entry is dropped
  // with the file (S4); config/ no longer exists.
  const integrityManifestPath = path.join(serverRoot, 'integrity-manifest.json');

  const files = [];
  files.push(fileEntry('firealive.db', dbBytes, 'base64'));

  const integrityManifest = readOptionalFile(integrityManifestPath);
  if (integrityManifest) {
    files.push(fileEntry('server/integrity-manifest.json', integrityManifest, 'utf8'));
  }

  // Version manifest is always present — generated here from current
  // install state at backup time.
  let versionInfo = { version: 'unknown', fuse_counter: null, build_id: null };
  try {
    const v = require('../lib/version');
    versionInfo = {
      version: v.version || 'unknown',
      fuse_counter: typeof v.fuseCounter === 'number' ? v.fuseCounter : null,
      build_id: v.buildId || null,
    };
  } catch (e) {
    logger.warn('backup-full-suite: lib/version unavailable', { error: e.message });
  }
  const versionManifestText = JSON.stringify(
    {
      ...versionInfo,
      taken_at: new Date().toISOString(),
    },
    null,
    2,
  );
  files.push(fileEntry('version-manifest.json', Buffer.from(versionManifestText, 'utf8'), 'utf8'));

  const envelope = {
    format: BUNDLE_FORMAT_VERSION,
    taken_at: new Date().toISOString(),
    files,
  };

  return Buffer.from(JSON.stringify(envelope), 'utf8');
}

// ── Public API ─────────────────────────────────────────────────────────

/**
 * performFullSuiteBackup(options)
 *
 * options:
 *   type                Trigger type for the backups.type column.
 *                       Accepted: 'on-demand' (operator-triggered,
 *                       default) | 'scheduled' (scheduler-
 *                       triggered) | 'snapshot' (pre-restore
 *                       snapshot).
 *   backupDir           Override BACKUP_DIR / BACKUP_PATH env vars.
 *   compressionLevel    zstd compression level; defaults to v2
 *                       engine default.
 *   keyWrappingScheme   'env-var' (default) or a KMS scheme.
 *   kekReference        For 'env-var' scheme, the env-var name
 *                       holding the KEK (default TIER1_ENCRYPTION_
 *                       KEY).
 *
 * Returns the same shape as performBackup() in services/backup.js
 * with one additional field:
 *
 *   {
 *     id, format_version (2), backup_dir, manifest_path,
 *     archive_path, manifest_sig_path, wrapped_key_path,
 *     size_bytes, manifest_sha256, status, kind ('full-suite')
 *   }
 *
 * Throws on any pipeline failure. The backups row is updated to
 * status='failed' before throw so the audit trail records the
 * attempt.
 */
async function performFullSuiteBackup(options = {}) {
  const type = options.type || 'on-demand';
  if (!['scheduled', 'on-demand', 'snapshot'].includes(type)) {
    throw new Error(`performFullSuiteBackup: invalid type '${type}'`);
  }

  const backupDir = resolveBackupDir(options.backupDir);
  const compressionLevel =
    options.compressionLevel != null ? options.compressionLevel : archiveSvc.DEFAULT_ZSTD_LEVEL;
  const keyWrappingScheme = options.keyWrappingScheme || 'env-var';
  const kekReference =
    options.kekReference || (keyWrappingScheme === 'env-var' ? 'TIER1_ENCRYPTION_KEY' : '');

  ensureDir(backupDir);
  cleanStaleTempDirs(backupDir);

  const backupId = crypto.randomBytes(16).toString('hex');
  const dirName = backupDirName();
  const tempDir = path.join(backupDir, `.${dirName}.tmp`);
  const finalDir = path.join(backupDir, dirName);

  const db = getDb();

  let signingKey;
  try {
    signingKey = signingKeysSvc.getActiveSigningKey(db);
  } catch (err) {
    throw new Error(
      `performFullSuiteBackup: no active backup signing key: ${err.message}`,
    );
  }

  const fuseRow = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  const schemaVersionRow = db
    .prepare("SELECT value FROM system_meta WHERE key = 'schema_version'")
    .get();
  const sourceFuseCounter = fuseRow ? parseInt(fuseRow.value, 10) : 0;
  const sourceSchemaVersion = schemaVersionRow ? schemaVersionRow.value : '1';

  db.prepare(
    `INSERT INTO backups (id, type, status, format_version, signing_key_id, kind)
     VALUES (?, ?, 'running', 2, ?, 'full-suite')`,
  ).run(backupId, type, signingKey.id);

  try {
    // Build the bundle envelope (multi-file JSON) using temp work area
    fs.mkdirSync(tempDir, { recursive: true });
    const bundleBytes = await buildBundle(tempDir);

    // Pass the bundle as a single source through the v2 pipeline
    const archive = await archiveSvc.buildArchive(bundleBytes, BUNDLE_FILENAME, {
      compressionLevel,
    });

    // Wrap the ephemeral key under the KEK
    const wrappedKey = await keyWrapSvc.wrapKey(archive.ephemeralKey, {
      scheme: keyWrappingScheme,
      kekReference,
    });
    const wrappedKeySha = crypto.createHash('sha256').update(wrappedKey).digest('hex');

    // Canonical manifest
    const manifestObj = manifestSvc.buildManifest({
      backupId,
      backupType: type,
      fileHashes: {
        archive: { sizeBytes: archive.sizeBytes, sha256: archive.sha256 },
        wrappedKey: { sizeBytes: wrappedKey.length, sha256: wrappedKeySha },
      },
      compression: 'zstd',
      compressionLevel,
      keyWrappingScheme,
      kekReference,
      // D-R2-4: stamp the salted, non-correlatable fingerprint of the KEK that wrapped this
      // backup, so a restore can refuse a foreign-KEK backup before the swap.
      kekFingerprint: keyWrapSvc.resolveKekFingerprint(keyWrappingScheme, kekReference, db),
      signingKeyId: signingKey.id,
      signingKeyFingerprint: signingKey.publicKeyFingerprint,
      sourceFuseCounter,
      sourceSchemaVersion,
    });

    const manifestBytes = manifestSvc.serialize(manifestObj);
    const { signature } = signingKeysSvc.signManifest(db, manifestBytes);

    fs.writeFileSync(
      path.join(tempDir, manifestSvc.ARCHIVE_FILENAME),
      archive.encryptedArchive,
    );
    fs.writeFileSync(path.join(tempDir, manifestSvc.WRAPPED_KEY_FILENAME), wrappedKey);
    fs.writeFileSync(path.join(tempDir, manifestSvc.MANIFEST_FILENAME), manifestBytes);
    fs.writeFileSync(path.join(tempDir, manifestSvc.SIGNATURE_FILENAME), signature);
    fs.renameSync(tempDir, finalDir);

    // Verify-after-write
    const manifestOnDisk = fs.readFileSync(path.join(finalDir, manifestSvc.MANIFEST_FILENAME));
    if (!manifestOnDisk.equals(manifestBytes)) {
      throw new Error(
        'verify-after-write: manifest bytes on disk differ from in-memory bytes (disk corruption?)',
      );
    }
    const manifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex');

    const totalSize = directorySize(finalDir);
    db.prepare(
      `UPDATE backups
       SET status = 'verified',
           size_bytes = ?,
           sha256_hash = ?,
           manifest_path = ?,
           archive_path = ?,
           manifest_sig_path = ?,
           wrapped_key_path = ?
       WHERE id = ?`,
    ).run(
      totalSize,
      manifestSha256,
      path.join(finalDir, manifestSvc.MANIFEST_FILENAME),
      path.join(finalDir, manifestSvc.ARCHIVE_FILENAME),
      path.join(finalDir, manifestSvc.SIGNATURE_FILENAME),
      path.join(finalDir, manifestSvc.WRAPPED_KEY_FILENAME),
      backupId,
    );

    return {
      id: backupId,
      format_version: 2,
      kind: 'full-suite',
      backup_dir: finalDir,
      manifest_path: path.join(finalDir, manifestSvc.MANIFEST_FILENAME),
      archive_path: path.join(finalDir, manifestSvc.ARCHIVE_FILENAME),
      manifest_sig_path: path.join(finalDir, manifestSvc.SIGNATURE_FILENAME),
      wrapped_key_path: path.join(finalDir, manifestSvc.WRAPPED_KEY_FILENAME),
      size_bytes: totalSize,
      manifest_sha256: manifestSha256,
      status: 'verified',
    };
  } catch (err) {
    // Best-effort: mark the row failed before re-throwing.
    try {
      db.prepare("UPDATE backups SET status = 'failed' WHERE id = ?").run(backupId);
    } catch (updateErr) {
      logger.warn('backup-full-suite: failed to mark row failed', {
        backupId,
        error: updateErr.message,
      });
    }
    try {
      if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (cleanupErr) {
      logger.warn('backup-full-suite: temp dir cleanup failed', {
        tempDir,
        error: cleanupErr.message,
      });
    }
    throw err;
  }
}

module.exports = {
  performFullSuiteBackup,
  BUNDLE_FILENAME,
  BUNDLE_FORMAT_VERSION,
};

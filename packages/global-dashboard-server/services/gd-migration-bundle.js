// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- Migration Bundle Composer (FA-GDMIG1) (D14)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// Composes a GD deployment-migration bundle in the FA-GDMIG1 format from the GD
// full-suite backup (the B6b encrypted v2 pipeline). Unlike the Regional Server
// -- which layers a golden-baseline config capture alongside the data backup --
// the GD keeps no separate golden-baseline: the GD full-suite backup is a
// complete database backup, so GD config (the config table, system_meta, the
// sealed mode record) is captured inside the DATA layer itself. The bundle is
// therefore the GD-server backup plus a signed FA-GDMIG1 manifest.
//
// The FA-GDMIG1 manifest binds the backup by SHA-256 and is signed with the GD's
// Ed25519 backup signing key (the same key that already signs the embedded
// full-suite backup), so tampering with either the backup or the manifest is
// detectable on import. The manifest also records the source GD anchor
// fingerprint for provenance.
//
// IMPORTANT (D14 / 5b) -- a migration bundle deliberately carries NO instance
// identity. The reconciliation layers are:
//   - GD instance-level identity (anchor, CA, server/device keys, certs) ....
//     re-established FRESH on the target at import time (gd-migration-identity);
//     never restored verbatim, because verbatim identity restore IS cloning.
//   - data (audit / forensic chains, GD config, sealed history, registered MC
//     bindings and aggregate data) .... PRESERVED.
//
// This composer produces the DATA payload plus a signed manifest; the
// fresh-identity re-establishment is the job of the import reconciler
// (gd-migration-reconcile.js). Every export is recorded in the
// gd_migration_bundles ledger with a building -> complete / failed lifecycle.
// Each trust realm bundles its own artifacts; the GD is never a write-path into
// the Regional Server.
// -----------------------------------------------------------------------------

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const APP_VERSION = require('../package.json').version;
const { canonicalize, sha256Hex } = require('./report-signer');
const { performFullSuiteBackup } = require('./gd-backup-full-suite');
const signingKeysSvc = require('./gd-backup-signing-keys');
const manifestSvc = require('./gd-backup-manifest');
const anchor = require('./gd-instance-anchor');
const gdDataRoot = require('../lib/gd-data-root');

const logger = {
  info: (m, meta) => console.log('[gd-migration-bundle] ' + m, meta !== undefined ? meta : ''),
  warn: (m, meta) => console.warn('[gd-migration-bundle] ' + m, meta !== undefined ? meta : ''),
};

// FA-GDMIG1 envelope constants.
const FORMAT = 'FA-GDMIG1';
const BUNDLE_SCHEMA_VERSION = 1;

// File layout inside a composed bundle directory.
const MANIFEST_FILENAME = 'migration-manifest.json';
const SIGNATURE_FILENAME = 'migration-manifest.sig';
const BACKUP_SUBDIR = 'backup';

// The four full-suite backup artifacts copied into the bundle's backup/ dir.
const BACKUP_FILES = [
  manifestSvc.MANIFEST_FILENAME,
  manifestSvc.ARCHIVE_FILENAME,
  manifestSvc.WRAPPED_KEY_FILENAME,
  manifestSvc.SIGNATURE_FILENAME,
];

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function resolveBundleDir(override) {
  // P1-1: GD_MIGRATION_BUNDLE_DIR, else the canonical GD data root.
  // routes/gd-migration.js confines operator-supplied paths to this same root,
  // and before P1 it did NOT: it used the Regional Server's
  // MIGRATION_BUNDLE_DIR and a different default, so a bundle the GD exported
  // was not importable by the GD. Both now call this one function.
  return override || gdDataRoot.migrationBundlesDir();
}

function ensureDir(dir) {
  // 0700, and refuses an already group- or world-accessible directory.
  return gdDataRoot.ensureDir(dir);
}

// Recursive byte total (the bundle contains a backup/ subdirectory, so a
// top-level-only sum would undercount).
function directorySize(dir) {
  let total = 0;
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      total += directorySize(full);
    } else if (ent.isFile()) {
      total += fs.statSync(full).size;
    }
  }
  return total;
}

function sourceAnchorFingerprint(db, id) {
  try {
    const identity = anchor.load({ db: db });
    if (identity) return anchor.fingerprint(identity);
  } catch (err) {
    logger.warn('anchor fingerprint unavailable', { id: id, error: err.message });
  }
  return null;
}

// -----------------------------------------------------------------------------
// composeMigrationBundle(db, options)
//
// options:
//   createdByUserId  user id recorded as the bundle author (optional)
//   outputDir        override the bundle output directory (optional)
//
// Returns a result object describing the composed bundle. Throws on failure
// after marking the ledger row failed and cleaning the temp directory.
// -----------------------------------------------------------------------------
async function composeMigrationBundle(db, options) {
  options = options || {};
  const createdByUserId = options.createdByUserId || null;
  const id = 'gd-mig-' + crypto.randomUUID();
  const createdAt = new Date().toISOString();

  const baseDir = resolveBundleDir(options.outputDir);
  ensureDir(baseDir);
  const finalDir = path.join(baseDir, id);
  const tempDir = path.join(baseDir, '.' + id + '.tmp');

  db.prepare(
    'INSERT INTO gd_migration_bundles '
    + '(id, created_by_user_id, created_at, format, bundle_schema_version, '
    + 'app_version, status) '
    + "VALUES (?, ?, ?, ?, ?, ?, 'building')"
  ).run(id, createdByUserId, createdAt, FORMAT, BUNDLE_SCHEMA_VERSION, APP_VERSION);

  try {
    // DATA layer: a GD full-suite backup (already signed and KEK-wrapped through
    // the B6b encrypted v2 pipeline). This backup captures the full GD database,
    // GD config included, so no separate config layer is needed.
    const backup = await performFullSuiteBackup(db, {});

    // Bind the backup into the signed FA-GDMIG1 manifest.
    const manifest = {
      format: FORMAT,
      bundleSchemaVersion: BUNDLE_SCHEMA_VERSION,
      appVersion: APP_VERSION,
      createdAt: createdAt,
      backup: { id: backup.backup_id, manifestSha256: backup.manifest_sha256 },
      source: { anchorFingerprint: sourceAnchorFingerprint(db, id) },
    };
    const manifestCanonical = canonicalize(manifest);
    const manifestBytes = Buffer.from(manifestCanonical, 'utf8');
    const bundleSha256 = sha256Hex(manifestCanonical);

    const signingKey = signingKeysSvc.getActiveSigningKey(db);
    const signed = signingKeysSvc.signManifest(db, manifestBytes);

    // Assemble the self-contained bundle directory atomically (temp -> rename).
    if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
    fs.mkdirSync(tempDir, { recursive: true });
    fs.writeFileSync(path.join(tempDir, MANIFEST_FILENAME), manifestBytes);
    fs.writeFileSync(path.join(tempDir, SIGNATURE_FILENAME), signed.signature);
    const backupOut = path.join(tempDir, BACKUP_SUBDIR);
    fs.mkdirSync(backupOut, { recursive: true });
    for (const fname of BACKUP_FILES) {
      fs.copyFileSync(
        path.join(backup.backup_dir, fname),
        path.join(backupOut, fname),
      );
    }
    fs.renameSync(tempDir, finalDir);

    const sizeBytes = directorySize(finalDir);
    const manifestPath = path.join(finalDir, MANIFEST_FILENAME);
    const manifestSigPath = path.join(finalDir, SIGNATURE_FILENAME);
    const completedAt = new Date().toISOString();

    db.prepare(
      'UPDATE gd_migration_bundles '
      + 'SET status = ?, bundle_path = ?, manifest_path = ?, manifest_sig_path = ?, '
      + 'bundle_sha256 = ?, size_bytes = ?, backup_ref = ?, '
      + 'signing_key_fingerprint = ?, completed_at = ? '
      + 'WHERE id = ?'
    ).run(
      'complete', finalDir, manifestPath, manifestSigPath,
      bundleSha256, sizeBytes, backup.backup_id,
      signingKey.publicKeyFingerprint, completedAt, id,
    );

    logger.info('composed FA-GDMIG1 bundle', {
      id: id,
      bundle_sha256: bundleSha256,
      size_bytes: sizeBytes,
    });

    return {
      id: id,
      format: FORMAT,
      bundleSchemaVersion: BUNDLE_SCHEMA_VERSION,
      bundle_dir: finalDir,
      manifest_path: manifestPath,
      manifest_sig_path: manifestSigPath,
      bundle_sha256: bundleSha256,
      size_bytes: sizeBytes,
      backup_ref: backup.backup_id,
      signing_key_fingerprint: signingKey.publicKeyFingerprint,
      status: 'complete',
    };
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    try {
      db.prepare(
        'UPDATE gd_migration_bundles SET status = ?, error_message = ? WHERE id = ?'
      ).run('failed', message, id);
    } catch (updateErr) {
      logger.warn('failed to mark row failed', { id: id, error: updateErr.message });
    }
    try {
      if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (cleanupErr) {
      logger.warn('temp cleanup failed', { id: id, error: cleanupErr.message });
    }
    throw err;
  }
}

module.exports = {
  FORMAT,
  BUNDLE_SCHEMA_VERSION,
  MANIFEST_FILENAME,
  SIGNATURE_FILENAME,
  BACKUP_SUBDIR,
  composeMigrationBundle,
};

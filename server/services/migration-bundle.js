// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE — Migration Bundle Composer (FA-MIG1) (D14)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// Composes a deployment-migration bundle in the FA-MIG1 format from two
// existing building blocks already proven in the suite:
//
//   - golden-baseline (FA-GB1) config capture .... CONFIG layer (B5d3)
//   - full-suite backup ........................... DATA   layer (R3k)
//
// The FA-MIG1 manifest binds both components by SHA-256 and is signed with
// the deployment's Ed25519 backup signing key (the same key that already
// signs the embedded full-suite backup), so tampering with either component
// or the manifest is detectable on import. The manifest also records the
// source instance anchor fingerprint for provenance.
//
// IMPORTANT (D14 / D19) — a migration bundle deliberately carries NO
// instance identity. The three reconciliation layers are:
//
//   - instance-level identity (CA, server keys, AC device keys, certs,
//     enrollment) .... re-established FRESH on the target at import time;
//     never restored verbatim, because verbatim identity restore IS cloning.
//   - analyst-level keys (burnout keys, recovery wraps) .... PRESERVED
//     (recoverable via the offline recovery code).
//   - data (audit / forensic / legal chains, configs, sealed history) ....
//     PRESERVED.
//
// This composer produces the CONFIG + DATA payload plus a signed manifest;
// the fresh-identity re-establishment is the job of the import reconciler
// (services/migration-reconcile.js). Every export is recorded in the
// migration_bundles ledger with a building -> complete / failed lifecycle.
// ─────────────────────────────────────────────────────────────────────────────

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { logger } = require('./logger');
const { version: APP_VERSION } = require('../lib/version');
const { canonicalize, sha256Hex } = require('./report-signer');
const { captureBaseline, BASELINE_SCHEMA_VERSION } = require('./golden-baseline');
const { performFullSuiteBackup } = require('./backup-full-suite');
const signingKeysSvc = require('./backup-signing-keys');
const manifestSvc = require('./backup-manifest');
const anchor = require('./instance-anchor');
const dataRoot = require('../lib/data-root');

// FA-MIG1 envelope constants.
const FORMAT = 'FA-MIG1';
const BUNDLE_SCHEMA_VERSION = 1;

// File layout inside a composed bundle directory.
const MANIFEST_FILENAME = 'migration-manifest.json';
const SIGNATURE_FILENAME = 'migration-manifest.sig';
const BASELINE_FILENAME = 'golden-baseline.json';
const BACKUP_SUBDIR = 'backup';

// The four full-suite backup artifacts copied into the bundle's backup/ dir.
const BACKUP_FILES = [
  manifestSvc.MANIFEST_FILENAME,
  manifestSvc.ARCHIVE_FILENAME,
  manifestSvc.WRAPPED_KEY_FILENAME,
  manifestSvc.SIGNATURE_FILENAME,
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function resolveBundleDir(override) {
  // P1-1: MIGRATION_BUNDLE_DIR, else the canonical data root. routes/
  // migration.js confines operator-supplied paths to this same root, so both
  // must resolve identically -- they now call one function.
  return override || dataRoot.migrationBundlesDir();
}

function ensureDir(dir) {
  // 0700, and refuses an already group- or world-accessible directory.
  return dataRoot.ensureDir(dir);
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
    const identity = anchor.load({ db });
    if (identity) return anchor.fingerprint(identity);
  } catch (err) {
    logger.warn('migration-bundle: anchor fingerprint unavailable', {
      id,
      error: err.message,
    });
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// composeMigrationBundle(db, options)
//
// options:
//   createdByUserId  user id recorded as the bundle author (optional)
//   outputDir        override the bundle output directory (optional)
//
// Returns a result object describing the composed bundle. Throws on failure
// after marking the ledger row failed and cleaning the temp directory.
// ─────────────────────────────────────────────────────────────────────────────
async function composeMigrationBundle(db, options) {
  options = options || {};
  const createdByUserId = options.createdByUserId || null;
  const id = 'mig-' + crypto.randomUUID();
  const createdAt = new Date().toISOString();

  const baseDir = resolveBundleDir(options.outputDir);
  ensureDir(baseDir);
  const finalDir = path.join(baseDir, id);
  const tempDir = path.join(baseDir, '.' + id + '.tmp');

  db.prepare(
    'INSERT INTO migration_bundles '
    + '(id, created_by_user_id, created_at, format, bundle_schema_version, '
    + 'app_version, status) '
    + "VALUES (?, ?, ?, ?, ?, ?, 'building')"
  ).run(id, createdByUserId, createdAt, FORMAT, BUNDLE_SCHEMA_VERSION, APP_VERSION);

  try {
    // CONFIG layer: golden-baseline (FA-GB1) canonical capture.
    const baseline = captureBaseline(db);

    // DATA layer: a full-suite backup (already signed and KEK-wrapped).
    const backup = await performFullSuiteBackup({ type: 'snapshot' });

    // Bind both components into the signed FA-MIG1 manifest.
    const manifest = {
      format: FORMAT,
      bundleSchemaVersion: BUNDLE_SCHEMA_VERSION,
      appVersion: APP_VERSION,
      createdAt,
      baseline: { schemaVersion: BASELINE_SCHEMA_VERSION, sha256: baseline.sha256 },
      backup: { id: backup.id, manifestSha256: backup.manifest_sha256 },
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
    fs.writeFileSync(
      path.join(tempDir, BASELINE_FILENAME),
      Buffer.from(baseline.canonical, 'utf8'),
    );
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
      'UPDATE migration_bundles '
      + 'SET status = ?, bundle_path = ?, manifest_path = ?, manifest_sig_path = ?, '
      + 'bundle_sha256 = ?, size_bytes = ?, baseline_sha256 = ?, backup_ref = ?, '
      + 'signing_key_fingerprint = ?, completed_at = ? '
      + 'WHERE id = ?'
    ).run(
      'complete', finalDir, manifestPath, manifestSigPath,
      bundleSha256, sizeBytes, baseline.sha256, backup.id,
      signingKey.publicKeyFingerprint, completedAt, id,
    );

    logger.info('migration-bundle: composed FA-MIG1 bundle', {
      id,
      bundle_sha256: bundleSha256,
      size_bytes: sizeBytes,
    });

    return {
      id,
      format: FORMAT,
      bundleSchemaVersion: BUNDLE_SCHEMA_VERSION,
      bundle_dir: finalDir,
      manifest_path: manifestPath,
      manifest_sig_path: manifestSigPath,
      bundle_sha256: bundleSha256,
      size_bytes: sizeBytes,
      baseline_sha256: baseline.sha256,
      backup_ref: backup.id,
      signing_key_fingerprint: signingKey.publicKeyFingerprint,
      status: 'complete',
    };
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    try {
      db.prepare(
        'UPDATE migration_bundles SET status = ?, error_message = ? WHERE id = ?'
      ).run('failed', message, id);
    } catch (updateErr) {
      logger.warn('migration-bundle: failed to mark row failed', {
        id,
        error: updateErr.message,
      });
    }
    try {
      if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (cleanupErr) {
      logger.warn('migration-bundle: temp cleanup failed', {
        id,
        error: cleanupErr.message,
      });
    }
    throw err;
  }
}

module.exports = {
  FORMAT,
  BUNDLE_SCHEMA_VERSION,
  MANIFEST_FILENAME,
  SIGNATURE_FILENAME,
  BASELINE_FILENAME,
  BACKUP_SUBDIR,
  composeMigrationBundle,
};

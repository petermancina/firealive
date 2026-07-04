// -----------------------------------------------------------------------------
// FIREALIVE -- Migration Import Apply (FA-MIG1) (D14 / 5b)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// The destructive half of a FA-MIG1 deployment migration. It composes the
// read-only reconciler, the shared restore-swap primitive, the identity
// re-establishment, and the config re-baseline into one in-process flow:
//
//   1. hard verify gate: the bundle must be intact AND its signatures must
//      have verified against the trusted source key (planReconciliation's
//      proceedable). An apply never runs on structure alone.
//   2. read the embedded full-suite backup (the DATA layer) and its manifest,
//      plus the golden-baseline payload (the authoritative CONFIG layer).
//   3. close the live database handle so the swap can rename over it.
//   4. DATA: restore the source database through the shared, EDR-scanned swap
//      primitive (which also snapshots the current database for rollback).
//   5. reopen against the restored database.
//   6. IDENTITY: re-establish instance identity FRESH (the source identity is
//      wiped and re-minted; never carried, because that would be cloning).
//   7. CONFIG: re-baseline the curated config domain from the authoritative
//      golden-baseline snapshot.
//
// getDb opens a fresh connection per call, so no process restart is required
// for connection correctness. A restart is still recommended afterward (and
// the result says so) to refresh process-lifetime caches (deployment-mode
// summary, anchor) and to run schema migrations if the bundle came from a
// different build; cross-version migration is gated by the reconciler's
// version warning.
//
// The caller's database handle is closed by this function; callers must not
// reuse it afterward.
// -----------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const { getDb } = require('../db-init');
const reconcileSvc = require('./gd-migration-reconcile');
const migrationIdentity = require('./gd-migration-identity');
const dbRestoreSwap = require('./gd-db-restore-swap');
const goldenBaseline = require('./gd-golden-baseline');
const bundleSvc = require('./gd-migration-bundle');
const backupManifestSvc = require('./gd-backup-manifest');

const CODES = {
  REFUSED_UNVERIFIED: 'REFUSED_UNVERIFIED',
  BACKUP_MANIFEST_INVALID: 'BACKUP_MANIFEST_INVALID',
};

class MigrationApplyError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'MigrationApplyError';
    this.code = code;
    this.detail = detail || null;
  }
}

// -----------------------------------------------------------------------------
// applyReconciliation(db, options)
//
// options:
//   bundleDir            extracted FA-MIG1 bundle directory
//   trustedPublicKeyPem  source deployment backup signing public key (PEM)
//   executingUserId      operator id recorded for the config re-baseline
//   commonName           server certificate common name for the fresh identity
//   hostnames            server certificate SAN hostnames for the fresh identity
//
// Returns a result describing the restore, the fresh identity, the re-baseline,
// any reconciler warnings, and that a restart is recommended. Throws
// MigrationApplyError on the verify gate, or DbRestoreError from the swap.
// -----------------------------------------------------------------------------
async function applyReconciliation(db, options) {
  options = options || {};
  const bundleDir = options.bundleDir;

  // 1. Hard gate: intact AND signatures verified against the trusted key.
  const plan = reconcileSvc.planReconciliation(bundleDir, {
    trustedPublicKeyPem: options.trustedPublicKeyPem,
  });
  if (!plan.proceedable) {
    throw new MigrationApplyError(CODES.REFUSED_UNVERIFIED,
      'migration bundle is not proceedable; refusing to apply',
      { issues: plan.verification.issues, warnings: plan.warnings });
  }

  // 2. DATA layer inputs: embedded full-suite backup manifest + bytes.
  const backupDir = path.join(bundleDir, bundleSvc.BACKUP_SUBDIR);
  let backupManifest;
  try {
    backupManifest = JSON.parse(
      fs.readFileSync(path.join(backupDir, backupManifestSvc.MANIFEST_FILENAME), 'utf8'));
  } catch (err) {
    throw new MigrationApplyError(CODES.BACKUP_MANIFEST_INVALID,
      'embedded backup manifest is unreadable: ' + err.message);
  }
  const wrapping = backupManifest.key_wrapping || {};
  const archiveBytes = fs.readFileSync(
    path.join(backupDir, backupManifestSvc.ARCHIVE_FILENAME));
  const wrappedKeyBytes = fs.readFileSync(
    path.join(backupDir, backupManifestSvc.WRAPPED_KEY_FILENAME));

  // 3. CONFIG layer input: authoritative golden-baseline payload.
  const baselinePayload = JSON.parse(
    fs.readFileSync(path.join(bundleDir, bundleSvc.BASELINE_FILENAME), 'utf8'));
  const manifest = plan.verification.manifest || {};
  const baselineSchemaVersion =
    manifest.baseline && Number.isInteger(manifest.baseline.schemaVersion)
      ? manifest.baseline.schemaVersion
      : goldenBaseline.BASELINE_SCHEMA_VERSION;

  // 4. Close the live handle so the swap can rename over the database path.
  db.close();

  // 5. DATA: restore through the shared, EDR-scanned swap primitive.
  const restore = await dbRestoreSwap.restoreDatabaseFromArchive({
    archiveBytes,
    wrappedKeyBytes,
    scheme: wrapping.scheme,
    kekReference: wrapping.kek_reference,
    label: 'migration-restore',
  });

  // 6. Reopen against the restored database.
  const restoredDb = getDb();
  let identity;
  let baseline;
  try {
    // 7. IDENTITY: wipe the source identity and mint fresh.
    identity = migrationIdentity.reestablishIdentityFresh(restoredDb, {
      commonName: options.commonName || 'localhost',
      hostnames: options.hostnames || [],
    });
    // 8. CONFIG: re-baseline the curated domain from the authoritative snapshot.
    baseline = goldenBaseline.applyBaseline(
      restoredDb,
      { schemaVersion: baselineSchemaVersion, payload: baselinePayload },
      options.executingUserId || null);
  } finally {
    try { restoredDb.close(); } catch (closeErr) { /* best effort */ }
  }

  console.log('migration-apply: reconciliation applied', {
    preRestorePath: restore.preRestorePath,
    newAnchorFingerprint: identity.newAnchorFingerprint,
  });

  return {
    ok: true,
    preRestorePath: restore.preRestorePath,
    scan: restore.scan,
    identity,
    baseline,
    warnings: plan.warnings,
    restartRecommended: true,
  };
}

module.exports = {
  CODES,
  MigrationApplyError,
  applyReconciliation,
};

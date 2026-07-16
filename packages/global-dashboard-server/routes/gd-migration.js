// ==============================================================================
// FIREALIVE -- Migration API (FA-MIG1) (D14)
//
// Mounted in server/index.js under authMiddleware(['admin']) +
// configLockChokepoint(); /api/migration is a config-write mount, so every
// POST here is gated by the config lock and registered in
// middleware/config-write-routes.js.
//
// Endpoints:
//   POST /export          compose a signed FA-MIG1 bundle (step-up)
//   POST /import/preview   dry-run reconciliation plan (read-only)
//   POST /import/apply     restore + re-establish identity fresh (step-up)
//
// Import trust model: the source deployment's Ed25519 backup signing key must
// be registered as a trusted verification key (matching the foreign-backup
// trust model). The fingerprint is read from the bundle's embedded backup
// manifest and resolved against the registered keys; an unregistered key
// yields 403 and the apply is refused.
// ==============================================================================

const fs = require('fs');
const path = require('path');
const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const { gdMfaStepUp: mfaStepUp } = require('../services/gd-mfa-stepup');
const migrationBundle = require('../services/gd-migration-bundle');
const migrationReconcile = require('../services/gd-migration-reconcile');
const migrationApply = require('../services/gd-migration-apply');
const signingKeysSvc = require('../services/gd-backup-signing-keys');
const backupManifestSvc = require('../services/gd-backup-manifest');
const gdDataRoot = require('../lib/gd-data-root');

// Self-contained audit helper mapping the Regional auditLog(userId, eventType,
// detail, ip) signature onto the GD audit chain, so the call sites stay verbatim.
function auditLog(userId, eventType, detail, ip) {
  let adb;
  try { adb = getDb(); appendGdAuditEntry(adb, { userId, eventType, detail, ip }); }
  catch (e) { console.error('gd-migration audit error:', e.message); }
  finally { if (adb) { try { adb.close(); } catch (_e) { /* ignore */ } } }
}

// Failure code -> HTTP status for the apply path (MigrationApplyError and the
// DbRestoreError codes that propagate from the shared swap primitive).
const CODE_STATUS = {
  REFUSED_UNVERIFIED: 403,
  SIGNING_KEY_UNTRUSTED: 403,
  BACKUP_MANIFEST_INVALID: 400,
  KEY_UNWRAP_FAILED: 422,
  EXTRACT_FAILED: 422,
  EXTRACT_UNEXPECTED_FILE: 422,
  SCANNER_NOT_CONFIGURED: 409,
  MALWARE_DETECTED: 422,
  SCAN_FAILED: 409,
  PRE_RESTORE_SNAPSHOT_FAILED: 500,
  ATOMIC_APPLY_FAILED: 500,
};

// The server-controlled root that GD migration bundles live under, and the
// confinement root for the path-traversal defense below. It MUST resolve to
// exactly what the bundle composer (services/gd-migration-bundle.js) writes
// exports to.
//
// Before P1 it did not, and the mismatch was a live bug. This file was copied
// from the Regional Server's routes/migration.js and its paths were never
// adapted: it read MIGRATION_BUNDLE_DIR -- the REGIONAL server's variable, not
// the GD's GD_MIGRATION_BUNDLE_DIR -- and defaulted one directory higher, to
// <install>/resources/data/migration-bundles, under a different name, while the
// composer wrote to <gd-server>/data/gd-migration-bundles. Different variable,
// different root, different name. A bundle the GD exported was not importable
// by the GD, and this confinement root guarded a directory nothing ever wrote
// to. The stale comment naming "services/migration-bundle.js" and
// "MIGRATION_BUNDLE_DIR" is what a copy leaves behind.
//
// Composer and importer now call one function, so they cannot disagree again.
const BUNDLE_ROOT = path.resolve(gdDataRoot.migrationBundlesDir());

// Validate the bundle directory supplied in the request body and confine it to
// BUNDLE_ROOT. The operator-supplied value is resolved against the root and
// rejected unless it stays within it, so a request cannot drive a filesystem
// path outside the bundle area (path-traversal defense).
function resolveBundleDir(body) {
  const bundleDirInput = body && typeof body.bundleDir === 'string' ? body.bundleDir.trim() : '';
  if (!bundleDirInput) {
    return { error: 'bundleDir is required (server-side path to the extracted FA-MIG1 bundle)', code: 'INVALID_INPUT' };
  }
  const bundleDir = path.resolve(BUNDLE_ROOT, bundleDirInput);
  const rel = path.relative(BUNDLE_ROOT, bundleDir);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return { error: 'bundleDir must be within the configured migration bundle root', code: 'INVALID_INPUT' };
  }
  let stat;
  try {
    stat = fs.statSync(bundleDir);
  } catch (err) {
    return { error: 'bundleDir does not exist on this server', code: 'BUNDLE_NOT_FOUND' };
  }
  if (!stat.isDirectory()) {
    return { error: 'bundleDir is not a directory', code: 'BUNDLE_NOT_DIR' };
  }
  return { bundleDir };
}

// Resolve the source deployment's trusted backup signing key from the bundle's
// embedded backup manifest fingerprint. verKey is null when the fingerprint is
// not registered as trusted.
function resolveTrustedKey(db, bundleDir) {
  const backupManifestPath = path.join(
    bundleDir, migrationBundle.BACKUP_SUBDIR, backupManifestSvc.MANIFEST_FILENAME);
  let fingerprint = null;
  try {
    const manifest = JSON.parse(fs.readFileSync(backupManifestPath, 'utf8'));
    fingerprint = manifest.signing_key_fingerprint || null;
  } catch (err) {
    return { error: 'embedded backup manifest is missing or unreadable', code: 'BACKUP_MANIFEST_INVALID' };
  }
  const verKey = fingerprint
    ? signingKeysSvc.getVerificationKeyByFingerprint(db, fingerprint)
    : null;
  return { fingerprint, verKey };
}

// ==============================================================================
// POST /export -- compose a signed FA-MIG1 migration bundle.
// ==============================================================================
router.post('/export', mfaStepUp(), async (req, res) => {
  const db = getDb();
  try {
    const result = await migrationBundle.composeMigrationBundle(db, {
      createdByUserId: req.user.id,
    });
    auditLog(req.user.id, 'MIGRATION_BUNDLE_EXPORTED',
      'id=' + result.id + ' sha256=' + result.bundle_sha256, req.ip);
    return res.json(Object.assign({ ok: true }, result));
  } catch (err) {
    console.error('migration export failed', { error: err.message });
    return res.status(500).json({ error: err.message, code: 'EXPORT_FAILED' });
  } finally {
    try { db.close(); } catch (closeErr) { /* idempotent */ }
  }
});

// ==============================================================================
// POST /import/preview -- read-only reconciliation plan (dry run). Reports the
// section 5b plan, the source signing fingerprint, and whether that key is
// trusted. Never mutates.
// ==============================================================================
router.post('/import/preview', (req, res) => {
  const resolved = resolveBundleDir(req.body);
  if (resolved.error) return res.status(400).json(resolved);
  const db = getDb();
  try {
    const trust = resolveTrustedKey(db, resolved.bundleDir);
    if (trust.error) return res.status(400).json(trust);
    const plan = migrationReconcile.planReconciliation(resolved.bundleDir, {
      trustedPublicKeyPem: trust.verKey ? trust.verKey.publicKeyPem : undefined,
    });
    return res.json({
      ok: true,
      sourceSigningFingerprint: trust.fingerprint,
      sourceKeyTrusted: !!trust.verKey,
      plan,
    });
  } finally {
    try { db.close(); } catch (closeErr) { /* idempotent */ }
  }
});

// ==============================================================================
// POST /import/apply -- destructive. Refuses unless the source key is trusted,
// then restores the data and re-establishes instance identity fresh.
// ==============================================================================
router.post('/import/apply', mfaStepUp(), async (req, res) => {
  const resolved = resolveBundleDir(req.body);
  if (resolved.error) return res.status(400).json(resolved);
  const body = req.body || {};
  const db = getDb();
  try {
    const trust = resolveTrustedKey(db, resolved.bundleDir);
    if (trust.error) {
      try { db.close(); } catch (closeErr) { /* idempotent */ }
      return res.status(400).json(trust);
    }
    if (!trust.verKey) {
      try { db.close(); } catch (closeErr) { /* idempotent */ }
      return res.status(403).json({
        error: 'the source deployment backup signing key is not registered as trusted '
          + '(or has been rotated out); register it after confirming the fingerprint '
          + 'out of band, then retry',
        code: 'SIGNING_KEY_UNTRUSTED',
        fingerprint: trust.fingerprint,
      });
    }
    const result = await migrationApply.applyReconciliation(db, {
      bundleDir: resolved.bundleDir,
      trustedPublicKeyPem: trust.verKey.publicKeyPem,
      executingUserId: req.user.id,
      commonName: typeof body.commonName === 'string' ? body.commonName : undefined,
      hostnames: Array.isArray(body.hostnames) ? body.hostnames : undefined,
    });
    auditLog(req.user.id, 'MIGRATION_IMPORT_APPLIED',
      'fingerprint=' + trust.fingerprint
      + ' newAnchor=' + (result.identity && result.identity.newAnchorFingerprint)
      + ' preRestore=' + result.preRestorePath, req.ip);
    return res.json(Object.assign({ ok: true }, result));
  } catch (err) {
    try { db.close(); } catch (closeErr) { /* apply may have closed it; idempotent */ }
    console.error('migration apply failed', { code: err.code, error: err.message });
    auditLog(req.user.id, 'MIGRATION_IMPORT_FAILED',
      'code=' + (err.code || 'APPLY_FAILED') + ' error=' + err.message, req.ip);
    const status = CODE_STATUS[err.code] || 500;
    return res.status(status).json({
      error: err.message,
      code: err.code || 'APPLY_FAILED',
      detail: err.detail || null,
    });
  }
});

module.exports = router;

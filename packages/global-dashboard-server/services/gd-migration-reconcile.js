// -----------------------------------------------------------------------------
// FIREALIVE -- Migration Import Reconciliation (FA-MIG1) (D14 / 5b)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// Read-only verification and planning for importing a FA-MIG1 deployment
// migration bundle (produced by services/migration-bundle.js). This module
// never mutates: it proves a bundle is well-formed and intact, and it
// renders the section 5b reconciliation plan that the operator previews
// before authorizing an apply. The destructive apply (restore data, then
// re-establish instance identity fresh) is a separate, gated step.
//
// Verification layers:
//   - structure ....... manifest parses, format is FA-MIG1, schema supported
//   - integrity ....... SHA-256 of the golden-baseline payload and the
//                       embedded backup manifest match the FA-MIG1 manifest
//                       (no key required; detects corruption or substitution)
//   - authenticity .... when a trusted public key is supplied, the FA-MIG1
//                       manifest signature AND the embedded backup manifest
//                       signature are verified against it
//
// The trusted key is supplied by the caller, not embedded in the bundle: a
// migration is a trusted external restore, so the source deployment's backup
// signing key is established out of band (the same trust model the suite
// already uses for foreign backups). A self-asserted in-bundle key would
// only prove internal consistency, not provenance, so it is deliberately
// not trusted here.
//
// The section 5b plan separates three layers of the imported bundle:
//   - instance-level identity ... re-established FRESH on the target (never
//     restored verbatim, because verbatim identity restore IS cloning)
//   - analyst-level keys ........ PRESERVED (user-bound, survive the reset)
//   - data ...................... PRESERVED (audit / forensic chains,
//     config, sealed history, training / helper-pay)
// -----------------------------------------------------------------------------

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const APP_VERSION = require('../package.json').version;
const bundleSvc = require('./gd-migration-bundle');
const backupManifestSvc = require('./gd-backup-manifest');

const SUPPORTED_BUNDLE_SCHEMA_VERSION = bundleSvc.BUNDLE_SCHEMA_VERSION;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function verifyEd25519(messageBytes, signatureBytes, publicKey) {
  try {
    return crypto.verify(null, messageBytes, publicKey, signatureBytes);
  } catch (err) {
    return false;
  }
}

// -----------------------------------------------------------------------------
// verifyBundle(bundleDir, options)
//
// options:
//   trustedPublicKeyPem  PEM of the source deployment's Ed25519 backup
//                        signing key. When present, signatures are verified;
//                        when absent, only structure and integrity are checked.
//
// Returns a structured result. ok reflects structure + integrity (+ signatures
// when a key was supplied). signatureChecked tells callers whether authenticity
// was actually evaluated; an apply path must require a supplied key and valid
// signatures, never apply on structure alone.
// -----------------------------------------------------------------------------
function verifyBundle(bundleDir, options) {
  options = options || {};
  const issues = [];
  const result = {
    ok: false,
    bundleDir,
    format: null,
    bundleSchemaVersion: null,
    signatureChecked: false,
    manifestSignatureValid: null,
    backupSignatureValid: null,
    components: { baseline: null, backup: null },
    manifest: null,
    issues,
  };

  const manifestPath = path.join(bundleDir, bundleSvc.MANIFEST_FILENAME);
  const sigPath = path.join(bundleDir, bundleSvc.SIGNATURE_FILENAME);
  const baselinePath = path.join(bundleDir, bundleSvc.BASELINE_FILENAME);
  const backupDir = path.join(bundleDir, bundleSvc.BACKUP_SUBDIR);
  const backupManifestPath = path.join(backupDir, backupManifestSvc.MANIFEST_FILENAME);
  const backupSigPath = path.join(backupDir, backupManifestSvc.SIGNATURE_FILENAME);

  const required = [
    [manifestPath, 'migration manifest'],
    [sigPath, 'migration manifest signature'],
    [baselinePath, 'golden-baseline payload'],
    [backupManifestPath, 'embedded backup manifest'],
    [backupSigPath, 'embedded backup manifest signature'],
  ];
  for (const entry of required) {
    if (!fs.existsSync(entry[0])) issues.push('missing ' + entry[1]);
  }
  if (issues.length) return result;

  const manifestBytes = fs.readFileSync(manifestPath);
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (err) {
    issues.push('migration manifest is not valid JSON');
    return result;
  }
  result.manifest = manifest;
  result.format = manifest.format || null;
  result.bundleSchemaVersion =
    typeof manifest.bundleSchemaVersion === 'number' ? manifest.bundleSchemaVersion : null;

  if (manifest.format !== bundleSvc.FORMAT) {
    issues.push('unexpected format ' + String(manifest.format)
      + ' (expected ' + bundleSvc.FORMAT + ')');
  }
  if (!Number.isInteger(manifest.bundleSchemaVersion)) {
    issues.push('bundleSchemaVersion is missing or non-integer');
  } else if (manifest.bundleSchemaVersion !== SUPPORTED_BUNDLE_SCHEMA_VERSION) {
    issues.push('unsupported bundleSchemaVersion ' + manifest.bundleSchemaVersion
      + ' (this build supports ' + SUPPORTED_BUNDLE_SCHEMA_VERSION + ')');
  }

  // Integrity: component bytes must match the hashes the manifest commits to.
  const baselineSha = sha256File(baselinePath);
  const baselineOk = !!(manifest.baseline && baselineSha === manifest.baseline.sha256);
  result.components.baseline = baselineOk;
  if (!baselineOk) issues.push('golden-baseline payload SHA-256 does not match the manifest');

  const backupSha = sha256File(backupManifestPath);
  const backupOk = !!(manifest.backup && backupSha === manifest.backup.manifestSha256);
  result.components.backup = backupOk;
  if (!backupOk) issues.push('embedded backup manifest SHA-256 does not match the manifest');

  // Authenticity: only when a trusted key is supplied.
  if (options.trustedPublicKeyPem) {
    let publicKey;
    try {
      publicKey = crypto.createPublicKey(options.trustedPublicKeyPem);
    } catch (err) {
      issues.push('trusted public key is not a valid key');
      return result;
    }
    result.signatureChecked = true;
    result.manifestSignatureValid = verifyEd25519(
      manifestBytes, fs.readFileSync(sigPath), publicKey);
    if (!result.manifestSignatureValid) {
      issues.push('migration manifest signature did not verify against the trusted key');
    }
    result.backupSignatureValid = verifyEd25519(
      fs.readFileSync(backupManifestPath), fs.readFileSync(backupSigPath), publicKey);
    if (!result.backupSignatureValid) {
      issues.push('embedded backup manifest signature did not verify against the trusted key');
    }
  }

  result.ok = issues.length === 0
    && (!options.trustedPublicKeyPem
      || (result.manifestSignatureValid === true && result.backupSignatureValid === true));
  if (!result.ok) {
    console.warn('migration-reconcile: bundle verification failed', {
      bundleDir,
      issues,
    });
  }
  return result;
}

// -----------------------------------------------------------------------------
// planReconciliation(bundleDir, options)
//
// Verifies the bundle, then renders the section 5b three-layer plan plus
// source / bundle metadata and any version warnings. Read-only; this is the
// dry-run preview shown before an apply is authorized.
// -----------------------------------------------------------------------------
function planReconciliation(bundleDir, options) {
  options = options || {};
  const verification = verifyBundle(bundleDir, options);
  const manifest = verification.manifest || {};
  const warnings = [];

  if (manifest.appVersion && manifest.appVersion !== APP_VERSION) {
    warnings.push('bundle was exported from app version ' + manifest.appVersion
      + '; this target runs ' + APP_VERSION + '.');
  }
  if (!verification.signatureChecked) {
    warnings.push('signatures were not verified: supply the source deployment '
      + 'backup signing public key before authorizing an apply.');
  }

  return {
    verification,
    proceedable: verification.ok && verification.signatureChecked === true,
    source: {
      appVersion: manifest.appVersion || null,
      anchorFingerprint: (manifest.source && manifest.source.anchorFingerprint) || null,
      createdAt: manifest.createdAt || null,
    },
    bundle: {
      format: manifest.format || null,
      bundleSchemaVersion:
        typeof manifest.bundleSchemaVersion === 'number' ? manifest.bundleSchemaVersion : null,
      baselineSha256: (manifest.baseline && manifest.baseline.sha256) || null,
      backupId: (manifest.backup && manifest.backup.id) || null,
    },
    layers: {
      instanceIdentity: {
        action: 're-establish-fresh',
        preserved: false,
        detail: 'CA, server keys, analyst-client device signing keys, issued '
          + 'certificates, and enrollment are minted fresh on this target. The '
          + 'source instance identity is NOT restored verbatim, because verbatim '
          + 'identity restore is indistinguishable from cloning. Analyst clients '
          + 're-bind to the new identity through the authenticated teardown / '
          + 'reprovision ceremony after import.',
      },
      analystKeys: {
        action: 'preserve',
        preserved: true,
        detail: 'Per-analyst burnout keys and recovery wraps are restored as-is '
          + 'and remain recoverable through the offline recovery code; they are '
          + 'user-bound rather than instance-bound, so they survive the identity '
          + 'reset.',
      },
      data: {
        action: 'preserve',
        preserved: true,
        detail: 'Audit and forensic chains, team and system config, '
          + 'sealed history, and training / helper-pay records are restored as-is.',
      },
    },
    warnings,
  };
}

module.exports = {
  SUPPORTED_BUNDLE_SCHEMA_VERSION,
  verifyBundle,
  planReconciliation,
};

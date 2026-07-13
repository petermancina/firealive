// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE — Live Database Restore Swap (shared primitive)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The one security-reviewed path for replacing the live SQLite database with
// the contents of a signed, KEK-wrapped backup archive. Both the external
// restore orchestrator and the deployment-migration apply call this, so the
// most sensitive operation in the platform has a single implementation rather
// than divergent copies.
//
// Steps, in order (each fatal):
//   1. unwrap the data encryption key under the KEK
//   2. decrypt + decompress + untar the archive
//   3. confirm the extracted file is firealive.db
//   4. mandatory EDR malware scan of the extracted bytes (defense in depth
//      against a tampered archive whose signature still verifies, e.g. a
//      signing-key compromise); fail-closed on no scanner, on a detected
//      threat, and on an inconclusive scan
//   5. snapshot the CURRENT live database to a pre-restore file (rollback)
//   6. atomic-rename the extracted bytes over the live database path
//
// Contract: the caller MUST close its own database handle before calling, so
// the rename does not write to an unlinked ghost inode. getDb opens a fresh
// connection per call, so after this returns the caller simply calls getDb
// again to operate on the restored database; no process restart is required
// for connection correctness (a restart is still advisable to refresh any
// process-lifetime caches). The short-lived scan connection here is opened
// and closed internally and reads the pre-swap database (where scanner
// configuration lives).
// ─────────────────────────────────────────────────────────────────────────────

const fs = require('fs');
const path = require('path');

const { logger } = require('./logger');
const keyWrapSvc = require('./backup-key-wrapping');
const archiveSvc = require('./backup-archive');
const manifestSvc = require('./backup-manifest');
const { IntegrationManager } = require('./integration-manager');
const { DB_PATH, getDb } = require('../db/init');

const EXPECTED_DB_FILENAME = 'firealive.db';
const EXPECTED_MEDIA_TYPE = 'application/x-sqlite3';

const CODES = {
  KEY_UNWRAP_FAILED: 'KEY_UNWRAP_FAILED',
  EXTRACT_FAILED: 'EXTRACT_FAILED',
  EXTRACT_UNEXPECTED_FILE: 'EXTRACT_UNEXPECTED_FILE',
  SCANNER_NOT_CONFIGURED: 'SCANNER_NOT_CONFIGURED',
  MALWARE_DETECTED: 'MALWARE_DETECTED',
  SCAN_FAILED: 'SCAN_FAILED',
  PRE_RESTORE_SNAPSHOT_FAILED: 'PRE_RESTORE_SNAPSHOT_FAILED',
  ATOMIC_APPLY_FAILED: 'ATOMIC_APPLY_FAILED',
  KEK_MISMATCH: 'KEK_MISMATCH',
  KEK_FINGERPRINT_FAILED: 'KEK_FINGERPRINT_FAILED',
};

class DbRestoreError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'DbRestoreError';
    this.code = code;
    this.detail = detail || null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// scanExtractedBytes(payload)
//
// Mandatory EDR scan of the extracted database bytes. Opens its own short-
// lived connection (the pre-swap database holds scanner configuration) and
// closes it. Fail-closed: throws on no configured scanner, on a detected
// threat, and on an inconclusive result. Returns the scan result on success.
// ─────────────────────────────────────────────────────────────────────────────
async function scanExtractedBytes(payload) {
  const scanDb = getDb();
  let scanResult;
  try {
    const mgr = new IntegrationManager(scanDb);
    try {
      scanResult = await mgr.inspectFile(payload, EXPECTED_DB_FILENAME, EXPECTED_MEDIA_TYPE);
    } catch (err) {
      throw new DbRestoreError(CODES.SCAN_FAILED, 'malware scan threw: ' + err.message);
    }
  } finally {
    try { scanDb.close(); } catch (closeErr) { /* best effort */ }
  }
  if (scanResult.skipped === true) {
    throw new DbRestoreError(CODES.SCANNER_NOT_CONFIGURED,
      'restore requires at least one configured malware scanner. '
      + 'Configure one under MC > Malware Scanners and retry.');
  }
  if (scanResult.clean !== true) {
    const threats = Array.isArray(scanResult.threats) ? scanResult.threats : [];
    if (threats.length > 0) {
      throw new DbRestoreError(CODES.MALWARE_DETECTED,
        'malware detected in extracted backup bytes: ' + threats.join(', '),
        {
          scanId: scanResult.scanId || null,
          provider: scanResult.provider || null,
          threats,
          scanners: scanResult.scanners || [],
        });
    }
    throw new DbRestoreError(CODES.SCAN_FAILED,
      'malware scan did not produce an authoritative clean result '
      + '(all configured scanners errored)',
      { scanId: scanResult.scanId || null, scanners: scanResult.scanners || [] });
  }
  return scanResult;
}

// ─────────────────────────────────────────────────────────────────────────────
// restoreDatabaseFromArchive(options)
//
// options:
//   archiveBytes     Buffer of the encrypted archive (archive.tar.zst.enc)
//   wrappedKeyBytes  Buffer of the KEK-wrapped data key (wrapped-key.bin)
//   scheme           key-wrapping scheme from the backup manifest
//   kekReference     KEK reference from the backup manifest
//   label            short filesystem-safe tag for snapshot/temp filenames
//
// Returns { preRestorePath, scan, restored: true }. Throws DbRestoreError on
// any fatal condition. The caller must have closed its own db handle first.
// ─────────────────────────────────────────────────────────────────────────────
async function restoreDatabaseFromArchive(options) {
  options = options || {};
  const archiveBytes = options.archiveBytes;
  const wrappedKeyBytes = options.wrappedKeyBytes;
  const scheme = options.scheme;
  const kekReference = options.kekReference;
  const label = options.label || 'restore';

  // 1. Unwrap the data encryption key under the KEK.
  let ephemeralKey;
  try {
    ephemeralKey = await keyWrapSvc.unwrapKey(wrappedKeyBytes, scheme, kekReference);
  } catch (err) {
    throw new DbRestoreError(CODES.KEY_UNWRAP_FAILED,
      'DEK unwrap failed (scheme=' + scheme + ', kek=' + kekReference + '): ' + err.message,
      { hint: 'Restoring requires the same KEK that wrapped the data key.' });
  }

  // 2. Decrypt + decompress + untar.
  let extracted;
  try {
    extracted = await archiveSvc.extractArchive(archiveBytes, ephemeralKey);
  } catch (err) {
    throw new DbRestoreError(CODES.EXTRACT_FAILED, 'archive extraction failed: ' + err.message);
  }

  // 3. Confirm the extracted file is the expected SQLite database.
  if (extracted.name !== EXPECTED_DB_FILENAME) {
    throw new DbRestoreError(CODES.EXTRACT_UNEXPECTED_FILE,
      "extracted archive contains '" + extracted.name + "', expected '"
      + EXPECTED_DB_FILENAME + "'");
  }

  // 4. Mandatory EDR scan (fail-closed).
  const scan = await scanExtractedBytes(extracted.payload);

  // 4b. KEK-match gate (D-R2-4). Confirm this host's KEK matches the one the backup was wrapped
  // under, via the salted fingerprint the manifest carries -- so a foreign-KEK backup is refused
  // BEFORE the swap, with the live handle untouched. A cross-KEK restore must go through the
  // offline import-rekey tool. A legacy manifest with no fingerprint (verdict null) is not blocked.
  if (options.manifest) {
    let verdict;
    const fpDb = getDb();
    try {
      const targetKekFp = keyWrapSvc.resolveKekFingerprint(scheme, kekReference, fpDb);
      verdict = manifestSvc.verifyKekFingerprint(options.manifest, targetKekFp);
    } catch (err) {
      throw new DbRestoreError(CODES.KEK_FINGERPRINT_FAILED,
        'KEK fingerprint check failed: ' + err.message);
    } finally {
      try { fpDb.close(); } catch (closeErr) { /* best effort */ }
    }
    if (verdict === false) {
      throw new DbRestoreError(CODES.KEK_MISMATCH,
        'this backup was wrapped under a different KEK than this host resolves; '
        + 'a cross-KEK restore must go through the offline import-rekey tool');
    }
  }

  // 5. Pre-restore snapshot of the current live database (rollback path).
  const dbDir = path.dirname(DB_PATH);
  const preRestorePath = path.join(dbDir, 'pre-' + label + '-' + Date.now() + '.db');
  try {
    fs.copyFileSync(DB_PATH, preRestorePath);
  } catch (err) {
    throw new DbRestoreError(CODES.PRE_RESTORE_SNAPSHOT_FAILED,
      'failed to snapshot current DB to ' + preRestorePath + ': ' + err.message);
  }

  // 6. Atomic-rename the extracted bytes over the live database path.
  const tempDbPath = path.join(dbDir, '.' + label + '-' + Date.now() + '.db.tmp');
  try {
    fs.writeFileSync(tempDbPath, extracted.payload);
    fs.renameSync(tempDbPath, DB_PATH);
  } catch (err) {
    try { fs.unlinkSync(tempDbPath); } catch (cleanupErr) { /* best effort */ }
    throw new DbRestoreError(CODES.ATOMIC_APPLY_FAILED,
      'atomic apply failed: ' + err.message + ' -- recover from ' + preRestorePath);
  }

  logger.info('db-restore-swap: live database restored', { label, preRestorePath });
  return { preRestorePath, scan, restored: true };
}

module.exports = {
  CODES,
  DbRestoreError,
  EXPECTED_DB_FILENAME,
  scanExtractedBytes,
  restoreDatabaseFromArchive,
};

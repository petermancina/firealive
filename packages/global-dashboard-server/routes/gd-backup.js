// =============================================================================
// FIREALIVE GD -- Backup Control Routes (v2)
//
// Operator API for the GD's v2 backup engine, twinning the Regional backup routes:
// list backups, trigger a backup by strategy, inspect the attestation chain and a
// backup's restore lineage, verify a backup's integrity, and manage the manifest-
// signing keypair.
//
//   GET    /                     list the most recent backups (v2-aware fields)
//   POST   /                     trigger a backup; ?strategy= or { strategy } selects
//                                v2 | full | full-suite | incremental | differential
//                                | snapshot
//   GET    /chain                attestation-chain overview (head + stats)
//   POST   /chain/verify         verify the full hash-linked attestation chain
//   GET    /signing-keys         list manifest-signing keys (public material only)
//   POST   /signing-keys/rotate  rotate to a fresh local Ed25519 keypair
//   POST   /signing-keys/register-external   register an external public key
//   GET    /:id/chain            walk a backup's restore lineage (anchor -> leaf)
//   POST   /:id/verify           verify a backup (v1 hash; v2 manifest+sig+archive)
//
// Trigger dispatch:
//   v2 / full    -> gd-backup-v2.performV2Backup            (WAL-tracked v2 full)
//   full-suite   -> gd-backup-full-suite.performFullSuiteBackup  (encrypted comprehensive)
//   snapshot     -> gd-backup-v2.performSnapshotBackup       (encrypted point-in-time)
//   incremental  -> gd-backup-incremental.performIncrementalBackup
//   differential -> gd-backup-differential.performDifferentialBackup
//
// Incremental and differential ESCALATE to a full backup when no eligible parent /
// anchor exists; the response and audit record both the requested strategy and the
// strategy actually produced. Synchronous-await: trigger blocks until complete.
//
// Mounted in index.js behind authMiddleware + the config-lock chokepoint, so this
// router carries no auth of its own. Scheduling lives under /api/backup-schedules;
// retention is DB-authoritative plus GD_BACKUP_RETENTION_DAYS. Audit events are
// drawn from the BACKUP_* set. Route order places /chain and /signing-keys before
// the parameterized /:id paths so specific segments are not captured as an id.
// =============================================================================

'use strict';

const fs = require('fs');
const crypto = require('crypto');
const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const backupV2 = require('../services/gd-backup-v2');
const fullSuiteSvc = require('../services/gd-backup-full-suite');
const incrementalSvc = require('../services/gd-backup-incremental');
const differentialSvc = require('../services/gd-backup-differential');
const chainSvc = require('../services/gd-backup-chain');
const signingKeysSvc = require('../services/gd-backup-signing-keys');
const manifestSvc = require('../services/gd-backup-manifest');

const VALID_STRATEGIES = ['v2', 'full', 'full-suite', 'incremental', 'differential', 'snapshot'];
const RESTORABLE_STATUSES = ['verified', 'completed'];

function actorOf(req) {
  return req.user && req.user.id ? req.user.id : 'system';
}

function _audit(db, req, eventType, detail) {
  try {
    appendGdAuditEntry(db, { userId: actorOf(req), eventType, detail, ip: (req && req.ip) || null, severity: 'info' });
  } catch (e) {
    try { console.warn('[gd-backup] audit failed:', e && e.message); } catch (_e) { /* ignore */ }
  }
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// -- GET / (list) -------------------------------------------------------------
router.get('/', (req, res) => {
  let db;
  try {
    db = getDb();
    const backups = db.prepare(
      'SELECT id, type, backup_strategy, kind, size_bytes, sha256_hash, file_path, status, created_at, '
      + 'format_version, manifest_path, archive_path, manifest_sig_path, wrapped_key_path, '
      + 'signing_key_id, parent_backup_id, parent_full_backup_id, '
      + 'wal_start_position, wal_end_position, page_count '
      + 'FROM backups ORDER BY created_at DESC LIMIT 50'
    ).all();
    return res.json({ backups });
  } catch (err) {
    console.error('routes/gd-backup: list failed:', err.message);
    return res.status(500).json({ error: 'Failed to list backups' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- POST / (trigger) ---------------------------------------------------------
router.post('/', async (req, res) => {
  let db;
  const body = (req.body && typeof req.body === 'object') ? req.body : {};
  const requestedStrategy = String(req.query.strategy || body.strategy || 'v2').toLowerCase();
  if (VALID_STRATEGIES.indexOf(requestedStrategy) === -1) {
    return res.status(400).json({
      error: 'invalid strategy',
      code: 'INVALID_BACKUP_STRATEGY',
      hint: 'strategy must be one of: ' + VALID_STRATEGIES.join(', '),
    });
  }

  db = getDb();
  try {
    let result;
    let actualStrategy = requestedStrategy;
    let escalationReason = null;

    if (requestedStrategy === 'v2' || requestedStrategy === 'full') {
      result = await backupV2.performV2Backup(db, {});
    } else if (requestedStrategy === 'full-suite') {
      result = await fullSuiteSvc.performFullSuiteBackup(db, {});
      actualStrategy = 'full-suite';
    } else if (requestedStrategy === 'snapshot') {
      result = await backupV2.performSnapshotBackup(db, {});
      actualStrategy = 'snapshot';
    } else if (requestedStrategy === 'incremental') {
      const incResult = await incrementalSvc.performIncrementalBackup(db, {});
      if (incResult.escalated) {
        result = incResult.fullBackupResult;
        actualStrategy = 'full';
        escalationReason = incResult.reason;
      } else if (!incResult.ok) {
        throw new Error(incResult.error || 'incremental backup failed');
      } else {
        result = {
          id: incResult.backupId,
          format_version: 2,
          type: 'incremental',
          size_bytes: 0,
          manifest_sha256: incResult.manifestSha256,
          parent_backup_id: incResult.parentBackupId,
          parent_full_backup_id: incResult.parentFullBackupId,
          page_count: incResult.pageCount,
          wal_start_position: incResult.walStartPosition,
          wal_end_position: incResult.walEndPosition,
          status: 'verified',
          chain_entry: incResult.chain_entry,
          chain_error: incResult.chain_error,
        };
      }
    } else if (requestedStrategy === 'differential') {
      const diffResult = await differentialSvc.performDifferentialBackup(db, {});
      if (diffResult.escalated) {
        result = diffResult.fullBackupResult;
        actualStrategy = 'full';
        escalationReason = diffResult.reason;
      } else if (!diffResult.ok) {
        throw new Error(diffResult.error || 'differential backup failed');
      } else {
        result = {
          id: diffResult.backupId,
          format_version: 2,
          type: 'differential',
          size_bytes: 0,
          manifest_sha256: diffResult.manifestSha256,
          parent_backup_id: diffResult.anchorBackupId,
          parent_full_backup_id: diffResult.anchorBackupId,
          page_count: diffResult.pageCount,
          wal_start_position: diffResult.walStartPosition,
          wal_end_position: diffResult.walEndPosition,
          status: 'verified',
          chain_entry: diffResult.chain_entry,
          chain_error: diffResult.chain_error,
        };
      }
    }

    const escalationSuffix = escalationReason ? ' escalated_from=' + requestedStrategy + ' reason=' + escalationReason : '';
    _audit(db, req, 'BACKUP_CREATED',
      'id=' + result.id + ' format=v' + result.format_version + ' strategy=' + actualStrategy
      + ' requested=' + requestedStrategy + escalationSuffix + ' size=' + (result.size_bytes || 0)
      + ' manifestSha=' + ((result.manifest_sha256 || '').slice(0, 16)));

    return res.json(Object.assign({}, result, {
      requested_strategy: requestedStrategy,
      actual_strategy: actualStrategy,
      escalated: escalationReason !== null,
      escalation_reason: escalationReason,
    }));
  } catch (err) {
    console.error('routes/gd-backup: trigger failed:', err.message);
    _audit(db, req, 'BACKUP_FAILED', 'requested_strategy=' + requestedStrategy + ' error=' + String(err.message).slice(0, 200));
    return res.status(500).json({ error: 'Backup failed', strategy: requestedStrategy, message: err.message });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- GET /chain (attestation-chain overview) ----------------------------------
router.get('/chain', (req, res) => {
  let db;
  try {
    db = getDb();
    return res.json(chainSvc.getChainStats(db));
  } catch (err) {
    console.error('routes/gd-backup: chain stats failed:', err.message);
    return res.status(500).json({ error: 'Failed to load attestation chain' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- POST /chain/verify (verify the full attestation chain) -------------------
router.post('/chain/verify', (req, res) => {
  let db;
  try {
    db = getDb();
    const result = chainSvc.verifyFullChain(db);
    _audit(db, req, 'BACKUP_CHAIN_VERIFIED',
      'ok=' + (result && result.ok) + ' verified=' + (result && result.entriesVerified)
      + (result && result.ok === false ? ' brokenAt=' + result.brokenAtId + ' reason=' + result.reason : ''));
    return res.json(result);
  } catch (err) {
    console.error('routes/gd-backup: chain verify failed:', err.message);
    return res.status(500).json({ error: 'Failed to verify attestation chain' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- GET /signing-keys (public material only) ---------------------------------
router.get('/signing-keys', (req, res) => {
  let db;
  try {
    db = getDb();
    return res.json({ keys: signingKeysSvc.listKeys(db) });
  } catch (err) {
    console.error('routes/gd-backup: list signing keys failed:', err.message);
    return res.status(500).json({ error: 'Failed to list signing keys' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- POST /signing-keys/rotate ------------------------------------------------
router.post('/signing-keys/rotate', (req, res) => {
  let db;
  try {
    db = getDb();
    const result = signingKeysSvc.rotateKeypair(db);
    _audit(db, req, 'BACKUP_SIGNING_KEY_ROTATED',
      'newId=' + result.newId + ' fingerprint=' + (result.newPublicKeyFingerprint || '').slice(0, 16) + ' oldId=' + result.oldId);
    return res.json({ success: true, key: result });
  } catch (err) {
    console.error('routes/gd-backup: rotate signing key failed:', err.message);
    return res.status(500).json({ error: 'Failed to rotate signing key' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- POST /signing-keys/register-external -------------------------------------
router.post('/signing-keys/register-external', (req, res) => {
  let db;
  const body = (req.body && typeof req.body === 'object') ? req.body : {};
  db = getDb();
  try {
    const keyLabel = (typeof body.keyLabel === 'string' && body.keyLabel.trim()) ? body.keyLabel.trim() : null;
    const notes = (typeof body.notes === 'string' && body.notes.trim()) ? body.notes.trim() : null;
    const result = signingKeysSvc.registerExternalKey(db, {
      publicKeyPem: body.publicKeyPem,
      registeredByUserId: actorOf(req),
      keyLabel: keyLabel,
      notes: notes,
    });
    _audit(db, req, 'BACKUP_SIGNING_KEY_REGISTERED',
      'id=' + result.id + ' fingerprint=' + (result.publicKeyFingerprint || '').slice(0, 16) + ' label=' + (keyLabel || 'none'));
    return res.json({ success: true, key: result });
  } catch (err) {
    if (err instanceof signingKeysSvc.SigningKeyError) {
      return res.status(400).json({ error: err.message, code: err.code });
    }
    console.error('routes/gd-backup: register external key failed:', err.message);
    return res.status(500).json({ error: 'Failed to register external key' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- GET /:id/chain (restore lineage) -----------------------------------------
router.get('/:id/chain', (req, res) => {
  let db;
  try {
    db = getDb();
    const leaf = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);
    if (!leaf) return res.status(404).json({ error: 'Backup not found' });

    // Walk the restore lineage: follow parent_backup_id from the leaf up to the
    // anchor full backup. A cycle guard (visited set) and a depth cap bound the
    // walk; a referenced-but-missing parent stops the walk and flags the link.
    const chain = [];
    const seen = new Set();
    let current = leaf;
    let brokenParent = false;
    let guard = 0;
    while (current && guard < 1000) {
      if (seen.has(current.id)) break;
      seen.add(current.id);
      chain.unshift(current);
      if (!current.parent_backup_id) break;
      const parent = db.prepare('SELECT * FROM backups WHERE id = ?').get(current.parent_backup_id);
      if (!parent) { brokenParent = true; break; }
      current = parent;
      guard += 1;
    }

    let allRestorable = !brokenParent;
    let totalPageCount = 0;
    const chainSummary = chain.map(function (link) {
      const strategy = link.backup_strategy || 'full';
      const pageCount = link.page_count || 0;
      totalPageCount += pageCount;

      const filesToCheck = [];
      if (link.format_version === 2) {
        filesToCheck.push({ label: 'manifest', path: link.manifest_path });
        filesToCheck.push({ label: 'archive', path: link.archive_path });
        filesToCheck.push({ label: 'signature', path: link.manifest_sig_path });
        filesToCheck.push({ label: 'wrappedKey', path: link.wrapped_key_path });
      } else {
        filesToCheck.push({ label: 'artifact', path: link.file_path });
      }

      const missingFiles = filesToCheck.filter(function (f) { return !f.path || !fs.existsSync(f.path); }).map(function (f) { return f.label; });
      const filesPresent = missingFiles.length === 0;
      const linkRestorable = filesPresent && RESTORABLE_STATUSES.indexOf(link.status) !== -1;
      if (!linkRestorable) allRestorable = false;

      return {
        id: link.id,
        backup_strategy: strategy,
        created_at: link.created_at,
        page_count: pageCount,
        size_bytes: link.size_bytes,
        parent_backup_id: link.parent_backup_id,
        parent_full_backup_id: link.parent_full_backup_id,
        status: link.status,
        filesPresent: filesPresent,
        missingFiles: missingFiles,
        wal_start_position: link.wal_start_position,
        wal_end_position: link.wal_end_position,
      };
    });

    _audit(db, req, 'BACKUP_CHAIN_INSPECTED',
      'leaf=' + leaf.id + ' length=' + chain.length + ' restorable=' + allRestorable + (brokenParent ? ' brokenParent=true' : ''));
    return res.json({
      ok: true,
      leafBackupId: leaf.id,
      anchorBackupId: chain.length ? chain[0].id : leaf.id,
      chainLength: chain.length,
      totalPageCount: totalPageCount,
      restorable: allRestorable,
      brokenParent: brokenParent,
      chain: chainSummary,
    });
  } catch (err) {
    console.error('routes/gd-backup: chain inspect failed:', err.message);
    return res.status(500).json({ error: 'internal error', detail: err.message });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- POST /:id/verify (integrity check) ---------------------------------------
router.post('/:id/verify', (req, res) => {
  let db;
  try {
    db = getDb();
    const backup = db.prepare(
      'SELECT id, type, backup_strategy, kind, size_bytes, sha256_hash, file_path, status, created_at, format_version, '
      + 'manifest_path, archive_path, manifest_sig_path, wrapped_key_path, signing_key_id '
      + 'FROM backups WHERE id = ?'
    ).get(req.params.id);

    if (!backup) return res.status(404).json({ error: 'Backup not found' });
    if (backup.status === 'running') return res.json({ status: 'running', message: 'Backup still in progress' });
    if (backup.status === 'failed') return res.json({ status: 'failed', message: 'Backup creation previously failed; cannot verify' });

    // v1 path: single artifact at file_path, sha256_hash = artifact sha256.
    if (backup.format_version === 1 || backup.format_version === null || backup.format_version === undefined) {
      if (!backup.file_path || !fs.existsSync(backup.file_path)) {
        return res.json({ status: 'missing', format_version: 1, message: 'v1 backup artifact not found on disk', expectedPath: backup.file_path });
      }
      const buf = fs.readFileSync(backup.file_path);
      const currentHash = sha256Hex(buf);
      const matches = currentHash === backup.sha256_hash;
      _audit(db, req, 'BACKUP_VERIFIED', 'id=' + backup.id + ' format=v1 match=' + matches);
      return res.json({
        status: matches ? 'verified' : 'tampered',
        format_version: 1,
        storedHash: backup.sha256_hash,
        currentHash: currentHash,
        sizeBytes: buf.length,
        matches: matches,
      });
    }

    // v2 path: four-file layout; manifest hash + Ed25519 signature + in-manifest
    // file hashes. sha256_hash column holds the manifest sha256 for v2 backups.
    if (backup.format_version === 2) {
      const filePaths = {
        manifest: backup.manifest_path,
        archive: backup.archive_path,
        signature: backup.manifest_sig_path,
        wrappedKey: backup.wrapped_key_path,
      };
      const labels = Object.keys(filePaths);
      for (let i = 0; i < labels.length; i += 1) {
        const p = filePaths[labels[i]];
        if (!p || !fs.existsSync(p)) {
          return res.json({ status: 'missing', format_version: 2, message: 'v2 backup ' + labels[i] + ' file missing on disk', missing: labels[i], expectedPath: p });
        }
      }

      const manifestBytes = fs.readFileSync(filePaths.manifest);
      const manifestSha = sha256Hex(manifestBytes);
      const hashMatches = manifestSha === backup.sha256_hash;

      let signatureValid = false;
      let signatureError = null;
      try {
        const signatureBytes = fs.readFileSync(filePaths.signature);
        signatureValid = signingKeysSvc.verifyManifest(db, manifestBytes, signatureBytes, backup.signing_key_id);
      } catch (sigErr) {
        signatureError = sigErr.message;
      }

      let manifest;
      let parseError = null;
      try {
        manifest = manifestSvc.parse(manifestBytes);
        const validation = manifestSvc.validateStructure(manifest);
        if (!validation.ok) parseError = validation.error;
      } catch (parseErr) {
        parseError = parseErr.message;
      }

      let archiveSha = null;
      let wrappedSha = null;
      let archiveMatches = false;
      let wrappedMatches = false;
      let archiveExpected = null;
      let wrappedExpected = null;
      if (!parseError) {
        const archiveBytes = fs.readFileSync(filePaths.archive);
        archiveSha = sha256Hex(archiveBytes);
        const archiveEntry = manifestSvc.getFileEntry(manifest, manifestSvc.ARCHIVE_FILENAME);
        archiveExpected = archiveEntry ? archiveEntry.sha256 : null;
        archiveMatches = archiveExpected !== null && archiveSha === archiveExpected;

        const wrappedBytes = fs.readFileSync(filePaths.wrappedKey);
        wrappedSha = sha256Hex(wrappedBytes);
        const wrappedEntry = manifestSvc.getFileEntry(manifest, manifestSvc.WRAPPED_KEY_FILENAME);
        wrappedExpected = wrappedEntry ? wrappedEntry.sha256 : null;
        wrappedMatches = wrappedExpected !== null && wrappedSha === wrappedExpected;
      }

      const allValid = hashMatches && signatureValid && archiveMatches && wrappedMatches && !parseError;
      _audit(db, req, 'BACKUP_VERIFIED',
        'id=' + backup.id + ' format=v2 valid=' + allValid + ' manifestHash=' + hashMatches
        + ' signature=' + signatureValid + ' archive=' + archiveMatches + ' wrappedKey=' + wrappedMatches);

      return res.json({
        status: allValid ? 'verified' : 'tampered',
        format_version: 2,
        sizeBytes: backup.size_bytes,
        matches: allValid,
        checks: {
          manifestHash: { stored: backup.sha256_hash, actual: manifestSha, matches: hashMatches },
          signature: { valid: signatureValid, error: signatureError, signing_key_id: backup.signing_key_id },
          archiveHash: { manifest: archiveExpected, actual: archiveSha, matches: archiveMatches },
          wrappedKeyHash: { manifest: wrappedExpected, actual: wrappedSha, matches: wrappedMatches },
        },
        parseError: parseError,
      });
    }

    return res.status(500).json({ error: 'Unknown backup format', format_version: backup.format_version });
  } catch (err) {
    console.error('routes/gd-backup: verify failed:', err.message);
    return res.status(500).json({ error: 'Failed to verify backup', message: err.message });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

module.exports = router;

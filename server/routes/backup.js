// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Routes
// POST /api/backup              — trigger on-demand backup (v2 format)
// GET  /api/backup              — list backup history (mixed v1 + v2)
// GET  /api/backup/:id/verify   — verify backup integrity (format-aware)
// POST /api/backup/config       — update backup schedule config
// GET  /api/backup/config       — get current backup config
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { performBackup } = require('../services/backup');
const { performFullSuiteBackup } = require('../services/backup-full-suite');
// R3l C67: per-strategy on-demand dispatch
const { performIncrementalBackup } = require('../services/backup-incremental');
const { performDifferentialBackup } = require('../services/backup-differential');
// R3l C68: chain preview endpoint reuses the walker from the restore-chain service
const restoreChainSvc = require('../services/restore-chain');
const manifestSvc = require('../services/backup-manifest');
const signingKeysSvc = require('../services/backup-signing-keys');

// ── List Backups ─────────────────────────────────────────────────────────────
//
// Returns mixed v1 + v2 rows. Frontend distinguishes by format_version:
//   v1: file_path is set, manifest_path/etc are NULL
//   v2: file_path is NULL, manifest_path/archive_path/manifest_sig_path/
//       wrapped_key_path are set, signing_key_id is set
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const backups = db.prepare(`
      SELECT id, type, size_bytes, file_path, sha256_hash, status, created_at,
             format_version, manifest_path, archive_path, manifest_sig_path,
             wrapped_key_path, signing_key_id
      FROM backups
      ORDER BY created_at DESC
      LIMIT 50
    `).all();
    db.close();
    res.json({ backups });
  } catch (err) {
    logger.error('List backups error', { error: err.message });
    res.status(500).json({ error: 'Failed to list backups' });
  }
});

// ── Trigger On-Demand Backup ─────────────────────────────────────────────────
//
// Synchronous-await. The endpoint blocks until the backup is complete
// (or fails) and responds with the full result. SOC operators clicking
// "backup now" get immediate confirmation of success/failure rather
// than having to poll.
//
// Tradeoff: HTTP timeout for very large databases. If a customer hits
// reverse-proxy or load-balancer timeouts on large backups, an
// async-with-polling mode can be added via an opt-in `?async=true`
// parameter -- not in v1.0.30 scope.
//
// Calls performBackup('on-demand') from services/backup.js, which is
// the same engine the scheduler uses for scheduled backups. Both
// triggers produce v2 backups in v1.0.30+.
router.post('/', async (req, res) => {
  // R3l C67: per-strategy on-demand dispatch. Strategy comes from the
  // query string (?strategy=incremental) or body ({strategy:"differential"}).
  // Default 'full' preserves pre-R3l behavior for clients that don't
  // specify a strategy.
  //
  // Dispatch table:
  //   full         -> performBackup('on-demand')                       (existing path)
  //   snapshot     -> performBackup('snapshot')                        (existing variant)
  //   incremental  -> performIncrementalBackup({type:'on-demand'})    (R3l C63)
  //   differential -> performDifferentialBackup({type:'on-demand'})   (R3l C64)
  //
  // Incremental and differential return either:
  //   - a normal-shape result (ok:true, escalated:false, backupId, ...) OR
  //   - an escalated result (ok:true, escalated:true, reason, fullBackupResult)
  //     which means no eligible parent existed and a full backup was taken instead.
  //
  // The audit log records the requested strategy AND the actual strategy
  // produced (they differ on escalation), so post-hoc analysis can
  // distinguish "operator requested differential, system produced full
  // because no anchor existed" from "operator requested full directly".
  const VALID_STRATEGIES = ['full', 'incremental', 'differential', 'snapshot'];
  const requestedStrategy = (req.query.strategy || req.body.strategy || 'full').toLowerCase();
  if (!VALID_STRATEGIES.includes(requestedStrategy)) {
    return res.status(400).json({
      error: 'invalid strategy',
      code: 'INVALID_BACKUP_STRATEGY',
      hint: `strategy must be one of: ${VALID_STRATEGIES.join(', ')}`,
    });
  }

  try {
    let result;
    let actualStrategy = requestedStrategy;
    let escalationReason = null;

    if (requestedStrategy === 'full') {
      result = await performBackup('on-demand');
    } else if (requestedStrategy === 'snapshot') {
      result = await performBackup('snapshot');
      actualStrategy = 'snapshot';
    } else if (requestedStrategy === 'incremental') {
      const incResult = await performIncrementalBackup({ type: 'on-demand' });
      if (incResult.escalated) {
        // Escalated to a full backup. The fullBackupResult is the
        // performBackup() return; surface it as the canonical result
        // and record the escalation in the response + audit.
        result = incResult.fullBackupResult;
        actualStrategy = 'full';
        escalationReason = incResult.reason;
      } else if (!incResult.ok) {
        throw new Error(incResult.error || 'incremental backup failed');
      } else {
        // Translate incremental result shape into the canonical fields
        // that the rest of this handler + audit log expects.
        result = {
          id: incResult.backupId,
          format_version: 2,
          size_bytes: 0,  // archive size not reported; manifest covers it
          manifest_sha256: incResult.manifestSha256,
          backup_strategy: 'incremental',
          parent_backup_id: incResult.parentBackupId,
          parent_full_backup_id: incResult.parentFullBackupId,
          page_count: incResult.pageCount,
          wal_start_position: incResult.walStartPosition,
          wal_end_position: incResult.walEndPosition,
        };
      }
    } else if (requestedStrategy === 'differential') {
      const diffResult = await performDifferentialBackup({ type: 'on-demand' });
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
          size_bytes: 0,
          manifest_sha256: diffResult.manifestSha256,
          backup_strategy: 'differential',
          parent_backup_id: diffResult.anchorBackupId,
          parent_full_backup_id: diffResult.anchorBackupId,
          page_count: diffResult.pageCount,
          wal_start_position: diffResult.walStartPosition,
          wal_end_position: diffResult.walEndPosition,
        };
      }
    }

    const escalationSuffix = escalationReason ? ` escalated_from=${requestedStrategy} reason=${escalationReason}` : '';
    auditLog(
      req.user.id,
      'BACKUP_CREATED',
      `id=${result.id} format=v${result.format_version} strategy=${actualStrategy} requested=${requestedStrategy}${escalationSuffix} size=${result.size_bytes} manifestSha=${(result.manifest_sha256 || '').slice(0, 16)}`,
      req.ip,
    );

    // Return shape extended with strategy + escalation fields
    res.json({
      ...result,
      requested_strategy: requestedStrategy,
      actual_strategy: actualStrategy,
      escalated: escalationReason !== null,
      escalation_reason: escalationReason,
    });
  } catch (err) {
    logger.error('Trigger backup error', { strategy: requestedStrategy, error: err.message });
    auditLog(req.user.id, 'BACKUP_FAILED', `requested_strategy=${requestedStrategy} error=${err.message.slice(0, 200)}`, req.ip);
    res.status(500).json({ error: 'Backup failed', strategy: requestedStrategy, message: err.message });
  }
});

// ── Trigger Full-Suite Comprehensive Backup (R3k) ─────────────────────────────
//
// Operator-initiated comprehensive backup capturing the regional DB
// snapshot, on-disk config files (integrity-manifest.json, electron-
// security.js if present), and a backup-time version manifest.
// Returns the same shape as POST / with an additional kind:
// 'full-suite' field. Same audit event-type pattern as single-DB
// backup, namespaced FULL_SUITE_* for distinct lifecycle tracking.
//
// Synchronous-await mirrors POST /. Per BUILD-PLAN-v23 Assumptions,
// full-suite payload remains under the v2 engine's 8 GB ceiling for
// typical install volumes.
router.post('/full-suite', async (req, res) => {
  try {
    const result = await performFullSuiteBackup({ type: 'on-demand' });
    auditLog(
      req.user.id,
      'FULL_SUITE_BACKUP_CREATED',
      `id=${result.id} format=v${result.format_version} kind=${result.kind} size=${result.size_bytes} manifestSha=${result.manifest_sha256.slice(0, 16)}`,
      req.ip,
    );
    res.json(result);
  } catch (err) {
    logger.error('Trigger full-suite backup error', { error: err.message });
    auditLog(req.user.id, 'FULL_SUITE_BACKUP_FAILED', `error=${err.message.slice(0, 200)}`, req.ip);
    res.status(500).json({ error: 'Full-suite backup failed', message: err.message });
  }
});

// ── Verify Backup Integrity ──────────────────────────────────────────────────
//
// FORMAT-AWARE. Different verification paths for v1 and v2 rows.
//
// v1 (legacy raw .db file copies):
//   - read backup.file_path bytes
//   - hash, compare to backup.sha256_hash
//   - returns 'verified' if match, 'tampered' if not
//
// v2 (encrypted-signed directory layout):
//   - all four files (manifest, archive, signature, wrapped-key) exist
//     on disk at the recorded paths
//   - manifest.json bytes hash to the value in backups.sha256_hash
//   - Ed25519 signature on manifest.sig verifies against the public key
//     of the row's signing_key_id (works even for keys that have since
//     been rotated out of active status)
//   - the in-manifest file hashes for archive.tar.zst.enc and
//     wrapped-key.bin match the actual file bytes on disk
//
//   ALL FOUR v2 checks must pass for status='verified'. Any one
//   failure returns 'tampered' with per-check detail in the response
//   so an operator can tell which check failed.
router.get('/:id/verify', async (req, res) => {
  try {
    const db = getDb();
    const backup = db.prepare(`
      SELECT id, type, size_bytes, file_path, sha256_hash, status, created_at,
             format_version, manifest_path, archive_path, manifest_sig_path,
             wrapped_key_path, signing_key_id
      FROM backups
      WHERE id = ?
    `).get(req.params.id);

    if (!backup) {
      db.close();
      return res.status(404).json({ error: 'Backup not found' });
    }
    if (backup.status === 'running') {
      db.close();
      return res.json({ status: 'running', message: 'Backup still in progress' });
    }
    if (backup.status === 'failed') {
      db.close();
      return res.json({ status: 'failed', message: 'Backup creation previously failed; cannot verify' });
    }

    // ── v1 path ──────────────────────────────────────────────────────────────
    if (backup.format_version === 1) {
      db.close();
      if (!backup.file_path || !fs.existsSync(backup.file_path)) {
        return res.json({ status: 'missing', message: 'v1 backup file not found on disk' });
      }
      const fileBuffer = fs.readFileSync(backup.file_path);
      const currentHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
      const matches = currentHash === backup.sha256_hash;
      auditLog(req.user?.id, 'BACKUP_VERIFIED', `id=${backup.id} format=v1 match=${matches}`, req.ip);
      return res.json({
        status: matches ? 'verified' : 'tampered',
        format_version: 1,
        storedHash: backup.sha256_hash,
        currentHash,
        sizeBytes: fileBuffer.length,
        matches,
      });
    }

    // ── v2 path ──────────────────────────────────────────────────────────────
    if (backup.format_version === 2) {
      const filePaths = {
        manifest:   backup.manifest_path,
        archive:    backup.archive_path,
        signature:  backup.manifest_sig_path,
        wrappedKey: backup.wrapped_key_path,
      };
      // 1. All four files exist on disk
      for (const [label, p] of Object.entries(filePaths)) {
        if (!p || !fs.existsSync(p)) {
          db.close();
          return res.json({
            status: 'missing',
            format_version: 2,
            message: `v2 backup ${label} file missing on disk`,
            missing: label,
            expectedPath: p,
          });
        }
      }

      // 2. Manifest hash matches stored hash
      const manifestBytes = fs.readFileSync(filePaths.manifest);
      const manifestSha   = crypto.createHash('sha256').update(manifestBytes).digest('hex');
      const hashMatches   = manifestSha === backup.sha256_hash;

      // 3. Ed25519 signature verifies against the row's signing_key_id
      let signatureValid = false;
      let signatureError = null;
      try {
        const signature = fs.readFileSync(filePaths.signature);
        signatureValid = signingKeysSvc.verifyManifest(db, manifestBytes, signature, backup.signing_key_id);
      } catch (sigErr) {
        signatureError = sigErr.message;
      }

      // 4. In-manifest file hashes match actual file bytes
      let manifest;
      let parseError = null;
      try {
        manifest = manifestSvc.parse(manifestBytes);
        const validation = manifestSvc.validateStructure(manifest);
        if (!validation.ok) parseError = validation.error;
      } catch (parseErr) {
        parseError = parseErr.message;
      }

      let archiveSha = null, wrappedSha = null;
      let archiveMatches = false, wrappedMatches = false;
      let archiveExpected = null, wrappedExpected = null;

      if (!parseError) {
        const archiveBytes = fs.readFileSync(filePaths.archive);
        archiveSha = crypto.createHash('sha256').update(archiveBytes).digest('hex');
        const archiveEntry = manifestSvc.getFileEntry(manifest, manifestSvc.ARCHIVE_FILENAME);
        archiveExpected = archiveEntry ? archiveEntry.sha256 : null;
        archiveMatches  = archiveExpected !== null && archiveSha === archiveExpected;

        const wrappedKeyBytes = fs.readFileSync(filePaths.wrappedKey);
        wrappedSha = crypto.createHash('sha256').update(wrappedKeyBytes).digest('hex');
        const wrappedEntry = manifestSvc.getFileEntry(manifest, manifestSvc.WRAPPED_KEY_FILENAME);
        wrappedExpected = wrappedEntry ? wrappedEntry.sha256 : null;
        wrappedMatches  = wrappedExpected !== null && wrappedSha === wrappedExpected;
      }

      db.close();

      const allValid = hashMatches && signatureValid && archiveMatches && wrappedMatches && !parseError;
      auditLog(
        req.user?.id,
        'BACKUP_VERIFIED',
        `id=${backup.id} format=v2 valid=${allValid} manifestHash=${hashMatches} signature=${signatureValid} archive=${archiveMatches} wrappedKey=${wrappedMatches}`,
        req.ip,
      );

      return res.json({
        status: allValid ? 'verified' : 'tampered',
        format_version: 2,
        sizeBytes: backup.size_bytes,
        matches: allValid,
        checks: {
          manifestHash:    { stored: backup.sha256_hash, actual: manifestSha,   matches: hashMatches },
          signature:       { valid: signatureValid, error: signatureError, signing_key_id: backup.signing_key_id },
          archiveHash:     { manifest: archiveExpected, actual: archiveSha,   matches: archiveMatches },
          wrappedKeyHash:  { manifest: wrappedExpected, actual: wrappedSha,   matches: wrappedMatches },
        },
        parseError,
      });
    }

    // ── Unknown format ──────────────────────────────────────────────────────
    db.close();
    return res.status(500).json({
      error: 'Unknown backup format',
      format_version: backup.format_version,
    });
  } catch (err) {
    logger.error('Verify backup error', { error: err.message });
    res.status(500).json({ error: 'Failed to verify backup', message: err.message });
  }
});

// ── R3l C68: Restore Chain Preview ───────────────────────────────────────────
//
// GET /api/backup/:id/chain
//
// Returns the ordered list of backups that would be walked to restore
// from the given backup id. For full and snapshot backups the chain is
// just [the backup itself]. For differentials it's [anchor, leaf]. For
// incrementals it can be arbitrarily long.
//
// This endpoint is read-only. It does NOT validate per-file hashes or
// signatures (that's what /execute-chain does internally via
// validateChain). It DOES check that every chain link's files exist on
// disk and flag any missing files in the response, which lets a UI
// show a "chain incomplete" warning before the operator attempts a
// restore.
//
// Response:
//   {
//     ok: true,
//     leafBackupId,
//     anchorBackupId,
//     chainLength,
//     totalPageCount,         sum of page_count across all links
//     restorable,             true iff every link's files exist and
//                             every link's status === 'verified'
//     chain: [
//       {
//         id, backup_strategy, created_at, page_count, size_bytes,
//         parent_backup_id, parent_full_backup_id, status,
//         filesPresent,       boolean (manifest + archive + sig + key all exist)
//         missingFiles,       array of label strings if any are missing
//       },
//       ...
//     ]
//   }
router.get('/:id/chain', (req, res) => {
  let db;
  try {
    db = getDb();
    const leaf = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);
    if (!leaf) { db.close(); return res.status(404).json({ error: 'Backup not found' }); }

    let chain;
    try {
      chain = restoreChainSvc.walkChain(db, req.params.id);
    } catch (walkErr) {
      db.close();
      return res.status(400).json({
        error: 'cannot walk restore chain',
        code: 'CHAIN_WALK_FAILED',
        detail: walkErr.message,
      });
    }

    // Per-link file-existence check (cheap; no hash recompute).
    let allRestorable = true;
    let totalPageCount = 0;
    const chainSummary = chain.map(link => {
      const strategy = link.backup_strategy || 'full';
      const pageCount = link.page_count || 0;
      totalPageCount += pageCount;

      // Files to check vary by format. v1 backups have file_path only;
      // v2 has the four-file layout. Pre-R3l v2 fulls and post-R3l
      // inc/diff all use the four-file layout.
      const filesToCheck = [];
      if (link.format_version === 1) {
        filesToCheck.push({ label: 'file', path: link.file_path });
      } else if (link.format_version === 2) {
        filesToCheck.push({ label: 'manifest', path: link.manifest_path });
        filesToCheck.push({ label: 'archive', path: link.archive_path });
        filesToCheck.push({ label: 'signature', path: link.manifest_sig_path });
        filesToCheck.push({ label: 'wrappedKey', path: link.wrapped_key_path });
      }

      const missingFiles = filesToCheck.filter(f => !f.path || !fs.existsSync(f.path)).map(f => f.label);
      const filesPresent = missingFiles.length === 0;
      const linkRestorable = filesPresent && link.status === 'verified';
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
        filesPresent,
        missingFiles,
        wal_start_position: link.wal_start_position,
        wal_end_position: link.wal_end_position,
      };
    });

    db.close();
    return res.json({
      ok: true,
      leafBackupId: leaf.id,
      anchorBackupId: chain[0].id,
      chainLength: chain.length,
      totalPageCount,
      restorable: allRestorable,
      chain: chainSummary,
    });
  } catch (err) {
    try { if (db) db.close(); } catch (_) {}
    logger.error('GET /api/backup/:id/chain crashed', { error: err.message });
    return res.status(500).json({ error: 'internal error', detail: err.message });
  }
});

// ── Backup Schedule Config ───────────────────────────────────────────────────
//
// R3i C11: /api/backup/config GET and POST are now backwards-
// compatibility shims over the canonical backup_schedules table
// (promoted into init.js migration discipline in C2). The legacy
// singleton at team_config.backup_config was backfilled into a
// 'Legacy default' row in C11's init migration if the singleton
// existed; if the singleton never existed, the GET endpoint
// surfaces the hardcoded v1.0.x defaults the original
// implementation returned. New callers should use
// /api/backup-schedules (multi-schedule with preset enforcement);
// these two endpoints stay live for one version of deprecation
// grace, with the response body carrying deprecated:true and a
// replacement hint for caller discovery.
router.get('/config', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare(
      "SELECT id, frequency, interval, time, retention FROM backup_schedules ORDER BY id LIMIT 1"
    ).get();
    db.close();
    if (row) {
      const freqOrInterval = row.frequency || row.interval || 'daily';
      const retentionMatch = /^(\d+)\s*day/i.exec(row.retention || '');
      const retentionDays = retentionMatch
        ? parseInt(retentionMatch[1], 10)
        : 30;
      res.json({
        schedule: freqOrInterval,
        time: row.time || '02:00',
        retentionDays,
        deprecated: true,
        replacement: '/api/backup-schedules',
      });
    } else {
      // No schedules in the canonical table; surface the hardcoded
      // v1.0.x defaults the original singleton-config implementation
      // returned when team_config.backup_config was empty. Pre-R3i
      // callers depending on this shape continue to receive it.
      res.json({
        schedule: 'daily',
        time: '02:00',
        retentionDays: 30,
        deprecated: true,
        replacement: '/api/backup-schedules',
      });
    }
  } catch (err) {
    logger.error('Get backup config error', { error: err.message });
    res.status(500).json({ error: 'Failed to get backup config' });
  }
});

router.post('/config', (req, res) => {
  const { schedule, time, retentionDays } = req.body;
  try {
    const db = getDb();
    const validated = {
      schedule: ['daily', 'weekly', 'monthly'].includes(schedule)
        ? schedule
        : 'daily',
      time: /^\d{1,2}:\d{2}$/.test(time) ? time : '02:00',
      retentionDays: Math.max(
        7,
        Math.min(365, parseInt(retentionDays, 10) || 30),
      ),
    };
    // Find the first row (singleton-semantic) or create a 'Legacy
    // default' row if none exists. Direct SQL rather than service
    // call because the legacy endpoint preserves singleton-overwrite
    // semantics (no preset, no overlap detection, no validation
    // beyond the legacy bounds).
    const existing = db.prepare(
      'SELECT id FROM backup_schedules ORDER BY id LIMIT 1'
    ).get();
    if (existing) {
      db.prepare(`
        UPDATE backup_schedules
        SET interval = ?, time = ?, retention = ?
        WHERE id = ?
      `).run(
        validated.schedule,
        validated.time,
        `${validated.retentionDays} days`,
        existing.id,
      );
    } else {
      db.prepare(`
        INSERT INTO backup_schedules
          (type, interval, retention, destination, encrypted,
           active, last_run, created_at, name, regulatory_preset_id,
           time, day_of_week, day_of_month, next_run,
           last_status, last_error)
        VALUES
          ('full', ?, ?, 'local', 1,
           1, NULL, ?, 'Legacy default', NULL,
           ?, NULL, NULL, NULL,
           NULL, NULL)
      `).run(
        validated.schedule,
        `${validated.retentionDays} days`,
        new Date().toISOString(),
        validated.time,
      );
    }
    db.close();
    // Update team_config.backup_config singleton too, so any external
    // tooling still reading the singleton directly sees the latest
    // value. The canonical table is the source of truth; the
    // singleton is a read-shadow.
    try {
      const shadowDb = getDb();
      const shadow = JSON.stringify({
        schedule: validated.schedule,
        time: validated.time,
        retentionDays: validated.retentionDays,
      });
      shadowDb.prepare(
        "INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('backup_config', ?, ?)"
      ).run(shadow, req.user.id);
      shadowDb.close();
    } catch (shadowErr) {
      logger.warn('R3i: legacy backup_config shadow write failed', {
        error: shadowErr.message,
      });
    }
    auditLog(
      req.user.id,
      'BACKUP_CONFIG_DEPRECATED_USAGE',
      `Legacy /api/backup/config POST used; consider migrating to POST /api/backup-schedules. Singleton: ${JSON.stringify(validated)}`,
      req.ip,
    );
    res.json({
      schedule: validated.schedule,
      time: validated.time,
      retentionDays: validated.retentionDays,
      deprecated: true,
      replacement: '/api/backup-schedules',
    });
  } catch (err) {
    logger.error('Update backup config error', { error: err.message });
    res.status(500).json({ error: 'Failed to update backup config' });
  }
});

module.exports = router;

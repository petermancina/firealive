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
// the same engine the scheduler uses for daily-auto backups. Both
// triggers produce v2 backups in v1.0.30+.
router.post('/', async (req, res) => {
  try {
    const result = await performBackup('on-demand');
    auditLog(
      req.user.id,
      'BACKUP_CREATED',
      `id=${result.id} format=v${result.format_version} size=${result.size_bytes} manifestSha=${result.manifest_sha256.slice(0, 16)}`,
      req.ip,
    );
    res.json(result);
  } catch (err) {
    logger.error('Trigger backup error', { error: err.message });
    auditLog(req.user.id, 'BACKUP_FAILED', `error=${err.message.slice(0, 200)}`, req.ip);
    res.status(500).json({ error: 'Backup failed', message: err.message });
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

// ── Backup Schedule Config ───────────────────────────────────────────────────
//
// Unchanged from v1.0.29. Schedule config is orthogonal to format and
// stays the same shape across the v1 -> v2 transition.
router.get('/config', (req, res) => {
  try {
    const db = getDb();
    const config = db.prepare("SELECT value FROM team_config WHERE key = 'backup_config'").get();
    db.close();
    res.json(config ? JSON.parse(config.value) : { schedule: 'daily', time: '02:00', retentionDays: 30 });
  } catch (err) {
    logger.error('Get backup config error', { error: err.message });
    res.status(500).json({ error: 'Failed to get backup config' });
  }
});

router.post('/config', (req, res) => {
  const { schedule, time, retentionDays } = req.body;
  try {
    const db = getDb();
    const config = JSON.stringify({
      schedule: ['daily', 'weekly', 'monthly'].includes(schedule) ? schedule : 'daily',
      time: /^\d{2}:\d{2}$/.test(time) ? time : '02:00',
      retentionDays: Math.max(7, Math.min(365, parseInt(retentionDays, 10) || 30)),
    });
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('backup_config', ?, ?)").run(config, req.user.id);
    db.close();
    auditLog(req.user.id, 'BACKUP_CONFIG_UPDATED', config, req.ip);
    res.json(JSON.parse(config));
  } catch (err) {
    logger.error('Update backup config error', { error: err.message });
    res.status(500).json({ error: 'Failed to update backup config' });
  }
});

module.exports = router;

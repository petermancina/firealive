// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Restore & Settings Revert Routes
// GET  /api/restore/points              — list available restore points (backups + configs)
// GET  /api/restore/preview/:id         — preview what a restore would change
// POST /api/restore/execute/:id         — execute restore from backup (v1 + v2)
// GET  /api/restore/configs             — list saved configuration snapshots
// POST /api/restore/config-save         — save current config as named snapshot
// POST /api/restore/config-revert/:id   — revert to a config snapshot
//
// FORMAT-AWARE.
//
// v1 backups (legacy raw SQLite .db file copies) restore by reading the
// file at backup.file_path, hashing, and fs.copyFileSync over DB_PATH.
// This path is unchanged from v1.0.29.
//
// v2 backups (encrypted-signed directory layout) restore by:
//   1. Verifying the Ed25519 signature on manifest.json against the
//      public key of the backup's signing_key_id (key may be active or
//      rotated out -- both work)
//   2. Parsing + structurally validating the manifest
//   3. Verifying the in-manifest file hashes match actual on-disk
//      bytes for archive.tar.zst.enc and wrapped-key.bin
//   4. Unwrapping the ephemeral data key via the manifest-recorded
//      key_wrapping scheme + KEK reference
//   5. Extracting the archive (decrypt -> decompress -> untar) to
//      recover the SQLite .db bytes
//   6. fs.copyFileSync the recovered .db over DB_PATH
//
// Both paths produce a pre-restore backup of the CURRENT DB state as a
// raw .db file in the backup dir before any destructive write. The
// pre-restore path returns success with a note that the server must
// restart to flush in-memory state -- same as v1.0.29.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const archiveSvc = require('../services/backup-archive');
const keyWrapSvc = require('../services/backup-key-wrapping');
const manifestSvc = require('../services/backup-manifest');
const signingKeysSvc = require('../services/backup-signing-keys');
const chainSvc = require('../services/backup-chain');

// ── List Restore Points ──────────────────────────────────────────────────────
router.get('/points', (req, res) => {
  try {
    const db = getDb();
    const backups = db.prepare(`
      SELECT id, type, size_bytes, file_path, sha256_hash, status, created_at,
             format_version, manifest_path, archive_path, manifest_sig_path,
             wrapped_key_path, signing_key_id
      FROM backups
      WHERE status = 'verified'
      ORDER BY created_at DESC
      LIMIT 30
    `).all();
    const configs = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'config_snapshot_%' ORDER BY key DESC").all();
    db.close();

    const configSnapshots = configs.map(c => {
      try {
        const data = JSON.parse(c.value);
        return { id: c.key.replace('config_snapshot_', ''), name: data.name, createdAt: data.createdAt, createdBy: data.createdBy };
      } catch { return null; }
    }).filter(Boolean);

    res.json({
      backups: backups.map(b => ({
        id: b.id,
        type: b.type,
        format_version: b.format_version,
        sizeMB: b.size_bytes ? (b.size_bytes / 1024 / 1024).toFixed(2) : null,
        hash: b.sha256_hash ? b.sha256_hash.slice(0, 16) + '…' : null,
        status: b.status,
        createdAt: b.created_at,
      })),
      configSnapshots,
    });
  } catch (err) {
    logger.error('List restore points error', { error: err.message });
    res.status(500).json({ error: 'Failed to list restore points' });
  }
});

// ── Preview Restore ──────────────────────────────────────────────────────────
//
// Format-aware. v1 reports just whether the .db file is on disk. v2
// reports per-file presence and (if all files present) the manifest's
// metadata so the operator can see what they're about to restore.
router.get('/preview/:id', (req, res) => {
  try {
    const db = getDb();
    const backup = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);
    db.close();

    if (!backup) return res.status(404).json({ error: 'Backup not found' });
    if (backup.status !== 'verified') return res.status(400).json({ error: 'Backup not verified — cannot restore' });

    if (backup.format_version === 1) {
      const fileExists = fs.existsSync(backup.file_path || '');
      return res.json({
        id: backup.id,
        type: backup.type,
        format_version: 1,
        createdAt: backup.created_at,
        sizeMB: backup.size_bytes ? (backup.size_bytes / 1024 / 1024).toFixed(2) : null,
        hash: backup.sha256_hash,
        fileExists,
        warning: 'Restoring will replace the current database with this backup. This action is irreversible. A pre-restore backup will be created automatically.',
      });
    }

    if (backup.format_version === 2) {
      const filesOnDisk = {
        manifest:   { path: backup.manifest_path,     exists: !!backup.manifest_path     && fs.existsSync(backup.manifest_path) },
        archive:    { path: backup.archive_path,      exists: !!backup.archive_path      && fs.existsSync(backup.archive_path) },
        signature:  { path: backup.manifest_sig_path, exists: !!backup.manifest_sig_path && fs.existsSync(backup.manifest_sig_path) },
        wrappedKey: { path: backup.wrapped_key_path,  exists: !!backup.wrapped_key_path  && fs.existsSync(backup.wrapped_key_path) },
      };
      const allPresent = Object.values(filesOnDisk).every(f => f.exists);

      // If the manifest is on disk, parse it for richer preview info.
      // Don't fail the whole preview on parse errors -- just return the
      // structural state.
      let manifestPreview = null;
      let manifestParseError = null;
      if (filesOnDisk.manifest.exists) {
        try {
          const bytes = fs.readFileSync(backup.manifest_path);
          const m = manifestSvc.parse(bytes);
          const v = manifestSvc.validateStructure(m);
          if (!v.ok) {
            manifestParseError = v.error;
          } else {
            manifestPreview = {
              backup_id:                  m.backup_id,
              backup_type:                m.backup_type,
              created_at:                 m.created_at,
              encryption:                 m.encryption,
              compression:                m.compression,
              key_wrapping:               m.key_wrapping,
              source_fuse_counter:        m.source_db.fuse_counter_at_creation,
              source_schema_version:      m.source_db.schema_version,
              archive_size_bytes:         manifestSvc.getFileEntry(m, manifestSvc.ARCHIVE_FILENAME)?.sizeBytes ?? null,
              wrapped_key_size_bytes:     manifestSvc.getFileEntry(m, manifestSvc.WRAPPED_KEY_FILENAME)?.sizeBytes ?? null,
            };
          }
        } catch (err) {
          manifestParseError = err.message;
        }
      }

      return res.json({
        id: backup.id,
        type: backup.type,
        format_version: 2,
        createdAt: backup.created_at,
        sizeMB: backup.size_bytes ? (backup.size_bytes / 1024 / 1024).toFixed(2) : null,
        manifestSha256: backup.sha256_hash,
        signing_key_id: backup.signing_key_id,
        filesOnDisk,
        allPresent,
        manifestPreview,
        manifestParseError,
        warning: 'Restoring will replace the current database with this backup. This action is irreversible. A pre-restore backup will be created automatically. The server must be restarted after restore to ensure all in-memory state reflects the restored database.',
      });
    }

    return res.status(500).json({ error: 'Unknown backup format', format_version: backup.format_version });
  } catch (err) {
    logger.error('Preview restore error', { error: err.message });
    res.status(500).json({ error: 'Failed to preview restore' });
  }
});

// ── Execute Restore ──────────────────────────────────────────────────────────
//
// Format-aware. The confirmation gate uses the first 8 hex chars of
// backups.sha256_hash for both formats (which means manifest hash for
// v2 rows, .db hash for v1 rows -- both are 64-char hex strings, both
// work the same way for confirmation).
//
// Pre-restore backup is a raw .db copy of the CURRENT live database
// state, regardless of which format is being restored from. This is
// an emergency recoverability backstop, not a long-term backup;
// recovery from it is rare and the format-quality concerns that drive
// v2 don't apply.
router.post('/execute/:id', async (req, res) => {
  const { confirmHash } = req.body;

  try {
    const db = getDb();
    const backup = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);

    if (!backup) { db.close(); return res.status(404).json({ error: 'Backup not found' }); }
    if (backup.status !== 'verified') { db.close(); return res.status(400).json({ error: 'Backup not verified' }); }

    // Confirmation gate
    if (confirmHash !== backup.sha256_hash?.slice(0, 8)) {
      db.close();
      return res.status(400).json({
        error: 'Confirmation required. Send { confirmHash: "<first 8 chars of backup hash>" }',
        hint: backup.sha256_hash?.slice(0, 8),
      });
    }

    // ── v1 path ──────────────────────────────────────────────────────────────
    if (backup.format_version === 1) {
      if (!fs.existsSync(backup.file_path)) {
        db.close();
        return res.status(400).json({ error: 'Backup file not found on disk' });
      }
      db.close();

      // Pre-restore raw copy
      const { DB_PATH } = require('../db/init');
      const preRestorePath = path.join(path.dirname(backup.file_path), `pre-restore-${Date.now()}.db`);
      fs.copyFileSync(DB_PATH, preRestorePath);

      // Verify v1 integrity
      const fileBuffer = fs.readFileSync(backup.file_path);
      const currentHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
      if (currentHash !== backup.sha256_hash) {
        return res.status(400).json({ error: 'Backup integrity check failed — file has been modified since verification' });
      }

      // Restore
      fs.copyFileSync(backup.file_path, DB_PATH);

      auditLog(req.user.id, 'DATABASE_RESTORED', `backup=${backup.id} format=v1 from=${backup.created_at} pre-restore=${path.basename(preRestorePath)}`, req.ip);
      logger.warn('DATABASE RESTORED (v1)', { backupId: backup.id, from: backup.created_at });

      return res.json({
        ok: true,
        format_version: 1,
        message: 'Database restored successfully. A pre-restore backup was saved.',
        preRestorePath: path.basename(preRestorePath),
        restoredFrom: backup.created_at,
        note: 'The server should be restarted to ensure all in-memory state reflects the restored database.',
      });
    }

    // ── v2 path ──────────────────────────────────────────────────────────────
    if (backup.format_version === 2) {
      // 1. All four files present
      const filePaths = {
        manifest:   backup.manifest_path,
        archive:    backup.archive_path,
        signature:  backup.manifest_sig_path,
        wrappedKey: backup.wrapped_key_path,
      };
      for (const [label, p] of Object.entries(filePaths)) {
        if (!p || !fs.existsSync(p)) {
          db.close();
          return res.status(400).json({
            error: `v2 backup ${label} file missing on disk`,
            missing: label,
            expectedPath: p,
          });
        }
      }

      // 1b. R3d-2 PRECONDITION: chain integrity verified up to this
      //     backup's CREATE entry. Refuses the restore if the chain
      //     is broken anywhere from genesis to the backup's CREATE
      //     entry (inclusive). Partial-chain semantics: a chain
      //     break AFTER the backup's CREATE entry does NOT block
      //     this restore (the backup's provenance was committed
      //     before the break and is still attestable).
      //
      //     Failure here is FATAL. Unlike chain append at backup
      //     creation time (where degraded mode is OK because the
      //     alternative is no backups), here the alternative is
      //     simply declining the restore until chain integrity is
      //     restored. SOC operators must investigate before
      //     destructively replacing the live DB. There is
      //     deliberately no `?force=true` override -- forcing is
      //     a future feature when a real recovery scenario
      //     justifies it.
      //
      //     If the backup has no CREATE entry at all (e.g. it was
      //     created during a chain-keypair outage in degraded
      //     mode), the chain check returns no_create_entry and
      //     the restore is refused with a precise error so the
      //     operator can decide whether to investigate.
      const chainCheck = chainSvc.verifyChainUpToBackup(db, backup.id);
      if (!chainCheck.ok) {
        db.close();
        auditLog(
          req.user?.id,
          'RESTORE_REFUSED_CHAIN_BROKEN',
          `backup=${backup.id} reason=${chainCheck.reason} brokenAtId=${chainCheck.brokenAtId || 'none'}`,
          req.ip,
        );
        return res.status(409).json({
          error: 'v2 chain integrity precondition failed -- restore refused',
          chain: {
            ok: false,
            reason: chainCheck.reason,
            brokenAtId: chainCheck.brokenAtId,
            entriesVerified: chainCheck.entriesVerified,
            detail: chainCheck.detail,
          },
          remediation: chainCheck.reason === 'no_create_entry'
            ? 'This backup has no CREATE entry in the chain. It may have been created during a chain-keypair outage (degraded mode). Investigate the chain history before restoring.'
            : 'The chain has been tampered or has become inconsistent before/at this backup. Investigate the chain (admin: GET /api/backup-chain/verify) before restoring.',
        });
      }

      // 2. Read all four
      const manifestBytes   = fs.readFileSync(filePaths.manifest);
      const signature       = fs.readFileSync(filePaths.signature);
      const archiveBytes    = fs.readFileSync(filePaths.archive);
      const wrappedKeyBytes = fs.readFileSync(filePaths.wrappedKey);

      // 3. Verify manifest hash matches the row's stored hash
      const manifestSha = crypto.createHash('sha256').update(manifestBytes).digest('hex');
      if (manifestSha !== backup.sha256_hash) {
        db.close();
        return res.status(400).json({
          error: 'v2 manifest hash mismatch with backups.sha256_hash',
          stored: backup.sha256_hash,
          actual: manifestSha,
        });
      }

      // 4. Verify Ed25519 signature
      const sigValid = signingKeysSvc.verifyManifest(db, manifestBytes, signature, backup.signing_key_id);
      if (!sigValid) {
        db.close();
        return res.status(400).json({
          error: 'v2 manifest signature verification failed',
          signing_key_id: backup.signing_key_id,
        });
      }

      // 5. Parse + validate manifest
      let manifest;
      try {
        manifest = manifestSvc.parse(manifestBytes);
      } catch (parseErr) {
        db.close();
        return res.status(400).json({ error: 'v2 manifest unparseable', detail: parseErr.message });
      }
      const validation = manifestSvc.validateStructure(manifest);
      if (!validation.ok) {
        db.close();
        return res.status(400).json({ error: 'v2 manifest structurally invalid', detail: validation.error });
      }

      // 6. Verify in-manifest file hashes match actual bytes
      const archiveSha = crypto.createHash('sha256').update(archiveBytes).digest('hex');
      const archiveEntry = manifestSvc.getFileEntry(manifest, manifestSvc.ARCHIVE_FILENAME);
      if (!archiveEntry || archiveSha !== archiveEntry.sha256) {
        db.close();
        return res.status(400).json({
          error: 'v2 archive file hash mismatch with manifest',
          manifestHash: archiveEntry ? archiveEntry.sha256 : null,
          actualHash: archiveSha,
        });
      }

      const wrappedSha = crypto.createHash('sha256').update(wrappedKeyBytes).digest('hex');
      const wrappedEntry = manifestSvc.getFileEntry(manifest, manifestSvc.WRAPPED_KEY_FILENAME);
      if (!wrappedEntry || wrappedSha !== wrappedEntry.sha256) {
        db.close();
        return res.status(400).json({
          error: 'v2 wrapped-key file hash mismatch with manifest',
          manifestHash: wrappedEntry ? wrappedEntry.sha256 : null,
          actualHash: wrappedSha,
        });
      }

      // 7b. R3d-2: append RESTORE_REQUEST entry to the chain BEFORE
      //     destructive work begins. Records intent in the audit
      //     trail so a REQUEST with no following COMPLETE is
      //     forensically detectable as a failed/aborted restore.
      //
      //     Failure to append RESTORE_REQUEST is FATAL -- unlike at
      //     backup creation time, the restore has not yet started
      //     destructive work, so there is no "preserve recoverability"
      //     argument for degraded mode. If we cannot record intent,
      //     we should not proceed with destructive operation.
      let restoreRequestEntry = null;
      try {
        const result = chainSvc.appendChainEntry(db, {
          eventType: 'RESTORE_REQUEST',
          backupId: backup.id,
          actorUserId: req.user?.id || null,
          payload: {
            restore_initiated_at: new Date().toISOString(),
            backup_signing_key_id: backup.signing_key_id,
            backup_created_at: backup.created_at,
            backup_chain_create_entry_id: chainCheck.chainEntryId,
          },
        });
        restoreRequestEntry = {
          id: result.id,
          this_hash: result.thisHash,
          created_at: result.createdAt,
        };
      } catch (chainErr) {
        db.close();
        logger.error('chain RESTORE_REQUEST append failed; refusing restore', {
          backupId: backup.id,
          error: chainErr.message,
        });
        return res.status(500).json({
          error: 'v2 chain RESTORE_REQUEST append failed; restore refused',
          detail: chainErr.message,
          hint: 'Cannot record restore intent in the chain. Restoring without recording intent would create an unauditable destructive operation. Investigate the chain-signing-keys configuration and retry.',
        });
      }

      db.close();

      // 7. Unwrap the ephemeral key
      let ephemeralKey;
      try {
        ephemeralKey = await keyWrapSvc.unwrapKey(
          wrappedKeyBytes,
          manifest.key_wrapping.scheme,
          manifest.key_wrapping.kek_reference,
        );
      } catch (unwrapErr) {
        return res.status(500).json({
          error: 'v2 ephemeral key unwrap failed',
          detail: unwrapErr.message,
          hint: 'Most often this means TIER1_ENCRYPTION_KEY (or the manifest-recorded KEK) has changed since this backup was created. Restoring requires the same KEK that was used to encrypt.',
        });
      }

      // 8. Extract archive (AES-GCM decrypt -> zstd decompress -> untar)
      let extracted;
      try {
        extracted = await archiveSvc.extractArchive(archiveBytes, ephemeralKey);
      } catch (extractErr) {
        return res.status(500).json({
          error: 'v2 archive extraction failed',
          detail: extractErr.message,
        });
      }
      if (extracted.name !== 'firealive.db') {
        return res.status(500).json({
          error: 'v2 archive contains unexpected file',
          expected: 'firealive.db',
          actual: extracted.name,
        });
      }

      // 9. Pre-restore raw copy of CURRENT live DB state
      const { DB_PATH } = require('../db/init');
      const preRestoreDir = path.dirname(DB_PATH);
      const preRestorePath = path.join(preRestoreDir, `pre-restore-${Date.now()}.db`);
      fs.copyFileSync(DB_PATH, preRestorePath);

      // 10. Write recovered .db bytes to a temp file, then atomic-rename
      // over DB_PATH. Atomic rename ensures DB_PATH is never partially
      // written even if the process crashes mid-write.
      const tempDbPath = path.join(preRestoreDir, `.restore-${Date.now()}.db.tmp`);
      try {
        fs.writeFileSync(tempDbPath, extracted.payload);
        fs.renameSync(tempDbPath, DB_PATH);
      } catch (writeErr) {
        // Cleanup temp file if the rename failed
        try { fs.unlinkSync(tempDbPath); } catch { /* ignore */ }
        return res.status(500).json({
          error: 'v2 restore write failed',
          detail: writeErr.message,
        });
      }

      // 11. R3d-2: append RESTORE_COMPLETE entry to the RESTORED
      //     chain. Note this opens a NEW DB connection -- the live
      //     DB at DB_PATH is now the restored database (atomic
      //     rename happened in step 10). The chain in the restored
      //     DB has whatever entries existed at backup-creation time.
      //     This COMPLETE entry chains forward from that historical
      //     head, signed by the restored DB's chain-signing key
      //     (which is also the key that was active at backup-
      //     creation time).
      //
      //     Forensic semantics: a future operator inspecting the
      //     restored DB's chain sees a RESTORE_COMPLETE entry at
      //     the head documenting that this database was restored
      //     from the named backup at the recorded time. The OLD
      //     chain (which had the RESTORE_REQUEST) has been
      //     overwritten -- but the audit log (separate table)
      //     preserves the REQUEST record.
      //
      //     Failure to append RESTORE_COMPLETE is DEGRADED-MODE.
      //     The restore has succeeded; the live DB is the restored
      //     state. Refusing to surface that to the user because
      //     we couldn't write a chain entry would be perverse.
      //     Loud log + chain_complete_error in the response.
      let restoreCompleteEntry = null;
      let restoreCompleteError = null;
      try {
        const newDb = getDb();
        try {
          const result = chainSvc.appendChainEntry(newDb, {
            eventType: 'RESTORE_COMPLETE',
            backupId: backup.id,
            actorUserId: req.user?.id || null,
            payload: {
              restore_completed_at: new Date().toISOString(),
              restored_db_size_bytes: extracted.payload.length,
              pre_restore_filename: path.basename(preRestorePath),
              backup_signing_key_id: backup.signing_key_id,
              backup_created_at: backup.created_at,
              source_chain_request_entry_id: restoreRequestEntry ? restoreRequestEntry.id : null,
              source_chain_request_this_hash: restoreRequestEntry ? restoreRequestEntry.this_hash : null,
            },
          });
          restoreCompleteEntry = {
            id: result.id,
            this_hash: result.thisHash,
            created_at: result.createdAt,
          };
        } finally {
          newDb.close();
        }
      } catch (chainErr) {
        restoreCompleteError = chainErr.message;
        logger.error(
          'chain RESTORE_COMPLETE append failed (restore itself succeeded). ' +
          'The restored database lacks a chain entry recording the restoration. ' +
          'Audit log preserves the event but the restored chain is missing the head annotation.',
          { backupId: backup.id, error: chainErr.message },
        );
      }

      auditLog(
        req.user.id,
        'DATABASE_RESTORED',
        `backup=${backup.id} format=v2 from=${backup.created_at} signing_key_id=${backup.signing_key_id} pre-restore=${path.basename(preRestorePath)} manifest_fuse_counter=${manifest.source_db.fuse_counter_at_creation}`,
        req.ip,
      );
      logger.warn('DATABASE RESTORED (v2)', {
        backupId: backup.id,
        from: backup.created_at,
        signingKeyId: backup.signing_key_id,
        manifestFuseCounter: manifest.source_db.fuse_counter_at_creation,
      });

      return res.json({
        ok: true,
        format_version: 2,
        message: 'Database restored successfully. A pre-restore backup was saved.',
        preRestorePath: path.basename(preRestorePath),
        restoredFrom: backup.created_at,
        manifestFuseCounter: manifest.source_db.fuse_counter_at_creation,
        sizeBytes: extracted.payload.length,
        chain: {
          request_entry: restoreRequestEntry,        // in old (overwritten) chain
          complete_entry: restoreCompleteEntry,      // in new (restored) chain
          complete_error: restoreCompleteError,
        },
        note: 'The server should be restarted to ensure all in-memory state reflects the restored database.',
      });
    }

    db.close();
    return res.status(500).json({ error: 'Unknown backup format', format_version: backup.format_version });
  } catch (err) {
    logger.error('Execute restore error', { error: err.message });
    res.status(500).json({ error: 'Failed to execute restore', message: err.message });
  }
});

// ── Configuration Snapshots ──────────────────────────────────────────────────
//
// Unchanged from v1.0.29. Config snapshots are orthogonal to backup
// format and stay the same shape across the v1 -> v2 transition.
router.get('/configs', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'config_snapshot_%' ORDER BY key DESC").all();
    db.close();
    const snapshots = rows.map(r => { try { const d = JSON.parse(r.value); return { id: r.key.replace('config_snapshot_', ''), name: d.name, createdAt: d.createdAt }; } catch { return null; } }).filter(Boolean);
    res.json({ snapshots });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list config snapshots' });
  }
});

router.post('/config-save', (req, res) => {
  const { name } = req.body;
  if (!name || name.length > 100) return res.status(400).json({ error: 'name required (max 100 chars)' });

  try {
    const db = getDb();
    const allConfig = db.prepare("SELECT key, value FROM team_config WHERE key NOT LIKE 'config_snapshot_%' AND key NOT LIKE 'pending_user_%' AND key NOT LIKE 'lockout_%' AND key NOT LIKE 'reset_%' AND key NOT LIKE 'peer_request_%' AND key NOT LIKE 'peer_session_%'").all();
    const reportConfig = db.prepare('SELECT * FROM report_config WHERE id = ?').get('default');
    const slaConfig = db.prepare('SELECT * FROM sla_config WHERE id = ?').get('default');
    const notifConfig = db.prepare('SELECT * FROM notification_config WHERE id = ?').get('default');

    const id = Date.now().toString(36);
    const snapshot = {
      name: name.slice(0, 100),
      createdAt: new Date().toISOString(),
      createdBy: req.user.id,
      teamConfig: allConfig,
      reportConfig,
      slaConfig,
      notifConfig,
    };

    db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(`config_snapshot_${id}`, JSON.stringify(snapshot), req.user.id);
    db.close();

    auditLog(req.user.id, 'CONFIG_SNAPSHOT_SAVED', `name="${name}"`, req.ip);
    res.status(201).json({ id, name });
  } catch (err) {
    logger.error('Save config snapshot error', { error: err.message });
    res.status(500).json({ error: 'Failed to save config snapshot' });
  }
});

router.post('/config-revert/:id', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`config_snapshot_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Snapshot not found' }); }

    const snapshot = JSON.parse(row.value);

    // Save current state first
    const currentId = Date.now().toString(36);
    const currentConfig = db.prepare("SELECT key, value FROM team_config WHERE key NOT LIKE 'config_snapshot_%'").all();
    db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(
      `config_snapshot_${currentId}`,
      JSON.stringify({ name: 'Auto-save before revert', createdAt: new Date().toISOString(), createdBy: req.user.id, teamConfig: currentConfig }),
      req.user.id
    );

    // Restore team_config entries
    for (const { key, value } of snapshot.teamConfig) {
      if (key.startsWith('config_snapshot_')) continue;
      db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(key, value, req.user.id);
    }

    // Restore report/SLA/notification configs
    if (snapshot.reportConfig) {
      db.prepare("INSERT OR REPLACE INTO report_config (id, schedule, day_of_week, time_of_day, format, recipients, siem_feed, sections) VALUES ('default', ?, ?, ?, ?, ?, ?, ?)").run(
        snapshot.reportConfig.schedule, snapshot.reportConfig.day_of_week, snapshot.reportConfig.time_of_day,
        snapshot.reportConfig.format, snapshot.reportConfig.recipients, snapshot.reportConfig.siem_feed, snapshot.reportConfig.sections
      );
    }

    db.close();
    auditLog(req.user.id, 'CONFIG_REVERTED', `to snapshot "${snapshot.name}" (${req.params.id})`, req.ip);
    res.json({ ok: true, revertedTo: snapshot.name, autoSavedAs: currentId });
  } catch (err) {
    logger.error('Config revert error', { error: err.message });
    res.status(500).json({ error: 'Failed to revert config' });
  }
});

module.exports = router;

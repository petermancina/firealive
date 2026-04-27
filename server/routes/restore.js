// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Restore & Settings Revert Routes
// GET  /api/restore/points      — list available restore points (backups + configs)
// GET  /api/restore/preview/:id — preview what a restore would change
// POST /api/restore/execute/:id — execute restore from backup
// GET  /api/restore/configs     — list saved configuration snapshots
// POST /api/restore/config-save — save current config as named snapshot
// POST /api/restore/config-revert/:id — revert to a config snapshot
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── List Restore Points ──────────────────────────────────────────────────────
router.get('/points', (req, res) => {
  try {
    const db = getDb();
    const backups = db.prepare("SELECT id, type, size_bytes, file_path, sha256_hash, status, created_at FROM backups WHERE status = 'verified' ORDER BY created_at DESC LIMIT 30").all();
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
        id: b.id, type: b.type, sizeMB: b.size_bytes ? (b.size_bytes / 1024 / 1024).toFixed(2) : null,
        hash: b.sha256_hash?.slice(0, 16) + '…', status: b.status, createdAt: b.created_at,
      })),
      configSnapshots,
    });
  } catch (err) {
    logger.error('List restore points error', { error: err.message });
    res.status(500).json({ error: 'Failed to list restore points' });
  }
});

// ── Preview Restore ──────────────────────────────────────────────────────────
router.get('/preview/:id', (req, res) => {
  try {
    const db = getDb();
    const backup = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);
    db.close();

    if (!backup) return res.status(404).json({ error: 'Backup not found' });
    if (backup.status !== 'verified') return res.status(400).json({ error: 'Backup not verified — cannot restore' });

    const fileExists = fs.existsSync(backup.file_path);

    res.json({
      id: backup.id,
      type: backup.type,
      createdAt: backup.created_at,
      sizeMB: backup.size_bytes ? (backup.size_bytes / 1024 / 1024).toFixed(2) : null,
      hash: backup.sha256_hash,
      fileExists,
      warning: 'Restoring will replace the current database with this backup. This action is irreversible. A pre-restore backup will be created automatically.',
    });
  } catch (err) {
    logger.error('Preview restore error', { error: err.message });
    res.status(500).json({ error: 'Failed to preview restore' });
  }
});

// ── Execute Restore ──────────────────────────────────────────────────────────
router.post('/execute/:id', (req, res) => {
  const { confirmHash } = req.body;

  try {
    const db = getDb();
    const backup = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);

    if (!backup) { db.close(); return res.status(404).json({ error: 'Backup not found' }); }
    if (backup.status !== 'verified') { db.close(); return res.status(400).json({ error: 'Backup not verified' }); }
    if (!fs.existsSync(backup.file_path)) { db.close(); return res.status(400).json({ error: 'Backup file not found on disk' }); }

    // Require confirmation hash
    if (confirmHash !== backup.sha256_hash?.slice(0, 8)) {
      db.close();
      return res.status(400).json({ error: 'Confirmation required. Send { confirmHash: "<first 8 chars of backup hash>" }', hint: backup.sha256_hash?.slice(0, 8) });
    }

    db.close();

    // Create pre-restore backup
    const { DB_PATH } = require('../db/init');
    const preRestorePath = path.join(path.dirname(backup.file_path), `pre-restore-${Date.now()}.db`);
    fs.copyFileSync(DB_PATH, preRestorePath);

    // Verify backup integrity before restore
    const fileBuffer = fs.readFileSync(backup.file_path);
    const currentHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    if (currentHash !== backup.sha256_hash) {
      return res.status(400).json({ error: 'Backup integrity check failed — file has been modified since verification' });
    }

    // Execute restore
    fs.copyFileSync(backup.file_path, DB_PATH);

    auditLog(req.user.id, 'DATABASE_RESTORED', `backup=${backup.id} from=${backup.created_at} pre-restore=${preRestorePath}`, req.ip);
    logger.warn('DATABASE RESTORED', { backupId: backup.id, from: backup.created_at });

    res.json({
      ok: true,
      message: 'Database restored successfully. A pre-restore backup was saved.',
      preRestorePath: path.basename(preRestorePath),
      restoredFrom: backup.created_at,
      note: 'The server should be restarted to ensure all in-memory state reflects the restored database.',
    });
  } catch (err) {
    logger.error('Execute restore error', { error: err.message });
    res.status(500).json({ error: 'Failed to execute restore' });
  }
});

// ── Configuration Snapshots ──────────────────────────────────────────────────
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

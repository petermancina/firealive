// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Routes
// POST /api/backup              — trigger on-demand backup
// GET  /api/backup              — list backup history
// GET  /api/backup/:id/verify   — verify backup integrity (SHA-256)
// POST /api/backup/config       — update backup schedule config
// GET  /api/backup/config       — get current backup config
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { backupService } = require('../services/backup');
const { logger } = require('../services/logger');

const BACKUP_DIR = process.env.BACKUP_DIR || path.join(__dirname, '../../data/backups');

// ── List Backups ─────────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const backups = db.prepare('SELECT * FROM backups ORDER BY created_at DESC LIMIT 50').all();
    db.close();
    res.json({ backups });
  } catch (err) {
    logger.error('List backups error', { error: err.message });
    res.status(500).json({ error: 'Failed to list backups' });
  }
});

// ── Trigger On-Demand Backup ─────────────────────────────────────────────────
router.post('/', async (req, res) => {
  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `firealive-backup-${timestamp}.db`;
    const filePath = path.join(BACKUP_DIR, filename);

    // Ensure backup directory
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

    // Insert record as running
    db.prepare('INSERT INTO backups (id, type, file_path, status) VALUES (?, ?, ?, ?)').run(id, 'on-demand', filePath, 'running');

    // Copy the database file
    const { DB_PATH } = require('../db/init');
    const sourceDb = new (require('better-sqlite3'))(DB_PATH);
    sourceDb.backup(filePath).then(() => {
      sourceDb.close();

      // Compute SHA-256
      const fileBuffer = fs.readFileSync(filePath);
      const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
      const size = fileBuffer.length;

      const updateDb = getDb();
      updateDb.prepare('UPDATE backups SET status = ?, sha256_hash = ?, size_bytes = ? WHERE id = ?').run('verified', hash, size, id);
      updateDb.close();

      auditLog(req.user.id, 'BACKUP_CREATED', `type=on-demand size=${size} hash=${hash.slice(0, 16)}…`, req.ip);
    }).catch(err => {
      const errDb = getDb();
      errDb.prepare('UPDATE backups SET status = ? WHERE id = ?').run('failed', id);
      errDb.close();
      logger.error('Backup copy failed', { error: err.message });
    });

    db.close();
    res.status(202).json({ id, status: 'running', filePath: filename });
  } catch (err) {
    logger.error('Trigger backup error', { error: err.message });
    res.status(500).json({ error: 'Failed to trigger backup' });
  }
});

// ── Verify Backup Integrity ──────────────────────────────────────────────────
router.get('/:id/verify', (req, res) => {
  try {
    const db = getDb();
    const backup = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);
    db.close();

    if (!backup) return res.status(404).json({ error: 'Backup not found' });
    if (backup.status === 'running') return res.json({ status: 'running', message: 'Backup still in progress' });

    if (!fs.existsSync(backup.file_path)) {
      return res.json({ status: 'missing', message: 'Backup file not found on disk' });
    }

    const fileBuffer = fs.readFileSync(backup.file_path);
    const currentHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    const matches = currentHash === backup.sha256_hash;

    auditLog(req.user?.id, 'BACKUP_VERIFIED', `id=${backup.id} match=${matches}`, req.ip);
    res.json({
      status: matches ? 'verified' : 'tampered',
      storedHash: backup.sha256_hash,
      currentHash,
      sizeBytes: fileBuffer.length,
      matches,
    });
  } catch (err) {
    logger.error('Verify backup error', { error: err.message });
    res.status(500).json({ error: 'Failed to verify backup' });
  }
});

// ── Backup Schedule Config ───────────────────────────────────────────────────
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

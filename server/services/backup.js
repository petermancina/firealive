// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Service
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { logger } = require('./logger');
const { DB_PATH } = require('../db/init');

function performBackup(type = 'on-demand') {
  const backupDir = process.env.BACKUP_PATH || path.join(__dirname, '../../data/backups');
  if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `firealive-backup-${timestamp}.db`;
  const dest = path.join(backupDir, filename);

  try {
    fs.copyFileSync(DB_PATH, dest);
    const stats = fs.statSync(dest);
    const hash = crypto.createHash('sha256').update(fs.readFileSync(dest)).digest('hex');

    // Log backup to database
    const { getDb } = require('../db/init');
    const db = getDb();
    db.prepare('INSERT INTO backups (type, size_bytes, file_path, sha256_hash, status) VALUES (?, ?, ?, ?, ?)')
      .run(type, stats.size, dest, hash, 'verified');
    db.close();

    logger.info(`Backup complete: ${filename} (${(stats.size / 1024 / 1024).toFixed(1)} MB) sha256:${hash.slice(0, 12)}`);

    // Clean old backups beyond retention
    cleanOldBackups(backupDir);

    return { filename, size: stats.size, hash, status: 'verified' };
  } catch (err) {
    logger.error('Backup failed', { error: err.message });
    throw err;
  }
}

function cleanOldBackups(backupDir) {
  const retentionDays = parseInt(process.env.BACKUP_RETENTION_DAYS || '35');
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;

  try {
    const files = fs.readdirSync(backupDir).filter(f => f.startsWith('firealive-backup-'));
    for (const file of files) {
      const filePath = path.join(backupDir, file);
      const stat = fs.statSync(filePath);
      if (stat.mtimeMs < cutoff) {
        fs.unlinkSync(filePath);
        logger.info(`Deleted old backup: ${file}`);
      }
    }
  } catch (err) {
    logger.error('Backup cleanup failed', { error: err.message });
  }
}

module.exports = { performBackup };

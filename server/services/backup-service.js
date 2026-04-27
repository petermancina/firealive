const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class BackupService {
  constructor(db, backupDir) {
    this.db = db;
    this.backupDir = backupDir || path.join(process.cwd(), 'data', 'backups');
    this._initTables();
    if (!fs.existsSync(this.backupDir)) fs.mkdirSync(this.backupDir, { recursive: true });
  }
  _initTables() {
    this.db.prepare(`CREATE TABLE IF NOT EXISTS backup_history (
      id TEXT PRIMARY KEY, type TEXT, size INTEGER, hash TEXT,
      destination TEXT, encrypted INTEGER, created_at TEXT
    )`).run();
    this.db.prepare(`CREATE TABLE IF NOT EXISTS backup_schedules (
      id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, interval TEXT,
      retention TEXT, destination TEXT, encrypted INTEGER DEFAULT 1,
      active INTEGER DEFAULT 1, last_run TEXT, created_at TEXT
    )`).run();
  }
  createBackup(type = 'full') {
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `firealive-${type}-${timestamp}.db.bak`;
    const destPath = path.join(this.backupDir, filename);
    // SECURITY: Prevent path traversal in backup filenames
    if (!destPath.startsWith(this.backupDir)) throw new Error('Invalid backup path');
    // Copy current database
    const dbPath = this.db.name;
    if (fs.existsSync(dbPath)) {
      fs.copyFileSync(dbPath, destPath);
      const stats = fs.statSync(destPath);
      const hash = crypto.createHash('sha256').update(fs.readFileSync(destPath)).digest('hex');
      this.db.prepare("INSERT INTO backup_history (id, type, size, hash, destination, encrypted, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)").run(id, type, stats.size, hash, destPath, new Date().toISOString());
      return { id, type, size: stats.size, hash, path: destPath };
    }
    return { error: 'Database file not found' };
  }
  getHistory() { return this.db.prepare("SELECT * FROM backup_history ORDER BY created_at DESC LIMIT 20").all(); }
  getSchedules() { return this.db.prepare("SELECT * FROM backup_schedules WHERE active = 1").all(); }
  addSchedule(type, interval, retention, destination) {
    this.db.prepare("INSERT INTO backup_schedules (type, interval, retention, destination, created_at) VALUES (?, ?, ?, ?, ?)").run(type, interval, retention, destination, new Date().toISOString());
  }
  restore(backupId) {
    const backup = this.db.prepare("SELECT * FROM backup_history WHERE id = ?").get(backupId);
    if (!backup || !fs.existsSync(backup.destination)) return { error: 'Backup not found' };
    const hash = crypto.createHash('sha256').update(fs.readFileSync(backup.destination)).digest('hex');
    if (hash !== backup.hash) return { error: 'Backup integrity check failed — hash mismatch' };
    return { verified: true, path: backup.destination, hash };
  }
}

module.exports = { BackupService };

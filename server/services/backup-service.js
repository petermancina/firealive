const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// BackupService — v1.0.0 baseline backup class. As of R3i C10, the
// schedule-related methods (addSchedule, getSchedules) delegate to
// the canonical backup-schedules service that owns the
// backup_schedules table in init.js migration discipline (promoted
// in R3i C2). The createBackup / getHistory / restore methods
// remain local to this class and still operate against the
// backup_history table, which is lazily created on construction
// here. A future v100 cleanup phase (currently scoped for R3l) can
// promote backup_history into init.js when that phase addresses
// the broader v100 stub feature set.
//
// Public contract preserved: the four v100 stub routes in
// server/routes/v100-features.js continue to function with their
// existing signatures. Internally, addSchedule now routes through
// the modern persistence + floor-enforcement + scheduler-poll
// pipeline.

class BackupService {
  constructor(db, backupDir) {
    this.db = db;
    this.backupDir = backupDir || path.join(process.cwd(), 'data', 'backups');
    this._initHistoryTable();
    if (!fs.existsSync(this.backupDir)) fs.mkdirSync(this.backupDir, { recursive: true });
  }

  // R3i C10: trimmed from the previous _initTables() method. Only
  // backup_history is lazily created here now; backup_schedules
  // moved to init.js in C2. Idempotent CREATE TABLE IF NOT EXISTS
  // — no-op when the table already exists.
  _initHistoryTable() {
    this.db.prepare(`CREATE TABLE IF NOT EXISTS backup_history (
      id TEXT PRIMARY KEY, type TEXT, size INTEGER, hash TEXT,
      destination TEXT, encrypted INTEGER, created_at TEXT
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

  // R3i C10: getSchedules() now delegates to the canonical
  // backup-schedules service. The legacy contract (return active
  // schedules as raw row objects) is preserved by filtering to
  // active=1 at the call site. The modern service's list() returns
  // ALL schedules with preset metadata JOINed in; v100 callers
  // who read the result and only care about the legacy columns
  // (type, interval, retention, destination, encrypted, active,
  // last_run, created_at) get those columns intact and ignore the
  // additional R3i columns + preset_* JOIN columns.
  getSchedules() {
    const backupSchedules = require('./backup-schedules');
    return backupSchedules.list().filter(s => s.active === 1);
  }

  // R3i C10: addSchedule(type, interval, retention, destination)
  // delegates to backupSchedules.create() with the legacy v100
  // signature mapped to the modern body shape. Specifically:
  //
  //   - 'interval' (legacy free-form string e.g. 'Every 4hr')
  //     preserved as-is; the modern service falls back to
  //     _legacyIntervalToFrequency when frequency is null on
  //     scheduler tick.
  //
  //   - 'retention' (legacy free-form string e.g. '30 days')
  //     preserved as-is; applyPresetFloor reads retention_days
  //     first, then falls back to parsing the retention string
  //     via /(\d+)\s*day/i.
  //
  //   - encrypted defaults to 1 (the legacy v100 contract treated
  //     encryption as implicit; the parameter was never exposed).
  //
  //   - active defaults to 1 (legacy semantics: newly added
  //     schedules are immediately active).
  //
  //   - regulatory_preset_id is null (legacy v100 callers do not
  //     pick presets; no floor enforcement runs).
  //
  //   - name is null (legacy v100 callers do not supply one; the
  //     MC schedules list renders 'Schedule #N' fallback for
  //     unnamed rows).
  //
  // Return value: the modern service returns the created schedule
  // row. The v100 stub route at routes/v100-features.js line 80
  // currently discards the return value (responds with
  // { saved: true }); behavior is unchanged.
  addSchedule(type, interval, retention, destination) {
    const backupSchedules = require('./backup-schedules');
    return backupSchedules.create({
      type,
      interval,
      retention,
      destination,
      encrypted: 1,
      active: 1,
    });
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

const os = require('os');
const fs = require('fs');

class SystemHealthMonitor {
  constructor(db) { this.db = db; }
  getMetrics() {
    const mem = process.memoryUsage();
    const dbPath = this.db?.name;
    let dbSize = 0;
    try { if (dbPath && fs.existsSync(dbPath)) dbSize = fs.statSync(dbPath).size; } catch {}
    return {
      cpu: `${Math.round(os.loadavg()[0] * 100 / os.cpus().length)}%`,
      memory: `${Math.round(mem.rss / 1024 / 1024)}MB`,
      heap: `${Math.round(mem.heapUsed / 1024 / 1024)}MB`,
      db: `${(dbSize / 1024 / 1024).toFixed(1)}MB`,
      uptime: this._formatUptime(process.uptime()),
      platform: process.platform,
      nodeVersion: process.version,
      pid: process.pid,
    };
  }
  _formatUptime(seconds) {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
  }
  getConnectedClients() {
    try {
      return this.db.prepare("SELECT id, uuid, pseudonym, last_heartbeat, active FROM users WHERE role='analyst'").all().map(u => ({
        ...u, connected: u.last_heartbeat && (Date.now() - new Date(u.last_heartbeat).getTime() < 90000)
      }));
    } catch { return []; }
  }
}
module.exports = { SystemHealthMonitor };

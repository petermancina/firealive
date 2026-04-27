const https = require('https');
const http = require('http');

class IntegrationManager {
  constructor(db) { this.db = db; this._initTables(); }
  _initTables() {
    this.db.prepare(`CREATE TABLE IF NOT EXISTS integration_status (
      id TEXT PRIMARY KEY, type TEXT, platform TEXT, endpoint TEXT,
      status TEXT DEFAULT 'not configured', last_check TEXT,
      last_success TEXT, error_count INTEGER DEFAULT 0
    )`).run();
  }
  async testConnection(type, endpoint) {
    try {
      const url = new URL(endpoint);
      return new Promise((resolve) => {
        const mod = url.protocol === 'https:' ? https : http;
        const req = mod.request({ hostname: url.hostname, port: url.port, path: '/health', method: 'GET', timeout: 5000 }, (res) => {
          resolve({ connected: true, status: res.statusCode, type });
        });
        req.on('error', (e) => resolve({ connected: false, error: e.message, type }));
        req.on('timeout', () => { req.destroy(); resolve({ connected: false, error: 'Timeout', type }); });
        req.end();
      });
    } catch (e) { return { connected: false, error: e.message, type }; }
  }
  saveConfig(type, platform, endpoint, apiKeyHash) {
    this.db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(
      `${type}_config`, JSON.stringify({ platform, endpoint, apiKeyHash, configuredAt: new Date().toISOString() })
    );
    this.db.prepare("INSERT OR REPLACE INTO integration_status (id, type, platform, endpoint, status, last_check) VALUES (?, ?, ?, ?, 'configured', ?)").run(
      type, type, platform, endpoint, new Date().toISOString()
    );
    return { saved: true, type, platform };
  }
  getAll() { return this.db.prepare("SELECT * FROM integration_status").all(); }
  getConfig(type) {
    const row = this.db.prepare("SELECT value FROM config WHERE key = ?").get(`${type}_config`);
    return row ? JSON.parse(row.value) : null;
  }
}
module.exports = { IntegrationManager };

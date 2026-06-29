// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — System Routes
// GET  /api/system/health     — health check (public, no auth needed)
// GET  /api/system/version    — version info + fuse counter
// GET  /api/system/config     — system configuration
// POST /api/system/fuse-check — verify anti-rollback fuse
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const os = require('os');
const fs = require('fs');
const { getDb, DB_PATH } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

const { version, fuseCounter, buildId } = require('../lib/version');

const APP_VERSION = version;
const FUSE_COUNTER = fuseCounter;
const BUILD_ID = buildId;

// ── Health Check ─────────────────────────────────────────────────────────────
router.get('/health', (req, res) => {
  try {
    const db = getDb();
    // Quick DB connectivity test
    db.prepare('SELECT 1').get();
    db.close();

    res.json({
      status: 'healthy',
      version: APP_VERSION,
      fuse: FUSE_COUNTER,
      uptime: Math.floor(process.uptime()),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    logger.error('Health check failed', { error: err.message });
    res.status(503).json({ status: 'unhealthy', error: 'Database connectivity failed' });
  }
});

// ── Version Info ─────────────────────────────────────────────────────────────
router.get('/version', (req, res) => {
  try {
    const db = getDb();
    const meta = {};
    const rows = db.prepare('SELECT key, value FROM system_meta').all();
    for (const r of rows) meta[r.key] = r.value;

    // Integration status summary
    const integrations = db.prepare(`
      SELECT integration_type, status FROM integration_config ORDER BY integration_type
    `).all();

    const analystCount = db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'analyst'").get();
    const auditCount = db.prepare('SELECT COUNT(*) AS count FROM audit_log').get();

    db.close();

    // R3l C8: CPU load and DB size observability.
    // os.loadavg() returns [1min, 5min, 15min] run-queue averages. Normalising
    // by core count yields a per-core utilisation figure; capped at 100% so
    // bursty loads above 1.0/core don't render as misleadingly high values.
    // os.loadavg() returns [0, 0, 0] on Windows; cpu metrics will read 0 there
    // which is intentional (the field is documented as advisory, not exact).
    const loadAvg = os.loadavg();
    const cpuCores = os.cpus().length || 1;
    const cpuPercent = (n) => Math.min(100, Math.max(0, Math.round((n / cpuCores) * 100)));

    // DB size — fs.statSync on the SQLite file. If WAL mode is active there is
    // also a -wal companion file; we report just the main file for stability of
    // the metric across checkpoints. Failures (missing path, permission) return
    // null rather than crashing the version endpoint.
    let dbSizeBytes = null;
    try {
      dbSizeBytes = fs.statSync(DB_PATH).size;
    } catch (statErr) {
      logger.warn('Version endpoint could not stat DB file', { path: DB_PATH, error: statErr.message });
    }

    res.json({
      version: APP_VERSION,
      buildId: BUILD_ID,
      fuseCounter: FUSE_COUNTER,
      storedFuse: parseInt(meta.fuse_counter, 10),
      fuseValid: parseInt(meta.fuse_counter, 10) <= FUSE_COUNTER,
      schemaVersion: meta.schema_version,
      installedAt: meta.installed_at,
      environment: process.env.NODE_ENV || 'development',
      analysts: analystCount.count,
      auditEvents: auditCount.count,
      integrations: integrations.map(i => ({ type: i.integration_type, status: i.status })),
      runtime: {
        node: process.version,
        platform: os.platform(),
        arch: os.arch(),
        uptime: Math.floor(process.uptime()),
        memory: {
          rss: Math.round(process.memoryUsage().rss / 1024 / 1024) + 'MB',
          heap: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
        },
        cpu: {
          cores: cpuCores,
          loadAvg1m: loadAvg[0],
          loadAvg5m: loadAvg[1],
          loadAvg15m: loadAvg[2],
          percent1m: cpuPercent(loadAvg[0]),
          percent5m: cpuPercent(loadAvg[1]),
          percent15m: cpuPercent(loadAvg[2]),
        },
      },
      database: {
        path: DB_PATH,
        sizeBytes: dbSizeBytes,
        sizeMB: dbSizeBytes === null ? null : Math.round((dbSizeBytes / 1024 / 1024) * 100) / 100,
      },
    });
  } catch (err) {
    logger.error('Version info error', { error: err.message });
    res.status(500).json({ error: 'Failed to get version info' });
  }
});

// ── Anti-Rollback Fuse Check ─────────────────────────────────────────────────
router.post('/fuse-check', (req, res) => {
  try {
    const db = getDb();
    const storedFuse = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
    const stored = parseInt(storedFuse?.value, 10) || 0;
    db.close();

    const valid = stored <= FUSE_COUNTER;

    if (!valid) {
      logger.error('ANTI-ROLLBACK VIOLATION', { stored, expected: FUSE_COUNTER });
      auditLog(req.user?.id, 'FUSE_VIOLATION', `stored=${stored} expected=${FUSE_COUNTER}`, req.ip);
    }

    res.json({
      valid,
      storedFuse: stored,
      appFuse: FUSE_COUNTER,
      message: valid ? 'Fuse counter valid — no rollback detected' : 'ANTI-ROLLBACK VIOLATION: stored fuse exceeds app fuse. This binary may be a downgrade.',
    });
  } catch (err) {
    logger.error('Fuse check error', { error: err.message });
    res.status(500).json({ error: 'Failed to check fuse counter' });
  }
});

// ── System Config ────────────────────────────────────────────────────────────
router.get('/config', (req, res) => {
  try {
    const db = getDb();
    const configs = db.prepare("SELECT key, value, updated_at FROM team_config WHERE key NOT LIKE 'pubkey_%' AND key NOT LIKE 'soar_%'").all();
    db.close();

    const config = {};
    for (const c of configs) {
      try { config[c.key] = JSON.parse(c.value); } catch { config[c.key] = c.value; }
    }

    res.json({
      version: APP_VERSION,
      fuse: FUSE_COUNTER,
      config,
    });
  } catch (err) {
    logger.error('Get system config error', { error: err.message });
    res.status(500).json({ error: 'Failed to get system config' });
  }
});

module.exports = router;

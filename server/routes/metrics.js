// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Metrics Routes
// GET  /api/metrics      — full JSON metrics across all features
// GET  /api/metrics/cef  — CEF-formatted single line for SIEM ingestion
// ═══════════════════════════════════════════════════════════════════════════════
//
// These endpoints expose the MetricsCollector service over HTTP. The collector
// reads aggregate metrics across the entire FireAlive feature surface:
//
//   - team_health       — analyst headcount and average capacity score
//   - routing           — panic mode and routing-enabled flags
//   - peer_sessions     — peer skill-share session count over the last 24 hours
//   - training          — verified training completions
//   - assessments       — completed assessments and average score
//   - auth              — successful and failed login counts over 24 hours
//   - audit_integrity   — last hash prefix and intact flag
//   - backup            — last backup timestamp
//   - upskilling        — count of analysts with scheduled upskilling slots
//   - integrations      — SOAR / ticketing / IAM / SIEM connection status
//   - notifications     — total and unread notification counts
//   - ir_policies       — loaded IR policy count
//   - baselines         — analyst baseline counts (total and established)
//   - features          — feature toggle states
//   - system            — process uptime, memory, version, fuse counter
//
// The CEF endpoint formats the same data as a single CEF v0 line for SIEM
// ingestion. The Global Dashboard polls this endpoint to populate the
// regional health panel; SIEM platforms (Splunk, QRadar, Microsoft Sentinel)
// can ingest /api/metrics/cef on a schedule for dashboard display.
//
// Authorization is restricted to lead and admin roles at the mount level in
// server/index.js. Although the metrics are aggregate (no per-analyst
// breakdown), they would still leak operational signal — an attacker who can
// see auth failures, peer session counts, and integration health would get
// a meaningful map of the SOC's posture.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const { MetricsCollector } = require('../services/metrics-collector');

// ── GET /api/metrics — full JSON metrics ─────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const metrics = new MetricsCollector(db).collect();
    db.close();
    auditLog(req.user?.id, 'METRICS_READ', 'json', req.ip);
    res.json(metrics);
  } catch (err) {
    logger.error('Get metrics error', { error: err.message });
    res.status(500).json({ error: 'Failed to collect metrics' });
  }
});

// ── GET /api/metrics/cef — CEF-formatted single line ─────────────────────────
router.get('/cef', (req, res) => {
  try {
    const db = getDb();
    const cef = new MetricsCollector(db).toCEF();
    db.close();
    auditLog(req.user?.id, 'METRICS_READ', 'cef', req.ip);
    res.type('text/plain').send(cef);
  } catch (err) {
    logger.error('Get CEF metrics error', { error: err.message });
    res.status(500).json({ error: 'Failed to collect CEF metrics' });
  }
});

module.exports = router;

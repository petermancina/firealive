// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Alert Config Routes  (admin only; mounted in server/index.js)
//
//   GET  /api/alert-config  — current routing matrix, sustained thresholds, and
//                             metadata (defaults, severities, channels, whether
//                             a webhook URL is set). Audit is always-on and not
//                             part of the matrix.
//   PUT  /api/alert-config  — update any of: { matrix, thresholds, webhookUrl }.
//                             Each is sanitized; matrix/threshold updates merge
//                             over the current values so partial updates are
//                             safe. Threshold changes apply to the live runtime
//                             monitor immediately via configureThresholds().
//
// Writes are audited as ALERT_CONFIG_UPDATED (what changed; no secrets).
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { runtimeMonitor } = require('../services/runtime-monitor');
const {
  loadMatrix, DEFAULT_MATRIX, MATRIX_CONFIG_KEY, SEVERITIES, CHANNELS,
} = require('../services/alert-router');

const THRESHOLDS_CONFIG_KEY = 'runtime_monitor_thresholds';
const WEBHOOK_URL_CONFIG_KEY = 'alert_webhook_url';

// numeric threshold bounds (matches runtime-monitor's configurable keys)
const THRESHOLD_SPEC = {
  cpuEnter:     { min: 1, max: 100 },
  cpuExit:      { min: 0, max: 100 },
  cpuDwell:     { min: 1, max: 240, int: true },
  memEnterMult: { min: 1, max: 20 },
  memExitMult:  { min: 1, max: 20 },
  memDwell:     { min: 1, max: 240, int: true },
  dbEnterMult:  { min: 1, max: 100 },
  dbExitMult:   { min: 1, max: 100 },
  dbDwell:      { min: 1, max: 240, int: true },
  cooldownMs:   { min: 0, max: 3600000, int: true },
};

// Keep only known severities/channels with boolean values.
function sanitizeMatrix(input) {
  if (!input || typeof input !== 'object') return null;
  const out = {};
  for (const sev of SEVERITIES) {
    if (input[sev] && typeof input[sev] === 'object') {
      const row = {};
      for (const ch of CHANNELS) {
        if (typeof input[sev][ch] === 'boolean') row[ch] = input[sev][ch];
      }
      if (Object.keys(row).length) out[sev] = row;
    }
  }
  return Object.keys(out).length ? out : null;
}

// Keep only known numeric thresholds, clamped to sane bounds; keep exit <= enter.
function sanitizeThresholds(input) {
  if (!input || typeof input !== 'object') return null;
  const out = {};
  for (const [k, spec] of Object.entries(THRESHOLD_SPEC)) {
    let v = input[k];
    if (typeof v !== 'number' || !isFinite(v)) continue;
    if (spec.int) v = Math.round(v);
    out[k] = Math.max(spec.min, Math.min(spec.max, v));
  }
  if (out.cpuExit != null && out.cpuEnter != null && out.cpuExit > out.cpuEnter) out.cpuExit = out.cpuEnter;
  if (out.memExitMult != null && out.memEnterMult != null && out.memExitMult > out.memEnterMult) out.memExitMult = out.memEnterMult;
  if (out.dbExitMult != null && out.dbEnterMult != null && out.dbExitMult > out.dbEnterMult) out.dbExitMult = out.dbEnterMult;
  return Object.keys(out).length ? out : null;
}

router.get('/', (req, res) => {
  try {
    const db = getDb();
    const matrix = loadMatrix(db);
    const wh = db.prepare('SELECT value FROM config WHERE key = ?').get(WEBHOOK_URL_CONFIG_KEY);
    db.close();
    res.json({
      matrix,
      thresholds: runtimeMonitor.configureThresholds({}), // live copy, no mutation
      defaults: DEFAULT_MATRIX,
      severities: SEVERITIES,
      channels: CHANNELS,
      auditAlwaysOn: true,
      webhookConfigured: !!(wh && wh.value),
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load alert config' });
  }
});

router.put('/', (req, res) => {
  try {
    const body = req.body || {};
    const db = getDb();
    const changes = [];

    const matrix = sanitizeMatrix(body.matrix);
    if (matrix) {
      const existing = loadMatrix(db);
      const merged = {};
      for (const sev of SEVERITIES) merged[sev] = { ...existing[sev], ...(matrix[sev] || {}) };
      db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(MATRIX_CONFIG_KEY, JSON.stringify(merged));
      changes.push('routing matrix');
    }

    const thresholds = sanitizeThresholds(body.thresholds);
    if (thresholds) {
      const applied = runtimeMonitor.configureThresholds(thresholds);
      db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(THRESHOLDS_CONFIG_KEY, JSON.stringify(applied));
      changes.push('sustained thresholds');
    }

    if (typeof body.webhookUrl === 'string') {
      const url = body.webhookUrl.trim();
      if (url === '') {
        db.prepare('DELETE FROM config WHERE key = ?').run(WEBHOOK_URL_CONFIG_KEY);
        changes.push('webhook url (cleared)');
      } else {
        let u;
        try { u = new URL(url); } catch { db.close(); return res.status(400).json({ error: 'Invalid webhook URL' }); }
        if (u.protocol !== 'https:' && u.protocol !== 'http:') { db.close(); return res.status(400).json({ error: 'Invalid webhook URL' }); }
        db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(WEBHOOK_URL_CONFIG_KEY, url);
        changes.push('webhook url');
      }
    }

    if (changes.length === 0) { db.close(); return res.status(400).json({ error: 'No valid fields to update' }); }

    const newMatrix = loadMatrix(db);
    const wh = db.prepare('SELECT value FROM config WHERE key = ?').get(WEBHOOK_URL_CONFIG_KEY);
    db.close();
    auditLog(req.user && req.user.id, 'ALERT_CONFIG_UPDATED', changes.join(', '), req.ip);
    res.json({
      updated: changes,
      matrix: newMatrix,
      thresholds: runtimeMonitor.configureThresholds({}),
      webhookConfigured: !!(wh && wh.value),
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to update alert config' });
  }
});

module.exports = router;

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v0.0.25 — New Routes
// Adds: pseudonym system, data sovereignty/geo-fencing,
// global dashboard, enhanced backup schedules, sync interval config
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { requireArrayBody, requireObjectBody } = require('../middleware/body-validation');
const { logger } = require('../services/logger');
const { generatePseudonym, generateUniquePseudonym } = require('../lib/pseudonym');

// ── Pseudonym System ────────────────────────────────────────────────────────
// The pseudonym is the ONLY identifier stored alongside burnout data.
// IAM username → pseudonym mapping is encrypted and exportable, never stored
// in the main database in plaintext. The pseudonym scheme itself lives in
// server/lib/pseudonym.js (shared with provisioning and the backfill).

router.get('/pseudonyms/config', (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'pseudonym_config'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : {
      enabled: true, autoGenerate: true, allowCustom: true,
      showRealNameToLead: true, leadExportEnabled: true
    });
  } catch (e) { res.status(500).json({ error: 'Failed to load pseudonym config' }); }
});

router.put('/pseudonyms/config', requireObjectBody, (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('pseudonym_config', ?)").run(JSON.stringify(req.body));
    auditLog(req.user?.id || 'system', 'PSEUDONYM_CONFIG_UPDATED', 'Pseudonym system config updated');
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save pseudonym config' }); }
});

router.post('/pseudonyms/generate', (req, res) => {
  // Suggest a pseudonym for the UI (uniqueness is enforced on assign).
  res.json({ pseudonym: generatePseudonym() });
});

router.post('/pseudonyms/assign', (req, res) => {
  try {
    const { analystId, pseudonym } = req.body;
    const db = getDb();
    // Store only the pseudonym on the users row
    db.prepare("UPDATE users SET pseudonym = ?, pseudonym_rotated_at = ? WHERE id = ? AND role = 'analyst'").run(pseudonym, new Date().toISOString(), analystId);
    // The real identity mapping is NOT stored in the DB — it's only in the
    // encrypted export that the Team Lead downloads and stores offline.
    auditLog('system', 'PSEUDONYM_ASSIGNED', `Pseudonym assigned (identity not logged)`);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to assign pseudonym' }); }
});

router.post('/pseudonyms/rotate-all', (req, res) => {
  try {
    const db = getDb();
    const analysts = db.prepare("SELECT id FROM users WHERE role = 'analyst'").all();
    const used = new Set();
    analysts.forEach(a => {
      const pseudonym = generateUniquePseudonym((candidate) => used.has(candidate));
      used.add(pseudonym);
      db.prepare("UPDATE users SET pseudonym = ?, pseudonym_rotated_at = ? WHERE id = ? AND role = 'analyst'").run(pseudonym, new Date().toISOString(), a.id);
    });
    auditLog(req.user?.id || 'system', 'PSEUDONYMS_ROTATED', `All ${analysts.length} pseudonyms rotated`);
    db.close();
    res.json({ success: true, rotated: analysts.length });
  } catch (e) { res.status(500).json({ error: 'Failed to rotate pseudonyms' }); }
});

// ── Global Dashboard Config ─────────────────────────────────────────────────
router.get('/global-dashboard/config', (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'global_dashboard_config'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : { enabled: false, ingestEndpoints: [], readOnlyApiKey: '' });
  } catch (e) { res.status(500).json({ error: 'Failed to load global dashboard config' }); }
});

router.put('/global-dashboard/config', requireObjectBody, (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('global_dashboard_config', ?)").run(JSON.stringify(req.body));
    auditLog(req.user?.id || 'system', 'GLOBAL_DASH_CONFIG_UPDATED', 'Global Dashboard export config updated');
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save global dashboard config' }); }
});

// Aggregate data export — called on schedule by the MC to push to Global Dashboard
router.get('/global-dashboard/aggregate', (req, res) => {
  try {
    const db = getDb();
    const analysts = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'analyst'").get();
    // Only aggregate data — no individual analyst info
    const aggregate = {
      region: 'configured_region',
      timestamp: new Date().toISOString(),
      teamSize: analysts.count,
      // All metrics are team-level averages, never individual
      avgBurnoutScore: null, // calculated from pseudonymized data
      capacityUtilization: null,
      automationRate: null,
      slaCompliance: null,
      certificationCoverage: null,
      trainingCompletion: null,
    };
    db.close();
    res.json(aggregate);
  } catch (e) { res.status(500).json({ error: 'Failed to generate aggregate' }); }
});

// ── Backup Schedules ────────────────────────────────────────────────────────
router.get('/backup-schedules', (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'backup_schedules'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : []);
  } catch (e) { res.status(500).json({ error: 'Failed to load backup schedules' }); }
});

router.put('/backup-schedules', requireArrayBody, (req, res) => {
  try {
    if (!Array.isArray(req.body)) {
      return res.status(400).json({ error: 'Request body must be an array of schedules' });
    }
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('backup_schedules', ?)").run(JSON.stringify(req.body));
    db.close();
    auditLog(req.user?.id || 'system', 'BACKUP_SCHEDULES_UPDATED', `${req.body.length} schedules configured`, req.ip);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save backup schedules' }); }
});


// ── Sync Interval Configuration ─────────────────────────────────────────────
router.get('/sync-interval/config', (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'sync_interval_config'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : { intervalMin: 15, adaptiveSync: true, urgentThresholdSec: 30, batchMode: true });
  } catch (e) { res.status(500).json({ error: 'Failed to load sync interval config' }); }
});

router.put('/sync-interval/config', requireObjectBody, (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('sync_interval_config', ?)").run(JSON.stringify(req.body));
    auditLog(req.user?.id || 'system', 'SYNC_INTERVAL_UPDATED', `Interval: ${req.body.intervalMin}min, adaptive: ${req.body.adaptiveSync}`);
    db.close();
    // B5d4: push the new cadence to every connected analyst client so the
    // refresh timer updates live (the on-connect push lives in the WS auth
    // handler). Best-effort; the config is already persisted.
    try {
      const wsServer = req.app && req.app.locals && req.app.locals.wsServer;
      if (wsServer && typeof wsServer.broadcastSyncCadence === 'function') {
        wsServer.broadcastSyncCadence(req.body);
      }
    } catch (refreshErr) { /* non-fatal */ }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save sync interval config' }); }
});

module.exports = router;

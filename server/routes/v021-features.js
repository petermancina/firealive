// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v0.0.21 — New Routes
// Adds: vulnerability scanner integration, recertification, lead messaging
// (non-anonymous), config export/import, SASE wizard, log integrity check,
// access control environment config, peer chat scheduling
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { version } = require('../lib/version');

// ── Vulnerability Scanner Integration ────────────────────────────────────────
// Allows approved scanners (Nessus, OpenVAS, Qualys) to scan the app.
// Unauthorized scans are blocked by the network hardening middleware.
router.get('/vuln-scan/config', (req, res) => {
  try {
    const db = getDb();
    const config = db.prepare("SELECT value FROM team_config WHERE key = 'vuln_scan_config'").get();
    db.close();
    res.json(config ? JSON.parse(config.value) : {
      enabled: false,
      allowedScanners: [],
      allowedIPs: [],
      lastScan: null,
      schedule: 'weekly',
    });
  } catch (err) { res.status(500).json({ error: 'Failed to get vuln scan config' }); }
});

router.put('/vuln-scan/config', (req, res) => {
  const { enabled, allowedScanners, allowedIPs, schedule } = req.body;
  const validScanners = ['nessus', 'openvas', 'qualys', 'rapid7', 'tenable_io', 'nuclei'];
  const config = {
    enabled: !!enabled,
    allowedScanners: (allowedScanners || []).filter(s => validScanners.includes(s)),
    allowedIPs: (allowedIPs || []).filter(ip => /^[\d./:]+$/.test(ip)).slice(0, 10),
    schedule: ['daily', 'weekly', 'monthly', 'manual'].includes(schedule) ? schedule : 'weekly',
    lastScan: null,
    updatedAt: new Date().toISOString(),
  };
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('vuln_scan_config', ?, ?)").run(JSON.stringify(config), req.user.id);
    db.close();
    auditLog(req.user.id, 'VULNSCAN_CONFIG_UPDATED', `scanners=${config.allowedScanners.join(',')}`, req.ip);
    res.json({ ok: true, config });
  } catch (err) { res.status(500).json({ error: 'Failed to update vuln scan config' }); }
});

// ── Recertification ──────────────────────────────────────────────────────────
router.get('/recert/status', (req, res) => {
  const { checkRecertDue } = require('../services/recertification');
  res.json(checkRecertDue());
});

router.get('/recert/report', (req, res) => {
  const { generateRecertReport } = require('../services/recertification');
  const report = generateRecertReport();
  auditLog(req.user.id, 'RECERT_REPORT_GENERATED', '', req.ip);
  res.json(report);
});

router.post('/recert/complete', (req, res) => {
  const { completeRecert } = require('../services/recertification');
  const result = completeRecert(req.user.id);
  res.json(result);
});

router.put('/recert/config', (req, res) => {
  const { intervalDays, enabled } = req.body;
  try {
    const db = getDb();
    const existing = db.prepare("SELECT value FROM team_config WHERE key = 'recert_config'").get();
    const config = existing ? JSON.parse(existing.value) : {};
    config.intervalDays = Math.max(30, Math.min(365, parseInt(intervalDays, 10) || 90));
    config.enabled = enabled !== false;
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('recert_config', ?, ?)").run(JSON.stringify(config), req.user.id);
    db.close();
    auditLog(req.user.id, 'RECERT_CONFIG_UPDATED', `interval=${config.intervalDays}d`, req.ip);
    res.json({ ok: true, config });
  } catch (err) { res.status(500).json({ error: 'Failed to update recert config' }); }
});

// ── Access Control Environment Config ────────────────────────────────────────
router.get('/access-control/config', (req, res) => {
  try {
    const db = getDb();
    const config = db.prepare("SELECT value FROM team_config WHERE key = 'access_control_config'").get();
    db.close();
    res.json(config ? JSON.parse(config.value) : {
      model: 'rbac', // rbac, abac, mac, dac
      enforceSessionBinding: true,
      maxConcurrentSessions: 3,
      sessionTimeoutMinutes: 480,
      requireMfaForAdmin: true,
      requireMfaForConfig: true,
    });
  } catch (err) { res.status(500).json({ error: 'Failed to get access control config' }); }
});

router.put('/access-control/config', (req, res) => {
  const { model, enforceSessionBinding, maxConcurrentSessions, sessionTimeoutMinutes, requireMfaForAdmin, requireMfaForConfig } = req.body;
  const validModels = ['rbac', 'abac', 'mac', 'dac'];
  const config = {
    model: validModels.includes(model) ? model : 'rbac',
    enforceSessionBinding: enforceSessionBinding !== false,
    maxConcurrentSessions: Math.max(1, Math.min(10, parseInt(maxConcurrentSessions, 10) || 3)),
    sessionTimeoutMinutes: Math.max(15, Math.min(1440, parseInt(sessionTimeoutMinutes, 10) || 480)),
    requireMfaForAdmin: requireMfaForAdmin !== false,
    requireMfaForConfig: requireMfaForConfig !== false,
  };
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('access_control_config', ?, ?)").run(JSON.stringify(config), req.user.id);
    db.close();
    auditLog(req.user.id, 'ACCESS_CONTROL_UPDATED', `model=${config.model}`, req.ip);
    res.json({ ok: true, config });
  } catch (err) { res.status(500).json({ error: 'Failed to update access control config' }); }
});

// ── Log Integrity Check ──────────────────────────────────────────────────────
router.get('/logs/integrity', (req, res) => {
  const { detectMissingLogs } = require('../services/soar-alerting');
  const result = detectMissingLogs();
  res.json(result);
});

// ── Configuration Export/Import ──────────────────────────────────────────────
router.get('/config/export', (req, res) => {
  try {
    const db = getDb();
    const teamConfig = db.prepare("SELECT key, value FROM team_config WHERE key NOT LIKE 'peer_%' AND key NOT LIKE 'ooda_%' AND key NOT LIKE 'cert%' AND key NOT LIKE 'pending_%' AND key NOT LIKE 'lockout_%' AND key NOT LIKE 'reset_%' AND key NOT LIKE 'config_snapshot_%' AND key NOT LIKE 'pubkey_%'").all();
    const reportConfig = db.prepare('SELECT * FROM report_config WHERE id = ?').get('default');
    const slaConfig = db.prepare('SELECT * FROM sla_config WHERE id = ?').get('default');
    const notifConfig = db.prepare('SELECT * FROM notification_config WHERE id = ?').get('default');
    db.close();

    const exportData = {
      exportType: 'firealive_config',
      version,
      exportedAt: new Date().toISOString(),
      checksum: null,
      teamConfig, reportConfig, slaConfig, notifConfig,
    };
    // Compute checksum
    const content = JSON.stringify({ ...exportData, checksum: undefined });
    exportData.checksum = crypto.createHash('sha256').update(content).digest('hex');

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=firealive-config-${new Date().toISOString().slice(0, 10)}.json`);
    auditLog(req.user.id, 'CONFIG_EXPORTED', '', req.ip);
    res.json(exportData);
  } catch (err) { res.status(500).json({ error: 'Failed to export config' }); }
});

// Config change management report
router.get('/config/change-report', (req, res) => {
  try {
    const db = getDb();
    const configChanges = db.prepare(`
      SELECT timestamp, event_type, detail, user_id,
             (SELECT name FROM users WHERE id = audit_log.user_id) AS user_name
      FROM audit_log
      WHERE event_type LIKE '%CONFIG%' OR event_type LIKE '%UPDATED%' OR event_type LIKE '%FEATURE%'
      ORDER BY timestamp DESC LIMIT 100
    `).all();
    db.close();

    res.json({
      reportType: 'configuration_change_management',
      generatedAt: new Date().toISOString(),
      version,
      changeCount: configChanges.length,
      changes: configChanges,
    });
  } catch (err) { res.status(500).json({ error: 'Failed to generate change report' }); }
});

// ── SASE Integration Wizard ──────────────────────────────────────────────────
router.get('/sase/config', (req, res) => {
  try {
    const db = getDb();
    const config = db.prepare("SELECT value FROM team_config WHERE key = 'sase_config'").get();
    db.close();
    res.json(config ? JSON.parse(config.value) : {
      enabled: false,
      provider: null, // zscaler, netskope, palo_alto_prisma, cato, cloudflare
      ztnaEndpoint: '',
      casbEnabled: false,
      swgEnabled: false,
      fwaasPolicyId: '',
      deployedAsSECaaS: false,
    });
  } catch (err) { res.status(500).json({ error: 'Failed to get SASE config' }); }
});

router.put('/sase/config', (req, res) => {
  const { enabled, provider, ztnaEndpoint, casbEnabled, swgEnabled, fwaasPolicyId, deployedAsSECaaS } = req.body;
  const validProviders = ['zscaler', 'netskope', 'palo_alto_prisma', 'cato', 'cloudflare', 'fortinet'];
  const config = {
    enabled: !!enabled,
    provider: validProviders.includes(provider) ? provider : null,
    ztnaEndpoint: (ztnaEndpoint || '').slice(0, 512),
    casbEnabled: !!casbEnabled,
    swgEnabled: !!swgEnabled,
    fwaasPolicyId: (fwaasPolicyId || '').slice(0, 128),
    deployedAsSECaaS: !!deployedAsSECaaS,
    updatedAt: new Date().toISOString(),
  };
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('sase_config', ?, ?)").run(JSON.stringify(config), req.user.id);
    db.close();
    auditLog(req.user.id, 'SASE_CONFIG_UPDATED', `provider=${config.provider}`, req.ip);
    res.json({ ok: true, config });
  } catch (err) { res.status(500).json({ error: 'Failed to update SASE config' }); }
});

// ── Peer Chat Scheduling ─────────────────────────────────────────────────────
router.post('/peer-schedule/request', (req, res) => {
  const { availableTimes, topic, excludeIds } = req.body;
  if (!availableTimes || !Array.isArray(availableTimes) || availableTimes.length === 0) {
    return res.status(400).json({ error: 'availableTimes[] required (array of ISO datetime strings)' });
  }
  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(
      `peer_sched_${id}`,
      JSON.stringify({
        id, topic: (topic || '').slice(0, 500), availableTimes: availableTimes.slice(0, 20),
        excludeIds: excludeIds || [], requesterId: req.user.id,
        status: 'open', createdAt: new Date().toISOString(), matchedTime: null, matchedWith: null,
      }),
      req.user.id
    );
    db.close();
    auditLog(req.user.id, 'PEER_SCHEDULE_REQUESTED', `${availableTimes.length} time slots`, req.ip);
    res.status(201).json({ id, status: 'open', slots: availableTimes.length });
  } catch (err) { res.status(500).json({ error: 'Failed to create schedule request' }); }
});

router.get('/peer-schedule/available', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare("SELECT value FROM team_config WHERE key LIKE 'peer_sched_%'").all();
    db.close();
    const requests = rows.map(r => { try { return JSON.parse(r.value); } catch { return null; } })
      .filter(r => r && r.status === 'open' && r.requesterId !== req.user.id && !(r.excludeIds || []).includes(req.user.id))
      .map(r => ({ id: r.id, topic: r.topic, availableTimes: r.availableTimes, createdAt: r.createdAt }));
    res.json({ requests });
  } catch (err) { res.status(500).json({ error: 'Failed to list schedule requests' }); }
});

router.post('/peer-schedule/:id/accept', (req, res) => {
  const { selectedTime } = req.body;
  if (!selectedTime) return res.status(400).json({ error: 'selectedTime required' });
  try {
    const db = getDb();
    const row = db.prepare("SELECT key, value FROM team_config WHERE key = ?").get(`peer_sched_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Request not found' }); }
    const request = JSON.parse(row.value);
    if (request.status !== 'open') { db.close(); return res.status(400).json({ error: 'Already matched' }); }
    if (!request.availableTimes.includes(selectedTime)) { db.close(); return res.status(400).json({ error: 'Selected time not in available slots' }); }

    request.status = 'matched';
    request.matchedTime = selectedTime;
    request.matchedWith = req.user.id;
    db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(request), row.key);
    db.close();
    auditLog(req.user.id, 'PEER_SCHEDULE_MATCHED', `time=${selectedTime}`, req.ip);
    res.json({ ok: true, matchedTime: selectedTime });
  } catch (err) { res.status(500).json({ error: 'Failed to accept schedule' }); }
});

module.exports = router;

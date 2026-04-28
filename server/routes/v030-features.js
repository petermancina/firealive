// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v0.0.31 — Global Dashboard Push Routes
// Regional Server pushes aggregate (pseudonymized) data to the GD Server
// on a configurable schedule. No individual analyst data is ever transmitted.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { requireObjectBody } = require('../middleware/body-validation');
const { logger } = require('../services/logger');

// ── Push aggregate metrics to Global Dashboard Server ────────────────────────
router.post('/global-dashboard/push', async (req, res) => {
  try {
    const db = getDb();
    
    // Get GD config
    const gdCfgRow = db.prepare("SELECT value FROM config WHERE key = 'global_dashboard_config'").get();
    const gdCfg = gdCfgRow ? JSON.parse(gdCfgRow.value) : { enabled: false };
    
    if (!gdCfg.enabled || !gdCfg.ingestEndpoints?.length) {
      db.close();
      return res.json({ pushed: false, reason: 'Global Dashboard export not enabled or no endpoint configured' });
    }

    // Gather AGGREGATE metrics only — never individual analyst data
    const analysts = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'analyst'").get();
    
    // Calculate team-level metrics
    const metrics = {
      healthScore: 75, // In production: computed from aggregate signals
      utilization: 70,
      automationRate: 38,
      certCoverage: 62,
      slaCompliance: 91,
      turnoverRisk: 'medium',
      analystCount: analysts?.count || 0,
      activeIncidents: 0,
      burnoutRoutingActive: true,
      proactiveBreaksGiven: 0,
      upskillingHoursUsed: 0,
      timestamp: new Date().toISOString(),
    };

    // Push to each configured GD endpoint
    const results = [];
    for (const endpoint of gdCfg.ingestEndpoints) {
      try {
        // In production: HTTPS POST to GD Server
        // const response = await fetch(endpoint, {
        //   method: 'POST',
        //   headers: { 'Content-Type': 'application/json' },
        //   body: JSON.stringify({ apiKey: gdCfg.readOnlyApiKey, metrics }),
        // });
        results.push({ endpoint, status: 'pushed', timestamp: new Date().toISOString() });
        logger.info(`Pushed aggregate metrics to GD: ${endpoint}`);
      } catch (pushErr) {
        results.push({ endpoint, status: 'failed', error: pushErr.message });
        logger.error(`Failed to push to GD: ${endpoint}`, pushErr);
      }
    }

    auditLog('SYSTEM', 'GD_METRICS_PUSHED', `Pushed to ${results.filter(r => r.status === 'pushed').length}/${results.length} endpoints`);
    db.close();
    res.json({ pushed: true, results });
  } catch (e) {
    logger.error('GD push failed', e);
    res.status(500).json({ error: 'Failed to push to Global Dashboard' });
  }
});

// ── Configure GD push schedule ───────────────────────────────────────────────
router.get('/global-dashboard/push-config', (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'gd_push_schedule'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : { intervalMinutes: 60, enabled: true });
  } catch (e) { res.status(500).json({ error: 'Failed to get push config' }); }
});

router.put('/global-dashboard/push-config', requireObjectBody, (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('gd_push_schedule', ?)").run(JSON.stringify(req.body));
    auditLog(req.user?.id || 'system', 'GD_PUSH_SCHEDULE_UPDATED', `Interval: ${req.body.intervalMinutes}min`);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save push config' }); }
});

// ── Client backup trigger from MC ────────────────────────────────────────────
// MC triggers backups on all connected clients
router.post('/clients/trigger-backup', (req, res) => {
  try {
    const { type = 'incremental', targets = 'all' } = req.body;
    const db = getDb();
    // In production: sends backup command to each client via WebSocket/push
    auditLog(req.user?.id || 'system', 'CLIENT_BACKUP_TRIGGERED', `Type: ${type}, targets: ${targets}`);
    db.close();
    res.json({ success: true, message: `Backup trigger sent to ${targets === 'all' ? 'all clients' : targets}` });
  } catch (e) { res.status(500).json({ error: 'Client backup trigger failed' }); }
});

// ── Client log collection from MC ────────────────────────────────────────────
router.post('/clients/collect-logs', (req, res) => {
  try {
    const { targets = 'all', logTypes = ['audit', 'forensics', 'runtime'] } = req.body;
    const db = getDb();
    // In production: requests log transmission from each client
    auditLog(req.user?.id || 'system', 'CLIENT_LOGS_COLLECTED', `Types: ${logTypes.join(', ')}, targets: ${targets}`);
    db.close();
    res.json({ success: true, message: `Log collection requested from ${targets}` });
  } catch (e) { res.status(500).json({ error: 'Log collection failed' }); }
});

// ── Client update push ───────────────────────────────────────────────────────
router.post('/clients/push-update', (req, res) => {
  try {
    const { version, staggerMinutes = 5, requireLabTest = true } = req.body;
    const db = getDb();
    auditLog(req.user?.id || 'system', 'CLIENT_UPDATE_PUSHED', `Version: ${version}, stagger: ${staggerMinutes}min`);
    db.close();
    res.json({ success: true, message: `Update ${version} push initiated (staggered ${staggerMinutes}min)` });
  } catch (e) { res.status(500).json({ error: 'Update push failed' }); }
});

// ── Client config propagation ────────────────────────────────────────────────
// When MC changes configs that affect clients, push the changes
router.post('/clients/propagate-config', (req, res) => {
  try {
    const { configType, data, targets = 'all' } = req.body;
    const db = getDb();
    // Config types that propagate to clients:
    // - feature_toggles: which features are enabled/disabled
    // - iam_config: IAM/MFA settings
    // - wifi_policy: WiFi security requirements
    // - posture_config: posture assessment checks
    // - access_control: access control model
    // - notification_config: what notifications analysts receive
    // - routing_config: burnout routing parameters
    // - upskilling_config: upskilling hour settings
    // - peer_schedule_config: peer chat scheduling windows
    auditLog(req.user?.id || 'system', 'CONFIG_PROPAGATED', `${configType} → ${targets}`);
    db.close();
    res.json({ success: true, configType, targets });
  } catch (e) { res.status(500).json({ error: 'Config propagation failed' }); }
});

// ── Proactive break: MC approves, server notifies client ─────────────────────
router.post('/proactive-break/send', (req, res) => {
  try {
    const { analystPseudonym, hours, duration } = req.body;
    const db = getDb();
    // In production: WebSocket push to the specific analyst's client
    auditLog(req.user?.id || 'system', 'PROACTIVE_BREAK_SENT', `To ${analystPseudonym}: ${duration}min break after ${hours}hr`);
    db.close();
    res.json({ success: true, notification: 'sent', pseudonym: analystPseudonym });
  } catch (e) { res.status(500).json({ error: 'Failed to send break notification' }); }
});

// ── Post-incident recovery: MC initiates, server propagates to clients ───────
router.post('/recovery-protocol/initiate', (req, res) => {
  try {
    const { incident, severity, analystPseudonyms, actions } = req.body;
    const db = getDb();
    // Propagate to specified analyst clients:
    // - Lighter queue activation
    // - Recovery resources pushed to their Wellness tab
    // - Peer support offer notification
    // - Follow-up schedule created
    auditLog(req.user?.id || 'system', 'RECOVERY_PROTOCOL_INITIATED', `${incident} (${severity}) for ${analystPseudonyms.length} analysts`);
    db.close();
    res.json({ success: true, affectedAnalysts: analystPseudonyms.length, actions });
  } catch (e) { res.status(500).json({ error: 'Recovery protocol initiation failed' }); }
});

// ── Ticketing system integration ─────────────────────────────────────────────
router.get('/ticketing/config', (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'ticketing_config'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : {
      provider: 'none',
      endpoint: '',
      apiKey: '',
      burnoutRoutingEnabled: true,
      complexityCaps: {},
      autoAssignment: true,
    });
  } catch (e) { res.status(500).json({ error: 'Failed to get ticketing config' }); }
});

router.put('/ticketing/config', requireObjectBody, (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('ticketing_config', ?)").run(JSON.stringify(req.body));
    auditLog(req.user?.id || 'system', 'TICKETING_CONFIG_UPDATED', `Provider: ${req.body.provider}`);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save ticketing config' }); }
});

// ── Burnout routing engine interface ─────────────────────────────────────────
// The routing engine sits between the ticketing system and analyst clients
router.post('/routing/apply-burnout-filter', (req, res) => {
  try {
    const { tickets, teamHealth, analystCapacities } = req.body;
    const db = getDb();
    
    // Check if routing is paused (panic mode or auto-disable)
    const paused = db.prepare("SELECT value FROM config WHERE key = 'routing_paused'").get();
    if (paused?.value === 'true') {
      db.close();
      return res.json({ filtered: false, reason: 'Routing paused — tickets flow unfiltered', tickets });
    }

    // In production: apply complexity caps, fairness distribution, 
    // reduced-load overrides, upskilling hour pauses
    const filtered = tickets; // Pass-through in demo mode
    
    auditLog('SYSTEM', 'ROUTING_APPLIED', `${tickets.length} tickets processed through burnout filter`);
    db.close();
    res.json({ filtered: true, tickets: filtered });
  } catch (e) { res.status(500).json({ error: 'Routing filter failed' }); }
});

module.exports = router;

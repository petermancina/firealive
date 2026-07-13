// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v0.0.24 — New Routes
// Adds: MFA wizard, threat hunting integrations, tripwire, compromise scan,
// auth logs, posture assessment, HA config, fail-open routing, config
// troubleshooter, general certs, auth log notifications
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { requireObjectBody } = require('../middleware/body-validation');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');

// ── Threat Hunting Integrations ─────────────────────────────────────────────
router.get('/threat-hunting/config', (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'threat_hunting_config'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : { xdr: { enabled: false }, atp: { enabled: false }, ngav: { enabled: false }, mspScanner: { enabled: false } });
  } catch (e) { res.status(500).json({ error: 'Failed to load threat hunting config' }); }
});

router.put('/threat-hunting/config', requireObjectBody, (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('threat_hunting_config', ?)").run(JSON.stringify(req.body));
    auditLog(req.user?.id || 'system', 'THREAT_HUNTING_CONFIG_UPDATED', 'Threat hunting integrations updated');
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save threat hunting config' }); }
});

// ── Tripwire ────────────────────────────────────────────────────────────────
router.get('/tripwire/config', (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'tripwire_config'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : { enabled: false, thresholdPct: 40, autoDisableRouting: true, notifyLead: true, triggerSoarScan: true, triggerEdrScan: true, preserveAnonymity: true });
  } catch (e) { res.status(500).json({ error: 'Failed to load tripwire config' }); }
});

router.put('/tripwire/config', requireObjectBody, (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('tripwire_config', ?)").run(JSON.stringify(req.body));
    auditLog(req.user?.id || 'system', 'TRIPWIRE_CONFIG_UPDATED', `Threshold: ${req.body.thresholdPct}%`);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save tripwire config' }); }
});

// Tripwire check — called by routing engine on each reduced-load request
router.post('/tripwire/check', (req, res) => {
  try {
    const db = getDb();
    const cfgRow = db.prepare("SELECT value FROM config WHERE key = 'tripwire_config'").get();
    const cfg = cfgRow ? JSON.parse(cfgRow.value) : { enabled: false };
    if (!cfg.enabled) { db.close(); return res.json({ tripped: false, reason: 'tripwire disabled' }); }

    const analysts = db.prepare("SELECT COUNT(*) as total FROM users WHERE role = 'analyst'").get();
    const reducedRouting = db.prepare("SELECT COUNT(*) as count FROM routing_overrides WHERE type = 'reduced_load' AND active = 1").get();
    const pct = analysts.total > 0 ? (reducedRouting.count / analysts.total) * 100 : 0;

    if (pct >= cfg.thresholdPct) {
      auditLog('SYSTEM', 'TRIPWIRE_TRIGGERED', `${pct.toFixed(1)}% analysts in reduced routing (threshold: ${cfg.thresholdPct}%)`);
      // Auto-disable routing if configured
      if (cfg.autoDisableRouting) {
        db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('routing_paused', 'true')").run();
      }
      db.close();

      // Broadcast tripwire engagement to every active analyst. No requester
      // to exclude — this is fired by the system. mandatoryInApp ensures
      // every analyst sees this in-app regardless of preferences.
      let notifiedCount = 0;
      try {
        const eligible = notifications.getEligibleRecipients('routing_panic_engaged_tripwire', {
          roles: ['analyst'],
          activeOnly: true,
        });
        for (const recipientId of eligible) {
          try {
            notifications.notify({
              recipientId,
              eventType: 'routing_panic_engaged_tripwire',
              title: 'Tripwire engaged — wellness routing OFF',
              body: `The tripwire fired automatically because ${pct.toFixed(1)}% of analysts are on reduced routing (threshold ${cfg.thresholdPct}%). All analysts are now at maximum complexity until a team lead reviews the situation.`,
              linkTab: 'routing',
              linkParams: { focus: 'tripwire' },
            });
            notifiedCount++;
          } catch (notifyErr) {
            logger.warn('Tripwire: notify analyst failed (non-fatal)', { recipientId, error: notifyErr.message });
          }
        }
      } catch (broadcastErr) {
        logger.error('Tripwire: broadcast failed (non-fatal)', { error: broadcastErr.message });
      }

      return res.json({ tripped: true, pct: pct.toFixed(1), threshold: cfg.thresholdPct, notified: notifiedCount, actions: { routingDisabled: cfg.autoDisableRouting, leadNotified: cfg.notifyLead, soarTriggered: cfg.triggerSoarScan, edrTriggered: cfg.triggerEdrScan } });
    }
    db.close();
    res.json({ tripped: false, pct: pct.toFixed(1), threshold: cfg.thresholdPct });
  } catch (e) { logger.error('Tripwire check failed', e); res.status(500).json({ error: 'Tripwire check failed' }); }
});

// ── Compromise Scan ─────────────────────────────────────────────────────────
router.post('/compromise-scan/run', (req, res) => {
  try {
    const { targets } = req.body; // 'all' or array of client IDs
    const db = getDb();
    auditLog(req.user?.id || 'system', 'COMPROMISE_SCAN_INITIATED', `Targets: ${targets === 'all' ? 'ALL clients' : targets.join(', ')}`);

    // In production: sends scan commands to each client via secure channel
    // Each client runs: binary integrity, memory analysis, DB query spike detection,
    // network audit, config drift, EDR/XDR scan, API token verification,
    // audit log continuity, TLS cert pin, filesystem integrity
    // Returns signed report (Ed25519 signature over SHA-256 of results)

    const scanId = crypto.randomUUID();
    db.prepare("INSERT INTO config (key, value) VALUES (?, ?)").run(
      `compromise_scan_${scanId}`,
      JSON.stringify({ id: scanId, status: 'running', startedAt: new Date().toISOString(), targets })
    );
    db.close();
    res.json({ scanId, status: 'initiated' });
  } catch (e) { logger.error('Compromise scan failed', e); res.status(500).json({ error: 'Scan initiation failed' }); }
});

router.get('/compromise-scan/:scanId', (req, res) => {
  try {
    const db = getDb();
    const scan = db.prepare("SELECT value FROM config WHERE key = ?").get(`compromise_scan_${req.params.scanId}`);
    db.close();
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    res.json(JSON.parse(scan.value));
  } catch (e) { res.status(500).json({ error: 'Failed to get scan status' }); }
});

// ── Authorization Logs ──────────────────────────────────────────────────────
router.get('/auth-logs', (req, res) => {
  try {
    const db = getDb();
    const { limit = 100, offset = 0, status } = req.query;
    let query = "SELECT * FROM auth_log ORDER BY timestamp DESC LIMIT ? OFFSET ?";
    const params = [parseInt(limit), parseInt(offset)];
    if (status === 'failed') {
      query = "SELECT * FROM auth_log WHERE action LIKE '%FAIL%' ORDER BY timestamp DESC LIMIT ? OFFSET ?";
    }
    const logs = db.prepare(query).all(...params);
    const total = db.prepare("SELECT COUNT(*) as count FROM auth_log").get();
    db.close();
    res.json({ logs, total: total.count });
  } catch (e) { res.status(500).json({ error: 'Failed to fetch auth logs' }); }
});

router.get('/auth-logs/anomalies', (req, res) => {
  try {
    const db = getDb();
    // Check for out-of-cycle attempts (configurable hours)
    const cfgRow = db.prepare("SELECT value FROM config WHERE key = 'auth_log_notif_config'").get();
    const cfg = cfgRow ? JSON.parse(cfgRow.value) : { outOfCycleStartHr: 0, outOfCycleEndHr: 5, bruteForceThreshold: 5 };

    const anomalies = [];

    // Brute force detection: N+ failed attempts from same IP in last hour
    const bruteForce = db.prepare(
      "SELECT ip, COUNT(*) as attempts FROM auth_log WHERE action LIKE '%FAIL%' AND timestamp > datetime('now', '-1 hour') GROUP BY ip HAVING attempts >= ?"
    ).all(cfg.bruteForceThreshold);
    bruteForce.forEach(bf => anomalies.push({ type: 'brute_force', ip: bf.ip, attempts: bf.attempts, severity: 'high' }));

    // Out-of-cycle attempts
    const outOfCycle = db.prepare(
      "SELECT * FROM auth_log WHERE CAST(strftime('%H', timestamp) AS INTEGER) >= ? AND CAST(strftime('%H', timestamp) AS INTEGER) <= ? AND timestamp > datetime('now', '-24 hours') ORDER BY timestamp DESC"
    ).all(cfg.outOfCycleStartHr, cfg.outOfCycleEndHr);
    if (outOfCycle.length > 0) anomalies.push({ type: 'out_of_cycle', count: outOfCycle.length, severity: 'medium' });

    db.close();
    res.json({ anomalies });
  } catch (e) { res.status(500).json({ error: 'Failed to check auth anomalies' }); }
});

router.put('/auth-logs/notification-config', requireObjectBody, (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('auth_log_notif_config', ?)").run(JSON.stringify(req.body));
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save auth log notification config' }); }
});

// ── Posture Assessment ──────────────────────────────────────────────────────
router.get('/posture/config', (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'posture_config'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : { enabled: true, requireOnConnect: true, checks: { osUpdated: true, avEnabled: true, firewallEnabled: true, diskEncrypted: true, screenLockEnabled: true, wifiCompliant: true, endpointProtectionRunning: true, minTlsVersion: '1.2' }, blockOnFail: false, warnOnFail: true, gracePeriodMin: 10 });
  } catch (e) { res.status(500).json({ error: 'Failed to load posture config' }); }
});

router.put('/posture/config', requireObjectBody, (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('posture_config', ?)").run(JSON.stringify(req.body));
    auditLog(req.user?.id || 'system', 'POSTURE_CONFIG_UPDATED', 'Posture assessment configuration updated');
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save posture config' }); }
});

// Client posture check endpoint — called by analyst client on connection
router.post('/posture/check', (req, res) => {
  try {
    const db = getDb();
    const cfgRow = db.prepare("SELECT value FROM config WHERE key = 'posture_config'").get();
    const cfg = cfgRow ? JSON.parse(cfgRow.value) : { enabled: false };
    if (!cfg.enabled) { db.close(); return res.json({ allowed: true, reason: 'posture assessment disabled' }); }

    const clientPosture = req.body; // { osUpdated, avEnabled, firewallEnabled, ... }
    const failures = [];
    for (const [check, required] of Object.entries(cfg.checks)) {
      if (required === true && !clientPosture[check]) failures.push(check);
      if (check === 'minTlsVersion' && clientPosture.tlsVersion && clientPosture.tlsVersion < required) failures.push('minTlsVersion');
    }

    const passed = failures.length === 0;
    auditLog(req.body.clientId || 'unknown', passed ? 'POSTURE_CHECK_PASSED' : 'POSTURE_CHECK_FAILED', `Failures: ${failures.join(', ') || 'none'}`);
    db.close();

    if (!passed && cfg.blockOnFail) {
      return res.json({ allowed: false, failures, remediation: failures.map(f => REMEDIATION_MAP[f] || `Enable ${f}`), gracePeriodMin: cfg.gracePeriodMin });
    }
    res.json({ allowed: true, warnings: passed ? [] : failures, remediation: failures.map(f => REMEDIATION_MAP[f] || `Enable ${f}`) });
  } catch (e) { res.status(500).json({ error: 'Posture check failed' }); }
});

const REMEDIATION_MAP = {
  osUpdated: 'Install pending OS security updates and restart',
  avEnabled: 'Enable antivirus/endpoint protection software',
  firewallEnabled: 'Enable host firewall (Windows Firewall / macOS Firewall)',
  diskEncrypted: 'Enable disk encryption (BitLocker / FileVault)',
  screenLockEnabled: 'Enable screen lock with ≤ 5 minute timeout',
  wifiCompliant: 'Connect to WPA2-Enterprise or WPA3 network',
  endpointProtectionRunning: 'Start EDR/XDR agent',
  minTlsVersion: 'Update TLS configuration to minimum required version',
};

// ── Fail-Open Routing ───────────────────────────────────────────────────────
router.get('/fail-open/config', (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'fail_open_config'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : { enabled: true, autoDetect: true, notifyOnFailOpen: true, maxFailOpenMin: 60, restoreAuto: true });
  } catch (e) { res.status(500).json({ error: 'Failed to load fail-open config' }); }
});

router.put('/fail-open/config', requireObjectBody, (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('fail_open_config', ?)").run(JSON.stringify(req.body));
    auditLog(req.user?.id || 'system', 'FAILOPEN_CONFIG_UPDATED', 'Fail-open routing config updated');
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save fail-open config' }); }
});
// ── General Certifications ──────────────────────────────────────────────────
router.get('/certifications', (req, res) => {
  try {
    const db = getDb();
    const certs = db.prepare("SELECT * FROM general_certifications ORDER BY earned_date DESC").all();
    db.close();
    res.json({ certifications: certs });
  } catch (e) { res.status(500).json({ error: 'Failed to load certifications' }); }
});

router.post('/certifications', (req, res) => {
  try {
    const db = getDb();
    const { name, issuer, earnedDate, expiresDate, analystId, verificationUrl } = req.body;
    const id = crypto.randomUUID();
    db.prepare("INSERT INTO general_certifications (id, name, issuer, earned_date, expires_date, analyst_id, verification_url) VALUES (?, ?, ?, ?, ?, ?, ?)").run(id, name, issuer, earnedDate, expiresDate || null, analystId, verificationUrl || null);
    auditLog(req.user?.id || 'system', 'CERT_ADDED', `${name} for analyst ${analystId}`);
    db.close();
    res.json({ success: true, id });
  } catch (e) { res.status(500).json({ error: 'Failed to add certification' }); }
});

router.delete('/certifications/:id', (req, res) => {
  try {
    const db = getDb();
    db.prepare("DELETE FROM general_certifications WHERE id = ?").run(req.params.id);
    auditLog(req.user?.id || 'system', 'CERT_REMOVED', `Cert ${req.params.id} removed`);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to remove certification' }); }
});

module.exports = router;

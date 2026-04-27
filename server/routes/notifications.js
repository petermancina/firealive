// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Notifications Routes
// GET  /api/notifications/config     — get notification config
// PUT  /api/notifications/config     — update notification config
// POST /api/notifications/test       — send test notification
// GET  /api/notifications/history    — notification delivery history
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── Get Config ───────────────────────────────────────────────────────────────
router.get('/config', (req, res) => {
  try {
    const db = getDb();
    const config = db.prepare('SELECT * FROM notification_config WHERE id = ?').get('default');
    db.close();

    if (!config) return res.json(defaultConfig());

    // Redact sensitive values
    const safe = { ...config };
    if (safe.webhook_url) safe.webhook_url = safe.webhook_url.slice(0, 30) + '••••';
    if (safe.pagerduty_key) safe.pagerduty_key = safe.pagerduty_key.slice(0, 8) + '••••';

    res.json(safe);
  } catch (err) {
    logger.error('Get notification config error', { error: err.message });
    res.status(500).json({ error: 'Failed to get notification config' });
  }
});

// ── Update Config ────────────────────────────────────────────────────────────
router.put('/config', (req, res) => {
  const {
    threshold, emailEnabled, emailAddress,
    smsEnabled, smsNumber,
    webhookEnabled, webhookUrl,
    pagerdutyEnabled, pagerdutyKey,
  } = req.body;

  // Validate threshold
  const validThresholds = ['watch', 'stressed', 'critical'];
  const safeThreshold = validThresholds.includes(threshold) ? threshold : 'watch';

  // Validate email format (basic)
  if (emailEnabled && emailAddress && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailAddress)) {
    return res.status(400).json({ error: 'Invalid email address format' });
  }

  // Validate webhook URL
  if (webhookEnabled && webhookUrl && !/^https?:\/\/.+/.test(webhookUrl)) {
    return res.status(400).json({ error: 'Webhook URL must start with http:// or https://' });
  }

  try {
    const db = getDb();
    db.prepare(`
      INSERT OR REPLACE INTO notification_config 
        (id, threshold, email_enabled, email_address, sms_enabled, sms_number,
         webhook_enabled, webhook_url, pagerduty_enabled, pagerduty_key, updated_by)
      VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      safeThreshold,
      emailEnabled ? 1 : 0, (emailAddress || '').slice(0, 256),
      smsEnabled ? 1 : 0, (smsNumber || '').slice(0, 20),
      webhookEnabled ? 1 : 0, (webhookUrl || '').slice(0, 512),
      pagerdutyEnabled ? 1 : 0, (pagerdutyKey || '').slice(0, 64),
      req.user.id
    );
    db.close();

    auditLog(req.user.id, 'NOTIFICATION_CONFIG_UPDATED', `threshold=${safeThreshold}`, req.ip);
    res.json({ ok: true, threshold: safeThreshold });
  } catch (err) {
    logger.error('Update notification config error', { error: err.message });
    res.status(500).json({ error: 'Failed to update notification config' });
  }
});

// ── Test Notification ────────────────────────────────────────────────────────
router.post('/test', (req, res) => {
  try {
    const db = getDb();
    const config = db.prepare('SELECT * FROM notification_config WHERE id = ?').get('default');
    db.close();

    if (!config) return res.status(400).json({ error: 'No notification config found — configure first' });

    const results = [];

    // In production, these would make actual HTTP/SMTP/SMS calls
    if (config.email_enabled && config.email_address) {
      results.push({ channel: 'email', target: config.email_address, status: 'simulated_ok', message: 'Test email would be sent' });
    }
    if (config.sms_enabled && config.sms_number) {
      results.push({ channel: 'sms', target: config.sms_number, status: 'simulated_ok', message: 'Test SMS would be sent' });
    }
    if (config.webhook_enabled && config.webhook_url) {
      results.push({ channel: 'webhook', target: config.webhook_url.slice(0, 30) + '…', status: 'simulated_ok', message: 'Test webhook payload would be POST-ed' });
    }
    if (config.pagerduty_enabled && config.pagerduty_key) {
      results.push({ channel: 'pagerduty', target: 'events API', status: 'simulated_ok', message: 'Test PagerDuty event would be sent' });
    }

    if (results.length === 0) {
      return res.json({ message: 'No notification channels enabled' });
    }

    auditLog(req.user.id, 'NOTIFICATION_TEST', `channels=${results.map(r => r.channel).join(',')}`, req.ip);
    res.json({ results });
  } catch (err) {
    logger.error('Test notification error', { error: err.message });
    res.status(500).json({ error: 'Failed to test notifications' });
  }
});

// ── Notification History ─────────────────────────────────────────────────────
router.get('/history', (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const db = getDb();
    // Pull notification-related audit events as history
    const events = db.prepare(`
      SELECT id, timestamp, event_type, detail, user_id
      FROM audit_log
      WHERE event_type LIKE 'NOTIFICATION%' OR event_type LIKE 'ALERT%'
      ORDER BY timestamp DESC LIMIT ?
    `).all(Math.min(parseInt(limit, 10) || 50, 200));
    db.close();
    res.json({ events });
  } catch (err) {
    logger.error('Notification history error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch notification history' });
  }
});

function defaultConfig() {
  return {
    id: 'default', threshold: 'watch',
    email_enabled: 0, email_address: '',
    sms_enabled: 0, sms_number: '',
    webhook_enabled: 0, webhook_url: '',
    pagerduty_enabled: 0, pagerduty_key: '',
  };
}

module.exports = router;

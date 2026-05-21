// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Notifications Routes
// GET  /api/notifications/config     — get notification config
// PUT  /api/notifications/config     — update notification config
// POST /api/notifications/test       — send test notification
// GET  /api/notifications/history    — notification delivery history
//
// R3n introduces SOC-grade sensitive-field handling for webhook_url and
// pagerduty_key:
//   - GET /config strips the actual values of webhook_url and pagerduty_key
//     entirely from the response (no slice(0,30)+'••••' leak); surfaces
//     presence-metadata via webhook_url_present + pagerduty_key_present
//     booleans so the MC can render "Configured ✓" + "Change Secret"
//     affordances
//   - PUT /config merges sensitive fields via omission-rule: keys absent
//     from the incoming body are preserved from existing config; keys
//     present with non-empty strings take precedence; keys present with
//     empty strings clear the existing value
//   - Per-field audit markers MC_NOTIFICATION_SECRET_PRESERVED / _CHANGED /
//     _CLEARED for fine-grained threat-hunting visibility (field names
//     logged; values NEVER logged)
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

    if (!config) {
      const defaults = defaultConfig();
      return res.json({
        ...defaults,
        webhook_url_present: false,
        pagerduty_key_present: false,
      });
    }

    // SOC-grade: strip sensitive values entirely (no slice(0,N)+'••••' leak).
    // Surface presence-metadata so the MC can render "Configured ✓" +
    // "Change Secret" affordances per field.
    const safe = { ...config };
    const webhookPresent = !!safe.webhook_url && safe.webhook_url !== '';
    const pagerdutyPresent = !!safe.pagerduty_key && safe.pagerduty_key !== '';
    safe.webhook_url = '';
    safe.pagerduty_key = '';

    res.json({
      ...safe,
      webhook_url_present: webhookPresent,
      pagerduty_key_present: pagerdutyPresent,
    });
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
    webhookEnabled, pagerdutyEnabled,
  } = req.body;

  // Sensitive fields: distinguish "key present in body" from "key absent".
  // Absent means "preserve existing"; present (even empty string) means
  // explicit operator intent (change or clear). The MC frontend OMITS these
  // keys from PUT body unless the lead clicks "Change Secret".
  const webhookUrlProvided = 'webhookUrl' in req.body;
  const pagerdutyKeyProvided = 'pagerdutyKey' in req.body;
  const webhookUrl = req.body.webhookUrl;
  const pagerdutyKey = req.body.pagerdutyKey;

  // Validate threshold
  const validThresholds = ['watch', 'stressed', 'critical'];
  const safeThreshold = validThresholds.includes(threshold) ? threshold : 'watch';

  // Validate email format (basic)
  if (emailEnabled && emailAddress && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailAddress)) {
    return res.status(400).json({ error: 'Invalid email address format' });
  }

  // Validate webhook URL only when caller is explicitly setting a new value
  if (webhookEnabled && webhookUrlProvided && webhookUrl && !/^https?:\/\/.+/.test(webhookUrl)) {
    return res.status(400).json({ error: 'Webhook URL must start with http:// or https://' });
  }

  try {
    const db = getDb();

    // Fetch existing config (if any) to merge sensitive fields by omission rule
    const existing = db.prepare('SELECT * FROM notification_config WHERE id = ?').get('default');

    let resolvedWebhookUrl;
    let webhookSecretAction = null;
    if (!webhookUrlProvided) {
      resolvedWebhookUrl = existing ? (existing.webhook_url || '') : '';
      if (existing && existing.webhook_url) webhookSecretAction = 'preserved';
    } else if (webhookUrl === '' || webhookUrl == null) {
      resolvedWebhookUrl = '';
      if (existing && existing.webhook_url) webhookSecretAction = 'cleared';
    } else {
      resolvedWebhookUrl = webhookUrl;
      webhookSecretAction = (existing && existing.webhook_url === webhookUrl) ? null : 'changed';
    }

    let resolvedPagerdutyKey;
    let pagerdutySecretAction = null;
    if (!pagerdutyKeyProvided) {
      resolvedPagerdutyKey = existing ? (existing.pagerduty_key || '') : '';
      if (existing && existing.pagerduty_key) pagerdutySecretAction = 'preserved';
    } else if (pagerdutyKey === '' || pagerdutyKey == null) {
      resolvedPagerdutyKey = '';
      if (existing && existing.pagerduty_key) pagerdutySecretAction = 'cleared';
    } else {
      resolvedPagerdutyKey = pagerdutyKey;
      pagerdutySecretAction = (existing && existing.pagerduty_key === pagerdutyKey) ? null : 'changed';
    }

    db.prepare(`
      INSERT OR REPLACE INTO notification_config 
        (id, threshold, email_enabled, email_address, sms_enabled, sms_number,
         webhook_enabled, webhook_url, pagerduty_enabled, pagerduty_key, updated_by)
      VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      safeThreshold,
      emailEnabled ? 1 : 0, (emailAddress || '').slice(0, 256),
      smsEnabled ? 1 : 0, (smsNumber || '').slice(0, 20),
      webhookEnabled ? 1 : 0, resolvedWebhookUrl.slice(0, 512),
      pagerdutyEnabled ? 1 : 0, resolvedPagerdutyKey.slice(0, 64),
      req.user.id
    );
    db.close();

    // Overall save marker (unchanged from R3j)
    auditLog(req.user.id, 'NOTIFICATION_CONFIG_UPDATED', `threshold=${safeThreshold}`, req.ip);

    // Per-field SOC-grade audit markers (field names logged; VALUES never)
    if (webhookSecretAction === 'preserved') auditLog(req.user.id, 'MC_NOTIFICATION_SECRET_PRESERVED', 'field=webhook_url', req.ip);
    else if (webhookSecretAction === 'changed') auditLog(req.user.id, 'MC_NOTIFICATION_SECRET_CHANGED', 'field=webhook_url', req.ip);
    else if (webhookSecretAction === 'cleared') auditLog(req.user.id, 'MC_NOTIFICATION_SECRET_CLEARED', 'field=webhook_url', req.ip);

    if (pagerdutySecretAction === 'preserved') auditLog(req.user.id, 'MC_NOTIFICATION_SECRET_PRESERVED', 'field=pagerduty_key', req.ip);
    else if (pagerdutySecretAction === 'changed') auditLog(req.user.id, 'MC_NOTIFICATION_SECRET_CHANGED', 'field=pagerduty_key', req.ip);
    else if (pagerdutySecretAction === 'cleared') auditLog(req.user.id, 'MC_NOTIFICATION_SECRET_CLEARED', 'field=pagerduty_key', req.ip);

    res.json({
      ok: true,
      threshold: safeThreshold,
      webhookSecretAction,
      pagerdutySecretAction,
    });
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
      results.push({ channel: 'webhook', target: 'configured webhook URL', status: 'simulated_ok', message: 'Test webhook payload would be POST-ed' });
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

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Notifications Routes
// GET  /api/notifications/config     — get notification config
// PUT  /api/notifications/config     — update notification config
// POST /api/notifications/test       — send simulated test for all configured channels
// POST /api/notifications/sms/test   — send REAL test SMS to caller's registered phone (N1a C22)
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
//
// N1a C22 extends both GET and PUT for the SMS provider config columns
// added in N1a C1 (sms_provider, sms_account_sid, sms_auth_token_encrypted,
// sms_from_number). The sms_auth_token is encrypted at rest via TIER1_
// ENCRYPTION_KEY and follows the same sensitive-field handling as
// webhook_url + pagerduty_key. The new POST /sms/test endpoint dispatches
// a real test SMS to the caller's registered phone (from lead_notification_
// contacts table), rate-limited to 3 attempts per minute per user, with
// MC_SMS_TEST_SENT / _FAILED audit events.
//
// CRITICAL REGRESSION FIX (N1a C22):
// The pre-N1a PUT /config INSERT OR REPLACE clause did NOT include the
// SMS provider columns (introduced post-pre-N1a in C1 migration). Any
// PUT call would silently wipe those columns. C22's PUT now includes the
// SMS provider columns in the INSERT OR REPLACE with omission-rule merge
// preserving them when the caller doesn't explicitly modify them.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { sealTier1, openTier1 } = require('../services/tier1-seal');

// N1a C22: in-memory rate limiter for /sms/test. Sliding 60s window, 3 attempts
// per user. Cleared on server restart; production deployments behind a load
// balancer would need a shared store (Redis), but for single-instance
// deployments at v1.0.41, in-memory suffices.
const SMS_TEST_RATE_LIMIT_WINDOW_MS = 60_000;
const SMS_TEST_RATE_LIMIT_MAX = 3;
const _smsTestAttempts = new Map(); // userId -> array of attempt timestamps

function checkSmsTestRateLimit(userId) {
  const now = Date.now();
  const cutoff = now - SMS_TEST_RATE_LIMIT_WINDOW_MS;
  let attempts = _smsTestAttempts.get(userId) || [];
  attempts = attempts.filter(t => t > cutoff);
  if (attempts.length >= SMS_TEST_RATE_LIMIT_MAX) {
    return { allowed: false, retryAfterMs: attempts[0] + SMS_TEST_RATE_LIMIT_WINDOW_MS - now };
  }
  attempts.push(now);
  _smsTestAttempts.set(userId, attempts);
  return { allowed: true };
}

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
    //
    // N1a C22: extends the pattern to sms_auth_token_encrypted (BLOB; never
    // returned to clients) — surfaces sms_auth_token_present boolean. The
    // other SMS provider fields (sms_provider, sms_account_sid, sms_from_number)
    // are NOT sensitive credentials and pass through plainly so the UI can
    // render the current selection.
    const safe = { ...config };
    const webhookPresent = !!safe.webhook_url && safe.webhook_url !== '';
    const pagerdutyPresent = !!safe.pagerduty_key && safe.pagerduty_key !== '';
    const smsAuthTokenPresent = !!safe.sms_auth_token_encrypted;
    safe.webhook_url = '';
    safe.pagerduty_key = '';
    delete safe.sms_auth_token_encrypted;

    res.json({
      ...safe,
      webhook_url_present: webhookPresent,
      pagerduty_key_present: pagerdutyPresent,
      sms_auth_token_present: smsAuthTokenPresent,
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
    // N1a C22: SMS provider config fields (non-sensitive)
    smsProvider, smsAccountSid, smsFromNumber,
  } = req.body;

  // Sensitive fields: distinguish "key present in body" from "key absent".
  // Absent means "preserve existing"; present (even empty string) means
  // explicit operator intent (change or clear). The MC frontend OMITS these
  // keys from PUT body unless the lead clicks "Change Secret".
  const webhookUrlProvided = 'webhookUrl' in req.body;
  const pagerdutyKeyProvided = 'pagerdutyKey' in req.body;
  const webhookUrl = req.body.webhookUrl;
  const pagerdutyKey = req.body.pagerdutyKey;
  // N1a C22: SMS auth token follows the same sensitive-field handling pattern
  const smsAuthTokenProvided = 'smsAuthToken' in req.body;
  const smsAuthToken = req.body.smsAuthToken;
  // N1a C22: distinguish SMS provider field presence too — absence means
  // preserve existing, presence means explicit caller intent
  const smsProviderProvided = 'smsProvider' in req.body;
  const smsAccountSidProvided = 'smsAccountSid' in req.body;
  const smsFromNumberProvided = 'smsFromNumber' in req.body;

  // Validate threshold
  const validThresholds = ['watch', 'stressed', 'critical'];
  const safeThreshold = validThresholds.includes(threshold) ? threshold : 'watch';

  // Validate email format (basic)
  if (emailEnabled && emailAddress && !/^[^\s@]+@[^\s.@]+(?:\.[^\s.@]+)+$/.test(emailAddress)) {
    return res.status(400).json({ error: 'Invalid email address format' });
  }

  // Validate webhook URL only when caller is explicitly setting a new value
  if (webhookEnabled && webhookUrlProvided && webhookUrl && !/^https?:\/\/.+/.test(webhookUrl)) {
    return res.status(400).json({ error: 'Webhook URL must start with http:// or https://' });
  }

  // N1a C22: Validate SMS provider when caller is explicitly setting one
  if (smsProviderProvided && smsProvider != null && smsProvider !== '' && !['twilio', 'aws_sns'].includes(smsProvider)) {
    return res.status(400).json({ error: "SMS provider must be 'twilio' or 'aws_sns'" });
  }
  // N1a C22: Validate SMS from-number (E.164) when caller is explicitly setting one for Twilio
  if (smsFromNumberProvided && smsFromNumber != null && smsFromNumber !== '' && !/^\+[1-9]\d{1,14}$/.test(smsFromNumber)) {
    return res.status(400).json({ error: 'SMS from-number must be in E.164 format (e.g., +15551234567)' });
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

    // N1a C22: resolve SMS provider non-sensitive fields with omission rule
    const resolvedSmsProvider = smsProviderProvided
      ? (smsProvider || null)
      : (existing ? (existing.sms_provider || null) : null);
    const resolvedSmsAccountSid = smsAccountSidProvided
      ? ((smsAccountSid || '').slice(0, 256) || null)
      : (existing ? (existing.sms_account_sid || null) : null);
    const resolvedSmsFromNumber = smsFromNumberProvided
      ? ((smsFromNumber || '').slice(0, 20) || null)
      : (existing ? (existing.sms_from_number || null) : null);

    // N1a C22: resolve SMS auth token (sensitive — same omission-rule pattern
    // as webhook_url / pagerduty_key). The stored value is AES-256-GCM
    // encrypted via TIER1_ENCRYPTION_KEY; preserved as-is on omission;
    // encrypted on change; nulled on explicit clear.
    let resolvedSmsAuthTokenEncrypted;
    let smsAuthTokenAction = null;
    if (!smsAuthTokenProvided) {
      resolvedSmsAuthTokenEncrypted = existing ? (existing.sms_auth_token_encrypted || null) : null;
      if (existing && existing.sms_auth_token_encrypted) smsAuthTokenAction = 'preserved';
    } else if (smsAuthToken === '' || smsAuthToken == null) {
      resolvedSmsAuthTokenEncrypted = null;
      if (existing && existing.sms_auth_token_encrypted) smsAuthTokenAction = 'cleared';
    } else {
      try {
        resolvedSmsAuthTokenEncrypted = sealTier1('notification_config.sms_auth_token_encrypted', smsAuthToken);
        smsAuthTokenAction = 'changed';
      } catch (encErr) {
        db.close();
        logger.error('SMS auth token encrypt error', { error: encErr.message });
        return res.status(500).json({ error: 'Failed to encrypt SMS auth token — check TIER1_ENCRYPTION_KEY env' });
      }
    }

    db.prepare(`
      INSERT OR REPLACE INTO notification_config 
        (id, threshold, email_enabled, email_address, sms_enabled, sms_number,
         webhook_enabled, webhook_url, pagerduty_enabled, pagerduty_key,
         sms_provider, sms_account_sid, sms_auth_token_encrypted, sms_from_number,
         updated_by)
      VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      safeThreshold,
      emailEnabled ? 1 : 0, (emailAddress || '').slice(0, 256),
      smsEnabled ? 1 : 0, (smsNumber || '').slice(0, 20),
      webhookEnabled ? 1 : 0, resolvedWebhookUrl.slice(0, 512),
      pagerdutyEnabled ? 1 : 0, resolvedPagerdutyKey.slice(0, 64),
      resolvedSmsProvider, resolvedSmsAccountSid, resolvedSmsAuthTokenEncrypted, resolvedSmsFromNumber,
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

    // N1a C22: per-field audit for sms_auth_token
    if (smsAuthTokenAction === 'preserved') auditLog(req.user.id, 'MC_NOTIFICATION_SECRET_PRESERVED', 'field=sms_auth_token', req.ip);
    else if (smsAuthTokenAction === 'changed') auditLog(req.user.id, 'MC_NOTIFICATION_SECRET_CHANGED', 'field=sms_auth_token', req.ip);
    else if (smsAuthTokenAction === 'cleared') auditLog(req.user.id, 'MC_NOTIFICATION_SECRET_CLEARED', 'field=sms_auth_token', req.ip);

    // N1a C22: SMS provider config change audit (non-sensitive fields)
    if (smsProviderProvided || smsAccountSidProvided || smsFromNumberProvided) {
      auditLog(req.user.id, 'MC_SMS_PROVIDER_CONFIGURED',
        `provider=${resolvedSmsProvider || 'null'} account_sid_set=${!!resolvedSmsAccountSid} from_number_set=${!!resolvedSmsFromNumber}`,
        req.ip);
    }

    res.json({
      ok: true,
      threshold: safeThreshold,
      webhookSecretAction,
      pagerdutySecretAction,
      smsAuthTokenAction,
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

// ── N1a C22: Test SMS Dispatch ───────────────────────────────────────────────
// POST /api/notifications/sms/test — sends a REAL test SMS to the caller's
// registered phone number (from lead_notification_contacts table, N1a C6 +
// C19). Rate-limited to 3 attempts per minute per user (in-memory sliding
// window). The caller must be lead/admin role (analyst-role users
// have no row in lead_notification_contacts by design, so the lookup fails
// with LEAD_PHONE_NOT_REGISTERED — defense-in-depth on top of any future
// middleware-level role enforcement).
//
// Distinct from POST /test (the existing simulated-all-channels test).
// /sms/test is a real provider call — Twilio or AWS SNS — and consumes the
// caller's provider quota / billing. Failures (provider misconfiguration,
// missing phone, dispatch error) return structured 422 / 503 responses so
// the UI can render appropriate error messages.
router.post('/sms/test', async (req, res) => {
  try {
    const userId = req.user && req.user.id;
    if (!userId) return res.status(401).json({ error: 'Authentication required' });

    // Rate limit check
    const rateCheck = checkSmsTestRateLimit(userId);
    if (!rateCheck.allowed) {
      const retrySec = Math.ceil(rateCheck.retryAfterMs / 1000);
      res.set('Retry-After', String(retrySec));
      return res.status(429).json({
        error: `Rate limit exceeded: max ${SMS_TEST_RATE_LIMIT_MAX} test SMS per minute. Retry in ${retrySec}s.`,
        code: 'SMS_TEST_RATE_LIMITED',
        retryAfterSec: retrySec,
      });
    }

    const db = getDb();
    let phone, providerCfg;
    try {
      // Lookup caller's registered phone
      const contactRow = db.prepare(
        "SELECT phone FROM lead_notification_contacts WHERE user_id = ?"
      ).get(userId);
      if (!contactRow || !contactRow.phone) {
        db.close();
        return res.status(422).json({
          error: 'No phone registered. Register your phone in the Notification Preferences tab "Your Contact Info" Card first.',
          code: 'LEAD_PHONE_NOT_REGISTERED',
        });
      }
      phone = contactRow.phone;

      // Lookup SMS provider config
      const cfgRow = db.prepare(
        "SELECT sms_provider, sms_account_sid, sms_auth_token_encrypted, sms_from_number FROM notification_config WHERE id = 'default'"
      ).get();
      if (!cfgRow || !cfgRow.sms_provider || !cfgRow.sms_account_sid || !cfgRow.sms_auth_token_encrypted) {
        db.close();
        return res.status(422).json({
          error: 'SMS provider not configured. Configure the SMS Provider Card first.',
          code: 'SMS_PROVIDER_NOT_CONFIGURED',
        });
      }

      // Decrypt auth token
      let authToken;
      try {
        authToken = openTier1('notification_config.sms_auth_token_encrypted', cfgRow.sms_auth_token_encrypted);
      } catch (decErr) {
        db.close();
        logger.error('SMS test: decrypt error', { error: decErr.message });
        return res.status(500).json({
          error: 'Failed to decrypt SMS auth token — check TIER1_ENCRYPTION_KEY env',
          code: 'SMS_AUTH_TOKEN_DECRYPT_FAILED',
        });
      }

      providerCfg = {
        provider: cfgRow.sms_provider,
        accountSid: cfgRow.sms_account_sid,
        authToken,
        from: cfgRow.sms_from_number,
      };
    } finally {
      db.close();
    }

    // Dispatch via notifications-sms.js sendSms()
    const { sendSms } = require('../services/notifications-sms');
    const result = await sendSms(providerCfg.provider, providerCfg, {
      to: phone,
      body: 'FireAlive test SMS — your SMS notification channel is configured and reachable.',
    });

    if (result.ok) {
      auditLog(userId, 'MC_SMS_TEST_SENT',
        `provider=${providerCfg.provider} message_id=${result.providerMessageId || 'null'}`, req.ip);
      res.json({
        ok: true,
        provider: providerCfg.provider,
        providerMessageId: result.providerMessageId || null,
        message: 'Test SMS dispatched successfully',
      });
    } else {
      auditLog(userId, 'MC_SMS_TEST_FAILED',
        `provider=${providerCfg.provider} status=${result.status} error=${result.error}`, req.ip);
      res.status(503).json({
        error: result.error || 'SMS dispatch failed',
        code: 'SMS_TEST_DISPATCH_FAILED',
        status: result.status,
        provider: providerCfg.provider,
      });
    }
  } catch (err) {
    logger.error('SMS test error', { error: err.message });
    res.status(500).json({ error: 'Failed to send test SMS', code: 'SMS_TEST_INTERNAL_ERROR' });
  }
});

function defaultConfig() {
  return {
    id: 'default', threshold: 'watch',
    email_enabled: 0, email_address: '',
    sms_enabled: 0, sms_number: '',
    webhook_enabled: 0, webhook_url: '',
    pagerduty_enabled: 0, pagerduty_key: '',
    // N1a C22: SMS provider config defaults — null means unconfigured
    sms_provider: null, sms_account_sid: null, sms_from_number: null,
  };
}

module.exports = router;

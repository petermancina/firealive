// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Notifications SMS-Channel Pipeline
//
// Processes notifications queued for the SMS channel and delivers them via the
// team's configured SMS provider (Twilio or AWS SNS). Invoked periodically by
// the scheduler service (every 60s; configurable via NOTIFICATIONS_SMS_INTERVAL_SEC
// env var). Sibling to notifications-pipeline.js (email/webhook/PagerDuty) and
// notifications-desktop.js (WebSocket push; ships in N1a C9).
//
// PROVIDER CONFIG (resolved from notification_config row id='default', columns
// added by N1a C1 init.js migration):
//   - sms_provider:                'twilio' | 'aws_sns'
//   - sms_account_sid:             Twilio account SID (or AWS_ACCESS_KEY_ID for SNS)
//   - sms_auth_token_encrypted:    AES-256-GCM via TIER1_ENCRYPTION_KEY; decrypted
//                                  per cycle via encryption.js decrypt(); the raw
//                                  string is the Twilio auth token or AWS secret
//                                  access key
//   - sms_from_number:             Source phone in E.164 (Twilio); ignored by AWS SNS
//                                  at v1.0.41 (SenderID via MessageAttributes is a
//                                  future enhancement)
//
// RECIPIENT PHONE RESOLUTION (N1a C6 schema):
//   notifications.recipient_id is users.id. Phone is looked up via
//   lead_notification_contacts WHERE user_id = ?. That table is structurally
//   restricted to non-anonymous roles (lead, admin) — analysts NEVER
//   have rows there. If no row or no phone column value → skip with audit
//   NOTIFICATION_SMS_SKIPPED_NO_PHONE and notification_delivery_log status='skipped'.
//
// ANALYST ANONYMITY DEFENSE-IN-DEPTH (N1a C7):
//   resolvePreference() and getEligibleRecipients() in notifications.js already
//   gate so that analyst-role users never get sms_delivery_status='queued'.
//   But THIS pipeline ALSO checks the recipient's role per-row before dispatch.
//   If somehow an analyst row reached the SMS queue (race condition during C7
//   deployment, future bug, or DB tampering), we skip it with audit event
//   NOTIFICATION_SMS_SKIPPED_ANALYST_ROLE. This audit event firing in production
//   is a SIGNAL — investigate the stored-value source immediately.
//
// AUDIT LOGGING (notification_delivery_log + auditLog):
//   Every dispatch attempt writes a notification_delivery_log row with SHA-256-
//   hashed phone in recipient_handle_hash (never plaintext). Audit events on
//   non-success outcomes:
//     - NOTIFICATION_SMS_FAILED              (transport error, network, timeout)
//     - NOTIFICATION_SMS_BOUNCED             (carrier reject, invalid number, opt-out)
//     - NOTIFICATION_SMS_SKIPPED_NO_PHONE    (lead has no phone registered)
//     - NOTIFICATION_SMS_SKIPPED_ANALYST_ROLE (defense-in-depth — should be 0/yr)
//
// FAILURE HANDLING:
//   - Send failure (provider error, network, timeout) → status='failed' + audit
//   - Hard bounce (invalid phone, opt-out, carrier reject) → status='bounced'
//     + audit; row stays bounced (do not retry without admin intervention)
//   - No automatic retries; failed/bounced rows visible via audit log + the
//     notification_delivery_log table for forensic investigation
//   - 10s per-send timeout; pipeline is non-blocking across cycles
//
// PROVIDER LAZY-LOADING:
//   @aws-sdk/client-sns is lazy-required inside sendViaAwsSns (matches
//   nodemailer's lazy-load pattern in notifications-pipeline.js). If the SDK
//   is not installed and the provider is aws_sns, the send fails with a
//   helpful "npm install @aws-sdk/client-sns" message rather than crashing
//   the pipeline at module load.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');
const { openTier1 } = require('./tier1-seal');

const BATCH_SIZE = 50;
const SEND_TIMEOUT_MS = 10000;
const PIPELINE_VERSION = 1;

// ── Role policy ──────────────────────────────────────────────────────────────
// Duplicated from notifications.js (N1a C7) to keep this module standalone
// without introducing a circular-import risk against notifications.js. The
// policy is intentionally simple (lead, admin are contact-safe) and
// expected to remain stable. If the canonical policy in notifications.js
// changes, this duplicate must change in lockstep. Single grep-able function
// name keeps the drift risk auditable.
function isContactSafeRole(role) {
  return role === 'lead' || role === 'admin';
}

// ── Config resolution ────────────────────────────────────────────────────────
function loadSmsConfig(db) {
  const row = db.prepare(`
    SELECT sms_provider, sms_account_sid, sms_auth_token_encrypted, sms_from_number
    FROM notification_config WHERE id = 'default'
  `).get();
  if (!row || !row.sms_provider) return null;
  if (!row.sms_account_sid || !row.sms_auth_token_encrypted || !row.sms_from_number) return null;

  let authToken;
  try {
    authToken = openTier1('notification_config.sms_auth_token_encrypted', row.sms_auth_token_encrypted);
  } catch (err) {
    logger.error('SMS pipeline: failed to decrypt sms_auth_token_encrypted', { error: err.message });
    return null;
  }

  return {
    provider: row.sms_provider,
    accountSid: row.sms_account_sid,
    authToken,
    from: row.sms_from_number,
  };
}

function validateSmsConfig(cfg) {
  if (!cfg) return { valid: false, reason: 'No SMS provider configured' };
  if (!['twilio', 'aws_sns'].includes(cfg.provider)) {
    return { valid: false, reason: `Unsupported SMS provider: ${cfg.provider}` };
  }
  if (!cfg.accountSid || !cfg.authToken || !cfg.from) {
    return { valid: false, reason: 'Missing accountSid / authToken / from' };
  }
  return { valid: true };
}

// ── Recipient lookups ────────────────────────────────────────────────────────
// Phone lookup: returns null when no row exists in lead_notification_contacts
// (analyst case — table is empty by design) or when the phone column is NULL
// (lead who registered only their email). Pipeline treats either case as
// "skip with reason=no_lead_phone_registered" — no error to the recipient,
// no retry. Resolution is via PK index on user_id.
function lookupRecipientPhone(db, userId) {
  const row = db.prepare("SELECT phone FROM lead_notification_contacts WHERE user_id = ?").get(userId);
  return row && row.phone ? row.phone : null;
}

function lookupRecipientRole(db, userId) {
  const row = db.prepare("SELECT role FROM users WHERE id = ?").get(userId);
  return row ? row.role : null;
}

function hashPhone(phone) {
  return crypto.createHash('sha256').update(phone).digest('hex');
}

// ── Send transports ──────────────────────────────────────────────────────────

async function sendViaTwilio(cfg, { to, body }) {
  // Twilio Programmable Messaging REST API:
  //   POST https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/Messages.json
  //   Auth: HTTP Basic with accountSid:authToken (base64 encoded)
  //   Body: application/x-www-form-urlencoded with From / To / Body params
  const url = `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(cfg.accountSid)}/Messages.json`;
  const auth = Buffer.from(`${cfg.accountSid}:${cfg.authToken}`).toString('base64');
  const form = new URLSearchParams({ From: cfg.from, To: to, Body: body });

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), SEND_TIMEOUT_MS);
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': `FireAlive-Notifications-SMS/${PIPELINE_VERSION}`,
      },
      body: form.toString(),
      signal: ctrl.signal,
    });
    clearTimeout(t);

    if (resp.ok || resp.status === 201) {
      const json = await resp.json().catch(() => null);
      return { ok: true, status: 'sent', providerMessageId: json && json.sid ? json.sid : null };
    }

    // Bounce-class Twilio error codes (https://www.twilio.com/docs/api/errors):
    //   21211 — Invalid 'To' Phone Number
    //   21408 — Permission to send SMS not enabled for region
    //   21610 — Recipient unsubscribed (STOP)
    //   21614 — 'To' is not a valid mobile number
    const json = await resp.json().catch(() => null);
    const errorCode = json && json.code ? json.code : null;
    const isBounce = [21211, 21408, 21610, 21614].includes(errorCode);
    return {
      ok: false,
      status: isBounce ? 'bounced' : 'failed',
      error: `Twilio ${resp.status}${errorCode ? ` code=${errorCode}` : ''}: ${json && json.message ? json.message : 'unknown'}`,
    };
  } catch (err) {
    return {
      ok: false,
      status: 'failed',
      error: err.name === 'AbortError' ? 'Twilio timeout' : err.message,
    };
  }
}

async function sendViaAwsSns(cfg, { to, body }) {
  // Lazy-load AWS SDK (matches nodemailer lazy-load pattern in
  // notifications-pipeline.js sendViaSmtp). If the SDK is not installed,
  // fail with a helpful install instruction instead of crashing the pipeline.
  let SNSClient, PublishCommand;
  try {
    ({ SNSClient, PublishCommand } = require('@aws-sdk/client-sns'));
  } catch {
    return {
      ok: false,
      status: 'failed',
      error: '@aws-sdk/client-sns not installed; run npm install @aws-sdk/client-sns to enable AWS SNS SMS dispatch',
    };
  }

  // Column reuse for AWS:
  //   sms_account_sid → AWS_ACCESS_KEY_ID
  //   sms_auth_token  → AWS_SECRET_ACCESS_KEY (decrypted from sms_auth_token_encrypted)
  //   sms_from_number → unused at v1.0.41 (AWS SenderID via MessageAttributes is a future enhancement)
  //   AWS_REGION read from env; defaults to us-east-1
  const client = new SNSClient({
    region: process.env.AWS_REGION || 'us-east-1',
    credentials: {
      accessKeyId: cfg.accountSid,
      secretAccessKey: cfg.authToken,
    },
    requestHandler: { requestTimeout: SEND_TIMEOUT_MS },
  });

  try {
    const out = await client.send(new PublishCommand({
      PhoneNumber: to,
      Message: body,
      MessageAttributes: {
        'AWS.SNS.SMS.SMSType': { DataType: 'String', StringValue: 'Transactional' },
      },
    }));
    return { ok: true, status: 'sent', providerMessageId: out && out.MessageId ? out.MessageId : null };
  } catch (err) {
    // AWS SDK throws structured errors with .name; treat InvalidParameter
    // referring to phone/number as bounce, everything else as failed.
    const isBounce = err.name === 'InvalidParameter' && /phone|number/i.test(err.message || '');
    return {
      ok: false,
      status: isBounce ? 'bounced' : 'failed',
      error: `AWS SNS ${err.name}: ${err.message}`,
    };
  }
}

async function sendSms(provider, cfg, { to, body }) {
  if (provider === 'twilio') return sendViaTwilio(cfg, { to, body });
  if (provider === 'aws_sns') return sendViaAwsSns(cfg, { to, body });
  return { ok: false, status: 'failed', error: `Unknown SMS provider: ${provider}` };
}

// ── notification_delivery_log writer ─────────────────────────────────────────
// Best-effort write to the per-attempt audit table (N1a C1 schema). Failure to
// write does not block dispatch — we log a warning and continue. Forensic
// investigators can still join notifications.recipient_id back to the user via
// the row's *_delivery_status column.
function recordDeliveryAttempt(db, params) {
  try {
    db.prepare(`
      INSERT INTO notification_delivery_log (
        notification_id, channel, attempt_number, status,
        transport_provider, transport_message_id, recipient_handle_hash,
        error_message, latency_ms, completed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      params.notificationId,
      params.channel,
      params.attemptNumber || 1,
      params.status,
      params.transportProvider || null,
      params.transportMessageId || null,
      params.recipientHandleHash || null,
      params.errorMessage || null,
      params.latencyMs != null ? params.latencyMs : null
    );
  } catch (err) {
    logger.warn('SMS pipeline: failed to write notification_delivery_log row', {
      notificationId: params.notificationId,
      error: err.message,
    });
  }
}

// ── Pipeline entry point ─────────────────────────────────────────────────────
async function processSmsQueue() {
  const db = getDb();
  let cfg;
  try {
    cfg = loadSmsConfig(db);
  } catch (err) {
    logger.error('SMS pipeline: failed to load config', { error: err.message });
    db.close();
    return { processed: 0, sent: 0, failed: 0, bounced: 0, skipped: 0 };
  }

  const queued = db.prepare(`
    SELECT id, recipient_id, event_type, title, body
    FROM notifications
    WHERE sms_delivery_status = 'queued'
    ORDER BY created_at ASC
    LIMIT ?
  `).all(BATCH_SIZE);

  if (queued.length === 0) {
    db.close();
    return { processed: 0, sent: 0, failed: 0, bounced: 0, skipped: 0 };
  }

  const cfgCheck = validateSmsConfig(cfg);
  if (!cfgCheck.valid) {
    logger.info('SMS pipeline: queued items waiting but provider not configured', {
      queued: queued.length,
      reason: cfgCheck.reason,
    });
    db.close();
    return { processed: 0, sent: 0, failed: 0, bounced: 0, skipped: queued.length };
  }

  const stats = { processed: 0, sent: 0, failed: 0, bounced: 0, skipped: 0 };
  const updateStatus = db.prepare(`UPDATE notifications SET sms_delivery_status = ? WHERE id = ?`);

  for (const n of queued) {
    stats.processed++;

    // ── DEFENSE-IN-DEPTH: ANALYST-ROLE SKIP (N1a C7 anonymity enforcement) ──
    // This should never fire if C7 is working correctly — resolvePreference()
    // and getEligibleRecipients() ensure analyst-role users never reach the
    // SMS queue. If this DOES fire in production, it indicates a bug, race,
    // or DB tampering. The audit event makes it visible to ops monitoring;
    // recommend alerting on it.
    const role = lookupRecipientRole(db, n.recipient_id);
    if (!isContactSafeRole(role)) {
      updateStatus.run('skipped', n.id);
      stats.skipped++;
      recordDeliveryAttempt(db, {
        notificationId: n.id,
        channel: 'sms',
        status: 'skipped',
        errorMessage: `Recipient role=${role || 'unknown'} is not contact-safe; SMS suppressed (anonymity enforcement)`,
        attemptNumber: 1,
      });
      auditLog(null, 'NOTIFICATION_SMS_SKIPPED_ANALYST_ROLE',
        `id=${n.id} event=${n.event_type} role=${role || 'unknown'}`, null);
      logger.warn('SMS pipeline: skipped non-contact-safe role (should not occur post-C7 — investigate)', {
        notificationId: n.id,
        recipientId: n.recipient_id,
        role,
      });
      continue;
    }

    // ── PHONE LOOKUP ──
    const phone = lookupRecipientPhone(db, n.recipient_id);
    if (!phone) {
      updateStatus.run('skipped', n.id);
      stats.skipped++;
      recordDeliveryAttempt(db, {
        notificationId: n.id,
        channel: 'sms',
        status: 'skipped',
        errorMessage: 'no_lead_phone_registered',
        attemptNumber: 1,
      });
      auditLog(null, 'NOTIFICATION_SMS_SKIPPED_NO_PHONE',
        `id=${n.id} event=${n.event_type} recipient=${n.recipient_id}`, null);
      continue;
    }

    // ── DISPATCH ──
    // SMS body is title-prefixed and body-truncated to ~140 chars (single-segment
    // GSM-7 SMS is 160 chars; leaving headroom for the "[FireAlive] " prefix
    // plus the title length). Multi-segment SMS still works but costs more —
    // 140 is a deliberate cost-control default. The full body remains in the
    // in-app notification.
    const bodyText = `[FireAlive] ${n.title}${n.body ? `: ${n.body.substring(0, 140)}` : ''}`;
    const phoneHash = hashPhone(phone);
    const t0 = Date.now();
    const result = await sendSms(cfg.provider, cfg, { to: phone, body: bodyText });
    const latencyMs = Date.now() - t0;

    updateStatus.run(result.status, n.id);
    recordDeliveryAttempt(db, {
      notificationId: n.id,
      channel: 'sms',
      status: result.status,
      transportProvider: cfg.provider,
      transportMessageId: result.providerMessageId,
      recipientHandleHash: phoneHash,
      errorMessage: result.error || null,
      latencyMs,
      attemptNumber: 1,
    });

    if (result.ok) {
      stats.sent++;
    } else if (result.status === 'bounced') {
      stats.bounced++;
      auditLog(null, 'NOTIFICATION_SMS_BOUNCED',
        `id=${n.id} event=${n.event_type} provider=${cfg.provider} error=${result.error}`, null);
    } else {
      stats.failed++;
      auditLog(null, 'NOTIFICATION_SMS_FAILED',
        `id=${n.id} event=${n.event_type} provider=${cfg.provider} error=${result.error}`, null);
    }
  }

  db.close();
  return stats;
}

module.exports = {
  processSmsQueue,
  sendSms,
  validateSmsConfig,
  loadSmsConfig,
  BATCH_SIZE,
  SEND_TIMEOUT_MS,
};

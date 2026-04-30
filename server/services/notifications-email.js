// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Notifications Email Pipeline
//
// Processes queued in-app notifications and delivers them via the team's
// configured email channel. Invoked periodically by the scheduler service
// (every 60s; configurable via NOTIFICATIONS_EMAIL_INTERVAL_SEC env var).
//
// DELIVERY CHANNELS (resolved from notification_config row id='default',
// which is owned by routes/notifications.js):
//   - SMTP via Nodemailer (when email_enabled=1 and SMTP env vars set)
//   - Webhook POST (when webhook_enabled=1 and webhook_url set)
//   - PagerDuty event (when pagerduty_enabled=1 and pagerduty_key set)
//
// If the user opted into email for a notification but no delivery channel is
// configured, the row stays at email_delivery_status='queued'. The pipeline
// logs this state once per processing cycle and continues. When a channel
// later gets configured, queued emails flow through automatically.
//
// FAILURE HANDLING:
// On send failure (transport error, 4xx, 5xx, timeout), the row is updated
// to email_delivery_status='failed' with the error in a 'last_error' field
// (added in commit 1's schema as part of the body field's reuse — actually
// no, it's stored in the audit log via auditLog and the row stays 'failed').
// We do not retry automatically; failed emails are visible in the audit log
// and a lead can manually requeue them via /api/inbox/admin/requeue-email/:id
// (added in a later sub-phase if needed). Bounce detection happens via the
// SMTP/webhook response when available; bouncedstays distinct from 'failed'
// because bounced emails should not be re-sent without address change.
//
// The pipeline is non-blocking: if SMTP transport hangs, individual sends
// have a 10s timeout and the next cycle continues from where this left off.
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');

const BATCH_SIZE = 50;
const SEND_TIMEOUT_MS = 10000;
const PIPELINE_VERSION = 1;

// ── Config resolution ────────────────────────────────────────────────────────
function loadConfig(db) {
  const row = db.prepare(`
    SELECT email_enabled, email_address, webhook_enabled, webhook_url,
           pagerduty_enabled, pagerduty_key
    FROM notification_config WHERE id = 'default'
  `).get();
  if (!row) return null;
  return {
    smtp: row.email_enabled === 1 && row.email_address ? {
      address: row.email_address,
      host: process.env.SMTP_HOST || null,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      user: process.env.SMTP_USER || null,
      pass: process.env.SMTP_PASS || null,
      from: process.env.SMTP_FROM || row.email_address,
    } : null,
    webhook: row.webhook_enabled === 1 && row.webhook_url ? {
      url: row.webhook_url,
    } : null,
    pagerduty: row.pagerduty_enabled === 1 && row.pagerduty_key ? {
      key: row.pagerduty_key,
    } : null,
  };
}

function hasAnyChannel(cfg) {
  return !!(cfg && (cfg.smtp || cfg.webhook || cfg.pagerduty));
}

// ── Recipient email resolution ───────────────────────────────────────────────
// notifications.recipient_id is users.id. The user's email address is stored
// in users.username (which is treated as the login identifier; for SSO users
// it's the SSO email; for local users it's set at provisioning).
function lookupRecipientEmail(db, userId) {
  const row = db.prepare("SELECT username, name, auth_method, external_id FROM users WHERE id = ?").get(userId);
  if (!row) return null;
  if (row.auth_method !== 'local') return row.external_id || row.username;
  return row.username;
}

// ── Send transports ──────────────────────────────────────────────────────────

async function sendViaSmtp(cfg, { to, subject, text }) {
  if (!cfg.smtp.host || !cfg.smtp.user || !cfg.smtp.pass) {
    return { ok: false, status: 'failed', error: 'SMTP host/user/pass not set in env (SMTP_HOST/SMTP_USER/SMTP_PASS)' };
  }
  let nodemailer;
  try { nodemailer = require('nodemailer'); }
  catch { return { ok: false, status: 'failed', error: 'nodemailer not installed; run npm install nodemailer' }; }

  const transport = nodemailer.createTransport({
    host: cfg.smtp.host, port: cfg.smtp.port, secure: cfg.smtp.secure,
    auth: { user: cfg.smtp.user, pass: cfg.smtp.pass },
    connectionTimeout: SEND_TIMEOUT_MS, socketTimeout: SEND_TIMEOUT_MS,
  });
  try {
    const info = await transport.sendMail({
      from: cfg.smtp.from, to, subject, text,
    });
    if (info.rejected && info.rejected.length > 0) {
      return { ok: false, status: 'bounced', error: `Rejected: ${info.rejected.join(', ')}` };
    }
    return { ok: true, status: 'sent' };
  } catch (err) {
    const isBounce = /5\d\d|bounce|mailbox|no such user|user unknown/i.test(err.message || '');
    return { ok: false, status: isBounce ? 'bounced' : 'failed', error: err.message };
  }
}

async function sendViaWebhook(cfg, payload) {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), SEND_TIMEOUT_MS);
    const resp = await fetch(cfg.webhook.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': `FireAlive-Notifications/${PIPELINE_VERSION}` },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (resp.ok) return { ok: true, status: 'sent' };
    return { ok: false, status: 'failed', error: `Webhook returned ${resp.status}` };
  } catch (err) {
    return { ok: false, status: 'failed', error: err.name === 'AbortError' ? 'Webhook timeout' : err.message };
  }
}

async function sendViaPagerDuty(cfg, { subject, text, eventType }) {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), SEND_TIMEOUT_MS);
    const resp = await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routing_key: cfg.pagerduty.key,
        event_action: 'trigger',
        payload: {
          summary: subject,
          source: 'firealive',
          severity: 'info',
          custom_details: { body: text, event_type: eventType },
        },
      }),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (resp.ok || resp.status === 202) return { ok: true, status: 'sent' };
    return { ok: false, status: 'failed', error: `PagerDuty returned ${resp.status}` };
  } catch (err) {
    return { ok: false, status: 'failed', error: err.name === 'AbortError' ? 'PagerDuty timeout' : err.message };
  }
}

// ── Pipeline entry point ─────────────────────────────────────────────────────
async function processQueue() {
  const db = getDb();
  let cfg;
  try {
    cfg = loadConfig(db);
  } catch (err) {
    logger.error('Notifications email pipeline: failed to load config', { error: err.message });
    db.close();
    return { processed: 0, sent: 0, failed: 0, bounced: 0, skipped: 0 };
  }

  const queued = db.prepare(`
    SELECT id, recipient_id, event_type, title, body
    FROM notifications
    WHERE email_delivery_status = 'queued'
    ORDER BY created_at ASC
    LIMIT ?
  `).all(BATCH_SIZE);

  if (queued.length === 0) { db.close(); return { processed: 0, sent: 0, failed: 0, bounced: 0, skipped: 0 }; }

  if (!hasAnyChannel(cfg)) {
    logger.info('Notifications email pipeline: queued items waiting but no delivery channel configured', { queued: queued.length });
    db.close();
    return { processed: 0, sent: 0, failed: 0, bounced: 0, skipped: queued.length };
  }

  const stats = { processed: 0, sent: 0, failed: 0, bounced: 0, skipped: 0 };
  const updateStatus = db.prepare(`UPDATE notifications SET email_delivery_status = ?, delivered_email = ? WHERE id = ?`);

  for (const n of queued) {
    stats.processed++;
    const email = lookupRecipientEmail(db, n.recipient_id);
    if (!email) {
      updateStatus.run('failed', 0, n.id);
      stats.failed++;
      logger.warn('Notifications email pipeline: recipient has no email address', { notificationId: n.id, recipientId: n.recipient_id });
      continue;
    }

    const subject = `[FireAlive] ${n.title}`;
    const text = (n.body ? `${n.body}\n\n` : '') + `View in FireAlive: open the Inbox tab in your Management Console or Analyst Client.`;
    const payload = { subject, text, eventType: n.event_type, recipientEmail: email, recipientId: n.recipient_id, notificationId: n.id };

    let result;
    if (cfg.smtp) result = await sendViaSmtp(cfg, { to: email, subject, text });
    else if (cfg.webhook) result = await sendViaWebhook(cfg, payload);
    else if (cfg.pagerduty) result = await sendViaPagerDuty(cfg, { subject, text, eventType: n.event_type });

    if (result.ok) {
      updateStatus.run('sent', 1, n.id);
      stats.sent++;
    } else {
      updateStatus.run(result.status, 0, n.id);
      if (result.status === 'bounced') stats.bounced++;
      else stats.failed++;
      auditLog(null, 'NOTIFICATION_EMAIL_FAILED', `id=${n.id} event=${n.event_type} status=${result.status} error=${result.error}`, null);
    }
  }

  db.close();
  return stats;
}

module.exports = { processQueue, BATCH_SIZE, SEND_TIMEOUT_MS };

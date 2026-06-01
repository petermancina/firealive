// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Alert Transports (SIEM CEF push + ops email)
//
// Completes the `siem` and `email` channel seams used by alert-router.js (B3-C3).
//
//   pushAlert(db, alert)  — push a single CEF event for the alert to the
//                           configured SIEM over syslog (tcp/udp/tls), reusing
//                           the existing SiemAdapter. This is the immediate-
//                           correlation companion to the pull-based
//                           /api/metrics/cef line (SIEM platforms can poll the
//                           metrics line on a schedule; alerts are pushed the
//                           moment they fire).
//   emailAlert(db, alert) — email the alert to the configured operational
//                           address (notification_config.email_address) via the
//                           same SMTP env the notifications pipeline uses.
//
// Email is sent to the single configured ops address, NEVER to per-user
// addresses: users.email is an anonymity-sensitive HR-sync-only column and must
// not be used for alert delivery.
//
// Both helpers are best-effort and never throw — operational alerting must not
// be able to crash the monitor or the router.
// ═══════════════════════════════════════════════════════════════════════════════

const SEND_TIMEOUT_MS = 10000;

// alert severity label -> CEF numeric severity (0-10; higher = more severe)
function cefSeverity(sev) {
  switch (String(sev || '').toLowerCase()) {
    case 'critical': return 9;
    case 'high': return 7;
    case 'warning': return 5;
    case 'info': return 3;
    default: return 5;
  }
}

// ── SIEM CEF push ──────────────────────────────────────────────────────────────
async function pushAlert(db, alert) {
  try {
    const row = db.prepare("SELECT value FROM config WHERE key = 'siem_config'").get();
    if (!row || !row.value) return { status: 'not_configured' };
    let cfg;
    try { cfg = JSON.parse(row.value); } catch { return { status: 'invalid_config' }; }
    if (!cfg || !cfg.endpoint) return { status: 'not_configured' };

    const { SiemAdapter } = require('../integrations/siem-adapter');
    const siem = new SiemAdapter(cfg.endpoint, cfg.protocol || 'tls');
    const res = await siem.sendEvent(
      alert.type || 'SYSTEM_ALERT',
      cefSeverity(alert.severity),
      (alert.message || '').toString().replace(/[|\\]/g, '_')
    );
    return res && res.sent ? { status: 'sent' } : { status: 'error', detail: res && res.error };
  } catch (e) {
    return { status: 'error', detail: e.message };
  }
}

// ── Ops email ────────────────────────────────────────────────────────────────
async function emailAlert(db, alert) {
  try {
    const row = db.prepare(
      "SELECT email_enabled, email_address FROM notification_config WHERE id = 'default'"
    ).get();
    if (!row || row.email_enabled !== 1 || !row.email_address) return { status: 'not_configured' };

    const smtp = {
      host: process.env.SMTP_HOST || null,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      user: process.env.SMTP_USER || null,
      pass: process.env.SMTP_PASS || null,
      from: process.env.SMTP_FROM || row.email_address,
    };
    if (!smtp.host || !smtp.user || !smtp.pass) {
      return { status: 'not_configured', detail: 'SMTP env not set (SMTP_HOST/SMTP_USER/SMTP_PASS)' };
    }

    let nodemailer;
    try { nodemailer = require('nodemailer'); }
    catch { return { status: 'unavailable', detail: 'nodemailer not installed' }; }

    const transport = nodemailer.createTransport({
      host: smtp.host, port: smtp.port, secure: smtp.secure,
      auth: { user: smtp.user, pass: smtp.pass },
      connectionTimeout: SEND_TIMEOUT_MS, socketTimeout: SEND_TIMEOUT_MS,
    });
    const subject = `[FireAlive ${String(alert.severity || 'alert').toUpperCase()}] ${alert.type || 'SYSTEM_ALERT'}`;
    const text = `${alert.message || ''}\n\nType: ${alert.type || 'SYSTEM_ALERT'}\nSeverity: ${alert.severity || ''}\nTime: ${alert.timestamp || new Date().toISOString()}`;
    const info = await transport.sendMail({ from: smtp.from, to: row.email_address, subject, text });
    if (info && info.rejected && info.rejected.length > 0) {
      return { status: 'bounced', detail: `Rejected: ${info.rejected.join(', ')}` };
    }
    return { status: 'sent' };
  } catch (e) {
    return { status: 'error', detail: e.message };
  }
}

module.exports = { pushAlert, emailAlert, cefSeverity };

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Alert Transports (SIEM CEF push + ops email) (B6a)
//
// GD-server twin of the regional siem-push. Completes the `siem` and `email`
// channel seams used by the GD alert-router:
//
//   pushAlert(db, alert)  — push a single CEF event for the alert to the
//                           configured SIEM over syslog (tcp/udp/tls) via the
//                           GD SIEM adapter. The immediate-correlation companion
//                           to the pull-based GD metrics CEF line.
//   emailAlert(db, alert) — email the alert to the GD's configured ops
//                           recipients (notification_config.recipients, gated by
//                           notification_config.email) via the SMTP env.
//
// GD difference from the regional: the GD's notification_config is a CONFIG-KEY
// JSON value (not a table), so emailAlert reads { email, recipients } from it.
// Email goes only to the explicitly-configured ops recipients -- the GD holds no
// analyst identities, so there is no per-user-address anonymity concern, but the
// alert email is still an ops-only channel.
//
// Both helpers are best-effort and never throw -- operational alerting must not
// be able to crash the monitor or the router. nodemailer resolves from the root
// node_modules at runtime (a declared root dependency); if absent, emailAlert
// degrades to 'unavailable' rather than failing.
//
// AGPL-3.0-or-later
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

    const { GdSiemAdapter } = require('./gd-siem-adapter');
    const siem = new GdSiemAdapter(cfg.endpoint, cfg.protocol || 'tls');
    const res = await siem.sendEvent(
      alert.type || 'GD_SYSTEM_ALERT',
      cefSeverity(alert.severity),
      (alert.message || '').toString()
    );
    return res && res.sent ? { status: 'sent' } : { status: 'error', detail: res && res.error };
  } catch (e) {
    return { status: 'error', detail: e.message };
  }
}

// ── Ops email ────────────────────────────────────────────────────────────────
async function emailAlert(db, alert) {
  try {
    let cfg;
    try {
      const row = db.prepare("SELECT value FROM config WHERE key = 'notification_config'").get();
      cfg = row && row.value ? JSON.parse(row.value) : null;
    } catch { return { status: 'invalid_config' }; }
    if (!cfg || cfg.email !== true) return { status: 'not_configured' };

    const recipientList = String(cfg.recipients || '')
      .split(/[,;]/).map((s) => s.trim()).filter(Boolean);
    if (!recipientList.length) return { status: 'not_configured', detail: 'no recipients configured' };

    const smtp = {
      host: process.env.SMTP_HOST || null,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      user: process.env.SMTP_USER || null,
      pass: process.env.SMTP_PASS || null,
      from: process.env.SMTP_FROM || recipientList[0],
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
    const subject = `[FireAlive GD ${String(alert.severity || 'alert').toUpperCase()}] ${alert.type || 'GD_SYSTEM_ALERT'}`;
    const text = `${alert.message || ''}\n\nType: ${alert.type || 'GD_SYSTEM_ALERT'}\n` +
      `Severity: ${alert.severity || ''}\nTime: ${alert.timestamp || new Date().toISOString()}\n` +
      'Source: FireAlive Global Dashboard';
    const info = await transport.sendMail({ from: smtp.from, to: recipientList.join(', '), subject, text });
    if (info && info.rejected && info.rejected.length > 0) {
      return { status: 'bounced', detail: `Rejected: ${info.rejected.join(', ')}` };
    }
    return { status: 'sent' };
  } catch (e) {
    return { status: 'error', detail: e.message };
  }
}

module.exports = { pushAlert, emailAlert, cefSeverity };

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Alert Router (B6a)
//
// GD-server twin of the regional alert-router. Severity-tiered fan-out for GD
// self-protection signals (the runtime/anomaly monitor, integration-health
// failures, ingest-trust rejections, signing-key anomalies, compliance-rollup
// integrity, audit-chain breaks). One place decides, per severity, which
// delivery channels fire:
//
//   audit         — ALWAYS on, non-disableable (the durable hash-chained record)
//   soar          — push to the configured SOAR platform (automated response)
//   siem          — push a CEF event to the configured SIEM (immediate correlation)
//   email         — email the alert to the GD ops recipients
//   notification  — in-app insert into the GD shared notification queue (the only
//                   channel that writes a REPLICATED table; suppressed on an HA
//                   passive -- see _chNotification)
//   webhook       — generic outbound POST (PagerDuty / Slack / Teams / OpsGenie)
//
// The operator configures a per-severity routing matrix (config key
// 'alert_routing_matrix'); audit is always sent regardless of the matrix. The
// router is de-dup aware (suppresses identical type+severity within a window),
// isolates every channel (one failing never affects another), and NEVER throws
// -- operational alerting must not be able to crash a caller.
//
// Differences from the regional router: audit is written via the GD hash-chained
// appendGdAuditEntry (alert severity is mapped onto the audit enum); the
// notification channel inserts into the GD shared queue (no per-recipient fan-
// out); there is NO critical-alert websocket refresh (the GD has no analyst
// clients); and logging goes to console (the GD has no logger service). All
// alerts concern the GD server ITSELF -- never analyst data.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const https = require('https');
const http = require('http');

const SEVERITIES = ['info', 'warning', 'high', 'critical'];
const CHANNELS = ['soar', 'siem', 'email', 'notification', 'webhook']; // audit is implicit + always-on
const MATRIX_CONFIG_KEY = 'alert_routing_matrix';
const WEBHOOK_URL_CONFIG_KEY = 'alert_webhook_url';
const DEDUP_WINDOW_MS = 600000; // 10 min de-dup per (type|severity)

// Locked SOC-grade defaults: audit always; warning -> +siem; high -> +soar
// +siem +notification; critical -> all. Mirrors the db-init seed; used only as
// the fallback when the config matrix is absent or unparseable.
const DEFAULT_MATRIX = {
  info:     { soar: false, siem: false, email: false, notification: false, webhook: false },
  warning:  { soar: false, siem: true,  email: false, notification: false, webhook: false },
  high:     { soar: true,  siem: true,  email: false, notification: true,  webhook: false },
  critical: { soar: true,  siem: true,  email: true,  notification: true,  webhook: true  },
};

// in-process de-dup memory (single server process)
const _lastSent = new Map();

// alert severity -> GD audit_log severity enum ('info','warning','error','critical').
// 'high' has no audit-enum equivalent and maps to 'error'.
function _auditSeverity(sev) {
  switch (String(sev || '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'error';
    case 'warning': return 'warning';
    case 'info': return 'info';
    default: return 'warning';
  }
}

function loadMatrix(db) {
  const merged = {};
  for (const sev of SEVERITIES) merged[sev] = { ...DEFAULT_MATRIX[sev] };
  try {
    const row = db.prepare('SELECT value FROM config WHERE key = ?').get(MATRIX_CONFIG_KEY);
    if (row && row.value) {
      const parsed = JSON.parse(row.value);
      for (const sev of SEVERITIES) {
        if (parsed && typeof parsed[sev] === 'object' && parsed[sev]) {
          for (const ch of CHANNELS) {
            if (typeof parsed[sev][ch] === 'boolean') merged[sev][ch] = parsed[sev][ch];
          }
        }
      }
    }
  } catch { /* fall back to defaults */ }
  return merged;
}

function _deduped(type, severity) {
  const k = `${type}|${severity}`;
  const now = Date.now();
  const last = _lastSent.get(k) || 0;
  if (now - last < DEDUP_WINDOW_MS) return true;
  _lastSent.set(k, now);
  return false;
}

// ── Channel handlers (each best-effort, isolated, never throws upward) ─────────

function _chAudit(db, alert) {
  const { appendGdAuditEntry } = require('./gd-audit-chain');
  appendGdAuditEntry(db, {
    userId: alert.userId || null,
    eventType: alert.type || 'GD_SYSTEM_ALERT',
    detail: alert.message || '',
    severity: _auditSeverity(alert.severity),
    ip: alert.ip || null,
  });
  return { status: 'sent' };
}

async function _chSoar(db, alert) {
  const { dispatchToSoar } = require('./gd-soar-push');
  const r = await dispatchToSoar(db, alert.type || 'GD_SYSTEM_ALERT', alert);
  return r || { status: 'sent' };
}

async function _chSiem(db, alert) {
  const { pushAlert } = require('./gd-siem-push');
  const r = await pushAlert(db, alert);
  return r || { status: 'sent' };
}

async function _chEmail(db, alert) {
  const { emailAlert } = require('./gd-siem-push');
  const r = await emailAlert(db, alert);
  return r || { status: 'sent' };
}

function _chNotification(db, alert) {
  // HA sole-writer (B6d). `notifications` is a REPLICATED table, and this is the
  // only channel that writes one. Timer-driven alerts (the runtime monitor's FIM /
  // CPU / memory / db-read signals, integration-health) reach this router without
  // passing the request-layer write-guard, so on a confirmed paired passive this
  // insert would create rows the active never had -- diverging the pair and
  // colliding on the primary key when the active's rows replicate in.
  //
  // The alert is NOT lost. _chAudit runs first, unconditionally and before de-dup,
  // into the hash-chained audit_log, which is excluded from replication and is
  // therefore node-local and tamper-evident; the outbound channels (soar / siem /
  // email / webhook) still fire, so a tampered standby still pages the operator.
  // Only the replicated row is withheld. Fails OPEN: any probe error is treated as
  // "not a passive", so a standalone or active node always writes the notification.
  let passive = false;
  try {
    passive = require('./gd-ha-write-guard').isConfirmedPassive(db);
  } catch (probeErr) {
    passive = false;
  }
  if (passive) {
    return { status: 'skipped_ha_passive' };
  }

  // In-app insert into the GD shared notification queue (no per-recipient fan-
  // out -- the GD console viewers all read the same queue). GD-wide self-
  // protection alerts carry mc_id = null; an MC-scoped alert (e.g. ingest
  // rejection) carries its mc_id.
  db.prepare(
    "INSERT INTO notifications (type, mc_id, message, severity) VALUES ('security_alert', ?, ?, ?)"
  ).run(
    alert.mcId || null,
    `${alert.type || 'GD_SYSTEM_ALERT'}: ${alert.message || ''}`,
    String(alert.severity || 'warning')
  );
  return { status: 'sent' };
}

function _chWebhook(db, alert) {
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get(WEBHOOK_URL_CONFIG_KEY);
  const url = row && row.value ? String(row.value) : null;
  if (!url) return { status: 'not_configured' };
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve({ status: 'invalid_url' }); }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return resolve({ status: 'invalid_url' });
    const payload = JSON.stringify({
      source: 'firealive-gd', type: alert.type, severity: alert.severity,
      message: alert.message, timestamp: alert.timestamp || new Date().toISOString(),
    });
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: u.hostname, port: u.port, path: (u.pathname || '/') + (u.search || ''),
      method: 'POST', timeout: 5000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    }, (res) => { res.resume(); resolve({ status: 'sent', code: res.statusCode }); });
    req.on('error', (e) => resolve({ status: 'error', detail: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 'timeout' }); });
    req.write(payload);
    req.end();
  });
}

const DEFAULT_HANDLERS = {
  audit: _chAudit,
  soar: _chSoar,
  siem: _chSiem,
  email: _chEmail,
  notification: _chNotification,
  webhook: _chWebhook,
};

// ── Public entry ──────────────────────────────────────────────────────────────
//
// routeGdAlert(db, alert, opts?) -> { type, severity, deduped, channels: [...] }
//   alert: { type, severity, message, timestamp?, mcId?, userId?, ip?, ... }
//   opts.deps: optional channel-handler overrides (for testing/injection)
//
async function routeGdAlert(db, alert, opts = {}) {
  const out = { type: alert && alert.type, severity: null, deduped: false, channels: [] };
  try {
    if (!alert || typeof alert !== 'object') return out;
    let severity = String(alert.severity || 'warning').toLowerCase();
    if (!SEVERITIES.includes(severity)) severity = 'warning';
    out.severity = severity;

    const handlers = { ...DEFAULT_HANDLERS, ...(opts.deps || {}) };

    // Audit is ALWAYS sent, before the de-dup gate, so every alert is recorded.
    out.channels.push(await _run(handlers.audit, 'audit', db, alert));

    if (_deduped(alert.type || 'GD_SYSTEM_ALERT', severity)) {
      out.deduped = true;
      return out;
    }

    const matrix = loadMatrix(db)[severity] || {};
    for (const ch of CHANNELS) {
      if (matrix[ch]) out.channels.push(await _run(handlers[ch], ch, db, alert));
    }
  } catch (e) {
    try { console.warn('[gd-alert-router] unexpected error:', e && e.message); } catch (_) { /* ignore */ }
  }
  return out;
}

async function _run(handler, name, db, alert) {
  if (typeof handler !== 'function') return { channel: name, ok: false, status: 'no_handler' };
  try {
    const r = await handler(db, alert);
    return { channel: name, ok: (r && r.status !== 'error'), ...(r || {}) };
  } catch (e) {
    return { channel: name, ok: false, status: 'error', detail: e.message };
  }
}

// _chNotification and _chAudit are exported so the regression can assert the HA
// sole-writer property directly and synchronously: the replicated `notifications`
// row is withheld on a confirmed passive, while the node-local audit append still
// happens. routeGdAlert is async, and the GD regression runner invokes checks
// synchronously, so a check that awaited the router would record a pending Promise
// as a pass and assert nothing. Exporting the two channels keeps the assertion on
// the real code rather than a copy of its condition. Both are pure (db, alert)
// functions; neither is intended for use outside the router and the regression.
module.exports = {
  routeGdAlert,
  loadMatrix,
  DEFAULT_MATRIX,
  SEVERITIES,
  CHANNELS,
  MATRIX_CONFIG_KEY,
  _chNotification,
  _chAudit,
};

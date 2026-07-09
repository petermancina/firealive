// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Alert Router
//
// Severity-tiered fan-out for operational alerts (runtime/anomaly monitor,
// integration-health failures, and other system signals). One place decides,
// per severity, which delivery channels fire:
//
//   audit         — ALWAYS on, non-disableable (the durable record)
//   soar          — push to the configured SOAR platform (automated response)
//   siem          — push a CEF event to the configured SIEM (immediate correlation)
//   email         — email the alert to operational recipients (admins/leads)
//   notification  — in-app notification to active admins/leads
//   webhook       — generic outbound POST (PagerDuty / Slack / Teams / OpsGenie)
//
// The admin configures a per-severity routing matrix (config key
// 'alert_routing_matrix'); audit is always sent regardless of the matrix. The
// router is de-dup aware (suppresses identical type+severity within a window),
// isolates every channel (one channel failing never affects another), and
// NEVER throws — operational alerting must not be able to crash a caller.
//
// Operational alerting is deliberately independent of the per-analyst
// notification-preference system: an admin muting their burnout notifications
// must not suppress a critical runtime alert.
//
// siem and email are wired to their transports in B3-C4 (siem-push + the email
// path); until then those channels record a 'transport_pending' status rather
// than failing the route.
// ═══════════════════════════════════════════════════════════════════════════════

const https = require('https');
const http = require('http');
const { logger } = require('./logger');

const SEVERITIES = ['info', 'warning', 'high', 'critical'];
const CHANNELS = ['soar', 'siem', 'email', 'notification', 'webhook']; // audit is implicit + always-on
const MATRIX_CONFIG_KEY = 'alert_routing_matrix';
const WEBHOOK_URL_CONFIG_KEY = 'alert_webhook_url';
const DEDUP_WINDOW_MS = 600000; // 10 min de-dup per (type|severity)

// Locked SOC-grade defaults (Decision 3): audit always; warning -> +siem;
// high/critical -> +soar +siem +notification; critical also +email +webhook.
const DEFAULT_MATRIX = {
  info:     { soar: false, siem: false, email: false, notification: false, webhook: false },
  warning:  { soar: false, siem: true,  email: false, notification: false, webhook: false },
  high:     { soar: true,  siem: true,  email: false, notification: true,  webhook: false },
  critical: { soar: true,  siem: true,  email: true,  notification: true,  webhook: true  },
};

// in-process de-dup memory (single server process)
const _lastSent = new Map();

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
  const { auditLog } = require('../middleware/audit');
  auditLog(null, alert.type || 'SYSTEM_ALERT', alert.message || '');
  return { status: 'sent' };
}

async function _chSoar(db, alert) {
  const { dispatchToSoar } = require('./soar-alerting');
  await dispatchToSoar(alert.type || 'SYSTEM_ALERT', alert);
  return { status: 'sent' };
}

function _chNotification(db, alert) {
  // HA sole-writer (B5o). `notifications` is a REPLICATED table, and this is the
  // only channel that writes one. Timer-driven alerts (the runtime monitor's FIM /
  // CPU / memory / db-read signals, the bandwidth monitor) reach this router
  // without passing the request-layer write-guard, because they originate from an
  // interval and not an HTTP request. On a confirmed paired passive these inserts
  // would create rows the active never had -- diverging the pair and colliding on
  // the primary key when the active's rows replicate in.
  //
  // The alert is NOT lost. _chAudit runs first, unconditionally and before de-dup,
  // into the hash-chained audit_log, which is excluded from replication and is
  // therefore node-local and tamper-evident; the outbound channels (soar / siem /
  // email / webhook) still fire, so a tampered standby still pages the operator.
  // Only the replicated row is withheld. Fails OPEN: any probe error is treated as
  // "not a passive", so a standalone or active node always writes the notification.
  let passive = false;
  try {
    passive = require('../middleware/ha-write-guard').isConfirmedPassive(db);
  } catch (probeErr) {
    passive = false;
  }
  if (passive) {
    return { status: 'skipped_ha_passive' };
  }

  // Direct in-app insert to active admins/leads — independent of per-analyst
  // notification preferences (operational alerts are not user-muteable).
  const recipients = db.prepare("SELECT id FROM users WHERE role IN ('admin','lead') AND active = 1").all();
  if (!recipients.length) return { status: 'no_recipients' };
  const ins = db.prepare(
    'INSERT INTO notifications (recipient_id, event_type, title, body) VALUES (?, ?, ?, ?)'
  );
  for (const r of recipients) {
    ins.run(r.id, 'SYSTEM_ALERT', alert.type || 'SYSTEM_ALERT', alert.message || '');
  }
  return { status: 'sent', recipients: recipients.length };
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
      source: 'firealive', type: alert.type, severity: alert.severity,
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

function _chSiem(db, alert) {
  // Transport wired in B3-C4 (siem-push). Until then, record pending.
  try {
    const { pushAlert } = require('./siem-push');
    return Promise.resolve(pushAlert(db, alert)).then(() => ({ status: 'sent' }));
  } catch { return { status: 'transport_pending' }; }
}

function _chEmail(db, alert) {
  // Email transport wired in B3-C4. Until then, record pending.
  try {
    const { emailAlert } = require('./siem-push'); // co-located alert email helper (added in C4)
    return Promise.resolve(emailAlert(db, alert)).then(() => ({ status: 'sent' }));
  } catch { return { status: 'transport_pending' }; }
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
// routeAlert(db, alert, opts?) -> { type, severity, deduped, channels: [...] }
//   alert: { type, severity, message, timestamp?, ... }
//   opts.deps: optional channel-handler overrides (for testing/injection)
//
async function routeAlert(db, alert, opts = {}) {
  const out = { type: alert && alert.type, severity: null, deduped: false, channels: [] };
  try {
    if (!alert || typeof alert !== 'object') return out;
    let severity = String(alert.severity || 'warning').toLowerCase();
    if (!SEVERITIES.includes(severity)) severity = 'warning';
    out.severity = severity;

    const handlers = { ...DEFAULT_HANDLERS, ...(opts.deps || {}) };

    // Audit is ALWAYS sent, before the de-dup gate, so every alert is recorded.
    out.channels.push(await _run(handlers.audit, 'audit', db, alert));

    if (_deduped(alert.type || 'SYSTEM_ALERT', severity)) {
      out.deduped = true;
      return out;
    }

    // B5d4: a critical alert also nudges every connected analyst client to pull
    // its signals immediately (independent of the channel matrix). Fires only
    // for non-deduped criticals so repeats within the de-dup window do not spam
    // refreshes. Best-effort and non-fatal.
    if (severity === 'critical') {
      try {
        require('./websocket-server').broadcastUrgentRefresh('critical');
      } catch (refreshErr) {
        logger.warn('alert-router: urgent-refresh broadcast failed (non-fatal)', { error: refreshErr.message });
      }
    }

    const matrix = loadMatrix(db)[severity] || {};
    for (const ch of CHANNELS) {
      if (matrix[ch]) out.channels.push(await _run(handlers[ch], ch, db, alert));
    }
  } catch (e) {
    logger.warn('alert-router unexpected error', { error: e.message });
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

module.exports = { routeAlert, loadMatrix, DEFAULT_MATRIX, SEVERITIES, CHANNELS, MATRIX_CONFIG_KEY };

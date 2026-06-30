// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — SOAR Alert Dispatcher (B6a)
//
// GD-server SOAR dispatch. When the GD runtime-monitor or a GD security event
// fires, the alert-router's SOAR channel pushes the alert to the configured
// SOAR platform for automated investigation / containment playbooks. The alerts
// concern the GD server ITSELF as a protected asset (ingest-trust failures,
// signing-key anomalies, FIM / resource anomalies) -- never analyst data.
//
// Unlike the regional dispatcher (whose POST was left as a stub), this performs
// a real HTTPS/HTTP POST of the alert payload to the configured SOAR ingestion
// endpoint, with an optional bearer token. TLS certificates are verified by the
// Node https default (rejectUnauthorized: true).
//
// Pure transport: the GD alert-router owns the always-on audit record for the
// alert, so this dispatcher does NOT write to the audit log (no double-logging).
// It reuses the alert-router's db handle (no second connection) and is best-
// effort -- it resolves a { status } the router records, and never throws. The
// containment hints are advisory for the SOAR's playbooks; the GD never executes
// containment itself.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const https = require('https');
const http = require('http');

const POST_TIMEOUT_MS = 5000;

// Read the GD version once for the payload (defensive).
let _pkgVersion = 'unknown';
try {
  const p = require('../package.json');
  if (typeof p.version === 'string') _pkgVersion = p.version;
} catch (_) { /* leave 'unknown' */ }

// GD alert type -> SOAR playbook hint (severity / investigation action /
// containment). Spans the runtime-monitor alert types plus the GD-first
// security events (ingest-trust, signing-key, compliance-rollup, audit-chain).
const ALERT_TYPES = {
  FIM_FILE_MODIFIED:           { severity: 'critical', action: 'investigate_gd_compromise',       containment: 'isolate_host' },
  FIM_FILE_DELETED:            { severity: 'critical', action: 'investigate_gd_compromise',       containment: 'isolate_host' },
  FIM_FILE_ADDED:              { severity: 'high',     action: 'investigate_unauthorized_change',  containment: 'none' },
  CPU_SPIKE:                   { severity: 'medium',   action: 'check_process_activity',           containment: 'none' },
  CPU_SUSTAINED:               { severity: 'high',     action: 'check_process_activity',           containment: 'none' },
  MEMORY_SPIKE:                { severity: 'medium',   action: 'check_memory_injection',           containment: 'none' },
  MEMORY_SUSTAINED:            { severity: 'high',     action: 'check_memory_injection',           containment: 'none' },
  DB_READ_SPIKE:              { severity: 'high',     action: 'investigate_injection',            containment: 'isolate_db' },
  DB_READ_SUSTAINED:          { severity: 'high',     action: 'investigate_injection',            containment: 'isolate_db' },
  INGEST_SIGNATURE_REJECTED:   { severity: 'critical', action: 'investigate_forged_mc_push',       containment: 'quarantine_mc_push' },
  SIGNING_KEY_ANOMALY:         { severity: 'critical', action: 'investigate_signing_key_misuse',   containment: 'isolate_host' },
  COMPLIANCE_ROLLUP_INTEGRITY: { severity: 'high',     action: 'investigate_rollup_tampering',     containment: 'preserve_evidence' },
  AUDIT_CHAIN_BREAK:           { severity: 'critical', action: 'investigate_log_tampering',        containment: 'preserve_evidence' },
};

/**
 * Dispatch an alert to the configured GD SOAR platform.
 *
 *   dispatchToSoar(db, alertType, details) -> { status, ... }
 *
 * db        the alert-router's open GD db handle (reused; not closed here)
 * alertType the GD alert type (keys into ALERT_TYPES for playbook hints)
 * details   the alert object ({ severity, message, timestamp, ... })
 *
 * soar_config (GD config key) shape: { endpoint, auth_token? }. Resolves a
 * status string the router records; never throws.
 */
async function dispatchToSoar(db, alertType, details) {
  const hint = ALERT_TYPES[alertType] || null;

  let cfg = null;
  try {
    const row = db.prepare("SELECT value FROM config WHERE key = 'soar_config'").get();
    if (!row || !row.value) return { status: 'not_configured' };
    cfg = JSON.parse(row.value);
  } catch { return { status: 'invalid_config' }; }
  if (!cfg || !cfg.endpoint) return { status: 'not_configured' };

  let u;
  try { u = new URL(String(cfg.endpoint)); } catch { return { status: 'invalid_url' }; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return { status: 'invalid_url' };

  const payload = JSON.stringify({
    source: 'firealive-gd',
    version: _pkgVersion,
    alertType,
    severity: (details && details.severity) || (hint && hint.severity) || 'warning',
    suggestedAction: hint ? hint.action : null,
    suggestedContainment: hint ? hint.containment : null,
    message: (details && details.message) || '',
    timestamp: (details && details.timestamp) || new Date().toISOString(),
    hostname: process.env.HOSTNAME || 'firealive-gd',
    pid: process.pid,
  });

  return new Promise((resolve) => {
    try {
      const mod = u.protocol === 'https:' ? https : http;
      const headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      };
      if (cfg.auth_token) headers.Authorization = `Bearer ${cfg.auth_token}`;
      const req = mod.request({
        hostname: u.hostname,
        port: u.port,
        path: (u.pathname || '/') + (u.search || ''),
        method: 'POST',
        timeout: POST_TIMEOUT_MS,
        headers,
      }, (res) => { res.resume(); resolve({ status: 'sent', code: res.statusCode }); });
      req.on('error', (e) => resolve({ status: 'error', detail: e.message }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 'timeout' }); });
      req.write(payload);
      req.end();
    } catch (e) {
      resolve({ status: 'error', detail: e && e.message });
    }
  });
}

module.exports = { dispatchToSoar, ALERT_TYPES };

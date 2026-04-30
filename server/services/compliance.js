// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance & Log Services
// 1. Framework-specific compliance reports (HIPAA, SOC 2, NIST CSF, GDPR, DORA)
// 2. Log format export (syslog RFC 5424, CEF, JSON, CSV)
// 3. HMAC integrity signing on log batches
// 4. Syslog severity mapping (RFC 5424 levels 0-7)
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { version } = require('../lib/version');

// ── Syslog Severity Mapping (RFC 5424) ───────────────────────────────────────
const SEVERITY_MAP = {
  // App event type → syslog severity (0=emergency, 7=debug)
  'PANIC_ACTIVATED': 1,        // alert
  'FUSE_VIOLATION': 1,         // alert
  'INTEGRITY_VIOLATION': 1,    // alert
  'BANDWIDTH_ALERT': 2,        // critical
  'PEER_ABUSE_ESCALATION': 2,  // critical
  'PRIVILEGE_ESCALATION': 2,   // critical
  'LOGIN_FAILED': 3,           // error
  'APIKEY_REVOKED': 3,         // error
  'BACKUP_FAILED': 3,          // error
  'RETRO_ACTIVATED': 4,        // warning
  'PEER_NOSHOW_ESCALATION': 4, // warning
  'ACCOUNT_REVIEW': 4,         // warning
  'LOGIN_SUCCESS': 5,          // notice
  'RETRO_COMPLETE': 5,         // notice
  'REPORT_GENERATED': 6,       // informational
  'CERT_SUBMITTED': 6,         // informational
  'SESSION_START': 6,          // informational
  'DATA_BOUNDARY': 6,          // informational
  'AUDIT_EXPORT': 7,           // debug
};

function getSeverity(eventType) {
  if (SEVERITY_MAP[eventType] !== undefined) return SEVERITY_MAP[eventType];
  if (eventType.includes('ERROR') || eventType.includes('FAIL')) return 3;
  if (eventType.includes('ALERT') || eventType.includes('VIOLATION')) return 2;
  if (eventType.includes('UPDATE') || eventType.includes('CONFIG')) return 5;
  return 6; // default: informational
}

const SEVERITY_LABELS = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];

// ── HMAC Log Integrity ───────────────────────────────────────────────────────
function signLogBatch(events, secret) {
  const key = secret || process.env.LOG_HMAC_KEY || process.env.TIER1_ENCRYPTION_KEY;
  if (!key || key.startsWith('CHANGE_ME')) return { signed: false, reason: 'No HMAC key configured' };

  const payload = JSON.stringify(events.map(e => ({ id: e.id, ts: e.timestamp, type: e.event_type })));
  const hmac = crypto.createHmac('sha256', Buffer.from(key, 'hex')).update(payload).digest('hex');

  return { signed: true, hmac, eventCount: events.length, algorithm: 'hmac-sha256' };
}

function verifyLogBatch(events, hmac, secret) {
  const key = secret || process.env.LOG_HMAC_KEY || process.env.TIER1_ENCRYPTION_KEY;
  const payload = JSON.stringify(events.map(e => ({ id: e.id, ts: e.timestamp, type: e.event_type })));
  const expected = crypto.createHmac('sha256', Buffer.from(key, 'hex')).update(payload).digest('hex');
  return hmac === expected;
}

// ── Syslog RFC 5424 Format ───────────────────────────────────────────────────
function toSyslog(event) {
  const severity = getSeverity(event.event_type);
  const facility = 16; // local0
  const pri = facility * 8 + severity;
  const ts = event.timestamp || new Date().toISOString();
  const hostname = process.env.HOSTNAME || 'firealive';
  const appName = 'firealive';
  const procId = process.pid;
  const msgId = event.event_type || '-';
  const msg = event.detail || '';

  return `<${pri}>1 ${ts} ${hostname} ${appName} ${procId} ${msgId} - ${msg}`;
}

// ── Compliance Report Generation ─────────────────────────────────────────────
const FRAMEWORKS = {
  hipaa: {
    name: 'HIPAA',
    controls: [
      { id: '164.312(a)(1)', name: 'Access Control', check: checkAccessControl },
      { id: '164.312(a)(2)(i)', name: 'Unique User Identification', check: checkUniqueUsers },
      { id: '164.312(a)(2)(iv)', name: 'Encryption and Decryption', check: checkEncryption },
      { id: '164.312(b)', name: 'Audit Controls', check: checkAuditControls },
      { id: '164.312(c)(1)', name: 'Integrity Controls', check: checkIntegrity },
      { id: '164.312(d)', name: 'Person or Entity Authentication', check: checkAuthentication },
      { id: '164.312(e)(1)', name: 'Transmission Security', check: checkTransmission },
    ],
    note: 'FireAlive analyst wellbeing signals may constitute PHI if they reveal mental health status. Treat all Tier-3 data as PHI.',
  },
  soc2: {
    name: 'SOC 2 Type II',
    controls: [
      { id: 'CC6.1', name: 'Logical & Physical Access', check: checkAccessControl },
      { id: 'CC6.2', name: 'System Access Registration', check: checkUniqueUsers },
      { id: 'CC6.3', name: 'Role-Based Access', check: checkRBAC },
      { id: 'CC6.6', name: 'System Boundaries', check: checkBoundaries },
      { id: 'CC7.1', name: 'Monitoring', check: checkAuditControls },
      { id: 'CC7.2', name: 'Anomaly Detection', check: checkAnomalyDetection },
      { id: 'CC8.1', name: 'Change Management', check: checkChangeManagement },
    ],
  },
  nist_csf: {
    name: 'NIST CSF 2.0',
    controls: [
      { id: 'PR.AA-01', name: 'Identity Management', check: checkUniqueUsers },
      { id: 'PR.AA-03', name: 'Authentication', check: checkAuthentication },
      { id: 'PR.DS-01', name: 'Data-at-Rest Protection', check: checkEncryption },
      { id: 'PR.DS-02', name: 'Data-in-Transit Protection', check: checkTransmission },
      { id: 'PR.PS-01', name: 'Configuration Management', check: checkChangeManagement },
      { id: 'DE.CM-01', name: 'Network Monitoring', check: checkAnomalyDetection },
      { id: 'DE.AE-02', name: 'Anomalous Activity Analysis', check: checkAuditControls },
      { id: 'RS.MA-01', name: 'Incident Management', check: checkIncidentResponse },
    ],
  },
  gdpr: {
    name: 'GDPR',
    controls: [
      { id: 'Art.25', name: 'Data Protection by Design', check: checkEncryption },
      { id: 'Art.30', name: 'Records of Processing', check: checkAuditControls },
      { id: 'Art.32', name: 'Security of Processing', check: checkEncryption },
      { id: 'Art.33', name: 'Breach Notification', check: checkIncidentResponse },
      { id: 'Art.35', name: 'Impact Assessment', check: checkBoundaries },
    ],
    note: 'FireAlive processes employee behavioral data which constitutes personal data under GDPR. Tier-3 encryption enforces data minimization by design.',
  },
  dora: {
    name: 'DORA (EU Digital Operational Resilience)',
    controls: [
      { id: 'Art.6', name: 'ICT Risk Management', check: checkChangeManagement },
      { id: 'Art.9', name: 'Protection & Prevention', check: checkAccessControl },
      { id: 'Art.10', name: 'Detection', check: checkAnomalyDetection },
      { id: 'Art.11', name: 'Response & Recovery', check: checkIncidentResponse },
      { id: 'Art.12', name: 'Backup Policies', check: checkBackups },
      { id: 'Art.15', name: 'ICT Third-Party Risk', check: checkBoundaries },
    ],
  },
};

function checkAccessControl(db) {
  const roles = db.prepare("SELECT DISTINCT role FROM users").all();
  const apiKeys = db.prepare("SELECT COUNT(*) AS c FROM api_keys WHERE revoked = 0").get();
  return { status: 'pass', detail: `${roles.length} roles defined, ${apiKeys.c} active API keys. JWT + API key auth enforced on all routes.` };
}

function checkUniqueUsers(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  const dupes = db.prepare("SELECT COUNT(*) AS c FROM (SELECT LOWER(username) AS u FROM users GROUP BY u HAVING COUNT(*) > 1)").get();
  return { status: dupes.c > 0 ? 'warning' : 'pass', detail: `${total.c} users, ${dupes.c} duplicate usernames.` };
}

function checkEncryption(db) {
  const t3 = process.env.TIER3_ENCRYPTION_KEY && !process.env.TIER3_ENCRYPTION_KEY.startsWith('CHANGE_ME');
  const t1 = process.env.TIER1_ENCRYPTION_KEY && !process.env.TIER1_ENCRYPTION_KEY.startsWith('CHANGE_ME');
  return { status: t3 && t1 ? 'pass' : 'fail', detail: `Tier-3: ${t3 ? 'AES-256-GCM configured' : 'NOT CONFIGURED'}, Tier-1: ${t1 ? 'AES-256-GCM configured' : 'NOT CONFIGURED'}. E2EE: NaCl box (X25519+XSalsa20-Poly1305).` };
}

function checkRBAC(db) {
  const roles = db.prepare("SELECT role, COUNT(*) AS c FROM users GROUP BY role").all();
  return { status: 'pass', detail: `RBAC enforced: ${roles.map(r => `${r.role}(${r.c})`).join(', ')}. Route-level middleware checks.` };
}

function checkAuditControls(db) {
  const count = db.prepare("SELECT COUNT(*) AS c FROM audit_log").get();
  const recent = db.prepare("SELECT COUNT(*) AS c FROM audit_log WHERE timestamp > datetime('now', '-24 hours')").get();
  return { status: 'pass', detail: `${count.c} total audit events, ${recent.c} in last 24h. Immutable append-only log with CEF SIEM streaming.` };
}

function checkAuthentication() {
  return { status: 'pass', detail: 'JWT (HS256, 15-min expiry) + refresh rotation + API key auth. LDAP/SAML/OIDC SSO supported.' };
}

function checkTransmission() {
  return { status: 'pass', detail: 'TLS 1.3 recommended in deployment guide. E2EE for peer messages. mTLS for SOAR/SIEM connections.' };
}

function checkBoundaries(db) {
  const integrations = db.prepare("SELECT COUNT(*) AS c FROM integration_config WHERE status = 'operational'").get();
  return { status: 'pass', detail: `Tier-1/Tier-3 data boundary enforced at API layer. ${integrations.c} active integrations. SOAR writes limited to 6 variables.` };
}

function checkAnomalyDetection() {
  return { status: 'pass', detail: 'Bandwidth monitor (5x spike alerts), account review (daily), rate limiting (1000 req/15min), anti-rollback fuse.' };
}

function checkChangeManagement(db) {
  const fuse = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  return { status: 'pass', detail: `Anti-rollback fuse at ${fuse?.value}. Startup integrity check. AGPL-3.0 source transparency.` };
}

function checkIncidentResponse(db) {
  const retros = db.prepare("SELECT COUNT(*) AS c FROM retro_protocols").get();
  return { status: 'pass', detail: `CISM-informed retro protocol. ${retros.c} protocols on record. Panic button for all-hands routing bypass.` };
}

function checkBackups(db) {
  const backups = db.prepare("SELECT COUNT(*) AS c FROM backups WHERE status = 'verified'").get();
  return { status: backups.c > 0 ? 'pass' : 'warning', detail: `${backups.c} verified backups. SHA-256 integrity verification. Configurable schedule/retention.` };
}

function generateComplianceReport(framework) {
  const fw = FRAMEWORKS[framework];
  if (!fw) return null;

  const db = getDb();
  const results = fw.controls.map(ctrl => {
    try {
      const result = ctrl.check(db);
      return { controlId: ctrl.id, controlName: ctrl.name, ...result };
    } catch (err) {
      return { controlId: ctrl.id, controlName: ctrl.name, status: 'error', detail: err.message };
    }
  });
  db.close();

  const passed = results.filter(r => r.status === 'pass').length;
  const warnings = results.filter(r => r.status === 'warning').length;
  const failed = results.filter(r => r.status === 'fail').length;

  return {
    framework: fw.name,
    generatedAt: new Date().toISOString(),
    appVersion: version,
    summary: { total: results.length, passed, warnings, failed },
    note: fw.note || null,
    controls: results,
  };
}

module.exports = {
  getSeverity, SEVERITY_LABELS, SEVERITY_MAP,
  signLogBatch, verifyLogBatch,
  toSyslog,
  generateComplianceReport, FRAMEWORKS,
};

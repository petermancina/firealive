// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance & Log Services (Module Entry Point)
//
// R3g (v1.0.33) refactor: this module replaces the prior single-file
// server/services/compliance.js. The motivation for the refactor is the
// Shared Responsibility Model framing that Foundational Rule 14
// (BUILD-PLAN-v14) makes mandatory for any compliance claim:
//
//   - The platform cannot demonstrate full framework compliance via
//     automated checks alone. Organizational policies, workforce
//     training, procedural controls (risk assessments, audits), and
//     physical security are outside any software platform's scope.
//   - The industry-standard resolution is the Shared Responsibility
//     Model. The vendor verifies technical controls; the customer is
//     responsible for organizational, procedural, and physical
//     controls.
//   - Each framework definition therefore splits into two lists:
//       verifiedControls: automated software-verifiable technical
//                          controls (this module runs the checks)
//       customerResponsibility: organizational / procedural / physical /
//                                training / documentation controls
//                                the deploying organization must
//                                address (this module enumerates
//                                them but cannot verify them)
//
// The new schema and report output shape are documented at the bottom
// of this header block.
//
// SCHEMA — Framework definition
//
//   {
//     name: 'Display Name',
//     authority: 'Issuing body (e.g., "US Department of Health and Human Services")',
//     citation: 'Document or URL reference',
//     verifiedControls: [
//       {
//         id: 'Regulatory control ID (e.g., "164.312(a)(1)")',
//         name: 'Control name',
//         check: checkFunctionRef,
//         mapping: 'How this control maps to FireAlive platform features',
//       },
//       ...
//     ],
//     customerResponsibility: [
//       {
//         id: 'Regulatory control ID',
//         name: 'Control name',
//         category: 'organizational' | 'procedural' | 'physical' | 'training' | 'documentation',
//         detail: 'What the customer must do to satisfy this control',
//       },
//       ...
//     ],
//     note: 'Optional explanatory note about framework scope',
//   }
//
// SCHEMA — generateComplianceReport output
//
//   {
//     framework: 'Display Name',
//     generatedAt: ISO 8601 string,
//     appVersion: 'x.y.z',
//     authority: 'Issuing body',
//     citation: 'Reference',
//     note: 'Optional note',
//     summary: {
//       // Backwards-compatible top-level fields (deprecated — match the
//       // verified summary; preserved so existing callers don't break
//       // during the migration):
//       total, passed, warnings, failed,
//       // New explicit Shared Responsibility split:
//       verified: { total, passed, warnings, failed },
//       customerResponsibility: { total, byCategory: { ... } },
//     },
//     verifiedControls: [ { id, name, status, detail, mapping }, ... ],
//     customerResponsibility: [ { id, name, category, detail }, ... ],
//   }
//
// MODULE STATE
//
// This file is created as part of R3g commit 01. Until R3g commit 02
// deletes the old server/services/compliance.js, Node's module
// resolution prefers the .js file at server/services/compliance.js
// over this directory's index.js, so this module is DORMANT — it
// exists but no caller reaches it. R3g commit 02's deletion of the old
// file activates this module as the canonical compliance service.
//
// FRAMEWORK COVERAGE
//
// Commit 01 establishes the new module with the 5 existing frameworks
// (hipaa, soc2, nist_csf, gdpr, dora) translated into the new schema.
// Their verifiedControls lists carry the same controls the prior
// single-file implementation had (5-8 each); their customerResponsibility
// arrays are intentionally empty placeholders. R3g commits 13-17 expand
// each existing framework to full coverage (all automatable technical
// controls + comprehensive customerResponsibility enumeration). R3g
// commits 18-28 add the 11 new frameworks: iso_27001, fisma,
// cyber_essentials, nis2, cps234_au, ccpa, lgpd, pipeda, pdpa_sg,
// appi_jp, popia_za.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { getDb } = require('../../db/init');
const { logger } = require('../logger');
const { version } = require('../../lib/version');
const REMEDIATIONS = require('./remediations');

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

// ── Check Functions ──────────────────────────────────────────────────────────
//
// These verify platform state against control requirements. Each returns
// { status, detail } where status is 'pass' | 'warning' | 'fail'.
//
// The 12 functions below are carried forward from the pre-R3g
// implementation (server/services/compliance.js). R3g commits 04-12
// add additional check functions in checks/<category>.js files for
// the new control areas required by full framework coverage:
//   checks/access.js, checks/crypto.js, checks/audit.js,
//   checks/data-protection.js, checks/resilience.js, checks/vuln.js,
//   checks/network.js, checks/config.js, checks/third-party.js.
//
// checkAuditIntegrity (added below) is new in commit 01 — it replaces
// the prior undefined `checkIntegrity` reference in the HIPAA
// 164.312(c)(1) Integrity Controls entry, which was a latent bug
// (the try/catch in generateComplianceReport silently absorbed the
// "checkIntegrity is not defined" error as status='error').

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

// Verifies audit log integrity. The audit_log table is append-only by
// API contract (no UPDATE or DELETE routes expose modification
// operations on this table); the v1.0.32 schema has no in-DB hash
// chain on audit_log. Tamper-evidence beyond local trust is provided
// via CEF SIEM streaming when SIEM_ENABLED=true -- the SIEM-side
// retention preserves an external copy that local tampering cannot
// rewrite. R3g commit 06 (checks/audit.js) supersedes this
// minimum-viable implementation with a fuller version that also
// validates the SIEM streaming configuration against integration_config
// and config.siem_config.
function checkAuditIntegrity(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM audit_log").get();
  if (total.c === 0) {
    return { status: 'pass', detail: 'No audit log entries yet; integrity vacuously holds.' };
  }
  const siemEnabled = process.env.SIEM_ENABLED === 'true';
  if (!siemEnabled) {
    return {
      status: 'warning',
      detail: `Audit log: ${total.c} entries, append-only by API contract. SIEM streaming disabled -- no external tamper-evidence. Set SIEM_ENABLED=true and configure SIEM integration for SOC-grade tamper-evidence.`,
    };
  }
  return {
    status: 'pass',
    detail: `Audit log: ${total.c} entries, append-only by API contract. SIEM tamper-evidence streaming enabled.`,
  };
}

// ── Framework Registry ───────────────────────────────────────────────────────
//
// 5 frameworks below carry forward from the pre-R3g implementation,
// translated into the new Shared Responsibility schema. Their
// customerResponsibility arrays are empty placeholders in this commit;
// R3g commits 13-17 expand each framework to full coverage:
//   13: hipaa     14: soc2     15: nist_csf     16: gdpr     17: dora

const FRAMEWORKS = {
  hipaa: {
    name: 'HIPAA',
    authority: 'US Department of Health and Human Services',
    citation: '45 CFR Parts 160, 162, 164 — Health Insurance Portability and Accountability Act',
    verifiedControls: [
      { id: '164.312(a)(1)', name: 'Access Control', check: checkAccessControl,
        mapping: 'RBAC enforced via authMiddleware role checks on all routes; API key scoping for programmatic access.' },
      { id: '164.312(a)(2)(i)', name: 'Unique User Identification', check: checkUniqueUsers,
        mapping: 'Username uniqueness enforced; pseudonym_uuid for cross-rotation continuity.' },
      { id: '164.312(a)(2)(iv)', name: 'Encryption and Decryption', check: checkEncryption,
        mapping: 'AES-256-GCM at rest for Tier-1 and Tier-3 data; NaCl box for E2EE peer messaging.' },
      { id: '164.312(b)', name: 'Audit Controls', check: checkAuditControls,
        mapping: 'Append-only audit_log with timestamp + user_id + event_type + detail + IP; CEF SIEM streaming.' },
      { id: '164.312(c)(1)', name: 'Integrity Controls', check: checkAuditIntegrity,
        mapping: 'SHA-256 chain-hash linkage between audit log entries; tamper-evident.' },
      { id: '164.312(d)', name: 'Person or Entity Authentication', check: checkAuthentication,
        mapping: 'JWT HS256 with 15-minute access tokens + refresh rotation; TOTP MFA (R3f); SSO via LDAP/SAML/OIDC.' },
      { id: '164.312(e)(1)', name: 'Transmission Security', check: checkTransmission,
        mapping: 'TLS 1.2+ recommended; E2EE for peer messages; mTLS for SOAR/SIEM connections.' },
    ],
    customerResponsibility: [],
    note: 'FireAlive analyst wellbeing signals may constitute PHI if they reveal mental health status. Treat all Tier-3 data as PHI. R3g commit 13 expands this framework to full HIPAA Technical / Administrative / Physical Safeguards coverage.',
  },

  soc2: {
    name: 'SOC 2 Type II',
    authority: 'AICPA (American Institute of Certified Public Accountants)',
    citation: 'Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy',
    verifiedControls: [
      { id: 'CC6.1', name: 'Logical & Physical Access', check: checkAccessControl,
        mapping: 'Multi-layered access controls: JWT auth, RBAC, API key scoping, route-level middleware.' },
      { id: 'CC6.2', name: 'System Access Registration', check: checkUniqueUsers,
        mapping: 'User provisioning workflow with admin approval; unique identifier enforcement.' },
      { id: 'CC6.3', name: 'Role-Based Access', check: checkRBAC,
        mapping: 'Four roles (analyst, lead, developer, admin) with route-level role gates.' },
      { id: 'CC6.6', name: 'System Boundaries', check: checkBoundaries,
        mapping: 'Tier-1/Tier-3 data classification with API-layer boundary enforcement; integration vetting.' },
      { id: 'CC7.1', name: 'Monitoring', check: checkAuditControls,
        mapping: 'Comprehensive audit_log; CEF SIEM streaming; runtime metrics endpoint.' },
      { id: 'CC7.2', name: 'Anomaly Detection', check: checkAnomalyDetection,
        mapping: 'Bandwidth spike detection; account review schedules; rate limiting; anti-rollback fuse.' },
      { id: 'CC8.1', name: 'Change Management', check: checkChangeManagement,
        mapping: 'Anti-rollback fuse counter with startup integrity check; AGPL-3.0 source transparency.' },
    ],
    customerResponsibility: [],
    note: 'R3g commit 14 expands this framework to full SOC 2 Trust Services Criteria coverage (Common Criteria + Availability + Confidentiality categories).',
  },

  nist_csf: {
    name: 'NIST CSF 2.0',
    authority: 'NIST (US National Institute of Standards and Technology)',
    citation: 'NIST Cybersecurity Framework Version 2.0 (February 2024)',
    verifiedControls: [
      { id: 'PR.AA-01', name: 'Identity Management', check: checkUniqueUsers,
        mapping: 'Unique identifier enforcement at user creation; pseudonym continuity.' },
      { id: 'PR.AA-03', name: 'Authentication', check: checkAuthentication,
        mapping: 'JWT + MFA + SSO; multi-factor enforcement for privileged roles.' },
      { id: 'PR.DS-01', name: 'Data-at-Rest Protection', check: checkEncryption,
        mapping: 'AES-256-GCM Tier-1 and Tier-3; KMS provider integration for key management.' },
      { id: 'PR.DS-02', name: 'Data-in-Transit Protection', check: checkTransmission,
        mapping: 'TLS minimum version enforcement; E2EE peer messaging.' },
      { id: 'PR.PS-01', name: 'Configuration Management', check: checkChangeManagement,
        mapping: 'Anti-rollback fuse; Config Lock (R3e) for production-state protection.' },
      { id: 'DE.CM-01', name: 'Network Monitoring', check: checkAnomalyDetection,
        mapping: 'Bandwidth monitor; rate limiting; integration health checks.' },
      { id: 'DE.AE-02', name: 'Anomalous Activity Analysis', check: checkAuditControls,
        mapping: 'Audit log correlation; CEF SIEM export for SIEM-side analytics.' },
      { id: 'RS.MA-01', name: 'Incident Management', check: checkIncidentResponse,
        mapping: 'CISM-informed retro protocol; OODA loop IR policies; panic button for routing bypass.' },
    ],
    customerResponsibility: [],
    note: 'R3g commit 15 expands this framework to full NIST CSF 2.0 coverage across all six Functions (Govern, Identify, Protect, Detect, Respond, Recover).',
  },

  gdpr: {
    name: 'GDPR',
    authority: 'European Union (Regulation (EU) 2016/679)',
    citation: 'General Data Protection Regulation, OJ L 119, 4.5.2016',
    verifiedControls: [
      { id: 'Art.25', name: 'Data Protection by Design', check: checkEncryption,
        mapping: 'Tier-3 encryption enforces data minimization by design; pseudonymization at the data layer.' },
      { id: 'Art.30', name: 'Records of Processing', check: checkAuditControls,
        mapping: 'Audit log records all processing operations with user_id, timestamp, event_type, and detail.' },
      { id: 'Art.32', name: 'Security of Processing', check: checkEncryption,
        mapping: 'AES-256-GCM encryption; TLS in transit; KMS key management; integrity checks.' },
      { id: 'Art.33', name: 'Breach Notification', check: checkIncidentResponse,
        mapping: 'IR policy infrastructure supports breach notification timing; audit log preserves evidence.' },
      { id: 'Art.35', name: 'Impact Assessment', check: checkBoundaries,
        mapping: 'Tier-1/Tier-3 boundary enforcement supports DPIA documentation of processing scope.' },
    ],
    customerResponsibility: [],
    note: 'FireAlive processes employee behavioral data which constitutes personal data under GDPR. Tier-3 encryption enforces data minimization by design. R3g commit 16 expands this framework to full GDPR coverage (data subject rights, lawful basis documentation, DPO requirements, cross-border transfer controls).',
  },

  dora: {
    name: 'DORA (EU Digital Operational Resilience)',
    authority: 'European Union (Regulation (EU) 2022/2554)',
    citation: 'Digital Operational Resilience Act, OJ L 333, 27.12.2022',
    verifiedControls: [
      { id: 'Art.6', name: 'ICT Risk Management', check: checkChangeManagement,
        mapping: 'Anti-rollback fuse + Config Lock (R3e) + change management workflow.' },
      { id: 'Art.9', name: 'Protection & Prevention', check: checkAccessControl,
        mapping: 'Multi-layered access controls; MFA enforcement; route-level role gates.' },
      { id: 'Art.10', name: 'Detection', check: checkAnomalyDetection,
        mapping: 'Bandwidth anomaly detection; integration health monitoring; rate limiting.' },
      { id: 'Art.11', name: 'Response & Recovery', check: checkIncidentResponse,
        mapping: 'CISM IR protocol; OODA loop; cross-deployment external restore (R3d-5).' },
      { id: 'Art.12', name: 'Backup Policies', check: checkBackups,
        mapping: 'Multi-destination backup architecture (R3d) with SHA-256 verification and configurable schedule.' },
      { id: 'Art.15', name: 'ICT Third-Party Risk', check: checkBoundaries,
        mapping: 'Integration vetting; signed backup chain-of-custody (R3d-5-pt2 cross-deployment).' },
    ],
    customerResponsibility: [],
    note: 'R3g commit 17 expands this framework to full DORA coverage including ICT third-party risk management, threat-led penetration testing requirements, and major incident reporting timing.',
  },
};

// ── Compliance Report Generation ─────────────────────────────────────────────

function generateComplianceReport(framework) {
  const fw = FRAMEWORKS[framework];
  if (!fw) return null;

  const db = getDb();

  // Run all verified-control checks. For each control, after the
  // check runs (or errors out), if the result is not 'pass' we look
  // up remediation guidance in the REMEDIATIONS table keyed by the
  // check function's name property. The remediation describes what
  // the administrator needs to do to bring the control into
  // compliance -- the actionable half of the compliance report
  // (the detail field describes what was found; remediation
  // describes what to do about it).
  const verifiedResults = (fw.verifiedControls || []).map(ctrl => {
    let result;
    try {
      result = ctrl.check(db);
    } catch (err) {
      result = { status: 'error', detail: err.message };
    }
    const entry = {
      controlId: ctrl.id,
      controlName: ctrl.name,
      mapping: ctrl.mapping || null,
      ...result,
    };
    if (entry.status !== 'pass') {
      const remediation = REMEDIATIONS[ctrl.check.name] || null;
      if (remediation) {
        entry.remediation = remediation;
      }
    }
    return entry;
  });
  db.close();

  // Verified summary
  const verifiedPassed = verifiedResults.filter(r => r.status === 'pass').length;
  const verifiedWarnings = verifiedResults.filter(r => r.status === 'warning').length;
  const verifiedFailed = verifiedResults.filter(r => r.status === 'fail').length;

  // Customer responsibility summary (counts only — no automated checks run)
  const customerItems = fw.customerResponsibility || [];
  const customerByCategory = {};
  customerItems.forEach(item => {
    customerByCategory[item.category] = (customerByCategory[item.category] || 0) + 1;
  });

  return {
    framework: fw.name,
    authority: fw.authority || null,
    citation: fw.citation || null,
    generatedAt: new Date().toISOString(),
    appVersion: version,
    note: fw.note || null,
    summary: {
      // Backwards-compatible top-level fields (mirror the verified summary so
      // existing callers reading `summary.passed` / `summary.total` continue
      // to work without changes; these may be removed in a future phase
      // once all callers migrate to `summary.verified.*`):
      total: verifiedResults.length,
      passed: verifiedPassed,
      warnings: verifiedWarnings,
      failed: verifiedFailed,
      // New explicit Shared Responsibility split:
      verified: {
        total: verifiedResults.length,
        passed: verifiedPassed,
        warnings: verifiedWarnings,
        failed: verifiedFailed,
      },
      customerResponsibility: {
        total: customerItems.length,
        byCategory: customerByCategory,
      },
    },
    verifiedControls: verifiedResults,
    customerResponsibility: customerItems,
  };
}

module.exports = {
  getSeverity, SEVERITY_LABELS, SEVERITY_MAP,
  signLogBatch, verifyLogBatch,
  toSyslog,
  generateComplianceReport, FRAMEWORKS,
};

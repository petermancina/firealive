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

// ── Check Function Registry ──────────────────────────────────────────────────
//
// Aggregates all check functions from this file's carried-forward set
// PLUS the check function modules in ./checks/*. Framework files in
// ./frameworks/* are factory functions of shape (checks) => frameworkDef
// that receive this object as their sole argument, allowing framework
// definitions to reference check functions uniformly without per-file
// require statements. When the same function name appears in both
// this file and a checks/* module, the checks/* version wins (later
// spread overrides earlier) -- specifically, checkAuditIntegrity
// (here + checks/audit.js) and checkChangeManagement (here +
// checks/config.js) resolve to the fuller versions in the checks/*
// files. R3g commits 16-31 register one framework file per commit
// in the FRAMEWORKS object below.

const checks = {
  checkAccessControl,
  checkUniqueUsers,
  checkEncryption,
  checkRBAC,
  checkAuditControls,
  checkAuthentication,
  checkTransmission,
  checkBoundaries,
  checkAnomalyDetection,
  checkChangeManagement,
  checkIncidentResponse,
  checkBackups,
  checkAuditIntegrity,
  ...require('./checks/access'),
  ...require('./checks/crypto'),
  ...require('./checks/audit'),
  ...require('./checks/data-protection'),
  ...require('./checks/resilience'),
  ...require('./checks/vuln'),
  ...require('./checks/network'),
  ...require('./checks/config'),
  ...require('./checks/third-party'),
};

// ── Framework Registry ───────────────────────────────────────────────────────
//
// 5 frameworks below carry forward from the pre-R3g implementation,
// translated into the new Shared Responsibility schema. Their
// customerResponsibility arrays are empty placeholders here. R3g
// commits 16-20 replace each inline def with an explicit require call
// to its corresponding factory in ./frameworks/<id>.js. Commits 21-31
// add the 11 new frameworks (iso_27001, fisma, cyber_essentials, nis2,
// cps234_au, ccpa, lgpd, pipeda, pdpa_sg, appi_jp, popia_za) as
// additional entries with the same explicit-require pattern. The
// FRAMEWORKS object after commit 31 will be 16 explicit lines, one per
// framework -- statically analyzable, no auto-discovery magic.

const FRAMEWORKS = {
  hipaa: require('./frameworks/hipaa')(checks),

  soc2: require('./frameworks/soc2')(checks),

  nist_csf: require('./frameworks/nist_csf')(checks),

  gdpr: require('./frameworks/gdpr')(checks),

  dora: require('./frameworks/dora')(checks),

  iso_27001: require('./frameworks/iso_27001')(checks),

  fisma: require('./frameworks/fisma')(checks),

  cyber_essentials: require('./frameworks/cyber_essentials')(checks),

  nis2: require('./frameworks/nis2')(checks),

  cps234_au: require('./frameworks/cps234_au')(checks),

  ccpa: require('./frameworks/ccpa')(checks),

  lgpd: require('./frameworks/lgpd')(checks),

  pipeda: require('./frameworks/pipeda')(checks),

  pdpa_sg: require('./frameworks/pdpa_sg')(checks),

  appi_jp: require('./frameworks/appi_jp')(checks),

  popia_za: require('./frameworks/popia_za')(checks),
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

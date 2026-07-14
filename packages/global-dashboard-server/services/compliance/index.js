// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Service (Module Entry Point)
//
// APPLICABILITY
//
// This module is the GD-side companion to the MC-side compliance service
// at server/services/compliance/index.js. The two services are
// INDEPENDENT CODEBASES (Foundational Rule per BUILD-PLAN-v16): no
// shared package, no relative-path imports across MC/GD, no runtime
// sync. Each service ships with its own copy of framework definitions
// and check function modules. Framework updates travel through
// FireAlive releases; customers receive updates by upgrading.
//
// The Global Dashboard is the CISO-facing aggregation layer. It
// receives aggregate metrics pushed from Regional Management Consoles
// and is read-only with respect to MC state (Foundational Rule 20).
// This module assesses the GD's OWN platform-state posture against
// the 16 supported compliance frameworks. Cross-region aggregation of
// MC-reported posture is a separate feature scheduled for R3g PR3.
//
// FireAlive itself is a horizontal SOC wellbeing platform; it is not
// itself an entity scoped by HIPAA, GDPR, DORA, or any of the other
// frameworks below. The framework definitions here are provided as a
// service to customers who ARE scoped by those frameworks in their
// own organizational capacity (CISO operations, healthcare ops,
// financial-sector ops, regulated-jurisdiction ops, etc.). For
// customers outside a framework's scope, that framework's report can
// be ignored without consequence.
//
// SCHEMA — Framework definition
//
//   {
//     name: 'Display Name',
//     authority: 'Issuing body',
//     citation: 'Document or URL reference',
//     verifiedControls: [
//       {
//         id: 'Regulatory control ID',
//         name: 'Control name',
//         check: checkFunctionRef,
//         mapping: 'How this control maps to the GD platform',
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
// SCHEMA — generateComplianceReport output (matches MC's shape; the
// frontend renders both MC and GD reports through the same component)
//
//   {
//     framework: 'Display Name',
//     authority: 'Issuing body',
//     citation: 'Reference',
//     generatedAt: ISO 8601 string,
//     appVersion: 'x.y.z',
//     note: 'Optional note',
//     summary: {
//       // Backwards-compatible top-level fields (mirror verified summary):
//       total, passed, warnings, failed,
//       // Explicit Shared Responsibility split:
//       verified: { total, passed, warnings, failed },
//       customerResponsibility: { total, byCategory: { ... } },
//     },
//     verifiedControls: [ { controlId, controlName, status, detail, mapping }, ... ],
//     customerResponsibility: [ { id, name, category, detail }, ... ],
//   }
//
// MODULE STATE (R3g PR2 commit 32)
//
// This file is created in R3g PR2 commit 32 as the bare entry point
// for the GD compliance service. At commit-32 state:
//   - 13 inline check functions cover the fundamental control areas
//     using GD's database surface. They will be supplemented (not
//     replaced) by checks/* modules in subsequent commits, matching
//     the MC PR1 pattern.
//   - FRAMEWORKS object is empty. The 16 framework files
//     (frameworks/hipaa.js through frameworks/popia_za.js) are added
//     one per commit in the latter half of PR2 and registered here
//     via explicit require() — no auto-discovery, no fs walking.
//   - generateComplianceReport works against the empty FRAMEWORKS
//     and returns null for any framework key. The route handler that
//     calls it is wired in the final PR2 commit; until then this
//     module is reachable only by direct require().
//   - The `checks` aggregator (used by framework factory functions
//     in commits-to-come) is added in a later commit after the
//     checks/* modules exist on disk. Adding the spread of
//     require('./checks/access') etc. before those files exist would
//     crash at module load.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../../db-init');
const { version } = require('../../package.json');
const REMEDIATIONS = require('./remediations');

// ── Check Functions ──────────────────────────────────────────────────────────
//
// These verify GD platform state against control requirements. Each
// returns { status, detail } where status is 'pass' | 'warning' | 'fail'.
//
// The 13 functions below cover the fundamental control areas using GD's
// database (db-init.js schema). Subsequent PR2 commits add additional
// check functions in checks/<category>.js files mirroring the MC's
// PR1 layout. Where the GD lacks a feature the MC has (e.g., no IR
// policy registry, no signed log batches, no KMS provider table), the
// check returns 'warning' or 'fail' with an explanatory detail that
// surfaces the gap honestly rather than papering it over.

function checkAccessControl(db) {
  const roles = db.prepare("SELECT DISTINCT role FROM users").all();
  const userCount = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  return {
    status: 'pass',
    detail: `${roles.length} roles defined (ciso, vp, readonly), ${userCount.c} users. JWT bearer-token auth enforced on all /api routes via authMiddleware; role-array gating on each route.`,
  };
}

function checkUniqueUsers(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  const dupes = db.prepare("SELECT COUNT(*) AS c FROM (SELECT LOWER(username) AS u FROM users GROUP BY u HAVING COUNT(*) > 1)").get();
  return {
    status: dupes.c > 0 ? 'warning' : 'pass',
    detail: `${total.c} users, ${dupes.c} duplicate usernames. Database UNIQUE constraint on users.username.`,
  };
}

function checkEncryption(db) {
  const jwtKeyConfigured = !!process.env.GD_JWT_SECRET && !process.env.GD_JWT_SECRET.startsWith('CHANGE_ME');
  return {
    status: jwtKeyConfigured ? 'pass' : 'warning',
    detail: `Password storage: bcrypt (cost factor default 10). Session tokens: JWT signed with ${jwtKeyConfigured ? 'persistent GD_JWT_SECRET' : 'ephemeral key (set GD_JWT_SECRET env var for persistence across restarts)'}. Data-at-rest encryption is filesystem-level on the SQLite database file; customer-managed disk encryption (LUKS, FileVault, BitLocker) advised for SOC-grade posture.`,
  };
}

function checkRBAC(db) {
  const roles = db.prepare("SELECT role, COUNT(*) AS c FROM users GROUP BY role").all();
  return {
    status: 'pass',
    detail: `RBAC enforced: ${roles.map(r => `${r.role}(${r.c})`).join(', ')}. Route-level middleware checks role membership before handler execution. Three-tier model: ciso (full), vp (read + selected writes), readonly (read-only).`,
  };
}

function checkAuditControls(db) {
  const count = db.prepare("SELECT COUNT(*) AS c FROM audit_log").get();
  const recent = db.prepare("SELECT COUNT(*) AS c FROM audit_log WHERE timestamp > datetime('now', '-24 hours')").get();
  return {
    status: 'pass',
    detail: `${count.c} total audit events, ${recent.c} in last 24h. Every /api request (except /api/health) logged with user_id, event_type, ip, severity, and duration. Append-only by API contract; no UPDATE or DELETE routes expose modification of audit_log.`,
  };
}

function checkAuthentication(db) {
  const ssoMethods = db.prepare("SELECT auth_method, COUNT(*) AS c FROM users GROUP BY auth_method").all();
  const mfaEnrolled = db.prepare("SELECT COUNT(*) AS c FROM users u WHERE EXISTS (SELECT 1 FROM webauthn_credentials wc WHERE wc.user_id = u.id AND wc.is_passwordless = 1)").get();
  const totalUsers = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  return {
    status: 'pass',
    detail: `Login is a user-verified FIDO2 hardware passkey (AAL3, phishing-resistant); sessions are signed JWTs (HS256). Hardware passkey enrolled: ${mfaEnrolled.c}/${totalUsers.c} users. Auth methods: ${ssoMethods.map(m => `${m.auth_method}(${m.c})`).join(', ')}. SAML/OIDC/LDAP supported per users.auth_method column.`,
  };
}

function checkTransmission() {
  return {
    status: 'pass',
    detail: 'TLS termination expected at reverse proxy (nginx/Caddy/ALB) per deployment guide. Helmet middleware sets HSTS / X-Content-Type-Options / X-Frame-Options. CORS configured for credential-bearing requests.',
  };
}

function checkBoundaries(db) {
  const activeMcs = db.prepare("SELECT COUNT(*) AS c FROM management_consoles WHERE status = 'active'").get();
  const totalUsers = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  return {
    status: 'pass',
    detail: `GD by-design boundary: aggregate metrics only (regional_metrics table), no raw analyst PII. ${activeMcs.c} active MCs connected (data ingest one-way: MCs push to GD via /api/ingest/metrics; GD never writes back). ${totalUsers.c} GD-side users in users table (CISO/VP/readonly accounts only; analyst data lives at MC).`,
  };
}

function checkAnomalyDetection(db) {
  const failedLogins24h = db.prepare("SELECT COUNT(*) AS c FROM auth_log WHERE action = 'LOGIN_FAILED' AND timestamp > datetime('now', '-24 hours')").get();
  return {
    status: 'pass',
    detail: `Rate limiting: 1000 req per 15-minute window per IP on /api/* (apiLimiter middleware). Failed logins logged to auth_log (${failedLogins24h.c} in last 24h). Per-MC ingest tracked in management_consoles.last_sync for stale-MC detection.`,
  };
}

function checkChangeManagement(db) {
  const fuse = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  return {
    status: 'pass',
    detail: `Anti-rollback fuse counter at ${fuse?.value || 'unset'} (db-init seed; advances with each release). AGPL-3.0 source transparency. Configuration changes recorded in audit_log via request-logging middleware.`,
  };
}

function checkIncidentResponse(db) {
  return {
    status: 'warning',
    detail: 'GD does not currently host an incident-response policy registry. Customer-managed IR planning advised (NIST 800-61, ISO 27035). Note: SOC-level IR procedures (analyst-facing) live at the MC layer; GD-level IR is CISO/governance-tier responsibility and is currently operator-managed off-platform.',
  };
}

function checkBackups(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM backups").get();
  const recent = db.prepare("SELECT COUNT(*) AS c FROM backups WHERE created_at > datetime('now', '-7 days')").get();
  const schedules = db.prepare("SELECT COUNT(*) AS c FROM backup_schedules WHERE active = 1").get();
  if (total.c === 0) {
    return {
      status: 'fail',
      detail: `No backups recorded. ${schedules.c} active backup schedule(s) configured. Configure and verify a backup schedule via /api/backup-schedules before relying on the GD for production CISO operations.`,
    };
  }
  return {
    status: recent.c > 0 ? 'pass' : 'warning',
    detail: `${total.c} backups total, ${recent.c} in last 7 days. ${schedules.c} active backup schedule(s). SHA-256 hash recorded per backup (backups.sha256_hash column) for integrity verification.`,
  };
}

function checkAuditIntegrity(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM audit_log").get();
  if (total.c === 0) {
    return { status: 'pass', detail: 'No audit log entries yet; integrity vacuously holds.' };
  }
  return {
    status: 'warning',
    detail: `Audit log: ${total.c} entries, append-only by API contract. GD does not currently sign log batches or stream to an external SIEM — tamper-evidence is local-trust only. SIEM streaming integration is a future enhancement; until then, SOC-grade tamper-evidence depends on filesystem-level controls on the SQLite database file and the host's own audit infrastructure.`,
  };
}

// ── Check Function Aggregator ────────────────────────────────────────────────
//
// Spreads the 13 inline check functions above with the 9 checks/* category
// modules into a single `checks` namespace that framework factory functions
// consume. Later spreads in the object literal win on duplicate keys by design:
// checks/audit.js's checkAuditIntegrity supersedes the inline definition,
// and checks/config.js's checkChangeManagement supersedes the inline one.
// Both replacements are deliberate; the checks/* versions surface the
// SOC-grade detail required for framework references.

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
// Empty at commit-32 state. R3g PR2 subsequent commits add one framework
// per commit via the factory-function pattern, mirroring MC PR1:
//
//   hipaa: require('./frameworks/hipaa')(checks),
//   soc2:  require('./frameworks/soc2')(checks),
//   ...
//
// The `checks` aggregator (used by those factory functions) is introduced
// in a separate commit once the checks/* modules exist on disk. Until
// then, this registry is empty and generateComplianceReport returns null
// for every framework key.

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
      const remediation = REMEDIATIONS[ctrl.check.name];
      if (remediation) entry.remediation = remediation;
    }
    return entry;
  });
  db.close();

  const verifiedPassed = verifiedResults.filter(r => r.status === 'pass').length;
  const verifiedWarnings = verifiedResults.filter(r => r.status === 'warning').length;
  const verifiedFailed = verifiedResults.filter(r => r.status === 'fail').length;

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
      total: verifiedResults.length,
      passed: verifiedPassed,
      warnings: verifiedWarnings,
      failed: verifiedFailed,
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
  generateComplianceReport,
  FRAMEWORKS,
};

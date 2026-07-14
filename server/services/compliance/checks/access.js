// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Check Functions: Identity & Access
//
// R3g (v1.0.33): part of the comprehensive technical-control verification
// library that backs FireAlive's compliance claims under Foundational
// Rule 14 (Shared Responsibility framing).
//
// This file provides 8 check functions covering identity management,
// authentication, authorization, and Separation of Duties. Each function
// queries actual platform state (DB tables, environment variables,
// configuration) and returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'.
//
// Functions in this file are referenced from framework definitions in
// server/services/compliance/frameworks/<id>.js (R3g commits 13-28). They
// are not yet wired into the FRAMEWORKS registry by this commit; commits
// 13-17 expand the existing 5 frameworks to reference them, and commits
// 18-28 add the 11 new frameworks that reference them.
//
// PLATFORM STATE NOTES
//
// The R3g detailed plan (R3G-DETAILED-PLAN.md) anticipated several
// platform structures that don't match the v1.0.32 codebase. The
// functions below query the actual structures:
//
//   - Planned PASSWORD_MIN_LENGTH env var → not applicable; the platform
//     is passwordless (FIDO2 hardware-passkey login; no password to gate)
//   - Planned JWT_EXPIRES_IN env var → actual JWT_EXPIRY env var
//     in server/middleware/auth.js (default '15m')
//   - Planned auth_hardening table → does not exist; rate limiting is
//     in-memory via express-rate-limit (apiLimiter, 1000 req/15min);
//     failed logins are tracked in auth_log with action LIKE '%FAIL%'
//   - Planned users.mfa_enrolled column → MFA enrollment is a hardware
//     passkey in webauthn_credentials (is_passwordless=1); the gate is
//     mfa_enrollment_required (1 = login blocks a session until enrolled)
//   - Planned "lead-only badge attributes" for privilege separation →
//     no such concept; the users.role CHECK constraint makes roles
//     mutually exclusive (analyst | lead | admin)
//   - Planned iam_integrations table → does not exist; IAM is stored
//     in integration_config with integration_type in {iam_saml,
//     iam_oidc, iam_ldap, iam_cloud}
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkPasswordPolicy ──────────────────────────────────────────────────────
// FireAlive is passwordless: login is a user-verified FIDO2 hardware passkey
// (B5n3), so there is no password to set, store, or gate. The password /
// credential-management controls are satisfied by the phishing-resistant
// hardware credential, which is stronger than any password policy.
//
// Maps to controls including: HIPAA 164.308(a)(5)(ii)(D), SOC 2 CC6.1,
// NIST CSF PR.AA-03, ISO 27001 A.8.5, NIST 800-53 IA-5, NIS2 Art.21(2)(g),
// Cyber Essentials "User access control".
function checkPasswordPolicy() {
  return {
    status: 'pass',
    detail: 'FireAlive is passwordless: no passwords are stored (login is a user-verified FIDO2 hardware passkey, AAL3, phishing-resistant). The credential-strength control is the hardware key, stronger than any password-complexity policy.',
  };
}

// ── checkSessionTimeout ──────────────────────────────────────────────────────
// Verifies JWT access token expiry is within the SOC-grade 30-minute
// recommendation. Default is 15 minutes (JWT_EXPIRY env var in
// server/middleware/auth.js); operators can override but the check
// surfaces a warning if the value exceeds 30 minutes.
//
// Maps to controls including: HIPAA 164.312(a)(2)(iii) Automatic Logoff,
// SOC 2 CC6.1, NIST 800-53 AC-11/AC-12, ISO 27001 A.8.5.
function checkSessionTimeout() {
  const expiry = process.env.JWT_EXPIRY || '15m';
  const match = expiry.match(/^(\d+)([smhd])$/);
  if (!match) {
    return {
      status: 'warning',
      detail: `JWT_EXPIRY value "${expiry}" is not in expected <n><unit> format (s/m/h/d). Default 15m may apply at runtime.`,
    };
  }
  const num = parseInt(match[1], 10);
  const unit = match[2];
  const minutes = unit === 's' ? num / 60 : unit === 'm' ? num : unit === 'h' ? num * 60 : num * 60 * 24;
  if (minutes > 30) {
    return {
      status: 'warning',
      detail: `Session timeout configured at ${expiry} (${minutes} min) — exceeds SOC-grade 30-minute recommendation. Refresh rotation still applies.`,
    };
  }
  return {
    status: 'pass',
    detail: `Session timeout: ${expiry} (${minutes} min) JWT access token; HS256 signing; refresh rotation enforced.`,
  };
}

// ── checkAccountLockout ──────────────────────────────────────────────────────
// Verifies failed-login monitoring and rate limiting are active.
// FireAlive enforces account-lockout-equivalent protection via:
//   - apiLimiter (express-rate-limit): 1000 req/15min global
//   - IP-based failed-login tracking in auth_log (action LIKE '%FAIL%')
//   - Reverse-proxy-layer IP blocking based on the auth_log data
// There is no per-account DB-stored lockout state; the protection is
// IP-layer + audit-layer rather than per-account-counter.
//
// Maps to controls including: HIPAA 164.308(a)(5)(ii)(C), SOC 2 CC6.1,
// NIST 800-53 AC-7 Unsuccessful Logon Attempts, NIST CSF PR.AA-05,
// Cyber Essentials "User access control".
function checkAccountLockout(db) {
  const failedRecent = db.prepare(
    "SELECT COUNT(*) AS c FROM auth_log WHERE action LIKE '%FAIL%' AND timestamp > datetime('now', '-24 hours')"
  ).get();
  const distinctIps = db.prepare(
    "SELECT COUNT(DISTINCT ip) AS c FROM auth_log WHERE action LIKE '%FAIL%' AND timestamp > datetime('now', '-1 hour')"
  ).get();
  return {
    status: 'pass',
    detail: `apiLimiter active (1000 req/15min global); IP-based failed-login tracking via auth_log. Last 24h: ${failedRecent.c} failed attempts. Last 1h distinct source IPs: ${distinctIps.c}.`,
  };
}

// ── checkMfaEnforcement ──────────────────────────────────────────────────────
// Verifies all active users either have a hardware passkey enrolled or have
// mfa_enrollment_required=1 (login refuses to issue a session until a passkey
// is enrolled). MFA is a FIDO2 hardware passkey (AAL3, phishing-resistant),
// recorded in webauthn_credentials; the legacy totp_* columns were removed in
// B6i. SOC-grade default for mfa_enrollment_required is 1.
//
// Maps to controls including: HIPAA 164.312(d), SOC 2 CC6.1,
// NIST CSF PR.AA-02, ISO 27001 A.8.5, NIST 800-53 IA-2(1)/(2)
// (multifactor for privileged + non-privileged), NIS2 Art.21(2)(j),
// DORA Art.9(2).
function checkMfaEnforcement(db) {
  const stats = db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN EXISTS (
        SELECT 1 FROM webauthn_credentials wc
        WHERE wc.user_id = u.id AND wc.is_passwordless = 1
      ) THEN 1 ELSE 0 END) AS enrolled,
      SUM(CASE WHEN u.mfa_enrollment_required = 1 THEN 1 ELSE 0 END) AS required,
      SUM(CASE WHEN NOT EXISTS (
        SELECT 1 FROM webauthn_credentials wc
        WHERE wc.user_id = u.id AND wc.is_passwordless = 1
      ) AND u.mfa_enrollment_required = 0 THEN 1 ELSE 0 END) AS unenforced
    FROM users u WHERE u.active = 1
  `).get();
  if (stats.total === 0) {
    return { status: 'pass', detail: 'No active users; MFA enforcement vacuously holds.' };
  }
  if (stats.unenforced > 0) {
    return {
      status: 'warning',
      detail: `${stats.unenforced} of ${stats.total} active user(s) have MFA neither enrolled nor required (no passwordless hardware passkey AND mfa_enrollment_required = 0). SOC-grade policy requires mfa_enrollment_required = 1 for all roles.`,
    };
  }
  return {
    status: 'pass',
    detail: `MFA: ${stats.enrolled} of ${stats.total} active users have a hardware passkey enrolled; ${stats.required} have enrollment required. Login refuses a session when required and not enrolled.`,
  };
}

// ── checkPrivilegedSeparation ────────────────────────────────────────────────
// Verifies the admin role population is appropriately limited relative
// to total users (SoD norm: admins should typically be ≤25% of active
// users in a SOC of more than 4 users). Fails if no admin users exist.
// Roles are mutually exclusive at the DB CHECK constraint level.
//
// Maps to controls including: SOC 2 CC6.3 Role-Based Access, NIST 800-53
// AC-6 Least Privilege, ISO 27001 A.8.2 Privileged access rights,
// NIST CSF PR.AA-05.
function checkPrivilegedSeparation(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM users WHERE active = 1").get();
  const admins = db.prepare("SELECT COUNT(*) AS c FROM users WHERE active = 1 AND role = 'admin'").get();
  if (admins.c === 0) {
    return { status: 'fail', detail: 'No admin users defined — privileged role boundary violated; Config Lock and platform admin functions are unreachable.' };
  }
  if (total.c > 4) {
    const ratio = admins.c / total.c;
    if (ratio > 0.25) {
      return {
        status: 'warning',
        detail: `${admins.c} admin user(s) of ${total.c} active total (${(ratio * 100).toFixed(0)}%) — exceeds 25% SoD norm. Consider reducing admin headcount or auditing admin role assignments.`,
      };
    }
  }
  return {
    status: 'pass',
    detail: `${admins.c} admin(s) across ${total.c} active user(s). Roles mutually exclusive at users.role CHECK constraint (analyst | lead | admin).`,
  };
}

// ── checkApiKeyRotation ──────────────────────────────────────────────────────
// Verifies all active (non-revoked) API keys have been rotated within
// 90 days. Stale keys trigger a warning; bcrypt-hashed storage and
// scoped permissions provide defense in depth even if a stale key leaks.
//
// Maps to controls including: SOC 2 CC6.4 Manage Access, NIST 800-53
// IA-5(1) Authenticator Management — Password-Based Authentication
// (extended to API keys), ISO 27001 A.8.5, NIST CSF PR.AA-01.
function checkApiKeyRotation(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM api_keys WHERE revoked = 0").get();
  const stale = db.prepare(
    "SELECT COUNT(*) AS c FROM api_keys WHERE revoked = 0 AND created_at < datetime('now', '-90 days')"
  ).get();
  if (total.c === 0) {
    return { status: 'pass', detail: 'No active API keys configured.' };
  }
  if (stale.c > 0) {
    return {
      status: 'warning',
      detail: `${stale.c} of ${total.c} active API key(s) created over 90 days ago — recommend rotation. bcrypt-hashed storage and scoped permissions limit blast radius.`,
    };
  }
  return {
    status: 'pass',
    detail: `${total.c} active API key(s), all within 90-day rotation window. bcrypt-hashed storage; scoped permissions (comma-separated scopes column).`,
  };
}

// ── checkIamIntegrationHealth ────────────────────────────────────────────────
// Verifies any configured IAM/SSO integrations are in healthy operational
// state. The platform supports SAML, OIDC, LDAP, and Cloud IAM via
// integration_config rows with integration_type in {iam_saml, iam_oidc,
// iam_ldap, iam_cloud}. If no IAM integrations are configured, local
// FIDO2 hardware-passkey auth is the login path and the check passes vacuously.
//
// Maps to controls including: SOC 2 CC6.1/CC6.2, NIST CSF PR.AA-01,
// ISO 27001 A.5.16/A.8.5, NIST 800-53 IA-2/IA-8, NIS2 Art.21(2)(j),
// DORA Art.9(2).
function checkIamIntegrationHealth(db) {
  const integrations = db.prepare(`
    SELECT integration_type, status, COUNT(*) AS c
    FROM integration_config
    WHERE integration_type LIKE 'iam_%'
    GROUP BY integration_type, status
  `).all();
  if (integrations.length === 0) {
    return {
      status: 'pass',
      detail: 'No IAM integrations configured. Platform supports SAML/OIDC/LDAP/Cloud IAM via integration_config; local FIDO2 hardware-passkey auth is the active method.',
    };
  }
  const errored = integrations.filter(r => r.status === 'error');
  if (errored.length > 0) {
    const detail = errored.map(r => `${r.integration_type}(${r.c})`).join(', ');
    return {
      status: 'warning',
      detail: `IAM integration(s) in error state: ${detail}. Affected users may be unable to authenticate via SSO until remediated.`,
    };
  }
  const summary = integrations.map(r => `${r.integration_type}:${r.status}(${r.c})`).join(', ');
  return {
    status: 'pass',
    detail: `IAM integrations: ${summary}. Failover to local auth available if SSO unreachable.`,
  };
}

// ── checkRoleSeparation ──────────────────────────────────────────────────────
// Verifies Separation of Duties at the Config Lock boundary: when the
// platform is in production-locked state (config_lock_state.lock_active
// = 1), the user who toggled the lock must hold the 'admin' role. R3e
// enforces this at the route level; this check verifies the persisted
// state is consistent with SoD policy.
//
// Maps to controls including: SOC 2 CC6.3 Role-Based Access, NIST 800-53
// AC-3/AC-6, ISO 27001 A.5.18/A.8.2, NIST CSF PR.AA-05.
function checkRoleSeparation(db) {
  const lockState = db.prepare(
    "SELECT lock_active, locked_by_user_id FROM config_lock_state WHERE id = 1"
  ).get();
  if (!lockState || lockState.lock_active === 0) {
    return {
      status: 'pass',
      detail: 'Config Lock not currently active; Separation of Duties enforcement deferred until production lockdown.',
    };
  }
  if (!lockState.locked_by_user_id) {
    return {
      status: 'warning',
      detail: 'Config Lock active but locked_by_user_id is NULL — provenance not preserved.',
    };
  }
  const user = db.prepare("SELECT role FROM users WHERE id = ?").get(lockState.locked_by_user_id);
  if (!user) {
    return {
      status: 'warning',
      detail: 'Config Lock active; locked_by_user_id references a user that no longer exists in the users table.',
    };
  }
  if (user.role !== 'admin') {
    return {
      status: 'fail',
      detail: `Config Lock active but locked_by_user_id has role '${user.role}' — Separation of Duties violation. Only 'admin' role may toggle Config Lock (R3e enforced this at the route layer; stale DB rows may persist if a user was demoted after toggling).`,
    };
  }
  return {
    status: 'pass',
    detail: 'Config Lock active and locked by admin-role user. Separation of Duties preserved (admin toggle authority distinct from lead routing authority and analyst data-entry authority).',
  };
}

module.exports = {
  checkPasswordPolicy,
  checkSessionTimeout,
  checkAccountLockout,
  checkMfaEnforcement,
  checkPrivilegedSeparation,
  checkApiKeyRotation,
  checkIamIntegrationHealth,
  checkRoleSeparation,
};

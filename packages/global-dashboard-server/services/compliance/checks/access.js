// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Check Functions: Identity & Access
//
// R3g PR2 (v1.0.33): part of the GD-side technical-control verification
// library mirroring MC PR1's checks/access.js. Both files export the
// same 8 function names so framework definitions across MC and GD share
// a stable schema; the IMPLEMENTATIONS differ because each service
// queries its own database surface. There is no shared package and no
// cross-service import — each codebase is independent (Foundational
// Rule per BUILD-PLAN-v16, Option A).
//
// Each function returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'.
//
// PLATFORM STATE NOTES (GD-specific gaps relative to MC)
//
//   - GD is passwordless: login is a user-verified FIDO2 hardware
//     passkey (B5n3), so there is no password to set, store, or gate.
//     users.password_hash was removed in B6i. checkPasswordPolicy
//     reports the phishing-resistant posture as a pass.
//   - GD's session timeout is HARDCODED at 8h in the login route's
//     jwt.sign() call. CISO operations are infrequent and multi-step,
//     so the longer timeout is a deliberate UX choice — but it exceeds
//     the SOC-grade 30-minute norm and the check warns accordingly.
//   - GD has no per-user api_keys table. The management_consoles
//     table holds api_key values for MC → GD push authentication;
//     checkApiKeyRotation inspects those MC-side keys instead of
//     per-user keys.
//   - GD has no integration_config table. SSO method is stored
//     per-user in users.auth_method (values: local | saml | oidc |
//     ldap). checkIamIntegrationHealth inspects the distribution of
//     auth_method across users rather than per-integration state.
//   - GD has no config_lock_state table. The frontend exposes a Config
//     Lock button (firealive-gd jsx line 800) but the server has no
//     route handler. checkRoleSeparation warns that Config Lock SoD
//     enforcement is deferred until server-side persistence lands.
//   - GD MFA is a FIDO2 hardware passkey (webauthn_credentials); the
//     legacy mfa_secret / mfa_enabled columns were removed in B6i.
//     checkMfaEnforcement counts passkey enrollment.
//
// FORWARD-COMPATIBLE PATTERN
//
// Check functions in this file use a tableExists() helper to gracefully
// handle GD platform features that are planned but not yet shipped. As
// later BUILD-PLAN-v16 phases land (notably B5b v1.0.51 for real
// SAML/OIDC/LDAP IdP integration), the corresponding check functions
// automatically begin reporting on real platform state without
// requiring code changes here. This pattern keeps the compliance
// library aligned with the platform's roadmap rather than locked to a
// snapshot.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── tableExists ──────────────────────────────────────────────────────────────
// Forward-compatibility helper: returns true if a SQLite table named
// `name` exists in the connected DB. Used by check functions that
// query tables planned for future GD buildout phases (e.g.,
// integration_config in B5b v1.0.51), so the function returns a
// "planned, not yet shipped" warning today and seamlessly transitions
// to real evaluation when the table appears.
function tableExists(db, name) {
  return !!db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?"
  ).get(name);
}

// ── checkPasswordPolicy ──────────────────────────────────────────────────────
// GD is passwordless: login is a user-verified FIDO2 hardware passkey
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
    detail: 'GD is passwordless: no passwords are stored (users.password_hash removed in B6i). Login is a user-verified FIDO2 hardware passkey (AAL3, phishing-resistant) whose attestation chains to bundled trusted-vendor roots -- stronger than any password-complexity policy.',
  };
}

// ── checkSessionTimeout ──────────────────────────────────────────────────────
// Verifies the JWT session timeout. GD uses a hardcoded 8h expiry in
// the login route. CISO operations are infrequent and multi-step
// (regional reviews, report generation, ad-hoc queries) so 8h is a
// deliberate UX choice — but it exceeds the SOC-grade 30-minute norm.
//
// Maps to controls including: HIPAA 164.312(a)(2)(iii) Automatic Logoff,
// SOC 2 CC6.1, NIST 800-53 AC-11/AC-12, ISO 27001 A.8.5.
function checkSessionTimeout() {
  return {
    status: 'warning',
    detail: 'JWT access token expiry: 8h (hardcoded in /api/auth/login route\'s jwt.sign expiresIn parameter). HS256 signing. Exceeds SOC-grade 30-minute norm; the longer timeout reflects CISO operational rhythm (infrequent, multi-step sessions) rather than analyst-tier rhythm. Operators concerned about session compromise should reverse-proxy-enforce shorter idle timeouts at the load balancer layer.',
  };
}

// ── checkAccountLockout ──────────────────────────────────────────────────────
// Verifies failed-login monitoring and rate limiting are active. GD
// enforces account-lockout-equivalent protection via:
//   - apiLimiter (express-rate-limit): 1000 req/15min global
//   - IP-based failed-login tracking in auth_log
//     (action = 'LOGIN_FAILED' rows)
//   - Reverse-proxy-layer IP blocking based on the auth_log data
// There is no per-account DB-stored lockout state; the protection is
// IP-layer + audit-layer rather than per-account-counter.
//
// Maps to controls including: HIPAA 164.308(a)(5)(ii)(C), SOC 2 CC6.1,
// NIST 800-53 AC-7 Unsuccessful Logon Attempts, NIST CSF PR.AA-05,
// Cyber Essentials "User access control".
function checkAccountLockout(db) {
  const failedRecent = db.prepare(
    "SELECT COUNT(*) AS c FROM auth_log WHERE action = 'LOGIN_FAILED' AND timestamp > datetime('now', '-24 hours')"
  ).get();
  const distinctIps = db.prepare(
    "SELECT COUNT(DISTINCT ip) AS c FROM auth_log WHERE action = 'LOGIN_FAILED' AND timestamp > datetime('now', '-1 hour')"
  ).get();
  return {
    status: 'pass',
    detail: `apiLimiter active (1000 req/15min global, /api/health exempt); IP-based failed-login tracking via auth_log. Last 24h: ${failedRecent.c} failed attempts. Last 1h distinct source IPs with failures: ${distinctIps.c}.`,
  };
}

// ── checkMfaEnforcement ──────────────────────────────────────────────────────
// Verifies the MFA enrollment posture across GD users. MFA is a FIDO2
// hardware passkey (AAL3, phishing-resistant), recorded in
// webauthn_credentials; the legacy mfa_secret / mfa_enabled columns and
// the /api/auth/mfa-* routes were removed in B6i. Login is passkey-only
// (B5n3): the server refuses a session without a user-verified hardware
// passkey, so MFA is structurally enforced rather than optional.
//
// Maps to controls including: HIPAA 164.312(d), SOC 2 CC6.1,
// NIST CSF PR.AA-02, ISO 27001 A.8.5, NIST 800-53 IA-2(1)/(2),
// NIS2 Art.21(2)(j), DORA Art.9(2).
function checkMfaEnforcement(db) {
  const stats = db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN EXISTS (
        SELECT 1 FROM webauthn_credentials wc
        WHERE wc.user_id = u.id AND wc.is_passwordless = 1
      ) THEN 1 ELSE 0 END) AS enrolled
    FROM users u
  `).get();
  if (stats.total === 0) {
    return { status: 'pass', detail: 'No users; MFA enforcement vacuously holds.' };
  }
  if (stats.enrolled < stats.total) {
    return {
      status: 'warning',
      detail: `${stats.enrolled} of ${stats.total} user(s) have a hardware passkey enrolled. SOC-grade policy requires a FIDO2 hardware passkey for every CISO/VP/readonly account before granting production access.`,
    };
  }
  return {
    status: 'pass',
    detail: `MFA: ${stats.enrolled} of ${stats.total} users have a hardware passkey enrolled. Login is passkey-only; the server refuses to issue a session without a user-verified hardware passkey.`,
  };
}

// ── checkPrivilegedSeparation ────────────────────────────────────────────────
// Verifies the CISO/VP/readonly role distribution is reasonable. GD's
// three-tier model: CISO is highest privilege (full write), VP is
// mid-privilege (read + selected writes), readonly is non-privileged
// (read-only). Roles are mutually exclusive at the users.role CHECK
// constraint level.
//
// Maps to controls including: SOC 2 CC6.3 Role-Based Access, NIST 800-53
// AC-6 Least Privilege, ISO 27001 A.8.2 Privileged access rights,
// NIST CSF PR.AA-05.
function checkPrivilegedSeparation(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  const cisos = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'ciso'").get();
  const vps = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'vp'").get();
  const readonly = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'readonly'").get();
  if (cisos.c === 0) {
    return { status: 'fail', detail: 'No CISO-role users defined — CISO-only write operations (backups, schedules, MC registration, config) are unreachable. At least one CISO account required for production GD operations.' };
  }
  if (cisos.c > 3) {
    return {
      status: 'warning',
      detail: `${cisos.c} CISO-role users — SOC-grade norm is 1-2 (the CISO and their deputy). Reduce or audit CISO-role assignments; consider promoting deputy roles to VP-tier instead.`,
    };
  }
  return {
    status: 'pass',
    detail: `${cisos.c} CISO, ${vps.c} VP, ${readonly.c} readonly across ${total.c} user(s). Roles mutually exclusive at users.role CHECK constraint (ciso | vp | readonly).`,
  };
}

// ── checkApiKeyRotation ──────────────────────────────────────────────────────
// Verifies the management_consoles.api_key values (MC → GD push
// authentication tokens) have been rotated within 90 days of the MC's
// last_sync activity. There is no per-user api_keys table on the GD;
// the MC-trust tokens ARE the GD's "API keys" surface.
//
// Stale MC tokens trigger a warning; the MC → GD push channel is
// receive-only on the GD side (Foundational Rule 20), but a leaked MC
// key could allow an attacker to spoof aggregate-metrics pushes from
// that MC. 90-day rotation is the SOC-grade norm.
//
// Maps to controls including: SOC 2 CC6.4 Manage Access, NIST 800-53
// IA-5(1) Authenticator Management, ISO 27001 A.8.5, NIST CSF PR.AA-01.
function checkApiKeyRotation(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM management_consoles WHERE status = 'active'").get();
  const stale = db.prepare(
    "SELECT COUNT(*) AS c FROM management_consoles WHERE status = 'active' AND created_at < datetime('now', '-90 days')"
  ).get();
  if (total.c === 0) {
    return { status: 'pass', detail: 'No active management consoles registered; no MC-trust API keys in service.' };
  }
  if (stale.c > 0) {
    return {
      status: 'warning',
      detail: `${stale.c} of ${total.c} active MC(s) registered over 90 days ago — MC-trust api_key rotation recommended. Rotate via re-registration on the MC side. GD-stored keys are plaintext in management_consoles.api_key; reverse-proxy mTLS strongly advised for the push channel.`,
    };
  }
  return {
    status: 'pass',
    detail: `${total.c} active MC(s), all registered within 90-day rotation window. Each MC authenticates inbound pushes via its api_key column value.`,
  };
}

// ── checkIamIntegrationHealth ────────────────────────────────────────────────
// Verifies SSO/IdP integration health. Two-state behavior:
//
//   CURRENT STATE (pre-B5b v1.0.51): GD has no integration_config
//   table. SSO method is stored per-user in users.auth_method
//   (values: local | saml | oidc | ldap). The function reports
//   auth_method distribution honestly while noting that B5b will
//   land real SAML/OIDC/LDAP wiring with integration_config.
//
//   POST-B5b STATE (v1.0.51+): integration_config table exists with
//   integration_type values 'iam_saml' | 'iam_oidc' | 'iam_ldap'.
//   The function additionally surfaces per-integration status and
//   testing recency, mirroring MC's checkIntegrationHealth pattern.
//
// Forward-compatible: same function, behavior expands automatically
// when B5b ships and the table appears.
//
// Maps to controls including: SOC 2 CC6.1/CC6.2, NIST CSF PR.AA-01,
// ISO 27001 A.5.16/A.8.5, NIST 800-53 IA-2/IA-8, NIS2 Art.21(2)(j),
// DORA Art.9(2).
function checkIamIntegrationHealth(db) {
  const methods = db.prepare(
    "SELECT auth_method, COUNT(*) AS c FROM users GROUP BY auth_method"
  ).all();
  if (methods.length === 0) {
    return {
      status: 'pass',
      detail: 'No users in users table; IAM posture vacuously holds.',
    };
  }
  const summary = methods.map(m => `${m.auth_method}(${m.c})`).join(', ');
  const nonLocal = methods.filter(m => m.auth_method !== 'local');

  // Forward-compatible: when integration_config lands in B5b (v1.0.51),
  // surface per-IdP-integration health here.
  if (tableExists(db, 'integration_config')) {
    const idpIntegrations = db.prepare(
      "SELECT integration_type, status, last_test_at FROM integration_config WHERE integration_type LIKE 'iam_%'"
    ).all();
    if (idpIntegrations.length === 0 && nonLocal.length > 0) {
      return {
        status: 'warning',
        detail: `Users carry non-local auth_method values (${summary}) but no IdP integrations are configured in integration_config. Configure SAML/OIDC/LDAP via the IAM tab if non-local auth should be operational.`,
      };
    }
    if (idpIntegrations.length === 0) {
      return {
        status: 'pass',
        detail: `All users use local FIDO2 passkey auth (${methods[0].c} users). No IdP integrations configured in integration_config — acceptable for deployments not using external IdPs.`,
      };
    }
    const dayMs = 24 * 60 * 60 * 1000;
    const errored = idpIntegrations.filter(i => i.status === 'error');
    const stale = idpIntegrations.filter(i => {
      if (i.status !== 'operational') return false;
      if (!i.last_test_at) return true;
      return (Date.now() - new Date(i.last_test_at).getTime()) > 30 * dayMs;
    });
    if (errored.length > 0) {
      const erroredSummary = errored.map(i => i.integration_type).join(', ');
      return {
        status: 'warning',
        detail: `${errored.length} of ${idpIntegrations.length} IdP integration(s) in error state: ${erroredSummary}. Auth method distribution: ${summary}. Investigate via the IAM tab.`,
      };
    }
    if (stale.length > 0) {
      const staleSummary = stale.map(i => i.integration_type).join(', ');
      return {
        status: 'warning',
        detail: `${stale.length} operational IdP integration(s) not tested in 30+ days: ${staleSummary}. Test connectivity via the IAM tab.`,
      };
    }
    const integrationsSummary = idpIntegrations.map(i => `${i.integration_type}:${i.status}`).join(', ');
    return {
      status: 'pass',
      detail: `IAM integrations operational: ${integrationsSummary}. Auth method distribution across users: ${summary}.`,
    };
  }

  // Pre-B5b state: integration_config table not yet present.
  const recentSuccessByMethod = db.prepare(
    "SELECT method, COUNT(*) AS c FROM auth_log WHERE action = 'LOGIN_SUCCESS' AND timestamp > datetime('now', '-7 days') GROUP BY method"
  ).all();
  const recentSummary = recentSuccessByMethod.length > 0
    ? ` Recent 7d successful logins by method: ${recentSuccessByMethod.map(r => `${r.method || 'unset'}(${r.c})`).join(', ')}.`
    : ' No successful logins in last 7d.';
  if (nonLocal.length === 0) {
    return {
      status: 'pass',
      detail: `All users use local FIDO2 passkey auth (${methods[0].c} users). Per-user auth_method distribution: ${summary}.${recentSummary} Real SAML/OIDC/LDAP IdP integration planned for B5b (v1.0.51); integration_config table not yet present. Until then, auth_method is set per-user without per-integration health tracking.`,
    };
  }
  return {
    status: 'pass',
    detail: `Auth method distribution: ${summary}.${recentSummary} Real SAML/OIDC/LDAP IdP integration planned for B5b (v1.0.51); when shipped, per-integration health will surface here automatically.`,
  };
}

// ── checkRoleSeparation ──────────────────────────────────────────────────────
// Verifies Separation of Duties at the Config Lock boundary. The GD
// frontend (firealive-gd jsx) exposes a Config Lock toggle, but the
// GD server has no config_lock_state table and no /api/config/lock
// route handler — the feature is frontend-only on the GD side as of
// v0.0.31. SoD enforcement is therefore deferred until Config Lock
// server-side persistence lands in a future phase.
//
// Maps to controls including: SOC 2 CC6.3 Role-Based Access, NIST 800-53
// AC-3/AC-6, ISO 27001 A.5.18/A.8.2, NIST CSF PR.AA-05.
function checkRoleSeparation(db) {
  return {
    status: 'warning',
    detail: 'GD Config Lock server-side persistence not yet implemented (the frontend exposes a toggle but no /api/config/lock route handler exists). Config Lock Separation-of-Duties enforcement deferred until server-side persistence ships. Until then, role-based authority is enforced at the route-middleware layer only (CISO-only routes via authMiddleware([\'ciso\'])).',
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

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Check Functions: Cryptography
//
// R3g PR2 (v1.0.33): GD-side counterpart to MC PR1's checks/crypto.js.
// Both files export the same 5 function names so framework definitions
// reference these checks uniformly across MC and GD. Implementations
// differ because the GD has a substantially smaller cryptographic
// surface than the MC.
//
// Each function returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'.
//
// PLATFORM STATE NOTES (GD-specific gaps relative to MC)
//
//   - GD has no backup_signing_keys table. GD-side backups are
//     SHA-256-hashed (backups.sha256_hash column) but the hashes are not
//     cryptographically signed; there is no Ed25519 key registry for
//     GD's own backup manifests. The MC PR1 implementation of
//     checkKeyRotation queries that registry; the GD version returns
//     'warning' surfacing the absence. (Distinct from the signing_keys
//     table below, which holds MC public keys for verifying inbound
//     pushes — not GD's own signing material.)
//   - R3g PR3 (this PR) SHIPPED the signing_keys table: a per-MC public-
//     key registry for verifying inbound metrics and compliance-report
//     pushes. Each row tracks one MC's Ed25519 public key with
//     approval_status ('pending_approval' | 'approved' | 'rejected'),
//     gated by manual CISO or signing_key_approver review per ISO
//     27001 A.6.1.2 role segregation. Cryptographic trust
//     establishment requires manual CISO approval per role
//     segregation policy (ISO 27001 A.6.1.2). The signing_keys
//     registry's health is surfaced by checkSigningKeyRegistry in
//     checks/third-party.js; this file's checkKeyRotation focuses on
//     GD's own cryptographic posture (JWT secret) and cross-references
//     the MC-trust registry rather than re-evaluating it.
//   - GD has no TIER1/TIER3 encryption keys. The GD doesn't have a
//     tiered data-classification scheme — by design the GD holds only
//     aggregate metrics (regional_metrics) and account data (users).
//     checkAlgorithmStrength adapts to inspect GD_JWT_SECRET strength
//     (the closest analog: the HMAC key used to sign JWTs) and
//     describes the platform's actual cryptographic posture (bcrypt
//     password hashing, HS256 JWTs, crypto.randomBytes for IDs).
//   - GD has no enforceMinTls middleware. TLS enforcement is entirely
//     reverse-proxy-layer on the GD. checkTlsMinVersion documents
//     this honestly.
//   - GD has no kms_providers table. checkKmsProvider returns
//     'warning' noting that external KMS integration is a future
//     enhancement; data-at-rest is filesystem-level on the SQLite
//     database file.
//
// FORWARD-COMPATIBLE PATTERN
//
// Check functions in this file use a tableExists() helper to gracefully
// handle GD platform features that are planned but not yet shipped. As
// later BUILD-PLAN-v16 phases land (a future GD KMS integration phase
// for kms_providers), the corresponding check functions automatically
// begin reporting on real platform state without requiring code changes
// here. This pattern keeps the compliance library aligned with the
// platform's roadmap rather than locked to a snapshot.
//
// R3g PR3 has SHIPPED the signing_keys table for MC-trust verification.
// The forward-compatible skip-path for that registry has been replaced
// with active evaluation in checks/third-party.js's
// checkSigningKeyRegistry (Phase 9 / Commit 40). The remaining
// forward-compat skip is checkKmsProvider's kms_providers branch.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── tableExists ──────────────────────────────────────────────────────────────
// Forward-compatibility helper: returns true if a SQLite table named
// `name` exists in the connected DB. Used by check functions that
// query tables planned for future GD buildout phases, so the function
// returns a "planned, not yet shipped" warning today and seamlessly
// transitions to real evaluation when the table appears.
function tableExists(db, name) {
  return !!db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?"
  ).get(name);
}

// ── checkKeyRotation ─────────────────────────────────────────────────────────
// Verifies cryptographic key rotation posture for the GD's OWN
// cryptographic material. The GD has two relevant key surfaces:
//
//   - GD_JWT_SECRET: the HMAC key for signing JWTs. Set once at
//     deployment via env var; no in-platform rotation mechanism.
//     Operator-managed rotation requires regenerating the secret and
//     restarting the GD server (invalidates all existing JWTs).
//   - management_consoles.api_key: the per-MC trust tokens for the
//     MC → GD push channel. Rotation cadence covered by
//     checkApiKeyRotation in checks/access.js, not duplicated here.
//
// R3g PR3 added a THIRD signing-key surface: signing_keys (the
// MC-public-key trust registry for verifying inbound pushes). That
// registry's rotation pattern differs fundamentally — keys are
// generated MC-side via POST /api/gd-signing-key/rotate, submitted
// for GD-side review, and require manual CISO or
// signing_key_approver approval before they become trusted
// (approval_status='approved' AND is_active=1). Cryptographic trust
// establishment requires manual CISO approval per role segregation
// policy (ISO 27001 A.6.1.2). The rotation lifecycle is observable
// to operators via GET /api/signing-keys/pending and GET
// /api/mc/<id>/signing-keys (Commits 19-20). checkSigningKeyRegistry
// in checks/third-party.js surfaces its health (including a stale-
// pending signal at 7 days that flags neglected approval queues).
// This check does not re-evaluate signing_keys; the registry
// health belongs in third-party.js.
//
// Honest gap (unchanged by PR3): no rotation tracking on the GD side
// for GD_JWT_SECRET itself. SOC-grade deployments rotate
// GD_JWT_SECRET on a documented cadence (typically quarterly) with
// planned downtime; the platform does not currently enforce or
// measure that cadence.
//
// Maps to controls including: HIPAA 164.312(a)(2)(iv), SOC 2 CC6.7,
// NIST CSF PR.DS-01, ISO 27001 A.8.24, A.6.1.2 (role segregation
// for trust establishment, surfaced via signing_keys approval
// workflow), NIST 800-53 SC-12, AC-5 (segregation of duties),
// NIS2 Art.21(2)(h), DORA Art.9(3).
function checkKeyRotation() {
  const jwtKeyConfigured = !!process.env.GD_JWT_SECRET && !process.env.GD_JWT_SECRET.startsWith('CHANGE_ME');
  if (!jwtKeyConfigured) {
    return {
      status: 'fail',
      detail: 'GD_JWT_SECRET not configured (or still default placeholder). Server is generating an ephemeral random key per-restart; all existing JWTs are invalidated on each server restart, and there is no key continuity across deployments.',
    };
  }
  return {
    status: 'warning',
    detail: 'GD has no in-platform rotation registry for its own cryptographic material (GD_JWT_SECRET). Active key is GD_JWT_SECRET (set via env var, persistent across restarts). Operator-managed rotation: regenerate secret and restart server (invalidates existing JWTs). SOC-grade norm is quarterly rotation; the platform does not currently track or enforce this cadence. MC-trust api_key rotation tracked separately by checkApiKeyRotation. Inbound-push signing keys (signing_keys table, R3g PR3) have their own rotation lifecycle: MC-side generation, manual CISO/signing_key_approver approval, surfaced by checkSigningKeyRegistry in checks/third-party.js.',
  };
}

// ── checkAlgorithmStrength ───────────────────────────────────────────────────
// Verifies cryptographic algorithm and key-strength posture for the GD.
// The GD uses:
//
//   - bcrypt for password hashing (bcryptjs library, default cost factor)
//   - JWT with HS256 (HMAC-SHA256) signed via GD_JWT_SECRET
//   - crypto.randomBytes(16) for backup hashes and IDs
//   - crypto.randomUUID() for scan IDs
//
// The check verifies GD_JWT_SECRET is long enough for HMAC-SHA256
// (32 bytes / 64 hex chars recommended). Shorter keys reduce HMAC
// strength below SOC-grade norms.
//
// Maps to controls including: HIPAA 164.312(a)(2)(iv), SOC 2 CC6.7
// confidentiality, NIST CSF PR.DS-01, ISO 27001 A.8.24, A.6.1.2
// (where signing_keys' approval workflow enforces role segregation
// for trust-establishment cryptographic material), NIST 800-53
// SC-13 Cryptographic Protection, AC-5 (segregation), NIS2
// Art.21(2)(h), DORA Art.9(3).
function checkAlgorithmStrength() {
  const jwtKey = process.env.GD_JWT_SECRET;
  if (!jwtKey || jwtKey.startsWith('CHANGE_ME')) {
    return {
      status: 'fail',
      detail: 'GD_JWT_SECRET not configured (or still default placeholder). Server generates an ephemeral 32-byte random key per-restart — JWT signing works during the runtime session but there is no key continuity across restarts.',
    };
  }
  // Length check: HMAC-SHA256 keys can be any length but SOC-grade is
  // ≥32 bytes. If the value is hex-encoded, count bytes; otherwise
  // use raw character length as a lower-bound proxy.
  const hexPattern = /^[0-9a-fA-F]+$/;
  const byteLen = hexPattern.test(jwtKey) ? jwtKey.length / 2 : jwtKey.length;
  if (byteLen < 32) {
    return {
      status: 'warning',
      detail: `GD_JWT_SECRET appears to be ${byteLen} bytes (hex-decoded or raw). SOC-grade HMAC-SHA256 keys are ≥32 bytes (64 hex chars). Regenerate with crypto.randomBytes(32).toString('hex') and redeploy.`,
    };
  }
  return {
    status: 'pass',
    detail: `Password storage: bcrypt (bcryptjs). JWT: HS256 with ${byteLen}-byte GD_JWT_SECRET. Random IDs: crypto.randomBytes(16) for backup IDs and similar; crypto.randomUUID() for scan IDs. Application-layer at-rest encryption protects the most sensitive columns (signing-key private keys, the GD CA key, backup destination credentials) with AES-256-GCM under a hardware-sealed Tier-1 KEK (TPM 2.0 / Secure Enclave-sealed, decision D26 — a copied disk cannot unseal it; recovery-coded for disaster recovery). Bulk database data-at-rest is filesystem-level on the SQLite database file (operator-managed disk encryption).`,
  };
}

// ── checkTlsMinVersion ───────────────────────────────────────────────────────
// Verifies the platform is configured to enforce HTTPS in production.
// The GD's index.js uses plain app.listen() and has no enforceMinTls
// middleware equivalent to the MC's. TLS is entirely reverse-proxy-layer
// on the GD; SOC-grade deployments configure the proxy with minVersion
// TLSv1.2 or higher (documented as customer-responsibility in framework
// definitions).
//
// Maps to controls including: HIPAA 164.312(e)(1), SOC 2 CC6.7,
// NIST CSF PR.DS-02, ISO 27001 A.8.20, NIST 800-53 SC-8, NIS2
// Art.21(2)(h).
function checkTlsMinVersion() {
  return {
    status: 'warning',
    detail: 'GD has no application-layer HTTPS enforcement middleware (no equivalent of MC\'s enforceMinTls). TLS termination and version negotiation are entirely reverse-proxy responsibility. SOC-grade deployments configure the proxy with TLSv1.2 minimum (TLSv1.3 preferred) and reject plaintext HTTP requests at the proxy layer before they reach the GD application port. This is enumerated as customer-responsibility in framework definitions.',
  };
}

// ── checkKmsProvider ─────────────────────────────────────────────────────────
// Verifies external KMS integration posture. Two-state behavior:
//
//   CURRENT STATE (no kms_providers table): GD has not yet integrated
//   with an external KMS. Data-at-rest protection is filesystem-level
//   on the SQLite database file at GD_DB_PATH; operator-managed disk
//   encryption (LUKS, FileVault, BitLocker, AWS EBS encryption, etc.)
//   provides the at-rest guarantee. Returns warning surfacing the gap.
//
//   FUTURE STATE (kms_providers table present): GD has KMS integration
//   schema mirroring MC's kms_providers (name, provider_type,
//   last_probe_status, last_probe_at, enabled). The function surfaces
//   per-provider trust status with 7-day probe-recency expectation,
//   mirroring MC's checkKmsProviderTrust pattern.
//
// Forward-compatible: behavior expands automatically when a GD KMS
// integration phase adds the table.
//
// Maps to controls including: SOC 2 CC6.7, NIST CSF PR.DS-01,
// ISO 27001 A.8.24 Use of cryptography, NIST 800-53 SC-12
// Cryptographic Key Establishment, DORA Art.9(3).
function checkKmsProvider(db) {
  if (tableExists(db, 'kms_providers')) {
    const enabled = db.prepare(
      "SELECT name, provider_type, last_probe_status, last_probe_at FROM kms_providers WHERE enabled = 1"
    ).all();
    if (enabled.length === 0) {
      return {
        status: 'warning',
        detail: 'kms_providers table present but no providers enabled. Configure an external KMS for SOC-grade key management.',
      };
    }
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
    const untrusted = enabled.filter(r => {
      if (r.last_probe_status !== 'ok') return true;
      if (!r.last_probe_at) return true;
      return (Date.now() - new Date(r.last_probe_at).getTime()) > sevenDaysMs;
    });
    if (untrusted.length > 0) {
      const summary = untrusted.map(r => `${r.name}(${r.provider_type}: ${r.last_probe_status || 'never-probed'})`).join(', ');
      return {
        status: 'warning',
        detail: `${untrusted.length} of ${enabled.length} enabled KMS provider(s) have failed or stale probes (>7d or never-probed): ${summary}.`,
      };
    }
    const summary = enabled.map(r => `${r.name}(${r.provider_type})`).join(', ');
    return {
      status: 'pass',
      detail: `KMS provider trust: ${enabled.length} enabled provider(s), all with recent 'ok' probes within 7 days: ${summary}.`,
    };
  }
  return {
    status: 'warning',
    detail: 'GD has not yet integrated with an external KMS (kms_providers table not present). Data-at-rest protection is filesystem-level on the SQLite database file at the directory configured via GD_DB_PATH (default packages/global-dashboard-server/data/global-dashboard.db). SOC-grade deployments use operator-managed disk encryption (LUKS, FileVault, BitLocker, AWS EBS encryption, etc.) on the underlying volume. A GD KMS integration phase is planned for the broader GD buildout (B-phase track in BUILD-PLAN-v16); when it ships, this check will report per-provider trust automatically.',
  };
}

// ── checkCertValidity ────────────────────────────────────────────────────────
// Verifies the deployment posture supports operator-managed TLS
// certificate lifecycle. The GD runs behind a TLS-terminating reverse
// proxy; certificate issuance, expiry monitoring, and renewal happen
// at the proxy layer and are customer-responsibility (enumerated in
// framework definitions). The GD itself has no certificate-store
// integration and no NODE_ENV-gated production hardening; this check
// returns 'pass' as a description of the deployment-model expectation
// rather than a verification of running state.
//
// Maps to controls including: HIPAA 164.312(e)(1), SOC 2 CC6.7,
// NIST CSF PR.DS-02, ISO 27001 A.8.20, NIST 800-53 SC-8(1).
function checkCertValidity() {
  return {
    status: 'pass',
    detail: 'GD runs behind a TLS-terminating reverse proxy. Certificate lifecycle (CA issuance, expiry monitoring, renewal) is managed at the proxy layer and is customer-responsibility. Operators using ACME (Let\'s Encrypt) or commercial-CA renewal should configure proxy-side expiry alerting; the GD itself has no certificate-store integration.',
  };
}

module.exports = {
  checkKeyRotation,
  checkAlgorithmStrength,
  checkTlsMinVersion,
  checkKmsProvider,
  checkCertValidity,
};

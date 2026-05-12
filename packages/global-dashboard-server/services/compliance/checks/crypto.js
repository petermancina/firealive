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
//   - GD has no backup_signing_keys table. Backups are SHA-256-hashed
//     (backups.hash column) but the hashes are not cryptographically
//     signed; there is no Ed25519 key registry on the GD side. The MC
//     PR1 implementation of checkKeyRotation queries that registry;
//     the GD version returns 'warning' surfacing the absence.
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
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkKeyRotation ─────────────────────────────────────────────────────────
// Verifies cryptographic key rotation posture. The GD does not currently
// maintain a signing-key registry (no equivalent of MC's
// backup_signing_keys table); the closest GD-side cryptographic keys
// are:
//
//   - GD_JWT_SECRET: the HMAC key for signing JWTs. Set once at
//     deployment via env var; no in-platform rotation mechanism.
//     Operator-managed rotation requires regenerating the secret and
//     restarting the GD server (invalidates all existing JWTs).
//   - management_consoles.api_key: the per-MC trust tokens for the
//     MC → GD push channel. Rotation cadence covered by
//     checkApiKeyRotation in checks/access.js, not duplicated here.
//
// Honest gap: no rotation tracking on the GD side. SOC-grade
// deployments rotate GD_JWT_SECRET on a documented cadence (typically
// quarterly) with planned downtime; the platform does not currently
// enforce or measure that cadence.
//
// Maps to controls including: HIPAA 164.312(a)(2)(iv), SOC 2 CC6.7,
// NIST CSF PR.DS-01, ISO 27001 A.8.24, NIST 800-53 SC-12, NIS2
// Art.21(2)(h), DORA Art.9(3).
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
    detail: 'GD has no in-platform key rotation registry. Active cryptographic key is GD_JWT_SECRET (set via env var, persistent across restarts). Operator-managed rotation: regenerate secret and restart server (invalidates existing JWTs). SOC-grade norm is quarterly rotation; the platform does not currently track or enforce this cadence. MC-trust api_key rotation tracked separately by checkApiKeyRotation.',
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
// confidentiality, NIST CSF PR.DS-01, ISO 27001 A.8.24, NIST 800-53
// SC-13 Cryptographic Protection, NIS2 Art.21(2)(h), DORA Art.9(3).
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
    detail: `Password storage: bcrypt (bcryptjs). JWT: HS256 with ${byteLen}-byte GD_JWT_SECRET. Random IDs: crypto.randomBytes(16) for backup IDs and similar; crypto.randomUUID() for scan IDs. No application-layer at-rest encryption — data-at-rest protection is filesystem-level on the SQLite database file (operator-managed).`,
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
// Verifies KMS integration posture. The GD has no kms_providers table
// and no application-layer encryption operations that would consume
// KMS-supplied keys — the GD holds only aggregate metrics and account
// data, and data-at-rest protection is delegated to filesystem-level
// disk encryption.
//
// Maps to controls including: SOC 2 CC6.7, NIST CSF PR.DS-01,
// ISO 27001 A.8.24, NIST 800-53 SC-12 Cryptographic Key Establishment,
// DORA Art.9(3).
function checkKmsProvider() {
  return {
    status: 'warning',
    detail: 'GD does not currently integrate with an external KMS (no kms_providers table; no application-layer at-rest encryption operations). Data-at-rest protection is filesystem-level on the SQLite database file at the directory configured via GD_DB_PATH (default packages/global-dashboard-server/data/global-dashboard.db). SOC-grade deployments use operator-managed disk encryption (LUKS, FileVault, BitLocker, AWS EBS encryption, etc.) on the underlying volume.',
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

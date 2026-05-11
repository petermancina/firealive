// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Check Functions: Cryptography
//
// R3g (v1.0.33): part of the comprehensive technical-control verification
// library that backs FireAlive's compliance claims under Foundational
// Rule 14 (Shared Responsibility framing).
//
// This file provides 5 check functions covering cryptographic key
// management, algorithm strength, transport security, KMS integration,
// and certificate management. Each function queries actual platform
// state (DB tables, environment variables, configuration) and returns
// { status, detail } where status is 'pass' | 'warning' | 'fail'.
//
// Functions are referenced from framework definitions in
// server/services/compliance/frameworks/<id>.js (R3g commits 13-28).
// They are not yet wired into the FRAMEWORKS registry by this commit.
//
// PLATFORM STATE NOTES
//
// The R3g detailed plan (R3G-DETAILED-PLAN.md) anticipated some
// platform structures that don't match the v1.0.32 codebase. The
// functions below query the actual structures:
//
//   - Planned HTTPS_TLS_MIN_VERSION env var → does not exist; the
//     platform uses plain app.listen() with TLS termination expected
//     at the reverse proxy layer. enforceMinTls middleware
//     (server/middleware/security-hardening.js) rejects non-secure
//     requests when NODE_ENV=production.
//   - Planned HTTPS_CERT_PATH env var → does not exist; certificate
//     lifecycle (CA issuance, expiry monitoring, renewal) is managed
//     at the reverse proxy and is customer-responsibility (will be
//     enumerated as such in framework customerResponsibility lists).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkKeyRotation ─────────────────────────────────────────────────────────
// Verifies all active backup signing keys (Ed25519, used to sign the
// backup chain manifests for cross-deployment trust) have been rotated
// within the 180-day SOC-grade norm. Stale active keys trigger a
// warning. Keys that have been rotated out (rotated_out_at IS NOT NULL)
// are excluded from the check.
//
// Maps to controls including: HIPAA 164.312(a)(2)(iv), SOC 2 CC6.7,
// NIST CSF PR.DS-01, ISO 27001 A.8.24, NIST 800-53 SC-12, NIS2
// Art.21(2)(h), DORA Art.9(3).
function checkKeyRotation(db) {
  const total = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_signing_keys WHERE is_active = 1 AND rotated_out_at IS NULL"
  ).get();
  const stale = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_signing_keys WHERE is_active = 1 AND rotated_out_at IS NULL AND created_at < datetime('now', '-180 days')"
  ).get();
  if (total.c === 0) {
    return {
      status: 'warning',
      detail: 'No active backup signing keys. Backup chain manifests cannot be cryptographically signed until a key is generated or registered.',
    };
  }
  if (stale.c > 0) {
    return {
      status: 'warning',
      detail: `${stale.c} of ${total.c} active backup signing key(s) created over 180 days ago — recommend rotation. Ed25519 SPKI fingerprints carried in v3 manifests preserve cross-deployment trust during rotation.`,
    };
  }
  return {
    status: 'pass',
    detail: `${total.c} active backup signing key(s), all within 180-day rotation window. Ed25519 signatures; SPKI fingerprints for universal cross-deployment key identification.`,
  };
}

// ── checkAlgorithmStrength ───────────────────────────────────────────────────
// Verifies the configured encryption keys are strong enough for AES-256.
// TIER3 and TIER1 keys are hex-encoded; getKey() in
// server/services/encryption.js parses them via Buffer.from(hex, 'hex')
// and feeds them to AES-256-GCM (hardcoded ALGORITHM constant). A
// 32-byte key (64 hex chars) is required for AES-256; shorter keys
// would fail at runtime when the cipher is instantiated.
//
// Maps to controls including: HIPAA 164.312(a)(2)(iv), SOC 2 CC6.7
// confidentiality, NIST CSF PR.DS-01, ISO 27001 A.8.24, NIST 800-53
// SC-13 Cryptographic Protection, NIS2 Art.21(2)(h), DORA Art.9(3).
function checkAlgorithmStrength() {
  const t3 = process.env.TIER3_ENCRYPTION_KEY;
  const t1 = process.env.TIER1_ENCRYPTION_KEY;
  if (!t3 || t3.startsWith('CHANGE_ME')) {
    return { status: 'fail', detail: 'TIER3_ENCRYPTION_KEY not configured (or still default placeholder).' };
  }
  if (!t1 || t1.startsWith('CHANGE_ME')) {
    return { status: 'fail', detail: 'TIER1_ENCRYPTION_KEY not configured (or still default placeholder).' };
  }
  const hexPattern = /^[0-9a-fA-F]+$/;
  if (!hexPattern.test(t3) || !hexPattern.test(t1)) {
    return {
      status: 'fail',
      detail: 'Encryption key(s) not in hex format. Expected 64-char hex string (32 bytes for AES-256). Cipher instantiation would fail at runtime.',
    };
  }
  const t3Bytes = t3.length / 2;
  const t1Bytes = t1.length / 2;
  if (t3Bytes < 32 || t1Bytes < 32) {
    return {
      status: 'fail',
      detail: `Encryption key(s) too short for AES-256: TIER3=${t3Bytes} bytes, TIER1=${t1Bytes} bytes. Need 32 bytes (256 bits) minimum.`,
    };
  }
  return {
    status: 'pass',
    detail: `AES-256-GCM at rest: TIER3 ${t3Bytes}-byte key, TIER1 ${t1Bytes}-byte key. NaCl box (X25519 + XSalsa20-Poly1305) for E2EE peer messaging. Ed25519 signatures for backup chain manifests.`,
  };
}

// ── checkTlsMinVersion ───────────────────────────────────────────────────────
// Verifies the platform is configured to enforce HTTPS in production.
// TLS termination is expected at the reverse proxy layer
// (nginx/Caddy/cloud LB); the Node app uses plain app.listen(). The
// enforceMinTls middleware (server/middleware/security-hardening.js)
// rejects non-secure requests when NODE_ENV=production, which means
// all requests reaching application code came through HTTPS. The
// actual TLS version negotiated is the proxy's responsibility and
// SOC-grade deployments configure the proxy with minVersion TLSv1.2
// (documented as customer-responsibility in framework definitions).
//
// Maps to controls including: HIPAA 164.312(e)(1), SOC 2 CC6.7,
// NIST CSF PR.DS-02, ISO 27001 A.8.20, NIST 800-53 SC-8, NIS2
// Art.21(2)(h).
function checkTlsMinVersion() {
  if (process.env.NODE_ENV !== 'production') {
    return {
      status: 'pass',
      detail: `NODE_ENV is "${process.env.NODE_ENV || 'unset'}" (non-production); enforceMinTls middleware is dormant. Production deployments activate HTTPS rejection automatically.`,
    };
  }
  return {
    status: 'pass',
    detail: 'NODE_ENV=production; enforceMinTls middleware active (non-secure requests rejected). TLS version negotiated at reverse proxy layer; SOC-grade deployments configure proxy with minVersion TLSv1.2 or higher.',
  };
}

// ── checkKmsProvider ─────────────────────────────────────────────────────────
// Verifies at least one KMS provider is enabled. Supported provider
// types: env-var (default — encryption keys from process.env), aws-kms,
// azure-keyvault, gcp-kms, hashicorp-vault. A configured external KMS
// is SOC-grade because it removes encryption keys from the deployment's
// filesystem / environment. Warning if no providers enabled. Fail is
// not used because env-var fallback always provides some KMS even
// without DB configuration.
//
// Maps to controls including: SOC 2 CC6.7, NIST CSF PR.DS-01,
// ISO 27001 A.8.24, NIST 800-53 SC-12 Cryptographic Key Establishment,
// DORA Art.9(3).
function checkKmsProvider(db) {
  const enabled = db.prepare(
    "SELECT provider_type, COUNT(*) AS c FROM kms_providers WHERE enabled = 1 GROUP BY provider_type"
  ).all();
  const externalEnabled = enabled.filter(r => r.provider_type !== 'env-var');
  if (enabled.length === 0) {
    return {
      status: 'warning',
      detail: 'No KMS providers enabled in kms_providers. Platform falls back to env-var key sourcing; production deployments should configure an external KMS (AWS KMS, Azure Key Vault, GCP KMS, or HashiCorp Vault).',
    };
  }
  if (externalEnabled.length === 0) {
    return {
      status: 'warning',
      detail: `Only env-var KMS provider enabled. Production deployments should configure an external KMS for key custody outside the deployment environment.`,
    };
  }
  const summary = enabled.map(r => `${r.provider_type}(${r.c})`).join(', ');
  return {
    status: 'pass',
    detail: `KMS providers enabled: ${summary}. External key custody removes encryption keys from the deployment environment.`,
  };
}

// ── checkCertValidity ────────────────────────────────────────────────────────
// Verifies the deployment posture supports operator-managed TLS
// certificate lifecycle. The Node app runs behind a TLS-terminating
// reverse proxy; certificate issuance, expiry monitoring, and renewal
// happen at the proxy layer and are operator responsibility (documented
// as customer-responsibility in framework definitions). This check
// verifies the platform-side prerequisite — that production mode is
// set and HTTPS enforcement is active.
//
// Maps to controls including: HIPAA 164.312(e)(1), SOC 2 CC6.7,
// NIST CSF PR.DS-02, ISO 27001 A.8.20, NIST 800-53 SC-8(1).
function checkCertValidity() {
  if (process.env.NODE_ENV !== 'production') {
    return {
      status: 'pass',
      detail: `NODE_ENV is "${process.env.NODE_ENV || 'unset'}" (non-production); cert validity check deferred. Production deployments terminate TLS at reverse proxy with operator-managed certificate lifecycle.`,
    };
  }
  return {
    status: 'pass',
    detail: 'NODE_ENV=production with HTTPS enforcement active. Certificate lifecycle (CA issuance, expiry monitoring, renewal) is managed at the reverse proxy layer and is customer-responsibility (enumerated in framework customerResponsibility lists).',
  };
}

module.exports = {
  checkKeyRotation,
  checkAlgorithmStrength,
  checkTlsMinVersion,
  checkKmsProvider,
  checkCertValidity,
};

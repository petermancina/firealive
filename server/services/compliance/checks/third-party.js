// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Check Functions: Third-Party Risk
//
// R3g (v1.0.33): part of the comprehensive technical-control verification
// library that backs FireAlive's compliance claims under Foundational
// Rule 14 (Shared Responsibility framing).
//
// This file provides 4 check functions covering integration health
// (vendor reliability), vendor risk assessment readiness, KMS provider
// trust, and signing key registry integrity. Each function queries
// actual platform state and returns { status, detail } where status is
// 'pass' | 'warning' | 'fail'.
//
// Functions are referenced from framework definitions in
// server/services/compliance/frameworks/<id>.js (R3g commits 15-30
// after the +2 shift for remediations module).
//
// RELATIONSHIP TO OTHER CHECK FILES
//
// The functions in this file are distinct from related functions in
// other category files; the distinctions are:
//
//   - checkSystemBoundaries (network.js commit 10): broad status
//     across ALL integration types -- "are integrations errored?"
//     focused on boundary-as-attack-surface.
//   - checkIntegrationHealth (this file): vendor health and testing
//     recency -- "are integrations tested and reachable?" focused on
//     vendor-as-dependency.
//   - checkKeyRotation (crypto.js commit 04): backup signing key
//     rotation staleness ("when was this key last rotated?").
//   - checkSigningKeyRegistry (this file): registry presence for
//     both backup_signing_keys AND chain_signing_keys ("does the
//     platform have active keys for both signing roles?").
//
// PLATFORM STATE NOTES
//
//   - Planned integration_config.vendor_risk_score column -> does not
//     exist. Formal vendor risk assessment (vendor questionnaires,
//     SOC 2 review, DPA negotiation) is customer-responsibility. The
//     platform tracks last_test_at / last_test_result / status, which
//     is the testing-readiness foundation that supports vendor risk
//     review but doesn't replace it.
//   - KMS trust signal: kms_providers.last_probe_status ('ok' |
//     'failed') + last_probe_at recency.
//   - Two signing-key registries exist: backup_signing_keys (manifest
//     signing, Ed25519, supports external-registered keys for
//     cross-deployment trust per R3d-5-pt2) and chain_signing_keys
//     (backup chain entry signing, Ed25519, local-generated only).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkIntegrationHealth ───────────────────────────────────────────────────
// Verifies third-party integrations have been tested recently and are
// not silently broken. The integration_config table records
// last_test_at and last_test_result; an integration in 'operational'
// status that hasn't been tested in 30+ days may be functioning by
// coincidence (e.g., a SOAR webhook URL that no one has triggered).
// Warning if any operational integration is stale (last_test_at older
// than 30 days or NULL); pass if all are within the testing window.
//
// Maps to controls including: SOC 2 CC9.2 Vendor Management, NIST CSF
// GV.SC-04 / ID.SC-04 (CSF 1.1) / GV.SC-07 (CSF 2.0), ISO 27001
// A.5.21/A.5.22 Managing information security in the ICT supply
// chain, NIST 800-53 SR-3 Supply Chain Controls, DORA Art.28 ICT
// Third-Party Service Providers, NIS2 Art.21(2)(d).
function checkIntegrationHealth(db) {
  const operational = db.prepare(
    "SELECT integration_type, last_test_at FROM integration_config WHERE status = 'operational'"
  ).all();
  if (operational.length === 0) {
    return {
      status: 'pass',
      detail: 'No operational integrations to evaluate. Platform supports SOAR / SIEM / ticketing / IAM / SDN / cloud / training / notifications / backup integration types.',
    };
  }
  const staleOrUntested = operational.filter(r => {
    if (!r.last_test_at) return true;
    const testDate = new Date(r.last_test_at);
    const ageMs = Date.now() - testDate.getTime();
    return ageMs > 30 * 24 * 60 * 60 * 1000;
  });
  if (staleOrUntested.length > 0) {
    const types = [...new Set(staleOrUntested.map(r => r.integration_type))].join(', ');
    return {
      status: 'warning',
      detail: `${staleOrUntested.length} of ${operational.length} operational integration(s) have not been tested in 30+ days (or have never been tested). Affected types: ${types}. Run integration tests via the admin Integrations tab.`,
    };
  }
  return {
    status: 'pass',
    detail: `Integration health: ${operational.length} operational integration(s), all tested within 30 days. Test results in last_test_result column.`,
  };
}

// ── checkVendorRiskAssessment ────────────────────────────────────────────────
// Verifies vendor risk assessment readiness. The platform tracks the
// testing foundation (last_test_at / last_test_result / status) that
// supports vendor risk review but does not replace formal vendor risk
// assessment (which involves vendor questionnaires, SOC 2 report
// review, DPA negotiation -- all customer-responsibility). This check
// verifies the foundation is in place: every configured integration
// has been tested at least once, providing evidence of operational
// behavior for the risk-review process.
//
// Maps to controls including: SOC 2 CC9.2 Vendor Management,
// NIST CSF GV.SC-05 / GV.SC-06, ISO 27001 A.5.19 Information security
// in supplier relationships / A.5.20 Addressing information security
// within supplier agreements, NIST 800-53 SR-2 Supply Chain Risk
// Management Plan, DORA Art.28-30 Pre-contractual risk assessment,
// NIS2 Art.21(2)(d).
function checkVendorRiskAssessment(db) {
  const all = db.prepare(
    "SELECT integration_type, status, last_test_at FROM integration_config"
  ).all();
  if (all.length === 0) {
    return {
      status: 'pass',
      detail: 'No integrations configured. Vendor risk assessment (vendor questionnaires, SOC 2 review, DPA negotiation) is customer-responsibility when integrations are added.',
    };
  }
  const untested = all.filter(r => !r.last_test_at);
  if (untested.length > 0) {
    const types = [...new Set(untested.map(r => r.integration_type))].join(', ');
    return {
      status: 'warning',
      detail: `${untested.length} of ${all.length} integration(s) have never been tested (last_test_at IS NULL). Affected types: ${types}. Test every vendor integration to establish baseline operational evidence for risk review.`,
    };
  }
  return {
    status: 'pass',
    detail: `Vendor risk readiness: all ${all.length} configured integration(s) have at least one historical test result. Formal vendor risk assessment (vendor questionnaires, SOC 2 report review, DPA negotiation) is customer-responsibility.`,
  };
}

// ── checkKmsProviderTrust ────────────────────────────────────────────────────
// Verifies all enabled KMS providers have recent successful probes.
// The kms_providers.last_probe_status field records 'ok' or 'failed'
// from periodic connectivity / authentication probes; last_probe_at
// records the probe timestamp. Warning if any enabled provider has a
// failed probe OR has not been probed in 7 days. Pass if all enabled
// providers have recent 'ok' probes.
//
// Maps to controls including: SOC 2 CC6.7, NIST CSF PR.DS-01,
// ISO 27001 A.8.24 Use of cryptography, NIST 800-53 SC-12
// Cryptographic Key Establishment, DORA Art.9(3).
function checkKmsProviderTrust(db) {
  const enabled = db.prepare(
    "SELECT name, provider_type, last_probe_status, last_probe_at FROM kms_providers WHERE enabled = 1"
  ).all();
  if (enabled.length === 0) {
    return {
      status: 'warning',
      detail: 'No KMS providers enabled. Platform falls back to env-var key sourcing; production deployments should configure an external KMS.',
    };
  }
  const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
  const untrusted = enabled.filter(r => {
    if (r.last_probe_status !== 'ok') return true;
    if (!r.last_probe_at) return true;
    const ageMs = Date.now() - new Date(r.last_probe_at).getTime();
    return ageMs > sevenDaysMs;
  });
  if (untrusted.length > 0) {
    const summary = untrusted.map(r => `${r.name}(${r.provider_type}: ${r.last_probe_status || 'never-probed'})`).join(', ');
    return {
      status: 'warning',
      detail: `${untrusted.length} of ${enabled.length} enabled KMS provider(s) have failed or stale probes: ${summary}. Trust path not currently validated.`,
    };
  }
  const summary = enabled.map(r => `${r.name}(${r.provider_type})`).join(', ');
  return {
    status: 'pass',
    detail: `KMS provider trust: ${enabled.length} enabled provider(s), all with recent 'ok' probes within 7 days: ${summary}.`,
  };
}

// ── checkSigningKeyRegistry ──────────────────────────────────────────────────
// Verifies both signing-key registries have at least one active key:
//   - backup_signing_keys: signs per-backup manifests (Ed25519);
//     supports external-registered keys for cross-deployment trust.
//   - chain_signing_keys: signs backup chain entries (Ed25519);
//     local-generated only.
// Without an active key in each registry, the corresponding signing
// operation fails. Fail if either registry has no active key; pass
// if both have at least one active.
//
// Maps to controls including: SOC 2 CC6.7/CC8.1, NIST CSF PR.DS-01 /
// PR.DS-10, ISO 27001 A.8.24/A.8.13, NIST 800-53 SC-12/SI-7,
// DORA Art.9(3)/Art.12, HIPAA 164.312(c)(1).
function checkSigningKeyRegistry(db) {
  const backupKeys = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_signing_keys WHERE is_active = 1 AND rotated_out_at IS NULL"
  ).get();
  const chainKeys = db.prepare(
    "SELECT COUNT(*) AS c FROM chain_signing_keys WHERE is_active = 1 AND rotated_out_at IS NULL"
  ).get();
  if (backupKeys.c === 0 && chainKeys.c === 0) {
    return {
      status: 'fail',
      detail: 'Both signing-key registries empty: backup_signing_keys (manifest signing) and chain_signing_keys (chain entry signing) have no active keys. Backup operations cannot sign cryptographically.',
    };
  }
  if (backupKeys.c === 0) {
    return {
      status: 'fail',
      detail: 'backup_signing_keys registry empty. Per-backup manifest signing inactive; chain signing has ' + chainKeys.c + ' active key(s) but cannot compensate.',
    };
  }
  if (chainKeys.c === 0) {
    return {
      status: 'fail',
      detail: 'chain_signing_keys registry empty. Backup chain entry signing inactive; manifest signing has ' + backupKeys.c + ' active key(s) but cannot compensate.',
    };
  }
  return {
    status: 'pass',
    detail: `Signing key registries: backup_signing_keys has ${backupKeys.c} active key(s) (manifest signing); chain_signing_keys has ${chainKeys.c} active key(s) (chain entry signing). Both signing operations have cryptographic backing.`,
  };
}

module.exports = {
  checkIntegrationHealth,
  checkVendorRiskAssessment,
  checkKmsProviderTrust,
  checkSigningKeyRegistry,
};

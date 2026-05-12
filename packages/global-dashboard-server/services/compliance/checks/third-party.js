// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Check Functions: Third-Party Risk
//
// R3g PR2 (v1.0.33): GD-side counterpart to MC PR1's checks/third-party.js.
// Both files export the same 4 function names so framework definitions
// reference these checks uniformly across MC and GD. Implementations
// differ because the GD's third-party landscape is FUNDAMENTALLY
// different from MC's: the GD's primary third parties are the connected
// Management Consoles (management_consoles table), which push aggregate
// metrics inbound; SOAR/SIEM/cloud/etc. integrations are a future
// buildout layer.
//
// Each function returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'.
//
// THE GD's THIRD-PARTY MODEL
//
// LAYER 1 (always present): The MCs. Each connected MC is a third-party
// data source — it pushes aggregate metrics on a schedule and
// authenticates with an api_key (management_consoles.api_key). Per
// Foundational Rule 20 (BUILD-PLAN-v16), the GD never writes back to
// MC state, so the MCs are pure inbound dependencies.
//
// LAYER 2 (future, integration_config table): SOAR, SIEM, cloud, IAM,
// ticketing, and other operational integrations on the GD's own
// network. B5b (v1.0.51) introduces real IdP integration via
// integration_config; B3 (v1.0.48) wires SIEM/SOAR alerting; a future
// GD KMS phase adds kms_providers. Until those phases land, the GD's
// third-party surface is layer 1 only.
//
// LAYER 3 (future, signing-key registries):
//   - backup_signing_keys: GD's own backup manifest signing (mirroring
//     MC's R3d-5 pattern)
//   - chain_signing_keys: GD's own backup chain entry signing
//   - signing_keys: MC-trust registry for verifying inbound MC pushes
//     (R3g PR3 introduces this for the MC-push verification channel)
//
// FORWARD-COMPATIBLE PATTERN
//
// Each check function:
//   1. Always inspects layer-1 state (the MCs) since that exists today
//   2. Additionally queries layer-2 / layer-3 tables when they appear
//   3. Combines signals into a single status + detail
// This way the function reports honestly today AND expands naturally as
// the GD buildout adds the missing surfaces.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── tableExists ──────────────────────────────────────────────────────────────
// Forward-compatibility helper: returns true if a SQLite table named
// `name` exists in the connected DB.
function tableExists(db, name) {
  return !!db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?"
  ).get(name);
}

// ── checkIntegrationHealth ───────────────────────────────────────────────────
// Verifies the GD's third-party data sources are healthy. Always checks
// MC connection freshness (management_consoles.last_sync). When
// integration_config lands (B5b v1.0.51 et seq.), also checks SOAR /
// SIEM / cloud / IAM integration freshness via last_test_at. Returns
// combined warning if any source is stale or errored; pass if all are
// healthy.
//
// Maps to controls including: SOC 2 CC9.2 Vendor Management, NIST CSF
// GV.SC-04 / GV.SC-07, ISO 27001 A.5.21/A.5.22 ICT supply chain,
// NIST 800-53 SR-3 Supply Chain Controls, DORA Art.28 ICT Third-Party
// Service Providers, NIS2 Art.21(2)(d).
function checkIntegrationHealth(db) {
  const dayMs = 24 * 60 * 60 * 1000;

  // Layer 1: MC connection freshness
  const activeMcs = db.prepare(
    "SELECT id, name, last_sync FROM management_consoles WHERE status = 'active'"
  ).all();
  const staleMcs = activeMcs.filter(r => {
    if (!r.last_sync) return true;
    return (Date.now() - new Date(r.last_sync).getTime()) > dayMs;
  });

  // Layer 2: SOAR / SIEM / cloud / IAM integration freshness (forward-compatible)
  let integrationsChecked = false;
  let staleIntegrations = [];
  let erroredIntegrations = [];
  let operationalCount = 0;
  if (tableExists(db, 'integration_config')) {
    integrationsChecked = true;
    const operational = db.prepare(
      "SELECT integration_type, status, last_test_at FROM integration_config WHERE status = 'operational'"
    ).all();
    operationalCount = operational.length;
    staleIntegrations = operational.filter(r => {
      if (!r.last_test_at) return true;
      return (Date.now() - new Date(r.last_test_at).getTime()) > 30 * dayMs;
    });
    erroredIntegrations = db.prepare(
      "SELECT integration_type FROM integration_config WHERE status = 'error'"
    ).all();
  }

  const layer1Summary = activeMcs.length === 0
    ? 'no active MCs registered (third-party surface vacuously holds)'
    : `${activeMcs.length} active MC(s), ${staleMcs.length} with stale last_sync (>24h or NULL)`;
  const layer2Summary = !integrationsChecked
    ? 'integration_config table not yet present (B5b v1.0.51 et seq. will add SOAR/SIEM/IAM/cloud integrations)'
    : `${operationalCount} operational integration(s), ${staleIntegrations.length} stale (>30d), ${erroredIntegrations.length} errored`;

  if (staleMcs.length > 0 || staleIntegrations.length > 0 || erroredIntegrations.length > 0) {
    const issues = [];
    if (staleMcs.length > 0) {
      issues.push(`stale MCs: ${staleMcs.map(r => r.name || ('mc:' + r.id)).join(', ')}`);
    }
    if (erroredIntegrations.length > 0) {
      issues.push(`errored integrations: ${erroredIntegrations.map(r => r.integration_type).join(', ')}`);
    }
    if (staleIntegrations.length > 0) {
      issues.push(`stale integrations (>30d): ${staleIntegrations.map(r => r.integration_type).join(', ')}`);
    }
    return {
      status: 'warning',
      detail: `Integration health: ${issues.join('; ')}. Layer 1 (MCs): ${layer1Summary}. Layer 2: ${layer2Summary}.`,
    };
  }
  return {
    status: 'pass',
    detail: `Integration health: all third-party data sources healthy. Layer 1 (MCs): ${layer1Summary}. Layer 2: ${layer2Summary}.`,
  };
}

// ── checkVendorRiskAssessment ────────────────────────────────────────────────
// Verifies vendor risk assessment readiness. The platform tracks the
// foundational evidence (operational history, testing recency) that
// supports vendor risk review; formal vendor risk assessment (vendor
// questionnaires, SOC 2 report review, DPA negotiation) is customer-
// responsibility. Two-layer check:
//
//   Layer 1 (MCs): every active MC should have its country and
//   regulatory_framework documented, providing the jurisdictional
//   context for vendor risk review.
//
//   Layer 2 (integration_config, when present): every configured
//   integration should have at least one historical test result
//   (last_test_at not NULL), providing baseline operational evidence.
//
// Maps to controls including: SOC 2 CC9.2 Vendor Management,
// NIST CSF GV.SC-05 / GV.SC-06, ISO 27001 A.5.19/A.5.20,
// NIST 800-53 SR-2 Supply Chain Risk Management Plan, DORA Art.28-30
// Pre-contractual risk assessment, NIS2 Art.21(2)(d).
function checkVendorRiskAssessment(db) {
  // Layer 1: MC documentation completeness
  const activeMcs = db.prepare(
    "SELECT id, name, country, regulatory_framework FROM management_consoles WHERE status = 'active'"
  ).all();
  const undocumentedMcs = activeMcs.filter(r => !r.country || !r.regulatory_framework);

  // Layer 2: integration testing-readiness (forward-compatible)
  let integrationsChecked = false;
  let untestedIntegrations = [];
  let totalIntegrations = 0;
  if (tableExists(db, 'integration_config')) {
    integrationsChecked = true;
    const all = db.prepare(
      "SELECT integration_type, last_test_at FROM integration_config"
    ).all();
    totalIntegrations = all.length;
    untestedIntegrations = all.filter(r => !r.last_test_at);
  }

  if (activeMcs.length === 0 && !integrationsChecked) {
    return {
      status: 'pass',
      detail: 'No active MCs and no integration_config table — third-party surface empty. Vendor risk assessment vacuously holds.',
    };
  }

  const issues = [];
  if (undocumentedMcs.length > 0) {
    issues.push(`${undocumentedMcs.length} of ${activeMcs.length} active MC(s) missing country and/or regulatory_framework (jurisdictional context for vendor risk review): ${undocumentedMcs.map(r => r.name || ('mc:' + r.id)).join(', ')}`);
  }
  if (untestedIntegrations.length > 0) {
    issues.push(`${untestedIntegrations.length} of ${totalIntegrations} integration(s) never tested (no operational baseline for risk review): ${untestedIntegrations.map(r => r.integration_type).join(', ')}`);
  }

  if (issues.length > 0) {
    return {
      status: 'warning',
      detail: `Vendor risk readiness gaps: ${issues.join('; ')}. Formal vendor risk assessment (questionnaires, SOC 2 review, DPA negotiation) is customer-responsibility on top of this technical foundation.`,
    };
  }

  const summary = integrationsChecked
    ? `${activeMcs.length} active MC(s) documented (country + regulatory_framework); ${totalIntegrations} integration(s) all tested at least once`
    : `${activeMcs.length} active MC(s) documented (country + regulatory_framework); integration_config table not yet present (B5b v1.0.51 et seq. will add SOAR/SIEM/IAM/cloud integrations)`;
  return {
    status: 'pass',
    detail: `Vendor risk readiness: ${summary}. Formal vendor risk assessment (questionnaires, SOC 2 review, DPA negotiation) remains customer-responsibility.`,
  };
}

// ── checkKmsProviderTrust ────────────────────────────────────────────────────
// Verifies external KMS providers (when present) have recent successful
// probes. Mirrors MC's kms_providers.last_probe_status pattern. Two-state
// behavior: warning if kms_providers absent (future GD KMS phase); real
// per-provider trust evaluation once the table lands.
//
// Note: this function focuses on KMS-trust signal specifically (probe
// status + recency). The separate checkKmsProvider in checks/crypto.js
// reports the presence/absence of any KMS integration; this function
// (in checks/third-party.js) reports on the trust path WITHIN configured
// integrations.
//
// Maps to controls including: SOC 2 CC6.7, NIST CSF PR.DS-01,
// ISO 27001 A.8.24 Use of cryptography, NIST 800-53 SC-12
// Cryptographic Key Establishment, DORA Art.9(3).
function checkKmsProviderTrust(db) {
  if (!tableExists(db, 'kms_providers')) {
    return {
      status: 'warning',
      detail: 'GD has no external KMS integration as of v0.0.31 (kms_providers table not present). A future GD KMS integration phase (B-phase track in BUILD-PLAN-v16) will introduce per-provider trust probing; until then, KMS trust evaluation is operator-managed off-platform. When the table lands, this check reports per-provider probe status with 7-day recency expectation.',
    };
  }
  const enabled = db.prepare(
    "SELECT name, provider_type, last_probe_status, last_probe_at FROM kms_providers WHERE enabled = 1"
  ).all();
  if (enabled.length === 0) {
    return {
      status: 'warning',
      detail: 'kms_providers table present but no providers enabled. Configure an external KMS for SOC-grade key trust.',
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
// Verifies the platform's signing-key registries have active keys for
// each registered signing role. The GD's signing-key landscape comprises:
//
//   - backup_signing_keys (future GD buildout, parallel to MC's R3d-5
//     pattern): signs the GD's own per-backup manifests, Ed25519.
//   - chain_signing_keys (future GD buildout, parallel to MC's pattern):
//     signs GD backup chain entries, Ed25519.
//   - signing_keys (R3g PR3): MC-trust registry for verifying inbound
//     MC compliance-report pushes. Each connected MC registers a
//     signing key with the GD; PR3 signs pushed reports and the GD
//     verifies before accepting.
//
// Each registry adds when its corresponding phase ships. The check
// returns pass for any registry that exists AND has active keys; warning
// for any registry that doesn't yet exist; fail for any registry that
// exists but is empty.
//
// Maps to controls including: SOC 2 CC6.7/CC8.1, NIST CSF PR.DS-01 /
// PR.DS-10, ISO 27001 A.8.24/A.8.13, NIST 800-53 SC-12/SI-7,
// DORA Art.9(3)/Art.12, HIPAA 164.312(c)(1).
function checkSigningKeyRegistry(db) {
  const registries = [
    {
      table: 'backup_signing_keys',
      label: 'backup manifest signing',
      phaseNote: 'future GD backup-signing phase (parallel to MC R3d-5 pattern)',
    },
    {
      table: 'chain_signing_keys',
      label: 'backup chain entry signing',
      phaseNote: 'future GD backup-signing phase (parallel to MC pattern)',
    },
    {
      table: 'signing_keys',
      label: 'MC-trust verification',
      phaseNote: 'R3g PR3 (MC-push verification registry)',
    },
  ];

  const statuses = registries.map(r => {
    if (!tableExists(db, r.table)) {
      return { ...r, state: 'missing', activeCount: 0 };
    }
    let activeCount;
    try {
      const row = db.prepare(
        `SELECT COUNT(*) AS c FROM ${r.table} WHERE is_active = 1 AND rotated_out_at IS NULL`
      ).get();
      activeCount = row.c;
    } catch (e) {
      // Table exists but expected columns absent — surface as missing
      return { ...r, state: 'malformed', activeCount: 0 };
    }
    return { ...r, state: activeCount > 0 ? 'present' : 'empty', activeCount };
  });

  const missing = statuses.filter(s => s.state === 'missing');
  const empty = statuses.filter(s => s.state === 'empty');
  const malformed = statuses.filter(s => s.state === 'malformed');
  const present = statuses.filter(s => s.state === 'present');

  if (present.length === 0 && empty.length === 0 && malformed.length === 0) {
    // All registries missing — pre-phase state.
    return {
      status: 'warning',
      detail: `No signing-key registries present on the GD. Each future phase introduces one: ${registries.map(r => `${r.table} (${r.phaseNote})`).join('; ')}. Until those phases ship, MC → GD trust is api_key-based and operator-managed; GD backup integrity is hash-only (no cryptographic signature).`,
    };
  }

  if (empty.length > 0 || malformed.length > 0) {
    const issues = [];
    if (empty.length > 0) {
      issues.push(`empty registries: ${empty.map(s => `${s.table} (${s.label})`).join(', ')}`);
    }
    if (malformed.length > 0) {
      issues.push(`malformed registries (table present but expected columns missing): ${malformed.map(s => s.table).join(', ')}`);
    }
    return {
      status: 'fail',
      detail: `Signing-key registry gaps: ${issues.join('; ')}. ${present.length} present-and-populated: ${present.map(s => `${s.table} (${s.activeCount} active)`).join(', ') || 'none'}.`,
    };
  }

  const presentSummary = present.map(s => `${s.table} (${s.activeCount} active key(s), ${s.label})`).join('; ');
  const stillMissingSummary = missing.length > 0
    ? ` Not yet shipped: ${missing.map(s => `${s.table} (${s.phaseNote})`).join('; ')}.`
    : '';
  return {
    status: 'pass',
    detail: `Signing-key registries present and populated: ${presentSummary}.${stillMissingSummary}`,
  };
}

module.exports = {
  checkIntegrationHealth,
  checkVendorRiskAssessment,
  checkKmsProviderTrust,
  checkSigningKeyRegistry,
};

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
// MC connection freshness (management_consoles.last_sync). As of B6a also
// checks the GD's own self-protection integrations -- the SIEM/SOAR alert-
// routing config and the EDR seam (malware_scanner_integrations) -- and
// remains forward-compatible with a future unified integration_config
// table. Returns a combined warning if any source is stale or errored;
// pass if all are healthy.
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

  // Layer 2b: B6a self-protection integrations (the GD's own SIEM/SOAR/EDR for
  // protecting the GD server itself, never analyst data). SIEM/SOAR are config-
  // key based (presence only; no per-config test timestamp); the EDR seam
  // (malware_scanner_integrations) carries a per-integration last_test_status.
  const gdReadJson = (key) => {
    const row = db.prepare('SELECT value FROM config WHERE key = ?').get(key);
    if (!row || !row.value) return null;
    try { return JSON.parse(row.value); } catch { return null; }
  };
  const siemCfg = gdReadJson('siem_config');
  const soarCfg = gdReadJson('soar_config');
  const selfProt = [];
  if (siemCfg && siemCfg.endpoint) selfProt.push('SIEM');
  if (soarCfg && soarCfg.endpoint) selfProt.push('SOAR');
  let edrErrored = [];
  if (tableExists(db, 'malware_scanner_integrations')) {
    const edr = db.prepare(
      "SELECT display_name, last_test_status FROM malware_scanner_integrations WHERE enabled = 1"
    ).all();
    if (edr.length > 0) selfProt.push(edr.length + ' EDR');
    edrErrored = edr.filter(r => r.last_test_status === 'failed');
  }
  const selfProtSummary = selfProt.length > 0
    ? 'self-protection integrations: ' + selfProt.join(', ') + (edrErrored.length > 0 ? ' (' + edrErrored.length + ' EDR errored)' : '')
    : 'no self-protection integrations configured (in-platform runtime-monitor provides the baseline)';

  const layer1Summary = activeMcs.length === 0
    ? 'no active MCs registered (third-party surface vacuously holds)'
    : `${activeMcs.length} active MC(s), ${staleMcs.length} with stale last_sync (>24h or NULL)`;
  const integrationConfigSummary = !integrationsChecked
    ? 'unified integration_config table not yet present'
    : `${operationalCount} operational integration(s), ${staleIntegrations.length} stale (>30d), ${erroredIntegrations.length} errored`;
  const layer2Summary = `${integrationConfigSummary}; ${selfProtSummary}`;

  if (staleMcs.length > 0 || staleIntegrations.length > 0 || erroredIntegrations.length > 0 || edrErrored.length > 0) {
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
    if (edrErrored.length > 0) {
      issues.push(`errored EDR integrations: ${edrErrored.map(r => r.display_name).join(', ')}`);
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
//     MC compliance-report and metrics pushes. Each connected MC
//     registers a signing key with the GD; after manual CISO
//     approval, the GD verifies inbound push signatures against the
//     active approved row before accepting.
//
// R3g PR3 Phase 9 (C40): signing_keys is now special-cased to surface
// the approval workflow's state. Two queries replace the legacy
// is_active=1 count:
//   - approved + active: WHERE approval_status='approved' AND is_active=1
//     (currently-trusted MC signing keys, drives push verification)
//   - pending_approval:  WHERE approval_status='pending_approval'
//     (registrations awaiting CISO/signing_key_approver review)
//
// Status logic for signing_keys:
//   - mc_count == 0           -> 'warning' (pre-onboarding, can't have
//                                signing keys yet)
//   - approved_active == 0    -> 'warning' (MCs registered but no
//                                handshakes completed)
//   - stale_pending > 0       -> 'warning' (pending registrations >7d
//                                old suggests neglected CISO review,
//                                a compliance signal under
//                                ISO 27001 A.6.1.2 segregation /
//                                A.9.2.5 access reviews)
//   - else                    -> 'pass'
//
// The seven-day staleness threshold reflects industry norms for
// access-review SLAs. Tighter thresholds (e.g., 24h) generate noise;
// looser (e.g., 30d) misses neglected workflows.
//
// Maps to controls including: SOC 2 CC6.7/CC6.6/CC8.1, NIST CSF
// PR.DS-01 / PR.DS-10 / PR.AC-01, ISO 27001 A.8.24/A.8.13/A.6.1.2,
// NIST 800-53 SC-12/SI-7/AC-5, DORA Art.9(3)/Art.12, HIPAA 164.312(c)(1).
function checkSigningKeyRegistry(db) {
  // ── Backup registries (legacy is_active=1 check) ──
  const backupRegistries = [
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
  ];

  const backupStatuses = backupRegistries.map(r => {
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
      return { ...r, state: 'malformed', activeCount: 0 };
    }
    return { ...r, state: activeCount > 0 ? 'present' : 'empty', activeCount };
  });

  // ── signing_keys (R3g PR3 Phase 5 approval workflow) ──
  let signingKeysAssessment;
  if (!tableExists(db, 'signing_keys')) {
    signingKeysAssessment = {
      table: 'signing_keys',
      label: 'MC-trust verification',
      phaseNote: 'R3g PR3 (MC-push verification registry)',
      state: 'missing',
    };
  } else {
    try {
      const mcCountRow = db.prepare(
        "SELECT COUNT(*) AS c FROM management_consoles WHERE status = 'active'"
      ).get();
      const approvedActiveRow = db.prepare(
        "SELECT COUNT(*) AS c FROM signing_keys WHERE approval_status = 'approved' AND is_active = 1"
      ).get();
      const pendingRow = db.prepare(
        "SELECT COUNT(*) AS c FROM signing_keys WHERE approval_status = 'pending_approval'"
      ).get();
      const stalePendingRow = db.prepare(
        "SELECT COUNT(*) AS c FROM signing_keys WHERE approval_status = 'pending_approval' AND registered_at < datetime('now', '-7 days')"
      ).get();
      const distinctMcsRow = db.prepare(
        "SELECT COUNT(DISTINCT mc_id) AS c FROM signing_keys WHERE approval_status = 'approved' AND is_active = 1"
      ).get();

      signingKeysAssessment = {
        table: 'signing_keys',
        label: 'MC-trust verification',
        mcCount: mcCountRow.c,
        approvedActive: approvedActiveRow.c,
        pending: pendingRow.c,
        stalePending: stalePendingRow.c,
        distinctMcs: distinctMcsRow.c,
      };

      // Classify state for the combined-status logic below
      if (mcCountRow.c === 0) {
        signingKeysAssessment.state = 'pre_onboarding';
      } else if (approvedActiveRow.c === 0) {
        signingKeysAssessment.state = 'no_handshakes';
      } else if (stalePendingRow.c > 0) {
        signingKeysAssessment.state = 'stale_pending';
      } else {
        signingKeysAssessment.state = 'healthy';
      }
    } catch (e) {
      // Table exists but expected columns absent — surface as malformed
      signingKeysAssessment = {
        table: 'signing_keys',
        label: 'MC-trust verification',
        state: 'malformed',
        error: e.message,
      };
    }
  }

  // ── Combine into single status + detail ──
  const allBackupMissing = backupStatuses.every(s => s.state === 'missing');
  const signingKeysMissing = signingKeysAssessment.state === 'missing';

  // Edge case: nothing exists yet
  if (allBackupMissing && signingKeysMissing) {
    return {
      status: 'warning',
      detail: `No signing-key registries present on the GD. Each future phase introduces one: ${[...backupRegistries, { table: 'signing_keys', label: 'MC-trust verification', phaseNote: 'R3g PR3 (MC-push verification registry)' }].map(r => `${r.table} (${r.phaseNote})`).join('; ')}. Until those phases ship, MC → GD trust is api_key-based and operator-managed; GD backup integrity is hash-only (no cryptographic signature).`,
    };
  }

  // Fail conditions: any registry empty/malformed
  const empty = backupStatuses.filter(s => s.state === 'empty');
  const malformed = backupStatuses.filter(s => s.state === 'malformed');
  if (signingKeysAssessment.state === 'malformed') {
    malformed.push(signingKeysAssessment);
  }
  const present = backupStatuses.filter(s => s.state === 'present');

  if (empty.length > 0 || malformed.length > 0) {
    const issues = [];
    if (empty.length > 0) {
      issues.push(`empty registries: ${empty.map(s => `${s.table} (${s.label})`).join(', ')}`);
    }
    if (malformed.length > 0) {
      issues.push(`malformed registries (table present but expected columns missing): ${malformed.map(s => s.table).join(', ')}`);
    }
    // Add signing_keys context to the fail detail
    const skNote = signingKeysAssessment.state === 'malformed'
      ? ''
      : signingKeysAssessment.state === 'missing'
      ? ` signing_keys registry not yet shipped (R3g PR3 phase).`
      : ` signing_keys: ${signingKeysAssessment.approvedActive || 0} approved active key(s) across ${signingKeysAssessment.distinctMcs || 0} MC(s), ${signingKeysAssessment.pending || 0} pending review.`;
    return {
      status: 'fail',
      detail: `Signing-key registry gaps: ${issues.join('; ')}. ${present.length} present-and-populated: ${present.map(s => `${s.table} (${s.activeCount} active)`).join(', ') || 'none'}.${skNote}`,
    };
  }

  // signing_keys state-specific signals (the R3g PR3 Phase 9 logic)
  if (signingKeysAssessment.state === 'pre_onboarding') {
    return {
      status: 'warning',
      detail: `signing_keys registry exists but no Management Consoles are registered yet. MC-trust verification cannot exercise until at least one MC is onboarded via POST /api/mc/register and completes its initial handshake. Backup registries: ${backupStatuses.map(s => s.state === 'present' ? `${s.table} (${s.activeCount} active)` : `${s.table} (${s.state})`).join('; ')}.`,
    };
  }

  if (signingKeysAssessment.state === 'no_handshakes') {
    return {
      status: 'warning',
      detail: `${signingKeysAssessment.mcCount} MC(s) registered but 0 approved active signing keys. Handshakes have not yet completed; MC pushes will currently reject for lack of trust. ${signingKeysAssessment.pending} registration(s) awaiting CISO/signing_key_approver review. Operators: invoke POST /api/mc/<id>/signing-keys/<keyId>/approve to unblock.`,
    };
  }

  if (signingKeysAssessment.state === 'stale_pending') {
    return {
      status: 'warning',
      detail: `${signingKeysAssessment.approvedActive} signing key(s) are approved and active across ${signingKeysAssessment.distinctMcs} MC(s). ${signingKeysAssessment.pending} registration(s) awaiting CISO/signing_key_approver review, ${signingKeysAssessment.stalePending} of which are older than 7 days — suggests neglected approvals (ISO 27001 A.6.1.2 / A.9.2.5 access-review signal). Operator review of GET /api/signing-keys/pending recommended.`,
    };
  }

  // Healthy path
  const presentSummary = present.map(s => `${s.table} (${s.activeCount} active key(s), ${s.label})`).join('; ');
  const stillMissingBackup = backupStatuses.filter(s => s.state === 'missing');
  const stillMissingSummary = stillMissingBackup.length > 0
    ? ` Not yet shipped: ${stillMissingBackup.map(s => `${s.table} (${s.phaseNote})`).join('; ')}.`
    : '';
  const skHealthy = `signing_keys (${signingKeysAssessment.approvedActive} signing keys are approved and active across ${signingKeysAssessment.distinctMcs} MCs. ${signingKeysAssessment.pending} registrations are awaiting CISO/signing_key_approver review).`;

  return {
    status: 'pass',
    detail: `Signing-key registries present and populated: ${presentSummary ? presentSummary + '; ' : ''}${skHealthy}${stillMissingSummary}`,
  };
}

module.exports = {
  checkIntegrationHealth,
  checkVendorRiskAssessment,
  checkKmsProviderTrust,
  checkSigningKeyRegistry,
};

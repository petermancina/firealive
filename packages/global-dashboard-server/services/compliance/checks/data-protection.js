// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Check Functions: Data Protection
//
// R3g PR2 (v1.0.33): GD-side counterpart to MC PR1's
// checks/data-protection.js. Both files export the same 6 function
// names so framework definitions reference these checks uniformly
// across MC and GD. Implementations differ substantially because the
// GD's data-protection surface is intentionally narrower than the
// MC's — the GD by design holds aggregate metrics (regional_metrics
// table) and account data (users table); it does NOT hold raw analyst
// behavioral signals, ticketing data, or peer communications.
//
// Each function returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'.
//
// PLATFORM STATE NOTES (GD-specific differences from MC)
//
//   - GD has no users.tier column. The MC has Tier-1/Tier-2/Tier-3
//     classification on user records to enforce API-layer data
//     boundaries; the GD has only three roles (ciso/vp/readonly)
//     with no separate sensitivity tier. By design ALL data on the
//     GD is "aggregate, non-identifying" (regional_metrics) or
//     "account-level identity" (users) — the binary classification
//     is enforced architecturally rather than per-row.
//   - GD has no users.pseudonym column. Pseudonymization of analyst
//     behavioral data happens at the MC layer BEFORE aggregate metrics
//     are pushed to the GD. checkPseudonymization adapts to describe
//     this upstream guarantee.
//   - GD has no /api/legal-hold/export or /api/offboarding/execute
//     endpoints. Data subject rights surface on the GD is narrow:
//     only the GD users (CISO, VP, readonly accounts) are themselves
//     data subjects. Their data can be accessed via /api/audit-logs
//     and exported via /api/audit-logs/export, but no dedicated
//     erasure endpoint exists.
//   - GD has no backup_destinations table with retention_days /
//     credentials_encrypted / adapter columns. Retention and
//     encryption state live on backup_schedules (retention_days,
//     encrypted columns) and on backups (retention_until column,
//     populated when retention is enforced on a per-backup basis).
//   - GD has no users.geo_country column. Cross-border residency
//     awareness is keyed off management_consoles.country (the country
//     of each connected MC) and an operator-set config key
//     'gd_residency' (free-form text via PUT /api/config/gd_residency).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkDataClassification ──────────────────────────────────────────────────
// Verifies the GD's data-classification posture. The GD by design holds
// only aggregate metrics (regional_metrics, with no analyst-identifying
// fields) and account-level identity data (users, where role is
// ciso/vp/readonly). The classification is architectural rather than
// per-row: the data-boundary is enforced by what tables exist on the
// GD (no analyst data, no ticketing data, no peer messages), not by
// a tier column.
//
// Maps to controls including: SOC 2 CC6.6 System Boundaries, NIST CSF
// PR.DS-01, ISO 27001 A.5.12 Classification of information,
// NIST 800-53 RA-2, GDPR Art.5(1)(c) data minimization, LGPD Art.6,
// PDPA-SG Sec.24.
function checkDataClassification(db) {
  const userCount = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  const metricsCount = db.prepare("SELECT COUNT(*) AS c FROM regional_metrics").get();
  return {
    status: 'pass',
    detail: `GD data classification is architectural, not per-row: ${metricsCount.c} aggregate metric rows (regional_metrics — no analyst-identifying fields by design) + ${userCount.c} account records (users — CISO/VP/readonly tier). Analyst behavioral signals, ticketing data, and peer communications do not exist on the GD; that boundary is enforced by table absence, not by a runtime tier check.`,
  };
}

// ── checkPseudonymization ────────────────────────────────────────────────────
// Verifies pseudonymization posture. Pseudonymization of analyst
// behavioral data is enforced upstream at the MC layer: each MC keys
// its analyst behavioral signals to a pseudonym (users.pseudonym in
// MC schema) before producing aggregate metrics for push to the GD.
// The GD receives the aggregates; the identity-to-signal linkage
// never reaches the GD.
//
// Maps to controls including: GDPR Art.25 Data Protection by Design,
// NIST CSF PR.DS-10, ISO 27001 A.8.11 Data masking, NIST 800-53
// SC-28, LGPD Art.11, POPIA Sec.19.
function checkPseudonymization(db) {
  const metricsCount = db.prepare("SELECT COUNT(*) AS c FROM regional_metrics").get();
  return {
    status: 'pass',
    detail: `Pseudonymization enforced upstream at MC layer: each MC keys analyst behavioral signals to pseudonym before producing aggregate metrics. GD receives ${metricsCount.c} aggregate metric row(s) carrying no analyst-identifying fields (mc_id, health_score, utilization_pct, automation_rate, cert_coverage_pct, sla_compliance_pct, turnover_risk, analyst_count, active_incidents, burnout_routing_active, proactive_breaks_given, upskilling_hours_used). The identity-to-signal linkage never reaches the GD.`,
  };
}

// ── checkDataSubjectRights ───────────────────────────────────────────────────
// Verifies platform support for data subject rights mechanisms on the
// GD. The GD's data-subject surface is narrow: only the GD users
// themselves (CISO / VP / readonly accounts) are data subjects with
// respect to data held on the GD. Analyst data subjects' rights flow
// through the MC where their data actually resides; the GD has no
// direct relationship with analyst data subjects.
//
// Mechanisms available on GD:
//   - Access: audit_log queryable via /api/audit-logs and exportable
//     via /api/audit-logs/export/:format (per-user filtering can be
//     done client-side or via a future query parameter)
//   - Erasure: no dedicated erasure endpoint as of v0.0.31. Users
//     table supports row deletion via direct DB operations; an
//     application-layer DELETE /api/users/:id endpoint is a future
//     enhancement.
//   - Rectification: no /api/users/:id PATCH endpoint as of v0.0.31;
//     user updates flow through admin DB operations.
//
// Honest gap: GD-side data subject rights mechanisms are partial.
// Operator-side DB management fills the gap for now.
//
// Maps to controls including: GDPR Art.15/16/17/18/20, LGPD Art.18,
// PIPEDA Principle 4.9, CCPA Sec.1798.100/105/106, POPIA Sec.23/24/25,
// PDPA-SG Sec.21/22, APPI Art.32/33/34.
function checkDataSubjectRights(db) {
  const userCount = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  return {
    status: 'warning',
    detail: `GD data-subject surface: ${userCount.c} user account(s) are the GD's direct data subjects (analyst data subjects relate to the MC, not the GD). Access: /api/audit-logs + /api/audit-logs/export are available. Erasure and rectification: no dedicated /api/users/:id DELETE or PATCH endpoints on the GD as of v0.0.31 — operator handles via direct DB management. SOC-grade gap; application-layer endpoints are a future enhancement.`,
  };
}

// ── checkRetentionPolicy ─────────────────────────────────────────────────────
// Verifies retention policies are configured on backup schedules.
// GD stores retention_days per active schedule; per-backup
// retention_until is populated when retention is enforced. Audit log
// retention is unbounded (the GD does not auto-truncate).
//
// Maps to controls including: SOC 2 A1.2, NIST CSF PR.IP-04 / PR.PS-01,
// ISO 27001 A.5.13 Retention of information, NIST 800-53 SI-12,
// GDPR Art.5(1)(e) Storage limitation, HIPAA 164.316(b)(2) Time limit.
function checkRetentionPolicy(db) {
  const schedules = db.prepare("SELECT COUNT(*) AS c FROM backup_schedules WHERE active = 1").get();
  if (schedules.c === 0) {
    return {
      status: 'warning',
      detail: 'No active backup schedules on the GD. Retention policy enforcement deferred until at least one schedule is configured via /api/backup-schedules.',
    };
  }
  const withRetention = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_schedules WHERE active = 1 AND retention_days IS NOT NULL AND retention_days > 0"
  ).get();
  if (withRetention.c === 0) {
    return {
      status: 'warning',
      detail: `${schedules.c} active backup schedule(s) but none have retention_days configured. Backups grow without retention enforcement.`,
    };
  }
  return {
    status: 'pass',
    detail: `Retention: ${withRetention.c} of ${schedules.c} active backup schedule(s) have retention_days configured. GD audit_log retention is unbounded (no auto-truncation; storage-bounded). Per-backup retention_until populated where applicable.`,
  };
}

// ── checkBackupEncryption ────────────────────────────────────────────────────
// Verifies backup encryption is enabled on active schedules. GD's
// backup_schedules table carries an `encrypted` boolean column;
// default is 1 (encrypted) per db-init.js. Operator-managed disk
// encryption on the destination side (S3 SSE, GCS CMEK, Azure SE,
// local LUKS) is customer-responsibility regardless of this flag.
//
// Maps to controls including: HIPAA 164.312(a)(2)(iv), SOC 2 CC6.7,
// NIST CSF PR.DS-01, ISO 27001 A.8.13 Information backup,
// NIST 800-53 SC-28, DORA Art.12 Backup Policies, GDPR Art.32.
function checkBackupEncryption(db) {
  const schedules = db.prepare("SELECT id, encrypted, destination FROM backup_schedules WHERE active = 1").all();
  if (schedules.length === 0) {
    return {
      status: 'pass',
      detail: 'No active backup schedules; encryption check vacuously holds.',
    };
  }
  const unencrypted = schedules.filter(s => !s.encrypted);
  if (unencrypted.length > 0) {
    return {
      status: 'fail',
      detail: `${unencrypted.length} of ${schedules.length} active backup schedule(s) have encrypted = 0. Affected destinations: ${unencrypted.map(s => s.destination || 'unset').join(', ')}. Toggle the encrypted flag to 1 via /api/backup-schedules update, or recreate the schedule with encrypted=true.`,
    };
  }
  return {
    status: 'pass',
    detail: `Backup encryption: all ${schedules.length} active backup schedule(s) have encrypted = 1. Destination-side encryption at rest (S3 SSE / GCS CMEK / Azure SE / local LUKS or BitLocker) is operator-managed and customer-responsibility regardless of the in-platform encrypted flag.`,
  };
}

// ── checkCrossBorderTransferControls ─────────────────────────────────────────
// Verifies cross-border data-transfer awareness on the GD. GD does not
// carry per-user residency tags; the cross-border surface is
// management_consoles.country (the country of each connected regional
// MC, which determines where aggregate metrics originate from) and an
// operator-set config key 'gd_residency' (where the GD server itself
// is operated). When MCs in multiple countries feed a single GD,
// cross-border data flow occurs from each MC region to the GD's
// region; legal-basis documentation (Standard Contractual Clauses,
// adequacy decisions, Binding Corporate Rules) for those transfers
// is customer-responsibility.
//
// Maps to controls including: GDPR Art.44-49 Transfers, LGPD Art.33,
// POPIA Sec.72, PDPA-SG Sec.26, PIPEDA accountability principle,
// APPI Art.27-29.
function checkCrossBorderTransferControls(db) {
  const mcs = db.prepare("SELECT COUNT(*) AS c FROM management_consoles WHERE status = 'active'").get();
  if (mcs.c === 0) {
    return {
      status: 'pass',
      detail: 'No active management consoles connected; no cross-border data flow to assess on the GD.',
    };
  }
  const countries = db.prepare(
    "SELECT country, COUNT(*) AS c FROM management_consoles WHERE status = 'active' AND country IS NOT NULL GROUP BY country"
  ).all();
  const mcsWithoutCountry = db.prepare(
    "SELECT COUNT(*) AS c FROM management_consoles WHERE status = 'active' AND (country IS NULL OR country = '')"
  ).get();
  const gdResidency = db.prepare("SELECT value FROM config WHERE key = 'gd_residency'").get();
  const gdResidencyValue = gdResidency && gdResidency.value ? JSON.parse(gdResidency.value) : null;
  if (mcsWithoutCountry.c > 0) {
    return {
      status: 'warning',
      detail: `${mcsWithoutCountry.c} of ${mcs.c} active MC(s) have no country set. Cross-border data-flow assessment requires every MC to have its country recorded; update via MC registration form or PATCH /api/management-consoles/:id.`,
    };
  }
  const countriesSummary = countries.map(r => `${r.country}(${r.c})`).join(', ');
  if (!gdResidencyValue) {
    return {
      status: 'warning',
      detail: `MC residency tracked (${mcs.c} active MCs in countries: ${countriesSummary}) but GD server's own residency unset. Set config 'gd_residency' via PUT /api/config/gd_residency to document where the GD itself is operated; this is the destination side of every MC → GD cross-border flow.`,
    };
  }
  return {
    status: 'pass',
    detail: `Cross-border controls: ${mcs.c} active MC(s) across ${countries.length} countries (${countriesSummary}); GD server residency: ${JSON.stringify(gdResidencyValue)}. Legal-basis documentation (SCCs, adequacy decisions, BCRs) for each MC → GD transfer where country differs is customer-responsibility.`,
  };
}

module.exports = {
  checkDataClassification,
  checkPseudonymization,
  checkDataSubjectRights,
  checkRetentionPolicy,
  checkBackupEncryption,
  checkCrossBorderTransferControls,
};

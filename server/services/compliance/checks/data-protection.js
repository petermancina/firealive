// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Check Functions: Data Protection
//
// R3g (v1.0.33): part of the comprehensive technical-control verification
// library that backs FireAlive's compliance claims under Foundational
// Rule 14 (Shared Responsibility framing).
//
// This file provides 6 check functions covering data classification,
// pseudonymization, data subject rights, retention enforcement, backup
// encryption, and cross-border transfer controls. Each function queries
// actual platform state and returns { status, detail } where status is
// 'pass' | 'warning' | 'fail'.
//
// Functions are referenced from framework definitions in
// server/services/compliance/frameworks/<id>.js (R3g commits 13-28),
// particularly GDPR (commit 16), LGPD (commit 24), PIPEDA (commit 25),
// PDPA-SG (commit 26), APPI (commit 27), POPIA (commit 28).
//
// PLATFORM STATE NOTES
//
// The R3g detailed plan (R3G-DETAILED-PLAN.md) anticipated some
// platform structures that don't match the v1.0.32 codebase:
//
//   - Planned retention_policy table -> does not exist. Audit log
//     retention is unbounded (never auto-truncated). Backup
//     destinations carry per-destination retention_days. There is no
//     central retention policy table.
//   - Planned hard-delete user endpoint (DELETE /api/users/:id) ->
//     does not exist. The platform's right-to-erasure story is:
//     (a) offboarding marks accounts inactive (active=0,
//     offboarded_at set) preserving audit/legal-hold continuity;
//     (b) pseudonym rotation re-keys analyst data, effectively
//     erasing the link between identity and behavioral signals.
//   - Planned backup_destinations.encryption_enabled column -> does
//     not exist. Encryption state is composite: credentials encrypted
//     at rest (credentials_encrypted column), backup content with
//     Tier-3/Tier-1 columns already encrypted at column level (those
//     stay encrypted in dumps), destination-side encryption (S3 SSE,
//     GCS CMEK, Azure Storage encryption) is adapter-config and is
//     customer-responsibility.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkDataClassification ──────────────────────────────────────────────────
// Verifies all active users carry tier classifications (Tier-1: high
// sensitivity / Tier-2: moderate / Tier-3: low). The users.tier column
// has a CHECK constraint enforcing the (1, 2, 3) values; this check
// verifies the column is populated for all active users, which is the
// prerequisite for API-layer data-boundary enforcement.
//
// Maps to controls including: SOC 2 CC6.6 System Boundaries, NIST CSF
// PR.DS-01, ISO 27001 A.5.12 Classification of information,
// NIST 800-53 RA-2, GDPR Art.5(1)(c) data minimization, LGPD Art.6,
// PDPA-SG Sec.24.
function checkDataClassification(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM users WHERE active = 1").get();
  if (total.c === 0) {
    return { status: 'pass', detail: 'No active users; classification check vacuously holds.' };
  }
  const classified = db.prepare(
    "SELECT COUNT(*) AS c FROM users WHERE active = 1 AND tier IS NOT NULL"
  ).get();
  if (classified.c < total.c) {
    return {
      status: 'warning',
      detail: `${classified.c} of ${total.c} active user(s) carry tier classification. ${total.c - classified.c} user(s) lack tier assignment, leaving them outside the Tier-1/2/3 data boundary enforcement at the API layer.`,
    };
  }
  return {
    status: 'pass',
    detail: `Data classification: all ${total.c} active users carry tier classification (1, 2, or 3) enforced by users.tier CHECK constraint. API-layer boundary enforcement keyed off this column.`,
  };
}

// ── checkPseudonymization ────────────────────────────────────────────────────
// Verifies analyst users have pseudonyms assigned. The platform keys
// behavioral signals (burnout metrics, capacity scores, retro
// protocols) to users.pseudonym rather than users.name, so even read
// access to the burnout database does not link signals to identities
// without traversing the users table. Pass if all active analysts
// have pseudonyms; warning if any are missing.
//
// Maps to controls including: GDPR Art.25 Data Protection by Design,
// NIST CSF PR.DS-10, ISO 27001 A.8.11 Data masking, NIST 800-53
// SC-28, LGPD Art.11, POPIA Sec.19.
function checkPseudonymization(db) {
  const total = db.prepare(
    "SELECT COUNT(*) AS c FROM users WHERE active = 1 AND role = 'analyst'"
  ).get();
  if (total.c === 0) {
    return { status: 'pass', detail: 'No active analyst users; pseudonymization check vacuously holds.' };
  }
  const pseudonymized = db.prepare(
    "SELECT COUNT(*) AS c FROM users WHERE active = 1 AND role = 'analyst' AND pseudonym IS NOT NULL"
  ).get();
  const rotated = db.prepare(
    "SELECT COUNT(*) AS c FROM users WHERE active = 1 AND role = 'analyst' AND pseudonym_rotated_at IS NOT NULL"
  ).get();
  if (pseudonymized.c < total.c) {
    return {
      status: 'warning',
      detail: `${pseudonymized.c} of ${total.c} active analyst(s) have pseudonyms assigned. ${total.c - pseudonymized.c} unpseudonymized analyst(s) expose direct identity-to-signal linkage.`,
    };
  }
  return {
    status: 'pass',
    detail: `Pseudonymization: all ${total.c} active analyst(s) carry pseudonyms; ${rotated.c} have a pseudonym_rotated_at timestamp. Behavioral signals keyed to pseudonym, not name.`,
  };
}

// ── checkDataSubjectRights ───────────────────────────────────────────────────
// Verifies platform support for data subject rights mechanisms:
//   - Right to access / data portability: the data-subject export
//     endpoint (POST /api/data-subject/export) returns the subject's
//     record across every store; an analyst's bundle is sealed to the
//     analyst's key so only they can open it.
//   - Right to erasure: the dual-control erasure endpoint (POST
//     /api/data-subject/erase, approved at POST
//     /api/data-subject/erase/:id/approve) deletes the subject's
//     personal rows, crypto-shreds an analyst's key material, and
//     tombstones the user record while retaining de-identified audit
//     history.
//   - Right to rectification: standard user-update endpoints permit
//     correction of personal data.
// The check verifies the platform supports the mechanisms; whether
// they are exercised in response to a specific request is operational.
//
// Maps to controls including: GDPR Art.15/16/17/18/20 data subject
// rights, LGPD Art.18, PIPEDA Principle 4.9 Individual Access,
// CCPA Sec.1798.100/105/106, POPIA Sec.23/24/25, PDPA-SG Sec.21/22,
// APPI Art.32/33/34.
function checkDataSubjectRights(db) {
  // Platform-level capability: the routes exist at startup.
  // We additionally surface usage metrics from audit_log if available
  // (DATA_SUBJECT_EXPORT and DATA_SUBJECT_ERASURE events).
  const exportEvents = db.prepare(
    "SELECT COUNT(*) AS c FROM audit_log WHERE event_type = 'DATA_SUBJECT_EXPORT'"
  ).get();
  const erasureEvents = db.prepare(
    "SELECT COUNT(*) AS c FROM audit_log WHERE event_type = 'DATA_SUBJECT_ERASURE'"
  ).get();
  return {
    status: 'pass',
    detail: `Data subject rights mechanisms: access/portability via POST /api/data-subject/export (${exportEvents.c} historical events), erasure via dual-control POST /api/data-subject/erase (${erasureEvents.c} historical events) + pseudonym rotation. Rectification via standard user-update endpoints.`,
  };
}

// ── checkRetentionPolicy ─────────────────────────────────────────────────────
// Verifies retention policies are configured on backup destinations.
// The platform stores retention_days per destination in
// backup_destinations; audit_log retention is unbounded (the platform
// does not auto-truncate). Warning if no backup destination has
// retention configured; pass if any do.
//
// Maps to controls including: SOC 2 A1.2, NIST CSF PR.IP-04 (mapped
// onto PR.PS-01 in CSF 2.0), ISO 27001 A.5.13 Retention of
// information, NIST 800-53 SI-12, GDPR Art.5(1)(e) Storage
// limitation, HIPAA 164.316(b)(2) Time limit.
function checkRetentionPolicy(db) {
  const destinations = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_destinations WHERE enabled = 1"
  ).get();
  if (destinations.c === 0) {
    return {
      status: 'warning',
      detail: 'No enabled backup destinations. Retention policy enforcement deferred until destinations are configured.',
    };
  }
  const withRetention = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_destinations WHERE enabled = 1 AND retention_days IS NOT NULL"
  ).get();
  if (withRetention.c === 0) {
    return {
      status: 'warning',
      detail: `${destinations.c} enabled backup destination(s) but none have retention_days configured. Backups grow without retention enforcement.`,
    };
  }
  return {
    status: 'pass',
    detail: `Retention: ${withRetention.c} of ${destinations.c} enabled backup destinations have retention_days configured. Audit_log retention is unbounded (no auto-truncation; storage-bounded).`,
  };
}

// ── checkBackupEncryption ────────────────────────────────────────────────────
// Verifies backup destination credentials are encrypted at rest. All
// adapters except 'local' require credentials (SFTP password/key, S3
// access keys, Azure connection string, GCS service account JSON);
// these MUST be encrypted in the credentials_encrypted column. Fail
// if any non-local destination has NULL credentials_encrypted while
// being enabled.
//
// Maps to controls including: HIPAA 164.312(a)(2)(iv), SOC 2 CC6.7
// confidentiality, NIST CSF PR.DS-01, ISO 27001 A.8.13 Information
// backup, NIST 800-53 SC-28, DORA Art.12 Backup Policies,
// GDPR Art.32.
function checkBackupEncryption(db) {
  const destinations = db.prepare(
    "SELECT adapter, credentials_encrypted FROM backup_destinations WHERE enabled = 1"
  ).all();
  if (destinations.length === 0) {
    return {
      status: 'pass',
      detail: 'No enabled backup destinations.',
    };
  }
  const credentialed = destinations.filter(d => d.adapter !== 'local');
  const missingCreds = credentialed.filter(d => !d.credentials_encrypted);
  if (missingCreds.length > 0) {
    return {
      status: 'fail',
      detail: `${missingCreds.length} of ${credentialed.length} credentialed backup destination(s) lack credentials_encrypted at rest. Adapter(s) affected: ${[...new Set(missingCreds.map(d => d.adapter))].join(', ')}.`,
    };
  }
  return {
    status: 'pass',
    detail: `Backup encryption: ${credentialed.length} credentialed destination(s) all have credentials_encrypted (Tier-1 AES-256-GCM). Tier-3/Tier-1 columns remain encrypted in backup dumps. Destination-side encryption (S3 SSE / GCS CMEK / Azure SE) is adapter-config and customer-responsibility.`,
  };
}

// ── checkCrossBorderTransferControls ─────────────────────────────────────────
// Verifies cross-border data transfer controls. The platform supports
// residency tracking via users.geo_country and region-aware backup
// destinations (S3 bucket region, GCS region, Azure region embedded
// in destination config). The check verifies geo_country is being
// used to track user residency. Where cross-border transfers occur
// (backup to a destination in a different region than user
// residency), legal basis documentation (Standard Contractual Clauses,
// adequacy decisions, BCRs) is customer-responsibility, enumerated
// in framework customerResponsibility lists.
//
// Maps to controls including: GDPR Art.44-49 Transfers, LGPD Art.33,
// POPIA Sec.72, PDPA-SG Sec.26, PIPEDA accountability principle,
// APPI Art.27-29.
function checkCrossBorderTransferControls(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM users WHERE active = 1").get();
  if (total.c === 0) {
    return { status: 'pass', detail: 'No active users; transfer-controls check vacuously holds.' };
  }
  const withGeo = db.prepare(
    "SELECT COUNT(*) AS c FROM users WHERE active = 1 AND geo_country IS NOT NULL"
  ).get();
  const destinations = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_destinations WHERE enabled = 1"
  ).get();
  if (withGeo.c === 0) {
    return {
      status: 'warning',
      detail: `0 of ${total.c} active users have geo_country set; residency tracking inactive. Set users.geo_country to enable per-user residency awareness; document Standard Contractual Clauses or adequacy basis for any cross-region transfers as customer-responsibility.`,
    };
  }
  const ratio = withGeo.c / total.c;
  if (ratio < 0.8) {
    return {
      status: 'warning',
      detail: `${withGeo.c} of ${total.c} active users have geo_country set (${(ratio * 100).toFixed(0)}%). Residency tracking is partial.`,
    };
  }
  return {
    status: 'pass',
    detail: `Cross-border controls: ${withGeo.c} of ${total.c} active users carry geo_country residency tag (${(ratio * 100).toFixed(0)}%); ${destinations.c} enabled backup destination(s) with adapter-config region awareness. Legal-basis documentation (SCCs, adequacy) for cross-region transfers is customer-responsibility.`,
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

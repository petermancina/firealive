// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Check Functions: Resilience & Incident Response
//
// R3g (v1.0.33): part of the comprehensive technical-control verification
// library that backs FireAlive's compliance claims under Foundational
// Rule 14 (Shared Responsibility framing).
//
// This file provides 5 check functions covering backup frequency,
// multi-destination resilience, DR test recency, incident response
// plan existence, and notification timing SLAs. Each function queries
// actual platform state and returns { status, detail } where status is
// 'pass' | 'warning' | 'fail'.
//
// Functions are referenced from framework definitions in
// server/services/compliance/frameworks/<id>.js (R3g commits 13-28),
// particularly SOC 2 Availability category (commit 14), DORA
// (commit 17), NIS2 (commit 21), HIPAA Contingency Plan
// requirements (in commit 13's customerResponsibility list).
//
// PLATFORM STATE NOTES
//
// The R3g detailed plan (R3G-DETAILED-PLAN.md) anticipated some
// platform structures that don't match the v1.0.32 codebase:
//
//   - Planned ooda_policies table -> actual table is ir_policies
//     with policy_type CHECK (incident_response, playbook, runbook,
//     policy, procedure).
//   - Planned restore_approvals status='approved' AND executed=1 ->
//     actual status='consumed' means an approved restore was
//     executed (consumed_at timestamp set at consumption time).
//   - Planned alert_config -> sla_config holds the incident
//     notification SLAs: p1_mtta, p1_mttr, p2_mtta, p2_mttr.
//   - Planned backup_push schedule interpretation -> backup_pushes
//     is the history table (one row per push attempt); backup
//     scheduling lives in a separate lazy-created backup_schedules
//     table (in backup-service.js). The realistic signal for
//     "backups are running" is backup_pushes.status='succeeded'
//     in a recent window.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkBackupFrequency ─────────────────────────────────────────────────────
// Verifies the platform has had successful backup pushes within the
// last 48 hours. Backup scheduling is configured in the lazy-created
// backup_schedules table (backup-service.js); evidence of actual
// execution comes from backup_pushes.status='succeeded' rows. Warning
// if zero successful pushes in 48h (either no schedule, or scheduler
// is broken); pass if any recent success.
//
// Maps to controls including: SOC 2 A1.1/A1.2, NIST CSF PR.IP-04
// (CSF 1.1) / PR.PS-01 (CSF 2.0), ISO 27001 A.8.13 Information
// backup, NIST 800-53 CP-9 System Backup, DORA Art.12 Backup
// Policies, HIPAA 164.308(a)(7)(ii)(A) Data Backup Plan.
function checkBackupFrequency(db) {
  const recent = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_pushes WHERE status = 'succeeded' AND pushed_at > datetime('now', '-48 hours')"
  ).get();
  const total = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_pushes WHERE status = 'succeeded'"
  ).get();
  if (recent.c === 0 && total.c === 0) {
    return {
      status: 'warning',
      detail: 'No successful backup pushes recorded. Configure backup schedules and destinations to enable automated backups.',
    };
  }
  if (recent.c === 0) {
    return {
      status: 'warning',
      detail: `${total.c} historical successful backup push(es) but none in the last 48 hours. Scheduler may have stalled or destinations may be in error state.`,
    };
  }
  return {
    status: 'pass',
    detail: `Backup frequency: ${recent.c} successful push(es) in last 48 hours (${total.c} historical total). SHA-256 integrity verification on each push.`,
  };
}

// ── checkBackupMultiDestination ──────────────────────────────────────────────
// Verifies the platform maintains backups across multiple destinations
// to survive single-destination failure. Warning if zero or one
// destination enabled; pass if two or more. The R3d multi-destination
// architecture supports parallel pushes to local + S3 + Azure + GCS
// + SFTP.
//
// Maps to controls including: SOC 2 A1.2 Availability — Capacity,
// NIST CSF PR.IP-04 / PR.PS-01, ISO 27001 A.8.14 Redundancy of
// information processing facilities, NIST 800-53 CP-9(1),
// DORA Art.12, HIPAA 164.308(a)(7)(ii)(B) Disaster Recovery Plan.
function checkBackupMultiDestination(db) {
  const destinations = db.prepare(
    "SELECT adapter, COUNT(*) AS c FROM backup_destinations WHERE enabled = 1 GROUP BY adapter"
  ).all();
  const total = destinations.reduce((sum, r) => sum + r.c, 0);
  if (total === 0) {
    return {
      status: 'warning',
      detail: 'No enabled backup destinations. Configure at least two destinations across different adapter types for redundancy.',
    };
  }
  if (total === 1) {
    return {
      status: 'warning',
      detail: `Only 1 backup destination enabled (adapter: ${destinations[0].adapter}). Single-destination configuration cannot survive a destination failure. Add a second destination of a different type for redundancy.`,
    };
  }
  const adapterTypes = destinations.length;
  const summary = destinations.map(r => `${r.adapter}(${r.c})`).join(', ');
  return {
    status: 'pass',
    detail: `Multi-destination resilience: ${total} enabled destination(s) across ${adapterTypes} adapter type(s): ${summary}.`,
  };
}

// ── checkDrTestRecency ───────────────────────────────────────────────────────
// Verifies a disaster recovery restore has been executed in the last
// 90 days (DR testing requirement). The restore_approvals table
// tracks restore requests; status='consumed' with consumed_at set
// indicates an approved restore was executed. Warning if no consumed
// restore in the last 90 days; pass if any recent.
//
// Maps to controls including: SOC 2 A1.3 Availability — Recovery
// Testing, NIST CSF PR.IP-10 / RC.RP-02, ISO 27001 A.8.13/A.5.29
// Information security during disruption, NIST 800-53 CP-4
// Contingency Plan Testing, DORA Art.24, HIPAA 164.308(a)(7)(ii)(D)
// Testing and Revision.
function checkDrTestRecency(db) {
  const recent = db.prepare(
    "SELECT COUNT(*) AS c FROM restore_approvals WHERE status = 'consumed' AND consumed_at > datetime('now', '-90 days')"
  ).get();
  const total = db.prepare(
    "SELECT COUNT(*) AS c FROM restore_approvals WHERE status = 'consumed'"
  ).get();
  if (total.c === 0) {
    return {
      status: 'warning',
      detail: 'No restore approvals have been consumed (no DR test ever executed). Schedule a DR drill using the Backup tab\'s restore workflow.',
    };
  }
  if (recent.c === 0) {
    return {
      status: 'warning',
      detail: `${total.c} historical DR test(s) executed but none in the last 90 days. SOC-grade norm is at least quarterly DR testing.`,
    };
  }
  return {
    status: 'pass',
    detail: `DR test recency: ${recent.c} consumed restore(s) in last 90 days (${total.c} historical total). Approval-gated workflow with TOTP enforcement.`,
  };
}

// ── checkIrPlanExists ────────────────────────────────────────────────────────
// Verifies the platform has incident response plans on file. The
// ir_policies table holds uploaded IR documents tagged by policy_type
// (incident_response, playbook, runbook, policy, procedure). Warning
// if no incident_response or playbook entries exist; pass if any
// non-deleted IR policies are present. Surfaces historical retro
// protocol counts for incident-response activity context.
//
// Maps to controls including: SOC 2 CC7.4 Respond to Security
// Incidents, NIST CSF RS.MA-01 Incident Management, ISO 27001
// A.5.24 Information security incident management planning,
// NIST 800-53 IR-8 Incident Response Plan, DORA Art.17/18,
// NIS2 Art.21(2)(b), HIPAA 164.308(a)(6) Security Incident
// Procedures.
function checkIrPlanExists(db) {
  const irPolicies = db.prepare(
    "SELECT policy_type, COUNT(*) AS c FROM ir_policies WHERE deleted_at IS NULL AND policy_type IN ('incident_response', 'playbook') GROUP BY policy_type"
  ).all();
  const totalIr = irPolicies.reduce((sum, r) => sum + r.c, 0);
  const allPolicies = db.prepare(
    "SELECT COUNT(*) AS c FROM ir_policies WHERE deleted_at IS NULL"
  ).get();
  const retros = db.prepare("SELECT COUNT(*) AS c FROM retro_protocols").get();
  if (totalIr === 0) {
    if (allPolicies.c === 0) {
      return {
        status: 'warning',
        detail: 'No IR policies on file (ir_policies is empty). Upload incident response plans and playbooks via the Policies tab.',
      };
    }
    return {
      status: 'warning',
      detail: `${allPolicies.c} policy document(s) on file but none tagged 'incident_response' or 'playbook'. Tag relevant documents accordingly.`,
    };
  }
  const summary = irPolicies.map(r => `${r.policy_type}(${r.c})`).join(', ');
  return {
    status: 'pass',
    detail: `IR plan: ${totalIr} document(s) (${summary}); ${allPolicies.c} total non-deleted policies. Historical incident-response activity: ${retros.c} retro protocol(s).`,
  };
}

// ── checkNotificationTiming ──────────────────────────────────────────────────
// Verifies incident-notification SLA timings are configured. The
// sla_config singleton holds p1_mtta (Mean Time To Acknowledge for
// P1 incidents), p1_mttr (Mean Time To Resolve), p2_mtta, p2_mttr.
// SOC-grade norm for P1 is 5-minute MTTA, 60-minute MTTR; defaults
// match this. Pass if the default row exists and all four timing
// fields are populated; warning otherwise.
//
// Maps to controls including: SOC 2 CC7.4, NIST CSF DE.AE-06
// Notifications Provided / RS.CO-02 Stakeholder Notification,
// ISO 27001 A.5.24, NIST 800-53 IR-6 Incident Reporting,
// NIS2 Art.23 Significant incident notification (24-hour rule),
// DORA Art.19 Reporting of Major ICT Incidents, GDPR Art.33
// Breach Notification (72-hour rule).
function checkNotificationTiming(db) {
  const cfg = db.prepare("SELECT * FROM sla_config WHERE id = 'default'").get();
  if (!cfg) {
    return {
      status: 'warning',
      detail: 'sla_config has no default row -- incident-notification SLAs not initialized. Default timings (P1 5m MTTA / 60m MTTR; P2 15m MTTA / 4h MTTR) apply at the application layer.',
    };
  }
  const missing = [];
  if (!cfg.p1_mtta) missing.push('p1_mtta');
  if (!cfg.p1_mttr) missing.push('p1_mttr');
  if (!cfg.p2_mtta) missing.push('p2_mtta');
  if (!cfg.p2_mttr) missing.push('p2_mttr');
  if (missing.length > 0) {
    return {
      status: 'warning',
      detail: `sla_config missing timing field(s): ${missing.join(', ')}.`,
    };
  }
  return {
    status: 'pass',
    detail: `Notification timing: P1 MTTA=${cfg.p1_mtta} MTTR=${cfg.p1_mttr}; P2 MTTA=${cfg.p2_mtta} MTTR=${cfg.p2_mttr}. NIS2 24-hour and GDPR 72-hour external-notification timings are deployment policy on top of internal SLAs.`,
  };
}

module.exports = {
  checkBackupFrequency,
  checkBackupMultiDestination,
  checkDrTestRecency,
  checkIrPlanExists,
  checkNotificationTiming,
};

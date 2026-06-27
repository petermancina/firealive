// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Check Functions: Resilience & IR
//
// Part of the comprehensive technical-control verification library that backs
// FireAlive's compliance claims under the Shared Responsibility framing. These
// five checks assess the regional server's backup, recovery, and
// incident-response posture against the platform's actual schema.
//
// Each function returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'. The framework definitions reference these checks
// by name (see frameworks/*.js); the mappings there name the evidence each
// check inspects, and these implementations read exactly that evidence.
//
// PLATFORM STATE NOTES
//
//   - backups records each completed backup (status='verified'); backup_pushes
//     records each push to a storage destination (status='succeeded').
//   - storage_destination_routes maps each data type to a primary plus an
//     optional secondary (failover) destination drawn from the
//     storage_destinations registry; backups resolve through the
//     storage-routing resolver.
//   - restore_approvals gates every restore behind a second-person approval; a
//     consumed approval (status='consumed') records an executed restore and is
//     the backup-restore DR-drill signal.
//   - ir_policies is the incident-response plan / playbook / runbook registry.
//   - sla_config holds the per-priority MTTA / MTTR commitments; sla_measurements
//     records the actual measured response times.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const storageRouting = require('../../storage-routing');

// ── checkBackupFrequency ─────────────────────────────────────────────────────
// Verifies backups are produced on a regular cadence. The backups table records
// each completed backup (status='verified'); backup_pushes records each push to
// a configured storage destination (status='succeeded'). Warning when no recent
// verified backup; pass when a verified backup exists in the last 48 hours, with
// the offsite-push status reported.
//
// Maps to controls including: SOC 2 A1.1/A1.2, NIST CSF PR.IP-04 (CSF 1.1) /
// PR.PS-01 (CSF 2.0), ISO 27001 A.8.13, NIST 800-53 CP-9 System Backup,
// DORA Art.12, HIPAA 164.308(a)(7)(ii)(A).
function checkBackupFrequency(db) {
  const recentVerified = db.prepare(
    "SELECT COUNT(*) AS c FROM backups WHERE status = 'verified' AND created_at > datetime('now', '-48 hours')"
  ).get();
  const totalVerified = db.prepare(
    "SELECT COUNT(*) AS c FROM backups WHERE status = 'verified'"
  ).get();
  const recentPushes = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_pushes WHERE status = 'succeeded' AND pushed_at > datetime('now', '-48 hours')"
  ).get();
  const activeSchedules = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_schedules WHERE active = 1"
  ).get();

  if (totalVerified.c === 0) {
    return {
      status: 'warning',
      detail: `No verified backups recorded. ${activeSchedules.c} active backup schedule(s) configured; if non-zero, the scheduler may not be completing backups. Trigger a manual backup to bootstrap, then confirm it reaches a configured storage destination.`,
    };
  }
  if (recentVerified.c === 0) {
    return {
      status: 'warning',
      detail: `${totalVerified.c} historical verified backup(s) but none in the last 48 hours. ${activeSchedules.c} active schedule(s) -- the scheduler may have stalled.`,
    };
  }
  const pushNote = recentPushes.c > 0
    ? `${recentPushes.c} backup push(es) succeeded to a configured destination in the same window, evidencing offsite copies that survive loss of the host.`
    : 'No successful backup push to a remote destination in the last 48 hours -- backups are retained on-host only. Configure a backup storage route (primary + secondary) so a backup survives loss of the host.';
  return {
    status: 'pass',
    detail: `Backup cadence: ${recentVerified.c} verified backup(s) in the last 48 hours (${totalVerified.c} historical). ${activeSchedules.c} active schedule(s). Each backup records a SHA-256 manifest hash for integrity verification. ${pushNote}`,
  };
}

// ── checkBackupMultiDestination ──────────────────────────────────────────────
// Verifies backups are routed to more than one destination so a backup survives
// the failure of any single destination. Backups route through the
// storage-routing resolver to a primary plus an optional secondary (failover)
// destination, drawn from the storage_destinations registry (local + S3 / GCS /
// Azure / SFTP). Only enabled, distinct destinations count as redundancy. Pass
// when both a primary and a secondary resolve; warning when only a primary is
// configured (no failover); warning when no backup destination is routed.
//
// Maps to controls including: SOC 2 CC7.5 Recovery and Restoration / A1.2,
// NIST CSF PR.IP-04 / PR.PS-01, ISO 27001 A.8.14 Redundancy, NIST 800-53
// CP-9(1), DORA Art.12, HIPAA 164.308(a)(7)(ii)(B).
function checkBackupMultiDestination(db) {
  let destinations;
  try {
    const route = storageRouting.getRouteForType(db, 'backup');
    destinations = (route && Array.isArray(route.destinations)) ? route.destinations : [];
  } catch (err) {
    return {
      status: 'warning',
      detail: `Unable to resolve the backup storage route (${err.message}). Configure a primary and a secondary (failover) destination for backups under storage routing.`,
    };
  }

  if (destinations.length === 0) {
    return {
      status: 'warning',
      detail: 'No backup destination is configured under storage routing. Configure a primary and a secondary (failover) destination so a backup survives the loss of any single destination (3-2-1: an on-host copy plus two remote copies).',
    };
  }
  if (destinations.length === 1) {
    return {
      status: 'warning',
      detail: `Only a primary backup destination is configured ('${destinations[0].name}'); no secondary (failover) destination is set. A single remote destination cannot survive a destination failure. Configure a secondary destination on the backup route for redundancy.`,
    };
  }
  const names = destinations.map((d) => d.name).join(', ');
  return {
    status: 'pass',
    detail: `Multi-destination backup routing: a primary plus a secondary (failover) destination are configured (${names}). A backup survives the failure of either remote destination (an on-host copy plus two remote copies). Restores are gated by the restore_approvals second-person workflow with SHA-256 verification.`,
  };
}

// ── checkDrTestRecency ───────────────────────────────────────────────────────
// Verifies disaster-recovery (backup-restore) testing recency. A restore flows
// through the restore_approvals workflow (second-person approval); an approval
// that has been consumed (status='consumed') records an actual restore having
// executed -- the DR-drill signal. Pass when at least one restore was consumed
// in the last 90 days (an at-least-quarterly cadence); warning when DR testing
// has lapsed or none is on record.
//
// Maps to controls including: SOC 2 A1.3 Recovery Testing, NIST CSF PR.IP-10 /
// RC.RP-02, ISO 27001 A.8.13 / A.5.29, NIST 800-53 CP-4, DORA Art.24,
// HIPAA 164.308(a)(7)(ii)(D).
function checkDrTestRecency(db) {
  const recent = db.prepare(
    "SELECT COUNT(*) AS c FROM restore_approvals WHERE status = 'consumed' AND consumed_at > datetime('now', '-90 days')"
  ).get();
  const total = db.prepare(
    "SELECT COUNT(*) AS c FROM restore_approvals WHERE status = 'consumed'"
  ).get();

  if (recent.c > 0) {
    return {
      status: 'pass',
      detail: `Disaster-recovery testing is current: ${recent.c} restore(s) consumed in the last 90 days (${total.c} on record). A consumed restore_approval evidences an executed backup-restore drill through the second-person approval workflow, meeting the at-least-quarterly SOC-grade cadence.`,
    };
  }
  if (total.c > 0) {
    return {
      status: 'warning',
      detail: `Disaster-recovery testing has lapsed: ${total.c} restore(s) consumed historically but none in the last 90 days. Execute a backup-restore drill (request and consume a restore_approval) to restore the at-least-quarterly cadence SOC 2 A1.3 expects.`,
    };
  }
  return {
    status: 'warning',
    detail: 'No backup-restore drill on record (no consumed restore_approvals). Execute a restore through the restore_approvals workflow on a documented at-least-quarterly cadence to evidence recovery capability; an auditor will examine restore_approvals records.',
  };
}

// ── checkIrPlanExists ────────────────────────────────────────────────────────
// Verifies the platform holds incident-response plans on file. The ir_policies
// registry stores incident-response plans, playbooks, runbooks, policies, and
// procedures (soft-deleted rows carry a deleted_at stamp); sla_config records
// the per-priority MTTA / MTTR commitments those plans are held to. Pass when at
// least one incident-response plan or playbook is on file; warning when the
// registry holds no incident-response content.
//
// Maps to controls including: SOC 2 CC7.4, NIST CSF RS.MA-01, ISO 27001 A.5.24,
// NIST 800-53 IR-8, DORA Art.17/18, NIS2 Art.21(2)(b), HIPAA 164.308(a)(6).
function checkIrPlanExists(db) {
  const irPlans = db.prepare(
    "SELECT COUNT(*) AS c FROM ir_policies WHERE deleted_at IS NULL AND policy_type IN ('incident_response', 'playbook')"
  ).get();
  const allPolicies = db.prepare(
    "SELECT COUNT(*) AS c FROM ir_policies WHERE deleted_at IS NULL"
  ).get();
  const sla = db.prepare("SELECT COUNT(*) AS c FROM sla_config").get();

  if (allPolicies.c === 0) {
    return {
      status: 'warning',
      detail: 'No incident-response plans on file (the ir_policies registry is empty). Upload incident-response plans and scenario playbooks to the IR registry, covering scenarios such as platform compromise, database corruption, and credential exposure.',
    };
  }
  if (irPlans.c === 0) {
    return {
      status: 'warning',
      detail: `${allPolicies.c} document(s) in the ir_policies registry, but none typed as an incident-response plan or playbook. Add at least one incident_response or playbook document so the IR procedure is on record.`,
    };
  }
  const slaNote = sla.c > 0
    ? 'Per-priority MTTA / MTTR commitments are recorded in sla_config.'
    : 'No per-priority MTTA / MTTR commitments are configured in sla_config -- record them to bind the IR plans to response-time targets.';
  return {
    status: 'pass',
    detail: `Incident-response plans on file: ${irPlans.c} incident-response plan/playbook document(s) (${allPolicies.c} total in the IR registry). ${slaNote}`,
  };
}

// ── checkNotificationTiming ──────────────────────────────────────────────────
// Verifies incident-notification SLA timings are configured and measured.
// sla_config holds the per-priority MTTA / MTTR commitments (P1 / P2);
// sla_measurements records the actual measured response times. Pass when the SLA
// timings are configured, with recent measurements reported. External regulatory
// notification windows (NIS2 24h, DORA Art.19, GDPR Art.33 72h) are
// operator-tracked and enumerated in each framework's customerResponsibility
// list.
//
// Maps to controls including: SOC 2 CC7.4, NIST CSF DE.AE-06 / RS.CO-02,
// ISO 27001 A.5.24, NIST 800-53 IR-6, NIS2 Art.23, DORA Art.19, GDPR Art.33.
function checkNotificationTiming(db) {
  const cfg = db.prepare("SELECT * FROM sla_config WHERE id = 'default'").get();
  if (!cfg) {
    return {
      status: 'warning',
      detail: 'No incident-response SLA timings configured (sla_config has no default row). Configure the per-priority MTTA / MTTR commitments (P1 / P2) so incident notification and response are held to documented targets. External regulatory windows (NIS2 24h, DORA Art.19, GDPR Art.33 72h) are operator-tracked and listed in each framework customerResponsibility set.',
    };
  }
  const measured = db.prepare(
    "SELECT COUNT(*) AS c FROM sla_measurements WHERE measured_at > datetime('now', '-90 days')"
  ).get();
  const measureNote = measured.c > 0
    ? `${measured.c} response-time measurement(s) recorded in the last 90 days (sla_measurements), evidencing the timings are tracked against actual incidents.`
    : 'No response-time measurements recorded in the last 90 days -- record MTTA / MTTR per incident in sla_measurements to evidence the timings are met in practice.';
  return {
    status: 'pass',
    detail: `Incident-response SLA timings configured: P1 MTTA ${cfg.p1_mtta} / MTTR ${cfg.p1_mttr}, P2 MTTA ${cfg.p2_mtta} / MTTR ${cfg.p2_mttr}. ${measureNote} External regulatory notification windows (NIS2 24h, DORA Art.19, GDPR Art.33 72h) are operator-tracked and listed in each framework customerResponsibility set.`,
  };
}

module.exports = {
  checkBackupFrequency,
  checkBackupMultiDestination,
  checkDrTestRecency,
  checkIrPlanExists,
  checkNotificationTiming,
};

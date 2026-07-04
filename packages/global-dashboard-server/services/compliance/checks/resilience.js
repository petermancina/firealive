// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Check Functions: Resilience & IR
//
// R3g PR2 (v1.0.33): GD-side counterpart to MC PR1's
// checks/resilience.js. Both files export the same 5 function names
// so framework definitions reference these checks uniformly across
// MC and GD. Implementations differ because the GD has a substantially
// smaller resilience-and-IR surface than the MC.
//
// Each function returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'.
//
// PLATFORM STATE NOTES (GD-specific gaps relative to MC)
//
//   - The backups table is the direct record of completed backups;
//     rows are inserted by the v2 backup services (POST /api/backup,
//     CISO-only) and by the backup scheduler. Per-destination push
//     history now lives in the backup_pushes table.
//   - The destinations registry is storage_destinations (adapter
//     configs, credentials, immutability, and routing). This check
//     keys off the destination column on each backup_schedules row,
//     so it reflects scheduled-backup fan-out coverage rather than the
//     registry itself.
//   - GD has no restore_approvals table. The MC's DR test gauge is
//     restore_approvals.status='consumed' rows; the GD has no
//     restore workflow at all and therefore no DR test signal of
//     that kind. Closest proxies: /api/regression-test (a real
//     integration-test suite that is not a backup-restore drill)
//     and /api/compromise-scan (which DOES log a
//     COMPROMISE_SCAN audit event). Neither is a true backup-restore
//     drill; the GD has no backup-restore DR-drill infrastructure as of v0.0.31.
//   - GD has no ir_policies table. checkIrPlanExists returns warning;
//     IR planning for the GD is operator-managed off-platform.
//   - GD has no sla_config table. Notification thresholds live in
//     config.notification_config JSON (burnout_threshold, sla_below,
//     etc. — domain-specific thresholds, not incident MTTA/MTTR
//     timings). checkNotificationTiming returns warning describing
//     the gap.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkBackupFrequency ─────────────────────────────────────────────────────
// Verifies the GD has had backups recorded within the last 48 hours.
// The backups table is the direct record of completed backups
// (no separate push-history table on the GD). Warning if zero recent
// backups; pass if any in the last 48h.
//
// Maps to controls including: SOC 2 A1.1/A1.2, NIST CSF PR.IP-04
// (CSF 1.1) / PR.PS-01 (CSF 2.0), ISO 27001 A.8.13, NIST 800-53
// CP-9 System Backup, DORA Art.12, HIPAA 164.308(a)(7)(ii)(A).
function checkBackupFrequency(db) {
  const recent = db.prepare(
    "SELECT COUNT(*) AS c FROM backups WHERE status = 'verified' AND created_at > datetime('now', '-48 hours')"
  ).get();
  const total = db.prepare(
    "SELECT COUNT(*) AS c FROM backups WHERE status = 'verified'"
  ).get();
  const activeSchedules = db.prepare(
    "SELECT COUNT(*) AS c FROM backup_schedules WHERE active = 1"
  ).get();
  if (total.c === 0) {
    return {
      status: 'warning',
      detail: `No verified backups recorded on the GD. ${activeSchedules.c} active backup schedule(s) configured; if non-zero, the scheduler may not be wiring through to backups table insertion. Trigger a manual backup via POST /api/backup to bootstrap.`,
    };
  }
  if (recent.c === 0) {
    return {
      status: 'warning',
      detail: `${total.c} historical verified backup(s) on the GD but none in the last 48 hours. ${activeSchedules.c} active schedule(s) — scheduler may have stalled.`,
    };
  }
  return {
    status: 'pass',
    detail: `Backup frequency: ${recent.c} verified backup(s) in last 48 hours (${total.c} historical total). ${activeSchedules.c} active backup schedule(s). Each backup records SHA-256 hash for integrity verification.`,
  };
}

// ── checkBackupMultiDestination ──────────────────────────────────────────────
// Verifies the GD maintains backups across multiple destinations to
// survive single-destination failure. The GD's backup_schedules table
// has a `destination` column (free-form string per schedule). The
// check counts distinct destination values across ACTIVE schedules.
// Warning if zero or one distinct destination; pass if two or more.
//
// Maps to controls including: SOC 2 A1.2 Availability — Capacity,
// NIST CSF PR.IP-04 / PR.PS-01, ISO 27001 A.8.14 Redundancy,
// NIST 800-53 CP-9(1), DORA Art.12, HIPAA 164.308(a)(7)(ii)(B).
function checkBackupMultiDestination(db) {
  const rows = db.prepare(
    "SELECT destination, COUNT(*) AS c FROM backup_schedules WHERE active = 1 AND destination IS NOT NULL AND destination != '' GROUP BY destination"
  ).all();
  if (rows.length === 0) {
    return {
      status: 'warning',
      detail: 'No active backup schedules with destinations configured on the GD. Configure at least two schedules pointing to different destinations for redundancy.',
    };
  }
  if (rows.length === 1) {
    return {
      status: 'warning',
      detail: `Only 1 distinct backup destination across active schedules: '${rows[0].destination}' (${rows[0].c} schedule(s) using it). Single-destination configuration cannot survive a destination failure. Add a schedule pointing to a different destination for redundancy.`,
    };
  }
  const summary = rows.map(r => `${r.destination}(${r.c})`).join(', ');
  return {
    status: 'pass',
    detail: `Multi-destination resilience on the GD: ${rows.length} distinct destinations across active schedules: ${summary}.`,
  };
}

// ── checkDrTestRecency ───────────────────────────────────────────────────────
// Verifies disaster recovery test recency. The GD has no backup-restore
// DR-drill infrastructure as of v0.0.31:
//   - /api/regression-test runs a real integration-test suite (and writes
//     a REGRESSION_RUN audit entry) but does not exercise backup-restore.
//   - /api/compromise-scan does log a COMPROMISE_SCAN audit event but
//     is a self-scan, not a recovery drill.
//   - There is no restore workflow on the GD (no restore_approvals
//     table; no PUT/POST /api/backups/:id/restore endpoint).
// Honest gap: DR testing on the GD is operator-managed off-platform
// (operator restores a backup to a side-by-side GD instance manually).
//
// Maps to controls including: SOC 2 A1.3 Availability — Recovery
// Testing, NIST CSF PR.IP-10 / RC.RP-02, ISO 27001 A.8.13/A.5.29,
// NIST 800-53 CP-4, DORA Art.24, HIPAA 164.308(a)(7)(ii)(D).
function checkDrTestRecency(db) {
  const compromiseScans = db.prepare(
    "SELECT COUNT(*) AS c FROM audit_log WHERE event_type = 'COMPROMISE_SCAN' AND timestamp > datetime('now', '-90 days')"
  ).get();
  if (compromiseScans.c > 0) {
    return {
      status: 'warning',
      detail: `GD has no application-layer DR test infrastructure as of v0.0.31 (no restore workflow; /api/regression-test runs a real integration-test suite but is not a backup-restore drill). ${compromiseScans.c} compromise-scan event(s) in last 90 days provide partial self-integrity signal but are not a true backup-restore drill. SOC-grade DR testing on the GD is currently operator-managed off-platform.`,
    };
  }
  return {
    status: 'warning',
    detail: 'GD has no application-layer DR test infrastructure as of v0.0.31. SOC-grade DR testing is operator-managed off-platform (restore a backup to a side-by-side GD instance on a documented cadence — quarterly per SOC 2 A1.3 norm).',
  };
}

// ── checkIrPlanExists ────────────────────────────────────────────────────────
// Verifies the platform has incident response plans on file. GD has
// no ir_policies table or equivalent IR document registry. IR
// planning at the GD layer (CISO/governance-tier IR) is
// operator-managed off-platform.
//
// Note: SOC-level IR procedures (analyst-facing) live at the MC layer
// — the GD is not responsible for SOC-level IR planning. The IR gap
// at the GD layer covers things like: what happens if the GD is
// compromised; what happens if the GD's database is corrupted; what
// happens if an MC is detected pushing suspicious aggregate metrics.
//
// Maps to controls including: SOC 2 CC7.4, NIST CSF RS.MA-01,
// ISO 27001 A.5.24, NIST 800-53 IR-8, DORA Art.17/18,
// NIS2 Art.21(2)(b), HIPAA 164.308(a)(6).
function checkIrPlanExists() {
  return {
    status: 'warning',
    detail: 'GD has no application-layer IR policy registry (no ir_policies table or document-upload endpoint as of v0.0.31). CISO/governance-tier incident response planning is operator-managed off-platform. Document scenarios specific to the GD layer: GD compromise, GD database corruption, suspicious aggregate metrics from an MC.',
  };
}

// ── checkNotificationTiming ──────────────────────────────────────────────────
// Verifies incident-notification SLA timings are configured. GD has
// no sla_config table; notification_config in the config key-value
// table holds domain-specific thresholds (burnout_threshold,
// sla_below) but not incident MTTA/MTTR timings. The GD's
// notification model is threshold-driven (alert when X crosses Y)
// rather than incident-severity-driven (P1 needs response in N
// minutes). The gap matters for frameworks that mandate timed
// incident notification (NIS2 24-hour rule, DORA Art.19, GDPR
// Art.33 72-hour rule).
//
// Maps to controls including: SOC 2 CC7.4, NIST CSF DE.AE-06 /
// RS.CO-02, ISO 27001 A.5.24, NIST 800-53 IR-6, NIS2 Art.23,
// DORA Art.19, GDPR Art.33.
function checkNotificationTiming(db) {
  const row = db.prepare("SELECT value FROM config WHERE key = 'notification_config'").get();
  if (!row || !row.value) {
    return {
      status: 'warning',
      detail: 'GD has no incident-timing SLA configuration. config.notification_config absent. SOC-grade incident-response SLAs (P1 MTTA, P1 MTTR, P2 MTTA, P2 MTTR) are operator-managed off-platform; external regulatory timings (NIS2 24h, GDPR 72h, DORA Art.19) are documented in framework customerResponsibility lists.',
    };
  }
  let cfg;
  try {
    cfg = JSON.parse(row.value);
  } catch (e) {
    return {
      status: 'fail',
      detail: `config.notification_config failed to parse: ${e.message}.`,
    };
  }
  return {
    status: 'warning',
    detail: `GD notification model is threshold-driven, not incident-severity-driven. notification_config holds domain thresholds (burnout_threshold=${cfg.burnout_threshold}, sla_below=${cfg.sla_below}) and delivery flags (email=${!!cfg.email}, sms=${!!cfg.sms}) but no incident MTTA/MTTR timings. External regulatory notification windows (NIS2 24h, DORA Art.19, GDPR Art.33 72h breach notification) are operator-tracked off-platform and enumerated in framework customerResponsibility lists.`,
  };
}

module.exports = {
  checkBackupFrequency,
  checkBackupMultiDestination,
  checkDrTestRecency,
  checkIrPlanExists,
  checkNotificationTiming,
};

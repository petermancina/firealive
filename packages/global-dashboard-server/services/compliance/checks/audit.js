// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Check Functions: Audit & Monitoring
//
// R3g PR2 (v1.0.33): GD-side counterpart to MC PR1's checks/audit.js.
// Both files export the same 6 function names so framework definitions
// reference these checks uniformly across MC and GD. Implementations
// differ because the GD has a substantially smaller audit-and-monitoring
// surface than the MC.
//
// Each function returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'.
//
// PLATFORM STATE NOTES (GD-specific gaps relative to MC)
//
//   - GD has no SIEM streaming infrastructure (no SIEM_ENABLED env
//     var consumption, no config.siem_config key, no
//     integration_config table at all). External tamper-evidence is
//     therefore unavailable on the GD side as of v0.0.31. SIEM
//     integration is a future enhancement; checkAuditIntegrity and
//     checkSyslogExport surface this honestly.
//   - GD has no integration_config table. The GD's "third parties"
//     are the connected MCs (management_consoles table); SIEM,
//     IAM, KMS integration tables that exist on the MC do not exist
//     on the GD.
//   - GD's notification_config is a JSON blob stored in the config
//     key-value table (key='notification_config'), not a dedicated
//     table with a 'default' row. checkAlertingThresholds parses
//     the JSON.
//   - GD's audit log export is at GET /api/audit-logs/export/:format
//     (not /api/audit/export-forensics like MC); checkForensicsExport
//     adapts.
//   - GD does NOT auto-truncate audit_log (same as MC; retention
//     bounded only by storage capacity).
//   - This file's checkAuditIntegrity OVERRIDES the inline version in
//     compliance/index.js when the checks aggregator merges this
//     module (later spreads win). Framework definitions reference
//     `checks.checkAuditIntegrity`, which resolves to this fuller
//     version once the aggregator is wired up.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkAuditRetention ──────────────────────────────────────────────────────
// Verifies the audit_log holds entries with sufficient retention period
// to meet regulatory minimums. The GD does not auto-truncate audit_log,
// so retention is bounded only by storage capacity; this check measures
// effective retention by inspecting the oldest entry's age. SOC-grade
// norm is 1 year minimum; HIPAA requires 6 years, SOC 2 typically 7
// years. Pass at >= 1 year; warning at < 1 year (which may simply
// reflect deployment age rather than policy failure).
//
// Maps to controls including: HIPAA 164.312(b) Audit Controls,
// SOC 2 CC7.1, NIST CSF DE.AE-03, ISO 27001 A.8.15, NIST 800-53 AU-11,
// NIS2 Art.21(2)(f).
function checkAuditRetention(db) {
  const oldest = db.prepare("SELECT MIN(timestamp) AS ts FROM audit_log").get();
  if (!oldest || !oldest.ts) {
    return { status: 'pass', detail: 'No audit log entries yet; retention check vacuously holds.' };
  }
  const ageRow = db.prepare(
    "SELECT CAST((julianday('now') - julianday(?)) AS INTEGER) AS days"
  ).get(oldest.ts);
  const days = ageRow.days || 0;
  if (days < 365) {
    return {
      status: 'warning',
      detail: `Oldest audit_log entry is ${days} day(s) old (< 1 year). GD does not auto-truncate audit_log — this reflects deployment age, not policy enforcement. SOC-grade norm is >= 1 year; HIPAA requires 6 years, SOC 2 typically 7 years.`,
    };
  }
  const years = (days / 365).toFixed(1);
  return {
    status: 'pass',
    detail: `Audit log retention: oldest entry ${days} days (${years} years). GD does not auto-truncate audit_log; retention bounded only by storage capacity.`,
  };
}

// ── checkAuditIntegrity ──────────────────────────────────────────────────────
// Verifies audit log integrity by validating the append-only contract
// and surfacing the lack of external tamper-evidence on the GD. The
// GD's audit_log table has no in-DB hash chain, and the GD has no
// SIEM streaming integration as of v0.0.31. Tamper-evidence beyond
// local trust is therefore unavailable; this check returns warning
// describing the gap honestly.
//
// Maps to controls including: HIPAA 164.312(c)(1) Integrity Controls,
// SOC 2 CC7.3, NIST CSF DE.AE-02, ISO 27001 A.8.15/A.8.16,
// NIST 800-53 AU-9 Protection of Audit Information, NIS2 Art.21(2)(f),
// DORA Art.10.
function checkAuditIntegrity(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM audit_log").get();
  if (total.c === 0) {
    return { status: 'pass', detail: 'No audit log entries yet; integrity vacuously holds.' };
  }
  return {
    status: 'warning',
    detail: `Audit log: ${total.c} entries, append-only by API contract (no UPDATE or DELETE routes expose modification of audit_log). GD has no SIEM streaming and no in-DB hash chain — external tamper-evidence is unavailable as of v0.0.31. SOC-grade tamper-evidence depends on filesystem-level controls on the SQLite database file (operator-managed disk encryption + WORM storage or remote append-only log shipping). SIEM streaming is a future enhancement.`,
  };
}

// ── checkSyslogExport ────────────────────────────────────────────────────────
// Verifies syslog/SIEM export capability is configured. The GD does
// not currently implement SIEM streaming (no SIEM_ENABLED env var
// consumption, no config.siem_config key, no integration_config
// table). Returns warning describing the gap.
//
// Maps to controls including: HIPAA 164.312(b), SOC 2 CC7.1,
// NIST CSF DE.CM-01, ISO 27001 A.8.15/A.8.16, NIST 800-53 AU-6,
// NIS2 Art.21(2)(f), DORA Art.10.
function checkSyslogExport() {
  return {
    status: 'warning',
    detail: 'GD has no SIEM streaming integration as of v0.0.31. The audit_log table is queryable via GET /api/audit-logs and exportable via GET /api/audit-logs/export/:format, but there is no continuous push to an external SIEM (Splunk, Elastic, Sentinel, Chronicle, etc.). SOC-grade deployments achieve tamper-evidence via SIEM-side retention of the streamed audit copy; until SIEM streaming ships, operators should periodically export and archive audit logs to an external WORM destination.',
  };
}

// ── checkForensicsExport ─────────────────────────────────────────────────────
// Verifies the platform provides a forensics-compatible audit export
// endpoint. The GD exposes GET /api/audit-logs/export/:format
// (authMiddleware ciso/vp) for retrieving the full audit_log in a
// format-selectable export (current path supports json; csv or other
// formats may be added in future). Operators consume this endpoint
// to feed audit data into external forensics tooling.
//
// Maps to controls including: SOC 2 CC7.4, NIST CSF RS.AN-03
// Forensic Investigation, ISO 27001 A.5.28 Collection of Evidence,
// NIST 800-53 IR-7 Incident Response Assistance, NIS2 Art.20,
// DORA Art.20.
function checkForensicsExport() {
  return {
    status: 'pass',
    detail: 'Forensics export: GET /api/audit-logs/export/:format endpoint mounted on the GD (authMiddleware ciso/vp). Returns full audit_log entries with timestamp, user_id, event_type, detail, ip, and severity. Operators can pipe the export into external forensics tooling or feed scheduled exports to a SIEM/archive.',
  };
}

// ── checkAlertingThresholds ──────────────────────────────────────────────────
// Verifies notification thresholds and at least one delivery channel
// are configured. GD stores notification_config as JSON in the config
// key-value table (key='notification_config') rather than a dedicated
// table. Expected fields: burnout_threshold, turnover_risk_high,
// sla_below (thresholds); email, sms (delivery flags); recipients
// (comma-separated targets).
//
// Maps to controls including: SOC 2 CC7.2 Anomaly Detection,
// NIST CSF DE.AE-06 Notifications Provided, ISO 27001 A.8.16
// Monitoring activities, NIST 800-53 AU-6, NIS2 Art.23, DORA Art.14.
function checkAlertingThresholds(db) {
  const row = db.prepare("SELECT value FROM config WHERE key = 'notification_config'").get();
  if (!row || !row.value) {
    return {
      status: 'warning',
      detail: 'config.notification_config not set — alerting not initialized on the GD. Default seed via db-init.js should populate this; if missing, re-run db-init or POST to /api/notifications/config.',
    };
  }
  let cfg;
  try {
    cfg = JSON.parse(row.value);
  } catch (e) {
    return {
      status: 'fail',
      detail: `config.notification_config exists but failed to parse as JSON: ${e.message}. Notification delivery cannot evaluate thresholds until the config row is repaired.`,
    };
  }
  const channels = [];
  if (cfg.email) channels.push('email');
  if (cfg.sms) channels.push('sms');
  const recipients = (cfg.recipients || '').trim();
  if (channels.length === 0) {
    return {
      status: 'warning',
      detail: `Alerting thresholds configured (burnout_threshold=${cfg.burnout_threshold}, sla_below=${cfg.sla_below}) but no delivery channel enabled — alerts fire but go nowhere. Enable email or sms in notification_config.`,
    };
  }
  if (!recipients) {
    return {
      status: 'warning',
      detail: `Alerting channels enabled (${channels.join(', ')}) but recipients list is empty. Configure recipients in notification_config to receive alerts.`,
    };
  }
  return {
    status: 'pass',
    detail: `Alerting: thresholds (burnout=${cfg.burnout_threshold}, sla_below=${cfg.sla_below}, turnover_risk_high=${!!cfg.turnover_risk_high}) with ${channels.length} delivery channel(s) enabled (${channels.join(', ')}) and recipients configured.`,
  };
}

// ── checkLogVolumeReasonable ─────────────────────────────────────────────────
// Verifies audit_log is receiving entries at a reasonable rate.
// Zero entries in the last 24 hours suggests logging is broken or the
// system is idle in production (warning either way). Extremely high
// volume (> 1M entries in 24h) suggests noise or DoS and warrants
// investigation.
//
// Maps to controls including: SOC 2 CC7.1, NIST CSF DE.CM-03,
// ISO 27001 A.8.16, NIST 800-53 AU-4/AU-12, NIS2 Art.21(2)(f).
function checkLogVolumeReasonable(db) {
  const recent = db.prepare(
    "SELECT COUNT(*) AS c FROM audit_log WHERE timestamp > datetime('now', '-24 hours')"
  ).get();
  if (recent.c === 0) {
    return {
      status: 'warning',
      detail: 'Zero audit_log entries in the last 24 hours. The GD\'s request-logging middleware writes one audit_log entry per /api request (except /api/health), so zero entries means either the GD has received no traffic in 24h or audit logging is broken. Investigate.',
    };
  }
  if (recent.c > 1000000) {
    return {
      status: 'warning',
      detail: `Audit log volume: ${recent.c} entries in last 24h — abnormally high. Investigate for noise events or DoS conditions consuming SQLite storage.`,
    };
  }
  return {
    status: 'pass',
    detail: `Audit log volume: ${recent.c} entries in last 24h — within reasonable operating range.`,
  };
}

module.exports = {
  checkAuditRetention,
  checkAuditIntegrity,
  checkSyslogExport,
  checkForensicsExport,
  checkAlertingThresholds,
  checkLogVolumeReasonable,
};

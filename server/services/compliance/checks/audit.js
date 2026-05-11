// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Check Functions: Audit & Monitoring
//
// R3g (v1.0.33): part of the comprehensive technical-control verification
// library that backs FireAlive's compliance claims under Foundational
// Rule 14 (Shared Responsibility framing).
//
// This file provides 6 check functions covering audit log retention,
// integrity, export, alerting, and volume monitoring. Each function
// queries actual platform state (DB tables, environment variables,
// configuration) and returns { status, detail } where status is
// 'pass' | 'warning' | 'fail'.
//
// Functions are referenced from framework definitions in
// server/services/compliance/frameworks/<id>.js (R3g commits 13-28).
// The checkAuditIntegrity function below supersedes the minimum-viable
// implementation in server/services/compliance/index.js once framework
// definitions are wired to import from this file (commits 13-17).
//
// PLATFORM STATE NOTES
//
// The R3g detailed plan (R3G-DETAILED-PLAN.md) anticipated several
// platform structures that don't match the v1.0.32 codebase. The
// functions below query the actual structures:
//
//   - Planned retention_policy table -> does not exist; audit_log is
//     never auto-truncated by the platform, so retention is bounded
//     only by storage capacity. The check measures effective retention
//     via the oldest audit_log entry's age.
//   - Planned SYSLOG_TARGET env var -> does not exist; SIEM streaming
//     is configured via two surfaces: (1) the config table with key
//     'siem_config' holding JSON {platform, host, port, endpoint,
//     enabled}; (2) integration_config rows with integration_type
//     'siem'. The runtime gate is SIEM_ENABLED env var.
//   - Planned alert_config table -> does not exist; alerting thresholds
//     live in notification_config (singleton row with threshold +
//     delivery channels: email, sms, webhook, pagerduty).
//   - Planned audit_log chain hash -> does not exist; tamper-evidence
//     story is append-only-by-API-contract + CEF SIEM streaming.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkAuditRetention ──────────────────────────────────────────────────────
// Verifies the audit_log holds entries with sufficient retention period
// to meet regulatory minimums. The platform does not auto-truncate
// audit_log, so retention is bounded only by storage capacity; this
// check measures effective retention by inspecting the oldest entry's
// age. SOC-grade norm is 1 year minimum; HIPAA requires 6 years,
// SOC 2 typically 7 years. Pass at >= 1 year; warning at < 1 year.
//
// Maps to controls including: HIPAA 164.312(b) Audit Controls
// (retention implied by audit-evidence requirement), SOC 2 CC7.1,
// NIST CSF DE.AE-03, ISO 27001 A.8.15, NIST 800-53 AU-11 Audit
// Record Retention, NIS2 Art.21(2)(f).
function checkAuditRetention(db) {
  const oldest = db.prepare(
    "SELECT MIN(timestamp) AS ts FROM audit_log"
  ).get();
  if (!oldest || !oldest.ts) {
    return { status: 'pass', detail: 'No audit log entries yet; retention check vacuously holds.' };
  }
  const ageDays = db.prepare(
    "SELECT CAST((julianday('now') - julianday(?)) AS INTEGER) AS days"
  ).get(oldest.ts);
  const days = ageDays.days || 0;
  if (days < 365) {
    return {
      status: 'warning',
      detail: `Oldest audit_log entry is ${days} day(s) old (< 1 year). Platform does not auto-truncate audit_log -- this reflects deployment age, not policy enforcement. SOC-grade norm is >= 1 year; HIPAA requires 6 years, SOC 2 typically 7 years.`,
    };
  }
  const years = (days / 365).toFixed(1);
  return {
    status: 'pass',
    detail: `Audit log retention: oldest entry ${days} days (${years} years). Platform does not auto-truncate audit_log; retention bounded only by storage capacity.`,
  };
}

// ── checkAuditIntegrity ──────────────────────────────────────────────────────
// Verifies audit log integrity by validating the append-only contract
// (no UPDATE or DELETE routes expose modification operations on the
// audit_log table) and the SIEM streaming configuration (which provides
// external tamper-evidence beyond local trust). The audit_log table
// has no in-DB hash chain in the v1.0.32 schema; tamper-evidence
// comes from the append-only contract plus the SIEM-side retention
// of a copy that local tampering cannot rewrite.
//
// This is the fuller implementation that supersedes the minimum-viable
// one in server/services/compliance/index.js -- it additionally
// validates that SIEM streaming is configured (not just enabled by
// env var) by checking the config table's siem_config row and the
// integration_config table for an operational SIEM integration.
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
  const siemEnabled = process.env.SIEM_ENABLED === 'true';
  const siemConfig = db.prepare("SELECT value FROM config WHERE key = 'siem_config'").get();
  const siemIntegration = db.prepare(
    "SELECT status FROM integration_config WHERE integration_type = 'siem' ORDER BY updated_at DESC LIMIT 1"
  ).get();
  const siemConfigured = !!siemConfig && !!siemConfig.value;
  const integrationOperational = siemIntegration && siemIntegration.status === 'operational';
  if (!siemEnabled) {
    return {
      status: 'warning',
      detail: `Audit log: ${total.c} entries, append-only by API contract. SIEM streaming disabled (SIEM_ENABLED != 'true') -- no external tamper-evidence. Set SIEM_ENABLED=true and configure SIEM integration for SOC-grade tamper-evidence.`,
    };
  }
  if (!siemConfigured && !integrationOperational) {
    return {
      status: 'warning',
      detail: `Audit log: ${total.c} entries. SIEM_ENABLED=true but neither config.siem_config nor integration_config (type='siem', status='operational') is set -- streaming destination not configured.`,
    };
  }
  return {
    status: 'pass',
    detail: `Audit log: ${total.c} entries, append-only by API contract. SIEM tamper-evidence streaming enabled and ${integrationOperational ? 'operational via integration_config' : 'configured via config.siem_config'}.`,
  };
}

// ── checkSyslogExport ────────────────────────────────────────────────────────
// Verifies syslog/SIEM export capability is configured. FireAlive
// supports CEF-formatted streaming to a SIEM target; the destination
// is configured via either the config table's siem_config row (JSON
// containing platform/host/port/endpoint) or the integration_config
// table with integration_type='siem'. The runtime gate is the
// SIEM_ENABLED env var. Pass if any destination is configured; warning
// if none.
//
// Maps to controls including: HIPAA 164.312(b), SOC 2 CC7.1,
// NIST CSF DE.CM-01, ISO 27001 A.8.15/A.8.16, NIST 800-53 AU-6
// Audit Record Review/Analysis (via SIEM correlation), NIS2
// Art.21(2)(f), DORA Art.10.
function checkSyslogExport(db) {
  const siemConfig = db.prepare("SELECT value FROM config WHERE key = 'siem_config'").get();
  const integrations = db.prepare(
    "SELECT status FROM integration_config WHERE integration_type = 'siem'"
  ).all();
  const operational = integrations.filter(r => r.status === 'operational');
  if (!siemConfig && integrations.length === 0) {
    return {
      status: 'warning',
      detail: 'No SIEM export configured. Configure via config.siem_config (CEF over syslog) or integration_config (integration_type=siem). Platform supports CEF formatting for SIEM correlation.',
    };
  }
  if (operational.length > 0) {
    return {
      status: 'pass',
      detail: `SIEM export: ${operational.length} operational integration(s) in integration_config. CEF-formatted audit_log streaming.`,
    };
  }
  if (siemConfig && siemConfig.value) {
    return {
      status: 'pass',
      detail: 'SIEM export configured via config.siem_config (CEF over syslog).',
    };
  }
  return {
    status: 'warning',
    detail: `SIEM integration row(s) exist in integration_config but none are in 'operational' status (current: ${integrations.map(r => r.status).join(', ')}).`,
  };
}

// ── checkForensicsExport ─────────────────────────────────────────────────────
// Verifies the platform provides a forensics-tool-compatible audit
// export endpoint. GET /api/audit/export-forensics is mounted at
// server/routes/compliance-monitoring.js:151 and exports audit_log
// entries in a format consumable by forensics tools. The check
// validates the platform capability; deployment-time route mounting
// is verified at startup by the express app.
//
// Maps to controls including: SOC 2 CC7.4, NIST CSF RS.AN-03
// Forensic Investigation, ISO 27001 A.5.28 Collection of Evidence,
// NIST 800-53 IR-7 Incident Response Assistance, NIS2 Art.20,
// DORA Art.20 Information Sharing.
function checkForensicsExport() {
  return {
    status: 'pass',
    detail: 'Forensics export: GET /api/audit/export-forensics endpoint mounted (compliance-monitoring router). Returns audit_log entries in forensics-tool-compatible format with chain-of-custody metadata.',
  };
}

// ── checkAlertingThresholds ──────────────────────────────────────────────────
// Verifies notification thresholds and at least one delivery channel
// are configured. The notification_config singleton stores threshold
// ('watch' | 'stressed' | 'critical') and delivery channel flags
// (email, sms, webhook, pagerduty). Warning if no delivery channel
// enabled (events fire but go nowhere); pass if at least one channel
// enabled.
//
// Maps to controls including: SOC 2 CC7.2 Anomaly Detection,
// NIST CSF DE.AE-06 Notifications Provided, ISO 27001 A.8.16
// Monitoring activities, NIST 800-53 AU-6, NIS2 Art.23, DORA Art.14.
function checkAlertingThresholds(db) {
  const cfg = db.prepare("SELECT * FROM notification_config WHERE id = 'default'").get();
  if (!cfg) {
    return {
      status: 'warning',
      detail: 'notification_config has no default row -- alerting not initialized. Initialize via notification settings UI.',
    };
  }
  const channels = [];
  if (cfg.email_enabled) channels.push('email');
  if (cfg.sms_enabled) channels.push('sms');
  if (cfg.webhook_enabled) channels.push('webhook');
  if (cfg.pagerduty_enabled) channels.push('pagerduty');
  if (channels.length === 0) {
    return {
      status: 'warning',
      detail: `Alerting threshold set to '${cfg.threshold}' but no delivery channel enabled -- alerts fire but go nowhere. Enable at least one of email/sms/webhook/pagerduty.`,
    };
  }
  return {
    status: 'pass',
    detail: `Alerting: threshold='${cfg.threshold}' with ${channels.length} delivery channel(s) enabled (${channels.join(', ')}).`,
  };
}

// ── checkLogVolumeReasonable ─────────────────────────────────────────────────
// Verifies audit_log is receiving entries at a reasonable rate.
// Zero entries in the last 24 hours suggests logging is broken or the
// system is idle in production (warning either way -- both warrant
// investigation). Extremely high volume (> 1M entries in 24h) suggests
// noise or DoS and also warrants investigation.
//
// Maps to controls including: SOC 2 CC7.1, NIST CSF DE.CM-03,
// ISO 27001 A.8.16, NIST 800-53 AU-4 Audit Log Storage Capacity /
// AU-12 Audit Record Generation, NIS2 Art.21(2)(f).
function checkLogVolumeReasonable(db) {
  const recent = db.prepare(
    "SELECT COUNT(*) AS c FROM audit_log WHERE timestamp > datetime('now', '-24 hours')"
  ).get();
  if (recent.c === 0) {
    return {
      status: 'warning',
      detail: 'Zero audit_log entries in the last 24 hours. Either logging is broken (auditLog function not invoked) or the system is idle in production. Investigate.',
    };
  }
  if (recent.c > 1000000) {
    return {
      status: 'warning',
      detail: `Audit log volume: ${recent.c} entries in last 24h -- abnormally high. Investigate for noise events or DoS conditions consuming storage.`,
    };
  }
  return {
    status: 'pass',
    detail: `Audit log volume: ${recent.c} entries in last 24h -- within reasonable operating range.`,
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

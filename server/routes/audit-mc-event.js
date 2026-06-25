// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Audit Event Emission Routes (Management Console, R3n)
//
// POST /api/audit/mc-event
//   Lets the MC frontend write semantic events into the audit_log table
//   for lead/admin actions that happen client-side without a corresponding
//   server-side save (yet). At v1.0.40, many MC tabs have UI "Save" buttons
//   whose real backends are still in flight (B5d/B5e/B5f catch-alls); the
//   audit marker is the only persistent record that the lead clicked Save.
//   When real backends ship, those save endpoints get auto-logged by the
//   auditMiddleware on every HTTP request, and these MC_* markers continue
//   to record click-action intent for SOC threat hunting.
//
// Companion to /api/audit/event (R3l C7) which serves the AC. The two
// endpoints share a common shape but use different prefixes and allowlists:
//
//   AC events → /api/audit/event   → prefix AC_  → 16-entry wellness/nav allowlist
//   MC events → /api/audit/mc-event → prefix MC_ → 59-entry operator-action allowlist
//   server-middleware events → no prefix → captured by auditMiddleware
//
// Why one physical audit_log table with prefix-based source distinction
// rather than three separate tables: SOC threat hunting requires cross-
// source correlation (e.g., AC_SIGNAL_VIEW followed by MC_FORENSIC_EXPORT
// followed by a server-middleware POST /api/backup is a potential insider
// attack chain). Splitting physically makes that correlation query much
// harder. The Audit Export UI (extended in C15/C16) gets a Source dropdown
// for the operator's per-stream view; underlying queries filter by
// event_type prefix.
//
// Forgery prevention
//   - Allowlist of bare event names — lead cannot emit arbitrary strings
//     like "ADMIN_LOGIN" or "BACKUP_CREATED" to obscure or mimic real
//     server-side events
//   - Server prepends an "MC_" prefix to every logged event_type so
//     auditors can immediately tell which entries are MC-emitted vs AC vs
//     server-middleware. The lead's frontend sends "HANDOFF_SENT" and the
//     audit_log row reads "MC_HANDOFF_SENT"
//   - req.user.id is the only source of identity; no user_id in the body
//   - ip_address is captured from req.ip server-side
//
// Failure semantics
//   Fire-and-forget. The MC frontend does not block on the response. The
//   endpoint returns 200 on valid input regardless of whether the under-
//   lying auditLog write succeeded (auditLog swallows DB errors internally).
//   4xx is reserved for malformed requests; 5xx for unexpected server
//   errors. The MC will not see audit-write failures.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

const MAX_DETAIL_LENGTH = 500;
const EVENT_TYPE_PREFIX = 'MC_';

// Allowlist of bare MC event names. The server prepends EVENT_TYPE_PREFIX
// before writing to audit_log. Adding new event types is a deliberate
// maintainer action — MC frontends cannot register new types at runtime.
//
// This list was generated at R3n C12 by cataloging every event name
// previously posted to the broken /api/v1/audit/log endpoint by
// firealive-mc.jsx (62 unique names across 59 callsites; some events
// appeared from multiple callsites with the same name).
const ALLOWED_EVENT_TYPES = new Set([
  // Access control / authentication
  'ACCESS_CTRL_SAVED',
  'AD_TEST',
  'API_OFFLINE',
  'AUTH_LOG_CONFIG_SAVED',
  'IAM_CONFIGURED',
  'KB_DEV_AUTH',
  // Routing
  'AUTO_DISABLE_ROUTING_SAVED',
  // Backup / restore / recovery
  'AUTO_UPDATE_SCHEDULE',
  'BACKUP_ALL_CLIENTS',
  'CLIENT_RESTORE_BACKUP',
  'CLIENT_REVERT_CONFIG',
  'CONFIG_EXPORTED',
  'UPDATE_PUSH',
  // Compromise + forensics
  'CHANGE_REPORT',
  'COMPROMISE_REPORT_EXPORT',
  'COMPROMISE_REPORT_SIEM',
  'COMPROMISE_REPORT_SOAR',
  'COMPROMISE_SCAN_ALL',
  'COMPROMISE_SCAN_COMPLETE',
  'FORENSIC_EXPORT',
  // Client provisioning + lifecycle
  'CLIENT_METRICS_REFRESH',
  'CLIENT_NOTIF_CONFIG',
  // Integrations
  'CLOUD_VULNSCAN_CONFIG',
  'EDR_CONFIG_SAVED',
  'KMS_CONFIG_SAVED',
  'SDN_CONFIGURED',
  'SASE_CONFIG_SAVED',
  'STORAGE_ROUTES_SAVED',
  'VIRT_CONFIGURED',
  'VULNSCAN_CONFIG_SAVED',
  'VULN_SCAN_ALL_CLIENTS',
  // Fail-open routing
  'FAILOPEN_CONFIG_SAVED',
  // Geo / location
  'GEO_CONFIG_SAVED',
  // Handoffs + shift transitions
  'HANDOFF_SENT',
  // Helper Pay configuration (C18)
  'HELPER_PAY_CONFIG_SAVED',
  // Compliance / reporting
  'HUMAN_IMPACT_REPORT',
  'PROACTIVE_CONFIG_SAVED',
  'POSTURE_CONFIG_SAVED',
  'RECERT_COMPLETED',
  'RECERT_INTERVAL',
  'RECERT_REPORT',
  'RISK_REGISTER_GENERATED',
  // Knowledge base
  'KB_SEARCH',
  // Lab / testing
  'LAB_CONFIG_SAVED',
  'LAB_TEST_CONNECTION',
  // Log integrity (R3l-ish neighborhood)
  'LOG_INTEGRITY_ALL',
  'LOG_INTEGRITY_CHECK',
  // Pseudonyms (admin operations)
  'PSEUDONYM_CONFIG_SAVED',
  'PSEUDONYM_MAPPING_EXPORTED',
  'PSEUDONYMS_ROTATED',
  // Regression / testing
  'REGRESSION_ALL_CLIENTS',
  // Retros + reminders
  'RETRO_REMINDER',
  // Setup wizard
  'SETUP_WIZARD_COMPLETE',
  // SIEM
  'SIEM_QUERY_COPIED',
  // Threat hunting
  'THREAT_HUNT_CONFIG_SAVED',
  // Thresholds
  'THRESHOLDS_SAVED',
  // Tripwire / integrity monitoring
  'TRIPWIRE_MANUAL_TEST',
  'TRIPWIRE_RESET',
  // WiFi policy
  'WIFI_POLICY_SAVED',
]);

// Pre-computed sorted list for error responses (so clients see a stable, alphabetised allowlist).
const ALLOWED_EVENT_TYPES_SORTED = Array.from(ALLOWED_EVENT_TYPES).sort();

// ── POST / ───────────────────────────────────────────────────────────────────
router.post('/', (req, res) => {
  // Identity comes from the JWT only.
  const userId = req.user && req.user.id;
  if (!userId) {
    return res.status(401).json({ error: 'JWT missing user id' });
  }

  const body = req.body || {};

  // ── Validate event_type ────────────────────────────────────────────────────
  if (typeof body.event_type !== 'string') {
    return res.status(400).json({ error: 'event_type required (string)' });
  }
  if (!ALLOWED_EVENT_TYPES.has(body.event_type)) {
    return res.status(400).json({
      error: 'event_type not allowed',
      allowed: ALLOWED_EVENT_TYPES_SORTED,
    });
  }

  // ── Validate detail (optional) ─────────────────────────────────────────────
  let detail = body.detail;
  if (detail !== undefined && detail !== null) {
    if (typeof detail !== 'string') {
      return res.status(400).json({ error: 'detail must be a string' });
    }
    if (detail.length > MAX_DETAIL_LENGTH) {
      return res.status(400).json({
        error: 'detail too long (max ' + MAX_DETAIL_LENGTH + ' chars)',
      });
    }
    // Strip control characters except tab/newline/CR. CEF formatting in
    // middleware/audit.js already escapes pipes and backslashes, so we only
    // need to neutralise non-printables that could disrupt log review tools.
    detail = detail.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  } else {
    detail = '';
  }

  const prefixedEventType = EVENT_TYPE_PREFIX + body.event_type;
  const ip = req.ip;

  // auditLog swallows DB errors internally and writes them to the server
  // logger; it never throws. Wrapping in try/catch defensively in case that
  // contract ever changes — but the endpoint still returns 200 either way
  // since the MC should not surface telemetry failures to the operator.
  try {
    auditLog(userId, prefixedEventType, detail, ip);
  } catch (err) {
    logger.error('audit/mc-event handler caught unexpected auditLog throw', {
      userId,
      eventType: prefixedEventType,
      error: err.message,
    });
  }

  res.json({
    ok: true,
    event_type: prefixedEventType,
    logged_at: new Date().toISOString(),
  });
});

module.exports = router;

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Audit Event Emission Routes (Analyst Client, R3l C7)
//
// POST /api/audit/event
//   Lets the analyst client write semantic events into the audit_log table
//   for actions that happen client-side and don't otherwise touch the server
//   (breathing exercise started, training module opened, wellness tab viewed,
//   etc.). The auditMiddleware in middleware/audit.js already auto-logs
//   every HTTP request as "METHOD /path"; this endpoint adds a parallel
//   stream of semantic event markers that compliance and wellness reviewers
//   can filter on directly.
//
// Forgery prevention
//   - Allowlist of bare event names — analyst cannot emit arbitrary strings
//     like "ADMIN_LOGIN" or "BACKUP_CREATED" to obscure or mimic real
//     server-side events
//   - Server prepends an "AC_" prefix to every logged event_type so auditors
//     can immediately tell which entries are client-emitted (AC_*) vs
//     server-emitted (no prefix). The analyst sends "SIGNAL_VIEW" and the
//     audit_log row reads "AC_SIGNAL_VIEW"
//   - req.user.id is the only source of identity; no analyst_id in the body
//   - ip_address is captured from req.ip server-side
//
// Tier-3 considerations
//   The audit_log is readable by leads and admins via /api/audit. The AC
//   should NEVER include Tier-3 data values (signal numbers, peer message
//   content, etc.) in the detail string. The allowlist covers action markers
//   only, never data carriers. A future hardening commit could split AC_*
//   events into an analyst-only audit stream if it turns out leads reviewing
//   audit logs can infer wellness state from event frequency alone.
//
// Failure semantics
//   This is a fire-and-forget endpoint. The AC frontend should not block on
//   the response — it logs telemetry asynchronously. The endpoint returns
//   200 on valid input regardless of whether the underlying auditLog write
//   succeeded (auditLog swallows DB errors internally and logs them to the
//   server logger). 4xx is reserved for malformed requests; 5xx is reserved
//   for unexpected server errors. The AC will not see audit-write failures.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

const MAX_DETAIL_LENGTH = 500;
const EVENT_TYPE_PREFIX = 'AC_';

// Allowlist of bare event names accepted from the analyst client. The server
// prepends EVENT_TYPE_PREFIX before writing to audit_log. Adding new event
// types to this set is a deliberate maintainer action — clients cannot
// register new types at runtime.
const ALLOWED_EVENT_TYPES = new Set([
  // View / navigation markers
  'SIGNAL_VIEW',
  'IMPACT_VIEW',
  'TRAINING_RECOMMENDATIONS_VIEW',
  'TRAINING_COMPLETION_VIEW',
  'SKILLS_TAB_VIEW',
  'WELLNESS_TAB_VIEW',
  'PEER_SKILLSHARE_VIEW',
  // Training interaction
  'TRAINING_MODULE_OPENED',
  'TRAINING_LINK_CLICKED',
  // Wellness activities
  'BREATHING_EXERCISE_STARTED',
  'BREATHING_EXERCISE_COMPLETED',
  'OODA_SIMULATOR_STARTED',
  'OODA_SIMULATOR_COMPLETED',
  'POST_INCIDENT_WELLNESS_STARTED',
  'POST_INCIDENT_WELLNESS_COMPLETED',
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
  // since the AC should not surface telemetry failures to the analyst.
  try {
    auditLog(userId, prefixedEventType, detail, ip);
  } catch (err) {
    logger.error('audit/event handler caught unexpected auditLog throw', {
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

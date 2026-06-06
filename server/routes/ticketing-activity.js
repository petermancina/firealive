// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Ticketing Activity Events (inbound push)
// POST /api/integrations/ticketing/activity-events
//   — Canonical analyst-action push receiver for the burnout-signal data feed
//     (Phase B5d1-F). The SOC's orchestration (a SOAR playbook or the ticketing
//     platform's webhook) maps its native events to the canonical action types
//     below and posts them here; FireAlive persists each as a ticket_actions row,
//     which the signal collector reads to derive the behavioral signals.
//
// This is the analyst-WORK counterpart to POST /api/routing/soar-events (which
// carries SOAR ROUTING decisions into ticket_assignments). The two are loosely
// coupled: this endpoint owns ticket_actions, soar-events owns ticket_assignments,
// and they join only on ticket_id. This endpoint never writes ticket_assignments
// and accepts actions for tickets the SOAR did not route (self-assigned or
// pre-existing).
//
// Auth: x-api-key with the ticketing:events scope ONLY. JWT is rejected
// (machine-to-machine; a lead/admin posting from a browser indicates misuse).
// Mounted in server/index.js BEFORE /api/integrations so it is NOT behind the
// config-lock gate: a locked configuration (an MFA-gated admin change) must not
// drop operational burnout-signal data.
//
// Read-only invariant preserved: FireAlive only RECEIVES action events; it never
// writes back to the ticketing system.
//
// Idempotency: external_action_id is the source platform's stable id for the
// action. ticket_actions carries a partial UNIQUE index on it (Phase B5d1-F
// F-PR1), so a re-delivered event is a no-op (INSERT OR IGNORE) and the handler
// returns 200 {idempotent: true} rather than double-counting — which would
// corrupt the burnout signals derived from these rows.
//
// Privacy: the audit detail uses analyst_pseudonym (NOT user.id) and never
// includes note contents. The raw notes / category / response_time stored in
// ticket_actions are operational ticket data the server already holds to
// function (the same class as ticket_assignments); the per-analyst BEHAVIORAL
// signals later derived from them (e.g. ticketQuality) are what get sealed to
// the analyst in Phase B5d1 PR D.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// Canonical analyst-action taxonomy. The source platform maps its native events
// to these. Kept deliberately small (the scope-creep guard, mirroring
// VALID_SOAR_EVENT_TYPES on the routing rail):
//   triage    — analyst's first action on a ticket (carries response_time_min;
//               feeds investigationTime and ticket volume / cognitive_load)
//   comment   — analyst added documentation (carries notes; feeds ticketQuality)
//   close     — analyst resolved a worked ticket (carries notes; feeds
//               ticketQuality and the resolved count)
//   escalate  — analyst escalated to a higher tier (feeds escalationRate)
//   dismiss   — analyst closed an alert as a false positive without escalation
//               (the rubber-stamp signal; feeds dismissRate — kept DISTINCT from
//               close so dismissRate and ticketQuality do not conflate)
//   reassign  — analyst handed a ticket off (feeds task_switching)
const VALID_ACTION_TYPES = ['triage', 'comment', 'close', 'escalate', 'dismiss', 'reassign'];

router.post('/', (req, res) => {
  if (!req.user.apiKey) {
    return res.status(403).json({ error: 'API key authentication required on this endpoint' });
  }
  if (!req.user.scopes?.includes('ticketing:events')) {
    return res.status(403).json({ error: 'Scope ticketing:events required' });
  }

  const {
    action_type, ticket_id, analyst_pseudonym, external_action_id,
    occurred_at, category, response_time_min, notes,
  } = req.body || {};

  const missing = [];
  if (!action_type) missing.push('action_type');
  if (!ticket_id) missing.push('ticket_id');
  if (!analyst_pseudonym) missing.push('analyst_pseudonym');
  if (!external_action_id) missing.push('external_action_id');
  if (missing.length > 0) {
    return res.status(400).json({ error: 'Missing required fields', fields: missing });
  }

  if (!VALID_ACTION_TYPES.includes(action_type)) {
    return res.status(400).json({ error: 'Invalid action_type', valid: VALID_ACTION_TYPES });
  }

  // response_time_min is optional; coerce leniently and store only a finite,
  // non-negative number (otherwise NULL). A bad value never drops the event.
  const rtNum = Number(response_time_min);
  const responseTime = Number.isFinite(rtNum) && rtNum >= 0 ? rtNum : null;

  try {
    const db = getDb();

    // Pseudonym -> user.id, server-side (the SOAR-side anonymity contract;
    // user.id is never echoed back). Inactive/offboarded analysts are excluded.
    const analyst = db.prepare(
      "SELECT id FROM users WHERE pseudonym = ? AND active = 1"
    ).get(analyst_pseudonym);

    if (!analyst) {
      db.close();
      return res.status(404).json({
        error: 'Unknown analyst_pseudonym',
        hint: 'The pseudonym may be stale (rotated since the SOAR last polled). Re-poll GET /api/routing/variables to refresh.',
      });
    }

    const actionId = crypto.randomBytes(16).toString('hex');
    // Use the source-reported action time as created_at so the collector's
    // time-windowed signals reflect when the work happened, not receipt time.
    const createdAt = (typeof occurred_at === 'string' && occurred_at) ? occurred_at : new Date().toISOString();

    // Idempotent insert keyed by external_action_id (partial UNIQUE index from
    // F-PR1). A re-delivered event hits the unique index and is ignored, so
    // result.changes === 0 means "already ingested".
    const result = db.prepare(`
      INSERT OR IGNORE INTO ticket_actions
        (id, analyst_id, ticket_id, action_type, category, response_time_min, notes, external_action_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      actionId,
      analyst.id,
      ticket_id,
      action_type,
      category ?? null,
      responseTime,
      typeof notes === 'string' ? notes : null,
      external_action_id,
      createdAt
    );

    db.close();

    if (result.changes === 0) {
      // Duplicate external_action_id — already ingested; no-op, no audit noise.
      return res.json({ idempotent: true, external_action_id });
    }

    // Audit uses pseudonym (NOT analyst.id) and never the note contents.
    auditLog(
      req.user.id,
      'ACTIVITY_EVENT_RECEIVED',
      `action_type=${action_type} ticket_id=${ticket_id} analyst_pseudonym=${analyst_pseudonym} external_action_id=${external_action_id}`,
      req.ip
    );

    res.status(201).json({
      action_id: actionId,
      action_type,
      accepted_at: createdAt,
    });
  } catch (err) {
    logger.error('Ticketing activity webhook error', { error: err.message });
    res.status(500).json({ error: 'Failed to process activity event' });
  }
});

module.exports = router;

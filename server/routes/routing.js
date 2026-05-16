// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Routing Routes
// GET  /api/routing               — get all routing caps
// PUT  /api/routing/:analystId    — update routing cap for an analyst
// POST /api/routing/equity        — run equity analysis
// GET  /api/routing/soar          — get SOAR routing variables (lead/admin UI)
// PUT  /api/routing/soar          — update SOAR routing variables
// POST /api/routing/panic         — engage/restore panic mode
// GET  /api/routing/panic         — read panic mode + post-deactivation linger state
// GET  /api/routing/variables     — SOAR polling contract (api-key, routing:read)
// POST /api/routing/soar-events   — SOAR webhook receiver (api-key, routing:events)
// GET  /api/routing/enabled       — read routing_enabled global toggle
// PUT  /api/routing/enabled       — set routing_enabled (lead/admin JWT only)
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');

const EQUITY_CAP = 0.35; // no analyst handles >35% of P0/P1 alerts

// Panic banner linger window after deactivation. The MC/AC banners poll
// /api/routing/panic and render a "routing restored" green banner while
// deactivated_at is within this window. After the window expires, the
// banner vanishes entirely. Hardcoded for R3j; future configurability
// deferred.
const PANIC_DEACTIVATED_LINGER_SECONDS = 300;

const VALID_SOAR_EVENT_TYPES = ['ticket_assigned', 'ticket_reassigned', 'ticket_closed'];

// ── R3j: SOAR Polling Contract — GET /api/routing/variables ──────────────────
// SOAR vendor polls this endpoint at its own cadence (typical: 30-60s).
// Returns the complete state the SOAR needs to make routing decisions:
// per-analyst capacity context (keyed by pseudonym, NEVER user.id), panic
// mode state, routing_enabled toggle state, and the 6 SOAR variables.
//
// Auth: x-api-key with routing:read scope (existing scope) OR lead/admin JWT.
// API key path: scope check below.
// JWT path: passes the mount's authMiddleware(['lead', 'admin']) and the
// scope check is skipped (req.user.apiKey is undefined for JWT auth).
//
// Privacy: analyst rows include pseudonym, tier, shift, available,
// capacity_score, last_heartbeat, complexity_cap, complexity_cap_is_override,
// complexity_cap_override_reason. NO user.id, name, or email. Inactive
// analysts (active=0; offboarded) are NEVER in the response.
router.get('/variables', (req, res) => {
  if (req.user.apiKey && !req.user.scopes?.includes('routing:read')) {
    return res.status(403).json({ error: 'Scope routing:read required' });
  }

  try {
    const db = getDb();

    const analysts = db.prepare(`
      SELECT u.pseudonym,
             u.tier,
             u.shift,
             u.available,
             u.capacity_score,
             u.last_heartbeat,
             rc.max_complexity         AS complexity_cap,
             rc.is_override            AS complexity_cap_is_override,
             rc.override_reason        AS complexity_cap_override_reason
      FROM users u
      LEFT JOIN routing_caps rc ON rc.analyst_id = u.id
      WHERE u.role = 'analyst' AND u.active = 1
      ORDER BY u.tier DESC, u.pseudonym
    `).all();

    // Mask SQLite INTEGER 0/1 to JSON boolean for available + is_override
    for (const a of analysts) {
      a.available = a.available === 1;
      a.complexity_cap_is_override = a.complexity_cap_is_override === 1;
    }

    const panicRow = db.prepare("SELECT value FROM team_config WHERE key = 'panic_mode'").get();
    const deactivatedRow = db.prepare("SELECT value FROM team_config WHERE key = 'panic_deactivated_at'").get();

    let panic_deactivated_at = null;
    if (deactivatedRow) {
      try {
        const ts = JSON.parse(deactivatedRow.value);
        const ageSec = (Date.now() - new Date(ts).getTime()) / 1000;
        if (ageSec <= PANIC_DEACTIVATED_LINGER_SECONDS) panic_deactivated_at = ts;
      } catch (_parseErr) {
        // Corrupted value — ignore; the row will be cleaned up opportunistically by GET /panic
      }
    }

    const enabledRow = db.prepare("SELECT value FROM team_config WHERE key = 'routing_enabled'").get();
    let routing_enabled = true; // default if row absent
    if (enabledRow) {
      try {
        routing_enabled = JSON.parse(enabledRow.value) === true;
      } catch (_parseErr) {
        routing_enabled = true;
      }
    }

    const vars = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'soar_%'").all();
    const soar_variables = {};
    for (const v of vars) {
      try {
        soar_variables[v.key.replace('soar_', '')] = JSON.parse(v.value);
      } catch (_parseErr) {
        soar_variables[v.key.replace('soar_', '')] = null;
      }
    }

    db.close();

    res.json({
      fetched_at: new Date().toISOString(),
      panic_mode: panicRow?.value === '"active"',
      panic_deactivated_at,
      routing_enabled,
      analysts,
      soar_variables,
    });
  } catch (err) {
    logger.error('Get routing variables error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch routing variables' });
  }
});

// ── R3j: SOAR Webhook Receiver — POST /api/routing/soar-events ───────────────
// SOAR vendor posts routing decisions back to FireAlive. Each event is
// persisted in soar_routing_events; ticket_assigned / ticket_reassigned
// additionally INSERT into ticket_assignments (status=open) and
// ticket_closed UPDATEs the matching open row to status=closed. The
// ticket_assignments side-effect closes the capacity-feedback loop:
// signal-collector.js's existing _getTicketCount query reads
// ticket_assignments on its next tick, so SOAR-reported assignment
// volume influences capacity_score automatically.
//
// Auth: x-api-key with routing:events scope ONLY. JWT auth is rejected
// (webhooks are machine-to-machine; a lead/admin posting to this endpoint
// from a browser indicates misuse).
//
// Idempotency: composite (soar_source, external_event_id) is UNIQUE in
// soar_routing_events. If a SOAR retries the same event, the duplicate is
// detected and the handler returns 200 with {idempotent: true, event_id}.
// SOARs that don't supply external_event_id get best-effort de-duplication
// via the audit log (each receipt is logged) but cannot achieve UNIQUE
// idempotency.
//
// Privacy: audit log uses analyst_pseudonym (NOT user.id) in the detail
// field. The SOAR-side anonymity contract is preserved end-to-end into
// FireAlive's audit trail.
router.post('/soar-events', (req, res) => {
  if (!req.user.apiKey) {
    return res.status(403).json({ error: 'API key authentication required on this endpoint' });
  }
  if (!req.user.scopes?.includes('routing:events')) {
    return res.status(403).json({ error: 'Scope routing:events required' });
  }

  const {
    event_type, ticket_id, analyst_pseudonym, assigned_at,
    soar_source, external_event_id, priority, complexity, reason, soar_metadata,
  } = req.body || {};

  const missing = [];
  if (!event_type) missing.push('event_type');
  if (!ticket_id) missing.push('ticket_id');
  if (!analyst_pseudonym) missing.push('analyst_pseudonym');
  if (!assigned_at) missing.push('assigned_at');
  if (missing.length > 0) {
    return res.status(400).json({ error: 'Missing required fields', fields: missing });
  }

  if (!VALID_SOAR_EVENT_TYPES.includes(event_type)) {
    return res.status(400).json({ error: 'Invalid event_type', valid: VALID_SOAR_EVENT_TYPES });
  }

  try {
    const db = getDb();

    const analyst = db.prepare(
      "SELECT id, capacity_score FROM users WHERE pseudonym = ? AND active = 1"
    ).get(analyst_pseudonym);

    if (!analyst) {
      db.close();
      return res.status(404).json({
        error: 'Unknown analyst_pseudonym',
        hint: 'The pseudonym may be stale (rotated since the SOAR last polled). Re-poll GET /api/routing/variables to refresh.',
      });
    }

    // Idempotency: only effective when soar_source AND external_event_id both supplied
    if (soar_source && external_event_id) {
      const existing = db.prepare(
        "SELECT id FROM soar_routing_events WHERE soar_source = ? AND external_event_id = ?"
      ).get(soar_source, external_event_id);
      if (existing) {
        db.close();
        return res.json({ idempotent: true, event_id: existing.id });
      }
    }

    const eventId = crypto.randomBytes(16).toString('hex');
    const receivedAt = new Date().toISOString();

    db.prepare(`
      INSERT INTO soar_routing_events
        (id, soar_source, external_event_id, event_type, ticket_id, analyst_pseudonym, analyst_id,
         priority, complexity, reason, soar_metadata, assigned_at, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      eventId,
      soar_source ?? null,
      external_event_id ?? null,
      event_type,
      ticket_id,
      analyst_pseudonym,
      analyst.id,
      priority ?? null,
      Number.isInteger(complexity) ? complexity : null,
      reason ?? null,
      soar_metadata ? JSON.stringify(soar_metadata) : null,
      assigned_at,
      receivedAt
    );

    if (event_type === 'ticket_assigned' || event_type === 'ticket_reassigned') {
      db.prepare(`
        INSERT INTO ticket_assignments
          (ticket_id, analyst_id, status, priority, capacity_score_at_assign, assigned_at)
        VALUES (?, ?, 'open', ?, ?, ?)
      `).run(
        ticket_id,
        analyst.id,
        priority ?? null,
        analyst.capacity_score ?? null,
        assigned_at
      );
    } else if (event_type === 'ticket_closed') {
      db.prepare(`
        UPDATE ticket_assignments
        SET status = 'closed', closed_at = ?
        WHERE ticket_id = ? AND status IN ('open', 'in_progress')
      `).run(receivedAt, ticket_id);
    }

    db.close();

    // Audit log uses pseudonym (NOT analyst.id) to preserve the SOAR-side
    // anonymity contract through the audit trail.
    auditLog(
      req.user.id,
      'SOAR_EVENT_RECEIVED',
      `event_type=${event_type} ticket_id=${ticket_id} analyst_pseudonym=${analyst_pseudonym} source=${soar_source ?? 'unknown'}`,
      req.ip
    );

    res.status(201).json({
      event_id: eventId,
      event_type,
      accepted_at: receivedAt,
    });
  } catch (err) {
    logger.error('SOAR webhook error', { error: err.message });
    res.status(500).json({ error: 'Failed to process SOAR event' });
  }
});

// ── R3j: routing_enabled toggle GET — read state ─────────────────────────────
// Either api-key (routing:read) or lead/admin JWT. Returns the current
// state of the silent-pause toggle, with optional updated_by name resolved
// from the users table.
router.get('/enabled', (req, res) => {
  if (req.user.apiKey && !req.user.scopes?.includes('routing:read')) {
    return res.status(403).json({ error: 'Scope routing:read required' });
  }

  try {
    const db = getDb();
    const row = db.prepare(`
      SELECT tc.value, tc.updated_at, tc.updated_by,
             u.name AS updated_by_name
      FROM team_config tc
      LEFT JOIN users u ON u.id = tc.updated_by
      WHERE tc.key = 'routing_enabled'
    `).get();
    db.close();

    if (!row) {
      // Row absent → treat as enabled (default). Matches the C2 migration's
      // intent and is the safe-by-default posture.
      return res.json({ enabled: true, updated_at: null, updated_by: null });
    }

    let enabled = true;
    try {
      enabled = JSON.parse(row.value) === true;
    } catch (_parseErr) {
      enabled = true;
    }

    res.json({
      enabled,
      updated_at: row.updated_at,
      updated_by: row.updated_by_name ?? null,
    });
  } catch (err) {
    logger.error('Get routing_enabled error', { error: err.message });
    res.status(500).json({ error: 'Failed to read routing_enabled' });
  }
});

// ── R3j: routing_enabled toggle PUT — mutate state ───────────────────────────
// Lead/admin JWT only. API-key auth is rejected because this is a config
// mutation — the SOAR shouldn't be able to silently pause its own variable
// feed via its read scope.
//
// NOTE: This route MUST be registered BEFORE the parameterized
// `PUT /:analystId` below or Express will match PUT /enabled as
// analystId="enabled". The file's current route order respects this
// constraint.
router.put('/enabled', (req, res) => {
  if (req.user.apiKey) {
    return res.status(403).json({ error: 'API key authentication not permitted on this endpoint; lead/admin JWT required' });
  }

  const { enabled } = req.body || {};
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ error: 'Body must include {enabled: boolean}' });
  }

  try {
    const db = getDb();
    db.prepare(`
      INSERT OR REPLACE INTO team_config (key, value, updated_by, updated_at)
      VALUES ('routing_enabled', ?, ?, datetime('now'))
    `).run(JSON.stringify(enabled), req.user.id);
    db.close();

    auditLog(req.user.id, 'ROUTING_ENABLED_TOGGLED', `enabled=${enabled}`, req.ip);
    res.json({ ok: true, enabled });
  } catch (err) {
    logger.error('Update routing_enabled error', { error: err.message });
    res.status(500).json({ error: 'Failed to update routing_enabled' });
  }
});

// ── Get All Routing Caps ─────────────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const caps = db.prepare(`
      SELECT rc.*, u.name, u.tier, u.shift, u.available
      FROM routing_caps rc
      JOIN users u ON u.id = rc.analyst_id
      ORDER BY u.tier DESC, u.name
    `).all();
    db.close();
    res.json({ caps });
  } catch (err) {
    logger.error('Get routing caps error', { error: err.message });
    res.status(500).json({ error: 'Failed to get routing caps' });
  }
});

// ── Update Analyst Routing Cap ───────────────────────────────────────────────
router.put('/:analystId', (req, res) => {
  const { maxComplexity, isOverride, overrideReason } = req.body;

  if (maxComplexity != null && (maxComplexity < 0 || maxComplexity > 5)) {
    return res.status(400).json({ error: 'maxComplexity must be 0-5' });
  }

  try {
    const db = getDb();
    const analyst = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'analyst'").get(req.params.analystId);
    if (!analyst) { db.close(); return res.status(404).json({ error: 'Analyst not found' }); }

    db.prepare(`
      INSERT INTO routing_caps (analyst_id, max_complexity, is_override, override_reason, override_by, updated_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(analyst_id) DO UPDATE SET
        max_complexity = COALESCE(?, max_complexity),
        is_override = COALESCE(?, is_override),
        override_reason = COALESCE(?, override_reason),
        override_by = ?,
        updated_at = datetime('now')
    `).run(
      req.params.analystId,
      maxComplexity ?? analyst.tier,
      isOverride ? 1 : 0,
      overrideReason?.slice(0, 500) || null,
      req.user.id,
      maxComplexity,
      isOverride ? 1 : null,
      overrideReason?.slice(0, 500) || null,
      req.user.id
    );
    db.close();

    auditLog(req.user.id, 'ROUTING_CAP_UPDATED', `analyst=${analyst.name} cap=${maxComplexity}${isOverride ? ' (override)' : ''}`, req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Update routing cap error', { error: err.message });
    res.status(500).json({ error: 'Failed to update routing cap' });
  }
});

// ── Equity Analysis ──────────────────────────────────────────────────────────
// Checks whether any analyst handles a disproportionate share of high-severity alerts.
// Returns recommendations if imbalance is detected.
router.post('/equity', (req, res) => {
  try {
    const db = getDb();
    const analysts = db.prepare(`
      SELECT u.id, u.name, u.tier, rc.max_complexity
      FROM users u
      LEFT JOIN routing_caps rc ON rc.analyst_id = u.id
      WHERE u.role = 'analyst' AND u.available = 1
    `).all();

    if (analysts.length === 0) { db.close(); return res.json({ message: 'No available analysts', balanced: true }); }

    // Calculate theoretical P0/P1 share per analyst
    // (In production, this would use actual ticket routing data from the SOAR)
    const totalCapacity = analysts.reduce((sum, a) => sum + (a.max_complexity || a.tier), 0);
    const analysis = analysts.map(a => {
      const cap = a.max_complexity || a.tier;
      const share = totalCapacity > 0 ? cap / totalCapacity : 0;
      return {
        id: a.id, name: a.name, tier: a.tier,
        maxComplexity: cap, share: Math.round(share * 1000) / 1000,
        overloaded: share > EQUITY_CAP,
      };
    });

    const overloaded = analysis.filter(a => a.overloaded);

    // Calculate Gini coefficient for workload distribution
    const shares = analysis.map(a => a.share).sort((a, b) => a - b);
    const n = shares.length;
    let gini = 0;
    for (let i = 0; i < n; i++) {
      gini += (2 * (i + 1) - n - 1) * shares[i];
    }
    gini = n > 0 ? gini / (n * shares.reduce((s, v) => s + v, 0)) : 0;

    db.close();

    const recommendations = overloaded.map(a => ({
      analystId: a.id, analystName: a.name,
      recommendation: `Reduce max_complexity from ${a.maxComplexity} to ${Math.max(1, a.maxComplexity - 1)} to achieve equitable distribution`,
    }));

    auditLog(req.user.id, 'EQUITY_ANALYSIS', `gini=${gini.toFixed(3)} overloaded=${overloaded.length}`, req.ip);

    res.json({
      balanced: overloaded.length === 0,
      giniCoefficient: Math.round(gini * 1000) / 1000,
      equityCap: EQUITY_CAP,
      analysts: analysis,
      recommendations,
    });
  } catch (err) {
    logger.error('Equity analysis error', { error: err.message });
    res.status(500).json({ error: 'Failed to run equity analysis' });
  }
});

// ── SOAR Routing Variables ───────────────────────────────────────────────────
// These 6 variables are written to the SOAR integration for routing decisions:
// analyst_capacity, complexity_cap, equity_weights, skill_matrix, burnout_risk_tier, shift_handoff
router.get('/soar', (req, res) => {
  try {
    const db = getDb();
    const vars = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'soar_%'").all();
    db.close();

    const soarVars = {};
    for (const v of vars) soarVars[v.key.replace('soar_', '')] = JSON.parse(v.value);

    res.json({ variables: soarVars });
  } catch (err) {
    logger.error('Get SOAR vars error', { error: err.message });
    res.status(500).json({ error: 'Failed to get SOAR routing variables' });
  }
});

router.put('/soar', (req, res) => {
  const validKeys = ['analyst_capacity', 'complexity_cap', 'equity_weights', 'skill_matrix', 'burnout_risk_tier', 'shift_handoff'];
  const { variables } = req.body;

  if (!variables || typeof variables !== 'object') {
    return res.status(400).json({ error: 'variables object required' });
  }

  try {
    const db = getDb();
    const upsert = db.prepare('INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES (?, ?, ?)');

    let updated = 0;
    for (const [key, value] of Object.entries(variables)) {
      if (validKeys.includes(key)) {
        upsert.run(`soar_${key}`, JSON.stringify(value), req.user.id);
        updated++;
      }
    }

    db.close();
    auditLog(req.user.id, 'SOAR_VARS_UPDATED', `keys=${Object.keys(variables).join(',')}`, req.ip);
    res.json({ ok: true, updated });
  } catch (err) {
    logger.error('Update SOAR vars error', { error: err.message });
    res.status(500).json({ error: 'Failed to update SOAR routing variables' });
  }
});

// ── Routing Panic Button (All Hands On Deck) ─────────────────────────────────
// Instantly disables all burnout-aware routing, restores maximum caps for all
// analysts, and sets SOAR variables to bypass wellness logic.
router.post('/panic', (req, res) => {
  const { activate } = req.body; // true = engage panic mode, false = restore normal

  try {
    const db = getDb();

    if (activate) {
      // Store current state for restoration
      const currentCaps = db.prepare(`
        SELECT analyst_id, max_complexity FROM routing_caps
      `).all();
      db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('panic_saved_caps', ?, ?)").run(
        JSON.stringify(currentCaps), req.user.id
      );

      // Max out all caps — every analyst gets maximum complexity
      db.prepare('UPDATE routing_caps SET max_complexity = 5, is_override = 1, override_reason = ?, override_by = ?, updated_at = datetime("now")').run(
        'PANIC MODE — all hands on deck', req.user.id
      );

      // Set SOAR to bypass
      db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('soar_burnout_risk_tier', ?, ?)").run('"bypassed"', req.user.id);
      db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('panic_mode', ?, ?)").run('"active"', req.user.id);

      db.close();
      auditLog(req.user.id, 'PANIC_ACTIVATED', 'All wellness routing disabled — all hands on deck', req.ip);

      // Broadcast to every active analyst. Lead/admin who pressed the button
      // already knows, so exclude them. mandatoryInApp ensures every analyst
      // sees this in-app even if they have email-only preferences set.
      let notifiedCount = 0;
      try {
        const eligible = notifications.getEligibleRecipients('routing_panic_engaged_manual', {
          roles: ['analyst'],
          activeOnly: true,
          excludeUserIds: [req.user.id],
        });
        for (const recipientId of eligible) {
          try {
            notifications.notify({
              recipientId,
              eventType: 'routing_panic_engaged_manual',
              title: 'Panic mode engaged — wellness routing OFF',
              body: 'A team lead has manually engaged panic mode. All analysts are now at maximum complexity until panic mode is lifted. You will receive another notification when wellness routing is restored.',
              linkTab: 'routing',
              linkParams: { focus: 'panic' },
            });
            notifiedCount++;
          } catch (notifyErr) {
            logger.warn('Panic activate: notify analyst failed (non-fatal)', { recipientId, error: notifyErr.message });
          }
        }
      } catch (broadcastErr) {
        logger.error('Panic activate: broadcast failed (non-fatal)', { error: broadcastErr.message });
      }

      return res.json({ ok: true, mode: 'panic', message: 'Wellness routing disabled. All analysts at maximum capacity.', notified: notifiedCount });
    } else {
      // Restore saved caps
      const saved = db.prepare("SELECT value FROM team_config WHERE key = 'panic_saved_caps'").get();
      if (saved) {
        const caps = JSON.parse(saved.value);
        const restore = db.prepare('UPDATE routing_caps SET max_complexity = ?, is_override = 0, override_reason = NULL, override_by = NULL, updated_at = datetime("now") WHERE analyst_id = ?');
        for (const c of caps) restore.run(c.max_complexity, c.analyst_id);
      }

      db.prepare("DELETE FROM team_config WHERE key = 'panic_mode'").run();
      db.prepare("DELETE FROM team_config WHERE key = 'panic_saved_caps'").run();

      // R3j: write panic_deactivated_at for the MC/AC banner 300s lingering
      // window. Banners poll /api/routing/panic and render a green "routing
      // restored" indicator while this timestamp is within
      // PANIC_DEACTIVATED_LINGER_SECONDS. After expiry the row is opportunistically
      // cleaned up by GET /api/routing/panic on the next read.
      db.prepare(`
        INSERT OR REPLACE INTO team_config (key, value, updated_by, updated_at)
        VALUES ('panic_deactivated_at', ?, ?, datetime('now'))
      `).run(JSON.stringify(new Date().toISOString()), req.user.id);

      db.close();
      auditLog(req.user.id, 'PANIC_DEACTIVATED', 'Wellness routing restored', req.ip);

      // Broadcast to every active analyst that routing is back. Lead who
      // pressed the button already knows. routing_panic_lifted is NOT
      // mandatoryInApp — analysts can silence the lift notification if
      // they only care about engagement events, not all-clear events.
      let notifiedCount = 0;
      try {
        const eligible = notifications.getEligibleRecipients('routing_panic_lifted', {
          roles: ['analyst'],
          activeOnly: true,
          excludeUserIds: [req.user.id],
        });
        for (const recipientId of eligible) {
          try {
            notifications.notify({
              recipientId,
              eventType: 'routing_panic_lifted',
              title: 'Panic mode lifted — wellness routing restored',
              body: 'Panic mode is over. Wellness routing is back on and your previous complexity cap has been restored.',
              linkTab: 'routing',
              linkParams: { focus: 'panic' },
            });
            notifiedCount++;
          } catch (notifyErr) {
            logger.warn('Panic deactivate: notify analyst failed (non-fatal)', { recipientId, error: notifyErr.message });
          }
        }
      } catch (broadcastErr) {
        logger.error('Panic deactivate: broadcast failed (non-fatal)', { error: broadcastErr.message });
      }

      return res.json({ ok: true, mode: 'normal', message: 'Wellness routing restored.', notified: notifiedCount });
    }
  } catch (err) {
    logger.error('Panic button error', { error: err.message });
    res.status(500).json({ error: 'Failed to toggle panic mode' });
  }
});

// ── Get Panic Mode Status ────────────────────────────────────────────────────
// R3j: response gains `deactivated_at` field. While panic_mode is active,
// deactivated_at is null. After deactivation, deactivated_at holds the ISO
// timestamp of the most recent deactivation for PANIC_DEACTIVATED_LINGER_SECONDS;
// the MC/AC banners use this to render a "routing restored" green banner
// during the linger window before vanishing. After the linger window the
// row is opportunistically deleted on the next read (so successive reads
// don't keep returning a stale timestamp).
router.get('/panic', (req, res) => {
  try {
    const db = getDb();
    const mode = db.prepare("SELECT value FROM team_config WHERE key = 'panic_mode'").get();
    const deactivatedRow = db.prepare("SELECT value FROM team_config WHERE key = 'panic_deactivated_at'").get();

    let deactivated_at = null;
    if (deactivatedRow) {
      try {
        const ts = JSON.parse(deactivatedRow.value);
        const ageSec = (Date.now() - new Date(ts).getTime()) / 1000;
        if (ageSec > PANIC_DEACTIVATED_LINGER_SECONDS) {
          // Expired — clean up opportunistically so we stop returning stale values
          db.prepare("DELETE FROM team_config WHERE key = 'panic_deactivated_at'").run();
        } else {
          deactivated_at = ts;
        }
      } catch (_parseErr) {
        // Corrupted value — best to remove it
        db.prepare("DELETE FROM team_config WHERE key = 'panic_deactivated_at'").run();
      }
    }

    db.close();
    res.json({
      active: mode?.value === '"active"',
      deactivated_at,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check panic mode' });
  }
});

module.exports = router;

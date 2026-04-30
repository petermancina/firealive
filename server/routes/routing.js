// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Routing Routes
// GET  /api/routing            — get all routing caps
// PUT  /api/routing/:analystId — update routing cap for an analyst
// POST /api/routing/equity     — run equity analysis
// GET  /api/routing/soar       — get SOAR routing variables
// PUT  /api/routing/soar       — update SOAR routing variables
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');

const EQUITY_CAP = 0.35; // no analyst handles >35% of P0/P1 alerts

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

      db.close();
      auditLog(req.user.id, 'PANIC_DEACTIVATED', 'Wellness routing restored', req.ip);
      return res.json({ ok: true, mode: 'normal', message: 'Wellness routing restored.' });
    }
  } catch (err) {
    logger.error('Panic button error', { error: err.message });
    res.status(500).json({ error: 'Failed to toggle panic mode' });
  }
});

// ── Get Panic Mode Status ────────────────────────────────────────────────────
router.get('/panic', (req, res) => {
  try {
    const db = getDb();
    const mode = db.prepare("SELECT value FROM team_config WHERE key = 'panic_mode'").get();
    db.close();
    res.json({ active: mode?.value === '"active"' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check panic mode' });
  }
});

module.exports = router;

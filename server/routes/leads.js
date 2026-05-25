// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Leads Routes
//
// Read-only roster of team leads for the pseudonymous lead chat. An analyst picks
// an on-shift lead from this list, then opens a 1:1 thread with them. Leads are
// NOT pseudonymized, so returning a lead's id, name, and shift to analysts is by
// design: the analyst chooses a known lead and needs the id to fetch the lead's
// lead-domain bundle and establish the Signal session. No analyst data, burnout
// signal, or pseudonym mapping is exposed here.
//
// GET /api/leads/on-shift — active leads (with shift) for the lead-chat picker
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

// ── On-shift leads for the lead-chat picker ──────────────────────────────────
// "On-shift" is every active lead. The deployment is single-team, so there is no
// team filter; each lead's assigned shift ('day' / 'swing' / 'night') is returned
// as context for the analyst's choice, but a lead is never hidden by shift -- a
// stressed analyst must always be able to reach someone.
router.get('/on-shift', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(
      "SELECT id, name, shift FROM users WHERE role = 'lead' AND active = 1 ORDER BY name COLLATE NOCASE"
    ).all();
    db.close();
    const leads = rows.map((r) => ({ id: r.id, name: r.name, shift: r.shift || null }));
    res.json({ leads });
  } catch (err) {
    logger.error('On-shift leads error', { error: err.message });
    res.status(500).json({ error: 'Failed to list on-shift leads' });
  }
});

module.exports = router;

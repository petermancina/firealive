// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Pseudonyms Routes (R3n)
// GET  /api/pseudonyms   — list active analyst pseudonyms (no real names)
//
// Powers the AC's Peer Skill-Share exclude UI. The analyst sees pseudonyms
// (e.g., Analyst-Phoenix-23, Analyst-Merlin-47) of colleagues they may want
// to exclude from a help-session pool; they never see real names through
// this surface. The pseudonym is the canonical handle for peer routing —
// chats already use it, the burnout-data store keys to it, and the lead's
// real-name mapping is exported to the lead-controlled file (NOT stored in
// the system). See FEATURE-GUIDE Peer Skill-Share and v025-features.js
// /pseudonyms/* routes for the broader pseudonym system context.
//
// Mounted at /api/pseudonyms by server/index.js with analyst+lead+admin JWT
// (analysts need it for the exclude UI; leads can use it for their own
// scheduling views; admins for diagnostics). Auth is enforced at the mount
// site, not in this file.
//
// Privacy contract: response contains pseudonym + tier + shift ONLY. Tier
// and shift are aids for the exclude UI's grouping affordance (e.g., "all
// Tier 2 day shift") and do NOT expose identity beyond the pseudonym.
// Specifically, the response NEVER includes:
//   • users.id (the analyst's UUID — would identify the row)
//   • users.name (the real name)
//   • users.email (the SSO join key)
//   • users.username, external_id, geo_country
//   • last_heartbeat, capacity_score, available, last_iam_check
//   • mfa state, role, anything else
//
// Pool intelligence (count by tier/shift) IS inferable from this response,
// but is already inferable from GET /api/team/overview (lead/admin) and
// GET /api/routing/variables (SOAR polling) — no NEW intelligence is leaked
// by this endpoint beyond the per-pseudonym handle.
//
// Sort order: shift (day, swing, night) → tier (descending; Tier 3 first
// since higher tier = more senior in this codebase's convention) →
// pseudonym (alphabetical). Stable ordering aids the exclude UI's grouping.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

router.get('/', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT pseudonym, tier, shift
      FROM users
      WHERE role = 'analyst'
        AND active = 1
        AND pseudonym IS NOT NULL
        AND pseudonym != ''
      ORDER BY
        CASE shift WHEN 'day' THEN 0 WHEN 'swing' THEN 1 WHEN 'night' THEN 2 ELSE 3 END,
        tier DESC,
        pseudonym
    `).all();
    db.close();
    res.json({ pseudonyms: rows });
  } catch (err) {
    logger.error('List pseudonyms error', { error: err.message });
    res.status(500).json({ error: 'Failed to list pseudonyms' });
  }
});

module.exports = router;

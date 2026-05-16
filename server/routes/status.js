// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — System Status Routes (AC-accessible)
// GET  /api/status/panic  — read panic_mode + post-deactivation linger state
//
// R3j (v1.0.36) introduces this router as a sibling to /api/system. The
// distinction:
//
//   /api/system  — admin-only configuration, version, fuse, config dumps
//   /api/status  — any-authenticated-role state reads needed by the AC
//
// The AC runs under the analyst role and cannot reach /api/routing/panic
// (which is mounted with ['lead', 'admin'] gating). The AC's panic banner
// needs the same {active, deactivated_at} state so analysts see the panic
// indicator. This router provides that read access without opening the
// rest of /api/system or /api/routing to analyst-role tokens.
//
// Mount: /api/status with authMiddleware(['analyst', 'lead', 'admin']) in
// server/index.js. The mount-level gate is satisfied by any authenticated
// user; the route handler does not do additional role checks.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

// Mirror of server/routes/routing.js PANIC_DEACTIVATED_LINGER_SECONDS.
// Kept as a separate constant so this file is independent of the routing
// module. The frontend mirror lives in frontend/firealive-mc.jsx (MC) and
// packages/analyst-client/analyst-client.jsx (AC) as
// PANIC_BANNER_LINGER_SECONDS.
const PANIC_DEACTIVATED_LINGER_SECONDS = 300;

// ── Panic Mode Status (AC-accessible) ────────────────────────────────────────
// Same response shape as GET /api/routing/panic:
//   { active: boolean, deactivated_at: string|null }
//
// Reading is idempotent; this is purely a state-query endpoint. No audit
// log entry on read (would generate excessive noise from the AC's 30s
// polling cadence).
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
          // Expired — clean up opportunistically so successive reads don't
          // keep returning a stale value. Matches the cleanup behavior in
          // /api/routing/panic GET so both endpoints share the same window
          // semantics.
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
    logger.error('Get status panic error', { error: err.message });
    res.status(500).json({ error: 'Failed to read panic state' });
  }
});

module.exports = router;

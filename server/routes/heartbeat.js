// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Heartbeat Routes
// POST /api/heartbeat — current user pings the server to refresh last_heartbeat
// ═══════════════════════════════════════════════════════════════════════════════
//
// Each FireAlive client app (Analyst Client, Management Console, Global
// Dashboard) calls this endpoint on a fixed interval (typically every 30s) so
// the server can track which clients are actively connected. The
// users.last_heartbeat column was added in R0 schema reconciliation; the
// system-health service (services/system-health.js) consumes it to compute
// connected-client status with a 90-second threshold (line 31:
// `Date.now() - new Date(u.last_heartbeat).getTime() < 90000`).
//
// The websocket-server.js service ALSO updates last_heartbeat on WS connect
// and disconnect events, providing a complementary realtime path for clients
// using WebSocket. This HTTP endpoint covers clients that fall back to
// polling, e.g. when a WebSocket connection is degraded behind a corporate
// proxy or NAT idle timeout.
//
// The endpoint deliberately does NOT modify users.active. The active column
// is the canonical "not offboarded" flag (R0 schema comment: "account active
// flag — distinct from the available shift status; offboarding sets to 0").
// A heartbeat is a liveness ping, not an authority to undo an offboarding —
// only POST /api/iam/confirm-status with action=offboard or action=active
// can change that flag.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

// ── POST /api/heartbeat ──────────────────────────────────────────────────────
router.post('/', (req, res) => {
  if (!req.user?.id) {
    return res.status(401).json({ error: 'Unauthenticated' });
  }
  try {
    const db = getDb();
    const now = new Date().toISOString();
    const result = db.prepare("UPDATE users SET last_heartbeat = ? WHERE id = ?").run(now, req.user.id);
    db.close();
    if (result.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ ack: true, at: now });
  } catch (err) {
    logger.error('Heartbeat error', { error: err.message });
    res.status(500).json({ error: 'Failed to record heartbeat' });
  }
});

module.exports = router;

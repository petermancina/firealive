// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Connected Clients Observability (R3l C9)
//
// GET /api/system/connected-clients
//
// Admin-only observability endpoint returning a snapshot of which users
// currently hold an active WebSocket session. Fills the gap left by the
// services/system-health.js getConnectedClients() capability that was
// identified during the R3l pre-flight audit as NOT being in canonical
// FireAlive — once C9 ships, system-health.js can be safely removed in R3m
// without losing this observability.
//
// Response shape
//   {
//     initialized,         // false if the WebSocket server never came up
//     count,               // total connected sessions
//     alive,               // sessions that responded to the most recent heartbeat
//     stale,               // sessions that did not respond (next heartbeat tick disconnects them)
//     by_role: { analyst, lead, admin, unknown },  // role aggregate
//     clients: [
//       { userId, role, isAlive },
//       ...
//     ]
//   }
//
// Privacy posture
//   - Admin-only via the existing /api/system mount auth in index.js.
//   - userId is the database PK (not the username/name). Admins can join to the
//     users table themselves if they need richer identity for incident response;
//     this endpoint deliberately does not duplicate that data.
//   - Role is included so admins can answer "how many analysts are online?"
//     without enumerating individual users for every check.
//   - No IP, no User-Agent, no connection start time. Those exist on the ws
//     object but are not surfaced here — adding them later would be a separate
//     commit with its own privacy review.
//
// Wiring contract
//   Depends on index.js setting app.locals.wsServer = wsServer after the
//   FireAliveWebSocket constructor runs (the C9b inline edit). If app.locals
//   does not contain wsServer (real-time features failed to initialise, or
//   this commit is deployed without the matching index.js edit), the endpoint
//   returns initialized:false with empty arrays rather than 500 — admins still
//   get a usable response that explains the absent state.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

const EMPTY_RESPONSE = {
  initialized: false,
  count: 0,
  alive: 0,
  stale: 0,
  by_role: {},
  clients: [],
  note: 'WebSocket server not initialized — real-time features unavailable',
};

// ── GET / ────────────────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  const wsServer = req.app && req.app.locals && req.app.locals.wsServer;
  if (!wsServer || !wsServer.clients || typeof wsServer.clients.entries !== 'function') {
    return res.json(EMPTY_RESPONSE);
  }

  const userIds = [];
  for (const userId of wsServer.clients.keys()) {
    userIds.push(userId);
  }

  // Look up roles for aggregate reporting. One round-trip with IN-clause; the
  // SET is bounded by the number of concurrent WebSocket sessions which in
  // practice stays in the low hundreds at most.
  let roleMap = new Map();
  if (userIds.length > 0) {
    const db = getDb();
    try {
      const placeholders = userIds.map(() => '?').join(',');
      const rows = db.prepare(
        'SELECT id, role FROM users WHERE id IN (' + placeholders + ')'
      ).all(...userIds);
      roleMap = new Map(rows.map((r) => [r.id, r.role]));
    } catch (err) {
      // Role lookup failure should not 500 the observability endpoint.
      // Fall back to role='unknown' for every entry so the caller still
      // gets per-session liveness data.
      logger.warn('connected-clients role lookup failed', { error: err.message });
    } finally {
      db.close();
    }
  }

  const clients = [];
  const byRole = {};
  let alive = 0;
  let stale = 0;

  for (const [userId, ws] of wsServer.clients.entries()) {
    const role = roleMap.get(userId) || 'unknown';
    const isAlive = !!ws.isAlive;

    clients.push({ userId, role, isAlive });
    byRole[role] = (byRole[role] || 0) + 1;
    if (isAlive) alive++;
    else stale++;
  }

  res.json({
    initialized: true,
    count: clients.length,
    alive,
    stale,
    by_role: byRole,
    clients,
  });
});

module.exports = router;

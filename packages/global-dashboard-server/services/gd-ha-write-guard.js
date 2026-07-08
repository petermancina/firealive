// packages/global-dashboard-server/services/gd-ha-write-guard.js
//
// Request-layer write-authority guard for GD High Availability (B6d). The GD twin
// of server/middleware/ha-write-guard.js (the GD keeps middleware-style modules in
// services/, like gd-sdn-admission / gd-sase-admission / gd-vm-attestation).
//
// It runs on top of the in-process HTTPS/mTLS listener (index.js): it gates by HTTP
// method, not by transport. In an active/passive deployment the passive is a warm
// standby -- the org's external load balancer routes client traffic to the active,
// and the passive normally receives only the peer link. FireAlive does not TRUST
// that routing. Consistent with its structural-enforcement posture, a confirmed
// passive refuses to SERVE state-changing requests itself, so a misrouted, retried,
// or directly-addressed request can never make the standby diverge from the active.
// This is the API-boundary companion to the scheduler's write gate
// (gd-backup-scheduler.mayRunWriteJob) and the epoch-fenced replication apply
// (gd-ha-replication.applyBatch): together they cover every write path on a passive.
//
// Behaviour:
//   - Only POST/PUT/PATCH/DELETE are considered; GET/HEAD/OPTIONS always pass
//     (reads are safe, and GET /ha/status plus LB health checks must work on the
//     passive).
//   - The /ha control plane is always allowed through, even on a passive: the
//     active's POSTs to /ha/peer/* (replication, heartbeat, lease) must be accepted,
//     and HA admin (pair, promote, config) must stay reachable to operate or recover
//     the standby.
//   - A blocked request returns 503 with a machine-readable code so callers and load
//     balancers can react.
//
// Fail-open: the guard blocks ONLY when this node is a positively-confirmed paired
// passive. Any uncertainty -- HA tables absent (a fresh standalone DB), config unset,
// parse or DB error -- allows the request through, so single-node and active
// deployments are never affected. The authoritative signal is gd_ha_node.role (set by
// gd-ha-pairing.finalizeRole and gd-ha-failover.promote/demote). ASCII-only.

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// Matches the HA control plane whether or not the /api mount prefix has been
// stripped by Express (app.use('/api/', ...) strips it from req.path, leaving
// /ha/...; a global mount would leave /api/ha/...). Both are exempted.
const HA_CONTROL_PATH = /^\/(api\/)?ha(\/|$)/;

// True only when HA is enabled, a peer is paired, AND this node's role is passive.
// Fail-open by construction: any missing state or error returns false (treated as
// "not a passive" -> request allowed), so a standalone node whose HA tables do not
// yet exist is never blocked.
function isConfirmedPassive(db) {
  try {
    const row = db.prepare("SELECT value FROM config WHERE key = 'ha_config'").get();
    if (!row) {
      return false;
    }
    let cfg;
    try {
      cfg = JSON.parse(row.value) || {};
    } catch (parseErr) {
      return false;
    }
    if (!cfg.enabled) {
      return false;
    }
    const peer = db.prepare("SELECT status FROM gd_ha_peer WHERE status = 'paired' LIMIT 1").get();
    if (!peer) {
      return false;
    }
    const node = db.prepare("SELECT role FROM gd_ha_node WHERE id = 'self'").get();
    return !!node && node.role === 'passive';
  } catch (err) {
    return false;
  }
}

// Express middleware factory, matching the GD convention (sdnAdmission(),
// saseAdmission(), gdVmAttestation(), ...).
function haWriteGuard() {
  return function (req, res, next) {
    if (!MUTATING_METHODS.has(req.method)) {
      return next();
    }
    if (HA_CONTROL_PATH.test(req.path)) {
      return next();
    }
    let passive = false;
    try {
      const { getDb } = require('../db-init');
      const db = getDb();
      try {
        passive = isConfirmedPassive(db);
      } finally {
        db.close();
      }
    } catch (probeErr) {
      // Fail open: never block a request because the authority probe failed.
      passive = false;
    }
    if (!passive) {
      return next();
    }
    return res.status(503).json({
      error: 'This node is a standby (HA passive). State-changing requests are served by the active node.',
      code: 'ha_passive_read_only'
    });
  };
}

module.exports = { haWriteGuard, isConfirmedPassive };

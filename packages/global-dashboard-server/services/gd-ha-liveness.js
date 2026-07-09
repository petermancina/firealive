'use strict';

// GD HA liveness signals (B6d) -- the GD twin of server/services/ha/ha-liveness.js.
// In-process timestamps consumed by the active's self-fence (gd-ha-failover
// .checkSelfFence, PR-3). Two independent signals:
//   - lastClientRequestAt: the last real client API request this GD node served,
//     stamped by the client-activity middleware (packages/global-dashboard-server/
//     index.js). It excludes the peer control plane (/api/ha/peer/*) and health
//     checks so peer chatter and load-balancer probes do not count as "clients are
//     still here".
//   - lastPeerContactAt: the last time this node successfully delivered a heartbeat
//     to its peer over the mTLS link, stamped by the scheduler's active heartbeat
//     tick.
// The self-fence demotes an active only when BOTH signals have gone stale -- the
// node is isolated from its clients AND its peer -- so two actives cannot both keep
// writing during a partition.
//
// In-memory by design: the writers (middleware / scheduler) and the reader
// (scheduler) are the same server process, and the signal is intentionally
// non-durable. A process restart leaves both null, which checkSelfFence reads as
// "insufficient signal" and will not fence on -- the safe default, since a freshly
// started node must never self-demote before it has had a chance to serve traffic
// or reach its peer.

// Which requests count as "a client is still reaching this node".
//
// Callers MUST pass the FULL request path (req.originalUrl), not req.path. The
// client-activity middleware is mounted at '/api/', and Express strips the mount
// path, so req.path there is '/health' -- never '/api/health'. This predicate is
// exported and asserted by the regression rather than left as an inline condition
// in index.js, because an unexported condition is exactly how these exclusions came
// to be compared against the wrong path form: every load-balancer probe stamped
// client activity, lastClientRequestAt never went stale, and the isolation
// self-fence could not fire in the one case it exists for.
//
// On uncertainty this returns TRUE (stamp). Not stamping is the dangerous direction:
// it ages the client signal and could self-fence an active that is genuinely serving,
// leaving the pair with no writer. Failing to fence an isolated active is the milder
// error, since the lease and the epoch fence already stop its writes from taking
// effect. This mirrors checkSelfFence, which abstains on insufficient signal.
const PEER_CONTROL_PREFIX = '/api/ha/peer';
const HEALTH_PATH = '/api/health';

function shouldStampClientRequest(fullPath) {
  if (typeof fullPath !== 'string' || !fullPath) {
    return true;
  }
  const p = fullPath.split('?')[0];
  if (p === HEALTH_PATH) {
    return false;
  }
  // Exact segment boundary: '/api/ha/peers' (were it ever added) is not the peer
  // control plane and would be a client route.
  if (p === PEER_CONTROL_PREFIX || p.startsWith(PEER_CONTROL_PREFIX + '/')) {
    return false;
  }
  return true;
}

let lastClientRequestAt = null;
let lastPeerContactAt = null;

function recordClientRequest() {
  lastClientRequestAt = new Date().toISOString();
}

function recordPeerContact() {
  lastPeerContactAt = new Date().toISOString();
}

function snapshot() {
  return {
    lastClientRequestAt: lastClientRequestAt,
    lastPeerContactAt: lastPeerContactAt,
  };
}

module.exports = {
  shouldStampClientRequest,
  recordClientRequest,
  recordPeerContact,
  snapshot,
};

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
  recordClientRequest,
  recordPeerContact,
  snapshot,
};

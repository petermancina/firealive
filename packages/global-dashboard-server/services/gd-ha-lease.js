// FIREALIVE GLOBAL DASHBOARD -- HA lease / epoch authority (B6d)
//
// The GD twin of server/services/ha/ha-lease.js. The lease/epoch is the INTERNAL
// failover authority. A monotonic epoch lives in gd_ha_lease (id = 'current'); the
// holder of the CURRENT epoch is the sole writer. The org's external load balancer
// routes traffic, but only the epoch holder may write, so a write misrouted to the
// wrong node is refused -- never split-brain, never divergence.
//
//   active  -- renewLease() refreshes this node's own lease each heartbeat tick.
//   passive -- recordPeerHeartbeat() adopts the active's epoch + lease expiry.
//   promote -- claimNextEpoch() bumps epoch + 1 and takes the lease. The
//              BEFORE-UPDATE gd_ha_lease_epoch_monotonic trigger permits the
//              increase and aborts any decrease, so a recovered old active that
//              re-claims a lower epoch cannot win.
//
// assertWriteAuthority() is the write gate. It is a NO-OP on a standalone
// (unpaired) node so single-node deployments are completely unaffected; once
// paired it throws HAWriteRefused unless this node is the active holder of an
// unexpired current-epoch lease. iAmActive() additionally fences on lease expiry,
// so an active that stops renewing (hung, partitioned) loses write authority on
// its own.
//
// Pure lease logic over the injected db handle: no transport, no external
// requires. ASCII-only; no template literals.

const DEFAULT_LEASE_TTL_SEC = 30; // matches gd-ha-pairing.finalizeRole's default

class HAWriteRefused extends Error {
  constructor(message) {
    super(message || 'gd-ha-lease: write refused -- this node is not the active lease holder');
    this.name = 'HAWriteRefused';
    this.code = 'HA_WRITE_REFUSED';
  }
}

function ensureLeaseRow(db) {
  // The active gets its lease row at pairing (finalizeRole); the passive does not,
  // so create the default row defensively before any read or update.
  db.prepare("INSERT OR IGNORE INTO gd_ha_lease (id, epoch, holder) VALUES ('current', 0, 'none')").run();
}

function getLease(db) {
  ensureLeaseRow(db);
  return db.prepare(
    "SELECT epoch, holder, lease_expires_at, last_heartbeat_at, term_started_at FROM gd_ha_lease WHERE id = 'current'"
  ).get();
}

function currentEpoch(db) {
  ensureLeaseRow(db);
  const row = db.prepare("SELECT epoch FROM gd_ha_lease WHERE id = 'current'").get();
  return row ? row.epoch : 0;
}

function nodeRole(db) {
  const row = db.prepare("SELECT role FROM gd_ha_node WHERE id = 'self'").get();
  return row ? row.role : 'standalone';
}

function leaseExpired(lease) {
  // A null expiry is treated as not-expired -- a freshly promoted active before
  // its first renew. A real active always carries an expiry.
  if (!lease || !lease.lease_expires_at) {
    return false;
  }
  return Date.parse(lease.lease_expires_at) <= Date.now();
}

function iAmActive(db) {
  if (nodeRole(db) !== 'active') {
    return false;
  }
  const lease = getLease(db);
  if (!lease || lease.holder !== 'self') {
    return false;
  }
  return !leaseExpired(lease);
}

function assertWriteAuthority(db) {
  // Standalone (HA not paired): the sole node writes freely. HA gating must never
  // affect single-node deployments.
  if (nodeRole(db) === 'standalone') {
    return;
  }
  if (iAmActive(db)) {
    return;
  }
  throw new HAWriteRefused();
}

function renewLease(db, ttlSec) {
  // Active-only: refresh THIS node's lease. The WHERE holder = 'self' guard means
  // a node that has lost the lease (was demoted, holder is now 'peer') cannot
  // resurrect it here.
  ensureLeaseRow(db);
  const ttl = ttlSec || DEFAULT_LEASE_TTL_SEC;
  const expires = new Date(Date.now() + ttl * 1000).toISOString();
  const info = db.prepare(
    "UPDATE gd_ha_lease SET holder = 'self', lease_expires_at = ?, last_heartbeat_at = datetime('now'), updated_at = datetime('now') WHERE id = 'current' AND holder = 'self'"
  ).run(expires);
  return { renewed: info.changes > 0, epoch: currentEpoch(db), leaseExpiresAt: expires };
}

function recordPeerHeartbeat(db, peerEpoch, peerLeaseExpiry) {
  // Passive-side: the active's heartbeat carries its epoch + lease expiry. Adopt
  // it when it is current-or-newer; refuse a heartbeat from a stale (lower-epoch)
  // active -- that node has been superseded and must step down.
  ensureLeaseRow(db);
  const cur = currentEpoch(db);
  const ep = Number(peerEpoch);
  if (!Number.isFinite(ep) || ep < cur) {
    return { ok: false, reason: 'stale_epoch', localEpoch: cur, peerEpoch: peerEpoch };
  }
  db.prepare(
    "UPDATE gd_ha_lease SET epoch = ?, holder = 'peer', lease_expires_at = ?, last_heartbeat_at = datetime('now'), updated_at = datetime('now') WHERE id = 'current'"
  ).run(ep, peerLeaseExpiry || null);
  return { ok: true, epoch: ep };
}

function claimNextEpoch(db, ttlSec) {
  // Promotion: bump the epoch and take the lease. The BEFORE-UPDATE monotonic
  // trigger permits the increase; it would abort a decrease.
  ensureLeaseRow(db);
  const ttl = ttlSec || DEFAULT_LEASE_TTL_SEC;
  const expires = new Date(Date.now() + ttl * 1000).toISOString();
  db.prepare(
    "UPDATE gd_ha_lease SET epoch = epoch + 1, holder = 'self', term_started_at = datetime('now'), lease_expires_at = ?, last_heartbeat_at = datetime('now'), updated_at = datetime('now') WHERE id = 'current'"
  ).run(expires);
  return currentEpoch(db);
}

module.exports = {
  HAWriteRefused,
  DEFAULT_LEASE_TTL_SEC,
  ensureLeaseRow,
  getLease,
  currentEpoch,
  iAmActive,
  assertWriteAuthority,
  renewLease,
  recordPeerHeartbeat,
  claimNextEpoch,
};

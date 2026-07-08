// FIREALIVE GLOBAL DASHBOARD -- HA failover orchestration (B6d)
//
// The GD twin of server/services/ha/ha-failover.js. Drives the passive's
// automated takeover when the active is lost, and the active's own step-down when
// it is superseded or isolated. Built on gd-ha-lease (epoch/lease authority) and
// gd-ha-keys (the sealed shared-material unwrap), plus the two runtime install
// hooks (gd-tier1-kek.installRuntimeKek, gd-jwt-secret.installRuntimeJwtSecret) so
// a promoted node can read Tier-1 columns and validate the same sessions the
// former active issued.
//
//   evaluatePromotion -- passive scheduler tick: if the active's heartbeat has
//                        gone stale past missCount intervals, and not within the
//                        post-promotion cooldown, promote.
//   promote           -- install shared KEK + JWT (fail before any state change),
//                        claim epoch + 1 and the lease, flip role to active, audit
//                        HA_PROMOTED with the measured elapsed.
//   reconcileRole     -- an active that has lost the current-epoch lease (a higher
//                        epoch was adopted, or its lease expired) steps down: the
//                        stale-epoch fence, the no-split-brain guarantee.
//   checkSelfFence    -- isolation self-fence: an active that has lost BOTH the
//                        peer link AND client traffic for the timeout self-demotes
//                        (the peer may have promoted). Conservative: both signals
//                        are required, so a serving active is never demoted.
//
// Pure orchestration over the injected db handle. ASCII-only; no template
// literals. All requires are services/ siblings (or ../db-init).

const haLease = require('./gd-ha-lease');
const haKeys = require('./gd-ha-keys');
const tier1 = require('./gd-tier1-kek');
const { installRuntimeJwtSecret } = require('./gd-jwt-secret');
const { appendGdAuditEntry } = require('./gd-audit-chain');
const { getDb } = require('../db-init');

const DEFAULTS = {
  leaseTtlSec: 30,
  heartbeatIntervalSec: 5,
  missCount: 3,
  promotionCooldownSec: 60,
  selfFenceTimeoutSec: 60,
};

function num(v, dflt) {
  const n = Number(v);
  return (Number.isFinite(n) && n > 0) ? n : dflt;
}

function getFailoverConfig(db) {
  let cfg = {};
  try {
    const row = db.prepare("SELECT value FROM config WHERE key = 'ha_config'").get();
    if (row && row.value) {
      const parsed = JSON.parse(row.value);
      if (parsed && typeof parsed === 'object') {
        cfg = parsed;
      }
    }
  } catch (e) {
    cfg = {};
  }
  return {
    leaseTtlSec: num(cfg.leaseTtlSec, DEFAULTS.leaseTtlSec),
    heartbeatIntervalSec: num(cfg.heartbeatIntervalSec, DEFAULTS.heartbeatIntervalSec),
    missCount: num(cfg.missCount, DEFAULTS.missCount),
    promotionCooldownSec: num(cfg.promotionCooldownSec, DEFAULTS.promotionCooldownSec),
    selfFenceTimeoutSec: num(cfg.selfFenceTimeoutSec, DEFAULTS.selfFenceTimeoutSec),
  };
}

function nodeRole(db) {
  const row = db.prepare("SELECT role FROM gd_ha_node WHERE id = 'self'").get();
  return row ? row.role : 'standalone';
}

function peerPaired(db) {
  return !!db.prepare("SELECT 1 FROM gd_ha_peer WHERE status = 'paired' LIMIT 1").get();
}

// Append a GD audit entry on a short-lived connection (the GD route audit
// pattern). Audit must never break a promotion / demotion.
function auditLog(userId, eventType, detail, ip) {
  let adb = null;
  try {
    adb = getDb();
    appendGdAuditEntry(adb, { userId: userId, eventType: eventType, detail: detail, ip: ip });
  } catch (err) {
    console.error('gd-ha-failover audit append failed:', err && err.message ? err.message : err);
  } finally {
    if (adb) { try { adb.close(); } catch (closeErr) { /* ignore */ } }
  }
}

function safeAudit(eventType, detail) {
  try {
    auditLog(null, eventType, detail, null);
  } catch (e) {
    // Audit must never break a promotion / demotion.
  }
}

function activeIsDown(db, cfg) {
  // Staleness is measured from the last heartbeat the active sent (recorded by
  // gd-ha-lease.recordPeerHeartbeat). Without a recorded heartbeat we do NOT
  // declare the active down -- this avoids promoting in the brief window right
  // after pairing, before the first heartbeat arrives.
  const lease = haLease.getLease(db);
  if (!lease || !lease.last_heartbeat_at) {
    return false;
  }
  const last = Date.parse(lease.last_heartbeat_at);
  if (!Number.isFinite(last)) {
    return false;
  }
  const thresholdMs = cfg.missCount * cfg.heartbeatIntervalSec * 1000;
  return (Date.now() - last) > thresholdMs;
}

function inCooldown(db, cfg) {
  // term_started_at is stamped when this node took the lease (claimNextEpoch /
  // pairing). On a passive that has not yet promoted it is null, so cooldown does
  // not block the first promotion; after promoting it suppresses a re-promotion
  // for promotionCooldownSec, bounding flap.
  const lease = haLease.getLease(db);
  if (!lease || !lease.term_started_at) {
    return false;
  }
  const started = Date.parse(lease.term_started_at);
  if (!Number.isFinite(started)) {
    return false;
  }
  return (Date.now() - started) < (cfg.promotionCooldownSec * 1000);
}

function promote(db, opts) {
  const t0 = Date.now();
  const cfg = getFailoverConfig(db);

  // 1. Unwrap + install the shared material FIRST, so any failure aborts before an
  //    epoch or role change. A node without sealed material cannot serve Tier-1
  //    columns, so refuse rather than promote into a half-working state.
  const node = db.prepare("SELECT sealed_promotion_kek FROM gd_ha_node WHERE id = 'self'").get();
  if (!node || !node.sealed_promotion_kek) {
    throw new Error('gd-ha-failover.promote: no sealed promotion material; cannot promote');
  }
  const raw = haKeys.unwrapKekWithLocal(db, node.sealed_promotion_kek);
  let material;
  try {
    material = JSON.parse(raw.toString('utf8'));
  } catch (e) {
    throw new Error('gd-ha-failover.promote: sealed promotion material is corrupt');
  }
  if (material.kek) {
    tier1.installRuntimeKek(Buffer.from(material.kek, 'hex'));
  }
  if (material.jwtSecret) {
    installRuntimeJwtSecret(material.jwtSecret);
  }

  // 2. Take the next epoch + the lease (the monotonic trigger guards the bump).
  const epoch = haLease.claimNextEpoch(db, cfg.leaseTtlSec);

  // 3. Buffered journal rows are applied on receipt (gd-ha-replication.applyBatch
  //    via /ha/peer/replicate), so there is nothing to drain here; promotion
  //    proceeds from the last applied LSN (the bounded-RPO window).

  // 4. Flip role to active.
  db.prepare("UPDATE gd_ha_node SET role = 'active', updated_at = datetime('now') WHERE id = 'self'").run();

  // 5. Audit (records epoch + measured elapsed).
  const elapsedMs = Date.now() - t0;
  safeAudit('HA_PROMOTED', 'Promoted to active at epoch ' + epoch + ' (' + elapsedMs + 'ms elapsed)');
  return { promoted: true, epoch: epoch, elapsedMs: elapsedMs };
}

function demote(db, reason, opts) {
  db.prepare("UPDATE gd_ha_node SET role = 'passive', updated_at = datetime('now') WHERE id = 'self'").run();
  const evt = (reason === 'self_fence') ? 'HA_SELF_FENCED' : 'HA_DEMOTED';
  safeAudit(evt, 'Demoted to passive (' + (reason || 'superseded') + ')');
  return { demoted: true, reason: reason || 'superseded' };
}

function reconcileRole(db, opts) {
  // If this node believes it is active but no longer holds an unexpired
  // current-epoch lease (a higher epoch was adopted from the peer, or its lease
  // expired), step down. This is the stale-epoch fence.
  if (nodeRole(db) === 'active' && !haLease.iAmActive(db)) {
    return demote(db, 'stale_epoch', opts);
  }
  return { demoted: false };
}

function evaluatePromotion(db, opts) {
  if (nodeRole(db) !== 'passive') {
    return { promoted: false, reason: 'not_passive' };
  }
  if (!peerPaired(db)) {
    return { promoted: false, reason: 'no_peer' };
  }
  const cfg = getFailoverConfig(db);
  if (!activeIsDown(db, cfg)) {
    return { promoted: false, reason: 'active_healthy' };
  }
  if (inCooldown(db, cfg)) {
    safeAudit('HA_PROMOTION_THROTTLED', 'Promotion suppressed by cooldown');
    return { promoted: false, reason: 'cooldown' };
  }
  return promote(db, opts);
}

function checkSelfFence(db, opts) {
  if (nodeRole(db) !== 'active') {
    return { fenced: false, reason: 'not_active' };
  }
  const cfg = getFailoverConfig(db);
  const now = Date.now();
  const peerAt = (opts && opts.lastPeerContactAt) ? Date.parse(opts.lastPeerContactAt) : null;
  const clientAt = (opts && opts.lastClientRequestAt) ? Date.parse(opts.lastClientRequestAt) : null;
  // Both signals are required. Missing either -> do NOT fence: never demote an
  // active that may still be serving the SOC just because the peer link is down.
  if (!Number.isFinite(peerAt) || !Number.isFinite(clientAt)) {
    return { fenced: false, reason: 'insufficient_signal' };
  }
  const timeoutMs = cfg.selfFenceTimeoutSec * 1000;
  if ((now - peerAt) > timeoutMs && (now - clientAt) > timeoutMs) {
    demote(db, 'self_fence', opts);
    return { fenced: true };
  }
  return { fenced: false, reason: 'not_isolated' };
}

module.exports = {
  DEFAULTS,
  getFailoverConfig,
  activeIsDown,
  inCooldown,
  evaluatePromotion,
  promote,
  demote,
  reconcileRole,
  checkSelfFence,
};

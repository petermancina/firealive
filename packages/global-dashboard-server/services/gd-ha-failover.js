// FIREALIVE GLOBAL DASHBOARD -- HA failover orchestration (B6d)
//
// The GD twin of server/services/ha/ha-failover.js. Drives the passive's
// automated takeover when the active is lost, and the active's own step-down when
// it is superseded or isolated. Built on gd-ha-lease (epoch/lease authority) and
// gd-ha-keys (the sealed shared-material unwrap), plus the two runtime install
// hooks (gd-tier1-kek.adoptSharedKek, gd-jwt-secret.installRuntimeJwtSecret) so
// a promoted node can read Tier-1 columns and validate the same sessions the
// former active issued.
//
//   evaluatePromotion -- passive scheduler tick: if the active's heartbeat has
//                        gone stale past missCount intervals, and not within the
//                        post-promotion cooldown, promote.
//   promote           -- adopt+persist shared KEK + JWT (fail before any state change),
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
// literals. All requires are services/ siblings.

const haLease = require('./gd-ha-lease');
const haKeys = require('./gd-ha-keys');
const haModes = require('./gd-ha-modes');
const tier1 = require('./gd-tier1-kek');
const { installRuntimeJwtSecret } = require('./gd-jwt-secret');
const { auditHaEvent } = require('./gd-ha-audit');

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

// A cloud passive whose attestation is failing hits the detect tick every
// heartbeat interval, so the refusal audit is throttled to one row per
// promotionCooldownSec. Operator-initiated promotions (manual failover, peer lease
// handover, self-test) go through promote() directly and audit every refusal --
// they are rare and each one deserves a record.
let lastRefusalAuditAt = 0;

function auditRefusalThrottled(db, cfg, detail) {
  const now = Date.now();
  if ((now - lastRefusalAuditAt) > (cfg.promotionCooldownSec * 1000)) {
    lastRefusalAuditAt = now;
    safeAudit(db, 'HA_PROMOTION_REFUSED', detail);
  }
}

// Append the audit entry on the SAME connection this module is mutating, rather
// than opening a second one. On a live node both point at one database file, so
// behavior is unchanged and one connection is saved -- but the role change and its
// audit record now always land in the same database. That matters wherever the
// caller supplies a database other than the live one (the regression exercises
// promote/demote against a hermetic in-memory copy): previously the mutation went
// to the temp database while the audit row went to the live chain, writing spurious
// HA_SELF_FENCED / HA_DEMOTED events into a tamper-evident log an auditor reads as
// real. Audit must never break a promotion / demotion, so failures are swallowed.
// Record an HA lifecycle event: append the audit row through the connection this
// module is mutating, then stream it to the operator's SIEM when that connection IS
// the durable chain. Both halves, the severity table, and the drill gate live in
// gd-ha-audit, so promote/demote/self-fence share one implementation with pairing, the
// peer gate, and the HA control plane rather than each carrying a copy. Never breaks a
// promotion or demotion: every failure is swallowed there.
function safeAudit(db, eventType, detail) {
  auditHaEvent(db, eventType, detail, null);
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

  // 0. Per-mode promotion gate, BEFORE the sealed material is unwrapped: an
  //    unverified platform must never unseal the Tier-1 KEK, even transiently. In
  //    cloud mode this re-attests the local confidential VM and throws on failure
  //    (fail-closed); every other mode allows. Audited, then rethrown so the caller
  //    (scheduler tick, manual failover, peer handover, self-test) sees the refusal.
  try {
    haModes.assertModePromotionAllowed(db);
  } catch (modeErr) {
    const detail = (modeErr && modeErr.message) ? modeErr.message.slice(0, 160) : 'mode gate refused promotion';
    safeAudit(db, 'HA_PROMOTION_REFUSED', detail);
    throw modeErr;
  }

  // 1. Unwrap + install the shared material, so any failure aborts before an
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
    // adoptSharedKek seals the shared KEK to THIS node's hardware and persists it to
    // node_state (excluded from replication), so a reboot of this now-active node
    // reloads it fail-closed rather than losing it (closes R1/R4). Runs before any
    // epoch/role change, so a hardware or persistence failure aborts the promotion.
    tier1.adoptSharedKek(db, Buffer.from(material.kek, 'hex'));
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

  // 5. Re-assert the per-mode network posture under the new active. SDN
  //    re-registers the east-west peer segment (idempotent); other modes no-op
  //    (SASE's boundary is an operator-declared connector-source allow-list). This
  //    is BEST-EFFORT and deliberately after the role flip: the org's load balancer
  //    routes client traffic, so a segment-registration failure must never block or
  //    unwind a promotion that has already taken the lease.
  try {
    const seg = haModes.registerHaSegments(db);
    if (seg && seg.registered) {
      safeAudit(db, 'HA_SEGMENT_REREGISTERED', 'Re-registered HA peer segment ' + seg.segment + ' under the new active');
    }
  } catch (segErr) {
    safeAudit(db, 'HA_SEGMENT_REREGISTER_FAILED', 'Segment re-registration failed after promotion (non-fatal): '
      + ((segErr && segErr.message) ? segErr.message.slice(0, 120) : 'error'));
  }

  // 6. Audit (records epoch + measured elapsed).
  const elapsedMs = Date.now() - t0;
  safeAudit(db, 'HA_PROMOTED', 'Promoted to active at epoch ' + epoch + ' (' + elapsedMs + 'ms elapsed)');
  return { promoted: true, epoch: epoch, elapsedMs: elapsedMs };
}

function demote(db, reason, opts) {
  db.prepare("UPDATE gd_ha_node SET role = 'passive', updated_at = datetime('now') WHERE id = 'self'").run();
  const evt = (reason === 'self_fence') ? 'HA_SELF_FENCED' : 'HA_DEMOTED';
  safeAudit(db, evt, 'Demoted to passive (' + (reason || 'superseded') + ')');
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
    safeAudit(db, 'HA_PROMOTION_THROTTLED', 'Promotion suppressed by cooldown');
    return { promoted: false, reason: 'cooldown' };
  }
  // Check the per-mode gate here too, so the automatic detect tick reports a refusal
  // rather than throwing every heartbeat interval. promote() re-checks it (defense in
  // depth for the direct callers); this pre-check exists to keep the tick quiet and
  // the audit log throttled.
  try {
    haModes.assertModePromotionAllowed(db);
  } catch (modeErr) {
    auditRefusalThrottled(db, cfg, 'Automatic promotion refused: '
      + ((modeErr && modeErr.message) ? modeErr.message.slice(0, 160) : 'mode gate refused promotion'));
    return { promoted: false, reason: 'mode_refused' };
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

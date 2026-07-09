// FIREALIVE -- High Availability routes (B5o)
//
// The single consolidated HA route, replacing the mockup /ha and /cluster
// endpoints. Three auth regimes, mounted separately in index.js:
//
//   configRouter  -- /api/ha/config, /api/ha/status, /api/ha/pair. Behind the
//                    normal JWT auth + config-lock chokepoint. Mutations
//                    (PUT /config, POST /pair) additionally require lead/admin.
//   pairInitRouter -- /api/ha/pair-init. Token-authenticated (the body carries a
//                    one-time pairing token); NOT JWT and NOT cert-pinned, since
//                    the peer pin does not exist until pairing completes.
//   peerRouter    -- /api/ha/peer/* (replicate, pair-secret, pair-baseline).
//                    Behind requirePeerCert (pinned mTLS), NOT JWT. index.js
//                    applies a large body limit here for replication/baseline.
//
// The heartbeat/lease/manual-failover/self-test endpoints arrive in PR-2.
// ASCII-only; no template literals.

const router = require('express').Router(); // configRouter
const peerRouter = require('express').Router();
const pairInitRouter = require('express').Router();
const { getDb } = require('../db/init');
// Audit through the connection each handler already holds, not a second one. auditLog()
// opens its own via getDb(); every handler here opens a db for the life of the request
// and closes it in a finally, so the extra connection bought nothing and split each
// operation from its audit record across two handles. auditLogOn appends on the given
// handle and gates SIEM streaming on isLiveChain(db), so a real HA admin action records
// and streams exactly as before. This is the pattern that let ha-failover, ha-pairing,
// and the alert router's audit channel forge rows into the live chain when handed any
// other database; the HA control plane should not model it.
const { auditLogOn } = require('../middleware/audit');
const { requireObjectBody } = require('../middleware/body-validation');
const { getClientCertThumbprint } = require('../middleware/auth');
const haPairing = require('../services/ha/ha-pairing');
const haReplication = require('../services/ha/ha-replication');
const deploymentMode = require('../services/deployment-mode');
const haLease = require('../services/ha/ha-lease');
const haFailover = require('../services/ha/ha-failover');
const haPeerLink = require('../services/ha/ha-peer-link');

const DEFAULT_HA_CONFIG = {
  enabled: false,
  mode: 'active_passive',
  peerEndpoint: null,
  selfEndpoint: null,
  syncIntervalSec: 5,
  heartbeatIntervalSec: 5,
  leaseTtlSec: 30,
  missCount: 3,
  promotionCooldownSec: 60,
  selfFenceTimeoutSec: 60,
};

function loadHaConfig(db) {
  const row = db.prepare("SELECT value FROM config WHERE key = 'ha_config'").get();
  let cfg = {};
  if (row) {
    try { cfg = JSON.parse(row.value) || {}; } catch (parseErr) { cfg = {}; }
  }
  return Object.assign({}, DEFAULT_HA_CONFIG, cfg);
}

function actor(req) {
  return (req.user && req.user.id) ? req.user.id : 'system';
}

function requireRole(req, res, roles) {
  const role = req.user && req.user.role;
  if (!role || roles.indexOf(role) === -1) {
    res.status(403).json({ error: 'insufficient role for this action' });
    return false;
  }
  return true;
}

const PEER_HEARTBEAT_PATH = '/api/ha/peer/heartbeat';
const PEER_LEASE_PATH = '/api/ha/peer/lease';

function nodeRole(db) {
  const row = db.prepare("SELECT role FROM ha_node WHERE id = 'self'").get();
  return row ? row.role : 'standalone';
}

function peerPaired(db) {
  return !!db.prepare("SELECT 1 FROM ha_peer WHERE status = 'paired' LIMIT 1").get();
}

// A lightweight integrity fingerprint over stable reference data, compared
// across the pair and before/after a drill to confirm no rows were lost.
function dataChecksum(db) {
  try {
    return 'u' + db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  } catch (e) {
    return 'na';
  }
}

// Apply an inbound peer epoch signal (heartbeat or lease assertion): adopt the
// monotonic epoch and step down if we are a now-superseded active.
function applyPeerLeaseSignal(db, body) {
  const r = haLease.recordPeerHeartbeat(db, body.epoch, body.leaseExpiresAt);
  haFailover.reconcileRole(db);
  return { ok: r.ok !== false, epoch: haLease.currentEpoch(db), reason: r.reason || null };
}

// --- config (JWT + config-lock) ------------------------------------------

router.get('/config', (req, res) => {
  const db = getDb();
  try {
    res.json(loadHaConfig(db));
  } catch (loadErr) {
    res.status(500).json({ error: 'Failed to load HA config' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

router.put('/config', requireObjectBody, (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) {
    return;
  }
  const db = getDb();
  try {
    const merged = Object.assign({}, DEFAULT_HA_CONFIG, req.body);
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('ha_config', ?)").run(JSON.stringify(merged));
    auditLogOn(db, actor(req), 'HA_CONFIG_UPDATED', 'Mode: active_passive, enabled: ' + (merged.enabled ? 'yes' : 'no'), req.ip);
    // Apply the new intervals live: re-register the HA scheduler ticks so a
    // changed heartbeat/replication interval takes effect without a restart.
    try { require('../services/scheduler').schedulerService.reloadHaJobs(); } catch (reloadErr) { /* scheduler not running; next start reads the saved config */ }
    res.json({ success: true });
  } catch (saveErr) {
    res.status(500).json({ error: 'Failed to save HA config' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

router.get('/status', (req, res) => {
  const db = getDb();
  try {
    const cfg = loadHaConfig(db);
    const node = db.prepare("SELECT role FROM ha_node WHERE id = 'self'").get() || { role: 'standalone' };
    const lease = db.prepare("SELECT epoch, holder, lease_expires_at, last_heartbeat_at FROM ha_lease WHERE id = 'current'").get() || { epoch: 0, holder: 'none' };
    const peer = db.prepare("SELECT peer_endpoint, peer_anchor_fingerprint, peer_cert_fingerprint, status, paired_at FROM ha_peer LIMIT 1").get() || null;
    const rep = db.prepare("SELECT lag_seconds, last_applied_lsn, last_shipped_lsn, last_acked_lsn, baseline_at, last_apply_at FROM ha_replication_state WHERE id = 'self'").get() || {};

    let mode = null;
    try { mode = deploymentMode.getMode(db); } catch (modeErr) { mode = null; }

    let reachable = false;
    if (lease.last_heartbeat_at) {
      const ageRow = db.prepare("SELECT (julianday('now') - julianday(?)) * 86400.0 AS secs").get(lease.last_heartbeat_at);
      const window = cfg.heartbeatIntervalSec * (cfg.missCount + 1);
      reachable = !!(ageRow && ageRow.secs != null && ageRow.secs < window);
    }

    res.json({
      enabled: !!cfg.enabled,
      mode: mode,
      role: node.role,
      epoch: lease.epoch,
      leaseHolder: lease.holder,
      leaseExpiresAt: lease.lease_expires_at || null,
      peer: peer ? {
        paired: peer.status === 'paired',
        status: peer.status,
        endpoint: peer.peer_endpoint,
        anchorFingerprint: peer.peer_anchor_fingerprint,
        certFingerprint: peer.peer_cert_fingerprint,
        pairedAt: peer.paired_at,
        lastHeartbeatAt: lease.last_heartbeat_at || null,
        reachable: reachable,
      } : { paired: false },
      replication: {
        lagSeconds: rep.lag_seconds != null ? rep.lag_seconds : 0,
        lastAppliedLsn: rep.last_applied_lsn != null ? rep.last_applied_lsn : 0,
        lastShippedLsn: rep.last_shipped_lsn != null ? rep.last_shipped_lsn : 0,
        lastAckedLsn: rep.last_acked_lsn != null ? rep.last_acked_lsn : 0,
        baselineAt: rep.baseline_at || null,
        lastApplyAt: rep.last_apply_at || null,
      },
    });
  } catch (statusErr) {
    res.status(500).json({ error: 'Failed to load HA status' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

router.post('/pair', requireObjectBody, async (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) {
    return;
  }
  const peerEndpoint = req.body.peerEndpoint;
  const token = req.body.token;
  if (typeof peerEndpoint !== 'string' || !peerEndpoint || typeof token !== 'string' || !token) {
    return res.status(400).json({ error: 'peerEndpoint and token are required' });
  }
  const db = getDb();
  try {
    const existing = db.prepare("SELECT status FROM ha_peer WHERE status = 'paired' LIMIT 1").get();
    if (existing) {
      return res.status(409).json({ error: 'already paired with a peer' });
    }
    const cfg = loadHaConfig(db);
    auditLogOn(db, actor(req), 'HA_PAIR_INITIATED', 'Pairing with ' + peerEndpoint, req.ip);
    const result = await haPairing.beginPairing(db, peerEndpoint, token, {
      selfEndpoint: cfg.selfEndpoint,
      leaseTtlSec: cfg.leaseTtlSec,
    });
    res.json({ success: true, role: result.role, peerFingerprint: result.peerFingerprint });
  } catch (pairErr) {
    const detail = (pairErr && pairErr.message) ? pairErr.message : 'error';
    try { auditLogOn(db, actor(req), 'HA_PAIR_FAILED', 'Pairing with ' + peerEndpoint + ' failed: ' + detail.slice(0, 160), req.ip); } catch (auditErr) { /* ignore */ }
    res.status(502).json({ error: 'pairing failed', detail: detail });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

router.post('/manual-failover', requireObjectBody, async (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) {
    return;
  }
  const db = getDb();
  try {
    if (nodeRole(db) !== 'active') {
      return res.status(409).json({ error: 'manual failover is initiated on the active node (it must step down first)' });
    }
    if (!peerPaired(db)) {
      return res.status(409).json({ error: 'no paired peer to fail over to' });
    }
    const fromEpoch = haLease.currentEpoch(db);
    // Step down FIRST so this node stops writing before the peer promotes -- the
    // make-before-break order that guarantees no split-brain.
    haFailover.demote(db, 'manual', {});
    try {
      // sendToPeer resolves the parsed response BODY (single resolve path); there
      // is no .json wrapper. Reading r.json yielded undefined, so the peer's real
      // epoch and promoted flag were never observed.
      const peer = await haPeerLink.sendToPeer(db, PEER_LEASE_PATH, { handover: true, fromEpoch: fromEpoch }, {}) || {};
      auditLogOn(db, actor(req), 'HA_MANUAL_FAILOVER', 'Graceful failover: stepped down, peer promoted to epoch ' + (peer.epoch || '?'), req.ip);
      res.json({ ok: true, role: 'passive', peerPromoted: peer.promoted !== false, peerEpoch: peer.epoch || null });
    } catch (sendErr) {
      const m = (sendErr && sendErr.message) ? sendErr.message.slice(0, 120) : 'error';
      auditLogOn(db, actor(req), 'HA_MANUAL_FAILOVER', 'Stepped down; handover signal failed (' + m + '); peer will promote via detection', req.ip);
      res.json({ ok: true, role: 'passive', peerPromoted: false, note: 'peer will promote via failure detection' });
    }
  } catch (failErr) {
    res.status(500).json({ error: 'manual failover error', detail: (failErr && failErr.message) ? failErr.message.slice(0, 160) : 'error' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

router.post('/test-failover', requireObjectBody, async (req, res) => {
  if (!requireRole(req, res, ['lead', 'admin'])) {
    return;
  }
  const db = getDb();
  try {
    if (nodeRole(db) !== 'active') {
      return res.status(409).json({ error: 'the failover self-test is run from the active node' });
    }
    if (!peerPaired(db)) {
      return res.status(409).json({ error: 'no paired peer for a failover self-test' });
    }
    try { auditLogOn(db, actor(req), 'HA_TEST_STARTED', 'HA failover self-test started', req.ip); } catch (auditErr) { /* ignore */ }
    const t0 = Date.now();
    const fromEpoch = haLease.currentEpoch(db);
    const checksumBefore = dataChecksum(db);
    // Fail over: step down, then promote the peer over the peer link.
    haFailover.demote(db, 'test', {});
    let promoteResp = {};
    try {
      promoteResp = await haPeerLink.sendToPeer(db, PEER_LEASE_PATH, { handover: true, test: true, fromEpoch: fromEpoch }, {}) || {};
    } catch (sendErr) {
      try { haFailover.promote(db, {}); } catch (restoreErr) { /* best-effort restore */ }
      return res.status(502).json({ ok: false, error: 'self-test could not promote the peer', detail: (sendErr && sendErr.message) ? sendErr.message.slice(0, 160) : 'error' });
    }
    const failoverMs = Date.now() - t0;
    const served = promoteResp.role === 'active' && promoteResp.promoted !== false;
    const integrityOk = !!promoteResp.checksum && promoteResp.checksum === checksumBefore;
    // Fail back: adopt the peer's new epoch so our next claim supersedes it,
    // re-promote, then notify the peer (it demotes). Best-effort -- a failback
    // failure leaves the peer active at a valid higher epoch, never split-brain.
    const tBack0 = Date.now();
    let restored = false;
    try {
      if (promoteResp.epoch) {
        haLease.recordPeerHeartbeat(db, promoteResp.epoch, null);
      }
      haFailover.promote(db, {});
      const lease = haLease.getLease(db) || {};
      const back = await haPeerLink.sendToPeer(db, PEER_LEASE_PATH, { epoch: haLease.currentEpoch(db), leaseExpiresAt: lease.lease_expires_at || null }, {});
      restored = !!(back && back.ok);
    } catch (backErr) {
      restored = false;
    }
    const failbackMs = Date.now() - tBack0;
    const result = {
      ok: true,
      failoverTimeMs: failoverMs,
      failbackTimeMs: failbackMs,
      served: served,
      integrityOk: integrityOk,
      restored: restored,
      epoch: haLease.currentEpoch(db),
    };
    try { auditLogOn(db, actor(req), 'HA_TEST_COMPLETE', 'HA self-test: failover ' + failoverMs + 'ms, served=' + served + ', integrity=' + integrityOk + ', restored=' + restored, req.ip); } catch (auditErr) { /* ignore */ }
    res.json(result);
  } catch (testErr) {
    res.status(500).json({ error: 'self-test error', detail: (testErr && testErr.message) ? testErr.message.slice(0, 160) : 'error' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

// --- pair-init (token-authenticated, NOT cert-pinned) --------------------

pairInitRouter.post('/', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const thumb = getClientCertThumbprint(req);
    const cfg = loadHaConfig(db);
    const result = haPairing.respondToPairInit(db, req.body, thumb, { selfEndpoint: cfg.selfEndpoint });
    if (!result.ok) {
      return res.status(result.status || 400).json({ error: result.error || 'pair-init failed' });
    }
    res.json({ bundle: result.bundle });
  } catch (initErr) {
    res.status(500).json({ error: 'pair-init error' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

// --- peer endpoints (pinned mTLS via requirePeerCert in index.js) --------

peerRouter.post('/replicate', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const result = haReplication.applyBatch(db, req.body);
    if (!result.ok) {
      return res.status(409).json(result); // epoch fence: stale active
    }
    res.json(result);
  } catch (repErr) {
    res.status(500).json({ error: 'replicate failed' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

peerRouter.post('/pair-secret', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    if (typeof req.body.envelope !== 'string' || !req.body.envelope) {
      return res.status(400).json({ error: 'envelope required' });
    }
    haPairing.receiveSharedMaterial(db, req.body.envelope);
    res.json({ ok: true });
  } catch (secretErr) {
    res.status(500).json({ error: 'pair-secret failed' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

peerRouter.post('/pair-baseline', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    if (typeof req.body.snapshot !== 'string' || !req.body.snapshot) {
      return res.status(400).json({ error: 'snapshot required' });
    }
    const cfg = loadHaConfig(db);
    const result = haPairing.receiveBaseline(db, req.body.snapshot, { leaseTtlSec: cfg.leaseTtlSec });
    res.json(result);
  } catch (baselineErr) {
    res.status(500).json({ error: 'pair-baseline failed' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

peerRouter.post('/heartbeat', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    res.json(applyPeerLeaseSignal(db, req.body || {}));
  } catch (hbErr) {
    res.status(500).json({ error: 'heartbeat error' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

peerRouter.post('/lease', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const body = req.body || {};
    if (body.handover === true) {
      // Graceful failover handover: the former active stepped down. Promote.
      if (nodeRole(db) === 'passive') {
        const r = haFailover.promote(db, {});
        return res.json({ ok: true, promoted: true, role: 'active', epoch: r.epoch, checksum: dataChecksum(db) });
      }
      // Already active (e.g., promoted via detection first): idempotent ack.
      return res.json({ ok: true, promoted: false, role: nodeRole(db), epoch: haLease.currentEpoch(db), checksum: dataChecksum(db) });
    }
    res.json(applyPeerLeaseSignal(db, body));
  } catch (leaseErr) {
    res.status(500).json({ error: 'lease error' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

module.exports = {
  configRouter: router,
  pairInitRouter: pairInitRouter,
  peerRouter: peerRouter,
};

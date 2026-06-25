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
const { auditLog } = require('../middleware/audit');
const { requireObjectBody } = require('../middleware/body-validation');
const { getClientCertThumbprint } = require('../middleware/auth');
const haPairing = require('../services/ha/ha-pairing');
const haReplication = require('../services/ha/ha-replication');
const deploymentMode = require('../services/deployment-mode');

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
    auditLog(actor(req), 'HA_CONFIG_UPDATED', 'Mode: active_passive, enabled: ' + (merged.enabled ? 'yes' : 'no'), req.ip);
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
    auditLog(actor(req), 'HA_PAIR_INITIATED', 'Pairing with ' + peerEndpoint, req.ip);
    const result = await haPairing.beginPairing(db, peerEndpoint, token, {
      selfEndpoint: cfg.selfEndpoint,
      leaseTtlSec: cfg.leaseTtlSec,
    });
    res.json({ success: true, role: result.role, peerFingerprint: result.peerFingerprint });
  } catch (pairErr) {
    const detail = (pairErr && pairErr.message) ? pairErr.message : 'error';
    try { auditLog(actor(req), 'HA_PAIR_FAILED', 'Pairing with ' + peerEndpoint + ' failed: ' + detail.slice(0, 160), req.ip); } catch (auditErr) { /* ignore */ }
    res.status(502).json({ error: 'pairing failed', detail: detail });
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

module.exports = {
  configRouter: router,
  pairInitRouter: pairInitRouter,
  peerRouter: peerRouter,
};

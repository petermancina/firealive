// packages/global-dashboard-server/routes/gd-ha.js
//
// The GD's /api/ha route -- the GD twin of server/routes/ha.js. Three routers:
//   configRouter   -- /api/ha/config, /status, /pair (operator control plane).
//                     Mounted behind authMiddleware(['ciso']) + the config-lock.
//                     Filled in the next commit; declared empty here.
//   peerRouter     -- /api/ha/peer/* (replicate, pair-secret, pair-baseline,
//                     heartbeat). Behind requirePeerCert (pinned mTLS), NOT JWT.
//                     index.js mounts it behind gd-ha-peer-link.requirePeerCert.
//   pairInitRouter -- /api/ha/pair-init. Token-authenticated (the body carries a
//                     single-use pairing token); NOT cert-pinned, since the pin
//                     does not exist yet at first contact.
//
// This commit delivers the peer data plane + pair-init. The /peer/lease endpoint
// (graceful-handover promotion) and the heartbeat's role-reconcile reaction are
// failover behavior and land with gd-ha-failover (PR-3). ASCII-only; no template
// literals.

const peerRouter = require('express').Router();
const pairInitRouter = require('express').Router();
const configRouter = require('express').Router();
const { getDb } = require('../db-init');
const gdHaPairing = require('../services/gd-ha-pairing');
const gdHaReplication = require('../services/gd-ha-replication');
const gdHaLease = require('../services/gd-ha-lease');

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

// Local body-validation middleware (the GD has no shared middleware/ dir): the
// request body must be a plain JSON object.
function requireObjectBody(req, res, next) {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'request body must be a JSON object' });
  }
  return next();
}

// The presented mTLS client-cert thumbprint (lowercase-hex fingerprint256), the
// same self-consistent format the peer-link pins with (gd-ha-peer-link).
function getClientCertThumbprint(req) {
  try {
    const sock = req.socket;
    if (!sock || typeof sock.getPeerCertificate !== 'function') return null;
    const cert = sock.getPeerCertificate();
    if (!cert || !cert.fingerprint256) return null;
    return cert.fingerprint256.split(':').join('').toLowerCase();
  } catch (err) {
    return null;
  }
}

// Apply an inbound peer epoch signal (heartbeat): adopt the monotonic epoch. The
// role-reconcile that steps down a now-superseded active is failover behavior and
// is added here with gd-ha-failover (PR-3).
function applyPeerLeaseSignal(db, body) {
  const r = gdHaLease.recordPeerHeartbeat(db, body.epoch, body.leaseExpiresAt);
  return { ok: r.ok !== false, epoch: gdHaLease.currentEpoch(db), reason: r.reason || null };
}

// --- peer endpoints (pinned mTLS via requirePeerCert in index.js) --------

peerRouter.post('/replicate', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const result = gdHaReplication.applyBatch(db, req.body);
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
    gdHaPairing.receiveSharedMaterial(db, req.body.envelope);
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
    const result = gdHaPairing.receiveBaseline(db, req.body.snapshot, { leaseTtlSec: cfg.leaseTtlSec });
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

// --- pair-init (token-authenticated; NOT cert-pinned) --------------------

pairInitRouter.post('/', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const thumb = getClientCertThumbprint(req);
    const cfg = loadHaConfig(db);
    const result = gdHaPairing.respondToPairInit(db, req.body, thumb, { selfEndpoint: cfg.selfEndpoint });
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

module.exports = {
  configRouter: configRouter,
  pairInitRouter: pairInitRouter,
  peerRouter: peerRouter,
};

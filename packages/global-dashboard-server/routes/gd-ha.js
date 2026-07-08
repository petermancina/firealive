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
const deploymentMode = require('../services/gd-deployment-mode');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');

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

// Append a GD audit entry on a short-lived connection (the GD route audit
// pattern). Never lets logging change an operation outcome.
function auditLog(userId, eventType, detail, ip) {
  let adb = null;
  try {
    adb = getDb();
    appendGdAuditEntry(adb, { userId: userId, eventType: eventType, detail: detail, ip: ip });
  } catch (err) {
    console.error('gd-ha route audit append failed:', err && err.message ? err.message : err);
  } finally {
    if (adb) { try { adb.close(); } catch (closeErr) { /* ignore */ } }
  }
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

// --- config / status / pair (operator control; mounted behind authMiddleware
//     (['ciso']) + the config-lock in index.js). Mutations are ciso-gated at the
//     mount, so no per-handler role check is repeated here. --------------------

configRouter.get('/config', (req, res) => {
  const db = getDb();
  try {
    res.json(loadHaConfig(db));
  } catch (loadErr) {
    res.status(500).json({ error: 'Failed to load HA config' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

configRouter.put('/config', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const merged = Object.assign({}, DEFAULT_HA_CONFIG, req.body);
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('ha_config', ?)").run(JSON.stringify(merged));
    auditLog(actor(req), 'HA_CONFIG_UPDATED', 'Mode: active_passive, enabled: ' + (merged.enabled ? 'yes' : 'no'), req.ip);
    // Apply the new intervals live: re-register the HA scheduler ticks so a
    // changed heartbeat/replication interval takes effect without a restart.
    try { require('../services/gd-backup-scheduler').gdBackupScheduler.reloadHaJobs(); } catch (reloadErr) { /* scheduler not running; next start reads the saved config */ }
    res.json({ success: true });
  } catch (saveErr) {
    res.status(500).json({ error: 'Failed to save HA config' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

configRouter.get('/status', (req, res) => {
  const db = getDb();
  try {
    const cfg = loadHaConfig(db);
    const node = db.prepare("SELECT role FROM gd_ha_node WHERE id = 'self'").get() || { role: 'standalone' };
    const lease = db.prepare("SELECT epoch, holder, lease_expires_at, last_heartbeat_at FROM gd_ha_lease WHERE id = 'current'").get() || { epoch: 0, holder: 'none' };
    const peer = db.prepare("SELECT peer_endpoint, peer_anchor_fingerprint, peer_cert_fingerprint, status, paired_at FROM gd_ha_peer LIMIT 1").get() || null;
    const rep = db.prepare("SELECT lag_seconds, last_applied_lsn, last_shipped_lsn, last_acked_lsn, baseline_at, last_apply_at FROM gd_ha_replication_state WHERE id = 'self'").get() || {};

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

// Standby side: issue a single-use pairing token (the opaque bootstrap the
// operator carries to the active). generatePairingToken is a twinned service
// export the MC leaves unrouted; the GD exposes it here so pairing can be
// initiated end-to-end.
configRouter.post('/pairing-token', (req, res) => {
  const db = getDb();
  try {
    const existing = db.prepare("SELECT status FROM gd_ha_peer WHERE status = 'paired' LIMIT 1").get();
    if (existing) {
      return res.status(409).json({ error: 'already paired with a peer' });
    }
    const cfg = loadHaConfig(db);
    const result = gdHaPairing.generatePairingToken(db, cfg.pairingTokenTtlSec);
    auditLog(actor(req), 'HA_PAIRING_TOKEN_ISSUED', 'One-time pairing token issued (this node standby)', req.ip);
    res.json({ bootstrap: result.bootstrap, expiresAt: result.expiresAt });
  } catch (tokErr) {
    res.status(500).json({ error: 'Failed to generate pairing token' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

// Active side: initiate pairing with the standby's endpoint + one-time token.
configRouter.post('/pair', requireObjectBody, async (req, res) => {
  const peerEndpoint = req.body.peerEndpoint;
  const token = req.body.token;
  if (typeof peerEndpoint !== 'string' || !peerEndpoint || typeof token !== 'string' || !token) {
    return res.status(400).json({ error: 'peerEndpoint and token are required' });
  }
  const db = getDb();
  try {
    const existing = db.prepare("SELECT status FROM gd_ha_peer WHERE status = 'paired' LIMIT 1").get();
    if (existing) {
      return res.status(409).json({ error: 'already paired with a peer' });
    }
    const cfg = loadHaConfig(db);
    auditLog(actor(req), 'HA_PAIR_INITIATED', 'Pairing with ' + peerEndpoint, req.ip);
    const result = await gdHaPairing.beginPairing(db, peerEndpoint, token, {
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

module.exports = {
  configRouter: configRouter,
  pairInitRouter: pairInitRouter,
  peerRouter: peerRouter,
};

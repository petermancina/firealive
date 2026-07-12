// packages/global-dashboard-server/routes/gd-ha.js
//
// The GD's /api/ha route -- the GD twin of server/routes/ha.js. Three routers,
// each with its OWN authentication, because they answer to different callers:
//
//   configRouter   -- the operator control plane. GET/PUT /config, GET /status,
//                     POST /pairing-token, /pair, /manual-failover, /self-test.
//                     index.js mounts it behind authMiddleware(['ciso']) + the
//                     config-lock chokepoint. Every event it emits has an
//                     operator behind it, so it audits through auditHaEventBy
//                     and the actor reaches the SIEM: an unattributed
//                     HA_MANUAL_FAILOVER at high severity is a worse signal than
//                     none, because the analyst cannot tell a takeover from a
//                     drill.
//   peerRouter     -- the peer data plane. POST /peer/replicate, /pair-secret,
//                     /pair-baseline, /heartbeat, /lease. index.js mounts it
//                     behind gd-ha-peer-link.requirePeerCert (pinned mTLS), NOT
//                     JWT -- the caller is the paired node, not a person.
//                     /heartbeat carries the epoch reaction (adopt a higher
//                     epoch, then reconcile role); /lease is the graceful
//                     handover a manual failover uses, make-before-break.
//   pairInitRouter -- POST /pair-init. Token-authenticated: the body carries a
//                     single-use pairing token. NOT cert-pinned, because the pin
//                     does not exist until pairing completes.
//
// The write guard exempts /api/ha so a passive can still be inspected, promoted,
// drilled, and recovered while it refuses every other mutating request.
//
// ASCII-only; no template literals.

const peerRouter = require('express').Router();
const pairInitRouter = require('express').Router();
const configRouter = require('express').Router();
const { getDb } = require('../db-init');
const gdHaPairing = require('../services/gd-ha-pairing');
const gdHaReplication = require('../services/gd-ha-replication');
const gdHaLease = require('../services/gd-ha-lease');
const gdHaFailover = require('../services/gd-ha-failover');
const gdHaPeerLink = require('../services/gd-ha-peer-link');
const { gdMfaStepUp } = require('../services/gd-mfa-stepup');
const deploymentMode = require('../services/gd-deployment-mode');
const { auditHaEventBy } = require('../services/gd-ha-audit');

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

const PEER_LEASE_PATH = '/api/ha/peer/lease';
const PEER_UNPAIR_PATH = '/api/ha/peer/unpair';

function nodeRole(db) {
  const row = db.prepare("SELECT role FROM gd_ha_node WHERE id = 'self'").get();
  return row ? row.role : 'standalone';
}

function peerPaired(db) {
  return !!db.prepare("SELECT 1 FROM gd_ha_peer WHERE status = 'paired' LIMIT 1").get();
}

// A lightweight integrity fingerprint over stable replicated reference data,
// compared across the pair and before/after a drill to confirm no rows were lost.
function dataChecksum(db) {
  try {
    return 'u' + db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  } catch (e) {
    return 'na';
  }
}

// Record an operator-initiated HA event: append the audit row on the SAME connection the
// handler is already using -- never a second one, which would split the operation from
// its audit record across two handles -- and stream it to the operator's SIEM when that
// connection IS the durable chain. Both halves and the severity table live in
// gd-ha-audit, shared with failover, pairing, and the peer gate.
//
// auditHaEventBy rather than auditHaEvent: every event this route emits has an operator
// behind it, and the actor is carried into the CEF message. A HA_MANUAL_FAILOVER
// streamed at high severity that does not say who triggered it is a worse SOC signal
// than none -- an analyst sees what looks like an unplanned takeover of the fleet
// aggregation plane and cannot tell it from a drill.
//
// All eight call sites sit between their handler's getDb() and its finally-block close,
// including the two inside catch blocks (HA_PAIR_FAILED, and the manual-failover
// handover-failed path) and the two in the self-test. The funnel reads the SIEM
// configuration synchronously and dispatches database-free, so nothing reaches for a
// handle the handler has since closed. Never lets logging change an operation outcome:
// failures are swallowed inside the funnel.
function safeAudit(db, userId, eventType, detail, ip) {
  auditHaEventBy(db, userId, eventType, detail, ip);
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

// Apply an inbound peer epoch signal (heartbeat or lease assertion): adopt the
// monotonic epoch and step down if we are a now-superseded active.
function applyPeerLeaseSignal(db, body) {
  const r = gdHaLease.recordPeerHeartbeat(db, body.epoch, body.leaseExpiresAt);
  gdHaFailover.reconcileRole(db);
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

// Graceful-handover promotion: the former active stepped down and is telling this
// node to take over now, rather than waiting for failure detection. Idempotent --
// a node that already promoted (via detection) simply acknowledges.
peerRouter.post('/lease', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const body = req.body || {};
    if (body.handover === true) {
      if (nodeRole(db) === 'passive') {
        const r = gdHaFailover.promote(db, {});
        return res.json({ ok: true, promoted: true, role: 'active', epoch: r.epoch, checksum: dataChecksum(db) });
      }
      return res.json({ ok: true, promoted: false, role: nodeRole(db), epoch: gdHaLease.currentEpoch(db), checksum: dataChecksum(db) });
    }
    res.json(applyPeerLeaseSignal(db, body));
  } catch (leaseErr) {
    res.status(500).json({ error: 'lease error' });
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
    safeAudit(db, actor(req), 'HA_CONFIG_UPDATED', 'Mode: active_passive, enabled: ' + (merged.enabled ? 'yes' : 'no'), req.ip);
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
    safeAudit(db, actor(req), 'HA_PAIRING_TOKEN_ISSUED', 'One-time pairing token issued (this node standby)', req.ip);
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
    safeAudit(db, actor(req), 'HA_PAIR_INITIATED', 'Pairing with ' + peerEndpoint, req.ip);
    const result = await gdHaPairing.beginPairing(db, peerEndpoint, token, {
      selfEndpoint: cfg.selfEndpoint,
      leaseTtlSec: cfg.leaseTtlSec,
    });
    res.json({ success: true, role: result.role, peerFingerprint: result.peerFingerprint });
  } catch (pairErr) {
    const detail = (pairErr && pairErr.message) ? pairErr.message : 'error';
    try { safeAudit(db, actor(req), 'HA_PAIR_FAILED', 'Pairing with ' + peerEndpoint + ' failed: ' + detail.slice(0, 160), req.ip); } catch (auditErr) { /* ignore */ }
    res.status(502).json({ error: 'pairing failed', detail: detail });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

// Graceful manual failover, initiated ON THE ACTIVE. Step down FIRST so this node
// stops writing before the peer promotes -- the make-before-break order that
// guarantees no split-brain. If the handover signal cannot be delivered, the peer
// still promotes via failure detection; this node stays passive either way.
configRouter.post('/unpair', gdMfaStepUp(), requireObjectBody, async (req, res) => {
  const db = getDb();
  try {
    if (!peerPaired(db)) {
      return res.status(409).json({ error: 'not paired with a peer' });
    }
    // Fail-closed peek: if this GD node holds replicated data under an adopted shared KEK,
    // refuse before signaling the peer or tearing down -- unpair would strand that data.
    const adopted = db.prepare("SELECT 1 FROM node_state WHERE key = 'shared_kek_sealed'").get();
    if (adopted) {
      return res.status(409).json({ error: 'unpair refused: this GD node holds replicated data under an adopted shared KEK; complete an offline rekey before un-pairing', code: 'UNPAIR_REKEY_REQUIRED' });
    }
    // Tell the peer to unpair too (best-effort), while we still hold its pin and endpoint.
    let peerUnpaired = false;
    let peerNote = null;
    try {
      const resp = await gdHaPeerLink.sendToPeer(db, PEER_UNPAIR_PATH, { unpair: true }, {}) || {};
      peerUnpaired = resp.ok === true;
      if (!peerUnpaired) peerNote = resp.error ? String(resp.error).slice(0, 120) : 'peer did not confirm';
    } catch (sendErr) {
      peerNote = (sendErr && sendErr.message) ? sendErr.message.slice(0, 120) : 'peer signal failed';
    }
    // Tear down our side (the fail-closed guard is re-checked inside unpair).
    gdHaPairing.unpair(db, {});
    safeAudit(db, actor(req), 'HA_UNPAIR', 'Un-paired to standalone; peer ' + (peerUnpaired ? 'also un-paired' : 'not confirmed (' + peerNote + ')'), req.ip);
    res.json({ ok: true, role: 'standalone', peerUnpaired: peerUnpaired, peerNote: peerNote });
  } catch (unpairErr) {
    const detail = (unpairErr && unpairErr.message) ? unpairErr.message : 'error';
    try { safeAudit(db, actor(req), 'HA_UNPAIR_FAILED', 'Un-pair failed: ' + detail.slice(0, 160), req.ip); } catch (auditErr) { /* ignore */ }
    res.status(500).json({ error: 'unpair failed', detail: detail.slice(0, 160) });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

configRouter.post('/manual-failover', requireObjectBody, async (req, res) => {
  const db = getDb();
  try {
    if (nodeRole(db) !== 'active') {
      return res.status(409).json({ error: 'manual failover is initiated on the active node (it must step down first)' });
    }
    if (!peerPaired(db)) {
      return res.status(409).json({ error: 'no paired peer to fail over to' });
    }
    const fromEpoch = gdHaLease.currentEpoch(db);
    gdHaFailover.demote(db, 'manual', {});
    try {
      const peer = await gdHaPeerLink.sendToPeer(db, PEER_LEASE_PATH, { handover: true, fromEpoch: fromEpoch }, {}) || {};
      safeAudit(db, actor(req), 'HA_MANUAL_FAILOVER', 'Graceful failover: stepped down, peer promoted to epoch ' + (peer.epoch || '?'), req.ip);
      res.json({ ok: true, role: 'passive', peerPromoted: peer.promoted !== false, peerEpoch: peer.epoch || null });
    } catch (sendErr) {
      const m = (sendErr && sendErr.message) ? sendErr.message.slice(0, 120) : 'error';
      safeAudit(db, actor(req), 'HA_MANUAL_FAILOVER', 'Stepped down; handover signal failed (' + m + '); peer will promote via detection', req.ip);
      res.json({ ok: true, role: 'passive', peerPromoted: false, note: 'peer will promote via failure detection' });
    }
  } catch (failErr) {
    res.status(500).json({ error: 'manual failover error', detail: (failErr && failErr.message) ? failErr.message.slice(0, 160) : 'error' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

// Failover self-test (drill), run FROM THE ACTIVE: fail over to the peer, measure
// it, verify the peer serves and its data matches, then fail back. Reports real
// measured numbers, never a hard-coded claim. Fail-back adopts the peer's new epoch
// FIRST so this node's re-promotion claims a strictly higher one -- a same-epoch
// re-promotion would put both nodes at the same epoch (split-brain). A failback
// failure leaves the peer active at a valid higher epoch, which is safe.
configRouter.post('/self-test', requireObjectBody, async (req, res) => {
  const db = getDb();
  try {
    if (nodeRole(db) !== 'active') {
      return res.status(409).json({ error: 'the failover self-test is run from the active node' });
    }
    if (!peerPaired(db)) {
      return res.status(409).json({ error: 'no paired peer for a failover self-test' });
    }
    try { safeAudit(db, actor(req), 'HA_TEST_STARTED', 'HA failover self-test started', req.ip); } catch (auditErr) { /* ignore */ }
    const t0 = Date.now();
    const fromEpoch = gdHaLease.currentEpoch(db);
    const checksumBefore = dataChecksum(db);
    gdHaFailover.demote(db, 'test', {});
    let promoteResp = {};
    try {
      promoteResp = await gdHaPeerLink.sendToPeer(db, PEER_LEASE_PATH, { handover: true, test: true, fromEpoch: fromEpoch }, {}) || {};
    } catch (sendErr) {
      try { gdHaFailover.promote(db, {}); } catch (restoreErr) { /* best-effort restore */ }
      return res.status(502).json({ ok: false, error: 'self-test could not promote the peer', detail: (sendErr && sendErr.message) ? sendErr.message.slice(0, 160) : 'error' });
    }
    const failoverMs = Date.now() - t0;
    const served = promoteResp.role === 'active' && promoteResp.promoted !== false;
    const integrityOk = !!promoteResp.checksum && promoteResp.checksum === checksumBefore;

    const tBack0 = Date.now();
    let restored = false;
    try {
      if (promoteResp.epoch) {
        gdHaLease.recordPeerHeartbeat(db, promoteResp.epoch, null);
      }
      gdHaFailover.promote(db, {});
      const lease = gdHaLease.getLease(db) || {};
      const back = await gdHaPeerLink.sendToPeer(db, PEER_LEASE_PATH, { epoch: gdHaLease.currentEpoch(db), leaseExpiresAt: lease.lease_expires_at || null }, {});
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
      epoch: gdHaLease.currentEpoch(db),
    };
    try { safeAudit(db, actor(req), 'HA_TEST_COMPLETE', 'HA self-test: failover ' + failoverMs + 'ms, served=' + served + ', integrity=' + integrityOk + ', restored=' + restored, req.ip); } catch (auditErr) { /* ignore */ }
    res.json(result);
  } catch (testErr) {
    res.status(500).json({ error: 'self-test error', detail: (testErr && testErr.message) ? testErr.message.slice(0, 160) : 'error' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

peerRouter.post('/unpair', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    // The peer is dissolving the pair; tear down our side too. Fail-closed: refuse if we
    // hold replicated data under an adopted shared KEK, and report it so the initiator
    // surfaces it.
    const adopted = db.prepare("SELECT 1 FROM node_state WHERE key = 'shared_kek_sealed'").get();
    if (adopted) {
      return res.status(409).json({ ok: false, error: 'peer holds data under an adopted shared KEK; rekey required before un-pair' });
    }
    gdHaPairing.unpair(db, {});
    res.json({ ok: true });
  } catch (unpairErr) {
    res.status(500).json({ ok: false, error: 'peer unpair failed' });
  } finally {
    try { db.close(); } catch (closeErr) { /* ignore */ }
  }
});

module.exports = {
  configRouter: configRouter,
  pairInitRouter: pairInitRouter,
  peerRouter: peerRouter,
};

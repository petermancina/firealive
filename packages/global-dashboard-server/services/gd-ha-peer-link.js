// FIREALIVE GLOBAL DASHBOARD -- HA peer link (B6d)
//
// The GD twin of server/services/ha/ha-peer-link.js. The mutually-authenticated
// mTLS transport between the two paired GD nodes, plus the inbound gate that
// protects /api/ha/peer/*.
//
// Each node presents its TLS server certificate -- the same one its HTTPS
// listener serves, persisted at <data>/gd-server-tls.crt|key -- as its mTLS
// client certificate when it connects to the peer. At pairing each node records
// the peer's CA certificate (gd_ha_peer.peer_ca_pem) and its exact leaf
// thumbprint (gd_ha_peer.peer_cert_fingerprint); because a node serves and
// presents the SAME certificate, one pinned CA + thumbprint covers both directions.
//
//   Outbound (sendToPeer): opens a fresh TLS connection (agent:false) that
//   validates the peer's chain against the pinned CA (rejectUnauthorized:true)
//   and pins the exact leaf by fingerprint in checkServerIdentity. The peer
//   certificate is issued by the peer's own internal CA and its CN does not
//   match the dialed host, so the fingerprint -- not the hostname -- is the
//   identity check. Then POSTs framed JSON and returns the parsed response.
//   Inbound (requirePeerCert): a route gate (no JWT) that admits a request only
//   if the presented client-cert thumbprint matches the pinned peer fingerprint;
//   otherwise 401 + an HA_PEER_REJECTED audit event.
//
// The peer-link pins in one self-consistent format -- lowercase-hex fingerprint256
// -- used by the pin, the outbound identity check, and the inbound gate. This is
// independent of the GD device-cert x5t#S256 thumbprint used elsewhere.
//
// ASCII-only; no template literals.

const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DB_PATH, getDb } = require('../db-init');
const { appendGdAuditEntry } = require('./gd-audit-chain');

const DEFAULT_TIMEOUT_MS = 15000;

function normalizeThumb(fp256) {
  return (typeof fp256 === 'string' && fp256) ? fp256.split(':').join('').toLowerCase() : null;
}

// The presented mTLS client-cert thumbprint for the inbound gate, in the peer-
// link's pin format (lowercase-hex fingerprint256), matching checkServerIdentity.
function getClientCertThumbprint(req) {
  try {
    const sock = req.socket;
    if (!sock || typeof sock.getPeerCertificate !== 'function') return null;
    const cert = sock.getPeerCertificate();
    if (!cert || !cert.fingerprint256) return null;
    return normalizeThumb(cert.fingerprint256);
  } catch (err) {
    return null;
  }
}

// Append a GD audit entry on its own short-lived connection (the GD route audit
// pattern). Never lets logging change a gate decision.
function auditLog(userId, eventType, detail, ip) {
  let adb = null;
  try {
    adb = getDb();
    appendGdAuditEntry(adb, { userId: userId, eventType: eventType, detail: detail, ip: ip });
  } catch (err) {
    console.error('gd-ha-peer-link audit append failed:', err && err.message ? err.message : err);
  } finally {
    if (adb) { try { adb.close(); } catch (closeErr) { /* ignore */ } }
  }
}

// The local node's TLS server certificate + key, reused as the mTLS client
// identity. Read fresh each call so a reconciled certificate is picked up.
function localTlsMaterial() {
  const dataDir = path.dirname(DB_PATH);
  const certPath = path.join(dataDir, 'gd-server-tls.crt');
  const keyPath = path.join(dataDir, 'gd-server-tls.key');
  return { cert: fs.readFileSync(certPath, 'utf8'), key: fs.readFileSync(keyPath, 'utf8') };
}

// The local certificate thumbprint (what the peer pins for this node). Used by
// gd-ha-pairing to advertise this node's identity. Returns lowercase hex SHA-256.
function localCertThumbprint() {
  const x = new crypto.X509Certificate(localTlsMaterial().cert);
  return normalizeThumb(x.fingerprint256);
}

function getPeer(db) {
  return db.prepare("SELECT peer_endpoint, peer_cert_fingerprint, peer_ca_pem, status FROM gd_ha_peer WHERE status = 'paired' LIMIT 1").get();
}

// Outbound: POST JSON to peer_endpoint + pathSuffix over pinned mTLS. Resolves
// with the parsed JSON body; rejects on pin mismatch, transport error, timeout,
// or a non-2xx status.
function sendToPeer(db, pathSuffix, payload, opts) {
  return new Promise(function (resolve, reject) {
    const peer = getPeer(db);
    if (!peer) {
      reject(new Error('gd-ha-peer-link: no paired peer'));
      return;
    }
    if (!peer.peer_ca_pem) {
      reject(new Error('gd-ha-peer-link: peer CA certificate not pinned (re-pair required)'));
      return;
    }
    let base;
    try {
      base = new URL(peer.peer_endpoint);
    } catch (parseErr) {
      reject(new Error('gd-ha-peer-link: invalid peer_endpoint'));
      return;
    }
    let mat;
    try {
      mat = localTlsMaterial();
    } catch (matErr) {
      reject(new Error('gd-ha-peer-link: local TLS material unavailable: ' + matErr.message));
      return;
    }
    const pinned = (peer.peer_cert_fingerprint || '').toLowerCase();
    const body = Buffer.from(JSON.stringify(payload || {}), 'utf8');
    const timeout = (opts && opts.timeoutMs) || DEFAULT_TIMEOUT_MS;

    // Validate the chain against the peer's pinned CA (rejectUnauthorized:true),
    // then pin the exact leaf by fingerprint in checkServerIdentity. The peer
    // certificate is issued by the peer node's own internal CA and its CN does
    // not match the dialed host, so the fingerprint -- not the hostname -- is the
    // identity check.
    const reqOpts = {
      host: base.hostname,
      port: base.port || 443,
      path: base.pathname.replace(/\/$/, '') + pathSuffix,
      method: 'POST',
      cert: mat.cert,
      key: mat.key,
      ca: [peer.peer_ca_pem],
      rejectUnauthorized: true,
      checkServerIdentity: function (host, cert) {
        const got = (cert && cert.fingerprint256) ? normalizeThumb(cert.fingerprint256) : null;
        if (!got || !pinned || got !== pinned) {
          return new Error('gd-ha-peer-link: peer certificate fingerprint mismatch');
        }
        return undefined;
      },
      agent: false, // fresh connection; no pooled socket
      timeout: timeout,
      headers: {
        'content-type': 'application/json',
        'content-length': body.length,
      },
    };

    const req = https.request(reqOpts, function (res) {
      const chunks = [];
      res.on('data', function (chunk) { chunks.push(chunk); });
      res.on('end', function () {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error('gd-ha-peer-link: peer returned HTTP ' + res.statusCode + ' ' + text.slice(0, 200)));
          return;
        }
        try {
          resolve(text ? JSON.parse(text) : {});
        } catch (jsonErr) {
          reject(new Error('gd-ha-peer-link: malformed JSON from peer'));
        }
      });
    });

    req.on('timeout', function () { req.destroy(new Error('gd-ha-peer-link: peer link timeout')); });
    req.on('error', function (err) { reject(err); });
    // TLS validation (chain + fingerprint pin) happens during the handshake, so
    // the body only leaves this node after the peer certificate is verified.
    req.write(body);
    req.end();
  });
}

// A sendFn(payload) bound to a peer path, for gd-ha-replication.shipOnce and the
// heartbeat/lease senders.
function peerSender(db, pathSuffix, opts) {
  return function (payload) {
    return sendToPeer(db, pathSuffix, payload, opts);
  };
}

// Inbound gate for /api/ha/peer/*: admit only a request presenting the pinned
// peer client certificate. No JWT. getDbFn injects the route's db getter.
function requirePeerCert(getDbFn) {
  return function (req, res, next) {
    let db = null;
    try {
      db = getDbFn();
      const peer = getPeer(db);
      const thumb = getClientCertThumbprint(req);
      const pinned = peer ? (peer.peer_cert_fingerprint || '').toLowerCase() : null;
      try { db.close(); } catch (closeErr) { /* ignore */ }
      db = null;
      if (!peer || !thumb || !pinned || thumb !== pinned) {
        try {
          auditLog(null, 'HA_PEER_REJECTED',
            'Peer link request with ' + (thumb ? 'unrecognized' : 'absent') + ' client certificate', req.ip);
        } catch (auditErr) { /* never let logging change the gate decision */ }
        return res.status(401).json({ error: 'peer authentication failed' });
      }
      return next();
    } catch (err) {
      try { if (db) db.close(); } catch (closeErr) { /* ignore */ }
      try { auditLog(null, 'HA_PEER_REJECTED', 'Peer link gate error', req.ip); } catch (auditErr) { /* ignore */ }
      return res.status(401).json({ error: 'peer authentication failed' });
    }
  };
}

module.exports = {
  normalizeThumb,
  localTlsMaterial,
  localCertThumbprint,
  sendToPeer,
  peerSender,
  requirePeerCert,
};

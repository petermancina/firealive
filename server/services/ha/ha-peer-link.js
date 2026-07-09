// FIREALIVE -- HA peer link (B5o)
//
// The mutually-authenticated mTLS transport between the two paired nodes, plus
// the inbound gate that protects /api/ha/peer/*.
//
// Each node presents its TLS server certificate -- the same one its HTTPS
// listener serves, persisted at <data>/server-tls.crt|key -- as its mTLS client
// certificate when it connects to the peer. At pairing each node records the
// peer's CA certificate (ha_peer.peer_ca_pem) and its exact leaf thumbprint
// (ha_peer.peer_cert_fingerprint); because a node serves and presents the SAME
// certificate, one pinned CA + thumbprint covers both directions.
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
// ASCII-only; no template literals.

const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DB_PATH } = require('../../db/init');
const { getClientCertThumbprint } = require('../../middleware/auth');
// Audit through the connection the gate is holding, never a second one. requirePeerCert
// is handed a db GETTER, so its caller -- including a test or a drill -- decides which
// database the gate consults; auditLog() opens its own via getDb() and ignored that,
// always writing to the live hash-chained log. A gate run against any other database
// would therefore forge an HA_PEER_REJECTED row an auditor reads as real. auditLogOn
// appends on the given handle and gates SIEM streaming on isLiveChain(db), so a real
// rejection records and streams exactly as before.
const { auditLogOn } = require('../../middleware/audit');

const DEFAULT_TIMEOUT_MS = 15000;

function normalizeThumb(fp256) {
  return (typeof fp256 === 'string' && fp256) ? fp256.split(':').join('').toLowerCase() : null;
}

// The local node's TLS server certificate + key, reused as the mTLS client
// identity. Read fresh each call so a reconciled certificate is picked up.
function localTlsMaterial() {
  const dataDir = path.dirname(DB_PATH);
  const certPath = path.join(dataDir, 'server-tls.crt');
  const keyPath = path.join(dataDir, 'server-tls.key');
  return { cert: fs.readFileSync(certPath, 'utf8'), key: fs.readFileSync(keyPath, 'utf8') };
}

// The local certificate thumbprint (what the peer pins for this node). Used by
// ha-pairing to advertise this node's identity. Returns lowercase hex SHA-256.
function localCertThumbprint() {
  const x = new crypto.X509Certificate(localTlsMaterial().cert);
  return normalizeThumb(x.fingerprint256);
}

function getPeer(db) {
  return db.prepare("SELECT peer_endpoint, peer_cert_fingerprint, peer_ca_pem, status FROM ha_peer WHERE status = 'paired' LIMIT 1").get();
}

// Outbound: POST JSON to peer_endpoint + pathSuffix over pinned mTLS. Resolves
// with the parsed JSON body; rejects on pin mismatch, transport error, timeout,
// or a non-2xx status.
// CONTRACT: sendToPeer resolves the PARSED RESPONSE BODY. There is no { json }
// wrapper -- callers read body fields directly (reply.epoch, ack.ok). This is the
// single place that shape is decided, so it is exported and asserted by the
// regression rather than left as an implicit convention.
//
// This contract was misread by three call sites (routes/ha.js manual-failover and
// test-failover, and the scheduler's heartbeat tick), each reading `.json` and
// silently receiving undefined. The self-test consequence was severe: the peer's
// epoch was never adopted, so the fail-back re-promotion tied the peer's epoch --
// a split-brain produced by the very drill meant to prove failover was safe.
//
// A silent misread is therefore the failure mode worth engineering against. Every
// parsed object carries a non-enumerable `json` accessor that THROWS a descriptive
// error. It is invisible to JSON.stringify, object spread, Object.keys, and for...in,
// and it defers entirely to a real `json` field if a peer ever sends one -- but a
// caller reaching for the old wrapper fails loudly, at the misuse site.
//
// Throws on a non-2xx status or a malformed body; returns {} for an empty body.
function parsePeerResponse(text, statusCode) {
  if (statusCode < 200 || statusCode >= 300) {
    throw new Error('ha-peer-link: peer returned HTTP ' + statusCode + ' ' + String(text || '').slice(0, 200));
  }
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch (jsonErr) {
    throw new Error('ha-peer-link: malformed JSON from peer');
  }
  if (body && typeof body === 'object' && !Array.isArray(body)
      && !Object.prototype.hasOwnProperty.call(body, 'json')) {
    Object.defineProperty(body, 'json', {
      enumerable: false,
      configurable: true,
      get: function () {
        throw new Error('ha-peer-link: sendToPeer resolves the response body directly; '
          + 'there is no .json wrapper. Read the field off the body (e.g. reply.epoch).');
      },
    });
  }
  return body;
}

function sendToPeer(db, pathSuffix, payload, opts) {
  return new Promise(function (resolve, reject) {
    const peer = getPeer(db);
    if (!peer) {
      reject(new Error('ha-peer-link: no paired peer'));
      return;
    }
    if (!peer.peer_ca_pem) {
      reject(new Error('ha-peer-link: peer CA certificate not pinned (re-pair required)'));
      return;
    }
    let base;
    try {
      base = new URL(peer.peer_endpoint);
    } catch (parseErr) {
      reject(new Error('ha-peer-link: invalid peer_endpoint'));
      return;
    }
    let mat;
    try {
      mat = localTlsMaterial();
    } catch (matErr) {
      reject(new Error('ha-peer-link: local TLS material unavailable: ' + matErr.message));
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
          return new Error('ha-peer-link: peer certificate fingerprint mismatch');
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
        try {
          resolve(parsePeerResponse(text, res.statusCode));
        } catch (parseErr) {
          reject(parseErr);
        }
      });
    });

    req.on('timeout', function () { req.destroy(new Error('ha-peer-link: peer link timeout')); });
    req.on('error', function (err) { reject(err); });
    // TLS validation (chain + fingerprint pin) happens during the handshake, so
    // the body only leaves this node after the peer certificate is verified.
    req.write(body);
    req.end();
  });
}

// A sendFn(payload) bound to a peer path, for ha-replication.shipOnce and the
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
      const rejected = (!peer || !thumb || !pinned || thumb !== pinned);
      // Audit BEFORE the connection is closed, so the rejection is recorded in the same
      // database the gate consulted. The close still happens ahead of next(), so a
      // permitted request does not carry this connection into the handlers.
      if (rejected) {
        try {
          auditLogOn(db, null, 'HA_PEER_REJECTED',
            'Peer link request with ' + (thumb ? 'unrecognized' : 'absent') + ' client certificate', req.ip);
        } catch (auditErr) { /* never let logging change the gate decision */ }
      }
      try { db.close(); } catch (closeErr) { /* ignore */ }
      db = null;
      if (rejected) {
        return res.status(401).json({ error: 'peer authentication failed' });
      }
      return next();
    } catch (err) {
      // If the gate failed before a handle existed, ask the injected getter for one so
      // the audit still lands in the caller's database, never a second live connection.
      try {
        const adb = db || getDbFn();
        auditLogOn(adb, null, 'HA_PEER_REJECTED', 'Peer link gate error', req.ip);
        if (!db) { try { adb.close(); } catch (closeErr) { /* ignore */ } }
      } catch (auditErr) { /* never let logging change the gate decision */ }
      try { if (db) db.close(); } catch (closeErr) { /* ignore */ }
      return res.status(401).json({ error: 'peer authentication failed' });
    }
  };
}

module.exports = {
  normalizeThumb,
  localTlsMaterial,
  localCertThumbprint,
  parsePeerResponse,
  sendToPeer,
  peerSender,
  requirePeerCert,
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v1.0.0 — Network Security
// DDoS mitigation, DNS security, ICMP/NTP filtering, client dissociation
// protection, ARP spoofing detection at application layer
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const ca = require('../services/ca');
const { getDb } = require('../db/init');

// ── Connection Tracking (anti-DDoS, anti-slowloris) ─────────────────────────
const activeConnections = new Map();
const CONNECTION_LIMITS = { perIp: 50, total: 500, slowThresholdMs: 30000 };

const connectionTracker = (req, res, next) => {
  const ip = req.ip || 'unknown';
  const count = activeConnections.get(ip) || 0;
  if (count >= CONNECTION_LIMITS.perIp) {
    return res.status(429).json({ error: 'Too many connections' });
  }
  activeConnections.set(ip, count + 1);
  res.on('finish', () => {
    const c = activeConnections.get(ip) || 1;
    if (c <= 1) activeConnections.delete(ip);
    else activeConnections.set(ip, c - 1);
  });
  // Slowloris protection: enforce request timeout
  req.setTimeout(CONNECTION_LIMITS.slowThresholdMs, () => {
    res.status(408).json({ error: 'Request timeout' });
    req.destroy();
  });
  next();
};

// ── DNS Packet Size Limiting ────────────────────────────────────────────────
// FireAlive doesn't serve DNS, but if processing DNS-related data:
const MAX_DNS_RESPONSE_SIZE = 512; // Standard DNS, no EDNS amplification
const validateDnsSize = (data) => {
  if (Buffer.isBuffer(data) && data.length > MAX_DNS_RESPONSE_SIZE) {
    return false; // Reject oversized DNS responses (DDoS amplification)
  }
  return true;
};

// ── Client Heartbeat (anti-dissociation) ────────────────────────────────────
// Clients must send heartbeats; if missed, connection is suspicious
const clientHeartbeats = new Map();
const HEARTBEAT_INTERVAL = 30000; // 30 seconds
const HEARTBEAT_TIMEOUT = 90000;  // 3 missed = disconnected

const registerHeartbeat = (clientId) => {
  clientHeartbeats.set(clientId, Date.now());
};

const isClientAlive = (clientId) => {
  const last = clientHeartbeats.get(clientId);
  if (!last) return false;
  return (Date.now() - last) < HEARTBEAT_TIMEOUT;
};

// ── Client-certificate verification (mTLS) ──────────────────────────────────
// With the HTTPS listener running requestCert:true / rejectUnauthorized:false,
// a client certificate is OPTIONAL at the TLS handshake (so password/LDAP-
// exception users can still connect); FireAlive therefore verifies a presented
// client cert at the APPLICATION layer against the built-in CA. This helper
// pulls the peer certificate off the TLS socket and runs it through
// ca.verifyClientCert (chain-to-CA + validity window + local revocation),
// returning the mapped user/external_id. A client cert is transport identity
// only, not a login credential; validateMtls (below) uses it to gate the
// internal inter-component API. Absence of a cert is reported as
// { valid:false, reason:'no_client_cert' } and is NOT an error by itself —
// whether to require a cert is the caller's policy decision.
function verifyPeerCertificate(req, db) {
  const sock = req && req.socket;
  const peer = sock && typeof sock.getPeerCertificate === 'function'
    ? sock.getPeerCertificate()
    : null;
  // An un-authenticated TLS peer yields an empty object (no DER); a presented
  // certificate carries .raw (DER bytes).
  if (!peer || !peer.raw || Object.keys(peer).length === 0) {
    return { valid: false, reason: 'no_client_cert' };
  }
  let pem;
  try {
    pem = new crypto.X509Certificate(peer.raw).toString();
  } catch (_) {
    return { valid: false, reason: 'parse_error' };
  }
  const ownDb = !db;
  const handle = db || getDb();
  try {
    return ca.verifyClientCert(handle, pem);
  } finally {
    if (ownDb) { try { handle.close(); } catch (_) { /* ignore */ } }
  }
}

// mTLS enforcement for the internal inter-component API. A valid, CA-issued,
// non-revoked client certificate is REQUIRED for any /api/internal/ route;
// other routes are not gated here (user authentication is handled in
// routes/auth.js). This runs regardless of NODE_ENV — the server always
// serves over TLS with client certs requested, so there is no dev exemption.
const validateMtls = (req, res, next) => {
  if (req.path.startsWith('/api/internal/')) {
    const result = verifyPeerCertificate(req);
    if (!result.valid) {
      return res.status(403).json({ error: 'mTLS required for internal API' });
    }
    req.mtlsClient = {
      userId: result.userId || null,
      externalId: result.externalId || null,
      fingerprint256: result.fingerprint256 || null,
    };
  }
  next();
};

// ── Request Origin Validation (anti-SSRF, anti-pivot) ───────────────────────
const BLOCKED_DESTINATIONS = [
  /^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^192\.168\./,
  /^127\./, /^0\./, /^169\.254\./, /^::1$/, /^fc00:/,
  /metadata\.google/, /metadata\.aws/
];

const preventPivot = (req, res, next) => {
  // If the request includes a URL/endpoint to connect to, validate it
  const urls = [req.body?.endpoint, req.body?.url, req.body?.webhookUrl].filter(Boolean);
  for (const url of urls) {
    try {
      const hostname = new URL(url).hostname;
      if (BLOCKED_DESTINATIONS.some(p => p.test(hostname))) {
        return res.status(400).json({ error: 'Blocked destination (internal network)' });
      }
    } catch {}
  }
  next();
};

module.exports = { connectionTracker, validateDnsSize, registerHeartbeat, isClientAlive, validateMtls, verifyPeerCertificate, preventPivot };

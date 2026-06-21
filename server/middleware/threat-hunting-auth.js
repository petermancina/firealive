// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Feed Gate (three independent factors) (B5m)
//
// Express middleware guarding the threat-hunting feed and TAXII routers. Access
// requires ALL THREE of the following, checked fail-closed in order; there is no
// fallback path:
//   1. a valid mutual-TLS client certificate that chains to THIS deployment's CA,
//      is within its validity window, is present in issued_certs, is not revoked,
//      and carries OU=threat-hunting-consumer;
//   2. a bearer token whose salted SHA-256 hash matches the authorization the
//      certificate is bound to (constant-time compare); and
//   3. a source IP inside that authorization's CIDR allow-list.
//
// Because the TLS listener is requestCert:true + rejectUnauthorized:false (so the
// WebAuthn / first-credential flow can proceed certless), the chain is validated
// HERE via ca.verifyClientCert -- the gate never trusts req.socket.authorized.
//
// Every attempt is written to the append-only, hash-chained access log. The
// precise failing factor is recorded internally but NOT returned to the caller
// (no oracle): all auth-factor failures answer 401, authorization-state failures
// answer 403, both with a generic body. On success the resolved authorization is
// attached as req.threatHuntingAuth and the authorized-access log entry (with the
// result_count and resolved category) is left to the route handler.
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const ca = require('../services/ca');
const registry = require('../services/threat-hunting-registry');
const { appendAccessLog } = require('../services/threat-hunting-access-log');

const CONSUMER_OU = ca.THREAT_HUNTING_CONSUMER_OU;

// ── source-IP matcher (same semantics as the allow-list cache) ───────────────
function normalizeIp(ip) {
  if (typeof ip !== 'string') return '';
  const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return m ? m[1] : ip;
}

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const o = Number(p);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    n = (n * 256) + o;
  }
  return n >>> 0;
}

function ipMatchesEntry(ip, entry) {
  ip = normalizeIp(ip).trim();
  entry = String(entry || '').trim();
  if (!ip || !entry) return false;
  if (entry.indexOf('/') === -1) return ip === normalizeIp(entry);
  const [net, bitsRaw] = entry.split('/');
  const bits = Number(bitsRaw);
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(normalizeIp(net));
  if (ipInt === null || netInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return false;
  }
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (~(0xffffffff >>> bits)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

function ipAllowed(ip, cidrs) {
  return Array.isArray(cidrs) && cidrs.some((c) => ipMatchesEntry(ip, c));
}

// ── certificate subject OU check ─────────────────────────────────────────────
// X509Certificate.subject is newline-separated RDNs (older builds may use ", ").
function subjectHasConsumerOu(subject) {
  if (typeof subject !== 'string' || !CONSUMER_OU) return false;
  const parts = subject.split(/\r?\n|,\s*/);
  for (const p of parts) {
    const m = p.match(/^\s*OU\s*=\s*(.+?)\s*$/i);
    if (m && m[1] === CONSUMER_OU) return true;
  }
  return false;
}

// ── bearer-token extraction (Authorization: Bearer <token>) ──────────────────
function extractBearer(req) {
  const authz = (req.get && req.get('authorization')) || '';
  if (authz && /^Bearer\s+/i.test(authz)) return authz.replace(/^Bearer\s+/i, '').trim();
  return null;
}

// The gate.
function threatHuntingGate(req, res, next) {
  const sourceIp = normalizeIp((req && req.ip) || '');
  const endpoint = String((req && (req.originalUrl || req.path)) || '').slice(0, 256);
  const db = getDb();
  let closed = false;
  const closeDb = () => {
    if (!closed) { closed = true; try { db.close(); } catch (_) { /* ignore */ } }
  };

  // Log the (internally precise) outcome, then answer with a generic body.
  const reject = (status, outcome, ctx) => {
    try {
      appendAccessLog(db, {
        authorization_id: (ctx && ctx.authorizationId) || null,
        consumer_type: (ctx && ctx.consumerType) || null,
        source_ip: sourceIp,
        cert_fingerprint: (ctx && ctx.fingerprint) || null,
        endpoint: endpoint,
        outcome: outcome,
        result_count: null,
      });
    } catch (_) { /* never let logging failure change the gate decision */ }
    closeDb();
    res.status(status).json({ error: 'threat-hunting access denied' });
  };

  try {
    // Factor 1 -- mutual-TLS client certificate.
    const peer = (req.socket && req.socket.getPeerCertificate)
      ? req.socket.getPeerCertificate(true)
      : null;
    if (!peer || !peer.raw || !peer.raw.length) {
      return reject(401, 'rejected_cert', null);
    }
    const verdict = ca.verifyClientCert(db, peer.raw);
    if (!verdict || !verdict.valid) {
      return reject(401, 'rejected_cert', null);
    }
    if (!subjectHasConsumerOu(verdict.subject)) {
      return reject(401, 'rejected_cert', { fingerprint: verdict.fingerprint256 });
    }
    const fp = verdict.fingerprint256;
    const row = registry.findByCertFingerprint(db, fp);
    if (!row) {
      return reject(401, 'rejected_cert', { fingerprint: fp });
    }
    const ctx = { authorizationId: row.id, consumerType: row.consumer_type, fingerprint: fp };
    if (row.enabled !== 1 || row.revoked_at) {
      return reject(403, 'rejected_disabled', ctx);
    }

    // Factor 2 -- bearer token (constant-time).
    const token = extractBearer(req);
    if (!token || !registry.verifyToken(row, token)) {
      return reject(401, 'rejected_token', ctx);
    }

    // Factor 3 -- source IP against the per-authorization allow-list.
    const cidrs = registry.publicAuthorization(row).allowed_cidrs;
    if (!ipAllowed(sourceIp, cidrs)) {
      return reject(403, 'rejected_ip', ctx);
    }

    // All three factors satisfied. Stamp last-access and hand the resolved
    // authorization to the route, which logs the authorized access once it knows
    // the result_count and resolved category.
    registry.touchAccess(db, row.id, sourceIp);
    req.threatHuntingAuth = {
      authorizationId: row.id,
      consumerType: row.consumer_type,
      certFingerprint: fp,
      defaultFormat: row.default_format,
      sourceIp: sourceIp,
      endpoint: endpoint,
    };
    closeDb();
    return next();
  } catch (_) {
    // Fail closed on any unexpected error.
    try {
      appendAccessLog(db, {
        source_ip: sourceIp, endpoint: endpoint, outcome: 'rejected_cert', result_count: null,
      });
    } catch (_e) { /* ignore */ }
    closeDb();
    return res.status(401).json({ error: 'threat-hunting access denied' });
  }
}

module.exports = threatHuntingGate;
module.exports.threatHuntingGate = threatHuntingGate;

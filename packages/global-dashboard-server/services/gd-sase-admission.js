// FIREALIVE GD -- SASE connection admission (B6c PR-4, read-only twin)
//
// Self-protection for sase mode: in connector-tunneled SASE the ZTNA App
// Connector is the ONLY network peer FireAlive should ever see, and the analyst's
// device-bound mTLS is terminated end-to-end inside that tunnel. This gate
// enforces both halves of that contract:
//
//   (a) Dark-app boundary -- the connection's RAW TCP socket peer must be in the
//       operator-declared connector-source allow-list. A peer outside it means
//       FireAlive is reachable off the sanctioned path (the dark-app boundary
//       failed): the connection is refused and a direct_exposure_refused posture
//       event is recorded.
//
//   (b) Passthrough integrity -- a connector-tunneled (raw-TCP, L4) connector never
//       injects an HTTP identity header. One present is positive proof of a
//       clientless / TLS-terminating edge that has stripped the analyst's device
//       certificate; FireAlive refuses it and records passthrough_violation_refused.
//       There is no weak FireAlive: clientless ZTNA is failed closed.
//
// The peer is the RAW socket peer (the connector), never req.ip / X-Forwarded-For
// -- FireAlive has trust-proxy/XFF handling, but the question here is "did this
// arrive via the connector," and the connector is the TCP peer; the analyst's own
// IP, if forwarded, is irrelevant to admission.
//
// Mode-gated: a pure pass-through in bare-metal / virtualized / cloud / sdn /
// unconfigured mode. Mount globally on /api/, after the rate limiter and before
// per-route auth (an unsanctioned origin is turned away before auth work).
//
// Secondary layer: the ZTNA connector is the primary network control and the
// hardware-anchored device mTLS is the primary identity defense, so this gate
// fails OPEN on a transient configuration-read error (it keeps serving rather than
// taking the surface down) and admits while the connector allow-list is
// unconfigured (so a fresh sase deployment is reachable to be configured). Both
// refusal kinds latch the degraded posture the fail-safe gate reads; refusals are
// throttled per source so a flood cannot bloat the log.
//
// IP matching mirrors the SDN admission matcher: IPv4 supports exact and CIDR;
// IPv6 supports exact match (operators list explicit IPv6 connector sources).
//
// Read-only twin of the Regional middleware/sase-admission.js: mode comes from
// gd-deployment-mode (a DB read, mode-cached) rather than app.locals, and the
// connector allow-list and posture go through gd-sase-mode. The dark-app and
// passthrough-integrity logic is verbatim.
//
// ASCII only; no template literals.

const logger = {
  warn: (m, o) => console.warn('[gd-sase-admission] ' + m, o || ''),
  info: (m, o) => console.log('[gd-sase-admission] ' + m, o || ''),
  error: (m, o) => console.error('[gd-sase-admission] ' + m, o || ''),
};
const { getDb } = require('../db-init');
const saseMode = require('./gd-sase-mode');
const deploymentMode = require('./gd-deployment-mode');

const CACHE_TTL_MS = 30 * 1000;
const REFUSAL_THROTTLE_MS = 60 * 1000;
const UNCONFIGURED_WARN_MS = 10 * 60 * 1000;

// Headers an identity-injecting (TLS-terminating / clientless) ZTNA or reverse
// proxy adds to convey the user it authenticated -- the very thing a passthrough
// connector must NOT do. Presence of any is positive proof the analyst's device
// certificate was stripped at the edge. X-Forwarded-For is deliberately NOT here:
// it is a normal hop header, not an identity assertion.
const CLIENTLESS_IDENTITY_HEADERS = [
  'cf-access-authenticated-user-email',
  'cf-access-jwt-assertion',
  'x-forwarded-user',
  'x-forwarded-email',
  'x-authenticated-user',
  'x-auth-request-user',
  'x-auth-request-email',
  'x-auth-request-preferred-username',
  'x-remote-user',
  'x-webauth-user'
];

let connectorCache = { sources: [], loadedAt: 0 };
let modeCache = { isSase: false, loadedAt: 0 };
let lastUnconfiguredWarnAt = 0;
const refusalSeen = new Map(); // (eventType|sourceIp) -> last-recorded timestamp

// Normalize an IPv4-mapped IPv6 address ("::ffff:1.2.3.4") to plain IPv4.
function normalizeIp(ip) {
  if (typeof ip !== 'string') return '';
  const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return m ? m[1] : ip;
}

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (let i = 0; i < parts.length; i++) {
    const o = Number(parts[i]);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    n = (n * 256) + o;
  }
  return n >>> 0;
}

// Match a source IP against one connector-source entry. IPv4: exact + CIDR;
// IPv6: exact match only.
function ipMatchesEntry(ip, entry) {
  ip = normalizeIp(ip).trim().toLowerCase();
  entry = String(entry || '').trim().toLowerCase();
  if (!ip || !entry) return false;
  if (entry.indexOf('/') === -1) return ip === normalizeIp(entry).toLowerCase();
  const slash = entry.split('/');
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(normalizeIp(slash[0]));
  const bits = Number(slash[1]);
  if (ipInt === null || netInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return false;
  }
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (~(0xffffffff >>> bits)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

// Same-host connections (127.0.0.0/8 or ::1) are inherently trusted.
function isLoopback(ip) {
  const n = normalizeIp(ip).trim().toLowerCase();
  if (n === '::1') return true;
  const i = ipv4ToInt(n);
  if (i !== null) {
    return ((i & 0xff000000) >>> 0) === ((0x7f000000) >>> 0);
  }
  return false;
}

// The first clientless/identity-proxy header present on the request, or null.
function clientlessIdentityHeader(req) {
  const h = (req && req.headers) || {};
  for (let i = 0; i < CLIENTLESS_IDENTITY_HEADERS.length; i++) {
    const name = CLIENTLESS_IDENTITY_HEADERS[i];
    const v = h[name];
    if (v !== undefined && v !== null && String(v).length > 0) return name;
  }
  return null;
}

// Refresh the connector-source cache. Fail-safe: on error, keep the last cache
// (a never-loaded cache stays empty, which admits -- the secondary-layer choice).
function refreshConnectorSources() {
  let db;
  try {
    db = getDb();
    const list = saseMode.getConnectorSources(db);
    connectorCache = { sources: Array.isArray(list) ? list : [], loadedAt: Date.now() };
  } catch (err) {
    connectorCache = { sources: connectorCache.sources, loadedAt: Date.now() };
    logger.warn('SASE admission connector-source refresh failed; keeping last-known connector sources', { error: err.message });
  } finally {
    if (db) { try { db.close(); } catch (_e) { /* ignore */ } }
  }
}

function getSources() {
  if (Date.now() - connectorCache.loadedAt > CACHE_TTL_MS) refreshConnectorSources();
  return connectorCache.sources;
}

function recordRefusal(eventType, ip, path, extra) {
  const now = Date.now();
  const key = eventType + '|' + ip;
  const last = refusalSeen.get(key) || 0;
  if (now - last < REFUSAL_THROTTLE_MS) return;
  refusalSeen.set(key, now);
  // Bound the map so a wide source range cannot grow it without limit.
  if (refusalSeen.size > 1024) {
    const cutoff = now - REFUSAL_THROTTLE_MS;
    for (const [k, v] of refusalSeen) { if (v < cutoff) refusalSeen.delete(k); }
  }
  logger.warn('SASE admission refused a connection', { kind: eventType, sourceIp: ip, path: path });
  let db;
  try {
    db = getDb();
    const detail = { sourceIp: ip, path: path };
    if (extra) { const keys = Object.keys(extra); for (let i = 0; i < keys.length; i++) detail[keys[i]] = extra[keys[i]]; }
    saseMode.recordPostureEvent(db, {
      eventType: eventType,
      severity: 'critical',
      detail: detail,
    });
  } catch (err) {
    logger.warn('SASE admission could not record the refusal posture event', { error: err.message });
  } finally {
    if (db) { try { db.close(); } catch (_e) { /* ignore */ } }
  }
}

// The GD reads its deployment mode from the DB (via gd-deployment-mode), not
// app.locals; caching it keeps the per-request gate off the DB in non-sase modes.
function refreshMode() {
  let db;
  try {
    db = getDb();
    modeCache = { isSase: !!deploymentMode.isSase(db), loadedAt: Date.now() };
  } catch (err) {
    modeCache = { isSase: modeCache.isSase, loadedAt: Date.now() };
    logger.warn('SASE admission mode refresh failed; keeping last-known mode', { error: err.message });
  } finally {
    if (db) { try { db.close(); } catch (_e) { /* ignore */ } }
  }
}

function isSaseMode() {
  if (Date.now() - modeCache.loadedAt > CACHE_TTL_MS) refreshMode();
  return modeCache.isSase;
}

function saseAdmission() {
  return function (req, res, next) {
    // Only sase mode admits on the connector perimeter; every other mode is a
    // pass-through.
    if (!isSaseMode()) return next();

    // The dark-app perimeter is enforced against the RAW TCP socket peer (the
    // connector), never req.ip / X-Forwarded-For.
    const peer = normalizeIp((req.socket && req.socket.remoteAddress) || '');
    // Local health checks and diagnostics keep working regardless of the list.
    if (isLoopback(peer)) return next();

    const sources = getSources();
    if (!sources.length) {
      // Unconfigured: admit so the deployment is reachable to be configured.
      const now = Date.now();
      if (now - lastUnconfiguredWarnAt > UNCONFIGURED_WARN_MS) {
        lastUnconfiguredWarnAt = now;
        logger.warn('SASE admission is not configured (no connector sources); admitting all connections until the ZTNA connector allow-list is set');
      }
      return next();
    }

    // (a) Dark-app boundary: the connection must arrive via the declared connector.
    let viaConnector = false;
    for (let i = 0; i < sources.length; i++) {
      if (ipMatchesEntry(peer, sources[i])) { viaConnector = true; break; }
    }
    if (!viaConnector) {
      recordRefusal('direct_exposure_refused', peer, req.path, null);
      return res.status(403).json({ error: 'This connection did not arrive through the declared ZTNA connector and is refused.' });
    }

    // (b) Passthrough integrity: a raw-TCP passthrough connector injects no identity
    // header; one present means a clientless / TLS-terminating edge stripped the
    // analyst's device certificate. Fail closed.
    const idHeader = clientlessIdentityHeader(req);
    if (idHeader) {
      recordRefusal('passthrough_violation_refused', peer, req.path, { identityHeader: idHeader });
      return res.status(403).json({ error: 'A clientless or TLS-terminating ZTNA edge was detected; FireAlive requires connector-tunneled passthrough and refuses this connection.' });
    }

    return next();
  };
}

module.exports = {
  saseAdmission,
  _refreshMode: refreshMode,
  _refreshConnectorSources: refreshConnectorSources,
  _ipMatchesEntry: ipMatchesEntry,
  _clientlessIdentityHeader: clientlessIdentityHeader,
  _cacheTtlMs: CACHE_TTL_MS,
};

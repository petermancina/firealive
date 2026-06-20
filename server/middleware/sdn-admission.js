// FIREALIVE -- SDN connection admission (B5i SDN Mode)
//
// Self-protection for sdn mode (D-B5i-4): FireAlive's own inter-component
// connections (AC <-> MC, MC <-> regional server, MC <-> GD) are admitted only
// from the operator-declared permitted SDN segments. A request arriving from
// outside those segments is refused and audited. This is zero-trust micro-
// segmentation for FireAlive's OWN east-west traffic, layered on the existing
// anchor-pin and device-bound proof-of-possession -- it polices FireAlive's
// doors, never the SDN itself.
//
// Mode-gated: a pure pass-through in bare-metal / virtualized / cloud /
// unconfigured mode. Mount globally on /api/, after the rate limiter and before
// per-route auth (an unpermitted origin is turned away before auth work).
//
// Secondary layer: the SDN's own microsegmentation is the primary control and
// the hardware anchor is the primary identity defense, so this gate fails OPEN
// on a transient configuration-read error (it keeps serving rather than taking
// the surface down) and admits while the permitted list is unconfigured (so a
// fresh sdn deployment is reachable to be configured). Refusals are recorded as
// posture events, throttled per source so a flood cannot bloat the log.
//
// IP matching mirrors the cloud-vuln allow-list matcher: IPv4 supports exact and
// CIDR; IPv6 supports exact match (operators list explicit IPv6 sources or rely
// on the SDN segmentation for IPv6 ranges).
//
// ASCII only; no template literals.

const { logger } = require('../services/logger');
const { getDb } = require('../db/init');
const sdnMode = require('../services/sdn-mode');

const CACHE_TTL_MS = 30 * 1000;
const REFUSAL_THROTTLE_MS = 60 * 1000;
const UNCONFIGURED_WARN_MS = 10 * 60 * 1000;

let segmentCache = { segments: [], loadedAt: 0 };
let lastUnconfiguredWarnAt = 0;
const refusalSeen = new Map(); // sourceIp -> last-recorded timestamp

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

// Match a source IP against one permitted-segment entry. IPv4: exact + CIDR;
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

// Refresh the permitted-segment cache. Fail-safe: on error, keep the last cache
// (a never-loaded cache stays empty, which admits -- the secondary-layer choice).
function refreshSegments() {
  let db;
  try {
    db = getDb();
    const map = sdnMode.getNetworkMap(db);
    const segs = Array.isArray(map.permittedSegments) ? map.permittedSegments : [];
    segmentCache = { segments: segs, loadedAt: Date.now() };
  } catch (err) {
    segmentCache = { segments: segmentCache.segments, loadedAt: Date.now() };
    logger.warn('SDN admission segment refresh failed; keeping last-known permitted segments', { error: err.message });
  } finally {
    if (db) { try { db.close(); } catch (_e) { /* ignore */ } }
  }
}

function getSegments() {
  if (Date.now() - segmentCache.loadedAt > CACHE_TTL_MS) refreshSegments();
  return segmentCache.segments;
}

function recordRefusal(ip, path) {
  const now = Date.now();
  const last = refusalSeen.get(ip) || 0;
  if (now - last < REFUSAL_THROTTLE_MS) return;
  refusalSeen.set(ip, now);
  // Bound the map so a wide source range cannot grow it without limit.
  if (refusalSeen.size > 1024) {
    const cutoff = now - REFUSAL_THROTTLE_MS;
    for (const [k, v] of refusalSeen) { if (v < cutoff) refusalSeen.delete(k); }
  }
  logger.warn('SDN admission refused a connection from a non-permitted segment', { sourceIp: ip, path: path });
  let db;
  try {
    db = getDb();
    sdnMode.recordPostureEvent(db, {
      eventType: 'admission_refused',
      severity: 'warning',
      detail: { sourceIp: ip, path: path },
    });
  } catch (err) {
    logger.warn('SDN admission could not record the refusal posture event', { error: err.message });
  } finally {
    if (db) { try { db.close(); } catch (_e) { /* ignore */ } }
  }
}

function sdnAdmission() {
  return function (req, res, next) {
    let mode;
    try {
      mode = (req.app && req.app.locals && req.app.locals.deploymentMode) || {};
    } catch (_e) {
      mode = {};
    }
    // Only sdn mode admits on segments; every other mode is a pass-through.
    if (!mode.sdn) return next();

    const ip = normalizeIp(req.ip || '');
    // Local health checks and diagnostics keep working regardless of the list.
    if (isLoopback(ip)) return next();

    const segments = getSegments();
    if (!segments.length) {
      // Unconfigured: admit so the deployment is reachable to be configured.
      const now = Date.now();
      if (now - lastUnconfiguredWarnAt > UNCONFIGURED_WARN_MS) {
        lastUnconfiguredWarnAt = now;
        logger.warn('SDN admission is not configured (no permitted segments); admitting all FireAlive connections until segments are set');
      }
      return next();
    }

    for (let i = 0; i < segments.length; i++) {
      if (ipMatchesEntry(ip, segments[i])) return next();
    }

    recordRefusal(ip, req.path);
    return res.status(403).json({ error: 'This connection originates outside the permitted SDN segments and is refused.' });
  };
}

module.exports = { sdnAdmission, _refreshSegments: refreshSegments, _ipMatchesEntry: ipMatchesEntry, _cacheTtlMs: CACHE_TTL_MS };

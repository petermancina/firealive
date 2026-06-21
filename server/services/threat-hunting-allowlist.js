// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Consumer IP Allow-List Cache (B5m)
//
// Used by the API rate limiter's skip() so that a high-volume telemetry pull
// from an AUTHORIZED threat-hunting consumer (EDR / XDR / ATP / NGAV / MSP) is
// not throttled as if it were an attack. An IP is exempt only when it falls
// inside the allow-list of an ENABLED authorization in
// threat_hunting_consumer_authorizations (the same registry the feed gate uses).
// This is the ONLY defense relaxed for authorized consumers:
//   - the mutual-TLS client cert + bearer token + IP gate on the feed and TAXII
//     endpoints still applies in full,
//   - the append-only access log still records every access (allow or deny),
//   - auth / brute-force lockout, method/path hardening, and all other
//     protections remain fully active even for a registered consumer IP.
//
// skip() runs on every /api/ request, so the allow-list is cached in memory and
// the DB is consulted at most once per TTL window. Failure is fail-safe: if the
// allow-list cannot be loaded, no IP is exempted (rate limiting stays on).
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');

const TTL_MS = 30 * 1000;
let cache = { cidrs: [], loadedAt: 0 };

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
  for (const p of parts) {
    const o = Number(p);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    n = (n * 256) + o;
  }
  return n >>> 0;
}

// Match a source IP against one allow-list entry. IPv4 supports exact + CIDR;
// IPv6 supports exact match (full IPv6 CIDR math is out of scope — operators
// list explicit IPv6 sources or rely on the firewall). Mirrors the matcher in
// middleware/threat-hunting-auth.js so exemption and access-gating agree.
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

// Reload the enabled-authorization CIDR set from the DB. Fail-safe: on error,
// keep whatever was cached and advance loadedAt so we don't hammer the DB
// during an outage (a never-loaded cache stays empty → nothing is exempted).
function refresh() {
  let db;
  try {
    db = getDb();
    const rows = db
      .prepare('SELECT allowed_cidrs FROM threat_hunting_consumer_authorizations WHERE enabled = 1')
      .all();
    const cidrs = [];
    for (const r of rows) {
      try {
        const arr = JSON.parse(r.allowed_cidrs);
        if (Array.isArray(arr)) {
          for (const c of arr) if (typeof c === 'string' && c.trim()) cidrs.push(c.trim());
        }
      } catch (_) { /* skip malformed row */ }
    }
    cache = { cidrs, loadedAt: Date.now() };
  } catch (_) {
    cache = { cidrs: cache.cidrs, loadedAt: Date.now() };
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
}

// True iff the source IP is inside an enabled authorization's allow-list.
// Cheap: synchronous in-memory check, with a DB reload at most once per TTL.
function isAuthorizedConsumerIp(ip) {
  ip = normalizeIp(ip || '');
  if (!ip) return false;
  if (Date.now() - cache.loadedAt > TTL_MS) refresh();
  if (!cache.cidrs.length) return false;
  return cache.cidrs.some((c) => ipMatchesEntry(ip, c));
}

module.exports = { isAuthorizedConsumerIp, _refresh: refresh, _ttlMs: TTL_MS };

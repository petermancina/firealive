// ===========================================================================
// FIREALIVE -- Vuln-Scan Scanner IP Allow-List Cache (B5p)
//
// Used by the API rate limiter's skip() so that a high-volume scan from an
// AUTHORIZED on-prem vulnerability scanner is not throttled as if it were an
// attack. An IP is exempt only when ALL of the following hold:
//   - the Vulnerability Scan feature is enabled (vuln_scan_config.enabled),
//   - the IP falls inside the allow-list of an ENABLED authorization in
//     vuln_scan_scanner_authorizations, AND
//   - that authorization's scanner_type is still permitted by the live policy
//     (vuln_scan_config.allowedScanners).
// The last clause is the live-policy enforcement point: removing a scanner type
// from the policy stops exempting its IPs within one TTL window, without
// mutating any authorization row. This is the ONLY defense relaxed for
// authorized scans:
//   - the token + IP gate on /api/vuln-scan-access still applies,
//   - the append-only, hash-chained scan-access log still records every scan,
//   - auth / brute-force lockout, method/path hardening, and all other
//     protections remain fully active even for a registered scanner IP.
//
// skip() runs on every /api/ request, so the allow-list is cached in memory and
// the DB is consulted at most once per TTL window. Failure is fail-safe: if the
// allow-list cannot be loaded, no IP is exempted (rate limiting stays on).
// ===========================================================================

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
// IPv6 supports exact match (full IPv6 CIDR math is out of scope -- operators
// list explicit IPv6 sources or rely on the firewall). Mirrors the matcher in
// routes/vuln-scan.js so exemption and access-gating agree.
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

// Read the live policy (enabled + allowedScanners) from team_config. Fail-safe:
// any error or missing/garbled config yields a disabled, empty policy so nothing
// is exempted.
function readPolicy(db) {
  try {
    const row = db
      .prepare("SELECT value FROM team_config WHERE key = 'vuln_scan_config'")
      .get();
    if (!row) return { enabled: false, allowedScanners: [] };
    const cfg = JSON.parse(row.value);
    const enabled = !!(cfg && cfg.enabled === true);
    const allowedScanners = (cfg && Array.isArray(cfg.allowedScanners))
      ? cfg.allowedScanners.filter((s) => typeof s === 'string')
      : [];
    return { enabled, allowedScanners };
  } catch (_) {
    return { enabled: false, allowedScanners: [] };
  }
}

// Reload the exempt CIDR set: the allowed_cidrs of ENABLED authorizations whose
// scanner_type is permitted by the live policy, but only while the feature is
// enabled. Fail-safe: on error, keep whatever was cached and advance loadedAt so
// we do not hammer the DB during an outage (a never-loaded cache stays empty ->
// nothing is exempted).
function refresh() {
  let db;
  try {
    db = getDb();
    const policy = readPolicy(db);
    const cidrs = [];
    if (policy.enabled && policy.allowedScanners.length) {
      const allowed = new Set(policy.allowedScanners);
      const rows = db
        .prepare('SELECT allowed_cidrs, scanner_type FROM vuln_scan_scanner_authorizations WHERE enabled = 1')
        .all();
      for (const r of rows) {
        if (!allowed.has(r.scanner_type)) continue;
        try {
          const arr = JSON.parse(r.allowed_cidrs);
          if (Array.isArray(arr)) {
            for (const c of arr) if (typeof c === 'string' && c.trim()) cidrs.push(c.trim());
          }
        } catch (_) { /* skip malformed row */ }
      }
    }
    cache = { cidrs, loadedAt: Date.now() };
  } catch (_) {
    cache = { cidrs: cache.cidrs, loadedAt: Date.now() };
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
}

// True iff the source IP is inside a permitted, enabled authorization's
// allow-list while the feature is enabled. Cheap: synchronous in-memory check,
// with a DB reload at most once per TTL.
function isAuthorizedVulnScannerSource(ip) {
  ip = normalizeIp(ip || '');
  if (!ip) return false;
  if (Date.now() - cache.loadedAt > TTL_MS) refresh();
  if (!cache.cidrs.length) return false;
  return cache.cidrs.some((c) => ipMatchesEntry(ip, c));
}

module.exports = { isAuthorizedVulnScannerSource, _refresh: refresh, _ttlMs: TTL_MS };

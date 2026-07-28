//
// FIREALIVE GD -- On-Prem Vulnerability Scanner Allow-List  [B6e]
//
// A sanctioned scan generates far more requests in a short window than any
// human session. Without an exemption the deployment's own rate limiter
// throttles the scan and the scan reports a false clean -- the security control
// defeating the security test.
//
// This surface is NEW in B6e, so unlike the cloud twin beside it there is no
// history of scans being throttled -- there were no scans. It gets the
// exemption from its first line for the same reason the cloud one needed it
// retrofitted: without it the limiter throttles a sanctioned scan and the scan
// reports a false clean, the security control defeating the security test.
//
// THIS IS THE ONLY DEFENCE RELAXED FOR AN AUTHORIZED SCAN. The mutual-TLS
// certificate factor, the bearer token, the source-IP allow-list, the live scan
// policy, the append-only hash-chained access log and the account lockout all
// stay fully active. An exempted IP gets more REQUESTS, never more ACCESS.
//
// TWO GATES, both required, and the order is deliberate:
//   1. the live policy must be enabled and permit the scanner's type
//   2. the authorization row must itself be enabled
//
// Gate 1 is what makes the master switch real. Without it the exemption would
// outlive the policy that authorized it: disabling cloud scanning would stop
// announces while these source IPs stayed exempt, so a scanner revoked BY
// POLICY would keep a privilege it should have lost.
//
// FAIL-SAFE. On any error the cache keeps whatever it held and advances
// loadedAt, so a database outage does not turn into a reload storm. A cache
// that never loaded stays EMPTY, and an empty cache exempts nobody -- the
// failure direction is toward more rate limiting, never less.
//
// AGPL-3.0-or-later
//

const { getDb } = require('../db-init');
const { readScanPolicy } = require('./gd-scan-policy');

const TTL_MS = 30 * 1000;
let cache = { cidrs: [], loadedAt: 0 };

function normalizeIp(ip) {
  const s = String(ip || '').trim();
  // Express reports IPv4-mapped IPv6 for a v4 peer behind some proxies.
  return s.startsWith('::ffff:') ? s.slice(7) : s;
}

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = parseInt(p, 10);
    if (v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

function ipMatchesEntry(ip, entry) {
  const e = String(entry || '').trim();
  if (!e) return false;
  if (!e.includes('/')) return e === ip;
  const [net, bitsRaw] = e.split('/');
  const bits = parseInt(bitsRaw, 10);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(net);
  if (ipInt === null || netInt === null) return false;
  const mask = bits === 32 ? 0xffffffff : (~(0xffffffff >>> bits)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

function refresh() {
  let db;
  try {
    db = getDb();
    const policy = readScanPolicy(db, 'on_prem');
    const cidrs = [];
    if (policy.enabled && policy.allowedScanners.length) {
      const allowed = new Set(policy.allowedScanners);
      const rows = db
        .prepare('SELECT allowed_cidrs, scanner_type FROM vuln_scan_scanner_authorizations WHERE enabled = 1')
        .all();
      for (const r of rows) {
        // A scanner type the policy no longer permits is not exempt, even
        // though its authorization row is still enabled.
        if (!allowed.has(r.scanner_type)) continue;
        try {
          const arr = JSON.parse(r.allowed_cidrs);
          if (Array.isArray(arr)) {
            for (const c of arr) if (typeof c === 'string' && c.trim()) cidrs.push(c.trim());
          }
        } catch (_) { /* skip a malformed row rather than failing the whole reload */ }
      }
    }
    cache = { cidrs, loadedAt: Date.now() };
  } catch (_) {
    cache = { cidrs: cache.cidrs, loadedAt: Date.now() };
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
}

// True iff the source IP is inside an enabled, policy-permitted authorization's
// allow-list. Synchronous in-memory check with a reload at most once per TTL,
// because it runs on every request through the limiter.
function isAuthorizedOnPremScannerIp(ip) {
  ip = normalizeIp(ip || '');
  if (!ip) return false;
  if (Date.now() - cache.loadedAt > TTL_MS) refresh();
  if (!cache.cidrs.length) return false;
  return cache.cidrs.some((c) => ipMatchesEntry(ip, c));
}

module.exports = { isAuthorizedOnPremScannerIp, _refresh: refresh, _ttlMs: TTL_MS };

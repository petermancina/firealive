// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GeoIP IP Utilities (B5n)
//
// Pure-Node IP helpers for login geo-fencing. No dependencies. Exports:
//
//   normalizeIp(ip)     — collapse an IPv4-mapped IPv6 ("::ffff:1.2.3.4") to
//                         plain IPv4, strip [brackets] and %zone-id, lowercase
//                         IPv6 hex. Returns '' for non-strings / empty input.
//   classifyIp(ip)      — 'loopback' | 'private' | 'reserved' | 'public', or
//                         null when the input is not a valid IP. The geo-fence
//                         uses 'loopback' to bypass and the other classes to
//                         explain why a non-public source cannot be geo-resolved.
//   cidrMatch(ip, cidr) — true iff ip falls inside cidr, for BOTH IPv4 and IPv6
//                         (exact match when cidr carries no /prefix). BigInt
//                         prefix compare; mismatched address families never match.
//   parseIp(ip)         — { version: 4 | 6, value: BigInt } | null. The shared
//                         primitive (also used by the MMDB reader to walk the
//                         binary search tree by address bits).
//
// The IPv4 path mirrors the proven matcher in cloud-vuln-allowlist.js; this
// module ADDS full IPv6 support and is self-contained (that file is unchanged).
// ═══════════════════════════════════════════════════════════════════════════════

// Collapse an IPv4-mapped IPv6 address to plain IPv4, strip URL brackets and an
// IPv6 zone id, and lowercase IPv6 hex. IPv4 input is returned unchanged.
function normalizeIp(ip) {
  if (typeof ip !== 'string') return '';
  let s = ip.trim();
  if (!s) return '';
  if (s.charAt(0) === '[' && s.charAt(s.length - 1) === ']') s = s.slice(1, -1);
  const pct = s.indexOf('%');
  if (pct !== -1) s = s.slice(0, pct);
  const mapped = s.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (mapped) return mapped[1];
  if (s.indexOf(':') !== -1) s = s.toLowerCase();
  return s;
}

// Dotted-quad IPv4 -> BigInt (0 .. 2^32-1), or null if malformed.
function ipv4ToBigInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const o = Number(p);
    if (o > 255) return null;
    n = (n << 8n) + BigInt(o);
  }
  return n;
}

// IPv6 text -> BigInt (0 .. 2^128-1), or null if malformed. Handles "::" zero
// compression and an embedded IPv4 tail ("::ffff:1.2.3.4", "64:ff9b::1.2.3.4").
function ipv6ToBigInt(input) {
  let s = String(input).toLowerCase();
  if (s.indexOf(':') === -1) return null;
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.indexOf('.') !== -1) {
    const v4 = ipv4ToBigInt(tail);
    if (v4 === null) return null;
    const hi = (v4 >> 16n) & 0xffffn;
    const lo = v4 & 0xffffn;
    s = s.slice(0, lastColon + 1) + hi.toString(16) + ':' + lo.toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  let groups;
  if (halves.length === 2) {
    const back = halves[1] ? halves[1].split(':') : [];
    const missing = 8 - (head.length + back.length);
    if (missing < 0) return null;
    groups = head.concat(new Array(missing).fill('0')).concat(back);
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    value = (value << 16n) + BigInt(parseInt(g, 16));
  }
  return value;
}

// Parse any IP to { version, value: BigInt }, or null if it is not a valid IP.
function parseIp(ip) {
  const norm = normalizeIp(ip);
  if (!norm) return null;
  if (norm.indexOf(':') === -1) {
    const v = ipv4ToBigInt(norm);
    return v === null ? null : { version: 4, value: v };
  }
  const v = ipv6ToBigInt(norm);
  return v === null ? null : { version: 6, value: v };
}

// Prefix mask for a family ("bits" high bits set) as a BigInt.
function maskBig(version, bits) {
  const total = version === 4 ? 32 : 128;
  if (bits <= 0) return 0n;
  if (bits >= total) return (1n << BigInt(total)) - 1n;
  const ones = (1n << BigInt(bits)) - 1n;
  return ones << BigInt(total - bits);
}

// Internal: does an already-parsed IP fall inside a well-formed literal CIDR?
// Used by classifyIp with trusted literals (no input validation needed).
function inCidr(parsed, cidr) {
  const slash = cidr.indexOf('/');
  const net = parseIp(cidr.slice(0, slash));
  const bits = Number(cidr.slice(slash + 1));
  if (!net || net.version !== parsed.version) return false;
  const m = maskBig(parsed.version, bits);
  return (parsed.value & m) === (net.value & m);
}

// 'loopback' | 'private' | 'reserved' | 'public', or null for an invalid IP.
function classifyIp(ip) {
  const parsed = parseIp(ip);
  if (!parsed) return null;
  if (parsed.version === 4) {
    if (inCidr(parsed, '127.0.0.0/8')) return 'loopback';
    if (inCidr(parsed, '10.0.0.0/8') ||
        inCidr(parsed, '172.16.0.0/12') ||
        inCidr(parsed, '192.168.0.0/16')) return 'private';
    if (inCidr(parsed, '0.0.0.0/8') ||
        inCidr(parsed, '169.254.0.0/16') ||
        inCidr(parsed, '100.64.0.0/10') ||
        inCidr(parsed, '192.0.0.0/24') ||
        inCidr(parsed, '192.0.2.0/24') ||
        inCidr(parsed, '198.18.0.0/15') ||
        inCidr(parsed, '198.51.100.0/24') ||
        inCidr(parsed, '203.0.113.0/24') ||
        inCidr(parsed, '224.0.0.0/4') ||
        inCidr(parsed, '240.0.0.0/4')) return 'reserved';
    return 'public';
  }
  if (inCidr(parsed, '::1/128')) return 'loopback';
  if (inCidr(parsed, 'fc00::/7')) return 'private';
  if (inCidr(parsed, '::/128') ||
      inCidr(parsed, 'fe80::/10') ||
      inCidr(parsed, 'ff00::/8') ||
      inCidr(parsed, '2001:db8::/32')) return 'reserved';
  return 'public';
}

// True iff ip falls inside cidr, for both IPv4 and IPv6. With no "/prefix",
// cidr is treated as an exact address. Untrusted input is fully validated.
function cidrMatch(ip, cidr) {
  const parsed = parseIp(ip);
  if (!parsed || typeof cidr !== 'string') return false;
  const c = cidr.trim();
  if (!c) return false;
  const slash = c.indexOf('/');
  if (slash === -1) {
    const other = parseIp(c);
    return !!other && other.version === parsed.version && other.value === parsed.value;
  }
  const bitsRaw = c.slice(slash + 1);
  if (!/^\d{1,3}$/.test(bitsRaw)) return false;
  const net = parseIp(c.slice(0, slash));
  if (!net || net.version !== parsed.version) return false;
  const total = parsed.version === 4 ? 32 : 128;
  const bits = Number(bitsRaw);
  if (bits > total) return false;
  const m = maskBig(parsed.version, bits);
  return (parsed.value & m) === (net.value & m);
}

module.exports = { normalizeIp, classifyIp, cidrMatch, parseIp };

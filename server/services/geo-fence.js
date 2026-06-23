// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Login Geo-Fence Decision Engine (B5n)
//
// The single decision point for per-user login geo-fencing. On every passwordless
// login, auth.js calls checkGeoFence(db, user, ip) and acts on the returned
// decision. This module is SYNCHRONOUS and SIDE-EFFECT-FREE: it reads config and
// the GeoIP service and returns a verdict. It writes no audit row, fires no
// alert, and sends no response -- auth.js owns all of that, so the policy and its
// effects stay separable and testable.
//
// Decision order (first match wins):
//   1. config disabled            -> allow (action 'disabled')
//   2. user has no assigned country (users.geo_country unset)
//                                 -> allow (action 'user-not-fenced'); an org
//                                    disables fencing for a user by not assigning
//                                    a country.
//   3. enabled but no GeoIP DB loaded
//                                 -> allow + flag (action 'misconfigured'); FAIL
//                                    OPEN so a missing database never bricks login
//                                    (auth.js raises a high-severity alert).
//   4. loopback source IP         -> allow (action 'bypass-loopback')
//   5. source IP in a trusted network CIDR
//                                 -> allow (action 'bypass-trusted'); the trusted-
//                                    network model, NOT trust-all-RFC-1918: only
//                                    explicitly declared subnets (and loopback)
//                                    bypass.
//   6. resolve the source IP to a country and compare:
//        unresolved (public-but-unknown, or private-but-untrusted)
//                                 -> FAILURE: block under enforcement, else allow
//                                    + flag (action 'unresolved').
//        matches the assigned country
//                                 -> allow (action 'match').
//        matches an active per-user exception country
//                                 -> allow (action 'exception').
//        otherwise                -> mismatch: block under enforcement, else allow
//                                    + flag (action 'mismatch').
//
// Enforcement: when geo_fence_config.enforceGeoLogin is true, a 'mismatch' or
// 'unresolved' verdict BLOCKS the login (auth.js returns 403); when false, the
// login is allowed but still audited and alerted. break-glass recovery has its
// own handler and never reaches this code.
//
//   checkGeoFence(db, user, ip) -> {
//     allowed, blocked, action, enforced, observedCountry, expectedCountries,
//     ipClass, reason
//   }
//   loadGeoConfig(db)           -> { enabled, enforceGeoLogin, trustedNetworks }
//   loadActiveExceptions(db, id)-> [ ISO country, ... ] (non-expired only)
// ═══════════════════════════════════════════════════════════════════════════════

const geoipService = require('./geoip/geoip-service');
const { classifyIp, cidrMatch } = require('./geoip/ip-utils');

const CONFIG_KEY = 'geo_fence_config';

// Read and normalize the geo-fence config. Defaults: disabled, enforce-on,
// no trusted networks. Tolerates a missing row, malformed JSON, and the legacy
// shape (the obsolete per-client list is simply ignored).
function loadGeoConfig(db) {
  let cfg = {};
  try {
    const row = db.prepare('SELECT value FROM config WHERE key = ?').get(CONFIG_KEY);
    if (row && row.value) cfg = JSON.parse(row.value);
  } catch (e) {
    cfg = {};
  }
  if (!cfg || typeof cfg !== 'object') cfg = {};
  const trusted = Array.isArray(cfg.trustedNetworks)
    ? cfg.trustedNetworks.filter((c) => typeof c === 'string' && c.trim()).map((c) => c.trim())
    : [];
  return {
    enabled: cfg.enabled === true,
    enforceGeoLogin: cfg.enforceGeoLogin !== false, // default true
    trustedNetworks: trusted,
  };
}

// Active (non-expired) per-user exception countries. Expiry is evaluated in JS
// for date-format robustness; a malformed or past expiry is treated as expired
// (fail-closed on a relaxation -- when in doubt, do not widen the allow-set).
function loadActiveExceptions(db, userId) {
  if (!userId) return [];
  let rows;
  try {
    rows = db
      .prepare('SELECT country, expires_at FROM geo_login_exceptions WHERE user_id = ?')
      .all(userId);
  } catch (e) {
    return [];
  }
  const now = Date.now();
  const out = [];
  for (const r of rows || []) {
    if (typeof r.country !== 'string' || !r.country.trim()) continue;
    if (r.expires_at && String(r.expires_at).trim()) {
      const t = Date.parse(r.expires_at);
      if (isNaN(t) || t <= now) continue; // malformed or expired -> skip
    }
    out.push(r.country.trim().toUpperCase());
  }
  return out;
}

function decision(action, reason, opts) {
  const o = opts || {};
  return {
    action: action,
    reason: reason,
    allowed: o.allowed !== false,
    blocked: o.blocked === true,
    enforced: o.enforced === true,
    observedCountry: o.observedCountry !== undefined ? o.observedCountry : null,
    expectedCountries: o.expectedCountries || [],
    ipClass: o.ipClass !== undefined ? o.ipClass : null,
  };
}

// Evaluate the geo-fence for one login. Pure: reads config + GeoIP, returns a
// verdict; performs no audit, alert, or response.
function checkGeoFence(db, user, ip) {
  const cfg = loadGeoConfig(db);
  const enforced = cfg.enforceGeoLogin;

  if (!cfg.enabled) {
    return decision('disabled', 'geo-fencing disabled', { enforced });
  }

  const home = user && typeof user.geo_country === 'string' ? user.geo_country.trim().toUpperCase() : '';
  if (!home) {
    return decision('user-not-fenced', 'user has no assigned country', { enforced });
  }

  if (!geoipService.isLoaded()) {
    return decision('misconfigured', 'geo-fencing enabled but no GeoIP database is loaded', {
      enforced,
      expectedCountries: [home],
    });
  }

  const ipClass = classifyIp(ip);

  if (ipClass === 'loopback') {
    return decision('bypass-loopback', 'loopback address bypasses geo-fencing', {
      enforced,
      ipClass,
      expectedCountries: [home],
    });
  }

  for (const cidr of cfg.trustedNetworks) {
    if (cidrMatch(ip, cidr)) {
      return decision('bypass-trusted', 'source IP is within a trusted network', {
        enforced,
        ipClass,
        expectedCountries: [home],
      });
    }
  }

  const exceptions = loadActiveExceptions(db, user && user.id);
  const expected = [home].concat(exceptions.filter((c) => c !== home));

  const observedRaw = geoipService.resolveCountry(ip);
  const observed = typeof observedRaw === 'string' && observedRaw.trim() ? observedRaw.trim().toUpperCase() : null;

  if (observed === null) {
    return decision('unresolved', 'source IP did not resolve to a country', {
      enforced,
      ipClass,
      observedCountry: null,
      expectedCountries: expected,
      allowed: !enforced,
      blocked: enforced,
    });
  }

  if (observed === home) {
    return decision('match', 'login country matches assigned country', {
      enforced,
      ipClass,
      observedCountry: observed,
      expectedCountries: expected,
    });
  }

  if (exceptions.indexOf(observed) !== -1) {
    return decision('exception', 'login country ' + observed + ' allowed by an active exception', {
      enforced,
      ipClass,
      observedCountry: observed,
      expectedCountries: expected,
    });
  }

  return decision('mismatch', 'login country ' + observed + ' does not match assigned ' + expected.join('/'), {
    enforced,
    ipClass,
    observedCountry: observed,
    expectedCountries: expected,
    allowed: !enforced,
    blocked: enforced,
  });
}

module.exports = { checkGeoFence, loadGeoConfig, loadActiveExceptions };

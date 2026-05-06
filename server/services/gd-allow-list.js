// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GD-Server Hostname Allow-List
// ═══════════════════════════════════════════════════════════════════════════════
//
// Allow-list of hostnames that are permitted as destinations for the
// GD push pipeline (the recurring metrics push from this Regional MC to
// the customer's Global Dashboard server).
//
// Configured at deployment time via the GD_ALLOWED_HOSTS environment
// variable, which is a comma-separated list of hostnames or IP literals.
// Examples:
//
//   GD_ALLOWED_HOSTS=gd.corp.local
//   GD_ALLOWED_HOSTS=gd-prod.corp.local,gd-staging.corp.local
//   GD_ALLOWED_HOSTS=10.0.5.20
//
// If GD_ALLOWED_HOSTS is unset or empty, the GD push feature is disabled
// entirely — neither the test endpoint nor the recurring push service
// will accept any URL. This is the secure default: GD push must be
// explicitly enabled at deployment time.
//
// This is the primary defense against SSRF (CodeQL js/request-forgery,
// alert #334). The user-provided URL flows from the admin's PUT into
// the gd_push_config DB row, but its hostname is checked against this
// allow-list at three points:
//
//   1. PUT /api/gd-config — at write time, before the URL is stored
//   2. POST /api/gd-config/test — at test time, defense in depth
//   3. server/services/gd-push.js — at every push, defense in depth
//
// Layered checks mean that if an attacker bypasses one layer (e.g.,
// tampers with the DB out of band) the others still prevent the push
// from reaching an unauthorized destination.
//
// Hostnames are matched case-insensitively (DNS hostnames are
// case-insensitive per RFC 1035). The match is exact — no wildcard or
// subdomain semantics. If you want gd.corp.com and staging.gd.corp.com,
// list both. This is deliberate; "smart" hostname matching is a common
// source of allow-list bypasses.
//
// Port is NOT part of the comparison. The allow-list contains hostnames
// only; URL.hostname returns hostname-only (no port). So `gd.corp.com`
// in the allow-list permits both `https://gd.corp.com:4001/...` and
// `https://gd.corp.com:443/...`.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Returns the configured allow-list of GD-Server hostnames.
 * Re-read from process.env on each call so that operators can adjust
 * the env var via process restart without code changes. (No caching;
 * this is a small string operation and runs at most a few times per
 * minute even at peak.)
 *
 * @returns {string[]} lowercased, trimmed hostnames; empty array if
 *                    GD_ALLOWED_HOSTS is unset or empty.
 */
function getAllowedHosts() {
  const raw = process.env.GD_ALLOWED_HOSTS || '';
  return raw
    .split(',')
    .map(h => h.trim().toLowerCase())
    .filter(h => h.length > 0);
}

/**
 * Validates a hostname against the configured allow-list.
 *
 * @param {string} hostname  The hostname to check (typically from
 *                           new URL(endpointUrl).hostname).
 * @returns {{ok: boolean, error?: string}}
 *
 * Returns {ok: false} with a clear error message if:
 *   - GD_ALLOWED_HOSTS is unset or empty (feature not enabled)
 *   - hostname is empty or not a string
 *   - hostname (lowercased) is not in the allow-list
 *
 * Returns {ok: true} only if the hostname exactly matches an entry
 * in the allow-list.
 */
function validateAllowedHost(hostname) {
  const allowed = getAllowedHosts();
  if (allowed.length === 0) {
    return {
      ok: false,
      error: 'GD push feature is not enabled on this MC. Set the GD_ALLOWED_HOSTS environment variable (comma-separated hostnames) to enable.',
    };
  }
  const target = String(hostname || '').trim().toLowerCase();
  if (!target) {
    return { ok: false, error: 'No hostname to validate.' };
  }
  if (!allowed.includes(target)) {
    return {
      ok: false,
      error: `Hostname '${target}' is not in the GD_ALLOWED_HOSTS allow-list. Configured hosts: ${allowed.join(', ')}.`,
    };
  }
  return { ok: true };
}

module.exports = { getAllowedHosts, validateAllowedHost };

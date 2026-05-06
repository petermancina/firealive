// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — HR Scheduling Platform Hostname Allow-List
// ═══════════════════════════════════════════════════════════════════════════════
//
// Allow-list of hostnames that are permitted as destinations for the
// HR scheduling platform sync (the per-tenant pull of analyst work
// schedules from external HR systems — UKG/Kronos, Workday, ADP,
// BambooHR, or Manual mode — into the MC's per-analyst availability
// records, and the push of upskilling assignments back as calendar
// events).
//
// Configured at deployment time via the HR_ALLOWED_HOSTS environment
// variable, which is a comma-separated list of hostnames or IP literals.
// Examples:
//
//   HR_ALLOWED_HOSTS=workday.corp.local
//   HR_ALLOWED_HOSTS=workday-prod.corp.local,bamboohr.corp.local
//   HR_ALLOWED_HOSTS=10.0.5.30
//
// If HR_ALLOWED_HOSTS is unset or empty, the HR scheduling sync feature
// is disabled entirely — neither the configure-then-test endpoint nor
// the per-platform adapters will accept any URL. This is the secure
// default: HR sync must be explicitly enabled at deployment time, the
// same posture established for GD push in v1.0.28.
//
// This is the primary defense against SSRF for the new HR sync surface.
// The user-provided URL flows from the lead/admin's PUT into the
// scheduling_platform_config DB row, but its hostname is checked against
// this allow-list at three points (defense in depth):
//
//   1. PUT /api/scheduling/config — at write time, before the URL is stored
//   2. POST /api/scheduling/test — at test time
//   3. server/services/scheduling-platforms/* — at every adapter call
//
// Layered checks mean that if an attacker bypasses one layer (e.g.,
// tampers with the DB out of band) the others still prevent the sync
// from reaching an unauthorized destination.
//
// Hostnames are matched case-insensitively (DNS hostnames are
// case-insensitive per RFC 1035). The match is exact — no wildcard or
// subdomain semantics. If you want workday.corp.com and
// staging.workday.corp.com, list both. This is deliberate; "smart"
// hostname matching is a common source of allow-list bypasses.
//
// Port is NOT part of the comparison. The allow-list contains hostnames
// only; URL.hostname returns hostname-only (no port). So `workday.corp.com`
// in the allow-list permits both `https://workday.corp.com:8443/...` and
// `https://workday.corp.com:443/...`.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Returns the configured allow-list of HR scheduling platform hostnames.
 * Re-read from process.env on each call so that operators can adjust
 * the env var via process restart without code changes. (No caching;
 * this is a small string operation and runs at most a few times per
 * minute even at peak.)
 *
 * @returns {string[]} lowercased, trimmed hostnames; empty array if
 *                    HR_ALLOWED_HOSTS is unset or empty.
 */
function getAllowedHosts() {
  const raw = process.env.HR_ALLOWED_HOSTS || '';
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
 *   - HR_ALLOWED_HOSTS is unset or empty (feature not enabled)
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
      error: 'HR scheduling sync feature is not enabled on this MC. Set the HR_ALLOWED_HOSTS environment variable (comma-separated hostnames) to enable.',
    };
  }
  const target = String(hostname || '').trim().toLowerCase();
  if (!target) {
    return { ok: false, error: 'No hostname to validate.' };
  }
  if (!allowed.includes(target)) {
    return {
      ok: false,
      error: `Hostname '${target}' is not in the HR_ALLOWED_HOSTS allow-list. Configured hosts: ${allowed.join(', ')}.`,
    };
  }
  return { ok: true };
}

module.exports = { getAllowedHosts, validateAllowedHost };

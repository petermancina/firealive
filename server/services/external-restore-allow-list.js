// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — External Restore Source Hostname Allow-List
// ═══════════════════════════════════════════════════════════════════════════════
//
// Allow-list of hostnames that are permitted as destinations for the
// External Restore source connectivity (the admin-only operation of
// pulling encrypted backup archives from network-share / NAS / S3 /
// Azure Blob / SFTP sources during compromise-recovery workflow).
//
// Note: local-mounted SMB and NFS sources do not technically need this
// allow-list because they don't make network calls outbound from the
// MC process — the OS handles the mount. However the check is applied
// uniformly across all five adapter types so the operator has one
// single place to declare which external locations FireAlive may
// touch, irrespective of how the protocol works under the hood.
//
// Configured at deployment time via the EXTERNAL_RESTORE_ALLOWED_HOSTS environment
// variable, which is a comma-separated list of hostnames or IP literals.
// Examples:
//
//   EXTERNAL_RESTORE_ALLOWED_HOSTS=backup.corp.local
//   EXTERNAL_RESTORE_ALLOWED_HOSTS=backup-primary.corp.local,backup-dr.us-east-2.s3.amazonaws.com
//   EXTERNAL_RESTORE_ALLOWED_HOSTS=nas-prod.dmz.local
//
// If EXTERNAL_RESTORE_ALLOWED_HOSTS is unset or empty, the External Restore feature
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
 *                    EXTERNAL_RESTORE_ALLOWED_HOSTS is unset or empty.
 */
function getAllowedHosts() {
  const raw = process.env.EXTERNAL_RESTORE_ALLOWED_HOSTS || '';
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
 *   - EXTERNAL_RESTORE_ALLOWED_HOSTS is unset or empty (feature not enabled)
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
      error: 'External Restore feature is not enabled on this MC. Set the EXTERNAL_RESTORE_ALLOWED_HOSTS environment variable (comma-separated hostnames) to enable.',
    };
  }
  const target = String(hostname || '').trim().toLowerCase();
  if (!target) {
    return { ok: false, error: 'No hostname to validate.' };
  }
  if (!allowed.includes(target)) {
    return {
      ok: false,
      error: `Hostname '${target}' is not in the EXTERNAL_RESTORE_ALLOWED_HOSTS allow-list. Configured hosts: ${allowed.join(', ')}.`,
    };
  }
  return { ok: true };
}

module.exports = { getAllowedHosts, validateAllowedHost };

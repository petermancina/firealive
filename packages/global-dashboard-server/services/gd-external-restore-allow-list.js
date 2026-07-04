// =============================================================================
// FIREALIVE GD -- External Restore Source Hostname Allow-List
// =============================================================================
//
// Allow-list of hostnames that are permitted as destinations for the External
// Restore source connectivity (the CISO-only operation of pulling encrypted
// backup archives from network-share / NAS / S3 / Azure Blob / SFTP sources
// during a compromise-recovery workflow).
//
// Note: local-mounted SMB and NFS sources do not technically make network calls
// outbound from the GD process -- the OS handles the mount. However the check is
// applied uniformly across all five source types so the operator has one single
// place to declare which external locations the GD may touch, irrespective of
// how the protocol works under the hood.
//
// Configured at deployment time via the GD_EXTERNAL_RESTORE_ALLOWED_HOSTS
// environment variable, a comma-separated list of hostnames or IP literals.
// Examples:
//
//   GD_EXTERNAL_RESTORE_ALLOWED_HOSTS=backup.corp.local
//   GD_EXTERNAL_RESTORE_ALLOWED_HOSTS=backup-primary.corp.local,backup-dr.us-east-2.s3.amazonaws.com
//   GD_EXTERNAL_RESTORE_ALLOWED_HOSTS=nas-prod.dmz.local
//
// If GD_EXTERNAL_RESTORE_ALLOWED_HOSTS is unset or empty, the External Restore
// feature is disabled entirely -- neither the configure-then-test endpoint nor
// the per-type adapters will accept any URL. This is the secure default:
// external restore must be explicitly enabled at deployment time.
//
// This is the primary defense against SSRF for the external-restore surface.
// A source's hostname is checked against this allow-list at multiple points
// (defense in depth): when a source is created/updated, when it is tested, and
// at every adapter fetch. Layered checks mean that if an attacker bypasses one
// layer (e.g. tampers with the DB out of band) the others still prevent the
// fetch from reaching an unauthorized destination.
//
// Hostnames are matched case-insensitively (DNS hostnames are case-insensitive
// per RFC 1035). The match is exact -- no wildcard or subdomain semantics. If
// you want backup.corp.com and dr.backup.corp.com, list both. This is
// deliberate; "smart" hostname matching is a common source of allow-list
// bypasses.
//
// Port is NOT part of the comparison. The allow-list contains hostnames only;
// URL.hostname returns hostname-only (no port). So `backup.corp.com` in the
// allow-list permits both `https://backup.corp.com:8443/...` and
// `https://backup.corp.com:443/...`.
// =============================================================================

/**
 * Returns the configured allow-list of external restore source hostnames.
 * Re-read from process.env on each call so operators can adjust the env var via
 * process restart without code changes. (No caching; a small string operation.)
 *
 * @returns {string[]} lowercased, trimmed hostnames; empty array if
 *                     GD_EXTERNAL_RESTORE_ALLOWED_HOSTS is unset or empty.
 */
function getAllowedHosts() {
  const raw = process.env.GD_EXTERNAL_RESTORE_ALLOWED_HOSTS || '';
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
 *   - GD_EXTERNAL_RESTORE_ALLOWED_HOSTS is unset or empty (feature not enabled)
 *   - hostname is empty or not a string
 *   - hostname (lowercased) is not in the allow-list
 *
 * Returns {ok: true} only if the hostname exactly matches an entry in the
 * allow-list.
 */
function validateAllowedHost(hostname) {
  const allowed = getAllowedHosts();
  if (allowed.length === 0) {
    return {
      ok: false,
      error: 'External Restore feature is not enabled on this GD. Set the GD_EXTERNAL_RESTORE_ALLOWED_HOSTS environment variable (comma-separated hostnames) to enable.',
    };
  }
  const target = String(hostname || '').trim().toLowerCase();
  if (!target) {
    return { ok: false, error: 'No hostname to validate.' };
  }
  if (!allowed.includes(target)) {
    return {
      ok: false,
      error: `Hostname '${target}' is not in the GD_EXTERNAL_RESTORE_ALLOWED_HOSTS allow-list. Configured hosts: ${allowed.join(', ')}.`,
    };
  }
  return { ok: true };
}

module.exports = { getAllowedHosts, validateAllowedHost };

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- GitHub Release Update-Check Service (B5r)
//
// Detect-and-notify only. Polls THIS repository's GitHub Releases for a newer
// stable release and reports the outcome. FireAlive never downloads, routes, or
// installs an update -- the operator tests in a lab sandbox and applies on their
// own change-management schedule. This module is the single place that reaches
// the network on the regional server.
//
// SOURCE -- one hardcoded endpoint:
//   GET https://api.github.com/repos/petermancina/firealive/releases/latest
//   /releases/latest returns only the newest NON-prerelease, non-draft release,
//   which is exactly what a SOC tool should surface (a beta must never nudge a
//   CISO). During the current pre-release era every release is a pre-release, so
//   this endpoint returns 404 -- a valid "no stable release published yet" state,
//   not an error. It lights up when the first real release is cut. There is
//   deliberately NO configurable source URL: no dead-code / SSRF surface.
//
// PROPERTIES (gold-standard, CISO-defensible):
//   - Opt-in at the caller; this module checks only when asked.
//   - Host-pinned to api.github.com -- a literal constant, never from config.
//   - Zero telemetry: a plain unauthenticated GET with a User-Agent and Accept
//     header only; no request body, no query string, nothing about the
//     deployment leaves the host.
//   - Fail-safe: any network error, timeout, oversize body, or unexpected
//     response yields 'source_unreachable' -- NEVER a false 'none' (up to date).
//   - Anti-rollback: 'available' only when the latest tag is STRICTLY newer than
//     the running version; never reports a downgrade.
//   - No redirects followed (https.request follows none; a 3xx is treated as
//     unreachable), so the pinned host cannot be bounced elsewhere.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const https = require('https');

const UPDATE_HOST = 'api.github.com';
const UPDATE_PATH = '/repos/petermancina/firealive/releases/latest';
const USER_AGENT = 'FireAlive-UpdateCheck';
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2 MB cap; a release JSON is small

// ---- version parsing (regex-free, strict) ----------------------------------

function isAllDigits(str) {
  if (typeof str !== 'string' || str.length === 0) return false;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c < 48 || c > 57) return false;
  }
  return true;
}

// Parse a version into [major, minor, patch]. Strips a leading 'v' and any
// pre-release / build-metadata suffix ('-' or '+'). Returns null on anything
// malformed so a bad tag can never be read as an available update.
function parseVersion(value) {
  let s = (value === null || value === undefined) ? '' : String(value);
  s = s.trim();
  if (s.length > 0 && (s[0] === 'v' || s[0] === 'V')) s = s.slice(1);
  let cut = s.length;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '-' || s[i] === '+') { cut = i; break; }
  }
  s = s.slice(0, cut);
  if (s.length === 0) return null;
  const segs = s.split('.');
  const out = [];
  for (let i = 0; i < segs.length && i < 3; i++) {
    if (!isAllDigits(segs[i])) return null;
    out.push(Number(segs[i]));
  }
  while (out.length < 3) out.push(0);
  return out;
}

// True only when latest is strictly newer than current. Malformed input on
// either side returns false (fail-safe: never invent an update).
function isStrictlyNewer(latest, current) {
  const a = parseVersion(latest);
  const b = parseVersion(current);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) {
    if (a[i] > b[i]) return true;
    if (a[i] < b[i]) return false;
  }
  return false;
}

// ---- the pinned GET (mirrors the cloud-metadata.js request idiom) -----------

// Resolves { status, body } on a completed HTTP exchange, or null on a
// transport error / timeout / oversize response. Never rejects.
function fetchLatestRelease(timeoutMs) {
  return new Promise(function (resolve) {
    let settled = false;
    function finish(value) {
      if (!settled) { settled = true; resolve(value); }
    }
    let req;
    try {
      req = https.request(
        {
          method: 'GET',
          host: UPDATE_HOST,
          path: UPDATE_PATH,
          headers: {
            'User-Agent': USER_AGENT,
            'Accept': 'application/vnd.github+json',
          },
          timeout: timeoutMs,
        },
        function (res) {
          const status = res.statusCode || 0;
          const chunks = [];
          let bytes = 0;
          let aborted = false;
          res.on('data', function (chunk) {
            if (aborted) return;
            bytes += chunk.length;
            if (bytes > MAX_RESPONSE_BYTES) {
              aborted = true;
              try { req.destroy(); } catch (e) { /* ignore */ }
              finish(null);
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', function () {
            if (aborted) return;
            finish({ status: status, body: Buffer.concat(chunks).toString('utf8') });
          });
        }
      );
    } catch (e) {
      finish(null);
      return;
    }
    req.on('error', function () { finish(null); });
    req.on('timeout', function () {
      try { req.destroy(); } catch (e) { /* ignore */ }
      finish(null);
    });
    try { req.end(); } catch (e) { finish(null); }
  });
}

// ---- public API -------------------------------------------------------------

// checkForUpdate({ currentVersion, timeoutMs }) ->
//   { result, latestVersion, releaseUrl, releaseName, checkedAt }
//
//   result: 'none'               running the latest, OR no stable release
//                                published yet (a 404 during the pre-release era)
//           'available'          a strictly-newer stable release exists
//           'source_unreachable' network / timeout / unexpected response
//
//   latestVersion is the release tag verbatim (e.g. 'v1.0.79') when known.
//
// Pure check: performs no DB writes; the caller records the outcome.
async function checkForUpdate(options) {
  const opts = options || {};
  const currentVersion = opts.currentVersion;
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const checkedAt = new Date().toISOString();

  // Default outcome is the fail-safe one.
  const unreachable = {
    result: 'source_unreachable',
    latestVersion: null,
    releaseUrl: null,
    releaseName: null,
    checkedAt: checkedAt,
  };

  const resp = await fetchLatestRelease(timeoutMs);

  // Transport failure / timeout / oversize -> unreachable (never up to date).
  if (!resp) return unreachable;

  // No published stable release yet (all pre-releases / drafts) -> not an error.
  if (resp.status === 404) {
    return { result: 'none', latestVersion: null, releaseUrl: null, releaseName: null, checkedAt: checkedAt };
  }

  // Anything other than a clean 200 (incl. 3xx -- we follow nothing, 403
  // rate-limit, 5xx) -> unreachable, so the operator is never shown a false
  // 'current'.
  if (resp.status !== 200) return unreachable;

  let data;
  try {
    data = JSON.parse(resp.body);
  } catch (e) {
    return unreachable; // unparseable -> unreachable, not up to date
  }
  if (!data || typeof data !== 'object' || typeof data.tag_name !== 'string') {
    return unreachable;
  }

  const latestTag = data.tag_name;
  if (isStrictlyNewer(latestTag, currentVersion)) {
    return {
      result: 'available',
      latestVersion: latestTag,
      releaseUrl: (typeof data.html_url === 'string') ? data.html_url : null,
      releaseName: (typeof data.name === 'string' && data.name.length > 0) ? data.name : latestTag,
      checkedAt: checkedAt,
    };
  }

  // Running the latest, or the published tag is older / equal -> none.
  return { result: 'none', latestVersion: latestTag, releaseUrl: null, releaseName: null, checkedAt: checkedAt };
}

module.exports = {
  checkForUpdate,
  // exported for the regression dry-run (no-network version comparison) and tests
  parseVersion,
  isStrictlyNewer,
  UPDATE_HOST,
  UPDATE_PATH,
};

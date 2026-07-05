// FIREALIVE GD -- SDN degraded-posture fail-safe gate (B6c PR-4, read-only twin)
//
// Assume-breach lockdown. A loss of segmentation assurance is NOT treated as a
// merely lost defense-in-depth layer. It is treated as a possible active
// compromise of the network the GD sits on, and the correct response to a
// possible breach is to assume breach.
//
// While posture is "degraded" this gate denies the ENTIRE /api/ surface. There
// is no allow-list. A deny-all lockdown has:
//   - no forgotten-route hole (nothing is allow-open by omission),
//   - no new-trust surface (auth and enrollment are denied, so an attacker who
//     has gained the network position the degradation signals cannot establish
//     a new session or device),
//   - no in-band recovery surface (config and sdn writes are denied, so the
//     lockdown cannot be lifted or the fabric reconfigured from the network),
//   - no system state leaked to the network (even a health route runs a DB
//     query and returns version detail, so it stays dark too).
// Recovery is automatic: when posture is restored the lockdown lifts. A GD-side
// misconfiguration that keeps posture degraded is cleared out of band on the
// host; there is deliberately no remote path to clear the lockdown.
//
// Fail-secure: a fault reading posture is treated as degraded (deny), never as
// healthy. The GD posture is the event-derived latch (gd-sdn-mode.getPosture) --
// a binary degraded flag with no uncertain band, so it locks down on a confirmed
// degradation and passes otherwise.
//
// Mode-gated: a pure pass-through in bare-metal / virtualized / cloud /
// unconfigured mode. Mount globally on /api/, after the admission gate and
// before per-route auth, so a denied request never reaches auth or a handler.
//
// Read-only twin of the Regional middleware/sdn-fail-safe.js: posture comes from
// gd-sdn-mode's event-derived latch (the Regional controller-probing state
// machine is not part of the read-only GD), and mode comes from
// gd-deployment-mode (a DB read, mode-cached) rather than app.locals.
//
// ASCII only; no template literals.

const logger = {
  warn: (m, o) => console.warn('[gd-sdn-fail-safe] ' + m, o || ''),
  info: (m, o) => console.log('[gd-sdn-fail-safe] ' + m, o || ''),
  error: (m, o) => console.error('[gd-sdn-fail-safe] ' + m, o || ''),
};
const { getDb } = require('../db-init');
const sdnMode = require('./gd-sdn-mode');
const deploymentMode = require('./gd-deployment-mode');

// Backoff hint for clients on the 503. Security-neutral.
const RETRY_AFTER_SECONDS = 30;

// Throttle the "gate is denying traffic" log so a sustained lockdown under load
// cannot flood the log. The degradation itself is already recorded as a posture
// event; this log is only an operator breadcrumb.
const DENY_LOG_THROTTLE_MS = 60 * 1000;
let lastDenyLogAt = 0;

const MODE_CACHE_TTL_MS = 30 * 1000;
let modeCache = { isSdn: false, loadedAt: 0 };

// Highest-security posture: the set of paths reachable while degraded is EMPTY.
// Deny-by-default with an empty allow-list denies every /api/ route during a
// suspected breach and cannot leave a route allow-open by omission. This frozen
// constant is the single, auditable extension point.
const DEGRADED_REACHABLE = Object.freeze([]);

// Segment-boundary prefix match: an entry "/api/x" matches "/api/x" and
// "/api/x/..." but never "/api/x-evil". With DEGRADED_REACHABLE empty this
// always returns false (deny everything); it stays correct for any future entry.
function isReachableWhileDegraded(path) {
  for (let i = 0; i < DEGRADED_REACHABLE.length; i++) {
    const entry = DEGRADED_REACHABLE[i];
    if (path === entry) return true;
    if (path.indexOf(entry + '/') === 0) return true;
  }
  return false;
}

// originalUrl is the full path at the app.use('/api/') mount; strip any query.
function requestPath(req) {
  const raw = (req && (req.originalUrl || req.url)) || '';
  const q = raw.indexOf('?');
  return q === -1 ? raw : raw.slice(0, q);
}

// The GD reads its deployment mode from the DB (via gd-deployment-mode), not
// app.locals; caching it keeps the per-request gate off the DB in non-sdn modes.
// Fail-safe: on error, keep the last-known value.
function refreshMode() {
  let db;
  try {
    db = getDb();
    modeCache = { isSdn: !!deploymentMode.isSdn(db), loadedAt: Date.now() };
  } catch (err) {
    modeCache = { isSdn: modeCache.isSdn, loadedAt: Date.now() };
    logger.warn('SDN fail-safe mode refresh failed; keeping last-known mode', { error: err.message });
  } finally {
    if (db) { try { db.close(); } catch (_e) { /* ignore */ } }
  }
}

function isSdnMode() {
  if (Date.now() - modeCache.loadedAt > MODE_CACHE_TTL_MS) refreshMode();
  return modeCache.isSdn;
}

function denyLockedDown(res) {
  const now = Date.now();
  if (now - lastDenyLogAt > DENY_LOG_THROTTLE_MS) {
    lastDenyLogAt = now;
    logger.warn('SDN posture is degraded; fail-safe gate is denying all /api/ traffic until posture is restored');
  }
  return res
    .status(503)
    .set('Retry-After', String(RETRY_AFTER_SECONDS))
    .json({ error: 'service_unavailable' });
}

function sdnFailSafe() {
  return function (req, res, next) {
    // Only sdn mode runs posture-based lockdown; every other mode passes through.
    if (!isSdnMode()) return next();

    let posture;
    let db;
    try {
      db = getDb();
      posture = sdnMode.getPosture(db);
    } catch (err) {
      // Fail secure: a fault reading posture is treated as degraded, never as
      // healthy -- lock down.
      logger.warn('SDN fail-safe could not read posture; failing secure (locking down)', { error: err.message });
      if (db) { try { db.close(); } catch (_e) { /* ignore */ } }
      return denyLockedDown(res);
    }
    if (db) { try { db.close(); } catch (_e) { /* ignore */ } }

    // Only a confirmed degradation locks down; a healthy latch passes.
    if (!posture || !posture.degraded) return next();

    const path = requestPath(req);
    if (isReachableWhileDegraded(path)) return next();

    return denyLockedDown(res);
  };
}

module.exports = {
  sdnFailSafe,
  _isReachableWhileDegraded: isReachableWhileDegraded,
  _degradedReachable: DEGRADED_REACHABLE,
  _refreshMode: refreshMode,
};

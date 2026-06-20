// FIREALIVE -- SASE degraded-posture fail-safe gate (B5k SASE Mode)
//
// Assume-breach lockdown. The SASE posture (services/sase-mode.js) latches
// degraded the moment a dark-app or passthrough boundary failure is observed -- a
// direct (non-connector) connection reaching FireAlive, or a clientless /
// TLS-terminating edge detected by its identity header. That is not treated as a
// merely lost defense-in-depth layer; it is evidence FireAlive is reachable off
// the sanctioned path or that analyst device certificates are being stripped, and
// the correct response to a possible breach is to assume breach.
//
// While posture is degraded this gate denies the ENTIRE /api/ surface. There is
// no allow-list. A deny-all lockdown has:
//   - no forgotten-route hole (nothing is allow-open by omission),
//   - no new-trust surface (auth and enrollment are denied, so an attacker in the
//     network position the degradation signals cannot establish a new session or
//     device),
//   - no in-band recovery surface (config and sase writes are denied, so the
//     lockdown cannot be lifted from the network),
//   - no system state leaked to the network (even /api/system/health runs a DB
//     query and returns version detail, so it stays dark too).
// Unlike a probe-driven control, an observed boundary breach does not "un-happen":
// recovery is NOT automatic. The operator closes the exposure (or removes the
// TLS-terminating edge) and records an explicit posture_restored out of band on
// the host; there is deliberately no remote path to clear the lockdown.
//
// Fail-secure: a fault reading posture is treated as degraded (deny), never as
// healthy. The latch is itself the anti-flap mechanism -- SASE posture has no
// "uncertain" middle state because its triggers are discrete, definitive events,
// not noisy probes, so there is nothing to debounce and nothing to flap.
//
// Mode-gated: a pure pass-through in bare-metal / virtualized / cloud / sdn /
// unconfigured mode. Mount globally on /api/, after the admission gate and before
// per-route auth, so a denied request never reaches auth or a handler.
//
// ASCII only; no template literals.

const { logger } = require('../services/logger');
const { getDb } = require('../db/init');
const saseMode = require('../services/sase-mode');

// Backoff hint for clients on the 503. Security-neutral.
const RETRY_AFTER_SECONDS = 30;

// Throttle the "gate is denying traffic" log so a sustained lockdown under load
// cannot flood the log. The degradation itself is already recorded in the posture
// log; this log is only an operator breadcrumb.
const DENY_LOG_THROTTLE_MS = 60 * 1000;
let lastDenyLogAt = 0;

// Highest-security posture: the set of paths reachable while degraded is EMPTY.
// Deny-by-default with an empty allow-list denies every /api/ route during a
// suspected breach and cannot leave a route allow-open by omission. This frozen
// constant is the single, auditable extension point -- a future operator decision
// to expose a strict liveness path would add it here, and only here.
const DEGRADED_REACHABLE = Object.freeze([]);

// Segment-boundary prefix match: an entry "/api/x" matches "/api/x" and
// "/api/x/..." but never "/api/x-evil". With DEGRADED_REACHABLE empty this always
// returns false (deny everything); it stays correct for any future entry.
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

function denyLockedDown(res) {
  const now = Date.now();
  if (now - lastDenyLogAt > DENY_LOG_THROTTLE_MS) {
    lastDenyLogAt = now;
    logger.warn('SASE posture is degraded; fail-safe gate is denying all /api/ traffic until posture is restored');
  }
  return res
    .status(503)
    .set('Retry-After', String(RETRY_AFTER_SECONDS))
    .json({ error: 'service_unavailable' });
}

function saseFailSafe() {
  return function (req, res, next) {
    let mode;
    try {
      mode = (req.app && req.app.locals && req.app.locals.deploymentMode) || {};
    } catch (_e) {
      mode = {};
    }
    // Only sase mode runs posture-based lockdown; every other mode passes through.
    if (!mode.sase) return next();

    let degraded;
    let db;
    try {
      db = getDb();
      degraded = saseMode.getPosture(db).degraded === true;
    } catch (err) {
      // Fail secure: a fault reading posture is treated as degraded, never as
      // healthy -- lock down.
      logger.warn('SASE fail-safe could not read posture; failing secure (locking down)', { error: err.message });
      if (db) { try { db.close(); } catch (_e) { /* ignore */ } }
      return denyLockedDown(res);
    }
    if (db) { try { db.close(); } catch (_e) { /* ignore */ } }

    // The latch is the anti-flap mechanism: degraded means a definitive boundary
    // breach was observed and has not been cleared by an explicit host-side
    // restore, so there is no "uncertain" middle state to pass.
    if (!degraded) return next();

    const path = requestPath(req);
    if (isReachableWhileDegraded(path)) return next();

    return denyLockedDown(res);
  };
}

module.exports = {
  saseFailSafe,
  _isReachableWhileDegraded: isReachableWhileDegraded,
  _degradedReachable: DEGRADED_REACHABLE,
};

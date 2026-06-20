// FIREALIVE -- SDN degraded-posture fail-safe gate (B5i SDN Mode)
//
// Assume-breach lockdown (D-B5i-5). The SDN posture state machine
// (services/sdn-posture.js) watches the operator's SDN integrations. A loss of
// segmentation assurance -- the controller unreachable or unauthenticated, or
// segmentation observed to have changed -- is NOT treated as a merely lost
// defense-in-depth layer. It is treated as a possible active compromise of the
// network FireAlive sits on, and the correct response to a possible breach is
// to assume breach.
//
// While aggregate posture is "degraded" this gate denies the ENTIRE /api/
// surface. There is no allow-list. A deny-all lockdown has:
//   - no forgotten-route hole (nothing is allow-open by omission),
//   - no new-trust surface (auth and enrollment are denied, so an attacker who
//     has gained the network position the degradation signals cannot establish
//     a new session or device),
//   - no in-band recovery surface (config and sdn writes are denied, so the
//     lockdown cannot be lifted or the fabric reconfigured from the network),
//   - no system state leaked to the network (even /api/system/health runs a DB
//     query and returns version detail, so it stays dark too).
// Recovery is automatic: when the SDN is repaired the probes succeed, the state
// machine restores posture, and the lockdown lifts. A FireAlive-side
// misconfiguration that keeps the probes failing is cleared out of band on the
// host; there is deliberately no remote path to clear the lockdown.
//
// Fail-secure: a fault reading posture is treated as degraded (deny), never as
// healthy. Only a confirmed "degraded" locks down -- "uncertain" passes,
// because the state machine's debounce/hysteresis governs the
// uncertain->degraded transition, so a transient probe blip does not flap the
// whole platform into a self-inflicted outage.
//
// Mode-gated: a pure pass-through in bare-metal / virtualized / cloud /
// unconfigured mode. Mount globally on /api/, after the admission gate and
// before per-route auth, so a denied request never reaches auth or a handler.
//
// ASCII only; no template literals.

const { logger } = require('../services/logger');
const { getDb } = require('../db/init');
const sdnPosture = require('../services/sdn-posture');

// Backoff hint for clients on the 503. Security-neutral.
const RETRY_AFTER_SECONDS = 30;

// Throttle the "gate is denying traffic" log so a sustained lockdown under load
// cannot flood the log. The degradation itself is already recorded by the state
// machine as a posture event; this log is only an operator breadcrumb.
const DENY_LOG_THROTTLE_MS = 60 * 1000;
let lastDenyLogAt = 0;

// Highest-security posture (D-B5i-5): the set of paths reachable while degraded
// is EMPTY. Deny-by-default with an empty allow-list denies every /api/ route
// during a suspected breach and cannot leave a route allow-open by omission.
// This frozen constant is the single, auditable extension point -- a future
// operator decision to expose a strict liveness path would add it here, and
// only here.
const DEGRADED_REACHABLE = Object.freeze([]);

// Segment-boundary prefix match: an entry "/api/x" matches "/api/x" and
// "/api/x/..." but never "/api/x-evil". With DEGRADED_REACHABLE empty this
// always returns false (deny everything); it stays correct for any future
// entry.
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
    logger.warn('SDN posture is degraded; fail-safe gate is denying all /api/ traffic until posture is restored');
  }
  return res
    .status(503)
    .set('Retry-After', String(RETRY_AFTER_SECONDS))
    .json({ error: 'service_unavailable' });
}

function sdnFailSafe() {
  return function (req, res, next) {
    let mode;
    try {
      mode = (req.app && req.app.locals && req.app.locals.deploymentMode) || {};
    } catch (_e) {
      mode = {};
    }
    // Only sdn mode runs posture-based lockdown; every other mode passes through.
    if (!mode.sdn) return next();

    let state;
    let db;
    try {
      db = getDb();
      state = sdnPosture.currentPosture(db);
    } catch (err) {
      // Fail secure: a fault reading posture is treated as degraded, never as
      // healthy -- lock down.
      logger.warn('SDN fail-safe could not read posture; failing secure (locking down)', { error: err.message });
      if (db) { try { db.close(); } catch (_e) { /* ignore */ } }
      return denyLockedDown(res);
    }
    if (db) { try { db.close(); } catch (_e) { /* ignore */ } }

    // Only a confirmed "degraded" locks down. "healthy" and "uncertain" pass:
    // the debounce/hysteresis in the state machine governs the
    // uncertain->degraded transition, so a transient blip does not flap the
    // platform into lockdown.
    if (state !== 'degraded') return next();

    const path = requestPath(req);
    if (isReachableWhileDegraded(path)) return next();

    return denyLockedDown(res);
  };
}

module.exports = {
  sdnFailSafe,
  _isReachableWhileDegraded: isReachableWhileDegraded,
  _degradedReachable: DEGRADED_REACHABLE,
};

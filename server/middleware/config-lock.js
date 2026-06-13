// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Config Lock Gate Middleware
//
// SOC-grade gate that refuses config-modifying requests with 423 Locked
// when config_lock_state.lock_active = 1. Applied at the route mount
// level in server/index.js for any route whose POST / PUT / PATCH /
// DELETE operations are considered "config changes" (KMS provider
// switch, GD push config, HR integration credentials, IAM role
// changes, audit log retention policy, integration onboarding, etc.).
//
// USAGE
//
//   const { configLockGate } = require('../middleware/config-lock');
//
//   // Apply at the route mount:
//   app.use('/api/kms-providers',
//     authMiddleware(['admin']),
//     configLockGate(),
//     require('./routes/kms-providers')
//   );
//
//   // Or per-route within a router file (where only specific
//   // operations are gated):
//   router.post('/rotate', configLockGate(), handler);
//
// SAFE-METHOD PASS-THROUGH
//
//   The middleware passes through GET, HEAD, and OPTIONS requests
//   unconditionally. Rationale:
//
//   - Reads are observability, not modification. Locking the
//     platform should not blind the admin to current config state
//     -- they still need to inspect KMS provider settings, GD push
//     config, audit logs, etc. to verify what they're looking at
//     before deciding to unlock.
//   - OPTIONS is CORS preflight; blocking it would break the
//     browser's ability to even reach the resource to determine
//     it's locked.
//   - HEAD is read-equivalent.
//
//   Mutating methods (POST, PUT, PATCH, DELETE) are gated when
//   lock_active = 1. The actual auth-level restriction (admin
//   role only) still applies via the authMiddleware applied
//   earlier in the chain; this gate is the ADDITIONAL SoD-aligned
//   restriction that says "even if you're admin, while the
//   platform is locked, you cannot make changes."
//
// RESPONSE SHAPE — 423 Locked
//
//   {
//     "error": "Configuration is locked. Unlock with admin MFA to proceed.",
//     "code": "CONFIG_LOCKED",
//     "locked_at": 1700000000000
//   }
//
//   The 423 body deliberately does NOT include locked_by_user_id /
//   locked_by_name. Avoid leaking user attribution information at
//   the refusal boundary -- the GET /api/config/lock endpoint
//   exposes that attribution for admins viewing the lock status
//   page, but a refusal to a config-change request does not need
//   to identify who locked it.
//
// AUDIT EVENT
//
//   CONFIG_LOCK_GATE_HIT
//
//   Emitted on every refused mutating request, with detail
//   "path=<METHOD> <path>". Used for forensic reconstruction of
//   what users attempted to change while the platform was locked
//   and for detecting anomalous activity (e.g., a compromised
//   admin account making repeated change attempts).
//
// SINGLETON-MISSING HANDLING (DEFENSIVE)
//
//   If config_lock_state has no row with id = 1, something is
//   seriously wrong with the deployment (init.js seeds the
//   singleton on every server start with ON CONFLICT DO NOTHING,
//   so this should never happen unless the row was manually
//   deleted or the database is corrupted). Fail-safe: refuse the
//   request with 423 + CONFIG_LOCK_STATE_MISSING code.
//
//   Recovery from this state requires direct DB intervention
//   (re-running init.js or manually INSERTing the singleton row)
//   plus calling POST /api/config/lock to set the desired state.
//   The POST endpoint has its own missing-singleton handling
//   (returns 500 STATE_NOT_INITIALIZED) and does NOT go through
//   this gating middleware, so the lock-toggle recovery path is
//   not itself blocked by the missing singleton.
//
// DB ERROR HANDLING (DEFENSIVE)
//
//   On unexpected DB query error, fail-safe with 500 -- do NOT
//   let the request through. Letting through on error would mean
//   that DB issues silently bypass the lock gate, which is
//   exactly the kind of edge-case bypass an attacker might
//   exploit by triggering DB-load conditions. Fail closed.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { auditLog } = require('./audit');
const { logger } = require('../services/logger');
const { isConfigWriteRequest } = require('./config-write-routes');
const { readInstanceStatus } = require('./quarantine-guard');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Factory for the config-lock gating middleware. Options:
 *
 *   eventDetail   Optional string appended to the audit event detail
 *                  when the gate fires. Useful for distinguishing
 *                  WHICH gated route triggered the event when
 *                  req.path alone is ambiguous (e.g., when applied
 *                  at a mount that contains multiple sub-paths).
 *                  Most callers can omit this -- req.path is
 *                  already in the audit detail.
 */
function configLockGate(options = {}) {
  const { eventDetail } = options;

  return function configLockGateMiddleware(req, res, next) {
    // Safe methods always pass through.
    if (SAFE_METHODS.has(req.method)) {
      return next();
    }

    // B5e (decision D5): a quarantined deployment -- one where a clone, fork,
    // or rollback was detected -- must not change configuration. Placing this
    // inside the config-write chokepoint covers every config-write route at
    // once. Fail-open on a status-read error (logged): do not block config
    // writes on a transient read fault; the boot halt and quarantine alert are
    // the primary controls.
    try {
      if (readInstanceStatus() === 'quarantined') {
        auditLog(
          req.user ? req.user.id : null,
          'CONFIG_WRITE_REFUSED_QUARANTINED',
          `path=${req.method} ${req.path}` + (eventDetail ? ` ${eventDetail}` : ''),
          req.ip
        );
        return res.status(403).json({
          error: 'This deployment is quarantined because a possible clone, fork, or rollback was detected. Configuration changes are disabled until the instance identity is re-established.',
          code: 'INSTANCE_QUARANTINED',
        });
      }
    } catch (quarantineErr) {
      logger.warn('Quarantine status check failed in config-lock gate; allowing', { error: quarantineErr.message });
    }

    const db = getDb();
    try {
      const row = db.prepare(
        'SELECT lock_active, locked_at FROM config_lock_state WHERE id = 1'
      ).get();

      if (!row) {
        // Singleton missing -- DB in a broken state. Fail-safe.
        logger.error(
          'config_lock_state singleton row missing; refusing gated route',
          { path: req.path, method: req.method }
        );
        auditLog(
          req.user ? req.user.id : null,
          'CONFIG_LOCK_GATE_HIT',
          `path=${req.method} ${req.path} reason=singleton_missing` +
            (eventDetail ? ` ${eventDetail}` : ''),
          req.ip
        );
        return res.status(423).json({
          error: 'Configuration lock state is not initialized; cannot verify lock state.',
          code: 'CONFIG_LOCK_STATE_MISSING',
        });
      }

      if (row.lock_active === 1) {
        // Locked -- refuse the mutating request.
        auditLog(
          req.user ? req.user.id : null,
          'CONFIG_LOCK_GATE_HIT',
          `path=${req.method} ${req.path}` +
            (eventDetail ? ` ${eventDetail}` : ''),
          req.ip
        );
        return res.status(423).json({
          error: 'Configuration is locked. Unlock with admin MFA to proceed.',
          code: 'CONFIG_LOCKED',
          locked_at: row.locked_at,
        });
      }

      // Unlocked -- proceed.
      return next();
    } catch (err) {
      // DB error -- fail-safe with 500. Do NOT let the request through.
      logger.error('configLockGate middleware error', {
        error: err.message,
        path: req.path,
        method: req.method,
      });
      return res.status(500).json({
        error: 'Internal error checking config lock state',
      });
    } finally {
      db.close();
    }
  };
}

/**
 * Registry-aware single chokepoint for the config lock.
 *
 * Unlike configLockGate (applied per config-only mount), this middleware is
 * driven by the config-write route registry and may be applied broadly: it
 * gates ONLY requests that isConfigWriteRequest() identifies as configuration
 * changes, and passes everything else (reads, operational mutations) straight
 * through. This is what lets it sit in front of the mixed feature routers
 * (v021-v030), where config writes and operational actions share the /api
 * mount, without blocking operations while the platform is locked.
 *
 * IDLE AUTO-RELOCK
 *
 *   An admin unlock starts a sliding idle window (config_lock_state
 *   .auto_relock_at). On each allowed config write the window slides forward
 *   by idle_minutes. If the window elapses, the next config write re-locks the
 *   platform (CONFIG_LOCK_AUTO_RELOCK audit event) and is refused, so a walked-
 *   away-from admin session cannot leave configuration writable indefinitely.
 *
 *   A platform that has never been locked (auto_relock_at IS NULL while
 *   unlocked) is not subject to idle relock -- config writes pass until an
 *   admin engages the lock at least once.
 *
 * Path resolution uses req.originalUrl (mount-independent), minus query string.
 */
function configLockChokepoint(options = {}) {
  const { eventDetail } = options;

  return function configLockChokepointMiddleware(req, res, next) {
    const fullPath = (req.originalUrl || req.url || '').split('?')[0];

    // Only configuration-changing requests are gated.
    if (!isConfigWriteRequest(req.method, fullPath)) {
      return next();
    }

    const db = getDb();
    try {
      const row = db.prepare(
        'SELECT lock_active, locked_at, auto_relock_at, idle_minutes ' +
          'FROM config_lock_state WHERE id = 1'
      ).get();

      if (!row) {
        logger.error(
          'config_lock_state singleton row missing; refusing config write',
          { path: fullPath, method: req.method }
        );
        auditLog(
          req.user ? req.user.id : null,
          'CONFIG_LOCK_GATE_HIT',
          `path=${req.method} ${fullPath} reason=singleton_missing` +
            (eventDetail ? ` ${eventDetail}` : ''),
          req.ip
        );
        return res.status(423).json({
          error: 'Configuration lock state is not initialized; cannot verify lock state.',
          code: 'CONFIG_LOCK_STATE_MISSING',
        });
      }

      const now = Date.now();

      // Idle auto-relock: an unlocked session whose sliding window has elapsed
      // re-locks before the next config change is allowed.
      if (
        row.lock_active === 0 &&
        row.auto_relock_at !== null &&
        row.auto_relock_at !== undefined &&
        now >= row.auto_relock_at
      ) {
        db.prepare(
          'UPDATE config_lock_state SET lock_active = 1, locked_at = ?, ' +
            'auto_relock_at = NULL, locked_by_user_id = NULL WHERE id = 1'
        ).run(now);
        auditLog(
          null,
          'CONFIG_LOCK_AUTO_RELOCK',
          `idle_minutes=${row.idle_minutes} relocked_at=${now}` +
            (eventDetail ? ` ${eventDetail}` : ''),
          req.ip
        );
        auditLog(
          req.user ? req.user.id : null,
          'CONFIG_LOCK_GATE_HIT',
          `path=${req.method} ${fullPath} reason=idle_auto_relock` +
            (eventDetail ? ` ${eventDetail}` : ''),
          req.ip
        );
        return res.status(423).json({
          error: 'Configuration auto-relocked after idle timeout. Unlock with admin MFA to proceed.',
          code: 'CONFIG_LOCKED',
          locked_at: now,
          reason: 'idle_auto_relock',
        });
      }

      // Explicitly locked.
      if (row.lock_active === 1) {
        auditLog(
          req.user ? req.user.id : null,
          'CONFIG_LOCK_GATE_HIT',
          `path=${req.method} ${fullPath}` +
            (eventDetail ? ` ${eventDetail}` : ''),
          req.ip
        );
        return res.status(423).json({
          error: 'Configuration is locked. Unlock with admin MFA to proceed.',
          code: 'CONFIG_LOCKED',
          locked_at: row.locked_at,
        });
      }

      // Unlocked. Inside an active unlock session, slide the idle window
      // forward on this allowed config write.
      if (row.auto_relock_at !== null && row.auto_relock_at !== undefined) {
        const idleMs = Math.max(1, Number(row.idle_minutes) || 15) * 60 * 1000;
        db.prepare(
          'UPDATE config_lock_state SET auto_relock_at = ? WHERE id = 1'
        ).run(now + idleMs);
      }

      return next();
    } catch (err) {
      logger.error('configLockChokepoint middleware error', {
        error: err.message,
        path: fullPath,
        method: req.method,
      });
      return res.status(500).json({
        error: 'Internal error checking config lock state',
      });
    } finally {
      db.close();
    }
  };
}

module.exports = { configLockGate, configLockChokepoint };

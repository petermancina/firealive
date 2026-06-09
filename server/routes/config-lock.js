// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Config Lock Routes
//
// SOC-grade admin-only gate over platform-config-modifying routes. When
// config_lock_state.lock_active = 1, all gated routes (KMS provider
// switch, GD push config, HR integration credentials, IAM role changes,
// audit log purges, integration onboarding) refuse with 423 Locked
// until an admin unlocks via POST /api/config/lock with fresh MFA
// proof. The gating middleware lives in server/middleware/config-lock.js
// (subsequent commit); this file handles only the lock-state read +
// toggle endpoints.
//
// ENDPOINTS
//
//   GET  /api/config/lock     read current lock state (any
//                              authenticated user; AC/MC use this to
//                              render lock-state across config UI)
//   POST /api/config/lock     toggle lock state (admin role + a fresh
//                              WebAuthn step-up assertion; body
//                              specifies action and body.stepup)
//
// REQUEST SHAPE — POST
//
//   {
//     "action": "lock" | "unlock",
//     "stepup": {
//       "challengeToken": "<jwt from POST /api/mfa/stepup/options>",
//       "response":       { <PublicKeyCredential assertion JSON> }
//     }
//   }
//
// RESPONSE SHAPE — GET / successful POST
//
//   {
//     "lock_active": true | false,
//     "locked_by_user_id": "user-..." | null,
//     "locked_by_name": "Alice Admin" | null,    // GET only; joined from users
//     "locked_at": 1700000000000 | null,
//     "last_mfa_verified_at": 1700000000000 | null
//   }
//
// ERROR CODES
//
//   400 INVALID_ACTION             action neither "lock" nor "unlock"
//   401 MFA_STEPUP_REQUIRED        no step-up assertion in body.stepup
//                                   (mfaStepUp middleware returns this;
//                                   the client must fetch a challenge
//                                   from /api/mfa/stepup/options, sign
//                                   it, and resend)
//   400 INVALID_INPUT              malformed body.stepup / assertion
//                                   (mfaStepUp middleware)
//   401 STEPUP_FAILED              unknown or foreign credential, or the
//                                   assertion failed verification
//                                   (mfaStepUp middleware)
//   403 INSUFFICIENT_ROLE          authenticated but role != 'admin'.
//                                   Writes CONFIG_LOCK_BYPASS_ATTEMPT
//                                   audit event before responding.
//   409 ALREADY_IN_STATE           lock already in requested state
//                                   (e.g., POST action=lock when
//                                   lock_active=1 already)
//   500 STATE_NOT_INITIALIZED      singleton row missing (should never
//                                   occur post-init; defensive)
//
// AUDIT EVENTS
//
//   CONFIG_LOCK_ENABLED            successful lock; method=webauthn
//   CONFIG_LOCK_DISABLED           successful unlock; method=webauthn
//   CONFIG_LOCK_BYPASS_ATTEMPT     non-admin attempted POST
//
// SoD NOTE
//
//   Lock toggle is admin-only. Lead role can supervise shifts and
//   manage analysts but cannot change platform configuration. This
//   matches SOC 2 Separation of Duties norms: the role that runs
//   incident response (lead) is distinct from the role that
//   administers platform settings (admin). Smaller SOCs where one
//   person wears both hats assign role='admin' at user setup.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { authMiddleware } = require('../middleware/auth');
const { mfaStepUp } = require('../middleware/mfa-stepup');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── Inline role gate ────────────────────────────────────────────────────────
//
// Sits between authMiddleware and mfaStepUp in the chain so that:
//   1. Non-admin requests are refused before any step-up processing,
//      eliminating a credential-probing surface for non-admin accounts.
//   2. The refusal emits CONFIG_LOCK_BYPASS_ATTEMPT to the audit log,
//      not just a logger.warn (authMiddleware's role gate emits only
//      logger.warn; for this SOC-grade event we want the structured
//      audit trail).
//
// This pattern -- inline role check after authMiddleware() -- matches
// the existing convention in routes/resources.js and routes/ooda.js.

function adminOnlyWithAudit(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    auditLog(
      req.user ? req.user.id : null,
      'CONFIG_LOCK_BYPASS_ATTEMPT',
      `role=${req.user ? req.user.role : 'unknown'}`,
      req.ip
    );
    return res.status(403).json({
      error: 'Admin role required to modify config lock state',
      code: 'INSUFFICIENT_ROLE',
    });
  }
  next();
}

// ── GET /api/config/lock ────────────────────────────────────────────────────
//
// Read current lock state. Any authenticated user can read this --
// the AC and MC use it to render lock-state across the config UI
// (greying out disabled buttons, showing "locked by X" banners). No
// role restriction.

router.get('/lock', authMiddleware(), (req, res) => {
  const db = getDb();
  try {
    const row = db.prepare(`
      SELECT
        cls.id,
        cls.lock_active,
        cls.locked_by_user_id,
        cls.locked_at,
        cls.last_mfa_verified_at,
        cls.auto_relock_at,
        cls.idle_minutes,
        u.name AS locked_by_name
      FROM config_lock_state cls
      LEFT JOIN users u ON u.id = cls.locked_by_user_id
      WHERE cls.id = 1
    `).get();

    if (!row) {
      logger.error('config_lock_state singleton row missing -- DB not initialized correctly');
      return res.status(500).json({
        error: 'Config lock state not initialized',
        code: 'STATE_NOT_INITIALIZED',
      });
    }

    const now = Date.now();
    // Idle auto-relock reconciliation: an unlocked platform whose sliding
    // window has elapsed re-locks here too, so the reported state stays
    // accurate even when no config write has occurred since expiry.
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
      auditLog(null, 'CONFIG_LOCK_AUTO_RELOCK',
        `idle_minutes=${row.idle_minutes} relocked_at=${now} source=status`, req.ip);
      row.lock_active = 1;
      row.locked_at = now;
      row.auto_relock_at = null;
      row.locked_by_user_id = null;
      row.locked_by_name = null;
    }

    return res.json({
      lock_active: row.lock_active === 1,
      locked_by_user_id: row.locked_by_user_id,
      locked_by_name: row.locked_by_name,
      locked_at: row.locked_at,
      last_mfa_verified_at: row.last_mfa_verified_at,
      auto_relock_at: row.auto_relock_at,
      idle_minutes: row.idle_minutes,
    });
  } catch (err) {
    logger.error('config-lock GET error', { error: err.message });
    return res.status(500).json({ error: 'Internal error' });
  } finally {
    db.close();
  }
});

// ── POST /api/config/lock ───────────────────────────────────────────────────
//
// Toggle lock state. Admin role + a fresh user-verified WebAuthn
// step-up assertion both required. Middleware chain:
//
//   1. authMiddleware()         -- require any authenticated user
//   2. adminOnlyWithAudit       -- require role='admin', emit
//                                   CONFIG_LOCK_BYPASS_ATTEMPT on
//                                   role mismatch
//   3. mfaStepUp()              -- require a fresh user-verified
//                                   WebAuthn assertion (body.stepup);
//                                   sets req.mfaStepUp.method
//                                   ('webauthn') on success
//   4. handler                  -- perform state transition + audit
//                                   log + return updated state
//
// Idempotency: requests that ask for the current state respond with
// 409 ALREADY_IN_STATE rather than silently succeeding. This lets
// the client distinguish "I changed the state" from "nothing
// happened" without ambiguity.

router.post('/lock',
  authMiddleware(),
  adminOnlyWithAudit,
  mfaStepUp(),
  (req, res) => {
    const { action } = req.body || {};

    if (action !== 'lock' && action !== 'unlock') {
      return res.status(400).json({
        error: 'action must be "lock" or "unlock"',
        code: 'INVALID_ACTION',
      });
    }

    // Optional admin-configurable idle window (minutes) before auto-relock.
    let idleMinutes = null;
    if (req.body && req.body.idle_minutes !== undefined && req.body.idle_minutes !== null) {
      idleMinutes = Number(req.body.idle_minutes);
      if (!Number.isInteger(idleMinutes) || idleMinutes < 1 || idleMinutes > 1440) {
        return res.status(400).json({
          error: 'idle_minutes must be an integer between 1 and 1440',
          code: 'INVALID_IDLE_MINUTES',
        });
      }
    }

    const db = getDb();
    try {
      const current = db.prepare(
        'SELECT lock_active, auto_relock_at, idle_minutes FROM config_lock_state WHERE id = 1'
      ).get();

      if (!current) {
        logger.error('config_lock_state singleton row missing on POST');
        return res.status(500).json({
          error: 'Config lock state not initialized',
          code: 'STATE_NOT_INITIALIZED',
        });
      }

      const now = Date.now();
      // Effective lock state accounts for an elapsed idle window: an unlocked
      // platform past its auto_relock_at is already effectively locked.
      const effectivelyLocked =
        current.lock_active === 1 ||
        (current.auto_relock_at !== null &&
          current.auto_relock_at !== undefined &&
          now >= current.auto_relock_at);
      const wantsLocked = action === 'lock';

      if (effectivelyLocked === wantsLocked) {
        return res.status(409).json({
          error: `Config is already ${effectivelyLocked ? 'locked' : 'unlocked'}`,
          code: 'ALREADY_IN_STATE',
        });
      }

      // Idle window to apply: the explicit override if supplied, else the
      // currently stored value (default 15).
      const effectiveIdle = idleMinutes !== null
        ? idleMinutes
        : (Number(current.idle_minutes) || 15);
      const autoRelockAt = wantsLocked ? null : now + effectiveIdle * 60 * 1000;

      db.prepare(`
        UPDATE config_lock_state
        SET lock_active = ?,
            locked_by_user_id = ?,
            locked_at = ?,
            last_mfa_verified_at = ?,
            auto_relock_at = ?,
            idle_minutes = ?
        WHERE id = 1
      `).run(
        wantsLocked ? 1 : 0,
        wantsLocked ? req.user.id : null,
        wantsLocked ? now : null,
        now,
        autoRelockAt,
        effectiveIdle
      );

      const eventName = wantsLocked ? 'CONFIG_LOCK_ENABLED' : 'CONFIG_LOCK_DISABLED';
      const eventDetail = wantsLocked
        ? `method=${req.mfaStepUp.method}`
        : `method=${req.mfaStepUp.method} idle_minutes=${effectiveIdle}`;
      auditLog(req.user.id, eventName, eventDetail, req.ip);

      const updated = db.prepare(`
        SELECT
          cls.lock_active,
          cls.locked_by_user_id,
          cls.locked_at,
          cls.last_mfa_verified_at,
          cls.auto_relock_at,
          cls.idle_minutes,
          u.name AS locked_by_name
        FROM config_lock_state cls
        LEFT JOIN users u ON u.id = cls.locked_by_user_id
        WHERE cls.id = 1
      `).get();

      return res.json({
        lock_active: updated.lock_active === 1,
        locked_by_user_id: updated.locked_by_user_id,
        locked_by_name: updated.locked_by_name,
        locked_at: updated.locked_at,
        last_mfa_verified_at: updated.last_mfa_verified_at,
        auto_relock_at: updated.auto_relock_at,
        idle_minutes: updated.idle_minutes,
      });
    } catch (err) {
      logger.error('config-lock POST error', {
        error: err.message,
        userId: req.user.id,
        action,
      });
      return res.status(500).json({ error: 'Internal error' });
    } finally {
      db.close();
    }
  }
);

module.exports = router;

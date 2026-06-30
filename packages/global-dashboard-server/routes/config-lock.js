// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Config Lock Routes (B6a)
//
// GD twin of the regional config-lock routes -- the lock-state read + toggle
// endpoints. The gating middleware is services/gd-config-lock.js; this file is
// the recovery surface and is deliberately NOT behind the chokepoint (the
// matcher exempts /api/config/lock*), so a locked platform can still be
// unlocked through it.
//
// ENDPOINTS (mounted at /api/config; the mount applies authMiddleware())
//   GET  /api/config/lock                  read lock state + attribution (any
//                                          authenticated GD user)
//   POST /api/config/lock/unlock-options   issue a fresh WebAuthn assertion
//                                          challenge for the unlock (CISO)
//   POST /api/config/lock                  engage (immediate) or release; engage
//                                          needs only the CISO role, release
//                                          requires a verified FRESH user-
//                                          verified passkey assertion (CISO)
//
// ASYMMETRY (locked design): engaging the lock only raises security, so a CISO
// may engage immediately. Releasing lowers security, so it demands a fresh
// hardware-passkey assertion (user-verified) bound to the CISO's OWN passwordless
// credential, with the signature counter advanced on success (replay defense).
// The GD is hardware-FIDO2-only, so an enrolled passwordless credential is a
// hardware key by construction.
//
// Idle auto-relock is reconciled here too (GET and POST), so the reported state
// stays accurate even when no config write has occurred since the window
// elapsed. Audit via the GD hash-chained appendGdAuditEntry; logging is console.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const gdWebauthn = require('../services/gd-webauthn');

function _audit(db, req, eventType, detail, severity) {
  try {
    appendGdAuditEntry(db, {
      userId: req && req.user ? req.user.id : null,
      eventType,
      detail,
      ip: (req && req.ip) || null,
      severity,
    });
  } catch (e) {
    try { console.warn('[config-lock route] audit failed:', e && e.message); } catch (_) { /* ignore */ }
  }
}

// Inline CISO gate that emits CONFIG_LOCK_BYPASS_ATTEMPT on a role mismatch
// (a structured audit event, not just a refusal).
function cisoOnlyWithAudit(req, res, next) {
  if (!req.user || req.user.role !== 'ciso') {
    const db = getDb();
    try { _audit(db, req, 'CONFIG_LOCK_BYPASS_ATTEMPT', `role=${req.user ? req.user.role : 'unknown'}`, 'warning'); }
    finally { try { db.close(); } catch (_) { /* ignore */ } }
    return res.status(403).json({ error: 'CISO role required to modify config lock state', code: 'INSUFFICIENT_ROLE' });
  }
  return next();
}

// Reconcile an elapsed idle window: an unlocked platform past auto_relock_at
// re-locks. Mutates and returns the row for an accurate reported state.
function _reconcileIdle(db, row, req) {
  const now = Date.now();
  if (row && row.lock_active === 0 && row.auto_relock_at !== null && row.auto_relock_at !== undefined && now >= row.auto_relock_at) {
    db.prepare('UPDATE config_lock_state SET lock_active = 1, locked_at = ?, auto_relock_at = NULL, locked_by_user_id = NULL WHERE id = 1').run(now);
    _audit(db, req, 'CONFIG_LOCK_AUTO_RELOCK', `idle_minutes=${row.idle_minutes} relocked_at=${now} source=status`, 'warning');
    row.lock_active = 1; row.locked_at = now; row.auto_relock_at = null; row.locked_by_user_id = null; row.locked_by_name = null;
  }
  return row;
}

function _stateResponse(row) {
  return {
    lock_active: row.lock_active === 1,
    locked_by_user_id: row.locked_by_user_id,
    locked_by_name: row.locked_by_name,
    locked_at: row.locked_at,
    auto_relock_at: row.auto_relock_at,
    idle_minutes: row.idle_minutes,
  };
}

const SELECT_STATE =
  'SELECT cls.lock_active, cls.locked_by_user_id, cls.locked_at, cls.auto_relock_at, cls.idle_minutes, ' +
  'u.name AS locked_by_name FROM config_lock_state cls LEFT JOIN users u ON u.id = cls.locked_by_user_id WHERE cls.id = 1';

// ── GET /api/config/lock ──────────────────────────────────────────────────────
router.get('/lock', (req, res) => {
  const db = getDb();
  try {
    let row = db.prepare(SELECT_STATE).get();
    if (!row) {
      try { console.error('[config-lock route] config_lock_state singleton missing'); } catch (_) { /* ignore */ }
      return res.status(500).json({ error: 'Config lock state not initialized', code: 'STATE_NOT_INITIALIZED' });
    }
    row = _reconcileIdle(db, row, req);
    return res.json(_stateResponse(row));
  } catch (err) {
    try { console.error('[config-lock route] GET error:', err && err.message); } catch (_) { /* ignore */ }
    return res.status(500).json({ error: 'Internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── POST /api/config/lock/unlock-options ──────────────────────────────────────
router.post('/lock/unlock-options', cisoOnlyWithAudit, async (req, res) => {
  const db = getDb();
  try {
    const rp = gdWebauthn.getRpConfig(db);
    const allowCredentials = db.prepare(
      'SELECT credential_id AS credentialId, transports FROM webauthn_credentials WHERE user_id = ? AND is_passwordless = 1'
    ).all(req.user.id);
    if (!allowCredentials.length) {
      return res.status(400).json({ error: 'No passwordless passkey enrolled for this user', code: 'NO_PASSKEY' });
    }
    const { options, challengeToken } = await gdWebauthn.beginAuthentication({ rp, allowCredentials, userVerification: 'required' });
    return res.json({ options, challengeToken });
  } catch (e) {
    try { console.error('[config-lock route] unlock-options error:', e && e.message); } catch (_) { /* ignore */ }
    return res.status(500).json({ error: 'Could not start unlock challenge' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── POST /api/config/lock ─────────────────────────────────────────────────────
router.post('/lock', cisoOnlyWithAudit, async (req, res) => {
  const body = req.body || {};
  const action = body.action;
  if (action !== 'lock' && action !== 'unlock') {
    return res.status(400).json({ error: 'action must be "lock" or "unlock"', code: 'INVALID_ACTION' });
  }

  let idleMinutes = null;
  if (body.idle_minutes !== undefined && body.idle_minutes !== null) {
    idleMinutes = Number(body.idle_minutes);
    if (!Number.isInteger(idleMinutes) || idleMinutes < 1 || idleMinutes > 1440) {
      return res.status(400).json({ error: 'idle_minutes must be an integer between 1 and 1440', code: 'INVALID_IDLE_MINUTES' });
    }
  }

  const db = getDb();
  try {
    const current = db.prepare('SELECT lock_active, auto_relock_at, idle_minutes FROM config_lock_state WHERE id = 1').get();
    if (!current) {
      try { console.error('[config-lock route] config_lock_state singleton missing on POST'); } catch (_) { /* ignore */ }
      return res.status(500).json({ error: 'Config lock state not initialized', code: 'STATE_NOT_INITIALIZED' });
    }

    const now = Date.now();
    const effectivelyLocked = current.lock_active === 1 ||
      (current.auto_relock_at !== null && current.auto_relock_at !== undefined && now >= current.auto_relock_at);
    const wantsLocked = action === 'lock';

    if (effectivelyLocked === wantsLocked) {
      return res.status(409).json({ error: `Config is already ${effectivelyLocked ? 'locked' : 'unlocked'}`, code: 'ALREADY_IN_STATE' });
    }

    // RELEASE requires a verified fresh user-verified passkey assertion bound to
    // the CISO's own passwordless credential.
    if (!wantsLocked) {
      const assertion = body.response || (body.stepup && body.stepup.response);
      const challengeToken = body.challengeToken || (body.stepup && body.stepup.challengeToken);
      if (!assertion || !challengeToken) {
        return res.status(401).json({ error: 'A fresh passkey assertion is required to unlock', code: 'STEPUP_REQUIRED' });
      }
      const credId = assertion.id || assertion.rawId;
      if (!credId) {
        return res.status(400).json({ error: 'Malformed assertion', code: 'INVALID_INPUT' });
      }
      const cred = db.prepare('SELECT * FROM webauthn_credentials WHERE credential_id = ?').get(credId);
      if (!cred) {
        _audit(db, req, 'CONFIG_LOCK_STEPUP_FAILED', 'reason=unknown_credential', 'warning');
        return res.status(401).json({ error: 'Unknown or foreign credential', code: 'STEPUP_FAILED' });
      }
      if (cred.user_id !== req.user.id || cred.is_passwordless !== 1) {
        _audit(db, req, 'CONFIG_LOCK_STEPUP_FAILED', 'reason=foreign_or_non_passwordless_credential', 'warning');
        return res.status(401).json({ error: 'Unknown or foreign credential', code: 'STEPUP_FAILED' });
      }
      const rp = gdWebauthn.getRpConfig(db);
      let verification;
      try {
        verification = await gdWebauthn.finishAuthentication({
          rp,
          response: assertion,
          challengeToken,
          credential: { credentialId: cred.credential_id, publicKey: cred.public_key, counter: cred.sign_count, transports: cred.transports },
          requireUserVerification: true,
        });
      } catch (vErr) {
        _audit(db, req, 'CONFIG_LOCK_STEPUP_FAILED', 'reason=assertion_verification_error', 'warning');
        return res.status(401).json({ error: 'Passkey verification failed', code: 'STEPUP_FAILED' });
      }
      if (!verification.verified) {
        _audit(db, req, 'CONFIG_LOCK_STEPUP_FAILED', 'reason=assertion_not_verified', 'warning');
        return res.status(401).json({ error: 'Passkey verification failed', code: 'STEPUP_FAILED' });
      }
      // Advance the signature counter on the verified credential (replay defense).
      db.prepare("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = datetime('now') WHERE id = ?")
        .run(verification.newCounter != null ? verification.newCounter : cred.sign_count, cred.id);
    }

    const effectiveIdle = idleMinutes !== null ? idleMinutes : (Number(current.idle_minutes) || 15);
    const autoRelockAt = wantsLocked ? null : now + effectiveIdle * 60 * 1000;

    db.prepare('UPDATE config_lock_state SET lock_active = ?, locked_by_user_id = ?, locked_at = ?, auto_relock_at = ?, idle_minutes = ? WHERE id = 1')
      .run(wantsLocked ? 1 : 0, wantsLocked ? req.user.id : null, wantsLocked ? now : null, autoRelockAt, effectiveIdle);

    _audit(
      db, req,
      wantsLocked ? 'CONFIG_LOCK_ENGAGED' : 'CONFIG_LOCK_RELEASED',
      wantsLocked ? 'method=ciso_immediate' : `method=webauthn_stepup idle_minutes=${effectiveIdle}`,
      'warning'
    );

    const updated = db.prepare(SELECT_STATE).get();
    return res.json(_stateResponse(updated));
  } catch (err) {
    try { console.error('[config-lock route] POST error:', err && err.message); } catch (_) { /* ignore */ }
    return res.status(500).json({ error: 'Internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

module.exports = router;

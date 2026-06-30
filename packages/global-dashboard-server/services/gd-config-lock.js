// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Config Lock Chokepoint (B6a)
//
// GD twin of the regional config-lock chokepoint. Registry-driven single
// chokepoint mounted broadly on /api: it gates ONLY requests that
// isGdConfigWriteRequest() identifies as configuration / trust-posture changes
// (services/gd-config-write-routes.js) and passes everything else -- reads,
// operational mutations, the inbound MC handshake, the config-lock recovery
// endpoints -- straight through. Refused config writes get 423 Locked.
//
// QUARANTINE REFUSAL (merged from the regional config-lock GATE)
//   A quarantined deployment (gd_instance_identity.status = 'quarantined' --
//   a suspected clone/fork/rollback) must not change configuration. The check
//   is fail-open on a status-read fault (the boot halt is the primary control).
//
// IDLE AUTO-RELOCK
//   An operator unlock starts a sliding idle window (config_lock_state
//   .auto_relock_at, ms-epoch). Each allowed config write slides it forward by
//   idle_minutes. If it elapses, the next config write re-locks the platform
//   (CONFIG_LOCK_AUTO_RELOCK) and is refused, so a walked-away session cannot
//   leave configuration writable indefinitely. A platform that has never been
//   locked (auto_relock_at IS NULL while unlocked) is not subject to idle relock.
//
// FAIL-SAFE
//   A missing singleton or a DB error fails CLOSED (423 / 500) -- a DB fault must
//   never silently bypass the lock. The config-lock recovery endpoints are
//   exempt in the matcher, so the unlock path is not blocked by this gate.
//
// Path resolution uses req.originalUrl (mount-independent), minus query string.
// Audit goes through the GD hash-chained appendGdAuditEntry; logging is console
// (the GD has no logger service). Unlock is a fresh hardware-passkey assertion
// (routes/config-lock.js), not session MFA.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('./gd-audit-chain');
const { isGdConfigWriteRequest } = require('./gd-config-write-routes');

// Audit best-effort: an audit failure must not prevent the security response.
function _audit(db, req, eventType, detail, severity, eventDetail) {
  try {
    appendGdAuditEntry(db, {
      userId: req && req.user ? req.user.id : null,
      eventType,
      detail: String(detail) + (eventDetail ? ` ${eventDetail}` : ''),
      severity,
      ip: (req && req.ip) || null,
    });
  } catch (e) {
    try { console.warn('[gd-config-lock] audit write failed:', e && e.message); } catch (_) { /* ignore */ }
  }
}

// Read the GD instance status (most-recent identity row). Fail-open on a read
// fault -- the boot halt and quarantine alert are the primary controls, so a
// transient read error must not block config writes here.
function _readInstanceStatus(db) {
  try {
    const r = db.prepare('SELECT status FROM gd_instance_identity ORDER BY id DESC LIMIT 1').get();
    return r ? r.status : null;
  } catch (e) {
    try { console.warn('[gd-config-lock] instance status read failed; allowing:', e && e.message); } catch (_) { /* ignore */ }
    return null;
  }
}

function configLockChokepoint(options = {}) {
  const { eventDetail } = options;

  return function gdConfigLockChokepointMiddleware(req, res, next) {
    const fullPath = (req.originalUrl || req.url || '').split('?')[0];

    // Only configuration / trust-posture changes are gated; everything else passes.
    if (!isGdConfigWriteRequest(req.method, fullPath)) {
      return next();
    }

    const db = getDb();
    try {
      // Quarantined deployment: no config changes until identity is re-established.
      if (_readInstanceStatus(db) === 'quarantined') {
        _audit(db, req, 'CONFIG_WRITE_REFUSED_QUARANTINED', `path=${req.method} ${fullPath}`, 'critical', eventDetail);
        return res.status(403).json({
          error: 'This deployment is quarantined because a possible clone, fork, or rollback was detected. Configuration changes are disabled until the instance identity is re-established.',
          code: 'INSTANCE_QUARANTINED',
        });
      }

      const row = db.prepare(
        'SELECT lock_active, locked_at, auto_relock_at, idle_minutes FROM config_lock_state WHERE id = 1'
      ).get();

      if (!row) {
        try { console.error('[gd-config-lock] config_lock_state singleton missing; refusing config write:', fullPath); } catch (_) { /* ignore */ }
        _audit(db, req, 'CONFIG_LOCK_GATE_HIT', `path=${req.method} ${fullPath} reason=singleton_missing`, 'error', eventDetail);
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
          'UPDATE config_lock_state SET lock_active = 1, locked_at = ?, auto_relock_at = NULL, locked_by_user_id = NULL WHERE id = 1'
        ).run(now);
        _audit(db, req, 'CONFIG_LOCK_AUTO_RELOCK', `idle_minutes=${row.idle_minutes} relocked_at=${now}`, 'warning', eventDetail);
        _audit(db, req, 'CONFIG_LOCK_GATE_HIT', `path=${req.method} ${fullPath} reason=idle_auto_relock`, 'warning', eventDetail);
        return res.status(423).json({
          error: 'Configuration auto-relocked after idle timeout. Unlock with hardware MFA to proceed.',
          code: 'CONFIG_LOCKED',
          locked_at: now,
          reason: 'idle_auto_relock',
        });
      }

      // Explicitly locked.
      if (row.lock_active === 1) {
        _audit(db, req, 'CONFIG_LOCK_GATE_HIT', `path=${req.method} ${fullPath}`, 'warning', eventDetail);
        return res.status(423).json({
          error: 'Configuration is locked. Unlock with hardware MFA to proceed.',
          code: 'CONFIG_LOCKED',
          locked_at: row.locked_at,
        });
      }

      // Unlocked. Inside an active unlock session, slide the idle window forward
      // on this allowed config write.
      if (row.auto_relock_at !== null && row.auto_relock_at !== undefined) {
        const idleMs = Math.max(1, Number(row.idle_minutes) || 15) * 60 * 1000;
        db.prepare('UPDATE config_lock_state SET auto_relock_at = ? WHERE id = 1').run(now + idleMs);
      }

      return next();
    } catch (err) {
      try { console.error('[gd-config-lock] chokepoint error:', err && err.message); } catch (_) { /* ignore */ }
      return res.status(500).json({ error: 'Internal error checking config lock state' });
    } finally {
      try { db.close(); } catch (_) { /* already closed */ }
    }
  };
}

module.exports = { configLockChokepoint };

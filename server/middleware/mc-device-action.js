// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — MC Privileged-Action Verifier (D24)
//
// Gates destructive recovery routes on a fresh, single-use signature from the
// calling MC operator's active hardware device key. The Management Console
// signs (action, target, iat, jti) on-chip (ECDSA P-256, raw r||s) before
// issuing a destructive request; this middleware reconstructs the identical
// message, looks up the operator's active mc_device_signing_keys row, and
// verifies the signature, so a stolen session token alone cannot trigger a
// teardown or reprovision — the action must originate from the operator's
// real hardware.
//
// target is derived server-side from the request (never trusted from the
// proof), so a signature captured for one object cannot be replayed against
// another. iat must fall inside a short freshness window and each jti is
// accepted at most once (in-memory single-use cache).
//
// MUST be applied AFTER an auth middleware that sets req.user.
// ═══════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('./audit');
const { checkClockIntegrity } = require('../services/clock-integrity');

const MC_ACTION_SIGNING_PREFIX = 'firealive-mc-device-action-v1:';
const MC_ACTION_SEP = String.fromCharCode(10);
const ACTION_TTL_SECONDS = 120;
const CLOCK_SKEW_SECONDS = 30;

// Single-use cache: jti -> expiry (epoch seconds). The freshness window
// bounds retention, so a process restart cannot widen the replay window.
const seenJti = new Map();
function pruneJti(now) {
  const dead = [];
  seenJti.forEach((exp, key) => { if (exp < now) dead.push(key); });
  dead.forEach((key) => seenJti.delete(key));
}
function jtiSeen(jti, now) {
  const exp = seenJti.get(jti);
  if (exp === undefined) return false;
  if (exp < now) { seenJti.delete(jti); return false; }
  return true;
}
function rememberJti(jti, now) {
  seenJti.set(jti, now + ACTION_TTL_SECONDS + CLOCK_SKEW_SECONDS);
}

// Reconstruct the exact bytes the MC signed on-chip (same prefix, field
// order, and separator as the client).
function actionMessage(action, target, iat, jti) {
  return Buffer.from(MC_ACTION_SIGNING_PREFIX + [action, target, String(iat), jti].join(MC_ACTION_SEP), 'utf8');
}

// Express middleware factory. Gate a destructive route with
//   requireDeviceAction('recovery.teardown', (req) => req.params.userId)
// targetOf derives the bound object from the request; omit it for actions
// with no specific target (target signs as the empty string).
function requireDeviceAction(action, targetOf) {
  return function deviceActionGate(req, res, next) {
    const signature = req.get('x-fa-device-action-signature');
    const iatRaw = req.get('x-fa-device-action-iat');
    const jti = req.get('x-fa-device-action-jti');
    const fingerprint = req.get('x-fa-device-action-fingerprint');
    const uid = req.user && req.user.id;
    if (!uid) {
      return res.status(401).json({ error: 'authentication required' });
    }
    if (!signature || !iatRaw || !jti || !fingerprint) {
      return res.status(401).json({ error: 'device action proof required' });
    }
    if (!/^[a-f0-9]{64}$/.test(fingerprint) || !/^[a-f0-9]{16,64}$/.test(jti)) {
      return res.status(400).json({ error: 'malformed device action proof' });
    }

    // Clock integrity: a signed action's freshness is judged against the wall
    // clock below, so a virtualized instance whose clock has jumped (snapshot
    // restore, pause/resume, migration) cannot be trusted to validate the iat
    // window. Fail closed in that case; bare-metal is never gated.
    const mode = (req.app && req.app.locals && req.app.locals.deploymentMode) || {};
    const clock = checkClockIntegrity({ virtualized: !!mode.virtualized });
    if (!clock.ok) {
      auditLog(uid, 'MC_DEVICE_ACTION_CLOCK_UNTRUSTED', action, req.ip);
      logger.error('mc device-action refused: clock integrity check failed', { reason: clock.reason, skewMs: clock.skewMs });
      return res.status(503).json({ error: 'server clock unverified; retry' });
    }

    const iat = Number(iatRaw);
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isInteger(iat) || iat > now + CLOCK_SKEW_SECONDS || iat < now - ACTION_TTL_SECONDS) {
      auditLog(uid, 'MC_DEVICE_ACTION_EXPIRED', action, req.ip);
      return res.status(403).json({ error: 'device action proof expired' });
    }
    if (jtiSeen(jti, now)) {
      auditLog(uid, 'MC_DEVICE_ACTION_REPLAY', action, req.ip);
      return res.status(403).json({ error: 'device action proof already used' });
    }
    const rawTarget = typeof targetOf === 'function' ? targetOf(req) : '';
    const target = rawTarget === null || rawTarget === undefined ? '' : String(rawTarget);
    let row;
    const db = getDb();
    try {
      row = db.prepare("SELECT public_key, fingerprint FROM mc_device_signing_keys WHERE user_id = ? AND active = 1").get(uid);
    } catch (err) {
      logger.error('mc device-action key lookup failed', { error: err.message });
      return res.status(500).json({ error: 'verification failed' });
    } finally {
      db.close();
    }
    if (!row) {
      auditLog(uid, 'MC_DEVICE_ACTION_NO_KEY', action, req.ip);
      return res.status(403).json({ error: 'no active device key registered' });
    }
    if (row.fingerprint !== fingerprint) {
      auditLog(uid, 'MC_DEVICE_ACTION_KEY_MISMATCH', action, req.ip);
      return res.status(403).json({ error: 'device action proof key mismatch' });
    }
    let ok = false;
    try {
      ok = crypto.verify('sha256', actionMessage(action, target, iat, jti), { key: crypto.createPublicKey(row.public_key), dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64'));
    } catch (_) {
      ok = false;
    }
    if (!ok) {
      auditLog(uid, 'MC_DEVICE_ACTION_BAD_SIG', action, req.ip);
      return res.status(403).json({ error: 'device action signature invalid' });
    }
    rememberJti(jti, now);
    pruneJti(now);
    auditLog(uid, 'MC_DEVICE_ACTION_VERIFIED', action + ':' + target, req.ip);
    req.deviceAction = { action: action, target: target, jti: jti, fingerprint: fingerprint };
    next();
  };
}

module.exports = {
  requireDeviceAction,
  actionMessage,
  MC_ACTION_SIGNING_PREFIX,
  MC_ACTION_SEP,
  ACTION_TTL_SECONDS,
  CLOCK_SKEW_SECONDS
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Step-up MFA Middleware
//
// Wraps an individual route handler in a "must provide a fresh
// totp_code (or recovery_code) in the request body" check, separate
// from login-time MFA. Used to gate sensitive admin actions
// (config-lock toggle, foreign signing-key registration, audit log
// purges, etc.) so that even a hijacked session cannot perform them
// without proving live access to the user's authenticator (or
// recovery code).
//
// USAGE
//
//   const { mfaStepUp } = require('../middleware/mfa-stepup');
//   const { authMiddleware } = require('../middleware/auth');
//
//   // Default: TOTP or recovery code accepted
//   router.post('/sensitive',
//     authMiddleware(['admin']),
//     mfaStepUp(),
//     handler);
//
//   // Recovery codes NOT accepted (e.g. recovery-regenerate route
//   // itself, or any other action where falling back to a recovery
//   // code would defeat the purpose):
//   router.post('/regenerate-recovery',
//     authMiddleware(['admin', 'lead', 'developer', 'analyst']),
//     mfaStepUp({ allowRecovery: false }),
//     handler);
//
// MUST be applied AFTER an auth middleware that sets req.user. This
// file does NOT do authentication itself; it reads req.user.id and
// trusts the upstream auth middleware established the session.
//
// REQUEST CONTRACT
//
// Body must contain EXACTLY ONE of:
//   { "totp_code":     "123456" }              -- 6 digits
//   { "recovery_code": "K7QM-3RTX-W9HJ" }      -- 14-char alphanumeric
//
// Sending both is rejected with 400 INVALID_INPUT to prevent
// ambiguity (and to deny attackers a way to probe both factors in a
// single request).
//
// RESPONSE ON SUCCESS
//
// Calls next(). Sets req.mfaStepUp for downstream handlers and
// audit:
//   { method: 'totp',     step:      <verified-step>      }  -- TOTP path
//   { method: 'recovery', remaining: <codes-left-after> }    -- recovery path
//
// RESPONSE ON FAILURE
//
// Returns the appropriate HTTP status with body:
//   { error: <message>, code: <stable-error-code>, detail?: <object> }
//
// Status mapping mirrors routes/mfa.js: 400 INVALID_INPUT, 401
// CODE_INVALID / CODE_REPLAY / RECOVERY_CODE_INVALID, 403 NOT_ENROLLED
// / RECOVERY_CODES_EXHAUSTED / NO_RECOVERY_CODES_GENERATED, 404
// USER_NOT_FOUND, 409 RECOVERY_CODE_RACE, 429 LOCKED_OUT, 500
// ENCRYPTION_NOT_CONFIGURED. The 401 MFA_STEPUP_REQUIRED status is
// returned when neither totp_code nor recovery_code is provided.
//
// AUDIT LOG
//
// totp.verify() and totp.consumeRecoveryCode() audit-log every
// outcome (TOTP_VERIFY_OK / TOTP_VERIFY_FAIL / TOTP_RECOVERY_USED /
// TOTP_RECOVERY_FAIL / etc.). The middleware does NOT add its own
// audit row -- the global auditMiddleware in index.js writes the
// HTTP-level entry, the totp service writes the operation-specific
// entry, and double-logging would be noise.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const totp = require('../services/totp');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

// ── Helpers ──────────────────────────────────────────────────────────────────

function totpCodeToHttpStatus(code) {
  switch (code) {
    case totp.CODES.INVALID_INPUT:
      return 400;
    case totp.CODES.USER_NOT_FOUND:
      return 404;
    case totp.CODES.NOT_ENROLLED:
    case totp.CODES.RECOVERY_CODES_EXHAUSTED:
    case totp.CODES.NO_RECOVERY_CODES_GENERATED:
      return 403;
    case totp.CODES.CODE_INVALID:
    case totp.CODES.CODE_REPLAY:
    case totp.CODES.RECOVERY_CODE_INVALID:
      return 401;
    case totp.CODES.RECOVERY_CODE_RACE:
      return 409;
    case totp.CODES.LOCKED_OUT:
      return 429;
    case totp.CODES.ENCRYPTION_NOT_CONFIGURED:
      return 500;
    default:
      return 500;
  }
}

function sendTotpError(res, err) {
  const status = totpCodeToHttpStatus(err.code);
  const body = { error: err.message, code: err.code };
  if (err.detail !== undefined) body.detail = err.detail;
  return res.status(status).json(body);
}

function validateTotpCode(value) {
  if (typeof value !== 'string') return 'totp_code must be a string';
  if (!/^\d{6}$/.test(value)) return 'totp_code must be exactly 6 digits';
  return null;
}

function validateRecoveryCode(value) {
  if (typeof value !== 'string') return 'recovery_code must be a string';
  // 14-char alphanumeric hyphenated format (e.g. "K7QM-3RTX-W9HJ").
  // The actual hash comparison happens in totp.consumeRecoveryCode;
  // this is just a syntactic gate to reject obviously-malformed
  // input before paying the bcrypt cost. Length-only check (1..64)
  // matches the service's input validation; we don't enforce the
  // exact format here so legacy formats remain consumable.
  if (value.length === 0 || value.length > 64) return 'recovery_code must be 1-64 characters';
  return null;
}

// ── Middleware factory ───────────────────────────────────────────────────────

/**
 * Build a step-up MFA middleware with the given options.
 *
 * Args:
 *   options
 *     allowRecovery   boolean, default true. When false, recovery
 *                     codes are rejected with 403 RECOVERY_NOT_ALLOWED
 *                     and only totp_code is accepted. Set false on
 *                     routes where falling back to a recovery code
 *                     would defeat the security purpose (e.g. the
 *                     recovery-code regeneration endpoint itself --
 *                     consuming a recovery code to authorize
 *                     regeneration would be circular).
 */
function mfaStepUp(options = {}) {
  const allowRecovery = (options && options.allowRecovery !== false);

  return function mfaStepUpMiddleware(req, res, next) {
    // Auth must have run already and set req.user.
    if (!req.user || typeof req.user.id !== 'string') {
      logger.error('mfaStepUp invoked without upstream auth -- check route definition order');
      return res.status(500).json({
        error: 'mfa-stepup middleware misconfigured: no upstream auth',
        code: 'INTERNAL',
      });
    }

    const totpCode = req.body && req.body.totp_code;
    const recoveryCode = req.body && req.body.recovery_code;

    // Strict: exactly one factor input must be present. Rejecting
    // both-provided prevents an attacker from probing both factors
    // in a single request, and rejecting neither is the standard
    // step-up-required signal to the client.
    if (totpCode && recoveryCode) {
      return res.status(400).json({
        error: 'provide exactly one of totp_code or recovery_code, not both',
        code: 'INVALID_INPUT',
      });
    }
    if (!totpCode && !recoveryCode) {
      return res.status(401).json({
        error: 'MFA step-up required: provide totp_code or recovery_code in the request body',
        code: 'MFA_STEPUP_REQUIRED',
        accepts: allowRecovery ? ['totp_code', 'recovery_code'] : ['totp_code'],
      });
    }

    // Refuse recovery codes early on routes that opt out -- before
    // touching the DB, before incurring any bcrypt cost.
    if (recoveryCode && !allowRecovery) {
      return res.status(403).json({
        error: 'this endpoint requires a TOTP code; recovery codes are not accepted',
        code: 'RECOVERY_NOT_ALLOWED',
      });
    }

    // Syntactic input validation. Service-level validation is the
    // authoritative one (it generates the audit log on real
    // failures), but checking here lets us 400 obviously-malformed
    // input without paying the DB / bcrypt cost.
    if (totpCode) {
      const codeError = validateTotpCode(totpCode);
      if (codeError) {
        return res.status(400).json({ error: codeError, code: 'INVALID_INPUT' });
      }
    } else {
      const codeError = validateRecoveryCode(recoveryCode);
      if (codeError) {
        return res.status(400).json({ error: codeError, code: 'INVALID_INPUT' });
      }
    }

    try {
      const db = getDb();

      if (totpCode) {
        const result = totp.verify(db, req.user.id, totpCode, req.ip || null);
        req.mfaStepUp = { method: 'totp', step: result.step };
      } else {
        const result = totp.consumeRecoveryCode(db, req.user.id, recoveryCode, req.ip || null);
        req.mfaStepUp = { method: 'recovery', remaining: result.remaining };
      }

      return next();
    } catch (err) {
      if (err instanceof totp.TotpError) return sendTotpError(res, err);
      logger.error('mfaStepUp middleware error', {
        userId: req.user.id,
        error: err.message,
        stack: err.stack,
      });
      return res.status(500).json({ error: 'MFA verification error', code: 'INTERNAL' });
    }
  };
}

module.exports = { mfaStepUp };

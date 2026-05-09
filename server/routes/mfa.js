// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — MFA (TOTP) Self-Service Routes
//
// Authenticated users manage their own TOTP enrollment via these endpoints.
// All operations are scoped to req.user.id -- the routes never accept a
// user_id parameter, so a user cannot enroll/disable another user's MFA.
// (Admin-mediated reset for lost devices is a separate flow that must
// itself require two-person approval; not implemented here.)
//
// Endpoints:
//   GET    /api/mfa/status                    { enrolled, in_enrollment }
//   POST   /api/mfa/enroll-start              -> { secret_base32, otpauth_url }
//   POST   /api/mfa/enroll-confirm            { totp_code } -> { enrolled_at }
//   POST   /api/mfa/verify                    { totp_code } -> { verified, step }
//   POST   /api/mfa/disable                   { totp_code } -> { disabled_at }
//
// Auth:
//   This file is mounted with authMiddleware(['analyst', 'lead', 'admin',
//   'developer']) in server/index.js. Any authenticated user can manage
//   their own MFA. No per-handler role tightening -- the user_id scoping
//   to req.user.id is the security boundary.
//
// Why a top-level /api/mfa rather than /api/auth/mfa:
//   - /api/auth is mounted without authMiddleware (login is unauthenticated)
//   - These endpoints all require an authenticated JWT
//   - Splitting into /api/mfa lets index.js cleanly apply authMiddleware
//     at the mount point without per-handler exemptions
//   - The frontend's existing /api/auth/mfa-verify path is dead code that
//     was never wired server-side; this file replaces it with the canonical
//     /api/mfa/verify. Frontend will be updated to match in a later commit.
//
// Audit log:
//   The TOTP service writes operation-specific events
//   (TOTP_ENROLL_START, TOTP_ENROLL_CONFIRM_OK/FAIL, TOTP_VERIFY_OK/FAIL/
//   REPLAY/REPLAY_RACE/BLOCKED, TOTP_DISABLED). The global auditMiddleware
//   in index.js writes the HTTP-level audit row. This file does not
//   duplicate-log.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const totp = require('../services/totp');

// ── Helpers ──────────────────────────────────────────────────────────────────

function totpCodeToHttpStatus(code) {
  switch (code) {
    case totp.CODES.INVALID_INPUT:
      return 400;
    case totp.CODES.USER_NOT_FOUND:
      return 404;
    case totp.CODES.NOT_ENROLLED:
      return 403;
    case totp.CODES.ALREADY_ENROLLED:
      return 409;
    case totp.CODES.CODE_INVALID:
    case totp.CODES.CODE_REPLAY:
      return 401;
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
  res.status(status).json(body);
}

function validateTotpCode(value) {
  if (typeof value !== 'string') return 'totp_code must be a string';
  if (!/^\d{6}$/.test(value)) return 'totp_code must be exactly 6 digits';
  return null; // valid
}

// ── GET /api/mfa/status ─────────────────────────────────────────────────────
//
// Returns the calling user's TOTP enrollment state. Used by the frontend
// to decide whether to show the "Set up MFA" wizard, the "Enter code"
// confirmation screen, or the "Disable MFA" management view.
router.get('/status', (req, res) => {
  try {
    const db = getDb();
    const enrolled = totp.isEnrolled(db, req.user.id);
    const inEnrollment = totp.isInEnrollment(db, req.user.id);
    return res.json({ enrolled, in_enrollment: inEnrollment });
  } catch (err) {
    logger.error('MFA status failed', { userId: req.user.id, error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/mfa/enroll-start ──────────────────────────────────────────────
//
// Generates a fresh TOTP secret for the calling user and stores it
// (encrypted) in users.totp_secret. Returns the base32 secret + an
// otpauth:// URI that the frontend renders as a QR code for the
// authenticator app to scan.
//
// SECURITY: the secret is returned ONCE in the response. The frontend
// must not log it, persist it client-side, or display it after the user
// has confirmed enrollment. The backend stores only the encrypted form;
// retrieving the plaintext later is impossible without re-running enroll.
router.post('/enroll-start', (req, res) => {
  try {
    const db = getDb();
    const result = totp.enrollStart(db, req.user.id, {
      issuer: 'FireAlive',
      account_label: req.user.name || req.user.id,
      client_ip: req.ip || null,
    });
    return res.status(201).json(result);
  } catch (err) {
    if (err instanceof totp.TotpError) return sendTotpError(res, err);
    logger.error('MFA enroll-start failed', { userId: req.user.id, error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/mfa/enroll-confirm ────────────────────────────────────────────
//
// Body: { totp_code: string (6 digits, required) }
//
// Confirms enrollment by verifying the user's first OTP from their
// authenticator app. On success, sets users.totp_enrolled_at and seeds
// users.totp_last_used_step so the same code cannot later be used for
// step-up MFA.
//
// Failed confirmations do not count toward the verify() lockout
// (enrollment is one-shot; locking would just frustrate users typing
// codes a second too late).
router.post('/enroll-confirm', (req, res) => {
  const code = req.body && req.body.totp_code;
  const codeError = validateTotpCode(code);
  if (codeError) {
    return res.status(400).json({ error: codeError, code: 'INVALID_INPUT' });
  }

  try {
    const db = getDb();
    const result = totp.enrollConfirm(db, req.user.id, code, req.ip || null);
    return res.json(result);
  } catch (err) {
    if (err instanceof totp.TotpError) return sendTotpError(res, err);
    logger.error('MFA enroll-confirm failed', { userId: req.user.id, error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/mfa/verify ────────────────────────────────────────────────────
//
// Body: { totp_code: string (6 digits, required) }
//
// General-purpose step-up verification. The same totp.verify() that
// routes/restore-approvals.js calls inline before approve. Exposed
// here for frontend flows that want to confirm MFA before navigating
// to a sensitive screen, or for clients that want to pre-flight a
// step-up before composing a privileged request body.
//
// Replay protection: a successful verify advances totp_last_used_step,
// so the same code cannot be re-used (here OR by routes/restore-
// approvals.js) within its 30-second window.
router.post('/verify', (req, res) => {
  const code = req.body && req.body.totp_code;
  const codeError = validateTotpCode(code);
  if (codeError) {
    return res.status(400).json({ error: codeError, code: 'INVALID_INPUT' });
  }

  try {
    const db = getDb();
    const result = totp.verify(db, req.user.id, code, req.ip || null);
    return res.json(result);
  } catch (err) {
    if (err instanceof totp.TotpError) return sendTotpError(res, err);
    logger.error('MFA verify failed', { userId: req.user.id, error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/mfa/disable ───────────────────────────────────────────────────
//
// Body: { totp_code: string (6 digits, required) }
//
// Disables MFA after verifying a valid current OTP. The OTP requirement
// prevents an attacker who has stolen a session token from also turning
// off the account's second factor.
//
// On success, clears users.totp_secret, totp_enrolled_at, and resets
// totp_last_used_step.
router.post('/disable', (req, res) => {
  const code = req.body && req.body.totp_code;
  const codeError = validateTotpCode(code);
  if (codeError) {
    return res.status(400).json({ error: codeError, code: 'INVALID_INPUT' });
  }

  try {
    const db = getDb();
    const result = totp.disable(db, req.user.id, code, req.ip || null);
    return res.json(result);
  } catch (err) {
    if (err instanceof totp.TotpError) return sendTotpError(res, err);
    logger.error('MFA disable failed', { userId: req.user.id, error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

module.exports = router;

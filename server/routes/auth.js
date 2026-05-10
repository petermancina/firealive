// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Auth Routes
//
// SOC-grade two-step login flow with mandatory MFA enforcement at the
// JWT-issuance boundary. JWTs are NEVER issued for users who are
// enrolled in MFA without first verifying a TOTP (or recovery) code,
// and never issued for users with mfa_enrollment_required=1 until
// they have completed enrollment.
//
// MFA BRIDGE TOKEN
//
// The two-step login is bridged by a short-lived signed JWT (5-minute
// TTL, mfa_pending=true claim) issued at password-verify time and
// consumed at second-factor-verify time. The bridge JWT is signed
// with the same JWT_SECRET as the auth JWT, but its payload shape is
// distinct (mfa_pending claim present + reduced claim set) so a
// bridge JWT cannot be substituted for an auth JWT and vice versa.
// All JWT verification on protected routes (middleware/auth.js) MUST
// reject tokens carrying mfa_pending=true; conversely, the MFA-step
// endpoints in this file accept ONLY tokens carrying mfa_pending=true.
//
// SINGLE-USE ENFORCEMENT
//
// The bridge JWT carries a JTI (16-byte hex random) claim. After
// successful second-factor verification, the JTI is INSERTed into
// mfa_consumed_jtis under ON CONFLICT(jti) DO NOTHING. If the insert
// no-op'd (the JTI was already on the denylist), the request is a
// replay and is refused. Race-safe by virtue of the PRIMARY KEY
// constraint at the storage layer.
//
// ENDPOINTS
//
//   POST /api/auth/login                   password -> JWT or bridge token
//   POST /api/auth/login-mfa               bridge + totp/recovery -> JWT
//   POST /api/auth/login-enroll-start      bridge -> secret + QR PNG
//   POST /api/auth/login-enroll-confirm    bridge + totp -> JWT + recovery_codes
//   POST /api/auth/refresh                 refresh token -> new JWT
//                                          (re-checks enrollment state)
//   POST /api/auth/logout                  invalidate session
//   GET  /api/auth/me                      current user info
//
// AUDIT EVENTS
//
//   LOGIN_FAILED                          password verify failed
//   LOGIN_PASSWORD_OK                     password verified, MFA pending
//   LOGIN_PASSWORD_OK_PENDING_ENROLLMENT  password verified, must enroll
//   LOGIN_SUCCESS                         JWT issued (analyst direct
//                                         path or post-MFA path; the
//                                         existing event name is
//                                         preserved)
//   LOGIN_MFA_SESSION_INVALID             bridge JWT bad/expired/
//                                         consumed
//   LOGIN_ENROLLMENT_BLOCKED              /refresh refused due to
//                                         pending enrollment after
//                                         upgrade
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const qrcode = require('qrcode');
const { getDb } = require('../db/init');
const { signToken } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const totp = require('../services/totp');

// ── Configuration ────────────────────────────────────────────────────────────

const MFA_BRIDGE_JWT_TTL_SECONDS = 5 * 60;           // 5 minutes
const MFA_JTI_BYTES = 16;                            // 128 bits, ample for unique IDs
const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;  // 7 days, matches v1.0.30

// JWT_SECRET fallback matches middleware/auth.js exactly so the
// bridge JWT and the auth JWT use the same key (signed JWTs with
// algorithm pinning prevent cross-purpose abuse via the mfa_pending
// claim assertion below).
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_INSECURE_DEFAULT';

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Sign a short-lived MFA bridge JWT for the given user. The bridge
 * JWT carries:
 *
 *   sub          stringified user id
 *   mfa_pending  literal true (claim discriminator)
 *   jti          16-byte hex random (single-use enforcement key)
 *   iat / exp    standard JWT timing claims (5-min TTL)
 *
 * The mfa_pending=true claim is the discriminator that distinguishes
 * a bridge JWT from an auth JWT: middleware/auth.js must reject any
 * token carrying this claim on protected routes, and the MFA-step
 * endpoints in this file must accept ONLY tokens carrying this claim.
 *
 * Returns { token, expires_at_ms, jti }. The token is sent to the
 * client; expires_at_ms is informational for the client UI; jti is
 * not exposed to the client (it's embedded in the JWT and recovered
 * server-side by verification).
 *
 * The verifier (verifyMfaSessionJwt below) does not store the JTI on
 * issue -- it only stores it on consume (mfa_consumed_jtis denylist).
 * Issued-but-unconsumed JTIs leave no DB trace; they expire silently
 * via the JWT's own exp claim.
 */
function createMfaSessionJwt(userId) {
  const jti = crypto.randomBytes(MFA_JTI_BYTES).toString('hex');
  const now = Math.floor(Date.now() / 1000);
  const exp = now + MFA_BRIDGE_JWT_TTL_SECONDS;
  const token = jwt.sign(
    {
      sub: String(userId),
      mfa_pending: true,
      jti,
      iat: now,
      exp,
    },
    JWT_SECRET,
    { algorithm: 'HS256' }
  );
  return {
    token,
    expires_at_ms: exp * 1000,
    jti,
  };
}

/**
 * Verify a bridge JWT. Returns { user_id, jti, exp_seconds } on
 * success; throws an Error with .code on failure.
 *
 * Failure codes (mirroring the v0 helper's vocabulary so audit logs
 * and HTTP status mapping stay structurally identical):
 *
 *   SESSION_NOT_FOUND   malformed token (jwt.verify threw something
 *                        other than expired)
 *   SESSION_EXPIRED     JWT exp passed
 *   SESSION_CONSUMED    JTI is on the mfa_consumed_jtis denylist
 *                        (caller must check separately; this code
 *                        is reserved for the consume path's mapping)
 *
 * The signature check, the exp check, and the mfa_pending claim
 * assertion all happen here. The denylist check happens at the
 * consume path because consume is atomic and we don't want a TOCTOU
 * between "lookup says fresh" and "insert says replay".
 */
function verifyMfaSessionJwt(token) {
  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    if (err && err.name === 'TokenExpiredError') {
      const e = new Error('session token expired');
      e.code = 'SESSION_EXPIRED';
      throw e;
    }
    const e = new Error('session token not found');
    e.code = 'SESSION_NOT_FOUND';
    throw e;
  }
  if (decoded.mfa_pending !== true) {
    // Caller passed an auth JWT or a JWT with the wrong shape.
    // Refuse explicitly rather than letting an auth JWT
    // accidentally be replayed against the MFA endpoints.
    const e = new Error('session token not found');
    e.code = 'SESSION_NOT_FOUND';
    throw e;
  }
  if (typeof decoded.jti !== 'string' || decoded.jti.length === 0) {
    const e = new Error('session token not found');
    e.code = 'SESSION_NOT_FOUND';
    throw e;
  }
  if (typeof decoded.sub !== 'string' || decoded.sub.length === 0) {
    const e = new Error('session token not found');
    e.code = 'SESSION_NOT_FOUND';
    throw e;
  }
  return {
    user_id: decoded.sub,
    jti: decoded.jti,
    exp_seconds: decoded.exp,
  };
}

/**
 * Atomically mark a bridge JTI as consumed. Inserts into
 * mfa_consumed_jtis under PRIMARY KEY (jti) -- if the row already
 * exists, the insert no-ops and we report the replay condition to
 * the caller via the SESSION_CONSUMED code.
 *
 * Single-use enforcement at the storage layer: there's no race
 * window between "is it consumed?" and "consume it" because the
 * INSERT is the consume. Two concurrent requests with the same JWT
 * race at the database, and exactly one wins.
 *
 * Returns { user_id } on first successful consume; throws with
 * .code = 'SESSION_CONSUMED' on replay, or .code = 'SESSION_RACE'
 * for unexpected DB conditions (kept for parity with the v0
 * helper's code vocabulary).
 *
 * Also opportunistically prunes expired rows from the denylist
 * (rows whose underlying JWT exp has already passed are safe to
 * delete; the JWT itself wouldn't verify anymore).
 */
function consumeMfaSessionJti(db, verified) {
  const nowMs = Date.now();
  const insert = db.prepare(`
    INSERT INTO mfa_consumed_jtis (jti, consumed_at, expires_at)
    VALUES (?, ?, ?)
    ON CONFLICT(jti) DO NOTHING
  `).run(verified.jti, nowMs, verified.exp_seconds * 1000);
  if (insert.changes === 0) {
    const e = new Error('session token already used');
    e.code = 'SESSION_CONSUMED';
    throw e;
  }
  if (insert.changes !== 1) {
    const e = new Error('session token raced; consumed by concurrent request');
    e.code = 'SESSION_RACE';
    throw e;
  }
  // Best-effort opportunistic prune of expired denylist rows.
  // Failure here is non-fatal -- the row is consumed regardless.
  try {
    db.prepare('DELETE FROM mfa_consumed_jtis WHERE expires_at < ?').run(nowMs);
  } catch (pruneErr) {
    logger.warn('mfa_consumed_jtis prune failed', { error: pruneErr.message });
  }
  return { user_id: verified.user_id };
}

/**
 * Check (without consuming) whether a JTI is already on the denylist.
 * Used by /login-mfa and /login-enroll-confirm to short-circuit a
 * replay before doing TOTP verification work; the actual single-use
 * gate is consumeMfaSessionJti above (race-safe via INSERT).
 */
function isMfaSessionJtiConsumed(db, jti) {
  return !!db.prepare('SELECT 1 FROM mfa_consumed_jtis WHERE jti = ?').get(jti);
}

/**
 * Issue accessToken + refreshToken + sessions row for the given
 * authenticated user. Centralized so /login (analyst path),
 * /login-mfa, and /login-enroll-confirm all use the same pathway.
 * Returns the response shape sent to the client.
 */
function issueJwt(db, user, ipAddress, userAgent) {
  const accessToken = signToken(user);
  const refreshToken = crypto.randomBytes(64).toString('hex');
  const refreshHash = bcrypt.hashSync(refreshToken, 10);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000).toISOString();
  db.prepare(`
    INSERT INTO sessions (user_id, refresh_token_hash, ip_address, user_agent, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(user.id, refreshHash, ipAddress || null, userAgent || null, expiresAt);
  db.prepare(`UPDATE users SET last_login = datetime('now') WHERE id = ?`).run(user.id);
  return {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      name: user.name,
      role: user.role,
      tier: user.tier,
      shift: user.shift,
    },
  };
}

// All session-invalid codes map to 401 -- the client must restart
// the login flow. 410 (Gone) might be more semantically correct for
// EXPIRED but the client behavior is identical (re-login), so 401
// keeps mapping simple.
function sessionInvalidStatus(_code) {
  return 401;
}

// ── POST /api/auth/login ─────────────────────────────────────────────────────
//
// Verify password; route to one of three outcomes based on user
// state:
//
//   1. User is enrolled in MFA (totp_enrolled_at IS NOT NULL):
//      Returns { mfa_required: true, mfa_session_token, accepts:
//      ['totp_code', 'recovery_code'] }. NO JWT issued. Client must
//      complete via POST /login-mfa with the token + a TOTP code or
//      recovery code.
//
//   2. User has mfa_enrollment_required=1 AND not enrolled:
//      Returns { mfa_enrollment_required: true, mfa_session_token,
//      enroll_endpoints }. NO JWT issued. Client must complete
//      enrollment via /login-enroll-start + /login-enroll-confirm;
//      the confirm endpoint issues the JWT.
//
//   3. User has no MFA enrollment AND no enrollment requirement
//      (analyst with default role state, or admin who explicitly
//      opted out -- not currently possible but this code path
//      preserves backward compat):
//      Returns { accessToken, refreshToken, user } directly.
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const db = getDb();
    const user = db.prepare(`
      SELECT * FROM users WHERE username = ? AND auth_method = ?
    `).get(username, 'local');

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      auditLog(null, 'LOGIN_FAILED', `username=${username}`, req.ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const enrolled = !!user.totp_enrolled_at;
    const enrollmentRequired = user.mfa_enrollment_required === 1;
    const ua = req.headers['user-agent'];

    // Path 1: enrolled -> issue bridge JWT, require MFA verify.
    if (enrolled) {
      const bridge = createMfaSessionJwt(user.id);
      auditLog(user.id, 'LOGIN_PASSWORD_OK',
        `role=${user.role} mfa=enrolled`, req.ip);
      return res.json({
        mfa_required: true,
        mfa_session_token: bridge.token,
        expires_at: bridge.expires_at_ms,
        accepts: ['totp_code', 'recovery_code'],
      });
    }

    // Path 2: enrollment required but not enrolled -> issue bridge
    // JWT, require enrollment via /login-enroll-start + -confirm.
    if (enrollmentRequired) {
      const bridge = createMfaSessionJwt(user.id);
      auditLog(user.id, 'LOGIN_PASSWORD_OK_PENDING_ENROLLMENT',
        `role=${user.role}`, req.ip);
      return res.json({
        mfa_enrollment_required: true,
        mfa_session_token: bridge.token,
        expires_at: bridge.expires_at_ms,
        enroll_endpoints: {
          start: '/api/auth/login-enroll-start',
          confirm: '/api/auth/login-enroll-confirm',
        },
      });
    }

    // Path 3: no MFA needed -> issue JWT directly. Backward-compat
    // with v1.0.30 and earlier; analyst default path.
    const result = issueJwt(db, user, req.ip, ua);
    auditLog(user.id, 'LOGIN_SUCCESS', `role=${user.role}`, req.ip);
    return res.json(result);
  } catch (err) {
    logger.error('Login error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'Authentication error' });
  }
});

// ── POST /api/auth/login-mfa ─────────────────────────────────────────────────
//
// Complete a two-step login by verifying the second factor. The
// request body must contain mfa_session_token (issued by /login)
// and EXACTLY ONE of totp_code or recovery_code (sending both is
// rejected to prevent ambiguity / dual-factor probing in a single
// request).
//
// On success: consumes the session token (single-use), issues
// accessToken + refreshToken + user, audit-logs LOGIN_SUCCESS. The
// MFA factor itself is audit-logged by the totp service
// (TOTP_VERIFY_OK / TOTP_RECOVERY_USED / etc.).
//
// On MFA-factor failure: session token is NOT consumed (the user
// may retry the MFA factor within the 5-min session TTL), but the
// totp service's lockout still applies (5 failures in 15 min ->
// 30-minute lockout via the totp:userId namespace).
router.post('/login-mfa', (req, res) => {
  const body = req.body || {};
  const sessionToken = body.mfa_session_token;
  const totpCode = body.totp_code;
  const recoveryCode = body.recovery_code;

  if (typeof sessionToken !== 'string' || sessionToken.length === 0) {
    return res.status(400).json({ error: 'mfa_session_token required' });
  }
  if (totpCode && recoveryCode) {
    return res.status(400).json({
      error: 'provide exactly one of totp_code or recovery_code, not both',
      code: 'INVALID_INPUT',
    });
  }
  if (!totpCode && !recoveryCode) {
    return res.status(400).json({
      error: 'provide totp_code or recovery_code',
      code: 'INVALID_INPUT',
      accepts: ['totp_code', 'recovery_code'],
    });
  }

  try {
    const db = getDb();

    // Verify bridge JWT WITHOUT consuming -- if MFA verification
    // fails, the user can retry within the JWT's TTL without re-
    // logging-in.
    let userId, verified;
    try {
      verified = verifyMfaSessionJwt(sessionToken);
      userId = verified.user_id;
    } catch (sessionErr) {
      auditLog(null, 'LOGIN_MFA_SESSION_INVALID',
        sessionErr.code || 'unknown', req.ip);
      return res.status(sessionInvalidStatus(sessionErr.code)).json({
        error: sessionErr.message,
        code: sessionErr.code || 'SESSION_INVALID',
      });
    }
    // Short-circuit replay: if the JTI is already on the denylist,
    // refuse before doing TOTP verification work. The actual single-
    // use gate is the atomic consume below; this check exists so a
    // confirmed-replay request returns immediately rather than after
    // TOTP processing.
    if (isMfaSessionJtiConsumed(getDb(), verified.jti)) {
      auditLog(userId, 'LOGIN_MFA_SESSION_INVALID', 'replay', req.ip);
      return res.status(401).json({
        error: 'session token already used',
        code: 'SESSION_CONSUMED',
      });
    }

    // Verify the MFA factor. The totp service handles audit logging
    // for the factor itself plus brute-force lockout.
    try {
      if (totpCode) {
        totp.verify(db, userId, totpCode, req.ip);
      } else {
        totp.consumeRecoveryCode(db, userId, recoveryCode, req.ip);
      }
    } catch (totpErr) {
      if (totpErr instanceof totp.TotpError) {
        const status = totpErr.code === totp.CODES.LOCKED_OUT ? 429
          : totpErr.code === totp.CODES.INVALID_INPUT ? 400
          : totpErr.code === totp.CODES.NOT_ENROLLED ? 403
          : totpErr.code === totp.CODES.NO_RECOVERY_CODES_GENERATED ? 403
          : totpErr.code === totp.CODES.RECOVERY_CODES_EXHAUSTED ? 403
          : totpErr.code === totp.CODES.RECOVERY_CODE_RACE ? 409
          : 401;
        return res.status(status).json({
          error: totpErr.message,
          code: totpErr.code,
          detail: totpErr.detail,
        });
      }
      throw totpErr;
    }

    // MFA passed. Atomic consume of the bridge JTI.
    try {
      consumeMfaSessionJti(db, verified);
    } catch (consumeErr) {
      auditLog(userId, 'LOGIN_MFA_SESSION_INVALID',
        `consume_race code=${consumeErr.code}`, req.ip);
      return res.status(sessionInvalidStatus(consumeErr.code)).json({
        error: 'session expired during MFA verification; please log in again',
        code: consumeErr.code || 'SESSION_INVALID',
      });
    }

    // Re-fetch the user to get fresh fields for issueJwt + the
    // public response. Defensive re-check that the user is still
    // enrolled in case MFA state changed between the password
    // verify and the MFA verify.
    const user = db.prepare(`SELECT * FROM users WHERE id = ?`).get(userId);
    if (!user) {
      return res.status(401).json({ error: 'user no longer exists' });
    }
    if (!user.totp_enrolled_at) {
      return res.status(401).json({
        error: 'MFA state changed during login; please log in again',
        code: 'MFA_STATE_CHANGED',
      });
    }

    const result = issueJwt(db, user, req.ip, req.headers['user-agent']);
    auditLog(user.id, 'LOGIN_SUCCESS', `role=${user.role} mfa=verified`, req.ip);
    return res.json(result);
  } catch (err) {
    logger.error('Login-MFA error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'Authentication error' });
  }
});

// ── POST /api/auth/login-enroll-start ────────────────────────────────────────
//
// First step of forced-enrollment flow for users with
// mfa_enrollment_required=1. The session token from /login proves
// the user has authenticated with their password; this endpoint
// returns the TOTP secret + otpauth URL + base64 PNG QR code so
// the user can scan into their authenticator app.
//
// Does NOT consume the session token -- that happens in
// /login-enroll-confirm. If the user fails to confirm, they can
// restart enrollment by calling /login-enroll-start again with the
// same session token (within the 5-min TTL). Each call replaces
// the in-progress secret (totp.enrollStart resets on re-call).
//
// Async handler: qrcode.toDataURL is Promise-based.
router.post('/login-enroll-start', async (req, res) => {
  const sessionToken = req.body && req.body.mfa_session_token;
  if (typeof sessionToken !== 'string' || sessionToken.length === 0) {
    return res.status(400).json({ error: 'mfa_session_token required' });
  }

  try {
    const db = getDb();
    let userId;
    try {
      ({ user_id: userId } = verifyMfaSessionJwt(sessionToken));
    } catch (sessionErr) {
      auditLog(null, 'LOGIN_MFA_SESSION_INVALID',
        sessionErr.code || 'unknown', req.ip);
      return res.status(sessionInvalidStatus(sessionErr.code)).json({
        error: sessionErr.message,
        code: sessionErr.code || 'SESSION_INVALID',
      });
    }

    const user = db.prepare(`
      SELECT id, username, name, totp_enrolled_at FROM users WHERE id = ?
    `).get(userId);
    if (!user) {
      return res.status(401).json({ error: 'user no longer exists' });
    }
    if (user.totp_enrolled_at) {
      // User became enrolled out-of-band. Refuse this path; the
      // session token is still valid, but the user should switch to
      // /login-mfa instead.
      return res.status(409).json({
        error: 'user is already enrolled; use /login-mfa instead',
        code: 'ALREADY_ENROLLED',
      });
    }

    let result;
    try {
      result = totp.enrollStart(db, userId, {
        issuer: 'FireAlive',
        account_label: user.name || user.username,
        client_ip: req.ip,
      });
    } catch (err) {
      if (err instanceof totp.TotpError) {
        return res.status(err.code === totp.CODES.ALREADY_ENROLLED ? 409 : 500).json({
          error: err.message,
          code: err.code,
        });
      }
      throw err;
    }

    // Best-effort QR PNG. Failure to render is non-fatal -- the
    // otpauth_url alone is sufficient for manual key entry.
    let qrPngDataUrl = null;
    try {
      qrPngDataUrl = await qrcode.toDataURL(result.otpauth_url, {
        errorCorrectionLevel: 'M',
        margin: 2,
        width: 256,
      });
    } catch (qrErr) {
      logger.warn('QR PNG render failed in login-enroll-start', {
        userId,
        error: qrErr.message,
      });
    }

    return res.status(201).json({
      secret_base32: result.secret_base32,
      otpauth_url: result.otpauth_url,
      qr_png_data_url: qrPngDataUrl,
    });
  } catch (err) {
    logger.error('Login-enroll-start error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'Authentication error' });
  }
});

// ── POST /api/auth/login-enroll-confirm ──────────────────────────────────────
//
// Second step of forced-enrollment flow. Verifies the user's first
// TOTP code from their authenticator, marks them enrolled, generates
// 10 single-use recovery codes, consumes the session token, and
// issues a JWT.
//
// Body: { mfa_session_token, totp_code }
//
// Response: { accessToken, refreshToken, user, recovery_codes }
//
//   recovery_codes is the array of 10 plaintext codes for one-time
//   display by the frontend. The frontend MUST display these and
//   advise the user to record them; the server cannot retrieve them
//   later (bcrypt-hashed at rest).
router.post('/login-enroll-confirm', (req, res) => {
  const body = req.body || {};
  const sessionToken = body.mfa_session_token;
  const totpCode = body.totp_code;

  if (typeof sessionToken !== 'string' || sessionToken.length === 0) {
    return res.status(400).json({ error: 'mfa_session_token required' });
  }
  if (typeof totpCode !== 'string' || !/^\d{6}$/.test(totpCode)) {
    return res.status(400).json({
      error: 'totp_code must be exactly 6 digits',
      code: 'INVALID_INPUT',
    });
  }

  try {
    const db = getDb();

    // Validate without consuming -- if confirm fails (typo'd code),
    // the user retries within the same bridge JWT TTL.
    let userId, verified;
    try {
      verified = verifyMfaSessionJwt(sessionToken);
      userId = verified.user_id;
    } catch (sessionErr) {
      auditLog(null, 'LOGIN_MFA_SESSION_INVALID',
        sessionErr.code || 'unknown', req.ip);
      return res.status(sessionInvalidStatus(sessionErr.code)).json({
        error: sessionErr.message,
        code: sessionErr.code || 'SESSION_INVALID',
      });
    }
    if (isMfaSessionJtiConsumed(db, verified.jti)) {
      auditLog(userId, 'LOGIN_MFA_SESSION_INVALID', 'replay', req.ip);
      return res.status(401).json({
        error: 'session token already used',
        code: 'SESSION_CONSUMED',
      });
    }

    let confirmResult;
    try {
      confirmResult = totp.enrollConfirm(db, userId, totpCode, req.ip);
    } catch (err) {
      if (err instanceof totp.TotpError) {
        const status = err.code === totp.CODES.CODE_INVALID ? 401
          : err.code === totp.CODES.NOT_ENROLLED ? 403
          : err.code === totp.CODES.ALREADY_ENROLLED ? 409
          : 400;
        return res.status(status).json({ error: err.message, code: err.code });
      }
      throw err;
    }

    // Confirmation succeeded. Consume the bridge JTI atomically.
    try {
      consumeMfaSessionJti(db, verified);
    } catch (consumeErr) {
      auditLog(userId, 'LOGIN_MFA_SESSION_INVALID',
        `enroll_consume_race code=${consumeErr.code}`, req.ip);
      return res.status(sessionInvalidStatus(consumeErr.code)).json({
        error: 'session expired during enrollment confirmation; please log in again',
        code: consumeErr.code || 'SESSION_INVALID',
      });
    }

    const user = db.prepare(`SELECT * FROM users WHERE id = ?`).get(userId);
    const result = issueJwt(db, user, req.ip, req.headers['user-agent']);
    auditLog(user.id, 'LOGIN_SUCCESS',
      `role=${user.role} mfa=enrolled-this-session`, req.ip);

    return res.json({
      ...result,
      recovery_codes: confirmResult.recovery_codes,
    });
  } catch (err) {
    logger.error('Login-enroll-confirm error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'Authentication error' });
  }
});

// ── POST /api/auth/refresh ───────────────────────────────────────────────────
//
// Re-issue an access token using a refresh token. R3f-modified:
// also re-checks the user's enrollment state on each refresh. If
// the user has mfa_enrollment_required=1 AND is not enrolled, the
// refresh is refused with 403 ENROLLMENT_REQUIRED -- the user must
// re-login through the new flow.
//
// This is the mechanism by which pre-v1.0.31 JWTs (issued before
// MFA enforcement was introduced) cannot extend the access of
// admins/leads who haven't enrolled. The 15-minute access-token
// TTL bounds the existing-JWT validity window; once that token
// expires, refresh refuses without enrollment, and the user must
// log in again under the new flow.
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

  try {
    const db = getDb();
    const sessions = db.prepare(`
      SELECT s.*,
             u.id   AS user_id,
             u.role AS role,
             u.name AS name,
             u.tier AS tier,
             u.shift AS shift,
             u.mfa_enrollment_required AS mfa_enrollment_required,
             u.totp_enrolled_at        AS totp_enrolled_at,
             u.active                  AS active
      FROM sessions s JOIN users u ON s.user_id = u.id
      WHERE s.expires_at > datetime('now')
    `).all();

    let matched = null;
    for (const s of sessions) {
      if (bcrypt.compareSync(refreshToken, s.refresh_token_hash)) {
        matched = s;
        break;
      }
    }

    if (!matched) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    if (matched.active === 0) {
      auditLog(matched.user_id, 'LOGIN_ENROLLMENT_BLOCKED',
        'user inactive on refresh', req.ip);
      return res.status(403).json({
        error: 'account is inactive',
        code: 'ACCOUNT_INACTIVE',
      });
    }
    if (matched.mfa_enrollment_required === 1 && !matched.totp_enrolled_at) {
      auditLog(matched.user_id, 'LOGIN_ENROLLMENT_BLOCKED',
        `role=${matched.role}`, req.ip);
      return res.status(403).json({
        error: 'MFA enrollment required; please log in again',
        code: 'ENROLLMENT_REQUIRED',
      });
    }

    const accessToken = signToken({
      id: matched.user_id,
      role: matched.role,
      name: matched.name,
      tier: matched.tier,
      shift: matched.shift,
    });
    return res.json({ accessToken });
  } catch (err) {
    logger.error('Token refresh error', { error: err.message });
    return res.status(500).json({ error: 'Token refresh failed' });
  }
});

// ── POST /api/auth/logout ────────────────────────────────────────────────────
//
// Unchanged from v1.0.30.
router.post('/logout', (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) {
    try {
      const db = getDb();
      const authHeader = req.headers.authorization;
      if (authHeader) {
        const decoded = jwt.decode(authHeader.slice(7));
        if (decoded && decoded.id) {
          db.prepare('DELETE FROM sessions WHERE user_id = ?').run(decoded.id);
          auditLog(decoded.id, 'LOGOUT', '', req.ip);
        }
      }
    } catch (err) {
      logger.error('Logout error', { error: err.message });
    }
  }
  return res.json({ ok: true });
});

// ── GET /api/auth/me ─────────────────────────────────────────────────────────
//
// Unchanged from v1.0.30.
router.get('/me', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    const { verifyToken } = require('../middleware/auth');
    const user = verifyToken(authHeader.slice(7));
    return res.json({
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
        tier: user.tier,
        shift: user.shift,
      },
    });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

module.exports = router;

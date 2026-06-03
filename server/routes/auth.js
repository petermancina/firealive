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
const { verifyPeerCertificate } = require('../middleware/network-security');
const ca = require('../services/ca');
const webauthn = require('../services/webauthn');
const { decryptConfig } = require('../services/encryption');
const rateLimit = require('express-rate-limit');

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
    if (!passwordAuthAllowed(db)) {
      auditLog(null, 'LOGIN_PASSWORD_BLOCKED', `username=${username}`, req.ip);
      return res.status(403).json({ error: 'password authentication is disabled (passwordless enforcement). Use a client certificate or passkey.' });
    }
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

// ═══════════════════════════════════════════════════════════════════════════════
// B5b — Passwordless authentication, the password/LDAP exception, and break-glass
//
// FireAlive's default posture is passwordless and phishing-resistant: a mutual-
// TLS client certificate or a FIDO2/WebAuthn passkey, both AAL3. Password and
// LDAP logins are an off-by-default exception gated behind the auth_enforcement
// config: 'passwordless' (default, by absence) rejects them at the application
// layer; 'allow_password' permits them. MFA is treated as ASSURANCE, not
// prompt-count — a cert+PIN or a user-verified passkey is already MFA-complete,
// so the passwordless paths issue a session directly unless the operator sets
// mfa_require_second_factor_always.
// ═══════════════════════════════════════════════════════════════════════════════

// auth_enforcement: 'passwordless' (default) | 'allow_password'.
function getAuthEnforcement(db) {
  try {
    const r = db.prepare("SELECT value FROM config WHERE key = 'auth_enforcement'").get();
    return r && r.value === 'allow_password' ? 'allow_password' : 'passwordless';
  } catch (_) {
    return 'passwordless';
  }
}
function passwordAuthAllowed(db) {
  return getAuthEnforcement(db) === 'allow_password';
}

// mfa_require_second_factor_always: default off. When on, even an AAL3
// passwordless login is bridged to a second factor (if the user has one).
function secondFactorAlways(db) {
  try {
    const r = db.prepare("SELECT value FROM config WHERE key = 'mfa_require_second_factor_always'").get();
    return !!(r && (r.value === 'true' || r.value === '1'));
  } catch (_) {
    return false;
  }
}

// Finish an AAL3 (cert / user-verified passkey) login. The credential is already
// MFA-complete, so issue the session directly — unless policy demands a second
// factor and the user actually has a TOTP factor enrolled.
function finishPasswordlessLogin(db, user, req, res, method) {
  if (user.offboarded_at) {
    auditLog(user.id, 'LOGIN_OFFBOARDED', `method=${method}`, req.ip);
    return res.status(403).json({ error: 'account offboarded' });
  }
  if (secondFactorAlways(db) && user.totp_enrolled_at) {
    const bridge = createMfaSessionJwt(user.id);
    auditLog(user.id, `LOGIN_${method.toUpperCase()}_OK`, `role=${user.role} mfa=required-by-policy`, req.ip);
    return res.json({
      mfa_required: true,
      mfa_session_token: bridge.token,
      expires_at: bridge.expires_at_ms,
      accepts: ['totp_code', 'recovery_code'],
    });
  }
  const result = issueJwt(db, user, req.ip, req.headers['user-agent']);
  auditLog(user.id, 'LOGIN_SUCCESS', `role=${user.role} method=${method} aal=high`, req.ip);
  return res.json(result);
}

// Decrypted LDAP/AD config from integration_config (iam_ldap), or null when not
// configured. The bind password lives only here, encrypted at rest, and is never
// exposed to the client.
function loadLdapConfig(db) {
  try {
    const row = db.prepare(
      "SELECT config_encrypted FROM integration_config WHERE integration_type = 'iam_ldap'"
    ).get();
    if (!row || !row.config_encrypted) return null;
    const cfg = decryptConfig(row.config_encrypted);
    return cfg && cfg.server ? cfg : null;
  } catch (_) {
    return null;
  }
}

// ── POST /api/auth/login-cert — passwordless mutual-TLS client certificate ───
// The TLS layer requested the client cert (requestCert:true); this verifies it
// against the built-in CA and maps it to a user via the issued_certs record
// (user_id, else external_id). No password and no second prompt — a hardware
// cert + PIN is AAL3.
router.post('/login-cert', (req, res) => {
  try {
    const db = getDb();
    const result = verifyPeerCertificate(req, db);
    if (!result.valid) {
      auditLog(null, 'LOGIN_CERT_FAILED', `reason=${result.reason || 'unknown'}`, req.ip);
      return res.status(401).json({ error: 'client certificate not accepted', reason: result.reason });
    }
    let user = null;
    if (result.userId) user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.userId);
    if (!user && result.externalId) user = db.prepare('SELECT * FROM users WHERE external_id = ?').get(result.externalId);
    if (!user) {
      auditLog(null, 'LOGIN_CERT_NO_USER', `external_id=${result.externalId || 'none'}`, req.ip);
      return res.status(401).json({ error: 'certificate valid but no matching user' });
    }
    return finishPasswordlessLogin(db, user, req, res, 'cert');
  } catch (err) {
    logger.error('Login-cert error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'Authentication error' });
  }
});

// ── POST /api/auth/login-webauthn/options — passkey assertion options ────────
// Returns WebAuthn authentication options + a stateless challenge token. With no
// username, allowCredentials is empty (discoverable/resident-key login); with a
// username, it is scoped to that user's passwordless credentials.
router.post('/login-webauthn/options', async (req, res) => {
  try {
    const db = getDb();
    const rp = webauthn.getRpConfig(db);
    let allowCredentials = [];
    const username = req.body && req.body.username;
    if (username) {
      const u = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
      if (u) {
        allowCredentials = db.prepare(
          'SELECT credential_id AS credentialId, transports FROM webauthn_credentials WHERE user_id = ? AND is_passwordless = 1'
        ).all(u.id);
      }
    }
    const { options, challengeToken } = await webauthn.beginAuthentication({
      rp, allowCredentials, userVerification: 'required',
    });
    return res.json({ options, challengeToken });
  } catch (err) {
    logger.error('Login-webauthn options error', { error: err.message });
    return res.status(500).json({ error: 'could not start passkey authentication' });
  }
});

// ── POST /api/auth/login-webauthn/verify — verify passkey assertion ──────────
// Looks up the credential by id, verifies the assertion (user verification
// REQUIRED → a verified passkey is MFA-complete), updates the signature counter
// (clone detection), and issues a session. Only credentials enrolled for
// passwordless use may serve as a primary login.
router.post('/login-webauthn/verify', async (req, res) => {
  try {
    const db = getDb();
    const body = req.body || {};
    const response = body.response;
    const challengeToken = body.challengeToken;
    if (!response || !challengeToken) {
      return res.status(400).json({ error: 'response and challengeToken required' });
    }
    const credId = response.id || response.rawId;
    if (!credId) return res.status(400).json({ error: 'malformed assertion' });
    const cred = db.prepare('SELECT * FROM webauthn_credentials WHERE credential_id = ?').get(credId);
    if (!cred) {
      auditLog(null, 'LOGIN_WEBAUTHN_UNKNOWN_CRED', '', req.ip);
      return res.status(401).json({ error: 'unknown credential' });
    }
    const rp = webauthn.getRpConfig(db);
    let verification;
    try {
      verification = await webauthn.finishAuthentication({
        rp,
        response,
        challengeToken,
        credential: {
          credentialId: cred.credential_id,
          publicKey: cred.public_key,
          counter: cred.sign_count,
          transports: cred.transports,
        },
        requireUserVerification: true,
      });
    } catch (vErr) {
      auditLog(cred.user_id, 'LOGIN_WEBAUTHN_FAILED', `err=${vErr.message}`, req.ip);
      return res.status(401).json({ error: 'passkey verification failed' });
    }
    if (!verification.verified) {
      auditLog(cred.user_id, 'LOGIN_WEBAUTHN_FAILED', 'not verified', req.ip);
      return res.status(401).json({ error: 'passkey verification failed' });
    }
    db.prepare("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = datetime('now') WHERE id = ?")
      .run(verification.newCounter != null ? verification.newCounter : cred.sign_count, cred.id);
    if (cred.is_passwordless !== 1) {
      auditLog(cred.user_id, 'LOGIN_WEBAUTHN_NOT_PASSWORDLESS', '', req.ip);
      return res.status(403).json({ error: 'this passkey is not enrolled for passwordless login' });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(cred.user_id);
    if (!user) return res.status(401).json({ error: 'user no longer exists' });
    return finishPasswordlessLogin(db, user, req, res, 'webauthn');
  } catch (err) {
    logger.error('Login-webauthn verify error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'Authentication error' });
  }
});

// ── POST /api/auth/login-ldap — LDAP/AD password (allow_password exception) ──
// Gated behind auth_enforcement=allow_password. Binds AS the user to verify
// credentials; LDAP password is AAL1, so the MFA second-factor bridge applies
// exactly as it does for local password login.
router.post('/login-ldap', async (req, res) => {
  try {
    const db = getDb();
    if (!passwordAuthAllowed(db)) {
      auditLog(null, 'LOGIN_LDAP_BLOCKED', 'passwordless enforcement', req.ip);
      return res.status(403).json({ error: 'password/LDAP authentication is disabled (passwordless enforcement)' });
    }
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const ldapCfg = loadLdapConfig(db);
    if (!ldapCfg) return res.status(503).json({ error: 'LDAP is not configured' });

    const { LdapClient } = require('../integrations/ldap');
    const client = new LdapClient(ldapCfg);
    const authd = await client.authenticate(username, password);
    if (!authd.success) {
      auditLog(null, 'LOGIN_LDAP_FAILED', `username=${username}`, req.ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Find the user; JIT-provision on first LDAP login.
    let user = db.prepare('SELECT * FROM users WHERE username = ? AND auth_method = ?').get(username, 'ldap');
    if (!user && authd.entry && authd.entry.objectGUID) {
      user = db.prepare('SELECT * FROM users WHERE external_id = ? AND auth_method = ?').get(authd.entry.objectGUID, 'ldap');
    }
    if (!user) {
      const role = client._mapGroupToRole(authd.entry ? authd.entry.memberOf : []);
      const info = db.prepare(`
        INSERT INTO users (username, name, role, tier, auth_method, external_id, mfa_enrollment_required)
        VALUES (?, ?, ?, ?, 'ldap', ?, 1)
      `).run(
        username,
        (authd.entry && authd.entry.displayName) || username,
        role,
        role === 'analyst' ? 1 : null,
        authd.entry ? authd.entry.objectGUID : null
      );
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
      auditLog(user.id, 'LDAP_JIT_PROVISIONED', `role=${role}`, req.ip);
    }
    if (user.offboarded_at) {
      auditLog(user.id, 'LOGIN_LDAP_OFFBOARDED', '', req.ip);
      return res.status(403).json({ error: 'account offboarded' });
    }

    // AAL1 password — require the second factor, mirroring local /login.
    if (user.totp_enrolled_at) {
      const bridge = createMfaSessionJwt(user.id);
      auditLog(user.id, 'LOGIN_LDAP_OK', `role=${user.role} mfa=enrolled`, req.ip);
      return res.json({
        mfa_required: true,
        mfa_session_token: bridge.token,
        expires_at: bridge.expires_at_ms,
        accepts: ['totp_code', 'recovery_code'],
      });
    }
    if (user.mfa_enrollment_required === 1) {
      const bridge = createMfaSessionJwt(user.id);
      auditLog(user.id, 'LOGIN_LDAP_OK_PENDING_ENROLLMENT', `role=${user.role}`, req.ip);
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
    const result = issueJwt(db, user, req.ip, req.headers['user-agent']);
    auditLog(user.id, 'LOGIN_SUCCESS', `role=${user.role} method=ldap`, req.ip);
    return res.json(result);
  } catch (err) {
    logger.error('Login-ldap error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'Authentication error' });
  }
});

// ── POST /api/auth/break-glass — audited recovery ────────────────────────────
// Last-resort recovery when all admin authenticators are lost. The operator
// presents the one-time recovery credential minted at CA init (hash-only at
// rest). On success this issues a short-lived, single-purpose token authorizing
// the enrollment of ONE new admin authenticator — and nothing else: it is not a
// session and grants no data access (the cert/passkey enrollment endpoints honor
// this token's scope). Every attempt is audited; success is CRITICAL. The route
// is additionally rate-limited.
const breakglassLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many recovery attempts; try again later' },
});
router.post('/break-glass', breakglassLimiter, (req, res) => {
  try {
    const db = getDb();
    const credential = req.body && req.body.recovery_credential;
    if (!credential) return res.status(400).json({ error: 'recovery_credential required' });
    const ok = ca.verifyRecoveryCredential(db, credential);
    if (!ok) {
      auditLog(null, 'AUTH_BREAKGLASS_FAILED', 'invalid recovery credential', req.ip);
      return res.status(401).json({ error: 'invalid recovery credential' });
    }
    const token = jwt.sign(
      { purpose: 'breakglass', scope: 'enroll-admin-authenticator' },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: 600 }
    );
    auditLog(null, 'AUTH_BREAKGLASS_USED', 'recovery credential accepted; admin-authenticator enrollment authorized', req.ip);
    return res.json({
      breakglass_token: token,
      expires_in: 600,
      scope: 'enroll-admin-authenticator',
      message: 'Use this token to enroll one new admin authenticator (client certificate or passkey), then rotate the recovery credential.',
    });
  } catch (err) {
    logger.error('Break-glass error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'recovery error' });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
// B5b — Session-less credential enrollment (bootstrap + break-glass)
//
// A brand-new user (no credential yet) and a break-glass recovery operator both
// lack a session, and password login is off by default — so they cannot use the
// session-gated /api/mfa enrollment endpoints. These unauthenticated endpoints,
// mounted under /api/auth, let them enroll a FIRST passwordless passkey when they
// present a valid authorization token:
//
//   - an enrollment token (single-use, DB-backed, bound to a specific user),
//     minted by admin provisioning; or
//   - a break-glass token (short-lived signed token from /break-glass), which
//     targets an existing admin account to restore admin access.
//
// The passkey is always enrolled as a passwordless (discoverable, user-verified)
// login credential. Cert enrollment via these tokens is handled alongside the
// IAM cert-enrollment endpoints.
// ═══════════════════════════════════════════════════════════════════════════════

// Resolve the enrollment authorization carried in the request body to a target
// user. Returns { ok:true, userId, kind, tokenRow? } or { ok:false, status, error }.
function resolveEnrollmentAuth(db, body) {
  body = body || {};
  if (body.enrollment_token) {
    const hash = crypto.createHash('sha256').update(String(body.enrollment_token)).digest('hex');
    const row = db.prepare(`
      SELECT * FROM enrollment_tokens
      WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL
        AND expires_at > datetime('now')
    `).get(hash);
    if (!row) return { ok: false, status: 401, error: 'invalid or expired enrollment token' };
    return { ok: true, userId: row.user_id, kind: 'enrollment', tokenRow: row };
  }
  if (body.breakglass_token) {
    let decoded;
    try {
      decoded = jwt.verify(body.breakglass_token, JWT_SECRET, { algorithms: ['HS256'] });
    } catch (_) {
      return { ok: false, status: 401, error: 'invalid break-glass token' };
    }
    if (!decoded || decoded.purpose !== 'breakglass') {
      return { ok: false, status: 401, error: 'invalid break-glass token' };
    }
    if (!body.admin_username) {
      return { ok: false, status: 400, error: 'admin_username required for break-glass enrollment' };
    }
    const admin = db.prepare("SELECT * FROM users WHERE username = ? AND role = 'admin'").get(body.admin_username);
    if (!admin) return { ok: false, status: 404, error: 'admin user not found' };
    return { ok: true, userId: admin.id, kind: 'breakglass' };
  }
  return { ok: false, status: 400, error: 'enrollment_token or breakglass_token required' };
}

// ── POST /api/auth/enroll/passkey/options ───────────────────────────────────
// Begin first-passkey enrollment for a token-authorized user. The passkey is
// requested as a discoverable resident key with user verification required.
router.post('/enroll/passkey/options', async (req, res) => {
  try {
    const db = getDb();
    const auth = resolveEnrollmentAuth(db, req.body);
    if (!auth.ok) {
      if (auth.status === 401) auditLog(null, 'ENROLL_TOKEN_REJECTED', auth.error, req.ip);
      return res.status(auth.status).json({ error: auth.error });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(auth.userId);
    if (!user) return res.status(404).json({ error: 'user not found' });
    const rp = webauthn.getRpConfig(db);
    const existing = db.prepare(
      'SELECT credential_id AS credentialId, transports FROM webauthn_credentials WHERE user_id = ?'
    ).all(user.id);
    const { options, challengeToken } = await webauthn.beginRegistration({
      rp,
      userId: user.id,
      userName: user.name || user.username || user.id,
      existingCredentials: existing,
      residentKey: 'required',
      userVerification: 'required',
    });
    return res.json({ options, challengeToken });
  } catch (err) {
    logger.error('Enroll passkey options error', { error: err.message });
    return res.status(500).json({ error: 'could not start enrollment' });
  }
});

// ── POST /api/auth/enroll/passkey/verify ────────────────────────────────────
// Finish first-passkey enrollment. Verifies the attestation (user verification
// required), persists the credential as passwordless, and — for an enrollment
// token — consumes it (single-use). Break-glass enrollment is audited as a
// critical event.
router.post('/enroll/passkey/verify', async (req, res) => {
  try {
    const db = getDb();
    const auth = resolveEnrollmentAuth(db, req.body);
    if (!auth.ok) {
      if (auth.status === 401) auditLog(null, 'ENROLL_TOKEN_REJECTED', auth.error, req.ip);
      return res.status(auth.status).json({ error: auth.error });
    }
    const body = req.body || {};
    if (!body.response || !body.challengeToken) {
      return res.status(400).json({ error: 'response and challengeToken required' });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(auth.userId);
    if (!user) return res.status(404).json({ error: 'user not found' });
    const rp = webauthn.getRpConfig(db);
    let result;
    try {
      result = await webauthn.finishRegistration({
        rp,
        response: body.response,
        challengeToken: body.challengeToken,
        requireUserVerification: true,
      });
    } catch (vErr) {
      return res.status(400).json({ error: 'passkey verification failed', detail: vErr.message });
    }
    if (!result.verified || !result.credential) {
      return res.status(400).json({ error: 'passkey verification failed' });
    }
    const c = result.credential;
    try {
      db.prepare(`
        INSERT INTO webauthn_credentials
          (user_id, credential_id, public_key, sign_count, transports, aaguid, is_passwordless)
        VALUES (?, ?, ?, ?, ?, ?, 1)
      `).run(user.id, c.credentialId, c.publicKey, c.counter || 0, c.transports || null, c.aaguid || null);
    } catch (dbErr) {
      if (/UNIQUE|constraint/i.test(dbErr.message)) {
        return res.status(409).json({ error: 'this authenticator is already enrolled' });
      }
      throw dbErr;
    }
    if (auth.kind === 'enrollment' && auth.tokenRow) {
      db.prepare("UPDATE enrollment_tokens SET used_at = datetime('now') WHERE id = ?").run(auth.tokenRow.id);
      auditLog(user.id, 'ENROLL_PASSKEY_BOOTSTRAP', `cred=${String(c.credentialId).slice(0, 12)}…`, req.ip);
    } else if (auth.kind === 'breakglass') {
      auditLog(user.id, 'AUTH_BREAKGLASS_ENROLLED', `admin passkey cred=${String(c.credentialId).slice(0, 12)}…`, req.ip);
    }
    return res.status(201).json({ enrolled: true, passwordless: true, credential_id: c.credentialId });
  } catch (err) {
    logger.error('Enroll passkey verify error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'enrollment error' });
  }
});


// ── POST /api/auth/enroll/cert ──────────────────────────────────────────────
// Finish first-certificate enrollment for a token-authorized (or break-glass)
// user. Takes a client-generated CSR, signs it with the built-in CA — the
// asserted identity is bound by a server-controlled SAN, not the CSR's CN, so
// a client cannot self-assert another user's identity — records the result in
// issued_certs, and returns the signed certificate plus the CA chain. For an
// enrollment token the token is consumed (single-use); break-glass issuance is
// audited as a critical event. Synchronous: ca.issueClientCert shells out to
// openssl.
router.post('/enroll/cert', (req, res) => {
  try {
    const db = getDb();
    const auth = resolveEnrollmentAuth(db, req.body);
    if (!auth.ok) {
      if (auth.status === 401) auditLog(null, 'ENROLL_TOKEN_REJECTED', auth.error, req.ip);
      return res.status(auth.status).json({ error: auth.error });
    }
    const body = req.body || {};
    if (!body.csrPem || typeof body.csrPem !== 'string') {
      return res.status(400).json({ error: 'csrPem (PEM string) required' });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(auth.userId);
    if (!user) return res.status(404).json({ error: 'user not found' });

    let issued;
    try {
      issued = ca.issueClientCert(db, {
        csrPem: body.csrPem,
        userId: user.id,
        externalId: user.external_id || null,
      });
    } catch (cErr) {
      return res.status(400).json({ error: 'certificate issuance failed', detail: cErr.message });
    }

    if (auth.kind === 'enrollment' && auth.tokenRow) {
      db.prepare("UPDATE enrollment_tokens SET used_at = datetime('now') WHERE id = ?").run(auth.tokenRow.id);
      auditLog(user.id, 'ENROLL_CERT_BOOTSTRAP', `serial=${issued.serial} fp=${String(issued.fingerprint256).slice(0, 16)}…`, req.ip);
    } else if (auth.kind === 'breakglass') {
      auditLog(user.id, 'AUTH_BREAKGLASS_CERT_ENROLLED', `admin cert serial=${issued.serial}`, req.ip);
    }

    return res.status(201).json({
      enrolled: true,
      certPem: issued.certPem,
      serial: issued.serial,
      fingerprint256: issued.fingerprint256,
      caCertPem: issued.caCertPem,
    });
  } catch (err) {
    logger.error('Enroll cert error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'enrollment error' });
  }
});

module.exports = router;

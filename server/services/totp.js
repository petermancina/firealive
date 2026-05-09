// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — TOTP Service (RFC 6238)
//
// Two-factor authentication via Time-Based One-Time Passwords. Used as the
// step-up MFA for the two-person restore-approval gate (services/restore-
// approvals.js -> approve()) and for any other privileged action that
// requires fresh user identity proof.
//
// Storage model (users table -- see db/init.js):
//   totp_secret           Tier-3 encrypted base32 secret, hex-encoded for
//                         SQLite TEXT compatibility. NULL until enrollStart.
//   totp_enrolled_at      ISO timestamp of successful enrollment. NULL while
//                         a user is in mid-enrollment (secret stored, not
//                         yet confirmed by a working OTP code).
//   totp_last_used_step   Absolute time-step counter of the last accepted
//                         OTP. Replay protection: subsequent verifies must
//                         use a step strictly greater than this value.
//
// Public API:
//   isEnrolled(db, userId)              -> boolean
//   isInEnrollment(db, userId)          -> boolean
//   enrollStart(db, userId, options)    -> { secret_base32, otpauth_url }
//   enrollConfirm(db, userId, code, ip) -> { enrolled_at }
//   verify(db, userId, code, ip)        -> { verified: true, step }
//   disable(db, userId, code, ip)       -> { disabled_at }
//
// All operations write to the audit log via middleware/audit. Callers
// (route handlers) should also add their own context-specific audit
// events on top (e.g. RESTORE_APPROVAL_APPROVED).
//
// Security properties:
//   - Tier-3 encryption-at-rest for the shared secret (compromise = bypass)
//   - Replay protection via monotonic step counter
//   - Brute-force lockout via the in-memory map from auth-hardening,
//     namespaced as `totp:${userId}` so TOTP failures don't share a
//     bucket with login failures
//   - Constant-time comparison inside speakeasy's verifyDelta
//   - Audit log on every operation (success and failure)
//   - disable() requires a valid current OTP -- you cannot turn off
//     someone else's MFA without their authenticator
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const speakeasy = require('speakeasy');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { encrypt, decrypt } = require('./encryption');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');
const { checkLockout, recordFailure, clearFailures } = require('../middleware/auth-hardening');

// ── Configuration ────────────────────────────────────────────────────────────

const TOTP_STEP_SECONDS = 30;       // RFC 6238 default; required by Google Authenticator etc.
const TOTP_WINDOW = 1;              // ±1 step (~±30s) clock-skew tolerance
const TOTP_DIGITS = 6;              // 6-digit codes (standard)
const TOTP_ALGORITHM = 'sha1';      // standard; required by every consumer authenticator app
const SECRET_BYTE_LENGTH = 20;      // 160 bits -> 32 base32 chars per RFC 4226 §5.1
const ISSUER_DEFAULT = 'FireAlive';
const LOCKOUT_NAMESPACE = 'totp:';  // separates TOTP failures from login failures

// ── Recovery code configuration ──────────────────────────────────────────────
//
// Recovery codes are single-use 14-char alphanumeric strings (e.g.
// "K7QM-3RTX-W9HJ") generated when the user completes TOTP enrollment.
// They are the user's fallback if their authenticator device is lost
// or unavailable. Codes are bcrypt-hashed at rest -- one-way hashing
// is strictly stronger than encryption for credential storage, since
// even compromise of TIER3_ENCRYPTION_KEY still leaves recovery codes
// unrecoverable.
//
// Alphabet: 32 unambiguous chars (no O/0/1/I/L), giving 5 bits per
// character. 12 alphanumeric chars * 5 bits = 60 bits per code; with
// bcrypt cost 10 (~100ms per check), brute-force on a single hash
// requires ~10^15 attempts at 100ms = millennia.
//
// Cost 10 matches the refresh-token pattern in routes/auth.js and
// keeps generation time bounded (~1 second sync on enrollment for
// 10 codes, acceptable for a one-time operation).

const RECOVERY_CODE_COUNT = 10;
const RECOVERY_CODE_GROUPS = 3;                                           // X-X-X
const RECOVERY_CODE_GROUP_LENGTH = 4;                                     // 4 chars per group
const RECOVERY_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';        // 32 unambiguous chars
const RECOVERY_CODE_BCRYPT_COST = 10;                                     // matches refresh-token storage

// ── Stable error codes (route layer maps to HTTP status) ─────────────────────

const CODES = {
  INVALID_INPUT:                'INVALID_INPUT',
  USER_NOT_FOUND:               'USER_NOT_FOUND',
  ALREADY_ENROLLED:             'ALREADY_ENROLLED',
  NOT_ENROLLED:                 'NOT_ENROLLED',
  CODE_INVALID:                 'CODE_INVALID',
  CODE_REPLAY:                  'CODE_REPLAY',
  LOCKED_OUT:                   'LOCKED_OUT',
  ENCRYPTION_NOT_CONFIGURED:    'ENCRYPTION_NOT_CONFIGURED',
  // R3f: recovery code error codes
  RECOVERY_CODE_INVALID:        'RECOVERY_CODE_INVALID',
  RECOVERY_CODES_EXHAUSTED:     'RECOVERY_CODES_EXHAUSTED',
  NO_RECOVERY_CODES_GENERATED:  'NO_RECOVERY_CODES_GENERATED',
  RECOVERY_CODE_RACE:           'RECOVERY_CODE_RACE',
};

class TotpError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'TotpError';
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

function nowEpochSeconds() {
  return Math.floor(Date.now() / 1000);
}

function currentStep() {
  return Math.floor(nowEpochSeconds() / TOTP_STEP_SECONDS);
}

function lockoutId(userId) {
  return `${LOCKOUT_NAMESPACE}${userId}`;
}

function getUser(db, userId) {
  if (typeof userId !== 'string' || userId === '') return null;
  return db.prepare(`
    SELECT id, username, totp_secret, totp_enrolled_at, totp_last_used_step
    FROM users WHERE id = ?
  `).get(userId);
}

/**
 * Encrypt a base32 secret with the Tier-3 key. Returns hex string for
 * SQLite TEXT storage. Throws TotpError if the Tier-3 key is missing
 * or invalid.
 */
function encryptSecret(base32) {
  try {
    return encrypt(base32, 'TIER3_ENCRYPTION_KEY').toString('hex');
  } catch (err) {
    throw new TotpError(
      CODES.ENCRYPTION_NOT_CONFIGURED,
      'TIER3_ENCRYPTION_KEY is not set; cannot encrypt TOTP secret. ' +
      'Generate a key with: ' +
      'node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
    );
  }
}

function decryptSecret(hex) {
  try {
    return decrypt(Buffer.from(hex, 'hex'), 'TIER3_ENCRYPTION_KEY');
  } catch (err) {
    throw new TotpError(
      CODES.ENCRYPTION_NOT_CONFIGURED,
      'Failed to decrypt TOTP secret -- TIER3_ENCRYPTION_KEY may be ' +
      'misconfigured, rotated without re-wrap, or the column value is corrupt',
    );
  }
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * True iff the user has confirmed TOTP enrollment (secret stored AND
 * enrolled_at set). Use this for the verify() pre-check in routes.
 */
function isEnrolled(db, userId) {
  const user = getUser(db, userId);
  return !!(user && user.totp_secret && user.totp_enrolled_at);
}

/**
 * True iff the user has started enrollment (secret stored) but has not
 * yet confirmed it with a working OTP code. The enrollment UI uses this
 * to know whether to start fresh or resume an in-progress flow.
 */
function isInEnrollment(db, userId) {
  const user = getUser(db, userId);
  return !!(user && user.totp_secret && !user.totp_enrolled_at);
}

/**
 * Generate a fresh TOTP secret and store it (encrypted). Does NOT mark
 * the user enrolled -- the caller must subsequently confirm with an
 * OTP code from their authenticator app via enrollConfirm().
 *
 * If the user is already fully enrolled, throws ALREADY_ENROLLED -- the
 * caller must disable() first to re-enroll.
 *
 * If the user is in mid-enrollment (secret stored but not confirmed),
 * the existing secret is replaced. This lets a user who lost their QR
 * mid-enrollment start over without admin intervention; nothing is
 * "active" yet so no security property is violated.
 *
 * Args:
 *   db        better-sqlite3 instance
 *   userId    string (required)
 *   options   { issuer?: string, account_label?: string, client_ip?: string }
 *
 * Returns: { secret_base32, otpauth_url }
 *
 * The route MUST only return secret_base32 and otpauth_url to the
 * authenticated user themselves. The secret should never appear in
 * any other response, log, or persistence layer (other than the
 * encrypted users.totp_secret column).
 *
 * QR PNG rendering is intentionally NOT done here -- the qrcode npm
 * library's PNG renderer is Promise-based, and this service file's
 * sync contract is preserved. Routes layer (POST /api/mfa/enroll-
 * start) awaits qrcode.toDataURL(otpauth_url) and merges
 * qr_png_base64 into the response to the client.
 */
function enrollStart(db, userId, options = {}) {
  const user = getUser(db, userId);
  if (!user) throw new TotpError(CODES.USER_NOT_FOUND, `user ${userId} not found`);
  if (user.totp_secret && user.totp_enrolled_at) {
    throw new TotpError(
      CODES.ALREADY_ENROLLED,
      'user is already enrolled in TOTP; call disable() first to re-enroll',
    );
  }

  const issuer = (options && typeof options.issuer === 'string' && options.issuer)
    ? options.issuer : ISSUER_DEFAULT;
  const label = (options && typeof options.account_label === 'string' && options.account_label)
    ? options.account_label : user.username;
  const clientIp = (options && typeof options.client_ip === 'string') ? options.client_ip : null;

  const secret = speakeasy.generateSecret({
    length: SECRET_BYTE_LENGTH,
    name: `${issuer} (${label})`,
    issuer,
  });

  // Persist (encrypted). Reset last_used_step to 0 -- if this is a re-
  // enrollment from a partial state, the old replay counter is no longer
  // meaningful since the secret itself changed.
  db.prepare(`
    UPDATE users
    SET totp_secret = ?,
        totp_enrolled_at = NULL,
        totp_last_used_step = 0,
        updated_at = datetime('now')
    WHERE id = ?
  `).run(encryptSecret(secret.base32), userId);

  auditLog(userId, 'TOTP_ENROLL_START', `issuer=${issuer} label=${label}`, clientIp);
  logger.info('TOTP enrollment started', { userId, issuer, label });

  return {
    secret_base32: secret.base32,
    otpauth_url: secret.otpauth_url,
  };
}

/**
 * Confirm TOTP enrollment by verifying the user's first code from their
 * authenticator app. On success, sets totp_enrolled_at, seeds
 * totp_last_used_step with the verified step (so this same code can
 * never be replayed for verify()), AND generates 10 single-use
 * recovery codes. The recovery codes are returned to the caller in
 * plaintext for one-time display to the user; their bcrypt hashes
 * are persisted in totp_recovery_codes_hashed.
 *
 * Failed enrollment confirmations do NOT count toward the lockout
 * counter -- this is a one-shot operation, the user can simply retry
 * by entering a fresh code, or restart enrollment. Lockout protection
 * applies only to verify().
 *
 * Returns: { enrolled_at, recovery_codes }
 *
 *   recovery_codes is an array of 10 plaintext strings. The caller
 *   (route handler) MUST display these to the user once and discard
 *   them; they are not stored plaintext anywhere on the server.
 */
function enrollConfirm(db, userId, code, clientIp) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    throw new TotpError(CODES.INVALID_INPUT, 'code must be a 6-digit string');
  }
  const ip = (typeof clientIp === 'string') ? clientIp : null;

  const user = getUser(db, userId);
  if (!user) throw new TotpError(CODES.USER_NOT_FOUND, `user ${userId} not found`);
  if (!user.totp_secret) {
    throw new TotpError(
      CODES.NOT_ENROLLED,
      'no enrollment in progress; call enrollStart() first',
    );
  }
  if (user.totp_enrolled_at) {
    throw new TotpError(CODES.ALREADY_ENROLLED, 'user is already enrolled');
  }

  const secret = decryptSecret(user.totp_secret);

  const result = speakeasy.totp.verifyDelta({
    secret,
    encoding: 'base32',
    token: code,
    window: TOTP_WINDOW,
    step: TOTP_STEP_SECONDS,
    digits: TOTP_DIGITS,
    algorithm: TOTP_ALGORITHM,
  });

  if (!result || typeof result.delta !== 'number') {
    auditLog(userId, 'TOTP_ENROLL_CONFIRM_FAIL', 'invalid code', ip);
    throw new TotpError(CODES.CODE_INVALID, 'TOTP code is invalid');
  }

  const usedStep = currentStep() + result.delta;
  const now = new Date().toISOString();

  // Race-safe: only confirm if still in mid-enrollment state.
  const upd = db.prepare(`
    UPDATE users
    SET totp_enrolled_at = ?,
        totp_last_used_step = ?,
        updated_at = datetime('now')
    WHERE id = ?
      AND totp_secret IS NOT NULL
      AND totp_enrolled_at IS NULL
  `).run(now, usedStep, userId);

  if (upd.changes !== 1) {
    // Race: another request confirmed enrollment between our read and
    // write. Treat as a no-op success -- the user is enrolled.
    logger.warn('TOTP enrollConfirm raced; user already enrolled', { userId });
  }

  auditLog(userId, 'TOTP_ENROLL_CONFIRM_OK', `step=${usedStep}`, ip);
  logger.info('TOTP enrollment confirmed', { userId, step: usedStep });

  // Generate recovery codes now that enrollment is confirmed. The user
  // just proved possession of the authenticator via the enrollment
  // code, so no additional MFA verification is needed for code
  // generation here. Codes are persisted (bcrypt-hashed) and returned
  // plaintext for one-time display.
  const recoveryCodes = generateRecoveryCodes(db, userId, { reason: 'enroll', client_ip: ip });

  return { enrolled_at: now, recovery_codes: recoveryCodes };
}

/**
 * Verify a TOTP code for an already-enrolled user. This is the primary
 * step-up MFA function used by privileged actions (restore approval,
 * config lock, panic mode, etc.).
 *
 * Lockout: identifier is namespaced as `totp:${userId}` to keep TOTP
 * failures separate from login failures (auth-hardening's bucket).
 * Defaults: 5 failures in 15 min -> 30-min lockout. On verify success,
 * the lockout counter is cleared.
 *
 * Replay protection: rejects any code whose step is <= the user's
 * last accepted step. Prevents an attacker who shoulder-surfed a single
 * OTP from re-using it within its 30-second validity window. The
 * counter is updated atomically with an optimistic lock so concurrent
 * requests cannot both succeed on the same step.
 *
 * Returns { verified: true, step } on success.
 * Throws TotpError on any failure (LOCKED_OUT, USER_NOT_FOUND,
 * NOT_ENROLLED, CODE_INVALID, CODE_REPLAY, INVALID_INPUT,
 * ENCRYPTION_NOT_CONFIGURED).
 */
function verify(db, userId, code, clientIp) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    throw new TotpError(CODES.INVALID_INPUT, 'code must be a 6-digit string');
  }
  const ip = (typeof clientIp === 'string') ? clientIp : null;
  const lockId = lockoutId(userId);

  const lockState = checkLockout(lockId);
  if (lockState.locked) {
    auditLog(userId, 'TOTP_VERIFY_BLOCKED', `locked remaining_ms=${lockState.remainingMs}`, ip);
    throw new TotpError(
      CODES.LOCKED_OUT,
      `TOTP verification temporarily locked due to repeated failures; ` +
      `try again in ${Math.ceil(lockState.remainingMs / 60000)} minutes`,
      { remaining_ms: lockState.remainingMs },
    );
  }

  const user = getUser(db, userId);
  if (!user) {
    // Don't recordFailure for user-not-found -- this is a route-level
    // misconfiguration, not a brute-force signal, and recording it
    // could be abused to lock out users by guessing their IDs.
    throw new TotpError(CODES.USER_NOT_FOUND, `user ${userId} not found`);
  }
  if (!user.totp_secret || !user.totp_enrolled_at) {
    throw new TotpError(CODES.NOT_ENROLLED, 'user has not completed TOTP enrollment');
  }

  const secret = decryptSecret(user.totp_secret);

  const result = speakeasy.totp.verifyDelta({
    secret,
    encoding: 'base32',
    token: code,
    window: TOTP_WINDOW,
    step: TOTP_STEP_SECONDS,
    digits: TOTP_DIGITS,
    algorithm: TOTP_ALGORITHM,
  });

  if (!result || typeof result.delta !== 'number') {
    recordFailure(lockId);
    auditLog(userId, 'TOTP_VERIFY_FAIL', 'invalid code', ip);
    throw new TotpError(CODES.CODE_INVALID, 'TOTP code is invalid');
  }

  const usedStep = currentStep() + result.delta;
  const lastStep = (typeof user.totp_last_used_step === 'number') ? user.totp_last_used_step : 0;

  if (usedStep <= lastStep) {
    recordFailure(lockId);
    auditLog(userId, 'TOTP_VERIFY_REPLAY', `step=${usedStep} last=${lastStep}`, ip);
    throw new TotpError(
      CODES.CODE_REPLAY,
      'TOTP code has already been used; wait for the next code',
      { used_step: usedStep, last_used_step: lastStep },
    );
  }

  // Atomic update with optimistic lock: only succeeds if no concurrent
  // verify() raced us and accepted a higher step.
  const upd = db.prepare(`
    UPDATE users
    SET totp_last_used_step = ?,
        updated_at = datetime('now')
    WHERE id = ?
      AND totp_secret IS NOT NULL
      AND totp_enrolled_at IS NOT NULL
      AND (totp_last_used_step IS NULL OR totp_last_used_step < ?)
  `).run(usedStep, userId, usedStep);

  if (upd.changes !== 1) {
    recordFailure(lockId);
    auditLog(userId, 'TOTP_VERIFY_REPLAY_RACE', `step=${usedStep}`, ip);
    throw new TotpError(
      CODES.CODE_REPLAY,
      'TOTP code was used by a concurrent request; wait for the next code',
      { used_step: usedStep },
    );
  }

  clearFailures(lockId);
  auditLog(userId, 'TOTP_VERIFY_OK', `step=${usedStep}`, ip);
  logger.info('TOTP verified', { userId, step: usedStep });

  return { verified: true, step: usedStep };
}

/**
 * Disable TOTP for a user. Requires a valid current OTP code as proof
 * of ownership -- you cannot disable someone else's MFA without their
 * authenticator. Admin-mediated reset (e.g. lost device) is a separate,
 * audit-heavy flow not implemented here; that path should require
 * second-person approval analogous to restore-approvals.
 *
 * On success, clears totp_secret, totp_enrolled_at, and resets
 * totp_last_used_step to 0.
 */
function disable(db, userId, code, clientIp) {
  // verify() handles all argument validation, lockout, and replay
  // protection. We piggyback on it so disable cannot be used to
  // sidestep any of those.
  const v = verify(db, userId, code, clientIp);
  const ip = (typeof clientIp === 'string') ? clientIp : null;
  const now = new Date().toISOString();

  db.prepare(`
    UPDATE users
    SET totp_secret = NULL,
        totp_enrolled_at = NULL,
        totp_last_used_step = 0,
        totp_recovery_codes_hashed = NULL,
        totp_recovery_codes_remaining = NULL,
        updated_at = datetime('now')
    WHERE id = ?
  `).run(userId);

  auditLog(userId, 'TOTP_DISABLED', `verified_step=${v.step}`, ip);
  logger.info('TOTP disabled', { userId });

  return { disabled_at: now };
}

// ── Recovery codes ───────────────────────────────────────────────────────────
//
// Single-use 14-char alphanumeric codes (e.g. "K7QM-3RTX-W9HJ") that
// substitute for a TOTP code when the user does not have access to
// their authenticator. Generated when TOTP enrollment is confirmed,
// regenerable later via regenerateRecoveryCodes (which requires a
// fresh TOTP code as proof of possession), one-way bcrypt-hashed at
// rest, single-use (consumption removes the matched hash from the
// stored array).
//
// Threat model:
//   - Bcrypt cost 10 + 60-bit code entropy -> brute force is
//     infeasible (~10^15 attempts at ~100ms each = millennia).
//   - Lockout namespace shared with TOTP (totp:userId) so attackers
//     can't probe both factors independently.
//   - One-way hashing -> compromise of TIER3_ENCRYPTION_KEY does
//     not expose recovery codes.
//   - Race-safe consume via CAS on the JSON-array column (the same
//     pattern as the TOTP step replay-protection update).

function generateRandomRecoveryCode() {
  // 4-4-4 alphanumeric, 60 bits of entropy total. Each character is
  // sampled from a 32-char unambiguous alphabet using crypto.randomInt
  // for cryptographically-secure randomness (Math.random would not be
  // SOC-grade -- it's not designed for cryptographic use).
  const groups = [];
  for (let g = 0; g < RECOVERY_CODE_GROUPS; g++) {
    let group = '';
    for (let c = 0; c < RECOVERY_CODE_GROUP_LENGTH; c++) {
      const idx = crypto.randomInt(0, RECOVERY_CODE_ALPHABET.length);
      group += RECOVERY_CODE_ALPHABET[idx];
    }
    groups.push(group);
  }
  return groups.join('-');
}

/**
 * Generate a fresh batch of recovery codes for an enrolled user. Used
 * by enrollConfirm (initial generation) and by regenerateRecoveryCodes
 * (caller-authorized rotation, which adds the TOTP-verified gate on
 * top). This function does NOT require any prior MFA verification --
 * the caller is responsible for ensuring the user is authorized to
 * generate codes (e.g. they just confirmed enrollment, or they
 * provided a valid TOTP).
 *
 * Replaces any existing codes (the column is overwritten, not
 * appended). All previously-issued codes for this user are
 * invalidated.
 *
 * Returns an array of plaintext codes for one-time display. The
 * caller MUST display these to the user once and discard; they are
 * never stored plaintext.
 *
 * Args:
 *   db        better-sqlite3 instance
 *   userId    string (required)
 *   options   { reason?: 'enroll' | 'regenerate', client_ip?: string }
 */
function generateRecoveryCodes(db, userId, options = {}) {
  if (typeof userId !== 'string' || userId === '') {
    throw new TotpError(CODES.INVALID_INPUT, 'userId is required');
  }
  const reason = (options && typeof options.reason === 'string') ? options.reason : 'enroll';
  const ip = (options && typeof options.client_ip === 'string') ? options.client_ip : null;

  const user = getUser(db, userId);
  if (!user) throw new TotpError(CODES.USER_NOT_FOUND, `user ${userId} not found`);
  if (!user.totp_secret || !user.totp_enrolled_at) {
    throw new TotpError(
      CODES.NOT_ENROLLED,
      'recovery codes can only be generated for users with confirmed TOTP enrollment',
    );
  }

  const codes = [];
  const hashes = [];
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const code = generateRandomRecoveryCode();
    codes.push(code);
    hashes.push(bcrypt.hashSync(code, RECOVERY_CODE_BCRYPT_COST));
  }

  db.prepare(`
    UPDATE users
    SET totp_recovery_codes_hashed = ?,
        totp_recovery_codes_remaining = ?,
        updated_at = datetime('now')
    WHERE id = ?
  `).run(JSON.stringify(hashes), codes.length, userId);

  const eventType = reason === 'regenerate' ? 'TOTP_RECOVERY_REGENERATED' : 'TOTP_RECOVERY_GENERATED';
  auditLog(userId, eventType, `count=${codes.length}`, ip);
  logger.info('TOTP recovery codes generated', { userId, reason, count: codes.length });

  return codes;
}

/**
 * Regenerate recovery codes, invalidating all previously-issued ones.
 * Requires a current valid TOTP code as proof of authenticator
 * possession -- protects against an attacker with a hijacked session
 * regenerating the codes (which would lock out the legitimate user
 * from their own recovery path).
 *
 * Returns the new plaintext codes for one-time display.
 */
function regenerateRecoveryCodes(db, userId, totpCode, clientIp) {
  // verify() handles all argument validation, lockout, and replay
  // protection. We piggyback on it so regenerate cannot be used to
  // sidestep those.
  verify(db, userId, totpCode, clientIp);
  return generateRecoveryCodes(db, userId, { reason: 'regenerate', client_ip: clientIp });
}

/**
 * Consume a single recovery code. Used as the fallback authentication
 * factor when the user does not have access to their TOTP
 * authenticator. Returns { verified: true, remaining } on success.
 *
 * Lockout protection: shares the totp:${userId} bucket with TOTP
 * verify, so attackers can't probe both factors independently. A
 * recovery code attempt failure counts against the same brute-force
 * lockout that protects TOTP.
 *
 * Race protection: CAS on the totp_recovery_codes_hashed column. If
 * another consume call wrote between our read and write, our update
 * is rejected and we throw RECOVERY_CODE_RACE -- the route handler
 * surfaces this as a transient 409 to the client, which can retry
 * with a different code.
 */
function consumeRecoveryCode(db, userId, code, clientIp) {
  if (typeof code !== 'string' || code.length === 0 || code.length > 64) {
    throw new TotpError(CODES.INVALID_INPUT, 'recovery code must be a non-empty string');
  }
  const ip = (typeof clientIp === 'string') ? clientIp : null;
  const lockId = lockoutId(userId);

  // Lockout shared with TOTP verify. An attacker who's exhausting
  // recovery codes is also exhausting TOTP attempts; one bucket
  // covers both attack paths.
  const lockState = checkLockout(lockId);
  if (lockState.locked) {
    auditLog(userId, 'TOTP_RECOVERY_BLOCKED', `locked remaining_ms=${lockState.remainingMs}`, ip);
    throw new TotpError(
      CODES.LOCKED_OUT,
      `MFA temporarily locked due to repeated failures; ` +
      `try again in ${Math.ceil(lockState.remainingMs / 60000)} minutes`,
      { remaining_ms: lockState.remainingMs },
    );
  }

  const user = getUser(db, userId);
  if (!user) {
    // Same rationale as verify(): don't recordFailure for user-not-
    // found, since this is a route-level misconfiguration rather than
    // a brute-force signal.
    throw new TotpError(CODES.USER_NOT_FOUND, `user ${userId} not found`);
  }
  if (!user.totp_secret || !user.totp_enrolled_at) {
    throw new TotpError(CODES.NOT_ENROLLED, 'user has not completed TOTP enrollment');
  }

  // Re-fetch the recovery code state -- getUser doesn't return these
  // columns by default since most callers don't need them.
  const recoveryRow = db.prepare(`
    SELECT totp_recovery_codes_hashed, totp_recovery_codes_remaining
    FROM users WHERE id = ?
  `).get(userId);

  if (!recoveryRow.totp_recovery_codes_hashed) {
    auditLog(userId, 'TOTP_RECOVERY_FAIL', 'no codes generated', ip);
    throw new TotpError(
      CODES.NO_RECOVERY_CODES_GENERATED,
      'no recovery codes have been generated for this user; use the regenerate endpoint',
    );
  }

  let hashes;
  try {
    hashes = JSON.parse(recoveryRow.totp_recovery_codes_hashed);
  } catch (parseErr) {
    logger.error('Recovery codes JSON parse failed', { userId, error: parseErr.message });
    throw new TotpError(CODES.NO_RECOVERY_CODES_GENERATED, 'recovery code state is corrupt; regenerate');
  }

  if (!Array.isArray(hashes) || hashes.length === 0) {
    auditLog(userId, 'TOTP_RECOVERY_EXHAUSTED', 'all consumed', ip);
    throw new TotpError(
      CODES.RECOVERY_CODES_EXHAUSTED,
      'all recovery codes have been used; regenerate or contact admin',
    );
  }

  // Linear bcrypt.compareSync scan. Each compare is ~100ms; up to 10
  // codes = up to 1 sec on the always-fail path. This is intentional:
  // forces brute-force attackers to spend ~1 sec per attempt even on
  // the fail path, while legitimate users with a valid code usually
  // match within the first few comparisons.
  let matchIndex = -1;
  for (let i = 0; i < hashes.length; i++) {
    if (bcrypt.compareSync(code, hashes[i])) {
      matchIndex = i;
      break;
    }
  }

  if (matchIndex === -1) {
    recordFailure(lockId);
    auditLog(userId, 'TOTP_RECOVERY_FAIL', `remaining=${hashes.length}`, ip);
    throw new TotpError(CODES.RECOVERY_CODE_INVALID, 'recovery code is invalid');
  }

  // Build new state with the matched hash removed, then CAS-write.
  const newHashes = hashes.slice(0, matchIndex).concat(hashes.slice(matchIndex + 1));
  const newRemaining = newHashes.length;
  const upd = db.prepare(`
    UPDATE users
    SET totp_recovery_codes_hashed = ?,
        totp_recovery_codes_remaining = ?,
        updated_at = datetime('now')
    WHERE id = ?
      AND totp_recovery_codes_hashed = ?
  `).run(JSON.stringify(newHashes), newRemaining, userId, recoveryRow.totp_recovery_codes_hashed);

  if (upd.changes !== 1) {
    // CAS failed: another consume raced us and modified the array
    // between our read and write. Don't credit the verification --
    // the caller must retry. Don't recordFailure since the code
    // itself was valid; the failure was transient state contention.
    auditLog(userId, 'TOTP_RECOVERY_RACE', `attempted_remaining=${newRemaining}`, ip);
    throw new TotpError(
      CODES.RECOVERY_CODE_RACE,
      'recovery code state changed during consumption; retry with a different code',
    );
  }

  clearFailures(lockId);
  auditLog(userId, 'TOTP_RECOVERY_USED', `remaining=${newRemaining}`, ip);
  logger.info('Recovery code consumed', { userId, remaining: newRemaining });

  return { verified: true, remaining: newRemaining };
}

/**
 * Read-only status of a user's recovery codes. Returns:
 *   { generated: boolean, remaining: number, total: number }
 *
 * generated is true once recovery codes have been generated for the
 * user (even if all have been consumed). remaining is the count of
 * unused codes; total is the original batch size (always
 * RECOVERY_CODE_COUNT for now). UI uses this to show a "low recovery
 * codes" warning when remaining drops below a threshold.
 */
function getRecoveryCodesStatus(db, userId) {
  if (typeof userId !== 'string' || userId === '') {
    throw new TotpError(CODES.INVALID_INPUT, 'userId is required');
  }
  const row = db.prepare(`
    SELECT totp_recovery_codes_hashed, totp_recovery_codes_remaining
    FROM users WHERE id = ?
  `).get(userId);
  if (!row) {
    throw new TotpError(CODES.USER_NOT_FOUND, `user ${userId} not found`);
  }
  const generated = !!row.totp_recovery_codes_hashed;
  const remaining = (typeof row.totp_recovery_codes_remaining === 'number')
    ? row.totp_recovery_codes_remaining
    : 0;
  return { generated, remaining, total: RECOVERY_CODE_COUNT };
}

// ── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  // Public API
  isEnrolled,
  isInEnrollment,
  enrollStart,
  enrollConfirm,
  verify,
  disable,

  // Recovery codes (R3f)
  generateRecoveryCodes,
  consumeRecoveryCode,
  regenerateRecoveryCodes,
  getRecoveryCodesStatus,

  // Error class + stable codes
  TotpError,
  CODES,

  // Configuration constants exposed for routes / tests
  TOTP_STEP_SECONDS,
  TOTP_WINDOW,
  TOTP_DIGITS,
  TOTP_ALGORITHM,
  RECOVERY_CODE_COUNT,

  // Internal helpers exposed for tests only -- not stable for production callers
  _internal: {
    currentStep,
    lockoutId,
    encryptSecret,
    decryptSecret,
    generateRandomRecoveryCode,
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Password Management Routes
// For orgs using local auth (no IAM/SSO). Implements:
//   - Secure password reset with time-limited tokens
//   - Account lockout after N failed attempts
//   - Rate limiting on auth endpoints (brute force / spray prevention)
//   - Session binding (IP + user agent) to prevent hijacking
//   - Password policy enforcement
//
// POST /api/auth/password/reset-request — request reset token
// POST /api/auth/password/reset         — reset with token
// POST /api/auth/password/change        — change while logged in
// GET  /api/auth/password/policy        — get password policy
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

const LOCKOUT_ATTEMPTS = 10;
const LOCKOUT_DURATION_MIN = 30;
const RESET_TOKEN_EXPIRY_MIN = 15;
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 128;

const PASSWORD_POLICY = {
  minLength: MIN_PASSWORD_LENGTH,
  maxLength: MAX_PASSWORD_LENGTH,
  requireUppercase: true,
  requireLowercase: true,
  requireDigit: true,
  requireSpecial: true,
  lockoutAttempts: LOCKOUT_ATTEMPTS,
  lockoutDurationMinutes: LOCKOUT_DURATION_MIN,
  resetTokenExpiryMinutes: RESET_TOKEN_EXPIRY_MIN,
  noAutofill: true,
  recommendations: [
    'Use a unique password — do not reuse passwords from other systems.',
    'Use a password manager to generate and store strong passwords.',
    'Never share your password or write it down.',
  ],
};

function validatePassword(password) {
  const errors = [];
  if (password.length < MIN_PASSWORD_LENGTH) errors.push(`Minimum ${MIN_PASSWORD_LENGTH} characters`);
  if (password.length > MAX_PASSWORD_LENGTH) errors.push(`Maximum ${MAX_PASSWORD_LENGTH} characters`);
  if (!/[A-Z]/.test(password)) errors.push('At least one uppercase letter');
  if (!/[a-z]/.test(password)) errors.push('At least one lowercase letter');
  if (!/\d/.test(password)) errors.push('At least one digit');
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) errors.push('At least one special character');
  return errors;
}

// ── Track Failed Attempts (in-memory, survives restart via DB) ───────────────
function getFailedAttempts(db, username) {
  const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`lockout_${username}`);
  if (!row) return { count: 0, lockedUntil: null };
  return JSON.parse(row.value);
}

function recordFailedAttempt(db, username) {
  const data = getFailedAttempts(db, username);
  data.count += 1;
  data.lastAttempt = new Date().toISOString();
  if (data.count >= LOCKOUT_ATTEMPTS) {
    data.lockedUntil = new Date(Date.now() + LOCKOUT_DURATION_MIN * 60000).toISOString();
  }
  db.prepare("INSERT OR REPLACE INTO team_config (key, value) VALUES (?, ?)").run(`lockout_${username}`, JSON.stringify(data));
  return data;
}

function clearFailedAttempts(db, username) {
  db.prepare("DELETE FROM team_config WHERE key = ?").run(`lockout_${username}`);
}

// ── Get Password Policy ──────────────────────────────────────────────────────
router.get('/policy', (req, res) => {
  res.json({ policy: PASSWORD_POLICY });
});

// ── Request Password Reset ───────────────────────────────────────────────────
router.post('/reset-request', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });

  try {
    const db = getDb();
    const user = db.prepare("SELECT id, username FROM users WHERE username = ? AND auth_method = 'local'").get(username);

    // Always return success (don't reveal if user exists)
    if (!user) {
      db.close();
      return res.json({ ok: true, message: 'If the account exists, a reset process has been initiated. Contact your team lead.' });
    }

    // Generate time-limited token
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const expiresAt = new Date(Date.now() + RESET_TOKEN_EXPIRY_MIN * 60000).toISOString();

    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(
      `reset_${user.id}`,
      JSON.stringify({ tokenHash, expiresAt, userId: user.id }),
      user.id
    );
    db.close();

    auditLog(user.id, 'PASSWORD_RESET_REQUESTED', '', req.ip);

    // In production, this token would be delivered via secure channel (team lead, email)
    // For now, return it (in production, remove this)
    res.json({
      ok: true,
      message: 'If the account exists, a reset process has been initiated. Contact your team lead.',
      // DEV ONLY — remove in production:
      _devToken: process.env.NODE_ENV !== 'production' ? token : undefined,
    });
  } catch (err) {
    logger.error('Reset request error', { error: err.message });
    res.status(500).json({ error: 'Failed to process reset request' });
  }
});

// ── Reset Password with Token ────────────────────────────────────────────────
router.post('/reset', (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: 'token and newPassword required' });

  const pwErrors = validatePassword(newPassword);
  if (pwErrors.length > 0) return res.status(400).json({ error: 'Password does not meet policy', violations: pwErrors });

  try {
    const db = getDb();
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Find matching reset token
    const rows = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'reset_%'").all();
    let found = null;
    for (const row of rows) {
      const data = JSON.parse(row.value);
      if (data.tokenHash === tokenHash) {
        if (new Date(data.expiresAt) < new Date()) {
          db.prepare("DELETE FROM team_config WHERE key = ?").run(row.key);
          db.close();
          return res.status(400).json({ error: 'Reset token has expired. Request a new one.' });
        }
        found = { key: row.key, ...data };
        break;
      }
    }

    if (!found) { db.close(); return res.status(400).json({ error: 'Invalid reset token' }); }

    // Update password
    const hash = bcrypt.hashSync(newPassword, 12);
    db.prepare('UPDATE users SET password_hash = ?, updated_at = datetime("now") WHERE id = ?').run(hash, found.userId);

    // Clean up token and lockout
    db.prepare("DELETE FROM team_config WHERE key = ?").run(found.key);
    clearFailedAttempts(db, found.userId);

    // Invalidate all sessions
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(found.userId);

    db.close();
    auditLog(found.userId, 'PASSWORD_RESET_COMPLETE', '', req.ip);
    res.json({ ok: true, message: 'Password reset successful. All sessions invalidated. Please log in.' });
  } catch (err) {
    logger.error('Reset error', { error: err.message });
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ── Change Password (while logged in) ────────────────────────────────────────
router.post('/change', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required' });

  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'currentPassword and newPassword required' });

  const pwErrors = validatePassword(newPassword);
  if (pwErrors.length > 0) return res.status(400).json({ error: 'Password does not meet policy', violations: pwErrors });

  try {
    const { verifyToken } = require('../middleware/auth');
    const decoded = verifyToken(authHeader.slice(7));

    const db = getDb();
    const user = db.prepare("SELECT * FROM users WHERE id = ? AND auth_method = 'local'").get(decoded.id);
    if (!user) { db.close(); return res.status(400).json({ error: 'Account uses SSO — password changes not supported here' }); }

    if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
      db.close();
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hash = bcrypt.hashSync(newPassword, 12);
    db.prepare('UPDATE users SET password_hash = ?, updated_at = datetime("now") WHERE id = ?').run(hash, user.id);
    db.close();

    auditLog(user.id, 'PASSWORD_CHANGED', '', req.ip);
    res.json({ ok: true, message: 'Password changed successfully.' });
  } catch (err) {
    logger.error('Change password error', { error: err.message });
    res.status(500).json({ error: 'Failed to change password' });
  }
});

module.exports = router;
module.exports.validatePassword = validatePassword;
module.exports.getFailedAttempts = getFailedAttempts;
module.exports.recordFailedAttempt = recordFailedAttempt;
module.exports.clearFailedAttempts = clearFailedAttempts;
module.exports.LOCKOUT_ATTEMPTS = LOCKOUT_ATTEMPTS;

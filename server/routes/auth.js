// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Auth Routes
// POST /api/auth/login — local username/password
// POST /api/auth/refresh — refresh JWT
// POST /api/auth/logout — invalidate session
// GET  /api/auth/me — current user info
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { signToken } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── Local Login ──────────────────────────────────────────────────────────────
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE username = ? AND auth_method = ?').get(username, 'local');

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      db.close();
      auditLog(null, 'LOGIN_FAILED', `username=${username}`, req.ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate tokens
    const accessToken = signToken(user);
    const refreshToken = crypto.randomBytes(64).toString('hex');
    const refreshHash = bcrypt.hashSync(refreshToken, 10);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    // Store session
    db.prepare(
      'INSERT INTO sessions (user_id, refresh_token_hash, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)'
    ).run(user.id, refreshHash, req.ip, req.headers['user-agent'], expiresAt);

    // Update last login
    db.prepare('UPDATE users SET last_login = datetime("now") WHERE id = ?').run(user.id);
    db.close();

    auditLog(user.id, 'LOGIN_SUCCESS', `role=${user.role}`, req.ip);

    res.json({
      accessToken,
      refreshToken,
      user: { id: user.id, name: user.name, role: user.role, tier: user.tier, shift: user.shift },
    });
  } catch (err) {
    logger.error('Login error', { error: err.message });
    res.status(500).json({ error: 'Authentication error' });
  }
});

// ── Token Refresh ────────────────────────────────────────────────────────────
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

  try {
    const db = getDb();
    const sessions = db.prepare(
      'SELECT s.*, u.* FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.expires_at > datetime("now")'
    ).all();

    let matched = null;
    for (const s of sessions) {
      if (bcrypt.compareSync(refreshToken, s.refresh_token_hash)) {
        matched = s;
        break;
      }
    }

    if (!matched) {
      db.close();
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const accessToken = signToken(matched);
    db.close();

    res.json({ accessToken });
  } catch (err) {
    logger.error('Token refresh error', { error: err.message });
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// ── Logout ───────────────────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    try {
      const db = getDb();
      // Delete all sessions for this token (we can't easily match by hash, so delete by user)
      const authHeader = req.headers.authorization;
      if (authHeader) {
        const jwt = require('jsonwebtoken');
        const decoded = jwt.decode(authHeader.slice(7));
        if (decoded?.id) {
          db.prepare('DELETE FROM sessions WHERE user_id = ?').run(decoded.id);
          auditLog(decoded.id, 'LOGOUT', '', req.ip);
        }
      }
      db.close();
    } catch (err) {
      logger.error('Logout error', { error: err.message });
    }
  }
  res.json({ ok: true });
});

// ── Current User ─────────────────────────────────────────────────────────────
router.get('/me', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const { verifyToken } = require('../middleware/auth');
    const user = verifyToken(authHeader.slice(7));
    res.json({ user: { id: user.id, name: user.name, role: user.role, tier: user.tier, shift: user.shift } });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

module.exports = router;

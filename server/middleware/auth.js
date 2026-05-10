// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Authentication Middleware
// Supports: local (username/password), SAML, OIDC, LDAP
// ═══════════════════════════════════════════════════════════════════════════════

const jwt = require('jsonwebtoken');
const { logger } = require('../services/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_INSECURE_DEFAULT';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '15m';

function signToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, name: user.name, tier: user.tier, shift: user.shift },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY, algorithm: 'HS256' }
  );
}

/**
 * Verify and decode an auth JWT.
 *
 * MFA BRIDGE JWT ASSERTION
 *
 * Rejects any token carrying mfa_pending=true. The MFA-bridge JWT
 * issued by routes/auth.js POST /login (and consumed by /login-mfa
 * + /login-enroll-confirm) carries this claim to mark itself as a
 * partial-login token, valid ONLY at the MFA-step endpoints. A
 * bridge JWT presented to a protected route -- whether by accident,
 * misuse, or attack -- is refused here regardless of whether the
 * signature, exp, and other structural checks pass.
 *
 * The error is shaped as a JsonWebTokenError so existing consumers
 * (authMiddleware below, websocket-server.js, password.js, the /me
 * + /refresh endpoints in routes/auth.js) handle it via their
 * existing invalid-token branches without code changes.
 *
 * Defense-in-depth: today the auth-JWT payload uses the `id` claim
 * and the bridge-JWT payload uses `sub`, so a bridge JWT presented
 * here would fail downstream when consumers read decoded.id and
 * find undefined. That asymmetry is real but implicit -- if
 * signToken is ever refactored to use `sub` (the more conventional
 * JWT field), the implicit protection silently disappears. The
 * explicit assertion below survives that refactor.
 */
function verifyToken(token) {
  const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  if (decoded && decoded.mfa_pending === true) {
    const e = new Error('MFA bridge JWT cannot be used for authentication');
    e.name = 'JsonWebTokenError';
    throw e;
  }
  return decoded;
}

/**
 * Express middleware factory. Returns middleware that checks JWT and role.
 * @param {string[]} allowedRoles - roles that can access this route
 */
function authMiddleware(allowedRoles = []) {
  return (req, res, next) => {
    // Check for API key authentication first
    const apiKey = req.headers['x-api-key'];
    if (apiKey) {
      return handleApiKeyAuth(apiKey, req, res, next);
    }

    // JWT Bearer token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    try {
      const token = authHeader.slice(7);
      const decoded = verifyToken(token);
      req.user = decoded;

      // Role check
      if (allowedRoles.length > 0 && !allowedRoles.includes(decoded.role)) {
        logger.warn('Access denied', { userId: decoded.id, role: decoded.role, required: allowedRoles, path: req.path });
        return res.status(403).json({ error: 'Insufficient permissions' });
      }

      next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
      }
      logger.warn('Invalid token', { error: err.message, path: req.path });
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

/**
 * API key authentication — checks x-api-key header against stored keys
 */
function handleApiKeyAuth(apiKey, req, res, next) {
  const bcrypt = require('bcryptjs');
  const { getDb } = require('../db/init');

  try {
    const db = getDb();
    const prefix = apiKey.slice(0, 8);
    const keys = db.prepare(
      'SELECT * FROM api_keys WHERE key_prefix = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > datetime("now"))'
    ).all(prefix);

    let matched = null;
    for (const k of keys) {
      if (bcrypt.compareSync(apiKey, k.key_hash)) {
        matched = k;
        break;
      }
    }

    if (!matched) {
      db.close();
      return res.status(401).json({ error: 'Invalid API key' });
    }

    // Update last_used_at
    db.prepare('UPDATE api_keys SET last_used_at = datetime("now") WHERE id = ?').run(matched.id);

    // Set user context from key creator
    const creator = db.prepare('SELECT id, role, name FROM users WHERE id = ?').get(matched.created_by);
    db.close();

    req.user = { id: creator.id, role: creator.role, name: creator.name, apiKey: true, scopes: matched.scopes.split(',') };
    next();
  } catch (err) {
    logger.error('API key auth error', { error: err.message });
    return res.status(500).json({ error: 'Authentication error' });
  }
}

module.exports = { authMiddleware, signToken, verifyToken };

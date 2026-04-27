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

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
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

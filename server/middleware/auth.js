// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Authentication Middleware
// Supports: local (username/password), SAML, OIDC, LDAP
// ═══════════════════════════════════════════════════════════════════════════════

const jwt = require('jsonwebtoken');
const { logger } = require('../services/logger');
const devicePop = require('../services/device-pop');
const deviceKey = require('../services/device-key');

let JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_INSECURE_DEFAULT';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '15m';

// Install a runtime JWT signing/validation secret. Used at HA promotion: the
// promoted passive unseals the shared JWT_SECRET (wrapped to its hardware at
// pairing) and installs it here, so it issues and validates the SAME sessions the
// former active did and users are not forced to re-authenticate after a failover.
// No-op for any node that never promotes -- the env value is used until installed.
function installRuntimeJwtSecret(secret) {
  if (secret) {
    JWT_SECRET = String(secret);
  }
}

function signToken(user, cnf) {
  const claims = { id: user.id, role: user.role, name: user.name, tier: user.tier, shift: user.shift };
  if (cnf) claims.cnf = cnf;
  return jwt.sign(claims, JWT_SECRET, { expiresIn: JWT_EXPIRY, algorithm: 'HS256' });
}

/**
 * Verify and decode an auth JWT.
 *
 * MFA BRIDGE JWT ASSERTION (defense-in-depth)
 *
 * Rejects any token carrying mfa_pending=true. The original R3f two-step
 * login flow used such an mfa_pending bridge JWT between password
 * verification and a second factor; that flow was removed when login became
 * passwordless single-step WebAuthn, so no route issues a bridge JWT today
 * (the /login-mfa and /login-enroll-confirm endpoints, and the
 * mfa_consumed_jtis denylist, are gone). This assertion is kept deliberately:
 * if an mfa_pending token ever appears -- via a future refactor that
 * reintroduces bridge tokens, by accident, or by attack -- it is refused for
 * authentication regardless of whether the signature, exp, and other
 * structural checks pass.
 *
 * The error is shaped as a JsonWebTokenError so existing consumers
 * (authMiddleware below, websocket-server.js, the /me + /refresh endpoints in
 * routes/auth.js) handle it via their existing invalid-token branches without
 * code changes.
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
function authMiddleware(allowedRoles = [], options = {}) {
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

      // Per-request proof-of-possession (B5f): a bound session must prove it
      // still holds the hardware device key on every call; a cnf-less session is
      // refused except on the bootstrap routes marked popExempt.
      const popCheck = enforceDevicePop(req, decoded, options);
      if (!popCheck.ok) {
        logger.warn('Device proof-of-possession refused', { userId: decoded.id, path: req.path, code: popCheck.code });
        return res.status(popCheck.status).json({ error: popCheck.error, code: popCheck.code });
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

// ══════════════════════════════════════════════════════════════════════════════
// Per-request proof-of-possession enforcement (B5f). A device-bound session
// (its token carries an RFC 7800 cnf.jkt) must present a fresh device-key proof
// on every request; a cnf-less session is refused except on the bootstrap routes
// marked popExempt (device-key registration and the self endpoints), which let a
// client register its key before its session is bound. Opportunistic mutual-TLS
// binding (cnf x5t#S256) is checked when present. The API-key path never reaches
// here. The active key is looked up by role: an analyst binds to the Analyst
// Client key table, an admin or lead to the Management Console key table.
// ══════════════════════════════════════════════════════════════════════════════
function enforceDevicePop(req, decoded, options) {
  if (options && options.popExempt) {
    return { ok: true };
  }
  const cnf = decoded && decoded.cnf;
  if (!cnf || !cnf.jkt) {
    return { ok: false, status: 401, code: 'device_binding_required', error: 'this session is not bound to a device key; sign in again' };
  }
  const { getDb } = require('../db/init');
  const db = getDb();
  try {
    const active = (decoded.role === 'analyst')
      ? db.prepare('SELECT public_key FROM ac_device_signing_keys WHERE user_id = ? AND active = 1').get(decoded.id)
      : db.prepare('SELECT public_key FROM mc_device_signing_keys WHERE user_id = ? AND active = 1').get(decoded.id);
    if (!active) {
      return { ok: false, status: 401, code: 'device_pop_required', error: 'the bound device key is no longer active; sign in again' };
    }
    if (deviceKey.jwkThumbprint(active.public_key) !== cnf.jkt) {
      return { ok: false, status: 401, code: 'device_pop_required', error: 'the device key has changed since this session was issued; sign in again' };
    }
    const proof = req.headers[devicePop.POP_HEADER];
    const result = devicePop.verifyPopProof({ method: req.method, path: (req.originalUrl || req.url || '').split('?')[0], proof: proof, publicKeyPem: active.public_key, jkt: cnf.jkt });
    if (!result.ok) {
      return { ok: false, status: 401, code: 'device_pop_required', error: 'device-key proof-of-possession: ' + result.reason };
    }
    if (cnf['x5t#S256']) {
      const certTp = getClientCertThumbprint(req);
      if (!certTp || certTp !== cnf['x5t#S256']) {
        return { ok: false, status: 401, code: 'device_pop_required', error: 'mutual-TLS client certificate does not match the bound session' };
      }
    }
    return { ok: true };
  } finally {
    db.close();
  }
}

// The mutual-TLS client-certificate thumbprint for the request, or null when no
// client certificate is present. Lowercase hex of the certificate SHA-256
// fingerprint, matching the value bound into cnf x5t#S256 at login.
function getClientCertThumbprint(req) {
  try {
    const sock = req.socket;
    if (!sock || typeof sock.getPeerCertificate !== 'function') return null;
    const cert = sock.getPeerCertificate();
    if (!cert || !cert.fingerprint256) return null;
    return cert.fingerprint256.split(':').join('').toLowerCase();
  } catch (_) {
    return null;
  }
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

module.exports = { authMiddleware, signToken, verifyToken, getClientCertThumbprint, installRuntimeJwtSecret };

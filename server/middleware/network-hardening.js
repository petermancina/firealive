// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Network Hardening Middleware
// Blocks reconnaissance attempts:
//   - Disables HTTP TRACE/TRACK methods
//   - Strips unnecessary response headers
//   - Returns identical errors for 404/403 (prevents path enumeration)
//   - Connection timeout for slowloris prevention
//   - Blocks HTTP methods not used by the app
// ═══════════════════════════════════════════════════════════════════════════════

const { logger } = require('../services/logger');

const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'];
const CONNECTION_TIMEOUT_MS = 30000; // 30 seconds

function networkHardening() {
  return (req, res, next) => {
    // 1. Block TRACE/TRACK (XST attacks, fingerprinting)
    if (['TRACE', 'TRACK'].includes(req.method.toUpperCase())) {
      logger.warn('Blocked TRACE/TRACK', { ip: req.ip, method: req.method });
      return res.status(405).json({ error: 'Method not allowed' });
    }

    // 2. Block unexpected HTTP methods
    if (!ALLOWED_METHODS.includes(req.method.toUpperCase())) {
      logger.warn('Blocked unexpected method', { ip: req.ip, method: req.method });
      return res.status(405).json({ error: 'Method not allowed' });
    }

    // 3. Strip headers that leak information
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');
    // Set strict security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // 4. Connection timeout
    req.setTimeout(CONNECTION_TIMEOUT_MS, () => {
      logger.warn('Request timeout (slowloris prevention)', { ip: req.ip, path: req.path });
      req.destroy();
    });

    next();
  };
}

/**
 * Unified error handler that prevents path enumeration.
 * Returns identical response for 404 and 403 to prevent attackers
 * from distinguishing "exists but forbidden" from "doesn't exist".
 */
function antiEnumerationErrors() {
  return (req, res, next) => {
    // Override res.status to normalize 403/404 for API routes
    const originalStatus = res.status.bind(res);
    res.status = function(code) {
      if (req.path.startsWith('/api/') && (code === 403 || code === 404)) {
        // Log the real status internally
        if (code === 403) {
          logger.debug('Access denied (masked as 404)', { ip: req.ip, path: req.path, userId: req.user?.id });
        }
        return originalStatus(404); // always return 404
      }
      return originalStatus(code);
    };
    next();
  };
}

/**
 * Port binding validator — logs exactly which port is bound
 * and monitors for unexpected socket activity.
 */
function validatePortBinding(server, expectedPort) {
  const addr = server.address();
  if (addr.port !== expectedPort) {
    logger.error('PORT MISMATCH', {
      expected: expectedPort,
      actual: addr.port,
      message: 'Application bound to unexpected port — possible hijack',
    });
  } else {
    logger.info('Port binding verified', { port: addr.port, address: addr.address });
  }
}

module.exports = { networkHardening, antiEnumerationErrors, validatePortBinding };

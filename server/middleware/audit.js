// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Audit Middleware
// Every API action is logged. Generates CEF format for SIEM streaming.
// Audit log is append-only (immutable).
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { cefDeviceVersion } = require('../lib/version');

function formatCEF(event, userId, detail, ip) {
  const ts = new Date().toISOString();
  // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
  return `CEF:0|FireAlive|WellbeingPlatform|${cefDeviceVersion}|${event}|${event}|3|rt=${ts} suser=${userId || 'anonymous'} msg=${(detail || '').replace(/[|\\]/g, '_')} src=${ip || ''}`;
}

function auditMiddleware(req, res, next) {
  // Capture the original end to log after response
  const originalEnd = res.end;
  const startTime = Date.now();

  res.end = function (...args) {
    const duration = Date.now() - startTime;
    const userId = req.user?.id || null;
    const eventType = `${req.method} ${req.baseUrl}${req.route?.path || req.path}`;
    const statusCode = res.statusCode;
    const ip = req.ip || req.connection?.remoteAddress;

    // Don't log health checks or static files
    if (req.path === '/health' || !req.path.startsWith('/api/')) {
      return originalEnd.apply(res, args);
    }

    try {
      const db = getDb();
      const detail = `${statusCode} ${duration}ms`;
      const cef = formatCEF(eventType, userId, detail, ip);

      db.prepare(
        'INSERT INTO audit_log (user_id, event_type, detail, ip_address, cef_message) VALUES (?, ?, ?, ?, ?)'
      ).run(userId, eventType, detail, ip, cef);

      db.close();

      // Stream to SIEM if configured
      if (process.env.SIEM_ENABLED === 'true') {
        streamToSIEM(cef);
      }
    } catch (err) {
      logger.error('Audit log write failed', { error: err.message });
    }

    return originalEnd.apply(res, args);
  };

  next();
}

/**
 * Write an explicit audit entry (for business events, not just HTTP requests)
 *
 * @param {string} userId - User ID, pseudonym, or 'system'/'SYSTEM' for non-user events
 * @param {string} eventType - Event type identifier (e.g. 'CONFIG_UPDATED', 'BACKUP_CREATED')
 * @param {string} detail - Human-readable detail string
 * @param {string} [ip] - Optional IP address; pass req.ip from route handlers
 */
function auditLog(userId, eventType, detail, ip) {
  try {
    const db = getDb();
    const cef = formatCEF(eventType, userId, detail, ip);
    db.prepare(
      'INSERT INTO audit_log (user_id, event_type, detail, ip_address, cef_message) VALUES (?, ?, ?, ?, ?)'
    ).run(userId, eventType, detail, ip, cef);
    db.close();

    if (process.env.SIEM_ENABLED === 'true') {
      streamToSIEM(cef);
    }
  } catch (err) {
    logger.error('Audit log write failed', { error: err.message });
  }
}


/**
 * Stream CEF message to SIEM via syslog
 */
function streamToSIEM(cefMessage) {
  try {
    const syslog = require('syslog-client');
    const host = process.env.SIEM_HOST;
    const port = parseInt(process.env.SIEM_PORT || '6514');
    const transport = process.env.SIEM_PROTOCOL === 'tls' ? syslog.Transport.Tls : syslog.Transport.Udp;
    const facility = syslog.Facility[process.env.SIEM_FACILITY || 'Local4'] || syslog.Facility.Local4;

    const client = syslog.createClient(host, { port, transport, facility });
    client.log(cefMessage, { severity: syslog.Severity.Informational }, (err) => {
      if (err) logger.error('SIEM stream error', { error: err.message });
      client.close();
    });
  } catch (err) {
    logger.error('SIEM client error', { error: err.message });
  }
}

module.exports = { auditMiddleware, auditLog, formatCEF };

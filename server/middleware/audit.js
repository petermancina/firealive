// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Audit Middleware
// Every API action is logged. Generates CEF format for SIEM streaming.
// Audit log is append-only with a SHA-256 hash chain + Ed25519-signed
// checkpoints (see services/audit-chain.js): every write goes through the
// chained appendAuditEntry path, which links each row to the previous one and
// is verified by GET /api/audit/integrity and the periodic integrity check.
// ═══════════════════════════════════════════════════════════════════════════════

const path = require('path');
const { getDb, DB_PATH } = require('../db/init');
const { logger } = require('../services/logger');
const { cefDeviceVersion } = require('../lib/version');
const { appendAuditEntry } = require('../services/audit-chain');

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

      // Chained, tamper-evident append (audit_log.hash / .prev_hash). The
      // head-read + INSERT run inside a transaction so concurrent requests
      // cannot read the same head and fork the chain.
      appendAuditEntry(db, { userId, eventType, detail, ip, cef });

      db.close();

      // Stream to SIEM if configured — the independent external copy that
      // forms the third tamper-evidence leg alongside the chain + checkpoints.
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
// Is this handle the real, durable audit chain -- the configured live database?
// A ':memory:' clone (the regression's hermetic copies) or any other file is not.
// The question is deliberately NOT "was a connection supplied": in production the
// callers always supply a live handle, so keying off injection would silence SIEM
// for every real failover.
function isLiveChain(db) {
  try {
    if (!db || typeof db.name !== 'string' || !db.name || db.name === ':memory:') {
      return false;
    }
    return path.resolve(db.name) === path.resolve(DB_PATH);
  } catch (pathErr) {
    return false;
  }
}

// Append a business event on a caller-supplied connection. Callers that already
// hold a handle (HA failover mutating ha_node/ha_lease) must audit THROUGH it, so
// the state change and its audit record always land in the same database.
//
// SIEM streaming is gated on that database actually BEING the live chain. A drill
// or a regression that exercises promote/demote against a scratch copy therefore
// records the event where the change happened and streams nothing -- it can neither
// forge a row into the tamper-evident chain an auditor reads, nor page a SOC with a
// fence that never occurred. A real failover, on the live handle, streams as before.
function auditLogOn(db, userId, eventType, detail, ip) {
  try {
    const cef = formatCEF(eventType, userId, detail, ip);
    // Same chained append path as the middleware — business events are part of
    // the same tamper-evident chain.
    appendAuditEntry(db, { userId, eventType, detail, ip, cef });

    if (isLiveChain(db) && process.env.SIEM_ENABLED === 'true') {
      streamToSIEM(cef);
    }
  } catch (err) {
    logger.error('Audit log write failed', { error: err.message });
  }
}

function auditLog(userId, eventType, detail, ip) {
  let db = null;
  try {
    db = getDb();
    auditLogOn(db, userId, eventType, detail, ip);
  } catch (err) {
    logger.error('Audit log write failed', { error: err.message });
  } finally {
    if (db) { try { db.close(); } catch (closeErr) { /* ignore */ } }
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

module.exports = { auditMiddleware, auditLog, auditLogOn, isLiveChain, formatCEF };

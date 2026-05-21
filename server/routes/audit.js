// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Audit Routes
// GET  /api/audit            — query audit log with filters
// GET  /api/audit/export     — export audit log (CSV, JSON, or CEF)
//                              R3n: optional source filter — all / mc / ac /
//                              ac-analyst (with analyst_id param) / server
// GET  /api/audit/stats      — aggregated event counts
// GET  /api/audit/integrity  — verify the SHA-256 chain across the audit log
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const { cefDeviceVersion } = require('../lib/version');
const { verifyAuditChain } = require('../middleware/pentest-hardening');

// ── Query Audit Log ──────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const { eventType, userId, startDate, endDate, limit = 200, offset = 0 } = req.query;
    const db = getDb();

    let sql = 'SELECT al.*, u.name AS user_name FROM audit_log al LEFT JOIN users u ON u.id = al.user_id WHERE 1=1';
    const params = [];

    if (eventType) { sql += ' AND al.event_type = ?'; params.push(eventType); }
    if (userId) { sql += ' AND al.user_id = ?'; params.push(userId); }
    if (startDate) { sql += ' AND al.timestamp >= ?'; params.push(startDate); }
    if (endDate) { sql += ' AND al.timestamp <= ?'; params.push(endDate); }

    sql += ' ORDER BY al.timestamp DESC LIMIT ? OFFSET ?';
    params.push(Math.min(parseInt(limit, 10) || 200, 1000), Math.max(parseInt(offset, 10) || 0, 0));

    const rows = db.prepare(sql).all(...params);

    // Total count for pagination
    let countSql = 'SELECT COUNT(*) AS total FROM audit_log WHERE 1=1';
    const countParams = [];
    if (eventType) { countSql += ' AND event_type = ?'; countParams.push(eventType); }
    if (userId) { countSql += ' AND user_id = ?'; countParams.push(userId); }
    if (startDate) { countSql += ' AND timestamp >= ?'; countParams.push(startDate); }
    if (endDate) { countSql += ' AND timestamp <= ?'; countParams.push(endDate); }
    const { total } = db.prepare(countSql).get(...countParams);

    db.close();
    res.json({ events: rows, total, limit: parseInt(limit, 10), offset: parseInt(offset, 10) });
  } catch (err) {
    logger.error('Query audit log error', { error: err.message });
    res.status(500).json({ error: 'Failed to query audit log' });
  }
});

// ── Export ────────────────────────────────────────────────────────────────────
router.get('/export', (req, res) => {
  try {
    const { format = 'json', startDate, endDate, source = 'all', analyst_id } = req.query;
    const db = getDb();

    let sql = 'SELECT al.*, u.name AS user_name FROM audit_log al LEFT JOIN users u ON u.id = al.user_id WHERE 1=1';
    const params = [];
    if (startDate) { sql += ' AND al.timestamp >= ?'; params.push(startDate); }
    if (endDate) { sql += ' AND al.timestamp <= ?'; params.push(endDate); }

    // R3n: source filter — operator can request MC-only / AC-only /
    // server-middleware-only / per-analyst slices. Single physical
    // audit_log table holds all event sources distinguished by
    // event_type prefix (MC_* / AC_* / no-prefix for server-middleware).
    // See server/routes/audit-mc-event.js header for the prefix taxonomy.
    if (source === 'mc') {
      sql += " AND al.event_type LIKE 'MC\\_%' ESCAPE '\\'";
    } else if (source === 'ac') {
      sql += " AND al.event_type LIKE 'AC\\_%' ESCAPE '\\'";
    } else if (source === 'ac-analyst') {
      if (!analyst_id || typeof analyst_id !== 'string') {
        db.close();
        return res.status(400).json({ error: 'ac-analyst source requires analyst_id query param' });
      }
      sql += " AND al.event_type LIKE 'AC\\_%' ESCAPE '\\' AND al.user_id = ?";
      params.push(analyst_id);
    } else if (source === 'server') {
      sql += " AND al.event_type NOT LIKE 'AC\\_%' ESCAPE '\\' AND al.event_type NOT LIKE 'MC\\_%' ESCAPE '\\'";
    } else if (source !== 'all') {
      db.close();
      return res.status(400).json({ error: `Invalid source: ${source}`, allowed: ['all', 'mc', 'ac', 'ac-analyst', 'server'] });
    }

    sql += ' ORDER BY al.timestamp ASC';

    const rows = db.prepare(sql).all(...params);
    db.close();

    if (format === 'csv') {
      // CSV injection protection: prefix formula characters with single quote
      const escape = (v) => {
        const s = String(v || '');
        return /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
      };
      const header = 'id,timestamp,user_id,user_name,event_type,detail,ip_address';
      const lines = rows.map(r =>
        [r.id, r.timestamp, escape(r.user_id), escape(r.user_name), escape(r.event_type), `"${escape(r.detail?.replace(/"/g, '""') || '')}"`, escape(r.ip_address)].join(',')
      );
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=firealive-audit-${new Date().toISOString().slice(0, 10)}.csv`);
      return res.send([header, ...lines].join('\n'));
    }

    if (format === 'cef') {
      const cefLines = rows.map(r => r.cef_message || `CEF:0|FireAlive|WellbeingPlatform|${cefDeviceVersion}|${r.event_type}|${r.event_type}|5|src=${r.ip_address || ''} suser=${r.user_name || ''} msg=${r.detail || ''}`);
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', `attachment; filename=firealive-audit-${new Date().toISOString().slice(0, 10)}.cef`);
      return res.send(cefLines.join('\n'));
    }

    // Default: JSON
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=firealive-audit-${new Date().toISOString().slice(0, 10)}.json`);
    res.json({ exportedAt: new Date().toISOString(), count: rows.length, events: rows });
  } catch (err) {
    logger.error('Export audit error', { error: err.message });
    res.status(500).json({ error: 'Failed to export audit log' });
  }
});

// ── Aggregated Stats ─────────────────────────────────────────────────────────
router.get('/stats', (req, res) => {
  try {
    const { days = 7 } = req.query;
    const db = getDb();
    const since = new Date(Date.now() - parseInt(days, 10) * 86400000).toISOString();

    const byType = db.prepare(`
      SELECT event_type, COUNT(*) AS count FROM audit_log WHERE timestamp >= ? GROUP BY event_type ORDER BY count DESC
    `).all(since);

    const byDay = db.prepare(`
      SELECT DATE(timestamp) AS day, COUNT(*) AS count FROM audit_log WHERE timestamp >= ? GROUP BY DATE(timestamp) ORDER BY day
    `).all(since);

    const total = db.prepare('SELECT COUNT(*) AS total FROM audit_log WHERE timestamp >= ?').get(since);

    db.close();
    res.json({ days: parseInt(days, 10), total: total.total, byType, byDay });
  } catch (err) {
    logger.error('Audit stats error', { error: err.message });
    res.status(500).json({ error: 'Failed to compute audit stats' });
  }
});

// ── Audit Chain Integrity Verification ───────────────────────────────────────
// Walks the audit_log table in id-order, confirming each row's prev_hash
// matches the previous row's hash. A mismatch indicates someone tampered with
// the audit log between two entries — either an INSERT, UPDATE, or DELETE that
// did not preserve the SHA-256 hash chain. The chain is the primary integrity
// guarantee for the immutable audit trail referenced in compliance reports
// (NIST AU-9, SOC2 CC7.3, ISO 27001 A.12.4.2).
//
// On success: { intact: true, entries: N }
// On tamper detection: { intact: false, brokenAt: <id>, expected: <hash>, found: <hash> }
//
// The check itself is logged to the audit chain so that a Team Lead running
// integrity checks creates an additional auditable trail of monitoring activity.
router.get('/integrity', (req, res) => {
  try {
    const db = getDb();
    const result = verifyAuditChain(db);
    db.close();
    auditLog(req.user?.id, 'AUDIT_INTEGRITY_CHECK',
      result.intact ? `intact entries=${result.entries}` : `BROKEN at id=${result.brokenAt}`,
      req.ip);
    res.json(result);
  } catch (err) {
    logger.error('Audit integrity check error', { error: err.message });
    res.status(500).json({ error: 'Failed to verify audit chain integrity' });
  }
});

module.exports = router;

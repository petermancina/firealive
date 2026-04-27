// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — SLA Routes
// GET  /api/sla/config        — get SLA targets
// PUT  /api/sla/config        — update SLA targets
// POST /api/sla/measurements  — record a measurement (from SOAR/SIEM integration)
// GET  /api/sla/measurements  — query measurements with filters
// GET  /api/sla/summary       — aggregated SLA performance
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── Get SLA Config ───────────────────────────────────────────────────────────
router.get('/config', (req, res) => {
  try {
    const db = getDb();
    const config = db.prepare('SELECT * FROM sla_config WHERE id = ?').get('default');
    db.close();
    res.json(config || { p1_mtta: '5m', p1_mttr: '60m', p2_mtta: '15m', p2_mttr: '4h' });
  } catch (err) {
    logger.error('Get SLA config error', { error: err.message });
    res.status(500).json({ error: 'Failed to get SLA config' });
  }
});

// ── Update SLA Targets ───────────────────────────────────────────────────────
router.put('/config', (req, res) => {
  const { p1Mtta, p1Mttr, p2Mtta, p2Mttr } = req.body;

  try {
    const db = getDb();
    db.prepare(`
      UPDATE sla_config SET
        p1_mtta = COALESCE(?, p1_mtta),
        p1_mttr = COALESCE(?, p1_mttr),
        p2_mtta = COALESCE(?, p2_mtta),
        p2_mttr = COALESCE(?, p2_mttr),
        updated_by = ?, updated_at = datetime('now')
      WHERE id = 'default'
    `).run(
      p1Mtta?.slice(0, 16) || null,
      p1Mttr?.slice(0, 16) || null,
      p2Mtta?.slice(0, 16) || null,
      p2Mttr?.slice(0, 16) || null,
      req.user.id
    );
    db.close();
    auditLog(req.user.id, 'SLA_CONFIG_UPDATED', JSON.stringify({ p1Mtta, p1Mttr, p2Mtta, p2Mttr }), req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Update SLA config error', { error: err.message });
    res.status(500).json({ error: 'Failed to update SLA config' });
  }
});

// ── Record Measurement ───────────────────────────────────────────────────────
router.post('/measurements', (req, res) => {
  const { priority, mttaSeconds, mttrSeconds, ticketRef } = req.body;

  if (!priority || !['P1', 'P2', 'P3'].includes(priority)) {
    return res.status(400).json({ error: 'priority required (P1, P2, or P3)' });
  }
  if (mttaSeconds == null && mttrSeconds == null) {
    return res.status(400).json({ error: 'At least one of mttaSeconds or mttrSeconds required' });
  }

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    db.prepare(`
      INSERT INTO sla_measurements (id, priority, mtta_seconds, mttr_seconds, ticket_ref)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      id, priority,
      mttaSeconds != null ? Math.max(0, parseInt(mttaSeconds, 10)) : null,
      mttrSeconds != null ? Math.max(0, parseInt(mttrSeconds, 10)) : null,
      ticketRef?.slice(0, 128) || null
    );
    db.close();
    res.status(201).json({ id });
  } catch (err) {
    logger.error('Record SLA measurement error', { error: err.message });
    res.status(500).json({ error: 'Failed to record measurement' });
  }
});

// ── Query Measurements ───────────────────────────────────────────────────────
router.get('/measurements', (req, res) => {
  try {
    const { priority, startDate, endDate, limit = 100 } = req.query;
    const db = getDb();

    let sql = 'SELECT * FROM sla_measurements WHERE 1=1';
    const params = [];

    if (priority) { sql += ' AND priority = ?'; params.push(priority); }
    if (startDate) { sql += ' AND measured_at >= ?'; params.push(startDate); }
    if (endDate) { sql += ' AND measured_at <= ?'; params.push(endDate); }

    sql += ' ORDER BY measured_at DESC LIMIT ?';
    params.push(Math.min(parseInt(limit, 10) || 100, 500));

    const measurements = db.prepare(sql).all(...params);
    db.close();
    res.json({ measurements });
  } catch (err) {
    logger.error('Query SLA measurements error', { error: err.message });
    res.status(500).json({ error: 'Failed to query measurements' });
  }
});

// ── Summary (30d rolling) ────────────────────────────────────────────────────
router.get('/summary', (req, res) => {
  try {
    const { days = 30 } = req.query;
    const since = new Date(Date.now() - parseInt(days, 10) * 86400000).toISOString();
    const db = getDb();

    const config = db.prepare('SELECT * FROM sla_config WHERE id = ?').get('default');

    const summary = db.prepare(`
      SELECT priority,
             COUNT(*) AS total_incidents,
             AVG(mtta_seconds) AS avg_mtta_seconds,
             AVG(mttr_seconds) AS avg_mttr_seconds,
             MIN(mtta_seconds) AS best_mtta,
             MAX(mtta_seconds) AS worst_mtta,
             MIN(mttr_seconds) AS best_mttr,
             MAX(mttr_seconds) AS worst_mttr
      FROM sla_measurements
      WHERE measured_at >= ?
      GROUP BY priority
      ORDER BY priority
    `).all(since);

    // Daily trend
    const trend = db.prepare(`
      SELECT DATE(measured_at) AS day, priority,
             AVG(mtta_seconds) AS avg_mtta,
             AVG(mttr_seconds) AS avg_mttr,
             COUNT(*) AS count
      FROM sla_measurements
      WHERE measured_at >= ?
      GROUP BY DATE(measured_at), priority
      ORDER BY day
    `).all(since);

    db.close();
    res.json({ days: parseInt(days, 10), targets: config, summary, trend });
  } catch (err) {
    logger.error('SLA summary error', { error: err.message });
    res.status(500).json({ error: 'Failed to compute SLA summary' });
  }
});

module.exports = router;

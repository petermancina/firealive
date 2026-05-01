// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Upskilling Schedule Routes
// GET  /api/upskilling/schedules — list all analyst upskilling time slots
// POST /api/upskilling/schedule  — save or update one analyst's upskilling slot
// ═══════════════════════════════════════════════════════════════════════════════
//
// Upskilling slots are protected windows during the workday when an analyst
// is taken out of the routing pool to focus on training (assessments, KB
// review, peer skill-share). Each analyst gets one configurable slot. The
// scheduler service honors these slots when distributing tickets.
//
// Slots are stored in team_config under keys of the form
// "upskilling_schedule_<analystId>" so they survive routing-cap changes and
// roll up into the team-level config snapshots used by /api/restore.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

const SLOT_PATTERN = /^([01]\d|2[0-3])-([01]\d|2[0-3])$/;
const KEY_PREFIX = 'upskilling_schedule_';

// ── List all upskilling schedules ────────────────────────────────────────────
router.get('/schedules', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT key, value FROM team_config WHERE key LIKE ?
    `).all(`${KEY_PREFIX}%`);
    db.close();
    const schedules = rows.map(r => {
      try {
        const data = JSON.parse(r.value);
        return {
          analystId: r.key.slice(KEY_PREFIX.length),
          slot: data.slot,
          updatedAt: data.updatedAt,
          updatedBy: data.updatedBy,
        };
      } catch { return null; }
    }).filter(Boolean);
    res.json({ schedules });
  } catch (err) {
    logger.error('List upskilling schedules error', { error: err.message });
    res.status(500).json({ error: 'Failed to list upskilling schedules' });
  }
});

// ── Save or update one analyst's upskilling slot ─────────────────────────────
router.post('/schedule', (req, res) => {
  const { analystId, slot } = req.body || {};
  if (!analystId || typeof analystId !== 'string') {
    return res.status(400).json({ error: 'analystId is required' });
  }
  if (!slot || typeof slot !== 'string' || !SLOT_PATTERN.test(slot)) {
    return res.status(400).json({ error: 'slot is required in HH-HH format (e.g. "14-15")' });
  }
  const [startHour, endHour] = slot.split('-').map(Number);
  if (endHour !== (startHour + 1) % 24) {
    return res.status(400).json({ error: 'slot must be a single one-hour window (e.g. "14-15")' });
  }
  try {
    const db = getDb();
    const user = db.prepare("SELECT id, role FROM users WHERE id = ?").get(analystId);
    if (!user) { db.close(); return res.status(404).json({ error: 'Analyst not found' }); }
    if (user.role !== 'analyst') { db.close(); return res.status(400).json({ error: 'User is not an analyst' }); }
    const now = new Date().toISOString();
    const payload = JSON.stringify({ slot, updatedAt: now, updatedBy: req.user?.id || null });
    db.prepare(`
      INSERT INTO team_config (key, value, updated_by)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')
    `).run(`${KEY_PREFIX}${analystId}`, payload, req.user?.id || null);
    db.close();
    auditLog(req.user?.id, 'UPSKILLING_SCHEDULED', `analyst=${analystId} slot=${slot}`, req.ip);
    res.json({ success: true, analystId, slot, updatedAt: now });
  } catch (err) {
    logger.error('Save upskilling schedule error', { error: err.message });
    res.status(500).json({ error: 'Failed to save upskilling schedule' });
  }
});

module.exports = router;

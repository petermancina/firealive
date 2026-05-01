// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — IAM Offboarding Routes
// GET  /api/iam/check-absence   — return analysts whose IAM check is overdue
// POST /api/iam/confirm-status  — confirm analyst as active, OR mark offboarded
// ═══════════════════════════════════════════════════════════════════════════════
//
// These routes support periodic recertification of analyst accounts. The team
// lead receives a list of analysts whose last_iam_check is older than the
// configured interval (or who have never been checked) and either confirms
// each one as still active (resetting the timer) or marks them offboarded.
// Offboarded analysts have active=0 and offboarded_at set; they no longer
// appear in routing or peer-share queues.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── List analysts due for IAM recertification ────────────────────────────────
router.get('/check-absence', (req, res) => {
  try {
    const db = getDb();
    // Read configured interval (hours) from team_config; default 168 (1 week)
    const cfgRow = db.prepare("SELECT value FROM team_config WHERE key = 'iam_config'").get();
    const intervalHours = (() => {
      if (!cfgRow) return 168;
      try {
        const cfg = JSON.parse(cfgRow.value);
        const h = Number(cfg.intervalHours);
        return Number.isFinite(h) && h > 0 ? h : 168;
      } catch { return 168; }
    })();
    const cutoff = new Date(Date.now() - intervalHours * 3600000).toISOString();
    const users = db.prepare(`
      SELECT id, pseudonym, last_iam_check
      FROM users
      WHERE role = 'analyst' AND active = 1
    `).all();
    db.close();
    const overdue = users.filter(u => !u.last_iam_check || u.last_iam_check < cutoff);
    auditLog(req.user?.id, 'IAM_CHECK_ABSENCE', `total=${users.length} overdue=${overdue.length}`, req.ip);
    res.json({
      checked: true,
      total: users.length,
      intervalHours,
      needsReview: overdue.map(u => ({ id: u.id, pseudonym: u.pseudonym, lastCheck: u.last_iam_check })),
    });
  } catch (err) {
    logger.error('IAM check-absence error', { error: err.message });
    res.status(500).json({ error: 'Failed to check IAM absence' });
  }
});

// ── Confirm analyst status (active or offboard) ──────────────────────────────
router.post('/confirm-status', (req, res) => {
  const { analystId, action } = req.body || {};
  if (!analystId || typeof analystId !== 'string') {
    return res.status(400).json({ error: 'analystId is required' });
  }
  if (action !== 'active' && action !== 'offboard') {
    return res.status(400).json({ error: 'action must be "active" or "offboard"' });
  }
  try {
    const db = getDb();
    const user = db.prepare("SELECT id, role FROM users WHERE id = ?").get(analystId);
    if (!user) { db.close(); return res.status(404).json({ error: 'Analyst not found' }); }
    if (user.role !== 'analyst') { db.close(); return res.status(400).json({ error: 'User is not an analyst' }); }
    const now = new Date().toISOString();
    if (action === 'offboard') {
      db.prepare("UPDATE users SET active = 0, offboarded_at = ? WHERE id = ?").run(now, analystId);
      auditLog(req.user?.id, 'IAM_OFFBOARD', `analyst=${analystId}`, req.ip);
    } else {
      db.prepare("UPDATE users SET last_iam_check = ? WHERE id = ?").run(now, analystId);
      auditLog(req.user?.id, 'IAM_CONFIRMED_ACTIVE', `analyst=${analystId}`, req.ip);
    }
    db.close();
    res.json({ success: true, analystId, action, at: now });
  } catch (err) {
    logger.error('IAM confirm-status error', { error: err.message });
    res.status(500).json({ error: 'Failed to update analyst status' });
  }
});

module.exports = router;

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Handoff Routes
// ═══════════════════════════════════════════════════════════════════════════════
const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');

router.get('/', (req, res) => {
  const db = getDb();
  const handoffs = db.prepare('SELECT h.*, u.name as created_by_name FROM handoffs h LEFT JOIN users u ON h.created_by = u.id ORDER BY h.created_at DESC LIMIT 50').all();
  db.close();
  res.json({ handoffs });
});

router.post('/', (req, res) => {
  const { notes, fromShift, toShift } = req.body;
  if (!notes?.trim()) return res.status(400).json({ error: 'Notes required' });

  const db = getDb();
  // Auto-generate team state summary
  const analysts = db.prepare('SELECT * FROM users WHERE role = ? AND shift = ?').all('analyst', fromShift || 'day');
  const lqCount = db.prepare('SELECT COUNT(*) as c FROM lighter_queue_requests WHERE status = ?').get('active');
  const retroCount = db.prepare('SELECT COUNT(*) as c FROM retro_protocols WHERE phase != ?').get('Complete');

  const autoSummary = `Staff: ${analysts.length} analysts. Active lighter queues: ${lqCount.c}. Active recovery protocols: ${retroCount.c}.`;

  db.prepare(
    'INSERT INTO handoffs (from_shift, to_shift, notes, auto_summary, created_by) VALUES (?, ?, ?, ?, ?)'
  ).run(fromShift || 'day', toShift || 'swing', notes, autoSummary, req.user.id);
  db.close();

  auditLog(req.user.id, 'HANDOFF_SUBMITTED', notes.slice(0, 100), req.ip);
  res.status(201).json({ ok: true, autoSummary });
});

module.exports = router;

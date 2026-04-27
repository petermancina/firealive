const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');

router.get('/', (req, res) => {
  const db = getDb();
  const q = req.user.role === 'analyst'
    ? db.prepare('SELECT d.*, a.name as system_name FROM delegations d JOIN automation_systems a ON d.target_system_id = a.id WHERE d.submitted_by = ? ORDER BY d.created_at DESC').all(req.user.id)
    : db.prepare('SELECT d.*, a.name as system_name, u.name as submitted_by_name FROM delegations d JOIN automation_systems a ON d.target_system_id = a.id JOIN users u ON d.submitted_by = u.id ORDER BY d.created_at DESC').all();
  db.close();
  res.json({ delegations: q });
});

router.post('/', (req, res) => {
  const { patternDescription, targetSystemId } = req.body;
  if (!patternDescription?.trim() || !targetSystemId) return res.status(400).json({ error: 'Pattern and target system required' });
  const db = getDb();
  db.prepare('INSERT INTO delegations (pattern_description, target_system_id, submitted_by) VALUES (?, ?, ?)').run(patternDescription, targetSystemId, req.user.id);
  db.close();
  auditLog(req.user.id, 'DELEGATION_SUBMITTED', patternDescription.slice(0, 100), req.ip);
  res.status(201).json({ ok: true });
});

router.put('/:id/review', (req, res) => {
  const { status } = req.body; // 'accepted' or 'rejected'
  if (!['accepted', 'rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  const db = getDb();
  db.prepare('UPDATE delegations SET status = ?, reviewed_by = ?, resolved_at = datetime("now") WHERE id = ?').run(status, req.user.id, req.params.id);
  db.close();
  auditLog(req.user.id, 'DELEGATION_REVIEWED', `${req.params.id} → ${status}`, req.ip);
  res.json({ ok: true });
});

module.exports = router;

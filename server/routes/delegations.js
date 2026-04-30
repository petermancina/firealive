const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');

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
  const { status, reviewerNotes } = req.body; // status: 'accepted' or 'rejected'
  if (!['accepted', 'rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status' });

  const db = getDb();

  // Fetch delegation + system name BEFORE the update so we have the analyst to notify and a readable target
  const existing = db.prepare(`
    SELECT d.id, d.submitted_by, d.pattern_description, a.name AS system_name
    FROM delegations d
    JOIN automation_systems a ON d.target_system_id = a.id
    WHERE d.id = ?
  `).get(req.params.id);

  if (!existing) { db.close(); return res.status(404).json({ error: 'Delegation not found' }); }

  db.prepare('UPDATE delegations SET status = ?, reviewed_by = ?, resolved_at = datetime("now") WHERE id = ?')
    .run(status, req.user.id, req.params.id);
  db.close();

  auditLog(req.user.id, 'DELEGATION_REVIEWED', `${req.params.id} → ${status}`, req.ip);

  // Notify the analyst who submitted the delegation request
  if (existing.submitted_by && existing.submitted_by !== req.user.id) {
    const truncatedPattern = existing.pattern_description.length > 80
      ? existing.pattern_description.slice(0, 80) + '…'
      : existing.pattern_description;
    const reviewerNotesText = (typeof reviewerNotes === 'string' && reviewerNotes.trim())
      ? `\n\nReviewer notes: ${reviewerNotes.trim().slice(0, 500)}`
      : '';

    try {
      notifications.notify({
        recipientId: existing.submitted_by,
        eventType: 'delegation_decision',
        title: status === 'accepted'
          ? `Delegation accepted: "${truncatedPattern}"`
          : `Delegation rejected: "${truncatedPattern}"`,
        body: status === 'accepted'
          ? `Your automation-delegation request for ${existing.system_name} has been accepted. The pattern will be handed off to the automation system on the next routing cycle.${reviewerNotesText}`
          : `Your automation-delegation request for ${existing.system_name} was rejected. The lead reviewing the request decided this pattern should remain handled by analysts. You can submit a revised request from the Automation tab.${reviewerNotesText}`,
        linkTab: 'automation',
        linkParams: { delegationId: req.params.id },
      });
    } catch (notifyErr) {
      logger.warn('Delegation review: notify analyst failed (non-fatal)', {
        delegationId: req.params.id,
        analystId: existing.submitted_by,
        error: notifyErr.message,
      });
    }
  }

  res.json({ ok: true });
});

module.exports = router;

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Abuse-reviewer designation (U3 PR E) — admin-only
//
// Lets an admin designate independent abuse reviewers and scope their authority.
// Mounted (E8) behind authMiddleware(['admin']); every handler ALSO re-checks the
// admin role so the route fails closed regardless of how it is mounted.
//
// Separation-of-duties rules enforced here:
//   - No self-assignment: an admin may not make themselves a reviewer.
//   - No management reviewers: a lead or admin may never be designated (a reviewer
//     must be independent of the people who could be reported).
//   - No party reviewers (case scope): the designee may not be a party to the
//     specific flag a case-scoped grant points at. (For 'all'/'team' scope, party
//     conflicts are caught per-case at review time by canReview.)
//
// Designating a non-management user promotes them to the abuse_reviewer role and
// creates the assignment atomically.
//
//   POST   /assignments       designate + scope a reviewer
//   GET    /assignments       list current assignments
//   DELETE /assignments/:id   revoke an assignment (does not demote the role)
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { REVIEWER_ROLE } = require('../services/abuse-reviewer-access');

const SCOPES = ['all', 'team', 'case'];
const MANAGEMENT_ROLES = ['lead', 'admin']; // may never review abuse (separation of duties)

function requireAdmin(req, res) {
  if (!req.user || req.user.role !== 'admin') {
    res.status(403).json({ error: 'forbidden' });
    return false;
  }
  return true;
}

// POST /assignments — designate a reviewer and grant a scoped assignment.
router.post('/assignments', (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { reviewerUserId, scope, teamId, flagId } = req.body || {};
  if (typeof reviewerUserId !== 'string' || !reviewerUserId) {
    return res.status(400).json({ error: 'reviewerUserId required' });
  }
  if (reviewerUserId === req.user.id) {
    return res.status(403).json({ error: 'an admin may not assign themselves as a reviewer' });
  }
  if (!SCOPES.includes(scope)) {
    return res.status(400).json({ error: "scope must be one of 'all', 'team', 'case'" });
  }
  if (scope === 'team' && (typeof teamId !== 'string' || !teamId)) {
    return res.status(400).json({ error: "teamId required for scope 'team'" });
  }
  if (scope === 'case' && (typeof flagId !== 'string' || !flagId)) {
    return res.status(400).json({ error: "flagId required for scope 'case'" });
  }

  let db;
  try {
    db = getDb();
    const target = db.prepare('SELECT id, role FROM users WHERE id = ?').get(reviewerUserId);
    if (!target) return res.status(404).json({ error: 'user not found' });
    if (MANAGEMENT_ROLES.includes(target.role)) {
      return res.status(403).json({ error: 'a lead or admin may not be designated a reviewer (separation of duties)' });
    }
    if (scope === 'case') {
      const flag = db.prepare('SELECT id, flagger_user_id, flagged_user_id FROM peer_abuse_flags WHERE id = ?').get(flagId);
      if (!flag) return res.status(404).json({ error: 'flag not found' });
      if (reviewerUserId === flag.flagger_user_id || reviewerUserId === flag.flagged_user_id) {
        return res.status(403).json({ error: 'the designee is a party to that case' });
      }
    }

    const willPromote = target.role !== REVIEWER_ROLE;
    const assignmentId = crypto.randomBytes(16).toString('hex');
    const designate = db.transaction(() => {
      if (willPromote) {
        db.prepare('UPDATE users SET role = ? WHERE id = ?').run(REVIEWER_ROLE, reviewerUserId);
      }
      db.prepare(
        'INSERT INTO abuse_reviewer_assignments (id, reviewer_user_id, scope, team_id, flag_id, created_by) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(
        assignmentId,
        reviewerUserId,
        scope,
        scope === 'team' ? teamId : null,
        scope === 'case' ? flagId : null,
        req.user.id
      );
    });
    designate();

    auditLog(req.user.id, 'ABUSE_REVIEWER_ASSIGNED',
      `reviewer ${reviewerUserId}, scope ${scope}${willPromote ? ', promoted to abuse_reviewer' : ''}`, req.ip);
    return res.status(201).json({ id: assignmentId, reviewerUserId, scope, promoted: willPromote });
  } catch (err) {
    logger.error('Failed to assign reviewer', { error: err.message });
    return res.status(500).json({ error: 'failed to assign reviewer' });
  } finally {
    if (db) db.close();
  }
});

// GET /assignments — list current assignments (admin view).
router.get('/assignments', (req, res) => {
  if (!requireAdmin(req, res)) return;
  let db;
  try {
    db = getDb();
    const rows = db.prepare(
      `SELECT a.id, a.reviewer_user_id, a.scope, a.team_id, a.flag_id, a.created_at, a.created_by,
              u.name AS reviewer_name, u.role AS reviewer_role
         FROM abuse_reviewer_assignments a
         LEFT JOIN users u ON u.id = a.reviewer_user_id
        ORDER BY a.created_at DESC`
    ).all();
    const assignments = rows.map((r) => ({
      id: r.id,
      reviewerUserId: r.reviewer_user_id,
      reviewerName: r.reviewer_name,
      reviewerRole: r.reviewer_role,
      scope: r.scope,
      teamId: r.team_id,
      flagId: r.flag_id,
      createdAt: r.created_at,
      createdBy: r.created_by,
    }));
    return res.json({ assignments });
  } catch (err) {
    logger.error('Failed to list reviewer assignments', { error: err.message });
    return res.status(500).json({ error: 'failed to list assignments' });
  } finally {
    if (db) db.close();
  }
});

// DELETE /assignments/:id — revoke an assignment. Does NOT demote the reviewer's
// role (that is a separate user-management action); it only removes the scope, so
// the reviewer can no longer review under it.
router.delete('/assignments/:id', (req, res) => {
  if (!requireAdmin(req, res)) return;
  let db;
  try {
    db = getDb();
    const row = db.prepare('SELECT id, reviewer_user_id FROM abuse_reviewer_assignments WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'assignment not found' });
    db.prepare('DELETE FROM abuse_reviewer_assignments WHERE id = ?').run(req.params.id);
    auditLog(req.user.id, 'ABUSE_REVIEWER_ASSIGNMENT_REVOKED',
      `assignment ${req.params.id}, reviewer ${row.reviewer_user_id}`, req.ip);
    return res.json({ id: req.params.id, revoked: true });
  } catch (err) {
    logger.error('Failed to revoke reviewer assignment', { error: err.message });
    return res.status(500).json({ error: 'failed to revoke assignment' });
  } finally {
    if (db) db.close();
  }
});

module.exports = router;

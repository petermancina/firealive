// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Enrollment Reconciliation (Management Console)
//
// FireAlive monitors only ENROLLED analysts -- those who have registered an
// active key from their Analyst Client. Roster (HR/IAM) membership alone never
// enrolls anyone, so an active analyst who has not set up their AC is invisible
// to every per-analyst feature (the collector, the team aggregates, the routing
// cap, interventions). This route is the one place that surfaces that gap to a
// Lead or Admin: it lists active analysts who are not enrolled so they can be
// prompted to set up, and it lets a Lead dismiss/exclude anyone who is
// intentionally not monitored (for example, carried as an analyst in IAM but not
// actually on the SOC rotation). Excluding suppresses the prompt and records
// who/why; including reverses it.
//
// No burnout or behavioral data is exposed here -- only enrollment status, which
// is an administrative fact, never a per-analyst metric. Names are shown because
// enrollment is an administrative action on a known person; the pseudonym (the
// burnout-data key) and the silent email join key are never used here.
//
// Mounted lead/admin-only in index.js, so every handler is already role-gated.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');

// GET /api/enrollment-reconciliation/pending
// Active analysts who are NOT enrolled and NOT excluded -- the people a Lead
// should get set up. Enriched with how many weeks of HR schedule each has and
// the most recent scheduled week, so an actively-scheduled-but-unmonitored
// analyst stands out from one who has no synced schedule at all.
router.get('/pending', (req, res) => {
  const db = getDb();
  try {
    const pending = db
      .prepare(
        'SELECT u.id, u.name, u.username, u.shift, ' +
          '(SELECT COUNT(*) FROM analyst_availability a WHERE a.user_id = u.id) AS scheduledWeeks, ' +
          '(SELECT MAX(week_start) FROM analyst_availability a WHERE a.user_id = u.id) AS latestScheduledWeek ' +
          'FROM users u ' +
          "WHERE u.role = 'analyst' AND u.active = 1 " +
          "AND u.id NOT IN (SELECT analyst_id FROM analyst_keys WHERE status = 'active') " +
          'AND u.id NOT IN (SELECT analyst_id FROM analyst_enrollment_exclusions) ' +
          'ORDER BY u.name'
      )
      .all();
    db.close();
    return res.json({ pending, count: pending.length });
  } catch (e) {
    db.close();
    return res.status(500).json({ error: 'failed to compute pending enrollments' });
  }
});

// GET /api/enrollment-reconciliation/excluded
// Analysts a Lead/Admin has explicitly excluded from the prompt, with who
// excluded them, the optional reason, and when -- so the decision can be
// reviewed or undone.
router.get('/excluded', (req, res) => {
  const db = getDb();
  try {
    const excluded = db
      .prepare(
        'SELECT e.analyst_id AS id, u.name, u.username, u.shift, ' +
          'e.excluded_by AS excludedBy, eb.name AS excludedByName, ' +
          'e.reason, e.excluded_at AS excludedAt ' +
          'FROM analyst_enrollment_exclusions e ' +
          'JOIN users u ON u.id = e.analyst_id ' +
          'LEFT JOIN users eb ON eb.id = e.excluded_by ' +
          'ORDER BY e.excluded_at DESC'
      )
      .all();
    db.close();
    return res.json({ excluded, count: excluded.length });
  } catch (e) {
    db.close();
    return res.status(500).json({ error: 'failed to list exclusions' });
  }
});

// POST /api/enrollment-reconciliation/exclude   { analyst_id, reason? }
// Mark an analyst as intentionally not monitored: suppresses the enrollment
// prompt for them and confirms they are never aggregated. Idempotent -- a repeat
// call just refreshes who/why. Only an active analyst can be excluded.
router.post('/exclude', (req, res) => {
  const body = req.body || {};
  const analystId = body.analyst_id;
  const reason = body.reason;
  if (!analystId || typeof analystId !== 'string') {
    return res.status(400).json({ error: 'analyst_id required' });
  }
  if (reason != null && typeof reason !== 'string') {
    return res.status(400).json({ error: 'reason must be a string' });
  }
  const db = getDb();
  try {
    const target = db
      .prepare("SELECT id FROM users WHERE id = ? AND role = 'analyst' AND active = 1")
      .get(analystId);
    if (!target) {
      db.close();
      return res.status(404).json({ error: 'no active analyst with that id' });
    }
    db.prepare(
      'INSERT INTO analyst_enrollment_exclusions (analyst_id, excluded_by, reason) ' +
        'VALUES (?, ?, ?) ' +
        'ON CONFLICT(analyst_id) DO UPDATE SET ' +
        'excluded_by = excluded.excluded_by, reason = excluded.reason, ' +
        "excluded_at = datetime('now')"
    ).run(analystId, (req.user && req.user.id) || null, reason || null);
    db.close();
    auditLog((req.user && req.user.id) || null, 'ENROLLMENT_EXCLUDED', analystId, req.ip);
    return res.json({ ok: true });
  } catch (e) {
    db.close();
    return res.status(500).json({ error: 'failed to exclude analyst' });
  }
});

// POST /api/enrollment-reconciliation/include   { analyst_id }
// Reverse an exclusion: the analyst returns to the pending prompt until enrolled.
router.post('/include', (req, res) => {
  const body = req.body || {};
  const analystId = body.analyst_id;
  if (!analystId || typeof analystId !== 'string') {
    return res.status(400).json({ error: 'analyst_id required' });
  }
  const db = getDb();
  try {
    const r = db
      .prepare('DELETE FROM analyst_enrollment_exclusions WHERE analyst_id = ?')
      .run(analystId);
    db.close();
    if (!r.changes) {
      return res.status(404).json({ error: 'analyst was not excluded' });
    }
    auditLog((req.user && req.user.id) || null, 'ENROLLMENT_INCLUDED', analystId, req.ip);
    return res.json({ ok: true });
  } catch (e) {
    db.close();
    return res.status(500).json({ error: 'failed to include analyst' });
  }
});

module.exports = router;

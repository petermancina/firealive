// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Assessments Routes
// GET    /api/assessments              — list assessments (lead sees all, analyst sees assigned)
// POST   /api/assessments              — create assessment (lead/admin)
// GET    /api/assessments/:id          — get assessment detail with skills
// POST   /api/assessments/:id/assign   — assign analysts to assessment
// POST   /api/assessments/:id/results  — record skill scores (analyst submits)
// GET    /api/assessments/analyst/me    — analyst's own results + gap analysis
// DELETE /api/assessments/:id          — archive assessment
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');

const GAP_THRESHOLD = 70; // below this = training recommended

// ── List Assessments ─────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const db = getDb();
    let assessments;

    if (req.user.role === 'analyst') {
      // Analyst sees only assessments assigned to them
      assessments = db.prepare(`
        SELECT a.*, u.name AS created_by_name,
          (SELECT COUNT(*) FROM assessment_skills WHERE assessment_id = a.id) AS skill_count,
          (SELECT COUNT(*) FROM assessment_results WHERE assessment_id = a.id AND analyst_id = ?) AS completed_count
        FROM assessments a
        JOIN assessment_assignees aa ON aa.assessment_id = a.id
        JOIN users u ON u.id = a.created_by
        WHERE aa.analyst_id = ? AND a.status = 'active'
        ORDER BY a.created_at DESC
      `).all(req.user.id, req.user.id);
    } else {
      assessments = db.prepare(`
        SELECT a.*, u.name AS created_by_name,
          (SELECT COUNT(*) FROM assessment_skills WHERE assessment_id = a.id) AS skill_count,
          (SELECT COUNT(*) FROM assessment_assignees WHERE assessment_id = a.id) AS assignee_count
        FROM assessments a
        JOIN users u ON u.id = a.created_by
        WHERE a.status = 'active'
        ORDER BY a.created_at DESC
      `).all();
    }

    db.close();
    res.json({ assessments });
  } catch (err) {
    logger.error('List assessments error', { error: err.message });
    res.status(500).json({ error: 'Failed to list assessments' });
  }
});

// ── Analyst's Own Results + Gap Analysis ─────────────────────────────────────
router.get('/analyst/me', (req, res) => {
  try {
    const db = getDb();
    const results = db.prepare(`
      SELECT ar.skill_id, ar.score, ar.completed_at, ar.assessment_id,
             a.name AS assessment_name,
             COALESCE(ask.custom_name, ar.skill_id) AS skill_name,
             ask.is_custom
      FROM assessment_results ar
      JOIN assessments a ON a.id = ar.assessment_id
      LEFT JOIN assessment_skills ask ON ask.assessment_id = ar.assessment_id AND ask.skill_id = ar.skill_id
      WHERE ar.analyst_id = ?
      ORDER BY ar.completed_at DESC
    `).all(req.user.id);

    // Build gap analysis — latest score per skill
    const latestBySkill = {};
    for (const r of results) {
      if (!latestBySkill[r.skill_id] || r.completed_at > latestBySkill[r.skill_id].completed_at) {
        latestBySkill[r.skill_id] = r;
      }
    }

    const gaps = Object.values(latestBySkill)
      .filter(r => r.score < GAP_THRESHOLD)
      .map(r => ({
        skillId: r.skill_id,
        skillName: r.skill_name,
        score: r.score,
        gap: GAP_THRESHOLD - r.score,
        assessmentName: r.assessment_name,
      }))
      .sort((a, b) => b.gap - a.gap);

    const strengths = Object.values(latestBySkill)
      .filter(r => r.score >= GAP_THRESHOLD)
      .map(r => ({ skillId: r.skill_id, skillName: r.skill_name, score: r.score }))
      .sort((a, b) => b.score - a.score);

    db.close();
    res.json({ results, gaps, strengths, gapThreshold: GAP_THRESHOLD });
  } catch (err) {
    logger.error('Analyst results error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch results' });
  }
});

// ── Get Assessment Detail ────────────────────────────────────────────────────
router.get('/:id', (req, res) => {
  try {
    const db = getDb();
    const assessment = db.prepare('SELECT * FROM assessments WHERE id = ?').get(req.params.id);
    if (!assessment) { db.close(); return res.status(404).json({ error: 'Assessment not found' }); }

    const skills = db.prepare('SELECT * FROM assessment_skills WHERE assessment_id = ?').all(req.params.id);
    const assignees = db.prepare(`
      SELECT u.id, u.name, u.tier,
        (SELECT COUNT(*) FROM assessment_results WHERE assessment_id = ? AND analyst_id = u.id) AS completed_skills
      FROM assessment_assignees aa JOIN users u ON u.id = aa.analyst_id
      WHERE aa.assessment_id = ?
    `).all(req.params.id, req.params.id);

    // Per-analyst results (lead/admin only)
    let analystResults = [];
    if (req.user.role !== 'analyst') {
      analystResults = db.prepare(`
        SELECT ar.analyst_id, u.name AS analyst_name, ar.skill_id, ar.score, ar.completed_at,
               COALESCE(ask.custom_name, ar.skill_id) AS skill_name
        FROM assessment_results ar
        JOIN users u ON u.id = ar.analyst_id
        LEFT JOIN assessment_skills ask ON ask.assessment_id = ar.assessment_id AND ask.skill_id = ar.skill_id
        WHERE ar.assessment_id = ?
        ORDER BY u.name, ar.skill_id
      `).all(req.params.id);
    }

    db.close();
    res.json({ assessment, skills, assignees, analystResults, gapThreshold: GAP_THRESHOLD });
  } catch (err) {
    logger.error('Get assessment error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch assessment' });
  }
});

// ── Create Assessment ────────────────────────────────────────────────────────
router.post('/', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can create assessments' });

  const { name, tier, skills } = req.body;
  if (!name || !tier || !skills?.length) {
    return res.status(400).json({ error: 'name, tier, and skills[] required' });
  }
  if (name.length > 200) return res.status(400).json({ error: 'Name too long (max 200)' });
  if (![1, 2, 3].includes(tier)) return res.status(400).json({ error: 'tier must be 1, 2, or 3' });

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    db.prepare('INSERT INTO assessments (id, name, tier, created_by) VALUES (?, ?, ?, ?)').run(id, name.slice(0, 200), tier, req.user.id);

    const insertSkill = db.prepare('INSERT INTO assessment_skills (assessment_id, skill_id, is_custom, custom_name, custom_desc) VALUES (?, ?, ?, ?, ?)');
    for (const s of skills) {
      insertSkill.run(id, s.id || crypto.randomBytes(8).toString('hex'), s.isCustom ? 1 : 0, s.customName?.slice(0, 200) || null, s.customDesc?.slice(0, 500) || null);
    }

    db.close();
    auditLog(req.user.id, 'ASSESSMENT_CREATED', `name=${name} tier=${tier} skills=${skills.length}`, req.ip);
    res.status(201).json({ id, name, tier });
  } catch (err) {
    logger.error('Create assessment error', { error: err.message });
    res.status(500).json({ error: 'Failed to create assessment' });
  }
});

// ── Assign Analysts ──────────────────────────────────────────────────────────
router.post('/:id/assign', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can assign assessments' });

  const { analystIds } = req.body;
  if (!analystIds?.length) return res.status(400).json({ error: 'analystIds[] required' });

  try {
    const db = getDb();
    const assessment = db.prepare('SELECT * FROM assessments WHERE id = ?').get(req.params.id);
    if (!assessment) { db.close(); return res.status(404).json({ error: 'Assessment not found' }); }

    const insert = db.prepare('INSERT OR IGNORE INTO assessment_assignees (assessment_id, analyst_id) VALUES (?, ?)');
    const newlyAssigned = [];
    for (const aid of analystIds) {
      const result = insert.run(req.params.id, aid);
      if (result.changes > 0) newlyAssigned.push(aid);
    }
    const assigned = newlyAssigned.length;

    db.close();
    auditLog(req.user.id, 'ASSESSMENT_ASSIGNED', `assessment=${assessment.name} analysts=${assigned}`, req.ip);

    // Notify each newly-assigned analyst (skip duplicates from re-assignment)
    for (const aid of newlyAssigned) {
      try {
        notifications.notify({
          recipientId: aid,
          eventType: 'assessment_assigned',
          title: `New assessment assigned: ${assessment.name}`,
          body: `A team lead has assigned the "${assessment.name}" skills assessment to you. Open the Skills & Assessments tab to view and submit your scores.`,
          linkTab: 'skills',
          linkParams: { assessmentId: req.params.id },
        });
      } catch (notifyErr) {
        logger.warn('Assessment assign: notify failed (non-fatal)', { analystId: aid, error: notifyErr.message });
      }
    }

    res.json({ ok: true, assigned });
  } catch (err) {
    logger.error('Assign assessment error', { error: err.message });
    res.status(500).json({ error: 'Failed to assign assessment' });
  }
});

// ── Record Results (analyst submits their scores) ────────────────────────────
router.post('/:id/results', (req, res) => {
  const { scores } = req.body;
  if (!scores || !Array.isArray(scores) || scores.length === 0) {
    return res.status(400).json({ error: 'scores[] required — array of { skillId, score }' });
  }

  try {
    const db = getDb();

    // Verify analyst is assigned
    const assigned = db.prepare('SELECT 1 FROM assessment_assignees WHERE assessment_id = ? AND analyst_id = ?').get(req.params.id, req.user.id);
    if (!assigned) { db.close(); return res.status(403).json({ error: 'Not assigned to this assessment' }); }

    const insert = db.prepare(`
      INSERT INTO assessment_results (id, assessment_id, analyst_id, skill_id, score)
      VALUES (?, ?, ?, ?, ?)
    `);

    for (const s of scores) {
      const score = Math.max(0, Math.min(100, parseInt(s.score, 10) || 0));
      insert.run(crypto.randomBytes(16).toString('hex'), req.params.id, req.user.id, s.skillId, score);
    }

    // Fetch assessment metadata + creator BEFORE close so we can notify the lead.
    const meta = db.prepare(`
      SELECT a.id, a.name, a.created_by, u.name AS analyst_name
      FROM assessments a, users u
      WHERE a.id = ? AND u.id = ?
    `).get(req.params.id, req.user.id);

    db.close();
    auditLog(req.user.id, 'ASSESSMENT_COMPLETED', `assessment=${req.params.id} skills=${scores.length}`, req.ip);

    // Notify the lead who created the assessment. Skip if the creator is the
    // submitting user (lead-self-assessment edge case).
    if (meta && meta.created_by && meta.created_by !== req.user.id) {
      try {
        notifications.notify({
          recipientId: meta.created_by,
          eventType: 'assessment_completed',
          title: `Assessment completed: ${meta.name}`,
          body: `${meta.analyst_name} submitted ${scores.length} skill score${scores.length === 1 ? '' : 's'} for the "${meta.name}" assessment. Open the Skills & Assessments tab to review their results and gap analysis.`,
          linkTab: 'skills',
          linkParams: { assessmentId: req.params.id, analystId: req.user.id },
        });
      } catch (notifyErr) {
        logger.warn('Assessment complete: notify creator failed (non-fatal)', { assessmentId: req.params.id, creatorId: meta.created_by, error: notifyErr.message });
      }
    }

    res.json({ ok: true, recorded: scores.length });
  } catch (err) {
    logger.error('Record assessment results error', { error: err.message });
    res.status(500).json({ error: 'Failed to record results' });
  }
});

// ── Archive Assessment ───────────────────────────────────────────────────────
router.delete('/:id', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can archive assessments' });

  try {
    const db = getDb();
    db.prepare('UPDATE assessments SET status = ? WHERE id = ?').run('archived', req.params.id);
    db.close();
    auditLog(req.user.id, 'ASSESSMENT_ARCHIVED', req.params.id, req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Archive assessment error', { error: err.message });
    res.status(500).json({ error: 'Failed to archive assessment' });
  }
});

module.exports = router;

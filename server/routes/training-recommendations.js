// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Training Recommendations Routes (Analyst Client, R3l C6)
// Tier-3 private: every query is hard-filtered by req.user.id from the JWT so
// an analyst can only ever read their own skill gaps and recommendations.
//
// GET /api/training-recommendations/me
//
// Pipeline
//   1. Pull the analyst's most-recent score per skill from assessment_results.
//      Keep only skills where the latest score is below the configurable
//      threshold (default 70). This matches the gap definition used by the
//      legacy /api/training/recommendations endpoint, so a lead's existing
//      assessment configuration carries over without changes.
//   2. Exclude skills the analyst has already submitted a completion
//      certificate for (team_config rows with key cert_{userId}_*). Same
//      exclusion logic as the legacy endpoint.
//   3. For each remaining gap, pull matching training_modules rows by skill_id
//      from the C1 tables (populated by the R3l C3 seed loader). Order
//      beginner-first, then free-first, then by id for stable ranking.
//
// Why this is the new canonical endpoint
//   The legacy /api/training/recommendations returns platform names + search
//   terms with NO URLs — a pre-R3l defense-in-depth that's now superseded by
//   the C1 url_legitimacy CHECK constraint plus the C3 loader's pre-flight
//   allowlist validation. Real URLs (605 web-verified modules from the C2
//   seed) give analysts a one-click path from gap to material. The legacy
//   endpoint stays in place for backward compatibility until the AC frontend
//   is fully wired in C10-C13.
//
// Privacy guarantee
//   The same skill-gap data is visible to leads via /api/assessments/* with
//   the appropriate role, BUT the recommendations endpoint is analyst-self
//   only. Leads recommending training to a specific analyst should use the
//   future lead-side recommendation surface (not in scope for C6).
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

const DEFAULT_THRESHOLD = 70;
const DEFAULT_LIMIT_PER_SKILL = 10;
const MAX_LIMIT_PER_SKILL = 50;
const ALLOWED_DIFFICULTIES = ['beginner', 'intermediate', 'advanced'];

// ── GET /me ──────────────────────────────────────────────────────────────────
router.get('/me', (req, res) => {
  // Tier-3 invariant: analyst id comes from the JWT, never from the request.
  const analystId = req.user && req.user.id;
  if (!analystId) {
    return res.status(401).json({ error: 'JWT missing analyst id' });
  }

  // ── Parse + validate query params ──────────────────────────────────────────
  let threshold = parseInt(req.query.threshold, 10);
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
    threshold = DEFAULT_THRESHOLD;
  }

  let limitPerSkill = parseInt(req.query.limit_per_skill, 10);
  if (!Number.isFinite(limitPerSkill) || limitPerSkill <= 0) {
    limitPerSkill = DEFAULT_LIMIT_PER_SKILL;
  } else if (limitPerSkill > MAX_LIMIT_PER_SKILL) {
    limitPerSkill = MAX_LIMIT_PER_SKILL;
  }

  const includeCompleted = req.query.include_completed === 'true';

  const difficultyFilter = req.query.difficulty;
  if (difficultyFilter && !ALLOWED_DIFFICULTIES.includes(difficultyFilter)) {
    return res.status(400).json({ error: 'invalid difficulty', allowed: ALLOWED_DIFFICULTIES });
  }

  const db = getDb();
  try {
    // ── Step 1: identify skill gaps from the analyst's most-recent results ───
    // Mirrors the gap query in the legacy /api/training/recommendations so the
    // same lead-configured assessments produce the same gap set.
    const gaps = db.prepare(`
      SELECT ar.skill_id,
             ar.score,
             COALESCE(ask.custom_name, ar.skill_id) AS skill_name
      FROM assessment_results ar
      LEFT JOIN assessment_skills ask
        ON ask.assessment_id = ar.assessment_id AND ask.skill_id = ar.skill_id
      WHERE ar.analyst_id = ?
        AND ar.score < ?
        AND ar.completed_at = (
          SELECT MAX(ar2.completed_at)
          FROM assessment_results ar2
          WHERE ar2.analyst_id = ar.analyst_id AND ar2.skill_id = ar.skill_id
        )
      ORDER BY ar.score ASC
    `).all(analystId, threshold);

    // ── Step 2: collect skills already completed via submitted certificate ───
    // Same convention the legacy endpoint uses: certificates are stored in
    // team_config with key pattern cert_{userId}_{skillId}, value is JSON
    // containing { skillId, ... }. Parsing failures are silently skipped so
    // a single malformed row never breaks the recommendations response.
    const completedSkills = new Set();
    if (!includeCompleted) {
      const completedRows = db.prepare(
        'SELECT value FROM team_config WHERE key LIKE ?'
      ).all('cert_' + analystId + '_%');
      for (const row of completedRows) {
        try {
          const parsed = JSON.parse(row.value);
          if (parsed && typeof parsed.skillId === 'string') {
            completedSkills.add(parsed.skillId);
          }
        } catch (parseErr) {
          // Malformed cert row — ignore for the purpose of this endpoint.
          // A separate maintenance commit could surface a warning, but for
          // recommendations we just don't exclude the skill.
        }
      }
    }

    // ── Step 3: pull matching modules per gap from training_modules (C1) ─────
    // The C1 schema has a partial index on (skill_id) WHERE active = 1, so
    // this lookup is index-backed even with 605+ modules.
    let modulesSql = `
      SELECT m.id, m.platform_id, m.skill_id, m.title, m.url, m.difficulty,
             m.free_or_paid, m.estimated_hours, m.description,
             p.name AS platform_name
      FROM training_modules m
      LEFT JOIN training_platforms p ON p.id = m.platform_id
      WHERE m.skill_id = ? AND m.active = 1
    `;
    if (difficultyFilter) {
      modulesSql += ' AND m.difficulty = ?';
    }
    modulesSql += `
      ORDER BY
        CASE m.difficulty
          WHEN 'beginner' THEN 1
          WHEN 'intermediate' THEN 2
          WHEN 'advanced' THEN 3
          ELSE 4
        END,
        CASE WHEN m.free_or_paid LIKE 'free%' THEN 1 ELSE 2 END,
        m.id ASC
      LIMIT ?
    `;
    const modulesStmt = db.prepare(modulesSql);

    const recommendations = [];
    const skillsWithNoModules = [];
    let totalModules = 0;
    let skillsExcludedCompleted = 0;

    for (const gap of gaps) {
      if (completedSkills.has(gap.skill_id)) {
        skillsExcludedCompleted++;
        continue;
      }

      const moduleParams = [gap.skill_id];
      if (difficultyFilter) moduleParams.push(difficultyFilter);
      moduleParams.push(limitPerSkill);

      const modules = modulesStmt.all(...moduleParams);
      if (modules.length === 0) {
        skillsWithNoModules.push(gap.skill_id);
      }
      totalModules += modules.length;

      recommendations.push({
        skill_id: gap.skill_id,
        skill_name: gap.skill_name,
        current_score: gap.score,
        target_score: threshold,
        gap: threshold - gap.score,
        modules,
      });
    }

    res.json({
      analyst_id: analystId,
      recommendations,
      meta: {
        gap_threshold: threshold,
        skills_below_threshold: gaps.length,
        skills_excluded_completed_cert: skillsExcludedCompleted,
        skills_with_modules: recommendations.length - skillsWithNoModules.length,
        skills_with_no_matching_modules: skillsWithNoModules,
        total_modules_recommended: totalModules,
        limit_per_skill: limitPerSkill,
        difficulty_filter: difficultyFilter || null,
        include_completed: includeCompleted,
      },
    });
  } catch (err) {
    logger.error('training-recommendations/me query failed', { analystId, error: err.message });
    res.status(500).json({ error: 'internal error' });
  } finally {
    db.close();
  }
});

module.exports = router;

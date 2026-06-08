// FireAlive v1.0.42 — AI Burnout Message routes
//
// Read/refresh endpoints over the precomputed team burnout-message cache. No
// LLM inference happens here: the scheduler job generates and caches content;
// these endpoints only serve fresh cached rows or report the honest
// AI-unavailable state. Never any canned content.
//
// Per-analyst AI interpretations are not served here. Under B5d1 an analyst's
// interpretation is private to the analyst: it is generated and read on the
// analyst's own device and is never decrypted server-side.
//
//   GET  /api/ai-burnout/team-intervention-prompts (lead/admin — Tier-1 only)
//   POST /api/ai-burnout/refresh                    (lead/admin — queue regen)

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const { computeTeamHealth } = require('../services/team-health');
const { computeTeamBehavioral } = require('../services/team-behavioral');
const teamConditions = require('../services/team-conditions');
const researchKb = require('../services/research-kb');

// Narrow the already-authenticated request (set by the mount-level
// authMiddleware) to a specific role set without re-verifying the token.
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Derive a coarse, honest reason for an unavailable team prompt from the latest
// failed inference for this feature; the scheduled team calls log under a null
// user_id. When the last call did not error, there is simply no fresh content
// yet (not generated, regenerating, or a rejected citation) -> 'pending'.
function unavailableReason(db) {
  let row;
  try {
    row = db
      .prepare(
        "SELECT status, error_message FROM ai_inference_log WHERE feature_id='burnout_messages' " +
          "AND user_id IS NULL AND status != 'success' ORDER BY created_at DESC LIMIT 1"
      )
      .get();
  } catch {
    row = null;
  }
  if (!row) return { reason: 'pending', detail: null };
  const msg = row.error_message || '';
  let reason = 'error';
  if (/not loaded|bootstrap|not present/i.test(msg)) reason = 'model_not_loaded';
  else if (/no provider configured/i.test(msg)) reason = 'not_configured';
  else if (row.status === 'timeout') reason = 'timeout';
  return { reason, detail: msg ? msg.slice(0, 200) : null };
}

// ── GET /team-intervention-prompts — Tier-1 team Actions feed.
// Recomputes team health and the active conditions live, then attaches the
// cached AI prompt for each active condition (or an unavailable notice). The
// condition label and severity are ALWAYS present, so a lead sees the detected
// condition even when AI guidance is unavailable.
router.get('/team-intervention-prompts', requireRole('lead', 'admin'), (req, res) => {
  const db = getDb();
  try {
    const th = computeTeamHealth(db);
    const tb = computeTeamBehavioral(db);
    const active = teamConditions.getActive(th);
    const fallback = unavailableReason(db);
    const conditions = active.map((c) => {
      const base = { key: c.key, severity: c.severity, label: c.label };
      const row = db
        .prepare(
          "SELECT content, model_name, kb_refs, generated_at FROM team_intervention_prompts " +
            "WHERE prompt_key=? AND expires_at > datetime('now')"
        )
        .get(c.key);
      if (!row) {
        return { ...base, status: 'unavailable', reason: fallback.reason, detail: fallback.detail };
      }
      let content = null;
      try {
        content = JSON.parse(row.content);
      } catch {
        content = null;
      }
      if (!content) {
        return { ...base, status: 'unavailable', reason: 'pending', detail: null };
      }
      return {
        ...base,
        status: 'ai',
        content,
        model_name: row.model_name,
        kb_refs: safeParseArray(row.kb_refs),
        generated_at: row.generated_at,
      };
    });
    res.json({ teamHealth: th, teamBehavioral: tb, conditions, kbVersion: researchKb.KB_VERSION });
  } catch (err) {
    logger.error('ai-burnout: team-intervention-prompts failed', { error: err.message });
    res.status(500).json({ error: 'internal error' });
  } finally {
    db.close();
  }
});

// ── POST /refresh — lead/admin asks for fresh team guidance.
// Expires the cached team prompts so the next precompute cycle regenerates the
// active conditions; no LLM work happens in this request. Rate-limited to one
// trigger per 60s per user and audited. Regeneration completes on the next
// team precompute cycle.
const refreshThrottle = new Map(); // userId -> last trigger ms (single-process best-effort)
const REFRESH_MIN_INTERVAL_MS = 60 * 1000;

router.post('/refresh', requireRole('lead', 'admin'), (req, res) => {
  const now = Date.now();
  const last = refreshThrottle.get(req.user.id) || 0;
  if (now - last < REFRESH_MIN_INTERVAL_MS) {
    const retryAfterSec = Math.ceil((REFRESH_MIN_INTERVAL_MS - (now - last)) / 1000);
    return res.status(429).json({ error: 'Please wait before refreshing again', retryAfterSec });
  }
  refreshThrottle.set(req.user.id, now);
  const db = getDb();
  try {
    db.prepare("UPDATE team_intervention_prompts SET expires_at = datetime('now', '-1 second')").run();
    auditLog(req.user.id, 'MC_AI_BURNOUT_REFRESH_TRIGGERED', null, req.ip);
    res.json({ ok: true, status: 'refresh_queued' });
  } catch (err) {
    logger.error('ai-burnout: refresh failed', { error: err.message });
    res.status(500).json({ error: 'internal error' });
  } finally {
    db.close();
  }
});

function safeParseArray(s) {
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

module.exports = router;

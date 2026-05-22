// FireAlive v1.0.42 — AI Burnout Message routes
//
// Read/refresh endpoints over the precomputed burnout-message caches. No LLM
// inference happens here: the scheduler jobs generate and cache content; these
// endpoints only serve fresh cached rows or report the honest AI-unavailable
// state. Never any canned content.
//
//   GET  /api/ai-burnout/analyst-interpretations   (analyst — own Tier-3 data)
//   GET  /api/ai-burnout/team-intervention-prompts (lead/admin — Tier-1 only)
//   POST /api/ai-burnout/refresh                    (lead/admin — queue regen)

const router = require('express').Router();
const { getDb } = require('../db/init');
const { decryptTier3 } = require('../services/encryption');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const { computeTeamHealth } = require('../services/team-health');
const teamConditions = require('../services/team-conditions');
const researchKb = require('../services/research-kb');

const SIGNAL_KEYS = ['investigationTime', 'dismissRate', 'ticketQuality', 'escalationRate'];

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

// Derive a coarse, honest reason for an unavailable item from the latest failed
// inference for this feature, scoped to the analyst (selfUserId) or to the
// scheduled team calls (selfUserId null). When the last call did not error,
// there is simply no fresh content yet (not generated, regenerating, or a
// rejected citation) -> 'pending'.
function unavailableReason(db, selfUserId) {
  let row;
  try {
    if (selfUserId) {
      row = db
        .prepare(
          "SELECT status, error_message FROM ai_inference_log WHERE feature_id='burnout_messages' " +
            "AND user_id=? AND status != 'success' ORDER BY created_at DESC LIMIT 1"
        )
        .get(selfUserId);
    } else {
      row = db
        .prepare(
          "SELECT status, error_message FROM ai_inference_log WHERE feature_id='burnout_messages' " +
            "AND user_id IS NULL AND status != 'success' ORDER BY created_at DESC LIMIT 1"
        )
        .get();
    }
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

// ── GET /analyst-interpretations — the caller's own per-signal interpretations.
// Returns all four signals; each is either AI content or an unavailable notice.
// The signal values themselves are not returned here (the My Signals tab
// already has them) — only the AI interpretation text, which is Tier-3 and
// decrypted for the owning analyst alone.
router.get('/analyst-interpretations', requireRole('analyst'), (req, res) => {
  const db = getDb();
  try {
    const analystId = req.user.id;
    const fallback = unavailableReason(db, analystId);
    const out = {};
    for (const sk of SIGNAL_KEYS) {
      const row = db
        .prepare(
          "SELECT interpretation_encrypted, model_name, kb_refs, generated_at FROM analyst_interpretations " +
            "WHERE analyst_id=? AND signal_key=? AND expires_at > datetime('now')"
        )
        .get(analystId, sk);
      if (!row) {
        out[sk] = { status: 'unavailable', reason: fallback.reason, detail: fallback.detail };
        continue;
      }
      try {
        const dec = decryptTier3(row.interpretation_encrypted);
        out[sk] = {
          status: 'ai',
          text: dec && dec.text,
          model_name: row.model_name,
          kb_refs: safeParseArray(row.kb_refs),
          generated_at: row.generated_at,
        };
      } catch (err) {
        logger.warn('ai-burnout: analyst interpretation decrypt failed', {
          analystId,
          signal: sk,
          error: err.message,
        });
        out[sk] = { status: 'unavailable', reason: 'decryption_failed', detail: null };
      }
    }
    res.json({ interpretations: out, kbVersion: researchKb.KB_VERSION });
  } catch (err) {
    logger.error('ai-burnout: analyst-interpretations failed', { error: err.message });
    res.status(500).json({ error: 'internal error' });
  } finally {
    db.close();
  }
});

// ── GET /team-intervention-prompts — Tier-1 team Actions feed.
// Recomputes team health and the active conditions live, then attaches the
// cached AI prompt for each active condition (or an unavailable notice). The
// condition label and severity are ALWAYS present, so a lead sees the detected
// condition even when AI guidance is unavailable.
router.get('/team-intervention-prompts', requireRole('lead', 'admin'), (req, res) => {
  const db = getDb();
  try {
    const th = computeTeamHealth(db);
    const active = teamConditions.getActive(th);
    const fallback = unavailableReason(db, null);
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
    res.json({ teamHealth: th, conditions, kbVersion: researchKb.KB_VERSION });
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

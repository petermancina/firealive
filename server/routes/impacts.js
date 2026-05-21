// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Impacts Routes (Analyst Client, R3l C5)
// Tier-3 private: every query is hard-filtered by req.user.id from the JWT so
// an analyst can only ever read their own impact history. There is no
// analyst_id query parameter, by design.
//
// Impacts are positive wellbeing events the burnout engine records when an
// analyst experiences something good — a clean incident resolution, a peer
// mentoring moment, a recovery uptick. See services/ai-burnout-engine.js
// (recordImpact). They are stored plain-text in analyst_impacts (unlike
// analyst_signals which is Tier-3 encrypted) because they carry no
// quantitative burnout indicators, only qualitative narrative.
//
// GET /api/impacts/me — analyst-self view returning:
//   • impacts        — filtered impact rows in reverse-chron order
//   • distinct_types — every type string present in the analyst's full history
//                      (used by the AC frontend to populate a filter dropdown
//                      without requiring a second round trip)
//   • meta           — pagination + filter echo
//
// This is the canonical analyst-self endpoint shipped in R3l. The historical
// weakly-scoped GET /impacts/:analystId variant in server/routes/v100-features.js
// (removed in R3m C3) took analyst id as a URL parameter rather than the
// JWT-self scope this endpoint enforces. The AC frontend wiring of this
// endpoint shipped in R3l C10-C13.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

const DEFAULT_LOOKBACK_DAYS = 30;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;

// Type strings are free-form — written by the burnout engine and potentially
// by future services. No allowlist validation: if a new type is added later
// the endpoint accepts it without code changes. The type column is queried
// only via parameterised binds so there is no injection surface.

// ── GET /me ──────────────────────────────────────────────────────────────────
router.get('/me', (req, res) => {
  // Tier-3 invariant: analyst id comes from the JWT, never from the request.
  // Defensive failure if the JWT is malformed — fail closed.
  const analystId = req.user && req.user.id;
  if (!analystId) {
    return res.status(401).json({ error: 'JWT missing analyst id' });
  }

  // ── Parse + validate query params ──────────────────────────────────────────
  const now = new Date();
  const defaultSince = new Date(now.getTime() - DEFAULT_LOOKBACK_DAYS * 24 * 60 * 60 * 1000);

  let sinceDate;
  let untilDate;
  try {
    sinceDate = req.query.since ? new Date(req.query.since) : defaultSince;
    untilDate = req.query.until ? new Date(req.query.until) : now;
    if (isNaN(sinceDate.getTime()) || isNaN(untilDate.getTime())) {
      return res.status(400).json({ error: 'invalid since/until timestamp; use ISO 8601 format' });
    }
    if (sinceDate.getTime() > untilDate.getTime()) {
      return res.status(400).json({ error: 'since must be earlier than until' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'invalid since/until timestamp; use ISO 8601 format' });
  }

  // Type filter (optional). Cap length to a reasonable bound so a pathological
  // querystring can't bloat the SQL bind parameter.
  let typeFilter = req.query.type;
  if (typeFilter !== undefined && typeFilter !== null) {
    if (typeof typeFilter !== 'string') {
      return res.status(400).json({ error: 'type filter must be a string' });
    }
    if (typeFilter.length > 100) {
      return res.status(400).json({ error: 'type filter too long (max 100 chars)' });
    }
    if (typeFilter.length === 0) {
      typeFilter = undefined; // treat empty string as no filter
    }
  }

  let limit = parseInt(req.query.limit, 10);
  if (!Number.isFinite(limit) || limit <= 0) {
    limit = DEFAULT_LIMIT;
  } else if (limit > MAX_LIMIT) {
    limit = MAX_LIMIT;
  }

  const db = getDb();
  try {
    // ── Impacts in the requested window ──────────────────────────────────────
    // datetime() applied on both sides because recorded_at is stored in
    // SQLite's "YYYY-MM-DD HH:MM:SS" format (via datetime('now')) while
    // incoming ISO 8601 strings carry T separators and Z suffixes.
    let impactsSql = `
      SELECT id, type, description, recorded_at
      FROM analyst_impacts
      WHERE analyst_id = ?
        AND datetime(recorded_at) >= datetime(?)
        AND datetime(recorded_at) <= datetime(?)
    `;
    const params = [analystId, sinceDate.toISOString(), untilDate.toISOString()];

    if (typeFilter) {
      impactsSql += ' AND type = ?';
      params.push(typeFilter);
    }

    impactsSql += ' ORDER BY recorded_at DESC LIMIT ?';
    params.push(limit);

    const impacts = db.prepare(impactsSql).all(...params);

    // ── Distinct types across full history (not bounded by since/until) ──────
    // Used by the AC frontend to populate a filter dropdown. Computed in the
    // same DB round so the client can render the UI without a second call.
    const distinctRows = db.prepare(
      'SELECT DISTINCT type FROM analyst_impacts WHERE analyst_id = ? AND type IS NOT NULL ORDER BY type ASC'
    ).all(analystId);
    const distinctTypes = distinctRows.map((r) => r.type);

    res.json({
      analyst_id: analystId,
      impacts,
      distinct_types: distinctTypes,
      meta: {
        count: impacts.length,
        since: sinceDate.toISOString(),
        until: untilDate.toISOString(),
        type: typeFilter || null,
        limit,
        truncated: impacts.length === limit,
      },
    });
  } catch (err) {
    logger.error('impacts/me query failed', { analystId, error: err.message });
    res.status(500).json({ error: 'internal error' });
  } finally {
    db.close();
  }
});

module.exports = router;

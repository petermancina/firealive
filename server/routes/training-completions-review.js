/**
 * routes/training-completions-review.js (R3l C16a)
 *
 * Lead/admin-only endpoints for reviewing training_completions submissions
 * that analysts make via POST /api/training/submit-completion (the schema is
 * pre-R3l canonical; the AC form was wired in R3l C13).
 *
 * Why this exists
 *   The pre-existing GET /api/training/completions in routes/training.js reads
 *   cert_* entries from team_config (training certificates with file uploads)
 *   and does not surface training_completions table rows. Without this route,
 *   submissions written by C13's POST handler go into a black hole: nobody can
 *   list, verify, or reject them.
 *
 * Endpoints
 *   GET  /                  — list completions filtered by status, with counts
 *   PATCH /:id              — transition a pending completion to verified|rejected
 *
 * Privacy / Tier-1 invariant
 *   Endpoints are role-gated to lead/admin via the mount in server/index.js.
 *   Responses include per-completion user_id and user_name so the lead can
 *   attribute submissions, which is appropriate at Tier-1 (the lead's normal
 *   visibility of their team's training activity). No Tier-3 wellness signals
 *   are exposed.
 *
 * Audit
 *   - List operation: TRAINING_COMPLETIONS_REVIEW_VIEWED (fire-and-forget)
 *   - Verify transition: TRAINING_COMPLETION_VERIFIED
 *   - Reject transition: TRAINING_COMPLETION_REJECTED
 *   All audit calls are best-effort and swallow errors internally.
 */

const express = require('express');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');

const router = express.Router();

const ALLOWED_STATUSES = new Set(['pending', 'verified', 'rejected', 'all']);
const ALLOWED_TRANSITIONS = new Set(['verified', 'rejected']);
const MAX_LIMIT = 200;
const DEFAULT_LIMIT = 50;

router.get('/', (req, res) => {
  const status = String(req.query.status || 'pending').toLowerCase();
  if (!ALLOWED_STATUSES.has(status)) {
    return res.status(400).json({
      error: 'Invalid status filter. Use: pending, verified, rejected, all.',
    });
  }

  let limit = parseInt(req.query.limit, 10);
  if (!Number.isFinite(limit) || limit < 1) limit = DEFAULT_LIMIT;
  if (limit > MAX_LIMIT) limit = MAX_LIMIT;

  let offset = parseInt(req.query.offset, 10);
  if (!Number.isFinite(offset) || offset < 0) offset = 0;

  let db;
  try {
    db = getDb();

    // Counts per status (used by the MC summary tiles)
    const countRows = db
      .prepare('SELECT status, COUNT(*) AS n FROM training_completions GROUP BY status')
      .all();
    const counts = { pending: 0, verified: 0, rejected: 0 };
    for (const r of countRows) {
      if (counts[r.status] !== undefined) counts[r.status] = r.n;
    }
    counts.total = counts.pending + counts.verified + counts.rejected;

    // Filtered list (most-recent-first)
    let whereClause = '';
    const params = [];
    if (status !== 'all') {
      whereClause = 'WHERE tc.status = ?';
      params.push(status);
    }
    const completions = db
      .prepare(
        'SELECT tc.id, tc.user_id, u.name AS user_name, tc.module, tc.platform, ' +
          'tc.url, tc.completion_date, tc.score, tc.status, ' +
          'tc.submitted_at, tc.verified_at, tc.verified_by ' +
          'FROM training_completions tc ' +
          'LEFT JOIN users u ON u.id = tc.user_id ' +
          whereClause +
          ' ORDER BY tc.submitted_at DESC LIMIT ? OFFSET ?'
      )
      .all(...params, limit, offset);

    try {
      auditLog(req.user.id, 'TRAINING_COMPLETIONS_REVIEW_VIEWED', {
        status,
        count: completions.length,
      });
    } catch (_e) {
      // best-effort
    }

    res.json({
      completions,
      counts,
      meta: {
        filtered_by_status: status,
        limit,
        offset,
        returned: completions.length,
      },
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to fetch training completions for review',
    });
  } finally {
    try {
      if (db) db.close();
    } catch (_e) {
      // ignore close errors
    }
  }
});

router.patch('/:id', (req, res) => {
  const id = String(req.params.id || '').trim();
  if (!id) {
    return res.status(400).json({ error: 'Missing completion id' });
  }

  const status = String((req.body && req.body.status) || '').toLowerCase();
  if (!ALLOWED_TRANSITIONS.has(status)) {
    return res.status(400).json({
      error: 'Invalid status transition. Allowed: verified, rejected.',
    });
  }

  let db;
  try {
    db = getDb();

    const existing = db
      .prepare('SELECT id, status FROM training_completions WHERE id = ?')
      .get(id);
    if (!existing) {
      return res.status(404).json({ error: 'Completion not found' });
    }
    if (existing.status !== 'pending') {
      return res.status(409).json({
        error:
          'Cannot transition from status \'' +
          existing.status +
          '\'. Only pending completions can be verified or rejected.',
      });
    }

    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
    db.prepare(
      'UPDATE training_completions SET status = ?, verified_at = ?, verified_by = ? WHERE id = ?'
    ).run(status, now, req.user.id, id);

    const eventType =
      status === 'verified'
        ? 'TRAINING_COMPLETION_VERIFIED'
        : 'TRAINING_COMPLETION_REJECTED';
    try {
      auditLog(req.user.id, eventType, { completion_id: id });
    } catch (_e) {
      // best-effort
    }

    res.json({
      id,
      status,
      verified_at: now,
      verified_by: req.user.id,
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to update training completion',
    });
  } finally {
    try {
      if (db) db.close();
    } catch (_e) {
      // ignore close errors
    }
  }
});

module.exports = router;

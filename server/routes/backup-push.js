// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Push Status Admin Routes
//
// Admin-only endpoints for inspecting push status and triggering
// manual retries. The push orchestrator (services/backup-push.js)
// runs automatically after every backup creation; the scheduler
// retries transient failures hourly. These endpoints expose:
//
//   - Read access to push status (for admin UI dashboards)
//   - Manual retry trigger (for "I just fixed the network" scenarios)
//   - Manual retry-all-due (operator-initiated equivalent of the
//     scheduler's hourly sweep)
//
// Mounted at /api/backup-push in server/index.js (commit 12 of this
// phase) with authMiddleware(['admin']). The route file does NOT
// apply auth itself.
//
// ENDPOINTS
//
//   GET  /api/backup-push
//     List push records with cursor pagination on id descending.
//     Query: ?limit=N (default 50, max 200), ?before=ID,
//            ?status=succeeded|failed|queued|running,
//            ?destination_id=ID, ?backup_id=ID
//     Returns: { pushes: [...], nextBefore: ID|null }
//     Each push row includes joined destination_name + adapter
//     for display. error_message is included for failed rows
//     so admin UI can show without a second fetch.
//
//   GET  /api/backup-push/:pushId
//     Single push record by id (number). 404 if missing.
//
//   GET  /api/backup-push/backup/:backupId
//     All push attempts for a given backup, ordered by created_at.
//     Useful for the per-backup detail page in admin UI.
//
//   POST /api/backup-push/:pushId/retry
//     Manually retry a single push. Behavior:
//       - If status='succeeded': returns 200 with skipped='already-succeeded'
//       - If status='running' or 'queued': returns 409 (already in progress)
//       - If status='failed' AND attempt_count >= MAX_ATTEMPTS: resets
//         attempt_count to 0 (operator override) and retries
//       - Otherwise: retries immediately, ignoring next_retry_at
//
//   POST /api/backup-push/retry-all-due
//     Trigger the scheduler-equivalent retry sweep. Same logic as
//     the cron job (commits 13-14). Useful when operator has just
//     fixed an upstream issue and wants retries now without
//     waiting for the next cron tick. Returns { retried, results: [...] }.
//
// MANUAL RETRY ATTEMPT-COUNT RESET
//
// When an admin clicks "retry now" on a push at MAX_ATTEMPTS,
// they're explicitly accepting responsibility for the override --
// typically because they've fixed the underlying issue (auth
// rotated, network repaired). Resetting attempt_count to 0 gives
// the push a fresh chain of automatic retries; if it fails 5
// more times, the cap trips again. The reset is logged in the
// audit trail with the admin's user id for accountability.
//
// AUDIT LOGGING
//
// Every endpoint emits an auditLog entry. The retry endpoints
// log retry triggers AND the resulting status. Sensitive fields
// (credentials, config values) are not relevant here -- this
// route reads only push metadata, not destination configs.
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const router = express.Router();

const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const backupPush = require('../services/backup-push');

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const VALID_STATUSES = new Set(['queued', 'running', 'succeeded', 'failed']);

// ── GET / (paginated list) ───────────────────────────────────────────────

router.get('/', (req, res) => {
  let db;
  try {
    db = getDb();

    let limit = parseInt(req.query.limit, 10);
    if (!Number.isInteger(limit) || limit < 1) limit = DEFAULT_LIMIT;
    if (limit > MAX_LIMIT) limit = MAX_LIMIT;

    const where = [];
    const args = [];

    if (typeof req.query.before === 'string' && req.query.before !== '') {
      const before = parseInt(req.query.before, 10);
      if (!Number.isInteger(before) || before < 1) {
        return res.status(400).json({ error: 'before must be a positive integer' });
      }
      where.push('bp.id < ?');
      args.push(before);
    }

    if (typeof req.query.status === 'string' && req.query.status !== '') {
      if (!VALID_STATUSES.has(req.query.status)) {
        return res.status(400).json({ error: `status must be one of: ${[...VALID_STATUSES].join(', ')}` });
      }
      where.push('bp.status = ?');
      args.push(req.query.status);
    }

    if (typeof req.query.destination_id === 'string' && req.query.destination_id !== '') {
      where.push('bp.destination_id = ?');
      args.push(req.query.destination_id);
    }

    if (typeof req.query.backup_id === 'string' && req.query.backup_id !== '') {
      where.push('bp.backup_id = ?');
      args.push(req.query.backup_id);
    }

    const whereSql = where.length > 0 ? 'WHERE ' + where.join(' AND ') : '';

    // Fetch one extra row to determine if there's a next page
    const sql = `
      SELECT bp.*, bd.name AS destination_name, bd.adapter AS destination_adapter
      FROM backup_pushes bp
      LEFT JOIN backup_destinations bd ON bd.id = bp.destination_id
      ${whereSql}
      ORDER BY bp.id DESC
      LIMIT ?
    `;
    const rows = db.prepare(sql).all(...args, limit + 1);
    let nextBefore = null;
    if (rows.length > limit) {
      nextBefore = rows[limit - 1].id;
      rows.length = limit;
    }

    auditLog(
      req.user?.id,
      'BACKUP_PUSHES_LISTED',
      `count=${rows.length}${req.query.status ? ` status=${req.query.status}` : ''}${req.query.destination_id ? ` destination_id=${req.query.destination_id}` : ''}${req.query.backup_id ? ` backup_id=${req.query.backup_id}` : ''}`,
      req.ip,
    );

    res.json({ pushes: rows, nextBefore });
  } catch (err) {
    logger.error('routes/backup-push: list failed', { error: err.message });
    res.status(500).json({ error: 'Failed to list pushes' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

// ── GET /:pushId (single status) ─────────────────────────────────────────
//
// Path order matters in Express. /:pushId would gobble paths like
// /backup/abc, so /backup/:backupId is registered FIRST. Same logic
// for the POST /retry-all-due path (registered before /:pushId/retry).
// In Express 5 + path-to-regexp v8, `:param(regex)` syntax was removed,
// so id validation happens inside the handler body.

router.get('/backup/:backupId', (req, res) => {
  let db;
  try {
    const backupId = req.params.backupId;
    if (typeof backupId !== 'string' || backupId.length === 0) {
      return res.status(400).json({ error: 'backupId required' });
    }
    db = getDb();
    const pushes = backupPush.listPushesForBackup(db, backupId);
    auditLog(req.user?.id, 'BACKUP_PUSHES_FOR_BACKUP_VIEWED', `backup_id=${backupId} count=${pushes.length}`, req.ip);
    res.json({ pushes });
  } catch (err) {
    logger.error('routes/backup-push: list-for-backup failed', { backupId: req.params.backupId, error: err.message });
    res.status(500).json({ error: 'Failed to get pushes for backup' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

router.get('/:pushId', (req, res) => {
  let db;
  try {
    const pushId = parseInt(req.params.pushId, 10);
    if (!Number.isInteger(pushId) || pushId < 1 || String(pushId) !== req.params.pushId) {
      return res.status(400).json({ error: 'pushId must be a positive integer' });
    }
    db = getDb();
    const row = db.prepare(`
      SELECT bp.*, bd.name AS destination_name, bd.adapter AS destination_adapter
      FROM backup_pushes bp
      LEFT JOIN backup_destinations bd ON bd.id = bp.destination_id
      WHERE bp.id = ?
    `).get(pushId);
    if (!row) return res.status(404).json({ error: 'Push not found' });
    auditLog(req.user?.id, 'BACKUP_PUSH_VIEWED', `push_id=${pushId} status=${row.status}`, req.ip);
    res.json({ push: row });
  } catch (err) {
    logger.error('routes/backup-push: get failed', { pushId: req.params.pushId, error: err.message });
    res.status(500).json({ error: 'Failed to get push' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

// ── POST /retry-all-due (manual scheduler-equivalent sweep) ──────────────
// Registered BEFORE /:pushId/retry so the literal path takes precedence.

router.post('/retry-all-due', async (req, res) => {
  let db;
  try {
    db = getDb();
    const result = await backupPush.retryAllDuePushes(db, { logger });
    const succeededCount = result.results.filter(r => r.ok && !r.skipped).length;
    const failedCount = result.results.filter(r => !r.ok && !r.skipped).length;
    const skippedCount = result.results.filter(r => r.skipped).length;
    auditLog(
      req.user?.id,
      'BACKUP_PUSH_RETRY_ALL_DUE',
      `retried=${result.retried} succeeded=${succeededCount} failed=${failedCount} skipped=${skippedCount}`,
      req.ip,
    );
    res.json({
      retried: result.retried,
      succeeded: succeededCount,
      failed: failedCount,
      skipped: skippedCount,
      results: result.results,
    });
  } catch (err) {
    logger.error('routes/backup-push: retry-all-due failed', { error: err.message });
    res.status(500).json({ error: 'Failed to retry due pushes' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

// ── POST /:pushId/retry (manual retry single push) ───────────────────────

router.post('/:pushId/retry', async (req, res) => {
  let db;
  try {
    const pushId = parseInt(req.params.pushId, 10);
    if (!Number.isInteger(pushId) || pushId < 1 || String(pushId) !== req.params.pushId) {
      return res.status(400).json({ error: 'pushId must be a positive integer' });
    }
    db = getDb();
    const existing = db.prepare('SELECT * FROM backup_pushes WHERE id = ?').get(pushId);
    if (!existing) return res.status(404).json({ error: 'Push not found' });

    if (existing.status === 'succeeded') {
      auditLog(req.user?.id, 'BACKUP_PUSH_RETRY_SKIPPED', `push_id=${pushId} reason=already-succeeded`, req.ip);
      return res.json({ pushId, ok: true, skipped: 'already-succeeded' });
    }
    if (existing.status === 'queued' || existing.status === 'running') {
      auditLog(req.user?.id, 'BACKUP_PUSH_RETRY_REFUSED', `push_id=${pushId} reason=in-progress current_status=${existing.status}`, req.ip);
      return res.status(409).json({
        error: `push is currently ${existing.status}; cannot retry while in progress`,
        current_status: existing.status,
      });
    }

    // Operator override at MAX_ATTEMPTS: reset attempt_count to 0 so
    // the standard retry path can proceed. Logged distinctly.
    let resetForOverride = false;
    if (existing.attempt_count >= backupPush.MAX_ATTEMPTS) {
      db.prepare('UPDATE backup_pushes SET attempt_count = 0, next_retry_at = NULL WHERE id = ?').run(pushId);
      resetForOverride = true;
      auditLog(
        req.user?.id,
        'BACKUP_PUSH_ATTEMPT_COUNT_RESET',
        `push_id=${pushId} previous_attempt_count=${existing.attempt_count} operator_override=true`,
        req.ip,
      );
    }

    const result = await backupPush.retryPush(db, pushId, { logger });

    auditLog(
      req.user?.id,
      result.ok ? 'BACKUP_PUSH_RETRY_OK' : 'BACKUP_PUSH_RETRY_FAILED',
      `push_id=${pushId} ok=${result.ok}${resetForOverride ? ' override=true' : ''}${result.error ? ' error=' + result.error.slice(0, 200) : ''}`,
      req.ip,
    );
    res.json({ pushId, override_applied: resetForOverride, ...result });
  } catch (err) {
    logger.error('routes/backup-push: retry failed', { pushId: req.params.pushId, error: err.message });
    res.status(500).json({ error: 'Failed to retry push' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

module.exports = router;

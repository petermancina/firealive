// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Notifications Admin Routes
// Mounted at /api/inbox/admin by server/index.js. Admin-only.
//
// GET  /api/inbox/admin/stats                — per-status counts and recent failures
// POST /api/inbox/admin/flush-queue          — invoke the email pipeline immediately
// POST /api/inbox/admin/requeue/:id          — requeue a single failed/bounced notification
// POST /api/inbox/admin/requeue-all-failed   — requeue all currently failed notifications
//
// These endpoints are for diagnosing and recovering from email delivery problems
// (SMTP credential rotation, bounced addresses that have been corrected,
// transient network failures during a cycle, etc.). Mounting under
// /api/inbox/admin keeps them grouped with the user-facing inbox endpoints
// while making the auth scope explicit at the mount point.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── Pipeline statistics ──────────────────────────────────────────────────────
router.get('/stats', (req, res) => {
  try {
    const db = getDb();

    const counts = db.prepare(`
      SELECT
        COUNT(*) FILTER (WHERE email_delivery_status IS NULL)            AS no_email_requested,
        COUNT(*) FILTER (WHERE email_delivery_status = 'queued')         AS queued,
        COUNT(*) FILTER (WHERE email_delivery_status = 'sent')           AS sent,
        COUNT(*) FILTER (WHERE email_delivery_status = 'failed')         AS failed,
        COUNT(*) FILTER (WHERE email_delivery_status = 'bounced')        AS bounced,
        COUNT(*)                                                         AS total
      FROM notifications
    `).get();

    // Recent failures (last 30 days) with error context from audit log
    const recentFailures = db.prepare(`
      SELECT
        n.id,
        n.recipient_id,
        n.event_type,
        n.title,
        n.email_delivery_status,
        n.created_at,
        (SELECT detail FROM audit_log
         WHERE event_type = 'NOTIFICATION_EMAIL_FAILED'
           AND detail LIKE 'id=' || n.id || '%'
         ORDER BY id DESC LIMIT 1) AS last_error
      FROM notifications n
      WHERE n.email_delivery_status IN ('failed', 'bounced')
        AND n.created_at > datetime('now', '-30 days')
      ORDER BY n.created_at DESC
      LIMIT 50
    `).all();

    db.close();

    res.json({ counts, recentFailures });
  } catch (err) {
    logger.error('Notifications admin stats error', { error: err.message });
    res.status(500).json({ error: 'Failed to load notifications stats' });
  }
});

// ── Flush the queue immediately ──────────────────────────────────────────────
router.post('/flush-queue', async (req, res) => {
  try {
    const { processQueue } = require('../services/notifications-pipeline');
    const stats = await processQueue();
    auditLog(req.user?.id, 'NOTIFICATIONS_QUEUE_FLUSHED_MANUALLY', JSON.stringify(stats), req.ip);
    res.json({ success: true, stats });
  } catch (err) {
    logger.error('Notifications flush-queue error', { error: err.message });
    res.status(500).json({ error: 'Failed to flush queue' });
  }
});

// ── Requeue a single failed/bounced notification ─────────────────────────────
router.post('/requeue/:id', (req, res) => {
  try {
    const { id } = req.params;
    if (!id || typeof id !== 'string') return res.status(400).json({ error: 'Notification id required' });

    const db = getDb();
    const row = db.prepare(`
      SELECT id, email_delivery_status FROM notifications WHERE id = ?
    `).get(id);

    if (!row) { db.close(); return res.status(404).json({ error: 'Notification not found' }); }
    if (row.email_delivery_status !== 'failed' && row.email_delivery_status !== 'bounced') {
      db.close();
      return res.status(400).json({
        error: `Cannot requeue notification in status "${row.email_delivery_status}". Only failed or bounced notifications can be requeued.`,
      });
    }

    db.prepare(`
      UPDATE notifications SET email_delivery_status = 'queued', delivered_email = 0 WHERE id = ?
    `).run(id);
    db.close();

    auditLog(req.user?.id, 'NOTIFICATION_REQUEUED', `id=${id} from=${row.email_delivery_status}`, req.ip);
    res.json({ success: true, id, previousStatus: row.email_delivery_status });
  } catch (err) {
    logger.error('Notification requeue error', { error: err.message });
    res.status(500).json({ error: 'Failed to requeue notification' });
  }
});

// ── Requeue all currently-failed notifications ───────────────────────────────
// Note: bounced notifications are NOT included by default — bounces typically
// require an address change before retrying. Pass {includeBounced: true} to
// requeue bounces as well.
router.post('/requeue-all-failed', (req, res) => {
  try {
    const includeBounced = req.body?.includeBounced === true;
    const db = getDb();

    const sql = includeBounced
      ? `UPDATE notifications SET email_delivery_status = 'queued', delivered_email = 0
         WHERE email_delivery_status IN ('failed', 'bounced')`
      : `UPDATE notifications SET email_delivery_status = 'queued', delivered_email = 0
         WHERE email_delivery_status = 'failed'`;

    const result = db.prepare(sql).run();
    db.close();

    auditLog(
      req.user?.id,
      'NOTIFICATIONS_BULK_REQUEUED',
      `count=${result.changes} includeBounced=${includeBounced}`,
      req.ip,
    );
    res.json({ success: true, requeued: result.changes, includeBounced });
  } catch (err) {
    logger.error('Notifications bulk requeue error', { error: err.message });
    res.status(500).json({ error: 'Failed to bulk-requeue notifications' });
  }
});

module.exports = router;

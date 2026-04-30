// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — In-App Notifications Routes
// Mounted at /api/inbox by server/index.js.
//
// GET    /api/inbox                — list notifications for the current user
// GET    /api/inbox/unread-count   — unread count for the badge
// POST   /api/inbox/:id/read       — mark one notification read
// POST   /api/inbox/read-all       — mark all current user's notifications read
// GET    /api/inbox/preferences    — get this user's effective preferences
// PUT    /api/inbox/preferences/:eventType — update one preference
//
// NOTE: The pre-existing /api/notifications namespace (routes/notifications.js)
// owns burnout-alert delivery-channel config (webhook, email, SMS, PagerDuty)
// for *outbound* alerting. That is a separate feature from in-app notifications
// and the namespaces are intentionally kept distinct.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const notifications = require('../services/notifications');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── List notifications for current user ──────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Authentication required' });

    const includeRead = req.query.includeRead === 'true' || req.query.includeRead === '1';
    const limitRaw = req.query.limit;
    const limit = limitRaw ? parseInt(limitRaw, 10) : 100;

    const items = notifications.listForUser(userId, { includeRead, limit });
    res.json({ items, count: items.length });
  } catch (err) {
    logger.error('List notifications error', { error: err.message });
    res.status(500).json({ error: 'Failed to list notifications' });
  }
});

// ── Unread badge count ───────────────────────────────────────────────────────
router.get('/unread-count', (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Authentication required' });
    res.json({ unread: notifications.unreadCount(userId) });
  } catch (err) {
    logger.error('Unread count error', { error: err.message });
    res.status(500).json({ error: 'Failed to get unread count' });
  }
});

// ── Mark one read ────────────────────────────────────────────────────────────
router.post('/:id/read', (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Authentication required' });

    const id = req.params.id;
    if (!id || typeof id !== 'string') return res.status(400).json({ error: 'Notification id required' });

    const ok = notifications.markRead(userId, id);
    if (!ok) return res.status(404).json({ error: 'Notification not found, already read, or does not belong to this user' });

    res.json({ success: true });
  } catch (err) {
    logger.error('Mark notification read error', { error: err.message });
    res.status(500).json({ error: 'Failed to mark notification read' });
  }
});

// ── Mark all read ────────────────────────────────────────────────────────────
router.post('/read-all', (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Authentication required' });

    const count = notifications.markAllRead(userId);
    auditLog(userId, 'NOTIFICATIONS_MARK_ALL_READ', `count=${count}`, req.ip);
    res.json({ success: true, marked: count });
  } catch (err) {
    logger.error('Mark all read error', { error: err.message });
    res.status(500).json({ error: 'Failed to mark all notifications read' });
  }
});

// ── Get preferences ──────────────────────────────────────────────────────────
router.get('/preferences', (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Authentication required' });
    res.json({ preferences: notifications.getPreferences(userId) });
  } catch (err) {
    logger.error('Get preferences error', { error: err.message });
    res.status(500).json({ error: 'Failed to get preferences' });
  }
});

// ── Update one preference ────────────────────────────────────────────────────
router.put('/preferences/:eventType', (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Authentication required' });

    const { eventType } = req.params;
    if (!notifications.isKnownEventType(eventType)) {
      return res.status(400).json({ error: `Unknown event type "${eventType}"` });
    }

    const inApp = req.body?.in_app === true || req.body?.in_app === 1;
    const email = req.body?.email === true || req.body?.email === 1;

    notifications.setPreference(userId, eventType, { in_app: inApp, email });
    auditLog(userId, 'NOTIFICATION_PREFERENCE_UPDATED', `event=${eventType} in_app=${inApp} email=${email}`, req.ip);

    res.json({ success: true, eventType, in_app: inApp, email });
  } catch (err) {
    logger.error('Update preference error', { error: err.message });
    res.status(500).json({ error: 'Failed to update preference' });
  }
});

module.exports = router;

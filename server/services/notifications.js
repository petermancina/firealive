// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Notifications Service
//
// Single owner of notification creation, listing, marking-read, and per-user
// per-event-type delivery preferences. All other code paths that need to
// generate a notification (assessments, retro, peer-share, IAM, helper-pay,
// etc.) call notify() here rather than writing to the notifications table
// directly.
//
// notify() handles channel fan-out: it consults the recipient's
// notification_preferences for the event_type and writes one notifications
// row regardless (so the in-app badge always reflects the event), then —
// if the user has email enabled for this event_type — enqueues an email
// delivery via the existing notification_config (the burnout-alerts email
// channel that's already wired through routes/notifications.js).
//
// EVENT TYPES are an explicit allowlist. Adding a new event type means
// adding it to EVENT_TYPES below AND defining a default preference. This
// keeps the notification surface intentional rather than ambient.
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');

// ── Event type registry ──────────────────────────────────────────────────────
// Each event type declares: human-readable label, default in_app, default email,
// and a description that the preferences UI surfaces to users.
const EVENT_TYPES = {
  assessment_assigned: {
    label: 'New assessment assigned to you',
    default: { in_app: 1, email: 0 },
    description: 'A team lead has assigned a skills assessment to you.',
  },
  assessment_completed: {
    label: 'Assessment completed by an analyst',
    default: { in_app: 1, email: 0 },
    description: '(Leads only) An analyst on your team finished an assessment.',
  },
  retro_scheduled: {
    label: 'Post-incident retrospective scheduled',
    default: { in_app: 1, email: 1 },
    description: 'You have been added to a post-incident recovery protocol.',
  },
  retro_followup_sent: {
    label: 'Post-incident recovery check-in',
    default: { in_app: 1, email: 1 },
    description: 'A scheduled check-in (24hr, 72hr, or 2-week mark) for one of your active recovery protocols.',
  },
  peer_request_received: {
    label: 'A peer wants to share with you',
    default: { in_app: 1, email: 0 },
    description: 'Another analyst has requested a peer skill-share session.',
  },
  peer_session_rated: {
    label: 'Your peer session was rated',
    default: { in_app: 1, email: 0 },
    description: 'A seeker rated a peer-share session you helped with.',
  },
  iam_recert_due: {
    label: 'IAM recertification is due',
    default: { in_app: 1, email: 1 },
    description: '(Leads only) One or more analysts need IAM recertification.',
  },
  helper_points_awarded: {
    label: 'Helper Pay points awarded',
    default: { in_app: 1, email: 0 },
    description: 'You earned Helper Pay points for a peer-share session.',
  },
  helper_redemption_approved: {
    label: 'Helper Pay redemption approved',
    default: { in_app: 1, email: 1 },
    description: 'Your Helper Pay redemption request has been approved.',
  },
  helper_redemption_denied: {
    label: 'Helper Pay redemption denied',
    default: { in_app: 1, email: 1 },
    description: 'Your Helper Pay redemption request was denied.',
  },
  delegation_decision: {
    label: 'Automation delegation decision',
    default: { in_app: 1, email: 0 },
    description: 'Your delegation request was accepted or rejected.',
  },
  routing_panic_engaged: {
    label: 'Panic-mode routing engaged',
    default: { in_app: 1, email: 1 },
    description: '(Leads/admins) Panic mode has been engaged on the team.',
  },
};

function isKnownEventType(eventType) {
  return Object.prototype.hasOwnProperty.call(EVENT_TYPES, eventType);
}

// ── Preference resolution ────────────────────────────────────────────────────
// Returns {in_app, email} effective for this user/event combination, falling
// back to EVENT_TYPES[eventType].default when the user has no row.
function resolvePreference(db, userId, eventType) {
  const row = db.prepare(`
    SELECT in_app, email FROM notification_preferences WHERE user_id = ? AND event_type = ?
  `).get(userId, eventType);
  if (row) return { in_app: row.in_app === 1, email: row.email === 1 };
  const fallback = EVENT_TYPES[eventType].default;
  return { in_app: fallback.in_app === 1, email: fallback.email === 1 };
}

// ── Email queue (deferred to a later commit) ─────────────────────────────────
// The email channel uses the existing notification_config row (configured via
// routes/notifications.js — webhook/PagerDuty/email/SMS for burnout alerts).
// For Phase 1.4a commit 2, we record that an email was *requested* but defer
// actual SMTP delivery to commit 4 (email pipeline). Until commit 4 lands,
// email_delivery_status='queued' is the terminal state.
function enqueueEmail(db, notificationId) {
  db.prepare(`
    UPDATE notifications SET email_delivery_status = 'queued' WHERE id = ?
  `).run(notificationId);
}

// ── Public API ───────────────────────────────────────────────────────────────

// Create one notification for one recipient. Returns the notification id.
// Throws if eventType is not a known event type.
function notify({ recipientId, eventType, title, body = null, linkTab = null, linkParams = null }) {
  if (!recipientId || typeof recipientId !== 'string') {
    throw new Error('notify(): recipientId is required');
  }
  if (!isKnownEventType(eventType)) {
    throw new Error(`notify(): unknown event type "${eventType}". Add it to EVENT_TYPES in services/notifications.js if it should exist.`);
  }
  if (!title || typeof title !== 'string') {
    throw new Error('notify(): title is required');
  }

  const db = getDb();
  try {
    const pref = resolvePreference(db, recipientId, eventType);

    const linkParamsJson = linkParams ? JSON.stringify(linkParams) : null;

    const result = db.prepare(`
      INSERT INTO notifications (recipient_id, event_type, title, body, link_tab, link_params, delivered_in_app, delivered_email)
      VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `).run(recipientId, eventType, title, body, linkTab, linkParamsJson, pref.in_app ? 1 : 0);

    const notificationId = db.prepare(`
      SELECT id FROM notifications WHERE rowid = ?
    `).get(result.lastInsertRowid)?.id;

    if (pref.email && notificationId) {
      enqueueEmail(db, notificationId);
    }

    return notificationId;
  } catch (err) {
    logger.error('notify failed', { recipientId, eventType, error: err.message });
    throw err;
  } finally {
    db.close();
  }
}

// Notify many recipients at once. Returns the array of notification ids
// (in the same order as recipientIds). Skips falsy ids silently.
function notifyMany({ recipientIds, eventType, title, body = null, linkTab = null, linkParams = null }) {
  if (!Array.isArray(recipientIds)) {
    throw new Error('notifyMany(): recipientIds must be an array');
  }
  return recipientIds
    .filter(id => typeof id === 'string' && id)
    .map(id => notify({ recipientId: id, eventType, title, body, linkTab, linkParams }));
}

// List notifications for a user. Default: unread, newest first, capped at 100.
// Pass {includeRead: true} to include already-read notifications.
function listForUser(userId, { includeRead = false, limit = 100 } = {}) {
  const db = getDb();
  try {
    const cap = Math.min(Math.max(parseInt(limit, 10) || 100, 1), 500);
    const sql = includeRead
      ? `SELECT id, event_type, title, body, link_tab, link_params, read_at, created_at
         FROM notifications WHERE recipient_id = ? ORDER BY created_at DESC LIMIT ?`
      : `SELECT id, event_type, title, body, link_tab, link_params, read_at, created_at
         FROM notifications WHERE recipient_id = ? AND read_at IS NULL ORDER BY created_at DESC LIMIT ?`;
    const rows = db.prepare(sql).all(userId, cap);
    return rows.map(r => ({
      ...r,
      link_params: r.link_params ? safeJsonParse(r.link_params) : null,
    }));
  } finally {
    db.close();
  }
}

// Count unread notifications for a user (for the badge in the MC/AC).
function unreadCount(userId) {
  const db = getDb();
  try {
    const row = db.prepare(`
      SELECT COUNT(*) AS c FROM notifications WHERE recipient_id = ? AND read_at IS NULL
    `).get(userId);
    return row?.c || 0;
  } finally {
    db.close();
  }
}

// Mark a single notification read. Returns true if it was unread and got marked,
// false if it didn't exist or was already read or didn't belong to this user.
function markRead(userId, notificationId) {
  const db = getDb();
  try {
    const result = db.prepare(`
      UPDATE notifications SET read_at = datetime('now')
      WHERE id = ? AND recipient_id = ? AND read_at IS NULL
    `).run(notificationId, userId);
    return result.changes > 0;
  } finally {
    db.close();
  }
}

// Mark all unread notifications read for a user. Returns the number marked.
function markAllRead(userId) {
  const db = getDb();
  try {
    const result = db.prepare(`
      UPDATE notifications SET read_at = datetime('now')
      WHERE recipient_id = ? AND read_at IS NULL
    `).run(userId);
    return result.changes;
  } finally {
    db.close();
  }
}

// Get all preferences for a user, including defaults for event types they
// haven't customized. Returns an object keyed by event_type.
function getPreferences(userId) {
  const db = getDb();
  try {
    const rows = db.prepare(`
      SELECT event_type, in_app, email FROM notification_preferences WHERE user_id = ?
    `).all(userId);
    const customByType = {};
    for (const r of rows) customByType[r.event_type] = { in_app: r.in_app === 1, email: r.email === 1 };

    const out = {};
    for (const [eventType, meta] of Object.entries(EVENT_TYPES)) {
      out[eventType] = {
        label: meta.label,
        description: meta.description,
        in_app: customByType[eventType]?.in_app ?? meta.default.in_app === 1,
        email: customByType[eventType]?.email ?? meta.default.email === 1,
        is_default: !customByType[eventType],
      };
    }
    return out;
  } finally {
    db.close();
  }
}

// Update one preference. Throws if eventType is unknown.
function setPreference(userId, eventType, { in_app, email }) {
  if (!isKnownEventType(eventType)) {
    throw new Error(`setPreference(): unknown event type "${eventType}"`);
  }
  const db = getDb();
  try {
    db.prepare(`
      INSERT INTO notification_preferences (user_id, event_type, in_app, email)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id, event_type) DO UPDATE
        SET in_app = excluded.in_app, email = excluded.email, updated_at = datetime('now')
    `).run(userId, eventType, in_app ? 1 : 0, email ? 1 : 0);
  } finally {
    db.close();
  }
}

// ── Internal helpers ─────────────────────────────────────────────────────────
function safeJsonParse(s) {
  try { return JSON.parse(s); } catch { return null; }
}

module.exports = {
  EVENT_TYPES,
  isKnownEventType,
  notify,
  notifyMany,
  listForUser,
  unreadCount,
  markRead,
  markAllRead,
  getPreferences,
  setPreference,
};

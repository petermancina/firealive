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
  peer_request_posted: {
    label: 'New peer support request available',
    default: { in_app: 0, email: 0 },
    description: 'An analyst posted a peer support request you are eligible to accept. Default off because volume can be high — opt in if you want to be a fast responder.',
    dailyCap: 5,
  },
  peer_request_accepted: {
    label: 'A peer accepted your support request',
    default: { in_app: 1, email: 0 },
    description: 'Someone has accepted your peer support request. A session is now active.',
  },
  peer_consent_mutual: {
    label: 'Identity revealed in peer session',
    default: { in_app: 1, email: 0 },
    description: 'Both parties consented to reveal identities in your active peer support session.',
  },
  peer_session_timed_out: {
    label: 'Peer session timed out — request re-queued',
    default: { in_app: 1, email: 0 },
    description: 'Your peer support request was accepted but the helper did not show up. Your request has been re-queued for a different helper.',
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
  routing_panic_engaged_manual: {
    label: 'Panic-mode routing engaged (manual)',
    default: { in_app: 1, email: 1 },
    description: 'A team lead has manually engaged panic mode. Wellness routing is OFF and every analyst is at maximum complexity until panic mode is lifted. In-app delivery cannot be turned off for this event.',
    mandatoryInApp: true,
  },
  routing_panic_engaged_tripwire: {
    label: 'Panic-mode routing engaged (tripwire)',
    default: { in_app: 1, email: 1 },
    description: 'The tripwire fired automatically because too many analysts are on reduced routing. Wellness routing is OFF and every analyst is at maximum complexity until the situation is reviewed. In-app delivery cannot be turned off for this event.',
    mandatoryInApp: true,
  },
  routing_panic_lifted: {
    label: 'Panic-mode routing lifted',
    default: { in_app: 1, email: 0 },
    description: 'Panic mode has been lifted. Wellness routing is back on and analysts have returned to their previous complexity caps.',
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

// Return all user IDs who have at least one channel enabled for `eventType`,
// optionally filtered to specific roles. Used by broadcast events:
// peer_request_posted, routing_panic_engaged, iam_recert_due.
//
// Resolution rules:
//   - A user with a row in notification_preferences for this event type uses
//     that row's in_app/email values.
//   - A user with no row uses the EVENT_TYPES[eventType].default values.
//   - "Eligible" = at least one of (in_app, email) is on.
//
// Filters:
//   - opts.roles: array like ['lead', 'admin']. If omitted, all roles are eligible.
//   - opts.activeOnly: defaults true. Restricts to users with active=1 (where
//     the column exists; users.active was added in v0.0.25 — but in this
//     codebase the column is on users.available rather than users.active.
//     We use users.available which is the actual column name in db/init.js.)
//   - opts.excludeUserIds: array of user IDs to exclude (e.g., the requester
//     in a peer-share broadcast, or analysts on the requester's exclude list).
function getEligibleRecipients(eventType, opts = {}) {
  if (!isKnownEventType(eventType)) {
    throw new Error(`getEligibleRecipients(): unknown event type "${eventType}"`);
  }

  const { roles, activeOnly = true, excludeUserIds = [] } = opts;
  const eventDefaults = EVENT_TYPES[eventType].default;

  const db = getDb();
  try {
    // Build user query
    const conditions = [];
    const params = [];
    if (Array.isArray(roles) && roles.length > 0) {
      conditions.push(`role IN (${roles.map(() => '?').join(',')})`);
      params.push(...roles);
    }
    if (activeOnly) conditions.push('available = 1');
    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const users = db.prepare(`SELECT id FROM users ${whereClause}`).all(...params);

    // Pre-fetch all preferences for this event type in one query
    const prefRows = db.prepare(`
      SELECT user_id, in_app, email FROM notification_preferences WHERE event_type = ?
    `).all(eventType);
    const prefByUser = {};
    for (const r of prefRows) prefByUser[r.user_id] = { in_app: r.in_app === 1, email: r.email === 1 };

    const excludeSet = new Set(excludeUserIds);
    const eligible = [];
    for (const u of users) {
      if (excludeSet.has(u.id)) continue;
      const pref = prefByUser[u.id] || { in_app: eventDefaults.in_app === 1, email: eventDefaults.email === 1 };
      if (pref.in_app || pref.email) eligible.push(u.id);
    }
    return eligible;
  } finally {
    db.close();
  }
}

// Return the count of notifications of `eventType` delivered to `userId`
// within the last `windowHours` (default 24). Used by event types with a
// dailyCap to skip recipients who would exceed it.
//
// "Delivered" here means delivered_in_app=1 OR delivered_email=1. Rows
// where neither flag is set don't count — they represent notifications
// the user opted out of, which were created but never surfaced.
function getDailySendCount(userId, eventType, windowHours = 24) {
  if (!isKnownEventType(eventType)) {
    throw new Error(`getDailySendCount(): unknown event type "${eventType}"`);
  }
  const db = getDb();
  try {
    const row = db.prepare(`
      SELECT COUNT(*) AS c
      FROM notifications
      WHERE recipient_id = ?
        AND event_type = ?
        AND (delivered_in_app = 1 OR delivered_email = 1)
        AND created_at > datetime('now', ?)
    `).get(userId, eventType, `-${windowHours} hours`);
    return row?.c || 0;
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
  getEligibleRecipients,
  getDailySendCount,
};

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
    default: { in_app: 1, email: 0, sms: 0, desktop: 1 },
    description: 'A team lead has assigned a skills assessment to you.',
  },
  assessment_completed: {
    label: 'Assessment completed by an analyst',
    default: { in_app: 1, email: 0, sms: 0, desktop: 1 },
    description: '(Leads only) An analyst on your team finished an assessment.',
  },
  retro_scheduled: {
    label: 'Post-incident retrospective scheduled',
    default: { in_app: 1, email: 1, sms: 0, desktop: 1 },
    description: 'You have been added to a post-incident recovery protocol.',
  },
  retro_followup_sent: {
    label: 'Post-incident recovery check-in',
    default: { in_app: 1, email: 1, sms: 0, desktop: 1 },
    description: 'A scheduled check-in (24hr, 72hr, or 2-week mark) for one of your active recovery protocols.',
  },
  peer_request_posted: {
    label: 'New peer support request available',
    default: { in_app: 0, email: 0, sms: 0, desktop: 0 },
    description: 'An analyst posted a peer support request you are eligible to accept. Default off because volume can be high — opt in if you want to be a fast responder.',
    dailyCap: 5,
  },
  peer_request_accepted: {
    label: 'A peer accepted your support request',
    default: { in_app: 1, email: 0, sms: 0, desktop: 1 },
    description: 'Someone has accepted your peer support request. A session is now active.',
  },
  peer_consent_mutual: {
    label: 'Identity revealed in peer session',
    default: { in_app: 1, email: 0, sms: 0, desktop: 1 },
    description: 'Both parties consented to reveal identities in your active peer support session.',
  },
  peer_session_timed_out: {
    label: 'Peer session timed out — request re-queued',
    default: { in_app: 1, email: 0, sms: 0, desktop: 1 },
    description: 'Your peer support request was accepted but the helper did not show up. Your request has been re-queued for a different helper.',
  },
  iam_recert_due: {
    label: 'IAM recertification is due',
    default: { in_app: 1, email: 1, sms: 0, desktop: 1 },
    description: '(Leads only) One or more analysts need IAM recertification.',
  },
  helper_points_awarded: {
    label: 'Helper Pay points awarded',
    default: { in_app: 1, email: 0, sms: 0, desktop: 1 },
    description: 'You earned Helper Pay points for a peer-share session.',
  },
  helper_redemption_approved: {
    label: 'Helper Pay redemption approved',
    default: { in_app: 1, email: 1, sms: 0, desktop: 1 },
    description: 'Your Helper Pay redemption request has been approved.',
  },
  helper_redemption_denied: {
    label: 'Helper Pay redemption denied',
    default: { in_app: 1, email: 1, sms: 0, desktop: 1 },
    description: 'Your Helper Pay redemption request was denied.',
  },
  delegation_decision: {
    label: 'Automation delegation decision',
    default: { in_app: 1, email: 0, sms: 0, desktop: 1 },
    description: 'Your delegation request was accepted or rejected.',
  },
  routing_panic_engaged_manual: {
    label: 'Panic-mode routing engaged (manual)',
    default: { in_app: 1, email: 1, sms: 0, desktop: 1 },
    description: 'A team lead has manually engaged panic mode. Wellness routing is OFF and every analyst is at maximum complexity until panic mode is lifted. In-app delivery cannot be turned off for this event.',
    mandatoryInApp: true,
  },
  routing_panic_engaged_tripwire: {
    label: 'Panic-mode routing engaged (tripwire)',
    default: { in_app: 1, email: 1, sms: 0, desktop: 1 },
    description: 'The tripwire fired automatically because too many analysts are on reduced routing. Wellness routing is OFF and every analyst is at maximum complexity until the situation is reviewed. In-app delivery cannot be turned off for this event.',
    mandatoryInApp: true,
  },
  routing_panic_lifted: {
    label: 'Panic-mode routing lifted',
    default: { in_app: 1, email: 0, sms: 0, desktop: 1 },
    description: 'Panic mode has been lifted. Wellness routing is back on and analysts have returned to their previous complexity caps.',
  },
  peer_abuse_flag_tier1: {
    label: 'Peer chat — minor conduct flag (tier 1)',
    default: { in_app: 1, email: 0, sms: 0, desktop: 1 },
    description: 'An analyst flagged a peer skill-share session for minor conduct issues — curt tone, dismissiveness, condescension, mild rudeness. No identity reveal. Aggregated for pattern detection. If a single peer accumulates many tier-1 flags from different reporters, consider a coaching conversation rather than disciplinary action.',
  },
  peer_abuse_flag_tier2: {
    label: 'Peer chat — personal attack flag (tier 2)',
    default: { in_app: 1, email: 1, sms: 0, desktop: 1 },
    description: 'An analyst flagged a peer skill-share session for direct insult, name-calling, mockery, or demeaning language. Per the peer-chat policy, the flagged peer\'s identity is revealed to you. Flagged content is retained in the secure vault for review. No automatic HR loop — your judgment on next steps.',
  },
  peer_abuse_flag_tier3: {
    label: 'Peer chat — urgent conduct flag (tier 3)',
    default: { in_app: 1, email: 1, sms: 0, desktop: 1 },
    description: 'An analyst flagged a peer skill-share session for urgent conduct: slurs, explicit threats, sexual harassment, or content suggesting imminent harm. Both the flagged peer\'s identity and the flagger\'s identity are revealed to you. HR intervention is recommended. In-app delivery cannot be turned off for this event.',
    mandatoryInApp: true,
  },
};

function isKnownEventType(eventType) {
  return Object.prototype.hasOwnProperty.call(EVENT_TYPES, eventType);
}

// ── Anonymity-preservation role check ────────────────────────────────────────
// N1a C7: Returns true if the role is a non-anonymous role (lead, admin,
// developer) and therefore eligible for the email + sms notification channels.
// Returns false for analyst-role users (anonymity-protected — only in_app +
// desktop channels are available) and for any unknown role (safe default —
// treat as anonymity-protected if the user lookup fails).
//
// This is the single source of truth for the channel-availability policy
// across resolvePreference(), setPreference(), and getEligibleRecipients().
// The same check is also applied by the route handlers at PUT
// /api/users/me/lead-contacts (ANALYST_CONTACT_STORAGE_BLOCKED, HTTP 403)
// and PUT /api/inbox/preferences/:eventType (ANALYST_CHANNEL_RESTRICTED,
// HTTP 422) — those route handlers will ship in N1a C19 + C21.
//
// Three-layer defense for analyst anonymity:
//   (a) UI layer — AC preference UI hides email + SMS checkboxes (N1a C16)
//   (b) API layer — route handlers reject analyst-role callers (N1a C19, C21)
//   (c) Dispatch layer — this function gates resolvePreference() +
//       getEligibleRecipients() so the dispatch path never honors email/sms
//       for analyst users regardless of stored notification_preferences
//       values (defense against DB tampering, legacy data, or API bypass)
function isContactSafeRole(role) {
  return role === 'lead' || role === 'admin' || role === 'developer';
}

// ── Preference resolution ────────────────────────────────────────────────────
// Returns {in_app, email, sms, desktop} effective for this user/event
// combination, falling back to EVENT_TYPES[eventType].default when the user
// has no row. Applies N1a C7 anonymity-preservation gating: email + sms are
// forced to false for analyst-role users regardless of stored values.
function resolvePreference(db, userId, eventType, opts = {}) {
  // N1a: Reads all 4 channel columns (in_app, email, sms, desktop). The sms +
  // desktop columns were added by the N1a migration in db/init.js. Existing
  // rows had those columns auto-defaulted at ALTER TIME (sms=0, desktop=1).
  // Downstream notify() uses these to decide which channels to enqueue per
  // notification.
  //
  // N1a C7: After computing the 4-channel pref object, applies anonymity-
  // preservation gating — analyst-role users get email + sms forced to false
  // regardless of stored values. Role can be passed via opts.role to avoid the
  // extra SELECT (caller already has it); otherwise looked up using the
  // provided db connection.
  const row = db.prepare(`
    SELECT in_app, email, sms, desktop FROM notification_preferences WHERE user_id = ? AND event_type = ?
  `).get(userId, eventType);
  let pref;
  if (row) {
    pref = {
      in_app: row.in_app === 1,
      email: row.email === 1,
      sms: row.sms === 1,
      desktop: row.desktop === 1,
    };
  } else {
    const fallback = EVENT_TYPES[eventType].default;
    pref = {
      in_app: fallback.in_app === 1,
      email: fallback.email === 1,
      // sms + desktop defaults may be undefined on older event-type defs (defensive
      // fallback: sms off, desktop on — matches the catalog policy for events
      // that don't override).
      sms: (fallback.sms ?? 0) === 1,
      desktop: (fallback.desktop ?? 1) === 1,
    };
  }

  // N1a C7: ANALYST ANONYMITY ENFORCEMENT (dispatch-layer defense)
  // Look up role if not provided. Unknown role → treat as anonymity-protected
  // (safer default for unknown user). isContactSafeRole() returns false unless
  // role is lead/admin/developer.
  let role = opts.role;
  if (role === undefined) {
    const userRow = db.prepare('SELECT role FROM users WHERE id = ?').get(userId);
    role = userRow ? userRow.role : undefined;
  }
  if (!isContactSafeRole(role)) {
    // Defense-in-depth: zero email + sms regardless of stored value. If any
    // analyst row has email=1 or sms=1 (DB tampering, legacy pre-N1a data, or
    // a future bug bypassing API enforcement), this dispatch-layer check
    // catches it before any identity-exposing channel fires. Log when we
    // actually CHANGE a value — silent no-op when stored values were already
    // 0/0 (the normal case for analyst users post-C7).
    if (pref.email || pref.sms) {
      logger.warn(
        `resolvePreference(): analyst-role user ${userId} has stored email=${pref.email} sms=${pref.sms} for event ${eventType} — forcing both to false (N1a C7 anonymity enforcement). Investigate stored-value source: stale pre-C7 data, DB tampering, or API bypass.`
      );
    }
    pref.email = false;
    pref.sms = false;
  }
  return pref;
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
    // N1a C16: Read all 4 channel columns (the sms + desktop columns were
    // added by the N1a C1 init.js migration).
    const rows = db.prepare(`
      SELECT event_type, in_app, email, sms, desktop FROM notification_preferences WHERE user_id = ?
    `).all(userId);
    const customByType = {};
    for (const r of rows) {
      customByType[r.event_type] = {
        in_app: r.in_app === 1,
        email: r.email === 1,
        sms: r.sms === 1,
        desktop: r.desktop === 1,
      };
    }

    // N1a C16: ANALYST ANONYMITY ENFORCEMENT (mirror of C7 resolvePreference
    // gating, applied at the read path too). Look up role once; if not contact-
    // safe, force email + sms to false in every event's returned pref. The UI
    // will render whatever it gets — gating here ensures analyst clients never
    // see stored email=true / sms=true values that could mislead them about
    // their actual channel availability.
    const userRow = db.prepare('SELECT role FROM users WHERE id = ?').get(userId);
    const role = userRow ? userRow.role : undefined;
    const contactSafe = isContactSafeRole(role);

    const out = {};
    for (const [eventType, meta] of Object.entries(EVENT_TYPES)) {
      const stored = customByType[eventType];
      let prefInApp = stored?.in_app ?? meta.default.in_app === 1;
      let prefEmail = stored?.email ?? meta.default.email === 1;
      let prefSms = stored?.sms ?? (meta.default.sms ?? 0) === 1;
      let prefDesktop = stored?.desktop ?? (meta.default.desktop ?? 1) === 1;
      if (!contactSafe) {
        prefEmail = false;
        prefSms = false;
      }
      out[eventType] = {
        label: meta.label,
        description: meta.description,
        in_app: prefInApp,
        email: prefEmail,
        sms: prefSms,
        desktop: prefDesktop,
        mandatory_in_app: !!meta.mandatoryInApp,
        is_default: !stored,
      };
    }
    return out;
  } finally {
    db.close();
  }
}

// Update one preference. Throws if eventType is unknown.
function setPreference(userId, eventType, { in_app, email, sms, desktop }) {
  if (!isKnownEventType(eventType)) {
    throw new Error(`setPreference(): unknown event type "${eventType}"`);
  }
  // Refuse to disable in_app for events flagged mandatoryInApp.
  // These are critical events (panic mode, tripwire, tier-3 abuse) where every
  // analyst MUST see the in-app notification regardless of preference. The
  // user can still opt out of email + sms + desktop for these events — only
  // in_app is enforced.
  if (EVENT_TYPES[eventType].mandatoryInApp && !in_app) {
    throw new Error(`setPreference(): in_app delivery cannot be disabled for "${eventType}" — this event is mandatory in-app for all users`);
  }
  // N1a: persist all 4 channels. UPSERT updates all 4 columns whenever the
  // user touches preferences via the UI. Each channel is independent — the
  // user can mix in_app + desktop for one event, email + sms for another.
  const db = getDb();
  try {
    // N1a C7: ANALYST ANONYMITY ENFORCEMENT (API-layer defense)
    // Look up the caller's role to enforce the channel-availability policy.
    // Analyst-role users cannot persist email=1 or sms=1 — these channels
    // require identity-exposing contact storage (lead_notification_contacts
    // table) that is structurally restricted to non-anonymous roles.
    // The route handler at PUT /api/inbox/preferences/:eventType catches this
    // throw and converts to HTTP 422 + body {code: 'ANALYST_CHANNEL_RESTRICTED'}
    // (will ship in N1a C19). Audit event MC_ANALYST_CHANNEL_RESTRICTION_ENFORCED
    // is emitted by the route handler on the throw.
    const userRow = db.prepare('SELECT role FROM users WHERE id = ?').get(userId);
    const role = userRow ? userRow.role : undefined;
    if (!isContactSafeRole(role) && (email || sms)) {
      const err = new Error(
        `setPreference(): email and sms channels are not available for analyst-role users — these channels are restricted to lead/admin/developer roles to preserve analyst anonymity`
      );
      err.code = 'ANALYST_CHANNEL_RESTRICTED';
      throw err;
    }
    db.prepare(`
      INSERT INTO notification_preferences (user_id, event_type, in_app, email, sms, desktop)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, event_type) DO UPDATE
        SET in_app = excluded.in_app,
            email = excluded.email,
            sms = excluded.sms,
            desktop = excluded.desktop,
            updated_at = datetime('now')
    `).run(userId, eventType, in_app ? 1 : 0, email ? 1 : 0, sms ? 1 : 0, desktop ? 1 : 0);
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
    // N1a C7: SELECT extended to include role for anonymity-preservation gating.
    // The role column is read alongside id so we can apply per-recipient
    // channel-availability policy without an N+1 query.
    const users = db.prepare(`SELECT id, role FROM users ${whereClause}`).all(...params);

    // Pre-fetch all preferences for this event type in one query.
    // N1a: SELECT extended to include sms + desktop columns alongside in_app + email.
    const prefRows = db.prepare(`
      SELECT user_id, in_app, email, sms, desktop FROM notification_preferences WHERE event_type = ?
    `).all(eventType);
    const prefByUser = {};
    for (const r of prefRows) {
      prefByUser[r.user_id] = {
        in_app: r.in_app === 1,
        email: r.email === 1,
        sms: r.sms === 1,
        desktop: r.desktop === 1,
      };
    }

    const excludeSet = new Set(excludeUserIds);
    const isMandatoryInApp = !!EVENT_TYPES[eventType].mandatoryInApp;
    const eligible = [];
    for (const u of users) {
      if (excludeSet.has(u.id)) continue;
      // For mandatoryInApp events, every matching user is eligible regardless
      // of their stored preference — these events (panic, tripwire, tier-3
      // abuse) cannot be silenced in-app. For all other events, the user must
      // have at least one channel turned on.
      if (isMandatoryInApp) { eligible.push(u.id); continue; }
      // N1a: fallback considers all 4 channel defaults from the event-type catalog.
      // Defensive ?? handling for events that haven't been extended with sms +
      // desktop defaults yet (shouldn't happen at v1.0.41 post-C2 but keeps the
      // fallback safe for any older test fixtures).
      const pref = prefByUser[u.id] || {
        in_app: eventDefaults.in_app === 1,
        email: eventDefaults.email === 1,
        sms: (eventDefaults.sms ?? 0) === 1,
        desktop: (eventDefaults.desktop ?? 1) === 1,
      };
      // N1a C7: ANALYST ANONYMITY ENFORCEMENT (dispatch-layer defense)
      // For non-contact-safe roles (analysts + unknown roles), the eligibility
      // check ignores the email + sms channels — only in_app + desktop are
      // honored. Defense-in-depth: even if prefByUser[u.id] somehow has
      // email=true or sms=true for an analyst (legacy data, DB tampering, or
      // race condition with C7 deployment), the eligibility OR-check below
      // won't count those channels toward inclusion in the recipient list.
      const channelsAvailable = isContactSafeRole(u.role)
        ? (pref.in_app || pref.email || pref.sms || pref.desktop)
        : (pref.in_app || pref.desktop);
      if (channelsAvailable) eligible.push(u.id);
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

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Notifications Desktop-Channel Pipeline
//
// Pushes notifications to Electron clients via the existing WebSocket server.
// Desktop dispatch is purely PUSH-BASED at v1.0.41 — there is no polling queue.
// The processDesktopQueue() entrypoint exists for API symmetry with the email +
// SMS pipelines but is a no-op stub.
//
// Per-notification dispatch happens via sendDesktopToUser(userId, payload),
// called synchronously by enqueueDesktop() in notifications.js (will ship in
// N1a C24). Sibling to notifications-pipeline.js (email/webhook/PagerDuty) and
// notifications-sms.js (Twilio/AWS SNS).
//
// ROLE POLICY:
//   Desktop notifications are available to ALL user roles, INCLUDING analysts.
//   The OS notification is rendered LOCALLY on the user's machine via Electron's
//   native Notification API — no identity-exposing data is stored server-side
//   and nothing leaves the user's own device. Therefore desktop notifications
//   do NOT trigger the anonymity-preservation gating that applies to email +
//   sms channels (N1a C7). The only role check in this file is defensive:
//   skip if the user record does not exist in the users table.
//
// CONNECTIVITY MODEL:
//   - User's Electron client connects to the WebSocket server at login
//     (handled by websocket-server.js — existing pre-N1a code)
//   - N1a C11 will add the wsServer.sendDesktopNotification(userId, payload)
//     method to the FireAliveWebSocket class
//   - sendDesktopToUser() (this file) lazy-requires the WebSocket server
//     singleton and calls the new method
//   - If the user's WebSocket is not connected (offline, network issue,
//     client closed), the dispatch is skipped with status='skipped' and
//     audit event NOTIFICATION_DESKTOP_SKIPPED_USER_OFFLINE; the in-app
//     notification remains as the fallback (in_app channel is independent
//     and writes directly to the notifications table at notify() time)
//
// AUDIT LOGGING:
//   - Every dispatch attempt writes a notification_delivery_log row (N1a C1
//     schema) with status='sent', 'skipped', or 'failed'
//   - recipient_handle_hash is left NULL for desktop — the userId itself is
//     the audit join key, and there is no PII handle (phone/email) to hash
//   - Audit events:
//       NOTIFICATION_DESKTOP_SKIPPED_USER_OFFLINE — WS not connected
//       NOTIFICATION_DESKTOP_FAILED              — WS send threw an exception
//
// LAZY-REQUIRE OF websocket-server:
//   Required inside getWsServer() rather than at module top to (a) avoid any
//   circular-import risk against websocket-server.js, which may reference
//   notification state during connection setup, and (b) allow this file to
//   load before N1a C11 ships the sendDesktopNotification method. Until C11
//   ships, sendDesktopToUser() is not called by anything — C24 is what wires
//   it into notify() via the new enqueueDesktop() helper.
//
// FUTURE ENHANCEMENT:
//   processDesktopQueue() could be extended to poll desktop_delivery_status=
//   'queued' rows and retry them when the user reconnects (today they get
//   skipped permanently if offline at the moment of dispatch). Not in scope
//   for v1.0.41 — the in-app inbox is the offline fallback. The decision to
//   keep this a no-op stub avoids growing scheduler.js with a cron job that
//   would do nothing useful, and keeps the contract surface minimal.
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');

const PIPELINE_VERSION = 1;

// ── Recipient lookup (defensive) ─────────────────────────────────────────────
function lookupRecipient(db, userId) {
  return db.prepare("SELECT id, role FROM users WHERE id = ?").get(userId);
}

// ── notification_delivery_log writer ─────────────────────────────────────────
// Best-effort write to the per-attempt audit table (N1a C1 schema). Mirror of
// the helper in notifications-sms.js; kept local to avoid cross-pipeline
// coupling. Write failures (DB lock contention, etc.) are logged but do not
// block dispatch — best-effort audit per the C1 design.
function recordDeliveryAttempt(db, params) {
  try {
    db.prepare(`
      INSERT INTO notification_delivery_log (
        notification_id, channel, attempt_number, status,
        transport_provider, transport_message_id, recipient_handle_hash,
        error_message, latency_ms, completed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      params.notificationId,
      params.channel,
      params.attemptNumber || 1,
      params.status,
      params.transportProvider || null,
      params.transportMessageId || null,
      params.recipientHandleHash || null,
      params.errorMessage || null,
      params.latencyMs != null ? params.latencyMs : null
    );
  } catch (err) {
    logger.warn('Desktop pipeline: failed to write notification_delivery_log row', {
      notificationId: params.notificationId,
      error: err.message,
    });
  }
}

// ── WebSocket server lazy-require ────────────────────────────────────────────
// Lazy-required to avoid circular-import risk and to allow this file to load
// safely before C11 ships the sendDesktopNotification method. Returns null if
// the module is not loadable for any reason (importing layer can decide how
// to handle that — sendDesktopToUser treats it as a skip).
function getWsServer() {
  try {
    return require('./websocket-server');
  } catch (err) {
    logger.warn('Desktop pipeline: websocket-server module not loadable', {
      error: err.message,
    });
    return null;
  }
}

// ── Dispatch entrypoint (synchronous push) ───────────────────────────────────
// Called by enqueueDesktop() in notifications.js (will ship in N1a C24). The
// payload should include at least:
//   { notificationId, title, body, eventType, linkTab, linkParams }
// so the Electron client can render the native OS notification with the right
// metadata + deep-link target.
//
// Returns:
//   { sent: true }
//   { sent: false, reason: 'user_not_found' | 'ws_method_unavailable'
//                          | 'user_offline' | 'ws_send_threw',
//     error?: string }
function sendDesktopToUser(userId, payload) {
  const notificationId = payload && payload.notificationId;
  if (!notificationId) {
    logger.warn('Desktop pipeline: sendDesktopToUser called without payload.notificationId');
    return { sent: false, reason: 'missing_notificationId' };
  }

  const db = getDb();
  const updateStatus = db.prepare(
    `UPDATE notifications SET desktop_delivery_status = ? WHERE id = ?`
  );
  const t0 = Date.now();

  try {
    // Defensive role lookup: skip if user record does not exist. Desktop is
    // available to ALL roles (including analysts) so no anonymity gating —
    // the OS notification is rendered locally on the user's own machine.
    const user = lookupRecipient(db, userId);
    if (!user) {
      updateStatus.run('skipped', notificationId);
      recordDeliveryAttempt(db, {
        notificationId,
        channel: 'desktop',
        status: 'skipped',
        errorMessage: 'recipient_user_not_found',
        attemptNumber: 1,
        latencyMs: Date.now() - t0,
      });
      logger.warn('Desktop pipeline: recipient user not found', { notificationId, userId });
      return { sent: false, reason: 'user_not_found' };
    }

    const wsServer = getWsServer();
    if (!wsServer || typeof wsServer.sendDesktopNotification !== 'function') {
      // C11 hasn't shipped yet, or the WS server exports differently. Skip +
      // log. Should never fire at v1.0.41 post-C11.
      updateStatus.run('skipped', notificationId);
      recordDeliveryAttempt(db, {
        notificationId,
        channel: 'desktop',
        status: 'skipped',
        errorMessage: 'ws_server_sendDesktopNotification_not_available',
        attemptNumber: 1,
        latencyMs: Date.now() - t0,
      });
      logger.warn('Desktop pipeline: wsServer.sendDesktopNotification not available (C11 may not have shipped)', {
        notificationId,
        userId,
      });
      return { sent: false, reason: 'ws_method_unavailable' };
    }

    let result;
    try {
      result = wsServer.sendDesktopNotification(userId, payload);
    } catch (err) {
      updateStatus.run('failed', notificationId);
      recordDeliveryAttempt(db, {
        notificationId,
        channel: 'desktop',
        status: 'failed',
        errorMessage: err.message,
        attemptNumber: 1,
        latencyMs: Date.now() - t0,
      });
      auditLog(null, 'NOTIFICATION_DESKTOP_FAILED',
        `id=${notificationId} userId=${userId} error=${err.message}`, null);
      logger.warn('Desktop pipeline: WS send threw', {
        notificationId,
        userId,
        error: err.message,
      });
      return { sent: false, reason: 'ws_send_threw', error: err.message };
    }

    const latencyMs = Date.now() - t0;
    if (result && result.sent) {
      updateStatus.run('sent', notificationId);
      recordDeliveryAttempt(db, {
        notificationId,
        channel: 'desktop',
        status: 'sent',
        transportProvider: 'websocket',
        attemptNumber: 1,
        latencyMs,
      });
      return { sent: true };
    }

    // result.sent === false → user not connected at this moment (offline,
    // logged out, network blip). Skip + audit. In-app channel is the
    // offline fallback — the notification is still visible in the inbox.
    updateStatus.run('skipped', notificationId);
    recordDeliveryAttempt(db, {
      notificationId,
      channel: 'desktop',
      status: 'skipped',
      errorMessage: (result && result.reason) || 'user_offline',
      attemptNumber: 1,
      latencyMs,
    });
    auditLog(null, 'NOTIFICATION_DESKTOP_SKIPPED_USER_OFFLINE',
      `id=${notificationId} userId=${userId} reason=${(result && result.reason) || 'user_offline'}`, null);
    return { sent: false, reason: (result && result.reason) || 'user_offline' };
  } finally {
    db.close();
  }
}

// ── Pipeline entrypoint (no-op stub) ─────────────────────────────────────────
// Desktop dispatch is purely push-based at v1.0.41 — there is no polling queue.
// processDesktopQueue() exists for API symmetry with notifications-pipeline.js
// (email) and notifications-sms.js. The scheduler does NOT call this function —
// N1a C10 adds only the SMS pipeline cron job. The function is exported here
// for forward compatibility if a future enhancement adds a retry-on-reconnect
// queue.
async function processDesktopQueue() {
  logger.debug('Desktop pipeline: processDesktopQueue() is a no-op stub at v1.0.41; dispatch is push-based via sendDesktopToUser()');
  return { processed: 0, sent: 0, failed: 0, bounced: 0, skipped: 0 };
}

module.exports = {
  processDesktopQueue,
  sendDesktopToUser,
  PIPELINE_VERSION,
};

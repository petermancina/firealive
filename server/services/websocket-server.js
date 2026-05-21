// FireAlive v1.0.0 — WebSocket Server
// Real-time: routing feed, peer chat, client heartbeat, notifications, signal updates
const WebSocket = require('ws');
const crypto = require('crypto');

// N1a C11: Module-level singleton reference. The FireAliveWebSocket constructor
// captures `this` here so that other modules (notably notifications-desktop.js
// for sendDesktopNotification dispatch) can reach the instance via require
// without going through Express app.locals. The instance is constructed once
// at server boot in index.js; if no instance has been constructed yet, the
// forwarder at the bottom of this file returns a safe { sent: false } result.
let _instance = null;

class FireAliveWebSocket {
  constructor(server, db) {
    this.db = db;
    this.clients = new Map(); // userId -> ws
    this.wss = new WebSocket.Server({ server, path: '/ws' });
    this.wss.on('connection', (ws, req) => this._onConnection(ws, req));
    // Signal collection every 15 minutes
    this._signalInterval = setInterval(() => this._collectSignals(), 900000);
    // SIEM push every 60 seconds
    this._siemInterval = setInterval(() => this._pushToSiem(), 60000);
    // N1a C11: Capture the singleton reference so the module-level forwarder
    // (used by notifications-desktop.js) can reach this instance.
    _instance = this;
  }

  _onConnection(ws, req) {
    ws.isAlive = true;
    ws.userId = null;
    ws.on('pong', () => { ws.isAlive = true; });
    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data);
        this._handleMessage(ws, msg);
      } catch {}
    });
    ws.on('close', () => {
      if (ws.userId) {
        this.clients.delete(ws.userId);
        this._updateHeartbeat(ws.userId, false);
      }
    });
  }

  _handleMessage(ws, msg) {
    switch (msg.type) {
      case 'auth':
        // JWT verification — reject connections that don't present a
        // valid, non-expired token. The client-supplied msg.userId
        // is intentionally ignored; ws.userId is set from the verified
        // token payload so a spoofed userId cannot be substituted.
        if (!msg.token || typeof msg.token !== 'string') {
          this._send(ws, { type: 'auth_error', error: 'Token required' });
          ws.close(1008, 'auth required');
          return;
        }
        try {
          const { verifyToken } = require('../middleware/auth');
          const decoded = verifyToken(msg.token);
          ws.userId = decoded.id;
          ws.userRole = decoded.role;
          this.clients.set(decoded.id, ws);
          this._updateHeartbeat(decoded.id, true);
          this._send(ws, { type: 'auth_ok', userId: decoded.id });
        } catch (err) {
          const code = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
          this._send(ws, { type: 'auth_error', error: err.message, code });
          ws.close(1008, 'auth failed');
          return;
        }
        break;
      case 'heartbeat':
        ws.isAlive = true;
        this._updateHeartbeat(ws.userId, true);
        this._send(ws, { type: 'heartbeat_ack' });
        break;
      case 'peer_message':
        // E2EE — message is already encrypted, just relay
        const target = this.clients.get(msg.targetId);
        if (target && target.readyState === WebSocket.OPEN) {
          this._send(target, { type: 'peer_message', from: ws.userId, encrypted: msg.encrypted, nonce: msg.nonce });
        }
        break;
      case 'signal_reading':
        // Record burnout signal from AC
        const { AiBurnoutEngine } = require('./ai-burnout-engine');
        new AiBurnoutEngine(this.db).recordSignal(ws.userId, msg.signal, msg.value);
        break;
      case 'subscribe_routing':
        ws.subscribeRouting = true;
        break;
      case 'subscribe_notifications':
        ws.subscribeNotifications = true;
        break;
    }
  }

  // Broadcast routing event to all subscribed MCs
  broadcastRouting(event) {
    this.clients.forEach((ws) => {
      if (ws.subscribeRouting && ws.readyState === WebSocket.OPEN) {
        this._send(ws, { type: 'routing_event', ...event });
      }
    });
  }

  // Send notification to specific user
  sendNotification(userId, notification) {
    const ws = this.clients.get(userId);
    if (ws && ws.readyState === WebSocket.OPEN) {
      this._send(ws, { type: 'notification', ...notification });
    }
  }

  // N1a C11: Send a desktop-channel push to a specific user. Used by
  // notifications-desktop.js sendDesktopToUser() (which itself is called
  // synchronously by notifications.js enqueueDesktop() — shipping in N1a C24).
  //
  // Returns { sent: true } if the user's Electron client is currently connected
  // and the WebSocket message was queued for send. Returns { sent: false,
  // reason: 'user_not_connected' } if the user is offline / never logged in /
  // disconnected. The caller in notifications-desktop.js writes the result to
  // notifications.desktop_delivery_status + notification_delivery_log.
  //
  // Wire format: { type: 'desktop_notify', payload }. The Electron renderer
  // (AC analyst-client.jsx + MC firealive-mc.jsx, listeners landing in N1a
  // C25 + C26) recognizes msg.type === 'desktop_notify' and forwards msg.payload
  // to the Electron main process via IPC channel 'notify:desktop' (preload
  // whitelist update in C12 + C13; main.js handlers in C14 + C15). The main
  // process then creates a native OS Notification via Electron's Notification
  // API.
  //
  // Role policy: desktop is available to ALL roles (including analysts) —
  // the OS notification is rendered locally on the user's machine, so no
  // identity-exposing data flows server-side. The role check at the dispatch
  // layer (notifications-desktop.js sendDesktopToUser) is purely defensive
  // (skip if user record doesn't exist in users table).
  sendDesktopNotification(userId, payload) {
    const ws = this.clients.get(userId);
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return { sent: false, reason: 'user_not_connected' };
    }
    this._send(ws, { type: 'desktop_notify', payload });
    return { sent: true };
  }

  // Broadcast signal update to MC
  broadcastSignalUpdate(analystId, signals) {
    this.clients.forEach((ws) => {
      if (ws.subscribeRouting && ws.readyState === WebSocket.OPEN) {
        this._send(ws, { type: 'signal_update', analystId, signals });
      }
    });
  }

  _send(ws, data) {
    try { ws.send(JSON.stringify(data)); } catch {}
  }

  _updateHeartbeat(userId, connected) {
    try {
      this.db.prepare("UPDATE users SET last_heartbeat = ?, active = ? WHERE id = ?").run(new Date().toISOString(), connected ? 1 : 0, userId);
    } catch {}
  }

  async _collectSignals() {
    try {
      const { SignalCollector } = require('./signal-collector');
      const collector = new SignalCollector(this.db);
      const result = await collector.collectAll();
      // Broadcast updates to MC
      const { AiBurnoutEngine } = require('./ai-burnout-engine');
      const engine = new AiBurnoutEngine(this.db);
      const analysts = this.db.prepare("SELECT id FROM users WHERE role='analyst' AND active=1").all();
      for (const a of analysts) {
        const signals = engine.getSignals(a.id);
        this.broadcastSignalUpdate(a.id, signals);
      }
    } catch (e) { console.error('[WS] Signal collection error:', e.message); }
  }

  async _pushToSiem() {
    try {
      const siemConfig = this.db.prepare("SELECT value FROM config WHERE key='siem_config'").get();
      if (!siemConfig) return;
      const config = JSON.parse(siemConfig.value);
      const { SiemAdapter } = require('../integrations/siem-adapter');
      const siem = new SiemAdapter(config.endpoint, 'tls');
      const { MetricsCollector } = require('./metrics-collector');
      const metrics = new MetricsCollector(this.db).collect();
      await siem.sendCEF(metrics);
    } catch (e) { console.error('[WS] SIEM push error:', e.message); }
  }

  // Heartbeat check — disconnect stale clients
  startHeartbeatCheck() {
    setInterval(() => {
      this.wss.clients.forEach((ws) => {
        if (!ws.isAlive) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
      });
    }, 30000);
  }

  shutdown() {
    clearInterval(this._signalInterval);
    clearInterval(this._siemInterval);
    this.wss.close();
  }
}

// N1a C11: Module-level forwarder so notifications-desktop.js can call
// `require('./websocket-server').sendDesktopNotification(userId, payload)`
// without needing access to the Express app.locals.wsServer reference. If the
// FireAliveWebSocket constructor has not yet been invoked (server is booting,
// or this file was loaded in a non-server context like a unit test), the
// forwarder returns a safe { sent: false, reason: 'ws_server_not_initialized' }
// result that notifications-desktop.js treats as a skip with audit log entry.
function sendDesktopNotification(userId, payload) {
  if (!_instance) {
    return { sent: false, reason: 'ws_server_not_initialized' };
  }
  return _instance.sendDesktopNotification(userId, payload);
}

module.exports = { FireAliveWebSocket, sendDesktopNotification };

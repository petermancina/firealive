// FireAlive v1.0.0 — WebSocket Server
// Real-time: routing feed, peer chat, client heartbeat, notifications, signal updates
const WebSocket = require('ws');
const crypto = require('crypto');

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
        // Validate JWT token
        ws.userId = msg.userId;
        this.clients.set(msg.userId, ws);
        this._updateHeartbeat(msg.userId, true);
        this._send(ws, { type: 'auth_ok' });
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

module.exports = { FireAliveWebSocket };

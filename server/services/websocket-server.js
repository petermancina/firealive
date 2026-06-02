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
    // Defense-in-depth limits aligned to FireAlive's actual WS traffic shape
    // (peer-chat libsignal envelopes, signal readings, notifications, routing
    // events -- all small JSON, realistic ceiling ~10 KiB per frame, no
    // fragmentation in normal operation). The ws 8.21.0 security patch
    // (remote memory-exhaustion DoS via tiny-fragment flooding,
    // CVE-class library-side fix) is already in place at the library-defaults
    // level; setting these options explicitly makes the security posture
    // readable, documents the calibration against known traffic, and
    // survives any future relaxation of library defaults.
    //
    // Calibration vs library defaults (per ws docs, master branch):
    //   maxPayload:        64 KiB    (default 100 MiB)        -- ~1600x tighter
    //   maxBufferedChunks: 256       (default 1,048,576)      -- ~4096x tighter
    //   maxFragments:      1024      (default 131,072)        -- ~128x tighter
    // FireAlive does not legitimately fragment messages or queue large chunk
    // backlogs; pathological values from a peer indicate an attack.
    this.wss = new WebSocket.Server({
      server,
      path: '/ws',
      maxPayload: 65536,
      maxBufferedChunks: 256,
      maxFragments: 1024,
    });
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
          // B4: deliver any compromise-scan commands queued while offline.
          this._deliverQueuedScans(ws, decoded.id);
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
      case 'scan_result': {
        // B4: ingest a device-signed compromise self-scan report from an AC.
        this._ingestScanResult(ws, msg);
        break;
      }
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

  // U1: notify every connected client that the feature-toggle state changed,
  // so the console and analyst clients grey or restore features live without a
  // reload. Sent to all authenticated clients (toggles affect everyone),
  // independent of routing subscription.
  broadcastFeatureToggles(features) {
    this.clients.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN) {
        this._send(ws, { type: 'feature_toggles_updated', features });
      }
    });
  }

  // ── B4: Compromise scan orchestration over the WebSocket channel ─────────
  // Fan out an orchestrate_scan command to the connected target ACs. Offline
  // targets are handled by the route (queued) and delivered on reconnect via
  // _deliverQueuedScans below.
  dispatchCompromiseScan(runId, userIds, opts = {}) {
    const manifest = opts.manifest || null;
    const expectedConfig = opts.expectedConfig || null;
    for (const userId of userIds) {
      const ws = this.clients.get(userId);
      if (ws && ws.readyState === WebSocket.OPEN) {
        this._send(ws, { type: 'orchestrate_scan', runId, manifest, expectedConfig });
      }
    }
  }

  // Deliver scan commands queued while an AC was offline (called after auth).
  // Stale (expired) queue entries are closed out; live ones are dispatched and
  // marked delivered. The original run's manifest/config are not replayed here.
  _deliverQueuedScans(ws, userId) {
    try {
      const now = new Date().toISOString();
      this.db.prepare("UPDATE compromise_scan_queue SET status = 'expired' WHERE user_id = ? AND status = 'queued' AND expires_at <= ?").run(userId, now);
      const pending = this.db.prepare("SELECT id, run_id FROM compromise_scan_queue WHERE user_id = ? AND status = 'queued' AND expires_at > ?").all(userId, now);
      for (const q of pending) {
        this._send(ws, { type: 'orchestrate_scan', runId: q.run_id, manifest: null, expectedConfig: null });
        this.db.prepare("UPDATE compromise_scan_queue SET status = 'delivered', delivered_at = ? WHERE id = ?").run(now, q.id);
      }
    } catch (e) { try { console.error('[WS] queued-scan delivery error:', e.message); } catch {} }
  }

  // Canonical bytes the AC device key signed. MUST match the analyst-client
  // main-process canonicalScanString exactly (fixed field order).
  _canonicalScan(r) {
    return [
      r.runId || '',
      r.scan_started_at,
      String(r.scan_duration_ms),
      r.status,
      String(r.tests_total),
      String(r.tests_passed),
      String(r.tests_failed),
      String(r.tests_inconclusive),
      r.details_json,
    ].join('\n');
  }

  // Ingest a signed scan report: verify the device signature against the
  // registered public key, store the (verified-or-not) result, advance run
  // completion, close out the delivery queue, and push progress to leads.
  _ingestScanResult(ws, msg) {
    try {
      if (!ws.userId) return;
      const result = msg && msg.result;
      if (!result || typeof result !== 'object' || typeof result.details_json !== 'string') return;
      if (!['clean', 'warning', 'fail', 'inconclusive'].includes(result.status)) return;

      let verified = false;
      const keyRow = this.db.prepare("SELECT public_key FROM ac_device_signing_keys WHERE user_id = ? AND active = 1").get(ws.userId);
      if (keyRow && result.signature) {
        try {
          const pub = crypto.createPublicKey(keyRow.public_key);
          verified = crypto.verify(null, Buffer.from(this._canonicalScan(result), 'utf8'), pub, Buffer.from(result.signature, 'base64'));
        } catch { verified = false; }
      }

      let runId = (typeof msg.runId === 'string' && msg.runId) ? msg.runId : null;
      let targetCount = 1;
      if (runId) {
        const run = this.db.prepare("SELECT targets_json, target_count FROM compromise_scan_runs WHERE id = ?").get(runId);
        if (!run) return; // unknown run
        let ids = [];
        try { ids = (JSON.parse(run.targets_json).ids) || []; } catch {}
        if (!ids.includes(ws.userId)) return; // not a target — never store injected results
        targetCount = run.target_count || ids.length || 1;
      } else {
        // Self-initiated scan: rate-limited to one self-run per user per 30s.
        const recent = this.db.prepare("SELECT id FROM compromise_scan_runs WHERE initiated_by = ? AND trigger = 'manual' AND target_count = 1 AND created_at > datetime('now', '-30 seconds') ORDER BY created_at DESC, rowid DESC LIMIT 1").get(ws.userId);
        if (recent) { runId = recent.id; }
        else {
          const created = this.db.prepare("INSERT INTO compromise_scan_runs (trigger, initiated_by, targets_json, target_count, unreachable_count, status) VALUES ('manual', ?, ?, 1, 0, 'in_progress') RETURNING id").get(ws.userId, JSON.stringify({ mode: 'self', ids: [ws.userId] }));
          runId = created.id;
        }
        targetCount = 1;
      }

      const pseudoRow = this.db.prepare("SELECT pseudonym FROM users WHERE id = ?").get(ws.userId);
      const pseudonym = pseudoRow ? pseudoRow.pseudonym : null;

      this.db.prepare(
        "INSERT INTO compromise_scan_results (run_id, user_id, pseudonym_at_scan, status, tests_total, tests_passed, tests_failed, tests_inconclusive, details_json, signature, signature_verified, signed_at, scan_started_at, scan_duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      ).run(
        runId, ws.userId, pseudonym, result.status,
        result.tests_total | 0, result.tests_passed | 0, result.tests_failed | 0, result.tests_inconclusive | 0,
        result.details_json, result.signature || null, verified ? 1 : 0, result.signed_at || null,
        result.scan_started_at || null, result.scan_duration_ms | 0
      );

      this.db.prepare("UPDATE compromise_scan_queue SET status = 'delivered', delivered_at = datetime('now') WHERE run_id = ? AND user_id = ? AND status IN ('queued', 'delivered')").run(runId, ws.userId);

      const completed = this.db.prepare("SELECT COUNT(*) AS c FROM compromise_scan_results WHERE run_id = ? AND signature_verified = 1").get(runId).c;
      if (completed >= targetCount) {
        this.db.prepare("UPDATE compromise_scan_runs SET completed_count = ?, status = 'complete', completed_at = datetime('now') WHERE id = ?").run(completed, runId);
      } else {
        this.db.prepare("UPDATE compromise_scan_runs SET completed_count = ? WHERE id = ?").run(completed, runId);
      }

      this._pushScanProgress(runId, pseudonym, result.status, verified);
    } catch (e) { try { console.error('[WS] scan_result ingest error:', e.message); } catch {} }
  }

  // Push per-client scan progress to leads/admins. Pseudonym only — no user id
  // and no burnout data ever crosses to the management console.
  _pushScanProgress(runId, pseudonym, status, verified) {
    this.clients.forEach((ws) => {
      if ((ws.userRole === 'lead' || ws.userRole === 'admin') && ws.readyState === WebSocket.OPEN) {
        this._send(ws, { type: 'scan_progress', runId, pseudonym, status, verified });
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

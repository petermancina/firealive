const { app, BrowserWindow, ipcMain, session, Notification } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let serverProcess = null;

app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

function startServer() {
  const serverPath = path.join(__dirname, '..', 'server', 'index.js');
  serverProcess = spawn('node', [serverPath], {
    env: { ...process.env, NODE_ENV: 'production', PORT: '3000' },
    stdio: 'pipe'
  });
  serverProcess.stdout.on('data', (d) => console.log('[Server]', d.toString()));
  serverProcess.stderr.on('data', (d) => console.error('[Server]', d.toString()));
  serverProcess.on('exit', (code) => console.log('[Server] Exited with code', code));
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1440, height: 900,
    title: 'FireAlive — Management Console',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' https://localhost:*; img-src 'self' data:; frame-src 'none'"]
      }
    });
  });

  win.loadFile('index.html');
}

// N1a C15: Desktop notification IPC handler. The renderer's WebSocket listener
// (firealive-mc.jsx — landing in N1a C26) forwards server `desktop_notify`
// pushes to this channel via the preload bridge (whitelisted in N1a C13).
// This handler constructs and shows a native OS notification using Electron's
// Notification API. The notification is rendered LOCALLY on the lead's own
// machine — no identity-exposing data flows server-side. Desktop is available
// to ALL roles (analyst anonymity policy from N1a C7 gates email + sms only;
// desktop is unrestricted because rendering is local-only).
//
// Payload shape (from N1a C11 server-side):
//   { notificationId, title, body, eventType, linkTab, linkParams }
// Only title + body + eventType are read here; the rest are reserved for
// future deep-link / inbox-jump enhancements.
//
// Critical-event urgency: routing_panic_* events (manual, tripwire, lifted)
// set `urgency: 'critical'` on Linux (KDE/GNOME render critical notifications
// prominently and persist them until dismissed). macOS + Windows ignore the
// field — that is expected and acceptable; the in-app channel surfaces these
// events with mandatoryInApp enforcement regardless. Tier-3 abuse events are
// also mandatoryInApp at the server but do not currently get critical urgency
// on the desktop side — could be extended in a follow-up if operator feedback
// indicates the abuse channel needs additional emphasis.
ipcMain.on('notify:desktop', (event, payload) => {
  if (!Notification.isSupported()) return;
  if (!payload || typeof payload !== 'object') return;

  const title = typeof payload.title === 'string' && payload.title.length > 0
    ? payload.title
    : 'FireAlive';
  const body = typeof payload.body === 'string' ? payload.body : '';

  const opts = { title, body, silent: false };
  if (typeof payload.eventType === 'string' && payload.eventType.startsWith('routing_panic')) {
    opts.urgency = 'critical';
  }

  try {
    const notif = new Notification(opts);
    notif.show();
  } catch {
    // Native notification API failure (rare; OS denied permission, display
    // server unavailable, or platform-specific edge case). Silently swallow —
    // the in-app notification is the user-visible fallback (in_app channel
    // is independent and writes directly to the notifications table at
    // notify() time on the server).
  }
});

app.whenReady().then(() => {
  startServer();
  // Wait for server to be ready
  setTimeout(createWindow, 2000);
});

app.on('window-all-closed', () => {
  if (serverProcess) serverProcess.kill();
  if (process.platform !== 'darwin') app.quit();
});

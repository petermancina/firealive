const { app, BrowserWindow, ipcMain, session, Notification, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');
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
        'Content-Security-Policy': ["default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self' https://localhost:*; img-src 'self' data:; frame-src 'none'"]
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

// ── Phase U3: Signal-protocol E2EE custody (management console, lead domain) ──
//
// All Signal-protocol cryptography runs here, in the main process. Identity
// private keys and Double-Ratchet session state never cross the IPC bridge: the
// renderer only ever sends/receives public pre-key bundles, opaque ciphertext
// envelopes, decrypted plaintext it composed itself, and safety numbers. Secrets
// are sealed at rest with the OS keychain (safeStorage). The management console is
// a lead-only client, so only the 'lead' cryptographic domain is provisioned.
//
// The shared wrapper (packages/shared/signal-e2ee.js) is bundled into this app by
// the CI copy step (build.yml) as ./signal-e2ee in a packaged build, and lives
// under ../packages/shared when run from source -- try both.
let createSignalE2EE;
try {
  ({ createSignalE2EE } = require('./signal-e2ee'));
} catch {
  ({ createSignalE2EE } = require('../packages/shared/signal-e2ee'));
}

// The reviewer-only seal helper (packages/shared/abuse-seal.js) is bundled the
// same way; load it with the same packaged/source fallback. It needs no native
// dependency (Node crypto only), so a plain require is enough.
let sealToReviewer;
try {
  ({ sealToReviewer } = require('./abuse-seal'));
} catch {
  ({ sealToReviewer } = require('../packages/shared/abuse-seal'));
}

// libsignal is a native ESM module; load it dynamically and normalize the shape
// across the ESM-namespace and CJS-default interop cases.
async function loadLibsignal() {
  const mod = await import('@signalapp/libsignal-client');
  return mod && mod.IdentityKeyPair ? mod : (mod && mod.default ? mod.default : mod);
}

// A small key/value store whose entire contents are sealed at rest with the OS
// keychain. The wrapper hands us libsignal-serialized bytes as base64 strings; we
// keep them in memory and persist the whole map as one safeStorage blob.
function createSealedStore(filePath) {
  let map = {};
  try {
    if (fs.existsSync(filePath)) {
      const sealed = fs.readFileSync(filePath);
      map = JSON.parse(safeStorage.decryptString(sealed)) || {};
    }
  } catch {
    map = {};
  }
  function persist() {
    const blob = safeStorage.encryptString(JSON.stringify(map));
    fs.writeFileSync(filePath, blob, { mode: 0o600 });
  }
  return {
    async get(key) {
      return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
    },
    async set(key, value) { map[key] = value; persist(); },
    async delete(key) { delete map[key]; persist(); },
    async list(prefix) { return Object.keys(map).filter((k) => k.startsWith(prefix)); },
  };
}

// Per-user E2EE state: the lead-domain wrapper over one sealed store.
let e2ee = null;

ipcMain.handle('e2ee:init', async (_event, userId) => {
  if (!userId) throw new Error('e2ee:init requires a userId');
  const uid = String(userId);
  if (e2ee && e2ee.userId === uid) return { ok: true };
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is unavailable; refusing to store E2EE keys unsealed');
  }
  const libsignal = await loadLibsignal();
  const backend = createSealedStore(path.join(app.getPath('userData'), 'e2ee-store.bin'));
  const lead = createSignalE2EE({ libsignal, backend, domain: 'lead', selfUserId: uid });
  await lead.init();
  e2ee = { userId: uid, lead };
  return { ok: true };
});

function domainHandle(domain) {
  if (!e2ee) throw new Error('e2ee not initialized; call e2ee:init first');
  if (domain !== 'lead') throw new Error('invalid e2ee domain (management console: lead only)');
  return e2ee[domain];
}

ipcMain.handle('e2ee:publishBundle', async (_e, { domain, oneTimeCount } = {}) =>
  domainHandle(domain).buildPublishableBundle({ oneTimeCount }));

ipcMain.handle('e2ee:replenishPrekeys', async (_e, { domain, count } = {}) =>
  domainHandle(domain).replenishOneTimePreKeys(count));

ipcMain.handle('e2ee:processBundle', async (_e, { domain, remoteUserId, bundle } = {}) => {
  await domainHandle(domain).processPeerBundle(remoteUserId, bundle);
  return { ok: true };
});

ipcMain.handle('e2ee:hasSession', async (_e, { domain, remoteUserId } = {}) =>
  ({ hasSession: await domainHandle(domain).hasSession(remoteUserId) }));

ipcMain.handle('e2ee:encrypt', async (_e, { domain, remoteUserId, plaintext } = {}) =>
  domainHandle(domain).encrypt(remoteUserId, plaintext));

ipcMain.handle('e2ee:decrypt', async (_e, { domain, remoteUserId, envelope } = {}) => {
  const plaintext = await domainHandle(domain).decrypt(remoteUserId, envelope);
  return { plaintext: plaintext.toString('utf8') };
});

ipcMain.handle('e2ee:safetyNumber', async (_e, { domain, remoteUserId, localId, remoteId } = {}) =>
  ({ safetyNumber: await domainHandle(domain).safetyNumber(remoteUserId, { localId, remoteId }) }));

// Seal abuse-flag content to the independent reviewer's public key (Model B). A
// lead reports an analyst's message here; the renderer passes the offending text
// (already decrypted on screen) and the flagger's note, plus the abuse-review
// public key it fetched, and gets back opaque base64 that only the Abuse Review
// Console can open. The server stores it and cannot read it; no private key is
// ever involved here. The renderer calls this once per field.
ipcMain.handle('abuse:seal', async (_e, { recipientPublicKey, plaintext } = {}) => {
  if (typeof recipientPublicKey !== 'string' || !recipientPublicKey) {
    throw new Error('recipientPublicKey (base64) required');
  }
  if (typeof plaintext !== 'string') {
    throw new Error('plaintext (string) required');
  }
  return { sealed: sealToReviewer(recipientPublicKey, plaintext) };
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

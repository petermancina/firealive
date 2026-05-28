// FireAlive Analyst Client — Electron Main Process
const { app, BrowserWindow, ipcMain, session, Notification, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');

// Security: disable navigation to external URLs
app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1280, height: 800,
    title: 'FireAlive — Analyst Client',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  // CSP header
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self' https://localhost:*; img-src 'self' data:; frame-src 'none'"]
      }
    });
  });

  win.loadFile('index.html');
  if (process.env.NODE_ENV === 'development') win.webContents.openDevTools();
}

// N1a C14: Desktop notification IPC handler. The renderer's WebSocket listener
// (analyst-client.jsx — landing in N1a C25) forwards server `desktop_notify`
// pushes to this channel via the preload bridge (whitelisted in N1a C12).
// This handler constructs and shows a native OS notification using Electron's
// Notification API. The notification is rendered LOCALLY on the analyst's own
// machine — no identity-exposing data flows server-side. Desktop is therefore
// available to ALL roles including analysts (anonymity policy from N1a C7
// gates email + sms only; desktop is unrestricted).
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

// ---------------------------------------------------------------------------
// Phase U3: Signal-protocol E2EE custody (main process).
//
// All Signal-protocol cryptography runs here, in the main process. Identity
// private keys and Double-Ratchet session state never cross the IPC bridge:
// the renderer only ever sends/receives public pre-key bundles, opaque
// ciphertext envelopes, decrypted plaintext it composed itself, and safety
// numbers. Secrets are sealed at rest with the OS keychain (safeStorage).
//
// The shared wrapper (packages/shared/signal-e2ee.js) is bundled into this app
// by the CI copy step (build.yml); it lives alongside main.js in a packaged
// build and under ../shared when run from source — try both.
let createSignalE2EE;
try {
  ({ createSignalE2EE } = require('./signal-e2ee'));
} catch {
  ({ createSignalE2EE } = require('../shared/signal-e2ee'));
}

// The reviewer-only seal helper (packages/shared/abuse-seal.js) is bundled the
// same way; load it with the same packaged/source fallback. It needs no native
// dependency (Node crypto only), so a plain require is enough.
let sealToReviewers;
try {
  ({ sealToReviewers } = require('./abuse-seal'));
} catch {
  ({ sealToReviewers } = require('../shared/abuse-seal'));
}

// The reporter-note sanitizer (packages/shared/note-sanitizer.js) is loaded the
// same packaged/source way. It hardens the reporter's free-text note before it
// is sealed; the flagged CONTENT is never passed through it.
let sanitizeNote;
try {
  ({ sanitizeNote } = require('./note-sanitizer'));
} catch {
  ({ sanitizeNote } = require('../shared/note-sanitizer'));
}

// libsignal is a native ESM module; load it dynamically and normalize the
// shape across the ESM-namespace and CJS-default interop cases.
async function loadLibsignal() {
  const mod = await import('@signalapp/libsignal-client');
  return mod && mod.IdentityKeyPair ? mod : (mod && mod.default ? mod.default : mod);
}

// A small key/value store whose entire contents are sealed at rest with the OS
// keychain. The wrapper hands us libsignal-serialized bytes as base64 strings;
// we keep them in memory and persist the whole map as one safeStorage blob.
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

// Per-user E2EE state: one wrapper per cryptographic domain (peer vs lead),
// sharing one sealed store (the wrapper namespaces its keys by domain).
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
  const peer = createSignalE2EE({ libsignal, backend, domain: 'peer', selfUserId: uid });
  const lead = createSignalE2EE({ libsignal, backend, domain: 'lead', selfUserId: uid });
  await peer.init();
  await lead.init();
  e2ee = { userId: uid, peer, lead };
  return { ok: true };
});

function domainHandle(domain) {
  if (!e2ee) throw new Error('e2ee not initialized; call e2ee:init first');
  if (domain !== 'peer' && domain !== 'lead') throw new Error('invalid e2ee domain');
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

// Seal abuse-flag content to the active reviewer recipient set.
// The renderer passes content it already holds (the decrypted offending message,
// or the flagger's note) plus the active abuse-review public keys it fetched, and
// gets back opaque base64 that ONLY a designated reviewer can open. The content is
// sealed to ALL active reviewer keys at once (one multi-recipient envelope), so any
// one reviewer opens it with their own private key. The server stores it and cannot
// read it; no private key is ever involved here. The renderer calls this once per
// field (offending text, note).
ipcMain.handle('abuse:seal', async (_e, { recipientPublicKeys, plaintext, sanitize } = {}) => {
  if (!Array.isArray(recipientPublicKeys) || recipientPublicKeys.length === 0) {
    throw new Error('recipientPublicKeys (non-empty array of base64) required');
  }
  if (!recipientPublicKeys.every((k) => typeof k === 'string' && k)) {
    throw new Error('each recipient public key must be base64');
  }
  if (typeof plaintext !== 'string') {
    throw new Error('plaintext (string) required');
  }
  // Only the reporter's note is sanitized (sanitize: true). The flagged content
  // is system-copied authentic text and must be sealed exactly as captured.
  const material = sanitize ? sanitizeNote(plaintext) : plaintext;
  return { sealed: sealToReviewers(recipientPublicKeys, material) };
});

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });

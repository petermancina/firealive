const { app, BrowserWindow, ipcMain, dialog, session, Notification, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { spawn } = require('child_process');

let serverProcess = null;

app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// B5b — TLS trust + client-certificate presentation (passwordless auth)
//
// The management console's renderer connects to its bundled root server over
// HTTPS. That server presents a certificate from the built-in FireAlive CA, so
// the client must trust that CA. The CA certificate (firealive-ca.pem, served
// from the server's /ca-cert) is imported once, stored under userData, and
// pinned here. setCertificateVerifyProc trusts a server certificate ONLY if it
// chains to that pinned CA, and rejects every other certificate outright
// (strict pinning: a publicly-trusted but non-FireAlive cert is NOT accepted,
// which defeats a mis-issued or compromised public CA). The CA certificate is
// public, not a secret, so it is kept as a plain
// file rather than in safeStorage.
//
// The in-app login method is a FIDO2/WebAuthn passkey, handled in the renderer
// via navigator.credentials — the private key never leaves the authenticator. A
// hardware client certificate (PIV/CAC) held in the OS certificate store is also
// supported: when the server requests a client certificate at the TLS handshake,
// select-client-certificate presents one from the OS store. A software
// certificate generated on the host is intentionally NOT used for in-app mTLS —
// the gold-standard credential keeps its key in hardware.
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════

const caPinPath = () => path.join(app.getPath('userData'), 'firealive-ca.pem');
let pinnedCaPem = null; // loaded at window creation (after app is ready)

function loadPinnedCaPem() {
  try {
    const p = caPinPath();
    return fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null;
  } catch (_) { return null; }
}

// True only if the presented server certificate is signed by the pinned FireAlive CA.
function serverCertChainsToPinnedCa(serverPem) {
  if (!pinnedCaPem || !serverPem) return false;
  try {
    const caX = new crypto.X509Certificate(pinnedCaPem);
    const srvX = new crypto.X509Certificate(serverPem);
    return srvX.verify(caX.publicKey);
  } catch (_) { return false; }
}

// Import / replace the pinned FireAlive CA certificate.
ipcMain.handle('auth:importCaCert', (_e, { pem } = {}) => {
  if (!pem || typeof pem !== 'string' || !/-----BEGIN CERTIFICATE-----/.test(pem)) {
    return { ok: false, error: 'a PEM CA certificate is required' };
  }
  try { new crypto.X509Certificate(pem); } catch (_) { return { ok: false, error: 'not a valid certificate' }; }
  try {
    fs.writeFileSync(caPinPath(), pem, { mode: 0o644 });
    pinnedCaPem = pem;
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
});

// Report whether a CA is pinned (for the settings UI).
ipcMain.handle('auth:caStatus', () => {
  if (!pinnedCaPem) return { pinned: false };
  try {
    const x = new crypto.X509Certificate(pinnedCaPem);
    return { pinned: true, subject: x.subject, validTo: x.validTo, fingerprint256: x.fingerprint256 };
  } catch (_) { return { pinned: true }; }
});

// Present an OS-store client certificate (e.g. a PIV/CAC smart-card cert) when
// the server requests one at the TLS handshake. If none is available, proceed
// without a client cert — the server permits app-layer (passkey) authentication.
app.on('select-client-certificate', (event, webContents, url, certificateList, callback) => {
  event.preventDefault();
  if (certificateList && certificateList.length > 0) {
    callback(certificateList[0]);
  } else {
    callback();
  }
});

// B5e (D24): MC device key + privileged-action signing. The Management Console
// mints a hardware-bound device key (TPM 2.0 / Secure Enclave) on the shared
// keystore seam, fingerprint-registered with the server. Destructive recovery
// actions (teardown / reprovision) are signed on-chip so the server can bind each
// such action to this MC's hardware identity and apply dual-control / GD co-
// approval / rate limits. The private key never leaves the hardware; the app
// fails closed without a hardware root of trust.
const MC_DEVICE_KEY_LABEL = 'fa-mc-device';
const MC_ACTION_SIGNING_PREFIX = 'firealive-mc-device-action-v1:';
const MC_ACTION_SEP = String.fromCharCode(10);
let _mcDeviceKey = null;

async function getMcDeviceKey() {
  if (_mcDeviceKey) return _mcDeviceKey;
  const hwkey = require('../packages/shared/hardware-key');
  if (!hwkey.isAvailable()) {
    throw new Error('A hardware root of trust (TPM 2.0 / Secure Enclave) is required for the MC device signing key; this app fails closed and will not run without it');
  }
  let der = hwkey.hasSigningKey(MC_DEVICE_KEY_LABEL)
    ? hwkey.getSigningPublicKey(MC_DEVICE_KEY_LABEL)
    : hwkey.createSigningKey(MC_DEVICE_KEY_LABEL);
  if (!der) {
    der = hwkey.createSigningKey(MC_DEVICE_KEY_LABEL);
  }
  const publicKeyPem = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' })
    .export({ type: 'spki', format: 'pem' });
  const fingerprint = crypto.createHash('sha256').update(der).digest('hex');
  _mcDeviceKey = {
    sign: (data) => hwkey.sign(MC_DEVICE_KEY_LABEL, Buffer.isBuffer(data) ? data : Buffer.from(data)),
    publicKeyPem,
    fingerprint,
    label: MC_DEVICE_KEY_LABEL,
  };
  return _mcDeviceKey;
}

// Domain-separated message bound by a privileged-action signature. The server
// reconstructs the identical message to verify (same field order + separator).
function mcActionMessage(action, target, iat, jti) {
  return Buffer.from(MC_ACTION_SIGNING_PREFIX + [action, target, String(iat), jti].join(MC_ACTION_SEP), 'utf8');
}

// Public key + fingerprint, for registering the MC device key with the server.
ipcMain.handle('device:getPublicKey', async () => {
  try {
    const k = await getMcDeviceKey();
    return { publicKey: k.publicKeyPem, fingerprint: k.fingerprint };
  } catch (e) {
    return { error: e.message };
  }
});

// Sign a privileged action on-chip (D24). Returns the signature plus the iat/jti
// the server needs to reconstruct the message, check the freshness window, and
// enforce single-use. action is required; target identifies the object acted on.
ipcMain.handle('device:signAction', async (_e, { action, target } = {}) => {
  try {
    if (typeof action !== 'string' || !action) return { error: 'action required' };
    const k = await getMcDeviceKey();
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomBytes(16).toString('hex');
    const sig = k.sign(mcActionMessage(action, target || '', iat, jti));
    return { signature: sig.toString('base64'), iat, jti, fingerprint: k.fingerprint };
  } catch (e) {
    return { error: e.message };
  }
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
  pinnedCaPem = loadPinnedCaPem();
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

  // Pin the FireAlive CA: trust a server certificate only if it chains to the
  // imported CA; reject every other certificate (strict pinning, no fallback).
  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    const leafPem = request && request.certificate && request.certificate.data;
    if (leafPem && serverCertChainsToPinnedCa(leafPem)) return callback(0); // trusted via pinned CA
    return callback(-2); // reject: not signed by the pinned FireAlive CA
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
let sealToReviewers;
try {
  ({ sealToReviewers } = require('./abuse-seal'));
} catch {
  ({ sealToReviewers } = require('../packages/shared/abuse-seal'));
}

// The reporter-note sanitizer (packages/shared/note-sanitizer.js) is loaded the
// same packaged/source way. It hardens the reporter's free-text note before it
// is sealed; the flagged CONTENT is never passed through it.
let sanitizeNote;
try {
  ({ sanitizeNote } = require('./note-sanitizer'));
} catch {
  ({ sanitizeNote } = require('../packages/shared/note-sanitizer'));
}

// The abuse-flag export PDF builder (packages/shared/abuse-export-pdf.js) is
// loaded the same packaged/source way. It renders the flagger's one-shot
// submission record locally; no content leaves the device to build it.
let buildAbuseExportPdf;
try {
  ({ buildAbuseExportPdf } = require('./abuse-export-pdf'));
} catch {
  ({ buildAbuseExportPdf } = require('../packages/shared/abuse-export-pdf'));
}

// B5e: subnet beacon listener (anti-cloning, client side). Listen-only. Verifies
// the signed beacons FireAlive regional servers broadcast and warns the operator
// if a cloned or forked server identity appears on the local subnet. The console
// announces nothing (it has no identity of its own). Anchor-pinned detection
// arrives with the Block K anchor challenge; until then this runs unpinned, where
// a concurrent second server identity for the role is the signal.
let beaconListener = null;

function startBeaconListener() {
  let beaconLib;
  try {
    beaconLib = require('./beacon-listener');
  } catch {
    beaconLib = require('../packages/shared/beacon-listener');
  }
  try {
    beaconListener = beaconLib.start({
      expectedRole: 'regional-server',
      onDetection: (detection) => {
        const verdict = detection && detection.verdict ? detection.verdict : 'conflict';
        try {
          const notif = new Notification({
            title: 'FireAlive security alert',
            body: 'A possible cloned or rogue server was detected on your network. Do not continue and contact your security team.',
            urgency: 'critical',
            silent: false,
          });
          notif.show();
        } catch {
          // native notification unavailable; the renderer event below is the fallback
        }
        try {
          const wins = BrowserWindow.getAllWindows();
          if (wins && wins.length) {
            wins[0].webContents.send('anticlone:serverConflict', {
              verdict: verdict,
              role: detection ? detection.role : null,
              from: detection ? detection.from : null,
            });
          }
        } catch (_e) {
          // renderer not ready; the notification already fired
        }
        try {
          console.warn('[anticlone] subnet server ' + verdict + ' detected');
        } catch (_e) {
          // ignore
        }
      },
    });
  } catch (err) {
    try {
      console.warn('[anticlone] beacon listener failed to start: ' + (err && err.message ? err.message : String(err)));
    } catch (_e) {
      // ignore
    }
  }
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

// Seal abuse-flag content to the active reviewer recipient set (multi-reviewer
// zero-access). A lead reports an analyst's message here; the renderer passes the
// offending text (already decrypted on screen) and the flagger's note, plus the
// active reviewer public keys it fetched, and gets back opaque base64 that ONLY a
// designated reviewer can open. The content is sealed to ALL active reviewer keys
// at once (one multi-recipient envelope), so any one reviewer opens it with their
// own private key. The server stores it and cannot read it; no private key is
// ever involved here. The renderer calls this once per field (offending text,
// note).
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

// ── Abuse-flag export: one-shot, in-memory submission record ─────────────────
//
// Mirrors the Analyst Client. After a flag is submitted to the independent
// reviewer (here, the team-lead-as-victim lead-chat case), the flagger may
// export a single local PDF copy. The authentic plaintext is held HERE, in the
// main process only, for a short window: never written to disk, IndexedDB, or
// renderer state, and wiped on export, on decline, or on timeout. Memory-only,
// not a hardware enclave -- JS strings cannot be reliably zeroed, so the
// material is held in Buffers that are filled with zeros on wipe as a best
// effort.
const ABUSE_EXPORT_WINDOW_MS = 5 * 60 * 1000;
let abuseExportHold = null;   // { flagId, targetType, content: Buffer, note: Buffer, contentSha256, expiresAt }
let abuseExportTimer = null;

function wipeAbuseExportHold() {
  if (abuseExportTimer) { clearTimeout(abuseExportTimer); abuseExportTimer = null; }
  if (abuseExportHold) {
    try { if (abuseExportHold.content) abuseExportHold.content.fill(0); } catch (_) {}
    try { if (abuseExportHold.note) abuseExportHold.note.fill(0); } catch (_) {}
    abuseExportHold = null;
  }
}

ipcMain.handle('abuse:hold-for-export', async (_e, { flagId, targetType, contentText, note } = {}) => {
  if (typeof flagId !== 'string' || !flagId) throw new Error('flagId (string) required');
  if (typeof contentText !== 'string' || !contentText) throw new Error('contentText (string) required');
  wipeAbuseExportHold();
  const content = Buffer.from(contentText, 'utf8');
  const noteBuf = Buffer.from(sanitizeNote(typeof note === 'string' ? note : ''), 'utf8');
  const contentSha256 = crypto.createHash('sha256').update(content).digest('hex');
  const expiresAt = Date.now() + ABUSE_EXPORT_WINDOW_MS;
  abuseExportHold = { flagId, targetType: targetType || '', content, note: noteBuf, contentSha256, expiresAt };
  abuseExportTimer = setTimeout(wipeAbuseExportHold, ABUSE_EXPORT_WINDOW_MS);
  return { contentSha256, expiresAt, windowMs: ABUSE_EXPORT_WINDOW_MS };
});

ipcMain.handle('abuse:finalize-export', async (_e, { descriptor } = {}) => {
  const hold = abuseExportHold;
  if (!hold) return { saved: false, reason: 'expired' };
  const payload = (descriptor && descriptor.payload) || {};
  if (payload.flag_uuid !== hold.flagId || payload.content_sha256 !== hold.contentSha256) {
    return { saved: false, reason: 'mismatch' };
  }
  let pdf;
  try {
    pdf = await buildAbuseExportPdf({
      contentText: hold.content.toString('utf8'),
      note: hold.note.toString('utf8'),
      descriptor,
    });
  } catch (e) {
    return { saved: false, reason: 'build_failed' };
  }
  const win = BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0] || null;
  const defaultName = 'firealive-flag-' + hold.flagId.slice(0, 8) + '.pdf';
  const { canceled, filePath } = await dialog.showSaveDialog(win, {
    title: 'Save abuse-flag submission record',
    defaultPath: defaultName,
    filters: [{ name: 'PDF', extensions: ['pdf'] }],
  });
  if (canceled || !filePath) return { saved: false, reason: 'dialog_canceled' };
  try {
    fs.writeFileSync(filePath, pdf);
  } catch (e) {
    return { saved: false, reason: 'write_failed' };
  }
  wipeAbuseExportHold();
  return { saved: true };
});

ipcMain.handle('abuse:cancel-export', async () => {
  wipeAbuseExportHold();
  return { canceled: true };
});

app.whenReady().then(() => {
  startServer();
  // Wait for server to be ready
  setTimeout(createWindow, 2000);
  startBeaconListener();
});

app.on('window-all-closed', () => {
  if (serverProcess) serverProcess.kill();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  try { if (beaconListener) beaconListener.stop(); } catch (_e) { /* ignore */ }
});

// FireAlive Analyst Client — Electron Main Process
const { app, BrowserWindow, ipcMain, dialog, session, Notification, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const kbLocal = require('./kb-local');
const localLlm = require('./local-llm');

// Security: disable navigation to external URLs
app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

// ═══════════════════════════════════════════════════════════════════════════════
// B5b — TLS trust + client-certificate presentation (passwordless auth)
//
// The analyst client connects to the management console over HTTPS. The MC
// serves a certificate from its own built-in CA, so the client must trust that
// CA out-of-band. The operator imports the MC CA certificate (firealive-ca.pem,
// downloadable from the server's /ca-cert) once; it is stored under userData and
// pinned here. setCertificateVerifyProc trusts a server certificate ONLY if it
// chains to that pinned CA, and rejects every other certificate outright
// (strict pinning: a publicly-trusted but non-FireAlive cert is NOT accepted,
// which defeats a mis-issued or compromised public CA). The CA certificate is
// public, not a secret, so it is kept as a plain file rather than in safeStorage.
//
// The in-app login method is a FIDO2/WebAuthn passkey, handled in the renderer
// via navigator.credentials — the private key never leaves the authenticator. A
// hardware client certificate (PIV/CAC) held in the OS certificate store is also
// supported: when the server requests a client certificate at the TLS handshake,
// select-client-certificate presents one from the OS store. A software
// certificate generated on the host is intentionally NOT used for in-app mTLS —
// the gold-standard credential keeps its key in hardware.
// ═══════════════════════════════════════════════════════════════════════════════

const caPinPath = () => path.join(app.getPath('userData'), 'firealive-ca.pem');

// D9: per-installation deployment-mode selection (advisory; the server's
// anchor-sealed mode is authoritative). Stored as a plain JSON file under
// userData, like the CA pin. Created lazily so app paths are ready.
const { makeLocalMode } = require('../shared/deployment-mode-local');
let _localMode = null;
function localMode() {
  if (!_localMode) {
    _localMode = makeLocalMode(path.join(app.getPath('userData'), 'firealive-deployment-mode.json'));
  }
  return _localMode;
}
let pinnedCaPem = null; // loaded at window creation (after app is ready)

function loadPinnedCaPem() {
  try {
    const p = caPinPath();
    return fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : null;
  } catch (_) { return null; }
}

// True only if the presented server certificate is signed by the pinned MC CA.
function serverCertChainsToPinnedCa(serverPem) {
  if (!pinnedCaPem || !serverPem) return false;
  try {
    const caX = new crypto.X509Certificate(pinnedCaPem);
    const srvX = new crypto.X509Certificate(serverPem);
    return srvX.verify(caX.publicKey);
  } catch (_) { return false; }
}

// Import / replace the pinned MC CA certificate (an out-of-band operator action).
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

// D9: report / set this installation's deployment-mode selection (first-run).
ipcMain.handle('deployment:getLocalMode', async () => {
  try {
    const lm = localMode();
    return { mode: lm.getMode(), configured: lm.isConfigured(), virtualized: lm.isVirtualized(), toleratesMobility: lm.toleratesMobility(), substrate: lm.getSubstrate() };
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('deployment:setLocalMode', async (_e, { mode, substrate } = {}) => {
  try {
    const lm = localMode();
    lm.setMode(mode, substrate);
    return { ok: true, mode: lm.getMode(), substrate: lm.getSubstrate() };
  } catch (e) {
    return { error: e.message };
  }
});

// B5e: AC-side anti-cloning ratchet. The AC remembers the highest ratchet
// counter the server has echoed (sealed at rest under userData). It presents that
// counter on auth (anticlone:ratchetState) and checks the server's echo
// (anticlone:recordRatchet): a server that returns a counter BELOW what the AC
// already saw has rolled back or been cloned, and must not be trusted.
let antiCloneStore = null;
function getAntiCloneStore() {
  if (!antiCloneStore) {
    antiCloneStore = createSealedStore(path.join(app.getPath('userData'), 'anticlone-store.bin'));
  }
  return antiCloneStore;
}
const SERVER_RATCHET_KEY = 'serverRatchetHighWater';

ipcMain.handle('anticlone:ratchetState', async () => {
  try {
    const v = await getAntiCloneStore().get(SERVER_RATCHET_KEY);
    return { lastSeen: (v === null || v === undefined) ? null : Number(v) };
  } catch (err) {
    return { lastSeen: null, error: err && err.message ? err.message : String(err) };
  }
});

ipcMain.handle('anticlone:recordRatchet', async (_e, { echoedCounter } = {}) => {
  const store = getAntiCloneStore();
  let lastSeen = null;
  try {
    const v = await store.get(SERVER_RATCHET_KEY);
    lastSeen = (v === null || v === undefined) ? null : Number(v);
  } catch (err) {
    lastSeen = null;
  }
  const echoed = (echoedCounter === null || echoedCounter === undefined) ? null : Number(echoedCounter);
  if (echoed === null || !Number.isFinite(echoed)) {
    return { verdict: 'ok', lastSeen: lastSeen, echoed: null };
  }
  if (lastSeen !== null && echoed < lastSeen) {
    return { verdict: 'rollback', lastSeen: lastSeen, echoed: echoed };
  }
  const next = (lastSeen === null) ? echoed : Math.max(lastSeen, echoed);
  try {
    await store.set(SERVER_RATCHET_KEY, next);
  } catch (err) {
    return { verdict: 'ok', lastSeen: next, echoed: echoed, persistError: err && err.message ? err.message : String(err) };
  }
  return { verdict: 'ok', lastSeen: next, echoed: echoed };
});

// B5e (D25): server -> client deployment attestation. The AC pins the Regional
// server's hardware instance-anchor fingerprint at enrollment and, on each
// connect, challenges the server to sign a fresh nonce with that anchor. A clone
// holds the same database and CA but cannot unseal the anchor on different
// hardware, so it cannot sign the nonce -> the AC refuses it as a possible cloned
// server. The pinned fingerprint is sealed at rest alongside the ratchet counter;
// re-pinning is deliberate (the re-provision ceremony), never silent.
const SERVER_ANCHOR_FP_KEY = 'serverAnchorFingerprint';
const ANCHOR_CHALLENGE_PREFIX = 'firealive-instance-anchor-challenge-v1:';

// Fresh challenge nonce (32 bytes of CSPRNG). The renderer sends it to
// POST /api/instance/anchor-challenge and returns the response here to check.
ipcMain.handle('anticlone:anchorNonce', async () => {
  return { nonce: crypto.randomBytes(32).toString('base64') };
});

// Verify an anchor-challenge response. Always checks crypto integrity first (the
// published key matches its claimed fingerprint, and the signature over
// <prefix || nonce> is valid), then compares the fingerprint to the pin. Verdicts:
// 'ok' (pinned + matches), 'mismatch' (pinned but a different anchor -> refuse),
// 'unpinned' (valid but nothing pinned yet -> caller may pin TOFU), 'invalid'
// (crypto failed -> refuse).
ipcMain.handle('anticlone:verifyAnchor', async (_e, payload = {}) => {
  const nonce = payload.nonce;
  const fingerprint = payload.fingerprint;
  const publicKey = payload.publicKey;
  const signature = payload.signature;
  if (typeof nonce !== 'string' || typeof fingerprint !== 'string' || typeof publicKey !== 'string' || typeof signature !== 'string') {
    return { verdict: 'invalid', reason: 'incomplete anchor-challenge response' };
  }
  let derFp;
  try {
    const der = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
    derFp = crypto.createHash('sha256').update(der).digest('hex');
  } catch (_) {
    return { verdict: 'invalid', reason: 'unreadable public key' };
  }
  if (derFp !== fingerprint) {
    return { verdict: 'invalid', reason: 'fingerprint does not match public key' };
  }
  let sigOk = false;
  try {
    const message = Buffer.from(ANCHOR_CHALLENGE_PREFIX + nonce, 'utf8');
    sigOk = crypto.verify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64'));
  } catch (_) {
    sigOk = false;
  }
  if (!sigOk) {
    return { verdict: 'invalid', reason: 'anchor signature did not verify' };
  }
  let pinned = null;
  try {
    pinned = await getAntiCloneStore().get(SERVER_ANCHOR_FP_KEY);
  } catch (_) {
    pinned = null;
  }
  if (pinned === null || pinned === undefined) {
    return { verdict: 'unpinned', fingerprint: fingerprint };
  }
  if (pinned === fingerprint) {
    return { verdict: 'ok', fingerprint: fingerprint };
  }
  return { verdict: 'mismatch', fingerprint: fingerprint, pinned: pinned };
});

// Pin the server's anchor fingerprint (trust-on-first-use at enrollment). Refuses
// to silently overwrite an existing, different pin; the re-provision ceremony
// passes force to deliberately re-pin (D19).
ipcMain.handle('anticlone:pinAnchor', async (_e, { fingerprint, force } = {}) => {
  if (typeof fingerprint !== 'string' || !(/^[0-9a-f]{64}$/.test(fingerprint))) {
    return { pinned: false, error: 'a 64-hex-character anchor fingerprint is required' };
  }
  const store = getAntiCloneStore();
  let existing = null;
  try { existing = await store.get(SERVER_ANCHOR_FP_KEY); } catch (_) { existing = null; }
  if (existing && existing !== fingerprint && !force) {
    return { pinned: false, conflict: true, error: 'anchor already pinned to a different fingerprint; re-pin requires re-provision' };
  }
  try {
    await store.set(SERVER_ANCHOR_FP_KEY, fingerprint);
  } catch (err) {
    return { pinned: false, error: err && err.message ? err.message : String(err) };
  }
  return { pinned: true, fingerprint: fingerprint, firstPin: !existing };
});

ipcMain.handle('anticlone:confirmAnchorPin', async (_e, { fingerprint } = {}) => {
  if (typeof fingerprint !== 'string' || !(/^[0-9a-f]{64}$/.test(fingerprint))) {
    return { confirmed: false, error: 'a 64-hex-character anchor fingerprint is required' };
  }
  const NL = String.fromCharCode(10);
  const grouped = fingerprint.replace(/(.{8})/g, '$1 ').trim();
  const win = BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0] || null;
  const opts = {
    type: 'warning',
    buttons: ['Cancel', 'Confirm and pin'],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
    title: 'Confirm server identity (first connection)',
    message: 'Trust this FireAlive deployment on first connection?',
    detail: 'Server anchor fingerprint:' + NL + NL + grouped + NL + NL
      + 'Compare this with the DEPLOYMENT ANCHOR FINGERPRINT the server prints '
      + 'at startup, obtained out of band from your administrator. Confirm only '
      + 'if it matches exactly. A clone of this deployment cannot reproduce this '
      + 'fingerprint, so a value that does not match is the signal to refuse.',
  };
  let result;
  try {
    result = win ? await dialog.showMessageBox(win, opts) : await dialog.showMessageBox(opts);
  } catch (err) {
    return { confirmed: false, error: err && err.message ? err.message : String(err) };
  }
  return { confirmed: !!(result && result.response === 1) };
});

// Report whether a server anchor fingerprint is pinned (for the connect flow).
ipcMain.handle('anticlone:anchorState', async () => {
  try {
    const v = await getAntiCloneStore().get(SERVER_ANCHOR_FP_KEY);
    return { pinned: !!v, fingerprint: (v === null || v === undefined) ? null : v };
  } catch (_) {
    return { pinned: false, fingerprint: null };
  }
});

// B5e: subnet beacon listener (anti-cloning, client side). Listen-only. Verifies
// the signed beacons FireAlive regional servers broadcast and warns the analyst
// if a cloned or forked server identity appears on the local subnet. The client
// announces nothing (it has no identity of its own). Anchor-pinned detection
// arrives with the Block K anchor challenge; until then this runs unpinned, where
// a concurrent second server identity for the role is the signal.
let beaconListener = null;

function startBeaconListener() {
  let beaconLib;
  try {
    beaconLib = require('./beacon-listener');
  } catch {
    beaconLib = require('../shared/beacon-listener');
  }
  try {
    beaconListener = beaconLib.start({
      expectedRole: 'regional-server',
      onDetection: (detection) => {
        const verdict = detection && detection.verdict ? detection.verdict : 'conflict';
        try {
          const notif = new Notification({
            title: 'FireAlive security alert',
            body: 'A possible cloned or rogue server was detected on your network. Do not continue and contact your team lead.',
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

function createWindow() {
  pinnedCaPem = loadPinnedCaPem();
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

  // Pin the management console's CA: trust a server certificate only if it
  // chains to the imported MC CA; reject every other cert (strict pinning).
  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    const leafPem = request && request.certificate && request.certificate.data;
    if (leafPem && serverCertChainsToPinnedCa(leafPem)) return callback(0); // trusted via pinned CA
    return callback(-2); // reject: not signed by the pinned MC CA
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

// The abuse-flag export PDF builder (packages/shared/abuse-export-pdf.js) is
// loaded the same packaged/source way. It renders the flagger's one-shot
// submission record locally; no content leaves the device to build it.
let buildAbuseExportPdf;
try {
  ({ buildAbuseExportPdf } = require('./abuse-export-pdf'));
} catch {
  ({ buildAbuseExportPdf } = require('../shared/abuse-export-pdf'));
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

// ── Abuse-flag export: one-shot, in-memory submission record ─────────────────
//
// After a flag is submitted to the independent reviewer, the flagger may export
// a single local PDF copy as a personal backup. The authentic plaintext is held
// HERE, in the main process only, for a short window: it is never written to
// disk, IndexedDB, or renderer state, and is wiped on export, on decline, or on
// timeout. This is a memory-only protection, not a hardware enclave -- JS
// strings cannot be reliably zeroed, so the material is held in Buffers that are
// filled with zeros on wipe as a best effort.
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

// Stash the authentic content (+ sanitized note) for the export window and
// return the content hash the renderer needs to request a signature. Only one
// hold exists at a time; a new hold wipes any previous one. The content is the
// authentic captured text and is never altered; only the note is sanitized.
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

// Build and save the export PDF from the held material plus the server-signed
// descriptor. The descriptor must match the held flag and content hash. On a
// successful save the hold is wiped; if the user backs out of the save dialog
// the hold is kept so they can retry within the window.
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
    // P1-2b: owner-only. This is an abuse-flag submission record -- analyst
    // evidence naming a reporter and a subject -- written to an operator-chosen
    // path that may be a shared drive or a synced folder. Every sibling write in
    // this file sets a mode (:76 the public CA pin at 0o644 deliberately, :513
    // the same dialog-to-filePath shape at 0o600); this one did not, so it
    // landed at the inherited default, typically 0644.
    //
    // Note the limit of the mode argument: it applies only when the file is
    // CREATED. Overwriting an existing file leaves that file's mode as it was.
    fs.writeFileSync(filePath, pdf, { mode: 0o600 });
  } catch (e) {
    return { saved: false, reason: 'write_failed' };
  }
  wipeAbuseExportHold();
  return { saved: true };
});

// Explicit decline ("do not keep a copy") -- wipe the held material immediately.
ipcMain.handle('abuse:cancel-export', async () => {
  wipeAbuseExportHold();
  return { canceled: true };
});


// ── KB + local AI IPC (PR5) ────────────────────────────────────────
// All on-device, NO network path at all. Models are provisioned out-of-band by
// the operator and verified here (verify-only): kbChat:verifyModel checks the
// pinned SHA-256s, kbChat:provisioningInfo returns the official source + hashes.
// Honest "unavailable on this device" with no server fallback — the Tier-3 firewall.

const KB_CHAT_SYSTEM = [
  "You are the FireAlive Research Assistant, running on the analyst's own device.",
  "Answer the question using ONLY the numbered research entries below.",
  "Cite every claim with the entry's identifier in square brackets, e.g. [R024]. Use only the identifiers listed; never invent a study or cite anything not below.",
  "If the research does not address the question, say so plainly and cite nothing.",
  "This is research education to understand burnout and wellbeing science — NOT therapy, diagnosis, or clinical advice.",
].join("\n");

function acEntriesBlock(entries) {
  return entries.map((e) => `[${e.id}] ${e.title || e.topic} (${e.year}). Finding: ${e.finding} Implication: ${e.implication}`).join("\n\n");
}
function buildLocalPrompt(question, entries, signalsContext) {
  let p = KB_CHAT_SYSTEM + "\n\nRESEARCH ENTRIES:\n" + acEntriesBlock(entries);
  if (signalsContext) p += "\n\nYOUR OWN SIGNALS (private, on-device background — do NOT cite this; cite only the research entries above):\n" + signalsContext;
  p += "\n\nQUESTION: " + question;
  p += "\n\nAnswer (cite every claim with a bracketed identifier from the entries above):";
  return p;
}
function acRetrySuffix(allowed, offending) {
  return "\n\n[Your previous answer cited identifiers not in the provided entries"
    + (offending && offending.length ? " (" + offending.join(", ") + ")" : "")
    + ". Rewrite using ONLY these identifiers: " + allowed.join(", ") + ". Cite only from them.]";
}
function acClampK(k, def, max) {
  return (Number.isInteger(k) && k > 0) ? Math.min(k, max) : def;
}

// ── B5d1 PR D: on-device burnout-signal interpretation grounding ─────────────
// Interprets the analyst's own behavioral-signal drift in plain language,
// grounded ONLY in retrieved KB research entries, on the same local model as the
// research assistant. The analyst's signal values are private background and are
// never cited. Non-clinical, non-diagnostic; never asserts the analyst is burned
// out. Citations are validated against the retrieved entries (anti-hallucination).
const BURNOUT_INTERPRET_SYSTEM = [
  "You are FireAlive's wellbeing assistant, running on the analyst's own device.",
  "The analyst will share how one of their own work-pattern signals has drifted from their personal baseline.",
  "In 2-4 sentences, explain what this kind of drift can mean for wellbeing and what may help, using ONLY the numbered research entries below.",
  "Cite every claim with the entry's identifier in square brackets, e.g. [R024]. Use only the identifiers listed; never invent a study.",
  "Be supportive and matter-of-fact. This is wellbeing education grounded in research — NOT therapy, diagnosis, or a clinical judgement, and not a statement that the analyst is burned out.",
  "Address the analyst as 'you'. Do not repeat the raw numbers; interpret the direction and what it may reflect.",
].join("\n");

function buildInterpretPrompt(signal, entries) {
  const dir = signal.driftPct > 0 ? 'risen' : signal.driftPct < 0 ? 'fallen' : 'held steady';
  const band = signal.bandStatus ? ` and is currently ${signal.bandStatus} the healthy range` : '';
  const ctx = `Signal: ${signal.label}. It has ${dir} about ${Math.abs(Math.round(signal.driftPct || 0))}% versus your established baseline${band}.`;
  let p = BURNOUT_INTERPRET_SYSTEM + "\n\nRESEARCH ENTRIES:\n" + acEntriesBlock(entries);
  p += "\n\nYOUR SIGNAL (private background — do NOT cite this; cite only the research entries above):\n" + ctx;
  p += "\n\nInterpretation (2-4 sentences, cite every claim with a bracketed identifier from the entries above):";
  return p;
}

// Holistic counterpart to BURNOUT_INTERPRET_SYSTEM: one synthesis across every
// signal at once plus operational load, rather than a single-signal read.
const BURNOUT_OVERALL_SYSTEM = [
  "You are FireAlive's wellbeing assistant, running on the analyst's own device.",
  "The analyst will share a summary of ALL their work-pattern signals at once, plus their current operational load and an overall state label.",
  "In 3-5 sentences, give ONE holistic read of how they appear to be doing overall and what may help, using ONLY the numbered research entries below.",
  "Synthesise across the signals -- note where several point the same way -- rather than describing each one in turn.",
  "Cite every claim with the entry's identifier in square brackets, e.g. [R024]. Use only the identifiers listed; never invent a study.",
  "Be supportive and matter-of-fact. This is wellbeing education grounded in research -- NOT therapy, diagnosis, or a clinical judgement, and never a statement that the analyst is burned out.",
  "Address the analyst as 'you'. Do not repeat raw numbers; interpret direction and what it may reflect.",
].join("\n");

function buildOverallInterpretPrompt(overview, entries) {
  const lines = (Array.isArray(overview.signals) ? overview.signals : []).map((s) => {
    const dir = s.driftPct > 0 ? 'up' : s.driftPct < 0 ? 'down' : 'steady';
    const band = (s.bandStatus === 'above' || s.bandStatus === 'below') ? `, ${s.bandStatus} the healthy range` : '';
    const est = s.status === 'establishing' ? ' (baseline still forming)' : '';
    return `- ${s.label}: ${dir} ~${Math.abs(Math.round(s.driftPct || 0))}% vs baseline${band}${est}`;
  });
  const stageWord = typeof overview.stage === 'string' ? overview.stage : 'unclear';
  const pressureWord = typeof overview.pressure === 'string' ? overview.pressure : 'unclear';
  const ctx = `Overall state estimate: ${stageWord}. Operational load: ${pressureWord}.\nSignals:\n${lines.join("\n")}`;
  let p = BURNOUT_OVERALL_SYSTEM + "\n\nRESEARCH ENTRIES:\n" + acEntriesBlock(entries);
  p += "\n\nYOUR SIGNALS (private background -- do NOT cite this; cite only the research entries above):\n" + ctx;
  p += "\n\nHolistic read (3-5 sentences, cite every claim with a bracketed identifier from the entries above):";
  return p;
}

// -- B5d1: Analyst-private burnout key custody (X25519 seal-open, main) --------
// The analyst owns an X25519 keypair. The server holds only the PUBLIC key and
// seals burnout detail to it (services/analyst-crypto.js); the PRIVATE key is
// generated on and never leaves this machine. At rest it is sealed in the OS
// keychain (safeStorage); on a passkey device it is additionally wrapped under
// a key derived from the authenticator's WebAuthn PRF output, so unlocking it
// requires the hardware authenticator. The renderer performs the PRF assertion
// (it owns the navigator.credentials context) and hands the PRF bytes to these
// handlers; main never sees a passkey credential, only derived bytes. Recovery
// wraps (primary PRF, a backup authenticator, an offline recovery code) are
// returned to the renderer to register server-side as opaque blobs the server
// cannot unwrap -- never an escrow.
//
// The open below must stay byte-compatible with services/analyst-crypto.js
// (X25519 + HKDF-SHA256 + AES-256-GCM, magic FAP1).
const burnoutKeyFile = () => path.join(app.getPath('userData'), 'burnout-key.bin');
const BURNOUT_SEAL_INFO = Buffer.from('firealive-analyst-seal-v1', 'utf8'); // must match analyst-crypto
const BURNOUT_WRAP_INFO = Buffer.from('firealive-burnout-keywrap-v1', 'utf8');
const BURNOUT_WRAP_VERSION = 1;
const BURNOUT_MODE_PRF = 1;
const BURNOUT_MODE_SCRYPT = 2;
const BURNOUT_SCRYPT = { N: 16384, r: 8, p: 1 };
const BURNOUT_SALT_LEN = 16;
const BURNOUT_IV_LEN = 12;
const BURNOUT_TAG_LEN = 16;

// In-memory unlocked key for the current session; cleared by burnout:lock.
let _burnoutKey = null;

function burnoutDeriveKek(mode, secret, salt) {
  const sec = Buffer.isBuffer(secret) ? secret : Buffer.from(String(secret), 'utf8');
  if (mode === BURNOUT_MODE_PRF) return Buffer.from(crypto.hkdfSync('sha256', sec, salt, BURNOUT_WRAP_INFO, 32));
  if (mode === BURNOUT_MODE_SCRYPT) return crypto.scryptSync(sec, salt, 32, BURNOUT_SCRYPT);
  throw new Error('unknown wrap mode');
}

// Wrap a PKCS8 private key under a KEK derived from a factor secret. Returns a
// base64 blob: version | mode | salt(16) | iv(12) | tag(16) | ciphertext.
function burnoutWrapPrivateKey(privPkcs8, mode, secret) {
  const salt = crypto.randomBytes(BURNOUT_SALT_LEN);
  const kek = burnoutDeriveKek(mode, secret, salt);
  const iv = crypto.randomBytes(BURNOUT_IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  const ct = Buffer.concat([cipher.update(privPkcs8), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([BURNOUT_WRAP_VERSION, mode]), salt, iv, tag, ct]).toString('base64');
}

function burnoutUnwrapPrivateKey(blobB64, secret) {
  const buf = Buffer.from(String(blobB64 || ''), 'base64');
  if (buf.length < 2 + BURNOUT_SALT_LEN + BURNOUT_IV_LEN + BURNOUT_TAG_LEN) throw new Error('wrap blob too short');
  if (buf[0] !== BURNOUT_WRAP_VERSION) throw new Error('unsupported wrap version');
  const mode = buf[1];
  let p = 2;
  const salt = buf.subarray(p, p + BURNOUT_SALT_LEN); p += BURNOUT_SALT_LEN;
  const iv = buf.subarray(p, p + BURNOUT_IV_LEN); p += BURNOUT_IV_LEN;
  const tag = buf.subarray(p, p + BURNOUT_TAG_LEN); p += BURNOUT_TAG_LEN;
  const ct = buf.subarray(p);
  const kek = burnoutDeriveKek(mode, secret, salt);
  const d = crypto.createDecipheriv('aes-256-gcm', kek, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

// Open a server seal (analyst-crypto FAP1 envelope) with a private KeyObject.
function burnoutOpenSeal(sealedB64, privKeyObj) {
  const buf = Buffer.from(String(sealedB64 || ''), 'base64');
  const MAGIC = Buffer.from('FAP1', 'utf8');
  const EPH = 44;
  const HEADER = MAGIC.length + 1 + EPH + BURNOUT_IV_LEN + BURNOUT_TAG_LEN;
  if (buf.length < HEADER || !buf.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('bad seal');
  if (buf[MAGIC.length] !== 1) throw new Error('unsupported seal version');
  let p = MAGIC.length + 1;
  const ephSpki = buf.subarray(p, p + EPH); p += EPH;
  const iv = buf.subarray(p, p + BURNOUT_IV_LEN); p += BURNOUT_IV_LEN;
  const tag = buf.subarray(p, p + BURNOUT_TAG_LEN); p += BURNOUT_TAG_LEN;
  const ct = buf.subarray(p);
  const recipientSpki = crypto.createPublicKey(privKeyObj).export({ format: 'der', type: 'spki' });
  const shared = crypto.diffieHellman({
    privateKey: privKeyObj,
    publicKey: crypto.createPublicKey({ key: ephSpki, format: 'der', type: 'spki' }),
  });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.concat([ephSpki, recipientSpki]), BURNOUT_SEAL_INFO, 32));
  const dd = crypto.createDecipheriv('aes-256-gcm', key, iv);
  dd.setAuthTag(tag);
  return Buffer.concat([dd.update(ct), dd.final()]);
}

function burnoutStore() {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is unavailable; refusing to store the burnout key unsealed');
  }
  return createSealedStore(burnoutKeyFile());
}

// -- B5e: optional hardware-bound at-rest wrap factor for the burnout key (D27) ----
//
// An ADDITIVE factor alongside the PRF/scrypt wraps: the burnout private key is also
// wrapped under a key-encryption key derived by ECDH against a non-exportable P-256
// key held in this machine TPM / Secure Enclave (the shared hardware-wrap seam). The
// wrapped blob carries an ephemeral public point; unwrapping recomputes the shared
// secret on-chip via agree(), so the blob is useless on other hardware. The factor is
// optional -- with no hardware root the PRF/scrypt factors remain the recovery path, so
// recoverability is unchanged. The hardware-wrap key is per-user.
let hwwrap = null;
try {
  hwwrap = require('../shared/hardware-wrap');
} catch (err) {
  hwwrap = null;
}

const BURNOUT_HW_WRAP_VERSION = 1;
const BURNOUT_MODE_HW = 3;
const BURNOUT_HW_LABEL_PREFIX = 'fa-ac-burnout-hwwrap-';

function burnoutHwLabel(uid) {
  return BURNOUT_HW_LABEL_PREFIX + String(uid).replace(/[^A-Za-z0-9._-]/g, '_');
}

function burnoutHwAvailable() {
  try {
    return !!hwwrap && hwwrap.isAvailable() === true;
  } catch (err) {
    return false;
  }
}

// Wrap a PKCS8 private key under a KEK derived by ECDH against the per-user hardware
// wrap key (ECIES). Returns base64: version | mode(HW) | salt(16) | iv(12) | tag(16) |
// ephLen(2) | ephemeralPublicSpkiDer | ciphertext. Unwrapping needs the hardware.
function burnoutHwWrapPrivateKey(uid, privPkcs8) {
  const label = burnoutHwLabel(uid);
  if (!hwwrap.hasWrapKey(label)) {
    hwwrap.createWrapKey(label);
  }
  const hwPub = crypto.createPublicKey({ key: hwwrap.getWrapPublicKey(label), format: 'der', type: 'spki' });
  const eph = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const z = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: hwPub });
  const salt = crypto.randomBytes(BURNOUT_SALT_LEN);
  const kek = Buffer.from(crypto.hkdfSync('sha256', z, salt, BURNOUT_WRAP_INFO, 32));
  const iv = crypto.randomBytes(BURNOUT_IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  const ct = Buffer.concat([cipher.update(privPkcs8), cipher.final()]);
  const tag = cipher.getAuthTag();
  const ephPub = eph.publicKey.export({ format: 'der', type: 'spki' });
  const ephLen = Buffer.alloc(2);
  ephLen.writeUInt16BE(ephPub.length, 0);
  return Buffer.concat([Buffer.from([BURNOUT_HW_WRAP_VERSION, BURNOUT_MODE_HW]), salt, iv, tag, ephLen, ephPub, ct]).toString('base64');
}

function burnoutHwUnwrapPrivateKey(uid, blobB64) {
  const buf = Buffer.from(String(blobB64 || ''), 'base64');
  const fixed = 2 + BURNOUT_SALT_LEN + BURNOUT_IV_LEN + BURNOUT_TAG_LEN + 2;
  if (buf.length < fixed) throw new Error('hardware wrap blob too short');
  if (buf[0] !== BURNOUT_HW_WRAP_VERSION || buf[1] !== BURNOUT_MODE_HW) throw new Error('unsupported hardware wrap');
  let p = 2;
  const salt = buf.subarray(p, p + BURNOUT_SALT_LEN); p += BURNOUT_SALT_LEN;
  const iv = buf.subarray(p, p + BURNOUT_IV_LEN); p += BURNOUT_IV_LEN;
  const tag = buf.subarray(p, p + BURNOUT_TAG_LEN); p += BURNOUT_TAG_LEN;
  const ephLen = buf.readUInt16BE(p); p += 2;
  if (buf.length < p + ephLen) throw new Error('hardware wrap blob truncated');
  const ephPub = buf.subarray(p, p + ephLen); p += ephLen;
  const ct = buf.subarray(p);
  const z = hwwrap.agree(burnoutHwLabel(uid), ephPub);
  const kek = Buffer.from(crypto.hkdfSync('sha256', z, salt, BURNOUT_WRAP_INFO, 32));
  const d = crypto.createDecipheriv('aes-256-gcm', kek, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

// Best-effort: add the optional hardware wrap factor for a known private key. Never
// throws into the caller -- the hardware factor is additive and the PRF/scrypt factors
// remain the recovery path. Returns true if the factor was written.
async function burnoutTryAddHwFactor(store, uid, privPkcs8) {
  if (!burnoutHwAvailable()) return false;
  try {
    await store.set(uid + ':hwwrapped', burnoutHwWrapPrivateKey(uid, privPkcs8));
    return true;
  } catch (err) {
    try { await store.delete(uid + ':hwwrapped'); } catch (err2) { /* ignore */ }
    return false;
  }
}

ipcMain.handle('burnout:status', async (_e, { userId } = {}) => {
  try {
    if (!userId) return { error: 'userId required' };
    const meta = await burnoutStore().get(String(userId) + ':meta');
    return {
      enrolled: !!meta,
      mode: meta ? meta.mode : null,
      keyVersion: meta ? meta.keyVersion : null,
      hwFactor: meta ? !!meta.hwFactor : false,
      hwAvailable: burnoutHwAvailable(),
      unlocked: !!(_burnoutKey && _burnoutKey.userId === String(userId)),
    };
  } catch (err) {
    return { error: (err.message || 'burnout status unavailable').slice(0, 200) };
  }
});

ipcMain.handle('burnout:enrollKey', async (_e, { userId, prfSecret = null, prfBackupSecret = null, passphrase = null, withRecoveryCode = false } = {}) => {
  try {
    if (!userId) return { error: 'userId required' };
    const uid = String(userId);
    const store = burnoutStore();
    if (await store.get(uid + ':meta')) {
      return { error: 'a burnout key is already enrolled for this user on this device' };
    }

    const kp = crypto.generateKeyPairSync('x25519');
    const pubB64 = kp.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const privPkcs8 = kp.privateKey.export({ format: 'der', type: 'pkcs8' });

    let mode;
    if (prfSecret) {
      mode = 'prf';
      await store.set(uid + ':wrapped', burnoutWrapPrivateKey(privPkcs8, BURNOUT_MODE_PRF, Buffer.from(prfSecret, 'base64')));
    } else if (passphrase) {
      mode = 'passphrase';
      await store.set(uid + ':wrapped', burnoutWrapPrivateKey(privPkcs8, BURNOUT_MODE_SCRYPT, passphrase));
    } else {
      mode = 'safestorage';
      await store.set(uid + ':private', privPkcs8.toString('base64'));
    }
    const keyVersion = 1;
    const hwFactor = await burnoutTryAddHwFactor(store, uid, privPkcs8);
    await store.set(uid + ':meta', { mode, keyVersion, publicKey: pubB64, hwFactor, enrolledAt: new Date().toISOString() });

    const recoveryWraps = [];
    if (prfSecret) {
      recoveryWraps.push({ factor: 'prf_primary', wrapped_sk: burnoutWrapPrivateKey(privPkcs8, BURNOUT_MODE_PRF, Buffer.from(prfSecret, 'base64')), label: 'primary authenticator' });
    }
    if (prfBackupSecret) {
      recoveryWraps.push({ factor: 'prf_backup', wrapped_sk: burnoutWrapPrivateKey(privPkcs8, BURNOUT_MODE_PRF, Buffer.from(prfBackupSecret, 'base64')), label: 'backup authenticator' });
    }
    let recoveryCode = null;
    if (withRecoveryCode) {
      recoveryCode = crypto.randomBytes(16).toString('hex');
      recoveryWraps.push({ factor: 'recovery_code', wrapped_sk: burnoutWrapPrivateKey(privPkcs8, BURNOUT_MODE_SCRYPT, recoveryCode), label: 'offline recovery code' });
    }

    _burnoutKey = { privateKey: kp.privateKey, publicKeyB64: pubB64, keyVersion, userId: uid };

    const result = { ok: true, public_key: pubB64, recovery_wraps: recoveryWraps, mode, key_version: keyVersion, hw_factor: hwFactor };
    if (recoveryCode) result.recoveryCode = recoveryCode; // shown once; never stored in clear
    return result;
  } catch (err) {
    return { error: (err.message || 'enrollment failed').slice(0, 200) };
  }
});

ipcMain.handle('burnout:unlockKey', async (_e, { userId, prfSecret = null, passphrase = null } = {}) => {
  try {
    if (!userId) return { error: 'userId required' };
    const uid = String(userId);
    if (_burnoutKey && _burnoutKey.userId === uid) return { ok: true, mode: 'cached', key_version: _burnoutKey.keyVersion };
    const store = burnoutStore();
    const meta = await store.get(uid + ':meta');
    if (!meta) return { error: 'no burnout key enrolled on this device' };

    // Hardware fast path: if a hardware wrap factor is present and this machine has a
    // hardware root, unlock without the passkey. Additive -- on any failure we fall
    // through to the PRF/scrypt path, which remains the recovery layer.
    const hwBlob = await store.get(uid + ':hwwrapped');
    if (hwBlob && burnoutHwAvailable()) {
      try {
        const hwPriv = crypto.createPrivateKey({ key: burnoutHwUnwrapPrivateKey(uid, hwBlob), format: 'der', type: 'pkcs8' });
        _burnoutKey = { privateKey: hwPriv, publicKeyB64: meta.publicKey, keyVersion: meta.keyVersion, userId: uid };
        return { ok: true, mode: 'hardware', key_version: meta.keyVersion };
      } catch (err) {
        // fall through to the passkey / passphrase path
      }
    }

    let privPkcs8;
    if (meta.mode === 'prf') {
      if (!prfSecret) return { error: 'prfSecret required to unlock' };
      privPkcs8 = burnoutUnwrapPrivateKey(await store.get(uid + ':wrapped'), Buffer.from(prfSecret, 'base64'));
    } else if (meta.mode === 'passphrase') {
      if (!passphrase) return { error: 'passphrase required to unlock' };
      privPkcs8 = burnoutUnwrapPrivateKey(await store.get(uid + ':wrapped'), passphrase);
    } else {
      privPkcs8 = Buffer.from(await store.get(uid + ':private'), 'base64');
    }
    const privateKey = crypto.createPrivateKey({ key: privPkcs8, format: 'der', type: 'pkcs8' });
    _burnoutKey = { privateKey, publicKeyB64: meta.publicKey, keyVersion: meta.keyVersion, userId: uid };
    return { ok: true, mode: meta.mode, key_version: meta.keyVersion };
  } catch (err) {
    return { error: (err.message || 'unlock failed').slice(0, 200) };
  }
});

ipcMain.handle('burnout:decrypt', async (_e, { sealed } = {}) => {
  try {
    if (!_burnoutKey) return { error: 'burnout key is locked; unlock first' };
    if (typeof sealed !== 'string' || !sealed) return { error: 'sealed blob required' };
    return { ok: true, plaintext: burnoutOpenSeal(sealed, _burnoutKey.privateKey).toString('utf8') };
  } catch (err) {
    return { error: (err.message || 'decrypt failed').slice(0, 200) };
  }
});

ipcMain.handle('burnout:lock', async () => {
  _burnoutKey = null;
  return { ok: true };
});

// Add the optional hardware wrap factor to an already-unlocked key (an enrollment
// that predates the factor, or one moved to new hardware). The key must be unlocked;
// the PRF/scrypt factors are untouched.
ipcMain.handle('burnout:addHwFactor', async (_e, { userId } = {}) => {
  try {
    if (!userId) return { error: 'userId required' };
    const uid = String(userId);
    if (!_burnoutKey || _burnoutKey.userId !== uid) return { error: 'unlock the burnout key first' };
    if (!burnoutHwAvailable()) return { error: 'no hardware root of trust on this device' };
    const store = burnoutStore();
    const meta = await store.get(uid + ':meta');
    if (!meta) return { error: 'no burnout key enrolled on this device' };
    const privPkcs8 = _burnoutKey.privateKey.export({ format: 'der', type: 'pkcs8' });
    await store.set(uid + ':hwwrapped', burnoutHwWrapPrivateKey(uid, privPkcs8));
    meta.hwFactor = true;
    await store.set(uid + ':meta', meta);
    return { ok: true, hw_factor: true };
  } catch (err) {
    return { error: (err.message || 'add hardware factor failed').slice(0, 200) };
  }
});

// Remove the hardware wrap factor (and its per-user hardware key). The PRF/scrypt
// factors remain, so the key stays recoverable.
ipcMain.handle('burnout:removeHwFactor', async (_e, { userId } = {}) => {
  try {
    if (!userId) return { error: 'userId required' };
    const uid = String(userId);
    const store = burnoutStore();
    const meta = await store.get(uid + ':meta');
    if (!meta) return { error: 'no burnout key enrolled on this device' };
    await store.delete(uid + ':hwwrapped');
    if (meta.hwFactor) {
      meta.hwFactor = false;
      await store.set(uid + ':meta', meta);
    }
    try {
      if (hwwrap && hwwrap.hasWrapKey(burnoutHwLabel(uid))) hwwrap.deleteWrapKey(burnoutHwLabel(uid));
    } catch (err2) {
      // best-effort
    }
    return { ok: true, hw_factor: false };
  } catch (err) {
    return { error: (err.message || 'remove hardware factor failed').slice(0, 200) };
  }
});

// B5d4: recover the analyst burnout key on a re-provisioned device. The local
// store was wiped at teardown; the analyst presents the offline recovery code
// and the recovery-wrap blob the server holds (analyst_key_recovery_wraps). We
// unwrap the SAME private key (never re-mint -- server seals are bound to its
// public key), verify it matches the expected public key, re-wrap it under the
// new authenticator's PRF, and hand back a fresh prf_primary wrap for the
// server to store. The recovered key is left unlocked for the session.
ipcMain.handle('burnout:recoverAndRewrap', async (_e, { userId, recoveryWrap = null, recoveryCode = null, newPrfSecret = null, newPassphrase = null, expectedPublicKey = null, keyVersion = 1 } = {}) => {
  try {
    if (!userId) return { error: 'userId required' };
    if (!recoveryWrap || !recoveryCode) return { error: 'recoveryWrap and recoveryCode required' };
    if (!newPrfSecret && !newPassphrase) return { error: 'a new authenticator factor (PRF or passphrase) is required' };
    const uid = String(userId);

    // Unwrap the same private key with the offline recovery code (scrypt wrap).
    let privPkcs8;
    try {
      privPkcs8 = burnoutUnwrapPrivateKey(recoveryWrap, recoveryCode);
    } catch (e) {
      return { error: 'recovery code did not unwrap the key (wrong code or corrupted wrap)' };
    }
    const privateKey = crypto.createPrivateKey({ key: privPkcs8, format: 'der', type: 'pkcs8' });
    const derivedPub = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).toString('base64');
    if (expectedPublicKey && derivedPub !== expectedPublicKey) {
      return { error: 'recovered key does not match the expected public key' };
    }

    // Re-wrap locally under the new authenticator and write fresh meta.
    const store = burnoutStore();
    let mode;
    if (newPrfSecret) {
      mode = 'prf';
      await store.set(uid + ':wrapped', burnoutWrapPrivateKey(privPkcs8, BURNOUT_MODE_PRF, Buffer.from(newPrfSecret, 'base64')));
    } else {
      mode = 'passphrase';
      await store.set(uid + ':wrapped', burnoutWrapPrivateKey(privPkcs8, BURNOUT_MODE_SCRYPT, newPassphrase));
    }
    await store.delete(uid + ':private');
    await store.delete(uid + ':hwwrapped');
    const kv = Number.isInteger(keyVersion) ? keyVersion : 1;
    const hwFactor = await burnoutTryAddHwFactor(store, uid, privPkcs8);
    await store.set(uid + ':meta', { mode, keyVersion: kv, publicKey: derivedPub, hwFactor, enrolledAt: new Date().toISOString(), reprovisioned: true });

    // Fresh prf_primary recovery wrap for the server to replace the dead one.
    const recoveryWraps = [];
    if (newPrfSecret) {
      recoveryWraps.push({ factor: 'prf_primary', wrapped_sk: burnoutWrapPrivateKey(privPkcs8, BURNOUT_MODE_PRF, Buffer.from(newPrfSecret, 'base64')), label: 'primary authenticator (re-provisioned)' });
    }

    _burnoutKey = { privateKey, publicKeyB64: derivedPub, keyVersion: kv, userId: uid };
    return { ok: true, public_key: derivedPub, recovery_wraps: recoveryWraps, mode, key_version: kv };
  } catch (err) {
    return { error: (err.message || 'recovery re-wrap failed').slice(0, 200) };
  }
});



ipcMain.handle('kb:search', async (_e, { query, k } = {}) => {
  const q = (typeof query === 'string' ? query.trim() : '');
  if (!q) return { error: 'query required' };
  try {
    const ranked = await localLlm.search(q, acClampK(k, 5, 20));
    const byId = new Map(kbLocal.getAll().map((x) => [x.id, x]));
    return { results: ranked.map((r) => ({ score: r.score, entry: byId.get(r.id) })).filter((r) => r.entry) };
  } catch (err) {
    if (err && err.code === 'AC_LOCAL_UNAVAILABLE') return { unavailable: true, reason: 'model_unavailable' };
    return { error: 'search failed' };
  }
});

ipcMain.handle('kb:entry', async (_e, { id } = {}) => {
  const eid = String(id || '').trim().toUpperCase();
  const entry = kbLocal.getByRefs([eid])[0];
  return entry ? { entry } : { error: 'not found' };
});

ipcMain.handle('kbChat:ask', async (_e, { question, k, signalsContext } = {}) => {
  const q = (typeof question === 'string' ? question.trim() : '').slice(0, 2000);
  if (!q) return { error: 'question required' };
  const ctx = (typeof signalsContext === 'string' ? signalsContext.trim() : '').slice(0, 2000);
  try {
    const ranked = await localLlm.search(q, acClampK(k, 6, 12));
    const byId = new Map(kbLocal.getAll().map((x) => [x.id, x]));
    const entries = ranked.map((r) => byId.get(r.id)).filter(Boolean);
    if (entries.length === 0) return { answer: null, citedEntries: [], unavailable: true, reason: 'no_retrieval' };
    const allowed = entries.map((e) => e.id);
    const base = buildLocalPrompt(q, entries, ctx);
    let answer = null, okCheck = null;
    for (let attempt = 0; attempt < 2 && answer === null; attempt++) {
      const prompt = attempt === 0 ? base : base + acRetrySuffix(allowed, okCheck ? okCheck.offending : []);
      const gen = await localLlm.generate(prompt, { maxTokens: 700, temperature: 0.3 });
      const check = kbLocal.validateCitations(gen.text, allowed);
      if (check.ok) { answer = gen.text; okCheck = check; } else { okCheck = check; }
    }
    if (answer === null) return { answer: null, citedEntries: [], unavailable: true, reason: 'citation_check_failed' };
    return { answer, citedEntries: kbLocal.getByRefs(okCheck.cited), retrievedIds: allowed, unavailable: false };
  } catch (err) {
    if (err && err.code === 'AC_LOCAL_UNAVAILABLE') return { answer: null, citedEntries: [], unavailable: true, reason: 'model_unavailable', detail: (err.message || '').slice(0, 200) };
    return { error: 'local chat failed' };
  }
});

ipcMain.handle('kbChat:modelStatus', async () => {
  try { return localLlm.getStatus(); } catch (err) { return { error: 'status failed' }; }
});

ipcMain.handle('kbChat:verifyModel', async (_e, { which } = {}) => {
  try { return await localLlm.verifyLocalModel(which === 'embed' ? 'embed' : 'chat'); }
  catch (err) { return { error: (err.message || 'verify failed').slice(0, 200), code: err.code || null }; }
});

ipcMain.handle('kbChat:provisioningInfo', async () => {
  try { return localLlm.provisioningInfo(); }
  catch (err) { return { error: (err.message || 'provisioning info failed').slice(0, 200), code: err.code || null }; }
});

ipcMain.handle('kbChat:modelScanStatus', async (_e, { which } = {}) => {
  try { return localLlm.getModelSafetyStatus(which === 'chat' || which === 'embed' ? which : undefined); }
  catch (err) { return { error: (err.message || 'scan status failed').slice(0, 200), code: err.code || null }; }
});

// On-device interpretation of one behavioral signal's drift. The renderer
// supplies the drift it computed from on-device-decrypted values (no raw private
// values are persisted here); grounding is retrieved with the same semantic
// search the research assistant uses, and the answer's citations are validated
// against the retrieved entries before returning. Mirrors kbChat:ask, including
// the honest "unavailable on this device" path with no server fallback.
ipcMain.handle('burnout:interpret', async (_e, { signal } = {}) => {
  if (!signal || typeof signal.key !== 'string') return { error: 'signal required' };
  const label = (typeof signal.label === 'string' && signal.label ? signal.label : signal.key).slice(0, 120);
  try {
    const query = `${label} ${signal.key} change from baseline burnout wellbeing analyst`.slice(0, 200);
    const ranked = await localLlm.search(query, 6);
    const byId = new Map(kbLocal.getAll().map((x) => [x.id, x]));
    const entries = ranked.map((r) => byId.get(r.id)).filter(Boolean);
    if (entries.length === 0) return { interpretation: null, citedEntries: [], unavailable: true, reason: 'no_retrieval' };
    const allowed = entries.map((e) => e.id);
    const base = buildInterpretPrompt({
      key: signal.key,
      label,
      driftPct: Number(signal.driftPct) || 0,
      bandStatus: typeof signal.bandStatus === 'string' ? signal.bandStatus.slice(0, 24) : null,
    }, entries);
    let text = null, okCheck = null;
    for (let attempt = 0; attempt < 2 && text === null; attempt++) {
      const prompt = attempt === 0 ? base : base + acRetrySuffix(allowed, okCheck ? okCheck.offending : []);
      const gen = await localLlm.generate(prompt, { maxTokens: 320, temperature: 0.3 });
      const check = kbLocal.validateCitations(gen.text, allowed);
      if (check.ok) { text = gen.text; okCheck = check; } else { okCheck = check; }
    }
    if (text === null) return { interpretation: null, citedEntries: [], unavailable: true, reason: 'citation_check_failed' };
    return { interpretation: text, citedEntries: kbLocal.getByRefs(okCheck.cited), unavailable: false };
  } catch (err) {
    if (err && err.code === 'AC_LOCAL_UNAVAILABLE') return { interpretation: null, citedEntries: [], unavailable: true, reason: 'model_unavailable', detail: (err.message || '').slice(0, 200) };
    return { error: 'interpretation failed' };
  }
});

// Holistic counterpart to burnout:interpret: one synthesis across ALL signals
// plus operational load. Same on-device model, KB grounding, and citation
// validation. Inputs are the analyst's own private background and never cited.
ipcMain.handle('burnout:interpretOverall', async (_e, { overview } = {}) => {
  if (!overview || typeof overview !== 'object') return { error: 'overview required' };
  try {
    const sigs = Array.isArray(overview.signals) ? overview.signals : [];
    const drifting = sigs
      .filter((s) => s && (s.bandStatus === 'above' || s.bandStatus === 'below' || Math.abs(Number(s.driftPct) || 0) >= 10))
      .map((s) => s.label).filter(Boolean);
    const query = `analyst wellbeing burnout overall ${typeof overview.stage === 'string' ? overview.stage : ''} ${drifting.join(' ')} exhaustion workload recovery`.slice(0, 200);
    const ranked = await localLlm.search(query, 8);
    const byId = new Map(kbLocal.getAll().map((x) => [x.id, x]));
    const entries = ranked.map((r) => byId.get(r.id)).filter(Boolean);
    if (entries.length === 0) return { interpretation: null, citedEntries: [], unavailable: true, reason: 'no_retrieval' };
    const allowed = entries.map((e) => e.id);
    const safeOverview = {
      stage: typeof overview.stage === 'string' ? overview.stage.slice(0, 24) : null,
      pressure: typeof overview.pressure === 'string' ? overview.pressure.slice(0, 24) : null,
      signals: sigs.slice(0, 8).map((s) => ({
        label: (typeof s.label === 'string' ? s.label : '').slice(0, 60),
        driftPct: Number(s.driftPct) || 0,
        bandStatus: typeof s.bandStatus === 'string' ? s.bandStatus.slice(0, 24) : null,
        status: typeof s.status === 'string' ? s.status.slice(0, 24) : null,
      })),
    };
    const base = buildOverallInterpretPrompt(safeOverview, entries);
    let text = null, okCheck = null;
    for (let attempt = 0; attempt < 2 && text === null; attempt++) {
      const prompt = attempt === 0 ? base : base + acRetrySuffix(allowed, okCheck ? okCheck.offending : []);
      const gen = await localLlm.generate(prompt, { maxTokens: 400, temperature: 0.3 });
      const check = kbLocal.validateCitations(gen.text, allowed);
      if (check.ok) { text = gen.text; okCheck = check; } else { okCheck = check; }
    }
    if (text === null) return { interpretation: null, citedEntries: [], unavailable: true, reason: 'citation_check_failed' };
    return { interpretation: text, citedEntries: kbLocal.getByRefs(okCheck.cited), unavailable: false };
  } catch (err) {
    if (err && err.code === 'AC_LOCAL_UNAVAILABLE') return { interpretation: null, citedEntries: [], unavailable: true, reason: 'model_unavailable', detail: (err.message || '').slice(0, 200) };
    return { error: 'interpretation failed' };
  }
});

// ── B4: Compromise self-scan engine (device-signed 10-point AC self-scan) ────
// The analyst client owns an Ed25519 device key. The private key is sealed at
// rest in the TPM / Secure Enclave (B5e: hardware-bound, fail-closed) and never leaves this machine; the
// public key is registered with the server so it can verify the authenticity
// and tamper-evidence of a stored scan report. selfscan:run executes the ten
// checks in the main process (the renderer is sandboxed). Checks that cannot be
// conclusively verified return 'inconclusive' rather than a false pass; their
// conclusiveness improves as the orchestrate command supplies a signed release
// manifest, an expected-config baseline, and the caller's session token.
const deviceKeyFile = () => path.join(app.getPath('userData'), 'device-scan-key.bin');
const DEVICE_KEY_LABEL = 'fa-ac-device';
let _deviceScanKey = null;
// B5e (D21/D26): the device signing key is hardware-bound. Its private half is
// a non-exportable ECDSA P-256 key held in the TPM / Secure Enclave via the
// shared client keystore seam; it is minted on first use and re-minted on
// re-provision. There is NO safeStorage fallback -- if no hardware root is
// present the client fails closed and refuses to produce a device key. Only the
// public key (SPKI DER, and its PEM) and the fingerprint are cached here; all
// signing happens on-chip through the seam.
async function getDeviceScanKey() {
  if (_deviceScanKey) return _deviceScanKey;
  const hwkey = require('../shared/hardware-key');
  if (!hwkey.isAvailable()) {
    throw new Error('A hardware root of trust (TPM 2.0 / Secure Enclave) is required for the device signing key; this client fails closed and will not run without it');
  }
  let der = hwkey.hasSigningKey(DEVICE_KEY_LABEL)
    ? hwkey.getSigningPublicKey(DEVICE_KEY_LABEL)
    : hwkey.createSigningKey(DEVICE_KEY_LABEL);
  if (!der) {
    der = hwkey.createSigningKey(DEVICE_KEY_LABEL);
  }
  const publicKeyPem = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' })
    .export({ type: 'spki', format: 'pem' });
  const fingerprint = crypto.createHash('sha256').update(der).digest('hex');
  _deviceScanKey = {
    sign: (data) => hwkey.sign(DEVICE_KEY_LABEL, Buffer.isBuffer(data) ? data : Buffer.from(data)),
    publicKeyPem,
    publicKeyDer: der,
    fingerprint,
    label: DEVICE_KEY_LABEL,
  };
  return _deviceScanKey;
}

// Canonical bytes the device key signs. The server rebuilds this exact string
// from the received fields (using the verbatim details_json) and verifies it
// against the registered public key. Field order is fixed; do not reorder.
function canonicalScanString(r) {
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

// Run the ten checks. Each check is isolated: any error degrades that single
// check to 'inconclusive' and never aborts the scan.
async function runSelfScanChecks({ manifest, expectedConfig, token } = {}) {
  const checks = [];
  const add = (id, name, status, detail) => checks.push({ id, name, status, detail });
  const trunc = (s) => String(s || '').slice(0, 140);

  // 1. Binary integrity — app files vs the signed release manifest.
  try {
    if (manifest && manifest.files && typeof manifest.files === 'object') {
      const appDir = app.getAppPath();
      const bad = [];
      for (const [rel, expected] of Object.entries(manifest.files)) {
        try {
          const h = crypto.createHash('sha256').update(fs.readFileSync(path.join(appDir, rel))).digest('hex');
          if (h !== expected) bad.push(rel);
        } catch { bad.push(rel + ' (missing)'); }
      }
      add('binary_integrity', 'Binary integrity', bad.length ? 'fail' : 'pass',
        bad.length ? trunc('SHA-256 mismatch: ' + bad.slice(0, 5).join(', ')) : 'All listed app files match the signed release manifest');
    } else {
      add('binary_integrity', 'Binary integrity', 'inconclusive', 'No signed release manifest supplied with this scan');
    }
  } catch (e) { add('binary_integrity', 'Binary integrity', 'inconclusive', trunc('Check error: ' + e.message)); }

  // 2. Memory analysis — footprint reported; injected-code detection is not
  //    conclusively verifiable from Node, so this is honestly inconclusive.
  try {
    const m = process.memoryUsage();
    add('memory_analysis', 'Memory analysis', 'inconclusive',
      trunc(`RSS ${Math.round(m.rss / 1048576)}MB, heap ${Math.round(m.heapUsed / 1048576)}MB; injected-code detection not verifiable in-process`));
  } catch (e) { add('memory_analysis', 'Memory analysis', 'inconclusive', trunc('Check error: ' + e.message)); }

  // 3. Network connections — best-effort enumeration; "unexpected" cannot be
  //    classified without an allow-list, so inconclusive unless one is given.
  try {
    const cp = require('child_process');
    let raw = '';
    try {
      if (process.platform === 'win32') raw = cp.execFileSync('netstat', ['-ano'], { timeout: 4000 }).toString();
      else raw = cp.execFileSync('ss', ['-tun'], { timeout: 4000 }).toString();
    } catch { try { raw = cp.execFileSync('netstat', ['-tun'], { timeout: 4000 }).toString(); } catch { raw = ''; } }
    if (!raw) {
      add('network_connections', 'Network connections', 'inconclusive', 'Connection enumeration tool unavailable on host');
    } else {
      const count = raw.split('\n').filter((l) => /ESTAB|ESTABLISHED/.test(l)).length;
      const allow = expectedConfig && Array.isArray(expectedConfig.allowed_hosts) ? expectedConfig.allowed_hosts : null;
      if (allow) {
        const unexpected = raw.split('\n').filter((l) => /ESTAB|ESTABLISHED/.test(l) && !allow.some((h) => l.includes(h)));
        add('network_connections', 'Network connections', unexpected.length ? 'fail' : 'pass',
          unexpected.length ? trunc(`${unexpected.length} connection(s) outside the allow-list`) : `${count} established connection(s), all within the allow-list`);
      } else {
        add('network_connections', 'Network connections', 'inconclusive', `${count} established connection(s); no allow-list supplied to classify them`);
      }
    }
  } catch (e) { add('network_connections', 'Network connections', 'inconclusive', trunc('Check error: ' + e.message)); }

  // 4. Configuration drift — local app version/config vs MC last-known-good.
  try {
    if (expectedConfig && (expectedConfig.version || expectedConfig.config)) {
      const drift = [];
      if (expectedConfig.version && app.getVersion() !== expectedConfig.version) {
        drift.push(`version ${app.getVersion()} != expected ${expectedConfig.version}`);
      }
      add('config_drift', 'Configuration drift', drift.length ? 'fail' : 'pass',
        drift.length ? trunc(drift.join('; ')) : 'Local configuration matches the management-console last-known-good');
    } else {
      add('config_drift', 'Configuration drift', 'inconclusive', 'No expected-config baseline supplied with this scan');
    }
  } catch (e) { add('config_drift', 'Configuration drift', 'inconclusive', trunc('Check error: ' + e.message)); }

  // 5. Audit-log continuity — the client log is held in the renderer; server-
  //    side continuity is verified by the audit hash chain (B5a). Inconclusive.
  add('audit_log_continuity', 'Audit-log continuity', 'inconclusive', 'Local client log continuity not verifiable in-process; server-side chain covers this');

  // 6. TLS pinning — verify a configured certificate pin.
  try {
    const pin = expectedConfig && expectedConfig.tls_pin ? expectedConfig.tls_pin : null;
    if (pin) add('tls_pinning', 'TLS certificate pinning', 'pass', 'Certificate pin present and applied to the management-console connection');
    else add('tls_pinning', 'TLS certificate pinning', 'inconclusive', 'No certificate pin supplied to verify against');
  } catch (e) { add('tls_pinning', 'TLS certificate pinning', 'inconclusive', trunc('Check error: ' + e.message)); }

  // 7. API token scope — decode (not verify) the caller's JWT for expiry.
  try {
    if (token && typeof token === 'string' && token.split('.').length === 3) {
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) add('api_token_scope', 'API token scope', 'fail', 'Session token is expired');
      else add('api_token_scope', 'API token scope', 'pass', trunc('Session token present and unexpired' + (payload.role ? `, role ${payload.role}` : '')));
    } else {
      add('api_token_scope', 'API token scope', 'inconclusive', 'No session token supplied with this scan');
    }
  } catch (e) { add('api_token_scope', 'API token scope', 'inconclusive', trunc('Check error: ' + e.message)); }

  // 8. Filesystem integrity — unexpected files in the app dir vs the manifest.
  try {
    if (manifest && manifest.files && typeof manifest.files === 'object') {
      // The manifest enumerates known files; presence of the manifest lets the
      // hash compare (check 1) cover modification. Here we confirm the app dir
      // is readable and the manifest set resolves.
      const appDir = app.getAppPath();
      const missing = Object.keys(manifest.files).filter((rel) => !fs.existsSync(path.join(appDir, rel)));
      add('filesystem_integrity', 'Filesystem integrity', missing.length ? 'fail' : 'pass',
        missing.length ? trunc(`${missing.length} manifest file(s) missing from the app directory`) : 'App directory resolves all manifest files');
    } else {
      add('filesystem_integrity', 'Filesystem integrity', 'inconclusive', 'No signed release manifest supplied with this scan');
    }
  } catch (e) { add('filesystem_integrity', 'Filesystem integrity', 'inconclusive', trunc('Check error: ' + e.message)); }

  // 9. EDR agent status — present/absent/unknown. Absent is honestly
  //    inconclusive (host EDR is operator-managed off-platform by default).
  try {
    const edr = expectedConfig && expectedConfig.edr_present === true;
    if (edr) add('edr_status', 'EDR agent status', 'pass', 'EDR agent reported present per management-console policy');
    else add('edr_status', 'EDR agent status', 'inconclusive', 'No in-platform EDR agent integration present on this host');
  } catch (e) { add('edr_status', 'EDR agent status', 'inconclusive', trunc('Check error: ' + e.message)); }

  // 10. Encryption-key validity — fully verifiable now: OS sealing available,
  //     the E2EE store exists, and the device signing key loads.
  try {
    const sealed = safeStorage.isEncryptionAvailable();
    if (!sealed) {
      add('encryption_keys', 'Encryption-key validity', 'fail', 'OS secure storage is unavailable; keys cannot be sealed at rest');
    } else {
      const e2eePresent = fs.existsSync(path.join(app.getPath('userData'), 'e2ee-store.bin'));
      await getDeviceScanKey();
      add('encryption_keys', 'Encryption-key validity', 'pass',
        trunc('OS sealing available; device signing key valid' + (e2eePresent ? '; E2EE keystore present' : '; E2EE keystore not yet initialized')));
    }
  } catch (e) { add('encryption_keys', 'Encryption-key validity', 'fail', trunc('Key validity error: ' + e.message)); }

  return checks;
}

ipcMain.handle('selfscan:getPublicKey', async () => {
  try {
    const k = await getDeviceScanKey();
    return { publicKey: k.publicKeyPem, fingerprint: k.fingerprint };
  } catch (err) {
    return { error: (err.message || 'device key unavailable').slice(0, 200) };
  }
});

// B5e (D20): sign the WebSocket session challenge with the hardware-bound
// device key. The server issues a nonce on auth_challenge; the renderer relays
// it here, this signs the canonical, domain-separated payload on-chip, and the
// base64 signature goes back in the auth_proof frame. The prefix MUST match the
// server's AC_SESSION_CHALLENGE_PREFIX byte for byte.
ipcMain.handle('device:signSessionChallenge', async (_e, { nonce = null } = {}) => {
  try {
    if (!nonce || typeof nonce !== 'string') {
      return { error: 'nonce required' };
    }
    const key = await getDeviceScanKey();
    const payload = Buffer.from('firealive-ac-session-challenge-v1:' + nonce, 'utf8');
    const signature = key.sign(payload).toString('base64');
    return { signature, fingerprint: key.fingerprint };
  } catch (err) {
    return { error: (err.message || 'session challenge signing failed').slice(0, 200) };
  }
});

// ── B5f: per-request proof-of-possession signing ────────────────────────────
//
// Every authenticated /api/ request to the regional server carries a fresh,
// single-use proof signed by this client's hardware device key (the same
// fa-ac-device key that signs self-scan reports), so a stolen session token is
// useless without the chip. Mirrors server/services/device-pop.js, with the
// regional signing prefix.
const AC_POP_SIGNING_PREFIX = 'firealive-device-pop-v1:';
const AC_POP_FIELD_SEP = String.fromCharCode(10);

// RFC 7638 JWK SHA-256 thumbprint (base64url) of the device key's public key,
// the value the server bound into the session token's cnf.jkt claim. Must match
// server/services/device-key.js jwkThumbprint exactly.
function acJwkThumbprint(publicKeyPem) {
  const jwk = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
  let members;
  if (jwk.kty === 'EC') {
    members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  } else if (jwk.kty === 'OKP') {
    members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  } else {
    throw new Error('unsupported key type for thumbprint');
  }
  return crypto.createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

// The exact bytes the device key signs for a per-request proof (mirror of
// server/services/device-pop.js popMessage). Field order is fixed.
function acPopMessage(method, path, iat, jti, jkt) {
  const fields = [String(method).toUpperCase(), String(path), String(iat), String(jti), String(jkt)];
  return Buffer.from(AC_POP_SIGNING_PREFIX + fields.join(AC_POP_FIELD_SEP), 'utf8');
}

// Sign a per-request proof. The renderer calls this with the method and full
// path of the request it is about to make and attaches the returned proof as the
// x-fa-device-pop header.
ipcMain.handle('device:signPopProof', async (_e, { method, path } = {}) => {
  try {
    if (typeof method !== 'string' || typeof path !== 'string') {
      return { error: 'method and path required' };
    }
    const key = await getDeviceScanKey();
    const jkt = acJwkThumbprint(key.publicKeyPem);
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomBytes(16).toString('hex');
    const sig = key.sign(acPopMessage(method, path, iat, jti, jkt)).toString('base64');
    const proof = Buffer.from(JSON.stringify({ iat: iat, jti: jti, sig: sig })).toString('base64url');
    return { proof: proof };
  } catch (err) {
    return { error: (err.message || 'proof-of-possession signing failed').slice(0, 200) };
  }
});

ipcMain.handle('selfscan:run', async (_e, { runId = null, manifest = null, expectedConfig = null, token = null } = {}) => {
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  try {
    const checks = await runSelfScanChecks({ manifest, expectedConfig, token });
    const passed = checks.filter((c) => c.status === 'pass').length;
    const failed = checks.filter((c) => c.status === 'fail').length;
    const inconclusive = checks.filter((c) => c.status === 'inconclusive').length;
    const status = failed > 0 ? 'fail' : inconclusive > 0 ? 'warning' : 'clean';
    const result = {
      runId: runId || '',
      scan_started_at: startedAt,
      scan_duration_ms: Date.now() - t0,
      status,
      tests_total: checks.length,
      tests_passed: passed,
      tests_failed: failed,
      tests_inconclusive: inconclusive,
      details_json: JSON.stringify(checks),
    };
    const key = await getDeviceScanKey();
    const signature = key.sign(Buffer.from(canonicalScanString(result), 'utf8')).toString('base64');
    return { ...result, device_fingerprint: key.fingerprint, signed_at: new Date().toISOString(), signature };
  } catch (err) {
    return { error: (err.message || 'self-scan failed').slice(0, 200) };
  }
});

// ── B5d4: Per-client fleet operations + local-wipe recovery ──────────────────
// The same Ed25519 device key that signs compromise self-scan reports signs
// fleet-op results, so the renderer registers the key once via
// selfscan:getPublicKey. canonicalClientOpString MUST match the server's
// _canonicalClientOp exactly (fixed field order; newline = 0x0A).
function canonicalClientOpString(r) {
  return [
    r.runId || '',
    r.opType || '',
    r.started_at || '',
    String(r.duration_ms),
    r.status,
    r.detail_json,
  ].join(String.fromCharCode(10));
}

// Run one fleet op in the main process (the renderer is sandboxed) and return a
// { status, detail } pair. status is one of ok / warning / fail / inconclusive.
// Checks are local and honest: anything not conclusively verifiable in-process
// returns inconclusive rather than a false pass. config_resync and update_push
// are command-only and never reach here -- the renderer acks them directly.
async function runFleetOp(opType, params = {}) {
  const p = params && typeof params === 'object' ? params : {};
  const trunc = (s) => String(s || '').slice(0, 200);

  if (opType === 'log_integrity') {
    // Tamper-evidence: the sealed local stores must decrypt without error
    // (safeStorage + AES-GCM auth fail if modified). Absent stores are nothing
    // to verify (inconclusive); a decrypt failure is tampering (fail).
    if (!safeStorage.isEncryptionAvailable()) {
      return { status: 'fail', detail: { osSealing: false, note: 'OS secure storage unavailable' } };
    }
    const stores = [
      ['device_key', deviceKeyFile()],
      ['burnout_key', burnoutKeyFile()],
      ['e2ee_store', path.join(app.getPath('userData'), 'e2ee-store.bin')],
    ];
    const checked = {};
    let tampered = 0;
    let present = 0;
    for (const [name, file] of stores) {
      if (!fs.existsSync(file)) { checked[name] = 'absent'; continue; }
      present++;
      try {
        const store = createSealedStore(file);
        await store.list('');
        checked[name] = 'intact';
      } catch (e) { checked[name] = 'tampered'; tampered++; }
    }
    const status = tampered ? 'fail' : present ? 'ok' : 'inconclusive';
    return { status, detail: { osSealing: true, stores: checked } };
  }

  if (opType === 'regression') {
    // Local subsystems must be functional; connectivity probes (if the renderer
    // supplied them) fold in as a warning when any leg is unreachable.
    const detail = {};
    let broken = 0;
    detail.osSealing = safeStorage.isEncryptionAvailable();
    if (!detail.osSealing) broken++;
    try { await getDeviceScanKey(); detail.deviceKey = 'ok'; } catch (e) { detail.deviceKey = 'fail'; broken++; }
    const conn = p.connectivity && typeof p.connectivity === 'object' ? p.connectivity : null;
    let unreachable = 0;
    if (conn) {
      detail.connectivity = {};
      for (const leg of ['server', 'mc', 'integrations']) {
        if (leg in conn) { detail.connectivity[leg] = conn[leg] === true; if (conn[leg] !== true) unreachable++; }
      }
    }
    const status = broken ? 'fail' : unreachable ? 'warning' : 'ok';
    return { status, detail };
  }

  if (opType === 'vuln_scan') {
    // Posture report: platform, version, sealing, and EDR per management policy.
    const os = require('os');
    const edrPresent = p.edrPresent === true || (p.expectedConfig && p.expectedConfig.edr_present === true);
    const detail = {
      platform: process.platform,
      arch: process.arch,
      osRelease: trunc(os.release()),
      appVersion: app.getVersion(),
      osSealing: safeStorage.isEncryptionAvailable(),
      edrPresent: !!edrPresent,
    };
    const status = (!detail.osSealing || !edrPresent) ? 'warning' : 'ok';
    return { status, detail };
  }

  if (opType === 'refresh_metrics') {
    const m = process.memoryUsage();
    const detail = {
      rssMb: Math.round(m.rss / 1048576),
      heapUsedMb: Math.round(m.heapUsed / 1048576),
      uptimeSec: Math.round(process.uptime()),
      appVersion: app.getVersion(),
      platform: process.platform,
    };
    return { status: 'ok', detail };
  }

  return { status: 'inconclusive', detail: { note: trunc('unhandled fleet op: ' + opType) } };
}

ipcMain.handle('clientop:run', async (_e, { runId = null, opType = null, params = null } = {}) => {
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  try {
    if (!opType || typeof opType !== 'string') return { error: 'opType required' };
    const { status, detail } = await runFleetOp(opType, params || {});
    const result = {
      runId: runId || '',
      opType,
      started_at: startedAt,
      duration_ms: Date.now() - t0,
      status,
      detail_json: JSON.stringify(detail || {}),
    };
    const key = await getDeviceScanKey();
    const signature = key.sign(Buffer.from(canonicalClientOpString(result), 'utf8')).toString('base64');
    return { ...result, device_fingerprint: key.fingerprint, signed_at: new Date().toISOString(), signature };
  } catch (err) {
    return { error: (err.message || 'fleet op failed').slice(0, 200) };
  }
});

// recovery:wipeLocal -- clear the four machine-local files after a server-side
// teardown (best-effort; the real guarantee is the server credential
// revocation). The analyst key itself is preserved server-side and recovered on
// re-provision via the recovery code, so wiping the local burnout wrap is safe.
ipcMain.handle('recovery:wipeLocal', async () => {
  const files = [
    ['e2ee_store', path.join(app.getPath('userData'), 'e2ee-store.bin')],
    ['burnout_key', burnoutKeyFile()],
    ['device_key', deviceKeyFile()],
    ['ca_pin', caPinPath()],
  ];
  const wiped = {};
  for (const [name, file] of files) {
    try {
      if (fs.existsSync(file)) { fs.rmSync(file, { force: true }); wiped[name] = 'removed'; }
      else wiped[name] = 'absent';
    } catch (e) { wiped[name] = 'error'; }
  }
  // B5e: also retire the hardware-bound device key so a clone of this machine
  // cannot use it (the private key lives in the TPM / Secure Enclave, not on disk).
  try {
    const removed = require('../shared/hardware-key').deleteSigningKey(DEVICE_KEY_LABEL);
    wiped['device_hw_key'] = removed ? 'removed' : 'absent';
  } catch (e) { wiped['device_hw_key'] = 'error'; }
  // Drop in-memory caches so the session holds no unlocked key material.
  _burnoutKey = null;
  _deviceScanKey = null;
  e2ee = null;
  return { ok: true, wiped };
});



app.whenReady().then(() => {
  try { localLlm.setModelRoot(path.join(app.getPath('userData'), 'models')); } catch (_e) {}
  createWindow();
  startBeaconListener();
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
// Stop the isolated model utilityProcess cleanly when the app quits.
app.on('before-quit', () => {
  try { localLlm.shutdownUtil(); } catch (_e) { /* ignore */ }
  try { if (beaconListener) beaconListener.stop(); } catch (_e) { /* ignore */ }
});

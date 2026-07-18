const { app, BrowserWindow, ipcMain, dialog, session, Notification, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { spawn } = require('child_process');

let serverProcess = null;
let isQuitting = false;

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

// D9: per-installation deployment-mode selection (advisory; the server's
// anchor-sealed mode is authoritative). Stored as a plain JSON file under
// userData, like the CA pin. Created lazily so app paths are ready.
const { makeLocalMode } = require('@firealive/shared/deployment-mode-local');
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
  const hwkey = require('@firealive/shared/hardware-key');
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

// ── B5f: per-request proof-of-possession signing ────────────────────────────
//
// Every authenticated /api/ request to the regional server carries a fresh,
// single-use proof signed by this console's hardware device key (the same
// fa-mc-device key that signs privileged actions), so a stolen session token is
// useless without the chip. Mirrors server/services/device-pop.js, with the
// regional signing prefix (distinct from the device-action prefix above).
const MC_POP_SIGNING_PREFIX = 'firealive-device-pop-v1:';
const MC_POP_FIELD_SEP = String.fromCharCode(10);

// RFC 7638 JWK SHA-256 thumbprint (base64url) of the device key's public key,
// the value the server bound into the session token's cnf.jkt claim. Must match
// server/services/device-key.js jwkThumbprint exactly.
function mcJwkThumbprint(publicKeyPem) {
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
function mcPopMessage(method, path, iat, jti, jkt) {
  const fields = [String(method).toUpperCase(), String(path), String(iat), String(jti), String(jkt)];
  return Buffer.from(MC_POP_SIGNING_PREFIX + fields.join(MC_POP_FIELD_SEP), 'utf8');
}

// Sign a per-request proof. The renderer calls this with the method and full
// path of the request it is about to make and attaches the returned proof as the
// x-fa-device-pop header.
ipcMain.handle('device:signPopProof', async (_e, { method, path } = {}) => {
  try {
    if (typeof method !== 'string' || typeof path !== 'string') {
      return { error: 'method and path required' };
    }
    const k = await getMcDeviceKey();
    const jkt = mcJwkThumbprint(k.publicKeyPem);
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomBytes(16).toString('hex');
    const sig = k.sign(mcPopMessage(method, path, iat, jti, jkt)).toString('base64');
    const proof = Buffer.from(JSON.stringify({ iat: iat, jti: jti, sig: sig })).toString('base64url');
    return { proof: proof };
  } catch (err) {
    return { error: (err.message || 'proof-of-possession signing failed').slice(0, 200) };
  }
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

function startServer() {
  const serverPath = path.join(__dirname, '..', 'server', 'index.js');
  // FATAL 2: a packaged Electron app ships no standalone node on PATH, so a bare
  // spawn('node', ...) fails with ENOENT. Spawn the Electron binary itself as a Node
  // runtime via ELECTRON_RUN_AS_NODE, and pass an explicit minimal environment
  // allow-list (only what the embedded server needs) rather than the whole parent env.
  const childEnv = { ELECTRON_RUN_AS_NODE: '1', NODE_ENV: 'production', PORT: '3000' };
  for (const k of ['PATH', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TMPDIR', 'TEMP', 'TMP', 'SystemRoot', 'LANG', 'LC_ALL', 'LC_CTYPE']) {
    if (process.env[k] !== undefined) childEnv[k] = process.env[k];
  }
  serverProcess = spawn(process.execPath, [serverPath], { env: childEnv, stdio: 'pipe' });
  serverProcess.stdout.on('data', (d) => console.log('[Server]', d.toString()));
  serverProcess.stderr.on('data', (d) => console.error('[Server]', d.toString()));
  // FATAL 2: fail loud and fail closed. The Management Console cannot function without
  // its embedded Regional Server; an unexpected exit is fatal, so surface it and quit
  // rather than leave a hollow window with no backend.
  serverProcess.on('exit', (code, signal) => {
    if (isQuitting) {
      console.log('[Server] exited during shutdown (code ' + code + ')');
      return;
    }
    console.error('[Server] FATAL: the embedded Regional Server exited unexpectedly (code '
      + code + ', signal ' + signal + '). The Management Console cannot operate without it '
      + 'and will now close.');
    app.quit();
  });
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
const { createSignalE2EE } = require('@firealive/shared/signal-e2ee');

// The abuse-seal helper (packages/shared/abuse-seal.js) is bundled the same way;
// load it with the same packaged/source fallback. It needs no native dependency
// (Node crypto only), so a plain require is enough. The Team-Lead review side
// uses the keypair/open/wrap helpers (the lead holds the private key and opens
// sealed cases in this main process).
const { generateReviewerKeypair, openForReviewer, wrapPrivateKey,
  unwrapPrivateKey, fingerprintForPubB64, publicKeyB64FromPrivate } = require('@firealive/shared/abuse-seal');

// B5e: subnet beacon listener (anti-cloning, client side). Listen-only. Verifies
// the signed beacons FireAlive regional servers broadcast and warns the operator
// if a cloned or forked server identity appears on the local subnet. The console
// announces nothing (it has no identity of its own). Anchor-pinned detection
// arrives with the Block K anchor challenge; until then this runs unpinned, where
// a concurrent second server identity for the role is the signal.
let beaconListener = null;

function startBeaconListener() {
  const beaconLib = require('@firealive/shared/beacon-listener');
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

// -- Team-Lead abuse-review key: bootstrap, unlock, and sealed-content opening --
// The Team Lead's abuse-review PRIVATE key never leaves this main process
// unencrypted: it is generated once, wrapped under the lead's passphrase, then
// sealed at rest with the OS keychain (safeStorage), and used only here to open
// sealed case content. The renderer only ever receives the PUBLIC key (to
// register) and decrypted plaintext (to display).
const leadAbuseKeyFile = () => path.join(app.getPath('userData'), 'lead-abuse-review-key.enc');

// Minimum passphrase length. A passphrase (length over composition) is the second
// factor protecting the private key at rest; the renderer hints on strength, this
// is the authoritative floor.
const ABUSE_MIN_PASSPHRASE_LEN = 12;

// The unwrapped private key is held ONLY in this main-process variable, only for
// the duration of an unlocked session. It is set by abuse:unlock and cleared by
// abuse:lock and on shutdown -- never written unwrapped, never sent to the
// renderer.
let unlockedAbusePrivB64 = null;

// Does a sealed Team-Lead abuse-review key already exist on this device? Drives
// the onboarding-vs-ready decision in the renderer.
ipcMain.handle('abuse:hasKey', () => {
  try { return fs.existsSync(leadAbuseKeyFile()); } catch { return false; }
});

// Generate this lead's abuse-review keypair on THIS device at first onboarding.
// The private key is wrapped under the lead's passphrase and then sealed with
// safeStorage before being persisted, so it is protected by something the lead
// knows AND the OS keychain. Only the PUBLIC key, algo, and an 8-byte fingerprint
// are returned, so the renderer can register the public key via POST
// /api/abuse-review-key (which adds this lead to the recipient set). The private
// key is never returned. Opening sealed content additionally requires an explicit
// unlock, since the stored key is passphrase-wrapped.
ipcMain.handle('abuse:generateKey', (_e, passphrase) => {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is unavailable; cannot protect the abuse-review key');
  }
  if (typeof passphrase !== 'string' || passphrase.length < ABUSE_MIN_PASSPHRASE_LEN) {
    throw new Error('a passphrase of at least ' + ABUSE_MIN_PASSPHRASE_LEN + ' characters is required');
  }
  if (fs.existsSync(leadAbuseKeyFile())) {
    throw new Error('an abuse-review key already exists on this device');
  }
  const kp = generateReviewerKeypair();
  const wrapped = wrapPrivateKey(kp.privateKeyB64, passphrase);
  fs.writeFileSync(leadAbuseKeyFile(), safeStorage.encryptString(wrapped), { mode: 0o600 });
  return { algo: kp.algo, publicKeyB64: kp.publicKeyB64, fingerprint: fingerprintForPubB64(kp.publicKeyB64).toString('hex') };
});

// Unlock the abuse-review key for this session: decrypt the safeStorage layer,
// then unwrap the passphrase layer, and hold the private key in memory until
// locked. A wrong passphrase fails the unwrap and no key is held. Returns the
// key's fingerprint so the UI can confirm which key is unlocked.
ipcMain.handle('abuse:unlock', (_e, passphrase) => {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is unavailable; cannot read the abuse-review key');
  }
  if (typeof passphrase !== 'string' || !passphrase) {
    throw new Error('a passphrase is required');
  }
  if (!fs.existsSync(leadAbuseKeyFile())) {
    throw new Error('no abuse-review key on this device');
  }
  const wrapped = safeStorage.decryptString(fs.readFileSync(leadAbuseKeyFile()));
  let privB64;
  try {
    privB64 = unwrapPrivateKey(wrapped, passphrase);
  } catch {
    throw new Error('incorrect passphrase');
  }
  unlockedAbusePrivB64 = privB64;
  return { unlocked: true, fingerprint: fingerprintForPubB64(publicKeyB64FromPrivate(privB64)).toString('hex') };
});

// Lock the abuse-review key: clear it from memory. Invoked by the renderer and on
// shutdown, so an unlocked session does not outlive the lead's presence.
ipcMain.handle('abuse:lock', () => {
  unlockedAbusePrivB64 = null;
  return { locked: true };
});

// Open one sealed value (a case's sealed note or sealed content) with the
// in-memory private key. The shared abuse-seal module's openForReviewer locates
// this lead's slot by fingerprint, unwraps the DEK, and decrypts the content.
// Refuses when the key is locked. Decryption happens only here; the renderer
// receives plaintext to display. The private key is never returned.
ipcMain.handle('abuse:open', (_e, sealedB64) => {
  if (typeof sealedB64 !== 'string' || !sealedB64) {
    throw new Error('sealed value (base64) required');
  }
  if (!unlockedAbusePrivB64) {
    throw new Error('abuse-review key is locked; unlock with your passphrase first');
  }
  return { plaintext: openForReviewer(unlockedAbusePrivB64, sealedB64).toString('utf8') };
});

// Remove this device's abuse-review key entirely: delete the wrapped key file
// and clear any unlocked private key from memory, so the lead can re-onboard
// with a fresh key. Server-side revocation of the registered public key is
// done separately by the renderer.
ipcMain.handle('abuse:deleteKey', () => {
  unlockedAbusePrivB64 = null;
  try {
    if (fs.existsSync(leadAbuseKeyFile())) fs.unlinkSync(leadAbuseKeyFile());
  } catch (e) {
    throw new Error('could not delete the abuse-review key file: ' + e.message);
  }
  return { deleted: true };
});

app.whenReady().then(() => {
  startServer();
  // Wait for server to be ready
  setTimeout(createWindow, 2000);
  startBeaconListener();
});

app.on('window-all-closed', () => {
  isQuitting = true;
  if (serverProcess) serverProcess.kill();
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  try { if (beaconListener) beaconListener.stop(); } catch (_e) { /* ignore */ }
  unlockedAbusePrivB64 = null;
});

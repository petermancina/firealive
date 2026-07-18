const { app, BrowserWindow, session, ipcMain, Notification, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

let gdServerProcess = null;
let isQuitting = false;

app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

// ═══════════════════════════════════════════════════════════════════════════════
// B5b — TLS trust + client-certificate presentation (passwordless auth)
//
// The Global Dashboard client connects over HTTPS to its bundled Global Dashboard
// server, which presents a certificate from the GD's own built-in CA, so the
// client must trust that CA out-of-band. The operator imports the GD CA
// certificate once (auth:importCaCert); it is stored under userData as
// firealive-gd-ca.pem and pinned here. setCertificateVerifyProc trusts a server
// certificate ONLY if it chains to that pinned CA, and rejects every other
// certificate outright (strict pinning: a publicly-trusted but non-FireAlive
// cert is NOT accepted, which defeats a mis-issued or compromised public CA).
// The CA certificate is public, not a secret, so it is kept as a plain file
// rather than in safeStorage.
//
// The Global Dashboard is passwordless-only; the in-app login method is a
// FIDO2/WebAuthn passkey, handled in the renderer via navigator.credentials — the
// private key never leaves the authenticator. A hardware client certificate
// (PIV/CAC) held in the OS certificate store is also supported: when the server
// requests a client certificate at the TLS handshake, select-client-certificate
// presents one from the OS store. A software certificate generated on the host is
// intentionally NOT used for in-app mTLS — the gold-standard credential keeps its
// key in hardware.
// ═══════════════════════════════════════════════════════════════════════════════

const caPinPath = () => path.join(app.getPath('userData'), 'firealive-gd-ca.pem');

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

// True only if the presented server certificate is signed by the pinned GD CA.
function serverCertChainsToPinnedCa(serverPem) {
  if (!pinnedCaPem || !serverPem) return false;
  try {
    const caX = new crypto.X509Certificate(pinnedCaPem);
    const srvX = new crypto.X509Certificate(serverPem);
    return srvX.verify(caX.publicKey);
  } catch (_) { return false; }
}

// Import / replace the pinned GD CA certificate (an out-of-band operator action).
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
    return { mode: lm.getMode(), configured: lm.isConfigured(), virtualized: lm.isVirtualized(), toleratesMobility: lm.toleratesMobility() };
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('deployment:setLocalMode', async (_e, { mode, substrate } = {}) => {
  try {
    const lm = localMode();
    lm.setMode(mode, substrate);
    return { ok: true, mode: lm.getMode(), substrate: (typeof lm.getSubstrate === 'function' ? lm.getSubstrate() : null) };
  } catch (e) {
    return { error: e.message };
  }
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

// === Operator device key (Block K, D20/D28) ================================
// The hardware-bound, non-exportable signing key this GD operator's app mints on
// the shared sign-only seam (TPM 2.0 / Secure Enclave; fail-closed, no software
// fallback). Its public half is registered with the GD server at enrollment; it
// signs the single-use login challenge and a fresh proof-of-possession on every
// API request. The signing prefixes and the PoP field order below are copied
// verbatim from the GD server's gd-device-key and gd-pop modules; they MUST stay
// in lockstep or signatures will not verify.
const GD_DEVICE_KEY_LABEL = 'fa-gd-device';
const GD_LOGIN_SIGNING_PREFIX = 'firealive-gd-device-key-login-v1:';
const GD_POP_SIGNING_PREFIX = 'firealive-gd-device-pop-v1:';
const GD_POP_FIELD_SEP = String.fromCharCode(10);
let _gdDeviceKey = null;

// RFC 7638 JWK SHA-256 thumbprint (base64url) of the device public key. Matches
// the GD server's jwkThumbprint, so the value the app signs into a PoP equals the
// session token's cnf.jkt binding.
function gdJwkThumbprint(publicKeyPem) {
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

// The exact bytes signed for a per-request proof (mirror of gd-pop.popMessage).
function gdPopMessage(method, path, iat, jti, jkt) {
  const fields = [String(method).toUpperCase(), String(path), String(iat), String(jti), String(jkt)];
  return Buffer.from(GD_POP_SIGNING_PREFIX + fields.join(GD_POP_FIELD_SEP), 'utf8');
}

// Mint or load the device key. Fails closed when no hardware root is present.
async function getGdDeviceKey() {
  if (_gdDeviceKey) return _gdDeviceKey;
  const hwkey = require('@firealive/shared/hardware-key');
  if (!hwkey.isAvailable()) {
    throw new Error('A hardware root of trust (TPM 2.0 / Secure Enclave) is required for the GD operator device signing key; this app fails closed and will not run without it');
  }
  let der = hwkey.hasSigningKey(GD_DEVICE_KEY_LABEL)
    ? hwkey.getSigningPublicKey(GD_DEVICE_KEY_LABEL)
    : hwkey.createSigningKey(GD_DEVICE_KEY_LABEL);
  if (!der) {
    der = hwkey.createSigningKey(GD_DEVICE_KEY_LABEL);
  }
  const publicKeyPem = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' })
    .export({ type: 'spki', format: 'pem' });
  const fingerprint = crypto.createHash('sha256').update(der).digest('hex');
  _gdDeviceKey = {
    sign: (data) => hwkey.sign(GD_DEVICE_KEY_LABEL, Buffer.isBuffer(data) ? data : Buffer.from(data)),
    publicKeyPem,
    fingerprint,
    jkt: gdJwkThumbprint(publicKeyPem),
    label: GD_DEVICE_KEY_LABEL,
  };
  return _gdDeviceKey;
}

// Public key + fingerprint, for registering the device key at enrollment.
ipcMain.handle('device:getPublicKey', async () => {
  try {
    const k = await getGdDeviceKey();
    return { publicKey: k.publicKeyPem, fingerprint: k.fingerprint };
  } catch (e) {
    return { error: e.message };
  }
});

// Sign the single-use login challenge on-chip (proof of possession at login).
ipcMain.handle('device:signLoginChallenge', async (_e, { challenge } = {}) => {
  try {
    if (typeof challenge !== 'string' || !challenge) return { error: 'challenge required' };
    const k = await getGdDeviceKey();
    const sig = k.sign(Buffer.from(GD_LOGIN_SIGNING_PREFIX + challenge, 'utf8'));
    return { signature: sig.toString('base64'), fingerprint: k.fingerprint };
  } catch (e) {
    return { error: e.message };
  }
});

// Sign a fresh per-request proof-of-possession on-chip. Returns the opaque
// base64url(JSON({ iat, jti, sig })) value the request wrapper sends as the
// x-fa-device-pop header.
ipcMain.handle('device:signPopProof', async (_e, { method, path } = {}) => {
  try {
    if (typeof method !== 'string' || typeof path !== 'string') return { error: 'method and path required' };
    const k = await getGdDeviceKey();
    const iat = Math.floor(Date.now() / 1000);
    const jti = crypto.randomBytes(16).toString('hex');
    const sig = k.sign(gdPopMessage(method, path, iat, jti, k.jkt));
    const proof = Buffer.from(JSON.stringify({ iat, jti, sig: sig.toString('base64') })).toString('base64url');
    return { proof };
  } catch (e) {
    return { error: e.message };
  }
});

// B5e (D25): server -> client deployment attestation, GD-server side. The GD app
// pins the GD-server's hardware instance-anchor fingerprint at enrollment and, on
// each connect, challenges the server to sign a fresh nonce with that anchor. A
// clone holds the same database and CA but cannot unseal the anchor on different
// hardware -> it cannot sign, and the app refuses it. The fingerprint is public
// (like the pinned CA), so it is kept as a plain JSON file under userData; re-
// pinning is deliberate (the re-provision ceremony), never silent.
const GD_ANCHOR_CHALLENGE_PREFIX = 'firealive-gd-instance-anchor-challenge-v1:';
const anchorPinPath = () => path.join(app.getPath('userData'), 'firealive-gd-anchor-pin.json');

function loadAnchorPin() {
  try {
    const f = anchorPinPath();
    if (!fs.existsSync(f)) return null;
    const o = JSON.parse(fs.readFileSync(f, 'utf8'));
    return o && typeof o.fingerprint === 'string' ? o.fingerprint : null;
  } catch (_) { return null; }
}
function saveAnchorPin(fingerprint) {
  fs.writeFileSync(anchorPinPath(), JSON.stringify({ fingerprint: fingerprint }), { mode: 0o600 });
}

// Fresh 32-byte challenge nonce. The renderer sends it to the GD-server's
// POST /api/instance/anchor-challenge and returns the response here to check.
ipcMain.handle('anticlone:anchorNonce', async () => {
  return { nonce: crypto.randomBytes(32).toString('base64') };
});

// Verify a GD anchor-challenge response: the published key matches its claimed
// fingerprint, the signature over <prefix || nonce> verifies, then the fingerprint
// is compared to the pin. Verdicts: 'ok', 'mismatch', 'unpinned', 'invalid'.
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
    const message = Buffer.from(GD_ANCHOR_CHALLENGE_PREFIX + nonce, 'utf8');
    sigOk = crypto.verify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64'));
  } catch (_) {
    sigOk = false;
  }
  if (!sigOk) {
    return { verdict: 'invalid', reason: 'anchor signature did not verify' };
  }
  const pinned = loadAnchorPin();
  if (pinned === null) {
    return { verdict: 'unpinned', fingerprint: fingerprint };
  }
  if (pinned === fingerprint) {
    return { verdict: 'ok', fingerprint: fingerprint };
  }
  return { verdict: 'mismatch', fingerprint: fingerprint, pinned: pinned };
});

// Pin the GD-server's anchor fingerprint (trust-on-first-use at enrollment).
// Refuses to silently overwrite a different pin; re-provision passes force (D19).
ipcMain.handle('anticlone:pinAnchor', async (_e, { fingerprint, force } = {}) => {
  if (typeof fingerprint !== 'string' || !(/^[0-9a-f]{64}$/.test(fingerprint))) {
    return { pinned: false, error: 'a 64-hex-character anchor fingerprint is required' };
  }
  const existing = loadAnchorPin();
  if (existing && existing !== fingerprint && !force) {
    return { pinned: false, conflict: true, error: 'anchor already pinned to a different fingerprint; re-pin requires re-provision' };
  }
  try {
    saveAnchorPin(fingerprint);
  } catch (err) {
    return { pinned: false, error: err && err.message ? err.message : String(err) };
  }
  return { pinned: true, fingerprint: fingerprint, firstPin: !existing };
});

// B5f (D-B5f-4): blocking operator confirmation before the first anchor pin
// (trust-on-first-use). On first contact the renderer calls this with the GD
// server's anchor fingerprint; the operator must compare it out of band with
// the GD DEPLOYMENT ANCHOR FINGERPRINT the GD server prints at startup and
// explicitly confirm before the app trusts and pins it. A native modal dialog
// makes the confirmation blocking and harder to spoof than a renderer modal;
// the default button is Cancel, so an accidental Enter or a closed dialog
// refuses. Returns confirmed:true only on a deliberate confirm.
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
    title: 'Confirm Global Dashboard server identity (first connection)',
    message: 'Trust this Global Dashboard server on first connection?',
    detail: 'GD server anchor fingerprint:' + NL + NL + grouped + NL + NL
      + 'Compare this with the GD DEPLOYMENT ANCHOR FINGERPRINT the GD server '
      + 'prints at startup, obtained out of band from your administrator. Confirm '
      + 'only if it matches exactly. A clone of this deployment cannot reproduce '
      + 'this fingerprint, so a value that does not match is the signal to refuse.',
  };
  let result;
  try {
    result = win ? await dialog.showMessageBox(win, opts) : await dialog.showMessageBox(opts);
  } catch (err) {
    return { confirmed: false, error: err && err.message ? err.message : String(err) };
  }
  return { confirmed: !!(result && result.response === 1) };
});

// Report whether a GD-server anchor fingerprint is pinned (for the connect flow).
ipcMain.handle('anticlone:anchorState', async () => {
  const v = loadAnchorPin();
  return { pinned: !!v, fingerprint: v || null };
});

function startGdServer() {
  const serverPath = path.join(__dirname, '..', 'global-dashboard-server', 'index.js');
  // FATAL 2: a packaged Electron app ships no standalone node on PATH, so a bare
  // spawn('node', ...) fails with ENOENT. Spawn the Electron binary itself as a Node
  // runtime via ELECTRON_RUN_AS_NODE, and pass an explicit minimal environment
  // allow-list rather than the whole parent environment.
  const childEnv = { ELECTRON_RUN_AS_NODE: '1', NODE_ENV: 'production', GD_PORT: '4001' };
  for (const k of ['PATH', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TMPDIR', 'TEMP', 'TMP', 'SystemRoot', 'LANG', 'LC_ALL', 'LC_CTYPE']) {
    if (process.env[k] !== undefined) childEnv[k] = process.env[k];
  }
  gdServerProcess = spawn(process.execPath, [serverPath], { env: childEnv, stdio: 'pipe' });
  gdServerProcess.stdout.on('data', (d) => console.log('[GD-Server]', d.toString()));
  gdServerProcess.stderr.on('data', (d) => console.error('[GD-Server]', d.toString()));
  // FATAL 2: the GD had no exit handler at all. Fail loud and fail closed -- the Global
  // Dashboard cannot function without its embedded server; an unexpected exit is fatal.
  gdServerProcess.on('exit', (code, signal) => {
    if (isQuitting) {
      console.log('[GD-Server] exited during shutdown (code ' + code + ')');
      return;
    }
    console.error('[GD-Server] FATAL: the embedded GD Server exited unexpectedly (code '
      + code + ', signal ' + signal + '). The Global Dashboard cannot operate without it '
      + 'and will now close.');
    app.quit();
  });
}

function createWindow() {
  pinnedCaPem = loadPinnedCaPem();
  const win = new BrowserWindow({
    width: 1440, height: 900,
    title: 'FireAlive — Global Dashboard',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': ["default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self' https://localhost:*; img-src 'self' data:; frame-src 'none'"] } });
  });
  // Pin the GD server's CA: trust a server certificate only if it chains to
  // the imported GD CA; reject every other cert (strict pinning).
  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    const leafPem = request && request.certificate && request.certificate.data;
    if (leafPem && serverCertChainsToPinnedCa(leafPem)) return callback(0); // trusted via pinned CA
    return callback(-2); // reject: not signed by the pinned GD CA
  });
  win.loadFile('index.html');
}

// B5e: subnet beacon listener (anti-cloning, client side). Listen-only. Verifies
// the signed beacons the FireAlive GD server broadcasts and warns the operator
// if a cloned or forked server identity appears on the local subnet. The
// dashboard announces nothing (it has no identity of its own). Anchor-pinned
// detection arrives with the Block K anchor challenge; until then this runs
// unpinned, where a concurrent second server identity for the role is the signal.
let beaconListener = null;

function startBeaconListener() {
  const beaconLib = require('@firealive/shared/beacon-listener');
  try {
    beaconListener = beaconLib.start({
      expectedRole: 'gd-server',
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

app.whenReady().then(() => { startGdServer(); setTimeout(createWindow, 2000); startBeaconListener(); });
app.on('window-all-closed', () => { isQuitting = true; if (gdServerProcess) gdServerProcess.kill(); if (process.platform !== 'darwin') app.quit(); });
app.on('before-quit', () => { try { if (beaconListener) beaconListener.stop(); } catch (_e) { /* ignore */ } });

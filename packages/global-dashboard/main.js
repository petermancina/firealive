const { app, BrowserWindow, session, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

let gdServerProcess = null;

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

function startGdServer() {
  const serverPath = path.join(__dirname, '..', 'global-dashboard-server', 'index.js');
  gdServerProcess = spawn('node', [serverPath], {
    env: { ...process.env, NODE_ENV: 'production', GD_PORT: '4001' },
    stdio: 'pipe'
  });
  gdServerProcess.stdout.on('data', (d) => console.log('[GD-Server]', d.toString()));
  gdServerProcess.stderr.on('data', (d) => console.error('[GD-Server]', d.toString()));
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

app.whenReady().then(() => { startGdServer(); setTimeout(createWindow, 2000); });
app.on('window-all-closed', () => { if (gdServerProcess) gdServerProcess.kill(); if (process.platform !== 'darwin') app.quit(); });

const { app, BrowserWindow, session, ipcMain, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');

// The reviewer seal helper (packages/shared/abuse-seal.js) is bundled the same
// way as in the AC/MC; load it with the same packaged/source fallback. Node
// crypto only -- no native dependency.
let generateReviewerKeypair, openAsReviewer;
try {
  ({ generateReviewerKeypair, openAsReviewer } = require('./abuse-seal'));
} catch {
  ({ generateReviewerKeypair, openAsReviewer } = require('../shared/abuse-seal'));
}

// The reviewer PRIVATE key never leaves this main process unencrypted: it is
// generated once, sealed at rest with the OS keychain (safeStorage), and used
// only here to open sealed case content. The renderer only ever receives the
// PUBLIC key (to register) and decrypted plaintext (to display).
const reviewerKeyFile = () => path.join(app.getPath('userData'), 'reviewer-key.enc');

// The Abuse Review Console talks ONLY to the existing FireAlive server's
// reviewer-only API (/api/abuse-review/*). It runs no server of its own -- the
// evidence vault stays single-source on the main server. Sealed case content is
// opened client-side in this main process; the abuse-seal helper and the
// reviewer-key bootstrap (generate keypair, register the public key, seal the
// private key via safeStorage) are added in F5b.

app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1440, height: 900,
    title: 'FireAlive — Abuse Review Console',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': ["default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self' https://localhost:*; img-src 'self' data:; frame-src 'none'"] } });
  });
  win.loadFile('index.html');
}

// ── Reviewer-key bootstrap + sealed-content opening (F5b) ───────────────────────
// Does a sealed reviewer key already exist on this device? Drives bootstrap vs ready.
ipcMain.handle('abuse:hasKey', () => {
  try { return fs.existsSync(reviewerKeyFile()); } catch { return false; }
});

// Generate the org reviewer keypair at first designation, seal the private key
// with safeStorage and persist it, and return ONLY the public key + algo so the
// renderer can register it via POST /api/abuse-review-key (which turns flagging
// on across the AC/MC). The private key is never returned.
ipcMain.handle('abuse:generateKey', () => {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is unavailable; cannot protect the reviewer key');
  }
  if (fs.existsSync(reviewerKeyFile())) {
    throw new Error('a reviewer key already exists on this device');
  }
  const kp = generateReviewerKeypair();
  fs.writeFileSync(reviewerKeyFile(), safeStorage.encryptString(kp.privateKeyB64), { mode: 0o600 });
  return { algo: kp.algo, publicKeyB64: kp.publicKeyB64 };
});

// Open one sealed value (a case's sealed note or sealed message) with the local
// private key. Decryption happens only here; the renderer receives plaintext to
// display. The private key is never returned or exposed.
ipcMain.handle('abuse:open', (_e, sealedB64) => {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is unavailable; cannot read the reviewer key');
  }
  if (typeof sealedB64 !== 'string' || !sealedB64) {
    throw new Error('sealed value (base64) required');
  }
  if (!fs.existsSync(reviewerKeyFile())) {
    throw new Error('no reviewer key on this device');
  }
  const privB64 = safeStorage.decryptString(fs.readFileSync(reviewerKeyFile()));
  return { plaintext: openAsReviewer(privB64, sealedB64).toString('utf8') };
});

app.whenReady().then(createWindow);
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

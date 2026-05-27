const { app, BrowserWindow, session, ipcMain, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');

// The reviewer seal helper (packages/shared/abuse-seal.js) is bundled the same
// way as in the AC/MC; load it with the same packaged/source fallback. Node
// crypto only -- no native dependency.
let generateReviewerKeypair, openAsReviewer, wrapPrivateKey, unwrapPrivateKey, fingerprintForPubB64, publicKeyB64FromPrivate;
try {
  ({ generateReviewerKeypair, openAsReviewer, wrapPrivateKey, unwrapPrivateKey, fingerprintForPubB64, publicKeyB64FromPrivate } = require('./abuse-seal'));
} catch {
  ({ generateReviewerKeypair, openAsReviewer, wrapPrivateKey, unwrapPrivateKey, fingerprintForPubB64, publicKeyB64FromPrivate } = require('../shared/abuse-seal'));
}

// The reviewer PRIVATE key never leaves this main process unencrypted: it is
// generated once, sealed at rest with the OS keychain (safeStorage), and used
// only here to open sealed case content. The renderer only ever receives the
// PUBLIC key (to register) and decrypted plaintext (to display).
const reviewerKeyFile = () => path.join(app.getPath('userData'), 'reviewer-key.enc');

// The unwrapped private key is held ONLY in this main-process variable, only for
// the duration of an unlocked session. It is set by abuse:unlock and cleared by
// abuse:lock (the F13 hard-lock) and on shutdown -- never written unwrapped, never
// sent to the renderer.
let unlockedPrivB64 = null;

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
    callback({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': ["default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self' https://localhost:*; img-src 'self' data:; frame-src 'none'"] } });
  });
  win.loadFile('index.html');
}

// ── Reviewer-key bootstrap + sealed-content opening (F5b) ───────────────────────
// Does a sealed reviewer key already exist on this device? Drives bootstrap vs ready.
ipcMain.handle('abuse:hasKey', () => {
  try { return fs.existsSync(reviewerKeyFile()); } catch { return false; }
});

// Minimum reviewer passphrase length. A passphrase (length over composition) is
// the second factor protecting the private key at rest; the renderer hints on
// strength, this is the authoritative floor.
const MIN_PASSPHRASE_LEN = 12;

// Generate this reviewer's keypair on THIS device at first designation. The
// private key is wrapped under the reviewer's passphrase and then sealed with
// safeStorage before being persisted, so it is protected by something the
// reviewer knows AND the OS keychain. Only the PUBLIC key, algo, and an 8-byte
// fingerprint are returned, so the renderer can register the public key via
// POST /api/abuse-review-key (which adds this reviewer to the recipient set).
// The private key is never returned. Opening sealed content additionally
// requires an explicit unlock (added next), since the stored key is now
// passphrase-wrapped.
ipcMain.handle('abuse:generateKey', (_e, passphrase) => {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is unavailable; cannot protect the reviewer key');
  }
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LEN) {
    throw new Error('a passphrase of at least ' + MIN_PASSPHRASE_LEN + ' characters is required');
  }
  if (fs.existsSync(reviewerKeyFile())) {
    throw new Error('a reviewer key already exists on this device');
  }
  const kp = generateReviewerKeypair();
  const wrapped = wrapPrivateKey(kp.privateKeyB64, passphrase);
  fs.writeFileSync(reviewerKeyFile(), safeStorage.encryptString(wrapped), { mode: 0o600 });
  return { algo: kp.algo, publicKeyB64: kp.publicKeyB64, fingerprint: fingerprintForPubB64(kp.publicKeyB64).toString('hex') };
});

// Unlock the reviewer key for this session: decrypt the safeStorage layer, then
// unwrap the passphrase layer, and hold the private key in memory until locked.
// A wrong passphrase fails the unwrap and no key is held. Returns the key's
// fingerprint so the UI can confirm which reviewer identity is unlocked.
ipcMain.handle('abuse:unlock', (_e, passphrase) => {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is unavailable; cannot read the reviewer key');
  }
  if (typeof passphrase !== 'string' || !passphrase) {
    throw new Error('a passphrase is required');
  }
  if (!fs.existsSync(reviewerKeyFile())) {
    throw new Error('no reviewer key on this device');
  }
  const wrapped = safeStorage.decryptString(fs.readFileSync(reviewerKeyFile()));
  let privB64;
  try {
    privB64 = unwrapPrivateKey(wrapped, passphrase);
  } catch {
    throw new Error('incorrect passphrase');
  }
  unlockedPrivB64 = privB64;
  return { unlocked: true, fingerprint: fingerprintForPubB64(publicKeyB64FromPrivate(privB64)).toString('hex') };
});

// Lock the reviewer key: clear it from memory. Invoked by the F13 hard-lock and on
// shutdown, so an unlocked session does not outlive the reviewer's presence.
ipcMain.handle('abuse:lock', () => {
  unlockedPrivB64 = null;
  return { locked: true };
});

// Open one sealed value (a case's sealed note or sealed message) with the in-memory
// private key. Refuses when the key is locked. Decryption happens only here; the
// renderer receives plaintext to display. The private key is never returned.
ipcMain.handle('abuse:open', (_e, sealedB64) => {
  if (typeof sealedB64 !== 'string' || !sealedB64) {
    throw new Error('sealed value (base64) required');
  }
  if (!unlockedPrivB64) {
    throw new Error('reviewer key is locked; unlock with your passphrase first');
  }
  return { plaintext: openAsReviewer(unlockedPrivB64, sealedB64).toString('utf8') };
});

app.whenReady().then(createWindow);
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
app.on('window-all-closed', () => { unlockedPrivB64 = null; if (process.platform !== 'darwin') app.quit(); });
app.on('before-quit', () => { unlockedPrivB64 = null; });

const { app, BrowserWindow, session, ipcMain, safeStorage, Notification } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// The reviewer seal helper (packages/shared/abuse-seal.js) is bundled the same
// way as in the AC/MC; load it with the same packaged/source fallback. Node
// crypto only -- no native dependency.
let generateReviewerKeypair, openForReviewer, wrapPrivateKey, unwrapPrivateKey, fingerprintForPubB64, publicKeyB64FromPrivate;
try {
  ({ generateReviewerKeypair, openForReviewer, wrapPrivateKey, unwrapPrivateKey, fingerprintForPubB64, publicKeyB64FromPrivate } = require('./abuse-seal'));
} catch {
  ({ generateReviewerKeypair, openForReviewer, wrapPrivateKey, unwrapPrivateKey, fingerprintForPubB64, publicKeyB64FromPrivate } = require('../shared/abuse-seal'));
}

// B5e: subnet beacon listener (anti-cloning, client side). Listen-only. Verifies
// the signed beacons FireAlive regional servers broadcast and warns the reviewer
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

// The reviewer PRIVATE key never leaves this main process unencrypted: it is
// generated once, sealed at rest with the OS keychain (safeStorage), and used
// only here to open sealed case content. The renderer only ever receives the
// PUBLIC key (to register) and decrypted plaintext (to display).
const reviewerKeyFile = () => path.join(app.getPath('userData'), 'reviewer-key.enc');

// D9: per-installation deployment-mode selection (advisory; the server's
// anchor-sealed mode is authoritative). Stored as a plain JSON file under
// userData. Created lazily so app paths are ready.
const { makeLocalMode } = require('../shared/deployment-mode-local');
let _localMode = null;
function localMode() {
  if (!_localMode) {
    _localMode = makeLocalMode(path.join(app.getPath('userData'), 'firealive-deployment-mode.json'));
  }
  return _localMode;
}

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

// D9: report / set this installation's deployment-mode selection (first-run).
ipcMain.handle('deployment:getLocalMode', async () => {
  try {
    const lm = localMode();
    return { mode: lm.getMode(), configured: lm.isConfigured(), virtualized: lm.isVirtualized() };
  } catch (e) {
    return { error: e.message };
  }
});

ipcMain.handle('deployment:setLocalMode', async (_e, { mode } = {}) => {
  try {
    const lm = localMode();
    lm.setMode(mode);
    return { ok: true, mode: lm.getMode() };
  } catch (e) {
    return { error: e.message };
  }
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
// private key. The shared abuse-seal module's openForReviewer locates this
// reviewer's slot by fingerprint, unwraps the DEK, and decrypts the content.
// Refuses when the key is locked. Decryption happens only here; the renderer
// receives plaintext to display. The private key is never returned.
ipcMain.handle('abuse:open', (_e, sealedB64) => {
  if (typeof sealedB64 !== 'string' || !sealedB64) {
    throw new Error('sealed value (base64) required');
  }
  if (!unlockedPrivB64) {
    throw new Error('reviewer key is locked; unlock with your passphrase first');
  }
  return { plaintext: openForReviewer(unlockedPrivB64, sealedB64).toString('utf8') };
});

// ── U4 PR 5-C: pinned CISO approval key + export-token verification ──────────
// The two-person legal-hold export is gated on THIS device verifying the CISO's
// signed approval token against a CISO public key pinned here, out of band. The
// pin is independent of the regional server: a hostile server cannot make a
// forged token verify (it lacks the CISO private key) and cannot change what
// this device pinned. Public key only; never any private material.
const cisoKeyFile = () => path.join(app.getPath('userData'), 'ciso-export-key.pin');

function cisoKeyFingerprint(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}
function loadPinnedCiso() {
  try {
    const raw = JSON.parse(fs.readFileSync(cisoKeyFile(), 'utf8'));
    if (!raw || !raw.publicKeyPem || !raw.fingerprint) return null;
    return raw;
  } catch { return null; }
}

// Is a CISO approval key pinned on this device?
ipcMain.handle('abuse:cisoKeyStatus', () => {
  const p = loadPinnedCiso();
  return p ? { pinned: true, fingerprint: p.fingerprint, pinnedAt: p.pinnedAt || null } : { pinned: false };
});

// Pin (or re-pin) the CISO approval public key. expectedFingerprint MUST be the
// value the reviewer confirmed OUT OF BAND with the CISO; it is recomputed from
// the key bytes and a mismatch is refused -- the check is enforced here, not
// trusted from input. Ed25519 only.
ipcMain.handle('abuse:pinCisoKey', (_e, args) => {
  const { publicKeyPem, expectedFingerprint } = args || {};
  if (typeof publicKeyPem !== 'string' || !publicKeyPem) throw new Error('publicKeyPem is required');
  if (typeof expectedFingerprint !== 'string' || !expectedFingerprint) throw new Error('expectedFingerprint is required');
  let key;
  try { key = crypto.createPublicKey(publicKeyPem); } catch { throw new Error('not a valid PEM public key'); }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('CISO approval key must be Ed25519');
  const actual = cisoKeyFingerprint(publicKeyPem);
  const expected = expectedFingerprint.trim().toLowerCase().replace(/[^0-9a-f]/g, '');
  if (actual !== expected) throw new Error('fingerprint mismatch: computed ' + actual + ', expected ' + expected);
  const pemNorm = key.export({ type: 'spki', format: 'pem' }).toString();
  fs.writeFileSync(cisoKeyFile(), JSON.stringify({ publicKeyPem: pemNorm, fingerprint: actual, pinnedAt: new Date().toISOString() }), { mode: 0o600 });
  return { pinned: true, fingerprint: actual };
});

// Verify a CISO export-approval token against the pinned key AND that it binds
// the expected request/case/decision. Returns { ok, reason? }. This is the
// authoritative gate the produce step calls before assembling a case file.
ipcMain.handle('abuse:verifyExportToken', (_e, args) => {
  const { payloadCanonical, signature, keyFingerprint, expectRequestId, expectFlagId, expectDecision } = args || {};
  const pinned = loadPinnedCiso();
  if (!pinned) return { ok: false, reason: 'no CISO key is pinned on this device; pin it out of band first' };
  if (typeof payloadCanonical !== 'string' || typeof signature !== 'string') return { ok: false, reason: 'malformed token' };
  if (keyFingerprint && String(keyFingerprint).toLowerCase() !== pinned.fingerprint) return { ok: false, reason: 'token key fingerprint does not match the pinned CISO key' };
  let sig;
  try { sig = Buffer.from(signature, 'hex'); } catch { return { ok: false, reason: 'signature not hex' }; }
  let verified;
  try { verified = crypto.verify(null, Buffer.from(payloadCanonical, 'utf8'), crypto.createPublicKey(pinned.publicKeyPem), sig); }
  catch { return { ok: false, reason: 'verification error' }; }
  if (!verified) return { ok: false, reason: 'signature does not verify against the pinned CISO key' };
  let parsed;
  try { parsed = JSON.parse(payloadCanonical); } catch { return { ok: false, reason: 'token payload not JSON' }; }
  if (expectRequestId != null && parsed.request_id !== String(expectRequestId)) return { ok: false, reason: 'token does not bind this request' };
  if (expectFlagId != null && parsed.flag_id !== String(expectFlagId)) return { ok: false, reason: 'token does not bind this case' };
  if (expectDecision != null && parsed.decision !== expectDecision) return { ok: false, reason: 'token decision mismatch' };
  return { ok: true, decision: parsed.decision, decidedAt: parsed.decided_at, nonce: parsed.nonce };
});

app.whenReady().then(() => { createWindow(); startBeaconListener(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
app.on('window-all-closed', () => { unlockedPrivB64 = null; if (process.platform !== 'darwin') app.quit(); });
app.on('before-quit', () => { unlockedPrivB64 = null; try { if (beaconListener) beaconListener.stop(); } catch (_e) { /* ignore */ } });

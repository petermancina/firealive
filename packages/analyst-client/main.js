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
    fs.writeFileSync(filePath, pdf);
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
// All on-device. kbChat:ask makes NO network call (the only network path is the
// explicit, SHA-256-verified kbChat:downloadModel). Honest "unavailable on this
// device" with no server fallback — the Tier-3 firewall.

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

ipcMain.handle('kbChat:downloadModel', async (_e, { which } = {}) => {
  try { return await localLlm.downloadModel(which === 'embed' ? 'embed' : 'chat'); }
  catch (err) { return { error: (err.message || 'download failed').slice(0, 200), code: err.code || null }; }
});

app.whenReady().then(() => {
  try { localLlm.setModelRoot(path.join(app.getPath('userData'), 'models')); } catch (_e) {}
  createWindow();
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });

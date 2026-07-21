// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Analyst Client local inference + retrieval (firewalled, on-device)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// The Analyst Client's OWN local AI: a heavyweight chat model + a first-party
// embedder, both run on the analyst's device via node-llama-cpp. It powers the
// Analyst KB Assistant chat (PR7) with ZERO server round-trips — preserving the
// Tier-3 firewall (the analyst's questions and signals never leave the device).
//
// VERIFY-ONLY: FireAlive never downloads models. The operator provisions the
// official files (the official publisher's page on Hugging Face or an
// internal mirror) into the AC model directory; this module verifies each file
// against a SHA-256 PINNED IN SOURCE before loading, and refuses on any mismatch
// or absence. No network is performed here. The pinned hashes match the server
// (scripts/download-model.js) and are updated only via a reviewed code change.
//
// There is NO server fallback by design: if the device can't run the model
// (node-llama-cpp missing, files not provisioned, hash mismatch, load failure),
// every entry point raises an honest AC_LOCAL_UNAVAILABLE. The renderer surfaces
// "unavailable on this device" rather than silently reaching the server.
//
// Models (same official sources as the server):
//   chat  — Phi-4 Q4_K (MIT), a single official GGUF (~9.05GB), loaded
//           directly. Heavyweight; the documented endpoint floor is
//           ~9.05GB free disk + ~10-12GB RAM. Under-spec / thin-VDI
//           endpoints lose the local chat (honest unavailable).
//   embed — Nomic Embed Text v1.5 F16 (Apache-2.0, ~274MB, 768-dim). Builds
//           the KB vector index on-device on first use and caches it locally.
//
// Public API:
//   setModelRoot(dir) / getModelRootPath()
//   getChatModelPath() / getEmbedModelPath()
//   chatModelPresent() / embedModelPresent()
//   verifyLocalModel(which) -> Promise<{ok,status,files}>   which: 'chat'|'embed'
//   provisioningInfo() -> object for the renderer's provisioning UX
//   getStatus() -> object for the renderer's model-status UX
//   embed(text) -> Promise<number[]>
//   ensureIndex() / buildIndex(opts) / loadIndex()
//   search(query, k) -> Promise<[{id, score}]>
//   generate(prompt, options) -> Promise<{text, modelName, tokenCount}>
//   unloadAll() -> Promise<void>
//   MODELS  (registry: official source, loadFile, per-file pinned SHA-256)
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const kbLocal = require('./kb-local');
const ggufValidate = require('./gguf-validate');
const localMalwareScan = require('./local-malware-scan');

// Minimal logger — the AC main process logs to the console.
const log = {
  info: (...a) => console.log('[local-llm]', ...a),
  warn: (...a) => console.warn('[local-llm]', ...a),
  error: (...a) => console.error('[local-llm]', ...a),
};

// ── Model registry (pinned in source, verify-only — NO download URLs) ─────────
// SHA-256s were read from the official publisher pages and are pinned here. They are
// byte-identical to the server manifest (scripts/download-model.js).
const MODELS = {
  chat: {
    label: 'Phi-4 Q4_K (Microsoft, MIT) - heavyweight on-device chat',
    officialSource: {
      huggingFaceRepo: 'microsoft/phi-4-gguf',
      pinnedCommit: '18ece485b98ae22388ffad82ad468cc2d774f6d4',
    },
    // node-llama-cpp loads this single-file GGUF; it is verified before load.
    loadFile: 'phi-4-Q4_K.gguf',
    files: [
      { filename: 'phi-4-Q4_K.gguf', sizeApprox: '9.05 GB',
        sha256: '5652b9be0ea4ae2842130d04fe31bc869fcb99a2b7106c53b4e754a343fd688f' },
    ],
    endpointFloor: '~9.05 GB free disk + ~10-12 GB RAM',
  },
  embed: {
    label: 'Nomic Embed Text v1.5 F16 (Nomic AI, Apache-2.0) - 768-dim embedder',
    officialSource: {
      huggingFaceRepo: 'nomic-ai/nomic-embed-text-v1.5-GGUF',
      pinnedCommit: '18d1044f4866e224159fce8c6fc5c4f3920176e7',
    },
    loadFile: 'nomic-embed-text-v1.5.f16.gguf',
    files: [
      { filename: 'nomic-embed-text-v1.5.f16.gguf', sizeApprox: '274 MB',
        sha256: 'f7af6f66802f4df86eda10fe9bbcfc75c39562bed48ef6ace719a251cf1c2fdb' },
    ],
    endpointFloor: '~274 MB free disk',
  },
};

const EXPECTED_DIM = kbLocal.EXPECTED_DIM || 768;

function resolveIdleUnloadMs() {
  const raw = process.env.FIREALIVE_AC_IDLE_UNLOAD_MS;
  if (raw === undefined || raw === '') return 5 * 60 * 1000;
  const n = parseInt(raw, 10);
  return (Number.isFinite(n) && n > 0) ? n : 5 * 60 * 1000;
}
const IDLE_UNLOAD_MS = resolveIdleUnloadMs();

// ── State ─────────────────────────────────────────────────────────────────────
let modelRootOverride = null;
let embeddingIndex = null, indexMeta = null;
let idleTimer = null;
// ── Isolated utilityProcess (on-device; contained loader + inference) ─────────
let util = null;                 // Electron UtilityProcess
let utilReady = false;
let utilReadyWaiters = [];
let current = null;              // single in-flight request { match, resolve, reject, timer }
let chain = Promise.resolve();   // single-flight executor
const loaded = { chat: false, embed: false };
let utilForkForTest = null;      // test injection hook (see __setUtilityFork)
const UTIL_TIMEOUT_MS = Number(process.env.FIREALIVE_LOCAL_LLM_TIMEOUT_MS) || 120000;
// Signature (size+mtime per file) of the last SHA-verified set, per model. Lets
// idle-reload skip re-hashing a byte-stable model; a file swap changes it.
let verifySig = { chat: null, embed: null };
let lastGate = { chat: null, embed: null }; // last model-file integrity & safety gate result per model

// ── Paths (trusted: env / app-configured / home; never request input) ─────────
function setModelRoot(dir) {
  modelRootOverride = dir ? path.resolve(dir) : null;
}
function getModelRootPath() {
  if (modelRootOverride) return modelRootOverride;
  const env = process.env.FIREALIVE_AC_MODEL_PATH;
  if (env) return path.resolve(env);
  return path.resolve(os.homedir(), '.firealive', 'ac-models');
}
function getChatModelPath() { return path.join(getModelRootPath(), MODELS.chat.loadFile); }
function getEmbedModelPath() { return path.join(getModelRootPath(), MODELS.embed.loadFile); }
function getCachePath() { return path.join(getModelRootPath(), 'kb-embeddings-local.json'); }
function embedderId() { return MODELS.embed.loadFile.replace(/\.gguf$/i, ''); }

function fileExists(p) { try { return fs.existsSync(p); } catch (_e) { return false; } }
function modelFilePaths(which) {
  const m = MODELS[which];
  if (!m) return [];
  const dir = getModelRootPath();
  return m.files.map(f => ({ ...f, path: path.join(dir, f.filename) }));
}
function chatModelPresent() { return modelFilePaths('chat').every(f => fileExists(f.path)); }
function embedModelPresent() { return modelFilePaths('embed').every(f => fileExists(f.path)); }

// ── Status + provisioning ─────────────────────────────────────────────────────
function getStatus() {
  const chatPresent = chatModelPresent();
  const embedPresent = embedModelPresent();
  return {
    modelRoot: getModelRootPath(),
    chat: { present: chatPresent, ready: loaded.chat, loadFile: MODELS.chat.loadFile, path: getChatModelPath() },
    embed: { present: embedPresent, ready: loaded.embed, loadFile: MODELS.embed.loadFile, path: getEmbedModelPath() },
    dim: EXPECTED_DIM,
    kbVersion: kbLocal.KB_VERSION,
    indexReady: embeddingIndex !== null,
    indexMeta,
    cachePath: getCachePath(),
    idleUnloadMs: IDLE_UNLOAD_MS,
    available: chatPresent && embedPresent,
    provisioningRequired: !(chatPresent && embedPresent),
  };
}

// Structured guide for the renderer: official source, pinned hashes, target dir.
function provisioningInfo() {
  const out = { modelRoot: getModelRootPath(), models: {} };
  for (const which of Object.keys(MODELS)) {
    const m = MODELS[which];
    out.models[which] = {
      label: m.label,
      officialSource: m.officialSource,
      endpointFloor: m.endpointFloor,
      files: m.files.map(f => ({ filename: f.filename, sizeApprox: f.sizeApprox, sha256: f.sha256 })),
      present: which === 'chat' ? chatModelPresent() : embedModelPresent(),
      safety: lastGate[which]
        ? { ok: lastGate[which].ok, overall: lastGate[which].overall, reason: lastGate[which].reason, at: lastGate[which].at }
        : null,
    };
  }
  return out;
}

// Last model-file integrity & safety gate result (for the renderer / IPC).
function getModelSafetyStatus(which) {
  if (which) return lastGate[which] || null;
  return { chat: lastGate.chat, embed: lastGate.embed };
}

function provisioningHint(which) {
  const m = MODELS[which];
  if (!m) return '';
  return 'Provision the official ' + m.officialSource.huggingFaceRepo + ' file(s) into ' +
    getModelRootPath() + ' (verify-only; no download). Run with --instructions for hashes.';
}

function unavailable(message) {
  const err = new Error(message);
  err.code = 'AC_LOCAL_UNAVAILABLE';
  return err;
}

function resetIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    log.info('idle timeout — unloading local models');
    unloadAll().catch((e) => log.error('idle unload failed', e.message));
  }, IDLE_UNLOAD_MS);
}

// ── Verify (the only integrity gate; NO network) ─────────────────────────────
function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

function filesSignature(which) {
  try {
    return modelFilePaths(which).map(f => {
      try { const st = fs.statSync(f.path); return f.filename + ':' + st.size + ':' + st.mtimeMs; }
      catch (_e) { return f.filename + ':missing'; }
    }).join('|');
  } catch (_e) { return null; }
}

async function verifyLocalModel(which) {
  const m = MODELS[which];
  if (!m) return { ok: false, status: 'unknown-model', which, files: [] };
  const files = [];
  let anyMissing = false, anyMismatch = false;
  for (const f of modelFilePaths(which)) {
    if (!fileExists(f.path)) {
      anyMissing = true;
      files.push({ filename: f.filename, present: false, match: false, expected: f.sha256, actual: null });
      continue;
    }
    const actual = await sha256File(f.path);
    const match = actual === f.sha256;
    if (!match) anyMismatch = true;
    files.push({ filename: f.filename, present: true, match, expected: f.sha256, actual });
  }
  const status = anyMissing ? 'missing' : (anyMismatch ? 'mismatch' : 'ok');
  return { ok: status === 'ok', status, which, files };
}

// ── Model-file integrity & safety gate (fail-closed, on-device) ──────────────
// Runs before the local loader reads the GGUF: hash-pin (layer 1) → GGUF format
// validation (layer 3) → local malware scan (layer 4, by-path, nothing leaves
// the device). Layer 2 (signature) is a server-side option; the AC gate is
// hash / format / malware. Short-circuits on the first failing layer.
async function runSafetyGate(which) {
  const result = { ok: false, overall: 'loaded', reason: null, status: null, files: [], at: Date.now() };
  const v = await verifyLocalModel(which); // layer 1 — hash-pin
  result.status = v.status;
  if (!v.ok) {
    result.overall = 'blocked_hash';
    result.reason = which + ' model failed verification (' + v.status + ')';
    result.files = v.files.map(f => ({ filename: f.filename, hashPinOk: !!f.match, formatOk: null, malware: null }));
    lastGate[which] = result;
    return result;
  }
  for (const f of modelFilePaths(which)) {
    const fr = { filename: f.filename, hashPinOk: true, formatOk: null, malware: null };
    if (/\.gguf$/i.test(f.filename)) {
      const fmt = ggufValidate.validateGguf(f.path); // layer 3 — format
      fr.formatOk = !!fmt.ok;
      if (!fmt.ok) {
        result.overall = 'blocked_format';
        result.reason = f.filename + ': GGUF format ' + fmt.reason + ' (' + fmt.code + ')';
        result.files.push(fr); lastGate[which] = result; return result;
      }
    }
    const mal = await localMalwareScan.scanModelFileLocal(f.path); // layer 4 — malware
    fr.malware = {
      scanner: mal.scanner || null,
      outcome: mal.noScanner ? 'no-scanner' : (mal.error ? 'error' : (mal.clean ? 'clean' : 'threat')),
      threats: mal.threats || [],
    };
    if (mal.noScanner) { result.overall = 'blocked_no_scanner'; result.reason = 'no local malware scanner available on this device'; result.files.push(fr); lastGate[which] = result; return result; }
    if (mal.error) { result.overall = 'blocked_malware'; result.reason = f.filename + ': scan error: ' + mal.reason; result.files.push(fr); lastGate[which] = result; return result; }
    if (!mal.clean) { result.overall = 'blocked_malware'; result.reason = f.filename + ': malware detected: ' + (mal.threats || []).join('; '); result.files.push(fr); lastGate[which] = result; return result; }
    result.files.push(fr);
  }
  result.ok = true; result.overall = 'loaded';
  lastGate[which] = result;
  return result;
}

// Verify-before-load with a re-run skip: only re-runs the gate when the on-disk
// file set changed (size/mtime) since the last successful gate pass.
async function verifyBeforeLoad(which) {
  const sig = filesSignature(which);
  if (sig !== null && sig === verifySig[which]) return;
  const gate = await runSafetyGate(which);
  if (!gate.ok) {
    verifySig[which] = null;
    throw unavailable(which + ' model failed the integrity & safety gate (' + gate.overall + '): ' + (gate.reason || 'unknown') + ' on this device. ' + provisioningHint(which));
  }
  verifySig[which] = sig;
}

// ── Isolated utilityProcess host (on-device; nothing leaves the machine) ──────
function spawnUtil() {
  const scriptPath = path.join(__dirname, 'model-utility.js').replace('app.asar' + path.sep, 'app.asar.unpacked' + path.sep);
  let forkFn = utilForkForTest;
  if (!forkFn) {
    let up;
    try { up = require('electron').utilityProcess; } catch (e) { throw unavailable('utilityProcess unavailable: ' + e.message); }
    if (!up || typeof up.fork !== 'function') throw unavailable('Electron utilityProcess.fork unavailable');
    forkFn = (p) => up.fork(p, [], { serviceName: 'firealive-model', stdio: 'inherit' });
  }
  util = forkFn(scriptPath);
  utilReady = false;
  util.on('message', onUtilMessage);
  util.on('exit', onUtilExit);
}

function finishCurrent(m, err) {
  if (!current) return;
  const c = current; current = null;
  if (c.timer) clearTimeout(c.timer);
  if (err) c.reject(err); else c.resolve(m);
}

function onUtilMessage(m) {
  if (!m || typeof m.t !== 'string') return;
  if (m.t === 'log') { const lv = m.level || 'info'; (log[lv] || log.info)('[model-utility] ' + m.msg, m.meta || undefined); return; }
  if (m.t === 'ready') { utilReady = true; const w = utilReadyWaiters; utilReadyWaiters = []; w.forEach((r) => r()); return; }
  if (m.t === 'loaded' && m.kind) loaded[m.kind] = true;
  if (m.t === 'unloaded') { if (m.kind === 'all' || !m.kind) { loaded.chat = false; loaded.embed = false; } else loaded[m.kind] = false; }
  if (current) {
    if (m.t === 'error') { const e = new Error(m.message || 'utility error'); e.code = m.code || 'AC_LOCAL_UNAVAILABLE'; finishCurrent(null, e); return; }
    if (current.match(m)) { finishCurrent(m, null); return; }
  }
}

function onUtilExit(code) {
  utilReady = false; util = null; loaded.chat = false; loaded.embed = false;
  if (current) finishCurrent(null, unavailable('model utility exited (' + code + ')'));
  log.warn('model utility exited', { code });
}

async function ensureUtil() {
  if (util && utilReady) return;
  if (!util) spawnUtil();
  if (!utilReady) {
    await new Promise((resolve, reject) => {
      const to = setTimeout(() => reject(unavailable('model utility did not become ready')), UTIL_TIMEOUT_MS);
      utilReadyWaiters.push(() => { clearTimeout(to); resolve(); });
    });
  }
}

function runUtil(msg, match) {
  const op = async () => {
    await ensureUtil();
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const e = new Error('model utility timed out'); e.code = 'AC_LOCAL_FAILED';
        finishCurrent(null, e);
        try { if (util) util.kill(); } catch (_e) { /* ignore */ }
      }, UTIL_TIMEOUT_MS);
      current = { match, resolve, reject, timer };
      try { util.postMessage(msg); } catch (e) { finishCurrent(null, unavailable('failed to message utility: ' + e.message)); }
    });
  };
  const result = chain.then(op, op);
  chain = result.then(() => {}, () => {});
  return result;
}

function shutdownUtil() {
  try { if (util) { if (typeof util.removeAllListeners === 'function') util.removeAllListeners('exit'); util.kill(); } } catch (_e) { /* ignore */ }
  util = null; utilReady = false; loaded.chat = false; loaded.embed = false;
  if (current) finishCurrent(null, unavailable('model utility shut down'));
}

// Test seam: inject a fake fork(scriptPath) -> UtilityProcess-like EventEmitter.
function __setUtilityFork(fn) { utilForkForTest = fn; }

async function loadChat() {
  if (loaded.chat) return;
  await verifyBeforeLoad('chat');           // gate runs in main, before any load
  const modelPath = getChatModelPath();
  let size = 0; try { size = fs.statSync(modelPath).size; } catch (_e) { /* worker re-stats */ }
  await runUtil({ t: 'load', kind: 'chat', modelPath, expectedSizeBytes: size }, (m) => m.t === 'loaded' && m.kind === 'chat');
  resetIdleTimer();
  log.info('chat model loaded (isolated)');
}

async function loadEmbed() {
  if (loaded.embed) return;
  await verifyBeforeLoad('embed');
  const modelPath = getEmbedModelPath();
  let size = 0; try { size = fs.statSync(modelPath).size; } catch (_e) { /* worker re-stats */ }
  await runUtil({ t: 'load', kind: 'embed', modelPath, expectedSizeBytes: size }, (m) => m.t === 'loaded' && m.kind === 'embed');
  resetIdleTimer();
  log.info('embedding model loaded (isolated)');
}

async function unloadAll() {
  if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
  // Stop the utility process entirely — frees all model memory and resets the
  // blast radius; it respawns lazily on next use.
  shutdownUtil();
  log.info('local models unloaded (utility stopped)');
}

// ── Embedding + index ─────────────────────────────────────────────────────────
// Nomic Embed task-instruction prefixes. embed() is the query entry point, so
// bare text defaults to a search query; document callers pass 'search_document: '.
const NOMIC_TASK_PREFIXES = ['search_query: ', 'search_document: ', 'classification: ', 'clustering: '];
function hasNomicTaskPrefix(text) {
  return NOMIC_TASK_PREFIXES.some(function (p) { return text.startsWith(p); });
}

async function embed(text) {
  if (typeof text !== 'string' || text.length === 0) {
    const e = new Error('embed() requires a non-empty string'); e.code = 'AC_LOCAL_FAILED'; throw e;
  }
  // Nomic requires a task prefix; bare text is treated as a search query.
  const prefixed = hasNomicTaskPrefix(text) ? text : 'search_query: ' + text;
  await loadEmbed();
  let vector;
  try {
    const m = await runUtil({ t: 'embed', id: 'e', text: prefixed }, (x) => x.t === 'embedding');
    vector = m.vector;
  } catch (err) {
    const e = new Error('embedding inference failed: ' + (err.message || String(err))); e.code = err.code || 'AC_LOCAL_FAILED'; throw e;
  }
  resetIdleTimer();
  return vector;
}

function readCacheSafe() {
  try { return JSON.parse(fs.readFileSync(getCachePath(), 'utf8')); } catch (_e) { return null; }
}
function isCacheFresh(c) {
  return !!c && c.kbVersion === kbLocal.KB_VERSION && c.embedderId === embedderId()
    && Array.isArray(c.entries) && c.entries.length === kbLocal.getAll().length;
}
function loadIndex() {
  const c = readCacheSafe();
  if (!isCacheFresh(c)) return null;
  embeddingIndex = c.entries.map((e) => ({ id: e.id, vector: e.vector }));
  indexMeta = { kbVersion: c.kbVersion, embedderId: c.embedderId, dim: c.dim, count: c.entries.length, generatedAt: c.generatedAt };
  return embeddingIndex;
}
async function buildIndex(opts) {
  opts = opts || {};
  const entries = kbLocal.getAll();
  const built = [];
  let dim = null;
  for (let i = 0; i < entries.length; i++) {
    const v = await embed('search_document: ' + kbLocal.entryEmbeddingText(entries[i]));
    if (dim === null) dim = v.length;
    built.push({ id: entries[i].id, vector: v });
    if (typeof opts.onProgress === 'function') opts.onProgress({ done: i + 1, total: entries.length });
  }
  const cache = { kbVersion: kbLocal.KB_VERSION, embedderId: embedderId(), dim, generatedAt: new Date().toISOString(), entries: built };
  try {
    fs.mkdirSync(path.dirname(getCachePath()), { recursive: true });
    fs.writeFileSync(getCachePath(), JSON.stringify(cache), 'utf8');
  } catch (err) {
    log.warn('could not persist local embeddings cache: ' + err.message);
  }
  embeddingIndex = built.map((e) => ({ id: e.id, vector: e.vector }));
  indexMeta = { kbVersion: cache.kbVersion, embedderId: cache.embedderId, dim, count: built.length, generatedAt: cache.generatedAt };
  return { dim, count: built.length };
}
async function ensureIndex() {
  if (embeddingIndex) return embeddingIndex;
  if (loadIndex()) return embeddingIndex;
  await buildIndex();
  return embeddingIndex;
}

async function search(query, k) {
  await ensureIndex();
  const qv = await embed('search_query: ' + query);
  return kbLocal.cosineTopN(qv, k, embeddingIndex);
}

// ── Chat ──────────────────────────────────────────────────────────────────────
function estimateTokens(a, b) { return Math.ceil(((a || '').length + (b || '').length) / 4); }

async function generate(prompt, options) {
  options = options || {};
  const maxTokens = options.maxTokens || 700;
  const temperature = (options.temperature !== undefined) ? options.temperature : 0.3;
  await loadChat();
  let text;
  try {
    const m = await runUtil({ t: 'generate', id: 'g', prompt, options: { maxTokens, temperature } }, (x) => x.t === 'result');
    text = m.text;
  } catch (err) {
    const e = new Error('local inference failed: ' + (err.message || String(err))); e.code = err.code || 'AC_LOCAL_FAILED'; throw e;
  }
  resetIdleTimer();
  return { text, modelName: MODELS.chat.loadFile, tokenCount: estimateTokens(prompt, text) };
}

module.exports = {
  MODELS,
  EXPECTED_DIM,
  setModelRoot,
  getModelRootPath,
  getChatModelPath,
  getEmbedModelPath,
  getCachePath,
  chatModelPresent,
  embedModelPresent,
  verifyLocalModel,
  provisioningInfo,
  getModelSafetyStatus,
  getStatus,
  loadChat,
  loadEmbed,
  unloadAll,
  embed,
  loadIndex,
  buildIndex,
  ensureIndex,
  search,
  generate,
  shutdownUtil,
  __setUtilityFork,
};

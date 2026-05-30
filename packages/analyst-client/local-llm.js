// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Analyst Client local inference + retrieval (firewalled, on-device)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// The Analyst Client's OWN local AI: a heavyweight chat model + the all-MiniLM
// embedder, both run on the analyst's device via node-llama-cpp. It powers the
// Analyst KB Assistant chat (PR7) with ZERO server round-trips — preserving the
// Tier-3 firewall (the analyst's questions and signals never leave the device).
//
// There is NO server fallback by design: if the device can't run the model
// (node-llama-cpp missing, model not downloaded, load failure), every entry point
// returns/raises an honest AC_LOCAL_UNAVAILABLE. The renderer surfaces "unavailable
// on this device" rather than silently reaching the server, which would breach the
// firewall.
//
// Mirrors the server conventions (server/services/internal-llm.js +
// kb-embeddings.js + scripts/download-model.js): lazy require('node-llama-cpp'),
// getLlama() → loadModel → context, idle-unload, SHA-256-verified download.
//
// Models (same caliber/source as the server):
//   chat  — Phi-3-mini-4k-instruct-q4 (~2.4GB, MIT). Heavyweight; ops-configurable
//           path but defaults heavyweight. This is the documented endpoint floor:
//           under-spec / thin-VDI endpoints lose the local chat (honest unavailable).
//   embed — all-MiniLM-L6-v2 Q8_0 (~25MB, 384-dim). Builds the KB vector index
//           on-device on first use and caches it locally.
//
// Public API:
//   setModelRoot(dir) / getModelRootPath()
//   getChatModelPath() / getEmbedModelPath()
//   chatModelPresent() / embedModelPresent()
//   getStatus() -> object for the renderer's model-status UX
//   embed(text) -> Promise<number[]>
//   ensureIndex() / buildIndex(opts) / loadIndex()
//   search(query, k) -> Promise<[{id, score}]>
//   generate(prompt, options) -> Promise<{text, modelName, tokenCount}>
//   downloadModel(which, opts) -> Promise<{which, path, sha256}>   which: 'chat'|'embed'
//   unloadAll() -> Promise<void>
//   MODELS  (registry: filenames, source URLs, pinned SHA-256)
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const https = require('https');
const kbLocal = require('./kb-local');

// Minimal logger — the AC main process logs to the console.
const log = {
  info: (...a) => console.log('[local-llm]', ...a),
  warn: (...a) => console.warn('[local-llm]', ...a),
  error: (...a) => console.error('[local-llm]', ...a),
};

// ── Model registry (pinned, verified) ────────────────────────────────────────
const MODELS = {
  chat: {
    label: 'Phi-3-mini-4k-instruct q4 (Microsoft, MIT) — heavyweight local chat',
    filename: 'phi-3-mini-4k-instruct-q4.gguf',
    sourceUrl: 'https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf',
    sha256: '8a83c7fb9049a9b2e92266fa7ad04933bb53aa1e85136b7b30f1b8000ff2edef',
  },
  embed: {
    label: 'all-MiniLM-L6-v2 Q8_0 (Second State, Apache-2.0) — 384-dim embedder',
    filename: 'all-MiniLM-L6-v2-Q8_0.gguf',
    sourceUrl: 'https://huggingface.co/second-state/All-MiniLM-L6-v2-Embedding-GGUF/resolve/main/all-MiniLM-L6-v2-Q8_0.gguf',
    sha256: '263215c3cadd6e16740741a7624ab4cbb6c8e777688bd5331ecfbf5681c2f8ed',
  },
};

const EXPECTED_DIM = kbLocal.EXPECTED_DIM || 384;
const MAX_REDIRECTS = 5;

function resolveIdleUnloadMs() {
  const raw = process.env.FIREALIVE_AC_IDLE_UNLOAD_MS;
  if (raw === undefined || raw === '') return 5 * 60 * 1000;
  const n = parseInt(raw, 10);
  return (Number.isFinite(n) && n > 0) ? n : 5 * 60 * 1000;
}
const IDLE_UNLOAD_MS = resolveIdleUnloadMs();

// ── State ─────────────────────────────────────────────────────────────────────
let modelRootOverride = null;
let llamaModule = null;
let llama = null;
let chatModel = null, chatContext = null;
let embedModel = null, embedContext = null;
let embeddingIndex = null, indexMeta = null;
let idleTimer = null;

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
function getChatModelPath() { return path.join(getModelRootPath(), MODELS.chat.filename); }
function getEmbedModelPath() { return path.join(getModelRootPath(), MODELS.embed.filename); }
function getCachePath() { return path.join(getModelRootPath(), 'kb-embeddings-local.json'); }
function embedderId() { return MODELS.embed.filename.replace(/\.gguf$/i, ''); }

function fileExists(p) { try { return fs.existsSync(p); } catch (_e) { return false; } }
function chatModelPresent() { return fileExists(getChatModelPath()); }
function embedModelPresent() { return fileExists(getEmbedModelPath()); }

// ── Status ──────────────────────────────────────────────────────────────────
function getStatus() {
  return {
    modelRoot: getModelRootPath(),
    chat: { present: chatModelPresent(), ready: !!(chatModel && chatContext), filename: MODELS.chat.filename, path: getChatModelPath() },
    embed: { present: embedModelPresent(), ready: !!(embedModel && embedContext), filename: MODELS.embed.filename, path: getEmbedModelPath() },
    dim: EXPECTED_DIM,
    kbVersion: kbLocal.KB_VERSION,
    indexReady: embeddingIndex !== null,
    indexMeta,
    cachePath: getCachePath(),
    idleUnloadMs: IDLE_UNLOAD_MS,
    // Honest capability flag for the renderer: can we run the chat right now?
    available: chatModelPresent() && embedModelPresent(),
  };
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

// ── node-llama-cpp loader ─────────────────────────────────────────────────────
function requireLlama() {
  if (llamaModule) return llamaModule;
  try {
    llamaModule = require('node-llama-cpp');
  } catch (err) {
    throw unavailable('node-llama-cpp not available on this device: ' + err.message);
  }
  return llamaModule;
}
async function getLlamaInstance() {
  if (llama) return llama;
  const { getLlama } = requireLlama();
  llama = await getLlama();
  return llama;
}

async function loadChat() {
  if (chatModel && chatContext) return;
  const modelPath = getChatModelPath();
  if (!fileExists(modelPath)) throw unavailable('chat model not downloaded on this device: ' + modelPath);
  const l = await getLlamaInstance();
  try {
    chatModel = await l.loadModel({ modelPath });
    chatContext = await chatModel.createContext();
  } catch (err) {
    chatModel = null; chatContext = null;
    throw unavailable('failed to load chat model on this device: ' + (err.message || String(err)));
  }
  resetIdleTimer();
  log.info('chat model loaded');
}

async function loadEmbed() {
  if (embedModel && embedContext) return;
  const modelPath = getEmbedModelPath();
  if (!fileExists(modelPath)) throw unavailable('embedding model not downloaded on this device: ' + modelPath);
  const l = await getLlamaInstance();
  try {
    embedModel = await l.loadModel({ modelPath });
    embedContext = await embedModel.createEmbeddingContext();
  } catch (err) {
    embedModel = null; embedContext = null;
    throw unavailable('failed to load embedding model on this device: ' + (err.message || String(err)));
  }
  resetIdleTimer();
  log.info('embedding model loaded');
}

async function unloadAll() {
  if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
  for (const [ctx, mdl] of [[chatContext, chatModel], [embedContext, embedModel]]) {
    if (ctx) { try { await ctx.dispose(); } catch (_e) {} }
    if (mdl) { try { await mdl.dispose(); } catch (_e) {} }
  }
  chatContext = chatModel = embedContext = embedModel = null;
  log.info('local models unloaded');
}

// ── Embedding + index ─────────────────────────────────────────────────────────
async function embed(text) {
  if (typeof text !== 'string' || text.length === 0) {
    const e = new Error('embed() requires a non-empty string'); e.code = 'AC_LOCAL_FAILED'; throw e;
  }
  await loadEmbed();
  let vector;
  try {
    const r = await embedContext.getEmbeddingFor(text);
    vector = Array.from(r.vector);
  } catch (err) {
    const e = new Error('embedding inference failed: ' + (err.message || String(err))); e.code = 'AC_LOCAL_FAILED'; throw e;
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
    const v = await embed(kbLocal.entryEmbeddingText(entries[i]));
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
  const qv = await embed(query);
  return kbLocal.cosineTopN(qv, k, embeddingIndex);
}

// ── Chat ──────────────────────────────────────────────────────────────────────
function estimateTokens(a, b) { return Math.ceil(((a || '').length + (b || '').length) / 4); }

async function generate(prompt, options) {
  options = options || {};
  const maxTokens = options.maxTokens || 700;
  const temperature = (options.temperature !== undefined) ? options.temperature : 0.3;
  await loadChat();
  const { LlamaChatSession } = requireLlama();
  const session = new LlamaChatSession({ contextSequence: chatContext.getSequence() });
  let text;
  try {
    text = await session.prompt(prompt, { temperature, maxTokens });
  } catch (err) {
    const e = new Error('local inference failed: ' + (err.message || String(err))); e.code = 'AC_LOCAL_FAILED'; throw e;
  }
  resetIdleTimer();
  return { text, modelName: MODELS.chat.filename, tokenCount: estimateTokens(prompt, text) };
}

// ── First-run model download (SHA-256 verified; mirrors scripts/download-model.js) ─
function downloadToFile(url, dest, redirectsLeft) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) return reject(new Error('too many redirects'));
        return resolve(downloadToFile(res.headers.location, dest, redirectsLeft - 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('download failed: HTTP ' + res.statusCode)); }
      const hash = crypto.createHash('sha256');
      const out = fs.createWriteStream(dest);
      res.on('data', (chunk) => hash.update(chunk));
      res.pipe(out);
      out.on('finish', () => out.close(() => resolve(hash.digest('hex'))));
      out.on('error', reject);
      res.on('error', reject);
    });
    req.on('error', reject);
  });
}

async function downloadModel(which, opts) {
  opts = opts || {};
  const m = MODELS[which];
  if (!m) { const e = new Error('unknown model: ' + which); e.code = 'AC_LOCAL_FAILED'; throw e; }
  const dir = getModelRootPath();
  fs.mkdirSync(dir, { recursive: true });
  const dest = path.join(dir, m.filename);
  const tmp = dest + '.download';
  log.info('downloading ' + which + ' model', m.sourceUrl);
  let actualSha;
  try {
    actualSha = await downloadToFile(m.sourceUrl, tmp, MAX_REDIRECTS);
  } catch (err) {
    try { fs.existsSync(tmp) && fs.unlinkSync(tmp); } catch (_e) {}
    throw unavailable('model download failed: ' + (err.message || String(err)));
  }
  if (m.sha256 && actualSha !== m.sha256) {
    try { fs.unlinkSync(tmp); } catch (_e) {}
    const e = new Error('SHA-256 mismatch for ' + m.filename + ' (expected ' + m.sha256 + ', got ' + actualSha + ')');
    e.code = 'AC_LOCAL_FAILED';
    throw e;
  }
  fs.renameSync(tmp, dest);
  log.info(which + ' model downloaded + verified', dest);
  return { which, path: dest, sha256: actualSha };
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
  downloadModel,
};

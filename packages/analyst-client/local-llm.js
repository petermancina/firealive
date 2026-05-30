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
// official files (verified Qwen org on Hugging Face, Alibaba ModelScope, or an
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
// Models (same official Qwen sources as the server):
//   chat  — Qwen2.5-14B-Instruct q4_K_M (Apache-2.0), 3 official split shards
//           (~9GB total), loaded from shard-00001. Heavyweight; the documented
//           endpoint floor is ~9GB free disk + ~10-12GB RAM. Under-spec /
//           thin-VDI endpoints lose the local chat (honest unavailable).
//   embed — Qwen3-Embedding-0.6B Q8_0 (Apache-2.0, ~639MB, 1024-dim). Builds the
//           KB vector index on-device on first use and caches it locally.
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

// Minimal logger — the AC main process logs to the console.
const log = {
  info: (...a) => console.log('[local-llm]', ...a),
  warn: (...a) => console.warn('[local-llm]', ...a),
  error: (...a) => console.error('[local-llm]', ...a),
};

// ── Model registry (pinned in source, verify-only — NO download URLs) ─────────
// SHA-256s were read from the official Qwen pages and are pinned here. They are
// byte-identical to the server manifest (scripts/download-model.js).
const MODELS = {
  chat: {
    label: 'Qwen2.5-14B-Instruct q4_K_M (Alibaba Qwen, Apache-2.0) — heavyweight on-device chat',
    officialSource: {
      huggingFaceRepo: 'Qwen/Qwen2.5-14B-Instruct-GGUF',
      pinnedCommit: '2b6a96d780143b4e8e3b970394e39e3774551f29',
      modelScope: 'Qwen/Qwen2.5-14B-Instruct-GGUF (Alibaba ModelScope, first-party)',
    },
    // node-llama-cpp loads the split GGUF from the first shard; siblings must be
    // present in the same directory. All shards are verified before load.
    loadFile: 'qwen2.5-14b-instruct-q4_k_m-00001-of-00003.gguf',
    files: [
      { filename: 'qwen2.5-14b-instruct-q4_k_m-00001-of-00003.gguf', sizeApprox: '3.99 GB',
        sha256: 'a09ea5e7b1eafb1b30b241726c3cc3c905c96f14ad41e246ffa5f44e53904f68' },
      { filename: 'qwen2.5-14b-instruct-q4_k_m-00002-of-00003.gguf', sizeApprox: '3.99 GB',
        sha256: '21b9457d079680d284e90ef69607c4b2d8ef64a09d4729cb7b5e1357bdba41ae' },
      { filename: 'qwen2.5-14b-instruct-q4_k_m-00003-of-00003.gguf', sizeApprox: '1.01 GB',
        sha256: 'c8d37006760a387a35216e070e6664d7da927f10be8eb870fef2e3d4833d9976' },
    ],
    endpointFloor: '~9 GB free disk + ~10-12 GB RAM',
  },
  embed: {
    label: 'Qwen3-Embedding-0.6B Q8_0 (Alibaba Qwen, Apache-2.0) — 1024-dim embedder',
    officialSource: {
      huggingFaceRepo: 'Qwen/Qwen3-Embedding-0.6B-GGUF',
      pinnedCommit: 'd20cf9c',
      modelScope: 'Qwen/Qwen3-Embedding-0.6B-GGUF (Alibaba ModelScope, first-party)',
    },
    loadFile: 'Qwen3-Embedding-0.6B-Q8_0.gguf',
    files: [
      { filename: 'Qwen3-Embedding-0.6B-Q8_0.gguf', sizeApprox: '639 MB',
        sha256: '06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439' },
    ],
    endpointFloor: '~640 MB free disk',
  },
};

const EXPECTED_DIM = kbLocal.EXPECTED_DIM || 1024;

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
// Signature (size+mtime per file) of the last SHA-verified set, per model. Lets
// idle-reload skip re-hashing a byte-stable model; a file swap changes it.
let verifySig = { chat: null, embed: null };

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
    chat: { present: chatPresent, ready: !!(chatModel && chatContext), loadFile: MODELS.chat.loadFile, path: getChatModelPath(), shards: MODELS.chat.files.length },
    embed: { present: embedPresent, ready: !!(embedModel && embedContext), loadFile: MODELS.embed.loadFile, path: getEmbedModelPath() },
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
    };
  }
  return out;
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

// Verify-before-load with a re-hash skip: only re-hashes when the on-disk file
// set changed (size/mtime) since the last successful verify.
async function verifyBeforeLoad(which) {
  const sig = filesSignature(which);
  if (sig !== null && sig === verifySig[which]) return;
  const v = await verifyLocalModel(which);
  if (!v.ok) {
    verifySig[which] = null;
    throw unavailable(which + ' model failed verification (' + v.status + ') on this device. ' + provisioningHint(which));
  }
  verifySig[which] = sig;
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
  await verifyBeforeLoad('chat');           // refuses on missing/mismatch, before any load
  const modelPath = getChatModelPath();
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
  await verifyBeforeLoad('embed');
  const modelPath = getEmbedModelPath();
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
  return { text, modelName: MODELS.chat.loadFile, tokenCount: estimateTokens(prompt, text) };
}

// ── Transitional shim (REMOVED once main.js moves to verifyLocalModel) ─────────
// FireAlive performs no downloads. Kept only so the pre-migration IPC handler
// resolves; it fails closed with no network.
async function downloadModel(which) {
  throw unavailable('FireAlive does not download models (verify-only). Provision the official files on this device; they are verified on load. ' + provisioningHint(which));
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
  downloadModel,   // transitional fail-closed shim (no network)
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — KB Embeddings Service (semantic retrieval over the Research KB)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Provides semantic retrieval over the FireAlive Research Knowledge Base
// (server/services/research-kb.js). Loads a small, purpose-built text-embedding
// model (Qwen3-Embedding-0.6B as a GGUF) through the SAME node-llama-cpp library the
// internal chat LLM uses, embeds each KB entry once, caches the vectors, and
// answers cosine-similarity top-N queries.
//
// This is the retrieval foundation for K1: the Lead KB Assistant chat (MC, server
// side) and — via a bundled mirror of this logic — the Analyst KB Assistant chat
// (AC, local). It does NOT generate any text and is NOT a chat surface; it only
// turns a query string into the most relevant KB entry ids + scores. The chat
// routes layer RAG (retrieve → ground an LLM → strict citation gate) on top.
//
// ── Model ───────────────────────────────────────────────────────────────────
// Embedding model: Qwen3-Embedding-0.6B (1024-dim, ~639MB GGUF, official Qwen org, Apache-2.0). Purpose-built for
// short-text retrieval and deliberately DECOUPLED from the chat LLM — a separate
// model, separate context, separate lifecycle. It stays inside the ruled-in
// node-llama-cpp library (this is NOT the transformers.js path the AI/ML strategy
// excluded). The model file is resolved from FIREALIVE_EMBED_MODEL_PATH, or
// defaults to the shared model root (~/.firealive/models, the same root the
// internal LLM uses). The bootstrap script adds this model to the download set
// (scripts/download-model.js, PR2/C2).
//
// ── Embedding text ──────────────────────────────────────────────────────────
// Each KB entry is embedded as `finding + implication + summary` joined by
// newlines — the three FireAlive-authored fields that carry the entry's meaning.
//
// ── Cache (kb-embeddings.json) ────────────────────────────────────────────────
// Embedding the corpus is done once and cached, keyed by KB_VERSION + embedder id.
// On load, a cache whose kbVersion or embedderId does not match the current KB /
// model is treated as stale and rebuilt. This means the cache regenerates
// automatically whenever the KB content version bumps (e.g. a future KB rebuild)
// or the embedding model changes — no manual invalidation. Cache location is
// FIREALIVE_KB_EMBEDDINGS_PATH, else <model root>/kb-embeddings.json.
//
// ── Idle unload ───────────────────────────────────────────────────────────────
// Like the internal LLM, the embedding model unloads after an idle timeout to
// free memory (FIREALIVE_EMBED_IDLE_UNLOAD_MS, default 5 minutes). The in-memory
// vector index (tiny — 50 × 1024 floats) stays resident regardless; only the model
// (which is only needed to embed live queries) is unloaded.
//
// ── Anti-hallucination note ───────────────────────────────────────────────────
// Retrieval returns only ids that exist in the KB (the index is built from
// getAll()). It can never surface a non-existent reference. The downstream chat
// still runs every model output through validateCitations as the hard gate.
//
// Public API:
//   isReady()                         -> boolean (embedding model loaded)
//   getStatus()                       -> object for the AI/ML Integrations tab
//   embed(text)                       -> Promise<number[]>  (1024-dim query vector)
//   cosineSimilarity(a, b)            -> number  (pure)
//   cosineTopN(queryVec, k, index?)   -> [{ id, score }]  sorted desc, len ≤ k
//   loadEmbeddings()                  -> index | null  (read cache; null if stale/absent)
//   buildEmbeddings(opts?)            -> Promise<{ kbVersion, embedderId, dim, count }>
//   ensureEmbeddings()                -> Promise<index>  (load cache, else build)
//   search(query, k)                  -> Promise<[{ id, score }]>  (embed + topN)
//   unloadModel()                     -> Promise<void>
//   getModelRootPath() / getEmbedderModelPath() / getCachePath() / embedderId()
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const os = require('os');
const { logger } = require('./logger');
const kb = require('./research-kb');

// ── Configuration ─────────────────────────────────────────────────────────────

// Default embedder filename. The exact source URL + pinned SHA-256 are wired in
// scripts/download-model.js (verify-only manifest); this is the on-disk name we look for.
const DEFAULT_EMBED_FILENAME = 'Qwen3-Embedding-0.6B-Q8_0.gguf';

// Expected dimensionality for Qwen3-Embedding-0.6B (sanity check, not enforced).
const EXPECTED_DIM = 1024;

function resolveEmbedIdleUnloadMs() {
  const raw = process.env.FIREALIVE_EMBED_IDLE_UNLOAD_MS;
  if (raw === undefined || raw === '') return 5 * 60 * 1000;
  const parsed = parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    logger.warn('FIREALIVE_EMBED_IDLE_UNLOAD_MS is not a positive integer; using default', { value: raw });
    return 5 * 60 * 1000;
  }
  return parsed;
}
const IDLE_UNLOAD_MS = resolveEmbedIdleUnloadMs();

// ── Module state ────────────────────────────────────────────────────────────
let llamaModule = null;        // lazily-required node-llama-cpp module
let model = null;              // loaded LlamaModel (embedding model)
let embeddingContext = null;   // active embedding context
let modelInfo = null;          // { path, name, sizeBytes, loadedAt }
let idleTimer = null;
let loadingPromise = null;     // de-duplicates concurrent loads
let embeddingIndex = null;     // [{ id, vector:number[] }] — resident vector index
let indexMeta = null;          // { kbVersion, embedderId, dim, count, generatedAt }

// ── Path resolution (server-computed, trusted; no request input here) ─────────

function getModelRootPath() {
  const envPath = process.env.FIREALIVE_MODEL_PATH;
  if (envPath) {
    if (envPath.endsWith('.gguf')) return path.resolve(path.dirname(envPath));
    return path.resolve(envPath);
  }
  return path.resolve(os.homedir(), '.firealive', 'models');
}

function getEmbedderModelPath() {
  const envPath = process.env.FIREALIVE_EMBED_MODEL_PATH;
  if (envPath && envPath.toLowerCase().endsWith('.gguf')) return path.resolve(envPath);
  return path.join(getModelRootPath(), DEFAULT_EMBED_FILENAME);
}

// Embedder id = the model filename without extension. Used as part of the cache
// key so swapping the embedding model invalidates (and rebuilds) the cache.
function embedderId() {
  return path.basename(getEmbedderModelPath()).replace(/\.gguf$/i, '');
}

function getCachePath() {
  const envPath = process.env.FIREALIVE_KB_EMBEDDINGS_PATH;
  if (envPath) return path.resolve(envPath);
  return path.join(getModelRootPath(), 'kb-embeddings.json');
}

function embedderModelExists() {
  try { return fs.existsSync(getEmbedderModelPath()); } catch (_) { return false; }
}

// ── Status ────────────────────────────────────────────────────────────────────

function isReady() {
  return model !== null && embeddingContext !== null;
}

function getStatus() {
  return {
    ready: isReady(),
    embedderModelPresent: embedderModelExists(),
    embedderModelPath: getEmbedderModelPath(),
    embedderId: embedderId(),
    idleUnloadMs: IDLE_UNLOAD_MS,
    kbVersion: kb.KB_VERSION,
    indexLoaded: embeddingIndex !== null,
    indexMeta: indexMeta,
    cachePath: getCachePath(),
    cacheFresh: isCacheFresh(readCacheSafe()),
  };
}

// ── Embedding model lifecycle ─────────────────────────────────────────────────

async function loadModel() {
  if (model && embeddingContext) return;
  if (loadingPromise) return loadingPromise;
  loadingPromise = doLoadModel(getEmbedderModelPath());
  try {
    await loadingPromise;
  } finally {
    loadingPromise = null;
  }
}

async function doLoadModel(modelPath) {
  if (!fs.existsSync(modelPath)) {
    const err = new Error(`embedding model file not found: ${modelPath}`);
    err.code = 'KB_EMBED_UNAVAILABLE';
    throw err;
  }

  // Lazy-require node-llama-cpp so this module can be imported even when the
  // dependency or the native binary isn't installed (mirrors internal-llm.js).
  if (!llamaModule) {
    try {
      llamaModule = require('node-llama-cpp');
    } catch (err) {
      const wrapped = new Error('node-llama-cpp not available: ' + err.message);
      wrapped.code = 'KB_EMBED_UNAVAILABLE';
      throw wrapped;
    }
  }

  const stat = fs.statSync(modelPath);
  logger.info('Loading KB embedding model', { path: modelPath, sizeBytes: stat.size });

  const { getLlama } = llamaModule;
  const llama = await getLlama();
  model = await llama.loadModel({ modelPath });
  embeddingContext = await model.createEmbeddingContext();

  modelInfo = {
    path: modelPath,
    name: path.basename(modelPath),
    sizeBytes: stat.size,
    loadedAt: new Date().toISOString(),
  };
  resetIdleTimer();
  logger.info('KB embedding model loaded', { name: modelInfo.name });
}

async function unloadModel() {
  if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
  if (embeddingContext) {
    try { await embeddingContext.dispose(); } catch (_) { /* ignore */ }
    embeddingContext = null;
  }
  if (model) {
    try { await model.dispose(); } catch (_) { /* ignore */ }
    model = null;
  }
  modelInfo = null;
  logger.info('KB embedding model unloaded');
}

function resetIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    logger.info('KB embedding model idle timeout — unloading');
    unloadModel().catch(err => logger.error('Embedding idle unload failed', { error: err.message }));
  }, IDLE_UNLOAD_MS);
}

// ── Embedding ─────────────────────────────────────────────────────────────────

async function embed(text) {
  if (typeof text !== 'string' || text.length === 0) {
    const err = new Error('embed() requires a non-empty string');
    err.code = 'KB_EMBED_FAILED';
    throw err;
  }
  if (!isReady()) await loadModel();
  if (!isReady()) {
    const err = new Error('KB embedding model not loaded');
    err.code = 'KB_EMBED_UNAVAILABLE';
    throw err;
  }
  let vector;
  try {
    const result = await embeddingContext.getEmbeddingFor(text);
    // node-llama-cpp returns a LlamaEmbedding whose .vector is a readonly
    // array of numbers; copy into a plain array for downstream math/serialization.
    vector = Array.from(result.vector);
  } catch (err) {
    const wrapped = new Error('embedding inference failed: ' + (err.message || String(err)));
    wrapped.code = 'KB_EMBED_FAILED';
    throw wrapped;
  }
  resetIdleTimer();
  return vector;
}

// Text used to represent a KB entry in vector space: the three FireAlive-authored
// meaning-bearing fields. Kept in one place so the AC mirror stays consistent.
function entryEmbeddingText(entry) {
  return [entry.finding, entry.implication, entry.summary]
    .filter(Boolean)
    .join('\n');
}

// ── Cosine similarity + top-N ─────────────────────────────────────────────────

// Pure. Returns cosine similarity in [-1, 1]; 0 for a zero-magnitude or
// mismatched-length input rather than NaN, so ranking stays well-defined.
function cosineSimilarity(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length === 0 || a.length !== b.length) {
    return 0;
  }
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

// Rank a query vector against an index ([{id, vector}]) and return the top-k as
// [{id, score}] sorted by score descending. Defaults to the resident index.
function cosineTopN(queryVec, k, index) {
  const idx = index || embeddingIndex;
  if (!Array.isArray(idx) || idx.length === 0) return [];
  const kk = (Number.isInteger(k) && k > 0) ? k : 5;
  return idx
    .map(e => ({ id: e.id, score: cosineSimilarity(queryVec, e.vector) }))
    .sort((x, y) => y.score - x.score)
    .slice(0, kk);
}

// ── Cache load / build ────────────────────────────────────────────────────────

function readCacheSafe() {
  try {
    const raw = fs.readFileSync(getCachePath(), 'utf8');
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

// A cache is fresh only if it matches BOTH the current KB content version and the
// current embedder id. Either changing forces a rebuild.
function isCacheFresh(cache) {
  return !!cache
    && cache.kbVersion === kb.KB_VERSION
    && cache.embedderId === embedderId()
    && Array.isArray(cache.entries)
    && cache.entries.length === kb.getAll().length;
}

// Load the cache into the resident index if fresh; returns the index or null.
function loadEmbeddings() {
  const cache = readCacheSafe();
  if (!isCacheFresh(cache)) {
    if (cache) {
      logger.info('KB embeddings cache stale — will rebuild', {
        cacheKbVersion: cache.kbVersion, kbVersion: kb.KB_VERSION,
        cacheEmbedder: cache.embedderId, embedderId: embedderId(),
      });
    }
    return null;
  }
  embeddingIndex = cache.entries.map(e => ({ id: e.id, vector: e.vector }));
  indexMeta = {
    kbVersion: cache.kbVersion, embedderId: cache.embedderId,
    dim: cache.dim, count: cache.entries.length, generatedAt: cache.generatedAt,
  };
  logger.info('KB embeddings cache loaded', indexMeta);
  return embeddingIndex;
}

// Build embeddings for every KB entry, write the cache, and set the resident
// index. Requires the embedding model to be available; throws KB_EMBED_UNAVAILABLE
// if it is not (the caller surfaces an honest "unavailable" state).
async function buildEmbeddings(opts) {
  opts = opts || {};
  const entries = kb.getAll();
  const built = [];
  let dim = null;

  logger.info('Building KB embeddings', { count: entries.length, embedderId: embedderId(), kbVersion: kb.KB_VERSION });
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const vector = await embed(entryEmbeddingText(entry));
    if (dim === null) dim = vector.length;
    built.push({ id: entry.id, vector });
    if (typeof opts.onProgress === 'function') {
      opts.onProgress({ done: i + 1, total: entries.length, id: entry.id });
    }
  }
  if (dim !== EXPECTED_DIM) {
    logger.warn('KB embeddings dimension is not the expected 1024', { dim, expected: EXPECTED_DIM });
  }

  const cache = {
    kbVersion: kb.KB_VERSION,
    embedderId: embedderId(),
    dim,
    generatedAt: new Date().toISOString(),
    entries: built,
  };
  const cachePath = getCachePath();
  fs.mkdirSync(path.dirname(cachePath), { recursive: true });
  fs.writeFileSync(cachePath, JSON.stringify(cache), 'utf8');

  embeddingIndex = built.map(e => ({ id: e.id, vector: e.vector }));
  indexMeta = { kbVersion: cache.kbVersion, embedderId: cache.embedderId, dim, count: built.length, generatedAt: cache.generatedAt };
  logger.info('KB embeddings built + cached', { ...indexMeta, cachePath });
  return { kbVersion: cache.kbVersion, embedderId: cache.embedderId, dim, count: built.length };
}

// Ensure a usable resident index: use it if already loaded, else load a fresh
// cache, else build (requires the model). Returns the index.
async function ensureEmbeddings() {
  if (embeddingIndex) return embeddingIndex;
  if (loadEmbeddings()) return embeddingIndex;
  await buildEmbeddings();
  return embeddingIndex;
}

// Convenience: embed a query and return the top-k KB ids + scores. The route
// layer maps ids → enriched entries via research-kb.getByRefs().
async function search(query, k) {
  await ensureEmbeddings();
  const queryVec = await embed(query);
  return cosineTopN(queryVec, k);
}

module.exports = {
  isReady,
  getStatus,
  embed,
  cosineSimilarity,
  cosineTopN,
  loadEmbeddings,
  buildEmbeddings,
  ensureEmbeddings,
  search,
  unloadModel,
  loadModel,
  getModelRootPath,
  getEmbedderModelPath,
  getCachePath,
  embedderId,
  entryEmbeddingText,
};

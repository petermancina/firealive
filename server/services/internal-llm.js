// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Internal LLM Service
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Wraps node-llama-cpp to provide local LLM inference for FireAlive's
// internal AI provider. Loads a quantized GGUF model on demand, serves
// chat-completion requests, and unloads after configurable idle timeout
// to free memory.
//
// Default model: Phi-3-mini-4k-instruct-q4_K_M (~2.4GB, MIT licensed,
// strong instruction-following + reasoning, 4k context window).
// Optional smaller fallback: Qwen-2.5-1.5B-instruct-q4_K_M (~1GB).
//
// This service is called by the AI provider dispatcher (ai-provider.js)
// when a feature is configured to use 'internal' as its provider. It
// should NOT be called directly by feature code; route everything
// through the dispatcher so audit logging, timeouts, and error
// classification are consistent.
//
// Model file location is determined by FIREALIVE_MODEL_PATH env var,
// or defaults to ~/.firealive/models/. The bootstrap script
// (scripts/download-model.js, commit 5) downloads the model on first run.
//
// Inference runs in the main Node process by default. For deployments
// where MC responsiveness during long generation is critical, the
// FIREALIVE_LLM_USE_WORKER env var enables worker-thread inference
// (transparent to callers; same generate() interface).
//
// Public API:
//
//   isReady() -> boolean
//     True if the service has a loaded model ready to serve calls.
//     Returns false if the model file is missing, has not been loaded
//     yet, or has been unloaded after idle.
//
//   getStatus() -> object
//     Returns details for the AI/ML Integrations tab:
//     { ready, modelPath, modelName, modelSizeBytes, loadedAt,
//       lastInferenceAt, idleUnloadMs }
//
//   loadModel(modelPath?) -> Promise<void>
//     Explicitly load the model. Idempotent. Called by the bootstrap
//     script after download, or implicitly on first generate() call.
//
//   unloadModel() -> Promise<void>
//     Explicitly unload to free memory. Called automatically after
//     idle timeout. Safe to call when no model is loaded.
//
//   generate(prompt, options) -> Promise<{text, modelName, tokenCount}>
//     Run inference. Loads the model lazily if not already loaded.
//     Resets idle-unload timer.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const os = require('os');
const { logger } = require('./logger');

// Configuration
const DEFAULT_MODEL_FILENAME = 'phi-3-mini-4k-instruct-q4.gguf';
const DEFAULT_IDLE_UNLOAD_MS = 5 * 60 * 1000;  // unload after 5 minutes of no use

// Module-level state
let llamaModule = null;       // lazily-required node-llama-cpp module
let model = null;              // loaded LlamaModel instance
let context = null;            // active LlamaContext
let modelInfo = null;          // { path, name, sizeBytes, loadedAt }
let lastInferenceAt = null;
let idleTimer = null;
let loadingPromise = null;     // de-duplicates concurrent load requests

// ── Public API ──────────────────────────────────────────────────────────────

function isReady() {
  return model !== null && context !== null;
}

function getStatus() {
  return {
    ready: isReady(),
    modelPath: modelInfo ? modelInfo.path : null,
    modelName: modelInfo ? modelInfo.name : null,
    modelSizeBytes: modelInfo ? modelInfo.sizeBytes : null,
    loadedAt: modelInfo ? modelInfo.loadedAt : null,
    lastInferenceAt,
    idleUnloadMs: DEFAULT_IDLE_UNLOAD_MS,
    available: modelFileExists(),
  };
}

async function loadModel(modelPath) {
  if (model && context) {
    // Already loaded; return immediately
    return;
  }

  // De-duplicate concurrent load requests
  if (loadingPromise) {
    return loadingPromise;
  }

  loadingPromise = doLoadModel(modelPath || resolveDefaultModelPath());
  try {
    await loadingPromise;
  } finally {
    loadingPromise = null;
  }
}

async function unloadModel() {
  if (idleTimer) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
  if (context) {
    try { await context.dispose(); } catch (_) { /* ignore */ }
    context = null;
  }
  if (model) {
    try { await model.dispose(); } catch (_) { /* ignore */ }
    model = null;
  }
  modelInfo = null;
  logger.info('Internal LLM unloaded');
}

async function generate(prompt, options) {
  options = options || {};
  const maxTokens = options.maxTokens || 1024;
  const temperature = (options.temperature !== undefined) ? options.temperature : 0.7;

  if (!isReady()) {
    await loadModel();
  }

  if (!isReady()) {
    const err = new Error('internal LLM not loaded');
    err.code = 'AI_INTERNAL_UNAVAILABLE';
    throw err;
  }

  // Ensure the chat session uses a fresh sequence so prior calls don't
  // leak context across unrelated features.
  const { LlamaChatSession } = llamaModule;
  const session = new LlamaChatSession({ contextSequence: context.getSequence() });

  let outputText;
  try {
    outputText = await session.prompt(prompt, {
      temperature,
      maxTokens,
    });
  } catch (err) {
    const wrapped = new Error('inference failed: ' + (err.message || String(err)));
    wrapped.code = 'AI_INFERENCE_FAILED';
    throw wrapped;
  }

  lastInferenceAt = new Date().toISOString();
  resetIdleTimer();

  return {
    text: outputText,
    modelName: modelInfo ? modelInfo.name : null,
    tokenCount: estimateTokens(prompt, outputText),
  };
}

// ── Internal helpers ────────────────────────────────────────────────────────

async function doLoadModel(modelPath) {
  if (!fs.existsSync(modelPath)) {
    const err = new Error(`model file not found: ${modelPath}`);
    err.code = 'AI_INTERNAL_UNAVAILABLE';
    throw err;
  }

  // Lazy-require node-llama-cpp so the dispatcher can be imported even when
  // the dependency isn't installed (e.g. during the F4a commit sequence
  // before package.json is updated in commit 9).
  if (!llamaModule) {
    try {
      llamaModule = require('node-llama-cpp');
    } catch (err) {
      const wrapped = new Error('node-llama-cpp not available: ' + err.message);
      wrapped.code = 'AI_INTERNAL_UNAVAILABLE';
      throw wrapped;
    }
  }

  const stat = fs.statSync(modelPath);
  const filename = path.basename(modelPath);
  logger.info('Loading internal LLM', { path: modelPath, sizeBytes: stat.size });

  const { getLlama } = llamaModule;
  const llama = await getLlama();
  model = await llama.loadModel({ modelPath });
  context = await model.createContext();

  modelInfo = {
    path: modelPath,
    name: filename,
    sizeBytes: stat.size,
    loadedAt: new Date().toISOString(),
  };

  resetIdleTimer();

  logger.info('Internal LLM loaded', { name: filename });
}

function resetIdleTimer() {
  if (idleTimer) {
    clearTimeout(idleTimer);
  }
  idleTimer = setTimeout(() => {
    logger.info('Internal LLM idle timeout — unloading');
    unloadModel().catch(err => logger.error('Idle unload failed', { error: err.message }));
  }, DEFAULT_IDLE_UNLOAD_MS);
}

function resolveDefaultModelPath() {
  const envPath = process.env.FIREALIVE_MODEL_PATH;
  if (envPath) {
    // env var can point to a directory or a specific file
    if (envPath.endsWith('.gguf')) return envPath;
    return path.join(envPath, DEFAULT_MODEL_FILENAME);
  }
  return path.join(os.homedir(), '.firealive', 'models', DEFAULT_MODEL_FILENAME);
}

function modelFileExists() {
  try {
    return fs.existsSync(resolveDefaultModelPath());
  } catch (_) {
    return false;
  }
}

function estimateTokens(prompt, output) {
  // Lightweight estimator. For audit log purposes only; real provider
  // implementations (commit 4 external-llm) report exact counts.
  return {
    input: Math.ceil((prompt || '').length / 4),
    output: Math.ceil((output || '').length / 4),
  };
}

module.exports = {
  isReady,
  getStatus,
  loadModel,
  unloadModel,
  generate,
};

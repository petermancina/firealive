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
// Default model: Phi-4 Q4_K (MIT), provisioned as a single official GGUF
// (~9.05 GB) and loaded directly. This is
// the MC's heavyweight internal model: it serves the lead KB chat AND the
// other server-side generative features (burnout messages, IR simulator,
// troubleshooter). Endpoint floor: ~9.05 GB free disk + ~10-12GB RAM.
//
// This service is called by the AI provider dispatcher (ai-provider.js)
// when a feature is configured to use 'internal' as its provider. It
// should NOT be called directly by feature code; route everything
// through the dispatcher so audit logging, timeouts, and error
// classification are consistent.
//
// Model file location is determined by FIREALIVE_MODEL_PATH env var, or
// defaults to ~/.firealive/models/. FireAlive never downloads models: the
// operator provisions the official files and scripts/download-model.js
// verifies them. doLoadModel refuses to load unless the pinned 'chat' model
// passes SHA-256 verification (verify-only).
//
// Idle-unload behavior is configurable via FIREALIVE_LLM_IDLE_UNLOAD_MS.
// Set to a positive integer (milliseconds) to override the default of
// 5 minutes. Invalid values fall back to the default with a warning log.
//
// ── Path-injection defense ──────────────────────────────────────────────────
// Any caller-supplied model path (e.g. from POST /api/ai-provider/model/load
// req.body.modelPath) is validated against the approved model root directory
// (~/.firealive/models or FIREALIVE_MODEL_PATH) by resolveAndValidateModelPath()
// before it ever reaches a filesystem call. Validation is two-pass: lexical
// containment (path.relative + isAbsolute checks against the root) followed
// by symlink-resolved containment (fs.realpath both sides, re-validate).
// Server-computed defaults from resolveDefaultModelPath() are trusted because
// they're built from env vars and homedir, not request input. Do NOT call
// doLoadModel() directly with unvalidated user input — always go through
// loadModel().
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
//     If modelPath is supplied, it is validated against the approved
//     model directory before loading.
//
//   unloadModel() -> Promise<void>
//     Explicitly unload to free memory. Called automatically after
//     idle timeout. Safe to call when no model is loaded.
//
//   generate(prompt, options) -> Promise<{text, modelName, tokenCount}>
//     Run inference. Loads the model lazily if not already loaded.
//     Resets idle-unload timer.
//
//   getModelRootPath() -> string
//     Returns the absolute path of the approved model root directory.
//     Used by the manifest endpoint and the path validator.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const os = require('os');
const { logger } = require('./logger');

// Configuration
const DEFAULT_MODEL_FILENAME = 'phi-4-Q4_K.gguf';

// Idle-unload timeout. Read once at module load from the
// FIREALIVE_LLM_IDLE_UNLOAD_MS env var (positive integer milliseconds);
// invalid or missing falls back to 5 minutes. The header documents this.
function resolveIdleUnloadMs() {
  const raw = process.env.FIREALIVE_LLM_IDLE_UNLOAD_MS;
  if (raw === undefined || raw === '') return 5 * 60 * 1000;
  const parsed = parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    logger.warn('FIREALIVE_LLM_IDLE_UNLOAD_MS is not a positive integer; using default', { value: raw });
    return 5 * 60 * 1000;
  }
  return parsed;
}
const IDLE_UNLOAD_MS = resolveIdleUnloadMs();

// Module-level state
let modelInfo = null;          // { path, name, sizeBytes, loadedAt }
let lastInferenceAt = null;
let idleTimer = null;
let loadingPromise = null;     // de-duplicates concurrent load requests
let provisioning = null;       // lazily-required verify-only provisioning tool
let chatVerifySig = null;      // signature of the last SHA-verified chat model file set
const modelSafety = require('./model-file-safety'); // layered model-file integrity & safety gate
const { getSharedHost } = require('./model-worker-host'); // isolated child-process loader
const workerHost = getSharedHost({ logger }); // chat (+ embed) run in a separate process

// ── Public API ──────────────────────────────────────────────────────────────

function isReady() {
  return modelInfo !== null && workerHost.isLoaded('chat');
}

function getStatus() {
  return {
    ready: isReady(),
    modelPath: modelInfo ? modelInfo.path : null,
    modelName: modelInfo ? modelInfo.name : null,
    modelSizeBytes: modelInfo ? modelInfo.sizeBytes : null,
    loadedAt: modelInfo ? modelInfo.loadedAt : null,
    lastInferenceAt,
    idleUnloadMs: IDLE_UNLOAD_MS,
    available: modelFileExists(),
    isolated: true,
  };
}

async function loadModel(modelPath) {
  if (isReady()) {
    // Already loaded; return immediately
    return;
  }

  // De-duplicate concurrent load requests
  if (loadingPromise) {
    return loadingPromise;
  }

  // Caller-supplied paths are validated against the approved model root
  // directory before being passed to filesystem operations. Server-computed
  // defaults (resolveDefaultModelPath) are trusted because they originate
  // from env vars and homedir, not request input. This is the single
  // chokepoint for path validation — do not bypass.
  const resolvedPath = modelPath
    ? await resolveAndValidateModelPath(modelPath)
    : resolveDefaultModelPath();

  loadingPromise = doLoadModel(resolvedPath);
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
  // Unload the chat model from the shared worker (frees the heavyweight model;
  // the worker process persists for embeddings, which kb-embeddings owns).
  try { await workerHost.unload('chat'); } catch (_) { /* ignore */ }
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

  // Inference runs in the isolated worker process; the host carries the
  // AI_INFERENCE_FAILED / AI_INTERNAL_UNAVAILABLE contract back on failure.
  const result = await workerHost.generate(prompt, { maxTokens, temperature });
  const outputText = result.text;

  lastInferenceAt = new Date().toISOString();
  resetIdleTimer();

  return {
    text: outputText,
    modelName: (modelInfo ? modelInfo.name : null) || result.modelName || null,
    tokenCount: estimateTokens(prompt, outputText),
  };
}

// ── Internal helpers ────────────────────────────────────────────────────────

// Signature of the chat model file set (filename:size:mtime per file). Lets us
// skip re-hashing a byte-stable, already-verified model on idle-reload while
// still detecting any on-disk file swap (size/mtime change forces re-verify).
function chatFilesSignature() {
  try {
    if (!provisioning || typeof provisioning.modelFiles !== 'function') return null;
    return provisioning.modelFiles('chat').map(f => {
      try { const st = fs.statSync(f.path); return f.filename + ':' + st.size + ':' + st.mtimeMs; }
      catch (_) { return f.filename + ':missing'; }
    }).join('|');
  } catch (_) { return null; }
}

// ── Loader privilege hardening (parent-side, pre-handoff) ────────────────────
// The GGUF is parsed and inference runs in a SEPARATE worker process
// (model-worker-host) — that isolation is the containment control, and the
// integrity & safety gate (verifyModelFileSafety, above) is the primary control.
// This function is the parent-side privilege check run BEFORE the path is handed
// to the worker: it refuses to load a native model as root in production (a
// parser RCE as root = full host compromise, and a worker forked from a root
// parent inherits root). The worker re-checks the same condition. Escape hatch
// for constrained environments that genuinely require it:
// FIREALIVE_ALLOW_ROOT_MODEL_LOAD=1.
//
// Deployment confinement — non-root user, read-only model mount, dropped Linux
// capabilities, seccomp/AppArmor, resource limits, no network egress — and the
// remaining sidecar / in-process-privilege-drop options are documented in
// docs/model-loader-isolation.md.
function applyLoadHardening(modelPath) {
  // POSIX privilege check (no-op where geteuid is unavailable, e.g. Windows).
  if (typeof process.geteuid === 'function' && process.geteuid() === 0) {
    const allowRoot = process.env.FIREALIVE_ALLOW_ROOT_MODEL_LOAD === '1';
    const production = process.env.NODE_ENV === 'production';
    if (production && !allowRoot) {
      const err = new Error(
        'refusing to load the internal model as root in production: a worker forked here would ' +
        'inherit root, so a GGUF-parser exploit would execute as root. Run the service as a non-root ' +
        'user, or set FIREALIVE_ALLOW_ROOT_MODEL_LOAD=1 to override.');
      err.code = 'AI_INTERNAL_UNAVAILABLE';
      err.modelSafety = { outcome: 'blocked_hardening', reason: 'root euid in production' };
      throw err;
    }
    logger.warn('Loading the internal model as root; run the service as a non-root user for blast-radius containment',
      { modelPath, production, allowRootOverride: allowRoot });
  }
}

async function doLoadModel(modelPath) {
  // PRECONDITION: `modelPath` has either been (a) validated by
  // resolveAndValidateModelPath() against getModelRootPath() when the
  // caller supplied a path, or (b) computed by resolveDefaultModelPath()
  // from FIREALIVE_MODEL_PATH / os.homedir(). Both sources are trusted
  // here. Direct calls to doLoadModel() with raw user input would bypass
  // this guarantee — always go through loadModel().

  // ── Verify-before-load (verify-only; NO network) ──────────────────────────
  // Refuse to load unless the pinned 'chat' model (Phi-4 Q4_K) passes
  // SHA-256 verification against the source-pinned hash.
  if (provisioning === null) {
    try { provisioning = require('../../scripts/download-model'); }
    catch (_) { provisioning = false; }
  }
  if (provisioning && typeof provisioning.verifyModel === 'function') {
    const sig = chatFilesSignature();
    if (sig !== chatVerifySig) {
      // Model-file integrity & safety gate (fail-closed) before the in-process
      // loader reads the file: hash-pin (layer 1, = verifyModel) → optional
      // signature → GGUF format validation → local malware scan. verifyModel
      // runs inside the gate, so the SHA-256 is computed once; reuse the
      // already-required provisioning tool for layer 1.
      const gate = await modelSafety.verifyModelFileSafety('chat', {
        actor: 'internal-llm',
        deps: { verifyModel: (id) => provisioning.verifyModel(id) },
      });
      if (!gate.ok) {
        chatVerifySig = null;
        const err = new Error(
          'internal chat model failed the integrity & safety gate (' + gate.overall + '): ' +
          (gate.blockedReason || 'unknown reason') + '; refusing to load. ' +
          'Provision the official Phi-4 Q4_K model and ensure a local malware ' +
          'scanner (clamdscan/clamscan or Microsoft Defender) is available, then verify: ' +
          'node scripts/download-model.js --model chat');
        err.code = 'AI_INTERNAL_UNAVAILABLE';
        err.modelSafety = { outcome: gate.overall, reason: gate.blockedReason };
        throw err;
      }
      chatVerifySig = sig;
    }
  }

  if (!fs.existsSync(modelPath)) {
    const err = new Error(`model file not found: ${modelPath}`);
    err.code = 'AI_INTERNAL_UNAVAILABLE';
    throw err;
  }

  const stat = fs.statSync(modelPath);
  const filename = path.basename(modelPath);
  logger.info('Loading internal LLM', { path: modelPath, sizeBytes: stat.size });

  // Parent-side privilege gate before we hand the path to the worker (the
  // worker re-checks too). Refuses to load as root in production.
  applyLoadHardening(modelPath);

  // Load in the isolated worker process. The gate above has already validated
  // the file; the worker re-stats it (size) on open as a TOCTOU guard.
  try {
    await workerHost.load('chat', modelPath, stat.size);
  } catch (err) {
    if (!err.code) err.code = 'AI_INTERNAL_UNAVAILABLE';
    throw err;
  }

  modelInfo = {
    path: modelPath,
    name: filename,
    sizeBytes: stat.size,
    loadedAt: new Date().toISOString(),
  };

  resetIdleTimer();

  logger.info('Internal LLM loaded (isolated worker)', { name: filename });
}

function resetIdleTimer() {
  if (idleTimer) {
    clearTimeout(idleTimer);
  }
  idleTimer = setTimeout(() => {
    logger.info('Internal LLM idle timeout — unloading');
    unloadModel().catch(err => logger.error('Idle unload failed', { error: err.message }));
  }, IDLE_UNLOAD_MS);
}

// ── Path resolution + validation ────────────────────────────────────────────
//
// getModelRootPath() returns the canonical directory that all loadable
// model files must live inside. Computed from server-controlled inputs
// only (FIREALIVE_MODEL_PATH env var, otherwise os.homedir()). Never
// derived from request input.
//
// resolveAndValidateModelPath(inputPath) is the path-injection barrier
// for caller-supplied paths. It:
//   1. Rejects non-string / empty / NUL-byte input
//   2. Resolves the input against the model root
//   3. Confirms the resolved path is a lexical descendant of the model
//      root (uses path.relative + startsWith('..') / isAbsolute checks —
//      the standard CodeQL-recognized barrier pattern for js/path-injection)
//   4. Confirms the resolved path ends in `.gguf` (defense-in-depth: even
//      a path inside the root must point to an actual model file)
//   5. Resolves symlinks via fs.realpath on both root and target, and
//      re-validates containment against the canonicalized root. This
//      defends against an attacker with filesystem write access to the
//      model directory planting a symlink that points outside it.
//
// The validator is async because step 5 stat's the filesystem.
// On success returns the absolute, symlink-resolved path. On failure
// throws an Error with code = 'AI_INTERNAL_INVALID_MODEL_PATH'.

function getModelRootPath() {
  const envPath = process.env.FIREALIVE_MODEL_PATH;
  if (envPath) {
    // env var may point to a specific file or a directory
    if (envPath.endsWith('.gguf')) {
      return path.resolve(path.dirname(envPath));
    }
    return path.resolve(envPath);
  }
  return path.resolve(os.homedir(), '.firealive', 'models');
}

async function resolveAndValidateModelPath(inputPath) {
  if (typeof inputPath !== 'string' || inputPath.length === 0) {
    const err = new Error('model path must be a non-empty string');
    err.code = 'AI_INTERNAL_INVALID_MODEL_PATH';
    throw err;
  }

  // NUL-byte rejection — defends against C-string truncation attacks
  // where an attacker appends "\0" + "garbage" to bypass extension checks.
  if (inputPath.indexOf('\0') !== -1) {
    const err = new Error('model path contains invalid characters');
    err.code = 'AI_INTERNAL_INVALID_MODEL_PATH';
    throw err;
  }

  const rootDir = getModelRootPath();
  const resolved = path.resolve(rootDir, inputPath);

  // First-pass: lexical containment. `path.relative(root, resolved)` returns:
  //   - '' if resolved === root (we reject — must be a file, not the dir)
  //   - a '..'-prefixed string if resolved escapes upward
  //   - an absolute path on a different drive/volume (Windows)
  //   - a clean child path (e.g. 'phi-4-Q4_K.gguf') otherwise
  // Only the last case is acceptable.
  const relative = path.relative(rootDir, resolved);
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    const err = new Error('model path escapes the approved model directory');
    err.code = 'AI_INTERNAL_INVALID_MODEL_PATH';
    throw err;
  }

  // Only .gguf model files are accepted.
  if (!resolved.toLowerCase().endsWith('.gguf')) {
    const err = new Error('model path must reference a .gguf file');
    err.code = 'AI_INTERNAL_INVALID_MODEL_PATH';
    throw err;
  }

  // Second-pass: symlink resolution. Lexical containment is necessary but
  // not sufficient — an attacker with filesystem write access to the model
  // root could plant a symlink (e.g. ~/.firealive/models/foo.gguf -> /etc/passwd)
  // that passes the lexical check but resolves outside the root. We canonicalize
  // both sides via fs.realpath and re-compare.
  //
  // If the file does not yet exist (e.g. caller is asking us to load a path
  // that hasn't been downloaded), fs.realpath throws ENOENT — that's expected;
  // the lexical check has already enforced containment, and the downstream
  // fs.existsSync in doLoadModel() will produce a clean "model file not found"
  // error. We only fail the validation here if realpath returns a real path
  // that escapes the root.
  let realRoot;
  try {
    realRoot = await fs.promises.realpath(rootDir);
  } catch (_) {
    // Root directory itself doesn't exist (fresh install). Use the lexical
    // root as the comparison anchor — input cannot escape it because we just
    // validated lexical containment above.
    realRoot = rootDir;
  }

  let realPath;
  try {
    realPath = await fs.promises.realpath(resolved);
  } catch (err) {
    if (err.code === 'ENOENT') {
      // File doesn't exist; lexical containment already passed. Allow through;
      // doLoadModel's existsSync will produce the user-facing error.
      return resolved;
    }
    const wrapped = new Error('model path validation failed: ' + err.message);
    wrapped.code = 'AI_INTERNAL_INVALID_MODEL_PATH';
    throw wrapped;
  }

  const realRelative = path.relative(realRoot, realPath);
  if (realRelative === '' || realRelative.startsWith('..') || path.isAbsolute(realRelative)) {
    const err = new Error('model path resolves outside the approved model directory (symlink)');
    err.code = 'AI_INTERNAL_INVALID_MODEL_PATH';
    throw err;
  }

  return realPath;
}

function resolveDefaultModelPath() {
  const envPath = process.env.FIREALIVE_MODEL_PATH;
  if (envPath && envPath.endsWith('.gguf')) {
    // env var points directly at a specific model file
    return envPath;
  }
  return path.join(getModelRootPath(), DEFAULT_MODEL_FILENAME);
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
  getModelRootPath,
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Model Worker (isolated child-process loader + inference)
//
// node-llama-cpp parses the GGUF and runs inference in this process. To contain a
// loader/parser exploit, the host (internal-llm.js / kb-embeddings.js) runs this
// file as a SEPARATE child process (child_process.fork) and talks to it over the
// built-in IPC channel. The B1 integrity & safety gate has ALREADY validated the
// file in the trusted parent before any path is handed here — this worker holds
// the least privilege it can: it never touches the database and reads only the
// model path it is given.
//
// Protocol (parent → worker):
//   { t:'load', kind:'chat'|'embed', modelPath, expectedSizeBytes? }
//   { t:'generate', id, prompt, options:{maxTokens,temperature} }
//   { t:'embed', id, text }
//   { t:'unload', kind }
//   { t:'status' }
// Protocol (worker → parent):
//   { t:'ready' } { t:'loaded', kind, modelName, sizeBytes }
//   { t:'result', id, text, modelName } { t:'embedding', id, vector, modelName }
//   { t:'unloaded', kind } { t:'status', chatLoaded, embedLoaded, info }
//   { t:'error', id?, code, message } { t:'log', level, msg, meta }
//
// createHandler/checkWorkerPrivileges are exported so the protocol can be unit
// tested with a stubbed llama module (no native binary required).
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

// In-worker privilege hardening — mirrors internal-llm.js applyLoadHardening.
// The worker is forked by an already-non-root parent in production; this is
// defence-in-depth in case it is ever launched directly or as root.
function checkWorkerPrivileges(env) {
  env = env || {};
  if (typeof process.geteuid === 'function' && process.geteuid() === 0) {
    const allowRoot = env.FIREALIVE_ALLOW_ROOT_MODEL_LOAD === '1';
    const production = env.NODE_ENV === 'production';
    if (production && !allowRoot) {
      return { ok: false, reason: 'model worker refusing to run as root in production (set FIREALIVE_ALLOW_ROOT_MODEL_LOAD=1 to override)' };
    }
  }
  return { ok: true };
}

// Factory so tests can inject a fake llama module + capture sent messages.
//   deps.loadLlama() -> the node-llama-cpp module (lazy)
//   deps.send(msg)   -> deliver a message to the parent
function createHandler(deps) {
  const loadLlama = deps.loadLlama;
  const send = deps.send;
  const log = (level, msg, meta) => { try { send({ t: 'log', level, msg, meta: meta || null }); } catch (_e) { /* ignore */ } };

  let llamaModule = null; // cached node-llama-cpp module
  let llama = null;       // cached getLlama() instance
  const state = {
    chat: { model: null, context: null, info: null },
    embed: { model: null, context: null, info: null },
  };

  async function ensureLlama() {
    if (!llamaModule) llamaModule = await loadLlama();
    if (!llama) {
      const { getLlama } = llamaModule;
      llama = await getLlama();
    }
    return llamaModule;
  }

  async function disposeKind(kind) {
    const s = state[kind];
    if (!s) return;
    try { if (s.context && typeof s.context.dispose === 'function') await s.context.dispose(); } catch (_e) { /* ignore */ }
    try { if (s.model && typeof s.model.dispose === 'function') await s.model.dispose(); } catch (_e) { /* ignore */ }
    s.model = null; s.context = null; s.info = null;
  }

  async function loadKind(kind, modelPath, expectedSizeBytes) {
    if (kind !== 'chat' && kind !== 'embed') {
      const e = new Error('unknown model kind: ' + kind); e.code = 'AI_INTERNAL_UNAVAILABLE'; throw e;
    }
    // Cheap TOCTOU guard: the parent gated the file; re-stat on open and refuse
    // on an unexpected size (a read-only model mount is the stronger control).
    let stat;
    try { stat = fs.statSync(modelPath); }
    catch (_e) { const e = new Error('model file not found at load: ' + modelPath); e.code = 'AI_INTERNAL_UNAVAILABLE'; throw e; }
    if (expectedSizeBytes != null && Number(expectedSizeBytes) !== stat.size) {
      const e = new Error('model file size changed between gate and load (expected ' + expectedSizeBytes + ', got ' + stat.size + ')');
      e.code = 'AI_INTERNAL_UNAVAILABLE'; throw e;
    }
    await ensureLlama();
    await disposeKind(kind); // replace any prior instance
    const model = await llama.loadModel({ modelPath });
    const context = (kind === 'chat')
      ? await model.createContext()
      : await model.createEmbeddingContext();
    state[kind].model = model;
    state[kind].context = context;
    state[kind].info = { name: path.basename(modelPath), sizeBytes: stat.size };
    return state[kind].info;
  }

  async function handle(msg) {
    if (!msg || typeof msg.t !== 'string') return;
    try {
      switch (msg.t) {
        case 'load': {
          const info = await loadKind(msg.kind, msg.modelPath, msg.expectedSizeBytes);
          send({ t: 'loaded', kind: msg.kind, modelName: info.name, sizeBytes: info.sizeBytes });
          break;
        }
        case 'generate': {
          const s = state.chat;
          if (!s.context) { send({ t: 'error', id: msg.id, code: 'AI_INTERNAL_UNAVAILABLE', message: 'chat model not loaded' }); break; }
          const options = msg.options || {};
          const maxTokens = options.maxTokens || 1024;
          const temperature = (options.temperature !== undefined) ? options.temperature : 0.7;
          const { LlamaChatSession } = llamaModule;
          const session = new LlamaChatSession({ contextSequence: s.context.getSequence() });
          let text;
          try { text = await session.prompt(msg.prompt, { temperature, maxTokens }); }
          catch (err) { send({ t: 'error', id: msg.id, code: 'AI_INFERENCE_FAILED', message: 'inference failed: ' + (err.message || String(err)) }); break; }
          send({ t: 'result', id: msg.id, text, modelName: s.info ? s.info.name : null });
          break;
        }
        case 'embed': {
          const s = state.embed;
          if (!s.context) { send({ t: 'error', id: msg.id, code: 'AI_INTERNAL_UNAVAILABLE', message: 'embedding model not loaded' }); break; }
          if (typeof msg.text !== 'string' || msg.text.length === 0) { send({ t: 'error', id: msg.id, code: 'AI_INFERENCE_FAILED', message: 'embed requires a non-empty string' }); break; }
          let vector;
          try { const r = await s.context.getEmbeddingFor(msg.text); vector = Array.from(r.vector); }
          catch (err) { send({ t: 'error', id: msg.id, code: 'AI_INFERENCE_FAILED', message: 'embedding inference failed: ' + (err.message || String(err)) }); break; }
          send({ t: 'embedding', id: msg.id, vector, modelName: s.info ? s.info.name : null });
          break;
        }
        case 'unload': {
          if (msg.kind === 'chat' || msg.kind === 'embed') await disposeKind(msg.kind);
          else { await disposeKind('chat'); await disposeKind('embed'); }
          send({ t: 'unloaded', kind: msg.kind || 'all' });
          break;
        }
        case 'status': {
          send({
            t: 'status',
            chatLoaded: !!state.chat.context,
            embedLoaded: !!state.embed.context,
            info: { chat: state.chat.info, embed: state.embed.info },
          });
          break;
        }
        default:
          send({ t: 'error', id: msg.id, code: 'AI_INTERNAL_UNAVAILABLE', message: 'unknown message type: ' + msg.t });
      }
    } catch (err) {
      send({ t: 'error', id: msg.id, code: err.code || 'AI_INTERNAL_UNAVAILABLE', message: err.message || String(err) });
    }
  }

  return { handle, _state: state };
}

// ── Fork-time entrypoint ─────────────────────────────────────────────────────
// Active only when run as a forked child (not when required by a test).
if (require.main === module) {
  const verdict = checkWorkerPrivileges(process.env);
  const sendToParent = (m) => { try { if (process.send) process.send(m); } catch (_e) { /* ignore */ } };
  if (!verdict.ok) {
    sendToParent({ t: 'error', code: 'AI_INTERNAL_UNAVAILABLE', message: verdict.reason });
    process.exit(1);
  }
  try { process.title = 'firealive-model-worker'; } catch (_e) { /* ignore */ }
  const handler = createHandler({
    loadLlama: () => import('node-llama-cpp'),
    send: sendToParent,
  });
  process.on('message', (msg) => { handler.handle(msg); });
  sendToParent({ t: 'ready' });
}

module.exports = { createHandler, checkWorkerPrivileges };

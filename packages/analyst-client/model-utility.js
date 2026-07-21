// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Analyst Client Model Utility (isolated on-device loader + inference)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// node-llama-cpp parses the GGUF and runs inference in-process. To contain a
// loader/parser exploit on the analyst's machine, the Analyst Client runs this
// file in an Electron utilityProcess (a sandboxed Node child of the main process)
// and talks to it over the parentPort MessagePort. The on-device integrity &
// safety gate (runSafetyGate in local-llm.js) has ALREADY validated the file in
// the main process before any path is handed here; nothing leaves the device.
//
// Protocol (main → utility):
//   { t:'load', kind:'chat'|'embed', modelPath, expectedSizeBytes? }
//   { t:'generate', id, prompt, options:{maxTokens,temperature} }
//   { t:'embed', id, text }
//   { t:'unload', kind } { t:'status' }
// Protocol (utility → main):
//   { t:'ready' } { t:'loaded', kind, modelName, sizeBytes }
//   { t:'result', id, text, modelName } { t:'embedding', id, vector, modelName }
//   { t:'unloaded', kind } { t:'status', chatLoaded, embedLoaded, info }
//   { t:'error', id?, code, message } { t:'log', level, msg, meta }
//
// createHandler is exported so the protocol can be unit tested with a stubbed
// llama module (no native binary required). Mirrors server/services/model-worker.js;
// AC-appropriate generation defaults; no refuse-as-root (this is a desktop app).
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

// deps.loadLlama() -> node-llama-cpp module (lazy); deps.send(msg) -> to main.
function createHandler(deps) {
  const loadLlama = deps.loadLlama;
  const send = deps.send;

  let llamaModule = null;
  let llama = null;
  const state = {
    chat: { model: null, context: null, info: null },
    embed: { model: null, context: null, info: null },
  };

  async function ensureLlama() {
    if (!llamaModule) llamaModule = await loadLlama();
    if (!llama) { const { getLlama } = llamaModule; llama = await getLlama(); }
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
    if (kind !== 'chat' && kind !== 'embed') { const e = new Error('unknown model kind: ' + kind); e.code = 'AC_LOCAL_UNAVAILABLE'; throw e; }
    let stat;
    try { stat = fs.statSync(modelPath); }
    catch (_e) { const e = new Error('model file not found at load: ' + modelPath); e.code = 'AC_LOCAL_UNAVAILABLE'; throw e; }
    if (expectedSizeBytes != null && Number(expectedSizeBytes) !== stat.size) {
      const e = new Error('model file size changed between gate and load (expected ' + expectedSizeBytes + ', got ' + stat.size + ')');
      e.code = 'AC_LOCAL_UNAVAILABLE'; throw e;
    }
    await ensureLlama();
    await disposeKind(kind);
    const model = await llama.loadModel({ modelPath });
    const context = (kind === 'chat') ? await model.createContext() : await model.createEmbeddingContext();
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
          if (!s.context) { send({ t: 'error', id: msg.id, code: 'AC_LOCAL_UNAVAILABLE', message: 'chat model not loaded' }); break; }
          const options = msg.options || {};
          const maxTokens = options.maxTokens || 700;
          const temperature = (options.temperature !== undefined) ? options.temperature : 0.3;
          const { LlamaChatSession } = llamaModule;
          const session = new LlamaChatSession({ contextSequence: s.context.getSequence() });
          let text;
          try { text = await session.prompt(msg.prompt, { temperature, maxTokens }); }
          catch (err) { send({ t: 'error', id: msg.id, code: 'AC_LOCAL_FAILED', message: 'local inference failed: ' + (err.message || String(err)) }); break; }
          send({ t: 'result', id: msg.id, text, modelName: s.info ? s.info.name : null });
          break;
        }
        case 'embed': {
          const s = state.embed;
          if (!s.context) { send({ t: 'error', id: msg.id, code: 'AC_LOCAL_UNAVAILABLE', message: 'embedding model not loaded' }); break; }
          if (typeof msg.text !== 'string' || msg.text.length === 0) { send({ t: 'error', id: msg.id, code: 'AC_LOCAL_FAILED', message: 'embed requires a non-empty string' }); break; }
          let vector;
          try { const r = await s.context.getEmbeddingFor(msg.text); vector = Array.from(r.vector); }
          catch (err) { send({ t: 'error', id: msg.id, code: 'AC_LOCAL_FAILED', message: 'embedding inference failed: ' + (err.message || String(err)) }); break; }
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
          send({ t: 'status', chatLoaded: !!state.chat.context, embedLoaded: !!state.embed.context, info: { chat: state.chat.info, embed: state.embed.info } });
          break;
        }
        default:
          send({ t: 'error', id: msg.id, code: 'AC_LOCAL_UNAVAILABLE', message: 'unknown message type: ' + msg.t });
      }
    } catch (err) {
      send({ t: 'error', id: msg.id, code: err.code || 'AC_LOCAL_UNAVAILABLE', message: err.message || String(err) });
    }
  }

  return { handle, _state: state };
}

// ── utilityProcess entrypoint ─────────────────────────────────────────────────
// Active only when run as an Electron utilityProcess (process.parentPort is set);
// not when this file is required by a test.
if (process.parentPort) {
  const post = (m) => { try { process.parentPort.postMessage(m); } catch (_e) { /* ignore */ } };
  const handler = createHandler({ loadLlama: () => import('node-llama-cpp'), send: post });
  process.parentPort.on('message', (e) => { handler.handle(e && e.data); });
  post({ t: 'ready' });
}

module.exports = { createHandler };

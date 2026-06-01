// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Model Worker Host (parent-side manager for the isolated loader)
//
// Owns the forked model-worker child process and exposes a small async API to the
// trusted parent (internal-llm.js for chat, kb-embeddings.js for embeddings). The
// B1 gate runs in the parent BEFORE load() hands a validated path here; this host
// only manages the process + the request channel.
//
// Guarantees:
//   • single-flight — one request in flight at a time (matches the current single-
//     context behaviour); requests queue FIFO.
//   • per-request timeout — on timeout the worker is killed and the request fails
//     with AI_INFERENCE_FAILED; the next request respawns a fresh worker.
//   • crash containment — a worker exit rejects the in-flight request and clears
//     loaded state; the next request respawns.
//   • restart circuit — more than maxRestarts spawns within restartWindowMs opens
//     a cooldown during which requests fail closed (AI_INTERNAL_UNAVAILABLE),
//     instead of thrashing.
//
// API: load(kind, modelPath, expectedSizeBytes?) · generate(prompt, options) ·
//      embed(text) · unload(kind?) · status() · isLoaded(kind?) · shutdown()
//
// `fork` is injectable for testing (drive the real worker handler with a stub
// llama, no native binary or real child process required).
// ═══════════════════════════════════════════════════════════════════════════════

const { fork: realFork } = require('child_process');
const path = require('path');

function createWorkerHost(opts) {
  opts = opts || {};
  const workerPath = opts.workerPath || path.join(__dirname, 'model-worker.js');
  const fork = opts.fork || realFork;
  const log = opts.logger || { info() {}, warn() {}, error() {} };
  const timeoutMs = opts.timeoutMs || Number(process.env.FIREALIVE_MODEL_WORKER_TIMEOUT_MS) || 120000;
  const readyTimeoutMs = opts.readyTimeoutMs || 30000;
  const maxRestarts = opts.maxRestarts || 5;
  const restartWindowMs = opts.restartWindowMs || 60000;
  const execArgv = opts.execArgv || [];
  const childEnv = opts.env || {};

  let child = null;
  let ready = false;
  let readyWaiters = [];
  let current = null;            // { match, resolve, reject, timer }
  let chain = Promise.resolve(); // sequential (single-flight) executor
  const loaded = { chat: false, embed: false };
  let spawnTimes = [];
  let circuitUntil = 0;

  function unavailable(message) { const e = new Error(message); e.code = 'AI_INTERNAL_UNAVAILABLE'; return e; }

  function finishCurrent(msg, err) {
    if (!current) return;
    const c = current; current = null;
    if (c.timer) clearTimeout(c.timer);
    if (err) c.reject(err); else c.resolve(msg);
  }

  function onMessage(msg) {
    if (!msg || typeof msg.t !== 'string') return;
    if (msg.t === 'log') { const lv = msg.level || 'info'; (log[lv] || log.info)('[model-worker] ' + msg.msg, msg.meta || undefined); return; }
    if (msg.t === 'ready') { ready = true; const w = readyWaiters; readyWaiters = []; w.forEach((r) => r()); return; }
    if (msg.t === 'loaded' && msg.kind) loaded[msg.kind] = true;
    if (msg.t === 'unloaded') { if (msg.kind === 'all' || !msg.kind) { loaded.chat = false; loaded.embed = false; } else loaded[msg.kind] = false; }
    if (current) {
      if (msg.t === 'error') { const e = new Error(msg.message || 'worker error'); e.code = msg.code || 'AI_INTERNAL_UNAVAILABLE'; finishCurrent(null, e); return; }
      if (current.match(msg)) { finishCurrent(msg, null); return; }
    }
  }

  function onExit(code, signal) {
    ready = false; child = null; loaded.chat = false; loaded.embed = false;
    log.warn('model worker exited', { code, signal });
    if (current) finishCurrent(null, unavailable('model worker exited (' + (signal || code) + ')'));
  }

  async function ensureReady() {
    const now = Date.now();
    if (now < circuitUntil) throw unavailable('model worker unavailable (restart circuit open)');
    if (child && ready) return;
    if (!child) {
      spawnTimes = spawnTimes.filter((t) => now - t < restartWindowMs);
      if (spawnTimes.length >= maxRestarts) { circuitUntil = now + restartWindowMs; throw unavailable('model worker exceeded restart limit; backing off'); }
      spawnTimes.push(now);
      child = fork(workerPath, [], { env: Object.assign({}, process.env, childEnv), execArgv, stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
      ready = false;
      child.on('message', onMessage);
      child.on('exit', onExit);
      child.on('error', (e) => log.error('model worker error', { error: e.message }));
    }
    if (!ready) {
      await new Promise((resolve, reject) => {
        const to = setTimeout(() => { reject(unavailable('model worker did not become ready')); }, readyTimeoutMs);
        readyWaiters.push(() => { clearTimeout(to); resolve(); });
      });
    }
  }

  function run(msg, match) {
    const op = async () => {
      await ensureReady();
      return await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const e = new Error('model worker timed out'); e.code = 'AI_INFERENCE_FAILED';
          finishCurrent(null, e);
          try { if (child) child.kill('SIGKILL'); } catch (_e) { /* ignore */ }
        }, timeoutMs);
        current = { match, resolve, reject, timer };
        try { child.send(msg); } catch (err) { finishCurrent(null, unavailable('failed to send to worker: ' + err.message)); }
      });
    };
    const result = chain.then(op, op);
    chain = result.then(() => {}, () => {}); // keep the chain alive regardless of outcome
    return result;
  }

  return {
    isLoaded(kind) { return kind ? !!loaded[kind] : (loaded.chat || loaded.embed); },

    async load(kind, modelPath, expectedSizeBytes) {
      if (kind !== 'chat' && kind !== 'embed') throw unavailable('unknown model kind: ' + kind);
      await run({ t: 'load', kind, modelPath, expectedSizeBytes }, (m) => m.t === 'loaded' && m.kind === kind);
      return { kind, loaded: true };
    },

    async generate(prompt, options) {
      const m = await run({ t: 'generate', id: 'g', prompt, options: options || {} }, (x) => x.t === 'result');
      return { text: m.text, modelName: m.modelName };
    },

    async embed(text) {
      const m = await run({ t: 'embed', id: 'e', text }, (x) => x.t === 'embedding');
      return m.vector;
    },

    async unload(kind) {
      await run({ t: 'unload', kind }, (m) => m.t === 'unloaded');
    },

    async status() {
      try {
        const m = await run({ t: 'status' }, (x) => x.t === 'status');
        return { spawned: true, ready: true, chatLoaded: m.chatLoaded, embedLoaded: m.embedLoaded, info: m.info };
      } catch (e) {
        return { spawned: !!child, ready, chatLoaded: loaded.chat, embedLoaded: loaded.embed, error: e.code || 'AI_INTERNAL_UNAVAILABLE' };
      }
    },

    shutdown() {
      try { if (child) { child.removeAllListeners('exit'); child.kill('SIGKILL'); } } catch (_e) { /* ignore */ }
      child = null; ready = false; loaded.chat = false; loaded.embed = false;
      if (current) finishCurrent(null, unavailable('model worker host shut down'));
    },
  };
}

// Shared singleton for the server side: one worker hosts both chat + embed.
let shared = null;
function getSharedHost(opts) { if (!shared) shared = createWorkerHost(opts); return shared; }
function _resetSharedHost() { if (shared) shared.shutdown(); shared = null; }

module.exports = { createWorkerHost, getSharedHost, _resetSharedHost };

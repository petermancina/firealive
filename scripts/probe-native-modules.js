#!/usr/bin/env node
'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// probe-native-modules.js  --  runtime companion to check-native-modules  (pre-N2)
// ═══════════════════════════════════════════════════════════════════════════
//
// Actually LOADS the two native N-API addons and exercises each, so the claim
// build.yml makes in a comment --
//
//   "node-llama-cpp and @mongodb-js/zstd are N-API and load under Electron
//    without a node-gyp rebuild"
//
// -- stops being an assertion and becomes a test. The smoke job runs this after
// `npm install`, so a prebuilt that does not load, or a zstd binding that
// installs but cannot round-trip, fails a pull request instead of surfacing the
// first time an analyst runs inference or the first time a backup is written.
//
// The smoke job already asserts better-sqlite3's `.node` is PRESENT in the
// extracted app (build.yml). Presence is not loading: a wrong-arch or truncated
// binary is present and does not load. This probe closes that gap for the two
// modules whose loadability the workflow only claimed -- by loading them and, for
// zstd, compressing and decompressing a buffer and checking it survived.
//
// WHY AN INJECTABLE LOADER
//
// The module loaders are parameters, exactly as model-worker.js takes
// `loadLlama: () => require('node-llama-cpp')` (model-worker.js:173) and
// model-worker-host takes an injectable `fork` "for testing". That lets
// --self-test drive the probe with fakes -- a healthy pair, and several broken
// ones -- and prove the probe passes the healthy pair and REJECTS each broken
// one, on every run, with no native module installed. In CI the same code path
// runs against the real `require`s.
//
// getLlama() is the load trigger for node-llama-cpp v3 (the native binding is
// lazy until then); calling it with no arguments selects the CPU backend, which
// is what a headless runner has, and loads the binding without needing a model
// file. zstd's round-trip needs no external input at all.
// ═══════════════════════════════════════════════════════════════════════════

const ZSTD_MODULE = '@mongodb-js/zstd';
const LLAMA_MODULE = 'node-llama-cpp';

// Load a module + exercise it. Loaders are injected. Throws with a clear,
// module-attributed message on any failure. Returns a per-module status map.
async function runProbe(deps) {
  const loadZstd = deps.loadZstd;
  const loadLlama = deps.loadLlama;
  const log = deps.log || (() => {});
  const status = {};

  // ── @mongodb-js/zstd: load + compress/decompress round-trip ──
  log('probing ' + ZSTD_MODULE + ' ...');
  let zstd;
  try { zstd = loadZstd(); }
  catch (e) { throw new Error(ZSTD_MODULE + ': require/load threw: ' + (e && e.message ? e.message : e)); }
  if (!zstd || typeof zstd.compress !== 'function' || typeof zstd.decompress !== 'function') {
    throw new Error(ZSTD_MODULE + ': loaded but does not expose compress()/decompress() -- backup archiving would fail');
  }
  const sample = Buffer.from('firealive native-module probe :: zstd round-trip :: ' + 'A'.repeat(4096));
  let restored;
  try {
    const compressed = await zstd.compress(sample, 3);
    if (!Buffer.isBuffer(compressed) || compressed.length === 0) {
      throw new Error('compress() returned no bytes');
    }
    restored = await zstd.decompress(compressed);
  } catch (e) {
    throw new Error(ZSTD_MODULE + ': compress/decompress threw: ' + (e && e.message ? e.message : e));
  }
  if (!Buffer.isBuffer(restored) || Buffer.compare(Buffer.from(restored), sample) !== 0) {
    throw new Error(ZSTD_MODULE + ': round-trip did not restore the input -- the native binding is loaded but wrong; every backup would be silently corrupt');
  }
  status.zstd = 'loaded + round-tripped ' + sample.length + ' bytes';
  log('  ' + ZSTD_MODULE + ': ok (' + status.zstd + ')');

  // ── node-llama-cpp: load + getLlama() (loads the native backend, no model) ──
  log('probing ' + LLAMA_MODULE + ' ...');
  let llamaModule;
  try { llamaModule = loadLlama(); }
  catch (e) { throw new Error(LLAMA_MODULE + ': require/load threw: ' + (e && e.message ? e.message : e)); }
  const getLlama = llamaModule && llamaModule.getLlama;
  if (typeof getLlama !== 'function') {
    throw new Error(LLAMA_MODULE + ': loaded but does not expose getLlama() -- inference would fail');
  }
  let llama;
  try { llama = await getLlama(); }
  catch (e) { throw new Error(LLAMA_MODULE + ': getLlama() threw (the native binding did not load): ' + (e && e.message ? e.message : e)); }
  if (!llama || typeof llama !== 'object') {
    throw new Error(LLAMA_MODULE + ': getLlama() did not return a Llama instance -- the native backend is not usable');
  }
  status.llama = 'loaded + getLlama() initialized the backend';
  log('  ' + LLAMA_MODULE + ': ok (' + status.llama + ')');

  return status;
}

// ── self-test: healthy fakes pass; each broken fake is rejected ──────────────
async function selfTest() {
  // a faithful fake zstd: length-prefixed passthrough that truly round-trips
  const goodZstd = () => ({
    compress: async (buf) => Buffer.concat([Buffer.from('Z'), Buffer.from(buf)]),
    decompress: async (buf) => Buffer.from(buf).slice(1),
  });
  const goodLlama = () => ({ getLlama: async () => ({ /* stand-in Llama instance */ __probe: true }) });

  const cases = [
    { name: 'healthy pair -> passes', deps: { loadZstd: goodZstd, loadLlama: goodLlama }, wantThrow: null },
    { name: 'zstd require throws', deps: { loadZstd: () => { throw new Error('MODULE_NOT_FOUND'); }, loadLlama: goodLlama }, wantThrow: 'require/load threw' },
    { name: 'zstd missing compress()', deps: { loadZstd: () => ({ decompress: async (b) => b }), loadLlama: goodLlama }, wantThrow: 'compress()/decompress()' },
    { name: 'zstd round-trip corrupts bytes', deps: { loadZstd: () => ({ compress: async (b) => Buffer.concat([Buffer.from('Z'), Buffer.from(b)]), decompress: async () => Buffer.from('corrupt') }), loadLlama: goodLlama }, wantThrow: 'did not restore the input' },
    { name: 'llama missing getLlama()', deps: { loadZstd: goodZstd, loadLlama: () => ({}) }, wantThrow: 'does not expose getLlama()' },
    { name: 'llama getLlama() throws (binding did not load)', deps: { loadZstd: goodZstd, loadLlama: () => ({ getLlama: async () => { throw new Error('dlopen failed'); } }) }, wantThrow: 'getLlama() threw' },
    { name: 'llama getLlama() returns null', deps: { loadZstd: goodZstd, loadLlama: () => ({ getLlama: async () => null }) }, wantThrow: 'did not return a Llama instance' },
  ];

  let bad = 0;
  for (const c of cases) {
    let threw = null;
    try { await runProbe(c.deps); } catch (e) { threw = e.message; }
    let ok;
    if (c.wantThrow === null) {
      ok = threw === null;
      if (!ok) console.error('  FAIL  ' + c.name + '\n        expected success, threw: ' + threw);
    } else {
      ok = threw !== null && threw.includes(c.wantThrow);
      if (!ok) console.error('  FAIL  ' + c.name + '\n        expected a throw containing ' + JSON.stringify(c.wantThrow) + ', got: ' + (threw === null ? '(no throw)' : threw));
    }
    if (ok) console.log('  ok    ' + c.name); else bad++;
  }
  if (bad) { console.error('\nprobe self-test FAILED: ' + bad + ' of ' + cases.length + ' cases.'); process.exit(1); }
  console.log('\nprobe self-test passed (' + cases.length + ' cases: healthy pair passes; require-throw, missing API, corrupt round-trip, and dead getLlama each rejected).');
}

// Only dispatch the CLI when run directly. Requiring this file (e.g. a future
// harness that wants runProbe) must NOT kick off a real load.
if (require.main === module) {
  if (process.argv.includes('--self-test')) {
    selfTest();
  } else {
    runProbe({
      loadZstd: () => require(ZSTD_MODULE),
      loadLlama: () => require(LLAMA_MODULE),
      log: (m) => console.log(m),
    }).then((status) => {
      console.log('\nprobe-native-modules passed: '
        + ZSTD_MODULE + ' [' + status.zstd + '], '
        + LLAMA_MODULE + ' [' + status.llama + '].');
    }).catch((e) => {
      console.error('\nprobe-native-modules FAILED: ' + (e && e.message ? e.message : e));
      process.exit(1);
    });
  }
}

module.exports = { runProbe };

#!/usr/bin/env node
'use strict';

// check-seal-version.js -- regression for B6h B-5 seal-format versioning.
//
// Both servers:
//   - the envelope open() floor rejects a value below MIN_SEAL_VERSION (crafted v0), while
//     v1 and v2 still open; sealVersionOf returns 1 for legacy / 2 for v2
//   - seal-version checkAndAdvance advances on a fresh node, refuses a rollback (cur < hw),
//     and never lowers the high-water
//   - reportStragglers counts a v1 straggler WITHOUT persisting (node_state unchanged)
//   - the boot hooks (HALT on rollback) are wired in both index.js

const fs = require('fs');
const path = require('path');
const Module = require('module');

const REPO = path.resolve(__dirname, '..');
const problems = [];
const check = (name, cond) => { if (!cond) problems.push(name); };
const read = (rel) => { try { return fs.readFileSync(path.join(REPO, rel), 'utf8'); } catch (e) { return ''; } };

function withStubs(map, fn) {
  const orig = Module._load;
  Module._load = function (r) { if (map[r]) return map[r](); return orig.apply(this, arguments); };
  try { return fn(); } finally { Module._load = orig; }
}
const naclStubs = {
  tweetnacl: () => ({ box: {}, sign: {}, randomBytes: (n) => Buffer.alloc(n), secretbox: Object.assign((m) => m, { open: (m) => m, nonceLength: 24, keyLength: 32, overheadLength: 16 }) }),
  'tweetnacl-util': () => ({ decodeBase64: (s) => Buffer.from(s, 'base64'), encodeBase64: (b) => Buffer.from(b).toString('base64'), decodeUTF8: (s) => Buffer.from(s), encodeUTF8: (b) => Buffer.from(b).toString() }),
};

// ---- Section A: the MC envelope floor + sealVersionOf ----
withStubs(Object.assign({}, naclStubs, {
  './encryption': () => ({ encryptWithKey: (pt) => Buffer.concat([Buffer.alloc(12), Buffer.alloc(16), Buffer.from(pt)]), decryptWithKey: (buf) => buf.subarray(28).toString('utf-8') }),
}), function () {
  delete require.cache[require.resolve(path.join(REPO, 'server/services/tier1-envelope.js'))];
  const env = require(path.join(REPO, 'server/services/tier1-envelope.js'));
  const key = Buffer.alloc(32, 7), fp = Buffer.alloc(8, 9), aad = Buffer.from('t\u0000c');
  const v2 = env.sealV2('hello', key, fp, aad);
  check('MC sealVersionOf(v2) = 2', env.sealVersionOf(v2) === 2);
  check('MC MIN_SEAL_VERSION = 1', env.MIN_SEAL_VERSION === 1);
  check('MC v2 opens at floor', env.open(v2, key, aad, fp) === 'hello');
  const v1 = Buffer.concat([Buffer.alloc(12), Buffer.alloc(16), Buffer.from('legacy')]); // no magic
  check('MC sealVersionOf(v1) = 1', env.sealVersionOf(v1) === 1);
  check('MC v1 opens at floor', env.open(v1, key) === 'legacy');
  const v0 = Buffer.from(v2); v0[env.MAGIC.length] = 0; // craft a below-floor version byte
  check('MC sealVersionOf(v0) = 0', env.sealVersionOf(v0) === 0);
  let floored = false; try { env.open(v0, key, aad, fp); } catch (e) { floored = /MIN_SEAL_VERSION floor/.test(e.message); }
  check('MC open() rejects a below-floor value', floored);
});

// ---- Section A': the GD envelope floor + sealVersionOf ----
withStubs(Object.assign({}, naclStubs, {
  './gd-encryption': () => ({ encryptConfigWithKey: (v) => JSON.stringify({ v: 1, iv: '', tag: '', ciphertext: Buffer.from(JSON.stringify(v)).toString('base64') }), decryptConfigWithKey: (e) => JSON.parse(Buffer.from(JSON.parse(e).ciphertext, 'base64').toString()) }),
}), function () {
  delete require.cache[require.resolve(path.join(REPO, 'packages/global-dashboard-server/services/gd-tier1-envelope.js'))];
  const env = require(path.join(REPO, 'packages/global-dashboard-server/services/gd-tier1-envelope.js'));
  const key = Buffer.alloc(32, 7), fp = Buffer.alloc(8, 9), aad = Buffer.from('t\u0000c');
  const v2 = env.sealV2('hello', key, fp, aad);
  check('GD sealVersionOf(v2) = 2', env.sealVersionOf(v2) === 2);
  check('GD v2 opens at floor', env.open(v2, key, aad, fp) === 'hello');
  const v1 = JSON.stringify({ v: 1, iv: '', tag: '', ciphertext: Buffer.from(JSON.stringify('legacy')).toString('base64') });
  check('GD sealVersionOf(v1) = 1', env.sealVersionOf(v1) === 1);
  check('GD v1 opens at floor', env.open(v1, key) === 'legacy');
  const v0 = JSON.stringify(Object.assign(JSON.parse(v2), { v: 0 }));
  check('GD sealVersionOf(v0) = 0', env.sealVersionOf(v0) === 0);
  let floored = false; try { env.open(v0, key, aad, fp); } catch (e) { floored = /MIN_SEAL_VERSION floor/.test(e.message); }
  check('GD open() rejects a below-floor value', floored);
});

// ---- Section B: seal-version high-water + stragglers (both servers) ----
function svSuite(label, modRel, envReq, colsReq, storage, mkV1, mkV2) {
  const stub = {};
  stub[envReq] = () => ({ CURRENT_SEAL_VERSION: 2, sealVersionOf: (x) => { const s = Buffer.isBuffer(x) ? x.toString() : String(x); try { const v = JSON.parse(s).v; return typeof v === 'number' ? v : (s.indexOf('V2') === 0 ? 2 : 1); } catch (e) { return s.indexOf('V2') === 0 ? 2 : 1; } } });
  stub[colsReq] = () => ({ TIER1_COLUMNS: COLS, GD_TIER1_COLUMNS: COLS });
  const COLS = [
    { table: 'ca_authority', column: 'ca_private_key_encrypted', domain: 'replicated', class: 'tier1', storage: storage },
    { table: 'kms_providers', column: 'credentials_encrypted', domain: 'replicated', class: 'tier1', storage: storage },
  ];
  withStubs(stub, function () {
    delete require.cache[require.resolve(path.join(REPO, modRel))];
    const sv = require(path.join(REPO, modRel));
    check(label + ' currentSealVersion = 2', sv.currentSealVersion() === 2);
    function mkDb(rows, ns) {
      const state = { ns: ns || {} };
      return {
        state: state,
        prepare(sql) {
          if (/node_state/.test(sql) && /SELECT/.test(sql)) return { get: () => state.ns.seal_version_high_water !== undefined ? { value: state.ns.seal_version_high_water } : undefined };
          if (/node_state/.test(sql)) return { run: (v) => { state.ns.seal_version_high_water = v; } };
          const t = (sql.match(/FROM "(\w+)"/) || [])[1]; const col = (sql.match(/"(\w+)" AS val/) || [])[1];
          return { all: () => (rows[t] || []).filter(x => x[col] != null).map(x => ({ val: x[col] })) };
        },
      };
    }
    let db = mkDb({}); let v = sv.checkAndAdvance(db);
    check(label + ' fresh advances to 2', v.rollback === false && v.highWater === 2 && db.state.ns.seal_version_high_water === '2');
    db = mkDb({}, { seal_version_high_water: '3' }); v = sv.checkAndAdvance(db);
    check(label + ' refuses a rollback (cur 2 < hw 3)', v.rollback === true && v.advanced === false);
    check(label + ' never lowers the high-water', db.state.ns.seal_version_high_water === '3');
    db = mkDb({ ca_authority: [{ ca_private_key_encrypted: mkV2() }], kms_providers: [{ credentials_encrypted: mkV1() }] });
    const before = JSON.stringify(db.state.ns);
    const rep = sv.reportStragglers(db);
    check(label + ' reportStragglers counts the 1 v1 straggler', rep.below === 1 && rep.total === 2);
    check(label + ' reportStragglers does NOT persist', JSON.stringify(db.state.ns) === before);
  });
}
svSuite('MC', 'server/services/seal-version.js', './tier1-envelope', './tier1-columns', 'base64',
  () => Buffer.from('V1yyyy').toString('base64'), () => Buffer.from('V2xxxx').toString('base64'));
svSuite('GD', 'packages/global-dashboard-server/services/gd-seal-version.js', './gd-tier1-envelope', './gd-tier1-columns', 'envelope',
  () => JSON.stringify({ v: 1, iv: 'x', tag: 'x', ciphertext: 'x' }), () => JSON.stringify({ v: 2, kek_fp: 'x', iv: 'x', tag: 'x', ciphertext: 'x' }));

// ---- Section C: boot hooks wired ----
const mcIndex = read('server/index.js');
check('MC boot hook: seal-version checkAndAdvance', /sealVersion\.checkAndAdvance/.test(mcIndex));
check('MC boot hook: HALT on seal-version rollback', /HALTING: seal-version anti-rollback/.test(mcIndex));
check('MC boot hook: reportStragglers', /sealVersion\.reportStragglers/.test(mcIndex));
const gdIndex = read('packages/global-dashboard-server/index.js');
check('GD boot hook: seal-version checkAndAdvance', /gdSealVersion\.checkAndAdvance/.test(gdIndex));
check('GD boot hook: HALT on seal-version rollback', /HALTING: GD seal-version anti-rollback/.test(gdIndex));

if (problems.length) {
  console.error('seal-version regression FAILED:');
  for (let i = 0; i < problems.length; i++) console.error('  - ' + problems[i]);
  process.exit(1);
}
console.log('seal-version regression passed: floor rejects below-floor (v0) while v1/v2 open, sealVersionOf, high-water advance + rollback-refused + never-lowered, stragglers without persist, and boot hooks wired (both servers).');

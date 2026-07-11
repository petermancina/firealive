#!/usr/bin/env node
'use strict';

/*
 * check-tier1-seal-roundtrip.js
 *
 * Round-trip regression for the Tier-1 seal/open chokepoint. For every column in
 * the generated registry it seals a value and opens it back through the REAL
 * tier1-seal module, and asserts:
 *
 *   - round trip: the opened value equals the sealed value (per the column's
 *     shape -- json objects and utf8 strings both survive);
 *   - storage type: storage 'buffer' yields a Buffer, 'base64'/'hex'/'envelope'
 *     yield a string;
 *   - domain -> key: a node-local column is sealed AND opened with ownKek(), a
 *     replicated column with sharedKek() -- the routing this phase exists for;
 *   - null passthrough: sealTier1/openTier1 of null return null;
 *   - fail-closed: an unregistered column and a tier1-derived column both throw.
 *
 * The chokepoint's crypto core (encryption.encryptWithKey) needs tweetnacl at
 * module load and its KEK resolvers need real hardware -- neither is present in
 * the pure-Node coverage job. So this loads the real modules with two seams
 * stubbed at require time: tweetnacl/tweetnacl-util (unused by the AES core) are
 * replaced with empty objects, and the KEK module is replaced with a mock that
 * returns two distinct fixed keys and records which one each call used. Nothing
 * else is stubbed: the real tier1-seal logic, the real AES envelope, and the real
 * committed registry are all exercised.
 *
 * Usage:
 *   node scripts/check-tier1-seal-roundtrip.js
 */

const path = require('path');
const Module = require('module');

// Distinct fixed keys per domain; the mock records every resolve so the test can
// assert which key a column used.
const OWN_KEK = Buffer.alloc(32, 0x11);
const SHARED_KEK = Buffer.alloc(32, 0x22);
const kekUsed = [];
function mockKek(sealModuleBasename) {
  return {
    ownKek: function () { kekUsed.push('own'); return OWN_KEK; },
    sharedKek: function () { kekUsed.push('shared'); return SHARED_KEK; },
  };
}

// Per-server wiring. Each entry names the seal module, its registry, the exported
// registry array, the KEK module the seal module requires (relative to it), and
// the basename used to scope the require interception.
const SERVERS = [
  {
    name: 'mc',
    sealModule: '../server/services/tier1-seal.js',
    registryModule: '../server/services/tier1-columns.js',
    registryExport: 'TIER1_COLUMNS',
    kekRequest: './tier1-kek',
    sealBasename: 'tier1-seal.js',
    derivedExample: 'ha_node.wrap_private_sealed',
  },
  {
    name: 'gd',
    sealModule: '../packages/global-dashboard-server/services/gd-tier1-seal.js',
    registryModule: '../packages/global-dashboard-server/services/gd-tier1-columns.js',
    registryExport: 'GD_TIER1_COLUMNS',
    kekRequest: './gd-tier1-kek',
    sealBasename: 'gd-tier1-seal.js',
    derivedExample: 'gd_ha_node.wrap_private_sealed',
  },
];

// Install the require interception once. It routes each server's KEK require to a
// mock and neutralizes tweetnacl for the real encryption module.
const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'tweetnacl' || request === 'tweetnacl-util') return {};
  if (parent && parent.filename) {
    for (let i = 0; i < SERVERS.length; i++) {
      const s = SERVERS[i];
      if (request === s.kekRequest && parent.filename.endsWith(s.sealBasename)) {
        return mockKek(s.sealBasename);
      }
    }
  }
  return originalLoad.apply(this, arguments);
};

function valueForShape(shape) {
  if (shape === 'json') return { pem: '-----BEGIN-----abc', list: ['a', 'b'], n: 7, nested: { ok: true } };
  if (shape === 'utf8') return 'a-plain-utf8-secret-token-0123456789';
  if (shape === 'raw') return Buffer.alloc(32, 0x5a); // not sealed via the chokepoint; present for completeness
  return null;
}

function runServer(s) {
  const problems = [];
  const seal = require(path.resolve(__dirname, s.sealModule));
  const registry = require(path.resolve(__dirname, s.registryModule))[s.registryExport];
  const tier1 = registry.filter(function (c) { return c.class === 'tier1'; });

  for (let i = 0; i < tier1.length; i++) {
    const c = tier1[i];
    const ref = c.table + '.' + c.column;
    const value = valueForShape(c.shape);

    kekUsed.length = 0;
    let stored, opened;
    try {
      stored = seal.sealTier1(ref, value);
      opened = seal.openTier1(ref, stored);
    } catch (e) {
      problems.push(s.name + ': ' + ref + ' threw: ' + e.message);
      continue;
    }
    const usedSeal = kekUsed[0];
    const usedOpen = kekUsed[1];

    // storage type
    const storageOk = c.storage === 'buffer' ? Buffer.isBuffer(stored) : (typeof stored === 'string');
    if (!storageOk) problems.push(s.name + ': ' + ref + ' storage ' + c.storage + ' produced ' + (Buffer.isBuffer(stored) ? 'Buffer' : typeof stored));

    // domain -> key
    const wantKey = c.domain === 'node-local' ? 'own' : 'shared';
    if (usedSeal !== wantKey || usedOpen !== wantKey) {
      problems.push(s.name + ': ' + ref + ' domain ' + c.domain + ' expected ' + wantKey + ' key, used seal=' + usedSeal + ' open=' + usedOpen);
    }

    // round trip
    if (JSON.stringify(opened) !== JSON.stringify(value)) {
      problems.push(s.name + ': ' + ref + ' round trip mismatch');
    }
  }

  // null passthrough (use any tier1 column)
  if (tier1.length) {
    const anyRef = tier1[0].table + '.' + tier1[0].column;
    if (seal.sealTier1(anyRef, null) !== null) problems.push(s.name + ': sealTier1(null) did not return null');
    if (seal.openTier1(anyRef, null) !== null) problems.push(s.name + ': openTier1(null) did not return null');
  }

  // fail-closed: unregistered
  let threw = false;
  try { seal.sealTier1('no_such_table.no_such_column', 'x'); } catch (e) { threw = true; }
  if (!threw) problems.push(s.name + ': sealTier1 accepted an unregistered column');

  // fail-closed: tier1-derived
  threw = false;
  try { seal.sealTier1(s.derivedExample, 'x'); } catch (e) { threw = true; }
  if (!threw) problems.push(s.name + ': sealTier1 accepted a tier1-derived column (' + s.derivedExample + ')');

  return { count: tier1.length, problems: problems };
}

function main() {
  let all = [];
  for (let i = 0; i < SERVERS.length; i++) {
    const s = SERVERS[i];
    const r = runServer(s);
    console.log('[' + (r.problems.length ? 'FAIL' : 'ok') + '] ' + s.name + ': ' + r.count + ' tier1 columns round-tripped');
    all = all.concat(r.problems);
  }
  console.log('');
  if (all.length) {
    console.error('Tier-1 seal round-trip regression FAILED:');
    for (let i = 0; i < all.length; i++) console.error('  - ' + all[i]);
    process.exit(1);
  }
  console.log('Tier-1 seal round-trip regression passed.');
}

if (require.main === module) main();

#!/usr/bin/env node
'use strict';

// check-ha-unpair.js
//
// Regression for the B6h A-10 un-pair flow on BOTH servers. A-10 adds un-pair +
// peer-unpair, gates every mutating HA route with MFA step-up AND config-lock, and
// sheds the shared KEK where safe -- fail-closed against data loss (a promoted node
// whose replicated data is under an adopted shared KEK refuses to un-pair until an
// offline rekey, Part B).
//
// It combines functional checks (loadable, standalone modules) with source-level
// assertions (for the routes and the pairing teardown, which pull in better-sqlite3
// and cannot be required in CI):
//   1. config-lock: /unpair and /manual-failover are config-write-gated on both
//      servers; HA reads are not;
//   2. MFA step-up: both mutating HA routes carry mfaStepUp()/gdMfaStepUp(), and the
//      mTLS peer /unpair route exists;
//   3. fail-closed un-pair: unpair() refuses when shared_kek_sealed is present and
//      otherwise reverses pairing (clears the peer, resets role to standalone, sheds
//      the shared KEK) on both servers;
//   4. clearSharedKek actually sheds: deleting node_state.shared_kek_sealed makes
//      sharedKek() fall back to ownKek() (both servers).

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Module = require('module');

// stub the hardware keystore for the clearSharedKek functional check
const MAGIC = Buffer.from('HWSEALv1');
const stubKs = { sealKey: (k) => Buffer.concat([MAGIC, Buffer.from(k)]), unsealKey: (b) => b.slice(MAGIC.length) };
const origLoad = Module._load;
Module._load = function (request) {
  if (typeof request === 'string' && request.indexOf('hardware-keystore') !== -1) return stubKs;
  return origLoad.apply(this, arguments);
};

const REPO = path.resolve(__dirname, '..');
const problems = [];
const check = (name, cond) => { if (!cond) problems.push(name); };
const read = (rel) => { try { return fs.readFileSync(path.join(REPO, rel), 'utf8'); } catch (e) { return ''; } };

// --- 1. config-lock gating (functional) ---
for (const [label, rel] of [
  ['MC', path.join('server', 'middleware', 'config-write-routes.js')],
  ['GD', path.join('packages', 'global-dashboard-server', 'services', 'gd-config-write-routes.js')],
]) {
  try {
    const m = require(path.join(REPO, rel));
    const fn = m.isConfigWriteRequest || m.isGdConfigWriteRequest;
    check(`${label}: /unpair is config-write gated`, typeof fn === 'function' && fn('POST', '/api/ha/unpair') === true);
    check(`${label}: /manual-failover is config-write gated`, typeof fn === 'function' && fn('POST', '/api/ha/manual-failover') === true);
    check(`${label}: HA status GET is not gated`, typeof fn === 'function' && fn('GET', '/api/ha/status') === false);
  } catch (e) {
    problems.push(`${label}: config-write-routes failed to load: ${e.message}`);
  }
}

// --- 2. MFA step-up on the mutating routes + peer route exists (source) ---
const mc = read(path.join('server', 'routes', 'ha.js'));
check('MC: /unpair requires mfaStepUp', /post\('\/unpair', mfaStepUp\(\)/.test(mc));
check('MC: /manual-failover requires mfaStepUp', /post\('\/manual-failover', mfaStepUp\(\)/.test(mc));
check('MC: peer /unpair route exists', /peerRouter\.post\('\/unpair'/.test(mc));
const gd = read(path.join('packages', 'global-dashboard-server', 'routes', 'gd-ha.js'));
check('GD: /unpair requires gdMfaStepUp', /post\('\/unpair', gdMfaStepUp\(\)/.test(gd));
check('GD: /manual-failover requires gdMfaStepUp', /post\('\/manual-failover', gdMfaStepUp\(\)/.test(gd));
check('GD: peer /unpair route exists', /peerRouter\.post\('\/unpair'/.test(gd));
check('MC: peer /unpair is rate-limited', /peerRouter\.post\('\/unpair', peerUnpairLimiter/.test(mc));
check('GD: peer /unpair is rate-limited', /peerRouter\.post\('\/unpair', peerUnpairLimiter/.test(gd));

// --- 3. fail-closed un-pair guard + teardown (source) ---
for (const [label, rel, peerTbl] of [
  ['MC', path.join('server', 'services', 'ha', 'ha-pairing.js'), 'ha_peer'],
  ['GD', path.join('packages', 'global-dashboard-server', 'services', 'gd-ha-pairing.js'), 'gd_ha_peer'],
]) {
  const src = read(rel);
  check(`${label}: unpair refuses when shared_kek_sealed present`,
    /node_state WHERE key = 'shared_kek_sealed'/.test(src) && /unpair refused/.test(src));
  check(`${label}: unpair clears the peer`, src.indexOf('DELETE FROM ' + peerTbl) !== -1);
  check(`${label}: unpair resets role to standalone`, /role = 'standalone'/.test(src));
  check(`${label}: unpair stops CDC capture`, /dropTriggers\(db\)/.test(src));
  check(`${label}: unpair sheds the shared KEK`, /clearSharedKek\(db\)/.test(src));
}

// --- 4. clearSharedKek actually sheds (functional) ---
function mockKekDb() {
  const m = new Map();
  return {
    prepare(sql) {
      return {
        run: (...a) => { if (/^DELETE/.test(sql)) m.delete('shared_kek_sealed'); else m.set('shared_kek_sealed', String(a[a.length - 1])); },
        get: () => (m.has('shared_kek_sealed') ? { value: m.get('shared_kek_sealed') } : undefined),
      };
    },
    _m: m,
  };
}
for (const [label, rel, envVar] of [
  ['MC', path.join('server', 'services', 'tier1-kek.js'), 'TIER1_ENCRYPTION_KEY'],
  ['GD', path.join('packages', 'global-dashboard-server', 'services', 'gd-tier1-kek.js'), 'GD_ENCRYPTION_KEY'],
]) {
  try {
    const kek = require(path.join(REPO, rel));
    kek._resetCacheForTests();
    process.env[envVar] = kek.SEAL_PREFIX + stubKs.sealKey(crypto.randomBytes(32)).toString('base64');
    const shared = crypto.randomBytes(32);
    const db = mockKekDb();
    kek.adoptSharedKek(db, shared);
    check(`${label}: precondition adopt installs the shared KEK`, kek.sharedKek().equals(shared));
    kek.clearSharedKek(db);
    check(`${label}: clearSharedKek deletes the wrapper`, !db._m.has('shared_kek_sealed'));
    check(`${label}: after clear, sharedKek falls back to ownKek`, kek.sharedKek().equals(kek.ownKek()));
    kek._resetCacheForTests();
  } catch (e) {
    problems.push(`${label}: tier1-kek clearSharedKek check failed: ${e.message}`);
  }
}

if (problems.length) {
  console.error('HA un-pair regression FAILED:');
  for (const p of problems) console.error('  - ' + p);
  process.exit(1);
}
console.log('HA un-pair regression passed: config-lock + MFA on mutating HA routes; fail-closed un-pair; shared-KEK shed (both servers).');

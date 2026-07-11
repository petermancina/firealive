#!/usr/bin/env node
'use strict';

// check-shared-kek-boot-reload.js
//
// Regression for the B6h A-7 shared-KEK continuity lifecycle, on BOTH servers
// (tier1-kek and gd-tier1-kek). A node promoted from passive installs the former
// active's KEK to read the replicated Tier-1 columns; before A-7 that install was
// in-memory only, so a reboot lost it and the node fell back to its own KEK and
// mis-read replicated data (R1/R4). A-7 seals the shared KEK to THIS node's
// hardware, persists it to the excluded node_state table, and reloads it on boot
// -- fail-closed if it cannot be unsealed.
//
// This runs in CI, where there is no hardware root of trust, so it stubs the
// hardware keystore with an invertible seal/unseal (and a togglable failure) and
// backs node_state with a mock db. It asserts, for each server:
//   1. no adopted shared KEK   -> loadSharedKekOnBoot is a no-op (false), and
//      sharedKek() falls back to ownKek();
//   2. adoptSharedKek          -> persists a hardware-sealed wrapper AND installs
//      it (sharedKek() == the adopted KEK, distinct from ownKek());
//   3. reboot -> reload         -> after clearing the in-memory cache,
//      loadSharedKekOnBoot restores the adopted KEK (sharedKek() correct again);
//   4. fail-closed on unseal    -> a present-but-unsealable wrapper THROWS on boot
//      (no silent fallback to ownKek());
//   5. fail-closed on shape     -> a non-hardware-sealed wrapper THROWS.
//
// The real hardware seal/unseal round-trip is already exercised by the ownKek
// provisioning/boot self-tests; this regression locks down the NEW persistence and
// fail-closed-reload logic that A-7 added.

const crypto = require('crypto');
const path = require('path');
const Module = require('module');

// --- stub the hardware keystore (invertible, with a failure toggle) --------
const MAGIC = Buffer.from('HWSEALv1');
let unsealShouldThrow = false;
const stubKeystore = {
  sealKey(rawKek) { return Buffer.concat([MAGIC, Buffer.from(rawKek)]); },
  unsealKey(blob) {
    if (unsealShouldThrow) throw new Error('TPM PCR mismatch (simulated hardware change)');
    if (!Buffer.isBuffer(blob) || !blob.slice(0, MAGIC.length).equals(MAGIC)) {
      throw new Error('sealed blob not recognized by this hardware');
    }
    return blob.slice(MAGIC.length);
  },
};
const origLoad = Module._load;
Module._load = function (request) {
  if (typeof request === 'string' && request.indexOf('hardware-keystore') !== -1) {
    return stubKeystore;
  }
  return origLoad.apply(this, arguments);
};

// --- mock db (Map-backed node_state, honoring the exact SQL shape used) -----
function mockDb() {
  const store = new Map();
  return {
    prepare() {
      return {
        run(key, value) { store.set(key, value); },
        get(key) { return store.has(key) ? { value: store.get(key) } : undefined; },
      };
    },
    _store: store,
  };
}

const KEK_LEN = 32;

function runServer(label, modulePath, ownKekEnvVar) {
  const kek = require(modulePath);
  const problems = [];
  const check = (name, cond) => { if (!cond) problems.push(`${label}: ${name}`); };

  // Provision a hardware-sealed own-KEK env value (ownKek unseals it via the stub).
  const setOwnKek = () => {
    process.env[ownKekEnvVar] =
      kek.SEAL_PREFIX + stubKeystore.sealKey(crypto.randomBytes(KEK_LEN)).toString('base64');
  };

  // 1. no adopted shared KEK -> boot reload is a no-op; sharedKek() == ownKek()
  kek._resetCacheForTests();
  setOwnKek();
  const db1 = mockDb();
  check('boot reload is a no-op with no adopted shared KEK', kek.loadSharedKekOnBoot(db1) === false);
  check('sharedKek() falls back to ownKek() when none adopted', kek.sharedKek().equals(kek.ownKek()));

  // 2. adopt -> persist + install
  const SHARED = crypto.randomBytes(KEK_LEN);
  kek._resetCacheForTests();
  setOwnKek();
  const db2 = mockDb();
  kek.adoptSharedKek(db2, SHARED);
  const wrapper = db2._store.get('shared_kek_sealed');
  check('adopt persists a hardware-sealed wrapper',
    typeof wrapper === 'string' && wrapper.indexOf(kek.SEAL_PREFIX) === 0);
  check('adopt installs the shared KEK (sharedKek == adopted)', kek.sharedKek().equals(SHARED));
  check('adopted shared KEK is distinct from ownKek', !kek.sharedKek().equals(kek.ownKek()));

  // 3. reboot -> reload restores the adopted KEK
  kek._resetCacheForTests();
  check('reload returns true when a shared KEK is present', kek.loadSharedKekOnBoot(db2) === true);
  check('after reload, sharedKek() == the adopted (former active) KEK', kek.sharedKek().equals(SHARED));

  // 4. fail-closed: present wrapper but unseal fails -> throws (no fallback)
  kek._resetCacheForTests();
  unsealShouldThrow = true;
  let threwUnseal = false;
  try { kek.loadSharedKekOnBoot(db2); } catch (e) { threwUnseal = /refusing to boot/.test(e.message); }
  check('fail-closed: unseal failure throws on boot (no ownKek fallback)', threwUnseal);
  unsealShouldThrow = false;

  // 5. fail-closed: a non-hardware-sealed wrapper -> throws
  kek._resetCacheForTests();
  const db5 = mockDb();
  db5._store.set('shared_kek_sealed', 'not-a-sealed-wrapper');
  let threwShape = false;
  try { kek.loadSharedKekOnBoot(db5); } catch (e) { threwShape = /not a hardware-sealed wrapper/.test(e.message); }
  check('fail-closed: a non-sealed wrapper throws', threwShape);

  kek._resetCacheForTests();
  return problems;
}

function main() {
  const servers = [
    ['MC tier1-kek', path.resolve(__dirname, '..', 'server', 'services', 'tier1-kek.js'), 'TIER1_ENCRYPTION_KEY'],
    ['GD gd-tier1-kek', path.resolve(__dirname, '..', 'packages', 'global-dashboard-server', 'services', 'gd-tier1-kek.js'), 'GD_ENCRYPTION_KEY'],
  ];
  let problems = [];
  for (const [label, p, envVar] of servers) {
    try {
      problems = problems.concat(runServer(label, p, envVar));
    } catch (e) {
      problems.push(`${label}: threw during the lifecycle test: ${e.message}`);
    }
  }
  if (problems.length) {
    console.error('Shared-KEK boot-reload regression FAILED:');
    for (const p of problems) console.error('  - ' + p);
    process.exit(1);
  }
  console.log('Shared-KEK boot-reload regression passed: adopt persists + installs, boot reloads, fail-closed on unseal (both servers).');
}

main();

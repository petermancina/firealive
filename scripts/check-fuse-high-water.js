#!/usr/bin/env node
'use strict';

// check-fuse-high-water.js
//
// Regression for the B6h A-8 anti-rollback fuse high-water on BOTH servers
// (fuse-high-water and gd-fuse-high-water). A-8 relocated the high-water from the
// replicating system_meta to the excluded node_state (node-local -- a standby must
// not inherit the active's mark) and added the GD's first boot-time fuse check.
//
// It runs in CI with the running build's fuse under test control (intercepting the
// fuse source -- the MC version module and the GD package.json) and node_state
// backed by a mock db. For each server it asserts:
//   1. fresh DB          -> no high-water -> checkAndAdvance seeds the current fuse,
//      no rollback;
//   2. same fuse         -> no rollback, no advance;
//   3. higher build      -> the high-water advances to the current fuse;
//   4. ROLLBACK          -> a build below the high-water returns rollback:true and
//      does NOT lower the high-water (the anti-rollback window stays closed);
//   5. readHighWater      -> reads node_state.
// Plus a source-level assertion that each module reads fuse_high_water from
// node_state (not system_meta), so a future edit cannot silently reintroduce the
// replicated read.

const fs = require('fs');
const path = require('path');
const Module = require('module');

// The running build's fuse, under test control. The MC version module and the GD
// package.json both expose fuseCounter; the interceptor returns a getter so a value
// captured at module load still reflects the current setting.
let FUSE = 75;
const origLoad = Module._load;
Module._load = function (request) {
  if (request === '../lib/version' || request === '../package.json') {
    return { get fuseCounter() { return FUSE; } };
  }
  return origLoad.apply(this, arguments);
};

function mockDb() {
  const m = new Map();
  return {
    prepare() {
      return {
        get: () => (m.has('fhw') ? { value: m.get('fhw') } : undefined),
        run: (v) => { m.set('fhw', String(v)); },
      };
    },
    _m: m,
  };
}

function runServer(label, modulePath) {
  const mod = require(modulePath);
  const problems = [];
  const check = (name, cond) => { if (!cond) problems.push(`${label}: ${name}`); };

  // source-level: the module must read fuse_high_water from node_state, not system_meta
  const src = fs.readFileSync(modulePath, 'utf8');
  check('reads fuse_high_water from node_state (source)',
    /FROM node_state WHERE key = 'fuse_high_water'/.test(src));
  check('does not read fuse_high_water from system_meta (source)',
    !/system_meta WHERE key = 'fuse_high_water'/.test(src));

  // 1. fresh -> seeds current, no rollback
  FUSE = 75;
  let db = mockDb();
  let v = mod.checkAndAdvance(db);
  check('fresh: no rollback, seeds current', !v.rollback && v.highWater === 75 && db._m.get('fhw') === '75');

  // 2. same fuse -> no advance
  v = mod.checkAndAdvance(db);
  check('same fuse: no rollback, no advance', !v.rollback && v.advanced === false);

  // 3. higher build -> advances
  FUSE = 80;
  v = mod.checkAndAdvance(db);
  check('higher build advances the high-water', !v.rollback && v.highWater === 80 && v.advanced === true && db._m.get('fhw') === '80');

  // 4. ROLLBACK -> verdict, does NOT lower the high-water
  FUSE = 78;
  v = mod.checkAndAdvance(db);
  check('rollback when fuse < high-water', v.rollback === true && v.currentFuse === 78 && v.highWater === 80 && v.advanced === false);
  check('rollback does not lower the high-water', db._m.get('fhw') === '80');

  // 5. readHighWater reads node_state
  check('readHighWater reads node_state', mod.readHighWater(db) === 80);

  return problems;
}

function main() {
  const servers = [
    ['MC fuse-high-water', path.resolve(__dirname, '..', 'server', 'services', 'fuse-high-water.js')],
    ['GD gd-fuse-high-water', path.resolve(__dirname, '..', 'packages', 'global-dashboard-server', 'services', 'gd-fuse-high-water.js')],
  ];
  let problems = [];
  for (const [label, p] of servers) {
    try {
      problems = problems.concat(runServer(label, p));
    } catch (e) {
      problems.push(`${label}: threw during the fuse test: ${e.message}`);
    }
  }
  if (problems.length) {
    console.error('Fuse high-water regression FAILED:');
    for (const p of problems) console.error('  - ' + p);
    process.exit(1);
  }
  console.log('Fuse high-water regression passed: node_state-backed, rollback detected without lowering the mark (both servers).');
}

main();

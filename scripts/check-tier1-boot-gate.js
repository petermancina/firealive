#!/usr/bin/env node
'use strict';

// check-tier1-boot-gate.js
//
// Regression for the B6h B-2 Tier-1 boot integrity gate on BOTH servers. The gate
// opens every chokepoint-sealed (class='tier1') Tier-1 column value under the KEK the
// node holds, so a wrong KEK, a partially-completed rekey, a relocated value, or
// corruption is caught at boot (fail-closed) rather than at first read.
//
// It stubs the seal module (openTier1 throws for values marked 'BAD') and the registry,
// drives the gate with a mock db, and asserts:
//   - all-good -> no failures;
//   - a bad value -> recorded;
//   - a never-promoted passive SKIPS replicated (its un-adopted data), but a passive
//     that has adopted a shared KEK, and an active/standalone, VERIFY replicated;
//   - tier1-derived (hardware-sealed) columns and not-yet-migrated tables are skipped.
// Plus source checks that both index.js boot hooks call the gate and fail closed.

const fs = require('fs');
const path = require('path');
const Module = require('module');

const REPO = path.resolve(__dirname, '..');
const problems = [];
const check = (name, cond) => { if (!cond) problems.push(name); };
const read = (rel) => { try { return fs.readFileSync(path.join(REPO, rel), 'utf8'); } catch (e) { return ''; } };

// A registry with a node-local tier1 column, a tier1-derived column (must be skipped),
// a replicated tier1 column, and a missing-table tier1 column (must be skipped).
const SAMPLE = [
  { table: 'audit_chain_signing_keys', column: 'private_key_encrypted', domain: 'node-local', class: 'tier1', shape: 'json', storage: 'buffer' },
  { table: 'ha_node', column: 'wrap_private_sealed', domain: 'node-local', class: 'tier1-derived', shape: 'utf8', storage: 'base64' },
  { table: 'integration_config', column: 'config_encrypted', domain: 'replicated', class: 'tier1', shape: 'json', storage: 'buffer' },
  { table: 'ghost_table', column: 'x', domain: 'node-local', class: 'tier1', shape: 'json', storage: 'buffer' },
];

const orig = Module._load;
Module._load = function (request) {
  if (request === './tier1-seal' || request === './gd-tier1-seal') {
    return { openTier1: function (ref, v) { if (String(v).indexOf('BAD') !== -1) throw new Error('KEK fingerprint mismatch'); return v; } };
  }
  if (request === './tier1-columns') return { TIER1_COLUMNS: SAMPLE };
  if (request === './gd-tier1-columns') return { GD_TIER1_COLUMNS: SAMPLE };
  return orig.apply(this, arguments);
};

function mockDb(opts) {
  const data = opts.data || {};
  const role = opts.role;
  const adopted = opts.adopted;
  const missing = opts.missing || ['ghost_table'];
  return {
    prepare: function (sql) {
      if (/FROM (ha_node|gd_ha_node)/.test(sql)) return { get: function () { return role === undefined ? undefined : { role: role }; } };
      if (/node_state WHERE key = 'shared_kek_sealed'/.test(sql)) return { get: function () { return adopted ? { x: 1 } : undefined; } };
      const m = sql.match(/FROM "([^"]+)"/);
      const tbl = m ? m[1] : null;
      if (missing.indexOf(tbl) !== -1) return { all: function () { throw new Error('no such table'); } };
      const vals = data[tbl] || [];
      return { all: function () { return vals.map(function (v, i) { return { rid: i + 1, val: v }; }); } };
    },
  };
}

function runModule(label, rel) {
  let gate;
  try {
    gate = require(path.join(REPO, rel));
  } catch (e) {
    problems.push(label + ': gate module failed to load: ' + e.message);
    return;
  }
  const N = { audit_chain_signing_keys: ['ok'], integration_config: ['ok'] };
  const good = mockDb({ role: 'standalone', data: N });
  check(label + ': all-good -> no failures', gate.verifyTier1Integrity(good).length === 0);

  const badLocal = mockDb({ role: 'standalone', data: { audit_chain_signing_keys: ['ok', 'BAD'], integration_config: ['ok'] } });
  const f1 = gate.verifyTier1Integrity(badLocal);
  check(label + ': a bad node-local value is recorded', f1.length === 1 && f1[0].column === 'audit_chain_signing_keys.private_key_encrypted');

  const badDerived = mockDb({ role: 'standalone', data: { ha_node: ['BAD'], audit_chain_signing_keys: ['ok'], integration_config: ['ok'] } });
  check(label + ': tier1-derived column is not verified', gate.verifyTier1Integrity(badDerived).length === 0);

  const passiveUnadopted = mockDb({ role: 'passive', adopted: false, data: { audit_chain_signing_keys: ['ok'], integration_config: ['BAD'] } });
  check(label + ': never-promoted passive skips replicated', gate.verifyTier1Integrity(passiveUnadopted).length === 0);
  check(label + ': skipsReplicated true for never-promoted passive', gate.skipsReplicated(passiveUnadopted) === true);

  const passiveAdopted = mockDb({ role: 'passive', adopted: true, data: { audit_chain_signing_keys: ['ok'], integration_config: ['BAD'] } });
  check(label + ': passive with adopted shared KEK verifies replicated', gate.verifyTier1Integrity(passiveAdopted).length === 1);

  const active = mockDb({ role: 'active', data: { audit_chain_signing_keys: ['ok'], integration_config: ['BAD'] } });
  check(label + ': active verifies replicated', gate.verifyTier1Integrity(active).length === 1);

  check(label + ': missing table is skipped', gate.verifyTier1Integrity(good).length === 0);
}

function sourceChecks() {
  const mc = read(path.join('server', 'index.js'));
  check('MC index.js calls the boot gate', /verifyTier1Integrity/.test(mc));
  check('MC index.js boot gate fails closed', /Tier-1 boot integrity gate FAILED[\s\S]{0,400}process\.exit\(1\)/.test(mc));
  const gd = read(path.join('packages', 'global-dashboard-server', 'index.js'));
  check('GD index.js calls the boot gate', /verifyTier1Integrity/.test(gd));
  check('GD index.js boot gate fails closed', /GD Tier-1 boot integrity gate FAILED[\s\S]{0,400}process\.exit\(1\)/.test(gd));
}

runModule('MC', path.join('server', 'services', 'tier1-boot-gate.js'));
runModule('GD', path.join('packages', 'global-dashboard-server', 'services', 'gd-tier1-boot-gate.js'));
sourceChecks();

if (problems.length) {
  console.error('Tier-1 boot integrity gate regression FAILED:');
  for (let i = 0; i < problems.length; i++) console.error('  - ' + problems[i]);
  process.exit(1);
}
console.log('Tier-1 boot integrity gate regression passed: full-value verification, domain-aware passive skip, fail-closed hooks (both servers).');

#!/usr/bin/env node
'use strict';

// check-deployment-mode-seal.js
//
// Regression for the B6h A-9 deployment-mode seal relocation, on BOTH servers
// (deployment-mode and gd-deployment-mode). A-9 moved the sealed, anchor-signed
// mode record from the replicating config to the excluded node_state (node-local --
// a standby must keep its own mode, not the active's replicated record, which is
// bound to the active's anchor and fails verification against the standby's), and
// added sealTampered() so promotion can refuse on a present-but-invalid seal.
//
// It runs in CI with a stubbed instance anchor (a real P-256 keypair, so a genuine
// record verifies) and a stubbed canonicalizer, plus a mock node_state db. For each
// module it asserts:
//   - source: readRecord and the write use node_state, not config;
//   - sealTampered(no record)   -> false  (bare-metal is not tampered);
//   - sealTampered(valid record)-> false  (a record that verifies is not tampered);
//   - sealTampered(garbage)     -> true   (present but does not verify -> tamper).
// Plus a tree-wide guard: no file under server/ or packages/ reads
// config.deployment_mode except the two init migrations (which copy the legacy
// value out and delete the row) -- the A-8.7 lesson applied preemptively.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Module = require('module');

// --- stub the anchor + canonicalizer ---------------------------------------
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const PUB_PEM = publicKey.export({ type: 'spki', format: 'pem' });
const IDENT = { instanceId: 'node-under-test', fingerprint: 'fp-under-test', publicKey: PUB_PEM };
const canon = (o) => JSON.stringify(o);

const origLoad = Module._load;
Module._load = function (request) {
  if (request === './instance-anchor' || request === './gd-instance-anchor') {
    return { load: () => IDENT, sign: () => Buffer.alloc(0) };
  }
  if (request === './report-signer' || request === './gd-report-signer') {
    return { canonicalize: canon };
  }
  return origLoad.apply(this, arguments);
};

function mockDb(recValue) {
  const m = new Map();
  if (recValue !== undefined) m.set('deployment_mode', recValue);
  return {
    prepare() {
      return {
        get: () => (m.has('deployment_mode') ? { value: m.get('deployment_mode') } : undefined),
        run: (v) => { m.set('deployment_mode', String(v)); },
      };
    },
  };
}

// A genuine record signed by the stub's private key over the exact signed payload
// the module verifies (mode + anchor binding + setAt, canonicalized).
function validRecord(mode) {
  const rec = {
    mode,
    instanceId: IDENT.instanceId,
    anchorFingerprint: IDENT.fingerprint,
    setAt: new Date().toISOString(),
  };
  const payload = Buffer.from(canon({
    mode: rec.mode,
    instanceId: rec.instanceId,
    anchorFingerprint: rec.anchorFingerprint,
    setAt: rec.setAt,
  }), 'utf8');
  rec.alg = 'ecdsa-p256-ieee-p1363';
  rec.signature = crypto.sign('sha256', payload, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
  return JSON.stringify(rec);
}

function runModule(label, modulePath) {
  const problems = [];
  const check = (name, cond) => { if (!cond) problems.push(`${label}: ${name}`); };

  const src = fs.readFileSync(modulePath, 'utf8');
  check('readRecord reads node_state (source)', /SELECT value FROM node_state WHERE key = \?/.test(src));
  check('the seal write targets node_state (source)', /INSERT OR REPLACE INTO node_state/.test(src));
  check('no config table read for the mode (source)', !/FROM config WHERE key = \?/.test(src) && !/INTO config \(/.test(src));

  const mod = require(modulePath);
  check('sealTampered(no record) is false (bare-metal)', mod.sealTampered(mockDb(undefined)) === false);
  check('sealTampered(valid record) is false', mod.sealTampered(mockDb(validRecord('virtualized'))) === false);
  check('sealTampered(garbage) is true', mod.sealTampered(mockDb('{"mode":"cloud","signature":"AAAA"}')) === true);
  // getMode returns the mode for a valid record, bare-metal for a tampered one
  check('getMode(valid) returns the sealed mode', mod.getMode(mockDb(validRecord('cloud'))) === mod.CLOUD);
  check('getMode(garbage) fails safe to bare-metal', mod.getMode(mockDb('{"mode":"cloud","signature":"AAAA"}')) === mod.BARE_METAL);

  return problems;
}

function treeWideConfigCheck() {
  const REPO = path.resolve(__dirname, '..');
  const ALLOWED = new Set([
    path.join('server', 'db', 'init.js'),
    path.join('packages', 'global-dashboard-server', 'db-init.js'),
  ]);
  const NEEDLE = "config WHERE key = 'deployment_mode'";
  const violations = [];
  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (!e.isFile() || !e.name.endsWith('.js')) continue;
      const rel = path.relative(REPO, full);
      if (ALLOWED.has(rel)) continue;
      let s;
      try { s = fs.readFileSync(full, 'utf8'); } catch { continue; }
      if (s.indexOf(NEEDLE) !== -1) {
        violations.push(rel + " reads config.deployment_mode -- the sealed mode lives in node_state (node-local, excluded from replication)");
      }
    }
  };
  for (const d of ['server', 'packages']) walk(path.join(REPO, d));
  return violations;
}

function main() {
  const modules = [
    ['MC deployment-mode', path.resolve(__dirname, '..', 'server', 'services', 'deployment-mode.js')],
    ['GD gd-deployment-mode', path.resolve(__dirname, '..', 'packages', 'global-dashboard-server', 'services', 'gd-deployment-mode.js')],
  ];
  let problems = treeWideConfigCheck();
  for (const [label, p] of modules) {
    try {
      problems = problems.concat(runModule(label, p));
    } catch (e) {
      problems.push(`${label}: threw during the seal test: ${e.message}`);
    }
  }
  if (problems.length) {
    console.error('Deployment-mode seal regression FAILED:');
    for (const p of problems) console.error('  - ' + p);
    process.exit(1);
  }
  console.log('Deployment-mode seal regression passed: node_state-backed, tamper detected, bare-metal fail-safe (both servers).');
}

main();

#!/usr/bin/env node
'use strict';

// check-macos-preflight.js -- regression for B6h B-7 (macOS named preflight error).
//
// For each of the four macOS Swift Secure Enclave backends: preflight() and the code
// MACOS_SWIFT_PREFLIGHT are exported; preflight() throws that named error (not a raw ENOENT) when
// the Swift toolchain cannot run or the bundled helper is not executable, with an actionable
// message. Runs on Linux CI, where the Swift toolchain is absent -- exactly the unavailable case.

const path = require('path');

const REPO = path.resolve(__dirname, '..');
const problems = [];
const check = (name, cond) => { if (!cond) problems.push(name); };

// [label, module path, swift-exe env var, custom-helper env var]
const BACKENDS = [
  ['server', 'server/services/instance-anchor/hardware-keystore-macos.js', 'FIREALIVE_SWIFT', 'FIREALIVE_SE_HELPER'],
  ['gd', 'packages/global-dashboard-server/services/gd-hardware-keystore-macos.js', 'FIREALIVE_GD_SWIFT', 'FIREALIVE_GD_SE_HELPER'],
  ['client-wrap', 'packages/shared/hardware-wrap-macos.js', 'FIREALIVE_CLIENT_SWIFT', 'FIREALIVE_CLIENT_SE_WRAP_HELPER'],
  ['client-key', 'packages/shared/hardware-key-macos.js', 'FIREALIVE_CLIENT_SWIFT', 'FIREALIVE_CLIENT_SE_HELPER'],
];

const ALL_HELPER_ENVS = BACKENDS.map((b) => b[3]);

BACKENDS.forEach(function (b) {
  const label = b[0];
  const swiftEnv = b[2];
  const helperEnv = b[3];
  const mod = require(path.join(REPO, b[1]));

  check(label + ': exports preflight', typeof mod.preflight === 'function');
  check(label + ': exports MACOS_SWIFT_PREFLIGHT', mod.MACOS_SWIFT_PREFLIGHT === 'MACOS_SWIFT_PREFLIGHT');

  // Case 1: Swift toolchain unavailable. Clear every custom-helper env so this backend takes the
  // swift path, and point its swift exe at a nonexistent command.
  const savedSwift = process.env[swiftEnv];
  const savedHelpers = {};
  ALL_HELPER_ENVS.forEach(function (h) { savedHelpers[h] = process.env[h]; delete process.env[h]; });
  process.env[swiftEnv] = '/nonexistent/fa-swift-preflight-xyz';
  let e1 = null;
  try { mod.preflight(); } catch (err) { e1 = err; }
  check(label + ': preflight throws when swift missing', e1 && e1.code === 'MACOS_SWIFT_PREFLIGHT');
  check(label + ': message names the fix', e1 && /bundled, signed helper binary/.test(e1.message));

  // Case 2: a bundled helper is configured but not executable.
  process.env[helperEnv] = '/nonexistent/fa-se-helper-xyz';
  let e2 = null;
  try { mod.preflight(); } catch (err) { e2 = err; }
  check(label + ': preflight throws when custom helper not executable', e2 && e2.code === 'MACOS_SWIFT_PREFLIGHT');

  // restore env
  if (savedSwift === undefined) { delete process.env[swiftEnv]; } else { process.env[swiftEnv] = savedSwift; }
  ALL_HELPER_ENVS.forEach(function (h) { if (savedHelpers[h] === undefined) { delete process.env[h]; } else { process.env[h] = savedHelpers[h]; } });
});

if (problems.length) {
  console.error('macos-preflight regression FAILED:');
  for (let i = 0; i < problems.length; i++) console.error('  - ' + problems[i]);
  process.exit(1);
}
console.log('macos-preflight regression passed: all four macOS Swift backends export preflight + MACOS_SWIFT_PREFLIGHT and raise the named, actionable error (not a raw ENOENT) when the Swift toolchain or the bundled helper is unavailable.');

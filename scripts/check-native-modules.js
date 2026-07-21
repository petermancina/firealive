#!/usr/bin/env node
'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// check-native-modules.js  --  the 21st gate  (pre-N2)
// ═══════════════════════════════════════════════════════════════════════════
//
// Guards the two native N-API addons the packaged apps depend on:
//
//   node-llama-cpp   -- GGUF inference (IR Simulator, burnout messages). Ships
//                       in the MC (via its embedded Regional Server) and the AC.
//   @mongodb-js/zstd -- tar+zstd compression of every encrypted backup archive
//                       (server/services/backup-archive.js:43). A SOC's restore
//                       path runs through it.
//
// WHY THIS EXISTS
//
// node-llama-cpp v3 does not compile from source; it resolves a PREBUILT,
// per-platform binary through optionalDependencies -- @node-llama-cpp/mac-x64,
// @node-llama-cpp/win-x64, @node-llama-cpp/linux-x64, and so on -- and npm
// installs only the one matching the host. If a Dependabot bump or a lockfile
// regeneration drops one platform's prebuilt from the lockfile, the app built
// for THAT platform ships with no loadable model binding, and the failure is
// silent until an analyst on that platform triggers inference. That is exactly
// the class of silent, platform-specific gap a source-level gate can close
// before a tag, and nothing checked it.
//
// This gate is DEPENDENCY-FREE (package.json + package-lock.json, Node
// built-ins), so it runs in the coverage job on every pull request. It proves
// the lockfile CONTAINS a prebuilt for every platform the app actually ships to.
// It does NOT prove the prebuilt loads -- that is check-native-modules' runtime
// companion, scripts/probe-native-modules.js, run in the smoke job. Presence is
// necessary; the probe adds sufficient.
//
// @mongodb-js/zstd is a single package that fetches its per-platform prebuilt at
// install time via prebuild-install, so the lockfile cannot show per-platform
// completeness for it. Here the gate asserts it is declared everywhere it is
// used, pinned consistently, and still carries prebuild-install (its fetch
// mechanism); the probe is what proves it loads and round-trips.
//
// ── INVARIANTS ────────────────────────────────────────────────────────────
//
//  A. node-llama-cpp is declared at the SAME version across every manifest that
//     uses it (root, server, analyst-client). A skew ships two llama versions
//     into interoperating code.
//  B. For every (platform, arch) the node-llama-cpp-shipping apps build -- the
//     MC (frontend, via the embedded server) and the AC (analyst-client) --
//     the matching @node-llama-cpp/<platform> prebuilt is present in the
//     lockfile, at node-llama-cpp's own version. The required set is DERIVED
//     from those apps' electron-builder targets, so adding a build arch updates
//     what the gate demands.
//  C. @mongodb-js/zstd is declared in root and server at the same version,
//     present in the lockfile, and still depends on prebuild-install.
//
// Run with --self-test to drive the detector against synthetic inputs that
// plant a dropped prebuilt, a version skew, and a broken zstd, and prove red.
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

const REPO = path.resolve(__dirname, '..');

// manifests that DECLARE node-llama-cpp (its consumers)
const LLAMA_MANIFESTS = ['package.json', 'server/package.json', 'packages/analyst-client/package.json'];
// manifests that DECLARE @mongodb-js/zstd (root + the embedded Regional Server, which runs backup-archive.js)
const ZSTD_MANIFESTS = ['package.json', 'server/package.json'];
// app packages whose electron-builder output SHIPS node-llama-cpp (MC via embedded server; AC directly)
const LLAMA_SHIPPING_APPS = ['frontend', 'packages/analyst-client'];

// electron-builder osKey -> node process.platform
const OS_OF = { mac: 'darwin', win: 'win32', linux: 'linux' };
// (platform, arch) -> the @node-llama-cpp prebuilt package basename it needs
function llamaPrebuiltFor(platform, arch) {
  const table = {
    'darwin/arm64': 'mac-arm64-metal',
    'darwin/x64': 'mac-x64',
    'win32/x64': 'win-x64',
    'win32/arm64': 'win-arm64',
    'linux/x64': 'linux-x64',
    'linux/arm64': 'linux-arm64',
    'linux/armv7l': 'linux-armv7l',
    'linux/arm': 'linux-armv7l',
  };
  return table[platform + '/' + arch] || null;
}

function depSpec(pkg, name) {
  return (pkg.dependencies && pkg.dependencies[name])
    || (pkg.devDependencies && pkg.devDependencies[name])
    || (pkg.optionalDependencies && pkg.optionalDependencies[name])
    || null;
}

// Derive the (platform, arch) pairs the node-llama-cpp-shipping apps build for.
function requiredLlamaTargets(appBuildConfigs) {
  const targets = new Set();
  for (const dir of LLAMA_SHIPPING_APPS) {
    const build = appBuildConfigs[dir];
    if (!build) continue;
    for (const osKey of ['mac', 'win', 'linux']) {
      const osCfg = build[osKey];
      if (!osCfg || !osCfg.target) continue;
      const platform = OS_OF[osKey];
      const tlist = Array.isArray(osCfg.target) ? osCfg.target : [osCfg.target];
      for (const t of tlist) {
        const arches = (typeof t === 'object' && t.arch) ? (Array.isArray(t.arch) ? t.arch : [t.arch]) : ['x64'];
        for (const a of arches) targets.add(platform + '\t' + a);
      }
    }
  }
  return [...targets].map((s) => { const [p, a] = s.split('\t'); return { platform: p, arch: a }; });
}

// ── core checker: manifests {relpath: pkgObj}, lock {packages}, appBuildConfigs {dir: build} ──
function checkNativeModules(manifests, lock, appBuildConfigs) {
  const problems = [];
  const lp = (lock && lock.packages) || {};

  // ── A. node-llama-cpp version consistency across its manifests
  const llamaSpecs = {};
  for (const m of LLAMA_MANIFESTS) {
    const pkg = manifests[m];
    if (!pkg) { problems.push('manifest missing: ' + m); continue; }
    const spec = depSpec(pkg, 'node-llama-cpp');
    if (!spec) { problems.push(m + ': does not declare node-llama-cpp (its consumer must pin it)'); continue; }
    llamaSpecs[m] = spec;
  }
  const distinctLlama = [...new Set(Object.values(llamaSpecs))];
  if (distinctLlama.length > 1) {
    problems.push('node-llama-cpp version skew across manifests: '
      + Object.entries(llamaSpecs).map(([m, s]) => m + '=' + s).join(', ')
      + ' -- interoperating code must ship one llama version');
  }

  // resolved node-llama-cpp version from the lockfile
  const llamaLock = lp['node_modules/node-llama-cpp'];
  const llamaVersion = llamaLock && llamaLock.version;
  if (!llamaVersion) {
    problems.push('lockfile: node-llama-cpp is not resolved (node_modules/node-llama-cpp missing)');
  }

  // ── B. per-platform prebuilt presence, derived from the shipping apps' targets
  const required = requiredLlamaTargets(appBuildConfigs);
  if (required.length === 0) {
    problems.push('no build targets found for the node-llama-cpp-shipping apps (' + LLAMA_SHIPPING_APPS.join(', ') + ') -- cannot derive the required prebuilt set');
  }
  const seenPrebuilt = new Set();
  for (const { platform, arch } of required) {
    const base = llamaPrebuiltFor(platform, arch);
    if (!base) { problems.push('no @node-llama-cpp prebuilt known for ' + platform + '/' + arch + ' -- add it to llamaPrebuiltFor()'); continue; }
    if (seenPrebuilt.has(base)) continue;
    seenPrebuilt.add(base);
    const key = 'node_modules/@node-llama-cpp/' + base;
    const entry = lp[key];
    if (!entry) {
      problems.push('lockfile: MISSING @node-llama-cpp/' + base + ' -- the ' + platform + '/' + arch
        + ' app would ship with no loadable model binding');
      continue;
    }
    if (llamaVersion && entry.version !== llamaVersion) {
      problems.push('lockfile: @node-llama-cpp/' + base + ' is ' + entry.version
        + ' but node-llama-cpp is ' + llamaVersion + ' -- prebuilt and loader must match');
    }
  }

  // ── C. @mongodb-js/zstd declaration + mechanism
  const zstdSpecs = {};
  for (const m of ZSTD_MANIFESTS) {
    const pkg = manifests[m];
    if (!pkg) continue; // already reported above if truly missing
    const spec = depSpec(pkg, '@mongodb-js/zstd');
    if (!spec) { problems.push(m + ': does not declare @mongodb-js/zstd (backup-archive.js requires it)'); continue; }
    zstdSpecs[m] = spec;
  }
  const distinctZstd = [...new Set(Object.values(zstdSpecs))];
  if (distinctZstd.length > 1) {
    problems.push('@mongodb-js/zstd version skew: ' + Object.entries(zstdSpecs).map(([m, s]) => m + '=' + s).join(', '));
  }
  const zstdLock = lp['node_modules/@mongodb-js/zstd'];
  if (!zstdLock) {
    problems.push('lockfile: @mongodb-js/zstd is not resolved');
  } else if (!(zstdLock.dependencies && zstdLock.dependencies['prebuild-install'])) {
    problems.push('lockfile: @mongodb-js/zstd no longer depends on prebuild-install -- its per-platform prebuilt fetch mechanism is gone; a source build would need a toolchain on every build runner');
  }

  return problems;
}

// ── self-test ─────────────────────────────────────────────────────────────
function selfTest() {
  const V = '3.19.0';
  const goodManifests = () => ({
    'package.json': { dependencies: { 'node-llama-cpp': '^' + V, '@mongodb-js/zstd': '^7.0.0' } },
    'server/package.json': { dependencies: { 'node-llama-cpp': '^' + V, '@mongodb-js/zstd': '^7.0.0' } },
    'packages/analyst-client/package.json': { dependencies: { 'node-llama-cpp': '^' + V } },
  });
  const goodLock = () => ({
    packages: {
      'node_modules/node-llama-cpp': { version: V },
      'node_modules/@node-llama-cpp/mac-arm64-metal': { version: V },
      'node_modules/@node-llama-cpp/mac-x64': { version: V },
      'node_modules/@node-llama-cpp/win-x64': { version: V },
      'node_modules/@node-llama-cpp/linux-x64': { version: V },
      'node_modules/@node-llama-cpp/linux-arm64': { version: V },
      'node_modules/@mongodb-js/zstd': { version: '7.0.0', dependencies: { 'prebuild-install': '^7.1.3', 'node-addon-api': '^8.5.0' } },
    },
  });
  // frontend: mac[arm64,x64] win[x64] linux[x64]; AC: adds linux[arm64]
  const goodConfigs = () => ({
    'frontend': { mac: { target: [{ target: 'dmg', arch: ['arm64', 'x64'] }] }, win: { target: [{ target: 'nsis', arch: ['x64'] }] }, linux: { target: [{ target: 'AppImage', arch: ['x64'] }] } },
    'packages/analyst-client': { mac: { target: [{ target: 'dmg', arch: ['arm64', 'x64'] }] }, win: { target: [{ target: 'nsis', arch: ['x64'] }] }, linux: { target: [{ target: 'AppImage', arch: ['x64', 'arm64'] }] } },
  });

  const cases = [];
  const add = (name, mutate, wantSubstr) => {
    const m = goodManifests(), l = goodLock(), c = goodConfigs();
    if (mutate) mutate(m, l, c);
    cases.push({ name, m, l, c, wantSubstr });
  };

  add('good inputs -> no problems', null, null);
  add('dropped mac-x64 prebuilt', (m, l) => { delete l.packages['node_modules/@node-llama-cpp/mac-x64']; }, 'MISSING @node-llama-cpp/mac-x64');
  add('dropped linux-arm64 (AC ships it)', (m, l) => { delete l.packages['node_modules/@node-llama-cpp/linux-arm64']; }, 'MISSING @node-llama-cpp/linux-arm64');
  add('llama version skew across manifests', (m) => { m['packages/analyst-client/package.json'].dependencies['node-llama-cpp'] = '^3.18.0'; }, 'version skew');
  add('prebuilt version != loader version', (m, l) => { l.packages['node_modules/@node-llama-cpp/win-x64'].version = '3.18.0'; }, 'must match');
  add('zstd not declared in server', (m) => { delete m['server/package.json'].dependencies['@mongodb-js/zstd']; }, 'does not declare @mongodb-js/zstd');
  add('zstd lost prebuild-install', (m, l) => { delete l.packages['node_modules/@mongodb-js/zstd'].dependencies['prebuild-install']; }, 'prebuild-install');
  add('node-llama-cpp unresolved in lockfile', (m, l) => { delete l.packages['node_modules/node-llama-cpp']; }, 'not resolved');

  let bad = 0;
  for (const cse of cases) {
    const problems = checkNativeModules(cse.m, cse.l, cse.c);
    let ok;
    if (cse.wantSubstr === null) {
      ok = problems.length === 0;
      if (!ok) console.error('  FAIL  ' + cse.name + '\n        expected NO problems, got:\n        - ' + problems.join('\n        - '));
    } else {
      ok = problems.some((p) => p.includes(cse.wantSubstr));
      if (!ok) console.error('  FAIL  ' + cse.name + '\n        expected a problem containing ' + JSON.stringify(cse.wantSubstr) + ', got:\n        - ' + (problems.join('\n        - ') || '(none)'));
    }
    if (ok) console.log('  ok    ' + cse.name); else bad++;
  }
  if (bad) { console.error('\nnative-modules self-test FAILED: ' + bad + ' of ' + cases.length + ' cases.'); process.exit(1); }
  console.log('\nnative-modules self-test passed (' + cases.length + ' cases: dropped prebuilt (x2), version skew, prebuilt/loader mismatch, zstd declaration, zstd mechanism, unresolved loader).');
}

if (process.argv.includes('--self-test')) {
  selfTest();
} else {
  const readJson = (rel) => { try { return JSON.parse(fs.readFileSync(path.join(REPO, rel), 'utf8')); } catch (e) { return null; } };
  const manifests = {};
  for (const m of new Set([].concat(LLAMA_MANIFESTS, ZSTD_MANIFESTS))) manifests[m] = readJson(m);
  const lock = readJson('package-lock.json');
  const appBuildConfigs = {};
  for (const dir of LLAMA_SHIPPING_APPS) { const p = readJson(path.join(dir, 'package.json')); appBuildConfigs[dir] = p && p.build; }
  if (!lock) { console.error('check-native-modules FAILED: package-lock.json not found or unreadable'); process.exit(1); }
  const problems = checkNativeModules(manifests, lock, appBuildConfigs);
  if (problems.length) {
    console.error('check-native-modules FAILED (' + problems.length + '):\n');
    for (const p of problems) console.error('  - ' + p);
    console.error('');
    process.exit(1);
  }
  console.log('check-native-modules passed: node-llama-cpp pinned consistently with a lockfile prebuilt for every shipped platform, '
    + '@mongodb-js/zstd declared and prebuild-install intact.');
}

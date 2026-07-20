#!/usr/bin/env node
'use strict';

// check-integrity.js
//
// Regression for the P1-6 code-integrity checks, on BOTH servers
// (server/services/integrity.js and
// packages/global-dashboard-server/services/gd-integrity.js).
//
// FATAL 5a was a Regional check that never ran in the packaged app (its manifest
// shipped at the repo-root config/, which extraResources did not copy) and that
// treated a MISSING manifest -- an attacker's first move -- as a silent pass
// rather than a halt. FATAL 5b was worse: the GD server had no code-integrity
// check at all. This gate is the assertion that would have caught both.
//
// It exercises each real module inside an isolated temp sandbox (a fake server
// tree copied module + version stub), so nothing in the working tree is touched.
// For each module it asserts:
//   - the module exists and exports { verifyIntegrity, generateManifest }
//     (the assertion that would have caught 5b: the GD check missing entirely);
//   - generateManifest() writes a manifest that covers index.js and EVERY
//     directory the module declares in SCAN_DIRS (no scanned dir silently
//     uncovered);
//   - a clean tree verifies (valid: true);
//   - a MODIFIED scanned file is detected as a violation (valid: false, a
//     MODIFIED entry present) -- the boot gate halts a production boot on this;
//   - a MISSING manifest returns { valid: false, violations: [], error: <set> }
//     -- the exact shape the fail-closed boot gate halts a production boot on.

const fs = require('fs');
const path = require('path');
const os = require('os');

const REPO = path.resolve(__dirname, '..');

// [label, real module path, server-root-relative dir, version-stub relative path,
//  how the version stub is written]
const MODULES = [
  {
    label: 'MC Regional integrity',
    modPath: path.join(REPO, 'server', 'services', 'integrity.js'),
    rootRel: 'server',
    // integrity.js does: const { version } = require('../lib/version')
    versionStub: { rel: path.join('lib', 'version.js'), body: "module.exports = { version: '0.0.0-test', fuseCounter: 0, buildId: 'test' };\n" },
  },
  {
    label: 'GD gd-integrity',
    modPath: path.join(REPO, 'packages', 'global-dashboard-server', 'services', 'gd-integrity.js'),
    rootRel: 'packages/global-dashboard-server',
    // gd-integrity.js does: const { version } = require('../package.json')
    versionStub: { rel: 'package.json', body: JSON.stringify({ name: 'gd-test', version: '0.0.0-test', fuseCounter: 0, buildId: 'test' }, null, 2) + '\n' },
  },
];

// Pull the declared SCAN_DIRS (and ROOT_FILES, if the module declares them) out
// of the module source, so the "covers every scanned directory" assertion tracks
// whatever the module actually claims to scan rather than a hardcoded copy.
function declaredArray(src, name) {
  const m = src.match(new RegExp('const\\s+' + name + '\\s*=\\s*\\[([^\\]]*)\\]'));
  if (!m) return null;
  return m[1].split(',').map(s => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
}

function runModule(mod) {
  const problems = [];
  const src = fs.readFileSync(mod.modPath, 'utf8');
  const scanDirs = declaredArray(src, 'SCAN_DIRS');
  if (!scanDirs || scanDirs.length === 0) {
    problems.push(`${mod.label}: could not find a non-empty SCAN_DIRS in ${path.basename(mod.modPath)}`);
    return problems;
  }
  const rootFiles = declaredArray(src, 'ROOT_FILES') || ['index.js'];
  // P1-6: pinned data trust anchors (fido-attestation-roots.json). A regression
  // that drops DATA_FILES coverage would leave the attestation roots swappable.
  const dataFiles = declaredArray(src, 'DATA_FILES') || [];

  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'check-integrity-'));
  try {
    const serverRoot = path.join(sandbox, mod.rootRel);
    const servicesDir = path.join(serverRoot, 'services');
    fs.mkdirSync(servicesDir, { recursive: true });

    // Copy the real module into the sandbox at the same relative location.
    const sandboxMod = path.join(servicesDir, path.basename(mod.modPath));
    fs.copyFileSync(mod.modPath, sandboxMod);

    // Write the version stub the module requires.
    const stubPath = path.join(serverRoot, mod.versionStub.rel);
    fs.mkdirSync(path.dirname(stubPath), { recursive: true });
    fs.writeFileSync(stubPath, mod.versionStub.body);

    // Fake top-level code files.
    for (const f of rootFiles) fs.writeFileSync(path.join(serverRoot, f), `// ${f}\n`);
    // A fake .js in each declared scanned directory (skip 'services' -- the
    // copied module already lives there and is itself covered).
    for (const d of scanDirs) {
      const dir = path.join(serverRoot, d);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'sample.js'), `// ${d}/sample.js\n`);
    }
    // A fake pinned data trust anchor for each declared DATA_FILE.
    if (dataFiles.length) {
      fs.mkdirSync(path.join(serverRoot, 'data'), { recursive: true });
      for (const f of dataFiles) fs.writeFileSync(path.join(serverRoot, 'data', f), '{"_comment":"sandbox trust anchor"}\n');
    }

    const api = require(sandboxMod);
    if (typeof api.verifyIntegrity !== 'function' || typeof api.generateManifest !== 'function') {
      problems.push(`${mod.label}: module does not export { verifyIntegrity, generateManifest }`);
      return problems;
    }

    // 1. generate -> manifest covers index.js and every scanned dir.
    const manifest = api.generateManifest();
    const keys = Object.keys(manifest.files);
    const prefix = mod.rootRel.split('/').pop(); // 'server' or 'global-dashboard-server'
    if (!keys.some(k => k === `${prefix}/index.js`)) {
      problems.push(`${mod.label}: manifest does not cover ${prefix}/index.js`);
    }
    for (const d of scanDirs) {
      if (!keys.some(k => k.startsWith(`${prefix}/${d}/`))) {
        problems.push(`${mod.label}: manifest does not cover scanned directory '${d}'`);
      }
    }
    for (const f of dataFiles) {
      if (!keys.some(k => k === `${prefix}/data/${f}`)) {
        problems.push(`${mod.label}: manifest does not cover pinned data trust anchor '${f}' (attestation roots would be swappable)`);
      }
    }

    // 2. clean verify -> valid.
    const clean = api.verifyIntegrity();
    if (!clean.valid) problems.push(`${mod.label}: a clean tree did not verify (valid=false): ${JSON.stringify(clean.violations)}`);

    // 3. modified file -> a MODIFIED violation, valid false.
    const victim = path.join(serverRoot, scanDirs[0], 'sample.js');
    fs.appendFileSync(victim, '// tampered\n');
    const tampered = api.verifyIntegrity();
    if (tampered.valid) problems.push(`${mod.label}: a modified file was NOT detected (valid=true)`);
    if (!tampered.violations.some(v => v.type === 'MODIFIED')) {
      problems.push(`${mod.label}: modified file did not produce a MODIFIED violation: ${JSON.stringify(tampered.violations)}`);
    }
    fs.writeFileSync(victim, `// ${scanDirs[0]}/sample.js\n`); // restore for the next step

    // 4. missing manifest -> valid:false, violations empty, error set
    //    (the exact shape the fail-closed boot gate halts a production boot on).
    // Find the manifest that generate() wrote (server root, *.json) and remove it.
    const manifestFile = fs.readdirSync(serverRoot).find(f => f.endsWith('integrity-manifest.json'));
    if (!manifestFile) {
      problems.push(`${mod.label}: generateManifest did not write a manifest at the server root`);
    } else {
      fs.unlinkSync(path.join(serverRoot, manifestFile));
      const missing = api.verifyIntegrity();
      if (missing.valid) problems.push(`${mod.label}: a MISSING manifest returned valid=true (fail-open!)`);
      if (missing.violations.length !== 0) problems.push(`${mod.label}: a MISSING manifest returned non-empty violations (should be empty + error)`);
      if (!missing.error) problems.push(`${mod.label}: a MISSING manifest did not set an error string`);
    }
  } finally {
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
  return problems;
}

function main() {
  let problems = [];

  // Static presence check against the REAL modules (the 5b catch: the GD module
  // missing or not exporting the check would fail here even before the sandbox).
  for (const mod of MODULES) {
    if (!fs.existsSync(mod.modPath)) {
      problems.push(`${mod.label}: module file is missing: ${path.relative(REPO, mod.modPath)}`);
      continue;
    }
    let real;
    try { real = require(mod.modPath); } catch (e) { problems.push(`${mod.label}: module failed to load: ${e.message}`); continue; }
    if (typeof real.verifyIntegrity !== 'function' || typeof real.generateManifest !== 'function') {
      problems.push(`${mod.label}: real module does not export { verifyIntegrity, generateManifest }`);
    }
  }

  for (const mod of MODULES) {
    if (!fs.existsSync(mod.modPath)) continue;
    try {
      problems = problems.concat(runModule(mod));
    } catch (e) {
      problems.push(`${mod.label}: threw during the integrity test: ${e.message}`);
    }
  }

  if (problems.length) {
    console.error('Integrity regression FAILED:');
    for (const p of problems) console.error('  - ' + p);
    process.exit(1);
  }
  console.log('Integrity regression passed: both servers export the check, the manifest covers index.js, every scanned directory, and the pinned data trust anchors (FIDO attestation roots), a modified file is detected, and a missing manifest is fail-closed (valid:false, empty violations, error set).');
}

main();

#!/usr/bin/env node
'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// check-workflow-validity.js  --  the 20th gate  (pre-N2)
// ═══════════════════════════════════════════════════════════════════════════
//
// Makes the release pipeline's own correctness a checked invariant instead of a
// thing verified by hand.
//
// WHY THIS EXISTS
//
// The v1.0.85 (P1) release did not publish on the first attempt. The release
// job listed `**/*.zip` in action-gh-release's `files:` while NO build target
// emits a zip -- every app builds dmg (mac), nsis -> .exe (win), and AppImage
// (linux) -- and `fail_on_unmatched_files: true` (correctly) turns an unmatched
// pattern into a hard failure. A pattern that can never match is the same class
// of defect as a green check that cannot go red: it looks like coverage and is
// not. Nothing checked that every `files:` glob corresponds to something the
// build actually produces, so the phantom rode to the tag.
//
// The same investigation (PACKAGING-PREFLIGHT-FINDINGS, G1/G2) had already found
// two structural holes in this workflow that were fixed in P1 and must not
// regress: `release` did not `needs: coverage` (so a red gate published anyway),
// and no workflow ran on a pull request (so nothing gated a merge). This gate
// pins both fixes in place.
//
// WHAT THIS IS AND IS NOT
//
// The coverage job is dependency-free by design -- it runs these scripts with
// no `npm install`, on Node built-ins only -- so this gate does TARGETED
// STRUCTURAL EXTRACTION of the specific semantic invariants below, not a full
// YAML parse. That division is deliberate: a pure YAML *syntax* error is already
// caught, because GitHub refuses to load an invalid workflow and the run errors
// out. What GitHub does NOT check is whether a `files:` glob is producible,
// whether `release` still needs its gates, or whether a PR still triggers CI --
// and those are exactly the holes that shipped. This gate targets what GitHub
// cannot. (A fuller schema lint -- actionlint -- is a reasonable future layer,
// but it is a downloaded Go binary, i.e. added supply-chain surface, and it does
// not know electron-builder's outputs, so it would not have caught the phantom.)
//
// On a pull request that edits build.yml, GitHub runs the EDITED workflow, so
// this step validates the edited file: a semantic break is caught here, a
// syntax break is caught by the workflow failing to load. Either way the bad
// change cannot reach main silently.
//
// ── INVARIANTS ────────────────────────────────────────────────────────────
//
//  A. Both workflow files exist, are non-empty, and contain no literal TAB
//     (YAML forbids tabs for indentation; a tab is a common paste corruption
//     that changes the parse).
//  B. build.yml triggers on `pull_request` (the G2 fix: gate the merge).
//  C. The `release` job `needs:` includes coverage, smoke, and posture-windows
//     (the G1 fix: a red gate withholds the release).
//  D. The release step sets `fail_on_unmatched_files: true` (a phantom glob
//     fails loud instead of publishing an empty release).
//  E. Every glob in the release `files:` list is PRODUCIBLE -- its extension is
//     one an electron-builder target in some app's package.json actually emits.
//     The producible set is DERIVED from the three app build configs, not
//     hardcoded, so changing a target (e.g. adding a zip target) updates what
//     the gate accepts. This is the invariant the phantom `.zip` violated.
//  F. regenerate-lockfile.yml stays `workflow_dispatch`-triggered and does NOT
//     gain a `push:` trigger (a lockfile-regen job firing on every push, then
//     committing, is a footgun).
//
// Run with --self-test to drive the detector against synthetic workflows that
// plant each defect above and prove it goes red.
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

const REPO = path.resolve(__dirname, '..');
const WF_DIR = path.join(REPO, '.github', 'workflows');
const BUILD_YML = path.join(WF_DIR, 'build.yml');
const LOCKFILE_YML = path.join(WF_DIR, 'regenerate-lockfile.yml');

// electron-builder target name -> the file extension it emits. Only the targets
// this project could use need to be exhaustive; unknown targets are reported so
// a new one is a deliberate addition here, not a silent gap.
const TARGET_EXT = {
  dmg: 'dmg', nsis: 'exe', nsisweb: 'exe', portable: 'exe', msi: 'msi',
  appimage: 'AppImage', deb: 'deb', rpm: 'rpm', snap: 'snap', freebsd: 'freebsd',
  pacman: 'pacman', p5p: 'p5p', apk: 'apk', zip: 'zip', tar_gz: 'tar.gz',
  tar_xz: 'tar.xz', tar_lz4: 'tar.lz4', tar_bz2: 'tar.bz2', dir: null,
  pkg: 'pkg', mas: 'app', 'mas-dev': 'app',
};

const APP_DIRS = [
  'frontend',
  path.join('packages', 'analyst-client'),
  path.join('packages', 'global-dashboard'),
];

function leadingSpaces(line) {
  let n = 0;
  while (n < line.length && line[n] === ' ') n++;
  return n;
}

// Slice the lines belonging to a top-level `on:` / job block: from the anchor
// line to the next line whose indentation is <= the anchor's (a sibling or
// dedent), skipping blanks and comments when deciding the boundary.
function blockAfter(lines, startIdx) {
  const baseIndent = leadingSpaces(lines[startIdx]);
  const out = [lines[startIdx]];
  for (let i = startIdx + 1; i < lines.length; i++) {
    const ln = lines[i];
    if (ln.trim() === '' || ln.trim().startsWith('#')) { out.push(ln); continue; }
    if (leadingSpaces(ln) <= baseIndent) break;
    out.push(ln);
  }
  return out;
}

function findLineIdx(lines, re) {
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return i;
  return -1;
}

// Derive the set of file extensions the electron-builder configs can emit.
function producibleExtensions(readJson) {
  const exts = new Set();
  const unknownTargets = [];
  for (const dir of APP_DIRS) {
    let pkg;
    try { pkg = readJson(path.join(REPO, dir, 'package.json')); }
    catch (e) { continue; }
    const build = pkg.build || {};
    for (const osKey of ['mac', 'win', 'linux']) {
      const osCfg = build[osKey];
      if (!osCfg || !osCfg.target) continue;
      const targets = Array.isArray(osCfg.target) ? osCfg.target : [osCfg.target];
      for (const t of targets) {
        const name = (typeof t === 'string' ? t : t.target || '').toLowerCase();
        if (!name) continue;
        if (!(name in TARGET_EXT)) { unknownTargets.push(dir + ' ' + osKey + ' -> ' + name); continue; }
        const ext = TARGET_EXT[name];
        if (ext) exts.add(ext.toLowerCase());
      }
    }
  }
  return { exts, unknownTargets };
}

// The extension of a release glob like `**/*.AppImage` or `**/*.dmg`.
function globExtension(glob) {
  const g = glob.trim();
  const dot = g.lastIndexOf('.');
  if (dot < 0) return '';
  return g.slice(dot + 1).toLowerCase();
}

// ── the core checker: takes the two file bodies + a package.json reader, returns problems[] ──
function checkWorkflows(buildYml, lockfileYml, readJson) {
  const problems = [];

  // A. tabs / non-empty
  for (const [name, body] of [['build.yml', buildYml], ['regenerate-lockfile.yml', lockfileYml]]) {
    if (body == null) { problems.push(name + ': missing'); continue; }
    if (body.trim() === '') { problems.push(name + ': empty'); continue; }
    if (body.indexOf('\t') !== -1) {
      const ln = body.slice(0, body.indexOf('\t')).split('\n').length;
      problems.push(name + ': contains a literal TAB (line ' + ln + ') -- YAML indentation must be spaces');
    }
  }
  if (buildYml == null) return problems; // nothing further checkable

  const lines = buildYml.split('\n');

  // locate the top-level `on:` block and the `release:` job
  const onIdx = findLineIdx(lines, /^on:\s*$/);
  if (onIdx < 0) { problems.push('build.yml: no top-level `on:` block found'); }
  const relIdx = findLineIdx(lines, /^  release:\s*$/);
  if (relIdx < 0) { problems.push('build.yml: no `release:` job found'); }

  // B. pull_request trigger
  if (onIdx >= 0) {
    const onBlock = blockAfter(lines, onIdx);
    if (!onBlock.some((l) => /^\s+pull_request:\s*$/.test(l) || /^\s+pull_request:\s/.test(l))) {
      problems.push('build.yml: `on:` has no `pull_request:` trigger -- nothing would gate a pull request (G2)');
    }
  }

  if (relIdx >= 0) {
    const rel = blockAfter(lines, relIdx);
    const relText = rel.join('\n');

    // C. release needs its gates
    const needsLine = rel.find((l) => /^\s+needs:\s*\[/.test(l));
    if (!needsLine) {
      problems.push('build.yml release: no inline `needs: [...]` found');
    } else {
      const inside = needsLine.slice(needsLine.indexOf('[') + 1, needsLine.lastIndexOf(']'));
      const needs = inside.split(',').map((s) => s.trim()).filter(Boolean);
      for (const required of ['coverage', 'smoke', 'posture-windows']) {
        if (!needs.includes(required)) {
          problems.push('build.yml release: `needs` is missing `' + required + '` -- a red gate could publish a release (G1)');
        }
      }
    }

    // D. fail_on_unmatched_files: true
    if (!/^\s+fail_on_unmatched_files:\s*true\s*$/m.test(relText)) {
      problems.push('build.yml release: `fail_on_unmatched_files: true` is not set -- a phantom glob would publish an empty release silently');
    }

    // E. every files: glob is producible
    const filesIdx = rel.findIndex((l) => /^\s+files:\s*\|\s*$/.test(l));
    if (filesIdx < 0) {
      // `files:` could be inline or a folded list; if we cannot find the block form, say so
      if (!/^\s+files:\s*/m.test(relText)) {
        problems.push('build.yml release: no `files:` list found on the release step');
      }
    } else {
      const filesIndent = leadingSpaces(rel[filesIdx]);
      const globs = [];
      for (let i = filesIdx + 1; i < rel.length; i++) {
        const ln = rel[i];
        if (ln.trim() === '') continue;
        if (leadingSpaces(ln) <= filesIndent) break; // dedent -> block ended
        const t = ln.trim();
        if (t.startsWith('#')) continue;
        globs.push(t);
      }
      const { exts, unknownTargets } = producibleExtensions(readJson);
      for (const u of unknownTargets) {
        problems.push('build.yml: electron-builder target not recognized by this gate (' + u + ') -- add it to TARGET_EXT so its output is checkable');
      }
      if (globs.length === 0) {
        problems.push('build.yml release: `files: |` block is empty');
      }
      for (const g of globs) {
        const ext = globExtension(g);
        if (!ext) { problems.push('build.yml release: files entry has no extension to check: ' + g); continue; }
        if (!exts.has(ext)) {
          problems.push('build.yml release: `' + g + '` targets .' + ext
            + ' but no electron-builder target emits that (producible: '
            + (exts.size ? '.' + [...exts].sort().join(', .') : 'none') + ') -- this is the phantom-glob class');
        }
      }
    }
  }

  // F. regenerate-lockfile stays workflow_dispatch, no push trigger
  if (lockfileYml != null && lockfileYml.trim() !== '') {
    const lfLines = lockfileYml.split('\n');
    const lfOn = findLineIdx(lfLines, /^on:\s*$/);
    if (lfOn < 0) {
      problems.push('regenerate-lockfile.yml: no top-level `on:` block found');
    } else {
      const lfBlock = blockAfter(lfLines, lfOn);
      if (!lfBlock.some((l) => /^\s+workflow_dispatch:\s*$/.test(l) || /^\s+workflow_dispatch:\s*/.test(l))) {
        problems.push('regenerate-lockfile.yml: `on:` no longer has `workflow_dispatch:`');
      }
      if (lfBlock.some((l) => /^\s+push:\s*$/.test(l) || /^\s+push:\s*/.test(l))) {
        problems.push('regenerate-lockfile.yml: `on:` gained a `push:` trigger -- a lockfile-regen job must not fire on every push');
      }
    }
  }

  return problems;
}

// ── self-test ─────────────────────────────────────────────────────────────
function selfTest() {
  // A minimal but structurally faithful good build.yml.
  const GOOD_BUILD = [
    'name: build',
    'on:',
    '  pull_request:',
    '  push:',
    "    branches: [main]",
    "    tags: ['v*']",
    'jobs:',
    '  coverage:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - run: node scripts/check-workflow-validity.js',
    '  smoke:',
    '    needs: coverage',
    '    runs-on: ubuntu-latest',
    '    steps: []',
    '  posture-windows:',
    '    needs: coverage',
    '    runs-on: windows-latest',
    '    steps: []',
    '  release:',
    '    needs: [coverage, smoke, posture-windows, build-mac, build-windows, build-linux]',
    "    if: startsWith(github.ref, 'refs/tags/')",
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: softprops/action-gh-release@v3',
    '        with:',
    '          fail_on_unmatched_files: true',
    '          files: |',
    '            **/*.dmg',
    '            **/*.exe',
    '            **/*.AppImage',
    '        env:',
    '          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}',
    '',
  ].join('\n');
  const GOOD_LOCK = ['name: regen', 'on:', '  workflow_dispatch:', 'jobs: {}', ''].join('\n');

  // A reader that yields build configs producing dmg / exe / AppImage only.
  const readJsonGood = (p) => {
    if (p.endsWith(path.join('frontend', 'package.json'))) {
      return { build: { mac: { target: [{ target: 'dmg' }] }, win: { target: 'nsis' }, linux: { target: [{ target: 'AppImage' }] } } };
    }
    return { build: {} };
  };

  const cases = [];
  const run = (name, buildYml, lockYml, reader, wantSubstr) => cases.push({ name, buildYml, lockYml, reader, wantSubstr });

  // 1. the good pair passes
  run('good pair -> no problems', GOOD_BUILD, GOOD_LOCK, readJsonGood, null);
  // 2. the phantom .zip (the actual P1 bug)
  run('phantom .zip glob flagged', GOOD_BUILD.replace('            **/*.AppImage', '            **/*.AppImage\n            **/*.zip'), GOOD_LOCK, readJsonGood, 'phantom-glob class');
  // 3. G1: coverage dropped from needs
  run('coverage missing from needs (G1)', GOOD_BUILD.replace('needs: [coverage, smoke, posture-windows,', 'needs: [smoke, posture-windows,'), GOOD_LOCK, readJsonGood, "missing `coverage`");
  // 4. G1: smoke dropped
  run('smoke missing from needs (G1)', GOOD_BUILD.replace('needs: [coverage, smoke,', 'needs: [coverage,'), GOOD_LOCK, readJsonGood, "missing `smoke`");
  // 5. G2: pull_request trigger removed
  run('pull_request trigger removed (G2)', GOOD_BUILD.replace('  pull_request:\n', ''), GOOD_LOCK, readJsonGood, 'no `pull_request:` trigger');
  // 6. fail_on_unmatched_files flipped
  run('fail_on_unmatched_files not true', GOOD_BUILD.replace('fail_on_unmatched_files: true', 'fail_on_unmatched_files: false'), GOOD_LOCK, readJsonGood, 'fail_on_unmatched_files: true');
  // 7. a literal tab
  run('literal TAB in build.yml', GOOD_BUILD.replace('  pull_request:', '\tpull_request:'), GOOD_LOCK, readJsonGood, 'literal TAB');
  // 8. lockfile gained a push trigger
  run('regenerate-lockfile push trigger', GOOD_BUILD, GOOD_LOCK.replace('  workflow_dispatch:', '  workflow_dispatch:\n  push:'), readJsonGood, 'must not fire on every push');
  // 9. producible set follows the config: if a zip TARGET exists, .zip is allowed
  run('zip allowed when a zip target exists', GOOD_BUILD.replace('            **/*.AppImage', '            **/*.AppImage\n            **/*.zip'), GOOD_LOCK,
    (p) => p.endsWith(path.join('frontend', 'package.json'))
      ? { build: { mac: { target: 'dmg' }, win: { target: 'nsis' }, linux: { target: ['AppImage', { target: 'zip' }] } } }
      : { build: {} }, null);

  let bad = 0;
  for (const c of cases) {
    const problems = checkWorkflows(c.buildYml, c.lockYml, c.reader);
    let ok;
    if (c.wantSubstr === null) {
      ok = problems.length === 0;
      if (!ok) console.error('  FAIL  ' + c.name + '\n        expected NO problems, got:\n        - ' + problems.join('\n        - '));
    } else {
      ok = problems.some((p) => p.includes(c.wantSubstr));
      if (!ok) console.error('  FAIL  ' + c.name + '\n        expected a problem containing ' + JSON.stringify(c.wantSubstr) + ', got:\n        - ' + (problems.join('\n        - ') || '(none)'));
    }
    if (ok) console.log('  ok    ' + c.name);
    else bad++;
  }
  if (bad) { console.error('\nworkflow-validity self-test FAILED: ' + bad + ' of ' + cases.length + ' cases.'); process.exit(1); }
  console.log('\nworkflow-validity self-test passed (' + cases.length + ' cases: phantom glob, G1 needs, G2 trigger, fail-on-unmatched, tabs, lockfile trigger, config-derived producible set).');
}

if (process.argv.includes('--self-test')) {
  selfTest();
} else {
  const readFileOrNull = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch (e) { return null; } };
  const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
  const problems = checkWorkflows(readFileOrNull(BUILD_YML), readFileOrNull(LOCKFILE_YML), readJson);
  if (problems.length) {
    console.error('check-workflow-validity FAILED (' + problems.length + '):\n');
    for (const p of problems) console.error('  - ' + p);
    console.error('');
    process.exit(1);
  }
  console.log('check-workflow-validity passed: release pipeline invariants hold '
    + '(pull_request trigger, release needs coverage+smoke+posture-windows, '
    + 'fail_on_unmatched_files true, every release glob producible by a build target).');
}

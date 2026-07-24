#!/usr/bin/env node
'use strict';

// check-manifest-consistency.js
//
// Asserts that every place FireAlive states its own version, fuse, and build
// identity says the same thing.
//
// WHY THIS EXISTS
//
// The release ceremony touches nine files: seven package.json manifests, the root
// lockfile, and the README. Nothing verified they agreed, so a partially-applied
// ceremony produced a tree that built, passed all 24 gates, and shipped -- while
// the anti-rollback fuse had not actually advanced.
//
// That is not cosmetic. server/lib/version.js reads fuseCounter from the ROOT
// package.json, and services/fuse-high-water.js compares it against the mark
// recorded in the database. If the root manifest is left behind, the release
// claims a fuse it does not carry, the high-water never advances, and the
// previous build still starts against the new release's data -- the exact
// downgrade window the fuse exists to close.
//
// It is also the failure mode most likely to happen, because the ceremony is
// mechanical and repetitive: one manifest missed in a list of nine, or a
// three-line change applied as a one-line edit so the version moves while the
// fuse and buildId do not. Both of those have now happened.
//
// WHAT IT ASSERTS
//
//   1. All seven manifests carry the same version.
//   2. The root lockfile agrees, in both places it records a version.
//   3. The two fuse-bearing manifests (root and GD server) agree on BOTH
//      fuseCounter and buildId -- not just version. A version-only edit is the
//      specific mistake this catches.
//   4. The README states that same version, fuse, and buildId, and links the
//      matching release tag.
//
// It deliberately does not check that the version was BUMPED -- a gate cannot
// know whether a given commit is a release. It checks only that the tree agrees
// with itself, which is the property that was actually violated.

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// The two manifests that carry fuse and build identity, and the five that carry
// version alone. Both lists are explicit rather than globbed: a manifest that
// silently stopped being checked is the same defect in a different place.
const FUSE_MANIFESTS = [
  'package.json',
  'packages/global-dashboard-server/package.json',
];
const VERSION_ONLY_MANIFESTS = [
  'frontend/package.json',
  'packages/analyst-client/package.json',
  'packages/global-dashboard/package.json',
  'packages/shared/package.json',
  'server/package.json',
];

function readJson(rel) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
}

function main() {
  const problems = [];

  // ---- 1 + 3: the manifests ---------------------------------------------
  const versions = [];
  const fuses = [];
  const builds = [];

  for (const rel of FUSE_MANIFESTS.concat(VERSION_ONLY_MANIFESTS)) {
    let pkg;
    try {
      pkg = readJson(rel);
    } catch (e) {
      problems.push(`${rel}: could not be read as JSON -- ${e.message}`);
      continue;
    }
    if (typeof pkg.version !== 'string' || !pkg.version) {
      problems.push(`${rel}: has no version field`);
      continue;
    }
    versions.push({ rel: rel, version: pkg.version });

    if (FUSE_MANIFESTS.indexOf(rel) !== -1) {
      if (typeof pkg.fuseCounter !== 'number') {
        problems.push(`${rel}: has no numeric fuseCounter, and it is one of the two manifests that must carry one`);
      } else {
        fuses.push({ rel: rel, fuse: pkg.fuseCounter });
      }
      if (typeof pkg.buildId !== 'string' || !pkg.buildId) {
        problems.push(`${rel}: has no buildId, and it is one of the two manifests that must carry one`);
      } else {
        builds.push({ rel: rel, buildId: pkg.buildId });
      }
    }
  }

  const canonical = versions.length ? versions[0].version : null;
  const disagreeing = versions.filter((v) => v.version !== canonical);
  if (canonical && disagreeing.length) {
    problems.push(
      `manifests disagree on version: ${versions[0].rel} says ${canonical}, but `
      + disagreeing.map((v) => `${v.rel} says ${v.version}`).join('; ')
      + ' -- a release ceremony that missed a file',
    );
  }

  if (fuses.length === FUSE_MANIFESTS.length && fuses[0].fuse !== fuses[1].fuse) {
    problems.push(
      `the two fuse-bearing manifests disagree on fuseCounter: ${fuses[0].rel} says ${fuses[0].fuse}, `
      + `${fuses[1].rel} says ${fuses[1].fuse}. Both servers must advance together, or one of them `
      + 'claims anti-rollback protection it does not have.',
    );
  }
  if (builds.length === FUSE_MANIFESTS.length && builds[0].buildId !== builds[1].buildId) {
    problems.push(
      `the two fuse-bearing manifests disagree on buildId: ${builds[0].rel} says ${builds[0].buildId}, `
      + `${builds[1].rel} says ${builds[1].buildId}`,
    );
  }

  // ---- 2: the lockfile ---------------------------------------------------
  try {
    const lock = readJson('package-lock.json');
    if (lock.version !== canonical) {
      problems.push(`package-lock.json: top-level version is ${lock.version}, manifests say ${canonical}`);
    }
    if (lock.packages && lock.packages[''] && lock.packages[''].version !== canonical) {
      problems.push(`package-lock.json: packages[""].version is ${lock.packages[''].version}, manifests say ${canonical}`);
    }
  } catch (e) {
    problems.push('package-lock.json: could not be read as JSON -- ' + e.message);
  }

  // ---- 4: the README -----------------------------------------------------
  // Matched by pattern rather than line number, so re-flowing the header does
  // not break the gate.
  try {
    const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');

    const vm = readme.match(/\*\*Version:\*\*\s*v([0-9]+\.[0-9]+\.[0-9]+)/);
    if (!vm) problems.push('README.md: no "**Version:** vX.Y.Z" line found');
    else if (vm[1] !== canonical) problems.push(`README.md: states version v${vm[1]}, manifests say ${canonical}`);

    const fm = readme.match(/\*\*E-fuse counter:\*\*\s*([0-9]+)/);
    if (!fm) problems.push('README.md: no "**E-fuse counter:** N" line found');
    else if (fuses.length && Number(fm[1]) !== fuses[0].fuse) {
      problems.push(
        `README.md: claims e-fuse counter ${fm[1]}, but the manifests carry ${fuses[0].fuse}. `
        + 'The README is what a reader trusts; a release that claims a fuse it does not carry has no '
        + 'anti-rollback protection for that version.',
      );
    }

    const bm = readme.match(/\*\*Build:\*\*\s*([0-9]{8}\.[0-9]+)/);
    if (!bm) problems.push('README.md: no "**Build:** YYYYMMDD.N" line found');
    else if (builds.length && bm[1] !== builds[0].buildId) {
      problems.push(`README.md: states build ${bm[1]}, manifests say ${builds[0].buildId}`);
    }

    const tag = readme.match(/releases\/tag\/v([0-9]+\.[0-9]+\.[0-9]+)/);
    if (tag && tag[1] !== canonical) {
      problems.push(`README.md: the installer link points at release tag v${tag[1]}, but this tree is ${canonical}`);
    }
  } catch (e) {
    problems.push('README.md: could not be read -- ' + e.message);
  }

  if (problems.length) {
    console.error('Manifest consistency gate FAILED:');
    for (const p of problems) console.error('  - ' + p);
    console.error('');
    console.error('Every place FireAlive states its version, fuse, and build identity must agree. A partially-applied release ceremony builds cleanly and ships a version whose anti-rollback fuse never advanced.');
    process.exit(1);
  }

  console.log(
    `Manifest consistency gate passed: 7 manifests, lockfile and README all at v${canonical}`
    + (fuses.length ? `, fuse ${fuses[0].fuse}, build ${builds[0].buildId}` : ''),
  );
}

main();

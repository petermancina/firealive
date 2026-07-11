#!/usr/bin/env node
'use strict';

/*
 * check-tier1-registry-coverage.js
 *
 * CI gate for the Tier-1 column registry. It re-runs the derivation
 * (scripts/derive-tier1-registry.js) against the working tree and fails the
 * build if the registry is not sound OR if a committed registry module is out of
 * sync with what the derivation now produces.
 *
 * It enforces two things per server:
 *
 *   1. SOUNDNESS -- the derivation verifies: no unclassified candidate, no
 *      tier1/tier1-derived/tier3 column without an ENCODING entry, no stale
 *      MANUAL entry, no missing/renamed ENCODING evidence or proof, no
 *      ENCODING/observed-codec contradiction, and the per-class counts match the
 *      expected derivation on the shipped tree.
 *
 *   2. SYNC -- the committed registry module (server/services/tier1-columns.js
 *      for the MC, packages/global-dashboard-server/services/gd-tier1-columns.js
 *      for the GD) is byte-identical (ignoring trailing whitespace) to a fresh
 *      --emit. This catches the dangerous case where the schema or a crypto site
 *      changed -- adding, moving, or re-encoding a Tier-1 column -- but the
 *      generated registry the servers load was not regenerated. A stale registry
 *      would let sealTier1/openTier1 miss a column or use the wrong encoding, so
 *      this is a hard failure with a one-line fix (regenerate with --emit).
 *
 * Exit 0 only if every server passes both checks. Any failure exits 1 and prints
 * the specific problems. Intended to run as its own CI job (see build.yml).
 *
 * Usage:
 *   node scripts/check-tier1-registry-coverage.js
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const derive = require('./derive-tier1-registry.js');

// The committed registry modules this gate keeps honest. Paths mirror the
// emitter's targets in derive-tier1-registry.js.
const REGISTRIES = [
  { server: 'mc', file: 'server/services/tier1-columns.js' },
  { server: 'gd', file: 'packages/global-dashboard-server/services/gd-tier1-columns.js' },
];

function normalize(text) {
  // Ignore trailing whitespace/newlines so an editor-added final newline (or its
  // absence) is not treated as drift. Interior content must match exactly.
  return String(text).replace(/[\s\uFEFF]+$/, '');
}

function checkServer(entry) {
  const problems = [];
  const d = derive.derive(entry.server);

  // 1. Soundness.
  const soundness = derive.verify(d);
  for (const p of soundness) problems.push(p);

  // 2. Sync of the committed module with a fresh emit.
  const expected = derive.emitModule(d);
  const abs = path.join(ROOT, entry.file);
  let committed = null;
  try { committed = fs.readFileSync(abs, 'utf8'); }
  catch (e) { committed = null; }

  if (committed === null) {
    problems.push(entry.server + ': committed registry not found at ' + entry.file +
      ' (generate it with: node scripts/derive-tier1-registry.js --emit ' + entry.server + ')');
  } else if (normalize(committed) !== normalize(expected)) {
    problems.push(entry.server + ': committed registry ' + entry.file +
      ' is out of sync with the derivation (regenerate with: node scripts/derive-tier1-registry.js --emit ' +
      entry.server + ')');
  }

  return { d: d, problems: problems, hasCommitted: committed !== null };
}

function main() {
  let allProblems = [];
  for (const entry of REGISTRIES) {
    const r = checkServer(entry);
    const c = r.d.counts;
    const status = r.problems.length ? 'FAIL' : 'ok';
    console.log('[' + status + '] ' + entry.server + ': ' +
      'tier1 ' + c.tier1 + ' (node-local ' + r.d.nodeLocalTier1 + ', replicated ' + r.d.replicatedTier1 + '), ' +
      'tier1-derived ' + c['tier1-derived'] + ', tier3 ' + c.tier3 + ', ' +
      'client-sealed ' + c['client-sealed'] + ', unused ' + c.unused + ', not-ciphertext ' + c['not-ciphertext'] +
      '; ' + r.d.rows.length + ' candidates; committed ' + (r.hasCommitted ? entry.file : 'MISSING'));
    allProblems = allProblems.concat(r.problems);
  }

  console.log('');
  if (allProblems.length) {
    console.error('Tier-1 registry coverage check FAILED:');
    for (const p of allProblems) console.error('  - ' + p);
    process.exit(1);
  }
  console.log('Tier-1 registry coverage check passed: derivation is sound and committed registries are in sync.');
}

if (require.main === module) main();

module.exports = { checkServer: checkServer };

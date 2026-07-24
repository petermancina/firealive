#!/usr/bin/env node
'use strict';

// check-rollback-containment.js
// CI gate for B6k, on BOTH servers.
//
// B6k adds the one operation in FireAlive that lets a build run BELOW the
// recorded anti-rollback high-water. Everything that makes it safe is a property
// of where it can be reached from and what it does NOT do -- and both kinds of
// property are invisible to ordinary tests, because they are defined by absence.
// A future edit could undo either without a single test failing, and the failure
// would surface only when an operator needs a rollback and cannot have one.
//
// So this gate asserts, for each server:
//
//   1. CONTAINMENT. The rollback service has no HTTP surface (no express, no
//      router), no route file references it, and index.js never mounts anything
//      that reaches it. It must be reachable ONLY from the offline CLI, on the
//      host, with the server stopped.
//   2. NO RATCHET. The rollback service never references the post-restore posture
//      module, and never writes the high-water. B6j-4's ratchet computes
//      max(current, restored), which is exactly why the ordinary restore path
//      cannot serve a rollback -- it would push the mark straight back to the new
//      build's fuse and the previous binary still would not start. Omitting the
//      ratchet IS the operation. It also asserts the service still READS the mark,
//      since losing that read disables the one-version-back gate.
//   3. THE CLI EXISTS AND DELEGATES. The gates live in the service; a CLI that
//      reimplemented them would drift out of agreement with it.
//   4. THE OP IS ADMITTED IN BOTH PLACES. VALID_OPS in the service and the
//      key_op_authorizations CHECK constraint in the schema are independent. A
//      mismatch means minting succeeds in code and is rejected at INSERT, so a
//      rollback authorization could not be created at the moment it is needed.
//   5. THE RESTORE-POINT STORE IS OUTSIDE THE DATA ROOT. A rollback replaces the
//      contents of the data root; a restore point stored inside it would be
//      destroyed by the operation it exists to serve -- the same shape of defect
//      P1-1 removed, where backups inside the app bundle died with the update.
//
// Source-level assertions read comment-stripped code, so a mention in prose does
// not trip the gate and a real reference cannot hide in one.

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

const SERVERS = [
  {
    label: 'MC',
    service: 'server/services/rollback-apply.js',
    cli: 'server/tools/rollback-apply.js',
    cliDelegatesTo: "require('../services/rollback-apply')",
    routesDir: 'server/routes',
    index: 'server/index.js',
    serviceToken: 'rollback-apply',
    koaService: 'server/services/key-op-authorization.js',
    schema: 'server/db/init.js',
    dataRootModule: 'server/lib/data-root.js',
    rootFn: 'dataRoot',
    forbidden: ['applyPostRestorePosture', 'restore-posture', 'persistHighWater'],
  },
  {
    label: 'GD',
    service: 'packages/global-dashboard-server/services/gd-rollback-apply.js',
    cli: 'packages/global-dashboard-server/tools/gd-rollback-apply.js',
    cliDelegatesTo: "require('../services/gd-rollback-apply')",
    routesDir: 'packages/global-dashboard-server/routes',
    index: 'packages/global-dashboard-server/index.js',
    serviceToken: 'gd-rollback-apply',
    koaService: 'packages/global-dashboard-server/services/gd-key-op-authorization.js',
    schema: 'packages/global-dashboard-server/db-init.js',
    dataRootModule: 'packages/global-dashboard-server/lib/gd-data-root.js',
    rootFn: 'gdDataRoot',
    forbidden: ['applyPostRestorePosture', 'gd-restore-posture', 'persistHighWater'],
  },
];

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

function stripComments(src) {
  return src.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
}

// A MENTION is not a reference. The regression suites deliberately read the
// rollback service's source to assert the absence-properties, and quote its path
// inside error strings -- that is the guard doing its job, not a leak. What
// matters is an actual import BINDING (const x = require('...rollback-apply'))
// or an Express mount, either of which would put the operation within reach of a
// request. Matching on those shapes rather than on the substring keeps the gate
// from flagging its own enforcement.
function importsRollback(code, token) {
  const bind = new RegExp(
    '(?:const|let|var)\\s+[^=;\\n]+=\\s*require\\(\\s*[\'"][^\'"]*' + token + '[\'"]\\s*\\)',
  );
  const bareRequire = new RegExp('^\\s*require\\(\\s*[\'"][^\'"]*' + token + '[\'"]\\s*\\)', 'm');
  const mount = new RegExp('app\\.use\\([^)\\n]*' + token);
  return bind.test(code) || bareRequire.test(code) || mount.test(code);
}

function checkServer(s) {
  const problems = [];

  // ---- the files must exist at all -------------------------------------
  for (const rel of [s.service, s.cli, s.koaService, s.schema, s.dataRootModule]) {
    if (!fs.existsSync(path.join(ROOT, rel))) {
      problems.push(`${s.label}: ${rel} is missing`);
    }
  }
  if (problems.length) return problems;

  const svc = stripComments(read(s.service));

  // ---- 1. CONTAINMENT ---------------------------------------------------
  if (/require\(['"]express['"]\)/.test(svc)) {
    problems.push(`${s.label}: ${s.service} requires express. The one operation that lets a build run below the anti-rollback mark must stay offline.`);
  }
  if (/\brouter\./.test(svc)) {
    problems.push(`${s.label}: ${s.service} uses a router. It must be reachable only from the offline CLI.`);
  }
  const routeOffenders = fs.readdirSync(path.join(ROOT, s.routesDir))
    .filter((f) => f.endsWith('.js'))
    .filter((f) => importsRollback(stripComments(read(path.join(s.routesDir, f))), s.serviceToken));
  if (routeOffenders.length) {
    problems.push(`${s.label}: these route files import the rollback service: ${routeOffenders.join(', ')}. A rollback must not be reachable over HTTP.`);
  }
  if (importsRollback(stripComments(read(s.index)), s.serviceToken)) {
    problems.push(`${s.label}: ${s.index} imports or mounts the rollback service. It must be reachable only from the offline CLI.`);
  }

  // ---- 2. NO RATCHET ----------------------------------------------------
  for (const forbidden of s.forbidden) {
    if (svc.indexOf(forbidden) !== -1) {
      problems.push(`${s.label}: ${s.service} references '${forbidden}'. The rollback path must not ratchet the fuse: it would restore the old database and then push the anti-rollback mark straight back to the new build's fuse, so the previous binary still would not start.`);
    }
  }
  if (svc.indexOf('readHighWater') === -1) {
    problems.push(`${s.label}: ${s.service} no longer reads the high-water mark, so the one-version-back gate cannot be enforced.`);
  }

  // ---- 3. THE CLI DELEGATES ---------------------------------------------
  const cli = read(s.cli);
  if (cli.indexOf(s.cliDelegatesTo) === -1) {
    problems.push(`${s.label}: ${s.cli} does not delegate to the rollback service. The gates live in the service; a CLI that reimplements them will drift.`);
  }

  // ---- 4. THE OP IS ADMITTED IN BOTH PLACES -----------------------------
  const koaSrc = read(s.koaService);
  const validOps = koaSrc.match(/const VALID_OPS = \[([^\]]*)\]/);
  if (!validOps) {
    problems.push(`${s.label}: could not read VALID_OPS from ${s.koaService}`);
  } else if (validOps[1].indexOf("'rollback'") === -1) {
    problems.push(`${s.label}: VALID_OPS in ${s.koaService} does not include 'rollback'.`);
  }
  const schemaSrc = read(s.schema);
  const koaTable = schemaSrc.indexOf('CREATE TABLE IF NOT EXISTS key_op_authorizations');
  if (koaTable === -1) {
    problems.push(`${s.label}: key_op_authorizations table not found in ${s.schema}`);
  } else {
    const window = schemaSrc.slice(koaTable, koaTable + 1200);
    if (window.indexOf("'rollback'") === -1) {
      problems.push(`${s.label}: the key_op_authorizations CHECK constraint in ${s.schema} does not admit 'rollback'. VALID_OPS and the schema are independent -- a mismatch means minting succeeds in code and is rejected at INSERT, so a rollback authorization could not be created at the moment it is needed.`);
    }
  }

  // ---- 5. THE STORE IS OUTSIDE THE DATA ROOT ----------------------------
  // Executed rather than pattern-matched: the accessors are what ship.
  const envSnapshot = {};
  for (const k of Object.keys(process.env)) {
    if (/^(FIREALIVE_|DB_PATH|GD_)/.test(k)) { envSnapshot[k] = process.env[k]; delete process.env[k]; }
  }
  try {
    const mod = require(path.join(ROOT, s.dataRootModule));
    if (typeof mod.restorePointsDir !== 'function') {
      problems.push(`${s.label}: ${s.dataRootModule} does not export restorePointsDir()`);
    } else {
      const root = path.resolve(mod[s.rootFn]());
      const store = path.resolve(mod.restorePointsDir());
      if (store === root || store.startsWith(root + path.sep)) {
        problems.push(`${s.label}: the restore-point store (${store}) resolves INSIDE the data root (${root}). A rollback replaces the contents of the data root, so the restore point would be destroyed by the operation it exists to serve.`);
      }
    }
  } catch (e) {
    problems.push(`${s.label}: could not evaluate ${s.dataRootModule}: ${e.message}`);
  } finally {
    Object.assign(process.env, envSnapshot);
  }

  return problems;
}

// ── 6. THE DOCS MUST STAY TRUE ─────────────────────────────────────────────
//
// Documentation that drifts from the code is a hazard of its own here, because
// the rollback procedure is followed by an operator under pressure whose
// deployment is already broken. Two specific ways it could go wrong:
//
//   - The store path is quoted in SETUP.md and in the mechanism doc. If
//     restorePointsDir() ever moves, those become instructions to look in a
//     directory that does not exist.
//   - The PRE-P1 procedure ("uninstall, reinstall the previous version, restore
//     from the console") is not merely stale -- it does not work. The reinstalled
//     older build halts at boot against a data root that still records the newer
//     mark, before the operator can reach any restore UI. If that text ever comes
//     back, it sends someone into a dead end at the worst possible moment.
//
// These run only in CI, against the repository. They deliberately do NOT live in
// the runtime regression suites: SETUP.md and docs/ are not shipped inside the
// packaged app, so a runtime check could only ever report them missing.
function checkDocs() {
  const problems = [];
  const docs = {
    'SETUP.md': 'SETUP.md',
    'docs/pre-upgrade-restore-point.md': 'docs/pre-upgrade-restore-point.md',
    'docs/automatic-updates.md': 'docs/automatic-updates.md',
  };
  for (const rel of Object.keys(docs)) {
    if (!fs.existsSync(path.join(ROOT, rel))) {
      problems.push(`docs: ${rel} is missing`);
    }
  }
  if (problems.length) return problems;

  const setup = read('SETUP.md');
  const mech = read('docs/pre-upgrade-restore-point.md');
  const updates = read('docs/automatic-updates.md');

  // The store paths the code actually returns must appear in the docs.
  const envSnapshot = {};
  for (const k of Object.keys(process.env)) {
    if (/^(FIREALIVE_|DB_PATH|GD_)/.test(k)) { envSnapshot[k] = process.env[k]; delete process.env[k]; }
  }
  try {
    for (const s of SERVERS) {
      const mod = require(path.join(ROOT, s.dataRootModule));
      if (typeof mod.restorePointsDir !== 'function') continue;
      // Compare on the trailing directory name, so a different home directory on
      // the machine running CI does not make this fail for the wrong reason.
      const leaf = path.basename(mod.restorePointsDir());
      if (setup.indexOf(leaf) === -1 && mech.indexOf(leaf) === -1) {
        problems.push(`docs: neither SETUP.md nor docs/pre-upgrade-restore-point.md mentions the ${s.label} restore-point directory ('${leaf}'), so an operator would be told to look in the wrong place`);
      }
    }
  } catch (e) {
    problems.push('docs: could not resolve the restore-point directories: ' + e.message);
  } finally {
    Object.assign(process.env, envSnapshot);
  }

  // The pre-P1 procedure must not come back.
  if (/Reinstall the previous version/i.test(setup)) {
    problems.push("SETUP.md: the pre-P1 rollback procedure ('Reinstall the previous version', then restore from the console) has returned. It does not work: the reinstalled build halts at boot against a data root that still records the newer fuse mark, before any restore UI is reachable.");
  }
  // And the parts that make the new one work must be present.
  // Match against text with markdown emphasis stripped. A doc that says
  // "*before* uninstalling" means exactly what "before uninstalling" means, and a
  // check that cannot see the difference between prose and its formatting will
  // flag correct documentation -- which trains people to ignore the gate.
  const plain = (t) => t.replace(/[*_`]/g, '').toLowerCase();
  const setupPlain = plain(setup);
  for (const [needle, why] of [
    ['before uninstalling', 'SETUP.md must state that the tool runs BEFORE uninstalling the newer version -- it ships inside that installation'],
    ['restore point', 'SETUP.md must tell the operator to take a restore point before updating'],
  ]) {
    if (setupPlain.indexOf(needle.toLowerCase()) === -1) problems.push('SETUP.md: ' + why);
  }
  if (updates.indexOf('pre-upgrade-restore-point.md') === -1) {
    problems.push('docs/automatic-updates.md: no longer links to the restore-point doc, so the update procedure does not tell an operator how to keep a way back');
  }
  return problems;
}

function main() {
  let problems = [];
  for (const s of SERVERS) {
    try {
      problems = problems.concat(checkServer(s));
    } catch (e) {
      problems.push(`${s.label}: threw during the containment check: ${e.message}`);
    }
  }
  try {
    problems = problems.concat(checkDocs());
  } catch (e) {
    problems.push('threw during the documentation check: ' + e.message);
  }
  if (problems.length) {
    console.error('Rollback containment gate FAILED:');
    for (const p of problems) console.error('  - ' + p);
    console.error('');
    console.error('The sanctioned rollback is safe because of where it CANNOT be reached from and what it does NOT do. Both are invisible to ordinary tests.');
    process.exit(1);
  }
  console.log('Rollback containment gate passed (both servers): offline-only, never ratchets, CLI delegates, op admitted in service and schema, store outside the data root, and the operator docs match the code.');
}

main();

#!/usr/bin/env node
'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// check-no-bundle-relative-data-paths.js  --  the 18th gate  (P1-3c)
// ═══════════════════════════════════════════════════════════════════════════
//
// Forbids a server from computing a runtime-state path relative to its own
// source. P1-1 moved every such path to server/lib/data-root.js and its GD twin;
// this keeps them there.
//
// WHY THIS EXISTS
//
// Before P1-1, `path.join(__dirname, '../../data/firealive.db')` put the
// database, the logs, the audit archive, the CEF spool, the migration bundles,
// and the backups inside the application bundle -- the directory an installer
// replaces. A restore point stored there dies with the thing it protects. On
// Linux the bundle is a read-only AppImage mount, so the first write fails
// outright. Nothing caught it because CI has never launched the product.
//
// Run with --self-test to verify the detector on synthetic inputs, including
// the historical defects and every construct that must NOT trip it.
//
// ── INVARIANTS ────────────────────────────────────────────────────────────
//
// A. EXECUTED. Every accessor of both data-root modules returns a path outside
//    the repository, under default env and under each override. ensureDir
//    creates 0700 and refuses a group- or world-accessible directory.
//    Executed rather than read: a grep for os.homedir() would still pass if a
//    refactor reintroduced a __dirname fallback below it.
//
// B. TOKENIZED. No __dirname-relative path in server/ or
//    packages/global-dashboard-server/ resolves into runtime state.
//
// C. An allow-list entry must name a path that exists as a committed artifact.
//    The list is EMPTY today and should stay that way; C is the tripwire that
//    stops it becoming a place dead code hides.
//
// ── WHY THE MATCHER ANCHORS ON __dirname AND NOT ON path.join ─────────────
//
// A draft of this gate matched /path\.(join|resolve)\(\s*__dirname/. Against
// this codebase that misses TWELVE of the sixty-nine call sites, because the
// callee is not always spelled `path`:
//
//   pathMod.join(__dirname, rel)              x5   (2 of them NON-LITERAL)
//   require('path').join(__dirname, 'index.js') x3
//   p.join(__dirname, 'routes', ...)          x2
//   pathx.join(__dirname, 'services', ...)    x1
//   p.resolve(__dirname)                      x1
//
// Worse, the draft was "reconciled" against a grep using the same narrow
// pattern -- two instruments sharing one blind spot, agreeing with each other.
// Anchoring on the __dirname identifier is shape-independent: every form above
// reduces to an id `__dirname` immediately preceded by a punct '('. The
// self-test carries a case per shape, and the site count is reconciled against
// a broad `__dirname` sweep that shares none of the matcher's assumptions.
//
// ── WHY A TOKENIZER AND NOT A REGEX ──────────────────────────────────────
//
// A regex matches this line, which is a comment:
//
//   // __dirname, e.g. path.join(__dirname, '../../data/firealive.db'). In a
//
// The B6d HA guards used a regex comment/string stripper; it desynchronised on
// quote-bearing regex literals and silently skipped roughly two-thirds of
// ha-pairing.js on BOTH servers while reporting PASS. This gate shares the
// tokenizer written for that fix (scripts/lib/js-tokenizer.js).
//
// ── WHY `data` IS NOT A RUNTIME-STATE SEGMENT ────────────────────────────
//
// It is the discriminator that does not work, and three earlier designs of this
// gate died on it. `server/data/` holds BUNDLED, READ-ONLY TRUST ANCHORS -- the
// cloud-attestation roots and the FIDO attestation roots -- which are supposed
// to be code-adjacent and must never move to a writable directory. The runtime
// state lives at ~/.firealive/. Both contain a segment named `data`, so the
// segment name cannot separate them, and neither can "does it escape the server
// root" (the GD's own pre-P1 database sat at gd-server/data/, INSIDE its root).
//
// The runtime-state directories have unambiguous names and the database has an
// unambiguous extension. That is what this gate keys on, and it needs no
// allow-list at all: every historical defect is caught and every trust anchor
// passes without an exception being written for it. An allow-list you do not
// need is an allow-list that cannot rot.
//
// ── A LIMITATION, STATED RATHER THAN HIDDEN ──────────────────────────────
//
// Invariant B flags `path.join(__dirname, someVariable)` because it cannot be
// resolved statically, and a scanner that silently passes what it cannot read
// is a scanner that lies about its own coverage. Two files legitimately do
// this: they iterate a literal array of code-relative .js paths to scan their
// own source (the B6d HA guards and the regression runner's source checks).
// Resolving that would need data-flow analysis this gate should not have.
//
// So SOURCE_SCANNERS suppresses the non-literal flag for those two files ONLY.
// The consequence, stated plainly: a FUTURE non-literal path reaching runtime
// state inside one of them would not be caught by invariant B. The primary
// rule -- a literal path reaching runtime state -- still applies to them in
// full, and to every other file without exception.
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const os = require('os');
const path = require('path');
const { tokenize } = require('./lib/js-tokenizer');

const REPO = path.resolve(__dirname, '..');
const SCAN_ROOTS = ['server', 'packages/global-dashboard-server'];

// The two modules that are ALLOWED to know where runtime state lives.
const DATA_ROOT_MODULES = [
  'server/lib/data-root.js',
  'packages/global-dashboard-server/lib/gd-data-root.js',
];

// Directory names that exist only at runtime. `data` is deliberately absent --
// see the header.
const STATE_DIRS = [
  'backups', 'logs', 'cef-spool', 'archive-pending',
  'migration-bundles', 'cicd-configs', 'cloud-packages',
];
const DB_FILE = /\.(db|sqlite|sqlite3)$/;

// Paths a __dirname site may resolve into despite the rules above. EMPTY, and
// invariant C keeps it honest: an entry must name a committed artifact.
const ALLOW_PATHS = [];

// Files whose __dirname joins with a variable are source scans, not state
// paths: each iterates a literal array of code-relative .js paths. See the
// limitation in the header. Invariant C requires each to exist.
const SOURCE_SCANNERS = [
  'server/services/regression-runner.js',
  'packages/global-dashboard-server/index.js',
];

const problems = [];
const fail = (m) => problems.push(m);

// ── the matcher ───────────────────────────────────────────────────────────
// A site is an id `__dirname` immediately preceded by a punct '('. Walk to the
// matching ')' counting depth; `str` tokens are path segments; any OTHER id
// inside the call means a non-literal argument, which cannot be resolved
// statically and is therefore a finding rather than a pass.
function sitesIn(src) {
  const toks = tokenize(src);
  const out = [];
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    if (t.type !== 'id' || t.value !== '__dirname') continue;
    const prev = toks[k - 1];
    if (!prev || prev.type !== 'punct' || prev.value !== '(') continue;
    const segs = [];
    let nonLiteral = null;
    let depth = 1;
    let j = k + 1;
    for (; j < toks.length && depth > 0; j++) {
      const u = toks[j];
      if (u.type === 'punct' && u.value === '(') { depth++; continue; }
      if (u.type === 'punct' && u.value === ')') { depth--; continue; }
      if (depth !== 1) continue;
      if (u.type === 'str') segs.push(u.value);
      else if (u.type === 'id' && !nonLiteral) nonLiteral = u.value;
    }
    out.push({ line: t.line, segs, nonLiteral });
  }
  return out;
}

function isState(resolved) {
  if (DB_FILE.test(resolved)) return 'a database file';
  const segs = resolved.split(path.sep);
  const hit = STATE_DIRS.find((s) => segs.includes(s));
  return hit ? ('the runtime-state directory "' + hit + '"') : null;
}

function allowed(resolved) {
  return ALLOW_PATHS.some((p) => {
    const abs = path.join(REPO, p);
    return resolved === abs || resolved.startsWith(abs + path.sep);
  });
}

function jsFiles(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const f = path.join(dir, e.name);
    if (e.isDirectory()) jsFiles(f, acc);
    else if (e.name.endsWith('.js')) acc.push(f);
  }
  return acc;
}

// ── invariant A ───────────────────────────────────────────────────────────
function underRepo(p) {
  const rel = path.relative(REPO, p);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function checkAccessors(modRel, rootEnv) {
  const abs = path.join(REPO, modRel);
  const load = () => { delete require.cache[require.resolve(abs)]; return require(abs); };
  const SKIP = new Set(['ensureDir', 'assertNoLegacyDatabase', 'legacyDbPath', 'DIR_MODE']);

  const run = (label) => {
    let mod;
    try { mod = load(); } catch (e) { fail('A: cannot load ' + modRel + ': ' + e.message); return; }
    for (const name of Object.keys(mod)) {
      if (SKIP.has(name) || typeof mod[name] !== 'function') continue;
      let got;
      try { got = mod[name](); } catch (e) { fail('A: ' + modRel + '.' + name + '() threw (' + label + '): ' + e.message); continue; }
      if (typeof got !== 'string' || !got) { fail('A: ' + modRel + '.' + name + '() returned a non-path (' + label + ')'); continue; }
      if (underRepo(path.resolve(got))) {
        fail('A: ' + modRel + '.' + name + '() -> ' + got + ' resolves INSIDE the application directory (' + label + ')');
      }
    }
  };

  const saved = { ...process.env };
  try {
    for (const k of Object.keys(process.env)) {
      if (/^(FIREALIVE_|DB_PATH|LOG_PATH|BACKUP_|ARCHIVE_|CEF_|CICD_|CLOUD_|MIGRATION_)/.test(k)) delete process.env[k];
    }
    run('default env');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-gate-'));
    process.env[rootEnv] = tmp;
    run(rootEnv + ' override');
    delete process.env[rootEnv];
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  } finally {
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, saved);
  }
}

function checkEnsureDir(modRel) {
  const mod = require(path.join(REPO, modRel));
  if (typeof mod.ensureDir !== 'function') { fail('A: ' + modRel + ' has no ensureDir'); return; }
  if (process.platform === 'win32') return; // POSIX modes are not modelled; the boot posture check covers ACLs

  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-gate-'));
  try {
    const fresh = path.join(base, 'fresh');
    mod.ensureDir(fresh);
    const m = fs.statSync(fresh).mode & 0o777;
    if (m !== 0o700) fail('A: ' + modRel + '.ensureDir created mode ' + m.toString(8) + ', expected 700');

    for (const bad of [0o777, 0o750]) {
      const d = path.join(base, 'wide' + bad.toString(8));
      fs.mkdirSync(d);
      fs.chmodSync(d, bad);
      let refused = false;
      try { mod.ensureDir(d); } catch (_e) { refused = true; }
      if (!refused) fail('A: ' + modRel + '.ensureDir ACCEPTED mode ' + bad.toString(8) + '; it must refuse a group- or world-accessible directory');
    }
  } finally {
    try { fs.rmSync(base, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

// ── invariant B ───────────────────────────────────────────────────────────
function scanTree() {
  let count = 0;
  for (const root of SCAN_ROOTS) {
    for (const file of jsFiles(path.join(REPO, root), [])) {
      const rel = path.relative(REPO, file).split(path.sep).join('/');
      if (DATA_ROOT_MODULES.includes(rel)) continue;
      let src;
      try { src = fs.readFileSync(file, 'utf8'); } catch (_e) { continue; }
      for (const s of sitesIn(src)) {
        count++;
        const where = rel + ':' + s.line;
        if (s.nonLiteral) {
          if (!SOURCE_SCANNERS.includes(rel)) {
            fail('B: ' + where + ' joins __dirname with the non-literal `' + s.nonLiteral
               + '`; it cannot be resolved statically, and a scanner that passes what it cannot '
               + 'read lies about its own coverage. Rewrite it with literal segments, or add the '
               + 'file to SOURCE_SCANNERS if it scans its own source.');
          }
          continue;
        }
        if (!s.segs.length) continue; // bare path.resolve(__dirname) -- the app dir itself
        const resolved = path.resolve(path.dirname(file), ...s.segs);
        const why = isState(resolved);
        if (why && !allowed(resolved)) {
          fail('B: ' + where + ' resolves to ' + path.relative(REPO, resolved) + ' -- ' + why
             + ' inside the application bundle. Runtime state belongs under the data root; use '
             + (rel.startsWith('packages/') ? 'lib/gd-data-root.js' : 'server/lib/data-root.js') + '.');
        }
      }
    }
  }
  return count;
}

// ── invariant C ───────────────────────────────────────────────────────────
function checkAllowList() {
  for (const p of ALLOW_PATHS) {
    if (!fs.existsSync(path.join(REPO, p))) {
      fail('C: allow-listed path "' + p + '" does not exist. A trust anchor ships with the code; '
         + 'an entry naming nothing is either stale or is hiding something. Remove it.');
    }
  }
  for (const f of SOURCE_SCANNERS) {
    if (!fs.existsSync(path.join(REPO, f))) {
      fail('C: SOURCE_SCANNERS names "' + f + '", which does not exist. Remove the entry.');
    }
  }
}

// ── the reconciliation ────────────────────────────────────────────────────
// The matcher is checked against an instrument that shares none of its
// assumptions: a raw text count of `__dirname`, minus the occurrences the
// tokenizer legitimately drops (comments) and the excluded data-root modules.
// A count that disagrees means the matcher has a blind spot, which is the one
// failure a scanner cannot report about itself.
function reconcile() {
  let raw = 0;
  let inComments = 0;
  for (const root of SCAN_ROOTS) {
    for (const file of jsFiles(path.join(REPO, root), [])) {
      const rel = path.relative(REPO, file).split(path.sep).join('/');
      if (DATA_ROOT_MODULES.includes(rel)) continue;
      const src = fs.readFileSync(file, 'utf8');
      raw += (src.match(/__dirname/g) || []).length;
      const seen = tokenize(src).filter((t) => t.type === 'id' && t.value === '__dirname').length;
      inComments += (src.match(/__dirname/g) || []).length - seen;
    }
  }
  return { raw, inComments, tokenized: raw - inComments };
}

// ── self-test ─────────────────────────────────────────────────────────────
function selfTest() {
  const F = 'server/services/x.js';   // two levels under the repo root
  const G = 'packages/global-dashboard-server/lib/y.js';
  const at = (rel, src) => {
    const file = path.join(REPO, rel);
    return sitesIn(src).map((s) => {
      if (s.nonLiteral) return 'nonliteral';
      if (!s.segs.length) return 'bare';
      const r = path.resolve(path.dirname(file), ...s.segs);
      return isState(r) ? 'RED' : 'green';
    });
  };

  const cases = [
    // every call shape present in this codebase must be SEEN
    [F, "const p = path.join(__dirname, '..', '..', 'data', 'firealive.db');", ['RED'], 'path.join -- the pre-P1 database'],
    [F, "const p = p2.join(__dirname, '..', '..', 'data', 'backups');", ['RED'], 'p.join -- an aliased path module'],
    [F, "const p = pathMod.join(__dirname, '..', '..', 'logs');", ['RED'], 'pathMod.join'],
    [F, "const p = require('path').join(__dirname, '..', '..', 'data', 'x.sqlite');", ['RED'], "require('path').join"],
    [F, "const p = pathx.resolve(__dirname, '..', '..', 'cef-spool');", ['RED'], 'pathx.resolve'],
    [G, "const p = path.join(__dirname, '..', 'data', 'global-dashboard.db');", ['RED'], 'the GD database INSIDE its own server root'],
    [G, "const p = path.join(__dirname, '..', '..', 'data', 'migration-bundles');", ['RED'], 'S1 -- the GD migration bundles'],

    // trust anchors and code reads must NOT trip it
    [F, "const d = path.join(__dirname, '..', 'data', 'attestation-roots');", ['green'], 'TRUST ANCHOR: cloud-attestation roots'],
    [F, "const d = path.join(__dirname, '..', 'data', 'fido-attestation-roots.json');", ['green'], 'TRUST ANCHOR: FIDO roots'],
    [F, "const v = require(path.join(__dirname, '..', '..', 'package.json')).version;", ['green'], 'code-relative read of package.json'],
    [F, "const r = path.resolve(__dirname);", ['bare'], 'the application directory itself'],

    // the tokenizer's contract, asserted here because this gate depends on it
    [F, "// path.join(__dirname, '../../data/firealive.db') is what P1-1 removed", [], 'a COMMENT must produce no site'],
    [F, "log('path.join(__dirname, \\'data\\', \\'x.db\\')');", [], 'a STRING must produce no site'],
    [F, "/* path.join(__dirname, '..', 'logs') */", [], 'a BLOCK COMMENT must produce no site'],

    // a non-literal cannot be resolved and is a finding, not a pass
    [F, "const p = pathMod.join(__dirname, rel);", ['nonliteral'], 'a non-literal argument is a FINDING'],
  ];

  let bad = 0;
  for (const [rel, src, want, name] of cases) {
    const got = at(rel, src);
    const ok = JSON.stringify(got) === JSON.stringify(want);
    if (!ok) { bad++; console.error('  FAIL  ' + name + '\n        want ' + JSON.stringify(want) + ' got ' + JSON.stringify(got)); }
  }
  if (bad) {
    console.error('\nSelf-test FAILED: ' + bad + ' of ' + cases.length + ' cases.');
    process.exit(1);
  }
  console.log('18th-gate self-test passed (' + cases.length + ' cases: every call shape seen, comments and strings ignored, non-literals flagged).');
}

// ── main ──────────────────────────────────────────────────────────────────
if (process.argv.includes('--self-test')) {
  selfTest();
} else {
  checkAccessors('server/lib/data-root.js', 'FIREALIVE_DATA_DIR');
  checkAccessors('packages/global-dashboard-server/lib/gd-data-root.js', 'FIREALIVE_GD_DATA_DIR');
  checkEnsureDir('server/lib/data-root.js');
  checkEnsureDir('packages/global-dashboard-server/lib/gd-data-root.js');
  const sites = scanTree();
  checkAllowList();
  const r = reconcile();

  // The reconciliation: an instrument sharing none of the matcher's
  // assumptions. Every __dirname the tokenizer sees must have been visited.
  if (r.tokenized !== sites) {
    fail('RECONCILIATION: a raw sweep finds ' + r.tokenized + ' __dirname identifiers but the '
       + 'matcher visited ' + sites + '. The matcher has a blind spot -- the one failure a '
       + 'scanner cannot report about itself.');
  }

  if (problems.length) {
    console.error('check-no-bundle-relative-data-paths FAILED (' + problems.length + '):\n');
    for (const p of problems) console.error('  - ' + p);
    console.error('');
    process.exit(1);
  }
  console.log('check-no-bundle-relative-data-paths passed: ' + sites + ' __dirname sites across '
    + SCAN_ROOTS.join(' + ') + ', none reaching runtime state; allow-list empty ('
    + r.raw + ' raw occurrences, ' + r.inComments + ' in comments).');
}

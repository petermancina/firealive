#!/usr/bin/env node
//
// FIREALIVE -- foreign-key enforcement guard (CI)  [B6g]
//
// B6g found that the Global Dashboard had been running with foreign keys
// DISABLED. `getDb()` was one line -- `return new Database(DB_PATH)` -- and
// better-sqlite3 defaults `foreign_keys` to OFF, so all 57 `REFERENCES ... ON
// DELETE` clauses across 15 parent tables were decorative. A DELETE of a row
// that a child RESTRICTed succeeded, and left the child pointing at an id that
// no longer existed.
//
// The fix is one pragma. This gate exists because the fix is one pragma AND
// three invariants that are silent when broken:
//
//   1. THE PRAGMA IS SET AT CONNECTION OPEN. Delete the line and nothing fails:
//      the schema still applies, every gate still passes, and the constraints go
//      back to being decorative. There is no test that would notice, which is
//      exactly how it was decorative for so long in the first place.
//
//   2. EVERY `foreign_keys = OFF` IS RESTORED. The 12-step table-rebuild
//      migrations must disable enforcement to drop a parent table, and each
//      restores it in a `finally`. An OFF with no matching ON leaves the
//      connection unenforced for the life of the process.
//
//   3. THE PRAGMA IS SET **BEFORE** THE TRANSACTION, NEVER INSIDE IT. This is
//      the one that would destroy a database rather than merely weaken it.
//      `PRAGMA foreign_keys` is a NO-OP inside a transaction -- SQLite ignores it
//      silently. While the connection defaulted to OFF that no-op was harmless.
//      Now that it defaults to ON, a rebuild that set the pragma inside its
//      transaction would run the drop-and-rename against enforced constraints,
//      and the failure would land mid-migration on an operator's live database.
//
//      All eight rebuilds already do this correctly. This gate is here so the
//      ninth does too.
//
// There is deliberately NO opt-out to check for: a switch that disables
// referential integrity is a switch someone eventually uses to silence an error,
// and the error is the control working.
//
// Run:  node scripts/check-foreign-keys-enforced.js
//       node scripts/check-foreign-keys-enforced.js --selftest
//
// AGPL-3.0-or-later
//

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// Servers that open a database and must enforce. Each names the file holding the
// connection factory and the function that opens it.
const SERVERS = [
  { name: 'gd', file: 'packages/global-dashboard-server/db-init.js', opener: 'function getDb()' },
];

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// Analyse one schema/connection file.
function analyse(src) {
  const lines = src.split('\n');
  const offs = [];
  const ons = [];
  lines.forEach((l, i) => {
    if (l.indexOf('foreign_keys = OFF') !== -1) offs.push(i + 1);
    if (l.indexOf('foreign_keys = ON') !== -1) ons.push(i + 1);
  });
  return { lines, offs, ons };
}

// Is the pragma set inside the opener function?
function pragmaInOpener(src, opener) {
  const i = src.indexOf(opener);
  if (i === -1) return { found: false, reason: 'opener not found: ' + opener };
  // the opener's body, by brace matching
  const braceStart = src.indexOf('{', i);
  let depth = 0;
  let end = -1;
  for (let j = braceStart; j < src.length; j += 1) {
    if (src[j] === '{') depth += 1;
    else if (src[j] === '}') {
      depth -= 1;
      if (depth === 0) { end = j; break; }
    }
  }
  if (end === -1) return { found: false, reason: 'opener body not delimited' };
  const body = src.slice(braceStart, end);
  return { found: body.indexOf('foreign_keys = ON') !== -1, body: body };
}

// For each OFF, find the next ON and assert (a) it exists, (b) it is in a
// finally, and (c) no transaction is opened between the OFF and the first
// statement that needs enforcement disabled.
function checkOffSites(lines, offs, ons) {
  const problems = [];
  for (const off of offs) {
    const next = ons.filter((x) => x > off);
    if (!next.length) {
      problems.push('foreign_keys = OFF at line ' + off + ' is never restored: the connection '
        + 'stays unenforced for the life of the process');
      continue;
    }
    const on = next[0];
    const between = lines.slice(off - 1, on).join('\n');
    if (between.indexOf('finally') === -1) {
      problems.push('foreign_keys = OFF at line ' + off + ' is restored at line ' + on
        + ' but not in a `finally`: a throwing migration leaves the connection unenforced');
    }
    // (c) THE ORDERING INVARIANT. Between the OFF and the transaction opening,
    // there must be nothing -- the pragma must come first. If a BEGIN or
    // db.transaction( appears BEFORE the pragma in the same block, the pragma is
    // a silent no-op.
    const beforeWindow = lines.slice(Math.max(0, off - 8), off - 1).join('\n');
    // Variable-agnostic: `\w+\.transaction(`, not `db.transaction(`. A rebuild
    // opened on a differently-named handle -- conn, database, tx -- is the same
    // defect, and matching one name is how a detector passes on the case it was
    // written to catch.
    if (/\w+\.transaction\(|BEGIN TRANSACTION|BEGIN IMMEDIATE|\bBEGIN\b/.test(beforeWindow)) {
      problems.push('foreign_keys = OFF at line ' + off + ' appears to be INSIDE an open '
        + 'transaction (a transaction is opened within the 8 lines above). PRAGMA foreign_keys '
        + 'is a NO-OP inside a transaction, so enforcement would stay ON while a 12-step rebuild '
        + 'drops a parent table -- the migration fails mid-flight on a live database.');
    }
  }
  return problems;
}

function selftest() {
  const cases = [];
  const t = (n, got, want) => cases.push({ n, ok: JSON.stringify(got) === JSON.stringify(want), got, want });

  // pragma detection inside an opener
  t('detects the pragma inside the opener',
    pragmaInOpener('function getDb() {\n  const db = new D();\n  db.pragma("foreign_keys = ON");\n  return db;\n}', 'function getDb()').found, true);
  t('>>> detects a MISSING pragma -- the silent regression <<<',
    pragmaInOpener('function getDb() {\n  return new D(P);\n}', 'function getDb()').found, false);
  t('reports a missing opener rather than passing',
    pragmaInOpener('function other() {}', 'function getDb()').found, false);

  // OFF with no ON
  let a = analyse('a\nx.pragma("foreign_keys = OFF");\nb\nc');
  t('>>> an OFF that is never restored is caught <<<',
    checkOffSites(a.lines, a.offs, a.ons).length, 1);

  // OFF restored, but not in a finally
  a = analyse('x.pragma("foreign_keys = OFF");\ndoWork();\nx.pragma("foreign_keys = ON");');
  t('>>> an OFF restored outside a finally is caught <<<',
    checkOffSites(a.lines, a.offs, a.ons).length, 1);

  // correct: OFF, transaction, restored in finally
  a = analyse([
    'x.pragma("foreign_keys = OFF");',
    'const m = x.transaction(() => { rebuild(); });',
    'try { m(); } finally { x.pragma("foreign_keys = ON"); }',
  ].join('\n'));
  t('the correct idiom passes', checkOffSites(a.lines, a.offs, a.ons).length, 0);

  // THE FATAL ONE: transaction opened before the pragma
  a = analyse([
    'const m = x.transaction(() => {',
    '  x.pragma("foreign_keys = OFF");',
    '  rebuild();',
    '});',
    'try { m(); } finally { x.pragma("foreign_keys = ON"); }',
  ].join('\n'));
  const probs = checkOffSites(a.lines, a.offs, a.ons);
  t('>>> a pragma INSIDE a transaction is caught <<<', probs.length >= 1, true);
  t('    ...and the message says why', /NO-OP inside a transaction/.test(probs.join(' ')), true);

  const bad = cases.filter((c) => !c.ok);
  for (const c of cases) {
    console.log('  ' + (c.ok ? 'ok  ' : 'FAIL') + '  ' + c.n
      + (c.ok ? '' : ' (got ' + JSON.stringify(c.got) + ', want ' + JSON.stringify(c.want) + ')'));
  }
  console.log('\nself-test: ' + (cases.length - bad.length) + '/' + cases.length + ' passed');
  process.exit(bad.length ? 1 : 0);
}

if (process.argv.indexOf('--selftest') !== -1) selftest();

const problems = [];
let offTotal = 0;
for (const s of SERVERS) {
  let src;
  try { src = read(s.file); } catch (e) {
    problems.push(s.name + ': cannot read ' + s.file);
    continue;
  }
  const p = pragmaInOpener(src, s.opener);
  if (!p.found) {
    problems.push(s.name + ': ' + s.opener + ' does not set `foreign_keys = ON`. '
      + 'Without it better-sqlite3 leaves foreign keys DISABLED and every REFERENCES ... '
      + 'ON DELETE clause in the schema is decorative.'
      + (p.reason ? ' (' + p.reason + ')' : ''));
  }
  const a = analyse(src);
  offTotal += a.offs.length;
  for (const prob of checkOffSites(a.lines, a.offs, a.ons)) problems.push(s.name + ': ' + prob);
}

if (problems.length) {
  console.error('Foreign-key enforcement gate FAILED (' + problems.length + '):\n');
  for (const p of problems) console.error('  - ' + p);
  console.error('');
  console.error('A REFERENCES clause that is not enforced is worse than no constraint at all:');
  console.error('it reads as protection in every review and provides none at runtime.');
  process.exit(1);
}
console.log('Foreign-key enforcement gate passed: ' + SERVERS.length + ' server(s) enforce at '
  + 'connection open, and all ' + offTotal + ' migration disables are set before their transaction '
  + 'and restored in a finally.');

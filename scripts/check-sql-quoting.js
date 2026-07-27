#!/usr/bin/env node
//
// FIREALIVE -- SQL String-Literal Quoting Guard (CI)  [O3]
//
// SQLite reads a DOUBLE-quoted token as an IDENTIFIER, not a string. It falls
// back to treating one as a literal only when compiled with SQLITE_DQS enabled,
// and better-sqlite3 -- the driver FireAlive ships -- disables that fallback.
// So this:
//
//     db.prepare('UPDATE t SET at = datetime("now") WHERE id = ?')
//
// does not set a timestamp. It throws:
//
//     no such column: "now" - should this be a string literal in single-quotes?
//
// Eleven statements were written that way across auth, KMS providers, the
// scheduler, retros, routing, team and delegations -- against 555 correct ones.
// They were found only because an O3 verification harness executed the SQL
// against a real database instead of pattern-matching it.
//
// A double-quoted token inside a SQLite date/time function is ALWAYS a string
// literal and never a legitimate identifier, so this check has no false
// positives. It deliberately does not attempt to police double quotes in SQL
// generally, where they can be valid identifier quoting.
//
// Run:  node scripts/check-sql-quoting.js
//       node scripts/check-sql-quoting.js --selftest
//
// AGPL-3.0-or-later
//

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SCAN_DIRS = ['server', 'packages', 'scripts', 'frontend'];
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out']);

// A double-quoted argument to a SQLite date/time function.
const OFFENDER = /\b(datetime|date|time|strftime|julianday)\(\s*"/g;

// This guard necessarily CONTAINS the pattern it looks for: in its header
// example, and in the self-test fixtures that prove the scanner works. Excluding
// it is not a carve-out that could hide a real defect -- it holds no production
// SQL -- and the self-test asserts the scanner still flags the pattern, so a
// broken scanner fails loudly rather than passing by exclusion. Same reasoning as
// check-workflow-validity.js, whose first version scanned the real scripts
// directory against its own synthetic fixtures and took 2 of 9 self-test cases
// red.
const SELF = path.resolve(__filename);

function walk(dir, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return out; }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(js|jsx|mjs|cjs)$/.test(e.name) && path.resolve(p) !== SELF) out.push(p);
  }
  return out;
}

function scanSource(src) {
  const hits = [];
  const lines = src.split('\n');
  lines.forEach((line, i) => {
    OFFENDER.lastIndex = 0;
    let m;
    while ((m = OFFENDER.exec(line)) !== null) {
      hits.push({ line: i + 1, fn: m[1], text: line.trim().slice(0, 100) });
    }
  });
  return hits;
}

function selftest() {
  const cases = [];
  const t = (n, got, want) => cases.push({ n, ok: got === want, got, want });

  t('flags datetime("now")', scanSource(`db.prepare('SET a = datetime("now")')`).length, 1);
  t('flags date("now")', scanSource(`db.prepare('date("now")')`).length, 1);
  t('flags strftime with a double-quoted format', scanSource(`db.prepare('strftime("%Y", x)')`).length, 1);
  t('flags whitespace before the quote', scanSource(`datetime( "now" )`).length, 1);
  t('accepts datetime(\'now\')', scanSource(`db.prepare("SET a = datetime('now')")`).length, 0);
  t('accepts CURRENT_TIMESTAMP', scanSource(`db.prepare('SET a = CURRENT_TIMESTAMP')`).length, 0);
  t('accepts a double-quoted IDENTIFIER elsewhere', scanSource(`db.prepare('SELECT "my col" FROM t')`).length, 0);
  t('accepts datetime(column)', scanSource(`db.prepare('SELECT datetime(created_at) FROM t')`).length, 0);
  t('counts two offenders on one line', scanSource(`a = datetime("now"); b = date("now")`).length, 2);
  t('reports the line number', scanSource(`x\ny\ndatetime("now")`)[0].line, 3);

  // The exclusion above must not be able to mask a scanner that stopped working.
  t('the scanner still detects the pattern it excludes itself for',
    scanSource(fs.readFileSync(__filename, 'utf8')).length > 0, true);

  const bad = cases.filter((c) => !c.ok);
  for (const c of cases) console.log('  ' + (c.ok ? 'ok  ' : 'FAIL') + '  ' + c.n + (c.ok ? '' : ` (got ${c.got}, want ${c.want})`));
  console.log('\nself-test: ' + (cases.length - bad.length) + '/' + cases.length + ' passed');
  process.exit(bad.length ? 1 : 0);
}

if (process.argv.indexOf('--selftest') !== -1) selftest();

const files = [];
for (const d of SCAN_DIRS) walk(path.join(ROOT, d), files);

const failures = [];
for (const f of files) {
  const hits = scanSource(fs.readFileSync(f, 'utf8'));
  for (const h of hits) {
    failures.push(`${path.relative(ROOT, f)}:${h.line}  ${h.fn}("...)  -- ${h.text}`);
  }
}

if (failures.length) {
  console.error('SQL quoting gate FAILED:\n');
  for (const f of failures) console.error('  - ' + f);
  console.error('\nSQLite reads a double-quoted token as an IDENTIFIER, not a string, and');
  console.error('better-sqlite3 disables the legacy fallback. These statements throw at');
  console.error('runtime: no such column: "now". Use single quotes for the SQL literal and');
  console.error('a double-quoted or template-literal JavaScript string around it.');
  process.exit(1);
}
console.log(`SQL quoting gate passed: ${files.length} files scanned, no double-quoted string literals in SQLite date/time functions.`);

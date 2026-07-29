#!/usr/bin/env node
//
// FIREALIVE -- Access-Log Outcome Coverage Guard (CI)  [B6e]
//
// Every hash-chained access log constrains its `outcome` column with a CHECK.
// Every writer emits outcome codes. When those two drift apart, the INSERT
// throws -- and on these surfaces a throwing INSERT does not merely lose a log
// line, it changes the HTTP status the caller receives.
//
// That is not hypothetical. O3 made three scanner access routers
// certificate-first and added `log('rejected_cert', ...)` as the FIRST
// rejection, before the token is ever compared. None of the three access-log
// tables permitted that value. The result on shipped v1.0.89:
//
//     scanner presents no certificate
//       -> log('rejected_cert', ...)
//       -> INSERT throws (CHECK constraint failed)
//       -> escapes log(), caught by the handler's outer catch
//       -> responds 500 "Failed to record scan access"
//
// So a certless caller got 500 while a caller with a valid certificate and a
// bad token got 401. That difference is externally observable: an ORACLE, in
// the exact place O3 had just removed one by answering every rejection with a
// single generic 401. And nothing was written to the audit log at all.
//
// This guard fails the build on two drifts:
//
//   OUTCOME-COVERAGE  a writer emits an outcome its table's CHECK does not
//                     permit.
//   LOG-CANNOT-THROW  an access-log writer whose failure can escape into the
//                     request path, where it would alter the response.
//
// TWO WRITER SHAPES, and the second is why a literal-only matcher is not
// enough. The scanner routers call `log('rejected_cert', ...)` with a literal.
// The threat-hunting feed and TAXII routers call a helper --
// `writeAccess(db, req, outcome, ...)` -- and pass `outcome: outcome`, a
// PARAMETER. A guard that matched only `outcome: '<literal>'` would find zero
// outcomes in those two files and pass vacuously, reporting coverage it never
// checked. So helper parameters are traced back to their call sites.
//
// Run:  node scripts/check-access-log-outcomes.js
//       node scripts/check-access-log-outcomes.js --selftest
//
// AGPL-3.0-or-later
//

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SELF = path.resolve(__filename);

// ── The registry: every access log, its schema file, and everything that
// writes to it. Adding a table here without its writers is itself a drift, so
// the self-test asserts the registry is non-trivial.
const ACCESS_LOGS = [
  {
    table: 'vuln_scan_access_log',
    schema: 'server/db/init.js',
    writers: ['server/routes/vuln-scan.js'],
  },
  {
    table: 'cloud_vuln_scan_access_log',
    schema: 'server/db/init.js',
    writers: ['server/routes/cloud-vuln-scan.js'],
  },
  {
    table: 'threat_hunting_access_log',
    schema: 'server/db/init.js',
    writers: [
      'server/middleware/threat-hunting-auth.js',
      'server/routes/threat-hunting-feed.js',
      'server/routes/threat-hunting-taxii.js',
    ],
  },
  {
    table: 'cloud_vuln_scan_access_log',
    schema: 'packages/global-dashboard-server/db-init.js',
    writers: ['packages/global-dashboard-server/routes/cloud-vuln-scan.js'],
    label: 'GD',
  },
];

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// Blank comments and string bodies before any POSITION comparison, preserving
// length and newlines so offsets stay comparable. Two O3 guards reported false
// orderings because an identifier appeared in a header comment.
function stripNonCode(src) {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const two = src.slice(i, i + 2);
    if (two === '//') {
      const j = src.indexOf('\n', i);
      const end = j === -1 ? src.length : j;
      out += ' '.repeat(end - i); i = end;
    } else if (two === '/*') {
      const j = src.indexOf('*/', i + 2);
      const end = j === -1 ? src.length : j + 2;
      out += src.slice(i, end).replace(/[^\n]/g, ' '); i = end;
    } else if (src[i] === "'" || src[i] === '"' || src[i] === '`') {
      const q = src[i]; let j = i + 1;
      while (j < src.length && src[j] !== q) { if (src[j] === '\\') j++; j++; }
      const end = Math.min(j + 1, src.length);
      out += src.slice(i, end).replace(/[^\n]/g, ' '); i = end;
    } else { out += src[i]; i++; }
  }
  return out;
}

// The set of values a table's outcome CHECK permits.
function checkValues(src, table) {
  const i = src.indexOf('CREATE TABLE IF NOT EXISTS ' + table + ' (');
  if (i === -1) return null;
  let d = 0, j;
  for (j = src.indexOf('(', i); j < src.length; j++) {
    if (src[j] === '(') d++;
    else if (src[j] === ')') { d--; if (d === 0) break; }
  }
  const block = src.slice(i, j + 1);
  const m = block.match(/outcome TEXT NOT NULL CHECK \(outcome IN \(([\s\S]*?)\)\)/);
  if (!m) return null;
  return new Set((m[1].match(/'([a-z_]+)'/g) || []).map((s) => s.replace(/'/g, '')));
}

// Every outcome a file emits, across BOTH writer shapes.
function emittedOutcomes(src) {
  const out = new Set();

  // Shape 1 -- a literal at the call site.
  for (const m of src.matchAll(/\blog\('([a-z_]+)'/g)) out.add(m[1]);
  for (const m of src.matchAll(/outcome:\s*'([a-z_]+)'/g)) out.add(m[1]);
  for (const m of src.matchAll(/reject\(\s*\d+\s*,\s*'([a-z_]+)'/g)) out.add(m[1]);

  // Shape 2 -- a helper taking the outcome as a PARAMETER. Find helpers whose
  // body writes `outcome: <param>`, then collect the literals their callers
  // pass in that position. Without this, a file using this shape contributes
  // nothing and the guard passes without having checked it.
  const helperDefs = [...src.matchAll(
    /function\s+(\w+)\s*\(([^)]*)\)\s*\{/g
  )];
  for (const def of helperDefs) {
    const name = def[1];
    const params = def[2].split(',').map((p) => p.trim());
    // does the body pass one of its params straight into outcome:?
    let d = 0, j;
    for (j = src.indexOf('{', def.index); j < src.length; j++) {
      if (src[j] === '{') d++;
      else if (src[j] === '}') { d--; if (d === 0) break; }
    }
    const body = src.slice(def.index, j + 1);
    const pm = body.match(/outcome:\s*(\w+)\s*[,}]/);
    if (!pm) continue;
    const idx = params.indexOf(pm[1]);
    if (idx === -1) continue;                       // not a parameter; a local
    // collect literals at that argument position in every call
    const callRe = new RegExp('\\b' + name + '\\s*\\(([^;]*?)\\)\\s*;', 'g');
    for (const call of src.matchAll(callRe)) {
      const args = splitArgs(call[1]);
      const a = (args[idx] || '').trim();
      const lm = a.match(/^'([a-z_]+)'$/);
      if (lm) out.add(lm[1]);
    }
  }
  return out;
}

// Split an argument list on top-level commas only.
function splitArgs(s) {
  const parts = [];
  let depth = 0, cur = '', q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { cur += c; if (c === q && s[i - 1] !== '\\') q = null; continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; cur += c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    if (c === ')' || c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
    cur += c;
  }
  parts.push(cur);
  return parts;
}

// Does every access-log write have a catch of ITS OWN?
//
// "Is it inside some try" is the wrong question, and asking it produced a false
// green on the exact regression this check exists to catch. The scanner handlers
// wrap their whole body in a try, so an unguarded write IS inside a try -- the
// outer one -- and that is precisely why the O3 defect produced a 500 rather
// than an uncaught crash. The outer catch caught it and turned a 401 refusal
// into a server error.
//
// The property that matters is narrower: the write must be enclosed by a try
// whose catch does NOT return a response. A catch that calls res.status(...) is
// a request-level handler; a write relying on it can change what the caller
// sees. A catch that only reports is a logging-level handler and is what these
// writes require.
function writeCanThrow(src) {
  const code = stripNonCode(src);
  const offenders = [];
  for (let i = 0; i < code.length; i++) {
    if (!code.startsWith('appendAccessLog', i)) continue;
    if (!/[\s;{}(),=>]/.test(code[i - 1] || ' ')) continue;
    const decl = code.slice(Math.max(0, i - 14), i + 18);
    if (/function\s+appendAccessLog/.test(decl)) { i += 14; continue; }
    if (!/^\s*\(/.test(code.slice(i + 15))) { i += 14; continue; }

    // Walk outward through enclosing blocks, nearest first, and find the first
    // try whose catch we can inspect.
    let depth = 0, guarded = false;
    for (let k = i; k >= 0; k--) {
      if (code[k] === '}') depth++;
      else if (code[k] === '{') {
        if (depth === 0) {
          const head = code.slice(Math.max(0, k - 8), k);
          if (/\btry\s*$/.test(head)) {
            // find this try's catch body
            let d2 = 0, e;
            for (e = k; e < code.length; e++) {
              if (code[e] === '{') d2++;
              else if (code[e] === '}') { d2--; if (d2 === 0) break; }
            }
            const cm = code.slice(e, e + 4000).match(/catch\s*\([^)]*\)\s*\{/);
            if (cm) {
              let d3 = 0, c0 = e + cm.index + cm[0].length - 1, c1;
              for (c1 = c0; c1 < code.length; c1++) {
                if (code[c1] === '{') d3++;
                else if (code[c1] === '}') { d3--; if (d3 === 0) break; }
              }
              const body = code.slice(c0, c1 + 1);
              // A catch that sends a response is a REQUEST handler, not a
              // logging guard -- a write relying on it can alter the response.
              if (!/\bres\s*\./.test(body)) { guarded = true; break; }
            }
          }
          depth = 0;
        } else depth--;
      }
    }
    if (!guarded) offenders.push(src.slice(0, i).split('\n').length);
    i += 14;
  }
  return offenders;
}

// ── self-test ───────────────────────────────────────────────────────────────
function selftest() {
  const cases = [];
  const t = (n, got, want) => cases.push({ n, ok: JSON.stringify(got) === JSON.stringify(want), got, want });

  t('checkValues reads a CHECK',
    [...checkValues("CREATE TABLE IF NOT EXISTS x (\n outcome TEXT NOT NULL CHECK (outcome IN (\n 'a',\n 'b'\n )),\n z TEXT\n);", 'x')].sort(),
    ['a', 'b']);
  t('checkValues returns null for an absent table',
    checkValues('CREATE TABLE IF NOT EXISTS y (id TEXT);', 'x'), null);

  t('emitted: literal log() call', [...emittedOutcomes("log('rejected_cert', {});")], ['rejected_cert']);
  t('emitted: outcome: literal', [...emittedOutcomes("appendAccessLog(db,{ outcome: 'authorized' });")], ['authorized']);
  t('emitted: reject(401, literal)', [...emittedOutcomes("return reject(401, 'rejected_token', null);")], ['rejected_token']);

  // The shape that would otherwise pass vacuously.
  const HELPER = `
function writeAccess(db, req, outcome, format) {
  appendAccessLog(db, { source_ip: '1', outcome: outcome, format: format });
}
writeAccess(db, req, 'authorized', 'json');
writeAccess(db, req, 'rejected_query', null);
`;
  t('emitted: helper PARAMETER traced to its call sites',
    [...emittedOutcomes(HELPER)].sort(), ['authorized', 'rejected_query']);

  t('splitArgs ignores commas inside nested calls',
    splitArgs("db, req, 'x', f(a, b), null").length, 5);

  t('writeCanThrow flags an unguarded write',
    writeCanThrow('appendAccessLog(db, {});').length > 0, true);
  t('writeCanThrow accepts a write guarded by a LOGGING catch',
    writeCanThrow('try {\n appendAccessLog(db, {});\n} catch (e) { logger.error("x"); }').length, 0);
  t('>>> writeCanThrow REJECTS a write guarded only by a RESPONSE catch <<<',
    writeCanThrow('try {\n appendAccessLog(db, {});\n} catch (e) { res.status(500).json({}); }').length, 1);
  t('...and accepts it once a logging catch is nested inside',
    writeCanThrow('try {\n try { appendAccessLog(db, {}); } catch (e) { logger.error("x"); }\n} catch (e) { res.status(500).json({}); }').length, 0);
  t('writeCanThrow ignores the function DECLARATION',
    writeCanThrow('function appendAccessLog(db, fields) {\n  return 1;\n}').length, 0);
  t('...but still flags an unguarded CALL in the same file',
    writeCanThrow('function appendAccessLog(db, f) { return 1; }\nappendAccessLog(db, {});').length, 1);
  t('writeCanThrow ignores a write named only in a comment',
    writeCanThrow('// appendAccessLog(db, {}) would be unguarded here\nconst x = 1;').length, 0);

  t('stripNonCode blanks a comment', /marker/.test(stripNonCode('// marker\nreal();')), false);
  t('stripNonCode keeps the code after it', /real\(\)/.test(stripNonCode('// marker\nreal();')), true);

  t('the registry covers 4 access logs', ACCESS_LOGS.length, 4);
  t('the registry names at least 6 writers',
    ACCESS_LOGS.reduce((n, l) => n + l.writers.length, 0) >= 6, true);

  const bad = cases.filter((c) => !c.ok);
  for (const c of cases) {
    console.log('  ' + (c.ok ? 'ok  ' : 'FAIL') + '  ' + c.n +
      (c.ok ? '' : ' (got ' + JSON.stringify(c.got) + ', want ' + JSON.stringify(c.want) + ')'));
  }
  console.log('\nself-test: ' + (cases.length - bad.length) + '/' + cases.length + ' passed');
  process.exit(bad.length ? 1 : 0);
}

if (process.argv.indexOf('--selftest') !== -1) selftest();

// ── the real run ────────────────────────────────────────────────────────────
const failures = [];

for (const log of ACCESS_LOGS) {
  const tag = (log.label ? log.label + ' ' : '') + log.table;
  let schemaSrc;
  try { schemaSrc = read(log.schema); }
  catch (_) { failures.push(`OUTCOME-COVERAGE: ${log.schema} not found`); continue; }

  const allowed = checkValues(schemaSrc, log.table);
  if (!allowed) {
    failures.push(`OUTCOME-COVERAGE: ${tag} has no outcome CHECK in ${log.schema}. An access log without a constrained outcome cannot be audited.`);
    continue;
  }

  for (const w of log.writers) {
    let src;
    try { src = read(w); }
    catch (_) { failures.push(`OUTCOME-COVERAGE: writer ${w} not found`); continue; }

    const emitted = emittedOutcomes(src);
    if (emitted.size === 0) {
      failures.push(`OUTCOME-COVERAGE: ${w} is registered as writing ${tag} but no outcome could be extracted. Either it stopped writing, or it uses a shape this guard does not understand -- and a guard that silently extracts nothing reports coverage it never checked.`);
      continue;
    }
    for (const o of emitted) {
      if (!allowed.has(o)) {
        failures.push(`OUTCOME-COVERAGE: ${w} emits '${o}' but ${tag}'s CHECK does not permit it. The INSERT throws, the audit record is lost, and on these surfaces the throw changes the HTTP status the caller receives -- turning a uniform refusal into an oracle.`);
      }
    }

    const unguarded = writeCanThrow(src);
    if (unguarded.length) {
      failures.push(`LOG-CANNOT-THROW: ${w} writes the access log outside a try/catch at line(s) ${unguarded.join(', ')}. A logging failure must never alter the response.`);
    }
  }
}

if (failures.length) {
  console.error('Access-log outcome coverage gate FAILED:\n');
  for (const f of failures) console.error('  - ' + f);
  console.error('\nAn access log is the record that answers "is something probing this');
  console.error('endpoint?". An outcome a writer can emit but the table cannot store is');
  console.error('worse than a missing log line: the INSERT throws, and the throw changes');
  console.error('what the caller sees.');
  process.exit(1);
}

const totals = ACCESS_LOGS.reduce((n, l) => n + l.writers.length, 0);
console.log(`Access-log outcome coverage gate passed: ${ACCESS_LOGS.length} access logs, ${totals} writers, every emitted outcome permitted by its CHECK and every write guarded.`);

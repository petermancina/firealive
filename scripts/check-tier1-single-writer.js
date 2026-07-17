#!/usr/bin/env node
'use strict';

// check-tier1-single-writer.js
//
// Enforces that no code seals or opens a Tier-1 column outside the domain-aware
// chokepoint (sealTier1 / openTier1). After B6h A-6 the bare encryptConfig /
// decryptConfig are deleted from both crypto modules and the raw encrypt /
// decrypt(..., 'TIER1_ENCRYPTION_KEY') shape throws at runtime. This guard makes
// both invariants CI-enforced so a future edit cannot quietly reintroduce a
// bypass.
//
// It uses a single-pass tokenizer rather than a regex stripper, for two reasons:
//   - a comment or string literal that merely mentions "encryptConfig" or the
//     TIER1 key name must NOT trip the guard (no false positives); and
//   - an aliased import such as `const { decryptConfig: foo } = require(...)`
//     must still be caught (the alias hid a real missed call site during A-6 --
//     the forensic-key reader -- so the guard tokenizes the identifier itself,
//     which the alias cannot disguise).
//
// P1-3a moved that tokenizer to scripts/lib/js-tokenizer.js so the 18th gate
// (check-no-bundle-relative-data-paths.js) uses the same one rather than a copy.
// The token stream is unchanged; this guard's --self-test is what proves it.
//
// Two violation classes:
//   1. retired-config-api : any use of the exact identifiers `encryptConfig` or
//      `decryptConfig` (the `...WithKey` cores are different identifiers and are
//      allowed). Covers calls, definitions, and aliased-import property keys.
//   2. raw-tier1-call     : a call `encrypt(...)` / `decrypt(...)` whose argument
//      list contains the string literal 'TIER1_ENCRYPTION_KEY'. Function
//      definitions are skipped for this class (a `function encrypt(` header is
//      not a call), but a reintroduced bare-config definition is still caught by
//      class 1.
//
// Scope: production code under server/ and packages/ (tooling in scripts/ is
// excluded -- this guard and the derive/golden scripts legitimately name the
// retired API). Run with --self-test to verify the detector on synthetic inputs.

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..');
const SCAN_DIRS = ['server', 'packages'];
const RETIRED = new Set(['encryptConfig', 'decryptConfig']);
const RAW = new Set(['encrypt', 'decrypt']);
const TIER1 = 'TIER1_ENCRYPTION_KEY';


// --- tokenizer -------------------------------------------------------------
// Shared with check-no-bundle-relative-data-paths.js. Emits
// { type, value, line } with type 'id' | 'str' | 'punct'; comments are skipped
// and string bodies never match an identifier. See that module's header.
const { tokenize } = require('./lib/js-tokenizer');

// --- detector --------------------------------------------------------------
function scan(src) {
  const toks = tokenize(src);
  const violations = [];
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    if (t.type !== 'id') continue;

    // class 1: the retired identifiers, in any position
    if (RETIRED.has(t.value)) {
      violations.push({ kind: 'retired-config-api', id: t.value, line: t.line });
      continue;
    }

    // class 2: raw encrypt/decrypt(...) carrying the TIER1 literal
    if (RAW.has(t.value)) {
      const prev = toks[k - 1];
      if (prev && prev.type === 'id' && prev.value === 'function') continue; // a definition, not a call
      const open = toks[k + 1];
      if (!open || open.type !== 'punct' || open.value !== '(') continue;
      let depth = 0;
      for (let m = k + 1; m < toks.length; m++) {
        const u = toks[m];
        if (u.type === 'punct' && u.value === '(') depth++;
        else if (u.type === 'punct' && u.value === ')') { depth--; if (depth === 0) break; }
        else if (u.type === 'str' && u.value === TIER1) {
          violations.push({ kind: 'raw-tier1-call', id: t.value, line: t.line });
          break;
        }
      }
    }
  }
  return violations;
}

// --- file walk -------------------------------------------------------------
function walk(dir, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.isFile() && e.name.endsWith('.js')) out.push(p);
  }
  return out;
}

// --- self-test -------------------------------------------------------------
function selfTest() {
  const cases = [
    ['clean chokepoint + cores',
      "const a = sealTier1('t.c', v); const b = openTier1('t.c', r);\n"
      + "const c = enc.encryptWithKey(d, k); const d2 = gd.encryptConfigWithKey(o, kek);\n"
      + "const e = encrypt(x, 'TIER3_ENCRYPTION_KEY');", 0],
    ['bare encryptConfig call', "const w = encryptConfig({ a: 1 });", 1],
    ['bare decryptConfig call', "const w = decryptConfig(buf);", 1],
    ['raw encrypt TIER1', "const z = encrypt(data, 'TIER1_ENCRYPTION_KEY');", 1],
    ['raw decrypt TIER1 via member', "obj = enc.decrypt(buffer, 'TIER1_ENCRYPTION_KEY');", 1],
    ['aliased import of decryptConfig', "const { decryptConfig: foo } = require('./x');", 1],
    ['comment mentioning both is safe',
      "// encryptConfig is retired; never call encrypt(x, 'TIER1_ENCRYPTION_KEY')\nconst ok = 1;", 0],
    ['string mentioning encryptConfig is safe', "log('encryptConfig disabled');", 0],
    ['reintroduced definition is caught',
      "function encryptConfig(d) { return encrypt(d, 'TIER1_ENCRYPTION_KEY'); }", 2],
  ];
  let failed = 0;
  for (const [name, src, expected] of cases) {
    const got = scan(src).length;
    const ok = got === expected;
    if (!ok) { failed++; console.error(`  FAIL self-test: ${name} -- expected ${expected}, got ${got}`); }
  }
  if (failed) {
    console.error(`\nSingle-writer guard self-test FAILED (${failed} case(s)).`);
    process.exit(1);
  }
  console.log('Single-writer guard self-test passed (detector flags bypasses, ignores comments/strings).');
}

// --- main ------------------------------------------------------------------
function main() {
  if (process.argv.includes('--self-test')) { selfTest(); return; }

  const files = [];
  for (const d of SCAN_DIRS) walk(path.join(REPO_ROOT, d), files);

  const problems = [];
  for (const f of files) {
    let src;
    try { src = fs.readFileSync(f, 'utf8'); } catch { continue; }
    for (const v of scan(src)) {
      problems.push({ file: path.relative(REPO_ROOT, f), ...v });
    }
  }

  if (problems.length) {
    console.error('Tier-1 single-writer guard FAILED: a registered column may be sealed outside the chokepoint.\n');
    for (const p of problems) {
      const msg = p.kind === 'retired-config-api'
        ? `uses the retired ${p.id} -- seal registered columns via sealTier1/openTier1, or wrap non-column data with ${p.id}WithKey + an explicit key`
        : `calls ${p.id}(..., 'TIER1_ENCRYPTION_KEY') -- the raw Tier-1 shape is retired; use the chokepoint`;
      console.error(`  ${p.file}:${p.line}  ${msg}`);
    }
    console.error(`\n${problems.length} violation(s).`);
    process.exit(1);
  }

  console.log(`Tier-1 single-writer guard passed: no bare config API or raw TIER1 shape in ${files.length} files.`);
}

main();

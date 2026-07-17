'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE -- shared single-pass JavaScript tokenizer  (P1-3a)
// ═══════════════════════════════════════════════════════════════════════════
//
// WHY THIS EXISTS
//
// Source-scanning CI gates must decide whether an identifier or a literal
// really appears in code, or merely inside a comment or a string. A regex
// stripper cannot do that reliably: it desynchronises on quote-bearing regex
// literals, on apostrophes inside comments, and on nested quotes.
//
// This is not a hypothetical. The B6d HA guards used a regex comment/string
// stripper; it silently skipped roughly two-thirds of ha-pairing.js on BOTH
// servers while reporting PASS. Replacing it with a single-pass tokenizer
// immediately exposed a real defect the guard had been blind to.
//
// The tokenizer was written for that fix and has lived inside
// scripts/check-tier1-single-writer.js ever since. P1-3a extracts it here so a
// second gate (scripts/check-no-bundle-relative-data-paths.js) can use the same
// one rather than carry a copy. Two copies of the module this project has
// already been burned by drifting is how the next blind guard gets written --
// the same failure class as four copies of a severity table drifting apart.
//
// WHAT IT EMITS
//
// A flat array of { type, value, line }, where type is one of:
//
//   'id'    an identifier. `path`, `join`, `__dirname`, `function`.
//   'str'   a string body, escapes folded, quotes dropped. Single, double, and
//           template literals all produce this type. A string NEVER matches an
//           identifier, so a quoted "encryptConfig" is not a violation and a
//           commented path.join(__dirname, ...) is not a site.
//   'punct' only '(' and ')'.
//
// Line and block comments are skipped entirely and emit nothing.
//
// WHY ONLY PARENTHESES ARE PUNCTUATION
//
// Parentheses are emitted because call-argument scanning needs them: a consumer
// finds a callee, checks that the next token opens a call, then walks to the
// matching close counting depth. Dots and commas are deliberately NOT emitted,
// and consumers must not depend on them.
//
// That constraint is what makes a consumer shape-independent, which is the
// point. `path.join(__dirname, 'x')`, `p.join(__dirname, 'x')`,
// `pathMod.join(__dirname, 'x')`, and `require('path').join(__dirname, 'x')`
// all tokenize to an id `__dirname` immediately preceded by a punct '(' --
// so a consumer anchored on __dirname sees all four, while a consumer anchored
// on the string "path.join" sees only the first. All four shapes are present in
// this codebase.
//
// WHAT IT IS NOT
//
// This is not a parser. It has no grammar, no AST, and no notion of scope,
// statements, or expressions. It cannot tell a call from a definition -- a
// consumer that needs that must check the preceding token itself. It does not
// distinguish a regex literal from division; it only guarantees that quotes and
// comments never leak their contents into the identifier stream, which is the
// property the gates depend on.
//
// PROVENANCE
//
// Extracted verbatim from scripts/check-tier1-single-writer.js (its tokenize
// function) with no behavioural change. That gate's own --self-test is the
// proof the extraction is faithful: it drives synthetic fixtures through the
// detector and asserts an exact violation count per case, including negative
// cases for a comment and a string that merely mention the retired identifiers.
// If this file altered the token stream, that self-test would fail.
// ═══════════════════════════════════════════════════════════════════════════

// Emits { type, value, line }. type is one of 'id' | 'str' | 'punct'. Line and
// block comments are skipped. String bodies are captured (with escapes folded)
// so a literal can be matched, but string tokens never match an identifier, so
// a quoted "encryptConfig" is not a violation.
function tokenize(src) {
  const toks = [];
  let i = 0;
  let line = 1;
  const n = src.length;
  const isIdStart = (c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c === '_' || c === '$';
  const isId = (c) => isIdStart(c) || (c >= '0' && c <= '9');
  while (i < n) {
    const c = src[i];
    if (c === '\n') { line++; i++; continue; }
    // line comment
    if (c === '/' && src[i + 1] === '/') {
      i += 2;
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    // block comment
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') line++;
        i++;
      }
      i += 2;
      continue;
    }
    // string (single, double, or template -- we only read the raw body)
    if (c === "'" || c === '"' || c === '`') {
      const q = c;
      const startLine = line;
      i++;
      let val = '';
      while (i < n) {
        if (src[i] === '\\') { val += src[i + 1] || ''; i += 2; continue; }
        if (src[i] === q) { i++; break; }
        if (src[i] === '\n') line++;
        val += src[i];
        i++;
      }
      toks.push({ type: 'str', value: val, line: startLine });
      continue;
    }
    // identifier
    if (isIdStart(c)) {
      let j = i + 1;
      while (j < n && isId(src[j])) j++;
      toks.push({ type: 'id', value: src.slice(i, j), line });
      i = j;
      continue;
    }
    // parentheses matter for call-argument scanning
    if (c === '(' || c === ')') {
      toks.push({ type: 'punct', value: c, line });
      i++;
      continue;
    }
    i++;
  }
  return toks;
}

module.exports = { tokenize };

'use strict';

// FireAlive -- shared Markdown reader for the in-app Help surfaces.
//
// Parses the subset of Markdown that FEATURE-GUIDE.md actually uses into a
// NEUTRAL NODE TREE. It does not produce HTML, and it does not import React.
//
// WHY A NODE TREE AND NOT AN HTML STRING. `dangerouslySetInnerHTML` appears ZERO
// times across all three Electron apps -- Management Console, Analyst Client and
// Global Dashboard. That is a maintained property, not an accident, and
// note-sanitizer.js already states the reasoning for the abuse-review UI: the
// console "renders decrypted notes as inert plain text (React text nodes, no
// HTML/markdown sink), so script execution is impossible there".
//
// The conventional build for this feature -- a Markdown-to-HTML library plus a
// sanitizer plus dangerouslySetInnerHTML -- would spend that property to save a
// few hundred lines, and would do it for content READ OFF DISK AT RUNTIME. A
// sanitizer is a deny-list of things known to be dangerous today. A tree of text
// nodes has nothing to inject into, because no HTML string is ever constructed
// at any stage. This module is the second kind.
//
// WHY IT RETURNS DATA RATHER THAN REACT ELEMENTS. Each app renders the tree with
// its own React and its own styles. Keeping the parser free of React means it can
// be tested in plain Node, and means `packages/shared` does not take a React
// dependency it would otherwise need in three places.
//
// WHAT THIS DELIBERATELY DOES NOT SUPPORT: raw HTML blocks, code fences and
// blockquotes. FEATURE-GUIDE.md contains none of them (verified: 0 fences, 0
// blockquotes). Anything that looks like an HTML tag is carried through as
// LITERAL TEXT, which is what a reader should see if a tag ever appears in a
// document that is not supposed to contain one.
//
// TROJAN SOURCE. The guide is read from disk at runtime, so a writer who can
// reach the file controls what an operator reads. Bidirectional and zero-width
// controls could make a security instruction DISPLAY differently from what it
// says -- reversing "never" and "always" in a sentence about key custody, for
// instance. The same character classes note-sanitizer.js uses are applied here,
// deliberately reusing that module's analysis rather than inventing a second and
// weaker set.

// C0/C1 control characters, excluding tab (\u0009) and newline (\u000A).
// Identical to note-sanitizer.js CONTROL.
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
// Zero-width characters and bidirectional formatting/override/isolate controls.
// Identical to note-sanitizer.js ZERO_WIDTH_BIDI.
const ZERO_WIDTH_BIDI = /[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/g;

// Only these schemes may become a live link. Everything else renders as plain
// text, keeping its label so the reader still sees what was written.
const SAFE_LINK = /^https?:\/\//i;

/**
 * Normalise a raw source string before parsing.
 *
 * NFC first so the text is canonical, then strip the two control classes. Order
 * matters: normalising afterwards could reintroduce a composed form built from
 * characters that were meant to be stripped.
 */
function normalise(src) {
  if (typeof src !== 'string') return '';
  let s = src;
  try { s = s.normalize('NFC'); } catch (_e) { /* older runtimes: fall through */ }
  return s.replace(CONTROL, '').replace(ZERO_WIDTH_BIDI, '');
}

// ── inline parsing ──────────────────────────────────────────────────────────
//
// Order is significant. Code spans are taken FIRST and their contents are never
// re-parsed, so `**not bold**` inside backticks stays literal -- which matters,
// because the guide documents literal Markdown and shell syntax in code spans.

function inlineText(v) { return { t: 'text', v: v }; }

function parseInline(s) {
  const out = [];
  let i = 0;
  let buf = '';
  const flush = () => { if (buf) { out.push(inlineText(buf)); buf = ''; } };

  while (i < s.length) {
    // `code`
    if (s[i] === '`') {
      const end = s.indexOf('`', i + 1);
      if (end !== -1) {
        flush();
        out.push({ t: 'code', v: s.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    }
    // [label](href)
    if (s[i] === '[') {
      const close = s.indexOf(']', i + 1);
      if (close !== -1 && s[close + 1] === '(') {
        const paren = s.indexOf(')', close + 2);
        if (paren !== -1) {
          const label = s.slice(i + 1, close);
          const href = s.slice(close + 2, paren);
          flush();
          if (SAFE_LINK.test(href)) {
            out.push({ t: 'link', href: href, children: parseInline(label) });
          } else {
            // Not a scheme we will make clickable. The label is still shown, and
            // the target is shown as text so nothing is hidden from the reader --
            // a link silently dropped is worse than one visibly inert.
            out.push(inlineText(label + ' (' + href + ')'));
          }
          i = paren + 1;
          continue;
        }
      }
    }
    // **bold**
    if (s[i] === '*' && s[i + 1] === '*') {
      const end = s.indexOf('**', i + 2);
      if (end !== -1) {
        flush();
        out.push({ t: 'b', children: parseInline(s.slice(i + 2, end)) });
        i = end + 2;
        continue;
      }
    }
    // *italic* -- single asterisk, and only when it is not part of a **pair**
    if (s[i] === '*' && s[i + 1] !== '*') {
      const end = s.indexOf('*', i + 1);
      if (end !== -1 && s[end + 1] !== '*') {
        flush();
        out.push({ t: 'i', children: parseInline(s.slice(i + 1, end)) });
        i = end + 1;
        continue;
      }
    }
    buf += s[i];
    i += 1;
  }
  flush();
  return out;
}

// ── block parsing ───────────────────────────────────────────────────────────

function splitRow(line) {
  // Trim the optional outer pipes by SLICING rather than replacing. Both patterns
  // were anchored, so a non-global replace was already complete -- but slicing is
  // what "drop the delimiter" actually means, and it leaves no regex replace for a
  // reader (or a scanner) to have to reason about.
  let t = line.trim();
  if (t.startsWith('|')) t = t.slice(1);
  if (t.endsWith('|')) t = t.slice(0, -1);
  return t.split('|').map((c) => c.trim());
}

/**
 * Drop a leading marker matched by an anchored pattern.
 *
 * The pattern must be anchored at the start; `exec` therefore matches at most
 * once, and the length of that match is exactly how much to remove.
 */
function stripPrefix(line, re) {
  const m = re.exec(line);
  return m ? line.slice(m[0].length) : line;
}

/**
 * Is this the `|---|---|` row that turns the line above it into a table header?
 *
 * A CHARACTER SCAN, not a regular expression, and deliberately. The pattern this
 * replaced -- /^\s*\|?[\s:-]*-[\s:|-]*\|?\s*$/ -- put '-' inside the first class,
 * standalone, AND inside the second, so a run of dashes could be divided between
 * the three in a number of ways that grows with its length. Measured before the
 * change: 1,000 dashes 4ms, 2,000 15ms, 4,000 52ms, 8,000 208ms, 16,000 834ms.
 * Quadratic, on a line read from a file at runtime.
 *
 * A scan is linear because it looks at each character once and never reconsiders.
 * That is a property of the shape rather than of the pattern being carefully
 * written, which is the same reason this module builds a node tree instead of an
 * HTML string.
 */
/**
 * `### Title` -> `{ level: 3, text: 'Title' }`, or null when the line is not a
 * heading. Hash characters are counted, not matched.
 */
function headingOf(line) {
  let n = 0;
  while (n < line.length && line[n] === '#') n += 1;
  if (n < 1 || n > 6 || n >= line.length) return null;
  const c = line[n];
  if (c !== ' ' && c !== '\t') return null;
  return { level: n, text: line.slice(n).trim() };
}

function isDivider(line) {
  let sawDash = false;
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i];
    if (c === '-') { sawDash = true; continue; }
    // The only other characters a divider row may contain: alignment colons,
    // cell separators, and padding.
    if (c !== ':' && c !== '|' && c !== ' ' && c !== '\t') return false;
  }
  return sawDash;
}

/**
 * Parse a Markdown fragment into a block-level node tree.
 *
 * @param {string} src
 * @returns {Array<object>} blocks
 */
function parseMarkdown(src) {
  const lines = normalise(src).split('\n');
  const blocks = [];
  let para = [];

  const flushPara = () => {
    if (!para.length) return;
    blocks.push({ t: 'p', children: parseInline(para.join(' ').trim()) });
    para = [];
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed === '') { flushPara(); continue; }

    // horizontal rule
    if (/^-{3,}$/.test(trimmed)) { flushPara(); blocks.push({ t: 'hr' }); continue; }

    // heading. Counted rather than matched: /^(#{1,6})\s+(.*)$/ leaves \s+ and
    // (.*) able to claim the same spaces, which is the ambiguity CodeQL flags as
    // polynomial. Counting the hashes and slicing has no such choice to make.
    const hd = headingOf(trimmed);
    if (hd) {
      flushPara();
      blocks.push({ t: 'h', level: hd.level, children: parseInline(hd.text) });
      continue;
    }

    // table: a row followed by a divider row
    if (trimmed.startsWith('|') && i + 1 < lines.length && isDivider(lines[i + 1])) {
      flushPara();
      const head = splitRow(trimmed);
      const rows = [];
      i += 2;
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        rows.push(splitRow(lines[i].trim()).map(parseInline));
        i += 1;
      }
      i -= 1;
      blocks.push({ t: 'table', head: head.map(parseInline), rows: rows });
      continue;
    }

    // unordered list
    if (/^[-*]\s+/.test(trimmed)) {
      flushPara();
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(parseInline(stripPrefix(lines[i], /^\s*[-*]\s+/)));
        i += 1;
      }
      i -= 1;
      blocks.push({ t: 'ul', items: items });
      continue;
    }

    // ordered list. FEATURE-GUIDE writes every item as "1." and relies on the
    // renderer to number them, which is standard Markdown practice -- so the
    // written number is deliberately ignored.
    if (/^\d+\.\s+/.test(trimmed)) {
      flushPara();
      const items = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(parseInline(stripPrefix(lines[i], /^\s*\d+\.\s+/)));
        i += 1;
      }
      i -= 1;
      blocks.push({ t: 'ol', items: items });
      continue;
    }

    para.push(trimmed);
  }
  flushPara();
  return blocks;
}

/**
 * Split a whole guide into its `###` sections, keyed by heading text.
 *
 * The section index is DERIVED FROM THE FILE, never hardcoded a second time.
 * That is the whole point: a hardcoded index is what let three apps drift to 93
 * unmapped tabs between them.
 *
 * @param {string} src
 * @returns {{order: string[], sections: Object<string,{group: string, body: string, line: number}>}}
 */
function indexSections(src) {
  const lines = normalise(src).split('\n');
  const sections = {};
  const order = [];
  let group = null;
  let key = null;
  let buf = [];
  let startLine = 0;

  const close = () => {
    if (key === null) return;
    sections[key] = { group: group, body: buf.join('\n').trim(), line: startLine };
    buf = [];
  };

  for (let i = 0; i < lines.length; i += 1) {
    const l = lines[i];
    if (/^##\s+/.test(l) && !/^###/.test(l)) {
      close(); key = null;
      group = stripPrefix(l, /^##\s+/).trim();
      continue;
    }
    if (/^###\s+/.test(l) && !/^####/.test(l)) {
      close();
      key = stripPrefix(l, /^###\s+/).trim();
      order.push(key);
      startLine = i + 1;
      continue;
    }
    if (key !== null) buf.push(l);
  }
  close();
  return { order: order, sections: sections };
}

module.exports = {
  parseMarkdown,
  indexSections,
  normalise,
  // exported for the gate's self-test
  parseInline,
  CONTROL,
  ZERO_WIDTH_BIDI,
  SAFE_LINK,
};

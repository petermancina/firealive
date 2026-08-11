'use strict';

// FireAlive MC -- main-process reader for the in-app Help content.
//
// WHY THE MAIN PROCESS READS THIS AND THE RENDERER DOES NOT. The Management
// Console's renderer runs with `nodeIntegration: false`, `contextIsolation:
// true` and a CSP of `default-src 'self'` (index.html), so it has no `require`,
// no `fs`, and cannot fetch a file:// URL. That is a deliberate hardening of the
// window, and Help is not a good enough reason to weaken any part of it.
//
// So the guide is read here, once, and the renderer receives PARSED DATA over a
// single whitelisted IPC channel. It never receives a path, and it never sends
// one.
//
// WHY IPC AND NOT AN HTTP ROUTE. The obvious alternative is a `/api/help/:topic`
// endpoint on the Regional Server. Two reasons against it, and the first is the
// one that matters:
//
//   HELP MUST WORK WHEN THE SERVER DOES NOT. An operator opens Help precisely
//   when something is wrong -- the server will not start, the certificate is
//   rejected, the config lock is stuck. Help that requires a healthy server is
//   help that is missing whenever it is needed.
//
//   A `:topic` PATH PARAMETER IS A TRAVERSAL SURFACE. It has to be validated
//   against something, and the validation has to be right forever. Here the
//   renderer sends a SECTION NAME that is looked up in a map built from the
//   file's own headings; a name that is not a key returns nothing. There is no
//   path to traverse because no path ever crosses the boundary.
//
// WHAT IS SENT ACROSS THE BOUNDARY. A parsed node tree of text and structure --
// never Markdown source, never HTML, never a filename. The renderer turns that
// tree into React elements. No stage of this produces an HTML string.
//
// THE FILE IS READ ONCE AND CACHED. It ships inside the asar archive and cannot
// change while the app runs, so re-reading it per request would buy nothing. A
// read failure is reported as a read failure rather than as an empty guide: a
// Help tab that silently shows nothing looks identical to a Help tab whose
// content was never written, and those need different responses from an operator.

const fs = require('fs');
const path = require('path');
const { parseMarkdown, indexSections } = require('@firealive/shared/help-markdown');
const { sectionForTab, NOT_FOR_MC } = require('./help-sections');

// The guide ships alongside main.js in the packaged app. `frontend/build.files`
// copies it in; check-help-coverage asserts that entry still exists, because a
// dropped file would leave every Help lookup failing at runtime with everything
// else still green.
const GUIDE_FILENAME = 'FEATURE-GUIDE.md';

let cache = null;

function guidePath() {
  // Packaged: alongside main.js inside app.asar. Development: two levels up at
  // the repository root. Both are checked because the second is where it lives
  // for anyone running `npm start` from a checkout.
  const local = path.join(__dirname, GUIDE_FILENAME);
  if (fs.existsSync(local)) return local;
  return path.join(__dirname, '..', GUIDE_FILENAME);
}

/**
 * Read and index the guide. Cached; the file cannot change while the app runs.
 *
 * @returns {{ok: true, order: string[], sections: object} | {ok: false, error: string}}
 */
function loadGuide() {
  if (cache) return cache;
  let src;
  try {
    src = fs.readFileSync(guidePath(), 'utf8');
  } catch (e) {
    // Reported, not swallowed. See the header: an unreadable guide and an
    // unwritten guide look the same to a reader and are not the same problem.
    cache = {
      ok: false,
      error: 'The in-app guide could not be read from this installation. '
        + 'The application is otherwise unaffected; reinstalling restores it.',
    };
    return cache;
  }
  const idx = indexSections(src);
  cache = { ok: true, order: idx.order, sections: idx.sections };
  return cache;
}

/**
 * The parsed help for one tab.
 *
 * @param {string} tabId
 * @param {string} navLabel
 * @returns {object} `{ok, title, group, blocks}` or `{ok:false, reason}`
 */
function helpForTab(tabId, navLabel) {
  const g = loadGuide();
  if (!g.ok) return { ok: false, reason: 'unreadable', error: g.error };

  const heading = sectionForTab(tabId, navLabel);

  // A heading on the not-for-this-app list is a mapping bug, not a missing
  // document, and it is answered differently: rendering it would show text about
  // a different product surface, which is worse than showing nothing.
  if (Object.prototype.hasOwnProperty.call(NOT_FOR_MC, heading)) {
    return { ok: false, reason: 'not-for-this-app', heading: heading };
  }

  const sec = g.sections[heading];
  if (!sec) return { ok: false, reason: 'no-section', heading: heading };

  return {
    ok: true,
    title: heading,
    group: sec.group,
    blocks: parseMarkdown(sec.body),
  };
}

/**
 * Search every section for a term, for the Help tab's search box.
 *
 * Matching is a plain case-insensitive substring test on the section's own text.
 * NOT a regular expression: the query comes from a text box, and a
 * caller-supplied pattern is a denial-of-service surface. The internal query
 * tool made the same choice in v1.0.57 for the same reason, and there is no
 * ReDoS-safe regular-expression engine to reach for instead.
 *
 * @param {string} term
 * @param {number} [limit]
 * @returns {Array<{title: string, group: string, snippet: string}>}
 */
function searchGuide(term, limit) {
  const g = loadGuide();
  if (!g.ok) return [];
  const q = String(term || '').trim().toLowerCase();
  if (q.length < 2) return [];
  const max = typeof limit === 'number' && limit > 0 ? limit : 25;
  const out = [];
  for (const title of g.order) {
    if (out.length >= max) break;
    if (Object.prototype.hasOwnProperty.call(NOT_FOR_MC, title)) continue;
    const sec = g.sections[title];
    const hay = (title + '\n' + sec.body).toLowerCase();
    const at = hay.indexOf(q);
    if (at === -1) continue;
    // A window of the surrounding text so the operator can see WHY it matched.
    const body = sec.body;
    const bodyAt = body.toLowerCase().indexOf(q);
    const start = bodyAt === -1 ? 0 : Math.max(0, bodyAt - 60);
    out.push({
      title: title,
      group: sec.group,
      // Whitespace collapsed by split/join rather than a regex replace. The
      // result is identical; there is simply no replace for a scanner to have to
      // reason about, and this is a snippet shown to an operator, not a sanitizer.
      snippet: (start > 0 ? '...' : '') + body.slice(start, start + 180).split(/\s+/).join(' ').trim(),
    });
  }
  return out;
}

/**
 * The opening sentence of a section, for the index.
 *
 * Derived from the guide rather than written a second time. The old Help tab kept
 * its own one-line description per screen, and those are exactly what drifted --
 * fifty screens ended up with none and a third of the rest no longer matched the
 * guide. A summary taken from the text it summarises cannot disagree with it.
 */
function summarise(body) {
  if (!body) return '';
  // Skip the bold lead-in ("What it's for:") and take the sentence after it.
  let t = body.split('\n')[0] || '';
  const colon = t.indexOf(':**');
  if (colon !== -1) t = t.slice(colon + 3);
  t = t.replace(/\*\*/g, '').trim();
  const stop = t.search(/\.\s/);
  if (stop !== -1 && stop < 240) t = t.slice(0, stop + 1);
  return t.length > 240 ? t.slice(0, 237) + '...' : t;
}

/** Every section title, grouped and summarised, for the Help tab's index view. */
function guideIndex() {
  const g = loadGuide();
  if (!g.ok) return { ok: false, error: g.error };
  const groups = {};
  for (const title of g.order) {
    if (Object.prototype.hasOwnProperty.call(NOT_FOR_MC, title)) continue;
    const grp = g.sections[title].group || 'Other';
    if (!groups[grp]) groups[grp] = [];
    groups[grp].push({ title: title, summary: summarise(g.sections[title].body) });
  }
  return { ok: true, groups: groups };
}

/** Test seam: drop the cache so a test can point at a different file. */
function _resetCache() { cache = null; }

/**
 * The Common Issues section, rendered as its own card.
 *
 * The Help tab this replaced ended with a short troubleshooting block, and H1
 * dropped it. A feature description answers "what is this screen"; it does not
 * answer "why isn't it working", and the second question is the one an operator
 * has when they open Help. Kept in the guide rather than hardcoded, so it is
 * maintained alongside everything else.
 */
function commonIssues() {
  const g = loadGuide();
  if (!g.ok) return null;
  const sec = g.sections['Common Issues'];
  if (!sec) return null;
  return { title: 'Common Issues', blocks: parseMarkdown(sec.body) };
}

module.exports = {
  GUIDE_FILENAME,
  commonIssues,
  summarise,
  guidePath,
  loadGuide,
  helpForTab,
  searchGuide,
  guideIndex,
  _resetCache,
};

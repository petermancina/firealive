#!/usr/bin/env node
//
// FIREALIVE -- in-app Help coverage guard (CI)  [H1]
//
// H1 found that 93 of 144 nav tabs across the three desktop apps had NO help
// entry of any kind -- the Management Console 50 of 95, the Global Dashboard 29
// of 35, and the Analyst Client's Help panel rendered ZERO entries behind a
// button that opened it. Only 33 of the MC's 45 hand-written entries still
// matched a section in FEATURE-GUIDE.md, the document they were written from.
//
// Three apps drifted the same way, independently, for one reason: NOTHING FAILED
// WHEN A TAB SHIPPED WITHOUT HELP. Every phase added tabs; no phase was ever
// stopped for leaving them undocumented. Fixing the 93 without fixing that
// produces the same 93 again, and H1 would be repeated in six months.
//
// So this gate is the deliverable, and the mapping is what it checks. Four
// invariants, each silent when broken:
//
//   1. EVERY NAV TAB RESOLVES TO A REAL GUIDE SECTION. A new tab with no section
//      fails the build in the phase that adds it, which is the only moment the
//      person who knows what it does is available to write about it.
//
//   2. NO TAB RESOLVES TO A FORBIDDEN SECTION. Some headings document a
//      different app -- the GD-scoped placeholder covering 14 GD tabs, and the
//      AC-side Helper Pay view. Rendering one of those in the MC shows text
//      about a product surface the operator is not looking at, which is worse
//      than showing nothing because it reads as authoritative.
//
//   3. EVERY DECLARED ALIAS POINTS AT A SECTION THAT EXISTS. A rename in the
//      guide silently orphans an alias; the tab then falls back to nothing.
//      Catching it here means a guide edit cannot quietly break the console.
//
//   4. THE GUIDE IS ACTUALLY SHIPPED. The Help tab reads FEATURE-GUIDE.md at
//      runtime from inside the packaged app. Drop it from `build.files` and
//      every gate still passes, every test still runs, and Help is empty in the
//      installer while working perfectly in development. That is the failure
//      this phase started from: the guide's own header claimed it was bundled
//      with every distribution, and it was bundled with none.
//
// WHAT THIS GATE DELIBERATELY DOES NOT DO: judge whether a section is any good.
// It cannot, and pretending otherwise would be the false-green this project
// keeps finding. It asserts that every tab points somewhere real, and that the
// something is shipped.
//
// Run:  node scripts/check-help-coverage.js
//       node scripts/check-help-coverage.js --selftest
//
// AGPL-3.0-or-later
//

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// Apps whose Help is wired to the guide. H2 adds the Analyst Client and H3 the
// Global Dashboard; until then they are absent here rather than listed and
// skipped, because a skipped entry looks the same as a passing one in output.
const APPS = [
  {
    name: 'mc',
    jsx: 'frontend/firealive-mc.jsx',
    map: 'frontend/help-sections.js',
    pkg: 'frontend/package.json',
    forbiddenKey: 'NOT_FOR_MC',
  },
];

const GUIDE = 'FEATURE-GUIDE.md';

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

/** `###` headings in the guide, in order. Derived, never hardcoded. */
function guideSections(src) {
  const out = {};
  const order = [];
  const dupes = [];
  let group = null;
  for (const line of src.split('\n')) {
    if (/^##\s+/.test(line) && !/^###/.test(line)) {
      group = line.replace(/^##\s+/, '').trim();
    } else if (/^###\s+/.test(line) && !/^####/.test(line)) {
      const k = line.replace(/^###\s+/, '').trim();
      // A repeated heading is not a stylistic matter. Sections are looked up BY
      // NAME, so the second occurrence silently replaces the first and every tab
      // mapped to that name reads the wrong document -- with the mapping still
      // resolving and every check still green. H1 found five such pairs, each
      // documenting a DIFFERENT APP: an MC operator on Certifications was being
      // shown the analyst's registration flow.
      if (Object.prototype.hasOwnProperty.call(out, k)) dupes.push(k);
      out[k] = group;
      order.push(k);
    }
  }
  return { map: out, order: order, dupes: dupes };
}

/**
 * Nav tabs, read from the app's own nav array.
 *
 * Parsed from the source rather than from a list kept beside it, for the same
 * reason the section index is derived: a second list is a second thing to forget
 * to update, and forgetting is the defect this gate exists to catch.
 */
function navTabs(src) {
  const at = src.indexOf('{cat:"');
  if (at === -1) return [];
  let start = src.lastIndexOf('[', at);
  let depth = 0;
  let end = -1;
  for (let i = start; i < src.length; i += 1) {
    if (src[i] === '[') depth += 1;
    else if (src[i] === ']') {
      depth -= 1;
      if (depth === 0) { end = i; break; }
    }
  }
  if (end === -1) return [];
  const nav = src.slice(start, end + 1);
  const out = [];
  const re = /\{id:"([a-z0-9_]+)",label:"([^"]+)"/g;
  let m;
  while ((m = re.exec(nav)) !== null) out.push({ id: m[1], label: m[2] });
  return out;
}

/**
 * Tabs that RENDER but carry no nav entry.
 *
 * `help_mc` is reached from a button rather than the nav array, so a nav-only
 * check could not see it -- and neither could it see any future tab added the
 * same way. These have no label to fall back on, so each must carry an explicit
 * alias; that is the correct demand rather than a limitation, because a tab with
 * no label cannot be resolved by name at all.
 */
function renderedTabs(src) {
  const out = new Set();
  const re = /\{tab==="([a-z0-9_]+)"/g;
  let m;
  while ((m = re.exec(src)) !== null) out.add(m[1]);
  return out;
}

/** Is the guide listed in this app's electron-builder file set? */
function shipsGuide(pkgJson) {
  const files = ((pkgJson.build || {}).files) || [];
  for (const entry of files) {
    if (typeof entry === 'string' && entry.indexOf(GUIDE) !== -1) return true;
    if (entry && typeof entry === 'object') {
      const filter = [].concat(entry.filter || []);
      if (filter.some((f) => String(f).indexOf(GUIDE) !== -1)) return true;
    }
  }
  return false;
}

function selftest() {
  const cases = [];
  const t = (n, got, want) => cases.push({ n, ok: JSON.stringify(got) === JSON.stringify(want), got, want });

  const g = guideSections('## Group A\n### One\ntext\n### Two\n## Group B\n### Three\n#### Not this\n');
  t('>>> a repeated heading is CAUGHT <<<',
    guideSections('### Dup\n### Dup\n').dupes, ['Dup']);
  t('...and distinct headings are not flagged', g.dupes, []);
  t('indexes ### headings only', g.order, ['One', 'Two', 'Three']);
  t('#### is not a section', Object.keys(g.map).indexOf('Not this'), -1);
  t('tracks the owning ## group', g.map.Three, 'Group B');

  const nav = navTabs('const NAV=[{cat:"a",label:"A"},{id:"x",label:"Ex"},{id:"y",label:"Why"}];');
  t('reads tabs from the nav array', nav.map((x) => x.id), ['x', 'y']);
  t('...with their labels', nav[1].label, 'Why');
  t('no nav array -> no tabs, not a crash', navTabs('const q=1;'), []);
  t('>>> finds tabs that render without a nav entry <<<',
    Array.from(renderedTabs('{tab==="alpha"&&(<div>{tab==="beta"&&(<div>')).sort(), ['alpha', 'beta']);

  t('>>> detects the guide in a plain files entry <<<',
    shipsGuide({ build: { files: ['main.js', 'FEATURE-GUIDE.md'] } }), true);
  t('>>> detects it in a {from,to,filter} entry <<<',
    shipsGuide({ build: { files: ['main.js', { from: '../', to: '.', filter: ['FEATURE-GUIDE.md'] }] } }), true);
  t('>>> MISSING guide is caught -- the silent regression <<<',
    shipsGuide({ build: { files: ['main.js', 'app.js'] } }), false);
  t('no build block at all is caught', shipsGuide({}), false);
  t('a filter that does not name it is caught',
    shipsGuide({ build: { files: [{ from: '../', to: '.', filter: ['README.md'] }] } }), false);

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
let checked = 0;

let guide;
try {
  guide = guideSections(read(GUIDE));
} catch (e) {
  console.error('Help coverage gate FAILED: cannot read ' + GUIDE + ' -- ' + e.message);
  process.exit(1);
}

// 0. Heading names are unique. Checked first, because everything below looks up
// sections BY NAME: with a collision present, the rest of this gate would report
// success while tabs resolved to whichever section happened to come last.
if (guide.dupes.length) {
  for (const d of guide.dupes) {
    problems.push(GUIDE + ': "### ' + d + '" appears more than once. Sections are looked up by '
      + 'name, so the later one silently replaces the earlier and any tab mapped to it reads the '
      + 'wrong document. Name them for what they document -- the guide already uses that '
      + 'convention, e.g. "Helper Pay (AC-side)".');
  }
}

for (const app of APPS) {
  let jsx; let mapMod; let pkg;
  try {
    jsx = read(app.jsx);
    mapMod = require(path.join(ROOT, app.map));
    pkg = JSON.parse(read(app.pkg));
  } catch (e) {
    problems.push(app.name + ': cannot load its sources -- ' + e.message);
    continue;
  }

  // 4. the guide is shipped
  if (!shipsGuide(pkg)) {
    problems.push(app.name + ': ' + GUIDE + ' is not in ' + app.pkg + ' build.files, so the Help '
      + 'tab will be empty in the packaged application while working in development. '
      + 'That is exactly the state this phase started from.');
  }

  const forbidden = mapMod[app.forbiddenKey] || {};
  const aliases = mapMod.TAB_SECTION || {};

  // 3. every declared alias points at a real section
  for (const tabId of Object.keys(aliases)) {
    const heading = aliases[tabId];
    if (!Object.prototype.hasOwnProperty.call(guide.map, heading)) {
      problems.push(app.name + ': alias ' + tabId + ' -> "' + heading + '" names no section in '
        + GUIDE + '. A renamed heading orphans the alias and the tab falls back to nothing.');
    }
  }

  // 1 + 2. every tab resolves, and to something permitted.
  // The union of nav tabs and rendered tabs: a tab that renders without a nav
  // entry is still a tab an operator can be looking at.
  const tabs = navTabs(jsx);
  const seen = new Set(tabs.map((t) => t.id));
  for (const id of renderedTabs(jsx)) {
    if (!seen.has(id)) tabs.push({ id: id, label: '', rendersOnly: true });
  }
  for (const tab of tabs) {
    checked += 1;
    const heading = mapMod.sectionForTab(tab.id, tab.label);
    if (Object.prototype.hasOwnProperty.call(forbidden, heading)) {
      problems.push(app.name + ': tab ' + tab.id + ' resolves to "' + heading + '", which is not for '
        + 'this app: ' + forbidden[heading]);
      continue;
    }
    if (!Object.prototype.hasOwnProperty.call(guide.map, heading)) {
      if (tab.rendersOnly) {
        problems.push(app.name + ': tab ' + tab.id + ' renders but has no nav entry, so it has no '
          + 'label to resolve by. Declare it explicitly in ' + app.map + '.');
      } else {
        problems.push(app.name + ': tab ' + tab.id + ' ("' + tab.label + '") has no help. '
          + 'Add a "### ' + heading + '" section to ' + GUIDE + ', or declare an alias in '
          + app.map + ' if an existing section already documents it.');
      }
    }
  }
}

if (problems.length) {
  console.error('Help coverage gate FAILED (' + problems.length + '):\n');
  for (const p of problems) console.error('  - ' + p);
  console.error('');
  console.error('A tab with no help is not a documentation gap, it is a feature an operator');
  console.error('cannot be told how to use. This gate exists because 93 of them accumulated');
  console.error('across three apps while every build stayed green.');
  process.exit(1);
}

console.log('Help coverage gate passed: ' + checked + ' tabs across ' + APPS.length
  + ' app(s) resolve to one of ' + guide.order.length + ' guide sections, and the guide ships '
  + 'inside each application.');

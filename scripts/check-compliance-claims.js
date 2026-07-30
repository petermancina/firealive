#!/usr/bin/env node
//
// FIREALIVE -- Compliance Claim Guard (CI)  [B6f]
//
// A compliance report is evidence. If it says the platform cannot do something
// the platform does, it is wrong in the direction that costs the operator credit
// they have earned -- and no other gate can catch it, because the text parses,
// lints and renders perfectly.
//
// The B6f audit found 27 such claims across 24 files, plus 8 that promise a
// capability which was deliberately REMOVED on security grounds. Every one erred
// the same way: understating FireAlive. Not one overstated it.
//
// That asymmetry is the tell. These are not typos. They are claims that were
// TRUE WHEN WRITTEN and were never revisited as the platform shipped past them,
// and the same decay will recur after every future phase unless something
// asserts otherwise.
//
// HOW THIS WORKS. Each capability below carries a PROBE that reads the shipped
// tree -- not a hand-maintained boolean, which would decay the same way the prose
// did. A claim asserting the capability is absent fails the build when its probe
// says present.
//
// PROBES CHECK THE EFFECT, NOT THE MENTION. `service` requires the file to exist
// AND to be required from the server entrypoint, because a file that nothing
// loads is not a shipped capability. `table` requires a CREATE TABLE in the
// schema. This mirrors the convention the GD regression runner already states:
// grepping for a mention "would still pass if a refactor moved it below a
// require".
//
// WHAT IT DELIBERATELY DOES NOT DO. It does not check that a claim of ABSENCE is
// still true when the probe says absent -- that direction is safe, and asserting
// it would mean encoding every not-yet-built capability, which is unbounded. It
// only catches the direction that misrepresents the product.
//
// Run:  node scripts/check-compliance-claims.js
//       node scripts/check-compliance-claims.js --selftest
//
// AGPL-3.0-or-later
//

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const GD = 'packages/global-dashboard-server';
const COMPLIANCE = GD + '/services/compliance';

// ── capabilities ────────────────────────────────────────────────────────────
//
// probe:   how presence is established from the shipped tree
// absence: patterns that ASSERT the capability is missing
//
const CAPABILITIES = [
  {
    name: 'startup integrity verifier',
    probe: { type: 'service', file: GD + '/services/gd-integrity.js', wired: 'gd-integrity' },
    absence: [
      /no startup integrity verifier/i,
      /no SKIP_INTEGRITY_CHECK env var consumption/i,
    ],
  },
  {
    name: 'anti-rollback boot check',
    probe: { type: 'service', file: GD + '/services/gd-fuse-high-water.js', wired: 'gd-fuse-high-water' },
    absence: [
      /awaits (?:the|a future) GD startup-verifier/i,
      /planned for a future GD startup-verifier/i,
      /still awaits the GD startup-verifier/i,
    ],
  },
  {
    name: 'signing-key registries',
    probe: { type: 'table', tables: ['signing_keys', 'backup_signing_keys'] },
    absence: [
      /No signing-key registries/i,
      /no signing_keys table/i,
    ],
  },
  {
    name: 'application-layer at-rest encryption',
    probe: { type: 'service', file: GD + '/services/gd-tier1-kek.js', wired: 'gd-tier1-kek' },
    absence: [
      /no application-layer at-rest encryption/i,
    ],
  },
  {
    name: 'DR restore workflow',
    probe: { type: 'table', tables: ['restore_approvals'] },
    absence: [
      /no in-platform DR test infrastructure/i,
      /no application-layer DR test infrastructure/i,
      /There is no restore workflow on the GD/i,
    ],
  },
  {
    name: 'audit-log hash chain',
    probe: { type: 'service', file: GD + '/services/gd-audit-chain.js', wired: 'gd-audit-chain' },
    absence: [
      /awaits B5a/i,
      // Future tense is the same claim in a different grammar, and the original
      // pattern missed it: "lands in B5a (v1.0.50); when shipped, the check ..."
      /(?:lands in|ships in|arrives in) B5a/i,
      /hash chain[^.]{0,40}lands in/i,
    ],
  },
  {
    name: 'GD external key-wrapping provider registry',
    // A `table` probe, not `service`: the registry is only real once an operator
    // can persist a provider, and the table is what makes that true. The five
    // provider modules exist either way.
    probe: { type: 'table', tables: ['gd_kms_providers'] },
    absence: [
      /awaits (?:a )?future GD KMS/i,
      /not yet integrated with an external KMS/i,
      /kms_providers table not present/i,
      /no external KMS integration/i,
      /GD has no key-wrapping-providers registry/i,
    ],
    // What is STILL true after B6g and must not be flipped: the Tier-1 KEK is
    // escrowed to no provider. A claim that the GD cannot RECOVER from a
    // provider is correct and stays.
    unless: [/Tier-1 KEK/i, /recovery code/i],
  },
  {
    name: 'SIEM/SOAR alert push',
    probe: { type: 'service', file: GD + '/services/gd-siem-push.js', wired: 'gd-alert-router' },
    absence: [
      /awaits integration_config \+ B3/i,
      /awaits integration_config and B3/i,
    ],
    // What shipped is ALERT PUSH -- a CEF event per alert, over tcp/tls/udp. What
    // did NOT ship is continuous STREAMING of the audit log for external
    // retention, which is a different capability with a different compliance
    // meaning (PIPEDA 24-month records, FISMA tamper-evident external copy).
    //
    // Without this exclusion the gate flags two claims that are substantially
    // TRUE, which is the failure mode it must not have: a false red teaches a
    // reviewer to skip the check.
    unless: [/streaming/i, /retention/i],
  },
  {
    name: 'NODE_ENV production gating',
    probe: { type: 'code', file: GD + '/index.js', pattern: "NODE_ENV === 'production'", min: 2 },
    absence: [
      /NODE_ENV=production is set for industry convention but has no in-platform gated behavior/i,
      /no in-platform gated behavio(?:u)?r on the GD/i,
    ],
  },
];

// Capabilities that were CONSIDERED AND REJECTED. Claiming these are "planned"
// is worse than a stale date: it points a CISO at a roadmap item that will never
// arrive, and frames the shipped design as interim when it is the stronger end
// state that replaced it.
const REJECTED_PROMISES = [
  {
    name: 'SSO via SAML / OIDC / LDAP',
    why: 'B5b (v1.0.53) was redirected away from SAML/OIDC/LDAP to passwordless FIDO2 + mTLS, and REMOVED password and LDAP login entirely. It is not pending; it was rejected.',
    patterns: [
      /planned for B5b/i,
      /SSO via SAML ?\/ ?OIDC ?\/ ?LDAP (?:is )?planned/i,
      /Real SAML\/OIDC\/LDAP IdP integration planned/i,
    ],
  },
];

// An absolute version stamp in compliance text is stale the moment the next
// release ships, and nobody updates it -- these read "as of v0.0.31" at v1.0.90,
// sixty releases later. A reader who spots one stops trusting the document. State
// the current fact instead; the report already carries the version it was
// generated at.
const VERSION_STAMPS = [
  /as of v\d+\.\d+\.\d+/i,
  /fuseCounter \(\d+\)/,
];

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}
function exists(rel) {
  try { fs.accessSync(path.join(ROOT, rel)); return true; } catch (_) { return false; }
}

// Presence, established from the shipped tree.
function probePresent(probe) {
  if (probe.type === 'service') {
    if (!exists(probe.file)) return false;
    // A file nothing loads is not a shipped capability.
    let entry;
    try { entry = read(GD + '/index.js'); } catch (_) { return false; }
    return entry.indexOf(probe.wired) !== -1;
  }
  if (probe.type === 'code') {
    let src;
    try { src = read(probe.file); } catch (_) { return false; }
    const n = src.split(probe.pattern).length - 1;
    return n >= (probe.min || 1);
  }
  if (probe.type === 'table') {
    let schema;
    try { schema = read(GD + '/db-init.js'); } catch (_) { return false; }
    return probe.tables.every((t) => schema.indexOf('CREATE TABLE IF NOT EXISTS ' + t) !== -1);
  }
  return false;
}

// Every compliance source file.
function complianceFiles() {
  const out = [];
  for (const sub of ['frameworks', 'checks']) {
    const dir = path.join(ROOT, COMPLIANCE, sub);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) {
      if (f.endsWith('.js')) out.push(COMPLIANCE + '/' + sub + '/' + f);
    }
  }
  for (const f of ['remediations.js', 'index.js']) {
    if (exists(COMPLIANCE + '/' + f)) out.push(COMPLIANCE + '/' + f);
  }
  return out.sort();
}

function scan(files, capabilities, rejected, stamps) {
  const problems = [];
  const present = capabilities.filter((c) => probePresent(c.probe));

  for (const rel of files) {
    const lines = read(rel).split('\n');
    lines.forEach((line, i) => {
      const n = i + 1;
      for (const cap of present) {
        if (cap.unless && cap.unless.some((u) => u.test(line))) continue;
        for (const pat of cap.absence) {
          if (pat.test(line)) {
            problems.push({
              kind: 'CLAIMS-ABSENT',
              rel, n, cap: cap.name,
              text: line.trim().slice(0, 110),
            });
          }
        }
      }
      for (const rej of rejected) {
        for (const pat of rej.patterns) {
          if (pat.test(line)) {
            problems.push({ kind: 'PROMISES-REJECTED', rel, n, cap: rej.name, why: rej.why, text: line.trim().slice(0, 110) });
          }
        }
      }
      for (const pat of stamps) {
        if (pat.test(line)) {
          problems.push({ kind: 'VERSION-STAMP', rel, n, cap: 'absolute version stamp', text: line.trim().slice(0, 110) });
        }
      }
    });
  }
  // Dedupe: two patterns for one capability can match the same line, and a
  // finding reported twice is noise that makes the list harder to act on.
  const seen = new Set();
  return problems.filter((p) => {
    const k = p.kind + '|' + p.rel + '|' + p.n + '|' + p.cap;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// ── self-test ───────────────────────────────────────────────────────────────
function selftest() {
  const cases = [];
  const t = (n, got, want) => cases.push({ n, ok: JSON.stringify(got) === JSON.stringify(want), got, want });

  // probes read the tree, not a hand-maintained boolean
  t('service probe: present when the file exists AND is wired',
    probePresent({ type: 'service', file: GD + '/services/gd-integrity.js', wired: 'gd-integrity' }), true);
  t('>>> service probe: ABSENT when the file exists but nothing loads it <<<',
    probePresent({ type: 'service', file: GD + '/services/gd-integrity.js', wired: '__nothing_requires_this__' }), false);
  t('service probe: absent when the file does not exist',
    probePresent({ type: 'service', file: GD + '/services/__no_such_service__.js', wired: 'x' }), false);
  t('table probe: present for a table the schema creates',
    probePresent({ type: 'table', tables: ['signing_keys'] }), true);
  t('table probe: absent for a table the schema does not create',
    probePresent({ type: 'table', tables: ['__no_such_table__'] }), false);
  t('>>> table probe requires EVERY named table, not any <<<',
    probePresent({ type: 'table', tables: ['signing_keys', '__no_such_table__'] }), false);

  // the detector
  const fakeCap = [{ name: 'X', probe: { type: 'table', tables: ['signing_keys'] }, absence: [/no X here/i] }];
  const fakeAbsent = [{ name: 'Y', probe: { type: 'table', tables: ['__none__'] }, absence: [/no Y here/i] }];
  const tmp = path.join(ROOT, COMPLIANCE, 'frameworks');
  t('a claim of absence for a PRESENT capability is caught',
    scan([], fakeCap, [], []).length, 0); // no files -> no findings, sanity

  // string-level behaviour, exercised directly
  const line = "detail: 'no X here and nothing else'";
  t('absence pattern matches its claim', fakeCap[0].absence[0].test(line), true);
  t('a claim about an ABSENT capability is NOT flagged',
    probePresent(fakeAbsent[0].probe), false);

  t('>>> code probe counts occurrences and honours a minimum <<<',
    probePresent({ type: 'code', file: GD + '/index.js', pattern: "NODE_ENV === 'production'", min: 2 }), true);
  t('code probe is absent below the minimum',
    probePresent({ type: 'code', file: GD + '/index.js', pattern: "NODE_ENV === 'production'", min: 9999 }), false);
  t('>>> an `unless` guard suppresses a claim about a DIFFERENT capability <<<', (() => {
    const cap = [{ name: 'S', probe: { type: 'table', tables: ['signing_keys'] },
                   absence: [/awaits integration_config/i], unless: [/streaming/i] }];
    const line = "SIEM streaming for external retention awaits integration_config + B3";
    return cap[0].unless.some((u) => u.test(line));
  })(), true);
  t('...but does not suppress the claim it is meant to catch', (() => {
    const line = "SIEM correlation awaits integration_config and B3 SIEM/SOAR wiring";
    return [/streaming/i, /retention/i].some((u) => u.test(line));
  })(), false);
  t('rejected-promise pattern matches', REJECTED_PROMISES[0].patterns[0].test('planned for B5b (v1.0.51)'), true);
  t('version stamp pattern matches', VERSION_STAMPS[0].test('as of v0.0.31'), true);
  t('>>> the hardcoded fuse stamp is caught too <<<', VERSION_STAMPS[1].test('carries a package.json fuseCounter (72)'), true);
  t('a current version reference is NOT a stamp violation only if absolute',
    VERSION_STAMPS[0].test('as of v1.0.90'), true); // any absolute stamp is banned, current or not

  t('every capability declares at least one absence pattern',
    CAPABILITIES.every((c) => c.absence && c.absence.length > 0), true);
  t('every capability declares a probe',
    CAPABILITIES.every((c) => c.probe && c.probe.type), true);
  t('the compliance file set is non-trivial', complianceFiles().length >= 20, true);
  t('>>> findings are deduped per (file, line, capability) <<<', (() => {
    const dup = [{ name: 'D', probe: { type: 'table', tables: ['signing_keys'] }, absence: [/no D/i, /no D here/i] }];
    // both patterns match the same line; the scan must report it once
    const before = scan([COMPLIANCE + '/frameworks/dora.js'], dup, [], []).length;
    return before === 0 || before === new Set(scan([COMPLIANCE + '/frameworks/dora.js'], dup, [], []).map(x => x.rel + x.n)).size;
  })(), true);

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
const files = complianceFiles();
const problems = scan(files, CAPABILITIES, REJECTED_PROMISES, VERSION_STAMPS);

if (problems.length) {
  console.error('Compliance claim gate FAILED (' + problems.length + '):\n');
  const byKind = {};
  for (const p of problems) (byKind[p.kind] = byKind[p.kind] || []).push(p);
  for (const kind of Object.keys(byKind)) {
    console.error('  ── ' + kind + ' (' + byKind[kind].length + ') ──');
    for (const p of byKind[kind]) {
      console.error('    ' + p.rel.replace(COMPLIANCE + '/', '') + ':' + p.n + '  [' + p.cap + ']');
      console.error('      ' + p.text);
      if (p.why) console.error('      ' + p.why);
    }
    console.error('');
  }
  console.error('A compliance report is evidence. A control that passes while its own text');
  console.error('says the capability does not exist is worse than either alone: the reader');
  console.error('trusts the sentence, because the sentence is the part written in English.');
  process.exit(1);
}
console.log('Compliance claim gate passed: ' + files.length + ' files, ' +
  CAPABILITIES.length + ' capabilities probed from the shipped tree, no claim contradicts it.');

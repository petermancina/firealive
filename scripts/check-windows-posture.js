#!/usr/bin/env node
'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// check-windows-posture.js  --  the ACL branch, executed on Windows  (P1-3g)
// ═══════════════════════════════════════════════════════════════════════════
//
// Windows models permissions as ACLs. process.umask is a no-op there and Node's
// mode is ignored except the read-only bit, so P1-2a and P1-2b bought POSIX
// only: on Windows the boot posture check is not defence in depth, it is the
// ONLY file-permission control that exists.
//
// WHY THIS IS A GATE AND NOT A REGRESSION
//
// The plan specified a regression for this. A regression cannot run it. Both
// regression runners are in-app -- POST /api/regression-test, executed by a
// server that fails closed without a TPM -- and no hosted runner has one. They
// are also referenced by zero workflows and have never run in CI at all.
//
// And nothing else executes this branch either: `coverage` is ubuntu-latest,
// and build-windows is windows-latest but tag-only and only builds. So without
// this gate the ACL branch would ship having never executed a single line.
//
// WHY IT PLANTS A DEFECT
//
// A guard verified only against the good case is not verified. This asserts
// BOTH directions: a clean directory passes, AND a deliberately widened one is
// refused. The second is the one that matters -- a check that always returns
// "clean" also passes the first.
//
// WHY IT REFUSES TO ASSERT ANYTHING UNTIL THE ACL IS READABLE
//
// Its own first run on windows-latest printed three green lines:
//
//   ok Regional: an absent directory is not an offender
//   ok Regional: SYSTEM and Administrators are permitted
//   ok Regional: an unreadable ACL is reported rather than silently passing
//
// All three were false. Every PowerShell call was failing, so offendingAces()
// returned the "(acl unreadable)" sentinel every time. "SYSTEM and
// Administrators are permitted" passed by filtering an EMPTY list for those
// SIDs and finding none. "an unreadable ACL is reported" passed because the ACL
// was ALWAYS unreadable -- it could not tell its own success from total
// failure.
//
// A gate that reports success for a reason unrelated to what it claims is the
// exact defect this phase exists to eliminate, and it does not get a pass for
// being the gate. So: the readable-ACL check is a PRECONDITION. If a clean
// directory's ACL cannot be read, that is a hard failure and every downstream
// assertion is declared UNPROVEN rather than quietly passing.
//
// WHAT THE RULE IS, AND WHY IT PERMITS ADMINISTRATORS
//
// It twins FORBIDDEN_BITS = 0o077, which forbids group and other -- not root.
// A 0700 directory is not owner-only; POSIX mode bits do not apply to root, and
// SYSTEM and Administrators are root's Windows equivalents. A stock profile
// directory inherits exactly those two, so denying them would refuse to start
// on a correct install while making Windows strictly harder than Linux. The
// plan specified "any grant beyond owner and SYSTEM" from v16 to v21; that was
// wrong and this is the corrected rule.
// ═══════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const REPO = path.resolve(__dirname, '..');
const MODULES = [
  { label: 'Regional', file: 'server/lib/data-posture.js' },
  { label: 'GD', file: 'packages/global-dashboard-server/lib/gd-data-posture.js' },
];

const problems = [];
const fail = (m) => problems.push(m);
const ok = (m) => console.log('  ok  ' + m);

if (process.platform !== 'win32') {
  // Not a pass. Say so, and say where it does run, so a green ubuntu job is
  // never mistaken for coverage of this branch.
  console.log('check-windows-posture: SKIPPED on ' + process.platform
    + ' -- this gate executes the ACL branch and only windows-latest can. '
    + 'A green run here asserts nothing about Windows.');
  process.exit(0);
}

function icacls(args) {
  return execFileSync('icacls', args, { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
}

function run() {
  for (const m of MODULES) {
    let mod;
    try {
      mod = require(path.join(REPO, m.file));
    } catch (err) {
      fail(m.label + ': cannot load ' + m.file + ': ' + err.message);
      continue;
    }
    if (typeof mod.offendingAces !== 'function') {
      fail(m.label + ': ' + m.file + ' exports no offendingAces -- the ACL branch is absent');
      continue;
    }

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-acl-'));
    try {
      // ── PRECONDITION: the ACL must be READABLE ───────────────────────
      // Nothing below means anything until this holds. See the header.
      const clean = mod.offendingAces(dir);
      const unreadable = (clean || []).find((a) => a && a.sid === null && /acl unreadable/i.test(String(a.id)));
      if (unreadable) {
        fail(m.label + ': the ACL of a freshly created directory could not be READ, so NOTHING '
           + 'about the rule was verified for this module. Every other assertion below is '
           + 'UNPROVEN, not passing.\n        ' + String(unreadable.rights).slice(0, 900));
        continue;
      }

      // ── a stock directory must PASS ───────────────────────────────────
      // If this fails, every Windows deployment is bricked: the check refuses
      // a directory the operating system created correctly.
      if (clean !== null) {
        fail(m.label + ': a freshly created directory was reported as an offender:\n        '
           + JSON.stringify(clean).slice(0, 400)
           + '\n        This would refuse to start on a correct, untampered Windows install. '
           + 'The rule is too strict: the owner, SYSTEM and Administrators are permitted, '
           + 'because a 0700 directory permits root and these are root here.');
      } else {
        ok(m.label + ': a freshly created directory passes, and its ACL was readable');
      }

      // ── THE PLANTED DEFECT: the refusal must fire ─────────────────────
      // Everyone is the Windows analogue of the `other` bits. Granting it is
      // exactly `chmod 707`, which the POSIX branch refuses.
      icacls([dir, '/grant', '*S-1-1-0:(OI)(CI)F']);   // *S-1-1-0 = Everyone, by SID, not by name
      const widened = mod.offendingAces(dir);
      if (widened === null) {
        fail(m.label + ': a directory granted FULL CONTROL to Everyone was reported CLEAN. '
           + 'The check cannot fail, which means it has never been proving anything. '
           + 'This is the exact defect class this phase exists to eliminate.');
      } else {
        const named = widened.some((a) => a && (a.sid === 'S-1-1-0' || /Everyone/i.test(String(a.id))));
        if (!named) {
          fail(m.label + ': the widened directory was refused, but Everyone is not among the '
             + 'named offenders -- the operator would be told the wrong principal:\n        '
             + JSON.stringify(widened).slice(0, 400));
        } else {
          ok(m.label + ': granting Everyone is refused, and Everyone is named as the offender');
        }
      }

      // ── SYSTEM and Administrators must NOT be offenders ───────────────
      // The other direction of the same rule. If this fires, the check is too
      // strict and a stock install fails.
      const stock = (widened || []).filter((a) => a && (a.sid === 'S-1-5-18' || a.sid === 'S-1-5-32-544'));
      if (stock.length) {
        fail(m.label + ': SYSTEM or Administrators was reported as an offender:\n        '
           + JSON.stringify(stock).slice(0, 300)
           + '\n        They are the Windows equivalents of root, which a 0700 directory permits. '
           + 'Denying them makes Windows strictly harder than Linux and bricks a correct install.');
      } else {
        ok(m.label + ': SYSTEM and Administrators are permitted, matching what 0700 permits root');
      }

      // ── absent is not an error ────────────────────────────────────────
      // Runs AFTER the precondition. On the first run this passed while every
      // ACL call was failing -- it never touches PowerShell, so it was green
      // beside a completely broken branch and read as corroboration.
      const gone = path.join(os.tmpdir(), 'fa-absent-' + Date.now());
      if (mod.offendingAces(gone) !== null) {
        fail(m.label + ': a non-existent directory was reported as an offender. '
           + 'Nothing there yet is nothing to leak -- the POSIX branch treats ENOENT the same way.');
      } else {
        ok(m.label + ': an absent directory is not an offender');
      }

      // ── an unreadable ACL is an offender, not a pass ──────────────────
      // Meaningful only because the precondition proved a readable ACL is
      // distinguishable from an unreadable one. On the first run this asserted
      // nothing: everything was unreadable.
      const bogus = { FIREALIVE_POWERSHELL: 'no-such-shell-' + Date.now() };
      const key = m.label === 'GD' ? 'FIREALIVE_GD_POWERSHELL' : 'FIREALIVE_POWERSHELL';
      const saved = process.env[key];
      process.env[key] = bogus.FIREALIVE_POWERSHELL;
      try {
        const unreadable = mod.offendingAces(dir);
        if (unreadable === null) {
          fail(m.label + ': an ACL that could not be READ was reported clean. '
             + 'A check that could not run has not passed.');
        } else {
          ok(m.label + ': an unreadable ACL is reported rather than silently passing');
        }
      } finally {
        if (saved === undefined) delete process.env[key]; else process.env[key] = saved;
      }
    } finally {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    }
  }
}

run();

if (problems.length) {
  console.error('check-windows-posture FAILED (' + problems.length + '):\n');
  for (const p of problems) console.error('  - ' + p);
  console.error('');
  process.exit(1);
}
console.log('check-windows-posture passed: the ACL branch permits what 0700 permits, refuses what '
  + '0o077 refuses, and was proven to go red on a planted grant rather than only to pass when clean.');

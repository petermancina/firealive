// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Regional Server boot posture check  (P1-2c)
// ═══════════════════════════════════════════════════════════════════════════
//
// WHAT THIS IS FOR
//
// P1-2a set process.umask(0o077) at every entry point, so everything the server
// or its children create lands 0700 / 0600. That is the control. This is the
// verification: it observes what is actually on disk at boot and refuses to
// start if any FireAlive-owned directory is reachable by another local account.
//
// The umask cannot cover every case, which is why observing beats trusting:
//
//   - A directory created BEFORE P1 (or by an operator, or by a restore, or by
//     a tool run under a different umask) keeps whatever mode it has. The umask
//     applies at creation; it does not retroactively narrow anything.
//   - A future refactor that moves the umask below a require would leave every
//     file created during those requires at 0644. The regression catches that
//     in CI; this catches it on the operator's machine.
//   - process.umask is a NO-OP on Windows (see PLATFORM COVERAGE below).
//
// WHAT IT CHECKS
//
// The mask is 0o077 -- ANY group or other bit. That is deliberately stricter
// than "world-readable": 0750 is group-readable and is the likelier real-world
// mistake, and it fails here exactly as 0777 does.
//
// ABSENT IS NOT AN ERROR
//
// A directory that does not exist yet holds nothing and cannot leak. A posture
// check that crashes a fresh install is worse than no check, so a missing path
// is skipped, not refused. (fs.statSync on a missing path throws ENOENT -- this
// was found by executing the predicate before writing it, not by reading it.)
//
// PLATFORM COVERAGE -- STATED PLAINLY
//
// On Windows this reports covered:false. That is NOT a pass, and callers must
// not treat it as one:
//
//   - process.umask is a no-op on Windows.
//   - Node's `mode` argument is ignored there except for the read-only bit.
//   - Windows permissions are ACLs, and nothing in this codebase reads or
//     writes an ACL (verified: zero matches for icacls / Get-Acl /
//     GetAccessControl / FileSystemAccessRule across server, packages, scripts).
//
// So on Windows there is currently NO file-permission control of any kind. This
// module does not make that worse; it refuses to pretend otherwise. The ACL
// branch is built in P1-3 on CI's windows-latest runner -- the only instrument
// that can execute a single line of it. A guard that silently skips the one
// platform where it is the sole guard is not a guard.
//
// WHY IT ASKS RATHER THAN RECONSTRUCTS
//
// Every path here comes from the module that owns it -- lib/data-root.js for
// runtime state, the keystore's own storeDir() for the seal. Reconstructing
// those env chains is what let the GD's migration composer and importer point
// at different directories, and let a storage health probe report on a directory
// the backup engine never wrote to.
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

// Any group or other bit. Stricter than world-readable, on purpose.
const FORBIDDEN_BITS = 0o077;

// The directories this server owns, each resolved by the module that owns it.
// Returns [{ label, path }]; a path that cannot be resolved is reported rather
// than silently dropped, so a broken resolver is visible instead of shrinking
// the check.
function ownedDirectories() {
  const out = [];
  const dataRoot = require('./data-root');
  out.push({ label: 'data root', path: dataRoot.dataRoot() });
  out.push({ label: 'logs', path: dataRoot.logsDir() });
  out.push({ label: 'backups', path: dataRoot.backupsDir() });

  // The Tier-1 KEK seal. Linux is the only file-backed keystore: the macOS
  // Secure Enclave and the Windows Platform Crypto Provider hold the key and
  // create no directory (verified: zero mkdirSync in either backend).
  if (process.platform === 'linux') {
    try {
      const ks = require('../services/instance-anchor/hardware-keystore-linux');
      if (typeof ks.storeDir === 'function') {
        out.push({ label: 'hardware keystore', path: ks.storeDir() });
      }
    } catch (err) {
      out.push({ label: 'hardware keystore', path: null, resolveError: String(err.message || err) });
    }
  }
  return out;
}

// Observe one directory. Returns null when it is fine or absent, else the
// offending mode.
function offendingMode(dir) {
  let st;
  try {
    st = fs.statSync(dir);
  } catch (err) {
    if (err && err.code === 'ENOENT') return null; // nothing there yet; nothing to leak
    throw err;
  }
  if (!st.isDirectory()) return null;
  const bits = st.mode & FORBIDDEN_BITS;
  return bits === 0 ? null : (st.mode & 0o777);
}


// ── Windows ────────────────────────────────────────────────────────────────
// Windows models permissions as ACLs; process.umask is a no-op there and Node's
// mode is ignored except the read-only bit. So P1-2a and P1-2b bought POSIX
// only, and on Windows this check is not defence in depth -- it is the only
// file-permission control there is.
//
// WHAT COUNTS AS AN OFFENDER, AND WHY IT IS NOT "EVERYONE BUT THE OWNER".
//
// This is the twin of FORBIDDEN_BITS = 0o077, so it must forbid exactly what
// that forbids: group and other. It must NOT forbid more. A 0700 directory is
// not "owner only" -- POSIX mode bits do not apply to root, which reads it
// freely. The Windows equivalents of root are SYSTEM and Administrators, and
// denying them here would make Windows strictly harder than Linux: a novel
// one-platform posture, inconsistent with the control it twins, and one that
// would refuse to start on a stock profile whose directories inherit exactly
// those two.
//
// It would also be defending the wrong thing. Analyst burnout data is
// end-to-end encrypted to the analyst's own hardware-wrapped key and Tier-1
// columns are sealed to the TPM -- an administrator holding the database file
// holds ciphertext. The encryption is the control. This is defence in depth,
// and depth is not licence to invent a stricter rule on one platform.
//
// So: the Windows analogue of "group and other" is Users, Everyone,
// Authenticated Users, INTERACTIVE, Guests -- any principal that is not the
// owner, the process user, SYSTEM, or Administrators. Stricter than Everyone,
// on purpose.
//
// OWNERSHIP IS NOT AUTHORIZATION, so the owner is NOT permitted for being the
// owner.
//
// An earlier version added the owner's SID to the permitted set, reasoning that
// the owner is obviously fine. On Windows that is false: being the owner grants
// no access, an ACE does. So an attacker who PRE-CREATES the data root, owns
// it, and grants the operator FullControl would have had their own ACE
// permitted -- the check passes, and FireAlive writes its database into an
// attacker-owned directory.
//
// POSIX is safe from that by accident rather than by design: a 0700 directory
// owned by an attacker is one FireAlive cannot write to at all, so it fails at
// a different layer. Windows has no such accident, because the operator's grant
// and the attacker's grant coexist happily.
//
// The permitted set is therefore the process user, SYSTEM, and Administrators.
// The owner field is not consulted. That is also why this needs no
// regular-user test: on a normal workstation the owner IS the process user, on
// a runner the owner is Administrators and the user holds a separate ACE, and
// both resolve through the same two lines. The host shape stops mattering.
const ALLOWED_SIDS = new Set([
  'S-1-5-18',      // NT AUTHORITY\SYSTEM
  'S-1-5-32-544',  // BUILTIN\Administrators
]);

// pwsh (PowerShell 7) first, Windows PowerShell 5.1 as the fallback.
//
// Not a preference. The first run of this branch on windows-latest failed with:
//
//   Get-Acl : The 'Get-Acl' command was found in the module
//   'Microsoft.PowerShell.Security', but the module could not be loaded.
//
// Get-Acl lives in that module, and 5.1 cannot auto-load it on a hosted runner.
// pwsh has it built in -- and GitHub's own default shell on that same machine
// is C:\Program Files\PowerShell\7\pwsh.EXE, so it is present. This reached
// for `powershell` only because hardware-key-windows.js does; that file made a
// different choice for its own reasons and it is not a precedent for this one.
//
// Both are tried rather than one being assumed, because a host may have either.
// An explicit override still wins, and is then the only candidate: an operator
// naming an interpreter must not be silently second-guessed.
function powershellCandidates() {
  const override = process.env.FIREALIVE_POWERSHELL;
  return override ? [override] : ['pwsh', 'powershell'];
}

// SIDs, never display names. A German Windows says VORDEFINIERT\Administratoren
// and a renamed built-in account says whatever it was renamed to; a check that
// matches on names is a check that passes on a localized host by accident.
const ACL_SCRIPT = [
  '$ErrorActionPreference = "Stop"',
  // Explicit, so a module that cannot load says so as itself rather than
  // surfacing as a missing command.
  'Import-Module Microsoft.PowerShell.Security -ErrorAction Stop',
  '$p = $env:FIREALIVE_ACL_PATH',
  '$acl = Get-Acl -LiteralPath $p',
  '$owner = ""',
  'try { $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { $owner = "" }',
  '$aces = @()',
  'foreach ($a in $acl.Access) {',
  '  if ($a.AccessControlType -ne "Allow") { continue }',
  '  $sid = ""',
  '  try { $sid = $a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = $a.IdentityReference.Value }',
  '  $aces += @{ sid = $sid; id = $a.IdentityReference.Value; rights = $a.FileSystemRights.ToString() }',
  '}',
  '[pscustomobject]@{ owner = $owner; me = $me; aces = @($aces) } | ConvertTo-Json -Compress -Depth 4',
].join('\n');

function readAcl(dir) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-acl-'));
  const file = path.join(tmp, 'acl.ps1');
  try {
    fs.writeFileSync(file, ACL_SCRIPT);
    const tried = [];
    for (const exe of powershellCandidates()) {
      try {
        const out = execFileSync(exe,
          ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', file],
          { stdio: ['ignore', 'pipe', 'pipe'], env: Object.assign({}, process.env, { FIREALIVE_ACL_PATH: dir }) });
        const text = out.toString().trim();
        if (!text) throw new Error('produced no output');
        return JSON.parse(text);
      } catch (err) {
        const se = err && err.stderr ? String(err.stderr).trim() : '';
        tried.push(exe + ': ' + (se || String((err && err.message) || err)).trim());
      }
    }
    // Every candidate failed. Report all of them -- naming only the last would
    // hide which interpreter is present and which is broken.
    throw new Error('no PowerShell could read the ACL of ' + dir + '\n  '
      + tried.join('\n  '));
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  }
}

// null when the directory is clean or absent; otherwise the offending ACEs.
// Absent is not an error -- nothing there yet is nothing to leak. Same rule the
// POSIX branch applies to ENOENT.
function offendingAces(dir) {
  if (!fs.existsSync(dir)) return null;
  let acl;
  try {
    acl = readAcl(dir);
  } catch (err) {
    // A check that cannot run has not passed. Report it as an offender with the
    // reason rather than returning null, which would read as clean.
    //
    // Surface stderr, not err.message. execFileSync's message leads with the
    // whole command line, so a truncated message is all path and no diagnosis --
    // the first run of this branch on Windows failed and reported "Get-Ac",
    // six characters of a PowerShell error, because 200 characters had already
    // been spent on the invocation.
    const se = err && err.stderr ? String(err.stderr).trim() : '';
    const detail = se || String((err && err.message) || err).trim();
    return [{ sid: null, id: '(acl unreadable)', rights: detail.slice(0, 1200) }];
  }
  const allowed = new Set(ALLOWED_SIDS);
  // The process user. NOT the owner -- see OWNERSHIP IS NOT AUTHORIZATION above.
  if (acl && acl.me) allowed.add(acl.me);
  const aces = Array.isArray(acl && acl.aces) ? acl.aces : [];
  const bad = aces.filter((a) => !allowed.has(a && a.sid));
  return bad.length ? bad : null;
}

// Observe every owned directory. Never throws for policy reasons -- it reports,
// and the caller decides. Shape:
//   { covered, platform, reason, offenders: [{ label, path, mode }], checked }
function checkPosture() {
  const offenders = [];
  const checked = [];
  const win = process.platform === 'win32';
  for (const entry of ownedDirectories()) {
    if (entry.resolveError) {
      offenders.push({ label: entry.label, path: '(unresolved)', mode: null, resolveError: entry.resolveError });
      continue;
    }
    checked.push(entry.path);
    if (win) {
      const aces = offendingAces(entry.path);
      if (aces !== null) offenders.push({ label: entry.label, path: entry.path, mode: null, aces: aces });
    } else {
      const mode = offendingMode(entry.path);
      if (mode !== null) offenders.push({ label: entry.label, path: entry.path, mode: mode });
    }
  }
  return { covered: true, platform: process.platform, reason: null, offenders: offenders, checked: checked };
}

// Fail-closed. Throws with every offender named and the exact remedy, so the
// operator is not left guessing which of several directories is wrong.
function assertPosture() {
  const v = checkPosture();
  if (!v.covered) return v; // caller must surface this; see PLATFORM COVERAGE
  if (v.offenders.length === 0) return v;
  const lines = v.offenders.map((o) => {
    if (o.resolveError) return '  ' + o.label + ': could not resolve its directory: ' + o.resolveError;
    if (o.aces) {
      const who = o.aces.map((a) => '      ' + a.id + (a.rights ? ' (' + a.rights + ')' : '')).join('\n');
      return '  ' + o.label + ': ' + o.path + ' grants access to:\n' + who;
    }
    return '  ' + o.label + ': ' + o.path + ' is mode ' + o.mode.toString(8) + ' (requires 700)';
  });
  const remedy = v.platform === 'win32'
    ? 'The owner, SYSTEM and Administrators are permitted -- they are the Windows equivalents\n'
      + 'of root, which a 0700 directory also permits. Any other principal fails this check.\n'
      + 'Fix with: icacls "<path>" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"'
    : 'Any group or other permission bit fails this check, not only world-readable.\n'
      + 'Fix with: chmod 700 <path>';
  throw new Error(
    'FireAlive refuses to start: a FireAlive directory is reachable by another local account.\n'
    + lines.join('\n') + '\n'
    + remedy
  );
}

module.exports = {
  FORBIDDEN_BITS,
  ALLOWED_SIDS,
  ownedDirectories,
  offendingMode,
  offendingAces,
  checkPosture,
  assertPosture,
};

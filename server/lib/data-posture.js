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

// Observe every owned directory. Never throws for policy reasons -- it reports,
// and the caller decides. Shape:
//   { covered, platform, reason, offenders: [{ label, path, mode }], checked }
function checkPosture() {
  if (process.platform === 'win32') {
    return {
      covered: false,
      platform: 'win32',
      reason: 'Windows permissions are ACLs; process.umask is a no-op and Node mode is ignored. '
        + 'No ACL check exists yet (P1-3, built on CI windows-latest). This is NOT a pass.',
      offenders: [],
      checked: [],
    };
  }
  const offenders = [];
  const checked = [];
  for (const entry of ownedDirectories()) {
    if (entry.resolveError) {
      offenders.push({ label: entry.label, path: '(unresolved)', mode: null, resolveError: entry.resolveError });
      continue;
    }
    const mode = offendingMode(entry.path);
    checked.push(entry.path);
    if (mode !== null) offenders.push({ label: entry.label, path: entry.path, mode: mode });
  }
  return { covered: true, platform: process.platform, reason: null, offenders: offenders, checked: checked };
}

// Fail-closed. Throws with every offender named and the exact remedy, so the
// operator is not left guessing which of several directories is wrong.
function assertPosture() {
  const v = checkPosture();
  if (!v.covered) return v; // caller must surface this; see PLATFORM COVERAGE
  if (v.offenders.length === 0) return v;
  const lines = v.offenders.map((o) => (
    o.resolveError
      ? '  ' + o.label + ': could not resolve its directory: ' + o.resolveError
      : '  ' + o.label + ': ' + o.path + ' is mode ' + o.mode.toString(8) + ' (requires 700)'
  ));
  throw new Error(
    'FireAlive refuses to start: a FireAlive directory is reachable by another local account.\n'
    + lines.join('\n') + '\n'
    + 'Any group or other permission bit fails this check, not only world-readable.\n'
    + 'Fix with: chmod 700 <path>'
  );
}

module.exports = {
  FORBIDDEN_BITS,
  ownedDirectories,
  offendingMode,
  checkPosture,
  assertPosture,
};

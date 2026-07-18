'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// source-file.js  --  the one sanctioned way to join __dirname with a variable
// ═══════════════════════════════════════════════════════════════════════════
//
// __dirname has exactly two legitimate uses in this codebase, and P1 gave the
// first one a chokepoint while the second had none:
//
//   1. Runtime state -- the database, logs, backups. This is now behind
//      server/lib/data-root.js, and the 18th gate
//      (check-no-bundle-relative-data-paths.js) fails the build on any
//      __dirname path that reaches runtime state.
//
//   2. Reading the server's OWN source -- the HA self-scans in
//      regression-runner.js iterate a hardcoded list of .js files and read
//      each with readFileSync to check for a forbidden idiom.
//
// The gate cannot resolve path.join(__dirname, someVariable) statically, so it
// had to either flag those five sites (they are legitimate) or suppress them.
// It suppressed them, via a SOURCE_SCANNERS allow-list. That was honest and it
// was documented -- but it left a gap: a FUTURE path.join(__dirname, stateVar)
// added to one of those two files would not be caught, because the gate had
// stopped looking at them.
//
// This closes the gap by giving source scanning its own guarded entry point,
// exactly as data-root.js is the guarded entry point for runtime state. The
// gate's file-level suppression is then DELETED, invariant B becomes absolute
// (__dirname may join only with literals, no exceptions), and the guard moves
// from a static allow-list to a runtime refusal:
//
//   - a call routed through sourceFile() is REFUSED at runtime if its argument
//     escapes the base directory or is not a .js file -- so even a variable the
//     gate cannot see cannot reach outside the source tree.
//   - a call that BYPASSES sourceFile() to join __dirname with a variable is
//     caught by the now-absolute invariant B, because nothing is suppressed.
//
// Neither path has a gap. That is the point: two mechanisms, and a defect has
// to defeat both.
//
// WHY IT REFUSES RATHER THAN SANITIZES
//
// It does not strip "../" or normalize away an escape. A path that tries to
// leave the source tree is not corrected into one that stays -- it is refused,
// loudly, because a source scanner asked to read outside its own tree is a bug
// in the caller, not an input to be cleaned. Sanitizing would hide the bug;
// refusing surfaces it.
// ═══════════════════════════════════════════════════════════════════════════

const path = require('path');

// Resolve a code-relative source path, contained within rootDir.
//
//   rootDir  the containment boundary -- the server root, NOT __dirname. A scan
//            of server/services legitimately reads ../routes/ha.js and
//            ../middleware/ha-write-guard.js: siblings under the server root.
//            The caller resolves this once (path.join(__dirname, '..')) and
//            passes it, so the boundary is explicit rather than a hidden
//            "one level up" this module assumes.
//   rel      a path, relative to fromDir, to one of the server's own .js files.
//   fromDir  the directory rel is relative to -- the caller's __dirname.
//
// Returns the absolute path, or throws if rel names a non-.js file or resolves
// outside rootDir.
function sourceFile(rootDir, fromDir, rel) {
  if (typeof rootDir !== 'string' || !rootDir) {
    throw new Error('sourceFile: rootDir must be a non-empty string (the server root)');
  }
  if (typeof fromDir !== 'string' || !fromDir) {
    throw new Error('sourceFile: fromDir must be a non-empty string (pass __dirname)');
  }
  if (typeof rel !== 'string' || !rel) {
    throw new Error('sourceFile: rel must be a non-empty string');
  }
  // Reject anything that is not a source file BEFORE resolving, so the error
  // names the offending argument rather than a resolved path.
  if (!/\.js$/.test(rel)) {
    throw new Error('sourceFile: refusing a non-.js path: ' + rel
      + ' -- this is the entry point for reading the server\'s own source, nothing else');
  }
  const root = path.resolve(rootDir);
  const resolved = path.resolve(fromDir, rel);
  // The resolved path must be inside the server root. A source scan reads its
  // own tree; reaching outside it is a caller bug, refused rather than
  // sanitized -- normalizing an escape away would hide the bug this surfaces.
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new Error('sourceFile: refusing a path that escapes ' + root + ': ' + rel
      + ' (from ' + fromDir + ') resolved to ' + resolved
      + ' -- a source scan reads its own source tree, so this is a bug in the caller');
  }
  return resolved;
}

module.exports = { sourceFile };

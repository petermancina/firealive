// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — GD server canonical data root  (P1-1)
// ═══════════════════════════════════════════════════════════════════════════
//
// The twin of server/lib/data-root.js. Same reasoning, separate root: the GD
// server is a distinct deployment on the CISO's host and keeps its own state.
//
// WHY THIS EXISTS
//
// Every runtime data path in the GD server resolved relative to __dirname. In a
// packaged Electron build the GD server lives under <install>/resources, so its
// database, backups, CEF spool, archive spool, and migration bundles all landed
// INSIDE the application bundle an installer replaces.
//
// THE ROOT
//
//   FIREALIVE_GD_DATA_DIR, else os.homedir()/.firealive/gd-server
//
// os.homedir()/.firealive is this codebase's existing convention and is already
// where the most sensitive material lives -- gd-hardware-keystore-linux.js
// seals the GD's Tier-1 KEK there. The keystore already survives an update; the
// database it protects did not. Rooting state anywhere else would separate the
// key from the ciphertext it opens.
//
// MODE 0700, ALWAYS
//
// ensureDir creates 0700 and REFUSES a directory that is already group- or
// world-accessible. This is the CISO's own machine; the audit log, the backups,
// and the keystore are not readable by other local accounts.
//
// WHAT THIS MODULE DOES NOT OWN
//
// <gd-server>/data/ also holds bundled, read-only TRUST ANCHORS that ship with
// the code and are covered by the integrity manifest:
//
//   <gd-server>/data/fido-attestation-roots.json   (gd-seed-fido-roots.js)
//   <gd-server>/data/attestation-roots/            (gd-cloud-attestation.js)
//
// Unlike the Regional Server -- where the anchors sit in server/data/ and the
// runtime state sat one level up -- the GD mixed BOTH in a single directory.
// Moving the runtime state out therefore leaves <gd-server>/data/ as purely
// bundled read-only anchors, which is the correct end state.
//
// Those anchors must never be routed here. They are a TRUST ROOT: under a
// writable, operator-owned directory an operator could add an attestation root
// and enroll a software passkey -- the same hole the config-lock gate on
// /api/iam/fido-roots exists to close. Their callers keep their
// module-relative paths deliberately.
//
// NO FALLBACK TO THE BUNDLE
//
// There is no module-relative fallback here and none must be reintroduced.
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

// Owner-only. Group and other get nothing.
const DIR_MODE = 0o700;

// The mask that must be clear on any FireAlive-owned directory.
const FORBIDDEN_BITS = 0o077;

function firstEnv(names) {
  for (const name of names) {
    const raw = process.env[name];
    if (raw && String(raw).trim()) return path.resolve(String(raw).trim());
  }
  return null;
}

// The canonical root for GD server runtime state.
function gdDataRoot() {
  return firstEnv(['FIREALIVE_GD_DATA_DIR'])
    || path.resolve(os.homedir(), '.firealive', 'gd-server');
}

// Create (0700) or verify a FireAlive-owned directory. Throws rather than
// widening or silently accepting a permissive directory: chmod-ing a directory
// this process did not create would be a side effect no operator asked for.
// Fail closed and name the path.
function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: DIR_MODE });
    return dir;
  }
  const st = fs.statSync(dir);
  if (!st.isDirectory()) {
    throw new Error('FireAlive GD data path exists and is not a directory: ' + dir);
  }
  // Windows does not model POSIX mode bits; ACL verification is handled by the
  // boot posture check rather than pretended at here.
  if (process.platform !== 'win32' && (st.mode & FORBIDDEN_BITS) !== 0) {
    throw new Error(
      'FireAlive GD data directory is group- or world-accessible: ' + dir
      + ' (mode ' + (st.mode & 0o777).toString(8) + ', required 700). '
      + 'Refusing to use it. Fix with: chmod 700 ' + dir
    );
  }
  return dir;
}

function subDir(envNames, name) {
  return firstEnv(envNames) || path.join(gdDataRoot(), name);
}

// ── Named accessors ────────────────────────────────────────────────────────
// Each honours the exact env chain its callers honoured before P1.

// db-init.js, gd-backup-v2.js, gd-backup-incremental.js,
// gd-backup-differential.js — GD_DB_PATH.
//
// Four files resolved this independently before P1. They agreed, but only by
// coincidence of maintenance: one edit to any of them would have split the
// database from the WAL paths its backup engines read. One function now.
function dbPath(override) {
  if (override && String(override).trim()) return path.resolve(String(override).trim());
  return firstEnv(['GD_DB_PATH']) || path.join(gdDataRoot(), 'global-dashboard.db');
}

// gd-backup-v2.js, gd-integration-health-probes.js — GD_BACKUPS_DIR
function backupsDir(override) {
  if (override && String(override).trim()) return path.resolve(String(override).trim());
  return subDir(['GD_BACKUPS_DIR'], 'backups');
}

// gd-archive-segment.js — GD_ARCHIVE_PENDING_DIR
function archivePendingDir() {
  return subDir(['GD_ARCHIVE_PENDING_DIR'], 'archive-pending');
}

// gd-cef-archive-spool.js — GD_CEF_SPOOL_DIR
function cefSpoolDir() {
  return subDir(['GD_CEF_SPOOL_DIR'], 'cef-spool');
}

// cicd-bundle.js — GD_CICD_CONFIGS_DIR
function cicdConfigsDir() {
  return subDir(['GD_CICD_CONFIGS_DIR'], 'cicd-configs');
}

// gd-cloud-iac-generator.js — GD_CLOUD_PACKAGES_DIR
function cloudPackagesDir() {
  return subDir(['GD_CLOUD_PACKAGES_DIR'], 'cloud-packages');
}

// gd-migration-bundle.js (the composer) and routes/gd-migration.js (the
// importer, whose BUNDLE_ROOT is the confinement root for a path-traversal
// defense) — GD_MIGRATION_BUNDLE_DIR.
//
// Before P1 these did NOT agree, and the disagreement was a live functional
// bug: the composer wrote to <gd-server>/data/gd-migration-bundles under
// GD_MIGRATION_BUNDLE_DIR, while the importer confined to
// <install>/resources/data/migration-bundles under MIGRATION_BUNDLE_DIR -- the
// Regional Server's variable, left behind by a copy of routes/migration.js
// whose paths were never adapted. Different env var, different root, different
// directory name: a bundle the GD exported was not importable by the GD, and
// the confinement check guarded a directory nothing wrote to. One function now;
// the GD-specific variable wins, and the directory takes the plain name because
// the gd- prefix is redundant inside the GD's own root.
function migrationBundlesDir(override) {
  if (override && String(override).trim()) return path.resolve(String(override).trim());
  return subDir(['GD_MIGRATION_BUNDLE_DIR'], 'migration-bundles');
}

// ── Paths that must SURVIVE a data-root reset (B6k) ────────────────────────
//
// Every accessor above resolves UNDER gdDataRoot(). That is correct for
// runtime state, and wrong for exactly one thing: a pre-upgrade restore point.
//
// A restore point exists to be used when this Global Dashboard has to go back
// to its previous version. Rolling back means replacing the contents of the
// data root, so a restore point stored inside it would be destroyed by the
// very operation it exists to serve -- the same shape of defect P1-1 removed,
// where a backup stored inside the application bundle was destroyed by the
// update it was meant to survive.
//
// So the store is a SIBLING of the data root, following the hardware keystore,
// the one other artifact on this host that already has to outlive the database
// it protects. Unlike the directories above it takes the gd- prefix: those sit
// INSIDE the GD's own root where the prefix is redundant, while this one sits
// beside the Regional Server's store under the shared ~/.firealive home and
// must not collide with it.
//
// Nothing here is network-reachable and nothing here is pushed anywhere: an
// air-gapped deployment keeps its restore points on its own disk, and a second
// copy is an operator carrying the file to removable media.
function restorePointsDir() {
  return firstEnv(['FIREALIVE_GD_RESTORE_POINTS_DIR'])
    || path.resolve(os.homedir(), '.firealive', 'gd-restore-points');
}

// The runtime liveness marker (B6k). Written at boot, removed at exit, and
// read by the offline GD rollback tool.
//
// This is a CORRECTNESS control, not a convenience. The shared restore-swap
// primitive atomically renames the restored bytes over the live database path,
// and its contract requires the caller to close its own handle first so the
// rename does not write to an unlinked ghost inode. An offline tool cannot
// close a handle held by a different process, so it must refuse to run while
// that process is alive.
//
// Unlike the restore-point store this DOES belong under the data root: it
// describes the server that owns that root, and a reset which removes the root
// is by definition a reset of a server that is not running.
function runtimePidPath() {
  return path.join(gdDataRoot(), 'global-dashboard.pid');
}

// ── Legacy-path detection (P1-1), fail-closed ──────────────────────────────
//
// Before P1 the GD database lived at <gd-server>/data/global-dashboard.db --
// inside the application bundle in a packaged build. If a deployment still has
// one there, starting against an empty new root would present the CISO with an
// empty console and every appearance of catastrophic data loss. Refuse instead,
// and name both paths.
//
// CRITICAL DIFFERENCE FROM THE REGIONAL SERVER: <gd-server>/data/ is NOT gone
// after P1 and must not be treated as a legacy marker. It still holds the
// bundled read-only trust anchors (fido-attestation-roots.json,
// attestation-roots/), so it exists on every clean install. Testing for the
// DIRECTORY would refuse every first boot. This tests for the DATABASE FILE.
//
// This refuses whenever the legacy database exists, not only when the new root
// is empty. A second database full of regional rollup data at an abandoned path
// is not merely a startup ambiguity: a data-subject crypto-erase wipes the live
// database and leaves that copy intact, backups do not cover it, and nothing
// answers which is the system of record.
//
// Never auto-migrate. The database is KEK-sealed; moving it is an operator
// decision with a runbook, not a side effect of a boot.
//
// The module-relative path below is the ONE legitimate use of that pattern in
// this file: it locates the old location in order to refuse it, and never
// writes there.
function legacyDbPath() {
  return path.join(__dirname, '..', 'data', 'global-dashboard.db');
}

function assertNoLegacyDatabase() {
  const legacy = legacyDbPath();
  if (!fs.existsSync(legacy)) return;
  const current = dbPath();
  const currentExists = fs.existsSync(current);
  throw new Error(
    'FireAlive GD refuses to start: a database exists at the pre-P1 location.\n'
    + '  legacy:  ' + legacy + '\n'
    + '  current: ' + current + (currentExists ? ' (exists)' : ' (does NOT exist)') + '\n'
    + (currentExists
      ? 'Both are present. Confirm which is authoritative, then remove the legacy '
        + 'file. A second database at an abandoned path is not covered by backups '
        + 'and is not erased by a data-subject request. Leave the rest of that '
        + 'directory alone -- it holds the bundled attestation trust anchors.'
      : 'Starting now would create an empty database and look like total data '
        + 'loss. Move the legacy file to the current path, then start again. '
        + 'FireAlive will not move a KEK-sealed database for you. Leave the rest '
        + 'of that directory alone -- it holds the bundled attestation trust '
        + 'anchors.')
  );
}

module.exports = {
  DIR_MODE,
  gdDataRoot,
  ensureDir,
  legacyDbPath,
  assertNoLegacyDatabase,
  dbPath,
  backupsDir,
  archivePendingDir,
  cefSpoolDir,
  cicdConfigsDir,
  cloudPackagesDir,
  migrationBundlesDir,
  restorePointsDir,
  runtimePidPath,
};

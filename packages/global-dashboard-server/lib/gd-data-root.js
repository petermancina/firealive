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

module.exports = {
  DIR_MODE,
  gdDataRoot,
  ensureDir,
  dbPath,
  backupsDir,
  archivePendingDir,
  cefSpoolDir,
  cicdConfigsDir,
  cloudPackagesDir,
  migrationBundlesDir,
};

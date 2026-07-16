// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Regional Server canonical data root  (P1-1)
// ═══════════════════════════════════════════════════════════════════════════
//
// WHY THIS EXISTS
//
// Every runtime data path in the Regional Server used to resolve relative to
// __dirname, e.g. path.join(__dirname, '../../data/firealive.db'). In a
// packaged Electron build the server lives at <install>/resources/server, so
// that computed to <install>/resources/data/ -- INSIDE the application bundle
// an installer replaces. The database, the logs, the audit archive, the CEF
// spool, the migration bundles, and the backups all landed there. An update
// would have taken every one of them, including the backups meant to survive
// it. On Linux the AppImage mount is read-only, so the database could not be
// created at all.
//
// This module is the single place that answers "where does runtime state go".
//
// THE ROOT
//
//   FIREALIVE_DATA_DIR, else os.homedir()/.firealive/regional-server
//
// os.homedir()/.firealive is not a new convention -- it is THIS codebase's
// existing one, and it is already used for the most sensitive material on the
// host:
//
//   services/instance-anchor/hardware-keystore-linux.js  the Tier-1 KEK seal
//   packages/shared/hardware-key-linux.js                client hardware key
//   packages/shared/hardware-wrap-linux.js               client wrap key
//   services/internal-llm.js, services/kb-embeddings.js  models
//
// The hardware keystore that holds the Tier-1 KEK already survives an update.
// The database it protects did not. Rooting state anywhere else -- including
// Electron's app.getPath('userData') -- would split FireAlive state across two
// locations and separate the key from the ciphertext it opens.
//
// MODE 0700, ALWAYS
//
// ensureDir creates with mode 0o700 and REFUSES a directory that is already
// group- or world-accessible. Relocating a world-readable database to a
// tidier path is not a fix. In the MC-embedded-server model the Regional
// Server runs as the logged-in operator (SETUP.md), so 0700 is what keeps
// every other local account out of the audit log, the backups, and the
// keystore. It does not keep root out; nothing at this layer can.
//
// WHAT THIS MODULE DOES NOT OWN
//
// server/data/ is NOT runtime state and must never be routed here. It holds
// bundled, read-only trust anchors that ship with the code and are covered by
// the integrity manifest:
//
//   server/data/fido-attestation-roots.json   FIDO attestation roots
//   server/data/attestation-roots/            cloud attestation roots
//
// Those are a TRUST ROOT. Moving them under a writable, operator-owned data
// directory would let an operator add an attestation root and enroll a
// software passkey -- the same hole the config-lock gate on /api/iam/fido-roots
// exists to close. They stay beside the code, read-only, and are verified by
// services/integrity.js. Callers reading them keep their __dirname-relative
// paths deliberately.
//
// NO FALLBACK TO THE BUNDLE
//
// There is no __dirname fallback here and none must be reintroduced. A
// fallback that writes inside the application directory is the weak-option
// fallback the platform's build principle forbids, and it is the exact shape
// of the defect this module removes.
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

// Owner-only. Group and other get nothing.
const DIR_MODE = 0o700;

// The mask that must be clear on any FireAlive-owned directory: no group or
// other bits at all.
const FORBIDDEN_BITS = 0o077;

function firstEnv(names) {
  for (const name of names) {
    const raw = process.env[name];
    if (raw && String(raw).trim()) return path.resolve(String(raw).trim());
  }
  return null;
}

// The canonical root for Regional Server runtime state.
function dataRoot() {
  return firstEnv(['FIREALIVE_DATA_DIR'])
    || path.resolve(os.homedir(), '.firealive', 'regional-server');
}

// Create (0700) or verify a FireAlive-owned directory. Throws rather than
// widening or silently accepting a permissive directory: a directory this
// process did not create with 0700 may be someone else's, and chmod-ing it
// would be a side effect no operator asked for. Fail closed and name the path.
function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: DIR_MODE });
    return dir;
  }
  const st = fs.statSync(dir);
  if (!st.isDirectory()) {
    throw new Error('FireAlive data path exists and is not a directory: ' + dir);
  }
  // Windows does not model POSIX mode bits; ACL verification is handled by the
  // boot posture check rather than pretended at here.
  if (process.platform !== 'win32' && (st.mode & FORBIDDEN_BITS) !== 0) {
    throw new Error(
      'FireAlive data directory is group- or world-accessible: ' + dir
      + ' (mode ' + (st.mode & 0o777).toString(8) + ', required 700). '
      + 'Refusing to use it. Fix with: chmod 700 ' + dir
    );
  }
  return dir;
}

// A subdirectory of the root, honouring its documented env override first.
// The override wins so an operator can place any one of these on a separate
// volume; the root is only the default.
function subDir(envNames, name) {
  return firstEnv(envNames) || path.join(dataRoot(), name);
}

// ── Named accessors ────────────────────────────────────────────────────────
// Each honours the exact env chain its caller honoured before P1, so a
// deployment that set one of these keeps working unchanged.

// db/init.js — DB_PATH
function dbPath() {
  return firstEnv(['DB_PATH']) || path.join(dataRoot(), 'firealive.db');
}

// services/logger.js — LOG_PATH
function logsDir() {
  return subDir(['LOG_PATH'], 'logs');
}

// services/backup.js, services/backup-full-suite.js — BACKUP_DIR, BACKUP_PATH.
// The optional override argument preserves resolveBackupDir(override).
function backupsDir(override) {
  if (override && String(override).trim()) return path.resolve(String(override).trim());
  return subDir(['BACKUP_DIR', 'BACKUP_PATH'], 'backups');
}

// services/archive-segment.js — ARCHIVE_PENDING_DIR
function archivePendingDir() {
  return subDir(['ARCHIVE_PENDING_DIR'], 'archive-pending');
}

// services/cef-archive-spool.js — CEF_SPOOL_DIR
function cefSpoolDir() {
  return subDir(['CEF_SPOOL_DIR'], 'cef-spool');
}

// services/cicd-generator.js — CICD_CONFIGS_DIR
function cicdConfigsDir() {
  return subDir(['CICD_CONFIGS_DIR'], 'cicd-configs');
}

// services/cloud-iac-generator.js — CLOUD_PACKAGES_DIR
function cloudPackagesDir() {
  return subDir(['CLOUD_PACKAGES_DIR'], 'cloud-packages');
}

// services/migration-bundle.js, routes/migration.js — MIGRATION_BUNDLE_DIR
function migrationBundlesDir() {
  return subDir(['MIGRATION_BUNDLE_DIR'], 'migration-bundles');
}

module.exports = {
  DIR_MODE,
  dataRoot,
  ensureDir,
  dbPath,
  logsDir,
  backupsDir,
  archivePendingDir,
  cefSpoolDir,
  cicdConfigsDir,
  cloudPackagesDir,
  migrationBundlesDir,
};

// ===============================================================================
// FIREALIVE -- External Restore: Network Share (SMB/CIFS) Source Adapter (v2)
//
// Source adapter for the External Restore feature. Operates on the v2
// directory-layout contract documented in
// services/external-restore/_README (or below): each backup is a folder
// named firealive-backup-<iso-ts> containing 4 files
// (archive.tar.zst.enc, wrapped-key.bin, manifest.json, manifest.sig).
//
// CONTRACT (shared across all 5 source adapters)
//
//   listBackups(ctx) -> { backups: [{ id, modifiedAt, sizeBytes }] }
//     Enumerates folders matching BACKUP_FOLDER_RE in the source's
//     base path. id = folder name (no slashes). modifiedAt = manifest.
//     json mtime as ISO-8601. sizeBytes = sum of all 4 files in folder.
//     Newest first. Folders that don't have all 4 expected files are
//     skipped (likely partial uploads).
//
//   fetchFile(ctx, backupId, filename) -> Buffer
//     Read one named file from a backup folder. filename must be one
//     of BACKUP_FILE_NAMES. Path-traversal-safe (rejects ../ etc).
//     archive.tar.zst.enc may be large (up to MAX_BACKUP_SIZE_BYTES,
//     8 GB); manifest.json/manifest.sig are bounded to
//     MAX_MANIFEST_BYTES (1 MB) for safety.
//
//   verifyStructure(ctx, backupId) -> { ok, missing[], present[],
//                                        totalSizeBytes }
//     Cheap structural check. Confirms all 4 expected files exist
//     with sizes within reasonable bounds. Does NOT verify Ed25519
//     manifest signature or file SHA-256 hashes -- that's the
//     orchestrator's job (services/external-restore.js, commit 8)
//     because crypto verification doesn't depend on the backend and
//     keeping it out of adapters keeps the adapter surface pure-I/O.
//
// OPERATING MODEL
//
// This adapter assumes the SMB/CIFS share is already mounted at the OS
// level (e.g. via /etc/fstab with mount.cifs, systemd automount, or
// equivalent). The GD reads from a local mount point on its filesystem;
// it does NOT perform mounting itself. This is a deliberate security
// and operational choice:
//
//   1. mount.cifs requires root or a specially-configured suid binary.
//      Embedding privileged mount logic in the FireAlive process would
//      widen the privilege surface unnecessarily.
//
//   2. SMB credentials managed via OS-level secrets (a credentials file
//      with 0600 perms, or a Kerberos keytab) are easier to audit and
//      rotate than credentials stored in FireAlive's DB.
//
//   3. SOC backup shares are typically read by multiple consumers
//      (FireAlive, monitoring agents, manual ops). One OS mount with
//      many readers is the canonical UNIX pattern.
//
// The credentials_encrypted field on a network_share source row holds
// METADATA for documentation/audit purposes only -- it is not used to
// authenticate the share at runtime. A typical credentials object:
//
//   {
//     "host": "fileserver.corp.local",
//     "share": "backups",
//     "username": "svc-firealive",
//     "domain": "CORP",
//     "note": "OS-mounted at /mnt/backups via /etc/fstab"
//   }
//
// The PATH field on the source row MUST be an absolute local directory
// path that resolves to an existing directory on the GD server. Validate
// at PUT time and re-validate on every adapter call.
//
// Customers who prefer in-process SMB (no OS mount) can extend or replace
// this adapter with samba-client or a similar library. The canonical
// ships with the OS-mount model.
//
// AGPL-3.0-or-later
// ===============================================================================

const fs = require('fs');
const path = require('path');

// -- Shared adapter constants -------------------------------------------------

// V2 directory layout: each backup is a folder, not a single file.
const BACKUP_FOLDER_RE = /^firealive-backup-\d{8}T\d{6}Z$/;

const BACKUP_FILE_NAMES = Object.freeze([
  'archive.tar.zst.enc',
  'wrapped-key.bin',
  'manifest.json',
  'manifest.sig',
]);
const BACKUP_FILE_NAMES_SET = new Set(BACKUP_FILE_NAMES);

// Hard upper bound on archive size to prevent a misconfigured source from
// exhausting GD memory. The lead's ops policy should set a lower per-
// deployment limit; this is the absolute ceiling.
const MAX_BACKUP_SIZE_BYTES = 8 * 1024 * 1024 * 1024;  // 8 GB

// Manifest + signature are tiny by design (a few KB at most). Cap defensively.
const MAX_MANIFEST_BYTES = 1 * 1024 * 1024;  // 1 MB

// -- Helpers ---------------------------------------------------------------

/**
 * Validate the source path as an absolute, existing, readable directory
 * on the local filesystem. Throws on failure with a clear message.
 */
function validateMountPoint(mountPath) {
  if (typeof mountPath !== 'string' || !mountPath.trim()) {
    throw new Error('source path is empty');
  }
  if (!path.isAbsolute(mountPath)) {
    throw new Error(`source path must be absolute, got: ${mountPath}`);
  }
  let stat;
  try { stat = fs.statSync(mountPath); }
  catch (err) {
    if (err.code === 'ENOENT') throw new Error(`source path does not exist: ${mountPath}`);
    if (err.code === 'EACCES') throw new Error(`source path not readable (permission denied): ${mountPath}`);
    throw new Error(`source path stat failed (${err.code}): ${mountPath}`);
  }
  if (!stat.isDirectory()) {
    throw new Error(`source path is not a directory: ${mountPath}`);
  }
  // Probe readability with a directory list -- catches read-perm-denied
  // even when stat succeeds (rare but observed in NFS no_root_squash setups).
  try { fs.readdirSync(mountPath); }
  catch (err) {
    throw new Error(`source path not readable (${err.code}): ${mountPath}`);
  }
}

/**
 * Resolve a backup identifier to its absolute on-disk folder path inside
 * the mount point. Defends against path traversal: backupId must match
 * BACKUP_FOLDER_RE (no slashes, no ..) and the resolved path must
 * remain inside the mount point. Throws on failure.
 */
function resolveBackupFolder(mountPath, backupId) {
  if (typeof backupId !== 'string' || !BACKUP_FOLDER_RE.test(backupId)) {
    throw new Error(`backupId '${backupId}' is not a valid v2 backup folder name`);
  }
  const fullPath = path.resolve(mountPath, backupId);
  const normMount = path.resolve(mountPath);
  if (!fullPath.startsWith(normMount + path.sep) && fullPath !== normMount) {
    throw new Error(`backupId '${backupId}' resolves outside the mount point -- refusing`);
  }
  return fullPath;
}

/**
 * Resolve a file within a backup folder. Path-traversal-safe: filename
 * must be in the BACKUP_FILE_NAMES_SET allowlist, AND the resolved path
 * must remain inside the backup folder. Throws on failure.
 */
function resolveBackupFile(mountPath, backupId, filename) {
  const folderPath = resolveBackupFolder(mountPath, backupId);
  if (typeof filename !== 'string' || !BACKUP_FILE_NAMES_SET.has(filename)) {
    throw new Error(
      `filename '${filename}' is not one of the expected v2 backup files: ` +
      BACKUP_FILE_NAMES.join(', '),
    );
  }
  const fullPath = path.resolve(folderPath, filename);
  if (!fullPath.startsWith(folderPath + path.sep) && fullPath !== folderPath) {
    throw new Error(`file '${filename}' resolves outside backup folder -- refusing`);
  }
  return fullPath;
}

/**
 * Sum the sizes of all expected v2 files in a backup folder. Returns
 * `{ totalSize, missing[], present[] }`. Used by listBackups to
 * compute sizeBytes and by verifyStructure to report completeness.
 */
function inventoryFolder(folderPath) {
  const present = [];
  const missing = [];
  let totalSize = 0;
  for (const name of BACKUP_FILE_NAMES) {
    const filePath = path.join(folderPath, name);
    let st;
    try { st = fs.statSync(filePath); }
    catch (err) {
      if (err.code === 'ENOENT') { missing.push(name); continue; }
      throw new Error(`stat failed for ${name}: ${err.code}`);
    }
    if (!st.isFile()) {
      missing.push(name);
      continue;
    }
    present.push(name);
    totalSize += st.size;
  }
  return { totalSize, missing, present };
}

// -- Adapter API -----------------------------------------------------------

/**
 * List all v2 backup folders in the source's mount-point directory.
 * Folders missing one or more of the 4 expected files are skipped
 * (partial-upload state) and noted in ctx.log.
 */
async function listBackups(ctx) {
  const mountPath = ctx.config.path;
  validateMountPoint(mountPath);

  let entries;
  try {
    entries = fs.readdirSync(mountPath, { withFileTypes: true });
  } catch (err) {
    throw new Error(`failed to list ${mountPath}: ${err.code || err.message}`);
  }

  const backups = [];
  let skippedPartial = 0;
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    if (!BACKUP_FOLDER_RE.test(ent.name)) continue;

    const folderPath = path.join(mountPath, ent.name);
    let inv;
    try { inv = inventoryFolder(folderPath); }
    catch { continue; }

    if (inv.missing.length > 0) {
      skippedPartial += 1;
      ctx.log('warn', 'listBackups: skipping partial backup folder', {
        backupId: ent.name, missing: inv.missing,
      });
      continue;
    }

    let manifestMtime;
    try {
      manifestMtime = fs.statSync(path.join(folderPath, 'manifest.json')).mtime;
    } catch { continue; }

    backups.push({
      id: ent.name,
      modifiedAt: manifestMtime.toISOString(),
      sizeBytes: inv.totalSize,
    });
  }

  // Newest first -- leads typically restore the most recent verified backup.
  backups.sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt));
  ctx.log('info', 'listBackups completed', {
    mountPath, count: backups.length, skippedPartial,
  });
  return { backups };
}

/**
 * Read one named file from a v2 backup folder into a Buffer. Caller
 * (orchestrator) handles decryption, decompression, and signature
 * verification.
 */
async function fetchFile(ctx, backupId, filename) {
  const mountPath = ctx.config.path;
  validateMountPoint(mountPath);
  const fullPath = resolveBackupFile(mountPath, backupId, filename);

  let st;
  try { st = fs.statSync(fullPath); }
  catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`file ${filename} not found in backup ${backupId}`);
    }
    throw new Error(`stat failed for ${backupId}/${filename}: ${err.code}`);
  }
  if (!st.isFile()) {
    throw new Error(`${backupId}/${filename} resolves to a non-file`);
  }

  const isManifestFile = filename === 'manifest.json' || filename === 'manifest.sig';
  const sizeLimit = isManifestFile ? MAX_MANIFEST_BYTES : MAX_BACKUP_SIZE_BYTES;
  if (st.size > sizeLimit) {
    throw new Error(
      `${backupId}/${filename} exceeds maximum supported size ` +
      `(${st.size} bytes > ${sizeLimit})`,
    );
  }

  let content;
  try {
    content = fs.readFileSync(fullPath);
  } catch (err) {
    throw new Error(`read failed for ${backupId}/${filename} (${err.code})`);
  }
  ctx.log('info', 'fetchFile completed', {
    backupId, filename, sizeBytes: content.length,
  });
  return content;
}

/**
 * Lightweight structural check: confirms all 4 expected files exist in
 * the backup folder and reports their sizes. Does NOT verify Ed25519
 * signature or file SHA-256 hashes -- the orchestrator handles that
 * because crypto doesn't depend on the backend.
 *
 * Returns:
 *   { ok, missing[], present[], totalSizeBytes }
 *
 * ok = (missing.length === 0).
 */
async function verifyStructure(ctx, backupId) {
  const mountPath = ctx.config.path;
  validateMountPoint(mountPath);
  const folderPath = resolveBackupFolder(mountPath, backupId);

  let st;
  try { st = fs.statSync(folderPath); }
  catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`backup folder not found: ${backupId}`);
    }
    throw new Error(`stat failed for ${backupId}: ${err.code}`);
  }
  if (!st.isDirectory()) {
    throw new Error(`backup id resolves to a non-directory: ${backupId}`);
  }

  const inv = inventoryFolder(folderPath);
  const result = {
    ok: inv.missing.length === 0,
    present: inv.present,
    missing: inv.missing,
    totalSizeBytes: inv.totalSize,
  };
  ctx.log('info', 'verifyStructure completed', {
    backupId, ok: result.ok, missingCount: inv.missing.length,
  });
  return result;
}

// -- Module exports --------------------------------------------------------

module.exports = {
  listBackups,
  fetchFile,
  verifyStructure,

  // Constants exposed for orchestrator + tests
  BACKUP_FOLDER_RE,
  BACKUP_FILE_NAMES,
  MAX_BACKUP_SIZE_BYTES,
  MAX_MANIFEST_BYTES,

  // Internal helpers exposed for tests only
  _internal: {
    validateMountPoint,
    resolveBackupFolder,
    resolveBackupFile,
    inventoryFolder,
  },
};

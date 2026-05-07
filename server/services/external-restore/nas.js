// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — External Restore: NAS (NFS) Source Adapter
//
// Second of five source adapters for the External Restore feature.
// Operates on the same listBackups / fetchBackup / verifyIntegrity
// contract as network-share.js (commit 4); see that file for the
// full adapter API documentation.
//
// ═══════════════════════════════════════════════════════════════════════════════
//
// OPERATING MODEL
//
// This adapter assumes the NFS export is already mounted at the OS
// level (e.g. via /etc/fstab with type=nfs/nfs4, autofs, or systemd
// .mount/.automount units). The MC reads from a local mount point on
// its filesystem; it does NOT perform mounting itself.
//
// As with the SMB adapter (network-share.js), three rationales support
// delegation to the OS:
//
//   1. mount.nfs requires root privileges. Embedding privileged mount
//      logic in the FireAlive process would widen the privilege surface.
//
//   2. NFS authentication is heterogeneous — the historical default is
//      AUTH_SYS (effectively trust IP + UID/GID), modern deployments
//      prefer AUTH_GSS (Kerberos). Both rely on infrastructure
//      external to FireAlive (NIS, FreeIPA, AD, /etc/krb5.conf, the
//      keytab file). Replicating that resolution chain inside an
//      application would be a maintenance disaster.
//
//   3. NFS exports are commonly read by multiple consumers; one OS
//      mount with many readers is the canonical pattern.
//
// The credentials_encrypted field on a nas source row holds metadata
// for documentation/audit purposes only. NFS commonly has no per-user
// credential — authentication is by host IP allow-list at the NFS
// server end, or by Kerberos principal mapped from the OS-level
// credential. A typical credentials object:
//
//   {
//     "host": "nas01.corp.local",
//     "export_path": "/vol/firealive_backups",
//     "mount_options": "nfsvers=4.2,sec=krb5p,hard,intr",
//     "kerberos_principal": "host/firealive-mc.corp.local@CORP.LOCAL",
//     "note": "OS-mounted at /mnt/nas-backups via systemd nas-backups.mount"
//   }
//
// For NFS without authentication (legacy AUTH_SYS deployments, lab
// environments), credentials may be an empty object. The route handler
// validates the shape but does not require any field non-empty.
//
// The PATH field on the source row MUST be an absolute local directory
// path that resolves to an existing readable directory.
//
// Customers using non-NFS NAS protocols (AFP, iSCSI, internal vendor
// protocols) can either use the network-share adapter where appropriate
// or extend this adapter family with a new type. Apple Filing Protocol
// (AFP) is deliberately not first-classed — Apple deprecated AFP in
// macOS 10.9 in favor of SMB, so AFP-served data should use the
// network-share adapter against an SMB or AFP-over-SMB mount.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// FireAlive backup file naming convention: <type>-<timestamp>.tar.gz.enc
// Match conservatively so we don't enumerate unrelated files in the
// share. The .enc suffix is canonical even when no encryption is in
// use (the orchestrator handles the no-decryption-key case).
const BACKUP_FILENAME_RE = /^[A-Za-z0-9_\-]{1,80}-\d{8}T\d{6}Z\.tar\.gz(?:\.enc)?$/;

// Hard limit on per-fetch read size so a misconfigured source can't
// exhaust the MC's memory by streaming a multi-terabyte file. The lead
// configures a sane upper bound at deployment time; this is the hard
// ceiling. Backups beyond this size cannot be restored via the UI flow
// — operator must use a more direct mechanism.
const MAX_BACKUP_SIZE_BYTES = 8 * 1024 * 1024 * 1024;  // 8 GB

// ── Helpers ───────────────────────────────────────────────────────────────

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
  // Probe readability with a directory list — catches read-perm-denied
  // even when stat succeeds (rare but observed in NFS no_root_squash setups).
  try { fs.readdirSync(mountPath); }
  catch (err) {
    throw new Error(`source path not readable (${err.code}): ${mountPath}`);
  }
}

/**
 * Resolve a backup identifier to its absolute on-disk path inside the
 * mount point. The id is the filename (basename) — adapters use the
 * filename as the stable identifier rather than synthesizing a UUID,
 * because backups on disk persist across MC restarts and the filename
 * is the natural primary key.
 *
 * Defends against path traversal: backupId must match the backup
 * filename regex (no slashes, no ..) and the resolved path must remain
 * inside the mount point. If either check fails, throws.
 */
function resolveBackupPath(mountPath, backupId) {
  if (typeof backupId !== 'string' || !BACKUP_FILENAME_RE.test(backupId)) {
    throw new Error(`backupId '${backupId}' is not a valid FireAlive backup filename`);
  }
  const fullPath = path.resolve(mountPath, backupId);
  // path.resolve normalizes; the result must still start with the mount
  // point (plus separator) for a backup that lives directly inside.
  const normMount = path.resolve(mountPath);
  if (!fullPath.startsWith(normMount + path.sep) && fullPath !== normMount) {
    throw new Error(`backupId '${backupId}' resolves outside the mount point — refusing`);
  }
  return fullPath;
}

// ── Adapter API ───────────────────────────────────────────────────────────

/**
 * List all backup-shaped files in the source's mount-point directory.
 * Returns metadata (filename as id, size, mtime) without reading file
 * contents.
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
  for (const ent of entries) {
    if (!ent.isFile()) continue;
    if (!BACKUP_FILENAME_RE.test(ent.name)) continue;
    const fullPath = path.join(mountPath, ent.name);
    let st;
    try { st = fs.statSync(fullPath); } catch { continue; }
    backups.push({
      id: ent.name,
      filename: ent.name,
      sizeBytes: st.size,
      modifiedAt: st.mtime.toISOString(),
    });
  }
  // Newest first — leads typically restore the most recent verified backup.
  backups.sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt));
  ctx.log('info', 'listBackups completed', { mountPath, count: backups.length });
  return { backups };
}

/**
 * Read the entire backup archive into a Buffer. Caller (orchestrator)
 * is responsible for decryption and decompression. Enforces
 * MAX_BACKUP_SIZE_BYTES to bound memory.
 */
async function fetchBackup(ctx, backupId) {
  const mountPath = ctx.config.path;
  validateMountPoint(mountPath);
  const fullPath = resolveBackupPath(mountPath, backupId);

  let st;
  try { st = fs.statSync(fullPath); }
  catch (err) {
    if (err.code === 'ENOENT') throw new Error(`backup not found: ${backupId}`);
    throw new Error(`stat failed for ${backupId}: ${err.code}`);
  }
  if (!st.isFile()) {
    throw new Error(`backup id resolves to a non-file: ${backupId}`);
  }
  if (st.size > MAX_BACKUP_SIZE_BYTES) {
    throw new Error(`backup ${backupId} exceeds maximum supported size (${st.size} bytes > ${MAX_BACKUP_SIZE_BYTES})`);
  }

  let content;
  try {
    content = fs.readFileSync(fullPath);
  } catch (err) {
    throw new Error(`read failed for ${backupId} (${err.code})`);
  }
  ctx.log('info', 'fetchBackup completed', { backupId, sizeBytes: content.length });
  return content;
}

/**
 * Streaming SHA-256 over the backup file. Compares against an optional
 * expected hash supplied by the caller. Used both before fetch (the
 * orchestrator may pre-verify a backup before deciding to download it)
 * and as a stand-alone integrity check.
 */
async function verifyIntegrity(ctx, backupId, opts = {}) {
  const mountPath = ctx.config.path;
  validateMountPoint(mountPath);
  const fullPath = resolveBackupPath(mountPath, backupId);

  let st;
  try { st = fs.statSync(fullPath); }
  catch (err) {
    if (err.code === 'ENOENT') throw new Error(`backup not found: ${backupId}`);
    throw new Error(`stat failed for ${backupId}: ${err.code}`);
  }

  const hash = crypto.createHash('sha256');
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(fullPath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', resolve);
    stream.on('error', reject);
  });
  const sha256 = hash.digest('hex');

  const result = {
    ok: !opts.expectedSha256 || (sha256 === opts.expectedSha256),
    sha256,
    sizeBytes: st.size,
  };
  if (opts.expectedSha256) result.expectedSha256 = opts.expectedSha256;
  ctx.log('info', 'verifyIntegrity completed', { backupId, sha256: sha256.slice(0, 12) + '...', ok: result.ok });
  return result;
}

module.exports = { listBackups, fetchBackup, verifyIntegrity };

// ===============================================================================
// FIREALIVE -- External Restore: SFTP Source Adapter (v2 directory layout)
//
// Source adapter for the External Restore feature. Operates on the v2
// directory-layout contract (see nas.js for the canonical contract
// documentation; identical for all 5 source adapters): each backup is
// a folder named firealive-backup-<iso-ts> containing 4 files
// (archive.tar.zst.enc, wrapped-key.bin, manifest.json, manifest.sig).
//
// CONTRACT (shared across all 5 source adapters)
//
//   listBackups(ctx)                  -> { backups: [{ id, modifiedAt,
//                                                       sizeBytes }] }
//   fetchFile(ctx, backupId, name)    -> Buffer
//   verifyStructure(ctx, backupId)    -> { ok, missing[], present[],
//                                           totalSizeBytes }
//
//   Crypto verification (Ed25519 sig + file SHA-256s) happens in the
//   orchestrator (services/external-restore.js, commit 8), not the
//   adapter -- adapters are pure I/O.
//
// IMPLEMENTATION NOTES
//
// SFTP is the only adapter that requires an external SSH library --
// there is no "raw SFTP" without a real SSH client. This adapter uses
// the 'ssh2' npm package directly (not the higher-level
// 'ssh2-sftp-client' wrapper) to keep the dependency surface minimal.
//
// 'ssh2' is added to dependencies in package.json (commit 14 of R3d-4
// part 2 if needed; ssh2 ships as a transitive of several existing
// dependencies). Until ssh2 is reachable, this adapter file sits on
// disk but throws MODULE_NOT_FOUND if the orchestrator dispatches to
// it -- acceptable because no other code paths invoke this file
// before the orchestrator is wired in commit 9.
//
// CREDENTIALS SHAPE on a source row (decrypted by the orchestrator):
//
//   {
//     "host":                 "sftp-backup.corp.local",   // required
//     "port":                 22,                          // optional, default 22
//     "username":             "firealive-readonly",        // required
//     "password":             "...",                       // optional (one of password/privateKey required)
//     "privateKey":           "-----BEGIN OPENSSH PRIVATE KEY-----\n...", // optional
//     "passphrase":           "...",                       // optional, decrypts privateKey
//     "hostKeyFingerprint":   "SHA256:abc123..."          // REQUIRED -- see Host Key Verification below
//   }
//
// One of `password` or `privateKey` is required (not both). Per-source
// choice -- the lead picks at configure time. Public-key auth is the
// SOC-grade default.
//
// HOST KEY VERIFICATION -- REQUIRED PINNING
//
// SFTP servers identify themselves with a host key the client must
// pin to detect MITM attacks. This adapter REQUIRES fingerprint
// pinning -- credentials.hostKeyFingerprint must be set to the
// expected SHA256 fingerprint (e.g. "SHA256:abc123..."). If the
// server's key doesn't match, the connection is refused.
//
// This is a deliberate SOC-grade default. SOC operators routinely
// capture host key fingerprints out-of-band during initial setup
// (a one-time `ssh-keyscan` against a trusted network or vendor-
// supplied known-hosts entry). Accepting unknown keys silently is
// the kind of degradation that turns "we have backup recovery" into
// "we trust whoever answers on the IP" -- exactly the failure mode
// External Restore is meant to defend against.
//
// Captured fingerprint format must be SHA256 base64 with the trailing
// '=' stripped, prefixed with "SHA256:". Standard `ssh-keyscan` output
// can be converted with `ssh-keygen -lf <known_hosts_file>`. The
// route handler validates the format on PUT.
//
// PATH on a source row is the absolute directory path on the SFTP
// server where backup folders live (e.g. "/srv/backups/firealive").
// Backup IDs are folder names within that directory, matching
// BACKUP_FOLDER_RE.
//
// AGPL-3.0-or-later
// ===============================================================================

const crypto = require('crypto');
const { Client } = require('ssh2');
const { validateAllowedHost } = require('../gd-external-restore-allow-list');

// -- Shared adapter constants -------------------------------------------------

const BACKUP_FOLDER_RE = /^firealive-backup-\d{8}T\d{6}Z$/;

const BACKUP_FILE_NAMES = Object.freeze([
  'archive.tar.zst.enc',
  'wrapped-key.bin',
  'manifest.json',
  'manifest.sig',
]);
const BACKUP_FILE_NAMES_SET = new Set(BACKUP_FILE_NAMES);

const MAX_BACKUP_SIZE_BYTES = 8 * 1024 * 1024 * 1024;  // 8 GB
const MAX_MANIFEST_BYTES = 1 * 1024 * 1024;            // 1 MB

// SSH connection lifecycle is per-operation by design: a single
// orchestrator pass through the adapter (list -> manifest -> wrapped-key
// -> archive) does ~3-4 SFTP operations. Holding a long-lived
// connection across them would shave ~300ms but adds idle-connection
// management complexity we don't need at this throughput level.
const CONNECT_TIMEOUT_MS = 30000;
const OPERATION_TIMEOUT_MS = 600000;        // 10 min for full fetches

// -- Helpers ---------------------------------------------------------------

function validateCredentials(creds) {
  if (!creds || typeof creds !== 'object') {
    throw new Error('credentials missing or not an object');
  }
  for (const k of ['host', 'username']) {
    if (typeof creds[k] !== 'string' || !creds[k].trim()) {
      throw new Error(`credentials.${k} required`);
    }
  }
  if (!creds.password && !creds.privateKey) {
    throw new Error('credentials must include either password or privateKey');
  }
  if (creds.password && creds.privateKey) {
    throw new Error('credentials must include password OR privateKey, not both');
  }
  if (creds.privateKey) {
    if (!/-----BEGIN (OPENSSH|RSA|EC|DSA|ENCRYPTED) PRIVATE KEY-----/.test(creds.privateKey)) {
      throw new Error('credentials.privateKey does not look like a PEM-encoded private key');
    }
  }
  if (creds.port !== undefined) {
    const p = parseInt(creds.port, 10);
    if (!Number.isFinite(p) || p < 1 || p > 65535) {
      throw new Error(`credentials.port '${creds.port}' is not a valid TCP port (1-65535)`);
    }
  }
  if (!creds.hostKeyFingerprint) {
    throw new Error('credentials.hostKeyFingerprint required (SOC-grade default -- capture fingerprint out-of-band via ssh-keyscan + ssh-keygen -lf, format "SHA256:...")');
  }
  if (!/^SHA256:[A-Za-z0-9+/=]{40,50}$/.test(creds.hostKeyFingerprint)) {
    throw new Error('credentials.hostKeyFingerprint must be in SHA256:... format');
  }
}

/**
 * Validate the source's path field. Must be an absolute POSIX-style
 * directory path on the remote SFTP server. We do NOT prefix-resolve
 * here (the remote path is opaque to local fs.path semantics) -- but
 * we reject obviously bad inputs.
 */
function validateRemotePath(remotePath) {
  if (typeof remotePath !== 'string' || !remotePath.trim()) {
    throw new Error('source path is empty');
  }
  if (!remotePath.startsWith('/')) {
    throw new Error(`source path must be absolute POSIX path, got: ${remotePath}`);
  }
  if (remotePath.includes('\0')) {
    throw new Error('source path contains null byte');
  }
}

/**
 * Validate a backupId for v2 directory layout. backupId is a folder
 * name (no slashes), matching BACKUP_FOLDER_RE.
 */
function validateBackupId(backupId) {
  if (typeof backupId !== 'string' || !BACKUP_FOLDER_RE.test(backupId)) {
    throw new Error(`backupId '${backupId}' is not a valid v2 backup folder name`);
  }
}

/**
 * Validate a filename for v2 directory layout. Must be one of the 4
 * expected files inside a backup folder.
 */
function validateFilename(filename) {
  if (typeof filename !== 'string' || !BACKUP_FILE_NAMES_SET.has(filename)) {
    throw new Error(
      `filename '${filename}' is not one of the expected v2 backup files: ` +
      BACKUP_FILE_NAMES.join(', '),
    );
  }
}

/**
 * Build a remote folder path: source's path + backupId.
 */
function joinRemoteFolder(remoteDir, backupId) {
  const trimmed = remoteDir.replace(/\/+$/, '');
  return `${trimmed}/${backupId}`;
}

/**
 * Build a remote file path: source's path + backupId + filename.
 */
function joinRemoteFile(remoteDir, backupId, filename) {
  return `${joinRemoteFolder(remoteDir, backupId)}/${filename}`;
}

/**
 * Open an SSH connection, run an operation, close cleanly. The
 * operation is given the SFTP session and must return a Promise.
 */
function withSftp(creds, log, op) {
  return new Promise((resolve, reject) => {
    const allowed = validateAllowedHost(creds.host);
    if (!allowed.ok) {
      return reject(new Error(`outbound host ${creds.host} rejected: ${allowed.error}`));
    }

    const conn = new Client();
    let settled = false;
    const settle = (err, value) => {
      if (settled) return;
      settled = true;
      try { conn.end(); } catch { /* best effort */ }
      err ? reject(err) : resolve(value);
    };

    const config = {
      host: creds.host,
      port: creds.port || 22,
      username: creds.username,
      readyTimeout: CONNECT_TIMEOUT_MS,
    };
    if (creds.password) config.password = creds.password;
    if (creds.privateKey) {
      config.privateKey = creds.privateKey;
      if (creds.passphrase) config.passphrase = creds.passphrase;
    }

    // Host key verification -- REQUIRED PINNING (see file header).
    config.hostVerifier = (key) => {
      const hash = crypto.createHash('sha256').update(key).digest('base64')
        .replaceAll('=', '');  // SSH fingerprint convention strips trailing '='
      const fingerprint = `SHA256:${hash}`;
      if (creds.hostKeyFingerprint !== fingerprint) {
        log('error', 'sftp host key MISMATCH -- refusing connection', {
          expected: creds.hostKeyFingerprint,
          received: fingerprint,
          host: creds.host,
        });
        return false;
      }
      return true;
    };

    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) return settle(new Error(`sftp session open failed: ${err.message}`));
        Promise.resolve(op(sftp))
          .then((result) => settle(null, result))
          .catch((opErr) => settle(opErr));
      });
    });
    conn.on('error', (err) => settle(new Error(`ssh connection failed: ${err.message}`)));
    const opTimer = setTimeout(() => {
      settle(new Error(`sftp operation timed out after ${OPERATION_TIMEOUT_MS}ms`));
    }, OPERATION_TIMEOUT_MS);
    conn.on('close', () => clearTimeout(opTimer));

    try { conn.connect(config); }
    catch (err) { settle(new Error(`ssh connect threw: ${err.message}`)); }
  });
}

/**
 * One SFTP readdir call returning all entries in a backup folder.
 * Used by listBackups (per candidate folder) and verifyStructure.
 * Returns { totalSize, missing[], present[], manifestMtime }.
 *
 * manifestMtime is the manifest.json mtime as a Unix timestamp
 * (number of seconds; SFTP convention) or null if missing.
 */
function inventoryFolderFromReaddir(entries) {
  const present = [];
  const missing = [];
  let totalSize = 0;
  let manifestMtime = null;

  const byName = new Map();
  for (const ent of entries) {
    byName.set(ent.filename, ent);
  }

  for (const name of BACKUP_FILE_NAMES) {
    const ent = byName.get(name);
    if (!ent || !ent.attrs || !ent.attrs.isFile()) {
      missing.push(name);
      continue;
    }
    present.push(name);
    totalSize += ent.attrs.size;
    if (name === 'manifest.json') {
      manifestMtime = ent.attrs.mtime;
    }
  }

  return { totalSize, missing, present, manifestMtime };
}

// -- Adapter API -----------------------------------------------------------

/**
 * List all v2 backup folders in the source's remote directory. For
 * each candidate folder name (matches BACKUP_FOLDER_RE), opens the
 * folder once via SFTP readdir to confirm completeness and compute
 * total size. Folders missing any of the 4 expected files are skipped
 * (likely partial uploads or in-progress backups) and the skip count
 * is logged.
 *
 * One readdir per candidate folder. For a directory with N backup
 * folders, this is N+1 SFTP round trips. At typical SOC-shop scale
 * (dozens of backups, not thousands), the latency is acceptable.
 */
async function listBackups(ctx) {
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const remoteDir = ctx.config.path;
  validateRemotePath(remoteDir);

  return withSftp(creds, ctx.log, async (sftp) => {
    const topEntries = await new Promise((resolve, reject) => {
      sftp.readdir(remoteDir, (err, list) => {
        if (err) return reject(new Error(`readdir ${remoteDir}: ${err.message}`));
        resolve(list);
      });
    });

    const candidates = [];
    for (const ent of topEntries) {
      if (!ent.attrs || !ent.attrs.isDirectory()) continue;
      if (!BACKUP_FOLDER_RE.test(ent.filename)) continue;
      candidates.push(ent.filename);
    }

    const backups = [];
    let skippedPartial = 0;

    // Sequential rather than parallel: SFTP servers commonly limit
    // concurrent operations per connection (typically 8-16). Going
    // sequential is slower but predictable and avoids triggering the
    // server's rate limits. For high-cadence deployments, future work
    // could batch with a small concurrency limit.
    for (const folderName of candidates) {
      const folderPath = joinRemoteFolder(remoteDir, folderName);
      let folderEntries;
      try {
        folderEntries = await new Promise((resolve, reject) => {
          sftp.readdir(folderPath, (err, list) => {
            if (err) return reject(new Error(`readdir ${folderPath}: ${err.message}`));
            resolve(list);
          });
        });
      } catch (err) {
        ctx.log('warn', 'listBackups: failed to read folder, skipping', {
          folderPath, error: err.message,
        });
        continue;
      }

      const inv = inventoryFolderFromReaddir(folderEntries);
      if (inv.missing.length > 0) {
        skippedPartial += 1;
        ctx.log('warn', 'listBackups: skipping partial backup folder', {
          backupId: folderName, missing: inv.missing,
        });
        continue;
      }

      backups.push({
        id: folderName,
        modifiedAt: new Date(inv.manifestMtime * 1000).toISOString(),
        sizeBytes: inv.totalSize,
      });
    }

    backups.sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt));
    ctx.log('info', 'listBackups completed', {
      remoteDir, count: backups.length, skippedPartial,
    });
    return { backups };
  });
}

/**
 * Read one named file from a v2 backup folder into a Buffer. Caller
 * (orchestrator) handles decryption, decompression, and signature
 * verification. Streams the file to bound memory growth and to enforce
 * the appropriate size limit during the read (not just at stat time --
 * defends against an attacker who fakes a small stat then streams a
 * huge body).
 */
async function fetchFile(ctx, backupId, filename) {
  validateBackupId(backupId);
  validateFilename(filename);
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const remoteDir = ctx.config.path;
  validateRemotePath(remoteDir);
  const remoteFile = joinRemoteFile(remoteDir, backupId, filename);

  const isManifestFile = filename === 'manifest.json' || filename === 'manifest.sig';
  const sizeLimit = isManifestFile ? MAX_MANIFEST_BYTES : MAX_BACKUP_SIZE_BYTES;

  return withSftp(creds, ctx.log, (sftp) => new Promise((resolve, reject) => {
    sftp.stat(remoteFile, (statErr, attrs) => {
      if (statErr) return reject(new Error(`stat ${remoteFile}: ${statErr.message}`));
      if (!attrs.isFile()) return reject(new Error(
        `${backupId}/${filename} resolves to a non-file`,
      ));
      if (attrs.size > sizeLimit) {
        return reject(new Error(
          `${backupId}/${filename} exceeds maximum supported size ` +
          `(${attrs.size} bytes > ${sizeLimit})`,
        ));
      }

      const stream = sftp.createReadStream(remoteFile);
      const chunks = [];
      let total = 0;
      stream.on('data', (c) => {
        total += c.length;
        if (total > sizeLimit) {
          stream.destroy(new Error(
            `${backupId}/${filename} exceeded size limit during stream`,
          ));
          return;
        }
        chunks.push(c);
      });
      stream.on('end', () => {
        const body = Buffer.concat(chunks);
        ctx.log('info', 'fetchFile completed', {
          backupId, filename, sizeBytes: body.length,
        });
        resolve(body);
      });
      stream.on('error', (err) => reject(new Error(
        `stream ${remoteFile}: ${err.message}`,
      )));
    });
  }));
}

/**
 * Lightweight structural check: opens the backup folder via SFTP
 * readdir and confirms all 4 expected files are present with
 * reasonable sizes. Does NOT verify Ed25519 signature or file SHA-
 * 256 hashes -- those live in the orchestrator (commit 8) where the
 * signing key is accessible.
 */
async function verifyStructure(ctx, backupId) {
  validateBackupId(backupId);
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const remoteDir = ctx.config.path;
  validateRemotePath(remoteDir);
  const folderPath = joinRemoteFolder(remoteDir, backupId);

  return withSftp(creds, ctx.log, (sftp) => new Promise((resolve, reject) => {
    sftp.stat(folderPath, (statErr, attrs) => {
      if (statErr) {
        if (statErr.code === 2 /* SFTP_STATUS_NO_SUCH_FILE */) {
          return reject(new Error(`backup folder not found: ${backupId}`));
        }
        return reject(new Error(`stat ${folderPath}: ${statErr.message}`));
      }
      if (!attrs.isDirectory()) {
        return reject(new Error(`backup id resolves to a non-directory: ${backupId}`));
      }

      sftp.readdir(folderPath, (rdErr, entries) => {
        if (rdErr) return reject(new Error(`readdir ${folderPath}: ${rdErr.message}`));
        const inv = inventoryFolderFromReaddir(entries);
        const result = {
          ok: inv.missing.length === 0,
          present: inv.present,
          missing: inv.missing,
          totalSizeBytes: inv.totalSize,
        };
        ctx.log('info', 'verifyStructure completed', {
          backupId, ok: result.ok, missingCount: inv.missing.length,
        });
        resolve(result);
      });
    });
  }));
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
    validateCredentials,
    validateRemotePath,
    validateBackupId,
    validateFilename,
    joinRemoteFolder,
    joinRemoteFile,
    inventoryFolderFromReaddir,
  },
};

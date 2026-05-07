// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — External Restore: SFTP Source Adapter
//
// Fifth and last of the source adapters for the External Restore feature.
// Operates on the listBackups / fetchBackup / verifyIntegrity contract
// shared with the other adapters in this directory; see network-share.js
// (commit 4) for the full adapter API documentation.
//
// ═══════════════════════════════════════════════════════════════════════════════
//
// IMPLEMENTATION NOTES
//
// SFTP is the only adapter that requires an external SSH library — there
// is no "raw SFTP" without a real SSH client. This adapter uses the
// 'ssh2' npm package directly (not the higher-level 'ssh2-sftp-client'
// wrapper) to keep the dependency surface minimal.
//
// 'ssh2' must be added to dependencies in package.json — landed in
// commit 9 of the R3d phase. Until that lands, this adapter file sits
// on disk but throws MODULE_NOT_FOUND if the orchestrator dispatches
// to it (acceptable because no other code paths invoke this file
// before the orchestrator is wired in commit 10).
//
// CREDENTIALS SHAPE on a source row (decrypted by the orchestrator):
//
//   {
//     "host":                 "sftp-backup.corp.local",  // required
//     "port":                 22,                         // optional, default 22
//     "username":             "firealive-readonly",       // required
//     "password":             "...",                      // optional (one of password/privateKey required)
//     "privateKey":           "-----BEGIN OPENSSH PRIVATE KEY-----\n...", // optional
//     "passphrase":           "...",                      // optional, decrypts privateKey
//     "hostKeyFingerprint":   "SHA256:abc123..."         // REQUIRED — see Host Key Verification below
//   }
//
// One of `password` or `privateKey` is required (not both). Per-source
// choice — the lead picks at configure time. Public-key auth is the
// SOC-grade default.
//
// HOST KEY VERIFICATION — REQUIRED PINNING
//
// SFTP servers identify themselves with a host key the client must
// pin to detect MITM attacks. This adapter REQUIRES fingerprint
// pinning — credentials.hostKeyFingerprint must be set to the
// expected SHA256 fingerprint (e.g. "SHA256:abc123..."). If the
// server's key doesn't match, the connection is refused.
//
// This is a deliberate SOC-grade default. SOC operators routinely
// capture host key fingerprints out-of-band during initial setup
// (a one-time `ssh-keyscan` against a trusted network or vendor-
// supplied known-hosts entry). Accepting unknown keys silently is
// the kind of degradation that turns "we have backup recovery" into
// "we trust whoever answers on the IP" — exactly the failure mode
// External Restore is meant to defend against.
//
// Captured fingerprint format must be SHA256 base64 with the trailing
// '=' stripped, prefixed with "SHA256:". Standard `ssh-keyscan` output
// can be converted with `ssh-keygen -lf <known_hosts_file>`. The
// route handler validates the format on PUT.
//
// PATH on a source row is the absolute directory path on the SFTP
// server where backups live (e.g. "/srv/backups/firealive"). Backup IDs
// are filenames within that directory.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const path = require('path');
const { Client } = require('ssh2');
const { validateAllowedHost } = require('../external-restore-allow-list');

const CONNECT_TIMEOUT_MS = 30000;
const OPERATION_TIMEOUT_MS = 600000;        // 10 min for full fetches
const MAX_BACKUP_SIZE_BYTES = 8 * 1024 * 1024 * 1024;  // 8 GB
const BACKUP_FILENAME_RE = /^[A-Za-z0-9_\-]{1,80}-\d{8}T\d{6}Z\.tar\.gz(?:\.enc)?$/;

// ── Helpers ───────────────────────────────────────────────────────────────

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
    throw new Error('credentials.hostKeyFingerprint required (SOC-grade default — capture fingerprint out-of-band via ssh-keyscan + ssh-keygen -lf, format "SHA256:...")');
  }
  if (!/^SHA256:[A-Za-z0-9+/=]{40,50}$/.test(creds.hostKeyFingerprint)) {
    throw new Error('credentials.hostKeyFingerprint must be in SHA256:... format');
  }
}

/**
 * Validate the source's path field. Must be an absolute POSIX-style
 * directory path on the remote SFTP server. We do NOT prefix-resolve
 * here (the remote path is opaque to local fs.path semantics) — but
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
 * Validate a backupId — same regex as the other adapters. Path
 * traversal defense: backupId is a filename only, no slashes.
 */
function validateBackupId(backupId) {
  if (typeof backupId !== 'string' || !BACKUP_FILENAME_RE.test(backupId)) {
    throw new Error(`backupId '${backupId}' is not a valid FireAlive backup filename`);
  }
}

/**
 * Build a remote path by joining the source's path + backupId. The
 * remote file system uses POSIX semantics regardless of the server's
 * underlying OS — SFTP normalizes to forward slashes.
 */
function joinRemote(remoteDir, backupId) {
  const trimmed = remoteDir.replace(/\/+$/, '');
  return `${trimmed}/${backupId}`;
}

/**
 * Open an SSH connection, run an operation, close cleanly. The
 * operation is given the SFTP session and must return a Promise.
 * Connection lifecycle is per-operation by design — see file header.
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
      // Strict cipher/kex/hostkey lists could be added here for
      // FIPS or hardened deployments. v1.0.30 uses ssh2's defaults
      // which already exclude legacy weak algorithms.
    };
    if (creds.password) config.password = creds.password;
    if (creds.privateKey) {
      config.privateKey = creds.privateKey;
      if (creds.passphrase) config.passphrase = creds.passphrase;
    }

    // Host key verification — REQUIRED PINNING (see file header).
    // validateCredentials guarantees creds.hostKeyFingerprint is set;
    // this verifier just confirms the server's key matches.
    config.hostVerifier = (key) => {
      const hash = crypto.createHash('sha256').update(key).digest('base64')
        .replace(/=+$/, '');  // SSH fingerprint convention strips trailing '='
      const fingerprint = `SHA256:${hash}`;
      if (creds.hostKeyFingerprint !== fingerprint) {
        log('error', 'sftp host key MISMATCH — refusing connection', {
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
    // Hard ceiling on the whole operation — defends against a
    // half-open connection that ready never fires on.
    const opTimer = setTimeout(() => {
      settle(new Error(`sftp operation timed out after ${OPERATION_TIMEOUT_MS}ms`));
    }, OPERATION_TIMEOUT_MS);
    conn.on('close', () => clearTimeout(opTimer));

    try { conn.connect(config); }
    catch (err) { settle(new Error(`ssh connect threw: ${err.message}`)); }
  });
}

// ── Adapter API ───────────────────────────────────────────────────────────

async function listBackups(ctx) {
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const remoteDir = ctx.config.path;
  validateRemotePath(remoteDir);

  return withSftp(creds, ctx.log, (sftp) => new Promise((resolve, reject) => {
    sftp.readdir(remoteDir, (err, list) => {
      if (err) return reject(new Error(`readdir ${remoteDir}: ${err.message}`));
      const backups = [];
      for (const ent of list) {
        if (!ent.attrs || !ent.attrs.isFile()) continue;
        if (!BACKUP_FILENAME_RE.test(ent.filename)) continue;
        backups.push({
          id: ent.filename,
          filename: ent.filename,
          sizeBytes: ent.attrs.size,
          modifiedAt: new Date(ent.attrs.mtime * 1000).toISOString(),
        });
      }
      backups.sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt));
      ctx.log('info', 'listBackups completed', { remoteDir, count: backups.length });
      resolve({ backups });
    });
  }));
}

async function fetchBackup(ctx, backupId) {
  validateBackupId(backupId);
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const remoteDir = ctx.config.path;
  validateRemotePath(remoteDir);
  const remoteFile = joinRemote(remoteDir, backupId);

  return withSftp(creds, ctx.log, (sftp) => new Promise((resolve, reject) => {
    sftp.stat(remoteFile, (statErr, attrs) => {
      if (statErr) return reject(new Error(`stat ${remoteFile}: ${statErr.message}`));
      if (!attrs.isFile()) return reject(new Error(`backup id resolves to a non-file: ${backupId}`));
      if (attrs.size > MAX_BACKUP_SIZE_BYTES) {
        return reject(new Error(`backup ${backupId} exceeds maximum supported size (${attrs.size} > ${MAX_BACKUP_SIZE_BYTES})`));
      }

      const stream = sftp.createReadStream(remoteFile);
      const chunks = [];
      let total = 0;
      stream.on('data', (c) => {
        total += c.length;
        if (total > MAX_BACKUP_SIZE_BYTES) {
          stream.destroy(new Error('exceeded MAX_BACKUP_SIZE_BYTES during stream'));
          return;
        }
        chunks.push(c);
      });
      stream.on('end', () => {
        const body = Buffer.concat(chunks);
        ctx.log('info', 'fetchBackup completed', { backupId, sizeBytes: body.length });
        resolve(body);
      });
      stream.on('error', (err) => reject(new Error(`stream ${remoteFile}: ${err.message}`)));
    });
  }));
}

async function verifyIntegrity(ctx, backupId, opts = {}) {
  validateBackupId(backupId);
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const remoteDir = ctx.config.path;
  validateRemotePath(remoteDir);
  const remoteFile = joinRemote(remoteDir, backupId);

  return withSftp(creds, ctx.log, (sftp) => new Promise((resolve, reject) => {
    sftp.stat(remoteFile, (statErr, attrs) => {
      if (statErr) return reject(new Error(`stat ${remoteFile}: ${statErr.message}`));
      const stream = sftp.createReadStream(remoteFile);
      const hash = crypto.createHash('sha256');
      let sizeBytes = 0;
      stream.on('data', (chunk) => {
        hash.update(chunk);
        sizeBytes += chunk.length;
        if (sizeBytes > MAX_BACKUP_SIZE_BYTES) {
          stream.destroy(new Error('exceeded MAX_BACKUP_SIZE_BYTES during stream'));
        }
      });
      stream.on('end', () => {
        const sha256 = hash.digest('hex');
        const out = {
          ok: !opts.expectedSha256 || (sha256 === opts.expectedSha256),
          sha256,
          sizeBytes,
        };
        if (opts.expectedSha256) out.expectedSha256 = opts.expectedSha256;
        ctx.log('info', 'verifyIntegrity completed', { backupId, sha256: sha256.slice(0, 12) + '...', ok: out.ok });
        resolve(out);
      });
      stream.on('error', (err) => reject(new Error(`stream ${remoteFile}: ${err.message}`)));
    });
  }));
}

module.exports = { listBackups, fetchBackup, verifyIntegrity };

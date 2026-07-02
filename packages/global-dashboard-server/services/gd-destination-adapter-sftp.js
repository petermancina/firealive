// =============================================================================
// FIREALIVE GD -- Destination Adapter: SFTP
//
// Pushes an artifact's files (a full-suite backup, a snapshot, a sealed
// audit-log / CEF segment, or a forensic-export bundle) to an SFTP server via
// the ssh2 library.
//
// SECURITY POSTURE
//
// HOST KEY PINNING IS REQUIRED, NOT OPTIONAL. The operator must provide
// config.host_key as an OpenSSH-format public key string (e.g.
// "ssh-ed25519 AAAAC3...comment" or "ssh-rsa AAAAB3...comment"). On every
// connection, the adapter verifies the SFTP server's presented host key
// matches the pinned key. Mismatch is a PERMANENT failure -- could be MITM.
// No TOFU mode, no warn-and-continue mode.
//
// AUTHENTICATION via password OR private key, specified by
// credentials.auth_method:
//
//   { auth_method: 'password',     password: '...' }
//   { auth_method: 'private_key',  private_key: '...PEM...',
//                                  private_key_passphrase: '...' }
//
// Credentials are decrypted by the storage-destinations registry from the
// destination row's credentials_encrypted column (GD Tier-1 AES-GCM). The
// adapter sees plaintext credentials and never persists or logs them.
//
// REMOTE LAYOUT MIRRORS SOURCE
//
// On host: <sourceDir>/            (e.g. firealive-gd-backup-<ts>/)
// On dest: <config.remote_path>/<sourceDirName>/
//
// Same files. Restoring would require pulling the directory back to a host and
// running the standard restore flow.
//
// ATOMICITY ON REMOTE
//
// Uploads all files into a hidden, adapter-owned temp dir
// (`.firealive-gd-push-<sourceDirName>.tmp/`) under remote_path, then
// sftp.rename() to the final name. POSIX rename of a directory is atomic on
// the same filesystem; the SFTP server enforces this. A crash mid-push leaves
// a hidden remote temp dir, never a partial visible artifact directory.
//
// REMOTE-SIDE VERIFICATION (NOT DONE)
//
// The adapter does NOT re-download files to verify SHA-256 round trip.
// Trusting SSH transport integrity (TCP + SSH MAC layer). Alternatives
// considered and rejected:
//
//   - Re-download every file: doubles bandwidth, expensive
//   - Run remote `sha256sum` via SSH exec: requires shell access, which
//     SFTP-only servers (the hardened security posture) do not offer
//   - Hash-after-write via SFTP: SFTP protocol does not support server-side
//     hashing as a standard operation
//
// The S3 adapter uses HTTP-level checksums where the object-storage protocol
// natively supports it. The SFTP integrity gap is a known limitation; SOC
// operators wanting cryptographic verification of off-host pushes should
// prefer S3 destinations.
//
// CONNECTION LIFECYCLE
//
// Each push opens a new SSH/SFTP connection, transfers files, closes. No
// connection pooling. Pushes are infrequent (one per artifact per
// destination); pooling complexity not justified.
//
// RETRYABLE TAXONOMY
//
// Permanent (retryable=false):
//   - Host key mismatch (security failure, never silently retry)
//   - Authentication failure
//   - Permission denied on remote
//   - Source files missing
//   - Path-traversal guard hits
//   - Malformed config / credentials
//
// Transient (retryable=true):
//   - DNS resolution failure (ENOTFOUND, EAI_AGAIN)
//   - Connection refused (ECONNREFUSED)
//   - Connection timeout (ETIMEDOUT)
//   - Reset / aborted connection mid-transfer (ECONNRESET)
//   - Disk full on remote (typically surfaces as a write error code;
//     included to be safe)
//   - Unknown errors (default retryable; scheduler eventually escalates to
//     permanent if persistent)
// =============================================================================

const fs = require('fs');
const path = require('path');
const base = require('./gd-destination-adapter-base');

const ADAPTER_NAME = 'sftp';
const TEMP_PREFIX = '.firealive-gd-push-';      // adapter-owned remote temp prefix
const TEMP_SUFFIX = '.tmp';
const DEFAULT_PORT = 22;
const DEFAULT_TIMEOUT_MS = 30000;       // 30s SSH handshake / readyTimeout
const DEFAULT_PUSH_TIMEOUT_MS = 600000; // 10min total push deadline

// Lazy-required so test environments without ssh2 installed don't fail
// at module-load. The actual push and probe paths require it.
function getSsh2() {
  return require('ssh2');
}

// --- Validation --------------------------------------------------------------

function validateConfig(config) {
  if (!config || typeof config !== 'object') {
    return { ok: false, error: 'config must be an object' };
  }
  const checks = [
    base.requireString(config, 'host', { maxLength: 255 }),
    base.requireInt(config, 'port', 1, 65535),
    base.requireString(config, 'username', { maxLength: 255, pattern: /^[A-Za-z0-9_.-]+$/ }),
    base.requireAbsolutePath(config, 'remote_path'),
    base.requireString(config, 'host_key', { maxLength: 8192 }),
  ];
  for (const r of checks) if (!r.ok) return r;

  // Validate the pinned host key parses correctly
  try {
    const ssh2 = getSsh2();
    const parsed = ssh2.utils.parseKey(config.host_key);
    if (parsed instanceof Error) {
      return {
        ok: false,
        error: `host_key did not parse as a valid SSH public key: ${parsed.message}`,
        field: 'host_key',
      };
    }
  } catch (err) {
    return {
      ok: false,
      error: `host_key parsing failed: ${err.message}`,
      field: 'host_key',
    };
  }

  return { ok: true };
}

function validateCredentials(credentials) {
  if (!credentials || typeof credentials !== 'object') {
    return { ok: false, error: 'credentials required (object with auth_method)' };
  }
  if (credentials.auth_method !== 'password' && credentials.auth_method !== 'private_key') {
    return {
      ok: false,
      error: `auth_method must be 'password' or 'private_key' (got ${JSON.stringify(credentials.auth_method)})`,
      field: 'auth_method',
    };
  }
  if (credentials.auth_method === 'password') {
    const r = base.requireString(credentials, 'password', { maxLength: 1024 });
    if (!r.ok) return r;
    if (credentials.private_key) {
      return { ok: false, error: 'auth_method=password but private_key is also set; pick one', field: 'private_key' };
    }
  } else {
    const r = base.requireString(credentials, 'private_key', { maxLength: 16384 });
    if (!r.ok) return r;
    if (!credentials.private_key.includes('PRIVATE KEY')) {
      return { ok: false, error: 'private_key does not look like a PEM-encoded private key (missing PRIVATE KEY marker)', field: 'private_key' };
    }
    if (credentials.password) {
      return { ok: false, error: 'auth_method=private_key but password is also set; pick one', field: 'password' };
    }
    if (credentials.private_key_passphrase !== undefined && typeof credentials.private_key_passphrase !== 'string') {
      return { ok: false, error: 'private_key_passphrase must be a string when present', field: 'private_key_passphrase' };
    }
  }
  return { ok: true };
}

// --- ssh2 connection helper --------------------------------------------------

/**
 * Open an SSH connection, verify host key, authenticate, return the
 * Client. Caller is responsible for sftp() and end().
 *
 * Wraps ssh2's callback API in a Promise. Throws DestinationAdapterError
 * with retryable flag set per error type.
 */
function connect(config, credentials, options = {}) {
  return new Promise((resolve, reject) => {
    const ssh2 = getSsh2();
    const client = new ssh2.Client();
    const expectedKey = ssh2.utils.parseKey(config.host_key);
    if (expectedKey instanceof Error) {
      return reject(new base.DestinationAdapterError(
        `host_key parsing failed: ${expectedKey.message}`,
        { adapter: ADAPTER_NAME, operation: 'connect', retryable: false },
      ));
    }
    const expectedSshBytes = expectedKey.getPublicSSH();

    let hostKeyVerified = false;

    client.on('error', (err) => {
      // Errors after host-key check are typically transport / auth.
      // ssh2 surfaces socket-level errors as 'error' events.
      const code = err.code || (err.level === 'authentication' ? 'EAUTH' : null);
      const retryable = !['EAUTH', 'EHOSTKEYMISMATCH'].includes(code);
      reject(new base.DestinationAdapterError(
        `SSH connection failed: ${err.message}`,
        {
          adapter: ADAPTER_NAME,
          operation: 'connect',
          retryable: retryable && classifyTransportRetryable(err.code) !== false,
          detail: { code, level: err.level, hostKeyVerified },
          cause: err,
        },
      ));
    });

    client.on('ready', () => resolve(client));

    const auth = credentials.auth_method === 'password'
      ? { password: credentials.password }
      : { privateKey: credentials.private_key, ...(credentials.private_key_passphrase ? { passphrase: credentials.private_key_passphrase } : {}) };

    client.connect({
      host: config.host,
      port: config.port,
      username: config.username,
      readyTimeout: options.timeoutMs || DEFAULT_TIMEOUT_MS,
      ...auth,
      hostVerifier: (presentedKey) => {
        // presentedKey is a Buffer of the SSH wire-format key bytes
        const ok = Buffer.isBuffer(presentedKey) && Buffer.compare(expectedSshBytes, presentedKey) === 0;
        if (ok) hostKeyVerified = true;
        return ok;
        // Returning false causes ssh2 to abort with a host-key error.
      },
    });
  });
}

/**
 * Classify a transport error code as retryable. Returns true for
 * transient (DNS, refused, timeout, reset) and false for permanent
 * (auth, host-key, malformed).
 *
 * Falsy or unrecognized codes default to retryable=true so we don't
 * give up on novel error categories.
 */
function classifyTransportRetryable(code) {
  if (!code) return true;
  const PERMANENT = new Set([
    'EAUTH',                  // ssh2-synthesized
    'EHOSTKEYMISMATCH',       // ssh2-synthesized
    'ENOENT',                 // file/path not found (config error)
    'EACCES',                 // permission denied
    'EPERM',                  // operation not permitted
  ]);
  return !PERMANENT.has(code);
}

// --- SFTP helpers (Promise-wrapped) ------------------------------------------

function openSftp(client) {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => err ? reject(err) : resolve(sftp));
  });
}

function sftpStat(sftp, p) {
  return new Promise((resolve, reject) => {
    sftp.stat(p, (err, stats) => err ? reject(err) : resolve(stats));
  });
}

function sftpMkdir(sftp, p) {
  return new Promise((resolve, reject) => {
    sftp.mkdir(p, (err) => err ? reject(err) : resolve());
  });
}

function sftpRename(sftp, from, to) {
  return new Promise((resolve, reject) => {
    sftp.rename(from, to, (err) => err ? reject(err) : resolve());
  });
}

function sftpFastPut(sftp, localPath, remotePath) {
  return new Promise((resolve, reject) => {
    sftp.fastPut(localPath, remotePath, {}, (err) => err ? reject(err) : resolve());
  });
}

function sftpUnlink(sftp, p) {
  return new Promise((resolve, reject) => {
    sftp.unlink(p, (err) => err ? reject(err) : resolve());
  });
}

function sftpReaddir(sftp, p) {
  return new Promise((resolve, reject) => {
    sftp.readdir(p, (err, list) => err ? reject(err) : resolve(list));
  });
}

function sftpRmdir(sftp, p) {
  return new Promise((resolve, reject) => {
    sftp.rmdir(p, (err) => err ? reject(err) : resolve());
  });
}

// --- probe -------------------------------------------------------------------

async function probe(config, credentials) {
  let client;
  try {
    client = await connect(config, credentials, { timeoutMs: DEFAULT_TIMEOUT_MS });
  } catch (err) {
    return {
      ok: false,
      error: err.message,
      detail: { retryable: err.retryable, ...(err.detail || {}) },
    };
  }
  try {
    const sftp = await openSftp(client);
    // Verify remote_path exists and is a directory
    let stat;
    try {
      stat = await sftpStat(sftp, config.remote_path);
    } catch (err) {
      return {
        ok: false,
        error: `remote_path '${config.remote_path}' not accessible: ${err.message}`,
        detail: { code: err.code },
      };
    }
    if (!stat.isDirectory()) {
      return { ok: false, error: `remote_path '${config.remote_path}' is not a directory` };
    }

    // Probe write by creating + removing a temp file
    const probeName = `.firealive-probe-${Date.now()}-${process.pid}`;
    const probePath = path.posix.join(config.remote_path, probeName);
    try {
      // Create a tiny local file to fastPut
      const localProbe = path.join(require('os').tmpdir(), probeName);
      fs.writeFileSync(localProbe, 'firealive-probe');
      try {
        await sftpFastPut(sftp, localProbe, probePath);
      } finally {
        try { fs.unlinkSync(localProbe); } catch { /* swallow */ }
      }
      try { await sftpUnlink(sftp, probePath); } catch { /* swallow */ }
    } catch (err) {
      return {
        ok: false,
        error: `cannot write to remote_path '${config.remote_path}': ${err.message}`,
        detail: { code: err.code },
      };
    }

    return { ok: true, detail: { remote_path: config.remote_path } };
  } finally {
    try { client.end(); } catch { /* swallow */ }
  }
}

// --- push --------------------------------------------------------------------

async function push(artifactContext, options = {}) {
  const logger = options.logger || console;
  const timeoutMs = options.timeoutMs || DEFAULT_PUSH_TIMEOUT_MS;
  const { destination, sourceDir, files, artifactId } = artifactContext;
  const config = destination.config;
  const credentials = destination.credentials;

  // Validate source exists locally (fail fast, before opening SSH)
  if (!fs.existsSync(sourceDir)) {
    throw new base.DestinationAdapterError(
      `source artifact directory not found: ${sourceDir}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: false },
    );
  }
  for (const f of files) {
    if (!fs.existsSync(f.absolutePath)) {
      throw new base.DestinationAdapterError(
        `source file not found: ${f.absolutePath}`,
        { adapter: ADAPTER_NAME, operation: 'push', retryable: false },
      );
    }
  }

  const sourceDirName = path.basename(sourceDir);

  // Defense-in-depth path-traversal guard. Temp dir uses a fixed,
  // adapter-owned prefix; the final dir mirrors the source name.
  let remoteFinalDir, remoteTempDir;
  try {
    remoteFinalDir = base.safeJoinSegment(config.remote_path, sourceDirName);
    remoteTempDir = base.safeJoinSegment(config.remote_path, TEMP_PREFIX + sourceDirName + TEMP_SUFFIX);
  } catch (err) {
    throw new base.DestinationAdapterError(
      `unsafe source directory name: ${err.message}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: false },
    );
  }

  // Open SSH connection
  let client;
  try {
    client = await connect(config, credentials, { timeoutMs });
  } catch (err) {
    if (err instanceof base.DestinationAdapterError) throw err;
    throw new base.DestinationAdapterError(
      `SSH connect failed: ${err.message}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: classifyTransportRetryable(err.code), cause: err },
    );
  }

  let bytesPushed = 0;
  try {
    const sftp = await openSftp(client);

    // Idempotency: if remoteFinalDir exists, treat as success
    let alreadyPresent = false;
    try {
      const stat = await sftpStat(sftp, remoteFinalDir);
      if (stat.isDirectory()) alreadyPresent = true;
    } catch (err) {
      // Expected: ENOENT means doesn't exist, fall through
      if (err.code !== 2 /* ssh2 SFTP NO_SUCH_FILE */ && !/no such/i.test(err.message)) {
        throw new base.DestinationAdapterError(
          `cannot stat remote ${remoteFinalDir}: ${err.message}`,
          { adapter: ADAPTER_NAME, operation: 'push', retryable: classifyTransportRetryable(err.code), cause: err },
        );
      }
    }

    if (alreadyPresent) {
      logger.info(`gd-destination-adapter-sftp: ${sourceDirName} already exists at destination; treating as idempotent success`, { destination: destination.id });
      let totalSize = 0;
      for (const f of files) totalSize += f.sizeBytes;
      return {
        destinationPath: remoteFinalDir,
        bytesPushed: totalSize,
        immutabilityVerified: null,
        destinationMetadata: { idempotent: true, alreadyPresent: true, host: config.host, remote_path: config.remote_path },
      };
    }

    // Create temp directory on remote
    try {
      await sftpMkdir(sftp, remoteTempDir);
    } catch (err) {
      throw new base.DestinationAdapterError(
        `mkdir failed for ${remoteTempDir}: ${err.message}`,
        { adapter: ADAPTER_NAME, operation: 'push', retryable: classifyTransportRetryable(err.code), cause: err },
      );
    }

    // Upload each file
    try {
      for (const f of files) {
        const remoteFilePath = path.posix.join(remoteTempDir, f.name);
        try {
          await sftpFastPut(sftp, f.absolutePath, remoteFilePath);
        } catch (err) {
          throw new base.DestinationAdapterError(
            `fastPut failed for ${f.name}: ${err.message}`,
            { adapter: ADAPTER_NAME, operation: 'push', retryable: classifyTransportRetryable(err.code), detail: { file: f.name }, cause: err },
          );
        }
        bytesPushed += f.sizeBytes;
        logger.info(`gd-destination-adapter-sftp: uploaded ${f.name} (${f.sizeBytes} bytes)`);
      }

      // Atomic rename
      try {
        await sftpRename(sftp, remoteTempDir, remoteFinalDir);
      } catch (err) {
        throw new base.DestinationAdapterError(
          `atomic rename failed: ${err.message}`,
          { adapter: ADAPTER_NAME, operation: 'push', retryable: classifyTransportRetryable(err.code), cause: err },
        );
      }
    } catch (err) {
      // Best-effort cleanup of temp dir on failure
      try {
        const list = await sftpReaddir(sftp, remoteTempDir).catch(() => []);
        for (const item of list) {
          try { await sftpUnlink(sftp, path.posix.join(remoteTempDir, item.filename)); } catch { /* swallow */ }
        }
        try { await sftpRmdir(sftp, remoteTempDir); } catch { /* swallow */ }
      } catch { /* swallow cleanup errors */ }
      throw err;
    }

    logger.info(`gd-destination-adapter-sftp: pushed ${sourceDirName} (${bytesPushed} bytes) to ${config.host}:${remoteFinalDir}`);

    return {
      destinationPath: remoteFinalDir,
      bytesPushed,
      immutabilityVerified: destination.immutability_mode === 'append-only'
        ? { mode: 'append-only', trustedBy: 'operator-declared' }
        : null,
      destinationMetadata: {
        artifactId,
        sourceDirName,
        host: config.host,
        port: config.port,
        username: config.username,
        remote_path: config.remote_path,
        remote_final_dir: remoteFinalDir,
        immutabilityMode: destination.immutability_mode,
      },
    };
  } finally {
    try { client.end(); } catch { /* swallow */ }
  }
}

// --- Adapter export + self-registration --------------------------------------

const adapter = {
  name: ADAPTER_NAME,
  description: 'Push artifacts to an SFTP server. Host key pinning is required (config.host_key).',
  supportedImmutabilityModes: ['none', 'append-only', 'unknown'],
  validateConfig,
  validateCredentials,
  probe,
  push,
};

base.registerAdapter(adapter);

module.exports = adapter;

// Internals exposed for tests
module.exports.__test__ = {
  classifyTransportRetryable,
  ADAPTER_NAME,
  DEFAULT_PORT,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_PUSH_TIMEOUT_MS,
  TEMP_PREFIX,
};

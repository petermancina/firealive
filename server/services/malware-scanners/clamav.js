// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Malware Scanner: ClamAV
//
// On-prem signature-based scanner. Open-source, free to deploy, the only
// option that works in air-gapped environments. Scans via ClamAV's INSTREAM
// protocol over a TCP socket (clamd is typically configured to listen on
// localhost:3310 but the host:port pair is configurable per integration).
//
// INSTREAM protocol (from clamd(8) man page and clamd's source):
//   1. Connect TCP to clamd
//   2. Send: "zINSTREAM\0"  (z prefix = NULL-terminated reply mode;
//                            INSTREAM = streaming scan command)
//   3. Send N chunks, each of: 4-byte big-endian length, then that many bytes
//      of content. Maximum chunk size is bounded by clamd's StreamMaxLength
//      directive, typically 25 MB. Our policy uploads cap at 500 KB so we
//      always fit in a single chunk.
//   4. Send 4-byte zero (\0\0\0\0) to terminate the stream
//   5. Read until \0 terminator; parse the response line
//      Possible responses:
//        "stream: OK\0"                       — clean
//        "stream: <virus_name> FOUND\0"       — threat detected
//        "stream: <error description> ERROR\0" — protocol or scan error
//        "INSTREAM size limit exceeded. ERROR\0" — content > StreamMaxLength
//
// This module does NOT require credentials beyond host:port (clamd does not
// implement authentication; security is provided by network ACLs binding
// clamd to localhost or to a private VLAN). The credentials JSON is therefore
// the simplest of the 18 providers:
//   { "host": "localhost", "port": 3310 }
//
// ClamAV self-test endpoint: PING command. Connect, send "zPING\0", expect
// "PONG\0" back. Used by the MC's "Test Connection" button.
//
// Phase F4c — Malware Scanner Integrations.
// ═══════════════════════════════════════════════════════════════════════════════

const net = require('net');
const crypto = require('crypto');

const PROVIDER_TYPE = 'clamav';
const PROVIDER_VERSION = '1.0.0';
const DEFAULT_HOST = 'localhost';
const DEFAULT_PORT = 3310;
const DEFAULT_TIMEOUT_MS = 30000; // ClamAV signature scans are typically <2s
                                  // but we give 30s headroom for first-call
                                  // signature DB load on a freshly-started clamd
const TEST_TIMEOUT_MS = 5000;
const MAX_CHUNK_SIZE = 25 * 1024 * 1024; // 25 MB matches clamd's default
                                          // StreamMaxLength

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Scan content against a ClamAV daemon.
 *
 * @param {object} args
 * @param {string|Buffer} args.content    raw content to scan
 * @param {string} args.fileName          for audit/logging only; clamd does
 *                                         not see the filename
 * @param {string} args.fileType          for audit/logging only
 * @param {object} args.credentials       decrypted credential object
 * @param {string} [args.credentials.host=localhost]
 * @param {number} [args.credentials.port=3310]
 * @param {number} [args.timeoutMs=30000]
 * @returns {Promise<{clean, threats, scanId, latencyMs, provider, providerInfo, error?}>}
 */
async function inspectFile(args) {
  const startedAt = Date.now();
  const scanId = 'clamav-' + crypto.randomBytes(8).toString('hex');
  const credentials = (args && args.credentials) || {};
  const host = credentials.host || DEFAULT_HOST;
  const port = Number(credentials.port) || DEFAULT_PORT;
  const timeoutMs = (args && args.timeoutMs) || DEFAULT_TIMEOUT_MS;

  if (!args || args.content === undefined || args.content === null) {
    return failClosed(scanId, host, port, startedAt, 'no content provided');
  }

  const buffer = Buffer.isBuffer(args.content)
    ? args.content
    : Buffer.from(String(args.content), 'utf-8');

  if (buffer.length === 0) {
    return failClosed(scanId, host, port, startedAt, 'content is empty');
  }
  if (buffer.length > MAX_CHUNK_SIZE) {
    // clamd's StreamMaxLength would reject this anyway; we catch it client-side
    // so we don't waste a connection.
    return failClosed(scanId, host, port, startedAt,
      `content size (${buffer.length} bytes) exceeds clamd stream limit (${MAX_CHUNK_SIZE})`);
  }

  let response;
  try {
    response = await runInstream(host, port, buffer, timeoutMs);
  } catch (err) {
    return failClosed(scanId, host, port, startedAt, err.message || String(err));
  }

  return parseInstreamResponse(response, scanId, host, port, startedAt);
}

/**
 * Test connectivity to a configured ClamAV daemon. Used by the MC's "Test
 * Connection" button. Returns {ok, latencyMs, version?, error?}.
 *
 * @param {object} credentials
 * @returns {Promise<{ok, latencyMs, version?, error?}>}
 */
async function testConnection(credentials) {
  const startedAt = Date.now();
  const host = (credentials && credentials.host) || DEFAULT_HOST;
  const port = Number(credentials && credentials.port) || DEFAULT_PORT;

  try {
    const ping = await runCommand(host, port, 'zPING\0', TEST_TIMEOUT_MS);
    if (ping !== 'PONG') {
      return {
        ok: false,
        latencyMs: Date.now() - startedAt,
        error: `unexpected PING response: ${truncate(ping, 80)}`,
      };
    }
    // Optional: also fetch VERSION for display in the MC. Best-effort; if
    // it fails, we still report the integration as healthy because PONG
    // succeeded.
    let version;
    try {
      version = await runCommand(host, port, 'zVERSION\0', TEST_TIMEOUT_MS);
    } catch (_) { /* best effort */ }
    return { ok: true, latencyMs: Date.now() - startedAt, version: version || null };
  } catch (err) {
    return {
      ok: false,
      latencyMs: Date.now() - startedAt,
      error: err.message || String(err),
    };
  }
}

// ── Internals ───────────────────────────────────────────────────────────────

/**
 * Send INSTREAM, write the content as one chunk, send terminator, read reply.
 */
function runInstream(host, port, contentBuffer, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let settled = false;
    const replyChunks = [];

    const cleanup = () => {
      try { socket.destroy(); } catch (_) {}
    };

    const fail = (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err instanceof Error ? err : new Error(String(err)));
    };

    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => fail(new Error(`clamd response timeout after ${timeoutMs}ms`)));
    socket.on('error', (e) => fail(new Error(`clamd connection error: ${e.message}`)));
    socket.on('close', () => {
      if (settled) return;
      settled = true;
      const reply = Buffer.concat(replyChunks).toString('utf-8').replace(/\0$/, '');
      if (!reply) {
        return reject(new Error('clamd closed connection with no reply'));
      }
      resolve(reply);
    });
    socket.on('data', (chunk) => replyChunks.push(chunk));

    socket.connect(port, host, () => {
      try {
        // Command preamble
        socket.write('zINSTREAM\0');
        // Single chunk: 4-byte big-endian length, then content
        const lengthHeader = Buffer.alloc(4);
        lengthHeader.writeUInt32BE(contentBuffer.length, 0);
        socket.write(lengthHeader);
        socket.write(contentBuffer);
        // Terminator: 4-byte zero
        socket.write(Buffer.alloc(4));
      } catch (writeErr) {
        fail(new Error(`clamd write error: ${writeErr.message}`));
      }
    });
  });
}

/**
 * Send a single z-prefixed command and read until NUL terminator. Used for
 * PING and VERSION.
 */
function runCommand(host, port, command, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let settled = false;
    const replyChunks = [];

    const cleanup = () => {
      try { socket.destroy(); } catch (_) {}
    };

    const fail = (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err instanceof Error ? err : new Error(String(err)));
    };

    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => fail(new Error(`clamd ${command.replace(/[\0z]/g,'')} timeout after ${timeoutMs}ms`)));
    socket.on('error', (e) => fail(new Error(`clamd connection error: ${e.message}`)));
    socket.on('close', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(replyChunks).toString('utf-8').replace(/\0$/, '').trim());
    });
    socket.on('data', (chunk) => replyChunks.push(chunk));

    socket.connect(port, host, () => {
      try { socket.write(command); }
      catch (writeErr) { fail(new Error(`clamd write error: ${writeErr.message}`)); }
    });
  });
}

/**
 * Parse a clamd INSTREAM reply into the dispatcher's standard return shape.
 * Reply formats:
 *   "stream: OK"                       → clean
 *   "stream: <SignatureName> FOUND"    → threats: ["<SignatureName>"]
 *   "stream: <error> ERROR"            → fail-closed with error
 *   "INSTREAM size limit exceeded. ERROR" → fail-closed
 */
function parseInstreamResponse(reply, scanId, host, port, startedAt) {
  const latencyMs = Date.now() - startedAt;
  const trimmed = (reply || '').trim();
  const providerInfo = `${host}:${port}`;

  if (!trimmed) {
    return {
      clean: false,
      threats: [],
      scanId,
      latencyMs,
      provider: PROVIDER_TYPE,
      providerInfo,
      error: 'empty reply from clamd',
    };
  }

  // Clean: "stream: OK"
  if (/^stream:\s*OK\s*$/i.test(trimmed)) {
    return {
      clean: true,
      threats: [],
      scanId,
      latencyMs,
      provider: PROVIDER_TYPE,
      providerInfo,
    };
  }

  // Threat detected: "stream: <SignatureName> FOUND"
  const foundMatch = trimmed.match(/^stream:\s*(.+?)\s+FOUND\s*$/i);
  if (foundMatch) {
    return {
      clean: false,
      threats: [foundMatch[1].trim()],
      scanId,
      latencyMs,
      provider: PROVIDER_TYPE,
      providerInfo,
    };
  }

  // Any error reply → fail-closed
  const errorMatch = trimmed.match(/^(?:stream:\s*)?(.+?)\s*ERROR\s*$/i);
  if (errorMatch) {
    return {
      clean: false,
      threats: [],
      scanId,
      latencyMs,
      provider: PROVIDER_TYPE,
      providerInfo,
      error: `clamd error: ${errorMatch[1].trim()}`,
    };
  }

  // Unrecognized response shape — fail-closed
  return {
    clean: false,
    threats: [],
    scanId,
    latencyMs,
    provider: PROVIDER_TYPE,
    providerInfo,
    error: `unrecognized clamd response: ${truncate(trimmed, 200)}`,
  };
}

function failClosed(scanId, host, port, startedAt, errorMessage) {
  return {
    clean: false,
    threats: [],
    scanId,
    latencyMs: Date.now() - startedAt,
    provider: PROVIDER_TYPE,
    providerInfo: `${host}:${port}`,
    error: errorMessage,
  };
}

function truncate(str, max) {
  if (typeof str !== 'string') return '';
  return str.length <= max ? str : str.slice(0, max - 3) + '...';
}

module.exports = {
  PROVIDER_TYPE,
  PROVIDER_VERSION,
  inspectFile,
  testConnection,
  // Exported for unit testing
  _internal: {
    parseInstreamResponse,
  },
};

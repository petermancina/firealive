// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GD Push Signer
//
// Per-request signature helper for outbound MC-to-GD pushes. Wraps the
// gd-push-signing-keys keypair-lifecycle service in the per-request
// signing protocol agreed for R3g PR3:
//
//   X-FA-Key-Fingerprint    SHA-256 hex of Ed25519 SPKI DER (64 chars,
//                           lowercase). Identifies which row in the GD's
//                           signing_keys trust registry the verifier
//                           should use.
//
//   X-FA-Timestamp          ISO 8601 UTC at sign time. The GD rejects
//                           requests where its receive-time clock is
//                           more than 5 minutes off this value.
//
//   X-FA-Signature          base64 of the Ed25519 signature over the
//                           payload `timestamp + "\n" + body`. The body
//                           component is the EXACT bytes of the request
//                           body, so the verifier hashes the raw body
//                           bytes (not a re-canonicalized parse).
//
// CONTRACT: the caller must POST the bodyBytes returned by this signer
// verbatim. If the caller serializes a JS object themselves and the
// serialization differs from what the signer used (key order, escape
// differences, whitespace), the GD signature check will fail. The
// safest pattern is:
//
//   const sig = signPushPayload(db, { foo: 1, bar: 2 });
//   await fetch(url, {
//     method: 'POST',
//     headers: {
//       'X-FA-Key-Fingerprint': sig.fingerprint,
//       'X-FA-Timestamp':       sig.timestamp,
//       'X-FA-Signature':       sig.signature,
//       'Content-Type':         'application/json',
//     },
//     body: sig.bodyBytes,            // <-- the signed bytes, verbatim
//   });
//
// PRIVATE-KEY HYGIENE: this module never caches the decrypted private
// key at module scope. Every signPushPayload() call decrypts fresh from
// the DB via getActivePushKey(). Same discipline as chain-signing-
// keys.signChainEntry — costs ~1ms per push, eliminates the
// long-lived-secret-in-process attack surface.
//
// VERIFICATION lives elsewhere. The MC only signs outbound pushes; the
// GD verifies inbound pushes via packages/global-dashboard-server/
// services/mc-signature-verifier.js (added in Commit 10). This module
// is sign-only.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { getActivePushKey } = require('./gd-push-signing-keys');

// ── Public API ────────────────────────────────────────────────────────────

/**
 * signPushPayload(db, body, options)
 *
 * Sign an outbound MC-to-GD push body with the currently-active
 * gd_push_signing_keys keypair. Returns the three header values plus
 * the exact body bytes that were signed.
 *
 * Inputs:
 *   db       better-sqlite3 handle
 *   body     one of:
 *              - string  — signed as-is (caller is responsible for
 *                          matching what they POST)
 *              - Buffer  — signed as-is, converted to string via
 *                          buf.toString('utf8') for the signing payload
 *              - object  — JSON.stringified internally; the signer
 *                          returns bodyBytes so the caller knows
 *                          exactly which serialization was signed
 *   options  optional:
 *              timestamp: ISO 8601 string override (defaults to now);
 *                         intended for tests, NOT for production use
 *
 * Returns: {
 *   fingerprint:  string  — X-FA-Key-Fingerprint header value
 *   timestamp:    string  — X-FA-Timestamp header value (ISO 8601 UTC)
 *   signature:    string  — X-FA-Signature header value (base64)
 *   bodyBytes:    string  — the exact body bytes to POST verbatim
 * }
 *
 * Throws if no active GD-push signing keypair exists. Callers should
 * call ensureActivePushKeypair(db) before the first push (typically
 * via the gd-config handshake flow in Commit 13).
 */
function signPushPayload(db, body, options = {}) {
  // 1) Normalize body into the exact string of bytes that will be sent.
  let bodyBytes;
  if (typeof body === 'string') {
    bodyBytes = body;
  } else if (Buffer.isBuffer(body)) {
    bodyBytes = body.toString('utf8');
  } else if (body !== null && typeof body === 'object') {
    bodyBytes = JSON.stringify(body);
  } else {
    throw new Error('signPushPayload: body must be a string, Buffer, or object');
  }

  // 2) Stamp current UTC time unless an override was supplied (tests).
  const timestamp = options.timestamp || nowIsoUtc();
  if (typeof timestamp !== 'string') {
    throw new Error('signPushPayload: options.timestamp must be a string when provided');
  }

  // 3) Build the signing payload exactly per the wire format:
  //      `${timestamp}\n${body}`
  //    Newline separator is non-ambiguous because the timestamp is
  //    fixed-format ISO 8601 (no embedded newlines).
  const signingPayload = Buffer.from(timestamp + '\n' + bodyBytes, 'utf8');

  // 4) Fetch active key (decrypts private key just-in-time), sign,
  //    discard private-key KeyObject after signing.
  const { privateKey, publicKeyFingerprint } = getActivePushKey(db);
  const signature = crypto.sign(null, signingPayload, privateKey);

  return {
    fingerprint: publicKeyFingerprint,
    timestamp,
    signature: signature.toString('base64'),
    bodyBytes,
  };
}

/**
 * buildPushHeaders(sigInfo, extraHeaders)
 *
 * Convenience wrapper that builds the final HTTP headers object for a
 * fetch / axios / undici call. Saves callers from repeating the
 * X-FA-* mapping. Optional extraHeaders are spread in last so caller
 * Content-Type, Accept, etc. override or sit alongside.
 *
 * Returns: a plain object suitable for fetch's `headers` option.
 */
function buildPushHeaders(sigInfo, extraHeaders = {}) {
  if (!sigInfo || typeof sigInfo !== 'object') {
    throw new Error('buildPushHeaders: sigInfo must be the return value of signPushPayload');
  }
  return {
    'X-FA-Key-Fingerprint': sigInfo.fingerprint,
    'X-FA-Timestamp':       sigInfo.timestamp,
    'X-FA-Signature':       sigInfo.signature,
    ...extraHeaders,
  };
}

// ── Internal helpers ──────────────────────────────────────────────────────

/**
 * nowIsoUtc()
 *
 * Current time as ISO 8601 with millisecond precision and trailing 'Z'.
 * Example: '2026-05-12T20:00:00.123Z'.
 *
 * Date.prototype.toISOString already returns this exact format; wrapped
 * here as a single seam so tests can monkey-patch if needed.
 */
function nowIsoUtc() {
  return new Date().toISOString();
}

module.exports = {
  signPushPayload,
  buildPushHeaders,
};

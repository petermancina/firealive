// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — MC Signature Verifier (R3g PR3)
//
// Verifies the X-FA-Signature header on inbound MC-to-GD pushes against
// the per-MC public keys in the signing_keys trust registry. This is
// the inverse of the MC's server/services/gd-push-signer.js
// signPushPayload() — same wire format, opposite direction.
//
// WIRE FORMAT (MUST stay byte-compatible with gd-push-signer.js)
//
//   X-FA-Key-Fingerprint    SHA-256 hex of Ed25519 SPKI DER (64 chars,
//                           lowercase). Identifies the signing_keys row
//                           (scoped to the calling MC) whose public key
//                           verifies this signature.
//
//   X-FA-Timestamp          ISO 8601 UTC at sign time. Rejected if more
//                           than 5 minutes off the GD's receive-time
//                           clock (in either direction — clock skew on
//                           either side counts).
//
//   X-FA-Signature          base64 of the Ed25519 signature over the
//                           payload `timestamp + "\n" + rawBody`. Raw
//                           body bytes are used, NOT a re-canonicalized
//                           parse, so the caller must capture the raw
//                           request buffer before JSON parsing (via
//                           express.json({verify: ...}) in the ingest
//                           routes).
//
// STRICT MODE
//
// PR3 lands this verifier on the inbound ingest path with NO grace
// period, NO backwards-compatibility flag, NO opt-out config. After
// PR3 ships, unsigned pushes are rejected at the GD with a 401 and an
// INGEST_SIGNATURE_REJECTED audit-log entry. The MC handshake (Commit
// 13) ensures every newly-configured GD-push connection registers its
// signing key before the first push.
//
// REPLAY WINDOW
//
// The 5-minute timestamp window mitigates replay but does not eliminate
// it. Compliance summaries are idempotent at the row level (the same
// summary re-ingested just re-inserts the same data), so this is
// acceptable for v1.0.33. A future hardening could add a server-side
// nonce table to enforce one-shot signatures; tracked as a deferred
// item in the build plan.
//
// ERROR CODES (in returned { code } field) — callers SHOULD audit-log
// these for forensic triage:
//
//   MISSING_HEADER         one of the three X-FA-* headers absent
//   MALFORMED_TIMESTAMP    timestamp doesn't parse as ISO 8601
//   TIMESTAMP_SKEW         outside the 5-minute window in either direction
//   MALFORMED_FINGERPRINT  not 64 chars of lowercase hex
//   MALFORMED_SIGNATURE    not valid base64 OR doesn't decode to 64 bytes
//   UNKNOWN_KEY            fingerprint not in active signing_keys for this MC
//   SIGNATURE_MISMATCH     Ed25519 verify failed
//   INTERNAL_ERROR         unexpected DB or crypto error
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

const CLOCK_SKEW_TOLERANCE_MS = 5 * 60 * 1000;   // 5 minutes
const FINGERPRINT_RE = /^[0-9a-f]{64}$/;
const BASE64_RE = /^[A-Za-z0-9+/]+=*$/;
const SIGNATURE_BYTES = 64;                       // Ed25519 fixed-size

const CODES = Object.freeze({
  MISSING_HEADER:        'MISSING_HEADER',
  MALFORMED_TIMESTAMP:   'MALFORMED_TIMESTAMP',
  TIMESTAMP_SKEW:        'TIMESTAMP_SKEW',
  MALFORMED_FINGERPRINT: 'MALFORMED_FINGERPRINT',
  MALFORMED_SIGNATURE:   'MALFORMED_SIGNATURE',
  UNKNOWN_KEY:           'UNKNOWN_KEY',
  SIGNATURE_MISMATCH:    'SIGNATURE_MISMATCH',
  INTERNAL_ERROR:        'INTERNAL_ERROR',
});

/**
 * verifyPushSignature(db, { mcId, headers, rawBody, nowMs })
 *
 * Verify the X-FA-Signature on an inbound MC-to-GD push.
 *
 * Inputs:
 *   db        better-sqlite3 handle
 *   mcId      string  resolved by caller from req.body.apiKey
 *                     against management_consoles
 *   headers   object  request headers (Express normalizes header
 *                     names to lowercase, so we accept both cases)
 *   rawBody   string  | Buffer the EXACT bytes of the request body
 *                     as received — typically req.rawBody captured by
 *                     express.json({ verify }) middleware
 *   nowMs     number  optional Date.now() override for tests
 *
 * Returns: {
 *   ok: boolean,
 *   error?: string,         (human-readable, safe to surface to operator)
 *   code?: string,          (CODES.* — stable, suitable for audit log)
 *   fingerprint?: string,   (always set when headers present, even on
 *                           verification failure, for forensic logging)
 * }
 *
 * Never throws. Internal errors are caught and returned as
 * { ok: false, code: 'INTERNAL_ERROR' } so the caller's audit-log path
 * stays uniform.
 */
function verifyPushSignature(db, params) {
  const { mcId, headers, rawBody } = params || {};
  const nowMs = (params && params.nowMs) ? params.nowMs : Date.now();

  // 1) Extract headers (case-insensitive — Express lowercases on receive).
  const fingerprint = pickHeader(headers, 'x-fa-key-fingerprint');
  const timestamp   = pickHeader(headers, 'x-fa-timestamp');
  const signatureB64 = pickHeader(headers, 'x-fa-signature');

  if (!fingerprint || !timestamp || !signatureB64) {
    return {
      ok: false,
      error: 'missing one or more X-FA-* signature headers',
      code: CODES.MISSING_HEADER,
      fingerprint: fingerprint || undefined,
    };
  }

  // 2) Fingerprint format check (cheap, runs before any DB lookup).
  if (!FINGERPRINT_RE.test(fingerprint)) {
    return {
      ok: false,
      error: 'X-FA-Key-Fingerprint not 64 lowercase hex chars',
      code: CODES.MALFORMED_FINGERPRINT,
      fingerprint,
    };
  }

  // 3) Timestamp parse + skew check.
  const tsMs = Date.parse(timestamp);
  if (Number.isNaN(tsMs)) {
    return {
      ok: false,
      error: 'X-FA-Timestamp does not parse as ISO 8601',
      code: CODES.MALFORMED_TIMESTAMP,
      fingerprint,
    };
  }
  const skew = Math.abs(nowMs - tsMs);
  if (skew > CLOCK_SKEW_TOLERANCE_MS) {
    return {
      ok: false,
      error: `X-FA-Timestamp skew ${Math.round(skew / 1000)}s exceeds tolerance of ${CLOCK_SKEW_TOLERANCE_MS / 1000}s`,
      code: CODES.TIMESTAMP_SKEW,
      fingerprint,
    };
  }

  // 4) Signature format check + decode.
  if (!BASE64_RE.test(signatureB64)) {
    return {
      ok: false,
      error: 'X-FA-Signature not valid base64',
      code: CODES.MALFORMED_SIGNATURE,
      fingerprint,
    };
  }
  let signatureBytes;
  try {
    signatureBytes = Buffer.from(signatureB64, 'base64');
  } catch (e) {
    return {
      ok: false,
      error: 'X-FA-Signature base64 decode failed',
      code: CODES.MALFORMED_SIGNATURE,
      fingerprint,
    };
  }
  if (signatureBytes.length !== SIGNATURE_BYTES) {
    return {
      ok: false,
      error: `X-FA-Signature decodes to ${signatureBytes.length} bytes, expected ${SIGNATURE_BYTES}`,
      code: CODES.MALFORMED_SIGNATURE,
      fingerprint,
    };
  }

  // 5) Lookup active trust row for (mcId, fingerprint). Uses the
  //    idx_signing_keys_mc_fingerprint composite index for O(log n)
  //    lookup. The is_active = 1 filter rejects rotated-out keys.
  let row;
  try {
    row = db.prepare(`
      SELECT id, public_key
      FROM signing_keys
      WHERE mc_id = ?
        AND public_key_fingerprint = ?
        AND is_active = 1
      LIMIT 1
    `).get(mcId, fingerprint);
  } catch (dbErr) {
    return {
      ok: false,
      error: 'database lookup failed',
      code: CODES.INTERNAL_ERROR,
      fingerprint,
    };
  }
  if (!row) {
    return {
      ok: false,
      error: 'fingerprint not in active signing_keys for this MC',
      code: CODES.UNKNOWN_KEY,
      fingerprint,
    };
  }

  // 6) Reconstruct the signing payload byte-for-byte and verify.
  //    The MC's gd-push-signer.js builds: Buffer.from(timestamp + "\n" + bodyBytes, 'utf8').
  //    We mirror exactly.
  let payload;
  try {
    const bodyStr = Buffer.isBuffer(rawBody)
      ? rawBody.toString('utf8')
      : (typeof rawBody === 'string' ? rawBody : '');
    payload = Buffer.from(timestamp + '\n' + bodyStr, 'utf8');
  } catch (e) {
    return {
      ok: false,
      error: 'payload reconstruction failed',
      code: CODES.INTERNAL_ERROR,
      fingerprint,
    };
  }

  let publicKey;
  try {
    publicKey = crypto.createPublicKey(row.public_key);
  } catch (e) {
    // Stored public_key didn't parse — this is a data-integrity bug,
    // not a verification failure caused by the caller. Surface as
    // INTERNAL_ERROR so an audit reviewer triages the DB row.
    return {
      ok: false,
      error: 'stored public key failed to parse',
      code: CODES.INTERNAL_ERROR,
      fingerprint,
    };
  }

  let verified;
  try {
    verified = crypto.verify(null, payload, publicKey, signatureBytes);
  } catch (e) {
    // crypto.verify can throw on malformed signature bytes for some
    // key types; Ed25519 typically returns false instead of throwing,
    // but handle defensively.
    return {
      ok: false,
      error: 'crypto.verify threw on signature check',
      code: CODES.INTERNAL_ERROR,
      fingerprint,
    };
  }
  if (!verified) {
    return {
      ok: false,
      error: 'signature does not verify against active public key',
      code: CODES.SIGNATURE_MISMATCH,
      fingerprint,
    };
  }

  return {
    ok: true,
    fingerprint,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────

function pickHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return null;
  // True case-insensitive lookup. Express normalizes incoming header
  // names to lowercase, so in production this iteration finds the
  // match on the first key. Mixed-case headers (typically only seen
  // from test fixtures or non-Express callers) still resolve.
  const target = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === target) {
      const v = headers[k];
      if (v == null) return null;
      if (Array.isArray(v)) return v[0] != null ? String(v[0]).trim() : null;
      const s = String(v).trim();
      return s || null;
    }
  }
  return null;
}

module.exports = {
  verifyPushSignature,
  CODES,
  CLOCK_SKEW_TOLERANCE_MS,
};

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
// STRICT MODE + APPROVAL REQUIREMENT + GRACE WINDOW
//
// PR3 lands this verifier on the inbound ingest path with NO grace
// period for unsigned pushes — unsigned pushes are rejected at the GD
// with a 401 and an INGEST_SIGNATURE_REJECTED audit-log entry. The MC
// handshake (Commit 27) ensures every newly-configured GD-push
// connection submits its signing key before the first push.
//
// As of R3g PR3 Phase 5 (Commit 22), the trust lookup ALSO requires
// approval_status='approved' on the signing_keys row. A row that was
// submitted but not yet approved by a CISO (approval_status=
// 'pending_approval') does NOT verify. Foundational Rule 22: trust
// establishment requires authentication an api_key thief wouldn't
// have. The CISO clicking approve in the C19 admin endpoint IS that
// authentication.
//
// ROTATION GRACE WINDOW
//
// When the CISO approves a replacement key (Commit 19's approve
// endpoint), the prior active key is atomically demoted: is_active=0,
// rotated_out_at=now, approval_status STAYS 'approved'. That last bit
// matters here. Without a grace window, in-flight pushes signed by
// the prior key in the seconds/minutes between CISO approval and the
// MC's next push tick (when it polls for status and commits the
// staged keypair locally) would all fail verification — the MC
// doesn't know the swap happened until it polls.
//
// The grace window query accepts EITHER:
//
//   - is_active = 1                       (the currently-active key), OR
//   - rotated_out_at IS NOT NULL          (recently rotated out)
//     AND rotated_out_at > (now - N min)  (within configured window)
//
// where N is read from config.signing_key_grace_period_minutes
// (seeded in Commit 16, default 60, range 0-1440).
//
// Setting N=0 collapses the window — only is_active=1 rows verify.
// Use this for emergency rotation when a key compromise is suspected:
// set N=0 in config BEFORE approving the replacement, and the moment
// the approve transaction commits, the old key dies for verification
// purposes. The trade-off is dropping any in-flight pushes signed by
// the old key, which for an emergency rotation is the right trade.
//
// Both pre-Phase-5 rows that the C14 migration backfilled to
// approval_status='approved' AND C18-style rows newly approved by the
// CISO match the new query identically. The migration story is
// continuous.
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
//   UNKNOWN_KEY            fingerprint not in approved+active-or-graced
//                          signing_keys for this MC (one bucket for
//                          unknown / not yet approved / rotated outside
//                          grace / rejected — collapsed so the verify
//                          path doesn't leak which state)
//   SIGNATURE_MISMATCH     Ed25519 verify failed
//   INTERNAL_ERROR         unexpected DB or crypto error
//
// SUCCESS-PATH OBSERVABILITY
//
// On successful verify, the result includes viaGraceWindow: boolean.
// The caller (metrics/compliance ingest handlers) can include this in
// audit details — true means the push verified against a rotated-out
// key still inside the grace window, useful for forensic correlation
// of "is the MC still using the old key after we rotated".
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

const DEFAULT_GRACE_PERIOD_MINUTES = 60;
const MAX_GRACE_PERIOD_MINUTES = 1440;  // 24h ceiling matches config range

/**
 * readGracePeriodMinutes(db)
 *
 * Read the operator-configured grace period from the config table.
 * Returns an integer in [0, MAX_GRACE_PERIOD_MINUTES]. Falls back to
 * DEFAULT_GRACE_PERIOD_MINUTES (60) if:
 *   - The row is missing entirely (e.g., a deploy that hasn't yet
 *     run the C16 seed)
 *   - The stored value isn't a valid non-negative integer string
 *
 * Negative values, NaN, and out-of-range values are clamped — never
 * trusted to control the SQL window. An operator who sets the value
 * to '99999' through some path that bypassed the admin API range
 * check still gets capped at 24h. An operator who sets the value to
 * 'banana' or '-5' gets the default of 60.
 *
 * Per-request read (not cached) so runtime config changes take effect
 * on the next inbound push. SQLite reads are cheap; one extra prepare
 * is negligible compared to the Ed25519 verify cost.
 */
function readGracePeriodMinutes(db) {
  try {
    const row = db.prepare("SELECT value FROM config WHERE key = 'signing_key_grace_period_minutes'").get();
    if (!row || typeof row.value !== 'string') return DEFAULT_GRACE_PERIOD_MINUTES;
    const n = parseInt(row.value, 10);
    if (!Number.isInteger(n) || n < 0) return DEFAULT_GRACE_PERIOD_MINUTES;
    if (n > MAX_GRACE_PERIOD_MINUTES) return MAX_GRACE_PERIOD_MINUTES;
    return n;
  } catch (e) {
    return DEFAULT_GRACE_PERIOD_MINUTES;
  }
}

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

  // 5) Lookup approved trust row for (mcId, fingerprint). Two paths
  //    legitimately match (R3g PR3 Phase 5, C22):
  //
  //      Path A — currently-active key:
  //        approval_status = 'approved' AND is_active = 1
  //
  //      Path B — recently-rotated approved key still inside grace:
  //        approval_status = 'approved' AND is_active = 0
  //        AND rotated_out_at IS NOT NULL
  //        AND rotated_out_at > (now - grace_period_minutes)
  //
  //    A row that's pending_approval, rejected, or rotated outside the
  //    grace window does NOT match. The UNKNOWN_KEY bucket collapses
  //    all four miss reasons (truly unknown / pending / rejected /
  //    rotated-outside-grace) so the verify path doesn't leak which.
  //
  //    Uses the idx_signing_keys_mc_fingerprint composite index for
  //    O(log n) lookup on the (mc_id, public_key_fingerprint) prefix;
  //    the approval_status + grace clauses filter the matching row(s)
  //    in a small scan.
  const graceMinutes = readGracePeriodMinutes(db);
  // SQLite datetime modifier strings: '-N minutes' offsets backward.
  // For N=0 the modifier is '-0 minutes', which evaluates to "now",
  // and the rotated_out_at > now comparison can never be true (the
  // rotated_out_at is by definition <= the now at which the rotation
  // transaction committed). So N=0 cleanly disables Path B.
  const graceModifier = `-${graceMinutes} minutes`;

  let row;
  try {
    row = db.prepare(`
      SELECT id, public_key, is_active, rotated_out_at
      FROM signing_keys
      WHERE mc_id = ?
        AND public_key_fingerprint = ?
        AND approval_status = 'approved'
        AND (is_active = 1
             OR (rotated_out_at IS NOT NULL
                 AND rotated_out_at > datetime('now', ?)))
      LIMIT 1
    `).get(mcId, fingerprint, graceModifier);
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
      error: 'fingerprint not approved or no longer accepted for this MC',
      code: CODES.UNKNOWN_KEY,
      fingerprint,
    };
  }
  const viaGraceWindow = row.is_active !== 1;

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
    viaGraceWindow,
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

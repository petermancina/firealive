// ══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Regional Per-Request Proof-of-Possession Verifier (Phase B5f)
//
// A regional session token is a bearer JWT, so binding the device key only at
// login would still leave a stolen token replayable from any machine. Following
// the shape of DPoP (RFC 9449), every authenticated /api/ request must also
// carry a fresh, single-use proof that the caller still holds the bound hardware
// device key (an Analyst Client or Management Console key, Blocks L and N).
//
// The proof is a base64url(JSON) header carrying { iat, jti, sig }; the device
// key signs the request method, the request path, that iat and jti, and the
// bound key's RFC 7638 thumbprint (so a captured proof cannot be moved to
// another request, key, or token). This service is the policy-neutral verifier;
// the auth middleware looks up the bound key and calls verifyPopProof on every
// request. It mirrors the Global Dashboard's gd-pop, with a distinct regional
// signing prefix so a proof minted for one server can never replay against the
// other.
// ══════════════════════════════════════════════════════════════════════════════

const deviceKey = require('./device-key');

// The header the client presents on every authenticated /api/ request.
const POP_HEADER = 'x-fa-device-pop';
// Freshness window. A proof older than POP_MAX_AGE_SEC is rejected; a small
// future tolerance absorbs a client clock running slightly ahead of the server.
const POP_MAX_AGE_SEC = 60;
const POP_FUTURE_SKEW_SEC = 10;
// Domain separation: distinct from the Global Dashboard prefix, so a per-request
// proof minted for the regional server can never be replayed against the GD (or
// vice versa), and a per-request proof can never collide with any other signed
// device-key ceremony.
const POP_SIGNING_PREFIX = 'firealive-device-pop-v1:';
// Field separator for the signed message (newline; never appears in an HTTP
// method, in the request path, or in the other fields).
const SEP = String.fromCharCode(10);

// Per-process replay guard: a successfully-verified jti is remembered until its
// freshness window closes, so the same proof cannot be replayed while still
// fresh. Sufficient for the regional server's single-backend deployment.
const seenPopJti = new Map(); // jti -> expiry epoch ms

function prunePopJti(nowMs) {
  for (const [jti, exp] of seenPopJti) {
    if (exp <= nowMs) seenPopJti.delete(jti);
  }
}

// The exact bytes the device key signs for a per-request proof. Binds the HTTP
// method, the request path, the proof's freshness (iat) and uniqueness (jti),
// and the bound key's thumbprint. The client reconstructs this from the same
// prefix and field order.
function popMessage(method, path, iat, jti, jkt) {
  const fields = [String(method).toUpperCase(), String(path), String(iat), String(jti), String(jkt)];
  return Buffer.from(POP_SIGNING_PREFIX + fields.join(SEP), 'utf8');
}

// Verify a per-request proof-of-possession.
//   method, path     the ACTUAL request line (never taken from the proof)
//   proof            the raw POP_HEADER value: base64url(JSON({ iat, jti, sig }))
//   publicKeyPem     the operator's active device key (looked up by the caller)
//   jkt              the bound key's thumbprint from the token's cnf.jkt claim
// Checks structure, a tight freshness window, single-use replay, and the
// signature against the bound key. Returns { ok: true } or { ok: false, reason }.
function verifyPopProof(args) {
  const method = args.method;
  const path = args.path;
  const proof = args.proof;
  const publicKeyPem = args.publicKeyPem;
  const jkt = args.jkt;
  if (!proof || typeof proof !== 'string') return { ok: false, reason: 'missing proof' };
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(proof, 'base64url').toString('utf8'));
  } catch (_) {
    return { ok: false, reason: 'malformed proof' };
  }
  if (!parsed || typeof parsed.iat !== 'number' || typeof parsed.jti !== 'string' || typeof parsed.sig !== 'string') {
    return { ok: false, reason: 'malformed proof' };
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (parsed.iat > nowSec + POP_FUTURE_SKEW_SEC) return { ok: false, reason: 'proof timestamp in the future' };
  if (parsed.iat < nowSec - POP_MAX_AGE_SEC) return { ok: false, reason: 'proof expired' };
  const nowMs = Date.now();
  prunePopJti(nowMs);
  if (seenPopJti.has(parsed.jti)) return { ok: false, reason: 'proof replayed' };
  let sig;
  try {
    sig = Buffer.from(parsed.sig, 'base64');
  } catch (_) {
    return { ok: false, reason: 'malformed signature' };
  }
  const message = popMessage(method, path, parsed.iat, parsed.jti, jkt);
  if (!deviceKey.verifyDeviceSignature(publicKeyPem, message, sig)) {
    return { ok: false, reason: 'signature verification failed' };
  }
  // Only a verified proof consumes its jti, so an attacker without the key cannot
  // pre-burn a jti the legitimate client is about to use.
  seenPopJti.set(parsed.jti, nowMs + (POP_MAX_AGE_SEC + POP_FUTURE_SKEW_SEC) * 1000);
  return { ok: true };
}

module.exports = {
  POP_HEADER,
  POP_MAX_AGE_SEC,
  POP_FUTURE_SKEW_SEC,
  POP_SIGNING_PREFIX,
  popMessage,
  verifyPopProof,
};

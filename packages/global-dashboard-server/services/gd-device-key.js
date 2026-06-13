// ══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD -- Device-Key Proof-of-Possession Service (Phase B5e)
//
// The hardware device key each GD operator's app mints (D20) proves possession
// of itself at login and, ultimately, on every request (D28). This service is
// the policy-neutral crypto core the auth stack builds on; it holds no routes and
// no database access:
//
//   - verifyDeviceKeySignature(...)  key-type-aware verify, Ed25519 / P-256,
//                                    mirroring the regional websocket-server check
//   - loginChallengeMessage(...)     the exact, domain-separated bytes the device
//                                    key signs at login (a versioned prefix so a
//                                    login proof can never be reused elsewhere)
//   - issueDeviceKeyChallenge(...)   a single-use, tightly-expiring login challenge
//   - consumeDeviceKeyChallenge(...) verify + one-time-consume that challenge
//   - jwkThumbprint(...)             RFC 7638 thumbprint for the RFC 7800 cnf.jkt
//                                    binding, recomputable from the registered key
// ══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Uses the GD's own GD_JWT_SECRET so one secret governs all GD-signed tokens
// (matches gd-webauthn).
const JWT_SECRET = process.env.GD_JWT_SECRET || 'CHANGE_ME_INSECURE_DEFAULT';

// A login device-key challenge is short-lived: the ceremony (request the
// challenge, sign it on-chip, submit the proof) completes in seconds, so a tight
// window leaves almost no room to capture and replay.
const CHALLENGE_TTL_SEC = 120;
const DEVICE_KEY_LOGIN_PURPOSE = 'gd-device-key-login';

// The device key signs these exact bytes at login. The versioned prefix is
// domain separation: a signature produced for login can never be lifted and
// replayed as a per-request proof-of-possession (which signs a different
// structure) or any other future device-key ceremony.
const LOGIN_SIGNING_PREFIX = 'firealive-gd-device-key-login-v1:';

// Single-use guard. A consumed challenge's jti is remembered until the moment it
// would have expired on its own, so a captured challenge token plus its signature
// cannot be replayed within the TTL. Per-process, which suffices for the GD's
// single-backend deployment.
const usedChallengeJti = new Map(); // jti -> expiry epoch ms

function pruneUsedJti(nowMs) {
  for (const [jti, exp] of usedChallengeJti) {
    if (exp <= nowMs) usedChallengeJti.delete(jti);
  }
}

// Mirrors the regional server's verifyDeviceSignature exactly: Ed25519 signs over
// the raw message (null digest); EC (P-256) signs sha256 with raw r||s (IEEE
// P1363) encoding. Accepts a PEM/DER string or buffer or an existing KeyObject.
// Any unparseable key, unsupported key type, or malformed signature verifies
// false rather than throwing.
function verifyDeviceKeySignature(publicKey, message, signature) {
  try {
    const keyObject = (typeof publicKey === 'string' || Buffer.isBuffer(publicKey))
      ? crypto.createPublicKey(publicKey)
      : publicKey;
    const keyType = keyObject.asymmetricKeyType;
    if (keyType === 'ed25519') {
      return crypto.verify(null, message, keyObject, signature);
    }
    if (keyType === 'ec') {
      return crypto.verify('sha256', message, { key: keyObject, dsaEncoding: 'ieee-p1363' }, signature);
    }
    return false;
  } catch (_) {
    return false;
  }
}

// The exact bytes the device key signs at login: the versioned prefix followed by
// the server-issued challenge. The client reconstructs this from the same prefix.
function loginChallengeMessage(challenge) {
  return Buffer.from(LOGIN_SIGNING_PREFIX + String(challenge), 'utf8');
}

// RFC 7638 JWK SHA-256 thumbprint (base64url) of the public key, the value bound
// into the session token's RFC 7800 cnf.jkt claim. Only the required members, in
// lexicographic order with no whitespace, are hashed, per the RFC.
function jwkThumbprint(publicKey) {
  const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
  let members;
  if (jwk.kty === 'EC') {
    members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  } else if (jwk.kty === 'OKP') {
    members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  } else {
    throw new Error('unsupported key type for thumbprint');
  }
  return crypto.createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

// Issue a single-use login challenge bound to one operator. Returns the raw
// challenge (what the device key signs, via loginChallengeMessage) and an opaque
// challenge token carrying the challenge, the operator id, a single-use jti, and a
// tight expiry, HMAC-signed with the GD secret.
function issueDeviceKeyChallenge(userId, purpose) {
  const challenge = crypto.randomBytes(32).toString('base64');
  const jti = crypto.randomBytes(16).toString('hex');
  const challengeToken = jwt.sign(
    { dk_challenge: challenge, purpose: purpose || DEVICE_KEY_LOGIN_PURPOSE, userId: String(userId), jti },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: CHALLENGE_TTL_SEC }
  );
  return { challenge, challengeToken };
}

// Verify and consume a challenge token: checks the HMAC and expiry, the expected
// purpose, and that the jti has not already been used, then marks it used. Throws
// on any failure (invalid or expired token, purpose mismatch, or replay). Returns
// the challenge bytes and the operator id the challenge was issued for.
function consumeDeviceKeyChallenge(token, expectedPurpose) {
  const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  if (!decoded || !decoded.dk_challenge || !decoded.jti) {
    throw new Error('invalid challenge token');
  }
  const wantPurpose = expectedPurpose || DEVICE_KEY_LOGIN_PURPOSE;
  if (decoded.purpose !== wantPurpose) {
    throw new Error('challenge token purpose mismatch');
  }
  const nowMs = Date.now();
  pruneUsedJti(nowMs);
  if (usedChallengeJti.has(decoded.jti)) {
    throw new Error('challenge already used');
  }
  const expMs = decoded.exp ? decoded.exp * 1000 : nowMs + CHALLENGE_TTL_SEC * 1000;
  usedChallengeJti.set(decoded.jti, expMs);
  return { challenge: decoded.dk_challenge, userId: decoded.userId || null, jti: decoded.jti };
}

module.exports = {
  verifyDeviceKeySignature,
  loginChallengeMessage,
  jwkThumbprint,
  issueDeviceKeyChallenge,
  consumeDeviceKeyChallenge,
  CHALLENGE_TTL_SEC,
  DEVICE_KEY_LOGIN_PURPOSE,
  LOGIN_SIGNING_PREFIX,
};

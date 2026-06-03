// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — FIDO2 / WebAuthn Relying-Party Service (Phase B5b)
//
// One of FireAlive's two co-primary passwordless, phishing-resistant credentials
// is a FIDO2/WebAuthn passkey (a hardware security key, or a platform/TPM
// authenticator). This service is the thin, policy-neutral wrapper around
// @simplewebauthn/server (^13.3.1) that the auth and MFA routes build on:
//
//   - getRpConfig(db)            resolve the Relying-Party identity (rpID / origin)
//   - beginRegistration(...)     options for enrolling a new passkey
//   - finishRegistration(...)    verify the attestation; return a normalized
//                                credential ready to persist in webauthn_credentials
//   - beginAuthentication(...)   options for a passkey login / 2nd-factor assertion
//   - finishAuthentication(...)  verify the assertion against a stored credential;
//                                return the new signature counter
//
// CHALLENGE HANDLING — STATELESS, NO TABLE
//   WebAuthn requires the exact challenge issued in the "begin" step to be
//   presented back in the "finish" step. Rather than persist per-attempt
//   challenges (a table + cleanup, and a coordination problem across instances),
//   this service wraps the library-generated challenge in a short-lived HS256
//   token signed with the same JWT_SECRET the rest of the auth stack uses (5-min
//   TTL, a `purpose` claim binding reg-vs-auth). The client returns the token
//   alongside the authenticator response; the "finish" step verifies the token
//   (signature + expiry + purpose) and feeds its challenge in as
//   expectedChallenge. Stateless, multi-instance-safe, and self-expiring.
//
// POLICY IS THE CALLER'S
//   userVerification / residentKey / requireUserVerification are parameters, not
//   baked-in. The passwordless login path (routes/auth.js) requires user
//   verification so a passkey login is MFA-complete on its own (a hardware key
//   PIN/biometric satisfies the second factor); a passkey enrolled merely as a
//   second factor can use the softer 'preferred'. This service expresses the
//   mechanism; the route expresses the assurance policy.
//
// supportedAlgorithmIDs is pinned to [-7, -257] (ES256 + RS256) — the pair every
// mainstream authenticator supports — which also sidesteps the OKP/Ed25519
// verification edge cases documented for some runtimes.
// ═══════════════════════════════════════════════════════════════════════════════

const jwt = require('jsonwebtoken');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

// Matches middleware/auth.js + routes/auth.js exactly so one secret governs all
// signed tokens.
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_INSECURE_DEFAULT';
const CHALLENGE_TTL_SEC = 300; // 5 minutes
const SUPPORTED_ALGORITHM_IDS = [-7, -257]; // ES256, RS256

// ── Relying-Party identity ────────────────────────────────────────────────────
// rpID is the registrable domain the user accesses (host only, no scheme/port);
// origin is the full https origin (scheme + host + [port], no trailing slash) and
// must match what the browser reports exactly. Both are deployment-specific:
// read from the config table (`webauthn_config` JSON), then env, then a localhost
// default for zero-config dev. An operator behind a 443 reverse proxy MUST set
// origin to e.g. "https://soc.example.org" (no :3000).
function getRpConfig(db) {
  let cfg = {};
  try {
    const row = db && db.prepare('SELECT value FROM config WHERE key = ?').get('webauthn_config');
    if (row && row.value) cfg = JSON.parse(row.value) || {};
  } catch (_) {
    cfg = {};
  }
  const rpID = cfg.rpID || process.env.WEBAUTHN_RP_ID || 'localhost';
  const rpName = cfg.rpName || process.env.WEBAUTHN_RP_NAME || 'FireAlive';
  const origin = cfg.origin || process.env.WEBAUTHN_ORIGIN || `https://${rpID}:3000`;
  return { rpID, rpName, origin };
}

// ── helpers ───────────────────────────────────────────────────────────────────
// Stored transports are a JSON string in webauthn_credentials.transports; the
// library wants an array (or undefined). Normalize either form.
function parseTransports(t) {
  if (Array.isArray(t)) return t;
  if (typeof t === 'string' && t) {
    try {
      const a = JSON.parse(t);
      return Array.isArray(a) ? a : undefined;
    } catch (_) {
      return undefined;
    }
  }
  return undefined;
}

function issueChallengeToken(challenge, extra) {
  return jwt.sign(
    Object.assign({ wa_challenge: challenge }, extra || {}),
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: CHALLENGE_TTL_SEC }
  );
}

function readChallengeToken(token, expectedPurpose) {
  const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  if (!decoded || !decoded.wa_challenge) throw new Error('invalid challenge token');
  if (expectedPurpose && decoded.purpose !== expectedPurpose) {
    throw new Error('challenge token purpose mismatch');
  }
  return decoded;
}

// ── Registration (enroll a passkey) ─────────────────────────────────────────────
async function beginRegistration({ rp, userId, userName, existingCredentials = [], residentKey = 'preferred', userVerification = 'preferred' }) {
  const options = await generateRegistrationOptions({
    rpName: rp.rpName,
    rpID: rp.rpID,
    userName: userName || String(userId),
    attestationType: 'none',
    excludeCredentials: (existingCredentials || []).map((c) => ({
      id: c.credentialId,
      transports: parseTransports(c.transports),
    })),
    authenticatorSelection: {
      residentKey,
      userVerification,
    },
    supportedAlgorithmIDs: SUPPORTED_ALGORITHM_IDS,
  });
  const challengeToken = issueChallengeToken(options.challenge, {
    purpose: 'reg',
    userId: userId != null ? String(userId) : null,
  });
  return { options, challengeToken };
}

async function finishRegistration({ rp, response, challengeToken, requireUserVerification = false }) {
  const decoded = readChallengeToken(challengeToken, 'reg');
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: decoded.wa_challenge,
    expectedOrigin: rp.origin,
    expectedRPID: rp.rpID,
    requireUserVerification,
  });
  if (!verification.verified || !verification.registrationInfo) {
    return { verified: false };
  }
  const info = verification.registrationInfo;
  const cred = info.credential;
  return {
    verified: true,
    userIdFromChallenge: decoded.userId || null,
    credential: {
      credentialId: cred.id, // Base64URLString
      publicKey: Buffer.from(cred.publicKey).toString('base64url'),
      counter: typeof cred.counter === 'number' ? cred.counter : 0,
      transports: cred.transports ? JSON.stringify(cred.transports) : null,
      aaguid: info.aaguid || null,
      deviceType: info.credentialDeviceType || null,
      backedUp: !!info.credentialBackedUp,
    },
  };
}

// ── Authentication (passkey login / 2nd factor) ─────────────────────────────────
async function beginAuthentication({ rp, allowCredentials = [], userVerification = 'preferred' }) {
  const options = await generateAuthenticationOptions({
    rpID: rp.rpID,
    allowCredentials: (allowCredentials || []).map((c) => ({
      id: c.credentialId,
      transports: parseTransports(c.transports),
    })),
    userVerification,
  });
  const challengeToken = issueChallengeToken(options.challenge, { purpose: 'auth' });
  return { options, challengeToken };
}

async function finishAuthentication({ rp, response, challengeToken, credential, requireUserVerification = false }) {
  const decoded = readChallengeToken(challengeToken, 'auth');
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: decoded.wa_challenge,
    expectedOrigin: rp.origin,
    expectedRPID: rp.rpID,
    credential: {
      id: credential.credentialId,
      publicKey: new Uint8Array(Buffer.from(credential.publicKey, 'base64url')),
      counter: typeof credential.counter === 'number' ? credential.counter : 0,
      transports: parseTransports(credential.transports),
    },
    requireUserVerification,
  });
  return {
    verified: !!verification.verified,
    newCounter: verification.authenticationInfo ? verification.authenticationInfo.newCounter : null,
  };
}

// ── Step-up authentication ──────────────────────────────────────
// A step-up is a fresh, user-verified WebAuthn assertion demanded at the moment
// of a sensitive action (config-lock toggle, restore approval, ...) so that a
// hijacked session cannot perform it without live access to the user's
// authenticator. It reuses the assertion machinery above with two differences:
// the challenge token carries purpose 'stepup' -- so a login assertion can never
// satisfy a step-up and vice versa -- and is bound to the acting user's id (the
// sub claim); and user verification is REQUIRED, not preferred. The caller
// (middleware/mfa-stepup.js) owns the DB work: it loads the user's passwordless
// credentials for allowCredentials, looks up the asserted credential, confirms it
// belongs to the acting user, and persists the new sign_count.
async function beginStepUp({ rp, allowCredentials = [], userId }) {
  const options = await generateAuthenticationOptions({
    rpID: rp.rpID,
    allowCredentials: (allowCredentials || []).map((c) => ({
      id: c.credentialId,
      transports: parseTransports(c.transports),
    })),
    userVerification: 'required',
  });
  const challengeToken = issueChallengeToken(options.challenge, {
    purpose: 'stepup',
    sub: userId,
  });
  return { options, challengeToken };
}

async function finishStepUp({ rp, response, challengeToken, credential, expectedUserId }) {
  const decoded = readChallengeToken(challengeToken, 'stepup');
  // Bind the challenge to the acting user: the token must have been issued for
  // this exact user id. Rejects presenting a step-up challenge minted for a
  // different user/session.
  if (!expectedUserId || decoded.sub !== expectedUserId) {
    throw new Error('challenge token user mismatch');
  }
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: decoded.wa_challenge,
    expectedOrigin: rp.origin,
    expectedRPID: rp.rpID,
    credential: {
      id: credential.credentialId,
      publicKey: new Uint8Array(Buffer.from(credential.publicKey, 'base64url')),
      counter: typeof credential.counter === 'number' ? credential.counter : 0,
      transports: parseTransports(credential.transports),
    },
    requireUserVerification: true,
  });
  return {
    verified: !!verification.verified,
    newCounter: verification.authenticationInfo ? verification.authenticationInfo.newCounter : null,
  };
}

module.exports = {
  getRpConfig,
  beginRegistration,
  finishRegistration,
  beginAuthentication,
  finishAuthentication,
  beginStepUp,
  finishStepUp,
  // exposed for reuse/tests
  parseTransports,
  issueChallengeToken,
  readChallengeToken,
  CHALLENGE_TTL_SEC,
  SUPPORTED_ALGORITHM_IDS,
};

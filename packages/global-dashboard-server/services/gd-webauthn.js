// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — FIDO2 / WebAuthn Relying-Party Service (Phase B5b)
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
//   token signed with the same GD_JWT_SECRET the GD auth stack uses (5-min
//   TTL, a `purpose` claim binding reg-vs-auth). The client returns the token
//   alongside the authenticator response; the "finish" step verifies the token
//   (signature + expiry + purpose) and feeds its challenge in as
//   expectedChallenge. Stateless, multi-instance-safe, and self-expiring.
//
// POLICY IS THE CALLER'S
//   userVerification / residentKey / requireUserVerification are parameters, not
//   baked-in. The passwordless login path (the GD auth routes) requires user
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
const crypto = require('crypto');
const { decodeAttestationObject } = require('@simplewebauthn/server/helpers');

// Uses the GD's own GD_JWT_SECRET so one secret governs all GD-signed tokens.
const JWT_SECRET = process.env.GD_JWT_SECRET || 'CHANGE_ME_INSECURE_DEFAULT';
const CHALLENGE_TTL_SEC = 300; // 5 minutes
const SUPPORTED_ALGORITHM_IDS = [-7, -257]; // ES256, RS256

// ── Relying-Party identity ────────────────────────────────────────────────────
// rpID is the registrable domain the user accesses (host only, no scheme/port);
// origin is the full https origin (scheme + host + [port], no trailing slash) and
// must match what the browser reports exactly. Both are deployment-specific:
// read from the config table (`webauthn_config` JSON), then env, then a localhost
// default for zero-config dev. An operator behind a 443 reverse proxy MUST set
// origin to e.g. "https://soc.example.org" (no :4001).
function getRpConfig(db) {
  let cfg = {};
  try {
    const row = db && db.prepare('SELECT value FROM config WHERE key = ?').get('webauthn_config');
    if (row && row.value) cfg = JSON.parse(row.value) || {};
  } catch (_) {
    cfg = {};
  }
  const rpID = cfg.rpID || process.env.GD_WEBAUTHN_RP_ID || 'localhost';
  const rpName = cfg.rpName || process.env.GD_WEBAUTHN_RP_NAME || 'FireAlive Global Dashboard';
  const origin = cfg.origin || process.env.GD_WEBAUTHN_ORIGIN || `https://${rpID}:4001`;
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
    attestationType: 'direct',
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

async function finishRegistration({ rp, response, challengeToken, requireUserVerification = false, db = null }) {
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
  // Hardware-attestation verdict: does the attestation chain to a trusted vendor
  // root? attestationVerified is true ONLY when a real x5c chained to a bundled or
  // admin-added root (rejecting 'none' and self-attestation); trustedRootId names
  // the matched root. The route layer feeds these to assertHardwareCredential.
  const chain = parseAttestationChain(info.attestationObject);
  const roots = loadTrustedRoots(db);
  const chainResult = verifyAttestationChain(chain, roots);
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
      fmt: info.fmt || null,
      attestationVerified: chainResult.verified === true,
      trustedRootId: chainResult.trustedRootId || null,
    },
  };
}

// ── Hardware-credential attestation gate (B5n3) ─────────────────────────────────
// FireAlive login requires a *hardware* FIDO2 key with a PIN. Enrollment must
// prove the passkey is genuine hardware: its attestation must chain to a trusted
// vendor root (fido_trusted_roots -- the bundled seed plus any admin-added root).
// We verify that chain here with Node's crypto.X509Certificate rather than via
// SettingsService.setRootCertificates, for three reasons: (1) a packed
// self-attestation carries no x5c and would pass verifyRegistrationResponse even
// with roots configured -- only inspecting the attestation for a real vendor x5c
// closes that gap; (2) we need to know WHICH root matched, to record
// trusted_root_id; and (3) one explicit gate yields a uniform, client-safe 422
// instead of a library throw. The library still performs every other WebAuthn
// check (challenge, origin, RP ID, signature, user verification, and the
// authData-vs-leaf AAGUID match).

// simplewebauthn decodes CBOR maps to JS Maps; tolerate a plain object too.
function cborGet(obj, key) {
  if (!obj) return undefined;
  if (typeof obj.get === 'function') return obj.get(key);
  return obj[key];
}

// Extract the attestation x5c (leaf-first DER chain) from a verified registration's
// attestation object as crypto.X509Certificate[]. Returns [] when the attestation
// carries no certificate (fmt 'none' or self-attestation) or cannot be parsed.
function parseAttestationChain(attestationObject) {
  if (!attestationObject) return [];
  let decoded;
  try {
    decoded = decodeAttestationObject(attestationObject);
  } catch (_) {
    return [];
  }
  const attStmt = cborGet(decoded, 'attStmt');
  const x5c = cborGet(attStmt, 'x5c');
  if (!Array.isArray(x5c) || x5c.length === 0) return [];
  const certs = [];
  for (const der of x5c) {
    try {
      certs.push(new crypto.X509Certificate(Buffer.from(der)));
    } catch (_) {
      return []; // a malformed cert in the chain -> no usable attestation
    }
  }
  return certs;
}

// Load the trusted attestation roots as parsed certificates. A single unparseable
// stored row is skipped (the seeder validates the seed and the admin-add route
// validates each PEM at insert time) so it cannot break enrollment for everyone.
function loadTrustedRoots(db) {
  const roots = [];
  if (!db) return roots;
  let rows;
  try {
    rows = db.prepare('SELECT id, root_pem FROM fido_trusted_roots').all();
  } catch (_) {
    return roots;
  }
  for (const row of rows || []) {
    try {
      roots.push({ id: row.id, cert: new crypto.X509Certificate(row.root_pem) });
    } catch (_) {
      // skip an unparseable stored root
    }
  }
  return roots;
}

// Verify a leaf-first chain links cryptographically and terminates at one of the
// trusted roots. Returns { verified, trustedRootId }. This is the trust-anchor
// decision for "is this genuine vendor hardware".
function verifyAttestationChain(chain, roots) {
  if (!Array.isArray(chain) || chain.length === 0) {
    return { verified: false, trustedRootId: null };
  }
  // Each cert must be signed by the next one up (name link + signature).
  for (let i = 0; i < chain.length - 1; i++) {
    const child = chain[i];
    const parent = chain[i + 1];
    if (child.issuer !== parent.subject) return { verified: false, trustedRootId: null };
    let ok = false;
    try { ok = child.verify(parent.publicKey); } catch (_) { ok = false; }
    if (!ok) return { verified: false, trustedRootId: null };
  }
  // The top of the chain must BE a trusted root, or be signed by one.
  const top = chain[chain.length - 1];
  for (const r of roots || []) {
    if (Buffer.compare(top.raw, r.cert.raw) === 0) {
      return { verified: true, trustedRootId: r.id };
    }
  }
  for (const r of roots || []) {
    if (top.issuer !== r.cert.subject) continue;
    let ok = false;
    try { ok = top.verify(r.cert.publicKey); } catch (_) { ok = false; }
    if (ok) return { verified: true, trustedRootId: r.id };
  }
  return { verified: false, trustedRootId: null };
}

// Thrown by assertHardwareCredential. The message is safe to surface to the client;
// reason is a machine-readable code for the audit log.
class HardwareCredentialError extends Error {
  constructor(reason) {
    super('This authenticator is not an accepted hardware security key. Use a FIDO2 hardware key (a security key or fob) that requires a PIN; synced or software passkeys are not accepted.');
    this.name = 'HardwareCredentialError';
    this.reason = reason || 'not_hardware';
  }
}

// The single chokepoint every enrollment path calls. Throws HardwareCredentialError
// unless the credential is proven genuine hardware: attestation chained to a
// trusted vendor root, a real attestation format is present, it is not a
// synced/backed-up credential, it is not a multi-device credential, and -- when
// the optional AAGUID allow-list is non-empty -- its model is on that list.
function assertHardwareCredential({ attestationVerified, backedUp, deviceType, fmt, aaguid, db }) {
  if (attestationVerified !== true) {
    throw new HardwareCredentialError('attestation_not_trusted');
  }
  if (!fmt || fmt === 'none') {
    throw new HardwareCredentialError('no_attestation');
  }
  if (backedUp !== false) {
    throw new HardwareCredentialError('synced_credential');
  }
  if (deviceType === 'multiDevice') {
    throw new HardwareCredentialError('multi_device_credential');
  }
  // Optional model narrowing: empty allow-list = any model from a trusted vendor.
  let allow = [];
  if (db) {
    try {
      allow = db.prepare('SELECT aaguid FROM fido_aaguid_allowlist').all().map((r) => r.aaguid);
    } catch (_) {
      allow = [];
    }
  }
  if (allow.length > 0 && (!aaguid || allow.indexOf(aaguid) === -1)) {
    throw new HardwareCredentialError('model_not_allowed');
  }
  return true;
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

// -- Step-up (re-prove the hardware credential for a sensitive action) --
// A fresh, user-verified assertion separate from login-time auth, used to gate
// sensitive operations so that even a hijacked session cannot perform them
// without live access to the operator's authenticator.
async function beginStepUp({ rp, allowCredentials = [], userId }) {
  const options = await generateAuthenticationOptions({
    rpID: rp.rpID,
    allowCredentials: (allowCredentials || []).map((c) => ({
      id: c.credentialId,
      transports: parseTransports(c.transports),
    })),
    userVerification: 'required',
  });
  // Bind the challenge to the acting user (sub) so a step-up challenge minted for
  // one user cannot be presented by another.
  const challengeToken = issueChallengeToken(options.challenge, { purpose: 'stepup', sub: userId });
  return { options, challengeToken };
}

async function finishStepUp({ rp, response, challengeToken, credential, expectedUserId }) {
  const decoded = readChallengeToken(challengeToken, 'stepup');
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
  // Hardware-credential attestation gate (B5n3)
  assertHardwareCredential,
  HardwareCredentialError,
  // exposed for reuse/tests
  parseTransports,
  issueChallengeToken,
  readChallengeToken,
  parseAttestationChain,
  loadTrustedRoots,
  verifyAttestationChain,
  CHALLENGE_TTL_SEC,
  SUPPORTED_ALGORITHM_IDS,
};

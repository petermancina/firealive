// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — MFA Self-Service Routes (passkeys, certificates, step-up)
//
// Authenticated users manage their own phishing-resistant credentials via
// these endpoints. All operations are scoped to req.user.id -- the routes
// never accept a user_id parameter, so a user cannot enroll, remove, or
// step-up as anyone else.
//
// There is no TOTP self-service: TOTP was removed platform-wide in favor of
// passkeys and client certificates (both AAL3, phishing-resistant).
//
// Endpoints:
//   POST   /api/mfa/passkey/register-options  { passwordless? } -> { options, challengeToken }
//   POST   /api/mfa/passkey/register-verify   { response, challengeToken, passwordless?, label? }
//   GET    /api/mfa/passkeys                   -> { passkeys }
//   DELETE /api/mfa/passkeys/:id               -> { deleted }   (lockout-guarded)
//   POST   /api/mfa/cert/enroll                { csrPem } -> { certPem, serial, ... }
//   GET    /api/mfa/certs                      -> issued certificates for the user
//   POST   /api/mfa/certs/revoke               { serial, reason? } -> { revoked, serial }
//   POST   /api/mfa/stepup/options             -> { options, challengeToken }
//
// Step-up: /stepup/options issues a fresh, user-verified assertion challenge
// over the caller's passwordless passkeys. The signed assertion is replayed in
// body.stepup on a sensitive route, where the mfaStepUp middleware verifies it
// before the action runs.
//
// Auth:
//   This file is mounted with authMiddleware(['analyst', 'lead', 'admin'])
//   in server/index.js. Any authenticated user can manage
//   their own credentials. No per-handler role tightening -- the user_id
//   scoping to req.user.id is the security boundary.
//
// Why a top-level /api/mfa rather than /api/auth/mfa:
//   - /api/auth is mounted without authMiddleware (login is unauthenticated)
//   - These endpoints all require an authenticated JWT
//   - Splitting into /api/mfa lets index.js cleanly apply authMiddleware
//     at the mount point without per-handler exemptions
//
// Audit log:
//   Passkey/cert operations and step-up outcomes are audited at the route or
//   middleware (e.g. STEPUP_WEBAUTHN_OK / STEPUP_WEBAUTHN_FAILED); the global
//   auditMiddleware in index.js writes the HTTP-level row. This file does not
//   duplicate-log.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const webauthn = require('../services/webauthn');
const ca = require('../services/ca');
const { auditLog } = require('../middleware/audit');

// ═══════════════════════════════════════════════════════════════════════════════
// B5b — FIDO2/WebAuthn passkey enrollment & management (self-service)
//
// These endpoints let an already-authenticated user enroll and manage their own
// passkeys on the session-protected /api/mfa mount. A passkey can be enrolled
// either as a PASSWORDLESS login credential (discoverable / resident key, user
// verification required — AAL3, usable on its own at /login-webauthn) or as a
// SECOND FACTOR only. The WebAuthn protocol work lives in services/webauthn.js;
// this file persists results in webauthn_credentials and enforces a lockout
// guard on removal.
//
// First-credential bootstrap (a brand-new user with no session) and break-glass
// recovery enrollment are deliberately NOT here — those callers have no session
// and are handled by a separate token-gated path.
// ═══════════════════════════════════════════════════════════════════════════════

// Count a user's usable LOGIN methods, optionally excluding one passkey (used to
// preview the effect of a deletion). A login method is an active issued
// certificate or a passwordless passkey -- the only ways to obtain a session.
// Second-factor-only passkeys are NOT login methods and never count here.
function countLoginMethodsExcluding(db, userId, excludePasskeyId, excludeCertSerial) {
  const pwlessPasskeys = db.prepare(
    'SELECT COUNT(*) AS c FROM webauthn_credentials WHERE user_id = ? AND is_passwordless = 1 AND id != ?'
  ).get(userId, excludePasskeyId || '').c;
  const activeCerts = db.prepare(
    "SELECT COUNT(*) AS c FROM issued_certs WHERE user_id = ? AND status = 'active' AND serial != ?"
  ).get(userId, excludeCertSerial || '').c;
  return pwlessPasskeys + activeCerts;
}

// ── POST /api/mfa/passkey/register-options ──────────────────────────────────
// Begin passkey enrollment for the calling user. Body: { passwordless?: bool }.
// A passwordless passkey is requested as a discoverable resident key with user
// verification required; a second-factor passkey uses softer settings.
router.post('/passkey/register-options', async (req, res) => {
  try {
    const db = getDb();
    const passwordless = !!(req.body && req.body.passwordless);
    const rp = webauthn.getRpConfig(db);
    const existing = db.prepare(
      'SELECT credential_id AS credentialId, transports FROM webauthn_credentials WHERE user_id = ?'
    ).all(req.user.id);
    const { options, challengeToken } = await webauthn.beginRegistration({
      rp,
      userId: req.user.id,
      userName: req.user.name || req.user.id,
      existingCredentials: existing,
      residentKey: passwordless ? 'required' : 'discouraged',
      userVerification: passwordless ? 'required' : 'preferred',
    });
    return res.json({ options, challengeToken });
  } catch (err) {
    logger.error('Passkey register-options failed', { userId: req.user.id, error: err.message });
    return res.status(500).json({ error: 'could not start passkey enrollment', code: 'INTERNAL' });
  }
});

// ── POST /api/mfa/passkey/register-verify ───────────────────────────────────
// Finish passkey enrollment. Body: { response, challengeToken, passwordless?, label? }.
// For a passwordless passkey, user verification is required at verification time
// so the credential is genuinely MFA-complete. Persists the credential and
// returns its public identifier.
router.post('/passkey/register-verify', async (req, res) => {
  try {
    const db = getDb();
    const body = req.body || {};
    if (!body.response || !body.challengeToken) {
      return res.status(400).json({ error: 'response and challengeToken required' });
    }
    const passwordless = !!body.passwordless;
    const rp = webauthn.getRpConfig(db);
    let result;
    try {
      result = await webauthn.finishRegistration({
        rp,
        response: body.response,
        challengeToken: body.challengeToken,
        requireUserVerification: passwordless,
        db,
      });
    } catch (vErr) {
      return res.status(400).json({ error: 'passkey verification failed', detail: vErr.message });
    }
    if (!result.verified || !result.credential) {
      return res.status(400).json({ error: 'passkey verification failed' });
    }
    const c = result.credential;
    // Hardware-credential verdict. A passwordless passkey can serve as a login
    // credential, so it MUST be genuine hardware -- gate it with the same
    // chokepoint as first-credential enrollment (reject with 422 + audit). A
    // second-factor-only passkey cannot log in (is_passwordless = 0 is refused at
    // /login-webauthn/verify), so its hardware status is recorded honestly but is
    // not required.
    let hardwareVerified = 0;
    try {
      webauthn.assertHardwareCredential({
        attestationVerified: c.attestationVerified,
        backedUp: c.backedUp,
        deviceType: c.deviceType,
        fmt: c.fmt,
        aaguid: c.aaguid,
        db,
      });
      hardwareVerified = 1;
    } catch (hwErr) {
      if (!(hwErr instanceof webauthn.HardwareCredentialError)) throw hwErr;
      if (passwordless) {
        auditLog(req.user.id, 'ENROLL_PASSKEY_NOT_HARDWARE',
          `reason=${hwErr.reason} fmt=${c.fmt || 'none'} aaguid=${c.aaguid || 'none'} backedUp=${c.backedUp} passwordless=true`, req.ip);
        return res.status(422).json({ error: hwErr.message, code: 'ENROLL_PASSKEY_NOT_HARDWARE' });
      }
      // second-factor only: not hardware, but permitted; hardwareVerified stays 0
    }
    try {
      db.prepare(`
        INSERT INTO webauthn_credentials
          (user_id, credential_id, public_key, sign_count, transports, aaguid, is_passwordless,
           backed_up, device_type, attestation_fmt, hardware_verified, trusted_root_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.user.id,
        c.credentialId,
        c.publicKey,
        c.counter || 0,
        c.transports || null,
        c.aaguid || null,
        passwordless ? 1 : 0,
        c.backedUp ? 1 : 0,
        c.deviceType || null,
        c.fmt || null,
        hardwareVerified,
        c.trustedRootId || null
      );
    } catch (dbErr) {
      // UNIQUE(credential_id) violation => the authenticator is already enrolled.
      if (/UNIQUE|constraint/i.test(dbErr.message)) {
        return res.status(409).json({ error: 'this authenticator is already enrolled' });
      }
      throw dbErr;
    }
    auditLog(req.user.id, 'WEBAUTHN_PASSKEY_ENROLLED',
      `passwordless=${passwordless} cred=${String(c.credentialId).slice(0, 12)}…`, req.ip);
    return res.status(201).json({
      enrolled: true,
      passwordless,
      credential_id: c.credentialId,
      backed_up: !!c.backedUp,
      device_type: c.deviceType || null,
    });
  } catch (err) {
    logger.error('Passkey register-verify failed', { userId: req.user.id, error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── GET /api/mfa/passkeys ───────────────────────────────────────────────────
// List the calling user's passkeys (no key material).
router.get('/passkeys', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT id, credential_id, is_passwordless, aaguid, created_at, last_used_at
      FROM webauthn_credentials WHERE user_id = ?
      ORDER BY created_at DESC, rowid DESC
    `).all(req.user.id);
    return res.json({ passkeys: rows });
  } catch (err) {
    logger.error('Passkey list failed', { userId: req.user.id, error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── DELETE /api/mfa/passkeys/:id ────────────────────────────────────────────
// Remove one of the calling user's passkeys. Refuses if it would leave the user
// with no way to authenticate (no password, no active certificate, no other
// passwordless passkey) — lockout prevention.
router.delete('/passkeys/:id', (req, res) => {
  try {
    const db = getDb();
    const id = req.params.id;
    const cred = db.prepare('SELECT * FROM webauthn_credentials WHERE id = ? AND user_id = ?').get(id, req.user.id);
    if (!cred) return res.status(404).json({ error: 'passkey not found' });
    if (countLoginMethodsExcluding(db, req.user.id, id) === 0) {
      return res.status(409).json({
        error: 'cannot remove your last login credential; enroll another authenticator first',
        code: 'LAST_CREDENTIAL',
      });
    }
    db.prepare('DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?').run(id, req.user.id);
    auditLog(req.user.id, 'WEBAUTHN_PASSKEY_REMOVED', `cred=${String(cred.credential_id).slice(0, 12)}…`, req.ip);
    return res.json({ removed: true, id });
  } catch (err) {
    logger.error('Passkey delete failed', { userId: req.user.id, error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});


// ── POST /api/mfa/stepup/options ──────────────────────────────
// Begin a step-up: issue a fresh, user-verified assertion challenge for the
// calling user's passwordless passkeys. The client signs the returned options
// and resends the assertion (with this challengeToken) in body.stepup on the
// sensitive route, where the mfaStepUp middleware verifies it. Step-up requires
// an enrolled passwordless passkey; a user with none (e.g. certificate-only)
// must enroll one before performing step-up-gated actions.
router.post('/stepup/options', async (req, res) => {
  try {
    const db = getDb();
    const rp = webauthn.getRpConfig(db);
    const creds = db.prepare(
      'SELECT credential_id AS credentialId, transports FROM webauthn_credentials WHERE user_id = ? AND is_passwordless = 1'
    ).all(req.user.id);
    if (!creds.length) {
      return res.status(409).json({
        error: 'step-up requires an enrolled passwordless passkey; none found for this account',
        code: 'NO_STEPUP_CREDENTIAL',
      });
    }
    const { options, challengeToken } = await webauthn.beginStepUp({
      rp,
      allowCredentials: creds,
      userId: req.user.id,
    });
    return res.json({ options, challengeToken });
  } catch (err) {
    logger.error('MFA stepup options failed', { userId: req.user.id, error: err.message });
    return res.status(500).json({ error: 'could not start step-up', code: 'INTERNAL' });
  }
});

// ── POST /api/mfa/cert/enroll ───────────────────────────────────────────────
// Self-service client-certificate enrollment for the calling user. Takes a CSR
// the user generated on-device and signs it with the built-in CA; the asserted
// identity is bound by a server-controlled SAN (the user's external_id), not
// the CSR's CN, so a user cannot self-assert another identity. The issued
// certificate is recorded in issued_certs and returned with the CA chain.
// Synchronous: CA issuance shells out to openssl.
router.post('/cert/enroll', (req, res) => {
  try {
    const db = getDb();
    const body = req.body || {};
    if (!body.csrPem || typeof body.csrPem !== 'string') {
      return res.status(400).json({ error: 'csrPem (PEM string) required', code: 'CSR_REQUIRED' });
    }
    const user = db.prepare('SELECT id, external_id FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: 'user not found' });
    let issued;
    try {
      issued = ca.issueClientCert(db, { csrPem: body.csrPem, userId: user.id, externalId: user.external_id || null });
    } catch (cErr) {
      return res.status(400).json({ error: 'certificate issuance failed', detail: cErr.message, code: 'ISSUANCE_FAILED' });
    }
    auditLog(req.user.id, 'CERT_SELF_ENROLLED', `serial=${issued.serial} fp=${String(issued.fingerprint256).slice(0, 16)}…`, req.ip);
    return res.status(201).json({
      enrolled: true,
      certPem: issued.certPem,
      serial: issued.serial,
      fingerprint256: issued.fingerprint256,
      caCertPem: issued.caCertPem,
    });
  } catch (err) {
    logger.error('Cert self-enroll failed', { userId: req.user.id, error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── GET /api/mfa/certs ──────────────────────────────────────────────────────
// List the calling user's own issued client certificates.
router.get('/certs', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT serial, subject, status, issued_at, expires_at, fingerprint256, revoked_at, revoked_reason
      FROM issued_certs WHERE user_id = ?
      ORDER BY issued_at DESC, rowid DESC
    `).all(req.user.id);
    return res.json({ certs: rows });
  } catch (err) {
    logger.error('Cert list failed', { userId: req.user.id, error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/mfa/certs/revoke ──────────────────────────────────────────────
// Revoke one of the calling user's own certificates. Refuses if it would leave
// the user with no way to authenticate (no password, no other active cert, no
// passwordless passkey) — lockout prevention.
router.post('/certs/revoke', (req, res) => {
  try {
    const db = getDb();
    const { serial, reason } = req.body || {};
    if (!serial) return res.status(400).json({ error: 'serial required', code: 'SERIAL_REQUIRED' });
    const cert = db.prepare('SELECT status FROM issued_certs WHERE serial = ? AND user_id = ?').get(serial, req.user.id);
    if (!cert) return res.status(404).json({ error: 'certificate not found' });
    if (cert.status === 'revoked') return res.status(409).json({ error: 'certificate already revoked', code: 'ALREADY_REVOKED' });
    if (countLoginMethodsExcluding(db, req.user.id, null, serial) === 0) {
      return res.status(409).json({
        error: 'cannot revoke your last login credential; enroll another authenticator first',
        code: 'LAST_CREDENTIAL',
      });
    }
    ca.revokeCert(db, { serial, reason: reason || 'self-service' });
    auditLog(req.user.id, 'CERT_SELF_REVOKED', `serial=${serial} reason=${reason || 'self-service'}`, req.ip);
    return res.json({ revoked: true, serial });
  } catch (err) {
    logger.error('Cert self-revoke failed', { userId: req.user.id, error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

module.exports = router;

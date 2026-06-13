// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Auth Routes
//
// Passwordless, phishing-resistant authentication. The only ways in are a
// mutual-TLS client certificate (verified against the built-in CA) or a
// FIDO2/WebAuthn passkey — both AAL3 and MFA-complete on their own, so there is
// no password login, no LDAP login, and no second-factor prompt. Lockout
// recovery is the audited one-time break-glass credential, which authorizes the
// enrollment of a single new authenticator and nothing else. Sessions are a
// short-lived access JWT plus a rotating refresh token.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getDb } = require('../db/init');
const { signToken } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { verifyPeerCertificate } = require('../middleware/network-security');
const ca = require('../services/ca');
const webauthn = require('../services/webauthn');
const { isVirtualized } = require('../services/deployment-mode');
const { checkClockIntegrity } = require('../services/clock-integrity');
const rateLimit = require('express-rate-limit');

// ── Configuration ────────────────────────────────────────────────────────────

const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;  // 7 days, matches v1.0.30

// JWT_SECRET fallback matches middleware/auth.js exactly so the
// break-glass enrollment token and the auth JWT use the same key
// (HS256, algorithm-pinned on verification).
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_INSECURE_DEFAULT';

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Issue accessToken + refreshToken + sessions row for the given
 * authenticated user. Centralized so the cert and passkey login paths share it.
 * Returns the response shape sent to the client.
 */
function issueJwt(db, user, ipAddress, userAgent) {
  const accessToken = signToken(user);
  const refreshToken = crypto.randomBytes(64).toString('hex');
  const refreshHash = bcrypt.hashSync(refreshToken, 10);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000).toISOString();
  // Enforce max concurrent sessions (access-control config); evict the oldest beyond the limit.
  let maxSessions = 3;
  try {
    const acRow = db.prepare("SELECT value FROM team_config WHERE key = 'access_control_config'").get();
    if (acRow) {
      const m = parseInt(JSON.parse(acRow.value).maxConcurrentSessions, 10);
      if (m >= 1 && m <= 10) maxSessions = m;
    }
  } catch (e) { /* fall back to the default */ }
  const activeSessions = db.prepare(
    "SELECT id FROM sessions WHERE user_id = ? AND expires_at > datetime('now') ORDER BY created_at ASC"
  ).all(user.id);
  const overflow = activeSessions.length - (maxSessions - 1);
  if (overflow > 0) {
    const delSession = db.prepare("DELETE FROM sessions WHERE id = ?");
    for (const r of activeSessions.slice(0, overflow)) delSession.run(r.id);
  }
  db.prepare(`
    INSERT INTO sessions (user_id, refresh_token_hash, ip_address, user_agent, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(user.id, refreshHash, ipAddress || null, userAgent || null, expiresAt);
  db.prepare(`UPDATE users SET last_login = datetime('now') WHERE id = ?`).run(user.id);
  return {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      name: user.name,
      role: user.role,
      tier: user.tier,
      shift: user.shift,
    },
  };
}

// All session-invalid codes map to 401 -- the client must restart
// the login flow. 410 (Gone) might be more semantically correct for
// EXPIRED but the client behavior is identical (re-login), so 401
// keeps mapping simple.
function sessionInvalidStatus(_code) {
  return 401;
}

// ── POST /api/auth/refresh ───────────────────────────────────────────────────
//
// Re-issue an access token using a refresh token. Refused if the account is
// inactive; otherwise a fresh short-lived access token is returned.
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

  try {
    const db = getDb();
    const sessions = db.prepare(`
      SELECT s.*,
             u.id   AS user_id,
             u.role AS role,
             u.name AS name,
             u.tier AS tier,
             u.shift AS shift,
             u.active                  AS active
      FROM sessions s JOIN users u ON s.user_id = u.id
      WHERE s.expires_at > datetime('now')
    `).all();

    let matched = null;
    for (const s of sessions) {
      if (bcrypt.compareSync(refreshToken, s.refresh_token_hash)) {
        matched = s;
        break;
      }
    }

    if (!matched) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    if (matched.active === 0) {
      auditLog(matched.user_id, 'LOGIN_ENROLLMENT_BLOCKED',
        'user inactive on refresh', req.ip);
      return res.status(403).json({
        error: 'account is inactive',
        code: 'ACCOUNT_INACTIVE',
      });
    }
    const accessToken = signToken({
      id: matched.user_id,
      role: matched.role,
      name: matched.name,
      tier: matched.tier,
      shift: matched.shift,
    });
    return res.json({ accessToken });
  } catch (err) {
    logger.error('Token refresh error', { error: err.message });
    return res.status(500).json({ error: 'Token refresh failed' });
  }
});

// ── POST /api/auth/logout ────────────────────────────────────────────────────
//
// Unchanged from v1.0.30.
router.post('/logout', (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) {
    try {
      const db = getDb();
      const authHeader = req.headers.authorization;
      if (authHeader) {
        const decoded = jwt.decode(authHeader.slice(7));
        if (decoded && decoded.id) {
          db.prepare('DELETE FROM sessions WHERE user_id = ?').run(decoded.id);
          auditLog(decoded.id, 'LOGOUT', '', req.ip);
        }
      }
    } catch (err) {
      logger.error('Logout error', { error: err.message });
    }
  }
  return res.json({ ok: true });
});

// ── GET /api/auth/me ─────────────────────────────────────────────────────────
//
// Unchanged from v1.0.30.
router.get('/me', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    const { verifyToken } = require('../middleware/auth');
    const user = verifyToken(authHeader.slice(7));
    return res.json({
      user: {
        id: user.id,
        name: user.name,
        role: user.role,
        tier: user.tier,
        shift: user.shift,
      },
    });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// B5b — Passwordless authentication + break-glass
//
// The only accepted credentials are a mutual-TLS client certificate and a
// FIDO2/WebAuthn passkey, both AAL3 and MFA-complete — no password or LDAP login
// path and no second-factor prompt. Break-glass is the sole recovery.
// ═══════════════════════════════════════════════════════════════════════════════

// Finish an AAL3 (cert / user-verified passkey) login. The credential is already
// MFA-complete, so the session is issued directly; the only gate is an
// offboarded account.
function finishPasswordlessLogin(db, user, req, res, method) {
  if (user.offboarded_at) {
    auditLog(user.id, 'LOGIN_OFFBOARDED', `method=${method}`, req.ip);
    return res.status(403).json({ error: 'account offboarded' });
  }
  const result = issueJwt(db, user, req.ip, req.headers['user-agent']);
  auditLog(user.id, 'LOGIN_SUCCESS', `role=${user.role} method=${method} aal=high`, req.ip);
  return res.json(result);
}

// ── POST /api/auth/login-cert — passwordless mutual-TLS client certificate ───
// The TLS layer requested the client cert (requestCert:true); this verifies it
// against the built-in CA and maps it to a user via the issued_certs record
// (user_id, else external_id). No password and no second prompt — a hardware
// cert + PIN is AAL3.
router.post('/login-cert', (req, res) => {
  try {
    const db = getDb();
    const result = verifyPeerCertificate(req, db);
    if (!result.valid) {
      auditLog(null, 'LOGIN_CERT_FAILED', `reason=${result.reason || 'unknown'}`, req.ip);
      return res.status(401).json({ error: 'client certificate not accepted', reason: result.reason });
    }
    let user = null;
    if (result.userId) user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.userId);
    if (!user && result.externalId) user = db.prepare('SELECT * FROM users WHERE external_id = ?').get(result.externalId);
    if (!user) {
      auditLog(null, 'LOGIN_CERT_NO_USER', `external_id=${result.externalId || 'none'}`, req.ip);
      return res.status(401).json({ error: 'certificate valid but no matching user' });
    }
    return finishPasswordlessLogin(db, user, req, res, 'cert');
  } catch (err) {
    logger.error('Login-cert error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'Authentication error' });
  }
});

// ── POST /api/auth/login-webauthn/options — passkey assertion options ────────
// Returns WebAuthn authentication options + a stateless challenge token. With no
// username, allowCredentials is empty (discoverable/resident-key login); with a
// username, it is scoped to that user's passwordless credentials.
router.post('/login-webauthn/options', async (req, res) => {
  try {
    const db = getDb();
    const rp = webauthn.getRpConfig(db);
    let allowCredentials = [];
    const username = req.body && req.body.username;
    if (username) {
      const u = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
      if (u) {
        allowCredentials = db.prepare(
          'SELECT credential_id AS credentialId, transports FROM webauthn_credentials WHERE user_id = ? AND is_passwordless = 1'
        ).all(u.id);
      }
    }
    const { options, challengeToken } = await webauthn.beginAuthentication({
      rp, allowCredentials, userVerification: 'required',
    });
    return res.json({ options, challengeToken });
  } catch (err) {
    logger.error('Login-webauthn options error', { error: err.message });
    return res.status(500).json({ error: 'could not start passkey authentication' });
  }
});

// ── POST /api/auth/login-webauthn/verify — verify passkey assertion ──────────
// Looks up the credential by id, verifies the assertion (user verification
// REQUIRED → a verified passkey is MFA-complete), updates the signature counter
// (clone detection), and issues a session. Only credentials enrolled for
// passwordless use may serve as a primary login.
router.post('/login-webauthn/verify', async (req, res) => {
  try {
    const db = getDb();
    const body = req.body || {};
    const response = body.response;
    const challengeToken = body.challengeToken;
    if (!response || !challengeToken) {
      return res.status(400).json({ error: 'response and challengeToken required' });
    }
    const credId = response.id || response.rawId;
    if (!credId) return res.status(400).json({ error: 'malformed assertion' });
    const cred = db.prepare('SELECT * FROM webauthn_credentials WHERE credential_id = ?').get(credId);
    if (!cred) {
      auditLog(null, 'LOGIN_WEBAUTHN_UNKNOWN_CRED', '', req.ip);
      return res.status(401).json({ error: 'unknown credential' });
    }
    const rp = webauthn.getRpConfig(db);
    let verification;
    try {
      verification = await webauthn.finishAuthentication({
        rp,
        response,
        challengeToken,
        credential: {
          credentialId: cred.credential_id,
          publicKey: cred.public_key,
          counter: cred.sign_count,
          transports: cred.transports,
        },
        requireUserVerification: true,
      });
    } catch (vErr) {
      auditLog(cred.user_id, 'LOGIN_WEBAUTHN_FAILED', `err=${vErr.message}`, req.ip);
      return res.status(401).json({ error: 'passkey verification failed' });
    }
    if (!verification.verified) {
      auditLog(cred.user_id, 'LOGIN_WEBAUTHN_FAILED', 'not verified', req.ip);
      return res.status(401).json({ error: 'passkey verification failed' });
    }
    db.prepare("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = datetime('now') WHERE id = ?")
      .run(verification.newCounter != null ? verification.newCounter : cred.sign_count, cred.id);
    if (cred.is_passwordless !== 1) {
      auditLog(cred.user_id, 'LOGIN_WEBAUTHN_NOT_PASSWORDLESS', '', req.ip);
      return res.status(403).json({ error: 'this passkey is not enrolled for passwordless login' });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(cred.user_id);
    if (!user) return res.status(401).json({ error: 'user no longer exists' });
    return finishPasswordlessLogin(db, user, req, res, 'webauthn');
  } catch (err) {
    logger.error('Login-webauthn verify error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'Authentication error' });
  }
});

// ── POST /api/auth/break-glass — audited recovery ────────────────────────────
// Last-resort recovery when all admin authenticators are lost. The operator
// presents the one-time recovery credential minted at CA init (hash-only at
// rest). On success this issues a short-lived, single-purpose token authorizing
// the enrollment of ONE new admin authenticator — and nothing else: it is not a
// session and grants no data access (the cert/passkey enrollment endpoints honor
// this token's scope). Every attempt is audited; success is CRITICAL. The route
// is additionally rate-limited.
const breakglassLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many recovery attempts; try again later' },
});
router.post('/break-glass', breakglassLimiter, (req, res) => {
  try {
    const db = getDb();
    const credential = req.body && req.body.recovery_credential;
    if (!credential) return res.status(400).json({ error: 'recovery_credential required' });
    const ok = ca.verifyRecoveryCredential(db, credential);
    if (!ok) {
      auditLog(null, 'AUTH_BREAKGLASS_FAILED', 'invalid recovery credential', req.ip);
      return res.status(401).json({ error: 'invalid recovery credential' });
    }
    const token = jwt.sign(
      { purpose: 'breakglass', scope: 'enroll-admin-authenticator' },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: 600 }
    );
    auditLog(null, 'AUTH_BREAKGLASS_USED', 'recovery credential accepted; admin-authenticator enrollment authorized', req.ip);
    return res.json({
      breakglass_token: token,
      expires_in: 600,
      scope: 'enroll-admin-authenticator',
      message: 'Use this token to enroll one new admin authenticator (client certificate or passkey), then rotate the recovery credential.',
    });
  } catch (err) {
    logger.error('Break-glass error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'recovery error' });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
// B5b — Session-less credential enrollment (bootstrap + break-glass)
//
// A brand-new user (no credential yet) and a break-glass recovery operator both
// lack a session, and password login is off by default — so they cannot use the
// session-gated /api/mfa enrollment endpoints. These unauthenticated endpoints,
// mounted under /api/auth, let them enroll a FIRST passwordless passkey when they
// present a valid authorization token:
//
//   - an enrollment token (single-use, DB-backed, bound to a specific user),
//     minted by admin provisioning; or
//   - a break-glass token (short-lived signed token from /break-glass), which
//     targets an existing admin account to restore admin access.
//
// The passkey is always enrolled as a passwordless (discoverable, user-verified)
// login credential. Cert enrollment via these tokens is handled alongside the
// IAM cert-enrollment endpoints.
// ═══════════════════════════════════════════════════════════════════════════════

// Resolve the enrollment authorization carried in the request body to a target
// user. Returns { ok:true, userId, kind, tokenRow? } or { ok:false, status, error }.
function resolveEnrollmentAuth(db, body) {
  body = body || {};
  // Clock integrity: both authorization paths below trust time-based
  // validity (the enrollment token's SQL expiry check and the break-glass
  // token's signed expiry). Neither survives a VM snapshot rollback as a
  // defense, because a rollback restores the database too, so a used or
  // expired token can be revived. In virtualized mode a jumped clock cannot
  // be trusted to enforce expiry, so refuse session-less enrollment
  // authorization. Bare-metal is never gated.
  if (body.enrollment_token || body.breakglass_token) {
    const clock = checkClockIntegrity({ virtualized: isVirtualized(db) });
    if (!clock.ok) {
      auditLog(null, 'ENROLL_AUTH_CLOCK_UNTRUSTED', 'enrollment authorization refused: clock integrity check failed', null);
      return { ok: false, status: 503, error: 'server clock unverified; retry' };
    }
  }
  if (body.enrollment_token) {
    const hash = crypto.createHash('sha256').update(String(body.enrollment_token)).digest('hex');
    const row = db.prepare(`
      SELECT * FROM enrollment_tokens
      WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL
        AND expires_at > datetime('now')
    `).get(hash);
    if (!row) return { ok: false, status: 401, error: 'invalid or expired enrollment token' };
    return { ok: true, userId: row.user_id, kind: 'enrollment', tokenRow: row };
  }
  if (body.breakglass_token) {
    let decoded;
    try {
      decoded = jwt.verify(body.breakglass_token, JWT_SECRET, { algorithms: ['HS256'] });
    } catch (_) {
      return { ok: false, status: 401, error: 'invalid break-glass token' };
    }
    if (!decoded || decoded.purpose !== 'breakglass') {
      return { ok: false, status: 401, error: 'invalid break-glass token' };
    }
    if (!body.admin_username) {
      return { ok: false, status: 400, error: 'admin_username required for break-glass enrollment' };
    }
    const admin = db.prepare("SELECT * FROM users WHERE username = ? AND role = 'admin'").get(body.admin_username);
    if (!admin) return { ok: false, status: 404, error: 'admin user not found' };
    return { ok: true, userId: admin.id, kind: 'breakglass' };
  }
  return { ok: false, status: 400, error: 'enrollment_token or breakglass_token required' };
}

// ── POST /api/auth/enroll/passkey/options ───────────────────────────────────
// Begin first-passkey enrollment for a token-authorized user. The passkey is
// requested as a discoverable resident key with user verification required.
router.post('/enroll/passkey/options', async (req, res) => {
  try {
    const db = getDb();
    const auth = resolveEnrollmentAuth(db, req.body);
    if (!auth.ok) {
      if (auth.status === 401) auditLog(null, 'ENROLL_TOKEN_REJECTED', auth.error, req.ip);
      return res.status(auth.status).json({ error: auth.error });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(auth.userId);
    if (!user) return res.status(404).json({ error: 'user not found' });
    const rp = webauthn.getRpConfig(db);
    const existing = db.prepare(
      'SELECT credential_id AS credentialId, transports FROM webauthn_credentials WHERE user_id = ?'
    ).all(user.id);
    const { options, challengeToken } = await webauthn.beginRegistration({
      rp,
      userId: user.id,
      userName: user.name || user.username || user.id,
      existingCredentials: existing,
      residentKey: 'required',
      userVerification: 'required',
    });
    return res.json({ options, challengeToken });
  } catch (err) {
    logger.error('Enroll passkey options error', { error: err.message });
    return res.status(500).json({ error: 'could not start enrollment' });
  }
});

// ── POST /api/auth/enroll/passkey/verify ────────────────────────────────────
// Finish first-passkey enrollment. Verifies the attestation (user verification
// required), persists the credential as passwordless, and — for an enrollment
// token — consumes it (single-use). Break-glass enrollment is audited as a
// critical event.
router.post('/enroll/passkey/verify', async (req, res) => {
  try {
    const db = getDb();
    const auth = resolveEnrollmentAuth(db, req.body);
    if (!auth.ok) {
      if (auth.status === 401) auditLog(null, 'ENROLL_TOKEN_REJECTED', auth.error, req.ip);
      return res.status(auth.status).json({ error: auth.error });
    }
    const body = req.body || {};
    if (!body.response || !body.challengeToken) {
      return res.status(400).json({ error: 'response and challengeToken required' });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(auth.userId);
    if (!user) return res.status(404).json({ error: 'user not found' });
    const rp = webauthn.getRpConfig(db);
    let result;
    try {
      result = await webauthn.finishRegistration({
        rp,
        response: body.response,
        challengeToken: body.challengeToken,
        requireUserVerification: true,
      });
    } catch (vErr) {
      return res.status(400).json({ error: 'passkey verification failed', detail: vErr.message });
    }
    if (!result.verified || !result.credential) {
      return res.status(400).json({ error: 'passkey verification failed' });
    }
    const c = result.credential;
    try {
      db.prepare(`
        INSERT INTO webauthn_credentials
          (user_id, credential_id, public_key, sign_count, transports, aaguid, is_passwordless)
        VALUES (?, ?, ?, ?, ?, ?, 1)
      `).run(user.id, c.credentialId, c.publicKey, c.counter || 0, c.transports || null, c.aaguid || null);
    } catch (dbErr) {
      if (/UNIQUE|constraint/i.test(dbErr.message)) {
        return res.status(409).json({ error: 'this authenticator is already enrolled' });
      }
      throw dbErr;
    }
    if (auth.kind === 'enrollment' && auth.tokenRow) {
      db.prepare("UPDATE enrollment_tokens SET used_at = datetime('now') WHERE id = ?").run(auth.tokenRow.id);
      auditLog(user.id, 'ENROLL_PASSKEY_BOOTSTRAP', `cred=${String(c.credentialId).slice(0, 12)}…`, req.ip);
    } else if (auth.kind === 'breakglass') {
      auditLog(user.id, 'AUTH_BREAKGLASS_ENROLLED', `admin passkey cred=${String(c.credentialId).slice(0, 12)}…`, req.ip);
    }
    return res.status(201).json({ enrolled: true, passwordless: true, credential_id: c.credentialId });
  } catch (err) {
    logger.error('Enroll passkey verify error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'enrollment error' });
  }
});


// ── POST /api/auth/enroll/cert ──────────────────────────────────────────────
// Finish first-certificate enrollment for a token-authorized (or break-glass)
// user. Takes a client-generated CSR, signs it with the built-in CA — the
// asserted identity is bound by a server-controlled SAN, not the CSR's CN, so
// a client cannot self-assert another user's identity — records the result in
// issued_certs, and returns the signed certificate plus the CA chain. For an
// enrollment token the token is consumed (single-use); break-glass issuance is
// audited as a critical event. Synchronous: ca.issueClientCert shells out to
// openssl.
router.post('/enroll/cert', (req, res) => {
  try {
    const db = getDb();
    const auth = resolveEnrollmentAuth(db, req.body);
    if (!auth.ok) {
      if (auth.status === 401) auditLog(null, 'ENROLL_TOKEN_REJECTED', auth.error, req.ip);
      return res.status(auth.status).json({ error: auth.error });
    }
    const body = req.body || {};
    if (!body.csrPem || typeof body.csrPem !== 'string') {
      return res.status(400).json({ error: 'csrPem (PEM string) required' });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(auth.userId);
    if (!user) return res.status(404).json({ error: 'user not found' });

    let issued;
    try {
      issued = ca.issueClientCert(db, {
        csrPem: body.csrPem,
        userId: user.id,
        externalId: user.external_id || null,
      });
    } catch (cErr) {
      return res.status(400).json({ error: 'certificate issuance failed', detail: cErr.message });
    }

    if (auth.kind === 'enrollment' && auth.tokenRow) {
      db.prepare("UPDATE enrollment_tokens SET used_at = datetime('now') WHERE id = ?").run(auth.tokenRow.id);
      auditLog(user.id, 'ENROLL_CERT_BOOTSTRAP', `serial=${issued.serial} fp=${String(issued.fingerprint256).slice(0, 16)}…`, req.ip);
    } else if (auth.kind === 'breakglass') {
      auditLog(user.id, 'AUTH_BREAKGLASS_CERT_ENROLLED', `admin cert serial=${issued.serial}`, req.ip);
    }

    return res.status(201).json({
      enrolled: true,
      certPem: issued.certPem,
      serial: issued.serial,
      fingerprint256: issued.fingerprint256,
      caCertPem: issued.caCertPem,
    });
  } catch (err) {
    logger.error('Enroll cert error', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'enrollment error' });
  }
});

module.exports = router;

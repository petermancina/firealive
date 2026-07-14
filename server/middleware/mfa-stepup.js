// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Step-up MFA Middleware (WebAuthn)
//
// Wraps an individual route handler in a "must present a fresh,
// user-verified WebAuthn assertion" check, separate from login-time
// auth. Used to gate sensitive actions (config-lock toggle, restore
// approvals, foreign signing-key registration, audit-log purges, ...)
// so that even a hijacked session cannot perform them without live
// access to the user's authenticator — the operator re-proves the
// hardware credential at the moment of the action.
//
// This replaces the former TOTP / recovery-code step-up. TOTP is
// removed platform-wide; a phishable one-time code guarding the most
// sensitive operations was exactly backwards (the login path is already
// phishing-resistant). A fresh user-verified passkey assertion keeps the
// whole stack at AAL3.
//
// USAGE
//
//   const { mfaStepUp } = require('../middleware/mfa-stepup');
//   const { authMiddleware } = require('../middleware/auth');
//
//   router.post('/sensitive',
//     authMiddleware(['admin']),
//     mfaStepUp(),
//     handler);
//
// TWO-STEP PROTOCOL (the client fetches a challenge, signs it, then
// calls the sensitive route with the assertion):
//
//   1. POST /api/mfa/stepup/options   → { options, challengeToken }
//                                        (see routes/mfa.js)
//   2. navigator.credentials.get(options)   → assertion
//   3. POST <sensitive route>  with body.stepup = { challengeToken, response }
//
// MUST be applied AFTER an auth middleware that sets req.user. This file
// does NOT authenticate; it reads req.user.id and re-proves the
// credential the session belongs to.
//
// REQUEST CONTRACT
//
//   body.stepup = {
//     challengeToken: "<jwt issued by /api/mfa/stepup/options>",
//     response:       { <PublicKeyCredential assertion JSON> }
//   }
//
// RESPONSE ON SUCCESS
//
//   Calls next(). Sets req.mfaStepUp for downstream handlers and audit:
//     { method: 'webauthn', credentialId: <base64url credential id> }
//
// RESPONSE ON FAILURE
//
//   401 MFA_STEPUP_REQUIRED   no assertion supplied (client must fetch a
//                             challenge, sign it, and resend)
//   400 INVALID_INPUT         malformed body.stepup / assertion
//   401 STEPUP_FAILED         unknown or foreign credential, or the
//                             assertion failed verification (bad
//                             signature, wrong challenge/origin/RPID,
//                             user-verification not performed, expired or
//                             mismatched challenge token)
//   500 INTERNAL              middleware misconfigured / unexpected error
//
// AUDIT LOG
//
// The WebAuthn service is a pure primitive and does not log, so this
// middleware writes the operation-level audit row for every outcome
// (STEPUP_WEBAUTHN_OK / STEPUP_WEBAUTHN_FAILED). The global
// auditMiddleware in index.js still writes the HTTP-level entry, and the
// gated route records the action itself with req.mfaStepUp.method.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const webauthn = require('../services/webauthn');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('./audit');

// ── Middleware factory ───────────────────────────────────────────────────────

/**
 * Build a step-up MFA middleware that requires a fresh, user-verified
 * WebAuthn assertion from the acting user before the route handler runs.
 *
 * Takes no options: there is no recovery-code fallback (recovery codes
 * were a TOTP construct) and no relaxation knob — step-up is always a
 * live, user-verified assertion. Account-recovery / lockout is handled
 * by the audited break-glass flow, not by relaxing step-up.
 */
function mfaStepUp() {
  return async function mfaStepUpMiddleware(req, res, next) {
    // Auth must have run already and set req.user.
    if (!req.user || typeof req.user.id !== 'string') {
      logger.error('mfaStepUp invoked without upstream auth -- check route definition order');
      return res.status(500).json({
        error: 'mfa-stepup middleware misconfigured: no upstream auth',
        code: 'INTERNAL',
      });
    }

    // The assertion + its challenge token travel together in body.stepup,
    // namespaced so they never collide with the gated route's own body.
    const stepup = req.body && req.body.stepup;
    if (!stepup || typeof stepup !== 'object') {
      return res.status(401).json({
        error: 'MFA step-up required: obtain a challenge from /api/mfa/stepup/options, '
          + 'sign it with your passkey, and resend the assertion in body.stepup',
        code: 'MFA_STEPUP_REQUIRED',
        accepts: ['stepup'],
      });
    }

    const challengeToken = stepup.challengeToken;
    const response = stepup.response;
    if (typeof challengeToken !== 'string' || !challengeToken
      || !response || typeof response !== 'object') {
      return res.status(400).json({
        error: 'body.stepup must contain challengeToken (string) and response (assertion object)',
        code: 'INVALID_INPUT',
      });
    }

    const credId = response.id || response.rawId;
    if (!credId || typeof credId !== 'string') {
      return res.status(400).json({
        error: 'malformed assertion: missing credential id',
        code: 'INVALID_INPUT',
      });
    }

    const db = getDb();
    try {
      // The credential must exist, belong to the acting user, and be
      // enrolled for passwordless use. Scoping the lookup to req.user.id
      // is the DB-level ownership check; finishStepUp additionally binds
      // the challenge token's sub claim to the acting user, so a stolen
      // challenge minted for someone else cannot be replayed here.
      const cred = db.prepare(
        'SELECT * FROM webauthn_credentials WHERE credential_id = ? AND user_id = ? AND is_passwordless = 1'
      ).get(credId, req.user.id);
      if (!cred) {
        auditLog(req.user.id, 'STEPUP_WEBAUTHN_FAILED', 'unknown or foreign credential', req.ip);
        return res.status(401).json({ error: 'step-up failed', code: 'STEPUP_FAILED' });
      }

      const rp = webauthn.getRpConfig(db);
      let verification;
      try {
        verification = await webauthn.finishStepUp({
          rp,
          response,
          challengeToken,
          credential: {
            credentialId: cred.credential_id,
            publicKey: cred.public_key,
            counter: cred.sign_count,
            transports: cred.transports,
          },
          expectedUserId: req.user.id,
        });
      } catch (vErr) {
        auditLog(req.user.id, 'STEPUP_WEBAUTHN_FAILED', `err=${vErr.message}`, req.ip);
        return res.status(401).json({ error: 'step-up failed', code: 'STEPUP_FAILED' });
      }
      if (!verification.verified) {
        auditLog(req.user.id, 'STEPUP_WEBAUTHN_FAILED', 'not verified', req.ip);
        return res.status(401).json({ error: 'step-up failed', code: 'STEPUP_FAILED' });
      }

      // Persist the new signature counter (authenticator clone detection),
      // mirroring the login path.
      db.prepare("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = datetime('now') WHERE id = ?")
        .run(verification.newCounter != null ? verification.newCounter : cred.sign_count, cred.id);

      auditLog(req.user.id, 'STEPUP_WEBAUTHN_OK', `credentialId=${credId}`, req.ip);
      req.mfaStepUp = { method: 'webauthn', credentialId: credId };
      return next();
    } catch (err) {
      logger.error('mfaStepUp middleware error', {
        userId: req.user.id,
        error: err.message,
        stack: err.stack,
      });
      return res.status(500).json({ error: 'MFA verification error', code: 'INTERNAL' });
    } finally {
      try { db.close(); } catch (_) { /* ignore */ }
    }
  };
}

module.exports = { mfaStepUp };

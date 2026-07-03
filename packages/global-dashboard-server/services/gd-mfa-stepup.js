// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- Step-up MFA Middleware (WebAuthn)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// Wraps an individual route handler in a "must present a fresh, user-verified
// WebAuthn assertion" check, separate from login-time auth. Used to gate
// sensitive actions (config-baseline revert/import, restore approvals and
// execution, foreign signing-key registration, migration import) so that even a
// hijacked session cannot perform them without live access to the operator's
// authenticator -- the operator re-proves the hardware credential at the moment
// of the action. This is the GD twin of the Regional Server's step-up MFA
// middleware; a fresh user-verified passkey assertion keeps the stack at AAL3.
//
// USAGE
//   const { gdMfaStepUp } = require('../services/gd-mfa-stepup');
//   router.post('/sensitive', authMiddleware(['ciso']), gdMfaStepUp(), handler);
//
// TWO-STEP PROTOCOL (the client fetches a challenge, signs it, then calls the
// sensitive route with the assertion):
//   1. POST /api/mfa/stepup/options   -> { options, challengeToken }
//   2. navigator.credentials.get(options)   -> assertion
//   3. POST <sensitive route>  with body.stepup = { challengeToken, response }
//
// MUST be applied AFTER an auth middleware that sets req.user. This file does
// NOT authenticate; it reads req.user.id and re-proves the credential the
// session belongs to. finishStepUp additionally binds the challenge token's sub
// claim to the acting user, so a stolen challenge minted for someone else cannot
// be replayed here.
//
// RESPONSE ON SUCCESS  calls next(); sets req.mfaStepUp = { method: 'webauthn',
//   credentialId } for downstream handlers and audit.
// RESPONSE ON FAILURE  401 MFA_STEPUP_REQUIRED (no assertion) / 400 INVALID_INPUT
//   (malformed) / 401 STEPUP_FAILED (unknown or foreign credential, or the
//   assertion failed verification) / 500 INTERNAL. There is no relaxation knob
//   and no recovery-code fallback; account recovery is the audited break-glass
//   flow, not a relaxed step-up.
// -----------------------------------------------------------------------------

const gdWebauthn = require('./gd-webauthn');
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('./gd-audit-chain');

function auditBestEffort(db, req, eventType, detail, severity) {
  try {
    appendGdAuditEntry(db, {
      userId: req.user ? req.user.id : null,
      eventType: eventType,
      detail: detail,
      ip: req.ip,
      severity: severity || 'info',
    });
  } catch (_e) {
    // best-effort: never let an audit write failure change the auth outcome
  }
}

/**
 * Build a step-up MFA middleware that requires a fresh, user-verified WebAuthn
 * assertion from the acting user before the route handler runs. Takes no
 * options: step-up is always a live, user-verified assertion.
 */
function gdMfaStepUp() {
  return async function gdMfaStepUpMiddleware(req, res, next) {
    // Auth must have run already and set req.user.
    if (!req.user || typeof req.user.id !== 'string') {
      console.error('[gd-mfa-stepup] invoked without upstream auth -- check route definition order');
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
      // The credential must exist, belong to the acting user, and be enrolled
      // for passwordless use. Scoping the lookup to req.user.id is the DB-level
      // ownership check.
      const cred = db.prepare(
        'SELECT * FROM webauthn_credentials WHERE credential_id = ? AND user_id = ? AND is_passwordless = 1'
      ).get(credId, req.user.id);
      if (!cred) {
        auditBestEffort(db, req, 'STEPUP_WEBAUTHN_FAILED', 'unknown or foreign credential', 'warning');
        return res.status(401).json({ error: 'step-up failed', code: 'STEPUP_FAILED' });
      }

      const rp = gdWebauthn.getRpConfig(db);
      let verification;
      try {
        verification = await gdWebauthn.finishStepUp({
          rp: rp,
          response: response,
          challengeToken: challengeToken,
          credential: {
            credentialId: cred.credential_id,
            publicKey: cred.public_key,
            counter: cred.sign_count,
            transports: cred.transports,
          },
          expectedUserId: req.user.id,
        });
      } catch (vErr) {
        auditBestEffort(db, req, 'STEPUP_WEBAUTHN_FAILED', 'err=' + vErr.message, 'warning');
        return res.status(401).json({ error: 'step-up failed', code: 'STEPUP_FAILED' });
      }
      if (!verification.verified) {
        auditBestEffort(db, req, 'STEPUP_WEBAUTHN_FAILED', 'not verified', 'warning');
        return res.status(401).json({ error: 'step-up failed', code: 'STEPUP_FAILED' });
      }

      // Persist the new signature counter (authenticator clone detection),
      // mirroring the login path.
      db.prepare("UPDATE webauthn_credentials SET sign_count = ?, last_used_at = datetime('now') WHERE id = ?")
        .run(verification.newCounter != null ? verification.newCounter : cred.sign_count, cred.id);

      auditBestEffort(db, req, 'STEPUP_WEBAUTHN_OK', 'credentialId=' + credId, 'info');
      req.mfaStepUp = { method: 'webauthn', credentialId: credId };
      return next();
    } catch (err) {
      console.error('[gd-mfa-stepup] middleware error: ' + err.message);
      return res.status(500).json({ error: 'MFA verification error', code: 'INTERNAL' });
    } finally {
      try { db.close(); } catch (_e) { /* ignore */ }
    }
  };
}

module.exports = { gdMfaStepUp };

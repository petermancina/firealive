// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GD Push Signing Key Admin Routes (R3g PR3 Phase 5)
//
//   GET  /api/gd-signing-key         — read active key fingerprint + rotation
//                                      history (no private material exposed)
//   POST /api/gd-signing-key/rotate  — stage a new keypair locally, submit it
//                                      to the GD for CISO approval, advance
//                                      gd_push_config.handshake_status to
//                                      'pending_approval'. Promotion to the
//                                      active key happens later via C28's
//                                      push tick after the CISO approves.
//
// All endpoints are admin-only (mounted under authMiddleware(['admin']) in
// server/index.js). Establishing or changing the MC-to-GD trust channel
// is a security-significant action — operator-level, never analyst.
//
// PHASE 5 ROTATION SEMANTICS
//
// Pre-Phase-5 this route did a local atomic rotation: generated keypair,
// demoted prior, promoted new — all in one transaction. The GD trusted
// whatever the api_key-authenticated MC subsequently registered (the
// C12 design). Under Foundational Rule 22 (BUILD-PLAN-v18), the new
// key is not trusted by the GD until the CISO approves it on the GD
// side, so rotation can no longer complete in a single local
// transaction.
//
// The new flow this route implements:
//   1. stageNewPushKeypair(db) — insert new is_active=0 row locally.
//      The prior active key (if any) stays active and continues
//      signing pushes.
//   2. POST to <endpoint_url>/api/mc/<mc_id>/signing-key with the
//      api_key and the staged public key. The GD's C18 endpoint lands
//      it as approval_status='pending_approval'.
//   3. Update gd_push_config: handshake_status='pending_approval',
//      pending_signing_key_id=stagedId, last_handshake_at=now.
//   4. Return { status: 'pending_approval', stagedKeyId, fingerprint,
//      handshakeNote } to the operator. Promotion happens later via
//      the C28 push tick.
//
// Errors:
//   - Missing config (endpoint_url / api_key / mc_id) -> 400, no stage
//   - GD POST fails (network, 4xx, 5xx) -> rollback staged row,
//     surface GD's error code to the operator, leave gd_push_config
//     unchanged. Stage + rollback is a no-op from the operator's view
//     so the operator can retry without manual cleanup.
//   - Allow-list rejection -> 400, no stage (defense in depth)
//
// HISTORICAL KEYS ARE NEVER DELETED via this route. Once a staged row
// is promoted to is_active=1 (by the C28 tick) and later demoted on
// the next rotation, its row stays in gd_push_signing_keys with
// is_active=0 + rotated_out_at so historical audit records (and any
// in-flight pushes signed under the prior key during the brief
// rotation window) remain verifiable. There is no DELETE endpoint.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const signingKeysSvc = require('../services/gd-push-signing-keys');
// R3g PR3 Phase 5 (C26): outbound HTTP to the GD for submitting the
// staged signing key. Mirrors gd-push.js's outbound-call patterns:
// allow-list re-validation, AbortController timeout, redirect: 'error'.
const { openTier1 } = require('../services/tier1-seal');
const { validateAllowedHost } = require('../services/gd-allow-list');

const REQUEST_TIMEOUT_MS = 30000;

// ── GET /api/gd-signing-key ──────────────────────────────────────────────
//
// Returns:
//   {
//     active: null | {
//       id, fingerprint, createdAt, notes
//     },
//     history: [
//       { id, fingerprint, isActive, createdAt, rotatedOutAt, notes },
//       ...
//     ]                                  ordered newest first
//   }
//
// `active` is null until ensureActivePushKeypair runs (typically as part
// of the gd-config handshake, Commit 13). Operators inspecting a fresh
// install before configuring GD-push see active: null + history: [] —
// the correct empty-state.

router.get('/', (req, res) => {
  try {
    const db = getDb();

    const all = signingKeysSvc.listPushKeys(db);
    const active = all.find(k => k.isActive) || null;

    res.json({
      active: active
        ? {
            id: active.id,
            fingerprint: active.publicKeyFingerprint,
            createdAt: active.createdAt,
            notes: active.notes,
          }
        : null,
      history: all.map(k => ({
        id: k.id,
        fingerprint: k.publicKeyFingerprint,
        isActive: k.isActive,
        createdAt: k.createdAt,
        rotatedOutAt: k.rotatedOutAt,
        notes: k.notes,
      })),
    });
  } catch (err) {
    logger.error('gd-signing-key GET failed', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to read GD push signing keys' });
  }
});

// ── POST /api/gd-signing-key/rotate ──────────────────────────────────────
//
// Body (optional):
//   { notes: string }                    operator-supplied rotation reason
//                                        stored in the new row's notes
//                                        column. Defaults to "manual
//                                        rotation". 500-char limit at the
//                                        route layer; the DB column is
//                                        unbounded TEXT.
//
// Returns on success (202):
//   {
//     status: 'pending_approval',
//     stagedKeyId,
//     fingerprint,
//     handshakeNote: "Awaiting CISO approval on the GD side. The next
//                     push tick will poll for status and commit (or
//                     roll back) the staged keypair when the CISO
//                     decides."
//   }
//
// Returns on prerequisite failure (400):
//   { error: <human-readable message> }
//   - GD push not configured (no endpoint_url / api_key / mc_id)
//   - notes too long
//   - allow-list rejects the configured endpoint hostname
//
// Returns on GD-side rejection (403/409/etc, varies):
//   { error: <message>, code: <GD error code>, gdStatus: <HTTP status> }
//   The staged keypair has been rolled back; gd_push_config is unchanged.
//   The operator can fix the underlying issue and retry.
//
// Returns on GD network failure (502):
//   { error: 'Failed to submit signing key to GD', detail }
//   The staged keypair has been rolled back. Retry-safe.
//
// Audit events:
//   GD_PUSH_SIGNING_KEY_STAGED      severity=info,  on stage + submit
//                                   success (202 path)
//   GD_PUSH_SIGNING_KEY_STAGE_FAILED severity=warning, on any failure
//                                   path. Detail captures the stage
//                                   (prerequisite / allow-list / network /
//                                   gd-rejection) and reason.

const NOTES_MAX_LEN = 500;

router.post('/rotate', async (req, res) => {
  const rawNotes = (req.body && typeof req.body.notes === 'string')
    ? req.body.notes.trim()
    : '';

  if (rawNotes.length > NOTES_MAX_LEN) {
    auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED',
      `stage=validate reason=notes_too_long len=${rawNotes.length}`, req.ip);
    return res.status(400).json({
      error: `notes exceeds maximum length of ${NOTES_MAX_LEN} characters`,
    });
  }

  const notes = rawNotes || 'manual rotation';

  // ── 1. Read prerequisites from gd_push_config ─────────────────────────
  // We need endpoint_url, mc_id, and the encrypted api_key. All three must
  // be set before we can submit. If any is missing, fail early (no stage,
  // no DB write) so the operator gets a clean prerequisite error.
  let config;
  let apiKey;
  try {
    const db = getDb();
    try {
      config = db.prepare(`
        SELECT endpoint_url, api_key_encrypted, mc_id, handshake_status
        FROM gd_push_config WHERE id = 1
      `).get();
    } finally {
      db.close();
    }
  } catch (err) {
    logger.error('gd-signing-key rotate: config read failed', { error: err.message });
    return res.status(500).json({ error: 'Failed to read GD push configuration' });
  }

  if (!config) {
    auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED', 'stage=prereq reason=no_config_row', req.ip);
    return res.status(400).json({
      error: 'GD push is not configured (no gd_push_config row). Set endpoint_url, mc_id, and api_key via PUT /api/gd-config first.',
    });
  }
  if (!config.endpoint_url) {
    auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED', 'stage=prereq reason=missing_endpoint_url', req.ip);
    return res.status(400).json({ error: 'GD endpoint_url is not configured. Set it via PUT /api/gd-config first.' });
  }
  if (!config.mc_id) {
    auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED', 'stage=prereq reason=missing_mc_id', req.ip);
    return res.status(400).json({ error: 'mc_id is not configured. Set it via PUT /api/gd-config first.' });
  }
  if (!config.api_key_encrypted) {
    auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED', 'stage=prereq reason=missing_api_key', req.ip);
    return res.status(400).json({ error: 'api_key is not configured. Set it via PUT /api/gd-config first.' });
  }

  // Decrypt api_key once for the outbound submission. Never logged; never
  // included in response bodies; never persisted outside the encrypted
  // column it was read from.
  try {
    apiKey = openTier1('gd_push_config.api_key_encrypted', config.api_key_encrypted);
  } catch (err) {
    logger.error('gd-signing-key rotate: api_key decrypt failed', { error: err.message });
    auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED', 'stage=prereq reason=api_key_decrypt_failed', req.ip);
    return res.status(500).json({ error: 'Failed to decrypt stored api_key — check TIER1_ENCRYPTION_KEY env var' });
  }

  // ── 2. Build + validate the submission URL ────────────────────────────
  // Defense in depth: re-validate the stored endpoint's hostname against
  // GD_ALLOWED_HOSTS at submit time, NOT just at write-time
  // (gd-config.js's validateEndpointUrl gated PUT). Reasons mirror
  // gd-push.js's same check on the metrics push path: the DB row could
  // have been tampered with out of band, the allow-list could have been
  // tightened since the URL was stored, or gd_push_config could have
  // been seeded via an external migration that bypassed the route.
  const submitUrl = config.endpoint_url.replace(/\/+$/, '') + '/api/mc/' + encodeURIComponent(config.mc_id) + '/signing-key';
  let parsedUrl;
  try { parsedUrl = new URL(submitUrl); }
  catch (err) {
    auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED', `stage=prereq reason=invalid_url detail=${err.message}`, req.ip);
    return res.status(400).json({ error: 'Configured GD URL is malformed: ' + err.message });
  }
  const allowed = validateAllowedHost(parsedUrl.hostname);
  if (!allowed.ok) {
    auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED', `stage=allowlist reason=${allowed.error}`, req.ip);
    return res.status(400).json({ error: 'GD allow-list rejected hostname: ' + allowed.error });
  }

  // ── 3. Stage the new keypair locally ──────────────────────────────────
  let staged;
  try {
    const db = getDb();
    try {
      staged = signingKeysSvc.stageNewPushKeypair(db, { notes });
    } finally {
      db.close();
    }
  } catch (err) {
    logger.error('gd-signing-key rotate: stage failed', { error: err.message });
    auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED', `stage=local_stage reason=${err.message.slice(0, 200)}`, req.ip);
    return res.status(500).json({ error: 'Failed to stage new keypair' });
  }

  // ── 4. Submit the staged public key to the GD ─────────────────────────
  // On any failure of this step, the staged row is rolled back so the
  // operator can retry without manual cleanup.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let gdResp;
  let gdBody;
  try {
    try {
      gdResp = await fetch(submitUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          apiKey,
          public_key: staged.publicKeyPem,
          public_key_fingerprint: staged.publicKeyFingerprint,
        }),
        signal: controller.signal,
        // No redirects — defense against SSRF-via-redirect (a pre-approved
        // hostname returning a 302 to e.g. 169.254.169.254 metadata).
        redirect: 'error',
      });
      // Parse response body once; tolerant to non-JSON failures.
      const text = await gdResp.text();
      try { gdBody = JSON.parse(text); }
      catch { gdBody = { error: text.slice(0, 500) }; }
    } finally {
      clearTimeout(timeout);
    }
  } catch (netErr) {
    // Network-level failure (DNS, TCP, TLS, timeout, abort, redirect-blocked)
    rollbackAndAudit(req, staged, 'network', netErr.message);
    return res.status(502).json({
      error: 'Failed to submit signing key to GD',
      detail: netErr.message.slice(0, 200),
    });
  }

  if (!gdResp.ok) {
    // GD returned 4xx or 5xx. Treat as rejection: rollback + surface the
    // GD's error to the operator so they can act (e.g., 409 KEY_PREVIOUSLY_
    // REJECTED means the operator must investigate why the CISO rejected
    // an earlier attempt).
    rollbackAndAudit(req, staged, 'gd_rejection', `status=${gdResp.status} code=${gdBody?.code || 'unknown'}`);
    return res.status(gdResp.status >= 500 ? 502 : 400).json({
      error: gdBody?.error || 'GD rejected signing key submission',
      code: gdBody?.code,
      gdStatus: gdResp.status,
    });
  }

  // ── 5. Update gd_push_config to track the pending handshake ───────────
  try {
    const db = getDb();
    try {
      db.prepare(`
        UPDATE gd_push_config
        SET handshake_status = 'pending_approval',
            pending_signing_key_id = ?,
            last_handshake_at = datetime('now'),
            updated_at = datetime('now')
        WHERE id = 1
      `).run(staged.id);
    } finally {
      db.close();
    }
  } catch (err) {
    // Submission succeeded on the GD side but our local handshake-state
    // bookkeeping failed. The staged row stays — rolling it back would
    // leave the GD with an orphan pending submission. Log loudly so the
    // operator can fix gd_push_config manually if needed.
    logger.error('gd-signing-key rotate: post-submit config update failed', {
      error: err.message,
      stagedId: staged.id,
      gdAccepted: true,
    });
    auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED',
      `stage=post_submit_config_update stagedId=${staged.id} note=GD_ACCEPTED_BUT_LOCAL_BOOKKEEPING_FAILED reason=${err.message.slice(0, 200)}`, req.ip);
    // Don't roll back the staged row — it's been accepted by the GD.
    return res.status(500).json({
      error: 'Submission succeeded on GD but local state update failed; check gd_push_config row manually',
      stagedKeyId: staged.id,
      fingerprint: staged.publicKeyFingerprint,
    });
  }

  // ── 6. Success ────────────────────────────────────────────────────────
  auditLog(
    req.user.id,
    'GD_PUSH_SIGNING_KEY_STAGED',
    `stagedId=${staged.id} fingerprint=${staged.publicKeyFingerprint} gdStatus=${gdResp.status} notes=${JSON.stringify(notes)}`,
    req.ip,
  );
  return res.status(202).json({
    status: 'pending_approval',
    stagedKeyId: staged.id,
    fingerprint: staged.publicKeyFingerprint,
    handshakeNote: 'Awaiting CISO approval on the GD side. The next push tick will poll for status and commit (or roll back) the staged keypair when the CISO decides.',
  });
});

// Rollback the staged row when the GD submission fails. Best-effort:
// rollback errors are logged but don't change the response sent to the
// operator (the original failure is what they need to act on).
function rollbackAndAudit(req, staged, stage, reason) {
  try {
    const db = getDb();
    try {
      signingKeysSvc.rollbackStagedKeypair(db, staged.id);
    } finally {
      db.close();
    }
  } catch (rbErr) {
    logger.error('gd-signing-key rotate: rollback failed', {
      error: rbErr.message,
      stagedId: staged.id,
    });
  }
  auditLog(req.user.id, 'GD_PUSH_SIGNING_KEY_STAGE_FAILED',
    `stage=${stage} stagedId=${staged.id} fingerprint=${staged.publicKeyFingerprint} rolledBack=true reason=${reason.slice(0, 300)}`, req.ip);
}

module.exports = router;

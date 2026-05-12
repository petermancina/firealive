// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GD Push Signing Key Admin Routes (R3g PR3)
//
//   GET  /api/gd-signing-key         — read active key fingerprint + rotation
//                                      history (no private material exposed)
//   POST /api/gd-signing-key/rotate  — generate new keypair, demote prior
//                                      active key with rotated_out_at
//
// All endpoints are admin-only (mounted under authMiddleware(['admin']) in
// server/index.js). Establishing or changing the MC-to-GD trust channel
// is a security-significant action — operator-level, never analyst.
//
// Rotation is local-only: it creates a new active gd_push_signing_keys
// row and demotes the prior active row, but does NOT itself re-register
// the new public key with the GD. After rotating, the operator must
// re-save GD push configuration (PUT /api/gd-config) which triggers the
// handshake in Commit 13 to push the new public key to the GD's
// signing_keys trust registry. Until handshake completes, outbound
// pushes will be signed under a fingerprint the GD doesn't recognize
// and will be rejected — the GET response surfaces this state.
//
// HISTORICAL KEYS ARE NEVER DELETED. Rotated-out rows stay with
// is_active = 0 + rotated_out_at so historical audit records (and any
// in-flight pushes signed under the prior key during the brief
// rotation window) remain verifiable. There is no DELETE endpoint.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const signingKeysSvc = require('../services/gd-push-signing-keys');

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
// Returns:
//   {
//     newId,
//     newFingerprint,
//     oldId | null,
//     oldFingerprint | null,
//     handshakeRequired: true,
//     handshakeNote: "Re-save GD push configuration to register the new
//                    public key with the GD before the next push."
//   }
//
// If no active key existed at rotation time, oldId/oldFingerprint are
// null and the call effectively performs initial key generation.
//
// Audit: GD_PUSH_SIGNING_KEY_ROTATED with both fingerprints + notes so
// post-hoc forensic correlation can match this rotation to subsequent
// handshake events on the GD side (MC_SIGNING_KEY_REGISTERED in GD
// audit log).

const NOTES_MAX_LEN = 500;

router.post('/rotate', (req, res) => {
  const rawNotes = (req.body && typeof req.body.notes === 'string')
    ? req.body.notes.trim()
    : '';

  if (rawNotes.length > NOTES_MAX_LEN) {
    return res.status(400).json({
      error: `notes exceeds maximum length of ${NOTES_MAX_LEN} characters`,
    });
  }

  const notes = rawNotes || 'manual rotation';

  try {
    const db = getDb();
    const result = signingKeysSvc.rotatePushKeypair(db, { notes });

    auditLog(
      req.user.id,
      'GD_PUSH_SIGNING_KEY_ROTATED',
      `newId=${result.newId} newFingerprint=${result.newPublicKeyFingerprint} oldId=${result.oldId ?? 'none'} oldFingerprint=${result.oldPublicKeyFingerprint ?? 'none'} notes=${JSON.stringify(notes)}`,
      req.ip,
    );

    res.json({
      newId: result.newId,
      newFingerprint: result.newPublicKeyFingerprint,
      oldId: result.oldId,
      oldFingerprint: result.oldPublicKeyFingerprint,
      handshakeRequired: true,
      handshakeNote: 'Re-save GD push configuration (PUT /api/gd-config) to register the new public key with the GD before the next outbound push.',
    });
  } catch (err) {
    logger.error('gd-signing-key rotate failed', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to rotate GD push signing key' });
  }
});

module.exports = router;

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Signing Keys Admin Routes (R3d-5-pt2)
//
// Admin HTTP layer for the cross-deployment external-restore trust setup:
// register a foreign deployment's public Ed25519 key here so v3 manifests
// signed by that deployment can be verified, list all known keys
// (local-generated + external-registered), preview a fingerprint before
// committing, and revoke trust in a registered external key.
//
// All endpoints are admin-only (mounted under authMiddleware(['admin']) in
// server/index.js) -- establishing trust in a foreign signing key is a
// security-significant action and must be restricted to administrators.
//
//   GET    /                  list all keys (local + external)
//                             query: ?origin=local-generated|external-registered
//                                     to filter
//   POST   /validate          parse + sanity-check a pasted PEM, return its
//                             fingerprint without registering. The MC UI calls
//                             this to show the operator the fingerprint so
//                             they can confirm out-of-band before committing.
//                             Audit-trail neutral (no DB write).
//   POST   /                  register a foreign deployment's public key
//                             body: { public_key_pem, key_label?, notes? }
//                             Audit: BACKUP_SIGNING_KEY_REGISTERED
//   DELETE /:id               revoke trust in a registered external key
//                             (sets rotated_out_at, preserves audit trail)
//                             Refuses to revoke local-generated keys.
//                             Audit: BACKUP_SIGNING_KEY_REVOKED
//
// Service errors (signingKeysSvc.SigningKeyError) carry typed CODES that
// map to HTTP status:
//   INVALID_PEM, WRONG_KEY_TYPE, WRONG_KEY_USAGE, INVALID_INPUT  -> 400
//   KEY_NOT_FOUND                                                 -> 404
//   DUPLICATE_FINGERPRINT, NOT_EXTERNAL_KEY, ALREADY_REVOKED      -> 409
//   anything else                                                 -> 500 (logged)
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const signingKeysSvc = require('../services/backup-signing-keys');

// ── Error mapping ─────────────────────────────────────────────────────

function statusForSigningKeyError(err) {
  if (!err || !err.code) return 500;
  const C = signingKeysSvc.CODES;
  switch (err.code) {
    case C.INVALID_PEM:
    case C.WRONG_KEY_TYPE:
    case C.WRONG_KEY_USAGE:
    case C.INVALID_INPUT:
      return 400;
    case C.KEY_NOT_FOUND:
      return 404;
    case C.DUPLICATE_FINGERPRINT:
    case C.NOT_EXTERNAL_KEY:
    case C.ALREADY_REVOKED:
      return 409;
    default:
      return 500;
  }
}

function sendSigningKeyError(res, err, op) {
  if (err instanceof signingKeysSvc.SigningKeyError) {
    const status = statusForSigningKeyError(err);
    const body = { error: err.message, code: err.code };
    if (err.details && Object.keys(err.details).length) {
      body.details = err.details;
    }
    return res.status(status).json(body);
  }
  // Non-typed error: log full stack, return generic 500.
  logger.error(`backup-signing-keys ${op} unexpected error`, {
    error: err.message,
    stack: err.stack,
  });
  return res.status(500).json({ error: `Failed to ${op}` });
}

// ── List keys ─────────────────────────────────────────────────────────
//
// GET /api/backup-signing-keys
// GET /api/backup-signing-keys?origin=local-generated
// GET /api/backup-signing-keys?origin=external-registered
//
// Returns all keys with public-side metadata. Never includes private key
// material (the service layer doesn't even SELECT it for listing).

router.get('/', (req, res) => {
  const origin = typeof req.query.origin === 'string' ? req.query.origin : null;
  const db = getDb();
  try {
    const keys = signingKeysSvc.listKeys(db, origin ? { origin } : {});
    res.json({ keys });
  } catch (err) {
    return sendSigningKeyError(res, err, 'list signing keys');
  } finally {
    db.close();
  }
});

// ── Validate a pasted PEM (no DB write) ──────────────────────────────
//
// POST /api/backup-signing-keys/validate
// body: { public_key_pem }
//
// Parses + sanity-checks the pasted PEM and returns the fingerprint that
// would be stored if registered. The MC UI calls this when the operator
// pastes a foreign deployment's public key so the fingerprint can be
// shown for out-of-band confirmation BEFORE committing the registration.
// No audit log entry: this is a parse check, not a state change.

router.post('/validate', (req, res) => {
  const body = req.body || {};
  const { public_key_pem } = body;
  if (typeof public_key_pem !== 'string' || !public_key_pem.trim()) {
    return res.status(400).json({ error: 'public_key_pem is required' });
  }
  try {
    const { publicKeyFingerprint, publicKeyPem } = signingKeysSvc.validateExternalPublicKey(public_key_pem);
    res.json({
      ok: true,
      publicKeyFingerprint,
      publicKeyPem,
    });
  } catch (err) {
    return sendSigningKeyError(res, err, 'validate public key');
  }
});

// ── Register external key ────────────────────────────────────────────
//
// POST /api/backup-signing-keys
// body: {
//   public_key_pem  (string, required)  -- foreign deployment's pubkey
//   key_label       (string, optional)  -- operator-friendly description
//                                           (max 200 chars)
//   notes           (string, optional)
// }
//
// Inserts a new row with key_origin='external-registered',
// is_active=0, private_key_encrypted=NULL, registered_by_user_id=<caller>,
// registered_at=now. The service layer enforces validation (Ed25519,
// public-only, fingerprint not already registered).

router.post('/', (req, res) => {
  const body = req.body || {};
  const { public_key_pem, key_label, notes } = body;

  if (typeof public_key_pem !== 'string' || !public_key_pem.trim()) {
    return res.status(400).json({ error: 'public_key_pem is required' });
  }
  if (key_label !== undefined && key_label !== null) {
    if (typeof key_label !== 'string' || key_label.length > 200) {
      return res.status(400).json({ error: 'key_label must be a string up to 200 chars' });
    }
  }
  if (notes !== undefined && notes !== null && typeof notes !== 'string') {
    return res.status(400).json({ error: 'notes must be a string' });
  }

  const db = getDb();
  try {
    const result = signingKeysSvc.registerExternalKey(db, {
      publicKeyPem: public_key_pem,
      registeredByUserId: req.user.id,
      keyLabel: key_label || null,
      notes: notes || null,
    });
    auditLog(
      req.user.id,
      'BACKUP_SIGNING_KEY_REGISTERED',
      `id=${result.id} fingerprint=${result.publicKeyFingerprint} label=${JSON.stringify(key_label || '')}`,
      req.ip,
    );
    res.json({
      ok: true,
      id: result.id,
      publicKeyFingerprint: result.publicKeyFingerprint,
      registeredAt: result.registeredAt,
    });
  } catch (err) {
    return sendSigningKeyError(res, err, 'register external key');
  } finally {
    db.close();
  }
});

// ── Revoke external key ──────────────────────────────────────────────
//
// DELETE /api/backup-signing-keys/:id
//
// Sets rotated_out_at = now on an external-registered row. Refuses to
// revoke local-generated rows (rotation goes through a different code
// path). Refuses if already revoked. Preserves the audit trail
// (registered_by_user_id, registered_at, key_label remain) so a future
// audit can see who registered the key and who revoked it.

router.delete('/:id', (req, res) => {
  const idStr = req.params.id;
  const id = parseInt(idStr, 10);
  if (!Number.isInteger(id) || id < 1 || String(id) !== idStr) {
    return res.status(400).json({ error: 'id must be a positive integer' });
  }

  const db = getDb();
  try {
    const result = signingKeysSvc.revokeExternalKey(db, id);
    auditLog(
      req.user.id,
      'BACKUP_SIGNING_KEY_REVOKED',
      `id=${result.id} fingerprint=${result.publicKeyFingerprint}`,
      req.ip,
    );
    res.json({
      ok: true,
      id: result.id,
      publicKeyFingerprint: result.publicKeyFingerprint,
      rotatedOutAt: result.rotatedOutAt,
    });
  } catch (err) {
    return sendSigningKeyError(res, err, 'revoke external key');
  } finally {
    db.close();
  }
});

module.exports = router;

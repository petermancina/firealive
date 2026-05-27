// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Abuse-review public-key endpoints (multi-reviewer zero-access)
//
// The server stores and serves PUBLIC key material only. Flag content (peer,
// board, lead-chat) is sealed by the flagger's client to the active reviewer
// recipient set (the shared abuse-seal module's multi-recipient envelope)
// before it leaves the device, so the server holds only opaque ciphertext it
// cannot open. Each reviewer's PRIVATE key is generated on, and never leaves,
// that reviewer's own device.
//
// GET  /api/abuse-review-keys  — fetch ALL active public keys (the recipient
//                                set), so a flagger's client can seal to every
//                                reviewer at once. Returns { active:false,
//                                keys:[] } when none is registered, which keeps
//                                flagging disabled: with no key, nobody could
//                                decrypt a flag.
// POST /api/abuse-review-key   — register a public key, ADDING it to the active
//                                recipient set (admin-only). Does not retire
//                                existing keys; rejects a key whose fingerprint
//                                is already active. A label names the key for
//                                the admin UI; the fingerprint is derived
//                                server-side.
// POST /api/abuse-review-key/:id/revoke
//                              — remove a key from the active recipient set
//                                (admin-only). Sets active=0; flags sealed to
//                                other active reviewers stay openable by them.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const keysRouter = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// A crypto_box public key is 32 bytes (~44 base64 chars); cap generously without
// inviting abuse. Mirrors the e2ee-keys.js base64 validation.
const MAX_PUBKEY_B64 = 512;
function isB64(s, maxLen) {
  return typeof s === 'string' && s.length > 0 && s.length <= maxLen && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}

// GET — ALL active abuse-review public keys (the recipient set), newest first.
// A flagger's client seals to every key returned here at once, so adding a
// reviewer simply grows this list. Returns { active:false, keys:[] } when none.
keysRouter.get('/', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(
      'SELECT id, public_key, algo, label, fingerprint FROM abuse_review_keys WHERE active = 1 ORDER BY created_at DESC'
    ).all();
    db.close();
    return res.json({
      active: rows.length > 0,
      keys: rows.map((row) => ({
        id: row.id,
        publicKey: Buffer.from(row.public_key).toString('base64'),
        algo: row.algo,
        label: row.label || null,
        fingerprint: row.fingerprint || null,
      })),
    });
  } catch (err) {
    logger.error('Failed to read abuse-review keys', { error: err.message });
    return res.status(500).json({ error: 'failed to read abuse-review keys' });
  }
});

// POST — register a new abuse-review PUBLIC key, ADDING it to the active recipient
// set (admin-only for now). Does NOT retire existing keys: each active key is one
// independent reviewer and content is sealed to all of them. A label names the key
// for the admin UI; the fingerprint is derived server-side and used to reject a key
// already in the active set.
router.post('/', (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { publicKey, algo, label } = req.body || {};
  if (!isB64(publicKey, MAX_PUBKEY_B64)) {
    return res.status(400).json({ error: 'publicKey (base64) required' });
  }
  const algoVal = (typeof algo === 'string' && algo.length > 0 && algo.length <= 64) ? algo : 'crypto_box_seal';
  const labelVal = (typeof label === 'string' && label.trim().length > 0) ? label.trim().slice(0, 120) : null;

  // 8-byte fingerprint of the SPKI-DER public key (hex). Matches abuse-seal's
  // fingerprintForPubB64, so a key's fingerprint here equals the slot tag used
  // when sealing to it.
  const fingerprint = crypto.createHash('sha256').update(Buffer.from(publicKey, 'base64')).digest().subarray(0, 8).toString('hex');

  const keyId = crypto.randomBytes(16).toString('hex');
  try {
    const db = getDb();
    const dup = db.prepare('SELECT 1 FROM abuse_review_keys WHERE active = 1 AND fingerprint = ?').get(fingerprint);
    if (dup) {
      db.close();
      return res.status(409).json({ error: 'a key with this fingerprint is already active' });
    }
    db.prepare(
      'INSERT INTO abuse_review_keys (id, public_key, algo, label, fingerprint, registered_by, active) VALUES (?, ?, ?, ?, ?, ?, 1)'
    ).run(keyId, Buffer.from(publicKey, 'base64'), algoVal, labelVal, fingerprint, req.user.id);
    db.close();
  } catch (err) {
    logger.error('Failed to register abuse-review key', { error: err.message });
    return res.status(500).json({ error: 'failed to register abuse-review key' });
  }

  // Audit metadata only -- the key is public; record who added it and which key.
  auditLog(req.user.id, 'ABUSE_REVIEW_KEY_REGISTERED', `key ${keyId}, fp ${fingerprint}, algo ${algoVal}`, req.ip);

  return res.status(201).json({ id: keyId, algo: algoVal, label: labelVal, fingerprint, active: true });
});

// POST /:id/revoke — remove a key from the active recipient set (admin-only). Sets
// active=0 so no new flags seal to it; flags already sealed to other active
// reviewers stay openable by them. Returns 404 when no active key has that id
// (unknown or already revoked), so the action is safe to retry.
router.post('/:id/revoke', (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  const { id } = req.params;
  if (typeof id !== 'string' || id.length === 0 || id.length > 64) {
    return res.status(400).json({ error: 'valid key id required' });
  }

  let changed = 0;
  try {
    const db = getDb();
    const info = db.prepare('UPDATE abuse_review_keys SET active = 0 WHERE id = ? AND active = 1').run(id);
    changed = info.changes;
    db.close();
  } catch (err) {
    logger.error('Failed to revoke abuse-review key', { error: err.message });
    return res.status(500).json({ error: 'failed to revoke abuse-review key' });
  }

  if (changed === 0) {
    return res.status(404).json({ error: 'no active key with that id' });
  }

  // Audit metadata only -- the key is public; record who revoked which key.
  auditLog(req.user.id, 'ABUSE_REVIEW_KEY_REVOKED', `key ${id}`, req.ip);

  return res.json({ id, active: false, revoked: true });
});

module.exports = router;
module.exports.keysRouter = keysRouter;

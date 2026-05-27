// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Abuse-review public-key endpoint (U3 PR D, Model B)
//
// The server stores and serves PUBLIC key material only. Flag content (peer,
// board, lead-chat) is sealed to this public key by the flagger's client
// (libsodium crypto_box_seal) before it leaves the device, so the server holds
// only opaque ciphertext it cannot open. The matching PRIVATE key lives solely
// in the Abuse Review Console and is never sent here.
//
// GET  /api/abuse-review-key   — fetch the active public key (so a flagger's
//                                client can seal to it). Returns { active:false,
//                                key:null } when none is registered, which keeps
//                                flagging disabled: with no key, nobody could
//                                decrypt a flag. Kept for back-compat (single key).
// GET  /api/abuse-review-keys  — fetch ALL active public keys (the recipient
//                                set), so a flagger's client can seal to every
//                                reviewer at once. Returns { active:false,
//                                keys:[] } when none is registered.
// POST /api/abuse-review-key   — register a new active public key. Admin-only
//                                here; in PR F the Abuse Review Console
//                                (abuse_reviewer) registers the key it generates
//                                on first run, and this guard/mount is extended
//                                to include that role. Registering deactivates
//                                any prior active key (single active key).
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

// GET — the active abuse-review public key, or { active:false } if none.
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare(
      'SELECT id, public_key, algo FROM abuse_review_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1'
    ).get();
    db.close();
    if (!row) {
      return res.json({ active: false, key: null });
    }
    return res.json({
      active: true,
      key: {
        id: row.id,
        publicKey: Buffer.from(row.public_key).toString('base64'),
        algo: row.algo,
      },
    });
  } catch (err) {
    logger.error('Failed to read abuse-review key', { error: err.message });
    return res.status(500).json({ error: 'failed to read abuse-review key' });
  }
});

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

// POST — register a new active abuse-review PUBLIC key (admin-only for now).
router.post('/', (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { publicKey, algo } = req.body || {};
  if (!isB64(publicKey, MAX_PUBKEY_B64)) {
    return res.status(400).json({ error: 'publicKey (base64) required' });
  }
  const algoVal = (typeof algo === 'string' && algo.length > 0 && algo.length <= 64) ? algo : 'crypto_box_seal';

  const keyId = crypto.randomBytes(16).toString('hex');
  try {
    const db = getDb();
    const register = db.transaction(() => {
      // Single active key: retire any current one, then add the new active key.
      db.prepare('UPDATE abuse_review_keys SET active = 0 WHERE active = 1').run();
      db.prepare(
        'INSERT INTO abuse_review_keys (id, public_key, algo, registered_by, active) VALUES (?, ?, ?, ?, 1)'
      ).run(keyId, Buffer.from(publicKey, 'base64'), algoVal, req.user.id);
    });
    register();
    db.close();
  } catch (err) {
    logger.error('Failed to register abuse-review key', { error: err.message });
    return res.status(500).json({ error: 'failed to register abuse-review key' });
  }

  // Audit metadata only -- the key is public, but record who registered it.
  auditLog(req.user.id, 'ABUSE_REVIEW_KEY_REGISTERED', `key ${keyId}, algo ${algoVal}`, req.ip);

  return res.status(201).json({ id: keyId, algo: algoVal, active: true });
});

module.exports = router;
module.exports.keysRouter = keysRouter;

// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — MC Device-Key Registration (D24)
//
// Registers (and rotates) the hardware device-signing public key for the
// Management Console operator making the call. The MC binds privileged,
// destructive recovery actions to a signature from this key, so the server
// must hold a trustworthy copy of each operator's active public key to
// verify those action proofs (the verifier lives alongside the destructive
// routes). Keys are ECDSA P-256 public keys minted in the operator's
// hardware (TPM 2.0 / Secure Enclave) and exported as SPKI PEM; the private
// half never leaves the device.
//
// Like the GD registration path, the server recomputes the fingerprint from
// the submitted public key and refuses any client-asserted value that does
// not match, so the stored fingerprint provably identifies the stored key.
// At most one key is active per operator (DB-enforced); registering a new
// key retires the prior one in a single transaction.
//
// Endpoints (mounted at /api/mc-device-key; lead/admin):
//   POST /register   register or rotate the calling operator's device key
// ═══════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

// POST /register ────────────────────────────────────────────────────────────
router.post('/register', (req, res) => {
  const { publicKey, fingerprint } = req.body || {};
  if (typeof publicKey !== 'string' || !publicKey || typeof fingerprint !== 'string' || !fingerprint) {
    return res.status(400).json({ error: 'publicKey and fingerprint required' });
  }
  if (!/-----BEGIN PUBLIC KEY-----/.test(publicKey) || !/^[a-f0-9]{64}$/.test(fingerprint)) {
    return res.status(400).json({ error: 'invalid key material' });
  }
  // Recompute the fingerprint server-side (sha256 of the SPKI DER, the house
  // format) and require it to match, so the stored fingerprint provably binds
  // the registered key rather than trusting a client-asserted label.
  let computed;
  try {
    const der = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
    computed = crypto.createHash('sha256').update(der).digest('hex');
  } catch (_) {
    return res.status(400).json({ error: 'unparseable public key' });
  }
  if (computed !== fingerprint) {
    return res.status(400).json({ error: 'fingerprint does not match public key' });
  }
  const db = getDb();
  try {
    const uid = req.user.id;
    const existing = db.prepare("SELECT id, public_key FROM mc_device_signing_keys WHERE user_id = ? AND active = 1").get(uid);
    if (existing && existing.public_key === publicKey) {
      return res.json({ ok: true, rotated: false });
    }
    const rotate = db.transaction(() => {
      db.prepare("UPDATE mc_device_signing_keys SET active = 0, retired_at = datetime('now') WHERE user_id = ? AND active = 1").run(uid);
      db.prepare("INSERT INTO mc_device_signing_keys (user_id, public_key, fingerprint) VALUES (?, ?, ?)").run(uid, publicKey, fingerprint);
    });
    rotate();
    res.json({ ok: true, rotated: !!existing });
  } catch (err) {
    logger.error('mc device-key registration failed', { error: err.message });
    res.status(500).json({ error: 'registration failed' });
  } finally {
    db.close();
  }
});

module.exports = router;

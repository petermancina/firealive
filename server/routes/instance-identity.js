// ══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Instance Identity Routes (anti-cloning, D25)
// POST /api/instance/anchor-challenge — sign a client nonce with the hardware
//   instance anchor so a client can verify it is talking to the authentic (non-
//   cloned) deployment and refuse a clone that cannot unseal the anchor.
// ══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const instanceAnchor = require('../services/instance-anchor');
const { getDb } = require('../db/init');

// Domain-separation prefix: an anchor signature produced for this challenge can
// never be reused as a signature in any other anchor context (and vice versa).
const ANCHOR_CHALLENGE_PREFIX = 'firealive-instance-anchor-challenge-v1:';
const NONCE_MIN_BYTES = 16;
const NONCE_MAX_BYTES = 128;

// POST /api/instance/anchor-challenge
// The client sends a fresh random nonce; the server signs <prefix || nonce> with
// its hardware instance anchor (ECDSA P-256, raw r||s) and returns the signature
// together with the anchor fingerprint and SPKI public key. A perfect clone holds
// the same database and CA but cannot unseal the anchor private key on different
// hardware, so it cannot produce a valid signature over the client's fresh nonce
// -> the client refuses it as a possible cloned server (D25). This is the mirror
// of the client -> server device-key gate (D20) and is GD-independent.
router.post('/anchor-challenge', function (req, res) {
  const nonce = req.body && req.body.nonce;
  if (!nonce || typeof nonce !== 'string') {
    return res.status(400).json({ error: 'nonce required' });
  }
  const nonceBuf = Buffer.from(nonce, 'base64');
  if (nonceBuf.length < NONCE_MIN_BYTES || nonceBuf.length > NONCE_MAX_BYTES) {
    return res.status(400).json({ error: 'nonce must decode to 16-128 bytes' });
  }
  const db = getDb();
  try {
    const identity = instanceAnchor.load({ db: db });
    if (!identity) {
      return res.status(503).json({ error: 'instance identity not established' });
    }
    const message = Buffer.from(ANCHOR_CHALLENGE_PREFIX + nonce, 'utf8');
    const signature = instanceAnchor.sign({ db: db, identity: identity, data: message });
    if (!signature || !Buffer.isBuffer(signature) || signature.length === 0) {
      return res.status(503).json({ error: 'instance anchor unavailable' });
    }
    return res.json({
      instanceId: identity.instanceId,
      fingerprint: identity.fingerprint,
      publicKey: identity.publicKey,
      signature: Buffer.from(signature).toString('base64'),
      alg: 'ecdsa-p256-ieee-p1363'
    });
  } catch (e) {
    return res.status(500).json({ error: 'anchor challenge failed' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

module.exports = router;

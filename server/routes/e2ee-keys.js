// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Signal-protocol pre-key bundle routes (X3DH / PQXDH)
//
// The server stores PUBLIC key material only and is content-blind. Private keys
// and Double-Ratchet state never leave the client (Electron main, sealed).
//
// POST /api/e2ee/publish          — publish/replace the caller's bundle (a domain)
// POST /api/e2ee/prekeys          — replenish the caller's one-time pre-keys
// GET  /api/e2ee/count            — how many one-time pre-keys remain (a domain)
// GET  /api/e2ee/bundle/:userId   — fetch+consume a bundle (lead domain only;
//                                   peer bundles are fetched session-scoped via
//                                   peers.js to preserve analyst anonymity)
//
// Bundles are namespaced by (user_id, domain), domain IN ('peer','lead').
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

const DOMAINS = ['peer', 'lead'];

// Generous caps: EC keys/signatures are tiny (~33/64 bytes); a Kyber public key
// is ~1.5KB (~2KB base64). 8192 chars leaves headroom without inviting abuse.
function isB64(s, maxLen) {
  return typeof s === 'string' && s.length > 0 && s.length <= maxLen && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}
function validKeyObj(o) {
  return o && typeof o === 'object'
    && Number.isInteger(o.id) && o.id >= 0
    && isB64(o.publicKey, 8192) && isB64(o.signature, 1024);
}

// Reusable bundle fetch. Selects the public bundle for (userId, domain) and
// atomically consumes one available one-time pre-key (or returns null for it
// when the supply is depleted — PreKeyBundle tolerates a null one-time key).
// Returns the JSON shape the client wrapper's processPeerBundle expects, or
// null if the user has no (complete) bundle published in that domain.
// The caller owns the db handle (open/close).
function consumeBundleForUser(db, userId, domain) {
  const tx = db.transaction((uid, dom) => {
    const identity = db.prepare(
      'SELECT identity_pubkey, registration_id FROM e2ee_identity_keys WHERE user_id = ? AND domain = ?'
    ).get(uid, dom);
    if (!identity) return null;

    const signed = db.prepare(
      "SELECT key_id, pubkey, signature FROM e2ee_signed_prekeys WHERE user_id = ? AND domain = ? AND kind = 'signed'"
    ).get(uid, dom);
    const kyber = db.prepare(
      "SELECT key_id, pubkey, signature FROM e2ee_signed_prekeys WHERE user_id = ? AND domain = ? AND kind = 'kyber'"
    ).get(uid, dom);
    if (!signed || !kyber) return null; // incomplete bundle

    const otp = db.prepare(
      'SELECT key_id, pubkey FROM e2ee_one_time_prekeys WHERE user_id = ? AND domain = ? AND consumed_at IS NULL ORDER BY key_id LIMIT 1'
    ).get(uid, dom);
    if (otp) {
      db.prepare(
        "UPDATE e2ee_one_time_prekeys SET consumed_at = datetime('now') WHERE user_id = ? AND domain = ? AND key_id = ?"
      ).run(uid, dom, otp.key_id);
    }
    return { identity, signed, kyber, otp };
  });

  const r = tx(userId, domain);
  if (!r) return null;

  return {
    registrationId: r.identity.registration_id,
    deviceId: 1, // single-device model
    identityKey: Buffer.from(r.identity.identity_pubkey).toString('base64'),
    signedPreKey: {
      id: r.signed.key_id,
      publicKey: Buffer.from(r.signed.pubkey).toString('base64'),
      signature: Buffer.from(r.signed.signature).toString('base64'),
    },
    kyberPreKey: {
      id: r.kyber.key_id,
      publicKey: Buffer.from(r.kyber.pubkey).toString('base64'),
      signature: Buffer.from(r.kyber.signature).toString('base64'),
    },
    oneTimePreKey: r.otp
      ? { id: r.otp.key_id, publicKey: Buffer.from(r.otp.pubkey).toString('base64') }
      : null,
  };
}

// ── Publish / replace the caller's bundle for one domain ─────────────────────
router.post('/publish', (req, res) => {
  const { domain, identityKey, registrationId, signedPreKey, kyberPreKey, oneTimePreKeys } = req.body || {};

  if (!DOMAINS.includes(domain)) {
    return res.status(400).json({ error: "domain must be 'peer' or 'lead'" });
  }
  if (!isB64(identityKey, 8192) || !Number.isInteger(registrationId)) {
    return res.status(400).json({ error: 'identityKey (base64) and integer registrationId required' });
  }
  if (!validKeyObj(signedPreKey) || !validKeyObj(kyberPreKey)) {
    return res.status(400).json({ error: 'signedPreKey and kyberPreKey {id, publicKey, signature} required' });
  }
  if (!Array.isArray(oneTimePreKeys) || oneTimePreKeys.length > 200
      || !oneTimePreKeys.every((k) => k && Number.isInteger(k.id) && isB64(k.publicKey, 8192))) {
    return res.status(400).json({ error: 'oneTimePreKeys must be an array (max 200) of {id, publicKey}' });
  }

  try {
    const db = getDb();
    const uid = req.user.id;
    const publish = db.transaction(() => {
      db.prepare(
        'INSERT OR REPLACE INTO e2ee_identity_keys (user_id, domain, identity_pubkey, registration_id) VALUES (?, ?, ?, ?)'
      ).run(uid, domain, Buffer.from(identityKey, 'base64'), registrationId);

      db.prepare(
        "INSERT OR REPLACE INTO e2ee_signed_prekeys (user_id, domain, kind, key_id, pubkey, signature) VALUES (?, ?, 'signed', ?, ?, ?)"
      ).run(uid, domain, signedPreKey.id, Buffer.from(signedPreKey.publicKey, 'base64'), Buffer.from(signedPreKey.signature, 'base64'));

      db.prepare(
        "INSERT OR REPLACE INTO e2ee_signed_prekeys (user_id, domain, kind, key_id, pubkey, signature) VALUES (?, ?, 'kyber', ?, ?, ?)"
      ).run(uid, domain, kyberPreKey.id, Buffer.from(kyberPreKey.publicKey, 'base64'), Buffer.from(kyberPreKey.signature, 'base64'));

      const insOtp = db.prepare(
        'INSERT OR IGNORE INTO e2ee_one_time_prekeys (user_id, domain, key_id, pubkey) VALUES (?, ?, ?, ?)'
      );
      for (const k of oneTimePreKeys) {
        insOtp.run(uid, domain, k.id, Buffer.from(k.publicKey, 'base64'));
      }
    });
    publish();
    db.close();

    auditLog(req.user.id, 'E2EE_BUNDLE_PUBLISHED', `domain=${domain}`, req.ip);
    res.status(201).json({ ok: true });
  } catch (err) {
    logger.error('Publish bundle error', { error: err.message });
    res.status(500).json({ error: 'Failed to publish pre-key bundle' });
  }
});

// ── Replenish the caller's one-time pre-keys ─────────────────────────────────
router.post('/prekeys', (req, res) => {
  const { domain, oneTimePreKeys } = req.body || {};
  if (!DOMAINS.includes(domain)) {
    return res.status(400).json({ error: "domain must be 'peer' or 'lead'" });
  }
  if (!Array.isArray(oneTimePreKeys) || oneTimePreKeys.length === 0 || oneTimePreKeys.length > 200
      || !oneTimePreKeys.every((k) => k && Number.isInteger(k.id) && isB64(k.publicKey, 8192))) {
    return res.status(400).json({ error: 'oneTimePreKeys must be a non-empty array (max 200) of {id, publicKey}' });
  }

  try {
    const db = getDb();
    const uid = req.user.id;
    const insOtp = db.prepare(
      'INSERT OR IGNORE INTO e2ee_one_time_prekeys (user_id, domain, key_id, pubkey) VALUES (?, ?, ?, ?)'
    );
    const add = db.transaction(() => {
      for (const k of oneTimePreKeys) insOtp.run(uid, domain, k.id, Buffer.from(k.publicKey, 'base64'));
    });
    add();
    db.close();

    auditLog(req.user.id, 'E2EE_PREKEYS_REPLENISHED', `domain=${domain} count=${oneTimePreKeys.length}`, req.ip);
    res.status(201).json({ ok: true });
  } catch (err) {
    logger.error('Replenish prekeys error', { error: err.message });
    res.status(500).json({ error: 'Failed to replenish one-time pre-keys' });
  }
});

// ── Remaining one-time pre-key count (so the client knows when to replenish) ──
router.get('/count', (req, res) => {
  const domain = req.query.domain;
  if (!DOMAINS.includes(domain)) {
    return res.status(400).json({ error: "domain query param must be 'peer' or 'lead'" });
  }
  try {
    const db = getDb();
    const row = db.prepare(
      'SELECT COUNT(*) AS available FROM e2ee_one_time_prekeys WHERE user_id = ? AND domain = ? AND consumed_at IS NULL'
    ).get(req.user.id, domain);
    db.close();
    res.json({ available: row.available });
  } catch (err) {
    logger.error('Prekey count error', { error: err.message });
    res.status(500).json({ error: 'Failed to count one-time pre-keys' });
  }
});

// ── Fetch + consume a bundle (LEAD domain only) ──────────────────────────────
// Peer-domain bundles are NOT fetchable by user id — that would reveal analyst
// identity. Peer chat fetches a bundle session-scoped via peers.js (B10), which
// reuses consumeBundleForUser after resolving the counterpart from the session.
router.get('/bundle/:userId', (req, res) => {
  const domain = req.query.domain;
  if (domain !== 'lead') {
    return res.status(400).json({ error: "by-user bundle fetch is restricted to domain='lead'; peer bundles are session-scoped" });
  }
  try {
    const db = getDb();
    const bundle = consumeBundleForUser(db, req.params.userId, domain);
    db.close();
    if (!bundle) return res.status(404).json({ error: 'No bundle published for that user in this domain' });
    auditLog(req.user.id, 'E2EE_BUNDLE_FETCHED', `domain=${domain}`, req.ip);
    res.json({ bundle });
  } catch (err) {
    logger.error('Fetch bundle error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch pre-key bundle' });
  }
});

module.exports = router;
module.exports.consumeBundleForUser = consumeBundleForUser;

// FIREALIVE GLOBAL DASHBOARD -- HA replication key-agreement (B6d)
//
// The GD twin of server/services/ha/ha-keys.js. Active/passive HA needs the
// passive to read the active's Tier-1-encrypted columns and validate its
// JWT_SECRET-signed sessions AFTER it promotes -- but the GD Tier-1 KEK is sealed
// to each node's own hardware (gd-tier1-kek.js: "a copied disk cannot unseal it"),
// so the pair cannot simply share a sealed KEK. The decided design (B5o pre-flight,
// Q1.b, and the B6d PR-1 sealed-KEK foundation) is anchor-to-anchor key-agreement:
// each node holds a purpose-built X25519 key-agreement keypair whose PUBLIC key is
// signed by the GD hardware anchor (binding it to that hardware identity), and
// whose PRIVATE key is sealed to local hardware. At pairing the active wraps the
// shared Tier-1 material (the raw KEK + JWT_SECRET bundle) to the passive's X25519
// public key via ephemeral-static ECDH; the passive stores the wrapped blob and
// unwraps it ONLY at promotion, with its own hardware. This preserves the anti-
// clone guarantee for every non-paired deployment: no raw KEK is ever shared, and
// the wrapped blob is opaque without the passive's sealed key.
//
// The GD hardware anchor key (gd-instance-anchor.js) is sign-only (ECDSA P-256,
// IEEE P1363 over SHA-256); it cannot perform ECDH/decrypt itself, which is
// exactly why a separate X25519 key authenticated by an anchor signature does the
// wrapping. The X25519 private key is sealed under a key HKDF-derived from the
// GD's local hardware-sealed Tier-1 KEK (domain-separated), so it is recoverable
// only on this hardware.
//
// All secrets are passed as Buffers; nothing is logged. ASCII-only strings; no
// template literals (backend discipline).

const crypto = require('crypto');
const anchor = require('./gd-instance-anchor');
const tier1 = require('./gd-tier1-kek');

const HKDF_LEN = 32;
const WRAP_SEAL_INFO = 'firealive-gd-ha-wrapkey-seal-v1'; // derive the X25519-private-key sealing key from the GD Tier-1 KEK
const WRAP_SEAL_SALT = 'firealive-gd-ha-wrapkey-seal-salt-v1';
const KEK_WRAP_INFO = 'firealive-gd-ha-kek-wrap-v1';      // derive the ECDH KEK-wrapping key
const ENVELOPE_VERSION = 1;

// ---------------------------------------------------------------------------
// Local hardware sealing (AES-256-GCM under a key derived from the Tier-1 KEK).
// resolveTier1Kek() fails closed unless the KEK can be unsealed on this hardware,
// so anything sealed here is recoverable only on this node.
// ---------------------------------------------------------------------------

function localSealKey() {
  const kek = tier1.resolveTier1Kek(); // 32-byte Buffer; throws if not unsealable on this hardware
  return Buffer.from(
    crypto.hkdfSync('sha256', kek, Buffer.from(WRAP_SEAL_SALT), Buffer.from(WRAP_SEAL_INFO), HKDF_LEN)
  );
}

// Seal arbitrary secret bytes to THIS hardware. Returns a base64 JSON envelope.
function sealToHardware(secretBuf) {
  if (!Buffer.isBuffer(secretBuf)) {
    throw new Error('gd-ha-keys.sealToHardware: secret must be a Buffer');
  }
  const key = localSealKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(secretBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  const env = {
    v: ENVELOPE_VERSION,
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: tag.toString('base64'),
  };
  return Buffer.from(JSON.stringify(env)).toString('base64');
}

// Unseal bytes sealed by sealToHardware on THIS hardware.
function unsealFromHardware(sealedB64) {
  const env = JSON.parse(Buffer.from(String(sealedB64), 'base64').toString('utf8'));
  const key = localSealKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(env.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(env.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(env.ct, 'base64')), decipher.final()]);
}

// ---------------------------------------------------------------------------
// gd_ha_node 'self' row + the local X25519 wrap keypair.
// ---------------------------------------------------------------------------

function ensureSelfRow(db) {
  db.prepare("INSERT OR IGNORE INTO gd_ha_node (id) VALUES ('self')").run();
}

// Ensure this node has an X25519 key-agreement keypair, the anchor signature
// binding its public key to this hardware identity, and its gd_ha_node row.
// Idempotent. Returns { wrapPublicPem, wrapPubkeyAnchorSig }.
function ensureWrapKeypair(db) {
  ensureSelfRow(db);
  const existing = db.prepare("SELECT wrap_public_pem, wrap_pubkey_anchor_sig FROM gd_ha_node WHERE id = 'self'").get();
  if (existing && existing.wrap_public_pem && existing.wrap_pubkey_anchor_sig) {
    return { wrapPublicPem: existing.wrap_public_pem, wrapPubkeyAnchorSig: existing.wrap_pubkey_anchor_sig };
  }
  const pair = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const sealedPriv = sealToHardware(Buffer.from(pair.privateKey, 'utf8'));
  const sig = anchor.sign({ db: db, data: Buffer.from(pair.publicKey, 'utf8') });
  if (!sig) {
    throw new Error('gd-ha-keys.ensureWrapKeypair: cannot anchor-sign the wrap key -- no hardware instance identity (fail-closed)');
  }
  const sigB64 = Buffer.from(sig).toString('base64');
  db.prepare(
    "UPDATE gd_ha_node SET wrap_public_pem = ?, wrap_private_sealed = ?, wrap_pubkey_anchor_sig = ?, updated_at = datetime('now') WHERE id = 'self'"
  ).run(pair.publicKey, sealedPriv, sigB64);
  return { wrapPublicPem: pair.publicKey, wrapPubkeyAnchorSig: sigB64 };
}

// The local wrap public key + its anchor signature, for the pairing handshake.
function getLocalWrapPublic(db) {
  const row = db.prepare("SELECT wrap_public_pem, wrap_pubkey_anchor_sig FROM gd_ha_node WHERE id = 'self'").get();
  if (!row || !row.wrap_public_pem) {
    return null;
  }
  return { wrapPublicPem: row.wrap_public_pem, wrapPubkeyAnchorSig: row.wrap_pubkey_anchor_sig };
}

// ---------------------------------------------------------------------------
// Peer wrap-key authentication + KEK wrap/unwrap.
// ---------------------------------------------------------------------------

// Verify a peer's anchor signature over its X25519 wrap public key, proving the
// wrap key belongs to the peer's hardware identity (ECDSA P-256 / IEEE P1363 /
// SHA-256 -- the shape gd-instance-anchor uses). Returns a boolean.
function verifyPeerWrapKey(peerWrapPublicPem, peerWrapSigB64, peerAnchorPublicPem) {
  if (typeof peerWrapPublicPem !== 'string' || typeof peerWrapSigB64 !== 'string' || typeof peerAnchorPublicPem !== 'string') {
    return false;
  }
  try {
    return crypto.verify(
      'sha256',
      Buffer.from(peerWrapPublicPem, 'utf8'),
      { key: peerAnchorPublicPem, dsaEncoding: 'ieee-p1363' },
      Buffer.from(peerWrapSigB64, 'base64')
    );
  } catch (err) {
    return false;
  }
}

// Wrap shared secret material to a peer's X25519 wrap public key via ephemeral-
// static ECDH -> HKDF -> AES-256-GCM. The peer unwraps with unwrapKekWithLocal
// using its sealed private key, only at promotion. Returns a base64 JSON envelope.
function wrapKekToPeer(secretBuf, peerWrapPublicPem) {
  if (!Buffer.isBuffer(secretBuf)) {
    throw new Error('gd-ha-keys.wrapKekToPeer: secret must be a Buffer');
  }
  const peerPub = crypto.createPublicKey(peerWrapPublicPem);
  const eph = crypto.generateKeyPairSync('x25519');
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: peerPub });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(16), Buffer.from(KEK_WRAP_INFO), HKDF_LEN));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(secretBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  const env = {
    v: ENVELOPE_VERSION,
    epk: eph.publicKey.export({ type: 'spki', format: 'pem' }),
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: tag.toString('base64'),
  };
  return Buffer.from(JSON.stringify(env)).toString('base64');
}

// Unwrap secret material wrapped to THIS node's X25519 wrap public key, using the
// hardware-sealed private key. Used only at promotion. Returns the secret Buffer.
function unwrapKekWithLocal(db, wrappedB64) {
  const row = db.prepare("SELECT wrap_private_sealed FROM gd_ha_node WHERE id = 'self'").get();
  if (!row || !row.wrap_private_sealed) {
    throw new Error('gd-ha-keys.unwrapKekWithLocal: no sealed wrap private key on this node');
  }
  const privPem = unsealFromHardware(row.wrap_private_sealed).toString('utf8');
  const env = JSON.parse(Buffer.from(String(wrappedB64), 'base64').toString('utf8'));
  const shared = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(privPem),
    publicKey: crypto.createPublicKey(env.epk),
  });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(16), Buffer.from(KEK_WRAP_INFO), HKDF_LEN));
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(env.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(env.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(env.ct, 'base64')), decipher.final()]);
}

module.exports = {
  ensureSelfRow,
  ensureWrapKeypair,
  getLocalWrapPublic,
  verifyPeerWrapKey,
  wrapKekToPeer,
  unwrapKekWithLocal,
  sealToHardware,
  unsealFromHardware,
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — server-side SEAL-ONLY half of the abuse "sealed box" (U3 PR G)
//
// Anyone can SEAL to the abuse-review PUBLIC key (no secret needed); only the
// holder of the matching PRIVATE key (the Abuse Review Console) can OPEN it. This
// module gives the SERVER the ability to seal -- and ONLY to seal. It carries no
// opening code and the server never holds a reviewer private key, so the server
// is structurally incapable of reading sealed abuse content. That is the whole
// point of Model B: flagged content reaches the independent reviewer without the
// server, a lead, an admin, or a DB/key insider ever being able to decrypt it.
//
// The server needs to seal because of the one-time peer/board re-seal migration
// (server/db/reseal-abuse-flags.js): it decrypts the legacy Tier-3 (Model A) copy
// it can still read and re-seals it to the reviewer public key, then drops the
// Tier-3 copy -- after which even the server can no longer read it.
//
// This is a deliberate copy of the SEAL half of packages/shared/abuse-seal.js
// (the client/ABC counterpart, which also opens). The server deploys only the
// server/ tree (see Dockerfile), so packages/shared is not on the server at
// runtime and the server needs its own copy. The seal construction below is
// byte-identical to the shared module so the ABC's openAsReviewer can open what
// this seals; the two MUST stay compatible. A round-trip test (server seals ->
// shared opens) guards against drift.
//
//   MAGIC(4) || ephPubSPKI(44) || iv(12) || gcmTag(16) || ciphertext
//   shared = X25519(ephemeralPriv, recipientPub)
//   key    = HKDF-SHA256(ikm=shared, salt=ephPubSPKI||recipientPubSPKI,
//                        info="firealive-abuse-seal-v1", len=32)
//   ciphertext, gcmTag = AES-256-GCM(key, iv, plaintext)
//
// X25519 ECIES over Node's built-in crypto -- no native or WASM dependency.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

const MAGIC = Buffer.from('FAS1', 'utf8');               // FireAlive Abuse Seal v1
const INFO = Buffer.from('firealive-abuse-seal-v1', 'utf8');
const ALGO = 'x25519-hkdf-sha256-aes256gcm';
const EPH_SPKI_LEN = 44;                                 // X25519 SPKI DER length
const IV_LEN = 12;
const TAG_LEN = 16;

function toPub(spkiDer) {
  return crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
}
function pubSpki(keyObj) {
  return keyObj.export({ format: 'der', type: 'spki' });
}

// Seal plaintext to the recipient (abuse-review) public key. recipientPubB64 is
// SPKI-DER base64, as stored in abuse_review_keys.public_key. Returns base64.
// Byte-identical to packages/shared/abuse-seal.js sealToReviewer -- do not let
// these diverge (the ABC opens what this produces).
function sealToReviewer(recipientPubB64, plaintext) {
  const recipientSpki = Buffer.from(recipientPubB64, 'base64');
  const recipientPub = toPub(recipientSpki);

  const eph = crypto.generateKeyPairSync('x25519');
  const ephSpki = pubSpki(eph.publicKey);
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPub });
  const salt = Buffer.concat([ephSpki, recipientSpki]);
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, INFO, 32));

  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([MAGIC, ephSpki, iv, tag, ct]).toString('base64');
}

// Is this stored blob already a Model B sealed box (vs a legacy Tier-3 Model A
// AES-GCM blob)? Sealed boxes begin with the 4-byte MAGIC; a Tier-3 blob begins
// with a random 12-byte IV, so a false match is ~1/2^32. The re-seal migration
// uses this to stay idempotent (skip already-sealed blobs).
function isSealed(buf) {
  return Buffer.isBuffer(buf) && buf.length >= MAGIC.length && buf.subarray(0, MAGIC.length).equals(MAGIC);
}

// SEAL-ONLY by design: no openAsReviewer here. The server must never be able to
// read sealed content. Opening lives only in the ABC (packages/shared/abuse-seal).
module.exports = { ALGO, MAGIC, EPH_SPKI_LEN, sealToReviewer, isSealed };

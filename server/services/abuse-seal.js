// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — server-side SEAL-ONLY half of the abuse "sealed box" (U3 PR G,
// extended for multi-reviewer in PR I)
//
// Anyone can SEAL to an abuse-review PUBLIC key (no secret needed); only the
// holder of the matching PRIVATE key (a designated reviewer in the Abuse Review
// Console) can OPEN it. This module gives the SERVER the ability to seal -- and
// ONLY to seal. It carries no opening code and the server never holds a reviewer
// private key, so the server is structurally incapable of reading sealed abuse
// content. That is the whole point of the model: flagged content reaches a
// reviewer without the server, a lead, an admin, or a DB/key insider ever being
// able to decrypt it.
//
// The server needs to seal because of the one-time peer/board re-seal migration
// (server/db/reseal-abuse-flags.js): it decrypts the legacy Tier-3 (Model A) copy
// it can still read and re-seals it to the active reviewer recipient set, then
// drops the Tier-3 copy -- after which even the server can no longer read it.
//
// This is a deliberate copy of the SEAL halves of packages/shared/abuse-seal.js
// (the client/reviewer-side counterpart, which also opens). The server deploys
// only the server/ tree (see Dockerfile), so packages/shared is not on the server
// at runtime and the server needs its own copy. Both seal constructions below
// are byte-identical to the shared module so a reviewer's openForReviewer opens
// what this seals; the two MUST stay compatible. A round-trip test (server seals
// -> shared opens) guards against drift.
//
//   FAS1 (single recipient, legacy):
//     MAGIC(4) || ephPubSPKI(44) || iv(12) || gcmTag(16) || ciphertext
//     shared = X25519(ephemeralPriv, recipientPub)
//     key    = HKDF-SHA256(ikm=shared, salt=ephPubSPKI||recipientPubSPKI,
//                          info="firealive-abuse-seal-v1", len=32)
//     ciphertext, gcmTag = AES-256-GCM(key, iv, plaintext)
//
//   FAS2 (multi-recipient, current): a random 32-byte content key (DEK) encrypts
//   the content once under AES-256-GCM; the DEK is then ECIES-wrapped to each
//   recipient public key separately (the same X25519 -> HKDF -> AES-256-GCM
//   construction as FAS1, domain-separated by a v2 HKDF info). Layout:
//
//     MAGIC2(4) || nRecipients(1) ||
//       [ fp(8) || ephPubSPKI(44) || wrapIv(12) || wrapTag(16) || wrappedDEK(32) ] x n ||
//     contentIv(12) || contentTag(16) || ciphertext
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

// Is this stored blob already a sealed box (FAS1 single-recipient or FAS2
// multi-recipient), vs a legacy Tier-3 Model A AES-GCM blob? Sealed boxes begin
// with one of the 4-byte magics; a Tier-3 blob begins with a random 12-byte IV,
// so a false match on either magic is ~1/2^32. The re-seal migration uses this
// to stay idempotent (skip already-sealed blobs in either format).
function isSealed(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < MAGIC.length) return false;
  const head = buf.subarray(0, MAGIC.length);
  return head.equals(MAGIC) || head.equals(MAGIC2);
}

// ── FAS2: multi-recipient envelope (U3 PR I, seal half) ─────────────────────────
// Seal once to MANY recipient public keys at once. The server uses this in the
// reseal migration when more than one reviewer is registered, so the re-sealed
// legacy flags open for any one of them. Byte-identical to the FAS2 seal in
// packages/shared/abuse-seal.js -- a reviewer's openForReviewer opens what this
// produces.
const MAGIC2 = Buffer.from('FAS2', 'utf8');              // FireAlive Abuse Seal v2
const INFO2 = Buffer.from('firealive-abuse-seal-v2-wrap', 'utf8');
const FP_LEN = 8;                                        // recipient fingerprint
const DEK_LEN = 32;                                      // content key (AES-256)
const MAX_RECIPIENTS = 255;                              // nRecipients is one byte

// 8-byte fingerprint of a recipient public key (SPKI-DER base64). Same construction
// as packages/shared/abuse-seal.js -- both ends produce the identical slot tag.
function fingerprintForPubB64(recipientPubB64) {
  const spki = Buffer.from(recipientPubB64, 'base64');
  return crypto.createHash('sha256').update(spki).digest().subarray(0, FP_LEN);
}

// Seal plaintext to MANY recipient public keys at once. recipientPubB64List is a
// non-empty array of SPKI-DER base64 keys (the active reviewer recipient set).
// Returns base64.
function sealToReviewers(recipientPubB64List, plaintext) {
  if (!Array.isArray(recipientPubB64List) || recipientPubB64List.length === 0) {
    throw new Error('at least one recipient public key is required');
  }
  if (recipientPubB64List.length > MAX_RECIPIENTS) {
    throw new Error('too many recipients (max ' + MAX_RECIPIENTS + ')');
  }

  // Encrypt the content once under a random data-encryption key (DEK).
  const dek = crypto.randomBytes(DEK_LEN);
  const contentIv = crypto.randomBytes(IV_LEN);
  const contentCipher = crypto.createCipheriv('aes-256-gcm', dek, contentIv);
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
  const contentCt = Buffer.concat([contentCipher.update(pt), contentCipher.final()]);
  const contentTag = contentCipher.getAuthTag();

  // Wrap the DEK to each recipient independently (ECIES per recipient).
  const slots = recipientPubB64List.map((recipientPubB64) => {
    const recipientSpki = Buffer.from(recipientPubB64, 'base64');
    const recipientPub = toPub(recipientSpki);
    const fp = fingerprintForPubB64(recipientPubB64);

    const eph = crypto.generateKeyPairSync('x25519');
    const ephSpki = pubSpki(eph.publicKey);
    const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPub });
    const salt = Buffer.concat([ephSpki, recipientSpki]);
    const wrapKey = Buffer.from(crypto.hkdfSync('sha256', shared, salt, INFO2, 32));

    const wrapIv = crypto.randomBytes(IV_LEN);
    const wrapCipher = crypto.createCipheriv('aes-256-gcm', wrapKey, wrapIv);
    const wrappedDek = Buffer.concat([wrapCipher.update(dek), wrapCipher.final()]);
    const wrapTag = wrapCipher.getAuthTag();

    return Buffer.concat([fp, ephSpki, wrapIv, wrapTag, wrappedDek]);
  });

  const count = Buffer.from([recipientPubB64List.length]);
  return Buffer.concat([MAGIC2, count, ...slots, contentIv, contentTag, contentCt]).toString('base64');
}

// SEAL-ONLY by design: no open functions here. The server must never be able to
// read sealed content. Opening lives only on reviewer devices via the shared
// abuse-seal module (openForReviewer dispatches FAS1 and FAS2).
module.exports = { ALGO, MAGIC, MAGIC2, EPH_SPKI_LEN, sealToReviewer, sealToReviewers, fingerprintForPubB64, isSealed };

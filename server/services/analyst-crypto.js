'use strict';

/*
 * analyst-crypto.js -- server-side seal-to-public-key helpers (Phase B5d1).
 *
 * Purpose
 * -------
 * Per-analyst burnout detail is sealed to each analyst's X25519 public key so
 * the server can WRITE per-analyst data but can never READ it back. There is
 * no analyst private key anywhere on the server and, by deliberate design,
 * no decrypt path in this module: the server can seal, validate, and parse the
 * envelope, and nothing more. The analyst's device holds the private key and
 * opens these blobs (Analyst Client key-custody layer). The server's own
 * aggregate and routing needs are met by the de-identified metrics store and
 * the metric-free routing cap, not by reading these blobs.
 *
 * This realizes the founding promise -- management cannot access individual
 * analyst data even with database credentials -- in cryptography rather than
 * policy: a database read yields only opaque ciphertext.
 *
 * Construction
 * ------------
 * Single-recipient ECIES using node's crypto: the same X25519 + HKDF-SHA256 +
 * AES-256-GCM construction the codebase already uses to seal to a public key
 * (packages/shared/abuse-seal.js). These node primitives are equally available
 * in the Analyst Client (Electron main), so the AC opens these seals with no
 * extra dependency. A fresh ephemeral keypair per seal agrees with the
 * recipient public key; HKDF derives the AES key with a salt that binds the
 * ephemeral and recipient public keys; AES-256-GCM authenticates.
 *
 * Keys: X25519, public as SPKI-DER and private as PKCS8-DER, base64-encoded.
 *
 * Wire format (one buffer; stored base64)
 * ---------------------------------------
 *   bytes 0..3      magic 'FAP1'
 *   byte  4         version (SEALED_VERSION)
 *   bytes 5..48     ephemeral public key, X25519 SPKI-DER (EPH_SPKI_LEN = 44)
 *   bytes 49..60    AES-GCM iv (IV_LEN = 12)
 *   bytes 61..76    AES-GCM tag (TAG_LEN = 16)
 *   bytes 77..end   ciphertext
 */

const crypto = require('crypto');

const MAGIC = Buffer.from('FAP1', 'utf8'); // FireAlive Analyst Private v1
const SEALED_VERSION = 1;
const ALGO = 'x25519-hkdf-sha256-aes256gcm';
const EPH_SPKI_LEN = 44; // X25519 SPKI-DER public key length
const IV_LEN = 12;
const TAG_LEN = 16;
const HEADER_LEN = MAGIC.length + 1 + EPH_SPKI_LEN + IV_LEN + TAG_LEN; // 77
const INFO = Buffer.from('firealive-analyst-seal-v1', 'utf8');

function toPublicKey(spkiDer) {
  return crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
}
function exportSpki(keyObj) {
  return keyObj.export({ format: 'der', type: 'spki' });
}
function decodeBase64(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError('expected a non-empty base64 string');
  }
  return Buffer.from(value, 'base64');
}

/*
 * isValidPublicKey(publicKeyB64) -> boolean
 * True only for a base64 string that parses as an X25519 SPKI-DER public key.
 * Used at key-registration time and by the regression checks; never throws.
 */
function isValidPublicKey(publicKeyB64) {
  try {
    return toPublicKey(decodeBase64(publicKeyB64)).asymmetricKeyType === 'x25519';
  } catch (err) {
    return false;
  }
}

/*
 * sealToPublicKey(plaintext, recipientPublicKeyB64) -> base64 string
 * Seals plaintext (Buffer or string) to the recipient's X25519 public key. The
 * result is decryptable only by the holder of the matching private key.
 */
function sealToPublicKey(plaintext, recipientPublicKeyB64) {
  const recipientSpki = decodeBase64(recipientPublicKeyB64);
  let recipientPub;
  try {
    recipientPub = toPublicKey(recipientSpki);
  } catch (err) {
    throw new Error('invalid recipient public key');
  }
  if (recipientPub.asymmetricKeyType !== 'x25519') {
    throw new Error('recipient public key is not X25519');
  }

  const message = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');

  const eph = crypto.generateKeyPairSync('x25519');
  const ephSpki = exportSpki(eph.publicKey);
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPub });
  const salt = Buffer.concat([ephSpki, recipientSpki]);
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, INFO, 32));

  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(message), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([MAGIC, Buffer.from([SEALED_VERSION]), ephSpki, iv, tag, ciphertext]).toString(
    'base64'
  );
}

/*
 * parseSealed(sealedB64) -> { version, ephemeralPublicKey, iv, tag, ciphertext }
 * Validates the envelope shape and splits it into its parts (all Buffers). The
 * server uses this only to assert structural integrity (regression checks); it
 * does not and cannot decrypt the ciphertext.
 */
function parseSealed(sealedB64) {
  const buf = decodeBase64(sealedB64);
  if (buf.length < HEADER_LEN || !buf.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('bad seal magic or sealed blob too short');
  }
  const version = buf[MAGIC.length];
  if (version !== SEALED_VERSION) {
    throw new Error('unsupported sealed version: ' + version);
  }
  let p = MAGIC.length + 1;
  const ephemeralPublicKey = buf.subarray(p, p + EPH_SPKI_LEN);
  p += EPH_SPKI_LEN;
  const iv = buf.subarray(p, p + IV_LEN);
  p += IV_LEN;
  const tag = buf.subarray(p, p + TAG_LEN);
  p += TAG_LEN;
  const ciphertext = buf.subarray(p);
  return { version: version, ephemeralPublicKey: ephemeralPublicKey, iv: iv, tag: tag, ciphertext: ciphertext };
}

module.exports = {
  MAGIC: MAGIC,
  SEALED_VERSION: SEALED_VERSION,
  ALGO: ALGO,
  EPH_SPKI_LEN: EPH_SPKI_LEN,
  IV_LEN: IV_LEN,
  TAG_LEN: TAG_LEN,
  HEADER_LEN: HEADER_LEN,
  isValidPublicKey: isValidPublicKey,
  sealToPublicKey: sealToPublicKey,
  parseSealed: parseSealed,
};

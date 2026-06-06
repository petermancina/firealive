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
 * opens these blobs (Analyst Client key-custody layer, later PRs). The
 * server's own aggregate and routing needs are met by the de-identified
 * metrics store and the metric-free routing cap, not by reading these blobs.
 *
 * This realizes the founding promise -- management cannot access individual
 * analyst data even with database credentials -- in cryptography rather than
 * policy: a database read yields only opaque ciphertext.
 *
 * Construction
 * ------------
 * Anonymous-sender sealed box built on tweetnacl's nacl.box (Curve25519 key
 * agreement + XSalsa20-Poly1305 authenticated encryption), the same primitive
 * already used elsewhere in this codebase. Each call uses a fresh ephemeral
 * keypair and a random nonce; the ephemeral secret key is wiped after sealing.
 * The recipient opens with nacl.box.open(ciphertext, nonce, ephemeralPublic,
 * analystSecret).
 *
 * Wire format (one buffer; stored base64-encoded)
 * -----------------------------------------------
 *   byte  0          version (SEALED_VERSION)
 *   bytes 1..32      ephemeral public key (PUBLIC_KEY_BYTES)
 *   bytes 33..56     nonce (NONCE_BYTES)
 *   bytes 57..end    ciphertext (plaintext + 16-byte Poly1305 tag)
 */

const nacl = require('tweetnacl');

const SEALED_VERSION = 1;
const PUBLIC_KEY_BYTES = nacl.box.publicKeyLength; // 32
const NONCE_BYTES = nacl.box.nonceLength; // 24
const OVERHEAD_BYTES = nacl.box.overheadLength; // 16 (Poly1305 tag)
const HEADER_BYTES = 1 + PUBLIC_KEY_BYTES + NONCE_BYTES; // 57

function decodeBase64(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError('expected a non-empty base64 string');
  }
  return Buffer.from(value, 'base64');
}

/*
 * isValidPublicKey(publicKeyB64) -> boolean
 * True only for a base64 string decoding to exactly PUBLIC_KEY_BYTES. Used at
 * key-registration time and by the regression checks; never throws.
 */
function isValidPublicKey(publicKeyB64) {
  try {
    return decodeBase64(publicKeyB64).length === PUBLIC_KEY_BYTES;
  } catch (err) {
    return false;
  }
}

/*
 * sealToPublicKey(plaintext, recipientPublicKeyB64) -> base64 string
 * Seals plaintext (Buffer or string) to the recipient's X25519 public key.
 * The result is decryptable only by the holder of the matching private key.
 */
function sealToPublicKey(plaintext, recipientPublicKeyB64) {
  const recipientPublicKey = decodeBase64(recipientPublicKeyB64);
  if (recipientPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error('invalid recipient public key length');
  }

  const message = Buffer.isBuffer(plaintext)
    ? plaintext
    : Buffer.from(String(plaintext), 'utf8');

  const ephemeral = nacl.box.keyPair();
  const nonce = nacl.randomBytes(NONCE_BYTES);
  const sealed = nacl.box(
    Uint8Array.from(message),
    nonce,
    Uint8Array.from(recipientPublicKey),
    ephemeral.secretKey
  );
  if (!sealed) {
    throw new Error('seal operation failed');
  }

  const out = Buffer.alloc(HEADER_BYTES + sealed.length);
  out[0] = SEALED_VERSION;
  Buffer.from(ephemeral.publicKey).copy(out, 1);
  Buffer.from(nonce).copy(out, 1 + PUBLIC_KEY_BYTES);
  Buffer.from(sealed).copy(out, HEADER_BYTES);

  // Best-effort scrub: the ephemeral secret key is never needed again.
  ephemeral.secretKey.fill(0);

  return out.toString('base64');
}

/*
 * parseSealed(sealedB64) -> { version, ephemeralPublicKey, nonce, ciphertext }
 * Validates the envelope shape and splits it into its parts (all Buffers).
 * The server uses this only to assert structural integrity (regression
 * checks); it does not and cannot decrypt the ciphertext.
 */
function parseSealed(sealedB64) {
  const buf = decodeBase64(sealedB64);
  if (buf.length < HEADER_BYTES + OVERHEAD_BYTES) {
    throw new Error('sealed blob is too short');
  }
  const version = buf[0];
  if (version !== SEALED_VERSION) {
    throw new Error('unsupported sealed version: ' + version);
  }
  return {
    version: version,
    ephemeralPublicKey: buf.slice(1, 1 + PUBLIC_KEY_BYTES),
    nonce: buf.slice(1 + PUBLIC_KEY_BYTES, HEADER_BYTES),
    ciphertext: buf.slice(HEADER_BYTES)
  };
}

module.exports = {
  SEALED_VERSION: SEALED_VERSION,
  PUBLIC_KEY_BYTES: PUBLIC_KEY_BYTES,
  NONCE_BYTES: NONCE_BYTES,
  OVERHEAD_BYTES: OVERHEAD_BYTES,
  HEADER_BYTES: HEADER_BYTES,
  isValidPublicKey: isValidPublicKey,
  sealToPublicKey: sealToPublicKey,
  parseSealed: parseSealed
};

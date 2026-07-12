'use strict';

// FIREALIVE (Global Dashboard) -- Tier-1 versioned envelope (v2)
//
// The GD twin of server/services/tier1-envelope.js, but framed as a JSON string
// to match gd-encryption's existing at-rest shape ({v, iv, tag, ciphertext}, all
// base64) rather than a raw Buffer. It sits under gd-tier1-seal.js and replaces the
// bare v1 envelope (gd-encryption.encryptConfigWithKey) with a versioned one:
//
//   v2 JSON:  { v: 2, kek_fp, iv, tag, ciphertext }   (all base64)
//   GCM AAD:  'fa-gd-tier1-v2' || kek_fp || aad        (aad = table || column)
//
// The AAD is a CANONICAL byte construction, not the JSON text, so it does not
// depend on key order or whitespace. It gives the same two properties as the MC
// envelope: relocation resistance (R6 -- a value moved to another column fails the
// GCM tag) and wrong-KEK fail-fast (kek_fp names the sealing KEK).
//
// Reads are VERSIONED on the JSON `v` field. A v2 value is verified and opened
// here; anything else (a legacy v1 {v:1,...} value, or junk) is delegated to
// gd-encryption.decryptConfigWithKey unchanged -- which reads v1 and rejects the
// rest. Existing at-rest bytes stay readable; only new writes are v2. The offline
// rekey tool re-seals v1 -> v2.

const crypto = require('crypto');
const gdEnc = require('./gd-encryption');

const ALGORITHM = 'aes-256-gcm';
const VERSION = 2;
const KEK_FP_LEN = 8;
const V2_AAD_TAG = Buffer.from('fa-gd-tier1-v2', 'ascii');

// True if a stored envelope string is a v2 GD Tier-1 envelope.
function isV2(envelope) {
  if (typeof envelope !== 'string' || envelope.length === 0) return false;
  try { return JSON.parse(envelope).v === VERSION; } catch (e) { return false; }
}

// Seal an object into a v2 envelope string under `kek`, stamping `kekFp` (8 bytes)
// and binding `aad` (the column binding) into the GCM AAD alongside the version tag.
function sealV2(obj, kek, kekFp, aad) {
  if (obj === undefined) throw new Error('gd-tier1-envelope: obj is undefined');
  if (!Buffer.isBuffer(kekFp) || kekFp.length !== KEK_FP_LEN) {
    throw new Error('gd-tier1-envelope: kekFp must be an ' + KEK_FP_LEN + '-byte Buffer');
  }
  const aadBuf = aad == null ? Buffer.alloc(0) : (Buffer.isBuffer(aad) ? aad : Buffer.from(aad));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, kek, iv);
  cipher.setAAD(Buffer.concat([V2_AAD_TAG, kekFp, aadBuf]));
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(obj), 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: VERSION,
    kek_fp: kekFp.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ct.toString('base64'),
  });
}

// Open a stored envelope string. v2 values are verified (kek_fp against
// expectedKekFp when supplied, AAD) and decrypted here; legacy v1 values are
// delegated to gd-encryption.decryptConfigWithKey. Returns the decrypted object.
function open(envelope, kek, aad, expectedKekFp) {
  if (!isV2(envelope)) {
    return gdEnc.decryptConfigWithKey(envelope, kek);
  }
  const parsed = JSON.parse(envelope);
  if (!parsed.kek_fp || !parsed.iv || !parsed.tag || !parsed.ciphertext) {
    throw new Error('gd-tier1-envelope: v2 envelope missing kek_fp / iv / tag / ciphertext');
  }
  const kekFp = Buffer.from(parsed.kek_fp, 'base64');
  if (Buffer.isBuffer(expectedKekFp) && expectedKekFp.length === KEK_FP_LEN && !kekFp.equals(expectedKekFp)) {
    throw new Error('gd-tier1-envelope: KEK fingerprint mismatch -- this value was sealed under a different KEK '
      + '(wrong domain key, or a value relocated from another node/column)');
  }
  const aadBuf = aad == null ? Buffer.alloc(0) : (Buffer.isBuffer(aad) ? aad : Buffer.from(aad));
  const iv = Buffer.from(parsed.iv, 'base64');
  const tag = Buffer.from(parsed.tag, 'base64');
  const ct = Buffer.from(parsed.ciphertext, 'base64');
  const decipher = crypto.createDecipheriv(ALGORITHM, kek, iv);
  decipher.setAAD(Buffer.concat([V2_AAD_TAG, kekFp, aadBuf]));
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString('utf8'));
}

module.exports = {
  VERSION,
  KEK_FP_LEN,
  isV2,
  sealV2,
  open,
};

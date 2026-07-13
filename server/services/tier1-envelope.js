'use strict';

// FIREALIVE -- Tier-1 versioned envelope (v2 with AAD binding + KEK fingerprint)
//
// The at-rest wrapper for every Tier-1 column, sitting under the domain-aware
// chokepoint (tier1-seal.js). It replaces the bare v1 envelope
// (encryption.encryptWithKey, iv||tag||ct, no AAD) with a versioned format:
//
//   v2 wire:  magic(4) || version(1) || kek_fp(8) || iv(12) || tag(16) || ct
//   GCM AAD:  header || aad   where header = magic || version || kek_fp
//             and aad is the caller's column binding (table || column bytes)
//
// Two properties this buys, both required by the plan:
//   1. Relocation resistance (R6). The column identity is authenticated, so a
//      ciphertext copied to a different column/table fails the GCM tag rather
//      than silently decrypting in the wrong place.
//   2. Wrong-KEK fail-fast. kek_fp names which KEK sealed the value; a reader
//      holding the wrong KEK (a node-local column under the shared KEK, a
//      replicated column under own KEK before a shared KEK was adopted, or a
//      relocated/corrupt value) is rejected with a clear error, not a cryptic
//      GCM failure.
//
// Reads are VERSIONED. open() dispatches on the 4-byte magic: a v2 value is
// verified and opened here; anything else is a legacy v1 value and is delegated
// to encryption.decryptWithKey unchanged (no AAD). Existing at-rest bytes stay
// readable; only new writes are v2. The offline rekey tool re-seals v1 -> v2.

const crypto = require('crypto');
const enc = require('./encryption');

const ALGORITHM = 'aes-256-gcm';
const MAGIC = Buffer.from('FAT1', 'ascii'); // 0x46 0x41 0x54 0x31
const VERSION = 2;
const KEK_FP_LEN = 8;
const IV_LEN = 12;
const TAG_LEN = 16;
const HEADER_LEN = MAGIC.length + 1 + KEK_FP_LEN; // magic || version || kek_fp = 13

// The version new writes use, and the floor below which open() refuses. MIN_SEAL_VERSION = 1
// keeps legacy v1 values readable until they are rekeyed; raise it to 2 to permanently retire
// v1 (reject any value not on the AAD-bound, KEK-fingerprinted v2 envelope) once every
// deployment has been rekeyed.
const CURRENT_SEAL_VERSION = VERSION;
const MIN_SEAL_VERSION = 1;

// True if a stored value is a v2 Tier-1 envelope (as opposed to a legacy v1 one).
function isV2(buffer) {
  return Buffer.isBuffer(buffer)
    && buffer.length >= HEADER_LEN + IV_LEN + TAG_LEN
    && buffer.subarray(0, MAGIC.length).equals(MAGIC);
}

// The seal version of a stored value: the version byte of a magic'd envelope (2 for v2), or 1
// for a legacy v1 value (no magic). Read-only -- never decrypts. Used by the boot straggler
// scan and the anti-rollback seal-version high-water.
function sealVersionOf(buffer) {
  return isV2(buffer) ? buffer[MAGIC.length] : 1;
}

// Seal plaintext into a v2 envelope under `key`, stamping `kekFp` (8 bytes) and
// binding `aad` (the caller's column binding) into the GCM AAD alongside the header.
function sealV2(plaintext, key, kekFp, aad) {
  if (!Buffer.isBuffer(kekFp) || kekFp.length !== KEK_FP_LEN) {
    throw new Error('tier1-envelope: kekFp must be an ' + KEK_FP_LEN + '-byte Buffer');
  }
  const aadBuf = aad == null ? Buffer.alloc(0) : (Buffer.isBuffer(aad) ? aad : Buffer.from(aad));
  const iv = crypto.randomBytes(IV_LEN);
  const header = Buffer.concat([MAGIC, Buffer.from([VERSION]), kekFp]);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(Buffer.concat([header, aadBuf]));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([header, iv, tag, ct]);
}

// Open a stored value. v2 values are verified (version, kek_fp against
// expectedKekFp when supplied, AAD) and decrypted here; legacy v1 values are
// delegated to encryption.decryptWithKey (no AAD). Returns the utf-8 plaintext.
function open(buffer, key, aad, expectedKekFp) {
  // Floor: refuse any value sealed below MIN_SEAL_VERSION (downgrade / retired-format defense),
  // before any decrypt path.
  const version = sealVersionOf(buffer);
  if (version < MIN_SEAL_VERSION) {
    throw new Error('tier1-envelope: seal version ' + version + ' is below the MIN_SEAL_VERSION floor '
      + MIN_SEAL_VERSION + ' -- this value must be rekeyed to a current envelope');
  }
  if (!isV2(buffer)) {
    // Legacy v1: bare iv||tag||ct, no AAD, no fingerprint.
    return enc.decryptWithKey(buffer, key);
  }
  if (version !== VERSION) {
    throw new Error('tier1-envelope: unsupported envelope version ' + version);
  }
  const kekFp = buffer.subarray(MAGIC.length + 1, HEADER_LEN);
  if (Buffer.isBuffer(expectedKekFp) && expectedKekFp.length === KEK_FP_LEN && !kekFp.equals(expectedKekFp)) {
    throw new Error('tier1-envelope: KEK fingerprint mismatch -- this value was sealed under a different KEK '
      + '(wrong domain key, or a value relocated from another node/column)');
  }
  const header = buffer.subarray(0, HEADER_LEN);
  const iv = buffer.subarray(HEADER_LEN, HEADER_LEN + IV_LEN);
  const tag = buffer.subarray(HEADER_LEN + IV_LEN, HEADER_LEN + IV_LEN + TAG_LEN);
  const ct = buffer.subarray(HEADER_LEN + IV_LEN + TAG_LEN);
  const aadBuf = aad == null ? Buffer.alloc(0) : (Buffer.isBuffer(aad) ? aad : Buffer.from(aad));
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAAD(Buffer.concat([header, aadBuf]));
  decipher.setAuthTag(tag);
  return decipher.update(ct, null, 'utf-8') + decipher.final('utf-8');
}

module.exports = {
  MAGIC,
  VERSION,
  CURRENT_SEAL_VERSION,
  MIN_SEAL_VERSION,
  KEK_FP_LEN,
  HEADER_LEN,
  isV2,
  sealVersionOf,
  sealV2,
  open,
};

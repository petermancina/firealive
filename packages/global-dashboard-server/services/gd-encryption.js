// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Tier-1 Encryption Helper (R3k C28; hardware-sealed KEK, B6d)
//
// AES-256-GCM wrap/unwrap of small JSON config blobs (signing-key
// private PEMs, etc). Parallel to MC's server/services/encryption.js
// but uses GD's OWN key envelope.
//
// THREAT MODEL & ISOLATION
// ========================
//
// Per the locked R3k Sub-phase 6 design decision: the GD-server has
// its OWN signing keys and its OWN wrapping KEK distinct from the
// MC's. This file's encrypt/decrypt functions are the floor that
// distinction sits on. An MC compromise that leaks the MC's KEK does
// not pivot into a GD compromise; an operator who replaces GD's KEK
// does not need to re-key any MC.
//
// KEY MATERIAL (hardware-sealed, B6d)
// ===================================
//
// The Tier-1 KEK is resolved from gd-tier1-kek -- the single hardware-
// sealed resolver, the GD twin of the regional server's tier1-kek.
// Under decision D26 the KEK is hardware-sealed and fail-closed for
// EVERY deployment mode: GD_ENCRYPTION_KEY carries an opaque wrapper
// that only the GD host TPM 2.0 / Secure Enclave can unseal. A raw key
// is REFUSED and the former GD_JWT_SECRET-derived fallback is retired
// -- no weak KEK source survives on the GD (parity with the MC). See
// gd-tier1-kek.js for provisioning, the one-time recovery code, and the
// HA-promotion install path.
//
// FORMAT
// ======
//
//   encryptConfig(obj)  -> {v: 1, iv, tag, ciphertext} (all base64)
//
//   decryptConfig(blob) -> the same obj, or throws if the GCM tag
//                          doesn't verify (tamper detection).
//
// The wrapped envelope is the value stored in cloud_iac_signing_keys
// .private_key_wrapped (and any future GD wrapped-config columns).
// The format key 'v: 1' lets future rotations distinguish envelopes
// across crypto upgrades without ambiguity.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const gdTier1Kek = require('./gd-tier1-kek');

// Resolve the GD Tier-1 KEK from the hardware-sealed resolver. gd-tier1-kek reads
// GD_ENCRYPTION_KEY (a hardware-sealed wrapper), unseals it on this GD hardware,
// and caches it -- refusing a raw key and the retired GD_JWT_SECRET fallback
// (fail-closed, every mode). At GD HA promotion the promoted passive installs the
// shared KEK there, so this resolves the shared key from that point on.
function deriveKek() {
  return gdTier1Kek.resolveTier1Kek();
}

// Core: seal a config object into the GD self-describing envelope string under a
// given raw 32-byte key. encryptConfig() below is this with the resolved KEK; the
// domain-aware Tier-1 chokepoint (gd-tier1-seal) calls this with ownKek() or
// sharedKek() by column, so there is exactly one envelope implementation.
function encryptConfigWithKey(obj, kek) {
  if (obj === undefined) throw new Error('encryptConfigWithKey: obj is undefined');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: 1,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  });
}

function encryptConfig(obj) {
  return encryptConfigWithKey(obj, deriveKek());
}

function decryptConfigWithKey(envelope, kek) {
  if (typeof envelope !== 'string' || envelope.length === 0) {
    throw new Error('decryptConfigWithKey: envelope must be a non-empty string');
  }
  let parsed;
  try {
    parsed = JSON.parse(envelope);
  } catch (e) {
    throw new Error(`decryptConfigWithKey: envelope is not valid JSON: ${e.message}`);
  }
  if (parsed.v !== 1) {
    throw new Error(`decryptConfigWithKey: unsupported envelope version v=${parsed.v}`);
  }
  if (!parsed.iv || !parsed.tag || !parsed.ciphertext) {
    throw new Error('decryptConfigWithKey: envelope missing iv / tag / ciphertext');
  }
  const iv = Buffer.from(parsed.iv, 'base64');
  const tag = Buffer.from(parsed.tag, 'base64');
  const ciphertext = Buffer.from(parsed.ciphertext, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

function decryptConfig(envelope) {
  return decryptConfigWithKey(envelope, deriveKek());
}

// Retained for the Cloud Mode boot caller. Under B6d the Tier-1 KEK is hardware-
// sealed and fail-closed for EVERY mode (gd-tier1-kek refuses a raw key and the
// GD_JWT_SECRET fallback), so Cloud Mode no longer needs a separate KEK rule --
// hardware-sealing is universal and strictly stronger than the former secret-store
// requirement. This is now a no-op; the caller is retired in the Cloud Mode
// KEK-gate commit.
function requireCloudKek() {}

// Clear the resolved-KEK cache. The cache now lives in gd-tier1-kek (not this
// module), so delegate -- callers and tests that re-require gd-encryption no
// longer reset the KEK by that alone.
function _resetKekCache() {
  gdTier1Kek._resetCacheForTests();
}

module.exports = {
  encryptConfig,
  decryptConfig,
  encryptConfigWithKey,
  decryptConfigWithKey,
  deriveKek,
  _resetKekCache,
  requireCloudKek,
};

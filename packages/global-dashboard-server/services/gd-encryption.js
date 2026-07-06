// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Tier-1 Encryption Helper (R3k C28)
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
// distinction sits on. An MC compromise that leaks
// TIER1_ENCRYPTION_KEY does not pivot into a GD compromise; an
// operator who replaces GD's KEK does not need to re-key any MC.
//
// KEY MATERIAL
// ============
//
// Env var (in priority order):
//
//   GD_ENCRYPTION_KEY      preferred; 32-byte hex (64 chars) Key-
//                          Encryption-Key supplied by deployment.
//
//   GD_JWT_SECRET          fallback; hashed via SHA-256 to derive a
//                          32-byte key. Less ideal — couples
//                          encryption-at-rest to the JWT signing
//                          secret — but keeps the GD operable on
//                          installs that haven't yet provisioned a
//                          dedicated GD_ENCRYPTION_KEY. Emits a
//                          warning to the console at first use.
//
//   (none)                 deriveKey throws. The GD will not start
//                          a Sub-phase-6 generator route without a
//                          usable KEK source.
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

let cachedKek = null;
let fallbackWarned = false;
// Cloud Mode latch: once the boot flips this (in cloud mode, before any Tier-1
// operation), the GD_JWT_SECRET KEK fallback is refused -- only a dedicated
// GD_ENCRYPTION_KEY from the cloud secret store is accepted (fail-closed).
let cloudKekRequired = false;

function deriveKek() {
  if (cachedKek) return cachedKek;

  const explicit = process.env.GD_ENCRYPTION_KEY;
  if (explicit) {
    if (!/^[0-9a-fA-F]{64}$/.test(explicit)) {
      throw new Error(
        'GD_ENCRYPTION_KEY is set but is not exactly 64 hex chars (32 bytes). Generate with `openssl rand -hex 32` and set as GD_ENCRYPTION_KEY in the GD-server environment.',
      );
    }
    cachedKek = Buffer.from(explicit, 'hex');
    return cachedKek;
  }

  // Cloud Mode: the Tier-1 KEK must be a dedicated GD_ENCRYPTION_KEY sourced from
  // the cloud secret store. On a confidential VM the whole security model is the
  // sealed instance, so Tier-1 data must never be keyed off the JWT secret --
  // refuse the fallback fail-closed rather than silently weakening the KEK.
  if (cloudKekRequired) {
    throw new Error(
      'Cloud Mode requires a dedicated GD_ENCRYPTION_KEY (32-byte hex) sourced from the cloud secret store; the GD_JWT_SECRET KEK fallback is refused on a confidential VM (fail-closed). Generate with `openssl rand -hex 32` and provide it via the cloud secret store.',
    );
  }

  const jwtSecret = process.env.GD_JWT_SECRET;
  if (jwtSecret) {
    if (!fallbackWarned) {
      console.warn(
        '[gd-encryption] WARNING: GD_ENCRYPTION_KEY not set; deriving Tier-1 KEK from GD_JWT_SECRET via SHA-256. For SOC-grade posture, set a dedicated 32-byte GD_ENCRYPTION_KEY (openssl rand -hex 32) and migrate any wrapped configs before retiring this fallback.',
      );
      fallbackWarned = true;
    }
    cachedKek = crypto.createHash('sha256').update(jwtSecret).digest();
    return cachedKek;
  }

  throw new Error(
    'gd-encryption: neither GD_ENCRYPTION_KEY nor GD_JWT_SECRET is set. The GD-server cannot wrap or unwrap Tier-1 configs (signing keys, etc.) without a KEK source.',
  );
}

function encryptConfig(obj) {
  if (obj === undefined) throw new Error('encryptConfig: obj is undefined');
  const kek = deriveKek();
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

function decryptConfig(envelope) {
  if (typeof envelope !== 'string' || envelope.length === 0) {
    throw new Error('decryptConfig: envelope must be a non-empty string');
  }
  let parsed;
  try {
    parsed = JSON.parse(envelope);
  } catch (e) {
    throw new Error(`decryptConfig: envelope is not valid JSON: ${e.message}`);
  }
  if (parsed.v !== 1) {
    throw new Error(`decryptConfig: unsupported envelope version v=${parsed.v}`);
  }
  if (!parsed.iv || !parsed.tag || !parsed.ciphertext) {
    throw new Error('decryptConfig: envelope missing iv / tag / ciphertext');
  }
  const kek = deriveKek();
  const iv = Buffer.from(parsed.iv, 'base64');
  const tag = Buffer.from(parsed.tag, 'base64');
  const ciphertext = Buffer.from(parsed.ciphertext, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

// Called by the GD boot in Cloud Mode, before any Tier-1 operation: from now on
// the GD_JWT_SECRET KEK fallback is refused and only a dedicated GD_ENCRYPTION_KEY
// is accepted. Clears any cached KEK so the rule applies even if a KEK was already
// derived earlier in boot (a JWT-derived KEK is discarded and re-derived under the
// cloud rule, which then fails closed if GD_ENCRYPTION_KEY is absent).
function requireCloudKek() {
  cloudKekRequired = true;
  cachedKek = null;
}

function _resetKekCache() {
  cachedKek = null;
  fallbackWarned = false;
  cloudKekRequired = false;
}

module.exports = {
  encryptConfig,
  decryptConfig,
  _resetKekCache,
  requireCloudKek,
};

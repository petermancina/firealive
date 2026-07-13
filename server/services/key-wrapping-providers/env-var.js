// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Env-var Key Wrapping Provider
//
// Wraps and unwraps DEKs using a Key Encryption Key (KEK) read from a
// process environment variable. This is the R3d-1 default behavior,
// refactored to plug into the R3d-4 provider registry.
//
// Tier 3 security: the KEK lives in the FireAlive process's environment
// variable space, readable by any process running as the same user.
// Operator's responsibility to inject from a secrets manager and protect
// the host. Last-resort fallback for installs that haven't deployed cloud
// KMS or HashiCorp Vault. Auto-seeded as the initial default kms_provider
// by db/init.js boot path so existing R3d-1/R3d-2/R3d-3 backups keep
// working without operator intervention.
//
// CONFIG SCHEMA (kms_providers.config JSON for env-var rows)
//
//   {
//     "env_var_name": "TIER1_ENCRYPTION_KEY"
//   }
//
// env_var_name: the name of the process env var holding the hex-encoded
// 32-byte KEK. Must match the conventional shell env var pattern
// (^[A-Z][A-Z0-9_]*$). Default seeded value is 'TIER1_ENCRYPTION_KEY'
// (the same KEK used elsewhere for integration credentials and signing
// keys).
//
// Operators with stricter key-rotation requirements can configure
// additional env-var providers pointing at different env vars (e.g.
// 'BACKUP_KEK_2026Q2') and rotate the default. The old provider stays
// in the table so old backups remain unwrappable.
//
// CREDENTIALS
//
// Env-var providers do NOT use credentials_encrypted. The KEK IS the
// env var; there's nothing to encrypt and store separately.
// validateCredentials rejects any non-null credentials.
//
// WRAP/UNWRAP FORMAT
//
// wrap() returns a Buffer of raw AES-256-GCM output:
//
//   iv (12 bytes) || tag (16 bytes) || ciphertext (32 bytes for a
//                                                 32-byte plaintext DEK)
//
// = 60 bytes total. The dispatcher (commits 20-21) base64-encodes
// this and embeds it in the wrapped-key.bin envelope:
//
//   { "v": 1, "scheme": "env-var", "ref": "<env_var_name>",
//     "wrapped": "<base64 of wrap() output>" }
//
// Adapters do not interpret each other's formats. The dispatcher
// reads scheme + ref from the envelope to route unwrap to this
// provider with the right config.
//
// VALIDATION TIMING
//
// validateConfig only checks that env_var_name has the correct shape
// (^[A-Z][A-Z0-9_]*$). It does NOT check that the env var is currently
// set or that its value is a valid 32-byte hex KEK -- env vars can be
// added or rotated between provider creation and first use, so deferred
// validation in wrap/unwrap handles those cases with precise error
// messages. probe() catches both classes of failure at provider-create
// time by performing a real round-trip.
//
// ERRORS
//
// All wrap/unwrap failures throw KeyWrappingError with retryable=false.
// Env-var errors are ALWAYS permanent: a missing env var stays missing
// until the operator adds it; a malformed KEK stays malformed; an auth-
// tag mismatch on unwrap means the wrong key, which no retry can fix.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const base = require('./base');
const tier1Kek = require('../tier1-kek');

const PROVIDER_NAME = 'env-var';
const SECURITY_TIER = 3;

// AES-256-GCM constants matching R3d-1
const ENC_ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH_BYTES = 32;     // AES-256
const IV_LENGTH_BYTES = 12;      // GCM standard
const TAG_LENGTH_BYTES = 16;     // GCM standard

const ENV_VAR_NAME_PATTERN = /^[A-Z][A-Z0-9_]*$/;

// ── KEK retrieval ────────────────────────────────────────────────────────
//
// Reads the KEK from the named env var. Validates name format, presence,
// non-placeholder, hex format, and 32-byte length. Throws KeyWrappingError
// with operation='wrap' or 'unwrap' as set by caller.

function readEnvVarKek(envVarName, operation) {
  if (typeof envVarName !== 'string' || !ENV_VAR_NAME_PATTERN.test(envVarName)) {
    throw new base.KeyWrappingError(
      `env_var_name '${envVarName}' is not a valid env var name`,
      { provider: PROVIDER_NAME, operation, retryable: false },
    );
  }
  // The FireAlive Tier-1 KEK is hardware-sealed and fail-closed (decision D26):
  // resolve TIER1_ENCRYPTION_KEY by unsealing it on this hardware rather than
  // reading a raw hex key. A backup wrapped under it can only be unwrapped with
  // the same KEK -- from the original hardware or the offline recovery code.
  // Return a copy: the resolver caches the KEK, and wrap/unwrap zero their local
  // reference after use, which must not corrupt that cache.
  if (envVarName === 'TIER1_ENCRYPTION_KEY') {
    try {
      return Buffer.from(tier1Kek.resolveTier1Kek());
    } catch (err) {
      throw new base.KeyWrappingError(
        err && err.message ? err.message : String(err),
        { provider: PROVIDER_NAME, operation, retryable: false, detail: { reason: 'hardware-sealed-kek' } },
      );
    }
  }
  const hex = process.env[envVarName];
  if (!hex) {
    throw new base.KeyWrappingError(
      `env var ${envVarName} is not set`,
      { provider: PROVIDER_NAME, operation, retryable: false, detail: { reason: 'missing' } },
    );
  }
  if (hex === 'CHANGE_ME' || hex.startsWith('CHANGE_ME')) {
    throw new base.KeyWrappingError(
      `env var ${envVarName} is set to a placeholder; generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`,
      { provider: PROVIDER_NAME, operation, retryable: false, detail: { reason: 'placeholder' } },
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new base.KeyWrappingError(
      `env var ${envVarName} is not valid hex`,
      { provider: PROVIDER_NAME, operation, retryable: false, detail: { reason: 'malformed-hex' } },
    );
  }
  const key = Buffer.from(hex, 'hex');
  if (key.length !== KEY_LENGTH_BYTES) {
    throw new base.KeyWrappingError(
      `env var ${envVarName} decoded to ${key.length} bytes, expected ${KEY_LENGTH_BYTES}`,
      { provider: PROVIDER_NAME, operation, retryable: false, detail: { reason: 'wrong-length', got: key.length, expected: KEY_LENGTH_BYTES } },
    );
  }
  return key;
}

// ── Provider interface implementations ───────────────────────────────────

function validateConfig(config) {
  if (!config || typeof config !== 'object') {
    return { ok: false, error: 'config must be a JSON object', field: 'config' };
  }
  const r = base.requireString(config, 'env_var_name', { maxLength: 128, pattern: ENV_VAR_NAME_PATTERN });
  if (!r.ok) {
    // Override the error with a more env-var-specific message
    return {
      ok: false,
      error: `env_var_name must match ${ENV_VAR_NAME_PATTERN} (uppercase, digits, underscore, starts with letter)`,
      field: 'env_var_name',
    };
  }
  // Reject any unexpected extra fields to catch typos that would
  // otherwise be silently ignored.
  const extras = Object.keys(config).filter(k => k !== 'env_var_name');
  if (extras.length > 0) {
    return {
      ok: false,
      error: `unexpected fields in config: ${extras.join(', ')}`,
      field: extras[0],
    };
  }
  return { ok: true };
}

function validateCredentials(credentials) {
  // env-var providers don't use stored credentials. The KEK IS the env var.
  if (credentials === null || credentials === undefined) return { ok: true };
  if (typeof credentials === 'object' && Object.keys(credentials).length === 0) return { ok: true };
  return {
    ok: false,
    error: 'env-var provider does not accept credentials (KEK is read from process env at wrap/unwrap time)',
    field: 'credentials',
  };
}

async function wrap(plaintextDek, config, credentials, options) {
  // Inputs
  if (!Buffer.isBuffer(plaintextDek) || plaintextDek.length !== KEY_LENGTH_BYTES) {
    throw new base.KeyWrappingError(
      `plaintextDek must be a ${KEY_LENGTH_BYTES}-byte Buffer (got ${Buffer.isBuffer(plaintextDek) ? plaintextDek.length + ' bytes' : typeof plaintextDek})`,
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: false },
    );
  }
  const cv = validateConfig(config);
  if (!cv.ok) {
    throw new base.KeyWrappingError(cv.error, { provider: PROVIDER_NAME, operation: 'wrap', retryable: false, detail: { field: cv.field } });
  }

  const kek = readEnvVarKek(config.env_var_name, 'wrap');
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ENC_ALGORITHM, kek, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintextDek), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Zero out the local KEK reference as best-effort defense; Node's
  // GC may still hold copies elsewhere, but this signals intent.
  kek.fill(0);
  return Buffer.concat([iv, authTag, ciphertext]);
}

async function unwrap(wrappedDek, config, credentials, options) {
  if (!Buffer.isBuffer(wrappedDek)) {
    throw new base.KeyWrappingError(
      `wrappedDek must be a Buffer (got ${typeof wrappedDek})`,
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  const minLength = IV_LENGTH_BYTES + TAG_LENGTH_BYTES + KEY_LENGTH_BYTES;
  if (wrappedDek.length < minLength) {
    throw new base.KeyWrappingError(
      `wrappedDek too short (got ${wrappedDek.length}, need at least ${minLength})`,
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false, detail: { reason: 'truncated' } },
    );
  }
  const cv = validateConfig(config);
  if (!cv.ok) {
    throw new base.KeyWrappingError(cv.error, { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false, detail: { field: cv.field } });
  }

  const iv = wrappedDek.subarray(0, IV_LENGTH_BYTES);
  const authTag = wrappedDek.subarray(IV_LENGTH_BYTES, IV_LENGTH_BYTES + TAG_LENGTH_BYTES);
  const ciphertext = wrappedDek.subarray(IV_LENGTH_BYTES + TAG_LENGTH_BYTES);

  const kek = readEnvVarKek(config.env_var_name, 'unwrap');
  const decipher = crypto.createDecipheriv(ENC_ALGORITHM, kek, iv);
  decipher.setAuthTag(authTag);

  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    kek.fill(0);
    // Auth tag mismatch -- wrong KEK or tampered wrapped bytes. Always permanent.
    throw new base.KeyWrappingError(
      `AES-GCM unwrap failed (likely wrong KEK or tampered wrapped-key): ${err.message}`,
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false, detail: { reason: 'auth-tag-mismatch' }, cause: err },
    );
  }
  kek.fill(0);

  if (plaintext.length !== KEY_LENGTH_BYTES) {
    throw new base.KeyWrappingError(
      `unwrapped DEK has unexpected length ${plaintext.length} (expected ${KEY_LENGTH_BYTES})`,
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false, detail: { reason: 'wrong-length' } },
    );
  }
  return plaintext;
}

async function probe(config, credentials, options) {
  const cv = validateConfig(config);
  if (!cv.ok) return { ok: false, error: cv.error, detail: { field: cv.field, phase: 'config' } };
  return base.probeRoundTrip(provider, config, credentials, options);
}

// ── Provider object + registration ───────────────────────────────────────

// D-R2-4: a one-way fingerprint of the KEK this provider wraps under. The env-var KEK is local
// 32-byte material (readEnvVarKek resolves the same key wrap/unwrap use, including the tier1Kek
// default), so fingerprint the material -- it never appears in the manifest.
function kekFingerprint(config) {
  const kek = readEnvVarKek((config || {}).env_var_name, 'kek-fingerprint');
  return base.kekFpFromMaterial(kek);
}

// D-R2-2: unwrap a wrapped DEK with a PROVIDED raw KEK instead of the env var. Used ONLY by the
// offline import-rekey tool, where the source KEK is recovered transiently from the source
// recovery code and the DEK was wrapped under it. Same envelope format as unwrap
// (iv || tag || ciphertext, AES-256-GCM); the raw KEK is the caller's to scrub.
function unwrapWithRawKek(wrappedDek, rawKek) {
  if (!Buffer.isBuffer(wrappedDek)) {
    throw new Error('env-var unwrapWithRawKek: wrappedDek must be a Buffer');
  }
  if (!Buffer.isBuffer(rawKek) || rawKek.length !== KEY_LENGTH_BYTES) {
    throw new Error('env-var unwrapWithRawKek: rawKek must be a ' + KEY_LENGTH_BYTES + '-byte Buffer');
  }
  const iv = wrappedDek.subarray(0, IV_LENGTH_BYTES);
  const authTag = wrappedDek.subarray(IV_LENGTH_BYTES, IV_LENGTH_BYTES + TAG_LENGTH_BYTES);
  const ciphertext = wrappedDek.subarray(IV_LENGTH_BYTES + TAG_LENGTH_BYTES);
  const decipher = crypto.createDecipheriv(ENC_ALGORITHM, rawKek, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

const provider = {
  name: PROVIDER_NAME,
  description: 'KEK from process env var (TIER1_ENCRYPTION_KEY by default). Tier 3 -- KEK lives in process memory.',
  securityTier: SECURITY_TIER,
  validateConfig,
  validateCredentials,
  probe,
  wrap,
  unwrap,
  unwrapWithRawKek,
  kekFingerprint,
};

base.registerProvider(provider);

module.exports = provider;

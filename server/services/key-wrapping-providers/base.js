// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Key Wrapping Provider Base
//
// Common interface, registry, and helpers for KEK (key encryption key)
// providers. Each provider (env-var, AWS KMS, Azure Key Vault, GCP KMS,
// HashiCorp Vault) implements the interface contract documented below
// and registers itself via registerProvider() at module-load time.
//
// THE KEY WRAPPING DISPATCHER (services/backup-key-wrapping.js, refactored
// in commits 20-21 of this phase) routes wrap/unwrap calls through this
// registry based on the configured kms_providers.provider_type.
//
// PROVIDER INTERFACE (each provider module exports ONE object with these
// fields, then calls registerProvider at end of module):
//
//   name: string
//     Lowercase identifier matching kms_providers.provider_type:
//     'env-var' | 'aws-kms' | 'azure-keyvault' | 'gcp-kms' |
//     'hashicorp-vault'
//
//   description: string
//     Short human-readable description shown in admin UI.
//
//   securityTier: number
//     1 (HSM-backed, never-extractable, e.g. PKCS#11 future)
//     2 (cloud KMS / Vault transit -- KEK never leaves provider HSM)
//     3 (KEK in process memory, e.g. env-var)
//     For SOC operator decision-making in the admin UI picker.
//
//   validateConfig(config) -> { ok, error?, field? }
//     Synchronous validation of the config JSON object. Return
//     { ok: true } if valid, { ok: false, error, field } otherwise.
//     Field optional but helps admin UI highlight the offending input.
//
//   validateCredentials(credentials) -> { ok, error?, field? }
//     Synchronous validation of the credentials object. May return
//     { ok: true } if the provider supports a no-credentials mode
//     (e.g., env-var; cloud SDKs falling back to instance metadata).
//
//   async probe(config, credentials) -> { ok, error?, detail? }
//     Round-trip test: wrap a known plaintext, unwrap it, verify
//     bytes match. Surfaces config errors before the first real
//     wrap operation. Should be FAST (ideally <5s); cloud KMS
//     providers should set per-call timeouts.
//
//   async wrap(plaintextDek, config, credentials, options) -> Buffer
//     The core wrap operation. Inputs:
//       plaintextDek: Buffer of raw DEK bytes (typically 32 for AES-256)
//       config: parsed JSON config object
//       credentials: decrypted credentials object or null
//       options: { logger, signal, timeoutMs }
//     Returns: Buffer in provider-specific format. Format details:
//       env-var:        iv(12) + tag(16) + ciphertext  (AES-GCM)
//       aws-kms:        AWS KMS ciphertext blob (opaque to us)
//       azure-keyvault: Azure Key Vault ciphertext blob (opaque)
//       gcp-kms:        GCP KMS ciphertext blob (opaque)
//       hashicorp-vault Vault transit response with key version prefix
//     Adapters never interpret each other's formats. The manifest's
//     key_wrapping.scheme field tells unwrap-time which provider to
//     dispatch to.
//     Throws KeyWrappingError on failure. The error's retryable flag
//     tells callers whether to retry (transient) or give up (permanent).
//
//   async unwrap(wrappedDek, config, credentials, options) -> Buffer
//     The inverse of wrap. Inputs:
//       wrappedDek: Buffer in the same format produced by wrap
//       config + credentials: same shape as wrap
//       options: same shape as wrap
//     Returns: plaintext DEK Buffer (raw bytes).
//     Throws KeyWrappingError on failure. UnwrapAuth failures are
//     ALWAYS permanent (key not found, wrong KMS key, etc.) -- no
//     amount of retrying makes a wrong key correct.
//
// REGISTRY
//
// Provider modules call registerProvider(provider) at end of module
// load. The dispatcher looks up providers via getProvider(name).
// listProviders() returns metadata for the admin UI picker.
//
// SECURITY-TIER CRITERIA (for the admin UI to display warnings)
//
// Tier 1 (HSM): KEK in dedicated tamper-evident hardware that physically
//   cannot extract the key (PKCS#11 with appropriate token). Reserved
//   for future R3d-5+ providers; no R3d-4 provider declares Tier 1.
//
// Tier 2 (cloud KMS / Vault): KEK in cloud provider's HSM (FIPS 140-2
//   Level 3 in eligible regions) or self-hosted Vault transit engine.
//   The KEK never leaves the provider's HSM/vault; only ciphertext
//   crosses the network. Includes aws-kms, azure-keyvault, gcp-kms,
//   hashicorp-vault.
//
// Tier 3 (env-var): KEK exists in the FireAlive process's environment
//   variable, readable by any process running as the same user.
//   Operator's responsibility to inject from a secrets manager. Last-
//   resort fallback; default for backward compatibility.
// ═══════════════════════════════════════════════════════════════════════════════

const VALID_PROVIDER_NAMES = new Set([
  'env-var',
  'aws-kms',
  'azure-keyvault',
  'gcp-kms',
  'hashicorp-vault',
]);

const VALID_SECURITY_TIERS = new Set([1, 2, 3]);

// ── Error class ──────────────────────────────────────────────────────────

/**
 * Error thrown by provider operations. Carries:
 *
 *   provider     string  the provider name that threw
 *   operation    string  'probe' | 'wrap' | 'unwrap' | 'validate*'
 *   retryable    bool    true for transient failures (network, throttling,
 *                        5xx); false for permanent (auth, key-not-found,
 *                        malformed-input). Unwrap auth failures are
 *                        ALWAYS permanent: no retry helps when the
 *                        key reference is wrong.
 *   detail       any     provider-specific extras (status code, request id)
 *
 * The Error subclass carries cause via standard Error options so stack
 * traces survive chaining.
 */
class KeyWrappingError extends Error {
  constructor(message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'KeyWrappingError';
    this.provider = options.provider || 'unknown';
    this.operation = options.operation || 'unknown';
    this.retryable = options.retryable === true;   // default false
    this.detail = options.detail || null;
  }
}

// ── Registry ─────────────────────────────────────────────────────────────

const providerRegistry = new Map();

// Domain separation for backup KEK fingerprints (D-R2-4). A provider's kekFingerprint()
// returns one of these two forms; backup-manifest then salts it per backup_id, so the value
// in the manifest is non-correlatable across backups.
//
//   kekFingerprint(config, credentials) -> lowercase-hex string   (NEW provider method)
//     A stable, one-way fingerprint of the KEK this provider wraps under. env-var fingerprints
//     the raw material; cloud KMS fingerprints the stable key reference (the material never
//     leaves the HSM). It lets a restore confirm the target's KEK matches the backup's WITHOUT
//     unwrapping anything. (Enforced in registerProvider only once every provider implements it.)
const cryptoMod = require('crypto');
const FA_BACKUP_KEK_DOMAIN = 'fa-backup-kek:v1';

// Fingerprint of raw KEK MATERIAL (env-var scheme: the 32-byte KEK itself). The material never
// appears in the manifest -- only this domain-separated SHA-256, hex.
function kekFpFromMaterial(materialBuffer) {
  if (!Buffer.isBuffer(materialBuffer) || materialBuffer.length === 0) {
    throw new Error('kekFpFromMaterial: materialBuffer must be a non-empty Buffer');
  }
  return cryptoMod.createHash('sha256')
    .update(Buffer.concat([Buffer.from(FA_BACKUP_KEK_DOMAIN + '|material|'), materialBuffer]))
    .digest('hex');
}

// Fingerprint of a stable KEK REFERENCE (cloud KMS: the key ARN / URL / resource name). The
// KEK material stays in the HSM; the reference is the stable identifier. Domain-separated
// SHA-256, hex.
function kekFpFromReference(reference) {
  if (typeof reference !== 'string' || reference === '') {
    throw new Error('kekFpFromReference: reference must be a non-empty string');
  }
  return cryptoMod.createHash('sha256')
    .update(FA_BACKUP_KEK_DOMAIN + '|reference|' + reference, 'utf-8')
    .digest('hex');
}

function registerProvider(provider) {
  if (!provider || typeof provider !== 'object') {
    throw new Error('registerProvider: provider must be an object');
  }
  if (!VALID_PROVIDER_NAMES.has(provider.name)) {
    throw new Error(`registerProvider: invalid provider name '${provider.name}' (must be one of: ${[...VALID_PROVIDER_NAMES].join(', ')})`);
  }
  for (const required of ['validateConfig', 'validateCredentials', 'probe', 'wrap', 'unwrap']) {
    if (typeof provider[required] !== 'function') {
      throw new Error(`registerProvider: provider '${provider.name}' missing required method '${required}'`);
    }
  }
  if (!VALID_SECURITY_TIERS.has(provider.securityTier)) {
    throw new Error(`registerProvider: provider '${provider.name}' must declare securityTier in {1, 2, 3}`);
  }
  providerRegistry.set(provider.name, provider);
}

function getProvider(name) {
  return providerRegistry.get(name) || null;
}

function listProviders() {
  return [...providerRegistry.values()].map(p => ({
    name: p.name,
    description: p.description || '',
    securityTier: p.securityTier,
  }));
}

function clearRegistry() {
  // Exposed for tests; not used in production
  providerRegistry.clear();
}

// ── Shared validation helpers ────────────────────────────────────────────
//
// Providers use these for common config patterns. Same pattern as
// destination-adapter-base.js (R3d-3 commit 3).

/**
 * Validate that a value is a non-empty string. Returns
 * { ok: false, error, field } on failure or { ok: true } on success.
 */
function requireString(obj, key, opts = {}) {
  const value = obj && obj[key];
  if (typeof value !== 'string' || value === '') {
    return { ok: false, error: `${key} required (must be non-empty string)`, field: key };
  }
  if (opts.maxLength && value.length > opts.maxLength) {
    return { ok: false, error: `${key} exceeds max length ${opts.maxLength}`, field: key };
  }
  if (opts.pattern && !opts.pattern.test(value)) {
    return { ok: false, error: `${key} does not match expected format`, field: key };
  }
  return { ok: true };
}

/**
 * Validate that a value is one of the allowed enum values.
 */
function requireEnum(obj, key, allowedValues) {
  const value = obj && obj[key];
  if (!allowedValues.includes(value)) {
    return {
      ok: false,
      error: `${key} must be one of: ${allowedValues.join(', ')}`,
      field: key,
    };
  }
  return { ok: true };
}

/**
 * Validate that a value is an integer in [min, max].
 */
function requireInt(obj, key, min, max) {
  const value = obj && obj[key];
  if (!Number.isInteger(value)) {
    return { ok: false, error: `${key} required (must be integer)`, field: key };
  }
  if (value < min || value > max) {
    return { ok: false, error: `${key} must be in range [${min}, ${max}]`, field: key };
  }
  return { ok: true };
}

/**
 * Validate that a value is a URL. Loose check: must parse as a URL,
 * scheme must be http/https. Tighter checks (TLS-only, host whitelist)
 * are operator-policy concerns left to the deployment.
 */
function requireUrl(obj, key, opts = {}) {
  const value = obj && obj[key];
  if (typeof value !== 'string' || value === '') {
    return { ok: false, error: `${key} required (must be URL string)`, field: key };
  }
  let parsed;
  try { parsed = new URL(value); } catch {
    return { ok: false, error: `${key} is not a valid URL`, field: key };
  }
  const allowedSchemes = opts.schemes || ['http:', 'https:'];
  if (!allowedSchemes.includes(parsed.protocol)) {
    return { ok: false, error: `${key} must use scheme: ${allowedSchemes.map(s => s.replace(':','')).join(' or ')}`, field: key };
  }
  return { ok: true };
}

/**
 * Round-trip probe helper. Generates a fresh test plaintext, calls
 * wrap then unwrap, verifies the bytes match. Returns the standard
 * { ok, error?, detail? } shape.
 *
 * Providers can use this in their probe() implementation to share
 * the round-trip test logic. They still need to construct any
 * provider-specific connectivity pre-checks (network reachability,
 * etc.) before calling this.
 */
async function probeRoundTrip(provider, config, credentials, options = {}) {
  const crypto = require('crypto');
  const testPlaintext = crypto.randomBytes(32);
  let wrapped, recovered;
  try {
    wrapped = await provider.wrap(testPlaintext, config, credentials, options);
  } catch (err) {
    return { ok: false, error: `probe wrap failed: ${err.message}`, detail: { phase: 'wrap', cause: err.detail } };
  }
  if (!Buffer.isBuffer(wrapped) || wrapped.length === 0) {
    return { ok: false, error: 'probe wrap returned non-Buffer or empty result', detail: { phase: 'wrap-format' } };
  }
  try {
    recovered = await provider.unwrap(wrapped, config, credentials, options);
  } catch (err) {
    return { ok: false, error: `probe unwrap failed: ${err.message}`, detail: { phase: 'unwrap', cause: err.detail } };
  }
  if (!Buffer.isBuffer(recovered) || !recovered.equals(testPlaintext)) {
    return { ok: false, error: 'probe round-trip recovered bytes did not match', detail: { phase: 'compare' } };
  }
  return { ok: true, detail: { wrappedBytes: wrapped.length } };
}

// ── Module exports ───────────────────────────────────────────────────────

module.exports = {
  FA_BACKUP_KEK_DOMAIN,
  kekFpFromMaterial,
  kekFpFromReference,
  // Error class
  KeyWrappingError,

  // Registry
  registerProvider,
  getProvider,
  listProviders,
  clearRegistry,

  // Validation helpers
  requireString,
  requireEnum,
  requireInt,
  requireUrl,
  probeRoundTrip,

  // Constants
  VALID_PROVIDER_NAMES: [...VALID_PROVIDER_NAMES],
  VALID_SECURITY_TIERS: [...VALID_SECURITY_TIERS],
};

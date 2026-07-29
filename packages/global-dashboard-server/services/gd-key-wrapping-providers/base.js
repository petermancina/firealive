// =============================================================================
// FIREALIVE GD -- key-wrapping provider registry base  [B6g]
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
//
// The GD twin of server/services/key-wrapping-providers/base.js. Derived from it
// rather than hand-written: same contract, same validation helpers, same
// registry semantics, and 341 lines meant to be identical are how two
// implementations drift apart.
//
// The GD server is fully self-contained -- no local package dependency, never
// requires from server/, and 86 of its services are twins of a server/services
// file. A shared module is not available here, so the twin is the mechanism.
//
// TWO THINGS DIFFER FROM THE REGIONAL SERVER'S COPY, both deliberate:
//
//   'gd-tier1' replaces 'env-var' as the local scheme. Not a rename. The MC's
//   env-var KEK is a hex string in the process environment; the GD's Tier-1 KEK
//   is hardware-sealed to this host's TPM 2.0 / Secure Enclave and a copied disk
//   cannot unseal it.
//
//   FA_BACKUP_KEK_DOMAIN is unchanged, and that matters for compatibility rather
//   than symmetry: the domain separator only ever appears inside a fingerprint,
//   and the GD's EXISTING gd-tier1 manifests do not use it at all -- they record
//   gdTier1Kek.ownKekFingerprint() directly. The gd-tier1 provider must keep
//   doing that, or every manifest already written fails its fingerprint check.
//   The domain is used only by the four cloud providers, which are new here.
//

const VALID_PROVIDER_NAMES = new Set([
  // The GD's local scheme. The Regional Server's equivalent is 'env-var', whose
  // KEK is a hex string in the process environment; the GD's is the Tier-1 KEK,
  // hardware-sealed to this host's TPM 2.0 / Secure Enclave. Not a rename -- a
  // different and stronger thing, which is why the name differs.
  'gd-tier1',
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
//     A stable, one-way fingerprint of the KEK this provider wraps under. gd-tier1 fingerprints
//     the raw material; cloud KMS fingerprints the stable key reference (the material never
//     leaves the HSM). It lets a restore confirm the target's KEK matches the backup's WITHOUT
//     unwrapping anything. (Enforced in registerProvider only once every provider implements it.)
const cryptoMod = require('crypto');
const FA_BACKUP_KEK_DOMAIN = 'fa-backup-kek:v1';

// Fingerprint of raw KEK MATERIAL (raw KEK material). The material never
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
  for (const required of ['validateConfig', 'validateCredentials', 'probe', 'wrap', 'unwrap', 'kekFingerprint']) {
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
// B6g: `opts.allowListEnv` names the environment variable holding the
// authorised hosts. When supplied, the URL's host must appear in it exactly.
// Callers that omit it get scheme validation only -- which is what this did
// for every caller before B6g, and is why an operator could point a KMS
// provider at cloud instance metadata.
const endpointAllowList = require('./endpoint-allow-list');

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
  // B6g: the host check. Scheme alone let an operator point a provider at
    // https://169.254.169.254/ and have the server fetch it with credentials.
    if (opts.allowListEnv) {
      const check = endpointAllowList.checkEndpoint(value, opts.allowListEnv, opts.env);
      if (!check.ok) return { ok: false, error: `${key}: ${check.error}`, field: key };
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

  // B6g: endpoint host allow-list, re-exported so providers reach it on the
  // wrap and unwrap paths without a second require.
  checkEndpoint: endpointAllowList.checkEndpoint,
  allowedHosts: endpointAllowList.allowedHosts,

  // Constants
  VALID_PROVIDER_NAMES: [...VALID_PROVIDER_NAMES],
  VALID_SECURITY_TIERS: [...VALID_SECURITY_TIERS],
};

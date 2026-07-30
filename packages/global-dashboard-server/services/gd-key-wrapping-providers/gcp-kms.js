// =============================================================================
// FIREALIVE GD -- gcp-kms key-wrapping provider  [B6g]
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
//
// The GD twin of server/services/key-wrapping-providers/gcp-kms.js.
// Derived from it, every substitution asserted -- the contract, the SDK calls
// and the error taxonomy are identical, and four 400-line files meant to be the
// same are how two implementations drift.
//
// ONE FUNCTIONAL DIFFERENCE: the endpoint allow-list reads GD_KMS_ALLOWED_HOSTS,
// not KMS_ALLOWED_HOSTS. Separate trust realms get separate allow-lists, and the
// Regional Server's list authorises nothing here -- asserted by test.
//
// WHAT THIS PROVIDER WRAPS: the per-backup ephemeral data key, and only that.
// It does not wrap the GD Tier-1 KEK, and the Tier-1 KEK is escrowed to no
// provider anywhere. A key an IAM principal can unwrap over the network is a key
// a compromised deployment can unwrap over the network, which would reduce the
// anti-clone guarantee from what the TPM is worth to what the cloud IAM policy is
// worth. This is custody of the archive key. It is not disaster recovery.
//

const base = require('./base');

const PROVIDER_NAME = 'gcp-kms';
const SECURITY_TIER = 2;

const VALID_PROJECT_ID_PATTERN = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const VALID_LOCATION_PATTERN = /^[a-z][a-z0-9-]+$/;
const VALID_KEY_NAME_PATTERN = /^[a-zA-Z0-9_-]{1,63}$/;
const VALID_KEY_VERSION_PATTERN = /^[1-9][0-9]*$/;   // positive integer

// ── SDK loading (lazy + test-overridable) ─────────────────────────────────

let _sdkOverride = null;

function _setSdkForTest(sdk) {
  _sdkOverride = sdk;
}

function _getSdk() {
  if (_sdkOverride) return _sdkOverride;
  try {
    // eslint-disable-next-line global-require
    return require('@google-cloud/kms');
  } catch (err) {
    throw new base.KeyWrappingError(
      "@google-cloud/kms not installed; run: npm install @google-cloud/kms",
      { provider: PROVIDER_NAME, operation: 'sdk-load', retryable: false, cause: err },
    );
  }
}

// ── Retryable classification ──────────────────────────────────────────────
//
// GCP errors carry .code (numeric gRPC code OR HTTP status), .message,
// .details. The Google Cloud Node client surfaces both shapes depending
// on transport.

const RETRYABLE_GRPC_CODES = new Set([
  1,   // CANCELLED
  4,   // DEADLINE_EXCEEDED
  8,   // RESOURCE_EXHAUSTED (throttling)
  10,  // ABORTED
  13,  // INTERNAL
  14,  // UNAVAILABLE
]);

const PERMANENT_GRPC_CODES = new Set([
  3,   // INVALID_ARGUMENT
  5,   // NOT_FOUND
  6,   // ALREADY_EXISTS
  7,   // PERMISSION_DENIED
  9,   // FAILED_PRECONDITION
  11,  // OUT_OF_RANGE
  12,  // UNIMPLEMENTED
  16,  // UNAUTHENTICATED
]);

function isRetryableGcpError(err) {
  if (!err) return false;
  if (typeof err.code === 'number') {
    if (RETRYABLE_GRPC_CODES.has(err.code)) return true;
    if (PERMANENT_GRPC_CODES.has(err.code)) return false;
    // Numeric HTTP status (when client uses HTTP transport)
    if (err.code === 429) return true;
    if (err.code >= 500 && err.code < 600) return true;
    if (err.code >= 400 && err.code < 500) return false;
  }
  // Node socket errors
  if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT' ||
      err.code === 'ENETUNREACH' || err.code === 'ENOTFOUND' ||
      err.code === 'EAI_AGAIN') return true;
  // Default: permanent (safer than auto-retry on the unknown)
  return false;
}

// ── Provider interface implementations ────────────────────────────────────

function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ok: false, error: 'config must be a JSON object', field: 'config' };
  }

  let r = base.requireString(config, 'project_id', { maxLength: 30, pattern: VALID_PROJECT_ID_PATTERN });
  if (!r.ok) return { ok: false, error: 'project_id must be 6-30 lowercase chars (letters, digits, dashes); start with letter, end with letter or digit', field: 'project_id' };

  r = base.requireString(config, 'location_id', { maxLength: 64, pattern: VALID_LOCATION_PATTERN });
  if (!r.ok) return { ok: false, error: 'location_id must be lowercase token (e.g. us-east1, europe-west1, global)', field: 'location_id' };

  r = base.requireString(config, 'key_ring_id', { maxLength: 63, pattern: VALID_KEY_NAME_PATTERN });
  if (!r.ok) return { ok: false, error: 'key_ring_id must be 1-63 chars (alphanumeric, hyphens, underscores)', field: 'key_ring_id' };

  r = base.requireString(config, 'key_id', { maxLength: 63, pattern: VALID_KEY_NAME_PATTERN });
  if (!r.ok) return { ok: false, error: 'key_id must be 1-63 chars (alphanumeric, hyphens, underscores)', field: 'key_id' };

  if (config.key_version !== undefined && config.key_version !== null) {
    if (typeof config.key_version !== 'string' || !VALID_KEY_VERSION_PATTERN.test(config.key_version)) {
      return { ok: false, error: 'key_version must be a positive integer string (e.g. "3")', field: 'key_version' };
    }
  }

  if (config.additional_aad_b64 !== undefined && config.additional_aad_b64 !== null) {
    if (typeof config.additional_aad_b64 !== 'string' || config.additional_aad_b64.length === 0) {
      return { ok: false, error: 'additional_aad_b64 must be non-empty base64 string', field: 'additional_aad_b64' };
    }
    try {
      const decoded = Buffer.from(config.additional_aad_b64, 'base64');
      if (decoded.length === 0) {
        return { ok: false, error: 'additional_aad_b64 decoded to empty bytes', field: 'additional_aad_b64' };
      }
    } catch {
      return { ok: false, error: 'additional_aad_b64 is not valid base64', field: 'additional_aad_b64' };
    }
  }

  // Reject unexpected fields (typo defense)
  const allowed = new Set(['project_id', 'location_id', 'key_ring_id', 'key_id', 'key_version', 'additional_aad_b64']);
  for (const k of Object.keys(config)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in config: ${k}`, field: k };
    }
  }
  return { ok: true };
}

function validateCredentials(credentials) {
  if (credentials === null || credentials === undefined) return { ok: true };
  if (typeof credentials !== 'object' || Array.isArray(credentials)) {
    return { ok: false, error: 'credentials must be a JSON object or null', field: 'credentials' };
  }
  if (Object.keys(credentials).length === 0) return { ok: true };

  if (credentials.service_account_json === undefined || credentials.service_account_json === null) {
    return { ok: false, error: 'service_account_json required', field: 'service_account_json' };
  }

  let parsed;
  if (typeof credentials.service_account_json === 'string') {
    try { parsed = JSON.parse(credentials.service_account_json); }
    catch (err) {
      return { ok: false, error: `service_account_json is not valid JSON: ${err.message}`, field: 'service_account_json' };
    }
  } else if (typeof credentials.service_account_json === 'object' && !Array.isArray(credentials.service_account_json)) {
    parsed = credentials.service_account_json;
  } else {
    return { ok: false, error: 'service_account_json must be a JSON string or object', field: 'service_account_json' };
  }

  if (typeof parsed.client_email !== 'string' || parsed.client_email === '') {
    return { ok: false, error: 'service_account_json.client_email required', field: 'service_account_json' };
  }
  if (typeof parsed.private_key !== 'string' || !parsed.private_key.includes('PRIVATE KEY')) {
    return { ok: false, error: 'service_account_json.private_key required (PEM PKCS#8 format)', field: 'service_account_json' };
  }
  if (parsed.type && parsed.type !== 'service_account') {
    return { ok: false, error: `service_account_json.type must be 'service_account' (got '${parsed.type}')`, field: 'service_account_json' };
  }

  const allowed = new Set(['service_account_json']);
  for (const k of Object.keys(credentials)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in credentials: ${k}`, field: k };
    }
  }
  return { ok: true };
}

function buildResourceName(config, includeVersion) {
  const ringPath = `projects/${config.project_id}/locations/${config.location_id}/keyRings/${config.key_ring_id}`;
  const keyPath = `${ringPath}/cryptoKeys/${config.key_id}`;
  if (includeVersion && config.key_version) {
    return `${keyPath}/cryptoKeyVersions/${config.key_version}`;
  }
  return keyPath;
}

function parseServiceAccountJson(credentials) {
  if (!credentials || typeof credentials !== 'object' || Object.keys(credentials).length === 0) {
    return null;
  }
  const sa = credentials.service_account_json;
  if (typeof sa === 'string') {
    return JSON.parse(sa);
  }
  return sa;
}

function buildClient(config, credentials) {
  const sdk = _getSdk();
  const sa = parseServiceAccountJson(credentials);
  const clientOptions = { projectId: config.project_id };
  if (sa) {
    clientOptions.credentials = {
      client_email: sa.client_email,
      private_key: sa.private_key,
    };
  }
  return new sdk.KeyManagementServiceClient(clientOptions);
}

async function wrap(plaintextDek, config, credentials, options = {}) {
  if (!Buffer.isBuffer(plaintextDek) || plaintextDek.length === 0) {
    throw new base.KeyWrappingError(
      'plaintextDek must be a non-empty Buffer',
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: false },
    );
  }
  const cv = validateConfig(config);
  if (!cv.ok) {
    throw new base.KeyWrappingError(cv.error, { provider: PROVIDER_NAME, operation: 'wrap', retryable: false, detail: { field: cv.field } });
  }

  const client = buildClient(config, credentials);
  const name = buildResourceName(config, true);   // include version if pinned

  const request = { name, plaintext: plaintextDek };
  if (config.additional_aad_b64) {
    request.additionalAuthenticatedData = Buffer.from(config.additional_aad_b64, 'base64');
  }

  let response;
  try {
    [response] = await client.encrypt(request);
  } catch (err) {
    throw new base.KeyWrappingError(
      `GCP KMS encrypt failed: ${err.message || err.code || 'unknown error'}`,
      {
        provider: PROVIDER_NAME,
        operation: 'wrap',
        retryable: isRetryableGcpError(err),
        detail: { code: err.code, name: err.name },
        cause: err,
      },
    );
  } finally {
    try { await client.close(); } catch { /* swallow */ }
  }

  if (!response.ciphertext || response.ciphertext.length === 0) {
    throw new base.KeyWrappingError(
      'GCP KMS returned empty ciphertext',
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: false },
    );
  }
  return Buffer.from(response.ciphertext);
}

async function unwrap(wrappedDek, config, credentials, options = {}) {
  if (!Buffer.isBuffer(wrappedDek) || wrappedDek.length === 0) {
    throw new base.KeyWrappingError(
      'wrappedDek must be a non-empty Buffer',
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  const cv = validateConfig(config);
  if (!cv.ok) {
    throw new base.KeyWrappingError(cv.error, { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false, detail: { field: cv.field } });
  }

  const client = buildClient(config, credentials);
  // Decrypt always uses bare cryptoKey name (no version) so old
  // ciphertext decrypts after rotation as long as the historical
  // version is still present.
  const name = buildResourceName(config, false);

  const request = { name, ciphertext: wrappedDek };
  if (config.additional_aad_b64) {
    request.additionalAuthenticatedData = Buffer.from(config.additional_aad_b64, 'base64');
  }

  let response;
  try {
    [response] = await client.decrypt(request);
  } catch (err) {
    throw new base.KeyWrappingError(
      `GCP KMS decrypt failed: ${err.message || err.code || 'unknown error'}`,
      {
        provider: PROVIDER_NAME,
        operation: 'unwrap',
        retryable: isRetryableGcpError(err),
        detail: { code: err.code, name: err.name },
        cause: err,
      },
    );
  } finally {
    try { await client.close(); } catch { /* swallow */ }
  }

  if (!response.plaintext || response.plaintext.length === 0) {
    throw new base.KeyWrappingError(
      'GCP KMS returned empty plaintext',
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  return Buffer.from(response.plaintext);
}

async function probe(config, credentials, options) {
  const cv = validateConfig(config);
  if (!cv.ok) return { ok: false, error: cv.error, detail: { field: cv.field, phase: 'config' } };
  const cre = validateCredentials(credentials);
  if (!cre.ok) return { ok: false, error: cre.error, detail: { field: cre.field, phase: 'credentials' } };
  return base.probeRoundTrip(provider, config, credentials, options);
}

// ── Provider object + registration ────────────────────────────────────────

// D-R2-4: the Cloud KMS KEK material stays in the HSM; fingerprint the stable cryptoKey resource
// name (the bare key Decrypt uses -- version excluded, matching the wrapped-envelope ref).
function kekFingerprint(config) {
  const c = config || {};
  if (!c.project_id || !c.location_id || !c.key_ring_id || !c.key_id) {
    throw new Error('gcp-kms kekFingerprint: project_id, location_id, key_ring_id, key_id required');
  }
  const ref = 'projects/' + String(c.project_id) + '/locations/' + String(c.location_id)
    + '/keyRings/' + String(c.key_ring_id) + '/cryptoKeys/' + String(c.key_id);
  return base.kekFpFromReference(ref);
}

const provider = {
  name: PROVIDER_NAME,
  description: 'Google Cloud KMS envelope encryption via @google-cloud/kms. Tier 2 -- KEK in Cloud HSM (FIPS 140-2 Level 3 in Cloud HSM regions).',
  securityTier: SECURITY_TIER,
  validateConfig,
  validateCredentials,
  probe,
  wrap,
  unwrap,
  kekFingerprint,
  // Test-only export
  _setSdkForTest,
};

base.registerProvider(provider);

module.exports = provider;

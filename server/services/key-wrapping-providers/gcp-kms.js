// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Google Cloud KMS Key Wrapping Provider
//
// Wraps and unwraps DEKs via Google Cloud Key Management Service using the
// @google-cloud/kms SDK. The KEK lives inside Cloud KMS (FIPS 140-2 Level
// 3 in Cloud HSM regions) and never leaves Google Cloud -- FireAlive sends
// plaintext DEK to client.encrypt, gets back ciphertext; for unwrap, sends
// ciphertext to client.decrypt, gets back plaintext DEK.
//
// Tier 2 security: KEK in cloud HSM. Same security tier as aws-kms,
// azure-keyvault, hashicorp-vault.
//
// CONFIG SCHEMA (kms_providers.config JSON for gcp-kms rows)
//
//   {
//     "project_id":  "my-gcp-project-12345",
//     "location_id": "us-east1",                 (or "global")
//     "key_ring_id": "firealive-keyring",
//     "key_id":      "firealive-backup-kek",
//     "key_version": "3",                          (optional integer-as-string)
//     "additional_aad_b64": "..."                  (optional; advanced)
//   }
//
// project_id:   GCP project ID hosting the keyring. Pattern:
//               6-30 chars, lowercase letters/digits/dashes, must
//               start with letter (GCP project ID rules).
//
// location_id:  GCP region where the keyring lives. Examples:
//               'us-east1', 'europe-west1', 'asia-southeast1', or
//               the special 'global' (multi-region with regulated
//               replication). We accept any non-empty lowercase
//               token; GCP rejects unknown locations at first call.
//
// key_ring_id:  Name of the keyring (1-63 chars, alphanumeric +
//               hyphens/underscores).
//
// key_id:       Name of the cryptoKey within the keyring (1-63
//               chars). The KEK material lives under this name as
//               one or more cryptoKeyVersions; GCP marks one as
//               "primary" which is used for encryption when no
//               version is specified.
//
// key_version:  Optional version pinning. If provided, encrypt
//               targets /cryptoKeyVersions/<version> (a specific
//               key generation). If omitted, encrypt uses the
//               primary version (recommended for operators with
//               GCP-managed automatic rotation).
//               Decrypt ALWAYS uses the bare cryptoKey resource
//               name, regardless of this field, so old ciphertext
//               continues to decrypt after rotation as long as
//               the historical version is still present (GCP
//               retains versions for the configured rotation
//               period unless explicitly destroyed).
//
// additional_aad_b64:
//               Optional base64-encoded byte string passed as
//               AdditionalAuthenticatedData on encrypt and
//               decrypt. Same purpose as AWS encryption_context
//               -- binds wrapped key to a use case. Different
//               AAD on decrypt -> permanent failure
//               (FailedPrecondition / INVALID_ARGUMENT).
//
// CREDENTIALS SCHEMA (kms_providers.credentials_encrypted)
//
// Either explicit service account:
//
//   {
//     "service_account_json": "<full JSON string>"
//   }
//
//   OR
//
//   {
//     "service_account_json": { ...full JSON object... }
//   }
//
// The full GCP service account JSON contains client_email +
// private_key (PEM PKCS#8) plus other metadata. Provider extracts
// the two required fields and passes them to the SDK.
//
// Or null/empty -> SDK uses Application Default Credentials (ADC):
//   1. GOOGLE_APPLICATION_CREDENTIALS env var pointing to file
//   2. GCE/GKE/Cloud Run metadata server (instance metadata)
//   3. User credentials from `gcloud auth application-default login`
//
// Recommended for FireAlive-on-GCE/GKE/CloudRun -- no GCP secrets
// in FireAlive database.
//
// WIRE FORMAT
//
// wrap() returns Buffer of GCP KMS ciphertext (opaque). The dispatcher
// (commits 20-21) base64-encodes and embeds in wrapped-key.bin envelope:
//
//   { "v": 1, "scheme": "gcp-kms",
//     "ref": "projects/.../cryptoKeys/firealive-backup-kek",
//     "wrapped": "<base64>" }
//
// SDK NOT YET INSTALLED
//
// @google-cloud/kms is added to package.json in commit 23. Until
// then, this module loads cleanly (require is lazy inside
// _getSdk()). Any wrap/unwrap call before then throws
// KeyWrappingError(operation='sdk-load') with "npm install
// @google-cloud/kms" instruction. Existing env-var/aws-kms/
// azure-keyvault rows continue working.
// ═══════════════════════════════════════════════════════════════════════════════

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

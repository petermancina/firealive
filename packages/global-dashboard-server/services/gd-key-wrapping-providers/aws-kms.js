// =============================================================================
// FIREALIVE GD -- aws-kms key-wrapping provider  [B6g]
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
//
// The GD twin of server/services/key-wrapping-providers/aws-kms.js.
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

const PROVIDER_NAME = 'aws-kms';
const SECURITY_TIER = 2;

const VALID_REGION_PATTERN = /^[a-z]{2,4}-[a-z]+-\d{1,2}$/;
const DEFAULT_TIMEOUT_MS = 10000;

// ── SDK loading (lazy + test-overridable) ─────────────────────────────────
//
// Production: lazy require('@aws-sdk/client-kms') on first call.
// Test: provider._setSdkForTest(mockSdk) injects a stub before first call.

let _sdkOverride = null;

function _setSdkForTest(sdk) {
  // Exposed for unit tests only. Pass null to clear.
  _sdkOverride = sdk;
}

function _getSdk() {
  if (_sdkOverride) return _sdkOverride;
  try {
    // eslint-disable-next-line global-require
    return require('@aws-sdk/client-kms');
  } catch (err) {
    throw new base.KeyWrappingError(
      "@aws-sdk/client-kms is not installed; run: npm install @aws-sdk/client-kms",
      { provider: PROVIDER_NAME, operation: 'sdk-load', retryable: false, cause: err },
    );
  }
}

// ── Retryable classification ──────────────────────────────────────────────
//
// AWS SDK errors carry .name (e.g. 'ThrottlingException') and
// .$metadata.httpStatusCode. Auth/permission/key-not-found errors are
// permanent (retrying with the same wrong reference won't help). Network,
// throttle, 5xx are retryable.

const RETRYABLE_AWS_ERROR_NAMES = new Set([
  'ThrottlingException',
  'KMSInternalException',
  'DependencyTimeoutException',
  'RequestTimeout',
  'TimeoutError',
  'NetworkingError',
  'KeyUnavailableException',
  'KMSInvalidStateException',
]);

const PERMANENT_AWS_ERROR_NAMES = new Set([
  'AccessDeniedException',
  'IncorrectKeyException',
  'InvalidCiphertextException',
  'InvalidGrantTokenException',
  'InvalidKeyUsageException',
  'NotFoundException',
  'DisabledException',
  'KMSInvalidSignatureException',
]);

function isRetryableAwsError(err) {
  if (!err) return false;
  if (err.name && RETRYABLE_AWS_ERROR_NAMES.has(err.name)) return true;
  if (err.name && PERMANENT_AWS_ERROR_NAMES.has(err.name)) return false;
  // HTTP 5xx => retryable, 4xx => permanent
  const status = err.$metadata && err.$metadata.httpStatusCode;
  if (typeof status === 'number') {
    if (status >= 500 && status < 600) return true;
    if (status >= 400 && status < 500) return false;
  }
  // Node socket errors
  if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT' ||
      err.code === 'ENETUNREACH' || err.code === 'ENOTFOUND' ||
      err.code === 'EAI_AGAIN') return true;
  // Default: permanent (safer to surface to operator than auto-retry indefinitely)
  return false;
}

// ── Provider interface implementations ────────────────────────────────────

function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ok: false, error: 'config must be a JSON object', field: 'config' };
  }
  let r = base.requireString(config, 'region', { maxLength: 32, pattern: VALID_REGION_PATTERN });
  if (!r.ok) {
    return { ok: false, error: r.error, field: 'region' };
  }
  r = base.requireString(config, 'key_id', { maxLength: 2048 });
  if (!r.ok) return { ok: false, error: r.error, field: 'key_id' };

  if (config.encryption_context !== undefined) {
    const ec = config.encryption_context;
    if (!ec || typeof ec !== 'object' || Array.isArray(ec)) {
      return { ok: false, error: 'encryption_context must be a JSON object', field: 'encryption_context' };
    }
    for (const [k, v] of Object.entries(ec)) {
      if (typeof v !== 'string' || v === '') {
        return { ok: false, error: `encryption_context.${k} must be a non-empty string`, field: 'encryption_context' };
      }
      if (typeof k !== 'string' || k === '' || k.length > 256) {
        return { ok: false, error: 'encryption_context keys must be non-empty strings (max 256 chars)', field: 'encryption_context' };
      }
    }
  }

  // Reject unexpected fields (typo defense)
  const allowed = new Set(['region', 'key_id', 'encryption_context']);
  for (const k of Object.keys(config)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in config: ${k}`, field: k };
    }
  }
  return { ok: true };
}

function validateCredentials(credentials) {
  // null/undefined/empty: SDK uses default credential chain. OK.
  if (credentials === null || credentials === undefined) return { ok: true };
  if (typeof credentials !== 'object' || Array.isArray(credentials)) {
    return { ok: false, error: 'credentials must be a JSON object or null', field: 'credentials' };
  }
  if (Object.keys(credentials).length === 0) return { ok: true };

  let r = base.requireString(credentials, 'access_key_id', { maxLength: 128 });
  if (!r.ok) return { ok: false, error: r.error, field: 'access_key_id' };
  r = base.requireString(credentials, 'secret_access_key', { maxLength: 256 });
  if (!r.ok) return { ok: false, error: r.error, field: 'secret_access_key' };

  if (credentials.session_token !== undefined) {
    if (typeof credentials.session_token !== 'string' || credentials.session_token === '') {
      return { ok: false, error: 'session_token must be non-empty string if provided', field: 'session_token' };
    }
    if (credentials.session_token.length > 4096) {
      return { ok: false, error: 'session_token exceeds 4096 chars', field: 'session_token' };
    }
  }

  const allowed = new Set(['access_key_id', 'secret_access_key', 'session_token']);
  for (const k of Object.keys(credentials)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in credentials: ${k}`, field: k };
    }
  }
  return { ok: true };
}

function buildClient(config, credentials) {
  const sdk = _getSdk();
  const clientConfig = {
    region: config.region,
    // Disable SDK-internal retry; backup-push layer enforces our own.
    maxAttempts: 1,
  };
  if (credentials && typeof credentials === 'object' && Object.keys(credentials).length > 0) {
    clientConfig.credentials = {
      accessKeyId: credentials.access_key_id,
      secretAccessKey: credentials.secret_access_key,
      ...(credentials.session_token ? { sessionToken: credentials.session_token } : {}),
    };
  }
  return new sdk.KMSClient(clientConfig);
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

  const sdk = _getSdk();
  const client = buildClient(config, credentials);
  let response;
  try {
    response = await client.send(new sdk.EncryptCommand({
      KeyId: config.key_id,
      Plaintext: plaintextDek,
      ...(config.encryption_context ? { EncryptionContext: config.encryption_context } : {}),
    }));
  } catch (err) {
    throw new base.KeyWrappingError(
      `AWS KMS Encrypt failed: ${err.message || err.name || 'unknown error'}`,
      {
        provider: PROVIDER_NAME,
        operation: 'wrap',
        retryable: isRetryableAwsError(err),
        detail: {
          code: err.name,
          requestId: err.$metadata && err.$metadata.requestId,
          httpStatus: err.$metadata && err.$metadata.httpStatusCode,
        },
        cause: err,
      },
    );
  } finally {
    try { client.destroy && client.destroy(); } catch { /* swallow */ }
  }

  if (!response.CiphertextBlob || response.CiphertextBlob.length === 0) {
    throw new base.KeyWrappingError(
      'AWS KMS returned empty CiphertextBlob',
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: false },
    );
  }
  return Buffer.from(response.CiphertextBlob);
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

  const sdk = _getSdk();
  const client = buildClient(config, credentials);
  let response;
  try {
    response = await client.send(new sdk.DecryptCommand({
      CiphertextBlob: wrappedDek,
      KeyId: config.key_id,
      ...(config.encryption_context ? { EncryptionContext: config.encryption_context } : {}),
    }));
  } catch (err) {
    throw new base.KeyWrappingError(
      `AWS KMS Decrypt failed: ${err.message || err.name || 'unknown error'}`,
      {
        provider: PROVIDER_NAME,
        operation: 'unwrap',
        retryable: isRetryableAwsError(err),
        detail: {
          code: err.name,
          requestId: err.$metadata && err.$metadata.requestId,
          httpStatus: err.$metadata && err.$metadata.httpStatusCode,
        },
        cause: err,
      },
    );
  } finally {
    try { client.destroy && client.destroy(); } catch { /* swallow */ }
  }

  if (!response.Plaintext || response.Plaintext.length === 0) {
    throw new base.KeyWrappingError(
      'AWS KMS returned empty Plaintext',
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  return Buffer.from(response.Plaintext);
}

async function probe(config, credentials, options) {
  const cv = validateConfig(config);
  if (!cv.ok) return { ok: false, error: cv.error, detail: { field: cv.field, phase: 'config' } };
  const cre = validateCredentials(credentials);
  if (!cre.ok) return { ok: false, error: cre.error, detail: { field: cre.field, phase: 'credentials' } };
  return base.probeRoundTrip(provider, config, credentials, options);
}

// ── Provider object + registration ────────────────────────────────────────

// D-R2-4: the AWS KMS KEK material stays in the HSM; fingerprint the stable key reference (ARN).
function kekFingerprint(config) {
  return base.kekFpFromReference((config || {}).key_id);
}

const provider = {
  name: PROVIDER_NAME,
  description: 'AWS KMS envelope encryption via @aws-sdk/client-kms. Tier 2 -- KEK in AWS HSM (FIPS 140-2 Level 3 in eligible regions).',
  securityTier: SECURITY_TIER,
  validateConfig,
  validateCredentials,
  probe,
  wrap,
  unwrap,
  kekFingerprint,
  // Test-only export; not used in production paths
  _setSdkForTest,
};

base.registerProvider(provider);

module.exports = provider;

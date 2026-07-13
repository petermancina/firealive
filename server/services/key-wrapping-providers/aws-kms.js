// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — AWS KMS Key Wrapping Provider
//
// Wraps and unwraps DEKs via AWS Key Management Service envelope
// encryption. Uses @aws-sdk/client-kms; the KEK lives in an AWS HSM
// (FIPS 140-2 Level 3 in eligible regions) and never leaves AWS.
// We send plaintext DEK to KMS Encrypt, get back a ciphertext blob;
// to unwrap, we send the ciphertext blob to KMS Decrypt, get back
// plaintext DEK. The KEK itself is never visible to FireAlive.
//
// Tier 2 security: KEK in cloud HSM. Compare with Tier 3 (env-var,
// KEK in process memory) and Tier 1 (PKCS#11 hardware token, never
// extractable -- reserved for future).
//
// CONFIG SCHEMA (kms_providers.config JSON for aws-kms rows)
//
//   {
//     "region": "us-east-1",
//     "key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd-..."
//                  | "alias/firealive-backups"
//                  | "abcd-1234-..." (key id)
//     "encryption_context": { "purpose": "firealive-backup",
//                              "tenant": "acme-corp" }      (optional)
//   }
//
// region:    AWS region for the KMS client. Pattern check is loose
//            because AWS adds new regions; format validated as
//            ^[a-z]{2,4}-[a-z]+-\d{1,2}$ to catch obvious typos
//            without rejecting future regions.
//
// key_id:    Any KMS key reference accepted by the KMS API: full
//            ARN, key id (UUID), alias name (alias/...), or alias
//            ARN. We don't try to validate the format beyond
//            non-empty + length cap; KMS will reject invalid
//            references at Encrypt/Decrypt time.
//
// encryption_context (optional):
//            Plain {string: string} object. Becomes part of the
//            AAD for the AES-GCM operation inside KMS. The same
//            context must be supplied at Decrypt time. This binds
//            the wrapped key to a specific use case: a wrapped
//            key created with context {purpose: "backup"} cannot
//            be Decrypted under context {purpose: "other"} even
//            by an authorized caller.
//
//            Operators rotating to a new provider with different
//            encryption_context MUST keep the old provider row
//            enabled (enabled=1) to unwrap historical backups --
//            disabling the old row breaks recovery for backups
//            created under it.
//
// CREDENTIALS SCHEMA (kms_providers.credentials_encrypted)
//
// Either explicit IAM credentials:
//
//   {
//     "access_key_id":     "AKIA...",
//     "secret_access_key": "...",
//     "session_token":     "..."        (optional, STS-vended creds)
//   }
//
// Or null/empty (credentials_encrypted=NULL in DB), in which case
// the SDK uses its default credential chain: instance profile,
// container role, env vars, ~/.aws/credentials. This is the
// recommended posture for FireAlive-on-EC2 / FireAlive-on-ECS
// deployments -- no AWS secrets in the FireAlive database.
//
// WIRE FORMAT
//
// wrap() returns a Buffer of the AWS KMS CiphertextBlob (opaque).
// AWS embeds the key ARN, encryption context hash, and other
// metadata inside the blob; FireAlive treats it as a black box.
// The Buffer is base64-encoded by the dispatcher (commits 20-21)
// and embedded in the wrapped-key.bin envelope:
//
//   { "v": 1, "scheme": "aws-kms",
//     "ref": "arn:aws:kms:us-east-1:123456789012:key/abcd-...",
//     "wrapped": "<base64 of CiphertextBlob>" }
//
// SDK RETRY DISABLED
//
// The AWS SDK has internal retry logic (maxAttempts default 3).
// We disable it (maxAttempts=1) because retry policy is enforced
// at the backup-push layer with our own backoff + chain-of-custody
// audit. Double-retrying creates duplicate KMS API calls without
// audit visibility.
//
// SDK NOT YET INSTALLED
//
// @aws-sdk/client-kms is not added to package.json until commit 23
// of this phase. Until then, this module loads cleanly (the SDK
// require is lazy, inside _getSdk()), but any wrap/unwrap call
// throws KeyWrappingError with a helpful "run npm install" message.
// Existing env-var rows continue to work; no aws-kms rows can exist
// until operators create them after R3d-5 ships v1.0.30.
// ═══════════════════════════════════════════════════════════════════════════════

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

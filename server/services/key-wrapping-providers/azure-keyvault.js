// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Azure Key Vault Key Wrapping Provider
//
// Wraps and unwraps DEKs via Azure Key Vault using the @azure/keyvault-keys
// SDK with @azure/identity for authentication. The KEK lives inside Azure
// Key Vault (FIPS 140-2 Level 2 in Standard SKU; Level 3 in Premium /
// Managed HSM) and never leaves Azure -- FireAlive sends plaintext DEK to
// CryptographyClient.wrapKey, gets back wrapped bytes; for unwrap, sends
// wrapped bytes to CryptographyClient.unwrapKey, gets back plaintext DEK.
//
// Tier 2 security: KEK in cloud HSM. Same security tier as aws-kms,
// gcp-kms, hashicorp-vault.
//
// CONFIG SCHEMA (kms_providers.config JSON for azure-keyvault rows)
//
//   {
//     "vault_url":   "https://my-vault.vault.azure.net",
//     "key_name":    "firealive-backup-kek",
//     "key_version": "abc123def456...",       (optional; omit for latest)
//     "algorithm":   "RSA-OAEP-256"           (optional; see below)
//   }
//
// vault_url:    Full Azure Key Vault URL. Validated as https URL.
//               Standard form: https://<vault-name>.vault.azure.net.
//               Managed HSM form: https://<hsm-name>.managedhsm.azure.net.
//               Sovereign clouds: .vault.azure.cn (China),
//               .vault.azure.us (Government), .vault.usgovcloudapi.net,
//               etc. We accept any https URL; Azure will reject
//               unreachable hosts at first call.
//
// key_name:     Name of the KEK in the vault. Pattern enforced by Azure:
//               1-127 chars, alphanumeric + dashes. We validate length
//               and a loose pattern; Azure rejects malformed at first call.
//
// key_version:  Optional specific version (32-char hex). Omit to use
//               latest version (recommended; supports automatic rotation).
//               Pinning to a version is useful for compliance audits
//               where the exact key material must be reproducible.
//
// algorithm:    Wrap algorithm. Allowlist below. Default RSA-OAEP-256
//               since it works in Standard SKU (RSA keys are universal).
//               A256KW / A256GCM require symmetric keys (Premium SKU
//               or Managed HSM only).
//
//               ALLOWED:
//                 RSA-OAEP-256   (recommended; SHA-256 padding)
//                 RSA-OAEP       (SHA-1 padding; legacy but supported)
//                 A256KW         (AES Key Wrap; Premium/Managed HSM)
//                 A256GCM        (AES-GCM; Premium/Managed HSM)
//
//               REJECTED:
//                 RSA1_5         (deprecated PKCS#1 v1.5 padding;
//                                 vulnerable to Bleichenbacher attacks)
//                 anything else
//
// CREDENTIALS SCHEMA (kms_providers.credentials_encrypted)
//
// Either explicit service principal:
//
//   {
//     "tenant_id":     "00000000-0000-0000-0000-000000000000",
//     "client_id":     "00000000-0000-0000-0000-000000000000",
//     "client_secret": "..."
//   }
//
// Or null/empty -> SDK uses DefaultAzureCredential, which tries (in
// order): managed identity (recommended for Azure-hosted FireAlive),
// EnvironmentCredential (AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET env
// vars), AzureCliCredential. Recommended for FireAlive-on-Azure
// deployments -- no Azure secrets in FireAlive database.
//
// WIRE FORMAT
//
// wrap() returns Buffer of the algorithm-specific wrapped output:
//   RSA-OAEP*: 256 bytes (RSA 2048) or 384 bytes (RSA 3072) etc.
//   A256KW:    plaintext_length + 8 bytes (AES Key Wrap overhead)
//   A256GCM:   nonce(12) + tag(16) + ciphertext bytes
// All opaque to us; embedded in the wrapped-key.bin envelope by the
// dispatcher (commits 20-21):
//
//   { "v": 1, "scheme": "azure-keyvault",
//     "ref": "https://my-vault.vault.azure.net/keys/key-name/version",
//     "wrapped": "<base64>" }
//
// Algorithm is part of the EnvelopeContext so unwrap-time uses the
// same algorithm. (Stored in dispatcher's envelope, not here.)
//
// SDK NOT YET INSTALLED
//
// @azure/keyvault-keys + @azure/identity are added to package.json in
// commit 23. Until then, this module loads cleanly (require is lazy
// inside _getSdks()). Any wrap/unwrap call before then throws
// KeyWrappingError(operation='sdk-load') with a clear "npm install"
// message naming both packages. Existing env-var/aws-kms rows
// continue working independently.
// ═══════════════════════════════════════════════════════════════════════════════

const base = require('./base');

const PROVIDER_NAME = 'azure-keyvault';
const SECURITY_TIER = 2;

const VALID_KEY_NAME_PATTERN = /^[a-zA-Z0-9-]+$/;
const VALID_KEY_VERSION_PATTERN = /^[a-f0-9]{32}$/;
const ALLOWED_ALGORITHMS = new Set([
  'RSA-OAEP-256',
  'RSA-OAEP',
  'A256KW',
  'A256GCM',
]);
const DEFAULT_ALGORITHM = 'RSA-OAEP-256';

// ── SDK loading (lazy + test-overridable) ─────────────────────────────────

let _sdksOverride = null;

function _setSdkForTest(sdks) {
  // sdks: { keyvault: ...exports, identity: ...exports } or null to clear
  _sdksOverride = sdks;
}

function _getSdks() {
  if (_sdksOverride) return _sdksOverride;
  let keyvault, identity;
  try {
    // eslint-disable-next-line global-require
    keyvault = require('@azure/keyvault-keys');
  } catch (err) {
    throw new base.KeyWrappingError(
      "@azure/keyvault-keys not installed; run: npm install @azure/keyvault-keys @azure/identity",
      { provider: PROVIDER_NAME, operation: 'sdk-load', retryable: false, cause: err },
    );
  }
  try {
    // eslint-disable-next-line global-require
    identity = require('@azure/identity');
  } catch (err) {
    throw new base.KeyWrappingError(
      "@azure/identity not installed; run: npm install @azure/keyvault-keys @azure/identity",
      { provider: PROVIDER_NAME, operation: 'sdk-load', retryable: false, cause: err },
    );
  }
  return { keyvault, identity };
}

// ── Retryable classification ──────────────────────────────────────────────
//
// Azure SDK throws RestError with .statusCode, .code, .message. Network
// errors come through as standard Node errors with .code (ECONNRESET etc.).

const RETRYABLE_AZURE_ERROR_CODES = new Set([
  'TooManyRequests',
  'ServiceUnavailable',
  'InternalServerError',
  'OperationTimedOut',
  'GatewayTimeout',
  'BadGateway',
  'KeyVaultErrorException',  // generic KV server-side error
]);

const PERMANENT_AZURE_ERROR_CODES = new Set([
  'Unauthorized',
  'Forbidden',
  'KeyNotFound',
  'KeyDisabled',
  'KeyExpired',
  'KeyNotYetValid',
  'BadParameter',
  'BadRequest',
  'CertificateNotFound',
]);

function isRetryableAzureError(err) {
  if (!err) return false;
  if (err.code && RETRYABLE_AZURE_ERROR_CODES.has(err.code)) return true;
  if (err.code && PERMANENT_AZURE_ERROR_CODES.has(err.code)) return false;
  if (typeof err.statusCode === 'number') {
    if (err.statusCode === 429) return true;        // throttling
    if (err.statusCode >= 500 && err.statusCode < 600) return true;
    if (err.statusCode >= 400 && err.statusCode < 500) return false;
  }
  // Node socket errors
  if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT' ||
      err.code === 'ENETUNREACH' || err.code === 'ENOTFOUND' ||
      err.code === 'EAI_AGAIN') return true;
  // Default: permanent (safer than infinite retry on the unknown)
  return false;
}

// ── Provider interface implementations ────────────────────────────────────

function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ok: false, error: 'config must be a JSON object', field: 'config' };
  }

  let r = base.requireUrl(config, 'vault_url', { schemes: ['https:'] });
  if (!r.ok) return { ok: false, error: r.error, field: 'vault_url' };

  r = base.requireString(config, 'key_name', {
    maxLength: 127,
    pattern: VALID_KEY_NAME_PATTERN,
  });
  if (!r.ok) {
    return { ok: false, error: 'key_name must be 1-127 alphanumeric + dashes', field: 'key_name' };
  }

  if (config.key_version !== undefined && config.key_version !== null) {
    if (typeof config.key_version !== 'string' || !VALID_KEY_VERSION_PATTERN.test(config.key_version)) {
      return { ok: false, error: 'key_version must be 32 hex chars (or omit for latest)', field: 'key_version' };
    }
  }

  if (config.algorithm !== undefined && config.algorithm !== null) {
    if (!ALLOWED_ALGORITHMS.has(config.algorithm)) {
      return {
        ok: false,
        error: `algorithm must be one of: ${[...ALLOWED_ALGORITHMS].join(', ')} (RSA1_5 deprecated, not allowed)`,
        field: 'algorithm',
      };
    }
  }

  // Reject unexpected fields (typo defense)
  const allowed = new Set(['vault_url', 'key_name', 'key_version', 'algorithm']);
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

  // Service principal: tenant_id + client_id + client_secret all required
  let r = base.requireString(credentials, 'tenant_id', { maxLength: 64 });
  if (!r.ok) return { ok: false, error: r.error, field: 'tenant_id' };

  r = base.requireString(credentials, 'client_id', { maxLength: 64 });
  if (!r.ok) return { ok: false, error: r.error, field: 'client_id' };

  r = base.requireString(credentials, 'client_secret', { maxLength: 1024 });
  if (!r.ok) return { ok: false, error: r.error, field: 'client_secret' };

  const allowed = new Set(['tenant_id', 'client_id', 'client_secret']);
  for (const k of Object.keys(credentials)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in credentials: ${k}`, field: k };
    }
  }
  return { ok: true };
}

function buildKeyIdentifier(config) {
  // Azure key identifier URL form:
  //   https://vault/keys/key-name           (latest version)
  //   https://vault/keys/key-name/version   (specific version)
  const base = config.vault_url.replace(/\/$/, '');
  const tail = config.key_version
    ? `/keys/${config.key_name}/${config.key_version}`
    : `/keys/${config.key_name}`;
  return base + tail;
}

function buildCredential(credentials) {
  const { identity } = _getSdks();
  if (!credentials || typeof credentials !== 'object' || Object.keys(credentials).length === 0) {
    return new identity.DefaultAzureCredential();
  }
  return new identity.ClientSecretCredential(
    credentials.tenant_id,
    credentials.client_id,
    credentials.client_secret,
  );
}

function buildCryptoClient(config, credentials) {
  const { keyvault } = _getSdks();
  const credential = buildCredential(credentials);
  const keyId = buildKeyIdentifier(config);
  return new keyvault.CryptographyClient(keyId, credential);
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

  const algorithm = config.algorithm || DEFAULT_ALGORITHM;
  const client = buildCryptoClient(config, credentials);

  let response;
  try {
    response = await client.wrapKey(algorithm, plaintextDek);
  } catch (err) {
    throw new base.KeyWrappingError(
      `Azure Key Vault wrapKey failed: ${err.message || err.code || 'unknown error'}`,
      {
        provider: PROVIDER_NAME,
        operation: 'wrap',
        retryable: isRetryableAzureError(err),
        detail: {
          code: err.code,
          httpStatus: err.statusCode,
          algorithm,
        },
        cause: err,
      },
    );
  }

  if (!response.result || response.result.length === 0) {
    throw new base.KeyWrappingError(
      'Azure Key Vault wrapKey returned empty result',
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: false },
    );
  }
  return Buffer.from(response.result);
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

  const algorithm = config.algorithm || DEFAULT_ALGORITHM;
  const client = buildCryptoClient(config, credentials);

  let response;
  try {
    response = await client.unwrapKey(algorithm, wrappedDek);
  } catch (err) {
    throw new base.KeyWrappingError(
      `Azure Key Vault unwrapKey failed: ${err.message || err.code || 'unknown error'}`,
      {
        provider: PROVIDER_NAME,
        operation: 'unwrap',
        retryable: isRetryableAzureError(err),
        detail: {
          code: err.code,
          httpStatus: err.statusCode,
          algorithm,
        },
        cause: err,
      },
    );
  }

  if (!response.result || response.result.length === 0) {
    throw new base.KeyWrappingError(
      'Azure Key Vault unwrapKey returned empty result',
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  return Buffer.from(response.result);
}

async function probe(config, credentials, options) {
  const cv = validateConfig(config);
  if (!cv.ok) return { ok: false, error: cv.error, detail: { field: cv.field, phase: 'config' } };
  const cre = validateCredentials(credentials);
  if (!cre.ok) return { ok: false, error: cre.error, detail: { field: cre.field, phase: 'credentials' } };
  return base.probeRoundTrip(provider, config, credentials, options);
}

// ── Provider object + registration ────────────────────────────────────────

// D-R2-4: the Azure Key Vault KEK material stays in the HSM; fingerprint the stable key
// identifier URL (vault_url/keys/key_name[/key_version]), matching the wrapped-envelope ref.
function kekFingerprint(config) {
  const c = config || {};
  if (!c.vault_url || !c.key_name) {
    throw new Error('azure-keyvault kekFingerprint: config.vault_url and config.key_name required');
  }
  const ref = String(c.vault_url) + '/keys/' + String(c.key_name)
    + (c.key_version ? '/' + String(c.key_version) : '');
  return base.kekFpFromReference(ref);
}

const provider = {
  name: PROVIDER_NAME,
  description: 'Azure Key Vault envelope encryption via @azure/keyvault-keys + @azure/identity. Tier 2 -- KEK in Azure HSM (FIPS 140-2 Level 2 in Standard SKU; Level 3 in Premium / Managed HSM).',
  securityTier: SECURITY_TIER,
  validateConfig,
  validateCredentials,
  probe,
  wrap,
  unwrap,
  kekFingerprint,
  // Test-only export
  _setSdkForTest,
  // Exposed for documentation / admin UI
  ALLOWED_ALGORITHMS: [...ALLOWED_ALGORITHMS],
  DEFAULT_ALGORITHM,
};

base.registerProvider(provider);

module.exports = provider;

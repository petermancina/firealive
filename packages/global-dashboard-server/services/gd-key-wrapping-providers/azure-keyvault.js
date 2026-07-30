// =============================================================================
// FIREALIVE GD -- azure-keyvault key-wrapping provider  [B6g]
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
//
// The GD twin of server/services/key-wrapping-providers/azure-keyvault.js.
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

// B6g: which environment variable names the authorised endpoint hosts. The
// Regional Server reads KMS_ALLOWED_HOSTS; the GD twin of this provider reads
// GD_KMS_ALLOWED_HOSTS. Naming it here rather than inside the allow-list module
// keeps one module serving both servers.
const ALLOW_LIST_ENV = 'GD_KMS_ALLOWED_HOSTS';

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

  let r = base.requireUrl(config, 'vault_url', { schemes: ['https:'], allowListEnv: ALLOW_LIST_ENV });
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
  // B6g: re-check the host on the CRYPTO path. Same reasoning as the Vault
  // provider: rows predating the allow-list are not constrained by a check that
  // only runs at config-write, and wrap() and unwrap() both reach here.
  const hostCheck = base.checkEndpoint(config.vault_url, ALLOW_LIST_ENV);
  if (!hostCheck.ok) {
    throw new base.KeyWrappingError(`azure-keyvault: ${hostCheck.error}`, {
      provider: 'azure-keyvault', operation: 'endpoint-allow-list', retryable: false,
    });
  }
  // Renamed from `base` in B6g: the old local shadowed the module import of the
  // same name, so any reference to the module earlier in this function hit the
  // temporal dead zone -- a runtime ReferenceError that node --check cannot see.
  // `baseUrl` also matches what the hashicorp-vault provider calls its equivalent.
  const baseUrl = config.vault_url.replace(/\/$/, '');
  const tail = config.key_version
    ? `/keys/${config.key_name}/${config.key_version}`
    : `/keys/${config.key_name}`;
  return baseUrl + tail;
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

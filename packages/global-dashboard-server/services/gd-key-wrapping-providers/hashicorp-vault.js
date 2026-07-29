// =============================================================================
// FIREALIVE GD -- hashicorp-vault key-wrapping provider  [B6g]
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
//
// The GD twin of server/services/key-wrapping-providers/hashicorp-vault.js.
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

const https = require('https');
const { URL } = require('url');
const base = require('./base');

// B6g: which environment variable names the authorised endpoint hosts. The
// Regional Server reads KMS_ALLOWED_HOSTS; the GD twin of this provider reads
// GD_KMS_ALLOWED_HOSTS. Naming it here rather than inside the allow-list module
// keeps one module serving both servers.
const ALLOW_LIST_ENV = 'GD_KMS_ALLOWED_HOSTS';

const PROVIDER_NAME = 'hashicorp-vault';
const SECURITY_TIER = 2;

const VALID_KEY_NAME_PATTERN = /^[a-zA-Z0-9_-]{1,128}$/;
const VALID_TRANSIT_PATH_PATTERN = /^[a-zA-Z0-9_-]+(\/[a-zA-Z0-9_-]+)*$/;
const VALID_NAMESPACE_PATTERN = /^[a-zA-Z0-9_-]+(\/[a-zA-Z0-9_-]+)*$/;
const VAULT_CIPHERTEXT_PATTERN = /^vault:v\d+:[A-Za-z0-9+/=]+$/;

const REQUEST_TIMEOUT_MS = parseInt(process.env.VAULT_REQUEST_TIMEOUT_MS, 10) || 15000;

// ── Validation ────────────────────────────────────────────────────────────

function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ok: false, error: 'config must be a JSON object', field: 'config' };
  }

  let r = base.requireUrl(config, 'vault_addr', { schemes: ['https:'], allowListEnv: ALLOW_LIST_ENV });
  if (!r.ok) return { ok: false, error: r.error, field: 'vault_addr' };

  if (config.transit_path !== undefined) {
    if (typeof config.transit_path !== 'string' || !VALID_TRANSIT_PATH_PATTERN.test(config.transit_path)) {
      return { ok: false, error: 'transit_path must be alphanumeric with optional slashes (no leading/trailing slash)', field: 'transit_path' };
    }
  }

  r = base.requireString(config, 'key_name', { maxLength: 128, pattern: VALID_KEY_NAME_PATTERN });
  if (!r.ok) return { ok: false, error: 'key_name must be 1-128 chars (alphanumeric, hyphens, underscores)', field: 'key_name' };

  if (config.key_version !== undefined && config.key_version !== null) {
    if (!Number.isInteger(config.key_version) || config.key_version < 1) {
      return { ok: false, error: 'key_version must be a positive integer', field: 'key_version' };
    }
  }

  if (config.namespace !== undefined && config.namespace !== null) {
    if (typeof config.namespace !== 'string' || !VALID_NAMESPACE_PATTERN.test(config.namespace)) {
      return { ok: false, error: 'namespace must be alphanumeric path (e.g. "ops/team-blue")', field: 'namespace' };
    }
  }

  if (config.ca_cert_pem !== undefined && config.ca_cert_pem !== null) {
    if (typeof config.ca_cert_pem !== 'string' ||
        !config.ca_cert_pem.includes('BEGIN CERTIFICATE')) {
      return { ok: false, error: 'ca_cert_pem must be a PEM-encoded certificate', field: 'ca_cert_pem' };
    }
  }

  if (config.context_b64 !== undefined && config.context_b64 !== null) {
    if (typeof config.context_b64 !== 'string' || config.context_b64.length === 0) {
      return { ok: false, error: 'context_b64 must be non-empty base64', field: 'context_b64' };
    }
    try {
      const decoded = Buffer.from(config.context_b64, 'base64');
      if (decoded.length === 0) return { ok: false, error: 'context_b64 decoded to empty', field: 'context_b64' };
    } catch {
      return { ok: false, error: 'context_b64 is not valid base64', field: 'context_b64' };
    }
  }

  // Defense: explicitly reject tls_skip_verify so it doesn't get added later
  if ('tls_skip_verify' in config || 'insecure' in config || 'verify' in config) {
    return { ok: false, error: 'tls_skip_verify / insecure / verify options not supported; use ca_cert_pem for self-signed certs', field: 'config' };
  }

  const allowed = new Set(['vault_addr', 'transit_path', 'key_name', 'key_version', 'namespace', 'ca_cert_pem', 'context_b64']);
  for (const k of Object.keys(config)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in config: ${k}`, field: k };
    }
  }
  return { ok: true };
}

function validateCredentials(credentials) {
  if (credentials === null || credentials === undefined) {
    return { ok: false, error: 'credentials.token required for Vault provider', field: 'token' };
  }
  if (typeof credentials !== 'object' || Array.isArray(credentials)) {
    return { ok: false, error: 'credentials must be a JSON object', field: 'credentials' };
  }

  const r = base.requireString(credentials, 'token', { maxLength: 4096 });
  if (!r.ok) return { ok: false, error: 'credentials.token required (Vault token)', field: 'token' };

  const allowed = new Set(['token']);
  for (const k of Object.keys(credentials)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in credentials: ${k}`, field: k };
    }
  }
  return { ok: true };
}

// ── HTTP helper ──────────────────────────────────────────────────────────
//
// Test override: provider._setHttpsForTest({request: ...}) injects a stub.

let _httpsOverride = null;
function _setHttpsForTest(stub) { _httpsOverride = stub; }
function _getHttps() { return _httpsOverride || https; }

function postJson(urlStr, body, headers, caCertPem) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const bodyStr = JSON.stringify(body);
    const options = {
      method: 'POST',
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
        ...headers,
      },
      timeout: REQUEST_TIMEOUT_MS,
    };
    if (caCertPem) {
      options.ca = caCertPem;
      // Default: rejectUnauthorized = true. Do NOT override.
    }

    const req = _getHttps().request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ statusCode: res.statusCode, headers: res.headers, body: text });
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error(`Vault request timed out after ${REQUEST_TIMEOUT_MS}ms`));
    });
    req.write(bodyStr);
    req.end();
  });
}

// ── Retryable classification ──────────────────────────────────────────────

function isRetryableVaultStatus(status) {
  if (status === 429) return true;            // rate limit
  if (status === 503) return true;            // sealed / standby / not ready
  if (status >= 500 && status < 600) return true;
  return false;
}

function isRetryableNetworkError(err) {
  if (!err || !err.code) return false;
  return ['ECONNRESET', 'ETIMEDOUT', 'ENETUNREACH', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED'].includes(err.code);
}

function isRetryableError(err, statusCode) {
  if (statusCode !== undefined) return isRetryableVaultStatus(statusCode);
  return isRetryableNetworkError(err);
}

// ── Provider operations ──────────────────────────────────────────────────

function buildEndpoint(config, action) {
  // B6g: re-check the host on the CRYPTO path, not only at config-write.
  // Every gd_kms_providers row written before this allow-list existed carries a
  // vault_addr that validateConfig never examined against it, and a check that
  // runs only on write cannot constrain what was already written. wrap() and
  // unwrap() both route through here, so one call point covers both.
  //
  // Throws rather than returning a result: a caller able to ignore an error
  // here is a caller able to wrap a data key against an unauthorised host.
  const hostCheck = base.checkEndpoint(config.vault_addr, ALLOW_LIST_ENV);
  if (!hostCheck.ok) {
    throw new base.KeyWrappingError(`hashicorp-vault: ${hostCheck.error}`, {
      provider: 'hashicorp-vault', operation: 'endpoint-allow-list', retryable: false,
    });
  }
  const transit = config.transit_path || 'transit';
  const baseUrl = config.vault_addr.replace(/\/$/, '');
  return `${baseUrl}/v1/${transit}/${action}/${encodeURIComponent(config.key_name)}`;
}

function buildHeaders(credentials, config) {
  const headers = { 'X-Vault-Token': credentials.token };
  if (config.namespace) headers['X-Vault-Namespace'] = config.namespace;
  return headers;
}

async function wrap(plaintextDek, config, credentials, options = {}) {
  if (!Buffer.isBuffer(plaintextDek) || plaintextDek.length === 0) {
    throw new base.KeyWrappingError(
      'plaintextDek must be a non-empty Buffer',
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: false },
    );
  }
  const cv = validateConfig(config);
  if (!cv.ok) throw new base.KeyWrappingError(cv.error, { provider: PROVIDER_NAME, operation: 'wrap', retryable: false, detail: { field: cv.field } });
  const cre = validateCredentials(credentials);
  if (!cre.ok) throw new base.KeyWrappingError(cre.error, { provider: PROVIDER_NAME, operation: 'wrap', retryable: false, detail: { field: cre.field } });

  const url = buildEndpoint(config, 'encrypt');
  const body = { plaintext: plaintextDek.toString('base64') };
  if (config.key_version) body.key_version = config.key_version;
  if (config.context_b64) body.context = config.context_b64;

  let response;
  try {
    response = await postJson(url, body, buildHeaders(credentials, config), config.ca_cert_pem);
  } catch (err) {
    throw new base.KeyWrappingError(
      `Vault encrypt request failed: ${err.message}`,
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: isRetryableError(err), detail: { code: err.code }, cause: err },
    );
  }

  if (response.statusCode !== 200) {
    let errors;
    try { errors = JSON.parse(response.body).errors; } catch { errors = [response.body]; }
    throw new base.KeyWrappingError(
      `Vault encrypt returned ${response.statusCode}: ${(errors || []).join('; ')}`,
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: isRetryableError(null, response.statusCode), detail: { httpStatus: response.statusCode, vaultErrors: errors } },
    );
  }

  let parsed;
  try { parsed = JSON.parse(response.body); }
  catch (err) {
    throw new base.KeyWrappingError(
      `Vault encrypt returned non-JSON body: ${err.message}`,
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: false },
    );
  }
  const ciphertext = parsed && parsed.data && parsed.data.ciphertext;
  if (typeof ciphertext !== 'string' || !VAULT_CIPHERTEXT_PATTERN.test(ciphertext)) {
    throw new base.KeyWrappingError(
      `Vault encrypt returned malformed ciphertext: ${typeof ciphertext === 'string' ? ciphertext.slice(0, 32) : typeof ciphertext}`,
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: false },
    );
  }
  return Buffer.from(ciphertext, 'utf8');
}

async function unwrap(wrappedDek, config, credentials, options = {}) {
  if (!Buffer.isBuffer(wrappedDek) || wrappedDek.length === 0) {
    throw new base.KeyWrappingError(
      'wrappedDek must be a non-empty Buffer',
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  const cv = validateConfig(config);
  if (!cv.ok) throw new base.KeyWrappingError(cv.error, { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false });
  const cre = validateCredentials(credentials);
  if (!cre.ok) throw new base.KeyWrappingError(cre.error, { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false });

  const ciphertext = wrappedDek.toString('utf8');
  if (!VAULT_CIPHERTEXT_PATTERN.test(ciphertext)) {
    throw new base.KeyWrappingError(
      `wrappedDek is not a Vault transit ciphertext (expected vault:v<N>:<base64>)`,
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false, detail: { reason: 'malformed' } },
    );
  }

  const url = buildEndpoint(config, 'decrypt');
  const body = { ciphertext };
  if (config.context_b64) body.context = config.context_b64;

  let response;
  try {
    response = await postJson(url, body, buildHeaders(credentials, config), config.ca_cert_pem);
  } catch (err) {
    throw new base.KeyWrappingError(
      `Vault decrypt request failed: ${err.message}`,
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: isRetryableError(err), detail: { code: err.code }, cause: err },
    );
  }

  if (response.statusCode !== 200) {
    let errors;
    try { errors = JSON.parse(response.body).errors; } catch { errors = [response.body]; }
    throw new base.KeyWrappingError(
      `Vault decrypt returned ${response.statusCode}: ${(errors || []).join('; ')}`,
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: isRetryableError(null, response.statusCode), detail: { httpStatus: response.statusCode, vaultErrors: errors } },
    );
  }

  let parsed;
  try { parsed = JSON.parse(response.body); }
  catch (err) {
    throw new base.KeyWrappingError(
      `Vault decrypt returned non-JSON body: ${err.message}`,
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  const plaintextB64 = parsed && parsed.data && parsed.data.plaintext;
  if (typeof plaintextB64 !== 'string' || plaintextB64.length === 0) {
    throw new base.KeyWrappingError(
      'Vault decrypt returned empty plaintext',
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  return Buffer.from(plaintextB64, 'base64');
}

async function probe(config, credentials, options) {
  const cv = validateConfig(config);
  if (!cv.ok) return { ok: false, error: cv.error, detail: { field: cv.field, phase: 'config' } };
  const cre = validateCredentials(credentials);
  if (!cre.ok) return { ok: false, error: cre.error, detail: { field: cre.field, phase: 'credentials' } };
  return base.probeRoundTrip(provider, config, credentials, options);
}

// ── Provider object + registration ────────────────────────────────────────

// D-R2-4: the Vault transit KEK material never leaves Vault; fingerprint the stable transit key
// reference (vault_addr [/namespace] /transit_path/keys/key_name).
function kekFingerprint(config) {
  const c = config || {};
  if (!c.vault_addr || !c.key_name) {
    throw new Error('hashicorp-vault kekFingerprint: config.vault_addr and config.key_name required');
  }
  const transitPath = c.transit_path || 'transit';
  const ns = c.namespace ? String(c.namespace) + '/' : '';
  const ref = String(c.vault_addr) + '/' + ns + String(transitPath) + '/keys/' + String(c.key_name);
  return base.kekFpFromReference(ref);
}

const provider = {
  name: PROVIDER_NAME,
  description: 'HashiCorp Vault transit engine via raw HTTPS API (no SDK dependency). Tier 2 -- KEK in Vault HSM (Enterprise) or software-encrypted storage (OSS). Recommended for on-prem and EU privacy-first deployments.',
  securityTier: SECURITY_TIER,
  validateConfig,
  validateCredentials,
  probe,
  wrap,
  unwrap,
  kekFingerprint,
  // Test-only exports
  _setHttpsForTest,
};

base.registerProvider(provider);

module.exports = provider;

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — HashiCorp Vault Key Wrapping Provider
//
// Wraps and unwraps DEKs via HashiCorp Vault's transit secrets engine,
// using raw HTTPS calls -- NO SDK dependency. The KEK lives inside the
// Vault transit backend and never leaves Vault. We POST plaintext DEK
// (base64-encoded) to /v1/transit/encrypt/<key>, get back a
// "vault:v1:<base64>" ciphertext string; for unwrap, POST that string
// to /v1/transit/decrypt/<key>, get back base64 plaintext.
//
// Tier 2 security: KEK in Vault's HSM-backed storage (Vault Enterprise +
// HSM auto-unseal) or in software-encrypted storage (Vault OSS).
// Same security tier as aws-kms, azure-keyvault, gcp-kms.
//
// CRITICAL FOR EU PRIVACY-FIRST AND ON-PREM
//
// Self-hosted Vault is the on-prem KEK provider for SOCs that:
//   - Cannot use US cloud KMS for data sovereignty reasons
//   - Run on EU privacy-first clouds (Hetzner, OVHcloud, Scaleway)
//     where managed KMS isn't available or doesn't meet compliance
//   - Are air-gapped or highly network-restricted
//   - Want a unified secrets/PKI/transit infrastructure they control
//
// CONFIG SCHEMA (kms_providers.config JSON for hashicorp-vault rows)
//
//   {
//     "vault_addr":   "https://vault.example.com:8200",     (required)
//     "transit_path": "transit",                             (optional;
//                                                            default
//                                                            'transit')
//     "key_name":     "firealive-backup-kek",               (required)
//     "key_version":  3,                                     (optional integer)
//     "namespace":    "ops/team-blue",                       (optional;
//                                                            Enterprise)
//     "ca_cert_pem":  "-----BEGIN CERTIFICATE-----...",      (optional;
//                                                            for
//                                                            self-signed)
//     "context_b64":  "<base64>"                              (optional;
//                                                            convergent
//                                                            encryption)
//   }
//
// vault_addr:    Full Vault URL with scheme + port. https only;
//                http rejected. Operators with a private VPN tunnel
//                can use a private hostname; the URL just needs to
//                resolve from FireAlive's network.
//
// transit_path: Mount path of the transit engine. Vault's default is
//                'transit'; operators sometimes mount it elsewhere
//                (e.g., 'transit/firealive') for namespace
//                organization. Validated as alphanumeric with
//                slashes; no leading/trailing slash.
//
// key_name:      Name of the encryption key inside the transit
//                engine. Pattern: 1-128 alphanumeric/-/_ chars.
//                Vault rejects malformed names at first call.
//
// key_version:   Optional integer pinning to specific key version.
//                Vault transit supports automatic rotation; if
//                omitted, encrypt uses the current primary version.
//                The "vault:v<N>:..." prefix in the ciphertext
//                already records the version, so decrypt works
//                regardless of this field.
//
// namespace:     Vault Enterprise namespace. Sent via X-Vault-Namespace
//                header. Required if FireAlive's role+token are
//                scoped to a namespace; omit for OSS or root namespace.
//
// ca_cert_pem:   PEM-encoded CA certificate for self-signed Vault
//                deployments. If provided, the TLS connection only
//                trusts this CA (overrides system trust store).
//                If omitted, Node's default system CA store is used.
//                NO tls_skip_verify option -- there is no escape
//                hatch for unverified TLS. Operators must either
//                use a publicly-trusted cert or supply the CA PEM.
//
// context_b64:   Optional base64-encoded context for Vault's
//                convergent/derived-key features (transit
//                "derived" keys). Most operators don't use this;
//                it's exposed for parity with Vault's API.
//
// CREDENTIALS SCHEMA (kms_providers.credentials_encrypted)
//
//   {
//     "token": "hvs.CAESI..."                                (required)
//   }
//
// token:         Vault token. Typically issued via AppRole login
//                with policies like:
//                   path "transit/encrypt/firealive-backup-kek" {
//                     capabilities = ["update"]
//                   }
//                   path "transit/decrypt/firealive-backup-kek" {
//                     capabilities = ["update"]
//                   }
//
//                Token renewal is the operator's concern -- typically
//                a Vault Agent sidecar refreshes the token in the env
//                or in the credentials_encrypted row. R3d-4 doesn't
//                implement token renewal; we use the token as-is and
//                let permission-denied errors surface to the operator.
//
// WIRE FORMAT
//
// Vault transit returns ciphertext as a UTF-8 string with a
// "vault:v<N>:<base64>" format. wrap() returns Buffer.from(string, 'utf8')
// for downstream embedding in the wrapped-key.bin envelope:
//
//   { "v": 1, "scheme": "hashicorp-vault",
//     "ref": "vault.example.com:8200/transit/keys/firealive-backup-kek",
//     "wrapped": "<base64 of UTF-8 'vault:v3:abc...'>" }
//
// The dispatcher base64-encodes the Buffer (which contains the
// UTF-8 bytes of the vault: string). On unwrap, dispatcher decodes
// and provides the same Buffer; provider converts to UTF-8 string
// to send to Vault decrypt.
//
// REQUEST/RESPONSE FORMAT
//
// POST /v1/<transit_path>/encrypt/<key_name>
//   Body: { "plaintext": "<base64>", "key_version": N?,
//           "context": "<base64>"? }
//   Response: { "data": { "ciphertext": "vault:v3:<base64>",
//                          "key_version": 3 } }
//
// POST /v1/<transit_path>/decrypt/<key_name>
//   Body: { "ciphertext": "vault:v3:<base64>",
//           "context": "<base64>"? }
//   Response: { "data": { "plaintext": "<base64>" } }
//
// Headers: X-Vault-Token: <token>
//          X-Vault-Namespace: <namespace>?    (Enterprise)
//          Content-Type: application/json
//
// All HTTP requests have a 15s timeout; operators with very high
// Vault latency can adjust via VAULT_REQUEST_TIMEOUT_MS env (read
// at provider load time; defaults to 15000).
// ═══════════════════════════════════════════════════════════════════════════════

const https = require('https');
const { URL } = require('url');
const base = require('./base');

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

  let r = base.requireUrl(config, 'vault_addr', { schemes: ['https:'] });
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

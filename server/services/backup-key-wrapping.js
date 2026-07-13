// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Key Wrapping Service (Registry Dispatcher)
//
// Wraps and unwraps the per-backup ephemeral 256-bit AES-GCM key. The
// wrapped form is what gets written to wrapped-key.bin in the v2 backup
// directory; the raw ephemeral key never touches disk and never lives
// in the database.
//
// REFACTORED IN R3d-4 PART 2 (commits 10a/10b)
//
// Pre-refactor (R3d-1 through R3d-3): this file inlined an env-var-only
// implementation. The five planned cloud-KMS schemes were named in
// SUPPORTED_SCHEMES but threw "not yet implemented".
//
// Post-refactor (this file): the implementations live in
// services/key-wrapping-providers/{env-var, aws-kms, azure-keyvault,
// gcp-kms, hashicorp-vault}.js. Each provider module self-registers
// with the base registry at module-load time. This file is a thin
// dispatcher that routes wrap/unwrap by scheme to the right provider.
//
// SCHEMES (matches kms_providers.provider_type CHECK constraint)
//
//   env-var          KEK in process environment variable (Tier 3)
//   aws-kms          KEK in AWS KMS (Tier 2, FIPS 140-2 L3 in eligible regions)
//   azure-keyvault   KEK in Azure Key Vault (Tier 2)
//   gcp-kms          KEK in GCP KMS (Tier 2)
//   hashicorp-vault  KEK in HashiCorp Vault transit engine (Tier 2)
//
// ENVELOPE FORMAT (wrapped-key.bin contents -- UNCHANGED from R3d-1)
//
// JSON object (cleartext, operator-inspectable with `cat`):
//
//   {
//     "v":       1,                       (envelope version)
//     "scheme":  "env-var",               (provider name, matches kms_providers.provider_type)
//     "ref":     "<scheme-specific>",     (env_var_name for env-var,
//                                          kms_providers.id (UUID) for cloud schemes)
//     "wrapped": "base64..."              (provider-specific wrapped bytes)
//   }
//
// REF SEMANTICS PER SCHEME
//
//   env-var          ref = the env var name (e.g. "TIER1_ENCRYPTION_KEY").
//                    Backward-compatible with R3d-1 through R3d-3 manifests.
//                    No DB lookup needed; the env var IS the lookup.
//
//   aws-kms,         ref = the kms_providers row's id (UUID). The dispatcher
//   azure-keyvault,  performs a DB lookup to get config + decrypt credentials.
//   gcp-kms,         Caller MUST pass { db } in options for these schemes.
//   hashicorp-vault
//
// This split keeps env-var calls identical to pre-refactor (no source
// changes needed in backup.js or routes/restore.js for the default
// deployment) while enabling cloud-KMS dispatch when configured.
//
// INTEGRITY (UNCHANGED)
//
// The wrapped-key.bin file's SHA-256 is recorded in manifest.json's
// files[] entry. The manifest is signed with Ed25519. Any tampering
// of wrapped-key.bin (including the scheme/ref fields) changes the
// SHA-256 and is caught by manifest verification before unwrapKey is
// called.
//
// Defense-in-depth: unwrapKey verifies envelope.scheme/ref match the
// expectedScheme/expectedRef passed by the caller (which the caller
// reads from the verified manifest). A mismatch throws before any
// cryptographic operation runs.
//
// CONCURRENCY
//
// ensureProvidersLoaded() is idempotent and safe under concurrent calls.
// Provider modules use module-scoped state via base.js's Map registry;
// re-loading is a no-op (registerProvider rejects duplicates inside the
// provider modules' load logic).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const base = require('./key-wrapping-providers/base');
const { openTier1 } = require('./tier1-seal');

// ── Constants ────────────────────────────────────────────────────────────────

const ENVELOPE_VERSION = 1;
const KEY_LENGTH_BYTES = 32;     // AES-256

// Schemes this dispatcher knows about. The actual implementation per
// scheme is delegated to the corresponding provider module.
const SUPPORTED_SCHEMES = [
  'env-var',
  'aws-kms',
  'azure-keyvault',
  'gcp-kms',
  'hashicorp-vault',
];

const SCHEMES_REQUIRING_DB_LOOKUP = new Set([
  'aws-kms',
  'azure-keyvault',
  'gcp-kms',
  'hashicorp-vault',
]);

// ── Provider module loading ──────────────────────────────────────────────────
//
// Each provider's require() triggers a registerProvider() call inside
// its module body. We do this lazily on first wrap/unwrap rather than
// at this module's top level so a missing optional provider (e.g.
// aws-kms not yet npm-installed) doesn't crash the server at startup.
// Providers themselves use lazy require() for their cloud SDKs, so
// loading the provider module itself is always safe.

let _providersLoaded = false;

function ensureProvidersLoaded() {
  if (_providersLoaded) return;
  // Order doesn't matter; each module is independent.
  // Wrap each in try/catch so a malformed provider doesn't prevent
  // others from loading. Failures here are programming errors (bad
  // provider implementation), not operator config errors.
  const provisions = [
    './key-wrapping-providers/env-var',
    './key-wrapping-providers/aws-kms',
    './key-wrapping-providers/azure-keyvault',
    './key-wrapping-providers/gcp-kms',
    './key-wrapping-providers/hashicorp-vault',
  ];
  for (const path of provisions) {
    try {
      require(path);
    } catch (err) {
      // Don't swallow -- a provider failing to load is a serious
      // problem we want surfaced. But continue loading the others
      // so a single broken provider doesn't disable env-var.
      // Use process.stderr directly to avoid circular dependency
      // with services/logger.js.
      process.stderr.write(
        `[backup-key-wrapping] failed to load ${path}: ${err.message}\n`,
      );
    }
  }
  _providersLoaded = true;
}

// ── Envelope serialization (unchanged from pre-refactor) ────────────────────

function serializeEnvelope(envelope) {
  return Buffer.from(JSON.stringify(envelope), 'utf-8');
}

function parseEnvelope(envelopeBytes) {
  const text = Buffer.isBuffer(envelopeBytes)
    ? envelopeBytes.toString('utf-8')
    : String(envelopeBytes);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`backup-key-wrapping: envelope is not valid JSON: ${err.message}`);
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('backup-key-wrapping: envelope is not a JSON object');
  }
  if (parsed.v !== ENVELOPE_VERSION) {
    throw new Error(`backup-key-wrapping: envelope version ${parsed.v} unsupported (expected ${ENVELOPE_VERSION})`);
  }
  for (const required of ['scheme', 'ref', 'wrapped']) {
    if (typeof parsed[required] !== 'string' || parsed[required] === '') {
      throw new Error(`backup-key-wrapping: envelope missing required field '${required}'`);
    }
  }
  return parsed;
}

// ── kms_providers row lookup (cloud schemes only) ───────────────────────────

/**
 * Look up a kms_providers row by id. Returns the row with config
 * (JSON-parsed) and credentials (Tier-1-decrypted, JSON-parsed) ready
 * to pass to a provider's wrap/unwrap.
 *
 * Throws if the row is not found, disabled, or its provider_type does
 * not match expectedScheme (defense-in-depth: a manifest claiming
 * scheme='aws-kms' must reference an actually-aws-kms row).
 *
 * For env-var scheme this function is NOT called; ref is interpreted
 * as the env var name directly.
 */
function loadKmsProviderRow(db, rowId, expectedScheme) {
  if (!db || typeof db.prepare !== 'function') {
    throw new Error(
      `backup-key-wrapping: scheme '${expectedScheme}' requires opts.db ` +
      'for kms_providers row lookup',
    );
  }
  const row = db.prepare(
    'SELECT id, name, provider_type, config, credentials_encrypted, enabled FROM kms_providers WHERE id = ?',
  ).get(rowId);
  if (!row) {
    throw new Error(
      `backup-key-wrapping: kms_providers row '${rowId}' not found ` +
      `(scheme '${expectedScheme}'). The provider may have been deleted ` +
      'after this backup was created -- consult audit log for the ' +
      'KMS_PROVIDER_DELETED event and recover from a sibling backup ' +
      'wrapped under a still-existing provider.',
    );
  }
  if (row.provider_type !== expectedScheme) {
    throw new Error(
      `backup-key-wrapping: kms_providers row '${rowId}' has provider_type ` +
      `'${row.provider_type}' but envelope claims scheme '${expectedScheme}'`,
    );
  }
  if (row.enabled !== 1) {
    throw new Error(
      `backup-key-wrapping: kms_providers row '${rowId}' is disabled. ` +
      'Re-enable via the admin UI or set kms_providers.enabled = 1 ' +
      'before retrying.',
    );
  }

  let config;
  try {
    config = row.config ? JSON.parse(row.config) : {};
  } catch (err) {
    throw new Error(`backup-key-wrapping: kms_providers row '${rowId}' has malformed config JSON: ${err.message}`);
  }

  let credentials = null;
  if (row.credentials_encrypted) {
    try {
      // credentials_encrypted is the kms_providers Tier-1 column (hex storage);
      // openTier1 hex-decodes, decrypts, and JSON.parses per the registry.
      credentials = openTier1('kms_providers.credentials_encrypted', row.credentials_encrypted);
    } catch (err) {
      throw new Error(
        `backup-key-wrapping: kms_providers row '${rowId}' credentials ` +
        `failed to decrypt: ${err.message}. TIER1_ENCRYPTION_KEY may be ` +
        'misconfigured, rotated without re-wrap, or the row value is corrupt.',
      );
    }
  }

  return { row, config, credentials };
}

// ── Cloud Mode backup-KEK posture (D-B5h-5) ─────
//
// A backup KEK held in a process environment variable lives in the same memory
// as the running server, which a confidential VM is meant to protect but which
// a snapshot/restore or operator misconfiguration could still expose. Cloud
// Mode therefore refuses an env-var backup KEK for NEW backups and requires a
// cloud-KMS or Vault provider, so the KEK stays out of process memory. The
// Tier-1 KEK is unaffected -- it stays sealed to the instance vTPM. This gates
// WRAPPING only; unwrapKey (restore) accepts any scheme so existing backups
// remain recoverable.

const CLOUD_BACKUP_KEK_SCHEMES = SUPPORTED_SCHEMES.filter((s) => s !== 'env-var');

function assertCloudBackupKekPosture(scheme, cloud) {
  if (cloud === true && scheme === 'env-var') {
    const err = new Error(
      'backup-key-wrapping: cloud mode requires a cloud-KMS or Vault backup ' +
      'KEK (one of ' + CLOUD_BACKUP_KEK_SCHEMES.join(', ') + '); an env-var ' +
      'KEK is refused because it would hold the key in process memory. The ' +
      'Tier-1 KEK is unaffected and stays sealed to the instance vTPM.',
    );
    err.code = 'CLOUD_BACKUP_KEK_REQUIRED';
    throw err;
  }
}

// Lazy, decoupled read of the sealed deployment mode. Returns false when no db
// is available or the mode cannot be read, so the posture never blocks a
// non-cloud or db-less wrap.
function isCloudDeployment(db) {
  if (!db || typeof db.prepare !== 'function') return false;
  try {
    return require('./deployment-mode').summary(db).substrateCloud === true;
  } catch (_e) {
    return false;
  }
}


// ── Public: wrapKey ──────────────────────────────────────────────────────────

/**
 * Wrap an ephemeral 256-bit data key.
 *
 * Inputs:
 *   ephemeralKey  Buffer (32 bytes, AES-256)
 *   options       { scheme, kekReference, db?, logger?, signal?, timeoutMs? }
 *                 scheme        -- one of SUPPORTED_SCHEMES
 *                 kekReference  -- env var name for env-var scheme;
 *                                  kms_providers.id (UUID) for cloud schemes
 *                 db            -- required for cloud schemes
 *                 logger        -- optional, passed to provider for diagnostics
 *                 signal        -- optional AbortSignal for cancellation
 *                 timeoutMs     -- optional per-call timeout
 *
 * Returns: Buffer -- the wrapped-key.bin file contents (JSON envelope as UTF-8 bytes)
 *
 * Backward compatibility: the existing env-var call shape
 *   { scheme: 'env-var', kekReference: 'TIER1_ENCRYPTION_KEY' }
 * works without source changes in backup.js. db/logger/signal/timeoutMs
 * are all optional for env-var scheme.
 */
// Resolve a scheme's config + credentials from its kekReference. Single source of truth shared
// by wrapKey and resolveKekFingerprint, so the fingerprint always matches the KEK the DEK was
// wrapped under. env-var: kekReference IS the env var name (no DB lookup); cloud: kekReference =
// kms_providers.id, look up the row.
function resolveSchemeConfig(scheme, kekReference, db) {
  if (scheme === 'env-var') {
    return { config: { env_var_name: kekReference }, credentials: null };
  }
  const loaded = loadKmsProviderRow(db, kekReference, scheme);
  return { config: loaded.config, credentials: loaded.credentials };
}

async function wrapKey(ephemeralKey, options) {
  if (!Buffer.isBuffer(ephemeralKey) || ephemeralKey.length !== KEY_LENGTH_BYTES) {
    throw new Error(`backup-key-wrapping: ephemeralKey must be a ${KEY_LENGTH_BYTES}-byte Buffer`);
  }
  if (!options || typeof options !== 'object') {
    throw new Error('backup-key-wrapping: options object required');
  }
  const { scheme, kekReference, db, logger, signal, timeoutMs } = options;

  if (typeof scheme !== 'string' || !SUPPORTED_SCHEMES.includes(scheme)) {
    throw new Error(
      `backup-key-wrapping: unknown scheme '${scheme}' ` +
      `(supported: ${SUPPORTED_SCHEMES.join(', ')})`,
    );
  }
  if (typeof kekReference !== 'string' || !kekReference) {
    throw new Error('backup-key-wrapping: kekReference required (non-empty string)');
  }

  // Cloud backup-KEK posture (D-B5h-5): refuse an env-var KEK for new backups
  // on a cloud substrate (cloud mode or SDN+cloud). Restore (unwrapKey) is
  // unaffected.
  assertCloudBackupKekPosture(scheme, isCloudDeployment(db));

  ensureProvidersLoaded();

  const provider = base.getProvider(scheme);
  if (!provider) {
    throw new Error(
      `backup-key-wrapping: provider for scheme '${scheme}' is not registered. ` +
      'The provider module may have failed to load -- check stderr at startup.',
    );
  }

  // Resolve config + credentials per scheme (shared with resolveKekFingerprint).
  const { config, credentials } = resolveSchemeConfig(scheme, kekReference, db);

  const providerOpts = { logger, signal, timeoutMs };
  let wrapped;
  try {
    wrapped = await provider.wrap(ephemeralKey, config, credentials, providerOpts);
  } catch (err) {
    // Re-raise; provider sets KeyWrappingError with retryable flag.
    throw err;
  }
  if (!Buffer.isBuffer(wrapped) || wrapped.length === 0) {
    throw new Error(`backup-key-wrapping: provider '${scheme}' wrap returned non-Buffer or empty`);
  }

  const envelope = {
    v: ENVELOPE_VERSION,
    scheme,
    ref: kekReference,
    wrapped: wrapped.toString('base64'),
  };
  return serializeEnvelope(envelope);
}

// ── Public: unwrapKey ────────────────────────────────────────────────────────

/**
 * Unwrap a wrapped-key.bin file back to the raw 32-byte ephemeral key.
 *
 * Inputs:
 *   envelopeBytes    Buffer or string -- the wrapped-key.bin contents
 *   expectedScheme   string -- the manifest-declared scheme
 *   expectedRef      string -- the manifest-declared kek_reference
 *   options          { db?, logger?, signal?, timeoutMs? } (optional)
 *
 * Defense-in-depth: throws if the envelope's claimed scheme/ref do not
 * match expectedScheme/expectedRef, even though the manifest's
 * files[].sha256 hash would also catch this. Two redundant integrity
 * gates is the SOC-grade design.
 *
 * Returns: Buffer (32 bytes -- the ephemeral key)
 */
async function unwrapKey(envelopeBytes, expectedScheme, expectedRef, options) {
  if (typeof expectedScheme !== 'string' || !expectedScheme) {
    throw new Error('backup-key-wrapping: expectedScheme required for unwrap');
  }
  if (typeof expectedRef !== 'string' || !expectedRef) {
    throw new Error('backup-key-wrapping: expectedRef required for unwrap');
  }
  if (!SUPPORTED_SCHEMES.includes(expectedScheme)) {
    throw new Error(
      `backup-key-wrapping: unknown scheme '${expectedScheme}' ` +
      `(supported: ${SUPPORTED_SCHEMES.join(', ')})`,
    );
  }

  const envelope = parseEnvelope(envelopeBytes);

  if (envelope.scheme !== expectedScheme) {
    throw new Error(
      `backup-key-wrapping: envelope scheme '${envelope.scheme}' ` +
      `does not match manifest-declared scheme '${expectedScheme}'`,
    );
  }
  if (envelope.ref !== expectedRef) {
    throw new Error(
      `backup-key-wrapping: envelope ref '${envelope.ref}' ` +
      `does not match manifest-declared ref '${expectedRef}'`,
    );
  }

  ensureProvidersLoaded();

  const provider = base.getProvider(expectedScheme);
  if (!provider) {
    throw new Error(
      `backup-key-wrapping: provider for scheme '${expectedScheme}' is not ` +
      'registered. The provider module may have failed to load -- check ' +
      'stderr at startup.',
    );
  }

  // Resolve config + credentials per scheme (same logic as wrapKey).
  const opts = options || {};
  let config, credentials;
  if (expectedScheme === 'env-var') {
    config = { env_var_name: expectedRef };
    credentials = null;
  } else {
    const loaded = loadKmsProviderRow(opts.db, expectedRef, expectedScheme);
    config = loaded.config;
    credentials = loaded.credentials;
  }

  const wrappedBytes = Buffer.from(envelope.wrapped, 'base64');
  const providerOpts = {
    logger: opts.logger,
    signal: opts.signal,
    timeoutMs: opts.timeoutMs,
  };

  let plaintext;
  try {
    plaintext = await provider.unwrap(wrappedBytes, config, credentials, providerOpts);
  } catch (err) {
    // Re-raise with provider's KeyWrappingError. Unwrap auth failures
    // are always permanent; no retry helps when the key is wrong.
    throw err;
  }

  if (!Buffer.isBuffer(plaintext)) {
    throw new Error(`backup-key-wrapping: provider '${expectedScheme}' unwrap returned non-Buffer`);
  }
  if (plaintext.length !== KEY_LENGTH_BYTES) {
    throw new Error(
      `backup-key-wrapping: provider '${expectedScheme}' unwrap returned ` +
      `${plaintext.length} bytes, expected ${KEY_LENGTH_BYTES}`,
    );
  }
  return plaintext;
}

// ── Module exports ───────────────────────────────────────────────────────────

// Compute the KEK fingerprint for a wrapping scheme (D-R2-4). Dispatches to the provider's
// kekFingerprint; the caller supplies the same config/credentials it passes to wrapKey. Used at
// backup creation to stamp the manifest, and at restore to recompute against the target's KEK.
function computeKekFingerprint(scheme, config, credentials) {
  if (typeof scheme !== 'string' || !SUPPORTED_SCHEMES.includes(scheme)) {
    throw new Error(`backup-key-wrapping: unknown scheme '${scheme}' for KEK fingerprint`);
  }
  ensureProvidersLoaded();
  const provider = base.getProvider(scheme);
  if (!provider || typeof provider.kekFingerprint !== 'function') {
    throw new Error(`backup-key-wrapping: provider '${scheme}' has no kekFingerprint`);
  }
  return provider.kekFingerprint(config, credentials);
}

// D-R2-2: raw-KEK DEK unwrap for the offline import-rekey tool. A cross-KEK bundle's DEK is
// wrapped under the SOURCE KEK; the tool recovers that KEK from the source recovery code and
// unwraps with it here (bypassing reference resolution). ONLY env-var (local-material) supports
// this -- a cloud KEK never leaves the HSM, so a cloud cross-KEK import is not a raw-KEK operation.
function unwrapKeyWithRawKek(wrappedDek, scheme, rawKek) {
  if (typeof scheme !== 'string' || !SUPPORTED_SCHEMES.includes(scheme)) {
    throw new Error(`backup-key-wrapping: unknown scheme '${scheme}' for raw-KEK unwrap`);
  }
  if (scheme !== 'env-var') {
    throw new Error(`backup-key-wrapping: raw-KEK unwrap is only supported for the env-var scheme (cloud KEKs stay in the HSM); scheme='${scheme}'`);
  }
  ensureProvidersLoaded();
  const provider = base.getProvider('env-var');
  if (!provider || typeof provider.unwrapWithRawKek !== 'function') {
    throw new Error('backup-key-wrapping: env-var provider has no unwrapWithRawKek');
  }
  return provider.unwrapWithRawKek(wrappedDek, rawKek);
}

// Resolve a scheme's config from its kekReference (the same resolution wrapKey uses), then
// compute the KEK fingerprint. The backup path uses this at creation to stamp the manifest and at
// restore to recompute against the target's KEK.
function resolveKekFingerprint(scheme, kekReference, db) {
  if (typeof scheme !== 'string' || !SUPPORTED_SCHEMES.includes(scheme)) {
    throw new Error(`backup-key-wrapping: unknown scheme '${scheme}' for KEK fingerprint`);
  }
  if (typeof kekReference !== 'string' || !kekReference) {
    throw new Error('backup-key-wrapping: kekReference required for KEK fingerprint');
  }
  ensureProvidersLoaded();
  const { config, credentials } = resolveSchemeConfig(scheme, kekReference, db);
  return computeKekFingerprint(scheme, config, credentials);
}

module.exports = {
  // Public API (signatures unchanged from pre-refactor for env-var
  // backward compatibility; cloud schemes accept additional options.db)
  wrapKey,
  unwrapKey,
  computeKekFingerprint,
  resolveKekFingerprint,
  unwrapKeyWithRawKek,
  assertCloudBackupKekPosture,

  // Exported for tests and for diagnostic tools that may want to
  // inspect a wrapped-key.bin without performing crypto.
  parseEnvelope,
  serializeEnvelope,

  // Constants (preserved from pre-refactor for any callers importing them).
  ENVELOPE_VERSION,
  KEY_LENGTH_BYTES,
  SUPPORTED_SCHEMES,

  // Internal helpers exposed for tests only -- not stable for production callers.
  _internal: {
    ensureProvidersLoaded,
    loadKmsProviderRow,
  },
};

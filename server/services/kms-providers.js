// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — KMS Providers Service
//
// Manages rows in the kms_providers table. Each row describes one Key
// Encryption Key (KEK) source -- env-var fallback, AWS KMS, Azure Key
// Vault, GCP KMS, or HashiCorp Vault transit engine -- and is consumed
// by services/backup-key-wrapping.js to wrap/unwrap per-backup ephemeral
// data keys.
//
// Public API:
//   listProviders(db, opts?)              -> array
//   getProviderById(db, id)               -> row | null
//   getProviderByName(db, name)           -> row | null
//   getDefault(db)                        -> row (throws if none)
//   probeConfig(db, args, opts?)          -> { ok, error?, detail? }
//   createProvider(db, args, ctx)         -> row  (audit: KMS_PROVIDER_CREATED)
//   updateProvider(db, id, args, ctx)     -> row  (audit: KMS_PROVIDER_UPDATED)
//   setDefault(db, id, ctx)               -> { previous_default_id, new_default_id }
//   enableProvider(db, id, ctx)           -> row  (audit: KMS_PROVIDER_ENABLED)
//   disableProvider(db, id, ctx)          -> row  (audit: KMS_PROVIDER_DISABLED)
//   deleteProvider(db, id, ctx)           -> { deleted: true }
//   probeProvider(db, id, ctx)            -> { ok, error?, detail?, probed_at }
//
// Read APIs NEVER return credentials_encrypted -- the field is stripped.
// Decryption only happens internally during probe and inside backup-key-
// wrapping.js's loadKmsProviderRow.
//
// SOC-grade properties built in:
//   - Tier-1 AES-256-GCM encryption-at-rest for credentials
//   - validateConfig + validateCredentials BEFORE insert/update via the
//     provider's own validators (typed errors, no half-formed rows)
//   - Optional probe before commit so config errors surface as create-
//     time failures rather than first-wrap failures hours later
//   - Audit log on every state transition (CREATE/UPDATE/ENABLE/DISABLE/
//     SET_DEFAULT/DELETE/PROBE)
//   - Atomic default swap inside a transaction: the unique partial index
//     idx_kms_providers_default (WHERE is_default = 1) guarantees only
//     one default exists at any moment
//   - Refuses to hard-delete the env-var-default seed row -- disable
//     instead if you really mean to remove it from the wrap rotation
//   - Refuses to hard-delete the current default -- caller must set a
//     different default first, then delete
//   - Refuses to disable the only enabled row -- backups must always
//     have a wrap target available
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const base = require('./key-wrapping-providers/base');
const { sealTier1, openTier1 } = require('./tier1-seal');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');

// ── Constants ────────────────────────────────────────────────────────────────

const SEED_ROW_NAME = 'env-var-default';
const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$/;
const NAME_MAX_LENGTH = 64;
const VALID_PROVIDER_TYPES = base.VALID_PROVIDER_NAMES;
const PROBE_DEFAULT_TIMEOUT_MS = 10000;

// ── Stable error codes (route layer maps to HTTP) ────────────────────────────

const CODES = {
  INVALID_INPUT:                'INVALID_INPUT',
  NAME_CONFLICT:                'NAME_CONFLICT',
  PROVIDER_NOT_FOUND:           'PROVIDER_NOT_FOUND',
  PROVIDER_DISABLED:            'PROVIDER_DISABLED',
  PROVIDER_VALIDATION_FAILED:   'PROVIDER_VALIDATION_FAILED',
  PROVIDER_PROBE_FAILED:        'PROVIDER_PROBE_FAILED',
  IS_SEED_ROW:                  'IS_SEED_ROW',
  IS_DEFAULT:                   'IS_DEFAULT',
  LAST_ENABLED:                 'LAST_ENABLED',
  ENCRYPTION_NOT_CONFIGURED:    'ENCRYPTION_NOT_CONFIGURED',
  PROVIDER_NOT_REGISTERED:      'PROVIDER_NOT_REGISTERED',
};

class KmsProviderError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'KmsProviderError';
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

function nowSqlite() {
  // 'YYYY-MM-DD HH:MM:SS' in UTC, matching the DEFAULT (datetime('now'))
  // pattern used everywhere else in the schema.
  return new Date().toISOString().slice(0, 19).replace('T', ' ');
}

function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

function ensureProvidersLoaded() {
  // Provider modules self-register at require-time. Loading them here
  // ensures listProviders() and provider lookups work even if no
  // wrap/unwrap call has run yet. Idempotent.
  const provisions = [
    './key-wrapping-providers/env-var',
    './key-wrapping-providers/aws-kms',
    './key-wrapping-providers/azure-keyvault',
    './key-wrapping-providers/gcp-kms',
    './key-wrapping-providers/hashicorp-vault',
  ];
  for (const path of provisions) {
    try { require(path); } catch (err) {
      process.stderr.write(`[kms-providers] failed to load ${path}: ${err.message}\n`);
    }
  }
}

function validateName(name) {
  if (typeof name !== 'string' || name === '') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'name required (non-empty string)');
  }
  if (name.length > NAME_MAX_LENGTH) {
    throw new KmsProviderError(CODES.INVALID_INPUT, `name max length ${NAME_MAX_LENGTH}`);
  }
  if (!NAME_PATTERN.test(name)) {
    throw new KmsProviderError(
      CODES.INVALID_INPUT,
      'name must be lowercase alphanumeric with optional hyphens, ' +
      'not starting or ending with a hyphen',
    );
  }
}

function validateProviderType(providerType) {
  if (!VALID_PROVIDER_TYPES.includes(providerType)) {
    throw new KmsProviderError(
      CODES.INVALID_INPUT,
      `provider_type must be one of: ${VALID_PROVIDER_TYPES.join(', ')}`,
    );
  }
}

function getProviderImpl(providerType) {
  ensureProvidersLoaded();
  const impl = base.getProvider(providerType);
  if (!impl) {
    throw new KmsProviderError(
      CODES.PROVIDER_NOT_REGISTERED,
      `provider implementation for '${providerType}' is not registered. ` +
      'The module may have failed to load -- check stderr at startup.',
    );
  }
  return impl;
}

/**
 * Run validateConfig + validateCredentials on the given values. Throws
 * KmsProviderError(PROVIDER_VALIDATION_FAILED) if either rejects.
 */
function validateConfigAndCredentials(impl, config, credentials) {
  const cfgResult = impl.validateConfig(config || {});
  if (!cfgResult.ok) {
    throw new KmsProviderError(
      CODES.PROVIDER_VALIDATION_FAILED,
      `config invalid: ${cfgResult.error}`,
      { phase: 'config', field: cfgResult.field },
    );
  }
  const credResult = impl.validateCredentials(credentials);
  if (!credResult.ok) {
    throw new KmsProviderError(
      CODES.PROVIDER_VALIDATION_FAILED,
      `credentials invalid: ${credResult.error}`,
      { phase: 'credentials', field: credResult.field },
    );
  }
}

/**
 * Encrypt credentials object with Tier-1 and hex-encode for SQLite TEXT.
 * Returns null for null/undefined input (env-var has no credentials).
 */
function encryptCredentials(credentials) {
  if (credentials === null || credentials === undefined) return null;
  try {
    return sealTier1('kms_providers.credentials_encrypted', credentials);
  } catch (err) {
    throw new KmsProviderError(
      CODES.ENCRYPTION_NOT_CONFIGURED,
      `cannot encrypt credentials -- TIER1_ENCRYPTION_KEY may not be set: ${err.message}`,
    );
  }
}

function decryptCredentials(hexOrNull) {
  if (!hexOrNull) return null;
  try {
    return openTier1('kms_providers.credentials_encrypted', hexOrNull);
  } catch (err) {
    throw new KmsProviderError(
      CODES.ENCRYPTION_NOT_CONFIGURED,
      `cannot decrypt credentials -- TIER1_ENCRYPTION_KEY may have rotated ` +
      `without re-wrap, or the column value is corrupt: ${err.message}`,
    );
  }
}

/**
 * Strip credentials_encrypted from a row before returning to a caller.
 * Parses config JSON. last_probe_* fields are passed through as-is.
 */
function publicView(row) {
  if (!row) return null;
  let config = {};
  try { config = row.config ? JSON.parse(row.config) : {}; } catch { config = {}; }
  return {
    id: row.id,
    name: row.name,
    provider_type: row.provider_type,
    config,
    has_credentials: row.credentials_encrypted !== null && row.credentials_encrypted !== '',
    enabled: row.enabled === 1,
    is_default: row.is_default === 1,
    last_probe_at: row.last_probe_at,
    last_probe_status: row.last_probe_status,
    last_probe_error: row.last_probe_error,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

// ── Read API ─────────────────────────────────────────────────────────────────

function listProviders(db, opts = {}) {
  const where = [];
  const params = [];
  if (opts.provider_type !== undefined) {
    validateProviderType(opts.provider_type);
    where.push('provider_type = ?');
    params.push(opts.provider_type);
  }
  if (opts.enabled !== undefined) {
    where.push('enabled = ?');
    params.push(opts.enabled ? 1 : 0);
  }
  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const limit = Math.min(Math.max(Number(opts.limit) || 100, 1), 1000);
  const offset = Math.max(Number(opts.offset) || 0, 0);
  const rows = db.prepare(`
    SELECT * FROM kms_providers
    ${whereClause}
    ORDER BY is_default DESC, enabled DESC, name ASC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset);
  return rows.map(publicView);
}

function getProviderById(db, id) {
  if (typeof id !== 'string' || id === '') return null;
  const row = db.prepare('SELECT * FROM kms_providers WHERE id = ?').get(id);
  return publicView(row);
}

function getProviderByName(db, name) {
  if (typeof name !== 'string' || name === '') return null;
  const row = db.prepare('SELECT * FROM kms_providers WHERE name = ?').get(name);
  return publicView(row);
}

/**
 * Returns the row marked is_default = 1. Throws if none exists, which
 * indicates a misconfigured deployment (the seed row should always be
 * present unless an admin explicitly cleared the default flag and
 * never set a new one -- that's an operator error, not a service bug).
 */
function getDefault(db) {
  const row = db.prepare(
    'SELECT * FROM kms_providers WHERE is_default = 1 AND enabled = 1',
  ).get();
  if (!row) {
    throw new KmsProviderError(
      CODES.PROVIDER_NOT_FOUND,
      'no enabled default kms_provider row exists. Set one with setDefault() ' +
      'or re-run db/init.js to restore the env-var-default seed row.',
    );
  }
  return publicView(row);
}

// ── Probe (no DB write) ──────────────────────────────────────────────────────

/**
 * Validate + round-trip a config/credentials pair without persisting.
 * Use before createProvider() to surface bad config at form-submit time
 * rather than after a row is in the DB.
 *
 * Returns: { ok: true, detail } | { ok: false, error, detail? }
 * Never throws (other than for INVALID_INPUT on provider_type) so the
 * route layer can show the result inline as form feedback.
 */
async function probeConfig(db, args, opts = {}) {
  if (!args || typeof args !== 'object') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'args object required');
  }
  validateProviderType(args.provider_type);
  const impl = getProviderImpl(args.provider_type);
  try {
    validateConfigAndCredentials(impl, args.config, args.credentials);
  } catch (err) {
    if (err instanceof KmsProviderError && err.code === CODES.PROVIDER_VALIDATION_FAILED) {
      return { ok: false, error: err.message, detail: err.detail };
    }
    throw err;
  }
  return await impl.probe(args.config || {}, args.credentials || null, {
    timeoutMs: opts.timeoutMs || PROBE_DEFAULT_TIMEOUT_MS,
    logger,
  });
}

// ── Mutating API ─────────────────────────────────────────────────────────────

/**
 * Create a new kms_providers row.
 *
 * args: {
 *   name              required, unique, ^[a-z0-9-]+$
 *   provider_type     required, one of VALID_PROVIDER_TYPES
 *   config            required, object (validated by provider)
 *   credentials       optional, object or null (validated by provider)
 *   enabled           optional, default true
 *   is_default        optional, default false (atomically swaps current default)
 *   probe             optional, default true for cloud schemes, false for env-var
 * }
 * ctx: { user_id, client_ip }
 *
 * Returns: the new row's publicView.
 *
 * Throws KmsProviderError on validation, name collision, or probe failure
 * (when probe=true). On probe failure, the row is NOT inserted -- this
 * is the "fail fast at create" behavior that turns first-wrap failures
 * into create-time failures.
 */
async function createProvider(db, args, ctx) {
  if (!args || typeof args !== 'object') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'args object required');
  }
  if (!ctx || typeof ctx !== 'object' || typeof ctx.user_id !== 'string') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'ctx.user_id required');
  }

  validateName(args.name);
  validateProviderType(args.provider_type);
  const impl = getProviderImpl(args.provider_type);
  validateConfigAndCredentials(impl, args.config, args.credentials);

  const enabled = args.enabled === undefined ? true : Boolean(args.enabled);
  const isDefault = Boolean(args.is_default);
  const shouldProbe = args.probe === undefined
    ? args.provider_type !== 'env-var'
    : Boolean(args.probe);

  // Probe before INSERT so failures surface here rather than at first wrap.
  let probeAt = null;
  let probeStatus = null;
  let probeError = null;
  if (shouldProbe) {
    const probeResult = await impl.probe(
      args.config || {},
      args.credentials || null,
      { timeoutMs: PROBE_DEFAULT_TIMEOUT_MS, logger },
    );
    probeAt = nowSqlite();
    if (probeResult.ok) {
      probeStatus = 'ok';
    } else {
      probeStatus = 'failed';
      probeError = probeResult.error || 'probe failed without an error message';
      throw new KmsProviderError(
        CODES.PROVIDER_PROBE_FAILED,
        `probe failed: ${probeError}`,
        probeResult.detail,
      );
    }
  }

  const id = generateId();
  const credentialsHex = encryptCredentials(args.credentials);

  // Insert and (optionally) atomic-swap default in one transaction so
  // the unique partial index doesn't throw between the two UPDATEs.
  const tx = db.transaction(() => {
    // Detect name collision pre-insert for a typed error rather than
    // letting the UNIQUE constraint surface as a generic SqliteError.
    const existing = db.prepare('SELECT 1 FROM kms_providers WHERE name = ?').get(args.name);
    if (existing) {
      throw new KmsProviderError(
        CODES.NAME_CONFLICT,
        `kms_providers row with name '${args.name}' already exists`,
      );
    }

    if (isDefault) {
      db.prepare('UPDATE kms_providers SET is_default = 0 WHERE is_default = 1').run();
    }

    db.prepare(`
      INSERT INTO kms_providers (
        id, name, provider_type, config, credentials_encrypted,
        enabled, is_default, last_probe_at, last_probe_status, last_probe_error
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      args.name,
      args.provider_type,
      JSON.stringify(args.config || {}),
      credentialsHex,
      enabled ? 1 : 0,
      isDefault ? 1 : 0,
      probeAt,
      probeStatus,
      probeError,
    );
  });
  tx();

  const newRow = db.prepare('SELECT * FROM kms_providers WHERE id = ?').get(id);

  auditLog(
    ctx.user_id,
    'KMS_PROVIDER_CREATED',
    `id=${id} name=${args.name} provider_type=${args.provider_type} ` +
      `enabled=${enabled} is_default=${isDefault} probed=${shouldProbe}`,
    ctx.client_ip || null,
  );
  logger.info('kms_provider created', {
    id, name: args.name, provider_type: args.provider_type,
    enabled, is_default: isDefault, probed: shouldProbe,
  });

  return publicView(newRow);
}

/**
 * Update mutable fields on an existing row.
 *
 * args: {
 *   name?           rename (validated for uniqueness)
 *   config?         replace config; triggers re-validate + re-probe
 *   credentials?    replace credentials; triggers re-validate + re-probe.
 *                   Pass null to clear; omit to keep the existing value.
 *   enabled?        toggle enable/disable (also see enableProvider/disableProvider)
 * }
 * ctx: { user_id, client_ip }
 *
 * Provider type cannot be changed -- create a new row and delete the old one.
 */
async function updateProvider(db, id, args, ctx) {
  if (typeof id !== 'string' || id === '') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'id required');
  }
  if (!ctx || typeof ctx.user_id !== 'string') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'ctx.user_id required');
  }
  args = args || {};

  const existing = db.prepare('SELECT * FROM kms_providers WHERE id = ?').get(id);
  if (!existing) {
    throw new KmsProviderError(CODES.PROVIDER_NOT_FOUND, `kms_provider ${id} not found`);
  }

  const updates = [];
  const params = [];
  const changed = {};

  if (args.name !== undefined && args.name !== existing.name) {
    validateName(args.name);
    const collision = db.prepare(
      'SELECT 1 FROM kms_providers WHERE name = ? AND id != ?',
    ).get(args.name, id);
    if (collision) {
      throw new KmsProviderError(
        CODES.NAME_CONFLICT,
        `kms_providers row with name '${args.name}' already exists`,
      );
    }
    updates.push('name = ?');
    params.push(args.name);
    changed.name = args.name;
  }

  // Determine effective new config + credentials for re-validate / re-probe.
  // Only re-probe if either changed.
  const cfgChanged = args.config !== undefined;
  const credChanged = args.credentials !== undefined;
  if (cfgChanged || credChanged) {
    const impl = getProviderImpl(existing.provider_type);
    const newConfig = cfgChanged ? args.config : JSON.parse(existing.config || '{}');
    let newCredentials;
    if (credChanged) {
      newCredentials = args.credentials;
    } else {
      newCredentials = decryptCredentials(existing.credentials_encrypted);
    }
    validateConfigAndCredentials(impl, newConfig, newCredentials);

    // Re-probe (skip for env-var per createProvider's default behavior)
    if (existing.provider_type !== 'env-var') {
      const probeResult = await impl.probe(newConfig || {}, newCredentials || null, {
        timeoutMs: PROBE_DEFAULT_TIMEOUT_MS, logger,
      });
      const probeAt = nowSqlite();
      if (!probeResult.ok) {
        throw new KmsProviderError(
          CODES.PROVIDER_PROBE_FAILED,
          `probe failed after update: ${probeResult.error || 'unknown'}`,
          probeResult.detail,
        );
      }
      updates.push('last_probe_at = ?', 'last_probe_status = ?', 'last_probe_error = ?');
      params.push(probeAt, 'ok', null);
    }

    if (cfgChanged) {
      updates.push('config = ?');
      params.push(JSON.stringify(newConfig || {}));
      changed.config = true;
    }
    if (credChanged) {
      updates.push('credentials_encrypted = ?');
      params.push(encryptCredentials(newCredentials));
      changed.credentials = true;
    }
  }

  if (args.enabled !== undefined) {
    const targetEnabled = Boolean(args.enabled);
    if (targetEnabled !== (existing.enabled === 1)) {
      if (!targetEnabled) {
        // Disabling: refuse if it's the only enabled row or if it's the default.
        guardAgainstLastEnabled(db, id);
        if (existing.is_default === 1) {
          throw new KmsProviderError(
            CODES.IS_DEFAULT,
            'cannot disable the default kms_provider; set a different default first',
          );
        }
      }
      updates.push('enabled = ?');
      params.push(targetEnabled ? 1 : 0);
      changed.enabled = targetEnabled;
    }
  }

  if (updates.length === 0) {
    return publicView(existing);
  }

  updates.push("updated_at = datetime('now')");
  params.push(id);
  db.prepare(`UPDATE kms_providers SET ${updates.join(', ')} WHERE id = ?`).run(...params);

  const updated = db.prepare('SELECT * FROM kms_providers WHERE id = ?').get(id);

  auditLog(
    ctx.user_id,
    'KMS_PROVIDER_UPDATED',
    `id=${id} fields=${Object.keys(changed).join(',')}`,
    ctx.client_ip || null,
  );
  logger.info('kms_provider updated', { id, changed });

  return publicView(updated);
}

function guardAgainstLastEnabled(db, idAboutToBeDisabled) {
  const otherEnabled = db.prepare(
    'SELECT COUNT(*) AS c FROM kms_providers WHERE enabled = 1 AND id != ?',
  ).get(idAboutToBeDisabled).c;
  if (otherEnabled === 0) {
    throw new KmsProviderError(
      CODES.LAST_ENABLED,
      'cannot disable the only enabled kms_provider; backups would have ' +
      'no wrap target. Enable another row first.',
    );
  }
}

function enableProvider(db, id, ctx) {
  return updateProvider(db, id, { enabled: true }, ctx);
}

function disableProvider(db, id, ctx) {
  return updateProvider(db, id, { enabled: false }, ctx);
}

/**
 * Atomically switch the default-marked row. Refuses if the target is
 * disabled (the default must be usable). The unique partial index
 * idx_kms_providers_default guarantees at most one default at a time;
 * the transaction ensures the swap is atomic.
 */
function setDefault(db, id, ctx) {
  if (typeof id !== 'string' || id === '') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'id required');
  }
  if (!ctx || typeof ctx.user_id !== 'string') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'ctx.user_id required');
  }

  const target = db.prepare('SELECT * FROM kms_providers WHERE id = ?').get(id);
  if (!target) {
    throw new KmsProviderError(CODES.PROVIDER_NOT_FOUND, `kms_provider ${id} not found`);
  }
  if (target.enabled !== 1) {
    throw new KmsProviderError(
      CODES.PROVIDER_DISABLED,
      'cannot set a disabled kms_provider as default; enable it first',
    );
  }

  let previousDefaultId = null;
  const tx = db.transaction(() => {
    const prev = db.prepare(
      'SELECT id FROM kms_providers WHERE is_default = 1',
    ).get();
    previousDefaultId = prev ? prev.id : null;
    if (previousDefaultId === id) return; // no-op
    db.prepare('UPDATE kms_providers SET is_default = 0, updated_at = datetime("now") WHERE is_default = 1').run();
    db.prepare('UPDATE kms_providers SET is_default = 1, updated_at = datetime("now") WHERE id = ?').run(id);
  });
  tx();

  auditLog(
    ctx.user_id,
    'KMS_PROVIDER_DEFAULT_CHANGED',
    `previous=${previousDefaultId || 'none'} new=${id}`,
    ctx.client_ip || null,
  );
  logger.info('kms_provider default changed', { previous_default_id: previousDefaultId, new_default_id: id });

  return { previous_default_id: previousDefaultId, new_default_id: id };
}

/**
 * Hard-delete a row. Refuses to delete:
 *   - the env-var-default seed row (use disable instead)
 *   - the current default (set a different default first)
 *   - the only enabled row (would leave backups with no wrap target)
 *
 * Note: this does NOT check whether any extant backup was wrapped under
 * this row -- the manifest's ref field is on disk, not queryable from
 * SQL. Operators MUST keep all kms_providers rows referenced by any
 * backup they intend to be able to restore. The audit log entry
 * KMS_PROVIDER_DELETED records the deletion for forensic reconstruction.
 */
function deleteProvider(db, id, ctx) {
  if (typeof id !== 'string' || id === '') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'id required');
  }
  if (!ctx || typeof ctx.user_id !== 'string') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'ctx.user_id required');
  }

  const existing = db.prepare('SELECT * FROM kms_providers WHERE id = ?').get(id);
  if (!existing) {
    throw new KmsProviderError(CODES.PROVIDER_NOT_FOUND, `kms_provider ${id} not found`);
  }
  if (existing.name === SEED_ROW_NAME) {
    throw new KmsProviderError(
      CODES.IS_SEED_ROW,
      `cannot delete the '${SEED_ROW_NAME}' seed row; disable it instead. ` +
      'Re-running db/init.js will not re-create a deleted seed row.',
    );
  }
  if (existing.is_default === 1) {
    throw new KmsProviderError(
      CODES.IS_DEFAULT,
      'cannot delete the default kms_provider; set a different default first',
    );
  }
  if (existing.enabled === 1) {
    guardAgainstLastEnabled(db, id);
  }

  db.prepare('DELETE FROM kms_providers WHERE id = ?').run(id);

  auditLog(
    ctx.user_id,
    'KMS_PROVIDER_DELETED',
    `id=${id} name=${existing.name} provider_type=${existing.provider_type}`,
    ctx.client_ip || null,
  );
  logger.warn('kms_provider deleted', {
    id, name: existing.name, provider_type: existing.provider_type,
  });

  return { deleted: true };
}

/**
 * Round-trip probe an existing row. Updates last_probe_at, last_probe_status,
 * last_probe_error on the row and audit-logs the result.
 *
 * Returns: { ok, error?, detail?, probed_at }
 */
async function probeProvider(db, id, ctx, opts = {}) {
  if (typeof id !== 'string' || id === '') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'id required');
  }
  if (!ctx || typeof ctx.user_id !== 'string') {
    throw new KmsProviderError(CODES.INVALID_INPUT, 'ctx.user_id required');
  }

  const row = db.prepare('SELECT * FROM kms_providers WHERE id = ?').get(id);
  if (!row) {
    throw new KmsProviderError(CODES.PROVIDER_NOT_FOUND, `kms_provider ${id} not found`);
  }

  const impl = getProviderImpl(row.provider_type);
  const config = row.config ? JSON.parse(row.config) : {};
  const credentials = decryptCredentials(row.credentials_encrypted);

  const result = await impl.probe(config, credentials, {
    timeoutMs: opts.timeoutMs || PROBE_DEFAULT_TIMEOUT_MS,
    logger,
  });
  const probedAt = nowSqlite();

  db.prepare(`
    UPDATE kms_providers
    SET last_probe_at = ?,
        last_probe_status = ?,
        last_probe_error = ?,
        updated_at = datetime('now')
    WHERE id = ?
  `).run(
    probedAt,
    result.ok ? 'ok' : 'failed',
    result.ok ? null : (result.error || 'probe failed without an error message'),
    id,
  );

  auditLog(
    ctx.user_id,
    'KMS_PROVIDER_PROBED',
    `id=${id} name=${row.name} status=${result.ok ? 'ok' : 'failed'}` +
      (result.ok ? '' : ` error=${result.error}`),
    ctx.client_ip || null,
  );
  logger.info('kms_provider probed', { id, name: row.name, ok: result.ok, error: result.error });

  return { ...result, probed_at: probedAt };
}

// ── Module exports ───────────────────────────────────────────────────────────

module.exports = {
  // Read API
  listProviders,
  getProviderById,
  getProviderByName,
  getDefault,

  // Probe (no DB write)
  probeConfig,

  // Mutating API
  createProvider,
  updateProvider,
  setDefault,
  enableProvider,
  disableProvider,
  deleteProvider,
  probeProvider,

  // Error class + codes
  KmsProviderError,
  CODES,

  // Constants
  VALID_PROVIDER_TYPES,
  SEED_ROW_NAME,

  // Internal helpers exposed for tests only
  _internal: {
    nowSqlite,
    generateId,
    publicView,
    encryptCredentials,
    decryptCredentials,
    ensureProvidersLoaded,
  },
};

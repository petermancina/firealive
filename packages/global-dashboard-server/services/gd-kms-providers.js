'use strict';

// =============================================================================
// FIREALIVE GD -- KMS provider registry service  [B6g]
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
//
// CRUD for gd_kms_providers, the registry of key-wrapping providers that may
// hold the GD's per-backup data key.
//
// CUSTODY, NEVER RECOVERY. A provider here wraps the PER-BACKUP EPHEMERAL DATA
// KEY. It does not wrap the GD Tier-1 KEK, and the Tier-1 KEK is escrowed to no
// provider anywhere. Recovering a deployment always means re-establishing the
// KEK from the offline recovery code, because a v2 archive is the database file
// and the secret columns inside it stay sealed to hardware that is gone.
// Nothing in this file is a recovery path, and no message it emits may suggest
// one.
//
// FOUR GUARDS THAT THE REGIONAL SERVER'S EQUIVALENT DOES NOT HAVE, each for a
// reason found in this codebase rather than imported from it:
//
//   1. THE RESIDENCY GATE AT CONFIGURATION TIME. A KMS key has a region and its
//      operator has a domicile, and a key custodian can be COMPELLED TO UNWRAP.
//      gd-key-custody-residency evaluates that before a provider is stored, and
//      denies by default when a residency policy is declared but key_custody is
//      unset -- unlike the data-location categories, which treat an unset policy
//      as open.
//
//   2. DELETION REFUSED WHILE A BACKUP DEPENDS ON IT. Checked here AND enforced
//      by the database: backups.wrap_provider_id REFERENCES gd_kms_providers(id)
//      ON DELETE RESTRICT, and B6g turned foreign-key enforcement on, so a
//      caller who bypasses this service entirely still cannot orphan a backup.
//      The service check exists to produce a message an operator can act on;
//      the FK exists because a message is not a control.
//
//   3. RETIREMENT AS A FIRST-CLASS STATE. `enabled = 0` means "do not use for
//      new backups". `retired = 1` means "keep this row only so existing
//      manifests can still restore". One flag for both is how an operator
//      removes a provider a manifest still needs.
//
//   4. NO SILENT DOWNGRADE. Changing a provider's type or config is prospective
//      only. It never rewrites what an existing manifest recorded, because
//      restore dispatches on the manifest's {scheme, ref} and not on current
//      config.
//
// Credentials are sealed through gd-tier1-seal, whose column registry is
// GENERATED from the schema. Sealing an unregistered column throws, so
// gd_kms_providers.credentials_encrypted was registered in the same change that
// created the table.

const crypto = require('crypto');
const base = require('./gd-key-wrapping-providers/base');
const { sealTier1, openTier1 } = require('./gd-tier1-seal');
const keyCustody = require('./gd-key-custody-residency');

const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$/;
const NAME_MAX_LENGTH = 64;
const LOCAL_PROVIDER_TYPE = 'gd-tier1';

const CODES = {
  INVALID_INPUT: 'INVALID_INPUT',
  NAME_CONFLICT: 'NAME_CONFLICT',
  PROVIDER_NOT_FOUND: 'PROVIDER_NOT_FOUND',
  PROVIDER_DISABLED: 'PROVIDER_DISABLED',
  PROVIDER_VALIDATION_FAILED: 'PROVIDER_VALIDATION_FAILED',
  PROVIDER_PROBE_FAILED: 'PROVIDER_PROBE_FAILED',
  PROVIDER_NOT_REGISTERED: 'PROVIDER_NOT_REGISTERED',
  IS_DEFAULT: 'IS_DEFAULT',
  LAST_ENABLED: 'LAST_ENABLED',
  IN_USE: 'IN_USE',
  RESIDENCY_DENIED: 'RESIDENCY_DENIED',
  IS_LOCAL: 'IS_LOCAL',
};

class GdKmsProviderError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'GdKmsProviderError';
    this.code = code;
    this.detail = detail || null;
  }
}

function nowSqlite() {
  return new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
}

function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

// Provider modules self-register at require time. Loading them here means a
// lookup works before any wrap has run. Idempotent.
function ensureProvidersLoaded() {
  const mods = [
    './gd-key-wrapping-providers/gd-tier1',
    './gd-key-wrapping-providers/aws-kms',
    './gd-key-wrapping-providers/azure-keyvault',
    './gd-key-wrapping-providers/gcp-kms',
    './gd-key-wrapping-providers/hashicorp-vault',
  ];
  for (const m of mods) {
    try { require(m); } catch (_e) { /* a provider whose SDK is absent stays unregistered */ }
  }
}

function validateName(name) {
  if (typeof name !== 'string' || name === '') {
    throw new GdKmsProviderError(CODES.INVALID_INPUT, 'name required');
  }
  if (name.length > NAME_MAX_LENGTH) {
    throw new GdKmsProviderError(CODES.INVALID_INPUT,
      'name must be at most ' + NAME_MAX_LENGTH + ' characters');
  }
  if (!NAME_PATTERN.test(name)) {
    throw new GdKmsProviderError(CODES.INVALID_INPUT,
      'name must be lower-case alphanumeric with internal hyphens');
  }
  return name;
}

function getProviderImpl(providerType) {
  ensureProvidersLoaded();
  const impl = base.getProvider(providerType);
  if (!impl) {
    throw new GdKmsProviderError(CODES.PROVIDER_NOT_REGISTERED,
      "provider type '" + providerType + "' is not registered on this server");
  }
  return impl;
}

// ── credentials ─────────────────────────────────────────────────────────────
// Sealed under the GD Tier-1 KEK through the domain-aware chokepoint. The column
// is registered in gd-tier1-columns.js, which is GENERATED from the schema --
// sealTier1 throws on an unregistered column rather than silently storing
// plaintext.
function encryptCredentials(credentials) {
  if (credentials === null || credentials === undefined) return null;
  if (typeof credentials === 'object' && Object.keys(credentials).length === 0) return null;
  return sealTier1('gd_kms_providers.credentials_encrypted', credentials);
}

function decryptCredentials(stored) {
  if (stored === null || stored === undefined) return null;
  return openTier1('gd_kms_providers.credentials_encrypted', stored);
}

// A read NEVER returns a secret. Not redacted, not partially masked: absent.
// A field that is present-but-masked invites a UI to round-trip it back on save,
// which is how a masked value becomes the stored value.
function publicView(row) {
  if (!row) return null;
  let config = {};
  try { config = JSON.parse(row.config); } catch (_e) { config = {}; }
  return {
    id: row.id,
    name: row.name,
    provider_type: row.provider_type,
    config: config,
    has_credentials: row.credentials_encrypted !== null && row.credentials_encrypted !== undefined,
    enabled: row.enabled === 1,
    retired: row.retired === 1,
    is_default: row.is_default === 1,
    residency: {
      country: row.residency_country || null,
      provider_domicile: row.residency_provider_domicile || null,
      verdict: row.residency_verdict || null,
    },
    last_probe_at: row.last_probe_at || null,
    last_probe_status: row.last_probe_status || null,
    last_probe_error: row.last_probe_error || null,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function listProviders(db, opts) {
  const o = opts || {};
  let sql = 'SELECT * FROM gd_kms_providers';
  const where = [];
  if (o.enabledOnly) where.push('enabled = 1');
  if (!o.includeRetired) where.push('retired = 0');
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY is_default DESC, name ASC';
  return db.prepare(sql).all().map(publicView);
}

function getProviderById(db, id) {
  return publicView(db.prepare('SELECT * FROM gd_kms_providers WHERE id = ?').get(id));
}

function getProviderByName(db, name) {
  return publicView(db.prepare('SELECT * FROM gd_kms_providers WHERE name = ?').get(name));
}

function getDefault(db) {
  const row = db.prepare(
    'SELECT * FROM gd_kms_providers WHERE is_default = 1 AND enabled = 1 AND retired = 0',
  ).get();
  return publicView(row);
}

// ── the in-use check ────────────────────────────────────────────────────────
/**
 * How many backups depend on this provider to unwrap their data key?
 *
 * NULL wrap_provider_id is not a dependency: those rows are either gd-tier1
 * (whose key is the local KEK, with no registry row) or pre-B6g backups, which
 * could only have been gd-tier1 because that was the sole supported scheme.
 */
function backupsUsing(db, id) {
  const row = db.prepare('SELECT count(*) AS c FROM backups WHERE wrap_provider_id = ?').get(id);
  return row ? row.c : 0;
}

// ── residency ───────────────────────────────────────────────────────────────
/**
 * Evaluate key custody and refuse a blocked arrangement.
 *
 * Returns the verdict so the caller can record it on the row. Throws only when
 * the verdict blocks: a `warn`-mode violation is recorded and surfaced, not
 * refused, because that is what warn mode means.
 */
function requirePermittedCustody(db, providerType, config, declaredCountry) {
  const verdict = keyCustody.evaluateKeyCustody(db, providerType, config, declaredCountry);
  if (!verdict.permitted) {
    throw new GdKmsProviderError(CODES.RESIDENCY_DENIED, verdict.reason, {
      action: verdict.action,
      destinationJurisdiction: verdict.destinationJurisdiction,
      providerDomicile: verdict.providerDomicile,
      permittedRegions: verdict.permittedRegions,
    });
  }
  return verdict;
}

// ── create ──────────────────────────────────────────────────────────────────
async function createProvider(db, args, ctx) {
  if (!args || typeof args !== 'object') {
    throw new GdKmsProviderError(CODES.INVALID_INPUT, 'args required');
  }
  if (!ctx || typeof ctx.user_id !== 'string') {
    throw new GdKmsProviderError(CODES.INVALID_INPUT, 'ctx.user_id required');
  }

  const name = validateName(args.name);
  const providerType = args.provider_type;
  const impl = getProviderImpl(providerType);
  const config = args.config && typeof args.config === 'object' ? args.config : {};
  const credentials = args.credentials === undefined ? null : args.credentials;

  if (db.prepare('SELECT id FROM gd_kms_providers WHERE name = ?').get(name)) {
    throw new GdKmsProviderError(CODES.NAME_CONFLICT, "a provider named '" + name + "' already exists");
  }

  const cfgCheck = impl.validateConfig(config);
  if (cfgCheck && cfgCheck.ok === false) {
    throw new GdKmsProviderError(CODES.PROVIDER_VALIDATION_FAILED, cfgCheck.error, { field: cfgCheck.field });
  }
  const credCheck = impl.validateCredentials(credentials);
  if (credCheck && credCheck.ok === false) {
    throw new GdKmsProviderError(CODES.PROVIDER_VALIDATION_FAILED, credCheck.error);
  }

  // Residency BEFORE the row is written. Storing a provider and then refusing to
  // use it would leave an operator with a configured provider that silently
  // never wraps anything.
  const verdict = requirePermittedCustody(db, providerType, config, args.residency_country);

  const id = generateId();
  db.prepare(
    'INSERT INTO gd_kms_providers '
    + '(id, name, provider_type, config, credentials_encrypted, enabled, retired, is_default, '
    + ' residency_country, residency_provider_domicile, residency_verdict, created_at, updated_at) '
    + 'VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?)',
  ).run(
    id, name, providerType, JSON.stringify(config), encryptCredentials(credentials),
    args.enabled === false ? 0 : 1,
    verdict.destinationJurisdiction, verdict.providerDomicile, verdict.action,
    nowSqlite(), nowSqlite(),
  );
  return { provider: getProviderById(db, id), residency: verdict };
}

// ── update ──────────────────────────────────────────────────────────────────
async function updateProvider(db, id, args, ctx) {
  if (!ctx || typeof ctx.user_id !== 'string') {
    throw new GdKmsProviderError(CODES.INVALID_INPUT, 'ctx.user_id required');
  }
  const existing = db.prepare('SELECT * FROM gd_kms_providers WHERE id = ?').get(id);
  if (!existing) {
    throw new GdKmsProviderError(CODES.PROVIDER_NOT_FOUND, 'provider ' + id + ' not found');
  }

  // The provider TYPE is immutable. Changing it would leave the row's recorded
  // residency, its credentials and its config describing a different service
  // than the one named -- and every manifest that recorded this provider would
  // now point at a row that means something else. Create a new provider and
  // retire this one.
  if (args.provider_type !== undefined && args.provider_type !== existing.provider_type) {
    throw new GdKmsProviderError(CODES.INVALID_INPUT,
      'provider_type is immutable: create a new provider and retire this one. '
      + 'Changing it in place would leave manifests that recorded this provider pointing at '
      + 'a row describing a different service.');
  }

  const impl = getProviderImpl(existing.provider_type);
  const config = args.config && typeof args.config === 'object'
    ? args.config
    : JSON.parse(existing.config);

  const cfgCheck = impl.validateConfig(config);
  if (cfgCheck && cfgCheck.ok === false) {
    throw new GdKmsProviderError(CODES.PROVIDER_VALIDATION_FAILED, cfgCheck.error, { field: cfgCheck.field });
  }

  const verdict = requirePermittedCustody(
    db, existing.provider_type, config,
    args.residency_country !== undefined ? args.residency_country : existing.residency_country,
  );

  const sets = ['config = ?', 'residency_country = ?', 'residency_provider_domicile = ?',
    'residency_verdict = ?', 'updated_at = ?'];
  const vals = [JSON.stringify(config), verdict.destinationJurisdiction,
    verdict.providerDomicile, verdict.action, nowSqlite()];

  if (args.credentials !== undefined) {
    const credCheck = impl.validateCredentials(args.credentials);
    if (credCheck && credCheck.ok === false) {
      throw new GdKmsProviderError(CODES.PROVIDER_VALIDATION_FAILED, credCheck.error);
    }
    sets.push('credentials_encrypted = ?');
    vals.push(encryptCredentials(args.credentials));
  }
  if (args.name !== undefined) {
    const nm = validateName(args.name);
    const clash = db.prepare('SELECT id FROM gd_kms_providers WHERE name = ? AND id != ?').get(nm, id);
    if (clash) throw new GdKmsProviderError(CODES.NAME_CONFLICT, "a provider named '" + nm + "' already exists");
    sets.push('name = ?'); vals.push(nm);
  }

  vals.push(id);
  db.prepare('UPDATE gd_kms_providers SET ' + sets.join(', ') + ' WHERE id = ?').run(...vals);
  return { provider: getProviderById(db, id), residency: verdict };
}

// ── enable / disable / retire ───────────────────────────────────────────────
function guardAgainstLastEnabled(db, idAboutToBeDisabled) {
  const row = db.prepare(
    'SELECT count(*) AS c FROM gd_kms_providers WHERE enabled = 1 AND retired = 0 AND id != ?',
  ).get(idAboutToBeDisabled);
  if (!row || row.c === 0) {
    throw new GdKmsProviderError(CODES.LAST_ENABLED,
      'cannot disable the last enabled provider: the GD would have no way to wrap a backup key. '
      + 'Enable another provider first.');
  }
}

function setEnabled(db, id, enabled) {
  const existing = db.prepare('SELECT * FROM gd_kms_providers WHERE id = ?').get(id);
  if (!existing) throw new GdKmsProviderError(CODES.PROVIDER_NOT_FOUND, 'provider ' + id + ' not found');
  if (!enabled) guardAgainstLastEnabled(db, id);
  db.prepare('UPDATE gd_kms_providers SET enabled = ?, updated_at = ? WHERE id = ?')
    .run(enabled ? 1 : 0, nowSqlite(), id);
  return getProviderById(db, id);
}

/**
 * Retire a provider: stop using it for new backups, keep the row so existing
 * manifests can still restore.
 *
 * This is the supported exit for a provider that backups depend on, and the
 * reason deletion can be refused without stranding the operator.
 */
function retireProvider(db, id) {
  const existing = db.prepare('SELECT * FROM gd_kms_providers WHERE id = ?').get(id);
  if (!existing) throw new GdKmsProviderError(CODES.PROVIDER_NOT_FOUND, 'provider ' + id + ' not found');
  if (existing.is_default === 1) {
    throw new GdKmsProviderError(CODES.IS_DEFAULT,
      'cannot retire the default provider; set a different default first');
  }
  if (existing.enabled === 1) guardAgainstLastEnabled(db, id);
  db.prepare('UPDATE gd_kms_providers SET retired = 1, enabled = 0, updated_at = ? WHERE id = ?')
    .run(nowSqlite(), id);
  return getProviderById(db, id);
}

function setDefault(db, id) {
  const existing = db.prepare('SELECT * FROM gd_kms_providers WHERE id = ?').get(id);
  if (!existing) throw new GdKmsProviderError(CODES.PROVIDER_NOT_FOUND, 'provider ' + id + ' not found');
  if (existing.enabled !== 1) {
    throw new GdKmsProviderError(CODES.PROVIDER_DISABLED, 'cannot make a disabled provider the default');
  }
  if (existing.retired === 1) {
    throw new GdKmsProviderError(CODES.INVALID_INPUT, 'cannot make a retired provider the default');
  }
  const tx = db.transaction(() => {
    db.prepare('UPDATE gd_kms_providers SET is_default = 0 WHERE is_default = 1').run();
    db.prepare('UPDATE gd_kms_providers SET is_default = 1, updated_at = ? WHERE id = ?')
      .run(nowSqlite(), id);
  });
  tx();
  return getProviderById(db, id);
}

// ── delete ──────────────────────────────────────────────────────────────────
/**
 * Delete a provider.
 *
 * REFUSED while any backup depends on it. Checked here so the operator gets a
 * message naming the count and the remedy; enforced by the database because a
 * message is not a control -- backups.wrap_provider_id REFERENCES
 * gd_kms_providers(id) ON DELETE RESTRICT, and B6g enabled foreign keys.
 */
function deleteProvider(db, id) {
  const existing = db.prepare('SELECT * FROM gd_kms_providers WHERE id = ?').get(id);
  if (!existing) throw new GdKmsProviderError(CODES.PROVIDER_NOT_FOUND, 'provider ' + id + ' not found');
  if (existing.is_default === 1) {
    throw new GdKmsProviderError(CODES.IS_DEFAULT,
      'cannot delete the default provider; set a different default first');
  }

  const inUse = backupsUsing(db, id);
  if (inUse > 0) {
    throw new GdKmsProviderError(CODES.IN_USE,
      inUse + ' backup(s) were wrapped with this provider and need it to restore. '
      + 'Retire it instead: retiring stops new backups using it and keeps the row '
      + 'so those archives can still be opened.', { backups: inUse });
  }
  if (existing.enabled === 1) guardAgainstLastEnabled(db, id);

  db.prepare('DELETE FROM gd_kms_providers WHERE id = ?').run(id);
  return { deleted: true, id: id };
}

// ── probe ───────────────────────────────────────────────────────────────────
async function probeProvider(db, id, opts) {
  const existing = db.prepare('SELECT * FROM gd_kms_providers WHERE id = ?').get(id);
  if (!existing) throw new GdKmsProviderError(CODES.PROVIDER_NOT_FOUND, 'provider ' + id + ' not found');
  const impl = getProviderImpl(existing.provider_type);
  let config = {};
  try { config = JSON.parse(existing.config); } catch (_e) { config = {}; }

  let status = 'ok';
  let error = null;
  try {
    const r = await impl.probe(config, decryptCredentials(existing.credentials_encrypted), opts || {});
    if (r && r.ok === false) { status = 'failed'; error = r.error || 'probe reported failure'; }
  } catch (e) {
    status = 'failed';
    error = e && e.message ? e.message : String(e);
  }
  db.prepare('UPDATE gd_kms_providers SET last_probe_at = ?, last_probe_status = ?, '
    + 'last_probe_error = ?, updated_at = ? WHERE id = ?')
    .run(nowSqlite(), status, error, nowSqlite(), id);
  return { status: status, error: error };
}

module.exports = {
  CODES,
  GdKmsProviderError,
  LOCAL_PROVIDER_TYPE,
  ensureProvidersLoaded,
  encryptCredentials,
  decryptCredentials,
  publicView,
  listProviders,
  getProviderById,
  getProviderByName,
  getDefault,
  backupsUsing,
  createProvider,
  updateProvider,
  setEnabled,
  retireProvider,
  setDefault,
  deleteProvider,
  probeProvider,
};

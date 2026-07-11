// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Storage Destinations CRUD Service
//
// Manages rows in storage_destinations -- the generalized destination
// registry (backups were its first consumer, but it holds the routing
// target for every artifact type Storage Routing routes: backups, audit-log
// archives, forensic exports, snapshots, and CEF-stream archives). Validates
// against the loaded adapter registry, encrypts credentials at rest under
// Tier-1 AES-GCM, exposes public (no-credentials) and internal
// (with-credentials) retrieval paths.
//
// PUBLIC API
//
//   createDestination(db, input)
//     Validates input via the destination's adapter, encrypts
//     credentials, INSERTs the row. Returns the created row's
//     public view.
//
//   updateDestination(db, id, input)
//     Same validation. Re-encrypts credentials if input includes a
//     credentials field; preserves existing credentials_encrypted
//     if input omits credentials. Updates updated_at.
//
//   listDestinations(db, options)
//     Returns array of public views (no credentials, ever). Each
//     row includes aggregate push stats (total, succeeded, failed,
//     queued) for the admin UI.
//
//   getDestinationById(db, id)
//     Public view of a single destination. Returns null if missing.
//
//   getDestinationWithCredentials(db, id)
//     INTERNAL USE ONLY. Returns the destination row with
//     credentials decrypted. Called by the push orchestrator. Never
//     returned by routes; the routes always use getDestinationById
//     or listDestinations.
//
//   listEnabledDestinations(db)
//     Convenience: getDestinationWithCredentials for every row
//     where enabled = 1. The push orchestrator calls this after
//     a backup creation to enumerate push targets.
//
//   probeDestination(db, id)
//     On-demand probe of a destination. Decrypts credentials
//     just-in-time, calls adapter.probe, returns the probe result.
//     Does not modify the destination row.
//
//   deleteDestination(db, id)
//     ON DELETE RESTRICT in schema means this fails if push
//     records reference the destination. Operators should disable
//     (enabled=0) instead of delete to preserve audit continuity.
//     The function refuses to delete if any push records exist
//     (independent check before SQL); tries the DELETE; surfaces
//     SQL error if it fires.
//
// ADAPTER LOADING
//
// At module load, this service requires all five adapter files
// (destination-adapter-local, -sftp, -s3, -gcs, -azure-blob). Each
// adapter self-registers via base.registerAdapter on require, so
// after this module is loaded the registry is fully populated. The
// push orchestrator's module load also triggers the same chain. The
// cloud adapters load their provider SDK lazily (only when a push or
// probe runs), so requiring them here costs nothing at boot.
//
// The cloud adapters (s3, gcs, azure-blob) were built and tested in
// R3d-4 but were gated off behind ADAPTERS_LANDING_IN_R3D4; B5q
// activates them (the HSM/KMS credential-at-rest dependency they
// waited on now exists), so all five adapters are live.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const base = require('./destination-adapter-base');

// Force adapter self-registration. Each adapter file calls
// base.registerAdapter at end of module.
require('./destination-adapter-local');
require('./destination-adapter-sftp');
require('./destination-adapter-s3');
require('./destination-adapter-gcs');
require('./destination-adapter-azure-blob');

const { sealTier1, openTier1 } = require('./tier1-seal');
const deploymentMode = require('./deployment-mode');
const dataResidency = require('./data-residency');

// ── Helpers ──────────────────────────────────────────────────────────────

function generateId() {
  return crypto.randomUUID();
}

/**
 * Validate input shape for create/update. Returns:
 *   { ok: true, normalized: {...} } with normalized values
 *   { ok: false, error, field? }
 */
function validateInput(input, { isUpdate = false } = {}) {
  if (!input || typeof input !== 'object') {
    return { ok: false, error: 'input must be an object' };
  }

  // name
  if (!isUpdate || input.name !== undefined) {
    const r = base.requireString(input, 'name', { maxLength: 100, pattern: /^[A-Za-z0-9 ._-]+$/ });
    if (!r.ok) return r;
  }

  // adapter (immutable on update)
  if (!isUpdate) {
    const r = base.requireString(input, 'adapter');
    if (!r.ok) return r;
    if (!base.VALID_ADAPTER_NAMES.includes(input.adapter)) {
      return { ok: false, error: `adapter must be one of: ${base.VALID_ADAPTER_NAMES.join(', ')}`, field: 'adapter' };
    }
  }

  // The adapter implementation (loaded via registry)
  let adapter = null;
  if (!isUpdate) {
    adapter = base.getAdapter(input.adapter);
    if (!adapter) {
      return { ok: false, error: `adapter '${input.adapter}' not loaded; service may have started before adapter modules registered`, field: 'adapter' };
    }
  }

  // config (always required on create; only validated on update if present)
  if (!isUpdate || input.config !== undefined) {
    if (!input.config || typeof input.config !== 'object') {
      return { ok: false, error: 'config must be an object', field: 'config' };
    }
  }

  // credentials (required by adapter contract; varies)
  // On update, omitted credentials means "keep existing". On create, must
  // be present (even if empty object for local adapter).
  if (!isUpdate && input.credentials === undefined) {
    return { ok: false, error: 'credentials required (use null or {} if adapter does not need credentials)', field: 'credentials' };
  }

  // immutability_mode
  if (!isUpdate || input.immutability_mode !== undefined) {
    if (!base.VALID_IMMUTABILITY_MODES.includes(input.immutability_mode)) {
      return {
        ok: false,
        error: `immutability_mode must be one of: ${base.VALID_IMMUTABILITY_MODES.join(', ')}`,
        field: 'immutability_mode',
      };
    }
  }

  // enabled (optional, default 1; coerced to 0/1)
  let enabled = 1;
  if (input.enabled !== undefined) {
    if (input.enabled === true || input.enabled === 1) enabled = 1;
    else if (input.enabled === false || input.enabled === 0) enabled = 0;
    else return { ok: false, error: 'enabled must be boolean or 0/1', field: 'enabled' };
  }

  // retention_days (optional, NULL = use global)
  let retentionDays = null;
  if (input.retention_days !== undefined && input.retention_days !== null) {
    if (!Number.isInteger(input.retention_days) || input.retention_days < 1 || input.retention_days > 36500) {
      return { ok: false, error: 'retention_days must be integer in [1, 36500] or null', field: 'retention_days' };
    }
    retentionDays = input.retention_days;
  }

  return {
    ok: true,
    normalized: {
      name: input.name,
      adapter: input.adapter,           // undefined on update
      config: input.config,             // undefined on partial update
      credentials: input.credentials,   // undefined on partial update
      immutability_mode: input.immutability_mode,
      enabled,
      retention_days: retentionDays,
      adapterImpl: adapter,             // null on update; resolved below
    },
  };
}

/**
 * Run adapter-specific validation against the loaded adapter
 * implementation. Validates immutability_mode is in the adapter's
 * supportedImmutabilityModes; calls adapter.validateConfig and
 * adapter.validateCredentials.
 */
function validateAgainstAdapter(adapter, config, credentials, immutabilityMode) {
  // immutability_mode must be supported by the adapter
  if (!adapter.supportedImmutabilityModes.includes(immutabilityMode)) {
    return {
      ok: false,
      error: `adapter '${adapter.name}' does not support immutability_mode '${immutabilityMode}' (supported: ${adapter.supportedImmutabilityModes.join(', ')})`,
      field: 'immutability_mode',
    };
  }
  // adapter-specific config validation
  if (config !== undefined) {
    const c = adapter.validateConfig(config);
    if (!c.ok) return c;
  }
  // adapter-specific credentials validation
  if (credentials !== undefined) {
    const c = adapter.validateCredentials(credentials);
    if (!c.ok) return c;
  }
  return { ok: true };
}

/**
 * Encrypt a credentials object for storage. Returns null when the
 * adapter doesn't use credentials (null/undefined/empty input).
 *
 * Uses the same on-disk format as integration-manager.js: the AES-GCM
 * Buffer (iv + tag + ciphertext) is base64-encoded for storage in
 * the TEXT column. decryptCredentials is the symmetric inverse.
 */
function encryptCredentials(credentials) {
  if (credentials === null || credentials === undefined) return null;
  if (typeof credentials === 'object' && Object.keys(credentials).length === 0) return null;
  return sealTier1('storage_destinations.credentials_encrypted', credentials);
}

/**
 * Decrypt credentials_encrypted; returns null if column was NULL.
 * Reverses the base64 round-trip from encryptCredentials.
 */
function decryptCredentials(stored) {
  if (stored === null || stored === undefined) return null;
  return openTier1('storage_destinations.credentials_encrypted', stored);
}

// ── DB helpers ───────────────────────────────────────────────────────────

function rowToPublicView(row) {
  if (!row) return null;
  let configObj;
  try { configObj = JSON.parse(row.config); } catch { configObj = null; }
  return {
    id: row.id,
    name: row.name,
    adapter: row.adapter,
    config: configObj,
    enabled: row.enabled === 1,
    immutability_mode: row.immutability_mode,
    retention_days: row.retention_days,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function rowToInternalView(row) {
  if (!row) return null;
  let configObj;
  try { configObj = JSON.parse(row.config); } catch { configObj = null; }
  return {
    ...rowToPublicView(row),
    credentials: decryptCredentials(row.credentials_encrypted),
  };
}

function attachPushStats(db, publicView) {
  const stats = db.prepare(`
    SELECT
      COUNT(*) AS total,
      COUNT(CASE WHEN status = 'succeeded' THEN 1 END) AS succeeded,
      COUNT(CASE WHEN status = 'failed'    THEN 1 END) AS failed,
      COUNT(CASE WHEN status = 'queued'    THEN 1 END) AS queued,
      COUNT(CASE WHEN status = 'running'   THEN 1 END) AS running,
      MAX(pushed_at) AS last_pushed_at
    FROM backup_pushes
    WHERE destination_id = ?
  `).get(publicView.id);
  publicView.push_stats = {
    total: stats.total || 0,
    succeeded: stats.succeeded || 0,
    failed: stats.failed || 0,
    queued: stats.queued || 0,
    running: stats.running || 0,
    last_pushed_at: stats.last_pushed_at || null,
  };
  return publicView;
}

// ── Public API ───────────────────────────────────────────────────────────

// Config-time data-residency helpers. A blocked verdict (enforce mode +
// violation/undeclared) becomes a validation error the route surfaces as a 400;
// a warn verdict is attached to the returned view as residencyWarning so the
// route can audit it and the console can display it.
function residencyBlockError(ev) {
  const regionList = (ev.permittedRegions && ev.permittedRegions.length)
    ? ev.permittedRegions.join(', ') : 'none';
  const err = new Error('data residency: ' + ev.reason
    + ' (backup category is in enforce mode; permitted regions: ' + regionList + ')');
  err.field = 'config';
  err.validation = true;
  err.residencyBlocked = true;
  return err;
}

function residencyWarningText(ev) {
  if (ev && (ev.action === 'violation-region' || ev.action === 'undeclared')) {
    return 'data residency: ' + ev.reason;
  }
  return null;
}

function withResidencyWarning(view, warning) {
  if (warning) view.residencyWarning = warning;
  return view;
}

function createDestination(db, input) {
  const v = validateInput(input, { isUpdate: false });
  if (!v.ok) {
    const err = new Error(v.error);
    err.field = v.field;
    err.validation = true;
    throw err;
  }
  // Virtualized substrate: a 'local' destination writes the backup into this
  // instance's own filesystem, which a VM snapshot or clone captures wholesale,
  // defeating backup independence and proliferating backup data with every
  // clone. On a virtualized substrate (virtualized mode or SDN+virtualized)
  // backups must target external storage, so reject the local adapter here. A
  // bare-metal substrate is unaffected, and KEK-sealing already applies in
  // every mode via backup-key-wrapping.
  if (v.normalized.adapter === 'local' && deploymentMode.summary(db).substrateVirtualized === true) {
    const err = new Error('local backup destinations are not allowed on a virtualized substrate; configure an external destination (sftp, s3, azure-blob, or gcs) so backups are not captured by VM snapshots or clones');
    err.field = 'adapter';
    err.validation = true;
    throw err;
  }

  const adapterImpl = v.normalized.adapterImpl;
  const adapterValidation = validateAgainstAdapter(
    adapterImpl,
    v.normalized.config,
    v.normalized.credentials,
    v.normalized.immutability_mode,
  );
  if (!adapterValidation.ok) {
    const err = new Error(adapterValidation.error);
    err.field = adapterValidation.field;
    err.validation = true;
    throw err;
  }

  // Config-time residency gate: evaluate the input config before persisting.
  const residencyEv = dataResidency.evaluateConfig(db, 'backup', v.normalized.adapter, v.normalized.config, null);
  if (residencyEv.blocked) {
    throw residencyBlockError(residencyEv);
  }
  const residencyWarning = residencyWarningText(residencyEv);

  const id = generateId();
  const credentialsEncrypted = encryptCredentials(v.normalized.credentials);
  const configJson = JSON.stringify(v.normalized.config);

  db.prepare(`
    INSERT INTO storage_destinations
      (id, name, adapter, config, credentials_encrypted, enabled,
       immutability_mode, retention_days)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, v.normalized.name, v.normalized.adapter, configJson,
    credentialsEncrypted, v.normalized.enabled,
    v.normalized.immutability_mode, v.normalized.retention_days,
  );

  const row = db.prepare('SELECT * FROM storage_destinations WHERE id = ?').get(id);
  return withResidencyWarning(attachPushStats(db, rowToPublicView(row)), residencyWarning);
}

function updateDestination(db, id, input) {
  if (typeof id !== 'string' || !id) {
    const err = new Error('id required'); err.validation = true; throw err;
  }
  const existing = db.prepare('SELECT * FROM storage_destinations WHERE id = ?').get(id);
  if (!existing) return null;

  const v = validateInput(input, { isUpdate: true });
  if (!v.ok) {
    const err = new Error(v.error); err.field = v.field; err.validation = true; throw err;
  }

  const adapterImpl = base.getAdapter(existing.adapter);
  if (!adapterImpl) {
    const err = new Error(`adapter '${existing.adapter}' not loaded; cannot update destination`);
    err.field = 'adapter'; err.validation = true; throw err;
  }

  // Adapter-level validation against either the new or existing values.
  // For partial updates that don't touch a field, we re-validate using
  // the existing stored value to maintain consistency.
  const effectiveConfig = input.config !== undefined ? input.config : JSON.parse(existing.config);
  const effectiveCredentials = input.credentials !== undefined ? input.credentials : decryptCredentials(existing.credentials_encrypted);
  const effectiveImmutability = input.immutability_mode !== undefined ? input.immutability_mode : existing.immutability_mode;
  const adapterValidation = validateAgainstAdapter(
    adapterImpl, effectiveConfig, effectiveCredentials, effectiveImmutability,
  );
  if (!adapterValidation.ok) {
    const err = new Error(adapterValidation.error);
    err.field = adapterValidation.field; err.validation = true; throw err;
  }

  // Config-time residency gate on the effective config. Block a config change
  // or an enable that would violate the policy under enforce; a rename/disable
  // of an already-non-compliant destination is allowed (remediation), with the
  // write-time push gate as the backstop.
  const residencyEv = dataResidency.evaluateConfig(db, 'backup', existing.adapter, effectiveConfig, id);
  const enabling = input.enabled !== undefined && v.normalized.enabled === true;
  if (residencyEv.blocked && (input.config !== undefined || enabling)) {
    throw residencyBlockError(residencyEv);
  }
  const residencyWarning = residencyWarningText(residencyEv);

  // Build SET clause incrementally based on which fields changed
  const sets = [];
  const args = [];
  if (input.name !== undefined) { sets.push('name = ?'); args.push(v.normalized.name); }
  if (input.config !== undefined) { sets.push('config = ?'); args.push(JSON.stringify(input.config)); }
  if (input.credentials !== undefined) {
    sets.push('credentials_encrypted = ?');
    args.push(encryptCredentials(input.credentials));
  }
  if (input.enabled !== undefined) { sets.push('enabled = ?'); args.push(v.normalized.enabled); }
  if (input.immutability_mode !== undefined) {
    sets.push('immutability_mode = ?'); args.push(v.normalized.immutability_mode);
  }
  if (input.retention_days !== undefined) {
    sets.push('retention_days = ?'); args.push(v.normalized.retention_days);
  }
  if (sets.length === 0) {
    // Nothing to update; return current state
    return withResidencyWarning(attachPushStats(db, rowToPublicView(existing)), residencyWarning);
  }
  sets.push("updated_at = datetime('now')");
  args.push(id);

  db.prepare(`UPDATE storage_destinations SET ${sets.join(', ')} WHERE id = ?`).run(...args);

  const row = db.prepare('SELECT * FROM storage_destinations WHERE id = ?').get(id);
  return withResidencyWarning(attachPushStats(db, rowToPublicView(row)), residencyWarning);
}

function listDestinations(db, options = {}) {
  const where = [];
  const args = [];
  if (options.enabledOnly) where.push('enabled = 1');
  if (options.adapter) { where.push('adapter = ?'); args.push(options.adapter); }
  const sql = `
    SELECT * FROM storage_destinations
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY created_at DESC
  `;
  const rows = db.prepare(sql).all(...args);
  return rows.map(r => attachPushStats(db, rowToPublicView(r)));
}

function getDestinationById(db, id) {
  if (typeof id !== 'string' || !id) return null;
  const row = db.prepare('SELECT * FROM storage_destinations WHERE id = ?').get(id);
  if (!row) return null;
  return attachPushStats(db, rowToPublicView(row));
}

function getDestinationWithCredentials(db, id) {
  if (typeof id !== 'string' || !id) return null;
  const row = db.prepare('SELECT * FROM storage_destinations WHERE id = ?').get(id);
  if (!row) return null;
  return rowToInternalView(row);
}

function listEnabledDestinations(db) {
  const rows = db.prepare('SELECT * FROM storage_destinations WHERE enabled = 1 ORDER BY created_at ASC').all();
  return rows.map(rowToInternalView);
}

async function probeDestination(db, id) {
  const dest = getDestinationWithCredentials(db, id);
  if (!dest) return { ok: false, error: 'destination not found' };
  const adapter = base.getAdapter(dest.adapter);
  if (!adapter) return { ok: false, error: `adapter '${dest.adapter}' not loaded` };
  try {
    return await adapter.probe(dest.config, dest.credentials);
  } catch (err) {
    return { ok: false, error: err.message, detail: { thrown: true } };
  }
}

function deleteDestination(db, id) {
  if (typeof id !== 'string' || !id) {
    const err = new Error('id required'); err.validation = true; throw err;
  }
  const existing = db.prepare('SELECT id FROM storage_destinations WHERE id = ?').get(id);
  if (!existing) return { deleted: false, reason: 'not_found' };

  // Pre-check: count push records (the FK is ON DELETE RESTRICT
  // so the SQL will fire too, but pre-check gives better error
  // messaging for the operator).
  const pushCount = db.prepare('SELECT COUNT(*) AS c FROM backup_pushes WHERE destination_id = ?').get(id).c;
  if (pushCount > 0) {
    return {
      deleted: false,
      reason: 'has_push_history',
      detail: `destination has ${pushCount} push record(s); disable (enabled=0) instead of delete to preserve audit continuity`,
    };
  }

  try {
    db.prepare('DELETE FROM storage_destinations WHERE id = ?').run(id);
    return { deleted: true };
  } catch (err) {
    // FK ON DELETE RESTRICT (defense-in-depth, should not fire after the pre-check)
    return { deleted: false, reason: 'fk_constraint', detail: err.message };
  }
}

module.exports = {
  // public API
  createDestination,
  updateDestination,
  listDestinations,
  getDestinationById,
  getDestinationWithCredentials,
  listEnabledDestinations,
  probeDestination,
  deleteDestination,

  // exposed for tests
  encryptCredentials,
  decryptCredentials,
  validateInput,
  validateAgainstAdapter,
};

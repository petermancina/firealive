// =============================================================================
// FIREALIVE GD -- Storage Destinations CRUD Service
//
// Manages rows in storage_destinations -- the Global Dashboard's generalized
// destination registry. It holds the routing target for every artifact type
// GD Storage Routing routes: full-suite backups, snapshots, audit-log
// archives, forensic exports, and CEF-stream archives. Validates against the
// loaded adapter registry, encrypts credentials at rest under the GD Tier-1
// KEK (gd-encryption AES-256-GCM), and exposes public (no-credentials) and
// internal (with-credentials) retrieval paths.
//
// This is the GD trust realm's own registry: credentials are wrapped with the
// GD KEK and the destinations receive the GD's own artifacts. It is never a
// write-path into the Regional Server's destinations.
//
// PUBLIC API
//
//   createDestination(db, input)
//     Validates input via the destination's adapter, encrypts credentials,
//     INSERTs the row. Returns the created row's public view.
//
//   updateDestination(db, id, input)
//     Same validation. Re-encrypts credentials if input includes a
//     credentials field; preserves existing credentials_encrypted if input
//     omits credentials. Updates updated_at.
//
//   listDestinations(db, options)
//     Returns array of public views (no credentials, ever). Each row includes
//     aggregate push stats (total, succeeded, failed, queued) across all
//     artifact push tables for the admin UI.
//
//   getDestinationById(db, id)
//     Public view of a single destination. Returns null if missing.
//
//   getDestinationWithCredentials(db, id)
//     INTERNAL USE ONLY. Returns the destination row with credentials
//     decrypted. Called by the push orchestrator. Never returned by routes.
//
//   listEnabledDestinations(db)
//     Convenience: getDestinationWithCredentials for every row where
//     enabled = 1.
//
//   probeDestination(db, id)
//     On-demand probe of a destination. Decrypts credentials just-in-time,
//     calls adapter.probe (passing the destination's immutability_mode so an
//     object-lock destination is verified fail-closed against the target
//     bucket), returns the probe result. Does not modify the destination row.
//
//   deleteDestination(db, id)
//     ON DELETE RESTRICT in schema means this fails if any push record (backup,
//     archive-segment, or forensic-export) references the destination.
//     Operators should disable (enabled=0) instead of delete to preserve audit
//     continuity. The function refuses to delete if any push records exist
//     (independent check before SQL); tries the DELETE; surfaces SQL error if
//     it fires.
//
// ADAPTER LOADING
//
// At module load, this service requires all five GD adapter files
// (gd-destination-adapter-local, -sftp, -s3, -gcs, -azure-blob). Each adapter
// self-registers via base.registerAdapter on require, so after this module is
// loaded the registry is fully populated. The push orchestrator's module load
// also triggers the same chain. The cloud adapters load their provider SDK
// lazily (only when a push or probe runs), so requiring them here costs
// nothing at boot.
// =============================================================================

const crypto = require('crypto');
const base = require('./gd-destination-adapter-base');

// Force adapter self-registration. Each adapter file calls
// base.registerAdapter at end of module.
require('./gd-destination-adapter-local');
require('./gd-destination-adapter-sftp');
require('./gd-destination-adapter-s3');
require('./gd-destination-adapter-gcs');
require('./gd-destination-adapter-azure-blob');

const { sealTier1, openTier1 } = require('./gd-tier1-seal');
const dataResidency = require('./gd-data-residency');

// --- Helpers -----------------------------------------------------------------

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
 * Encrypt a credentials object for storage. Returns null when the adapter
 * doesn't use credentials (null/undefined/empty input). gd-encryption's
 * encryptConfig returns a self-describing JSON envelope string (v/iv/tag/
 * ciphertext), which is stored directly in the credentials_encrypted TEXT
 * column. decryptCredentials is the symmetric inverse.
 */
function encryptCredentials(credentials) {
  if (credentials === null || credentials === undefined) return null;
  if (typeof credentials === 'object' && Object.keys(credentials).length === 0) return null;
  return sealTier1('storage_destinations.credentials_encrypted', credentials);
}

/**
 * Decrypt credentials_encrypted; returns null if column was NULL. The stored
 * value is the gd-encryption envelope string produced by encryptCredentials.
 */
function decryptCredentials(stored) {
  if (stored === null || stored === undefined) return null;
  return openTier1('storage_destinations.credentials_encrypted', stored);
}

// --- DB helpers --------------------------------------------------------------

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

// Aggregate push counts for a destination across every artifact push table.
// The GD routes five artifact types, so a destination may receive backups,
// archive segments (audit-log / CEF), and forensic exports -- summing all
// three gives an accurate per-destination view (counting only backups would
// show zero for a segment- or export-only destination).
const PUSH_TABLES = ['backup_pushes', 'archive_segment_pushes', 'forensic_export_pushes'];

function attachPushStats(db, publicView) {
  const agg = { total: 0, succeeded: 0, failed: 0, queued: 0, running: 0, last_pushed_at: null };
  for (const table of PUSH_TABLES) {
    const s = db.prepare(`
      SELECT
        COUNT(*) AS total,
        COUNT(CASE WHEN status = 'succeeded' THEN 1 END) AS succeeded,
        COUNT(CASE WHEN status = 'failed'    THEN 1 END) AS failed,
        COUNT(CASE WHEN status = 'queued'    THEN 1 END) AS queued,
        COUNT(CASE WHEN status = 'running'   THEN 1 END) AS running,
        MAX(pushed_at) AS last_pushed_at
      FROM ${table}
      WHERE destination_id = ?
    `).get(publicView.id);
    agg.total += s.total || 0;
    agg.succeeded += s.succeeded || 0;
    agg.failed += s.failed || 0;
    agg.queued += s.queued || 0;
    agg.running += s.running || 0;
    if (s.last_pushed_at && (!agg.last_pushed_at || s.last_pushed_at > agg.last_pushed_at)) {
      agg.last_pushed_at = s.last_pushed_at;
    }
  }
  publicView.push_stats = agg;
  return publicView;
}

// Count push records referencing a destination across every artifact push
// table. Used by deleteDestination's pre-check (all three tables have an
// ON DELETE RESTRICT FK to storage_destinations).
function countPushRecords(db, id) {
  let total = 0;
  for (const table of PUSH_TABLES) {
    total += db.prepare(`SELECT COUNT(*) AS c FROM ${table} WHERE destination_id = ?`).get(id).c;
  }
  return total;
}

// --- Public API --------------------------------------------------------------

// Config-time data-residency helpers. A blocked verdict (enforce mode +
// violation/undeclared) becomes a validation error the route surfaces as a 400; a
// warn verdict is attached to the returned view as residencyWarning so the route can
// audit it and the console can display it. Destinations are gated against the
// 'backup' category as the representative baseline; per-category enforcement happens
// when a destination is routed (gd-storage-routing.writeRoute).
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
  if (residencyEv.blocked) throw residencyBlockError(residencyEv);
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

  // Config-time residency gate on the effective (post-update) config.
  const residencyEv = dataResidency.evaluateConfig(db, 'backup', existing.adapter, effectiveConfig, id);
  if (residencyEv.blocked) throw residencyBlockError(residencyEv);
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
    // Nothing to update; return current state (still surfacing any residency warning)
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
    // Pass immutability_mode so an object-lock destination is verified
    // fail-closed against the target bucket's Object Lock configuration.
    return await adapter.probe(dest.config, dest.credentials, { immutabilityMode: dest.immutability_mode });
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

  // Pre-check: count push records across all artifact push tables (the FKs
  // are ON DELETE RESTRICT so the SQL will fire too, but pre-check gives
  // better error messaging for the operator).
  const pushCount = countPushRecords(db, id);
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

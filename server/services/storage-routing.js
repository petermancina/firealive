// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Storage Routing Resolver (B5q)
//
// One resolver every artifact-writer calls to learn where a given data type
// should be written. Backs the storage_destination_routes table (one row per
// data type) and resolves each route to a concrete, enabled storage_destinations
// entry.
//
// Resolution:
//   getRouteForType(db, dataType) -> { destination, pathPrefix, options, ... }
//   - 'snapshot' inherits the 'backup' route when its own route has no usable
//     destination (the "Same as backups" behavior), with an elective override:
//     a snapshot route with its own enabled destination wins.
//   - an unconfigured / disabled route, or one whose destination is missing or
//     disabled, resolves to { destination: null } so the writer keeps its local
//     behavior (no push) rather than failing.
//
// Config-save gates (writeRoute), both fail-closed:
//   - HARD immutability gate: audit_log archives MUST route to an
//     immutability-capable destination (S3 Object Lock / Azure Immutable Blob /
//     GCS Retention Lock / local-or-sftp append-only -> immutability_mode
//     'object-lock' or 'append-only'). Any data type may additionally opt in via
//     options.immutability_required. Enabling a route that violates this is
//     refused.
//   - Residency gate: dataResidency.evaluateConfig(db, category, ...) is
//     consulted with the route's data type as the category; a blocked verdict
//     (enforce mode, out-of-region or undeclared) refuses the save. Mirrors the
//     backup-destination config-save gate.
//
// Schema: db/init.js -> storage_destination_routes. Destinations are read
// through services/storage-destinations.js (public view, no credentials).
// ═══════════════════════════════════════════════════════════════════════════════

const dataResidency = require('./data-residency');
const storageDestinations = require('./storage-destinations');

const VALID_DATA_TYPES = ['backup', 'audit_log', 'forensic_export', 'snapshot', 'cef_archive'];

// Immutability-capable at-rest modes. 'none' and 'unknown' do not qualify.
const IMMUTABILITY_CAPABLE_MODES = ['append-only', 'object-lock'];

function isImmutabilityCapable(mode) {
  return IMMUTABILITY_CAPABLE_MODES.includes(mode);
}

// audit_log is always immutability-required; any type can opt in via options.
function immutabilityRequired(dataType, options) {
  if (dataType === 'audit_log') return true;
  return !!(options && options.immutability_required === true);
}

function parseOptions(raw) {
  if (!raw) return {};
  try {
    const obj = JSON.parse(raw);
    return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : {};
  } catch (_err) {
    return {};
  }
}

function nowStamp() {
  return new Date().toISOString().replace('T', ' ').replace(/\..+$/, '');
}

// ── Route rows ─────────────────────────────────────────────────────────────

function rowToRoute(row) {
  if (!row) return null;
  return {
    dataType: row.data_type,
    destinationRef: row.destination_ref,
    pathPrefix: row.path_prefix,
    options: parseOptions(row.options),
    enabled: row.enabled === 1,
    updatedBy: row.updated_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function emptyRoute(dataType) {
  return {
    dataType,
    destinationRef: null,
    pathPrefix: null,
    options: {},
    enabled: false,
    updatedBy: null,
    createdAt: null,
    updatedAt: null,
  };
}

function readRouteRow(db, dataType) {
  return db
    .prepare(
      `SELECT data_type, destination_ref, path_prefix, options, enabled,
              updated_by, created_at, updated_at
       FROM storage_destination_routes WHERE data_type = ?`
    )
    .get(dataType);
}

/**
 * readRoute(db, dataType)
 *
 * Single route as a normalized object; an unconfigured type returns a default
 * empty route rather than null. Returns null only for an invalid data type.
 */
function readRoute(db, dataType) {
  if (!VALID_DATA_TYPES.includes(dataType)) return null;
  const row = readRouteRow(db, dataType);
  return row ? rowToRoute(row) : emptyRoute(dataType);
}

/**
 * readRoutes(db)
 *
 * All five routes (configured or default), in canonical data-type order. Used
 * by the routing config endpoint.
 */
function readRoutes(db) {
  const rows = db
    .prepare(
      `SELECT data_type, destination_ref, path_prefix, options, enabled,
              updated_by, created_at, updated_at
       FROM storage_destination_routes`
    )
    .all();
  const byType = {};
  for (const r of rows) byType[r.data_type] = rowToRoute(r);
  return VALID_DATA_TYPES.map((t) => byType[t] || emptyRoute(t));
}

// ── Resolution ─────────────────────────────────────────────────────────────

// Resolve a route to a usable destination (route enabled + ref set + the
// destination exists and is enabled); else null.
function resolveDestination(db, route) {
  if (!route || !route.enabled || !route.destinationRef) return null;
  const dest = storageDestinations.getDestinationById(db, route.destinationRef);
  if (!dest || !dest.enabled) return null;
  return dest;
}

/**
 * getRouteForType(db, dataType)
 *
 * The writer-facing resolver. Returns:
 *   {
 *     destination,    the resolved storage_destinations public view, or null
 *     pathPrefix,     the route's path prefix (may be null)
 *     options,        parsed per-type options object
 *     dataType,       the requested data type
 *     configured,     true when a usable destination resolved
 *     inheritedFrom,  'backup' when snapshot fell back to the backup route, else null
 *   }
 *
 * When destination is null the caller keeps its local behavior (no push).
 */
function getRouteForType(db, dataType) {
  if (!VALID_DATA_TYPES.includes(dataType)) {
    return { destination: null, pathPrefix: null, options: {}, dataType, configured: false, inheritedFrom: null };
  }

  const own = readRoute(db, dataType);
  let effective = own;
  let inheritedFrom = null;
  let dest = resolveDestination(db, own);

  // snapshot inherits the backup route when it has no usable destination of its own
  if (!dest && dataType === 'snapshot') {
    const backupRoute = readRoute(db, 'backup');
    const backupDest = resolveDestination(db, backupRoute);
    if (backupDest) {
      effective = backupRoute;
      dest = backupDest;
      inheritedFrom = 'backup';
    }
  }

  if (!dest) {
    return {
      destination: null,
      pathPrefix: own.pathPrefix,
      options: own.options,
      dataType,
      configured: false,
      inheritedFrom: null,
    };
  }

  return {
    destination: dest,
    pathPrefix: effective.pathPrefix,
    options: effective.options,
    dataType,
    configured: true,
    inheritedFrom,
  };
}

// ── Config-save (with gates) ───────────────────────────────────────────────

/**
 * writeRoute(db, dataType, input, updatedBy)
 *
 * Upsert one route after the immutability + residency gates. Returns
 *   { ok: true, route }
 * or a typed failure
 *   { ok: false, code, error, field?, residency? }
 * with code one of:
 *   INVALID_DATA_TYPE | DESTINATION_REQUIRED | DESTINATION_NOT_FOUND |
 *   DESTINATION_DISABLED | IMMUTABILITY_REQUIRED | RESIDENCY_BLOCKED
 *
 * input: { destination_ref, path_prefix, options, enabled }. enabled defaults
 * to true when a destination_ref is supplied, false otherwise.
 */
function writeRoute(db, dataType, input = {}, updatedBy = null) {
  if (!VALID_DATA_TYPES.includes(dataType)) {
    return {
      ok: false,
      code: 'INVALID_DATA_TYPE',
      error: `data_type must be one of: ${VALID_DATA_TYPES.join(', ')}`,
      field: 'data_type',
    };
  }

  const destinationRef =
    input.destination_ref === undefined || input.destination_ref === null || input.destination_ref === ''
      ? null
      : String(input.destination_ref);
  const enabled = input.enabled === undefined ? (destinationRef ? 1 : 0) : input.enabled ? 1 : 0;
  const pathPrefix =
    input.path_prefix === undefined || input.path_prefix === null ? null : String(input.path_prefix);

  let options = {};
  if (input.options !== undefined && input.options !== null) {
    if (typeof input.options === 'string') options = parseOptions(input.options);
    else if (typeof input.options === 'object' && !Array.isArray(input.options)) options = input.options;
  }

  // Resolve the destination (if any).
  let destination = null;
  if (destinationRef) {
    destination = storageDestinations.getDestinationById(db, destinationRef);
    if (!destination) {
      return {
        ok: false,
        code: 'DESTINATION_NOT_FOUND',
        error: `no storage destination with id '${destinationRef}'`,
        field: 'destination_ref',
      };
    }
    if (enabled === 1 && !destination.enabled) {
      return {
        ok: false,
        code: 'DESTINATION_DISABLED',
        error: `storage destination '${destinationRef}' is disabled; enable it before routing to it`,
        field: 'destination_ref',
      };
    }
  } else if (enabled === 1) {
    return {
      ok: false,
      code: 'DESTINATION_REQUIRED',
      error: 'cannot enable a route with no destination_ref',
      field: 'destination_ref',
    };
  }

  // HARD immutability gate (fail closed). Only when enabling a route to a destination.
  if (destination && enabled === 1 && immutabilityRequired(dataType, options)) {
    if (!isImmutabilityCapable(destination.immutability_mode)) {
      const why =
        dataType === 'audit_log'
          ? 'audit_log archives require an immutability-capable destination'
          : 'this route requires an immutability-capable destination (immutability_required)';
      return {
        ok: false,
        code: 'IMMUTABILITY_REQUIRED',
        error:
          `${why}; destination '${destination.name}' has immutability_mode ` +
          `'${destination.immutability_mode}' (need 'append-only' or 'object-lock')`,
        field: 'destination_ref',
      };
    }
  }

  // Residency config-save gate (block under enforce). Only when a destination is set.
  if (destination) {
    const ev = dataResidency.evaluateConfig(db, dataType, destination.adapter, destination.config, destinationRef);
    if (ev.blocked) {
      return {
        ok: false,
        code: 'RESIDENCY_BLOCKED',
        error: ev.reason || 'blocked by data residency policy',
        residency: ev,
      };
    }
  }

  const now = nowStamp();
  db.prepare(
    `INSERT INTO storage_destination_routes
       (data_type, destination_ref, path_prefix, options, enabled, updated_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(data_type) DO UPDATE SET
       destination_ref = excluded.destination_ref,
       path_prefix = excluded.path_prefix,
       options = excluded.options,
       enabled = excluded.enabled,
       updated_by = excluded.updated_by,
       updated_at = excluded.updated_at`
  ).run(dataType, destinationRef, pathPrefix, JSON.stringify(options), enabled, updatedBy, now, now);

  return { ok: true, route: readRoute(db, dataType) };
}

module.exports = {
  VALID_DATA_TYPES,
  getRouteForType,
  readRoutes,
  readRoute,
  writeRoute,
  isImmutabilityCapable,
  immutabilityRequired,
};

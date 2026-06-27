// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Storage Routing Resolver (B5q)
//
// One resolver every artifact-writer calls to learn where a given data type
// should be written. Backs the storage_destination_routes table (one row per
// data type) and resolves each route to its concrete, enabled storage_destinations
// entries.
//
// Revision v3 -- primary + optional secondary (failover) destination per route.
// A route names a primary destination and, optionally, a distinct secondary; the
// writer pushes the same artifact to each. This is bounded (<= 2), admin-chosen,
// and per-type -- not a return to unbounded fan-out.
//
// Resolution:
//   getRouteForType(db, dataType) -> { destinations: [primary, secondary], ... }
//   - destinations is an ordered array of 0-2 usable destinations (primary first,
//     then the secondary when set, enabled, and distinct from the primary). If the
//     primary is missing/disabled but the secondary is usable, the secondary stands
//     in (destinations = [secondary]).
//   - 'snapshot' inherits the 'backup' route's pair when its own route has no usable
//     destination (the "Same as backups" behavior), with an elective override: a
//     snapshot route with its own enabled destination(s) wins.
//   - an unconfigured / disabled route, or one whose destinations are all
//     missing/disabled, resolves to { destinations: [] } so the writer keeps its
//     local behavior (no push) rather than failing.
//   - `destination` is also returned as a convenience alias for the primary
//     (destinations[0] || null).
//
// Config-save gates (writeRoute), all fail-closed and applied to BOTH the primary
// and the secondary:
//   - HARD immutability gate: audit_log archives MUST route to an
//     immutability-capable destination (S3 Object Lock / Azure Immutable Blob /
//     GCS Retention Lock / local-or-sftp append-only -> immutability_mode
//     'object-lock' or 'append-only'). Any data type may additionally opt in via
//     options.immutability_required. The failover copy must meet the same bar.
//   - Residency gate: dataResidency.evaluateConfig(db, category, ...) is consulted
//     for each destination with the route's data type as the category; a blocked
//     verdict (enforce mode, out-of-region or undeclared) refuses the save.
//   - The secondary must exist, be enabled (when the route is enabled), and differ
//     from the primary.
//   Typed failures carry a `which: 'primary' | 'secondary'` discriminator.
//
// Schema: db/init.js -> storage_destination_routes. Destinations are read through
// services/storage-destinations.js (public view, no credentials).
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
    secondaryDestinationRef: row.secondary_destination_ref,
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
    secondaryDestinationRef: null,
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
      `SELECT data_type, destination_ref, secondary_destination_ref, path_prefix, options,
              enabled, updated_by, created_at, updated_at
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
      `SELECT data_type, destination_ref, secondary_destination_ref, path_prefix, options,
              enabled, updated_by, created_at, updated_at
       FROM storage_destination_routes`
    )
    .all();
  const byType = {};
  for (const r of rows) byType[r.data_type] = rowToRoute(r);
  return VALID_DATA_TYPES.map((t) => byType[t] || emptyRoute(t));
}

// ── Resolution ─────────────────────────────────────────────────────────────

// Resolve a single destination ref to a usable public view (exists + enabled);
// else null.
function resolveOne(db, ref) {
  if (!ref) return null;
  const dest = storageDestinations.getDestinationById(db, ref);
  if (!dest || !dest.enabled) return null;
  return dest;
}

// Resolve a route to its ordered usable destinations: [primary?, secondary?].
// The route must be enabled. The secondary is included only when usable and
// distinct from the primary. A dead primary with a live secondary yields
// [secondary].
function resolveDestinations(db, route) {
  if (!route || !route.enabled) return [];
  const out = [];
  const primary = resolveOne(db, route.destinationRef);
  if (primary) out.push(primary);
  const secondary = resolveOne(db, route.secondaryDestinationRef);
  if (secondary && (!primary || secondary.id !== primary.id)) out.push(secondary);
  return out;
}

/**
 * getRouteForType(db, dataType)
 *
 * The writer-facing resolver. Returns:
 *   {
 *     destinations,   ordered array of 0-2 usable storage_destinations public
 *                     views (primary first, then secondary)
 *     destination,    convenience alias for the primary (destinations[0] || null)
 *     pathPrefix,     the route's path prefix (may be null)
 *     options,        parsed per-type options object
 *     dataType,       the requested data type
 *     configured,     true when at least one usable destination resolved
 *     inheritedFrom,  'backup' when snapshot fell back to the backup route, else null
 *   }
 *
 * When destinations is empty the caller keeps its local behavior (no push).
 */
function getRouteForType(db, dataType) {
  if (!VALID_DATA_TYPES.includes(dataType)) {
    return {
      destinations: [],
      destination: null,
      pathPrefix: null,
      options: {},
      dataType,
      configured: false,
      inheritedFrom: null,
    };
  }

  const own = readRoute(db, dataType);
  let effective = own;
  let inheritedFrom = null;
  let destinations = resolveDestinations(db, own);

  // snapshot inherits the backup route's pair when it has no usable destination
  if (destinations.length === 0 && dataType === 'snapshot') {
    const backupRoute = readRoute(db, 'backup');
    const backupDests = resolveDestinations(db, backupRoute);
    if (backupDests.length > 0) {
      effective = backupRoute;
      destinations = backupDests;
      inheritedFrom = 'backup';
    }
  }

  return {
    destinations,
    destination: destinations[0] || null,
    pathPrefix: effective.pathPrefix,
    options: effective.options,
    dataType,
    configured: destinations.length > 0,
    inheritedFrom,
  };
}

// ── Config-save (with gates) ───────────────────────────────────────────────

// Validate one destination ref for a route. ref may be null (returns ok with a
// null destination). Applies the NOT_FOUND check whenever a ref is set, and the
// DISABLED / immutability / residency gates only when the route is enabled.
// `which` is 'primary' or 'secondary' and selects the offending field name and
// the discriminator on a failure.
function validateRouteDestination(db, dataType, ref, enabled, options, which) {
  const field = which === 'secondary' ? 'secondary_destination_ref' : 'destination_ref';
  if (!ref) return { ok: true, destination: null };

  const destination = storageDestinations.getDestinationById(db, ref);
  if (!destination) {
    return {
      ok: false,
      code: 'DESTINATION_NOT_FOUND',
      error: `no storage destination with id '${ref}'`,
      field,
      which,
    };
  }
  if (enabled === 1 && !destination.enabled) {
    return {
      ok: false,
      code: 'DESTINATION_DISABLED',
      error: `storage destination '${ref}' is disabled; enable it before routing to it`,
      field,
      which,
    };
  }
  if (enabled === 1 && immutabilityRequired(dataType, options)) {
    if (!isImmutabilityCapable(destination.immutability_mode)) {
      const why =
        dataType === 'audit_log'
          ? 'audit_log archives require an immutability-capable destination'
          : 'this route requires an immutability-capable destination (immutability_required)';
      return {
        ok: false,
        code: 'IMMUTABILITY_REQUIRED',
        error:
          `${why}; ${which} destination '${destination.name}' has immutability_mode ` +
          `'${destination.immutability_mode}' (need 'append-only' or 'object-lock')`,
        field,
        which,
      };
    }
  }
  if (enabled === 1) {
    const ev = dataResidency.evaluateConfig(db, dataType, destination.adapter, destination.config, ref);
    if (ev.blocked) {
      return {
        ok: false,
        code: 'RESIDENCY_BLOCKED',
        error: ev.reason || 'blocked by data residency policy',
        residency: ev,
        which,
      };
    }
  }
  return { ok: true, destination };
}

/**
 * writeRoute(db, dataType, input, updatedBy)
 *
 * Upsert one route after the immutability + residency gates (run for the primary
 * and the secondary). Returns
 *   { ok: true, route }
 * or a typed failure
 *   { ok: false, code, error, field?, which?, residency? }
 * with code one of:
 *   INVALID_DATA_TYPE | DESTINATION_REQUIRED | DESTINATION_NOT_FOUND |
 *   DESTINATION_DISABLED | IMMUTABILITY_REQUIRED | RESIDENCY_BLOCKED |
 *   SECONDARY_SAME_AS_PRIMARY
 *
 * input: { destination_ref, secondary_destination_ref, path_prefix, options,
 * enabled }. enabled defaults to true when a destination_ref is supplied, false
 * otherwise. A secondary requires a primary and must differ from it.
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

  const norm = (v) => (v === undefined || v === null || v === '' ? null : String(v));
  const destinationRef = norm(input.destination_ref);
  const secondaryRef = norm(input.secondary_destination_ref);
  const enabled = input.enabled === undefined ? (destinationRef ? 1 : 0) : input.enabled ? 1 : 0;
  const pathPrefix =
    input.path_prefix === undefined || input.path_prefix === null ? null : String(input.path_prefix);

  let options = {};
  if (input.options !== undefined && input.options !== null) {
    if (typeof input.options === 'string') options = parseOptions(input.options);
    else if (typeof input.options === 'object' && !Array.isArray(input.options)) options = input.options;
  }

  // A secondary cannot stand without a primary.
  if (secondaryRef && !destinationRef) {
    return {
      ok: false,
      code: 'DESTINATION_REQUIRED',
      error: 'cannot set a secondary destination without a primary destination_ref',
      field: 'destination_ref',
      which: 'primary',
    };
  }
  // Enabling requires a primary.
  if (!destinationRef && enabled === 1) {
    return {
      ok: false,
      code: 'DESTINATION_REQUIRED',
      error: 'cannot enable a route with no destination_ref',
      field: 'destination_ref',
      which: 'primary',
    };
  }
  // The secondary must differ from the primary.
  if (secondaryRef && destinationRef && secondaryRef === destinationRef) {
    return {
      ok: false,
      code: 'SECONDARY_SAME_AS_PRIMARY',
      error: 'secondary destination must differ from the primary destination',
      field: 'secondary_destination_ref',
      which: 'secondary',
    };
  }

  // Gate both destinations (fail closed).
  const primaryCheck = validateRouteDestination(db, dataType, destinationRef, enabled, options, 'primary');
  if (!primaryCheck.ok) return primaryCheck;
  const secondaryCheck = validateRouteDestination(db, dataType, secondaryRef, enabled, options, 'secondary');
  if (!secondaryCheck.ok) return secondaryCheck;

  const now = nowStamp();
  db.prepare(
    `INSERT INTO storage_destination_routes
       (data_type, destination_ref, secondary_destination_ref, path_prefix, options,
        enabled, updated_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(data_type) DO UPDATE SET
       destination_ref = excluded.destination_ref,
       secondary_destination_ref = excluded.secondary_destination_ref,
       path_prefix = excluded.path_prefix,
       options = excluded.options,
       enabled = excluded.enabled,
       updated_by = excluded.updated_by,
       updated_at = excluded.updated_at`
  ).run(dataType, destinationRef, secondaryRef, pathPrefix, JSON.stringify(options), enabled, updatedBy, now, now);

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
  // exposed for tests
  resolveDestinations,
};

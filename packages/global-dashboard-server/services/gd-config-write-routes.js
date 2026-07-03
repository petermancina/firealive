// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Config-Write Route Registry (B6a)
//
// Single source of truth for which GD API endpoints constitute a *configuration
// or trust-posture change* and must therefore sit behind the GD config-lock
// chokepoint (services/gd-config-lock.js). GD twin of the regional config-write-
// routes registry.
//
// WHY A REGISTRY (not a blanket /api gate)
//   The GD mounts configuration writes (SIEM/SOAR config, alert matrix, backup
//   schedules, notification config, signing-key trust decisions) alongside
//   operational actions (run a health probe, trigger a backup, run the
//   compromise scan, acknowledge a notification, ingest an MC push). A mount-
//   level gate over /api would wrongly block normal GD operations while the
//   platform is locked, so configuration writes are tagged here at the mount or
//   endpoint level and their operational siblings are deliberately absent.
//
// The config-lock recovery endpoints (GET/POST /api/config/lock*) are NEVER
// gated -- the operator unlocks THROUGH them, so they are explicitly exempt.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// Config-only mounts: ANY mutating request under one of these prefixes is a
// configuration change.
//   /api/self-protection/config  -- the self-protection config sub-router
//        (SIEM/SOAR/alert-matrix/runtime-thresholds/webhook/integration-health).
//        The router's operational endpoints (status reads, run-now probe,
//        runtime metrics) live OUTSIDE /config and are not gated.
//   /api/backup-schedules        -- backup schedule configuration (the manual
//        trigger and full-suite run are operational and live elsewhere).
//   /api/malware-scanners        -- the EDR scanner-management surface (add /
//        update / delete / scan-mode / test). Reads (list, get scan-mode) are
//        safe methods and pass.
//   /api/config-baseline         -- config snapshots + golden baseline; mount-
//        gated to cover the :id and /keys routes (save, register/revoke key,
//        import, revert, delete). Reads (list, diff, export, get keys) pass.
const CONFIG_WRITE_MOUNTS = [
  '/api/self-protection/config',
  '/api/backup-schedules',
  '/api/malware-scanners',
  '/api/config-baseline',
];

// Exact config-write endpoints inside mixed routers (operational siblings such
// as /api/auto-update/check-now and /api/notifications/:id/acknowledge are
// intentionally NOT listed and pass through).
const CONFIG_WRITE_PATHS = [
  { method: 'PUT', path: '/api/notifications/config' },
  { method: 'PUT', path: '/api/auto-update/config' },
];

// Parameterized trust-posture mutations (the MC signing-key trust decisions and
// fleet offboard). These change which inbound MCs the GD trusts and so are
// frozen with the rest of the GD configuration when the lock is engaged. The
// inbound MC handshake (/api/mc/register, /api/mc/me/*) and report requests are
// deliberately absent -- they are not GD-admin configuration.
const CONFIG_WRITE_PATTERNS = [
  { method: 'POST', re: /^\/api\/mc\/[^/]+\/signing-key$/ },
  { method: 'POST', re: /^\/api\/mc\/[^/]+\/signing-keys\/[^/]+\/approve$/ },
  { method: 'POST', re: /^\/api\/mc\/[^/]+\/signing-keys\/[^/]+\/reject$/ },
  { method: 'PUT', re: /^\/api\/mc\/[^/]+\/offboard$/ },
];

// Never gated: the config-lock recovery endpoints (unlock is performed through
// them). Method-and-path separation already keeps them clear of the rules
// above; this list is the explicit, belt-and-suspenders guarantee.
const CONFIG_LOCK_EXEMPT = [
  '/api/config/lock',
  '/api/config/lock/unlock-options',
];

/**
 * True when (method, fullPath) is a GD configuration/trust-posture change that
 * must be gated by the config lock. `fullPath` is the query-stripped request
 * path (e.g. '/api/self-protection/config/siem'). Safe methods always return
 * false; the config-lock recovery endpoints always return false.
 */
function isGdConfigWriteRequest(method, fullPath) {
  if (!method || !fullPath) return false;
  const m = String(method).toUpperCase();
  if (!MUTATING_METHODS.has(m)) return false;
  const path = String(fullPath);

  // Recovery endpoints are never gated.
  for (const ex of CONFIG_LOCK_EXEMPT) if (path === ex) return false;

  // Config-only mounts.
  for (const mount of CONFIG_WRITE_MOUNTS) {
    if (path === mount || path.startsWith(mount + '/')) return true;
  }
  // Exact config-write endpoints.
  for (const r of CONFIG_WRITE_PATHS) {
    if (r.method === m && r.path === path) return true;
  }
  // Parameterized trust-posture mutations.
  for (const r of CONFIG_WRITE_PATTERNS) {
    if (r.method === m && r.re.test(path)) return true;
  }
  // Generic config setter: PUT /api/config/<key> (lock endpoints exempted above).
  if (m === 'PUT' && path.startsWith('/api/config/')) return true;

  return false;
}

module.exports = {
  CONFIG_WRITE_MOUNTS,
  CONFIG_WRITE_PATHS,
  CONFIG_WRITE_PATTERNS,
  CONFIG_LOCK_EXEMPT,
  MUTATING_METHODS,
  isGdConfigWriteRequest,
};

//
// FIREALIVE -- Config-Write Route Registry
//
// Single source of truth for which API endpoints constitute a *configuration
// change* and must therefore sit behind the config-lock chokepoint. Consumed
// by:
//
//   - server/middleware/config-lock.js   (the chokepoint gate)
//   - the config-lock coverage guard      (CI test: every config-write route
//                                           in the codebase must be represented
//                                           here, so a newly-added config
//                                           endpoint cannot ship un-gated)
//
// WHY A REGISTRY (not a mount prefix)
//
//   The feature routers v021-v030 mount at the bare /api prefix and mix
//   configuration writes (e.g. PUT /api/edr/config) with operational actions
//   (e.g. POST /api/edr/scan, POST /api/posture/check, POST /api/proactive/
//   approve). A mount-level gate over /api would wrongly block normal SOC
//   operations while the platform is locked. So config writes inside those
//   routers are tagged here at the *endpoint* level; their operational
//   siblings are deliberately absent and pass through.
//
//   The config-only admin routers (KMS providers, IAM, backup, integrations,
//   ...) have no operational endpoints, so every mutating request under their
//   mount prefix is a config change and they are represented by prefix.
//
// AGPL-3.0-or-later
//

// Config-only routers: ANY mutating request (POST/PUT/PATCH/DELETE) under one
// of these mount prefixes is a configuration change.
const CONFIG_WRITE_MOUNTS = [
  '/api/integrations',
  '/api/v1/malware-scanners',
  '/api/apikeys',
  '/api/storage-destinations',
  '/api/storage-routing',  // B5q: per-data-type storage routes (primary + secondary set + test probe gated under the mount)
  '/api/backup-push',
  '/api/backup-schedules',
  '/api/gd-config',
  '/api/gd-signing-key',
  '/api/scheduling',
  '/api/audit',
  '/api/backup-signing-keys',
  '/api/kms-providers',
  '/api/external-restore',
  '/api/ai-provider',
  '/api/iam',
  '/api/cloud-vuln',
  '/api/config-baseline',  // snapshots + golden-baseline (mount-gated to cover the :id routes)
  '/api/client-recovery',  // B5d4: per-client AC teardown + re-provision (POST writes gated)
  '/api/migration',  // B5e: FA-MIG1 deployment migration export + import (POST writes gated)
  '/api/geoip',  // B5n: GeoIP database provisioning (POST /database upload gated)
  '/api/geo-fence',  // B5n: login geo-fence config/exceptions/per-user country (all writes + the resolve dry-run gated under the mount)
  '/api/data-residency',  // B5n2: data-residency policy/declarations/transfer-mechanism (all writes + the evaluate re-check gated under the mount)
  '/api/vuln-scan',  // B5p: on-prem vulnerability-scanner authorization registry + config + access-log (all writes gated under the mount)
  '/api/key-ops',  // B6h B-3: KOA request/approve/authorize (all writes gated; a rekey needs config unlocked)
];

// Exact config-write endpoints inside the mixed feature routers (v021-v030).
// Their operational siblings (scans, checks, approvals, client pushes, peer
// chat/scheduling, MFA enrollment, etc.) are intentionally NOT listed and are
// never gated.
const CONFIG_WRITE_PATHS = [
  { method: 'PUT',  path: '/api/recert/config' },
  { method: 'PUT',  path: '/api/access-control/config' },
  { method: 'PUT',  path: '/api/sase/config' },
  { method: 'PUT',  path: '/api/notifications/client-config' },
  { method: 'PUT',  path: '/api/calendar/config' },
  { method: 'PUT',  path: '/api/edr/config' },
  { method: 'PUT',  path: '/api/kms/config' },
  { method: 'PUT',  path: '/api/network/wifi-policy' },
  { method: 'PUT',  path: '/api/threat-hunting/config' },
  { method: 'PUT',  path: '/api/tripwire/config' },
  { method: 'PUT',  path: '/api/auth-logs/notification-config' },
  { method: 'PUT',  path: '/api/posture/config' },
  { method: 'PUT',  path: '/api/ha/config' },
  { method: 'POST', path: '/api/ha/manual-failover' },
  { method: 'POST', path: '/api/ha/unpair' },
  { method: 'PUT',  path: '/api/fail-open/config' },
  { method: 'PUT',  path: '/api/pseudonyms/config' },
  { method: 'PUT',  path: '/api/global-dashboard/config' },
  { method: 'PUT',  path: '/api/sync-interval/config' },
  { method: 'PUT',  path: '/api/proactive/config' },
  { method: 'PUT',  path: '/api/upskilling-hour/config' },
  { method: 'PUT',  path: '/api/auto-disable-routing/config' },
  { method: 'PUT',  path: '/api/global-dashboard/push-config' },
  { method: 'PUT',  path: '/api/ticketing/config' },
  { method: 'PUT',  path: '/api/auto-update/config' },  // B5r: update-detection schedule (check-now + status are operational, pass through)
];

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * True when (method, path) is a configuration-changing request that must be
 * gated by the config lock. `path` is the full request path (e.g.
 * '/api/edr/config'), without query string. Safe methods always return false.
 */
function isConfigWriteRequest(method, path) {
  if (!method || !path) return false;
  const m = String(method).toUpperCase();
  if (!MUTATING_METHODS.has(m)) return false;
  for (const mount of CONFIG_WRITE_MOUNTS) {
    if (path === mount || path.startsWith(mount + '/')) return true;
  }
  for (const route of CONFIG_WRITE_PATHS) {
    if (route.method === m && route.path === path) return true;
  }
  return false;
}

module.exports = {
  CONFIG_WRITE_MOUNTS,
  CONFIG_WRITE_PATHS,
  MUTATING_METHODS,
  isConfigWriteRequest,
};

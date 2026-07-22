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
  '/api/key-ops',  // B6h B-3: KOA request/approve/authorize (all writes gated; a rekey needs config unlocked)
  // ── B6j: MC-parity coverage ──────────────────────────────────────────────
  // Each mount below is a config-only or trust-posture surface the MC already
  // gates (server/middleware/config-write-routes.js). The GD shipped them all
  // BEFORE B6a built this chokepoint and none was ever registered, so they were
  // reachable while the platform was locked. INTERNAL restore (/api/restore) is
  // deliberately NOT here -- it is governed by two-person approval + a passkey
  // step-up and stays available for incident response; B6j-4 handles its posture.
  '/api/iam',                   // FIDO trust-anchor admin (add/remove attestation roots + AAGUIDs); all-config. THE SHARP GAP: a locked-config ciso must not add a root then enroll a software passkey (defeats B5n3).
  '/api/cloud-vuln',            // scanner-authorization registry (mint/update/revoke). The scanner ANNOUNCE (/api/cloud-vuln-access, a separate mount) is deliberately never gated -- a scanner must announce while locked.
  '/api/migration',             // FA-MIG1 deployment migration export + import (MC parity freezes export too).
  '/api/storage-destinations',  // destination CRUD (SFTP/S3/GCS/Azure credentials); freezes /:id/probe while locked (a config-time connectivity test).
  '/api/external-restore',      // external restore-source CRUD (credentials); freezes /test, /preview, /restore-request, /restore-execute -- pulling an off-box archive is a config-time trust action, frozen while locked.
  '/api/storage-routing',       // per-data-type routing; freezes /:type/test while locked (config-time).
  '/api/data-residency',        // residency policy/declarations/transfer-mechanism; freezes /evaluate while locked (config-time re-check).
];

// Exact config-write endpoints inside mixed routers (operational siblings such
// as /api/auto-update/check-now and /api/notifications/:id/acknowledge are
// intentionally NOT listed and pass through).
const CONFIG_WRITE_PATHS = [
  { method: 'PUT', path: '/api/notifications/config' },
  { method: 'PUT', path: '/api/auto-update/config' },
  { method: 'POST', path: '/api/ha/manual-failover' },
  { method: 'POST', path: '/api/ha/unpair' },
  // ── B6j: exact config/trust endpoints inside mixed routers ───────────────
  // These live in routers whose mount also carries genuine operational actions
  // (trigger a backup, verify a chain, build a cloud package), so the mount
  // cannot be gated whole; only the specific config/trust write is tagged.
  { method: 'POST', path: '/api/backup/signing-keys/rotate' },            // rotate the GD backup signing key. Siblings POST /api/backup (trigger), /chain/verify, /:id/verify stay open (operational).
  { method: 'POST', path: '/api/backup/signing-keys/register-external' }, // register an external key the platform will TRUST to sign backups -- a trust-root write.
  { method: 'POST', path: '/api/cloud/signing-keys/rotate' },            // rotate the GD cloud-package signing key. Sibling POST /api/cloud/package stays open (operational).
  { method: 'PUT',  path: '/api/sase/config' },                          // SASE mode config -- exact MC twin.
  { method: 'PUT',  path: '/api/sdn/network-map' },                      // SDN network-map config (the only mutation under /api/sdn; siblings are reads).
  // GD HA operator control plane (configRouter, mounted at /api/ha behind ciso
  // auth + the chokepoint). Gating the admin-initiated pairing means no NEW peer
  // pairing can start while locked, so the inbound peer/* + pair-init handshake
  // handlers (pinned mTLS / token-authed, mounted OUTSIDE the config-lock in
  // index.js) stay open by design. POST /api/ha/manual-failover + /unpair above
  // were already gated; these three close the rest of the HA config surface.
  { method: 'PUT',  path: '/api/ha/config' },                            // GD HA configuration (peer settings, timeouts).
  { method: 'POST', path: '/api/ha/pairing-token' },                     // issue a pairing token to enroll a new standby -- config-time trust.
  { method: 'POST', path: '/api/ha/pair' },                              // establish HA pairing with a peer -- config-time trust.
  // Non-shaped trust/secret writes defined as inline app.METHOD handlers in
  // index.js (surfaced by the strict GD coverage check; a shape heuristic misses
  // them -- no /config or /signing-keys). Both sit behind the broad chokepoint.
  { method: 'POST', path: '/api/mc/register' },                          // registers a NEW Management Console (inserts management_consoles + issues an API key) -- a trust-expanding write; no new MC should enroll while locked.
  { method: 'POST', path: '/api/cicd/webhook-secret/rotate' },           // writes config.cicd_webhook_secret -- a platform-secret rotation (golden-baseline already treats this key as excluded secret state).
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

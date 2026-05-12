// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Check Functions: Configuration Mgmt
//
// R3g PR2 (v1.0.33): GD-side counterpart to MC PR1's checks/config.js.
// Both files export the same 4 function names so framework definitions
// reference these checks uniformly across MC and GD. Implementations
// differ because the GD has a substantially smaller configuration-
// management surface than the MC.
//
// Each function returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'.
//
// PLATFORM STATE NOTES (GD-specific gaps relative to MC)
//
//   - GD has no config_lock_state table. The GD frontend exposes a
//     Config Lock toggle (firealive-gd jsx line 800) that POSTs to
//     /api/config/lock, but the GD server has no route handler for
//     that path — the feature is frontend-stubbed on the GD side.
//     checkConfigLockState surfaces this honestly.
//   - GD has no fuseCounter field in package.json. The MC's
//     anti-rollback check (DB system_meta.fuse_counter vs package.json
//     fuseCounter) cannot run on the GD because there is no package
//     side to the comparison. The fuse value in system_meta exists
//     but is decorative without a startup integrity check to enforce
//     it.
//   - GD has NODE_ENV references only in stub comments ("In
//     production: ..."); no actual behavior is gated on NODE_ENV in
//     the GD's index.js. checkSecureBaseline reports NODE_ENV as a
//     label but does not claim runtime behaviors that don't exist.
//   - GD has CONFIG_UPDATED audit events from PUT /api/config/:key.
//     checkChangeManagement queries these.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkConfigLockState ─────────────────────────────────────────────────────
// Verifies Config Lock state. The GD has no config_lock_state table
// and no server-side /api/config/lock route handler — the Config
// Lock feature is frontend-stubbed on the GD as of v0.0.31. Returns
// warning surfacing the gap; production deployments cannot achieve
// SOC-grade configuration immutability on the GD until server-side
// persistence ships.
//
// Maps to controls including: SOC 2 CC8.1 Change Management,
// NIST CSF PR.PS-01 Configuration Management, ISO 27001 A.8.9
// Configuration management / A.8.18 Use of privileged utility
// programs, NIST 800-53 CM-5 Access Restrictions for Change,
// NIS2 Art.21(2)(e), Cyber Essentials "Secure configuration".
function checkConfigLockState() {
  return {
    status: 'warning',
    detail: 'GD has no Config Lock server-side persistence as of v0.0.31. The frontend exposes a Config Lock toggle (firealive-gd jsx) that POSTs to /api/config/lock, but no route handler exists on the GD server. SOC-grade configuration immutability on the GD is unavailable until the route handler and config_lock_state table ship. Until then, configuration-change discipline is operator-managed: route-middleware role gating (CISO-only on PUT /api/config/:key) enforces who CAN change configuration, not whether changes are permitted at all in a locked-down posture.',
  };
}

// ── checkChangeManagement ────────────────────────────────────────────────────
// Verifies the change management infrastructure: anti-rollback fuse is
// set in system_meta AND recent CONFIG_UPDATED events are recorded
// in audit_log. PUT /api/config/:key (CISO-only) inserts CONFIG_UPDATED
// rows for every key change. This implementation OVERRIDES the inline
// checkChangeManagement in compliance/index.js when the checks
// aggregator merges this module (later spreads win).
//
// Maps to controls including: SOC 2 CC8.1 Change Management, NIST CSF
// PR.PS-01 / ID.AM-02 / GV.OC-01, ISO 27001 A.8.32, NIST 800-53 CM-3 /
// SI-7, NIS2 Art.21(2)(a), DORA Art.6 ICT Risk Management.
function checkChangeManagement(db) {
  const fuse = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  if (!fuse || !fuse.value) {
    return {
      status: 'fail',
      detail: 'fuse_counter not set in system_meta on the GD. Change management infrastructure not initialized; re-run db-init.js.',
    };
  }
  const fuseInt = parseInt(fuse.value, 10);
  if (isNaN(fuseInt) || fuseInt < 1) {
    return {
      status: 'fail',
      detail: `fuse_counter on the GD has invalid value "${fuse.value}".`,
    };
  }
  const recentChanges = db.prepare(
    "SELECT COUNT(*) AS c FROM audit_log WHERE event_type = 'CONFIG_UPDATED' AND timestamp > datetime('now', '-30 days')"
  ).get();
  const totalChanges = db.prepare(
    "SELECT COUNT(*) AS c FROM audit_log WHERE event_type = 'CONFIG_UPDATED'"
  ).get();
  if (totalChanges.c === 0) {
    return {
      status: 'pass',
      detail: `GD anti-rollback fuse at ${fuseInt}. No CONFIG_UPDATED events recorded yet in audit_log (deployment may be new). AGPL-3.0 source transparency.`,
    };
  }
  return {
    status: 'pass',
    detail: `GD change management: anti-rollback fuse at ${fuseInt}; ${recentChanges.c} CONFIG_UPDATED event(s) in last 30 days (${totalChanges.c} historical total). Every PUT /api/config/:key inserts an audit_log row with user_id and the key changed.`,
  };
}

// ── checkAntiRollback ────────────────────────────────────────────────────────
// Verifies anti-rollback fuse posture. Unlike MC, the GD has no
// package.json fuseCounter field and no startup integrity check that
// compares package.json fuseCounter against system_meta.fuse_counter.
// The fuse value in system_meta exists (seeded by db-init.js with a
// hardcoded value) but is decorative without enforcement. Returns
// warning explaining the gap; pass on the fuse value being a valid
// integer, since that's the only signal available.
//
// Maps to controls including: SOC 2 CC8.1, NIST CSF PR.PS-01,
// ISO 27001 A.8.9, NIST 800-53 SI-7 / SA-22, DORA Art.6.
function checkAntiRollback(db) {
  const dbFuseRow = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  if (!dbFuseRow || !dbFuseRow.value) {
    return {
      status: 'fail',
      detail: 'system_meta.fuse_counter not set on the GD. Anti-rollback signal absent.',
    };
  }
  const dbFuse = parseInt(dbFuseRow.value, 10);
  if (isNaN(dbFuse)) {
    return {
      status: 'fail',
      detail: `system_meta.fuse_counter on the GD has non-integer value "${dbFuseRow.value}".`,
    };
  }
  return {
    status: 'warning',
    detail: `GD has no startup anti-rollback enforcement. system_meta.fuse_counter=${dbFuse} is set (seeded by db-init.js) but the GD has no package.json fuseCounter field and no startup check comparing the two. The fuse value is informational rather than enforcing. A future GD enhancement should add a package.json fuseCounter field plus a startup integrity check that refuses to start if package.json fuseCounter < system_meta.fuse_counter (the rollback signal).`,
  };
}

// ── checkSecureBaseline ──────────────────────────────────────────────────────
// Reports NODE_ENV value but does not claim runtime behaviors that do
// not exist on the GD. Unlike MC, GD has no NODE_ENV-gated middleware
// (no enforceMinTls, no production-mode error handling, no mTLS on
// internal routes — the GD has no /api/internal/ routes). NODE_ENV
// is purely a label on the GD as of v0.0.31, included for parity with
// industry convention but without runtime effect.
//
// Maps to controls including: SOC 2 CC8.1, NIST CSF PR.PS-01,
// ISO 27001 A.8.9, NIST 800-53 CM-2 / CM-6 / CM-7, Cyber Essentials
// "Secure configuration".
function checkSecureBaseline() {
  const env = process.env.NODE_ENV;
  if (env === 'production') {
    return {
      status: 'warning',
      detail: 'NODE_ENV=production set on the GD, but the GD has no NODE_ENV-gated middleware as of v0.0.31 (no enforceMinTls, no production-mode error handling, no mTLS enforcement, no /api/internal/ routes). NODE_ENV is a label without runtime effect on the GD. HTTPS enforcement and hardened error handling are entirely reverse-proxy responsibility and customer-managed; the proxy must terminate TLS, sanitize error responses if needed, and segregate the GD\'s management port from public networks.',
    };
  }
  if (!env || env === 'development' || env === 'test') {
    return {
      status: 'warning',
      detail: `NODE_ENV="${env || 'unset'}". The GD has no NODE_ENV-gated production hardening to activate by setting this value — secure baseline elements (HTTPS, error sanitization, network isolation) are entirely operator-managed at the reverse-proxy / deployment layer regardless of NODE_ENV. The label should still be set to 'production' on production deployments for industry convention.`,
    };
  }
  return {
    status: 'warning',
    detail: `NODE_ENV="${env}" -- non-standard value. Expected one of 'production', 'development', 'test'. Verify deployment configuration.`,
  };
}

module.exports = {
  checkConfigLockState,
  checkChangeManagement,
  checkAntiRollback,
  checkSecureBaseline,
};

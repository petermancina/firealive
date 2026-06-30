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
//   - GD Config Lock is fully implemented as of B6a: the config_lock_state
//     singleton, the /api/config/lock routes (engage, and unlock via a
//     fresh hardware passkey assertion), and the config-write chokepoint.
//     checkConfigLockState reports real lock state.
//   - GD package.json now carries a fuseCounter field (added in B6a,
//     set to the platform anti-rollback floor). The MC's full anti-
//     rollback check (refuse startup when package.json fuseCounter <
//     system_meta.fuse_counter) still cannot run on the GD: there is
//     no boot-time comparison yet. The manifest fuse and the seeded
//     system_meta fuse are both present, but the value is reported,
//     not enforced, until the GD startup-verifier phase wires the
//     comparison. checkAntiRollback reports that posture.
//   - GD has NODE_ENV references only in stub comments ("In
//     production: ..."); no actual behavior is gated on NODE_ENV in
//     the GD's index.js. checkSecureBaseline reports NODE_ENV as a
//     label but does not claim runtime behaviors that don't exist.
//   - GD has CONFIG_UPDATED audit events from PUT /api/config/:key.
//     checkChangeManagement queries these.
//
// FORWARD-COMPATIBLE PATTERN
//
// Check functions in this file use a tableExists() helper to gracefully
// handle GD platform features behind a forward-compatible table probe.
// GD Config Lock server-side persistence (the config_lock_state table +
// the /api/config/lock routes + the config-write chokepoint) ships as of
// B6a, so checkConfigLockState reports real lock state; the table-absent
// path below is now a defensive fallback for incomplete initialization.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── tableExists ──────────────────────────────────────────────────────────────
// Forward-compatibility helper: returns true if a SQLite table named
// `name` exists in the connected DB.
function tableExists(db, name) {
  return !!db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?"
  ).get(name);
}

// ── checkConfigLockState ─────────────────────────────────────────────────────
// Verifies Config Lock state. As of B6a the GD has server-side Config
// Lock persistence (the config_lock_state singleton, the /api/config/lock
// routes, and the config-write chokepoint), so this check reports real
// lock state:
//
//   fail    -- config_lock_state row missing (incomplete initialization)
//   warning -- NODE_ENV=production AND lock_active=0 (production should lock)
//   pass    -- Config Lock active, or not active in a non-production env
//
// Unlock requires the ciso role + a fresh hardware passkey (WebAuthn)
// assertion (the GD is hardware-key-only; there is no TOTP path). If the
// config_lock_state table is somehow absent, the defensive fallback below
// returns a warning pointing at db-init.js.
//
// Maps to controls including: SOC 2 CC8.1 Change Management,
// NIST CSF PR.PS-01 Configuration Management, ISO 27001 A.8.9
// Configuration management / A.8.18 Use of privileged utility
// programs, NIST 800-53 CM-5 Access Restrictions for Change,
// NIS2 Art.21(2)(e), Cyber Essentials "Secure configuration".
function checkConfigLockState(db) {
  if (tableExists(db, 'config_lock_state')) {
    const lockState = db.prepare(
      "SELECT lock_active, locked_by_user_id, locked_at FROM config_lock_state WHERE id = 1"
    ).get();
    if (!lockState) {
      return {
        status: 'fail',
        detail: 'config_lock_state singleton row missing on the GD. Config Lock infrastructure initialized incompletely — table present but no default row.',
      };
    }
    const isProduction = process.env.NODE_ENV === 'production';
    if (isProduction && lockState.lock_active === 0) {
      return {
        status: 'warning',
        detail: 'NODE_ENV=production on the GD but Config Lock is not active (lock_active = 0). Production deployments should enable Config Lock to prevent unauthorized platform-configuration changes. Engage via the Config Lock control with a hardware passkey (WebAuthn) assertion.',
      };
    }
    if (lockState.lock_active === 1) {
      return {
        status: 'pass',
        detail: `GD Config Lock active (locked_at=${lockState.locked_at}, locked_by_user_id=${lockState.locked_by_user_id || 'NULL'}). Platform-configuration routes gated; unlock requires the ciso role + a fresh hardware passkey (WebAuthn) assertion.`,
      };
    }
    return {
      status: 'pass',
      detail: `GD Config Lock not active (NODE_ENV="${process.env.NODE_ENV || 'unset'}"). Non-production environments may operate unlocked; production deployments should lock.`,
    };
  }
  return {
    status: 'warning',
    detail: 'config_lock_state table unexpectedly absent on the GD. Server-side Config Lock ships as of B6a (the config_lock_state singleton, the /api/config/lock routes, and the config-write chokepoint); a missing table indicates incomplete initialization. Re-run db-init.js to create it, after which this check reports real lock state automatically.',
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
// Verifies anti-rollback fuse posture. The GD package.json now carries
// a fuseCounter field (added in B6a), but unlike the MC there is still
// no startup integrity check comparing package.json fuseCounter against
// system_meta.fuse_counter. The seeded system_meta fuse and the new
// manifest fuse are both present, but the value is reported rather than
// enforced until the startup-verifier phase wires the boot-time check.
// Returns warning explaining the remaining gap; pass on the fuse value
// being a valid integer, since that's the runtime signal available.
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
    detail: `GD anti-rollback is reported, not yet enforced. system_meta.fuse_counter=${dbFuse} is set (seeded by db-init.js) and package.json now carries a fuseCounter field (added in B6a, set to the platform anti-rollback floor), but there is still no startup check comparing the two. The fuse value is informational until the GD startup-verifier phase adds a boot-time integrity check that refuses to start if package.json fuseCounter < system_meta.fuse_counter (the rollback signal).`,
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

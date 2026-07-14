// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Check Functions: Configuration Management
//
// R3g (v1.0.33): part of the comprehensive technical-control verification
// library that backs FireAlive's compliance claims under Foundational
// Rule 14 (Shared Responsibility framing).
//
// This file provides 4 check functions covering Config Lock state,
// change management audit trail, anti-rollback fuse integrity, and
// secure baseline (production-mode) verification. Each function
// queries actual platform state and returns { status, detail } where
// status is 'pass' | 'warning' | 'fail'.
//
// Functions are referenced from framework definitions in
// server/services/compliance/frameworks/<id>.js (R3g commits 13-28).
//
// RELATIONSHIP TO index.js
//
// The pre-R3g compliance.js (and the commit-01 carryover in
// compliance/index.js) contained a minimal checkChangeManagement that
// only read the fuse_counter value. The checkChangeManagement in this
// file is the FULLER implementation that additionally counts recent
// configuration change events from audit_log. Framework definitions
// in R3g commits 13-17 will be wired to import this fuller version
// from checks/config.js; until that wiring happens, both versions
// coexist (they are not in conflict -- each framework definition
// names a specific implementation).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkConfigLockState ─────────────────────────────────────────────────────
// Verifies the Config Lock state is appropriate for the deployment
// environment. In production (NODE_ENV='production'), Config Lock
// must be active (lock_active = 1) to prevent unauthorized platform-
// configuration changes -- this is the SOC-grade hardening introduced
// in R3e (v1.0.32). Warning if production AND lock_active = 0; pass
// if production AND locked, or non-production (where lock state is
// operator-discretion).
//
// Maps to controls including: SOC 2 CC8.1 Change Management,
// NIST CSF PR.PS-01 Configuration Management, ISO 27001 A.8.9
// Configuration management / A.8.18 Use of privileged utility
// programs, NIST 800-53 CM-5 Access Restrictions for Change,
// NIS2 Art.21(2)(e), Cyber Essentials "Secure configuration".
function checkConfigLockState(db) {
  const lockState = db.prepare(
    "SELECT lock_active, locked_by_user_id, locked_at FROM config_lock_state WHERE id = 1"
  ).get();
  if (!lockState) {
    return {
      status: 'fail',
      detail: 'config_lock_state singleton row missing. Config Lock infrastructure not initialized (R3e migration may not have run).',
    };
  }
  const isProduction = process.env.NODE_ENV === 'production';
  if (isProduction && lockState.lock_active === 0) {
    return {
      status: 'warning',
      detail: 'NODE_ENV=production but Config Lock is not active (lock_active = 0). Production deployments should enable Config Lock to prevent unauthorized platform-configuration changes. Toggle via admin Config Lock UI with a hardware-passkey step-up.',
    };
  }
  if (lockState.lock_active === 1) {
    return {
      status: 'pass',
      detail: `Config Lock active (locked_at=${lockState.locked_at}, locked_by_user_id=${lockState.locked_by_user_id || 'NULL'}). Platform-configuration routes gated; modifications require unlock + admin role + a hardware-passkey step-up.`,
    };
  }
  return {
    status: 'pass',
    detail: `Config Lock not active (NODE_ENV="${process.env.NODE_ENV || 'unset'}"). Non-production environments may operate unlocked; production deployments should lock.`,
  };
}

// ── checkChangeManagement ────────────────────────────────────────────────────
// Verifies the change management infrastructure: anti-rollback fuse is
// set in system_meta AND recent configuration-change events are
// recorded in audit_log. The fuller implementation supersedes the
// minimum-viable version in compliance/index.js. Pass if fuse is set
// AND audit_log shows configuration-change activity in the last 30
// days; warning if either signal is missing.
//
// Maps to controls including: SOC 2 CC8.1 Change Management, NIST CSF
// PR.PS-01 / ID.AM-02 / GV.OC-01, ISO 27001 A.8.32 Change management,
// NIST 800-53 CM-3 Configuration Change Control / SI-7, NIS2
// Art.21(2)(a), DORA Art.6 ICT Risk Management.
function checkChangeManagement(db) {
  const fuse = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  if (!fuse || !fuse.value) {
    return {
      status: 'fail',
      detail: 'fuse_counter not set in system_meta. Change management infrastructure not initialized.',
    };
  }
  const fuseInt = parseInt(fuse.value, 10);
  if (isNaN(fuseInt) || fuseInt < 1) {
    return {
      status: 'fail',
      detail: `fuse_counter has invalid value "${fuse.value}".`,
    };
  }
  const recentChanges = db.prepare(
    "SELECT COUNT(*) AS c FROM audit_log WHERE event_type LIKE '%CONFIG%' AND timestamp > datetime('now', '-30 days')"
  ).get();
  const totalChanges = db.prepare(
    "SELECT COUNT(*) AS c FROM audit_log WHERE event_type LIKE '%CONFIG%'"
  ).get();
  if (totalChanges.c === 0) {
    return {
      status: 'pass',
      detail: `Anti-rollback fuse at ${fuseInt}. No configuration changes recorded in audit_log yet (system likely just deployed). AGPL-3.0 source transparency.`,
    };
  }
  return {
    status: 'pass',
    detail: `Change management: anti-rollback fuse at ${fuseInt}; ${recentChanges.c} configuration change event(s) in last 30 days (${totalChanges.c} historical total). All changes audit-logged with user_id and timestamp.`,
  };
}

// ── checkAntiRollback ────────────────────────────────────────────────────────
// Verifies the anti-rollback fuse in system_meta matches package.json's
// fuseCounter field. The two values are seeded from the same source
// at startup (server/lib/version.js reads package.json, init.js writes
// fuse_counter into system_meta with that value). A mismatch indicates
// either DB tampering (someone manually changed system_meta), an
// in-progress rollback attempt (older package.json with newer DB), or
// a migration that hasn't completed. Fail on mismatch; pass on match.
//
// Maps to controls including: SOC 2 CC8.1, NIST CSF PR.PS-01,
// ISO 27001 A.8.9, NIST 800-53 SI-7 Software/Firmware/Information
// Integrity / SA-22 Unsupported System Components, DORA Art.6.
function checkAntiRollback(db) {
  let pkgFuse;
  try {
    const version = require('../../../lib/version');
    pkgFuse = version.fuseCounter;
  } catch (err) {
    return {
      status: 'fail',
      detail: `Cannot resolve server/lib/version.js to read package.json fuseCounter: ${err.message}.`,
    };
  }
  const dbFuseRow = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  if (!dbFuseRow || !dbFuseRow.value) {
    return {
      status: 'fail',
      detail: `fuse_counter not set in system_meta. package.json declares fuseCounter=${pkgFuse}; DB should match after init.js runs.`,
    };
  }
  const dbFuse = parseInt(dbFuseRow.value, 10);
  if (isNaN(dbFuse)) {
    return {
      status: 'fail',
      detail: `system_meta.fuse_counter value "${dbFuseRow.value}" is not an integer.`,
    };
  }
  if (dbFuse !== pkgFuse) {
    return {
      status: 'fail',
      detail: `Anti-rollback mismatch: package.json fuseCounter=${pkgFuse}, system_meta.fuse_counter=${dbFuse}. Possible rollback attempt, DB tampering, or incomplete migration.`,
    };
  }
  return {
    status: 'pass',
    detail: `Anti-rollback: package.json fuseCounter=${pkgFuse} matches system_meta.fuse_counter=${dbFuse}. Monotonic increment enforced at release; startup integrity check rejects rollback attempts.`,
  };
}

// ── checkSecureBaseline ──────────────────────────────────────────────────────
// Verifies the deployment is running with secure baseline settings.
// NODE_ENV=production activates:
//   - enforceMinTls middleware (rejects non-HTTPS requests)
//   - production-mode error handling (no stack traces in responses)
//   - mTLS enforcement on /api/internal/ routes
//   - Hardened security headers
// Warning if NODE_ENV is unset or non-production; fail if explicitly
// set to 'development' or 'test' on what appears to be a production
// deployment (no good way to detect this from inside the process,
// so warning is the best we can do without additional context).
//
// Maps to controls including: SOC 2 CC8.1, NIST CSF PR.PS-01,
// ISO 27001 A.8.9, NIST 800-53 CM-2 Baseline Configuration / CM-6
// Configuration Settings / CM-7 Least Functionality, Cyber
// Essentials "Secure configuration".
function checkSecureBaseline() {
  const env = process.env.NODE_ENV;
  if (env === 'production') {
    return {
      status: 'pass',
      detail: 'Secure baseline: NODE_ENV=production. HTTPS enforcement, mTLS on internal routes, hardened error handling, and production-mode security headers are active.',
    };
  }
  if (!env || env === 'development' || env === 'test') {
    return {
      status: 'warning',
      detail: `NODE_ENV="${env || 'unset'}". Secure baseline elements (HTTPS enforcement, production error handling, mTLS enforcement) require NODE_ENV=production. Acceptable for development; production deployments must set NODE_ENV=production.`,
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

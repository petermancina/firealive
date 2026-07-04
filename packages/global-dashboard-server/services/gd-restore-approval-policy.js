// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- Restore Approval Policy Service
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// Reads + writes the operator-configured policy for restore approval, the GD twin
// of the Regional Server's restore-approval-policy service. Stored in system_meta:
//
//   restore_approval_mode             string in {strict, delayed-self-approval, disabled}
//   restore_approval_window_hours     positive integer; default 24
//
// Auto-seeded on first boot by db-init.js. The GD seeds delayed-self-approval
// (the single-CISO operational default) rather than the Regional Server's strict
// two-person default; strict remains available. Operators change the policy via
// the admin route; routes emit audit logs on changes, and this service is purely
// read/write + validation.
//
// MODES
//
//   strict
//     Restore requires approval from a SECOND operator (different user id from
//     the requester) within the approval window. After the window expires the
//     request status becomes expired and a fresh request is needed. A
//     single-operator deployment cannot push a restore through in strict mode;
//     such deployments should use delayed-self-approval or disabled.
//
//   delayed-self-approval (GD default)
//     Same as strict, BUT after the window has elapsed AND no second operator has
//     approved, the original requester can approve their own request. The window
//     itself is the security property: a malicious operator (or compromised
//     credentials) cannot push a restore through faster than the window allows,
//     giving legitimate operators time to spot the pending request in the audit
//     log and email digests.
//
//   disabled
//     No second-person approval. The first operator proceeds directly. The chain
//     integrity precondition is still enforced. Intended for deployments where
//     requiring a second person would block all recovery.
//
// Reading is sync (a single SELECT each); writing is sync with validation. No
// caching layer -- the values are read on each restore request, and those are
// rare events.
// -----------------------------------------------------------------------------

const VALID_MODES = ['strict', 'delayed-self-approval', 'disabled'];
const DEFAULT_MODE = 'delayed-self-approval';
const DEFAULT_WINDOW_HOURS = 24;
const MIN_WINDOW_HOURS = 1;
const MAX_WINDOW_HOURS = 24 * 30;   // 30 days; longer suggests misuse

// -- Read API ----------------------------------------------------------------

/**
 * Get the current approval mode. Returns DEFAULT_MODE if the row is missing (the
 * boot path should have seeded it; this fallback covers partial-init scenarios).
 */
function getMode(db) {
  const row = db.prepare("SELECT value FROM system_meta WHERE key = 'restore_approval_mode'").get();
  if (!row || !VALID_MODES.includes(row.value)) return DEFAULT_MODE;
  return row.value;
}

/**
 * Get the configured approval window in hours. Returns DEFAULT_WINDOW_HOURS if
 * missing or out of range. Range-check on read defends against out-of-band manual
 * updates that bypass setWindowHours.
 */
function getWindowHours(db) {
  const row = db.prepare("SELECT value FROM system_meta WHERE key = 'restore_approval_window_hours'").get();
  if (!row) return DEFAULT_WINDOW_HOURS;
  const n = parseInt(row.value, 10);
  if (!Number.isInteger(n) || n < MIN_WINDOW_HOURS || n > MAX_WINDOW_HOURS) return DEFAULT_WINDOW_HOURS;
  return n;
}

/**
 * Convenience: get both settings in a single object.
 */
function getConfig(db) {
  return {
    mode: getMode(db),
    window_hours: getWindowHours(db),
  };
}

/**
 * Convenience: returns true if the configured mode requires any kind of approval
 * workflow (strict OR delayed-self-approval). Returns false for 'disabled'. The
 * caller's restore handler uses this to decide whether to enter the approval flow
 * at all.
 */
function isApprovalRequired(db) {
  return getMode(db) !== 'disabled';
}

// -- Write API ---------------------------------------------------------------

/**
 * Set the approval mode. Validates against VALID_MODES; throws on invalid input.
 * Caller handles audit logging.
 *
 * Returns the previous mode so the caller can include "old -> new" detail in the
 * audit log.
 */
function setMode(db, newMode) {
  if (typeof newMode !== 'string' || !VALID_MODES.includes(newMode)) {
    const err = new Error(`mode must be one of: ${VALID_MODES.join(', ')}`);
    err.validation = true;
    err.field = 'mode';
    throw err;
  }
  const previous = getMode(db);
  // INSERT OR REPLACE (UPSERT) so first-run installs that lacked the row still
  // work, and subsequent writes update cleanly.
  db.prepare(`
    INSERT INTO system_meta (key, value)
    VALUES ('restore_approval_mode', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(newMode);
  return { previous, current: newMode };
}

/**
 * Set the approval window in hours. Validates range; throws on invalid input.
 * Caller handles audit logging.
 *
 * Returns the previous value.
 */
function setWindowHours(db, hours) {
  if (!Number.isInteger(hours) || hours < MIN_WINDOW_HOURS || hours > MAX_WINDOW_HOURS) {
    const err = new Error(`window_hours must be integer in [${MIN_WINDOW_HOURS}, ${MAX_WINDOW_HOURS}]`);
    err.validation = true;
    err.field = 'window_hours';
    throw err;
  }
  const previous = getWindowHours(db);
  db.prepare(`
    INSERT INTO system_meta (key, value)
    VALUES ('restore_approval_window_hours', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(String(hours));
  return { previous, current: hours };
}

/**
 * Update both settings atomically (single transaction). Either both succeed or
 * neither. Useful for the policy-change admin endpoint where operators may change
 * both at once.
 *
 * Returns { mode: {previous, current}, window_hours: {previous, current} }.
 * Validation errors throw before any write happens (validation runs before the
 * transaction starts).
 */
function setConfig(db, { mode, window_hours }) {
  // Validate first; throw before writing.
  if (mode !== undefined && (typeof mode !== 'string' || !VALID_MODES.includes(mode))) {
    const err = new Error(`mode must be one of: ${VALID_MODES.join(', ')}`);
    err.validation = true; err.field = 'mode';
    throw err;
  }
  if (window_hours !== undefined && (!Number.isInteger(window_hours) || window_hours < MIN_WINDOW_HOURS || window_hours > MAX_WINDOW_HOURS)) {
    const err = new Error(`window_hours must be integer in [${MIN_WINDOW_HOURS}, ${MAX_WINDOW_HOURS}]`);
    err.validation = true; err.field = 'window_hours';
    throw err;
  }

  const txn = db.transaction(() => {
    const result = {};
    if (mode !== undefined) result.mode = setMode(db, mode);
    if (window_hours !== undefined) result.window_hours = setWindowHours(db, window_hours);
    return result;
  });
  return txn();
}

module.exports = {
  // Read API
  getMode,
  getWindowHours,
  getConfig,
  isApprovalRequired,

  // Write API
  setMode,
  setWindowHours,
  setConfig,

  // Constants exposed for routes / tests
  VALID_MODES,
  DEFAULT_MODE,
  DEFAULT_WINDOW_HOURS,
  MIN_WINDOW_HOURS,
  MAX_WINDOW_HOURS,
};

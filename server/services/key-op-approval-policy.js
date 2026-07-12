'use strict';

// FIREALIVE -- Key-Operation Approval Policy (B6h B-3)
//
// The two-person approval mode and window for DESTRUCTIVE KEY OPERATIONS (a rekey,
// a migration-import re-seal, a deployment reset), stored in system_meta. It is the
// parallel of restore-approval-policy.js and shares the restore-approvals engine's
// state machine and second-person rule -- but with ONE deliberate difference: there
// is NO 'disabled' mode. A restore can, by owner policy, run without a second person;
// a destructive key operation can NEVER be un-gated. The honest emergency escape
// hatch is not a disabled mode -- it is stopping the server and using the offline
// recovery code, which needs no KOA.
//
//   key_op_approval_mode          string in {strict, delayed-self-approval}
//   key_op_approval_window_hours  integer in [1, 720]  (delayed-self only)

const VALID_MODES = ['strict', 'delayed-self-approval']; // no 'disabled' -- a key op is never un-gated
const DEFAULT_MODE = 'strict';
const DEFAULT_WINDOW_HOURS = 24;
const MIN_WINDOW_HOURS = 1;
const MAX_WINDOW_HOURS = 24 * 30; // 30 days; longer suggests misuse

// Current key-operation approval mode. Range-checks on read so an out-of-band manual
// system_meta edit cannot force an invalid or (critically) a 'disabled' mode -- an
// unknown value falls back to the strict default.
function getMode(db) {
  const row = db.prepare("SELECT value FROM system_meta WHERE key = 'key_op_approval_mode'").get();
  if (!row || !VALID_MODES.includes(row.value)) return DEFAULT_MODE;
  return row.value;
}

// Configured delayed-self window in hours; falls back to the default if missing or
// out of range (defends against out-of-band edits that bypass setWindowHours).
function getWindowHours(db) {
  const row = db.prepare("SELECT value FROM system_meta WHERE key = 'key_op_approval_window_hours'").get();
  if (!row) return DEFAULT_WINDOW_HOURS;
  const n = parseInt(row.value, 10);
  if (!Number.isInteger(n) || n < MIN_WINDOW_HOURS || n > MAX_WINDOW_HOURS) return DEFAULT_WINDOW_HOURS;
  return n;
}

// Set the key-operation approval mode. Validates against VALID_MODES (which excludes
// 'disabled'); throws on an invalid value.
function setMode(db, newMode) {
  if (typeof newMode !== 'string' || !VALID_MODES.includes(newMode)) {
    const err = new Error('key_op_approval_mode must be one of: ' + VALID_MODES.join(', '));
    err.code = 'INVALID_KEY_OP_APPROVAL_MODE';
    throw err;
  }
  db.prepare(
    "INSERT INTO system_meta (key, value) VALUES ('key_op_approval_mode', ?) " +
    "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  ).run(newMode);
  return newMode;
}

// Set the delayed-self window in hours. Validates the range; throws otherwise.
function setWindowHours(db, hours) {
  const n = typeof hours === 'number' ? hours : parseInt(hours, 10);
  if (!Number.isInteger(n) || n < MIN_WINDOW_HOURS || n > MAX_WINDOW_HOURS) {
    const err = new Error('key_op_approval_window_hours must be an integer in [' + MIN_WINDOW_HOURS + ', ' + MAX_WINDOW_HOURS + ']');
    err.code = 'INVALID_KEY_OP_APPROVAL_WINDOW';
    throw err;
  }
  db.prepare(
    "INSERT INTO system_meta (key, value) VALUES ('key_op_approval_window_hours', ?) " +
    "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  ).run(String(n));
  return n;
}

module.exports = {
  VALID_MODES,
  DEFAULT_MODE,
  DEFAULT_WINDOW_HOURS,
  MIN_WINDOW_HOURS,
  MAX_WINDOW_HOURS,
  getMode,
  getWindowHours,
  setMode,
  setWindowHours,
};

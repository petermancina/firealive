// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE GLOBAL DASHBOARD ── Post-Restore Node-Local Posture (B6j-4)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// A restore overwrites the ENTIRE GD database from a backup -- including the two
// node-local security records the rest of the platform already treats as
// never-carried identity / anti-rollback state:
//
//   * node_state.fuse_high_water -- the anti-rollback high-water. gd-fuse-high-
//       water.checkAndAdvance() reads it at boot FROM INSIDE the database, so a
//       raw restore of an old backup (low mark) run on an old binary (low fuse)
//       boots cleanly: the mark that is supposed to detect a rollback rode inside
//       the thing being rolled back. This fixup writes max(pre-restore, restored)
//       so a restore can NEVER lower the mark -- the fuse stays a one-way ratchet
//       across restores. The supported incident-response play (CURRENT binary + an
//       older last-known-good backup) is unaffected: the running binary's fuse
//       still meets the (bumped) mark, so it boots.
//
//   * config_lock_state.lock_active -- a raw restore reverts the lock to the
//       backup's state, so restoring a pre-lock backup silently lands UNLOCKED.
//       D6: a restore always lands LOCKED; the operator unlocks deliberately with
//       a fresh hardware passkey. Fail-safe over least-surprise. Not a privilege
//       bypass -- a restore already requires two-person approval + a passkey step-
//       up, strictly more than an unlock.
//
// This is the doctrine gd-golden-baseline.js already applies to a CONFIG REVERT
// (it excludes fuse_counter / fuse_high_water / deployment_mode / config_lock_
// state as "identity / anti-rollback state ... never carried"). The full restore
// path is a raw DB copy and never got the same treatment; B6j-4 gives it.
//
// Applied to the RESTORED database (a fresh handle opened after the swap), before
// the operator-prompted restart. db-init at restart does not override it: its
// config_lock_state seed is INSERT OR IGNORE (the singleton now exists, locked),
// and checkAndAdvance reads the bumped mark.
//
// Uses only the better-sqlite3 / node:sqlite common subset (prepare/get/run,
// exec), so the logic is identical across both servers and unit-testable.

const { readHighWater } = require('./gd-fuse-high-water');

// node_state is a stable KV table (key TEXT PRIMARY KEY, value TEXT NOT NULL) on
// both servers. Ensure it exists so the mark is written even when restoring a
// backup that predates node_state -- otherwise the anti-rollback hole reopens for
// a pre-B6h backup (no mark inside -> old binary boots).
function ensureNodeState(db) {
  db.exec('CREATE TABLE IF NOT EXISTS node_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
}

function writeHighWater(db, value) {
  db.prepare(
    "INSERT INTO node_state (key, value) VALUES ('fuse_high_water', ?) " +
      'ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  ).run(String(value));
}

function tableExists(db, name) {
  return !!db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(name);
}

/**
 * Repair node-local posture on a just-restored GD database.
 *
 * @param {object} db  an OPEN handle to the RESTORED database (post-swap).
 * @param {object} [opts]
 * @param {number|null} [opts.preFuseHighWater]  fuse_high_water read from the
 *        LIVE database BEFORE the restore overwrote it (null if none existed).
 * @returns {{fuseHighWater:(number|null), fusePre:(number|null),
 *            fuseRestored:(number|null), configForceLocked:boolean}}
 */
function applyPostRestorePosture(db, opts = {}) {
  const pre = Number.isInteger(opts.preFuseHighWater) ? opts.preFuseHighWater : null;

  // 1) Anti-rollback fuse high-water: never let a restore lower it.
  ensureNodeState(db);
  const restored = readHighWater(db); // may be null (backup predates the mark)
  let target = null;
  if (pre !== null || restored !== null) {
    const a = pre === null ? -Infinity : pre;
    const b = restored === null ? -Infinity : restored;
    const max = Math.max(a, b);
    target = Number.isFinite(max) ? max : null;
  }
  if (target !== null) {
    writeHighWater(db, target);
  }

  // 2) Force-lock config (D6). Only if the table exists; a backup predating the
  //    config-lock feature (pre-B6a) has no lock state to preserve, and db-init
  //    seeds the singleton at restart.
  let configForceLocked = false;
  if (tableExists(db, 'config_lock_state')) {
    db.prepare(
      'INSERT INTO config_lock_state (id, lock_active, locked_at, idle_minutes) ' +
        'VALUES (1, 1, ?, 15) ' +
        'ON CONFLICT(id) DO UPDATE SET lock_active = 1, locked_at = excluded.locked_at, ' +
        'auto_relock_at = NULL, locked_by_user_id = NULL'
    ).run(Date.now());
    configForceLocked = true;
  }

  return {
    fuseHighWater: target,
    fusePre: pre,
    fuseRestored: restored,
    configForceLocked,
  };
}

module.exports = { applyPostRestorePosture };

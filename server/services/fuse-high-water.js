// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Fuse High-Water (Anti-Rollback)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// Boot-time anti-rollback gate (B5e, decision D7). The version module is the
// single source of truth for the running build's fuse counter. This module
// tracks the highest fuse this deployment has ever recorded in
// node_state.fuse_high_water (node-local, excluded from replication so a standby
// never inherits the active's mark; relocated from system_meta in B6h A-8) and refuses to let
// the running build sit BELOW that high-water: a lower fuse means the binary was
// downgraded or an older snapshot or image was restored -- a rollback.
//
// The local check catches a binary downgrade against a preserved database. A
// full VM snapshot restore (binary and database rolled back together) is caught
// by the AC-fleet and GD attestation layers and, where present, the vTPM NV
// monotonic counter (D7) -- both build on this high-water.
//
// checkAndAdvance() returns the verdict; the startup caller decides to refuse
// boot, quarantine, and raise the loud alert.

const version = require('../lib/version');

function currentFuse() {
  return version.fuseCounter;
}

function readHighWater(db) {
  let row;
  try {
    row = db.prepare("SELECT value FROM node_state WHERE key = 'fuse_high_water'").get();
  } catch (err) {
    return null;
  }
  if (!row) {
    return null;
  }
  const n = parseInt(row.value, 10);
  return Number.isInteger(n) ? n : null;
}

function persistHighWater(db, value) {
  db.prepare("INSERT INTO node_state (key, value) VALUES ('fuse_high_water', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(String(value));
}

// Compare the running build's fuse against the recorded high-water. A running
// build below the high-water is a rollback; otherwise advance the high-water.
function checkAndAdvance(db) {
  const cur = currentFuse();
  const hw = readHighWater(db);
  if (hw !== null && cur < hw) {
    return { rollback: true, currentFuse: cur, highWater: hw, advanced: false };
  }
  const next = (hw === null) ? cur : Math.max(hw, cur);
  const advanced = (hw !== null && next > hw);
  if (hw === null || advanced) {
    persistHighWater(db, next);
  }
  return { rollback: false, currentFuse: cur, highWater: next, advanced: advanced };
}

module.exports = {
  currentFuse,
  readHighWater,
  checkAndAdvance,
};

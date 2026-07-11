// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── GD Fuse High-Water (Anti-Rollback)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// Boot-time anti-rollback gate for the GD Server (B6h A-8, decision D7/D17) -- the
// GD twin of the Regional Server's fuse-high-water. The GD had no boot-time anti-
// rollback until now; this is its first fuse check. The running build's fuse
// counter is the GD package.json fuseCounter (the same source the GD backup suite
// reads); there is no GD version module. This module tracks the highest fuse this
// GD deployment has ever recorded in node_state.fuse_high_water -- node-local and
// excluded from replication, so a promoted-from-standby GD never inherits another
// node's mark -- and refuses to let the running build sit BELOW that high-water: a
// lower fuse means the binary was downgraded or an older snapshot or image was
// restored -- a rollback.
//
// checkAndAdvance() returns the verdict; the startup caller (fail-closed) decides
// to refuse boot, quarantine, and raise the loud alert.

function currentFuse() {
  const pkg = require('../package.json');
  return typeof pkg.fuseCounter === 'number' ? pkg.fuseCounter : 0;
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

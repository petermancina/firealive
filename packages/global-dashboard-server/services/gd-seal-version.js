// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE (Global Dashboard) ── Seal-Version High-Water (Anti-Rollback) + straggler report
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// Boot-time seal-format anti-rollback (B6h B-5); GD twin of server/services/seal-version.js.
// The Tier-1 envelope is the single source of truth for the seal version new
// writes use (CURRENT_SEAL_VERSION). This module tracks the highest seal version
// this deployment has ever run in node_state.seal_version_high_water (node-local,
// excluded from replication -- it describes THIS node's binary/format) and
// refuses to let the running build sit BELOW that mark: a lower current version
// means the binary was downgraded to one that writes an older, weaker envelope
// -- a rollback. checkAndAdvance() returns the verdict; the startup caller
// decides to refuse boot, quarantine, and raise the alert (as with the fuse).
//
// reportStragglers() is separate and advisory: it walks the Tier-1 registry and
// reports how many stored values are still below the current seal version (v1
// legacy awaiting rekey). It PRINTS and NEVER persists -- rewriting an at-rest
// value is the KOA-gated offline rekey's job, not a silent boot mutation. The
// version peek reads only the envelope's magic/version bytes; it uses no key and
// never decrypts, so it is safe even on a node that cannot open the value.

const tier1Envelope = require('./gd-tier1-envelope');
const { GD_TIER1_COLUMNS } = require('./gd-tier1-columns');

function currentSealVersion() {
  return tier1Envelope.CURRENT_SEAL_VERSION;
}

function readHighWater(db) {
  let row;
  try {
    row = db.prepare("SELECT value FROM node_state WHERE key = 'seal_version_high_water'").get();
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
  db.prepare("INSERT INTO node_state (key, value) VALUES ('seal_version_high_water', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(String(value));
}

// A running build below the recorded high-water is a rollback to an older seal
// format; otherwise advance the high-water. Same shape as fuse checkAndAdvance.
function checkAndAdvance(db) {
  const cur = currentSealVersion();
  const hw = readHighWater(db);
  if (hw !== null && cur < hw) {
    return { rollback: true, currentSealVersion: cur, highWater: hw, advanced: false };
  }
  const next = (hw === null) ? cur : Math.max(hw, cur);
  const advanced = (hw !== null && next > hw);
  if (hw === null || advanced) {
    persistHighWater(db, next);
  }
  return { rollback: false, currentSealVersion: cur, highWater: next, advanced: advanced };
}

// Walk every Tier-1 column and count values below the current seal version.
// PRINTS a summary; NEVER writes. Returns { below, total, current }.
function reportStragglers(db) {
  const cur = currentSealVersion();
  const cols = GD_TIER1_COLUMNS.filter(function (c) { return c.class === 'tier1'; });
  let below = 0;
  let total = 0;
  const perColumn = {};
  for (let i = 0; i < cols.length; i++) {
    const c = cols[i];
    let rows;
    try {
      rows = db.prepare(
        'SELECT "' + c.column + '" AS val FROM "' + c.table + '" WHERE "' + c.column + '" IS NOT NULL'
      ).all();
    } catch (queryErr) {
      continue; // table/column not present on this deployment
    }
    for (let j = 0; j < rows.length; j++) {
      total++;
      // GD stores the envelope as the value itself, so peek the version directly.
      const v = tier1Envelope.sealVersionOf(rows[j].val);
      if (v < cur) {
        below++;
        const ref = c.table + '.' + c.column;
        perColumn[ref] = (perColumn[ref] || 0) + 1;
      }
    }
  }
  if (below > 0) {
    console.log('[seal-version] ' + below + ' of ' + total + ' Tier-1 values are below the current seal version ' + cur + ':');
    const keys = Object.keys(perColumn);
    for (let k = 0; k < keys.length; k++) {
      console.log('  ' + keys[k] + ': ' + perColumn[keys[k]]);
    }
    console.log('[seal-version] NOTE: values are NOT rewritten here -- run the offline rekey to re-seal them to the current envelope.');
  }
  return { below: below, total: total, current: cur };
}

module.exports = {
  currentSealVersion,
  readHighWater,
  persistHighWater,
  checkAndAdvance,
  reportStragglers,
};

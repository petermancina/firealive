'use strict';

// FIREALIVE -- Tier-1 boot integrity gate (B-2)
//
// At startup, after the shared KEK has been reloaded (A-7) and before the server
// serves, verify that every chokepoint-sealed Tier-1 column value in the database
// opens under the KEK this node actually holds. This turns the v2 envelope's
// per-read fingerprint check into a whole-database boot assertion, so a wrong KEK
// (an operator points the node at the wrong env-sealed key), a partially-completed
// rekey (an interrupted B-4 run leaves some columns under a different KEK), or
// at-rest corruption is caught here rather than surfacing later at first read.
//
// It opens each value in full (not just the fingerprint), so it also catches a
// wrong KEK on a legacy v1 value (via the GCM tag), a relocated value (AAD), and
// corruption -- the strongest check available.
//
// Domain-aware, to avoid false positives: a never-promoted PASSIVE has not adopted
// the shared KEK, so its replicated columns are the active's data under a KEK it
// does not hold and cannot be verified until it promotes. Those columns are skipped
// (not treated as a failure). Node-local columns are always verified; a promoted
// node (or a standalone/active) verifies replicated columns too.
//
// The gate collects all failures rather than throwing on the first, so the caller
// can report the full picture. The caller decides the (fail-closed) response.

const tier1Seal = require('./tier1-seal');
const { TIER1_COLUMNS } = require('./tier1-columns');

// True if this node is a standby that has never adopted a shared KEK. In that state
// the replicated Tier-1 columns are the active's data under the active's KEK, which
// this node does not hold; they are verifiable only after promotion, so the gate
// skips them here.
function skipsReplicated(db) {
  let role = null;
  try {
    const row = db.prepare("SELECT role FROM ha_node WHERE id = 'self'").get();
    role = row ? row.role : null;
  } catch (e) {
    role = null; // no ha_node table yet (fresh DB) -> standalone -> do not skip
  }
  if (role !== 'passive') return false;
  try {
    return !db.prepare("SELECT 1 FROM node_state WHERE key = 'shared_kek_sealed'").get();
  } catch (e) {
    return true; // passive with no node_state -> never adopted a shared KEK
  }
}

// Verify every class='tier1' (chokepoint-sealed) column value opens under this node's
// KEK. Returns an array of failure descriptors { column, rowid, error }; empty means
// all good. Never throws on a per-value failure -- failures are collected.
function verifyTier1Integrity(db) {
  const failures = [];
  const skipRepl = skipsReplicated(db);
  const cols = TIER1_COLUMNS.filter(function (c) { return c.class === 'tier1'; });
  for (let i = 0; i < cols.length; i++) {
    const c = cols[i];
    if (c.domain === 'replicated' && skipRepl) continue;
    const ref = c.table + '.' + c.column;
    let rows;
    try {
      rows = db.prepare(
        'SELECT rowid AS rid, "' + c.column + '" AS val FROM "' + c.table + '" WHERE "' + c.column + '" IS NOT NULL'
      ).all();
    } catch (queryErr) {
      // Missing table/column (schema not yet migrated on a fresh DB) is not a KEK
      // failure; skip it.
      continue;
    }
    for (let j = 0; j < rows.length; j++) {
      try {
        tier1Seal.openTier1(ref, rows[j].val);
      } catch (openErr) {
        failures.push({
          column: ref,
          rowid: rows[j].rid,
          error: (openErr && openErr.message) ? openErr.message.slice(0, 160) : 'error',
        });
      }
    }
  }
  return failures;
}

module.exports = {
  verifyTier1Integrity,
  skipsReplicated,
};

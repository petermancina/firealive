'use strict';

// FIREALIVE -- Offline node rekey (B6h B-4)
//
// Rebind a promoted node's replicated Tier-1 columns from the adopted shared KEK to
// THIS node's own KEK, then shed the shared KEK, so the node is standalone again and
// can be un-paired (the A-10 guard passes once node_state.shared_kek_sealed is gone).
//
// This is a DESTRUCTIVE key operation and is gated by a KOA (op='rekey'): rekeyNode
// verifies the KOA offline against this node's anchor public key, checks the op, and
// consumes it single-use. It is invoked by the offline rekey CLI (server/tools/
// rekey-node.js), which an operator runs on the node itself (hardware is required to
// unseal the shared KEK and seal under the own KEK) -- not through the live API.
//
// Guarantees (master principle):
//   ATOMIC      -- consume-KOA + re-seal every replicated value + clearSharedKek run in
//                  ONE db transaction. Any failure rolls the whole thing back: the KOA
//                  stays consumable, no value is half-rekeyed, the wrapper stays.
//   FAIL-CLOSED -- resealValue throws if a value will not open under the shared KEK
//                  (wrong key / tamper); inside the transaction that aborts everything.
//   FORWARD-ONLY (D-R2-7) -- re-seals ONLY the live replicated config columns. Backups
//                  and forensic exports are chained at-rest artifacts sealed under the
//                  old KEK and are never touched here; retain the old recovery code to
//                  read them. (Those are not Tier-1 columns, so they are not iterated.)

const { TIER1_COLUMNS } = require('./tier1-columns');
const tier1Seal = require('./tier1-seal');
const tier1Kek = require('./tier1-kek');
const koa = require('./key-op-authorization');

const REPLICATED = TIER1_COLUMNS.filter((c) => c.domain === 'replicated');

function fail(code, message) {
  const e = new Error('rekey: ' + message);
  e.code = code;
  throw e;
}

// Rekey this node: rebind the replicated columns shared-KEK -> own-KEK under a rekey KOA.
// args: { koaId }  -- the id of an approved, minted, unconsumed KOA with op='rekey'.
// Returns { resealed, columns }.
function rekeyNode(db, args) {
  const koaId = args && args.koaId;
  if (typeof koaId !== 'string' || koaId === '') fail('INVALID_INPUT', 'koaId is required');

  // 1. Load and verify the authorization BEFORE touching any data.
  const koaRow = koa.getKoa(db, koaId);
  if (!koaRow) fail('NO_KOA', 'unknown KOA id ' + koaId);
  if (koaRow.op !== 'rekey') fail('WRONG_OP', 'KOA op is "' + koaRow.op + '", expected "rekey"');
  const anchorPem = koa.anchorPublicPem(db);
  if (!anchorPem) fail('NO_ANCHOR', 'this node has no anchor public key to verify the KOA against');
  const verdict = koa.verifyKoa(koaRow, anchorPem);
  if (!verdict.valid) fail('KOA_INVALID', 'authorization is not valid (' + verdict.reason + ')');

  // 2. Capture the KEKs. sharedKek() is the adopted shared KEK on a promoted node; it falls
  //    back to ownKek() only when nothing was adopted -- in which case there is nothing to do.
  const fromKek = tier1Kek.sharedKek();
  const toKek = tier1Kek.ownKek();
  if (Buffer.compare(fromKek, toKek) === 0) {
    fail('NOTHING_TO_REKEY', 'no adopted shared KEK on this node (not a promoted node, or already rekeyed)');
  }
  const fromKekFp = tier1Kek.sharedKekFingerprint();
  const toKekFp = tier1Kek.ownKekFingerprint();

  // 3. One atomic transaction: consume the KOA, re-seal every replicated value, shed the KEK.
  const run = db.transaction(() => {
    if (!koa.consumeKoa(db, koaId, 'node-rekey')) {
      fail('KOA_NOT_CONSUMABLE', 'the authorization is not consumable (already used, or vanished)');
    }
    let resealed = 0;
    for (let i = 0; i < REPLICATED.length; i++) {
      const c = REPLICATED[i];
      const ref = c.table + '.' + c.column;
      let rows;
      try {
        rows = db.prepare(
          'SELECT rowid AS rid, "' + c.column + '" AS val FROM "' + c.table + '" WHERE "' + c.column + '" IS NOT NULL'
        ).all();
      } catch (e) {
        // The table may not exist on this deployment (feature never configured); nothing
        // is sealed there, so there is nothing to rekey. Skip it.
        continue;
      }
      for (let j = 0; j < rows.length; j++) {
        // Fail-closed: resealValue throws if the value will not open under the shared KEK.
        // Being inside the transaction, that rolls back the consume and every prior update.
        const next = tier1Seal.resealValue(ref, rows[j].val, fromKek, fromKekFp, toKek, toKekFp);
        db.prepare('UPDATE "' + c.table + '" SET "' + c.column + '" = ? WHERE rowid = ?').run(next, rows[j].rid);
        resealed++;
      }
    }
    // Now that every replicated value is under the own KEK, drop the shared-KEK wrapper.
    tier1Kek.clearSharedKek(db);
    return resealed;
  });

  const resealed = run();
  return { resealed: resealed, columns: REPLICATED.length };
}

module.exports = {
  REPLICATED_COLUMNS: REPLICATED,
  rekeyNode,
};

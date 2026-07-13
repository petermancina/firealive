// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Tier-1 Import Rekey (FA-MIG1)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// Re-seal every Tier-1 column of a freshly imported deployment from the SOURCE KEK
// (recovered transiently from the source recovery code) to THIS target's own KEK.
// This is the cross-KEK import path (D-R2-1/2/3): the online /import/apply handles
// only same-KEK imports and refuses a foreign-KEK bundle at the restore gate; the
// offline CLI orchestrates unwrap-with-source-KEK -> restore -> importRekey, and
// this module does the final re-seal on the restored, live database.
//
// The mirror of B-4 rekeyNode, with three differences: the source KEK comes from a
// recovery code (not an adopted shared KEK), EVERY Tier-1 column is re-sealed (an
// imported DB has both node-local and replicated columns under the source KEK, not
// just the replicated ones), and there is no shared-KEK wrapper to shed.
//
//   ATOMIC       -- consume-KOA + re-seal every Tier-1 value run in ONE db
//                   transaction. Any failure rolls the whole thing back: the KOA
//                   stays unconsumed and no value is left half-rekeyed.
//   FAIL-CLOSED  -- resealValue throws if a value will not open under the source KEK
//                   (wrong recovery code / passphrase / tamper). Inside the
//                   transaction that aborts everything.
//   FORWARD-ONLY -- re-seals ONLY the live Tier-1 columns of the restored DB
//                   (D-R2-7). Imported backup/bundle artifacts stay under the
//                   source KEK; keep the source recovery code to read them.
//   SCRUBBED     -- the recovered source KEK is zeroed as soon as the work ends,
//                   whatever the outcome. It never persists and never lingers.

const { TIER1_COLUMNS } = require('./tier1-columns');
const tier1Kek = require('./tier1-kek');
const tier1Seal = require('./tier1-seal');
const koa = require('./key-op-authorization');

// Every class='tier1' column -- node-local AND replicated. An imported DB has all of
// them sealed under the source's Tier-1 KEK.
const TIER1 = TIER1_COLUMNS.filter((c) => c.class === 'tier1');

function fail(code, message) {
  const e = new Error('import-rekey: ' + message);
  e.code = code;
  throw e;
}

// Re-seal an imported deployment's Tier-1 columns from the source KEK to this node's own KEK.
// args:
//   koaId               id of an approved, minted, unconsumed KOA with op='migration-import'
//   sourceRecoveryCode  the source deployment's Tier-1 recovery code (fa-tier1-recovery:v1:...)
//   sourcePassphrase    the passphrase that unlocks that recovery code
// Returns { resealed, columns }.
function importRekey(db, args) {
  args = args || {};
  const koaId = args.koaId;
  const recoveryCode = args.sourceRecoveryCode;
  const passphrase = args.sourcePassphrase;
  if (typeof koaId !== 'string' || koaId === '') fail('INVALID_INPUT', 'koaId is required');
  if (typeof recoveryCode !== 'string' || recoveryCode === '') fail('INVALID_INPUT', 'sourceRecoveryCode is required');
  if (typeof passphrase !== 'string' || passphrase === '') fail('INVALID_INPUT', 'sourcePassphrase is required');

  // 1. Verify the authorization BEFORE touching any data or recovering any key.
  const koaRow = koa.getKoa(db, koaId);
  if (!koaRow) fail('NO_KOA', 'unknown KOA id ' + koaId);
  if (koaRow.op !== 'migration-import') {
    fail('WRONG_OP', 'KOA op is "' + koaRow.op + '", expected "migration-import"');
  }
  const anchorPem = koa.anchorPublicPem(db);
  if (!anchorPem) fail('NO_ANCHOR', 'this node has no anchor public key to verify the KOA against');
  const verdict = koa.verifyKoa(koaRow, anchorPem);
  if (!verdict.valid) fail('KOA_INVALID', 'authorization is not valid (' + verdict.reason + ')');

  // 2. Recover the SOURCE KEK transiently from the recovery code. Everything after this point is
  //    wrapped so the key is scrubbed in the finally, no matter how we leave.
  let fromKek;
  try {
    fromKek = tier1Kek.recoverKekFromCode(recoveryCode, passphrase);
  } catch (err) {
    fail('RECOVERY_FAILED', 'could not recover the source KEK from the recovery code: ' + err.message);
  }

  try {
    const toKek = tier1Kek.ownKek();
    const fromKekFp = tier1Kek.kekFingerprint(fromKek);
    const toKekFp = tier1Kek.ownKekFingerprint();
    if (Buffer.compare(fromKek, toKek) === 0) {
      fail('NOTHING_TO_REKEY', 'the source and target KEK are identical (use the online apply for a same-KEK import)');
    }

    // 3. One atomic transaction: consume the KOA, re-seal every Tier-1 value source -> own.
    const run = db.transaction(() => {
      if (!koa.consumeKoa(db, koaId, 'import-rekey')) {
        fail('KOA_NOT_CONSUMABLE', 'the authorization is not consumable (already used, or vanished)');
      }
      let resealed = 0;
      for (let i = 0; i < TIER1.length; i++) {
        const c = TIER1[i];
        const ref = c.table + '.' + c.column;
        let rows;
        try {
          rows = db.prepare(
            'SELECT rowid AS rid, "' + c.column + '" AS val FROM "' + c.table + '" WHERE "' + c.column + '" IS NOT NULL'
          ).all();
        } catch (queryErr) {
          // Table not present on this deployment (feature never configured); nothing sealed there.
          continue;
        }
        for (let j = 0; j < rows.length; j++) {
          // Fail-closed: resealValue throws if the value will not open under the source KEK.
          // Being inside the transaction, that rolls back the consume and every prior update.
          const next = tier1Seal.resealValue(ref, rows[j].val, fromKek, fromKekFp, toKek, toKekFp);
          db.prepare('UPDATE "' + c.table + '" SET "' + c.column + '" = ? WHERE rowid = ?').run(next, rows[j].rid);
          resealed++;
        }
      }
      return resealed;
    });

    const resealed = run();
    return { resealed: resealed, columns: TIER1.length };
  } finally {
    if (Buffer.isBuffer(fromKek)) fromKek.fill(0);
  }
}

module.exports = {
  TIER1_COLUMNS: TIER1,
  importRekey,
};

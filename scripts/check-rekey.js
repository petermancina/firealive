#!/usr/bin/env node
'use strict';

// check-rekey.js -- regression for the B6h B-4 offline node rekey.
//
// Uses the REAL tier1-seal / tier1-rekey modules (only the KEKs, the KOA, and the DB are
// stubbed) so the re-seal crypto is genuinely exercised. Covers both servers:
//   - resealValue round-trips a value shared-KEK -> own-KEK and fails closed on the wrong key
//   - rekeyNode consumes the KOA + re-seals every replicated column + clearSharedKek (happy)
//   - ATOMIC: a value that will not open mid-rekey rolls back -- KOA still consumable, wrapper
//     intact, nothing re-sealed
//   - FORWARD-ONLY: a non-Tier-1 "backup" row is never touched
//   - source: the rekey modules + CLIs exist, and the A-10 unpair guard still refuses while
//     node_state.shared_kek_sealed exists

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Module = require('module');

const REPO = path.resolve(__dirname, '..');
const problems = [];
const check = (name, cond) => { if (!cond) problems.push(name); };

const keyA = Buffer.alloc(32, 0xAA); // adopted shared KEK
const keyB = Buffer.alloc(32, 0xBB); // this node's own KEK
const fpOf = (k) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from('fa-tier1-kekfp:v1'), k])).digest().subarray(0, 8);
const fpA = fpOf(keyA), fpB = fpOf(keyB);

const kek = { shared: keyA, sharedFp: fpA, cleared: false }; // mutable KEK state the stub reads
const koaCfg = { op: 'rekey', valid: true };                 // KOA config (not transaction state)

function suite(label, sealModRel, rekeyModRel, kekModName, koaModName, repRef) {
  kek.shared = keyA; kek.sharedFp = fpA; kek.cleared = false; koaCfg.op = 'rekey'; koaCfg.valid = true;
  let state; // the transaction-managed mock DB state (rows, backups, koaConsumed)

  const orig = Module._load;
  Module._load = function (r) {
    if (typeof r === 'string' && r.indexOf('hardware-keystore') !== -1) return { sealKey: (k) => k, unsealKey: (b) => b };
    if (r === 'tweetnacl') return { box: {}, sign: {}, randomBytes: (n) => Buffer.alloc(n), secretbox: Object.assign((m) => m, { open: (m) => m, nonceLength: 24, keyLength: 32, overheadLength: 16 }) };
    if (r === 'tweetnacl-util') return { decodeBase64: (s) => Buffer.from(s, 'base64'), encodeBase64: (b) => Buffer.from(b).toString('base64'), decodeUTF8: (s) => Buffer.from(s), encodeUTF8: (b) => Buffer.from(b).toString() };
    if (r === kekModName) return {
      ownKek: () => keyB, sharedKek: () => kek.shared,
      ownKekFingerprint: () => fpB, sharedKekFingerprint: () => kek.sharedFp,
      clearSharedKek: () => { kek.cleared = true; },
    };
    if (r === koaModName) return {
      getKoa: (db, id) => id === 'koa-x' ? { id: 'koa-x', op: koaCfg.op, signature: 'sig' } : null,
      anchorPublicPem: () => 'PEM',
      verifyKoa: () => koaCfg.valid ? { valid: true } : { valid: false, reason: 'bad' },
      consumeKoa: () => { if (state.koaConsumed) return false; state.koaConsumed = true; return true; },
    };
    return orig.apply(this, arguments);
  };

  let seal, rekey;
  try {
    delete require.cache[require.resolve(path.join(REPO, sealModRel))];
    delete require.cache[require.resolve(path.join(REPO, rekeyModRel))];
    seal = require(path.join(REPO, sealModRel));
    rekey = require(path.join(REPO, rekeyModRel));

    // --- resealValue round-trip (real crypto) ---
    const storedA = seal.sealTier1(repRef, 'secret-' + label);
    const storedB = seal.resealValue(repRef, storedA, keyA, fpA, keyB, fpB);
    kek.shared = keyB; kek.sharedFp = fpB;
    check(label + ' resealValue: opens under own KEK after rekey', seal.openTier1(repRef, storedB) === 'secret-' + label);
    let threw = false; try { seal.openTier1(repRef, storedA); } catch (e) { threw = true; }
    check(label + ' resealValue: old shared-KEK value no longer opens under own KEK', threw);
    kek.shared = keyA; kek.sharedFp = fpA;
    threw = false; try { seal.resealValue(repRef, storedB, keyA, fpA, keyB, fpB); } catch (e) { threw = true; }
    check(label + ' resealValue: fails closed on wrong fromKek', threw);

    // --- rekeyNode over a mock db ---
    const repCol = rekey.REPLICATED_COLUMNS[0];
    const ref0 = repCol.table + '.' + repCol.column;
    function freshDb(withBad) {
      const rows = {}; rows[repCol.table] = [{ rid: 1, [repCol.column]: seal.sealTier1(ref0, 'live-secret') }];
      if (withBad) rows[repCol.table].push({ rid: 2, [repCol.column]: 'not-a-valid-envelope' });
      state = { rows: rows, backups: [{ id: 'b1', blob: 'OLD-KEK-BACKUP' }], koaConsumed: false };
      kek.shared = keyA; kek.sharedFp = fpA; kek.cleared = false;
    }
    const db = {
      prepare(sql) {
        return {
          all: () => { const t = (sql.match(/FROM "(\w+)"/) || [])[1]; const col = (sql.match(/"(\w+)" AS val/) || [])[1]; if (!state.rows[t]) throw new Error('no such table'); return state.rows[t].filter(x => x[col] != null).map(x => ({ rid: x.rid, val: x[col] })); },
          run: (val, rid) => { const t = (sql.match(/UPDATE "(\w+)"/) || [])[1]; const col = (sql.match(/SET "(\w+)"/) || [])[1]; const row = state.rows[t].find(x => x.rid === rid); if (row) row[col] = val; },
          get: () => undefined,
        };
      },
      transaction(fn) { return function () { const snap = JSON.stringify(state); try { return fn(); } catch (e) { state = JSON.parse(snap); throw e; } }; },
    };

    freshDb(false);
    const res = rekey.rekeyNode(db, { koaId: 'koa-x' });
    check(label + ' rekeyNode: re-sealed the live row', res.resealed >= 1);
    check(label + ' rekeyNode: consumed the KOA', state.koaConsumed === true);
    check(label + ' rekeyNode: shed the shared KEK', kek.cleared === true);
    check(label + ' rekeyNode: forward-only -- backup row untouched', state.backups[0].blob === 'OLD-KEK-BACKUP');
    kek.shared = keyB; kek.sharedFp = fpB;
    check(label + ' rekeyNode: live value now opens under own KEK', seal.openTier1(ref0, state.rows[repCol.table][0][repCol.column]) === 'live-secret');
    kek.shared = keyA; kek.sharedFp = fpA;

    freshDb(true);
    let rb = false; try { rekey.rekeyNode(db, { koaId: 'koa-x' }); } catch (e) { rb = true; }
    check(label + ' rekeyNode: throws on an unopenable value', rb);
    check(label + ' rekeyNode: rollback -- KOA still consumable', state.koaConsumed === false);
    check(label + ' rekeyNode: rollback -- shared KEK NOT shed', kek.cleared === false);
  } catch (e) {
    problems.push(label + ' suite error: ' + e.message);
  } finally {
    Module._load = orig;
  }
}

suite('MC', 'server/services/tier1-seal.js', 'server/services/tier1-rekey.js', './tier1-kek', './key-op-authorization', 'storage_destinations.credentials_encrypted');
suite('GD', 'packages/global-dashboard-server/services/gd-tier1-seal.js', 'packages/global-dashboard-server/services/gd-tier1-rekey.js', './gd-tier1-kek', './gd-key-op-authorization', 'storage_destinations.credentials_encrypted');

const exists = (p) => fs.existsSync(path.join(REPO, p));
check('MC rekey service present', exists('server/services/tier1-rekey.js'));
check('GD rekey service present', exists('packages/global-dashboard-server/services/gd-tier1-rekey.js'));
check('MC rekey CLI present', exists('server/tools/rekey-node.js'));
check('GD rekey CLI present', exists('packages/global-dashboard-server/tools/gd-rekey-node.js'));
const haPairing = (() => { try { return fs.readFileSync(path.join(REPO, 'server/services/ha/ha-pairing.js'), 'utf8'); } catch (e) { return ''; } })();
check('A-10 unpair guard still refuses while shared_kek_sealed exists', /shared_kek_sealed/.test(haPairing) && /unpair refused/i.test(haPairing));

if (problems.length) {
  console.error('rekey regression FAILED:');
  for (let i = 0; i < problems.length; i++) console.error('  - ' + problems[i]);
  process.exit(1);
}
console.log('rekey regression passed: resealValue round-trip + fail-closed, rekeyNode consume+reseal+shed, atomic rollback, forward-only, and guarded surfaces (both servers).');

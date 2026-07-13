#!/usr/bin/env node
'use strict';

// check-import-rekey.js -- regression for B6h B-6 (FA-MIG1 rekey-on-import).
//
//   - the backup manifest's salted KEK fingerprint is non-correlatable and verifies (match /
//     mismatch / null-for-legacy) -- MC + GD
//   - the raw-KEK DEK unwrap round-trips through the env-var provider and the dispatcher, and the
//     dispatcher rejects non-env-var schemes (cloud KEKs stay in the HSM)
//   - importRekey validates its KOA (op='migration-import'), recovers + scrubs the source KEK, and
//     re-seals EVERY class='tier1' column (node-local AND replicated), excluding tier1-derived --
//     MC + GD
//   - the restore accepts rawKek and SKIPS the same-KEK gate on that path -- MC + GD
//   - the offline CLI orchestrates recover -> restore(rawKek) -> importRekey -> scrub -- MC + GD

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Module = require('module');

const REPO = path.resolve(__dirname, '..');
const problems = [];
const check = (name, cond) => { if (!cond) problems.push(name); };
const read = (rel) => { try { return fs.readFileSync(path.join(REPO, rel), 'utf8'); } catch (e) { return ''; } };

function withStubs(map, fn) {
  const orig = Module._load;
  Module._load = function (r) { if (map[r]) return map[r](); return orig.apply(this, arguments); };
  try { return fn(); } finally { Module._load = orig; }
}
const naclStubs = {
  'hardware-keystore': () => ({ sealKey: (k) => k, unsealKey: (b) => b }),
  tweetnacl: () => ({ box: {}, sign: {}, randomBytes: (n) => Buffer.alloc(n), secretbox: Object.assign((m) => m, { open: (m) => m, nonceLength: 24, keyLength: 32, overheadLength: 16 }) }),
  'tweetnacl-util': () => ({ decodeBase64: (s) => Buffer.from(s, 'base64'), encodeBase64: (b) => Buffer.from(b).toString('base64'), decodeUTF8: (s) => Buffer.from(s), encodeUTF8: (b) => Buffer.from(b).toString() }),
};
function hwStub(r) { return typeof r === 'string' && r.indexOf('hardware-keystore') !== -1; }

// ---- Section A: manifest fingerprint (MC + GD) ----
['server/services/backup-manifest.js', 'packages/global-dashboard-server/services/gd-backup-manifest.js'].forEach(function (rel) {
  const tag = rel.indexOf('gd-') !== -1 ? 'GD' : 'MC';
  const bm = require(path.join(REPO, rel));
  const fp = 'aabbccdd11223344';
  const f1 = bm.saltedKekFingerprint(fp, 'backup-1');
  const f2 = bm.saltedKekFingerprint(fp, 'backup-2');
  check(tag + ' salted fp is 64 hex', /^[0-9a-f]{64}$/.test(f1));
  check(tag + ' fp non-correlatable across backups', f1 !== f2);
  const m = { backup_id: 'backup-1', kek_fingerprint: f1 };
  check(tag + ' verifyKekFingerprint match', bm.verifyKekFingerprint(m, fp) === true);
  check(tag + ' verifyKekFingerprint mismatch', bm.verifyKekFingerprint(m, '9999888877776666') === false);
  check(tag + ' verifyKekFingerprint null for legacy', bm.verifyKekFingerprint({ backup_id: 'x' }, fp) === null);
});

// ---- Section B: raw-KEK unwrap (MC env-var provider + dispatcher) ----
withStubs(naclStubs, function () {
  const RAW = 'ab'.repeat(32); process.env.CHK_KEK = RAW;
  const envProv = require(path.join(REPO, 'server/services/key-wrapping-providers/env-var.js'));
  const kw = require(path.join(REPO, 'server/services/backup-key-wrapping.js'));
  return envProv.wrap(crypto.randomBytes(32), { env_var_name: 'CHK_KEK' }, null, {}).then(function () {}).catch(function () {});
});
// synchronous portion (wrap is async; do a sync round-trip via the provider directly)
withStubs(naclStubs, function () {
  const RAW = Buffer.from('cd'.repeat(32), 'hex'); process.env.CHK_KEK2 = 'cd'.repeat(32);
  const envProv = require(path.join(REPO, 'server/services/key-wrapping-providers/env-var.js'));
  const kw = require(path.join(REPO, 'server/services/backup-key-wrapping.js'));
  // craft a wrapped DEK by encrypting with the same GCM the provider uses
  const dek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', RAW, iv);
  const ct = Buffer.concat([c.update(dek), c.final()]);
  const wrapped = Buffer.concat([iv, c.getAuthTag(), ct]);
  check('MC provider raw-KEK unwrap recovers the DEK', Buffer.compare(envProv.unwrapWithRawKek(wrapped, RAW), dek) === 0);
  check('MC dispatcher raw-KEK unwrap recovers the DEK', Buffer.compare(kw.unwrapKeyWithRawKek(wrapped, 'env-var', RAW), dek) === 0);
  check('MC dispatcher rejects a cloud scheme', (function () { try { kw.unwrapKeyWithRawKek(wrapped, 'aws-kms', RAW); return false; } catch (e) { return /only supported for the env-var/.test(e.message); } })());
});

// ---- Section C: importRekey (MC + GD) ----
function importRekeySuite(tag, rel, colMod, kekMod, sealMod, koaMod) {
  const SRC = Buffer.alloc(32, 0x11); const TGT = Buffer.alloc(32, 0x22); let scrubbed = false;
  const stub = {};
  stub[colMod] = () => { const cols = [
    { table: 'ca_authority', column: 'ca_private_key_encrypted', domain: 'replicated', class: 'tier1', storage: 'buffer' },
    { table: 'id_tbl', column: 'signing_key_encrypted', domain: 'node-local', class: 'tier1', storage: 'buffer' },
    { table: 'derived_tbl', column: 'v', domain: 'node-local', class: 'tier1-derived', storage: 'buffer' },
  ]; return { TIER1_COLUMNS: cols, GD_TIER1_COLUMNS: cols }; };
  stub[kekMod] = () => ({
    recoverKekFromCode: (code) => { if (code === 'bad') throw new Error('bad'); const b = Buffer.from(SRC); const of = b.fill.bind(b); b.fill = (v) => { scrubbed = true; return of(v); }; return b; },
    ownKek: () => TGT, kekFingerprint: (k) => k.equals(SRC) ? 'srcfp' : 'tgtfp', ownKekFingerprint: () => 'tgtfp',
  });
  stub[sealMod] = () => ({ resealValue: (ref, val, fk, ffp, tk, tfp) => { if (ffp !== 'srcfp' || tfp !== 'tgtfp') throw new Error('fp'); return 'RES:' + String(val); } });
  stub[koaMod] = () => ({ getKoa: (db, id) => id === 'good' ? { op: 'migration-import' } : (id === 'wrongop' ? { op: 'rekey' } : null), anchorPublicPem: () => 'PEM', verifyKoa: () => ({ valid: true }), consumeKoa: () => true });
  withStubs(stub, function () {
    delete require.cache[require.resolve(path.join(REPO, rel))];
    const ir = require(path.join(REPO, rel));
    const args = { koaId: 'good', sourceRecoveryCode: 'fa-tier1-recovery:v1:z', sourcePassphrase: 'pw' };
    function mkDb(store) { return { transaction: (fn) => () => fn(),
      prepare(sql) {
        if (/^SELECT/.test(sql)) { const t = (sql.match(/FROM "(\w+)"/) || [])[1]; return { all: () => (store[t] || []).map((v, i) => ({ rid: i + 1, val: v })) }; }
        if (/^UPDATE/.test(sql)) { const ut = (sql.match(/UPDATE "(\w+)"/) || [])[1]; return { run: (val, rid) => { store[ut][rid - 1] = val; } }; }
        return { run: () => {}, all: () => [] };
      } }; }
    check(tag + ' importRekey rejects wrong KOA op', (function () { try { ir.importRekey(mkDb({}), Object.assign({}, args, { koaId: 'wrongop' })); return false; } catch (e) { return e.code === 'WRONG_OP'; } })());
    check(tag + ' importRekey rejects a bad recovery code', (function () { try { ir.importRekey(mkDb({}), Object.assign({}, args, { sourceRecoveryCode: 'bad' })); return false; } catch (e) { return e.code === 'RECOVERY_FAILED'; } })());
    const store = { ca_authority: ['A1', 'A2'], id_tbl: ['S1'], derived_tbl: ['M1'] };
    const res = ir.importRekey(mkDb(store), args);
    check(tag + ' importRekey re-seals all tier1 (node-local + replicated)', res.resealed === 3 && res.columns === 2);
    check(tag + ' importRekey leaves tier1-derived untouched', store.derived_tbl[0] === 'M1');
    check(tag + ' importRekey scrubs the source KEK', scrubbed === true);
  });
}
importRekeySuite('MC', 'server/services/tier1-import-rekey.js', './tier1-columns', './tier1-kek', './tier1-seal', './key-op-authorization');
importRekeySuite('GD', 'packages/global-dashboard-server/services/gd-tier1-import-rekey.js', './gd-tier1-columns', './gd-tier1-kek', './gd-tier1-seal', './gd-key-op-authorization');

// ---- Section D: restore gate-skip + CLI orchestration (source checks, both servers) ----
[['MC', 'server/services/db-restore-swap.js'], ['GD', 'packages/global-dashboard-server/services/gd-db-restore-swap.js']].forEach(function (p) {
  const src = read(p[1]);
  check(p[0] + ' restore accepts rawKek', /options\.rawKek/.test(src));
  check(p[0] + ' restore uses unwrapKeyWithRawKek', /unwrapKeyWithRawKek/.test(src));
  check(p[0] + ' restore skips the gate when rawKek supplied', /options\.manifest && !rawKek/.test(src));
});
[['MC', 'server/tools/import-rekey.js'], ['GD', 'packages/global-dashboard-server/tools/gd-import-rekey.js']].forEach(function (p) {
  const src = read(p[1]);
  check(p[0] + ' CLI recovers the source KEK', /recoverKekFromCode/.test(src));
  check(p[0] + ' CLI restores with rawKek', /rawKek: sourceKek/.test(src));
  check(p[0] + ' CLI calls importRekey', /importRekey\(/.test(src));
  check(p[0] + ' CLI scrubs the source KEK', /sourceKek\.fill\(0\)/.test(src));
});

if (problems.length) {
  console.error('import-rekey regression FAILED:');
  for (let i = 0; i < problems.length; i++) console.error('  - ' + problems[i]);
  process.exit(1);
}
console.log('import-rekey regression passed: manifest fingerprint (non-correlatable, verify match/mismatch/null), raw-KEK unwrap round-trip + cloud rejected, importRekey (all tier1, tier1-derived excluded, KOA + recovery validation, scrub), restore gate-skip, and CLI orchestration -- both servers.');

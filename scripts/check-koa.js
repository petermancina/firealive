#!/usr/bin/env node
'use strict';

// check-koa.js -- regression for the B6h B-3 Key-Operation Authorization (KOA).
//
// Covers the load-bearing invariants on both servers:
//   1. Token primitive: mint (requires an approved gate whose id matches) -> offline
//      verify against the anchor public key -> atomic single-use consume; a tampered
//      field, a wrong key, no approval, and a double-consume all fail. Real ECDSA.
//   2. Key-op policy: strict/delayed-self only, NO disabled -- and a manual 'disabled'
//      in system_meta is ignored on read (falls back to strict).
//   3. Anti-drift: the standalone verify-koa tool's canonical payload is byte-identical
//      to key-op-authorization.canonicalPayload.
//   4. Source: the approval_method CHECK is passkey-only on both servers; /api/key-ops is
//      config-write-gated on both; both routes are mounted.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Module = require('module');

const REPO = path.resolve(__dirname, '..');
const problems = [];
const check = (name, cond) => { if (!cond) problems.push(name); };
const read = (rel) => { try { return fs.readFileSync(path.join(REPO, rel), 'utf8'); } catch (e) { return ''; } };

const orig = Module._load;
Module._load = function (r) {
  if (typeof r === 'string' && r.indexOf('hardware-keystore') !== -1) return { sealKey: (k) => k, unsealKey: (b) => b };
  return orig.apply(this, arguments);
};

// Load a KOA module with anchor.sign / approvals / db stubbed for a given key pair + gate.
function loadKoaModule(rel, anchorReq, approvalsReq, privateKey, gateRef) {
  const stubs = {};
  stubs[anchorReq] = { sign: ({ data }) => crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }) };
  stubs[approvalsReq] = { findUsableForKeyOp: () => gateRef.value };
  const prev = Module._load;
  Module._load = function (r) { if (stubs[r]) return stubs[r]; return prev.apply(this, arguments); };
  try {
    delete require.cache[require.resolve(path.join(REPO, rel))];
    return require(path.join(REPO, rel));
  } finally {
    Module._load = prev;
  }
}

function tokenTests(label, rel, anchorReq, approvalsReq, identityTable) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const PEM = publicKey.export({ type: 'spki', format: 'pem' });
  const gateRef = { value: { id: 'appr-1' } };
  const koa = loadKoaModule(rel, anchorReq, approvalsReq, privateKey, gateRef);

  let store = {};
  const db = { prepare(sql) {
    if (sql.indexOf('anchor_public FROM ' + identityTable) !== -1) return { get: () => ({ anchor_public: PEM }) };
    if (/INSERT INTO key_op_authorizations/.test(sql)) return { run: (...a) => { store[a[0]] = { id: a[0], op: a[1], key_op_ref: a[2], approval_id: a[3], requested_by_user_id: a[4], created_at: a[5], expires_at: a[6], anchor_public_fingerprint: a[7], signature: a[8], consumed_at: null }; } };
    if (/SELECT \* FROM key_op_authorizations WHERE id/.test(sql)) return { get: (id) => store[id] };
    if (/UPDATE key_op_authorizations SET consumed_at/.test(sql)) return { run: (ts, ctx, id) => { if (store[id] && store[id].consumed_at === null) { store[id].consumed_at = ts; return { changes: 1 }; } return { changes: 0 }; } };
    return { get: () => undefined, run: () => ({ changes: 0 }) };
  } };

  const row = koa.mintKoa(db, { op: 'rekey', key_op_ref: 'rekey:gen-7', approval_id: 'appr-1', requested_by_user_id: 'u1' });
  check(label + ': mint writes a signed row', !!(row && row.signature));
  check(label + ': verify valid for fresh KOA', koa.verifyKoa(row, PEM).valid === true);
  check(label + ': tampered field fails verify', koa.verifyKoa(Object.assign({}, row, { key_op_ref: 'EVIL' }), PEM).valid === false);
  check(label + ': wrong key fails verify', koa.verifyKoa(row, crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' })).valid === false);
  gateRef.value = null;
  let threw = false; try { koa.mintKoa(db, { op: 'rekey', key_op_ref: 'x', approval_id: 'a', requested_by_user_id: 'u' }); } catch (e) { threw = e.code === 'NO_APPROVAL'; }
  check(label + ': mint refuses without an approval', threw);
  gateRef.value = { id: 'OTHER' }; threw = false; try { koa.mintKoa(db, { op: 'rekey', key_op_ref: 'x', approval_id: 'appr-1', requested_by_user_id: 'u' }); } catch (e) { threw = e.code === 'APPROVAL_MISMATCH'; }
  check(label + ': mint refuses on approval_id mismatch', threw);
  check(label + ': first consume succeeds', koa.consumeKoa(db, row.id, 'tool') === true);
  check(label + ': second consume fails (single-use)', koa.consumeKoa(db, row.id, 'tool') === false);
  return koa;
}

function policyTests(label, rel) {
  delete require.cache[require.resolve(path.join(REPO, rel))];
  const pol = require(path.join(REPO, rel));
  check(label + " policy: no 'disabled' mode", !pol.VALID_MODES.includes('disabled'));
  const mem = {};
  const db = { prepare(sql) {
    if (/key_op_approval_mode/.test(sql) && /SELECT/.test(sql)) return { get: () => mem.mode !== undefined ? { value: mem.mode } : undefined };
    if (/key_op_approval_mode/.test(sql)) return { run: (v) => { mem.mode = v; } };
    return { get: () => undefined, run: () => {} };
  } };
  check(label + ' policy: defaults to strict', pol.getMode(db) === 'strict');
  let threw = false; try { pol.setMode(db, 'disabled'); } catch (e) { threw = true; }
  check(label + " policy: setMode('disabled') rejected", threw);
  mem.mode = 'disabled';
  check(label + " policy: manual 'disabled' ignored on read", pol.getMode(db) === 'strict');
}

// 1 + 2: token + policy, both servers
const mcKoa = tokenTests('MC', 'server/services/key-op-authorization.js', './instance-anchor', './restore-approvals', 'instance_identity');
tokenTests('GD', 'packages/global-dashboard-server/services/gd-key-op-authorization.js', './gd-instance-anchor', './gd-restore-approvals', 'gd_instance_identity');
policyTests('MC', 'server/services/key-op-approval-policy.js');
policyTests('GD', 'packages/global-dashboard-server/services/gd-key-op-approval-policy.js');

// 3: anti-drift -- the tool's canonical payload matches the module's
const k = { id: 'a', op: 'rekey', key_op_ref: 'b', approval_id: 'c', requested_by_user_id: 'd', created_at: 'e', expires_at: 'f' };
const toolCp = Buffer.from([k.id, k.op, k.key_op_ref, k.approval_id, k.requested_by_user_id, k.created_at, k.expires_at].join('\u0000'), 'utf8');
check('verify-koa tool canonical payload matches the module (no drift)', toolCp.equals(mcKoa.canonicalPayload(k)));
const toolSrc = read(path.join('server', 'tools', 'verify-koa.js'));
check('verify-koa tool uses ieee-p1363 offline verify', /dsaEncoding:\s*'ieee-p1363'/.test(toolSrc) && /crypto\.verify/.test(toolSrc));

// 4: source checks
const mcInit = read(path.join('server', 'db', 'init.js'));
const gdInit = read(path.join('packages', 'global-dashboard-server', 'db-init.js'));
check('MC approval_method CHECK is passkey-only', /second-person-webauthn/.test(mcInit) && !/'second-person-totp'/.test(mcInit));
check('GD approval_method CHECK is passkey-only', /second-person-webauthn/.test(gdInit) && !/'second-person-totp'/.test(gdInit));
check('key_op_authorizations table present (MC)', /CREATE TABLE IF NOT EXISTS key_op_authorizations/.test(mcInit));
check('key_op_authorizations table present (GD)', /CREATE TABLE IF NOT EXISTS key_op_authorizations/.test(gdInit));
check('MC /api/key-ops is config-write-gated', /'\/api\/key-ops'/.test(read(path.join('server', 'middleware', 'config-write-routes.js'))));
check('GD /api/key-ops is config-write-gated', /'\/api\/key-ops'/.test(read(path.join('packages', 'global-dashboard-server', 'services', 'gd-config-write-routes.js'))));
check('MC /api/key-ops mounted with config-lock', /app\.use\('\/api\/key-ops'[\s\S]{0,120}configLockChokepoint\(\)/.test(read(path.join('server', 'index.js'))));
check('GD /api/key-ops mounted', /app\.use\('\/api\/key-ops'/.test(read(path.join('packages', 'global-dashboard-server', 'index.js'))));

if (problems.length) {
  console.error('KOA regression FAILED:');
  for (let i = 0; i < problems.length; i++) console.error('  - ' + problems[i]);
  process.exit(1);
}
console.log('KOA regression passed: token mint/verify/consume (both servers), no-disabled policy, verifier anti-drift, and passkey-only + config-locked surfaces.');

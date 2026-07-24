'use strict';

// FIREALIVE -- Key-Operation Authorization (KOA) token primitive (B6h B-3)
//
// A KOA is an anchor-signed, single-use token authorizing ONE destructive key
// operation (a rekey, a migration-import re-seal, a deployment reset). It is the
// thing the offline rekey tool (B-4) checks before it re-seals data.
//
// Trust chain, no weak link:
//   1. A two-person approval (restore-approvals, key_op_ref target) must be
//      APPROVED first -- mintKoa refuses without a usable gate, and the approval
//      row's id must match.
//   2. The running server, which alone holds the hardware anchor, SIGNS the
//      canonical payload with instance-anchor (ECDSA P-256). A copied disk cannot
//      sign, so it cannot mint a KOA.
//   3. The offline tool VERIFIES the signature against instance_identity.
//      anchor_public alone -- no hardware, no running server, no network -- so an
//      air-gapped operator can confirm authenticity, then consumes it in the same
//      transaction as the operation (single-use).
//
// The signature covers a CANONICAL payload with a fixed field order, NUL-joined,
// so it is independent of JSON key order/whitespace and none of the fields (op,
// target, the approval it rode in on, requester, validity window) can be altered.

const crypto = require('crypto');
const anchor = require('./instance-anchor');
const approvals = require('./restore-approvals');

const VALID_OPS = ['rekey', 'migration-import', 'deployment-reset', 'rollback'];
const DEFAULT_TTL_MS = 60 * 60 * 1000; // 1 hour to carry a fresh KOA to the offline tool
const MAX_TTL_MS = 24 * 60 * 60 * 1000; // 24h ceiling

// B6k: 'rollback' carries its OWN ceiling, and only that op is affected.
//
// Every other op is minted and consumed in one sitting -- an operator authorizes
// a rekey and runs the tool -- so 24h is generous. A rollback authorization has a
// different shape: it may be minted BEFORE an upgrade, as a contingency, while
// the deployment is still healthy and can authenticate. If the new build then
// fails to boot, nothing can be minted afterwards, which is precisely the case
// the contingency exists for. A 24h ceiling would mean the authorization expired
// before the operator discovered they needed it.
//
// The longer window is bounded by everything else about the token rather than by
// time: it authorizes ONE restore point (key_op_ref), on one host (anchor
// signature), once (consumed_at), and the offline tool additionally refuses
// unless the bundle's fuse is exactly one below the current mark -- so a further
// upgrade VOIDS any outstanding rollback authorization without anyone revoking it.
const ROLLBACK_MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function maxTtlFor(op) {
  return op === 'rollback' ? ROLLBACK_MAX_TTL_MS : MAX_TTL_MS;
}

function nowIso() { return new Date().toISOString(); }
function requireNonEmpty(v, name) {
  if (typeof v !== 'string' || v === '') { const e = new Error('key-op-authorization: ' + name + ' required'); e.code = 'INVALID_INPUT'; throw e; }
}

// The exact bytes the anchor signs and the offline tool re-derives. Fixed order.
function canonicalPayload(koa) {
  return Buffer.from([
    koa.id, koa.op, koa.key_op_ref, koa.approval_id,
    koa.requested_by_user_id, koa.created_at, koa.expires_at,
  ].join('\u0000'), 'utf8');
}

function getKoa(db, id) {
  return db.prepare('SELECT * FROM key_op_authorizations WHERE id = ?').get(id);
}

// The instance's anchor public key (PEM SPKI) -- what verifyKoa checks against.
function anchorPublicPem(db) {
  const row = db.prepare('SELECT anchor_public FROM instance_identity ORDER BY id LIMIT 1').get();
  return row ? row.anchor_public : null;
}

// A short fingerprint of anchor_public, stored on the row so an operator can tell
// at a glance which instance minted a KOA (defense in depth; the signature is the
// real check).
function anchorPublicFingerprint(db) {
  const pem = anchorPublicPem(db);
  if (!pem) return null;
  return crypto.createHash('sha256').update(pem).digest('hex').slice(0, 32);
}

// Mint a KOA. Requires an APPROVED two-person gate for this key operation, and the
// gate's id must match args.approval_id. Signs the canonical payload with the
// instance anchor and writes the single-use row. Returns the stored row.
function mintKoa(db, args) {
  if (!args || typeof args !== 'object') { const e = new Error('key-op-authorization: args required'); e.code = 'INVALID_INPUT'; throw e; }
  requireNonEmpty(args.op, 'op');
  if (!VALID_OPS.includes(args.op)) { const e = new Error('key-op-authorization: op must be one of ' + VALID_OPS.join(', ')); e.code = 'INVALID_INPUT'; throw e; }
  requireNonEmpty(args.key_op_ref, 'key_op_ref');
  requireNonEmpty(args.approval_id, 'approval_id');
  requireNonEmpty(args.requested_by_user_id, 'requested_by_user_id');

  // The two-person gate MUST be approved and usable, and it must be the one named.
  const gate = approvals.findUsableForKeyOp(db, {
    key_op_ref: args.key_op_ref,
    requested_by_user_id: args.requested_by_user_id,
  });
  if (!gate) { const e = new Error('key-op-authorization: no usable (approved, unconsumed, in-window) two-person approval for this key operation'); e.code = 'NO_APPROVAL'; throw e; }
  if (gate.id !== args.approval_id) { const e = new Error('key-op-authorization: approval_id does not match the usable approval'); e.code = 'APPROVAL_MISMATCH'; throw e; }

  const ttlCap = maxTtlFor(args.op);
  let ttl = typeof args.ttl_ms === 'number' ? args.ttl_ms : DEFAULT_TTL_MS;
  if (args.op === 'rollback') {
    // B6k fails LOUD rather than silently degrading. The legacy behaviour below
    // quietly substitutes one hour for an out-of-range request, which for a
    // contingency rollback authorization is a footgun: the operator would upgrade
    // believing they had a 30-day way back and actually have sixty minutes. An
    // explicit refusal is the only safe answer.
    if (typeof args.ttl_ms === 'number' && (!Number.isFinite(ttl) || ttl <= 0 || ttl > ttlCap)) {
      const e = new Error('key-op-authorization: ttl_ms for a rollback must be > 0 and <= ' + ttlCap + ' ms (30 days); refusing rather than silently substituting the 1h default');
      e.code = 'INVALID_TTL';
      throw e;
    }
    if (typeof args.ttl_ms !== 'number') ttl = DEFAULT_TTL_MS;
  } else if (!Number.isFinite(ttl) || ttl <= 0 || ttl > ttlCap) {
    // Unchanged for every pre-B6k op.
    ttl = DEFAULT_TTL_MS;
  }

  const id = crypto.randomBytes(16).toString('hex');
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + ttl).toISOString();
  const koa = {
    id, op: args.op, key_op_ref: args.key_op_ref, approval_id: args.approval_id,
    requested_by_user_id: args.requested_by_user_id, created_at: createdAt, expires_at: expiresAt,
  };
  const signature = anchor.sign({ db: db, data: canonicalPayload(koa) });

  db.prepare(
    'INSERT INTO key_op_authorizations ' +
    '(id, op, key_op_ref, approval_id, requested_by_user_id, created_at, expires_at, anchor_public_fingerprint, signature) ' +
    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(id, koa.op, koa.key_op_ref, koa.approval_id, koa.requested_by_user_id, createdAt, expiresAt, anchorPublicFingerprint(db), signature.toString('base64'));

  return getKoa(db, id);
}

// Verify a KOA row OFFLINE against a PEM public key. No db, no hardware, no network.
// Returns { valid, reason }. Checks the anchor signature over the canonical payload,
// then expiry and single-use.
function verifyKoa(koaRow, anchorPublicPem) {
  if (!koaRow || typeof koaRow !== 'object') return { valid: false, reason: 'no KOA row' };
  if (typeof anchorPublicPem !== 'string' || anchorPublicPem === '') return { valid: false, reason: 'no anchor public key' };
  if (typeof koaRow.signature !== 'string' || koaRow.signature === '') return { valid: false, reason: 'no signature' };
  let sigOk;
  try {
    sigOk = crypto.verify(
      'sha256',
      canonicalPayload(koaRow),
      { key: anchorPublicPem, dsaEncoding: 'ieee-p1363' },
      Buffer.from(koaRow.signature, 'base64'),
    );
  } catch (e) {
    return { valid: false, reason: 'verify error: ' + e.message };
  }
  if (!sigOk) return { valid: false, reason: 'signature mismatch (tampered, wrong instance, or corrupt)' };
  if (koaRow.expires_at && new Date(koaRow.expires_at).getTime() < Date.now()) return { valid: false, reason: 'expired' };
  if (koaRow.consumed_at) return { valid: false, reason: 'already consumed' };
  return { valid: true };
}

// Consume a KOA atomically (single-use): set consumed_at iff still null. Returns
// true iff THIS call consumed it (a losing concurrent caller gets false).
function consumeKoa(db, id, context) {
  const res = db.prepare(
    'UPDATE key_op_authorizations SET consumed_at = ?, consumed_context = ? WHERE id = ? AND consumed_at IS NULL'
  ).run(nowIso(), (typeof context === 'string' && context !== '') ? context : null, id);
  return res.changes === 1;
}

module.exports = {
  VALID_OPS,
  DEFAULT_TTL_MS,
  MAX_TTL_MS,
  ROLLBACK_MAX_TTL_MS,
  maxTtlFor,
  canonicalPayload,
  anchorPublicPem,
  anchorPublicFingerprint,
  getKoa,
  mintKoa,
  verifyKoa,
  consumeKoa,
};

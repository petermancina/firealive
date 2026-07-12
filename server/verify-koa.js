#!/usr/bin/env node
'use strict';

// FIREALIVE -- standalone offline KOA verifier (B6h B-3)
//
// Verify a Key-Operation Authorization against an instance's anchor public key
// using ONLY Node's crypto + fs. No database, no hardware, no running server, no
// npm dependencies -- copy this one file and the two inputs to an air-gapped box
// and it runs. It is what an operator (or the B-4 rekey tool) uses to
// independently confirm a KOA is authentic and usable before acting.
//
// Usage:
//   node verify-koa.js <koa.json> <anchor_public.pem>
//
//   <koa.json>          one KOA row as JSON (id, op, key_op_ref, approval_id,
//                       requested_by_user_id, created_at, expires_at, signature,
//                       and optionally consumed_at)
//   <anchor_public.pem> the instance's instance_identity.anchor_public (PEM SPKI)
//
// Exit codes: 0 valid and usable; 1 signature invalid; 3 signature valid but not
// usable (expired or already consumed); 2 usage/IO error.
//
// IMPORTANT: the canonical payload below MUST stay byte-identical to
// server/services/key-op-authorization.js canonicalPayload(). The CI regression
// cross-checks this tool against that module so the two cannot drift.

const crypto = require('crypto');
const fs = require('fs');

// Fixed field order, NUL-joined -- identical to key-op-authorization.canonicalPayload.
function canonicalPayload(koa) {
  return Buffer.from([
    koa.id, koa.op, koa.key_op_ref, koa.approval_id,
    koa.requested_by_user_id, koa.created_at, koa.expires_at,
  ].join('\u0000'), 'utf8');
}

function main(argv) {
  const koaPath = argv[2];
  const pemPath = argv[3];
  if (!koaPath || !pemPath) {
    process.stderr.write('usage: node verify-koa.js <koa.json> <anchor_public.pem>\n');
    return 2;
  }

  let koa, pem;
  try {
    koa = JSON.parse(fs.readFileSync(koaPath, 'utf8'));
  } catch (e) {
    process.stderr.write('ERROR: cannot read/parse KOA JSON: ' + e.message + '\n');
    return 2;
  }
  try {
    pem = fs.readFileSync(pemPath, 'utf8');
  } catch (e) {
    process.stderr.write('ERROR: cannot read anchor public key: ' + e.message + '\n');
    return 2;
  }
  if (typeof koa.signature !== 'string' || koa.signature === '') {
    process.stderr.write('INVALID: KOA has no signature\n');
    return 1;
  }

  let sigOk;
  try {
    sigOk = crypto.verify(
      'sha256',
      canonicalPayload(koa),
      { key: pem, dsaEncoding: 'ieee-p1363' },
      Buffer.from(koa.signature, 'base64'),
    );
  } catch (e) {
    process.stderr.write('INVALID: verification error: ' + e.message + '\n');
    return 1;
  }
  if (!sigOk) {
    process.stderr.write('INVALID: signature mismatch -- tampered, wrong instance, or corrupt.\n');
    return 1;
  }

  process.stdout.write('SIGNATURE VALID for KOA ' + koa.id + '\n');
  process.stdout.write('  op:           ' + koa.op + '\n');
  process.stdout.write('  key_op_ref:   ' + koa.key_op_ref + '\n');
  process.stdout.write('  approval_id:  ' + koa.approval_id + '\n');
  process.stdout.write('  requested_by: ' + koa.requested_by_user_id + '\n');
  process.stdout.write('  created_at:   ' + koa.created_at + '\n');
  process.stdout.write('  expires_at:   ' + koa.expires_at + '\n');

  const now = Date.now();
  const expired = koa.expires_at && new Date(koa.expires_at).getTime() < now;
  const consumed = koa.consumed_at !== undefined && koa.consumed_at !== null && koa.consumed_at !== '';
  if (consumed) process.stdout.write('  consumed_at:  ' + koa.consumed_at + '\n');

  if (expired) {
    process.stderr.write('NOT USABLE: the KOA has expired.\n');
    return 3;
  }
  if (consumed) {
    process.stderr.write('NOT USABLE: the KOA has already been consumed (single use).\n');
    return 3;
  }
  process.stdout.write('KOA is VALID and USABLE.\n');
  return 0;
}

process.exit(main(process.argv));

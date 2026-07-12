// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Tier-1 column seal/open chokepoint (domain-aware)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The single place every Tier-1 column is sealed and opened. Given a column
// reference (table.column), it looks the column up in the generated registry
// (tier1-columns.js) and applies that column's three facts:
//
//   domain   -> which KEK. node-local columns (CDC-excluded: signing-key private
//               keys, the CA key) are sealed under THIS node's own KEK; replicated
//               columns (integration credentials and the other CDC-replicated
//               columns) are sealed under the deployment active's shared KEK. This
//               is the fix the whole phase exists for: a promoted node reads its
//               own node-local columns with ownKek() and the replicated columns
//               with sharedKek(), instead of one process-wide key.
//   shape    -> how the plaintext is serialized before sealing. json = JSON round
//               trip; utf8 = a raw string.
//   storage  -> how the ciphertext is encoded at rest. buffer = the raw
//               iv|tag|ciphertext Buffer (a BLOB, or a Buffer bound to a TEXT
//               column); base64 / hex = that Buffer encoded into a TEXT column.
//
// The at-rest bytes are identical to what encryptConfig(...) / encrypt(...,
// 'TIER1_ENCRYPTION_KEY') produced before, so converting a call site to
// sealTier1/openTier1 does not rewrite any stored value: the envelope is the
// same v1 envelope (encryption.encryptWithKey) and, on a standalone or active
// node, ownKek() == sharedKek(), so replicated columns keep the same key too.
//
// Fail-closed: a column reference that is not a registered Tier-1 column throws,
// and a tier1-derived column (an HKDF/hardware seal, e.g. ha_node.wrap_private_
// sealed) is refused here -- those are sealed by ha-keys, not this chokepoint.

'use strict';

const tier1Envelope = require('./tier1-envelope');
const tier1Kek = require('./tier1-kek');
const { TIER1_COLUMNS } = require('./tier1-columns');

// table.column -> registry row. Built once from the generated registry.
const REGISTRY = new Map();
for (let i = 0; i < TIER1_COLUMNS.length; i++) {
  const c = TIER1_COLUMNS[i];
  REGISTRY.set(c.table + '.' + c.column, c);
}

function meta(colRef) {
  const m = REGISTRY.get(colRef);
  if (!m) {
    throw new Error('tier1-seal: ' + colRef + ' is not a registered Tier-1 column ' +
      '(use table.column exactly as in tier1-columns.js; regenerate the registry if the column is new)');
  }
  if (m.class !== 'tier1') {
    throw new Error('tier1-seal: ' + colRef + ' is class ' + m.class +
      ', which is not sealed via tier1-seal (tier1-derived columns use hardware seals in ha-keys)');
  }
  return m;
}

function keyForDomain(domain) {
  if (domain === 'node-local') return tier1Kek.ownKek();
  if (domain === 'replicated') return tier1Kek.sharedKek();
  throw new Error('tier1-seal: unknown domain ' + domain);
}

// The KEK fingerprint stamped into (and checked against) the v2 envelope for a
// column's domain -- lets a read fail fast and clearly when it holds the wrong KEK.
function kekFpForDomain(domain) {
  if (domain === 'node-local') return tier1Kek.ownKekFingerprint();
  if (domain === 'replicated') return tier1Kek.sharedKekFingerprint();
  throw new Error('tier1-seal: unknown domain ' + domain);
}

// The per-column AAD binding: table and column names, NUL-separated. Combined with
// the envelope header (magic||version||kek_fp) inside the v2 envelope, this pins a
// ciphertext to its exact column so it cannot be relocated (R6).
function aadForColumn(colRef) {
  const dot = colRef.indexOf('.');
  return Buffer.from(colRef.slice(0, dot) + '\u0000' + colRef.slice(dot + 1), 'utf8');
}

function serialize(value, shape) {
  if (shape === 'json') return JSON.stringify(value);
  if (shape === 'utf8') {
    if (typeof value !== 'string') {
      throw new Error('tier1-seal: a utf8 column expects a string value, got ' + typeof value);
    }
    return value;
  }
  throw new Error('tier1-seal: unsupported shape ' + shape);
}

function deserialize(text, shape) {
  if (shape === 'json') return JSON.parse(text);
  if (shape === 'utf8') return text;
  throw new Error('tier1-seal: unsupported shape ' + shape);
}

// Encode the raw v1 envelope Buffer to its at-rest representation.
function encodeStorage(envelope, storage) {
  if (storage === 'buffer') return envelope;
  if (storage === 'base64') return envelope.toString('base64');
  if (storage === 'hex') return envelope.toString('hex');
  throw new Error('tier1-seal: unsupported storage ' + storage);
}

// Decode an at-rest value back to the raw v1 envelope Buffer.
function decodeStorage(stored, storage) {
  if (storage === 'buffer') return Buffer.isBuffer(stored) ? stored : Buffer.from(stored);
  if (storage === 'base64') return Buffer.from(stored, 'base64');
  if (storage === 'hex') return Buffer.from(stored, 'hex');
  throw new Error('tier1-seal: unsupported storage ' + storage);
}

// Seal a value for a Tier-1 column. Returns the at-rest representation to store
// (a Buffer for storage 'buffer', a string for 'base64'/'hex'). A null/undefined
// value seals to null -- an absent column is stored NULL, not an encrypted null.
function sealTier1(colRef, value) {
  if (value === null || value === undefined) return null;
  const m = meta(colRef);
  const key = keyForDomain(m.domain);
  const envelope = tier1Envelope.sealV2(serialize(value, m.shape), key, kekFpForDomain(m.domain), aadForColumn(colRef));
  return encodeStorage(envelope, m.storage);
}

// Open a Tier-1 column's stored value. Returns null for a NULL column.
function openTier1(colRef, stored) {
  if (stored === null || stored === undefined) return null;
  const m = meta(colRef);
  const key = keyForDomain(m.domain);
  const envelope = decodeStorage(stored, m.storage);
  return deserialize(tier1Envelope.open(envelope, key, aadForColumn(colRef), kekFpForDomain(m.domain)), m.shape);
}

// True if colRef is a Tier-1 (chokepoint-sealed) column.
function isRegistered(colRef) {
  const m = REGISTRY.get(colRef);
  return !!m && m.class === 'tier1';
}

module.exports = {
  sealTier1,
  openTier1,
  isRegistered,
};

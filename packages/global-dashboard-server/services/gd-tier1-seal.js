// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE GLOBAL DASHBOARD ── Tier-1 column seal/open chokepoint (domain-aware)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The GD twin of server/services/tier1-seal.js: the single place every GD Tier-1
// column is sealed and opened. Given a column reference (table.column) it looks the
// column up in the generated GD registry (gd-tier1-columns.js) and applies its
// domain:
//
//   domain node-local -> sealed under THIS GD node's own KEK (ownKek): the
//     CDC-excluded columns (GD signing-key private keys, the GD CA key).
//   domain replicated -> sealed under the GD deployment active's shared KEK
//     (sharedKek): the CDC-replicated columns. On a standalone or active GD node
//     the shared KEK IS ownKek; on a promoted GD node it is the former active's
//     KEK. This routing is the fix the phase exists for.
//
// Every GD Tier-1 column uses one at-rest format -- gd-encryption's self-describing
// JSON envelope string {v, iv, tag, ciphertext} carrying a JSON payload (shape json,
// storage envelope). So the chokepoint seals with gd-encryption.encryptConfigWithKey
// and opens with decryptConfigWithKey, which serialize and envelope in one step. GD
// has no raw-buffer (base64/hex) Tier-1 columns, and therefore no raw-buffer path:
// a column whose registry storage is not 'envelope' is refused fail-closed, so
// introducing one is a deliberate, visible change (extend this module and add a
// raw-buffer core to gd-encryption).
//
// The at-rest bytes match what encryptConfig(...) produced before -- the same
// envelope, and on a standalone/active GD node ownKek() == sharedKek() -- so
// converting a call site does not rewrite any stored value. A null/undefined value
// seals to null; a NULL column opens to null.
//
// Fail-closed: an unregistered column throws, and a tier1-derived column (an
// HKDF/hardware seal, e.g. gd_ha_node.wrap_private_sealed) is refused here -- those
// are sealed by gd-ha-keys, not this chokepoint.

'use strict';

const gdTier1Envelope = require('./gd-tier1-envelope');
const gdTier1Kek = require('./gd-tier1-kek');
const { GD_TIER1_COLUMNS } = require('./gd-tier1-columns');

// table.column -> registry row. Built once from the generated GD registry.
const REGISTRY = new Map();
for (let i = 0; i < GD_TIER1_COLUMNS.length; i++) {
  const c = GD_TIER1_COLUMNS[i];
  REGISTRY.set(c.table + '.' + c.column, c);
}

function meta(colRef) {
  const m = REGISTRY.get(colRef);
  if (!m) {
    throw new Error('gd-tier1-seal: ' + colRef + ' is not a registered GD Tier-1 column ' +
      '(use table.column exactly as in gd-tier1-columns.js; regenerate the registry if the column is new)');
  }
  if (m.class !== 'tier1') {
    throw new Error('gd-tier1-seal: ' + colRef + ' is class ' + m.class +
      ', which is not sealed via gd-tier1-seal (tier1-derived columns use hardware seals in gd-ha-keys)');
  }
  return m;
}

function keyForDomain(domain) {
  if (domain === 'node-local') return gdTier1Kek.ownKek();
  if (domain === 'replicated') return gdTier1Kek.sharedKek();
  throw new Error('gd-tier1-seal: unknown domain ' + domain);
}

// The KEK fingerprint stamped into (and checked against) the v2 envelope for a
// column's domain -- lets a read fail fast and clearly when it holds the wrong KEK.
function kekFpForDomain(domain) {
  if (domain === 'node-local') return gdTier1Kek.ownKekFingerprint();
  if (domain === 'replicated') return gdTier1Kek.sharedKekFingerprint();
  throw new Error('gd-tier1-seal: unknown domain ' + domain);
}

// The per-column AAD binding: table and column names, NUL-separated. Combined with
// the version tag + kek_fp inside the v2 envelope, this pins a ciphertext to its
// exact column so it cannot be relocated (R6).
function aadForColumn(colRef) {
  const dot = colRef.indexOf('.');
  return Buffer.from(colRef.slice(0, dot) + '\u0000' + colRef.slice(dot + 1), 'utf8');
}

function assertEnvelope(colRef, m) {
  if (m.storage !== 'envelope') {
    throw new Error('gd-tier1-seal: ' + colRef + ' has storage ' + m.storage +
      '; GD Tier-1 columns are envelope-only (add a raw-buffer core to gd-encryption and a path here to introduce one)');
  }
  if (m.shape !== 'json') {
    throw new Error('gd-tier1-seal: ' + colRef + ' has shape ' + m.shape +
      '; the GD envelope carries a JSON payload');
  }
}

// Seal a value for a GD Tier-1 column. Returns the envelope string to store, or
// null for a null/undefined value (an absent column is stored NULL).
function sealTier1(colRef, value) {
  if (value === null || value === undefined) return null;
  const m = meta(colRef);
  assertEnvelope(colRef, m);
  return gdTier1Envelope.sealV2(value, keyForDomain(m.domain), kekFpForDomain(m.domain), aadForColumn(colRef));
}

// Open a GD Tier-1 column's stored envelope. Returns null for a NULL column.
function openTier1(colRef, stored) {
  if (stored === null || stored === undefined) return null;
  const m = meta(colRef);
  assertEnvelope(colRef, m);
  return gdTier1Envelope.open(stored, keyForDomain(m.domain), aadForColumn(colRef), kekFpForDomain(m.domain));
}

// Re-seal an already-stored GD Tier-1 value from one KEK to another. Opens the stored
// envelope under fromKek (verifying fromKekFp for v2) and re-seals the same plaintext as a
// v2 envelope under toKek/toKekFp -- upgrading any legacy v1 value to v2. Used ONLY by the
// offline node rekey (B-4) to rebind a promoted GD node's replicated columns from the adopted
// shared KEK to its own KEK. Fails closed: throws if the value will not open under fromKek, so
// the rekey caller aborts the whole transaction rather than persist a half-rekeyed row.
function resealValue(colRef, stored, fromKek, fromKekFp, toKek, toKekFp) {
  if (stored === null || stored === undefined) return null;
  const m = meta(colRef);
  assertEnvelope(colRef, m);
  const plaintext = gdTier1Envelope.open(stored, fromKek, aadForColumn(colRef), fromKekFp);
  return gdTier1Envelope.sealV2(plaintext, toKek, toKekFp, aadForColumn(colRef));
}

// True if colRef is a GD Tier-1 (chokepoint-sealed) column.
function isRegistered(colRef) {
  const m = REGISTRY.get(colRef);
  return !!m && m.class === 'tier1';
}

module.exports = {
  sealTier1,
  openTier1,
  resealValue,
  isRegistered,
};

// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Instance Anchor (pluggable interface / dispatcher)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// THE INSTANCE ANCHOR (B5e, decision D26)
//
// An instance anchor binds this deployment's identity to a hardware root of
// trust so that a cloned disk or image cannot reconstitute the original instance
// on other hardware. The anchor is the spine of FireAlive's anti-cloning
// hardening: every per-instance secret (CA, client certs, device + analyst +
// E2EE keys, the chain-signing key families, enrollment tokens) is only as
// un-clonable as the identity that mints and seals it.
//
// FireAlive requires a hardware root of trust and FAILS CLOSED without one
// (D26) -- there is no software fallback. The single implementation is
// hardware-anchor.js, which creates an ECDSA P-256 signing key in, and seals
// state to, the platform root of trust (TPM 2.0 on Linux/Windows, Secure Enclave
// on macOS) via the cross-platform hardware-keystore seam. A copied disk cannot
// unseal or sign, so it cannot become the original.
//
// This module is the dispatcher. It resolves the hardware anchor, refuses (fail
// closed) when no hardware root is present, and delegates the interface methods.
// An identity recorded under a legacy non-hardware kind ('software' / 'vtpm',
// from before D26) is not honored: such a deployment must re-provision onto a
// hardware root, and getImpl throws for any kind other than 'hardware'.
//
// INTERFACE CONTRACT (the implementation MUST export):
//   isAvailable(options)              boolean   cheap hardware capability probe
//   establish({ db, logger })         identity  first-boot mint + record
//   load({ db, logger })              identity | null
//   sealState({ db, identity, data }) sealed    seal arbitrary bytes / JSON
//   unsealState({ db, identity, sealed }) plain
//   verify({ db, identity })          { valid, reason }
//   sign({ db, identity, data })      Buffer    ECDSA P-256 (raw r||s) signature
//   ratchet({ db, identity })         { counter }  advance the monotonic counter
//   fingerprint(identity)             string    SHA-256 hex of the SPKI
//
// An identity descriptor is a plain object:
//   { instanceId, anchorKind, publicKey, fingerprint, fuseHighWater, status }
//
// All methods are synchronous to match better-sqlite3 and the service layer.

const KIND_HARDWARE = 'hardware';

// The only supported anchor is the hardware anchor. A legacy non-hardware kind
// is rejected (fail-closed): the deployment must re-provision onto a hardware
// root of trust (D26). No software fallback is ever loaded.
function getImpl(kind) {
  if (kind === KIND_HARDWARE) {
    return require('./hardware-anchor');
  }
  throw new Error('instance anchor: unsupported anchor kind "' + kind + '"; FireAlive requires a hardware root of trust (TPM 2.0 / Secure Enclave) and this deployment must re-provision (D26)');
}

// Resolve the hardware anchor, failing closed when no hardware root of trust is
// present. There is no software fallback. Returns { kind, impl }.
function resolveAnchor(options) {
  options = options || {};
  const impl = getImpl(KIND_HARDWARE);
  let available = false;
  try {
    available = typeof impl.isAvailable === 'function' && impl.isAvailable(options) === true;
  } catch (err) {
    available = false;
  }
  if (!available) {
    throw new Error('instance anchor: no hardware root of trust (TPM 2.0 / Secure Enclave) available; refusing to establish identity (fail-closed, no software fallback, D26)');
  }
  return { kind: KIND_HARDWARE, impl: impl };
}

// Read the anchor kind recorded for the established identity. Returns null when
// no identity exists yet (or the table is not present).
function recordedKind(db) {
  try {
    const row = db.prepare('SELECT anchor_kind FROM instance_identity ORDER BY id LIMIT 1').get();
    return row && row.anchor_kind ? row.anchor_kind : null;
  } catch (err) {
    return null;
  }
}

// Resolve the implementation for an already-established identity. Prefers the
// kind on the descriptor, then the persisted record, then hardware. getImpl
// rejects a legacy non-hardware kind (fail-closed).
function implFor(options) {
  options = options || {};
  let kind = null;
  if (options.identity && options.identity.anchorKind) {
    kind = options.identity.anchorKind;
  } else if (options.db) {
    kind = recordedKind(options.db);
  }
  kind = kind || KIND_HARDWARE;
  return { kind: kind, impl: getImpl(kind) };
}

// INTERFACE METHODS -- delegate to the hardware anchor.

// First-boot establishment: mint the hardware-rooted identity and record it.
// Fails closed (throws) when no hardware root of trust is present.
function establish(options) {
  const resolved = resolveAnchor(options);
  const opts = Object.assign({}, options, { anchorKind: resolved.kind });
  return resolved.impl.establish(opts);
}

// Load the established identity, dispatching to the kind that minted it. Returns
// null when no identity has been established.
function load(options) {
  options = options || {};
  const kind = options.db ? recordedKind(options.db) : null;
  if (!kind) {
    return null;
  }
  return getImpl(kind).load(options);
}

function sealState(options) {
  return implFor(options).impl.sealState(options);
}

function unsealState(options) {
  return implFor(options).impl.unsealState(options);
}

function verify(options) {
  return implFor(options).impl.verify(options);
}

function sign(options) {
  return implFor(options).impl.sign(options);
}

function ratchet(options) {
  return implFor(options).impl.ratchet(options);
}

function fingerprint(identity) {
  const kind = identity && identity.anchorKind ? identity.anchorKind : KIND_HARDWARE;
  return getImpl(kind).fingerprint(identity);
}

module.exports = {
  KIND_HARDWARE,
  getImpl,
  resolveAnchor,
  recordedKind,
  establish,
  load,
  sealState,
  unsealState,
  verify,
  sign,
  ratchet,
  fingerprint,
};

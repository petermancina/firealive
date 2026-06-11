// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Instance Anchor (pluggable interface / dispatcher)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// THE INSTANCE ANCHOR (B5e, decision D2)
//
// An instance anchor binds this deployment's identity to a root of trust so that
// a cloned disk or image cannot silently reconstitute the original instance on
// other hardware. The anchor is the spine of FireAlive's anti-cloning hardening:
// every per-instance secret (CA, client certs, device + analyst + E2EE keys, the
// chain-signing key families, enrollment tokens) is only as un-clonable as the
// identity that mints and seals it.
//
// Two implementations satisfy the interface defined here:
//
//   software-anchor.js  the always-available baseline -- a per-instance secret
//                       sealed at rest with the Tier-1 KEK. Ships in Block A.
//                       Defeats duplicate-key generation, snapshot rollback, and
//                       fork/split-brain; a fully isolated software-only clone is
//                       the documented residual.
//   vtpm-anchor.js      a hardware-backed anchor -- the secret plus a monotonic
//                       counter sealed to a TPM/vTPM. Ships in Block D. Closes
//                       cloning at the root (a sealed identity will not unseal on
//                       other hardware). Attempted where present, with graceful
//                       fallback to the software anchor (it never bricks a boot).
//
// This module is the dispatcher. It selects the active implementation, delegates
// the interface methods to it, and keeps the two paths independent so that a
// not-yet-shipped or platform-absent implementation never breaks the path in use.
//
// INTERFACE CONTRACT (every implementation MUST export):
//   isAvailable(options)              boolean   cheap capability probe
//   establish({ db, logger })         identity  first-boot mint + seal + record
//   load({ db, logger })              identity | null
//   sealState({ db, identity, data }) sealed    seal arbitrary bytes / JSON
//   unsealState({ db, identity, sealed }) plain
//   verify({ db, identity })          { valid, reason }
//   sign({ db, identity, data })      Buffer    Ed25519 signature over data
//   ratchet({ db, identity })         { counter }  advance the monotonic counter
//   fingerprint(identity)             string    SHA-256 hex of the SPKI
//
// An identity descriptor is a plain object:
//   { instanceId, anchorKind, publicKey, fingerprint, fuseHighWater, status }
//
// All methods are synchronous to match better-sqlite3 and the service layer.

const KIND_SOFTWARE = 'software';
const KIND_VTPM = 'vtpm';

// Lazy require so that an absent implementation (e.g. vtpm-anchor.js before
// Block D, or on a host with no TPM) never breaks the path that is in use.
function getImpl(kind) {
  if (kind === KIND_VTPM) {
    return require('./vtpm-anchor');
  }
  return require('./software-anchor');
}

// Select the strongest anchor available. The vTPM is only attempted when the
// caller opts in (virtualization mode / hardware present); any failure falls
// back to the software anchor, which is always available. Returns { kind, impl }.
function resolveAnchor(options) {
  options = options || {};
  if (options.preferVtpm) {
    try {
      const impl = getImpl(KIND_VTPM);
      if (impl && typeof impl.isAvailable === 'function' && impl.isAvailable(options)) {
        return { kind: KIND_VTPM, impl: impl };
      }
    } catch (err) {
      const reason = err && err.message ? err.message : String(err);
      if (options.logger && typeof options.logger.warn === 'function') {
        options.logger.warn('vTPM anchor unavailable; using software anchor', { reason: reason });
      }
    }
  }
  return { kind: KIND_SOFTWARE, impl: getImpl(KIND_SOFTWARE) };
}

// Read the anchor kind recorded for the established identity so that load,
// verify, seal, and ratchet dispatch to the implementation that minted it.
// Returns null when no identity exists yet (or the table is not present).
function recordedKind(db) {
  try {
    const row = db.prepare('SELECT anchor_kind FROM instance_identity ORDER BY id LIMIT 1').get();
    return row && row.anchor_kind ? row.anchor_kind : null;
  } catch (err) {
    return null;
  }
}

// Resolve the implementation for an already-established identity. Prefers the
// kind carried on the descriptor, then the persisted record, then software.
function implFor(options) {
  options = options || {};
  let kind = null;
  if (options.identity && options.identity.anchorKind) {
    kind = options.identity.anchorKind;
  } else if (options.db) {
    kind = recordedKind(options.db);
  }
  kind = kind || KIND_SOFTWARE;
  return { kind: kind, impl: getImpl(kind) };
}

// INTERFACE METHODS -- delegate to the active implementation.

// First-boot establishment: mint a fresh per-instance secret, seal it to the
// best available anchor, and record the identity (including its anchor kind).
function establish(options) {
  const resolved = resolveAnchor(options);
  const opts = Object.assign({}, options, { anchorKind: resolved.kind });
  return resolved.impl.establish(opts);
}

// Load the established identity, dispatching to the kind that minted it.
// Returns null when no identity has been established.
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
  const kind = identity && identity.anchorKind ? identity.anchorKind : KIND_SOFTWARE;
  return getImpl(kind).fingerprint(identity);
}

module.exports = {
  KIND_SOFTWARE,
  KIND_VTPM,
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

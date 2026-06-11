// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Instance Anchor (software implementation)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The always-available software instance anchor (B5e, decision D2). The
// per-instance identity is an Ed25519 keypair: the private key is the instance
// secret, sealed at rest with the Tier-1 KEK (encryptConfig); the public key and
// its SHA-256-over-SPKI-DER fingerprint are the deployment's verifiable identity,
// computed identically to the report / gd-push / backup signing-key fingerprints
// so the GD-side collision check compares like with like.
//
// This implementation satisfies the instance-anchor interface (see index.js). It
// stores identity in the instance_identity table and is the baseline that the
// vTPM anchor (Block D) hardens at the root. It defeats duplicate-key generation
// (the fresh keypair is gated behind the first-boot entropy reseed), snapshot
// rollback (the monotonic ratchet + the attested high-water mark), and
// fork/split-brain; a fully isolated software-only clone is the documented
// residual.
//
// SECURITY NOTE: the seal is only as strong as the Tier-1 KEK. On a vTPM-less
// host an imaged disk plus the KEK env var can decrypt the secret; that residual
// is closed by the vTPM-sealed KEK in Block D (or the optional operator KEK
// passphrase for high-sensitivity sites).

const crypto = require('crypto');
const { encryptConfig, decryptConfig } = require('../encryption');

const KIND_SOFTWARE = 'software';
const STATUS_ACTIVE = 'active';

// SHA-256 hex of the SPKI DER -- identical to computePublicKeyFingerprint in the
// signing-key services, so instance fingerprints are comparable across them.
function computeFingerprint(publicKeyPem) {
  if (typeof publicKeyPem !== 'string' || !publicKeyPem.trim()) {
    throw new Error('computeFingerprint: publicKeyPem must be a non-empty string');
  }
  const keyObj = crypto.createPublicKey(publicKeyPem);
  const der = keyObj.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// Shape the in-memory identity descriptor from a stored row. fuse_high_water is
// read from system_meta when present (it is seeded and checked by the high-water
// commit); null before then.
function descriptorFromRow(row, db) {
  let fuseHighWater = null;
  if (db) {
    try {
      const m = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_high_water'").get();
      if (m && m.value !== null && m.value !== undefined) {
        fuseHighWater = Number(m.value);
      }
    } catch (err) {
      fuseHighWater = null;
    }
  }
  return {
    instanceId: row.instance_id,
    anchorKind: row.anchor_kind,
    publicKey: row.anchor_public,
    fingerprint: row.fingerprint,
    ratchetCounter: row.ratchet_counter,
    status: row.status,
    establishedAt: row.established_at,
    lastAttestedAt: row.last_attested_at,
    fuseHighWater: fuseHighWater,
  };
}

// The software anchor is always available.
function isAvailable() {
  return true;
}

// Load the established identity, or null if none exists (or the table is absent).
function load(options) {
  options = options || {};
  const db = options.db;
  let row;
  try {
    row = db.prepare("SELECT * FROM instance_identity ORDER BY id LIMIT 1").get();
  } catch (err) {
    return null;
  }
  if (!row) {
    return null;
  }
  return descriptorFromRow(row, db);
}

// First-boot establishment. Idempotent: if an identity already exists it is
// returned unchanged (re-running startup never mints a second identity). Mints a
// fresh Ed25519 keypair, seals the private key with the Tier-1 KEK, and records
// the identity.
function establish(options) {
  options = options || {};
  const db = options.db;
  const existing = load({ db: db });
  if (existing) {
    return existing;
  }
  const pair = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const fp = computeFingerprint(publicKeyPem);
  const instanceId = 'inst-' + crypto.randomUUID();
  const sealed = encryptConfig({ pem: privateKeyPem });
  db.prepare(
    "INSERT INTO instance_identity " +
    "(instance_id, anchor_kind, anchor_public, anchor_seal, fingerprint, ratchet_counter, status) " +
    "VALUES (?, ?, ?, ?, ?, 0, ?)"
  ).run(instanceId, KIND_SOFTWARE, publicKeyPem, sealed, fp, STATUS_ACTIVE);
  if (options.logger && typeof options.logger.info === 'function') {
    options.logger.info('instance identity established', {
      instanceId: instanceId,
      anchorKind: KIND_SOFTWARE,
      fingerprint: fp,
    });
  }
  const row = db.prepare("SELECT * FROM instance_identity WHERE instance_id = ?").get(instanceId);
  return descriptorFromRow(row, db);
}

// Seal arbitrary JSON-serializable data with the Tier-1 KEK. Returns the sealed
// buffer for the caller to store. (The identity is unused by the software anchor;
// the vTPM anchor binds the seal to the identity's TPM object.)
function sealState(options) {
  options = options || {};
  return encryptConfig({ v: options.data });
}

// Reverse of sealState.
function unsealState(options) {
  options = options || {};
  return decryptConfig(options.sealed).v;
}

// Verify the identity is intact: the recorded fingerprint matches the public key,
// and the sealed private key both unseals (KEK correct) and corresponds to the
// public key (a signed-nonce round-trip). Returns { valid, reason }.
function verify(options) {
  options = options || {};
  const db = options.db;
  const identity = options.identity || load({ db: db });
  if (!identity) {
    return { valid: false, reason: 'no instance identity established' };
  }
  try {
    if (computeFingerprint(identity.publicKey) !== identity.fingerprint) {
      return { valid: false, reason: 'fingerprint does not match public key' };
    }
    const row = db.prepare("SELECT anchor_seal FROM instance_identity WHERE instance_id = ?").get(identity.instanceId);
    if (!row) {
      return { valid: false, reason: 'identity row missing' };
    }
    const unsealed = decryptConfig(row.anchor_seal);
    const privateKey = crypto.createPrivateKey(unsealed.pem);
    const publicKey = crypto.createPublicKey(identity.publicKey);
    const nonce = crypto.randomBytes(32);
    const signature = crypto.sign(null, nonce, privateKey);
    if (!crypto.verify(null, nonce, publicKey, signature)) {
      return { valid: false, reason: 'sealed key does not match public key' };
    }
    return { valid: true, reason: null };
  } catch (err) {
    return { valid: false, reason: err && err.message ? err.message : String(err) };
  }
}

// Sign arbitrary bytes with the sealed instance private key (Ed25519). The
// subnet peer-beacon uses this to authenticate the beacons it broadcasts so a
// receiver can prove a beacon came from a holder of the instance key -- a random
// host on the subnet cannot forge one. Returns a Buffer signature, or null if no
// identity is established.
function sign(options) {
  options = options || {};
  const db = options.db;
  const identity = options.identity || load({ db: db });
  if (!identity) {
    return null;
  }
  const row = db.prepare("SELECT anchor_seal FROM instance_identity WHERE instance_id = ?").get(identity.instanceId);
  if (!row) {
    return null;
  }
  const unsealed = decryptConfig(row.anchor_seal);
  const privateKey = crypto.createPrivateKey(unsealed.pem);
  const data = Buffer.isBuffer(options.data) ? options.data : Buffer.from(String(options.data));
  return crypto.sign(null, data, privateKey);
}

// Advance the instance-level monotonic ratchet (fork/rollback signal) and stamp
// the attestation time. Returns the new counter value.
function ratchet(options) {
  options = options || {};
  const db = options.db;
  const identity = options.identity || load({ db: db });
  if (!identity) {
    throw new Error('ratchet: no instance identity established');
  }
  db.prepare("UPDATE instance_identity SET ratchet_counter = ratchet_counter + 1, last_attested_at = datetime('now') WHERE instance_id = ?").run(identity.instanceId);
  const row = db.prepare("SELECT ratchet_counter FROM instance_identity WHERE instance_id = ?").get(identity.instanceId);
  return { counter: row ? row.ratchet_counter : null };
}

// SHA-256-over-SPKI-DER fingerprint for the identity.
function fingerprint(identity) {
  if (identity && identity.fingerprint) {
    return identity.fingerprint;
  }
  if (identity && identity.publicKey) {
    return computeFingerprint(identity.publicKey);
  }
  throw new Error('fingerprint: identity has no public key');
}

module.exports = {
  isAvailable,
  establish,
  load,
  sealState,
  unsealState,
  verify,
  sign,
  ratchet,
  fingerprint,
  computeFingerprint,
};

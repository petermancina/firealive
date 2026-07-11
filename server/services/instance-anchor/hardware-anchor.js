// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Instance Anchor (hardware implementation)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// THE HARDWARE INSTANCE ANCHOR (B5e, decision D26)
//
// A hardware-backed anchor implementing the instance-anchor interface (see
// index.js) via the cross-platform hardware-keystore seam. The instance identity
// is an ECDSA P-256 signing key created in, and never leaving, the platform root
// of trust (TPM 2.0 on Linux/Windows, Secure Enclave on macOS) -- so a copied
// disk cannot reconstitute the instance or sign as it. ECDSA P-256 is used
// because it is the one algorithm common to all three roots of trust (the Secure
// Enclave has no Ed25519). The public key and its SHA-256-over-SPKI-DER
// fingerprint are the verifiable identity, computed identically to the report /
// gd-push / software-anchor fingerprints so the GD collision check compares like
// with like.
//
// Differences from the (retired) software anchor:
//   - No sealed private key at rest: the key lives in hardware, so anchor_seal
//     carries only a non-secret marker (the backend kind + the key label).
//   - Signatures are ECDSA P-256 raw r||s (IEEE P1363) over a SHA-256 digest;
//     verifiers use crypto.verify('sha256', ..., { dsaEncoding: 'ieee-p1363' }).
//   - sealState envelopes data under a hardware-sealed AES-256-GCM key, so the
//     envelope only opens on this instance's root of trust.
//
// Fail-closed (D26): with no hardware root of trust, establish refuses; there is
// no software fallback.

const crypto = require('crypto');
const keystore = require('./hardware-keystore');

const KIND_HARDWARE = 'hardware';
const STATUS_ACTIVE = 'active';
const SEAL_ALG = 'aes-256-gcm';

// SHA-256 hex of the SPKI DER of a PEM public key -- identical to the signing-key
// services and the software anchor, so fingerprints are comparable across them.
function computeFingerprint(publicKeyPem) {
  if (typeof publicKeyPem !== 'string' || !publicKeyPem.trim()) {
    throw new Error('computeFingerprint: publicKeyPem must be a non-empty string');
  }
  const keyObj = crypto.createPublicKey(publicKeyPem);
  const der = keyObj.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// SHA-256 hex of an SPKI DER buffer (the keystore returns public keys as DER).
function fingerprintOfDer(der) {
  return crypto.createHash('sha256').update(der).digest('hex');
}

// Convert the keystore's SPKI DER public key to PEM, so anchor_public is stored
// as PEM exactly like the software anchor.
function derToPem(der) {
  const keyObj = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  return keyObj.export({ type: 'spki', format: 'pem' });
}

// Shape the in-memory identity descriptor from a stored row, reading
// fuse_high_water from system_meta when present (null before the high-water
// commit seeds it).
function descriptorFromRow(row, db) {
  let fuseHighWater = null;
  if (db) {
    try {
      const m = db.prepare("SELECT value FROM node_state WHERE key = 'fuse_high_water'").get();
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

// Available only when the hardware root of trust is present. Fail-closed: a host
// with no TPM / Secure Enclave reports false and establish refuses.
function isAvailable(options) {
  try {
    return keystore.isAvailable() === true;
  } catch (err) {
    return false;
  }
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

// First-boot establishment. Idempotent: an existing identity is returned
// unchanged. Requires a hardware root of trust and refuses (fail-closed) when
// absent. The signing key is created in hardware under the instance id.
function establish(options) {
  options = options || {};
  const db = options.db;
  const existing = load({ db: db });
  if (existing) {
    return existing;
  }
  if (!isAvailable()) {
    throw new Error('hardware anchor: no hardware root of trust (TPM 2.0 / Secure Enclave) available; refusing to establish identity (fail-closed, D26)');
  }
  const instanceId = 'inst-' + crypto.randomUUID();
  const der = keystore.createSigningKey(instanceId);
  const publicKeyPem = derToPem(der);
  const fp = computeFingerprint(publicKeyPem);
  let backend = null;
  try {
    backend = keystore.describe().backend;
  } catch (err) {
    backend = null;
  }
  const seal = JSON.stringify({ hardware: backend, label: instanceId });
  db.prepare(
    "INSERT INTO instance_identity " +
    "(instance_id, anchor_kind, anchor_public, anchor_seal, fingerprint, ratchet_counter, status) " +
    "VALUES (?, ?, ?, ?, ?, 0, ?)"
  ).run(instanceId, KIND_HARDWARE, publicKeyPem, seal, fp, STATUS_ACTIVE);
  if (options.logger && typeof options.logger.info === 'function') {
    options.logger.info('instance identity established', {
      instanceId: instanceId,
      anchorKind: KIND_HARDWARE,
      backend: backend,
      fingerprint: fp,
    });
  }
  const row = db.prepare("SELECT * FROM instance_identity WHERE instance_id = ?").get(instanceId);
  return descriptorFromRow(row, db);
}

// Seal arbitrary JSON-serializable data: a fresh AES-256 key is sealed to the
// hardware root (sealKey) and the data is AES-256-GCM encrypted under it. The
// sealed key will not unseal on different hardware, so the envelope is bound to
// this instance's root of trust. Returns a Buffer for the caller to store.
function sealState(options) {
  options = options || {};
  const aesKey = crypto.randomBytes(32);
  const sealedKey = keystore.sealKey(aesKey);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(SEAL_ALG, aesKey, iv);
  const plaintext = Buffer.from(JSON.stringify({ v: options.data }), 'utf8');
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const envelope = {
    alg: SEAL_ALG,
    sk: Buffer.from(sealedKey).toString('base64'),
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: tag.toString('base64'),
  };
  return Buffer.from(JSON.stringify(envelope), 'utf8');
}

// Reverse of sealState: unseal the AES key in hardware and AES-256-GCM decrypt.
function unsealState(options) {
  options = options || {};
  const envelope = JSON.parse(Buffer.from(options.sealed).toString('utf8'));
  const aesKey = keystore.unsealKey(Buffer.from(envelope.sk, 'base64'));
  const decipher = crypto.createDecipheriv(SEAL_ALG, aesKey, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ct, 'base64')), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8')).v;
}

// Verify the identity is intact: the recorded fingerprint matches the public
// key, the hardware signing key is present and corresponds to that public key,
// and a fresh sign-then-verify round-trip succeeds. Returns { valid, reason }.
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
    const label = identity.instanceId;
    const der = keystore.getSigningPublicKey(label);
    if (!der) {
      return { valid: false, reason: 'hardware signing key not present' };
    }
    if (fingerprintOfDer(der) !== identity.fingerprint) {
      return { valid: false, reason: 'hardware key does not match recorded public key' };
    }
    const nonce = crypto.randomBytes(32);
    const signature = keystore.sign(label, nonce);
    const publicKey = crypto.createPublicKey(identity.publicKey);
    const ok = crypto.verify('sha256', nonce, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
    if (!ok) {
      return { valid: false, reason: 'hardware key signature did not verify' };
    }
    return { valid: true, reason: null };
  } catch (err) {
    return { valid: false, reason: err && err.message ? err.message : String(err) };
  }
}

// Sign arbitrary bytes with the hardware instance key (ECDSA P-256, raw r||s /
// IEEE P1363 over a SHA-256 digest). Returns a Buffer, or null if no identity.
function sign(options) {
  options = options || {};
  const db = options.db;
  const identity = options.identity || load({ db: db });
  if (!identity) {
    return null;
  }
  const data = Buffer.isBuffer(options.data) ? options.data : Buffer.from(String(options.data));
  return keystore.sign(identity.instanceId, data);
}

// Advance the instance-level monotonic ratchet and stamp the attestation time.
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
  fingerprintOfDer,
  derToPem,
};

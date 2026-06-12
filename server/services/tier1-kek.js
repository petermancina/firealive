// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Tier-1 KEK (hardware-sealed, recovery-coded)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The Tier-1 KEK is the AES-256-GCM key encrypting server-side secrets at rest
// (integration credentials, every signing-key private key, the CA key). Under
// decision D26 it is HARDWARE-SEALED and fail-closed: the value carried in the
// TIER1_ENCRYPTION_KEY environment variable is no longer a raw hex key but an
// opaque wrapper (prefix below) that only the host TPM 2.0 / Secure Enclave can
// unseal. A copied disk or cloned VM cannot unseal it, so the secrets it guards
// stay inert off the original hardware. A raw key is REFUSED -- there is no
// software path, because a raw key in the environment is exactly the exposure a
// clone would copy.
//
// Because the sealed KEK dies with the hardware, provisioning also emits a one-
// time RECOVERY CODE: the same KEK bytes wrapped under an operator passphrase
// (scrypt + AES-256-GCM). It is shown once and kept OFFLINE. On hardware loss the
// operator re-establishes the identical KEK from the recovery code on a new
// machine, re-seals it to the new root of trust, and restores from backup -- a
// backup is encrypted UNDER this KEK and cannot be opened without it. The
// recovery code never lives on the running server, so it does not weaken the
// anti-clone property. Backing up the server AND keeping the recovery code
// offline are both essential; neither alone can recover a failed deployment.
//
// This module is the single resolver both consumers call: encryption.js (the
// just-in-time encryptConfig / decryptConfig chokepoint) and the env-var KMS key-
// wrapping provider used by the backup engine. The unsealed KEK is cached in
// process memory so the hardware is touched once per process, not per operation.
//
// The unseal leaf operation needs real hardware (none in CI), so that path ships
// platform-validation-pending. The recovery-code make/recover round-trip and the
// fail-closed resolution rules are pure software and fully covered by tests.

const crypto = require('crypto');

const KEK_BYTES = 32;
const SEAL_PREFIX = 'fa-tier1-hwseal:v1:';
const RECOVERY_PREFIX = 'fa-tier1-recovery:v1:';
const MIN_PASSPHRASE_LENGTH = 12;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

let cachedKek = null;

function assertKek(buf) {
  if (!Buffer.isBuffer(buf) || buf.length !== KEK_BYTES) {
    throw new Error('expected a ' + KEK_BYTES + '-byte Tier-1 KEK');
  }
}

function assertPassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error('recovery passphrase must be at least ' + MIN_PASSPHRASE_LENGTH + ' characters');
  }
}

function keystore() {
  return require('./instance-anchor/hardware-keystore');
}

// Generate a fresh random Tier-1 KEK. Used only at provisioning time.
function generateKek() {
  return crypto.randomBytes(KEK_BYTES);
}

// Seal a raw KEK to this hardware and return the TIER1_ENCRYPTION_KEY wrapper
// string. Throws (fail-closed) if no hardware root of trust is present.
function sealKekToWrapper(rawKek) {
  assertKek(rawKek);
  const sealed = keystore().sealKey(rawKek);
  if (!Buffer.isBuffer(sealed) || sealed.length === 0) {
    throw new Error('hardware keystore returned an empty sealed blob');
  }
  return SEAL_PREFIX + sealed.toString('base64');
}

// Resolve the raw Tier-1 KEK for use by the encryption chokepoint and the backup
// KMS provider. Reads TIER1_ENCRYPTION_KEY, which MUST be a hardware-sealed
// wrapper; unseals it on this hardware and caches the result. Fail-closed on a
// missing value, a raw (non-sealed) value, or an unseal failure.
function resolveTier1Kek() {
  if (cachedKek) {
    return cachedKek;
  }
  const raw = process.env.TIER1_ENCRYPTION_KEY;
  if (!raw || raw === 'CHANGE_ME' || raw.indexOf('CHANGE_ME') === 0) {
    throw new Error('TIER1_ENCRYPTION_KEY is not configured. Provision the hardware-sealed Tier-1 KEK with: node scripts/provision-tier1-kek.js');
  }
  if (raw.indexOf(SEAL_PREFIX) !== 0) {
    throw new Error('TIER1_ENCRYPTION_KEY must be a hardware-sealed value beginning ' + SEAL_PREFIX + ' -- a raw key is refused (fail-closed, decision D26). Provision with: node scripts/provision-tier1-kek.js, or recover on new hardware with: node scripts/recover-tier1-kek.js');
  }
  const sealedBlob = Buffer.from(raw.slice(SEAL_PREFIX.length), 'base64');
  let kek;
  try {
    kek = keystore().unsealKey(sealedBlob);
  } catch (err) {
    const detail = err && err.message ? err.message : String(err);
    throw new Error('Tier-1 KEK could not be unsealed on this hardware: ' + detail + '. If the TPM or Secure Enclave changed, recover with: node scripts/recover-tier1-kek.js');
  }
  assertKek(kek);
  cachedKek = kek;
  return cachedKek;
}

// Wrap a raw KEK under an operator passphrase, producing the one-time recovery
// code that is shown once at provisioning and stored offline.
function makeRecoveryCode(rawKek, passphrase) {
  assertKek(rawKek);
  assertPassphrase(passphrase);
  const salt = crypto.randomBytes(SALT_BYTES);
  const derived = crypto.scryptSync(Buffer.from(passphrase, 'utf-8'), salt, KEK_BYTES, SCRYPT_PARAMS);
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', derived, iv);
  const ct = Buffer.concat([cipher.update(rawKek), cipher.final()]);
  const tag = cipher.getAuthTag();
  const payload = Buffer.concat([salt, iv, tag, ct]);
  return RECOVERY_PREFIX + payload.toString('base64');
}

// Re-establish the identical KEK bytes from a recovery code and its passphrase,
// for disaster recovery on replacement hardware.
function recoverKekFromCode(recoveryCode, passphrase) {
  if (typeof recoveryCode !== 'string' || recoveryCode.indexOf(RECOVERY_PREFIX) !== 0) {
    throw new Error('not a Tier-1 recovery code (expected a value beginning ' + RECOVERY_PREFIX + ')');
  }
  assertPassphrase(passphrase);
  const payload = Buffer.from(recoveryCode.slice(RECOVERY_PREFIX.length), 'base64');
  if (payload.length < SALT_BYTES + IV_BYTES + TAG_BYTES + KEK_BYTES) {
    throw new Error('Tier-1 recovery code is truncated or corrupted');
  }
  const salt = payload.subarray(0, SALT_BYTES);
  const iv = payload.subarray(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const tag = payload.subarray(SALT_BYTES + IV_BYTES, SALT_BYTES + IV_BYTES + TAG_BYTES);
  const ct = payload.subarray(SALT_BYTES + IV_BYTES + TAG_BYTES);
  const derived = crypto.scryptSync(Buffer.from(passphrase, 'utf-8'), salt, KEK_BYTES, SCRYPT_PARAMS);
  const decipher = crypto.createDecipheriv('aes-256-gcm', derived, iv);
  decipher.setAuthTag(tag);
  let kek;
  try {
    kek = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch (err) {
    throw new Error('Tier-1 recovery failed -- wrong passphrase or corrupted recovery code');
  }
  assertKek(kek);
  return kek;
}

function _resetCacheForTests() {
  cachedKek = null;
}

module.exports = {
  KEK_BYTES,
  SEAL_PREFIX,
  RECOVERY_PREFIX,
  generateKek,
  sealKekToWrapper,
  resolveTier1Kek,
  makeRecoveryCode,
  recoverKekFromCode,
  _resetCacheForTests,
};

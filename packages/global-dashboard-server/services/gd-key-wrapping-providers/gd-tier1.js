'use strict';

// =============================================================================
// FIREALIVE GD -- gd-tier1 key-wrapping provider  [B6g]
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
//
// The GD's local scheme, and the only one that existed before B6g. It wraps the
// per-backup ephemeral data key under the GD Tier-1 KEK -- hardware-sealed to
// this host's TPM 2.0 / Secure Enclave, so a copied disk or cloned VM cannot
// unseal it.
//
// THIS FILE IS A REFACTOR, NOT A NEW CAPABILITY. Every byte it produces must be
// what gd-backup-key-wrapping.js produced before the registry existed, because
// EVERY GD BACKUP EVER TAKEN carries a wrapped-key.bin in that exact format and
// must still restore. Three things are therefore copied verbatim rather than
// re-derived:
//
//   1. THE WRAPPED PAYLOAD. encryptConfigWithKey({ k: <base64 of the raw key> },
//      deriveKek()) -- an object with a single key `k`, not the raw buffer, and
//      not any other property name. The gd-encryption envelope STRING is then
//      utf-8 -> base64 for the outer envelope's `wrapped` field. Changing the
//      property name, the encoding, or the double-encoding breaks every existing
//      archive.
//
//   2. THE KEK FINGERPRINT. gdTier1Kek.ownKekFingerprint().toString('hex').
//      NOT base.kekFpFromMaterial and NOT base.kekFpFromReference. The Regional
//      Server's providers fingerprint through a domain-separated hash
//      ('fa-backup-kek:v1'); the GD's existing manifests record the own-KEK
//      fingerprint directly and never use that domain at all. Twinning the MC's
//      helper here would produce a different fingerprint for the same KEK, and
//      every manifest already written would fail its check on restore.
//
//      The four cloud providers added by B6g DO use the domain-separated
//      reference helper, because they are new and no GD manifest records them.
//
//   3. THE ENVELOPE SHAPE {v, scheme, ref, wrapped}, owned by
//      gd-backup-key-wrapping.js and unchanged.
//
// SECURITY TIER 1, not the Regional Server's env-var tier 3. That difference is
// the point of the scheme rather than a bookkeeping detail: the MC's env-var KEK
// is a hex string sitting in the process environment, readable by anything that
// can read /proc or a core dump. The GD's is sealed to hardware and unwrapped
// only by the TPM on this host. They are not the same control with a different
// name.
//
// NO CREDENTIALS. There is nothing to store: the KEK is derived from the host,
// not supplied by an operator. validateCredentials REFUSES anything non-null
// rather than ignoring it, because an operator who thinks they have configured a
// credential here has misunderstood what this provider is, and silently
// discarding it would leave them believing a secret is protecting something.

const base = require('./base');
const { encryptConfigWithKey, decryptConfigWithKey, deriveKek } = require('../gd-encryption');
const gdTier1Kek = require('../gd-tier1-kek');

const PROVIDER_NAME = 'gd-tier1';

// Tier 1: KEK sealed to hardware this host holds. See the header for why this is
// not the MC env-var provider's tier 3.
const SECURITY_TIER = 1;

const KEY_LENGTH_BYTES = 32; // AES-256 data key

// The stable reference recorded in the manifest. There is one KEK per GD, so the
// reference is a constant rather than a key id -- but it is still carried, and
// still checked on unwrap, because the manifest's {scheme, ref} pair is what
// restore dispatches on.
const KEK_REFERENCE = 'GD_ENCRYPTION_KEY';

function validateConfig(config) {
  // No configurable surface. Accepting arbitrary keys here would let an operator
  // believe they had configured something that is not read.
  if (config && typeof config === 'object') {
    const keys = Object.keys(config);
    if (keys.length > 0) {
      return {
        ok: false,
        error: 'gd-tier1 takes no configuration; unexpected keys: ' + keys.join(', '),
        field: keys[0],
      };
    }
  }
  return { ok: true };
}

function validateCredentials(credentials) {
  if (credentials === null || credentials === undefined) return { ok: true };
  return {
    ok: false,
    error: 'gd-tier1 does not accept credentials: the KEK is sealed to this host and '
      + 'is never operator-supplied. Nothing you enter here would protect anything.',
  };
}

/**
 * Wrap the per-backup ephemeral data key.
 *
 * Returns the gd-encryption envelope STRING, utf-8 -> base64. The caller
 * (gd-backup-key-wrapping.js) puts that in the outer envelope's `wrapped` field.
 * Byte-for-byte what the pre-registry implementation produced.
 */
async function wrap(plaintextDek, _config, _credentials, _options) {
  if (!Buffer.isBuffer(plaintextDek) || plaintextDek.length !== KEY_LENGTH_BYTES) {
    throw new base.KeyWrappingError(
      'gd-tier1 wrap: plaintextDek must be a ' + KEY_LENGTH_BYTES + '-byte Buffer',
      { provider: PROVIDER_NAME, operation: 'wrap', retryable: false },
    );
  }
  // { k: <base64> } exactly -- see header note 1.
  const gdEnvelope = encryptConfigWithKey({ k: plaintextDek.toString('base64') }, deriveKek());
  return Buffer.from(gdEnvelope, 'utf-8').toString('base64');
}

/**
 * Unwrap back to the raw 32-byte data key.
 *
 * Accepts the base64 form this provider's wrap() produced.
 */
async function unwrap(wrappedDek, _config, _credentials, _options) {
  let obj;
  try {
    const gdEnvelope = Buffer.from(String(wrappedDek), 'base64').toString('utf-8');
    obj = decryptConfigWithKey(gdEnvelope, deriveKek());
  } catch (err) {
    // The failure mode that matters: this is what a wrong KEK looks like, and on
    // the GD a wrong KEK usually means the archive is being opened on hardware
    // that did not seal it. Say so, because "decrypt failed" sends an operator
    // hunting for a corrupt file.
    throw new base.KeyWrappingError(
      'gd-tier1 unwrap failed: the wrapped key did not open under this host Tier-1 KEK. '
      + 'A v2 archive stays sealed to the hardware that produced it; recovering on '
      + 'replacement hardware means re-establishing the KEK from the offline recovery code.',
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false, cause: err },
    );
  }
  if (!obj || typeof obj.k !== 'string') {
    throw new base.KeyWrappingError(
      'gd-tier1 unwrap: envelope opened but carried no key',
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  const key = Buffer.from(obj.k, 'base64');
  if (key.length !== KEY_LENGTH_BYTES) {
    throw new base.KeyWrappingError(
      'gd-tier1 unwrap: recovered key is ' + key.length + ' bytes, expected ' + KEY_LENGTH_BYTES,
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  return key;
}

/**
 * Round-trip probe. Local only -- there is no external service to reach, so this
 * proves the KEK is available and self-consistent, which is the whole of what
 * this provider depends on.
 */
async function probe(config, credentials, options) {
  return base.probeRoundTrip(provider, config, credentials, options);
}

/**
 * The KEK fingerprint recorded in the manifest.
 *
 * gdTier1Kek.ownKekFingerprint().toString('hex') -- NOT base.kekFpFromMaterial.
 * See header note 2: the MC's domain-separated helper would produce a different
 * fingerprint for the same KEK, and every GD manifest already written would fail
 * its check on restore.
 */
function kekFingerprint(_config) {
  return gdTier1Kek.ownKekFingerprint().toString('hex');
}

/**
 * Unwrap with a raw KEK supplied by the caller rather than this host's.
 *
 * Used ONLY by the offline import-rekey tool, where the source KEK is recovered
 * transiently from the source deployment's recovery code. It is not a restore
 * path and must never be reachable from a request handler.
 */
function unwrapWithRawKek(wrappedDek, rawKek) {
  const gdEnvelope = Buffer.from(String(wrappedDek), 'base64').toString('utf-8');
  const obj = decryptConfigWithKey(gdEnvelope, rawKek);
  if (!obj || typeof obj.k !== 'string') {
    throw new base.KeyWrappingError(
      'gd-tier1 unwrapWithRawKek: envelope opened but carried no key',
      { provider: PROVIDER_NAME, operation: 'unwrap', retryable: false },
    );
  }
  return Buffer.from(obj.k, 'base64');
}

const provider = {
  name: PROVIDER_NAME,
  description: 'GD Tier-1 KEK, hardware-sealed to this host TPM 2.0 / Secure Enclave. '
    + 'Tier 1 -- a copied disk or cloned VM cannot unseal it. No external custodian, '
    + 'so no foreign law reaches the wrapping key.',
  securityTier: SECURITY_TIER,
  kekReference: KEK_REFERENCE,
  validateConfig,
  validateCredentials,
  probe,
  wrap,
  unwrap,
  unwrapWithRawKek,
  kekFingerprint,
};

base.registerProvider(provider);

module.exports = provider;

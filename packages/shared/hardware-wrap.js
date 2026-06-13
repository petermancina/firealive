'use strict';

//
// FireAlive -- shared cross-platform hardware data-wrap seam (client at-rest key wrap).
//
// Client-side counterpart to the sign-only device-identity seam (./hardware-key.js).
// Runs in an Electron main process (the AC today, per D27). Where hardware-key.js
// gives a client a non-exportable signing key to PROVE possession, this seam gives
// a client a non-exportable ECDH key-agreement key to WRAP a data key at rest, so a
// wrapped blob cannot be unwrapped off this machine. The two seams are deliberately
// separate: device identity signs (hardware-key.js); data keys are wrapped by key
// agreement (here). This keeps D18 separation between MACHINE-bound identity and
// USER-bound recoverable data keys.
//
// PURPOSE (decision D27): an OPTIONAL hardware-bound at-rest wrap of the analyst
// burnout data key, added ALONGSIDE the WebAuthn-PRF and scrypt factors. The wrap is
// ECIES-style and assembled by the caller: to WRAP, the caller generates an ephemeral
// P-256 key, derives a KEK by ECDH against this key public point (getWrapPublicKey)
// in software, and AES-GCM-wraps the data key; to UNWRAP, the caller calls
// agree(label, ephemeralPublic) so the HARDWARE recomputes the same shared secret
// from its private key -- which is why the blob is useless on other hardware.
//
// FAIL-CLOSED, BUT OPTIONAL (the difference from hardware-key.js): like the identity
// seam, this seam has NO software key-agreement fallback -- with no usable hardware
// root, isAvailable() is false and the key operations throw
// HardwareWrapUnavailableError; it never performs a software ECDH dressed up as
// hardware. UNLIKE the identity seam, the caller treats the hardware factor as an
// OPTIONAL, additive layer: when this seam is unavailable the caller does not hard
// stop -- it simply does not offer the hardware factor and falls back to the
// passkey-recoverable PRF / scrypt factors, so recoverability is unchanged.
//
// Platform backends (loaded lazily, one per OS):
//   linux  -> ./hardware-wrap-linux    (TPM 2.0; tpm2-tools, TPM2_ECDH_ZGen)
//   win32  -> ./hardware-wrap-windows   (TPM 2.0; CNG Platform Crypto Provider, NCrypt secret agreement)
//   darwin -> ./hardware-wrap-macos     (Secure Enclave; SecKey, ECDHKeyExchangeStandard)
//
// Backend contract (each per-OS backend module exports):
//   kind                    -- short string naming the root of trust
//   isAvailable()           -- true only when a usable hardware root is present
//   createWrapKey(label)    -- create a non-exportable ECDH key-agreement key,
//                              replacing any existing key at this label; return its
//                              public key as SPKI DER (Buffer). The portable curve is
//                              P-256 (both TPM 2.0 and the Secure Enclave support
//                              P-256 ECDH); the SPKI DER carries the curve.
//   getWrapPublicKey(label) -- SPKI DER (Buffer) for an existing key, or null. Used
//                              by the caller for the (software) wrap side.
//   hasWrapKey(label)       -- true if a key exists at this label
//   deleteWrapKey(label)    -- remove the key (teardown / re-mint); return true if a
//                              key was removed
//   agree(label, peerDer)   -- compute the ECDH shared secret on-chip between this
//                              key and a peer public key given as SPKI DER (Buffer);
//                              return the shared secret Buffer -- the 32-byte
//                              X-coordinate of the shared point (the SEC1 / SP
//                              800-56A Z value). The caller derives a KEK from it
//                              with HKDF; this seam returns Z only and performs no
//                              key derivation itself.
//
// The hardware leaf operations (createWrapKey, agree) cannot be exercised without
// real hardware (no TPM / Secure Enclave in CI), so the backends ship
// platform-validation-pending. This seam own logic -- platform dispatch, availability
// gating, and the fail-closed contract -- is fully testable, and that is what its
// tests cover.

const HARDWARE_ROOT_LABEL = 'TPM 2.0 / Secure Enclave';

class HardwareWrapUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = 'HardwareWrapUnavailableError';
  }
}

function backendModuleForPlatform(platform) {
  if (platform === 'linux') {
    return './hardware-wrap-linux';
  }
  if (platform === 'win32') {
    return './hardware-wrap-windows';
  }
  if (platform === 'darwin') {
    return './hardware-wrap-macos';
  }
  return null;
}

let backendResolved = false;
let backend = null;

function loadBackend() {
  if (backendResolved) {
    return backend;
  }
  backendResolved = true;
  backend = null;
  const moduleName = backendModuleForPlatform(process.platform);
  if (!moduleName) {
    return null;
  }
  try {
    backend = require(moduleName);
  } catch (err) {
    // Absent or unloadable backend is a fail-closed condition, never a fallback.
    backend = null;
  }
  return backend;
}

function isAvailable() {
  const b = loadBackend();
  if (!b || typeof b.isAvailable !== 'function') {
    return false;
  }
  try {
    return b.isAvailable() === true;
  } catch (err) {
    return false;
  }
}

function describe() {
  const b = loadBackend();
  return {
    platform: process.platform,
    backend: b && typeof b.kind === 'string' ? b.kind : null,
    available: isAvailable(),
  };
}

function requireBackend() {
  const b = loadBackend();
  if (!b) {
    throw new HardwareWrapUnavailableError(
      'No hardware data-wrap backend for platform ' + process.platform +
      '. A hardware root of trust (' + HARDWARE_ROOT_LABEL + ') is required to wrap ' +
      'or unwrap with the hardware factor; this seam fails closed and performs no ' +
      'software key agreement. The hardware factor is optional: callers fall back to ' +
      'their passkey-recoverable factors when it is absent.'
    );
  }
  if (!isAvailable()) {
    throw new HardwareWrapUnavailableError(
      'Hardware root of trust (' + HARDWARE_ROOT_LABEL + ') not detected on this ' +
      process.platform + ' host. The hardware data-wrap factor fails closed and ' +
      'performs no software key agreement; callers fall back to their ' +
      'passkey-recoverable factors.'
    );
  }
  return b;
}

function createWrapKey(label) {
  return requireBackend().createWrapKey(label);
}

function getWrapPublicKey(label) {
  return requireBackend().getWrapPublicKey(label);
}

function hasWrapKey(label) {
  return requireBackend().hasWrapKey(label) === true;
}

function deleteWrapKey(label) {
  return requireBackend().deleteWrapKey(label) === true;
}

function agree(label, peerPublicDer) {
  return requireBackend().agree(label, peerPublicDer);
}

module.exports = {
  isAvailable,
  describe,
  createWrapKey,
  getWrapPublicKey,
  hasWrapKey,
  deleteWrapKey,
  agree,
  backendModuleForPlatform,
  HardwareWrapUnavailableError,
};

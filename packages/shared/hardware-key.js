'use strict';

//
// FireAlive -- shared cross-platform hardware keystore seam (client device keys).
//
// Client-side counterpart to server/services/instance-anchor/hardware-keystore.js.
// Runs in an Electron main process (AC / MC / GD app). It is the single seam
// through which a client creates its non-exportable device signing key and signs
// with it on-chip; the private key never leaves the hardware. The server anchor
// uses the server seam; the client device keys use this one. The two mirror the
// same contract so a device key is as hardware-rooted as a deployment identity.
//
// SCOPE (decision D26): a hardware root of trust is REQUIRED and this seam fails
// closed without one. There is NO safeStorage fallback -- a client with no usable
// hardware root cannot mint or use a device key, and the caller must treat that
// as a hard stop (refuse to enroll or run) rather than degrade to a software key.
// Device keys are sign-only: this seam deliberately exposes no seal/unseal or
// NV-counter operations (those are server-anchor concerns); a device key only
// proves possession by signing.
//
// Platform backends (loaded lazily, one per OS):
//   linux  -> ./hardware-key-linux    (TPM 2.0; kernel resource manager / tpm2-tools)
//   win32  -> ./hardware-key-windows   (TPM 2.0; CNG Platform Crypto Provider)
//   darwin -> ./hardware-key-macos     (Secure Enclave; SecKey)
//
// Fail-closed contract: there is NO software fallback. If the platform is
// unsupported, the backend module is absent, or the backend reports no usable
// hardware, then isAvailable() returns false and every key operation throws
// HardwareKeyUnavailableError.
//
// Backend contract (each per-OS backend module exports):
//   kind                       -- short string naming the root of trust
//   isAvailable()              -- true only when a usable hardware root is present
//   createSigningKey(label)    -- create a non-exportable signing key, replacing
//                                 any existing key at this label; return its public
//                                 key as SPKI DER (Buffer). The portable algorithm
//                                 is ECDSA P-256 (both TPM 2.0 and the Secure
//                                 Enclave support it; Ed25519 is not universally
//                                 available in the Secure Enclave). The SPKI DER
//                                 carries the algorithm, so verifiers derive it
//                                 from the key rather than assuming one.
//   getSigningPublicKey(label) -- SPKI DER (Buffer) for an existing key, or null
//   hasSigningKey(label)       -- true if a key exists at this label
//   deleteSigningKey(label)    -- remove the key (used on teardown / re-mint);
//                                 return true if a key was removed
//   sign(label, data)          -- sign a Buffer on-chip; return the signature
//                                 Buffer (raw r||s, IEEE P1363, over SHA-256)
//
// The hardware leaf operations cannot be exercised without real hardware (no TPM
// / Secure Enclave in CI), so the backends ship platform-validation-pending. This
// seam's own logic -- platform dispatch, availability gating, and the fail-closed
// contract -- is fully testable, and that is what its tests cover.

const HARDWARE_ROOT_LABEL = 'TPM 2.0 / Secure Enclave';

class HardwareKeyUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = 'HardwareKeyUnavailableError';
  }
}

function backendModuleForPlatform(platform) {
  if (platform === 'linux') {
    return './hardware-key-linux';
  }
  if (platform === 'win32') {
    return './hardware-key-windows';
  }
  if (platform === 'darwin') {
    return './hardware-key-macos';
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
    throw new HardwareKeyUnavailableError(
      'No hardware keystore backend for platform ' + process.platform +
      '. A hardware root of trust (' + HARDWARE_ROOT_LABEL + ') is required; ' +
      'this client will not mint or use a device key without it.'
    );
  }
  if (!isAvailable()) {
    throw new HardwareKeyUnavailableError(
      'Hardware root of trust (' + HARDWARE_ROOT_LABEL + ') not detected on this ' +
      process.platform + ' host. FireAlive fails closed and will not create or use ' +
      'a device key without it.'
    );
  }
  return b;
}

function createSigningKey(label) {
  return requireBackend().createSigningKey(label);
}

function getSigningPublicKey(label) {
  return requireBackend().getSigningPublicKey(label);
}

function hasSigningKey(label) {
  return requireBackend().hasSigningKey(label) === true;
}

function deleteSigningKey(label) {
  return requireBackend().deleteSigningKey(label) === true;
}

function sign(label, data) {
  return requireBackend().sign(label, data);
}

module.exports = {
  isAvailable,
  describe,
  createSigningKey,
  getSigningPublicKey,
  hasSigningKey,
  deleteSigningKey,
  sign,
  backendModuleForPlatform,
  HardwareKeyUnavailableError,
};

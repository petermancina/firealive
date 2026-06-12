// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Hardware Keystore (cross-platform seam)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The GD Server is an independent backend and shares no modules with server/;
// this is its own copy of the hardware keystore seam, mirroring server/services/
// instance-anchor/hardware-keystore.js. Platform glue is identical; only the
// header, the backend module names, and the key-label namespace differ.
//
// CROSS-PLATFORM HARDWARE KEYSTORE SEAM (B5e, decision D26)
//
// FireAlive requires a hardware root of trust and fails closed without one
// (D26, which withdraws the earlier software-fallback posture). This module is
// the single seam through which both identity layers create non-exportable
// keys, sign with them on-chip, seal small secrets, and drive a monotonic
// anti-rollback counter. The server deployment anchor uses it directly; the
// client device keys use the shared client seam that mirrors this contract.
// Private key material never leaves the hardware.
//
// Platform backends (loaded lazily, one per OS):
//   linux  -> ./gd-hardware-keystore-linux    (TPM 2.0; kernel resource manager / tpm2-tools)
//   win32  -> ./gd-hardware-keystore-windows   (TPM 2.0; CNG Platform Crypto Provider)
//   darwin -> ./gd-hardware-keystore-macos     (Secure Enclave; SecKey)
//
// Fail-closed contract: there is NO software fallback. If the platform is
// unsupported, the backend module is absent, or the backend reports no usable
// hardware, then isAvailable() returns false and every key operation throws
// HardwareKeystoreUnavailableError. The anchor must treat that as a hard stop --
// refuse to establish or load identity -- never as a reason to run degraded.
//
// Backend contract (each per-OS backend module exports):
//   kind                       -- short string naming the root of trust
//   isAvailable()              -- true only when a usable hardware root is present
//   createSigningKey(label)    -- create a non-exportable signing key; return its
//                                 public key as SPKI DER (Buffer). The portable
//                                 algorithm is ECDSA P-256: both TPM 2.0 and the
//                                 Secure Enclave support it, whereas Ed25519 is
//                                 not universally available in the Secure Enclave.
//                                 The SPKI DER carries the algorithm, so verifiers
//                                 derive it from the key rather than assuming one.
//   getSigningPublicKey(label) -- SPKI DER (Buffer) for an existing key, or null
//   sign(label, data)          -- sign a Buffer on-chip; return the signature Buffer
//   sealKey(keyBuffer)         -- seal a small secret to this hardware; return an
//                                 opaque sealed Buffer that will NOT unseal on any
//                                 other hardware
//   unsealKey(sealedBlob)      -- unseal; throw if not the same hardware
//   nvDefineCounter(index)     -- define a monotonic NV counter (idempotent)
//   nvReadCounter(index)       -- read the counter value
//   nvIncrementCounter(index)  -- increment; return the new value
//
// The hardware leaf operations cannot be exercised without real hardware (no
// TPM / Secure Enclave in CI), so the backends ship platform-validation-pending.
// This seam's own logic -- platform dispatch, availability gating, and the
// fail-closed contract -- is fully testable, and that is what its tests cover.

const HARDWARE_ROOT_LABEL = 'TPM 2.0 / Secure Enclave';

class HardwareKeystoreUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = 'HardwareKeystoreUnavailableError';
  }
}

function backendModuleForPlatform(platform) {
  if (platform === 'linux') {
    return './gd-hardware-keystore-linux';
  }
  if (platform === 'win32') {
    return './gd-hardware-keystore-windows';
  }
  if (platform === 'darwin') {
    return './gd-hardware-keystore-macos';
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
    throw new HardwareKeystoreUnavailableError(
      'No hardware keystore backend for platform ' + process.platform +
      '. A hardware root of trust (' + HARDWARE_ROOT_LABEL + ') is required; ' +
      'FireAlive will not establish identity without it.'
    );
  }
  if (!isAvailable()) {
    throw new HardwareKeystoreUnavailableError(
      'Hardware root of trust (' + HARDWARE_ROOT_LABEL + ') not detected on this ' +
      process.platform + ' host. FireAlive fails closed and will not establish or ' +
      'load identity without it.'
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

function sign(label, data) {
  return requireBackend().sign(label, data);
}

function sealKey(keyBuffer) {
  return requireBackend().sealKey(keyBuffer);
}

function unsealKey(sealedBlob) {
  return requireBackend().unsealKey(sealedBlob);
}

function nvDefineCounter(index) {
  return requireBackend().nvDefineCounter(index);
}

function nvReadCounter(index) {
  return requireBackend().nvReadCounter(index);
}

function nvIncrementCounter(index) {
  return requireBackend().nvIncrementCounter(index);
}

module.exports = {
  isAvailable,
  describe,
  createSigningKey,
  getSigningPublicKey,
  sign,
  sealKey,
  unsealKey,
  nvDefineCounter,
  nvReadCounter,
  nvIncrementCounter,
  backendModuleForPlatform,
  HardwareKeystoreUnavailableError,
};

// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Instance Anchor (macOS Secure Enclave keystore backend)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// macOS SECURE ENCLAVE BACKEND (B5e, decision D26) -- PLATFORM-VALIDATION-PENDING
//
// Implements the hardware-keystore backend contract on macOS using the Secure
// Enclave through the Security framework (SecKey), driven by a small Swift
// helper. Honest status: there is no macOS host in this build environment, so
// the helper never executes here. The SecKey calls use documented APIs but are
// platform-validation-pending and verified on real macOS + Secure Enclave
// hardware. What IS verified by this module's tests: availability detection,
// helper argv construction, the X9.63-point to SPKI-DER public-key conversion,
// SHA-256 digest hashing, output parsing, and fail-closed behaviour (a helper
// error propagates; no fallback).
//
// Helper runner: in production set FIREALIVE_SE_HELPER to a bundled, signed,
// compiled helper binary; in development the Swift source below is run with the
// swift interpreter (FIREALIVE_SWIFT, default "swift"). Either way the protocol
// is the same: argv = [op, ...], base64 (or NULL / YES / NO) on stdout, non-zero
// exit on error.
//
// Key model:
//   - Signing keys are EC P-256 keys created in the Secure Enclave
//     (kSecAttrTokenIDSecureEnclave), permanent, addressed by application tag;
//     the private key never leaves the enclave, so a copied disk cannot use it.
//     Signatures use ECDSASignatureDigestRFC4754 over a SHA-256 digest computed
//     here, giving raw r||s (IEEE P1363) to match the other backends; the public
//     key is returned as an X9.63 point and wrapped to SPKI DER in Node.
//   - Sealing uses a Secure-Enclave EC key with ECIES
//     (eciesEncryptionCofactorX963SHA256AESGCM): sealKey encrypts to the public
//     half, unsealKey decrypts in the enclave. Suitable for small secrets.
//
// KNOWN GAP (validation-pending): the Secure Enclave has no monotonic NV
// counter, so the nv* methods throw; the anti-rollback high-water (D7) is the
// software primary, with the required-vs-best-effort decision left to the
// rollback-hardening commit (matching the Windows backend).

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const KIND = 'secure-enclave';

const SWIFT_HELPER = `import Foundation
import Security
import CryptoKit

let SIGN_TAG = "com.firealive.sign."
let SEAL_TAG = "com.firealive.seal"

func emitError(_ message: String) {
  FileHandle.standardError.write(Data(message.utf8))
  exit(1)
}

func loadKey(_ tag: String) -> SecKey? {
  let query: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrApplicationTag as String: Data(tag.utf8),
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecReturnRef as String: true,
  ]
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)
  if status == errSecSuccess, let key = item {
    return (key as! SecKey)
  }
  return nil
}

func createKey(_ tag: String) -> SecKey {
  var error: Unmanaged<CFError>?
  guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error) else {
    emitError("access control failed")
    exit(1)
  }
  let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
      kSecAttrIsPermanent as String: true,
      kSecAttrApplicationTag as String: Data(tag.utf8),
      kSecAttrAccessControl as String: access,
    ],
  ]
  guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    emitError("key creation failed")
    exit(1)
  }
  return key
}

func publicPoint(_ key: SecKey) -> Data {
  guard let pub = SecKeyCopyPublicKey(key) else { emitError("no public key"); exit(1) }
  var error: Unmanaged<CFError>?
  guard let raw = SecKeyCopyExternalRepresentation(pub, &error) else { emitError("export failed"); exit(1) }
  return raw as Data
}

let arguments = CommandLine.arguments
if arguments.count < 2 { emitError("no op") }
let op = arguments[1]

switch op {
case "available":
  if SecureEnclave.isAvailable { print("YES") } else { print("NO") }
case "create":
  if arguments.count < 3 { emitError("no label") }
  let tag = SIGN_TAG + arguments[2]
  if loadKey(tag) != nil { emitError("signing key already exists") }
  let key = createKey(tag)
  print(publicPoint(key).base64EncodedString())
case "getpub":
  if arguments.count < 3 { emitError("no label") }
  let tag = SIGN_TAG + arguments[2]
  guard let key = loadKey(tag) else { print("NULL"); exit(0) }
  print(publicPoint(key).base64EncodedString())
case "sign":
  if arguments.count < 4 { emitError("no digest") }
  let tag = SIGN_TAG + arguments[2]
  guard let key = loadKey(tag) else { emitError("no signing key"); exit(1) }
  guard let digest = Data(base64Encoded: arguments[3]) else { emitError("bad digest"); exit(1) }
  var error: Unmanaged<CFError>?
  guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureDigestRFC4754, digest as CFData, &error) else { emitError("sign failed"); exit(1) }
  print((sig as Data).base64EncodedString())
case "seal":
  if arguments.count < 3 { emitError("no secret") }
  guard let secret = Data(base64Encoded: arguments[2]) else { emitError("bad secret"); exit(1) }
  let key = loadKey(SEAL_TAG) ?? createKey(SEAL_TAG)
  guard let pub = SecKeyCopyPublicKey(key) else { emitError("no public key"); exit(1) }
  var error: Unmanaged<CFError>?
  guard let ct = SecKeyCreateEncryptedData(pub, .eciesEncryptionCofactorX963SHA256AESGCM, secret as CFData, &error) else { emitError("seal failed"); exit(1) }
  print((ct as Data).base64EncodedString())
case "unseal":
  if arguments.count < 3 { emitError("no blob") }
  guard let blob = Data(base64Encoded: arguments[2]) else { emitError("bad blob"); exit(1) }
  guard let key = loadKey(SEAL_TAG) else { emitError("no seal key"); exit(1) }
  var error: Unmanaged<CFError>?
  guard let pt = SecKeyCreateDecryptedData(key, .eciesEncryptionCofactorX963SHA256AESGCM, blob as CFData, &error) else { emitError("unseal failed"); exit(1) }
  print((pt as Data).base64EncodedString())
default:
  emitError("unknown op")
}`;

function swiftExe() {
  return process.env.FIREALIVE_SWIFT || 'swift';
}

function safeLabel(label) {
  return String(label).replace(/[^A-Za-z0-9._-]/g, '_');
}

const MACOS_SWIFT_PREFLIGHT = 'MACOS_SWIFT_PREFLIGHT';

// A hardware-backed keystore that fails cryptically could mask that the Secure Enclave root of
// trust is not actually present -- which an operator must know. So an unavailable macOS helper is
// surfaced as a clear, NAMED error (code MACOS_SWIFT_PREFLIGHT) rather than a raw spawn ENOENT.
function preflightError(detail) {
  const e = new Error('macOS Secure Enclave helper unavailable: ' + detail);
  e.code = MACOS_SWIFT_PREFLIGHT;
  return e;
}

// Verify the Secure Enclave helper can run before relying on it. Throws a named
// MACOS_SWIFT_PREFLIGHT error if the bundled helper is not executable or the Swift toolchain
// cannot run. Safe to call at startup for an early, actionable failure.
function preflight() {
  const custom = process.env.FIREALIVE_SE_HELPER;
  if (custom) {
    try {
      fs.accessSync(custom, fs.constants.X_OK);
    } catch (err) {
      throw preflightError('FIREALIVE_SE_HELPER="' + custom + '" is not an executable file (' + (err.code || err.message) + '); point it at the bundled, signed helper binary.');
    }
    return;
  }
  try {
    execFileSync(swiftExe(), ['--version'], { stdio: ['ignore', 'ignore', 'ignore'] });
  } catch (err) {
    throw preflightError('the Swift toolchain (' + swiftExe() + ') could not run (' + (err.code || err.message) + '); install the Xcode command-line tools, or set FIREALIVE_SE_HELPER to the bundled, signed helper binary.');
  }
}

function realRunHelper(args) {
  const custom = process.env.FIREALIVE_SE_HELPER;
  if (custom) {
    try {
      return execFileSync(custom, args, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        throw preflightError('FIREALIVE_SE_HELPER="' + custom + '" could not be executed (ENOENT); point it at the bundled, signed helper binary.');
      }
      throw err;
    }
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-se-'));
  const file = path.join(dir, 'helper.swift');
  try {
    fs.writeFileSync(file, SWIFT_HELPER);
    return execFileSync(swiftExe(), [file].concat(args), { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      throw preflightError('the Swift toolchain (' + swiftExe() + ') could not run (ENOENT); install the Xcode command-line tools, or set FIREALIVE_SE_HELPER to the bundled, signed helper binary.');
    }
    throw err;
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (err) {
      // best-effort cleanup
    }
  }
}

function toBase64Url(buf) {
  return buf.toString('base64url');
}

function x963ToSpkiDer(b64point) {
  const point = Buffer.from(b64point, 'base64');
  if (point.length !== 65 || point[0] !== 0x04) {
    throw new Error('hardware keystore (macos): unexpected public key point format');
  }
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: toBase64Url(point.subarray(1, 33)),
    y: toBase64Url(point.subarray(33, 65)),
  };
  const keyObj = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  return keyObj.export({ type: 'spki', format: 'der' });
}

function _isAvailable(run) {
  try {
    return String(run(['available'])).trim() === 'YES';
  } catch (err) {
    return false;
  }
}

function _createSigningKey(run, label) {
  const out = String(run(['create', safeLabel(label)])).trim();
  return x963ToSpkiDer(out);
}

function _getSigningPublicKey(run, label) {
  const out = String(run(['getpub', safeLabel(label)])).trim();
  if (out === 'NULL') {
    return null;
  }
  return x963ToSpkiDer(out);
}

function _sign(run, label, data) {
  const digest = crypto.createHash('sha256').update(data).digest();
  const out = String(run(['sign', safeLabel(label), digest.toString('base64')])).trim();
  return Buffer.from(out, 'base64');
}

function _sealKey(run, data) {
  const out = String(run(['seal', Buffer.from(data).toString('base64')])).trim();
  return Buffer.from(out, 'base64');
}

function _unsealKey(run, blob) {
  const out = String(run(['unseal', Buffer.from(blob).toString('base64')])).trim();
  return Buffer.from(out, 'base64');
}

function nvUnsupported() {
  throw new Error('hardware keystore (macos): the Secure Enclave has no monotonic NV counter; anti-rollback uses the software high-water (validation-pending integration)');
}

function isAvailable() {
  return _isAvailable(realRunHelper);
}

function createSigningKey(label) {
  return _createSigningKey(realRunHelper, label);
}

function getSigningPublicKey(label) {
  return _getSigningPublicKey(realRunHelper, label);
}

function sign(label, data) {
  return _sign(realRunHelper, label, data);
}

function sealKey(keyBuffer) {
  return _sealKey(realRunHelper, keyBuffer);
}

function unsealKey(sealedBlob) {
  return _unsealKey(realRunHelper, sealedBlob);
}

function nvDefineCounter(index) {
  return nvUnsupported();
}

function nvReadCounter(index) {
  return nvUnsupported();
}

function nvIncrementCounter(index) {
  return nvUnsupported();
}

module.exports = {
  kind: KIND,
  isAvailable,
  preflight,
  MACOS_SWIFT_PREFLIGHT,
  createSigningKey,
  getSigningPublicKey,
  sign,
  sealKey,
  unsealKey,
  nvDefineCounter,
  nvReadCounter,
  nvIncrementCounter,
  // internal seams exported for tests (argv construction / conversion / parsing / fail-closed)
  _isAvailable,
  _createSigningKey,
  _getSigningPublicKey,
  _sign,
  _sealKey,
  _unsealKey,
  x963ToSpkiDer,
  toBase64Url,
  safeLabel,
  SWIFT_HELPER,
};

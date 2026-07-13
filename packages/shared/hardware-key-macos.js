'use strict';

//
// FireAlive -- shared client hardware-key backend: macOS Secure Enclave.
//
// macOS backend for packages/shared/hardware-key.js (the client device-key seam),
// mirroring server/services/instance-anchor/hardware-keystore-macos.js but trimmed
// to the sign-only device-key subset (no seal/unseal/NV). PLATFORM-VALIDATION-PENDING:
// there is no macOS host in CI, so the Swift helper never executes here; the SecKey
// calls are documented APIs verified on real macOS + Secure Enclave hardware. What
// the tests verify: availability detection, helper argv construction, the X9.63-point
// to SPKI-DER conversion, SHA-256 digest hashing, output parsing, the key lifecycle
// (create / has / get-public / delete / sign, with replace-on-create), and fail-closed
// behaviour (a helper error propagates; no fallback).
//
// Helper runner: in production set FIREALIVE_CLIENT_SE_HELPER to a bundled, signed,
// compiled helper binary; in development the Swift source below runs with the swift
// interpreter (FIREALIVE_CLIENT_SWIFT, default "swift"). Protocol: argv = [op, ...],
// base64 (or NULL / YES / NO / DELETED / ABSENT) on stdout, non-zero exit on error.
//
// Key model:
//   - Device signing keys are EC P-256 keys created in the Secure Enclave
//     (kSecAttrTokenIDSecureEnclave), permanent, addressed by a client-namespaced
//     application tag (com.firealive.client.sign.<label>) so they never collide with
//     the server keystore; the private key never leaves the enclave, so a copied disk
//     cannot use it. Re-minting deletes the existing key and creates a fresh one.
//     Signatures use ECDSASignatureDigestRFC4754 over a SHA-256 digest computed here,
//     giving raw r||s (IEEE P1363); the public key is returned as an X9.63 point and
//     wrapped to SPKI DER in Node.

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const KIND = 'secure-enclave';

const SWIFT_HELPER = `import Foundation
import Security
import CryptoKit

let SIGN_TAG = "com.firealive.client.sign."

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

func deleteKey(_ tag: String) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrApplicationTag as String: Data(tag.utf8),
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
  ]
  let status = SecItemDelete(query as CFDictionary)
  return status == errSecSuccess
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
  _ = deleteKey(tag)
  let key = createKey(tag)
  print(publicPoint(key).base64EncodedString())
case "getpub":
  if arguments.count < 3 { emitError("no label") }
  let tag = SIGN_TAG + arguments[2]
  guard let key = loadKey(tag) else { print("NULL"); exit(0) }
  print(publicPoint(key).base64EncodedString())
case "has":
  if arguments.count < 3 { emitError("no label") }
  let tag = SIGN_TAG + arguments[2]
  if loadKey(tag) != nil { print("YES") } else { print("NO") }
case "delete":
  if arguments.count < 3 { emitError("no label") }
  let tag = SIGN_TAG + arguments[2]
  if loadKey(tag) != nil { _ = deleteKey(tag); print("DELETED") } else { print("ABSENT") }
case "sign":
  if arguments.count < 4 { emitError("no digest") }
  let tag = SIGN_TAG + arguments[2]
  guard let key = loadKey(tag) else { emitError("no signing key"); exit(1) }
  guard let digest = Data(base64Encoded: arguments[3]) else { emitError("bad digest"); exit(1) }
  var error: Unmanaged<CFError>?
  guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureDigestRFC4754, digest as CFData, &error) else { emitError("sign failed"); exit(1) }
  print((sig as Data).base64EncodedString())
default:
  emitError("unknown op")
}`;

function swiftExe() {
  return process.env.FIREALIVE_CLIENT_SWIFT || 'swift';
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
  const custom = process.env.FIREALIVE_CLIENT_SE_HELPER;
  if (custom) {
    try {
      fs.accessSync(custom, fs.constants.X_OK);
    } catch (err) {
      throw preflightError('FIREALIVE_CLIENT_SE_HELPER="' + custom + '" is not an executable file (' + (err.code || err.message) + '); point it at the bundled, signed helper binary.');
    }
    return;
  }
  try {
    execFileSync(swiftExe(), ['--version'], { stdio: ['ignore', 'ignore', 'ignore'] });
  } catch (err) {
    throw preflightError('the Swift toolchain (' + swiftExe() + ') could not run (' + (err.code || err.message) + '); install the Xcode command-line tools, or set FIREALIVE_CLIENT_SE_HELPER to the bundled, signed helper binary.');
  }
}

function realRunHelper(args) {
  const custom = process.env.FIREALIVE_CLIENT_SE_HELPER;
  if (custom) {
    try {
      return execFileSync(custom, args, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        throw preflightError('FIREALIVE_CLIENT_SE_HELPER="' + custom + '" could not be executed (ENOENT); point it at the bundled, signed helper binary.');
      }
      throw err;
    }
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-cl-se-'));
  const file = path.join(dir, 'helper.swift');
  try {
    fs.writeFileSync(file, SWIFT_HELPER);
    return execFileSync(swiftExe(), [file].concat(args), { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      throw preflightError('the Swift toolchain (' + swiftExe() + ') could not run (ENOENT); install the Xcode command-line tools, or set FIREALIVE_CLIENT_SE_HELPER to the bundled, signed helper binary.');
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
    throw new Error('client hardware key (macos): unexpected public key point format');
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

function _hasSigningKey(run, label) {
  return String(run(['has', safeLabel(label)])).trim() === 'YES';
}

function _deleteSigningKey(run, label) {
  return String(run(['delete', safeLabel(label)])).trim() === 'DELETED';
}

function _sign(run, label, data) {
  const digest = crypto.createHash('sha256').update(data).digest();
  const out = String(run(['sign', safeLabel(label), digest.toString('base64')])).trim();
  return Buffer.from(out, 'base64');
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

function hasSigningKey(label) {
  return _hasSigningKey(realRunHelper, label);
}

function deleteSigningKey(label) {
  return _deleteSigningKey(realRunHelper, label);
}

function sign(label, data) {
  return _sign(realRunHelper, label, data);
}

module.exports = {
  kind: KIND,
  isAvailable,
  preflight,
  MACOS_SWIFT_PREFLIGHT,
  createSigningKey,
  getSigningPublicKey,
  hasSigningKey,
  deleteSigningKey,
  sign,
  // internal seams exported for tests (argv construction / conversion / parsing / fail-closed)
  _isAvailable,
  _createSigningKey,
  _getSigningPublicKey,
  _hasSigningKey,
  _deleteSigningKey,
  _sign,
  x963ToSpkiDer,
  toBase64Url,
  safeLabel,
  SWIFT_HELPER,
};

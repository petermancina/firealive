'use strict';

//
// FireAlive -- shared client hardware data-wrap backend: macOS Secure Enclave (ECDH).
//
// macOS backend for packages/shared/hardware-wrap.js (the client data-wrap seam),
// the key-agreement sibling of hardware-key-macos.js (the sign-only device-key
// backend). Where that backend signs, this one performs ECDH P-256 key agreement so a
// caller can wrap a data key at rest (D27). PLATFORM-VALIDATION-PENDING: there is no
// macOS host in CI, so the Swift helper never executes here; the SecKey calls are
// documented APIs verified on real macOS + Secure Enclave hardware. What the tests
// verify: availability detection, helper argv construction, the X9.63-point <-> SPKI-
// DER conversions (both directions), output parsing, the key lifecycle (create / has /
// get-public / delete / agree, with replace-on-create), the ECDH round-trip against a
// software stand-in, and fail-closed behaviour (a helper error propagates; no fallback).
//
// Helper runner: in production set FIREALIVE_CLIENT_SE_WRAP_HELPER to a bundled,
// signed, compiled helper binary; in development the Swift source below runs with the
// swift interpreter (FIREALIVE_CLIENT_SWIFT, default "swift"). Protocol: argv =
// [op, ...], base64 (or NULL / YES / NO / DELETED / ABSENT) on stdout, non-zero exit
// on error.
//
// Key model:
//   - Wrap keys are EC P-256 keys created in the Secure Enclave
//     (kSecAttrTokenIDSecureEnclave), permanent, addressed by a client-namespaced
//     application tag (com.firealive.client.wrap.<label>) so they never collide with
//     the server keystore or the device-key signing keys (com.firealive.client.sign.
//     <label>); the private key never leaves the enclave, so a copied disk cannot use
//     it. Re-minting deletes the existing key and creates a fresh one.
//   - agree() uses SecKeyCopyKeyExchangeResult with ecdhKeyExchangeStandard, which
//     returns the raw shared secret Z (the big-endian X-coordinate of the shared
//     point) with no KDF, matching what Node crypto.diffieHellman returns -- so a
//     software wrap-side ECDH and this hardware unwrap-side ECDH derive the same KEK.
//     Public keys are returned as X9.63 points and wrapped to SPKI DER in Node; peer
//     keys are converted from SPKI DER to X9.63 in Node before the helper imports them.

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const KIND = 'secure-enclave';

const SWIFT_HELPER = `import Foundation
import Security
import CryptoKit

let WRAP_TAG = "com.firealive.client.wrap."

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
  let tag = WRAP_TAG + arguments[2]
  _ = deleteKey(tag)
  let key = createKey(tag)
  print(publicPoint(key).base64EncodedString())
case "getpub":
  if arguments.count < 3 { emitError("no label") }
  let tag = WRAP_TAG + arguments[2]
  guard let key = loadKey(tag) else { print("NULL"); exit(0) }
  print(publicPoint(key).base64EncodedString())
case "has":
  if arguments.count < 3 { emitError("no label") }
  let tag = WRAP_TAG + arguments[2]
  if loadKey(tag) != nil { print("YES") } else { print("NO") }
case "delete":
  if arguments.count < 3 { emitError("no label") }
  let tag = WRAP_TAG + arguments[2]
  if loadKey(tag) != nil { _ = deleteKey(tag); print("DELETED") } else { print("ABSENT") }
case "agree":
  if arguments.count < 4 { emitError("no peer") }
  let tag = WRAP_TAG + arguments[2]
  guard let key = loadKey(tag) else { emitError("no wrap key"); exit(1) }
  guard let peerData = Data(base64Encoded: arguments[3]) else { emitError("bad peer"); exit(1) }
  let peerAttrs: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
  ]
  var peerError: Unmanaged<CFError>?
  guard let peerKey = SecKeyCreateWithData(peerData as CFData, peerAttrs as CFDictionary, &peerError) else { emitError("bad peer key"); exit(1) }
  var error: Unmanaged<CFError>?
  guard let secret = SecKeyCopyKeyExchangeResult(key, .ecdhKeyExchangeStandard, peerKey, [:] as CFDictionary, &error) else { emitError("agree failed"); exit(1) }
  print((secret as Data).base64EncodedString())
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
  const custom = process.env.FIREALIVE_CLIENT_SE_WRAP_HELPER;
  if (custom) {
    try {
      fs.accessSync(custom, fs.constants.X_OK);
    } catch (err) {
      throw preflightError('FIREALIVE_CLIENT_SE_WRAP_HELPER="' + custom + '" is not an executable file (' + (err.code || err.message) + '); point it at the bundled, signed helper binary.');
    }
    return;
  }
  try {
    execFileSync(swiftExe(), ['--version'], { stdio: ['ignore', 'ignore', 'ignore'] });
  } catch (err) {
    throw preflightError('the Swift toolchain (' + swiftExe() + ') could not run (' + (err.code || err.message) + '); install the Xcode command-line tools, or set FIREALIVE_CLIENT_SE_WRAP_HELPER to the bundled, signed helper binary.');
  }
}

function realRunHelper(args) {
  const custom = process.env.FIREALIVE_CLIENT_SE_WRAP_HELPER;
  if (custom) {
    try {
      return execFileSync(custom, args, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        throw preflightError('FIREALIVE_CLIENT_SE_WRAP_HELPER="' + custom + '" could not be executed (ENOENT); point it at the bundled, signed helper binary.');
      }
      throw err;
    }
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-cl-wrap-se-'));
  const file = path.join(dir, 'helper.swift');
  try {
    fs.writeFileSync(file, SWIFT_HELPER);
    return execFileSync(swiftExe(), [file].concat(args), { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      throw preflightError('the Swift toolchain (' + swiftExe() + ') could not run (ENOENT); install the Xcode command-line tools, or set FIREALIVE_CLIENT_SE_WRAP_HELPER to the bundled, signed helper binary.');
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

function leftPad32(buf) {
  if (buf.length === 32) {
    return buf;
  }
  if (buf.length > 32) {
    return buf.subarray(buf.length - 32);
  }
  return Buffer.concat([Buffer.alloc(32 - buf.length), buf]);
}

// X9.63 uncompressed point (from the Secure Enclave) -> SPKI DER, for create/getpub.
function x963ToSpkiDer(b64point) {
  const point = Buffer.from(b64point, 'base64');
  if (point.length !== 65 || point[0] !== 0x04) {
    throw new Error('client hardware wrap (macos): unexpected public key point format');
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

// SPKI DER (a peer ephemeral public) -> X9.63 uncompressed point base64, for agree.
function spkiToX963B64(spkiDer) {
  const keyObj = crypto.createPublicKey({ key: Buffer.from(spkiDer), format: 'der', type: 'spki' });
  const jwk = keyObj.export({ format: 'jwk' });
  const x = leftPad32(Buffer.from(jwk.x, 'base64url'));
  const y = leftPad32(Buffer.from(jwk.y, 'base64url'));
  const point = Buffer.concat([Buffer.from([0x04]), x, y]);
  return point.toString('base64');
}

// ---- backend seams (injected run for tests) ----

function _isAvailable(run) {
  try {
    return String(run(['available'])).trim() === 'YES';
  } catch (err) {
    return false;
  }
}

function _createWrapKey(run, label) {
  const out = String(run(['create', safeLabel(label)])).trim();
  return x963ToSpkiDer(out);
}

function _getWrapPublicKey(run, label) {
  const out = String(run(['getpub', safeLabel(label)])).trim();
  if (out === 'NULL') {
    return null;
  }
  return x963ToSpkiDer(out);
}

function _hasWrapKey(run, label) {
  return String(run(['has', safeLabel(label)])).trim() === 'YES';
}

function _deleteWrapKey(run, label) {
  return String(run(['delete', safeLabel(label)])).trim() === 'DELETED';
}

function _agree(run, label, peerPublicDer) {
  const peerB64 = spkiToX963B64(peerPublicDer);
  const out = String(run(['agree', safeLabel(label), peerB64])).trim();
  return Buffer.from(out, 'base64');
}

// ---- public API (real helper run) ----

function isAvailable() {
  return _isAvailable(realRunHelper);
}

function createWrapKey(label) {
  return _createWrapKey(realRunHelper, label);
}

function getWrapPublicKey(label) {
  return _getWrapPublicKey(realRunHelper, label);
}

function hasWrapKey(label) {
  return _hasWrapKey(realRunHelper, label);
}

function deleteWrapKey(label) {
  return _deleteWrapKey(realRunHelper, label);
}

function agree(label, peerPublicDer) {
  return _agree(realRunHelper, label, peerPublicDer);
}

module.exports = {
  kind: KIND,
  isAvailable,
  preflight,
  MACOS_SWIFT_PREFLIGHT,
  createWrapKey,
  getWrapPublicKey,
  hasWrapKey,
  deleteWrapKey,
  agree,
  // internal seams exported for tests (argv construction / conversion / parsing / fail-closed)
  _isAvailable,
  _createWrapKey,
  _getWrapPublicKey,
  _hasWrapKey,
  _deleteWrapKey,
  _agree,
  x963ToSpkiDer,
  spkiToX963B64,
  toBase64Url,
  leftPad32,
  safeLabel,
  SWIFT_HELPER,
};

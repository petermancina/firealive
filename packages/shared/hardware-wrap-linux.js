'use strict';

//
// FireAlive -- shared client hardware data-wrap backend: Linux TPM 2.0 (ECDH).
//
// Linux backend for packages/shared/hardware-wrap.js (the client data-wrap seam),
// the key-agreement sibling of hardware-key-linux.js (the sign-only device-key
// backend). Where that backend signs, this one performs ECDH P-256 key agreement so
// a caller can wrap a data key at rest (D27). PLATFORM-VALIDATION-PENDING: the
// tpm2-tools command sequences below follow standard usage but have not been run
// against a TPM in CI. What the tests verify: availability detection, command
// construction and ordering, the on-disk key lifecycle (create / has / get-public /
// delete / agree, with replace-on-create), the TPM2B_ECC_POINT encode/parse, the
// ECDH round-trip against a software stand-in, and fail-closed behaviour (any tool
// error propagates; no software fallback).
//
// Key model:
//   - Wrap keys are ECC P-256 (ecc256) with the DECRYPT attribute (not sign), so the
//     TPM will perform ECDH (TPM2_ECDH_ZGen) with them. Non-exportable (fixedtpm,
//     fixedparent), created under a transient deterministic owner primary; the
//     wrapped child blobs (.pub/.priv) are stored on disk per label and the private
//     blob is parent-encrypted, so a copied disk cannot load or use the key.
//     Re-minting replaces the blobs in place. The store directory is
//     FIREALIVE_CLIENT_HW_WRAP_KEYSTORE_DIR (default ~/.firealive/client-hw-wrap-
//     keystore), kept distinct from both the server keystore and the device-key
//     signing keystore so the two client key kinds never collide.
//   - agree() returns the 32-byte ECDH shared secret Z (the X-coordinate of the
//     shared point), matching what Node crypto.diffieHellman returns for the same
//     inputs, so a software wrap-side ECDH and this hardware unwrap-side ECDH derive
//     the same KEK. Public keys are SPKI DER.
//
// The transmission interface is selected via TPM2TOOLS_TCTI (overridable with
// FIREALIVE_CLIENT_TPM2_TCTI, shared with the device-key backend -- same TPM),
// defaulting to the kernel resource manager device.

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const KIND = 'tpm2.0-linux';
const WRAP_KEY_ALG = 'ecc256';
const TPM_DEVICES = ['/dev/tpmrm0', '/dev/tpm0'];

function defaultTcti() {
  if (process.env.FIREALIVE_CLIENT_TPM2_TCTI) {
    return process.env.FIREALIVE_CLIENT_TPM2_TCTI;
  }
  for (let i = 0; i < TPM_DEVICES.length; i += 1) {
    try {
      if (fs.existsSync(TPM_DEVICES[i])) {
        return 'device:' + TPM_DEVICES[i];
      }
    } catch (err) {
      // ignore and try the next device
    }
  }
  return 'device:/dev/tpmrm0';
}

function realRun(tool, args) {
  const env = Object.assign({}, process.env, { TPM2TOOLS_TCTI: defaultTcti() });
  return execFileSync(tool, args, { env: env, stdio: ['ignore', 'pipe', 'pipe'] });
}

function realDeviceExists() {
  for (let i = 0; i < TPM_DEVICES.length; i += 1) {
    try {
      if (fs.existsSync(TPM_DEVICES[i])) {
        return true;
      }
    } catch (err) {
      // ignore
    }
  }
  return false;
}

function storeDir() {
  return process.env.FIREALIVE_CLIENT_HW_WRAP_KEYSTORE_DIR ||
    path.join(os.homedir(), '.firealive', 'client-hw-wrap-keystore');
}

function safeLabel(label) {
  return String(label).replace(/[^A-Za-z0-9._-]/g, '_');
}

function keyPaths(dir, label) {
  const safe = safeLabel(label);
  return { pub: path.join(dir, safe + '.pub'), priv: path.join(dir, safe + '.priv') };
}

function withWorkdir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-cl-wrap-tpm-'));
  try {
    return fn(dir);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (err) {
      // best-effort cleanup
    }
  }
}

function primaryContext(run, work) {
  const primary = path.join(work, 'primary.ctx');
  run('tpm2_createprimary', ['-C', 'o', '-G', 'ecc', '-g', 'sha256', '-c', primary]);
  return primary;
}

function publicKeyDer(run, work, pubPath, privPath, primaryCtx) {
  const primary = primaryCtx || primaryContext(run, work);
  const keyCtx = path.join(work, 'key.ctx');
  run('tpm2_load', ['-C', primary, '-u', pubPath, '-r', privPath, '-c', keyCtx]);
  const pemPath = path.join(work, 'key.pem');
  run('tpm2_readpublic', ['-c', keyCtx, '-f', 'pem', '-o', pemPath]);
  const pem = fs.readFileSync(pemPath);
  const keyObj = crypto.createPublicKey({ key: pem, format: 'pem' });
  return keyObj.export({ type: 'spki', format: 'der' });
}

// ---- TPM2B_ECC_POINT helpers (peer-point encode, Z-point parse) ----

function u16be(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
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

// Raw P-256 public coordinates (X, Y; 32 bytes each) from an SPKI DER public key,
// via its JWK form so we do not hand-parse the DER.
function spkiToRawPoint(spkiDer) {
  const keyObj = crypto.createPublicKey({ key: Buffer.from(spkiDer), format: 'der', type: 'spki' });
  const jwk = keyObj.export({ format: 'jwk' });
  return { x: leftPad32(Buffer.from(jwk.x, 'base64url')), y: leftPad32(Buffer.from(jwk.y, 'base64url')) };
}

// Encode a public point as a TPM2B_ECC_POINT (the peer-public form tpm2_ecdhzgen
// reads): outerSize || (xSize || X) || (ySize || Y).
function eccPointToTpm2b(x, y) {
  const xParam = Buffer.concat([u16be(x.length), x]);
  const yParam = Buffer.concat([u16be(y.length), y]);
  const point = Buffer.concat([xParam, yParam]);
  return Buffer.concat([u16be(point.length), point]);
}

// Parse the X coordinate (the ECDH shared secret Z) from a TPM2B_ECC_POINT as
// written by tpm2_ecdhzgen -o. Layout: outerSize(2) | xSize(2) | X | ySize(2) | Y.
function tpm2bPointX(buf) {
  if (buf.length < 4) {
    throw new Error('client hardware wrap: short TPM2B_ECC_POINT');
  }
  const xSize = buf.readUInt16BE(2);
  if (buf.length < 4 + xSize) {
    throw new Error('client hardware wrap: truncated TPM2B_ECC_POINT X');
  }
  return leftPad32(buf.subarray(4, 4 + xSize));
}

// ---- backend seams (injected run/deviceExists for tests) ----

function _isAvailable(run, deviceExists) {
  if (!deviceExists()) {
    return false;
  }
  try {
    run('tpm2_getcap', ['properties-fixed']);
    return true;
  } catch (err) {
    return false;
  }
}

function _hasWrapKey(dir, label) {
  const p = keyPaths(dir, label);
  return fs.existsSync(p.pub) && fs.existsSync(p.priv);
}

function _deleteWrapKey(dir, label) {
  const p = keyPaths(dir, label);
  let removed = false;
  const targets = [p.pub, p.priv];
  for (let i = 0; i < targets.length; i += 1) {
    try {
      if (fs.existsSync(targets[i])) {
        fs.rmSync(targets[i], { force: true });
        removed = true;
      }
    } catch (err) {
      // best-effort
    }
  }
  return removed;
}

function _createWrapKey(run, dir, label) {
  const p = keyPaths(dir, label);
  fs.mkdirSync(dir, { recursive: true });
  // Wrap keys are re-minted on enrollment: replace any existing key at this label.
  _deleteWrapKey(dir, label);
  return withWorkdir(function (work) {
    const primary = primaryContext(run, work);
    const pub = path.join(work, 'key.pub');
    const priv = path.join(work, 'key.priv');
    run('tpm2_create', ['-C', primary, '-G', WRAP_KEY_ALG, '-g', 'sha256', '-u', pub, '-r', priv,
      '-a', 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt']);
    fs.copyFileSync(pub, p.pub);
    fs.copyFileSync(priv, p.priv);
    return publicKeyDer(run, work, p.pub, p.priv, primary);
  });
}

function _getWrapPublicKey(run, dir, label) {
  const p = keyPaths(dir, label);
  if (!fs.existsSync(p.pub) || !fs.existsSync(p.priv)) {
    return null;
  }
  return withWorkdir(function (work) {
    return publicKeyDer(run, work, p.pub, p.priv);
  });
}

function _agree(run, dir, label, peerPublicDer) {
  const p = keyPaths(dir, label);
  if (!fs.existsSync(p.pub) || !fs.existsSync(p.priv)) {
    throw new Error('client hardware wrap: no wrap key for label ' + safeLabel(label));
  }
  const point = spkiToRawPoint(peerPublicDer);
  const peerTpm2b = eccPointToTpm2b(point.x, point.y);
  return withWorkdir(function (work) {
    const primary = primaryContext(run, work);
    const keyCtx = path.join(work, 'key.ctx');
    run('tpm2_load', ['-C', primary, '-u', p.pub, '-r', p.priv, '-c', keyCtx]);
    const peerPath = path.join(work, 'peer.point');
    fs.writeFileSync(peerPath, peerTpm2b);
    const zPath = path.join(work, 'z.point');
    run('tpm2_ecdhzgen', ['-c', keyCtx, '-u', peerPath, '-o', zPath]);
    return tpm2bPointX(fs.readFileSync(zPath));
  });
}

// ---- public API (real run / real device probe) ----

function isAvailable() {
  return _isAvailable(realRun, realDeviceExists);
}

function createWrapKey(label) {
  return _createWrapKey(realRun, storeDir(), label);
}

function getWrapPublicKey(label) {
  return _getWrapPublicKey(realRun, storeDir(), label);
}

function hasWrapKey(label) {
  return _hasWrapKey(storeDir(), label);
}

function deleteWrapKey(label) {
  return _deleteWrapKey(storeDir(), label);
}

function agree(label, peerPublicDer) {
  return _agree(realRun, storeDir(), label, peerPublicDer);
}

module.exports = {
  kind: KIND,
  isAvailable,
  createWrapKey,
  getWrapPublicKey,
  hasWrapKey,
  deleteWrapKey,
  agree,
  // internal seams exported for tests (command construction / parsing / fail-closed)
  _isAvailable,
  _createWrapKey,
  _getWrapPublicKey,
  _hasWrapKey,
  _deleteWrapKey,
  _agree,
  keyPaths,
  safeLabel,
  defaultTcti,
  spkiToRawPoint,
  eccPointToTpm2b,
  tpm2bPointX,
  leftPad32,
};

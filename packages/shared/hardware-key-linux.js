'use strict';

//
// FireAlive -- shared client hardware-key backend: Linux TPM 2.0.
//
// Linux backend for packages/shared/hardware-key.js (the client device-key seam),
// mirroring server/services/instance-anchor/hardware-keystore-linux.js but trimmed
// to the sign-only device-key subset (no seal/unseal/NV -- those are server-anchor
// concerns). PLATFORM-VALIDATION-PENDING: the tpm2-tools command sequences below
// follow standard usage but have not been run against a TPM in CI. What the tests
// verify: availability detection, command construction and ordering, the on-disk
// key lifecycle (create / has / get-public / delete / sign, with replace-on-create),
// and the fail-closed behaviour (any tool error propagates; no software fallback).
//
// Key model:
//   - Device signing keys are ECDSA P-256 (ecc256), non-exportable (fixedtpm,
//     fixedparent), created under a transient deterministic owner primary. The
//     wrapped child blobs (.pub/.priv) are stored on disk per label; the private
//     blob is parent-encrypted, so it is useless on any other TPM -- a copied
//     disk cannot load or use the key. Re-minting replaces the blobs in place.
//     The store directory is FIREALIVE_CLIENT_HW_KEYSTORE_DIR (default
//     ~/.firealive/client-hw-keystore), kept distinct from the server keystore.
//   - Signatures are returned in raw r||s form (tpm2_sign -f plain), i.e. IEEE
//     P1363; verifiers must use dsaEncoding 'ieee-p1363'. Public keys are SPKI
//     DER so verifiers derive the algorithm from the key.
//
// The transmission interface is selected via TPM2TOOLS_TCTI (overridable with
// FIREALIVE_CLIENT_TPM2_TCTI), defaulting to the kernel resource manager device.

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const KIND = 'tpm2.0-linux';
const SIGN_KEY_ALG = 'ecc256';
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
  return process.env.FIREALIVE_CLIENT_HW_KEYSTORE_DIR ||
    path.join(os.homedir(), '.firealive', 'client-hw-keystore');
}

function safeLabel(label) {
  return String(label).replace(/[^A-Za-z0-9._-]/g, '_');
}

function keyPaths(dir, label) {
  const safe = safeLabel(label);
  return { pub: path.join(dir, safe + '.pub'), priv: path.join(dir, safe + '.priv') };
}

function withWorkdir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-cl-tpm-'));
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

function _hasSigningKey(dir, label) {
  const p = keyPaths(dir, label);
  return fs.existsSync(p.pub) && fs.existsSync(p.priv);
}

function _deleteSigningKey(dir, label) {
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

function _createSigningKey(run, dir, label) {
  const p = keyPaths(dir, label);
  fs.mkdirSync(dir, { recursive: true });
  // Device keys are re-minted on enrollment: replace any existing key at this label.
  _deleteSigningKey(dir, label);
  return withWorkdir(function (work) {
    const primary = primaryContext(run, work);
    const pub = path.join(work, 'key.pub');
    const priv = path.join(work, 'key.priv');
    run('tpm2_create', ['-C', primary, '-G', SIGN_KEY_ALG, '-g', 'sha256', '-u', pub, '-r', priv,
      '-a', 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign']);
    fs.copyFileSync(pub, p.pub);
    fs.copyFileSync(priv, p.priv);
    return publicKeyDer(run, work, p.pub, p.priv, primary);
  });
}

function _getSigningPublicKey(run, dir, label) {
  const p = keyPaths(dir, label);
  if (!fs.existsSync(p.pub) || !fs.existsSync(p.priv)) {
    return null;
  }
  return withWorkdir(function (work) {
    return publicKeyDer(run, work, p.pub, p.priv);
  });
}

function _sign(run, dir, label, data) {
  const p = keyPaths(dir, label);
  if (!fs.existsSync(p.pub) || !fs.existsSync(p.priv)) {
    throw new Error('client hardware key: no signing key for label ' + safeLabel(label));
  }
  return withWorkdir(function (work) {
    const primary = primaryContext(run, work);
    const keyCtx = path.join(work, 'key.ctx');
    run('tpm2_load', ['-C', primary, '-u', p.pub, '-r', p.priv, '-c', keyCtx]);
    const dataPath = path.join(work, 'data.bin');
    fs.writeFileSync(dataPath, data);
    const sigPath = path.join(work, 'sig.bin');
    run('tpm2_sign', ['-c', keyCtx, '-g', 'sha256', '-f', 'plain', '-o', sigPath, dataPath]);
    return fs.readFileSync(sigPath);
  });
}

function isAvailable() {
  return _isAvailable(realRun, realDeviceExists);
}

function createSigningKey(label) {
  return _createSigningKey(realRun, storeDir(), label);
}

function getSigningPublicKey(label) {
  return _getSigningPublicKey(realRun, storeDir(), label);
}

function hasSigningKey(label) {
  return _hasSigningKey(storeDir(), label);
}

function deleteSigningKey(label) {
  return _deleteSigningKey(storeDir(), label);
}

function sign(label, data) {
  return _sign(realRun, storeDir(), label, data);
}

module.exports = {
  kind: KIND,
  isAvailable,
  createSigningKey,
  getSigningPublicKey,
  hasSigningKey,
  deleteSigningKey,
  sign,
  // internal seams exported for tests (command construction / parsing / fail-closed)
  _isAvailable,
  _createSigningKey,
  _getSigningPublicKey,
  _hasSigningKey,
  _deleteSigningKey,
  _sign,
  keyPaths,
  safeLabel,
  defaultTcti,
};

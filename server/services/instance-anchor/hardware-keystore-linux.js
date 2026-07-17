// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Instance Anchor (Linux TPM 2.0 keystore backend)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// LINUX TPM 2.0 BACKEND (B5e, decision D26) -- PLATFORM-VALIDATION-PENDING
//
// Implements the hardware-keystore backend contract on Linux using tpm2-tools
// against the kernel resource manager (/dev/tpmrm0, falling back to /dev/tpm0).
// Honest status: the tpm2-tools command SEQUENCES below follow standard usage
// but have NOT been executed against a TPM in this build environment. Treat them
// as the validation starting point -- they may need adjustment on first run on
// real hardware (flag spellings, output formats, attribute syntax). What IS
// verified by this module's tests: availability detection, command construction
// and ordering, output parsing, and the fail-closed behaviour (any tool error
// propagates; there is no software fallback).
//
// Key model:
//   - Signing keys are ECDSA P-256 (ecc256), non-exportable (fixedtpm,
//     fixedparent), created under a transient deterministic owner primary. The
//     wrapped child blobs (.pub/.priv) are stored on disk per label; the private
//     blob is parent-encrypted, so it is useless on any other TPM -- a copied
//     disk cannot load or use the key. The store directory is
//     FIREALIVE_HW_KEYSTORE_DIR (default ~/.firealive/hw-keystore).
//   - Signatures are returned in raw r||s form (tpm2_sign -f plain), i.e. IEEE
//     P1363; verifiers must use dsaEncoding 'ieee-p1363'. Public keys are
//     returned as SPKI DER so verifiers derive the algorithm from the key.
//   - Sealed secrets are TPM sealed-data objects; the returned blob packs the
//     sealed .pub/.priv and will only unseal on the same TPM.
//   - The anti-rollback counter is a TPM NV counter at the given index.
//
// The transmission interface is selected via TPM2TOOLS_TCTI (overridable with
// FIREALIVE_TPM2_TCTI), defaulting to the kernel resource manager device.

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const KIND = 'tpm2.0-linux';
const SIGN_KEY_ALG = 'ecc256';
const TPM_DEVICES = ['/dev/tpmrm0', '/dev/tpm0'];

function defaultTcti() {
  if (process.env.FIREALIVE_TPM2_TCTI) {
    return process.env.FIREALIVE_TPM2_TCTI;
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
  return process.env.FIREALIVE_HW_KEYSTORE_DIR || path.join(os.homedir(), '.firealive', 'hw-keystore');
}

function safeLabel(label) {
  return String(label).replace(/[^A-Za-z0-9._-]/g, '_');
}

function withWorkdir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-tpm-'));
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

function packBlob(pub, priv) {
  const head = Buffer.alloc(4);
  head.writeUInt32BE(pub.length, 0);
  return Buffer.concat([head, Buffer.from(pub), Buffer.from(priv)]);
}

function unpackBlob(blob) {
  const b = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
  const pubLen = b.readUInt32BE(0);
  return { pub: b.subarray(4, 4 + pubLen), priv: b.subarray(4 + pubLen) };
}

function nvIndexHex(index) {
  return '0x' + Number(index).toString(16);
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

function _createSigningKey(run, dir, label) {
  const safe = safeLabel(label);
  fs.mkdirSync(dir, { recursive: true });
  const pubPath = path.join(dir, safe + '.pub');
  const privPath = path.join(dir, safe + '.priv');
  if (fs.existsSync(pubPath) || fs.existsSync(privPath)) {
    throw new Error('hardware keystore: signing key already exists for label ' + safe);
  }
  return withWorkdir(function (work) {
    const primary = primaryContext(run, work);
    const pub = path.join(work, 'key.pub');
    const priv = path.join(work, 'key.priv');
    run('tpm2_create', ['-C', primary, '-G', SIGN_KEY_ALG, '-g', 'sha256', '-u', pub, '-r', priv,
      '-a', 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign']);
    fs.copyFileSync(pub, pubPath);
    fs.copyFileSync(priv, privPath);
    return publicKeyDer(run, work, pubPath, privPath, primary);
  });
}

function _getSigningPublicKey(run, dir, label) {
  const safe = safeLabel(label);
  const pubPath = path.join(dir, safe + '.pub');
  const privPath = path.join(dir, safe + '.priv');
  if (!fs.existsSync(pubPath) || !fs.existsSync(privPath)) {
    return null;
  }
  return withWorkdir(function (work) {
    return publicKeyDer(run, work, pubPath, privPath);
  });
}

function _sign(run, dir, label, data) {
  const safe = safeLabel(label);
  const pubPath = path.join(dir, safe + '.pub');
  const privPath = path.join(dir, safe + '.priv');
  if (!fs.existsSync(pubPath) || !fs.existsSync(privPath)) {
    throw new Error('hardware keystore: no signing key for label ' + safe);
  }
  return withWorkdir(function (work) {
    const primary = primaryContext(run, work);
    const keyCtx = path.join(work, 'key.ctx');
    run('tpm2_load', ['-C', primary, '-u', pubPath, '-r', privPath, '-c', keyCtx]);
    const dataPath = path.join(work, 'data.bin');
    fs.writeFileSync(dataPath, data);
    const sigPath = path.join(work, 'sig.bin');
    run('tpm2_sign', ['-c', keyCtx, '-g', 'sha256', '-f', 'plain', '-o', sigPath, dataPath]);
    return fs.readFileSync(sigPath);
  });
}

function _sealKey(run, data) {
  return withWorkdir(function (work) {
    const primary = primaryContext(run, work);
    const secretPath = path.join(work, 'secret.bin');
    fs.writeFileSync(secretPath, data);
    const sealPub = path.join(work, 'seal.pub');
    const sealPriv = path.join(work, 'seal.priv');
    run('tpm2_create', ['-C', primary, '-i', secretPath, '-u', sealPub, '-r', sealPriv,
      '-a', 'fixedtpm|fixedparent|userwithauth']);
    return packBlob(fs.readFileSync(sealPub), fs.readFileSync(sealPriv));
  });
}

function _unsealKey(run, blob) {
  const parts = unpackBlob(blob);
  return withWorkdir(function (work) {
    const primary = primaryContext(run, work);
    const sealPub = path.join(work, 'seal.pub');
    const sealPriv = path.join(work, 'seal.priv');
    fs.writeFileSync(sealPub, parts.pub);
    fs.writeFileSync(sealPriv, parts.priv);
    const sealCtx = path.join(work, 'seal.ctx');
    run('tpm2_load', ['-C', primary, '-u', sealPub, '-r', sealPriv, '-c', sealCtx]);
    const outPath = path.join(work, 'unsealed.bin');
    run('tpm2_unseal', ['-c', sealCtx, '-o', outPath]);
    return fs.readFileSync(outPath);
  });
}

function _nvDefineCounter(run, index) {
  const hx = nvIndexHex(index);
  try {
    run('tpm2_nvdefine', [hx, '-C', 'o', '-a', 'nt=counter|ownerwrite|ownerread|authread|authwrite']);
  } catch (err) {
    const message = String(err && err.message);
    if (!/already|defined|0x14c/i.test(message)) {
      throw err;
    }
  }
  return true;
}

function _nvReadCounter(run, index) {
  const hx = nvIndexHex(index);
  const out = run('tpm2_nvread', [hx, '-C', 'o']);
  const buf = Buffer.isBuffer(out) ? out : Buffer.from(String(out));
  if (buf.length >= 8) {
    return Number(buf.readBigUInt64BE(buf.length - 8));
  }
  return Number(String(out).trim());
}

function _nvIncrementCounter(run, index) {
  const hx = nvIndexHex(index);
  run('tpm2_nvincrement', [hx, '-C', 'o']);
  return _nvReadCounter(run, index);
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

function sign(label, data) {
  return _sign(realRun, storeDir(), label, data);
}

function sealKey(keyBuffer) {
  return _sealKey(realRun, keyBuffer);
}

function unsealKey(sealedBlob) {
  return _unsealKey(realRun, sealedBlob);
}

function nvDefineCounter(index) {
  return _nvDefineCounter(realRun, index);
}

function nvReadCounter(index) {
  return _nvReadCounter(realRun, index);
}

function nvIncrementCounter(index) {
  return _nvIncrementCounter(realRun, index);
}

module.exports = {
  kind: KIND,
  isAvailable,
  // P1-2c: the boot posture check verifies this directory is owner-only. It must
  // ask rather than reconstruct the FIREALIVE_HW_KEYSTORE_DIR chain -- duplicated
  // path logic is what let the GD's migration composer and importer point at
  // different directories, and let the storage health probe report on a directory
  // the backup engine never wrote to. One resolver, one answer.
  storeDir,
  createSigningKey,
  getSigningPublicKey,
  sign,
  sealKey,
  unsealKey,
  nvDefineCounter,
  nvReadCounter,
  nvIncrementCounter,
  // internal seams exported for tests (command construction / parsing / fail-closed)
  _isAvailable,
  _createSigningKey,
  _getSigningPublicKey,
  _sign,
  _sealKey,
  _unsealKey,
  _nvDefineCounter,
  _nvReadCounter,
  _nvIncrementCounter,
  packBlob,
  unpackBlob,
  nvIndexHex,
  safeLabel,
  defaultTcti,
};

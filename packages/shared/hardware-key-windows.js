'use strict';

//
// FireAlive -- shared client hardware-key backend: Windows TPM 2.0 / CNG.
//
// Windows backend for packages/shared/hardware-key.js (the client device-key seam),
// mirroring server/services/instance-anchor/hardware-keystore-windows.js but trimmed
// to the sign-only device-key subset (no seal/unseal/NV). PLATFORM-VALIDATION-PENDING:
// there is no Windows host in CI, so none of the PowerShell / .NET below executes
// here; the CNG calls are documented APIs verified on real Windows + TPM hardware.
// What the tests verify: availability detection, PowerShell script construction,
// output parsing, the key lifecycle (create / has / get-public / delete / sign, with
// replace-on-create), and fail-closed behaviour (any PowerShell error propagates).
//
// Key model:
//   - Device signing keys are ECDSA P-256 CngKeys in the Microsoft Platform Crypto
//     Provider, created as machine keys with ExportPolicy None -- non-exportable and
//     TPM-bound, so a copied disk cannot use them. Keys are addressed by name in the
//     provider (no on-disk blobs); the names are client-namespaced
//     (FIREALIVE_CLIENT_SIGN_<label>) so they never collide with the server keystore.
//     Re-minting deletes the existing key and creates a fresh one. Signatures come
//     from ECDsaCng.SignData (default IEEE P1363, raw r||s); public keys are exported
//     as SPKI DER (ExportSubjectPublicKeyInfo).
//
// The PowerShell executable is FIREALIVE_CLIENT_POWERSHELL (default "powershell").

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const KIND = 'tpm2.0-windows';
const PROVIDER = 'Microsoft Platform Crypto Provider';
const SIGN_PREFIX = 'FIREALIVE_CLIENT_SIGN_';

function powershellExe() {
  return process.env.FIREALIVE_CLIENT_POWERSHELL || 'powershell';
}

function safeLabel(label) {
  return String(label).replace(/[^A-Za-z0-9._-]/g, '_');
}

function realRunPowerShell(script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-cl-ps-'));
  const file = path.join(dir, 'op.ps1');
  try {
    fs.writeFileSync(file, script);
    const out = execFileSync(powershellExe(),
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', file],
      { stdio: ['ignore', 'pipe', 'pipe'] });
    return out.toString().trim();
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (err) {
      // best-effort cleanup
    }
  }
}

function scriptIsAvailable() {
  return `$ErrorActionPreference = 'Stop'
try {
  $tpm = Get-Tpm
  if ($tpm.TpmPresent -and $tpm.TpmReady) { 'YES' } else { 'NO' }
} catch { 'NO' }`;
}

function scriptCreateSigningKey(safe) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${SIGN_PREFIX}${safe}'
if ([System.Security.Cryptography.CngKey]::Exists($name, $provider)) {
  [System.Security.Cryptography.CngKey]::Open($name, $provider).Delete()
}
$params = [System.Security.Cryptography.CngKeyCreationParameters]::new()
$params.Provider = $provider
$params.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
$params.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
$params.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
$key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::ECDsaP256, $name, $params)
$ecdsa = [System.Security.Cryptography.ECDsaCng]::new($key)
[Convert]::ToBase64String($ecdsa.ExportSubjectPublicKeyInfo())`;
}

function scriptGetSigningPublicKey(safe) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${SIGN_PREFIX}${safe}'
if (-not [System.Security.Cryptography.CngKey]::Exists($name, $provider)) { 'NULL' } else {
  $key = [System.Security.Cryptography.CngKey]::Open($name, $provider)
  $ecdsa = [System.Security.Cryptography.ECDsaCng]::new($key)
  [Convert]::ToBase64String($ecdsa.ExportSubjectPublicKeyInfo())
}`;
}

function scriptHasSigningKey(safe) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${SIGN_PREFIX}${safe}'
if ([System.Security.Cryptography.CngKey]::Exists($name, $provider)) { 'YES' } else { 'NO' }`;
}

function scriptDeleteSigningKey(safe) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${SIGN_PREFIX}${safe}'
if ([System.Security.Cryptography.CngKey]::Exists($name, $provider)) {
  [System.Security.Cryptography.CngKey]::Open($name, $provider).Delete()
  'DELETED'
} else { 'ABSENT' }`;
}

function scriptSign(safe, b64data) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${SIGN_PREFIX}${safe}'
if (-not [System.Security.Cryptography.CngKey]::Exists($name, $provider)) { throw 'client hardware key: no signing key' }
$key = [System.Security.Cryptography.CngKey]::Open($name, $provider)
$ecdsa = [System.Security.Cryptography.ECDsaCng]::new($key)
$data = [Convert]::FromBase64String('${b64data}')
[Convert]::ToBase64String($ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256))`;
}

function _isAvailable(run) {
  try {
    return String(run(scriptIsAvailable())).trim() === 'YES';
  } catch (err) {
    return false;
  }
}

function _createSigningKey(run, label) {
  const out = String(run(scriptCreateSigningKey(safeLabel(label)))).trim();
  return Buffer.from(out, 'base64');
}

function _getSigningPublicKey(run, label) {
  const out = String(run(scriptGetSigningPublicKey(safeLabel(label)))).trim();
  if (out === 'NULL') {
    return null;
  }
  return Buffer.from(out, 'base64');
}

function _hasSigningKey(run, label) {
  return String(run(scriptHasSigningKey(safeLabel(label)))).trim() === 'YES';
}

function _deleteSigningKey(run, label) {
  return String(run(scriptDeleteSigningKey(safeLabel(label)))).trim() === 'DELETED';
}

function _sign(run, label, data) {
  const b64 = Buffer.from(data).toString('base64');
  const out = String(run(scriptSign(safeLabel(label), b64))).trim();
  return Buffer.from(out, 'base64');
}

function isAvailable() {
  return _isAvailable(realRunPowerShell);
}

function createSigningKey(label) {
  return _createSigningKey(realRunPowerShell, label);
}

function getSigningPublicKey(label) {
  return _getSigningPublicKey(realRunPowerShell, label);
}

function hasSigningKey(label) {
  return _hasSigningKey(realRunPowerShell, label);
}

function deleteSigningKey(label) {
  return _deleteSigningKey(realRunPowerShell, label);
}

function sign(label, data) {
  return _sign(realRunPowerShell, label, data);
}

module.exports = {
  kind: KIND,
  isAvailable,
  createSigningKey,
  getSigningPublicKey,
  hasSigningKey,
  deleteSigningKey,
  sign,
  // internal seams exported for tests (script construction / parsing / fail-closed)
  _isAvailable,
  _createSigningKey,
  _getSigningPublicKey,
  _hasSigningKey,
  _deleteSigningKey,
  _sign,
  scriptIsAvailable,
  scriptCreateSigningKey,
  scriptGetSigningPublicKey,
  scriptHasSigningKey,
  scriptDeleteSigningKey,
  scriptSign,
  safeLabel,
};

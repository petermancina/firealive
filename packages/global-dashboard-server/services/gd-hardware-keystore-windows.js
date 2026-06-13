// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Hardware Keystore (Windows TPM 2.0 / CNG backend)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The GD Server own Windows TPM 2.0 / CNG keystore backend, a per-package copy
// of server/services/instance-anchor/hardware-keystore-windows.js (the GD
// backend shares no modules with server/). The CNG logic is identical; it is
// GD-namespaced -- FIREALIVE_GD_POWERSHELL for the interpreter, and the CNG
// key names are prefixed FIREALIVE_GD_SIGN_ / FIREALIVE_GD_SEAL -- so a GD
// Server co-located with a regional server on one host never collides in the
// machine CNG store (signing keys are further isolated by the gd-inst- label).
//
// WINDOWS TPM 2.0 BACKEND (B5e, decision D26) -- PLATFORM-VALIDATION-PENDING
//
// Implements the hardware-keystore backend contract on Windows using the CNG
// Microsoft Platform Crypto Provider (the TPM-backed key storage provider) via
// PowerShell + .NET. Honest status: there is no Windows host in this build
// environment, so NONE of the PowerShell / .NET below executes here. The .NET
// calls use documented CNG APIs but are platform-validation-pending and verified
// on real Windows + TPM hardware. What IS verified by this module's tests:
// availability detection, PowerShell script construction, output parsing, and
// the fail-closed behaviour (any PowerShell error propagates; no fallback).
//
// Key model:
//   - Signing keys are ECDSA P-256 CngKeys created in the Platform Crypto
//     Provider as machine keys with ExportPolicy None -- non-exportable and
//     TPM-bound, so a copied disk cannot use them. Keys are addressed by name
//     in the provider (no on-disk blobs). Signatures come from ECDsaCng.SignData,
//     whose default format is IEEE P1363 (raw r||s), matching the contract;
//     public keys are exported as SPKI DER (ExportSubjectPublicKeyInfo).
//   - Sealing uses a TPM-backed RSA CngKey (also machine, non-exportable):
//     sealKey RSA-OAEP-SHA256 encrypts the secret to the key's public half;
//     unsealKey decrypts in the TPM. Suitable for small secrets (a KEK).
//
// KNOWN GAP (validation-pending): a Windows TPM NV counter requires TSS.MSR or
// direct TBS, which is not integrated here; the nv* methods throw a clear error
// rather than ship unverified calls. The anti-rollback high-water (D7) is the
// software primary; whether the NV counter is required hardening or
// best-effort on Windows is settled with the rollback-hardening commit.
//
// The PowerShell executable is FIREALIVE_GD_POWERSHELL (default "powershell").

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const KIND = 'tpm2.0-windows';
const PROVIDER = 'Microsoft Platform Crypto Provider';
const SIGN_PREFIX = 'FIREALIVE_GD_SIGN_';
const SEAL_KEY_NAME = 'FIREALIVE_GD_SEAL';

function powershellExe() {
  return process.env.FIREALIVE_GD_POWERSHELL || 'powershell';
}

function safeLabel(label) {
  return String(label).replace(/[^A-Za-z0-9._-]/g, '_');
}

function realRunPowerShell(script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-gd-ps-'));
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
if ([System.Security.Cryptography.CngKey]::Exists($name, $provider)) { throw 'hardware keystore: signing key already exists' }
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

function scriptSign(safe, b64data) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${SIGN_PREFIX}${safe}'
if (-not [System.Security.Cryptography.CngKey]::Exists($name, $provider)) { throw 'hardware keystore: no signing key' }
$key = [System.Security.Cryptography.CngKey]::Open($name, $provider)
$ecdsa = [System.Security.Cryptography.ECDsaCng]::new($key)
$data = [Convert]::FromBase64String('${b64data}')
[Convert]::ToBase64String($ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256))`;
}

function scriptSeal(b64secret) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${SEAL_KEY_NAME}'
if (-not [System.Security.Cryptography.CngKey]::Exists($name, $provider)) {
  $params = [System.Security.Cryptography.CngKeyCreationParameters]::new()
  $params.Provider = $provider
  $params.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
  $params.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
  [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $name, $params) | Out-Null
}
$key = [System.Security.Cryptography.CngKey]::Open($name, $provider)
$rsa = [System.Security.Cryptography.RSACng]::new($key)
$secret = [Convert]::FromBase64String('${b64secret}')
[Convert]::ToBase64String($rsa.Encrypt($secret, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))`;
}

function scriptUnseal(b64blob) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$key = [System.Security.Cryptography.CngKey]::Open('${SEAL_KEY_NAME}', $provider)
$rsa = [System.Security.Cryptography.RSACng]::new($key)
$ct = [Convert]::FromBase64String('${b64blob}')
[Convert]::ToBase64String($rsa.Decrypt($ct, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))`;
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

function _sign(run, label, data) {
  const b64 = Buffer.from(data).toString('base64');
  const out = String(run(scriptSign(safeLabel(label), b64))).trim();
  return Buffer.from(out, 'base64');
}

function _sealKey(run, data) {
  const b64 = Buffer.from(data).toString('base64');
  const out = String(run(scriptSeal(b64))).trim();
  return Buffer.from(out, 'base64');
}

function _unsealKey(run, blob) {
  const b64 = Buffer.from(blob).toString('base64');
  const out = String(run(scriptUnseal(b64))).trim();
  return Buffer.from(out, 'base64');
}

function nvUnsupported() {
  throw new Error('hardware keystore (windows): TPM NV counter requires TSS.MSR / TBS integration; not yet available on this backend (validation-pending)');
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

function sign(label, data) {
  return _sign(realRunPowerShell, label, data);
}

function sealKey(keyBuffer) {
  return _sealKey(realRunPowerShell, keyBuffer);
}

function unsealKey(sealedBlob) {
  return _unsealKey(realRunPowerShell, sealedBlob);
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
  createSigningKey,
  getSigningPublicKey,
  sign,
  sealKey,
  unsealKey,
  nvDefineCounter,
  nvReadCounter,
  nvIncrementCounter,
  // internal seams exported for tests (script construction / parsing / fail-closed)
  _isAvailable,
  _createSigningKey,
  _getSigningPublicKey,
  _sign,
  _sealKey,
  _unsealKey,
  scriptIsAvailable,
  scriptCreateSigningKey,
  scriptGetSigningPublicKey,
  scriptSign,
  scriptSeal,
  scriptUnseal,
  safeLabel,
};

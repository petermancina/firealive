'use strict';

//
// FireAlive -- shared client hardware data-wrap backend: Windows TPM 2.0 / CNG (ECDH).
//
// Windows backend for packages/shared/hardware-wrap.js (the client data-wrap seam),
// the key-agreement sibling of hardware-key-windows.js (the sign-only device-key
// backend). Where that backend signs, this one performs ECDH P-256 key agreement so a
// caller can wrap a data key at rest (D27). PLATFORM-VALIDATION-PENDING: there is no
// Windows host in CI, so none of the PowerShell / .NET below executes here; the CNG
// calls are documented APIs verified on real Windows + TPM hardware. What the tests
// verify: availability detection, PowerShell script construction, output parsing, the
// key lifecycle (create / has / get-public / delete / agree, with replace-on-create),
// the ECDH round-trip against a software stand-in, and fail-closed behaviour.
//
// Key model:
//   - Wrap keys are ECDH P-256 CngKeys in the Microsoft Platform Crypto Provider,
//     created as machine keys with ExportPolicy None and KeyUsage KeyAgreement --
//     non-exportable and TPM-bound, so a copied disk cannot use them. Keys are
//     addressed by name in the provider (no on-disk blobs); the names are client-
//     namespaced (FIREALIVE_CLIENT_WRAP_<label>) so they never collide with the
//     server keystore or the device-key signing keys (FIREALIVE_CLIENT_SIGN_<label>).
//     Re-minting deletes the existing key and creates a fresh one.
//   - agree() uses ECDiffieHellmanCng.DeriveRawSecretAgreement, which returns the raw
//     shared secret Z (the big-endian X-coordinate of the shared point) with no KDF,
//     matching what Node crypto.diffieHellman returns -- so a software wrap-side ECDH
//     and this hardware unwrap-side ECDH derive the same KEK. Public keys are exported
//     and peer keys imported as SPKI DER (Export/ImportSubjectPublicKeyInfo). These
//     APIs (like the signing backend ExportSubjectPublicKeyInfo) require .NET 5+ /
//     PowerShell 7; FIREALIVE_CLIENT_POWERSHELL selects the interpreter.
//
// The PowerShell executable is FIREALIVE_CLIENT_POWERSHELL (default "powershell").

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const KIND = 'tpm2.0-windows';
const PROVIDER = 'Microsoft Platform Crypto Provider';
const WRAP_PREFIX = 'FIREALIVE_CLIENT_WRAP_';

function powershellExe() {
  return process.env.FIREALIVE_CLIENT_POWERSHELL || 'powershell';
}

function safeLabel(label) {
  return String(label).replace(/[^A-Za-z0-9._-]/g, '_');
}

function realRunPowerShell(script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-cl-wrap-ps-'));
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

function scriptCreateWrapKey(safe) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${WRAP_PREFIX}${safe}'
if ([System.Security.Cryptography.CngKey]::Exists($name, $provider)) {
  [System.Security.Cryptography.CngKey]::Open($name, $provider).Delete()
}
$params = [System.Security.Cryptography.CngKeyCreationParameters]::new()
$params.Provider = $provider
$params.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
$params.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
$params.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::KeyAgreement
$key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::ECDiffieHellmanP256, $name, $params)
$ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]::new($key)
[Convert]::ToBase64String($ecdh.ExportSubjectPublicKeyInfo())`;
}

function scriptGetWrapPublicKey(safe) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${WRAP_PREFIX}${safe}'
if (-not [System.Security.Cryptography.CngKey]::Exists($name, $provider)) { 'NULL' } else {
  $key = [System.Security.Cryptography.CngKey]::Open($name, $provider)
  $ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]::new($key)
  [Convert]::ToBase64String($ecdh.ExportSubjectPublicKeyInfo())
}`;
}

function scriptHasWrapKey(safe) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${WRAP_PREFIX}${safe}'
if ([System.Security.Cryptography.CngKey]::Exists($name, $provider)) { 'YES' } else { 'NO' }`;
}

function scriptDeleteWrapKey(safe) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${WRAP_PREFIX}${safe}'
if ([System.Security.Cryptography.CngKey]::Exists($name, $provider)) {
  [System.Security.Cryptography.CngKey]::Open($name, $provider).Delete()
  'DELETED'
} else { 'ABSENT' }`;
}

function scriptAgree(safe, b64peer) {
  return `$ErrorActionPreference = 'Stop'
$provider = [System.Security.Cryptography.CngProvider]::new('${PROVIDER}')
$name = '${WRAP_PREFIX}${safe}'
if (-not [System.Security.Cryptography.CngKey]::Exists($name, $provider)) { throw 'client hardware wrap: no wrap key' }
$key = [System.Security.Cryptography.CngKey]::Open($name, $provider)
$ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]::new($key)
$peer = [System.Security.Cryptography.ECDiffieHellman]::Create()
$peer.ImportSubjectPublicKeyInfo([Convert]::FromBase64String('${b64peer}'), [ref]$null)
$z = $ecdh.DeriveRawSecretAgreement($peer.PublicKey)
[Convert]::ToBase64String($z)`;
}

// ---- backend seams (injected run for tests) ----

function _isAvailable(run) {
  try {
    return String(run(scriptIsAvailable())).trim() === 'YES';
  } catch (err) {
    return false;
  }
}

function _createWrapKey(run, label) {
  const out = String(run(scriptCreateWrapKey(safeLabel(label)))).trim();
  return Buffer.from(out, 'base64');
}

function _getWrapPublicKey(run, label) {
  const out = String(run(scriptGetWrapPublicKey(safeLabel(label)))).trim();
  if (out === 'NULL') {
    return null;
  }
  return Buffer.from(out, 'base64');
}

function _hasWrapKey(run, label) {
  return String(run(scriptHasWrapKey(safeLabel(label)))).trim() === 'YES';
}

function _deleteWrapKey(run, label) {
  return String(run(scriptDeleteWrapKey(safeLabel(label)))).trim() === 'DELETED';
}

function _agree(run, label, peerPublicDer) {
  const b64 = Buffer.from(peerPublicDer).toString('base64');
  const out = String(run(scriptAgree(safeLabel(label), b64))).trim();
  return Buffer.from(out, 'base64');
}

// ---- public API (real PowerShell run) ----

function isAvailable() {
  return _isAvailable(realRunPowerShell);
}

function createWrapKey(label) {
  return _createWrapKey(realRunPowerShell, label);
}

function getWrapPublicKey(label) {
  return _getWrapPublicKey(realRunPowerShell, label);
}

function hasWrapKey(label) {
  return _hasWrapKey(realRunPowerShell, label);
}

function deleteWrapKey(label) {
  return _deleteWrapKey(realRunPowerShell, label);
}

function agree(label, peerPublicDer) {
  return _agree(realRunPowerShell, label, peerPublicDer);
}

module.exports = {
  kind: KIND,
  isAvailable,
  createWrapKey,
  getWrapPublicKey,
  hasWrapKey,
  deleteWrapKey,
  agree,
  // internal seams exported for tests (script construction / parsing / fail-closed)
  _isAvailable,
  _createWrapKey,
  _getWrapPublicKey,
  _hasWrapKey,
  _deleteWrapKey,
  _agree,
  scriptIsAvailable,
  scriptCreateWrapKey,
  scriptGetWrapPublicKey,
  scriptHasWrapKey,
  scriptDeleteWrapKey,
  scriptAgree,
  safeLabel,
};

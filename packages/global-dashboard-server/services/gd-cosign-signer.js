// ===============================================================================
// FIREALIVE GD -- Cosign Signer (B6c PR-5, verbatim twin)
//
// Cosign shell-out wrapper. The Cloud & IaC generator (Sub-phase 4 /
// C12) calls signBlob() during bundle assembly to produce a Sigstore-
// compatible signature on the output bundle archive.
//
// SOC-GRADE: SIGSTORE OR 503
// ==========================
//
// Per the cross-cutting Sigstore/SBOM decisions in R3K-DETAILED-BUILD-
// PLAN-v1 (BUILD-PLAN-v23 R3k cross-cutting locked decisions), this
// service refuses to fall back to any non-Sigstore signing path. If
// `cosign` is not installed on the FireAlive host, signBlob() throws
// CosignNotInstalledError. The caller in routes/gd-cloud.js (the cloud route)
// catches that specific error class and returns 503 with the install-
// command message rather than producing a bundle without a Sigstore-
// verifiable signature.
//
// DECOUPLED FROM SIGNING-KEY LIFECYCLE
// ====================================
//
// This wrapper takes the unwrapped private key PEM as an argument
// rather than fetching/unwrapping itself. The Cloud & IaC generator
// (C12) is responsible for: (1) fetching the active signing key row
// from cloud_iac_signing_keys table via the lifecycle service (C11),
// (2) unwrapping the private key bytes via KMS, then (3) calling
// signBlob with the PEM string. This decoupling lets cosign-signer
// ship before cloud-iac-signing-keys without a circular dependency.
//
// CONTRACT
// ========
//
//   signBlob(blobPath, privateKeyPem, outputSignaturePath, options)
//
//     blobPath              Absolute path to the blob to sign
//                           (typically the bundle.tar.gz archive).
//
//     privateKeyPem         PEM-encoded ECDSA P-256 private key
//                           string (already KMS-unwrapped by the
//                           caller). Cosign default algorithm is
//                           cosign-ecdsa-p256.
//
//     outputSignaturePath   Absolute path where the signature file
//                           will be written. Parent dirs are
//                           created if missing.
//
//     options.timeoutMs     Max execution time (default 2 min;
//                           signing is much faster than SBOM
//                           generation).
//
//     Returns               { path, sizeBytes, sha256 }
//
//     Throws                CosignNotInstalledError if `which cosign`
//                           finds nothing. Error otherwise.
//
// SECURITY
// ========
//
// The private key PEM is written to a temp file in a secure
// directory with 0600 perms. The temp file is unlinked in a
// finally block so it never lingers on disk after the signing call
// returns (or throws). The temp dir uses crypto.randomBytes for
// uniqueness so concurrent signings don't collide.
//
// execFileSync with binary 'cosign' and fixed argv (no shell
// interpretation). COSIGN_PASSWORD env var set to empty string so
// cosign doesn't prompt for a password -- our PEM private keys come
// out of the KMS unwrap step already unprotected. COSIGN_YES=true
// suppresses the interactive "y/n" confirmation cosign may emit on
// upload paths (irrelevant for sign-blob without upload, but
// defensive).
//
// stdio is ['ignore', 'ignore', 'pipe'] -- stdout discarded (cosign
// writes the signature directly via --output-signature), stderr
// captured for error surfacing.
//
// KEY-BASED VS KEYLESS
// ====================
//
// This wrapper does KEY-BASED signing only (operator-managed key in
// cloud_iac_signing_keys table). The keyless OIDC flow is for the
// CI/CD generator's pipeline OUTPUT (the operator's CI does keyless
// signing at build time). The Cloud & IaC bundles signed HERE by
// FireAlive itself use the operator-managed key because the
// FireAlive process doesn't have a Sigstore OIDC identity in most
// deployments.
// ===============================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const DEFAULT_TIMEOUT_MS = 2 * 60 * 1000;

class CosignNotInstalledError extends Error {
  constructor(message) {
    super(
      message ||
        'Cosign is not installed on this host. Install via https://github.com/sigstore/cosign (e.g. `curl -sSfL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64 && chmod +x /usr/local/bin/cosign`) and ensure it is on PATH. See docs/cloud-iac-supply-chain.md for full prerequisites.',
    );
    this.name = 'CosignNotInstalledError';
    this.code = 'COSIGN_NOT_INSTALLED';
  }
}

function checkCosignAvailable() {
  const result = spawnSync('which', ['cosign'], { encoding: 'utf8' });
  if (result.status !== 0) return false;
  const out = (result.stdout || '').trim();
  return out.length > 0;
}

function validateAbsolutePath(label, p) {
  if (typeof p !== 'string' || p.length === 0) {
    throw new Error(`${label}: must be a non-empty string`);
  }
  if (p.indexOf('\0') !== -1) {
    throw new Error(`${label}: must not contain null bytes`);
  }
  if (!path.isAbsolute(p)) {
    throw new Error(`${label}: must be an absolute path`);
  }
}

function validatePemString(label, pem) {
  if (typeof pem !== 'string' || pem.length === 0) {
    throw new Error(`${label}: must be a non-empty string`);
  }
  if (!/-----BEGIN [A-Z ]+PRIVATE KEY-----/.test(pem)) {
    throw new Error(`${label}: does not appear to be a PEM-encoded private key`);
  }
}

/**
 * Sign a blob with the supplied PEM-encoded private key using cosign
 * sign-blob.
 *
 * @param   {string} blobPath              absolute path to the blob to sign
 * @param   {string} privateKeyPem         PEM-encoded ECDSA P-256 private key
 * @param   {string} outputSignaturePath   absolute path where the signature
 *                                         will be written
 * @param   {object} [options]
 * @param   {number} [options.timeoutMs]   max execution time (default 2 min)
 * @returns {{path: string, sizeBytes: number, sha256: string}}
 * @throws  {CosignNotInstalledError}      if `cosign` is not on PATH
 * @throws  {Error}                        on timeout, non-zero exit, or
 *                                         output validation failure
 */
function signBlob(blobPath, privateKeyPem, outputSignaturePath, options = {}) {
  validateAbsolutePath('blobPath', blobPath);
  validateAbsolutePath('outputSignaturePath', outputSignaturePath);
  validatePemString('privateKeyPem', privateKeyPem);

  if (!fs.existsSync(blobPath)) {
    throw new Error(`signBlob: blobPath does not exist: ${blobPath}`);
  }

  if (!checkCosignAvailable()) {
    throw new CosignNotInstalledError();
  }

  // Ensure parent dir for the signature output exists
  const outDir = path.dirname(outputSignaturePath);
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  // Write the unwrapped PEM to a 0600 temp file. The directory is
  // OS-tmp + random suffix so concurrent signings can't collide.
  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'firealive-gd-cosign-' + crypto.randomBytes(8).toString('hex') + '-'),
  );
  const keyTmpPath = path.join(tmpDir, 'signing-key.pem');

  try {
    fs.writeFileSync(keyTmpPath, privateKeyPem, { mode: 0o600 });

    const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;

    try {
      execFileSync(
        'cosign',
        [
          'sign-blob',
          '--key', keyTmpPath,
          '--output-signature', outputSignaturePath,
          '--yes',
          blobPath,
        ],
        {
          timeout: timeoutMs,
          stdio: ['ignore', 'ignore', 'pipe'],
          env: {
            ...process.env,
            COSIGN_PASSWORD: '',
            COSIGN_YES: 'true',
          },
        },
      );
    } catch (err) {
      const stderr = err.stderr ? err.stderr.toString('utf8').trim() : '';
      throw new Error(
        `cosign sign-blob failed: ${err.message}${stderr ? ` (stderr: ${stderr.slice(0, 500)})` : ''}`,
      );
    }

    if (!fs.existsSync(outputSignaturePath)) {
      throw new Error(
        `cosign completed but expected signature file not found at ${outputSignaturePath}`,
      );
    }
    const stat = fs.statSync(outputSignaturePath);
    if (stat.size === 0) {
      throw new Error(`cosign produced empty signature at ${outputSignaturePath}`);
    }

    const sigBytes = fs.readFileSync(outputSignaturePath);
    const sha256 = crypto.createHash('sha256').update(sigBytes).digest('hex');

    return {
      path: outputSignaturePath,
      sizeBytes: stat.size,
      sha256,
    };
  } finally {
    // Always clean the temp key file, even if signing threw. Best-
    // effort -- a failure to clean is logged-and-swallowed by the
    // caller's existing audit/logging path; we don't want cleanup
    // failures to mask actual signing errors.
    try {
      if (fs.existsSync(keyTmpPath)) fs.unlinkSync(keyTmpPath);
    } catch { /* swallow */ }
    try {
      if (fs.existsSync(tmpDir)) fs.rmdirSync(tmpDir);
    } catch { /* swallow */ }
  }
}

module.exports = {
  signBlob,
  CosignNotInstalledError,
  DEFAULT_TIMEOUT_MS,
};

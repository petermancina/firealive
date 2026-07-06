// ===============================================================================
// FIREALIVE GD -- SBOM Generator (B6c PR-5, verbatim twin)
//
// Syft shell-out wrapper. The Cloud & IaC generator (Sub-phase 4 / C12)
// calls generateSbom() during bundle assembly to produce an SPDX-JSON
// Software Bill of Materials describing the FireAlive GD install going
// into the deployment artifact.
//
// SOC-GRADE: REAL SBOM OR 503
// ===========================
//
// Per the cross-cutting Sigstore/SBOM decisions in R3K-DETAILED-BUILD-
// PLAN-v1 (BUILD-PLAN-v23 R3k section), this service refuses to fall
// back to anything weaker than a real Syft-generated SBOM. If `syft`
// is not installed on the FireAlive host, generateSbom() throws
// SyftNotInstalledError. The caller in routes/gd-cloud.js (the cloud route) catches
// that specific error class and returns 503 with an explicit install-
// command message rather than producing a bundle with a stub or
// approximate SBOM.
//
// CONTRACT
// ========
//
//   generateSbom(installPath, outputPath, options)
//
//     installPath          Absolute path to the FireAlive GD install
//                          directory to scan (typically the project
//                          root with package.json + node_modules).
//
//     outputPath           Absolute path where the SPDX-JSON SBOM
//                          file will be written. Parent directories
//                          are created if missing.
//
//     options.timeoutMs    Max execution time. Default 5 minutes;
//                          SBOM scan of a typical install completes
//                          in well under 1 minute.
//
//     Returns              { path, sizeBytes, sha256 }
//
//     Throws               SyftNotInstalledError if `which syft`
//                          finds nothing. Error otherwise (timeout,
//                          non-zero exit, output validation
//                          failure, etc.).
//
// SECURITY
// ========
//
// Uses execFileSync with the binary name 'syft' and a fixed argv
// array (no shell interpretation, no word-splitting on the content
// of installPath or outputPath). Argument values are validated to
// be absolute paths without null bytes. Path-traversal protection
// in installPath/outputPath is the caller's responsibility; this
// wrapper does shape validation only.
//
// stdio is ['ignore', 'ignore', 'pipe'] -- stdout is discarded (Syft
// writes the SBOM directly via -o spdx-json=<path>), stderr is
// captured and surfaced in error messages.
//
// PLATFORM
// ========
//
// POSIX-style availability check via `which`. Windows operators
// install syft and ensure it's on PATH; the `which` probe will not
// find it on a pure cmd.exe environment but does work under WSL or
// PowerShell with `which.exe` installed (common). Per the install
// documentation, FireAlive deployment is POSIX-first (Linux container
// or macOS); Windows deployments are out of the SOC-grade primary
// support matrix.
// ===============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

class SyftNotInstalledError extends Error {
  constructor(message) {
    super(
      message ||
        'Syft is not installed on this host. Install via https://github.com/anchore/syft (e.g. `curl -sSfL https://raw.githubusercontent.com/anchore/syft/v1.44.0/install.sh | sh -s -- -b /usr/local/bin v1.44.0`) and ensure it is on PATH. See docs/cloud-iac-supply-chain.md for full prerequisites.',
    );
    this.name = 'SyftNotInstalledError';
    this.code = 'SYFT_NOT_INSTALLED';
  }
}

function checkSyftAvailable() {
  const result = spawnSync('which', ['syft'], { encoding: 'utf8' });
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

/**
 * Generate an SPDX-JSON SBOM for the given install path.
 *
 * @param   {string} installPath           absolute path to the dir to scan
 * @param   {string} outputPath            absolute path to write the SBOM
 * @param   {object} [options]
 * @param   {number} [options.timeoutMs]   max execution time (default 5 min)
 * @returns {{path: string, sizeBytes: number, sha256: string}}
 * @throws  {SyftNotInstalledError}        if `syft` is not on PATH
 * @throws  {Error}                        on non-zero exit, timeout, or
 *                                         output validation failure
 */
function generateSbom(installPath, outputPath, options = {}) {
  validateAbsolutePath('installPath', installPath);
  validateAbsolutePath('outputPath', outputPath);

  if (!checkSyftAvailable()) {
    throw new SyftNotInstalledError();
  }

  // Ensure parent dir for the output file exists
  const outDir = path.dirname(outputPath);
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;

  try {
    execFileSync(
      'syft',
      [installPath, '-o', `spdx-json=${outputPath}`],
      {
        timeout: timeoutMs,
        stdio: ['ignore', 'ignore', 'pipe'],
      },
    );
  } catch (err) {
    const stderr = err.stderr ? err.stderr.toString('utf8').trim() : '';
    throw new Error(
      `syft invocation failed: ${err.message}${stderr ? ` (stderr: ${stderr.slice(0, 500)})` : ''}`,
    );
  }

  if (!fs.existsSync(outputPath)) {
    throw new Error(`syft completed but expected output file not found at ${outputPath}`);
  }
  const stat = fs.statSync(outputPath);
  if (stat.size === 0) {
    throw new Error(`syft produced empty output at ${outputPath}`);
  }

  const fileBytes = fs.readFileSync(outputPath);
  const sha256 = crypto.createHash('sha256').update(fileBytes).digest('hex');

  // Lightweight structural validation: parseable JSON containing
  // an SPDX version marker. We don't validate the full SPDX schema;
  // Syft's output is trusted to be well-formed SPDX-JSON if the
  // invocation succeeded with our flags.
  let parsed;
  try {
    parsed = JSON.parse(fileBytes.toString('utf8'));
  } catch (parseErr) {
    throw new Error(`syft output is not valid JSON: ${parseErr.message}`);
  }
  if (!parsed.spdxVersion && !parsed.SPDXVersion) {
    throw new Error('syft output missing SPDX version marker (spdxVersion / SPDXVersion)');
  }

  return {
    path: outputPath,
    sizeBytes: stat.size,
    sha256,
  };
}

module.exports = {
  generateSbom,
  SyftNotInstalledError,
  DEFAULT_TIMEOUT_MS,
};

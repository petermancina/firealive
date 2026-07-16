// ===============================================================================
// FIREALIVE GD -- Cloud & IaC Generator (B6c PR-5 twin)
//
// Main orchestrator service for the Cloud & IaC artifact generator
// (Sub-phase 4). Produces deployable Infrastructure-as-Code bundles
// for the operator's chosen (provider, iac_tool) combination, with
// SBOM + Sigstore signing per the locked Q1 decision.
//
// PIPELINE
// ========
//
//   1. Validate (provider, iac_tool) combination against the matrix
//      of supported pairs.
//   2. Ensure an active Cloud & IaC signing key exists (R3k C11),
//      generating one on the spot if this is the first generation.
//   3. Capture install snapshot: users count by role, integration
//      platforms (names only, no credentials), KMS provider, data
//      volume, version + fuse. Persisted with the bundle for audit.
//   4. Dispatch to the template module for iac_tool, passing the
//      snapshot + provider. Templates return a list of files (path
//      + content) destined for the iac/ subdirectory of the bundle.
//   5. Write the template-produced IaC files to the bundle workdir.
//   6. Write README.md (deployment instructions + secrets mapping
//      for the chosen provider).
//   7. Generate SBOM via sbom-generator (R3k C9). 503 on caller side
//      if Syft missing.
//   8. Write bundle-manifest.json listing every file with SHA-256.
//   9. Tar + gzip the workdir into bundle.tar.gz.
//   10. Sign bundle.tar.gz via cosign-signer (R3k C10) with the
//       active signing key from C11. 503 on caller side if Cosign
//       missing.
//   11. INSERT cloud_packages row with all paths, hashes, snapshot,
//       and signing_key_id.
//   12. Return the row's id + paths + hashes.
//
// FAILURE SEMANTICS
// =================
//
// Errors propagate to the caller (routes/cloud.js in C19), which
// catches:
//
//   SyftNotInstalledError    -> 503 with the install-command message
//   CosignNotInstalledError  -> 503 with the install-command message
//   invalid provider/tool    -> 400 with the matrix of valid pairs
//   any other Error          -> 500 with the error message
//
// On any failure mid-pipeline the partial bundle workdir is removed
// in a finally block so a failed generation never leaves stray bytes
// in data/cloud-packages.
//
// PROVIDER x IAC TOOL MATRIX
// ==========================
//
// Not every combination is valid. The PROVIDER_TOOL_MATRIX below
// records the supported pairs. Cloud Mode requires a confidential
// VM, so the provider set is the three that offer one (AWS, Azure,
// GCP); container formats are not generated (the GD needs a
// per-instance hardware root, which a TPM-less container cannot
// provide):
//
//   - CloudFormation is AWS-only.
//   - Bicep is Azure-only.
//   - GCP Deployment Manager is GCP-only.
//   - Terraform and Pulumi are universal (work for every supported
//     provider).
//
// The route handler in C19 validates the combination before invoking
// generatePackage(); this service does its own validation defensively.
// ===============================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const logger = {
  info: (m, o) => console.log('[gd-cloud-iac-generator] ' + m, o || ''),
  warn: (m, o) => console.warn('[gd-cloud-iac-generator] ' + m, o || ''),
  error: (m, o) => console.error('[gd-cloud-iac-generator] ' + m, o || ''),
};
const { DB_PATH } = require('../db-init');
const sbomGenerator = require('./gd-sbom-generator');
const cosignSigner = require('./gd-cosign-signer');
const signingKeys = require('./gd-cloud-iac-signing-keys');
const gdDataRoot = require('../lib/gd-data-root');

// -- Constants ----------------------------------------------------------

const PROVIDER_TOOL_MATRIX = {
  aws:   ['terraform', 'pulumi', 'cloudformation'],
  azure: ['terraform', 'pulumi', 'bicep'],
  gcp:   ['terraform', 'pulumi', 'gcp-dm'],
};

const SECRETS_MAPPING_BY_PROVIDER = {
  aws:   'AWS Secrets Manager (recommended) or Systems Manager Parameter Store. The generated IaC references secrets by ARN.',
  azure: 'Azure Key Vault. The generated IaC references secrets by Key Vault secret URI.',
  gcp:   'Google Secret Manager. The generated IaC references secrets by resource name (projects/<project>/secrets/<name>/versions/latest).',
};

function resolveCloudPackagesDir(override) {
  // P1-1: GD_CLOUD_PACKAGES_DIR, else the canonical GD data root.
  return override || gdDataRoot.cloudPackagesDir();
}

function ensureDir(dir) {
  // 0700, and refuses an already group- or world-accessible directory.
  return gdDataRoot.ensureDir(dir);
}

function sha256OfFile(filePath) {
  const bytes = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

// -- Install snapshot ---------------------------------------------------

function captureInstallSnapshot(db) {
  const safe = (fn, fallback) => {
    try { return fn(); } catch (e) { return fallback; }
  };

  const userTotal = safe(
    () => db.prepare('SELECT COUNT(*) AS n FROM users').get().n,
    0,
  );
  const byRole = safe(() => {
    const rows = db.prepare("SELECT role, COUNT(*) AS n FROM users GROUP BY role").all();
    const out = {};
    for (const r of rows) out[r.role || 'unknown'] = r.n;
    return out;
  }, {});

  const integrations = safe(() => {
    // integration_config schema varies; capture platform name without
    // credentials. Best-effort enumeration.
    const rows = db.prepare("SELECT key FROM integration_config").all();
    return rows.map(r => ({ key: r.key }));
  }, []);

  let dbSizeBytes = 0;
  try {
    if (fs.existsSync(DB_PATH)) dbSizeBytes = fs.statSync(DB_PATH).size;
  } catch (e) { /* keep 0 */ }

  const kmsProviders = safe(() => {
    const rows = db
      .prepare("SELECT name FROM kms_providers WHERE status = 'active'")
      .all();
    return rows.map(r => r.name);
  }, []);

  let versionInfo = { version: 'unknown', fuse_counter: null, build_id: null };
  try {
    const v = require('../package.json');
    versionInfo = {
      version: v.version || 'unknown',
      fuse_counter: typeof v.fuseCounter === 'number' ? v.fuseCounter : null,
      build_id: v.buildId || null,
    };
  } catch (e) { /* keep defaults */ }

  return {
    captured_at: new Date().toISOString(),
    users: { total: userTotal, by_role: byRole },
    integrations,
    kms_providers: kmsProviders,
    data: { db_size_bytes: dbSizeBytes },
    version: versionInfo,
  };
}

// -- README -------------------------------------------------------------

function buildReadme(provider, iacTool, snapshot, packageId, signingKeyFingerprint) {
  const lines = [
    `# FireAlive GD Deployment Bundle`,
    ``,
    `**Package id:** \`${packageId}\``,
    `**Generated:** ${snapshot.captured_at}`,
    `**Source version:** ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    `**Provider:** ${provider}`,
    `**IaC tool:** ${iacTool}`,
    ``,
    `## Contents`,
    ``,
    `- \`iac/\` -- deployable Infrastructure-as-Code files for ${iacTool} targeting ${provider}.`,
    `- \`sbom.spdx.json\` -- Software Bill of Materials for the FireAlive GD install being deployed.`,
    `- \`bundle-manifest.json\` -- per-file SHA-256 integrity attestation.`,
    `- \`README.md\` -- this file.`,
    ``,
    `## Verifying the signature`,
    ``,
    `The archive \`bundle.tar.gz\` is signed by the FireAlive GD Cloud & IaC signing key. Verify with cosign:`,
    ``,
    `\`\`\`bash`,
    `cosign verify-blob --key <cloud-iac-public-key.pem> --signature bundle.tar.gz.sig bundle.tar.gz`,
    `\`\`\``,
    ``,
    `Signing key fingerprint (SHA-256 of SPKI DER): \`${signingKeyFingerprint}\``,
    ``,
    `Retrieve the public key via \`GET /api/cloud/packages/${packageId}/public-key\` on the originating FireAlive GD install.`,
    ``,
    `## Secrets mapping`,
    ``,
    SECRETS_MAPPING_BY_PROVIDER[provider] || 'Secrets mapping for this provider is not documented.',
    ``,
    `Required environment variables (set by the generated IaC or in your provider's secret store):`,
    ``,
    `- \`GD_ENCRYPTION_KEY\` -- 32-byte hex Tier-1 KEK, sourced from the cloud secret store (required in cloud mode; the JWT-secret fallback is refused).`,
    `- \`GD_JWT_SECRET\` -- at least 16 random characters, never share.`,
    `- \`BACKUP_DIR\` (optional) -- override default \`/data/backups\`.`,
    `- \`GD_CLOUD_PACKAGES_DIR\` (optional) -- override default \`/data/cloud-packages\`.`,
    ``,
    `## Install posture at generation time`,
    ``,
    `- Users: ${snapshot.users.total} total (${JSON.stringify(snapshot.users.by_role)})`,
    `- Active KMS providers: ${snapshot.kms_providers.length > 0 ? snapshot.kms_providers.join(', ') : 'none (env-var KEK)'}`,
    `- DB size at capture: ${snapshot.data.db_size_bytes} bytes`,
    ``,
    `These values were baked into the IaC files as deployment baseline. Adjust them in the IaC source before applying if your target environment differs.`,
    ``,
    `## Deploying`,
    ``,
    `1. Verify the signature (above).`,
    `2. Provision secrets in your provider's secret store per the mapping above.`,
    `3. Run the IaC tool against the files in \`iac/\` (e.g. \`terraform init && terraform apply\`).`,
    `4. After first boot, run \`POST /api/regression-test\` against the new GD install to confirm health.`,
    ``,
  ];
  return lines.join('\n');
}

// -- Bundle manifest ----------------------------------------------------

function buildBundleManifest(packageId, provider, iacTool, snapshot, files, sbomEntry, signingKeyId, signingKeyFingerprint) {
  return {
    format: 'firealive-gd-cloud-iac-bundle-v1',
    package_id: packageId,
    provider,
    iac_tool: iacTool,
    generated_at: snapshot.captured_at,
    source_version: snapshot.version,
    signing_key: {
      id: signingKeyId,
      fingerprint_sha256: signingKeyFingerprint,
      algorithm: 'cosign-ecdsa-p256',
    },
    sbom: sbomEntry,
    files: files.map(f => ({
      path: f.relativePath,
      size_bytes: f.sizeBytes,
      sha256: f.sha256,
    })),
  };
}

// -- tar+gzip via system tar --------------------------------------------

function tarGzipDirectory(sourceDir, outputArchivePath) {
  // -C sourceDir . packs everything inside sourceDir without the
  // sourceDir prefix in the tar entries. Operators unpack with
  // `tar -xzf bundle.tar.gz` into an empty directory.
  execFileSync(
    'tar',
    ['-czf', outputArchivePath, '-C', sourceDir, '.'],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  );
}

// -- Public API ---------------------------------------------------------

/**
 * Generate a Cloud & IaC bundle.
 *
 * @param {object} db                    SQLite db handle
 * @param {string} provider              one of PROVIDER_TOOL_MATRIX keys
 * @param {string} iacTool               valid tool for the provider
 * @param {object} options
 * @param {number} options.userId        users.id for generated_by FK
 * @param {string} [options.cloudPackagesDir]   override storage dir
 * @returns {object}                     {id, paths, hashes, snapshot}
 * @throws  {SyftNotInstalledError}      if syft missing
 * @throws  {CosignNotInstalledError}    if cosign missing
 * @throws  {Error}                      on invalid combination or
 *                                       pipeline failure
 */
function generatePackage(db, provider, iacTool, options = {}) {
  // Validate
  if (!PROVIDER_TOOL_MATRIX[provider]) {
    throw new Error(`invalid provider '${provider}'; valid: ${Object.keys(PROVIDER_TOOL_MATRIX).join(', ')}`);
  }
  if (!PROVIDER_TOOL_MATRIX[provider].includes(iacTool)) {
    throw new Error(
      `invalid (provider, iac_tool) combination ('${provider}', '${iacTool}'); valid tools for ${provider}: ${PROVIDER_TOOL_MATRIX[provider].join(', ')}`,
    );
  }
  if (!options.userId || typeof options.userId !== 'number') {
    throw new Error('generatePackage: options.userId (integer users.id) is required');
  }

  // Signing key (ensure + fetch active)
  signingKeys.ensureActiveKey(db);
  const activeKey = signingKeys.getActiveSigningKey(db);

  // Snapshot
  const snapshot = captureInstallSnapshot(db);

  // Template dispatch (lazy require so the module load chain doesn't
  // require all templates at C13 boot -- templates ship in C14)
  let templateModule;
  try {
    templateModule = require('./gd-cloud-iac-templates/' + iacTool);
  } catch (e) {
    throw new Error(
      `template module for iac_tool='${iacTool}' could not be loaded: ${e.message}`,
    );
  }
  if (typeof templateModule.render !== 'function') {
    throw new Error(`template module for '${iacTool}' missing render() function`);
  }
  const rendered = templateModule.render(snapshot, provider);
  if (!rendered || !Array.isArray(rendered.files)) {
    throw new Error(`template '${iacTool}' did not return {files: [...]}`);
  }

  // Allocate package id + workdir
  const packageId = crypto.randomBytes(16).toString('hex');
  const cloudPackagesDir = resolveCloudPackagesDir(options.cloudPackagesDir);
  ensureDir(cloudPackagesDir);
  const bundleDir = path.join(cloudPackagesDir, packageId);
  const bundleWorkDir = path.join(bundleDir, '_work');
  ensureDir(bundleWorkDir);
  const iacDir = path.join(bundleWorkDir, 'iac');
  ensureDir(iacDir);

  try {
    // 1. Write template-produced IaC files
    const fileRecords = [];
    for (const f of rendered.files) {
      if (typeof f.path !== 'string' || typeof f.content !== 'string') {
        throw new Error(`template '${iacTool}' produced an invalid file entry`);
      }
      // Defend against path traversal in template output
      const safeRelative = path.normalize(f.path).replace(/^[\\/]+/, '');
      if (safeRelative.indexOf('..') === 0 || safeRelative.indexOf(path.sep + '..') !== -1) {
        throw new Error(`template '${iacTool}' produced a path-traversal path: ${f.path}`);
      }
      const absolutePath = path.join(iacDir, safeRelative);
      ensureDir(path.dirname(absolutePath));
      fs.writeFileSync(absolutePath, f.content, 'utf8');
      const stat = fs.statSync(absolutePath);
      const sha256 = sha256OfFile(absolutePath);
      fileRecords.push({
        relativePath: 'iac/' + safeRelative,
        absolutePath,
        sizeBytes: stat.size,
        sha256,
      });
    }

    // 2. Write README.md
    const readmePath = path.join(bundleWorkDir, 'README.md');
    const readmeText = buildReadme(provider, iacTool, snapshot, packageId, activeKey.publicKeyFingerprint);
    fs.writeFileSync(readmePath, readmeText, 'utf8');
    fileRecords.push({
      relativePath: 'README.md',
      absolutePath: readmePath,
      sizeBytes: fs.statSync(readmePath).size,
      sha256: sha256OfFile(readmePath),
    });

    // 3. SBOM
    const sbomPath = path.join(bundleWorkDir, 'sbom.spdx.json');
    const sbomScanDir = path.join(__dirname, '..');
    const sbomResult = sbomGenerator.generateSbom(sbomScanDir, sbomPath);
    fileRecords.push({
      relativePath: 'sbom.spdx.json',
      absolutePath: sbomPath,
      sizeBytes: sbomResult.sizeBytes,
      sha256: sbomResult.sha256,
    });

    // 4. Bundle manifest (lists every file's sha; itself NOT in the
    //    file list since the manifest's own hash would be circular)
    const manifestObj = buildBundleManifest(
      packageId, provider, iacTool, snapshot, fileRecords,
      { path: 'sbom.spdx.json', sha256: sbomResult.sha256, size_bytes: sbomResult.sizeBytes },
      activeKey.id, activeKey.publicKeyFingerprint,
    );
    const manifestPath = path.join(bundleWorkDir, 'bundle-manifest.json');
    const manifestText = JSON.stringify(manifestObj, null, 2);
    fs.writeFileSync(manifestPath, manifestText, 'utf8');
    const manifestSha = sha256OfFile(manifestPath);

    // 5. Tar+gzip the workdir
    const archivePath = path.join(bundleDir, 'bundle.tar.gz');
    tarGzipDirectory(bundleWorkDir, archivePath);

    // 6. Sign the archive
    const signaturePath = path.join(bundleDir, 'bundle.tar.gz.sig');
    const sigResult = cosignSigner.signBlob(
      archivePath,
      activeKey.privateKeyPem,
      signaturePath,
    );

    // 7. Move sidecar manifest + sbom outside the workdir for direct
    //    inspection without unpacking the archive
    const sidecarManifestPath = path.join(bundleDir, 'bundle-manifest.json');
    const sidecarSbomPath = path.join(bundleDir, 'sbom.spdx.json');
    fs.copyFileSync(manifestPath, sidecarManifestPath);
    fs.copyFileSync(sbomPath, sidecarSbomPath);

    // 8. INSERT cloud_packages row
    const archiveStat = fs.statSync(archivePath);
    db.prepare(
      `INSERT INTO cloud_packages
         (id, provider, iac_tool, generated_by,
          bundle_dir_path, bundle_archive_path,
          manifest_sha256, sbom_path, sbom_sha256,
          signature_path, signature_sha256,
          signing_key_id, install_snapshot_json, size_bytes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      packageId,
      provider,
      iacTool,
      options.userId,
      bundleDir,
      archivePath,
      manifestSha,
      sidecarSbomPath,
      sbomResult.sha256,
      signaturePath,
      sigResult.sha256,
      activeKey.id,
      JSON.stringify(snapshot),
      archiveStat.size,
    );

    // 9. Clean up the workdir (sidecar files already copied)
    fs.rmSync(bundleWorkDir, { recursive: true, force: true });

    logger.info('cloud-iac-generator: package generated', {
      id: packageId,
      provider,
      iac_tool: iacTool,
      signing_key_id: activeKey.id,
      size_bytes: archiveStat.size,
    });

    return {
      id: packageId,
      provider,
      iac_tool: iacTool,
      bundle_dir_path: bundleDir,
      bundle_archive_path: archivePath,
      manifest_sha256: manifestSha,
      sbom_path: sidecarSbomPath,
      sbom_sha256: sbomResult.sha256,
      signature_path: signaturePath,
      signature_sha256: sigResult.sha256,
      signing_key_id: activeKey.id,
      signing_key_fingerprint: activeKey.publicKeyFingerprint,
      size_bytes: archiveStat.size,
      generated_at: snapshot.captured_at,
      install_snapshot: snapshot,
    };
  } catch (err) {
    // Best-effort cleanup of partial bundle dir on any failure
    try {
      if (fs.existsSync(bundleDir)) fs.rmSync(bundleDir, { recursive: true, force: true });
    } catch (cleanupErr) {
      logger.warn('cloud-iac-generator: failed to clean partial bundle', {
        bundleDir,
        error: cleanupErr.message,
      });
    }
    throw err;
  }
}

module.exports = {
  generatePackage,
  PROVIDER_TOOL_MATRIX,
  SECRETS_MAPPING_BY_PROVIDER,
};

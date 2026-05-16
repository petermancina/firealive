// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Cloud & IaC Templates: Docker Image Manifest (R3k C14)
//
// Universal. Produces a JSON manifest describing the Docker images
// the deployment requires and their expected SHA-256 digests. NOT
// the same thing as an OCI manifest (which lives inside the registry);
// this is an operator-facing inventory used during deployment
// pre-flight to verify that the images being pulled match the
// expected hashes recorded at generation time.
// ═══════════════════════════════════════════════════════════════════════════════

function render(snapshot, provider) {
  const manifest = {
    format: 'firealive-docker-image-manifest-v1',
    generated_at: snapshot.captured_at,
    provider,
    source_version: snapshot.version,
    images: [
      {
        name: 'firealive-server',
        reference: 'ghcr.io/petermancina/firealive:latest',
        digest_sha256: 'sha256:UNKNOWN_PIN_AT_DEPLOY_TIME',
        notes: 'Pin to a specific tag (e.g. v1.0.37) and capture the digest with `docker image inspect` after pull. Update the digest field here to enable preflight verification.',
      },
    ],
    preflight_verify: [
      '# After pulling, verify each image hash matches the digest above:',
      '#   docker image inspect ghcr.io/petermancina/firealive:v1.0.37 --format \'{{.Id}}\'',
      '# Compare the output sha256 against images[].digest_sha256 in this manifest.',
    ],
    notes: [
      `Snapshot at generation: users=${snapshot.users.total}, db_size_bytes=${snapshot.data.db_size_bytes}, version=${snapshot.version.version}`,
      'This manifest is a deployment integrity artifact alongside the SBOM. Whereas the SBOM records the source-code BOM, this records the runtime container image inventory.',
    ],
  };

  return {
    files: [
      { path: 'image-manifest.json', content: JSON.stringify(manifest, null, 2) },
    ],
  };
}

module.exports = { render };

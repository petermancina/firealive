// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Cloud & IaC Templates: GCP Deployment Manager (R3k C14)
//
// GCP-only.
// ═══════════════════════════════════════════════════════════════════════════════

function render(snapshot, provider) {
  if (provider !== 'gcp') {
    throw new Error(`gcp-dm template: GCP-only, got '${provider}'`);
  }
  const main = [
    `# FireAlive GCP Deployment Manager configuration`,
    `# Snapshot at generation: users=${snapshot.users.total}, db_size_bytes=${snapshot.data.db_size_bytes}, version=${snapshot.version.version}`,
    '',
    'resources:',
    '  - name: firealive-tier1-key',
    '    type: gcp-types/secretmanager-v1:projects.secrets',
    '    properties:',
    '      secretId: firealive-tier1-key',
    '      replication: { automatic: {} }',
    '',
    '  - name: firealive-tier1-key-version',
    '    type: gcp-types/secretmanager-v1:projects.secrets.versions',
    '    properties:',
    '      parent: $(ref.firealive-tier1-key.name)',
    '      payload:',
    '        data: $(ref.firealive-tier1-key-data)',
    '',
    '  - name: firealive-jwt-secret',
    '    type: gcp-types/secretmanager-v1:projects.secrets',
    '    properties:',
    '      secretId: firealive-jwt-secret',
    '      replication: { automatic: {} }',
    '',
    '  - name: firealive-cloud-run',
    '    type: gcp-types/run-v2:projects.locations.services',
    '    properties:',
    '      parent: projects/your-project-id/locations/us-central1',
    '      serviceId: firealive',
    '      template:',
    '        containers:',
    '          - image: ghcr.io/petermancina/firealive:latest',
    '            ports:',
    '              - containerPort: 3000',
    '            env:',
    '              - name: TIER1_ENCRYPTION_KEY',
    '                valueSource:',
    '                  secretKeyRef:',
    '                    secret: $(ref.firealive-tier1-key.name)',
    '                    version: latest',
    '              - name: JWT_SECRET',
    '                valueSource:',
    '                  secretKeyRef:',
    '                    secret: $(ref.firealive-jwt-secret.name)',
    '                    version: latest',
    '',
    'outputs:',
    '  - name: serviceUrl',
    '    value: $(ref.firealive-cloud-run.uri)',
    '',
    '# Note: GCP Deployment Manager has been in deprecation track since 2024;',
    '# for new projects prefer Terraform or the Pulumi GCP provider. This',
    '# template is retained for parity with the existing Cloud & IaC menu.',
    '',
  ].join('\n');
  return {
    files: [{ path: 'firealive.yaml', content: main }],
  };
}

module.exports = { render };

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Cloud & IaC Templates: GCP Deployment Manager (R3k C14, Cloud Mode B5h)
//
// GCP-only. Provisions FireAlive on a CONFIDENTIAL VM: AMD SEV-SNP memory
// encryption (confidentialInstanceConfig) plus Shielded VM, which provides a
// vTPM (TPM 2.0 hardware root of trust), secure boot, and integrity
// monitoring. Cloud mode REQUIRES confidential computing and is attested at
// boot, so the managed-container path (Cloud Run) is intentionally not emitted.
//
// Secrets live in Secret Manager and are fetched at boot by the instance
// service account; they are never placed in metadata in cleartext, because the
// confidential-VM model assumes the provider can read instance metadata but not
// guest memory. Deployment Manager expands $(...) as its own reference syntax,
// so the boot script uses backtick command substitution instead; the template
// carries no backslash escapes.
// ═══════════════════════════════════════════════════════════════════════════════

const NL = String.fromCharCode(10);

function render(snapshot, provider) {
  if (provider !== 'gcp') {
    throw new Error(`gcp-dm template: GCP-only, got '${provider}'`);
  }
  const main = [
    '# FireAlive GCP Deployment Manager configuration - confidential VM',
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
    '  - name: firealive-jwt-secret-version',
    '    type: gcp-types/secretmanager-v1:projects.secrets.versions',
    '    properties:',
    '      parent: $(ref.firealive-jwt-secret.name)',
    '      payload:',
    '        data: $(ref.firealive-jwt-secret-data)',
    '',
    '  # Confidential VM (SEV-SNP) with Shielded VM: vTPM (TPM 2.0 root of',
    '  # trust), secure boot, and integrity monitoring. The machine type must be',
    '  # SEV-SNP-capable (n2d / c2d) on the AMD Milan platform; SEV-SNP requires',
    '  # the host to terminate (no live migration) on maintenance. On-demand',
    '  # only: cloud mode refuses spot / autoscaled / ephemeral-fleet instances.',
    '  - name: firealive',
    '    type: compute.v1.instance',
    '    properties:',
    '      zone: us-central1-a',
    '      machineType: zones/us-central1-a/machineTypes/n2d-standard-2',
    '      minCpuPlatform: AMD Milan',
    '      confidentialInstanceConfig:',
    '        enableConfidentialCompute: true',
    '        confidentialInstanceType: SEV_SNP',
    '      shieldedInstanceConfig:',
    '        enableVtpm: true',
    '        enableIntegrityMonitoring: true',
    '        enableSecureBoot: true',
    '      scheduling:',
    '        onHostMaintenance: TERMINATE',
    '        automaticRestart: true',
    '        preemptible: false',
    '      disks:',
    '        - boot: true',
    '          autoDelete: true',
    '          initializeParams:',
    '            sourceImage: projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64',
    '      networkInterfaces:',
    '        - network: global/networks/default',
    '          accessConfigs:',
    '            - name: External NAT',
    '              type: ONE_TO_ONE_NAT',
    '      serviceAccounts:',
    '        - email: default',
    '          scopes:',
    '            - https://www.googleapis.com/auth/cloud-platform',
    '      labels:',
    '        deployment_mode: cloud',
    '      metadata:',
    '        items:',
    '          - key: startup-script',
    '            value: |',
    '              #!/bin/bash',
    '              set -e',
    '              mkdir -p /etc/firealive',
    '              TIER1=`gcloud secrets versions access latest --secret=firealive-tier1-key`',
    '              JWT=`gcloud secrets versions access latest --secret=firealive-jwt-secret`',
    '              umask 077',
    '              echo "TIER1_ENCRYPTION_KEY=$TIER1" > /etc/firealive/.env',
    '              echo "JWT_SECRET=$JWT" >> /etc/firealive/.env',
    '              echo "FIREALIVE_DEPLOYMENT_MODE=cloud" >> /etc/firealive/.env',
    '              systemctl enable --now firealive',
    '',
    'outputs:',
    '  - name: instanceIp',
    '    value: $(ref.firealive.networkInterfaces[0].accessConfigs[0].natIP)',
    '',
    '# Secrets are fetched by the instance service account, which must hold',
    '# roles/secretmanager.secretAccessor on the two secrets above. The data',
    '# values come from the $(ref.*-data) deployment inputs.',
    '# Note: GCP Deployment Manager has been in deprecation track since 2024;',
    '# for new projects prefer Terraform or the Pulumi GCP provider. This',
    '# template is retained for parity with the existing Cloud & IaC menu.',
    '',
  ].join(NL);
  return {
    files: [{ path: 'firealive.yaml', content: main }],
  };
}

module.exports = { render };

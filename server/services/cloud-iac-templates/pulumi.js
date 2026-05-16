// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Cloud & IaC Templates: Pulumi TypeScript (R3k C14)
//
// Per-provider Pulumi templates emitting index.ts + Pulumi.yaml +
// package.json. Operators run `npm install && pulumi up`.
// ═══════════════════════════════════════════════════════════════════════════════

const PROVIDER_FNS = {
  aws: renderAws,
  azure: renderAzure,
  gcp: renderGcp,
  hetzner: renderHetzner,
  ovhcloud: renderOvhcloud,
  exoscale: renderExoscale,
};

function render(snapshot, provider) {
  const fn = PROVIDER_FNS[provider];
  if (!fn) throw new Error(`pulumi template: unsupported provider '${provider}'`);
  return { files: fn(snapshot) };
}

function pulumiYaml(provider) {
  return [
    'name: firealive',
    'runtime: nodejs',
    'description: FireAlive deployment (Pulumi / TypeScript)',
    `# Provider: ${provider}`,
    '',
  ].join('\n');
}

function packageJson(provider) {
  const deps = {
    aws:      '"@pulumi/aws": "^6.0.0"',
    azure:    '"@pulumi/azure-native": "^2.0.0"',
    gcp:      '"@pulumi/gcp": "^7.0.0"',
    hetzner:  '"@pulumi/command": "^0.9.0"',
    ovhcloud: '"@pulumi/command": "^0.9.0"',
    exoscale: '"@pulumi/command": "^0.9.0"',
  };
  return [
    '{',
    '  "name": "firealive-pulumi",',
    '  "main": "index.ts",',
    '  "dependencies": {',
    '    "@pulumi/pulumi": "^3.100.0",',
    `    ${deps[provider]}`,
    '  },',
    '  "devDependencies": {',
    '    "@types/node": "^20.0.0",',
    '    "typescript": "^5.0.0"',
    '  }',
    '}',
    '',
  ].join('\n');
}

function renderAws(snapshot) {
  const idx = [
    'import * as pulumi from "@pulumi/pulumi";',
    'import * as aws from "@pulumi/aws";',
    '',
    'const cfg = new pulumi.Config();',
    'const tier1Key = cfg.requireSecret("tier1EncryptionKey");',
    'const jwtSecret = cfg.requireSecret("jwtSecret");',
    'const imageRef = cfg.get("firealiveImage") ?? "ghcr.io/petermancina/firealive:latest";',
    '',
    'const tier1Secret = new aws.secretsmanager.Secret("firealive-tier1", { name: "firealive/tier1-encryption-key" });',
    'new aws.secretsmanager.SecretVersion("firealive-tier1-v", {',
    '    secretId: tier1Secret.id,',
    '    secretString: tier1Key,',
    '});',
    '',
    'const jwtSecretRes = new aws.secretsmanager.Secret("firealive-jwt", { name: "firealive/jwt-secret" });',
    'new aws.secretsmanager.SecretVersion("firealive-jwt-v", {',
    '    secretId: jwtSecretRes.id,',
    '    secretString: jwtSecret,',
    '});',
    '',
    'const cluster = new aws.ecs.Cluster("firealive", { name: "firealive" });',
    '',
    'export const clusterArn = cluster.arn;',
    'export const note = "Production deployment requires VPC + subnets + ALB + ECS service + IAM execution role + CloudWatch logs + persistent EFS or RDS";',
    `// Snapshot at generation: users=${snapshot.users.total}, db_size_bytes=${snapshot.data.db_size_bytes}`,
    '',
  ].join('\n');
  return [
    { path: 'index.ts', content: idx },
    { path: 'Pulumi.yaml', content: pulumiYaml('aws') },
    { path: 'package.json', content: packageJson('aws') },
  ];
}

function renderAzure(snapshot) {
  const idx = [
    'import * as pulumi from "@pulumi/pulumi";',
    'import * as azure from "@pulumi/azure-native";',
    '',
    'const cfg = new pulumi.Config();',
    'const tier1Key = cfg.requireSecret("tier1EncryptionKey");',
    'const jwtSecret = cfg.requireSecret("jwtSecret");',
    'const imageRef = cfg.get("firealiveImage") ?? "ghcr.io/petermancina/firealive:latest";',
    '',
    'const rg = new azure.resources.ResourceGroup("firealive-rg", { location: "eastus" });',
    '',
    'const kv = new azure.keyvault.Vault("firealive-kv", {',
    '    resourceGroupName: rg.name,',
    '    properties: {',
    '        sku: { family: "A", name: "standard" },',
    '        tenantId: "<your-tenant-id>",',
    '        accessPolicies: [],',
    '    },',
    '});',
    '',
    'export const resourceGroupName = rg.name;',
    'export const note = "Production deployment requires Container Instance or AKS cluster with secrets bound from the Key Vault above";',
    `// Snapshot at generation: users=${snapshot.users.total}, db_size_bytes=${snapshot.data.db_size_bytes}`,
    '',
  ].join('\n');
  return [
    { path: 'index.ts', content: idx },
    { path: 'Pulumi.yaml', content: pulumiYaml('azure') },
    { path: 'package.json', content: packageJson('azure') },
  ];
}

function renderGcp(snapshot) {
  const idx = [
    'import * as pulumi from "@pulumi/pulumi";',
    'import * as gcp from "@pulumi/gcp";',
    '',
    'const cfg = new pulumi.Config();',
    'const tier1Key = cfg.requireSecret("tier1EncryptionKey");',
    'const jwtSecret = cfg.requireSecret("jwtSecret");',
    'const imageRef = cfg.get("firealiveImage") ?? "ghcr.io/petermancina/firealive:latest";',
    '',
    'const tier1Secret = new gcp.secretmanager.Secret("tier1", {',
    '    secretId: "firealive-tier1-key",',
    '    replication: { auto: {} },',
    '});',
    'new gcp.secretmanager.SecretVersion("tier1-v", {',
    '    secret: tier1Secret.id,',
    '    secretData: tier1Key,',
    '});',
    '',
    'const service = new gcp.cloudrunv2.Service("firealive", {',
    '    location: "us-central1",',
    '    template: {',
    '        containers: [{',
    '            image: imageRef,',
    '            ports: [{ containerPort: 3000 }],',
    '        }],',
    '    },',
    '});',
    '',
    'export const url = service.uri;',
    `// Snapshot at generation: users=${snapshot.users.total}, db_size_bytes=${snapshot.data.db_size_bytes}`,
    '',
  ].join('\n');
  return [
    { path: 'index.ts', content: idx },
    { path: 'Pulumi.yaml', content: pulumiYaml('gcp') },
    { path: 'package.json', content: packageJson('gcp') },
  ];
}

function renderHetzner(snapshot) {
  return renderVmShellOut('hetzner', snapshot);
}
function renderOvhcloud(snapshot) {
  return renderVmShellOut('ovhcloud', snapshot);
}
function renderExoscale(snapshot) {
  return renderVmShellOut('exoscale', snapshot);
}

function renderVmShellOut(provider, snapshot) {
  // Hetzner / OVHcloud / Exoscale don't have first-class Pulumi
  // resource providers in the same way the big-three do; the canonical
  // pattern is to use @pulumi/command to drive their respective CLIs
  // or REST APIs from a Pulumi stack.
  const idx = [
    'import * as pulumi from "@pulumi/pulumi";',
    'import * as command from "@pulumi/command";',
    '',
    'const cfg = new pulumi.Config();',
    'const tier1Key = cfg.requireSecret("tier1EncryptionKey");',
    'const jwtSecret = cfg.requireSecret("jwtSecret");',
    'const imageRef = cfg.get("firealiveImage") ?? "ghcr.io/petermancina/firealive:latest";',
    '',
    `// ${provider}-specific provisioning via the provider's CLI or REST API.`,
    '// This stub uses @pulumi/command to shell out; replace with the provider-',
    '// native Pulumi provider when it ships, or with a Terraform-bridge module.',
    `const provisionVm = new command.local.Command("${provider}-provision", {`,
    `    create: "echo 'TODO: invoke ${provider} CLI to provision the VM and bootstrap the Docker container'",`,
    '});',
    '',
    'export const provisionStatus = provisionVm.stdout;',
    `// Snapshot at generation: users=${snapshot.users.total}, db_size_bytes=${snapshot.data.db_size_bytes}`,
    '',
  ].join('\n');
  return [
    { path: 'index.ts', content: idx },
    { path: 'Pulumi.yaml', content: pulumiYaml(provider) },
    { path: 'package.json', content: packageJson(provider) },
  ];
}

module.exports = { render };

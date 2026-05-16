// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Cloud & IaC Bundle Generator (R3k C29)
//
// Consolidated GD-side equivalent of MC's Sub-phase 4 services:
//   server/services/sbom-generator.js          (R3k C9)
//   server/services/cosign-signer.js           (R3k C10)
//   server/services/cloud-iac-signing-keys.js  (R3k C11)
//   server/services/cloud-iac-generator.js     (R3k C13)
//   server/services/cloud-iac-templates/*.js   (R3k C14-C22, 9 files)
//
// All collapsed into ONE module rather than scattered services to
// keep GD-server's monolithic-file convention and to avoid forcing
// MC's services as deployment dependencies on standalone GD
// installs (containerized GD deployments may not ship MC code).
//
// DEPLOYMENT SHAPE
// ================
//
// The MC bundles target deployment of FIREALIVE MC-server (port
// 3000, image ghcr.io/petermancina/firealive). The GD bundles
// target deployment of FIREALIVE GD-server (port 4001, image
// ghcr.io/petermancina/firealive-gd, different env-var
// requirements: GD_JWT_SECRET + GD_ENCRYPTION_KEY rather than
// JWT_SECRET + TIER1_ENCRYPTION_KEY). The GD_DEPLOY_SHAPE constant
// captures the divergence centrally so per-template renderers stay
// shape-agnostic.
//
// PUBLIC API
// ==========
//
//   generatePackage(db, provider, iacTool, options)
//     db                       SQLite handle on the GD database
//     provider                 one of PROVIDER_TOOL_MATRIX keys
//     iacTool                  valid tool for the provider
//     options.userId           required; users.id for generated_by FK
//     options.cloudPackagesDir optional; override storage root
//
//     Returns {id, provider, iac_tool, paths, hashes, signing_key_*,
//              size_bytes, generated_at, install_snapshot}
//     Throws  SyftNotInstalledError / CosignNotInstalledError (which
//             the route handler in C30 maps to 503), invalid
//             combination -> 400, other Error -> 500.
//
//   signingKeys.ensureActiveKey(db)
//   signingKeys.getActiveSigningKey(db)
//   signingKeys.getVerificationKey(db, id)
//   signingKeys.rotateActiveKey(db)
//   signingKeys.listKeys(db)
//
//   PROVIDER_TOOL_MATRIX
//   SECRETS_MAPPING_BY_PROVIDER
//   SyftNotInstalledError, CosignNotInstalledError
//
// FAILURE SEMANTICS
// =================
//
// Partial bundle dirs are cleaned in finally on any pipeline failure.
// cloud_packages row is INSERTed only after all artifacts written;
// either-completes-or-throws shape matches MC's generator.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');
const { encryptConfig, decryptConfig } = require('./gd-encryption');

// ── Constants ──────────────────────────────────────────────────────────

const PROVIDER_TOOL_MATRIX = {
  aws:      ['terraform', 'pulumi', 'cloudformation', 'docker-compose', 'docker-manifest', 'kubernetes', 'helm'],
  azure:    ['terraform', 'pulumi', 'bicep',          'docker-compose', 'docker-manifest', 'kubernetes', 'helm'],
  gcp:      ['terraform', 'pulumi', 'gcp-dm',         'docker-compose', 'docker-manifest', 'kubernetes', 'helm'],
  hetzner:  ['terraform', 'pulumi',                   'docker-compose', 'docker-manifest', 'kubernetes', 'helm'],
  ovhcloud: ['terraform', 'pulumi',                   'docker-compose', 'docker-manifest', 'kubernetes', 'helm'],
  exoscale: ['terraform', 'pulumi',                   'docker-compose', 'docker-manifest', 'kubernetes', 'helm'],
};

const SECRETS_MAPPING_BY_PROVIDER = {
  aws:      'AWS Secrets Manager (recommended) or Systems Manager Parameter Store. The generated IaC references secrets by ARN.',
  azure:    'Azure Key Vault. The generated IaC references secrets by Key Vault secret URI.',
  gcp:      'Google Secret Manager. The generated IaC references secrets by resource name.',
  hetzner:  'Hetzner has no managed secrets store; the generated IaC references secrets via env vars from .env or a Vault instance.',
  ovhcloud: 'OVHcloud Vault (Hashi-compatible) or environment variables. The generated IaC references secrets via Vault paths.',
  exoscale: 'Exoscale has no managed secrets store; the generated IaC references secrets via env vars from .env or a Vault instance.',
};

const GD_DEPLOY_SHAPE = {
  image: 'ghcr.io/petermancina/firealive-gd:latest',
  port: 4001,
  envVars: ['GD_JWT_SECRET', 'GD_ENCRYPTION_KEY'],
  dataDir: '/data',
  serviceName: 'firealive-gd',
  description: 'FireAlive Global Dashboard regional aggregator',
};

const DEFAULT_SYFT_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_COSIGN_TIMEOUT_MS = 2 * 60 * 1000;

// ── Error classes ──────────────────────────────────────────────────────

class SyftNotInstalledError extends Error {
  constructor(message) {
    super(message || 'Syft is not installed on this host. Install via https://github.com/anchore/syft and ensure it is on PATH.');
    this.name = 'SyftNotInstalledError';
    this.code = 'SYFT_NOT_INSTALLED';
  }
}

class CosignNotInstalledError extends Error {
  constructor(message) {
    super(message || 'Cosign is not installed on this host. Install via https://github.com/sigstore/cosign and ensure it is on PATH.');
    this.name = 'CosignNotInstalledError';
    this.code = 'COSIGN_NOT_INSTALLED';
  }
}

// ── Generic helpers ────────────────────────────────────────────────────

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function sha256OfFile(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function validateAbsolutePath(label, p) {
  if (typeof p !== 'string' || p.length === 0) throw new Error(`${label}: must be a non-empty string`);
  if (p.indexOf('\0') !== -1) throw new Error(`${label}: must not contain null bytes`);
  if (!path.isAbsolute(p)) throw new Error(`${label}: must be an absolute path`);
}

function which(binary) {
  const result = spawnSync('which', [binary], { encoding: 'utf8' });
  if (result.status !== 0) return false;
  return ((result.stdout || '').trim()).length > 0;
}

// ── SBOM (Syft shell-out) ──────────────────────────────────────────────

function generateSbom(installPath, outputPath, options = {}) {
  validateAbsolutePath('installPath', installPath);
  validateAbsolutePath('outputPath', outputPath);
  if (!which('syft')) throw new SyftNotInstalledError();
  ensureDir(path.dirname(outputPath));
  const timeoutMs = options.timeoutMs || DEFAULT_SYFT_TIMEOUT_MS;
  try {
    execFileSync(
      'syft',
      [installPath, '-o', `spdx-json=${outputPath}`],
      { timeout: timeoutMs, stdio: ['ignore', 'ignore', 'pipe'] },
    );
  } catch (err) {
    const stderr = err.stderr ? err.stderr.toString('utf8').trim() : '';
    throw new Error(`syft failed: ${err.message}${stderr ? ` (stderr: ${stderr.slice(0, 500)})` : ''}`);
  }
  if (!fs.existsSync(outputPath)) throw new Error(`syft completed but no output at ${outputPath}`);
  const stat = fs.statSync(outputPath);
  if (stat.size === 0) throw new Error(`syft produced empty output at ${outputPath}`);
  const bytes = fs.readFileSync(outputPath);
  let parsed;
  try { parsed = JSON.parse(bytes.toString('utf8')); }
  catch (e) { throw new Error(`syft output not valid JSON: ${e.message}`); }
  if (!parsed.spdxVersion && !parsed.SPDXVersion) {
    throw new Error('syft output missing SPDX version marker');
  }
  return {
    path: outputPath,
    sizeBytes: stat.size,
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
  };
}

// ── Cosign sign-blob shell-out ─────────────────────────────────────────

function signBlob(blobPath, privateKeyPem, outputSignaturePath, options = {}) {
  validateAbsolutePath('blobPath', blobPath);
  validateAbsolutePath('outputSignaturePath', outputSignaturePath);
  if (typeof privateKeyPem !== 'string' || !/-----BEGIN [A-Z ]+PRIVATE KEY-----/.test(privateKeyPem)) {
    throw new Error('signBlob: privateKeyPem does not appear to be a PEM-encoded private key');
  }
  if (!fs.existsSync(blobPath)) throw new Error(`signBlob: blobPath does not exist: ${blobPath}`);
  if (!which('cosign')) throw new CosignNotInstalledError();
  ensureDir(path.dirname(outputSignaturePath));

  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'firealive-gd-cosign-' + crypto.randomBytes(8).toString('hex') + '-'),
  );
  const keyTmpPath = path.join(tmpDir, 'signing-key.pem');
  try {
    fs.writeFileSync(keyTmpPath, privateKeyPem, { mode: 0o600 });
    const timeoutMs = options.timeoutMs || DEFAULT_COSIGN_TIMEOUT_MS;
    try {
      execFileSync(
        'cosign',
        ['sign-blob', '--key', keyTmpPath, '--output-signature', outputSignaturePath, '--yes', blobPath],
        {
          timeout: timeoutMs,
          stdio: ['ignore', 'ignore', 'pipe'],
          env: { ...process.env, COSIGN_PASSWORD: '', COSIGN_YES: 'true' },
        },
      );
    } catch (err) {
      const stderr = err.stderr ? err.stderr.toString('utf8').trim() : '';
      throw new Error(`cosign sign-blob failed: ${err.message}${stderr ? ` (stderr: ${stderr.slice(0, 500)})` : ''}`);
    }
    if (!fs.existsSync(outputSignaturePath)) {
      throw new Error(`cosign produced no signature at ${outputSignaturePath}`);
    }
    const stat = fs.statSync(outputSignaturePath);
    if (stat.size === 0) throw new Error(`cosign produced empty signature at ${outputSignaturePath}`);
    return {
      path: outputSignaturePath,
      sizeBytes: stat.size,
      sha256: sha256OfFile(outputSignaturePath),
    };
  } finally {
    try { if (fs.existsSync(keyTmpPath)) fs.unlinkSync(keyTmpPath); } catch { /* swallow */ }
    try { if (fs.existsSync(tmpDir)) fs.rmdirSync(tmpDir); } catch { /* swallow */ }
  }
}

// ── Signing-keys lifecycle ─────────────────────────────────────────────

function fingerprintPublicKey(pem) {
  const obj = crypto.createPublicKey(pem);
  const der = obj.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

function _insertActiveKey(db) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const wrapped = encryptConfig({ pem: privateKey });
  const result = db
    .prepare(
      `INSERT INTO cloud_iac_signing_keys
         (public_key, private_key_wrapped, algorithm, status)
       VALUES (?, ?, 'cosign-ecdsa-p256', 'active')`,
    )
    .run(publicKey, wrapped);
  return db
    .prepare('SELECT * FROM cloud_iac_signing_keys WHERE rowid = ?')
    .get(result.lastInsertRowid);
}

const signingKeys = {
  ensureActiveKey(db) {
    const existing = db
      .prepare("SELECT id FROM cloud_iac_signing_keys WHERE status = 'active' LIMIT 1")
      .get();
    if (existing) return { id: existing.id, created: false };
    const row = _insertActiveKey(db);
    return { id: row.id, created: true };
  },

  getActiveSigningKey(db) {
    const row = db
      .prepare(
        `SELECT id, public_key, private_key_wrapped, algorithm, created_at
           FROM cloud_iac_signing_keys
           WHERE status = 'active' LIMIT 1`,
      )
      .get();
    if (!row) throw new Error('no active cloud_iac_signing_keys row; call ensureActiveKey first');
    const { pem: privateKeyPem } = decryptConfig(row.private_key_wrapped);
    return {
      id: row.id,
      publicKeyPem: row.public_key,
      privateKeyPem,
      algorithm: row.algorithm,
      publicKeyFingerprint: fingerprintPublicKey(row.public_key),
      createdAt: row.created_at,
    };
  },

  getVerificationKey(db, id) {
    const row = db
      .prepare(
        `SELECT id, public_key, algorithm, status, created_at, rotated_at
           FROM cloud_iac_signing_keys WHERE id = ?`,
      )
      .get(id);
    if (!row) return null;
    return {
      id: row.id,
      publicKeyPem: row.public_key,
      algorithm: row.algorithm,
      status: row.status,
      publicKeyFingerprint: fingerprintPublicKey(row.public_key),
      createdAt: row.created_at,
      rotatedAt: row.rotated_at,
    };
  },

  rotateActiveKey(db) {
    const tx = db.transaction(() => {
      const prior = db.prepare("SELECT id FROM cloud_iac_signing_keys WHERE status = 'active' LIMIT 1").get();
      if (prior) {
        db.prepare("UPDATE cloud_iac_signing_keys SET status='rotated', rotated_at=datetime('now') WHERE id=?").run(prior.id);
      }
      const next = _insertActiveKey(db);
      return { oldId: prior ? prior.id : null, newId: next.id };
    });
    return tx();
  },

  revokeKey(db, id) {
    const tx = db.transaction(() => {
      const row = db.prepare("SELECT status FROM cloud_iac_signing_keys WHERE id = ?").get(id);
      if (!row) throw new Error(`cloud_iac_signing_keys row not found: ${id}`);
      if (row.status === 'revoked') return { id, prior_status: 'revoked' };
      db.prepare("UPDATE cloud_iac_signing_keys SET status='revoked', rotated_at=COALESCE(rotated_at, datetime('now')) WHERE id=?").run(id);
      return { id, prior_status: row.status };
    });
    return tx();
  },

  listKeys(db) {
    const rows = db
      .prepare(
        `SELECT id, public_key, algorithm, status, created_at, rotated_at
           FROM cloud_iac_signing_keys ORDER BY created_at DESC`,
      )
      .all();
    return rows.map(r => ({
      id: r.id,
      publicKeyPem: r.public_key,
      publicKeyFingerprint: fingerprintPublicKey(r.public_key),
      algorithm: r.algorithm,
      status: r.status,
      createdAt: r.created_at,
      rotatedAt: r.rotated_at,
    }));
  },
};

// ── Install snapshot (GD-shape) ────────────────────────────────────────

function captureInstallSnapshot(db) {
  const safe = (fn, fb) => { try { return fn(); } catch (e) { return fb; } };
  const users = safe(() => {
    const total = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
    const byRole = {};
    const rows = db.prepare("SELECT role, COUNT(*) AS n FROM users GROUP BY role").all();
    for (const r of rows) byRole[r.role || 'unknown'] = r.n;
    return { total, by_role: byRole };
  }, { total: 0, by_role: {} });

  const mcs = safe(() => {
    const total = db.prepare('SELECT COUNT(*) AS n FROM management_consoles').get().n;
    const active = db.prepare("SELECT COUNT(*) AS n FROM management_consoles WHERE status='active'").get().n;
    return { total, active };
  }, { total: 0, active: 0 });

  const keys = safe(() => {
    const total = db.prepare('SELECT COUNT(*) AS n FROM signing_keys').get().n;
    const active = db.prepare("SELECT COUNT(*) AS n FROM signing_keys WHERE status='active'").get().n;
    return { total, active };
  }, { total: 0, active: 0 });

  let dbSizeBytes = 0;
  try {
    const dbPath = db.name || (db.pragma && db.pragma('database_list', { simple: false })?.[0]?.file);
    if (dbPath && fs.existsSync(dbPath)) dbSizeBytes = fs.statSync(dbPath).size;
  } catch (e) { /* keep 0 */ }

  let versionInfo = { version: 'unknown', fuse_counter: null, build_id: null };
  try {
    const pkg = require('../package.json');
    versionInfo = {
      version: pkg.version || 'unknown',
      fuse_counter: typeof pkg.fuseCounter === 'number' ? pkg.fuseCounter : null,
      build_id: pkg.buildId || null,
    };
  } catch (e) { /* keep defaults */ }

  return {
    captured_at: new Date().toISOString(),
    side: 'gd',
    users,
    management_consoles: mcs,
    signing_keys: keys,
    data: { db_size_bytes: dbSizeBytes },
    version: versionInfo,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEMPLATES — 9 IaC formats × 6 providers (39 valid combinations)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Each renderer takes (snapshot, provider) and returns
// {files: [{path, content}, ...]} relative to iac/ subdir.

// ─── shared template helpers ───────────────────────────────────────────

function commonEnvVarLines() {
  // Returns env-var array (one per line) referencing the GD shape
  return GD_DEPLOY_SHAPE.envVars.map(v => `${v}=\${${v}}`);
}

// ─── terraform ─────────────────────────────────────────────────────────

function renderTerraformVariablesTf() {
  return [
    'variable "gd_encryption_key" {',
    '  description = "32-byte hex KEK for GD-side Tier-1 wrap (GD_ENCRYPTION_KEY)"',
    '  type        = string',
    '  sensitive   = true',
    '}',
    '',
    'variable "gd_jwt_secret" {',
    '  description = "JWT signing secret for the GD-server (GD_JWT_SECRET)"',
    '  type        = string',
    '  sensitive   = true',
    '}',
    '',
    'variable "gd_image" {',
    '  description = "Docker image reference for the GD-server"',
    '  type        = string',
    `  default     = "${GD_DEPLOY_SHAPE.image}"`,
    '}',
    '',
    'variable "instance_size" {',
    '  description = "Provider-specific compute size identifier"',
    '  type        = string',
    '}',
    '',
  ].join('\n');
}

function renderTerraformOutputsTf() {
  return [
    'output "gd_endpoint" {',
    '  description = "Public endpoint URL for the GD-server"',
    '  value       = local.gd_endpoint',
    '}',
    '',
  ].join('\n');
}

function renderTerraform(snapshot, provider) {
  const port = GD_DEPLOY_SHAPE.port;
  let main;
  if (provider === 'aws') {
    main = [
      'terraform {',
      '  required_providers {',
      '    aws = {',
      '      source  = "hashicorp/aws"',
      '      version = "~> 5.0"',
      '    }',
      '  }',
      '}',
      '',
      'provider "aws" { region = "us-east-1" }',
      '',
      'resource "aws_secretsmanager_secret" "gd_kek" { name = "firealive-gd/encryption-key" }',
      'resource "aws_secretsmanager_secret_version" "gd_kek_v" {',
      '  secret_id     = aws_secretsmanager_secret.gd_kek.id',
      '  secret_string = var.gd_encryption_key',
      '}',
      '',
      'resource "aws_secretsmanager_secret" "gd_jwt" { name = "firealive-gd/jwt-secret" }',
      'resource "aws_secretsmanager_secret_version" "gd_jwt_v" {',
      '  secret_id     = aws_secretsmanager_secret.gd_jwt.id',
      '  secret_string = var.gd_jwt_secret',
      '}',
      '',
      'resource "aws_ecs_cluster" "gd" { name = "firealive-gd" }',
      '',
      'resource "aws_ecs_task_definition" "gd" {',
      '  family                   = "firealive-gd"',
      '  network_mode             = "awsvpc"',
      '  requires_compatibilities = ["FARGATE"]',
      '  cpu                      = "1024"',
      '  memory                   = "2048"',
      '  container_definitions    = jsonencode([{',
      '    name      = "firealive-gd"',
      '    image     = var.gd_image',
      `    portMappings = [{ containerPort = ${port}, hostPort = ${port} }]`,
      '    secrets = [',
      '      { name = "GD_ENCRYPTION_KEY", valueFrom = aws_secretsmanager_secret.gd_kek.arn },',
      '      { name = "GD_JWT_SECRET",     valueFrom = aws_secretsmanager_secret.gd_jwt.arn }',
      '    ]',
      '  }])',
      '}',
      '',
      'locals { gd_endpoint = "https://<your-alb-dns>:' + port + '" }',
      '',
      `# Snapshot: users=${snapshot.users.total} MCs=${snapshot.management_consoles.total} active=${snapshot.management_consoles.active}`,
      '',
    ].join('\n');
  } else if (provider === 'azure') {
    main = [
      'terraform {',
      '  required_providers {',
      '    azurerm = { source = "hashicorp/azurerm", version = "~> 3.0" }',
      '  }',
      '}',
      'provider "azurerm" { features {} }',
      '',
      'resource "azurerm_resource_group" "gd" { name = "firealive-gd-rg", location = "eastus" }',
      'data "azurerm_client_config" "current" {}',
      '',
      'resource "azurerm_key_vault" "gd" {',
      '  name                = "firealive-gd-kv"',
      '  resource_group_name = azurerm_resource_group.gd.name',
      '  location            = azurerm_resource_group.gd.location',
      '  tenant_id           = data.azurerm_client_config.current.tenant_id',
      '  sku_name            = "standard"',
      '}',
      '',
      'resource "azurerm_key_vault_secret" "gd_kek" {',
      '  name         = "gd-encryption-key"',
      '  value        = var.gd_encryption_key',
      '  key_vault_id = azurerm_key_vault.gd.id',
      '}',
      'resource "azurerm_key_vault_secret" "gd_jwt" {',
      '  name         = "gd-jwt-secret"',
      '  value        = var.gd_jwt_secret',
      '  key_vault_id = azurerm_key_vault.gd.id',
      '}',
      '',
      'resource "azurerm_container_group" "gd" {',
      '  name                = "firealive-gd"',
      '  location            = azurerm_resource_group.gd.location',
      '  resource_group_name = azurerm_resource_group.gd.name',
      '  os_type             = "Linux"',
      '  ip_address_type     = "Public"',
      '  dns_name_label      = "firealive-gd-${random_id.suffix.hex}"',
      '  container {',
      '    name   = "firealive-gd"',
      '    image  = var.gd_image',
      '    cpu    = "1.0"',
      '    memory = "2.0"',
      `    ports { port = ${port} protocol = "TCP" }`,
      '    secure_environment_variables = {',
      '      GD_ENCRYPTION_KEY = var.gd_encryption_key',
      '      GD_JWT_SECRET     = var.gd_jwt_secret',
      '    }',
      '  }',
      '}',
      '',
      'resource "random_id" "suffix" { byte_length = 4 }',
      `locals { gd_endpoint = "https://\${azurerm_container_group.gd.fqdn}:${port}" }`,
      '',
      `# Snapshot: users=${snapshot.users.total} MCs=${snapshot.management_consoles.total}`,
      '',
    ].join('\n');
  } else if (provider === 'gcp') {
    main = [
      'terraform {',
      '  required_providers { google = { source = "hashicorp/google", version = "~> 5.0" } }',
      '}',
      'provider "google" { project = "your-gcp-project", region = "us-central1" }',
      '',
      'resource "google_secret_manager_secret" "gd_kek" { secret_id = "firealive-gd-kek", replication { auto {} } }',
      'resource "google_secret_manager_secret_version" "gd_kek_v" { secret = google_secret_manager_secret.gd_kek.id, secret_data = var.gd_encryption_key }',
      '',
      'resource "google_secret_manager_secret" "gd_jwt" { secret_id = "firealive-gd-jwt", replication { auto {} } }',
      'resource "google_secret_manager_secret_version" "gd_jwt_v" { secret = google_secret_manager_secret.gd_jwt.id, secret_data = var.gd_jwt_secret }',
      '',
      'resource "google_cloud_run_v2_service" "gd" {',
      '  name     = "firealive-gd"',
      '  location = "us-central1"',
      '  template {',
      '    containers {',
      '      image = var.gd_image',
      `      ports { container_port = ${port} }`,
      '      env { name = "GD_ENCRYPTION_KEY", value_source { secret_key_ref { secret = google_secret_manager_secret.gd_kek.secret_id, version = "latest" } } }',
      '      env { name = "GD_JWT_SECRET",     value_source { secret_key_ref { secret = google_secret_manager_secret.gd_jwt.secret_id, version = "latest" } } }',
      '    }',
      '  }',
      '}',
      '',
      'locals { gd_endpoint = google_cloud_run_v2_service.gd.uri }',
      `# Snapshot: users=${snapshot.users.total} MCs=${snapshot.management_consoles.total}`,
      '',
    ].join('\n');
  } else {
    // hetzner / ovhcloud / exoscale share the cloud-init Docker pattern
    const providerBlocks = {
      hetzner: [
        'terraform {',
        '  required_providers { hcloud = { source = "hetznercloud/hcloud", version = "~> 1.45" } }',
        '}',
        'provider "hcloud" { }',
        '',
        'resource "hcloud_server" "gd" {',
        '  name        = "firealive-gd"',
        '  image       = "docker-ce"',
        '  server_type = var.instance_size',
        '  location    = "fsn1"',
      ].join('\n'),
      ovhcloud: [
        'terraform {',
        '  required_providers { ovh = { source = "ovh/ovh", version = "~> 0.40" } }',
        '}',
        'provider "ovh" { endpoint = "ovh-eu" }',
        '',
        'resource "ovh_cloud_project_instance" "gd" {',
        '  service_name = "your-ovh-project-id"',
        '  region       = "GRA9"',
        '  name         = "firealive-gd"',
        '  flavor_name  = var.instance_size',
        '  image_name   = "Docker"',
      ].join('\n'),
      exoscale: [
        'terraform {',
        '  required_providers { exoscale = { source = "exoscale/exoscale", version = "~> 0.55" } }',
        '}',
        'provider "exoscale" { }',
        '',
        'data "exoscale_template" "docker" { zone = "ch-gva-2", name = "Linux Ubuntu 22.04 LTS 64-bit", filter = "featured" }',
        '',
        'resource "exoscale_compute_instance" "gd" {',
        '  zone        = "ch-gva-2"',
        '  name        = "firealive-gd"',
        '  template_id = data.exoscale_template.docker.id',
        '  type        = var.instance_size',
        '  disk_size   = 50',
      ].join('\n'),
    };
    main = [
      providerBlocks[provider],
      '  user_data = <<-EOT',
      '    #cloud-config',
      '    write_files:',
      '      - path: /etc/firealive-gd/.env',
      '        permissions: "0600"',
      '        content: |',
      '          GD_ENCRYPTION_KEY=${var.gd_encryption_key}',
      '          GD_JWT_SECRET=${var.gd_jwt_secret}',
      '    runcmd:',
      `      - docker run -d --name firealive-gd --restart=always -p ${port}:${port} --env-file /etc/firealive-gd/.env -v firealive-gd-data:${GD_DEPLOY_SHAPE.dataDir} \${var.gd_image}`,
      '  EOT',
      '}',
      '',
      `locals { gd_endpoint = "https://\${${provider === 'hetzner' ? 'hcloud_server.gd.ipv4_address' : provider === 'ovhcloud' ? 'ovh_cloud_project_instance.gd.address' : 'exoscale_compute_instance.gd.public_ip_address'}}:${port}" }`,
      '',
      `# Snapshot: users=${snapshot.users.total} MCs=${snapshot.management_consoles.total}`,
      '',
    ].join('\n');
  }
  return [
    { path: 'main.tf', content: main },
    { path: 'variables.tf', content: renderTerraformVariablesTf() },
    { path: 'outputs.tf', content: renderTerraformOutputsTf() },
  ];
}

// ─── pulumi ────────────────────────────────────────────────────────────

function renderPulumi(snapshot, provider) {
  const port = GD_DEPLOY_SHAPE.port;
  const pulumiYaml = [
    'name: firealive-gd',
    'runtime: nodejs',
    'description: FireAlive GD-server deployment',
    `# Provider: ${provider}`,
    '',
  ].join('\n');

  const depsByProvider = {
    aws: '"@pulumi/aws": "^6.0.0"',
    azure: '"@pulumi/azure-native": "^2.0.0"',
    gcp: '"@pulumi/gcp": "^7.0.0"',
    hetzner: '"@pulumi/command": "^0.9.0"',
    ovhcloud: '"@pulumi/command": "^0.9.0"',
    exoscale: '"@pulumi/command": "^0.9.0"',
  };

  const packageJson = [
    '{',
    '  "name": "firealive-gd-pulumi",',
    '  "main": "index.ts",',
    '  "dependencies": {',
    '    "@pulumi/pulumi": "^3.100.0",',
    `    ${depsByProvider[provider]}`,
    '  },',
    '  "devDependencies": { "@types/node": "^20.0.0", "typescript": "^5.0.0" }',
    '}',
    '',
  ].join('\n');

  let idx;
  if (provider === 'aws') {
    idx = [
      'import * as pulumi from "@pulumi/pulumi";',
      'import * as aws from "@pulumi/aws";',
      'const cfg = new pulumi.Config();',
      'const gdKek = cfg.requireSecret("gdEncryptionKey");',
      'const gdJwt = cfg.requireSecret("gdJwtSecret");',
      `const image = cfg.get("gdImage") ?? "${GD_DEPLOY_SHAPE.image}";`,
      'const kek = new aws.secretsmanager.Secret("gd-kek", { name: "firealive-gd/encryption-key" });',
      'new aws.secretsmanager.SecretVersion("gd-kek-v", { secretId: kek.id, secretString: gdKek });',
      'const jwt = new aws.secretsmanager.Secret("gd-jwt", { name: "firealive-gd/jwt-secret" });',
      'new aws.secretsmanager.SecretVersion("gd-jwt-v", { secretId: jwt.id, secretString: gdJwt });',
      'const cluster = new aws.ecs.Cluster("gd", { name: "firealive-gd" });',
      'export const clusterArn = cluster.arn;',
      `// Snapshot: MCs=${snapshot.management_consoles.total}, users=${snapshot.users.total}`,
      '',
    ].join('\n');
  } else if (provider === 'azure') {
    idx = [
      'import * as pulumi from "@pulumi/pulumi";',
      'import * as azure from "@pulumi/azure-native";',
      'const cfg = new pulumi.Config();',
      'const rg = new azure.resources.ResourceGroup("firealive-gd-rg", { location: "eastus" });',
      'export const resourceGroupName = rg.name;',
      `// Snapshot: MCs=${snapshot.management_consoles.total}`,
      '',
    ].join('\n');
  } else if (provider === 'gcp') {
    idx = [
      'import * as pulumi from "@pulumi/pulumi";',
      'import * as gcp from "@pulumi/gcp";',
      'const cfg = new pulumi.Config();',
      `const image = cfg.get("gdImage") ?? "${GD_DEPLOY_SHAPE.image}";`,
      'const service = new gcp.cloudrunv2.Service("firealive-gd", {',
      '  location: "us-central1",',
      '  template: {',
      `    containers: [{ image, ports: [{ containerPort: ${port} }] }],`,
      '  },',
      '});',
      'export const url = service.uri;',
      `// Snapshot: MCs=${snapshot.management_consoles.total}`,
      '',
    ].join('\n');
  } else {
    idx = [
      'import * as pulumi from "@pulumi/pulumi";',
      'import * as command from "@pulumi/command";',
      `// ${provider}-specific provisioning via the provider CLI`,
      `const provision = new command.local.Command("${provider}-provision", {`,
      `  create: "echo 'TODO: invoke ${provider} CLI to provision GD-server VM'",`,
      '});',
      'export const status = provision.stdout;',
      `// Snapshot: MCs=${snapshot.management_consoles.total}`,
      '',
    ].join('\n');
  }

  return [
    { path: 'index.ts', content: idx },
    { path: 'Pulumi.yaml', content: pulumiYaml },
    { path: 'package.json', content: packageJson },
  ];
}

// ─── cloudformation (AWS only) ─────────────────────────────────────────

function renderCloudformation(snapshot, provider) {
  if (provider !== 'aws') throw new Error(`cloudformation: AWS-only, got '${provider}'`);
  const port = GD_DEPLOY_SHAPE.port;
  const yaml = [
    'AWSTemplateFormatVersion: "2010-09-09"',
    'Description: FireAlive GD-server deployment (ECS Fargate + Secrets Manager)',
    '',
    'Parameters:',
    '  GdEncryptionKey: { Type: String, NoEcho: true }',
    '  GdJwtSecret:     { Type: String, NoEcho: true }',
    `  GdImage:         { Type: String, Default: ${GD_DEPLOY_SHAPE.image} }`,
    '',
    'Resources:',
    '  GdKekSecret:',
    '    Type: AWS::SecretsManager::Secret',
    '    Properties: { Name: firealive-gd/encryption-key, SecretString: !Ref GdEncryptionKey }',
    '',
    '  GdJwtSecretRes:',
    '    Type: AWS::SecretsManager::Secret',
    '    Properties: { Name: firealive-gd/jwt-secret, SecretString: !Ref GdJwtSecret }',
    '',
    '  Cluster:',
    '    Type: AWS::ECS::Cluster',
    '    Properties: { ClusterName: firealive-gd }',
    '',
    '  TaskExecRole:',
    '    Type: AWS::IAM::Role',
    '    Properties:',
    '      AssumeRolePolicyDocument:',
    '        Version: "2012-10-17"',
    '        Statement:',
    '          - { Effect: Allow, Principal: { Service: ecs-tasks.amazonaws.com }, Action: sts:AssumeRole }',
    '      ManagedPolicyArns:',
    '        - arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy',
    '        - arn:aws:iam::aws:policy/SecretsManagerReadWrite',
    '',
    '  TaskDef:',
    '    Type: AWS::ECS::TaskDefinition',
    '    Properties:',
    '      Family: firealive-gd',
    '      NetworkMode: awsvpc',
    '      RequiresCompatibilities: [FARGATE]',
    '      Cpu: "1024"',
    '      Memory: "2048"',
    '      ExecutionRoleArn: !GetAtt TaskExecRole.Arn',
    '      ContainerDefinitions:',
    '        - Name: firealive-gd',
    '          Image: !Ref GdImage',
    '          PortMappings:',
    `            - { ContainerPort: ${port}, HostPort: ${port} }`,
    '          Secrets:',
    '            - { Name: GD_ENCRYPTION_KEY, ValueFrom: !Ref GdKekSecret }',
    '            - { Name: GD_JWT_SECRET,     ValueFrom: !Ref GdJwtSecretRes }',
    '',
    'Outputs:',
    '  ClusterArn:',
    '    Value: !GetAtt Cluster.Arn',
    '',
    `# Snapshot: MCs=${snapshot.management_consoles.total}`,
    '',
  ].join('\n');
  return [{ path: 'firealive-gd.yaml', content: yaml }];
}

// ─── docker-compose (universal) ────────────────────────────────────────

function renderDockerCompose(snapshot, provider) {
  const port = GD_DEPLOY_SHAPE.port;
  const yaml = [
    `# FireAlive GD-server (provider: ${provider})`,
    `# Snapshot: MCs=${snapshot.management_consoles.total}, users=${snapshot.users.total}, version=${snapshot.version.version}`,
    '',
    'version: "3.9"',
    'services:',
    '  firealive-gd:',
    `    image: ${GD_DEPLOY_SHAPE.image}`,
    '    restart: unless-stopped',
    `    ports: ["${port}:${port}"]`,
    '    environment:',
    '      - GD_ENCRYPTION_KEY=${GD_ENCRYPTION_KEY}',
    '      - GD_JWT_SECRET=${GD_JWT_SECRET}',
    `      - BACKUP_DIR=${GD_DEPLOY_SHAPE.dataDir}/backups`,
    '    volumes:',
    `      - firealive-gd-data:${GD_DEPLOY_SHAPE.dataDir}`,
    '    healthcheck:',
    `      test: ["CMD", "curl", "-fsS", "http://localhost:${port}/api/health"]`,
    '      interval: 30s',
    '      timeout: 5s',
    '      retries: 3',
    '',
    'volumes:',
    '  firealive-gd-data:',
    '    driver: local',
    '',
  ].join('\n');
  const envExample = [
    '# .env template for FireAlive GD-server',
    `# Generated: ${snapshot.captured_at}`,
    'GD_ENCRYPTION_KEY=replace-with-32-byte-hex-kek',
    'GD_JWT_SECRET=replace-with-16+-random-chars',
    '',
  ].join('\n');
  return [
    { path: 'docker-compose.yml', content: yaml },
    { path: '.env.example', content: envExample },
  ];
}

// ─── docker-manifest (universal) ───────────────────────────────────────

function renderDockerManifest(snapshot, provider) {
  const manifest = {
    format: 'firealive-gd-docker-image-manifest-v1',
    generated_at: snapshot.captured_at,
    provider,
    source_version: snapshot.version,
    images: [{
      name: 'firealive-gd-server',
      reference: GD_DEPLOY_SHAPE.image,
      digest_sha256: 'sha256:UNKNOWN_PIN_AT_DEPLOY_TIME',
      notes: 'Pin to a specific tag (e.g. v1.0.37) and capture the digest with `docker image inspect`.',
    }],
    notes: [`Snapshot: MCs=${snapshot.management_consoles.total}, users=${snapshot.users.total}`],
  };
  return [{ path: 'image-manifest.json', content: JSON.stringify(manifest, null, 2) }];
}

// ─── kubernetes (universal) ────────────────────────────────────────────

function renderKubernetes(snapshot, provider) {
  const port = GD_DEPLOY_SHAPE.port;
  const deployment = [
    'apiVersion: apps/v1',
    'kind: Deployment',
    'metadata:',
    '  name: firealive-gd',
    `  labels: { app: firealive-gd, firealive.io/provider: ${provider} }`,
    'spec:',
    '  replicas: 1',
    '  selector: { matchLabels: { app: firealive-gd } }',
    '  template:',
    '    metadata: { labels: { app: firealive-gd } }',
    '    spec:',
    '      containers:',
    '        - name: firealive-gd',
    `          image: ${GD_DEPLOY_SHAPE.image}`,
    `          ports: [{ containerPort: ${port}, name: http }]`,
    '          env:',
    '            - { name: GD_ENCRYPTION_KEY, valueFrom: { secretKeyRef: { name: firealive-gd-secrets, key: gd_encryption_key } } }',
    '            - { name: GD_JWT_SECRET,     valueFrom: { secretKeyRef: { name: firealive-gd-secrets, key: gd_jwt_secret } } }',
    '          volumeMounts: [{ name: data, mountPath: ' + GD_DEPLOY_SHAPE.dataDir + ' }]',
    `          readinessProbe: { httpGet: { path: /api/health, port: ${port} }, initialDelaySeconds: 10, periodSeconds: 30 }`,
    `          livenessProbe:  { httpGet: { path: /api/health, port: ${port} }, initialDelaySeconds: 30, periodSeconds: 60 }`,
    '          resources:',
    '            requests: { cpu: "500m", memory: "1Gi" }',
    '            limits:   { cpu: "2000m", memory: "4Gi" }',
    '      volumes:',
    '        - { name: data, persistentVolumeClaim: { claimName: firealive-gd-data } }',
    `# Snapshot: MCs=${snapshot.management_consoles.total}`,
    '',
  ].join('\n');
  const service = [
    'apiVersion: v1',
    'kind: Service',
    'metadata: { name: firealive-gd, labels: { app: firealive-gd } }',
    'spec:',
    '  type: ClusterIP',
    '  selector: { app: firealive-gd }',
    `  ports: [{ name: http, port: 80, targetPort: ${port} }]`,
    '',
  ].join('\n');
  const pvc = [
    'apiVersion: v1',
    'kind: PersistentVolumeClaim',
    'metadata: { name: firealive-gd-data }',
    'spec:',
    '  accessModes: ["ReadWriteOnce"]',
    '  resources: { requests: { storage: 50Gi } }',
    '',
  ].join('\n');
  const secretExample = [
    '# kubectl create secret generic firealive-gd-secrets \\',
    '#   --from-literal=gd_encryption_key=<32-byte-hex> \\',
    '#   --from-literal=gd_jwt_secret=<random-16+-chars>',
    'apiVersion: v1',
    'kind: Secret',
    'metadata: { name: firealive-gd-secrets }',
    'type: Opaque',
    'stringData:',
    '  gd_encryption_key: REPLACE_WITH_32_BYTE_HEX',
    '  gd_jwt_secret: REPLACE_WITH_16+_RANDOM_CHARS',
    '',
  ].join('\n');
  return [
    { path: 'firealive-gd-deployment.yaml', content: deployment },
    { path: 'firealive-gd-service.yaml', content: service },
    { path: 'firealive-gd-pvc.yaml', content: pvc },
    { path: 'firealive-gd-secret.example.yaml', content: secretExample },
  ];
}

// ─── helm (universal) ──────────────────────────────────────────────────

function renderHelm(snapshot, provider) {
  const port = GD_DEPLOY_SHAPE.port;
  const chart = [
    'apiVersion: v2',
    'name: firealive-gd',
    'description: FireAlive Global Dashboard',
    'type: application',
    `version: ${snapshot.version.version === 'unknown' ? '0.1.0' : snapshot.version.version}`,
    `appVersion: "${snapshot.version.version}"`,
    `# Provider: ${provider}`,
    '',
  ].join('\n');
  const values = [
    'image:',
    `  repository: ${GD_DEPLOY_SHAPE.image.split(':')[0]}`,
    '  tag: latest',
    '  pullPolicy: IfNotPresent',
    'replicaCount: 1',
    'service:',
    '  type: ClusterIP',
    '  port: 80',
    `  targetPort: ${port}`,
    'persistence: { enabled: true, size: 50Gi, storageClass: "" }',
    'resources:',
    '  requests: { cpu: 500m, memory: 1Gi }',
    '  limits:   { cpu: 2000m, memory: 4Gi }',
    'secrets: { gdEncryptionKey: "", gdJwtSecret: "" }',
    '',
  ].join('\n');
  const helpers = '{{- define "firealive-gd.labels" -}}\napp.kubernetes.io/name: firealive-gd\napp.kubernetes.io/instance: {{ .Release.Name }}\n{{- end -}}\n';
  const deployment = [
    'apiVersion: apps/v1',
    'kind: Deployment',
    'metadata: { name: {{ .Release.Name }}, labels: {{- include "firealive-gd.labels" . | nindent 4 }} }',
    'spec:',
    '  replicas: {{ .Values.replicaCount }}',
    '  selector: { matchLabels: { app.kubernetes.io/name: firealive-gd, app.kubernetes.io/instance: {{ .Release.Name }} } }',
    '  template:',
    '    metadata: { labels: {{- include "firealive-gd.labels" . | nindent 8 }} }',
    '    spec:',
    '      containers:',
    '        - name: firealive-gd',
    '          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"',
    `          ports: [{ containerPort: ${port} }]`,
    '          env:',
    '            - { name: GD_ENCRYPTION_KEY, valueFrom: { secretKeyRef: { name: {{ .Release.Name }}-secrets, key: gd_encryption_key } } }',
    '            - { name: GD_JWT_SECRET,     valueFrom: { secretKeyRef: { name: {{ .Release.Name }}-secrets, key: gd_jwt_secret } } }',
    '          resources: {{- toYaml .Values.resources | nindent 12 }}',
    '',
  ].join('\n');
  const service = [
    'apiVersion: v1',
    'kind: Service',
    'metadata: { name: {{ .Release.Name }}, labels: {{- include "firealive-gd.labels" . | nindent 4 }} }',
    'spec:',
    '  type: {{ .Values.service.type }}',
    '  selector: { app.kubernetes.io/name: firealive-gd, app.kubernetes.io/instance: {{ .Release.Name }} }',
    '  ports: [{ port: {{ .Values.service.port }}, targetPort: {{ .Values.service.targetPort }} }]',
    '',
  ].join('\n');
  const secret = [
    'apiVersion: v1',
    'kind: Secret',
    'metadata: { name: {{ .Release.Name }}-secrets }',
    'type: Opaque',
    'stringData:',
    '  gd_encryption_key: {{ .Values.secrets.gdEncryptionKey | quote }}',
    '  gd_jwt_secret:     {{ .Values.secrets.gdJwtSecret | quote }}',
    '',
  ].join('\n');
  return [
    { path: 'Chart.yaml', content: chart },
    { path: 'values.yaml', content: values },
    { path: 'templates/_helpers.tpl', content: helpers },
    { path: 'templates/deployment.yaml', content: deployment },
    { path: 'templates/service.yaml', content: service },
    { path: 'templates/secret.yaml', content: secret },
  ];
}

// ─── bicep (Azure only) ────────────────────────────────────────────────

function renderBicep(snapshot, provider) {
  if (provider !== 'azure') throw new Error(`bicep: Azure-only, got '${provider}'`);
  const port = GD_DEPLOY_SHAPE.port;
  const main = [
    '// FireAlive GD-server Azure deployment (Bicep)',
    `// Snapshot: MCs=${snapshot.management_consoles.total}, users=${snapshot.users.total}`,
    '',
    "param location string = resourceGroup().location",
    `param gdImage string = '${GD_DEPLOY_SHAPE.image}'`,
    "@secure() param gdEncryptionKey string",
    "@secure() param gdJwtSecret string",
    "param operatorObjectId string",
    '',
    "var kvName = 'firealive-gd-kv-${uniqueString(resourceGroup().id)}'",
    "var aciName = 'firealive-gd'",
    '',
    "resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {",
    "  name: kvName",
    "  location: location",
    "  properties: {",
    "    sku: { family: 'A', name: 'standard' }",
    "    tenantId: subscription().tenantId",
    "    accessPolicies: [ { tenantId: subscription().tenantId, objectId: operatorObjectId, permissions: { secrets: ['get','list','set'] } } ]",
    "  }",
    "}",
    "resource kvKek 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = { parent: kv, name: 'gd-encryption-key', properties: { value: gdEncryptionKey } }",
    "resource kvJwt 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = { parent: kv, name: 'gd-jwt-secret', properties: { value: gdJwtSecret } }",
    '',
    "resource aci 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {",
    "  name: aciName",
    "  location: location",
    "  properties: {",
    "    osType: 'Linux'",
    `    ipAddress: { type: 'Public', dnsNameLabel: aciName, ports: [ { port: ${port}, protocol: 'TCP' } ] }`,
    "    containers: [",
    "      {",
    "        name: 'firealive-gd'",
    "        properties: {",
    "          image: gdImage",
    "          resources: { requests: { cpu: 1, memoryInGB: 2 } }",
    `          ports: [ { port: ${port} } ]`,
    "          environmentVariables: [",
    "            { name: 'GD_ENCRYPTION_KEY', secureValue: gdEncryptionKey }",
    "            { name: 'GD_JWT_SECRET',    secureValue: gdJwtSecret }",
    "          ]",
    "        }",
    "      }",
    "    ]",
    "  }",
    "}",
    '',
    `output gdEndpoint string = 'https://\${aci.properties.ipAddress.fqdn}:${port}'`,
    '',
  ].join('\n');
  return [{ path: 'main.bicep', content: main }];
}

// ─── gcp-dm (GCP only) ─────────────────────────────────────────────────

function renderGcpDm(snapshot, provider) {
  if (provider !== 'gcp') throw new Error(`gcp-dm: GCP-only, got '${provider}'`);
  const port = GD_DEPLOY_SHAPE.port;
  const yaml = [
    '# FireAlive GD-server GCP Deployment Manager configuration',
    `# Snapshot: MCs=${snapshot.management_consoles.total}`,
    '',
    'resources:',
    '  - name: gd-kek',
    '    type: gcp-types/secretmanager-v1:projects.secrets',
    '    properties: { secretId: firealive-gd-kek, replication: { automatic: {} } }',
    '  - name: gd-jwt',
    '    type: gcp-types/secretmanager-v1:projects.secrets',
    '    properties: { secretId: firealive-gd-jwt, replication: { automatic: {} } }',
    '  - name: firealive-gd-cr',
    '    type: gcp-types/run-v2:projects.locations.services',
    '    properties:',
    '      parent: projects/your-project-id/locations/us-central1',
    '      serviceId: firealive-gd',
    '      template:',
    '        containers:',
    `          - image: ${GD_DEPLOY_SHAPE.image}`,
    `            ports: [{ containerPort: ${port} }]`,
    '            env:',
    '              - { name: GD_ENCRYPTION_KEY, valueSource: { secretKeyRef: { secret: $(ref.gd-kek.name), version: latest } } }',
    '              - { name: GD_JWT_SECRET,    valueSource: { secretKeyRef: { secret: $(ref.gd-jwt.name), version: latest } } }',
    '',
    '# Note: GCP Deployment Manager is in deprecation track since 2024.',
    '',
  ].join('\n');
  return [{ path: 'firealive-gd.yaml', content: yaml }];
}

// ─── Dispatch ──────────────────────────────────────────────────────────

const TEMPLATE_DISPATCH = {
  terraform: renderTerraform,
  pulumi: renderPulumi,
  cloudformation: renderCloudformation,
  'docker-compose': renderDockerCompose,
  'docker-manifest': renderDockerManifest,
  kubernetes: renderKubernetes,
  helm: renderHelm,
  bicep: renderBicep,
  'gcp-dm': renderGcpDm,
};

// ═══════════════════════════════════════════════════════════════════════════════
// ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════════════

function resolveCloudPackagesDir(override) {
  return (
    override
    || process.env.GD_CLOUD_PACKAGES_DIR
    || path.join(__dirname, '../data/cloud-packages')
  );
}

function buildReadme(provider, iacTool, snapshot, packageId, signingKeyFingerprint) {
  return [
    '# FireAlive GD-server Deployment Bundle',
    '',
    `**Package id:** \`${packageId}\``,
    `**Generated:** ${snapshot.captured_at}`,
    `**Source GD version:** ${snapshot.version.version} (fuse=${snapshot.version.fuse_counter})`,
    `**Provider:** ${provider}`,
    `**IaC tool:** ${iacTool}`,
    '',
    '## Contents',
    '',
    `- \`iac/\` — IaC files for ${iacTool} targeting ${provider}`,
    '- `sbom.spdx.json` — SBOM',
    '- `bundle-manifest.json` — per-file SHA-256',
    '- `README.md` — this file',
    '',
    '## Verifying the signature',
    '',
    '```bash',
    'cosign verify-blob --key <gd-cloud-iac-public-key.pem> --signature bundle.tar.gz.sig bundle.tar.gz',
    '```',
    '',
    `Signing key fingerprint: \`${signingKeyFingerprint}\``,
    '',
    '## Secrets mapping',
    '',
    SECRETS_MAPPING_BY_PROVIDER[provider] || '(no provider-specific mapping)',
    '',
    'Required env vars (set by the IaC or your secret store):',
    '',
    '- `GD_ENCRYPTION_KEY` — 32-byte hex KEK for GD-side Tier-1 wrap',
    '- `GD_JWT_SECRET` — JWT signing secret (≥16 random chars)',
    '',
    '## Install posture at generation time',
    '',
    `- Users: ${snapshot.users.total} (${JSON.stringify(snapshot.users.by_role)})`,
    `- Management Consoles: ${snapshot.management_consoles.active} active / ${snapshot.management_consoles.total} total`,
    `- Signing keys: ${snapshot.signing_keys.active} active / ${snapshot.signing_keys.total} total`,
    '',
  ].join('\n');
}

function tarGzipDirectory(sourceDir, outputArchivePath) {
  execFileSync(
    'tar',
    ['-czf', outputArchivePath, '-C', sourceDir, '.'],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  );
}

function generatePackage(db, provider, iacTool, options = {}) {
  if (!PROVIDER_TOOL_MATRIX[provider]) {
    throw new Error(`invalid provider '${provider}'; valid: ${Object.keys(PROVIDER_TOOL_MATRIX).join(', ')}`);
  }
  if (!PROVIDER_TOOL_MATRIX[provider].includes(iacTool)) {
    throw new Error(`invalid (provider, iac_tool) ('${provider}', '${iacTool}'); valid: ${PROVIDER_TOOL_MATRIX[provider].join(', ')}`);
  }
  if (!options.userId || typeof options.userId !== 'number') {
    throw new Error('generatePackage: options.userId is required');
  }

  signingKeys.ensureActiveKey(db);
  const activeKey = signingKeys.getActiveSigningKey(db);
  const snapshot = captureInstallSnapshot(db);

  const renderer = TEMPLATE_DISPATCH[iacTool];
  if (!renderer) throw new Error(`no template for iac_tool='${iacTool}'`);
  const rendered = renderer(snapshot, provider);
  if (!Array.isArray(rendered) || rendered.length === 0) {
    throw new Error(`template '${iacTool}' returned no files`);
  }

  const packageId = crypto.randomBytes(16).toString('hex');
  const cloudPackagesDir = resolveCloudPackagesDir(options.cloudPackagesDir);
  ensureDir(cloudPackagesDir);
  const bundleDir = path.join(cloudPackagesDir, packageId);
  const workDir = path.join(bundleDir, '_work');
  ensureDir(workDir);
  const iacDir = path.join(workDir, 'iac');
  ensureDir(iacDir);

  try {
    const fileRecords = [];
    for (const f of rendered) {
      const safe = path.normalize(f.path).replace(/^[\\/]+/, '');
      if (safe.startsWith('..') || safe.includes(path.sep + '..')) {
        throw new Error(`template '${iacTool}' produced traversal path: ${f.path}`);
      }
      const abs = path.join(iacDir, safe);
      ensureDir(path.dirname(abs));
      fs.writeFileSync(abs, f.content, 'utf8');
      fileRecords.push({
        relativePath: 'iac/' + safe,
        absolutePath: abs,
        sizeBytes: fs.statSync(abs).size,
        sha256: sha256OfFile(abs),
      });
    }

    const readmePath = path.join(workDir, 'README.md');
    fs.writeFileSync(readmePath, buildReadme(provider, iacTool, snapshot, packageId, activeKey.publicKeyFingerprint), 'utf8');
    fileRecords.push({ relativePath: 'README.md', absolutePath: readmePath, sizeBytes: fs.statSync(readmePath).size, sha256: sha256OfFile(readmePath) });

    const sbomPath = path.join(workDir, 'sbom.spdx.json');
    const scanDir = path.join(__dirname, '..');
    const sbomResult = generateSbom(scanDir, sbomPath);
    fileRecords.push({ relativePath: 'sbom.spdx.json', absolutePath: sbomPath, sizeBytes: sbomResult.sizeBytes, sha256: sbomResult.sha256 });

    const manifestObj = {
      format: 'firealive-gd-cloud-iac-bundle-v1',
      package_id: packageId,
      provider, iac_tool: iacTool,
      generated_at: snapshot.captured_at,
      source_version: snapshot.version,
      signing_key: { id: activeKey.id, fingerprint_sha256: activeKey.publicKeyFingerprint, algorithm: 'cosign-ecdsa-p256' },
      sbom: { path: 'sbom.spdx.json', sha256: sbomResult.sha256, size_bytes: sbomResult.sizeBytes },
      files: fileRecords.map(f => ({ path: f.relativePath, size_bytes: f.sizeBytes, sha256: f.sha256 })),
    };
    const manifestPath = path.join(workDir, 'bundle-manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(manifestObj, null, 2), 'utf8');
    const manifestSha = sha256OfFile(manifestPath);

    const archivePath = path.join(bundleDir, 'bundle.tar.gz');
    tarGzipDirectory(workDir, archivePath);

    const signaturePath = path.join(bundleDir, 'bundle.tar.gz.sig');
    const sigResult = signBlob(archivePath, activeKey.privateKeyPem, signaturePath);

    const sidecarManifestPath = path.join(bundleDir, 'bundle-manifest.json');
    const sidecarSbomPath = path.join(bundleDir, 'sbom.spdx.json');
    fs.copyFileSync(manifestPath, sidecarManifestPath);
    fs.copyFileSync(sbomPath, sidecarSbomPath);

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
      packageId, provider, iacTool, options.userId,
      bundleDir, archivePath,
      manifestSha, sidecarSbomPath, sbomResult.sha256,
      signaturePath, sigResult.sha256,
      activeKey.id, JSON.stringify(snapshot), archiveStat.size,
    );

    fs.rmSync(workDir, { recursive: true, force: true });

    return {
      id: packageId,
      provider, iac_tool: iacTool,
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
    try { if (fs.existsSync(bundleDir)) fs.rmSync(bundleDir, { recursive: true, force: true }); } catch { /* swallow */ }
    throw err;
  }
}

module.exports = {
  generatePackage,
  signingKeys,
  captureInstallSnapshot,
  PROVIDER_TOOL_MATRIX,
  SECRETS_MAPPING_BY_PROVIDER,
  GD_DEPLOY_SHAPE,
  SyftNotInstalledError,
  CosignNotInstalledError,
};

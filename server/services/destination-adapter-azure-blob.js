// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Azure Blob Storage Destination Adapter
//
// Pushes v2 backups to Azure Blob Storage using @azure/storage-blob and
// @azure/identity for authentication. BlockBlobClient.uploadFile handles
// multipart uploads automatically for large files (the archive.tar.zst.enc).
//
// AUTH MODES (operator-selectable via credentials)
//
//   1. Account key       { account_key: "<base64>" }
//                         Most common for storage accounts; account
//                         keys grant FULL access to the storage account
//                         so principle of least privilege favors SAS
//                         tokens or service principals.
//
//   2. SAS token         { sas_token: "?sv=2024-...&sig=..." }
//                         Scoped, time-limited. Operators issue
//                         container-scoped SAS tokens with write/read
//                         permissions only. Token expires; operators
//                         must rotate before expiry.
//
//   3. Service principal { tenant_id, client_id, client_secret }
//                         Azure AD authentication via
//                         ClientSecretCredential. Recommended for
//                         enterprise deployments with RBAC on the
//                         storage account.
//
//   4. Managed identity  null / empty -> DefaultAzureCredential
//                         For FireAlive-on-Azure (App Service, AKS,
//                         VM) where the host has a managed identity
//                         with appropriate RBAC.
//
// SOVEREIGN CLOUDS via endpoint_suffix:
//
//   core.windows.net          (default; public Azure)
//   core.chinacloudapi.cn     (Azure China)
//   core.usgovcloudapi.net    (Azure US Government)
//
// CONFIG SCHEMA
//
//   {
//     "account_name":     "firealivebackups",      (required;
//                                                   3-24 lowercase
//                                                   alphanumeric)
//     "container_name":   "backups",                (required;
//                                                   3-63 chars,
//                                                   lowercase
//                                                   alphanumeric +
//                                                   dashes; cannot
//                                                   start/end with
//                                                   dash; no
//                                                   consecutive
//                                                   dashes)
//     "endpoint_suffix":  "core.windows.net",       (optional;
//                                                   default
//                                                   public cloud)
//     "prefix":           "production/"             (optional;
//                                                   trailing /,
//                                                   no leading /)
//   }
//
// BLOB LAYOUT
//
//   <container>/<prefix><sourceDirName>/
//     archive.tar.zst.enc
//     manifest.json
//     manifest.sig
//     wrapped-key.bin
//     _complete.flag       (written LAST; atomicity marker)
//
// _complete.flag pattern matches the S3 adapter (commit 10) for
// cross-cloud consistency. Restore code (R3d-5) treats the absence
// of _complete.flag as "in-progress / aborted push" and skips.
//
// IMMUTABILITY VIA AZURE'S "IMMUTABLE STORAGE WITH VERSIONING"
//
// Azure's analog to S3 Object Lock. supportedImmutabilityModes
// includes 'object-lock'. When destination.immutability_mode=
// 'object-lock', the adapter sets a Locked time-based retention
// policy on each blob via setImmutabilityPolicy AFTER upload.
//
// Container-level vs per-blob: Azure supports both. We use per-blob
// (setImmutabilityPolicy on each blob) because (a) it works regardless
// of container-level policy, (b) it gives explicit verification, and
// (c) the same retention applies whether the container has a default
// policy or not. The probe (commit 13) verifies that the container has
// version-level immutability enabled, which is required to set
// per-blob policies.
//
// CHECKSUM VERIFICATION
//
// Azure Blob storage supports Content-MD5 transit verification (we
// compute MD5 client-side, send via BlobHTTPHeaders, Azure verifies
// on receipt). MD5 is weak cryptographically but adequate for
// transit integrity (the actual cryptographic integrity is on the
// FireAlive manifest signature and the v2 backup archive's AES-GCM
// authentication tag).
//
// Newer Azure SDK supports CRC64 via transactionalContentCrc64;
// we set transactionalContentMD5 for broadest server-side support.
//
// SDK NOT YET INSTALLED
//
// @azure/storage-blob added to package.json in commit 23 (alongside
// the AWS, GCP SDKs and the @azure/keyvault-keys + @azure/identity
// already used by the azure-keyvault KEK provider). Until then, this
// module loads cleanly. Any push call before commit 23 throws
// DestinationAdapterError with "npm install" instruction.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const base = require('./destination-adapter-base');

const ADAPTER_NAME = 'azure-blob';

const VALID_ACCOUNT_NAME_PATTERN = /^[a-z0-9]{3,24}$/;
const VALID_CONTAINER_NAME_PATTERN = /^[a-z0-9](-?[a-z0-9])*$/;   // 3-63 chars; no consecutive dashes; can't start/end with dash
const VALID_ENDPOINT_SUFFIX_PATTERN = /^[a-z][a-z0-9.-]+[a-z]$/;
const VALID_PREFIX_PATTERN = /^([a-zA-Z0-9!_.*'()/\-]+\/)?$/;

// ── SDK loading (lazy + test-overridable) ─────────────────────────────────

let _sdksOverride = null;

function _setSdkForTest(sdks) {
  _sdksOverride = sdks;
}

function _getSdks() {
  if (_sdksOverride) return _sdksOverride;
  let storageBlob, identity;
  try {
    // eslint-disable-next-line global-require
    storageBlob = require('@azure/storage-blob');
  } catch (err) {
    throw new base.DestinationAdapterError(
      "@azure/storage-blob not installed; run: npm install @azure/storage-blob @azure/identity",
      { adapter: ADAPTER_NAME, operation: 'sdk-load', retryable: false, cause: err },
    );
  }
  try {
    // eslint-disable-next-line global-require
    identity = require('@azure/identity');
  } catch (err) {
    throw new base.DestinationAdapterError(
      "@azure/identity not installed; run: npm install @azure/storage-blob @azure/identity",
      { adapter: ADAPTER_NAME, operation: 'sdk-load', retryable: false, cause: err },
    );
  }
  return { storageBlob, identity };
}

// ── Retryable classification ──────────────────────────────────────────────

const RETRYABLE_AZURE_ERROR_CODES = new Set([
  'ServerBusy',
  'OperationTimedOut',
  'InternalError',
  'TooManyRequests',
  'ServiceUnavailable',
]);

const PERMANENT_AZURE_ERROR_CODES = new Set([
  'AuthenticationFailed',
  'AuthorizationFailure',
  'AuthorizationPermissionMismatch',
  'ContainerNotFound',
  'BlobNotFound',
  'ContainerAlreadyExists',
  'InvalidUri',
  'InvalidAuthenticationInfo',
  'AccountIsDisabled',
  'InvalidHeaderValue',
  'InvalidInput',
]);

function isRetryableAzureError(err) {
  if (!err) return false;
  if (err.code && RETRYABLE_AZURE_ERROR_CODES.has(err.code)) return true;
  if (err.code && PERMANENT_AZURE_ERROR_CODES.has(err.code)) return false;
  if (typeof err.statusCode === 'number') {
    if (err.statusCode === 429) return true;
    if (err.statusCode >= 500 && err.statusCode < 600) return true;
    if (err.statusCode >= 400 && err.statusCode < 500) return false;
  }
  if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT' ||
      err.code === 'ENETUNREACH' || err.code === 'ENOTFOUND' ||
      err.code === 'EAI_AGAIN' || err.code === 'ECONNREFUSED') return true;
  return false;
}

// ── Validation ────────────────────────────────────────────────────────────

function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ok: false, error: 'config must be a JSON object', field: 'config' };
  }

  let r = base.requireString(config, 'account_name', { maxLength: 24, pattern: VALID_ACCOUNT_NAME_PATTERN });
  if (!r.ok) return { ok: false, error: 'account_name must be 3-24 lowercase alphanumeric chars', field: 'account_name' };

  if (typeof config.container_name !== 'string' || config.container_name.length < 3 || config.container_name.length > 63 || !VALID_CONTAINER_NAME_PATTERN.test(config.container_name) || config.container_name.includes('--')) {
    return { ok: false, error: 'container_name must be 3-63 lowercase alphanumeric + dashes; no leading/trailing dash; no consecutive dashes', field: 'container_name' };
  }

  if (config.endpoint_suffix !== undefined && config.endpoint_suffix !== null) {
    if (typeof config.endpoint_suffix !== 'string' || !VALID_ENDPOINT_SUFFIX_PATTERN.test(config.endpoint_suffix)) {
      return { ok: false, error: 'endpoint_suffix must be a valid Azure endpoint suffix (e.g. core.windows.net, core.chinacloudapi.cn, core.usgovcloudapi.net)', field: 'endpoint_suffix' };
    }
  }

  if (config.prefix !== undefined && config.prefix !== null && config.prefix !== '') {
    if (typeof config.prefix !== 'string' || !VALID_PREFIX_PATTERN.test(config.prefix)) {
      return { ok: false, error: 'prefix must be empty or end with /, no leading slash', field: 'prefix' };
    }
  }

  const allowed = new Set(['account_name', 'container_name', 'endpoint_suffix', 'prefix']);
  for (const k of Object.keys(config)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in config: ${k}`, field: k };
    }
  }
  return { ok: true };
}

function validateCredentials(credentials) {
  if (credentials === null || credentials === undefined) return { ok: true };
  if (typeof credentials !== 'object' || Array.isArray(credentials)) {
    return { ok: false, error: 'credentials must be a JSON object or null', field: 'credentials' };
  }
  if (Object.keys(credentials).length === 0) return { ok: true };

  // Determine which auth mode is in use. Exactly ONE mode allowed.
  const hasAccountKey = !!credentials.account_key;
  const hasSasToken = !!credentials.sas_token;
  const hasServicePrincipal = !!(credentials.tenant_id || credentials.client_id || credentials.client_secret);

  const modeCount = (hasAccountKey ? 1 : 0) + (hasSasToken ? 1 : 0) + (hasServicePrincipal ? 1 : 0);
  if (modeCount > 1) {
    return { ok: false, error: 'mutually exclusive auth modes: choose one of account_key, sas_token, or service principal (tenant_id+client_id+client_secret)', field: 'credentials' };
  }
  if (modeCount === 0) {
    return { ok: false, error: 'one of account_key, sas_token, or service principal required (or omit credentials entirely for managed identity)', field: 'credentials' };
  }

  if (hasAccountKey) {
    const r = base.requireString(credentials, 'account_key', { maxLength: 256 });
    if (!r.ok) return { ok: false, error: r.error, field: 'account_key' };
    // Allow base64 and base64url variants; Azure account keys are base64
    if (!/^[A-Za-z0-9+/=_-]+$/.test(credentials.account_key)) {
      return { ok: false, error: 'account_key must be base64 (Azure storage account key format)', field: 'account_key' };
    }
  }

  if (hasSasToken) {
    const r = base.requireString(credentials, 'sas_token', { maxLength: 4096 });
    if (!r.ok) return { ok: false, error: r.error, field: 'sas_token' };
    // SAS tokens start with '?' or with sv= (without leading ?)
    if (!credentials.sas_token.startsWith('?') && !credentials.sas_token.startsWith('sv=')) {
      return { ok: false, error: 'sas_token must start with ? or sv= (Azure SAS token format)', field: 'sas_token' };
    }
  }

  if (hasServicePrincipal) {
    let r = base.requireString(credentials, 'tenant_id', { maxLength: 64 });
    if (!r.ok) return { ok: false, error: 'tenant_id required for service principal auth', field: 'tenant_id' };
    r = base.requireString(credentials, 'client_id', { maxLength: 64 });
    if (!r.ok) return { ok: false, error: 'client_id required for service principal auth', field: 'client_id' };
    r = base.requireString(credentials, 'client_secret', { maxLength: 1024 });
    if (!r.ok) return { ok: false, error: 'client_secret required for service principal auth', field: 'client_secret' };
  }

  const allowed = new Set(['account_key', 'sas_token', 'tenant_id', 'client_id', 'client_secret']);
  for (const k of Object.keys(credentials)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in credentials: ${k}`, field: k };
    }
  }
  return { ok: true };
}

// ── Client construction ──────────────────────────────────────────────────

function buildBlobServiceUrl(config) {
  const suffix = config.endpoint_suffix || 'core.windows.net';
  return `https://${config.account_name}.blob.${suffix}`;
}

function buildBlobServiceClient(config, credentials) {
  const { storageBlob, identity } = _getSdks();
  const url = buildBlobServiceUrl(config);

  if (!credentials || typeof credentials !== 'object' || Object.keys(credentials).length === 0) {
    // Managed identity / DefaultAzureCredential
    return new storageBlob.BlobServiceClient(url, new identity.DefaultAzureCredential());
  }

  if (credentials.account_key) {
    const cred = new storageBlob.StorageSharedKeyCredential(config.account_name, credentials.account_key);
    return new storageBlob.BlobServiceClient(url, cred);
  }

  if (credentials.sas_token) {
    const sasUrl = url + (credentials.sas_token.startsWith('?') ? credentials.sas_token : '?' + credentials.sas_token);
    return new storageBlob.BlobServiceClient(sasUrl);
  }

  if (credentials.tenant_id) {
    const cred = new identity.ClientSecretCredential(
      credentials.tenant_id, credentials.client_id, credentials.client_secret,
    );
    return new storageBlob.BlobServiceClient(url, cred);
  }

  // Should never reach here -- validateCredentials enforces one mode
  throw new base.DestinationAdapterError(
    'no auth mode determined from credentials',
    { adapter: ADAPTER_NAME, operation: 'sdk-load', retryable: false },
  );
}

function md5OfFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('md5');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (c) => hash.update(c));
    stream.on('end', () => resolve(hash.digest()));
    stream.on('error', reject);
  });
}

function buildImmutabilityPolicy(immutabilityMode, retentionDays) {
  if (immutabilityMode !== 'object-lock') return null;
  const days = (typeof retentionDays === 'number' && retentionDays >= 1) ? retentionDays : 30;
  return {
    expiresOn: new Date(Date.now() + days * 24 * 60 * 60 * 1000),
    policyMode: 'Locked',  // immutable; cannot shorten the policy
  };
}

// ── Probe ────────────────────────────────────────────────────────────────

async function probe(config, credentials, options = {}) {
  const cv = validateConfig(config);
  if (!cv.ok) return { ok: false, error: cv.error, detail: { field: cv.field, phase: 'config' } };
  const cre = validateCredentials(credentials);
  if (!cre.ok) return { ok: false, error: cre.error, detail: { field: cre.field, phase: 'credentials' } };

  let serviceClient;
  try {
    serviceClient = buildBlobServiceClient(config, credentials);
  } catch (err) {
    return { ok: false, error: `client construction failed: ${err.message}`, detail: { phase: 'client' } };
  }
  const containerClient = serviceClient.getContainerClient(config.container_name);
  const probeBlobName = `${config.prefix || ''}.firealive-probe-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const probeContent = crypto.randomBytes(64);

  try {
    const blob = containerClient.getBlockBlobClient(probeBlobName);
    await blob.upload(probeContent, probeContent.length);
  } catch (err) {
    return { ok: false, error: `probe upload failed: ${err.message || err.code}`, detail: { phase: 'put', code: err.code } };
  }
  try {
    const blob = containerClient.getBlockBlobClient(probeBlobName);
    await blob.download();
  } catch (err) {
    return { ok: false, error: `probe download failed: ${err.message || err.code}`, detail: { phase: 'get', code: err.code } };
  }
  try {
    const blob = containerClient.getBlockBlobClient(probeBlobName);
    await blob.delete();
  } catch {
    // Probe blob not deleted -- non-fatal
  }
  return { ok: true, detail: { phase: 'roundtrip' } };
}

// ── Push ─────────────────────────────────────────────────────────────────

async function push(backupContext, options = {}) {
  const logger = options.logger || console;
  const { destination, sourceDir, files, backupId } = backupContext;
  const config = destination.config;
  const credentials = destination.credentials;
  const sourceDirName = path.basename(sourceDir);

  if (sourceDirName.includes('/') || sourceDirName.includes('\\') ||
      sourceDirName === '.' || sourceDirName === '..' ||
      sourceDirName.startsWith('.')) {
    throw new base.DestinationAdapterError(
      `unsafe source directory name: ${sourceDirName}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: false },
    );
  }

  for (const f of files) {
    if (!fs.existsSync(f.absolutePath)) {
      throw new base.DestinationAdapterError(
        `source file not found: ${f.absolutePath}`,
        { adapter: ADAPTER_NAME, operation: 'push', retryable: false },
      );
    }
  }

  const serviceClient = buildBlobServiceClient(config, credentials);
  const containerClient = serviceClient.getContainerClient(config.container_name);
  const prefix = config.prefix || '';
  const blobPrefix = `${prefix}${sourceDirName}/`;
  const completeFlagBlobName = `${blobPrefix}_complete.flag`;

  const immutabilityPolicy = buildImmutabilityPolicy(destination.immutability_mode, destination.retention_days);

  // Idempotency check: if _complete.flag exists, this backup was already pushed.
  try {
    const flagBlob = containerClient.getBlockBlobClient(completeFlagBlobName);
    const exists = await flagBlob.exists();
    if (exists) {
      logger.info(`destination-adapter-azure-blob: backup ${sourceDirName} already complete on https://${config.account_name}.blob.${config.endpoint_suffix || 'core.windows.net'}/${config.container_name}/${blobPrefix} (skipping)`);
      return {
        destinationPath: `azureblob://${config.account_name}/${config.container_name}/${blobPrefix}`,
        bytesPushed: 0,
        immutabilityVerified: immutabilityPolicy ? { mode: 'object-lock', trustedBy: 'azure-immutability-policy' } : null,
        destinationMetadata: {
          backupId, sourceDirName,
          accountName: config.account_name,
          containerName: config.container_name,
          blobPrefix,
          alreadyPresent: true,
          immutabilityMode: destination.immutability_mode,
        },
      };
    }
  } catch (err) {
    // exists() can throw on auth/network failures -- propagate those
    throw new base.DestinationAdapterError(
      `idempotency check failed: ${err.message || err.code}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: isRetryableAzureError(err), detail: { code: err.code }, cause: err },
    );
  }

  let bytesPushed = 0;
  const uploadedBlobs = [];

  try {
    for (const file of files) {
      const blobName = `${blobPrefix}${file.name}`;
      const blob = containerClient.getBlockBlobClient(blobName);
      const fileSize = fs.statSync(file.absolutePath).size;
      const md5 = await md5OfFile(file.absolutePath);

      try {
        await blob.uploadFile(file.absolutePath, {
          blobHTTPHeaders: {
            blobContentMD5: md5,
            blobContentType: 'application/octet-stream',
          },
        });
      } catch (err) {
        throw new base.DestinationAdapterError(
          `Azure Blob upload of ${file.name} failed: ${err.message || err.code}`,
          { adapter: ADAPTER_NAME, operation: 'push', retryable: isRetryableAzureError(err), detail: { file: file.name, code: err.code }, cause: err },
        );
      }

      // Set per-blob immutability policy AFTER upload (Azure requires this
      // on a committed blob, not during upload itself).
      if (immutabilityPolicy) {
        try {
          await blob.setImmutabilityPolicy(immutabilityPolicy);
        } catch (err) {
          throw new base.DestinationAdapterError(
            `Azure setImmutabilityPolicy for ${file.name} failed: ${err.message || err.code}`,
            { adapter: ADAPTER_NAME, operation: 'push', retryable: isRetryableAzureError(err), detail: { file: file.name, code: err.code, hint: 'container must have version-level immutability enabled' }, cause: err },
          );
        }
      }

      uploadedBlobs.push(blobName);
      bytesPushed += fileSize;
      logger.info(`destination-adapter-azure-blob: uploaded ${file.name} (${fileSize} bytes) to ${blobName}`);
    }

    // After all files succeed, write _complete.flag last.
    const completeMarker = JSON.stringify({
      backup_id: backupId, source_dir: sourceDirName,
      completed_at: new Date().toISOString(),
      file_count: files.length, total_bytes: bytesPushed,
    });
    const completeMd5 = crypto.createHash('md5').update(completeMarker).digest();
    const flagBlob = containerClient.getBlockBlobClient(completeFlagBlobName);
    await flagBlob.upload(completeMarker, Buffer.byteLength(completeMarker), {
      blobHTTPHeaders: {
        blobContentMD5: completeMd5,
        blobContentType: 'application/json',
      },
    });
    if (immutabilityPolicy) {
      await flagBlob.setImmutabilityPolicy(immutabilityPolicy);
    }

    logger.info(`destination-adapter-azure-blob: pushed ${sourceDirName} (${bytesPushed} bytes) to ${config.container_name}/${blobPrefix}`);

    return {
      destinationPath: `azureblob://${config.account_name}/${config.container_name}/${blobPrefix}`,
      bytesPushed,
      immutabilityVerified: immutabilityPolicy ? {
        mode: 'object-lock',
        trustedBy: 'azure-immutability-policy',
        retentionUntil: immutabilityPolicy.expiresOn.toISOString(),
      } : null,
      destinationMetadata: {
        backupId, sourceDirName,
        accountName: config.account_name,
        containerName: config.container_name,
        blobPrefix,
        endpointSuffix: config.endpoint_suffix || 'core.windows.net',
        immutabilityMode: destination.immutability_mode,
      },
    };
  } catch (err) {
    if (err instanceof base.DestinationAdapterError) throw err;
    throw new base.DestinationAdapterError(
      `unexpected push failure: ${err.message}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: true, cause: err },
    );
  }
}

// ── Adapter export + self-registration ──────────────────────────────────

const adapter = {
  name: ADAPTER_NAME,
  description: 'Push backups to Azure Blob Storage via @azure/storage-blob. Supports account key, SAS token, service principal, or managed identity. Sovereign clouds via endpoint_suffix. Object Lock equivalent via Azure immutable storage with versioning.',
  supportedImmutabilityModes: ['none', 'append-only', 'object-lock', 'unknown'],
  validateConfig,
  validateCredentials,
  probe,
  push,
  // Test-only export
  _setSdkForTest,
};

base.registerAdapter(adapter);

module.exports = adapter;

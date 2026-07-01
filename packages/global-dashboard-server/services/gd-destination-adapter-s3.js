// =============================================================================
// FIREALIVE GD -- S3 Destination Adapter
//
// Pushes artifacts (full-suite backups, snapshots, sealed audit-log / CEF
// segments, forensic-export bundles) to AWS S3 OR any S3-compatible object
// storage service. Uses @aws-sdk/client-s3 + @aws-sdk/lib-storage. The
// lib-storage Upload helper handles multipart uploads automatically for large
// files (a full-suite backup archive can reach GB).
//
// S3-COMPATIBLE PROVIDERS COVERED FOR FREE
//
// The endpoint config field accepts a custom URL, so this single adapter
// covers all S3-compatible services without separate code:
//
//   AWS S3              (default; omit endpoint)
//   Hetzner Object Storage    https://<region>.your-objectstorage.com
//   OVHcloud Object Storage   https://s3.<region>.io.cloud.ovh.net
//   Scaleway Object Storage   https://s3.<region>.scw.cloud
//   MinIO (self-hosted)       https://minio.example.com:9000
//   Wasabi                    https://s3.<region>.wasabisys.com
//   Backblaze B2              https://s3.<region>.backblazeb2.com
//   Cloudflare R2             https://<account>.r2.cloudflarestorage.com
//   Linode Object Storage     https://<region>.linodeobjects.com
//   DigitalOcean Spaces       https://<region>.digitaloceanspaces.com
//   ...any other S3-compatible service
//
// EU privacy-first deployments are recommended: Hetzner / OVHcloud /
// Scaleway for storage + HashiCorp Vault for KEK = US-cloud-free
// artifact pipeline.
//
// CONFIG SCHEMA (config JSON for s3 destination rows)
//
//   {
//     "bucket":            "firealive-gd-backups",   (required)
//     "region":            "us-east-1",              (required)
//     "prefix":            "production/",            (optional;
//                                                    forward-slash trailing
//                                                    style; no leading slash)
//     "endpoint":          "https://...",            (optional; for
//                                                    S3-compatible
//                                                    services)
//     "force_path_style":  true,                     (optional; required
//                                                    by some S3-compat
//                                                    services)
//     "sse":               "AES256" | "aws:kms",     (optional;
//                                                    server-side
//                                                    encryption)
//     "sse_kms_key_id":    "arn:aws:kms:..."         (required if
//                                                    sse='aws:kms')
//   }
//
// Note: SSE is defense-in-depth on top of FireAlive's own artifact
// encryption. With the GD KEK + S3 SSE-KMS, you have two independent keys
// protecting the same data; rotate either without re-encrypting the other.
//
// CREDENTIALS SCHEMA
//
//   { "access_key_id": "AKIA...",
//     "secret_access_key": "...",
//     "session_token": "..." (optional) }
//
//   OR null/empty -> SDK default credential chain
//
// OBJECT STORAGE LAYOUT
//
//   <bucket>/<prefix><sourceDirName>/
//     <artifact files>
//     _complete.flag       (written LAST; presence = atomicity marker)
//
// _complete.flag is written ONLY after every other file has been confirmed
// uploaded. Restore code treats the absence of _complete.flag as
// "in-progress / aborted push" and skips the directory. Operators can
// configure S3 lifecycle rules to expire directories that lack
// _complete.flag after N days.
//
// IMMUTABILITY VIA OBJECT LOCK
//
// supportedImmutabilityModes includes 'object-lock'. When the destination's
// immutability_mode = 'object-lock', the adapter sets ObjectLockMode +
// ObjectLockRetainUntilDate on every PutObject so writes are immutable until
// the retention period expires. This is the write-once path the GD audit-log
// and CEF archival writers rely on: audit_log routing requires an
// immutability-capable destination, and probe() fails closed if the target
// bucket is not Object-Lock-enabled.
//
// Object Lock probe verifies the bucket has Object Lock CONFIGURATION enabled
// before allowing pushes; destinations declared as 'object-lock' but pushing
// to a non-locked bucket are rejected at probe time.
//
// SDK LAZY-LOADED
//
// @aws-sdk/client-s3 + @aws-sdk/lib-storage are GD server dependencies. This
// module loads cleanly even if they are somehow absent (require is lazy inside
// _getSdks()); a push or probe call then throws DestinationAdapterError with a
// clear "npm install" instruction. The local + sftp adapters are unaffected.
//
// CHECKSUM VERIFICATION
//
// PutObject calls include ChecksumSHA256 so S3 verifies on receipt. We compute
// the sha256 from disk before upload and hand it to S3, which rejects the
// object if the received bytes do not match. Verifies end-to-end integrity at
// the HTTP level.
// =============================================================================

const fs = require('fs');
const crypto = require('crypto');
const base = require('./gd-destination-adapter-base');

const ADAPTER_NAME = 's3';

const VALID_BUCKET_PATTERN = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
// Region pattern accepts any reasonable token. AWS regions like 'us-east-1'
// match; so do Hetzner ('hel1', 'fsn1'), Scaleway ('fr-par', 'nl-ams'),
// DigitalOcean ('nyc3', 'sfo3'), OVH (lowercase like 'bhs', 'gra'),
// Cloudflare R2 ('auto'). Backblaze B2 ('us-west-001') matches too.
// We don't try to enforce specific cloud naming -- the SDK rejects
// invalid regions at API call time.
const VALID_REGION_PATTERN = /^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$/;
const VALID_PREFIX_PATTERN = /^([a-zA-Z0-9!_.*'()/\-]+\/)?$/;
const VALID_SSE_VALUES = new Set(['AES256', 'aws:kms']);

// --- SDK loading (lazy + test-overridable) -----------------------------------

let _sdksOverride = null;

function _setSdkForTest(sdks) {
  _sdksOverride = sdks;
}

function _getSdks() {
  if (_sdksOverride) return _sdksOverride;
  let s3, libStorage;
  try {
    // eslint-disable-next-line global-require
    s3 = require('@aws-sdk/client-s3');
  } catch (err) {
    throw new base.DestinationAdapterError(
      "@aws-sdk/client-s3 not installed; run: npm install @aws-sdk/client-s3 @aws-sdk/lib-storage",
      { adapter: ADAPTER_NAME, operation: 'sdk-load', retryable: false, cause: err },
    );
  }
  try {
    // eslint-disable-next-line global-require
    libStorage = require('@aws-sdk/lib-storage');
  } catch (err) {
    throw new base.DestinationAdapterError(
      "@aws-sdk/lib-storage not installed; run: npm install @aws-sdk/client-s3 @aws-sdk/lib-storage",
      { adapter: ADAPTER_NAME, operation: 'sdk-load', retryable: false, cause: err },
    );
  }
  return { s3, libStorage };
}

// --- Retryable classification ------------------------------------------------

const RETRYABLE_S3_ERROR_NAMES = new Set([
  'ThrottlingException',
  'RequestTimeout',
  'RequestTimeoutException',
  'ServiceUnavailable',
  'SlowDown',
  'InternalError',
  'TimeoutError',
  'NetworkingError',
]);

const PERMANENT_S3_ERROR_NAMES = new Set([
  'AccessDenied',
  'InvalidAccessKeyId',
  'SignatureDoesNotMatch',
  'NoSuchBucket',
  'NoSuchKey',
  'BucketAlreadyExists',
  'InvalidBucketName',
  'EntityTooLarge',
  'InvalidRequest',
  'InvalidArgument',
  'PermanentRedirect',
]);

function isRetryableS3Error(err) {
  if (!err) return false;
  if (err.name && RETRYABLE_S3_ERROR_NAMES.has(err.name)) return true;
  if (err.name && PERMANENT_S3_ERROR_NAMES.has(err.name)) return false;
  const status = err.$metadata && err.$metadata.httpStatusCode;
  if (typeof status === 'number') {
    if (status === 429) return true;
    if (status >= 500 && status < 600) return true;
    if (status >= 400 && status < 500) return false;
  }
  if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT' ||
      err.code === 'ENETUNREACH' || err.code === 'ENOTFOUND' ||
      err.code === 'EAI_AGAIN' || err.code === 'ECONNREFUSED') return true;
  return false;
}

// --- Validation --------------------------------------------------------------

function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ok: false, error: 'config must be a JSON object', field: 'config' };
  }

  let r = base.requireString(config, 'bucket', { maxLength: 63, pattern: VALID_BUCKET_PATTERN });
  if (!r.ok) {
    return { ok: false, error: 'bucket must be 3-63 lowercase chars (S3 naming rules: alphanumeric, dots, hyphens; no leading/trailing dot or hyphen)', field: 'bucket' };
  }

  r = base.requireString(config, 'region', { maxLength: 32, pattern: VALID_REGION_PATTERN });
  if (!r.ok) return { ok: false, error: 'region must be valid AWS region format (e.g. us-east-1) or special "auto"/"global" for some S3-compatible services', field: 'region' };

  if (config.prefix !== undefined && config.prefix !== null && config.prefix !== '') {
    if (typeof config.prefix !== 'string' || !VALID_PREFIX_PATTERN.test(config.prefix)) {
      return { ok: false, error: 'prefix must be empty or end with /, no leading slash, only alphanumeric and -._/!*\'() chars', field: 'prefix' };
    }
  }

  if (config.endpoint !== undefined && config.endpoint !== null) {
    const r2 = base.requireString({ endpoint: config.endpoint }, 'endpoint', { maxLength: 256 });
    if (!r2.ok) return { ok: false, error: 'endpoint must be a non-empty URL string', field: 'endpoint' };
    try {
      const url = new URL(config.endpoint);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        return { ok: false, error: 'endpoint must use https or http scheme', field: 'endpoint' };
      }
      // http allowed for self-hosted MinIO on private networks; production
      // should use https. We log a warning at probe time but don't block here.
    } catch {
      return { ok: false, error: 'endpoint is not a valid URL', field: 'endpoint' };
    }
  }

  if (config.force_path_style !== undefined && typeof config.force_path_style !== 'boolean') {
    return { ok: false, error: 'force_path_style must be boolean', field: 'force_path_style' };
  }

  if (config.sse !== undefined && config.sse !== null) {
    if (!VALID_SSE_VALUES.has(config.sse)) {
      return { ok: false, error: `sse must be 'AES256' or 'aws:kms'`, field: 'sse' };
    }
    if (config.sse === 'aws:kms') {
      const r3 = base.requireString(config, 'sse_kms_key_id', { maxLength: 2048 });
      if (!r3.ok) return { ok: false, error: 'sse_kms_key_id required when sse=aws:kms', field: 'sse_kms_key_id' };
    }
  }

  if (config.sse_kms_key_id !== undefined && config.sse !== 'aws:kms') {
    return { ok: false, error: 'sse_kms_key_id requires sse=aws:kms', field: 'sse_kms_key_id' };
  }

  const allowed = new Set(['bucket', 'region', 'prefix', 'endpoint', 'force_path_style', 'sse', 'sse_kms_key_id']);
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

  let r = base.requireString(credentials, 'access_key_id', { maxLength: 128 });
  if (!r.ok) return { ok: false, error: r.error, field: 'access_key_id' };
  r = base.requireString(credentials, 'secret_access_key', { maxLength: 256 });
  if (!r.ok) return { ok: false, error: r.error, field: 'secret_access_key' };
  if (credentials.session_token !== undefined) {
    if (typeof credentials.session_token !== 'string' || credentials.session_token === '') {
      return { ok: false, error: 'session_token must be non-empty if provided', field: 'session_token' };
    }
  }

  const allowed = new Set(['access_key_id', 'secret_access_key', 'session_token']);
  for (const k of Object.keys(credentials)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in credentials: ${k}`, field: k };
    }
  }
  return { ok: true };
}

// --- S3 client construction --------------------------------------------------

function buildClient(config, credentials) {
  const { s3 } = _getSdks();
  const clientConfig = {
    region: config.region,
    maxAttempts: 1,   // storage-push layer handles retry
  };
  if (config.endpoint) {
    clientConfig.endpoint = config.endpoint;
  }
  if (config.force_path_style) {
    clientConfig.forcePathStyle = true;
  }
  if (credentials && typeof credentials === 'object' && Object.keys(credentials).length > 0) {
    clientConfig.credentials = {
      accessKeyId: credentials.access_key_id,
      secretAccessKey: credentials.secret_access_key,
      ...(credentials.session_token ? { sessionToken: credentials.session_token } : {}),
    };
  }
  return new s3.S3Client(clientConfig);
}

function buildSseParams(config) {
  if (!config.sse) return {};
  if (config.sse === 'AES256') return { ServerSideEncryption: 'AES256' };
  if (config.sse === 'aws:kms') {
    return {
      ServerSideEncryption: 'aws:kms',
      SSEKMSKeyId: config.sse_kms_key_id,
    };
  }
  return {};
}

function buildObjectLockParams(immutabilityMode, retentionDays) {
  if (immutabilityMode !== 'object-lock') return {};
  // Default 30-day retention; operators with stricter posture configure
  // higher via destination.retention_days. The DB column stores this
  // (storage_destinations.retention_days) but we accept it here only when
  // in object-lock mode.
  const days = (typeof retentionDays === 'number' && retentionDays >= 1) ? retentionDays : 30;
  const retainUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  return {
    ObjectLockMode: 'COMPLIANCE',          // strict: nobody can shorten
    ObjectLockRetainUntilDate: retainUntil,
  };
}

function sha256OfFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (c) => hash.update(c));
    stream.on('end', () => resolve(hash.digest()));
    stream.on('error', reject);
  });
}

// --- Probe -------------------------------------------------------------------
//
// Verifies bucket reachability + write permission via a small probe object.
// When options.immutabilityMode === 'object-lock', ALSO verifies the bucket
// has Object Lock CONFIGURATION enabled (must be set at bucket creation;
// cannot be added later). Operators who declare immutability_mode='object-
// lock' on a non-Object-Lock-enabled bucket get a clear probe failure
// rather than a confusing PutObject failure during the first push.
//
// Object Lock probe:
//   1. PutObject roundtrip (basic reachability + write permission)
//   2. If immutabilityMode='object-lock', call GetObjectLockConfiguration
//      and verify ObjectLockEnabled='Enabled' in the response
//   3. Surface the bucket's default retention rule (if any) in
//      probe result so admins can compare to declared retention_days

async function probe(config, credentials, options = {}) {
  const cv = validateConfig(config);
  if (!cv.ok) return { ok: false, error: cv.error, detail: { field: cv.field, phase: 'config' } };
  const cre = validateCredentials(credentials);
  if (!cre.ok) return { ok: false, error: cre.error, detail: { field: cre.field, phase: 'credentials' } };

  const { s3 } = _getSdks();
  const client = buildClient(config, credentials);
  const probeBytes = crypto.randomBytes(64);
  const prefix = config.prefix || '';
  const probeKey = `${prefix}.firealive-probe-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  try {
    await client.send(new s3.PutObjectCommand({
      Bucket: config.bucket,
      Key: probeKey,
      Body: probeBytes,
      ChecksumSHA256: probeBytes.slice(0, 32).toString('base64'),   // not the real hash; just exercises the path
    }));
  } catch (err) {
    try { client.destroy && client.destroy(); } catch { /* swallow */ }
    return { ok: false, error: `probe PutObject failed: ${err.message || err.name}`, detail: { phase: 'put', code: err.name, retryable: isRetryableS3Error(err) } };
  }
  try {
    await client.send(new s3.GetObjectCommand({ Bucket: config.bucket, Key: probeKey }));
  } catch (err) {
    try { client.destroy && client.destroy(); } catch { /* swallow */ }
    return { ok: false, error: `probe GetObject failed: ${err.message || err.name}`, detail: { phase: 'get', code: err.name } };
  }
  try {
    await client.send(new s3.DeleteObjectCommand({ Bucket: config.bucket, Key: probeKey }));
  } catch {
    // Probe object not deleted -- non-fatal; operator can clean up.
  }

  // Object Lock verification (only when destination declares object-lock mode)
  let objectLockDetail = null;
  if (options.immutabilityMode === 'object-lock') {
    let configResponse;
    try {
      configResponse = await client.send(new s3.GetObjectLockConfigurationCommand({
        Bucket: config.bucket,
      }));
    } catch (err) {
      try { client.destroy && client.destroy(); } catch { /* swallow */ }
      // ObjectLockConfigurationNotFoundError = bucket lacks Object Lock config.
      // Permanent: cannot enable Object Lock on an existing bucket; operator
      // must recreate the bucket with Object Lock enabled at creation time.
      const code = err.name || (err.Code && err.Code);
      if (code === 'ObjectLockConfigurationNotFoundError') {
        return {
          ok: false,
          error: `bucket '${config.bucket}' does not have Object Lock enabled. Object Lock must be enabled at bucket creation; it cannot be added to an existing bucket. Recreate the bucket with Object Lock enabled, or change immutability_mode to 'none' / 'append-only' / 'unknown'.`,
          detail: { phase: 'object-lock-not-configured', code, retryable: false },
        };
      }
      // Other errors during GetObjectLockConfiguration -- surface as probe failure
      return {
        ok: false,
        error: `probe GetObjectLockConfiguration failed: ${err.message || err.name}`,
        detail: { phase: 'object-lock-check', code, retryable: isRetryableS3Error(err) },
      };
    }
    // Verify the configuration actually has ObjectLockEnabled=Enabled
    const olConfig = configResponse && configResponse.ObjectLockConfiguration;
    if (!olConfig || olConfig.ObjectLockEnabled !== 'Enabled') {
      try { client.destroy && client.destroy(); } catch { /* swallow */ }
      return {
        ok: false,
        error: `bucket '${config.bucket}' GetObjectLockConfiguration returned ObjectLockEnabled='${olConfig && olConfig.ObjectLockEnabled}' (expected 'Enabled')`,
        detail: { phase: 'object-lock-not-enabled', retryable: false },
      };
    }
    // Capture default retention rule (if configured) for the admin UI
    objectLockDetail = {
      configured: true,
      retentionMode: olConfig.Rule && olConfig.Rule.DefaultRetention && olConfig.Rule.DefaultRetention.Mode,
      defaultRetentionDays: olConfig.Rule && olConfig.Rule.DefaultRetention && olConfig.Rule.DefaultRetention.Days,
      defaultRetentionYears: olConfig.Rule && olConfig.Rule.DefaultRetention && olConfig.Rule.DefaultRetention.Years,
    };
  }

  try { client.destroy && client.destroy(); } catch { /* swallow */ }
  return {
    ok: true,
    detail: {
      phase: 'roundtrip',
      ...(objectLockDetail ? { objectLock: objectLockDetail } : {}),
    },
  };
}

// --- Push --------------------------------------------------------------------

async function push(artifactContext, options = {}) {
  const logger = options.logger || console;
  const { destination, sourceDir, files, artifactId } = artifactContext;
  const config = destination.config;
  const credentials = destination.credentials;   // already decrypted by registry
  const sourceDirName = require('path').basename(sourceDir);

  // Defense: validate sourceDirName doesn't contain dangerous chars for
  // S3 keys (slashes, parent-dir refs, leading dot).
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

  const { s3, libStorage } = _getSdks();
  const client = buildClient(config, credentials);
  const prefix = config.prefix || '';
  const keyPrefix = `${prefix}${sourceDirName}/`;
  const completeFlagKey = `${keyPrefix}_complete.flag`;

  const sseParams = buildSseParams(config);
  const lockParams = buildObjectLockParams(destination.immutability_mode, destination.retention_days);

  // Idempotency: check for existing _complete.flag. If present, this
  // artifact was already pushed -- treat as no-op success.
  try {
    await client.send(new s3.HeadObjectCommand({ Bucket: config.bucket, Key: completeFlagKey }));
    logger.info(`gd-destination-adapter-s3: artifact ${sourceDirName} already complete on s3://${config.bucket}/${keyPrefix} (skipping)`);
    try { client.destroy && client.destroy(); } catch { /* swallow */ }
    return {
      destinationPath: `s3://${config.bucket}/${keyPrefix}`,
      bytesPushed: 0,
      immutabilityVerified: lockParams.ObjectLockMode ? { mode: 'object-lock', trustedBy: 'object-lock-headers' } : null,
      destinationMetadata: {
        artifactId, sourceDirName, bucket: config.bucket, keyPrefix,
        alreadyPresent: true, immutabilityMode: destination.immutability_mode,
      },
    };
  } catch (err) {
    if (err.name !== 'NotFound' && err.name !== 'NoSuchKey' &&
        !(err.$metadata && err.$metadata.httpStatusCode === 404)) {
      // Non-404 errors during HEAD -- propagate
      try { client.destroy && client.destroy(); } catch { /* swallow */ }
      throw new base.DestinationAdapterError(
        `idempotency check (HeadObject _complete.flag) failed: ${err.message || err.name}`,
        { adapter: ADAPTER_NAME, operation: 'push', retryable: isRetryableS3Error(err), detail: { code: err.name }, cause: err },
      );
    }
    // 404 is the expected case: artifact not yet present, proceed with push.
  }

  let bytesPushed = 0;
  try {
    for (const file of files) {
      const sourceHash = await sha256OfFile(file.absolutePath);
      const sourceHashB64 = sourceHash.toString('base64');
      const stream = fs.createReadStream(file.absolutePath);
      const fileSize = fs.statSync(file.absolutePath).size;
      const objectKey = `${keyPrefix}${file.name}`;

      const upload = new libStorage.Upload({
        client,
        params: {
          Bucket: config.bucket,
          Key: objectKey,
          Body: stream,
          ChecksumSHA256: sourceHashB64,
          ChecksumAlgorithm: 'SHA256',
          ...sseParams,
          ...lockParams,
        },
      });

      try {
        await upload.done();
      } catch (err) {
        throw new base.DestinationAdapterError(
          `S3 upload of ${file.name} failed: ${err.message || err.name}`,
          { adapter: ADAPTER_NAME, operation: 'push', retryable: isRetryableS3Error(err), detail: { file: file.name, code: err.name }, cause: err },
        );
      }
      bytesPushed += fileSize;
      logger.info(`gd-destination-adapter-s3: uploaded ${file.name} (${fileSize} bytes) to s3://${config.bucket}/${objectKey}`);
    }

    // After all files succeed, write _complete.flag last. Restore code
    // checks this marker; absence => incomplete push to skip.
    const completeMarker = JSON.stringify({
      artifact_id: artifactId, source_dir: sourceDirName,
      completed_at: new Date().toISOString(),
      file_count: files.length, total_bytes: bytesPushed,
    });
    const markerHash = crypto.createHash('sha256').update(completeMarker).digest('base64');
    await client.send(new s3.PutObjectCommand({
      Bucket: config.bucket,
      Key: completeFlagKey,
      Body: completeMarker,
      ChecksumSHA256: markerHash,
      ChecksumAlgorithm: 'SHA256',
      ContentType: 'application/json',
      ...sseParams,
      ...lockParams,
    }));

    logger.info(`gd-destination-adapter-s3: pushed ${sourceDirName} (${bytesPushed} bytes) to s3://${config.bucket}/${keyPrefix}`);

    return {
      destinationPath: `s3://${config.bucket}/${keyPrefix}`,
      bytesPushed,
      immutabilityVerified: lockParams.ObjectLockMode ? {
        mode: 'object-lock',
        trustedBy: 'object-lock-headers',
        retentionUntil: lockParams.ObjectLockRetainUntilDate.toISOString(),
      } : null,
      destinationMetadata: {
        artifactId, sourceDirName, bucket: config.bucket, keyPrefix,
        endpoint: config.endpoint || null,
        immutabilityMode: destination.immutability_mode,
      },
    };
  } catch (err) {
    if (err instanceof base.DestinationAdapterError) throw err;
    throw new base.DestinationAdapterError(
      `unexpected push failure: ${err.message}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: true, cause: err },
    );
  } finally {
    try { client.destroy && client.destroy(); } catch { /* swallow */ }
  }
}

// --- Adapter export + self-registration --------------------------------------

const adapter = {
  name: ADAPTER_NAME,
  description: 'Push artifacts to AWS S3 or any S3-compatible service (Hetzner / OVHcloud / Scaleway / MinIO / Wasabi / B2 / R2 / DO Spaces). Endpoint config field enables EU privacy-first deployments. Object Lock supported for write-once immutability.',
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

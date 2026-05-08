// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Google Cloud Storage Destination Adapter
//
// Pushes v2 backups to Google Cloud Storage using the @google-cloud/storage
// SDK. The SDK's Bucket.upload + File.save handle resumable uploads
// automatically for large files (the archive.tar.zst.enc).
//
// Final cloud destination adapter; AWS S3 (commit 10) + Azure Blob
// (commit 11) + GCS (this commit) round out the major-cloud coverage.
// EU privacy-first deployments use the S3 adapter with custom endpoint
// pointed at Hetzner / OVHcloud / Scaleway.
//
// AUTH MODES (simpler than Azure -- only two)
//
//   1. Service account JSON  { service_account_json: "..." | {...} }
//                              Same shape as the gcp-kms KEK provider
//                              (commit 8). Accepts the SA JSON either
//                              as a string (parseable) or as an object.
//                              Provider extracts client_email +
//                              private_key for the SDK's credentials
//                              option.
//
//   2. ADC                   null/empty -> Application Default
//                              Credentials. Tries:
//                              GOOGLE_APPLICATION_CREDENTIALS env var,
//                              GCE/GKE/Cloud Run metadata server,
//                              `gcloud auth application-default login`.
//                              Recommended for FireAlive-on-GCP -- no
//                              GCP secrets in FireAlive database.
//
// CONFIG SCHEMA
//
//   {
//     "project_id":   "firealive-prod-12345",      (required)
//     "bucket":       "firealive-backups",          (required)
//     "prefix":       "production/"                  (optional;
//                                                    trailing /,
//                                                    no leading /)
//   }
//
// project_id: GCP project ID hosting the bucket. Same pattern as
//             gcp-kms (6-30 lowercase chars, etc.).
//
// bucket:     GCS bucket name. GCS naming rules: 3-63 chars (without
//             periods; longer with periods up to 222); lowercase
//             letters, digits, dashes, underscores; must start and
//             end with letter or digit. Cannot contain 'goog' or
//             start with 'google'. We validate the simpler form
//             (3-63, no periods) which covers most operator use
//             cases. The SDK rejects malformed names at API time.
//
// prefix:     Optional path prefix inside the bucket (e.g.
//             "production/"). Same shape as S3 / Azure adapters.
//
// Note: NO region in config because GCS region is bucket-level (set
// at bucket creation by the operator), not a per-request parameter.
//
// OBJECT LAYOUT
//
//   gs://<bucket>/<prefix><sourceDirName>/
//     archive.tar.zst.enc
//     manifest.json
//     manifest.sig
//     wrapped-key.bin
//     _complete.flag       (written LAST; atomicity marker)
//
// _complete.flag pattern matches the S3 adapter (commit 10) and Azure
// Blob adapter (commit 11) for cross-cloud consistency.
//
// IMMUTABILITY VIA GCS OBJECT RETENTION
//
// supportedImmutabilityModes includes 'object-lock'. GCS Object
// Retention is the GCP analog to S3 Object Lock and Azure's
// immutable storage with versioning. When destination.immutability_mode
// = 'object-lock', the adapter sets a Locked per-object retention
// policy via file.setMetadata({ retention: { mode: 'Locked',
// retainUntilTime } }).
//
// REQUIREMENT: the bucket must have Object Retention Lock enabled at
// bucket creation time. Without this, per-object retention cannot be
// set. The probe (commit 13) verifies this with a HEAD-style check.
//
// Locked retention is permanent: once set, the retention period can
// only be EXTENDED, never shortened or removed. This is the desired
// posture for ransomware-protected backup archives.
//
// CHECKSUM VERIFICATION
//
// Every upload sets the md5Hash metadata; GCS verifies on receipt
// and rejects with 400 if the body doesn't match. (GCS also supports
// crc32c; we use md5 because it's simpler to compute and adequate for
// transit verification -- the actual cryptographic integrity is on
// the v2 archive's AES-GCM tag and the manifest signature.)
//
// SDK NOT YET INSTALLED
//
// @google-cloud/storage added to package.json in commit 23 (alongside
// the AWS S3 + Azure Blob SDKs). Until then, this module loads
// cleanly. Any push or probe call before commit 23 throws
// DestinationAdapterError with "npm install @google-cloud/storage"
// instruction. Existing local + sftp + s3 + azure-blob adapters
// continue working.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const base = require('./destination-adapter-base');

const ADAPTER_NAME = 'gcs';

const VALID_PROJECT_ID_PATTERN = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const VALID_BUCKET_PATTERN = /^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$/;
const VALID_PREFIX_PATTERN = /^([a-zA-Z0-9!_.*'()/\-]+\/)?$/;

// ── SDK loading (lazy + test-overridable) ─────────────────────────────────

let _sdkOverride = null;

function _setSdkForTest(sdk) {
  _sdkOverride = sdk;
}

function _getSdk() {
  if (_sdkOverride) return _sdkOverride;
  try {
    // eslint-disable-next-line global-require
    return require('@google-cloud/storage');
  } catch (err) {
    throw new base.DestinationAdapterError(
      "@google-cloud/storage not installed; run: npm install @google-cloud/storage",
      { adapter: ADAPTER_NAME, operation: 'sdk-load', retryable: false, cause: err },
    );
  }
}

// ── Retryable classification ──────────────────────────────────────────────
//
// GCS errors come through with .code (numeric HTTP status) and .errors.
// Some errors propagate from the underlying gax library with .code as
// gRPC numeric code. We classify both forms.

const RETRYABLE_GCS_HTTP_CODES = new Set([408, 429, 500, 502, 503, 504]);
const RETRYABLE_GRPC_CODES = new Set([1, 4, 8, 10, 13, 14]);
const PERMANENT_GRPC_CODES = new Set([3, 5, 6, 7, 9, 11, 12, 16]);

function isRetryableGcsError(err) {
  if (!err) return false;
  if (typeof err.code === 'number') {
    if (RETRYABLE_GCS_HTTP_CODES.has(err.code)) return true;
    if (err.code >= 500 && err.code < 600) return true;
    if (err.code >= 400 && err.code < 500) return false;
    if (RETRYABLE_GRPC_CODES.has(err.code)) return true;
    if (PERMANENT_GRPC_CODES.has(err.code)) return false;
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

  let r = base.requireString(config, 'project_id', { maxLength: 30, pattern: VALID_PROJECT_ID_PATTERN });
  if (!r.ok) return { ok: false, error: 'project_id must be 6-30 lowercase chars (letters, digits, dashes); start with letter, end with letter or digit', field: 'project_id' };

  r = base.requireString(config, 'bucket', { maxLength: 63, pattern: VALID_BUCKET_PATTERN });
  if (!r.ok) return { ok: false, error: 'bucket must be 3-63 lowercase chars (letters, digits, dashes, underscores); start and end with letter or digit', field: 'bucket' };

  // GCS naming restriction: cannot contain 'goog' or start with 'google'
  if (config.bucket.includes('goog') || config.bucket.startsWith('google')) {
    return { ok: false, error: 'bucket name cannot contain "goog" or start with "google" (GCS naming restriction)', field: 'bucket' };
  }

  if (config.prefix !== undefined && config.prefix !== null && config.prefix !== '') {
    if (typeof config.prefix !== 'string' || !VALID_PREFIX_PATTERN.test(config.prefix)) {
      return { ok: false, error: 'prefix must be empty or end with /, no leading slash', field: 'prefix' };
    }
  }

  const allowed = new Set(['project_id', 'bucket', 'prefix']);
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

  if (credentials.service_account_json === undefined || credentials.service_account_json === null) {
    return { ok: false, error: 'service_account_json required (or omit credentials entirely for ADC)', field: 'service_account_json' };
  }

  let parsed;
  if (typeof credentials.service_account_json === 'string') {
    try { parsed = JSON.parse(credentials.service_account_json); }
    catch (err) {
      return { ok: false, error: `service_account_json is not valid JSON: ${err.message}`, field: 'service_account_json' };
    }
  } else if (typeof credentials.service_account_json === 'object' && !Array.isArray(credentials.service_account_json)) {
    parsed = credentials.service_account_json;
  } else {
    return { ok: false, error: 'service_account_json must be a JSON string or object', field: 'service_account_json' };
  }

  if (typeof parsed.client_email !== 'string' || parsed.client_email === '') {
    return { ok: false, error: 'service_account_json.client_email required', field: 'service_account_json' };
  }
  if (typeof parsed.private_key !== 'string' || !parsed.private_key.includes('PRIVATE KEY')) {
    return { ok: false, error: 'service_account_json.private_key required (PEM PKCS#8)', field: 'service_account_json' };
  }
  if (parsed.type && parsed.type !== 'service_account') {
    return { ok: false, error: `service_account_json.type must be 'service_account' (got '${parsed.type}')`, field: 'service_account_json' };
  }

  const allowed = new Set(['service_account_json']);
  for (const k of Object.keys(credentials)) {
    if (!allowed.has(k)) {
      return { ok: false, error: `unexpected field in credentials: ${k}`, field: k };
    }
  }
  return { ok: true };
}

// ── Client construction ──────────────────────────────────────────────────

function parseServiceAccountJson(credentials) {
  if (!credentials || typeof credentials !== 'object' || Object.keys(credentials).length === 0) {
    return null;
  }
  const sa = credentials.service_account_json;
  if (typeof sa === 'string') return JSON.parse(sa);
  return sa;
}

function buildClient(config, credentials) {
  const sdk = _getSdk();
  const sa = parseServiceAccountJson(credentials);
  const clientOptions = { projectId: config.project_id };
  if (sa) {
    clientOptions.credentials = {
      client_email: sa.client_email,
      private_key: sa.private_key,
    };
  }
  return new sdk.Storage(clientOptions);
}

function buildRetentionMetadata(immutabilityMode, retentionDays) {
  if (immutabilityMode !== 'object-lock') return null;
  const days = (typeof retentionDays === 'number' && retentionDays >= 1) ? retentionDays : 30;
  return {
    mode: 'Locked',
    retainUntilTime: new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString(),
  };
}

function md5OfFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('md5');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (c) => hash.update(c));
    stream.on('end', () => resolve(hash.digest('base64')));
    stream.on('error', reject);
  });
}

// ── Probe ────────────────────────────────────────────────────────────────

async function probe(config, credentials, options = {}) {
  const cv = validateConfig(config);
  if (!cv.ok) return { ok: false, error: cv.error, detail: { field: cv.field, phase: 'config' } };
  const cre = validateCredentials(credentials);
  if (!cre.ok) return { ok: false, error: cre.error, detail: { field: cre.field, phase: 'credentials' } };

  let storage;
  try {
    storage = buildClient(config, credentials);
  } catch (err) {
    return { ok: false, error: `client construction failed: ${err.message}`, detail: { phase: 'client' } };
  }

  const bucket = storage.bucket(config.bucket);
  const probeName = `${config.prefix || ''}.firealive-probe-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const probeContent = crypto.randomBytes(64);
  const file = bucket.file(probeName);

  try {
    await file.save(probeContent, {
      metadata: {
        md5Hash: crypto.createHash('md5').update(probeContent).digest('base64'),
      },
    });
  } catch (err) {
    return { ok: false, error: `probe upload failed: ${err.message}`, detail: { phase: 'put', code: err.code, retryable: isRetryableGcsError(err) } };
  }
  try {
    await file.download();
  } catch (err) {
    return { ok: false, error: `probe download failed: ${err.message}`, detail: { phase: 'get', code: err.code } };
  }
  try {
    await file.delete();
  } catch {
    // Probe object not deleted -- non-fatal
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

  const storage = buildClient(config, credentials);
  const bucket = storage.bucket(config.bucket);
  const prefix = config.prefix || '';
  const objectPrefix = `${prefix}${sourceDirName}/`;
  const completeFlagName = `${objectPrefix}_complete.flag`;

  const retentionMetadata = buildRetentionMetadata(destination.immutability_mode, destination.retention_days);

  // Idempotency: check for existing _complete.flag
  try {
    const flagFile = bucket.file(completeFlagName);
    const [exists] = await flagFile.exists();
    if (exists) {
      logger.info(`destination-adapter-gcs: backup ${sourceDirName} already complete on gs://${config.bucket}/${objectPrefix} (skipping)`);
      return {
        destinationPath: `gs://${config.bucket}/${objectPrefix}`,
        bytesPushed: 0,
        immutabilityVerified: retentionMetadata ? { mode: 'object-lock', trustedBy: 'gcs-object-retention' } : null,
        destinationMetadata: {
          backupId, sourceDirName,
          bucket: config.bucket, objectPrefix,
          alreadyPresent: true,
          immutabilityMode: destination.immutability_mode,
        },
      };
    }
  } catch (err) {
    throw new base.DestinationAdapterError(
      `idempotency check failed: ${err.message}`,
      { adapter: ADAPTER_NAME, operation: 'push', retryable: isRetryableGcsError(err), detail: { code: err.code }, cause: err },
    );
  }

  let bytesPushed = 0;
  try {
    for (const file of files) {
      const objectName = `${objectPrefix}${file.name}`;
      const gcsFile = bucket.file(objectName);
      const fileSize = fs.statSync(file.absolutePath).size;
      const md5Hash = await md5OfFile(file.absolutePath);

      const saveOptions = {
        metadata: {
          md5Hash,
          contentType: 'application/octet-stream',
        },
        resumable: true,   // SDK auto-resumable for files > 5MB
      };
      if (retentionMetadata) {
        saveOptions.metadata.retention = retentionMetadata;
      }

      try {
        // Use createWriteStream for streaming the file in (avoids loading
        // the entire archive into memory for large files).
        await new Promise((resolve, reject) => {
          const writeStream = gcsFile.createWriteStream(saveOptions);
          fs.createReadStream(file.absolutePath)
            .on('error', reject)
            .pipe(writeStream)
            .on('error', reject)
            .on('finish', resolve);
        });
      } catch (err) {
        throw new base.DestinationAdapterError(
          `GCS upload of ${file.name} failed: ${err.message}`,
          { adapter: ADAPTER_NAME, operation: 'push', retryable: isRetryableGcsError(err), detail: { file: file.name, code: err.code }, cause: err },
        );
      }
      bytesPushed += fileSize;
      logger.info(`destination-adapter-gcs: uploaded ${file.name} (${fileSize} bytes) to gs://${config.bucket}/${objectName}`);
    }

    // _complete.flag last
    const completeMarker = JSON.stringify({
      backup_id: backupId, source_dir: sourceDirName,
      completed_at: new Date().toISOString(),
      file_count: files.length, total_bytes: bytesPushed,
    });
    const completeMd5 = crypto.createHash('md5').update(completeMarker).digest('base64');
    const flagFile = bucket.file(completeFlagName);
    const flagOptions = {
      metadata: {
        md5Hash: completeMd5,
        contentType: 'application/json',
      },
    };
    if (retentionMetadata) {
      flagOptions.metadata.retention = retentionMetadata;
    }
    await flagFile.save(completeMarker, flagOptions);

    logger.info(`destination-adapter-gcs: pushed ${sourceDirName} (${bytesPushed} bytes) to gs://${config.bucket}/${objectPrefix}`);

    return {
      destinationPath: `gs://${config.bucket}/${objectPrefix}`,
      bytesPushed,
      immutabilityVerified: retentionMetadata ? {
        mode: 'object-lock',
        trustedBy: 'gcs-object-retention',
        retentionUntil: retentionMetadata.retainUntilTime,
      } : null,
      destinationMetadata: {
        backupId, sourceDirName,
        bucket: config.bucket, objectPrefix,
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
  description: 'Push backups to Google Cloud Storage via @google-cloud/storage. Supports service account JSON or Application Default Credentials. Object Lock equivalent via GCS Object Retention (Locked).',
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

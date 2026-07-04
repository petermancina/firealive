// ===============================================================================
// FIREALIVE -- External Restore: AWS S3 Source Adapter (v2 directory layout)
//
// Source adapter for the External Restore feature. Operates on the v2
// directory-layout contract (see nas.js for the canonical contract
// documentation; identical for all 5 source adapters): each backup is
// a "folder" (S3 key prefix) named firealive-backup-<iso-ts>/
// containing 4 objects (archive.tar.zst.enc, wrapped-key.bin,
// manifest.json, manifest.sig).
//
// CONTRACT (shared across all 5 source adapters)
//
//   listBackups(ctx)                  -> { backups: [{ id, modifiedAt,
//                                                       sizeBytes }] }
//   fetchFile(ctx, backupId, name)    -> Buffer
//   verifyStructure(ctx, backupId)    -> { ok, missing[], present[],
//                                           totalSizeBytes }
//
//   Crypto verification (Ed25519 sig + file SHA-256s) happens in the
//   orchestrator (services/external-restore.js, commit 8), not the
//   adapter -- adapters are pure I/O.
//
// IMPLEMENTATION NOTES
//
// This adapter speaks raw AWS S3 over HTTPS using SigV4 request signing
// and the built-in node:https client -- no @aws-sdk/* dependency.
// Rationale (unchanged from v1):
//
//   1. The 15 malware-scanner integrations in server/services/
//      malware-scanners/ all use built-in https + crypto for the same
//      reason (avoid pulling large vendor SDKs into a tool that has to
//      deploy widely). External Restore should match that pattern.
//   2. The S3 surface this adapter needs is small -- ListObjectsV2 and
//      GET object. Implementing SigV4 for these two operations is well
//      understood, security-auditable, and small.
//   3. Smaller deploy footprint matters for SOC environments that
//      bundle FireAlive into restricted Docker images.
//
// SigV4 implementation reference:
//   https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
//
// CREDENTIALS SHAPE on a source row (after Tier-1 decryption):
//
//   {
//     "region":          "us-east-2",            // required
//     "bucket":          "firealive-backups",    // required
//     "accessKeyId":     "AKIA...",              // required
//     "secretAccessKey": "wJalrXUtnFEMI...",     // required
//     "sessionToken":    "FwoGZXIvYXdzEKb..."    // optional (STS)
//   }
//
// PATH on a source row is the key prefix WITHIN the bucket where backups
// live -- e.g. "mc-prod/backups/" or just "" for the bucket root.
// Trailing slash is added if missing. Backup IDs are FOLDER names
// matching BACKUP_FOLDER_RE; full S3 key for a file is
// `${prefix}${backupId}/${filename}`.
//
// S3-compatible storage (MinIO, Wasabi, Backblaze B2 with S3 API) is
// NOT supported in this canonical adapter -- only AWS S3 itself. The
// allow-list permits only `*.amazonaws.com` so even a misconfigured
// credential blob can't pivot to an arbitrary host. A future extension
// can add an `endpoint` field; v1.0.30 ships AWS-only.
//
// AGPL-3.0-or-later
// ===============================================================================

const https = require('https');
const crypto = require('crypto');
const { validateAllowedHost } = require('../gd-external-restore-allow-list');

// -- Shared adapter constants -------------------------------------------------

const BACKUP_FOLDER_RE = /^firealive-backup-\d{8}T\d{6}Z$/;

const BACKUP_FILE_NAMES = Object.freeze([
  'archive.tar.zst.enc',
  'wrapped-key.bin',
  'manifest.json',
  'manifest.sig',
]);
const BACKUP_FILE_NAMES_SET = new Set(BACKUP_FILE_NAMES);

const MAX_BACKUP_SIZE_BYTES = 8 * 1024 * 1024 * 1024;  // 8 GB
const MAX_MANIFEST_BYTES = 1 * 1024 * 1024;            // 1 MB

const SIGV4_ALGORITHM = 'AWS4-HMAC-SHA256';
const SERVICE_NAME = 's3';
const SIGNED_HEADERS_LIST = 'host;x-amz-content-sha256;x-amz-date';
const REQUEST_TIMEOUT_MS = 60000;        // 60s for ListObjectsV2 / small GETs
const FETCH_TIMEOUT_MS   = 600000;       // 10min for archive downloads

// -- SigV4 signing helpers (UNCHANGED from v1) ----------------------------

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function deriveSigningKey(secretAccessKey, dateStamp, region, service) {
  const kDate    = hmacSha256('AWS4' + secretAccessKey, dateStamp);
  const kRegion  = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, 'aws4_request');
  return kSigning;
}

function awsTimestamp() {
  return new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function uriEncodePath(p) {
  return p.split('/').map(seg =>
    seg.replace(/[^A-Za-z0-9\-._~]/g, c =>
      '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')
    )
  ).join('/');
}

function uriEncodeQueryValue(v) {
  return String(v).replace(/[^A-Za-z0-9\-._~]/g, c =>
    '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')
  );
}

function canonicalQueryString(params) {
  const keys = Object.keys(params).sort();
  return keys.map(k => `${uriEncodeQueryValue(k)}=${uriEncodeQueryValue(params[k])}`).join('&');
}

function signRequest({ method, host, canonicalUri, queryParams, region, accessKeyId, secretAccessKey, sessionToken, payloadHash }) {
  const amzDate = awsTimestamp();
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${region}/${SERVICE_NAME}/aws4_request`;
  const canonicalQs = canonicalQueryString(queryParams || {});

  const canonicalHeaders =
    `host:${host}\n` +
    `x-amz-content-sha256:${payloadHash}\n` +
    `x-amz-date:${amzDate}\n`;

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQs,
    canonicalHeaders,
    SIGNED_HEADERS_LIST,
    payloadHash,
  ].join('\n');

  const stringToSign = [
    SIGV4_ALGORITHM,
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  const signingKey = deriveSigningKey(secretAccessKey, dateStamp, region, SERVICE_NAME);
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  const authorization =
    `${SIGV4_ALGORITHM} Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${SIGNED_HEADERS_LIST}, ` +
    `Signature=${signature}`;

  return {
    authorization,
    amzDate,
    payloadHash,
    sessionToken: sessionToken || null,
  };
}

/**
 * Make a signed S3 request. For non-stream mode, buffers the response
 * body up to maxBytes and rejects if the body exceeds that. For stream
 * mode (used internally for verifyStructure / archive fetches), returns
 * { stream } and lets the caller bound size.
 */
function s3Request(opts, stream) {
  const {
    method, host, path: reqPath, queryParams,
    region, accessKeyId, secretAccessKey, sessionToken,
    timeoutMs, maxBytes,
  } = opts;
  const sizeCap = typeof maxBytes === 'number' && maxBytes > 0
    ? maxBytes : MAX_BACKUP_SIZE_BYTES;

  const allowed = validateAllowedHost(host);
  if (!allowed.ok) {
    return Promise.reject(new Error(`outbound host ${host} rejected: ${allowed.error}`));
  }

  const payloadHash = sha256Hex('');  // GET requests have empty body
  const sig = signRequest({
    method, host, canonicalUri: reqPath,
    queryParams, region, accessKeyId, secretAccessKey, sessionToken,
    payloadHash,
  });

  const headers = {
    'Host': host,
    'x-amz-content-sha256': sig.payloadHash,
    'x-amz-date': sig.amzDate,
    'Authorization': sig.authorization,
  };
  if (sig.sessionToken) headers['x-amz-security-token'] = sig.sessionToken;

  const qs = canonicalQueryString(queryParams || {});
  const url = `https://${host}${reqPath}${qs ? '?' + qs : ''}`;

  return new Promise((resolve, reject) => {
    const req = https.request(url, { method, headers, timeout: timeoutMs }, (res) => {
      if (stream) {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          let buf = '';
          res.setEncoding('utf8');
          res.on('data', (c) => { if (buf.length < 4096) buf += c; });
          res.on('end', () => reject(new Error(`s3 ${method} ${reqPath} -> ${res.statusCode}: ${buf.slice(0, 500)}`)));
          return;
        }
        return resolve({ statusCode: res.statusCode, headers: res.headers, stream: res });
      }
      const chunks = [];
      let totalBytes = 0;
      let aborted = false;
      res.on('data', (c) => {
        if (aborted) return;
        totalBytes += c.length;
        if (totalBytes > sizeCap) {
          aborted = true;
          req.destroy(new Error(`response body exceeded ${sizeCap} bytes`));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        if (aborted) return;
        const body = Buffer.concat(chunks);
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ statusCode: res.statusCode, headers: res.headers, body });
        } else {
          reject(new Error(`s3 ${method} ${reqPath} -> ${res.statusCode}: ${body.toString('utf8').slice(0, 500)}`));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`s3 ${method} ${reqPath} timed out after ${timeoutMs}ms`)));
    req.end();
  });
}

// -- Helpers ---------------------------------------------------------------

function virtualHostedHost(bucket, region) {
  return `${bucket}.s3.${region}.amazonaws.com`;
}

function normalizePrefix(rawPath) {
  let p = String(rawPath || '').replace(/^\/+/, '');
  if (p && !p.endsWith('/')) p += '/';
  return p;
}

function validateCredentials(creds) {
  if (!creds || typeof creds !== 'object') {
    throw new Error('credentials missing or not an object');
  }
  for (const k of ['region', 'bucket', 'accessKeyId', 'secretAccessKey']) {
    if (typeof creds[k] !== 'string' || !creds[k].trim()) {
      throw new Error(`credentials.${k} required`);
    }
  }
  if (!/^[a-z0-9-]+$/.test(creds.region)) {
    throw new Error(`credentials.region '${creds.region}' is not a valid AWS region name`);
  }
  if (!/^[a-z0-9.\-]{3,63}$/.test(creds.bucket)) {
    throw new Error(`credentials.bucket '${creds.bucket}' is not a valid S3 bucket name`);
  }
}

function validateBackupId(backupId) {
  if (typeof backupId !== 'string' || !BACKUP_FOLDER_RE.test(backupId)) {
    throw new Error(`backupId '${backupId}' is not a valid v2 backup folder name`);
  }
}

function validateFilename(filename) {
  if (typeof filename !== 'string' || !BACKUP_FILE_NAMES_SET.has(filename)) {
    throw new Error(
      `filename '${filename}' is not one of the expected v2 backup files: ` +
      BACKUP_FILE_NAMES.join(', '),
    );
  }
}

function parseListObjectsV2Xml(xml) {
  const objects = [];
  const re = /<Contents>([\s\S]*?)<\/Contents>/g;
  let match;
  while ((match = re.exec(xml)) !== null) {
    const inner = match[1];
    const get = (tag) => {
      const m = inner.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
      return m ? m[1] : null;
    };
    objects.push({
      key: get('Key'),
      size: parseInt(get('Size') || '0', 10),
      lastModified: get('LastModified'),
      etag: (get('ETag') || '').replace(/^"|"$/g, ''),
    });
  }
  const truncatedM = xml.match(/<IsTruncated>([^<]*)<\/IsTruncated>/);
  const truncated = truncatedM ? truncatedM[1] === 'true' : false;
  const nextTokenM = xml.match(/<NextContinuationToken>([^<]*)<\/NextContinuationToken>/);
  return {
    objects,
    isTruncated: truncated,
    nextContinuationToken: nextTokenM ? nextTokenM[1] : null,
  };
}

/**
 * Run a paginated ListObjectsV2 call and return all objects under a
 * given key prefix. Caps at 50 pages (50000 objects) to bound a runaway
 * bucket. Each paginated call is a separate signed request.
 */
async function listAllObjects(creds, host, keyPrefix) {
  const collected = [];
  let continuationToken = null;
  for (let page = 0; page < 50; page++) {
    const queryParams = { 'list-type': '2', 'max-keys': '1000', prefix: keyPrefix };
    if (continuationToken) queryParams['continuation-token'] = continuationToken;

    const result = await s3Request({
      method: 'GET',
      host,
      path: '/',
      queryParams,
      region: creds.region,
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      sessionToken: creds.sessionToken,
      timeoutMs: REQUEST_TIMEOUT_MS,
      maxBytes: 16 * 1024 * 1024,  // ListObjectsV2 XML capped at 16 MB
    });

    const xml = result.body.toString('utf8');
    const parsed = parseListObjectsV2Xml(xml);
    for (const obj of parsed.objects) collected.push(obj);
    if (!parsed.isTruncated || !parsed.nextContinuationToken) break;
    continuationToken = parsed.nextContinuationToken;
  }
  return collected;
}

/**
 * Group flat object list by folder. Given a key like
 * `<prefix><folderName>/<filename>`, extract folderName + filename and
 * group. Objects whose key shape doesn't match the v2 folder/file
 * convention are silently skipped. Returns Map<folderName, {
 * present[], totalSize, manifestLastModified }>.
 */
function groupObjectsByFolder(objects, keyPrefix) {
  const folders = new Map();
  for (const obj of objects) {
    const key = obj.key || '';
    if (keyPrefix && !key.startsWith(keyPrefix)) continue;
    const rel = key.slice(keyPrefix.length);
    const slashIdx = rel.indexOf('/');
    if (slashIdx <= 0) continue;  // not folder-shaped
    const folderName = rel.slice(0, slashIdx);
    const filename = rel.slice(slashIdx + 1);
    if (!BACKUP_FOLDER_RE.test(folderName)) continue;
    if (!BACKUP_FILE_NAMES_SET.has(filename)) continue;
    if (filename.includes('/')) continue;  // nested object in folder

    let entry = folders.get(folderName);
    if (!entry) {
      entry = { present: [], totalSize: 0, manifestLastModified: null };
      folders.set(folderName, entry);
    }
    entry.present.push(filename);
    entry.totalSize += obj.size || 0;
    if (filename === 'manifest.json') {
      entry.manifestLastModified = obj.lastModified;
    }
  }
  return folders;
}

// -- Adapter API -----------------------------------------------------------

/**
 * List all v2 backup folders in the source's bucket+prefix. Strategy:
 * one paginated ListObjectsV2 over the prefix (typically 1 page since
 * 4 files * dozens of backups < 1000 keys per page); group resulting
 * objects by folder; emit only folders that have all 4 expected files.
 *
 * Round trips: ceil(total_objects / 1000), typically 1 for SOC-shop
 * scale.
 */
async function listBackups(ctx) {
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = virtualHostedHost(creds.bucket, creds.region);

  const allObjects = await listAllObjects(creds, host, prefix);
  const folders = groupObjectsByFolder(allObjects, prefix);

  const backups = [];
  let skippedPartial = 0;
  for (const [folderName, info] of folders.entries()) {
    const presentSet = new Set(info.present);
    const missing = BACKUP_FILE_NAMES.filter(n => !presentSet.has(n));
    if (missing.length > 0) {
      skippedPartial += 1;
      ctx.log('warn', 'listBackups: skipping partial backup folder', {
        backupId: folderName, missing,
      });
      continue;
    }
    backups.push({
      id: folderName,
      modifiedAt: info.manifestLastModified,
      sizeBytes: info.totalSize,
    });
  }

  backups.sort((a, b) => (b.modifiedAt || '').localeCompare(a.modifiedAt || ''));
  ctx.log('info', 'listBackups completed', {
    bucket: creds.bucket, prefix, count: backups.length, skippedPartial,
  });
  return { backups };
}

/**
 * Fetch one named file from a v2 backup folder. Constructs the full S3
 * key as `${prefix}${backupId}/${filename}` and issues a GET object.
 * Manifest-vs-archive size limit selection.
 */
async function fetchFile(ctx, backupId, filename) {
  validateBackupId(backupId);
  validateFilename(filename);
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = virtualHostedHost(creds.bucket, creds.region);
  const key = `${prefix}${backupId}/${filename}`;
  const reqPath = '/' + uriEncodePath(key);

  const isManifestFile = filename === 'manifest.json' || filename === 'manifest.sig';
  const sizeLimit = isManifestFile ? MAX_MANIFEST_BYTES : MAX_BACKUP_SIZE_BYTES;
  const timeoutMs = isManifestFile ? REQUEST_TIMEOUT_MS : FETCH_TIMEOUT_MS;

  const result = await s3Request({
    method: 'GET',
    host,
    path: reqPath,
    queryParams: {},
    region: creds.region,
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    sessionToken: creds.sessionToken,
    timeoutMs,
    maxBytes: sizeLimit,
  });

  ctx.log('info', 'fetchFile completed', {
    backupId, filename, sizeBytes: result.body.length,
  });
  return result.body;
}

/**
 * Lightweight structural check: ListObjectsV2 with prefix
 * `${prefix}${backupId}/` enumerates the (up to 4) objects in the
 * folder. Confirms all 4 expected files are present and reports their
 * sizes. NO crypto -- the orchestrator handles Ed25519 sig + SHA-256
 * verification.
 */
async function verifyStructure(ctx, backupId) {
  validateBackupId(backupId);
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = virtualHostedHost(creds.bucket, creds.region);
  const folderPrefix = `${prefix}${backupId}/`;

  const allObjects = await listAllObjects(creds, host, folderPrefix);
  const folders = groupObjectsByFolder(allObjects, prefix);
  const info = folders.get(backupId);

  if (!info) {
    ctx.log('warn', 'verifyStructure: folder has no recognized files', { backupId });
    return {
      ok: false,
      present: [],
      missing: [...BACKUP_FILE_NAMES],
      totalSizeBytes: 0,
    };
  }

  const presentSet = new Set(info.present);
  const missing = BACKUP_FILE_NAMES.filter(n => !presentSet.has(n));
  const result = {
    ok: missing.length === 0,
    present: info.present,
    missing,
    totalSizeBytes: info.totalSize,
  };
  ctx.log('info', 'verifyStructure completed', {
    backupId, ok: result.ok, missingCount: missing.length,
  });
  return result;
}

// -- Module exports --------------------------------------------------------

module.exports = {
  listBackups,
  fetchFile,
  verifyStructure,

  // Constants exposed for orchestrator + tests
  BACKUP_FOLDER_RE,
  BACKUP_FILE_NAMES,
  MAX_BACKUP_SIZE_BYTES,
  MAX_MANIFEST_BYTES,

  // Internal helpers exposed for tests only
  _internal: {
    sha256Hex, hmacSha256, deriveSigningKey, awsTimestamp,
    uriEncodePath, uriEncodeQueryValue, canonicalQueryString,
    signRequest, virtualHostedHost, normalizePrefix,
    validateCredentials, validateBackupId, validateFilename,
    parseListObjectsV2Xml, listAllObjects, groupObjectsByFolder,
    s3Request,
  },
};

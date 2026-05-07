// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — External Restore: AWS S3 Source Adapter
//
// Third of five source adapters for the External Restore feature.
// Operates on the listBackups / fetchBackup / verifyIntegrity contract
// shared with the other adapters in this directory; see network-share.js
// (commit 4) for the full adapter API documentation.
//
// ═══════════════════════════════════════════════════════════════════════════════
//
// IMPLEMENTATION NOTES
//
// This adapter speaks raw AWS S3 over HTTPS using SigV4 request signing
// and the built-in node:https client — no @aws-sdk/* dependency.
// Rationale:
//
//   1. The 15 malware-scanner integrations in server/services/malware-scanners/
//      all use built-in https + crypto for the same reason (avoid pulling
//      large vendor SDKs into a tool that has to deploy widely). External
//      Restore should match that pattern for consistency.
//
//   2. The S3 surface this adapter needs is tiny — just GET ListObjectsV2
//      and GET object. Implementing SigV4 for these two operations is
//      ~150 lines, well documented, and easier to security-audit than
//      pulling in tens of thousands of lines of SDK code.
//
//   3. Smaller deploy footprint matters for SOC environments that bundle
//      FireAlive into restricted Docker images.
//
// SigV4 implementation reference:
//   https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
//
// CREDENTIALS SHAPE on a source row (the credentials_encrypted blob,
// after Tier-1 decryption by the orchestrator):
//
//   {
//     "region":          "us-east-2",            // required
//     "bucket":          "firealive-backups",    // required
//     "accessKeyId":     "AKIA...",              // required
//     "secretAccessKey": "wJalrXUtnFEMI...",     // required
//     "sessionToken":    "FwoGZXIvYXdzEKb..."    // optional — STS sessions
//   }
//
// PATH on a source row is the key prefix WITHIN the bucket where backups
// live — e.g. "mc-prod/backups/" or just "" for the bucket root. Trailing
// slash is added if missing. Backup IDs are filenames RELATIVE to the
// prefix; full S3 key is `${prefix}${backupId}`.
//
// S3-compatible storage (MinIO, Wasabi, Backblaze B2 with S3 API) is NOT
// supported in this canonical adapter — only AWS S3 itself. A future
// extension can add an `endpoint` field to credentials and override the
// virtual-hosted host construction below. v1.0.30 ships AWS-only; the
// allow-list does NOT permit endpoints other than `*.amazonaws.com` so
// even a misconfigured credential blob can't pivot to an arbitrary host.
// ═══════════════════════════════════════════════════════════════════════════════

const https = require('https');
const crypto = require('crypto');
const { validateAllowedHost } = require('../external-restore-allow-list');

const SIGV4_ALGORITHM = 'AWS4-HMAC-SHA256';
const SERVICE_NAME = 's3';
const SIGNED_HEADERS_LIST = 'host;x-amz-content-sha256;x-amz-date';
const REQUEST_TIMEOUT_MS = 60000;        // 60s for ListObjectsV2 and small GETs
const FETCH_TIMEOUT_MS   = 600000;       // 10min for full backup downloads
const MAX_BACKUP_SIZE_BYTES = 8 * 1024 * 1024 * 1024;  // 8 GB matches network-share.js
const BACKUP_FILENAME_RE = /^[A-Za-z0-9_\-]{1,80}-\d{8}T\d{6}Z\.tar\.gz(?:\.enc)?$/;

// ── SigV4 signing helpers ─────────────────────────────────────────────────

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
  // YYYYMMDDTHHMMSSZ format with no separators
  return new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

/**
 * URI-encode the path component for SigV4 canonical request. AWS docs
 * specify: encode every byte except A-Z, a-z, 0-9, '-', '.', '_', '~'.
 * Forward slash is NOT encoded for S3 keys (we keep '/').
 */
function uriEncodePath(p) {
  return p.split('/').map(seg =>
    seg.replace(/[^A-Za-z0-9\-._~]/g, c =>
      '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')
    )
  ).join('/');
}

/**
 * URI-encode a query string value. Same rules as uriEncodePath but '/'
 * IS encoded here.
 */
function uriEncodeQueryValue(v) {
  return String(v).replace(/[^A-Za-z0-9\-._~]/g, c =>
    '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')
  );
}

/**
 * Build the canonical query string from an object. Keys are sorted
 * lexicographically; both keys and values are URI-encoded.
 */
function canonicalQueryString(params) {
  const keys = Object.keys(params).sort();
  return keys.map(k => `${uriEncodeQueryValue(k)}=${uriEncodeQueryValue(params[k])}`).join('&');
}

/**
 * Sign a SigV4 request. Returns the Authorization header value plus
 * the x-amz-date and x-amz-content-sha256 headers that need to be
 * included on the actual request.
 */
function signRequest({ method, host, canonicalUri, queryParams, region, accessKeyId, secretAccessKey, sessionToken, payloadHash }) {
  const amzDate = awsTimestamp();
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${region}/${SERVICE_NAME}/aws4_request`;
  const canonicalQs = canonicalQueryString(queryParams || {});

  // Canonical headers MUST be sorted by header name (lowercase).
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
 * Make a signed S3 request. Returns { statusCode, body, headers } on
 * 2xx; throws on transport errors or non-2xx (with body included in
 * the error message for diagnostics).
 *
 * stream === true returns a passthrough stream of the response body
 * instead of buffering it (used by fetchBackup and verifyIntegrity to
 * cap memory).
 */
function s3Request({ method, host, path, queryParams, region, accessKeyId, secretAccessKey, sessionToken, timeoutMs }, stream) {
  // SSRF allow-list check at every outbound call (defense in depth).
  const allowed = validateAllowedHost(host);
  if (!allowed.ok) {
    return Promise.reject(new Error(`outbound host ${host} rejected: ${allowed.error}`));
  }

  const payloadHash = sha256Hex('');  // GET requests have empty body
  const sig = signRequest({
    method, host, canonicalUri: path,
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
  const url = `https://${host}${path}${qs ? '?' + qs : ''}`;

  return new Promise((resolve, reject) => {
    const req = https.request(url, { method, headers, timeout: timeoutMs }, (res) => {
      if (stream) {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          // Read the error body for diagnostics, then reject
          let buf = '';
          res.setEncoding('utf8');
          res.on('data', (c) => { if (buf.length < 4096) buf += c; });
          res.on('end', () => reject(new Error(`s3 ${method} ${path} -> ${res.statusCode}: ${buf.slice(0, 500)}`)));
          return;
        }
        return resolve({ statusCode: res.statusCode, headers: res.headers, stream: res });
      }
      const chunks = [];
      let totalBytes = 0;
      res.on('data', (c) => {
        totalBytes += c.length;
        if (totalBytes > MAX_BACKUP_SIZE_BYTES) {
          req.destroy(new Error('response body exceeded MAX_BACKUP_SIZE_BYTES'));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ statusCode: res.statusCode, headers: res.headers, body });
        } else {
          reject(new Error(`s3 ${method} ${path} -> ${res.statusCode}: ${body.toString('utf8').slice(0, 500)}`));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`s3 ${method} ${path} timed out after ${timeoutMs}ms`)));
    req.end();
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────

function virtualHostedHost(bucket, region) {
  // Virtual-hosted-style URL is the modern recommended form. The path-style
  // form (s3.region.amazonaws.com/bucket) is being deprecated by AWS.
  return `${bucket}.s3.${region}.amazonaws.com`;
}

/**
 * Normalize the source's path field into a key prefix:
 *   - Strip leading slash (S3 keys never start with '/')
 *   - Add trailing slash if missing and prefix is non-empty
 *   - Empty prefix ('') means "list at the bucket root"
 */
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

function parseListObjectsV2Xml(xml) {
  // Minimal XML parser tailored to ListObjectsV2 response. Avoids
  // pulling in xml2js or a full XML parser dependency. Handles only
  // the fields we care about: Key, Size, LastModified, ETag,
  // IsTruncated, NextContinuationToken.
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

// ── Adapter API ───────────────────────────────────────────────────────────

async function listBackups(ctx) {
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = virtualHostedHost(creds.bucket, creds.region);

  const collected = [];
  let continuationToken = null;
  // Cap continuation iterations so a misconfigured bucket can't loop
  // the lead's UI forever. 50 pages * 1000 objects = 50000 max enumerated.
  for (let page = 0; page < 50; page++) {
    const queryParams = { 'list-type': '2', 'max-keys': '1000', prefix };
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
    });

    const xml = result.body.toString('utf8');
    const parsed = parseListObjectsV2Xml(xml);
    for (const obj of parsed.objects) {
      // Strip prefix to get the relative backup id (filename)
      const rel = prefix && obj.key.startsWith(prefix) ? obj.key.slice(prefix.length) : obj.key;
      if (!rel || rel.includes('/')) continue;  // skip nested objects
      if (!BACKUP_FILENAME_RE.test(rel)) continue;
      collected.push({
        id: rel,
        filename: rel,
        sizeBytes: obj.size,
        modifiedAt: obj.lastModified,
        etag: obj.etag,
      });
    }
    if (!parsed.isTruncated || !parsed.nextContinuationToken) break;
    continuationToken = parsed.nextContinuationToken;
  }

  collected.sort((a, b) => (b.modifiedAt || '').localeCompare(a.modifiedAt || ''));
  ctx.log('info', 'listBackups completed', { bucket: creds.bucket, prefix, count: collected.length });
  return { backups: collected };
}

async function fetchBackup(ctx, backupId) {
  if (!BACKUP_FILENAME_RE.test(backupId)) {
    throw new Error(`backupId '${backupId}' is not a valid FireAlive backup filename`);
  }
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = virtualHostedHost(creds.bucket, creds.region);
  const key = prefix + backupId;
  const path = '/' + uriEncodePath(key);

  const result = await s3Request({
    method: 'GET',
    host,
    path,
    queryParams: {},
    region: creds.region,
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    sessionToken: creds.sessionToken,
    timeoutMs: FETCH_TIMEOUT_MS,
  });

  ctx.log('info', 'fetchBackup completed', { backupId, sizeBytes: result.body.length });
  return result.body;
}

async function verifyIntegrity(ctx, backupId, opts = {}) {
  if (!BACKUP_FILENAME_RE.test(backupId)) {
    throw new Error(`backupId '${backupId}' is not a valid FireAlive backup filename`);
  }
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = virtualHostedHost(creds.bucket, creds.region);
  const key = prefix + backupId;
  const path = '/' + uriEncodePath(key);

  // Stream the object through SHA-256 to avoid buffering the whole
  // archive into memory just to hash it.
  const result = await s3Request({
    method: 'GET',
    host,
    path,
    queryParams: {},
    region: creds.region,
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    sessionToken: creds.sessionToken,
    timeoutMs: FETCH_TIMEOUT_MS,
  }, /* stream */ true);

  const hash = crypto.createHash('sha256');
  let sizeBytes = 0;
  await new Promise((resolve, reject) => {
    result.stream.on('data', (chunk) => {
      hash.update(chunk);
      sizeBytes += chunk.length;
      if (sizeBytes > MAX_BACKUP_SIZE_BYTES) {
        result.stream.destroy(new Error('object exceeds MAX_BACKUP_SIZE_BYTES'));
      }
    });
    result.stream.on('end', resolve);
    result.stream.on('error', reject);
  });
  const sha256 = hash.digest('hex');

  const out = {
    ok: !opts.expectedSha256 || (sha256 === opts.expectedSha256),
    sha256,
    sizeBytes,
  };
  if (opts.expectedSha256) out.expectedSha256 = opts.expectedSha256;
  ctx.log('info', 'verifyIntegrity completed', { backupId, sha256: sha256.slice(0, 12) + '...', ok: out.ok });
  return out;
}

module.exports = { listBackups, fetchBackup, verifyIntegrity };

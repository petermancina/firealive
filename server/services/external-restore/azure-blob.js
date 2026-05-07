// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — External Restore: Azure Blob Storage Source Adapter
//
// Fourth of five source adapters for the External Restore feature.
// Operates on the listBackups / fetchBackup / verifyIntegrity contract
// shared with the other adapters in this directory; see network-share.js
// (commit 4) for the full adapter API documentation.
//
// ═══════════════════════════════════════════════════════════════════════════════
//
// IMPLEMENTATION NOTES
//
// Speaks raw Azure Blob Storage REST API over HTTPS using the built-in
// node:https client and either Shared Key signing or SAS-token URLs —
// no @azure/* SDK dependency. Same rationale as the S3 adapter
// (commit 6): the malware-scanner integrations all use built-in https,
// and the surface needed here is small (List Blobs + Get Blob).
//
// Azure Shared Key signing reference:
//   https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
//
// Azure SAS reference:
//   https://learn.microsoft.com/en-us/rest/api/storageservices/delegate-access-with-shared-access-signature
//
// CREDENTIALS SHAPE on a source row (decrypted by the orchestrator):
//
//   Shared Key auth:
//     {
//       "accountName":   "firealivebackups",       // required
//       "accountKey":    "AbCdEf...",              // base64-encoded; required (or sasToken)
//       "containerName": "mc-prod-backups"         // required
//     }
//
//   SAS Token auth:
//     {
//       "accountName":   "firealivebackups",       // required
//       "sasToken":      "?sv=2024-01-...&sig=...", // required (or accountKey)
//       "containerName": "mc-prod-backups"         // required
//     }
//
// Either accountKey OR sasToken is required, not both. Shared Key gives
// full account-level access; SAS tokens are scoped (preferred for least-
// privilege deployments). Per-source choice — leads can configure
// separate sources with different auth modes side-by-side.
//
// PATH on a source row is the prefix WITHIN the container where backups
// live (e.g. "mc-prod/backups/" or "" for container root).
// ═══════════════════════════════════════════════════════════════════════════════

const https = require('https');
const crypto = require('crypto');
const { validateAllowedHost } = require('../external-restore-allow-list');

const REQUEST_TIMEOUT_MS = 60000;
const FETCH_TIMEOUT_MS   = 600000;
const MAX_BACKUP_SIZE_BYTES = 8 * 1024 * 1024 * 1024;  // 8 GB
const BACKUP_FILENAME_RE = /^[A-Za-z0-9_\-]{1,80}-\d{8}T\d{6}Z\.tar\.gz(?:\.enc)?$/;
const X_MS_VERSION = '2023-11-03';  // pinned for stability

// ── Shared Key signing ────────────────────────────────────────────────────

/**
 * Sign an Azure Blob request using Shared Key.
 *
 * The canonical request format is documented at
 * https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
 *
 * String to sign (literal newlines between every field):
 *   VERB \n
 *   Content-Encoding \n
 *   Content-Language \n
 *   Content-Length (empty if zero) \n
 *   Content-MD5 \n
 *   Content-Type \n
 *   Date (empty when x-ms-date is used) \n
 *   If-Modified-Since \n
 *   If-Match \n
 *   If-None-Match \n
 *   If-Unmodified-Since \n
 *   Range \n
 *   CanonicalizedHeaders \n
 *   CanonicalizedResource
 *
 * For our GET-only requests every conditional/content header is empty.
 */
function signSharedKey({ method, accountName, accountKey, urlPath, queryParams, xmsDate }) {
  const canonicalizedHeaders =
    `x-ms-date:${xmsDate}\n` +
    `x-ms-version:${X_MS_VERSION}`;

  // CanonicalizedResource format:
  //   /<accountname><urlpath>\n
  //   <param-name>:<value-1>,<value-2>,...
  //   (sorted lex by param name; values comma-joined if duplicated)
  const sortedParams = Object.keys(queryParams || {}).sort();
  const paramLines = sortedParams.map(k => {
    const v = queryParams[k];
    const values = Array.isArray(v) ? v.slice().sort() : [v];
    return `${k.toLowerCase()}:${values.join(',')}`;
  });
  const canonicalizedResource = `/${accountName}${urlPath}` +
    (paramLines.length ? '\n' + paramLines.join('\n') : '');

  const stringToSign = [
    method.toUpperCase(),
    '',  // Content-Encoding
    '',  // Content-Language
    '',  // Content-Length (empty for GET)
    '',  // Content-MD5
    '',  // Content-Type
    '',  // Date (using x-ms-date instead)
    '',  // If-Modified-Since
    '',  // If-Match
    '',  // If-None-Match
    '',  // If-Unmodified-Since
    '',  // Range
    canonicalizedHeaders,
    canonicalizedResource,
  ].join('\n');

  const keyBytes = Buffer.from(accountKey, 'base64');
  const signature = crypto.createHmac('sha256', keyBytes).update(stringToSign, 'utf8').digest('base64');
  return `SharedKey ${accountName}:${signature}`;
}

// ── HTTPS request helper ──────────────────────────────────────────────────

function buildBlobHost(accountName) {
  return `${accountName}.blob.core.windows.net`;
}

/**
 * Make a signed Azure Blob request. Returns { statusCode, body, headers }
 * or { statusCode, headers, stream } when stream=true. Throws on
 * transport errors or non-2xx.
 */
function azureRequest({ method, host, urlPath, queryParams, accountName, accountKey, sasToken, timeoutMs }, stream) {
  const allowed = validateAllowedHost(host);
  if (!allowed.ok) {
    return Promise.reject(new Error(`outbound host ${host} rejected: ${allowed.error}`));
  }

  const xmsDate = new Date().toUTCString();

  // Build the request URL. SAS-token auth appends the token to the
  // query string; Shared Key auth uses the Authorization header.
  let qsParts = [];
  for (const [k, v] of Object.entries(queryParams || {})) {
    if (Array.isArray(v)) {
      for (const vi of v) qsParts.push(`${encodeURIComponent(k)}=${encodeURIComponent(vi)}`);
    } else {
      qsParts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
  }

  let urlSuffix = qsParts.length ? '?' + qsParts.join('&') : '';
  const headers = {
    'Host': host,
    'x-ms-date': xmsDate,
    'x-ms-version': X_MS_VERSION,
  };
  if (accountKey) {
    headers['Authorization'] = signSharedKey({
      method, accountName, accountKey, urlPath, queryParams, xmsDate,
    });
  } else if (sasToken) {
    // SAS tokens already contain `?sv=...&sig=...`. Strip leading '?' if
    // present so we can compose with our own query string.
    const sasClean = sasToken.startsWith('?') ? sasToken.slice(1) : sasToken;
    urlSuffix = urlSuffix ? urlSuffix + '&' + sasClean : '?' + sasClean;
  } else {
    return Promise.reject(new Error('azure adapter: neither accountKey nor sasToken provided'));
  }

  const url = `https://${host}${urlPath}${urlSuffix}`;

  return new Promise((resolve, reject) => {
    const req = https.request(url, { method, headers, timeout: timeoutMs }, (res) => {
      if (stream) {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          let buf = '';
          res.setEncoding('utf8');
          res.on('data', (c) => { if (buf.length < 4096) buf += c; });
          res.on('end', () => reject(new Error(`azure ${method} ${urlPath} -> ${res.statusCode}: ${buf.slice(0, 500)}`)));
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
          reject(new Error(`azure ${method} ${urlPath} -> ${res.statusCode}: ${body.toString('utf8').slice(0, 500)}`));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`azure ${method} ${urlPath} timed out after ${timeoutMs}ms`)));
    req.end();
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────

function validateCredentials(creds) {
  if (!creds || typeof creds !== 'object') {
    throw new Error('credentials missing or not an object');
  }
  for (const k of ['accountName', 'containerName']) {
    if (typeof creds[k] !== 'string' || !creds[k].trim()) {
      throw new Error(`credentials.${k} required`);
    }
  }
  if (!creds.accountKey && !creds.sasToken) {
    throw new Error('credentials must include either accountKey or sasToken');
  }
  if (creds.accountKey && creds.sasToken) {
    throw new Error('credentials must include accountKey OR sasToken, not both');
  }
  if (!/^[a-z0-9]{3,24}$/.test(creds.accountName)) {
    throw new Error(`credentials.accountName '${creds.accountName}' is not a valid Azure storage account name (3-24 lowercase alphanumeric)`);
  }
  if (!/^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$/.test(creds.containerName)) {
    throw new Error(`credentials.containerName '${creds.containerName}' is not a valid Azure container name`);
  }
  if (creds.accountKey) {
    // Account keys are base64-encoded 64-byte secrets — 88 base64 chars.
    if (!/^[A-Za-z0-9+/=]{40,200}$/.test(creds.accountKey)) {
      throw new Error('credentials.accountKey does not look like a base64-encoded Azure storage account key');
    }
  }
}

function normalizePrefix(rawPath) {
  let p = String(rawPath || '').replace(/^\/+/, '');
  if (p && !p.endsWith('/')) p += '/';
  return p;
}

function uriEncodePath(p) {
  return p.split('/').map(seg =>
    seg.replace(/[^A-Za-z0-9\-._~]/g, c =>
      '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')
    )
  ).join('/');
}

/**
 * Minimal XML parser for Azure's List Blobs response.
 * Handles only the fields we need:
 *   <Blob><Name>...</Name><Properties><Content-Length>...</Content-Length>
 *     <Last-Modified>...</Last-Modified><Etag>...</Etag></Properties></Blob>
 *   <NextMarker>...</NextMarker>
 */
function parseListBlobsXml(xml) {
  const blobs = [];
  const re = /<Blob>([\s\S]*?)<\/Blob>/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const inner = m[1];
    const get = (tag) => {
      const r = inner.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
      return r ? r[1] : null;
    };
    blobs.push({
      name: get('Name'),
      contentLength: parseInt(get('Content-Length') || '0', 10),
      lastModified: get('Last-Modified'),
      etag: (get('Etag') || '').replace(/^"|"$/g, ''),
    });
  }
  const nextMarkerM = xml.match(/<NextMarker>([^<]*)<\/NextMarker>/);
  return {
    blobs,
    nextMarker: nextMarkerM && nextMarkerM[1] ? nextMarkerM[1] : null,
  };
}

// ── Adapter API ───────────────────────────────────────────────────────────

async function listBackups(ctx) {
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = buildBlobHost(creds.accountName);
  const containerPath = `/${creds.containerName}`;

  const collected = [];
  let marker = null;
  // Cap continuations like the S3 adapter — Azure default page size is
  // 5000 max; 50 pages = 250000 max enumerated.
  for (let page = 0; page < 50; page++) {
    const queryParams = {
      'restype': 'container',
      'comp': 'list',
      'prefix': prefix,
      'maxresults': '5000',
    };
    if (marker) queryParams['marker'] = marker;

    const result = await azureRequest({
      method: 'GET',
      host,
      urlPath: containerPath,
      queryParams,
      accountName: creds.accountName,
      accountKey: creds.accountKey,
      sasToken: creds.sasToken,
      timeoutMs: REQUEST_TIMEOUT_MS,
    });

    const xml = result.body.toString('utf8');
    const parsed = parseListBlobsXml(xml);
    for (const b of parsed.blobs) {
      const rel = prefix && b.name.startsWith(prefix) ? b.name.slice(prefix.length) : b.name;
      if (!rel || rel.includes('/')) continue;  // skip nested
      if (!BACKUP_FILENAME_RE.test(rel)) continue;
      collected.push({
        id: rel,
        filename: rel,
        sizeBytes: b.contentLength,
        modifiedAt: b.lastModified ? new Date(b.lastModified).toISOString() : null,
        etag: b.etag,
      });
    }
    if (!parsed.nextMarker) break;
    marker = parsed.nextMarker;
  }

  collected.sort((a, b) => (b.modifiedAt || '').localeCompare(a.modifiedAt || ''));
  ctx.log('info', 'listBackups completed', { account: creds.accountName, container: creds.containerName, prefix, count: collected.length });
  return { backups: collected };
}

async function fetchBackup(ctx, backupId) {
  if (!BACKUP_FILENAME_RE.test(backupId)) {
    throw new Error(`backupId '${backupId}' is not a valid FireAlive backup filename`);
  }
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = buildBlobHost(creds.accountName);
  const blobPath = `/${creds.containerName}/${uriEncodePath(prefix + backupId)}`;

  const result = await azureRequest({
    method: 'GET',
    host,
    urlPath: blobPath,
    queryParams: {},
    accountName: creds.accountName,
    accountKey: creds.accountKey,
    sasToken: creds.sasToken,
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
  const host = buildBlobHost(creds.accountName);
  const blobPath = `/${creds.containerName}/${uriEncodePath(prefix + backupId)}`;

  const result = await azureRequest({
    method: 'GET',
    host,
    urlPath: blobPath,
    queryParams: {},
    accountName: creds.accountName,
    accountKey: creds.accountKey,
    sasToken: creds.sasToken,
    timeoutMs: FETCH_TIMEOUT_MS,
  }, /* stream */ true);

  const hash = crypto.createHash('sha256');
  let sizeBytes = 0;
  await new Promise((resolve, reject) => {
    result.stream.on('data', (chunk) => {
      hash.update(chunk);
      sizeBytes += chunk.length;
      if (sizeBytes > MAX_BACKUP_SIZE_BYTES) {
        result.stream.destroy(new Error('blob exceeds MAX_BACKUP_SIZE_BYTES'));
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

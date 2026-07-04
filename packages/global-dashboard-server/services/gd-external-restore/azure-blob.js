// ===============================================================================
// FIREALIVE -- External Restore: Azure Blob Source Adapter (v2 directory layout)
//
// Source adapter for the External Restore feature. Operates on the v2
// directory-layout contract (see nas.js for the canonical contract
// documentation; identical for all 5 source adapters): each backup is
// a "folder" (Azure blob name prefix) firealive-backup-<iso-ts>/
// containing 4 blobs (archive.tar.zst.enc, wrapped-key.bin,
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
// Speaks raw Azure Blob Storage REST API over HTTPS using the built-in
// node:https client and either Shared Key signing or SAS-token URLs --
// no @azure/* SDK dependency. Same rationale as the S3 adapter
// (commit 6): malware-scanner integrations all use built-in https,
// and the surface needed here is small (List Blobs + Get Blob).
//
// Azure Shared Key signing reference:
//   https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
//
// Azure SAS reference:
//   https://learn.microsoft.com/en-us/rest/api/storageservices/delegate-access-with-shared-access-signature
//
// CREDENTIALS SHAPE on a source row (after Tier-1 decryption):
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
// full account-level access; SAS tokens are scoped (preferred for
// least-privilege deployments). Per-source choice -- leads can configure
// separate sources with different auth modes side-by-side.
//
// PATH on a source row is the prefix WITHIN the container where backups
// live -- e.g. "mc-prod/backups/" or "" for container root. Trailing
// slash is added if missing. Backup IDs are FOLDER names matching
// BACKUP_FOLDER_RE; full blob name for a file is
// `${prefix}${backupId}/${filename}`.
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

const REQUEST_TIMEOUT_MS = 60000;
const FETCH_TIMEOUT_MS   = 600000;
const X_MS_VERSION = '2023-11-03';  // pinned for stability

// -- Shared Key signing (UNCHANGED from v1) -------------------------------

/**
 * Sign an Azure Blob request using Shared Key.
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

// -- HTTPS request helper --------------------------------------------------

function buildBlobHost(accountName) {
  return `${accountName}.blob.core.windows.net`;
}

/**
 * Make a signed Azure Blob request. Returns { statusCode, body, headers }
 * or { statusCode, headers, stream } when stream=true. Throws on
 * transport errors or non-2xx.
 *
 * Optional maxBytes parameter caps the buffered response size on a
 * per-call basis (List Blobs vs file fetch have different bounds).
 */
function azureRequest(opts, stream) {
  const {
    method, host, urlPath, queryParams,
    accountName, accountKey, sasToken,
    timeoutMs, maxBytes,
  } = opts;
  const sizeCap = typeof maxBytes === 'number' && maxBytes > 0
    ? maxBytes : MAX_BACKUP_SIZE_BYTES;

  const allowed = validateAllowedHost(host);
  if (!allowed.ok) {
    return Promise.reject(new Error(`outbound host ${host} rejected: ${allowed.error}`));
  }

  const xmsDate = new Date().toUTCString();

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
          reject(new Error(`azure ${method} ${urlPath} -> ${res.statusCode}: ${body.toString('utf8').slice(0, 500)}`));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`azure ${method} ${urlPath} timed out after ${timeoutMs}ms`)));
    req.end();
  });
}

// -- Helpers ---------------------------------------------------------------

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
    if (!/^[A-Za-z0-9+/=]{40,200}$/.test(creds.accountKey)) {
      throw new Error('credentials.accountKey does not look like a base64-encoded Azure storage account key');
    }
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

/**
 * Run a paginated List Blobs call and return all blobs under a given
 * blob-name prefix. Caps at 50 pages to bound a runaway container.
 * Each paginated call is a separate signed request.
 */
async function listAllBlobs(creds, host, blobPrefix) {
  const containerPath = `/${creds.containerName}`;
  const collected = [];
  let marker = null;
  for (let page = 0; page < 50; page++) {
    const queryParams = {
      'restype': 'container',
      'comp': 'list',
      'prefix': blobPrefix,
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
      maxBytes: 16 * 1024 * 1024,  // List Blobs XML capped at 16 MB
    });

    const xml = result.body.toString('utf8');
    const parsed = parseListBlobsXml(xml);
    for (const b of parsed.blobs) collected.push(b);
    if (!parsed.nextMarker) break;
    marker = parsed.nextMarker;
  }
  return collected;
}

/**
 * Group flat blob list by folder. Given a blob name like
 * `<prefix><folderName>/<filename>`, extract folderName + filename and
 * group. Blobs whose name shape doesn't match the v2 folder/file
 * convention are silently skipped. Returns Map<folderName, {
 * present[], totalSize, manifestLastModified }>.
 */
function groupBlobsByFolder(blobs, blobPrefix) {
  const folders = new Map();
  for (const b of blobs) {
    const name = b.name || '';
    if (blobPrefix && !name.startsWith(blobPrefix)) continue;
    const rel = name.slice(blobPrefix.length);
    const slashIdx = rel.indexOf('/');
    if (slashIdx <= 0) continue;
    const folderName = rel.slice(0, slashIdx);
    const filename = rel.slice(slashIdx + 1);
    if (!BACKUP_FOLDER_RE.test(folderName)) continue;
    if (!BACKUP_FILE_NAMES_SET.has(filename)) continue;
    if (filename.includes('/')) continue;

    let entry = folders.get(folderName);
    if (!entry) {
      entry = { present: [], totalSize: 0, manifestLastModified: null };
      folders.set(folderName, entry);
    }
    entry.present.push(filename);
    entry.totalSize += b.contentLength || 0;
    if (filename === 'manifest.json') {
      entry.manifestLastModified = b.lastModified
        ? new Date(b.lastModified).toISOString()
        : null;
    }
  }
  return folders;
}

// -- Adapter API -----------------------------------------------------------

/**
 * List all v2 backup folders in the source's container+prefix. Strategy:
 * one paginated List Blobs over the prefix; group resulting blobs by
 * folder; emit only folders that have all 4 expected files. Round
 * trips: ceil(total_blobs / 5000), typically 1 at SOC-shop scale.
 */
async function listBackups(ctx) {
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = buildBlobHost(creds.accountName);

  const allBlobs = await listAllBlobs(creds, host, prefix);
  const folders = groupBlobsByFolder(allBlobs, prefix);

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
    account: creds.accountName, container: creds.containerName,
    prefix, count: backups.length, skippedPartial,
  });
  return { backups };
}

/**
 * Fetch one named blob from a v2 backup folder. Constructs the full
 * blob name as `${prefix}${backupId}/${filename}` and issues a GET.
 * Manifest-vs-archive size limit selection.
 */
async function fetchFile(ctx, backupId, filename) {
  validateBackupId(backupId);
  validateFilename(filename);
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = buildBlobHost(creds.accountName);
  const blobName = `${prefix}${backupId}/${filename}`;
  const blobPath = `/${creds.containerName}/${uriEncodePath(blobName)}`;

  const isManifestFile = filename === 'manifest.json' || filename === 'manifest.sig';
  const sizeLimit = isManifestFile ? MAX_MANIFEST_BYTES : MAX_BACKUP_SIZE_BYTES;
  const timeoutMs = isManifestFile ? REQUEST_TIMEOUT_MS : FETCH_TIMEOUT_MS;

  const result = await azureRequest({
    method: 'GET',
    host,
    urlPath: blobPath,
    queryParams: {},
    accountName: creds.accountName,
    accountKey: creds.accountKey,
    sasToken: creds.sasToken,
    timeoutMs,
    maxBytes: sizeLimit,
  });

  ctx.log('info', 'fetchFile completed', {
    backupId, filename, sizeBytes: result.body.length,
  });
  return result.body;
}

/**
 * Lightweight structural check: List Blobs with prefix
 * `${prefix}${backupId}/` enumerates the (up to 4) blobs in the
 * folder. Returns presence + size summary. NO crypto -- the
 * orchestrator handles Ed25519 sig + file SHA-256 verification.
 */
async function verifyStructure(ctx, backupId) {
  validateBackupId(backupId);
  const creds = ctx.config.credentials;
  validateCredentials(creds);
  const prefix = normalizePrefix(ctx.config.path);
  const host = buildBlobHost(creds.accountName);
  const folderPrefix = `${prefix}${backupId}/`;

  const allBlobs = await listAllBlobs(creds, host, folderPrefix);
  const folders = groupBlobsByFolder(allBlobs, prefix);
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
    signSharedKey, buildBlobHost, validateCredentials,
    validateBackupId, validateFilename, normalizePrefix,
    uriEncodePath, parseListBlobsXml, listAllBlobs,
    groupBlobsByFolder, azureRequest,
  },
};

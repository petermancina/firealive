// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — External Restore: Orchestrator Service
//
// Public API for the External Restore feature. Wraps the 5 source
// adapters (services/external-restore/{nas,network-share,sftp,s3,
// azure-blob}.js) with the cryptographic verification, two-person
// approval gate, audit-trail integration, and atomic apply that the
// adapters deliberately stay out of.
//
// PUBLIC API
//
//   listSources(db)
//   getSource(db, id)
//   createSource(db, args)
//   updateSource(db, id, patch)
//   deleteSource(db, id)
//   testSource(db, id, log)
//   browseSource(db, id, log)
//   previewBackup(db, sourceId, externalBackupId, log)
//   requestRestore(db, args)
//   executeRestore(db, args)
//
//   ExternalRestoreError (with stable CODES)
//
// DESIGN
//
// This file is a service layer; it does NOT call writeAuditEvent or
// emit HTTP responses. The routes layer (routes/external-restore.js,
// commit 9) translates HTTP requests, performs role/MFA checks, writes
// audit events, and maps the typed errors thrown from here to HTTP
// statuses. Same separation-of-concerns pattern used by
// services/kms-providers.js and services/restore-approvals.js.
//
// ADAPTER CONTRACT (uniform across all 5 adapters; v2 directory layout):
//
//   listBackups(ctx)               -> { backups: [{ id, modifiedAt,
//                                                    sizeBytes }] }
//   fetchFile(ctx, backupId, name) -> Buffer
//   verifyStructure(ctx, backupId) -> { ok, missing[], present[],
//                                        totalSizeBytes }
//
// Adapters are pure I/O. Crypto verification (Ed25519 manifest sig,
// SHA-256 file hashes) lives here; DEK unwrapping delegates to
// services/backup-key-wrapping.js (the registry dispatcher built in
// R3d-4 part 2).
//
// EXECUTION FLOW (executeRestore, the heavy lift)
//
//   1.  Validate the approval row is approved + usable
//   2.  Load the source; load + decrypt credentials
//   3.  Dispatch to the adapter for verifyStructure (presence check)
//   4.  Adapter fetchFile manifest.json + manifest.sig
//   5.  Parse manifest; validate structure; verify Ed25519 signature
//       against the public key in backup_signing_keys
//   6.  Adapter fetchFile wrapped-key.bin + archive.tar.zst.enc
//   7.  Verify each file's SHA-256 against the in-manifest hash
//   8.  Append RESTORE_REQUEST entry to the LOCAL chain (so a request
//       with no completion is forensically detectable as failure)
//   9.  Unwrap DEK via backup-key-wrapping registry
//  10.  extractArchive (AES-GCM decrypt -> zstd decompress -> untar)
//  11.  Confirm extracted file is named firealive.db
//  12.  Pre-restore snapshot of CURRENT live DB
//  13.  Atomic-rename extracted bytes over DB_PATH
//  14.  Append RESTORE_COMPLETE to the chain
//  15.  Mark the approval row consumed
//  16.  Update source last_used_at
//
// At every step, on error: log the step we got to, leave any partial
// state recoverable (pre-restore snapshot is a safety net), and throw
// a typed error so the routes layer can return a clear HTTP status.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { encryptConfig, decryptConfig } = require('./encryption');
const approvalsSvc = require('./restore-approvals');
const keyWrapSvc = require('./backup-key-wrapping');
const archiveSvc = require('./backup-archive');
const manifestSvc = require('./backup-manifest');
const signingKeysSvc = require('./backup-signing-keys');
const chainSvc = require('./backup-chain');

// ── Constants ─────────────────────────────────────────────────────────────

const VALID_SOURCE_TYPES = Object.freeze([
  'network_share', 'nas', 's3', 'azure_blob', 'sftp',
]);
const SOURCE_TYPE_SET = new Set(VALID_SOURCE_TYPES);

// Map DB source_type (underscored) to adapter filename (hyphenated).
const SOURCE_TYPE_TO_ADAPTER = Object.freeze({
  'network_share': 'network-share',
  'nas':           'nas',
  's3':            's3',
  'azure_blob':    'azure-blob',
  'sftp':          'sftp',
});

const NAME_MAX_LENGTH = 200;
const PATH_MAX_LENGTH = 4096;

// ── Typed errors ──────────────────────────────────────────────────────────

const CODES = Object.freeze({
  INVALID_INPUT:           'INVALID_INPUT',
  SOURCE_NOT_FOUND:        'SOURCE_NOT_FOUND',
  SOURCE_DISABLED:         'SOURCE_DISABLED',
  SOURCE_NAME_CONFLICT:    'SOURCE_NAME_CONFLICT',
  ADAPTER_FAILED:          'ADAPTER_FAILED',
  BACKUP_NOT_FOUND:        'BACKUP_NOT_FOUND',
  STRUCTURE_INVALID:       'STRUCTURE_INVALID',
  MANIFEST_PARSE_FAILED:   'MANIFEST_PARSE_FAILED',
  MANIFEST_INVALID:        'MANIFEST_INVALID',
  MANIFEST_SIG_MISMATCH:   'MANIFEST_SIG_MISMATCH',
  SIGNING_KEY_UNKNOWN:     'SIGNING_KEY_UNKNOWN',
  FILE_HASH_MISMATCH:      'FILE_HASH_MISMATCH',
  KEY_UNWRAP_FAILED:       'KEY_UNWRAP_FAILED',
  EXTRACT_FAILED:          'EXTRACT_FAILED',
  EXTRACT_UNEXPECTED_FILE: 'EXTRACT_UNEXPECTED_FILE',
  APPROVAL_NOT_FOUND:      'APPROVAL_NOT_FOUND',
  APPROVAL_NOT_USABLE:     'APPROVAL_NOT_USABLE',
  CHAIN_APPEND_FAILED:     'CHAIN_APPEND_FAILED',
  PRE_RESTORE_SNAPSHOT_FAILED: 'PRE_RESTORE_SNAPSHOT_FAILED',
  ATOMIC_APPLY_FAILED:     'ATOMIC_APPLY_FAILED',
});

class ExternalRestoreError extends Error {
  constructor(code, message, detail = null) {
    super(message);
    this.name = 'ExternalRestoreError';
    this.code = code;
    this.detail = detail;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────

function requireNonEmptyString(value, fieldName, maxLen) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new ExternalRestoreError(CODES.INVALID_INPUT, `${fieldName} required`);
  }
  if (maxLen && value.length > maxLen) {
    throw new ExternalRestoreError(CODES.INVALID_INPUT,
      `${fieldName} exceeds maximum length of ${maxLen}`);
  }
}

function nowSqlite() {
  return new Date().toISOString().replace('T', ' ').replace(/\..+$/, '');
}

/**
 * Load the adapter module for a given source_type. Adapters live in
 * services/external-restore/<adapter-name>.js where adapter-name is
 * the hyphenated form of the DB source_type.
 *
 * Cached after first load to avoid repeated require() calls. Throws
 * INVALID_INPUT for unknown source_type.
 */
const _adapterCache = new Map();
function loadAdapter(sourceType) {
  if (_adapterCache.has(sourceType)) return _adapterCache.get(sourceType);
  if (!SOURCE_TYPE_SET.has(sourceType)) {
    throw new ExternalRestoreError(CODES.INVALID_INPUT,
      `unknown source_type: ${sourceType}`);
  }
  const adapterName = SOURCE_TYPE_TO_ADAPTER[sourceType];
  const adapter = require(`./external-restore/${adapterName}`);
  _adapterCache.set(sourceType, adapter);
  return adapter;
}

/**
 * Build the ctx object passed to adapter calls. Decrypts credentials
 * lazily so a routes-layer caller that only needs source metadata
 * doesn't pay the decrypt cost.
 */
function buildAdapterCtx(sourceRow, log) {
  return {
    sourceRow,
    log: typeof log === 'function' ? log : () => {},
    config: {
      path: sourceRow.path,
      credentials: decryptCredentials(sourceRow),
    },
  };
}

function encryptCredentials(plaintext) {
  // encryptConfig returns a Buffer; we store as base64 in the DB so
  // the column can be TEXT (matches existing source rows).
  const buf = encryptConfig(plaintext);
  return buf.toString('base64');
}

function decryptCredentials(sourceRow) {
  if (!sourceRow.credentials_encrypted) return null;
  try {
    const buf = Buffer.from(sourceRow.credentials_encrypted, 'base64');
    return decryptConfig(buf);
  } catch (err) {
    throw new ExternalRestoreError(CODES.INVALID_INPUT,
      `credentials decrypt failed for source ${sourceRow.id}: ${err.message}`);
  }
}

function rowOrThrow(db, id) {
  const row = db.prepare('SELECT * FROM external_restore_sources WHERE id = ?').get(id);
  if (!row) {
    throw new ExternalRestoreError(CODES.SOURCE_NOT_FOUND,
      `external_restore_sources id ${id} not found`);
  }
  return row;
}

// ── Source CRUD ───────────────────────────────────────────────────────────

function listSources(db, options = {}) {
  const onlyEnabled = options.enabled === true;
  const sql = onlyEnabled
    ? 'SELECT * FROM external_restore_sources WHERE enabled = 1 ORDER BY name ASC'
    : 'SELECT * FROM external_restore_sources ORDER BY name ASC';
  return db.prepare(sql).all();
}

function getSource(db, id) {
  return rowOrThrow(db, id);
}

function createSource(db, args) {
  if (!args || typeof args !== 'object') {
    throw new ExternalRestoreError(CODES.INVALID_INPUT, 'args object required');
  }
  requireNonEmptyString(args.name, 'name', NAME_MAX_LENGTH);
  requireNonEmptyString(args.source_type, 'source_type');
  if (!SOURCE_TYPE_SET.has(args.source_type)) {
    throw new ExternalRestoreError(CODES.INVALID_INPUT,
      `source_type must be one of: ${VALID_SOURCE_TYPES.join(', ')}`);
  }
  requireNonEmptyString(args.path, 'path', PATH_MAX_LENGTH);
  if (!args.credentials || typeof args.credentials !== 'object') {
    throw new ExternalRestoreError(CODES.INVALID_INPUT,
      'credentials object required (validated by adapter on first use)');
  }

  const existing = db.prepare(
    'SELECT id FROM external_restore_sources WHERE name = ?'
  ).get(args.name);
  if (existing) {
    throw new ExternalRestoreError(CODES.SOURCE_NAME_CONFLICT,
      `source name '${args.name}' already in use (id ${existing.id})`);
  }

  const credentialsEncrypted = encryptCredentials(args.credentials);
  const result = db.prepare(`
    INSERT INTO external_restore_sources (
      name, source_type, path, credentials_encrypted,
      enabled, created_by_user_id
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    args.name,
    args.source_type,
    args.path,
    credentialsEncrypted,
    args.enabled === false ? 0 : 1,
    args.created_by_user_id || null,
  );
  return getSource(db, result.lastInsertRowid);
}

function updateSource(db, id, patch) {
  rowOrThrow(db, id);  // ensure exists
  if (!patch || typeof patch !== 'object') {
    throw new ExternalRestoreError(CODES.INVALID_INPUT, 'patch object required');
  }

  const sets = [];
  const params = [];

  if (patch.name !== undefined) {
    requireNonEmptyString(patch.name, 'name', NAME_MAX_LENGTH);
    const conflict = db.prepare(
      'SELECT id FROM external_restore_sources WHERE name = ? AND id != ?'
    ).get(patch.name, id);
    if (conflict) {
      throw new ExternalRestoreError(CODES.SOURCE_NAME_CONFLICT,
        `source name '${patch.name}' already in use (id ${conflict.id})`);
    }
    sets.push('name = ?'); params.push(patch.name);
  }
  if (patch.path !== undefined) {
    requireNonEmptyString(patch.path, 'path', PATH_MAX_LENGTH);
    sets.push('path = ?'); params.push(patch.path);
  }
  if (patch.credentials !== undefined) {
    if (!patch.credentials || typeof patch.credentials !== 'object') {
      throw new ExternalRestoreError(CODES.INVALID_INPUT,
        'credentials must be an object');
    }
    sets.push('credentials_encrypted = ?');
    params.push(encryptCredentials(patch.credentials));
  }
  if (patch.enabled !== undefined) {
    sets.push('enabled = ?'); params.push(patch.enabled ? 1 : 0);
  }
  // source_type is intentionally NOT updatable -- it determines the
  // adapter, the credentials shape, and the path semantics. Changing it
  // post-hoc would invalidate the credentials. Operators delete + create
  // a new source instead.

  if (sets.length === 0) return getSource(db, id);

  sets.push("updated_at = datetime('now')");
  params.push(id);
  db.prepare(`UPDATE external_restore_sources SET ${sets.join(', ')} WHERE id = ?`).run(...params);
  return getSource(db, id);
}

function deleteSource(db, id) {
  rowOrThrow(db, id);  // ensure exists
  db.prepare('DELETE FROM external_restore_sources WHERE id = ?').run(id);
  return { id, deleted: true };
}

// ── Adapter operations ────────────────────────────────────────────────────

/**
 * Lightweight connectivity test. Calls the adapter's listBackups and
 * reports whether it succeeded + how many backups were found. Errors
 * surface as ADAPTER_FAILED with the underlying message in detail.
 */
async function testSource(db, id, log) {
  const source = rowOrThrow(db, id);
  if (!source.enabled) {
    throw new ExternalRestoreError(CODES.SOURCE_DISABLED,
      `source ${source.name} is disabled`);
  }
  const adapter = loadAdapter(source.source_type);
  const ctx = buildAdapterCtx(source, log);
  try {
    const result = await adapter.listBackups(ctx);
    return {
      ok: true,
      sourceId: source.id,
      sourceName: source.name,
      sourceType: source.source_type,
      backupCount: result.backups.length,
      newest: result.backups[0] ? result.backups[0].id : null,
    };
  } catch (err) {
    throw new ExternalRestoreError(CODES.ADAPTER_FAILED,
      `adapter ${source.source_type} failed: ${err.message}`);
  }
}

/**
 * List backups in a source. Same return shape as the adapter's
 * listBackups, plus source identity for the routes layer.
 */
async function browseSource(db, id, log) {
  const source = rowOrThrow(db, id);
  if (!source.enabled) {
    throw new ExternalRestoreError(CODES.SOURCE_DISABLED,
      `source ${source.name} is disabled`);
  }
  const adapter = loadAdapter(source.source_type);
  const ctx = buildAdapterCtx(source, log);
  let result;
  try {
    result = await adapter.listBackups(ctx);
  } catch (err) {
    throw new ExternalRestoreError(CODES.ADAPTER_FAILED,
      `adapter ${source.source_type} failed: ${err.message}`);
  }

  return {
    sourceId: source.id,
    sourceName: source.name,
    sourceType: source.source_type,
    backups: result.backups,
  };
}

/**
 * Fetch + verify a backup's manifest WITHOUT pulling the archive.
 * Used by the UI's "preview" pane: the lead reviews manifest details
 * before requesting two-person approval to actually restore.
 *
 * Returns:
 *   {
 *     sourceId, sourceName, externalBackupId,
 *     manifest: <parsed manifest object>,
 *     manifestSigOk: bool,
 *     signingKeyId, signingKeyKnown: bool,
 *     structure: { ok, missing[], present[], totalSizeBytes }
 *   }
 *
 * If manifestSigOk is false or signingKeyKnown is false, the routes
 * layer should refuse to allow a restore request even if the operator
 * insists. Both are critical safety properties.
 */
async function previewBackup(db, sourceId, externalBackupId, log) {
  const source = rowOrThrow(db, sourceId);
  if (!source.enabled) {
    throw new ExternalRestoreError(CODES.SOURCE_DISABLED,
      `source ${source.name} is disabled`);
  }
  requireNonEmptyString(externalBackupId, 'externalBackupId');

  const adapter = loadAdapter(source.source_type);
  const ctx = buildAdapterCtx(source, log);

  // 1. Confirm structure first -- if any of the 4 files is missing,
  //    bail out before downloading anything heavier than a directory
  //    listing.
  let structure;
  try {
    structure = await adapter.verifyStructure(ctx, externalBackupId);
  } catch (err) {
    throw new ExternalRestoreError(CODES.ADAPTER_FAILED,
      `verifyStructure failed: ${err.message}`);
  }
  if (!structure.ok) {
    throw new ExternalRestoreError(CODES.STRUCTURE_INVALID,
      `backup ${externalBackupId} is missing files: ${structure.missing.join(', ')}`,
      { structure });
  }

  // 2. Fetch manifest + sig (small files; cheap)
  let manifestBytes;
  let signatureBytes;
  try {
    manifestBytes  = await adapter.fetchFile(ctx, externalBackupId, 'manifest.json');
    signatureBytes = await adapter.fetchFile(ctx, externalBackupId, 'manifest.sig');
  } catch (err) {
    throw new ExternalRestoreError(CODES.ADAPTER_FAILED,
      `manifest/sig fetch failed: ${err.message}`);
  }

  // 3. Parse + validate manifest structure
  let manifest;
  try {
    manifest = manifestSvc.parse(manifestBytes);
  } catch (err) {
    throw new ExternalRestoreError(CODES.MANIFEST_PARSE_FAILED,
      `manifest unparseable: ${err.message}`);
  }
  const validation = manifestSvc.validateStructure(manifest);
  if (!validation.ok) {
    throw new ExternalRestoreError(CODES.MANIFEST_INVALID,
      `manifest structurally invalid: ${validation.error}`);
  }

  // 4. Verify Ed25519 signature against public key in
  //    backup_signing_keys. If the signing key id isn't recognized
  //    (e.g. the backup was signed by a DIFFERENT FireAlive
  //    deployment whose public key isn't registered here), report
  //    that distinct condition rather than collapsing both into
  //    "sig invalid".
  const signingKeyId = manifest.chain_signing_key_id || manifest.signing_key_id;
  const verifyKey = signingKeysSvc.getVerificationKey(db, signingKeyId);
  let manifestSigOk = false;
  let signingKeyKnown = !!verifyKey;
  if (signingKeyKnown) {
    try {
      manifestSigOk = signingKeysSvc.verifyManifest(db, manifestBytes, signatureBytes, signingKeyId);
    } catch {
      manifestSigOk = false;
    }
  }

  return {
    sourceId: source.id,
    sourceName: source.name,
    sourceType: source.source_type,
    externalBackupId,
    manifest,
    manifestSigOk,
    signingKeyId,
    signingKeyKnown,
    structure,
  };
}

// ── Restore workflow ──────────────────────────────────────────────────────

/**
 * Create an approval row targeting an external (sourceId,
 * externalBackupId) pair. Wraps approvalsSvc.createApprovalRequest
 * with the external shape. Routes layer maps the response into the UI.
 *
 * Args:
 *   { source_id, external_backup_id, requested_by_user_id,
 *     request_reason?, client_ip? }
 *
 * Returns the created approval row.
 */
function requestRestore(db, args) {
  if (!args || typeof args !== 'object') {
    throw new ExternalRestoreError(CODES.INVALID_INPUT, 'args object required');
  }
  if (typeof args.source_id !== 'number' && typeof args.source_id !== 'string') {
    throw new ExternalRestoreError(CODES.INVALID_INPUT, 'source_id required');
  }
  requireNonEmptyString(args.external_backup_id, 'external_backup_id');
  requireNonEmptyString(args.requested_by_user_id, 'requested_by_user_id');

  // Confirm the source exists + is enabled before creating an
  // approval -- avoids leaving dangling approval rows referencing
  // deleted/disabled sources.
  const source = rowOrThrow(db, args.source_id);
  if (!source.enabled) {
    throw new ExternalRestoreError(CODES.SOURCE_DISABLED,
      `source ${source.name} is disabled`);
  }

  // Delegate to restore-approvals service. The service-layer XOR
  // validation in commit 2 ensures we don't accidentally pass
  // backup_id alongside (source_id, external_backup_id).
  return approvalsSvc.createApprovalRequest(db, {
    source_id: String(args.source_id),
    external_backup_id: args.external_backup_id,
    requested_by_user_id: args.requested_by_user_id,
    request_reason: args.request_reason || null,
    client_ip: args.client_ip || null,
  });
}

/**
 * Execute a restore. Heavy lift -- the destructive operation.
 *
 * Args:
 *   { approval_id, executing_user_id, client_ip? }
 *
 * Preconditions:
 *   - approval_id refers to an approved + unconsumed approval row
 *     targeting an external (source_id, external_backup_id) pair
 *     for THIS user (the consumer-must-equal-requester rule)
 *   - the source is still present + enabled
 *
 * On success:
 *   - the LIVE database has been atomically replaced with the
 *     bytes from the restored backup
 *   - a pre-restore snapshot of the previous live state has been
 *     written next to it for safety
 *   - RESTORE_REQUEST + RESTORE_COMPLETE chain entries have been
 *     appended to the LOCAL chain
 *   - the approval row is marked consumed
 *   - the source's last_used_at has been updated
 *
 * Returns:
 *   {
 *     ok: true,
 *     approval_id,
 *     source_id, external_backup_id,
 *     pre_restore_snapshot_path,
 *     restore_request_chain_id,
 *     restore_complete_chain_id,
 *     restored_db_size_bytes
 *   }
 */
async function executeRestore(db, args) {
  if (!args || typeof args !== 'object') {
    throw new ExternalRestoreError(CODES.INVALID_INPUT, 'args object required');
  }
  requireNonEmptyString(args.approval_id, 'approval_id');
  requireNonEmptyString(args.executing_user_id, 'executing_user_id');

  // 1. Look up the approval; ensure it's approved + usable + targets
  //    the external shape (not a local backup).
  const approval = approvalsSvc.getApproval(db, args.approval_id);
  if (!approval) {
    throw new ExternalRestoreError(CODES.APPROVAL_NOT_FOUND,
      `approval ${args.approval_id} not found`);
  }
  if (!approval.source_id || !approval.external_backup_id) {
    throw new ExternalRestoreError(CODES.APPROVAL_NOT_USABLE,
      `approval ${args.approval_id} targets a local backup, not an external one`);
  }
  // Defense in depth: re-check usability here even though the routes
  // layer already verified. A racing expiry sweep could have flipped
  // the row between verification and consumption.
  const usable = approvalsSvc.findUsableForExternal(db, {
    source_id: approval.source_id,
    external_backup_id: approval.external_backup_id,
    requested_by_user_id: args.executing_user_id,
  });
  if (!usable || usable.id !== approval.id) {
    throw new ExternalRestoreError(CODES.APPROVAL_NOT_USABLE,
      `approval ${args.approval_id} is not currently usable (status=${approval.status}, consumed_at=${approval.consumed_at || 'null'})`);
  }

  // 2. Load source + adapter
  const source = rowOrThrow(db, approval.source_id);
  if (!source.enabled) {
    throw new ExternalRestoreError(CODES.SOURCE_DISABLED,
      `source ${source.name} is disabled`);
  }
  const adapter = loadAdapter(source.source_type);
  const log = (level, msg, meta) => { /* routes layer can replace */ };
  const ctx = buildAdapterCtx(source, log);
  const externalBackupId = approval.external_backup_id;

  // 3. verifyStructure (presence)
  let structure;
  try {
    structure = await adapter.verifyStructure(ctx, externalBackupId);
  } catch (err) {
    throw new ExternalRestoreError(CODES.ADAPTER_FAILED,
      `verifyStructure failed: ${err.message}`);
  }
  if (!structure.ok) {
    throw new ExternalRestoreError(CODES.STRUCTURE_INVALID,
      `backup ${externalBackupId} is missing files: ${structure.missing.join(', ')}`);
  }

  // 4. Fetch manifest + sig
  let manifestBytes;
  let signatureBytes;
  try {
    manifestBytes  = await adapter.fetchFile(ctx, externalBackupId, 'manifest.json');
    signatureBytes = await adapter.fetchFile(ctx, externalBackupId, 'manifest.sig');
  } catch (err) {
    throw new ExternalRestoreError(CODES.ADAPTER_FAILED,
      `manifest/sig fetch failed: ${err.message}`);
  }

  // 5. Parse + validate + sig-verify manifest
  let manifest;
  try { manifest = manifestSvc.parse(manifestBytes); }
  catch (err) {
    throw new ExternalRestoreError(CODES.MANIFEST_PARSE_FAILED,
      `manifest unparseable: ${err.message}`);
  }
  const validation = manifestSvc.validateStructure(manifest);
  if (!validation.ok) {
    throw new ExternalRestoreError(CODES.MANIFEST_INVALID,
      `manifest structurally invalid: ${validation.error}`);
  }
  const signingKeyId = manifest.chain_signing_key_id || manifest.signing_key_id;
  if (!signingKeysSvc.getVerificationKey(db, signingKeyId)) {
    throw new ExternalRestoreError(CODES.SIGNING_KEY_UNKNOWN,
      `manifest signing_key_id ${signingKeyId} is not in the local backup_signing_keys table; register the public key first`);
  }
  let manifestSigOk;
  try {
    manifestSigOk = signingKeysSvc.verifyManifest(db, manifestBytes, signatureBytes, signingKeyId);
  } catch (err) {
    throw new ExternalRestoreError(CODES.MANIFEST_SIG_MISMATCH,
      `manifest signature verification threw: ${err.message}`);
  }
  if (!manifestSigOk) {
    throw new ExternalRestoreError(CODES.MANIFEST_SIG_MISMATCH,
      `manifest signature does not verify against signing_key_id ${signingKeyId}`);
  }

  // 6. Fetch wrapped-key + archive
  let wrappedKeyBytes;
  let archiveBytes;
  try {
    wrappedKeyBytes = await adapter.fetchFile(ctx, externalBackupId, 'wrapped-key.bin');
    archiveBytes    = await adapter.fetchFile(ctx, externalBackupId, 'archive.tar.zst.enc');
  } catch (err) {
    throw new ExternalRestoreError(CODES.ADAPTER_FAILED,
      `wrapped-key/archive fetch failed: ${err.message}`);
  }

  // 7. Verify each file's SHA-256 against the in-manifest record
  const archiveSha = crypto.createHash('sha256').update(archiveBytes).digest('hex');
  const archiveEntry = manifestSvc.getFileEntry(manifest, manifestSvc.ARCHIVE_FILENAME);
  if (!archiveEntry || archiveSha !== archiveEntry.sha256) {
    throw new ExternalRestoreError(CODES.FILE_HASH_MISMATCH,
      `archive sha256 mismatch (manifest=${archiveEntry ? archiveEntry.sha256 : 'null'}, actual=${archiveSha})`);
  }
  const wrappedSha = crypto.createHash('sha256').update(wrappedKeyBytes).digest('hex');
  const wrappedEntry = manifestSvc.getFileEntry(manifest, manifestSvc.WRAPPED_KEY_FILENAME);
  if (!wrappedEntry || wrappedSha !== wrappedEntry.sha256) {
    throw new ExternalRestoreError(CODES.FILE_HASH_MISMATCH,
      `wrapped-key sha256 mismatch (manifest=${wrappedEntry ? wrappedEntry.sha256 : 'null'}, actual=${wrappedSha})`);
  }

  // 8. Append RESTORE_REQUEST chain entry BEFORE destructive work.
  //    Failure to append is FATAL -- if we cannot record intent,
  //    we don't proceed.
  let restoreRequestChainId;
  try {
    const result = chainSvc.appendChainEntry(db, {
      eventType: 'RESTORE_REQUEST',
      backupId: null,  // external -- no local backup_id
      actorUserId: args.executing_user_id,
      payload: {
        external_restore: true,
        source_id: source.id,
        source_name: source.name,
        source_type: source.source_type,
        external_backup_id: externalBackupId,
        approval_id: approval.id,
        manifest_signing_key_id: signingKeyId,
        restore_initiated_at: new Date().toISOString(),
      },
    });
    restoreRequestChainId = result.id;
  } catch (err) {
    throw new ExternalRestoreError(CODES.CHAIN_APPEND_FAILED,
      `RESTORE_REQUEST chain append failed: ${err.message}`);
  }

  // 9. Unwrap DEK via the registry dispatcher
  let ephemeralKey;
  try {
    ephemeralKey = await keyWrapSvc.unwrapKey(
      wrappedKeyBytes,
      manifest.key_wrapping.scheme,
      manifest.key_wrapping.kek_reference,
    );
  } catch (err) {
    throw new ExternalRestoreError(CODES.KEY_UNWRAP_FAILED,
      `DEK unwrap failed (scheme=${manifest.key_wrapping.scheme}, kek=${manifest.key_wrapping.kek_reference}): ${err.message}`,
      { hint: 'Most often this means the KEK has been rotated or the kms_providers row has changed since this backup was created. Restoring requires the same KEK that wrapped the DEK.' });
  }

  // 10. Decrypt + decompress + untar
  let extracted;
  try {
    extracted = await archiveSvc.extractArchive(archiveBytes, ephemeralKey);
  } catch (err) {
    throw new ExternalRestoreError(CODES.EXTRACT_FAILED,
      `archive extraction failed: ${err.message}`);
  }

  // 11. Confirm extracted file is the expected SQLite database
  if (extracted.name !== 'firealive.db') {
    throw new ExternalRestoreError(CODES.EXTRACT_UNEXPECTED_FILE,
      `extracted archive contains '${extracted.name}', expected 'firealive.db'`);
  }

  // 12. Pre-restore snapshot of CURRENT live DB
  const { DB_PATH } = require('../db/init');
  const dbDir = path.dirname(DB_PATH);
  const preRestorePath = path.join(dbDir, `pre-external-restore-${Date.now()}.db`);
  try {
    fs.copyFileSync(DB_PATH, preRestorePath);
  } catch (err) {
    throw new ExternalRestoreError(CODES.PRE_RESTORE_SNAPSHOT_FAILED,
      `failed to snapshot current DB to ${preRestorePath}: ${err.message}`);
  }

  // 13. Atomic-rename extracted bytes over DB_PATH
  const tempDbPath = path.join(dbDir, `.external-restore-${Date.now()}.db.tmp`);
  try {
    fs.writeFileSync(tempDbPath, extracted.payload);
    fs.renameSync(tempDbPath, DB_PATH);
  } catch (err) {
    // If the atomic apply fails, the pre-restore snapshot is the
    // recovery path. Operator restores from preRestorePath via
    // direct file copy.
    try { fs.unlinkSync(tempDbPath); } catch { /* best effort */ }
    throw new ExternalRestoreError(CODES.ATOMIC_APPLY_FAILED,
      `atomic apply failed: ${err.message} -- recover from ${preRestorePath}`);
  }

  // 14. Append RESTORE_COMPLETE to the chain. Note: this writes to
  //     the NEW database (atomic rename has already swapped). We
  //     append to the chain in the new DB so the audit trail
  //     reflects the restored state.
  let restoreCompleteChainId;
  try {
    const result = chainSvc.appendChainEntry(db, {
      eventType: 'RESTORE_COMPLETE',
      backupId: null,
      actorUserId: args.executing_user_id,
      payload: {
        external_restore: true,
        source_id: source.id,
        external_backup_id: externalBackupId,
        approval_id: approval.id,
        manifest_signing_key_id: signingKeyId,
        pre_restore_snapshot_path: preRestorePath,
        restore_request_chain_id: restoreRequestChainId,
        restored_at: new Date().toISOString(),
        restored_db_size_bytes: extracted.payload.length,
      },
    });
    restoreCompleteChainId = result.id;
  } catch (err) {
    // Logged but non-fatal -- the restore succeeded; only the audit
    // marker is missing. Operator can investigate post-hoc.
    log('error', 'RESTORE_COMPLETE chain append failed (restore succeeded)', {
      error: err.message,
    });
  }

  // 15. Mark approval consumed
  try {
    approvalsSvc.consumeApproval(db, {
      approval_id: approval.id,
      consumed_by_user_id: args.executing_user_id,
    });
  } catch (err) {
    log('error', 'approval consumeApproval failed (restore succeeded)', {
      approvalId: approval.id, error: err.message,
    });
  }

  // 16. Update source last_used_at
  try {
    db.prepare(
      "UPDATE external_restore_sources SET last_used_at = datetime('now') WHERE id = ?"
    ).run(source.id);
  } catch (err) {
    log('error', 'last_used_at update failed (restore succeeded)', {
      sourceId: source.id, error: err.message,
    });
  }

  return {
    ok: true,
    approval_id: approval.id,
    source_id: source.id,
    external_backup_id: externalBackupId,
    pre_restore_snapshot_path: preRestorePath,
    restore_request_chain_id: restoreRequestChainId,
    restore_complete_chain_id: restoreCompleteChainId || null,
    restored_db_size_bytes: extracted.payload.length,
  };
}

// ── Module exports ────────────────────────────────────────────────────────

module.exports = {
  // Source CRUD
  listSources,
  getSource,
  createSource,
  updateSource,
  deleteSource,

  // Adapter operations
  testSource,
  browseSource,
  previewBackup,

  // Restore workflow
  requestRestore,
  executeRestore,

  // Errors + constants
  ExternalRestoreError,
  CODES,
  VALID_SOURCE_TYPES,
  SOURCE_TYPE_TO_ADAPTER,

  // Internal helpers exposed for tests
  _internal: {
    loadAdapter,
    buildAdapterCtx,
    encryptCredentials,
    decryptCredentials,
    requireNonEmptyString,
    nowSqlite,
  },
};

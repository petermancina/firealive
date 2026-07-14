// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — External Restore Routes
//
// HTTP API in front of services/external-restore.js. Admins manage
// external restore sources (the remote storage locations where v2
// backups live) and execute disaster-recovery restores against
// approved approval rows.
//
// ENDPOINTS
//
//   Source CRUD:
//     GET    /api/external-restore/sources               list
//     GET    /api/external-restore/sources/:id           get one
//     POST   /api/external-restore/sources               create
//     PATCH  /api/external-restore/sources/:id           update
//     DELETE /api/external-restore/sources/:id           delete
//
//   Adapter operations:
//     POST   /api/external-restore/sources/:id/test      connectivity test
//     GET    /api/external-restore/sources/:id/browse    list backups
//     POST   /api/external-restore/sources/:id/preview/:backupId
//                                                         preview manifest
//
//   Restore workflow:
//     POST   /api/external-restore/sources/:id/restore-request/:backupId
//                                                         create approval row
//     POST   /api/external-restore/restore-execute/:approvalId
//                                                         execute restore
//
// AUTH MODEL
//
// This file is mounted with authMiddleware(['admin']) in
// server/index.js. All operations are admin-only because external
// restore replaces the LIVE database -- it's the most destructive
// operation in the system. No per-handler role tightening; auth
// gate is at the mount.
//
// TWO-PERSON APPROVAL GATE
//
// /restore-execute/:approvalId is the destructive endpoint and is
// gated by the existing /api/restore-approvals approval workflow:
//   1. Admin A POSTs to /sources/:id/restore-request/:backupId,
//      which creates an approval row (via approvalsSvc).
//   2. Admin B POSTs to /api/restore-approvals/:approvalId/approve
//      with a hardware-passkey step-up (existing route from R3d-4 part 2).
//   3. Admin A POSTs to /restore-execute/:approvalId. The service
//      verifies the approval is approved + usable + targets the
//      external (source_id, external_backup_id) shape + the
//      executing user matches the requester.
//
// This route file does NOT duplicate the step-up gate -- the existing
// approve flow handles it. The execute endpoint just consumes the
// already-approved row.
//
// AUDIT LOG
//
// The global auditMiddleware in index.js writes the HTTP-level audit
// row for every request. The orchestrator service appends domain-
// specific chain entries (RESTORE_REQUEST, RESTORE_COMPLETE) inside
// executeRestore. This route file does not duplicate-log.
//
// ERROR MAPPING
//
// Service throws ExternalRestoreError with stable .code; this file
// maps codes to HTTP statuses (see externalCodeToHttpStatus).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const externalSvc = require('../services/external-restore');

// ── Error mapping ────────────────────────────────────────────────────────

function externalCodeToHttpStatus(code) {
  switch (code) {
    case externalSvc.CODES.INVALID_INPUT:
      return 400;
    case externalSvc.CODES.SOURCE_NOT_FOUND:
    case externalSvc.CODES.BACKUP_NOT_FOUND:
    case externalSvc.CODES.APPROVAL_NOT_FOUND:
      return 404;
    case externalSvc.CODES.SOURCE_DISABLED:
    case externalSvc.CODES.SOURCE_NAME_CONFLICT:
    case externalSvc.CODES.APPROVAL_NOT_USABLE:
      return 409;
    case externalSvc.CODES.STRUCTURE_INVALID:
    case externalSvc.CODES.MANIFEST_PARSE_FAILED:
    case externalSvc.CODES.MANIFEST_INVALID:
    case externalSvc.CODES.MANIFEST_SIG_MISMATCH:
    case externalSvc.CODES.SIGNING_KEY_UNKNOWN:
    case externalSvc.CODES.FILE_HASH_MISMATCH:
    case externalSvc.CODES.EXTRACT_UNEXPECTED_FILE:
    case externalSvc.CODES.SCANNER_NOT_CONFIGURED:
    case externalSvc.CODES.MALWARE_DETECTED:
      return 422;
    case externalSvc.CODES.ADAPTER_FAILED:
    case externalSvc.CODES.KEY_UNWRAP_FAILED:
    case externalSvc.CODES.EXTRACT_FAILED:
    case externalSvc.CODES.CHAIN_APPEND_FAILED:
    case externalSvc.CODES.PRE_RESTORE_SNAPSHOT_FAILED:
    case externalSvc.CODES.ATOMIC_APPLY_FAILED:
    case externalSvc.CODES.SCAN_FAILED:
      return 500;
    default:
      return 500;
  }
}

function sendError(res, err) {
  if (err instanceof externalSvc.ExternalRestoreError) {
    const status = externalCodeToHttpStatus(err.code);
    const body = { error: err.message, code: err.code };
    if (err.detail !== undefined && err.detail !== null) body.detail = err.detail;
    return res.status(status).json(body);
  }
  // Unexpected (non-typed) error -- log + 500 with sanitized message.
  logger.error('external-restore unexpected error', {
    error: err.message, stack: err.stack,
  });
  return res.status(500).json({
    error: 'internal server error',
    code: 'INTERNAL_ERROR',
  });
}

function parseId(value, fieldName) {
  const n = Number.parseInt(value, 10);
  if (!Number.isInteger(n) || n <= 0) {
    const err = new externalSvc.ExternalRestoreError(
      externalSvc.CODES.INVALID_INPUT,
      `${fieldName} must be a positive integer (got ${JSON.stringify(value)})`,
    );
    throw err;
  }
  return n;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Build a logger callback the orchestrator can use to emit structured
 * messages. Tags every line with the request id (for trace continuity)
 * and the calling user id (for forensic attribution).
 */
function buildLog(req) {
  const requestId = req.id || req.headers['x-request-id'] || null;
  const userId = req.user ? req.user.id : null;
  return (level, msg, meta) => {
    const fullMeta = { requestId, userId, ...(meta || {}) };
    if (typeof logger[level] === 'function') {
      logger[level](msg, fullMeta);
    } else {
      logger.info(msg, fullMeta);
    }
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// SOURCE CRUD
// ═══════════════════════════════════════════════════════════════════════════

// ── GET /api/external-restore/sources ──────────────────────────────────────
//
// Query:
//   ?enabled=true   only enabled sources
router.get('/sources', (req, res) => {
  let db;
  try {
    db = getDb();
    const opts = {};
    if (req.query.enabled !== undefined) {
      const v = String(req.query.enabled).toLowerCase();
      opts.enabled = v === 'true' || v === '1';
    }
    const rows = externalSvc.listSources(db, opts);
    // Strip credentials_encrypted from the public view -- it's an
    // opaque ciphertext blob, not useful to clients and a small
    // forensic-hygiene win not to ship it.
    const sanitized = rows.map(({ credentials_encrypted, ...rest }) => rest);
    return res.json({ sources: sanitized });
  } catch (err) {
    return sendError(res, err);
  } finally {
    if (db) db.close();
  }
});

// ── GET /api/external-restore/sources/:id ──────────────────────────────────
router.get('/sources/:id', (req, res) => {
  let db;
  try {
    const id = parseId(req.params.id, 'id');
    db = getDb();
    const row = externalSvc.getSource(db, id);
    const { credentials_encrypted, ...rest } = row;
    return res.json({ source: rest });
  } catch (err) {
    return sendError(res, err);
  } finally {
    if (db) db.close();
  }
});

// ── POST /api/external-restore/sources ─────────────────────────────────────
//
// Body:
//   {
//     name:        string (required)
//     source_type: 'network_share' | 'nas' | 's3' | 'azure_blob' | 'sftp'
//     path:        string (required)
//     credentials: object (required) -- adapter-specific, encrypted at rest
//     enabled:     boolean (optional, default true)
//   }
router.post('/sources', (req, res) => {
  let db;
  try {
    if (!isPlainObject(req.body)) {
      return res.status(400).json({
        error: 'request body must be a JSON object',
        code: externalSvc.CODES.INVALID_INPUT,
      });
    }
    db = getDb();
    const created = externalSvc.createSource(db, {
      name: req.body.name,
      source_type: req.body.source_type,
      path: req.body.path,
      credentials: req.body.credentials,
      enabled: req.body.enabled,
      created_by_user_id: req.user ? req.user.id : null,
    });
    const { credentials_encrypted, ...rest } = created;
    return res.status(201).json({ source: rest });
  } catch (err) {
    return sendError(res, err);
  } finally {
    if (db) db.close();
  }
});

// ── PATCH /api/external-restore/sources/:id ─────────────────────────────────
//
// Body: partial update of any of { name, path, credentials, enabled }.
// source_type is intentionally NOT updatable -- delete + create instead.
router.patch('/sources/:id', (req, res) => {
  let db;
  try {
    const id = parseId(req.params.id, 'id');
    if (!isPlainObject(req.body)) {
      return res.status(400).json({
        error: 'request body must be a JSON object',
        code: externalSvc.CODES.INVALID_INPUT,
      });
    }
    if (req.body.source_type !== undefined) {
      return res.status(400).json({
        error: 'source_type is not updatable -- delete + create a new source',
        code: externalSvc.CODES.INVALID_INPUT,
      });
    }
    db = getDb();
    const updated = externalSvc.updateSource(db, id, {
      name: req.body.name,
      path: req.body.path,
      credentials: req.body.credentials,
      enabled: req.body.enabled,
    });
    const { credentials_encrypted, ...rest } = updated;
    return res.json({ source: rest });
  } catch (err) {
    return sendError(res, err);
  } finally {
    if (db) db.close();
  }
});

// ── DELETE /api/external-restore/sources/:id ────────────────────────────────
router.delete('/sources/:id', (req, res) => {
  let db;
  try {
    const id = parseId(req.params.id, 'id');
    db = getDb();
    const result = externalSvc.deleteSource(db, id);
    return res.json(result);
  } catch (err) {
    return sendError(res, err);
  } finally {
    if (db) db.close();
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ADAPTER OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

// ── POST /api/external-restore/sources/:id/test ─────────────────────────────
//
// Lightweight connectivity probe. Calls the adapter's listBackups and
// reports success + count without enumerating details. Synchronous;
// adapter timeouts apply (typically 30-60s).
router.post('/sources/:id/test', async (req, res) => {
  let db;
  try {
    const id = parseId(req.params.id, 'id');
    db = getDb();
    const result = await externalSvc.testSource(db, id, buildLog(req));
    return res.json(result);
  } catch (err) {
    return sendError(res, err);
  } finally {
    if (db) db.close();
  }
});

// ── GET /api/external-restore/sources/:id/browse ────────────────────────────
//
// Full listBackups call. Returns the array of v2 backup folders with
// id (folder name), modifiedAt, sizeBytes. Newest first.
router.get('/sources/:id/browse', async (req, res) => {
  let db;
  try {
    const id = parseId(req.params.id, 'id');
    db = getDb();
    const result = await externalSvc.browseSource(db, id, buildLog(req));
    return res.json(result);
  } catch (err) {
    return sendError(res, err);
  } finally {
    if (db) db.close();
  }
});

// ── POST /api/external-restore/sources/:id/preview/:backupId ────────────────
//
// Fetch + verify manifest WITHOUT downloading the archive. Returns the
// parsed manifest, sig verification status, signing key recognition
// status, and structure inventory.
//
// The lead reviews this before requesting two-person approval. If
// manifestSigOk=false or signingKeyKnown=false, the UI should refuse
// to proceed with a restore request even if the operator insists --
// these are critical safety properties.
router.post('/sources/:id/preview/:backupId', async (req, res) => {
  let db;
  try {
    const id = parseId(req.params.id, 'id');
    const backupId = String(req.params.backupId || '');
    db = getDb();
    const result = await externalSvc.previewBackup(db, id, backupId, buildLog(req));
    return res.json(result);
  } catch (err) {
    return sendError(res, err);
  } finally {
    if (db) db.close();
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// RESTORE WORKFLOW
// ═══════════════════════════════════════════════════════════════════════════

// ── POST /api/external-restore/sources/:id/restore-request/:backupId ────────
//
// Create an approval row targeting an external (source_id,
// external_backup_id) pair. Writes through to services/restore-
// approvals (XOR-validated external shape). The current approval
// mode (strict / delayed-self / disabled) determines whether the
// row is created in 'pending' or already-approved state.
//
// Body (optional):
//   {
//     request_reason: string  -- max 1024 chars, recorded in audit
//   }
//
// After creation, route the user to the approve flow:
//   POST /api/restore-approvals/:approvalId/approve  (step-up-gated)
router.post('/sources/:id/restore-request/:backupId', (req, res) => {
  let db;
  try {
    const id = parseId(req.params.id, 'id');
    const backupId = String(req.params.backupId || '');
    db = getDb();
    const requestReason = (req.body && typeof req.body.request_reason === 'string')
      ? req.body.request_reason
      : null;
    const approval = externalSvc.requestRestore(db, {
      source_id: id,
      external_backup_id: backupId,
      requested_by_user_id: req.user.id,
      request_reason: requestReason,
      client_ip: req.ip || null,
    });
    // Surface enough context for the UI to drive the next step
    // without a second round-trip.
    return res.status(201).json({
      approval_id: approval.id,
      status: approval.status,
      approval_mode_at_creation: approval.approval_mode_at_creation,
      approval_window_hours: approval.approval_window_hours,
      expires_at: approval.expires_at,
      next_step: approval.status === 'approved'
        ? `POST /api/external-restore/restore-execute/${approval.id}`
        : `POST /api/restore-approvals/${approval.id}/approve (hardware-passkey step-up required)`,
    });
  } catch (err) {
    return sendError(res, err);
  } finally {
    if (db) db.close();
  }
});

// ── POST /api/external-restore/restore-execute/:approvalId ───────────────────
//
// THE DESTRUCTIVE ENDPOINT. Atomically replaces the live database
// with the bytes from the external backup referenced by an approved
// approval row.
//
// Preconditions enforced by the service:
//   - approval_id refers to an approved + unconsumed row
//   - approval row targets the external (source_id, external_backup_id)
//     shape (not a local backup_id)
//   - the executing user is the original requester (consumer-must-equal-
//     requester rule from R3d-4 part 2)
//   - the source is still present + enabled
//
// The orchestrator runs the full 16-step flow (verify structure ->
// fetch + verify manifest sig + file hashes -> RESTORE_REQUEST chain
// entry -> unwrap DEK -> decrypt + decompress + untar -> pre-restore
// snapshot -> atomic apply -> RESTORE_COMPLETE chain entry ->
// consumeApproval -> last_used_at).
//
// Response on success: see executeRestore return shape.
// Response on failure: typed error mapped to HTTP status. Note that
// CHAIN_APPEND_FAILED on RESTORE_REQUEST means NOTHING destructive
// happened; CHAIN_APPEND_FAILED logged-non-fatally on RESTORE_COMPLETE
// means the restore SUCCEEDED but the audit marker is missing.
router.post('/restore-execute/:approvalId', async (req, res) => {
  let db;
  try {
    const approvalId = String(req.params.approvalId || '');
    db = getDb();
    const result = await externalSvc.executeRestore(db, {
      approval_id: approvalId,
      executing_user_id: req.user.id,
      client_ip: req.ip || null,
    });
    return res.json(result);
  } catch (err) {
    return sendError(res, err);
  } finally {
    if (db) db.close();
  }
});

module.exports = router;

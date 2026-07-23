// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Restore & Settings Revert Routes
// GET  /api/restore/points              — list available restore points (backups + configs)
// GET  /api/restore/preview/:id         — preview what a restore would change
// POST /api/restore/execute/:id         — execute restore from backup (v1 + v2)
// GET  /api/restore/configs             — list saved configuration snapshots
// POST /api/restore/config-save         — save current config as named snapshot
// POST /api/restore/config-revert/:id   — revert to a config snapshot
//
// FORMAT-AWARE.
//
// v1 backups (legacy raw SQLite .db file copies) restore by reading the
// file at backup.file_path, hashing, and fs.copyFileSync over DB_PATH.
// The destructive write itself is unchanged from v1.0.29; the approval
// gate (R3d-4) and the chain RESTORE_REQUEST/RESTORE_COMPLETE entries
// (R3d-4 part 2 commit 16) are new for v1 too -- legacy backups must
// not be a back door around two-person approval.
//
// v2 backups (encrypted-signed directory layout) restore by:
//   1. Verifying the Ed25519 signature on manifest.json against the
//      public key of the backup's signing_key_id (key may be active or
//      rotated out -- both work)
//   2. Parsing + structurally validating the manifest
//   3. Verifying the in-manifest file hashes match actual on-disk
//      bytes for archive.tar.zst.enc and wrapped-key.bin
//   4. Unwrapping the ephemeral data key via the manifest-recorded
//      key_wrapping scheme + KEK reference
//   5. Extracting the archive (decrypt -> decompress -> untar) to
//      recover the SQLite .db bytes
//   6. fs.copyFileSync the recovered .db over DB_PATH
//
// Both paths produce a pre-restore backup of the CURRENT DB state as a
// raw .db file in the backup dir before any destructive write. The
// pre-restore path returns success with a note that the server must
// restart to flush in-memory state -- same as v1.0.29.
//
// ═══════════════════════════════════════════════════════════════════════════════
// APPROVAL GATE (R3d-4 part 2 commit 16)
//
// Every POST /execute/:id call is gated by services/restore-approvals.js
// regardless of backup format. The route reads the operator-configured
// mode from system_meta via services/restore-approval-policy.js and
// branches:
//
//   strict, delayed-self-approval:
//     Request body MUST include approval_id. The approval row must be:
//       - status = 'approved'
//       - backup_id matches the path :id    (cross-backup reuse blocked)
//       - requested_by_user_id matches req.user.id
//                                            (only the original
//                                             requester can consume)
//       - within consumption deadline
//                                            (approved_at + window_hours)
//     The route appends RESTORE_REQUEST to the chain FIRST (so the
//     approval row's chain_request_entry_id can reference it), then
//     calls consumeApproval. consumeApproval re-checks the consumption
//     deadline as defense-in-depth. If consume fails, the chain entry
//     is already written (REQUEST without COMPLETE = forensic signature
//     of an aborted restore -- intended).
//
//   disabled:
//     Route auto-creates an approval row via createApprovalRequest.
//     The service writes that row with status='approved' and
//     approval_method='disabled-mode-bypass' (see
//     services/restore-approvals.js createApprovalRequest disabled-mode
//     branch). The route then calls consumeApproval on the same id.
//     Result: a uniform audit trail across all three modes -- every
//     destructive restore has a corresponding restore_approvals row
//     with backup_id, requester, method, and chain_request_entry_id.
//
// VALIDATION ORDER inside POST /execute/:id:
//   1. Backup row exists, status='verified'
//   2. confirmHash matches first 8 hex chars of backup.sha256_hash
//   3. Format-aware preconditions
//        v1: file_path exists on disk
//        v2: all four files on disk + chain integrity precondition
//            (chainSvc.verifyChainUpToBackup)
//   4. Approval gate PRE-VALIDATION (cheap reads only; no row mutation)
//        - In disabled mode, defer creation+consume to step 7
//        - In strict / delayed-self-approval, read approval row and
//          enforce backup_id / requester / status checks. Refuses
//          loudly with stable error codes the MC can surface.
//   5. v2: read manifest, verify hash + signature + parse + structure,
//        verify in-manifest archive/wrapped-key hashes
//   6. Append RESTORE_REQUEST chain entry (BOTH v1 and v2)
//   7. consumeApproval(db, { id, chain_request_entry_id })
//        In disabled mode: createApprovalRequest first (auto-approved
//        row), then consumeApproval same call site.
//        Failure here = refuse the restore. Chain entry remains
//        appended; that is the desired forensic property.
//   8. v1 destructive: fs.copyFileSync(backup.file_path, DB_PATH)
//      v2 destructive: pre-restore copy + key unwrap + archive extract
//                      + atomic rename of recovered .db over DB_PATH
//   9. Append RESTORE_COMPLETE chain entry on RESTORED DB (BOTH v1 + v2)
//  10. auditLog DATABASE_RESTORED + response with chain provenance
//
// SCOPE NOTE
//   POST /config-revert/:id is NOT gated in this commit. Config
//   snapshots are non-destructive in the same sense as a DB restore
//   (revert auto-saves current state first); they don't carry analyst
//   data; and they're not subject to the same compromise scenarios.
//   A future commit can extend the gate to config-revert if the
//   threat model warrants. Commit 15's commit description named
//   config-snapshot in the gated set; that was an error in the
//   description and is corrected here.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { appendAuditEntry } = require('../services/audit-chain');
const { readHighWater } = require('../services/fuse-high-water');
const { applyPostRestorePosture } = require('../services/restore-posture');
const { logger } = require('../services/logger');
const archiveSvc = require('../services/backup-archive');
const keyWrapSvc = require('../services/backup-key-wrapping');
const manifestSvc = require('../services/backup-manifest');
const signingKeysSvc = require('../services/backup-signing-keys');
const chainSvc = require('../services/backup-chain');
const approvalsSvc = require('../services/restore-approvals');
const approvalPolicy = require('../services/restore-approval-policy');
// R3l C66: chain walker/validator/replayer for incremental + differential restores
const restoreChainSvc = require('../services/restore-chain');
const { IntegrationManager } = require('../services/integration-manager');

// ── Approval-gate helpers ────────────────────────────────────────────────────
//
// Two helpers split the two phases of the gate so the main handler
// reads as a flat sequence rather than a deeply nested branch:
//
//   preValidateApproval(db, { backup, userId, body, mode })
//     -> { ok: true,  approvalRow }       on success
//     -> { ok: false, status, body }      on refusal (route returns this)
//
//   ApprovalConsumeError                  thrown from consumeApprovalGated
//     instances carry { httpStatus, body }
//
// Both helpers DO NOT close the db; the handler owns connection
// lifetime to keep the existing v2 transaction structure.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cheap pre-validation for strict/delayed-self-approval modes. Refuses
 * the restore early with a clear error before any chain or destructive
 * work. Does NOT mutate state.
 *
 * In 'disabled' mode the approval row is auto-created at consume time
 * (step 7), so this helper short-circuits with ok=true and a sentinel
 * approvalRow=null which the consume helper recognizes as the disabled-
 * mode signal.
 */
function preValidateApproval(db, { backup, userId, body, mode, ip }) {
  if (mode === 'disabled') {
    return { ok: true, approvalRow: null, autoCreate: true };
  }

  // strict OR delayed-self-approval: client MUST supply approval_id
  const approvalId = body && typeof body.approval_id === 'string' ? body.approval_id : null;
  if (!approvalId) {
    return {
      ok: false,
      status: 400,
      body: {
        error: `approval_id required (mode=${mode})`,
        mode,
        code: 'APPROVAL_REQUIRED',
        hint: 'create a restore approval request first via POST /api/restore-approvals (commit 17), have a second admin approve, then retry POST /execute with { confirmHash, approval_id }',
      },
    };
  }

  const row = approvalsSvc.getApproval(db, approvalId);
  if (!row) {
    return {
      ok: false,
      status: 404,
      body: {
        error: 'approval not found',
        approval_id: approvalId,
        code: approvalsSvc.CODES.APPROVAL_NOT_FOUND,
      },
    };
  }

  // Security: the approval must be for THIS backup. Otherwise an
  // operator could accumulate approvals on low-value backups and
  // redirect them to higher-value ones.
  if (row.backup_id !== backup.id) {
    auditLog(
      userId,
      'RESTORE_APPROVAL_BACKUP_MISMATCH',
      `approval=${approvalId} approval_backup=${row.backup_id} requested_backup=${backup.id}`,
      ip,
    );
    return {
      ok: false,
      status: 403,
      body: {
        error: 'approval is not for this backup',
        code: 'APPROVAL_BACKUP_MISMATCH',
        approval_backup_id: row.backup_id,
        requested_backup_id: backup.id,
      },
    };
  }

  // Security: only the original requester can consume their approval.
  // A second admin's approve() advances the row to status=approved
  // but the consume must come from the original requester. This keeps
  // the consume API-symmetric with the request: whoever created it
  // is the only one who can spend it.
  if (row.requested_by_user_id !== userId) {
    auditLog(
      userId,
      'RESTORE_APPROVAL_REQUESTER_MISMATCH',
      `approval=${approvalId} approval_requester=${row.requested_by_user_id} consuming_user=${userId}`,
      ip,
    );
    return {
      ok: false,
      status: 403,
      body: {
        error: 'only the original requester can consume the approval',
        code: 'APPROVAL_REQUESTER_MISMATCH',
      },
    };
  }

  if (row.status !== 'approved') {
    return {
      ok: false,
      status: 409,
      body: {
        error: `approval is in '${row.status}' state, not 'approved'`,
        current_status: row.status,
        code: row.status === 'consumed'
          ? approvalsSvc.CODES.APPROVAL_TERMINAL
          : approvalsSvc.CODES.APPROVAL_NOT_APPROVED,
      },
    };
  }

  return { ok: true, approvalRow: row, autoCreate: false };
}

/**
 * Custom error type so the handler can let bubble-up errors carry
 * their HTTP status without re-mapping at every call site.
 */
class ApprovalConsumeError extends Error {
  constructor(httpStatus, body) {
    super(body && body.error ? body.error : 'approval consume failed');
    this.name = 'ApprovalConsumeError';
    this.httpStatus = httpStatus;
    this.body = body;
  }
}

/**
 * Map an ApprovalError code to an HTTP status. Mirrors the conventions
 * documented in services/restore-approvals.js:
 *   INVALID_INPUT                          -> 400
 *   APPROVAL_NOT_FOUND                     -> 404
 *   APPROVAL_NOT_PENDING                   -> 409
 *   APPROVAL_NOT_APPROVED                  -> 409
 *   APPROVAL_TERMINAL                      -> 409
 *   APPROVAL_CONSUMPTION_DEADLINE_PASSED   -> 409
 *   CONCURRENT_MUTATION                    -> 409
 *   APPROVER_SAME_AS_REQUESTER             -> 403
 *   WINDOW_NOT_ELAPSED                     -> 403
 *   DISABLED_MODE_NO_MANUAL_APPROVE        -> 409
 *   STEPUP_NOT_VERIFIED                    -> 403
 */
function approvalCodeToHttpStatus(code) {
  switch (code) {
    case approvalsSvc.CODES.INVALID_INPUT:
      return 400;
    case approvalsSvc.CODES.APPROVAL_NOT_FOUND:
      return 404;
    case approvalsSvc.CODES.APPROVAL_NOT_PENDING:
    case approvalsSvc.CODES.APPROVAL_NOT_APPROVED:
    case approvalsSvc.CODES.APPROVAL_TERMINAL:
    case approvalsSvc.CODES.APPROVAL_CONSUMPTION_DEADLINE_PASSED:
    case approvalsSvc.CODES.CONCURRENT_MUTATION:
    case approvalsSvc.CODES.DISABLED_MODE_NO_MANUAL_APPROVE:
      return 409;
    case approvalsSvc.CODES.APPROVER_SAME_AS_REQUESTER:
    case approvalsSvc.CODES.WINDOW_NOT_ELAPSED:
    case approvalsSvc.CODES.STEPUP_NOT_VERIFIED:
      return 403;
    default:
      return 500;
  }
}

/**
 * Phase-2 of the gate: actually mutate the row to 'consumed'. Called
 * AFTER the chain RESTORE_REQUEST entry exists so we have its id.
 *
 * For 'disabled' mode this also creates the approval row (auto-
 * approved with method='disabled-mode-bypass') first.
 *
 * Throws ApprovalConsumeError with httpStatus + body on failure.
 * Returns { approvalRow, consumeResult } on success.
 */
function consumeApprovalGated(db, {
  preValidateResult,
  backup,
  userId,
  body,
  ip,
  chainRequestEntryId,
  mode,
}) {
  let approvalRow = preValidateResult.approvalRow;

  if (preValidateResult.autoCreate) {
    // disabled mode: createApprovalRequest yields a row already in
    // status='approved' with approval_method='disabled-mode-bypass'.
    try {
      approvalRow = approvalsSvc.createApprovalRequest(db, {
        backup_id: backup.id,
        requested_by_user_id: userId,
        request_reason: (body && typeof body.reason === 'string')
          ? body.reason.slice(0, 1024)
          : 'disabled-mode auto-approval at restore time',
        client_ip: ip,
      });
      auditLog(
        userId,
        'RESTORE_APPROVAL_AUTO_APPROVED',
        `backup=${backup.id} approval=${approvalRow.id} method=disabled-mode-bypass mode=disabled`,
        ip,
      );
    } catch (err) {
      logger.error('disabled-mode auto-approval create failed', {
        backupId: backup.id, error: err.message,
      });
      const code = (err && err.code) || 'CREATE_APPROVAL_FAILED';
      throw new ApprovalConsumeError(500, {
        error: 'failed to record disabled-mode bypass approval',
        detail: err.message,
        code,
      });
    }
  }

  // Now consume. Defense-in-depth: the service re-checks consumption
  // deadline and the row's current status (approved + not consumed).
  let consumeResult;
  try {
    consumeResult = approvalsSvc.consumeApproval(db, {
      id: approvalRow.id,
      chain_request_entry_id: chainRequestEntryId,
    });
  } catch (err) {
    if (err instanceof approvalsSvc.ApprovalError) {
      auditLog(
        userId,
        'RESTORE_APPROVAL_CONSUME_FAILED',
        `backup=${backup.id} approval=${approvalRow.id} code=${err.code} chain_request_entry=${chainRequestEntryId} mode=${mode}`,
        ip,
      );
      throw new ApprovalConsumeError(approvalCodeToHttpStatus(err.code), {
        error: err.message,
        code: err.code,
        detail: err.detail,
      });
    }
    logger.error('approval consume unexpected error', {
      approvalId: approvalRow.id, error: err.message,
    });
    throw new ApprovalConsumeError(500, {
      error: 'approval consume failed unexpectedly',
      detail: err.message,
    });
  }

  auditLog(
    userId,
    'RESTORE_APPROVAL_CONSUMED',
    `backup=${backup.id} approval=${approvalRow.id} method=${approvalRow.approval_method || consumeResult.approval_method || 'unknown'} chain_request_entry=${chainRequestEntryId} mode=${mode}`,
    ip,
  );

  return { approvalRow, consumeResult };
}

// ── List Restore Points ──────────────────────────────────────────────────────
router.get('/points', (req, res) => {
  try {
    const db = getDb();
    const backups = db.prepare(`
      SELECT id, type, size_bytes, file_path, sha256_hash, status, created_at,
             format_version, manifest_path, archive_path, manifest_sig_path,
             wrapped_key_path, signing_key_id
      FROM backups
      WHERE status = 'verified'
      ORDER BY created_at DESC
      LIMIT 30
    `).all();
    const configs = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'config_snapshot_%' ORDER BY key DESC").all();
    db.close();

    const configSnapshots = configs.map(c => {
      try {
        const data = JSON.parse(c.value);
        return { id: c.key.replace('config_snapshot_', ''), name: data.name, createdAt: data.createdAt, createdBy: data.createdBy };
      } catch { return null; }
    }).filter(Boolean);

    res.json({
      backups: backups.map(b => ({
        id: b.id,
        type: b.type,
        format_version: b.format_version,
        sizeMB: b.size_bytes ? (b.size_bytes / 1024 / 1024).toFixed(2) : null,
        hash: b.sha256_hash ? b.sha256_hash.slice(0, 16) + '…' : null,
        status: b.status,
        createdAt: b.created_at,
      })),
      configSnapshots,
    });
  } catch (err) {
    logger.error('List restore points error', { error: err.message });
    res.status(500).json({ error: 'Failed to list restore points' });
  }
});

// ── Preview Restore ──────────────────────────────────────────────────────────
//
// Format-aware. v1 reports just whether the .db file is on disk. v2
// reports per-file presence and (if all files present) the manifest's
// metadata so the operator can see what they're about to restore.
//
// Preview surfaces the configured approval policy (mode + window) so
// the MC can render the correct UI -- "request approval first" vs
// "ready to restore" vs "disabled mode" -- without a separate round
// trip. Preview does NOT itself trigger any approval state changes.
router.get('/preview/:id', (req, res) => {
  try {
    const db = getDb();
    const backup = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);
    const policySnapshot = approvalPolicy.getConfig(db);
    db.close();

    if (!backup) return res.status(404).json({ error: 'Backup not found' });
    if (backup.status !== 'verified') return res.status(400).json({ error: 'Backup not verified — cannot restore' });

    const baseApprovalInfo = {
      mode: policySnapshot.mode,
      window_hours: policySnapshot.window_hours,
      approval_required: policySnapshot.mode !== 'disabled',
    };

    if (backup.format_version === 1) {
      const fileExists = fs.existsSync(backup.file_path || '');
      return res.json({
        id: backup.id,
        type: backup.type,
        format_version: 1,
        createdAt: backup.created_at,
        sizeMB: backup.size_bytes ? (backup.size_bytes / 1024 / 1024).toFixed(2) : null,
        hash: backup.sha256_hash,
        fileExists,
        approval: baseApprovalInfo,
        warning: 'Restoring will replace the current database with this backup. This action is irreversible. A pre-restore backup will be created automatically.',
      });
    }

    if (backup.format_version === 2) {
      const filesOnDisk = {
        manifest:   { path: backup.manifest_path,     exists: !!backup.manifest_path     && fs.existsSync(backup.manifest_path) },
        archive:    { path: backup.archive_path,      exists: !!backup.archive_path      && fs.existsSync(backup.archive_path) },
        signature:  { path: backup.manifest_sig_path, exists: !!backup.manifest_sig_path && fs.existsSync(backup.manifest_sig_path) },
        wrappedKey: { path: backup.wrapped_key_path,  exists: !!backup.wrapped_key_path  && fs.existsSync(backup.wrapped_key_path) },
      };
      const allPresent = Object.values(filesOnDisk).every(f => f.exists);

      // If the manifest is on disk, parse it for richer preview info.
      // Don't fail the whole preview on parse errors -- just return the
      // structural state.
      let manifestPreview = null;
      let manifestParseError = null;
      if (filesOnDisk.manifest.exists) {
        try {
          const bytes = fs.readFileSync(backup.manifest_path);
          const m = manifestSvc.parse(bytes);
          const v = manifestSvc.validateStructure(m);
          if (!v.ok) {
            manifestParseError = v.error;
          } else {
            manifestPreview = {
              backup_id:                  m.backup_id,
              backup_type:                m.backup_type,
              created_at:                 m.created_at,
              encryption:                 m.encryption,
              compression:                m.compression,
              key_wrapping:               m.key_wrapping,
              source_fuse_counter:        m.source_db.fuse_counter_at_creation,
              source_schema_version:      m.source_db.schema_version,
              archive_size_bytes:         manifestSvc.getFileEntry(m, manifestSvc.ARCHIVE_FILENAME)?.sizeBytes ?? null,
              wrapped_key_size_bytes:     manifestSvc.getFileEntry(m, manifestSvc.WRAPPED_KEY_FILENAME)?.sizeBytes ?? null,
            };
          }
        } catch (err) {
          manifestParseError = err.message;
        }
      }

      return res.json({
        id: backup.id,
        type: backup.type,
        format_version: 2,
        createdAt: backup.created_at,
        sizeMB: backup.size_bytes ? (backup.size_bytes / 1024 / 1024).toFixed(2) : null,
        manifestSha256: backup.sha256_hash,
        signing_key_id: backup.signing_key_id,
        filesOnDisk,
        allPresent,
        manifestPreview,
        manifestParseError,
        approval: baseApprovalInfo,
        warning: 'Restoring will replace the current database with this backup. This action is irreversible. A pre-restore backup will be created automatically. The server must be restarted after restore to ensure all in-memory state reflects the restored database.',
      });
    }

    return res.status(500).json({ error: 'Unknown backup format', format_version: backup.format_version });
  } catch (err) {
    logger.error('Preview restore error', { error: err.message });
    res.status(500).json({ error: 'Failed to preview restore' });
  }
});

// ── Execute Restore ──────────────────────────────────────────────────────────
//
// Format-aware. The confirmation gate uses the first 8 hex chars of
// backups.sha256_hash for both formats (which means manifest hash for
// v2 rows, .db hash for v1 rows -- both are 64-char hex strings, both
// work the same way for confirmation).
//
// Pre-restore backup is a raw .db copy of the CURRENT live database
// state, regardless of which format is being restored from. This is
// an emergency recoverability backstop, not a long-term backup;
// recovery from it is rare and the format-quality concerns that drive
// v2 don't apply.
//
// Approval gate (R3d-4 part 2 commit 16):
//   - Reads policy mode from system_meta.
//   - In strict / delayed-self-approval, requires body.approval_id;
//     pre-validates row (backup match, requester match, status=approved)
//     before any chain or destructive work.
//   - In disabled mode, auto-creates an approval row with
//     method='disabled-mode-bypass' to keep the audit trail uniform.
//   - Appends RESTORE_REQUEST chain entry, then consumeApproval with
//     chain_request_entry_id linkage. consumeApproval re-checks
//     consumption deadline as defense-in-depth.
//   - Failure of consumeApproval refuses the restore. The chain entry
//     remains; REQUEST without COMPLETE is the forensic signature of
//     an aborted/refused restore -- intended behavior.
router.post('/execute/:id', async (req, res) => {
  const { confirmHash } = req.body;

  // Resolve the acting user up front. The audit middleware tolerates a
  // null user but the approval gate cannot -- a destructive operation
  // without a known actor is exactly what the gate exists to prevent.
  const userId = req.user && typeof req.user.id === 'string' ? req.user.id : null;
  if (!userId) {
    return res.status(401).json({
      error: 'authentication required for restore',
      code: 'AUTH_REQUIRED',
    });
  }

  try {
    const db = getDb();
    // B6j-4: capture the anti-rollback fuse high-water from the LIVE DB before the
    // restore overwrites it, so the post-restore fixup can ratchet it forward.
    let preFuseHighWater = null;
    try { preFuseHighWater = readHighWater(db); } catch (_e) { /* live DB may predate node_state */ }
    const backup = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);

    if (!backup) { db.close(); return res.status(404).json({ error: 'Backup not found' }); }
    if (backup.status !== 'verified') { db.close(); return res.status(400).json({ error: 'Backup not verified' }); }

    // Confirmation gate
    if (confirmHash !== backup.sha256_hash?.slice(0, 8)) {
      db.close();
      return res.status(400).json({
        error: 'Confirmation required. Send { confirmHash: "<first 8 chars of backup hash>" }',
        hint: backup.sha256_hash?.slice(0, 8),
      });
    }

    // ── R3l C66: chain restore redirect ───────────────────────────────────
    //
    // Incremental and differential backups can't be restored standalone
    // by this endpoint — they need their parent chain walked, validated,
    // and replayed in order. The new POST /api/restore/execute-chain/:id
    // endpoint handles that case end-to-end with the same approval gate
    // and audit log semantics as this endpoint, but uses
    // services/restore-chain.js (walkChain + validateChain + replayChain)
    // instead of the single-archive flow below.
    //
    // Returning 400 here with a structured pointer (rather than transparently
    // proxying to the chain endpoint) keeps the API contract honest:
    // clients calling /execute/:id with a chain backup are expressing an
    // incorrect assumption about how the backup is structured. The
    // response includes the strategy + parent_backup_id so a UI can
    // automatically retry against /execute-chain/:id if appropriate.
    if (backup.format_version === 2
        && (backup.backup_strategy === 'incremental' || backup.backup_strategy === 'differential')) {
      db.close();
      return res.status(400).json({
        error: 'chain restore required for this backup',
        code: 'CHAIN_RESTORE_REQUIRED',
        strategy: backup.backup_strategy,
        parent_backup_id: backup.parent_backup_id,
        parent_full_backup_id: backup.parent_full_backup_id,
        hint: `Use POST /api/restore/execute-chain/${req.params.id} with the same { confirmHash, approval_id? } body to restore the full chain.`,
      });
    }

    // ── Approval gate phase 1: pre-validation ────────────────────────────
    //
    // Cheap reads only; no row mutation. Refuses early on obvious
    // failures (no approval_id, wrong backup, wrong requester, not
    // approved). Disabled-mode short-circuits with autoCreate=true and
    // defers row creation to phase 2.
    const policyMode = approvalPolicy.getMode(db);
    const preValidate = preValidateApproval(db, {
      backup,
      userId,
      body: req.body,
      mode: policyMode,
      ip: req.ip,
    });
    if (!preValidate.ok) {
      db.close();
      return res.status(preValidate.status).json(preValidate.body);
    }

    // ── v1 path ──────────────────────────────────────────────────────────
    if (backup.format_version === 1) {
      if (!fs.existsSync(backup.file_path)) {
        db.close();
        return res.status(400).json({ error: 'Backup file not found on disk' });
      }

      // Verify v1 integrity BEFORE any destructive work or approval
      // consume. If the on-disk file has been tampered, fail loud
      // without spending the approval.
      const fileBuffer = fs.readFileSync(backup.file_path);
      const currentHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
      if (currentHash !== backup.sha256_hash) {
        db.close();
        return res.status(400).json({ error: 'Backup integrity check failed — file has been modified since verification' });
      }

      // Append RESTORE_REQUEST chain entry. v1 backups predate the
      // chain CREATE step, so there's no integrity precondition to
      // verify (verifyChainUpToBackup would return no_create_entry).
      // The RESTORE_REQUEST entry is still meaningful: it documents
      // the destructive intent in the tamper-evident chain regardless
      // of whether the source backup itself is chain-anchored.
      let restoreRequestEntry = null;
      try {
        const result = chainSvc.appendChainEntry(db, {
          eventType: 'RESTORE_REQUEST',
          backupId: backup.id,
          actorUserId: userId,
          payload: {
            restore_initiated_at: new Date().toISOString(),
            backup_format_version: 1,
            backup_created_at: backup.created_at,
          },
        });
        restoreRequestEntry = {
          id: result.id,
          this_hash: result.thisHash,
          created_at: result.createdAt,
        };
      } catch (chainErr) {
        db.close();
        logger.error('chain RESTORE_REQUEST append failed (v1); refusing restore', {
          backupId: backup.id, error: chainErr.message,
        });
        return res.status(500).json({
          error: 'v1 chain RESTORE_REQUEST append failed; restore refused',
          detail: chainErr.message,
          hint: 'Cannot record restore intent in the chain. Refusing destructive operation. Investigate the chain-signing-keys configuration and retry.',
        });
      }

      // Approval gate phase 2: consume.
      let approvalConsumeResult, approvalRowFinal;
      try {
        const consumed = consumeApprovalGated(db, {
          preValidateResult: preValidate,
          backup,
          userId,
          body: req.body,
          ip: req.ip,
          chainRequestEntryId: restoreRequestEntry.id,
          mode: policyMode,
        });
        approvalRowFinal = consumed.approvalRow;
        approvalConsumeResult = consumed.consumeResult;
      } catch (err) {
        db.close();
        if (err instanceof ApprovalConsumeError) {
          return res.status(err.httpStatus).json(err.body);
        }
        throw err;
      }

      db.close();

      // Pre-restore raw copy of CURRENT live DB.
      const { DB_PATH } = require('../db/init');
      const preRestorePath = path.join(path.dirname(backup.file_path), `pre-restore-${Date.now()}.db`);
      fs.copyFileSync(DB_PATH, preRestorePath);

      // Destructive write.
      fs.copyFileSync(backup.file_path, DB_PATH);

      // Append RESTORE_COMPLETE on the restored chain. Same degraded-
      // mode semantics as the v2 path: append failure is logged but
      // the restore is reported successful.
      let restoreCompleteEntry = null;
      let restoreCompleteError = null;
      try {
        const newDb = getDb();
        try {
          // B6j-4: repair node-local posture on the RESTORED DB before the restart
          // prompt -- ratchet the fuse high-water to max(pre,restored) so a restore
          // can never lower it, and force-lock config (D6). db-init at restart will
          // not override it. Audited on the same handle to avoid a second connection.
          const posture = applyPostRestorePosture(newDb, { preFuseHighWater });
          appendAuditEntry(newDb, { userId, eventType: 'POST_RESTORE_POSTURE_APPLIED', detail: `format=v1 fuse_high_water=${posture.fuseHighWater} pre=${posture.fusePre} restored=${posture.fuseRestored} config_force_locked=${posture.configForceLocked}`, ip: req.ip });
          const result = chainSvc.appendChainEntry(newDb, {
            eventType: 'RESTORE_COMPLETE',
            backupId: backup.id,
            actorUserId: userId,
            payload: {
              restore_completed_at: new Date().toISOString(),
              backup_format_version: 1,
              pre_restore_filename: path.basename(preRestorePath),
              backup_created_at: backup.created_at,
              source_chain_request_entry_id: restoreRequestEntry.id,
              source_chain_request_this_hash: restoreRequestEntry.this_hash,
              approval_id: approvalRowFinal.id,
              approval_method: approvalRowFinal.approval_method || approvalConsumeResult.approval_method || 'unknown',
            },
          });
          restoreCompleteEntry = {
            id: result.id,
            this_hash: result.thisHash,
            created_at: result.createdAt,
          };
        } finally {
          newDb.close();
        }
      } catch (chainErr) {
        restoreCompleteError = chainErr.message;
        logger.error(
          'chain RESTORE_COMPLETE append failed (v1; restore itself succeeded). ' +
          'Audit log preserves the event but the restored chain is missing the head annotation.',
          { backupId: backup.id, error: chainErr.message },
        );
      }

      auditLog(
        userId,
        'DATABASE_RESTORED',
        `backup=${backup.id} format=v1 from=${backup.created_at} pre-restore=${path.basename(preRestorePath)} approval=${approvalRowFinal.id} method=${approvalRowFinal.approval_method || 'unknown'}`,
        req.ip,
      );
      logger.warn('DATABASE RESTORED (v1)', {
        backupId: backup.id, from: backup.created_at, approvalId: approvalRowFinal.id,
      });

      return res.json({
        ok: true,
        format_version: 1,
        message: 'Database restored successfully. A pre-restore backup was saved.',
        preRestorePath: path.basename(preRestorePath),
        restoredFrom: backup.created_at,
        approval: {
          id: approvalRowFinal.id,
          method: approvalRowFinal.approval_method || approvalConsumeResult.approval_method || null,
          mode_at_creation: approvalRowFinal.approval_mode_at_creation,
          consumed_at: approvalConsumeResult.consumed_at,
        },
        chain: {
          request_entry: restoreRequestEntry,
          complete_entry: restoreCompleteEntry,
          complete_error: restoreCompleteError,
        },
        note: 'The server should be restarted to ensure all in-memory state reflects the restored database.',
      });
    }

    // ── v2 path ──────────────────────────────────────────────────────────
    if (backup.format_version === 2) {
      // 1. All four files present
      const filePaths = {
        manifest:   backup.manifest_path,
        archive:    backup.archive_path,
        signature:  backup.manifest_sig_path,
        wrappedKey: backup.wrapped_key_path,
      };
      for (const [label, p] of Object.entries(filePaths)) {
        if (!p || !fs.existsSync(p)) {
          db.close();
          return res.status(400).json({
            error: `v2 backup ${label} file missing on disk`,
            missing: label,
            expectedPath: p,
          });
        }
      }

      // 1b. R3d-2 PRECONDITION: chain integrity verified up to this
      //     backup's CREATE entry. Refuses the restore if the chain
      //     is broken anywhere from genesis to the backup's CREATE
      //     entry (inclusive). Partial-chain semantics: a chain
      //     break AFTER the backup's CREATE entry does NOT block
      //     this restore (the backup's provenance was committed
      //     before the break and is still attestable).
      //
      //     Failure here is FATAL. Unlike chain append at backup
      //     creation time (where degraded mode is OK because the
      //     alternative is no backups), here the alternative is
      //     simply declining the restore until chain integrity is
      //     restored. SOC operators must investigate before
      //     destructively replacing the live DB. There is
      //     deliberately no `?force=true` override -- forcing is
      //     a future feature when a real recovery scenario
      //     justifies it.
      //
      //     If the backup has no CREATE entry at all (e.g. it was
      //     created during a chain-keypair outage in degraded
      //     mode), the chain check returns no_create_entry and
      //     the restore is refused with a precise error so the
      //     operator can decide whether to investigate.
      const chainCheck = chainSvc.verifyChainUpToBackup(db, backup.id);
      if (!chainCheck.ok) {
        db.close();
        auditLog(
          userId,
          'RESTORE_REFUSED_CHAIN_BROKEN',
          `backup=${backup.id} reason=${chainCheck.reason} brokenAtId=${chainCheck.brokenAtId || 'none'}`,
          req.ip,
        );
        return res.status(409).json({
          error: 'v2 chain integrity precondition failed -- restore refused',
          chain: {
            ok: false,
            reason: chainCheck.reason,
            brokenAtId: chainCheck.brokenAtId,
            entriesVerified: chainCheck.entriesVerified,
            detail: chainCheck.detail,
          },
          remediation: chainCheck.reason === 'no_create_entry'
            ? 'This backup has no CREATE entry in the chain. It may have been created during a chain-keypair outage (degraded mode). Investigate the chain history before restoring.'
            : 'The chain has been tampered or has become inconsistent before/at this backup. Investigate the chain (admin: GET /api/backup-chain/verify) before restoring.',
        });
      }

      // 2. Read all four
      const manifestBytes   = fs.readFileSync(filePaths.manifest);
      const signature       = fs.readFileSync(filePaths.signature);
      const archiveBytes    = fs.readFileSync(filePaths.archive);
      const wrappedKeyBytes = fs.readFileSync(filePaths.wrappedKey);

      // 3. Verify manifest hash matches the row's stored hash
      const manifestSha = crypto.createHash('sha256').update(manifestBytes).digest('hex');
      if (manifestSha !== backup.sha256_hash) {
        db.close();
        return res.status(400).json({
          error: 'v2 manifest hash mismatch with backups.sha256_hash',
          stored: backup.sha256_hash,
          actual: manifestSha,
        });
      }

      // 4. Parse + validate manifest. Has to come BEFORE signature
      //    verification because v3 sigs are looked up by the
      //    fingerprint embedded in the manifest itself; we must
      //    parse to extract it. JSON.parse is hardened against
      //    arbitrary input (no code-exec risk) so trusting the
      //    parse step before the sig-verify step is safe;
      //    validateStructure additionally rejects malformed
      //    manifests before we try to use any field.
      let manifest;
      try {
        manifest = manifestSvc.parse(manifestBytes);
      } catch (parseErr) {
        db.close();
        return res.status(400).json({ error: 'v2 manifest unparseable', detail: parseErr.message });
      }
      const validation = manifestSvc.validateStructure(manifest);
      if (!validation.ok) {
        db.close();
        return res.status(400).json({ error: 'v2 manifest structurally invalid', detail: validation.error });
      }

      // 5. Verify Ed25519 signature against the public key whose
      //    fingerprint is embedded in the manifest. Cross-deployment-
      //    safe path: a backup created here resolves to our own
      //    active key by fingerprint; a backup created elsewhere
      //    resolves only if an admin has registered the foreign
      //    deployment's public key. Local restore is always the
      //    same-deployment case (operators don't restore foreign
      //    backups via the local-backup table -- that's what
      //    external-restore is for) but the verification path is
      //    the same for consistency and so the audit log carries
      //    the fingerprint.
      const signingKeyFingerprint = manifest.signing_key_fingerprint;
      const sigValid = signingKeysSvc.verifyManifestByFingerprint(db, manifestBytes, signature, signingKeyFingerprint);
      if (!sigValid) {
        db.close();
        return res.status(400).json({
          error: 'v2 manifest signature verification failed',
          signing_key_id: backup.signing_key_id,
          signing_key_fingerprint: signingKeyFingerprint,
        });
      }

      // 6. Verify in-manifest file hashes match actual bytes
      const archiveSha = crypto.createHash('sha256').update(archiveBytes).digest('hex');
      const archiveEntry = manifestSvc.getFileEntry(manifest, manifestSvc.ARCHIVE_FILENAME);
      if (!archiveEntry || archiveSha !== archiveEntry.sha256) {
        db.close();
        return res.status(400).json({
          error: 'v2 archive file hash mismatch with manifest',
          manifestHash: archiveEntry ? archiveEntry.sha256 : null,
          actualHash: archiveSha,
        });
      }

      const wrappedSha = crypto.createHash('sha256').update(wrappedKeyBytes).digest('hex');
      const wrappedEntry = manifestSvc.getFileEntry(manifest, manifestSvc.WRAPPED_KEY_FILENAME);
      if (!wrappedEntry || wrappedSha !== wrappedEntry.sha256) {
        db.close();
        return res.status(400).json({
          error: 'v2 wrapped-key file hash mismatch with manifest',
          manifestHash: wrappedEntry ? wrappedEntry.sha256 : null,
          actualHash: wrappedSha,
        });
      }

      // 7b. R3d-2: append RESTORE_REQUEST entry to the chain BEFORE
      //     destructive work begins. Records intent in the audit
      //     trail so a REQUEST with no following COMPLETE is
      //     forensically detectable as a failed/aborted restore.
      //
      //     Failure to append RESTORE_REQUEST is FATAL -- unlike at
      //     backup creation time, the restore has not yet started
      //     destructive work, so there is no "preserve recoverability"
      //     argument for degraded mode. If we cannot record intent,
      //     we should not proceed with destructive operation.
      let restoreRequestEntry = null;
      try {
        const result = chainSvc.appendChainEntry(db, {
          eventType: 'RESTORE_REQUEST',
          backupId: backup.id,
          actorUserId: userId,
          payload: {
            restore_initiated_at: new Date().toISOString(),
            backup_signing_key_id: backup.signing_key_id,
            backup_signing_key_fingerprint: signingKeyFingerprint,
            backup_created_at: backup.created_at,
            backup_chain_create_entry_id: chainCheck.chainEntryId,
          },
        });
        restoreRequestEntry = {
          id: result.id,
          this_hash: result.thisHash,
          created_at: result.createdAt,
        };
      } catch (chainErr) {
        db.close();
        logger.error('chain RESTORE_REQUEST append failed; refusing restore', {
          backupId: backup.id,
          error: chainErr.message,
        });
        return res.status(500).json({
          error: 'v2 chain RESTORE_REQUEST append failed; restore refused',
          detail: chainErr.message,
          hint: 'Cannot record restore intent in the chain. Restoring without recording intent would create an unauditable destructive operation. Investigate the chain-signing-keys configuration and retry.',
        });
      }

      // 7c. Approval gate phase 2: consume.
      //
      //     The chain RESTORE_REQUEST entry is now committed; consume
      //     references its id. If consume fails (deadline expired,
      //     concurrent mutation, etc.), refuse the restore. The
      //     chain entry remains -- REQUEST without COMPLETE is the
      //     forensic signature of an aborted restore.
      let approvalConsumeResult, approvalRowFinal;
      try {
        const consumed = consumeApprovalGated(db, {
          preValidateResult: preValidate,
          backup,
          userId,
          body: req.body,
          ip: req.ip,
          chainRequestEntryId: restoreRequestEntry.id,
          mode: policyMode,
        });
        approvalRowFinal = consumed.approvalRow;
        approvalConsumeResult = consumed.consumeResult;
      } catch (err) {
        db.close();
        if (err instanceof ApprovalConsumeError) {
          return res.status(err.httpStatus).json(err.body);
        }
        throw err;
      }

      db.close();

      // 7. Unwrap the ephemeral key
      let ephemeralKey;
      try {
        ephemeralKey = await keyWrapSvc.unwrapKey(
          wrappedKeyBytes,
          manifest.key_wrapping.scheme,
          manifest.key_wrapping.kek_reference,
        );
      } catch (unwrapErr) {
        return res.status(500).json({
          error: 'v2 ephemeral key unwrap failed',
          detail: unwrapErr.message,
          hint: 'Most often this means TIER1_ENCRYPTION_KEY (or the manifest-recorded KEK) has changed since this backup was created. Restoring requires the same KEK that was used to encrypt.',
        });
      }

      // 8. Extract archive (AES-GCM decrypt -> zstd decompress -> untar)
      let extracted;
      try {
        extracted = await archiveSvc.extractArchive(archiveBytes, ephemeralKey);
      } catch (extractErr) {
        return res.status(500).json({
          error: 'v2 archive extraction failed',
          detail: extractErr.message,
        });
      }
      if (extracted.name !== 'firealive.db') {
        return res.status(500).json({
          error: 'v2 archive contains unexpected file',
          expected: 'firealive.db',
          actual: extracted.name,
        });
      }

      // 8b. Layer-2 EDR scan of the extracted SQLite bytes. Mandatory:
      //     defense-in-depth even though the local backup is signed by
      //     this deployment's chain-signing key. Catches the case
      //     where an attacker with local code-exec replaced or
      //     modified backup files between creation and restore, and
      //     prevents the restore path from being used as a malware-
      //     delivery channel into a host that's otherwise been
      //     hardened against direct uploads. Three FATAL refusal
      //     conditions, all enforced before the destructive pre-
      //     restore snapshot:
      //
      //       skipped:true             -> SCANNER_NOT_CONFIGURED
      //       clean:false + threats[]  -> MALWARE_DETECTED
      //       clean:false + no threats -> SCAN_FAILED (fail-safe)
      //
      //     Uses a temp db handle because the restore-handler db was
      //     closed at the consume step to release the file lock for
      //     atomic-rename, and IntegrationManager queries the
      //     malware_scanner_integrations registry.
      let scanResult;
      {
        const scanDb = getDb();
        try {
          const mgr = new IntegrationManager(scanDb);
          try {
            scanResult = await mgr.inspectFile(
              extracted.payload,
              'firealive.db',
              'application/x-sqlite3',
            );
          } catch (scanErr) {
            return res.status(500).json({
              error: 'v2 malware scan threw',
              detail: scanErr.message,
              code: 'SCAN_FAILED',
            });
          }
        } finally {
          try { scanDb.close(); } catch { /* best effort */ }
        }
      }
      if (scanResult.skipped === true) {
        auditLog(
          userId,
          'RESTORE_REJECTED_NO_SCANNER',
          `backup=${backup.id} format=v2 reason=no_scanner_configured`,
          req.ip,
        );
        return res.status(422).json({
          error: 'restore requires at least one configured malware scanner. Configure one under MC > Malware Scanners and retry.',
          code: 'SCANNER_NOT_CONFIGURED',
        });
      }
      if (scanResult.clean !== true) {
        const threats = Array.isArray(scanResult.threats) ? scanResult.threats : [];
        if (threats.length > 0) {
          auditLog(
            userId,
            'RESTORE_REJECTED_MALWARE',
            `backup=${backup.id} format=v2 scan_id=${scanResult.scanId || 'null'} provider=${scanResult.provider || 'null'} threats=${threats.join(',')}`,
            req.ip,
          );
          return res.status(422).json({
            error: 'malware detected in extracted backup bytes',
            code: 'MALWARE_DETECTED',
            threats,
            scan_id: scanResult.scanId || null,
            provider: scanResult.provider || null,
          });
        }
        auditLog(
          userId,
          'RESTORE_REJECTED_SCAN_FAILED',
          `backup=${backup.id} format=v2 scan_id=${scanResult.scanId || 'null'} no_authoritative_result`,
          req.ip,
        );
        return res.status(500).json({
          error: 'malware scan did not produce an authoritative clean result (all configured scanners errored)',
          code: 'SCAN_FAILED',
          scan_id: scanResult.scanId || null,
        });
      }

      // 9. Pre-restore raw copy of CURRENT live DB state
      const { DB_PATH } = require('../db/init');
      const preRestoreDir = path.dirname(DB_PATH);
      const preRestorePath = path.join(preRestoreDir, `pre-restore-${Date.now()}.db`);
      fs.copyFileSync(DB_PATH, preRestorePath);

      // 10. Write recovered .db bytes to a temp file, then atomic-rename
      // over DB_PATH. Atomic rename ensures DB_PATH is never partially
      // written even if the process crashes mid-write.
      const tempDbPath = path.join(preRestoreDir, `.restore-${Date.now()}.db.tmp`);
      try {
        fs.writeFileSync(tempDbPath, extracted.payload);
        fs.renameSync(tempDbPath, DB_PATH);
      } catch (writeErr) {
        // Cleanup temp file if the rename failed
        try { fs.unlinkSync(tempDbPath); } catch { /* ignore */ }
        return res.status(500).json({
          error: 'v2 restore write failed',
          detail: writeErr.message,
        });
      }

      // 11. R3d-2: append RESTORE_COMPLETE entry to the RESTORED
      //     chain. Note this opens a NEW DB connection -- the live
      //     DB at DB_PATH is now the restored database (atomic
      //     rename happened in step 10). The chain in the restored
      //     DB has whatever entries existed at backup-creation time.
      //     This COMPLETE entry chains forward from that historical
      //     head, signed by the restored DB's chain-signing key
      //     (which is also the key that was active at backup-
      //     creation time).
      //
      //     Forensic semantics: a future operator inspecting the
      //     restored DB's chain sees a RESTORE_COMPLETE entry at
      //     the head documenting that this database was restored
      //     from the named backup at the recorded time. The OLD
      //     chain (which had the RESTORE_REQUEST and the consumed
      //     approval row) has been overwritten -- but the audit
      //     log (separate table, also overwritten) preserved the
      //     REQUEST + CONSUME records up to the moment of the
      //     atomic rename, and the pre-restore.db preserves the
      //     full pre-restore state including the consumed approval
      //     row for forensic reconstruction.
      //
      //     Failure to append RESTORE_COMPLETE is DEGRADED-MODE.
      //     The restore has succeeded; the live DB is the restored
      //     state. Refusing to surface that to the user because
      //     we couldn't write a chain entry would be perverse.
      //     Loud log + chain_complete_error in the response.
      let restoreCompleteEntry = null;
      let restoreCompleteError = null;
      try {
        const newDb = getDb();
        try {
          // B6j-4: repair node-local posture on the RESTORED DB (see the v1 path).
          const posture = applyPostRestorePosture(newDb, { preFuseHighWater });
          appendAuditEntry(newDb, { userId, eventType: 'POST_RESTORE_POSTURE_APPLIED', detail: `format=v2 fuse_high_water=${posture.fuseHighWater} pre=${posture.fusePre} restored=${posture.fuseRestored} config_force_locked=${posture.configForceLocked}`, ip: req.ip });
          const result = chainSvc.appendChainEntry(newDb, {
            eventType: 'RESTORE_COMPLETE',
            backupId: backup.id,
            actorUserId: userId,
            payload: {
              restore_completed_at: new Date().toISOString(),
              restored_db_size_bytes: extracted.payload.length,
              pre_restore_filename: path.basename(preRestorePath),
              backup_signing_key_id: backup.signing_key_id,
              backup_signing_key_fingerprint: signingKeyFingerprint,
              backup_created_at: backup.created_at,
              source_chain_request_entry_id: restoreRequestEntry ? restoreRequestEntry.id : null,
              source_chain_request_this_hash: restoreRequestEntry ? restoreRequestEntry.this_hash : null,
              approval_id: approvalRowFinal.id,
              approval_method: approvalRowFinal.approval_method || approvalConsumeResult.approval_method || 'unknown',
              malware_scan: {
                clean: scanResult.clean === true,
                scan_id: scanResult.scanId || null,
                provider: scanResult.provider || null,
                mode: scanResult.mode || null,
                latency_ms: scanResult.latencyMs || 0,
                inspector_version: scanResult.inspectorVersion || null,
                scanners: Array.isArray(scanResult.scanners)
                  ? scanResult.scanners.map(s => ({
                      id: s.id || null,
                      provider_type: s.provider_type || null,
                      clean: s.clean === true,
                      scan_id: s.scanId || null,
                      latency_ms: s.latencyMs || 0,
                      attempted: s.attempted === true,
                      error: s.error || null,
                    }))
                  : [],
              },
            },
          });
          restoreCompleteEntry = {
            id: result.id,
            this_hash: result.thisHash,
            created_at: result.createdAt,
          };
        } finally {
          newDb.close();
        }
      } catch (chainErr) {
        restoreCompleteError = chainErr.message;
        logger.error(
          'chain RESTORE_COMPLETE append failed (restore itself succeeded). ' +
          'The restored database lacks a chain entry recording the restoration. ' +
          'Audit log preserves the event but the restored chain is missing the head annotation.',
          { backupId: backup.id, error: chainErr.message },
        );
      }

      auditLog(
        userId,
        'DATABASE_RESTORED',
        `backup=${backup.id} format=v2 from=${backup.created_at} signing_key_id=${backup.signing_key_id} signing_key_fingerprint=${signingKeyFingerprint} pre-restore=${path.basename(preRestorePath)} manifest_fuse_counter=${manifest.source_db.fuse_counter_at_creation} approval=${approvalRowFinal.id} method=${approvalRowFinal.approval_method || 'unknown'}`,
        req.ip,
      );
      logger.warn('DATABASE RESTORED (v2)', {
        backupId: backup.id,
        from: backup.created_at,
        signingKeyId: backup.signing_key_id,
        signingKeyFingerprint,
        manifestFuseCounter: manifest.source_db.fuse_counter_at_creation,
        approvalId: approvalRowFinal.id,
      });

      return res.json({
        ok: true,
        format_version: 2,
        message: 'Database restored successfully. A pre-restore backup was saved.',
        preRestorePath: path.basename(preRestorePath),
        restoredFrom: backup.created_at,
        manifestFuseCounter: manifest.source_db.fuse_counter_at_creation,
        sizeBytes: extracted.payload.length,
        approval: {
          id: approvalRowFinal.id,
          method: approvalRowFinal.approval_method || approvalConsumeResult.approval_method || null,
          mode_at_creation: approvalRowFinal.approval_mode_at_creation,
          consumed_at: approvalConsumeResult.consumed_at,
        },
        chain: {
          request_entry: restoreRequestEntry,        // in old (overwritten) chain
          complete_entry: restoreCompleteEntry,      // in new (restored) chain
          complete_error: restoreCompleteError,
        },
        note: 'The server should be restarted to ensure all in-memory state reflects the restored database.',
      });
    }

    db.close();
    return res.status(500).json({ error: 'Unknown backup format', format_version: backup.format_version });
  } catch (err) {
    logger.error('Execute restore error', { error: err.message });
    res.status(500).json({ error: 'Failed to execute restore', message: err.message });
  }
});

// ── R3l C66: Chain Restore (incremental + differential) ───────────────
//
// POST /api/restore/execute-chain/:id
//
// Restore from an incremental or differential backup by walking the
// parent chain back to the anchor full backup, validating every link,
// then replaying the entire chain onto the live DB file. Goes through
// the SAME approval-gate machinery as POST /execute/:id but uses
// services/restore-chain.js for the actual restore mechanics.
//
// Request body:
//   { confirmHash, approval_id? }
// Same shape as /execute/:id. confirmHash MUST match the first 8 chars
// of the LEAF backup's sha256_hash (the one in the URL path), not the
// anchor's; the approval_id (if required by policy) must be issued
// against the leaf as well.
//
// Steps:
//   1. Auth check
//   2. Backup lookup; reject if strategy is not incremental/differential
//   3. Walk the chain
//   4. Confirm hash gate
//   5. Approval pre-validation
//   6. File existence check for every chain link
//   7. validateChain (manifest hashes, signatures, per-page sha256)
//   8. Approval consume (Phase 2)
//   9. Pre-restore snapshot of current DB
//  10. replayChain to live DB path
//  11. Audit log
//  12. Return success response with chain summary
router.post('/execute-chain/:id', async (req, res) => {
  const { confirmHash } = req.body;
  const userId = req.user && typeof req.user.id === 'string' ? req.user.id : null;
  if (!userId) {
    return res.status(401).json({ error: 'authentication required for restore', code: 'AUTH_REQUIRED' });
  }

  let db;
  try {
    db = getDb();
    // B6j-4: capture the anti-rollback fuse high-water from the LIVE DB before the
    // chain replay overwrites it, so the post-restore fixup can ratchet it forward.
    let preFuseHighWater = null;
    try { preFuseHighWater = readHighWater(db); } catch (_e) { /* live DB may predate node_state */ }
    const leaf = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);
    if (!leaf) { db.close(); return res.status(404).json({ error: 'Backup not found' }); }
    if (leaf.status !== 'verified') { db.close(); return res.status(400).json({ error: 'Backup not verified' }); }
    if (leaf.format_version !== 2) {
      db.close();
      return res.status(400).json({ error: 'execute-chain requires format_version=2', strategy: leaf.backup_strategy });
    }
    const strategy = leaf.backup_strategy || 'full';
    if (strategy !== 'incremental' && strategy !== 'differential') {
      db.close();
      return res.status(400).json({
        error: 'execute-chain only supports incremental or differential backups',
        strategy,
        hint: `Use POST /api/restore/execute/${req.params.id} for full or snapshot backups.`,
      });
    }

    // Confirm hash gate (against the LEAF, not the anchor)
    if (confirmHash !== leaf.sha256_hash?.slice(0, 8)) {
      db.close();
      return res.status(400).json({
        error: 'Confirmation required. Send { confirmHash: "<first 8 chars of LEAF backup hash>" }',
        hint: leaf.sha256_hash?.slice(0, 8),
      });
    }

    // Walk the chain
    let chain;
    try {
      chain = restoreChainSvc.walkChain(db, leaf.id);
    } catch (walkErr) {
      db.close();
      return res.status(400).json({
        error: 'cannot walk restore chain',
        detail: walkErr.message,
        code: 'CHAIN_WALK_FAILED',
      });
    }

    // Approval gate pre-validation (uses leaf as the gated backup)
    const policyMode = approvalPolicy.getMode(db);
    const preValidate = preValidateApproval(db, {
      backup: leaf,
      userId,
      body: req.body,
      mode: policyMode,
      ip: req.ip,
    });
    if (!preValidate.ok) {
      db.close();
      return res.status(preValidate.status).json(preValidate.body);
    }

    // Verify every chain link's files exist on disk
    for (const link of chain) {
      const paths = {
        manifest:   link.manifest_path,
        archive:    link.archive_path,
        signature:  link.manifest_sig_path,
        wrappedKey: link.wrapped_key_path,
      };
      for (const [label, p] of Object.entries(paths)) {
        if (!p || !fs.existsSync(p)) {
          db.close();
          return res.status(400).json({
            error: `chain link ${link.id} ${label} file missing on disk`,
            chainLinkId: link.id,
            chainLinkStrategy: link.backup_strategy || 'full',
            missing: label,
            expectedPath: p,
          });
        }
      }
    }

    // Validate the entire chain end-to-end before any destructive work
    let validation;
    try {
      validation = await restoreChainSvc.validateChain(db, chain);
    } catch (validateErr) {
      db.close();
      return res.status(500).json({
        error: 'chain validation crashed',
        detail: validateErr.message,
      });
    }
    if (!validation.ok) {
      db.close();
      return res.status(400).json({
        error: 'chain validation failed',
        code: 'CHAIN_VALIDATION_FAILED',
        validation,
      });
    }

    // Approval consume (Phase 2) — same helper as /execute/:id
    let approvalConsumeResult;
    let approvalRowFinal;
    try {
      const consumed = consumeApprovalGated(db, {
        backup: leaf,
        userId,
        body: req.body,
        mode: policyMode,
        ip: req.ip,
      });
      approvalConsumeResult = consumed.consume_result;
      approvalRowFinal = consumed.approval_row;
    } catch (approvalErr) {
      db.close();
      const status = approvalCodeToHttpStatus(approvalErr.code);
      return res.status(status).json({
        error: approvalErr.message,
        code: approvalErr.code,
        detail: approvalErr.detail || null,
      });
    }

    // Pre-restore snapshot of current DB to backup dir
    const { DB_PATH } = require('../db/init');
    const preRestoreTs = new Date().toISOString().replace(/[:.]/g, '-');
    const preRestoreDir = path.dirname(DB_PATH);
    const preRestorePath = path.join(preRestoreDir, `pre-restore-chain-${preRestoreTs}.db`);
    try {
      fs.copyFileSync(DB_PATH, preRestorePath);
    } catch (preErr) {
      db.close();
      return res.status(500).json({
        error: 'pre-restore snapshot failed; refusing to proceed',
        detail: preErr.message,
      });
    }

    // Close the management DB before we write to its file (better-sqlite3
    // holds the file open; replay writes raw page bytes).
    // We reopen for the audit log after.
    db.close();

    // Replay the chain. Skip validation since we already ran it.
    let replay;
    try {
      replay = await restoreChainSvc.replayChain(getDb(), chain, DB_PATH, { skipValidation: true });
    } catch (replayErr) {
      // Reopen db just for audit logging the failure
      const auditDb = getDb();
      auditLog(
        userId,
        'DATABASE_RESTORE_FAILED',
        `chain leaf=${leaf.id} strategy=${strategy} crashed=true detail=${replayErr.message.slice(0, 120)}`,
        req.ip,
      );
      auditDb.close();
      return res.status(500).json({
        error: 'chain replay crashed',
        detail: replayErr.message,
        preRestorePath: path.basename(preRestorePath),
      });
    }

    if (!replay.ok) {
      const auditDb = getDb();
      auditLog(
        userId,
        'DATABASE_RESTORE_FAILED',
        `chain leaf=${leaf.id} strategy=${strategy} reason=${(replay.error || 'unknown').slice(0, 120)} linksReplayed=${replay.linksReplayed}`,
        req.ip,
      );
      auditDb.close();
      return res.status(500).json({
        error: 'chain replay failed; DB may be in inconsistent state',
        detail: replay.error,
        linksReplayed: replay.linksReplayed,
        framesApplied: replay.framesApplied,
        preRestorePath: path.basename(preRestorePath),
        recoveryHint: `Restore the pre-restore snapshot at ${path.basename(preRestorePath)} to recover the prior database state.`,
      });
    }

    // Success — re-open DB for audit log
    const auditDb = getDb();
    // B6j-4: repair node-local posture on the RESTORED DB (see the /execute paths).
    const posture = applyPostRestorePosture(auditDb, { preFuseHighWater });
    appendAuditEntry(auditDb, { userId, eventType: 'POST_RESTORE_POSTURE_APPLIED', detail: `format=chain fuse_high_water=${posture.fuseHighWater} pre=${posture.fusePre} restored=${posture.fuseRestored} config_force_locked=${posture.configForceLocked}`, ip: req.ip });
    auditLog(
      userId,
      'DATABASE_RESTORED',
      `chain leaf=${leaf.id} anchor=${replay.anchorBackupId} strategy=${strategy} links=${replay.linksReplayed} frames=${replay.framesApplied} pre-restore=${path.basename(preRestorePath)} approval=${approvalRowFinal.id} method=${approvalRowFinal.approval_method || 'unknown'}`,
      req.ip,
    );
    logger.warn('DATABASE RESTORED (chain)', {
      leafBackupId: leaf.id,
      anchorBackupId: replay.anchorBackupId,
      strategy,
      linksReplayed: replay.linksReplayed,
      framesApplied: replay.framesApplied,
      approvalId: approvalRowFinal.id,
    });
    auditDb.close();

    return res.json({
      ok: true,
      format_version: 2,
      restore_kind: 'chain',
      message: 'Database restored successfully from chain. A pre-restore snapshot was saved.',
      preRestorePath: path.basename(preRestorePath),
      leafBackupId: leaf.id,
      anchorBackupId: replay.anchorBackupId,
      strategy,
      chain: chain.map(b => ({
        id: b.id,
        strategy: b.backup_strategy || 'full',
        created_at: b.created_at,
        page_count: b.page_count,
      })),
      linksReplayed: replay.linksReplayed,
      framesApplied: replay.framesApplied,
      approval: {
        id: approvalRowFinal.id,
        method: approvalRowFinal.approval_method || approvalConsumeResult.approval_method || null,
        mode_at_creation: approvalRowFinal.approval_mode_at_creation,
        consumed_at: approvalConsumeResult.consumed_at,
      },
      note: 'The server should be restarted to ensure all in-memory state reflects the restored database.',
    });
  } catch (err) {
    try { if (db) db.close(); } catch (_) {}
    logger.error('execute-chain handler crashed', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error during chain restore', detail: err.message });
  }
});

// ── Configuration Snapshots (moved) ──
//
// The configuration snapshot endpoints that used to live here
// (GET /configs, POST /config-save, POST /config-revert/:id) were
// superseded in Phase B5d3 by routes/config-baseline.js, mounted at
// /api/config-baseline. That is the single canonical surface: snapshot
// list/save/diff/revert/delete plus signed FA-GB1 export/import and the
// trusted-key endpoints.

module.exports = router;

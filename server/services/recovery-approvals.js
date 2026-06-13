// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE — Dual-Control Recovery Approvals (D24)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The lifecycle for two-operator destructive client recovery. One operator
// requests a teardown or reprovision (createPending); a second, distinct
// operator — or the GD — co-approves it (approve), at which point the
// underlying client-recovery service runs. Both operators authenticate with
// their hardware device keys at the HTTP layer (requireDeviceAction); this
// service enforces the policy: a requester cannot approve their own request,
// each pending request is single-flight per target+action (DB-enforced), and
// unapproved requests lapse after a TTL.
//
// Errors carry a .code the route maps to HTTP: INVALID_ACTION,
// INVALID_APPROVAL_KIND, USER_NOT_FOUND, NOT_AN_ANALYST, PENDING_EXISTS,
// NOT_FOUND, ALREADY_DECIDED, EXPIRED, SELF_APPROVAL, CONFLICT.
// ─────────────────────────────────────────────────────────────────────────────

const recovery = require('./client-recovery');

const DEFAULT_TTL_SECONDS = 900;
const ACTIONS = ['teardown', 'reprovision'];
const APPROVAL_KINDS = ['operator', 'gd'];

const ROW_COLUMNS =
  'id, action, target_user_id, reason, status, requested_by, ' +
  'requester_fingerprint, requested_at, expires_at, approval_kind, ' +
  'approved_by, approver_fingerprint, decided_at, recovery_run_id, ' +
  'executed_at, error';

function fail(code, message) {
  const e = new Error(message || code);
  e.code = code;
  return e;
}

function isUniqueViolation(e) {
  return !!e && (e.code === 'SQLITE_CONSTRAINT_UNIQUE' ||
    (typeof e.message === 'string' && e.message.indexOf('UNIQUE constraint') !== -1));
}

// Record a destructive request as pending. Validates the action and that the
// target is a real analyst, then inserts one pending row (the partial unique
// index rejects a duplicate pending request for the same target+action).
function createPending(db, params) {
  const p = params || {};
  const action = p.action;
  if (ACTIONS.indexOf(action) === -1) throw fail('INVALID_ACTION', 'unknown action');
  const targetUserId = p.targetUserId;
  if (typeof targetUserId !== 'string' || !targetUserId) throw fail('USER_NOT_FOUND', 'analyst not found');
  const requestedBy = p.requestedBy;
  const requesterFingerprint = p.requesterFingerprint;
  const reason = p.reason || null;
  const ttl = Number.isInteger(p.ttlSeconds) && p.ttlSeconds > 0 ? p.ttlSeconds : DEFAULT_TTL_SECONDS;

  const user = db.prepare('SELECT id, role FROM users WHERE id = ?').get(targetUserId);
  if (!user) throw fail('USER_NOT_FOUND', 'analyst not found');
  if (user.role !== 'analyst') throw fail('NOT_AN_ANALYST', 'target is not an analyst');

  let info;
  try {
    info = db.prepare(
      'INSERT INTO recovery_action_approvals ' +
      '(action, target_user_id, reason, requested_by, requester_fingerprint, expires_at) ' +
      "VALUES (?, ?, ?, ?, ?, datetime('now', '+" + ttl + " seconds'))"
    ).run(action, targetUserId, reason, requestedBy, requesterFingerprint);
  } catch (e) {
    if (isUniqueViolation(e)) throw fail('PENDING_EXISTS', 'a pending request already exists for this analyst and action');
    throw e;
  }
  const row = db.prepare('SELECT id, status, expires_at FROM recovery_action_approvals WHERE rowid = ?').get(info.lastInsertRowid);
  return { id: row.id, status: row.status, expiresAt: row.expires_at };
}

function getAction(db, id) {
  return db.prepare('SELECT ' + ROW_COLUMNS + ' FROM recovery_action_approvals WHERE id = ?').get(id) || null;
}

// Pending, non-expired requests, newest first.
function listPending(db, opts) {
  const limit = opts && Number.isInteger(opts.limit) && opts.limit > 0 ? opts.limit : 100;
  return db.prepare(
    'SELECT ' + ROW_COLUMNS + ' FROM recovery_action_approvals ' +
    "WHERE status = 'pending' AND expires_at > datetime('now') " +
    'ORDER BY requested_at DESC LIMIT ?'
  ).all(limit);
}

// Lapse any pending requests past their expiry. Returns the number expired.
function expireStale(db) {
  const info = db.prepare(
    "UPDATE recovery_action_approvals SET status = 'expired', updated_at = datetime('now') " +
    "WHERE status = 'pending' AND expires_at <= datetime('now')"
  ).run();
  return info.changes;
}

// Co-approve and execute. approverId MUST differ from the requester. On success
// the row moves to 'executed' with the linked recovery run; if execution itself
// fails the row stays 'approved' with the error recorded and the error is
// re-thrown for the caller to map.
function approve(db, params) {
  const p = params || {};
  const id = p.id;
  const approverId = p.approverId;
  const approverFingerprint = p.approverFingerprint;
  const approvalKind = p.approvalKind || 'operator';
  if (APPROVAL_KINDS.indexOf(approvalKind) === -1) throw fail('INVALID_APPROVAL_KIND', 'unknown approval kind');

  const row = db.prepare(
    'SELECT ' + ROW_COLUMNS + ", (expires_at <= datetime('now')) AS is_expired " +
    'FROM recovery_action_approvals WHERE id = ?'
  ).get(id);
  if (!row) throw fail('NOT_FOUND', 'approval request not found');
  if (row.status !== 'pending') throw fail('ALREADY_DECIDED', 'request already ' + row.status);
  if (row.is_expired) {
    db.prepare("UPDATE recovery_action_approvals SET status = 'expired', updated_at = datetime('now') WHERE id = ? AND status = 'pending'").run(id);
    throw fail('EXPIRED', 'request has expired');
  }
  if (row.requested_by === approverId) throw fail('SELF_APPROVAL', 'the requester cannot approve their own request');

  // Atomically claim the request so two approvers cannot both execute it.
  const claim = db.prepare(
    "UPDATE recovery_action_approvals SET status = 'approved', approval_kind = ?, " +
    'approved_by = ?, approver_fingerprint = ?, ' +
    "decided_at = datetime('now'), updated_at = datetime('now') " +
    "WHERE id = ? AND status = 'pending' AND expires_at > datetime('now')"
  ).run(approvalKind, approverId, approverFingerprint, id);
  if (claim.changes !== 1) throw fail('CONFLICT', 'request is no longer pending');

  let result;
  try {
    if (row.action === 'teardown') {
      result = recovery.teardownAc(db, row.target_user_id, {
        initiatedBy: row.requested_by,
        reason: row.reason,
        wsServer: p.wsServer || null
      });
    } else {
      result = recovery.reprovisionAc(db, row.target_user_id, { initiatedBy: row.requested_by });
    }
  } catch (e) {
    db.prepare("UPDATE recovery_action_approvals SET error = ?, updated_at = datetime('now') WHERE id = ?").run(e && e.message ? e.message : 'execution failed', id);
    throw e;
  }
  db.prepare(
    "UPDATE recovery_action_approvals SET status = 'executed', recovery_run_id = ?, " +
    "executed_at = datetime('now'), updated_at = datetime('now') WHERE id = ?"
  ).run(result.recoveryRunId, id);
  return { id: id, action: row.action, targetUserId: row.target_user_id, result: result };
}

// Reject a pending request. decidedBy is recorded; the requester may reject
// their own (acts as a cancellation).
function reject(db, params) {
  const p = params || {};
  const id = p.id;
  const row = db.prepare('SELECT status FROM recovery_action_approvals WHERE id = ?').get(id);
  if (!row) throw fail('NOT_FOUND', 'approval request not found');
  if (row.status !== 'pending') throw fail('ALREADY_DECIDED', 'request already ' + row.status);
  const info = db.prepare(
    "UPDATE recovery_action_approvals SET status = 'rejected', approved_by = ?, " +
    "decided_at = datetime('now'), updated_at = datetime('now') " +
    "WHERE id = ? AND status = 'pending'"
  ).run(p.decidedBy, id);
  if (info.changes !== 1) throw fail('CONFLICT', 'request is no longer pending');
  return { id: id, status: 'rejected' };
}

module.exports = {
  DEFAULT_TTL_SECONDS,
  createPending,
  getAction,
  listPending,
  expireStale,
  approve,
  reject
};

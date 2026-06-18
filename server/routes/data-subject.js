'use strict';

// ---------------------------------------------------------------------------
// FireAlive -- Data-Subject Rights routes (access export + dual-control erasure).
//
// POST /api/data-subject/export serves a data-subject ACCESS request. Two modes:
//   - Self-service: the caller exports their own data (no subject_id, or a
//     subject_id equal to the caller's id). Available to every role. The
//     gathered bundle is returned to the caller's own authenticated session;
//     for an analyst the sealed analyst_private_data blobs inside the bundle
//     still decrypt on-device with the key the Analyst Client already holds.
//   - Organization-initiated: an admin passes a subject_id for another user.
//     If that subject is an analyst the WHOLE bundle is sealed to the analyst's
//     active key, so the admin who ran the export holds only ciphertext and
//     only the analyst can open it on their device. For a non-analyst subject
//     -- whose data the server can read, and who has no clean per-subject seal
//     key -- the gathered bundle is returned to the operator.
//
// ERASURE is dual-control (mirrors restore-approvals): POST /erase has an admin
// create a pending data_subject_erasure_requests row; POST /erase/:id/approve
// has a SECOND admin approve it with a fresh MFA step-up, and only then does the
// erasure run and the row move to 'executed'. The approver must differ from the
// requester. GET /erase/pending lists the queue for the approver.
//
// Every successful export emits DATA_SUBJECT_EXPORT; a request emits
// DATA_SUBJECT_ERASURE_REQUESTED; a completed erasure emits DATA_SUBJECT_ERASURE.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { mfaStepUp } = require('../middleware/mfa-stepup');
const { gatherSubjectData, sealBundleToAnalyst, eraseSubject } = require('../services/data-subject');

// POST /export -- access export (self-service any role; org-initiated by admin)
router.post('/export', (req, res) => {
  const requesterId = req.user.id;
  const requesterRole = req.user.role;

  const rawSubject = req.body ? req.body.subject_id : undefined;
  if (rawSubject !== undefined && rawSubject !== null && typeof rawSubject !== 'string') {
    return res.status(400).json({ error: 'subject_id must be a string' });
  }
  const subjectId = rawSubject ? rawSubject : requesterId;
  const selfService = subjectId === requesterId;

  // Exporting another subject's data is organization-initiated and admin-only.
  if (!selfService && requesterRole !== 'admin') {
    return res.status(403).json({ error: "Only an admin may export another user's data" });
  }

  const db = getDb();
  let response;
  let mode;
  let sealed = false;
  try {
    const subject = db.prepare('SELECT id, role FROM users WHERE id = ?').get(subjectId);
    if (!subject) {
      return res.status(404).json({ error: 'Subject not found' });
    }

    const bundle = gatherSubjectData(db, subjectId);

    if (selfService) {
      // Own data to the caller's session; analyst blobs decrypt on-device.
      mode = 'self';
      response = { mode: 'self', bundle: bundle };
    } else if (subject.role === 'analyst') {
      // Seal the whole bundle to the analyst so the admin sees only ciphertext.
      mode = 'org';
      let sealedDescriptor;
      try {
        sealedDescriptor = sealBundleToAnalyst(db, subjectId, bundle);
      } catch (sealErr) {
        if (sealErr && sealErr.code === 'NO_ACTIVE_ANALYST_KEY') {
          return res.status(409).json({
            error: 'Subject has no active analyst key to seal an export to',
            code: 'NO_ACTIVE_ANALYST_KEY',
          });
        }
        throw sealErr;
      }
      sealed = true;
      response = { mode: 'org', sealed: true, export: sealedDescriptor };
    } else {
      // Non-analyst subject: nothing of theirs is hidden from the server, and
      // there is no clean per-subject seal key, so return the bundle as-is.
      mode = 'org';
      response = { mode: 'org', sealed: false, bundle: bundle };
    }
  } finally {
    db.close();
  }

  auditLog(
    requesterId,
    'DATA_SUBJECT_EXPORT',
    'subject=' + subjectId + ' mode=' + mode + ' sealed=' + sealed,
    req.ip
  );
  return res.json(response);
});

// --- Dual-control erasure ----------------------------------------------------------------
// Right-to-erasure is destructive, so it is split across two admins: one creates
// a pending request, a second (different) admin approves it with a fresh MFA
// step-up, and only then does the erasure run. Mirrors the restore-approvals
// idiom; the data_subject_erasure_requests row records the lifecycle.

// Admin gate, applied before mfaStepUp so non-admins never reach step-up.
function eraseAdminGate(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only an admin may manage erasure requests', code: 'FORBIDDEN' });
  }
  next();
}

// POST /erase -- an admin creates a pending erasure request for a subject.
router.post('/erase', eraseAdminGate, (req, res) => {
  const subjectId = req.body ? req.body.subject_id : undefined;
  if (typeof subjectId !== 'string' || subjectId === '') {
    return res.status(400).json({ error: 'subject_id is required and must be a non-empty string', code: 'INVALID_INPUT' });
  }

  const db = getDb();
  let outcome;
  try {
    const subject = db.prepare('SELECT id FROM users WHERE id = ?').get(subjectId);
    if (!subject) {
      outcome = { status: 404, body: { error: 'Subject not found', code: 'SUBJECT_NOT_FOUND' } };
    } else {
      const existing = db
        .prepare("SELECT id FROM data_subject_erasure_requests WHERE subject_id = ? AND status = 'pending'")
        .get(subjectId);
      if (existing) {
        outcome = {
          status: 409,
          body: { error: 'a pending erasure request already exists for this subject', code: 'ERASURE_ALREADY_PENDING', request_id: existing.id },
        };
      } else {
        const id = crypto.randomBytes(16).toString('hex');
        db.prepare(
          "INSERT INTO data_subject_erasure_requests (id, subject_id, requested_by, status) VALUES (?, ?, ?, 'pending')"
        ).run(id, subjectId, req.user.id);
        const row = db.prepare('SELECT * FROM data_subject_erasure_requests WHERE id = ?').get(id);
        outcome = { status: 201, body: row, audit: 'request=' + id + ' subject=' + subjectId };
      }
    }
  } finally {
    db.close();
  }

  if (outcome.audit) {
    auditLog(req.user.id, 'DATA_SUBJECT_ERASURE_REQUESTED', outcome.audit, req.ip);
  }
  return res.status(outcome.status).json(outcome.body);
});

// GET /erase/pending -- the approver queue (admin/lead). Lets the second
// approver discover pending requests; mirrors restore-approvals /pending.
router.get('/erase/pending', (req, res) => {
  if (!req.user || (req.user.role !== 'admin' && req.user.role !== 'lead')) {
    return res.status(403).json({ error: 'insufficient permissions', code: 'FORBIDDEN' });
  }
  const db = getDb();
  try {
    const rows = db
      .prepare("SELECT id, subject_id, requested_by, requested_at FROM data_subject_erasure_requests WHERE status = 'pending' ORDER BY requested_at, id")
      .all();
    return res.json({ items: rows, count: rows.length });
  } finally {
    db.close();
  }
});

// POST /erase/:id/approve -- a SECOND admin approves with a fresh MFA step-up;
// on approval the erasure executes and the row is marked executed. The approver
// must differ from the requester (dual control).
router.post('/erase/:id/approve', eraseAdminGate, mfaStepUp(), (req, res) => {
  const id = req.params.id;
  const approverId = req.user.id;

  const db = getDb();
  let outcome;
  let receipt;
  try {
    const row = db.prepare('SELECT * FROM data_subject_erasure_requests WHERE id = ?').get(id);
    if (!row) {
      outcome = { status: 404, body: { error: 'erasure request not found', code: 'ERASURE_NOT_FOUND' } };
    } else if (row.status !== 'pending') {
      outcome = { status: 409, body: { error: 'erasure request is not pending', code: 'ERASURE_NOT_PENDING', status: row.status } };
    } else if (row.requested_by === approverId) {
      outcome = {
        status: 403,
        body: { error: 'the approver must differ from the requester', code: 'APPROVER_SAME_AS_REQUESTER' },
        audit: { event: 'DATA_SUBJECT_ERASURE_APPROVE_REJECTED', detail: 'request=' + id + ' reason=same_approver' },
      };
    } else {
      const approveTxn = db.transaction(function approveErasureTxn() {
        // Claim the row under the transaction so a concurrent approve cannot
        // double-execute; only then run the (atomic) erasure. If the erasure
        // throws, the whole transaction -- including this claim -- rolls back.
        const claim = db
          .prepare("UPDATE data_subject_erasure_requests SET status = 'executed', approved_by = ?, approved_at = datetime('now'), executed_at = datetime('now') WHERE id = ? AND status = 'pending'")
          .run(approverId, id);
        if (claim.changes !== 1) {
          const e = new Error('erasure request is not pending');
          e.code = 'ERASURE_NOT_PENDING';
          throw e;
        }
        receipt = eraseSubject(db, row.subject_id);
      });

      try {
        approveTxn();
        const updated = db.prepare('SELECT * FROM data_subject_erasure_requests WHERE id = ?').get(id);
        outcome = {
          status: 200,
          body: { request: updated, receipt: receipt },
          audit: { event: 'DATA_SUBJECT_ERASURE', detail: 'request=' + id + ' subject=' + row.subject_id + ' role=' + receipt.role + ' crypto_shredded=' + receipt.crypto_shredded },
        };
      } catch (txErr) {
        if (txErr && txErr.code === 'ERASURE_NOT_PENDING') {
          outcome = { status: 409, body: { error: 'erasure request is not pending', code: 'ERASURE_NOT_PENDING' } };
        } else if (txErr && txErr.code === 'SUBJECT_NOT_FOUND') {
          outcome = { status: 409, body: { error: 'subject no longer present', code: 'SUBJECT_NOT_FOUND' } };
        } else {
          throw txErr;
        }
      }
    }
  } finally {
    db.close();
  }

  if (outcome.audit) {
    auditLog(approverId, outcome.audit.event, outcome.audit.detail, req.ip);
  }
  return res.status(outcome.status).json(outcome.body);
});

module.exports = router;

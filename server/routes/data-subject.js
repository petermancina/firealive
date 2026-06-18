'use strict';

// ---------------------------------------------------------------------------
// FireAlive -- Data-Subject Rights routes (access export).
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
// Dual-control erasure is added in a later commit; this file is export-only for
// now. Every successful export emits a DATA_SUBJECT_EXPORT audit event.
// ---------------------------------------------------------------------------

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { gatherSubjectData, sealBundleToAnalyst } = require('../services/data-subject');

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

module.exports = router;

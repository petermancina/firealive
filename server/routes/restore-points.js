'use strict';

// FIREALIVE -- /api/restore-points routes (B6k)
//
// The operator surface for taking a PRE-UPGRADE restore point: a full-suite
// backup captured at the current fuse and schema, written to a store OUTSIDE
// the data root so it survives the rollback it exists to serve.
//
// Gating: mounted with authMiddleware(['admin']) in index.js and deliberately
// WITHOUT configLockChokepoint(), matching /api/backup. Taking a restore point
// is an operational action -- it reads the deployment and writes a backup, and
// changes no configuration. Requiring the configuration lock to be OPEN would
// mean an operator had to unlock the platform in order to protect it before an
// upgrade, which is exactly backwards: the moment before an upgrade is when a
// deployment should be at its most locked down.
//
// No step-up either, for the same reason /api/backup has none. The whole value
// of a pre-upgrade restore point is that operators actually take one; friction
// here buys nothing, because the artifact this produces cannot be used to
// change anything. Consuming it is where the gates live -- an anchor-signed,
// single-use, one-version-deep authorization checked by an offline tool.

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const restorePointSvc = require('../services/restore-point');
const dataRoot = require('../lib/data-root');

// POST /api/restore-points -- take one now.
router.post('/', async (req, res) => {
  const db = getDb();
  const ip = req.ip || null;
  const note = req.body && typeof req.body.note === 'string' ? req.body.note.slice(0, 500) : null;

  try {
    const rp = await restorePointSvc.createRestorePoint(db, {
      userId: req.user.id,
      note: note,
      ip: ip,
    });
    logger.info('Pre-upgrade restore point created', {
      id: rp.id, backup: rp.backup_id, fuse: rp.source_fuse_counter, version: rp.source_version,
    });
    return res.status(201).json({
      restore_point: rp,
      store: dataRoot.restorePointsDir(),
      // Said plainly in the response because it is the operating instruction
      // that makes the artifact useful, and an operator who reads only this
      // should still end up with a recoverable deployment.
      note_to_operator: 'This restore point is stored outside the data directory so it '
        + 'survives an uninstall. Roll back with the offline tool on this host; '
        + 'copy the bundle to removable media if you want a second copy.',
    });
  } catch (e) {
    const code = (e && e.code) || 'ERROR';
    const status = code === 'INVALID_INPUT' ? 400 : 500;
    // Loud, and never a partial success: createRestorePoint throws rather than
    // returning a half-made restore point, so an operator is never told they
    // have a way back when they do not.
    logger.error('Pre-upgrade restore point FAILED', { error: e.message, code: code });
    auditLog(req.user.id, 'RESTORE_POINT_FAILED', 'error=' + e.message, ip);
    return res.status(status).json({
      error: e.message,
      code: code,
      warning: 'NO restore point was created. Do not upgrade until one exists.',
    });
  }
});

// GET /api/restore-points -- newest first, with a per-row bundle_present flag so
// the console can show that a bundle an operator is relying on has gone missing.
router.get('/', (req, res) => {
  const db = getDb();
  try {
    const limit = req.query && req.query.limit ? parseInt(req.query.limit, 10) : undefined;
    const rows = restorePointSvc.list(db, limit);
    return res.json({
      restore_points: rows,
      store: dataRoot.restorePointsDir(),
      missing: rows.filter((r) => !r.bundle_present).length,
    });
  } catch (e) {
    return res.status(500).json({ error: e.message, code: (e && e.code) || 'ERROR' });
  }
});

// GET /api/restore-points/:id
router.get('/:id', (req, res) => {
  const db = getDb();
  try {
    const row = restorePointSvc.get(db, req.params.id);
    if (!row) return res.status(404).json({ error: 'restore point not found', code: 'NOT_FOUND' });
    return res.json({ restore_point: row });
  } catch (e) {
    return res.status(500).json({ error: e.message, code: (e && e.code) || 'ERROR' });
  }
});

module.exports = router;

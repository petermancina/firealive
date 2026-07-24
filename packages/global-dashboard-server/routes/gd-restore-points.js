'use strict';

// FIREALIVE -- /api/restore-points routes (Global Dashboard) (B6k)
//
// The operator surface for taking a PRE-UPGRADE restore point on the Global
// Dashboard: a full-suite backup captured at the current fuse and schema,
// written to a store OUTSIDE the GD data root so it survives the rollback it
// exists to serve.
//
// Gating: mounted with authMiddleware(['ciso']) in index.js and deliberately
// WITHOUT a config-lock chokepoint, matching /api/backup. Taking a restore
// point changes no configuration -- it reads the deployment and writes a
// backup. Requiring the configuration lock to be OPEN would mean unlocking the
// GD in order to protect it before an upgrade, which is exactly backwards.
//
// Because the GD is held to the STRICT coverage model (every mutating endpoint
// gated or in a reasoned operational allow-list), POST /api/restore-points is
// listed in GD_OPERATIONAL_ALLOWLIST in scripts/check-config-lock-coverage.js
// with that reasoning, rather than being silently unregistered.
//
// No step-up either, for the same reason /api/backup has none: the whole value
// of a pre-upgrade restore point is that operators actually take one, and the
// artifact this produces cannot change anything. The gates live on CONSUMING
// it -- an anchor-signed, single-use, one-version-deep authorization checked by
// an offline tool.

const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const restorePointSvc = require('../services/gd-restore-point');
const gdDataRoot = require('../lib/gd-data-root');

function actorOf(req) {
  return req.user && req.user.id ? req.user.id : 'system';
}

function _audit(db, req, eventType, detail) {
  try {
    appendGdAuditEntry(db, {
      userId: actorOf(req), eventType, detail, ip: (req && req.ip) || null, severity: 'info',
    });
  } catch (e) {
    try { console.warn('[gd-restore-points] audit failed:', e && e.message); } catch (_e) { /* ignore */ }
  }
}

// POST /api/restore-points -- take one now.
router.post('/', async (req, res) => {
  const db = getDb();
  const note = req.body && typeof req.body.note === 'string' ? req.body.note.slice(0, 500) : null;

  try {
    const rp = await restorePointSvc.createRestorePoint(db, {
      userId: actorOf(req),
      note: note,
      ip: (req && req.ip) || null,
    });
    return res.status(201).json({
      restore_point: rp,
      store: gdDataRoot.restorePointsDir(),
      note_to_operator: 'This restore point is stored outside the GD data directory so it '
        + 'survives an uninstall. Roll back with the offline tool on this host; '
        + 'copy the bundle to removable media if you want a second copy.',
    });
  } catch (err) {
    const code = (err && err.code) || 'ERROR';
    const status = code === 'INVALID_INPUT' ? 400 : 500;
    // Loud, and never a partial success: createRestorePoint throws rather than
    // returning a half-made restore point, so an operator is never told they
    // have a way back when they do not.
    console.error('routes/gd-restore-points: create failed:', err.message);
    _audit(db, req, 'RESTORE_POINT_FAILED', 'error=' + String(err.message).slice(0, 200));
    return res.status(status).json({
      error: err.message,
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
      store: gdDataRoot.restorePointsDir(),
      missing: rows.filter((r) => !r.bundle_present).length,
    });
  } catch (err) {
    console.error('routes/gd-restore-points: list failed:', err.message);
    return res.status(500).json({ error: err.message, code: (err && err.code) || 'ERROR' });
  }
});

// GET /api/restore-points/:id
router.get('/:id', (req, res) => {
  const db = getDb();
  try {
    const row = restorePointSvc.get(db, req.params.id);
    if (!row) return res.status(404).json({ error: 'restore point not found', code: 'NOT_FOUND' });
    return res.json({ restore_point: row });
  } catch (err) {
    console.error('routes/gd-restore-points: get failed:', err.message);
    return res.status(500).json({ error: err.message, code: (err && err.code) || 'ERROR' });
  }
});

module.exports = router;

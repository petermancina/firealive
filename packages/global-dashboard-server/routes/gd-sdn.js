// FIREALIVE GD -- SDN admin routes (B6c PR-4, read-only twin)
//
// Admin API surface for SDN Mode. Mounted in index.js behind CISO auth and the
// global config-lock chokepoint:
//
//   app.use('/api/sdn', authMiddleware(['ciso']), require('./routes/gd-sdn'));
//
// Read-only-tailored twin of the Regional routes/sdn.js. The GD holds no SDN
// controller integrations and drives no controller, so the Regional
// /integrations* (list / create / read / update / delete / probe / topology /
// segmentation) and /segment-policy endpoints are omitted; only the operator's
// own admission config and the GD's posture are exposed.
//
// Endpoints:
//   GET /network-map   read the operator-declared permitted-segment allow-list
//   PUT /network-map   update the allow-list (the GD's own admission config)
//   GET /posture       current SDN posture (event-derived latch) + recent events
//
// ASCII only; no template literals.

const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const sdnMode = require('./gd-sdn-mode');

// Map a service error to an HTTP status. Validation -> 400, missing -> 404,
// otherwise 500.
function statusForError(err) {
  const code = (err && err.code) ? String(err.code) : '';
  if (code === 'UNSUPPORTED_PLATFORM' || code.indexOf('INVALID_') === 0) return 400;
  if (code === 'NOT_FOUND') return 404;
  return 500;
}

// Local audit helper (the GD has no auditLog middleware): append a queryable
// event to the GD audit chain. Best-effort -- an audit-write failure never
// changes the handler's response.
function auditLog(userId, eventType, detail, ip) {
  let adb = null;
  try {
    adb = getDb();
    appendGdAuditEntry(adb, { userId: userId || 'anonymous', eventType: eventType, detail: detail || '', ip: ip || null });
  } catch (_e) {
    // swallow
  } finally {
    if (adb) { try { adb.close(); } catch (_e2) { /* ignore */ } }
  }
}

// -- Network map --------------------------------------------------------------

router.get('/network-map', function (req, res) {
  const db = getDb();
  try {
    return res.json({ networkMap: sdnMode.getNetworkMap(db) });
  } catch (e) {
    return res.status(500).json({ error: 'failed to read network map' });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

router.put('/network-map', function (req, res) {
  const db = getDb();
  try {
    const body = req.body || {};
    const updated = sdnMode.setNetworkMap(db, {
      permittedSegments: body.permittedSegments,
      updatedBy: req.user ? req.user.id : null
    });
    try {
      const segmentCount = updated && updated.permittedSegments ? updated.permittedSegments.length : 0;
      auditLog(req.user ? req.user.id : null, 'SDN_NETWORK_MAP_UPDATED', 'segments=' + segmentCount, req.ip);
    } catch (_e) {}
    return res.json({ networkMap: updated });
  } catch (e) {
    return res.status(statusForError(e)).json({ error: e.message || 'failed to update network map', code: e.code });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

// -- Posture ------------------------------------------------------------------

router.get('/posture', function (req, res) {
  const db = getDb();
  try {
    // The GD posture is the event-derived binary latch (no controller-probing
    // state machine); state is derived from it for response-shape parity.
    const p = sdnMode.getPosture(db, { recentLimit: 20 });
    const state = p.degraded ? 'degraded' : 'healthy';
    return res.json({ state: state, degraded: p.degraded, since: p.since, lastTransition: p.lastTransition, recent: p.recent });
  } catch (e) {
    return res.status(500).json({ error: 'failed to read posture' });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

module.exports = router;

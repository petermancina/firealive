// =============================================================================
// FIREALIVE GD -- Storage Destinations Admin Routes
//
// CRUD endpoints for managing the GD's off-host push destinations -- the storage-
// destination registry that backs backups, audit-log archives, forensic exports,
// snapshots, and CEF archives. All operations go through gd-storage-destinations,
// which validates against the loaded adapter registry, encrypts credentials at
// rest under the Tier-1 KEK, and exposes public (no-credentials) retrieval paths.
// Twins the Regional storage-destinations routes.
//
// Mounted at /api/storage-destinations in index.js with authMiddleware; the route
// file does NOT apply auth itself.
//
// ENDPOINTS
//   GET    /                 list (public view + push_stats); ?enabled=true, ?adapter=
//   GET    /adapters         available adapter implementations (create-picker source)
//   GET    /:id              single destination (public view + push_stats); 404 if missing
//   POST   /                 create; body validates against the adapter contract; 400 on
//                            validation error with { error, field }; 409 on duplicate name
//   PATCH  /:id              partial update (adapter immutable); 404 if missing
//   DELETE /:id              delete; 409 has_push_history (disable instead); 404 if missing
//   POST   /:id/probe        run adapter.probe (JIT-decrypt credentials); no row mutation
//
// The residency gate is forward-compatible: when gd-data-residency's config-time
// gate is wired into create/update, a blocked create/update throws with
// residencyBlocked and is surfaced here; a soft warning rides on the returned view.
// Every create/update reconciles the cross-border transfer register.
//
// AUDIT: every endpoint emits a GD audit-chain entry. Sensitive fields
// (credentials, config values) are never logged -- only id, name, adapter type,
// and the probe ok/error summary.
// =============================================================================

const express = require('express');
const router = express.Router();

const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const storageDestinations = require('../services/gd-storage-destinations');
const dataResidency = require('../services/gd-data-residency');
const base = require('../services/gd-destination-adapter-base');

function _audit(db, req, eventType, detail) {
  try {
    appendGdAuditEntry(db, {
      userId: req && req.user ? req.user.id : null,
      eventType,
      detail,
      ip: (req && req.ip) || null,
      severity: 'info',
    });
  } catch (e) {
    try { console.warn('[storage-destinations] audit failed:', e && e.message); } catch (_e) { /* ignore */ }
  }
}

function _reconcile(db) {
  try { dataResidency.reconcileTransfers(db); }
  catch (e) { console.error('routes/storage-destinations: residency reconcile failed:', e.message); }
}

// -- GET / --------------------------------------------------------------------
router.get('/', (req, res) => {
  let db;
  try {
    db = getDb();
    const options = {};
    if (req.query.enabled === 'true' || req.query.enabled === '1') options.enabledOnly = true;
    if (typeof req.query.adapter === 'string' && req.query.adapter !== '') options.adapter = req.query.adapter;
    const destinations = storageDestinations.listDestinations(db, options);
    _audit(db, req, 'STORAGE_DESTINATIONS_LISTED',
      `count=${destinations.length}${options.enabledOnly ? ' enabled-only' : ''}${options.adapter ? ` adapter=${options.adapter}` : ''}`);
    res.json({ destinations });
  } catch (err) {
    console.error('routes/storage-destinations: list failed:', err.message);
    res.status(500).json({ error: 'Failed to list destinations' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- GET /adapters (must precede /:id) ----------------------------------------
router.get('/adapters', (req, res) => {
  let db;
  try {
    db = getDb();
    const available = base.listAdapters().map((a) => ({ ...a, status: 'available' }));
    _audit(db, req, 'STORAGE_DESTINATION_ADAPTERS_VIEWED', `loaded=${available.length}`);
    res.json({ available });
  } catch (err) {
    console.error('routes/storage-destinations: adapters list failed:', err.message);
    res.status(500).json({ error: 'Failed to list adapters' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- GET /:id -----------------------------------------------------------------
router.get('/:id', (req, res) => {
  let db;
  try {
    db = getDb();
    const destination = storageDestinations.getDestinationById(db, req.params.id);
    if (!destination) return res.status(404).json({ error: 'Destination not found' });
    _audit(db, req, 'STORAGE_DESTINATION_VIEWED', `id=${destination.id} name=${destination.name} adapter=${destination.adapter}`);
    res.json({ destination });
  } catch (err) {
    console.error('routes/storage-destinations: get failed:', err.message);
    res.status(500).json({ error: 'Failed to get destination' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- POST / -------------------------------------------------------------------
router.post('/', (req, res) => {
  let db;
  try {
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ error: 'Request body required' });
    }
    db = getDb();
    let destination;
    try {
      destination = storageDestinations.createDestination(db, req.body);
    } catch (err) {
      if (err.residencyBlocked) {
        _audit(db, req, 'RESIDENCY_DESTINATION_BLOCKED',
          `name=${req.body.name || '?'} adapter=${req.body.adapter || '?'} ${err.message}`);
      }
      if (err.validation) {
        return res.status(400).json({ error: err.message, field: err.field || null });
      }
      const msg = String(err.message || '');
      if (msg.toLowerCase().includes('unique')) {
        return res.status(409).json({ error: 'A destination with that name already exists', field: 'name' });
      }
      throw err;
    }
    _audit(db, req, 'STORAGE_DESTINATION_CREATED',
      `id=${destination.id} name=${destination.name} adapter=${destination.adapter} immutability=${destination.immutability_mode} enabled=${destination.enabled}`);
    _reconcile(db);
    if (destination.residencyWarning) {
      _audit(db, req, 'RESIDENCY_DESTINATION_WARNED',
        `id=${destination.id} name=${destination.name} adapter=${destination.adapter} ${destination.residencyWarning}`);
    }
    res.status(201).json({ destination });
  } catch (err) {
    console.error('routes/storage-destinations: create failed:', err.message);
    res.status(500).json({ error: 'Failed to create destination' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- PATCH /:id ---------------------------------------------------------------
router.patch('/:id', (req, res) => {
  let db;
  try {
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ error: 'Request body required' });
    }
    db = getDb();
    let destination;
    try {
      destination = storageDestinations.updateDestination(db, req.params.id, req.body);
    } catch (err) {
      if (err.residencyBlocked) {
        _audit(db, req, 'RESIDENCY_DESTINATION_BLOCKED', `id=${req.params.id} ${err.message}`);
      }
      if (err.validation) {
        return res.status(400).json({ error: err.message, field: err.field || null });
      }
      const msg = String(err.message || '');
      if (msg.toLowerCase().includes('unique')) {
        return res.status(409).json({ error: 'A destination with that name already exists', field: 'name' });
      }
      throw err;
    }
    if (destination === null) return res.status(404).json({ error: 'Destination not found' });
    const changedFields = Object.keys(req.body).filter((k) => !['credentials', 'config'].includes(k));
    if (req.body.config !== undefined) changedFields.push('config');
    if (req.body.credentials !== undefined) changedFields.push('credentials');
    _audit(db, req, 'STORAGE_DESTINATION_UPDATED',
      `id=${destination.id} name=${destination.name} fields=${changedFields.join(',') || 'none'}`);
    _reconcile(db);
    if (destination.residencyWarning) {
      _audit(db, req, 'RESIDENCY_DESTINATION_WARNED',
        `id=${destination.id} name=${destination.name} adapter=${destination.adapter} ${destination.residencyWarning}`);
    }
    res.json({ destination });
  } catch (err) {
    console.error('routes/storage-destinations: update failed:', err.message);
    res.status(500).json({ error: 'Failed to update destination' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- DELETE /:id --------------------------------------------------------------
router.delete('/:id', (req, res) => {
  let db;
  try {
    db = getDb();
    const result = storageDestinations.deleteDestination(db, req.params.id);
    if (result.deleted === false) {
      if (result.reason === 'not_found') {
        return res.status(404).json({ error: 'Destination not found' });
      }
      if (result.reason === 'has_push_history') {
        _audit(db, req, 'STORAGE_DESTINATION_DELETE_REFUSED', `id=${req.params.id} reason=has_push_history`);
        return res.status(409).json({
          error: 'Destination has push history; cannot delete',
          reason: result.reason,
          detail: result.detail,
          remediation: 'PATCH enabled=false to retire the destination while preserving audit continuity',
        });
      }
      return res.status(409).json({ error: 'Cannot delete destination', reason: result.reason, detail: result.detail });
    }
    _audit(db, req, 'STORAGE_DESTINATION_DELETED', `id=${req.params.id}`);
    res.json({ deleted: true });
  } catch (err) {
    console.error('routes/storage-destinations: delete failed:', err.message);
    res.status(500).json({ error: 'Failed to delete destination' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- POST /:id/probe ----------------------------------------------------------
router.post('/:id/probe', async (req, res) => {
  let db;
  try {
    db = getDb();
    const dest = storageDestinations.getDestinationById(db, req.params.id);
    if (!dest) return res.status(404).json({ error: 'Destination not found' });

    const probeResult = await storageDestinations.probeDestination(db, req.params.id);
    _audit(db, req,
      probeResult.ok ? 'STORAGE_DESTINATION_PROBE_OK' : 'STORAGE_DESTINATION_PROBE_FAILED',
      `id=${req.params.id} name=${dest.name} adapter=${dest.adapter}${probeResult.ok ? '' : ' error=' + (probeResult.error || 'unknown')}`);
    res.json({ probe: probeResult });
  } catch (err) {
    console.error('routes/storage-destinations: probe failed:', err.message);
    res.status(500).json({ error: 'Failed to probe destination' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

module.exports = router;

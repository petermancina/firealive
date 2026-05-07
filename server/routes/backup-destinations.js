// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Destinations Admin Routes
//
// Admin-only CRUD endpoints for managing off-host push destinations.
// All operations go through services/backup-destinations.js which
// validates against the loaded adapter registry, encrypts credentials
// at rest under Tier-1 AES-GCM, and exposes public (no-credentials)
// retrieval paths.
//
// Mounted at /api/backup-destinations in server/index.js with
// authMiddleware(['admin']) (commit 12 of this phase). The route
// file does NOT apply auth itself.
//
// ENDPOINTS
//
//   GET    /api/backup-destinations
//     List destinations (public view, with per-row push_stats).
//     Query: ?enabled=true (only enabled), ?adapter=local|sftp
//
//   GET    /api/backup-destinations/adapters
//     List available adapter implementations from the registry
//     (name, description, supportedImmutabilityModes). Used by
//     the admin UI to populate the "create destination" picker.
//     Includes ADAPTERS_LANDING_IN_R3D4 with status='not-yet-implemented'
//     so operators see what's coming.
//
//   GET    /api/backup-destinations/:id
//     Get single destination (public view + push_stats). 404 if missing.
//
//   POST   /api/backup-destinations
//     Create new destination. Body validates against the adapter's
//     contract. Returns the created public view. 400 on validation
//     error with { error, field } pointing at the offending input.
//
//   PATCH  /api/backup-destinations/:id
//     Partial update. Adapter is immutable; attempts to change it
//     are silently ignored. Omitted fields preserve existing values.
//     Returns updated public view; 404 if missing.
//
//   DELETE /api/backup-destinations/:id
//     Delete destination. Refused if push records reference it
//     (returns 409 with reason='has_push_history'); operators
//     should disable (PATCH enabled=false) instead to preserve
//     audit continuity.
//
//   POST   /api/backup-destinations/:id/probe
//     Run adapter.probe to test connectivity. Decrypts credentials
//     just-in-time, calls the adapter, returns the probe result.
//     Does NOT modify the destination row. The probe runs
//     synchronously with adapter-specific timeouts (defaults to
//     5s for local, 30s for SFTP); admin UI should show a spinner.
//
// AUDIT LOGGING
//
// Every endpoint emits an auditLog entry. Sensitive fields
// (credentials, config) are NOT logged -- only the destination
// id, name, and adapter type. Probe results are logged with
// just the ok/error summary.
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const router = express.Router();

const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const backupDestinations = require('../services/backup-destinations');
const base = require('../services/destination-adapter-base');

// ── GET / ────────────────────────────────────────────────────────────────

router.get('/', (req, res) => {
  let db;
  try {
    db = getDb();
    const options = {};
    if (req.query.enabled === 'true' || req.query.enabled === '1') {
      options.enabledOnly = true;
    }
    if (typeof req.query.adapter === 'string' && req.query.adapter !== '') {
      options.adapter = req.query.adapter;
    }
    const destinations = backupDestinations.listDestinations(db, options);
    auditLog(
      req.user?.id,
      'BACKUP_DESTINATIONS_LISTED',
      `count=${destinations.length}${options.enabledOnly ? ' enabled-only' : ''}${options.adapter ? ` adapter=${options.adapter}` : ''}`,
      req.ip,
    );
    res.json({ destinations });
  } catch (err) {
    logger.error('routes/backup-destinations: list failed', { error: err.message });
    res.status(500).json({ error: 'Failed to list destinations' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

// ── GET /adapters ────────────────────────────────────────────────────────

router.get('/adapters', (req, res) => {
  try {
    const loaded = base.listAdapters().map(a => ({
      ...a,
      status: 'available',
    }));
    const landingInR3d4 = backupDestinations.ADAPTERS_LANDING_IN_R3D4.map(name => ({
      name,
      description: 'Lands in R3d-4 alongside HSM/KMS work',
      supportedImmutabilityModes: ['unknown'],
      status: 'not-yet-implemented',
    }));
    // Filter out any landing-in-r3d4 names that happen to be already loaded
    const loadedNames = new Set(loaded.map(a => a.name));
    const upcoming = landingInR3d4.filter(a => !loadedNames.has(a.name));
    auditLog(req.user?.id, 'BACKUP_DESTINATION_ADAPTERS_VIEWED', `loaded=${loaded.length} upcoming=${upcoming.length}`, req.ip);
    res.json({ available: loaded, upcoming });
  } catch (err) {
    logger.error('routes/backup-destinations: adapters list failed', { error: err.message });
    res.status(500).json({ error: 'Failed to list adapters' });
  }
});

// ── GET /:id ─────────────────────────────────────────────────────────────

router.get('/:id', (req, res) => {
  let db;
  try {
    db = getDb();
    const destination = backupDestinations.getDestinationById(db, req.params.id);
    if (!destination) return res.status(404).json({ error: 'Destination not found' });
    auditLog(req.user?.id, 'BACKUP_DESTINATION_VIEWED', `id=${destination.id} name=${destination.name} adapter=${destination.adapter}`, req.ip);
    res.json({ destination });
  } catch (err) {
    logger.error('routes/backup-destinations: get failed', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Failed to get destination' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

// ── POST / ───────────────────────────────────────────────────────────────

router.post('/', (req, res) => {
  let db;
  try {
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ error: 'Request body required' });
    }
    db = getDb();
    let destination;
    try {
      destination = backupDestinations.createDestination(db, req.body);
    } catch (err) {
      if (err.validation) {
        return res.status(400).json({ error: err.message, field: err.field || null });
      }
      // SQL constraint violation (e.g., UNIQUE name)
      const msg = String(err.message || '');
      if (msg.toLowerCase().includes('unique')) {
        return res.status(409).json({ error: 'A destination with that name already exists', field: 'name' });
      }
      throw err;
    }
    auditLog(req.user?.id, 'BACKUP_DESTINATION_CREATED', `id=${destination.id} name=${destination.name} adapter=${destination.adapter} immutability=${destination.immutability_mode} enabled=${destination.enabled}`, req.ip);
    res.status(201).json({ destination });
  } catch (err) {
    logger.error('routes/backup-destinations: create failed', { error: err.message });
    res.status(500).json({ error: 'Failed to create destination' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

// ── PATCH /:id ───────────────────────────────────────────────────────────

router.patch('/:id', (req, res) => {
  let db;
  try {
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ error: 'Request body required' });
    }
    db = getDb();
    let destination;
    try {
      destination = backupDestinations.updateDestination(db, req.params.id, req.body);
    } catch (err) {
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
    // Build a concise change summary for audit (non-sensitive fields only)
    const changedFields = Object.keys(req.body).filter(k => !['credentials', 'config'].includes(k));
    if (req.body.config !== undefined) changedFields.push('config');         // mention but don't log values
    if (req.body.credentials !== undefined) changedFields.push('credentials'); // mention but don't log values
    auditLog(req.user?.id, 'BACKUP_DESTINATION_UPDATED', `id=${destination.id} name=${destination.name} fields=${changedFields.join(',') || 'none'}`, req.ip);
    res.json({ destination });
  } catch (err) {
    logger.error('routes/backup-destinations: update failed', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Failed to update destination' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

// ── DELETE /:id ──────────────────────────────────────────────────────────

router.delete('/:id', (req, res) => {
  let db;
  try {
    db = getDb();
    const result = backupDestinations.deleteDestination(db, req.params.id);
    if (result.deleted === false) {
      if (result.reason === 'not_found') {
        return res.status(404).json({ error: 'Destination not found' });
      }
      if (result.reason === 'has_push_history') {
        auditLog(req.user?.id, 'BACKUP_DESTINATION_DELETE_REFUSED', `id=${req.params.id} reason=has_push_history`, req.ip);
        return res.status(409).json({
          error: 'Destination has push history; cannot delete',
          reason: result.reason,
          detail: result.detail,
          remediation: 'PATCH enabled=false to retire the destination while preserving audit continuity',
        });
      }
      // FK constraint hit (defense in depth)
      return res.status(409).json({ error: 'Cannot delete destination', reason: result.reason, detail: result.detail });
    }
    auditLog(req.user?.id, 'BACKUP_DESTINATION_DELETED', `id=${req.params.id}`, req.ip);
    res.json({ deleted: true });
  } catch (err) {
    logger.error('routes/backup-destinations: delete failed', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Failed to delete destination' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

// ── POST /:id/probe ──────────────────────────────────────────────────────

router.post('/:id/probe', async (req, res) => {
  let db;
  try {
    db = getDb();
    // Verify the destination exists before running the probe
    const dest = backupDestinations.getDestinationById(db, req.params.id);
    if (!dest) return res.status(404).json({ error: 'Destination not found' });

    const probeResult = await backupDestinations.probeDestination(db, req.params.id);
    auditLog(
      req.user?.id,
      probeResult.ok ? 'BACKUP_DESTINATION_PROBE_OK' : 'BACKUP_DESTINATION_PROBE_FAILED',
      `id=${req.params.id} name=${dest.name} adapter=${dest.adapter}${probeResult.ok ? '' : ' error=' + (probeResult.error || 'unknown')}`,
      req.ip,
    );
    res.json({ probe: probeResult });
  } catch (err) {
    logger.error('routes/backup-destinations: probe failed', { id: req.params.id, error: err.message });
    res.status(500).json({ error: 'Failed to probe destination' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

module.exports = router;

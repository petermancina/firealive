// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Storage Routing Admin Routes (B5q)
//
// Admin API for the per-data-type storage routes: which destination (a primary
// plus an optional secondary) each routed data type is written to. Backs the
// storage routing tab in the management console.
//
//   GET    /api/storage-routing            list every data type's route (with
//                                          resolved destination names)
//   GET    /api/storage-routing/:type      one data type's route
//   PUT    /api/storage-routing/:type      set a data type's primary + optional
//                                          secondary (validated + audited)
//   POST   /api/storage-routing/:type/test probe the type's routed destination(s)
//
// Writes go through storageRouting.writeRoute, which runs the immutability +
// residency gates on BOTH the primary and the secondary and returns a typed
// failure ({ code, which, ... }); this layer maps those to HTTP status and
// audits. Mounting (index.js) applies admin auth + the config-write chokepoint,
// so these handlers assume an authenticated admin and only read req.user.id for
// the audit actor. Credentials are never read or returned here; the test probe
// decrypts them just-in-time inside the destinations service.
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const router = express.Router();

const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { requireObjectBody } = require('../middleware/body-validation');
const { logger } = require('../services/logger');
const storageRouting = require('../services/storage-routing');
const storageDestinations = require('../services/storage-destinations');

function actorOf(req) {
  return req.user && req.user.id ? req.user.id : 'system';
}

function isValidType(type) {
  return storageRouting.VALID_DATA_TYPES.indexOf(type) !== -1;
}

// Map a writeRoute typed-failure code to an HTTP status. A residency refusal is a
// policy decision (forbidden); everything else is a bad request.
function statusForCode(code) {
  return code === 'RESIDENCY_BLOCKED' ? 403 : 400;
}

// Resolve the configured destination refs to display names (config only, never
// credentials), so the console can show names alongside the stored ids.
function enrichRoute(db, route) {
  const nameOf = (ref) => {
    if (!ref) return null;
    try {
      const d = storageDestinations.getDestinationById(db, ref);
      return d ? d.name : null;
    } catch (e) {
      return null;
    }
  };
  return Object.assign({}, route, {
    destinationName: nameOf(route.destinationRef),
    secondaryDestinationName: nameOf(route.secondaryDestinationRef),
  });
}

// ── GET / ────────────────────────────────────────────────────────────────

router.get('/', (req, res) => {
  const db = getDb();
  try {
    const routes = storageRouting.readRoutes(db).map((r) => enrichRoute(db, r));
    auditLog(actorOf(req), 'STORAGE_ROUTING_VIEWED', `types=${routes.length}`, req.ip);
    return res.json({ routes: routes });
  } catch (err) {
    logger.error('routes/storage-routing: list failed', { error: err.message });
    return res.status(500).json({ error: 'failed to list storage routes' });
  } finally {
    try { db.close(); } catch { /* swallow */ }
  }
});

// ── GET /:type ─────────────────────────────────────────────────────────────

router.get('/:type', (req, res) => {
  const type = req.params.type;
  if (!isValidType(type)) {
    return res.status(404).json({ error: 'unknown data type', validTypes: storageRouting.VALID_DATA_TYPES });
  }
  const db = getDb();
  try {
    const route = enrichRoute(db, storageRouting.readRoute(db, type));
    auditLog(actorOf(req), 'STORAGE_ROUTING_VIEWED', `type=${type}`, req.ip);
    return res.json({ route: route });
  } catch (err) {
    logger.error('routes/storage-routing: get failed', { type: type, error: err.message });
    return res.status(500).json({ error: 'failed to read storage route' });
  } finally {
    try { db.close(); } catch { /* swallow */ }
  }
});

// ── PUT /:type ─────────────────────────────────────────────────────────────

router.put('/:type', requireObjectBody, (req, res) => {
  const type = req.params.type;
  if (!isValidType(type)) {
    return res.status(404).json({ error: 'unknown data type', validTypes: storageRouting.VALID_DATA_TYPES });
  }
  const db = getDb();
  try {
    const result = storageRouting.writeRoute(db, type, req.body, actorOf(req));
    if (!result.ok) {
      // Audit the refusal; residency blocks are surfaced distinctly.
      const event = result.code === 'RESIDENCY_BLOCKED' ? 'STORAGE_ROUTING_BLOCKED' : 'STORAGE_ROUTING_REJECTED';
      auditLog(actorOf(req), event, `type=${type} code=${result.code} which=${result.which || '-'}`, req.ip);
      const body = { error: result.error, code: result.code };
      if (result.field) body.field = result.field;
      if (result.which) body.which = result.which;
      if (result.residency) body.residency = result.residency;
      return res.status(statusForCode(result.code)).json(body);
    }

    const route = enrichRoute(db, result.route);
    auditLog(
      actorOf(req),
      'STORAGE_ROUTING_SET',
      `type=${type} primary=${route.destinationRef || 'none'} secondary=${route.secondaryDestinationRef || 'none'} enabled=${route.enabled}`,
      req.ip,
    );
    return res.json({ success: true, route: route });
  } catch (err) {
    logger.error('routes/storage-routing: set failed', { type: type, error: err.message });
    return res.status(500).json({ error: 'failed to set storage route' });
  } finally {
    try { db.close(); } catch { /* swallow */ }
  }
});

// ── POST /:type/test ─────────────────────────────────────────────────────

router.post('/:type/test', async (req, res) => {
  const type = req.params.type;
  if (!isValidType(type)) {
    return res.status(404).json({ error: 'unknown data type', validTypes: storageRouting.VALID_DATA_TYPES });
  }
  let db;
  try {
    db = getDb();
    const route = storageRouting.readRoute(db, type);
    const targets = [];
    if (route.destinationRef) targets.push({ role: 'primary', ref: route.destinationRef });
    if (route.secondaryDestinationRef) targets.push({ role: 'secondary', ref: route.secondaryDestinationRef });

    if (targets.length === 0) {
      auditLog(actorOf(req), 'STORAGE_ROUTING_TEST', `type=${type} configured=false`, req.ip);
      return res.json({ dataType: type, configured: false, results: [] });
    }

    const results = [];
    for (let i = 0; i < targets.length; i += 1) {
      const t = targets[i];
      const dest = storageDestinations.getDestinationById(db, t.ref);
      if (!dest) {
        results.push({ role: t.role, ref: t.ref, name: null, ok: false, error: 'destination not found' });
        continue;
      }
      let probe;
      try {
        probe = await storageDestinations.probeDestination(db, t.ref);
      } catch (probeErr) {
        probe = { ok: false, error: probeErr.message };
      }
      results.push({ role: t.role, ref: t.ref, name: dest.name, ok: probe.ok === true, error: probe.ok ? undefined : (probe.error || 'unknown'), detail: probe.detail });
    }

    const allOk = results.every((r) => r.ok);
    auditLog(
      actorOf(req),
      allOk ? 'STORAGE_ROUTING_TEST_OK' : 'STORAGE_ROUTING_TEST_FAILED',
      `type=${type} probed=${results.length} ok=${results.filter((r) => r.ok).length}`,
      req.ip,
    );
    return res.json({ dataType: type, configured: true, ok: allOk, results: results });
  } catch (err) {
    logger.error('routes/storage-routing: test failed', { type: type, error: err.message });
    return res.status(500).json({ error: 'failed to test storage route' });
  } finally {
    if (db) try { db.close(); } catch { /* swallow */ }
  }
});

module.exports = router;

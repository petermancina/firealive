// =============================================================================
// FIREALIVE GD -- Storage Routing Admin Routes
//
// Admin API for the per-data-type storage routes: which destination (a primary
// plus an optional secondary) each routed data type is written to. Backs the
// storage routing tab. Twins the Regional storage-routing routes.
//
//   GET    /                 list every data type's route (with resolved names)
//   GET    /replication      per-data-type replication health (before /:type so
//                            'replication' is not captured as a data type)
//   GET    /:type            one data type's route
//   PUT    /:type            set a data type's primary + optional secondary
//                            (validated + audited)
//   POST   /:type/test       probe the type's routed destination(s)
//
// Writes go through gd-storage-routing.writeRoute, which runs the immutability
// (and, once wired, residency) gates on BOTH the primary and secondary and returns
// a typed failure ({ code, which, field, ... }); this layer maps those to HTTP
// status and audits. Mounting (index.js) applies auth + the config-lock chokepoint,
// so these handlers assume an authenticated operator and only read req.user.id for
// the audit actor. Credentials are never read or returned; the test probe decrypts
// them just-in-time inside the destinations service.
// =============================================================================

const express = require('express');
const router = express.Router();

const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const storageRouting = require('../services/gd-storage-routing');
const storageDestinations = require('../services/gd-storage-destinations');
const replicationStatus = require('../services/gd-replication-status');

function actorOf(req) {
  return req.user && req.user.id ? req.user.id : 'system';
}

function _audit(db, req, eventType, detail) {
  try {
    appendGdAuditEntry(db, { userId: actorOf(req), eventType, detail, ip: (req && req.ip) || null, severity: 'info' });
  } catch (e) {
    try { console.warn('[storage-routing] audit failed:', e && e.message); } catch (_e) { /* ignore */ }
  }
}

function isValidType(type) {
  return storageRouting.VALID_DATA_TYPES.indexOf(type) !== -1;
}

// A residency refusal is a policy decision (forbidden); everything else is a bad
// request.
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
    } catch (_e) {
      return null;
    }
  };
  return Object.assign({}, route, {
    destinationName: nameOf(route.destinationRef),
    secondaryDestinationName: nameOf(route.secondaryDestinationRef),
  });
}

// -- GET / --------------------------------------------------------------------
router.get('/', (req, res) => {
  let db;
  try {
    db = getDb();
    const routes = storageRouting.readRoutes(db).map((r) => enrichRoute(db, r));
    _audit(db, req, 'STORAGE_ROUTING_VIEWED', `types=${routes.length}`);
    return res.json({ routes });
  } catch (err) {
    console.error('routes/storage-routing: list failed:', err.message);
    return res.status(500).json({ error: 'failed to list storage routes' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- GET /replication (before /:type) -----------------------------------------
router.get('/replication', (req, res) => {
  let db;
  try {
    db = getDb();
    const replication = replicationStatus.getReplicationStatus(db);
    _audit(db, req, 'STORAGE_REPLICATION_VIEWED', `types=${replication.length}`);
    return res.json({ replication });
  } catch (err) {
    console.error('routes/storage-routing: replication status failed:', err.message);
    return res.status(500).json({ error: 'failed to read replication status' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- GET /:type ---------------------------------------------------------------
router.get('/:type', (req, res) => {
  let db;
  const type = req.params.type;
  if (!isValidType(type)) {
    return res.status(404).json({ error: 'unknown data type', validTypes: storageRouting.VALID_DATA_TYPES });
  }
  try {
    db = getDb();
    const route = enrichRoute(db, storageRouting.readRoute(db, type));
    _audit(db, req, 'STORAGE_ROUTING_VIEWED', `type=${type}`);
    return res.json({ route });
  } catch (err) {
    console.error('routes/storage-routing: get failed:', err.message);
    return res.status(500).json({ error: 'failed to read storage route' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- PUT /:type ---------------------------------------------------------------
router.put('/:type', (req, res) => {
  let db;
  const type = req.params.type;
  if (!isValidType(type)) {
    return res.status(404).json({ error: 'unknown data type', validTypes: storageRouting.VALID_DATA_TYPES });
  }
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'request body required' });
  }
  try {
    db = getDb();
    const result = storageRouting.writeRoute(db, type, req.body, actorOf(req));
    if (!result.ok) {
      const event = result.code === 'RESIDENCY_BLOCKED' ? 'STORAGE_ROUTING_BLOCKED' : 'STORAGE_ROUTING_REJECTED';
      _audit(db, req, event, `type=${type} code=${result.code} which=${result.which || '-'}`);
      const body = { error: result.error, code: result.code };
      if (result.field) body.field = result.field;
      if (result.which) body.which = result.which;
      if (result.residency) body.residency = result.residency;
      return res.status(statusForCode(result.code)).json(body);
    }

    const route = enrichRoute(db, result.route);
    _audit(db, req, 'STORAGE_ROUTING_SET',
      `type=${type} primary=${route.destinationRef || 'none'} secondary=${route.secondaryDestinationRef || 'none'} enabled=${route.enabled}`);
    return res.json({ success: true, route });
  } catch (err) {
    console.error('routes/storage-routing: set failed:', err.message);
    return res.status(500).json({ error: 'failed to set storage route' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

// -- POST /:type/test ---------------------------------------------------------
router.post('/:type/test', async (req, res) => {
  let db;
  const type = req.params.type;
  if (!isValidType(type)) {
    return res.status(404).json({ error: 'unknown data type', validTypes: storageRouting.VALID_DATA_TYPES });
  }
  try {
    db = getDb();
    const route = storageRouting.readRoute(db, type);
    const targets = [];
    if (route.destinationRef) targets.push({ role: 'primary', ref: route.destinationRef });
    if (route.secondaryDestinationRef) targets.push({ role: 'secondary', ref: route.secondaryDestinationRef });

    if (targets.length === 0) {
      _audit(db, req, 'STORAGE_ROUTING_TEST', `type=${type} configured=false`);
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
    _audit(db, req, allOk ? 'STORAGE_ROUTING_TEST_OK' : 'STORAGE_ROUTING_TEST_FAILED',
      `type=${type} probed=${results.length} ok=${results.filter((r) => r.ok).length}`);
    return res.json({ dataType: type, configured: true, ok: allOk, results });
  } catch (err) {
    console.error('routes/storage-routing: test failed:', err.message);
    return res.status(500).json({ error: 'failed to test storage route' });
  } finally {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
});

module.exports = router;

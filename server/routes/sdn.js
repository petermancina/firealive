// FIREALIVE -- SDN admin routes (B5i SDN Mode)
//
// Admin API surface for SDN Mode. Mounted in index.js behind admin auth and the
// config-lock chokepoint:
//
//   app.use('/api/sdn', authMiddleware(['admin']), configLockChokepoint(),
//           require('./routes/sdn'));
//
// Endpoints:
//   GET    /integrations                  list controller integrations (no creds)
//   POST   /integrations                  create an integration
//   GET    /integrations/:id              read one (no creds)
//   PUT    /integrations/:id              update one (credentials omission-rule)
//   DELETE /integrations/:id              remove one (posture events preserved)
//   POST   /integrations/:id/probe        on-demand read-only reachability probe
//   GET    /integrations/:id/topology     read-only controller topology read
//   GET    /integrations/:id/segmentation read-only controller segmentation read
//   GET    /network-map                   read the operator-declared topology map
//   PUT    /network-map                   update the topology map
//   GET    /posture                       current aggregate posture + recent events
//   GET    /segment-policy/:platform      generate a segmentation-policy artifact
//
// Security invariants:
//   - Credentials are WRITE-ONLY. No response ever returns api_credentials; reads
//     surface only a credentialsConfigured boolean. The credential blob is the
//     Tier-1 KEK wrap (encryptConfig) that the probe scheduler decrypts.
//   - READ-ONLY toward the controller. probe / topology / segmentation use the
//     registry's read-only adapters, which structurally cannot expose a write
//     verb. This route never applies, pushes, or programs any controller policy.
//   - platform is immutable after creation (it pins the adapter + schema CHECK).
//   - Audit records operator identity and whether credentials changed -- never
//     credential values.
//
// ASCII only; no template literals.

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { sealTier1, openTier1 } = require('../services/tier1-seal');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const registry = require('../services/sdn');
const sdnMode = require('../services/sdn-mode');
const sdnPosture = require('../services/sdn-posture');
const segmentPolicy = require('../services/sdn-segment-policy');

// Map a service error to an HTTP status. Validation/unsupported -> 400, missing
// -> 404, otherwise 500.
function statusForError(err) {
  const code = (err && err.code) ? String(err.code) : '';
  if (code === 'UNSUPPORTED_PLATFORM' || code.indexOf('INVALID_') === 0) return 400;
  if (code === 'NOT_FOUND') return 404;
  return 500;
}

// Public projection of an integration row -- never includes credentials.
function rowToPublic(row) {
  return {
    id: row.id,
    name: row.name,
    platform: row.platform,
    apiEndpoint: row.api_endpoint,
    endpointFingerprint: row.endpoint_fingerprint,
    enabled: !!row.enabled,
    credentialsConfigured: !!row.api_credentials_encrypted,
    lastProbeAt: row.last_probe_at,
    lastProbeStatus: row.last_probe_status,
    lastProbeDetail: row.last_probe_detail,
    consecutiveFailures: row.consecutive_failures,
    consecutiveSuccesses: row.consecutive_successes,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

// Decrypt the stored credential blob and assemble the adapter config used by the
// read-only adapters (probe / topology / segmentation).
function loadAdapterConfig(row) {
  let credentials = {};
  if (row.api_credentials_encrypted) {
    credentials = openTier1('sdn_integrations.api_credentials_encrypted', row.api_credentials_encrypted);
  }
  return {
    apiEndpoint: row.api_endpoint,
    endpointFingerprint: row.endpoint_fingerprint,
    credentials: credentials || {}
  };
}

function isPlainObject(v) {
  return v && typeof v === 'object' && !Array.isArray(v);
}

// -- Integrations: list / read ------------------------------------------------

router.get('/integrations', function (req, res) {
  const db = getDb();
  try {
    const rows = db.prepare('SELECT * FROM sdn_integrations ORDER BY created_at DESC, rowid DESC').all();
    return res.json({ integrations: rows.map(rowToPublic) });
  } catch (e) {
    logger.error('SDN list integrations failed', { error: e.message });
    return res.status(500).json({ error: 'failed to list integrations' });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

router.get('/integrations/:id', function (req, res) {
  const db = getDb();
  try {
    const row = db.prepare('SELECT * FROM sdn_integrations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'integration not found' });
    return res.json({ integration: rowToPublic(row) });
  } catch (e) {
    return res.status(500).json({ error: 'failed to read integration' });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

// -- Integrations: create -----------------------------------------------------

router.post('/integrations', function (req, res) {
  const db = getDb();
  try {
    const body = req.body || {};
    const name = (typeof body.name === 'string') ? body.name.trim() : '';
    const platform = (typeof body.platform === 'string') ? body.platform.trim() : '';
    const apiEndpoint = (typeof body.apiEndpoint === 'string') ? body.apiEndpoint.trim() : '';
    const endpointFingerprint = (typeof body.endpointFingerprint === 'string') ? body.endpointFingerprint.trim() : null;

    if (!name) return res.status(400).json({ error: 'name is required' });
    if (!registry.isSupported(platform)) {
      return res.status(400).json({ error: 'unsupported platform', validPlatforms: registry.listPlatforms() });
    }
    if (!apiEndpoint) return res.status(400).json({ error: 'apiEndpoint is required' });

    const credentials = isPlainObject(body.credentials) ? body.credentials : {};
    const encrypted = sealTier1('sdn_integrations.api_credentials_encrypted', credentials);
    const id = crypto.randomBytes(16).toString('hex');

    db.prepare(
      'INSERT INTO sdn_integrations (id, name, platform, api_endpoint, api_credentials_encrypted, endpoint_fingerprint, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(id, name, platform, apiEndpoint, encrypted, endpointFingerprint, req.user ? req.user.id : null);

    const credentialsSet = Object.keys(credentials).length > 0;
    try { auditLog(req.user ? req.user.id : null, 'SDN_INTEGRATION_CREATED', 'id=' + id + ' platform=' + platform + ' credentialsSet=' + credentialsSet, req.ip); } catch (_e) {}

    const row = db.prepare('SELECT * FROM sdn_integrations WHERE id = ?').get(id);
    return res.status(201).json({ integration: rowToPublic(row) });
  } catch (e) {
    logger.error('SDN create integration failed', { error: e.message });
    return res.status(500).json({ error: 'failed to create integration' });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

// -- Integrations: update (credentials omission-rule) -------------------------

router.put('/integrations/:id', function (req, res) {
  const db = getDb();
  try {
    const row = db.prepare('SELECT * FROM sdn_integrations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'integration not found' });

    const body = req.body || {};
    if (body.platform !== undefined && body.platform !== row.platform) {
      return res.status(400).json({ error: 'platform cannot be changed; delete and recreate the integration' });
    }

    const name = (typeof body.name === 'string' && body.name.trim()) ? body.name.trim() : row.name;
    const apiEndpoint = (typeof body.apiEndpoint === 'string' && body.apiEndpoint.trim()) ? body.apiEndpoint.trim() : row.api_endpoint;
    const endpointFingerprint = (body.endpointFingerprint === undefined)
      ? row.endpoint_fingerprint
      : ((typeof body.endpointFingerprint === 'string') ? body.endpointFingerprint.trim() : null);
    const enabled = (body.enabled === undefined) ? row.enabled : (body.enabled ? 1 : 0);

    // Omission-rule: credentials absent -> preserve the existing blob; an empty
    // object or null -> explicit clear; a populated object -> re-encrypt.
    let encrypted = row.api_credentials_encrypted;
    let credentialsChanged = false;
    if (body.credentials !== undefined) {
      if (body.credentials === null || (isPlainObject(body.credentials) && Object.keys(body.credentials).length === 0)) {
        encrypted = sealTier1('sdn_integrations.api_credentials_encrypted', {});
        credentialsChanged = true;
      } else if (isPlainObject(body.credentials)) {
        encrypted = sealTier1('sdn_integrations.api_credentials_encrypted', body.credentials);
        credentialsChanged = true;
      }
    }

    db.prepare(
      "UPDATE sdn_integrations SET name = ?, api_endpoint = ?, api_credentials_encrypted = ?, endpoint_fingerprint = ?, enabled = ?, updated_at = datetime('now') WHERE id = ?"
    ).run(name, apiEndpoint, encrypted, endpointFingerprint, enabled, row.id);

    try { auditLog(req.user ? req.user.id : null, 'SDN_INTEGRATION_UPDATED', 'id=' + row.id + ' credentialsChanged=' + credentialsChanged, req.ip); } catch (_e) {}

    const updated = db.prepare('SELECT * FROM sdn_integrations WHERE id = ?').get(row.id);
    return res.json({ integration: rowToPublic(updated) });
  } catch (e) {
    logger.error('SDN update integration failed', { error: e.message });
    return res.status(500).json({ error: 'failed to update integration' });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

// -- Integrations: delete (preserve append-only posture events) ---------------

router.delete('/integrations/:id', function (req, res) {
  const db = getDb();
  try {
    const row = db.prepare('SELECT id, platform FROM sdn_integrations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'integration not found' });

    const tx = db.transaction(function () {
      // Detach (do not delete) the append-only posture events, preserving the
      // event history while satisfying the foreign key.
      db.prepare('UPDATE sdn_posture_events SET integration_id = NULL WHERE integration_id = ?').run(row.id);
      db.prepare('DELETE FROM sdn_integrations WHERE id = ?').run(row.id);
    });
    tx();

    try { auditLog(req.user ? req.user.id : null, 'SDN_INTEGRATION_DELETED', 'id=' + row.id + ' platform=' + row.platform, req.ip); } catch (_e) {}
    return res.json({ deleted: true, id: row.id });
  } catch (e) {
    logger.error('SDN delete integration failed', { error: e.message });
    return res.status(500).json({ error: 'failed to delete integration' });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

// -- Integrations: on-demand probe (read-only) --------------------------------

router.post('/integrations/:id/probe', async function (req, res) {
  const db = getDb();
  try {
    const row = db.prepare('SELECT * FROM sdn_integrations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'integration not found' });

    let status = 'error';
    let detail = null;
    try {
      const cfg = loadAdapterConfig(row);
      const adapter = registry.getAdapter(row.platform);
      const result = await adapter.probe(cfg);
      status = (result && result.status) ? result.status : 'error';
      detail = (result && result.detail) ? result.detail : null;
    } catch (e) {
      status = 'error';
      detail = 'probe setup or execution failed';
    }

    let posture = null;
    try { posture = sdnPosture.recordProbeResult(db, { integrationId: row.id, status: status, detail: detail }); } catch (_e) {}
    try { auditLog(req.user ? req.user.id : null, 'SDN_INTEGRATION_PROBED', 'id=' + row.id + ' status=' + status, req.ip); } catch (_e) {}

    return res.json({ status: status, detail: detail, posture: posture });
  } catch (e) {
    return res.status(500).json({ error: 'probe failed' });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

// -- Integrations: read-only controller reads ---------------------------------

router.get('/integrations/:id/topology', async function (req, res) {
  const db = getDb();
  try {
    const row = db.prepare('SELECT * FROM sdn_integrations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'integration not found' });
    const cfg = loadAdapterConfig(row);
    const adapter = registry.getAdapter(row.platform);
    const topology = await adapter.readTopology(cfg);
    try { sdnMode.recordPostureEvent(db, { integrationId: row.id, eventType: 'topology_read', severity: 'info', detail: { ok: true } }); } catch (_e) {}
    try { auditLog(req.user ? req.user.id : null, 'SDN_TOPOLOGY_READ', 'id=' + row.id, req.ip); } catch (_e) {}
    return res.json({ topology: topology });
  } catch (e) {
    return res.status(502).json({ error: 'controller topology read failed', detail: String(e && e.message ? e.message : 'read error') });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

router.get('/integrations/:id/segmentation', async function (req, res) {
  const db = getDb();
  try {
    const row = db.prepare('SELECT * FROM sdn_integrations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'integration not found' });
    const cfg = loadAdapterConfig(row);
    const adapter = registry.getAdapter(row.platform);
    const segmentation = await adapter.readSegmentation(cfg);
    try { sdnMode.recordPostureEvent(db, { integrationId: row.id, eventType: 'segmentation_read', severity: 'info', detail: { ok: true } }); } catch (_e) {}
    try { auditLog(req.user ? req.user.id : null, 'SDN_SEGMENTATION_READ', 'id=' + row.id, req.ip); } catch (_e) {}
    return res.json({ segmentation: segmentation });
  } catch (e) {
    return res.status(502).json({ error: 'controller segmentation read failed', detail: String(e && e.message ? e.message : 'read error') });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

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
      tierSegmentMap: body.tierSegmentMap,
      sdwanSites: body.sdwanSites,
      updatedBy: req.user ? req.user.id : null
    });
    try {
      const zoneCount = updated && updated.tierSegmentMap ? Object.keys(updated.tierSegmentMap).length : 0;
      auditLog(req.user ? req.user.id : null, 'SDN_NETWORK_MAP_UPDATED', 'zones=' + zoneCount, req.ip);
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
    const state = sdnPosture.currentPosture(db);
    const p = sdnMode.getPosture(db, { recentLimit: 20 });
    return res.json({ state: state, degraded: p.degraded, since: p.since, lastTransition: p.lastTransition, recent: p.recent });
  } catch (e) {
    return res.status(500).json({ error: 'failed to read posture' });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

// -- Segmentation-policy artifact ---------------------------------------------

router.get('/segment-policy/:platform', function (req, res) {
  const db = getDb();
  try {
    const networkMap = sdnMode.getNetworkMap(db);
    const artifact = segmentPolicy.generateSegmentPolicy(networkMap, req.params.platform);
    try { auditLog(req.user ? req.user.id : null, 'SDN_SEGMENT_POLICY_GENERATED', 'platform=' + req.params.platform, req.ip); } catch (_e) {}
    const wantsDownload = req.query && (req.query.download === '1' || req.query.download === 'true');
    if (wantsDownload) {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename="' + artifact.filename + '"');
      return res.send(artifact.content);
    }
    return res.json(artifact);
  } catch (e) {
    return res.status(statusForError(e)).json({ error: e.message || 'failed to generate segmentation policy', code: e.code });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

module.exports = router;

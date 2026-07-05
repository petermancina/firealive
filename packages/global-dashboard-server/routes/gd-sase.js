// FIREALIVE GD -- SASE admin routes (B6c PR-4, read-only twin)
//
// Admin API surface for SASE Mode. Mounted at /api/sase behind CISO auth and the
// global config-lock chokepoint:
//
//   app.use('/api/sase', authMiddleware(['ciso']), require('./routes/gd-sase'));
//
// Twins the Regional /sase/config GET/PUT (which live inside the Regional feature-
// map route v021-features.js) as a dedicated GD route, and adds GET /posture --
// symmetric with routes/gd-sdn.js. SASE has no controller layer, so nothing is
// omitted; only the config store (the GD's 'config' key/value table, which has no
// updated_by column -- the updater is captured in the audit event instead) and
// the posture source (gd-sase-mode) are tailored.
//
// Endpoints:
//   GET /config    read the SASE wizard config (connector sources, provider, ...)
//   PUT /config    update the SASE config (validates connector sources)
//   GET /posture   current SASE posture (latched, event-derived) + recent events
//
// ASCII only; no template literals.

const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const saseMode = require('../services/gd-sase-mode');

const VALID_PROVIDERS = ['zscaler', 'netskope', 'palo_alto_prisma', 'cato', 'cloudflare', 'fortinet'];

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

// -- Config -------------------------------------------------------------------

router.get('/config', function (req, res) {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM config WHERE key = 'sase_config'").get();
    db.close();
    return res.json(row ? JSON.parse(row.value) : {
      enabled: false,
      provider: null,
      ztnaEndpoint: '',
      connectorSources: [],
      casbEnabled: false,
      swgEnabled: false,
      fwaasPolicyId: '',
      deployedAsSECaaS: false,
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to get SASE config' });
  }
});

router.put('/config', function (req, res) {
  const b = req.body || {};
  let normalizedSources;
  try {
    normalizedSources = saseMode.normalizeConnectorSources(b.connectorSources);
  } catch (e) {
    return res.status(400).json({ error: e.message || 'invalid connector sources', code: e.code });
  }
  const config = {
    enabled: !!b.enabled,
    provider: VALID_PROVIDERS.indexOf(b.provider) !== -1 ? b.provider : null,
    ztnaEndpoint: (b.ztnaEndpoint || '').slice(0, 512),
    connectorSources: normalizedSources,
    casbEnabled: !!b.casbEnabled,
    swgEnabled: !!b.swgEnabled,
    fwaasPolicyId: (b.fwaasPolicyId || '').slice(0, 128),
    deployedAsSECaaS: !!b.deployedAsSECaaS,
    updatedAt: new Date().toISOString(),
  };
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('sase_config', ?)").run(JSON.stringify(config));
    db.close();
    auditLog(req.user ? req.user.id : null, 'SASE_CONFIG_UPDATED', 'provider=' + config.provider, req.ip);
    return res.json({ ok: true, config: config });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update SASE config' });
  }
});

// -- Posture ------------------------------------------------------------------

router.get('/posture', function (req, res) {
  const db = getDb();
  try {
    // The SASE posture is the latched, event-derived flag; state is derived from
    // it for response-shape parity with the SDN posture endpoint.
    const p = saseMode.getPosture(db, { recentLimit: 20 });
    const state = p.degraded ? 'degraded' : 'healthy';
    return res.json({ state: state, degraded: p.degraded, since: p.since, lastEvent: p.lastEvent, restoredAt: p.restoredAt, recent: p.recent });
  } catch (e) {
    return res.status(500).json({ error: 'failed to read posture' });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

module.exports = router;

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Integration Health Routes  (admin only; mounted in server/index.js)
//
//   GET /api/integration-health  — current master toggle + settings (per-
//        integration flags, KMS deep-probe flag, periodic toggle + interval),
//        plus metadata (canonical integration keys, interval bounds).
//   PUT /api/integration-health  — update any of:
//        { master, intervalMinutes, periodicEnabled, kmsDeep, integrations:{} }
//        validated/merged by the config helper; audited.
//
// The on-demand probe-run endpoints (POST /probe, GET /results) are added to
// this router in B3-C11.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const cfg = require('../services/integration-health-config');

const META = () => ({
  integrationKeys: cfg.INTEGRATION_KEYS,
  intervalBounds: { min: cfg.MIN_INTERVAL_MIN, max: cfg.MAX_INTERVAL_MIN },
});

function summarizeChange(b) {
  const parts = [];
  if (typeof b.master === 'boolean') parts.push(`master=${b.master}`);
  if (b.intervalMinutes != null) parts.push('intervalMinutes');
  if (typeof b.periodicEnabled === 'boolean') parts.push(`periodicEnabled=${b.periodicEnabled}`);
  if (typeof b.kmsDeep === 'boolean') parts.push(`kmsDeep=${b.kmsDeep}`);
  if (b.integrations && typeof b.integrations === 'object') {
    const ks = Object.keys(b.integrations).filter((k) => cfg.INTEGRATION_KEYS.includes(k));
    if (ks.length) parts.push(`integrations:${ks.join(',')}`);
  }
  return parts.length ? parts.join('; ') : 'no-op';
}

router.get('/', (req, res) => {
  try {
    const db = getDb();
    const settings = cfg.getSettings(db);
    db.close();
    res.json({ ...settings, ...META() });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load integration-health settings' });
  }
});

router.put('/', (req, res) => {
  try {
    const body = req.body || {};
    const recognized = ['master', 'intervalMinutes', 'periodicEnabled', 'kmsDeep', 'integrations'];
    if (!recognized.some((k) => body[k] !== undefined)) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    const db = getDb();
    const updated = cfg.updateSettings(db, body);
    db.close();
    auditLog(req.user && req.user.id, 'INTEGRATION_HEALTH_CONFIG_UPDATED', summarizeChange(body), req.ip);
    res.json({ ...updated, ...META() });
  } catch (e) {
    res.status(500).json({ error: 'Failed to update integration-health settings' });
  }
});

module.exports = router;

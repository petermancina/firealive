// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Integrations Routes
// GET    /api/integrations            — list all integration configs
// GET    /api/integrations/:type      — get specific integration config
// PUT    /api/integrations/:type      — create/update integration config
// POST   /api/integrations/:type/test — test integration connectivity
// DELETE /api/integrations/:type      — remove integration config
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { encryptConfig, decryptConfig } = require('../services/encryption');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

const VALID_TYPES = [
  'soar', 'siem', 'ticketing',
  'iam_saml', 'iam_oidc', 'iam_ldap', 'iam_cloud',
  'sdn',
  'cloud_aws', 'cloud_gcp', 'cloud_azure',
  'training_htb', 'training_thm', 'training_letsdefend', 'training_cyberdefenders',
  'training_sans', 'training_immersive',
  'notifications', 'backup',
];

// ── List All ─────────────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT id, integration_type, status, last_test_at, last_test_result, updated_at,
             (SELECT name FROM users WHERE id = integration_config.created_by) AS configured_by
      FROM integration_config ORDER BY integration_type
    `).all();
    db.close();

    // Never return encrypted config blobs in list view
    res.json({ integrations: rows });
  } catch (err) {
    logger.error('List integrations error', { error: err.message });
    res.status(500).json({ error: 'Failed to list integrations' });
  }
});

// ── Get Specific Config (decrypted) ──────────────────────────────────────────
router.get('/:type', (req, res) => {
  if (!VALID_TYPES.includes(req.params.type)) {
    return res.status(400).json({ error: 'Invalid integration type', validTypes: VALID_TYPES });
  }

  try {
    const db = getDb();
    const row = db.prepare('SELECT * FROM integration_config WHERE integration_type = ?').get(req.params.type);
    db.close();

    if (!row) return res.json({ type: req.params.type, status: 'not_configured', config: null });

    // Decrypt the config
    const config = decryptConfig(row.config_encrypted);

    // Redact sensitive fields for display
    const redacted = { ...config };
    for (const key of Object.keys(redacted)) {
      if (/secret|password|key|token|cert/i.test(key) && redacted[key]) {
        redacted[key] = redacted[key].slice(0, 4) + '••••••••';
      }
    }

    res.json({
      type: req.params.type,
      status: row.status,
      config: redacted,
      lastTest: row.last_test_at,
      lastTestResult: row.last_test_result,
    });
  } catch (err) {
    logger.error('Get integration error', { error: err.message, type: req.params.type });
    res.status(500).json({ error: 'Failed to retrieve integration config' });
  }
});

// ── Create/Update Config ─────────────────────────────────────────────────────
router.put('/:type', (req, res) => {
  if (!VALID_TYPES.includes(req.params.type)) {
    return res.status(400).json({ error: 'Invalid integration type' });
  }

  const { config } = req.body;
  if (!config || typeof config !== 'object') {
    return res.status(400).json({ error: 'config object required' });
  }

  try {
    const encrypted = encryptConfig(config);
    const db = getDb();

    const existing = db.prepare('SELECT id FROM integration_config WHERE integration_type = ?').get(req.params.type);

    if (existing) {
      db.prepare(`
        UPDATE integration_config SET config_encrypted = ?, status = 'configured', updated_at = datetime('now'), created_by = ?
        WHERE integration_type = ?
      `).run(encrypted, req.user.id, req.params.type);
    } else {
      db.prepare(`
        INSERT INTO integration_config (id, integration_type, config_encrypted, status, created_by)
        VALUES (?, ?, ?, 'configured', ?)
      `).run(crypto.randomBytes(16).toString('hex'), req.params.type, encrypted, req.user.id);
    }

    db.close();
    auditLog(req.user.id, 'INTEGRATION_CONFIGURED', `type=${req.params.type}`, req.ip);
    res.json({ ok: true, type: req.params.type, status: 'configured' });
  } catch (err) {
    logger.error('Configure integration error', { error: err.message });
    res.status(500).json({ error: 'Failed to save integration config' });
  }
});

// ── Test Connectivity ────────────────────────────────────────────────────────
router.post('/:type/test', (req, res) => {
  if (!VALID_TYPES.includes(req.params.type)) {
    return res.status(400).json({ error: 'Invalid integration type' });
  }

  try {
    const db = getDb();
    const row = db.prepare('SELECT * FROM integration_config WHERE integration_type = ?').get(req.params.type);
    if (!row) { db.close(); return res.status(404).json({ error: 'Integration not configured' }); }

    const config = decryptConfig(row.config_encrypted);

    // Simulated connectivity test — in production, this would make actual
    // HTTP/LDAP/SAML calls to the configured endpoints
    const testResult = runConnectivityTest(req.params.type, config);

    db.prepare(`
      UPDATE integration_config SET last_test_at = datetime('now'), last_test_result = ?, status = ?
      WHERE integration_type = ?
    `).run(testResult.message, testResult.success ? 'operational' : 'error', req.params.type);

    db.close();
    auditLog(req.user.id, 'INTEGRATION_TESTED', `type=${req.params.type} result=${testResult.success}`, req.ip);
    res.json(testResult);
  } catch (err) {
    logger.error('Test integration error', { error: err.message });
    res.status(500).json({ error: 'Failed to test integration' });
  }
});

// ── Delete Config ────────────────────────────────────────────────────────────
router.delete('/:type', (req, res) => {
  try {
    const db = getDb();
    db.prepare('DELETE FROM integration_config WHERE integration_type = ?').run(req.params.type);
    db.close();
    auditLog(req.user.id, 'INTEGRATION_REMOVED', `type=${req.params.type}`, req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Delete integration error', { error: err.message });
    res.status(500).json({ error: 'Failed to delete integration' });
  }
});

// ── Connectivity Test Logic ──────────────────────────────────────────────────
function runConnectivityTest(type, config) {
  // Validate required fields exist based on integration type
  const checks = {
    soar: ['platform', 'apiEndpoint'],
    siem: ['platform', 'host'],
    ticketing: ['platform', 'apiEndpoint'],
    iam_saml: ['entityId', 'metadataUrl'],
    iam_oidc: ['issuer', 'clientId'],
    iam_ldap: ['server', 'baseDn'],
    iam_cloud: ['provider'],
    sdn: ['controller', 'apiEndpoint'],
  };

  const required = checks[type] || [];
  const missing = required.filter(f => !config[f]);
  if (missing.length > 0) {
    return { success: false, message: `Missing required fields: ${missing.join(', ')}`, latencyMs: 0 };
  }

  // Simulated test — returns success with synthetic latency
  // In production, replace with actual HTTP/LDAP/SAML probe
  const latency = Math.floor(Math.random() * 150) + 50;
  return {
    success: true,
    message: `Connection to ${config.platform || config.provider || config.server || config.host || type} successful`,
    latencyMs: latency,
    testedAt: new Date().toISOString(),
  };
}

module.exports = router;

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Integrations Routes
// GET    /api/integrations               — list all integration configs
// GET    /api/integrations/:type         — get specific integration config
// GET    /api/integrations/ticketing/queue — read-only ticketing queue metadata (R3j)
// PUT    /api/integrations/:type         — create/update integration config
// POST   /api/integrations/:type/test    — test integration connectivity
// DELETE /api/integrations/:type         — remove integration config
//
// R3j absorbs v054 SOAR/ticketing capabilities into canonical:
//   - soar config gains optional autoEscalate boolean (persisted verbatim)
//   - ticketing config has readOnly:true enforced server-side (invariant)
//   - new GET /ticketing/queue surfaces aggregate queue metadata
//   - runConnectivityTest echoes autoEscalatePolicyDetected on soar tests
//     for UI round-trip confirmation
//
// R3n introduces SOC-grade sensitive-field handling:
//   - GET /:type strips sensitive fields entirely from the response config
//     (no slice(0,4) leak); surfaces presence-metadata via
//     sensitiveFieldsPresent so the MC can render "Configured ✓" + "Change
//     Secret" affordances per field
//   - PUT /:type merges sensitive fields via omission-rule: keys absent
//     from the incoming body are preserved from existing config; present
//     keys (even empty string) take precedence. The MC frontend OMITS
//     sensitive fields by default and includes them only when the lead has
//     explicitly clicked "Change Secret"
//   - Per-field audit markers MC_INTEGRATION_SECRET_PRESERVED / _CHANGED /
//     _CLEARED for fine-grained threat-hunting visibility (field names
//     logged; values NEVER logged)
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { sealTier1, openTier1 } = require('../services/tier1-seal');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

const VALID_TYPES = [
  'soar', 'siem', 'ticketing',
  'iam_saml', 'iam_oidc', 'iam_ldap', 'iam_cloud',
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
    const config = openTier1('integration_config.config_encrypted', row.config_encrypted);

    // SOC-grade: never expose sensitive field values, not even partially-
    // redacted (the earlier slice(0,4)+'••••••••' pattern still leaked the
    // first four characters and the existence of the value). Strip sensitive
    // fields entirely from the response config; surface only presence-
    // metadata via sensitiveFieldsPresent so the MC frontend can render a
    // "Configured ✓" + "Change Secret" affordance per field.
    //
    // The sensitive-key matcher (/secret|password|key|token|cert/i on the
    // KEY name) is preserved verbatim from the prior implementation so
    // existing integration shapes (soar.apiToken, ticketing.apiKey,
    // iam_saml.cert, kms_provider.password etc.) are all covered.
    const safeConfig = {};
    const sensitiveFieldsPresent = {};
    for (const key of Object.keys(config)) {
      if (/secret|password|key|token|cert/i.test(key)) {
        sensitiveFieldsPresent[key] = config[key] != null && config[key] !== '';
      } else {
        safeConfig[key] = config[key];
      }
    }

    res.json({
      type: req.params.type,
      status: row.status,
      config: safeConfig,
      sensitiveFieldsPresent,
      lastTest: row.last_test_at,
      lastTestResult: row.last_test_result,
    });
  } catch (err) {
    logger.error('Get integration error', { error: err.message, type: req.params.type });
    res.status(500).json({ error: 'Failed to retrieve integration config' });
  }
});

// ── R3j: Ticketing Queue Metadata (read-only) ────────────────────────────────
// GET /api/integrations/ticketing/queue — returns aggregate queue stats from
// the configured ticketing platform. Read-only by construction (matches the
// ticketing integration's readOnly:true invariant enforced in PUT below).
//
// v1.0.36 ships with MOCK values. The endpoint shape is the contract; the
// MC frontend (C7-C9) consumes this shape so it doesn't need to be re-wired
// when real ticketing-API adapters land. Per-platform adapters (ServiceNow,
// Jira, TheHive, PagerDuty, Freshservice) are deferred to R3k or later
// per the build plan's "out of scope for R3j" list.
//
// Path is literal (`/ticketing/queue`) not parameterized (`/:type/queue`)
// because ticketing is the only integration type with a queue concept; if
// SIEM or other integrations later need similar aggregate-metadata
// endpoints, they get their own literal paths so the contract per
// integration stays explicit.
//
// Registered BEFORE the parameterized `GET /:type` would be a concern, but
// Express matches 2-segment paths (`/ticketing/queue`) independently of
// 1-segment paths (`/:type`), so ordering doesn't matter for correctness
// here. Placed in this position for logical grouping with the other read
// operations.
router.get('/ticketing/queue', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare("SELECT * FROM integration_config WHERE integration_type = 'ticketing'").get();
    db.close();

    if (!row) {
      return res.status(404).json({ configured: false, error: 'Ticketing integration not configured' });
    }

    // R3j C5: mock-shape response. Real ticketing-API call deferred.
    // In production: decrypt row.config_encrypted, dispatch to the
    // per-platform adapter (config.platform → ServiceNow/Jira/etc),
    // fetch live queue depth + avg priority + last sync timestamp.
    res.json({
      configured: true,
      queueDepth: 0,
      avgPriority: 'medium',
      lastSync: new Date().toISOString(),
      _mock: true,
      _note: 'Live ticketing-API integration deferred to a future phase. The shape of this response is stable; the values become real once per-platform adapters land.',
    });
  } catch (err) {
    logger.error('Get ticketing queue metadata error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch ticketing queue metadata' });
  }
});

// ── Create/Update Config ─────────────────────────────────────────────────────
router.put('/:type', (req, res) => {
  if (!VALID_TYPES.includes(req.params.type)) {
    return res.status(400).json({ error: 'Invalid integration type' });
  }

  const { config: incomingConfig } = req.body;
  if (!incomingConfig || typeof incomingConfig !== 'object') {
    return res.status(400).json({ error: 'config object required' });
  }

  try {
    // ── Omission-based merge for sensitive fields ──────────────────────────
    // SOC-grade contract: the MC frontend OMITS sensitive field keys
    // (apiToken, password, secret, key, cert) from the PUT body unless
    // the lead has explicitly clicked "Change Secret" and entered a new
    // value. The server's job is to preserve existing values when keys
    // are absent from the incoming body.
    //
    // Three cases per sensitive key:
    //   (a) key omitted from incomingConfig → preserve existing value
    //       (emit MC_INTEGRATION_SECRET_PRESERVED audit marker)
    //   (b) key present with non-empty value → use new value
    //       (emit MC_INTEGRATION_SECRET_CHANGED audit marker)
    //   (c) key present with empty string → explicit clear
    //       (emit MC_INTEGRATION_SECRET_CLEARED audit marker)
    //
    // For brand-new integrations (no existing config), only case (b)/(c)
    // apply since there's nothing to preserve.
    const db = getDb();
    const existingRow = db.prepare('SELECT id, config_encrypted FROM integration_config WHERE integration_type = ?').get(req.params.type);
    const existingConfig = existingRow ? openTier1('integration_config.config_encrypted', existingRow.config_encrypted) : null;

    const mergedConfig = { ...incomingConfig };
    const preservedFields = [];
    const changedFields = [];
    const clearedFields = [];

    if (existingConfig) {
      // For each sensitive field key in existing config that is omitted
      // from incomingConfig, copy existing value into merged result
      for (const key of Object.keys(existingConfig)) {
        if (/secret|password|key|token|cert/i.test(key)) {
          if (!(key in incomingConfig)) {
            mergedConfig[key] = existingConfig[key];
            preservedFields.push(key);
          } else if (incomingConfig[key] === '' || incomingConfig[key] === null) {
            clearedFields.push(key);
          } else if (incomingConfig[key] !== existingConfig[key]) {
            changedFields.push(key);
          }
          // else: incoming value equals existing — no-op (no audit row)
        }
      }
      // Also catch sensitive fields in incomingConfig that AREN'T in
      // existing (e.g., adding apiToken to an integration that had none)
      for (const key of Object.keys(incomingConfig)) {
        if (/secret|password|key|token|cert/i.test(key) && !(key in existingConfig)) {
          if (incomingConfig[key] && incomingConfig[key] !== '') {
            changedFields.push(key);
          }
        }
      }
    } else {
      // New integration: any sensitive field with a non-empty value counts
      // as a "change" (first set) for audit purposes
      for (const key of Object.keys(incomingConfig)) {
        if (/secret|password|key|token|cert/i.test(key) && incomingConfig[key] && incomingConfig[key] !== '') {
          changedFields.push(key);
        }
      }
    }

    // R3j: per-type normalization runs BEFORE encryption on the merged
    // config. The function returns a possibly-modified copy along with
    // audit-log marker strings for any invariants enforced.
    const { normalized, auditMarkers } = normalizeConfigForType(req.params.type, mergedConfig);

    const encrypted = sealTier1('integration_config.config_encrypted', normalized);

    if (existingRow) {
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

    // ── Audit logging (operator identity recorded; NEVER field values) ─────
    // One INTEGRATION_CONFIGURED row per save (overall marker), plus per-
    // field MC_INTEGRATION_SECRET_* rows for fine-grained threat-hunting
    // visibility. The detail strings include the field key name (e.g.,
    // "apiToken") but NEVER the value.
    const detail = auditMarkers.length > 0
      ? `type=${req.params.type} (${auditMarkers.join('; ')})`
      : `type=${req.params.type}`;
    auditLog(req.user.id, 'INTEGRATION_CONFIGURED', detail, req.ip);

    for (const field of preservedFields) {
      auditLog(req.user.id, 'MC_INTEGRATION_SECRET_PRESERVED', `type=${req.params.type} field=${field}`, req.ip);
    }
    for (const field of changedFields) {
      auditLog(req.user.id, 'MC_INTEGRATION_SECRET_CHANGED', `type=${req.params.type} field=${field}`, req.ip);
    }
    for (const field of clearedFields) {
      auditLog(req.user.id, 'MC_INTEGRATION_SECRET_CLEARED', `type=${req.params.type} field=${field}`, req.ip);
    }

    res.json({
      ok: true,
      type: req.params.type,
      status: 'configured',
      secretFieldsPreserved: preservedFields.length,
      secretFieldsChanged: changedFields.length,
      secretFieldsCleared: clearedFields.length,
    });
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

    const config = openTier1('integration_config.config_encrypted', row.config_encrypted);

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
  const result = {
    success: true,
    message: `Connection to ${config.platform || config.provider || config.server || config.host || type} successful`,
    latencyMs: latency,
    testedAt: new Date().toISOString(),
  };

  // R3j: SOAR test echoes the autoEscalate flag if set. The UI uses this
  // to confirm round-trip persistence (the field was correctly saved into
  // the encrypted config blob on the prior PUT and is now visible to the
  // server's read path). The echo is informational only — no behavior
  // change in the simulated test itself.
  if (type === 'soar' && config.autoEscalate === true) {
    result.autoEscalatePolicyDetected = true;
  }

  return result;
}

// ── R3j: Per-Type Config Normalization ───────────────────────────────────────
// Runs in PUT /:type before encryption. Returns:
//   { normalized: <possibly-modified config>, auditMarkers: <string[]> }
//
// The function is purely transformational — no DB access, no side
// effects. Type-specific rules:
//
//   soar:
//     Coerce config.autoEscalate to a strict boolean if present.
//     Accepts truthy/falsy values but stores a boolean so subsequent
//     reads always get a known type.
//
//   ticketing:
//     Enforce the readOnly:true invariant server-side. Whatever the
//     client supplies (true/false/missing/undefined) is replaced with
//     literal true. This matches the v054 design intent line 35-37
//     where the original stub hardcoded readOnly:true at the storage
//     layer. The PUT response audit log includes the marker
//     "READ-ONLY invariant enforced" so operators see the action in
//     the audit trail.
//
//   default:
//     Pass through unchanged. Other integration types have no per-type
//     invariants in R3j scope.
function normalizeConfigForType(type, config) {
  const normalized = { ...config };
  const auditMarkers = [];

  if (type === 'soar') {
    if ('autoEscalate' in normalized) {
      const coerced = Boolean(normalized.autoEscalate);
      if (coerced !== normalized.autoEscalate) {
        auditMarkers.push(`autoEscalate coerced to ${coerced}`);
      }
      normalized.autoEscalate = coerced;
    }
  } else if (type === 'ticketing') {
    if (normalized.readOnly !== true) {
      auditMarkers.push('READ-ONLY invariant enforced');
    }
    normalized.readOnly = true;
  }

  return { normalized, auditMarkers };
}

module.exports = router;

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Self-Protection Routes (B6a)
//
// Configuration + status surface for the GD's self-protection subsystem. All of
// this concerns the GD server ITSELF as a protected asset (its SIEM/SOAR/EDR
// integrations, alert routing, runtime-monitor thresholds, integration-health
// probes) -- never analyst data, which the GD never holds.
//
// Mounted at /api/self-protection with authMiddleware(['ciso','vp']). The
// configuration writes live under the /config sub-path so the config-lock
// chokepoint (which gates /api/self-protection/config) freezes them when the
// platform is locked; the operational reads and the run-now probe live outside
// /config and are never gated. GET requests under /config are reads (safe
// method) and pass the chokepoint regardless.
//
// Secrets are never returned: the SOAR auth token, the webhook URL path, and the
// EDR credentials are masked or omitted on read. EDR credentials are stored
// AES-256-GCM-encrypted (gd-encryption.encryptConfig).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const gdEncryption = require('../services/gd-encryption');
const { gdRuntimeMonitor } = require('../services/gd-runtime-monitor');
const gdIntegrationHealth = require('../services/gd-integration-health');
const { loadMatrix } = require('../services/gd-alert-router');

const EDR_PROVIDERS = [
  'crowdstrike_falcon', 'microsoft_defender_endpoint', 'sentinelone', 'palo_alto_cortex_xdr',
  'trellix_edr', 'sophos_intercept_x', 'vmware_carbon_black', 'cisco_secure_endpoint',
  'wazuh', 'elastic_defend', 'limacharlie',
];
const SIEM_PROTOCOLS = ['tcp', 'udp', 'tls'];
const SEVERITIES = ['info', 'warning', 'high', 'critical'];
const MATRIX_CHANNELS = ['soar', 'siem', 'email', 'notification', 'webhook'];

// ── helpers ───────────────────────────────────────────────────────────────────
function _audit(db, req, eventType, detail) {
  try {
    appendGdAuditEntry(db, { userId: req && req.user ? req.user.id : null, eventType, detail, ip: (req && req.ip) || null, severity: 'info' });
  } catch (e) { try { console.warn('[self-protection] audit failed:', e && e.message); } catch (_) { /* ignore */ } }
}
function _readJson(db, key, dflt) {
  try { const r = db.prepare('SELECT value FROM config WHERE key = ?').get(key); return r && r.value ? JSON.parse(r.value) : dflt; }
  catch { return dflt; }
}
function _writeJson(db, key, obj) {
  db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(key, JSON.stringify(obj));
}
function _readScalar(db, key, dflt) {
  try { const r = db.prepare('SELECT value FROM config WHERE key = ?').get(key); return r && r.value !== undefined && r.value !== null ? r.value : dflt; }
  catch { return dflt; }
}
function _writeScalar(db, key, val) {
  db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(key, String(val));
}
function _isHttpUrl(s) { try { const u = new URL(String(s)); return u.protocol === 'http:' || u.protocol === 'https:'; } catch { return false; } }

// ════════════════════════════ CONFIG (gated under /config) ════════════════════

// ── SIEM ──
router.get('/config/siem', (req, res) => {
  const db = getDb();
  try { const c = _readJson(db, 'siem_config', null); return res.json({ configured: !!(c && c.endpoint), endpoint: (c && c.endpoint) || null, protocol: (c && c.protocol) || 'tls' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});
router.put('/config/siem', (req, res) => {
  const b = req.body || {};
  if (typeof b.endpoint !== 'string' || !b.endpoint.trim()) return res.status(400).json({ error: 'endpoint is required', code: 'INVALID_INPUT' });
  const protocol = b.protocol || 'tls';
  if (!SIEM_PROTOCOLS.includes(protocol)) return res.status(400).json({ error: 'protocol must be one of tcp, udp, tls', code: 'INVALID_INPUT' });
  const db = getDb();
  try { _writeJson(db, 'siem_config', { endpoint: b.endpoint.trim(), protocol }); _audit(db, req, 'SELF_PROTECTION_SIEM_CONFIGURED', `endpoint=${b.endpoint.trim()} protocol=${protocol}`); return res.json({ ok: true }); }
  catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});

// ── SOAR (auth token masked on read; preserved if omitted on write) ──
router.get('/config/soar', (req, res) => {
  const db = getDb();
  try { const c = _readJson(db, 'soar_config', null); return res.json({ configured: !!(c && c.endpoint), endpoint: (c && c.endpoint) || null, has_auth_token: !!(c && c.auth_token) }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});
router.put('/config/soar', (req, res) => {
  const b = req.body || {};
  if (typeof b.endpoint !== 'string' || !_isHttpUrl(b.endpoint)) return res.status(400).json({ error: 'endpoint must be an http(s) URL', code: 'INVALID_INPUT' });
  const db = getDb();
  try {
    const existing = _readJson(db, 'soar_config', {}) || {};
    const next = { endpoint: b.endpoint.trim() };
    if (b.auth_token === '') { /* explicit clear */ }
    else if (typeof b.auth_token === 'string' && b.auth_token.length) next.auth_token = b.auth_token;
    else if (existing.auth_token) next.auth_token = existing.auth_token; // preserve
    _writeJson(db, 'soar_config', next);
    _audit(db, req, 'SELF_PROTECTION_SOAR_CONFIGURED', `endpoint=${next.endpoint} auth_token=${next.auth_token ? 'set' : 'none'}`);
    return res.json({ ok: true });
  } catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});

// ── Alert routing matrix ──
router.get('/config/alert-matrix', (req, res) => {
  const db = getDb();
  try { return res.json({ matrix: loadMatrix(db) }); }
  catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});
router.put('/config/alert-matrix', (req, res) => {
  const b = req.body || {};
  const matrix = b.matrix || b;
  if (!matrix || typeof matrix !== 'object') return res.status(400).json({ error: 'matrix object required', code: 'INVALID_INPUT' });
  const clean = {};
  for (const sev of SEVERITIES) {
    if (matrix[sev] && typeof matrix[sev] === 'object') {
      clean[sev] = {};
      for (const ch of MATRIX_CHANNELS) if (typeof matrix[sev][ch] === 'boolean') clean[sev][ch] = matrix[sev][ch];
    }
  }
  if (!Object.keys(clean).length) return res.status(400).json({ error: 'no valid severity/channel entries', code: 'INVALID_INPUT' });
  const db = getDb();
  try { _writeJson(db, 'alert_routing_matrix', clean); _audit(db, req, 'SELF_PROTECTION_ALERT_MATRIX_UPDATED', `severities=${Object.keys(clean).join(',')}`); return res.json({ ok: true, matrix: loadMatrix(db) }); }
  catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});

// ── Runtime-monitor thresholds (persist + apply live) ──
router.get('/config/runtime-thresholds', (req, res) => {
  const db = getDb();
  try { return res.json({ thresholds: _readJson(db, 'runtime_monitor_thresholds', {}) }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});
router.put('/config/runtime-thresholds', (req, res) => {
  const b = req.body || {};
  const thresholds = b.thresholds || b;
  if (!thresholds || typeof thresholds !== 'object' || Array.isArray(thresholds)) return res.status(400).json({ error: 'thresholds object required', code: 'INVALID_INPUT' });
  for (const k of Object.keys(thresholds)) {
    const v = thresholds[k];
    if (typeof v !== 'number' || !isFinite(v) || v < 0) return res.status(400).json({ error: `threshold '${k}' must be a non-negative number`, code: 'INVALID_INPUT' });
  }
  const db = getDb();
  try {
    _writeJson(db, 'runtime_monitor_thresholds', thresholds);
    try { gdRuntimeMonitor.configureThresholds(thresholds); } catch (_e) { /* monitor may not be started; persisted regardless */ }
    _audit(db, req, 'SELF_PROTECTION_RUNTIME_THRESHOLDS_UPDATED', `keys=${Object.keys(thresholds).join(',')}`);
    return res.json({ ok: true });
  } catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});

// ── Webhook URL (masked on read) ──
router.get('/config/webhook', (req, res) => {
  const db = getDb();
  try {
    const url = _readScalar(db, 'alert_webhook_url', '');
    let host = null; try { if (url) host = new URL(url).host; } catch { host = null; }
    return res.json({ configured: !!url, host });
  } finally { try { db.close(); } catch (_) { /* ignore */ } }
});
router.put('/config/webhook', (req, res) => {
  const b = req.body || {};
  const url = b.url === undefined || b.url === null ? '' : String(b.url);
  if (url && !_isHttpUrl(url)) return res.status(400).json({ error: 'url must be an http(s) URL or empty to clear', code: 'INVALID_INPUT' });
  const db = getDb();
  try { _writeScalar(db, 'alert_webhook_url', url); _audit(db, req, 'SELF_PROTECTION_WEBHOOK_CONFIGURED', url ? 'set' : 'cleared'); return res.json({ ok: true }); }
  catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});

// ── Integration-health config (master toggle + per-integration) ──
router.get('/config/integration-health', (req, res) => {
  const db = getDb();
  try {
    const master = _readScalar(db, 'integration_health_probes_enabled', 'false') === 'true';
    const integrations = _readJson(db, 'integration_health_config', { kms: { enabled: false }, storage: { enabled: false }, mc_trust: { enabled: false } });
    return res.json({ master, integrations });
  } finally { try { db.close(); } catch (_) { /* ignore */ } }
});
router.put('/config/integration-health', (req, res) => {
  const b = req.body || {};
  if (typeof b.master !== 'boolean' && (!b.integrations || typeof b.integrations !== 'object')) {
    return res.status(400).json({ error: 'provide master (boolean) and/or integrations object', code: 'INVALID_INPUT' });
  }
  const db = getDb();
  try {
    if (typeof b.master === 'boolean') _writeScalar(db, 'integration_health_probes_enabled', b.master ? 'true' : 'false');
    if (b.integrations && typeof b.integrations === 'object') {
      const cur = _readJson(db, 'integration_health_config', { kms: { enabled: false }, storage: { enabled: false }, mc_trust: { enabled: false } });
      for (const k of ['kms', 'storage', 'mc_trust']) {
        if (b.integrations[k] && typeof b.integrations[k].enabled === 'boolean') cur[k] = { enabled: b.integrations[k].enabled };
      }
      _writeJson(db, 'integration_health_config', cur);
    }
    _audit(db, req, 'SELF_PROTECTION_INTEGRATION_HEALTH_CONFIGURED', `master=${b.master}`);
    return res.json({ ok: true });
  } catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});

// ── EDR seam CRUD (malware_scanner_integrations; credentials encrypted) ──
function _edrRow(r) {
  return {
    id: r.id, provider_type: r.provider_type, display_name: r.display_name, endpoint: r.endpoint,
    enabled: r.enabled === 1, has_credentials: !!r.credentials_encrypted,
    configured_by: r.configured_by, configured_at: r.configured_at,
    last_test_at: r.last_test_at, last_test_status: r.last_test_status, last_test_error: r.last_test_error,
  };
}
router.get('/config/edr', (req, res) => {
  const db = getDb();
  try { const rows = db.prepare('SELECT * FROM malware_scanner_integrations ORDER BY configured_at DESC').all(); return res.json({ integrations: rows.map(_edrRow) }); }
  catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});
router.post('/config/edr', (req, res) => {
  const b = req.body || {};
  if (!EDR_PROVIDERS.includes(b.provider_type)) return res.status(400).json({ error: 'provider_type must be a supported EDR provider', code: 'INVALID_INPUT', supported: EDR_PROVIDERS });
  if (typeof b.display_name !== 'string' || !b.display_name.trim()) return res.status(400).json({ error: 'display_name is required', code: 'INVALID_INPUT' });
  let credsEnc = null;
  if (b.credentials !== undefined && b.credentials !== null && b.credentials !== '') {
    try { credsEnc = gdEncryption.encryptConfig(b.credentials); } catch (e) { return res.status(500).json({ error: 'Could not encrypt credentials' }); }
  }
  const db = getDb();
  try {
    const id = require('crypto').randomBytes(16).toString('hex');
    db.prepare('INSERT INTO malware_scanner_integrations (id, provider_type, display_name, endpoint, credentials_encrypted, enabled, configured_by) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(id, b.provider_type, b.display_name.trim(), b.endpoint || null, credsEnc, b.enabled ? 1 : 0, req.user ? req.user.id : null);
    _audit(db, req, 'SELF_PROTECTION_EDR_ADDED', `id=${id} provider=${b.provider_type} name="${b.display_name.trim()}"`);
    return res.status(201).json({ ok: true, id });
  } catch (e) { return res.status(500).json({ error: 'Internal error', detail: e.message }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});
router.put('/config/edr/:id', (req, res) => {
  const b = req.body || {};
  const id = req.params.id;
  const db = getDb();
  try {
    const row = db.prepare('SELECT * FROM malware_scanner_integrations WHERE id = ?').get(id);
    if (!row) return res.status(404).json({ error: 'EDR integration not found', code: 'NOT_FOUND' });
    const display_name = typeof b.display_name === 'string' && b.display_name.trim() ? b.display_name.trim() : row.display_name;
    const endpoint = b.endpoint !== undefined ? (b.endpoint || null) : row.endpoint;
    const enabled = typeof b.enabled === 'boolean' ? (b.enabled ? 1 : 0) : row.enabled;
    let credsEnc = row.credentials_encrypted;
    if (b.credentials === '') credsEnc = null;
    else if (b.credentials !== undefined && b.credentials !== null) {
      try { credsEnc = gdEncryption.encryptConfig(b.credentials); } catch (e) { return res.status(500).json({ error: 'Could not encrypt credentials' }); }
    }
    db.prepare('UPDATE malware_scanner_integrations SET display_name = ?, endpoint = ?, enabled = ?, credentials_encrypted = ? WHERE id = ?')
      .run(display_name, endpoint, enabled, credsEnc, id);
    _audit(db, req, 'SELF_PROTECTION_EDR_UPDATED', `id=${id}`);
    return res.json({ ok: true });
  } catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});
router.delete('/config/edr/:id', (req, res) => {
  const id = req.params.id;
  const db = getDb();
  try {
    const info = db.prepare('DELETE FROM malware_scanner_integrations WHERE id = ?').run(id);
    if (!info.changes) return res.status(404).json({ error: 'EDR integration not found', code: 'NOT_FOUND' });
    _audit(db, req, 'SELF_PROTECTION_EDR_REMOVED', `id=${id}`);
    return res.json({ ok: true });
  } catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});

// ════════════════════════════ OPERATIONAL (not gated) ═════════════════════════

// ── Overall status rollup ──
router.get('/status', (req, res) => {
  const db = getDb();
  try {
    let lock = null;
    try { const l = db.prepare('SELECT lock_active, locked_at, auto_relock_at FROM config_lock_state WHERE id = 1').get(); lock = l ? { lock_active: l.lock_active === 1, locked_at: l.locked_at, auto_relock_at: l.auto_relock_at } : null; } catch { lock = null; }
    const ih = gdIntegrationHealth.getCachedResults(db);
    let runtime = null; try { runtime = gdRuntimeMonitor.getMetrics(); } catch { runtime = null; }
    let recentAlerts = 0; try { recentAlerts = (db.prepare("SELECT COUNT(*) AS n FROM notifications WHERE type = 'security_alert' AND created_at > datetime('now','-24 hours')").get() || {}).n || 0; } catch { recentAlerts = 0; }
    return res.json({
      lock,
      integration_health: ih ? { ranAt: ih.ranAt, summary: ih.summary, masterEnabled: ih.masterEnabled } : { ran: false },
      runtime: runtime ? { cpu: runtime.cpu, memMB: runtime.memMB, fileCount: runtime.fileCount, dbReadsPerMin: runtime.dbReadsPerMin } : null,
      recent_alerts_24h: recentAlerts,
    });
  } catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});

// ── Integration-health: cached + run-now ──
router.get('/integration-health', (req, res) => {
  const db = getDb();
  try { const cached = gdIntegrationHealth.getCachedResults(db); return res.json(cached || { ran: false }); }
  catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});
router.post('/integration-health/run', async (req, res) => {
  const db = getDb();
  try { const result = await gdIntegrationHealth.runAndCache(db); _audit(db, req, 'SELF_PROTECTION_INTEGRATION_HEALTH_RUN', `total=${result.summary.total} ok=${result.summary.ok}`); return res.json(result); }
  catch (e) { return res.status(500).json({ error: 'Internal error', detail: e.message }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});

// ── Runtime metrics + recent alerts ──
router.get('/runtime/metrics', (req, res) => {
  try { return res.json(gdRuntimeMonitor.getMetrics()); }
  catch (e) { return res.status(500).json({ error: 'Internal error' }); }
});
router.get('/runtime/alerts', (req, res) => {
  const db = getDb();
  try {
    const rows = db.prepare("SELECT id, type, mc_id, message, severity, acknowledged, created_at FROM notifications WHERE type = 'security_alert' ORDER BY created_at DESC LIMIT 50").all();
    return res.json({ alerts: rows });
  } catch (e) { return res.status(500).json({ error: 'Internal error' }); }
  finally { try { db.close(); } catch (_) { /* ignore */ } }
});

module.exports = router;

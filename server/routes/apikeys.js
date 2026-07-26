// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — API Keys Routes
// GET    /api/apikeys       — list all keys (prefix + metadata only)
// POST   /api/apikeys       — generate a new key
// DELETE /api/apikeys/:id   — revoke a key
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const ca = require('../services/ca');
const { mfaStepUp } = require('../middleware/mfa-stepup');

const VALID_SCOPES = [
  'health:read', 'siem:read', 'siem:write',
  'reports:generate', 'routing:read', 'routing:write', 'routing:events',
  'audit:read', 'backup:trigger', 'assessments:read',
  'integrations:read', 'integrations:write', 'ticketing:events',
  'cicd:webhook',
];

// ── List Keys (never returns raw key) ────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const keys = db.prepare(`
      SELECT id, name, key_prefix, scopes, expires_at, revoked, 
             created_at, last_used_at,
             (SELECT name FROM users WHERE id = api_keys.created_by) AS created_by_name
      FROM api_keys ORDER BY created_at DESC
    `).all();
    db.close();
    res.json({ keys });
  } catch (err) {
    logger.error('List API keys error', { error: err.message });
    res.status(500).json({ error: 'Failed to list API keys' });
  }
});

// ── Generate Key ─────────────────────────────────────────────────────────────
router.post('/', mfaStepUp(), (req, res) => {
  const { name, scopes, expiresIn } = req.body;
  if (!name || typeof name !== 'string' || name.length > 128) {
    return res.status(400).json({ error: 'name required (max 128 chars)' });
  }
  if (!scopes || !Array.isArray(scopes) || scopes.length === 0) {
    return res.status(400).json({ error: 'At least one scope required' });
  }
  const invalid = scopes.filter(s => !VALID_SCOPES.includes(s));
  if (invalid.length > 0) {
    return res.status(400).json({ error: `Invalid scopes: ${invalid.join(', ')}`, validScopes: VALID_SCOPES });
  }

  try {
    const rawKey = `scr-${crypto.randomBytes(32).toString('hex')}`;
    const prefix = rawKey.slice(0, 8);
    const keyHash = bcrypt.hashSync(rawKey, 12);
    const id = crypto.randomBytes(16).toString('hex');

    let expiresAt = null;
    if (expiresIn) {
      const ms = { '30d': 30, '90d': 90, '180d': 180, '365d': 365 }[expiresIn];
      if (ms) expiresAt = new Date(Date.now() + ms * 86400000).toISOString();
    }

    const db = getDb();

    // O3 Half 2: a key is sender-constrained, so minting one mints the
    // certificate that constrains it. Both happen in ONE transaction: a
    // certificate in issued_certs with no api_keys row bound to it is an
    // orphaned credential, and an api_keys row with no certificate cannot
    // authenticate at all (cert_fingerprint is NOT NULL). Neither half is
    // allowed to land without the other.
    const cert = db.transaction(() => {
      const c = ca.issueMachineConsumerCert(db, { displayName: name.slice(0, 128), ou: ca.API_KEY_CONSUMER_OU });
      db.prepare(
        'INSERT INTO api_keys (id, name, key_hash, key_prefix, scopes, expires_at, created_by, cert_fingerprint, cert_serial) '
        + 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
      ).run(id, name.slice(0, 128), keyHash, prefix, scopes.join(','), expiresAt, req.user.id, c.fingerprint, c.serial);
      return c;
    })();
    db.close();

    auditLog(req.user.id, 'APIKEY_CREATED',
      `name=${name} scopes=${scopes.join(',')} cert_fp=${cert.fingerprint} cert_serial=${cert.serial}`, req.ip);

    res.status(201).json({
      id, name, rawKey, prefix, scopes, expiresAt,
      certFingerprint: cert.fingerprint,
      certSerial: cert.serial,
      // Returned exactly once and never retrievable again. The key alone
      // authenticates nothing: the client must present this certificate on the
      // TLS connection that carries it.
      certPem: cert.certPem,
      keyPem: cert.keyPem,
      caCertPem: cert.caCertPem,
      warning: 'Store the key, the client certificate and its private key securely. None will be shown again. The key will not authenticate without its certificate.',
    });
  } catch (err) {
    logger.error('Create API key error', { error: err.message });
    res.status(500).json({ error: 'Failed to create API key' });
  }
});

// ── Revoke Key ───────────────────────────────────────────────────────────────
router.delete('/:id', mfaStepUp(), (req, res) => {
  try {
    const db = getDb();
    const key = db.prepare('SELECT id, name FROM api_keys WHERE id = ?').get(req.params.id);
    if (!key) { db.close(); return res.status(404).json({ error: 'Key not found' }); }

    // O3 Half 2: revoke the bound certificate as well. Flagging the row alone
    // leaves a certificate this deployment's CA still vouches for -- a
    // credential the operator believes destroyed and which is not.
    const bound = db.prepare('SELECT cert_serial FROM api_keys WHERE id = ?').get(req.params.id);
    db.transaction(() => {
      db.prepare('UPDATE api_keys SET revoked = 1 WHERE id = ?').run(req.params.id);
      if (bound && bound.cert_serial) {
        ca.revokeCert(db, { serial: bound.cert_serial, reason: 'api_key_revoked' });
      }
    })();
    db.close();

    auditLog(req.user.id, 'APIKEY_REVOKED', `name=${key.name}`, req.ip);
    res.json({ ok: true, revoked: key.name });
  } catch (err) {
    logger.error('Revoke API key error', { error: err.message });
    res.status(500).json({ error: 'Failed to revoke key' });
  }
});

module.exports = router;

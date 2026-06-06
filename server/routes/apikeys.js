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
router.post('/', (req, res) => {
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
    db.prepare(`
      INSERT INTO api_keys (id, name, key_hash, key_prefix, scopes, expires_at, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, name.slice(0, 128), keyHash, prefix, scopes.join(','), expiresAt, req.user.id);
    db.close();

    auditLog(req.user.id, 'APIKEY_CREATED', `name=${name} scopes=${scopes.join(',')}`, req.ip);

    res.status(201).json({
      id, name, rawKey, prefix, scopes, expiresAt,
      warning: 'Store this key securely. It will not be shown again.',
    });
  } catch (err) {
    logger.error('Create API key error', { error: err.message });
    res.status(500).json({ error: 'Failed to create API key' });
  }
});

// ── Revoke Key ───────────────────────────────────────────────────────────────
router.delete('/:id', (req, res) => {
  try {
    const db = getDb();
    const key = db.prepare('SELECT id, name FROM api_keys WHERE id = ?').get(req.params.id);
    if (!key) { db.close(); return res.status(404).json({ error: 'Key not found' }); }

    db.prepare('UPDATE api_keys SET revoked = 1 WHERE id = ?').run(req.params.id);
    db.close();

    auditLog(req.user.id, 'APIKEY_REVOKED', `name=${key.name}`, req.ip);
    res.json({ ok: true, revoked: key.name });
  } catch (err) {
    logger.error('Revoke API key error', { error: err.message });
    res.status(500).json({ error: 'Failed to revoke key' });
  }
});

module.exports = router;

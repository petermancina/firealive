// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Admin Management Router (B5m)
//
// Admin-only management of consumer authorizations and the access log. Mounted
// behind the admin JWT and the config-lock chokepoint in server/index.js.
//
//   GET    /authorizations            list (no secrets)
//   POST   /authorizations            create -> returns cert + key + token ONCE
//   GET    /authorizations/:id        one (no secrets)
//   PUT    /authorizations/:id        update mutable policy fields
//   DELETE /authorizations/:id        revoke (disables row + revokes the cert)
//   GET    /access-log                recent access entries (bounded)
//   GET    /access-log/verify         recompute + verify the hash chain
//
// The registry service does the cert/token work; these handlers validate input,
// audit-log the mutation, and shape the response. The cert, private key, and
// token are returned exactly once at creation and are never retrievable again.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const registry = require('../services/threat-hunting-registry');
const { verifyAccessLogChain } = require('../services/threat-hunting-access-log');

function isInputError(err) {
  return err && typeof err.message === 'string'
    && /allowed_cidrs|consumer_type|display_name|default_format/.test(err.message);
}

// ── List authorizations ──────────────────────────────────────────────────────
router.get('/authorizations', function (req, res) {
  const db = getDb();
  try {
    res.json({
      authorizations: registry.listAuthorizations(db),
      validConsumerTypes: registry.CONSUMER_TYPES,
      validFormats: registry.FORMATS,
    });
  } catch (err) {
    logger.error('threat-hunting list authorizations error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to list authorizations' });
  } finally { db.close(); }
});

// ── Create authorization ─────────────────────────────────────────────────────
router.post('/authorizations', function (req, res) {
  const body = req.body || {};
  if (!registry.CONSUMER_TYPES.includes(body.consumer_type)) {
    return res.status(400).json({ error: 'Invalid consumer_type', validConsumerTypes: registry.CONSUMER_TYPES });
  }
  if (typeof body.display_name !== 'string' || !body.display_name.trim() || body.display_name.length > 128) {
    return res.status(400).json({ error: 'display_name required (1-128 chars)' });
  }
  if (!Array.isArray(body.allowed_cidrs) || body.allowed_cidrs.length === 0) {
    return res.status(400).json({ error: 'allowed_cidrs must be a non-empty array of IP / CIDR strings' });
  }
  if (body.default_format != null && body.default_format !== '' && !registry.FORMATS.includes(body.default_format)) {
    return res.status(400).json({ error: 'Invalid default_format', validFormats: registry.FORMATS });
  }
  if (body.notes != null && (typeof body.notes !== 'string' || body.notes.length > 1000)) {
    return res.status(400).json({ error: 'notes must be a string up to 1000 chars' });
  }

  const db = getDb();
  try {
    const created = registry.createAuthorization(db, {
      consumerType: body.consumer_type,
      displayName: body.display_name,
      allowedCidrs: body.allowed_cidrs,
      defaultFormat: body.default_format,
      createdBy: req.user.id,
      notes: body.notes,
    });
    auditLog(
      req.user.id, 'THREAT_HUNTING_AUTH_CREATED',
      'consumer=' + created.authorization.consumer_type
        + ' name="' + created.authorization.display_name + '"'
        + ' cidrs=' + created.authorization.allowed_cidrs.length
        + ' fp=' + created.authorization.cert_fingerprint,
      req.ip
    );
    // cert + key + token returned ONCE -- never retrievable again
    res.status(201).json({
      authorization: created.authorization,
      token: created.token,
      cert_pem: created.certPem,
      key_pem: created.keyPem,
      ca_cert_pem: created.caCertPem,
    });
  } catch (err) {
    if (isInputError(err)) return res.status(400).json({ error: err.message });
    logger.error('threat-hunting create authorization error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to create authorization' });
  } finally { db.close(); }
});

// ── Get one ──────────────────────────────────────────────────────────────────
router.get('/authorizations/:id', function (req, res) {
  const db = getDb();
  try {
    const a = registry.getAuthorization(db, req.params.id);
    if (!a) return res.status(404).json({ error: 'Authorization not found' });
    res.json({ authorization: a });
  } catch (err) {
    logger.error('threat-hunting get authorization error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to get authorization' });
  } finally { db.close(); }
});

// ── Update authorization ─────────────────────────────────────────────────────
router.put('/authorizations/:id', function (req, res) {
  const body = req.body || {};
  if (body.display_name !== undefined
      && (typeof body.display_name !== 'string' || !body.display_name.trim() || body.display_name.length > 128)) {
    return res.status(400).json({ error: 'display_name must be 1-128 chars' });
  }
  if (body.allowed_cidrs !== undefined
      && (!Array.isArray(body.allowed_cidrs) || body.allowed_cidrs.length === 0)) {
    return res.status(400).json({ error: 'allowed_cidrs must be a non-empty array of IP / CIDR strings' });
  }
  if (body.default_format !== undefined && !registry.FORMATS.includes(body.default_format)) {
    return res.status(400).json({ error: 'Invalid default_format', validFormats: registry.FORMATS });
  }
  if (body.notes !== undefined && body.notes != null
      && (typeof body.notes !== 'string' || body.notes.length > 1000)) {
    return res.status(400).json({ error: 'notes must be a string up to 1000 chars' });
  }

  const db = getDb();
  try {
    const updated = registry.updateAuthorization(db, req.params.id, {
      displayName: body.display_name,
      allowedCidrs: body.allowed_cidrs,
      defaultFormat: body.default_format,
      enabled: body.enabled,
      notes: body.notes,
    });
    if (!updated) return res.status(404).json({ error: 'Authorization not found' });
    auditLog(req.user.id, 'THREAT_HUNTING_AUTH_UPDATED', 'id=' + req.params.id + ' enabled=' + (updated.enabled ? 1 : 0), req.ip);
    res.json({ authorization: updated });
  } catch (err) {
    if (isInputError(err)) return res.status(400).json({ error: err.message });
    logger.error('threat-hunting update authorization error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to update authorization' });
  } finally { db.close(); }
});

// ── Revoke authorization ─────────────────────────────────────────────────────
router.delete('/authorizations/:id', function (req, res) {
  const db = getDb();
  try {
    const result = registry.revokeAuthorization(db, req.params.id);
    if (!result.revoked) return res.status(404).json({ error: 'Authorization not found' });
    auditLog(req.user.id, 'THREAT_HUNTING_AUTH_REVOKED', 'id=' + req.params.id + ' certRevoked=' + (result.certRevoked ? 1 : 0), req.ip);
    res.json({ revoked: true, cert_revoked: result.certRevoked === true });
  } catch (err) {
    logger.error('threat-hunting revoke authorization error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to revoke authorization' });
  } finally { db.close(); }
});

// ── Access log: verify the chain ─────────────────────────────────────────────
router.get('/access-log/verify', function (req, res) {
  const db = getDb();
  try {
    const result = verifyAccessLogChain(db);
    auditLog(
      req.user.id, 'THREAT_HUNTING_ACCESS_LOG_VERIFIED',
      'intact=' + result.intact + ' count=' + result.count + (result.brokenAt ? (' brokenAt=' + result.brokenAt) : ''),
      req.ip
    );
    res.json(result);
  } catch (err) {
    logger.error('threat-hunting verify access-log error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to verify access log' });
  } finally { db.close(); }
});

// ── Access log: recent entries ───────────────────────────────────────────────
router.get('/access-log', function (req, res) {
  const db = getDb();
  try {
    const n = parseInt(req.query.limit, 10);
    const limit = Math.min(Math.max(Number.isInteger(n) ? n : 100, 1), 1000);
    const rows = db.prepare(
      'SELECT id, prev_hash, this_hash, authorization_id, consumer_type, source_ip, cert_fingerprint, '
        + 'endpoint, format, query_summary, outcome, result_count, accessed_at '
        + 'FROM threat_hunting_access_log ORDER BY id DESC LIMIT ?'
    ).all(limit);
    res.json({ entries: rows, count: rows.length });
  } catch (err) {
    logger.error('threat-hunting access-log error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to read access log' });
  } finally { db.close(); }
});

module.exports = router;

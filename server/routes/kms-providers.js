// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — KMS Providers Admin Routes
//
// HTTP API in front of services/kms-providers.js. Admins use these
// endpoints to view, create, configure, probe, and switch the active
// kms_providers row(s) used for backup DEK wrapping.
//
// Endpoints:
//   GET    /api/kms-providers                  list all
//   GET    /api/kms-providers/default          get current default
//   GET    /api/kms-providers/:id              get one
//   POST   /api/kms-providers                  create new (validates + probes)
//   POST   /api/kms-providers/probe-config     probe a prospective config (no DB write)
//   PATCH  /api/kms-providers/:id              update mutable fields
//   POST   /api/kms-providers/:id/enable       enable
//   POST   /api/kms-providers/:id/disable      disable
//   POST   /api/kms-providers/:id/set-default  atomically swap default
//   POST   /api/kms-providers/:id/probe        round-trip probe an existing row
//   DELETE /api/kms-providers/:id              hard-delete (with safety guards)
//
// Auth model:
//   This file is mounted with authMiddleware(['admin']) in
//   server/index.js. All operations are admin-only because they
//   manage the keys that protect every backup. No per-handler
//   role tightening; the auth gate is at the mount.
//
// No hardware-passkey step-up:
//   Unlike POST /api/restore-approvals/:id/approve, these endpoints
//   do NOT require a hardware-passkey step-up. The destructive surface is bounded
//   by the service-level guards (seed-row protection, default-row
//   protection, last-enabled-row protection) and every mutation is
//   audit-logged. A future commit may add a hardware-passkey step-up on
//   set-default and delete if SOC-audit experience suggests it's
//   warranted.
//
// Audit log:
//   The service writes operation-specific events
//   (KMS_PROVIDER_CREATED, _UPDATED, _ENABLED, _DISABLED,
//   _DEFAULT_CHANGED, _DELETED, _PROBED). The global auditMiddleware
//   in index.js writes the HTTP-level audit row. This file does not
//   duplicate-log.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const kmsSvc = require('../services/kms-providers');

// ── Error mapping ────────────────────────────────────────────────────────────

function kmsCodeToHttpStatus(code) {
  switch (code) {
    case kmsSvc.CODES.INVALID_INPUT:
      return 400;
    case kmsSvc.CODES.PROVIDER_NOT_FOUND:
      return 404;
    case kmsSvc.CODES.NAME_CONFLICT:
    case kmsSvc.CODES.PROVIDER_DISABLED:
    case kmsSvc.CODES.IS_SEED_ROW:
    case kmsSvc.CODES.IS_DEFAULT:
    case kmsSvc.CODES.LAST_ENABLED:
      return 409;
    case kmsSvc.CODES.PROVIDER_VALIDATION_FAILED:
    case kmsSvc.CODES.PROVIDER_PROBE_FAILED:
      return 422;
    case kmsSvc.CODES.ENCRYPTION_NOT_CONFIGURED:
    case kmsSvc.CODES.PROVIDER_NOT_REGISTERED:
      return 500;
    default:
      return 500;
  }
}

function sendKmsError(res, err) {
  const status = kmsCodeToHttpStatus(err.code);
  const body = { error: err.message, code: err.code };
  if (err.detail !== undefined) body.detail = err.detail;
  res.status(status).json(body);
}

function ctx(req) {
  return { user_id: req.user.id, client_ip: req.ip || null };
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// ── GET /api/kms-providers ──────────────────────────────────────────────────
//
// Query: ?provider_type=, ?enabled=true|false, ?limit=N, ?offset=N
router.get('/', (req, res) => {
  try {
    const opts = {};
    if (req.query.provider_type) opts.provider_type = String(req.query.provider_type);
    if (req.query.enabled !== undefined) {
      const v = String(req.query.enabled).toLowerCase();
      opts.enabled = v === 'true' || v === '1';
    }
    if (req.query.limit !== undefined) opts.limit = Number(req.query.limit);
    if (req.query.offset !== undefined) opts.offset = Number(req.query.offset);

    const items = kmsSvc.listProviders(getDb(), opts);
    return res.json({ items, count: items.length });
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers list failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── GET /api/kms-providers/default ──────────────────────────────────────────
router.get('/default', (req, res) => {
  try {
    const row = kmsSvc.getDefault(getDb());
    return res.json(row);
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers get-default failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/kms-providers/probe-config ────────────────────────────────────
//
// Body: { provider_type, config, credentials }
//
// Pure: no DB write. Use BEFORE create to surface bad config at form-
// submit time as inline validation feedback.
//
// Returns 200 with { ok: bool, error?, detail? } either way -- a probe
// failure is a 200 with ok:false, NOT an HTTP error, because the
// "did the probe succeed" is itself the answer the caller wants.
// HTTP errors are reserved for malformed requests.
router.post('/probe-config', async (req, res) => {
  const body = req.body || {};
  if (!isPlainObject(body)) {
    return res.status(400).json({ error: 'request body must be an object', code: 'INVALID_INPUT' });
  }
  if (typeof body.provider_type !== 'string') {
    return res.status(400).json({ error: 'provider_type required', code: 'INVALID_INPUT' });
  }
  if (body.config !== undefined && !isPlainObject(body.config)) {
    return res.status(400).json({ error: 'config must be an object when provided', code: 'INVALID_INPUT' });
  }
  if (body.credentials !== undefined && body.credentials !== null && !isPlainObject(body.credentials)) {
    return res.status(400).json({ error: 'credentials must be an object or null when provided', code: 'INVALID_INPUT' });
  }

  try {
    const result = await kmsSvc.probeConfig(getDb(), {
      provider_type: body.provider_type,
      config: body.config || {},
      credentials: body.credentials === undefined ? null : body.credentials,
    });
    return res.json(result);
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers probe-config failed', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── GET /api/kms-providers/:id ──────────────────────────────────────────────
router.get('/:id', (req, res) => {
  try {
    const row = kmsSvc.getProviderById(getDb(), req.params.id);
    if (!row) {
      return res.status(404).json({ error: `kms_provider ${req.params.id} not found`, code: 'PROVIDER_NOT_FOUND' });
    }
    return res.json(row);
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers get failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/kms-providers ─────────────────────────────────────────────────
//
// Body:
//   {
//     name              required, ^[a-z0-9-]+$, max 64
//     provider_type     required, one of env-var/aws-kms/azure-keyvault/gcp-kms/hashicorp-vault
//     config            required, object (provider-specific schema)
//     credentials       optional, object or null
//     enabled           optional, default true
//     is_default        optional, default false (if true, atomically swaps current default)
//     probe             optional, default true for cloud, false for env-var
//   }
//
// Returns 201 with the new row's publicView (no credentials_encrypted).
router.post('/', async (req, res) => {
  const body = req.body || {};
  if (!isPlainObject(body)) {
    return res.status(400).json({ error: 'request body must be an object', code: 'INVALID_INPUT' });
  }
  if (body.config !== undefined && !isPlainObject(body.config)) {
    return res.status(400).json({ error: 'config must be an object', code: 'INVALID_INPUT' });
  }
  if (body.credentials !== undefined && body.credentials !== null && !isPlainObject(body.credentials)) {
    return res.status(400).json({ error: 'credentials must be an object or null', code: 'INVALID_INPUT' });
  }

  try {
    const row = await kmsSvc.createProvider(getDb(), {
      name: body.name,
      provider_type: body.provider_type,
      config: body.config || {},
      credentials: body.credentials === undefined ? null : body.credentials,
      enabled: body.enabled,
      is_default: body.is_default,
      probe: body.probe,
    }, ctx(req));
    return res.status(201).json(row);
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers create failed', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── PATCH /api/kms-providers/:id ────────────────────────────────────────────
//
// Body (all fields optional):
//   {
//     name           rename (validated for uniqueness)
//     config         replace config (triggers re-validate + re-probe)
//     credentials    replace credentials (triggers re-validate + re-probe).
//                    Pass null to clear; omit to keep the existing value.
//     enabled        toggle enable/disable (also see /enable + /disable)
//   }
//
// provider_type is immutable. Create a new row + delete the old to
// switch types. is_default is changed via /set-default for clarity.
router.patch('/:id', async (req, res) => {
  const body = req.body || {};
  if (!isPlainObject(body)) {
    return res.status(400).json({ error: 'request body must be an object', code: 'INVALID_INPUT' });
  }
  if (body.config !== undefined && !isPlainObject(body.config)) {
    return res.status(400).json({ error: 'config must be an object', code: 'INVALID_INPUT' });
  }
  if (body.credentials !== undefined && body.credentials !== null && !isPlainObject(body.credentials)) {
    return res.status(400).json({ error: 'credentials must be an object or null', code: 'INVALID_INPUT' });
  }
  if (body.provider_type !== undefined) {
    return res.status(400).json({
      error: 'provider_type is immutable; create a new row and delete this one to switch',
      code: 'INVALID_INPUT',
    });
  }
  if (body.is_default !== undefined) {
    return res.status(400).json({
      error: 'use POST /:id/set-default to change the default',
      code: 'INVALID_INPUT',
    });
  }

  try {
    const updateArgs = {};
    if (body.name !== undefined) updateArgs.name = body.name;
    if (body.config !== undefined) updateArgs.config = body.config;
    if (body.credentials !== undefined) updateArgs.credentials = body.credentials;
    if (body.enabled !== undefined) updateArgs.enabled = body.enabled;

    const row = await kmsSvc.updateProvider(getDb(), req.params.id, updateArgs, ctx(req));
    return res.json(row);
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers update failed', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/kms-providers/:id/enable ──────────────────────────────────────
router.post('/:id/enable', async (req, res) => {
  try {
    const row = await kmsSvc.enableProvider(getDb(), req.params.id, ctx(req));
    return res.json(row);
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers enable failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/kms-providers/:id/disable ─────────────────────────────────────
router.post('/:id/disable', async (req, res) => {
  try {
    const row = await kmsSvc.disableProvider(getDb(), req.params.id, ctx(req));
    return res.json(row);
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers disable failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/kms-providers/:id/set-default ─────────────────────────────────
//
// Atomically swap the default-marked row. Refuses if target is disabled
// (the default must be usable). Returns:
//   { previous_default_id, new_default_id }
router.post('/:id/set-default', (req, res) => {
  try {
    const result = kmsSvc.setDefault(getDb(), req.params.id, ctx(req));
    return res.json(result);
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers set-default failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── POST /api/kms-providers/:id/probe ───────────────────────────────────────
//
// Round-trip probe an existing row. Updates last_probe_* columns and
// audit-logs the result. Returns the probe outcome as JSON; a failed
// probe returns 200 with { ok: false, error, ... } rather than an
// HTTP error -- the probe outcome IS the response data.
router.post('/:id/probe', async (req, res) => {
  try {
    const result = await kmsSvc.probeProvider(getDb(), req.params.id, ctx(req));
    return res.json(result);
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers probe failed', { error: err.message, stack: err.stack });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

// ── DELETE /api/kms-providers/:id ───────────────────────────────────────────
//
// Hard-delete. Refuses for the env-var-default seed row, the current
// default, and the only enabled row. Operators must keep all rows
// referenced by any backup they intend to restore -- there is no FK
// from backups to kms_providers, so the service cannot enforce that.
router.delete('/:id', (req, res) => {
  try {
    const result = kmsSvc.deleteProvider(getDb(), req.params.id, ctx(req));
    return res.json(result);
  } catch (err) {
    if (err instanceof kmsSvc.KmsProviderError) return sendKmsError(res, err);
    logger.error('kms-providers delete failed', { error: err.message });
    return res.status(500).json({ error: 'internal error', code: 'INTERNAL' });
  }
});

module.exports = router;

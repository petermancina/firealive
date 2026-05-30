// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — AI Provider Routes
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Endpoints for the AI/ML Integrations tab in MC. Lead-only.
//
//   GET  /api/ai-provider/status                  — overall status
//   GET  /api/ai-provider/config                  — list per-feature configs
//   PUT  /api/ai-provider/config/:featureId       — update one feature config
//   GET  /api/ai-provider/inferences/:featureId   — recent inference log
//   POST /api/ai-provider/model/verify            — verify provisioned model files (no download)
//   GET  /api/ai-provider/model/verify/status     — poll verification
//   GET  /api/ai-provider/model/provisioning      — provisioning guide + pinned hashes
//   POST /api/ai-provider/model/load              — load model into memory
//   POST /api/ai-provider/model/unload            — unload model from memory
//
// All endpoints require lead/admin role; AI provider routing is a platform-
// configuration concern and analysts shouldn't be able to point burnout
// message generation (their own data) at an unapproved external provider.
// Each modification fires an audit log entry.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { getDb } = require('../db/init');
const { encryptConfig } = require('../services/encryption');
const aiProvider = require('../services/ai-provider');

// Lazy requires for services that may not exist yet (commit-sequence safety)
let internalLlm = null;
function getInternalLlm() {
  if (internalLlm === null) {
    try { internalLlm = require('../services/internal-llm'); }
    catch (_) { internalLlm = false; }
  }
  return internalLlm || null;
}

let downloader = null;
function getDownloader() {
  if (downloader === null) {
    try { downloader = require('../../scripts/download-model'); }
    catch (_) { downloader = false; }
  }
  return downloader || null;
}

// ── Module-scoped verify job tracker ────────────────────────────────────────
// FireAlive never downloads models. This verifies the operator-provisioned
// files (streaming SHA-256) in the background; the client polls
// /model/verify/status. The chat model (~9 GB) takes a moment to hash.

let verifyJob = null;  // { model, status, result, error, startedAt, finishedAt, initiatedBy }

function leadOrAdmin(req, res, next) {
  if (!req.user || !['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

router.use(leadOrAdmin);

// ── GET /api/ai-provider/status ─────────────────────────────────────────────

router.get('/status', (req, res) => {
  try {
    const llm = getInternalLlm();
    const dl = getDownloader();
    const internalStatus = llm ? llm.getStatus() : { ready: false, available: false, reason: 'service not present' };
    const modelPresent = dl ? dl.isModelPresent('chat') : false;
    const embedderPresent = dl ? dl.isModelPresent('embedding') : false;
    const configs = aiProvider.listProviderConfigs();
    return res.json({
      internalLlm: internalStatus,
      modelPresent,
      embedderPresent,
      provisioningRequired: !(modelPresent && embedderPresent),
      featuresConfigured: configs.length,
      activeDownload: null,  // FireAlive does not download models (verify-only)
      activeVerify: verifyJob ? {
        model: verifyJob.model,
        status: verifyJob.status,
        startedAt: verifyJob.startedAt,
      } : null,
    });
  } catch (err) {
    logger.error('AI provider status failed', { error: err.message });
    return res.status(500).json({ error: 'failed to read status' });
  }
});

// ── GET /api/ai-provider/config ─────────────────────────────────────────────

router.get('/config', (req, res) => {
  try {
    const configs = aiProvider.listProviderConfigs();
    return res.json({ configs });
  } catch (err) {
    logger.error('AI provider config list failed', { error: err.message });
    return res.status(500).json({ error: 'failed to list configs' });
  }
});

// ── PUT /api/ai-provider/config/:featureId ──────────────────────────────────

const VALID_FEATURES = ['ir_simulator', 'burnout_messages', 'kb_synthesis', 'ttx_enhancement', 'troubleshooter', 'kb_chat'];
const VALID_PROVIDERS = ['internal', 'anthropic', 'openai', 'gemini', 'azure_openai', 'aws_bedrock', 'custom'];

router.put('/config/:featureId', (req, res) => {
  const { featureId } = req.params;
  if (!VALID_FEATURES.includes(featureId)) {
    return res.status(400).json({ error: 'invalid featureId; must be one of: ' + VALID_FEATURES.join(', ') });
  }

  const body = req.body || {};
  const { provider, modelName, providerConfig, maxTokens, temperature } = body;

  if (!VALID_PROVIDERS.includes(provider)) {
    return res.status(400).json({ error: 'invalid provider; must be one of: ' + VALID_PROVIDERS.join(', ') });
  }

  const maxTok = parseInt(maxTokens, 10) || 1024;
  if (maxTok < 1 || maxTok > 32000) {
    return res.status(400).json({ error: 'maxTokens must be between 1 and 32000' });
  }

  const temp = (temperature === undefined || temperature === null) ? 0.7 : Number(temperature);
  if (Number.isNaN(temp) || temp < 0 || temp > 2) {
    return res.status(400).json({ error: 'temperature must be between 0 and 2' });
  }

  // Encrypt providerConfig if present (external providers need credentials).
  // Internal provider has no credentials so config_encrypted is NULL.
  let configEncrypted = null;
  if (provider !== 'internal') {
    if (!providerConfig || typeof providerConfig !== 'object') {
      return res.status(400).json({ error: `providerConfig required for provider: ${provider}` });
    }
    try {
      configEncrypted = encryptConfig(providerConfig);
    } catch (err) {
      logger.error('Failed to encrypt provider config', { featureId, error: err.message });
      return res.status(500).json({ error: 'failed to encrypt provider config' });
    }
  }

  const db = getDb();
  try {
    db.prepare(`
      INSERT INTO ai_provider_config (feature_id, provider, model_name, config_encrypted, max_tokens, temperature, updated_by, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(feature_id) DO UPDATE SET
        provider = excluded.provider,
        model_name = excluded.model_name,
        config_encrypted = excluded.config_encrypted,
        max_tokens = excluded.max_tokens,
        temperature = excluded.temperature,
        updated_by = excluded.updated_by,
        updated_at = datetime('now')
    `).run(featureId, provider, modelName || null, configEncrypted, maxTok, temp, req.user.id);
  } catch (err) {
    logger.error('Failed to write ai_provider_config', { featureId, error: err.message });
    return res.status(500).json({ error: 'failed to save config' });
  } finally {
    db.close();
  }

  auditLog(req.user.id, 'AI_PROVIDER_CONFIGURED', `feature=${featureId} provider=${provider} model=${modelName || 'default'}`, req.ip);
  return res.json({ ok: true, featureId, provider, modelName: modelName || null });
});

// ── GET /api/ai-provider/inferences/:featureId ──────────────────────────────

router.get('/inferences/:featureId', (req, res) => {
  const { featureId } = req.params;
  if (!VALID_FEATURES.includes(featureId)) {
    return res.status(400).json({ error: 'invalid featureId' });
  }
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 500);
  try {
    const inferences = aiProvider.recentInferences(featureId, limit);
    return res.json({ inferences });
  } catch (err) {
    logger.error('Failed to read inferences', { featureId, error: err.message });
    return res.status(500).json({ error: 'failed to read inferences' });
  }
});

// ── POST /api/ai-provider/model/verify  (alias: /model/download) ─────────────
// FireAlive does NOT download models. This verifies the operator-provisioned
// files against the source-pinned SHA-256s (scripts/download-model.js). The
// legacy /model/download path is kept as a compat alias and also verifies.

router.post(['/model/verify', '/model/download'], (req, res) => {
  const dl = getDownloader();
  if (!dl) {
    return res.status(500).json({ error: 'provisioning tool not present' });
  }
  if (verifyJob && verifyJob.status === 'running') {
    return res.status(409).json({ error: 'a verification is already running', activeVerify: verifyJob });
  }

  // Optional model id. Legacy { variant: "phi3" } bodies are ignored and fall
  // through to verifying everything.
  const requested = (req.body && (req.body.model || req.body.variant)) || 'all';
  const model = dl.MODELS[requested] ? requested : 'all';

  verifyJob = {
    model,
    status: 'running',
    result: null,
    error: null,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    initiatedBy: req.user.id,
  };

  const run = model === 'all'
    ? dl.verifyAll()
    : dl.verifyModel(model).then(r => ({ ok: r.ok, models: { [model]: r } }));

  Promise.resolve(run)
    .then((result) => {
      verifyJob.status = result.ok ? 'ok' : 'failed';
      verifyJob.result = result;
      verifyJob.finishedAt = new Date().toISOString();
      auditLog(req.user.id, result.ok ? 'AI_MODEL_VERIFIED' : 'AI_MODEL_VERIFY_FAILED', `model=${model}`, null);
    })
    .catch((err) => {
      verifyJob.status = 'failed';
      verifyJob.error = err.message;
      verifyJob.finishedAt = new Date().toISOString();
      logger.error('Model verification failed', { model, error: err.message });
      auditLog(req.user.id, 'AI_MODEL_VERIFY_FAILED', `model=${model} error=${err.message}`, null);
    });

  return res.status(202).json({
    ok: true,
    message: 'FireAlive does not download models; verifying provisioned files. Poll /model/verify/status.',
    job: { model, startedAt: verifyJob.startedAt },
  });
});

// ── GET /api/ai-provider/model/verify/status  (alias: /model/download/status) ─

router.get(['/model/verify/status', '/model/download/status'], (req, res) => {
  if (!verifyJob) {
    return res.json({ active: false });
  }
  return res.json({
    active: verifyJob.status === 'running',
    job: verifyJob,
  });
});

// ── GET /api/ai-provider/model/provisioning ──────────────────────────────────
// Operator guide: official first-party source, pinned hashes, target dir,
// endpoint floor. No network is performed.

router.get('/model/provisioning', (req, res) => {
  const dl = getDownloader();
  if (!dl) {
    return res.status(500).json({ error: 'provisioning tool not present' });
  }
  try {
    const modelDir = dl.resolveModelDir();
    const models = {};
    for (const id of dl.MODEL_IDS) {
      const m = dl.MODELS[id];
      models[id] = {
        kind: m.kind,
        label: m.label,
        officialSource: m.officialSource,
        endpointFloor: m.endpointFloor,
        files: m.files.map(f => ({ filename: f.filename, sizeApprox: f.sizeApprox, sha256: f.sha256 })),
        instructions: dl.provisioningInstructions(id),
        present: dl.isModelPresent(id),
      };
    }
    return res.json({ modelDir, models });
  } catch (err) {
    logger.error('provisioning info failed', { error: err.message });
    return res.status(500).json({ error: 'failed to build provisioning info' });
  }
});

// ── POST /api/ai-provider/model/load ────────────────────────────────────────

router.post('/model/load', async (req, res) => {
  const llm = getInternalLlm();
  if (!llm) {
    return res.status(500).json({ error: 'internal-llm service not present' });
  }
  try {
    await llm.loadModel(req.body && req.body.modelPath);
    auditLog(req.user.id, 'AI_MODEL_LOADED', null, req.ip);
    return res.json({ ok: true, status: llm.getStatus() });
  } catch (err) {
    logger.error('Model load failed', { error: err.message });
    return res.status(500).json({ error: err.message, code: err.code });
  }
});

// ── POST /api/ai-provider/model/unload ──────────────────────────────────────

router.post('/model/unload', async (req, res) => {
  const llm = getInternalLlm();
  if (!llm) {
    return res.status(500).json({ error: 'internal-llm service not present' });
  }
  try {
    await llm.unloadModel();
    auditLog(req.user.id, 'AI_MODEL_UNLOADED', null, req.ip);
    return res.json({ ok: true });
  } catch (err) {
    logger.error('Model unload failed', { error: err.message });
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;

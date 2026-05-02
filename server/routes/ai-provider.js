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
//   POST /api/ai-provider/model/download          — trigger model download
//   GET  /api/ai-provider/model/download/status   — poll download progress
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

// ── Module-scoped download job tracker ──────────────────────────────────────
// Single concurrent download supported. The download process runs in the
// background; the client polls /model/download/status for progress.

let downloadJob = null;  // { variant, status, progress, error, startedAt, finishedAt }

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
    const modelPresent = dl ? dl.isModelPresent() : false;
    const configs = aiProvider.listProviderConfigs();
    return res.json({
      internalLlm: internalStatus,
      modelPresent,
      featuresConfigured: configs.length,
      activeDownload: downloadJob ? {
        variant: downloadJob.variant,
        status: downloadJob.status,
        progress: downloadJob.progress,
        startedAt: downloadJob.startedAt,
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

const VALID_FEATURES = ['ir_simulator', 'burnout_messages', 'kb_synthesis', 'ttx_enhancement', 'troubleshooter'];
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

// ── POST /api/ai-provider/model/download ────────────────────────────────────

router.post('/model/download', (req, res) => {
  const dl = getDownloader();
  if (!dl) {
    return res.status(500).json({ error: 'download script not present' });
  }

  // Don't double-trigger
  if (downloadJob && downloadJob.status === 'running') {
    return res.status(409).json({ error: 'a download is already running', activeDownload: downloadJob });
  }

  const variant = (req.body && req.body.variant) || dl.DEFAULT_VARIANT;
  if (!dl.VARIANTS[variant]) {
    return res.status(400).json({ error: 'unknown variant; must be one of: ' + Object.keys(dl.VARIANTS).join(', ') });
  }

  downloadJob = {
    variant,
    status: 'running',
    progress: { downloadedBytes: 0, totalBytes: 0, pct: 0 },
    error: null,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    initiatedBy: req.user.id,
  };

  // Run download in the background
  dl.downloadModel(variant, {
    silent: true,
    onProgress: (p) => {
      if (downloadJob) downloadJob.progress = p;
    },
  })
    .then(() => {
      downloadJob.status = 'complete';
      downloadJob.progress.pct = 100;
      downloadJob.finishedAt = new Date().toISOString();
      auditLog(req.user.id, 'AI_MODEL_DOWNLOADED', `variant=${variant}`, null);
    })
    .catch((err) => {
      downloadJob.status = 'error';
      downloadJob.error = err.message;
      downloadJob.finishedAt = new Date().toISOString();
      logger.error('Model download failed', { variant, error: err.message });
      auditLog(req.user.id, 'AI_MODEL_DOWNLOAD_FAILED', `variant=${variant} error=${err.message}`, null);
    });

  return res.status(202).json({
    ok: true,
    message: 'download started; poll /model/download/status for progress',
    job: { variant, startedAt: downloadJob.startedAt },
  });
});

// ── GET /api/ai-provider/model/download/status ──────────────────────────────

router.get('/model/download/status', (req, res) => {
  if (!downloadJob) {
    return res.json({ active: false });
  }
  return res.json({
    active: downloadJob.status === 'running',
    job: downloadJob,
  });
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

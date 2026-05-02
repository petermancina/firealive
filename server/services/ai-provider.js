// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — AI Provider Dispatcher
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Unified interface for AI inference across the platform. Every AI-using
// feature calls this dispatcher rather than calling internal or external
// providers directly. The dispatcher reads per-feature configuration from
// the ai_provider_config table and routes the call accordingly.
//
// Usage:
//
//   const { generate } = require('./ai-provider');
//   const result = await generate('ir_simulator', 'Generate an OODA scenario...', {
//     maxTokens: 1500,
//     temperature: 0.6,
//   });
//   // result.text — the generated output
//   // result.provider — which provider answered
//   // result.modelName — which model
//   // result.latencyMs — how long it took
//   // result.tokenCount — { input, output }
//
// Throws structured errors:
//   - 'AI_NOT_CONFIGURED' — no row in ai_provider_config for featureId
//   - 'AI_INTERNAL_UNAVAILABLE' — internal provider selected but model not loaded
//   - 'AI_EXTERNAL_UNAVAILABLE' — external provider selected but config missing
//   - 'AI_TIMEOUT' — call exceeded configured timeout
//   - 'AI_RATE_LIMITED' — external provider rate-limited the call
//   - 'AI_INFERENCE_FAILED' — generic inference error
//
// Every call is logged to ai_inference_log regardless of success/failure.
// The log records token counts and metadata only; prompt and response content
// are NOT stored to avoid leaking Tier-3 burnout data into plain audit logs.
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { decryptConfig } = require('./encryption');
const { logger } = require('./logger');

// Default per-call timeout. Overridable in options.
const DEFAULT_TIMEOUT_MS = 60000;  // 60s — internal LLM scenario generation can be slow

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Generate text via the configured provider for the given feature.
 *
 * @param {string} featureId  one of the ai_provider_config CHECK list values
 * @param {string} prompt     the prompt to send to the model
 * @param {object} options    optional overrides
 *   - maxTokens (default: from ai_provider_config or 1024)
 *   - temperature (default: from ai_provider_config or 0.7)
 *   - timeoutMs (default: 60000)
 *   - userId (default: null) — for audit log attribution
 * @returns {Promise<{text, provider, modelName, latencyMs, tokenCount}>}
 */
async function generate(featureId, prompt, options) {
  options = options || {};
  const startedAt = Date.now();

  if (!featureId || typeof featureId !== 'string') {
    throw aiError('AI_NOT_CONFIGURED', 'featureId required');
  }
  if (!prompt || typeof prompt !== 'string') {
    throw aiError('AI_NOT_CONFIGURED', 'prompt required');
  }

  // Look up per-feature config
  const config = readProviderConfig(featureId);
  if (!config) {
    throw aiError('AI_NOT_CONFIGURED', `no provider configured for feature: ${featureId}`);
  }

  const provider = config.provider;
  const modelName = config.modelName;
  const maxTokens = options.maxTokens || config.maxTokens || 1024;
  const temperature = (options.temperature !== undefined) ? options.temperature : (config.temperature !== null ? config.temperature : 0.7);
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
  const userId = options.userId || null;

  let result;
  try {
    if (provider === 'internal') {
      result = await callInternal(prompt, modelName, maxTokens, temperature, timeoutMs);
    } else {
      result = await callExternal(provider, prompt, modelName, maxTokens, temperature, config.providerConfig, timeoutMs);
    }
  } catch (err) {
    const latencyMs = Date.now() - startedAt;
    writeInferenceLog({
      featureId,
      provider,
      modelName,
      userId,
      inputTokenCount: estimateTokens(prompt),
      outputTokenCount: 0,
      latencyMs,
      status: classifyError(err),
      errorMessage: err.message ? err.message.slice(0, 500) : String(err).slice(0, 500),
    });
    logger.warn('AI generation failed', {
      featureId,
      provider,
      error: err.message,
      latencyMs,
    });
    throw err;
  }

  const latencyMs = Date.now() - startedAt;
  writeInferenceLog({
    featureId,
    provider,
    modelName: result.modelName || modelName,
    userId,
    inputTokenCount: result.tokenCount.input,
    outputTokenCount: result.tokenCount.output,
    latencyMs,
    status: 'success',
    errorMessage: null,
  });

  return {
    text: result.text,
    provider,
    modelName: result.modelName || modelName,
    latencyMs,
    tokenCount: result.tokenCount,
  };
}

/**
 * Read the current configuration for a feature.
 * Returns null if no row exists.
 */
function readProviderConfig(featureId) {
  const db = getDb();
  try {
    const row = db.prepare(`
      SELECT feature_id, provider, model_name, config_encrypted, max_tokens, temperature, updated_at
      FROM ai_provider_config
      WHERE feature_id = ?
    `).get(featureId);
    if (!row) return null;

    let providerConfig = null;
    if (row.config_encrypted) {
      try {
        providerConfig = decryptConfig(row.config_encrypted);
      } catch (err) {
        logger.error('Failed to decrypt AI provider config', { featureId, error: err.message });
        // Don't throw here — the dispatcher will surface this as AI_EXTERNAL_UNAVAILABLE
        // when the call attempts to use providerConfig.
      }
    }

    return {
      featureId: row.feature_id,
      provider: row.provider,
      modelName: row.model_name,
      maxTokens: row.max_tokens,
      temperature: row.temperature,
      providerConfig,
      updatedAt: row.updated_at,
    };
  } finally {
    db.close();
  }
}

/**
 * List all configured features. Returns rows without the encrypted blob.
 * Used by the AI/ML Integrations tab to show current routing.
 */
function listProviderConfigs() {
  const db = getDb();
  try {
    const rows = db.prepare(`
      SELECT feature_id, provider, model_name, max_tokens, temperature, updated_by, updated_at,
             (config_encrypted IS NOT NULL) AS has_external_config
      FROM ai_provider_config
      ORDER BY feature_id
    `).all();
    return rows.map(r => ({
      featureId: r.feature_id,
      provider: r.provider,
      modelName: r.model_name,
      maxTokens: r.max_tokens,
      temperature: r.temperature,
      updatedBy: r.updated_by,
      updatedAt: r.updated_at,
      hasExternalConfig: !!r.has_external_config,
    }));
  } finally {
    db.close();
  }
}

/**
 * Get the latest N inference log entries for a feature.
 * Used by the AI/ML Integrations tab to show recent activity and errors.
 */
function recentInferences(featureId, limit) {
  limit = Math.min(parseInt(limit, 10) || 50, 500);
  const db = getDb();
  try {
    const rows = db.prepare(`
      SELECT id, feature_id, provider, model_name, user_id,
             input_token_count, output_token_count, latency_ms, status, error_message, created_at
      FROM ai_inference_log
      WHERE feature_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).all(featureId, limit);
    return rows;
  } finally {
    db.close();
  }
}

// ── Provider Routing ────────────────────────────────────────────────────────
// internal-llm.js and external-llm.js are loaded lazily so the dispatcher
// can be imported even when those services aren't present yet (e.g. during
// the F4a commit sequence before commits 3 and 4 land).

async function callInternal(prompt, modelName, maxTokens, temperature, timeoutMs) {
  let internalLlm;
  try {
    internalLlm = require('./internal-llm');
  } catch (err) {
    throw aiError('AI_INTERNAL_UNAVAILABLE', 'internal-llm service not present');
  }
  if (!internalLlm.isReady || !internalLlm.isReady()) {
    throw aiError('AI_INTERNAL_UNAVAILABLE', 'internal LLM not loaded; run model bootstrap');
  }
  return await runWithTimeout(
    internalLlm.generate(prompt, { modelName, maxTokens, temperature }),
    timeoutMs,
  );
}

async function callExternal(provider, prompt, modelName, maxTokens, temperature, providerConfig, timeoutMs) {
  if (!providerConfig) {
    throw aiError('AI_EXTERNAL_UNAVAILABLE', `no credentials configured for provider: ${provider}`);
  }
  let externalLlm;
  try {
    externalLlm = require('./external-llm');
  } catch (err) {
    throw aiError('AI_EXTERNAL_UNAVAILABLE', 'external-llm service not present');
  }
  return await runWithTimeout(
    externalLlm.generate(provider, prompt, { modelName, maxTokens, temperature, providerConfig }),
    timeoutMs,
  );
}

function runWithTimeout(promise, timeoutMs) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(aiError('AI_TIMEOUT', `inference exceeded ${timeoutMs}ms`)), timeoutMs)),
  ]);
}

// ── Inference Log ───────────────────────────────────────────────────────────

function writeInferenceLog(entry) {
  const db = getDb();
  try {
    db.prepare(`
      INSERT INTO ai_inference_log
        (feature_id, provider, model_name, user_id,
         input_token_count, output_token_count, latency_ms, status, error_message)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.featureId,
      entry.provider,
      entry.modelName || null,
      entry.userId || null,
      entry.inputTokenCount || null,
      entry.outputTokenCount || null,
      entry.latencyMs,
      entry.status,
      entry.errorMessage || null,
    );
  } catch (err) {
    // Audit log writes should never break the application path. Log the
    // failure to the logger but don't throw.
    logger.error('Failed to write ai_inference_log entry', { error: err.message, entry });
  } finally {
    db.close();
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Rough token count estimator. Used only for audit log when the provider
 * doesn't return real token counts. Approximates the standard 4-chars-per-token
 * heuristic for English text.
 */
function estimateTokens(text) {
  if (!text) return 0;
  return Math.ceil(text.length / 4);
}

function classifyError(err) {
  if (err && err.code) {
    if (err.code === 'AI_TIMEOUT') return 'timeout';
    if (err.code === 'AI_RATE_LIMITED') return 'rate_limited';
  }
  return 'error';
}

function aiError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

module.exports = {
  generate,
  readProviderConfig,
  listProviderConfigs,
  recentInferences,
};

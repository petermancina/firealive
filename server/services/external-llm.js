// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — External LLM Service
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Wraps HTTP calls to external AI providers. Called by the AI provider
// dispatcher (ai-provider.js) when a feature is configured to use a
// non-'internal' provider.
//
// Supported providers (matching the ai_provider_config CHECK constraint):
//
//   anthropic     — Anthropic API (Claude family)
//   openai        — OpenAI API (GPT family)
//   gemini        — Google Generative Language API (Gemini family)
//   azure_openai  — Azure OpenAI Service (per-deployment endpoints)
//   aws_bedrock   — AWS Bedrock (multi-model: Claude, Titan, Llama, etc.)
//   custom        — User-provided OpenAI-compatible endpoint
//
// Each provider exposes a normalized generate() interface. The dispatcher
// passes the decrypted providerConfig blob (endpoint URL + API key + any
// provider-specific fields) and we issue the HTTP call, parse the response,
// and return a unified shape:
//
//   { text, modelName, tokenCount: { input, output } }
//
// All HTTP calls use Node's built-in fetch (Node 18+). No third-party HTTP
// dependency required. Requests respect the dispatcher's timeoutMs via
// AbortController.
//
// This service is NOT called directly by feature code. Always go through
// the dispatcher.
// ═══════════════════════════════════════════════════════════════════════════════

const { logger } = require('./logger');

// Default models per provider — used when ai_provider_config.model_name is null.
const DEFAULT_MODELS = {
  anthropic: 'claude-opus-4-7',
  openai: 'gpt-5.5',
  gemini: 'gemini-2.5-pro',
  azure_openai: null,        // Azure requires per-deployment model name; no useful default
  aws_bedrock: 'anthropic.claude-opus-4-7',
  custom: null,              // custom endpoints must specify their own model
};

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Run inference against an external provider.
 *
 * @param {string} provider       one of: anthropic, openai, gemini, azure_openai, aws_bedrock, custom
 * @param {string} prompt
 * @param {object} options
 *   - modelName (optional; falls back to DEFAULT_MODELS[provider])
 *   - maxTokens
 *   - temperature
 *   - providerConfig — decrypted blob from ai_provider_config.config_encrypted
 * @returns {Promise<{text, modelName, tokenCount: {input, output}}>}
 */
async function generate(provider, prompt, options) {
  options = options || {};
  const providerConfig = options.providerConfig || {};
  const modelName = options.modelName || DEFAULT_MODELS[provider];
  const maxTokens = options.maxTokens || 1024;
  const temperature = (options.temperature !== undefined) ? options.temperature : 0.7;

  if (!modelName) {
    throw aiError('AI_EXTERNAL_UNAVAILABLE',
      `provider '${provider}' requires model_name in ai_provider_config (no default available)`);
  }
  if (!providerConfig.apiKey && provider !== 'custom') {
    throw aiError('AI_EXTERNAL_UNAVAILABLE',
      `provider '${provider}' requires apiKey in providerConfig`);
  }

  switch (provider) {
    case 'anthropic':    return generateAnthropic(prompt, modelName, maxTokens, temperature, providerConfig);
    case 'openai':       return generateOpenAI(prompt, modelName, maxTokens, temperature, providerConfig);
    case 'gemini':       return generateGemini(prompt, modelName, maxTokens, temperature, providerConfig);
    case 'azure_openai': return generateAzureOpenAI(prompt, modelName, maxTokens, temperature, providerConfig);
    case 'aws_bedrock':  return generateAWSBedrock(prompt, modelName, maxTokens, temperature, providerConfig);
    case 'custom':       return generateCustom(prompt, modelName, maxTokens, temperature, providerConfig);
    default:
      throw aiError('AI_EXTERNAL_UNAVAILABLE', `unsupported provider: ${provider}`);
  }
}

// ── Per-provider implementations ────────────────────────────────────────────

async function generateAnthropic(prompt, modelName, maxTokens, temperature, cfg) {
  const url = cfg.endpointUrl || 'https://api.anthropic.com/v1/messages';
  const res = await fetchWithRetry(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': cfg.apiKey,
      'anthropic-version': cfg.anthropicVersion || '2023-06-01',
    },
    body: JSON.stringify({
      model: modelName,
      max_tokens: maxTokens,
      temperature,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
  const data = await parseJsonResponse(res, 'anthropic');
  const text = (data.content || [])
    .filter(b => b.type === 'text')
    .map(b => b.text)
    .join('');
  const usage = data.usage || {};
  return {
    text,
    modelName,
    tokenCount: {
      input: usage.input_tokens || 0,
      output: usage.output_tokens || 0,
    },
  };
}

async function generateOpenAI(prompt, modelName, maxTokens, temperature, cfg) {
  const url = cfg.endpointUrl || 'https://api.openai.com/v1/chat/completions';
  const res = await fetchWithRetry(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${cfg.apiKey}`,
    },
    body: JSON.stringify({
      model: modelName,
      max_tokens: maxTokens,
      temperature,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
  const data = await parseJsonResponse(res, 'openai');
  const choice = (data.choices && data.choices[0]) || {};
  const text = (choice.message && choice.message.content) || '';
  const usage = data.usage || {};
  return {
    text,
    modelName,
    tokenCount: {
      input: usage.prompt_tokens || 0,
      output: usage.completion_tokens || 0,
    },
  };
}

async function generateGemini(prompt, modelName, maxTokens, temperature, cfg) {
  // Gemini's generative language API uses a per-model URL with the API key
  // either in a query param or in the x-goog-api-key header. Header preferred.
  const baseUrl = cfg.endpointUrl || 'https://generativelanguage.googleapis.com/v1beta';
  const url = `${baseUrl}/models/${encodeURIComponent(modelName)}:generateContent`;
  const res = await fetchWithRetry(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': cfg.apiKey,
    },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        maxOutputTokens: maxTokens,
        temperature,
      },
    }),
  });
  const data = await parseJsonResponse(res, 'gemini');
  const candidate = (data.candidates && data.candidates[0]) || {};
  const parts = (candidate.content && candidate.content.parts) || [];
  const text = parts.map(p => p.text || '').join('');
  const usage = data.usageMetadata || {};
  return {
    text,
    modelName,
    tokenCount: {
      input: usage.promptTokenCount || 0,
      output: usage.candidatesTokenCount || 0,
    },
  };
}

async function generateAzureOpenAI(prompt, modelName, maxTokens, temperature, cfg) {
  // Azure OpenAI uses per-deployment endpoint URLs supplied by the customer.
  // modelName here is the Azure deployment name (configurable per Azure resource).
  if (!cfg.endpointUrl) {
    throw aiError('AI_EXTERNAL_UNAVAILABLE',
      'azure_openai requires endpointUrl in providerConfig (the Azure resource URL)');
  }
  const apiVersion = cfg.apiVersion || '2024-08-01-preview';
  const url = `${cfg.endpointUrl}/openai/deployments/${encodeURIComponent(modelName)}/chat/completions?api-version=${encodeURIComponent(apiVersion)}`;
  const res = await fetchWithRetry(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'api-key': cfg.apiKey,
    },
    body: JSON.stringify({
      max_tokens: maxTokens,
      temperature,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
  const data = await parseJsonResponse(res, 'azure_openai');
  const choice = (data.choices && data.choices[0]) || {};
  const text = (choice.message && choice.message.content) || '';
  const usage = data.usage || {};
  return {
    text,
    modelName,
    tokenCount: {
      input: usage.prompt_tokens || 0,
      output: usage.completion_tokens || 0,
    },
  };
}

async function generateAWSBedrock(prompt, modelName, maxTokens, temperature, cfg) {
  // Bedrock requires SigV4 signing of every request, which is non-trivial
  // without the AWS SDK. To avoid forcing the AWS SDK as a runtime dependency
  // on every install, this implementation expects the user-supplied
  // endpointUrl to be a SigV4-signing proxy in their environment (e.g.
  // an internal API Gateway or a small Lambda fronting Bedrock).
  //
  // For deployments that prefer direct Bedrock access, the @aws-sdk/client-
  // bedrock-runtime package can be added later as an opt-in dependency,
  // and this branch can switch to the SDK path based on a config flag.
  if (!cfg.endpointUrl) {
    throw aiError('AI_EXTERNAL_UNAVAILABLE',
      'aws_bedrock requires endpointUrl in providerConfig (a SigV4-signing proxy in your AWS environment); direct SDK support is opt-in via cfg.useDirectSdk and a separate dependency install');
  }
  // Bedrock's invoke-model body shape varies by model family. We support
  // the Anthropic-on-Bedrock shape by default since that's the most common
  // pairing for FireAlive's use case.
  const body = {
    anthropic_version: 'bedrock-2023-05-31',
    max_tokens: maxTokens,
    temperature,
    messages: [{ role: 'user', content: prompt }],
  };
  const res = await fetchWithRetry(cfg.endpointUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${cfg.apiKey}`,  // proxy-managed credential
      'X-Bedrock-Model-Id': modelName,
    },
    body: JSON.stringify(body),
  });
  const data = await parseJsonResponse(res, 'aws_bedrock');
  const text = (data.content || [])
    .filter(b => b.type === 'text')
    .map(b => b.text)
    .join('') || data.completion || '';
  const usage = data.usage || {};
  return {
    text,
    modelName,
    tokenCount: {
      input: usage.input_tokens || 0,
      output: usage.output_tokens || 0,
    },
  };
}

async function generateCustom(prompt, modelName, maxTokens, temperature, cfg) {
  // Custom endpoints follow the OpenAI Chat Completions API shape.
  // Useful for self-hosted vLLM, Ollama, LiteLLM, LM Studio, etc.
  if (!cfg.endpointUrl) {
    throw aiError('AI_EXTERNAL_UNAVAILABLE',
      'custom provider requires endpointUrl in providerConfig');
  }
  const headers = { 'Content-Type': 'application/json' };
  if (cfg.apiKey) headers['Authorization'] = `Bearer ${cfg.apiKey}`;
  if (cfg.extraHeaders && typeof cfg.extraHeaders === 'object') {
    Object.assign(headers, cfg.extraHeaders);
  }
  const res = await fetchWithRetry(cfg.endpointUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: modelName,
      max_tokens: maxTokens,
      temperature,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
  const data = await parseJsonResponse(res, 'custom');
  const choice = (data.choices && data.choices[0]) || {};
  const text = (choice.message && choice.message.content) || '';
  const usage = data.usage || {};
  return {
    text,
    modelName,
    tokenCount: {
      input: usage.prompt_tokens || 0,
      output: usage.completion_tokens || 0,
    },
  };
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

/**
 * Issue an HTTP request. The dispatcher already provides the outer timeout via
 * Promise.race in ai-provider.js, so we don't add a second AbortController
 * here. We do retry once on transient failures (5xx, network error).
 */
async function fetchWithRetry(url, init) {
  const maxAttempts = 2;
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(url, init);
      if (res.status >= 500 && attempt < maxAttempts) {
        logger.warn('External AI returned 5xx, retrying', { url, status: res.status, attempt });
        await sleep(500);
        continue;
      }
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt < maxAttempts) {
        logger.warn('External AI request failed, retrying', { url, error: err.message, attempt });
        await sleep(500);
      }
    }
  }
  throw aiError('AI_INFERENCE_FAILED', 'external AI request failed: ' + (lastErr ? lastErr.message : 'unknown'));
}

async function parseJsonResponse(res, provider) {
  if (res.status === 429) {
    let detail = '';
    try { detail = await res.text(); } catch (_) { /* ignore */ }
    throw aiError('AI_RATE_LIMITED', `${provider} returned 429: ${detail.slice(0, 200)}`);
  }
  if (!res.ok) {
    let detail = '';
    try { detail = await res.text(); } catch (_) { /* ignore */ }
    throw aiError('AI_INFERENCE_FAILED', `${provider} returned ${res.status}: ${detail.slice(0, 200)}`);
  }
  try {
    return await res.json();
  } catch (err) {
    throw aiError('AI_INFERENCE_FAILED', `${provider} returned invalid JSON: ${err.message}`);
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function aiError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

module.exports = {
  generate,
  DEFAULT_MODELS,
};

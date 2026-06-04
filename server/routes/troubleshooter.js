// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Troubleshooter (server-side diagnostics + internal-LLM synthesis)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
//   POST /api/troubleshoot   (admin) — { description }
//     → { topic, findings[], baseline[], diagnosis, aiUnavailable:false }
//     or { topic, findings[], baseline[], diagnosis:null, aiUnavailable:true, aiReason }
//
// One query, one complete answer. The flow:
//
//   1. Run the rule-based diagnostics engine (services/troubleshooter-diagnostics)
//      against live server state. It keyword-routes the description to a topic and
//      returns ranked findings + an always-run baseline. It never throws.
//   2. Build a grounding prompt containing the operator's problem and ONLY those
//      findings, and instruct the model to reason solely over them.
//   3. Generate the "diagnosis & prioritized fixes" synthesis with the INTERNAL
//      LLM ONLY (services/internal-llm, called directly — the KB-chat pattern).
//      This route never consults ai_provider_config and has no path that could
//      route its context to an external provider; it is internal-only by design.
//
// If the internal model is not loaded or inference fails, the route does NOT
// error — it returns the rule-based findings with diagnosis:null and
// aiUnavailable:true. The findings are useful on their own.
//
// Privacy/audit: the description and the synthesis are content and are never
// logged. Only metadata (feature_id, provider, model, token estimate, latency,
// status) is written to ai_inference_log; the audit event records the topic and
// finding count only — never the problem text or the diagnosis.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const { getDb } = require('../db/init');
const internalLlm = require('../services/internal-llm');
const diagnostics = require('../services/troubleshooter-diagnostics');

const MAX_DESCRIPTION = 1000;
const MAX_TOKENS = 600;
const TEMPERATURE = 0.3;   // low — grounded, factual synthesis over the findings

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Metadata-only inference log (mirrors services/ai-provider.js writeInferenceLog).
// Never throws — a log-write failure must not break the response path.
function writeInferenceLog(entry) {
  try {
    getDb().prepare(
      'INSERT INTO ai_inference_log '
      + '(feature_id, provider, model_name, user_id, input_token_count, output_token_count, latency_ms, status, error_message) '
      + 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      'troubleshooter', 'internal', entry.modelName || null, entry.userId || null,
      null, entry.outputTokenCount || null, entry.latencyMs, entry.status, entry.errorMessage || null
    );
  } catch (err) {
    logger.error('Failed to write ai_inference_log entry (troubleshooter)', { error: err.message });
  }
}

// Map an internal-LLM error to a short reason for the rule-based-only fallback.
function unavailableReason(err) {
  const code = (err && err.code) ? err.code : '';
  const msg = (err && err.message) ? err.message : '';
  if (code === 'AI_INTERNAL_UNAVAILABLE' || code === 'AI_INTERNAL_INVALID_MODEL_PATH') {
    return /not found|not present|not loaded|node-llama-cpp/i.test(msg) ? 'model_not_loaded' : 'model_unavailable';
  }
  if (code === 'AI_INFERENCE_FAILED') { return 'inference_failed'; }
  return 'inference_error';
}

// Build the grounding prompt: the model reasons ONLY over the supplied findings.
function buildPrompt(description, findings, baseline) {
  const lines = [];
  lines.push('You are the FireAlive diagnostic assistant. A SOC operator is troubleshooting a problem with the FireAlive platform.');
  lines.push('');
  lines.push('Operator problem description:');
  lines.push(String(description));
  lines.push('');
  lines.push('Automated rule-based checks against the live system (these are the ONLY facts you may use):');
  const fmt = (fnd) => '- [' + String(fnd.status).toUpperCase() + '] ' + fnd.label + ': ' + fnd.detail
    + (fnd.fix ? ' (suggested fix: ' + fnd.fix + ')' : '');
  for (const fnd of findings) { lines.push(fmt(fnd)); }
  if (baseline && baseline.length) {
    lines.push('');
    lines.push('System baseline checks:');
    for (const fnd of baseline) { lines.push(fmt(fnd)); }
  }
  lines.push('');
  lines.push('Instructions: Using ONLY the checks above, identify the most likely cause(s) of the '
    + 'operator problem and give a short, prioritized list of concrete fixes, referencing the relevant '
    + 'check labels. Be concise. Do NOT invent platform state, configuration, features, or checks that '
    + 'are not listed above. If the checks do not explain the problem, say so and suggest what to inspect next.');
  return lines.join('\n');
}

router.post('/', requireRole('admin'), async (req, res) => {
  const body = req.body || {};
  const description = (typeof body.description === 'string' ? body.description.trim() : '').slice(0, MAX_DESCRIPTION);
  if (!description) {
    return res.status(400).json({ error: 'description is required (non-empty string, max ' + MAX_DESCRIPTION + ' characters)' });
  }

  const started = Date.now();
  const db = getDb();

  // 1. Rule-based diagnostics (always available; never throws).
  const result = diagnostics.runDiagnostics(db, description);
  const topic = result.topic;
  const findings = result.findings || [];
  const baseline = result.baseline || [];

  // 2–3. LLM synthesis over the findings (internal model only, called directly).
  const prompt = buildPrompt(description, findings, baseline);
  let gen;
  try {
    gen = await internalLlm.generate(prompt, { maxTokens: MAX_TOKENS, temperature: TEMPERATURE });
  } catch (err) {
    const reason = unavailableReason(err);
    writeInferenceLog({ userId: req.user.id, latencyMs: Date.now() - started, status: 'error', errorMessage: reason });
    auditLog(req.user.id, 'MC_TROUBLESHOOT', 'topic=' + topic + ' findings=' + findings.length + ' ai=unavailable(' + reason + ')', req.ip);
    return res.json({ topic: topic, findings: findings, baseline: baseline, diagnosis: null, aiUnavailable: true, aiReason: reason });
  }

  const text = (gen && typeof gen.text === 'string') ? gen.text.trim() : '';
  if (!text) {
    writeInferenceLog({ userId: req.user.id, modelName: gen ? gen.modelName : null, outputTokenCount: gen ? gen.tokenCount : null, latencyMs: Date.now() - started, status: 'error', errorMessage: 'empty_synthesis' });
    auditLog(req.user.id, 'MC_TROUBLESHOOT', 'topic=' + topic + ' findings=' + findings.length + ' ai=empty', req.ip);
    return res.json({ topic: topic, findings: findings, baseline: baseline, diagnosis: null, aiUnavailable: true, aiReason: 'empty_synthesis' });
  }

  // Success — findings + baseline + the grounded synthesis.
  writeInferenceLog({ userId: req.user.id, modelName: gen.modelName, outputTokenCount: gen.tokenCount, latencyMs: Date.now() - started, status: 'success' });
  auditLog(req.user.id, 'MC_TROUBLESHOOT', 'topic=' + topic + ' findings=' + findings.length + ' ai=ok', req.ip);
  return res.json({ topic: topic, findings: findings, baseline: baseline, diagnosis: text, aiUnavailable: false });
});

module.exports = router;

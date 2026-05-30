// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Lead KB Assistant chat (server-side RAG over the Research KB)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
//   POST /api/kb-chat   (lead/admin) — { question, k?, teamContext? }
//     → { answer, citedEntries[], retrievedIds[], modelName, unavailable:false }
//     or { answer:null, citedEntries:[], unavailable:true, reason }
//
// A research-education assistant for SOC team leads. It is NOT therapy and gives
// organizational, research-grounded guidance only. The flow is strict RAG:
//
//   1. Embed the question and retrieve the top-N most similar KB entries
//      (server/services/kb-embeddings).
//   2. Build a grounding prompt containing ONLY those entries and instruct the
//      model to cite every claim with the entry's [R0xx]/[N0xx] identifier.
//   3. Generate with the INTERNAL LLM ONLY (server/services/internal-llm,
//      called directly). This route never consults ai_provider_config and never
//      routes to an external provider — the lead chat is internal-only by design,
//      regardless of any feature config row.
//   4. Run the output through research-kb.validateCitations against the RETRIEVED
//      ids (stricter than the whole KB: the model may only cite what it was
//      given). On failure, retry once with a corrective instruction; if it still
//      fails, REJECT — return an unavailable result rather than ungrounded text.
//
// Privacy/audit: the question and answer are content and are never logged. Only
// metadata (feature_id, provider, model, token estimate, latency, status) is
// written to ai_inference_log; the audit event records counts only.
//
// teamContext (optional): the MC may pass a short, already-aggregated, non-
// attributable team summary (Tier-1 data the lead already sees) as background.
// It is clearly marked non-citable in the prompt — only KB entries are citable —
// and is length-capped. It is never logged.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const { getDb } = require('../db/init');
const researchKb = require('../services/research-kb');
const kbEmbeddings = require('../services/kb-embeddings');
const internalLlm = require('../services/internal-llm');

const DEFAULT_K = 6;
const MAX_K = 12;
const MAX_QUESTION = 2000;
const MAX_TEAM_CONTEXT = 2000;
const MAX_TOKENS = 700;
const TEMPERATURE = 0.3;   // low — grounded, factual, low-creativity

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

const SYSTEM = [
  'You are the FireAlive Research Assistant for SOC team leads.',
  "Answer the lead's question using ONLY the numbered research entries provided below.",
  'Every factual claim must cite the entry it comes from, using that entry\'s identifier in square brackets, e.g. [R024].',
  'Use only the identifiers listed below. Never cite an identifier that is not in the entries, and never invent a study.',
  'If the provided research does not address the question, say so plainly and cite nothing.',
  'Be concise and practical. This is organizational, research-grounded guidance — not medical, clinical, or therapeutic advice.',
].join('\n');

function entriesBlock(entries) {
  return entries
    .map((e) => `[${e.id}] ${e.title || e.topic} (${e.year}). Finding: ${e.finding} Implication: ${e.implication}`)
    .join('\n\n');
}

function buildPrompt(question, entries, teamContext) {
  let p = SYSTEM + '\n\nRESEARCH ENTRIES:\n' + entriesBlock(entries);
  if (teamContext) {
    p += '\n\nTEAM CONTEXT (aggregate, non-attributable background — do NOT cite this; cite only the research entries above):\n' + teamContext;
  }
  p += '\n\nLEAD\'S QUESTION: ' + question;
  p += '\n\nAnswer (cite every claim with a bracketed identifier from the entries above):';
  return p;
}

function retrySuffix(allowedIds, offending) {
  return '\n\n[Your previous answer cited identifiers that were not in the provided entries'
    + (offending && offending.length ? ' (' + offending.join(', ') + ')' : '')
    + '. Rewrite the answer using ONLY these identifiers: ' + allowedIds.join(', ')
    + '. Cite only from them, and cite nothing else.]';
}

// Metadata-only inference log (mirrors services/ai-provider.js writeInferenceLog).
// Never throws — an audit-write failure must not break the response path.
function writeInferenceLog(entry) {
  try {
    getDb().prepare(
      'INSERT INTO ai_inference_log '
      + '(feature_id, provider, model_name, user_id, input_token_count, output_token_count, latency_ms, status, error_message) '
      + 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      'kb_chat', 'internal', entry.modelName || null, entry.userId || null,
      null, entry.outputTokenCount || null, entry.latencyMs, entry.status, entry.errorMessage || null
    );
  } catch (err) {
    logger.error('Failed to write ai_inference_log entry (kb_chat)', { error: err.message });
  }
}

// Map an embedder/LLM unavailability to an honest 503 payload + reason.
function mapUnavailable(err) {
  const msg = (err && err.message) ? err.message : '';
  if (err && (err.code === 'KB_EMBED_UNAVAILABLE' || err.code === 'AI_INTERNAL_UNAVAILABLE')) {
    const reason = /not found|not present|not loaded|node-llama-cpp/i.test(msg) ? 'model_not_loaded' : 'unavailable';
    return { reason };
  }
  return null; // not an availability error
}

router.post('/', requireRole('lead', 'admin'), async (req, res) => {
  const body = req.body || {};
  const question = (typeof body.question === 'string' ? body.question.trim() : '').slice(0, MAX_QUESTION);
  if (!question) {
    return res.status(400).json({ error: 'question is required (non-empty string)' });
  }
  let k = parseInt(body.k, 10);
  if (!Number.isInteger(k) || k <= 0) k = DEFAULT_K;
  if (k > MAX_K) k = MAX_K;
  const teamContext = (typeof body.teamContext === 'string' ? body.teamContext.trim() : '').slice(0, MAX_TEAM_CONTEXT);

  const started = Date.now();
  try {
    // 1. Retrieve top-N (embedder may be unavailable → honest 503).
    let ranked;
    try {
      ranked = await kbEmbeddings.search(question, k);
    } catch (err) {
      const u = mapUnavailable(err);
      if (u) {
        writeInferenceLog({ userId: req.user.id, latencyMs: Date.now() - started, status: 'error', errorMessage: 'embedder_' + u.reason });
        return res.status(503).json({ answer: null, citedEntries: [], unavailable: true, reason: u.reason });
      }
      throw err;
    }
    const byId = new Map(researchKb.getAll().map((e) => [e.id, e]));
    const entries = ranked.map((r) => byId.get(r.id)).filter(Boolean);
    if (entries.length === 0) {
      writeInferenceLog({ userId: req.user.id, latencyMs: Date.now() - started, status: 'error', errorMessage: 'no_retrieval' });
      return res.json({ answer: null, citedEntries: [], unavailable: true, reason: 'no_retrieval' });
    }
    const allowed = entries.map((e) => e.id);
    const basePrompt = buildPrompt(question, entries, teamContext);

    // 2–3. Generate (internal LLM only) + citation gate, retry once.
    let answer = null, okCheck = null, modelName = null, tokenCount = null;
    for (let attempt = 0; attempt < 2 && answer === null; attempt++) {
      const prompt = attempt === 0 ? basePrompt : basePrompt + retrySuffix(allowed, okCheck ? okCheck.offending : []);
      let gen;
      try {
        gen = await internalLlm.generate(prompt, { maxTokens: MAX_TOKENS, temperature: TEMPERATURE });
      } catch (err) {
        const u = mapUnavailable(err);
        if (u) {
          writeInferenceLog({ userId: req.user.id, latencyMs: Date.now() - started, status: 'error', errorMessage: 'llm_' + u.reason });
          return res.status(503).json({ answer: null, citedEntries: [], unavailable: true, reason: u.reason });
        }
        throw err;
      }
      modelName = gen.modelName;
      tokenCount = gen.tokenCount;
      const check = researchKb.validateCitations(gen.text, allowed);
      if (check.ok) { answer = gen.text; okCheck = check; } else { okCheck = check; }
    }

    // 4. Reject if the gate never passed — never return ungrounded text.
    if (answer === null) {
      writeInferenceLog({ userId: req.user.id, modelName, outputTokenCount: tokenCount, latencyMs: Date.now() - started, status: 'error', errorMessage: 'citation_check_failed' });
      auditLog(req.user.id, 'MC_KB_CHAT', 'k=' + k + ' status=rejected', req.ip);
      return res.json({ answer: null, citedEntries: [], unavailable: true, reason: 'citation_check_failed' });
    }

    // Success — attach the enriched entries that were actually cited.
    const citedEntries = researchKb.getByRefs(okCheck.cited);
    writeInferenceLog({ userId: req.user.id, modelName, outputTokenCount: tokenCount, latencyMs: Date.now() - started, status: 'success' });
    auditLog(req.user.id, 'MC_KB_CHAT', 'k=' + k + ' cited=' + okCheck.cited.length, req.ip);
    return res.json({ answer, citedEntries, retrievedIds: allowed, modelName, unavailable: false });
  } catch (err) {
    logger.error('kb-chat failed', { error: err && err.message });
    return res.status(500).json({ error: 'internal error' });
  }
});

module.exports = router;

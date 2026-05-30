// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Research KB routes (semantic search + entry lookup)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Read-only retrieval surface over the Research Knowledge Base for the
// Management Console (lead/admin). This is the PR2 retrieval foundation — there
// is NO text generation here. /search embeds the query, ranks the KB by cosine
// similarity, and returns the matching enriched entries with their scores;
// /entry returns a single enriched entry. The Lead KB Assistant chat (PR4) layers
// RAG (retrieve → ground an internal LLM → strict citation gate) on top of these.
//
//   POST /api/kb/search      (lead/admin) — { query, k? } → top-N entries + scores
//   GET  /api/kb/entry/:id    (lead/admin) — one enriched entry by R-/N-ref id
//
// Mounted with authMiddleware(['lead','admin']) in server/index.js, so req.user
// is already authenticated; requireRole() below just narrows the role set.
//
// Honest-unavailable contract: when the embedding model isn't present (the
// bootstrap hasn't fetched it, or the host can't run it), search returns HTTP 503
// with a structured { status:'unavailable', reason, detail } body rather than a
// 500 — the same honesty the rest of FireAlive's AI surfaces use. The KB entry
// lookup does NOT need the model and keeps working regardless.
//
// Privacy/audit: the search query is treated as content and is NOT written to the
// audit log — only metadata (result count, k) is recorded, consistent with the
// metadata-only AI audit philosophy.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const researchKb = require('../services/research-kb');
const kbEmbeddings = require('../services/kb-embeddings');

const DEFAULT_K = 5;
const MAX_K = 20;

// Narrow the already-authenticated request to a role set (mount-level
// authMiddleware has already verified the token + set req.user).
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Map a KB embedding error to an honest unavailable payload.
function unavailablePayload(err) {
  const msg = (err && err.message) ? err.message : 'embedding service unavailable';
  let reason = 'error';
  if (err && err.code === 'KB_EMBED_UNAVAILABLE') {
    reason = /not found|not present|node-llama-cpp/i.test(msg) ? 'model_not_loaded' : 'unavailable';
  } else if (err && err.code === 'KB_EMBED_FAILED') {
    reason = 'inference_failed';
  }
  return { status: 'unavailable', reason, detail: msg.slice(0, 200) };
}

// ── POST /search — embed the query, rank the KB, return enriched entries + scores.
// Body: { query: string, k?: number }. k is clamped to [1, MAX_K] (default 5).
router.post('/search', requireRole('lead', 'admin'), async (req, res) => {
  const body = req.body || {};
  const query = (typeof body.query === 'string') ? body.query.trim() : '';
  if (!query) {
    return res.status(400).json({ error: 'query is required (non-empty string)' });
  }
  let k = parseInt(body.k, 10);
  if (!Number.isInteger(k) || k <= 0) k = DEFAULT_K;
  if (k > MAX_K) k = MAX_K;

  try {
    const ranked = await kbEmbeddings.search(query, k);   // [{ id, score }] in score order
    const byId = new Map(researchKb.getAll().map((e) => [e.id, e]));
    const results = ranked
      .map((r) => ({ score: r.score, entry: byId.get(r.id) }))
      .filter((r) => r.entry);                            // ids always exist; defensive
    // Metadata-only audit — the query text itself is not logged.
    auditLog(req.user.id, 'MC_KB_SEARCH', `k=${k} n=${results.length}`, req.ip);
    return res.json({ query, k, count: results.length, results });
  } catch (err) {
    const payload = unavailablePayload(err);
    logger.warn('KB search unavailable', { reason: payload.reason, error: err && err.message });
    return res.status(503).json(payload);
  }
});

// ── GET /entry/:id — one enriched entry. No model needed.
router.get('/entry/:id', requireRole('lead', 'admin'), (req, res) => {
  const id = String(req.params.id || '').trim().toUpperCase();
  const entry = researchKb.getByRefs([id])[0];
  if (!entry) {
    return res.status(404).json({ error: 'KB entry not found', id });
  }
  return res.json({ entry });
});

module.exports = router;

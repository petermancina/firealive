// FireAlive v1.0.42 — Burnout Message Generator
//
// Orchestrates AI generation of the team-level burnout-intervention prompts for
// the N1b precompute jobs. Per-analyst signal interpretations are private to the
// analyst and generated ON-DEVICE (never server-side), so this module produces
// only the team surface. It owns three responsibilities:
//
//   1. Whole-KB grounding. Every prompt embeds the entire 42-entry research KB
//      (research-kb.getAll), so the model may ground a suggestion in any entry,
//      not a fixed subset.
//   2. Strict anti-hallucination gate. The model is instructed to cite only the
//      provided R-refs; the output is then validated against the whole KB. If
//      any cited ref is off-KB (or the output is malformed), the result is
//      retried once and, failing that, rejected. No canned content is ever
//      produced — a rejected or failed generation returns { ok: false }, and
//      the caller writes no cache row, so the read surface shows the honest
//      AI-unavailable state.
//   3. Provider failure handling. Any aiError (AI_NOT_CONFIGURED,
//      AI_INTERNAL_UNAVAILABLE, AI_TIMEOUT, AI_INFERENCE_FAILED, ...) returns
//      { ok: false, reason } immediately — a retry can't fix a config or
//      availability problem.

const aiProvider = require('./ai-provider');
const researchKb = require('./research-kb');
const { logger } = require('./logger');

const TIMEOUT_MS = 30000;
const MAX_ATTEMPTS = 2; // one initial attempt + one retry

// Compact one-line-per-entry serialization of the KB for prompt embedding.
function serializeKb() {
  return researchKb
    .getAll()
    .map((e) => `${e.id} — ${e.finding} Implication: ${e.implication}`)
    .join('\n');
}

// ── Prompt builders ──────────────────────────────────────────────────────────

function teamPrompt(condition, th, retry) {
  const correction = retry
    ? '\nIMPORTANT: your previous response was rejected for citing research not in the list, or for invalid JSON. Cite ONLY R-ref ids present in the list, and return strictly the JSON object described.\n'
    : '';
  return [
    'You are a SOC team-health advisor writing for a shift lead. A team-level',
    'condition has been detected from aggregate metrics only \u2014 there is no',
    'individual analyst data and you must not refer to any individual.',
    '',
    `Condition: ${condition.label} (key ${condition.key}, severity ${condition.severity})`,
    `Team aggregate: health score ${th.score}/100 (${th.status}); average`,
    `utilization ${th.avgUtil}%; ${th.oc} of ${th.size} analysts over capacity;`,
    `${th.ext} in extended over-capacity.`,
    '',
    'Favor structural and organizational actions (staffing, routing, automation,',
    'scheduling) over individual ones, consistent with the evidence. Be concrete',
    'and non-alarmist.',
    '',
    'Ground your guidance ONLY in the peer-reviewed research below. Cite the',
    'entries you rely on by R-ref id. Do NOT cite research not in this list. Do',
    'NOT invent citations or statistics.',
    correction,
    'RESEARCH KNOWLEDGE BASE:',
    serializeKb(),
    '',
    'Respond with ONLY a JSON object \u2014 no markdown fences, no preamble \u2014 in',
    'exactly this shape:',
    '{"full":{"title":"...","body":"...","cite":"..."},"compact":{"title":"...","body":"...","cite":"..."},"minimal":{"title":"...","body":"..."}}',
    'The "full" body is 3 to 6 sentences with a concrete ACTION and a WHY that',
    'cites R-refs in parentheses. "compact" is 1 to 2 sentences. "minimal" is a',
    'short phrase. Each "cite" field lists the cited refs as "KB refs: R0XX, R0YY".',
  ].join('\n');
}

// ── Parsers (return { validateText, result } or null) ─────────────────────────

function parseTeam(text) {
  let s = String(text || '').trim();
  // Strip markdown fences and any prose around the JSON object.
  const first = s.indexOf('{');
  const last = s.lastIndexOf('}');
  if (first === -1 || last === -1 || last < first) return null;
  s = s.slice(first, last + 1);
  let obj;
  try {
    obj = JSON.parse(s);
  } catch {
    return null;
  }
  const ok = (v) => v && typeof v.title === 'string' && typeof v.body === 'string';
  if (!ok(obj.full) || !ok(obj.compact) || !ok(obj.minimal)) return null;
  const content = {
    full: { title: obj.full.title, body: obj.full.body, cite: obj.full.cite || '' },
    compact: { title: obj.compact.title, body: obj.compact.body, cite: obj.compact.cite || '' },
    minimal: { title: obj.minimal.title, body: obj.minimal.body },
  };
  return { validateText: JSON.stringify(content), result: { content } };
}

// ── Core: generate -> parse -> strict citation gate -> retry once ─────────────

async function generateWithGate(kind, buildPrompt, parse, userId) {
  const allRefs = researchKb.getAll().map((e) => e.id);
  let reason = 'AI_INFERENCE_FAILED';
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    let res;
    try {
      res = await aiProvider.generate('burnout_messages', buildPrompt(attempt > 0), {
        timeoutMs: TIMEOUT_MS,
        userId: userId || null,
      });
    } catch (err) {
      // Provider/config/availability failure — a retry won't help.
      return { ok: false, reason: err && err.code ? err.code : 'AI_INFERENCE_FAILED' };
    }
    const parsed = parse(res.text);
    if (!parsed) {
      reason = 'AI_MALFORMED_OUTPUT';
      continue;
    }
    const v = researchKb.validateCitations(parsed.validateText, allRefs);
    if (!v.ok) {
      reason = 'AI_CITATION_REJECTED';
      logger.warn('burnout-message-generator: rejected off-KB citation', {
        kind,
        offending: v.offending,
      });
      continue;
    }
    return { ok: true, ...parsed.result, model_name: res.modelName, kb_refs: v.cited };
  }
  return { ok: false, reason };
}

// ── Public API ────────────────────────────────────────────────────────────────

// condition: { key, severity, label }; th: team-health aggregate.
// Returns { ok:true, content:{full,compact,minimal}, model_name, kb_refs } or
// { ok:false, reason }. Scheduled (no triggering user) so userId is null.
function generateTeamPrompt(condition, th) {
  return generateWithGate(
    'team',
    (retry) => teamPrompt(condition, th, retry),
    parseTeam,
    null
  );
}

module.exports = { generateTeamPrompt };

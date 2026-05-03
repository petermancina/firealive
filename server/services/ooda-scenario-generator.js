// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — OODA Scenario Generator
//
// Generates OODA-loop training scenarios for the IR Simulator. Replaces the
// pre-F4b hardcoded ransomware template in routes/ooda.js with LLM-driven
// generation that uses uploaded ir_policies and ooda_aars as context.
//
// Pipeline:
//   1. Caller provides scenarioType, difficulty, optional policy filter,
//      and userId (for audit log attribution)
//   2. Fetch matching policies from ir_policies (deleted_at IS NULL)
//   3. Fetch recent AARs from ooda_aars (deleted_at IS NULL, capped)
//   4. Run policies through ir-policy-parser to get structured context
//   5. Build a prompt with the structured context, scenarioType, difficulty
//   6. Call aiProvider.generate('ir_simulator', prompt, {userId, ...})
//   7. Parse the LLM JSON output into a node tree
//   8. Validate the tree structure (every choice points to a real node, etc.)
//   9. Return { tree, sourcePolicyIds, providerInfo }
//
// Failure modes:
//   - AI_NOT_CONFIGURED — dispatcher has no row for 'ir_simulator'. Caller
//     should respond 503 and direct admin to MC AI/ML Integrations.
//   - AI_TIMEOUT — model took longer than dispatcher's timeout. Caller
//     should respond 504 with retry hint.
//   - AI_RATE_LIMITED — external provider throttled. Caller responds 429.
//   - SCENARIO_INVALID_OUTPUT — LLM produced output that doesn't parse or
//     fails structural validation. Caller responds 502; the inference
//     audit log already captured the failure.
//   - SCENARIO_NO_POLICIES — no policies uploaded yet. Caller responds 400
//     directing the user to upload at least one policy first.
//
// This service does NOT write to the database. The caller (routes/ooda.js)
// is responsible for persisting the returned tree to ooda_scenarios. This
// keeps the generator pure (input → output) and easy to reason about.
//
// Phase F4b — IR Simulator backend.
// ═══════════════════════════════════════════════════════════════════════════════

const aiProvider = require('./ai-provider');
const { parsePolicies } = require('./ir-policy-parser');
const { logger } = require('./logger');
const { getDb } = require('../db/init');

const FEATURE_ID = 'ir_simulator';
const DEFAULT_TIMEOUT_MS = 90000;       // 90s — scenario gen is heavier than chat
const DEFAULT_MAX_TOKENS = 2500;
const DEFAULT_TEMPERATURE = 0.7;
const MAX_POLICIES_IN_PROMPT = 5;
const MAX_AARS_IN_PROMPT = 3;
const MIN_NODES_PER_SCENARIO = 4;       // observe + orient + decide + act minimum
const MAX_NODES_PER_SCENARIO = 12;
const MAX_CHOICES_PER_NODE = 4;
const VALID_PHASES = ['observe', 'orient', 'decide', 'act', 'resolution'];
const VALID_TYPES = [
  'ransomware', 'phishing', 'data_exfil', 'insider_threat',
  'apt', 'ddos', 'supply_chain', 'credential_compromise',
];
const VALID_DIFFICULTIES = ['beginner', 'intermediate', 'advanced'];

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Generate a scenario of the given type and difficulty using uploaded
 * policies and AARs as context.
 *
 * @param {object} params
 * @param {string} params.scenarioType       one of VALID_TYPES
 * @param {string} params.difficulty         one of VALID_DIFFICULTIES
 * @param {string[]} [params.policyIds]      optional filter — only use these
 *                                           policy ids as context (default: all)
 * @param {string} [params.userId]           audit log attribution
 * @returns {Promise<{tree, sourcePolicyIds, provider, modelName, latencyMs, tokenCount}>}
 */
async function generateScenario(params) {
  const { scenarioType, difficulty } = validateParams(params || {});
  const userId = params && params.userId ? params.userId : null;
  const policyIdFilter = Array.isArray(params && params.policyIds) ? params.policyIds : null;

  // 1. Fetch policies
  const policies = fetchPolicies(policyIdFilter);
  if (policies.length === 0) {
    throw scenarioError(
      'SCENARIO_NO_POLICIES',
      'no IR policies available — upload at least one policy before generating scenarios'
    );
  }

  // 2. Fetch AARs
  const aars = fetchRecentAars();

  // 3. Parse policies into structured context
  const parsed = parsePolicies(policies);

  // 4. Build prompt
  const prompt = buildPrompt({ scenarioType, difficulty, parsed, aars });

  // 5. Call dispatcher
  let result;
  try {
    result = await aiProvider.generate(FEATURE_ID, prompt, {
      userId,
      maxTokens: DEFAULT_MAX_TOKENS,
      temperature: DEFAULT_TEMPERATURE,
      timeoutMs: DEFAULT_TIMEOUT_MS,
    });
  } catch (err) {
    // Dispatcher errors (AI_NOT_CONFIGURED, AI_TIMEOUT, etc.) are passed
    // through unchanged — they already have the right error codes for the
    // caller to switch on.
    logger.warn('Scenario generation: dispatcher error', {
      scenarioType, difficulty, error: err.message, code: err.code,
    });
    throw err;
  }

  // 6. Parse LLM output
  let tree;
  try {
    tree = parseTreeOutput(result.text);
  } catch (parseErr) {
    logger.warn('Scenario generation: LLM output parse failed', {
      scenarioType, difficulty, error: parseErr.message,
      sampleOutput: result.text ? result.text.slice(0, 300) : '',
    });
    throw scenarioError(
      'SCENARIO_INVALID_OUTPUT',
      'model output could not be parsed as a scenario tree'
    );
  }

  // 7. Validate tree structurally
  try {
    validateTree(tree, { scenarioType, difficulty });
  } catch (validateErr) {
    logger.warn('Scenario generation: structural validation failed', {
      scenarioType, difficulty, error: validateErr.message,
    });
    throw scenarioError(
      'SCENARIO_INVALID_OUTPUT',
      `scenario structure invalid: ${validateErr.message}`
    );
  }

  return {
    tree,
    sourcePolicyIds: policies.map(p => p.id),
    provider: result.provider,
    modelName: result.modelName,
    latencyMs: result.latencyMs,
    tokenCount: result.tokenCount,
  };
}

// ── Step helpers ────────────────────────────────────────────────────────────

function validateParams(params) {
  const scenarioType = VALID_TYPES.includes(params.scenarioType) ? params.scenarioType : null;
  const difficulty = VALID_DIFFICULTIES.includes(params.difficulty) ? params.difficulty : null;
  if (!scenarioType) {
    throw scenarioError('SCENARIO_INVALID_PARAMS', `scenarioType must be one of: ${VALID_TYPES.join(', ')}`);
  }
  if (!difficulty) {
    throw scenarioError('SCENARIO_INVALID_PARAMS', `difficulty must be one of: ${VALID_DIFFICULTIES.join(', ')}`);
  }
  return { scenarioType, difficulty };
}

function fetchPolicies(policyIdFilter) {
  const db = getDb();
  try {
    let rows;
    if (policyIdFilter && policyIdFilter.length > 0) {
      // Use a parameterized IN clause built from a placeholder list; never
      // interpolate user-supplied ids into the SQL string directly.
      const placeholders = policyIdFilter.map(() => '?').join(',');
      const sql = `SELECT id, title, policy_type, content, scenario_tags, version, uploaded_at
                   FROM ir_policies
                   WHERE deleted_at IS NULL
                     AND id IN (${placeholders})
                   ORDER BY uploaded_at DESC
                   LIMIT ?`;
      rows = db.prepare(sql).all(...policyIdFilter, MAX_POLICIES_IN_PROMPT);
    } else {
      rows = db.prepare(`
        SELECT id, title, policy_type, content, scenario_tags, version, uploaded_at
        FROM ir_policies
        WHERE deleted_at IS NULL
        ORDER BY uploaded_at DESC
        LIMIT ?
      `).all(MAX_POLICIES_IN_PROMPT);
    }
    return rows;
  } finally {
    db.close();
  }
}

function fetchRecentAars() {
  const db = getDb();
  try {
    return db.prepare(`
      SELECT id, title, content, incident_date, lessons_learned, uploaded_at
      FROM ooda_aars
      WHERE deleted_at IS NULL
      ORDER BY uploaded_at DESC
      LIMIT ?
    `).all(MAX_AARS_IN_PROMPT);
  } finally {
    db.close();
  }
}

// ── Prompt construction ─────────────────────────────────────────────────────

function buildPrompt({ scenarioType, difficulty, parsed, aars }) {
  const difficultyGuidance = {
    beginner: 'Use clear, well-signposted choices. Each wrong answer should have an obvious tell. Avoid red herrings. Target a SOC analyst in their first 6 months.',
    intermediate: 'Mix straightforward choices with two or three plausible-but-wrong options per node. Include at least one node where the analyst must reconcile conflicting signals. Target an analyst with 1-3 years of experience.',
    advanced: 'Include adversarial misdirection — at least one node where the most obvious response is wrong because it tips off the attacker. Require the analyst to reason about second-order effects. Target a senior analyst or threat hunter.',
  };

  const sections = [];

  sections.push('You are generating an OODA-loop incident response training scenario for SOC analysts.');
  sections.push('');
  sections.push(`SCENARIO TYPE: ${scenarioType}`);
  sections.push(`DIFFICULTY: ${difficulty}`);
  sections.push(`DIFFICULTY GUIDANCE: ${difficultyGuidance[difficulty]}`);
  sections.push('');

  // Policy context
  sections.push('=== UPLOADED IR POLICIES (use as ground truth for the correct response path) ===');
  if (parsed.metadata.policy_count === 0) {
    sections.push('(no policies provided — generate based on industry best practices)');
  } else {
    sections.push(`${parsed.metadata.policy_count} policy/policies provided. Key extracted structure:`);
    if (parsed.detection_signals.length > 0) {
      sections.push('');
      sections.push('Detection signals from policies:');
      for (const s of parsed.detection_signals.slice(0, 10)) sections.push(`- ${s}`);
    }
    if (parsed.decision_points.length > 0) {
      sections.push('');
      sections.push('Decision points from policies:');
      for (const dp of parsed.decision_points.slice(0, 10)) {
        sections.push(`- IF ${dp.condition} → ${dp.action}`);
      }
    }
    if (parsed.escalation_paths.length > 0) {
      sections.push('');
      sections.push('Escalation requirements from policies:');
      for (const e of parsed.escalation_paths.slice(0, 8)) sections.push(`- ${e}`);
    }
    if (parsed.roles.length > 0) {
      sections.push('');
      sections.push(`Defined roles: ${parsed.roles.slice(0, 12).join(', ')}`);
    }
    if (parsed.containment_actions.length > 0) {
      sections.push('');
      sections.push('Containment actions from policies:');
      for (const a of parsed.containment_actions.slice(0, 10)) sections.push(`- ${a}`);
    }
    if (parsed.communications.length > 0) {
      sections.push('');
      sections.push('Communications obligations:');
      for (const c of parsed.communications.slice(0, 6)) sections.push(`- ${c}`);
    }
  }
  sections.push('');

  // AAR context
  if (aars.length > 0) {
    sections.push('=== RECENT AFTER-ACTION REPORTS (use for realistic flavor and lessons learned) ===');
    for (const aar of aars) {
      sections.push(`---`);
      sections.push(`Title: ${aar.title}`);
      if (aar.incident_date) sections.push(`Date: ${aar.incident_date}`);
      if (aar.lessons_learned) {
        sections.push(`Lessons learned: ${truncate(aar.lessons_learned, 600)}`);
      }
    }
    sections.push('');
  }

  // Output schema
  sections.push('=== OUTPUT FORMAT ===');
  sections.push('Respond with ONE JSON object and nothing else. No prose before or after, no markdown fences. Schema:');
  sections.push('');
  sections.push('{');
  sections.push('  "title": "<short descriptive title>",');
  sections.push('  "briefing": "<2-4 sentence opening situation summary the analyst sees first>",');
  sections.push('  "nodes": [');
  sections.push('    {');
  sections.push('      "id": "<unique snake_case id, e.g. observe_1>",');
  sections.push('      "phase": "<one of: observe, orient, decide, act, resolution>",');
  sections.push('      "type": "<\'decision\' for choice nodes, \'resolution\' for the terminal node>",');
  sections.push('      "prompt": "<the scenario question or situation update shown to the analyst>",');
  sections.push('      "choices": [');
  sections.push('        {');
  sections.push('          "text": "<the choice as a button label>",');
  sections.push('          "correct": <true|false>,');
  sections.push('          "nextNodeId": "<id of the next node if correct, omit if wrong>",');
  sections.push('          "explanation": "<why this is right or wrong, 1-3 sentences>"');
  sections.push('        }');
  sections.push('      ],');
  sections.push('      "summary": "<resolution-only: full scenario summary tying back to OODA phases>"');
  sections.push('    }');
  sections.push('  ]');
  sections.push('}');
  sections.push('');
  sections.push('CONSTRAINTS:');
  sections.push(`- Between ${MIN_NODES_PER_SCENARIO} and ${MAX_NODES_PER_SCENARIO} nodes total, including the resolution node.`);
  sections.push('- The first node must be in the "observe" phase.');
  sections.push('- The flow must progress observe → orient → decide → act → resolution. You may have multiple nodes per phase but never skip phases.');
  sections.push('- Exactly one resolution node, with type "resolution", phase "resolution", an empty choices array, and a non-empty summary.');
  sections.push(`- Each decision node has 2-${MAX_CHOICES_PER_NODE} choices.`);
  sections.push('- Exactly one choice per decision node has correct=true. That choice has a nextNodeId pointing to a real node id in this scenario.');
  sections.push('- Wrong choices have correct=false, no nextNodeId, and an explanation that teaches why the choice is wrong (not just "wrong, try again").');
  sections.push('- All node ids referenced in nextNodeId must exist in the nodes array.');
  sections.push('- Ground the correct path in the uploaded policy context above. The wrong choices should be plausible but contradict the policy or violate IR best practices.');
  sections.push('');
  sections.push('Output the JSON now.');

  return sections.join('\n');
}

function truncate(str, max) {
  if (typeof str !== 'string') return '';
  return str.length <= max ? str : str.slice(0, max - 3) + '...';
}

// ── Output parsing + validation ─────────────────────────────────────────────

function parseTreeOutput(rawText) {
  if (typeof rawText !== 'string' || rawText.trim().length === 0) {
    throw new Error('empty model output');
  }

  // Strip markdown code fences if the model emitted them despite the prompt
  // instruction. Match ```json ... ``` or just ``` ... ```.
  let text = rawText.trim();
  const fenceMatch = text.match(/^```(?:json)?\s*\n?([\s\S]*?)\n?```\s*$/i);
  if (fenceMatch) text = fenceMatch[1].trim();

  // Some models prepend "Here is the scenario:" — try to find the first
  // opening brace and parse from there.
  const firstBrace = text.indexOf('{');
  if (firstBrace > 0) text = text.slice(firstBrace);

  // Try to find the matching closing brace if there's trailing prose.
  const lastBrace = text.lastIndexOf('}');
  if (lastBrace !== -1 && lastBrace < text.length - 1) text = text.slice(0, lastBrace + 1);

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error('JSON parse failed: ' + err.message);
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('parsed value is not an object');
  }

  return parsed;
}

function validateTree(tree, { scenarioType, difficulty }) {
  if (!tree.title || typeof tree.title !== 'string') {
    throw new Error('missing or invalid title');
  }
  if (!tree.briefing || typeof tree.briefing !== 'string') {
    throw new Error('missing or invalid briefing');
  }
  if (!Array.isArray(tree.nodes)) {
    throw new Error('nodes must be an array');
  }
  if (tree.nodes.length < MIN_NODES_PER_SCENARIO) {
    throw new Error(`too few nodes (${tree.nodes.length} < ${MIN_NODES_PER_SCENARIO})`);
  }
  if (tree.nodes.length > MAX_NODES_PER_SCENARIO) {
    throw new Error(`too many nodes (${tree.nodes.length} > ${MAX_NODES_PER_SCENARIO})`);
  }

  const ids = new Set();
  let resolutionCount = 0;
  let firstNodePhase = null;

  for (let i = 0; i < tree.nodes.length; i++) {
    const node = tree.nodes[i];
    if (!node || typeof node !== 'object') {
      throw new Error(`node ${i} is not an object`);
    }
    if (!node.id || typeof node.id !== 'string') {
      throw new Error(`node ${i} missing id`);
    }
    if (ids.has(node.id)) {
      throw new Error(`duplicate node id: ${node.id}`);
    }
    ids.add(node.id);
    if (i === 0) firstNodePhase = node.phase;

    if (!VALID_PHASES.includes(node.phase)) {
      throw new Error(`node ${node.id}: invalid phase "${node.phase}"`);
    }
    if (!node.prompt || typeof node.prompt !== 'string') {
      throw new Error(`node ${node.id}: missing prompt`);
    }
    if (node.type === 'resolution' || node.phase === 'resolution') {
      resolutionCount++;
      if (!node.summary || typeof node.summary !== 'string') {
        throw new Error(`resolution node ${node.id}: missing summary`);
      }
      if (!Array.isArray(node.choices) || node.choices.length !== 0) {
        throw new Error(`resolution node ${node.id}: choices must be empty array`);
      }
      continue;
    }

    // Decision node
    if (!Array.isArray(node.choices) || node.choices.length < 2) {
      throw new Error(`node ${node.id}: decision nodes must have at least 2 choices`);
    }
    if (node.choices.length > MAX_CHOICES_PER_NODE) {
      throw new Error(`node ${node.id}: too many choices (${node.choices.length})`);
    }

    // Per-choice shape validation
    for (let j = 0; j < node.choices.length; j++) {
      const choice = node.choices[j];
      if (!choice || typeof choice !== 'object') {
        throw new Error(`node ${node.id} choice ${j}: not an object`);
      }
      if (!choice.text || typeof choice.text !== 'string') {
        throw new Error(`node ${node.id} choice ${j}: missing text`);
      }
      if (typeof choice.correct !== 'boolean') {
        throw new Error(`node ${node.id} choice ${j}: correct must be boolean`);
      }
      if (!choice.explanation || typeof choice.explanation !== 'string') {
        throw new Error(`node ${node.id} choice ${j}: missing explanation`);
      }
    }

    // Exactly-one-correct check (run after per-choice shape so error messages
    // are diagnostic in order: shape errors first, then semantic errors)
    const correctChoices = node.choices.filter(c => c.correct);
    if (correctChoices.length !== 1) {
      throw new Error(`node ${node.id}: must have exactly 1 correct choice (found ${correctChoices.length})`);
    }
    if (!correctChoices[0].nextNodeId || typeof correctChoices[0].nextNodeId !== 'string') {
      throw new Error(`node ${node.id}: correct choice missing nextNodeId`);
    }
  }

  if (firstNodePhase !== 'observe') {
    throw new Error(`first node phase must be "observe", got "${firstNodePhase}"`);
  }
  if (resolutionCount !== 1) {
    throw new Error(`must have exactly 1 resolution node (found ${resolutionCount})`);
  }

  // Verify all nextNodeId references resolve to real nodes
  for (const node of tree.nodes) {
    if (!Array.isArray(node.choices)) continue;
    for (const choice of node.choices) {
      if (choice.correct && choice.nextNodeId && !ids.has(choice.nextNodeId)) {
        throw new Error(`node ${node.id}: nextNodeId "${choice.nextNodeId}" does not match any node`);
      }
    }
  }

  // Annotate validated metadata onto the tree for downstream consumers
  tree.scenarioType = scenarioType;
  tree.difficulty = difficulty;
  tree.nodeCount = tree.nodes.length;
}

// ── Errors ──────────────────────────────────────────────────────────────────

function scenarioError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

module.exports = {
  generateScenario,
  // Exported for unit testing of internal parsing logic
  _internal: {
    parseTreeOutput,
    validateTree,
    buildPrompt,
    VALID_TYPES,
    VALID_DIFFICULTIES,
    VALID_PHASES,
  },
};

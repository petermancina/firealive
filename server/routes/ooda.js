// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — OODA Loop Incident Response Simulator
// Management Console: upload IR policies, playbooks, after-action reports
// Analyst Client: AI-generated choose-your-own-adventure IR exercises
//
// POST /api/ooda/policies           — upload policy/playbook (lead)
// GET  /api/ooda/policies           — list uploaded policies
// DELETE /api/ooda/policies/:id     — remove policy
// POST /api/ooda/aar               — upload after-action report
// GET  /api/ooda/aar               — list AARs
// POST /api/ooda/generate           — generate a scenario from policies+AARs
// GET  /api/ooda/scenarios          — list available scenarios
// GET  /api/ooda/scenarios/:id      — get full scenario with decision tree
// POST /api/ooda/scenarios/:id/play — submit a choice, get next node
// GET  /api/ooda/history            — analyst's exercise completion history
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { generateScenario } = require('../services/ooda-scenario-generator');

const MAX_POLICY_SIZE = 500000; // 500KB text max
const MAX_AAR_LESSONS_SIZE = 5000;
const OODA_PHASES = ['observe', 'orient', 'decide', 'act'];

// Map error codes from the scenario generator + dispatcher to HTTP status
// codes. Defined once so commit 5's play/history endpoints can reuse it
// when they also start surfacing generator-side errors (e.g. on regenerate).
function statusForGeneratorError(err) {
  if (!err || !err.code) return 500;
  switch (err.code) {
    case 'SCENARIO_INVALID_PARAMS': return 400;
    case 'SCENARIO_NO_POLICIES': return 400;
    case 'SCENARIO_INVALID_OUTPUT': return 502;
    case 'AI_NOT_CONFIGURED': return 503;
    case 'AI_TIMEOUT': return 504;
    case 'AI_RATE_LIMITED': return 429;
    case 'AI_INTERNAL_UNAVAILABLE': return 503;
    case 'AI_INTERNAL_INVALID_MODEL_PATH': return 500;
    default: return 500;
  }
}

// ── Upload Policy/Playbook ───────────────────────────────────────────────────
router.post('/policies', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can upload policies' });

  const { title, content, type, scenarioTags } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'title and content required' });
  if (content.length > MAX_POLICY_SIZE) return res.status(400).json({ error: `Content too large (max ${MAX_POLICY_SIZE / 1000}KB)` });

  const validTypes = ['incident_response', 'playbook', 'runbook', 'policy', 'procedure'];
  const safeType = validTypes.includes(type) ? type : 'policy';
  const safeTitle = title.slice(0, 256);
  const safeContent = content.slice(0, MAX_POLICY_SIZE);
  const tags = Array.isArray(scenarioTags) ? scenarioTags.filter(t => typeof t === 'string').slice(0, 20) : [];
  const contentHash = crypto.createHash('sha256').update(safeContent).digest('hex');

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO ir_policies (id, title, policy_type, content, content_hash, scenario_tags, version, uploaded_by, uploaded_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    `).run(id, safeTitle, safeType, safeContent, contentHash, JSON.stringify(tags), req.user.id, now, now);
    db.close();
    auditLog(req.user.id, 'OODA_POLICY_UPLOADED', `"${safeTitle}" (${safeType})`, req.ip);
    res.status(201).json({ id, title: safeTitle, type: safeType, scenarioTags: tags });
  } catch (err) {
    logger.error('Upload policy error', { error: err.message });
    res.status(500).json({ error: 'Failed to upload policy' });
  }
});

router.get('/policies', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT id, title, policy_type AS type, scenario_tags, version, uploaded_by, uploaded_at, updated_at
      FROM ir_policies
      WHERE deleted_at IS NULL
      ORDER BY uploaded_at DESC
    `).all();
    db.close();
    const policies = rows.map(r => ({
      id: r.id,
      title: r.title,
      type: r.type,
      scenarioTags: (() => { try { return JSON.parse(r.scenario_tags); } catch { return []; } })(),
      version: r.version,
      uploadedBy: r.uploaded_by,
      uploadedAt: r.uploaded_at,
      updatedAt: r.updated_at,
    }));
    res.json({ policies });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list policies' });
  }
});

router.delete('/policies/:id', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can remove policies' });
  try {
    const db = getDb();
    // Soft delete: preserve the row so historical runbooks can still
    // reference the policy version they were generated from.
    const result = db.prepare("UPDATE ir_policies SET deleted_at = datetime('now') WHERE id = ? AND deleted_at IS NULL").run(req.params.id);
    db.close();
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Policy not found or already deleted' });
    }
    auditLog(req.user.id, 'OODA_POLICY_REMOVED', req.params.id, req.ip);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to remove policy' });
  }
});

// ── Upload After-Action Report ───────────────────────────────────────────────
router.post('/aar', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can upload AARs' });

  const { title, content, incidentDate, lessonsLearned } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'title and content required' });

  const safeTitle = title.slice(0, 256);
  const safeContent = content.slice(0, MAX_POLICY_SIZE);
  const safeLessons = typeof lessonsLearned === 'string' ? lessonsLearned.slice(0, MAX_AAR_LESSONS_SIZE) : null;
  const safeIncidentDate = typeof incidentDate === 'string' ? incidentDate.slice(0, 32) : null;

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    db.prepare(`
      INSERT INTO ooda_aars (id, title, content, incident_date, lessons_learned, uploaded_by, uploaded_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(id, safeTitle, safeContent, safeIncidentDate, safeLessons, req.user.id);
    db.close();
    auditLog(req.user.id, 'OODA_AAR_UPLOADED', `"${safeTitle}"`, req.ip);
    res.status(201).json({ id, title: safeTitle });
  } catch (err) {
    logger.error('Upload AAR error', { error: err.message });
    res.status(500).json({ error: 'Failed to upload AAR' });
  }
});

router.get('/aar', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT id, title, incident_date, uploaded_at
      FROM ooda_aars
      WHERE deleted_at IS NULL
      ORDER BY uploaded_at DESC
    `).all();
    db.close();
    const aars = rows.map(r => ({
      id: r.id,
      title: r.title,
      incidentDate: r.incident_date,
      uploadedAt: r.uploaded_at,
    }));
    res.json({ aars });
  } catch (err) {
    logger.error('List AAR error', { error: err.message });
    res.status(500).json({ error: 'Failed to list AARs' });
  }
});

// ── Generate Scenario ────────────────────────────────────────────────────────
// Calls the OODA scenario generator service, which loads ir_policies + ooda_aars,
// builds a structured prompt, dispatches through the AI provider (internal local
// LLM by default; per-feature override configurable via the MC AI/ML
// Integrations tab), validates the model output, and returns a tree.
// We persist the validated tree to the ooda_scenarios canonical table.
router.post('/generate', async (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can generate scenarios' });

  const { scenarioType, difficulty, policyIds } = req.body || {};

  let result;
  try {
    result = await generateScenario({
      scenarioType,
      difficulty,
      policyIds: Array.isArray(policyIds) ? policyIds : null,
      userId: req.user.id,
    });
  } catch (err) {
    const status = statusForGeneratorError(err);
    logger.warn('Generate scenario error', {
      scenarioType, difficulty,
      code: err && err.code,
      message: err && err.message,
      status,
    });
    return res.status(status).json({
      error: err && err.message ? err.message : 'Failed to generate scenario',
      code: err && err.code ? err.code : 'UNKNOWN',
    });
  }

  // Persist the validated tree to ooda_scenarios. The full tree (nodes,
  // choices, explanations) is stored in the `tree` column verbatim;
  // scalar fields are denormalized for indexed listing.
  const id = crypto.randomBytes(16).toString('hex');
  const treeJson = JSON.stringify(result.tree);
  const sourcePolicyIdsJson = JSON.stringify(result.sourcePolicyIds || []);
  const generatedByProvider = result.modelName ? `${result.provider}/${result.modelName}` : result.provider;

  try {
    const db = getDb();
    db.prepare(`
      INSERT INTO ooda_scenarios (id, title, scenario_type, difficulty, tree, node_count, generated_by_provider, source_policy_ids, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      id,
      result.tree.title,
      result.tree.scenarioType,
      result.tree.difficulty,
      treeJson,
      result.tree.nodeCount,
      generatedByProvider,
      sourcePolicyIdsJson,
      req.user.id
    );
    db.close();
  } catch (dbErr) {
    logger.error('Persist scenario error', { error: dbErr.message });
    return res.status(500).json({ error: 'Generated scenario but failed to persist it' });
  }

  auditLog(
    req.user.id,
    'OODA_SCENARIO_GENERATED',
    `type=${result.tree.scenarioType} difficulty=${result.tree.difficulty} nodes=${result.tree.nodeCount} provider=${generatedByProvider} latency_ms=${result.latencyMs}`,
    req.ip
  );

  res.status(201).json({
    id,
    title: result.tree.title,
    type: result.tree.scenarioType,
    difficulty: result.tree.difficulty,
    nodeCount: result.tree.nodeCount,
    sourcePolicyIds: result.sourcePolicyIds,
    provider: result.provider,
    modelName: result.modelName,
    latencyMs: result.latencyMs,
  });
});

// ── List Scenarios ───────────────────────────────────────────────────────────
router.get('/scenarios', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT id, title, scenario_type, difficulty, node_count, generated_by_provider, created_at
      FROM ooda_scenarios
      WHERE archived_at IS NULL
      ORDER BY created_at DESC
    `).all();
    db.close();
    const scenarios = rows.map(r => ({
      id: r.id,
      title: r.title,
      type: r.scenario_type,
      difficulty: r.difficulty,
      nodeCount: r.node_count,
      generatedByProvider: r.generated_by_provider,
      createdAt: r.created_at,
    }));
    res.json({ scenarios });
  } catch (err) {
    logger.error('List scenarios error', { error: err.message });
    res.status(500).json({ error: 'Failed to list scenarios' });
  }
});

// ── Get Scenario (start node only) ────────────────────────────────────────────
// The analyst progresses node-by-node via POST /scenarios/:id/play; we never
// return the entire tree (with answer keys) to a client.
router.get('/scenarios/:id', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare(`
      SELECT id, title, scenario_type, difficulty, tree, node_count
      FROM ooda_scenarios
      WHERE id = ? AND archived_at IS NULL
    `).get(req.params.id);
    db.close();
    if (!row) return res.status(404).json({ error: 'Scenario not found' });

    let tree;
    try {
      tree = JSON.parse(row.tree);
    } catch (parseErr) {
      logger.error('Scenario tree parse error', { id: req.params.id, error: parseErr.message });
      return res.status(500).json({ error: 'Scenario data is corrupted' });
    }
    if (!Array.isArray(tree.nodes) || tree.nodes.length === 0) {
      return res.status(500).json({ error: 'Scenario has no nodes' });
    }

    res.json({
      id: row.id,
      title: row.title,
      type: row.scenario_type,
      difficulty: row.difficulty,
      briefing: tree.briefing,
      startNode: tree.nodes[0],
      totalNodes: row.node_count,
    });
  } catch (err) {
    logger.error('Get scenario error', { error: err.message });
    res.status(500).json({ error: 'Failed to get scenario' });
  }
});

// ── Play — Submit Choice ─────────────────────────────────────────────────────
router.post('/scenarios/:id/play', (req, res) => {
  const { currentNodeId, choiceIndex } = req.body;
  if (currentNodeId === undefined || choiceIndex === undefined) return res.status(400).json({ error: 'currentNodeId and choiceIndex required' });

  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`ooda_scenario_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Scenario not found' }); }

    const scenario = JSON.parse(row.value);
    const node = scenario.nodes.find(n => n.id === currentNodeId);
    if (!node) { db.close(); return res.status(404).json({ error: 'Node not found' }); }

    const choice = node.choices?.[choiceIndex];
    if (!choice) { db.close(); return res.status(400).json({ error: 'Invalid choice index' }); }

    if (!choice.correct) {
      db.close();
      return res.json({
        correct: false,
        explanation: choice.explanation,
        message: 'That choice would lead to further damage. Review the explanation and try again.',
        currentNode: node, // stay on same node
      });
    }

    // Correct choice — advance to next node
    const nextNode = scenario.nodes.find(n => n.id === choice.nextNodeId);

    // Track progress
    const progressKey = `ooda_progress_${req.user.id}_${req.params.id}`;
    const existing = db.prepare("SELECT value FROM team_config WHERE key = ?").get(progressKey);
    const progress = existing ? JSON.parse(existing.value) : { nodesCompleted: [], startedAt: new Date().toISOString() };
    if (!progress.nodesCompleted.includes(currentNodeId)) progress.nodesCompleted.push(currentNodeId);

    const isComplete = !nextNode || nextNode.type === 'resolution';
    if (isComplete) progress.completedAt = new Date().toISOString();

    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(progressKey, JSON.stringify(progress), req.user.id);
    db.close();

    if (isComplete) {
      auditLog(req.user.id, 'OODA_SCENARIO_COMPLETED', `scenario=${req.params.id} nodes=${progress.nodesCompleted.length}`, req.ip);
    }

    res.json({
      correct: true,
      explanation: choice.explanation,
      nextNode: nextNode || null,
      complete: isComplete,
      progress: { completed: progress.nodesCompleted.length, total: scenario.nodes.length },
    });
  } catch (err) {
    logger.error('Play scenario error', { error: err.message });
    res.status(500).json({ error: 'Failed to process choice' });
  }
});

// ── Exercise History ─────────────────────────────────────────────────────────
router.get('/history', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare("SELECT key, value FROM team_config WHERE key LIKE ?").all(`ooda_progress_${req.user.id}_%`);
    db.close();
    const history = rows.map(r => {
      try {
        const d = JSON.parse(r.value);
        const scenarioId = r.key.replace(`ooda_progress_${req.user.id}_`, '');
        return { scenarioId, nodesCompleted: d.nodesCompleted.length, startedAt: d.startedAt, completedAt: d.completedAt || null };
      } catch { return null; }
    }).filter(Boolean);
    res.json({ history });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get history' });
  }
});

module.exports = router;

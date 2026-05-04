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
const { sanitize, SANITIZER_VERSION } = require('../services/content-sanitizer');
const { IntegrationManager, INSPECTOR_VERSION } = require('../services/integration-manager');

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

// ── Two-layer upload scan ────────────────────────────────────────────────────
//
// Runs the layer-1 content sanitizer first (catches FireAlive-domain threats:
// prompt injection, embedded executables, encoding attacks). If clean, runs
// the layer-2 EDR inspector (catches malware signatures and threat-intel
// matches via the deploying organization's EDR integration). Either layer's
// rejection blocks the upload — fail-closed.
//
// If layer 2 (EDR) is not configured, it returns {skipped: true, clean: true}.
// That is NOT a green light by itself — it means "this layer has nothing to
// add." The layer-1 sanitizer must still have passed. Per the security model
// established in commits 6a and 6b, an unscanned upload is never allowed to
// land: layer 1 runs always, layer 2 runs when configured, and the deploying
// organization is encouraged (in docs and in the MC) to configure EDR for
// defense in depth.
//
// Returns: {
//   ok: bool,                  true only if both layers cleared
//   layer1: {clean, threats, scanId, sanitizerVersion},
//   layer2: {clean, skipped, threats, scanId, provider, latencyMs,
//            error?, inspectorVersion},
//   rejectedBy: 'layer1' | 'layer2' | null,
// }
async function runUploadScans(content, fileName, fileType) {
  // Layer 1 — sanitizer (sync, deterministic, network-free)
  const layer1 = sanitize(content, { fileName, fileType });
  if (!layer1.clean) {
    return { ok: false, layer1, layer2: null, rejectedBy: 'layer1' };
  }

  // Layer 2 — EDR (async; only runs if layer 1 cleared). The IntegrationManager
  // is instantiated per upload because it caches a db handle in this.db; we
  // open one, run the inspection, close it.
  const db = getDb();
  let layer2;
  try {
    const mgr = new IntegrationManager(db);
    layer2 = await mgr.inspectFile(content, fileName, fileType);
  } finally {
    db.close();
  }
  if (!layer2.clean) {
    return { ok: false, layer1, layer2, rejectedBy: 'layer2' };
  }
  return { ok: true, layer1, layer2, rejectedBy: null };
}

// Build the per-upload audit-log fragment that records both scan layers.
// Used in the OODA_POLICY_UPLOADED and OODA_AAR_UPLOADED detail strings.
function scanAuditFragment(scans) {
  const parts = [
    `sanitizer=${scans.layer1.sanitizerVersion}/${scans.layer1.scanId}`,
  ];
  if (scans.layer2 && scans.layer2.skipped) {
    parts.push('edr=skipped');
  } else if (scans.layer2) {
    parts.push(
      `edr=${scans.layer2.provider}/${scans.layer2.scanId || 'no-id'}`
        + ` (${scans.layer2.latencyMs}ms)`
    );
  }
  return parts.join(' ');
}

// ── Upload Policy/Playbook ───────────────────────────────────────────────────
// Two-layer scan gate: content-sanitizer (layer 1, FireAlive-domain threats)
// and EDR inspector (layer 2, malware signatures via configured EDR). Either
// layer's rejection blocks the upload. Both scans are logged to the audit
// trail regardless of outcome.
router.post('/policies', async (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can upload policies' });

  const { title, content, type, scenarioTags } = req.body || {};
  if (!title || !content) return res.status(400).json({ error: 'title and content required' });
  if (typeof content !== 'string') return res.status(400).json({ error: 'content must be a string' });
  if (content.length > MAX_POLICY_SIZE) return res.status(400).json({ error: `Content too large (max ${MAX_POLICY_SIZE / 1000}KB)` });

  const validTypes = ['incident_response', 'playbook', 'runbook', 'policy', 'procedure'];
  const safeType = validTypes.includes(type) ? type : 'policy';
  const safeTitle = String(title).slice(0, 256);
  const safeContent = content.slice(0, MAX_POLICY_SIZE);
  const tags = Array.isArray(scenarioTags) ? scenarioTags.filter(t => typeof t === 'string').slice(0, 20) : [];
  const contentHash = crypto.createHash('sha256').update(safeContent).digest('hex');

  // Two-layer scan. Both layers run before any database write.
  let scans;
  try {
    scans = await runUploadScans(safeContent, safeTitle + '.policy', 'text/plain');
  } catch (scanErr) {
    logger.error('Policy upload scan error', { error: scanErr.message });
    return res.status(500).json({ error: 'Upload scan failed', code: 'SCAN_INFRASTRUCTURE_ERROR' });
  }

  // Phase F4c: IR Simulator uploads require an active malware scanner.
  // runUploadScans returns layer2.skipped=true when no scanner is
  // configured (the org hasn't set up any of the 15 supported vendors via
  // MC > Malware Scanners). For the IR Simulator paths specifically, this
  // is treated as a hard gate — the LLM context that scenarios get
  // generated from MUST have been malware-scanned end-to-end. Other
  // upload paths in the codebase may still tolerate skipped EDR (their
  // risk profile is different); this gate is local to /policies and /aar.
  //
  // Rejection happens BEFORE the !scans.ok check below because skipped
  // produces ok=true (layer2.clean is true when it didn't run). Without
  // this explicit gate, the upload would proceed.
  if (scans.layer2 && scans.layer2.skipped === true) {
    auditLog(
      req.user.id,
      'OODA_POLICY_UPLOAD_REJECTED',
      `"${safeTitle}" rejected_by=malware_scanner_required (no scanner configured)`,
      req.ip
    );
    return res.status(422).json({
      error: 'IR policy uploads require a configured malware scanner. Configure at least one scanner under MC > Malware Scanners and try again.',
      code: 'MALWARE_SCANNER_REQUIRED',
    });
  }

  if (!scans.ok) {
    auditLog(
      req.user.id,
      'OODA_POLICY_UPLOAD_REJECTED',
      `"${safeTitle}" rejected_by=${scans.rejectedBy} ${scanAuditFragment(scans)}`,
      req.ip
    );
    if (scans.rejectedBy === 'layer1') {
      return res.status(422).json({
        error: 'Content rejected by safety scan',
        code: 'CONTENT_REJECTED_SANITIZER',
        threats: scans.layer1.threats,
        scanId: scans.layer1.scanId,
      });
    }
    // layer 2
    return res.status(422).json({
      error: scans.layer2.error
        ? 'EDR scan failed (configured but unreachable or returned an error)'
        : 'Content rejected by EDR scan',
      code: scans.layer2.error ? 'EDR_SCAN_UNAVAILABLE' : 'CONTENT_REJECTED_EDR',
      threats: scans.layer2.threats,
      scanId: scans.layer2.scanId,
      provider: scans.layer2.provider,
    });
  }

  // Both layers passed — persist and audit.
  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO ir_policies (id, title, policy_type, content, content_hash, scenario_tags, version, uploaded_by, uploaded_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    `).run(id, safeTitle, safeType, safeContent, contentHash, JSON.stringify(tags), req.user.id, now, now);
    db.close();
    auditLog(
      req.user.id,
      'OODA_POLICY_UPLOADED',
      `"${safeTitle}" (${safeType}) ${scanAuditFragment(scans)}`,
      req.ip
    );
    res.status(201).json({ id, title: safeTitle, type: safeType, scanId: scans.layer1.scanId, scenarioTags: tags });
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
// Same two-layer scan gate as POST /policies. AAR content is also LLM-prompt
// input (commit 3's ooda-scenario-generator includes recent AARs in its
// scenario-generation prompt) so the prompt-injection defense applies here
// equally.
router.post('/aar', async (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can upload AARs' });

  const { title, content, incidentDate, lessonsLearned } = req.body || {};
  if (!title || !content) return res.status(400).json({ error: 'title and content required' });
  if (typeof content !== 'string') return res.status(400).json({ error: 'content must be a string' });
  if (content.length > MAX_POLICY_SIZE) return res.status(400).json({ error: `Content too large (max ${MAX_POLICY_SIZE / 1000}KB)` });

  const safeTitle = String(title).slice(0, 256);
  const safeContent = content.slice(0, MAX_POLICY_SIZE);
  const safeLessons = typeof lessonsLearned === 'string' ? lessonsLearned.slice(0, MAX_AAR_LESSONS_SIZE) : null;
  const safeIncidentDate = typeof incidentDate === 'string' ? incidentDate.slice(0, 32) : null;

  // The lessons_learned field is also LLM input, so scan it too if present.
  // We scan content + lessons together as one combined blob — they're
  // serialized into the same prompt anyway, and a separate scan for lessons
  // would duplicate audit log entries unnecessarily.
  const combinedForScan = safeLessons ? `${safeContent}\n\n--- LESSONS LEARNED ---\n${safeLessons}` : safeContent;

  let scans;
  try {
    scans = await runUploadScans(combinedForScan, safeTitle + '.aar', 'text/plain');
  } catch (scanErr) {
    logger.error('AAR upload scan error', { error: scanErr.message });
    return res.status(500).json({ error: 'Upload scan failed', code: 'SCAN_INFRASTRUCTURE_ERROR' });
  }

  // Phase F4c: same hard gate as POST /policies — IR Simulator AAR uploads
  // require an active malware scanner. See the comment block at the
  // matching location in POST /policies for full rationale. Identical
  // behavior applies here: layer2.skipped=true means no scanner is
  // configured; reject with 422 MALWARE_SCANNER_REQUIRED before the
  // !scans.ok check (since skipped produces ok=true).
  if (scans.layer2 && scans.layer2.skipped === true) {
    auditLog(
      req.user.id,
      'OODA_AAR_UPLOAD_REJECTED',
      `"${safeTitle}" rejected_by=malware_scanner_required (no scanner configured)`,
      req.ip
    );
    return res.status(422).json({
      error: 'AAR uploads require a configured malware scanner. Configure at least one scanner under MC > Malware Scanners and try again.',
      code: 'MALWARE_SCANNER_REQUIRED',
    });
  }

  if (!scans.ok) {
    auditLog(
      req.user.id,
      'OODA_AAR_UPLOAD_REJECTED',
      `"${safeTitle}" rejected_by=${scans.rejectedBy} ${scanAuditFragment(scans)}`,
      req.ip
    );
    if (scans.rejectedBy === 'layer1') {
      return res.status(422).json({
        error: 'Content rejected by safety scan',
        code: 'CONTENT_REJECTED_SANITIZER',
        threats: scans.layer1.threats,
        scanId: scans.layer1.scanId,
      });
    }
    return res.status(422).json({
      error: scans.layer2.error
        ? 'EDR scan failed (configured but unreachable or returned an error)'
        : 'Content rejected by EDR scan',
      code: scans.layer2.error ? 'EDR_SCAN_UNAVAILABLE' : 'CONTENT_REJECTED_EDR',
      threats: scans.layer2.threats,
      scanId: scans.layer2.scanId,
      provider: scans.layer2.provider,
    });
  }

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    db.prepare(`
      INSERT INTO ooda_aars (id, title, content, incident_date, lessons_learned, uploaded_by, uploaded_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(id, safeTitle, safeContent, safeIncidentDate, safeLessons, req.user.id);
    db.close();
    auditLog(
      req.user.id,
      'OODA_AAR_UPLOADED',
      `"${safeTitle}" ${scanAuditFragment(scans)}`,
      req.ip
    );
    res.status(201).json({ id, title: safeTitle, scanId: scans.layer1.scanId });
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
// Reads the scenario tree from ooda_scenarios.tree (the canonical table from
// commit 1's schema) and writes per-analyst progress into ooda_progress
// (composite PK on user_id + scenario_id, INSERT OR REPLACE on each correct
// step). Wrong choices keep the analyst on the same node and don't write
// progress — the explanation is the teaching moment.
router.post('/scenarios/:id/play', (req, res) => {
  const { currentNodeId, choiceIndex } = req.body || {};
  if (currentNodeId === undefined || choiceIndex === undefined) {
    return res.status(400).json({ error: 'currentNodeId and choiceIndex required' });
  }

  try {
    const db = getDb();
    const row = db.prepare(`
      SELECT id, tree, node_count
      FROM ooda_scenarios
      WHERE id = ? AND archived_at IS NULL
    `).get(req.params.id);
    if (!row) { db.close(); return res.status(404).json({ error: 'Scenario not found' }); }

    let tree;
    try {
      tree = JSON.parse(row.tree);
    } catch (parseErr) {
      db.close();
      logger.error('Scenario tree parse error', { id: req.params.id, error: parseErr.message });
      return res.status(500).json({ error: 'Scenario data is corrupted' });
    }
    if (!Array.isArray(tree.nodes)) {
      db.close();
      return res.status(500).json({ error: 'Scenario has no nodes' });
    }

    const node = tree.nodes.find(n => n.id === currentNodeId);
    if (!node) { db.close(); return res.status(404).json({ error: 'Node not found' }); }

    const choice = Array.isArray(node.choices) ? node.choices[choiceIndex] : null;
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
    const nextNode = choice.nextNodeId ? tree.nodes.find(n => n.id === choice.nextNodeId) : null;

    // Track progress in ooda_progress.
    // Composite PK is (user_id, scenario_id), so INSERT OR REPLACE updates
    // the existing row in place when the analyst progresses to a new node.
    const existing = db.prepare(`
      SELECT nodes_completed, started_at, completed_at
      FROM ooda_progress
      WHERE user_id = ? AND scenario_id = ?
    `).get(req.user.id, req.params.id);

    let nodesCompleted;
    let startedAt;
    if (existing) {
      try {
        nodesCompleted = JSON.parse(existing.nodes_completed);
        if (!Array.isArray(nodesCompleted)) nodesCompleted = [];
      } catch { nodesCompleted = []; }
      startedAt = existing.started_at;
    } else {
      nodesCompleted = [];
      startedAt = new Date().toISOString();
    }
    if (!nodesCompleted.includes(currentNodeId)) nodesCompleted.push(currentNodeId);

    const isComplete = !nextNode || nextNode.type === 'resolution' || nextNode.phase === 'resolution';
    const completedAt = isComplete ? new Date().toISOString() : null;

    db.prepare(`
      INSERT OR REPLACE INTO ooda_progress (user_id, scenario_id, nodes_completed, started_at, completed_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(req.user.id, req.params.id, JSON.stringify(nodesCompleted), startedAt, completedAt);

    db.close();

    if (isComplete) {
      auditLog(
        req.user.id,
        'OODA_SCENARIO_COMPLETED',
        `scenario=${req.params.id} nodes=${nodesCompleted.length} duration_ms=${new Date(completedAt) - new Date(startedAt)}`,
        req.ip
      );
    }

    res.json({
      correct: true,
      explanation: choice.explanation,
      nextNode: nextNode || null,
      complete: isComplete,
      progress: { completed: nodesCompleted.length, total: row.node_count },
    });
  } catch (err) {
    logger.error('Play scenario error', { error: err.message });
    res.status(500).json({ error: 'Failed to process choice' });
  }
});

// ── Exercise History ─────────────────────────────────────────────────────────
// Returns the calling analyst's run history across all scenarios. Joins
// ooda_progress (the analyst-keyed progress rows) with ooda_scenarios to
// get titles/types/totals, so the response is a single ready-to-render list.
router.get('/history', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT
        p.scenario_id    AS scenarioId,
        p.nodes_completed AS nodesCompletedJson,
        p.started_at     AS startedAt,
        p.completed_at   AS completedAt,
        s.title          AS title,
        s.scenario_type  AS type,
        s.difficulty     AS difficulty,
        s.node_count     AS totalNodes
      FROM ooda_progress p
      LEFT JOIN ooda_scenarios s ON s.id = p.scenario_id AND s.archived_at IS NULL
      WHERE p.user_id = ?
      ORDER BY COALESCE(p.completed_at, p.started_at) DESC
    `).all(req.user.id);
    db.close();

    const history = rows.map(r => {
      let nodesCompletedCount = 0;
      try {
        const arr = JSON.parse(r.nodesCompletedJson);
        if (Array.isArray(arr)) nodesCompletedCount = arr.length;
      } catch { /* malformed JSON — count as 0 */ }
      return {
        scenarioId: r.scenarioId,
        title: r.title,             // null if scenario was archived/deleted
        type: r.type,
        difficulty: r.difficulty,
        nodesCompleted: nodesCompletedCount,
        totalNodes: r.totalNodes,
        startedAt: r.startedAt,
        completedAt: r.completedAt,
      };
    });
    res.json({ history });
  } catch (err) {
    logger.error('History error', { error: err.message });
    res.status(500).json({ error: 'Failed to get history' });
  }
});

// ── Mastery (per-analyst aggregation) ─────────────────────────────────────────
// Returns aggregated training metrics for the calling analyst, broken down
// by scenario type and difficulty. Used by the IR Simulator dashboard's
// progress view to show which areas the analyst is strong in vs. needs more
// practice. Read-only; never writes to the DB.
//
// Response shape:
//   {
//     overall: { startedCount, completedCount, completionRate, avgDurationMs },
//     byType: [ { type, started, completed, completionRate }, ... ],
//     byDifficulty: [ { difficulty, started, completed, completionRate }, ... ],
//     recentCompletions: [ { scenarioId, title, type, difficulty, completedAt }, ... ],
//   }
router.get('/mastery', (req, res) => {
  try {
    const db = getDb();
    // Overall counts. Single round-trip for both started and completed
    // and the average duration (only across completed scenarios).
    const overallRow = db.prepare(`
      SELECT
        COUNT(*) AS started,
        SUM(CASE WHEN completed_at IS NOT NULL THEN 1 ELSE 0 END) AS completed,
        AVG(CASE
          WHEN completed_at IS NOT NULL
            THEN (strftime('%s', completed_at) - strftime('%s', started_at)) * 1000
          ELSE NULL
        END) AS avg_duration_ms
      FROM ooda_progress
      WHERE user_id = ?
    `).get(req.user.id);

    // Per-scenario-type completion rate. Inner join — a progress row whose
    // scenario was archived is excluded from the type breakdown (still
    // counted in the overall numbers above).
    const byTypeRows = db.prepare(`
      SELECT
        s.scenario_type AS type,
        COUNT(*) AS started,
        SUM(CASE WHEN p.completed_at IS NOT NULL THEN 1 ELSE 0 END) AS completed
      FROM ooda_progress p
      JOIN ooda_scenarios s ON s.id = p.scenario_id AND s.archived_at IS NULL
      WHERE p.user_id = ?
      GROUP BY s.scenario_type
      ORDER BY s.scenario_type
    `).all(req.user.id);

    // Per-difficulty completion rate.
    const byDifficultyRows = db.prepare(`
      SELECT
        s.difficulty AS difficulty,
        COUNT(*) AS started,
        SUM(CASE WHEN p.completed_at IS NOT NULL THEN 1 ELSE 0 END) AS completed
      FROM ooda_progress p
      JOIN ooda_scenarios s ON s.id = p.scenario_id AND s.archived_at IS NULL
      WHERE p.user_id = ?
      GROUP BY s.difficulty
      ORDER BY CASE s.difficulty
        WHEN 'beginner' THEN 1
        WHEN 'intermediate' THEN 2
        WHEN 'advanced' THEN 3
        ELSE 4 END
    `).all(req.user.id);

    // 5 most recent completions for the dashboard activity feed.
    const recentRows = db.prepare(`
      SELECT
        p.scenario_id    AS scenarioId,
        p.completed_at   AS completedAt,
        s.title          AS title,
        s.scenario_type  AS type,
        s.difficulty     AS difficulty
      FROM ooda_progress p
      LEFT JOIN ooda_scenarios s ON s.id = p.scenario_id AND s.archived_at IS NULL
      WHERE p.user_id = ? AND p.completed_at IS NOT NULL
      ORDER BY p.completed_at DESC
      LIMIT 5
    `).all(req.user.id);
    db.close();

    const started = overallRow.started || 0;
    const completed = overallRow.completed || 0;
    res.json({
      overall: {
        startedCount: started,
        completedCount: completed,
        completionRate: started > 0 ? completed / started : 0,
        avgDurationMs: overallRow.avg_duration_ms ? Math.round(overallRow.avg_duration_ms) : null,
      },
      byType: byTypeRows.map(r => ({
        type: r.type,
        started: r.started,
        completed: r.completed,
        completionRate: r.started > 0 ? r.completed / r.started : 0,
      })),
      byDifficulty: byDifficultyRows.map(r => ({
        difficulty: r.difficulty,
        started: r.started,
        completed: r.completed,
        completionRate: r.started > 0 ? r.completed / r.started : 0,
      })),
      recentCompletions: recentRows.map(r => ({
        scenarioId: r.scenarioId,
        title: r.title,
        type: r.type,
        difficulty: r.difficulty,
        completedAt: r.completedAt,
      })),
    });
  } catch (err) {
    logger.error('Mastery error', { error: err.message });
    res.status(500).json({ error: 'Failed to get mastery aggregation' });
  }
});

module.exports = router;

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

const MAX_POLICY_SIZE = 500000; // 500KB text max
const OODA_PHASES = ['observe', 'orient', 'decide', 'act'];

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

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(
      `ooda_aar_${id}`,
      JSON.stringify({ id, title: title.slice(0, 256), content: content.slice(0, MAX_POLICY_SIZE), incidentDate, lessonsLearned: lessonsLearned?.slice(0, 5000), uploadedAt: new Date().toISOString() }),
      req.user.id
    );
    db.close();
    auditLog(req.user.id, 'OODA_AAR_UPLOADED', `"${title}"`, req.ip);
    res.status(201).json({ id, title });
  } catch (err) {
    res.status(500).json({ error: 'Failed to upload AAR' });
  }
});

router.get('/aar', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare("SELECT value FROM team_config WHERE key LIKE 'ooda_aar_%'").all();
    db.close();
    const aars = rows.map(r => { try { const d = JSON.parse(r.value); return { id: d.id, title: d.title, incidentDate: d.incidentDate, uploadedAt: d.uploadedAt }; } catch { return null; } }).filter(Boolean);
    res.json({ aars });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list AARs' });
  }
});

// ── Generate Scenario ────────────────────────────────────────────────────────
// In production, this calls the AI engine with policy+AAR context.
// For now, generates structured scenarios from templates informed by uploaded content.
router.post('/generate', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can generate scenarios' });

  const { scenarioType, difficulty } = req.body;
  const validTypes = ['ransomware', 'phishing', 'data_exfil', 'insider_threat', 'apt', 'ddos', 'supply_chain', 'credential_compromise'];
  const type = validTypes.includes(scenarioType) ? scenarioType : validTypes[Math.floor(Math.random() * validTypes.length)];
  const diff = ['beginner', 'intermediate', 'advanced'].includes(difficulty) ? difficulty : 'intermediate';

  try {
    const db = getDb();

    // Load policies and AARs for context
    const policies = db.prepare("SELECT id, title, policy_type AS type, content, scenario_tags, version, uploaded_by, uploaded_at FROM ir_policies WHERE deleted_at IS NULL").all()
      .map(p => ({ ...p, scenario_tags: (() => { try { return JSON.parse(p.scenario_tags); } catch { return []; } })() }));
    const aars = db.prepare("SELECT value FROM team_config WHERE key LIKE 'ooda_aar_%'").all()
      .map(r => { try { return JSON.parse(r.value); } catch { return null; } }).filter(Boolean);

    // Generate scenario decision tree
    const scenario = generateScenarioTree(type, diff, policies, aars);
    const id = crypto.randomBytes(16).toString('hex');

    db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(
      `ooda_scenario_${id}`,
      JSON.stringify({ ...scenario, id, createdAt: new Date().toISOString(), createdBy: req.user.id }),
      req.user.id
    );

    db.close();
    auditLog(req.user.id, 'OODA_SCENARIO_GENERATED', `type=${type} difficulty=${diff} nodes=${scenario.nodes.length}`, req.ip);
    res.status(201).json({ id, title: scenario.title, type, difficulty: diff, nodeCount: scenario.nodes.length });
  } catch (err) {
    logger.error('Generate scenario error', { error: err.message });
    res.status(500).json({ error: 'Failed to generate scenario' });
  }
});

// ── List Scenarios ───────────────────────────────────────────────────────────
router.get('/scenarios', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare("SELECT value FROM team_config WHERE key LIKE 'ooda_scenario_%'").all();
    db.close();
    const scenarios = rows.map(r => {
      try { const d = JSON.parse(r.value); return { id: d.id, title: d.title, type: d.type, difficulty: d.difficulty, nodeCount: d.nodes?.length, createdAt: d.createdAt }; } catch { return null; }
    }).filter(Boolean);
    res.json({ scenarios });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list scenarios' });
  }
});

// ── Get Scenario (full decision tree) ────────────────────────────────────────
router.get('/scenarios/:id', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`ooda_scenario_${req.params.id}`);
    db.close();
    if (!row) return res.status(404).json({ error: 'Scenario not found' });
    const scenario = JSON.parse(row.value);
    // Only return the first node — analyst progresses by making choices
    res.json({
      id: scenario.id, title: scenario.title, type: scenario.type, difficulty: scenario.difficulty,
      startNode: scenario.nodes[0],
      totalNodes: scenario.nodes.length,
    });
  } catch (err) {
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

// ── Scenario Generation Engine ───────────────────────────────────────────────
// Builds a decision tree with OODA phases as stages.
// In production, this would call an AI model with policy context.
// For now, uses structured templates.

function generateScenarioTree(type, difficulty, policies, aars) {
  const templates = {
    ransomware: {
      title: 'Ransomware Containment Exercise',
      briefing: 'Multiple endpoints are showing encrypted file extensions and a ransom note has appeared on 3 workstations in the finance department. The SIEM has flagged anomalous SMB traffic.',
      nodes: [
        { id: 'observe_1', phase: 'observe', type: 'decision', prompt: 'You receive a P1 alert about encrypted files. What do you look at first?',
          choices: [
            { text: 'Check the SIEM for correlated alerts across the network', correct: true, nextNodeId: 'observe_2', explanation: 'Correct — establishing the scope of the incident is the first priority in the Observe phase. The SIEM will show if this is isolated or spreading.' },
            { text: 'Immediately disconnect all affected machines from the network', correct: false, explanation: 'While containment is important, it belongs in the Act phase. First you need to Observe — understand what you\'re dealing with before taking action that could destroy forensic evidence.' },
            { text: 'Open the ransom note to see what group is responsible', correct: false, explanation: 'Never interact with ransomware artifacts directly from your workstation. This could trigger additional payloads or C2 callbacks.' },
          ]},
        { id: 'observe_2', phase: 'observe', type: 'decision', prompt: 'SIEM shows SMB lateral movement from a single source IP to 47 endpoints over the last 2 hours. EDR shows a known ransomware binary hash. What else do you check?',
          choices: [
            { text: 'Check if the source IP maps to a compromised user account and verify their access scope', correct: true, nextNodeId: 'orient_1', explanation: 'Correct — identifying the compromised account tells you the blast radius (what they can access) and helps you move to the Orient phase with a clear picture.' },
            { text: 'Start reimaging the affected machines', correct: false, explanation: 'Reimaging destroys forensic evidence and doesn\'t address the root cause. The attacker still has access through the compromised account.' },
          ]},
        { id: 'orient_1', phase: 'orient', type: 'decision', prompt: 'The source is a service account used by the finance automation tool. It has admin rights across the finance OU. You\'ve identified the attack vector. How do you Orient?',
          choices: [
            { text: 'Map the service account\'s permissions, identify all systems it can reach, check if domain admin was escalated', correct: true, nextNodeId: 'decide_1', explanation: 'Correct — in the Orient phase, you\'re building a complete picture. The service account\'s reach defines your containment boundary.' },
            { text: 'Disable the service account immediately', correct: false, explanation: 'This is an Act step, and doing it without a full picture could alert the attacker to pivot to a backup access method before you\'ve identified all their footholds.' },
          ]},
        { id: 'decide_1', phase: 'decide', type: 'decision', prompt: 'Orientation complete: 47 endpoints affected, no domain admin escalation, attacker used a known vulnerability (CVE patched 3 months ago but not applied to this OU). What\'s your decision?',
          choices: [
            { text: 'Coordinate simultaneous containment: disable the service account, isolate affected OU at the network level, preserve forensic images of 3 representative machines', correct: true, nextNodeId: 'act_1', explanation: 'Correct — the Decide phase means choosing a coordinated action plan. Simultaneous containment prevents the attacker from reacting to piecemeal responses.' },
            { text: 'Focus on patching the vulnerability first to prevent reinfection', correct: false, explanation: 'Patching is important but it\'s a recovery step. The attacker is active now — containment must happen before remediation.' },
          ]},
        { id: 'act_1', phase: 'act', type: 'decision', prompt: 'You\'ve decided on coordinated containment. What\'s the execution order?',
          choices: [
            { text: '1) Network isolate the finance OU, 2) Disable the service account, 3) Begin forensic imaging, 4) Notify management and legal', correct: true, nextNodeId: 'resolution', explanation: 'Correct — network isolation first prevents further spread, then credential kill, then evidence preservation, then notifications. This is the standard IR execution order.' },
            { text: '1) Notify management, 2) Disable the account, 3) Start cleanup', correct: false, explanation: 'Notifications should not delay containment actions. Every minute the attacker has network access, more data is at risk.' },
          ]},
        { id: 'resolution', phase: 'resolution', type: 'resolution', prompt: 'Incident contained. The ransomware spread was limited to the finance OU. Forensic images captured. Service account disabled. Network segment isolated. Management and legal notified.',
          summary: 'You successfully navigated all four OODA phases: Observed the scope via SIEM, Oriented by mapping the attack surface, Decided on coordinated containment, and Acted with proper execution order. Key lesson: simultaneous containment prevents attacker pivot.',
          choices: []
        },
      ],
    },
  };

  // Use template for known types, generate variations for others
  const base = templates[type] || templates.ransomware;

  // Customize with policy references if available
  if (policies.length > 0) {
    base.policyContext = `This exercise references ${policies.length} uploaded policy/playbook document(s): ${policies.map(p => p.title).join(', ')}.`;
  }
  if (aars.length > 0) {
    base.aarContext = `Informed by ${aars.length} after-action report(s): ${aars.map(a => a.title).join(', ')}.`;
  }

  base.type = type;
  base.difficulty = difficulty;

  return base;
}

module.exports = router;

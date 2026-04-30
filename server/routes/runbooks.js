// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — IR Recovery Runbook Routes (Phase 1.4c)
//
// Org-policy-driven runbooks. Leads pick a scenario type and an uploaded IR
// policy; the parser extracts ordered steps from the policy and creates a
// runbook in 'draft' status. The lead reviews and edits before activating.
// During an active incident, analysts/leads tick off steps with optional
// completion notes. When the incident is over, the runbook is finalized
// and becomes part of the immutable audit trail.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');
const { parsePolicyToSteps } = require('../services/runbook-parser');

const VALID_SCENARIO_TYPES = [
  'ransomware',
  'data_exfiltration',
  'insider_threat',
  'credential_compromise',
  'ddos',
  'supply_chain',
  'cloud_account_compromise',
  'database_corruption',
  'server_crash',
  'backup_restoration',
  'ir_team_handoff',
];

// Parser is in services/runbook-parser.js — extracted in commit 4a so it can
// be tested in isolation and reused by future scenario generators.

router.post('/generate', (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { scenarioType, policyId, title, incidentId } = req.body || {};

  if (!VALID_SCENARIO_TYPES.includes(scenarioType)) {
    return res.status(400).json({ error: 'scenarioType must be one of: ' + VALID_SCENARIO_TYPES.join(', ') });
  }
  if (!policyId || typeof policyId !== 'string') {
    return res.status(400).json({ error: 'policyId required' });
  }

  let runbookId;
  let policy;
  try {
    const db = getDb();
    policy = db.prepare('SELECT id, title, policy_type, content, version FROM ir_policies WHERE id = ? AND deleted_at IS NULL').get(policyId);
    if (!policy) {
      db.close();
      return res.status(404).json({ error: 'policy not found or deleted' });
    }
    const steps = parsePolicyToSteps(policy.content, scenarioType);
    runbookId = crypto.randomBytes(16).toString('hex');
    const safeTitle = (title && typeof title === 'string') ? title.slice(0, 256) : (scenarioType.replace(/_/g, ' ') + ' runbook from "' + policy.title + '"');
    const safeIncidentId = (incidentId && typeof incidentId === 'string') ? incidentId.slice(0, 128) : null;
    const now = new Date().toISOString();
    const insertRunbook = db.prepare("INSERT INTO runbooks (id, scenario_type, title, source_policy_id, source_policy_version, status, generated_by, generated_at, incident_id) VALUES (?, ?, ?, ?, ?, 'draft', ?, ?, ?)");
    const insertStep = db.prepare('INSERT INTO runbook_steps (id, runbook_id, step_number, title, instruction, expected_outcome, is_critical) VALUES (?, ?, ?, ?, ?, ?, ?)');
    const txn = db.transaction(() => {
      insertRunbook.run(runbookId, scenarioType, safeTitle, policy.id, policy.version, req.user.id, now, safeIncidentId);
      steps.forEach((s, idx) => {
        insertStep.run(crypto.randomBytes(16).toString('hex'), runbookId, idx + 1, s.title, s.instruction, s.expected_outcome, s.is_critical);
      });
    });
    txn();
    db.close();
  } catch (err) {
    logger.error('Failed to generate runbook', { error: err.message, scenarioType, policyId });
    return res.status(500).json({ error: 'failed to generate runbook' });
  }

  try {
    const db = getDb();
    const recipients = db.prepare("SELECT id FROM users WHERE role IN ('lead', 'admin')").all();
    db.close();
    for (const r of recipients) {
      notifications.notify('runbook_generated', r.id, {
        title: 'IR Recovery Runbook generated (draft)',
        body: 'A new ' + scenarioType.replace(/_/g, ' ') + ' runbook is in draft status from policy "' + policy.title + '". Review and activate when ready.',
        linkTab: 'runbook',
        linkParams: JSON.stringify({ runbookId }),
      }).catch((notifyErr) => {
        logger.error('Failed to deliver runbook_generated notification', { error: notifyErr.message, recipientId: r.id });
      });
    }
  } catch (err) {
    logger.error('Failed to enumerate runbook_generated recipients', { error: err.message });
  }

  auditLog(req.user.id, 'RUNBOOK_GENERATED', scenarioType + ' from policy ' + policyId + ' (v' + policy.version + ')', req.ip);

  return res.status(201).json({
    id: runbookId,
    scenarioType,
    sourcePolicyId: policy.id,
    sourcePolicyVersion: policy.version,
    status: 'draft',
  });
});
router.get('/', (req, res) => {
  const status = ['draft', 'active', 'completed', 'cancelled', 'all'].includes(req.query.status) ? req.query.status : 'all';
  const scenario = VALID_SCENARIO_TYPES.includes(req.query.scenario) ? req.query.scenario : null;
  const where = [];
  const params = [];
  if (status !== 'all') { where.push('r.status = ?'); params.push(status); }
  if (scenario) { where.push('r.scenario_type = ?'); params.push(scenario); }
  const whereSql = where.length > 0 ? ' WHERE ' + where.join(' AND ') : '';

  let rows;
  try {
    const db = getDb();
    rows = db.prepare("SELECT r.id, r.scenario_type, r.title, r.status, r.source_policy_id, r.source_policy_version, r.generated_at, r.generated_by, r.activated_at, r.finalized_at, r.incident_id, gen.name AS generated_by_name, p.title AS source_policy_title, (SELECT COUNT(*) FROM runbook_steps s WHERE s.runbook_id = r.id) AS step_count, (SELECT COUNT(*) FROM runbook_steps s WHERE s.runbook_id = r.id AND s.completed_at IS NOT NULL) AS steps_completed, (SELECT COUNT(*) FROM runbook_steps s WHERE s.runbook_id = r.id AND s.skipped = 1) AS steps_skipped FROM runbooks r LEFT JOIN users gen ON gen.id = r.generated_by LEFT JOIN ir_policies p ON p.id = r.source_policy_id" + whereSql + " ORDER BY CASE r.status WHEN 'active' THEN 0 WHEN 'draft' THEN 1 WHEN 'completed' THEN 2 ELSE 3 END, r.generated_at DESC").all(...params);
    db.close();
  } catch (err) {
    logger.error('Failed to list runbooks', { error: err.message });
    return res.status(500).json({ error: 'failed to list runbooks' });
  }

  const runbooks = rows.map((r) => ({
    id: r.id,
    scenarioType: r.scenario_type,
    title: r.title,
    status: r.status,
    sourcePolicyId: r.source_policy_id,
    sourcePolicyVersion: r.source_policy_version,
    sourcePolicyTitle: r.source_policy_title,
    generatedAt: r.generated_at,
    generatedBy: r.generated_by_name || r.generated_by,
    activatedAt: r.activated_at,
    finalizedAt: r.finalized_at,
    incidentId: r.incident_id,
    stepCount: r.step_count,
    stepsCompleted: r.steps_completed,
    stepsSkipped: r.steps_skipped,
  }));

  return res.json({ runbooks });
});

router.get('/:id', (req, res) => {
  const runbookId = req.params.id;
  if (!runbookId || typeof runbookId !== 'string' || runbookId.length > 64) {
    return res.status(400).json({ error: 'invalid runbook id' });
  }

  try {
    const db = getDb();
    const r = db.prepare('SELECT r.*, gen.name AS generated_by_name, act.name AS activated_by_name, fin.name AS finalized_by_name, p.title AS source_policy_title FROM runbooks r LEFT JOIN users gen ON gen.id = r.generated_by LEFT JOIN users act ON act.id = r.activated_by LEFT JOIN users fin ON fin.id = r.finalized_by LEFT JOIN ir_policies p ON p.id = r.source_policy_id WHERE r.id = ?').get(runbookId);

    if (!r) {
      db.close();
      return res.status(404).json({ error: 'runbook not found' });
    }

    const stepRows = db.prepare('SELECT s.*, comp.name AS completed_by_name FROM runbook_steps s LEFT JOIN users comp ON comp.id = s.completed_by WHERE s.runbook_id = ? ORDER BY s.step_number ASC').all(runbookId);
    db.close();

    const steps = stepRows.map((s) => ({
      id: s.id,
      stepNumber: s.step_number,
      title: s.title,
      instruction: s.instruction,
      expectedOutcome: s.expected_outcome,
      isCritical: s.is_critical === 1,
      completedAt: s.completed_at,
      completedBy: s.completed_by_name || s.completed_by,
      completionNote: s.completion_note,
      skipped: s.skipped === 1,
      skipReason: s.skip_reason,
    }));

    return res.json({
      runbook: {
        id: r.id,
        scenarioType: r.scenario_type,
        title: r.title,
        status: r.status,
        sourcePolicyId: r.source_policy_id,
        sourcePolicyVersion: r.source_policy_version,
        sourcePolicyTitle: r.source_policy_title,
        generatedAt: r.generated_at,
        generatedBy: r.generated_by_name || r.generated_by,
        activatedAt: r.activated_at,
        activatedBy: r.activated_by_name || r.activated_by,
        finalizedAt: r.finalized_at,
        finalizedBy: r.finalized_by_name || r.finalized_by,
        incidentId: r.incident_id,
        notes: r.notes,
      },
      steps,
    });
  } catch (err) {
    logger.error('Failed to fetch runbook', { runbookId, error: err.message });
    return res.status(500).json({ error: 'failed to fetch runbook' });
  }
});

module.exports = router;

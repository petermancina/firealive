// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — IR Recovery Runbook Routes (Phase 1.4c)
//
// Org-policy-driven runbooks. Leads pick a scenario type and an uploaded IR
// policy; the parser extracts ordered steps from the policy and creates a
// runbook in 'draft' status. The lead reviews and edits before activating.
// During an active incident, analysts/leads tick off steps with optional
// completion notes. When the incident is over, the runbook is finalized
// and becomes part of the immutable audit trail.
//
// POST /api/runbooks/generate                  — generate from policy (lead/admin)
// GET  /api/runbooks                            — list runbooks with filters
// GET  /api/runbooks/:id                        — fetch runbook + steps
// POST /api/runbooks/:id/activate               — draft → active (lead/admin)
// POST /api/runbooks/:id/finalize               — active → completed (lead/admin)
// POST /api/runbooks/:id/cancel                 — any → cancelled (lead/admin)
// POST /api/runbooks/:id/steps/:stepId/complete — mark step done (any role)
// POST /api/runbooks/:id/steps/:stepId/skip     — mark step skipped (lead/admin)
// GET  /api/runbooks/scenarios/:type/policies   — list policies tagged for scenario
//
// Activate, finalize, cancel, complete-step, skip-step, and the scenario-policies
// endpoint live in commits 4 and 5 of this PR. This commit ships generate,
// list, and fetch.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');

// Valid scenario types. Match the OODA simulator's vocabulary where it
// overlaps, with additional types for incidents the OODA simulator doesn't
// model (server crash, backup restoration, etc).
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

// ── Inline policy → steps parser ─────────────────────────────────────────────
//
// Extracts ordered steps from policy markdown. The parser looks for:
//   - Numbered list items (1. Foo, 2. Bar) — each is a step
//   - Markdown headers (## Step 1: Foo) — each is a step
//   - Bulleted lists under a "Steps" or "Procedure" header
//
// For each step, the parser captures:
//   - title: the first line (truncated to 200 chars)
//   - instruction: full body text after the title until the next step
//   - expected_outcome: text following "Expected:" or "Outcome:" markers
//   - is_critical: true if the step is marked "CRITICAL" or "MANDATORY"
//
// This is a real parser, not a TODO. It handles common policy formatting
// patterns. Policies that don't use any recognized structure fall back to
// a single "Follow the policy document" step pointing at the policy ID —
// the lead can edit the runbook in draft state to add steps manually.
//
// Will be extracted to server/services/runbook-parser.js in commit 4 once
// the route is shipping. Inlined here so this commit is a self-contained
// vertical slice.
function parsePolicyToSteps(policyContent, scenarioType) {
  const lines = policyContent.split(/\r?\n/);
  const steps = [];
  let currentStep = null;
  let inStepsSection = false;

  // Pattern: numbered item at start of line (1. Foo, 1) Foo, etc.)
  const numberedRe = /^\s*(\d+)[\.\)]\s+(.+)/;
  // Pattern: ## Step N: title or ## N. title
  const headerStepRe = /^#{2,6}\s+(?:Step\s+)?(\d+)[:\.]?\s+(.+)/i;
  // Pattern: ## Steps / ## Procedure / ## Actions / etc.
  const stepsHeaderRe = /^#{2,6}\s+(steps?|procedures?|actions?|response|recovery)\b/i;
  // Pattern: bulleted list under a steps header
  const bulletRe = /^\s*[\*\-\+]\s+(.+)/;

  function pushStep(s) {
    if (!s) return;
    const title = (s.title || '').slice(0, 200);
    const instruction = (s.instructionLines || []).join('\n').trim() || title;
    if (!title && !instruction) return;
    // Look for expected outcome markers in the instruction body
    let expectedOutcome = null;
    const outcomeMatch = instruction.match(/(?:^|\n)\s*(?:Expected|Outcome|Result)[:\.]?\s*(.+?)(?=\n\s*\n|$)/is);
    if (outcomeMatch) expectedOutcome = outcomeMatch[1].trim().slice(0, 1000);
    const isCritical = /\b(CRITICAL|MANDATORY|MUST)\b/i.test(title) || /\b(CRITICAL|MANDATORY|MUST NOT FAIL)\b/i.test(instruction.slice(0, 500));
    steps.push({
      title,
      instruction: instruction.slice(0, 5000),
      expected_outcome: expectedOutcome,
      is_critical: isCritical ? 1 : 0,
    });
  }

  for (const line of lines) {
    const headerStepMatch = line.match(headerStepRe);
    if (headerStepMatch) {
      pushStep(currentStep);
      currentStep = { title: headerStepMatch[2].trim(), instructionLines: [] };
      inStepsSection = true;
      continue;
    }
    const numberedMatch = line.match(numberedRe);
    if (numberedMatch) {
      pushStep(currentStep);
      currentStep = { title: numberedMatch[2].trim(), instructionLines: [] };
      inStepsSection = true;
      continue;
    }
    if (stepsHeaderRe.test(line)) {
      inStepsSection = true;
      continue;
    }
    if (inStepsSection) {
      const bulletMatch = line.match(bulletRe);
      if (bulletMatch && !currentStep) {
        // Bulleted list under a Steps header (no numbering) — each bullet a step
        currentStep = { title: bulletMatch[1].trim(), instructionLines: [] };
        continue;
      }
      if (bulletMatch && currentStep) {
        // Bullet inside a step — append to instruction
        currentStep.instructionLines.push('• ' + bulletMatch[1].trim());
        continue;
      }
      if (line.trim() && currentStep) {
        currentStep.instructionLines.push(line);
      }
    }
  }
  pushStep(currentStep);

  // Fallback: if the parser found nothing, return a single step that points
  // at the source policy. The lead will edit the runbook in draft state.
  if (steps.length === 0) {
    steps.push({
      title: 'Review the source policy and add steps manually',
      instruction: 'The runbook generator could not extract structured steps from this policy. Open the source policy in the IR Simulator policies tab, identify the recovery procedure, and add steps to this runbook in draft state before activating.',
      expected_outcome: null,
      is_critical: 0,
    });
  }

  return steps;
}

// ── POST /api/runbooks/generate — generate a runbook from a policy ──────────
router.post('/generate', (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { scenarioType, policyId, title, incidentId } = req.body || {};

  if (!VALID_SCENARIO_TYPES.includes(scenarioType)) {
    return res.status(400).json({ error: `scenarioType must be one of: ${VALID_SCENARIO_TYPES.join(', ')}` });
  }
  if (!policyId || typeof policyId !== 'string') {
    return res.status(400).json({ error: 'policyId required' });
  }

  let runbookId;
  let policy;
  try {
    const db = getDb();

    policy = db.prepare(`
      SELECT id, title, policy_type, content, version
      FROM ir_policies
      WHERE id = ? AND deleted_at IS NULL
    `).get(policyId);

    if (!policy) {
      db.close();
      return res.status(404).json({ error: 'policy not found or deleted' });
    }

    const steps = parsePolicyToSteps(policy.content, scenarioType);

    runbookId = crypto.randomBytes(16).toString('hex');
    const safeTitle = (title && typeof title === 'string')
      ? title.slice(0, 256)
      : `${scenarioType.replace(/_/g, ' ')} runbook from "${policy.title}"`;
    const safeIncidentId = (incidentId && typeof incidentId === 'string') ? incidentId.slice(0, 128) : null;
    const now = new Date().toISOString();

    // Insert runbook + steps in a transaction so a parse failure mid-insert
    // doesn't leave a half-built runbook in the table.
    const insertRunbook = db.prepare(`
      INSERT INTO runbooks
        (id, scenario_type, title, source_policy_id, source_policy_version, status, generated_by, generated_at, incident_id)
      VALUES (?, ?, ?, ?, ?, 'draft', ?, ?, ?)
    `);
    const insertStep = db.prepare(`
      INSERT INTO runbook_steps
        (id, runbook_id, step_number, title, instruction, expected_outcome, is_critical)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

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

  // Notify leads/admins that a new runbook is in draft status. Notification
  // failures must not undo the generation.
  try {
    const db = getDb();
    const recipients = db.prepare("SELECT id FROM users WHERE role IN ('lead', 'admin')").all();
    db.close();
    for (const r of recipients) {
      notifications.notify('runbook_generated', r.id, {
        title: 'IR Recovery Runbook generated (draft)',
        body: `A new ${scenarioType.replace(/_/g, ' ')} runbook is in draft status from policy "${policy.title}". Review and activate when ready.`,
        linkTab: 'runbook',
        linkParams: JSON.stringify({ runbookId }),
      }).catch((notifyErr) => {
        logger.error('Failed to​​​​​​​​​​​​​​​​

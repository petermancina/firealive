// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — IR Recovery Runbook Parser (Phase 1.4c)
//
// Extracts ordered steps from policy markdown text. Used by the runbooks
// route to convert an uploaded ir_policies.content blob into a series of
// structured runbook_steps rows.
//
// The parser handles three common policy markup patterns:
//   1. Numbered list items: "1. Foo", "2) Bar"
//   2. Markdown headers: "## Step 1: Foo", "### 2. Bar"
//   3. Bulleted lists under a Steps/Procedure/Actions section header
//
// For each step, it extracts:
//   - title:            first line, truncated to 200 chars
//   - instruction:      full body text after the title, up to 5KB
//   - expected_outcome: text following "Expected:" / "Outcome:" / "Result:"
//                       markers, up to 1000 chars (nullable)
//   - is_critical:      1 if title or first 500 chars of instruction contain
//                       CRITICAL / MANDATORY / MUST, else 0
//
// If no recognizable structure is found, returns a single fallback step
// directing the lead to add steps manually in draft state. This preserves
// the contract that a runbook always has at least one step.
// ═══════════════════════════════════════════════════════════════════════════════

const NUMBERED_RE = /^\s*(\d+)[\.\)]\s+(.+)/;
const HEADER_STEP_RE = /^#{2,6}\s+(?:Step\s+)?(\d+)[:\.]?\s+(.+)/i;
const STEPS_HEADER_RE = /^#{2,6}\s+(steps?|procedures?|actions?|response|recovery)\b/i;
const BULLET_RE = /^\s*[\*\-\+]\s+(.+)/;
const OUTCOME_RE = /(?:^|\n)\s*(?:Expected|Outcome|Result)[:\.]?\s*(.+?)(?=\n\s*\n|$)/is;
const CRITICAL_TITLE_RE = /\b(CRITICAL|MANDATORY|MUST)\b/i;
const CRITICAL_BODY_RE = /\b(CRITICAL|MANDATORY|MUST NOT FAIL)\b/i;

const MAX_TITLE_LENGTH = 200;
const MAX_INSTRUCTION_LENGTH = 5000;
const MAX_OUTCOME_LENGTH = 1000;
const CRITICAL_BODY_SCAN_LENGTH = 500;

function parsePolicyToSteps(policyContent, scenarioType) {
  if (typeof policyContent !== 'string' || policyContent.length === 0) {
    return [fallbackStep()];
  }

  const lines = policyContent.split(/\r?\n/);
  const steps = [];
  let currentStep = null;
  let inStepsSection = false;

  for (const line of lines) {
    const headerStepMatch = line.match(HEADER_STEP_RE);
    if (headerStepMatch) {
      pushStep(steps, currentStep);
      currentStep = { title: headerStepMatch[2].trim(), instructionLines: [] };
      inStepsSection = true;
      continue;
    }

    const numberedMatch = line.match(NUMBERED_RE);
    if (numberedMatch) {
      pushStep(steps, currentStep);
      currentStep = { title: numberedMatch[2].trim(), instructionLines: [] };
      inStepsSection = true;
      continue;
    }

    if (STEPS_HEADER_RE.test(line)) {
      inStepsSection = true;
      continue;
    }

    if (inStepsSection) {
      const bulletMatch = line.match(BULLET_RE);
      if (bulletMatch && !currentStep) {
        currentStep = { title: bulletMatch[1].trim(), instructionLines: [] };
        continue;
      }
      if (bulletMatch && currentStep) {
        currentStep.instructionLines.push('• ' + bulletMatch[1].trim());
        continue;
      }
      if (line.trim() && currentStep) {
        currentStep.instructionLines.push(line);
      }
    }
  }
  pushStep(steps, currentStep);

  if (steps.length === 0) {
    return [fallbackStep()];
  }

  return steps;
}

function pushStep(steps, s) {
  if (!s) return;
  const title = (s.title || '').slice(0, MAX_TITLE_LENGTH);
  const instructionRaw = (s.instructionLines || []).join('\n').trim();
  const instruction = (instructionRaw || title).slice(0, MAX_INSTRUCTION_LENGTH);
  if (!title && !instruction) return;

  let expectedOutcome = null;
  const outcomeMatch = instruction.match(OUTCOME_RE);
  if (outcomeMatch) {
    expectedOutcome = outcomeMatch[1].trim().slice(0, MAX_OUTCOME_LENGTH);
  }

  const titleHit = CRITICAL_TITLE_RE.test(title);
  const bodyHit = CRITICAL_BODY_RE.test(instruction.slice(0, CRITICAL_BODY_SCAN_LENGTH));
  const isCritical = (titleHit || bodyHit) ? 1 : 0;

  steps.push({
    title,
    instruction,
    expected_outcome: expectedOutcome,
    is_critical: isCritical,
  });
}

function fallbackStep() {
  return {
    title: 'Review the source policy and add steps manually',
    instruction: 'The runbook generator could not extract structured steps from this policy. Open the source policy in the IR Simulator policies tab, identify the recovery procedure, and add steps to this runbook in draft state before activating.',
    expected_outcome: null,
    is_critical: 0,
  };
}

module.exports = { parsePolicyToSteps };

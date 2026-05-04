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
const oodaJobs = require('../services/ooda-generation-jobs');

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

// ── Phase F4c: Threshold-mode replenishment check ───────────────────────────
//
// Called from POST /scenarios/:id/play when an analyst completes a scenario.
// For each policy the scenario was generated from, checks the policy's
// replenishment_config:
//
//   1. mode === 'threshold'?              if not, skip
//   2. unplayed-pool count for THIS user  if >= threshold_x, skip
//      below threshold_x?
//   3. is a job already queued/running    if so, skip (anti-pile-up)
//      for this policy?
//   4. enqueue a generation job with the policy's configured batch_size
//
// The "unplayed pool" for a (user, policy) pair is: the count of active
// scenarios linked to this policy (via source_policy_ids JSON containing
// the policy id) that the user hasn't COMPLETED. Partial progress doesn't
// count — only scenarios with completed_at set in ooda_progress are
// considered "played" for pool-floor purposes.
//
// Defense in depth: the entire helper is wrapped in try/catch and any
// failure is non-fatal. If the threshold check throws or times out, the
// analyst's /play response is unaffected. The check is async-friendly
// but kept synchronous here because better-sqlite3 doesn't return
// promises and the queries are local/fast.
//
// Audit attribution: the analyst whose play triggered the check is
// recorded as enqueued_by on the resulting generation job. This lets
// admins reconstruct "scenario X completed by user Y triggered job Z".
function checkThresholdReplenishment(sourcePolicyIdsJson, userId) {
  let policyIds;
  try {
    policyIds = JSON.parse(sourcePolicyIdsJson || '[]');
    if (!Array.isArray(policyIds)) policyIds = [];
  } catch {
    return;
  }
  if (policyIds.length === 0) return;

  const db = getDb();
  try {
    for (const policyId of policyIds) {
      try {
        // Read the policy's replenishment config. Skip silently if the
        // policy was deleted between scenario creation and now.
        const policy = db.prepare(`
          SELECT id, replenishment_config FROM ir_policies
          WHERE id = ? AND deleted_at IS NULL
        `).get(policyId);
        if (!policy) continue;

        let cfg;
        try {
          cfg = JSON.parse(policy.replenishment_config || '{}');
        } catch {
          // Malformed config — analyst's play succeeds; admin can fix
          // the config when they notice the missing replenishment.
          continue;
        }

        if (cfg.mode !== 'threshold') continue;

        const thresholdX = parseInt(cfg.threshold_x, 10);
        if (!Number.isInteger(thresholdX) || thresholdX < 1 || thresholdX > 50) {
          continue;
        }

        // Count unplayed scenarios for this (user, policy) pair. Uses
        // SQLite's json_each() to query inside the source_policy_ids
        // JSON array — supported natively in better-sqlite3.
        const countRow = db.prepare(`
          SELECT COUNT(*) AS unplayed_count
          FROM ooda_scenarios s
          WHERE s.archived_at IS NULL
            AND EXISTS (
              SELECT 1 FROM json_each(s.source_policy_ids)
              WHERE json_each.value = ?
            )
            AND NOT EXISTS (
              SELECT 1 FROM ooda_progress p
              WHERE p.scenario_id = s.id
                AND p.user_id = ?
                AND p.completed_at IS NOT NULL
            )
        `).get(policyId, userId);

        const unplayedCount = countRow ? countRow.unplayed_count : 0;
        if (unplayedCount >= thresholdX) continue;

        // Anti-pile-up: skip if a job is already queued or running for
        // this policy. Without this guard, every play below threshold
        // would enqueue another job, accumulating queue pressure.
        const existingJob = db.prepare(`
          SELECT id FROM ooda_generation_jobs
          WHERE policy_id = ? AND status IN ('queued', 'running')
          LIMIT 1
        `).get(policyId);
        if (existingJob) continue;

        // Resolve batch_size with fallback to 5 (matches the canonical
        // default in db/init.js)
        const rawBatch = parseInt(cfg.batch_size, 10);
        const batchSize = (Number.isInteger(rawBatch) && rawBatch >= 1 && rawBatch <= 20)
          ? rawBatch : 5;

        try {
          const jobId = oodaJobs.enqueueJob({
            policy_id: policyId,
            mode: 'threshold',
            target_count_per_difficulty: batchSize,
            enqueued_by: userId,
          });
          logger.info('Threshold replenishment enqueued', {
            policy_id: policyId,
            job_id: jobId,
            unplayed_count: unplayedCount,
            threshold_x: thresholdX,
            batch_size: batchSize,
            triggered_by: userId,
          });
        } catch (enqueueErr) {
          logger.error('Threshold replenishment: enqueue failed', {
            policy_id: policyId,
            error: enqueueErr.message,
          });
        }
      } catch (perPolicyErr) {
        // Per-policy errors are logged but don't stop other policies in
        // the same scenario from being checked.
        logger.warn('Threshold replenishment: per-policy check failed', {
          policy_id: policyId,
          error: perPolicyErr.message,
        });
      }
    }
  } finally {
    db.close();
  }
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

// ── Update per-policy replenishment config (Phase F4c) ──────────────────────
//
// PATCH /api/ooda/policies/:id/replenishment-config
//
// Updates a single policy's replenishment_config JSON column. Read by:
//   - The threshold-replenishment hook in POST /scenarios/:id/play
//     (commit 7 of PR #3)
//   - The scheduled-mode cron in services/scheduler.js (commit 4 of PR #3)
//   - The auto_initial_upload check in POST /policies (future enhancement)
//
// Validates the entire incoming config object server-side. Each field has a
// known type, range, and conditional applicability:
//
//   mode           required; one of 'threshold', 'scheduled', 'manual',
//                  'disabled'. The other fields' applicability depends on
//                  this — e.g. threshold_x is only meaningful when
//                  mode='threshold'. Unrelated fields are tolerated (stored)
//                  but ignored at runtime so the UI can preserve user input
//                  across mode toggles.
//
//   threshold_x    integer 1-50, only meaningful when mode='threshold'
//   batch_size     integer 1-20, all auto modes use it
//   scheduled_hour integer 0-23, only meaningful when mode='scheduled'
//   scheduled_days optional array of 'sun'|'mon'|...|'sat' strings, only
//                  meaningful when mode='scheduled'. Empty/missing means
//                  every day.
//   auto_initial_upload  boolean. Whether to auto-enqueue an
//                        initial-batch generation job at policy upload
//                        time. PR #3 commit 5 did NOT wire this hook
//                        yet — the column is set, but no upload-time
//                        generation fires. Wiring the auto-enqueue hook
//                        is a separate F4c task.
//
// Audit: OODA_POLICY_REPL_CONFIG_UPDATED with the policy id, the incoming
// mode, and a compact summary of changed fields. The full prior config is
// not logged (would be noisy for what is functionally a settings-write).
//
// Permission: lead/admin only. Same role pattern as the rest of /policies.
router.patch('/policies/:id/replenishment-config', (req, res) => {
  if (req.user.role === 'analyst') {
    return res.status(403).json({ error: 'Only leads/admins can change replenishment config' });
  }

  const body = req.body || {};

  // Validate mode (required)
  const VALID_MODES = ['threshold', 'scheduled', 'manual', 'disabled'];
  if (!VALID_MODES.includes(body.mode)) {
    return res.status(400).json({
      error: `mode must be one of: ${VALID_MODES.join(', ')}`,
      code: 'INVALID_MODE',
    });
  }

  // Validate threshold_x if mode='threshold' (other modes can supply or
  // omit; we tolerate but normalize)
  let thresholdX = null;
  if (body.threshold_x != null) {
    const n = parseInt(body.threshold_x, 10);
    if (!Number.isInteger(n) || n < 1 || n > 50) {
      return res.status(400).json({
        error: 'threshold_x must be an integer between 1 and 50',
        code: 'INVALID_THRESHOLD_X',
      });
    }
    thresholdX = n;
  } else if (body.mode === 'threshold') {
    return res.status(400).json({
      error: 'threshold_x is required when mode is threshold',
      code: 'INVALID_THRESHOLD_X',
    });
  }

  // Validate batch_size (required for all auto modes; tolerated/ignored
  // for mode='disabled'; we still validate if supplied)
  let batchSize = null;
  if (body.batch_size != null) {
    const n = parseInt(body.batch_size, 10);
    if (!Number.isInteger(n) || n < 1 || n > 20) {
      return res.status(400).json({
        error: 'batch_size must be an integer between 1 and 20',
        code: 'INVALID_BATCH_SIZE',
      });
    }
    batchSize = n;
  } else if (body.mode === 'threshold' || body.mode === 'scheduled' || body.mode === 'manual') {
    return res.status(400).json({
      error: 'batch_size is required when mode is threshold, scheduled, or manual',
      code: 'INVALID_BATCH_SIZE',
    });
  }

  // Validate scheduled_hour if mode='scheduled'
  let scheduledHour = null;
  if (body.scheduled_hour != null) {
    const n = parseInt(body.scheduled_hour, 10);
    if (!Number.isInteger(n) || n < 0 || n > 23) {
      return res.status(400).json({
        error: 'scheduled_hour must be an integer between 0 and 23',
        code: 'INVALID_SCHEDULED_HOUR',
      });
    }
    scheduledHour = n;
  } else if (body.mode === 'scheduled') {
    return res.status(400).json({
      error: 'scheduled_hour is required when mode is scheduled',
      code: 'INVALID_SCHEDULED_HOUR',
    });
  }

  // Validate scheduled_days if supplied (always optional; empty/missing =
  // every day)
  const VALID_DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
  let scheduledDays = null;
  if (body.scheduled_days != null) {
    if (!Array.isArray(body.scheduled_days)) {
      return res.status(400).json({
        error: 'scheduled_days must be an array',
        code: 'INVALID_SCHEDULED_DAYS',
      });
    }
    for (const d of body.scheduled_days) {
      if (typeof d !== 'string' || !VALID_DAYS.includes(d)) {
        return res.status(400).json({
          error: `scheduled_days entries must be one of: ${VALID_DAYS.join(', ')}`,
          code: 'INVALID_SCHEDULED_DAYS',
        });
      }
    }
    // Deduplicate while preserving canonical order
    scheduledDays = VALID_DAYS.filter(d => body.scheduled_days.includes(d));
  }

  // Validate auto_initial_upload (boolean; default true if absent)
  let autoInitialUpload;
  if (body.auto_initial_upload === undefined || body.auto_initial_upload === null) {
    autoInitialUpload = true;
  } else if (typeof body.auto_initial_upload === 'boolean') {
    autoInitialUpload = body.auto_initial_upload;
  } else {
    return res.status(400).json({
      error: 'auto_initial_upload must be a boolean',
      code: 'INVALID_AUTO_INITIAL_UPLOAD',
    });
  }

  // Build the canonical config object. Only include fields that apply to
  // the current mode plus the always-applicable batch_size and
  // auto_initial_upload. This way runtime readers can rely on a clean
  // contract and the UI doesn't have to filter stale fields when the
  // mode changes.
  const config = { mode: body.mode };
  if (body.mode === 'threshold') config.threshold_x = thresholdX;
  if (body.mode === 'scheduled') {
    config.scheduled_hour = scheduledHour;
    if (scheduledDays && scheduledDays.length > 0) config.scheduled_days = scheduledDays;
  }
  if (body.mode !== 'disabled') config.batch_size = batchSize;
  config.auto_initial_upload = autoInitialUpload;

  // Persist
  let updateResult;
  try {
    const db = getDb();
    updateResult = db.prepare(`
      UPDATE ir_policies
      SET replenishment_config = ?, updated_at = datetime('now')
      WHERE id = ? AND deleted_at IS NULL
    `).run(JSON.stringify(config), req.params.id);
    db.close();
  } catch (err) {
    logger.error('Replenishment config update failed', {
      policy_id: req.params.id, error: err.message,
    });
    return res.status(500).json({ error: 'Failed to update replenishment config' });
  }

  if (updateResult.changes === 0) {
    return res.status(404).json({
      error: 'Policy not found or has been deleted',
      code: 'POLICY_NOT_FOUND',
    });
  }

  auditLog(
    req.user.id,
    'OODA_POLICY_REPL_CONFIG_UPDATED',
    `policy=${req.params.id} mode=${config.mode}`
      + (config.threshold_x != null ? ` threshold_x=${config.threshold_x}` : '')
      + (config.batch_size != null ? ` batch_size=${config.batch_size}` : '')
      + (config.scheduled_hour != null ? ` hour=${config.scheduled_hour}` : '')
      + (config.scheduled_days ? ` days=${config.scheduled_days.join(',')}` : '')
      + ` auto_init=${config.auto_initial_upload}`,
    req.ip
  );

  return res.json({
    policy_id: req.params.id,
    replenishment_config: config,
  });
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

// ── Remove AAR ───────────────────────────────────────────────────────────────
// Soft delete (matches the policy delete pattern). Preserves the row so any
// historically-generated scenarios that referenced this AAR retain their
// provenance trail. Lead/admin only.
router.delete('/aar/:id', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can remove AARs' });
  try {
    const db = getDb();
    const result = db.prepare("UPDATE ooda_aars SET deleted_at = datetime('now') WHERE id = ? AND deleted_at IS NULL").run(req.params.id);
    db.close();
    if (result.changes === 0) {
      return res.status(404).json({ error: 'AAR not found or already deleted' });
    }
    auditLog(req.user.id, 'OODA_AAR_REMOVED', req.params.id, req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Remove AAR error', { error: err.message });
    res.status(500).json({ error: 'Failed to remove AAR' });
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
      SELECT id, tree, node_count, source_policy_ids
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

      // Phase F4c: threshold-mode replenishment check. After the
      // analyst's pool of unplayed scenarios drops below a policy's
      // threshold_x, enqueue a generation job to refill. Best-effort
      // and non-fatal — any failure inside the helper is logged but
      // doesn't affect the analyst's response.
      try {
        checkThresholdReplenishment(row.source_policy_ids, req.user.id);
      } catch (replErr) {
        logger.warn('Threshold replenishment check threw (non-fatal)', {
          scenario_id: req.params.id,
          user_id: req.user.id,
          error: replErr.message,
        });
      }
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
// Access is analyst-only. Leads and admins are explicitly rejected here
// even though the parent /api/ooda mount allows them — they don't take
// trainings, so they don't have meaningful mastery data of their own.
// A defense against future frontend changes that might accidentally
// surface lead-mastery data: even if the UI were to call /mastery from
// a lead session, the backend refuses. A separate route would be needed
// to surface aggregate analyst-mastery data to leads (not built here).
//
// Response shape:
//   {
//     overall: { startedCount, completedCount, completionRate, avgDurationMs },
//     byType: [ { type, started, completed, completionRate }, ... ],
//     byDifficulty: [ { difficulty, started, completed, completionRate }, ... ],
//     recentCompletions: [ { scenarioId, title, type, difficulty, completedAt }, ... ],
//   }
router.get('/mastery', (req, res) => {
  if (req.user.role !== 'analyst') {
    return res.status(403).json({
      error: 'Mastery tracking is for analysts only',
      code: 'MASTERY_ANALYST_ONLY',
    });
  }
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

// ── Scenario Generation Jobs (Phase F4c) ─────────────────────────────────────
//
// Async generation of OODA scenarios. The IR Simulator's generate-on-upload,
// scheduled-replenishment, and threshold-replenishment flows all enqueue
// jobs through this surface. The worker module (services/ooda-generation-
// jobs.js) processes them in the background; these routes are the
// HTTP-facing wrappers around the worker's exported API.
//
// Permissions: enqueue and cancel are lead/admin only (mirrors the
// /policies and /aar upload pattern). Status and list reads are also
// lead/admin only — analysts see scenarios served to them via /scenarios,
// not queue introspection. Cancellation is best-effort: the worker stops
// at the next scenario boundary; the in-flight LLM call (if any) runs to
// completion.
//
// Wire-level errors map cleanly:
//   400  invalid args (mode, target_count_per_difficulty, policy_id missing)
//   403  analyst role attempted enqueue/cancel
//   404  job id or policy id not found
//   409  cancel requested on a job already in a terminal state
//   500  unexpected worker or DB error

// POST /api/ooda/generation-jobs — enqueue a new generation job.
router.post('/generation-jobs', (req, res) => {
  if (req.user.role === 'analyst') {
    return res.status(403).json({ error: 'Only leads/admins can enqueue generation jobs' });
  }

  const body = req.body || {};
  // Accept both target_count_per_difficulty (canonical) and batch_size (alias
  // used by the MC wizard and replenishment_config). Either works.
  const target = body.target_count_per_difficulty != null
    ? body.target_count_per_difficulty
    : body.batch_size;
  const mode = body.mode || 'manual';

  let jobId;
  try {
    jobId = oodaJobs.enqueueJob({
      policy_id: body.policy_id,
      mode,
      target_count_per_difficulty: target,
      enqueued_by: req.user.id,
    });
  } catch (err) {
    // The worker's enqueueJob throws plain Error for validation failures.
    // Map common cases to 400/404; other failures bubble as 500.
    const msg = err.message || 'unknown';
    if (msg.includes('policy not found')) {
      return res.status(404).json({ error: msg, code: 'POLICY_NOT_FOUND' });
    }
    if (msg.includes('policy_id is required')
        || msg.includes('mode must be one of')
        || msg.includes('target_count_per_difficulty')) {
      return res.status(400).json({ error: msg, code: 'INVALID_JOB_ARGS' });
    }
    logger.error('Generation job enqueue failed', {
      error: msg, body: { policy_id: body.policy_id, mode, target },
    });
    return res.status(500).json({ error: 'Failed to enqueue generation job' });
  }

  auditLog(
    req.user.id,
    'OODA_GEN_JOB_ENQUEUED',
    `id=${jobId} policy=${body.policy_id} mode=${mode} batch_size=${target}`,
    req.ip
  );

  return res.status(202).json({
    job_id: jobId,
    status_url: `/api/ooda/generation-jobs/${jobId}`,
    message: 'Job enqueued; poll status_url for progress',
  });
});

// GET /api/ooda/generation-jobs/:id — fetch a single job's status.
router.get('/generation-jobs/:id', (req, res) => {
  if (req.user.role === 'analyst') {
    return res.status(403).json({ error: 'Only leads/admins can view generation job status' });
  }

  let job;
  try {
    job = oodaJobs.getJobStatus(req.params.id);
  } catch (err) {
    logger.error('Generation job status fetch failed', { id: req.params.id, error: err.message });
    return res.status(500).json({ error: 'Failed to fetch job status' });
  }
  if (!job) {
    return res.status(404).json({ error: 'Job not found', code: 'JOB_NOT_FOUND' });
  }
  return res.json(job);
});

// GET /api/ooda/generation-jobs — list jobs with optional filters. Most
// recent first, default limit 50, max 200.
router.get('/generation-jobs', (req, res) => {
  if (req.user.role === 'analyst') {
    return res.status(403).json({ error: 'Only leads/admins can list generation jobs' });
  }

  const filter = {};
  if (req.query.policy_id) filter.policy_id = String(req.query.policy_id);
  if (req.query.status) {
    const status = String(req.query.status);
    if (!['queued', 'running', 'done', 'failed', 'cancelled'].includes(status)) {
      return res.status(400).json({
        error: `status filter must be one of: queued, running, done, failed, cancelled`,
        code: 'INVALID_STATUS_FILTER',
      });
    }
    filter.status = status;
  }
  if (req.query.limit) {
    const lim = parseInt(req.query.limit, 10);
    if (!Number.isInteger(lim) || lim < 1) {
      return res.status(400).json({
        error: 'limit must be a positive integer',
        code: 'INVALID_LIMIT',
      });
    }
    filter.limit = lim;
  }

  let jobs;
  try {
    jobs = oodaJobs.listJobs(filter);
  } catch (err) {
    logger.error('Generation job list failed', { filter, error: err.message });
    return res.status(500).json({ error: 'Failed to list generation jobs' });
  }
  return res.json({ jobs, count: jobs.length });
});

// POST /api/ooda/generation-jobs/:id/cancel — cancel a queued or running
// job. Best-effort: stops at next scenario boundary; in-flight LLM call
// is allowed to complete.
router.post('/generation-jobs/:id/cancel', (req, res) => {
  if (req.user.role === 'analyst') {
    return res.status(403).json({ error: 'Only leads/admins can cancel generation jobs' });
  }

  // Fetch first so we can distinguish "not found" (404) from "already
  // terminal" (409). The worker's cancelJob returns false for both cases
  // and the route layer's job is to provide more helpful HTTP semantics.
  let job;
  try {
    job = oodaJobs.getJobStatus(req.params.id);
  } catch (err) {
    logger.error('Generation job cancel: status fetch failed', {
      id: req.params.id, error: err.message,
    });
    return res.status(500).json({ error: 'Failed to access job for cancellation' });
  }
  if (!job) {
    return res.status(404).json({ error: 'Job not found', code: 'JOB_NOT_FOUND' });
  }
  if (job.status !== 'queued' && job.status !== 'running') {
    return res.status(409).json({
      error: `Job is already in terminal state '${job.status}'`,
      code: 'JOB_ALREADY_TERMINAL',
      status: job.status,
    });
  }

  // Snapshot the pre-cancel status for the audit log. Capturing here
  // rather than reading job.status after cancelJob() means the audit
  // log accurately records what the job was BEFORE the cancel,
  // regardless of whether getJobStatus returns shared or fresh state.
  const previousStatus = job.status;

  let applied;
  try {
    applied = oodaJobs.cancelJob(req.params.id, req.user.id);
  } catch (err) {
    logger.error('Generation job cancel failed', { id: req.params.id, error: err.message });
    return res.status(500).json({ error: 'Failed to cancel generation job' });
  }
  // Race condition: between the getJobStatus and cancelJob calls, the
  // worker may have completed/failed the job. Surface this as 409.
  if (!applied) {
    return res.status(409).json({
      error: 'Job transitioned to terminal state during cancellation request',
      code: 'JOB_ALREADY_TERMINAL',
    });
  }

  auditLog(
    req.user.id,
    'OODA_GEN_JOB_CANCEL_REQUESTED',
    `id=${req.params.id} previous_status=${previousStatus}`,
    req.ip
  );

  return res.json({
    job_id: req.params.id,
    status: 'cancelled',
    note: 'Best-effort cancel: worker stops at next scenario boundary. In-flight LLM call (if any) completes.',
  });
});

module.exports = router;

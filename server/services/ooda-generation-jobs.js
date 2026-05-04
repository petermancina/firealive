// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — OODA Scenario Generation Jobs (Phase F4c)
//
// Background worker that generates OODA Loop scenarios asynchronously.
// Decouples scenario generation (slow, AI-dependent, can fail) from the
// HTTP request lifecycle. Routes enqueue jobs and return immediately;
// the worker picks them up, calls the existing scenario generator one
// scenario at a time, and persists each scenario to ooda_scenarios as
// it completes.
//
// ── Why background work ────────────────────────────────────────────────
//
// The existing routes/ooda.js POST /generate endpoint is synchronous —
// the caller waits while the LLM call runs (up to 90s timeout). This
// works for one-off "generate one scenario" requests but is a poor fit
// for the threshold-replenishment and initial-upload flows established
// in Phase F4c, which need to generate batches of scenarios. Holding an
// HTTP connection open for 5+ minutes while 15 scenarios are generated
// serially is fragile and rude to clients.
//
// ── Concurrency model ──────────────────────────────────────────────────
//
// Bounded in-process worker, default cap of 2 concurrent jobs (env-
// overrideable via OODA_JOB_CONCURRENCY). At the cap, additional queued
// jobs wait their turn. The worker polls the ooda_generation_jobs table
// every OODA_JOB_TICK_MS milliseconds (default 2s) for new queued
// jobs.
//
// The worker communicates with the rest of the application ONLY through
// the database — it doesn't share in-process state with the API server,
// doesn't accept callbacks, doesn't fire events. This is intentional:
// if we ever need to convert the worker to a separate process for
// scale or isolation reasons, it's a deployment change rather than a
// code change. Routes enqueue jobs by writing to the table; the worker
// reads pending jobs from the table; the UI reads job progress from the
// table; cancellation is a status update on the table.
//
// ── Crash recovery ─────────────────────────────────────────────────────
//
// On startup, the worker transitions any rows in 'running' status back
// to 'queued' (these jobs were running when the previous server
// instance was killed). Their progress_json field reflects how many
// scenarios were already persisted before the crash, so resumption
// continues from where it left off without re-generating completed
// scenarios.
//
// ── Generation strategy ────────────────────────────────────────────────
//
// Each job specifies target_count_per_difficulty (1-20). The worker
// generates that many scenarios for EACH of the three difficulty levels
// (beginner, intermediate, advanced), distributing scenario types
// round-robin across the 8 valid scenario types so the resulting pool
// has good type diversity. Total scenarios per job:
//   3 * target_count_per_difficulty
//
// Per-scenario persistence: each generated scenario is INSERTed into
// ooda_scenarios as soon as the LLM returns (and the tree validates).
// progress_json on the job row is updated incrementally to reflect
// completion. This means a job that fails after generating 8/15
// scenarios leaves 8 USABLE scenarios behind — analysts can play those
// while the lead investigates the failure and (optionally) re-enqueues.
//
// ── Job lifecycle states ───────────────────────────────────────────────
//
//   queued    — waiting to be picked up by a worker slot
//   running   — currently generating; progress_json updates per scenario
//   done      — all target scenarios generated successfully
//   failed    — error during generation; partial results persisted,
//               error_message captures the failure reason
//   cancelled — admin cancelled via API; stops at next scenario boundary
//               (in-flight LLM call completes; subsequent scenarios are
//               skipped)
//
// ── Cancellation honor ─────────────────────────────────────────────────
//
// The worker checks the job's status between scenarios. If an admin set
// it to 'cancelled' (via routes/ooda.js POST /generation-jobs/:id
// /cancel), the worker stops generating, persists the
// 'cancelled' state with completed_at, and frees the worker slot. Any
// in-flight LLM call is allowed to complete (since aborting it cleanly
// would require dispatcher-level cancellation support that doesn't
// exist yet; PR #4+ may add it). This means cancellation is best-
// effort: it stops the NEXT scenario from being generated, not the
// current one.
//
// ── Job timeout ────────────────────────────────────────────────────────
//
// Each individual scenario generation call (one LLM round-trip) has its
// own 90s timeout enforced by the existing dispatcher. The WORKER
// imposes a wall-clock timeout per job (default 5min, env-overrideable
// via OODA_JOB_TIMEOUT_MS) — if the job is still running after that,
// the worker marks it 'failed' with a timeout error and frees the
// slot. This caps the impact of a stuck or slow AI provider.
//
// Phase F4c — IR Simulator backend gating + generation jobs.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');
const { generateScenario } = require('./ooda-scenario-generator');

const VALID_TYPES = [
  'ransomware', 'phishing', 'data_exfil', 'insider_threat',
  'apt', 'ddos', 'supply_chain', 'credential_compromise',
];
const VALID_DIFFICULTIES = ['beginner', 'intermediate', 'advanced'];
const VALID_MODES = ['initial_upload', 'manual', 'threshold', 'scheduled'];

const DEFAULT_CONCURRENCY = 2;
const DEFAULT_TICK_MS = 2000;          // 2 second poll interval
const DEFAULT_JOB_TIMEOUT_MS = 300000; // 5 minute per-job wall-clock cap
const MIN_TICK_MS = 200;
const MAX_TICK_MS = 60000;

function readConcurrency() {
  const raw = parseInt(process.env.OODA_JOB_CONCURRENCY, 10);
  if (Number.isFinite(raw) && raw >= 1 && raw <= 8) return raw;
  return DEFAULT_CONCURRENCY;
}

function readTickMs() {
  const raw = parseInt(process.env.OODA_JOB_TICK_MS, 10);
  if (Number.isFinite(raw) && raw >= MIN_TICK_MS && raw <= MAX_TICK_MS) return raw;
  return DEFAULT_TICK_MS;
}

function readJobTimeoutMs() {
  const raw = parseInt(process.env.OODA_JOB_TIMEOUT_MS, 10);
  if (Number.isFinite(raw) && raw >= 30000 && raw <= 3600000) return raw;
  return DEFAULT_JOB_TIMEOUT_MS;
}

// ── Public API ──────────────────────────────────────────────────────────────

// Enqueue a new generation job. Returns the new job id.
//
// args:
//   policy_id (string, required)            — must reference an existing ir_policies row
//   mode (string, required)                 — VALID_MODES
//   target_count_per_difficulty (int, 1-20) — scenarios per difficulty level
//   enqueued_by (string, optional)          — user id for attribution
function enqueueJob(args) {
  if (!args || typeof args !== 'object') {
    throw new Error('enqueueJob requires args object');
  }
  const { policy_id, mode, target_count_per_difficulty, enqueued_by } = args;
  if (typeof policy_id !== 'string' || policy_id.length === 0) {
    throw new Error('policy_id is required');
  }
  if (!VALID_MODES.includes(mode)) {
    throw new Error(`mode must be one of: ${VALID_MODES.join(', ')}`);
  }
  const target = parseInt(target_count_per_difficulty, 10);
  if (!Number.isInteger(target) || target < 1 || target > 20) {
    throw new Error('target_count_per_difficulty must be an integer between 1 and 20');
  }

  const db = getDb();
  try {
    // Verify the policy exists; rejecting at enqueue time is much friendlier
    // than letting the job run and fail
    const policy = db.prepare('SELECT id FROM ir_policies WHERE id = ?').get(policy_id);
    if (!policy) {
      throw new Error(`policy not found: ${policy_id}`);
    }
    const id = crypto.randomBytes(16).toString('hex');
    db.prepare(`
      INSERT INTO ooda_generation_jobs
        (id, policy_id, status, mode, target_count_per_difficulty, progress_json, enqueued_by)
      VALUES (?, ?, 'queued', ?, ?, '[]', ?)
    `).run(id, policy_id, mode, target, enqueued_by || null);
    return id;
  } finally {
    db.close();
  }
}

// Get a job's current status. Returns null if not found.
function getJobStatus(id) {
  if (typeof id !== 'string' || id.length === 0) {
    throw new Error('id is required');
  }
  const db = getDb();
  try {
    const row = db.prepare(`
      SELECT id, policy_id, status, mode, target_count_per_difficulty,
             progress_json, enqueued_by, enqueued_at, started_at,
             completed_at, error_message, provider
      FROM ooda_generation_jobs WHERE id = ?
    `).get(id);
    if (!row) return null;
    return normalizeJobRow(row);
  } finally {
    db.close();
  }
}

// List jobs filtered by policy, status, or both. Most recent first.
// limit defaults to 50, capped at 200.
function listJobs(filter) {
  filter = filter || {};
  const limit = Math.min(200, Math.max(1, parseInt(filter.limit, 10) || 50));

  const where = [];
  const params = [];
  if (filter.policy_id) {
    where.push('policy_id = ?');
    params.push(filter.policy_id);
  }
  if (filter.status) {
    where.push('status = ?');
    params.push(filter.status);
  }
  const whereClause = where.length > 0 ? 'WHERE ' + where.join(' AND ') : '';

  const db = getDb();
  try {
    const rows = db.prepare(`
      SELECT id, policy_id, status, mode, target_count_per_difficulty,
             progress_json, enqueued_by, enqueued_at, started_at,
             completed_at, error_message, provider
      FROM ooda_generation_jobs
      ${whereClause}
      ORDER BY enqueued_at DESC
      LIMIT ?
    `).all(...params, limit);
    return rows.map(normalizeJobRow);
  } finally {
    db.close();
  }
}

// Cancel a job. Pending jobs are marked cancelled immediately. Running
// jobs are marked cancelled and the worker stops at the next scenario
// boundary. Already-finished jobs return false. Returns true if the
// cancellation was applied (status changed to 'cancelled').
function cancelJob(id, cancelled_by) {
  if (typeof id !== 'string' || id.length === 0) {
    throw new Error('id is required');
  }
  const db = getDb();
  try {
    const row = db.prepare('SELECT status FROM ooda_generation_jobs WHERE id = ?').get(id);
    if (!row) return false;
    if (row.status !== 'queued' && row.status !== 'running') return false;

    db.prepare(`
      UPDATE ooda_generation_jobs
      SET status = 'cancelled',
          completed_at = datetime('now'),
          error_message = ?
      WHERE id = ?
    `).run(`cancelled by ${cancelled_by || 'unknown'}`, id);
    return true;
  } finally {
    db.close();
  }
}

// Idempotent. Crash recovery + worker loop launch. Called from the
// scheduler service at server startup.
let _started = false;
let _shuttingDown = false;
let _activeSlots = 0;
let _tickTimer = null;
const _runningJobs = new Map();        // id -> { startedAt, timeoutHandle }

function start() {
  if (_started) return { alreadyStarted: true };
  _started = true;
  _shuttingDown = false;

  recoverOrphanedJobs();
  scheduleTick();

  logger.info('OODA generation jobs worker started', {
    concurrency: readConcurrency(),
    tickMs: readTickMs(),
    jobTimeoutMs: readJobTimeoutMs(),
  });
  return { alreadyStarted: false };
}

// Idempotent. Called from process SIGTERM/SIGINT handlers. Stops new
// jobs from being picked up but lets in-flight jobs run to completion.
function shutdown() {
  _shuttingDown = true;
  if (_tickTimer) {
    clearTimeout(_tickTimer);
    _tickTimer = null;
  }
}

// ── Internals ───────────────────────────────────────────────────────────────

// Crash recovery: any rows in 'running' status from the previous
// process are orphaned. Transition them back to 'queued' so the worker
// picks them up. progress_json is preserved — already-persisted
// scenarios stay persisted; only un-generated scenarios will be
// generated on resume.
function recoverOrphanedJobs() {
  const db = getDb();
  try {
    const orphaned = db.prepare(`
      SELECT id FROM ooda_generation_jobs WHERE status = 'running'
    `).all();
    if (orphaned.length === 0) return;
    db.prepare(`
      UPDATE ooda_generation_jobs
      SET status = 'queued',
          started_at = NULL,
          error_message = COALESCE(error_message, '')
            || ' [resumed after server restart]'
      WHERE status = 'running'
    `).run();
    logger.info('OODA generation jobs: orphaned jobs recovered', {
      count: orphaned.length,
    });
  } catch (err) {
    logger.error('OODA generation jobs: orphan recovery failed', { error: err.message });
  } finally {
    db.close();
  }
}

function scheduleTick() {
  if (_shuttingDown) return;
  _tickTimer = setTimeout(tick, readTickMs());
}

// One tick: while there's free worker capacity AND queued jobs, pick
// up jobs and start them in parallel. Each job runs as an independent
// async function that frees its slot when complete.
function tick() {
  if (_shuttingDown) return;
  try {
    const cap = readConcurrency();
    while (_activeSlots < cap) {
      const job = claimNextJob();
      if (!job) break;
      _activeSlots++;
      runJob(job)
        .catch(err => {
          logger.error('OODA generation jobs: runJob threw unexpectedly', {
            jobId: job.id, error: err.message, stack: err.stack,
          });
        })
        .finally(() => {
          _activeSlots--;
        });
    }
  } catch (err) {
    logger.error('OODA generation jobs: tick failed', { error: err.message });
  } finally {
    scheduleTick();
  }
}

// Atomically claim the oldest queued job by transitioning it to
// 'running'. Returns the claimed row or null if none available. The
// SQLite better-sqlite3 driver runs in-process and is single-threaded
// from our perspective, so this read-then-update is safe in the
// in-process worker model — there's no other process competing for
// the same job. (When/if we move to a separate-process worker, this
// claim would need to be wrapped in BEGIN IMMEDIATE TRANSACTION.)
function claimNextJob() {
  const db = getDb();
  try {
    const next = db.prepare(`
      SELECT id, policy_id, mode, target_count_per_difficulty, progress_json
      FROM ooda_generation_jobs
      WHERE status = 'queued'
      ORDER BY enqueued_at ASC
      LIMIT 1
    `).get();
    if (!next) return null;
    db.prepare(`
      UPDATE ooda_generation_jobs
      SET status = 'running', started_at = datetime('now')
      WHERE id = ? AND status = 'queued'
    `).run(next.id);
    return next;
  } finally {
    db.close();
  }
}

// Run a single job to completion. Generates scenarios one at a time,
// persisting each to ooda_scenarios and updating progress_json on the
// job row. Honors cancellation between scenarios. Imposes a wall-clock
// timeout. Always transitions the job to a terminal status (done,
// failed, or cancelled) before returning.
async function runJob(job) {
  const startedAt = Date.now();
  const timeoutMs = readJobTimeoutMs();
  const target = job.target_count_per_difficulty;
  const totalScenarios = target * VALID_DIFFICULTIES.length;

  // Restore progress from a possibly-resumed job. progress_json is an
  // array of {difficulty, type, scenarioId, status, error?} entries
  // covering the scenarios we've ALREADY attempted. We pick up where
  // it left off.
  let progress;
  try {
    progress = JSON.parse(job.progress_json || '[]');
    if (!Array.isArray(progress)) progress = [];
  } catch { progress = []; }

  let providerSummary = null;
  let typeIdx = 0;
  let scenariosFailed = 0;

  try {
    for (const difficulty of VALID_DIFFICULTIES) {
      const alreadyForThisDifficulty = progress.filter(
        p => p.difficulty === difficulty && p.status === 'done'
      ).length;
      for (let i = alreadyForThisDifficulty; i < target; i++) {
        // Cancellation check
        if (await isJobCancelled(job.id)) {
          await persistJobTerminal(job.id, 'cancelled', progress, providerSummary, null);
          return;
        }
        // Timeout check
        if (Date.now() - startedAt >= timeoutMs) {
          await persistJobTerminal(
            job.id, 'failed', progress, providerSummary,
            `wall-clock timeout (${timeoutMs}ms)`
          );
          return;
        }

        const scenarioType = VALID_TYPES[typeIdx % VALID_TYPES.length];
        typeIdx++;

        const entry = { difficulty, type: scenarioType, status: 'pending' };
        progress.push(entry);

        try {
          const result = await generateScenario({
            scenarioType,
            difficulty,
            policyIds: [job.policy_id],
            userId: null,
          });
          const scenarioId = await persistScenario(result, job.policy_id);
          entry.scenarioId = scenarioId;
          entry.status = 'done';
          if (!providerSummary && result.provider) {
            providerSummary = result.modelName
              ? `${result.provider}/${result.modelName}`
              : result.provider;
          }
        } catch (err) {
          entry.status = 'failed';
          entry.error = (err && err.code) ? err.code : (err && err.message) || 'unknown';
          scenariosFailed++;
          logger.warn('OODA generation jobs: scenario generation failed', {
            jobId: job.id, scenarioType, difficulty,
            error: err.message, code: err.code,
          });

          // If the AI provider isn't configured at all, there's no point
          // attempting more scenarios. Fail the whole job fast.
          if (err && err.code === 'AI_NOT_CONFIGURED') {
            await persistJobTerminal(
              job.id, 'failed', progress, providerSummary,
              'AI provider not configured (AI_NOT_CONFIGURED)'
            );
            return;
          }
        }

        await updateProgress(job.id, progress);
      }
    }

    // All target scenarios attempted; mark done. Note we mark done even
    // if some scenarios failed individually — the job ran to completion,
    // partial output is still useful, and the audit log captures the
    // mixed outcome.
    const status = scenariosFailed === totalScenarios ? 'failed' : 'done';
    const errorMsg = scenariosFailed > 0
      ? `${scenariosFailed}/${totalScenarios} scenarios failed during generation`
      : null;
    await persistJobTerminal(job.id, status, progress, providerSummary, errorMsg);

    auditLog(
      job.enqueued_by || null,
      status === 'done' ? 'OODA_GEN_JOB_COMPLETED' : 'OODA_GEN_JOB_FAILED',
      `id=${job.id} mode=${job.mode} policy=${job.policy_id}`
        + ` succeeded=${totalScenarios - scenariosFailed}/${totalScenarios}`
        + ` latency_ms=${Date.now() - startedAt}`,
      null
    );
  } catch (err) {
    logger.error('OODA generation jobs: job execution failed', {
      jobId: job.id, error: err.message, stack: err.stack,
    });
    await persistJobTerminal(
      job.id, 'failed', progress, providerSummary,
      `worker error: ${err.message}`
    );
  }
}

function isJobCancelled(jobId) {
  const db = getDb();
  try {
    const row = db.prepare('SELECT status FROM ooda_generation_jobs WHERE id = ?').get(jobId);
    return row && row.status === 'cancelled';
  } finally {
    db.close();
  }
}

function updateProgress(jobId, progress) {
  const db = getDb();
  try {
    db.prepare(`
      UPDATE ooda_generation_jobs
      SET progress_json = ?
      WHERE id = ? AND status = 'running'
    `).run(JSON.stringify(progress), jobId);
  } finally {
    db.close();
  }
}

function persistJobTerminal(jobId, status, progress, provider, errorMessage) {
  const db = getDb();
  try {
    db.prepare(`
      UPDATE ooda_generation_jobs
      SET status = ?,
          progress_json = ?,
          completed_at = datetime('now'),
          provider = COALESCE(?, provider),
          error_message = COALESCE(?, error_message)
      WHERE id = ?
    `).run(status, JSON.stringify(progress), provider, errorMessage, jobId);
  } finally {
    db.close();
  }
}

// Persist a single generated scenario to ooda_scenarios. Mirrors the
// pattern in routes/ooda.js POST /generate exactly so generated
// scenarios behave identically regardless of code path. created_by is
// the job's enqueuer (so audit traces can follow the chain
// "user enqueued job → job generated scenario").
function persistScenario(result, sourcePolicyId) {
  const id = crypto.randomBytes(16).toString('hex');
  const treeJson = JSON.stringify(result.tree);
  const sourcePolicyIdsJson = JSON.stringify(result.sourcePolicyIds || [sourcePolicyId]);
  const generatedByProvider = result.modelName
    ? `${result.provider}/${result.modelName}`
    : result.provider;

  const db = getDb();
  try {
    // The job's enqueued_by was already validated at enqueue time; we
    // use a system attribution here since the worker doesn't carry a
    // request user. Audit trail still ties back via the job's
    // enqueued_by → completed_at chain.
    db.prepare(`
      INSERT INTO ooda_scenarios
        (id, title, scenario_type, difficulty, tree, node_count,
         generated_by_provider, source_policy_ids, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      id,
      result.tree.title || 'Generated Scenario',
      result.tree.scenarioType,
      result.tree.difficulty,
      treeJson,
      result.tree.nodeCount || 0,
      generatedByProvider || null,
      sourcePolicyIdsJson,
      'system-worker'
    );
    return id;
  } finally {
    db.close();
  }
}

function normalizeJobRow(row) {
  let progress = [];
  try {
    progress = JSON.parse(row.progress_json || '[]');
    if (!Array.isArray(progress)) progress = [];
  } catch { progress = []; }
  const completed = progress.filter(p => p.status === 'done').length;
  const failed = progress.filter(p => p.status === 'failed').length;
  const total = row.target_count_per_difficulty * VALID_DIFFICULTIES.length;

  return {
    id: row.id,
    policy_id: row.policy_id,
    status: row.status,
    mode: row.mode,
    target_count_per_difficulty: row.target_count_per_difficulty,
    total_scenarios: total,
    scenarios_completed: completed,
    scenarios_failed: failed,
    progress,
    enqueued_by: row.enqueued_by,
    enqueued_at: row.enqueued_at,
    started_at: row.started_at,
    completed_at: row.completed_at,
    error_message: row.error_message,
    provider: row.provider,
  };
}

module.exports = {
  enqueueJob,
  getJobStatus,
  listJobs,
  cancelJob,
  start,
  shutdown,
  // Constants exposed for routes/UI consistency
  VALID_MODES,
  VALID_TYPES,
  VALID_DIFFICULTIES,
  // Internals exposed for unit testing
  _internal: {
    recoverOrphanedJobs,
    claimNextJob,
    runJob,
    normalizeJobRow,
    readConcurrency,
    readTickMs,
    readJobTimeoutMs,
  },
};

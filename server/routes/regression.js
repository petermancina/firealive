// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Regression Routes (R3k C5)
//
// Single canonical endpoint for the on-demand regression suite.
//
//   POST /api/regression/run
//     Triggers the full RegressionRunner battery (services/regression-
//     runner.js, rewritten in R3k C4). Returns the structured result
//     and writes a semantic REGRESSION_RUN entry to the audit log
//     with the pass/total summary.
//
// MOUNT
// =====
// Mounted at /api/regression in server/index.js (R3k C6) behind
// authMiddleware(['admin']). The mount-level role gate satisfies all
// in-router protection; no per-handler role re-check.
//
// The endpoint is intentionally admin-only. The regression suite
// probes secrets-adjacent state (KMS round-trip, JWT_SECRET presence,
// signing-key inventories, integration_config row counts) and the
// result detail strings expose information about install posture that
// should not flow to lead/analyst roles. Lead-facing system health
// summaries route through different surfaces (e.g., /api/system/*).
//
// DESIGN NOTES
// ============
//
// 1. Synchronous. The runner is synchronous (better-sqlite3 + crypto
//    primitives all sync). No async wrapper needed; Express
//    happily awaits a synchronous handler.
//
// 2. Pass/fail summary in the audit log detail. Storing the full
//    results array in the audit log would balloon the table with
//    one ~25 KB entry per run. Instead the audit entry captures
//    {total, passed, failed, failures_count, ranAt, version, fuse}
//    so the audit trail records that a run happened and its outcome
//    without persisting the detail strings. Operators investigating
//    a specific failure use the API response (live) or re-run.
//
// 3. Errors are surfaced, not swallowed. If the runner itself
//    throws (a defect in the runner, not a check failure), the
//    handler returns 500 with the error message. Individual check
//    failures are normal and return 200 with status='fail' in the
//    results array.
//
// 4. Audit-write failures don't fail the response. Standard
//    canonical pattern (matches backup-schedules.js writeAuditEvent):
//    audit-log write errors are logged at warn level and swallowed
//    so a transient audit failure doesn't mask a successful regression
//    run.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { RegressionRunner } = require('../services/regression-runner');

function writeAuditEvent(req, eventType, detail) {
  try {
    const db = getDb();
    db.prepare(
      `INSERT INTO audit_log (user_id, event_type, detail, ip_address)
         VALUES (?, ?, ?, ?)`
    ).run(
      req.user ? req.user.id : null,
      eventType,
      JSON.stringify(detail || {}),
      req.ip || null,
    );
  } catch (auditErr) {
    logger.warn('regression audit-log write failed', {
      eventType,
      error: auditErr.message,
    });
  }
}

router.post('/run', async (req, res) => {
  let result;
  try {
    const db = getDb();
    const runner = new RegressionRunner(db);
    result = await runner.run();
  } catch (runErr) {
    logger.error('regression run failed at top level', { error: runErr.message });
    return res.status(500).json({
      error: 'regression_run_failed',
      detail: runErr.message,
    });
  }

  writeAuditEvent(req, 'REGRESSION_RUN', {
    total: result.total,
    passed: result.passed,
    failed: result.failed,
    failures_count: result.failures ? result.failures.length : result.failed,
    ranAt: result.ranAt,
    version: result.version,
    fuse: result.fuse,
  });

  return res.status(200).json(result);
});

module.exports = router;

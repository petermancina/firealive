// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — CI/CD Routes (R3k C24)
//
// Canonical endpoints for the CI/CD pipeline-config generator
// (Sub-phase 5).
//
//   GET  /api/cicd/platforms              list supported CI platforms
//   POST /api/cicd/generate               generate pipeline config
//   GET  /api/cicd/configs                list past configs
//   GET  /api/cicd/configs/:id            fetch config detail
//   GET  /api/cicd/configs/:id/download   download generated pipeline
//   POST /api/cicd/runs                   webhook receiver from external CI
//   GET  /api/cicd/runs                   list incoming run records
//   GET  /api/cicd/runs/:id               fetch run detail
//
// AUTH MODEL (dual)
// =================
//
// Mounted in server/index.js (C24 mount edit) with:
//
//   app.use('/api/cicd', authMiddleware(['admin']), require('./routes/cicd'));
//
// authMiddleware admits two paths:
//   1. JWT Bearer with role=admin (the normal user-facing path)
//   2. x-api-key (which sets req.user.apiKey = true and req.user.scopes
//      from the api_keys row; bypasses the role check by design)
//
// Per-endpoint splits:
//
//   - POST /runs    requires api-key + cicd:webhook scope. JWTs are
//                   rejected at handler entry (requireApiKeyCicdWebhook
//                   below). Compromised api-key with this scope can
//                   only INSERT cicd_runs rows; cannot read pipeline
//                   configs or trigger generation.
//
//   - all other     require JWT admin. api-keys are rejected at handler
//                   entry (requireJwtAdmin below) so the cicd:webhook
//                   key cannot exfiltrate snapshot data or trigger
//                   generation.
//
// Matches R3j's /api/routing dual-auth split (routing:read for the
// polling endpoint, routing:events for the webhook receiver,
// lead/admin JWT for everything else).
//
// IDEMPOTENCY
// ===========
//
// POST /runs collides on the composite UNIQUE index
// (platform, external_run_id) from R3k C1; the handler catches the
// SQLITE_CONSTRAINT_UNIQUE error and returns 200 with
// {idempotent: true, run_id} rather than 409.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const fs = require('fs');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const cicdGenerator = require('../services/cicd-generator');

// ── Per-endpoint auth gates ────────────────────────────────────────────

function requireJwtAdmin(req, res, next) {
  if (req.user && req.user.apiKey) {
    return res.status(403).json({ error: 'JWT authentication required on this endpoint' });
  }
  next();
}

function requireApiKeyCicdWebhook(req, res, next) {
  if (!req.user || !req.user.apiKey) {
    return res.status(403).json({ error: 'API key authentication required on this endpoint' });
  }
  if (!req.user.scopes || !req.user.scopes.includes('cicd:webhook')) {
    return res.status(403).json({ error: 'Scope cicd:webhook required' });
  }
  next();
}

// ── GET /platforms ─────────────────────────────────────────────────────

router.get('/platforms', requireJwtAdmin, (req, res) => {
  res.json({
    platforms: cicdGenerator.VALID_PLATFORMS,
    purposes: cicdGenerator.VALID_PURPOSES,
    filenames: cicdGenerator.PLATFORM_FILENAME,
  });
});

// ── POST /generate ─────────────────────────────────────────────────────

router.post('/generate', requireJwtAdmin, (req, res) => {
  const { platform, purpose } = req.body || {};
  if (!platform || !purpose) {
    return res.status(400).json({
      error: 'platform and purpose are required',
      valid_platforms: cicdGenerator.VALID_PLATFORMS,
      valid_purposes: cicdGenerator.VALID_PURPOSES,
    });
  }

  try {
    const db = getDb();
    const result = cicdGenerator.generateConfig(db, platform, purpose, {
      userId: req.user.id,
    });
    auditLog(
      req.user.id,
      'CICD_CONFIG_GENERATED',
      `id=${result.id} platform=${platform} purpose=${purpose}`,
      req.ip,
    );
    res.json(result);
  } catch (err) {
    logger.error('cicd generate failed', { error: err.message });
    auditLog(req.user.id, 'CICD_CONFIG_FAILED', `platform=${platform} error=${err.message.slice(0, 200)}`, req.ip);
    if (/^invalid (platform|purpose)/.test(err.message)) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'cicd generation failed', message: err.message });
  }
});

// ── GET /configs ───────────────────────────────────────────────────────

router.get('/configs', requireJwtAdmin, (req, res) => {
  try {
    const db = getDb();
    const rows = db
      .prepare(
        `SELECT id, platform, purpose, generated_at, generated_yaml_path, created_by
           FROM cicd_configs
           ORDER BY generated_at DESC
           LIMIT 100`,
      )
      .all();
    res.json({ configs: rows });
  } catch (err) {
    logger.error('cicd configs list failed', { error: err.message });
    res.status(500).json({ error: 'configs list failed', message: err.message });
  }
});

router.get('/configs/:id', requireJwtAdmin, (req, res) => {
  try {
    const db = getDb();
    const row = db
      .prepare(`SELECT * FROM cicd_configs WHERE id = ?`)
      .get(req.params.id);
    if (!row) return res.status(404).json({ error: 'config not found' });
    // Parse snapshot for friendlier JSON response shape
    let snapshot = null;
    try { snapshot = JSON.parse(row.current_install_snapshot_json); } catch (e) { /* leave null */ }
    res.json({ ...row, install_snapshot: snapshot });
  } catch (err) {
    logger.error('cicd config fetch failed', { error: err.message });
    res.status(500).json({ error: 'config fetch failed', message: err.message });
  }
});

router.get('/configs/:id/download', requireJwtAdmin, (req, res) => {
  try {
    const db = getDb();
    const row = db
      .prepare(`SELECT platform, generated_yaml_path FROM cicd_configs WHERE id = ?`)
      .get(req.params.id);
    if (!row) return res.status(404).json({ error: 'config not found' });
    if (!fs.existsSync(row.generated_yaml_path)) {
      return res.status(410).json({ error: 'pipeline file no longer on disk' });
    }
    const filename = cicdGenerator.PLATFORM_FILENAME[row.platform] || 'pipeline.yml';
    const downloadName = filename.split('/').pop();
    res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);
    res.setHeader('Content-Type', 'text/yaml');
    fs.createReadStream(row.generated_yaml_path).pipe(res);
  } catch (err) {
    logger.error('cicd config download failed', { error: err.message });
    res.status(500).json({ error: 'download failed', message: err.message });
  }
});

// ── POST /runs (webhook receiver) ──────────────────────────────────────

router.post('/runs', requireApiKeyCicdWebhook, (req, res) => {
  const {
    external_run_id, platform, config_id, status,
    started_at, finished_at, commit_sha, branch,
    step_results, ci_metadata,
  } = req.body || {};

  const missing = [];
  if (!external_run_id) missing.push('external_run_id');
  if (!platform) missing.push('platform');
  if (!status) missing.push('status');
  if (!started_at) missing.push('started_at');
  if (missing.length > 0) {
    return res.status(400).json({ error: 'Missing required fields', fields: missing });
  }

  if (!cicdGenerator.VALID_PLATFORMS.includes(platform)) {
    return res.status(400).json({ error: 'Invalid platform', valid: cicdGenerator.VALID_PLATFORMS });
  }

  const VALID_STATUSES = ['queued', 'running', 'passed', 'failed', 'cancelled'];
  if (!VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: 'Invalid status', valid: VALID_STATUSES });
  }

  try {
    const db = getDb();
    // Insert with raw payload preserved verbatim for forensic
    // inspection; the typed columns mirror the most-queried fields.
    db.prepare(
      `INSERT INTO cicd_runs
         (external_run_id, platform, config_id, status, started_at,
          finished_at, commit_sha, branch, step_results_json,
          ci_metadata_json, received_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
    ).run(
      external_run_id,
      platform,
      config_id || null,
      status,
      started_at,
      finished_at || null,
      commit_sha || null,
      branch || null,
      step_results ? JSON.stringify(step_results) : null,
      ci_metadata ? JSON.stringify(ci_metadata) : null,
    );

    const inserted = db
      .prepare(
        `SELECT id, received_at FROM cicd_runs
           WHERE platform = ? AND external_run_id = ?`,
      )
      .get(platform, external_run_id);

    logger.info('cicd-runs: received run status', {
      run_id: inserted.id,
      external_run_id,
      platform,
      status,
    });

    res.json({
      received: true,
      idempotent: false,
      run_id: inserted.id,
      received_at: inserted.received_at,
    });
  } catch (err) {
    // SQLite raises SQLITE_CONSTRAINT_UNIQUE on duplicate
    // (platform, external_run_id). Convert to idempotent 200.
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || /UNIQUE constraint/i.test(err.message)) {
      try {
        const db = getDb();
        const existing = db
          .prepare(
            `SELECT id, received_at FROM cicd_runs
               WHERE platform = ? AND external_run_id = ?`,
          )
          .get(platform, external_run_id);
        return res.json({
          received: true,
          idempotent: true,
          run_id: existing ? existing.id : null,
          received_at: existing ? existing.received_at : null,
        });
      } catch (lookupErr) {
        logger.error('cicd-runs idempotency lookup failed', { error: lookupErr.message });
      }
    }
    logger.error('cicd-runs insert failed', { error: err.message });
    res.status(500).json({ error: 'cicd run insert failed', message: err.message });
  }
});

router.get('/runs', requireJwtAdmin, (req, res) => {
  try {
    const db = getDb();
    const rows = db
      .prepare(
        `SELECT id, external_run_id, platform, config_id, status,
                started_at, finished_at, commit_sha, branch, received_at
           FROM cicd_runs
           ORDER BY received_at DESC
           LIMIT 200`,
      )
      .all();
    res.json({ runs: rows });
  } catch (err) {
    logger.error('cicd runs list failed', { error: err.message });
    res.status(500).json({ error: 'runs list failed', message: err.message });
  }
});

router.get('/runs/:id', requireJwtAdmin, (req, res) => {
  try {
    const db = getDb();
    const row = db
      .prepare(`SELECT * FROM cicd_runs WHERE id = ?`)
      .get(req.params.id);
    if (!row) return res.status(404).json({ error: 'run not found' });
    let stepResults = null;
    let ciMeta = null;
    try { stepResults = row.step_results_json ? JSON.parse(row.step_results_json) : null; } catch (e) {}
    try { ciMeta = row.ci_metadata_json ? JSON.parse(row.ci_metadata_json) : null; } catch (e) {}
    res.json({ ...row, step_results: stepResults, ci_metadata: ciMeta });
  } catch (err) {
    logger.error('cicd run fetch failed', { error: err.message });
    res.status(500).json({ error: 'run fetch failed', message: err.message });
  }
});

module.exports = router;

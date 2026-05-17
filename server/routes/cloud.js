// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Cloud & IaC Routes (R3k C34)
//
// Canonical endpoints for the MC-side Cloud & IaC generator
// (Sub-phase 4 services / R3k C9-C22). Backfill commit — the
// generator services and 9 template renderers shipped in
// Sub-phase 4 without a routes file; C34 closes that gap so the
// MC frontend wiring (C36+) has a real /api/cloud/* surface to
// call into.
//
//   GET  /api/cloud/providers                provider x iac_tool
//                                            matrix + secrets mapping
//   POST /api/cloud/package                  generate bundle
//                                            body: {provider, iac_tool}
//   GET  /api/cloud/packages                 list past bundles
//                                            (100 most recent)
//   GET  /api/cloud/packages/:id             fetch row + parsed snapshot
//   GET  /api/cloud/packages/:id/download    stream bundle.tar.gz
//   GET  /api/cloud/packages/:id/public-key  retrieve verifier PEM
//   POST /api/cloud/signing-keys/rotate      operator-triggered rotation
//
// AUTH
// ====
//
// Mounted with authMiddleware(['admin']) in server/index.js (C35
// mount edit). authMiddleware admits two paths:
//   1. JWT Bearer with role=admin (the user-facing path)
//   2. x-api-key (bypasses role check; per-endpoint scope checks
//      enforce actual auth)
//
// All cloud endpoints reject api-keys at handler entry via
// requireJwtAdmin. Cloud bundle generation has no api-key use case
// (no webhook receiver, no automated polling) — JWT-only matches
// the operator-driven UX.
//
// ERROR MAPPING
// =============
//
//   SyftNotInstalledError      -> 503 with code SYFT_NOT_INSTALLED
//                                 + install-command message
//   CosignNotInstalledError    -> 503 with code COSIGN_NOT_INSTALLED
//                                 + install-command message
//   invalid provider/tool      -> 400 with valid combinations
//   other                      -> 500
//
// Aligns with the cross-cutting SOC-grade Sigstore-or-503 / SBOM-
// or-503 decisions from R3k C9/C10.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const fs = require('fs');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const cloudIacGenerator = require('../services/cloud-iac-generator');
const cloudIacSigningKeys = require('../services/cloud-iac-signing-keys');

// ── Per-handler auth gate ──────────────────────────────────────────────

function requireJwtAdmin(req, res, next) {
  if (req.user && req.user.apiKey) {
    return res.status(403).json({ error: 'JWT authentication required on this endpoint' });
  }
  next();
}

// ── GET /providers ─────────────────────────────────────────────────────

router.get('/providers', requireJwtAdmin, (req, res) => {
  res.json({
    provider_tool_matrix: cloudIacGenerator.PROVIDER_TOOL_MATRIX,
    secrets_mapping: cloudIacGenerator.SECRETS_MAPPING_BY_PROVIDER,
  });
});

// ── POST /package ──────────────────────────────────────────────────────

router.post('/package', requireJwtAdmin, (req, res) => {
  const { provider, iac_tool } = req.body || {};
  if (!provider || !iac_tool) {
    return res.status(400).json({
      error: 'provider and iac_tool are required',
      providers: Object.keys(cloudIacGenerator.PROVIDER_TOOL_MATRIX),
    });
  }

  try {
    const db = getDb();
    const result = cloudIacGenerator.generatePackage(db, provider, iac_tool, { userId: req.user.id });
    auditLog(
      req.user.id,
      'CLOUD_PACKAGE_GENERATED',
      `id=${result.id} provider=${provider} iac_tool=${iac_tool} size=${result.size_bytes} manifestSha=${result.manifest_sha256.slice(0, 16)}`,
      req.ip,
    );
    res.json(result);
  } catch (err) {
    logger.error('cloud package generation failed', { error: err.message, provider, iac_tool });
    auditLog(
      req.user.id,
      'CLOUD_PACKAGE_FAILED',
      `provider=${provider} iac_tool=${iac_tool} error=${(err.message || '').slice(0, 200)}`,
      req.ip,
    );
    if (err.name === 'SyftNotInstalledError' || err.code === 'SYFT_NOT_INSTALLED') {
      return res.status(503).json({ error: 'Syft not installed', message: err.message, code: 'SYFT_NOT_INSTALLED' });
    }
    if (err.name === 'CosignNotInstalledError' || err.code === 'COSIGN_NOT_INSTALLED') {
      return res.status(503).json({ error: 'Cosign not installed', message: err.message, code: 'COSIGN_NOT_INSTALLED' });
    }
    if (/^invalid (provider|\(provider)/.test(err.message)) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Cloud package generation failed', message: err.message });
  }
});

// ── GET /packages ──────────────────────────────────────────────────────

router.get('/packages', requireJwtAdmin, (req, res) => {
  try {
    const db = getDb();
    const rows = db
      .prepare(
        `SELECT id, provider, iac_tool, generated_at, generated_by,
                bundle_archive_path, manifest_sha256, sbom_sha256,
                signature_sha256, signing_key_id, size_bytes
           FROM cloud_packages
           ORDER BY generated_at DESC
           LIMIT 100`,
      )
      .all();
    res.json({ packages: rows });
  } catch (err) {
    logger.error('cloud packages list failed', { error: err.message });
    res.status(500).json({ error: 'packages list failed', message: err.message });
  }
});

router.get('/packages/:id', requireJwtAdmin, (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare('SELECT * FROM cloud_packages WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'package not found' });
    let snapshot = null;
    try { snapshot = JSON.parse(row.install_snapshot_json); } catch (e) { /* leave null */ }
    res.json({ ...row, install_snapshot: snapshot });
  } catch (err) {
    logger.error('cloud package fetch failed', { error: err.message });
    res.status(500).json({ error: 'package fetch failed', message: err.message });
  }
});

router.get('/packages/:id/download', requireJwtAdmin, (req, res) => {
  try {
    const db = getDb();
    const row = db
      .prepare('SELECT bundle_archive_path, provider, iac_tool FROM cloud_packages WHERE id = ?')
      .get(req.params.id);
    if (!row) return res.status(404).json({ error: 'package not found' });
    if (!fs.existsSync(row.bundle_archive_path)) {
      return res.status(410).json({ error: 'bundle archive no longer on disk' });
    }
    const downloadName = `firealive-${row.provider}-${row.iac_tool}-${req.params.id}.tar.gz`;
    res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);
    res.setHeader('Content-Type', 'application/gzip');
    fs.createReadStream(row.bundle_archive_path).pipe(res);
  } catch (err) {
    logger.error('cloud package download failed', { error: err.message });
    res.status(500).json({ error: 'download failed', message: err.message });
  }
});

router.get('/packages/:id/public-key', requireJwtAdmin, (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare('SELECT signing_key_id FROM cloud_packages WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'package not found' });
    const key = cloudIacSigningKeys.getVerificationKey(db, row.signing_key_id);
    if (!key) return res.status(404).json({ error: 'signing key not found' });
    res.json({
      key_id: key.id,
      public_key_pem: key.publicKeyPem,
      algorithm: key.algorithm,
      status: key.status,
      fingerprint_sha256: key.publicKeyFingerprint,
      created_at: key.createdAt,
      rotated_at: key.rotatedAt,
    });
  } catch (err) {
    logger.error('cloud public-key fetch failed', { error: err.message });
    res.status(500).json({ error: 'public-key fetch failed', message: err.message });
  }
});

// ── POST /signing-keys/rotate ──────────────────────────────────────────

router.post('/signing-keys/rotate', requireJwtAdmin, (req, res) => {
  try {
    const db = getDb();
    const result = cloudIacSigningKeys.rotateActiveKey(db);
    auditLog(
      req.user.id,
      'CLOUD_SIGNING_KEY_ROTATED',
      `oldId=${result.oldId || '(none)'} newId=${result.newId}`,
      req.ip,
    );
    res.json({ rotated: true, ...result });
  } catch (err) {
    logger.error('cloud signing-key rotation failed', { error: err.message });
    res.status(500).json({ error: 'Signing key rotation failed', message: err.message });
  }
});

module.exports = router;

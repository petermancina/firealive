// FIREALIVE GD -- Cloud & IaC Routes (B6c PR-5 twin)
//
// Canonical /api/cloud/* surface for the GD-side Cloud & IaC generator, replacing
// the inline bundle-based handlers that consumed the monolithic cloud-iac-bundle.
// A twin of the Regional routes/cloud.js, wired to the modular gd-cloud-iac-
// generator + gd-cloud-iac-signing-keys.
//
//   GET  /api/cloud/providers                provider x iac_tool matrix + secrets
//   POST /api/cloud/package                  generate a signed package
//                                            body: {provider, iac_tool}
//   GET  /api/cloud/packages                 list past packages (100 most recent)
//   GET  /api/cloud/packages/:id             fetch row + parsed snapshot
//   GET  /api/cloud/packages/:id/download    stream bundle.tar.gz
//   GET  /api/cloud/packages/:id/public-key  retrieve the verifier PEM
//   POST /api/cloud/signing-keys/rotate      operator-triggered key rotation
//
// Auth: the mount in index.js applies authMiddleware(['ciso','vp']) -- the oversight
// role 'vp' may READ (list/fetch/download/verify), matching how the GD gates every
// comparable security-operational surface (audit logs, compliance, cloud-vuln, cicd
// configs). The two WRITE endpoints (generate package, rotate signing key) step up to
// ciso-only via requireCiso below -- separation of duties: oversight reads, ciso acts.
// The GD is JWT-only here (the api_key path is MC->GD metrics push, not user auth).
// Error mapping matches the SOC-grade contract: Syft/Cosign missing -> 503, bad -> 400.
//
// ASCII only; no template literals in stored strings.

const router = require('express').Router();
const fs = require('fs');
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const cloudIacGenerator = require('../services/gd-cloud-iac-generator');
const cloudIacSigningKeys = require('../services/gd-cloud-iac-signing-keys');

const logger = {
  error: (m, o) => console.error('[gd-cloud] ' + m, o || ''),
};

// Local audit helper: append a queryable event to the GD audit chain on its own
// db handle. Best-effort -- an audit-write failure never changes the response.
function auditLog(userId, eventType, detail, severity) {
  let adb = null;
  try {
    adb = getDb();
    appendGdAuditEntry(adb, { userId: userId || 'anonymous', eventType: eventType, detail: detail || '', severity: severity || 'info' });
  } catch (_e) {
    // swallow
  } finally {
    if (adb) { try { adb.close(); } catch (_e2) { /* ignore */ } }
  }
}

// -- Write step-up: ciso only ------------------------------------------------
// The mount admits ciso + vp; vp is read-only oversight. Package generation and
// signing-key rotation are write actions restricted to ciso. req.user.role is set
// by the mount-level authMiddleware.
function requireCiso(req, res, next) {
  if (!req.user || req.user.role !== 'ciso') {
    return res.status(403).json({ error: 'ciso role required for this action' });
  }
  return next();
}

// -- GET /providers -----------------------------------------------------------

router.get('/providers', (req, res) => {
  res.json({
    provider_tool_matrix: cloudIacGenerator.PROVIDER_TOOL_MATRIX,
    secrets_mapping: cloudIacGenerator.SECRETS_MAPPING_BY_PROVIDER,
  });
});

// -- POST /package ------------------------------------------------------------

router.post('/package', requireCiso, (req, res) => {
  const body = req.body || {};
  const provider = body.provider;
  const iacTool = body.iac_tool;
  if (!provider || !iacTool) {
    return res.status(400).json({
      error: 'provider and iac_tool are required',
      providers: Object.keys(cloudIacGenerator.PROVIDER_TOOL_MATRIX),
    });
  }
  const db = getDb();
  try {
    const result = cloudIacGenerator.generatePackage(db, provider, iacTool, { userId: req.user.id });
    auditLog(req.user.id, 'CLOUD_PACKAGE_GENERATED', 'id=' + result.id + ' provider=' + provider + ' iac_tool=' + iacTool + ' size=' + result.size_bytes, 'info');
    return res.json(result);
  } catch (err) {
    logger.error('cloud package generation failed', { error: err.message, provider: provider, iac_tool: iacTool });
    auditLog(req.user.id, 'CLOUD_PACKAGE_FAILED', 'provider=' + provider + ' iac_tool=' + iacTool + ' error=' + (err.message || '').slice(0, 200), 'warning');
    if (err.name === 'SyftNotInstalledError' || err.code === 'SYFT_NOT_INSTALLED') {
      return res.status(503).json({ error: 'Syft not installed', message: err.message, code: 'SYFT_NOT_INSTALLED' });
    }
    if (err.name === 'CosignNotInstalledError' || err.code === 'COSIGN_NOT_INSTALLED') {
      return res.status(503).json({ error: 'Cosign not installed', message: err.message, code: 'COSIGN_NOT_INSTALLED' });
    }
    if (/^invalid (provider|\(provider)/.test(err.message || '')) {
      return res.status(400).json({ error: err.message });
    }
    return res.status(500).json({ error: 'Cloud package generation failed', message: err.message });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

// -- GET /packages ------------------------------------------------------------

router.get('/packages', (req, res) => {
  const db = getDb();
  try {
    const rows = db
      .prepare(
        'SELECT id, provider, iac_tool, generated_at, generated_by,'
        + ' bundle_archive_path, manifest_sha256, sbom_sha256,'
        + ' signature_sha256, signing_key_id, size_bytes'
        + ' FROM cloud_packages ORDER BY generated_at DESC LIMIT 100',
      )
      .all();
    return res.json({ packages: rows });
  } catch (err) {
    logger.error('cloud packages list failed', { error: err.message });
    return res.status(500).json({ error: 'packages list failed', message: err.message });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

router.get('/packages/:id', (req, res) => {
  const db = getDb();
  try {
    const row = db.prepare('SELECT * FROM cloud_packages WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'package not found' });
    let snapshot = null;
    try { snapshot = JSON.parse(row.install_snapshot_json); } catch (e) { /* leave null */ }
    return res.json(Object.assign({}, row, { install_snapshot: snapshot }));
  } catch (err) {
    logger.error('cloud package fetch failed', { error: err.message });
    return res.status(500).json({ error: 'package fetch failed', message: err.message });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

router.get('/packages/:id/download', (req, res) => {
  const db = getDb();
  try {
    const row = db
      .prepare('SELECT bundle_archive_path, provider, iac_tool FROM cloud_packages WHERE id = ?')
      .get(req.params.id);
    if (!row) return res.status(404).json({ error: 'package not found' });
    if (!fs.existsSync(row.bundle_archive_path)) {
      return res.status(410).json({ error: 'bundle archive no longer on disk' });
    }
    const downloadName = 'firealive-gd-' + row.provider + '-' + row.iac_tool + '-' + req.params.id + '.tar.gz';
    res.setHeader('Content-Disposition', 'attachment; filename="' + downloadName + '"');
    res.setHeader('Content-Type', 'application/gzip');
    return fs.createReadStream(row.bundle_archive_path).pipe(res);
  } catch (err) {
    logger.error('cloud package download failed', { error: err.message });
    return res.status(500).json({ error: 'download failed', message: err.message });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

router.get('/packages/:id/public-key', (req, res) => {
  const db = getDb();
  try {
    const row = db.prepare('SELECT signing_key_id FROM cloud_packages WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'package not found' });
    const key = cloudIacSigningKeys.getVerificationKey(db, row.signing_key_id);
    if (!key) return res.status(404).json({ error: 'signing key not found' });
    return res.json({
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
    return res.status(500).json({ error: 'public-key fetch failed', message: err.message });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

// -- POST /signing-keys/rotate ------------------------------------------------

router.post('/signing-keys/rotate', requireCiso, (req, res) => {
  const db = getDb();
  try {
    const result = cloudIacSigningKeys.rotateActiveKey(db);
    auditLog(req.user.id, 'CLOUD_SIGNING_KEY_ROTATED', 'oldId=' + (result.oldId || '(none)') + ' newId=' + result.newId, 'info');
    return res.json(Object.assign({ rotated: true }, result));
  } catch (err) {
    logger.error('cloud signing-key rotation failed', { error: err.message });
    return res.status(500).json({ error: 'Signing key rotation failed', message: err.message });
  } finally {
    try { db.close(); } catch (_e) { /* ignore */ }
  }
});

module.exports = router;
module.exports.requireCiso = requireCiso;

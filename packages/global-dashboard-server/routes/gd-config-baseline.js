// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- Config Snapshots & Golden-Baseline Routes
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// The single canonical HTTP surface for GD configuration snapshots and the
// portable, secrets-free golden baseline, the GD twin of the Regional Server's
// config-baseline routes. Mounted at /api/config-baseline under
// authMiddleware(['ciso']) with the global config-lock chokepoint (index.js), so
// the whole surface is CISO-only and the mutating endpoints sit behind the config
// lock (registered in gd-config-write-routes.js). Revert and import additionally
// require a fresh MFA step-up.
//
//   GET    /                 list snapshots (+ the retention cap)
//   POST   /                 save a manual snapshot (retention enforced)
//   GET    /keys             list trusted report-signing keys (local +
//                            external); query: ?origin=...
//   POST   /keys/validate    parse a pasted PEM, return its fingerprint for
//                            out-of-band confirmation (no DB write)
//   POST   /keys             register a foreign deployment's public key
//   DELETE /keys/:id         revoke a registered external key
//   POST   /import           import a signed FA-GDGB1 bundle (MFA step-up).
//                            ?dryRun=1 validates without applying. Runs the
//                            gate: scan -> verify signature -> validate ->
//                            pre-import snapshot -> apply, fail-closed.
//   GET    /:id/export       download the snapshot as a signed FA-GDGB1 bundle
//   GET    /:id/diff         change report: current config vs the snapshot
//   POST   /:id/revert       revert to a snapshot (MFA step-up; auto-saves the
//                            current config first)
//   DELETE /:id              delete a snapshot
//
// SIGNING / TRUST MODEL
//   Export signs the snapshot's canonical-payload digest with this deployment's
//   active local Ed25519 report-signing key (reportKeys.signReportDigest) and
//   ships the public key + its fingerprint in the bundle. The bundle is
//   self-verifying.
//
//   Import verifies the signature BY FINGERPRINT against a key already registered
//   in report_signing_keys -- never against the PEM carried in the bundle. A
//   foreign deployment's key must be registered first (operator confirms the
//   fingerprint out of band), which is what makes a cross-deployment import a
//   deliberate trust decision. A revoked external key fails closed
//   (getReportVerificationKey returns null). Same-deployment round-trips work
//   without registration because the local key is present.
// -----------------------------------------------------------------------------

const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const { gdMfaStepUp } = require('../services/gd-mfa-stepup');
const APP_VERSION = require('../package.json').version;
const gb = require('../services/gd-golden-baseline');
const gbValidate = require('../services/gd-golden-baseline-validate');
const reportKeys = require('../services/report-signing-keys');
const { getInstanceLabel, sha256Hex } = require('../services/report-signer');
const { runUploadScans } = require('../services/gd-upload-scan');

// Best-effort audit-chain write; never let an audit failure change the response.
function audit(db, req, eventType, detail) {
  try {
    appendGdAuditEntry(db, {
      userId: req && req.user ? req.user.id : null,
      eventType,
      detail,
      ip: (req && req.ip) || null,
      severity: 'info',
    });
  } catch (_e) { /* best-effort */ }
}

// -- Error mapping -----------------------------------------------------------

function statusForGbError(code) {
  switch (code) {
    case gb.CODES.INVALID_INPUT:
    case gb.CODES.UNSUPPORTED_SCHEMA_VERSION:
      return 400;
    case gb.CODES.SNAPSHOT_NOT_FOUND:
      return 404;
    case gb.CODES.RETENTION_CAP_REACHED:
      return 409;
    default:
      return 500;
  }
}

function statusForSigningKeyError(code) {
  const C = reportKeys.CODES;
  switch (code) {
    case C.INVALID_PEM:
    case C.WRONG_KEY_TYPE:
    case C.WRONG_KEY_USAGE:
    case C.INVALID_INPUT:
      return 400;
    case C.KEY_NOT_FOUND:
      return 404;
    case C.DUPLICATE_FINGERPRINT:
    case C.NOT_EXTERNAL_KEY:
    case C.ALREADY_REVOKED:
      return 409;
    default:
      return 500;
  }
}

function sendError(res, err, op) {
  if (err instanceof gb.GBError) {
    return res.status(statusForGbError(err.code)).json({ error: err.message, code: err.code });
  }
  if (err instanceof reportKeys.SigningKeyError) {
    const body = { error: err.message, code: err.code };
    if (err.details && Object.keys(err.details).length) body.details = err.details;
    return res.status(statusForSigningKeyError(err.code)).json(body);
  }
  if (err instanceof gbValidate.BaselineValidationError) {
    return res.status(400).json({ error: err.message, code: err.code, issues: err.issues });
  }
  console.error(`[gd-config-baseline] ${op} unexpected error: ${err.message}`);
  return res.status(500).json({ error: `Failed to ${op}` });
}

// -- Snapshots: list + save --------------------------------------------------

router.get('/', (req, res) => {
  const db = getDb();
  try {
    res.json({ snapshots: gb.listSnapshots(db), retention: gb.readRetention(db) });
  } catch (err) {
    return sendError(res, err, 'list snapshots');
  } finally {
    db.close();
  }
});

router.post('/', (req, res) => {
  const body = req.body || {};
  const name = typeof body.name === 'string' ? body.name : '';
  const db = getDb();
  try {
    const result = gb.saveSnapshot(db, { name, origin: 'manual', userId: req.user.id });
    audit(db, req, 'CONFIG_SNAPSHOT_SAVED',
      `id=${result.id} name=${JSON.stringify(result.name)} sha256=${result.sha256}`);
    for (const prunedId of result.pruned) {
      audit(db, req, 'CONFIG_SNAPSHOT_PRUNED', `id=${prunedId} reason=retention`);
    }
    res.status(201).json({
      ok: true, id: result.id, name: result.name, origin: result.origin,
      sha256: result.sha256, secretsPresent: result.secretsPresent, pruned: result.pruned,
    });
  } catch (err) {
    return sendError(res, err, 'save snapshot');
  } finally {
    db.close();
  }
});

// -- Trusted signing keys ----------------------------------------------------

// These are defined before the /:id routes so 'keys' is never parsed as a
// snapshot id.

router.get('/keys', (req, res) => {
  const origin = typeof req.query.origin === 'string' ? req.query.origin : null;
  const db = getDb();
  try {
    res.json({ keys: reportKeys.listReportKeys(db, origin ? { origin } : {}) });
  } catch (err) {
    return sendError(res, err, 'list signing keys');
  } finally {
    db.close();
  }
});

// Parse + sanity-check a pasted PEM and return the fingerprint to confirm out
// of band. No DB write, so no audit entry and no config-lock concern.
router.post('/keys/validate', (req, res) => {
  const body = req.body || {};
  const pem = body.public_key_pem;
  if (typeof pem !== 'string' || !pem.trim()) {
    return res.status(400).json({ error: 'public_key_pem is required' });
  }
  try {
    const { publicKeyFingerprint, publicKeyPem } = reportKeys.validateExternalPublicKey(pem);
    res.json({ ok: true, publicKeyFingerprint, publicKeyPem });
  } catch (err) {
    return sendError(res, err, 'validate public key');
  }
});

router.post('/keys', (req, res) => {
  const body = req.body || {};
  const { public_key_pem, key_label, notes } = body;
  if (typeof public_key_pem !== 'string' || !public_key_pem.trim()) {
    return res.status(400).json({ error: 'public_key_pem is required' });
  }
  if (key_label !== undefined && key_label !== null
      && (typeof key_label !== 'string' || key_label.length > 200)) {
    return res.status(400).json({ error: 'key_label must be a string up to 200 chars' });
  }
  if (notes !== undefined && notes !== null && typeof notes !== 'string') {
    return res.status(400).json({ error: 'notes must be a string' });
  }
  const db = getDb();
  try {
    const result = reportKeys.registerExternalKey(db, {
      publicKeyPem: public_key_pem,
      registeredByUserId: req.user.id,
      keyLabel: key_label || null,
      notes: notes || null,
    });
    audit(db, req, 'BASELINE_KEY_REGISTERED',
      `id=${result.id} fingerprint=${result.publicKeyFingerprint} label=${JSON.stringify(key_label || '')}`);
    res.status(201).json({
      ok: true, id: result.id,
      publicKeyFingerprint: result.publicKeyFingerprint,
      registeredAt: result.registeredAt,
    });
  } catch (err) {
    return sendError(res, err, 'register external key');
  } finally {
    db.close();
  }
});

router.delete('/keys/:id', (req, res) => {
  const idStr = req.params.id;
  const id = parseInt(idStr, 10);
  if (!Number.isInteger(id) || id < 1 || String(id) !== idStr) {
    return res.status(400).json({ error: 'id must be a positive integer' });
  }
  const db = getDb();
  try {
    const result = reportKeys.revokeExternalKey(db, id);
    audit(db, req, 'BASELINE_KEY_REVOKED',
      `id=${result.id} fingerprint=${result.publicKeyFingerprint}`);
    res.json({
      ok: true, id: result.id,
      publicKeyFingerprint: result.publicKeyFingerprint,
      rotatedOutAt: result.rotatedOutAt,
    });
  } catch (err) {
    return sendError(res, err, 'revoke external key');
  } finally {
    db.close();
  }
});

// -- Import (the gate) -- MFA step-up ----------------------------------------

// POST /import  (?dryRun=1 to validate without applying)
// body: { bundle: <FA-GDGB1 object>, stepup: <passkey assertion> }
//
// Gate order, fail-closed at every step:
//   1) scan the raw bytes (layer 1 sanitizer + layer 2 forced all_configured;
//      no scanner configured -> MALWARE_SCANNER_REQUIRED)
//   2) validate the envelope structure + version compatibility
//   3) verify the signature BY FINGERPRINT against a registered trusted key
//   4) validate + bound-check the config payload (the domain layer)
//   5) (dryRun stops here and returns the change report)
//   6) take an automatic pre-import snapshot
//   7) apply as a transactional full-replace
router.post('/import', gdMfaStepUp(), async (req, res) => {
  const dryRun = req.query.dryRun === '1' || req.query.dryRun === 'true';
  const body = req.body || {};
  const bundle = body.bundle;
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
    return res.status(400).json({ error: 'request body must include a bundle object', code: 'INVALID_INPUT' });
  }

  const db = getDb();
  try {
    // 1) scan the raw bytes -- every configured scanner must clear it
    const rawText = JSON.stringify(bundle);
    const scans = await runUploadScans(rawText, 'golden-baseline.fa-gdgb1.json', 'application/json',
      { scanMode: 'all_configured' });
    if (scans.layer2 && scans.layer2.skipped) {
      // No scanner configured. The baseline import REQUIRES one -- fail closed.
      return res.status(409).json({
        error: 'a malware scanner must be configured before a baseline can be imported',
        code: 'MALWARE_SCANNER_REQUIRED',
      });
    }
    if (!scans.ok) {
      if (scans.rejectedBy === 'layer1') {
        return res.status(422).json({
          error: 'the uploaded file was rejected by content inspection',
          code: 'CONTENT_REJECTED', layer: 'sanitizer',
          detail: (scans.layer1 && scans.layer1.threats) || [],
        });
      }
      const l2 = scans.layer2 || {};
      if (l2.error) {
        return res.status(409).json({
          error: 'a configured malware scanner could not complete the scan',
          code: 'EDR_SCAN_UNAVAILABLE', detail: l2.error,
        });
      }
      return res.status(422).json({
        error: 'the uploaded file was flagged by a malware scanner',
        code: 'THREAT_DETECTED', threats: l2.threats || [],
      });
    }

    // 2) envelope structure + version compatibility
    const env = gbValidate.validateEnvelope(bundle);

    // 3) verify the signature by fingerprint against a registered trusted key
    const canonical = gbValidate.validateBaselinePayload(env.schemaVersion, env.payload).canonical;
    const recomputedSha = sha256Hex(canonical);
    if (recomputedSha !== env.sha256) {
      return res.status(400).json({
        error: 'the payload digest does not match the bundle',
        code: 'DIGEST_MISMATCH',
      });
    }
    const verKey = reportKeys.getReportVerificationKey(db, env.signingKey.fingerprint);
    if (!verKey) {
      return res.status(403).json({
        error: 'the signing key is not registered as trusted (or has been revoked); '
          + 'register it via the trusted keys endpoint after confirming its fingerprint out of band',
        code: 'SIGNING_KEY_UNTRUSTED', fingerprint: env.signingKey.fingerprint,
      });
    }
    let signature;
    try {
      signature = Buffer.from(env.signature, 'base64');
    } catch (e) {
      signature = Buffer.alloc(0);
    }
    const digest = Buffer.from(recomputedSha, 'hex');
    const sigValid = reportKeys.verifyReportDigest(db, digest, signature, env.signingKey.fingerprint);
    if (!sigValid) {
      return res.status(403).json({
        error: 'signature verification failed',
        code: 'SIGNATURE_INVALID', fingerprint: env.signingKey.fingerprint,
      });
    }

    // 4/5) dry run: report what would change, without snapshot or apply
    if (dryRun) {
      const diff = gb.diffBaseline(db, { schemaVersion: env.schemaVersion, payload: env.payload });
      return res.json({
        ok: true, dryRun: true, valid: true,
        schemaVersion: env.schemaVersion, appVersion: env.appVersion,
        signingKeyFingerprint: env.signingKey.fingerprint,
        warnings: env.warnings, diff,
      });
    }

    // 6) automatic pre-import safety snapshot (secrets-free, like all snapshots)
    const preSnap = gb.saveSnapshot(db, {
      name: `Auto-save before import ${new Date().toISOString()}`,
      origin: 'pre-import', userId: req.user.id,
    });
    for (const prunedId of preSnap.pruned) {
      audit(db, req, 'CONFIG_SNAPSHOT_PRUNED', `id=${prunedId} reason=retention`);
    }
    audit(db, req, 'CONFIG_SNAPSHOT_SAVED', `id=${preSnap.id} origin=pre-import`);

    // 7) apply (transactional full-replace)
    const report = gb.applyBaseline(db, { schemaVersion: env.schemaVersion, payload: env.payload }, req.user.id);

    audit(db, req, 'CONFIG_SNAPSHOT_IMPORTED',
      `fingerprint=${env.signingKey.fingerprint} appVersion=${env.appVersion} `
      + `preImportSnapshot=${preSnap.id} requiresCredentials=${report.requiresCredentials.length}`);

    res.json({
      ok: true, imported: true,
      preImportSnapshotId: preSnap.id,
      applied: report.applied,
      requiresCredentials: report.requiresCredentials,
      skippedIntegrations: report.skippedIntegrations,
      warnings: [...env.warnings, ...report.warnings],
    });
  } catch (err) {
    return sendError(res, err, 'import baseline');
  } finally {
    db.close();
  }
});

// -- Export a signed FA-GDGB1 bundle -----------------------------------------

router.get('/:id/export', (req, res) => {
  const id = req.params.id;
  const db = getDb();
  try {
    const snap = gb.getSnapshot(db, id);
    if (snap.baseline_schema_version !== gb.BASELINE_SCHEMA_VERSION) {
      return res.status(400).json({
        error: 'only current-format snapshots can be exported',
        code: 'UNSUPPORTED_SCHEMA_VERSION',
      });
    }
    const digest = Buffer.from(snap.sha256, 'hex');
    let signed;
    try {
      signed = reportKeys.signReportDigest(db, digest);
    } catch (e) {
      console.error(`[gd-config-baseline] export signing failed: ${e.message}`);
      return res.status(500).json({ error: 'failed to sign the baseline export', code: 'SIGNING_FAILED' });
    }
    const verKey = reportKeys.getReportVerificationKey(db, signed.keyFingerprint);
    const bundle = {
      format: 'FA-GDGB1',
      baselineSchemaVersion: snap.baseline_schema_version,
      appVersion: snap.app_version || APP_VERSION,
      instanceLabel: getInstanceLabel(db),
      exportedAt: new Date().toISOString(),
      snapshot: { id: snap.id, name: snap.name, origin: snap.origin, createdAt: snap.created_at },
      payload: JSON.parse(snap.payload),
      sha256: snap.sha256,
      signature: signed.signature.toString('base64'),
      signingKey: {
        publicKeyPem: verKey ? verKey.publicKeyPem : null,
        fingerprint: signed.keyFingerprint,
      },
    };
    audit(db, req, 'CONFIG_SNAPSHOT_EXPORTED',
      `id=${snap.id} fingerprint=${signed.keyFingerprint}`);
    const filename = `firealive-gd-baseline-${snap.id}.fa-gdgb1.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(JSON.stringify(bundle, null, 2));
  } catch (err) {
    return sendError(res, err, 'export snapshot');
  } finally {
    db.close();
  }
});

// -- Change report (diff) + revert + delete ----------------------------------

router.get('/:id/diff', (req, res) => {
  const id = req.params.id;
  const db = getDb();
  try {
    const snap = gb.getSnapshot(db, id);
    const payload = JSON.parse(snap.payload);
    const diff = gb.diffBaseline(db, { schemaVersion: snap.baseline_schema_version, payload });
    res.json({ ok: true, snapshotId: snap.id, diff });
  } catch (err) {
    return sendError(res, err, 'diff snapshot');
  } finally {
    db.close();
  }
});

// Revert to a snapshot. MFA step-up required. The current config is auto-saved
// as a pre-revert snapshot first, then the chosen snapshot is applied as a
// transactional full-replace.
router.post('/:id/revert', gdMfaStepUp(), (req, res) => {
  const id = req.params.id;
  const db = getDb();
  try {
    const snap = gb.getSnapshot(db, id);
    const payload = JSON.parse(snap.payload);
    const preSnap = gb.saveSnapshot(db, {
      name: `Auto-save before revert ${new Date().toISOString()}`,
      origin: 'pre-revert', userId: req.user.id,
    });
    for (const prunedId of preSnap.pruned) {
      audit(db, req, 'CONFIG_SNAPSHOT_PRUNED', `id=${prunedId} reason=retention`);
    }
    audit(db, req, 'CONFIG_SNAPSHOT_SAVED', `id=${preSnap.id} origin=pre-revert`);
    const report = gb.applyBaseline(db, { schemaVersion: snap.baseline_schema_version, payload }, req.user.id);
    audit(db, req, 'CONFIG_SNAPSHOT_REVERTED',
      `id=${snap.id} preRevertSnapshot=${preSnap.id} schemaVersion=${snap.baseline_schema_version}`);
    res.json({
      ok: true, reverted: true,
      snapshotId: snap.id, preRevertSnapshotId: preSnap.id,
      applied: report.applied,
      requiresCredentials: report.requiresCredentials,
      warnings: report.warnings,
    });
  } catch (err) {
    return sendError(res, err, 'revert snapshot');
  } finally {
    db.close();
  }
});

router.delete('/:id', (req, res) => {
  const id = req.params.id;
  const db = getDb();
  try {
    const result = gb.deleteSnapshot(db, id);
    audit(db, req, 'CONFIG_SNAPSHOT_DELETED', `id=${result.deleted}`);
    res.json({ ok: true, deleted: result.deleted });
  } catch (err) {
    return sendError(res, err, 'delete snapshot');
  } finally {
    db.close();
  }
});

module.exports = router;

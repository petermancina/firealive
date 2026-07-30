// =============================================================================
// FIREALIVE GD -- KMS provider registry routes  [B6g]
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
//
// Mounted under authMiddleware(['ciso']) + the config-lock chokepoint in
// index.js, and registered in gd-config-write-routes so the lock actually
// freezes it. Every mutating handler additionally carries a hardware-passkey
// step-up.
//
// WHY BOTH THE LOCK AND A STEP-UP. The config lock answers "is the platform
// accepting configuration changes right now?"; the step-up answers "is the
// person at the keyboard the CISO?". Configuring a key custodian is the act
// that decides who can be compelled to open the operator's backups, so it is
// gated the same way minting a credential is.
//
// CUSTODY, NEVER RECOVERY. Nothing here is a recovery path, and no response
// message may suggest one. A provider wraps the per-backup data key; the GD
// Tier-1 KEK is escrowed to no provider anywhere, and recovering a deployment
// always means re-establishing the KEK from the offline recovery code.
//
// NO SECRET IS EVER RETURNED. Reads go through the service's publicView, which
// omits credentials entirely rather than masking them -- a masked field invites
// a console to send the mask back on save, which is how a mask becomes the
// stored value.

const router = require('express').Router();
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');
const { gdMfaStepUp } = require('../services/gd-mfa-stepup');
const svc = require('../services/gd-kms-providers');

function audit(db, req, eventType, detail) {
  try {
    appendGdAuditEntry(db, {
      userId: req && req.user ? req.user.id : null,
      eventType,
      detail,
      ip: (req && req.ip) || null,
      severity: 'info',
    });
  } catch (_e) { /* best-effort: the audit must never break the response */ }
}

// Map a service error to a status. Anything unrecognised is 500, deliberately:
// a new error code should surface as a server error rather than be silently
// reported as a client mistake.
function statusFor(code) {
  switch (code) {
    case svc.CODES.INVALID_INPUT:
    case svc.CODES.PROVIDER_VALIDATION_FAILED:
      return 400;
    case svc.CODES.NAME_CONFLICT:
    case svc.CODES.IS_DEFAULT:
    case svc.CODES.LAST_ENABLED:
    case svc.CODES.IN_USE:
    case svc.CODES.PROVIDER_DISABLED:
      return 409;
    case svc.CODES.RESIDENCY_DENIED:
      return 403;
    case svc.CODES.PROVIDER_NOT_FOUND:
      return 404;
    case svc.CODES.PROVIDER_NOT_REGISTERED:
      return 501;
    default:
      return 500;
  }
}

function fail(res, err) {
  if (err && err.name === 'GdKmsProviderError') {
    return res.status(statusFor(err.code)).json({
      error: err.message,
      code: err.code,
      detail: err.detail || undefined,
    });
  }
  return res.status(500).json({ error: 'kms provider operation failed' });
}

// ── reads ───────────────────────────────────────────────────────────────────

router.get('/', (req, res) => {
  const db = getDb();
  try {
    // Retired providers are hidden by default and returned on request. They are
    // not deleted, so a console that never asks would show nothing explaining
    // why an old backup still restores.
    const includeRetired = req.query.include_retired === 'true';
    res.json({ providers: svc.listProviders(db, { includeRetired }) });
  } catch (err) {
    fail(res, err);
  }
});

router.get('/:id', (req, res) => {
  const db = getDb();
  try {
    const p = svc.getProviderById(db, req.params.id);
    if (!p) return res.status(404).json({ error: 'provider not found', code: svc.CODES.PROVIDER_NOT_FOUND });
    // How many backups depend on this provider. Shown on the read so an
    // operator sees the reason a delete will be refused BEFORE attempting it.
    res.json({ provider: p, backups_using: svc.backupsUsing(db, req.params.id) });
  } catch (err) {
    fail(res, err);
  }
});

// ── writes ──────────────────────────────────────────────────────────────────

router.post('/', gdMfaStepUp(), async (req, res) => {
  const db = getDb();
  try {
    const r = await svc.createProvider(db, req.body || {}, { user_id: req.user ? req.user.id : null });
    audit(db, req, 'GD_KMS_PROVIDER_CREATED',
      `provider ${r.provider.name} (${r.provider.provider_type}) created; `
      + `key custody ${r.residency.keyCustody || 'unresolved'}, residency ${r.residency.action}`);
    res.status(201).json(r);
  } catch (err) {
    // A residency refusal is audited too. The attempt is the security-relevant
    // event: someone tried to place the wrapping key in a jurisdiction the
    // operator's own policy does not permit.
    if (err && err.code === svc.CODES.RESIDENCY_DENIED) {
      audit(db, req, 'GD_KMS_PROVIDER_RESIDENCY_DENIED',
        `create refused: ${err.message}`);
    }
    fail(res, err);
  }
});

router.put('/:id', gdMfaStepUp(), async (req, res) => {
  const db = getDb();
  try {
    const r = await svc.updateProvider(db, req.params.id, req.body || {}, { user_id: req.user ? req.user.id : null });
    audit(db, req, 'GD_KMS_PROVIDER_UPDATED',
      `provider ${r.provider.name} updated; residency ${r.residency.action}`);
    res.json(r);
  } catch (err) {
    if (err && err.code === svc.CODES.RESIDENCY_DENIED) {
      audit(db, req, 'GD_KMS_PROVIDER_RESIDENCY_DENIED', `update refused: ${err.message}`);
    }
    fail(res, err);
  }
});

router.post('/:id/enable', gdMfaStepUp(), (req, res) => {
  const db = getDb();
  try {
    const p = svc.setEnabled(db, req.params.id, true);
    audit(db, req, 'GD_KMS_PROVIDER_ENABLED', `provider ${p.name} enabled`);
    res.json({ provider: p });
  } catch (err) { fail(res, err); }
});

router.post('/:id/disable', gdMfaStepUp(), (req, res) => {
  const db = getDb();
  try {
    const p = svc.setEnabled(db, req.params.id, false);
    audit(db, req, 'GD_KMS_PROVIDER_DISABLED', `provider ${p.name} disabled`);
    res.json({ provider: p });
  } catch (err) { fail(res, err); }
});

router.post('/:id/retire', gdMfaStepUp(), (req, res) => {
  const db = getDb();
  try {
    const p = svc.retireProvider(db, req.params.id);
    audit(db, req, 'GD_KMS_PROVIDER_RETIRED',
      `provider ${p.name} retired: no new backups will use it, and archives already `
      + 'wrapped with it can still be opened');
    res.json({ provider: p });
  } catch (err) { fail(res, err); }
});

router.post('/:id/default', gdMfaStepUp(), (req, res) => {
  const db = getDb();
  try {
    const p = svc.setDefault(db, req.params.id);
    audit(db, req, 'GD_KMS_PROVIDER_DEFAULT_SET', `provider ${p.name} is now the default`);
    res.json({ provider: p });
  } catch (err) { fail(res, err); }
});

router.delete('/:id', gdMfaStepUp(), (req, res) => {
  const db = getDb();
  try {
    const existing = svc.getProviderById(db, req.params.id);
    const r = svc.deleteProvider(db, req.params.id);
    audit(db, req, 'GD_KMS_PROVIDER_DELETED',
      `provider ${existing ? existing.name : req.params.id} deleted (no backups depended on it)`);
    res.json(r);
  } catch (err) {
    if (err && err.code === svc.CODES.IN_USE) {
      audit(db, req, 'GD_KMS_PROVIDER_DELETE_REFUSED', err.message);
    }
    fail(res, err);
  }
});

// ── probe ───────────────────────────────────────────────────────────────────
//
// Reads metadata or describes the key. NEVER a wrap or an unwrap: a health check
// that exercised the crypto path would produce ciphertext nobody asked for and
// would fail for an operator whose IAM policy grants describe but not encrypt,
// which is a legitimate and tighter grant.
router.post('/:id/test', gdMfaStepUp(), async (req, res) => {
  const db = getDb();
  try {
    const r = await svc.probeProvider(db, req.params.id, {});
    audit(db, req, 'GD_KMS_PROVIDER_PROBED',
      `provider ${req.params.id} probe ${r.status}${r.error ? ': ' + r.error : ''}`);
    res.json(r);
  } catch (err) { fail(res, err); }
});

module.exports = router;

// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE — Deployment Mode (D9)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The deployment mode (bare-metal, virtualized, or cloud) is chosen once at install
// and hardware-sealed with the instance anchor, so it cannot be flipped at
// runtime to unlock the relaxed virtualization allowances. The seal binds the
// mode to THIS deployment's anchor (instanceId + fingerprint) and is an
// anchor signature over the canonical record; tampering with the stored value
// breaks the signature, and a clone that copied the database but not the
// hardware anchor cannot re-sign.
//
// A missing or tamper-detected seal FAILS SAFE to bare-metal — the strict
// path with no VM allowances — so a forged 'virtualized' value never weakens
// the anti-cloning enforcement. Bare-metal deployments simply never set a
// mode and run strict by default.
// ─────────────────────────────────────────────────────────────────────────────

const crypto = require('crypto');
const anchor = require('./instance-anchor');
const { canonicalize } = require('./report-signer');

const MODE_KEY = 'deployment_mode';
const BARE_METAL = 'bare-metal';
const VIRTUALIZED = 'virtualized';
const CLOUD = 'cloud';
const MODES = [BARE_METAL, VIRTUALIZED, CLOUD];
const SIG_ALG = 'ecdsa-p256-ieee-p1363';

function fail(code, message) {
  const e = new Error(message || code);
  e.code = code;
  return e;
}

function readRecord(db) {
  const row = db.prepare("SELECT value FROM config WHERE key = ?").get(MODE_KEY);
  if (!row || !row.value) return null;
  try { return JSON.parse(row.value); } catch (_e) { return null; }
}

// The exact bytes the anchor signs: the mode bound to this deployment's
// anchor identity and the time it was sealed.
function signedPayload(rec) {
  return Buffer.from(canonicalize({
    mode: rec.mode,
    instanceId: rec.instanceId,
    anchorFingerprint: rec.anchorFingerprint,
    setAt: rec.setAt
  }), 'utf8');
}

function loadAnchor(db) {
  try { return anchor.load({ db: db }); } catch (_e) { return null; }
}

// True only if the stored record is a well-formed seal that verifies against
// the current anchor and binds to it.
function verifyRecord(db, rec) {
  if (!rec || MODES.indexOf(rec.mode) === -1 || !rec.signature) return false;
  const identity = loadAnchor(db);
  if (!identity || !identity.publicKey) return false;
  if (rec.instanceId !== identity.instanceId) return false;
  if (rec.anchorFingerprint !== identity.fingerprint) return false;
  try {
    return crypto.verify('sha256', signedPayload(rec),
      { key: crypto.createPublicKey(identity.publicKey), dsaEncoding: 'ieee-p1363' },
      Buffer.from(rec.signature, 'base64'));
  } catch (_e) {
    return false;
  }
}

// The effective mode. Missing or tamper-detected seal -> bare-metal (strict).
function getMode(db) {
  const rec = readRecord(db);
  if (rec && verifyRecord(db, rec)) return rec.mode;
  return BARE_METAL;
}

// A valid, anchor-sealed mode is on record.
function isConfigured(db) {
  const rec = readRecord(db);
  return !!(rec && verifyRecord(db, rec));
}

function isVirtualized(db) {
  return getMode(db) === VIRTUALIZED;
}

function isCloud(db) {
  return getMode(db) === CLOUD;
}

// Provisioning-only: set and hardware-seal the mode. Refuses to change an
// already-sealed mode unless opts.force (reserved for the authorized
// re-provision ceremony). Requires an established instance anchor to seal.
function setMode(db, mode, opts) {
  const o = opts || {};
  if (MODES.indexOf(mode) === -1) throw fail('INVALID_MODE', 'mode must be one of ' + MODES.join(', '));
  if (isConfigured(db) && !o.force) throw fail('MODE_ALREADY_SET', 'deployment mode is already provisioned');
  const identity = loadAnchor(db);
  if (!identity || !identity.publicKey) throw fail('ANCHOR_REQUIRED', 'instance anchor must be established before setting deployment mode');
  const rec = {
    mode: mode,
    instanceId: identity.instanceId,
    anchorFingerprint: identity.fingerprint,
    setAt: new Date().toISOString()
  };
  const signature = anchor.sign({ db: db, identity: identity, data: signedPayload(rec) });
  rec.alg = SIG_ALG;
  rec.signature = Buffer.from(signature).toString('base64');
  db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(MODE_KEY, JSON.stringify(rec));
  return { mode: mode, sealed: true };
}

// Best-effort hypervisor hint (Linux DMI). Informational only — the mode is
// operator-selected, never inferred from this. Returns null off-Linux or on
// any error, and never throws.
function detectHypervisor() {
  try {
    const fs = require('fs');
    const sources = ['/sys/class/dmi/id/product_name', '/sys/class/dmi/id/sys_vendor'];
    for (let i = 0; i < sources.length; i++) {
      let v;
      try { v = fs.readFileSync(sources[i], 'utf8'); } catch (_e) { continue; }
      if (!v) continue;
      if (/vmware/i.test(v)) return 'vmware';
      if (/virtualbox/i.test(v)) return 'virtualbox';
      if (/qemu|kvm/i.test(v)) return 'kvm';
      if (/hyper-v|microsoft corporation/i.test(v)) return 'hyperv';
      if (/xen/i.test(v)) return 'xen';
      if (/amazon|ec2/i.test(v)) return 'aws';
      if (/google/i.test(v)) return 'gcp';
    }
    return null;
  } catch (_e) {
    return null;
  }
}

// Mode context for app.locals and gating decisions elsewhere.
function summary(db) {
  const rec = readRecord(db);
  const valid = !!(rec && verifyRecord(db, rec));
  return {
    mode: valid ? rec.mode : BARE_METAL,
    configured: valid,
    recordPresent: !!rec,
    virtualized: valid && rec.mode === VIRTUALIZED,
    cloud: valid && rec.mode === CLOUD,
    hypervisor: detectHypervisor()
  };
}

module.exports = {
  getMode,
  setMode,
  isVirtualized,
  isCloud,
  isConfigured,
  detectHypervisor,
  summary,
  BARE_METAL,
  VIRTUALIZED,
  CLOUD,
  MODES,
  MODE_KEY
};

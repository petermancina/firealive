// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- Deployment Mode (D9)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// The GD-server deployment mode (bare-metal, virtualized, cloud, sdn, or sase)
// is chosen once at install and hardware-sealed with the GD instance anchor, so
// it cannot be flipped at runtime to unlock the relaxed virtualization
// allowances. The seal binds the mode to THIS deployment's anchor (instanceId +
// fingerprint) and is an anchor signature over the canonical record; tampering
// with the stored value breaks the signature, and a clone that copied the
// database but not the hardware anchor cannot re-sign.
//
// A missing or tamper-detected seal FAILS SAFE to bare-metal -- the strict path
// with no VM allowances -- so a forged 'virtualized' value never weakens the
// anti-cloning enforcement. Bare-metal deployments simply never set a mode and
// run strict by default. This is the GD-server twin of the Regional Server's
// deployment-mode; each trust realm seals its own mode against its own anchor.
//
// The sealed record lives in node_state (node-local, excluded from replication),
// so each GD node holds its OWN mode -- a replicated table let the active's record
// clobber a standby's and fail verification against the standby's anchor. Relocated
// from config in B6h A-9.
// -----------------------------------------------------------------------------

const crypto = require('crypto');
const anchor = require('./gd-instance-anchor');
const { canonicalize } = require('./report-signer');

const MODE_KEY = 'deployment_mode';
const BARE_METAL = 'bare-metal';
const VIRTUALIZED = 'virtualized';
const CLOUD = 'cloud';
const SDN = 'sdn';
const SASE = 'sase';
const MODES = [BARE_METAL, VIRTUALIZED, CLOUD, SDN, SASE];
// SDN and SASE compose with a host substrate; the other modes ARE their substrate.
const SUBSTRATES = [BARE_METAL, VIRTUALIZED, CLOUD];
const SIG_ALG = 'ecdsa-p256-ieee-p1363';

function fail(code, message) {
  const e = new Error(message || code);
  e.code = code;
  return e;
}

function readRecord(db) {
  const row = db.prepare("SELECT value FROM node_state WHERE key = ?").get(MODE_KEY);
  if (!row || !row.value) return null;
  try { return JSON.parse(row.value); } catch (_e) { return null; }
}

// The exact bytes the anchor signs: the mode bound to this deployment's anchor
// identity and the time it was sealed.
function signedPayload(rec) {
  const payload = {
    mode: rec.mode,
    instanceId: rec.instanceId,
    anchorFingerprint: rec.anchorFingerprint,
    setAt: rec.setAt
  };
  // The SDN/SASE host substrate is part of the signed bytes so it cannot be
  // flipped. Records without a substrate (the non-network modes) produce the
  // identical payload and re-verify unchanged.
  if (rec.substrate) payload.substrate = rec.substrate;
  return Buffer.from(canonicalize(payload), 'utf8');
}

function loadAnchor(db) {
  try { return anchor.load({ db: db }); } catch (_e) { return null; }
}

// True only if the stored record is a well-formed seal that verifies against the
// current anchor and binds to it. The GD anchor signs ECDSA P-256 (raw r||s /
// IEEE P1363 over a SHA-256 digest), so the record signature verifies with the
// same parameters the anchor used to produce it.
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

// True if a mode record is stored but does NOT verify against this GD node's anchor --
// tamper evidence: a corrupted seal, or a record bound to a different anchor (e.g. an
// active's record that reached a standby). A node with no record (bare-metal) or a valid
// record is NOT tampered. Promotion refuses on this signal (fail-closed).
function sealTampered(db) {
  const rec = readRecord(db);
  return !!(rec && !verifyRecord(db, rec));
}

function isVirtualized(db) {
  return getMode(db) === VIRTUALIZED;
}

function isCloud(db) {
  return getMode(db) === CLOUD;
}

function isSdn(db) {
  return getMode(db) === SDN;
}

function isSase(db) {
  return getMode(db) === SASE;
}

// Provisioning-only: set and hardware-seal the mode. Refuses to change an
// already-sealed mode unless opts.force (reserved for the authorized
// re-provision ceremony). Requires an established GD instance anchor to seal.
function setMode(db, mode, opts) {
  const o = opts || {};
  if (MODES.indexOf(mode) === -1) throw fail('INVALID_MODE', 'mode must be one of ' + MODES.join(', '));
  // SDN and SASE require a host substrate (bare-metal, virtualized, or cloud);
  // the other modes whose mode is their substrate reject one. The substrate is
  // sealed and signed alongside the mode.
  let substrate = null;
  if (mode === SDN || mode === SASE) {
    if (SUBSTRATES.indexOf(o.substrate) === -1) throw fail('INVALID_SUBSTRATE', 'sdn and sase deployments require a substrate, one of ' + SUBSTRATES.join(', '));
    substrate = o.substrate;
  } else if (o.substrate) {
    throw fail('SUBSTRATE_NOT_ALLOWED', 'only sdn and sase deployments carry a substrate');
  }
  if (isConfigured(db) && !o.force) throw fail('MODE_ALREADY_SET', 'deployment mode is already provisioned');
  const identity = loadAnchor(db);
  if (!identity || !identity.publicKey) throw fail('ANCHOR_REQUIRED', 'GD instance anchor must be established before setting deployment mode');
  const rec = {
    mode: mode,
    instanceId: identity.instanceId,
    anchorFingerprint: identity.fingerprint,
    setAt: new Date().toISOString()
  };
  if (substrate) rec.substrate = substrate;
  const signature = anchor.sign({ db: db, identity: identity, data: signedPayload(rec) });
  if (!signature) throw fail('ANCHOR_REQUIRED', 'GD instance anchor could not sign the deployment-mode seal');
  rec.alg = SIG_ALG;
  rec.signature = Buffer.from(signature).toString('base64');
  db.prepare("INSERT OR REPLACE INTO node_state (key, value) VALUES (?, ?)").run(MODE_KEY, JSON.stringify(rec));
  return { mode: mode, substrate: substrate, sealed: true };
}

// Best-effort hypervisor hint (Linux DMI). Informational only -- the mode is
// operator-selected, never inferred from this. Returns null off-Linux or on any
// error, and never throws.
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

// Best-effort host-substrate classification, used ONLY as a cross-check against
// the operator-declared FIREALIVE_GD_SUBSTRATE at SDN/SASE provisioning -- never
// as the authority. A responding cloud-provider metadata service is the strong
// cloud signal; otherwise a detected hypervisor means virtualized; otherwise
// bare-metal. Async (the metadata probe is async) and never throws. The db param
// is accepted for call-site symmetry and future use. gd-cloud-metadata lands in
// the Cloud Mode PR; until then the require fails closed to no cloud signal.
async function detectSubstrate(db) {
  try {
    let provider = null;
    try {
      const cloudMetadata = require('./gd-cloud-metadata');
      const meta = await cloudMetadata.readCloudMetadata();
      provider = (meta && meta.provider) ? meta.provider : null;
    } catch (_e) {
      provider = null;
    }
    if (provider) return CLOUD;
    if (detectHypervisor()) return VIRTUALIZED;
    return BARE_METAL;
  } catch (_e) {
    return BARE_METAL;
  }
}

// Mode context for app.locals and gating decisions elsewhere.
function summary(db) {
  const rec = readRecord(db);
  const valid = !!(rec && verifyRecord(db, rec));
  const mode = valid ? rec.mode : BARE_METAL;
  const virtualized = valid && mode === VIRTUALIZED;
  const cloud = valid && mode === CLOUD;
  const sdn = valid && mode === SDN;
  const sase = valid && mode === SASE;
  // The sealed substrate applies to SDN or SASE; null for the other modes (whose
  // mode is their substrate).
  const substrate = ((sdn || sase) && rec && rec.substrate && SUBSTRATES.indexOf(rec.substrate) !== -1) ? rec.substrate : null;
  // Substrate-effective gates: true for the top-level mode OR the matching
  // SDN/SASE substrate. Downstream consumers read these instead of the raw mode
  // booleans, so e.g. sdn/sase + virtualized engages the clock-integrity gate and
  // sdn/sase + cloud the confidential-VM attestation path.
  const substrateVirtualized = virtualized || ((sdn || sase) && substrate === VIRTUALIZED);
  const substrateCloud = cloud || ((sdn || sase) && substrate === CLOUD);
  return {
    mode: mode,
    configured: valid,
    recordPresent: !!rec,
    virtualized: virtualized,
    cloud: cloud,
    sdn: sdn,
    sase: sase,
    networkMode: sdn ? SDN : (sase ? SASE : null),
    substrate: substrate,
    substrateVirtualized: substrateVirtualized,
    substrateCloud: substrateCloud,
    easilyCopied: substrateVirtualized || substrateCloud,
    ccRequired: substrateCloud,
    hypervisor: detectHypervisor()
  };
}

module.exports = {
  getMode,
  setMode,
  isVirtualized,
  isCloud,
  isSdn,
  isSase,
  isConfigured,
  sealTampered,
  detectHypervisor,
  detectSubstrate,
  summary,
  BARE_METAL,
  VIRTUALIZED,
  CLOUD,
  SDN,
  SASE,
  MODES,
  SUBSTRATES,
  MODE_KEY
};

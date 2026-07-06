// FIREALIVE GD -- Cloud Mode configuration (B6c PR-5, verbatim twin)
//
// Stores the operator-selected Cloud Mode configuration: the cloud platform
// (aws/azure/gcp) and the stable hostname used as the primary certificate SAN
// for cert reconciliation across cloud address changes. It also holds the
// attestation policy and the record of the last successful attestation that the
// boot gate and pre-auth gate consult:
//   - TCB floor: the minimum acceptable platform TCB, stored per substrate tech.
//     Upward-only (monotonic) -- it can be raised but never lowered, so a
//     firmware-downgrade attempt cannot relax the gate.
//   - Pinned measurement: the launch measurement captured on the first verified
//     attestation (trust-on-first-use) and required to match on every boot.
//   - requireDedicatedTenancy: when set, the boot gate additionally requires the
//     instance to run on single-tenant (dedicated) hardware.
//   - Last-attestation record: time, tech, TCB, measurement, and verified /
//     validation-pending status, persisted by recordAttestation.
//
// The deployment MODE itself (the value cloud) is the anchor-sealed, tamper-
// evident record owned by gd-deployment-mode.js. This module holds the operational
// configuration that accompanies that mode, in the same config table. The
// platform and hostname are not security gates -- the confidential-computing
// technology and report are verified from the kernel by gd-cloud-attestation and
// the provider from live metadata by gd-cloud-metadata, neither of which trusts
// this stored value.
//
// ASCII only; no template literals.

const CONFIG_KEY = 'cloud_mode';
const PLATFORMS = ['aws', 'azure', 'gcp'];
const TCB_TECHS = ['sev-snp', 'tdx'];

function fail(code, message) {
  const e = new Error(message || code);
  e.code = code;
  return e;
}

function readConfig(db) {
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get(CONFIG_KEY);
  if (!row || !row.value) return null;
  try { return JSON.parse(row.value); } catch (e) { return null; }
}

function writeConfig(db, rec) {
  db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(CONFIG_KEY, JSON.stringify(rec));
}

// Accepts a DNS name or an IPv4/IPv6 literal. Returns null when not provided
// (Cloud Mode then relies on the instance metadata IP for the certificate SAN).
// Throws on a malformed value so a bad hostname is caught at provisioning.
function normalizeHostname(value) {
  if (value == null) return null;
  if (typeof value !== 'string') throw fail('INVALID_HOSTNAME', 'stable hostname must be a string');
  const h = value.trim().toLowerCase();
  if (h.length === 0) return null;
  if (h.length > 253) throw fail('INVALID_HOSTNAME', 'stable hostname is too long');
  if (!/^[a-z0-9.:-]+$/.test(h)) throw fail('INVALID_HOSTNAME', 'stable hostname has invalid characters');
  return h;
}

// ---- TCB floor (monotonic, upward-only) -----------------------------------

function clampSvn(x) {
  let v = Number(x);
  if (!isFinite(v) || v < 0) v = 0;
  if (v > 255) v = 255;
  return v | 0;
}

function normFloorSev(f) {
  const o = f || {};
  return {
    bootloader: clampSvn(o.bootloader),
    tee: clampSvn(o.tee),
    snp: clampSvn(o.snp),
    microcode: clampSvn(o.microcode),
  };
}

function mergeFloorSev(cur, next) {
  const a = normFloorSev(cur);
  const b = normFloorSev(next);
  return {
    bootloader: Math.max(a.bootloader, b.bootloader),
    tee: Math.max(a.tee, b.tee),
    snp: Math.max(a.snp, b.snp),
    microcode: Math.max(a.microcode, b.microcode),
  };
}

function mergeFloorTdx(cur, next) {
  const a = Buffer.from(String(cur || ''), 'hex');
  const b = Buffer.from(String(next || ''), 'hex');
  const len = Math.max(a.length, b.length);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i += 1) out[i] = Math.max(a[i] || 0, b[i] || 0);
  return out.toString('hex');
}

// Raise the stored TCB floor. opts: { tech: 'sev-snp'|'tdx', floor }. The floor
// merges monotonically with the stored value (component-wise max), so it can be
// raised but never lowered. A substrate-tech change resets to the new floor.
function setTcbFloor(db, opts) {
  const o = opts || {};
  if (TCB_TECHS.indexOf(o.tech) === -1) {
    throw fail('INVALID_TCB_TECH', 'tcb floor tech must be one of ' + TCB_TECHS.join(', '));
  }
  const rec = readConfig(db) || {};
  const sameTech = rec.tcbFloorTech === o.tech;
  if (o.tech === 'sev-snp') {
    rec.tcbFloor = mergeFloorSev(sameTech ? rec.tcbFloor : null, o.floor);
  } else {
    rec.tcbFloor = mergeFloorTdx(sameTech ? rec.tcbFloor : '', o.floor);
  }
  rec.tcbFloorTech = o.tech;
  writeConfig(db, rec);
  return { tcbFloor: rec.tcbFloor, tcbFloorTech: o.tech };
}

// ---- measurement pin (trust-on-first-use) ---------------------------------

// Pin the launch measurement on first use; on later calls verify it matches the
// pin without overwriting. Returns { measurement, firstPin, matched }.
function pinMeasurement(db, measurement) {
  const m = (measurement == null) ? null : String(measurement).toLowerCase();
  if (!m) return { measurement: null, firstPin: false, matched: false };
  const rec = readConfig(db) || {};
  if (!rec.measurementPin) {
    rec.measurementPin = m;
    writeConfig(db, rec);
    return { measurement: m, firstPin: true, matched: true };
  }
  return { measurement: rec.measurementPin, firstPin: false, matched: rec.measurementPin === m };
}

// ---- config read/write ----------------------------------------------------

// Returns the normalized config, or null if Cloud Mode has not been configured.
// ccRequired is always true for Cloud Mode.
function getCloudConfig(db) {
  const rec = readConfig(db);
  if (!rec) return null;
  return {
    platform: rec.platform || null,
    stableHostname: rec.stableHostname || null,
    ccRequired: true,
    ccLastVerified: rec.ccLastVerified || null,
    ccTech: rec.ccTech || null,
    ccTcb: rec.ccTcb || null,
    ccMeasurement: rec.ccMeasurement || null,
    ccVerified: rec.ccVerified === true,
    ccPending: rec.ccPending === true,
    tcbFloor: rec.tcbFloor || null,
    tcbFloorTech: rec.tcbFloorTech || null,
    measurementPin: rec.measurementPin || null,
    requireDedicatedTenancy: rec.requireDedicatedTenancy === true,
  };
}

// Provisioning: set the platform and (optional) stable hostname and dedicated-
// tenancy requirement. Validates the platform against the confidential-VM
// provider set. Preserves recorded attestation state and the TCB floor / pin.
function setCloudConfig(db, opts) {
  const o = opts || {};
  if (PLATFORMS.indexOf(o.platform) === -1) {
    throw fail('INVALID_PLATFORM', 'cloud platform must be one of ' + PLATFORMS.join(', '));
  }
  const stableHostname = normalizeHostname(o.stableHostname);
  const rec = readConfig(db) || {};
  rec.platform = o.platform;
  rec.stableHostname = stableHostname;
  if (o.requireDedicatedTenancy !== undefined) {
    rec.requireDedicatedTenancy = o.requireDedicatedTenancy === true;
  }
  writeConfig(db, rec);
  return getCloudConfig(db);
}

// Boot/verification: stamp the time, tech, and the attestation result (TCB,
// measurement, verified / validation-pending) of a successful attestation.
function recordAttestation(db, opts) {
  const o = opts || {};
  const rec = readConfig(db) || {};
  rec.ccLastVerified = new Date().toISOString();
  if (o.tech) rec.ccTech = o.tech;
  if (o.tcb !== undefined) rec.ccTcb = o.tcb;
  if (o.measurement !== undefined) rec.ccMeasurement = o.measurement;
  if (o.verified !== undefined) rec.ccVerified = o.verified === true;
  if (o.platformValidationPending !== undefined) rec.ccPending = o.platformValidationPending === true;
  writeConfig(db, rec);
  return getCloudConfig(db);
}

module.exports = {
  getCloudConfig,
  setCloudConfig,
  recordAttestation,
  setTcbFloor,
  pinMeasurement,
  PLATFORMS,
  TCB_TECHS,
  CONFIG_KEY,
};

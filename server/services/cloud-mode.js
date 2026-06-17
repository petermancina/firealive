// FIREALIVE -- Cloud Mode configuration (B5h Cloud Mode, C10)
//
// Stores the operator-selected Cloud Mode configuration: the cloud platform
// (aws/azure/gcp) and the stable hostname used as the primary certificate SAN
// for cert reconciliation across cloud address changes. It also records the
// timestamp and technology of the last successful confidential-computing
// attestation, which the pre-auth gate uses to confirm CC is currently verified.
//
// The deployment MODE itself (the value cloud) is the anchor-sealed, tamper-
// evident record owned by deployment-mode.js. This module holds the operational
// configuration that accompanies that mode; it is stored in the same config
// table. The platform and hostname are not security gates -- the confidential-
// computing technology is detected from the kernel by cloud-attestation, and the
// provider is detected from the live metadata service by cloud-metadata, neither
// of which trusts this stored value -- so the config is kept unsigned.
//
// ASCII only; no template literals.

const CONFIG_KEY = 'cloud_mode';
const PLATFORMS = ['aws', 'azure', 'gcp'];

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
  };
}

// Provisioning: set the platform and (optional) stable hostname. Validates the
// platform against the confidential-VM provider set. Preserves any recorded
// attestation timestamp.
function setCloudConfig(db, opts) {
  const o = opts || {};
  if (PLATFORMS.indexOf(o.platform) === -1) {
    throw fail('INVALID_PLATFORM', 'cloud platform must be one of ' + PLATFORMS.join(', '));
  }
  const stableHostname = normalizeHostname(o.stableHostname);
  const rec = readConfig(db) || {};
  rec.platform = o.platform;
  rec.stableHostname = stableHostname;
  writeConfig(db, rec);
  return getCloudConfig(db);
}

// Boot/verification: stamp the time and technology of a successful attestation.
function recordAttestation(db, opts) {
  const o = opts || {};
  const rec = readConfig(db) || {};
  rec.ccLastVerified = new Date().toISOString();
  if (o.tech) rec.ccTech = o.tech;
  writeConfig(db, rec);
  return getCloudConfig(db);
}

module.exports = {
  getCloudConfig,
  setCloudConfig,
  recordAttestation,
  PLATFORMS,
  CONFIG_KEY,
};

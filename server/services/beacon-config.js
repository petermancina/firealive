// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Subnet Beacon Configuration
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// Deployment-time configuration for the signed subnet peer-beacon
// (services/peer-beacon.js) and its detection response. All values come from
// environment variables so they are set once at deployment and are never
// user-editable at runtime.
//
//   FIREALIVE_BEACON_DISABLED      '1'/'true'/'yes'/'on' turns the beacon off
//                                  entirely (default: enabled). Use on networks
//                                  where UDP broadcast is disallowed; the AC
//                                  ratchet, anti-rollback high-water, and GD
//                                  collision detections remain active without it.
//   FIREALIVE_BEACON_PORT          UDP port (default 47100).
//   FIREALIVE_BEACON_BROADCAST     broadcast address (default 255.255.255.255).
//   FIREALIVE_BEACON_INTERVAL_MS   broadcast interval in ms (default 30000).
//   FIREALIVE_BEACON_ALLOWLIST     comma-separated SHA-256 anchor fingerprints
//                                  (hex) that are KNOWN-LEGITIMATE peers. A
//                                  detected peer whose fingerprint is on this list
//                                  is treated as an authorized co-deployment (for
//                                  example an HA pair) and is NOT quarantined.
//                                  Empty (the default) means no co-deployments are
//                                  declared, so every conflicting identity is
//                                  treated as a potential clone -- the secure
//                                  anti-cloning default (allow-list over blocklist).

const DEFAULT_PORT = 47100;
const DEFAULT_BROADCAST = '255.255.255.255';
const DEFAULT_INTERVAL_MS = 30000;

function isTruthy(value) {
  const s = String(value || '').trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

// Parsed, normalized allow-list of legitimate peer anchor fingerprints.
function getAllowlist() {
  const raw = process.env.FIREALIVE_BEACON_ALLOWLIST || '';
  return raw
    .split(',')
    .map(function (f) { return f.trim().toLowerCase(); })
    .filter(function (f) { return f.length > 0; });
}

// True only if the fingerprint is a declared legitimate co-deployment. An empty
// allow-list returns false for everything, so every conflict is treated as
// suspicious by default.
function isAllowlisted(fingerprint) {
  const fp = String(fingerprint || '').trim().toLowerCase();
  if (!fp) {
    return false;
  }
  return getAllowlist().indexOf(fp) !== -1;
}

// Resolved beacon channel configuration.
function getBeaconConfig() {
  const port = parseInt(process.env.FIREALIVE_BEACON_PORT, 10);
  const intervalMs = parseInt(process.env.FIREALIVE_BEACON_INTERVAL_MS, 10);
  return {
    enabled: !isTruthy(process.env.FIREALIVE_BEACON_DISABLED),
    port: (Number.isInteger(port) && port > 0) ? port : DEFAULT_PORT,
    broadcastAddress: process.env.FIREALIVE_BEACON_BROADCAST || DEFAULT_BROADCAST,
    intervalMs: (Number.isInteger(intervalMs) && intervalMs > 0) ? intervalMs : DEFAULT_INTERVAL_MS,
    allowlist: getAllowlist(),
  };
}

module.exports = {
  DEFAULT_PORT,
  DEFAULT_BROADCAST,
  DEFAULT_INTERVAL_MS,
  getBeaconConfig,
  getAllowlist,
  isAllowlisted,
};

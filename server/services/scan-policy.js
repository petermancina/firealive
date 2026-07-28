//
// FIREALIVE -- Scan Policy (shared)  [B6e]
//
// ONE reader for the master switch and permitted-scanner list that govern a
// vulnerability-scan surface, used by every enforcement point on this server:
//
//   routes/vuln-scan.js         on-prem   key: vuln_scan_config
//   routes/cloud-vuln-scan.js   cloud     key: cloud_vuln_config
//   services/vuln-scan-allowlist.js       (on-prem rate-limiter exemption)
//   services/cloud-vuln-allowlist.js      (cloud rate-limiter exemption)
//
// WHY THIS EXISTS. Before B6e exactly one of the four scan surfaces across both
// servers had a policy layer: the Regional Server's on-prem router, built by
// B5p. The cloud surfaces on both servers had none -- no master switch, no
// permitted-scanner list. An operator could disable on-prem scanning
// platform-wide with one toggle and had NO WAY AT ALL to disable cloud
// scanning short of revoking each authorization one at a time.
//
// That was not an oversight. v022-features.js:513-521 records the earlier
// cloud config-only stub being deliberately REMOVED when B1 built the real
// authorization model, on the reasoning that it "has no faithful mapping into
// the new per-scanner token + IP-allow-list authorization model." Sound for a
// stub. But B5p then built a real policy layer for on-prem and cloud never
// received the equivalent, leaving one policed surface beside two unpoliced
// ones.
//
// ONE POLICY SHAPE, APPLIED PER SURFACE -- not one merged policy. The two
// scanner vocabularies are COMPLETELY DISJOINT:
//
//   on-prem: nessus, openvas, qualys, rapid7, tenable_io, nuclei
//   cloud:   scoutsuite, prowler, pacu, cloudbrute, checkov
//
// A single allowedScanners list spanning both would be ambiguous about which
// surface a name governs, and an ambiguous allow-list is worse than two clear
// ones. Each surface keeps its own config row and its own vocabulary; what is
// shared is the SHAPE, the fail-safe, and this reader.
//
// FAIL-SAFE, AND THE DIRECTION MATTERS. Absent, unparseable, or errored config
// yields { enabled: false, allowedScanners: [] } -- scanning off, nothing
// permitted. A policy reader that failed OPEN would turn a corrupted row into a
// silently unrestricted scan surface. Mirrors readPolicy in
// services/vuln-scan-allowlist.js, which has behaved this way since B5p.
//
// AGPL-3.0-or-later
//

const VALID_SCHEDULES = ['daily', 'weekly', 'monthly', 'manual'];

// The surfaces, their config keys, and their vocabularies. A surface absent
// from here has no policy, which the B6e coverage gate treats as a failure.
const SURFACES = {
  on_prem: {
    key: 'vuln_scan_config',
    validScanners: ['nessus', 'openvas', 'qualys', 'rapid7', 'tenable_io', 'nuclei'],
  },
  cloud: {
    key: 'cloud_vuln_config',
    validScanners: ['scoutsuite', 'prowler', 'pacu', 'cloudbrute', 'checkov'],
  },
};

/**
 * Read the live policy for one scan surface.
 *
 * @param {object} db       an open database handle
 * @param {string} surface  'on_prem' | 'cloud'
 * @returns {{enabled: boolean, allowedScanners: string[], schedule: string}}
 */
function readScanPolicy(db, surface) {
  const spec = SURFACES[surface];
  // An unknown surface must not resolve to a permissive default. A typo here
  // would otherwise silently disable every policy check at that call site.
  if (!spec) {
    return { enabled: false, allowedScanners: [], schedule: 'weekly' };
  }
  const off = { enabled: false, allowedScanners: [], schedule: 'weekly' };
  try {
    if (!db || typeof db.prepare !== 'function') return off;
    const row = db.prepare('SELECT value FROM team_config WHERE key = ?').get(spec.key);
    if (!row || !row.value) return off;
    const cfg = JSON.parse(row.value);
    return {
      // Strict true, not truthy: the string "false" must not enable scanning.
      enabled: !!(cfg && cfg.enabled === true),
      // Filtered against the surface's own vocabulary, so a scanner name that
      // belongs to the OTHER surface can never be permitted here.
      allowedScanners: (cfg && Array.isArray(cfg.allowedScanners))
        ? cfg.allowedScanners.filter((s) => spec.validScanners.includes(s))
        : [],
      schedule: (cfg && VALID_SCHEDULES.includes(cfg.schedule)) ? cfg.schedule : 'weekly',
    };
  } catch (_) {
    return off;
  }
}

/** The config key for a surface, for the routes that write it. */
function policyKey(surface) {
  return SURFACES[surface] ? SURFACES[surface].key : null;
}

/** The permitted scanner vocabulary for a surface. */
function validScanners(surface) {
  return SURFACES[surface] ? SURFACES[surface].validScanners.slice() : [];
}

module.exports = { readScanPolicy, policyKey, validScanners, VALID_SCHEDULES, SURFACES };

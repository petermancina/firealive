//
// FIREALIVE GD -- Scan Policy (shared)  [B6e]
//
// Twin of server/services/scan-policy.js. SEPARATE FILE by design, not by
// oversight: the two servers are separate deployments with separate databases,
// and the row this reads lives in the GD's own `config` table -- not the
// Regional Server's `team_config`. Sharing a module would imply a shared store
// that does not exist. Same reasoning as O3's two machine-cert verifiers.
//
// What must stay identical is the SHAPE and the FAIL-SAFE, not the storage.
//
// TWO STORAGE DIVERGENCES from the MC twin, both verified in the schema rather
// than assumed:
//   - the GD's config table is (key, value) only -- there is NO updated_by
//     column, so the writer records the actor in the audit trail instead
//     (db-init.js:479-482)
//   - the key names are the same, but the table is not
//
// ONE POLICY SHAPE PER SURFACE, not one merged policy. The vocabularies are
// disjoint, so a single allowedScanners list would be ambiguous about which
// surface a name governs. The GD carries BOTH surfaces once B6e lands its
// on-prem router: cloud (shipped since B1) and on-prem (this phase).
//
// FAIL-SAFE, AND THE DIRECTION MATTERS. Absent, unparseable, or errored config
// yields { enabled: false, allowedScanners: [] } -- scanning off, nothing
// permitted, nothing exempted from rate limiting. A reader that failed OPEN
// would turn a corrupted row into a silently unrestricted scan surface.
//
// AGPL-3.0-or-later
//

const VALID_SCHEDULES = ['daily', 'weekly', 'monthly', 'manual'];

const SURFACES = {
  cloud: {
    key: 'cloud_vuln_config',
    validScanners: ['scoutsuite', 'prowler', 'pacu', 'cloudbrute', 'checkov'],
  },
  on_prem: {
    key: 'vuln_scan_config',
    validScanners: ['nessus', 'openvas', 'qualys', 'rapid7', 'tenable_io', 'nuclei'],
  },
};

/**
 * Read the live policy for one scan surface on the Global Dashboard.
 *
 * @param {object} db       an open GD database handle
 * @param {string} surface  'cloud' | 'on_prem'
 * @returns {{enabled: boolean, allowedScanners: string[], schedule: string}}
 */
function readScanPolicy(db, surface) {
  const spec = SURFACES[surface];
  const off = { enabled: false, allowedScanners: [], schedule: 'weekly' };
  // An unknown surface must not resolve to a permissive default: a typo at a
  // call site would otherwise silently disable every policy check there.
  if (!spec) return off;
  try {
    if (!db || typeof db.prepare !== 'function') return off;
    // The GD's own config table, NOT team_config.
    const row = db.prepare('SELECT value FROM config WHERE key = ?').get(spec.key);
    if (!row || !row.value) return off;
    const cfg = JSON.parse(row.value);
    return {
      // Strict true, not truthy: the string "false" must not enable scanning.
      enabled: !!(cfg && cfg.enabled === true),
      // Filtered against this surface's own vocabulary, so a scanner name
      // belonging to the OTHER surface can never be permitted here.
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

/** The permitted scanner vocabulary for a surface. Returns a COPY. */
function validScanners(surface) {
  return SURFACES[surface] ? SURFACES[surface].validScanners.slice() : [];
}

module.exports = { readScanPolicy, policyKey, validScanners, VALID_SCHEDULES, SURFACES };

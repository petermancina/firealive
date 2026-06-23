// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Data-Residency Core Service
//
// The decision and reconciliation logic behind the data-residency policy. Where
// geo-fencing (B5n) controls who may log in from where, this controls where the
// bytes physically live across jurisdictions (e.g. GDPR Chapter V).
//
// Synchronous and (for the decision) side-effect-free, mirroring geo-fence.js:
// callers act on the returned verdict and own the audit/alert. better-sqlite3
// is synchronous, so nothing here awaits.
//
// Exports:
//   loadResidencyConfig(db)                       -> the policy, defaults merged
//   evaluateDestination(db, category, ref)        -> a destination verdict
//   reconcileTransfers(db)                         -> rebuild the transfer register
//   summarize(db)                                  -> { transfers, documented, blocked }
//   resolveDestinationJurisdiction(db, cat, ref)   -> { country, providerDomicile, region, keyCustody, source }
//   defaultConfig(), foreignLawExposure(), deriveStatus()
//   CATEGORIES, MODES, RECONCILED_CATEGORIES, CONFIG_KEY
//
// The policy is destination-agnostic (data category -> permitted regions), so it
// is forward-compatible with B5q: B5n2 enforces it for backups + the live
// deployment; B5q's storage resolver extends enforcement to the routed types.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const regions = require('./residency-regions');

const CONFIG_KEY = 'data_residency_config';

// All recognized data categories. live_deployment is the deployment itself (one
// declared primary residency, never blocked); backup has real remote
// destinations today; the four routed types are declared/co-resident now and
// enforced once B5q routes them.
const CATEGORIES = [
  'live_deployment', 'backup', 'audit_log', 'forensic_export', 'snapshot', 'cef_archive',
];
const MODES = ['enforce', 'warn', 'declare-only'];

// Categories reconciled into the transfer register by this phase. Backups are
// the only category with real remote destinations today; B5q extends this list
// to the routed types when it adds their storage routing.
const RECONCILED_CATEGORIES = ['backup'];

// Default policy: off. live_deployment is declare-only (never blocked -- a
// running deployment cannot be relocated). Destination-backed categories start
// unconstrained (empty permittedRegions) in warn mode.
function defaultConfig() {
  return {
    enabled: false,
    primaryResidency: { country: null, region: null, providerDomicile: null, source: 'declared' },
    categories: {
      live_deployment: { mode: 'declare-only' },
      backup: { permittedRegions: [], mode: 'warn' },
      audit_log: { permittedRegions: [], mode: 'warn' },
      forensic_export: { permittedRegions: [], mode: 'warn' },
      snapshot: { permittedRegions: [], mode: 'warn' },
      cef_archive: { permittedRegions: [], mode: 'warn' },
    },
  };
}

function upperOrNull(v) {
  return (typeof v === 'string' && v.trim().length) ? v.trim().toUpperCase() : null;
}
function strOrNull(v) {
  return (typeof v === 'string' && v.trim().length) ? v.trim() : null;
}

// Read + parse the policy, merging stored fields onto the default so callers
// always receive a complete, well-typed shape. A missing or malformed key
// yields the default (off).
function loadResidencyConfig(db) {
  const cfg = defaultConfig();
  let stored = null;
  try {
    const row = db.prepare('SELECT value FROM config WHERE key = ?').get(CONFIG_KEY);
    if (row && typeof row.value === 'string') stored = JSON.parse(row.value);
  } catch (e) {
    stored = null;
  }
  if (!stored || typeof stored !== 'object') return cfg;

  if (typeof stored.enabled === 'boolean') cfg.enabled = stored.enabled;

  if (stored.primaryResidency && typeof stored.primaryResidency === 'object') {
    const pr = stored.primaryResidency;
    cfg.primaryResidency = {
      country: upperOrNull(pr.country),
      region: strOrNull(pr.region),
      providerDomicile: upperOrNull(pr.providerDomicile),
      source: (pr.source === 'cloud-metadata') ? 'cloud-metadata' : 'declared',
    };
  }

  if (stored.categories && typeof stored.categories === 'object') {
    for (let i = 0; i < CATEGORIES.length; i += 1) {
      const cat = CATEGORIES[i];
      const sc = stored.categories[cat];
      if (!sc || typeof sc !== 'object') continue;
      if (cat === 'live_deployment') {
        cfg.categories[cat] = { mode: 'declare-only' };
        continue;
      }
      const mode = (sc.mode === 'enforce' || sc.mode === 'warn') ? sc.mode : 'warn';
      const permitted = Array.isArray(sc.permittedRegions)
        ? sc.permittedRegions
            .filter(function (t) { return typeof t === 'string' && t.trim().length; })
            .map(function (t) { return t.trim().toUpperCase(); })
        : [];
      cfg.categories[cat] = { permittedRegions: permitted, mode: mode };
    }
  }
  return cfg;
}

// The operator's declared jurisdiction if present, else a best-effort inference
// from the backup destination's adapter config (backup category only, where the
// ref is a backup_destinations.id). Reads config only, never credentials.
function resolveDestinationJurisdiction(db, category, destinationRef) {
  // 1. Operator declaration.
  try {
    const decl = db.prepare(
      'SELECT declared_country, declared_region, provider_domicile, key_custody '
      + 'FROM data_residency_destinations WHERE destination_kind = ? AND destination_ref = ?'
    ).get(category, destinationRef);
    if (decl && strOrNull(decl.declared_country)) {
      return {
        country: upperOrNull(decl.declared_country),
        providerDomicile: upperOrNull(decl.provider_domicile),
        region: strOrNull(decl.declared_region),
        keyCustody: strOrNull(decl.key_custody),
        source: 'declared',
      };
    }
  } catch (e) {
    // fall through to inference
  }

  // 2. Best-effort inference (backup destinations only).
  if (category === 'backup') {
    try {
      const dest = db.prepare('SELECT adapter, config FROM backup_destinations WHERE id = ?').get(destinationRef);
      if (dest && typeof dest.config === 'string') {
        let parsed = null;
        try { parsed = JSON.parse(dest.config); } catch (e2) { parsed = null; }
        if (parsed && typeof parsed === 'object') {
          const inf = regions.inferDestinationRegion(dest.adapter, parsed);
          if (inf && inf.country) {
            return {
              country: inf.country,
              providerDomicile: inf.domicile || null,
              region: inf.region || null,
              keyCustody: null,
              source: 'inferred',
            };
          }
        }
      }
    } catch (e) {
      // none
    }
  }
  return { country: null, providerDomicile: null, region: null, keyCustody: null, source: null };
}

function verdict(action, compliant, mode, blocked, jurisdiction, providerDomicile, keyCustody, permitted, reason) {
  return {
    action: action,
    compliant: compliant,
    mode: mode,
    blocked: blocked,
    destinationJurisdiction: jurisdiction,
    providerDomicile: providerDomicile,
    keyCustody: keyCustody,
    permittedRegions: permitted,
    reason: reason,
  };
}

// Evaluate one destination for a category. Synchronous, no writes. Decision
// order: disabled -> declare-only -> category-open -> undeclared -> permitted ->
// violation. blocked is true only on a violation/undeclared under enforce mode.
function evaluateDestination(db, category, destinationRef) {
  const cfg = loadResidencyConfig(db);

  // (1) Feature off -- nothing enforced.
  if (!cfg.enabled) {
    return verdict('disabled', true, null, false, null, null, null, [], 'data residency not enabled');
  }

  const cat = cfg.categories[category] || null;
  const mode = (cat && (cat.mode === 'enforce' || cat.mode === 'warn' || cat.mode === 'declare-only'))
    ? cat.mode : 'warn';

  // (2) Declare-only (the live deployment) is surfaced, never blocked.
  if (mode === 'declare-only') {
    return verdict('declare-only', true, 'declare-only', false, null, null, null, [],
      'category is declare-only (never blocked)');
  }

  const permitted = (cat && Array.isArray(cat.permittedRegions)) ? cat.permittedRegions : [];

  // (3) No permitted-region policy set -> unconstrained (open).
  if (!permitted.length) {
    return verdict('category-open', true, mode, false, null, null, null, [],
      'no permitted-region policy set for category');
  }

  // (4) Resolve jurisdiction (declared, else inferred). Undeclared fails closed
  //     under enforce.
  const jur = resolveDestinationJurisdiction(db, category, destinationRef);
  if (!jur.country) {
    return verdict('undeclared', false, mode, (mode === 'enforce'), null, jur.providerDomicile,
      jur.keyCustody, permitted, 'destination jurisdiction is undeclared and could not be inferred');
  }

  // (5) Allow-list check.
  if (regions.isPermitted(jur.country, permitted)) {
    return verdict('compliant', true, mode, false, jur.country, jur.providerDomicile, jur.keyCustody,
      permitted, 'destination jurisdiction ' + jur.country + ' is within the permitted regions');
  }
  return verdict('violation-region', false, mode, (mode === 'enforce'), jur.country, jur.providerDomicile,
    jur.keyCustody, permitted, 'destination jurisdiction ' + jur.country + ' is outside the permitted regions');
}

// US-domiciled providers (AWS / GCP / Azure) are reachable under the US CLOUD
// Act regardless of region; other domiciles carry their own home law. This is
// the residency-is-not-sovereignty signal carried on each register row.
function foreignLawExposure(providerDomicile) {
  const d = upperOrNull(providerDomicile);
  if (!d) return null;
  if (d === 'US') return 'US CLOUD Act';
  return d + ' provider-domicile law';
}

function deriveStatus(mechanism) {
  if (mechanism === 'adequacy' || mechanism === 'scc' || mechanism === 'bcr' || mechanism === 'derogation') {
    return 'documented';
  }
  return 'undocumented';
}

// Is a destination in the given country blocked by the category policy? Only
// when the category is in enforce mode with a non-empty permitted list that the
// country is not in. (Matches evaluateDestination's block logic.)
function isBlockedByPolicy(cfg, category, country) {
  const cat = cfg.categories[category];
  if (!cat || cat.mode !== 'enforce') return false;
  const permitted = Array.isArray(cat.permittedRegions) ? cat.permittedRegions : [];
  if (!permitted.length) return false;
  return !regions.isPermitted(country, permitted);
}

function listDestinationsForCategory(db, category) {
  if (category === 'backup') {
    const rows = db.prepare('SELECT id FROM backup_destinations WHERE enabled = 1').all();
    return rows.map(function (r) { return r.id; });
  }
  // B5q categories have no live destinations resolvable here yet.
  return [];
}

function upsertTransfer(db, t) {
  const existing = db.prepare(
    'SELECT mechanism FROM data_residency_transfers WHERE transfer_key = ?'
  ).get(t.transfer_key);
  const status = t.blocked ? 'blocked' : deriveStatus(existing ? existing.mechanism : 'unset');
  if (existing) {
    // Preserve operator annotations (mechanism, notes, review) and detected_at.
    db.prepare(
      'UPDATE data_residency_transfers SET data_category = ?, source_jurisdiction = ?, '
      + 'dest_jurisdiction = ?, destination_ref = ?, provider_domicile = ?, '
      + 'foreign_law_exposure = ?, key_custody = ?, status = ? WHERE transfer_key = ?'
    ).run(t.data_category, t.source_jurisdiction, t.dest_jurisdiction, t.destination_ref,
      t.provider_domicile, t.foreign_law_exposure, t.key_custody, status, t.transfer_key);
  } else {
    db.prepare(
      'INSERT INTO data_residency_transfers (transfer_key, data_category, source_jurisdiction, '
      + 'dest_jurisdiction, destination_ref, provider_domicile, foreign_law_exposure, key_custody, '
      + "mechanism, mechanism_notes, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unset', NULL, ?)"
    ).run(t.transfer_key, t.data_category, t.source_jurisdiction, t.dest_jurisdiction,
      t.destination_ref, t.provider_domicile, t.foreign_law_exposure, t.key_custody, status);
  }
}

function pruneStaleTransfers(db, categories, seen) {
  for (let i = 0; i < categories.length; i += 1) {
    const rows = db.prepare(
      'SELECT transfer_key FROM data_residency_transfers WHERE data_category = ?'
    ).all(categories[i]);
    for (let j = 0; j < rows.length; j += 1) {
      if (!seen[rows[j].transfer_key]) {
        db.prepare('DELETE FROM data_residency_transfers WHERE transfer_key = ?').run(rows[j].transfer_key);
      }
    }
  }
}

// Rebuild the cross-border transfer register for the reconciled categories. A
// transfer is any enabled destination whose resolved jurisdiction differs from
// the deployment's declared primary residency. Upserts current transfers
// (preserving operator annotations), then prunes stale rows for the handled
// categories only (so B5q-managed rows are untouched). Cross-border detection
// requires a declared primary residency; without one, none are computed.
function reconcileTransfers(db) {
  const cfg = loadResidencyConfig(db);
  const source = (cfg.primaryResidency && cfg.primaryResidency.country)
    ? cfg.primaryResidency.country : null;

  const run = db.transaction(function () {
    const seen = {};
    if (source) {
      for (let i = 0; i < RECONCILED_CATEGORIES.length; i += 1) {
        const category = RECONCILED_CATEGORIES[i];
        const refs = listDestinationsForCategory(db, category);
        for (let j = 0; j < refs.length; j += 1) {
          const ref = refs[j];
          const jur = resolveDestinationJurisdiction(db, category, ref);
          if (!jur.country) continue;            // unclassifiable; surfaced as undeclared elsewhere
          if (jur.country === source) continue;  // co-resident, not a cross-border transfer
          const key = category + ':' + ref;
          seen[key] = true;
          upsertTransfer(db, {
            transfer_key: key,
            data_category: category,
            source_jurisdiction: source,
            dest_jurisdiction: jur.country,
            destination_ref: ref,
            provider_domicile: jur.providerDomicile || null,
            foreign_law_exposure: foreignLawExposure(jur.providerDomicile),
            key_custody: jur.keyCustody || null,
            blocked: isBlockedByPolicy(cfg, category, jur.country),
          });
        }
      }
    }
    pruneStaleTransfers(db, RECONCILED_CATEGORIES, seen);
  });
  run();
}

// { transfers, documented, blocked }. documented = a recorded transfer
// mechanism (anything but 'unset' / 'none'); blocked = a refused write.
function summarize(db) {
  const out = { transfers: 0, documented: 0, blocked: 0 };
  try {
    const total = db.prepare('SELECT COUNT(*) AS n FROM data_residency_transfers').get();
    out.transfers = total ? total.n : 0;
    const doc = db.prepare(
      "SELECT COUNT(*) AS n FROM data_residency_transfers WHERE mechanism NOT IN ('unset', 'none')"
    ).get();
    out.documented = doc ? doc.n : 0;
    const blk = db.prepare(
      "SELECT COUNT(*) AS n FROM data_residency_transfers WHERE status = 'blocked'"
    ).get();
    out.blocked = blk ? blk.n : 0;
  } catch (e) {
    return { transfers: 0, documented: 0, blocked: 0 };
  }
  return out;
}

module.exports = {
  CONFIG_KEY: CONFIG_KEY,
  CATEGORIES: CATEGORIES,
  MODES: MODES,
  RECONCILED_CATEGORIES: RECONCILED_CATEGORIES,
  defaultConfig: defaultConfig,
  loadResidencyConfig: loadResidencyConfig,
  resolveDestinationJurisdiction: resolveDestinationJurisdiction,
  evaluateDestination: evaluateDestination,
  foreignLawExposure: foreignLawExposure,
  deriveStatus: deriveStatus,
  isBlockedByPolicy: isBlockedByPolicy,
  reconcileTransfers: reconcileTransfers,
  summarize: summarize,
};

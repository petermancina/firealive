'use strict';

// =============================================================================
// FIREALIVE GD -- key-custody residency gate  [B6g]
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// =============================================================================
//
// A KMS key has a region, and the operator of that KMS has a domicile. Wrapping
// the GD's backup data key under a US-domiciled key while gd_residency declares
// EU-only is a cross-border KEY-CUSTODY event, not a data-location event, and
// FireAlive already treats "whose law can compel" as a first-class control.
//
// WHY THIS DOES NOT REUSE gd-data-residency.js's decide().
// That was the obvious build, and it is wrong. decide() in gd-data-residency.js
// runs a fixed order -- disabled, declare-only, category-open, undeclared,
// permitted, violation -- and its third step is:
//
//     // No permitted-region policy set -> unconstrained (open).
//     if (!permitted.length) {
//       return verdict('category-open', true, mode, false, ...);
//     }
//
// That is FAIL-OPEN on an unset policy, and it is the right default for the
// categories it governs. An operator who enables residency but has not listed
// permitted regions for `backup` should not have every backup blocked; the
// destination is already recorded and the transfer register already surfaces it.
//
// Key custody is different in kind. A KMS key holder can be COMPELLED TO
// UNWRAP. The data-location categories answer "where do the bytes sit"; this one
// answers "who can be ordered to open them". Silently permitting a US-domiciled
// KMS to hold the wrapping key for an EU-only deployment, because the operator
// left one field blank, is precisely the half-applied control this project keeps
// finding: a switch that reports success and does part of the job.
//
// So this module reuses the residency machinery -- the same config, the same
// region-to-country map, the same verdict shape, the same foreign-law
// derivation -- and overrides exactly one step: an enabled residency policy with
// no key_custody permitted list DENIES rather than opening.
//
// THE ONE THING IT DOES NOT DO IS BLOCK A DEPLOYMENT THAT NEVER ASKED. When
// residency is disabled entirely (cfg.enabled === false) this permits, because
// an operator who has not turned residency on has not made a residency claim
// this could contradict. Default-deny applies WITHIN a declared policy, not to
// deployments that never declared one. Blocking those would make an unrelated
// feature a prerequisite for configuring a KMS provider.
//
// The denial is loud and names the remedy, because a default-deny an operator
// cannot act on is indistinguishable from a bug.

const residency = require('./gd-data-residency');
const regions = require('./gd-residency-regions');

// The category key. It IS listed in gd-data-residency's CATEGORIES, because that
// array is what loadResidencyConfig iterates -- a category absent from it is
// silently DROPPED when the config is read, so a key_custody policy could never
// load. That was found by executing the gate, not by reading it.
//
// Being listed there does not route it through decide(): checked rather than
// assumed. routes/data-residency.js iterates CATEGORIES only to validate and
// store (:229), the reconcile path uses RECONCILED_CATEGORIES (:70) which this
// deliberately does not join, and every evaluateDestination / evaluateConfig
// call site passes an explicit category.
const CATEGORY = 'key_custody';

// Which config field holds a provider's region, per provider type. The KMS
// regions are the same region tokens those clouds use everywhere else, so
// gd-residency-regions' PROVIDERS map already resolves them -- this is the
// per-provider knowledge of WHERE TO LOOK, which that map does not carry.
//
// gd-tier1 has no entry: it is the local KEK, there is no external custodian,
// and no jurisdiction question arises. hashicorp-vault and azure-keyvault have
// no entry either -- both are addressed by hostname rather than a cloud region
// token, so their jurisdiction cannot be inferred and must be DECLARED.
// VERIFIED against each provider's validateConfig rather than assumed. Two of
// the three first written here were wrong, and both failed silently in the same
// direction: no region found -> `undeclared` -> blocked under enforce, permitted
// under warn. A residency control that cannot read the config it governs still
// returns a verdict, which is worse than returning none.
//
//   aws-kms         requires region, key_id                 -> region
//   gcp-kms         requires project_id, LOCATION_ID, ...   -> location_id
//   azure-keyvault  requires vault_url, key_name            -> NO REGION FIELD
//
// azure-keyvault is deliberately absent. Its config carries no region: the
// vault's DNS name (my-vault.vault.azure.net) does not encode one, so the
// jurisdiction cannot be inferred and must be DECLARED -- the same treatment
// hashicorp-vault gets, and for the same reason. Inferring a country from a
// hostname would be a guess presented as a fact.
const REGION_FIELD = {
  'aws-kms': { field: 'region', provider: 'aws' },
  'gcp-kms': { field: 'location_id', provider: 'gcp' },
};

/**
 * Resolve the jurisdiction of a KMS provider config.
 *
 * Returns the same shape gd-data-residency's resolvers return, so the verdict
 * carries the same fields the transfer register already stores.
 *
 * @param {string} providerType
 * @param {object} config
 * @param {string|null} declaredCountry  operator-declared, overrides inference
 * @returns {{country: string|null, providerDomicile: string|null, keyCustody: string|null, source: string}}
 */
function resolveProviderJurisdiction(providerType, config, declaredCountry) {
  // A declaration always wins over an inference. The operator knows things the
  // region token does not encode -- a Vault cluster's physical location, a
  // sovereign-cloud partition -- and a declared fact should never be overridden
  // by a guess.
  const declared = typeof declaredCountry === 'string' && declaredCountry.trim()
    ? declaredCountry.trim().toUpperCase()
    : null;

  if (providerType === 'gd-tier1') {
    // The local KEK. No external custodian, so no foreign law reaches it: this
    // is the one provider type whose key custody is unambiguously the
    // deployment's own.
    return {
      country: declared,
      providerDomicile: null,
      keyCustody: 'local (GD Tier-1 KEK, hardware-sealed)',
      source: 'local',
    };
  }

  const spec = REGION_FIELD[providerType];
  if (!spec) {
    // hashicorp-vault and anything added later without a region field.
    return {
      country: declared,
      providerDomicile: declared ? null : null,
      keyCustody: declared
        ? 'operator-declared (' + declared + ')'
        : 'undeclared (no region to infer from)',
      source: declared ? 'declared' : 'undeclared',
    };
  }

  const token = config && typeof config[spec.field] === 'string' ? config[spec.field].trim() : '';
  if (!token) {
    return {
      country: declared,
      providerDomicile: null,
      keyCustody: declared ? 'operator-declared (' + declared + ')' : 'undeclared (no region set)',
      source: declared ? 'declared' : 'undeclared',
    };
  }

  const hit = regions.regionToCountry(token);
  const country = declared || (hit ? hit.country : null);
  // The domicile is a property of the PROVIDER, not the region. An EU region
  // operated by a US company is still reachable under US law, which is the
  // whole point of tracking domicile separately from location.
  const domicile = hit ? hit.domicile : null;

  return {
    country: country,
    providerDomicile: domicile,
    keyCustody: (country ? country : 'unknown') + ' key custody via ' + providerType
      + (domicile ? ' (' + domicile + '-domiciled operator)' : ''),
    source: declared ? 'declared' : (hit ? 'inferred' : 'unresolved'),
  };
}

/**
 * Evaluate whether a KMS provider may hold the backup wrapping key.
 *
 * @param {object} db
 * @param {string} providerType
 * @param {object} config
 * @param {string|null} [declaredCountry]
 * @returns {object} a residency verdict, plus `permitted` (boolean)
 */
function evaluateKeyCustody(db, providerType, config, declaredCountry) {
  const cfg = residency.loadResidencyConfig(db);
  const jur = resolveProviderJurisdiction(providerType, config, declaredCountry);

  const base = {
    action: null,
    compliant: false,
    mode: null,
    blocked: false,
    destinationJurisdiction: jur.country,
    providerDomicile: jur.providerDomicile,
    keyCustody: jur.keyCustody,
    permittedRegions: [],
    reason: '',
    permitted: false,
  };

  // Residency not in use at all: this gate makes no claim. See the header --
  // default-deny applies within a declared policy, not to deployments that
  // never declared one.
  if (!cfg.enabled) {
    return Object.assign({}, base, {
      action: 'disabled', compliant: true, permitted: true,
      reason: 'data residency is not enabled; key custody is unconstrained',
    });
  }

  // The local KEK is always permitted. There is no external custodian to place
  // in a jurisdiction, and refusing it would leave a residency-enabled
  // deployment with no way to wrap a backup key at all.
  if (providerType === 'gd-tier1') {
    return Object.assign({}, base, {
      action: 'local-kek', compliant: true, permitted: true, mode: 'enforce',
      reason: 'gd-tier1 is the local hardware-sealed KEK; no external key custodian',
    });
  }

  const cat = cfg.categories && cfg.categories[CATEGORY] ? cfg.categories[CATEGORY] : null;
  const mode = cat && residency.MODES.indexOf(cat.mode) !== -1 ? cat.mode : 'enforce';
  const permittedRegions = cat && Array.isArray(cat.permittedRegions) ? cat.permittedRegions : [];

  // ── THE OVERRIDE ────────────────────────────────────────────────────────
  // gd-data-residency's decide() returns 'category-open' here and permits. This
  // denies. A KMS key holder can be compelled to unwrap, and an operator who
  // has declared a residency policy has not thereby authorised an unlisted
  // jurisdiction to hold the wrapping key for their backups.
  if (!permittedRegions.length) {
    return Object.assign({}, base, {
      action: 'denied-unset', compliant: false, blocked: true, mode: mode,
      permitted: false,
      reason: 'data residency is enabled but no permitted regions are set for '
        + CATEGORY + '. An external KMS holds the key that opens your backups and '
        + 'can be compelled to use it, so this is denied until you list the '
        + 'jurisdictions permitted to hold it.',
    });
  }

  if (!jur.country) {
    return Object.assign({}, base, {
      action: 'undeclared', compliant: false, blocked: (mode === 'enforce'),
      mode: mode, permittedRegions: permittedRegions,
      permitted: (mode !== 'enforce'),
      reason: 'key-custody jurisdiction is undeclared and could not be inferred from the provider config',
    });
  }

  if (regions.isPermitted(jur.country, permittedRegions)) {
    return Object.assign({}, base, {
      action: 'compliant', compliant: true, mode: mode,
      permittedRegions: permittedRegions, permitted: true,
      reason: 'key-custody jurisdiction ' + jur.country + ' is within the permitted regions',
    });
  }

  return Object.assign({}, base, {
    action: 'violation-region', compliant: false, blocked: (mode === 'enforce'),
    mode: mode, permittedRegions: permittedRegions,
    permitted: (mode !== 'enforce'),
    reason: 'key-custody jurisdiction ' + jur.country + ' is outside the permitted regions',
  });
}

/**
 * The transfer-register row a permitted-but-foreign custody arrangement should
 * produce. Returns null when there is nothing to register (local KEK, or
 * residency disabled).
 */
function transferRegisterEntry(providerName, verdictObj) {
  if (!verdictObj || verdictObj.action === 'disabled' || verdictObj.action === 'local-kek') return null;
  if (!verdictObj.providerDomicile && !verdictObj.destinationJurisdiction) return null;
  return {
    transfer_key: 'key_custody:' + providerName,
    data_category: CATEGORY,
    dest_jurisdiction: verdictObj.destinationJurisdiction,
    destination_ref: providerName,
    provider_domicile: verdictObj.providerDomicile,
    foreign_law_exposure: residency.foreignLawExposure(verdictObj.providerDomicile),
    key_custody: verdictObj.keyCustody,
    status: verdictObj.compliant ? 'undocumented' : 'blocked',
  };
}

module.exports = {
  CATEGORY: CATEGORY,
  REGION_FIELD: REGION_FIELD,
  resolveProviderJurisdiction: resolveProviderJurisdiction,
  evaluateKeyCustody: evaluateKeyCustody,
  transferRegisterEntry: transferRegisterEntry,
};

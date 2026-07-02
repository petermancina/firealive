// =============================================================================
// FIREALIVE GD -- Data-Residency Region Taxonomy
//
// Static, offline mapping from cloud-provider region codes to the ISO 3166-1
// alpha-2 country the region is physically in, plus the provider's legal domicile
// (the jurisdiction whose law can compel the provider, distinct from where the
// bytes sit -- residency is not sovereignty). Also defines legal blocs
// (EU / EEA / UK / US) so a residency policy may permit a bloc as shorthand for
// any member country. Twins the Regional region taxonomy; the region-to-country
// facts are provider facts and are identical on both sides.
//
// Used by gd-data-residency.js to:
//   - resolve a storage destination's jurisdiction (regionToCountry),
//   - test a jurisdiction against a permitted-region allow-list (isPermitted),
//   - best-effort auto-suggest a destination's region from its adapter config
//     (inferDestinationRegion) so the operator confirms rather than types it.
//
// The provider tables are intentionally best-effort, NOT exhaustive: an unmapped
// region resolves to a null country and the operator declares the jurisdiction
// manually rather than the system guessing wrong. ALL of AWS / GCP / Azure are
// US-domiciled (US CLOUD Act reach), the same "whose law can compel" axis as the
// AI-model provenance policy.
//
// AGPL-3.0-or-later
// =============================================================================

'use strict';

// Provider region -> ISO 3166-1 alpha-2 country. domicile is the provider's legal
// home. AWS / GCP / Azure are all US-domiciled.
const PROVIDERS = {
  aws: {
    domicile: 'US',
    regions: {
      'us-east-1': 'US', 'us-east-2': 'US', 'us-west-1': 'US', 'us-west-2': 'US',
      'ca-central-1': 'CA', 'ca-west-1': 'CA',
      'eu-west-1': 'IE', 'eu-west-2': 'GB', 'eu-west-3': 'FR',
      'eu-central-1': 'DE', 'eu-central-2': 'CH', 'eu-north-1': 'SE',
      'eu-south-1': 'IT', 'eu-south-2': 'ES',
      'sa-east-1': 'BR',
      'ap-south-1': 'IN', 'ap-south-2': 'IN',
      'ap-southeast-1': 'SG', 'ap-southeast-2': 'AU', 'ap-southeast-3': 'ID',
      'ap-southeast-4': 'AU',
      'ap-northeast-1': 'JP', 'ap-northeast-2': 'KR', 'ap-northeast-3': 'JP',
      'ap-east-1': 'HK',
      'me-south-1': 'BH', 'me-central-1': 'AE',
      'af-south-1': 'ZA', 'il-central-1': 'IL',
    },
  },
  gcp: {
    domicile: 'US',
    regions: {
      'us-central1': 'US', 'us-east1': 'US', 'us-east4': 'US', 'us-east5': 'US',
      'us-west1': 'US', 'us-west2': 'US', 'us-west3': 'US', 'us-west4': 'US',
      'us-south1': 'US',
      'northamerica-northeast1': 'CA', 'northamerica-northeast2': 'CA',
      'southamerica-east1': 'BR', 'southamerica-west1': 'CL',
      'europe-west1': 'BE', 'europe-west2': 'GB', 'europe-west3': 'DE',
      'europe-west4': 'NL', 'europe-west6': 'CH', 'europe-west8': 'IT',
      'europe-west9': 'FR', 'europe-west10': 'DE', 'europe-west12': 'IT',
      'europe-central2': 'PL', 'europe-north1': 'FI', 'europe-southwest1': 'ES',
      'asia-east1': 'TW', 'asia-east2': 'HK',
      'asia-northeast1': 'JP', 'asia-northeast2': 'JP', 'asia-northeast3': 'KR',
      'asia-south1': 'IN', 'asia-south2': 'IN',
      'asia-southeast1': 'SG', 'asia-southeast2': 'ID',
      'australia-southeast1': 'AU', 'australia-southeast2': 'AU',
      'me-west1': 'IL', 'me-central1': 'QA', 'me-central2': 'SA',
      'africa-south1': 'ZA',
    },
  },
  azure: {
    domicile: 'US',
    regions: {
      'eastus': 'US', 'eastus2': 'US', 'centralus': 'US', 'northcentralus': 'US',
      'southcentralus': 'US', 'westcentralus': 'US',
      'westus': 'US', 'westus2': 'US', 'westus3': 'US',
      'canadacentral': 'CA', 'canadaeast': 'CA',
      'brazilsouth': 'BR',
      'northeurope': 'IE', 'westeurope': 'NL',
      'uksouth': 'GB', 'ukwest': 'GB',
      'francecentral': 'FR', 'francesouth': 'FR',
      'germanywestcentral': 'DE', 'germanynorth': 'DE',
      'switzerlandnorth': 'CH', 'switzerlandwest': 'CH',
      'norwayeast': 'NO', 'norwaywest': 'NO',
      'swedencentral': 'SE', 'polandcentral': 'PL',
      'italynorth': 'IT', 'spaincentral': 'ES',
      'eastasia': 'HK', 'southeastasia': 'SG',
      'japaneast': 'JP', 'japanwest': 'JP',
      'koreacentral': 'KR', 'koreasouth': 'KR',
      'centralindia': 'IN', 'southindia': 'IN', 'westindia': 'IN',
      'australiaeast': 'AU', 'australiasoutheast': 'AU', 'australiacentral': 'AU',
      'uaenorth': 'AE', 'uaecentral': 'AE',
      'southafricanorth': 'ZA', 'southafricawest': 'ZA',
      'israelcentral': 'IL', 'qatarcentral': 'QA',
    },
  },
};

// Legal blocs -> the ISO country set they expand to. A residency policy may list a
// bloc name (e.g. 'EU') as shorthand for any member country. 'US' is a
// single-country alias kept for symmetry with the other shorthands.
const EU_COUNTRIES = [
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR',
  'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK',
  'SI', 'ES', 'SE',
];
const EEA_COUNTRIES = EU_COUNTRIES.concat(['IS', 'LI', 'NO']);

const BLOCS = {
  EU: EU_COUNTRIES,
  EEA: EEA_COUNTRIES,
  UK: ['GB'],
  US: ['US'],
};

// Uppercase + trim a token; returns null for non-strings or empty input.
function normalizeToken(v) {
  if (typeof v !== 'string') return null;
  const t = v.trim().toUpperCase();
  return t.length ? t : null;
}

// Look up a provider region code -> { country, domicile, provider } or null.
// Region-code formats differ across providers (aws 'us-east-1', gcp 'us-east1',
// azure 'eastus'), so a cross-provider scan is unambiguous in practice; first
// match wins.
function regionToCountry(region) {
  if (typeof region !== 'string') return null;
  const key = region.trim();
  if (!key.length) return null;
  const names = Object.keys(PROVIDERS);
  for (let i = 0; i < names.length; i += 1) {
    const p = PROVIDERS[names[i]];
    if (Object.prototype.hasOwnProperty.call(p.regions, key)) {
      return { country: p.regions[key], domicile: p.domicile, provider: names[i] };
    }
  }
  return null;
}

// Given an ISO country code, return it plus the blocs it belongs to (a bloc whose
// name equals the country, e.g. the US alias for US, is not listed).
function resolveJurisdiction(country) {
  const c = normalizeToken(country);
  if (!c) return { country: null, blocs: [] };
  const blocs = [];
  const names = Object.keys(BLOCS);
  for (let i = 0; i < names.length; i += 1) {
    if (names[i] !== c && BLOCS[names[i]].indexOf(c) !== -1) {
      blocs.push(names[i]);
    }
  }
  return { country: c, blocs: blocs };
}

// True if a jurisdiction (ISO country) is allowed by a permitted-region list.
// Tokens may be ISO country codes or bloc names. An empty or non-array list
// returns false; the caller treats an empty permitted list as "unconstrained"
// upstream, before calling here.
function isPermitted(jurisdiction, permittedRegions) {
  const c = normalizeToken(jurisdiction);
  if (!c) return false;
  if (!Array.isArray(permittedRegions)) return false;
  for (let i = 0; i < permittedRegions.length; i += 1) {
    const tok = normalizeToken(permittedRegions[i]);
    if (!tok) continue;
    if (tok === c) return true;
    if (Object.prototype.hasOwnProperty.call(BLOCS, tok) && BLOCS[tok].indexOf(c) !== -1) {
      return true;
    }
  }
  return false;
}

// Best-effort region auto-suggestion from a storage destination's adapter config.
// Returns { region, country, domicile, provider } (any field may be null) or null
// when nothing can be inferred and the operator must declare. Reads config only,
// never credentials.
//   - s3 with a custom endpoint: an S3-compatible third party (not AWS); the
//     region token is surfaced but country/domicile stay null because such a
//     provider is NOT US-domiciled by assumption (e.g. Hetzner, Scaleway).
//   - s3 without an endpoint: real AWS S3; resolve the region to a country and the
//     AWS US domicile where the region is mapped.
//   - gcs / azure-blob: region is bucket/account-level and absent from config.
//   - sftp / local: no region concept.
function inferDestinationRegion(adapter, config) {
  if (adapter !== 's3' || !config || typeof config !== 'object') return null;
  const region = (typeof config.region === 'string' && config.region.trim().length)
    ? config.region.trim()
    : null;
  if (!region) return null;
  const hasCustomEndpoint = (typeof config.endpoint === 'string' && config.endpoint.trim().length > 0);
  if (hasCustomEndpoint) {
    return { region: region, country: null, domicile: null, provider: null };
  }
  const hit = regionToCountry(region);
  if (hit) {
    return { region: region, country: hit.country, domicile: hit.domicile, provider: 'aws' };
  }
  // AWS region token we do not have mapped (e.g. 'global' / 'auto' / a new one).
  return { region: region, country: null, domicile: 'US', provider: 'aws' };
}

module.exports = {
  PROVIDERS: PROVIDERS,
  BLOCS: BLOCS,
  regionToCountry: regionToCountry,
  resolveJurisdiction: resolveJurisdiction,
  isPermitted: isPermitted,
  inferDestinationRegion: inferDestinationRegion,
  normalizeToken: normalizeToken,
};

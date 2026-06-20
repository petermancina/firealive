// FIREALIVE -- SDN controller adapter: VMware NSX-T (B5i SDN Mode)
//
// Reads the NSX-T Manager through the shared pinned HTTPS client
// (./https-client): mandatory certificate pinning to
// sdn_integrations.endpoint_fingerprint, optional mutual TLS, redirect refusal,
// timeout, and bounded responses. This adapter adds only NSX-T's read
// endpoints and exposes only the read-only contract -- every request is a GET,
// so it issues no mutating call, and the registry refuses any adapter that
// exposes a write-capable method.
//
// Authentication: HTTP Basic, which the NSX-T Policy API accepts on each
// request; the shared client applies it from the username/password credentials,
// so this adapter needs no separate login step.
//
// Reads (GET):
//   - segmentation: /policy/api/v1/infra/segments (logical segments),
//     /policy/api/v1/infra/domains/<domain>/groups (NSGroups),
//     /policy/api/v1/infra/domains/<domain>/security-policies (DFW policies),
//   - topology: /api/v1/transport-nodes (the transport-node fabric).
//
// credentials: { username, password, domain?, clientCertPem?, clientKeyPem?,
//                caPem? }   (domain defaults to "default")
//
// ASCII only; no template literals.

const client = require('./https-client');

// NSX-T list endpoints return { results: [...] }.
function results(parsed) {
  return (parsed && Array.isArray(parsed.results)) ? parsed.results : [];
}

function domainOf(config) {
  const creds = (config && config.credentials) || {};
  return String(creds.domain || 'default');
}

// --- read-only contract ---

// Reachability + authentication probe (GET the manager node info). Returns
// { status, detail } in reachable / unreachable / unauthenticated / error.
// Never throws.
function probe(config) {
  return client.probeReachability(config, '/api/v1/node');
}

// Read the transport-node fabric (topology). Read-only.
async function readTopology(config) {
  const tn = await client.getJson(config, '/api/v1/transport-nodes');
  return { transportNodes: results(tn) };
}

// Read the segmentation model: logical segments, groups, and DFW security
// policies. Read-only.
async function readSegmentation(config) {
  const domain = domainOf(config);
  const base = '/policy/api/v1/infra';
  const out = await Promise.all([
    client.getJson(config, base + '/segments'),
    client.getJson(config, base + '/domains/' + domain + '/groups'),
    client.getJson(config, base + '/domains/' + domain + '/security-policies'),
  ]);
  return {
    segments: results(out[0]),
    groups: results(out[1]),
    securityPolicies: results(out[2]),
  };
}

module.exports = { probe, readTopology, readSegmentation };

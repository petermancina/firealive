// FIREALIVE -- SDN controller adapter: Calico (B5i SDN Mode)
//
// Reads Calico / Calico Enterprise through the shared pinned HTTPS client
// (./https-client): mandatory certificate pinning to
// sdn_integrations.endpoint_fingerprint, optional mutual TLS, redirect refusal,
// timeout, and bounded responses. Every request is a GET, so the adapter issues
// no mutating call and exposes only the read-only contract; the registry
// refuses any adapter that exposes a write-capable method.
//
// Calico is Kubernetes-native: its policy objects are CRDs under the
// projectcalico.org API group, served by the (aggregated) Calico API server.
// The adapter authenticates with a Kubernetes bearer token (a read-only
// ServiceAccount token) or client-certificate mTLS, both applied by the shared
// client; there is no separate login step. All reads are cluster-wide lists,
// requiring read-only cluster RBAC.
//
// Reads:
//   - segmentation: globalnetworkpolicies, networkpolicies (Calico),
//     globalnetworksets,
//   - topology: nodes (Calico node inventory) and ippools (the IP address
//     plan).
//
// The API group/version are configurable to absorb version differences.
//
// credentials: {
//   token,                          // k8s ServiceAccount bearer token; or
//   clientCertPem, clientKeyPem,    // client-certificate auth
//   caPem?,                         // cluster CA
//   apiGroup?, apiVersion?, probePath?,
// }
//
// ASCII only; no template literals.

const client = require('./https-client');

const DEFAULT_API_GROUP = 'projectcalico.org';
const DEFAULT_API_VERSION = 'v3';

// Kubernetes list responses are { kind: "...List", items: [...] }.
function items(parsed) {
  return (parsed && Array.isArray(parsed.items)) ? parsed.items : [];
}

// Build a cluster-wide CRD list path for a plural resource. Calico's global
// resources are cluster-scoped and a cluster-wide list of the namespaced ones
// spans all namespaces, so no namespace prefix is used.
function resourcePath(config, plural) {
  const creds = (config && config.credentials) || {};
  const group = creds.apiGroup || DEFAULT_API_GROUP;
  const version = creds.apiVersion || DEFAULT_API_VERSION;
  return '/apis/' + group + '/' + version + '/' + plural;
}

// --- read-only contract ---

// Reachability + authentication probe (list global network policies, which also
// confirms read RBAC). Returns { status, detail } in reachable / unreachable /
// unauthenticated / error. Never throws.
function probe(config) {
  const creds = (config && config.credentials) || {};
  const probePath = creds.probePath || resourcePath(config, 'globalnetworkpolicies');
  return client.probeReachability(config, probePath);
}

// Read the Calico node inventory and the IP address pools (topology). Read-only.
async function readTopology(config) {
  const out = await Promise.all([
    client.getJson(config, resourcePath(config, 'nodes')),
    client.getJson(config, resourcePath(config, 'ippools')),
  ]);
  return { nodes: items(out[0]), ipPools: items(out[1]) };
}

// Read the segmentation model: global network policies, namespaced network
// policies, and global network sets. Read-only.
async function readSegmentation(config) {
  const out = await Promise.all([
    client.getJson(config, resourcePath(config, 'globalnetworkpolicies')),
    client.getJson(config, resourcePath(config, 'networkpolicies')),
    client.getJson(config, resourcePath(config, 'globalnetworksets')),
  ]);
  return {
    globalNetworkPolicies: items(out[0]),
    networkPolicies: items(out[1]),
    globalNetworkSets: items(out[2]),
  };
}

module.exports = { probe, readTopology, readSegmentation };

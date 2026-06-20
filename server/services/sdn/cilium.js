// FIREALIVE -- SDN controller adapter: Cilium (B5i SDN Mode)
//
// Reads Cilium / Cilium Enterprise through the shared pinned HTTPS client
// (./https-client): mandatory certificate pinning to
// sdn_integrations.endpoint_fingerprint, optional mutual TLS, redirect refusal,
// timeout, and bounded responses. Every request is a GET, so the adapter issues
// no mutating call and exposes only the read-only contract; the registry
// refuses any adapter that exposes a write-capable method.
//
// Cilium is Kubernetes-native (eBPF): its policy and inventory objects are CRDs
// under the cilium.io API group, served by the kube-apiserver. The adapter
// authenticates with a Kubernetes bearer token (a read-only ServiceAccount
// token) or client-certificate mTLS, both applied by the shared client; there
// is no separate login step. All reads are cluster-wide lists, requiring
// read-only cluster RBAC.
//
// Reads:
//   - segmentation: ciliumnetworkpolicies, ciliumclusterwidenetworkpolicies,
//   - topology: ciliumnodes, ciliumendpoints.
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

const DEFAULT_API_GROUP = 'cilium.io';
const DEFAULT_API_VERSION = 'v2';

// Kubernetes list responses are { kind: "...List", items: [...] }.
function items(parsed) {
  return (parsed && Array.isArray(parsed.items)) ? parsed.items : [];
}

// Build a cluster-wide CRD list path for a plural resource. A cluster-wide list
// of the namespaced resources spans all namespaces, so no namespace prefix is
// used.
function resourcePath(config, plural) {
  const creds = (config && config.credentials) || {};
  const group = creds.apiGroup || DEFAULT_API_GROUP;
  const version = creds.apiVersion || DEFAULT_API_VERSION;
  return '/apis/' + group + '/' + version + '/' + plural;
}

// --- read-only contract ---

// Reachability + authentication probe (list Cilium network policies, which also
// confirms read RBAC). Returns { status, detail } in reachable / unreachable /
// unauthenticated / error. Never throws.
function probe(config) {
  const creds = (config && config.credentials) || {};
  const probePath = creds.probePath || resourcePath(config, 'ciliumnetworkpolicies');
  return client.probeReachability(config, probePath);
}

// Read the Cilium node and endpoint inventory (topology). Read-only.
async function readTopology(config) {
  const out = await Promise.all([
    client.getJson(config, resourcePath(config, 'ciliumnodes')),
    client.getJson(config, resourcePath(config, 'ciliumendpoints')),
  ]);
  return { ciliumNodes: items(out[0]), ciliumEndpoints: items(out[1]) };
}

// Read the segmentation model: namespaced and cluster-wide Cilium network
// policies. Read-only.
async function readSegmentation(config) {
  const out = await Promise.all([
    client.getJson(config, resourcePath(config, 'ciliumnetworkpolicies')),
    client.getJson(config, resourcePath(config, 'ciliumclusterwidenetworkpolicies')),
  ]);
  return {
    ciliumNetworkPolicies: items(out[0]),
    ciliumClusterwideNetworkPolicies: items(out[1]),
  };
}

module.exports = { probe, readTopology, readSegmentation };

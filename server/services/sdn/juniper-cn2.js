// FIREALIVE -- SDN controller adapter: Juniper CN2 / Contrail (B5i SDN Mode)
//
// Reads Juniper Cloud-Native Contrail (CN2) through the shared pinned HTTPS
// client (./https-client): mandatory certificate pinning to
// sdn_integrations.endpoint_fingerprint, optional mutual TLS, redirect refusal,
// timeout, and bounded responses. Every request is a GET, so the adapter issues
// no mutating call and exposes only the read-only contract; the registry
// refuses any adapter that exposes a write-capable method.
//
// CN2 is Kubernetes-native: its Contrail objects are CRDs under the
// core.contrail.juniper.net API group, served by the kube-apiserver. The
// adapter authenticates with a Kubernetes bearer token (a read-only
// ServiceAccount token) or client-certificate mTLS, both applied by the shared
// client; there is no separate login step.
//
// Reads (cluster-wide list endpoints, requiring read-only cluster RBAC):
//   - segmentation: virtualnetworks, networkpolicies, firewallpolicies,
//   - topology: virtualrouters (the vRouter data-plane inventory).
//
// The API group/version and an optional namespace are configurable to absorb
// CN2 version differences.
//
// credentials: {
//   token,                          // k8s ServiceAccount bearer token; or
//   clientCertPem, clientKeyPem,    // client-certificate auth
//   caPem?,                         // cluster CA
//   apiGroup?, apiVersion?, namespace?, probePath?,
// }
//
// ASCII only; no template literals.

const client = require('./https-client');

const DEFAULT_API_GROUP = 'core.contrail.juniper.net';
const DEFAULT_API_VERSION = 'v1';

// Kubernetes list responses are { kind: "...List", items: [...] }.
function items(parsed) {
  return (parsed && Array.isArray(parsed.items)) ? parsed.items : [];
}

// Build a CRD list path for a plural resource, cluster-wide by default or
// namespaced when a namespace is configured.
function resourcePath(config, plural) {
  const creds = (config && config.credentials) || {};
  const group = creds.apiGroup || DEFAULT_API_GROUP;
  const version = creds.apiVersion || DEFAULT_API_VERSION;
  const base = '/apis/' + group + '/' + version;
  if (creds.namespace) {
    return base + '/namespaces/' + String(creds.namespace) + '/' + plural;
  }
  return base + '/' + plural;
}

// --- read-only contract ---

// Reachability + authentication probe (list virtualnetworks by default, which
// also confirms read RBAC). Returns { status, detail } in reachable /
// unreachable / unauthenticated / error. Never throws.
function probe(config) {
  const creds = (config && config.credentials) || {};
  const probePath = creds.probePath || resourcePath(config, 'virtualnetworks');
  return client.probeReachability(config, probePath);
}

// Read the vRouter data-plane inventory (topology). Read-only.
async function readTopology(config) {
  const vrouters = await client.getJson(config, resourcePath(config, 'virtualrouters'));
  return { virtualRouters: items(vrouters) };
}

// Read the segmentation model: virtual networks, network policies, and firewall
// policies. Read-only.
async function readSegmentation(config) {
  const out = await Promise.all([
    client.getJson(config, resourcePath(config, 'virtualnetworks')),
    client.getJson(config, resourcePath(config, 'networkpolicies')),
    client.getJson(config, resourcePath(config, 'firewallpolicies')),
  ]);
  return {
    virtualNetworks: items(out[0]),
    networkPolicies: items(out[1]),
    firewallPolicies: items(out[2]),
  };
}

module.exports = { probe, readTopology, readSegmentation };

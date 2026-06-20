// FIREALIVE -- SDN controller adapter: OpenFlow / OVS (B5i SDN Mode)
//
// Reads an OpenFlow controller's northbound REST API through the shared pinned
// HTTPS client (./https-client): mandatory certificate pinning to
// sdn_integrations.endpoint_fingerprint, optional mutual TLS, redirect refusal,
// timeout, and bounded responses. Every request is a GET, so the adapter issues
// no mutating call and exposes only the read-only contract; the registry
// refuses any adapter that exposes a write-capable method.
//
// OpenFlow controllers diverge widely (OpenDaylight, ONOS, Ryu, Floodlight), so
// the read paths default to the OpenDaylight RESTCONF shape and are overridable
// per integration. In the OpenFlow model the flow tables are the segmentation
// enforcement, so:
//   - topology     -> network-topology (nodes and links),
//   - segmentation -> the inventory / installed flow tables.
//
// Authentication: HTTP Basic (or a bearer token), applied by the shared client
// from the credentials; no separate login step.
//
// credentials: {
//   username, password,            // or: token
//   topologyPath?, flowsPath?, probePath?,
//   clientCertPem?, clientKeyPem?, caPem?,
// }
//
// ASCII only; no template literals.

const client = require('./https-client');

const DEFAULT_TOPOLOGY_PATH = '/restconf/operational/network-topology:network-topology';
const DEFAULT_FLOWS_PATH = '/restconf/operational/opendaylight-inventory:nodes';

// Surface the OpenDaylight-nested topology object when present, else return the
// controller's body as-is (ONOS/Ryu/Floodlight shapes differ).
function extractTopology(parsed) {
  if (parsed && parsed['network-topology']) return parsed['network-topology'];
  return parsed;
}

// Surface the inventory/flow node list when present, else return the body as-is.
function extractInventory(parsed) {
  if (parsed && parsed['opendaylight-inventory:nodes']) return parsed['opendaylight-inventory:nodes'];
  if (parsed && parsed.nodes) return parsed.nodes;
  return parsed;
}

// --- read-only contract ---

// Reachability + authentication probe. Defaults to reading the topology path (a
// successful read confirms reachable + authenticated); overridable. Returns
// { status, detail } in reachable / unreachable / unauthenticated / error.
// Never throws.
function probe(config) {
  const creds = (config && config.credentials) || {};
  const probePath = creds.probePath || creds.topologyPath || DEFAULT_TOPOLOGY_PATH;
  return client.probeReachability(config, probePath);
}

// Read the network topology (nodes and links). Read-only.
async function readTopology(config) {
  const creds = (config && config.credentials) || {};
  const parsed = await client.getJson(config, creds.topologyPath || DEFAULT_TOPOLOGY_PATH);
  return { topology: extractTopology(parsed) };
}

// Read the installed flow tables (the OpenFlow segmentation enforcement).
// Read-only.
async function readSegmentation(config) {
  const creds = (config && config.credentials) || {};
  const parsed = await client.getJson(config, creds.flowsPath || DEFAULT_FLOWS_PATH);
  return { flows: extractInventory(parsed) };
}

module.exports = { probe, readTopology, readSegmentation };

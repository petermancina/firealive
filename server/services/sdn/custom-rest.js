// FIREALIVE -- SDN controller adapter: Custom REST (B5i SDN Mode)
//
// The generic reference adapter and the template the seven vendor adapters
// follow. It reads an operator-described REST controller through the shared
// pinned HTTPS client (./https-client), which enforces mandatory certificate
// pinning to sdn_integrations.endpoint_fingerprint, optional mutual TLS,
// redirect refusal, a timeout, and a bounded response. This adapter adds only
// the generic REST shape (configurable probe / topology / segmentation paths)
// and exposes only the read-only contract; it never issues a mutating request,
// and the registry refuses any adapter that exposes a write-capable method.
//
// The route/scheduler layer decrypts sdn_integrations.api_credentials_encrypted
// (Tier-1) and passes a plain config; this adapter never touches Tier-1
// encryption directly.
//
// config = {
//   apiEndpoint:         'https://controller.example:443',
//   endpointFingerprint: 'sha-256 hex (colons optional)',   // REQUIRED (pinned)
//   credentials: {
//     // authentication (optional, first match wins):
//     token,                          // -> Authorization: Bearer <token>
//     apiKey, apiKeyHeader,           // -> <apiKeyHeader|X-API-Key>: <apiKey>
//     username, password,             // -> Authorization: Basic base64(u:p)
//     // mutual TLS (optional):
//     clientCertPem, clientKeyPem,
//     // server trust for a private controller (optional):
//     caPem,
//     // REST shape for this custom controller (optional; sane defaults):
//     probePath, topologyPath, segmentationPath,
//   },
// }
//
// ASCII only; no template literals.

const client = require('./https-client');

const DEFAULT_PROBE_PATH = '/';
const DEFAULT_TOPOLOGY_PATH = '/topology';
const DEFAULT_SEGMENTATION_PATH = '/segmentation';

// Reachability + authentication probe. Returns { status, detail } where status
// is one of reachable / unreachable / unauthenticated / error. Never throws.
function probe(config) {
  const creds = (config && config.credentials) || {};
  return client.probeReachability(config, creds.probePath || DEFAULT_PROBE_PATH);
}

// Read the controller's topology view (read-only). Returns parsed JSON.
function readTopology(config) {
  const creds = (config && config.credentials) || {};
  return client.getJson(config, creds.topologyPath || DEFAULT_TOPOLOGY_PATH);
}

// Read the controller's segmentation/policy view (read-only). Returns parsed
// JSON.
function readSegmentation(config) {
  const creds = (config && config.credentials) || {};
  return client.getJson(config, creds.segmentationPath || DEFAULT_SEGMENTATION_PATH);
}

module.exports = { probe, readTopology, readSegmentation };

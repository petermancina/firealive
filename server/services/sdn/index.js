// FIREALIVE -- SDN controller adapter registry (B5i SDN Mode)
//
// The single entry point to the per-platform SDN controller adapters. Each
// adapter (one file per platform in this directory) authenticates over mTLS to
// a pinned controller endpoint and performs READ-ONLY observation only:
//   - probe(config)            -> reachability + authentication status
//   - readTopology(config)     -> the controller's topology view
//   - readSegmentation(config) -> the controller's segmentation / policy view
//
// Read-only is the non-weakening linchpin (D-B5i-3): FireAlive never holds a
// credential or a code path that can alter a flow or push a policy, so a
// compromised FireAlive cannot become a policy-injection pivot into the fabric.
// This registry ENFORCES that at the boundary -- getAdapter() validates that an
// adapter exposes the three read methods and exposes NO method whose name
// matches a mutating verb (write / push / create / update / delete / set /
// apply / ...). An adapter that exposes a write-capable method is refused at
// resolution, so the read-only guarantee is structural, not a matter of review.
//
// Adapters are resolved lazily by platform key and cached, so this registry
// loads before any individual adapter is present and a controller call only
// touches the network when the probe scheduler or a route asks for it.
//
// Platform keys are the sdn_integrations.platform CHECK values; two map to a
// longer adapter filename (arista-cv -> arista-cloudvision, custom ->
// custom-rest).
//
// ASCII only; no template literals.

// The read-only contract every adapter must satisfy.
const READ_METHODS = ['probe', 'readTopology', 'readSegmentation'];

// A function whose exported name begins with any of these verbs could mutate
// the controller and is forbidden on the adapter surface.
const WRITE_METHOD_RE = /^(write|push|create|update|delete|remove|set|apply|modify|post|put|patch|configure|enforce|deploy|provision|add|insert)/i;

// platform key (sdn_integrations.platform CHECK value) -> adapter module path in
// this directory.
const PLATFORMS = {
  'cisco-aci': './cisco-aci',
  'vmware-nsx': './vmware-nsx',
  'openflow': './openflow',
  'arista-cv': './arista-cloudvision',
  'juniper-cn2': './juniper-cn2',
  'calico': './calico',
  'cilium': './cilium',
  'custom': './custom-rest',
};

const adapterCache = {};

function listPlatforms() {
  return Object.keys(PLATFORMS);
}

function isSupported(platform) {
  return Object.prototype.hasOwnProperty.call(PLATFORMS, String(platform));
}

// Validate that a resolved adapter honors the read-only contract: it must
// implement every read method and must NOT expose any write-capable method.
function assertReadOnly(platform, adapter) {
  if (!adapter || typeof adapter !== 'object') {
    throw new Error('SDN adapter for "' + platform + '" did not export an object');
  }
  for (let i = 0; i < READ_METHODS.length; i++) {
    if (typeof adapter[READ_METHODS[i]] !== 'function') {
      throw new Error('SDN adapter for "' + platform + '" is missing the read-only method ' + READ_METHODS[i]);
    }
  }
  const keys = Object.keys(adapter);
  for (let j = 0; j < keys.length; j++) {
    if (typeof adapter[keys[j]] === 'function' && WRITE_METHOD_RE.test(keys[j])) {
      throw new Error('SDN adapter for "' + platform + '" exposes a forbidden write-capable method: ' + keys[j]);
    }
  }
  return adapter;
}

// Resolve (lazily, cached) and validate the adapter for a platform key. Throws
// on an unknown platform, a missing adapter module, or a contract violation.
function getAdapter(platform) {
  const key = String(platform);
  if (!isSupported(key)) {
    throw new Error('Unknown SDN platform: "' + key + '"');
  }
  if (adapterCache[key]) return adapterCache[key];
  const mod = require(PLATFORMS[key]);
  const adapter = assertReadOnly(key, mod);
  adapterCache[key] = adapter;
  return adapter;
}

module.exports = {
  READ_METHODS,
  WRITE_METHOD_RE,
  PLATFORMS,
  listPlatforms,
  isSupported,
  assertReadOnly,
  getAdapter,
  _adapterCache: adapterCache,
};

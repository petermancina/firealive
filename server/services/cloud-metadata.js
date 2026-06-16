// FIREALIVE -- Cloud instance metadata reader (B5h Cloud Mode, C7)
//
// Best-effort reader for the cloud provider instance metadata service
// (IMDS). Cloud Mode uses it to (a) identify the provider, (b) source the
// instance IP and hostnames for cert-SAN reconciliation, and (c) detect
// spot/preemptible or autoscaled/scale-set instances, which Cloud Mode
// refuses for the regional server: a copied image plus a shared hardware
// root only stays clone-resistant on a single stable instance.
//
// Design:
//   - readCloudMetadata() is async and cached per process. It probes GCP,
//     then Azure, then AWS, and returns the first that responds; if none
//     responds it returns a neutral object with provider null and null
//     fields. It never throws and never blocks longer than the per-probe
//     timeout.
//   - The normalization parsers (buildAwsMetadata, parseAzureInstance,
//     parseGcpInstance) are pure and unit-tested with captured fixtures.
//     The network fetch is platform-validation-pending (exercised on a
//     real cloud instance at release).
//   - confidentialHint is only a best-effort signal from metadata; the
//     authoritative confidential-computing check is cloud-attestation (C8).
//
// No external dependencies (Node http only). ASCII only; no template
// literals.

const http = require('http');

const METADATA_TIMEOUT_MS = 1000;
const IMDS_LINK_LOCAL_HOST = '169.254.169.254';
const GCP_METADATA_HOST = 'metadata.google.internal';
const PROVIDERS = ['aws', 'azure', 'gcp'];

let cached;

function emptyMetadata() {
  return {
    provider: null,
    instanceId: null,
    privateIp: null,
    publicIp: null,
    hostnames: [],
    spot: null,
    autoscaled: null,
    tenancy: null,
    confidentialHint: null,
  };
}

function dedupeHostnames(values) {
  const out = [];
  for (let i = 0; i < values.length; i += 1) {
    const h = values[i];
    if (h && typeof h === 'string' && out.indexOf(h) === -1) out.push(h);
  }
  return out;
}

// Best-effort HTTP request. Resolves the response body on a 2xx, or null on
// any non-2xx, network error, or timeout. Never rejects.
function httpReq(method, host, requestPath, headers, timeoutMs) {
  return new Promise(function (resolve) {
    let settled = false;
    function finish(value) {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    }
    let req;
    try {
      req = http.request(
        {
          method: method,
          host: host,
          path: requestPath,
          headers: headers || {},
          timeout: timeoutMs,
        },
        function (res) {
          const chunks = [];
          res.on('data', function (chunk) { chunks.push(chunk); });
          res.on('end', function () {
            const status = res.statusCode || 0;
            if (status >= 200 && status < 300) {
              finish(Buffer.concat(chunks).toString('utf8'));
            } else {
              finish(null);
            }
          });
        }
      );
    } catch (e) {
      finish(null);
      return;
    }
    req.on('error', function () { finish(null); });
    req.on('timeout', function () {
      try { req.destroy(); } catch (e) { /* ignore */ }
      finish(null);
    });
    try { req.end(); } catch (e) { finish(null); }
  });
}

function getText(host, requestPath, headers) {
  return httpReq('GET', host, requestPath, headers, METADATA_TIMEOUT_MS).then(function (body) {
    return body == null ? null : body.trim();
  });
}

// ---- AWS (IMDSv2) ----

function awsToken() {
  return httpReq(
    'PUT',
    IMDS_LINK_LOCAL_HOST,
    '/latest/api/token',
    { 'X-aws-ec2-metadata-token-ttl-seconds': '60' },
    METADATA_TIMEOUT_MS
  ).then(function (body) {
    return body == null ? null : body.trim();
  });
}

function buildAwsMetadata(fields) {
  return {
    provider: 'aws',
    instanceId: fields.instanceId || null,
    privateIp: fields.localIpv4 || null,
    publicIp: fields.publicIpv4 || null,
    hostnames: dedupeHostnames([fields.hostname, fields.publicHostname]),
    spot: fields.lifeCycle == null ? null : (fields.lifeCycle === 'spot'),
    autoscaled: fields.asgState == null ? null : true,
    tenancy: fields.tenancy || null,
    confidentialHint: null,
  };
}

function fetchAws() {
  return awsToken().then(function (token) {
    if (!token) return null;
    const headers = { 'X-aws-ec2-metadata-token': token };
    const base = '/latest/meta-data/';
    return Promise.all([
      getText(IMDS_LINK_LOCAL_HOST, base + 'instance-id', headers),
      getText(IMDS_LINK_LOCAL_HOST, base + 'local-ipv4', headers),
      getText(IMDS_LINK_LOCAL_HOST, base + 'public-ipv4', headers),
      getText(IMDS_LINK_LOCAL_HOST, base + 'hostname', headers),
      getText(IMDS_LINK_LOCAL_HOST, base + 'public-hostname', headers),
      getText(IMDS_LINK_LOCAL_HOST, base + 'instance-life-cycle', headers),
      getText(IMDS_LINK_LOCAL_HOST, base + 'autoscaling/target-lifecycle-state', headers),
    ]).then(function (values) {
      return buildAwsMetadata({
        instanceId: values[0],
        localIpv4: values[1],
        publicIpv4: values[2],
        hostname: values[3],
        publicHostname: values[4],
        lifeCycle: values[5],
        asgState: values[6],
      });
    });
  });
}

// ---- Azure (IMDS) ----

function parseAzureInstance(obj) {
  const compute = (obj && obj.compute) || {};
  const network = (obj && obj.network) || {};
  let privateIp = null;
  let publicIp = null;
  try {
    const ip0 = network.interface[0].ipv4.ipAddress[0];
    privateIp = ip0.privateIpAddress || null;
    publicIp = ip0.publicIpAddress || null;
  } catch (e) { /* fields absent */ }
  let securityType = null;
  try { securityType = compute.securityProfile.securityType || null; } catch (e) { /* absent */ }
  let autoscaled = null;
  if (typeof compute.vmScaleSetName === 'string') {
    autoscaled = compute.vmScaleSetName.length > 0;
  }
  return {
    provider: 'azure',
    instanceId: compute.vmId || null,
    privateIp: privateIp,
    publicIp: publicIp,
    hostnames: dedupeHostnames([compute.name]),
    spot: compute.priority == null ? null : (compute.priority === 'Spot'),
    autoscaled: autoscaled,
    tenancy: null,
    confidentialHint: securityType == null ? null : (securityType === 'ConfidentialVM'),
  };
}

function fetchAzure() {
  return httpReq(
    'GET',
    IMDS_LINK_LOCAL_HOST,
    '/metadata/instance?api-version=2021-12-13',
    { Metadata: 'true' },
    METADATA_TIMEOUT_MS
  ).then(function (body) {
    if (body == null) return null;
    let obj;
    try { obj = JSON.parse(body); } catch (e) { return null; }
    if (!obj || !obj.compute) return null;
    return parseAzureInstance(obj);
  });
}

// ---- GCP (metadata) ----

function parseGcpInstance(obj) {
  const root = obj || {};
  const scheduling = root.scheduling || {};
  let privateIp = null;
  let publicIp = null;
  try {
    const ni0 = root.networkInterfaces[0];
    privateIp = ni0.ip || null;
    try { publicIp = ni0.accessConfigs[0].externalIp || null; } catch (e) { /* no public */ }
  } catch (e) { /* no interfaces */ }
  let createdBy = null;
  try { createdBy = (root.attributes && root.attributes['created-by']) || null; } catch (e) { /* absent */ }
  const provisioningModel = scheduling.provisioningModel || null;
  const preemptible = scheduling.preemptible;
  let spot = null;
  if (provisioningModel != null) {
    spot = provisioningModel === 'SPOT';
  } else if (typeof preemptible === 'boolean') {
    spot = preemptible;
  }
  let autoscaled = null;
  if (createdBy != null) {
    autoscaled = createdBy.indexOf('instanceGroupManagers/') !== -1;
  }
  return {
    provider: 'gcp',
    instanceId: root.id == null ? null : String(root.id),
    privateIp: privateIp,
    publicIp: publicIp,
    hostnames: dedupeHostnames([root.hostname, root.name]),
    spot: spot,
    autoscaled: autoscaled,
    tenancy: null,
    confidentialHint: null,
  };
}

function fetchGcp() {
  return httpReq(
    'GET',
    GCP_METADATA_HOST,
    '/computeMetadata/v1/instance/?recursive=true',
    { 'Metadata-Flavor': 'Google' },
    METADATA_TIMEOUT_MS
  ).then(function (body) {
    if (body == null) return null;
    let obj;
    try { obj = JSON.parse(body); } catch (e) { return null; }
    if (!obj || obj.id == null) return null;
    return parseGcpInstance(obj);
  });
}

// ---- Orchestration ----

// Probe providers in sequence; the first non-null result wins. metadata.google
// .internal does not resolve off GCP, and the link-local Azure/AWS probes fail
// fast off those clouds, so a non-cloud host falls through to emptyMetadata.
function readCloudMetadata() {
  if (cached !== undefined) return Promise.resolve(cached);
  return fetchGcp()
    .then(function (m) { return m || fetchAzure(); })
    .then(function (m) { return m || fetchAws(); })
    .then(function (m) {
      cached = m || emptyMetadata();
      return cached;
    })
    .catch(function () {
      cached = emptyMetadata();
      return cached;
    });
}

function detectProvider() {
  return readCloudMetadata().then(function (m) { return m.provider; });
}

module.exports = {
  readCloudMetadata,
  detectProvider,
  buildAwsMetadata,
  parseAzureInstance,
  parseGcpInstance,
  emptyMetadata,
  PROVIDERS,
  _resetCache: function () { cached = undefined; },
};

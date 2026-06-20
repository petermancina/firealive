// FIREALIVE -- SDN controller adapter: Arista CloudVision (B5i SDN Mode)
//
// Reads Arista CloudVision Portal (CVP) through the shared pinned HTTPS client
// (./https-client): mandatory certificate pinning to
// sdn_integrations.endpoint_fingerprint, optional mutual TLS, redirect refusal,
// timeout, and bounded responses. Reads are GET; the only non-GET is the CVP
// session-login step, which reads a session id and does not alter the network.
// The adapter exposes only the read-only contract; the registry refuses any
// adapter that exposes a write-capable method.
//
// Two authentication modes:
//   - service-account token (recommended): credentials.token -> the shared
//     client sends it as a bearer; no login step,
//   - session login: credentials.username/password -> POST the CVP login
//     endpoint, read the sessionId, and send it on reads as the access_token
//     cookie.
//
// CVP API generations diverge (cvpservice / resource API / CVaaS), so the read
// paths default to the cvpservice shape and are overridable per integration.
// Topology reads the device inventory; segmentation reads the CloudVision tag
// model (how CVP expresses grouping/segmentation).
//
// credentials: {
//   token,                          // or: username, password
//   loginPath?, topologyPath?, segmentationPath?, probePath?,
//   clientCertPem?, clientKeyPem?, caPem?,
// }
//
// ASCII only; no template literals.

const client = require('./https-client');

const DEFAULT_LOGIN_PATH = '/cvpservice/login/authenticate.do';
const DEFAULT_TOPOLOGY_PATH = '/cvpservice/inventory/devices';
const DEFAULT_TAGS_PATH = '/cvpservice/tag/v2/tags';

// A transport-only view of the config for session mode: credentials ride the
// login body and the access_token cookie, never an Authorization header.
function transportConfig(config) {
  const creds = (config && config.credentials) || {};
  return {
    apiEndpoint: config && config.apiEndpoint,
    endpointFingerprint: config && config.endpointFingerprint,
    credentials: {
      clientCertPem: creds.clientCertPem,
      clientKeyPem: creds.clientKeyPem,
      caPem: creds.caPem,
    },
  };
}

// Best-effort extraction of a list from a CVP response across API generations.
function extractList(parsed) {
  if (Array.isArray(parsed)) return parsed;
  if (parsed && Array.isArray(parsed.data)) return parsed.data;
  if (parsed && Array.isArray(parsed.devices)) return parsed.devices;
  if (parsed && Array.isArray(parsed.tags)) return parsed.tags;
  if (parsed && Array.isArray(parsed.notifications)) return parsed.notifications;
  return parsed;
}

// POST the CVP login endpoint and return the session id. Throws on a failed
// login (with httpStatus on an HTTP error) or a missing session id.
async function getSession(config) {
  const creds = (config && config.credentials) || {};
  const loginPath = creds.loginPath || DEFAULT_LOGIN_PATH;
  const body = JSON.stringify({ userId: String(creds.username || ''), password: String(creds.password || '') });
  const r = await client.pinnedRequest(transportConfig(config), {
    path: loginPath,
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body,
  });
  if (!r.ok) {
    const e = new Error('CloudVision login returned ' + r.status);
    e.httpStatus = r.status;
    throw e;
  }
  let parsed;
  try {
    parsed = JSON.parse(r.text);
  } catch (e) {
    throw new Error('CloudVision login did not return valid JSON');
  }
  const sessionId = parsed && (parsed.sessionId || parsed.session_id);
  if (!sessionId) {
    throw new Error('CloudVision login response did not contain a sessionId');
  }
  return sessionId;
}

// Authenticated GET: bearer-token mode lets the shared client apply the token;
// session mode logs in and sends the access_token cookie. Read-only.
async function authedGet(config, path) {
  const creds = (config && config.credentials) || {};
  if (creds.token) {
    return client.getJson(config, path);
  }
  const sessionId = await getSession(config);
  return client.getJson(transportConfig(config), path, { headers: { Cookie: 'access_token=' + sessionId } });
}

// --- read-only contract ---

// Reachability + authentication probe. Returns { status, detail } in reachable /
// unreachable / unauthenticated / error. Never throws.
async function probe(config) {
  const creds = (config && config.credentials) || {};
  if (creds.token) {
    return client.probeReachability(config, creds.probePath || creds.topologyPath || DEFAULT_TOPOLOGY_PATH);
  }
  try {
    await getSession(config);
    return { status: 'reachable', detail: 'CloudVision reachable and authenticated' };
  } catch (err) {
    if (err && (err.httpStatus === 401 || err.httpStatus === 403)) {
      return { status: 'unauthenticated', detail: 'CloudVision authentication rejected (' + err.httpStatus + ')' };
    }
    if (err && typeof err.httpStatus === 'number') {
      return { status: 'error', detail: 'CloudVision returned ' + err.httpStatus };
    }
    return client.classifyTransportError(err);
  }
}

// Read the device inventory (topology). Read-only.
async function readTopology(config) {
  const creds = (config && config.credentials) || {};
  const data = await authedGet(config, creds.topologyPath || DEFAULT_TOPOLOGY_PATH);
  return { devices: extractList(data) };
}

// Read the CloudVision tag model (segmentation). Read-only.
async function readSegmentation(config) {
  const creds = (config && config.credentials) || {};
  const data = await authedGet(config, creds.segmentationPath || DEFAULT_TAGS_PATH);
  return { tags: extractList(data) };
}

module.exports = { probe, readTopology, readSegmentation };

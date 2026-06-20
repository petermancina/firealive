// FIREALIVE -- SDN controller adapter: Cisco ACI / APIC (B5i SDN Mode)
//
// Reads the Application Policy Infrastructure Controller (APIC) through the
// shared pinned HTTPS client (./https-client): mandatory certificate pinning to
// sdn_integrations.endpoint_fingerprint, optional mutual TLS, redirect refusal,
// timeout, and bounded responses. This adapter adds only APIC's authentication
// and read endpoints, and exposes only the read-only contract -- it issues no
// mutating call (the single POST is the aaaLogin authentication step, which
// reads a session token and does not alter the fabric), and the registry
// refuses any adapter that exposes a write-capable method.
//
// Authentication: POST /api/aaaLogin.json with the operator's username and
// password in the body; the response carries a session token, sent on reads as
// the APIC-cookie. Certificate-signature auth is not used; the credential is a
// read-scoped APIC user.
//
// Reads (GET /api/class/<class>.json):
//   - segmentation: fvTenant (tenants), fvAEPg (endpoint groups), vzBrCP
//     (contracts between EPGs),
//   - topology: fabricNode (the spine/leaf fabric inventory).
//
// credentials: { username, password, clientCertPem?, clientKeyPem?, caPem? }
//
// ASCII only; no template literals.

const client = require('./https-client');

// A transport-only view of the config: the APIC session is carried in the
// aaaLogin body and the APIC-cookie, never as an Authorization header, so the
// username/password are kept out of the per-request auth headers.
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

// Flatten an APIC imdata array into a list of the named class's attributes.
function flattenImdata(parsed, className) {
  const arr = (parsed && Array.isArray(parsed.imdata)) ? parsed.imdata : [];
  const out = [];
  for (let i = 0; i < arr.length; i++) {
    const obj = arr[i] && arr[i][className];
    if (obj && obj.attributes) out.push(obj.attributes);
  }
  return out;
}

// POST aaaLogin and return the session token. Throws on a failed login (with
// httpStatus on an HTTP error) or a missing token.
async function authenticate(config) {
  const creds = (config && config.credentials) || {};
  const body = JSON.stringify({
    aaaUser: { attributes: { name: String(creds.username || ''), pwd: String(creds.password || '') } },
  });
  const r = await client.pinnedRequest(transportConfig(config), {
    path: '/api/aaaLogin.json',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body,
  });
  if (!r.ok) {
    const e = new Error('APIC aaaLogin returned ' + r.status);
    e.httpStatus = r.status;
    throw e;
  }
  let parsed;
  try {
    parsed = JSON.parse(r.text);
  } catch (e) {
    throw new Error('APIC aaaLogin did not return valid JSON');
  }
  const login = parsed && Array.isArray(parsed.imdata) && parsed.imdata[0] && parsed.imdata[0].aaaLogin;
  const token = login && login.attributes && login.attributes.token;
  if (!token) {
    throw new Error('APIC aaaLogin response did not contain a session token');
  }
  return token;
}

// GET an APIC managed-object class with the session cookie. Read-only.
async function getClass(config, token, className) {
  const r = await client.pinnedRequest(transportConfig(config), {
    path: '/api/class/' + className + '.json',
    headers: { Cookie: 'APIC-cookie=' + token },
  });
  if (!r.ok) {
    const e = new Error('APIC /api/class/' + className + ' returned ' + r.status);
    e.httpStatus = r.status;
    throw e;
  }
  try {
    return JSON.parse(r.text);
  } catch (e) {
    throw new Error('APIC /api/class/' + className + ' did not return valid JSON');
  }
}

// --- read-only contract ---

// Reachability + authentication probe. Returns { status, detail } where status
// is reachable / unreachable / unauthenticated / error. Never throws.
async function probe(config) {
  try {
    await authenticate(config);
    return { status: 'reachable', detail: 'APIC reachable and authenticated' };
  } catch (err) {
    if (err && (err.httpStatus === 401 || err.httpStatus === 403)) {
      return { status: 'unauthenticated', detail: 'APIC authentication rejected (' + err.httpStatus + ')' };
    }
    if (err && typeof err.httpStatus === 'number') {
      return { status: 'error', detail: 'APIC returned ' + err.httpStatus };
    }
    return client.classifyTransportError(err);
  }
}

// Read the fabric topology (spine/leaf inventory). Read-only.
async function readTopology(config) {
  const token = await authenticate(config);
  const nodes = await getClass(config, token, 'fabricNode');
  return { fabricNodes: flattenImdata(nodes, 'fabricNode') };
}

// Read the segmentation model: tenants, endpoint groups, and the contracts
// between them. Read-only.
async function readSegmentation(config) {
  const token = await authenticate(config);
  const results = await Promise.all([
    getClass(config, token, 'fvTenant'),
    getClass(config, token, 'fvAEPg'),
    getClass(config, token, 'vzBrCP'),
  ]);
  return {
    tenants: flattenImdata(results[0], 'fvTenant'),
    endpointGroups: flattenImdata(results[1], 'fvAEPg'),
    contracts: flattenImdata(results[2], 'vzBrCP'),
  };
}

module.exports = { probe, readTopology, readSegmentation };

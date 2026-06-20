// FIREALIVE -- SDN controller adapter: Custom REST (B5i SDN Mode)
//
// The generic reference adapter and the template the seven vendor adapters
// follow. It speaks to an operator-described REST controller over HTTPS with:
//   - mandatory certificate pinning to the stored endpoint fingerprint
//     (sdn_integrations.endpoint_fingerprint). Identity is the pinned cert, not
//     the address, since SDN controller addresses shift across sites
//     (D-B5i-8); an unpinned or mismatched certificate is refused.
//   - optional mutual TLS (a client certificate/key in the credentials),
//   - optional CA material for a private/self-signed controller,
//   - header-based authentication (bearer token, API key, or basic),
//   - GET-only reads. The adapter never issues a mutating request and exposes
//     only the read-only contract (probe / readTopology / readSegmentation);
//     the registry refuses any adapter that exposes a write-capable method.
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

const { Agent } = require('undici');

const FETCH_TIMEOUT_MS = 15 * 1000;
const MAX_BODY_BYTES = 10 * 1024 * 1024; // bound controller responses (OOM guard)

const DEFAULT_PROBE_PATH = '/';
const DEFAULT_TOPOLOGY_PATH = '/topology';
const DEFAULT_SEGMENTATION_PATH = '/segmentation';

// Normalize a certificate SHA-256 fingerprint for comparison: drop colons and
// whitespace, lowercase.
function normalizeFp(fp) {
  return String(fp || '').replace(/[:\s]/g, '').toLowerCase();
}

// Build the server-identity check that PINS the controller certificate to the
// stored fingerprint. The default hostname check is intentionally not enforced
// (controller addresses shift across sites; identity is the pinned cert). An
// absent or mismatched fingerprint is refused.
function makePinnedIdentityCheck(expectedFingerprint) {
  const want = normalizeFp(expectedFingerprint);
  return function (_host, cert) {
    if (!want) {
      return new Error('SDN endpoint fingerprint is not configured; refusing to connect to an unpinned controller');
    }
    const got = normalizeFp(cert && cert.fingerprint256);
    if (!got || got !== want) {
      return new Error('SDN controller certificate fingerprint does not match the pinned value (possible interception)');
    }
    return undefined;
  };
}

// Build a pinned (and optionally mutually-authenticated) undici Agent. TLS
// verification is never disabled; pinning is layered on top.
function buildAgent(config) {
  const creds = (config && config.credentials) || {};
  const connect = {
    rejectUnauthorized: true,
    checkServerIdentity: makePinnedIdentityCheck(config && config.endpointFingerprint),
  };
  if (creds.clientCertPem && creds.clientKeyPem) {
    connect.cert = creds.clientCertPem;
    connect.key = creds.clientKeyPem;
  }
  if (creds.caPem) {
    connect.ca = creds.caPem;
  }
  return new Agent({ connect: connect });
}

// Build the authentication headers from the credentials (first match wins).
function authHeaders(creds) {
  const h = { Accept: 'application/json' };
  if (creds.token) {
    h.Authorization = 'Bearer ' + creds.token;
  } else if (creds.apiKey) {
    h[creds.apiKeyHeader || 'X-API-Key'] = creds.apiKey;
  } else if (creds.username || creds.password) {
    const raw = String(creds.username || '') + ':' + String(creds.password || '');
    h.Authorization = 'Basic ' + Buffer.from(raw, 'utf8').toString('base64');
  }
  return h;
}

// Validate the endpoint is an https URL and resolve a path against it. Pinning
// and mTLS require TLS, so a non-https endpoint is refused.
function requireHttpsUrl(apiEndpoint, pathName) {
  let u;
  try {
    const baseRaw = String(apiEndpoint || '');
    const base = baseRaw.endsWith('/') ? baseRaw : baseRaw + '/';
    const rel = String(pathName || '').replace(/^\//, '');
    u = new URL(rel, base);
  } catch (e) {
    throw new Error('SDN controller endpoint is not a valid URL');
  }
  if (u.protocol !== 'https:') {
    throw new Error('SDN controller endpoint must use https (TLS is required for pinning and mTLS)');
  }
  return u;
}

// GET a controller path with the pinned/mTLS agent, a timeout, no redirects, and
// a bounded response body. Returns { ok, status, text, pathname }. Read-only.
async function request(config, pathName) {
  const creds = (config && config.credentials) || {};
  const url = requireHttpsUrl(config && config.apiEndpoint, pathName);
  const agent = buildAgent(config);
  const ctrl = new AbortController();
  const timer = setTimeout(function () { ctrl.abort(); }, FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url.toString(), {
      method: 'GET',
      headers: authHeaders(creds),
      redirect: 'error',
      signal: ctrl.signal,
      dispatcher: agent,
    });
    const lenHeader = Number(res.headers.get('content-length') || 0);
    if (lenHeader && lenHeader > MAX_BODY_BYTES) {
      throw new Error('SDN controller response exceeds the size limit');
    }
    const text = await res.text();
    if (text.length > MAX_BODY_BYTES) {
      throw new Error('SDN controller response exceeds the size limit');
    }
    return { ok: res.ok, status: res.status, text: text, pathname: url.pathname };
  } finally {
    clearTimeout(timer);
    agent.close().catch(function () { /* best-effort socket release */ });
  }
}

// GET a path and parse the JSON body, throwing on a non-2xx status or invalid
// JSON. Read-only.
async function getJson(config, pathName) {
  const r = await request(config, pathName);
  if (!r.ok) {
    const e = new Error('SDN controller ' + r.pathname + ' returned ' + r.status);
    e.httpStatus = r.status;
    throw e;
  }
  try {
    return JSON.parse(r.text);
  } catch (e) {
    throw new Error('SDN controller ' + r.pathname + ' did not return valid JSON');
  }
}

// Map a transport/TLS failure to a probe status matching the
// sdn_integrations.last_probe_status CHECK values.
function classifyTransportError(err) {
  const m = String((err && err.message) || '');
  const cm = String((err && err.cause && err.cause.message) || '');
  const all = m + ' ' + cm;
  if (/fingerprint|interception|certificate|self.signed|unable to verify|altnames|TLS|SSL|DEPTH_ZERO|UNABLE_TO|ERR_TLS/i.test(all)) {
    return { status: 'error', detail: 'TLS/pinning failure: ' + (cm || m) };
  }
  if (/timed out|abort|ECONNREFUSED|ECONNRESET|ENOTFOUND|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|socket hang up|fetch failed/i.test(all)) {
    return { status: 'unreachable', detail: (cm || m) };
  }
  return { status: 'error', detail: (m || 'unknown error') };
}

// --- read-only contract ---

// Reachability + authentication probe. Returns { status, detail } where status
// is one of reachable / unreachable / unauthenticated / error. Never throws.
async function probe(config) {
  const creds = (config && config.credentials) || {};
  const probePath = creds.probePath || DEFAULT_PROBE_PATH;
  try {
    const r = await request(config, probePath);
    if (r.ok) return { status: 'reachable', detail: 'controller reachable and authenticated' };
    if (r.status === 401 || r.status === 403) {
      return { status: 'unauthenticated', detail: 'authentication rejected (' + r.status + ')' };
    }
    return { status: 'error', detail: 'controller returned ' + r.status };
  } catch (err) {
    return classifyTransportError(err);
  }
}

// Read the controller's topology view (read-only). Returns parsed JSON.
async function readTopology(config) {
  const creds = (config && config.credentials) || {};
  return getJson(config, creds.topologyPath || DEFAULT_TOPOLOGY_PATH);
}

// Read the controller's segmentation/policy view (read-only). Returns parsed
// JSON.
async function readSegmentation(config) {
  const creds = (config && config.credentials) || {};
  return getJson(config, creds.segmentationPath || DEFAULT_SEGMENTATION_PATH);
}

module.exports = { probe, readTopology, readSegmentation };

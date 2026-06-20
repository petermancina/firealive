// FIREALIVE -- SDN controller pinned HTTPS client (B5i SDN Mode)
//
// The single sanctioned path from any SDN adapter to a controller. Every
// adapter (custom-rest and the seven vendor adapters) reaches its controller
// ONLY through this module, so the transport-security invariants are written,
// tested, and hardened in one place instead of re-implemented eight times:
//
//   - Certificate pinning is MANDATORY. Each request pins the controller
//     certificate to the stored endpoint fingerprint
//     (sdn_integrations.endpoint_fingerprint) and refuses an unpinned or
//     mismatched certificate. Identity is the pinned cert, not the address,
//     since SDN controller addresses shift across sites (D-B5i-8), so the
//     default hostname check is intentionally not enforced.
//   - TLS verification is NEVER disabled. Pinning is layered on top of it.
//   - Mutual TLS (client cert/key) and private-CA trust are used when supplied.
//   - Redirects are refused, requests carry a timeout, and the response body is
//     bounded (OOM guard).
//
// There is no code path here that issues an unpinned request, so an adapter
// cannot accidentally bypass pinning -- the guarantee is structural. Adapters
// must not import undici/fetch directly; they call this client.
//
// GET is the default and is what the read methods use. A non-GET is supported
// only so an adapter can complete a controller's AUTHENTICATION step (e.g. a
// session-token login); adapters never use it to change controller state, and
// the registry refuses any adapter that exposes a write-capable method.
//
// ASCII only; no template literals.

const { Agent } = require('undici');

const DEFAULT_TIMEOUT_MS = 15 * 1000;
const MAX_BODY_BYTES = 10 * 1024 * 1024; // bound controller responses (OOM guard)

// Normalize a certificate SHA-256 fingerprint for comparison: drop colons and
// whitespace, lowercase.
function normalizeFp(fp) {
  return String(fp || '').replace(/[:\s]/g, '').toLowerCase();
}

// Build the server-identity check that PINS the controller certificate to the
// stored fingerprint. An absent or mismatched fingerprint is refused.
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

// Build authentication headers from the credentials (first match wins). Adapters
// may pass their own headers instead/in addition.
function authHeaders(creds) {
  creds = creds || {};
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

// The one sanctioned controller request: pinned, optional mTLS, timed out, no
// redirects, bounded body. opts: { path, method, headers, body, timeoutMs }.
// Returns { ok, status, text, pathname }. GET by default.
async function pinnedRequest(config, opts) {
  opts = opts || {};
  const creds = (config && config.credentials) || {};
  const method = (opts.method || 'GET').toUpperCase();
  const url = requireHttpsUrl(config && config.apiEndpoint, opts.path);
  const agent = buildAgent(config);
  const ctrl = new AbortController();
  const timer = setTimeout(function () { ctrl.abort(); }, opts.timeoutMs || DEFAULT_TIMEOUT_MS);
  try {
    const headers = Object.assign({}, authHeaders(creds), opts.headers || {});
    const init = {
      method: method,
      headers: headers,
      redirect: 'error',
      signal: ctrl.signal,
      dispatcher: agent,
    };
    if (opts.body !== undefined && method !== 'GET' && method !== 'HEAD') {
      init.body = opts.body;
    }
    const res = await fetch(url.toString(), init);
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
// JSON. The read methods use this.
async function getJson(config, pathName, opts) {
  const r = await pinnedRequest(config, Object.assign({}, opts || {}, { path: pathName, method: 'GET' }));
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

// Shared reachability + authentication probe: GET a path and map the outcome to
// { status, detail } where status is reachable / unreachable / unauthenticated /
// error. Never throws. Each adapter's probe() is a thin call to this.
async function probeReachability(config, pathName, opts) {
  try {
    const r = await pinnedRequest(config, Object.assign({}, opts || {}, { path: pathName, method: 'GET' }));
    if (r.ok) return { status: 'reachable', detail: 'controller reachable and authenticated' };
    if (r.status === 401 || r.status === 403) {
      return { status: 'unauthenticated', detail: 'authentication rejected (' + r.status + ')' };
    }
    return { status: 'error', detail: 'controller returned ' + r.status };
  } catch (err) {
    return classifyTransportError(err);
  }
}

module.exports = {
  buildAgent,
  authHeaders,
  requireHttpsUrl,
  pinnedRequest,
  getJson,
  probeReachability,
  classifyTransportError,
  normalizeFp,
  MAX_BODY_BYTES,
  DEFAULT_TIMEOUT_MS,
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Integration Health Probe Registry
//
// Concrete, read-only health probes consumed by the integration-health
// orchestrator (B3-C6). Each descriptor exposes:
//   { key, label, enabled(db), configured(db), probe(db, entry) }
// and probe() resolves to { ok, status?, detail? } per the harness contract.
//
// This commit (B3-C8) registers the first batch: KMS and cloud storage. Later
// commits append LDAP/AD + SIEM (C9) and SOAR + EDR (C10).
//
//   kms      — by default a lightweight, read-only check (enabled providers
//              configured + credentials present + last known live-probe status);
//              when the admin enables the KMS deep-probe flag it performs a live
//              wrap/unwrap round-trip per enabled provider (the existing
//              probeProvider path, which records last_probe_*).
//   storage  — live reachability probe per enabled backup destination, reusing
//              the destination adapters' own probe() via probeDestination.
// ═══════════════════════════════════════════════════════════════════════════════

const net = require('net');
const tls = require('tls');
const kms = require('./kms-providers');
const destinations = require('./backup-destinations');
const ihCfg = require('./integration-health-config');

function _list(fn) {
  try { const v = fn(); return Array.isArray(v) ? v : []; } catch { return []; }
}

function _isGoodProbeStatus(s) {
  return s === 'ok' || s === 'success' || s === 'passed';
}

// ── KMS ─────────────────────────────────────────────────────────────────────
async function kmsProbe(db) {
  const providers = _list(() => kms.listProviders(db, { enabled: true }));
  if (!providers.length) return { status: 'not_configured' };

  if (!ihCfg.getKmsDeep(db)) {
    // Lightweight, read-only: credentials present + last known live-probe status.
    const noCreds = providers.filter((p) => !p.has_credentials);
    if (noCreds.length) {
      return { ok: false, status: 'auth_failed', detail: `${noCreds.length} of ${providers.length} provider(s) missing credentials` };
    }
    const priorFail = providers
      .map((p) => p.last_probe_status)
      .find((s) => s && !_isGoodProbeStatus(s));
    let detail = `metadata check: ${providers.length} provider(s) configured with credentials; live round-trip skipped (enable the KMS deep-probe flag for that)`;
    if (priorFail) detail += `; note: a prior live probe reported '${priorFail}'`;
    return { ok: true, status: 'ok', detail };
  }

  // Deep: live wrap/unwrap round-trip per enabled provider.
  const ctx = { user_id: 'system:integration-health' };
  let okCount = 0;
  const errs = [];
  for (const p of providers) {
    try {
      const r = await kms.probeProvider(db, p.id, ctx);
      if (r && r.ok) okCount++;
      else errs.push(`${p.name || p.id}: ${(r && r.error) || 'failed'}`);
    } catch (e) {
      errs.push(`${p.name || p.id}: ${e.message}`);
    }
  }
  if (okCount === providers.length) return { ok: true, status: 'ok', detail: `deep round-trip ok on ${okCount} provider(s)` };
  if (okCount === 0) return { ok: false, status: 'unreachable', detail: errs.join('; ') };
  return { ok: false, status: 'error', detail: `${okCount}/${providers.length} ok; ${errs.join('; ')}` };
}

// ── Cloud storage ─────────────────────────────────────────────────────────────
async function storageProbe(db) {
  const dests = _list(() => destinations.listDestinations(db, { enabledOnly: true }));
  if (!dests.length) return { status: 'not_configured' };

  let okCount = 0;
  const errs = [];
  for (const d of dests) {
    try {
      const r = await destinations.probeDestination(db, d.id);
      if (r && r.ok) okCount++;
      else errs.push(`${d.name || d.id}: ${(r && r.error) || 'failed'}`);
    } catch (e) {
      errs.push(`${d.name || d.id}: ${e.message}`);
    }
  }
  if (okCount === dests.length) return { ok: true, status: 'ok', detail: `${okCount} destination(s) reachable` };
  if (okCount === 0) return { ok: false, status: 'unreachable', detail: errs.join('; ') };
  return { ok: false, status: 'error', detail: `${okCount}/${dests.length} reachable; ${errs.join('; ')}` };
}

// ── LDAP / Active Directory ─────────────────────────────────────────────────
// Reads the LDAP connection config from integration_config (the encrypted
// 'iam_ldap' entry the IAM admin saves, and the same source the offboarding
// detector uses), then runs a minimal connectivity bind via integrations/
// ldap.js (no directory search). Returns null when no config is present.
function _loadIamConfig(db) {
  try {
    const row = db.prepare("SELECT config_encrypted FROM integration_config WHERE integration_type = 'iam_ldap'").get();
    if (!row || !row.config_encrypted) return null;
    const { decryptConfig } = require('./encryption');
    return decryptConfig(row.config_encrypted) || null;
  } catch { return null; }
}

function _ldapConfigured(db) {
  const c = _loadIamConfig(db);
  return !!(c && c.server && c.bindDn);
}

async function ldapProbe(db) {
  const c = _loadIamConfig(db);
  if (!c || !c.server || !c.bindDn) return { status: 'not_configured' };
  let LdapClient;
  try { ({ LdapClient } = require('../integrations/ldap')); }
  catch { return { ok: false, status: 'error', detail: 'ldap client unavailable' }; }
  try {
    const client = new LdapClient(c);
    const r = await client.testConnection();
    if (r && r.success) {
      const warn = r.encrypted === false ? ' (WARNING: unencrypted ldap://, use ldaps://)' : '';
      return { ok: true, status: 'ok', detail: `bind ok${warn}` };
    }
    const err = (r && r.error) || 'bind failed';
    const status = /credential|bind/i.test(err) ? 'auth_failed' : 'unreachable';
    return { ok: false, status, detail: err };
  } catch (e) {
    return { ok: false, status: 'unreachable', detail: e.message };
  }
}

// ── SIEM (CEF/Syslog) ──────────────────────────────────────────────────────────
// Connect-only reachability check — opens (and immediately closes) a TCP/TLS
// socket to the configured endpoint. No event is sent (non-mutating). UDP is
// connectionless, so reachability cannot be verified by a handshake; that is
// reported honestly rather than as a failure.
function _loadSiemConfig(db) {
  try {
    const r = db.prepare("SELECT value FROM config WHERE key = 'siem_config'").get();
    return r && r.value ? JSON.parse(r.value) : null;
  } catch { return null; }
}

function _parseSiemEndpoint(endpoint, protocol) {
  let host = 'localhost';
  let port = 6514;
  let useTls = String(protocol || '').toLowerCase() === 'tls';
  try {
    const u = new URL(endpoint);
    host = u.hostname || host;
    port = parseInt(u.port, 10) || port;
    if (u.protocol === 'tls:' || u.protocol === 'ssl:' || u.protocol === 'tcps:') useTls = true;
  } catch {
    const parts = String(endpoint || '').split(':');
    host = parts[0] || host;
    port = parseInt(parts[1], 10) || port;
  }
  return { host, port, useTls };
}

function _connectOnly(host, port, useTls, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    let sock;
    const onConnect = () => { try { sock.end(); } catch (_) {} finish({ ok: true }); };
    if (useTls) sock = tls.connect({ host, port, rejectUnauthorized: true, timeout: timeoutMs }, onConnect);
    else sock = net.connect({ host, port, timeout: timeoutMs }, onConnect);
    sock.on('error', (e) => {
      try { sock.destroy(); } catch (_) {}
      // Connect-only reachability probe: it sends no events and trusts no
      // response, so certificate validation stays enabled (rejectUnauthorized
      // is true above). A certificate-trust failure still proves the endpoint
      // is reachable and speaking TLS, so report it as reachable with an
      // untrusted-certificate caveat rather than as unreachable; genuine
      // connectivity failures (refused, reset, DNS) remain unreachable.
      const blob = `${(e && e.code) || ''} ${(e && e.message) || ''}`.replace(/_/g, ' ').toLowerCase();
      const certUntrusted = /cert|self signed|unable to verify|unable to get|issuer|altname|err tls|leaf signature/.test(blob);
      if (certUntrusted) finish({ ok: true, detail: `${host}:${port} reachable (TLS certificate not trusted)` });
      else finish({ ok: false, error: e.message });
    });
    sock.on('timeout', () => { try { sock.destroy(); } catch (_) {} finish({ ok: false, error: 'connect timeout' }); });
  });
}

async function siemProbe(db) {
  const c = _loadSiemConfig(db);
  if (!c || !c.endpoint) return { status: 'not_configured' };
  const { host, port, useTls } = _parseSiemEndpoint(c.endpoint, c.protocol);
  if (String(c.protocol || '').toLowerCase() === 'udp') {
    return { ok: true, status: 'ok', detail: `UDP syslog ${host}:${port} configured (connectionless — handshake reachability not applicable)` };
  }
  const r = await _connectOnly(host, port, useTls);
  if (r.ok) return { ok: true, status: 'ok', detail: r.detail || `${useTls ? 'TLS' : 'TCP'} connect ok to ${host}:${port}` };
  return { ok: false, status: 'unreachable', detail: `${host}:${port}: ${r.error}` };
}

// ── SOAR ────────────────────────────────────────────────────────────────────
// Health/auth check against the single configured SOAR platform's endpoint
// (GET /health via the integration manager). FireAlive supports several SOAR
// platforms but one is configured at a time (soar_config).
function _soarConfigured(db) {
  try {
    const r = db.prepare("SELECT value FROM config WHERE key = 'soar_config'").get();
    if (!r || !r.value) return false;
    const c = JSON.parse(r.value);
    return !!(c && c.endpoint);
  } catch { return false; }
}

async function soarProbe(db) {
  let cfg = null;
  try {
    const r = db.prepare("SELECT value FROM config WHERE key = 'soar_config'").get();
    cfg = r && r.value ? JSON.parse(r.value) : null;
  } catch { cfg = null; }
  if (!cfg || !cfg.endpoint) return { status: 'not_configured' };

  let IM;
  try { ({ IntegrationManager: IM } = require('./integration-manager')); }
  catch { return { ok: false, status: 'error', detail: 'integration manager unavailable' }; }

  let r;
  try { r = await new IM(db).testConnection('soar', cfg.endpoint); }
  catch (e) { return { ok: false, status: 'unreachable', detail: e.message }; }

  if (!r || !r.connected) return { ok: false, status: 'unreachable', detail: (r && r.error) || 'no connection' };
  const code = r.status || 0;
  if (code === 401) return { ok: false, status: 'auth_failed', detail: 'HTTP 401' };
  if (code === 403) return { ok: false, status: 'permission_denied', detail: 'HTTP 403' };
  if (code >= 500) return { ok: false, status: 'unreachable', detail: `HTTP ${code}` };
  return { ok: true, status: 'ok', detail: `${cfg.platform || 'soar'} /health HTTP ${code}` };
}

// ── EDR / Malware scanner ──────────────────────────────────────────────────────
// Live auth/connectivity check per configured scanner via the integration
// manager's testScanner (the same path the config UI uses; records last_test_*).
// EDR is operationally required, but the *health probe* is reported honestly:
// not_configured when no scanner is set up. The regression runner enforces the
// requirement separately.
function _scannerRows(db) {
  try { return db.prepare('SELECT id, provider_type FROM malware_scanner_integrations').all(); }
  catch { return []; }
}

async function edrProbe(db) {
  const scanners = _scannerRows(db);
  if (!scanners.length) return { status: 'not_configured' };

  let IM;
  try { ({ IntegrationManager: IM } = require('./integration-manager')); }
  catch { return { ok: false, status: 'error', detail: 'integration manager unavailable' }; }
  const im = new IM(db);

  let okCount = 0;
  const errs = [];
  for (const s of scanners) {
    try {
      const r = await im.testScanner(s.id);
      if (r && r.ok) okCount++;
      else errs.push(`${s.provider_type || s.id}: ${(r && r.error) || 'failed'}`);
    } catch (e) {
      errs.push(`${s.provider_type || s.id}: ${e.message}`);
    }
  }
  if (okCount === scanners.length) return { ok: true, status: 'ok', detail: `${okCount} scanner(s) reachable` };
  if (okCount === 0) return { ok: false, status: 'unreachable', detail: errs.join('; ') };
  return { ok: false, status: 'error', detail: `${okCount}/${scanners.length} ok; ${errs.join('; ')}` };
}

const registry = [
  {
    key: 'kms',
    label: 'KMS / Key-Wrapping Providers',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'kms'),
    configured: (db) => _list(() => kms.listProviders(db, { enabled: true })).length > 0,
    probe: (db) => kmsProbe(db),
  },
  {
    key: 'storage',
    label: 'Cloud Backup Storage',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'storage'),
    configured: (db) => _list(() => destinations.listDestinations(db, { enabledOnly: true })).length > 0,
    probe: (db) => storageProbe(db),
  },
  {
    key: 'iam',
    label: 'LDAP / Active Directory',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'iam'),
    configured: (db) => _ldapConfigured(db),
    probe: (db) => ldapProbe(db),
  },
  {
    key: 'siem',
    label: 'SIEM (CEF/Syslog)',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'siem'),
    configured: (db) => { const c = _loadSiemConfig(db); return !!(c && c.endpoint); },
    probe: (db) => siemProbe(db),
  },
  {
    key: 'soar',
    label: 'SOAR Platform',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'soar'),
    configured: (db) => _soarConfigured(db),
    probe: (db) => soarProbe(db),
  },
  {
    key: 'edr',
    label: 'EDR / Malware Scanner',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'edr'),
    configured: (db) => _scannerRows(db).length > 0,
    probe: (db) => edrProbe(db),
  },
];

module.exports = { registry, kmsProbe, storageProbe, ldapProbe, siemProbe, soarProbe, edrProbe };

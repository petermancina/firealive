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
const destinations = require('./storage-destinations');
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
    const { openTier1 } = require('./tier1-seal');
    return openTier1('integration_config.config_encrypted', row.config_encrypted) || null;
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

function _loadTicketingConfig(db) {
  try {
    const row = db.prepare("SELECT value FROM config WHERE key = 'ticketing_config'").get();
    if (!row) return null;
    const c = JSON.parse(row.value);
    if (!c || !c.provider || c.provider === 'none' || !c.endpoint || !c.apiKey) return null;
    return c;
  } catch (_e) {
    return null;
  }
}

async function ticketingProbe(db) {
  const cfg = _loadTicketingConfig(db);
  if (!cfg) return { status: 'not_configured' };
  let TicketingAdapter;
  try { ({ TicketingAdapter } = require('../integrations/ticketing-adapter')); }
  catch (_e) { return { ok: false, status: 'error', detail: 'ticketing adapter module unavailable' }; }
  try {
    const adapter = new TicketingAdapter(cfg.provider, cfg.endpoint, cfg.apiKey);
    const r = await adapter.getQueueMetadata();
    const code = (r && typeof r.status === 'number') ? r.status : 0;
    if (code >= 200 && code < 300) {
      return { ok: true, status: 'ok', detail: cfg.provider + ' reachable (HTTP ' + code + ')' };
    }
    if (code === 401 || code === 403) {
      return { ok: false, status: 'auth_failed', detail: cfg.provider + ' rejected the credentials (HTTP ' + code + ')' };
    }
    if (code === 0) {
      return { ok: false, status: 'unreachable', detail: cfg.provider + ' unreachable' + (r && r.error ? ': ' + r.error : '') };
    }
    return { ok: false, status: 'unreachable', detail: cfg.provider + ' returned HTTP ' + code };
  } catch (e) {
    return { ok: false, status: 'unreachable', detail: 'ticketing probe failed: ' + (e && e.message ? e.message : 'error') };
  }
}

function _loadSchedulingConfig(db) {
  try {
    return db.prepare("SELECT platform, last_sync_status, last_sync_at, last_sync_error FROM scheduling_platform_config WHERE id = 1").get() || null;
  } catch (_e) {
    return null;
  }
}

function schedulingProbe(db) {
  const row = _loadSchedulingConfig(db);
  if (!row || !row.platform || row.platform === 'manual') return { status: 'not_configured' };
  const st = row.last_sync_status;
  if (st === 'success') {
    return { ok: true, status: 'ok', detail: 'last sync ' + (row.last_sync_at || 'unknown') };
  }
  if (st === 'failure') {
    return { ok: false, status: 'error', detail: row.last_sync_error ? ('last sync failed: ' + row.last_sync_error) : 'last sync failed' };
  }
  if (st === 'pending') {
    return { ok: true, status: 'ok', detail: 'sync in progress' };
  }
  return { ok: false, status: 'error', detail: 'no successful sync recorded' };
}

function _enabledSdnIntegrations(db) {
  try {
    return db.prepare("SELECT name, last_probe_status, consecutive_failures FROM sdn_integrations WHERE enabled = 1").all();
  } catch (_e) {
    return [];
  }
}

function sdnProbe(db) {
  const rows = _enabledSdnIntegrations(db);
  if (!rows.length) return { status: 'not_configured' };
  let state = 'unknown';
  try { state = require('./sdn-posture').currentPosture(db); } catch (_e) {}
  const total = rows.length;
  const reachable = rows.filter((r) => r.last_probe_status === 'reachable').length;
  const failing = rows.filter((r) => r.last_probe_status === 'unreachable' || r.last_probe_status === 'unauthenticated' || r.last_probe_status === 'error');
  if (failing.length) {
    return { ok: false, status: 'unreachable', detail: 'posture ' + state + '; ' + failing.length + ' of ' + total + ' adapter(s) failing' };
  }
  if (state === 'degraded') {
    return { ok: false, status: 'unreachable', detail: 'SDN posture degraded' };
  }
  return { ok: true, status: 'ok', detail: 'posture ' + state + '; ' + reachable + ' of ' + total + ' adapter(s) reachable' };
}

function _saseConnectorState(db) {
  try {
    const sm = require('./sase-mode');
    const cfg = sm.getSaseConfig(db);
    const posture = sm.getPosture(db);
    return {
      sources: Array.isArray(cfg.connectorSources) ? cfg.connectorSources : [],
      provider: cfg.provider || null,
      degraded: posture.degraded === true,
      lastEvent: posture.lastEvent || null,
    };
  } catch (_e) {
    return { sources: [], provider: null, degraded: false, lastEvent: null };
  }
}

// State-read only: reports the configured connector allow-list and the latched
// posture. FireAlive sits BEHIND the ZTNA connector and never dials out, so this
// probe makes no network call and never contacts the SASE provider.
function saseProbe(db) {
  let sase = false;
  try { sase = require('./deployment-mode').isSase(db); } catch (_e) {}
  const state = _saseConnectorState(db);
  if (!sase || !state.sources.length) return { status: 'not_configured' };
  if (state.degraded) {
    return { ok: false, status: 'unreachable', detail: 'SASE posture degraded' + (state.lastEvent ? (' (' + state.lastEvent + ')') : '') };
  }
  const prefix = state.provider ? (state.provider + '; ') : '';
  return { ok: true, status: 'ok', detail: prefix + 'connector allow-list active (' + state.sources.length + ' source(s)); posture healthy' };
}

function cloudProbe(db) {
  let att;
  try { att = require('./cloud-attestation'); }
  catch (_e) { return { ok: false, status: 'error', detail: 'cloud attestation module unavailable' }; }
  let r;
  try { r = att.verifyAttestation(); }
  catch (e) { return { ok: false, status: 'error', detail: 'attestation check failed: ' + (e && e.message ? e.message : 'error') }; }
  if (r && r.verified === true) {
    return { ok: true, status: 'ok', detail: r.reason || ('confidential VM verified (' + (r.tech || 'cc') + ')') };
  }
  return { ok: false, status: 'error', detail: (r && r.reason) ? r.reason : 'confidential VM not verified' };
}

const CICD_FRESHNESS_MS = 7 * 24 * 60 * 60 * 1000;

function _parseTs(s) {
  if (!s || typeof s !== 'string') return NaN;
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) return Date.parse(s.replace(' ', 'T') + 'Z');
  return Date.parse(s);
}

function _enabledBackupSchedules(db) {
  try {
    return db.prepare("SELECT name, last_status, last_run, next_run FROM backup_schedules WHERE active = 1").all();
  } catch (_e) {
    return [];
  }
}

function backupProbe(db) {
  const rows = _enabledBackupSchedules(db);
  if (!rows.length) return { status: 'not_configured' };
  const now = Date.now();
  const failed = [];
  const overdue = [];
  for (const r of rows) {
    const st = (r.last_status || '').toLowerCase();
    if (st === 'failed' || st === 'failure' || st === 'error') { failed.push(r.name || 'schedule'); continue; }
    const nextMs = _parseTs(r.next_run);
    if (!Number.isNaN(nextMs) && nextMs < now) { overdue.push(r.name || 'schedule'); }
  }
  if (failed.length) {
    return { ok: false, status: 'error', detail: failed.length + ' schedule(s) failed: ' + failed.join(', ') };
  }
  if (overdue.length) {
    return { ok: false, status: 'error', detail: overdue.length + ' schedule(s) overdue: ' + overdue.join(', ') };
  }
  return { ok: true, status: 'ok', detail: rows.length + ' schedule(s), last run OK' };
}

function _cicdConfigs(db) {
  try { return db.prepare("SELECT id, platform FROM cicd_configs").all(); }
  catch (_e) { return []; }
}

function cicdProbe(db) {
  const configs = _cicdConfigs(db);
  if (!configs.length) return { status: 'not_configured' };
  const now = Date.now();
  let okCount = 0;
  let noRun = 0;
  const failed = [];
  const stale = [];
  for (const c of configs) {
    let run;
    try { run = db.prepare("SELECT status, received_at FROM cicd_runs WHERE config_id = ? ORDER BY received_at DESC LIMIT 1").get(c.id); }
    catch (_e) { run = null; }
    if (!run) { noRun++; continue; }
    const st = (run.status || '').toLowerCase();
    if (st === 'failed') { failed.push(c.platform || c.id); continue; }
    const rcv = _parseTs(run.received_at);
    if (!Number.isNaN(rcv) && (now - rcv) > CICD_FRESHNESS_MS) { stale.push(c.platform || c.id); continue; }
    okCount++;
  }
  if (failed.length) {
    return { ok: false, status: 'error', detail: failed.length + ' pipeline(s) failed: ' + failed.join(', ') };
  }
  if (stale.length) {
    return { ok: false, status: 'error', detail: stale.length + ' pipeline(s) stale (no run within the freshness window)' };
  }
  if (noRun === configs.length) {
    return { ok: false, status: 'error', detail: 'no pipeline runs reported yet' };
  }
  return { ok: true, status: 'ok', detail: okCount + ' of ' + configs.length + ' pipeline(s) reporting healthy runs' };
}

function _notificationConfigRow(db) {
  try {
    return db.prepare(
      "SELECT email_enabled, email_address, webhook_enabled, webhook_url, pagerduty_enabled, pagerduty_key, sms_provider, sms_account_sid, sms_auth_token_encrypted, sms_from_number FROM notification_config WHERE id = 'default'"
    ).get() || {};
  } catch (_e) {
    return {};
  }
}

function _externalChannelsConfigured(db) {
  const r = _notificationConfigRow(db);
  const email = r.email_enabled === 1 && !!r.email_address;
  const webhook = r.webhook_enabled === 1 && !!r.webhook_url;
  const pagerduty = r.pagerduty_enabled === 1 && !!r.pagerduty_key;
  const sms = !!(r.sms_provider && r.sms_account_sid && r.sms_auth_token_encrypted && r.sms_from_number);
  return { email: email, webhook: webhook, pagerduty: pagerduty, sms: sms, any: email || webhook || pagerduty || sms };
}

async function notificationsProbe(db) {
  const cfg = _externalChannelsConfigured(db);
  if (!cfg.any) return { status: 'not_configured' };
  let nf;
  try { nf = require('./notifications'); }
  catch (_e) { return { ok: false, status: 'error', detail: 'notifications service unavailable' }; }
  const checks = [];
  if (cfg.email) checks.push(['email', nf.probeEmailChannel]);
  if (cfg.webhook) checks.push(['webhook', nf.probeWebhookChannel]);
  if (cfg.pagerduty) checks.push(['pagerduty', nf.probePagerDutyChannel]);
  if (cfg.sms) checks.push(['sms', nf.probeSmsChannel]);
  const results = [];
  for (const pair of checks) {
    const name = pair[0];
    const fn = pair[1];
    let res;
    try {
      res = (typeof fn === 'function') ? await fn(db) : { ok: false, status: 'error', detail: 'helper missing' };
    } catch (e) {
      res = { ok: false, status: 'error', detail: (e && e.message) || 'probe threw' };
    }
    results.push({ name: name, status: res && res.status, ok: !!(res && res.ok) });
  }
  const detail = results.map(function (r) { return r.name + ': ' + (r.status || 'unknown'); }).join('; ');
  const anyAuth = results.some(function (r) { return r.status === 'auth_failed'; });
  const okCount = results.filter(function (r) { return r.ok; }).length;
  const total = results.length;
  if (anyAuth) return { ok: false, status: 'auth_failed', detail: detail };
  if (okCount === total) return { ok: true, status: 'ok', detail: okCount + ' of ' + total + ' channel(s) reachable' };
  if (okCount === 0) return { ok: false, status: 'unreachable', detail: detail };
  return { ok: false, status: 'error', detail: detail };
}

// ── Threat-Hunting Integrations (B5m) ───────────────────────────────
// FireAlive is the monitored asset here, not a client: this probe NEVER dials
// out. It reports inward state only -- whether the surface is enabled in policy,
// whether any consumer is authorized, and live authorization / access counts.
function thConfigEnabled(db) {
  try {
    const row = db.prepare("SELECT value FROM config WHERE key = 'threat_hunting_config'").get();
    if (!row || !row.value) return false;
    const cfg = JSON.parse(row.value);
    if (!cfg || typeof cfg !== 'object') return false;
    return Object.keys(cfg).some((k) => cfg[k] && cfg[k].enabled === true);
  } catch (_e) {
    return false;
  }
}

function thConfigured(db) {
  try {
    return db.prepare('SELECT COUNT(*) AS c FROM threat_hunting_consumer_authorizations').get().c > 0;
  } catch (_e) {
    return false;
  }
}

function threatHuntingProbe(db) {
  try {
    const total = db.prepare('SELECT COUNT(*) AS c FROM threat_hunting_consumer_authorizations').get().c;
    const active = db.prepare('SELECT COUNT(*) AS c FROM threat_hunting_consumer_authorizations WHERE enabled = 1').get().c;
    const accesses = db.prepare('SELECT COUNT(*) AS c FROM threat_hunting_access_log').get().c;
    const lastRow = db.prepare('SELECT accessed_at FROM threat_hunting_access_log ORDER BY id DESC LIMIT 1').get();
    const lastAccess = lastRow ? lastRow.accessed_at : null;
    const status = active + ' active authorization(s)'
      + (total > active ? (', ' + (total - active) + ' disabled') : '');
    return {
      ok: true,
      status: status,
      detail: 'authorizations=' + total + ' active=' + active + ' accesses=' + accesses
        + (lastAccess ? (' last_access=' + lastAccess) : ''),
    };
  } catch (err) {
    return {
      ok: false,
      status: 'unavailable',
      detail: 'threat-hunting tables not reachable: ' + ((err && err.message) ? err.message : 'error'),
    };
  }
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
  {
    key: 'ticketing',
    label: 'Ticketing (Jira / ServiceNow)',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'ticketing'),
    configured: (db) => !!_loadTicketingConfig(db),
    probe: (db) => ticketingProbe(db),
  },
  {
    key: 'scheduling',
    label: 'Workforce Scheduling (Workday / ADP)',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'scheduling'),
    configured: (db) => { const r = _loadSchedulingConfig(db); return !!(r && r.platform && r.platform !== 'manual'); },
    probe: (db) => schedulingProbe(db),
  },
  {
    key: 'sdn',
    label: 'SDN Controller',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'sdn'),
    configured: (db) => { try { return require('./deployment-mode').isSdn(db) && _enabledSdnIntegrations(db).length > 0; } catch (_e) { return false; } },
    probe: (db) => sdnProbe(db),
  },
  {
    key: 'sase',
    label: 'SASE / ZTNA',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'sase'),
    configured: (db) => { try { return require('./deployment-mode').isSase(db) && require('./sase-mode').getConnectorSources(db).length > 0; } catch (_e) { return false; } },
    probe: (db) => saseProbe(db),
  },
  {
    key: 'cloud',
    label: 'Cloud Confidential-VM Attestation',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'cloud'),
    configured: (db) => { try { return require('./deployment-mode').summary(db).substrateCloud === true; } catch (_e) { return false; } },
    probe: (db) => cloudProbe(db),
  },
  {
    key: 'backup',
    label: 'Backup Schedules',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'backup'),
    configured: (db) => _enabledBackupSchedules(db).length > 0,
    probe: (db) => backupProbe(db),
  },
  {
    key: 'cicd',
    label: 'CI/CD Pipeline',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'cicd'),
    configured: (db) => _cicdConfigs(db).length > 0,
    probe: (db) => cicdProbe(db),
  },
  {
    key: 'notifications',
    label: 'Notification Channels',
    enabled: (db) => ihCfg.isIntegrationEnabled(db, 'notifications'),
    configured: (db) => _externalChannelsConfigured(db).any,
    probe: (db) => notificationsProbe(db),
  },
  {
    key: 'threat_hunting',
    label: 'Threat Hunting Integrations',
    enabled: (db) => thConfigEnabled(db),
    configured: (db) => thConfigured(db),
    probe: (db) => threatHuntingProbe(db),
  },
];

module.exports = { registry, kmsProbe, storageProbe, ldapProbe, siemProbe, soarProbe, edrProbe, ticketingProbe, schedulingProbe, sdnProbe, saseProbe, cloudProbe, backupProbe, cicdProbe, notificationsProbe, threatHuntingProbe };

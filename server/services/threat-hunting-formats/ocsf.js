// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Output Formatter: OCSF (B5m)
//
// Maps each domain to an OCSF (Open Cybersecurity Schema Framework) event class
// and emits schema-faithful objects built from the ALREADY-PROJECTED model:
//
//   auth_events -> Authentication      (category 3, class 3002)
//   sessions    -> Authentication      (category 3, class 3002)
//   audit_trail -> API Activity        (category 6, class 6003)
//   integrity   -> Detection Finding   (category 2, class 2004)
//
// Every event carries the OCSF base fields (category/class/activity/type uids,
// time, severity, metadata) plus observables for the pseudonymized actor and the
// source IP. Any projected field without a natural OCSF home is preserved under
// the schema's unmapped object, so nothing is lost and nothing un-pseudonymized
// is introduced. These class choices are pragmatic mappings, documented here.
// ═══════════════════════════════════════════════════════════════════════════════

const OCSF_VERSION = '1.1.0';
const CONTENT_TYPE = 'application/json; charset=utf-8';

const SEVERITY_NAME = {
  0: 'Unknown', 1: 'Informational', 2: 'Low', 3: 'Medium',
  4: 'High', 5: 'Critical', 6: 'Fatal',
};

function toEpochMs(ts) {
  if (typeof ts !== 'string' || !ts) return null;
  let s = ts.trim();
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) s = s.replace(' ', 'T') + 'Z';
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? ms : null;
}

function lc(v) { return String(v == null ? '' : v).toLowerCase(); }

function auditActivity(d) {
  const s = lc(d);
  if (/create|add|issue|enroll|grant|register/.test(s)) return 1;
  if (/read|view|list|export|verify/.test(s)) return 2;
  if (/update|change|modify|rotate|config/.test(s)) return 3;
  if (/delete|revoke|remove|disable|purge/.test(s)) return 4;
  return 0;
}

function auditActivityName(d) {
  return { 0: 'Unknown', 1: 'Create', 2: 'Read', 3: 'Update', 4: 'Delete' }[auditActivity(d)];
}

function integritySeverity(d) {
  const s = lc(d);
  if (s === 'fail' || s === 'unreachable') return 4;
  if (s === 'warning') return 3;
  if (s === 'inconclusive') return 2;
  return 1; // clean / unknown
}

// Per-domain class binding. consumedExtra lists projected fields placed in a
// dedicated OCSF field (so they are not duplicated under unmapped).
const OCSF_DOMAIN = {
  auth_events: {
    category_uid: 3, category_name: 'Identity & Access Management',
    class_uid: 3002, class_name: 'Authentication',
    timeField: 'timestamp', discField: 'action',
    activityId: function () { return 1; },
    activityName: function () { return 'Logon'; },
    severityId: function (d) { return /lock|fail|deny|reject/.test(lc(d)) ? 3 : 1; },
    consumedExtra: [],
    decorate: function (out, e) {
      const fail = /lock|fail|deny|reject/.test(lc(e.action));
      out.status_id = fail ? 2 : 1;
      out.status = fail ? 'Failure' : 'Success';
    },
  },
  sessions: {
    category_uid: 3, category_name: 'Identity & Access Management',
    class_uid: 3002, class_name: 'Authentication',
    timeField: 'created_at', discField: null,
    activityId: function () { return 1; },
    activityName: function () { return 'Logon'; },
    severityId: function () { return 1; },
    consumedExtra: [],
    decorate: function (out) { out.status_id = 1; out.status = 'Success'; },
  },
  audit_trail: {
    category_uid: 6, category_name: 'Application Activity',
    class_uid: 6003, class_name: 'API Activity',
    timeField: 'timestamp', discField: 'event_type',
    activityId: function (d) { return auditActivity(d); },
    activityName: function (d) { return auditActivityName(d); },
    severityId: function (d) { return /delete|revoke|disable|fail|denied/.test(lc(d)) ? 3 : 1; },
    consumedExtra: [],
    decorate: function () {},
  },
  integrity: {
    category_uid: 2, category_name: 'Findings',
    class_uid: 2004, class_name: 'Detection Finding',
    timeField: 'received_at', discField: 'status',
    activityId: function () { return 1; },
    activityName: function () { return 'Create'; },
    severityId: function (d) { return integritySeverity(d); },
    consumedExtra: ['status'],
    decorate: function (out, e) { out.status = e.status != null ? String(e.status) : 'Unknown'; },
  },
};

function buildEvent(domain, event) {
  const e = event || {};
  const cfg = OCSF_DOMAIN[domain];
  if (!cfg) {
    return { class_uid: 0, class_name: 'Base Event', metadata: { version: OCSF_VERSION }, unmapped: e };
  }
  const disc = cfg.discField ? e[cfg.discField] : null;
  const activity_id = cfg.activityId(disc);
  const severity_id = cfg.severityId(disc);
  const time = toEpochMs(e[cfg.timeField]);

  const out = {
    category_uid: cfg.category_uid,
    category_name: cfg.category_name,
    class_uid: cfg.class_uid,
    class_name: cfg.class_name,
    activity_id: activity_id,
    activity_name: cfg.activityName(disc),
    type_uid: cfg.class_uid * 100 + activity_id,
    time: time,
    severity_id: severity_id,
    severity: SEVERITY_NAME[severity_id] || 'Unknown',
    metadata: {
      version: OCSF_VERSION,
      product: {
        name: 'FireAlive',
        vendor_name: 'FireAlive',
        feature: { name: 'threat-hunting' },
      },
    },
    message: String(domain) + (disc != null ? (':' + disc) : ''),
    observables: [],
    unmapped: {},
  };

  const consumed = { actor: true, source_ip: true };
  if (time !== null) consumed[cfg.timeField] = true;
  for (const k of cfg.consumedExtra) consumed[k] = true;

  if (e.actor !== undefined) {
    out.actor = { user: { name: e.actor, type: 'Pseudonym' } };
    out.observables.push({ name: 'actor.user.name', type: 'User Name', type_id: 4, value: String(e.actor) });
  }
  if (e.source_ip !== undefined) {
    out.src_endpoint = { ip: e.source_ip };
    out.observables.push({ name: 'src_endpoint.ip', type: 'IP Address', type_id: 2, value: String(e.source_ip) });
  }
  cfg.decorate(out, e);

  for (const k of Object.keys(e)) {
    if (consumed[k]) continue;
    out.unmapped[k] = e[k];
  }
  return out;
}

function events(model) {
  const m = model || {};
  const rows = Array.isArray(m.events) ? m.events : [];
  const domain = m.domain || 'threat-hunting';
  const ocsfEvents = [];
  for (const e of rows) ocsfEvents.push(buildEvent(domain, e));
  return JSON.stringify({
    format: 'ocsf',
    ocsf_version: OCSF_VERSION,
    domain: m.domain || null,
    generated_at: m.generated_at || null,
    count: ocsfEvents.length,
    has_more: m.has_more === true,
    next_cursor: m.next_cursor || null,
    events: ocsfEvents,
  });
}

function summary(model) {
  const m = model || {};
  return JSON.stringify({
    format: 'ocsf',
    ocsf_version: OCSF_VERSION,
    generated_at: m.generated_at || null,
    resource_metrics: m.resource_metrics || {},
    integrity: m.integrity || {},
  });
}

module.exports = {
  key: 'ocsf',
  contentType: CONTENT_TYPE,
  events: events,
  summary: summary,
  // exposed for tests
  buildEvent: buildEvent,
};

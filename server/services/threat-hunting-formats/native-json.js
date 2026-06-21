// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Output Formatter: native JSON (B5m)
//
// The default dialect. It wraps the already-projected internal model (the query
// framework's envelope, or the summary) in a stable, self-describing JSON
// document. The events are emitted exactly as the collectors projected them --
// actors pseudonymized, only allow-listed fields present -- so this formatter
// adds structure and metadata but never reaches back to any source row.
//
// Formatter contract (shared by every dialect in this directory):
//   key                      a short format identifier
//   contentType              the HTTP Content-Type to send
//   events(model) -> string  serialize a domain query result
//   summary(model) -> string serialize the telemetry summary
// where model carries { domain, label, count, events, has_more, next_cursor,
// generated_at } for events() and { resource_metrics, integrity, generated_at }
// for summary().
// ═══════════════════════════════════════════════════════════════════════════════

const KEY = 'json';
const CONTENT_TYPE = 'application/json; charset=utf-8';

function events(model) {
  const m = model || {};
  return JSON.stringify({
    format: KEY,
    schema: 'firealive.threat-hunting.events/1.0',
    domain: m.domain || null,
    label: m.label || null,
    generated_at: m.generated_at || null,
    count: typeof m.count === 'number' ? m.count : (Array.isArray(m.events) ? m.events.length : 0),
    has_more: m.has_more === true,
    next_cursor: m.next_cursor || null,
    events: Array.isArray(m.events) ? m.events : [],
  });
}

function summary(model) {
  const m = model || {};
  return JSON.stringify({
    format: KEY,
    schema: 'firealive.threat-hunting.summary/1.0',
    generated_at: m.generated_at || null,
    resource_metrics: m.resource_metrics || {},
    integrity: m.integrity || {},
  });
}

module.exports = {
  key: KEY,
  contentType: CONTENT_TYPE,
  events: events,
  summary: summary,
};

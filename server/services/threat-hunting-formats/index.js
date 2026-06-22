// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Output Format Dispatcher (B5m)
//
// Resolves a requested format key to its formatter. The set is closed
// {json, cef, ocsf, stix}: an absent format falls back to the default, but an
// explicitly-requested unknown format resolves to null so the route can reject
// it rather than silently substituting another dialect. Every formatter in this
// directory implements the shared contract { key, contentType, events(model),
// summary(model) }.
// ═══════════════════════════════════════════════════════════════════════════════

const nativeJson = require('./native-json');
const cef = require('./cef');
const ocsf = require('./ocsf');
const stix = require('./stix');

const FORMATTERS = {
  json: nativeJson,
  cef: cef,
  ocsf: ocsf,
  stix: stix,
};

const DEFAULT_FORMAT = 'json';
const FORMATS = Object.keys(FORMATTERS);

function isFormat(key) {
  return typeof key === 'string' && Object.prototype.hasOwnProperty.call(FORMATTERS, key);
}

// Strict lookup: a known format key returns its formatter, anything else null.
function getFormatter(key) {
  return isFormat(key) ? FORMATTERS[key] : null;
}

// Convenience for callers: an absent (null/undefined/empty) key uses the
// default; a present-but-unknown key returns null (closed set, no substitution).
function resolve(key) {
  if (key === undefined || key === null || key === '') return FORMATTERS[DEFAULT_FORMAT];
  return getFormatter(key);
}

module.exports = {
  FORMATS: FORMATS,
  DEFAULT_FORMAT: DEFAULT_FORMAT,
  isFormat: isFormat,
  getFormatter: getFormatter,
  resolve: resolve,
  formatters: FORMATTERS,
};

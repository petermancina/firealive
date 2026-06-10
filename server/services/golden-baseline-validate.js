// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Golden-Baseline Import Validation (D17 layer-1)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// This is the import-safety gate for golden-baseline bundles. In the import
// pipeline it runs AFTER the raw-bytes malware scan and the signature
// verification, and BEFORE the automatic pre-import snapshot and the apply
// (D17 gate order). It is pure structural validation: no database access, no
// side effects. Every failure is collected and thrown as one typed
// BaselineValidationError that the route maps to a 4xx response.
//
// WHY THIS LAYER EXISTS (defense in depth)
//   applyBaseline already iterates the allowlist rather than the payload, so
//   an unknown key can never reach the database. This layer sits in front of
//   it to (a) reject a malformed, tampered, or oversized file at the door with
//   a precise, operator-readable reason BEFORE any snapshot or mutation, and
//   (b) enforce the invariants the apply path assumes (allowlisted keys only,
//   scalar typing, secrets never carried as data).
//
// WHAT IT ENFORCES
//   Envelope (validateEnvelope):
//     - format is the expected FA-GB1 marker
//     - baselineSchemaVersion is an integer this build supports (refuse on
//       mismatch -- D21); appVersion is present (drift is a warning, not a
//       rejection)
//     - the payload, digest, signature, and signing-key block are
//       structurally present and well-shaped enough to verify
//   Payload (validateBaselinePayload):
//     - the three domain sections (teamConfig, configTable, tables) are
//       present objects
//     - ONLY allowlisted keys appear -- unknown team_config keys, unknown
//       config-table keys, unknown tables, and unknown columns are rejected,
//       never silently dropped, so a wrong or tampered file is visible
//     - key/value store values are strings; dedicated-table column values are
//       scalars (string, finite number, or null); booleans, objects, and
//       arrays are rejected (our exports never emit them and the database
//       cannot bind them)
//     - SECRETS ARE NEVER IMPORTABLE: a secret column appearing as a data key
//       is rejected outright; only the secretsPresent marker (an array naming
//       known secret columns) is allowed. This is the anti-smuggling control --
//       it blocks injecting a credential or a base64/binary blob through the
//       import path. Apply re-supplies secrets from the existing row or lands
//       the capability disabled-pending-credentials.
//     - size and shape caps bound resource use: a canonical-payload byte cap,
//       a nesting-depth cap (also protects the canonicalizer from deep
//       recursion), per-string and per-array length caps, and a per-object key
//       cap
//     - string values are screened for disallowed control characters and
//       script-shaped content
//
// The domain (allowlisted keys, table sections, secret columns) is imported
// from golden-baseline.js so the validator can never drift from the capture
// and apply engine -- there is one source of truth.
// ─────────────────────────────────────────────────────────────────────────────

const { canonicalize } = require('./report-signer');
const { version: APP_VERSION } = require('../lib/version');
const {
  BASELINE_SCHEMA_VERSION,
  TEAM_CONFIG_KEYS,
  CONFIG_TABLE_KEYS,
  TABLE_SECTIONS,
} = require('./golden-baseline');

// ── Limits + constants ──────────────────────────────────────────────

const LIMITS = {
  FILE_FORMAT: 'FA-GB1',
  MAX_PAYLOAD_BYTES: 1048576,     // 1 MiB of canonical config payload
  MAX_DEPTH: 12,                  // payload object/array nesting depth
  MAX_NODES: 100000,              // total elements in the payload graph
  MAX_STRING_LENGTH: 100000,      // per string value (characters)
  MAX_ARRAY_LENGTH: 10000,        // per rows / entries array
  MAX_KEYS_PER_OBJECT: 2000,      // per object
  MAX_SECRETS_MARKERS: 64,        // per secretsPresent array
};

// 64-char lowercase hex: both the payload digest and the signing-key
// fingerprint (SHA-256 over SPKI DER) share this shape.
const HEX64_RE = /^[0-9a-f]{64}$/;

// High-signal, near-zero-false-positive markers for script-shaped content in
// configuration strings. Legitimate configuration (URLs, emails, JSON blobs)
// does not contain these; an injected XSS / scriptlet payload does.
const SCRIPT_MARKERS = ['<script', '</script', 'javascript:', '<iframe', 'vbscript:'];

const SECTION_BY_TABLE = new Map(TABLE_SECTIONS.map((s) => [s.table, s]));

// ── Typed error + issue collector ───────────────────────────────────

class BaselineValidationError extends Error {
  constructor(issues, message) {
    super(message || 'Baseline validation failed.');
    this.name = 'BaselineValidationError';
    this.code = 'BASELINE_VALIDATION_FAILED';
    this.issues = Array.isArray(issues) ? issues : [];
  }
}

// Collects every problem found in one pass so the operator sees the full set
// of reasons a file was rejected, not just the first.
class Issues {
  constructor() {
    this.list = [];
  }

  add(path, message) {
    this.list.push({ path, message });
  }

  get any() {
    return this.list.length > 0;
  }

  throwIfAny() {
    if (this.list.length === 0) return;
    const head = this.list.slice(0, 5).map((i) => `${i.path}: ${i.message}`).join('; ');
    const more = this.list.length > 5 ? ` (and ${this.list.length - 5} more)` : '';
    throw new BaselineValidationError(this.list.slice(), `Baseline validation failed: ${head}${more}`);
  }
}

// ── Value predicates ────────────────────────────────────────────────

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// C0 control characters (except tab, LF, CR) and DEL are not allowed in
// configuration strings. Implemented by code-point scan rather than a regex
// so the source carries no escape sequences (house style).
function hasDisallowedControlChars(s) {
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13) continue;
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function isScriptShaped(s) {
  const lower = s.toLowerCase();
  for (const marker of SCRIPT_MARKERS) {
    if (lower.includes(marker)) return true;
  }
  return false;
}

function checkString(value, path, issues) {
  if (typeof value !== 'string') {
    issues.add(path, 'Expected a string value.');
    return;
  }
  if (value.length > LIMITS.MAX_STRING_LENGTH) {
    issues.add(path, `String exceeds the ${LIMITS.MAX_STRING_LENGTH}-character limit.`);
    return;
  }
  if (hasDisallowedControlChars(value)) {
    issues.add(path, 'String contains disallowed control characters.');
    return;
  }
  if (isScriptShaped(value)) {
    issues.add(path, 'String contains script-like content that is not allowed in configuration.');
  }
}

// Dedicated-table column values must be scalars the database can bind.
function checkScalar(value, path, issues) {
  if (value === null) return;
  const t = typeof value;
  if (t === 'string') {
    checkString(value, path, issues);
    return;
  }
  if (t === 'number') {
    if (!Number.isFinite(value)) issues.add(path, 'Numeric value must be finite.');
    return;
  }
  if (t === 'boolean') {
    issues.add(path, 'Boolean values are not allowed here; use 0 or 1.');
    return;
  }
  issues.add(path, 'Value must be a string, number, or null.');
}

// ── Structural limits (pre-canonicalization guard) ──────────────────

// A bounded walk run before canonicalization and detailed validation. It
// fails fast on pathological input (excessive depth, element count, array or
// object width, string length) so the canonicalizer and the schema checks
// never process an abusive object. Returns false to signal the walk should
// stop entirely.
function enforceStructure(value, path, issues, depth, counter) {
  counter.n += 1;
  if (counter.n > LIMITS.MAX_NODES) {
    issues.add(path, 'The configuration has too many elements.');
    return false;
  }
  if (depth > LIMITS.MAX_DEPTH) {
    issues.add(path, 'The configuration is nested too deeply.');
    return false;
  }
  if (Array.isArray(value)) {
    if (value.length > LIMITS.MAX_ARRAY_LENGTH) {
      issues.add(path, 'An array exceeds the maximum length.');
      return false;
    }
    for (let i = 0; i < value.length; i += 1) {
      if (!enforceStructure(value[i], `${path}[${i}]`, issues, depth + 1, counter)) return false;
    }
    return true;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value);
    if (keys.length > LIMITS.MAX_KEYS_PER_OBJECT) {
      issues.add(path, 'An object has too many keys.');
      return false;
    }
    for (const k of keys) {
      if (!enforceStructure(value[k], `${path}.${k}`, issues, depth + 1, counter)) return false;
    }
    return true;
  }
  if (typeof value === 'string' && value.length > LIMITS.MAX_STRING_LENGTH) {
    issues.add(path, 'A string exceeds the maximum length.');
    return false;
  }
  return true;
}

// ── Section validators ──────────────────────────────────────────────

// A key/value store section (teamConfig / configTable): every key must be in
// the allowlist and every value must be a string.
function validateKvSection(label, obj, allowKeys, issues) {
  const allow = new Set(allowKeys);
  for (const [k, v] of Object.entries(obj)) {
    const path = `${label}.${k}`;
    if (!allow.has(k)) {
      issues.add(path, 'Key is not in the configuration allowlist.');
      continue;
    }
    checkString(v, path, issues);
  }
}

// The secretsPresent marker: an array naming known secret columns for the
// section. The secret VALUES are never present -- only this inventory.
function validateSecretsPresent(value, secretSet, path, issues) {
  if (!Array.isArray(value)) {
    issues.add(path, 'secretsPresent must be an array.');
    return;
  }
  if (value.length > LIMITS.MAX_SECRETS_MARKERS) {
    issues.add(path, 'secretsPresent has too many entries.');
    return;
  }
  for (const item of value) {
    if (typeof item !== 'string') {
      issues.add(path, 'secretsPresent entries must be strings.');
      continue;
    }
    if (!secretSet.has(item)) {
      issues.add(path, `secretsPresent names an unknown secret column "${item}".`);
    }
  }
}

// A single record (a rows entry, a manifest entry, or a singleton row).
// Allowed keys are the section's data columns plus the secretsPresent marker.
// A secret column appearing as a DATA key is rejected -- the anti-smuggling
// control.
function validateRecord(record, allowCols, secretCols, path, issues) {
  const allow = new Set(allowCols);
  const secretSet = new Set(secretCols);
  for (const [k, v] of Object.entries(record)) {
    const childPath = `${path}.${k}`;
    if (k === 'secretsPresent') {
      validateSecretsPresent(v, secretSet, childPath, issues);
      continue;
    }
    if (secretSet.has(k)) {
      issues.add(childPath, 'Secret values cannot be imported; only the secretsPresent marker is allowed.');
      continue;
    }
    if (!allow.has(k)) {
      issues.add(childPath, 'Column is not in the configuration allowlist.');
      continue;
    }
    checkScalar(v, childPath, issues);
  }
}

function validateRecordArray(arr, allowCols, secretCols, label, issues) {
  if (!Array.isArray(arr)) {
    issues.add(label, 'Expected an array.');
    return;
  }
  if (arr.length > LIMITS.MAX_ARRAY_LENGTH) {
    issues.add(label, `Too many entries (${arr.length}).`);
    return;
  }
  arr.forEach((rec, i) => {
    const childPath = `${label}[${i}]`;
    if (!isPlainObject(rec)) {
      issues.add(childPath, 'Entry must be an object.');
      return;
    }
    validateRecord(rec, allowCols, secretCols, childPath, issues);
  });
}

// Reject section-level keys other than the expected ones for the mode.
function checkSectionKeys(section, allowed, label, issues) {
  const allow = new Set(allowed);
  for (const k of Object.keys(section)) {
    if (!allow.has(k)) issues.add(`${label}.${k}`, 'Unexpected section key.');
  }
}

function validateSection(sec, section, issues) {
  const label = `tables.${sec.table}`;
  if (!isPlainObject(section)) {
    issues.add(label, 'Section must be an object.');
    return;
  }
  if ('mode' in section && typeof section.mode !== 'string') {
    issues.add(`${label}.mode`, 'mode must be a string.');
  }
  const secretCols = sec.secretCols || [];

  if (sec.mode === 'singleton') {
    checkSectionKeys(section, ['mode', 'row'], label, issues);
    if (!('row' in section)) {
      issues.add(label, 'Singleton section must carry a row (object or null).');
      return;
    }
    if (section.row === null) return; // null row = remove the singleton; valid
    if (!isPlainObject(section.row)) {
      issues.add(`${label}.row`, 'row must be an object or null.');
      return;
    }
    validateRecord(section.row, sec.configCols, secretCols, `${label}.row`, issues);
    return;
  }
  if (sec.mode === 'rows') {
    checkSectionKeys(section, ['mode', 'rows'], label, issues);
    validateRecordArray(section.rows, sec.configCols, secretCols, `${label}.rows`, issues);
    return;
  }
  // manifest
  checkSectionKeys(section, ['mode', 'entries'], label, issues);
  validateRecordArray(section.entries, sec.manifestCols, secretCols, `${label}.entries`, issues);
}

function validateTablesSection(tables, issues) {
  for (const [tableName, section] of Object.entries(tables)) {
    const sec = SECTION_BY_TABLE.get(tableName);
    if (!sec) {
      issues.add(`tables.${tableName}`, 'Unknown configuration table.');
      continue;
    }
    validateSection(sec, section, issues);
  }
}

// ── Public entry points ─────────────────────────────────────────────

/**
 * Validate the FA-GB1 envelope structure and version compatibility. Returns a
 * normalized descriptor the route uses to verify the signature and then
 * validate the payload. Throws BaselineValidationError on any structural or
 * version problem. The appVersion drift (if any) is returned as a warning,
 * not a rejection.
 */
function validateEnvelope(bundle) {
  const issues = new Issues();
  if (!isPlainObject(bundle)) {
    issues.add('$', 'The imported file must be a JSON object.');
    issues.throwIfAny();
  }

  if (bundle.format !== LIMITS.FILE_FORMAT) {
    issues.add('format', `Unrecognized file format; expected ${LIMITS.FILE_FORMAT}.`);
  }

  const sv = bundle.baselineSchemaVersion;
  if (!Number.isInteger(sv)) {
    issues.add('baselineSchemaVersion', 'Missing or non-integer baselineSchemaVersion.');
  } else if (sv !== BASELINE_SCHEMA_VERSION) {
    issues.add('baselineSchemaVersion', `Unsupported baseline schema version ${sv}; this build imports version ${BASELINE_SCHEMA_VERSION}.`);
  }

  const warnings = [];
  if (typeof bundle.appVersion !== 'string' || !bundle.appVersion) {
    issues.add('appVersion', 'Missing appVersion.');
  } else if (bundle.appVersion !== APP_VERSION) {
    warnings.push(`This baseline was exported from app version ${bundle.appVersion}; this deployment runs ${APP_VERSION}. Review the change report before applying.`);
  }

  if (typeof bundle.sha256 !== 'string' || !HEX64_RE.test(bundle.sha256)) {
    issues.add('sha256', 'Missing or malformed payload digest (expected 64-character lowercase hex).');
  }

  if (typeof bundle.signature !== 'string' || bundle.signature.length === 0) {
    issues.add('signature', 'Missing signature.');
  }

  const sk = bundle.signingKey;
  if (!isPlainObject(sk)) {
    issues.add('signingKey', 'Missing signing-key block.');
  } else {
    if (typeof sk.publicKeyPem !== 'string' || sk.publicKeyPem.length === 0) {
      issues.add('signingKey.publicKeyPem', 'Missing signing public key.');
    }
    if (typeof sk.fingerprint !== 'string' || !HEX64_RE.test(sk.fingerprint)) {
      issues.add('signingKey.fingerprint', 'Missing or malformed signing-key fingerprint.');
    }
  }

  if (!isPlainObject(bundle.payload)) {
    issues.add('payload', 'Missing or malformed configuration payload.');
  }

  issues.throwIfAny();

  return {
    schemaVersion: sv,
    appVersion: bundle.appVersion,
    payload: bundle.payload,
    sha256: bundle.sha256,
    signature: bundle.signature,
    signingKey: { publicKeyPem: sk.publicKeyPem, fingerprint: sk.fingerprint },
    warnings,
  };
}

/**
 * Validate and bound-check the configuration payload against the golden-
 * baseline domain. Returns { payload, canonical, bytes, warnings }; the
 * payload is returned unchanged (not mutated) for the apply path. Throws
 * BaselineValidationError listing every problem found.
 */
function validateBaselinePayload(schemaVersion, payload) {
  const issues = new Issues();

  if (schemaVersion !== BASELINE_SCHEMA_VERSION) {
    issues.add('baselineSchemaVersion', `Unsupported baseline schema version ${schemaVersion}; this build imports version ${BASELINE_SCHEMA_VERSION}.`);
    issues.throwIfAny();
  }
  if (!isPlainObject(payload)) {
    issues.add('payload', 'The configuration payload must be an object.');
    issues.throwIfAny();
  }

  // Bound the structure before canonicalizing or walking it in detail.
  enforceStructure(payload, 'payload', issues, 0, { n: 0 });
  issues.throwIfAny();

  const canonical = canonicalize(payload);
  const bytes = Buffer.byteLength(canonical, 'utf8');
  if (bytes > LIMITS.MAX_PAYLOAD_BYTES) {
    issues.add('payload', `Configuration payload is ${bytes} bytes; the limit is ${LIMITS.MAX_PAYLOAD_BYTES}.`);
    issues.throwIfAny();
  }

  for (const k of Object.keys(payload)) {
    if (k !== 'teamConfig' && k !== 'configTable' && k !== 'tables') {
      issues.add(`payload.${k}`, 'Unexpected top-level key.');
    }
  }

  for (const key of ['teamConfig', 'configTable', 'tables']) {
    if (!(key in payload)) issues.add(`payload.${key}`, 'Required section is missing.');
    else if (!isPlainObject(payload[key])) issues.add(`payload.${key}`, 'Section must be an object.');
  }

  if (isPlainObject(payload.teamConfig)) {
    validateKvSection('teamConfig', payload.teamConfig, TEAM_CONFIG_KEYS, issues);
  }
  if (isPlainObject(payload.configTable)) {
    validateKvSection('configTable', payload.configTable, CONFIG_TABLE_KEYS, issues);
  }
  if (isPlainObject(payload.tables)) {
    validateTablesSection(payload.tables, issues);
  }

  issues.throwIfAny();
  return { payload, canonical, bytes, warnings: [] };
}

// ── Exports ─────────────────────────────────────────────────────────

module.exports = {
  LIMITS,
  BaselineValidationError,
  validateEnvelope,
  validateBaselinePayload,
};

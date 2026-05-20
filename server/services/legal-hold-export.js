// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Legal Hold Export Orchestrator (R3l C38)
//
// Single-shot synchronous orchestrator for producing a litigation-grade
// legal hold export package. Structurally parallel to forensic-export.js
// (C22) but with critical 2b differences:
//
//   - Status lifecycle is pending -> in_progress -> active (NOT complete).
//     'active' means the preservation mandate is in force. A separate
//     active -> released transition fires via releaseLegalHold() when a
//     CISO (separate from the original requester) executes a release.
//
//   - case_id and rationale are REQUIRED at the request level. Forensic
//     exports allow ad-hoc IR creation; legal holds cannot — every hold
//     must reference a litigation/regulatory matter and document why.
//
//   - custodian_filter optionally restricts slice fetches to data
//     concerning specific user_ids. Used when a hold targets a particular
//     person's activity (e.g., "preserve all evidence relating to
//     analyst Jane Doe's session activity between Q3 dates").
//
//   - indefinite_retention defaults to 1. While a hold is active
//     (hold_released_at IS NULL), the retention job MUST skip the row.
//     The retention skip is enforced by the retention service (lives
//     elsewhere — Workstream 3 or later); this orchestrator establishes
//     the contract by setting the default and documenting it here.
//
//   - Chain entries land in legal_hold_chain (NOT forensic_export_chain).
//     Append-only enforced by SQLite triggers from C37. Event types are
//     HOLD_CREATED / HOLD_COMPLETED / HOLD_DOWNLOADED / HOLD_RELEASED /
//     CHAIN_VERIFIED — distinct enum from forensic_export_chain's
//     EXPORT_* set so a chain reader can tell legal holds and forensic
//     exports apart even if their entries were ever interleaved.
//
//   - Signing keys live in legal_hold_chain_signing_keys, distinct from
//     forensic_export_chain_signing_keys. Legal admissibility requires
//     the chain of custody to be tied to a key set that wasn't also used
//     for routine forensic exports — separation eliminates an argument
//     opposing counsel could make about cross-workflow contamination.
//
//   - The release function (releaseLegalHold) enforces separate-actor
//     at the orchestrator layer. Defense-in-depth above the schema's
//     CHECK constraint (C37). The schema check fires if the route
//     layer is bypassed; the orchestrator check fires with a clean
//     error message in the normal flow.
//
// SEPARATE-ACTOR INVARIANT
//
// Release of a legal hold must be performed by a user different from the
// original requester. The constraint is enforced at THREE layers:
//
//   1. Schema (C37):  CHECK (hold_released_by_user_id IS NULL
//                            OR hold_released_by_user_id != requested_by_user_id)
//   2. Orchestrator (this file, releaseLegalHold): explicit comparison
//      before the UPDATE; throws SeparateActorViolation
//   3. Route layer (C46):  middleware check + ciso role gate
//
// All three layers must agree. The schema is the final backstop.
//
// EXCLUSION-BY-CONSTRUCTION
//
// Same posture as forensic-export.js: every SELECT enumerates columns
// explicitly; sensitive columns (refresh_token_hash, cef_message,
// private_key_encrypted, credentials_encrypted, audit_log.cef_message)
// are never selected. New table additions require explicit fetcher
// updates; forgetting drops the data silently — the SAFE failure mode.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { spawnSync } = require('child_process');

const { encryptConfig, decryptConfig } = require('./encryption');
const {
  canonicalSerialize,
  sliceSha256,
  buildManifestSkeleton,
  addSlice,
} = require('./audit-export-shared');

// ── Constants ─────────────────────────────────────────────────────────────

const DEFAULT_HOLD_DIR = path.join(process.cwd(), 'data', 'legal-holds');
const COSIGN_ENV_VAR = 'FIREALIVE_LEGAL_HOLD_USE_COSIGN';
const TAR_BLOCK_SIZE = 512;
const TAR_MAGIC = 'ustar\0';
const TAR_VERSION = '00';

// ── Lazy-loaded format serializer registry ────────────────────────────────
//
// Each entry maps a format identifier to a module that exposes:
//   { formatId, fileExtension, serialize(slices) -> Buffer }
//
// 8 format serializers ship in C39-C45 (pdf-bates + tiff-bates combined
// into C45). tryLoad() swallows MODULE_NOT_FOUND so this orchestrator can
// be installed in C38 (before C39-C45) without crashing at require time.
// When createLegalHold is called for a format whose serializer is not yet
// loaded, the orchestrator fails cleanly with a clear error message and
// stamps the row status='failed'.

const FORMAT_SERIALIZERS = {};

function tryLoad(formatId, modulePath) {
  try {
    const mod = require(modulePath);
    if (mod && typeof mod.serialize === 'function') {
      FORMAT_SERIALIZERS[formatId] = mod;
    }
  } catch (e) {
    if (e.code !== 'MODULE_NOT_FOUND') {
      // Real load error (e.g., syntax error inside a present module).
      // Surface to stderr but do not crash this module's require — the
      // orchestrator will report 'format not registered' for any request
      // that asks for this format.
      // eslint-disable-next-line no-console
      console.error('legal-hold-export: failed to load ' + formatId + ': ' + e.message);
    }
  }
}

tryLoad('edrm-xml', './legal-hold-formats/edrm-xml');
tryLoad('eml-mime', './legal-hold-formats/eml-mime');
tryLoad('pst', './legal-hold-formats/pst');
tryLoad('concordance', './legal-hold-formats/concordance');
tryLoad('relativity', './legal-hold-formats/relativity');
tryLoad('json-tarball', './legal-hold-formats/json-tarball');
tryLoad('pdf-bates', './legal-hold-formats/pdf-bates');
tryLoad('tiff-bates', './legal-hold-formats/tiff-bates');

// Test-only hook so unit tests can register a stub serializer without
// shipping a real module. Mirrors forensic-export.js's contract.
function _registerFormatForTest(formatId, serializer) {
  if (typeof serializer !== 'object' || typeof serializer.serialize !== 'function') {
    throw new Error('_registerFormatForTest: serializer must have a serialize() function');
  }
  FORMAT_SERIALIZERS[formatId] = serializer;
}

// ── Signing key lifecycle ─────────────────────────────────────────────────
//
// Distinct from forensic_export_chain_signing_keys. Legal admissibility
// requires the chain of custody to be tied to a key set that wasn't also
// used for routine forensic exports.

function ensureActiveSigningKey(db) {
  const existing = db
    .prepare(
      'SELECT id, public_key, fingerprint FROM legal_hold_chain_signing_keys WHERE active = 1 LIMIT 1'
    )
    .get();
  if (existing) {
    return {
      id: existing.id,
      publicKeyPem: existing.public_key,
      fingerprint: existing.fingerprint,
      isNewlyCreated: false,
    };
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privateKeyEncrypted = encryptConfig({ pem: privateKeyPem });

  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const fingerprint = crypto.createHash('sha256').update(spkiDer).digest('hex');
  const id = 'lhsk-' + crypto.randomUUID();

  db.prepare(
    'INSERT INTO legal_hold_chain_signing_keys (id, public_key, private_key_encrypted, fingerprint, active) VALUES (?, ?, ?, ?, 1)'
  ).run(id, publicKeyPem, privateKeyEncrypted, fingerprint);

  return { id, publicKeyPem, fingerprint, isNewlyCreated: true };
}

function loadActivePrivateKey(db) {
  const row = db
    .prepare(
      'SELECT id, public_key, private_key_encrypted, fingerprint FROM legal_hold_chain_signing_keys WHERE active = 1 LIMIT 1'
    )
    .get();
  if (!row) {
    throw new Error('No active legal hold signing key found');
  }
  const { pem } = decryptConfig(row.private_key_encrypted);
  const privateKey = crypto.createPrivateKey({ key: pem, format: 'pem' });
  return {
    id: row.id,
    publicKeyPem: row.public_key,
    privateKey,
    fingerprint: row.fingerprint,
  };
}

function signEd25519(privateKey, bytes) {
  return crypto.sign(null, bytes, privateKey).toString('hex');
}

// ── Multi-entry POSIX ustar tar builder ───────────────────────────────────
//
// Byte-identical to forensic-export.js's implementation. This duplication
// is intentional for now — extracting to a shared helper would be a
// refactor that doesn't belong in 2b scope. A future cleanup may move
// tar building into audit-export-shared.js once we have a third consumer.

function buildTarHeader(filename, payloadSize) {
  if (typeof filename !== 'string' || !filename || filename.length > 100) {
    throw new Error('buildTarHeader: filename must be 1-100 ASCII chars');
  }
  const header = Buffer.alloc(TAR_BLOCK_SIZE);

  const writeOctal = (value, offset, width) => {
    const str = value.toString(8);
    if (str.length > width - 1) {
      throw new Error('buildTarHeader: octal value too large for field');
    }
    header.write(str.padStart(width - 1, '0'), offset, width - 1, 'ascii');
    header[offset + width - 1] = 0;
  };

  header.write(filename, 0, 100, 'ascii');
  writeOctal(0o644, 100, 8);          // mode
  writeOctal(0, 108, 8);              // uid
  writeOctal(0, 116, 8);              // gid
  writeOctal(payloadSize, 124, 12);   // size
  writeOctal(Math.floor(Date.now() / 1000), 136, 12); // mtime
  for (let i = 148; i < 156; i++) header[i] = 0x20;   // chksum placeholder
  header[156] = 0x30;                 // typeflag '0' regular file
  header.write(TAR_MAGIC, 257, 6, 'binary');
  header.write(TAR_VERSION, 263, 2, 'ascii');

  let checksum = 0;
  for (let i = 0; i < TAR_BLOCK_SIZE; i++) checksum += header[i];
  writeOctal(checksum, 148, 7);
  header[155] = 0x20;
  return header;
}

function buildMultiEntryTar(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error('buildMultiEntryTar: at least one entry required');
  }
  const parts = [];
  for (const entry of entries) {
    if (!entry || typeof entry.name !== 'string' || !Buffer.isBuffer(entry.payload)) {
      throw new Error('buildMultiEntryTar: each entry needs {name: string, payload: Buffer}');
    }
    parts.push(buildTarHeader(entry.name, entry.payload.length));
    parts.push(entry.payload);
    const padding = TAR_BLOCK_SIZE - (entry.payload.length % TAR_BLOCK_SIZE);
    if (padding !== TAR_BLOCK_SIZE) parts.push(Buffer.alloc(padding));
  }
  parts.push(Buffer.alloc(TAR_BLOCK_SIZE * 2));
  return Buffer.concat(parts);
}

// ── Data slice fetchers (column-omitted SELECT + optional custodian filter)
//
// custodianFilter (array of user_ids) restricts rows to those concerning
// the listed custodians. When null/empty, no filter is applied.
//
// - audit_log:        filters on user_id (the actor)
// - backup_chain:     no user_id column → custodianFilter ignored
// - incident_records: empty in current schema → custodianFilter moot
// - auth_log:         filters on user (the username — auth_log doesn't
//                     have user_id; for custodian-filtered holds the
//                     caller must pass usernames, not user_ids, in
//                     custodian_filter, OR the route layer maps user_id
//                     → username before invoking the orchestrator)
// - sessions:         filters on user_id

function tableExists(db, name) {
  const row = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?")
    .get(name);
  return Boolean(row);
}

function parseCustodianFilter(raw) {
  if (!raw) return null;
  if (Array.isArray(raw)) return raw.filter((s) => typeof s === 'string' && s.length > 0);
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter((s) => typeof s === 'string' && s.length > 0) : null;
    } catch (_e) {
      return null;
    }
  }
  return null;
}

function fetchAuditLogSlice(db, opts) {
  if (!tableExists(db, 'audit_log')) return [];
  const custodians = parseCustodianFilter(opts.custodianFilter);
  if (custodians && custodians.length > 0) {
    const placeholders = custodians.map(() => '?').join(',');
    return db
      .prepare(
        'SELECT id, timestamp, user_id, event_type, detail, ip_address FROM audit_log ' +
          'WHERE (? IS NULL OR timestamp >= ?) AND (? IS NULL OR timestamp <= ?) ' +
          '  AND user_id IN (' + placeholders + ') ' +
          'ORDER BY id ASC'
      )
      .all(
        opts.timeWindowStart, opts.timeWindowStart,
        opts.timeWindowEnd, opts.timeWindowEnd,
        ...custodians
      );
  }
  return db
    .prepare(
      'SELECT id, timestamp, user_id, event_type, detail, ip_address FROM audit_log ' +
        'WHERE (? IS NULL OR timestamp >= ?) AND (? IS NULL OR timestamp <= ?) ' +
        'ORDER BY id ASC'
    )
    .all(
      opts.timeWindowStart, opts.timeWindowStart,
      opts.timeWindowEnd, opts.timeWindowEnd
    );
}

function fetchBackupChainSlice(db, opts) {
  if (!tableExists(db, 'backup_chain')) return [];
  // backup_chain has no per-user dimension; custodian_filter is ignored
  // for this slice. A hold scoped to a single custodian still includes
  // the full backup chain for the time window because backups are
  // platform-level artifacts not attributable to individual users.
  return db
    .prepare(
      'SELECT id, prev_hash, this_hash, signature, signing_key_id, event_type, backup_id, payload, created_at FROM backup_chain ' +
        'WHERE (? IS NULL OR created_at >= ?) AND (? IS NULL OR created_at <= ?) ' +
        'ORDER BY id ASC'
    )
    .all(
      opts.timeWindowStart, opts.timeWindowStart,
      opts.timeWindowEnd, opts.timeWindowEnd
    );
}

function fetchIncidentRecordsSlice(db, opts) {
  // Same posture as forensic-export.js: no dedicated incident_records
  // table in the current schema. Returns empty slice; flag is a noop.
  void db; void opts;
  return [];
}

function fetchAuthenticationLogsSlice(db, opts) {
  if (!tableExists(db, 'auth_log')) return [];
  const custodians = parseCustodianFilter(opts.custodianFilter);
  if (custodians && custodians.length > 0) {
    const placeholders = custodians.map(() => '?').join(',');
    return db
      .prepare(
        'SELECT id, timestamp, user, action, ip, method, reason, user_agent FROM auth_log ' +
          'WHERE (? IS NULL OR timestamp >= ?) AND (? IS NULL OR timestamp <= ?) ' +
          '  AND user IN (' + placeholders + ') ' +
          'ORDER BY id ASC'
      )
      .all(
        opts.timeWindowStart, opts.timeWindowStart,
        opts.timeWindowEnd, opts.timeWindowEnd,
        ...custodians
      );
  }
  return db
    .prepare(
      'SELECT id, timestamp, user, action, ip, method, reason, user_agent FROM auth_log ' +
        'WHERE (? IS NULL OR timestamp >= ?) AND (? IS NULL OR timestamp <= ?) ' +
        'ORDER BY id ASC'
    )
    .all(
      opts.timeWindowStart, opts.timeWindowStart,
      opts.timeWindowEnd, opts.timeWindowEnd
    );
}

function fetchUserAccessLogsSlice(db, opts) {
  if (!tableExists(db, 'sessions')) return [];
  const custodians = parseCustodianFilter(opts.custodianFilter);
  if (custodians && custodians.length > 0) {
    const placeholders = custodians.map(() => '?').join(',');
    return db
      .prepare(
        'SELECT id, user_id, ip_address, user_agent, created_at, expires_at FROM sessions ' +
          'WHERE (? IS NULL OR created_at >= ?) AND (? IS NULL OR created_at <= ?) ' +
          '  AND user_id IN (' + placeholders + ') ' +
          'ORDER BY created_at ASC'
      )
      .all(
        opts.timeWindowStart, opts.timeWindowStart,
        opts.timeWindowEnd, opts.timeWindowEnd,
        ...custodians
      );
  }
  return db
    .prepare(
      'SELECT id, user_id, ip_address, user_agent, created_at, expires_at FROM sessions ' +
        'WHERE (? IS NULL OR created_at >= ?) AND (? IS NULL OR created_at <= ?) ' +
        'ORDER BY created_at ASC'
    )
    .all(
      opts.timeWindowStart, opts.timeWindowStart,
      opts.timeWindowEnd, opts.timeWindowEnd
    );
}

// ── Chain entry append ────────────────────────────────────────────────────

function appendChainEntry(db, opts) {
  // opts: { holdId, actorUserId, eventType, manifestBytes, privateKey }
  // Hash chain: this_hash = SHA-256(prev_hash || canonicalize(payload)).
  // payload here = { event_type, hold_ref, actor_user_id, manifest_sha256,
  //                  timestamp }. manifest_sha256 ties the chain entry to
  // a specific manifest version.
  const prevRow = db
    .prepare('SELECT this_hash FROM legal_hold_chain ORDER BY id DESC LIMIT 1')
    .get();
  const prevHash = prevRow ? prevRow.this_hash : null;

  const manifestSha256 = sliceSha256(opts.manifestBytes);
  const payload = {
    event_type: opts.eventType,
    hold_ref: opts.holdId,
    actor_user_id: opts.actorUserId,
    manifest_sha256: manifestSha256,
    timestamp: new Date().toISOString(),
  };
  const payloadBytes = canonicalSerialize(payload);
  const linkInput = prevHash
    ? Buffer.concat([Buffer.from(prevHash, 'hex'), payloadBytes])
    : payloadBytes;
  const thisHash = crypto.createHash('sha256').update(linkInput).digest('hex');
  const signature = signEd25519(opts.privateKey, Buffer.from(thisHash, 'hex'));

  db.prepare(
    'INSERT INTO legal_hold_chain (prev_hash, this_hash, signature, event_type, hold_ref, actor_user_id) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(prevHash, thisHash, signature, opts.eventType, opts.holdId, opts.actorUserId);

  return { prevHash, thisHash, signature, manifestSha256 };
}

// ── Optional Cosign attestation ───────────────────────────────────────────
//
// Distinct env var from forensic exports (FIREALIVE_LEGAL_HOLD_USE_COSIGN
// vs FIREALIVE_FORENSIC_USE_COSIGN). Operators can enable Cosign for one
// workflow without enabling it for the other — useful when the legal
// team's sigstore setup is separate from the SOC's.

function maybeInvokeCosign(archivePath) {
  if (process.env[COSIGN_ENV_VAR] !== 'true') return null;
  const cosignPath = process.env.FIREALIVE_COSIGN_BINARY || 'cosign';
  const sigPath = archivePath + '.cosign.sig';
  const result = spawnSync(
    cosignPath,
    ['sign-blob', '--yes', '--output-signature', sigPath, archivePath],
    { encoding: 'utf-8', timeout: 60000 }
  );
  if (result.error || result.status !== 0) {
    return { ok: false, error: result.error ? result.error.message : 'cosign exited ' + result.status };
  }
  return { ok: true, sigPath };
}

// ── Custom error: SeparateActorViolation ──────────────────────────────────

class SeparateActorViolation extends Error {
  constructor(message) {
    super(message);
    this.name = 'SeparateActorViolation';
    this.statusCode = 403;
  }
}

// ── Main orchestrator ─────────────────────────────────────────────────────

/**
 * createLegalHold(db, request, opts?)
 *
 * Synchronously produces a legal hold export package. Returns the created
 * legal_hold_exports row id and artifact paths.
 *
 * request: {
 *   requestedByUserId: string (required)
 *   caseId: string (required — litigation/regulatory matter ID)
 *   rationale: string (REQUIRED — schema NOT NULL)
 *   timeWindowStart, timeWindowEnd: ISO 8601 string | null
 *   custodianFilter: string[] | string (JSON) | null
 *   outputFormats: string[] (1+ format ids; must all be registered)
 *   indefiniteRetention: boolean (default true)
 *   includeAuditLog, includeBackupChain, includeIncidentRecords,
 *     includeAuthenticationLogs, includeUserAccessLogs: boolean
 * }
 * opts: { holdDir? } (defaults to ./data/legal-holds)
 *
 * Throws on validation failure or if any required serializer is missing.
 * Status transitions:
 *   pending -> in_progress -> active  (happy path; preservation mandate live)
 *   pending -> in_progress -> failed  (on error)
 * Subsequent: active -> released  (only via releaseLegalHold)
 */
function createLegalHold(db, request, opts) {
  if (!db) throw new Error('createLegalHold: db required');
  if (!request || !request.requestedByUserId) {
    throw new Error('createLegalHold: requestedByUserId required');
  }
  if (!request.caseId || typeof request.caseId !== 'string') {
    throw new Error('createLegalHold: caseId required');
  }
  if (!request.rationale || typeof request.rationale !== 'string' || request.rationale.length < 20) {
    throw new Error('createLegalHold: rationale required (min 20 chars — every legal hold must document why)');
  }
  const formats = Array.isArray(request.outputFormats) ? request.outputFormats : [];
  if (formats.length === 0) {
    throw new Error('createLegalHold: at least one output format required');
  }
  for (const f of formats) {
    if (!FORMAT_SERIALIZERS[f]) {
      throw new Error('createLegalHold: format not registered: ' + f);
    }
  }

  const holdDir = (opts && opts.holdDir) || DEFAULT_HOLD_DIR;
  fs.mkdirSync(holdDir, { recursive: true });

  ensureActiveSigningKey(db);
  const holdId = 'lh-' + crypto.randomUUID();
  const custodianFilterStored = Array.isArray(request.custodianFilter)
    ? JSON.stringify(request.custodianFilter)
    : (typeof request.custodianFilter === 'string' ? request.custodianFilter : null);
  const indefiniteRetention = request.indefiniteRetention === false ? 0 : 1;

  db.prepare(
    'INSERT INTO legal_hold_exports (id, case_id, requested_by_user_id, rationale, time_window_start, time_window_end, custodian_filter, output_formats, include_audit_log, include_backup_chain, include_incident_records, include_authentication_logs, include_user_access_logs, indefinite_retention, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \'pending\')'
  ).run(
    holdId,
    request.caseId,
    request.requestedByUserId,
    request.rationale,
    request.timeWindowStart || null,
    request.timeWindowEnd || null,
    custodianFilterStored,
    formats.join(','),
    request.includeAuditLog === false ? 0 : 1,
    request.includeBackupChain === false ? 0 : 1,
    request.includeIncidentRecords === false ? 0 : 1,
    request.includeAuthenticationLogs === false ? 0 : 1,
    request.includeUserAccessLogs === false ? 0 : 1,
    indefiniteRetention
  );

  db.prepare("UPDATE legal_hold_exports SET status = 'in_progress' WHERE id = ?").run(holdId);

  let archivePath = null;
  let manifestPath = null;
  let manifestSigPath = null;
  try {
    db.exec('BEGIN');
    const slices = {};
    if (request.includeAuditLog !== false) slices.audit_log = fetchAuditLogSlice(db, request);
    if (request.includeBackupChain !== false) slices.backup_chain = fetchBackupChainSlice(db, request);
    if (request.includeIncidentRecords !== false) slices.incident_records = fetchIncidentRecordsSlice(db, request);
    if (request.includeAuthenticationLogs !== false) slices.authentication_logs = fetchAuthenticationLogsSlice(db, request);
    if (request.includeUserAccessLogs !== false) slices.user_access_logs = fetchUserAccessLogsSlice(db, request);
    db.exec('COMMIT');

    const manifest = buildManifestSkeleton({
      exportType: 'legal-hold',
      exportId: holdId,
      requestedByUserId: request.requestedByUserId,
      rationale: request.rationale,
      timeWindowStart: request.timeWindowStart,
      timeWindowEnd: request.timeWindowEnd,
      eventTypeFilter: null,
      outputFormats: formats,
      includeAuditLog: request.includeAuditLog !== false,
      includeBackupChain: request.includeBackupChain !== false,
      includeIncidentRecords: request.includeIncidentRecords !== false,
      includeAuthenticationLogs: request.includeAuthenticationLogs !== false,
      includeUserAccessLogs: request.includeUserAccessLogs !== false,
    });
    // Legal-hold-specific manifest extensions
    manifest.case_id = request.caseId;
    manifest.custodian_filter = parseCustodianFilter(request.custodianFilter);
    manifest.indefinite_retention = indefiniteRetention === 1;

    const tarEntries = [];
    for (const formatId of formats) {
      const serializer = FORMAT_SERIALIZERS[formatId];
      const sliceBytes = serializer.serialize(slices);
      if (!Buffer.isBuffer(sliceBytes)) {
        throw new Error('createLegalHold: serializer ' + formatId + ' did not return a Buffer');
      }
      const fileName = (serializer.fileExtension && serializer.fileExtension.startsWith('.'))
        ? formatId + serializer.fileExtension
        : formatId + '.bin';
      addSlice(manifest, {
        name: fileName,
        format: formatId,
        sha256: sliceSha256(sliceBytes),
        size_bytes: sliceBytes.length,
        line_count: serializer.lineOriented ? sliceBytes.toString('utf-8').split('\n').length - 1 : null,
      });
      tarEntries.push({ name: fileName, payload: sliceBytes });
    }

    const signingKey = loadActivePrivateKey(db);
    manifest.signing = {
      algorithm: 'ed25519',
      key_id: signingKey.id,
      fingerprint: signingKey.fingerprint,
    };
    const manifestBytes = canonicalSerialize(manifest);
    const manifestSignature = signEd25519(signingKey.privateKey, manifestBytes);
    tarEntries.push({ name: 'manifest.json', payload: manifestBytes });
    tarEntries.push({ name: 'manifest.sig', payload: Buffer.from(manifestSignature, 'hex') });

    const tarBytes = buildMultiEntryTar(tarEntries);
    const gzBytes = zlib.gzipSync(tarBytes);
    archivePath = path.join(holdDir, holdId + '.tar.gz');
    manifestPath = path.join(holdDir, holdId + '.manifest.json');
    manifestSigPath = path.join(holdDir, holdId + '.manifest.sig');
    fs.writeFileSync(archivePath, gzBytes);
    fs.writeFileSync(manifestPath, manifestBytes);
    fs.writeFileSync(manifestSigPath, Buffer.from(manifestSignature, 'hex'));
    const archiveSha256 = sliceSha256(gzBytes);

    const cosignResult = maybeInvokeCosign(archivePath);
    const cosignPath = cosignResult && cosignResult.ok ? cosignResult.sigPath : null;

    appendChainEntry(db, {
      holdId,
      actorUserId: request.requestedByUserId,
      eventType: 'HOLD_CREATED',
      manifestBytes,
      privateKey: signingKey.privateKey,
    });

    // Status='active' (NOT 'complete') — the preservation mandate is now
    // in force and will remain so until releaseLegalHold() fires.
    db.prepare(
      'UPDATE legal_hold_exports SET status = \'active\', manifest_path = ?, archive_path = ?, manifest_sig_path = ?, manifest_signing_key_id = ?, manifest_signing_key_fingerprint = ?, cosign_signature_path = ?, archive_sha256 = ?, size_bytes = ?, completed_at = ? WHERE id = ?'
    ).run(
      manifestPath,
      archivePath,
      manifestSigPath,
      signingKey.id,
      signingKey.fingerprint,
      cosignPath,
      archiveSha256,
      gzBytes.length,
      new Date().toISOString().replace('T', ' ').substring(0, 19),
      holdId
    );

    // Append HOLD_COMPLETED chain entry — marks the active-state transition.
    // Useful for chain readers distinguishing "creation in progress" from
    // "hold is now actively preserving evidence."
    appendChainEntry(db, {
      holdId,
      actorUserId: request.requestedByUserId,
      eventType: 'HOLD_COMPLETED',
      manifestBytes,
      privateKey: signingKey.privateKey,
    });

    return {
      id: holdId,
      caseId: request.caseId,
      archivePath,
      manifestPath,
      manifestSigPath,
      cosignSignaturePath: cosignPath,
      archiveSha256,
      sizeBytes: gzBytes.length,
      signingKeyId: signingKey.id,
      signingKeyFingerprint: signingKey.fingerprint,
      status: 'active',
      indefiniteRetention: indefiniteRetention === 1,
    };
  } catch (err) {
    for (const p of [archivePath, manifestPath, manifestSigPath]) {
      if (p) try { fs.unlinkSync(p); } catch (_e) { /* ignore */ }
    }
    try { db.exec('ROLLBACK'); } catch (_e) { /* not in tx */ }
    db.prepare("UPDATE legal_hold_exports SET status = 'failed', error_message = ? WHERE id = ?")
      .run(String(err && err.message ? err.message : err), holdId);
    throw err;
  }
}

/**
 * releaseLegalHold(db, holdId, releasedByUserId, rationale)
 *
 * Executes the separate-actor release of a legal hold. Verifies:
 *   1. Hold exists and is in status='active'
 *   2. releasedByUserId is NOT the original requested_by_user_id
 *      (SeparateActorViolation if same — defense-in-depth above schema CHECK)
 *   3. rationale is provided (release rationale, distinct from create rationale)
 *
 * Then UPDATEs the row (status='released', hold_released_at=now,
 * hold_released_by_user_id=releasedByUserId, hold_release_rationale=rationale)
 * and appends HOLD_RELEASED to the chain.
 *
 * The schema CHECK on hold_released_by_user_id != requested_by_user_id is
 * the final backstop — if this orchestrator check is somehow bypassed,
 * the UPDATE itself will fail with a SQLite IntegrityError.
 */
function releaseLegalHold(db, holdId, releasedByUserId, rationale) {
  if (!db) throw new Error('releaseLegalHold: db required');
  if (!holdId) throw new Error('releaseLegalHold: holdId required');
  if (!releasedByUserId) throw new Error('releaseLegalHold: releasedByUserId required');
  if (!rationale || typeof rationale !== 'string' || rationale.length < 20) {
    throw new Error('releaseLegalHold: rationale required (min 20 chars — every release must document why)');
  }

  const row = db
    .prepare(
      'SELECT id, case_id, requested_by_user_id, status, hold_released_at FROM legal_hold_exports WHERE id = ?'
    )
    .get(holdId);
  if (!row) {
    const e = new Error('releaseLegalHold: hold not found: ' + holdId);
    e.statusCode = 404;
    throw e;
  }
  if (row.status !== 'active') {
    const e = new Error('releaseLegalHold: hold not active (current status: ' + row.status + ')');
    e.statusCode = 409;
    throw e;
  }
  if (row.requested_by_user_id === releasedByUserId) {
    throw new SeparateActorViolation(
      'releaseLegalHold: separate-actor invariant violated — ' +
      'release must be performed by a user different from the original requester ' +
      '(requester=' + row.requested_by_user_id + ', releaser=' + releasedByUserId + ')'
    );
  }

  const signingKey = loadActivePrivateKey(db);
  // Build a release-context manifest fragment to sign in the chain entry.
  // The original archive's manifest is immutable; this fragment binds the
  // release event to the hold's identity.
  const releaseManifest = {
    release_event: 'HOLD_RELEASED',
    hold_id: holdId,
    case_id: row.case_id,
    original_requester: row.requested_by_user_id,
    releaser: releasedByUserId,
    rationale,
    released_at: new Date().toISOString(),
  };
  const releaseManifestBytes = canonicalSerialize(releaseManifest);

  try {
    db.exec('BEGIN');
    db.prepare(
      "UPDATE legal_hold_exports SET status = 'released', hold_released_at = ?, hold_released_by_user_id = ?, hold_release_rationale = ? WHERE id = ?"
    ).run(
      new Date().toISOString().replace('T', ' ').substring(0, 19),
      releasedByUserId,
      rationale,
      holdId
    );
    appendChainEntry(db, {
      holdId,
      actorUserId: releasedByUserId,
      eventType: 'HOLD_RELEASED',
      manifestBytes: releaseManifestBytes,
      privateKey: signingKey.privateKey,
    });
    db.exec('COMMIT');
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch (_e) { /* not in tx */ }
    throw err;
  }

  return {
    id: holdId,
    status: 'released',
    releasedAt: new Date().toISOString(),
    releasedByUserId,
    rationale,
  };
}

module.exports = {
  createLegalHold,
  releaseLegalHold,
  ensureActiveSigningKey,
  loadActivePrivateKey,
  signEd25519,
  buildMultiEntryTar,
  appendChainEntry,
  fetchAuditLogSlice,
  fetchBackupChainSlice,
  fetchIncidentRecordsSlice,
  fetchAuthenticationLogsSlice,
  fetchUserAccessLogsSlice,
  parseCustodianFilter,
  SeparateActorViolation,
  // test-only
  _registerFormatForTest,
};

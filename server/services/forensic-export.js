// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Forensic Export Orchestrator (R3l C22)
//
// Single-shot synchronous orchestrator for producing a SOC-grade forensic
// export package. Given a validated export request and a DB handle, this
// module:
//
//   1. Inserts a forensic_exports row with status='pending' and a fresh id
//   2. Transitions the row to status='in_progress' for in-flight visibility
//   3. Opens a SQLite read transaction so all slice fetches see the same
//      consistent snapshot of the data
//   4. Fetches each included data category via column-omitted SELECT
//      statements — the EXCLUSION-BY-CONSTRUCTION invariant. Each fetcher
//      hardcodes its column list, so a sensitive column (private_key_*,
//      credentials_encrypted, refresh_token_hash, cef_message) can never
//      leak through path manipulation or flag tampering
//   5. Combines the slice data into an event stream and dispatches it to
//      each requested format serializer (C23-C28). Serializers are loaded
//      lazily; missing ones are reported and the export fails cleanly
//   6. Computes SHA-256 of each serialized slice, adds slice descriptors
//      to the manifest skeleton via the shared addSlice() helper
//   7. Canonical-serializes the manifest, signs it with Ed25519 using the
//      active key from forensic_export_chain_signing_keys
//   8. Builds a single multi-entry POSIX ustar archive (slices +
//      manifest.json + manifest.sig), gzips it
//   9. Computes archive SHA-256
//  10. Optionally invokes the Cosign signer if env var
//      FIREALIVE_FORENSIC_USE_COSIGN=true (503 if binary missing per the
//      R3k pattern; failure does NOT roll back the otherwise-complete
//      Ed25519 archive)
//  11. Appends an EXPORT_CREATED entry to forensic_export_chain with hash
//      chain linkage to the previous entry and Ed25519 signature
//  12. Stamps the forensic_exports row with all produced paths, sizes,
//      hashes, fingerprints, and status='complete'
//
// If any step from (3) onward fails, the orchestrator stamps the row with
// status='failed' and error_message, removes any partial files it created,
// and rethrows. The pending row remains in the table for audit visibility.
//
// EXCLUSION-BY-CONSTRUCTION
//
// Every SELECT in this module explicitly lists its columns. SELECT * is
// forbidden because it could quietly pick up newly-added sensitive
// columns. The forbidden columns (per R3l plan):
//
//   - backup_signing_keys.private_key_encrypted             — never
//   - chain_signing_keys.private_key_encrypted              — never
//   - cloud_iac_signing_keys.private_key_encrypted          — never
//   - forensic_export_chain_signing_keys.private_key_encrypted — never
//   - kms_providers.credentials_encrypted                   — never
//   - sessions.refresh_token_hash                           — never
//   - any Tier-1-encrypted integration credentials          — never
//   - plaintext API keys / passwords / MFA secrets          — never
//   - audit_log.cef_message (already pre-formatted for SIEM streaming,
//     not appropriate for forensic export structure)        — never
//
// New table additions in future commits MUST update the relevant fetcher
// here to explicitly include any new safe columns. Forgetting to do so
// silently drops them from exports — which is the SAFE failure mode.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { spawnSync } = require('child_process');

const { sealTier1, openTier1 } = require('./tier1-seal');
const exportEncryption = require('./export-encryption');
const {
  canonicalSerialize,
  sliceSha256,
  buildManifestSkeleton,
  addSlice,
} = require('./audit-export-shared');
const os = require('os');
const storageRouting = require('./storage-routing');
const storageDestinations = require('./storage-destinations');
const dataResidency = require('./data-residency');
const destinationBase = require('./destination-adapter-base');

// ── Constants ─────────────────────────────────────────────────────────────

const DEFAULT_EXPORT_DIR = path.join(process.cwd(), 'data', 'forensic-exports');
const COSIGN_ENV_VAR = 'FIREALIVE_FORENSIC_USE_COSIGN';
const TAR_BLOCK_SIZE = 512;
const TAR_MAGIC = 'ustar\0';
const TAR_VERSION = '00';

// B5q: timeout for pushing a completed forensic export to its routed destination.
const FORENSIC_PUSH_TIMEOUT_MS = 5 * 60 * 1000;
// Revision v4: forensic push retry policy. Mirrors backup-push.js /
// archive-segment.js (MAX_ATTEMPTS = 5, same backoff). Both the primary and the
// secondary copy are retried (neither push gates the export, which succeeds on
// the local seal); each retry re-stages from the export's already-retained files.
const FORENSIC_MAX_ATTEMPTS = 5;
const FORENSIC_RETRY_DELAYS_SEC = [
  5 * 60,        // 5 min  -> attempt 2
  30 * 60,       // 30 min -> attempt 3
  2 * 60 * 60,   // 2 hr   -> attempt 4
  12 * 60 * 60,  // 12 hr  -> attempt 5
];
function forensicNextRetryAt(justCompletedAttempt) {
  if (justCompletedAttempt >= FORENSIC_MAX_ATTEMPTS) return null;
  const delaySec = FORENSIC_RETRY_DELAYS_SEC[justCompletedAttempt - 1];
  if (delaySec === undefined) return null;
  return new Date(Date.now() + delaySec * 1000).toISOString().slice(0, 19).replace('T', ' ');
}


// ── Lazy-loaded format serializer registry ────────────────────────────────
//
// Each entry maps a format identifier to a module that exposes:
//   { formatId, fileExtension, serialize(events) -> Buffer }
//
// The serializers ship in C23-C28. tryLoad() swallows MODULE_NOT_FOUND so
// this orchestrator can be installed in C22 (before C23-C28) without
// crashing at require-time. When an export requests a format whose
// serializer is not yet loaded, the orchestrator fails cleanly with a
// clear error message and stamps the row status='failed'.

const FORMAT_SERIALIZERS = {};

function tryLoad(formatId, modulePath) {
  try {
    FORMAT_SERIALIZERS[formatId] = require(modulePath);
  } catch (e) {
    if (e && e.code !== 'MODULE_NOT_FOUND') {
      // A real error (syntax, transitive failure) — surface it.
      throw e;
    }
    // Module not present yet; that's expected pre-C23-C28.
  }
}

tryLoad('sleuth-kit-bodyfile', './forensic-formats/sleuth-kit-bodyfile');
tryLoad('json-lines', './forensic-formats/json-lines');
tryLoad('plaso-l2t-csv', './forensic-formats/plaso-l2t-csv');
tryLoad('cef', './forensic-formats/cef');
tryLoad('evtx-xml', './forensic-formats/evtx-xml');
tryLoad('stix-21', './forensic-formats/stix-21');
tryLoad('dfxml', './forensic-formats/dfxml');
tryLoad('csv', './forensic-formats/csv');

// Test-only hook: register a synthetic serializer for unit testing C22
// before C23-C28 are written. Never used from routes or production paths.
function _registerFormatForTest(formatId, serializer) {
  FORMAT_SERIALIZERS[formatId] = serializer;
}

// ── Signing key management ────────────────────────────────────────────────
//
// Mirrors chain-signing-keys.js but against forensic_export_chain_signing_keys
// (different column names: active vs is_active, rotated_at vs rotated_out_at).
// The chain-signing-keys.js module is intentionally not reused so a future
// change to one signing family cannot silently affect the other.

function ensureActiveSigningKey(db) {
  const existing = db
    .prepare(
      'SELECT id, public_key, fingerprint FROM forensic_export_chain_signing_keys WHERE active = 1 LIMIT 1'
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
  const privateKeyEncrypted = sealTier1('forensic_export_chain_signing_keys.private_key_encrypted', { pem: privateKeyPem });

  // Fingerprint = SHA-256 of the raw SPKI bytes, hex
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const fingerprint = crypto.createHash('sha256').update(spkiDer).digest('hex');
  const id = 'fxsk-' + crypto.randomUUID();

  db.prepare(
    'INSERT INTO forensic_export_chain_signing_keys (id, public_key, private_key_encrypted, fingerprint, active) VALUES (?, ?, ?, ?, 1)'
  ).run(id, publicKeyPem, privateKeyEncrypted, fingerprint);

  return { id, publicKeyPem, fingerprint, isNewlyCreated: true };
}

function loadActivePrivateKey(db) {
  const row = db
    .prepare(
      'SELECT id, public_key, private_key_encrypted, fingerprint FROM forensic_export_chain_signing_keys WHERE active = 1 LIMIT 1'
    )
    .get();
  if (!row) {
    throw new Error('No active forensic export signing key found');
  }
  const { pem } = openTier1('forensic_export_chain_signing_keys.private_key_encrypted', row.private_key_encrypted);
  const privateKey = crypto.createPrivateKey({ key: pem, format: 'pem' });
  return {
    id: row.id,
    publicKeyPem: row.public_key,
    privateKey,
    fingerprint: row.fingerprint,
  };
}

function signEd25519(privateKey, bytes) {
  // Ed25519 in Node uses crypto.sign(null, message, privateKey) — algorithm
  // is implicit because the key type fixes it. Returns a Buffer; we hex-
  // encode for storage in manifest.signing and forensic_export_chain.
  return crypto.sign(null, bytes, privateKey).toString('hex');
}

// ── Multi-entry POSIX ustar tar builder ───────────────────────────────────
//
// Adapted from server/services/backup-archive.js but extended to handle
// multiple entries (slices + manifest.json + manifest.sig). Outputs a
// Buffer suitable for gzipping into a .tar.gz. Filenames must be <=100 ASCII
// chars (the ustar prefix field is unused).

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
  // entries: [{ name, payload: Buffer }]
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
  // End-of-archive: two zero blocks
  parts.push(Buffer.alloc(TAR_BLOCK_SIZE * 2));
  return Buffer.concat(parts);
}

// ── Data slice fetchers (column-omitted SELECT) ───────────────────────────
//
// Each fetcher hardcodes its column list and excludes sensitive columns.
// Time-window filtering is applied via prepared-statement parameters; null
// timeWindowStart / timeWindowEnd disables that side of the range. If the
// table does not exist (graceful degradation across deployments), the
// fetcher returns an empty array rather than throwing.

function tableExists(db, name) {
  const row = db
    .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(name);
  return !!row;
}

function fetchAuditLogSlice(db, opts) {
  if (!tableExists(db, 'audit_log')) return [];
  return db
    .prepare(
      // SELECT enumerates safe columns; cef_message is intentionally excluded
      // because it's a pre-formatted SIEM stream representation, not a
      // canonical record for forensic export. The structured columns are
      // sufficient for any downstream forensic tool.
      'SELECT id, timestamp, user_id, event_type, detail, ip_address FROM audit_log ' +
        'WHERE (? IS NULL OR timestamp >= ?) AND (? IS NULL OR timestamp <= ?) ' +
        '  AND (? IS NULL OR event_type = ?) ' +
        'ORDER BY id ASC'
    )
    .all(
      opts.timeWindowStart, opts.timeWindowStart,
      opts.timeWindowEnd, opts.timeWindowEnd,
      opts.eventTypeFilter, opts.eventTypeFilter
    );
}

function fetchBackupChainSlice(db, opts) {
  if (!tableExists(db, 'backup_chain')) return [];
  return db
    .prepare(
      // payload column included (it's already canonical JSON, useful for
      // forensic reconstruction of the backup state at chain-entry time).
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
  // No dedicated incident_records table in the current schema. CISM retros
  // and incident-related activity flow through audit_log with event_type
  // prefixes (e.g., 'INCIDENT_*', 'CISM_*'). Future commits may introduce
  // a dedicated table; until then this fetcher returns an empty slice so
  // the include_incident_records flag is a noop without breaking exports.
  void db; void opts;
  return [];
}

function fetchAuthenticationLogsSlice(db, opts) {
  if (!tableExists(db, 'auth_log')) return [];
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
  return db
    .prepare(
      // refresh_token_hash is intentionally excluded — a forensic export
      // must never carry token material that could be replayed.
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
  // opts: { exportId, actorUserId, eventType, manifestBytes, privateKey }
  // Hash chain: this_hash = SHA-256(prev_hash || canonicalize(payload)).
  // payload here = { event_type, export_ref, actor_user_id, manifest_sha256,
  //                  timestamp }. The manifest_sha256 ties the chain entry
  // to a specific manifest version, so any later tampering with the manifest
  // breaks the chain.
  const prevRow = db
    .prepare(
      'SELECT this_hash FROM forensic_export_chain ORDER BY id DESC LIMIT 1'
    )
    .get();
  const prevHash = prevRow ? prevRow.this_hash : null;

  const manifestSha256 = sliceSha256(opts.manifestBytes);
  const payload = {
    event_type: opts.eventType,
    export_ref: opts.exportId,
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
    'INSERT INTO forensic_export_chain (prev_hash, this_hash, signature, event_type, export_ref, actor_user_id) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(prevHash, thisHash, signature, opts.eventType, opts.exportId, opts.actorUserId);

  return { prevHash, thisHash, signature, manifestSha256 };
}

// ── Optional Cosign attestation ───────────────────────────────────────────

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
    // Per R3k pattern: 503-equivalent — opt-in but failed. Caller decides
    // whether to fail the export or proceed without the Cosign layer. The
    // orchestrator below proceeds and stamps cosign=null on the row.
    return { ok: false, error: result.error ? result.error.message : 'cosign exited ' + result.status };
  }
  return { ok: true, sigPath };
}

// Atomically replace a file with new bytes: write a sibling .enc.tmp and rename
// over the target (rename is atomic within a filesystem). Used to overwrite the
// transient plaintext archive with FA-ENC1 ciphertext, and to write the sealed
// manifest sidecar without leaving a partial file behind on a crash mid-write.
function atomicReplace(targetPath, buf) {
  const tmp = targetPath + '.enc.tmp';
  fs.writeFileSync(tmp, buf);
  fs.renameSync(tmp, targetPath);
}

// ── Main orchestrator ─────────────────────────────────────────────────────

/**
 * createForensicExport(db, request, opts?)
 *
 * Produces a forensic export package (async; seals artifacts at rest). Returns the completed
 * forensic_exports row id and the artifact paths.
 *
 * request: {
 *   requestedByUserId: string (required)
 *   rationale: string | null
 *   timeWindowStart, timeWindowEnd: ISO 8601 string | null
 *   eventTypeFilter: string | null
 *   outputFormats: string[] (1+ format ids; must all be registered)
 *   includeAuditLog, includeBackupChain, includeIncidentRecords,
 *     includeAuthenticationLogs, includeUserAccessLogs: boolean
 * }
 * opts: { exportDir? } (defaults to ./data/forensic-exports)
 *
 * Throws on validation failure or if any required serializer is missing.
 * Status transitions on the forensic_exports row:
 *   pending -> in_progress -> complete  (happy path)
 *   pending -> in_progress -> failed    (on error)
 */
// ── B5q: push a completed forensic export to its routed destination(s) ───────
//
// Additive and never fatal. The forensic archive + manifest are already FA-ENC1
// ciphertext at rest (B5g), so this pushes the already-encrypted files as-is
// (encrypt-before-push holds with no re-encryption; the .sig sidecars carry no
// confidential content). The same set of files is pushed to the primary and,
// when configured, the secondary destination -- both on this run. The local copy
// and decrypt-on-download path are unchanged; a push failure never fails the
// export.
//
// Revision v4: every push is recorded in forensic_export_pushes, and BOTH the
// primary and secondary are retried until they land -- neither push gates the
// export, so neither is "authoritative" the way an archive primary is. A failed
// copy is left for retryPendingExportPushes, which re-stages from the export's
// retained files (forensic_exports.archive_path / manifest_path / sig sidecars),
// so there is no separate pending directory. The residency gate is re-evaluated
// per attempt.

// Stage a list of existing source files into a unique temp dir and push them to
// one destination. Returns the adapter push result; throws on push failure (no
// files, adapter missing, or the push itself). The temp dir is always cleaned --
// the durable copies are the export's retained files.
async function stageAndPushExport(dest, exportId, files, manifestSha256, pathPrefix, logger) {
  const stagingParent = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-forensic-'));
  const sourceDir = path.join(stagingParent, exportId);
  try {
    fs.mkdirSync(sourceDir, { recursive: true });
    const staged = [];
    for (const src of files) {
      if (!src || !fs.existsSync(src)) continue;
      const name = path.basename(src);
      const target = path.join(sourceDir, name);
      fs.copyFileSync(src, target);
      const bytes = fs.readFileSync(target);
      staged.push({
        name: name,
        absolutePath: target,
        sizeBytes: bytes.length,
        sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
      });
    }
    if (staged.length === 0) {
      throw new Error('no files to push');
    }
    const adapter = destinationBase.getAdapter(dest.adapter);
    if (!adapter) {
      throw new Error('adapter \'' + dest.adapter + '\' not loaded in registry');
    }
    const context = {
      backupId: exportId,
      sourceDir: sourceDir,
      files: staged,
      manifestSha256: manifestSha256,
      createdAt: new Date().toISOString().replace('T', ' ').substring(0, 19),
      // Recorded routing hint; current adapters mirror the source dir name under
      // the destination's configured base path.
      pathPrefix: pathPrefix,
      destination: {
        id: dest.id,
        name: dest.name,
        adapter: dest.adapter,
        config: dest.config,
        credentials: dest.credentials,
        immutability_mode: dest.immutability_mode,
        retention_days: dest.retention_days,
      },
    };
    return await adapter.push(context, { logger: logger, timeoutMs: FORENSIC_PUSH_TIMEOUT_MS });
  } finally {
    try {
      fs.rmSync(stagingParent, { recursive: true, force: true });
    } catch (_cleanupErr) {
      /* best-effort: staged files are encrypted; leftover is non-sensitive */
    }
  }
}

/**
 * runExportPushAttempt(db, pushId, files, manifestSha256, options)
 *
 * One residency-gated attempt to push an export copy to its destination,
 * updating the forensic_export_pushes row. Used by pushForensicExport (initial,
 * for each role) and retryPendingExportPushes. Mirrors the backup-push attempt/
 * backoff model (FORENSIC_MAX_ATTEMPTS). On success the row is 'succeeded'; on
 * failure it is 'failed' with next_retry_at (null once attempts are exhausted).
 * files may be omitted on retry, in which case it is derived from the export's
 * retained columns. Returns { ok, reason?, destinationPath?, bytesPushed?,
 * immutabilityVerified? }.
 */
async function runExportPushAttempt(db, pushId, files, manifestSha256, options = {}) {
  const logger = options.logger || console;

  const row = db.prepare(
    'SELECT id, export_id, destination_id, role, status, attempt_count FROM forensic_export_pushes WHERE id = ?'
  ).get(pushId);
  if (!row) return { ok: false, reason: 'push row not found' };
  if (row.status === 'succeeded') return { ok: true };

  const attemptCount = row.attempt_count + 1;
  const fail = (message) => {
    db.prepare(
      "UPDATE forensic_export_pushes SET status='failed', attempt_count=?, error_message=?, next_retry_at=?, last_attempt_at=datetime('now') WHERE id=?"
    ).run(attemptCount, String(message).slice(0, 1000), forensicNextRetryAt(attemptCount), pushId);
    return { ok: false, reason: message };
  };

  const residency = dataResidency.evaluateDestination(db, 'forensic_export', row.destination_id);
  if (residency.blocked) {
    logger.warn('forensic export destination blocked by residency; copy deferred', {
      exportId: row.export_id, destinationRef: row.destination_id, role: row.role, reason: residency.reason,
    });
    return fail('blocked by residency: ' + (residency.reason || 'policy'));
  }

  const dest = storageDestinations.getDestinationWithCredentials(db, row.destination_id);
  if (!dest) return fail('destination not found');

  let fileList = (files && files.length) ? files : null;
  if (!fileList) {
    const ex = db.prepare(
      'SELECT archive_path, manifest_path, manifest_sig_path, cosign_signature_path FROM forensic_exports WHERE id = ?'
    ).get(row.export_id);
    fileList = ex ? [ex.archive_path, ex.manifest_path, ex.manifest_sig_path, ex.cosign_signature_path] : [];
  }

  let pathPrefix = null;
  try {
    const route = storageRouting.getRouteForType(db, 'forensic_export');
    pathPrefix = route && route.pathPrefix ? String(route.pathPrefix) : null;
  } catch (_routeErr) {
    pathPrefix = null;
  }

  db.prepare(
    "UPDATE forensic_export_pushes SET status='running', attempt_count=?, last_attempt_at=datetime('now') WHERE id=?"
  ).run(attemptCount, pushId);

  let result;
  try {
    result = await stageAndPushExport(dest, row.export_id, fileList, manifestSha256 || null, pathPrefix, logger);
  } catch (pushErr) {
    return fail(pushErr.message);
  }

  db.prepare(
    "UPDATE forensic_export_pushes SET status='succeeded', pushed_at=datetime('now'), size_pushed_bytes=?, destination_path=?, error_message=NULL, next_retry_at=NULL WHERE id=?"
  ).run(result.bytesPushed || 0, result.destinationPath || null, pushId);
  return {
    ok: true,
    destinationPath: result.destinationPath || null,
    bytesPushed: result.bytesPushed || 0,
    immutabilityVerified: result.immutabilityVerified || null,
  };
}

// Returns one of:
//   { attempted: false, configured: false }                       no route
//   { attempted: true, configured: true, pushed, destinationRef,
//     destinationPath, bytesPushed, immutabilityVerified,
//     primaryReplicated, secondaryDestinationRef, secondaryReplicated }
async function pushForensicExport(db, ctx) {
  const logger = ctx.logger || console;

  const route = storageRouting.getRouteForType(db, 'forensic_export');
  if (!route.configured || !route.destinations || route.destinations.length === 0) {
    return { attempted: false, configured: false };
  }
  const primaryView = route.destinations[0];
  const secondaryView = route.destinations[1] || null;

  const manifestSha256 = ctx.manifestBytes ? sliceSha256(ctx.manifestBytes) : null;
  const files = ctx.files || [];

  // Record a push row per destination (reusing an existing row if a prior call
  // left one) and attempt each now. A failed copy is left for the retry sweep,
  // sourced from the export's retained files.
  const attemptRole = async (view, role) => {
    if (!view) return { ok: false, skipped: true };
    let pushId;
    const existing = db.prepare(
      'SELECT id FROM forensic_export_pushes WHERE export_id = ? AND role = ?'
    ).get(ctx.exportId, role);
    if (existing) {
      pushId = existing.id;
    } else {
      pushId = db.prepare(
        "INSERT INTO forensic_export_pushes (export_id, destination_id, role, status) VALUES (?, ?, ?, 'queued')"
      ).run(ctx.exportId, view.id, role).lastInsertRowid;
    }
    return runExportPushAttempt(db, pushId, files, manifestSha256, { logger });
  };

  const primaryOutcome = await attemptRole(primaryView, 'primary');
  const secondaryOutcome = await attemptRole(secondaryView, 'secondary');

  return {
    attempted: true,
    configured: true,
    pushed: primaryOutcome.ok === true,
    destinationRef: primaryView.id,
    destinationPath: primaryOutcome.destinationPath || null,
    bytesPushed: primaryOutcome.bytesPushed || 0,
    immutabilityVerified: primaryOutcome.immutabilityVerified || null,
    primaryReplicated: primaryOutcome.ok === true,
    secondaryDestinationRef: secondaryView ? secondaryView.id : null,
    secondaryReplicated: secondaryOutcome.ok === true,
  };
}

/**
 * retryPendingExportPushes(db, options)
 *
 * The forensic replication sweep. Re-attempts every export push that has not yet
 * landed and is due (status 'queued' or 'failed', attempts not exhausted,
 * next_retry_at null or past), re-staging from the export's retained files.
 * Mirrors the backup_pushes retry cadence; intended to be called on a schedule.
 * A row that exhausts FORENSIC_MAX_ATTEMPTS stays 'failed' (next_retry_at null)
 * and is not picked up again. Returns { scanned, succeeded, failed }.
 */
async function retryPendingExportPushes(db, options = {}) {
  const logger = options.logger || console;
  const limit = options.limit || 100;

  const due = db.prepare(
    "SELECT id FROM forensic_export_pushes WHERE status IN ('queued','failed') AND attempt_count < ? AND (next_retry_at IS NULL OR next_retry_at <= datetime('now')) ORDER BY id ASC LIMIT ?"
  ).all(FORENSIC_MAX_ATTEMPTS, limit);

  let succeeded = 0;
  let failed = 0;
  for (const r of due) {
    try {
      const res = await runExportPushAttempt(db, r.id, null, null, { logger });
      if (res.ok) succeeded += 1;
      else failed += 1;
    } catch (sweepErr) {
      failed += 1;
      logger.error('forensic export retry sweep attempt crashed', { pushId: r.id, error: sweepErr.message });
    }
  }
  return { scanned: due.length, succeeded, failed };
}

async function createForensicExport(db, request, opts) {
  if (!db) throw new Error('createForensicExport: db required');
  if (!request || !request.requestedByUserId) {
    throw new Error('createForensicExport: requestedByUserId required');
  }
  const formats = Array.isArray(request.outputFormats) ? request.outputFormats : [];
  if (formats.length === 0) {
    throw new Error('createForensicExport: at least one output format required');
  }
  for (const f of formats) {
    if (!FORMAT_SERIALIZERS[f]) {
      throw new Error('createForensicExport: format not registered: ' + f);
    }
  }

  const exportDir = (opts && opts.exportDir) || DEFAULT_EXPORT_DIR;
  fs.mkdirSync(exportDir, { recursive: true });

  ensureActiveSigningKey(db);
  const exportId = 'fe-' + crypto.randomUUID();

  // Insert pending row up-front so even a crash leaves an audit trace.
  db.prepare(
    'INSERT INTO forensic_exports (id, requested_by_user_id, rationale, time_window_start, time_window_end, event_type_filter, output_formats, include_audit_log, include_backup_chain, include_incident_records, include_authentication_logs, include_user_access_logs, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \'pending\')'
  ).run(
    exportId,
    request.requestedByUserId,
    request.rationale || null,
    request.timeWindowStart || null,
    request.timeWindowEnd || null,
    request.eventTypeFilter || null,
    formats.join(','),
    request.includeAuditLog === false ? 0 : 1,
    request.includeBackupChain === false ? 0 : 1,
    request.includeIncidentRecords === false ? 0 : 1,
    request.includeAuthenticationLogs === false ? 0 : 1,
    request.includeUserAccessLogs === false ? 0 : 1
  );

  db.prepare("UPDATE forensic_exports SET status = 'in_progress' WHERE id = ?").run(exportId);

  let archivePath = null;
  let manifestPath = null;
  let manifestSigPath = null;
  try {
    // Step 1: collect data slices inside a read transaction for snapshot
    // consistency. The transaction is implicit via better-sqlite3's
    // db.transaction() wrapping; we use immediate BEGIN/COMMIT here so
    // the slice queries observe a single snapshot.
    db.exec('BEGIN');
    const slices = {};
    if (request.includeAuditLog !== false) slices.audit_log = fetchAuditLogSlice(db, request);
    if (request.includeBackupChain !== false) slices.backup_chain = fetchBackupChainSlice(db, request);
    if (request.includeIncidentRecords !== false) slices.incident_records = fetchIncidentRecordsSlice(db, request);
    if (request.includeAuthenticationLogs !== false) slices.authentication_logs = fetchAuthenticationLogsSlice(db, request);
    if (request.includeUserAccessLogs !== false) slices.user_access_logs = fetchUserAccessLogsSlice(db, request);
    db.exec('COMMIT');

    // Step 2: build manifest skeleton
    const manifest = buildManifestSkeleton({
      exportType: 'forensic',
      exportId,
      requestedByUserId: request.requestedByUserId,
      rationale: request.rationale,
      timeWindowStart: request.timeWindowStart,
      timeWindowEnd: request.timeWindowEnd,
      eventTypeFilter: request.eventTypeFilter,
      outputFormats: formats,
      includeAuditLog: request.includeAuditLog !== false,
      includeBackupChain: request.includeBackupChain !== false,
      includeIncidentRecords: request.includeIncidentRecords !== false,
      includeAuthenticationLogs: request.includeAuthenticationLogs !== false,
      includeUserAccessLogs: request.includeUserAccessLogs !== false,
    });

    // Step 3: serialize each requested format, hash, and add as a slice
    const tarEntries = [];
    for (const formatId of formats) {
      const serializer = FORMAT_SERIALIZERS[formatId];
      const sliceBytes = serializer.serialize(slices);
      if (!Buffer.isBuffer(sliceBytes)) {
        throw new Error('createForensicExport: serializer ' + formatId + ' did not return a Buffer');
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

    // Step 4: sign manifest with Ed25519
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

    // Step 5: build the tar.gz and hash the PLAINTEXT archive (the delivered
    // package and its archive_sha256 are unchanged from pre-B5g).
    const tarBytes = buildMultiEntryTar(tarEntries);
    const gzBytes = zlib.gzipSync(tarBytes);
    const archiveSha256 = sliceSha256(gzBytes);
    archivePath = path.join(exportDir, exportId + '.tar.gz');
    manifestPath = path.join(exportDir, exportId + '.manifest.json');
    manifestSigPath = path.join(exportDir, exportId + '.manifest.sig');

    // Step 6: Cosign the PLAINTEXT archive (optional), then seal the archive and
    // the manifest sidecar at rest under the configured KEK (FA-ENC1). The
    // Ed25519 and Cosign signatures are over the plaintext, so the downloaded
    // package stays byte-identical; only the on-disk bytes become ciphertext.
    // The plaintext archive is written transiently so cosign sign-blob can read
    // it, then overwritten in place by the sealed ciphertext. The detached
    // .cosign.sig and .manifest.sig are signatures (no confidential content) and
    // stay plaintext. Each fresh per-artifact data key is wrapped under the KEK
    // and embedded in its FA-ENC1 header; the raw key never persists.
    fs.writeFileSync(archivePath, gzBytes);
    const cosignResult = maybeInvokeCosign(archivePath);
    const cosignPath = cosignResult && cosignResult.ok ? cosignResult.sigPath : null;
    const sealedArchive = await exportEncryption.sealArtifact(gzBytes, {
      exportId: exportId,
      role: exportEncryption.ROLE_ARCHIVE,
      db: db,
    });
    atomicReplace(archivePath, sealedArchive.framed);
    const sealedManifest = await exportEncryption.sealArtifact(manifestBytes, {
      exportId: exportId,
      role: exportEncryption.ROLE_MANIFEST,
      db: db,
    });
    atomicReplace(manifestPath, sealedManifest.framed);
    fs.writeFileSync(manifestSigPath, Buffer.from(manifestSignature, 'hex'));
    const atRestScheme = sealedArchive.scheme;
    const atRestKekRef = sealedArchive.kekRef;

    // Step 7: append EXPORT_CREATED chain entry
    appendChainEntry(db, {
      exportId,
      actorUserId: request.requestedByUserId,
      eventType: 'EXPORT_CREATED',
      manifestBytes,
      privateKey: signingKey.privateKey,
    });

    // Step 8: stamp row with artifact paths, hashes, status='complete'
    db.prepare(
      "UPDATE forensic_exports SET status = 'complete', manifest_path = ?, archive_path = ?, manifest_sig_path = ?, manifest_signing_key_id = ?, manifest_signing_key_fingerprint = ?, cosign_signature_path = ?, archive_sha256 = ?, size_bytes = ?, at_rest_scheme = ?, at_rest_kek_ref = ?, completed_at = ? WHERE id = ?"
    ).run(
      manifestPath,
      archivePath,
      manifestSigPath,
      signingKey.id,
      signingKey.fingerprint,
      cosignPath,
      archiveSha256,
      gzBytes.length,
      atRestScheme,
      atRestKekRef,
      new Date().toISOString().replace('T', ' ').substring(0, 19),
      exportId
    );

    // Step 9 (B5q): push the sealed export to the configured forensic_export
    // destination if one is routed. Additive and best-effort -- the local copy
    // is already complete and is the primary delivery; a push failure never
    // fails or rolls back the export. The outcome is logged and returned.
    let pushOutcome = { attempted: false };
    const pushLog = (opts && opts.logger) || console;
    try {
      pushOutcome = await pushForensicExport(db, {
        exportId: exportId,
        files: [archivePath, manifestPath, manifestSigPath, cosignPath],
        manifestBytes: manifestBytes,
        logger: pushLog,
      });
      if (pushOutcome.pushed) {
        pushLog.info('forensic export pushed to destination', {
          exportId: exportId,
          destinationRef: pushOutcome.destinationRef,
          destinationPath: pushOutcome.destinationPath,
        });
      } else if (pushOutcome.attempted) {
        pushLog.warn('forensic export not pushed', {
          exportId: exportId,
          reason: pushOutcome.reason || (pushOutcome.blocked ? 'residency blocked' : 'unknown'),
        });
      }
    } catch (pushErr) {
      pushOutcome = {
        attempted: true,
        pushed: false,
        error: String(pushErr && pushErr.message ? pushErr.message : pushErr),
      };
      pushLog.error('forensic export push failed (non-fatal)', {
        exportId: exportId,
        error: pushOutcome.error,
      });
    }

    return {
      id: exportId,
      archivePath,
      manifestPath,
      manifestSigPath,
      cosignSignaturePath: cosignPath,
      archiveSha256,
      sizeBytes: gzBytes.length,
      signingKeyId: signingKey.id,
      signingKeyFingerprint: signingKey.fingerprint,
      push: pushOutcome,
    };
  } catch (err) {
    // Cleanup partial files, stamp failure, and rethrow.
    for (const p of [archivePath, manifestPath, manifestSigPath, archivePath && archivePath + '.enc.tmp', manifestPath && manifestPath + '.enc.tmp']) {
      if (p) try { fs.unlinkSync(p); } catch (_e) { /* ignore */ }
    }
    try { db.exec('ROLLBACK'); } catch (_e) { /* not in tx */ }
    db.prepare("UPDATE forensic_exports SET status = 'failed', error_message = ? WHERE id = ?")
      .run(String(err && err.message ? err.message : err), exportId);
    throw err;
  }
}

module.exports = {
  createForensicExport,
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
  // test-only
  pushForensicExport,
  retryPendingExportPushes,
  _registerFormatForTest,
};

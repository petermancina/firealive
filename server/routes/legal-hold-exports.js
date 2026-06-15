// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Legal Hold Export Routes (R3l C46)
//
// HTTP endpoints exposing the legal hold export workflow. Structurally
// parallel to routes/forensic-exports.js (C29) but with critical 2b
// differences:
//
//   - POST /:id/release REPLACES forensic's DELETE /:id. Legal holds are
//     never deleted from the system — they transition through a release
//     workflow that preserves the chain entry forever. The release
//     records WHO released (separate from creator) and WHY (rationale,
//     min 20 chars) and emits a HOLD_RELEASED chain entry that survives.
//
//   - SEPARATE-ACTOR enforcement at THREE layers for the release flow:
//
//       1. THIS LAYER (route handler): explicit comparison + 403 with
//          a clean error message. Catches the violation BEFORE any
//          DB write, giving the cleanest UX.
//       2. ORCHESTRATOR LAYER (releaseLegalHold in legal-hold-export.js):
//          re-checks before the UPDATE, throws SeparateActorViolation.
//          Defense-in-depth if a future route bypass exists.
//       3. SCHEMA LAYER (C37 CHECK constraint on legal_hold_exports):
//          the final backstop. Direct SQL INSERT/UPDATE that violates
//          the invariant fails with SQLite IntegrityError. Litigation-
//          admissible by way of being structurally impossible to bypass.
//
//   - caseId and rationale are REQUIRED at create. Forensic exports allow
//     ad-hoc IR creation; legal holds cannot — every hold must reference
//     a litigation/regulatory matter and document why. 400 if missing.
//
//   - rationale min length is 20 chars at both create and release. Very
//     short rationales are presumptive abuse markers in this workflow
//     (a hold or release with rationale="ok" is not a defensible record).
//
//   - custodianFilter optional at create. Restricts evidence to a
//     specific person's activity. Threaded through to the orchestrator
//     which applies it at slice fetch time.
//
//   - indefiniteRetention optional at create, defaults to true. Setting
//     to false explicitly opts out — used for time-bounded preservation
//     orders rather than indefinite litigation holds.
//
// ROLE GATES
//
//   POST /                        admin OR ciso (broader than forensic's
//                                 admin-only; legal counsel CISOs may
//                                 initiate holds)
//   GET /                         admin or ciso
//   GET /:id/download             admin or ciso (read-only access to the
//                                 archive — the separate-actor invariant
//                                 applies only to release, not to access)
//   GET /:id/manifest             admin or ciso
//   POST /:id/release             ciso ONLY (release is a stricter action
//                                 than create; only CISOs can sign off
//                                 on terminating a preservation mandate)
//   GET /chain                    admin or ciso (non-destructive read)
//
// CHAIN EVENT TYPES EMITTED FROM THIS LAYER
//
//   HOLD_CREATED, HOLD_COMPLETED  emitted by the orchestrator (C38)
//   HOLD_DOWNLOADED               emitted here via appendChainEntryFromRoute
//   HOLD_RELEASED                 emitted by releaseLegalHold (C38) which
//                                 this route invokes
//
// The chain table is append-only via SQLite trigger from C37; entries
// emitted from any layer become permanent records.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const router = require('express').Router();
const fs = require('fs');
const crypto = require('crypto');

const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const legalHoldExport = require('../services/legal-hold-export');
const exportEncryption = require('../services/export-encryption');
const { canonicalSerialize, sliceSha256 } = require('../services/audit-export-shared');
const { decryptConfig } = require('../services/encryption');

// ── Role gates ────────────────────────────────────────────────────────────

function requireJwtAdminOrCiso(req, res, next) {
  if (req.user && req.user.apiKey) {
    return res.status(403).json({ error: 'JWT authentication required on this endpoint' });
  }
  if (!req.user || (req.user.role !== 'admin' && req.user.role !== 'ciso')) {
    return res.status(403).json({ error: 'Admin or CISO role required' });
  }
  next();
}

function requireJwtCiso(req, res, next) {
  if (req.user && req.user.apiKey) {
    return res.status(403).json({ error: 'JWT authentication required on this endpoint' });
  }
  if (!req.user || req.user.role !== 'ciso') {
    return res.status(403).json({ error: 'CISO role required for this action' });
  }
  next();
}

// ── Helper: append a chain entry from the route layer ───────────────────
//
// Used by the download handler to record HOLD_DOWNLOADED. Release uses
// the orchestrator's appendChainEntry internally; create emits both
// HOLD_CREATED and HOLD_COMPLETED inside the orchestrator. Loads the
// active legal-hold signing key (distinct from forensic_export signing
// keys per C37), computes the linked hash, signs, and inserts the row.

function appendChainEntryFromRoute(db, opts) {
  const { holdId, actorUserId, eventType } = opts;
  const keyRow = db
    .prepare(
      'SELECT id, public_key, private_key_encrypted, fingerprint FROM legal_hold_chain_signing_keys WHERE active = 1 LIMIT 1'
    )
    .get();
  if (!keyRow) {
    throw new Error('No active legal hold signing key found');
  }
  const { pem } = decryptConfig(keyRow.private_key_encrypted);
  const privateKey = crypto.createPrivateKey({ key: pem, format: 'pem' });

  const prevRow = db
    .prepare('SELECT this_hash FROM legal_hold_chain ORDER BY id DESC LIMIT 1')
    .get();
  const prevHash = prevRow ? prevRow.this_hash : null;

  const payload = {
    event_type: eventType,
    hold_ref: holdId,
    actor_user_id: actorUserId,
    timestamp: new Date().toISOString(),
  };
  const payloadBytes = canonicalSerialize(payload);
  const linkInput = prevHash
    ? Buffer.concat([Buffer.from(prevHash, 'hex'), payloadBytes])
    : payloadBytes;
  const thisHash = crypto.createHash('sha256').update(linkInput).digest('hex');
  const signature = crypto
    .sign(null, Buffer.from(thisHash, 'hex'), privateKey)
    .toString('hex');

  db.prepare(
    'INSERT INTO legal_hold_chain (prev_hash, this_hash, signature, event_type, hold_ref, actor_user_id) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(prevHash, thisHash, signature, eventType, holdId, actorUserId);

  return { prevHash, thisHash, signature };
}

// ── POST / — create + run a legal hold ────────────────────────────────────

router.post('/', requireJwtAdminOrCiso, async (req, res) => {
  const {
    caseId,
    rationale,
    timeWindowStart,
    timeWindowEnd,
    custodianFilter,
    outputFormats,
    indefiniteRetention,
    includeAuditLog,
    includeBackupChain,
    includeIncidentRecords,
    includeAuthenticationLogs,
    includeUserAccessLogs,
  } = req.body || {};

  // Route-layer validation (defense-in-depth ahead of orchestrator validation
  // — gives 400 instead of 500 for shape errors).
  if (!caseId || typeof caseId !== 'string' || caseId.trim().length === 0) {
    return res.status(400).json({ error: 'caseId required — every legal hold must reference a litigation/regulatory matter' });
  }
  if (!rationale || typeof rationale !== 'string' || rationale.trim().length < 20) {
    return res.status(400).json({ error: 'rationale required, min 20 chars — every legal hold must document why' });
  }
  if (!Array.isArray(outputFormats) || outputFormats.length === 0) {
    return res.status(400).json({ error: 'outputFormats (non-empty array) required' });
  }
  if (custodianFilter != null && !Array.isArray(custodianFilter)) {
    return res.status(400).json({ error: 'custodianFilter must be an array of user_ids when provided' });
  }

  try {
    const db = getDb();
    const result = await legalHoldExport.createLegalHold(db, {
      requestedByUserId: req.user.id,
      caseId: caseId.trim(),
      rationale: rationale.trim(),
      timeWindowStart: timeWindowStart || null,
      timeWindowEnd: timeWindowEnd || null,
      custodianFilter: custodianFilter || null,
      outputFormats,
      indefiniteRetention: indefiniteRetention !== false,
      includeAuditLog: includeAuditLog !== false,
      includeBackupChain: includeBackupChain !== false,
      includeIncidentRecords: includeIncidentRecords !== false,
      includeAuthenticationLogs: includeAuthenticationLogs !== false,
      includeUserAccessLogs: includeUserAccessLogs !== false,
    });

    auditLog(
      req.user.id,
      'LEGAL_HOLD_CREATED',
      'id=' + result.id +
        ' case=' + result.caseId +
        ' formats=' + outputFormats.join(',') +
        ' size=' + result.sizeBytes +
        ' sha256=' + (result.archiveSha256 || '').slice(0, 16) +
        ' key=' + (result.signingKeyFingerprint || '').slice(0, 16) +
        ' indef=' + result.indefiniteRetention,
      req.ip
    );
    res.json(result);
  } catch (err) {
    logger.error('legal hold creation failed', { error: err.message, userId: req.user.id });
    auditLog(
      req.user.id,
      'LEGAL_HOLD_FAILED',
      'error=' + (err.message || '').slice(0, 200),
      req.ip
    );
    if (/format not registered/i.test(err.message)) {
      return res.status(400).json({ error: err.message });
    }
    if (/caseId required|rationale required|at least one output format required|requestedByUserId required/i.test(err.message)) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Legal hold creation failed', message: err.message });
  }
});

// ── GET / — list 100 most recent holds ────────────────────────────────────

router.get('/', requireJwtAdminOrCiso, (req, res) => {
  try {
    const db = getDb();
    const rows = db
      .prepare(
        'SELECT id, case_id, requested_by_user_id, requested_at, rationale,' +
          ' time_window_start, time_window_end, custodian_filter, output_formats,' +
          ' status, archive_sha256, size_bytes, completed_at, error_message,' +
          ' manifest_signing_key_fingerprint, cosign_signature_path,' +
          ' indefinite_retention, hold_released_at, hold_released_by_user_id,' +
          ' hold_release_rationale, downloaded_at, downloaded_by_user_id' +
          ' FROM legal_hold_exports' +
          ' ORDER BY requested_at DESC' +
          ' LIMIT 100'
      )
      .all();
    auditLog(req.user.id, 'LEGAL_HOLD_LISTED', 'count=' + rows.length, req.ip);
    res.json({ holds: rows });
  } catch (err) {
    logger.error('legal hold list failed', { error: err.message });
    res.status(500).json({ error: 'list failed', message: err.message });
  }
});

// ── GET /:id/download — stream the tar.gz archive ─────────────────────────

router.get('/:id/download', requireJwtAdminOrCiso, async (req, res) => {
  try {
    const db = getDb();
    const row = db
      .prepare(
        'SELECT id, case_id, archive_path, size_bytes, status FROM legal_hold_exports WHERE id = ?'
      )
      .get(req.params.id);
    if (!row) {
      return res.status(404).json({ error: 'legal hold not found' });
    }
    if (!row.archive_path || !fs.existsSync(row.archive_path)) {
      return res.status(404).json({ error: 'archive file not found on disk' });
    }
    if (row.status !== 'active' && row.status !== 'released') {
      return res.status(409).json({ error: 'hold not in downloadable state (current status: ' + row.status + ')' });
    }

    // Update downloaded_at + downloaded_by on every download. The schema
    // captures the LAST download; a chain of HOLD_DOWNLOADED events
    // captures the full access history.
    db.prepare(
      'UPDATE legal_hold_exports SET downloaded_at = ?, downloaded_by_user_id = ? WHERE id = ?'
    ).run(new Date().toISOString().replace('T', ' ').substring(0, 19), req.user.id, row.id);

    // Append HOLD_DOWNLOADED chain entry — permanent access record.
    appendChainEntryFromRoute(db, {
      holdId: row.id,
      actorUserId: req.user.id,
      eventType: 'HOLD_DOWNLOADED',
    });

    auditLog(
      req.user.id,
      'LEGAL_HOLD_DOWNLOADED',
      'id=' + row.id + ' case=' + row.case_id + ' size=' + row.size_bytes,
      req.ip
    );

    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', 'attachment; filename="' + row.id + '.tar.gz"');
    if (row.size_bytes) res.setHeader('Content-Length', String(row.size_bytes));
    // Decrypt-on-download: if the on-disk artifact is sealed (FA-ENC1), unwrap
    // and decrypt it (buffered: GCM verifies the whole tag before any bytes are
    // sent), then deliver the standard plaintext tar.gz (its length equals the
    // size_bytes already set above). Legacy plaintext archives (pre-B5g) stream
    // as before. The delivered bytes are byte-identical either way.
    const magicFd = fs.openSync(row.archive_path, 'r');
    const magicProbe = Buffer.alloc(6);
    const magicRead = fs.readSync(magicFd, magicProbe, 0, 6, 0);
    fs.closeSync(magicFd);
    if (magicRead === 6 && exportEncryption.isFramed(magicProbe)) {
      const plaintext = await exportEncryption.openArtifact(fs.readFileSync(row.archive_path), { db });
      res.send(plaintext);
    } else {
      fs.createReadStream(row.archive_path).pipe(res);
    }
  } catch (err) {
    logger.error('legal hold download failed', { error: err.message });
    if (!res.headersSent) {
      res.status(500).json({ error: 'download failed', message: err.message });
    }
  }
});

// ── GET /:id/manifest — return manifest.json contents ─────────────────────

router.get('/:id/manifest', requireJwtAdminOrCiso, async (req, res) => {
  try {
    const db = getDb();
    const row = db
      .prepare('SELECT id, case_id, manifest_path FROM legal_hold_exports WHERE id = ?')
      .get(req.params.id);
    if (!row) {
      return res.status(404).json({ error: 'legal hold not found' });
    }
    if (!row.manifest_path || !fs.existsSync(row.manifest_path)) {
      return res.status(404).json({ error: 'manifest file not found on disk' });
    }
    const manifestRaw = fs.readFileSync(row.manifest_path);
    auditLog(req.user.id, 'LEGAL_HOLD_MANIFEST_FETCHED', 'id=' + row.id + ' case=' + row.case_id, req.ip);
    res.setHeader('Content-Type', 'application/json');
    // The manifest sidecar is sealed at rest (it carries case_id, custodian
    // filter, and retention metadata). Decrypt it for the authenticated reader;
    // legacy plaintext manifests (pre-B5g) are sent as is.
    if (exportEncryption.isFramed(manifestRaw)) {
      const plaintext = await exportEncryption.openArtifact(manifestRaw, { db });
      res.send(plaintext);
    } else {
      res.send(manifestRaw);
    }
  } catch (err) {
    logger.error('legal hold manifest fetch failed', { error: err.message });
    res.status(500).json({ error: 'manifest fetch failed', message: err.message });
  }
});

// ── POST /:id/release — separate-actor release of a legal hold ────────────
//
// Triple-layer separate-actor enforcement:
//   1. HERE: explicit comparison + 403 BEFORE invoking the orchestrator.
//      Cleanest UX path — caught immediately with a precise error.
//   2. ORCHESTRATOR: releaseLegalHold throws SeparateActorViolation if
//      it sees the same actor (defense in depth if a route bypass exists).
//   3. SCHEMA: SQLite CHECK constraint on legal_hold_exports refuses any
//      UPDATE that sets hold_released_by_user_id == requested_by_user_id.

router.post('/:id/release', requireJwtCiso, (req, res) => {
  const { rationale } = req.body || {};

  if (!rationale || typeof rationale !== 'string' || rationale.trim().length < 20) {
    return res.status(400).json({ error: 'rationale required, min 20 chars — every release must document why' });
  }

  try {
    const db = getDb();
    const row = db
      .prepare('SELECT id, case_id, requested_by_user_id, status FROM legal_hold_exports WHERE id = ?')
      .get(req.params.id);
    if (!row) {
      auditLog(req.user.id, 'LEGAL_HOLD_RELEASE_DENIED', 'id=' + req.params.id + ' reason=not_found', req.ip);
      return res.status(404).json({ error: 'legal hold not found' });
    }
    if (row.status !== 'active') {
      auditLog(req.user.id, 'LEGAL_HOLD_RELEASE_DENIED', 'id=' + row.id + ' reason=not_active status=' + row.status, req.ip);
      return res.status(409).json({ error: 'hold not active (current status: ' + row.status + ')' });
    }

    // Layer-1 separate-actor check. The orchestrator (layer-2) and schema
    // (layer-3) re-check. All three must agree.
    if (row.requested_by_user_id === req.user.id) {
      auditLog(
        req.user.id,
        'LEGAL_HOLD_RELEASE_DENIED',
        'id=' + row.id + ' case=' + row.case_id + ' reason=same_actor',
        req.ip
      );
      return res.status(403).json({
        error: 'separate-actor violation: the CISO performing the release must be a different user from the original requester',
        requested_by_user_id: row.requested_by_user_id,
        releaser_user_id: req.user.id,
      });
    }

    // Delegate to the orchestrator. It performs:
    //   - status check (active)
    //   - separate-actor re-check (throws SeparateActorViolation)
    //   - UPDATE inside a transaction
    //   - HOLD_RELEASED chain entry append
    //   - hold_released_at / hold_released_by_user_id / hold_release_rationale stamping
    const result = legalHoldExport.releaseLegalHold(
      db,
      row.id,
      req.user.id,
      rationale.trim()
    );

    auditLog(
      req.user.id,
      'LEGAL_HOLD_RELEASED',
      'id=' + row.id +
        ' case=' + row.case_id +
        ' requester=' + row.requested_by_user_id +
        ' releaser=' + req.user.id,
      req.ip
    );
    res.json(result);
  } catch (err) {
    // SeparateActorViolation from the orchestrator → 403 (shouldn't happen
    // since layer-1 already caught it, but defense-in-depth).
    if (err.name === 'SeparateActorViolation') {
      auditLog(
        req.user.id,
        'LEGAL_HOLD_RELEASE_DENIED',
        'id=' + req.params.id + ' reason=same_actor_orchestrator',
        req.ip
      );
      return res.status(403).json({ error: err.message });
    }
    // Schema CHECK violation from SQLite → 403 (final backstop reached).
    if (err.code === 'SQLITE_CONSTRAINT_CHECK' || /CHECK constraint failed/i.test(err.message || '')) {
      auditLog(
        req.user.id,
        'LEGAL_HOLD_RELEASE_DENIED',
        'id=' + req.params.id + ' reason=schema_check',
        req.ip
      );
      return res.status(403).json({ error: 'separate-actor violation: schema CHECK constraint refused the UPDATE' });
    }
    if (err.statusCode) {
      return res.status(err.statusCode).json({ error: err.message });
    }
    logger.error('legal hold release failed', { error: err.message, userId: req.user.id, id: req.params.id });
    res.status(500).json({ error: 'release failed', message: err.message });
  }
});

// ── GET /chain — chain inspection for verifiers ───────────────────────────
//
// Returns the legal_hold_chain table (capped at 1000 most recent entries
// for response-size safety). External verifiers consume this endpoint to:
//
//   1. Reconstruct the hash chain (verify each this_hash = SHA-256
//      (prev_hash || canonical(payload)))
//   2. Verify each Ed25519 signature against the active public key
//      (or a historical key referenced in the manifest)
//   3. Confirm HOLD_CREATED / HOLD_COMPLETED / HOLD_DOWNLOADED /
//      HOLD_RELEASED entries form an admissible audit trail
//
// Non-destructive read — admin and ciso both allowed.

router.get('/chain', requireJwtAdminOrCiso, (req, res) => {
  try {
    const db = getDb();
    const rows = db
      .prepare(
        'SELECT id, prev_hash, this_hash, signature, event_type, hold_ref, actor_user_id, created_at' +
          ' FROM legal_hold_chain ORDER BY id DESC LIMIT 1000'
      )
      .all();
    // Active signing key info so verifiers can pull the public key out
    // of the manifest's signing.key_id reference and validate signatures.
    const activeKey = db
      .prepare(
        'SELECT id, public_key, fingerprint, created_at FROM legal_hold_chain_signing_keys WHERE active = 1 LIMIT 1'
      )
      .get();
    auditLog(req.user.id, 'LEGAL_HOLD_CHAIN_INSPECTED', 'rows=' + rows.length, req.ip);
    res.json({ chain: rows, active_signing_key: activeKey || null });
  } catch (err) {
    logger.error('legal hold chain fetch failed', { error: err.message });
    res.status(500).json({ error: 'chain fetch failed', message: err.message });
  }
});

module.exports = router;

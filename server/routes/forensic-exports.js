// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Forensic Exports Routes (R3l C29a)
//
// HTTP surface for the forensic export orchestrator (R3l C22). Six
// endpoints expose the create/list/download/manifest/delete/chain
// lifecycle to MC frontend clients and external verifiers:
//
//   POST   /api/forensic-exports                create + run the export
//                                                synchronously, returning
//                                                the completed row metadata
//   GET    /api/forensic-exports                list 100 most recent rows
//   GET    /api/forensic-exports/:id/download   stream the tar.gz archive
//   GET    /api/forensic-exports/:id/manifest   stream the manifest.json
//   DELETE /api/forensic-exports/:id            separate-actor delete:
//                                                requires ciso role AND
//                                                actor != requested_by
//                                                user_id; appends an
//                                                EXPORT_DELETED chain entry
//   GET    /api/forensic-exports/chain          chain inspection for
//                                                external verifiers
//
// AUTH
// ====
//
// Mounted in server/index.js (C29b) with:
//
//   app.use('/api/forensic-exports', authMiddleware(['admin','ciso']), require('./routes/forensic-exports'));
//
// authMiddleware admits both roles so the DELETE endpoint can run with
// ciso JWT while the rest run with admin JWT. Per-handler logic enforces
// the per-endpoint role:
//
//   requireAdminOrCiso: admits either role for GETs and listing
//   requireJwtAdmin:    POST + download + manifest paths use admin only
//   requireJwtCiso:     DELETE requires ciso AND actor != creator
//
// API keys are rejected on every endpoint (forensic exports are an
// operator-driven UX with no automated webhook or polling pattern; matches
// the cloud-iac routes posture from R3k C34).
//
// SEPARATE-ACTOR INVARIANT FOR DELETE
// ====================================
//
// SOC-grade compliance frameworks (ISO 27001 A.9.4.5, NIST 800-53 AC-5,
// SOX-style separation-of-duties) require that destructive actions on
// audit records be performed by a different actor than the one who
// created the record. For forensic exports specifically:
//
//   - admin creates the export (POST)
//   - ciso (a different person) deletes the export (DELETE)
//
// Enforced in the DELETE handler by comparing req.user.id against the
// row's requested_by_user_id. The handler rejects with 403 if they
// match, even if the user holds a ciso role. This is application-layer
// enforcement; the DB schema documents the requirement in its comments
// but does not enforce via trigger (a trigger would need to know which
// actor is performing the DELETE, which SQLite triggers cannot
// inspect from the connection context).
//
// AUDIT TRAIL
// ===========
//
// Every endpoint calls auditLog(userId, eventType, detail, ip) at success
// and at failure paths. Event types:
//
//   FORENSIC_EXPORT_CREATED       successful POST
//   FORENSIC_EXPORT_FAILED        POST that threw
//   FORENSIC_EXPORT_LISTED        list endpoint (informational; cheap)
//   FORENSIC_EXPORT_DOWNLOADED    successful tar.gz download
//   FORENSIC_EXPORT_MANIFEST_READ successful manifest fetch
//   FORENSIC_EXPORT_DELETE_DENIED separate-actor violation OR row not
//                                  found OR archive missing
//   FORENSIC_EXPORT_DELETED       successful delete
//   FORENSIC_EXPORT_CHAIN_VIEWED  chain inspection
//
// CHAIN INTEGRATION
// =================
//
// Two chain mutations are made directly by these routes (the rest are
// inside the C22 orchestrator):
//
//   POST   appends EXPORT_CREATED via the orchestrator's own call to
//          appendChainEntry. No additional chain mutation here.
//   GET /:id/download appends EXPORT_DOWNLOADED with the downloading
//          user_id as actor — gives the verifier a record of who
//          retrieved the artifact.
//   DELETE appends EXPORT_DELETED with the ciso user_id as actor.
//
// The chain append helper here loads the active forensic signing key,
// computes the linked hash, and signs. Mirrors C22's appendChainEntry
// but in the route layer so the route can sign new entries without
// re-running the full orchestrator.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const router = require('express').Router();
const fs = require('fs');
const crypto = require('crypto');

const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const forensicExport = require('../services/forensic-export');
const exportEncryption = require('../services/export-encryption');
const { canonicalSerialize, sliceSha256 } = require('../services/audit-export-shared');
const { openTier1 } = require('../services/tier1-seal');

// ── Per-handler auth gates ──────────────────────────────────────────────

function requireJwtAdmin(req, res, next) {
  if (req.user && req.user.apiKey) {
    return res.status(403).json({ error: 'JWT authentication required on this endpoint' });
  }
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin role required' });
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

function requireAdminOrCiso(req, res, next) {
  if (req.user && req.user.apiKey) {
    return res.status(403).json({ error: 'JWT authentication required on this endpoint' });
  }
  if (!req.user || (req.user.role !== 'admin' && req.user.role !== 'ciso')) {
    return res.status(403).json({ error: 'Admin or CISO role required' });
  }
  next();
}

// ── Helper: append a chain entry from the route layer ──────────────────
//
// Used by DELETE and download handlers (POST goes through the orchestrator
// which appends EXPORT_CREATED internally). Loads the active forensic
// signing key, computes the linked hash, signs, and inserts the row. The
// chain table's append-only trigger prevents tampering after the insert.

function appendChainEntryFromRoute(db, opts) {
  const { exportId, actorUserId, eventType } = opts;
  // Load active signing key — mirrors forensic-export.js loadActivePrivateKey
  const keyRow = db
    .prepare(
      'SELECT id, public_key, private_key_encrypted, fingerprint FROM forensic_export_chain_signing_keys WHERE active = 1 LIMIT 1'
    )
    .get();
  if (!keyRow) {
    throw new Error('No active forensic export signing key found');
  }
  const { pem } = openTier1('forensic_export_chain_signing_keys.private_key_encrypted', keyRow.private_key_encrypted);
  const privateKey = crypto.createPrivateKey({ key: pem, format: 'pem' });

  const prevRow = db
    .prepare(
      'SELECT this_hash FROM forensic_export_chain ORDER BY id DESC LIMIT 1'
    )
    .get();
  const prevHash = prevRow ? prevRow.this_hash : null;

  const payload = {
    event_type: eventType,
    export_ref: exportId,
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
    'INSERT INTO forensic_export_chain (prev_hash, this_hash, signature, event_type, export_ref, actor_user_id) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(prevHash, thisHash, signature, eventType, exportId, actorUserId);

  return { prevHash, thisHash, signature };
}

// ── POST / — create + run ──────────────────────────────────────────────

router.post('/', requireJwtAdmin, async (req, res) => {
  const {
    rationale,
    timeWindowStart,
    timeWindowEnd,
    eventTypeFilter,
    outputFormats,
    includeAuditLog,
    includeBackupChain,
    includeIncidentRecords,
    includeAuthenticationLogs,
    includeUserAccessLogs,
  } = req.body || {};

  if (!Array.isArray(outputFormats) || outputFormats.length === 0) {
    return res.status(400).json({ error: 'outputFormats (non-empty array) required' });
  }

  try {
    const db = getDb();
    const result = await forensicExport.createForensicExport(db, {
      requestedByUserId: req.user.id,
      rationale: rationale || null,
      timeWindowStart: timeWindowStart || null,
      timeWindowEnd: timeWindowEnd || null,
      eventTypeFilter: eventTypeFilter || null,
      outputFormats,
      includeAuditLog: includeAuditLog !== false,
      includeBackupChain: includeBackupChain !== false,
      includeIncidentRecords: includeIncidentRecords !== false,
      includeAuthenticationLogs: includeAuthenticationLogs !== false,
      includeUserAccessLogs: includeUserAccessLogs !== false,
    });

    auditLog(
      req.user.id,
      'FORENSIC_EXPORT_CREATED',
      'id=' + result.id +
        ' formats=' + outputFormats.join(',') +
        ' size=' + result.sizeBytes +
        ' sha256=' + (result.archiveSha256 || '').slice(0, 16) +
        ' key=' + (result.signingKeyFingerprint || '').slice(0, 16),
      req.ip
    );
    res.json(result);
  } catch (err) {
    logger.error('forensic export creation failed', { error: err.message, userId: req.user.id });
    auditLog(
      req.user.id,
      'FORENSIC_EXPORT_FAILED',
      'error=' + (err.message || '').slice(0, 200),
      req.ip
    );
    if (/format not registered/i.test(err.message)) {
      return res.status(400).json({ error: err.message });
    }
    if (/at least one output format required|requestedByUserId required/i.test(err.message)) {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Forensic export creation failed', message: err.message });
  }
});

// ── GET / — list 100 most recent ───────────────────────────────────────

router.get('/', requireAdminOrCiso, (req, res) => {
  try {
    const db = getDb();
    const rows = db
      .prepare(
        'SELECT id, requested_by_user_id, requested_at, rationale,' +
          ' time_window_start, time_window_end, event_type_filter, output_formats,' +
          ' status, archive_sha256, size_bytes, completed_at, error_message,' +
          ' manifest_signing_key_fingerprint, cosign_signature_path,' +
          ' downloaded_at, downloaded_by_user_id' +
          ' FROM forensic_exports' +
          ' ORDER BY requested_at DESC' +
          ' LIMIT 100'
      )
      .all();
    auditLog(req.user.id, 'FORENSIC_EXPORT_LISTED', 'count=' + rows.length, req.ip);
    res.json({ exports: rows });
  } catch (err) {
    logger.error('forensic export list failed', { error: err.message });
    res.status(500).json({ error: 'list failed', message: err.message });
  }
});

// ── GET /:id/download — stream the tar.gz ──────────────────────────────

router.get('/:id/download', requireJwtAdmin, async (req, res) => {
  try {
    const db = getDb();
    const row = db
      .prepare(
        'SELECT id, archive_path, requested_by_user_id, status FROM forensic_exports WHERE id = ?'
      )
      .get(req.params.id);
    if (!row) {
      auditLog(req.user.id, 'FORENSIC_EXPORT_DOWNLOAD_DENIED', 'id=' + req.params.id + ' reason=not_found', req.ip);
      return res.status(404).json({ error: 'forensic export not found' });
    }
    if (row.status !== 'complete') {
      auditLog(req.user.id, 'FORENSIC_EXPORT_DOWNLOAD_DENIED', 'id=' + req.params.id + ' reason=status_' + row.status, req.ip);
      return res.status(409).json({ error: 'export not complete', status: row.status });
    }
    if (!row.archive_path || !fs.existsSync(row.archive_path)) {
      auditLog(req.user.id, 'FORENSIC_EXPORT_DOWNLOAD_DENIED', 'id=' + req.params.id + ' reason=archive_missing', req.ip);
      return res.status(410).json({ error: 'archive no longer on disk' });
    }

    // Stamp downloaded_at + downloaded_by + append chain entry. Order: chain
    // first (so the chain reflects the action before we send the body — if
    // the client connection drops mid-stream, the chain still records the
    // intent).
    appendChainEntryFromRoute(db, {
      exportId: row.id,
      actorUserId: req.user.id,
      eventType: 'EXPORT_DOWNLOADED',
    });
    db.prepare(
      'UPDATE forensic_exports SET downloaded_at = datetime(\'now\'), downloaded_by_user_id = ? WHERE id = ?'
    ).run(req.user.id, row.id);

    auditLog(
      req.user.id,
      'FORENSIC_EXPORT_DOWNLOADED',
      'id=' + row.id,
      req.ip
    );
    const downloadName = 'firealive-forensic-' + row.id + '.tar.gz';
    res.setHeader('Content-Disposition', 'attachment; filename="' + downloadName + '"');
    res.setHeader('Content-Type', 'application/gzip');
    // Decrypt-on-download: if the on-disk artifact is sealed (FA-ENC1), unwrap
    // and decrypt it (buffered: GCM verifies the whole tag before any bytes are
    // sent), then deliver the standard plaintext tar.gz. Legacy plaintext
    // archives (pre-B5g, not yet re-sealed by the boot migration) stream as
    // before. The delivered bytes are byte-identical either way.
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
    logger.error('forensic export download failed', { error: err.message });
    res.status(500).json({ error: 'download failed', message: err.message });
  }
});

// ── GET /:id/manifest — fetch the manifest JSON ────────────────────────

router.get('/:id/manifest', requireJwtAdmin, async (req, res) => {
  try {
    const db = getDb();
    const row = db
      .prepare('SELECT id, manifest_path, status FROM forensic_exports WHERE id = ?')
      .get(req.params.id);
    if (!row) {
      return res.status(404).json({ error: 'forensic export not found' });
    }
    if (row.status !== 'complete') {
      return res.status(409).json({ error: 'export not complete', status: row.status });
    }
    if (!row.manifest_path || !fs.existsSync(row.manifest_path)) {
      return res.status(410).json({ error: 'manifest no longer on disk' });
    }

    auditLog(req.user.id, 'FORENSIC_EXPORT_MANIFEST_READ', 'id=' + row.id, req.ip);
    res.setHeader('Content-Type', 'application/json');
    // The manifest sidecar is sealed at rest (it carries scope metadata such as
    // the slice hashes, counts, and time window). Decrypt it for the
    // authenticated reader; legacy plaintext manifests (pre-B5g) are sent as is.
    const manifestRaw = fs.readFileSync(row.manifest_path);
    if (exportEncryption.isFramed(manifestRaw)) {
      const plaintext = await exportEncryption.openArtifact(manifestRaw, { db });
      res.send(plaintext);
    } else {
      res.send(manifestRaw);
    }
  } catch (err) {
    logger.error('forensic export manifest fetch failed', { error: err.message });
    res.status(500).json({ error: 'manifest fetch failed', message: err.message });
  }
});

// ── DELETE /:id — separate-actor delete ────────────────────────────────

router.delete('/:id', requireJwtCiso, (req, res) => {
  try {
    const db = getDb();
    const row = db
      .prepare('SELECT id, requested_by_user_id, archive_path, manifest_path, manifest_sig_path FROM forensic_exports WHERE id = ?')
      .get(req.params.id);
    if (!row) {
      auditLog(req.user.id, 'FORENSIC_EXPORT_DELETE_DENIED', 'id=' + req.params.id + ' reason=not_found', req.ip);
      return res.status(404).json({ error: 'forensic export not found' });
    }

    // SEPARATE-ACTOR enforcement: the CISO performing the DELETE must
    // NOT be the same user who requested the export. This is the
    // application-layer separation-of-duties check required by ISO
    // 27001 A.9.4.5 / NIST 800-53 AC-5 / SOX-style controls.
    if (row.requested_by_user_id === req.user.id) {
      auditLog(req.user.id, 'FORENSIC_EXPORT_DELETE_DENIED', 'id=' + row.id + ' reason=same_actor', req.ip);
      return res.status(403).json({
        error: 'separate-actor violation: the actor performing DELETE must be a different person from the requesting admin',
      });
    }

    // Append chain entry BEFORE removing the row — keeps the chain
    // record of the deletion even if the row removal itself partially
    // fails. The chain table is append-only via DB trigger so this
    // entry cannot be unwound.
    appendChainEntryFromRoute(db, {
      exportId: row.id,
      actorUserId: req.user.id,
      eventType: 'EXPORT_DELETED',
    });

    // Best-effort removal of on-disk artifacts. We do NOT fail the
    // DELETE if files are already gone — the row was likely manually
    // cleaned up via filesystem maintenance.
    for (const p of [row.archive_path, row.manifest_path, row.manifest_sig_path]) {
      if (p) {
        try { fs.unlinkSync(p); } catch (_e) { /* ignore */ }
      }
    }
    // Remove the row itself.
    db.prepare('DELETE FROM forensic_exports WHERE id = ?').run(row.id);

    auditLog(
      req.user.id,
      'FORENSIC_EXPORT_DELETED',
      'id=' + row.id + ' creator=' + row.requested_by_user_id,
      req.ip
    );
    res.json({ deleted: true, id: row.id });
  } catch (err) {
    logger.error('forensic export delete failed', { error: err.message });
    res.status(500).json({ error: 'delete failed', message: err.message });
  }
});

// ── GET /chain — chain inspection for verifiers ────────────────────────
//
// Returns the full forensic_export_chain table (capped at 1000 most
// recent entries for response-size safety). External verifiers consume
// this endpoint to:
//
//   1. Reconstruct the hash chain (verify each this_hash = SHA-256
//      (prev_hash || canonical(payload)))
//   2. Verify each Ed25519 signature against the active public key
//      (or a historical key referenced in the manifest)
//   3. Detect gaps (missing seq numbers indicate tampering)
//
// Allowed for both admin and ciso roles — verification is a
// non-destructive read operation.

router.get('/chain', requireAdminOrCiso, (req, res) => {
  try {
    const db = getDb();
    const rows = db
      .prepare(
        'SELECT id, prev_hash, this_hash, signature, event_type, export_ref,' +
          ' actor_user_id, created_at' +
          ' FROM forensic_export_chain' +
          ' ORDER BY id DESC' +
          ' LIMIT 1000'
      )
      .all();
    // Include the active signing key public-PEM so verifiers can check
    // signatures without an extra round-trip. The verifier still has to
    // map each chain entry to the key active when it was signed; for
    // most deployments there's only one historical key.
    const keyRow = db
      .prepare('SELECT id, public_key, fingerprint FROM forensic_export_chain_signing_keys WHERE active = 1 LIMIT 1')
      .get();

    auditLog(req.user.id, 'FORENSIC_EXPORT_CHAIN_VIEWED', 'count=' + rows.length, req.ip);
    res.json({
      chain: rows,
      active_signing_key: keyRow
        ? {
            id: keyRow.id,
            public_key_pem: keyRow.public_key,
            fingerprint: keyRow.fingerprint,
          }
        : null,
    });
  } catch (err) {
    logger.error('forensic export chain inspection failed', { error: err.message });
    res.status(500).json({ error: 'chain inspection failed', message: err.message });
  }
});

module.exports = router;

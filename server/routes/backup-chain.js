// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Chain Inspection Routes (admin-only)
//
// READ-ONLY admin endpoints for inspecting the cryptographic chain of
// custody. The chain itself is append-only (enforced by SQLite triggers
// in db/init.js) so no PUT/PATCH/DELETE could ever succeed via this
// route file -- all endpoints here are GET.
//
// Mounted at /api/backup-chain in server/index.js with
// authMiddleware(['admin']). The route file does NOT apply auth itself
// -- same pattern as the other route files.
//
// ENDPOINTS
//
//   GET /api/backup-chain
//     List entries with cursor pagination on id descending.
//     Query params: ?limit=N (default 50, max 200), ?before=ID
//     Returns: { entries: [...], nextBefore: ID|null }
//     Signatures excluded from list responses (large; detail view has them).
//
//   GET /api/backup-chain/stats
//     Returns totals + head + last verify info.
//
//   GET /api/backup-chain/verify
//     Runs verifyFullChain -- walks every entry, checks linkage +
//     hash recomputation + Ed25519 signature verification. Synchronous;
//     can take several seconds on large chains. For chains exceeding
//     ~1M entries (not realistic in practice for backups), would
//     need streaming -- defer until needed.
//
//     Side effect: appends a VERIFY chain entry recording the result,
//     so periodic verification appears in the chain itself as
//     a self-consistency record.
//
//   GET /api/backup-chain/keys
//     Lists all chain signing keys with public-side metadata. Never
//     exposes private keys (they aren't even SELECTed -- see
//     chain-signing-keys.js listChainKeys).
//
//   GET /api/backup-chain/:id
//     Single-entry detail. Includes signature, payload, all metadata.
//
//   GET /api/backup-chain/backup/:backupId
//     All chain entries referencing a specific backup_id, ordered by
//     id ASC. Useful for forensic timeline reconstruction (CREATE,
//     subsequent VERIFY, eventual RESTORE_REQUEST etc.).
//
// AUDIT LOGGING
//
// Every endpoint emits an audit log entry. Chain inspection is itself
// a sensitive operation -- knowing who looked at the audit trail is
// itself part of the audit trail.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const chainSvc = require('../services/backup-chain');
const chainKeysSvc = require('../services/chain-signing-keys');

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

// ── Helpers ──────────────────────────────────────────────────────────────

function parseIntParam(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

function rowForListResponse(row) {
  // Exclude signature from list view (large, not useful for browsing).
  // Include everything else, parsing payload into object form.
  let payloadObj = null;
  try { payloadObj = JSON.parse(row.payload); } catch { /* leave null on parse error */ }
  return {
    id: row.id,
    prev_hash: row.prev_hash,
    this_hash: row.this_hash,
    signing_key_id: row.signing_key_id,
    event_type: row.event_type,
    backup_id: row.backup_id,
    payload: payloadObj,
    created_at: row.created_at,
  };
}

function rowForDetailResponse(row) {
  // Same as list view plus signature.
  return { ...rowForListResponse(row), signature: row.signature };
}

// ── GET /api/backup-chain ────────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const requestedLimit = parseIntParam(req.query.limit, DEFAULT_LIMIT);
    const limit = Math.max(1, Math.min(MAX_LIMIT, requestedLimit));
    const before = req.query.before ? parseIntParam(req.query.before, null) : null;

    const db = getDb();
    let rows;
    if (before !== null) {
      rows = db.prepare(`
        SELECT id, prev_hash, this_hash, signature, signing_key_id,
               event_type, backup_id, payload, created_at
        FROM backup_chain
        WHERE id < ?
        ORDER BY id DESC
        LIMIT ?
      `).all(before, limit);
    } else {
      rows = db.prepare(`
        SELECT id, prev_hash, this_hash, signature, signing_key_id,
               event_type, backup_id, payload, created_at
        FROM backup_chain
        ORDER BY id DESC
        LIMIT ?
      `).all(limit);
    }
    db.close();

    const entries = rows.map(rowForListResponse);
    const nextBefore = entries.length === limit ? entries[entries.length - 1].id : null;

    auditLog(req.user?.id, 'CHAIN_LISTED', `count=${entries.length} before=${before ?? 'head'}`, req.ip);
    res.json({ entries, nextBefore });
  } catch (err) {
    logger.error('Chain list error', { error: err.message });
    res.status(500).json({ error: 'Failed to list chain entries' });
  }
});

// ── GET /api/backup-chain/stats ──────────────────────────────────────────
router.get('/stats', (req, res) => {
  try {
    const db = getDb();
    const stats = chainSvc.getChainStats(db);
    db.close();

    auditLog(req.user?.id, 'CHAIN_STATS_VIEWED', `total=${stats.totalEntries}`, req.ip);
    res.json(stats);
  } catch (err) {
    logger.error('Chain stats error', { error: err.message });
    res.status(500).json({ error: 'Failed to get chain stats' });
  }
});

// ── GET /api/backup-chain/verify ─────────────────────────────────────────
//
// Walks every entry. Synchronous; can take several seconds on large
// chains. The endpoint also appends a VERIFY chain entry recording the
// result, so periodic verification leaves its own audit trail in the
// chain itself.
//
// QUERY PARAM: ?append_entry=false to skip appending the VERIFY entry
// (e.g., for repeated read-only health checks that shouldn't pollute
// the chain). Default true.
router.get('/verify', (req, res) => {
  try {
    const appendEntry = req.query.append_entry !== 'false';

    const db = getDb();
    const result = chainSvc.verifyFullChain(db);

    let verifyChainEntry = null;
    let verifyChainError = null;
    if (appendEntry) {
      try {
        const ce = chainSvc.appendChainEntry(db, {
          eventType: 'VERIFY',
          backupId: null,
          actorUserId: req.user?.id || null,
          payload: {
            verifier: 'admin-route',
            ok: result.ok,
            entries_verified: result.entriesVerified,
            broken_at_id: result.brokenAtId || null,
            reason: result.reason || null,
          },
        });
        verifyChainEntry = { id: ce.id, this_hash: ce.thisHash, created_at: ce.createdAt };
      } catch (chainErr) {
        verifyChainError = chainErr.message;
        logger.error('Chain VERIFY entry append failed', { error: chainErr.message });
      }
    }
    db.close();

    auditLog(
      req.user?.id,
      'CHAIN_VERIFIED',
      `ok=${result.ok} entriesVerified=${result.entriesVerified}` +
        (result.ok ? '' : ` brokenAt=${result.brokenAtId} reason=${result.reason}`),
      req.ip,
    );

    res.json({
      ...result,
      verifyChainEntry,
      verifyChainError,
    });
  } catch (err) {
    logger.error('Chain verify error', { error: err.message });
    res.status(500).json({ error: 'Failed to verify chain' });
  }
});

// ── GET /api/backup-chain/keys ───────────────────────────────────────────
router.get('/keys', (req, res) => {
  try {
    const db = getDb();
    const keys = chainKeysSvc.listChainKeys(db);
    db.close();

    auditLog(req.user?.id, 'CHAIN_KEYS_LISTED', `count=${keys.length}`, req.ip);
    res.json({ keys });
  } catch (err) {
    logger.error('Chain keys list error', { error: err.message });
    res.status(500).json({ error: 'Failed to list chain signing keys' });
  }
});

// ── GET /api/backup-chain/backup/:backupId ───────────────────────────────
//
// Note this route MUST be declared before /:id because /backup/:backupId
// could otherwise be parsed as :id = "backup" by Express.
router.get('/backup/:backupId', (req, res) => {
  try {
    const { backupId } = req.params;
    if (!backupId || typeof backupId !== 'string') {
      return res.status(400).json({ error: 'backupId required' });
    }

    const db = getDb();
    const rows = db.prepare(`
      SELECT id, prev_hash, this_hash, signature, signing_key_id,
             event_type, backup_id, payload, created_at
      FROM backup_chain
      WHERE backup_id = ?
      ORDER BY id ASC
    `).all(backupId);
    db.close();

    auditLog(req.user?.id, 'CHAIN_BACKUP_TIMELINE_VIEWED', `backup_id=${backupId} entries=${rows.length}`, req.ip);
    res.json({
      backup_id: backupId,
      entries: rows.map(rowForDetailResponse),
    });
  } catch (err) {
    logger.error('Chain backup timeline error', { error: err.message });
    res.status(500).json({ error: 'Failed to get backup timeline' });
  }
});

// ── GET /api/backup-chain/:id ────────────────────────────────────────────
router.get('/:id', (req, res) => {
  try {
    const id = parseIntParam(req.params.id, null);
    if (id === null) {
      return res.status(400).json({ error: 'id must be a positive integer' });
    }

    const db = getDb();
    const row = db.prepare(`
      SELECT id, prev_hash, this_hash, signature, signing_key_id,
             event_type, backup_id, payload, created_at
      FROM backup_chain
      WHERE id = ?
    `).get(id);
    db.close();

    if (!row) return res.status(404).json({ error: 'Chain entry not found' });

    auditLog(req.user?.id, 'CHAIN_ENTRY_VIEWED', `id=${id}`, req.ip);
    res.json(rowForDetailResponse(row));
  } catch (err) {
    logger.error('Chain entry detail error', { error: err.message });
    res.status(500).json({ error: 'Failed to get chain entry' });
  }
});

module.exports = router;

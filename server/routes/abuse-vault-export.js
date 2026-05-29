// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Abuse-Vault Legal-Hold Export: Request Route (U4 PR 5-C)
//
// Reviewer-gated endpoints for the FIRST half of the two-person legal-hold
// export flow: an independent reviewer (ARC) requests an export of a vaulted
// case with a mandatory rationale. The request lands in abuse_vault_export_
// requests as 'pending' and a LEGAL_HOLD_REQUESTED entry is appended to the
// abuse-vault chain.
//
// INDEPENDENCE: this router is mounted abuse_reviewer-only and writes NO
// audit_log entry -- the team lead / Management Console must never see export
// activity or its status. The immutable record is the chain (reviewer/CISO
// scoped). Approval is performed by a CISO in the Global Dashboard and pulled
// back over the dedicated ARC -> regional server -> GD channel (later commits);
// this file only creates and reads requests.
//
// Separation of duties is structural: the requester here is an MC-realm
// reviewer; the approver is a GD-realm CISO. The regional server has no approve
// path of its own.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { canReview, REVIEWER_ROLE } = require('../services/abuse-reviewer-access');
const avChain = require('../services/abuse-vault-chain');

const REVIEWABLE_TARGET_TYPES = ['lead_chat', 'peer_session', 'board_post'];
const REVIEWABLE_IN = REVIEWABLE_TARGET_TYPES.map(() => '?').join(', ');
const MIN_REASON = 20;
const MAX_REASON = 4000;
const APPROVAL_WINDOW_HOURS = 72;

function loadReviewerContext(db, userId) {
  const reviewer = db.prepare('SELECT id, role, active FROM users WHERE id = ?').get(userId);
  const assignments = db.prepare(
    'SELECT scope, team_id, flag_id FROM abuse_reviewer_assignments WHERE reviewer_user_id = ?'
  ).all(userId);
  return { reviewer, assignments };
}

function serializeRequest(r) {
  return {
    id: r.id,
    flagId: r.flag_id,
    status: r.status,
    reason: r.request_reason,
    requestedAt: r.requested_at,
    expiresAt: r.expires_at,
    approvedAt: r.approved_at || null,
    deniedAt: r.denied_at || null,
    denialReason: r.denied_at ? (r.denial_reason || null) : null,
    consumedAt: r.consumed_at || null,
  };
}

// Fail-closed router guard: abuse_reviewer ONLY, regardless of how mounted.
router.use((req, res, next) => {
  if (!req.user || req.user.role !== REVIEWER_ROLE) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
});

// POST /:flagId/request — request a legal-hold export of a vaulted case.
// Requires a rationale and authority over the case (same canReview gate as
// resolve). One open (pending or approved) request per case at a time.
router.post('/:flagId/request', (req, res) => {
  const { reason } = req.body || {};
  const rationale = (typeof reason === 'string') ? reason.trim() : '';
  if (rationale.length < MIN_REASON) {
    return res.status(400).json({ error: `a rationale of at least ${MIN_REASON} characters is required` });
  }
  if (rationale.length > MAX_REASON) {
    return res.status(400).json({ error: 'rationale too long' });
  }
  let db;
  try {
    db = getDb();
    const flag = db.prepare(
      `SELECT * FROM peer_abuse_flags WHERE id = ? AND target_type IN (${REVIEWABLE_IN})`
    ).get(req.params.flagId, ...REVIEWABLE_TARGET_TYPES);
    if (!flag) return res.status(404).json({ error: 'case not found' });

    const { reviewer, assignments } = loadReviewerContext(db, req.user.id);
    const decision = canReview({ reviewer, flag: { ...flag, teamIds: [] }, assignments });
    if (!decision.allowed) return res.status(403).json({ error: 'forbidden', reason: decision.reason });

    const open = db.prepare(
      "SELECT id FROM abuse_vault_export_requests WHERE flag_id = ? AND status IN ('pending', 'approved')"
    ).get(req.params.flagId);
    if (open) return res.status(409).json({ error: 'an export request for this case is already open' });

    const requestId = crypto.randomUUID();
    db.transaction(() => {
      db.prepare(`
        INSERT INTO abuse_vault_export_requests
          (id, flag_id, requested_by_user_id, request_reason, status,
           approval_window_hours, expires_at, client_ip_at_request)
        VALUES (?, ?, ?, ?, 'pending', ?, datetime('now', ?), ?)
      `).run(requestId, req.params.flagId, req.user.id, rationale,
             APPROVAL_WINDOW_HOURS, `+${APPROVAL_WINDOW_HOURS} hours`, req.ip || null);

      // The chain is the immutable record. A chain failure must not lose the
      // request; the boot integrity check / re-verify can reconcile.
      try {
        const entry = avChain.appendEntry(db, {
          eventType: 'LEGAL_HOLD_REQUESTED',
          flagId: req.params.flagId,
          requestRef: requestId,
          actorUserId: req.user.id,
        });
        db.prepare('UPDATE abuse_vault_export_requests SET chain_request_entry_id = ? WHERE id = ?')
          .run(entry.id, requestId);
      } catch (avErr) {
        logger.warn('abuse-vault-export: LEGAL_HOLD_REQUESTED chain append failed', { error: avErr.message });
      }
    })();

    const row = db.prepare('SELECT * FROM abuse_vault_export_requests WHERE id = ?').get(requestId);
    return res.status(201).json(serializeRequest(row));
  } catch (err) {
    logger.error('abuse-vault-export: failed to create request', { error: err.message });
    return res.status(500).json({ error: 'failed to create export request' });
  } finally {
    if (db) db.close();
  }
});

// GET /requests — the reviewer's own export requests (status list).
router.get('/requests', (req, res) => {
  let db;
  try {
    db = getDb();
    const rows = db.prepare(
      'SELECT * FROM abuse_vault_export_requests WHERE requested_by_user_id = ? ORDER BY requested_at DESC'
    ).all(req.user.id);
    return res.json({ requests: rows.map(serializeRequest) });
  } catch (err) {
    logger.error('abuse-vault-export: failed to list requests', { error: err.message });
    return res.status(500).json({ error: 'failed to list export requests' });
  } finally {
    if (db) db.close();
  }
});

// GET /requests/:id — one request's status (requester only; 404-masked otherwise).
router.get('/requests/:id', (req, res) => {
  let db;
  try {
    db = getDb();
    const row = db.prepare('SELECT * FROM abuse_vault_export_requests WHERE id = ?').get(req.params.id);
    if (!row || row.requested_by_user_id !== req.user.id) {
      return res.status(404).json({ error: 'request not found' });
    }
    return res.json(serializeRequest(row));
  } catch (err) {
    logger.error('abuse-vault-export: failed to get request', { error: err.message });
    return res.status(500).json({ error: 'failed to get export request' });
  } finally {
    if (db) db.close();
  }
});

module.exports = router;

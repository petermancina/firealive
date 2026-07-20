// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Helper Pay Routes
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// HTTP surface for the Helper Pay subsystem. Mounted under /api/helper-pay
// with authMiddleware(['analyst', 'lead', 'admin']) — the broadest role set
// any endpoint in this file needs. Endpoints requiring elevated roles
// (lead approval queue, admin catalog management, admin fraud reversal,
// admin export) check req.user.role inline and 403 on insufficient role.
//
// Endpoint groups:
//
//   Analyst self-service:
//     GET  /balance
//     GET  /ledger?limit&before
//     GET  /options
//     GET  /redemptions
//     POST /sessions/:sessionId/rate      (analyst rates a session helper)
//     POST /redeem                        (request a redemption)
//
//   Lead approval queue (lead, admin):
//     GET  /redemptions/pending
//     POST /redemptions/:id/decide        (approve or deny)
//     POST /redemptions/:id/fulfill       (mark fulfilled)
//
//   Admin catalog (admin only):
//     GET    /admin/options               (list all, including inactive)
//     POST   /admin/options
//     PUT    /admin/options/:id
//     DELETE /admin/options/:id           (soft delete via active=0)
//
//   Admin fraud reversal (admin only):
//     POST /admin/reverse                 body: { ledgerId, note }
//
//   Admin CSV export (admin only):
//     GET /admin/export.csv?type=ledger|redemptions
//
// Notifications are fired on a best-effort basis after a successful
// service call. A notify() failure logs and does NOT fail the request,
// because the canonical record (ledger row or redemption row) is already
// committed. The three event types this file consumes are pre-registered
// in services/notifications.js (helper_points_awarded,
// helper_redemption_approved, helper_redemption_denied).
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');
const router = express.Router();

const helperPay = require('../services/helper-pay');
const { notify } = require('../services/notifications');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');

// ── Inline role helpers ─────────────────────────────────────────────────────
// Mounting middleware already enforces analyst|lead|admin; these helpers
// gate elevated endpoints.

function isLeadOrAdmin(req) {
  return ['lead', 'admin'].includes(req.user && req.user.role);
}

function isAdmin(req) {
  return req.user && req.user.role === 'admin';
}

function newId() {
  return crypto.randomBytes(16).toString('hex');
}

// Maps a helper-pay service error code to an HTTP status. Default 500.
function statusForError(code) {
  switch (code) {
    case 'HELPER_INVALID_RATING':
    case 'HELPER_DUPLICATE_RATING':
      return 400;
    case 'HELPER_OPTION_INACTIVE':
    case 'HELPER_INSUFFICIENT_BALANCE':
    case 'HELPER_YEARLY_CAP_REACHED':
      return 409;
    case 'REDEMPTION_NOT_PENDING':
    case 'REDEMPTION_NOT_APPROVED':
      return 409;
    case 'LEDGER_ENTRY_NOT_FOUND':
      return 404;
    case 'USER_NOT_FOUND':
      return 404;
    case 'RATING_NOT_FOUND':
      return 404;
    case 'RATING_NOT_FLAGGED':
      return 409;
    default:
      return 500;
  }
}

function sendServiceError(res, err) {
  const status = statusForError(err.code);
  res.status(status).json({ error: err.code || 'INTERNAL_ERROR', message: err.message });
}

// Best-effort notify; never throws.
function safeNotify(payload) {
  try {
    notify(payload);
  } catch (err) {
    logger.warn('Helper Pay notify failed', { eventType: payload.eventType, error: err.message });
  }
}

// ── Config (lead/admin) ─────────────────────────────────────────────────────
// R3n: Helper Pay system config — 4 fields stored in team_config key-value
// row keyed 'helper_pay_config'. Distinct from the feature toggle (the
// future Features tab controls whether this subsystem is available at all);
// these settings govern its runtime behavior when enabled.
//
//   enabled:                   boolean — whether sessions accrue points
//   pointsThreshold:           int >= 1 — points required for redemption
//   payDifferentialPct:        number 0-100 — bonus pay percentage
//   designatedHelperThreshold: int >= pointsThreshold — qualifies the
//                              analyst as "designated helper" tier
//
// The MC's Helper Pay Configuration card (firealive-mc.jsx) reads via GET
// and saves via PUT. Audit-logged as MC_HELPER_PAY_CONFIG_SAVED on save.

const HELPER_PAY_CONFIG_DEFAULTS = {
  enabled: true,
  pointsThreshold: 50,
  payDifferentialPct: 5,
  designatedHelperThreshold: 100,
};

router.get('/config', (req, res) => {
  if (!isLeadOrAdmin(req)) {
    return res.status(403).json({ error: 'lead or admin role required' });
  }
  try {
    const db = getDb();
    const row = db.prepare("SELECT value, updated_by, updated_at FROM team_config WHERE key = 'helper_pay_config'").get();
    db.close();
    if (!row) {
      return res.json({ ...HELPER_PAY_CONFIG_DEFAULTS, _source: 'default' });
    }
    try {
      const parsed = JSON.parse(row.value);
      return res.json({
        ...HELPER_PAY_CONFIG_DEFAULTS,
        ...parsed,
        updatedAt: row.updated_at,
        updatedBy: row.updated_by,
        _source: 'stored',
      });
    } catch (parseErr) {
      logger.error('helper-pay config row JSON parse failed; returning defaults', { error: parseErr.message });
      return res.json({ ...HELPER_PAY_CONFIG_DEFAULTS, _source: 'default-fallback' });
    }
  } catch (err) {
    logger.error('helper-pay config read failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

router.put('/config', (req, res) => {
  if (!isLeadOrAdmin(req)) {
    return res.status(403).json({ error: 'lead or admin role required' });
  }

  const { enabled, pointsThreshold, payDifferentialPct, designatedHelperThreshold } = req.body || {};

  // Field-level validation (each error 400s with a specific message so
  // the MC can surface the exact problem to the operator)
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ error: 'enabled must be boolean' });
  }
  if (!Number.isInteger(pointsThreshold) || pointsThreshold < 1) {
    return res.status(400).json({ error: 'pointsThreshold must be a positive integer' });
  }
  if (typeof payDifferentialPct !== 'number' || payDifferentialPct < 0 || payDifferentialPct > 100 || !Number.isFinite(payDifferentialPct)) {
    return res.status(400).json({ error: 'payDifferentialPct must be a number between 0 and 100' });
  }
  if (!Number.isInteger(designatedHelperThreshold) || designatedHelperThreshold < pointsThreshold) {
    return res.status(400).json({ error: 'designatedHelperThreshold must be an integer >= pointsThreshold' });
  }

  const config = { enabled, pointsThreshold, payDifferentialPct, designatedHelperThreshold };

  try {
    const db = getDb();
    db.prepare(`
      INSERT INTO team_config (key, value, updated_by, updated_at)
      VALUES ('helper_pay_config', ?, ?, datetime('now'))
      ON CONFLICT(key) DO UPDATE SET
        value = excluded.value,
        updated_by = excluded.updated_by,
        updated_at = datetime('now')
    `).run(JSON.stringify(config), req.user.id);
    db.close();

    auditLog(
      req.user.id,
      'MC_HELPER_PAY_CONFIG_SAVED',
      `enabled=${enabled} pointsThreshold=${pointsThreshold} payDifferentialPct=${payDifferentialPct} designatedHelperThreshold=${designatedHelperThreshold}`,
      req.ip
    );

    res.json({ ok: true, config });
  } catch (err) {
    logger.error('helper-pay config save failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ── Analyst self-service ────────────────────────────────────────────────────

router.get('/balance', (req, res) => {
  try {
    const balance = helperPay.getBalance(req.user.id);
    res.json({ balance });
  } catch (err) {
    logger.error('helper-pay balance read failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

router.get('/ledger', (req, res) => {
  try {
    const limit = req.query.limit;
    const before = req.query.before;
    const rows = helperPay.getLedger(req.user.id, { limit, before });
    res.json({ entries: rows });
  } catch (err) {
    logger.error('helper-pay ledger read failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// Active redemption catalog visible to all roles.
router.get('/options', (req, res) => {
  const db = getDb();
  try {
    const options = db.prepare(
      `SELECT id, name, description, cost_points, redemption_type,
              approval_required, max_per_user_per_year
         FROM helper_redemption_options
         WHERE active = 1
         ORDER BY cost_points ASC, name ASC`
    ).all();
    res.json({ options });
  } catch (err) {
    logger.error('helper-pay options read failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  } finally {
    db.close();
  }
});

router.get('/redemptions', (req, res) => {
  const db = getDb();
  try {
    const rows = db.prepare(
      `SELECT r.id, r.option_id, o.name AS option_name, r.cost_points,
              r.status, r.requested_at, r.decided_at, r.decision_note,
              r.fulfilled_at
         FROM helper_redemptions r
         JOIN helper_redemption_options o ON o.id = r.option_id
         WHERE r.user_id = ?
         ORDER BY r.requested_at DESC
         LIMIT 100`
    ).all(req.user.id);
    res.json({ redemptions: rows });
  } catch (err) {
    logger.error('helper-pay my-redemptions read failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  } finally {
    db.close();
  }
});

// Build the report-doc-builder model from a helper-pay statement. A
// statement is fact-only -- no KB synthesis, no citations -- so the model
// carries pseudonym + balance metadata and two sections of itemized bullets
// (Points Ledger and Redemptions). Used by the signed PDF/DOCX export path.
function helperPayModel(stmt) {
  const meta = [
    ['Pseudonym', stmt.pseudonym || '(unset)'],
    ['Analyst ID', stmt.userId],
    ['Current Balance', String(stmt.balance) + ' points'],
    ['Generated', stmt.generatedAt],
  ];
  const ledgerBullets = stmt.ledger.length === 0
    ? ['(no ledger entries yet)']
    : stmt.ledger.map((e) => {
        const sign = (typeof e.delta === 'number' && e.delta >= 0) ? '+' : '';
        const notes = e.notes ? `  --  ${e.notes}` : '';
        const reason = e.reason || e.ref_type || '(unlabeled)';
        return `${e.created_at}  ·  ${sign}${e.delta} pts  ·  ${reason}  ·  balance ${e.balance_after}${notes}`;
      });
  const redemptionBullets = stmt.redemptions.length === 0
    ? ['(no redemptions yet)']
    : stmt.redemptions.map((r) => {
        const decided = r.decided_at ? `, decided ${r.decided_at}` : '';
        const note = r.decision_note ? ` (${r.decision_note})` : '';
        const fulfilled = r.fulfilled_at ? `, fulfilled ${r.fulfilled_at}` : '';
        return `${r.requested_at}  ·  ${r.option_name}  ·  ${r.cost_points} pts  ·  ${r.status}${decided}${note}${fulfilled}`;
      });
  return {
    title: 'Helper Pay Statement',
    subtitle: `${stmt.pseudonym || 'Analyst'} · current balance ${stmt.balance} points`,
    meta,
    sections: [
      { heading: 'Points Ledger', bullets: ledgerBullets },
      { heading: 'Redemptions', bullets: redemptionBullets },
    ],
  };
}

// Caller-scoped points statement for the analyst's own records. Returns only
// the requesting user's pseudonym, balance, ledger, and redemptions - never
// anyone else's. format chooses the output: json (default), csv, signed pdf,
// or signed docx. This is for personal record-keeping; it is not an HR or
// payroll document, and it never exposes another analyst's data.
router.get('/my-statement', async (req, res) => {
  const format = String(req.query.format || 'json').toLowerCase();
  if (!['json', 'csv', 'pdf', 'docx'].includes(format)) {
    return res.status(400).json({ error: 'format must be one of: json, csv, pdf, docx' });
  }
  const db = getDb();
  try {
    const userId = req.user.id;
    const balance = helperPay.getBalance(userId);
    const ledger = helperPay.getLedger(userId, { limit: 1000 });
    const redemptions = db.prepare(
      `SELECT r.id, r.option_id, o.name AS option_name, r.cost_points,
              r.status, r.requested_at, r.decided_at, r.decision_note,
              r.fulfilled_at
         FROM helper_redemptions r
         JOIN helper_redemption_options o ON o.id = r.option_id
         WHERE r.user_id = ?
         ORDER BY r.requested_at DESC`
    ).all(userId);
    const u = db.prepare(`SELECT pseudonym FROM users WHERE id = ?`).get(userId);
    const pseudonym = (u && u.pseudonym) || null;
    const generatedAt = new Date().toISOString();

    auditLog(userId, 'HELPER_STATEMENT_EXPORTED',
      `format=${format}; ledger=${ledger.length}; redemptions=${redemptions.length}`,
      req.ip);

    if (format === 'csv') {
      const lines = [];
      lines.push('Helper Pay Statement');
      lines.push(['Pseudonym', csvEscape(pseudonym)].join(','));
      lines.push(['Analyst ID', csvEscape(userId)].join(','));
      lines.push(['Current Balance', csvEscape(balance)].join(','));
      lines.push(['Generated', csvEscape(generatedAt)].join(','));
      lines.push('');
      lines.push('Points Ledger');
      const lh = ['created_at', 'delta', 'reason', 'ref_type', 'ref_id', 'balance_after', 'notes'];
      lines.push(lh.join(','));
      for (const e of ledger) lines.push(lh.map(k => csvEscape(e[k])).join(','));
      lines.push('');
      lines.push('Redemptions');
      const rh = ['requested_at', 'option_name', 'cost_points', 'status', 'decided_at', 'decision_note', 'fulfilled_at'];
      lines.push(rh.join(','));
      for (const r of redemptions) lines.push(rh.map(k => csvEscape(r[k])).join(','));
      // bytes-mode verification footer + sign the resulting CSV bytes, so
      // the CSV is a signed, verifiable artifact (same report_type and
      // owner_user_id auth rule as the pdf/docx path). Spreadsheet apps
      // render the '# '-prefixed lines as text in column A. The verifier
      // hashes the file bytes and calls /api/verify/report/<sha256>.
      const { buildWatermarkLines } = require('../services/report-watermark');
      const { signReport, getInstanceLabel } = require('../services/report-signer');
      const { ensureActiveReportKeypair } = require('../services/report-signing-keys');
      const reportKey = ensureActiveReportKeypair(db);
      const footerLines = buildWatermarkLines({
        instanceLabel: getInstanceLabel(db),
        keyFingerprint: reportKey.publicKeyFingerprint,
        signedAt: new Date().toISOString(),
      });
      lines.push('');
      for (const fl of footerLines) lines.push('# ' + fl);
      const csv = lines.join('\n') + '\n';
      const csvBytes = Buffer.from(csv, 'utf8');
      const descriptor = signReport({
        db,
        reportType: 'helper_pay',
        subjectRef: crypto.randomUUID(),
        material: csvBytes,
        metadata: {
          owner_user_id: userId,
          format: 'csv',
          balance,
          ledger_count: ledger.length,
          redemption_count: redemptions.length,
        },
      });
      const filename = `helper-pay-statement-${generatedAt.slice(0, 10)}.csv`;
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('X-Report-Verification', descriptor.sha256);
      return res.send(csvBytes);
    }

    if (format === 'pdf' || format === 'docx') {
      // Signed document export. The rendered file bytes are signed; the
      // bytes-mode footer instructs the verifier to compute the file's
      // SHA-256 and call GET /api/verify/report/<sha256>. report-doc-builder
      // (pdfkit/docx) is required only on this path so the json and csv paths
      // carry no new runtime dependency.
      const { buildReportPdf, buildReportDocx } = require('../services/report-doc-builder');
      const { signReport, getInstanceLabel } = require('../services/report-signer');
      const { ensureActiveReportKeypair } = require('../services/report-signing-keys');
      const reportKey = ensureActiveReportKeypair(db);
      const footer = {
        instanceLabel: getInstanceLabel(db),
        keyFingerprint: reportKey.publicKeyFingerprint,
        signedAt: new Date().toISOString(),
      };
      const model = helperPayModel({ pseudonym, userId, balance, ledger, redemptions, generatedAt });
      const buffer = format === 'pdf'
        ? await buildReportPdf(model, footer)
        : await buildReportDocx(model, footer);
      // owner_user_id in metadata is what the verify endpoint uses to enforce
      // the self-or-admin auth rule for helper_pay reports (PR 1's
      // report-verification.js). subject_ref is a per-statement uuid; the
      // statement itself is not persisted (it is regenerated on demand).
      const descriptor = signReport({
        db,
        reportType: 'helper_pay',
        subjectRef: crypto.randomUUID(),
        material: buffer,
        metadata: {
          owner_user_id: userId,
          format,
          balance,
          ledger_count: ledger.length,
          redemption_count: redemptions.length,
        },
      });
      const ext = format === 'pdf' ? 'pdf' : 'docx';
      const ctype = format === 'pdf'
        ? 'application/pdf'
        : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
      const filename = `helper-pay-statement-${generatedAt.slice(0, 10)}.${ext}`;
      res.setHeader('Content-Type', ctype);
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('X-Report-Verification', descriptor.sha256);
      return res.send(buffer);
    }

    res.json({ pseudonym, userId, balance, ledger, redemptions, generatedAt });
  } catch (err) {
    logger.error('helper-pay my-statement failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  } finally {
    db.close();
  }
});

// Submit a rating for a peer session. The rater is req.user (the seeker);
// the helper is derived from the session record by the service.
router.post('/sessions/:sessionId/rate', (req, res) => {
  try {
    const { stars, comment, helpfulnessTags } = req.body || {};
    const result = helperPay.recordRating(
      req.params.sessionId,
      req.user.id,
      stars,
      comment,
      helpfulnessTags
    );

    // If points actually accrued, notify the helper.
    if (result.ledgerId) {
      const db = getDb();
      try {
        const entry = db.prepare(
          `SELECT user_id, delta FROM helper_points_ledger WHERE id = ?`
        ).get(result.ledgerId);
        if (entry && entry.delta > 0) {
          safeNotify({
            recipientId: entry.user_id,
            eventType: 'helper_points_awarded',
            title: `You earned ${entry.delta} Helper Pay points`,
            body: `An analyst you helped rated the session and you earned ${entry.delta} points. Visit your Helper Pay tab to view your balance.`,
            linkTab: 'helper-pay',
          });
        }
      } finally {
        db.close();
      }
    }

    res.json(result);
  } catch (err) {
    if (err.code) return sendServiceError(res, err);
    logger.error('helper-pay rate session failed', {
      userId: req.user.id,
      sessionId: req.params.sessionId,
      error: err.message,
    });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// Request a redemption against a catalog option.
router.post('/redeem', (req, res) => {
  try {
    const { optionId } = req.body || {};
    if (!optionId) {
      return res.status(400).json({ error: 'BAD_REQUEST', message: 'optionId is required' });
    }
    const result = helperPay.requestRedemption(req.user.id, optionId);

    // Auto-approved options also notify the user that their points were debited.
    if (result.status === 'approved') {
      safeNotify({
        recipientId: req.user.id,
        eventType: 'helper_redemption_approved',
        title: 'Helper Pay redemption approved',
        body: 'Your redemption has been auto-approved and the points have been debited from your balance.',
        linkTab: 'helper-pay',
      });
    }
    // For approval-required options, leads will be notified through the
    // pending-queue UI poll. A push notification to leads on every request
    // would require a new helper_redemption_requested event type and a
    // recipient query for active leads; deferred to a follow-up phase.

    res.json(result);
  } catch (err) {
    if (err.code) return sendServiceError(res, err);
    logger.error('helper-pay redeem failed', { userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ── Lead approval queue ─────────────────────────────────────────────────────

router.get('/redemptions/pending', (req, res) => {
  if (!isLeadOrAdmin(req)) return res.status(403).json({ error: 'FORBIDDEN' });
  const db = getDb();
  try {
    const rows = db.prepare(
      `SELECT r.id, r.user_id, u.username, u.name AS user_name,
              r.option_id, o.name AS option_name, o.redemption_type,
              r.cost_points, r.requested_at
         FROM helper_redemptions r
         JOIN helper_redemption_options o ON o.id = r.option_id
         JOIN users u ON u.id = r.user_id
         WHERE r.status = 'requested'
         ORDER BY r.requested_at ASC`
    ).all();
    res.json({ pending: rows });
  } catch (err) {
    logger.error('helper-pay pending queue read failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  } finally {
    db.close();
  }
});

router.post('/redemptions/:id/decide', (req, res) => {
  if (!isLeadOrAdmin(req)) return res.status(403).json({ error: 'FORBIDDEN' });
  try {
    const { approve, note } = req.body || {};
    const result = helperPay.decideRedemption(req.params.id, req.user.id, !!approve, note);

    // Notify the redemption owner of the decision.
    const db = getDb();
    try {
      const r = db.prepare(`SELECT user_id FROM helper_redemptions WHERE id = ?`).get(req.params.id);
      if (r && r.user_id) {
        if (result.status === 'approved') {
          safeNotify({
            recipientId: r.user_id,
            eventType: 'helper_redemption_approved',
            title: 'Helper Pay redemption approved',
            body: note
              ? `Your redemption was approved. Note from your lead: ${note}`
              : 'Your redemption was approved. Points have been debited from your balance.',
            linkTab: 'helper-pay',
          });
        } else if (result.status === 'denied') {
          safeNotify({
            recipientId: r.user_id,
            eventType: 'helper_redemption_denied',
            title: 'Helper Pay redemption denied',
            body: note
              ? `Your redemption was denied. Note from your lead: ${note}`
              : 'Your redemption was denied. Your points balance is unchanged.',
            linkTab: 'helper-pay',
          });
        }
      }
    } finally {
      db.close();
    }

    res.json(result);
  } catch (err) {
    if (err.code) return sendServiceError(res, err);
    logger.error('helper-pay decide failed', {
      deciderId: req.user.id,
      redemptionId: req.params.id,
      error: err.message,
    });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

router.post('/redemptions/:id/fulfill', (req, res) => {
  if (!isLeadOrAdmin(req)) return res.status(403).json({ error: 'FORBIDDEN' });
  try {
    const result = helperPay.markFulfilled(req.params.id, req.user.id);
    res.json(result);
  } catch (err) {
    if (err.code) return sendServiceError(res, err);
    logger.error('helper-pay fulfill failed', {
      fulfillerId: req.user.id,
      redemptionId: req.params.id,
      error: err.message,
    });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ── Admin: redemption catalog management ────────────────────────────────────

router.get('/admin/options', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'FORBIDDEN' });
  const db = getDb();
  try {
    const options = db.prepare(
      `SELECT id, name, description, cost_points, redemption_type,
              approval_required, active, max_per_user_per_year,
              created_at, updated_at, updated_by
         FROM helper_redemption_options
         ORDER BY active DESC, cost_points ASC, name ASC`
    ).all();
    res.json({ options });
  } catch (err) {
    logger.error('helper-pay admin options read failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  } finally {
    db.close();
  }
});

router.post('/admin/options', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'FORBIDDEN' });
  const {
    name,
    description,
    costPoints,
    redemptionType,
    approvalRequired = true,
    maxPerUserPerYear,
  } = req.body || {};

  if (!name || typeof name !== 'string') {
    return res.status(400).json({ error: 'BAD_REQUEST', message: 'name is required' });
  }
  if (!Number.isInteger(costPoints) || costPoints <= 0) {
    return res.status(400).json({ error: 'BAD_REQUEST', message: 'costPoints must be a positive integer' });
  }
  if (!['time_off', 'gift_card', 'donation', 'other'].includes(redemptionType)) {
    return res.status(400).json({ error: 'BAD_REQUEST', message: 'redemptionType must be one of time_off, gift_card, donation, other' });
  }

  const db = getDb();
  try {
    const id = newId();
    db.prepare(
      `INSERT INTO helper_redemption_options
         (id, name, description, cost_points, redemption_type,
          approval_required, active, max_per_user_per_year, updated_by)
         VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`
    ).run(
      id,
      name,
      description || null,
      costPoints,
      redemptionType,
      approvalRequired ? 1 : 0,
      Number.isInteger(maxPerUserPerYear) && maxPerUserPerYear > 0 ? maxPerUserPerYear : null,
      req.user.id
    );
    res.json({ id });
  } catch (err) {
    logger.error('helper-pay admin create option failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  } finally {
    db.close();
  }
});

router.put('/admin/options/:id', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'FORBIDDEN' });
  const updates = req.body || {};
  const fields = [];
  const values = [];

  if (typeof updates.name === 'string') { fields.push('name = ?'); values.push(updates.name); }
  if (typeof updates.description === 'string') { fields.push('description = ?'); values.push(updates.description); }
  if (Number.isInteger(updates.costPoints) && updates.costPoints > 0) {
    fields.push('cost_points = ?'); values.push(updates.costPoints);
  }
  if (['time_off', 'gift_card', 'donation', 'other'].includes(updates.redemptionType)) {
    fields.push('redemption_type = ?'); values.push(updates.redemptionType);
  }
  if (typeof updates.approvalRequired === 'boolean') {
    fields.push('approval_required = ?'); values.push(updates.approvalRequired ? 1 : 0);
  }
  if (typeof updates.active === 'boolean') {
    fields.push('active = ?'); values.push(updates.active ? 1 : 0);
  }
  if (Number.isInteger(updates.maxPerUserPerYear) || updates.maxPerUserPerYear === null) {
    fields.push('max_per_user_per_year = ?');
    values.push(updates.maxPerUserPerYear);
  }

  if (fields.length === 0) {
    return res.status(400).json({ error: 'BAD_REQUEST', message: 'no updatable fields supplied' });
  }
  fields.push("updated_at = datetime('now')");
  fields.push('updated_by = ?');
  values.push(req.user.id);
  values.push(req.params.id);

  const db = getDb();
  try {
    const info = db.prepare(
      `UPDATE helper_redemption_options SET ${fields.join(', ')} WHERE id = ?`
    ).run(...values);
    if (info.changes === 0) {
      return res.status(404).json({ error: 'NOT_FOUND' });
    }
    res.json({ id: req.params.id, updated: true });
  } catch (err) {
    logger.error('helper-pay admin update option failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  } finally {
    db.close();
  }
});

// Soft-delete by setting active=0; preserves historic redemption FK integrity.
router.delete('/admin/options/:id', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'FORBIDDEN' });
  const db = getDb();
  try {
    const info = db.prepare(
      `UPDATE helper_redemption_options
          SET active = 0, updated_at = datetime('now'), updated_by = ?
          WHERE id = ?`
    ).run(req.user.id, req.params.id);
    if (info.changes === 0) {
      return res.status(404).json({ error: 'NOT_FOUND' });
    }
    res.json({ id: req.params.id, deactivated: true });
  } catch (err) {
    logger.error('helper-pay admin deactivate option failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  } finally {
    db.close();
  }
});

// ── Admin: fraud reversal ───────────────────────────────────────────────────

router.post('/admin/reverse', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'FORBIDDEN' });
  try {
    const { ledgerId, note } = req.body || {};
    if (!ledgerId) {
      return res.status(400).json({ error: 'BAD_REQUEST', message: 'ledgerId is required' });
    }
    const result = helperPay.reversePointsForFraud(ledgerId, req.user.id, note);
    res.json(result);
  } catch (err) {
    if (err.code) return sendServiceError(res, err);
    logger.error('helper-pay reverse failed', { adminId: req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ── Admin: CSV export ───────────────────────────────────────────────────────

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

router.get('/admin/export.csv', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'FORBIDDEN' });
  const type = (req.query.type || 'ledger').toString();
  const db = getDb();
  try {
    let header;
    let rows;
    if (type === 'ledger') {
      header = ['id', 'user_id', 'username', 'delta', 'reason', 'ref_type', 'ref_id',
                'balance_after', 'notes', 'created_by', 'created_at'];
      rows = db.prepare(
        `SELECT l.id, l.user_id, u.username, l.delta, l.reason, l.ref_type, l.ref_id,
                l.balance_after, l.notes, l.created_by, l.created_at
           FROM helper_points_ledger l
           LEFT JOIN users u ON u.id = l.user_id
           ORDER BY l.created_at DESC, l.id DESC`
      ).all();
    } else if (type === 'redemptions') {
      header = ['id', 'user_id', 'username', 'option_id', 'option_name', 'cost_points',
                'status', 'requested_at', 'decided_at', 'decided_by', 'decision_note',
                'fulfilled_at', 'ledger_id'];
      rows = db.prepare(
        `SELECT r.id, r.user_id, u.username, r.option_id, o.name AS option_name,
                r.cost_points, r.status, r.requested_at, r.decided_at, r.decided_by,
                r.decision_note, r.fulfilled_at, r.ledger_id
           FROM helper_redemptions r
           LEFT JOIN users u ON u.id = r.user_id
           LEFT JOIN helper_redemption_options o ON o.id = r.option_id
           ORDER BY r.requested_at DESC`
      ).all();
    } else {
      return res.status(400).json({ error: 'BAD_REQUEST', message: 'type must be ledger or redemptions' });
    }

    const lines = [header.join(',')];
    for (const r of rows) {
      lines.push(header.map(k => csvEscape(r[k])).join(','));
    }
    const csv = lines.join('\n') + '\n';

    const filename = `helper-pay-${type}-${new Date().toISOString().slice(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (err) {
    logger.error('helper-pay admin export failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  } finally {
    db.close();
  }
});

// ════════════════════════════════════════════════════════════════════════════
// R3h — Helper Recognition Leaderboard endpoints
// ════════════════════════════════════════════════════════════════════════════
//
// Four new endpoints supporting the v1.0.34 Helper Recognition Leaderboard:
//
//   GET  /leaderboard?limit=N     — top opted-in helpers (any authed role)
//   GET  /me/visibility           — current user's opt-in state for AC toggle
//   PUT  /visibility              — toggle current user's opt-in (rate-limited)
//   GET  /team-scores             — full-roster lead operational view
//
// Privacy invariants enforced at this layer:
//   I1: GET /leaderboard returns only opted-in analysts (filter in service)
//   I2: PUT /visibility writes ONLY req.user.id's row (route hard-codes
//       the userId from the authenticated session; no body-supplied
//       target user accepted)
//   I5: GET /team-scores bypasses opt-in but is gated to lead/admin
//
// Rate limiting: PUT /visibility is per-user 50/hr to prevent rapid-toggle
// abuse (the cache bust is cheap but logged actions add audit-log churn).
// keyGenerator uses req.user.id rather than the default IP, so a shared-
// office IP doesn't bucket multiple users together.

const visibilityToggleLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 50,
  message: { error: 'RATE_LIMIT_EXCEEDED',
    message: 'Too many visibility toggle requests. Please try again later.' },
  keyGenerator: (req) => (req.user && req.user.id) || ipKeyGenerator(req.ip),
  standardHeaders: true,
  legacyHeaders: false,
});

router.get('/leaderboard', (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 10;
    const entries = helperPay.getLeaderboard(limit);
    res.json({ entries, limit });
  } catch (err) {
    if (err.code) {
      return sendServiceError(res, err);
    }
    logger.error('helper-pay leaderboard read failed', {
      userId: req.user && req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

router.get('/me/visibility', (req, res) => {
  try {
    const result = helperPay.getVisibility(req.user.id);
    res.json(result);
  } catch (err) {
    if (err.code) {
      return sendServiceError(res, err);
    }
    logger.error('helper-pay visibility read failed', {
      userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

router.put('/visibility', visibilityToggleLimiter, (req, res) => {
  try {
    const body = req.body || {};
    if (typeof body.optIn !== 'boolean') {
      return res.status(400).json({ error: 'BAD_REQUEST',
        message: 'body must include optIn as a boolean' });
    }
    // Privacy invariant I2: hard-code the userId from the authenticated
    // session. Any body field claiming to target another user is ignored.
    const result = helperPay.setVisibility(req.user.id, body.optIn);

    // Explicit audit_log row for this privacy-sensitive event, in
    // addition to the auditMiddleware's automatic API-action row.
    // event_type LEADERBOARD_OPT_IN_FLIPPED is queryable for forensic
    // and compliance review.
    try {
      auditLog(
        req.user.id,
        'LEADERBOARD_OPT_IN_FLIPPED',
        JSON.stringify({ optIn: result.optIn }),
        req.ip || null
      );
    } catch (auditErr) {
      // Audit log failure must not fail the request; the canonical
      // state change (users.leaderboard_opt_in) is already committed.
      logger.warn('helper-pay visibility audit-log write failed',
        { userId: req.user.id, error: auditErr.message });
    }

    res.json(result);
  } catch (err) {
    if (err.code) {
      return sendServiceError(res, err);
    }
    logger.error('helper-pay visibility write failed', {
      userId: req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

router.get('/team-scores', (req, res) => {
  if (!isLeadOrAdmin(req)) {
    return res.status(403).json({ error: 'FORBIDDEN',
      message: 'team-scores requires lead or admin role' });
  }
  try {
    const entries = helperPay.getTeamScores();
    res.json({ entries });
  } catch (err) {
    if (err.code) {
      return sendServiceError(res, err);
    }
    logger.error('helper-pay team-scores read failed', {
      userId: req.user && req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// R3h-pt2 — Sock-puppet review queue endpoints
// ════════════════════════════════════════════════════════════════════════════
//
// Two new endpoints supporting the lead's sock-puppet review workflow:
//
//   GET  /flagged-ratings           — list currently-flagged ratings
//   POST /flagged-ratings/:id/decide — confirm fraud OR dismiss flag
//
// Both endpoints are lead/admin-only (the recognition leaderboard is a
// management surface; an analyst reviewing flags against their peers
// would defeat the whole point of the protection). The auditMiddleware
// writes a generic API-action row on each call; these handlers ALSO
// write explicit audit_log rows with event_type
// LEADERBOARD_SOCKPUPPET_CONFIRMED or LEADERBOARD_SOCKPUPPET_DISMISSED
// so the audit trail is queryable by event type for forensic and
// compliance review.

router.get('/flagged-ratings', (req, res) => {
  if (!isLeadOrAdmin(req)) {
    return res.status(403).json({ error: 'FORBIDDEN',
      message: 'flagged-ratings review requires lead or admin role' });
  }
  try {
    const entries = helperPay.getFlaggedRatings();
    res.json({ entries });
  } catch (err) {
    if (err.code) {
      return sendServiceError(res, err);
    }
    logger.error('helper-pay flagged-ratings read failed', {
      userId: req.user && req.user.id, error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

router.post('/flagged-ratings/:ratingId/decide', (req, res) => {
  if (!isLeadOrAdmin(req)) {
    return res.status(403).json({ error: 'FORBIDDEN',
      message: 'flagged-ratings decisions require lead or admin role' });
  }
  try {
    const body = req.body || {};
    if (typeof body.confirmFraud !== 'boolean') {
      return res.status(400).json({ error: 'BAD_REQUEST',
        message: 'body must include confirmFraud as a boolean' });
    }
    const note = typeof body.note === 'string' ? body.note.slice(0, 500) : null;
    const result = helperPay.decideFlaggedRating(
      req.params.ratingId,
      req.user.id,
      body.confirmFraud,
      note
    );

    // Explicit audit_log row with the right event_type for queryable
    // forensic review. Includes the rating id, decider, decision,
    // reversal ledger id (if any), and the lead-supplied note.
    try {
      auditLog(
        req.user.id,
        body.confirmFraud
          ? 'LEADERBOARD_SOCKPUPPET_CONFIRMED'
          : 'LEADERBOARD_SOCKPUPPET_DISMISSED',
        JSON.stringify({
          ratingId: req.params.ratingId,
          reversalLedgerId: result.reversalLedgerId || null,
          note: note || null,
        }),
        req.ip || null
      );
    } catch (auditErr) {
      // Audit log failure must not fail the request; the canonical
      // state change is already committed.
      logger.warn('helper-pay flagged-rating decide audit-log write failed',
        { userId: req.user.id, ratingId: req.params.ratingId,
          error: auditErr.message });
    }

    res.json(result);
  } catch (err) {
    if (err.code) {
      return sendServiceError(res, err);
    }
    logger.error('helper-pay flagged-rating decide failed', {
      userId: req.user && req.user.id,
      ratingId: req.params.ratingId,
      error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR' });
  }
});

module.exports = router;

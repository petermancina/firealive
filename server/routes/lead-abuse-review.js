// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Lead Abuse Review API — Team-Lead only
//
// Serves abuse cases to the Team Lead on the Management Console. Mounted behind
// authMiddleware(['lead']); a router-level guard ALSO re-checks role === 'lead'
// so the route fails closed regardless of how it is mounted.
//
// The server NEVER decrypts flag content. Each flag's sealed note and sealed
// offending content are stored as opaque multi-recipient envelopes (the shared
// abuse-seal module's FAS2 format); this API hands them back as base64 and the
// Management Console opens them client-side with the lead's own private key,
// which never leaves the lead's device. Identity reveal follows the policy: a
// lead or admin who is a party is shown by real name; an analyst is ONLY ever a
// pseudonym.
//
// Reviewable target types are 'peer_session' and 'board_post' (both
// analyst-to-analyst). The store is append-only and non-deletable -- a lead may
// only mark a case resolved with a structured verdict.
//
//   GET  /cases             — list reviewable cases (metadata only)
//   GET  /cases/:id         — one case: metadata + opaque sealed note/content (base64)
//   POST /cases/:id/resolve — mark a case resolved (verdict + rationale note)
//   GET  /patterns          — metadata-only behavioral patterns (repeat/escalation/retaliation)
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// Both reviewable flag target types. Each case's sealed content is opaque to the
// server -- it was sealed on the flagger's device to the active Team-Lead
// recipient set, and only a lead with the matching private key can open it.
const REVIEWABLE_TARGET_TYPES = ['peer_session', 'board_post'];
const REVIEWABLE_IN = REVIEWABLE_TARGET_TYPES.map(() => '?').join(', ');

const MAX_RESOLUTION_NOTE = 4000;

// Identity reveal. A lead (or admin) who is a party is shown by real name; an
// analyst -- or any other role -- is ONLY ever a pseudonym to the reviewing lead.
// The UUID is exposed so a lead can correlate repeat cases without ever learning
// an analyst's real name (which lives only in the lead's offline map).
function revealParty(db, userId, pseudonymAtSeal) {
  if (!userId) return { id: null, role: null, label: 'unknown' };
  const u = db.prepare('SELECT id, role, name, pseudonym FROM users WHERE id = ?').get(userId);
  if (!u) return { id: userId, role: null, label: pseudonymAtSeal || 'former user' };
  if (u.role === 'lead' || u.role === 'admin') {
    return { id: u.id, role: u.role, name: u.name, label: u.name };
  }
  const pseudo = pseudonymAtSeal || u.pseudonym || null;
  return { id: u.id, role: u.role, pseudonym: pseudo, label: pseudo || 'analyst' };
}

// Defense in depth: EVERY endpoint on this router serves the Team Lead ONLY. The
// mount (index.js) already role-gates; this router-level guard makes the route
// fail closed regardless of how it is mounted, and means any future endpoint
// added here is lead-gated by default.
router.use((req, res, next) => {
  if (!req.user || req.user.role !== 'lead') {
    auditLog(req.user && req.user.id, 'ABUSE_REVIEW_DENIED', `role ${req.user && req.user.role}: not a lead`, req.ip);
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
});

// GET /cases — reviewable cases (metadata only; no content).
router.get('/cases', (req, res) => {
  let db;
  try {
    db = getDb();
    const flags = db.prepare(
      `SELECT id, target_type, flagger_user_id, flagged_user_id, tier, created_at, resolved_at, resolved_by, determination
         FROM peer_abuse_flags
        WHERE target_type IN (${REVIEWABLE_IN})
        ORDER BY (resolved_at IS NOT NULL), tier DESC, created_at DESC`
    ).all(...REVIEWABLE_TARGET_TYPES);

    const cases = flags.map((f) => {
      const v = db.prepare(
        'SELECT flagger_pseudonym_at_seal, accused_pseudonym_at_seal FROM peer_abuse_evidence_vault WHERE flag_id = ?'
      ).get(f.id);
      return {
        id: f.id,
        targetType: f.target_type,
        tier: f.tier,
        createdAt: f.created_at,
        resolved: !!f.resolved_at,
        resolvedAt: f.resolved_at || null,
        determination: f.resolved_at ? (f.determination || null) : null,
        flagger: revealParty(db, f.flagger_user_id, v && v.flagger_pseudonym_at_seal),
        accused: revealParty(db, f.flagged_user_id, v && v.accused_pseudonym_at_seal),
      };
    });
    return res.json({ cases });
  } catch (err) {
    logger.error('Lead abuse review: failed to list cases', { error: err.message });
    return res.status(500).json({ error: 'failed to list cases' });
  } finally {
    if (db) db.close();
  }
});

// GET /cases/:id — one case with the opaque sealed note + content (base64).
router.get('/cases/:id', (req, res) => {
  let db;
  try {
    db = getDb();
    const f = db.prepare(
      `SELECT * FROM peer_abuse_flags WHERE id = ? AND target_type IN (${REVIEWABLE_IN})`
    ).get(req.params.id, ...REVIEWABLE_TARGET_TYPES);
    if (!f) return res.status(404).json({ error: 'case not found' });

    const v = db.prepare(
      `SELECT sealed_content_encrypted, context_encrypted, flagger_pseudonym_at_seal, accused_pseudonym_at_seal, sealed_at
         FROM peer_abuse_evidence_vault WHERE flag_id = ?`
    ).get(f.id);

    auditLog(req.user.id, 'ABUSE_REVIEW_VIEWED', `case ${f.id}, tier ${f.tier}`, req.ip);
    return res.json({
      case: {
        id: f.id,
        targetType: f.target_type,
        tier: f.tier,
        createdAt: f.created_at,
        resolved: !!f.resolved_at,
        resolvedAt: f.resolved_at || null,
        resolutionNote: f.resolved_at ? (f.resolution_note || null) : null,
        determination: f.resolved_at ? (f.determination || null) : null,
        flagger: revealParty(db, f.flagger_user_id, v && v.flagger_pseudonym_at_seal),
        accused: revealParty(db, f.flagged_user_id, v && v.accused_pseudonym_at_seal),
        // OPAQUE sealed envelopes -- the server cannot read these. The Management
        // Console opens them client-side with the lead's own private key.
        sealedNote: f.content_encrypted ? Buffer.from(f.content_encrypted).toString('base64') : null,
        sealedContent: v && v.sealed_content_encrypted ? Buffer.from(v.sealed_content_encrypted).toString('base64') : null,
        sealedContext: v && v.context_encrypted ? Buffer.from(v.context_encrypted).toString('base64') : null,
        sealedAt: v ? v.sealed_at : null,
      },
    });
  } catch (err) {
    logger.error('Lead abuse review: failed to read case', { error: err.message });
    return res.status(500).json({ error: 'failed to read case' });
  } finally {
    if (db) db.close();
  }
});

// POST /cases/:id/resolve — mark a case resolved with the lead's verdict + note.
// One-shot: the 409 below blocks any second resolution; there is no
// re-determination path by design. The verdict is stored on the flag row, never
// written to the audit log.
router.post('/cases/:id/resolve', (req, res) => {
  const { note, determination } = req.body || {};
  let db;
  try {
    db = getDb();
    const f = db.prepare(
      `SELECT * FROM peer_abuse_flags WHERE id = ? AND target_type IN (${REVIEWABLE_IN})`
    ).get(req.params.id, ...REVIEWABLE_TARGET_TYPES);
    if (!f) return res.status(404).json({ error: 'case not found' });
    if (f.resolved_at) return res.status(409).json({ error: 'case already resolved' });

    const DETERMINATIONS = ['substantiated', 'not_substantiated', 'inconclusive'];
    if (!DETERMINATIONS.includes(determination)) {
      return res.status(400).json({ error: `determination must be one of: ${DETERMINATIONS.join(', ')}` });
    }
    const rationale = (typeof note === 'string') ? note.trim() : '';
    if (!rationale) return res.status(400).json({ error: 'a rationale note is required' });
    if (rationale.length > MAX_RESOLUTION_NOTE) return res.status(400).json({ error: 'rationale note too long' });

    db.prepare(
      "UPDATE peer_abuse_flags SET resolved_at = datetime('now'), resolved_by = ?, resolution_note = ?, determination = ? WHERE id = ?"
    ).run(req.user.id, rationale, determination, f.id);

    auditLog(req.user.id, 'ABUSE_REVIEW_RESOLVED', `case ${f.id}, tier ${f.tier}`, req.ip);
    return res.json({ id: f.id, resolved: true, determination });
  } catch (err) {
    logger.error('Lead abuse review: failed to resolve case', { error: err.message });
    return res.status(500).json({ error: 'failed to resolve case' });
  } finally {
    if (db) db.close();
  }
});

// GET /patterns — metadata-only behavioral patterns (repeat_offender / escalation
// / retaliation) over reviewable flags. flagCount and maxTier are computed from
// the pattern's involved REVIEWABLE flags. Identities follow the reveal policy.
router.get('/patterns', (req, res) => {
  let db;
  try {
    db = getDb();
    const patterns = db.prepare(
      "SELECT * FROM peer_abuse_patterns ORDER BY (acknowledged_at IS NOT NULL), created_at DESC"
    ).all();

    const out = [];
    for (const pat of patterns) {
      let ids = [];
      try { ids = JSON.parse(pat.involved_flag_ids || '[]'); } catch (e) { ids = []; }

      const involved = [];
      let maxTier = 0;
      for (const fid of ids) {
        const f = db.prepare(
          `SELECT id, tier FROM peer_abuse_flags WHERE id = ? AND target_type IN (${REVIEWABLE_IN})`
        ).get(fid, ...REVIEWABLE_TARGET_TYPES);
        if (!f) continue; // not a reviewable target type
        involved.push(f.id);
        if (f.tier > maxTier) maxTier = f.tier;
      }
      if (involved.length === 0) continue;

      out.push({
        id: pat.id,
        patternType: pat.pattern_type,
        severity: pat.severity,
        flagCount: involved.length,
        maxTier,
        windowStart: pat.window_start,
        windowEnd: pat.window_end,
        acknowledged: !!pat.acknowledged_at,
        subject: revealParty(db, pat.subject_user_id, null),
        counterpart: pat.counterpart_user_id ? revealParty(db, pat.counterpart_user_id, null) : null,
        involvedFlagIds: involved,
      });
    }
    return res.json({ patterns: out });
  } catch (err) {
    logger.error('Lead abuse review: failed to list patterns', { error: err.message });
    return res.status(500).json({ error: 'failed to list patterns' });
  } finally {
    if (db) db.close();
  }
});

module.exports = router;

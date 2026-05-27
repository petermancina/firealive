// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Abuse Review API (U3 PR E, Model B) — reviewer-only
//
// Serves abuse cases to the independent abuse_reviewer ONLY. Mounted (E5) behind
// authMiddleware(['abuse_reviewer']); every handler ALSO re-checks access with
// canReview() (role + not-a-party + scope) so no single guard is load-bearing.
//
// The server NEVER decrypts flag content. For lead_chat (Model B) the sealed note
// and the sealed offending message are stored as opaque boxes; this API hands
// them back as base64 and the Abuse Review Console (PR F) opens them client-side
// with the abuse-review private key. Identity reveal follows the policy: a lead
// who is a party is shown by real name; an analyst is ONLY ever a pseudonym.
//
// Reviewable target types are limited to 'lead_chat' for now. Peer/board flags
// stay under Model A / MC review until the PR G cutover, which re-seals them to
// Model B and widens REVIEWABLE_TARGET_TYPES here. Serving them before then would
// hand the console undecryptable bytes and double-surface cases still in the MC.
//
//   GET  /cases            — list reviewable cases the reviewer may access (metadata only)
//   GET  /cases/:id        — one case: metadata + opaque sealed note/content (base64)
//   POST /cases/:id/resolve — mark a case resolved (reviewer disposition note)
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { canReview, REVIEWER_ROLE } = require('../services/abuse-reviewer-access');

// All three flag target types are reviewed here, by the independent Abuse Review
// Console ONLY. lead_chat was Model B from the start (PR D); peer_session and
// board_post were re-sealed to Model B and removed from MC review in the PR G
// cutover (see server/db/reseal-abuse-flags.js), so all three are now reviewer-
// only and the server cannot read any of them.
const REVIEWABLE_TARGET_TYPES = ['lead_chat', 'peer_session', 'board_post'];
const REVIEWABLE_IN = REVIEWABLE_TARGET_TYPES.map(() => '?').join(', ');

const MAX_RESOLUTION_NOTE = 4000;

// Identity reveal. A lead (or admin) who is a party is shown by real name; an
// analyst — or any other role — is ONLY ever a pseudonym to the reviewer. The
// UUID is exposed so the reviewer can correlate repeat cases without ever
// learning an analyst's real name (which lives only in the lead's offline map).
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

function loadReviewerContext(db, userId) {
  const reviewer = db.prepare('SELECT id, role, active FROM users WHERE id = ?').get(userId);
  const assignments = db.prepare(
    'SELECT scope, team_id, flag_id FROM abuse_reviewer_assignments WHERE reviewer_user_id = ?'
  ).all(userId);
  return { reviewer, assignments };
}

// Defense in depth: EVERY endpoint on this router serves abuse_reviewer ONLY.
// The mount (index.js) already role-gates, and each handler re-checks access via
// canReview, but this router-level guard makes the route fail closed regardless
// of how it is mounted -- and means any future endpoint added here is role-gated
// by default rather than relying on its author to remember the check.
router.use((req, res, next) => {
  if (!req.user || req.user.role !== REVIEWER_ROLE) {
    auditLog(req.user && req.user.id, 'ABUSE_REVIEW_DENIED', `role ${req.user && req.user.role}: not an abuse_reviewer`, req.ip);
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
});

// GET /cases — reviewable cases the reviewer may access (metadata only; no content).
router.get('/cases', (req, res) => {
  let db;
  try {
    db = getDb();
    const { reviewer, assignments } = loadReviewerContext(db, req.user.id);
    const flags = db.prepare(
      `SELECT id, target_type, flagger_user_id, flagged_user_id, tier, created_at, resolved_at, resolved_by
         FROM peer_abuse_flags
        WHERE target_type IN (${REVIEWABLE_IN})
        ORDER BY (resolved_at IS NOT NULL), tier DESC, created_at DESC`
    ).all(...REVIEWABLE_TARGET_TYPES);

    const cases = [];
    for (const f of flags) {
      // teamIds stays [] until a team-membership model exists (E3 note).
      if (!canReview({ reviewer, flag: { ...f, teamIds: [] }, assignments }).allowed) continue;
      const v = db.prepare(
        'SELECT flagger_pseudonym_at_seal, accused_pseudonym_at_seal FROM peer_abuse_evidence_vault WHERE flag_id = ?'
      ).get(f.id);
      cases.push({
        id: f.id,
        targetType: f.target_type,
        tier: f.tier,
        createdAt: f.created_at,
        resolved: !!f.resolved_at,
        resolvedAt: f.resolved_at || null,
        flagger: revealParty(db, f.flagger_user_id, v && v.flagger_pseudonym_at_seal),
        accused: revealParty(db, f.flagged_user_id, v && v.accused_pseudonym_at_seal),
      });
    }
    return res.json({ cases });
  } catch (err) {
    logger.error('Abuse review: failed to list cases', { error: err.message });
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

    const { reviewer, assignments } = loadReviewerContext(db, req.user.id);
    const decision = canReview({ reviewer, flag: { ...f, teamIds: [] }, assignments });
    if (!decision.allowed) {
      auditLog(req.user.id, 'ABUSE_REVIEW_DENIED', `case ${f.id}: ${decision.reason}`, req.ip);
      return res.status(403).json({ error: 'forbidden', reason: decision.reason });
    }

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
        flagger: revealParty(db, f.flagger_user_id, v && v.flagger_pseudonym_at_seal),
        accused: revealParty(db, f.flagged_user_id, v && v.accused_pseudonym_at_seal),
        // OPAQUE sealed boxes — the server cannot read these. The Abuse Review
        // Console opens them client-side with the abuse-review private key.
        sealedNote: f.content_encrypted ? Buffer.from(f.content_encrypted).toString('base64') : null,
        sealedContent: v && v.sealed_content_encrypted ? Buffer.from(v.sealed_content_encrypted).toString('base64') : null,
        sealedContext: v && v.context_encrypted ? Buffer.from(v.context_encrypted).toString('base64') : null,
        sealedAt: v ? v.sealed_at : null,
      },
    });
  } catch (err) {
    logger.error('Abuse review: failed to read case', { error: err.message });
    return res.status(500).json({ error: 'failed to read case' });
  } finally {
    if (db) db.close();
  }
});

// POST /cases/:id/resolve — mark a case resolved with the reviewer's disposition note.
router.post('/cases/:id/resolve', (req, res) => {
  const { note } = req.body || {};
  const noteVal = (typeof note === 'string' && note.length <= MAX_RESOLUTION_NOTE) ? note : '';
  let db;
  try {
    db = getDb();
    const f = db.prepare(
      `SELECT * FROM peer_abuse_flags WHERE id = ? AND target_type IN (${REVIEWABLE_IN})`
    ).get(req.params.id, ...REVIEWABLE_TARGET_TYPES);
    if (!f) return res.status(404).json({ error: 'case not found' });

    const { reviewer, assignments } = loadReviewerContext(db, req.user.id);
    const decision = canReview({ reviewer, flag: { ...f, teamIds: [] }, assignments });
    if (!decision.allowed) {
      auditLog(req.user.id, 'ABUSE_REVIEW_DENIED', `resolve ${f.id}: ${decision.reason}`, req.ip);
      return res.status(403).json({ error: 'forbidden', reason: decision.reason });
    }
    if (f.resolved_at) return res.status(409).json({ error: 'case already resolved' });

    db.prepare(
      "UPDATE peer_abuse_flags SET resolved_at = datetime('now'), resolved_by = ?, resolution_note = ? WHERE id = ?"
    ).run(req.user.id, noteVal, f.id);

    auditLog(req.user.id, 'ABUSE_REVIEW_RESOLVED', `case ${f.id}, tier ${f.tier}`, req.ip);
    return res.json({ id: f.id, resolved: true });
  } catch (err) {
    logger.error('Abuse review: failed to resolve case', { error: err.message });
    return res.status(500).json({ error: 'failed to resolve case' });
  } finally {
    if (db) db.close();
  }
});

// GET /patterns — metadata-only behavioral patterns (repeat_offender / escalation
// / retaliation) the reviewer may see. A pattern surfaces only if the reviewer
// can access at least one of its involved REVIEWABLE flags; flagCount and maxTier
// are computed from the accessible flags ALONE, so a reviewer never learns the
// count/tier of cases outside their scope (e.g. another team's cases). Identities
// follow the reveal policy.
router.get('/patterns', (req, res) => {
  let db;
  try {
    db = getDb();
    const { reviewer, assignments } = loadReviewerContext(db, req.user.id);
    const patterns = db.prepare(
      "SELECT * FROM peer_abuse_patterns ORDER BY (acknowledged_at IS NOT NULL), created_at DESC"
    ).all();

    const out = [];
    for (const pat of patterns) {
      let ids = [];
      try { ids = JSON.parse(pat.involved_flag_ids || '[]'); } catch (e) { ids = []; }

      const accessible = [];
      let maxTier = 0;
      for (const fid of ids) {
        const f = db.prepare(
          `SELECT id, target_type, flagger_user_id, flagged_user_id, tier
             FROM peer_abuse_flags WHERE id = ? AND target_type IN (${REVIEWABLE_IN})`
        ).get(fid, ...REVIEWABLE_TARGET_TYPES);
        if (!f) continue; // not a reviewable target type
        if (!canReview({ reviewer, flag: { ...f, teamIds: [] }, assignments }).allowed) continue;
        accessible.push(f.id);
        if (f.tier > maxTier) maxTier = f.tier;
      }
      if (accessible.length === 0) continue; // nothing in this pattern is accessible

      out.push({
        id: pat.id,
        patternType: pat.pattern_type,
        severity: pat.severity,
        flagCount: accessible.length,           // accessible cases only
        maxTier,                                  // max tier among accessible cases
        windowStart: pat.window_start,
        windowEnd: pat.window_end,
        acknowledged: !!pat.acknowledged_at,
        subject: revealParty(db, pat.subject_user_id, null),
        counterpart: pat.counterpart_user_id ? revealParty(db, pat.counterpart_user_id, null) : null,
        accessibleFlagIds: accessible,            // the cases this reviewer can open
      });
    }
    return res.json({ patterns: out });
  } catch (err) {
    logger.error('Abuse review: failed to list patterns', { error: err.message });
    return res.status(500).json({ error: 'failed to list patterns' });
  } finally {
    if (db) db.close();
  }
});

module.exports = router;

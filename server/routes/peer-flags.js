// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Peer Abuse Flag Routes (Phase 1.4b; U3 PR G cutover)
//
// Tiered abuse flagging for peer skill-share sessions and the peer board. Tiers
// (1 minor, 2 personal attack, 3 urgent) signal SEVERITY to the independent
// reviewer; they no longer escalate identity reveal.
//
// POST /api/peer/flags                       — analyst submits a flag
// GET  /api/peer/flags/review-pending-count  — lead/admin awareness count (no content)
//
// All flag content is sealed on the flagger's device to the active reviewer
// recipient set (the shared abuse-seal module's multi-recipient envelope) before
// it leaves the device; the server stores only opaque sealed envelopes it cannot
// read. Review and resolution happen ONLY in the independent Abuse Review Console
// (server/routes/abuse-review.js), never here and never by team leads -- the MC's
// old list/resolve/pattern endpoints were removed in the PR G cutover.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');
const patternDetector = require('../services/abuse-pattern-detector');
const { canReview } = require('../services/abuse-reviewer-access');

const VALID_TIERS = [1, 2, 3];

// Flags arrive as client-sealed envelopes (base64). A single note/message
// seals to well under MAX_SEALED_B64; the board context bundles a few messages,
// so it gets a larger cap. Shared by all three flag-submission paths.
const MAX_SEALED_B64 = 16384;
const MAX_SEALED_CONTEXT_B64 = 49152;
function isSealedB64(s, maxLen = MAX_SEALED_B64) {
  return typeof s === 'string' && s.length > 0 && s.length <= maxLen && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}

// Notify the assigned reviewer(s) of a new abuse case -- peer session, board
// post, or lead chat alike. Since the PR G cutover all abuse review is handled
// by the independent Abuse Review Console (never by leads: a lead may be the
// accused, and all flag content is reviewer-only sealed), so recipients
// are the abuse_reviewer(s) whose assignment covers this flag AND who are not a
// party to it (canReview). The notification carries metadata only; the sealed
// content is decrypted solely in the Abuse Review Console. notify() is
// synchronous, so each recipient is wrapped individually -- one bad recipient
// must not abort the rest.
function notifyReviewersOfFlag(flagId, tier) {
  const eventType = `abuse_review_case_tier${tier}`;
  const titleByTier = {
    1: 'Abuse review \u2014 minor conduct case',
    2: 'Abuse review \u2014 personal attack case',
    3: 'Abuse review \u2014 URGENT conduct case',
  };
  const bodyByTier = {
    1: 'A tier-1 abuse case was assigned to you. Review it in the Abuse Review Console when you have a moment.',
    2: 'A tier-2 abuse case was assigned to you. Open the Abuse Review Console to decrypt and review the sealed evidence.',
    3: 'A tier-3 abuse case (urgent: slurs, threats, harassment) was assigned to you. Review immediately in the Abuse Review Console.',
  };
  try {
    const db = getDb();
    const flag = db.prepare('SELECT id, flagger_user_id, flagged_user_id FROM peer_abuse_flags WHERE id = ?').get(flagId);
    if (!flag) { db.close(); return; }
    const reviewers = db.prepare("SELECT id, role, active FROM users WHERE role = 'abuse_reviewer'").all();
    const recipients = [];
    for (const rv of reviewers) {
      const assignments = db.prepare(
        'SELECT scope, team_id, flag_id FROM abuse_reviewer_assignments WHERE reviewer_user_id = ?'
      ).all(rv.id);
      if (canReview({ reviewer: rv, flag: { ...flag, teamIds: [] }, assignments }).allowed) {
        recipients.push(rv.id);
      }
    }
    db.close();
    for (const rid of recipients) {
      try {
        notifications.notify({
          recipientId: rid,
          eventType,
          title: titleByTier[tier],
          body: bodyByTier[tier],
          linkTab: 'abuse_review',
          linkParams: JSON.stringify({ flagId, tier }),
        });
      } catch (err) {
        logger.error('Failed to deliver abuse-review flag notification', { error: err.message, recipientId: rid, tier });
      }
    }
  } catch (err) {
    logger.error('Failed to enumerate abuse-review recipients', { error: err.message });
  }
}

// Submit a flag against a board post. The flagger's client seals the note, the
// offending post body, and a small thread-context window to the active reviewer
// recipient set (the shared abuse-seal module's multi-recipient envelope) before
// sending; the server stores those opaque sealed envelopes verbatim and NEVER
// reads them -- only a designated reviewer's Abuse Review Console, which holds
// the reviewer's own private key, can. The accused is still resolved from the
// post row server-side (never trusted from the client): the post's author is
// metadata the flag needs, not content. The post is pulled from the board
// pending review. Flagging is gated on at least one registered abuse-review key
// -- with none, there is no one who could decrypt a flag. encryptTier3 is
// deliberately NOT used here.
function submitBoardFlag(req, res) {
  const { boardPostId, tier, sealedNote, sealedContent, sealedContext } = req.body || {};
  if (!boardPostId || typeof boardPostId !== 'string') {
    return res.status(400).json({ error: 'boardPostId required' });
  }
  if (!VALID_TIERS.includes(tier)) {
    return res.status(400).json({ error: 'tier must be 1, 2, or 3' });
  }
  if (!isSealedB64(sealedContent)) {
    return res.status(400).json({ error: 'sealedContent required (base64 sealed envelope of the post body)' });
  }
  if (!isSealedB64(sealedNote)) {
    return res.status(400).json({ error: 'sealedNote required (base64 sealed envelope of the flagger note)' });
  }
  // Context is optional (a top-level post has no thread context), but if present
  // it must be a valid sealed envelope.
  if (sealedContext !== undefined && sealedContext !== null && !isSealedB64(sealedContext, MAX_SEALED_CONTEXT_B64)) {
    return res.status(400).json({ error: 'sealedContext, if provided, must be a base64 sealed envelope' });
  }

  let flagId;
  try {
    const db = getDb();

    // Gate: a flag can only be reviewed (decrypted) if an abuse-review key is
    // registered, so refuse to seal one into a void.
    const activeKey = db.prepare('SELECT id FROM abuse_review_keys WHERE active = 1 LIMIT 1').get();
    if (!activeKey) {
      db.close();
      return res.status(409).json({ error: 'flagging unavailable: no independent reviewer designated' });
    }

    // Resolve the accused from the post row (author is metadata, not content).
    const post = db.prepare(
      'SELECT id, author_id FROM peer_board_messages WHERE id = ? AND deleted_at IS NULL'
    ).get(boardPostId);
    if (!post) { db.close(); return res.status(404).json({ error: 'board post not found' }); }

    const accusedId = post.author_id;
    if (accusedId === req.user.id) { db.close(); return res.status(400).json({ error: 'cannot flag your own post' }); }

    const flaggerU = db.prepare('SELECT pseudonym FROM users WHERE id = ?').get(req.user.id);
    const accusedU = db.prepare('SELECT pseudonym FROM users WHERE id = ?').get(accusedId);

    flagId = crypto.randomBytes(16).toString('hex');
    const flaggerIp = req.ip || (req.connection && req.connection.remoteAddress) || null;

    // Store the client-sealed envelopes verbatim. content_encrypted holds the sealed
    // note; the vault holds the sealed post body and (if any) the sealed context.
    const noteBox = Buffer.from(sealedNote, 'base64');
    const contentBox = Buffer.from(sealedContent, 'base64');
    const contextBox = isSealedB64(sealedContext, MAX_SEALED_CONTEXT_B64) ? Buffer.from(sealedContext, 'base64') : null;

    const seal = db.transaction(() => {
      db.prepare(`
        INSERT INTO peer_abuse_flags
          (id, target_type, target_id, session_id, flagger_user_id, flagged_user_id, tier, content_encrypted, flagger_ip)
        VALUES (?, 'board_post', ?, NULL, ?, ?, ?, ?, ?)
      `).run(flagId, boardPostId, req.user.id, accusedId, tier, noteBox, flaggerIp);

      db.prepare(`
        INSERT INTO peer_abuse_evidence_vault
          (flag_id, target_type, target_id, sealed_content_encrypted, context_encrypted,
           flagger_user_id, accused_user_id, flagger_pseudonym_at_seal, accused_pseudonym_at_seal, tier_at_seal)
        VALUES (?, 'board_post', ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(flagId, boardPostId, contentBox, contextBox,
             req.user.id, accusedId, flaggerU ? flaggerU.pseudonym : null, accusedU ? accusedU.pseudonym : null, tier);

      db.prepare("UPDATE peer_board_messages SET removed_pending_review = 1, removed_at = datetime('now') WHERE id = ?").run(boardPostId);
    });
    seal();

    try { patternDetector.runForFlag(db, { flaggerId: req.user.id, flaggedId: accusedId }); }
    catch (e) { logger.error('pattern detection failed (board flag)', { error: e.message }); }

    db.close();
  } catch (err) {
    logger.error('Failed to submit board abuse flag', { error: err.message });
    return res.status(500).json({ error: 'failed to submit flag' });
  }

  notifyReviewersOfFlag(flagId, tier);
  auditLog(req.user.id, 'PEER_ABUSE_FLAG_SUBMITTED', `board_post ${(req.body || {}).boardPostId}, tier ${tier}, flag ${flagId}`, req.ip);

  return res.status(201).json({ id: flagId, tier, createdAt: new Date().toISOString() });
}

// Submit a flag against a lead-chat message (sealed reviewer-only). Either
// party may flag the other, so unlike peer flags the accused is NOT required to
// be an analyst -- a lead can be accused. Lead chat is E2EE, so the server can't
// read transport ciphertext; the flagger's client decrypts the offending message
// locally and seals BOTH it and the flagger's note to the active reviewer
// recipient set (the shared abuse-seal module's multi-recipient envelope) before
// sending. The server stores those opaque sealed envelopes verbatim and NEVER
// decrypts them -- only a designated reviewer's Abuse Review Console, which holds
// the reviewer's own private key, can. encryptTier3 is deliberately NOT used here.
//
// Reviewed ONLY by the independent Abuse Review Console (U3 PR F), never by team
// leads (a lead may be the accused): this path does NOT notify leads, and the
// lead-facing GET /flags excludes lead_chat. Flagging is gated on a registered
// abuse-review key -- with none, there is no one who could decrypt a flag.
function submitLeadChatFlag(req, res) {
  const { threadId, tier, sealedNote, sealedContent } = req.body || {};

  if (!threadId || typeof threadId !== 'string') {
    return res.status(400).json({ error: 'threadId required' });
  }
  if (!VALID_TIERS.includes(tier)) {
    return res.status(400).json({ error: 'tier must be 1, 2, or 3' });
  }
  if (!isSealedB64(sealedContent)) {
    return res.status(400).json({ error: 'sealedContent required (base64 sealed envelope of the offending message)' });
  }
  if (!isSealedB64(sealedNote)) {
    return res.status(400).json({ error: 'sealedNote required (base64 sealed envelope of the flagger note)' });
  }

  let flagId;
  try {
    const db = getDb();

    // Gate: a flag can only be reviewed (decrypted) if an abuse-review key is
    // registered, so refuse to seal one into a void.
    const activeKey = db.prepare('SELECT id FROM abuse_review_keys WHERE active = 1 LIMIT 1').get();
    if (!activeKey) {
      db.close();
      return res.status(409).json({ error: 'flagging unavailable: no independent reviewer designated' });
    }

    const thread = db.prepare('SELECT id, analyst_id, lead_id FROM lead_chat_threads WHERE id = ?').get(threadId);
    if (!thread) { db.close(); return res.status(404).json({ error: 'lead-chat thread not found' }); }

    // The flagger must be a participant; the accused is the counterpart. No
    // accused-must-be-analyst guard here -- a lead can be the accused.
    let accusedId = null;
    if (thread.analyst_id === req.user.id) accusedId = thread.lead_id;
    else if (thread.lead_id === req.user.id) accusedId = thread.analyst_id;
    if (!accusedId) { db.close(); return res.status(403).json({ error: 'not a participant in this thread' }); }
    if (accusedId === req.user.id) { db.close(); return res.status(400).json({ error: 'cannot flag yourself' }); }

    const flaggerU = db.prepare('SELECT pseudonym FROM users WHERE id = ?').get(req.user.id);
    const accusedU = db.prepare('SELECT pseudonym FROM users WHERE id = ?').get(accusedId);

    flagId = crypto.randomBytes(16).toString('hex');
    const flaggerIp = req.ip || (req.connection && req.connection.remoteAddress) || null;

    // Store the client-sealed envelopes verbatim. content_encrypted holds the sealed
    // note; the vault's sealed_content_encrypted holds the sealed offending text.
    // Neither is server-decryptable.
    const noteBox = Buffer.from(sealedNote, 'base64');
    const contentBox = Buffer.from(sealedContent, 'base64');

    const seal = db.transaction(() => {
      db.prepare(`
        INSERT INTO peer_abuse_flags
          (id, target_type, target_id, session_id, flagger_user_id, flagged_user_id, tier, content_encrypted, flagger_ip)
        VALUES (?, 'lead_chat', ?, NULL, ?, ?, ?, ?, ?)
      `).run(flagId, threadId, req.user.id, accusedId, tier, noteBox, flaggerIp);

      db.prepare(`
        INSERT INTO peer_abuse_evidence_vault
          (flag_id, target_type, target_id, sealed_content_encrypted, context_encrypted,
           flagger_user_id, accused_user_id, flagger_pseudonym_at_seal, accused_pseudonym_at_seal, tier_at_seal)
        VALUES (?, 'lead_chat', ?, ?, NULL, ?, ?, ?, ?, ?)
      `).run(flagId, threadId, contentBox,
             req.user.id, accusedId, flaggerU ? flaggerU.pseudonym : null, accusedU ? accusedU.pseudonym : null, tier);
    });
    seal();

    db.close();
  } catch (err) {
    logger.error('Failed to submit lead-chat abuse flag', { error: err.message });
    return res.status(500).json({ error: 'failed to submit flag' });
  }

  // Lead-chat abuse is ARC-only -- a lead may be the accused, so leads are never
  // notified here. Instead notify the assigned independent reviewer(s) whose
  // scope covers this case and who are not a party to it (canReview).
  notifyReviewersOfFlag(flagId, tier);

  // No pattern-detector call here: the detector writes to peer_abuse_patterns,
  // which the MC reads, so feeding lead_chat now would surface it to leads. The
  // lead-chat pattern feed lands at the PR G cutover, together with the MC
  // pattern removal. Audit records metadata only.
  auditLog(req.user.id, 'PEER_ABUSE_FLAG_SUBMITTED', `lead_chat ${threadId}, tier ${tier}, flag ${flagId}`, req.ip);

  return res.status(201).json({ id: flagId, tier, createdAt: new Date().toISOString() });
}

// ── POST /api/peer/flags — submit a flag ────────────────────────────────────
//
// Request body (peer-session flag):
//   {
//     sessionId: string (required)  — the peer skill-share session being flagged
//     tier: 1 | 2 | 3 (required)
//     sealedNote: string (required) — base64 sealed envelope of the flagger's note,
//                                     sealed on-device to the abuse-review key
//   }
// The accused is NOT supplied by the client: peer sessions are pseudonymous, so
// the flagger never learns the peer's user id. The server resolves the accused
// as the session counterpart (mirroring the lead-chat handler), which also
// authorizes the flagger as a participant.
//
// Response: { id, tier, createdAt }
//
// Side effects:
//   - Inserts row into peer_abuse_flags with the client-sealed note
//   - Notifies the assigned independent reviewer(s) via the tier event type
//   - Audit logs the flag submission (no content in audit — only metadata)
router.post('/flags', (req, res) => {
  // Board-post flags take a different shape (no session, accused resolved
  // server-side) and seal evidence to the vault -- handle them separately.
  if ((req.body || {}).target_type === 'board_post') {
    return submitBoardFlag(req, res);
  }
  if ((req.body || {}).target_type === 'lead_chat') {
    return submitLeadChatFlag(req, res);
  }

  const { sessionId, tier, sealedNote, sealedContent } = req.body || {};

  if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 200) {
    return res.status(400).json({ error: 'sessionId required (max 200 chars)' });
  }
  if (!VALID_TIERS.includes(tier)) {
    return res.status(400).json({ error: 'tier must be 1, 2, or 3' });
  }
  // The client seals the selected peer-chat messages (sealedContent) and the
  // reporter's note (sealedNote) to the active reviewer recipient set before
  // sending; the server stores the opaque envelopes verbatim and never reads
  // them. sealedContent carries the authentic flagged messages the client
  // copied from the session -- it is required so a peer-session flag can never
  // be submitted as a note alone (no unverifiable, typed-only accusations).
  if (!isSealedB64(sealedContent)) {
    return res.status(400).json({ error: 'sealedContent required (base64 sealed envelope of the selected peer-chat messages)' });
  }
  if (!isSealedB64(sealedNote)) {
    return res.status(400).json({ error: 'sealedNote required (base64 sealed envelope of the flagger note)' });
  }

  let flagId;
  try {
    const db = getDb();

    // Gate: a flag can only be reviewed (decrypted) if an abuse-review key is
    // registered, so refuse to seal one into a void.
    const activeKey = db.prepare('SELECT id FROM abuse_review_keys WHERE active = 1 LIMIT 1').get();
    if (!activeKey) {
      db.close();
      return res.status(409).json({ error: 'flagging unavailable: no independent reviewer designated' });
    }

    // Resolve the accused from the session: the flagger must be a participant,
    // and the accused is the counterpart. Peer sessions are pseudonymous, so the
    // client cannot (and must not) name the peer -- the server resolves it,
    // mirroring the lead-chat handler. Peer skill-share is analyst-to-analyst.
    const session = db.prepare('SELECT id, helper_id, seeker_id FROM peer_sessions WHERE id = ?').get(sessionId);
    if (!session) { db.close(); return res.status(404).json({ error: 'peer session not found' }); }
    let accusedId = null;
    if (session.helper_id === req.user.id) accusedId = session.seeker_id;
    else if (session.seeker_id === req.user.id) accusedId = session.helper_id;
    if (!accusedId) { db.close(); return res.status(403).json({ error: 'not a participant in this session' }); }
    if (accusedId === req.user.id) { db.close(); return res.status(400).json({ error: 'cannot flag yourself' }); }

    const flaggerU = db.prepare('SELECT pseudonym FROM users WHERE id = ?').get(req.user.id);
    const accusedU = db.prepare('SELECT pseudonym FROM users WHERE id = ?').get(accusedId);

    // Store the client-sealed envelopes verbatim. content_encrypted holds the
    // sealed note; the vault's sealed_content_encrypted holds the sealed
    // authentic messages the reporter selected. Neither is server-decryptable.
    const noteBox = Buffer.from(sealedNote, 'base64');
    const contentBox = Buffer.from(sealedContent, 'base64');

    flagId = crypto.randomBytes(16).toString('hex');
    const flaggerIp = req.ip || req.connection?.remoteAddress || null;

    const seal = db.transaction(() => {
      db.prepare(`
        INSERT INTO peer_abuse_flags
          (id, target_type, target_id, session_id, flagger_user_id, flagged_user_id, tier, content_encrypted, flagger_ip)
        VALUES (?, 'peer_session', NULL, ?, ?, ?, ?, ?, ?)
      `).run(flagId, sessionId, req.user.id, accusedId, tier, noteBox, flaggerIp);

      db.prepare(`
        INSERT INTO peer_abuse_evidence_vault
          (flag_id, target_type, target_id, sealed_content_encrypted, context_encrypted,
           flagger_user_id, accused_user_id, flagger_pseudonym_at_seal, accused_pseudonym_at_seal, tier_at_seal)
        VALUES (?, 'peer_session', ?, ?, NULL, ?, ?, ?, ?, ?)
      `).run(flagId, sessionId, contentBox,
             req.user.id, accusedId, flaggerU ? flaggerU.pseudonym : null, accusedU ? accusedU.pseudonym : null, tier);
    });
    seal();

    // Re-evaluate abuse patterns for this pair (advisory; must not block submission).
    try { patternDetector.runForFlag(db, { flaggerId: req.user.id, flaggedId: accusedId }); }
    catch (e) { logger.error('pattern detection failed (session flag)', { error: e.message }); }

    db.close();
  } catch (err) {
    logger.error('Failed to insert peer abuse flag', { error: err.message });
    return res.status(500).json({ error: 'failed to submit flag' });
  }

  // Notify the assigned independent reviewer(s) of the flag.
  notifyReviewersOfFlag(flagId, tier);

  auditLog(req.user.id, 'PEER_ABUSE_FLAG_SUBMITTED', `tier ${tier}, flag ${flagId}`, req.ip);

  return res.status(201).json({
    id: flagId,
    tier,
    createdAt: new Date().toISOString(),
  });
});

// GET /api/peer/flags/review-pending-count -- awareness-only count for the MC.
// After the PR G cutover the MC no longer reviews abuse (the independent Abuse
// Review Console does). This read-only count lets a lead/admin see HOW MANY items
// are pending independent review, with no content, no identities, and no per-item
// detail -- just a number, so management knows the system is handling reports
// without being a review surface. Counts all unresolved flags (every target type
// is reviewer-only once the cutover completes).
router.get('/review-pending-count', (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const db = getDb();
  try {
    const row = db.prepare('SELECT COUNT(*) AS n FROM peer_abuse_flags WHERE resolved_at IS NULL').get();
    return res.json({ count: row ? row.n : 0 });
  } finally {
    db.close();
  }
});

module.exports = router;

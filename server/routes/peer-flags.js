// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Peer Abuse Flag Routes (Phase 1.4b)
//
// Tiered abuse flagging for peer skill-share sessions. Three tiers:
//   1 — Minor (tone, dismissiveness, mild rudeness). No identity reveal.
//   2 — Personal attack (insult, mockery). Flagged peer's identity revealed.
//   3 — Urgent (slurs, threats, harassment). Both identities revealed; HR loop.
//
// POST /api/peer/flags                  — analyst submits a flag
// GET  /api/peer/flags                  — lead/admin lists flags (commit 5)
// POST /api/peer/flags/:id/resolve      — lead/admin resolves a flag (commit 5)
//
// All flag content is encrypted with Tier-3 AES-256-GCM. The server stores
// ciphertext only. Decryption happens at read time when a lead with the right
// role reviews flags.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { decryptTier3 } = require('../services/encryption');
const notifications = require('../services/notifications');
const patternDetector = require('../services/abuse-pattern-detector');
const { canReview } = require('../services/abuse-reviewer-access');

const VALID_TIERS = [1, 2, 3];

// Model B flags arrive as client-sealed boxes (base64). A single note/message
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
// accused, and peer/board content is now reviewer-only Model B), so recipients
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

// Submit a flag against a board post (Model B, reviewer-only). The flagger's
// client seals the note, the offending post body, and a small thread-context
// window to the abuse-review PUBLIC key before sending; the server stores those
// opaque boxes verbatim and NEVER reads them -- only the Abuse Review Console,
// which holds the private key, can. The accused is still resolved from the post
// row server-side (never trusted from the client): the post's author is metadata
// the flag needs, not content. The post is pulled from the board pending review.
// Flagging is gated on a registered abuse-review key -- with none, there is no
// one who could decrypt a flag. encryptTier3 is deliberately NOT used here.
function submitBoardFlag(req, res) {
  const { boardPostId, tier, sealedNote, sealedContent, sealedContext } = req.body || {};
  if (!boardPostId || typeof boardPostId !== 'string') {
    return res.status(400).json({ error: 'boardPostId required' });
  }
  if (!VALID_TIERS.includes(tier)) {
    return res.status(400).json({ error: 'tier must be 1, 2, or 3' });
  }
  if (!isSealedB64(sealedContent)) {
    return res.status(400).json({ error: 'sealedContent required (base64 sealed box of the post body)' });
  }
  if (!isSealedB64(sealedNote)) {
    return res.status(400).json({ error: 'sealedNote required (base64 sealed box of the flagger note)' });
  }
  // Context is optional (a top-level post has no thread context), but if present
  // it must be a valid sealed box.
  if (sealedContext !== undefined && sealedContext !== null && !isSealedB64(sealedContext, MAX_SEALED_CONTEXT_B64)) {
    return res.status(400).json({ error: 'sealedContext, if provided, must be a base64 sealed box' });
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

    // Store the client-sealed boxes verbatim. content_encrypted holds the sealed
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

// Submit a flag against a lead-chat message (Model B, reviewer-only). Either
// party may flag the other, so unlike peer flags the accused is NOT required to
// be an analyst -- a lead can be accused. Lead chat is E2EE, so the server can't
// read transport ciphertext; the flagger's client decrypts the offending message
// locally and seals BOTH it and the flagger's note to the abuse-review PUBLIC key
// (libsodium sealed box) before sending. The server stores those opaque sealed
// boxes verbatim and NEVER decrypts them -- only the Abuse Review Console, which
// holds the private key, can. encryptTier3 is deliberately NOT used here.
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
    return res.status(400).json({ error: 'sealedContent required (base64 sealed box of the offending message)' });
  }
  if (!isSealedB64(sealedNote)) {
    return res.status(400).json({ error: 'sealedNote required (base64 sealed box of the flagger note)' });
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

    // Store the client-sealed boxes verbatim. content_encrypted holds the sealed
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

  // Lead-chat abuse is ABC-only -- a lead may be the accused, so leads are never
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
// Request body (peer-session flag; Model B):
//   {
//     sessionId: string (required)  — the peer skill-share session being flagged
//     tier: 1 | 2 | 3 (required)
//     sealedNote: string (required) — base64 sealed box of the flagger's note,
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

  const { sessionId, tier, sealedNote } = req.body || {};

  if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 200) {
    return res.status(400).json({ error: 'sessionId required (max 200 chars)' });
  }
  if (!VALID_TIERS.includes(tier)) {
    return res.status(400).json({ error: 'tier must be 1, 2, or 3' });
  }
  // Model B: the client seals its note to the abuse-review key before sending;
  // the server stores the opaque box verbatim and never reads it.
  if (!isSealedB64(sealedNote)) {
    return res.status(400).json({ error: 'sealedNote required (base64 sealed box of the flagger note)' });
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

    // Store the client-sealed note verbatim (peer flags have no evidence vault).
    const noteBox = Buffer.from(sealedNote, 'base64');

    flagId = crypto.randomBytes(16).toString('hex');
    const flaggerIp = req.ip || req.connection?.remoteAddress || null;

    db.prepare(`
      INSERT INTO peer_abuse_flags
        (id, session_id, flagger_user_id, flagged_user_id, tier, content_encrypted, flagger_ip)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(flagId, sessionId, req.user.id, accusedId, tier, noteBox, flaggerIp);

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

// ── GET /api/peer/flags — list flags for review ─────────────────────────────
//
// Lead/admin only. Query parameters:
//   ?status=open|resolved|all   (default: open)
//   ?tier=1|2|3                 (optional filter)
//
// Response: { flags: [...] }
//
// Each flag includes decrypted content. Identity reveal follows tier rules:
//   - Tier 1: flagger and flagged are both anonymized to "Analyst-XXX"
//   - Tier 2: flagged peer's real name is shown; flagger remains anonymized
//   - Tier 3: both real names are shown (reciprocal accountability)
//
// The reveal happens at read time so a lead who skims a tier-1 flag never
// even sees encrypted-but-decryptable identity data — the response itself
// omits the names.
router.get('/flags', (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const status = ['open', 'resolved', 'all'].includes(req.query.status) ? req.query.status : 'open';
  const tierFilter = ['1', '2', '3'].includes(req.query.tier) ? parseInt(req.query.tier, 10) : null;

  // Lead-chat flags are reviewed only by the independent Abuse Review Console
  // (U3 PR F), never by leads -- a lead can be the accused. Exclude them from
  // this lead-facing list, which also keeps them out of the MC open-flag badge
  // (the MC counts this same response). Start the WHERE with that exclusion and
  // append the status/tier filters with AND.
  let where = " WHERE f.target_type != 'lead_chat'";
  const params = [];
  if (status === 'open') where += ' AND f.resolved_at IS NULL';
  else if (status === 'resolved') where += ' AND f.resolved_at IS NOT NULL';
  if (tierFilter !== null) {
    where += ' AND f.tier = ?';
    params.push(tierFilter);
  }

  let rows;
  try {
    const db = getDb();
    rows = db.prepare(`
      SELECT
        f.id, f.target_type, f.target_id, f.session_id,
        f.flagger_user_id, f.flagged_user_id, f.tier,
        f.content_encrypted, f.flagger_ip, f.created_at,
        f.resolved_at, f.resolved_by, f.resolution_note,
        flagger.name AS flagger_name,
        flagged.name AS flagged_name,
        resolver.name AS resolver_name,
        v.sealed_content_encrypted, v.context_encrypted,
        b.removed_pending_review AS board_removed,
        b.restored_at AS board_restored,
        b.deleted_at AS board_deleted
      FROM peer_abuse_flags f
      LEFT JOIN users flagger ON flagger.id = f.flagger_user_id
      LEFT JOIN users flagged ON flagged.id = f.flagged_user_id
      LEFT JOIN users resolver ON resolver.id = f.resolved_by
      LEFT JOIN peer_abuse_evidence_vault v ON v.flag_id = f.id
      LEFT JOIN peer_board_messages b ON b.id = f.target_id AND f.target_type = 'board_post'
      ${where}
      ORDER BY f.tier DESC, f.created_at DESC
    `).all(...params);
    db.close();
  } catch (err) {
    logger.error('Failed to list peer abuse flags', { error: err.message });
    return res.status(500).json({ error: 'failed to list flags' });
  }

  const flags = rows.map((row) => {
    let content;
    try {
      content = decryptTier3(row.content_encrypted);
    } catch (err) {
      logger.error('Failed to decrypt flag content', { flagId: row.id, error: err.message });
      content = '[decryption failed — Tier-3 key may be misconfigured]';
    }

    // Board flags carry their evidence in the vault; decrypt it for review.
    // The flagged content and its context are shown at every tier (they are the
    // evidence) -- only the party identities below follow the tier reveal.
    const isBoard = row.target_type === 'board_post';
    let sealedContent, context, boardStatus;
    if (isBoard) {
      if (row.sealed_content_encrypted) {
        try { sealedContent = decryptTier3(row.sealed_content_encrypted); }
        catch (e) { sealedContent = '[decryption failed]'; }
      }
      if (row.context_encrypted) {
        try { context = JSON.parse(decryptTier3(row.context_encrypted)); }
        catch (e) { context = null; }
      }
      boardStatus = row.board_deleted ? 'deleted'
        : row.board_removed ? 'removed_pending_review'
        : row.board_restored ? 'restored' : 'live';
    }

    // Identity reveal by tier. Anonymize names that this tier should not reveal.
    // We use first 8 chars of the user ID as the anonymous suffix so the lead
    // can still distinguish multiple anonymous flaggers/flagged in the same view.
    const flaggerAnon = `Analyst-${row.flagger_user_id.slice(0, 8)}`;
    const flaggedAnon = `Analyst-${row.flagged_user_id ? row.flagged_user_id.slice(0, 8) : 'unknown'}`;

    let flaggerDisplay, flaggedDisplay;
    if (row.tier === 1) {
      flaggerDisplay = flaggerAnon;
      flaggedDisplay = flaggedAnon;
    } else if (row.tier === 2) {
      flaggerDisplay = flaggerAnon;
      flaggedDisplay = row.flagged_name || flaggedAnon;
    } else {
      // tier 3 — both revealed
      flaggerDisplay = row.flagger_name || flaggerAnon;
      flaggedDisplay = row.flagged_name || flaggedAnon;
    }

    return {
      id: row.id,
      targetType: row.target_type,
      targetId: row.target_id,
      sessionId: row.session_id,
      tier: row.tier,
      content,
      ...(isBoard ? { sealedContent, context, boardStatus } : {}),
      flaggerDisplay,
      flaggedDisplay,
      flaggerIp: row.tier >= 2 ? row.flagger_ip : null, // tier-1 IPs not exposed
      createdAt: row.created_at,
      resolvedAt: row.resolved_at,
      resolvedBy: row.resolver_name,
      resolutionNote: row.resolution_note,
    };
  });

  return res.json({ flags });
});

// ── POST /api/peer/flags/:id/resolve — resolve a flag ───────────────────────
//
// Lead/admin only. Marks a flag as resolved with an optional note.
//
// Request body:
//   { note?: string (max 2000 chars), action?: 'dismiss' | 'uphold' | 'escalate' }
//
// For a board-post flag, action drives the post: 'dismiss' restores it to the
// board (removed_pending_review back to 0, restored_at set); 'uphold' and
// 'escalate' leave it removed. The evidence vault is never touched either way,
// so the sealed record survives a dismissal. For a session flag, action is
// ignored. When action is omitted on a board flag it defaults to 'uphold'.
//
// Response: { id, resolvedAt, resolvedBy, note, action }
router.post('/flags/:id/resolve', (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const flagId = req.params.id;
  if (!flagId || typeof flagId !== 'string' || flagId.length > 64) {
    return res.status(400).json({ error: 'invalid flag id' });
  }

  const note = (req.body && typeof req.body.note === 'string') ? req.body.note.slice(0, 2000) : null;
  const VALID_ACTIONS = ['dismiss', 'uphold', 'escalate'];
  const requestedAction = (req.body && VALID_ACTIONS.includes(req.body.action)) ? req.body.action : null;
  const now = new Date().toISOString();

  let updated;
  try {
    const db = getDb();
    const existing = db.prepare("SELECT id, resolved_at, tier, target_type, target_id FROM peer_abuse_flags WHERE id = ?").get(flagId);
    if (!existing) {
      db.close();
      return res.status(404).json({ error: 'flag not found' });
    }
    if (existing.resolved_at) {
      db.close();
      return res.status(409).json({ error: 'flag already resolved' });
    }

    const isBoard = existing.target_type === 'board_post';
    // Board flags default to 'uphold' (leave the post removed) unless the lead
    // explicitly dismisses; session flags have no post action.
    const effectiveAction = isBoard ? (requestedAction || 'uphold') : null;

    const apply = db.transaction(() => {
      db.prepare(`
        UPDATE peer_abuse_flags
        SET resolved_at = ?, resolved_by = ?, resolution_note = ?
        WHERE id = ?
      `).run(now, req.user.id, note, flagId);

      if (isBoard && existing.target_id && effectiveAction === 'dismiss') {
        // Restore the post to the board. The vault keeps the sealed evidence.
        db.prepare("UPDATE peer_board_messages SET removed_pending_review = 0, restored_at = ? WHERE id = ?").run(now, existing.target_id);
      }
      // 'uphold' and 'escalate' leave removed_pending_review = 1 (post stays off the board).
    });
    apply();

    updated = { tier: existing.tier, isBoard, action: effectiveAction };
    db.close();
  } catch (err) {
    logger.error('Failed to resolve peer abuse flag', { flagId, error: err.message });
    return res.status(500).json({ error: 'failed to resolve flag' });
  }

  auditLog(
    req.user.id,
    'PEER_ABUSE_FLAG_RESOLVED',
    `flag ${flagId}, tier ${updated.tier}${updated.isBoard ? ', action ' + updated.action : ''}`,
    req.ip
  );

  return res.json({
    id: flagId,
    resolvedAt: now,
    resolvedBy: req.user.id,
    note,
    action: updated.action,
  });
});

// ── GET /api/peer/flags/patterns ── detected abuse patterns ─────────────
//
// Lead/admin only. ?status=open|acknowledged|all (default open). Identities
// follow the same tiered reveal as flags, keyed on the pattern's max tier:
// tier 1 anonymizes both, tier 2 reveals the subject (offender), tier 3 reveals
// both. The detector only ever stores UUIDs; names are resolved here at read
// time and withheld per tier.
router.get('/flags/patterns', (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const status = ['open', 'acknowledged', 'all'].includes(req.query.status) ? req.query.status : 'open';
  let where = '';
  if (status === 'open') where = ' WHERE p.acknowledged_at IS NULL';
  else if (status === 'acknowledged') where = ' WHERE p.acknowledged_at IS NOT NULL';

  let rows;
  try {
    const db = getDb();
    rows = db.prepare(`
      SELECT
        p.id, p.pattern_type, p.subject_user_id, p.counterpart_user_id,
        p.involved_flag_ids, p.flag_count, p.max_tier, p.window_start, p.window_end,
        p.severity, p.acknowledged_at, p.acknowledged_by, p.created_at,
        subj.name AS subject_name,
        cpt.name AS counterpart_name,
        ackr.name AS ack_name
      FROM peer_abuse_patterns p
      LEFT JOIN users subj ON subj.id = p.subject_user_id
      LEFT JOIN users cpt ON cpt.id = p.counterpart_user_id
      LEFT JOIN users ackr ON ackr.id = p.acknowledged_by
      ${where}
      ORDER BY (p.severity = 'urgent') DESC, p.created_at DESC
    `).all();
    db.close();
  } catch (err) {
    logger.error('Failed to list abuse patterns', { error: err.message });
    return res.status(500).json({ error: 'failed to list patterns' });
  }

  const patterns = rows.map((row) => {
    const subjAnon = `Analyst-${(row.subject_user_id || 'unknown').slice(0, 8)}`;
    const cptAnon = row.counterpart_user_id ? `Analyst-${row.counterpart_user_id.slice(0, 8)}` : null;
    let subjectDisplay, counterpartDisplay;
    if (row.max_tier === 1) {
      subjectDisplay = subjAnon;
      counterpartDisplay = cptAnon;
    } else if (row.max_tier === 2) {
      subjectDisplay = row.subject_name || subjAnon;
      counterpartDisplay = cptAnon;
    } else {
      subjectDisplay = row.subject_name || subjAnon;
      counterpartDisplay = row.counterpart_user_id ? (row.counterpart_name || cptAnon) : null;
    }
    let involvedFlagIds = [];
    try { involvedFlagIds = JSON.parse(row.involved_flag_ids || '[]'); } catch (e) { involvedFlagIds = []; }
    return {
      id: row.id,
      patternType: row.pattern_type,
      subjectDisplay,
      counterpartDisplay,
      flagCount: row.flag_count,
      maxTier: row.max_tier,
      severity: row.severity,
      windowStart: row.window_start,
      windowEnd: row.window_end,
      involvedFlagIds,
      acknowledgedAt: row.acknowledged_at,
      acknowledgedBy: row.ack_name,
      createdAt: row.created_at,
    };
  });

  return res.json({ patterns });
});

// ── POST /api/peer/flags/patterns/:id/acknowledge ─────────────────────
router.post('/flags/patterns/:id/acknowledge', (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const patternId = req.params.id;
  if (!patternId || typeof patternId !== 'string' || patternId.length > 64) {
    return res.status(400).json({ error: 'invalid pattern id' });
  }
  const now = new Date().toISOString();
  try {
    const db = getDb();
    const existing = db.prepare("SELECT id, acknowledged_at FROM peer_abuse_patterns WHERE id = ?").get(patternId);
    if (!existing) { db.close(); return res.status(404).json({ error: 'pattern not found' }); }
    if (existing.acknowledged_at) { db.close(); return res.status(409).json({ error: 'pattern already acknowledged' }); }
    db.prepare("UPDATE peer_abuse_patterns SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ?").run(now, req.user.id, patternId);
    db.close();
  } catch (err) {
    logger.error('Failed to acknowledge abuse pattern', { patternId, error: err.message });
    return res.status(500).json({ error: 'failed to acknowledge pattern' });
  }
  auditLog(req.user.id, 'PEER_ABUSE_PATTERN_ACKNOWLEDGED', `pattern ${patternId}`, req.ip);
  return res.json({ id: patternId, acknowledgedAt: now, acknowledgedBy: req.user.id });
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

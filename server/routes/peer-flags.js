// ═══════════════════════════════════════════════════════════════
// FIREALIVE — Peer Abuse Flag Routes (Team-Lead review)
//
// Tiered abuse flagging for peer skill-share sessions and the peer board. Tiers
// (1 minor, 2 personal attack, 3 urgent) signal SEVERITY to the Team Lead; they
// do not escalate identity reveal.
//
// POST /api/peer/flags                       — analyst submits a flag
// GET  /api/peer/flags/review-pending-count  — lead/admin awareness count (no content)
//
// All flag content is sealed on the flagger's device to the active Team-Lead
// recipient set (the shared abuse-seal module's multi-recipient envelope) before
// it leaves the device; the server stores only opaque sealed envelopes it cannot
// read. Review and resolution happen in the Management Console, where a Team Lead
// decrypts the sealed evidence with their own device-held key. Peer-session and
// board flagging are analyst-to-analyst.
// ═══════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');
const patternDetector = require('../services/abuse-pattern-detector');
const avChain = require('../services/abuse-vault-chain');
const { signReportCanonical, getInstanceLabel } = require('../services/report-signer');

const VALID_TIERS = [1, 2, 3];

// Flags arrive as client-sealed envelopes (base64). A single note/message
// seals to well under MAX_SEALED_B64; the board context bundles a few messages,
// so it gets a larger cap. Shared by both flag-submission paths.
const MAX_SEALED_B64 = 16384;
const MAX_SEALED_CONTEXT_B64 = 49152;
function isSealedB64(s, maxLen = MAX_SEALED_B64) {
  return typeof s === 'string' && s.length > 0 && s.length <= maxLen && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}

// Notify the Team Lead(s) of a new abuse case -- peer session or board post.
// Abuse review is handled by the Team Lead on the Management Console; peer and
// board flags are analyst-to-analyst, so a lead is not a party. Recipients are
// the active leads, with the flagger and the accused excluded defensively so a
// lead never reviews a case they are party to. The notification carries metadata
// only; the sealed content is decrypted solely in the Management Console.
// notify() is synchronous, so each recipient is wrapped individually -- one bad
// recipient must not abort the rest.
function notifyLeadsOfFlag(flagId, tier) {
  const eventType = `abuse_review_case_tier${tier}`;
  const titleByTier = {
    1: 'Abuse review: minor conduct case',
    2: 'Abuse review: personal attack case',
    3: 'Abuse review: URGENT conduct case',
  };
  const bodyByTier = {
    1: 'A tier-1 abuse case is pending review. Open the abuse review tab in the Management Console when you have a moment.',
    2: 'A tier-2 abuse case is pending review. Open the abuse review tab in the Management Console to decrypt and review the sealed evidence.',
    3: 'A tier-3 abuse case (urgent: slurs, threats, harassment) is pending review. Review it immediately in the Management Console.',
  };
  try {
    const db = getDb();
    const flag = db.prepare('SELECT id, flagger_user_id, flagged_user_id FROM peer_abuse_flags WHERE id = ?').get(flagId);
    if (!flag) { db.close(); return; }
    const leads = db.prepare(
      "SELECT id FROM users WHERE role = 'lead' AND active = 1 AND id != ? AND id != ?"
    ).all(flag.flagger_user_id, flag.flagged_user_id);
    db.close();
    for (const lead of leads) {
      try {
        notifications.notify({
          recipientId: lead.id,
          eventType,
          title: titleByTier[tier],
          body: bodyByTier[tier],
          linkTab: 'abuse_review',
          linkParams: JSON.stringify({ flagId, tier }),
        });
      } catch (err) {
        logger.error('Failed to deliver abuse-review flag notification', { error: err.message, recipientId: lead.id, tier });
      }
    }
  } catch (err) {
    logger.error('Failed to enumerate abuse-review recipients', { error: err.message });
  }
}

// Submit a flag against a board post. The flagger's client seals the note, the
// offending post body, and a small thread-context window to the active Team-Lead
// recipient set (the shared abuse-seal module's multi-recipient envelope) before
// sending; the server stores those opaque sealed envelopes verbatim and NEVER
// reads them -- only a Team Lead's Management Console, which holds
// the lead's own private key, can. The accused is still resolved from the
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
      return res.status(409).json({ error: 'flagging unavailable: no review key registered' });
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

      try { avChain.appendEntry(db, { eventType: 'VAULT_SEALED', flagId, actorUserId: req.user.id }); }
      catch (avErr) { logger.warn('peer-flags: VAULT_SEALED chain append failed; will backfill at next boot', { error: avErr.message }); }

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

  notifyLeadsOfFlag(flagId, tier);

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
//   - Notifies the Team Lead(s) via the tier event type
//   - Audit logs the flag submission (no content in audit — only metadata)
router.post('/', (req, res) => {
  // Board-post flags take a different shape (no session, accused resolved
  // server-side) and seal evidence to the vault -- handle them separately.
  if ((req.body || {}).target_type === 'board_post') {
    return submitBoardFlag(req, res);
  }

  const { sessionId, tier, sealedNote, sealedContent } = req.body || {};

  if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 200) {
    return res.status(400).json({ error: 'sessionId required (max 200 chars)' });
  }
  if (!VALID_TIERS.includes(tier)) {
    return res.status(400).json({ error: 'tier must be 1, 2, or 3' });
  }
  // The client seals the selected peer-chat messages (sealedContent) and the
  // reporter's note (sealedNote) to the active Team-Lead recipient set before
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
      return res.status(409).json({ error: 'flagging unavailable: no review key registered' });
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

      try { avChain.appendEntry(db, { eventType: 'VAULT_SEALED', flagId, actorUserId: req.user.id }); }
      catch (avErr) { logger.warn('peer-flags: VAULT_SEALED chain append failed; will backfill at next boot', { error: avErr.message }); }
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

  // Notify the Team Lead(s) of the flag.
  notifyLeadsOfFlag(flagId, tier);


  return res.status(201).json({
    id: flagId,
    tier,
    createdAt: new Date().toISOString(),
  });
});

// ── POST /api/peer/flags/:id/sign-record — sign a flagger's export record ────
//
// After a flag is submitted, the flagger's client
// may build a one-shot, local PDF record of the submission as the flagger's
// personal backup (for example if the vault is later lost). This endpoint signs
// a canonical payload describing that submission so a Team Lead can
// later confirm an exported record is genuine and corresponds to a real flag --
// without the server ever seeing the flagged content.
//
// The server derives flag_uuid, target_type and submitted_at from the flag row
// (authoritative); only content_sha256 -- the SHA-256 of the authentic sealed
// content the client holds -- is supplied by the client. The Team Lead later
// recomputes that hash from the content they decrypt from the vault, so a
// client cannot forge it undetected.
//
// Flagger-only: anyone who is not the flag's flagger gets 404 (not 403), so the
// existence of a flag is never confirmed by probing. Writes NO MC-readable
// audit entry -- a flagger-identifying trace would defeat the zero-trace design.
router.post('/:id/sign-record', (req, res) => {
  const flagId = req.params.id;
  const contentSha = (req.body || {}).content_sha256;
  if (typeof contentSha !== 'string' || !/^[0-9a-f]{64}$/i.test(contentSha)) {
    return res.status(400).json({ error: 'content_sha256 (64 hex chars) required' });
  }

  let result;
  try {
    const db = getDb();
    const flag = db.prepare(
      'SELECT id, target_type, flagger_user_id, created_at FROM peer_abuse_flags WHERE id = ?'
    ).get(flagId);
    // Hide existence from everyone but the flagger.
    if (!flag || flag.flagger_user_id !== req.user.id) {
      db.close();
      return res.status(404).json({ error: 'not found' });
    }

    const payload = {
      flag_uuid: flag.id,
      target_type: flag.target_type,
      submitted_at: flag.created_at,
      instance_label: getInstanceLabel(db),
      content_sha256: contentSha.toLowerCase(),
    };
    const descriptor = signReportCanonical({
      db,
      reportType: 'abuse_flag',
      subjectRef: flag.id,
      payload,
      metadata: null,
    });
    db.close();

    result = {
      payload,
      canonical: descriptor.canonical,
      reportSha256: descriptor.sha256,
      signatureB64: descriptor.signatureB64,
      keyFingerprint: descriptor.keyFingerprint,
      instanceLabel: descriptor.instanceLabel,
      signedAt: descriptor.signedAt,
    };
  } catch (err) {
    logger.error('Failed to sign abuse-flag export record', { error: err.message });
    return res.status(500).json({ error: 'failed to sign record' });
  }

  // Deliberately no auditLog: signing an export must leave no flagger-identifying trace.
  return res.status(200).json(result);
});

// GET /api/peer/flags/review-pending-count -- awareness count for management.
// The Team Lead reviews abuse cases in the Management Console; this read-only
// count lets a lead/admin see HOW MANY items are pending review, with no
// content, no identities, and no per-item detail -- just a number. Counts all
// unresolved flags.
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

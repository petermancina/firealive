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
const { encryptTier3, decryptTier3 } = require('../services/encryption');
const notifications = require('../services/notifications');
const patternDetector = require('../services/abuse-pattern-detector');

const MAX_FLAG_CONTENT_LENGTH = 10000; // 10KB — enough for pasted chat excerpts
const VALID_TIERS = [1, 2, 3];

// Notify all leads/admins of a new flag. Shared by the session and board
// paths. notify() is synchronous (returns an id, throws on error), so each
// recipient is wrapped individually -- one bad recipient must not abort the
// rest, and there is no promise to .catch().
function notifyLeadsOfFlag(flagId, tier, source) {
  const eventType = `peer_abuse_flag_tier${tier}`;
  const prefix = source === 'board' ? 'Peer board' : 'Peer chat';
  const titleByTier = {
    1: `${prefix} \u2014 minor conduct flag`,
    2: `${prefix} \u2014 personal attack flag`,
    3: `${prefix} \u2014 URGENT conduct flag`,
  };
  const bodyByTier = {
    1: 'An analyst submitted a tier-1 flag for minor conduct issues. Review in the Peer Conduct tab when you have a moment.',
    2: 'An analyst submitted a tier-2 flag for a personal attack. The flagged peer\'s identity is visible to you. Review the Peer Conduct tab.',
    3: 'An analyst submitted a tier-3 flag for urgent conduct (slurs, threats, harassment). Both identities are revealed. HR intervention is recommended. Review immediately in the Peer Conduct tab.',
  };
  try {
    const db = getDb();
    const leads = db.prepare("SELECT id FROM users WHERE role IN ('lead', 'admin')").all();
    db.close();
    for (const lead of leads) {
      try {
        notifications.notify({
          recipientId: lead.id,
          eventType,
          title: titleByTier[tier],
          body: bodyByTier[tier],
          linkTab: 'peer_conduct',
          linkParams: JSON.stringify({ flagId, tier }),
        });
      } catch (err) {
        logger.error('Failed to deliver peer abuse flag notification', { error: err.message, recipientId: lead.id, tier });
      }
    }
  } catch (err) {
    logger.error('Failed to enumerate notification recipients', { error: err.message });
  }
}

// Submit a flag against a board post. The accused is resolved from the post
// row on the server (never trusted from the client); the flagged content and a
// small context window are sealed into the evidence vault, and the post is
// pulled from the board pending review. The flag's content_encrypted holds the
// flagger's note; the vault's sealed_content_encrypted holds the post body.
function submitBoardFlag(req, res) {
  const { boardPostId, tier, content } = req.body || {};
  if (!boardPostId || typeof boardPostId !== 'string') {
    return res.status(400).json({ error: 'boardPostId required' });
  }
  if (!VALID_TIERS.includes(tier)) {
    return res.status(400).json({ error: 'tier must be 1, 2, or 3' });
  }
  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'content required' });
  }
  if (content.length > MAX_FLAG_CONTENT_LENGTH) {
    return res.status(400).json({ error: `content max ${MAX_FLAG_CONTENT_LENGTH} chars` });
  }

  let flagId;
  try {
    const db = getDb();

    const post = db.prepare(`
      SELECT id, author_id, display_anonymous, content_encrypted, parent_id, thread_root_id, created_at
      FROM peer_board_messages WHERE id = ? AND deleted_at IS NULL
    `).get(boardPostId);
    if (!post) { db.close(); return res.status(404).json({ error: 'board post not found' }); }

    const accusedId = post.author_id;
    if (accusedId === req.user.id) { db.close(); return res.status(400).json({ error: 'cannot flag your own post' }); }

    // Context carries only display labels (pseudonym or "Anonymous"), never a
    // bystander's UUID. The accused's UUID is captured separately, below.
    const labelFor = (pp) => {
      if (pp.display_anonymous) return 'Anonymous';
      const u = db.prepare('SELECT pseudonym FROM users WHERE id = ?').get(pp.author_id);
      return (u && u.pseudonym) ? u.pseudonym : 'Analyst';
    };
    const decryptBody = (pp) => { try { return decryptTier3(pp.content_encrypted).toString('utf8'); } catch (e) { return ''; } };

    const flaggedBody = decryptBody(post);
    const context = [];
    const rootId = post.thread_root_id || post.id;
    if (rootId !== post.id) {
      const root = db.prepare('SELECT author_id, display_anonymous, content_encrypted, created_at FROM peer_board_messages WHERE id = ?').get(rootId);
      if (root) context.push({ role: 'root', label: labelFor(root), content: decryptBody(root), createdAt: root.created_at });
    }
    if (post.parent_id && post.parent_id !== rootId) {
      const parent = db.prepare('SELECT author_id, display_anonymous, content_encrypted, created_at FROM peer_board_messages WHERE id = ?').get(post.parent_id);
      if (parent) context.push({ role: 'parent', label: labelFor(parent), content: decryptBody(parent), createdAt: parent.created_at });
    }
    context.push({ role: 'flagged', label: labelFor(post), content: flaggedBody, createdAt: post.created_at });

    const flaggerU = db.prepare('SELECT pseudonym FROM users WHERE id = ?').get(req.user.id);
    const accusedU = db.prepare('SELECT pseudonym FROM users WHERE id = ?').get(accusedId);

    flagId = crypto.randomBytes(16).toString('hex');
    const flaggerIp = req.ip || (req.connection && req.connection.remoteAddress) || null;

    const seal = db.transaction(() => {
      db.prepare(`
        INSERT INTO peer_abuse_flags
          (id, target_type, target_id, session_id, flagger_user_id, flagged_user_id, tier, content_encrypted, flagger_ip)
        VALUES (?, 'board_post', ?, NULL, ?, ?, ?, ?, ?)
      `).run(flagId, boardPostId, req.user.id, accusedId, tier, encryptTier3(content), flaggerIp);

      db.prepare(`
        INSERT INTO peer_abuse_evidence_vault
          (flag_id, target_type, target_id, sealed_content_encrypted, context_encrypted,
           flagger_user_id, accused_user_id, flagger_pseudonym_at_seal, accused_pseudonym_at_seal, tier_at_seal)
        VALUES (?, 'board_post', ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(flagId, boardPostId, encryptTier3(flaggedBody), encryptTier3(JSON.stringify(context)),
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

  notifyLeadsOfFlag(flagId, tier, 'board');
  auditLog(req.user.id, 'PEER_ABUSE_FLAG_SUBMITTED', `board_post ${(req.body || {}).boardPostId}, tier ${tier}, flag ${flagId}`, req.ip);

  return res.status(201).json({ id: flagId, tier, createdAt: new Date().toISOString() });
}

// ── POST /api/peer/flags — submit a flag ────────────────────────────────────
//
// Request body:
//   {
//     sessionId: string (required)  — peer chat session being flagged
//     flaggedUserId: string (required) — the peer being flagged
//     tier: 1 | 2 | 3 (required)
//     content: string (required, max 10KB) — copy/paste of abusive text or description
//   }
//
// Response: { id, tier, createdAt }
//
// Side effects:
//   - Inserts row into peer_abuse_flags with encrypted content
//   - Notifies leads/admins via the appropriate tier event type
//   - Audit logs the flag submission (no content in audit — only metadata)
router.post('/flags', (req, res) => {
  // Board-post flags take a different shape (no session, accused resolved
  // server-side) and seal evidence to the vault -- handle them separately.
  if ((req.body || {}).target_type === 'board_post') {
    return submitBoardFlag(req, res);
  }

  const { sessionId, flaggedUserId, tier, content } = req.body || {};

  if (!sessionId || typeof sessionId !== 'string' || sessionId.length > 200) {
    return res.status(400).json({ error: 'sessionId required (max 200 chars)' });
  }
  if (!flaggedUserId || typeof flaggedUserId !== 'string') {
    return res.status(400).json({ error: 'flaggedUserId required' });
  }
  if (!VALID_TIERS.includes(tier)) {
    return res.status(400).json({ error: 'tier must be 1, 2, or 3' });
  }
  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'content required' });
  }
  if (content.length > MAX_FLAG_CONTENT_LENGTH) {
    return res.status(400).json({ error: `content max ${MAX_FLAG_CONTENT_LENGTH} chars` });
  }

  // Self-flagging is not meaningful — reject it.
  if (flaggedUserId === req.user.id) {
    return res.status(400).json({ error: 'cannot flag yourself' });
  }

  let flagId;
  try {
    const db = getDb();

    // Verify the flagged user exists and is an analyst (you can only flag analysts
    // since only analysts participate in peer skill-share). Defense in depth —
    // the AC UI already filters this, but the server should never trust the client.
    const flagged = db.prepare("SELECT id, role FROM users WHERE id = ?").get(flaggedUserId);
    if (!flagged) {
      db.close();
      return res.status(404).json({ error: 'flagged user not found' });
    }
    if (flagged.role !== 'analyst') {
      db.close();
      return res.status(400).json({ error: 'can only flag analysts' });
    }

    // Encrypt the content. encryptTier3 returns a single Buffer (iv + tag + ciphertext).
    const ciphertext = encryptTier3(content);

    flagId = crypto.randomBytes(16).toString('hex');
    const flaggerIp = req.ip || req.connection?.remoteAddress || null;

    db.prepare(`
      INSERT INTO peer_abuse_flags
        (id, session_id, flagger_user_id, flagged_user_id, tier, content_encrypted, flagger_ip)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(flagId, sessionId, req.user.id, flaggedUserId, tier, ciphertext, flaggerIp);

    // Re-evaluate abuse patterns for this pair (advisory; must not block submission).
    try { patternDetector.runForFlag(db, { flaggerId: req.user.id, flaggedId: flaggedUserId }); }
    catch (e) { logger.error('pattern detection failed (session flag)', { error: e.message }); }

    db.close();
  } catch (err) {
    logger.error('Failed to insert peer abuse flag', { error: err.message });
    return res.status(500).json({ error: 'failed to submit flag' });
  }

  // Notify leads/admins of the flag (shared with the board path).
  notifyLeadsOfFlag(flagId, tier, 'chat');

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

  let where = '';
  const params = [];
  if (status === 'open') where += ' WHERE f.resolved_at IS NULL';
  else if (status === 'resolved') where += ' WHERE f.resolved_at IS NOT NULL';
  if (tierFilter !== null) {
    where += where ? ' AND' : ' WHERE';
    where += ' f.tier = ?';
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

module.exports = router;

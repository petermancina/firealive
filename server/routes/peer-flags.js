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
const { encryptTier3 } = require('../services/encryption');
const notifications = require('../services/notifications');

const MAX_FLAG_CONTENT_LENGTH = 10000; // 10KB — enough for pasted chat excerpts
const VALID_TIERS = [1, 2, 3];

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

    db.close();
  } catch (err) {
    logger.error('Failed to insert peer abuse flag', { error: err.message });
    return res.status(500).json({ error: 'failed to submit flag' });
  }

  // Notify leads/admins. Recipients are determined by getEligibleRecipients()
  // in services/notifications.js, which filters by event-type preferences and
  // honors mandatoryInApp for tier 3.
  const eventType = `peer_abuse_flag_tier${tier}`;
  const titleByTier = {
    1: 'Peer chat — minor conduct flag',
    2: 'Peer chat — personal attack flag',
    3: 'Peer chat — URGENT conduct flag',
  };
  const bodyByTier = {
    1: 'An analyst submitted a tier-1 flag for minor conduct issues. Review in the Peer Conduct tab when you have a moment.',
    2: 'An analyst submitted a tier-2 flag for a personal attack. The flagged peer\'s identity is visible to you. Review the Peer Conduct tab.',
    3: 'An analyst submitted a tier-3 flag for urgent conduct (slurs, threats, harassment). Both identities are revealed. HR intervention is recommended. Review immediately in the Peer Conduct tab.',
  };

  // Notify all leads/admins. notify() handles role filtering via EVENT_TYPES
  // recipients implicit in preferences/registration.
  try {
    const db = getDb();
    const leads = db.prepare("SELECT id FROM users WHERE role IN ('lead', 'admin')").all();
    db.close();
    for (const lead of leads) {
      // notify() is synchronous — it returns a notification id and throws on
      // error — so each call is wrapped in its own try/catch. One bad recipient
      // must not abort delivery to the rest, and there is no promise to .catch().
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
        logger.error('Failed to deliver peer abuse flag notification', {
          error: err.message,
          recipientId: lead.id,
          tier,
        });
      }
    }
  } catch (err) {
    // Notification failure must not undo the flag submission. Log and continue.
    logger.error('Failed to enumerate notification recipients', { error: err.message });
  }

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
        f.id, f.session_id, f.flagger_user_id, f.flagged_user_id, f.tier,
        f.content_encrypted, f.flagger_ip, f.created_at,
        f.resolved_at, f.resolved_by, f.resolution_note,
        flagger.name AS flagger_name,
        flagged.name AS flagged_name,
        resolver.name AS resolver_name
      FROM peer_abuse_flags f
      LEFT JOIN users flagger ON flagger.id = f.flagger_user_id
      LEFT JOIN users flagged ON flagged.id = f.flagged_user_id
      LEFT JOIN users resolver ON resolver.id = f.resolved_by
      ${where}
      ORDER BY f.tier DESC, f.created_at DESC
    `).all(...params);
    db.close();
  } catch (err) {
    logger.error('Failed to list peer abuse flags', { error: err.message });
    return res.status(500).json({ error: 'failed to list flags' });
  }

  const { decryptTier3 } = require('../services/encryption');

  const flags = rows.map((row) => {
    let content;
    try {
      content = decryptTier3(row.content_encrypted);
    } catch (err) {
      logger.error('Failed to decrypt flag content', { flagId: row.id, error: err.message });
      content = '[decryption failed — Tier-3 key may be misconfigured]';
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
      sessionId: row.session_id,
      tier: row.tier,
      content,
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
//   { note?: string (max 2000 chars) }
//
// Response: { id, resolvedAt, resolvedBy, note }
router.post('/flags/:id/resolve', (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const flagId = req.params.id;
  if (!flagId || typeof flagId !== 'string' || flagId.length > 64) {
    return res.status(400).json({ error: 'invalid flag id' });
  }

  const note = (req.body && typeof req.body.note === 'string') ? req.body.note.slice(0, 2000) : null;
  const now = new Date().toISOString();

  let updated;
  try {
    const db = getDb();
    const existing = db.prepare("SELECT id, resolved_at, tier FROM peer_abuse_flags WHERE id = ?").get(flagId);
    if (!existing) {
      db.close();
      return res.status(404).json({ error: 'flag not found' });
    }
    if (existing.resolved_at) {
      db.close();
      return res.status(409).json({ error: 'flag already resolved' });
    }

    db.prepare(`
      UPDATE peer_abuse_flags
      SET resolved_at = ?, resolved_by = ?, resolution_note = ?
      WHERE id = ?
    `).run(now, req.user.id, note, flagId);

    updated = { tier: existing.tier };
    db.close();
  } catch (err) {
    logger.error('Failed to resolve peer abuse flag', { flagId, error: err.message });
    return res.status(500).json({ error: 'failed to resolve flag' });
  }

  auditLog(req.user.id, 'PEER_ABUSE_FLAG_RESOLVED', `flag ${flagId}, tier ${updated.tier}`, req.ip);

  return res.json({
    id: flagId,
    resolvedAt: now,
    resolvedBy: req.user.id,
    note,
  });
});

module.exports = router;

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Peer Support Routes
// Anonymous peer support request queue with:
//   - Exclusion lists (requester can hide request from specific peers)
//   - Mutual identity consent (both parties must opt in to reveal names)
//   - In-person willingness flag
//   - Anti-C2 protections (rate limiting, message size caps, no file transfer)
//
// POST /api/peers/requests          — create support request
// GET  /api/peers/requests          — view available requests (filtered by exclusions)
// POST /api/peers/requests/:id/accept — accept a request (creates chat session)
// POST /api/peers/sessions/:id/consent — signal willingness to reveal identity
// GET  /api/peers/sessions/:id      — get session status (incl. mutual consent state)
// POST /api/peers/sessions/:id/close — close session
//
// R3n: exclusion list now uses pseudonyms (excludePseudonyms in request body),
// not user UUIDs. The AC never sees user UUIDs; it fetches the pseudonym
// list from /api/pseudonyms and submits pseudonyms here. Server resolves
// pseudonyms → user IDs internally. Resolution is anonymity-preserving:
// the server already holds the pseudonym↔UUID mapping in users.pseudonym;
// no NEW privacy surface is created by this resolution.
//
// 50% exclusion cap: at least half the active analyst pool (rounded up
// via ceil) must remain as potential helpers after the exclusion list is
// applied. This prevents triangulation — a help-seeker cannot narrow the
// helper pool to a single identifiable person by excluding everyone else.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');

// Anti-C2: max messages per user per hour
const MAX_MESSAGES_PER_HOUR = 50;
const MAX_MESSAGE_LENGTH = 4096; // 4KB text max

// ── Create Support Request ───────────────────────────────────────────────────
router.post('/requests', (req, res) => {
  const { topic, excludePseudonyms, willingToMeetInPerson } = req.body;

  if (!topic || typeof topic !== 'string' || topic.length > 500) {
    return res.status(400).json({ error: 'topic required (max 500 chars)' });
  }

  // R3n: exclusion list is now pseudonyms (strings), not UUIDs. The AC
  // sees pseudonyms only via /api/pseudonyms and never sees user IDs.
  const requestedPseudonyms = Array.isArray(excludePseudonyms)
    ? excludePseudonyms.filter(p => typeof p === 'string' && p.length > 0).slice(0, 200)
    : [];

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');

    // Resolve pseudonyms → user IDs (server-side; AC never sees IDs).
    // Pseudonyms not matching any active analyst are silently dropped
    // (e.g., the analyst was offboarded between the AC's last /api/pseudonyms
    // fetch and now).
    let resolvedExcludeIds = [];
    if (requestedPseudonyms.length > 0) {
      const placeholders = requestedPseudonyms.map(() => '?').join(',');
      const rows = db.prepare(`
        SELECT id FROM users
        WHERE pseudonym IN (${placeholders})
          AND role = 'analyst'
          AND active = 1
      `).all(...requestedPseudonyms);
      resolvedExcludeIds = rows.map(r => r.id);
    }

    // Enforce 50% exclusion cap: at least half (ceil) of the active analyst
    // pool must remain available as potential helpers after exclusions.
    // Prevents triangulation by narrowing the helper pool to a single person.
    const activeRow = db.prepare(
      "SELECT COUNT(*) AS n FROM users WHERE role = 'analyst' AND active = 1"
    ).get();
    const activeCount = activeRow.n;
    const minRemaining = Math.ceil(activeCount * 0.5);
    const maxExcluded = activeCount - minRemaining;
    if (resolvedExcludeIds.length > maxExcluded) {
      db.close();
      return res.status(400).json({
        error: 'Exclusion list too large',
        detail: `At least ${minRemaining} active analyst${minRemaining === 1 ? '' : 's'} must remain as potential helpers after exclusion. With ${activeCount} active analyst${activeCount === 1 ? '' : 's'} in the pool, you may exclude at most ${maxExcluded}. Resolved exclusion count: ${resolvedExcludeIds.length}.`,
        activeAnalystCount: activeCount,
        maxExcluded,
        attemptedExcluded: resolvedExcludeIds.length,
      });
    }

    const excludeIds = resolvedExcludeIds;

    // Store request — requester identity is encrypted (server knows for routing
    // but never exposes to other analysts)
    db.prepare(`
      INSERT INTO team_config (key, value, updated_by)
      VALUES (?, ?, ?)
    `).run(
      `peer_request_${id}`,
      JSON.stringify({
        id,
        topic: topic.slice(0, 500),
        excludeIds,
        willingToMeet: !!willingToMeetInPerson,
        requesterId: req.user.id, // stored but never exposed
        status: 'open',
        createdAt: new Date().toISOString(),
      }),
      req.user.id
    );

    db.close();
    auditLog(req.user.id, 'PEER_REQUEST_CREATED', 'Anonymous peer support request', req.ip);

    // Broadcast notification to eligible helpers (opt-in event, daily cap 5)
    let notifiedCount = 0;
    let cappedCount = 0;
    try {
      const eligible = notifications.getEligibleRecipients('peer_request_posted', {
        roles: ['analyst', 'lead'],
        activeOnly: true,
        excludeUserIds: [req.user.id, ...excludeIds],
      });
      const dailyCap = notifications.EVENT_TYPES.peer_request_posted.dailyCap || Infinity;

      for (const recipientId of eligible) {
        const todayCount = notifications.getDailySendCount(recipientId, 'peer_request_posted');
        if (todayCount >= dailyCap) { cappedCount++; continue; }
        try {
          notifications.notify({
            recipientId,
            eventType: 'peer_request_posted',
            title: 'New peer support request available',
            body: `An analyst has posted a new peer support request you're eligible to accept. Topic: "${topic.slice(0, 120)}${topic.length > 120 ? '…' : ''}". Open the Peer Skill-Share tab to view available requests.`,
            linkTab: 'peer-share',
            linkParams: { focus: 'requests' },
          });
          notifiedCount++;
        } catch (notifyErr) {
          logger.warn('Peer request post: notify recipient failed (non-fatal)', { recipientId, error: notifyErr.message });
        }
      }
    } catch (broadcastErr) {
      logger.error('Peer request post: broadcast failed (non-fatal)', { error: broadcastErr.message });
    }

    res.status(201).json({ id, status: 'open', notified: notifiedCount, cappedFromBroadcast: cappedCount });
  } catch (err) {
    logger.error('Create peer request error', { error: err.message });
    res.status(500).json({ error: 'Failed to create peer request' });
  }
});

// ── View Available Requests ──────────────────────────────────────────────────
// Each analyst sees only requests where they are NOT on the exclusion list
// and they are not the requester.
router.get('/requests', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare("SELECT value FROM team_config WHERE key LIKE 'peer_request_%'").all();
    db.close();

    const requests = rows
      .map(r => { try { return JSON.parse(r.value); } catch { return null; } })
      .filter(r => r && r.status === 'open')
      // Filter out: requests where this analyst is excluded, or is the requester
      .filter(r => !r.excludeIds.includes(req.user.id) && r.requesterId !== req.user.id)
      // Strip requester identity — return only anonymous data
      .map(r => ({
        id: r.id,
        topic: r.topic,
        willingToMeet: r.willingToMeet,
        createdAt: r.createdAt,
      }));

    res.json({ requests });
  } catch (err) {
    logger.error('List peer requests error', { error: err.message });
    res.status(500).json({ error: 'Failed to list requests' });
  }
});

// ── Accept Request → Create Chat Session ─────────────────────────────────────
router.post('/requests/:id/accept', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`peer_request_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Request not found' }); }

    const request = JSON.parse(row.value);
    if (request.status !== 'open') { db.close(); return res.status(400).json({ error: 'Request already accepted or closed' }); }
    if (request.excludeIds.includes(req.user.id)) { db.close(); return res.status(403).json({ error: 'You are excluded from this request' }); }
    if (request.requesterId === req.user.id) { db.close(); return res.status(400).json({ error: 'Cannot accept your own request' }); }

    // Create session
    const sessionId = crypto.randomBytes(16).toString('hex');
    const session = {
      id: sessionId,
      requestId: request.id,
      requesterId: request.requesterId,
      accepterId: req.user.id,
      requesterConsent: false,  // mutual identity consent
      accepterConsent: false,
      willingToMeet: request.willingToMeet,
      status: 'active',
      createdAt: new Date().toISOString(),
      messageCount: 0,
    };

    // Update request status
    request.status = 'accepted';
    request.sessionId = sessionId;
    db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(request), `peer_request_${req.params.id}`);

    // Store session
    db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(
      `peer_session_${sessionId}`, JSON.stringify(session), req.user.id
    );

    db.close();
    auditLog(req.user.id, 'PEER_SESSION_CREATED', 'Anonymous peer chat session started', req.ip);

    // Notify the seeker (request.requesterId) that someone accepted
    try {
      notifications.notify({
        recipientId: request.requesterId,
        eventType: 'peer_request_accepted',
        title: 'A peer accepted your support request',
        body: `Someone has accepted your peer support request and a session is now active. Their identity remains hidden until both of you consent to reveal it. Open the Peer Skill-Share tab to start the conversation.`,
        linkTab: 'peer-share',
        linkParams: { sessionId, focus: 'session' },
      });
    } catch (notifyErr) {
      logger.warn('Peer accept: notify seeker failed (non-fatal)', { sessionId, requesterId: request.requesterId, error: notifyErr.message });
    }

    res.status(201).json({ sessionId, status: 'active' });
  } catch (err) {
    logger.error('Accept peer request error', { error: err.message });
    res.status(500).json({ error: 'Failed to accept request' });
  }
});

// ── Mutual Identity Consent ──────────────────────────────────────────────────
// Both parties must independently consent to reveal identities.
// Only when BOTH have consented do names become visible.
router.post('/sessions/:id/consent', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`peer_session_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Session not found' }); }

    const session = JSON.parse(row.value);
    if (session.status !== 'active') { db.close(); return res.status(400).json({ error: 'Session is not active' }); }

    // Determine which party is consenting (and which is the OTHER party)
    let firstConsenterId = null;
    if (req.user.id === session.requesterId) {
      session.requesterConsent = true;
      firstConsenterId = session.accepterId;
    } else if (req.user.id === session.accepterId) {
      session.accepterConsent = true;
      firstConsenterId = session.requesterId;
    } else {
      db.close(); return res.status(403).json({ error: 'You are not a participant in this session' });
    }

    db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(session), `peer_session_${req.params.id}`);
    db.close();

    const mutualConsent = session.requesterConsent && session.accepterConsent;
    auditLog(req.user.id, 'PEER_CONSENT', `Identity consent given. Mutual: ${mutualConsent}`, req.ip);

    // If both consented, return both names AND notify the first consenter
    if (mutualConsent) {
      const db2 = getDb();
      const requester = db2.prepare('SELECT name FROM users WHERE id = ?').get(session.requesterId);
      const accepter = db2.prepare('SELECT name FROM users WHERE id = ?').get(session.accepterId);
      db2.close();

      // Notify the OTHER party (the first consenter — they consented earlier and have been waiting)
      const firstConsenterIsRequester = firstConsenterId === session.requesterId;
      const peerName = firstConsenterIsRequester ? accepter?.name : requester?.name;

      try {
        notifications.notify({
          recipientId: firstConsenterId,
          eventType: 'peer_consent_mutual',
          title: 'Identity revealed in your peer session',
          body: peerName
            ? `Your peer in the active support session has consented to reveal their identity. You can now see each other's names. Your peer is ${peerName}. Open the Peer Skill-Share tab to continue.`
            : `Your peer in the active support session has consented to reveal their identity. You can now see each other's names. Open the Peer Skill-Share tab to continue.`,
          linkTab: 'peer-share',
          linkParams: { sessionId: req.params.id, focus: 'session' },
        });
      } catch (notifyErr) {
        logger.warn('Peer consent: notify first consenter failed (non-fatal)', { sessionId: req.params.id, firstConsenterId, error: notifyErr.message });
      }

      return res.json({
        mutualConsent: true,
        requesterName: requester?.name,
        accepterName: accepter?.name,
        message: 'Both parties have consented. Identities are now visible to each other.',
      });
    }

    res.json({ mutualConsent: false, message: 'Your consent recorded. Waiting for the other party.' });
  } catch (err) {
    logger.error('Peer consent error', { error: err.message });
    res.status(500).json({ error: 'Failed to record consent' });
  }
});

// ── Get Session Status ───────────────────────────────────────────────────────
router.get('/sessions/:id', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`peer_session_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Session not found' }); }

    const session = JSON.parse(row.value);

    // Verify participant
    if (req.user.id !== session.requesterId && req.user.id !== session.accepterId) {
      db.close(); return res.status(403).json({ error: 'Not a participant' });
    }

    const isRequester = req.user.id === session.requesterId;
    const mutualConsent = session.requesterConsent && session.accepterConsent;

    const response = {
      id: session.id,
      status: session.status,
      willingToMeet: session.willingToMeet,
      myConsent: isRequester ? session.requesterConsent : session.accepterConsent,
      peerConsent: isRequester ? session.accepterConsent : session.requesterConsent,
      mutualConsent,
      createdAt: session.createdAt,
    };

    // Only reveal names if mutual consent
    if (mutualConsent) {
      const peer = db.prepare('SELECT name FROM users WHERE id = ?').get(
        isRequester ? session.accepterId : session.requesterId
      );
      response.peerName = peer?.name;
    }

    db.close();
    res.json(response);
  } catch (err) {
    logger.error('Get session error', { error: err.message });
    res.status(500).json({ error: 'Failed to get session' });
  }
});

// ── Close Session ────────────────────────────────────────────────────────────
router.post('/sessions/:id/close', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`peer_session_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Session not found' }); }

    const session = JSON.parse(row.value);
    if (req.user.id !== session.requesterId && req.user.id !== session.accepterId) {
      db.close(); return res.status(403).json({ error: 'Not a participant' });
    }

    session.status = 'closed';
    session.closedAt = new Date().toISOString();
    db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(session), `peer_session_${req.params.id}`);
    db.close();

    auditLog(req.user.id, 'PEER_SESSION_CLOSED', `Session ${req.params.id} closed`, req.ip);
    res.json({ ok: true, status: 'closed' });
  } catch (err) {
    logger.error('Close session error', { error: err.message });
    res.status(500).json({ error: 'Failed to close session' });
  }
});

module.exports = router;

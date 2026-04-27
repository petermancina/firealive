// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Peer Support Enhancements
// Adds to the base peer support system:
//   - Helpfulness rating (1-5) after session close
//   - Points tracking for helpers → signals to team lead
//   - Timeout/no-show tracking with re-queue
//   - Abuse flagging (anonymous, attached to session)
//   - Auto-close on inactivity
//   - Team lead scheduling restrictions
//   - Customizable disclaimer
//   - Chat deletion on close (no persistence)
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── Default Disclaimer ───────────────────────────────────────────────────────
const DEFAULT_DISCLAIMER = `PEER SUPPORT CHAT — GUIDELINES & AGREEMENT

This is an anonymous, encrypted peer support channel for SOC analysts. Please read and accept before proceeding.

PURPOSE: This chat is for gaining practical skills and advice to do your job better, to contribute to your team's functioning, and to overcome job-related burnout. It is NOT a psychological counseling session.

ANONYMITY: Your identity is hidden by default. Both parties must independently consent to reveal identities. However, in smaller teams, total anonymity may not be practically achievable — co-workers may be able to infer who is participating.

CONDUCT EXPECTATIONS:
• Engage in respectful, constructive dialogue with sensitivity to what others are experiencing
• Provide practical advice on handling SOC tasks, communication, and workload
• Do not use demeaning, belittling, or abusive language
• Do not reference others' personality, personal background, race, sex, gender, sexuality, nationality, citizenship, immigration status, intelligence, age, or psychological/emotional health in a negative manner
• Do not use expletives — they may not be welcomed by other participants
• Do not circulate rumors, ill-will toward team members or management, or use this channel to vent without seeking constructive solutions
• Do not discuss romantic issues or sexuality
• If what your peer needs is beyond what a cybersecurity analyst can provide, recommend they seek professional help through their EAP or other professional resources

ABUSIVE LANGUAGE: Using abusive language may cause your teammates to stop requesting or providing support through this channel, which affects the entire team. Either party may flag abusive language, which will be tracked by the system. Repeated violations may result in restrictions.

NOT PROFESSIONAL COUNSELING: Your peer analysts are not trained, professional psychologists. This chat is not for the purpose of obtaining psychological counseling. It is for gaining practical skills and support to overcome job-related burnout. If you are experiencing psychological symptoms that require professional counseling, please seek professional support through your organization's Employee Assistance Program or a licensed mental health provider.

NO CHAT PERSISTENCE: When this chat session closes, all messages are permanently deleted. If you need to retain any resources or advice shared, copy the text before closing. There are no exports or persistence of chat content.

AUTO-CLOSE: Sessions will automatically close after 5 minutes of inactivity. You will receive a warning at 3 minutes.

This channel works because everyone commits to making it a legitimate, supportive space. By clicking "I Agree," you accept these guidelines.`;

// ── Get/Set Disclaimer (team lead customizable) ──────────────────────────────
router.get('/disclaimer', (req, res) => {
  try {
    const db = getDb();
    const custom = db.prepare("SELECT value FROM team_config WHERE key = 'peer_disclaimer'").get();
    db.close();

    // The professional counseling notice is always appended and cannot be removed
    const REQUIRED_NOTICE = '\n\nNOT PROFESSIONAL COUNSELING: Your peer analysts are not trained, professional psychologists. This chat is not for the purpose of obtaining psychological counseling. If you are experiencing psychological symptoms that require professional counseling, please seek professional support through your organization\'s Employee Assistance Program or a licensed mental health provider.';

    const disclaimer = custom ? custom.value : DEFAULT_DISCLAIMER;
    const hasRequiredNotice = disclaimer.includes('not trained, professional psychologists');

    res.json({
      disclaimer: hasRequiredNotice ? disclaimer : disclaimer + REQUIRED_NOTICE,
      isCustom: !!custom,
      requiredNoticeIncluded: true,
    });
  } catch (err) {
    logger.error('Get disclaimer error', { error: err.message });
    res.status(500).json({ error: 'Failed to get disclaimer' });
  }
});

router.put('/disclaimer', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can customize the disclaimer' });

  const { disclaimer } = req.body;
  if (!disclaimer || typeof disclaimer !== 'string') return res.status(400).json({ error: 'disclaimer text required' });
  if (disclaimer.length > 10000) return res.status(400).json({ error: 'Disclaimer too long (max 10000 chars)' });

  // Always append the required professional counseling notice
  const REQUIRED_NOTICE = '\n\nNOT PROFESSIONAL COUNSELING: Your peer analysts are not trained, professional psychologists. This chat is not for the purpose of obtaining psychological counseling. If you are experiencing psychological symptoms that require professional counseling, please seek professional support through your organization\'s Employee Assistance Program or a licensed mental health provider.';

  const fullDisclaimer = disclaimer.includes('not trained, professional psychologists')
    ? disclaimer
    : disclaimer + REQUIRED_NOTICE;

  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('peer_disclaimer', ?, ?)").run(fullDisclaimer, req.user.id);
    db.close();
    auditLog(req.user.id, 'PEER_DISCLAIMER_UPDATED', 'Custom disclaimer saved', req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Update disclaimer error', { error: err.message });
    res.status(500).json({ error: 'Failed to update disclaimer' });
  }
});

// ── Rate Session (after close) ───────────────────────────────────────────────
router.post('/sessions/:id/rate', (req, res) => {
  const { rating, wasInPerson } = req.body;
  if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'rating required (1-5)' });

  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`peer_session_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Session not found' }); }

    const session = JSON.parse(row.value);
    if (req.user.id !== session.requesterId) { db.close(); return res.status(403).json({ error: 'Only the requester can rate' }); }

    // Store rating
    session.rating = Math.max(1, Math.min(5, parseInt(rating, 10)));
    session.wasInPerson = !!wasInPerson;
    session.ratedAt = new Date().toISOString();
    db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(session), `peer_session_${req.params.id}`);

    // Award points to helper (stored separately, keyed by helper ID)
    const pointsKey = `peer_points_${session.accepterId}`;
    const existing = db.prepare("SELECT value FROM team_config WHERE key = ?").get(pointsKey);
    const points = existing ? JSON.parse(existing.value) : { total: 0, sessions: 0, avgRating: 0, ratings: [] };
    points.total += session.rating;
    points.sessions += 1;
    points.ratings.push({ sessionId: session.id, rating: session.rating, at: session.ratedAt });
    points.avgRating = Math.round((points.total / points.sessions) * 10) / 10;
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(pointsKey, JSON.stringify(points), req.user.id);

    db.close();
    auditLog(req.user.id, 'PEER_RATED', `session=${req.params.id} rating=${session.rating}`, req.ip);
    res.json({ ok: true, rating: session.rating });
  } catch (err) {
    logger.error('Rate session error', { error: err.message });
    res.status(500).json({ error: 'Failed to rate session' });
  }
});

// ── Flag Abusive Language ────────────────────────────────────────────────────
router.post('/sessions/:id/flag', (req, res) => {
  const { reason } = req.body;
  if (!reason || reason.length > 500) return res.status(400).json({ error: 'reason required (max 500 chars)' });

  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`peer_session_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Session not found' }); }

    const session = JSON.parse(row.value);
    if (req.user.id !== session.requesterId && req.user.id !== session.accepterId) {
      db.close(); return res.status(403).json({ error: 'Not a participant' });
    }

    // Determine who is being flagged (the other party)
    const flaggedUserId = req.user.id === session.requesterId ? session.accepterId : session.requesterId;

    if (!session.flags) session.flags = [];
    session.flags.push({
      by: req.user.id === session.requesterId ? 'requester' : 'accepter', // don't store actual ID in flag
      reason: reason.slice(0, 500),
      at: new Date().toISOString(),
    });

    db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(session), `peer_session_${req.params.id}`);

    // Track flags per user for escalation
    const flagKey = `peer_flags_${flaggedUserId}`;
    const flagData = db.prepare("SELECT value FROM team_config WHERE key = ?").get(flagKey);
    const flags = flagData ? JSON.parse(flagData.value) : { count: 0, sessions: [] };
    flags.count += 1;
    flags.sessions.push({ sessionId: session.id, at: new Date().toISOString() });
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(flagKey, JSON.stringify(flags), req.user.id);

    // Auto-alert team lead if 3+ flags
    if (flags.count >= 3) {
      auditLog(null, 'PEER_ABUSE_ESCALATION', `User has ${flags.count} abuse flags — review recommended`);
    }

    db.close();
    auditLog(req.user.id, 'PEER_FLAGGED', `session=${req.params.id}`, req.ip);
    res.json({ ok: true, message: 'Flag recorded. The other party will be notified their language was flagged.' });
  } catch (err) {
    logger.error('Flag session error', { error: err.message });
    res.status(500).json({ error: 'Failed to flag session' });
  }
});

// ── Timeout/No-Show Tracking ─────────────────────────────────────────────────
router.post('/sessions/:id/timeout', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`peer_session_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Session not found' }); }

    const session = JSON.parse(row.value);
    session.status = 'timed_out';
    session.timedOutAt = new Date().toISOString();
    db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(session), `peer_session_${req.params.id}`);

    // Track no-shows for the accepter
    const noShowKey = `peer_noshows_${session.accepterId}`;
    const noShowData = db.prepare("SELECT value FROM team_config WHERE key = ?").get(noShowKey);
    const noShows = noShowData ? JSON.parse(noShowData.value) : { count: 0, sessions: [] };
    noShows.count += 1;
    noShows.sessions.push({ sessionId: session.id, at: session.timedOutAt });
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(noShowKey, JSON.stringify(noShows), req.user.id);

    // Re-open the original request (minus the no-show accepter)
    const requestRow = db.prepare("SELECT value FROM team_config WHERE key = ?").get(`peer_request_${session.requestId}`);
    if (requestRow) {
      const request = JSON.parse(requestRow.value);
      request.status = 'open';
      if (!request.excludeIds.includes(session.accepterId)) request.excludeIds.push(session.accepterId);
      db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(request), `peer_request_${session.requestId}`);
    }

    // Alert team lead if 3+ no-shows
    if (noShows.count >= 3) {
      auditLog(null, 'PEER_NOSHOW_ESCALATION', `User has ${noShows.count} no-shows — team lead should review`);
    }

    db.close();
    auditLog(req.user.id, 'PEER_TIMEOUT', `session=${req.params.id} — re-queued`, req.ip);
    res.json({ ok: true, message: 'Session timed out. Request re-queued.' });
  } catch (err) {
    logger.error('Timeout session error', { error: err.message });
    res.status(500).json({ error: 'Failed to process timeout' });
  }
});

// ── Helper Points Summary (for team lead) ────────────────────────────────────
router.get('/points', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can view points summary' });

  try {
    const db = getDb();
    const rows = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'peer_points_%'").all();

    const summary = rows.map(r => {
      const userId = r.key.replace('peer_points_', '');
      const points = JSON.parse(r.value);
      const user = db.prepare('SELECT name, tier FROM users WHERE id = ?').get(userId);
      return {
        userId,
        name: user?.name || 'Unknown',
        tier: user?.tier,
        totalSessions: points.sessions,
        totalPoints: points.total,
        avgRating: points.avgRating,
      };
    }).sort((a, b) => b.totalPoints - a.totalPoints);

    // No-show data
    const noShowRows = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'peer_noshows_%'").all();
    const noShows = noShowRows.map(r => {
      const userId = r.key.replace('peer_noshows_', '');
      const data = JSON.parse(r.value);
      const user = db.prepare('SELECT name FROM users WHERE id = ?').get(userId);
      return { userId, name: user?.name, count: data.count };
    }).filter(n => n.count > 0);

    // Abuse flags
    const flagRows = db.prepare("SELECT key, value FROM team_config WHERE key LIKE 'peer_flags_%'").all();
    const flags = flagRows.map(r => {
      const userId = r.key.replace('peer_flags_', '');
      const data = JSON.parse(r.value);
      const user = db.prepare('SELECT name FROM users WHERE id = ?').get(userId);
      return { userId, name: user?.name, count: data.count };
    }).filter(f => f.count > 0);

    db.close();
    res.json({ helpers: summary, noShows, abuseFlags: flags });
  } catch (err) {
    logger.error('Points summary error', { error: err.message });
    res.status(500).json({ error: 'Failed to get points summary' });
  }
});

// ── Scheduling Restrictions (team lead sets when chat is allowed) ────────────
router.get('/schedule-config', (req, res) => {
  try {
    const db = getDb();
    const config = db.prepare("SELECT value FROM team_config WHERE key = 'peer_schedule_config'").get();
    db.close();
    res.json(config ? JSON.parse(config.value) : {
      allowDuringShift: true,
      blockedDays: [],       // e.g., ['saturday', 'sunday']
      blockedHoursStart: null, // e.g., '09:00'
      blockedHoursEnd: null,   // e.g., '17:00'
      maxSessionMinutes: 30,
      inactivityTimeoutMinutes: 5,
      inactivityWarningMinutes: 3,
    });
  } catch (err) {
    logger.error('Get schedule config error', { error: err.message });
    res.status(500).json({ error: 'Failed to get schedule config' });
  }
});

router.put('/schedule-config', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can set schedule restrictions' });

  const { allowDuringShift, blockedDays, blockedHoursStart, blockedHoursEnd, maxSessionMinutes, inactivityTimeoutMinutes } = req.body;

  try {
    const config = {
      allowDuringShift: allowDuringShift !== false,
      blockedDays: Array.isArray(blockedDays) ? blockedDays.filter(d => ['monday','tuesday','wednesday','thursday','friday','saturday','sunday'].includes(d)) : [],
      blockedHoursStart: /^\d{2}:\d{2}$/.test(blockedHoursStart) ? blockedHoursStart : null,
      blockedHoursEnd: /^\d{2}:\d{2}$/.test(blockedHoursEnd) ? blockedHoursEnd : null,
      maxSessionMinutes: Math.max(5, Math.min(120, parseInt(maxSessionMinutes, 10) || 30)),
      inactivityTimeoutMinutes: Math.max(2, Math.min(30, parseInt(inactivityTimeoutMinutes, 10) || 5)),
      inactivityWarningMinutes: Math.max(1, Math.min(29, (parseInt(inactivityTimeoutMinutes, 10) || 5) - 2)),
    };

    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('peer_schedule_config', ?, ?)").run(JSON.stringify(config), req.user.id);
    db.close();

    auditLog(req.user.id, 'PEER_SCHEDULE_UPDATED', JSON.stringify(config), req.ip);
    res.json({ ok: true, config });
  } catch (err) {
    logger.error('Update schedule config error', { error: err.message });
    res.status(500).json({ error: 'Failed to update schedule config' });
  }
});

module.exports = router;

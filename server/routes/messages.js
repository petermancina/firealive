// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Peer Messages Routes (Signal-protocol E2EE relay)
//
// The server NEVER sees plaintext or keys — only opaque libsignal ciphertext plus
// routing/ordering metadata transits through. Sessions are scoped by the peer_session
// records in peers.js; the relay resolves the recipient from the session and never
// returns a peer's user id to the client (analysts address their peer by sessionId,
// preserving pseudonymity). Public-key distribution is handled by the X3DH/PQXDH
// pre-key store (e2ee-keys.js) — the old NaCl public-key registry endpoints are gone.
//
// POST /api/messages            — relay one ciphertext into a session
// GET  /api/messages            — fetch incoming ciphertext for a session, in order
// PUT  /api/messages/:id/read   — recipient marks a message read
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// base64 ciphertext cap. libsignal messages are small (a few hundred bytes for
// a chat line; larger for an initial PreKey message but still well under this).
const MAX_CIPHERTEXT_B64 = 65536;

function loadSession(db, sessionId) {
  const row = db.prepare('SELECT value FROM team_config WHERE key = ?').get(`peer_session_${sessionId}`);
  if (!row) return null;
  try { return JSON.parse(row.value); } catch { return null; }
}

// ── Relay an encrypted message ───────────────────────────────────────────────
router.post('/', (req, res) => {
  const { sessionId, messageType, ciphertext, counter } = req.body || {};

  if (!sessionId || typeof sessionId !== 'string') {
    return res.status(400).json({ error: 'sessionId required' });
  }
  if (!Number.isInteger(messageType)) {
    return res.status(400).json({ error: 'messageType (integer) required' });
  }
  if (typeof ciphertext !== 'string' || ciphertext.length === 0 || ciphertext.length > MAX_CIPHERTEXT_B64) {
    return res.status(400).json({ error: 'ciphertext required (base64, max 64KB)' });
  }
  if (!Number.isInteger(counter) || counter < 0) {
    return res.status(400).json({ error: 'counter (non-negative integer) required' });
  }

  try {
    const db = getDb();
    const session = loadSession(db, sessionId);
    if (!session) { db.close(); return res.status(404).json({ error: 'Session not found' }); }
    if (session.status !== 'active') { db.close(); return res.status(400).json({ error: 'Session is not active' }); }

    // Resolve the recipient as the OTHER participant; reject non-participants.
    let recipientId;
    if (req.user.id === session.requesterId) recipientId = session.accepterId;
    else if (req.user.id === session.accepterId) recipientId = session.requesterId;
    else { db.close(); return res.status(403).json({ error: 'Not a participant in this session' }); }

    const id = crypto.randomBytes(16).toString('hex');
    db.prepare(`
      INSERT INTO peer_messages (id, session_id, sender_user_id, recipient_user_id, message_type, ciphertext, counter)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, sessionId, req.user.id, recipientId, messageType, Buffer.from(ciphertext, 'base64'), counter);

    db.close();
    // Audit records only that a message was relayed — never content or identities.
    auditLog(req.user.id, 'E2EE_MESSAGE_SENT', 'peer message relay', req.ip);
    res.status(201).json({ id, sent: true });
  } catch (err) {
    logger.error('Send message error', { error: err.message });
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// ── Fetch incoming messages for a session ────────────────────────────────────
// Returns only messages addressed to the caller, ordered by the sender's
// per-session counter (the Double Ratchet is order-sensitive). The caller cannot
// decrypt its own outgoing ciphertext, so own messages are intentionally omitted;
// the client renders its own sent lines from local state.
router.get('/', (req, res) => {
  const { sessionId, since } = req.query;
  if (!sessionId) return res.status(400).json({ error: 'sessionId query param required' });

  try {
    const db = getDb();
    const session = loadSession(db, sessionId);
    if (!session) { db.close(); return res.status(404).json({ error: 'Session not found' }); }
    if (req.user.id !== session.requesterId && req.user.id !== session.accepterId) {
      db.close(); return res.status(403).json({ error: 'Not a participant' });
    }

    let sql = 'SELECT id, message_type, ciphertext, counter, created_at FROM peer_messages WHERE session_id = ? AND recipient_user_id = ?';
    const params = [sessionId, req.user.id];
    if (since) { sql += ' AND created_at > ?'; params.push(since); }
    sql += ' ORDER BY counter ASC';

    const rows = db.prepare(sql).all(...params);

    if (rows.length) {
      const mark = db.prepare("UPDATE peer_messages SET delivered_at = datetime('now') WHERE id = ? AND delivered_at IS NULL");
      const markAll = db.transaction(() => { for (const m of rows) mark.run(m.id); });
      markAll();
    }
    db.close();

    const messages = rows.map((m) => ({
      id: m.id,
      messageType: m.message_type,
      ciphertext: m.ciphertext ? m.ciphertext.toString('base64') : null,
      counter: m.counter,
      createdAt: m.created_at,
    }));
    res.json({ messages });
  } catch (err) {
    logger.error('Fetch messages error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// ── Mark Read (recipient only) ───────────────────────────────────────────────
router.put('/:id/read', (req, res) => {
  try {
    const db = getDb();
    db.prepare("UPDATE peer_messages SET read_at = datetime('now') WHERE id = ? AND recipient_user_id = ?")
      .run(req.params.id, req.user.id);
    db.close();
    res.json({ ok: true });
  } catch (err) {
    logger.error('Mark read error', { error: err.message });
    res.status(500).json({ error: 'Failed to mark message as read' });
  }
});

module.exports = router;

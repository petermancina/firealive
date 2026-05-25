// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Lead-Chat Routes (Signal-protocol E2EE relay)
//
// The pseudonymous analyst<->team-lead chat. Like the peer relay (messages.js),
// the server NEVER sees plaintext or keys — only opaque libsignal ciphertext plus
// routing/ordering metadata. The chat uses the separate 'lead' key domain. Threads
// are 1:1 (one per analyst/lead pairing) and live in the lead_chat_threads table;
// the relay resolves the recipient from the thread. The analyst is pseudonymous in
// the system (the lead resolves real identity via an offline UUID->name map); leads
// are not pseudonymized. Closing a thread starts a 5-minute retention clock — the
// shared sweep then deletes the thread's messages, while the thread record persists
// as the reusable pairing anchor.
//
// POST /api/lead-chat/open            — analyst opens/continues a thread with a lead
// POST /api/lead-chat                 — relay one ciphertext into a thread
// GET  /api/lead-chat/thread          — fetch incoming ciphertext for a thread, in order
// GET  /api/lead-chat/threads         — caller's threads (lead inbox / analyst list)
// PUT  /api/lead-chat/:id/read        — recipient marks a message read
// POST /api/lead-chat/:threadId/close — close a thread, start the retention clock
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// base64 ciphertext cap. libsignal messages are small (a few hundred bytes for a
// chat line; larger for an initial PreKey message but still well under this).
const MAX_CIPHERTEXT_B64 = 65536;
const MESSAGE_KINDS = ['chat', 'inperson_1on1_request'];

function loadThread(db, threadId) {
  return db.prepare(
    'SELECT id, analyst_id, lead_id, status FROM lead_chat_threads WHERE id = ?'
  ).get(threadId) || null;
}

// Resolve the caller's role within a thread and the other party. Returns null if
// the caller is not a participant in this thread.
function resolveParticipant(thread, userId) {
  if (userId === thread.analyst_id) return { senderRole: 'analyst', recipientId: thread.lead_id };
  if (userId === thread.lead_id) return { senderRole: 'lead', recipientId: thread.analyst_id };
  return null;
}

// ── Open or continue a thread (analyst-initiated) ────────────────────────────
// Only analysts initiate a lead chat. One thread per (analyst, lead) pairing:
// INSERT OR IGNORE makes creation idempotent and race-safe against the UNIQUE
// constraint; a closed thread is reactivated so the existing ratchet session is
// reused. Leads reply within existing threads; they do not open new ones.
router.post('/open', (req, res) => {
  if (req.user.role !== 'analyst') {
    return res.status(403).json({ error: 'Only analysts initiate a lead chat' });
  }
  const { leadId } = req.body || {};
  if (!leadId || typeof leadId !== 'string') {
    return res.status(400).json({ error: 'leadId required' });
  }

  try {
    const db = getDb();
    const lead = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'lead' AND active = 1").get(leadId);
    if (!lead) { db.close(); return res.status(404).json({ error: 'No active lead with that id' }); }

    const id = crypto.randomBytes(16).toString('hex');
    const ins = db.prepare(
      'INSERT OR IGNORE INTO lead_chat_threads (id, analyst_id, lead_id) VALUES (?, ?, ?)'
    ).run(id, req.user.id, leadId);
    const created = ins.changes === 1;
    if (!created) {
      db.prepare(
        "UPDATE lead_chat_threads SET status = 'active', closed_at = NULL WHERE analyst_id = ? AND lead_id = ? AND status = 'closed'"
      ).run(req.user.id, leadId);
    }
    const row = db.prepare('SELECT id FROM lead_chat_threads WHERE analyst_id = ? AND lead_id = ?').get(req.user.id, leadId);
    db.close();

    auditLog(req.user.id, 'LEAD_CHAT_THREAD_OPENED', created ? 'created' : 'continued', req.ip);
    res.status(201).json({ threadId: row.id, status: 'active', created });
  } catch (err) {
    logger.error('Open lead-chat thread error', { error: err.message });
    res.status(500).json({ error: 'Failed to open lead chat' });
  }
});

// ── Relay an encrypted message ───────────────────────────────────────────────
router.post('/', (req, res) => {
  const { threadId, messageType, ciphertext, counter, kind } = req.body || {};

  if (!threadId || typeof threadId !== 'string') {
    return res.status(400).json({ error: 'threadId required' });
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
  const msgKind = kind === undefined ? 'chat' : kind;
  if (!MESSAGE_KINDS.includes(msgKind)) {
    return res.status(400).json({ error: "kind must be 'chat' or 'inperson_1on1_request'" });
  }

  try {
    const db = getDb();
    const thread = loadThread(db, threadId);
    if (!thread) { db.close(); return res.status(404).json({ error: 'Thread not found' }); }
    if (thread.status !== 'active') { db.close(); return res.status(400).json({ error: 'Thread is not active' }); }

    const part = resolveParticipant(thread, req.user.id);
    if (!part) { db.close(); return res.status(403).json({ error: 'Not a participant in this thread' }); }

    const id = crypto.randomBytes(16).toString('hex');
    const relay = db.transaction(() => {
      db.prepare(`
        INSERT INTO lead_messages
          (id, thread_id, analyst_id, lead_id, sender_user_id, recipient_user_id, sender_role, kind, message_type, ciphertext, counter)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, threadId, thread.analyst_id, thread.lead_id, req.user.id, part.recipientId, part.senderRole, msgKind, messageType, Buffer.from(ciphertext, 'base64'), counter);
      db.prepare(
        "UPDATE lead_chat_threads SET message_count = message_count + 1, last_message_at = datetime('now') WHERE id = ?"
      ).run(threadId);
    });
    relay();
    db.close();

    // Content-blind: audit records a relay plus the metadata kind only — never
    // content, never identities.
    auditLog(req.user.id, 'LEAD_CHAT_MESSAGE_SENT', `kind=${msgKind}`, req.ip);
    res.status(201).json({ id, sent: true });
  } catch (err) {
    logger.error('Send lead-chat message error', { error: err.message });
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// ── Fetch incoming messages for a thread ─────────────────────────────────────
// Returns only messages addressed to the caller, ordered by the sender's
// per-thread counter (the Double Ratchet is order-sensitive). The caller cannot
// decrypt its own outgoing ciphertext, so own messages are intentionally omitted;
// the client renders its own sent lines from local state.
router.get('/thread', (req, res) => {
  const { threadId, since } = req.query;
  if (!threadId) return res.status(400).json({ error: 'threadId query param required' });

  try {
    const db = getDb();
    const thread = loadThread(db, threadId);
    if (!thread) { db.close(); return res.status(404).json({ error: 'Thread not found' }); }
    if (!resolveParticipant(thread, req.user.id)) {
      db.close(); return res.status(403).json({ error: 'Not a participant' });
    }

    let sql = 'SELECT id, message_type, ciphertext, counter, kind, created_at FROM lead_messages WHERE thread_id = ? AND recipient_user_id = ?';
    const params = [threadId, req.user.id];
    if (since) { sql += ' AND created_at > ?'; params.push(since); }
    sql += ' ORDER BY counter ASC';

    const rows = db.prepare(sql).all(...params);
    if (rows.length) {
      const mark = db.prepare("UPDATE lead_messages SET delivered_at = datetime('now') WHERE id = ? AND delivered_at IS NULL");
      const markAll = db.transaction(() => { for (const m of rows) mark.run(m.id); });
      markAll();
    }
    db.close();

    const messages = rows.map((m) => ({
      id: m.id,
      messageType: m.message_type,
      ciphertext: m.ciphertext ? Buffer.from(m.ciphertext).toString('base64') : null,
      counter: m.counter,
      kind: m.kind,
      createdAt: m.created_at,
    }));
    res.json({ messages });
  } catch (err) {
    logger.error('Fetch lead-chat messages error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// ── List the caller's threads ────────────────────────────────────────────────
// Lead view (inbox): every analyst thread addressed to this lead, labeled by the
// analyst's PSEUDONYM — the real name is never in the system; the lead resolves it
// via their offline map keyed on counterpartId (analyst_id). Analyst view: their
// threads, labeled by the lead's real name (leads are not pseudonymized). unread
// and pending1on1 count only messages addressed TO the caller.
router.get('/threads', (req, res) => {
  try {
    const db = getDb();
    const me = req.user.id;
    let rows;
    if (req.user.role === 'analyst') {
      rows = db.prepare(`
        SELECT t.id, t.lead_id AS counterpart_id, u.name AS label, t.status,
               t.message_count, t.last_message_at, t.created_at, t.closed_at,
               (SELECT COUNT(*) FROM lead_messages m WHERE m.thread_id = t.id AND m.recipient_user_id = ? AND m.read_at IS NULL) AS unread,
               (SELECT COUNT(*) FROM lead_messages m WHERE m.thread_id = t.id AND m.recipient_user_id = ? AND m.kind = 'inperson_1on1_request' AND m.read_at IS NULL) AS pending_1on1
        FROM lead_chat_threads t JOIN users u ON u.id = t.lead_id
        WHERE t.analyst_id = ?
        ORDER BY COALESCE(t.last_message_at, t.created_at) DESC
      `).all(me, me, me);
    } else {
      rows = db.prepare(`
        SELECT t.id, t.analyst_id AS counterpart_id,
               COALESCE(NULLIF(u.pseudonym, ''), 'Analyst-' || substr(u.id, 1, 6)) AS label, t.status,
               t.message_count, t.last_message_at, t.created_at, t.closed_at,
               (SELECT COUNT(*) FROM lead_messages m WHERE m.thread_id = t.id AND m.recipient_user_id = ? AND m.read_at IS NULL) AS unread,
               (SELECT COUNT(*) FROM lead_messages m WHERE m.thread_id = t.id AND m.recipient_user_id = ? AND m.kind = 'inperson_1on1_request' AND m.read_at IS NULL) AS pending_1on1
        FROM lead_chat_threads t JOIN users u ON u.id = t.analyst_id
        WHERE t.lead_id = ?
        ORDER BY COALESCE(t.last_message_at, t.created_at) DESC
      `).all(me, me, me);
    }
    db.close();

    const threads = rows.map((t) => ({
      threadId: t.id,
      counterpartId: t.counterpart_id,
      label: t.label,
      status: t.status,
      messageCount: t.message_count,
      lastMessageAt: t.last_message_at,
      createdAt: t.created_at,
      closedAt: t.closed_at,
      unread: t.unread,
      pending1on1: t.pending_1on1 > 0,
    }));
    res.json({ threads });
  } catch (err) {
    logger.error('List lead-chat threads error', { error: err.message });
    res.status(500).json({ error: 'Failed to list threads' });
  }
});

// ── Mark Read (recipient only) ───────────────────────────────────────────────
router.put('/:id/read', (req, res) => {
  try {
    const db = getDb();
    db.prepare("UPDATE lead_messages SET read_at = datetime('now') WHERE id = ? AND recipient_user_id = ?")
      .run(req.params.id, req.user.id);
    db.close();
    res.json({ ok: true });
  } catch (err) {
    logger.error('Mark lead-chat read error', { error: err.message });
    res.status(500).json({ error: 'Failed to mark message as read' });
  }
});

// ── Close a thread (either participant) ──────────────────────────────────────
// Starts the 5-minute retention clock. The shared sweep deletes this thread's
// lead_messages once closed_at + 5 min has passed; the thread record persists so
// the pair can reopen later.
router.post('/:threadId/close', (req, res) => {
  try {
    const db = getDb();
    const thread = loadThread(db, req.params.threadId);
    if (!thread) { db.close(); return res.status(404).json({ error: 'Thread not found' }); }
    if (!resolveParticipant(thread, req.user.id)) {
      db.close(); return res.status(403).json({ error: 'Not a participant' });
    }
    db.prepare(
      "UPDATE lead_chat_threads SET status = 'closed', closed_at = datetime('now') WHERE id = ? AND status = 'active'"
    ).run(req.params.threadId);
    const row = db.prepare('SELECT closed_at FROM lead_chat_threads WHERE id = ?').get(req.params.threadId);
    db.close();
    auditLog(req.user.id, 'LEAD_CHAT_THREAD_CLOSED', 'retention clock started', req.ip);
    res.json({ ok: true, closedAt: row ? row.closed_at : null });
  } catch (err) {
    logger.error('Close lead-chat thread error', { error: err.message });
    res.status(500).json({ error: 'Failed to close thread' });
  }
});

module.exports = router;

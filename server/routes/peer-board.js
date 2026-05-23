// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Peer Message Board Routes (U2)
//
// The real board backend, replacing the prototype team_config key-value store.
// An analyst skill-share board with threaded replies. Posts auto-expire after
// seven days (swept by the scheduler). Post bodies are stored as Tier-3
// AES-256-GCM ciphertext and decrypted server-side at read time for authorized
// analysts and leads.
//
// PRIVACY: the author UUID is ALWAYS stored but NEVER returned to the client.
// The board shows the author's pseudonym (when a post is published under their
// handle) or "Anonymous" (when display_anonymous is set). Real names never
// appear here — identity is resolved on the backend only, and only through the
// tiered abuse-flag review. A `mine` flag tells the caller which posts it owns
// so the UI can offer delete, without exposing any author identity.
//
// GET    /api/peer-board/messages           — list top-level posts
// GET    /api/peer-board/threads/:rootId     — one thread (root + replies)
// POST   /api/peer-board/messages            — create a top-level post
// POST   /api/peer-board/messages/:id/reply  — reply within a thread
// POST   /api/peer-board/messages/:id/react  — toggle a reaction
// DELETE /api/peer-board/messages/:id         — soft-delete (author or lead)
//
// Mounted (with analyst/lead/admin auth) at /api/peer-board in index.js.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { encryptTier3, decryptTier3 } = require('../services/encryption');

const MAX_CONTENT = 4096;
const MAX_CATEGORY = 64;
const BOARD_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const ALLOWED_REACTIONS = ['helpful', 'thanks', 'insightful', 'same'];

// Build the reaction summary the client sees: per-reaction count plus whether
// the viewer has reacted. The stored shape is { reaction: [authorId, ...] };
// the author ids are NEVER returned — only counts and the viewer's own flag.
function reactionSummary(reactionsRaw, viewerId) {
  const summary = {};
  for (const k of ALLOWED_REACTIONS) {
    const list = Array.isArray(reactionsRaw[k]) ? reactionsRaw[k] : [];
    summary[k] = { count: list.length, mine: list.includes(viewerId) };
  }
  return summary;
}

// Render a stored row into the client-safe shape. NEVER returns author_id or
// the real name — only the pseudonym (or "Anonymous") and a `mine` flag.
function publicPost(row, viewerId, db) {
  let content = '';
  try { content = decryptTier3(row.content_encrypted).toString('utf8'); } catch (e) { content = ''; }

  let authorLabel = 'Anonymous';
  if (!row.display_anonymous) {
    const u = db.prepare('SELECT pseudonym FROM users WHERE id = ?').get(row.author_id);
    authorLabel = (u && u.pseudonym) ? u.pseudonym : 'Analyst';
  }

  let reactionsRaw = {};
  try { reactionsRaw = row.reactions ? JSON.parse(row.reactions) : {}; } catch (e) { reactionsRaw = {}; }

  return {
    id: row.id,
    content,
    authorLabel,
    anonymous: !!row.display_anonymous,
    mine: row.author_id === viewerId,
    category: row.category || null,
    parentId: row.parent_id || null,
    threadRootId: row.thread_root_id || null,
    depth: row.depth,
    reactions: reactionSummary(reactionsRaw, viewerId),
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

// ── GET /messages — top-level, live posts only ──────────────────────────────
router.get('/messages', (req, res) => {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT * FROM peer_board_messages
      WHERE parent_id IS NULL
        AND removed_pending_review = 0
        AND deleted_at IS NULL
        AND expires_at > datetime('now')
      ORDER BY created_at DESC
    `).all();
    const replyCount = db.prepare(`
      SELECT COUNT(*) n FROM peer_board_messages
      WHERE thread_root_id = ? AND removed_pending_review = 0 AND deleted_at IS NULL
    `);
    const out = rows.map((row) => {
      const post = publicPost(row, req.user.id, db);
      post.replyCount = replyCount.get(row.id).n;
      return post;
    });
    db.close();
    return res.json({ messages: out });
  } catch (err) {
    logger.error('peer-board list failed', { error: err.message });
    return res.status(500).json({ error: 'failed to load board' });
  }
});

// ── GET /threads/:rootId — root + replies (chronological), live posts only ──
router.get('/threads/:rootId', (req, res) => {
  const { rootId } = req.params;
  try {
    const db = getDb();
    const root = db.prepare(`
      SELECT * FROM peer_board_messages
      WHERE id = ? AND parent_id IS NULL AND removed_pending_review = 0 AND deleted_at IS NULL
    `).get(rootId);
    if (!root) { db.close(); return res.status(404).json({ error: 'thread not found' }); }
    const replies = db.prepare(`
      SELECT * FROM peer_board_messages
      WHERE thread_root_id = ? AND removed_pending_review = 0 AND deleted_at IS NULL
      ORDER BY created_at ASC
    `).all(rootId);
    const posts = [root, ...replies].map((r) => publicPost(r, req.user.id, db));
    db.close();
    return res.json({ thread: posts });
  } catch (err) {
    logger.error('peer-board thread failed', { error: err.message });
    return res.status(500).json({ error: 'failed to load thread' });
  }
});

// ── POST /messages — create a top-level post ────────────────────────────────
router.post('/messages', (req, res) => {
  const { content, anonymous, category } = req.body || {};
  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return res.status(400).json({ error: 'content required' });
  }
  if (content.length > MAX_CONTENT) {
    return res.status(400).json({ error: `content max ${MAX_CONTENT} chars` });
  }
  if (category != null && (typeof category !== 'string' || category.length > MAX_CATEGORY)) {
    return res.status(400).json({ error: `category max ${MAX_CATEGORY} chars` });
  }
  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    const displayAnon = anonymous === false ? 0 : 1; // posts default to anonymous
    const expiresAt = new Date(Date.now() + BOARD_TTL_MS).toISOString();
    db.prepare(`
      INSERT INTO peer_board_messages
        (id, author_id, display_anonymous, category, content_encrypted, parent_id, thread_root_id, depth, expires_at)
      VALUES (?, ?, ?, ?, ?, NULL, NULL, 0, ?)
    `).run(id, req.user.id, displayAnon, category || null, encryptTier3(content), expiresAt);
    const row = db.prepare('SELECT * FROM peer_board_messages WHERE id = ?').get(id);
    const post = publicPost(row, req.user.id, db);
    post.replyCount = 0;
    db.close();
    auditLog(req.user.id, 'PEER_BOARD_POST_CREATED', `post ${id}`, req.ip);
    return res.status(201).json({ message: post });
  } catch (err) {
    logger.error('peer-board create failed', { error: err.message });
    return res.status(500).json({ error: 'failed to create post' });
  }
});

// ── POST /messages/:id/reply — reply within a thread ────────────────────────
router.post('/messages/:id/reply', (req, res) => {
  const { id } = req.params;
  const { content, anonymous } = req.body || {};
  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return res.status(400).json({ error: 'content required' });
  }
  if (content.length > MAX_CONTENT) {
    return res.status(400).json({ error: `content max ${MAX_CONTENT} chars` });
  }
  try {
    const db = getDb();
    const parent = db.prepare(`
      SELECT id, thread_root_id, depth FROM peer_board_messages
      WHERE id = ? AND removed_pending_review = 0 AND deleted_at IS NULL
    `).get(id);
    if (!parent) { db.close(); return res.status(404).json({ error: 'post not found' }); }
    // A reply to a root anchors to that root; a reply to a reply inherits the
    // existing thread root, so the whole thread shares one thread_root_id.
    const threadRoot = parent.thread_root_id || parent.id;
    const replyId = crypto.randomBytes(16).toString('hex');
    const displayAnon = anonymous === false ? 0 : 1;
    const expiresAt = new Date(Date.now() + BOARD_TTL_MS).toISOString();
    db.prepare(`
      INSERT INTO peer_board_messages
        (id, author_id, display_anonymous, category, content_encrypted, parent_id, thread_root_id, depth, expires_at)
      VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)
    `).run(replyId, req.user.id, displayAnon, encryptTier3(content), parent.id, threadRoot, parent.depth + 1, expiresAt);
    const row = db.prepare('SELECT * FROM peer_board_messages WHERE id = ?').get(replyId);
    const post = publicPost(row, req.user.id, db);
    db.close();
    auditLog(req.user.id, 'PEER_BOARD_REPLY_CREATED', `reply ${replyId} on thread ${threadRoot}`, req.ip);
    return res.status(201).json({ message: post });
  } catch (err) {
    logger.error('peer-board reply failed', { error: err.message });
    return res.status(500).json({ error: 'failed to reply' });
  }
});

// ── POST /messages/:id/react — toggle a reaction ────────────────────────────
router.post('/messages/:id/react', (req, res) => {
  const { id } = req.params;
  const { reaction } = req.body || {};
  if (!ALLOWED_REACTIONS.includes(reaction)) {
    return res.status(400).json({ error: 'invalid reaction' });
  }
  try {
    const db = getDb();
    const row = db.prepare(`
      SELECT reactions FROM peer_board_messages
      WHERE id = ? AND removed_pending_review = 0 AND deleted_at IS NULL
    `).get(id);
    if (!row) { db.close(); return res.status(404).json({ error: 'post not found' }); }
    let reactions = {};
    try { reactions = row.reactions ? JSON.parse(row.reactions) : {}; } catch (e) { reactions = {}; }
    const list = Array.isArray(reactions[reaction]) ? reactions[reaction] : [];
    const at = list.indexOf(req.user.id);
    if (at >= 0) list.splice(at, 1); else list.push(req.user.id);
    reactions[reaction] = list;
    db.prepare('UPDATE peer_board_messages SET reactions = ? WHERE id = ?').run(JSON.stringify(reactions), id);
    db.close();
    return res.json({ reactions: reactionSummary(reactions, req.user.id) });
  } catch (err) {
    logger.error('peer-board react failed', { error: err.message });
    return res.status(500).json({ error: 'failed to react' });
  }
});

// ── DELETE /messages/:id — soft-delete (author or lead/admin) ───────────────
router.delete('/messages/:id', (req, res) => {
  const { id } = req.params;
  try {
    const db = getDb();
    const row = db.prepare('SELECT author_id, deleted_at FROM peer_board_messages WHERE id = ?').get(id);
    if (!row || row.deleted_at) { db.close(); return res.status(404).json({ error: 'post not found' }); }
    const isOwner = row.author_id === req.user.id;
    const isLead = req.user.role === 'lead' || req.user.role === 'admin';
    if (!isOwner && !isLead) { db.close(); return res.status(403).json({ error: 'not permitted' }); }
    db.prepare("UPDATE peer_board_messages SET deleted_at = datetime('now') WHERE id = ?").run(id);
    db.close();
    auditLog(req.user.id, 'PEER_BOARD_POST_DELETED', `post ${id}${(isLead && !isOwner) ? ' (by lead)' : ''}`, req.ip);
    return res.json({ deleted: true });
  } catch (err) {
    logger.error('peer-board delete failed', { error: err.message });
    return res.status(500).json({ error: 'failed to delete' });
  }
});

module.exports = router;

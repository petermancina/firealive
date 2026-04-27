// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Peer Messages Routes (E2EE)
// The server NEVER sees plaintext — only encrypted blobs transit through.
// Messages use NaCl box (X25519 + XSalsa20-Poly1305).
//
// POST /api/messages            — send encrypted message
// GET  /api/messages            — fetch inbox (ciphertext + nonces)
// PUT  /api/messages/:id/read   — mark message as read
// GET  /api/messages/keys       — get/register public key
// POST /api/messages/keys       — register public key
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── Key Registration ─────────────────────────────────────────────────────────
// Analysts register their public keys; the server stores only public keys.
// Secret keys never leave the client.

router.get('/keys', (req, res) => {
  try {
    const db = getDb();
    // Get all analyst public keys (for peer discovery)
    const keys = db.prepare(`
      SELECT tc.key AS user_id, tc.value AS public_key,
             u.name, u.tier
      FROM team_config tc
      JOIN users u ON u.id = REPLACE(tc.key, 'pubkey_', '')
      WHERE tc.key LIKE 'pubkey_%'
    `).all();
    db.close();
    res.json({ keys: keys.map(k => ({ userId: k.user_id.replace('pubkey_', ''), name: k.name, tier: k.tier, publicKey: k.public_key })) });
  } catch (err) {
    logger.error('Get keys error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch public keys' });
  }
});

router.post('/keys', (req, res) => {
  const { publicKey } = req.body;
  if (!publicKey || typeof publicKey !== 'string' || publicKey.length > 128) {
    return res.status(400).json({ error: 'publicKey required (base64 encoded, max 128 chars)' });
  }

  try {
    const db = getDb();
    db.prepare('INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES (?, ?, ?)').run(`pubkey_${req.user.id}`, publicKey, req.user.id);
    db.close();
    auditLog(req.user.id, 'PUBKEY_REGISTERED', '', req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Register key error', { error: err.message });
    res.status(500).json({ error: 'Failed to register public key' });
  }
});

// ── Send Encrypted Message ───────────────────────────────────────────────────
router.post('/', (req, res) => {
  const { recipientEncrypted, senderEncrypted, ciphertext, nonce, ephemeralPubkey } = req.body;

  if (!ciphertext || !nonce || !recipientEncrypted || !senderEncrypted) {
    return res.status(400).json({ error: 'ciphertext, nonce, recipientEncrypted, and senderEncrypted required' });
  }

  // Size limits: 64KB max per message
  if (ciphertext.length > 65536 || nonce.length > 128) {
    return res.status(400).json({ error: 'Message too large (max 64KB ciphertext)' });
  }

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');

    db.prepare(`
      INSERT INTO peer_messages (id, sender_encrypted, recipient_encrypted, ciphertext, nonce, ephemeral_pubkey)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      id,
      Buffer.from(senderEncrypted, 'base64'),
      Buffer.from(recipientEncrypted, 'base64'),
      Buffer.from(ciphertext, 'base64'),
      Buffer.from(nonce, 'base64'),
      ephemeralPubkey ? Buffer.from(ephemeralPubkey, 'base64') : null
    );

    db.close();

    // Audit log records only that a message was sent — never content or identities
    auditLog(req.user.id, 'E2EE_MESSAGE_SENT', 'peer message relay', req.ip);
    res.status(201).json({ id, sent: true });
  } catch (err) {
    logger.error('Send message error', { error: err.message });
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// ── Fetch Inbox ──────────────────────────────────────────────────────────────
// Client must try to decrypt each message with their key to determine
// which messages are addressed to them (server cannot know).
router.get('/', (req, res) => {
  try {
    const { since, limit = 50 } = req.query;
    const db = getDb();

    let sql = 'SELECT id, sender_encrypted, recipient_encrypted, ciphertext, nonce, ephemeral_pubkey, created_at, read_at FROM peer_messages';
    const params = [];

    if (since) {
      sql += ' WHERE created_at > ?';
      params.push(since);
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(Math.min(parseInt(limit, 10) || 50, 200));

    const messages = db.prepare(sql).all(...params).map(m => ({
      id: m.id,
      senderEncrypted: m.sender_encrypted?.toString('base64'),
      recipientEncrypted: m.recipient_encrypted?.toString('base64'),
      ciphertext: m.ciphertext?.toString('base64'),
      nonce: m.nonce?.toString('base64'),
      ephemeralPubkey: m.ephemeral_pubkey?.toString('base64') || null,
      createdAt: m.created_at,
      readAt: m.read_at,
    }));

    db.close();
    res.json({ messages });
  } catch (err) {
    logger.error('Fetch messages error', { error: err.message });
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// ── Mark Read ────────────────────────────────────────────────────────────────
router.put('/:id/read', (req, res) => {
  try {
    const db = getDb();
    db.prepare('UPDATE peer_messages SET read_at = datetime("now") WHERE id = ?').run(req.params.id);
    db.close();
    res.json({ ok: true });
  } catch (err) {
    logger.error('Mark read error', { error: err.message });
    res.status(500).json({ error: 'Failed to mark message as read' });
  }
});

module.exports = router;

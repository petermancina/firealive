// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Custom Recovery Resources Routes
// GET    /api/resources       — list resources (all roles can read)
// POST   /api/resources       — add resource (lead/admin)
// PUT    /api/resources/:id   — update resource (lead/admin)
// DELETE /api/resources/:id   — remove resource (lead/admin)
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { sanitizeUrl } = require('../services/url-sanitizer');

const VALID_CATEGORIES = ['professional', 'self-help', 'peer', 'training'];

// ── List Resources ───────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const { category } = req.query;
    const db = getDb();

    let sql = `
      SELECT cr.*, u.name AS created_by_name
      FROM custom_resources cr
      JOIN users u ON u.id = cr.created_by
    `;
    const params = [];

    if (category && VALID_CATEGORIES.includes(category)) {
      sql += ' WHERE cr.category = ?';
      params.push(category);
    }

    sql += ' ORDER BY cr.created_at DESC';
    const resources = db.prepare(sql).all(...params);
    db.close();
    res.json({ resources });
  } catch (err) {
    logger.error('List resources error', { error: err.message });
    res.status(500).json({ error: 'Failed to list resources' });
  }
});

// ── Add Resource ─────────────────────────────────────────────────────────────
router.post('/', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can add resources' });

  const { title, url, category } = req.body;
  if (!title || !url || !category) return res.status(400).json({ error: 'title, url, and category required' });
  if (!VALID_CATEGORIES.includes(category)) return res.status(400).json({ error: `Invalid category. Valid: ${VALID_CATEGORIES.join(', ')}` });
  if (title.length > 256) return res.status(400).json({ error: 'Title too long (max 256)' });
  if (url.length > 1024) return res.status(400).json({ error: 'URL too long (max 1024)' });
  if (!/^https?:\/\/.+/.test(url)) return res.status(400).json({ error: 'URL must start with http:// or https://' });

  // Sanitize URL against encoding tricks, punycode, etc.
  const urlCheck = sanitizeUrl(url);
  if (!urlCheck.valid) return res.status(400).json({ error: `URL rejected: ${urlCheck.reason}` });

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');
    db.prepare('INSERT INTO custom_resources (id, title, url, category, created_by) VALUES (?, ?, ?, ?, ?)').run(
      id, title.slice(0, 256), url.slice(0, 1024), category, req.user.id
    );
    db.close();
    auditLog(req.user.id, 'RESOURCE_ADDED', `title=${title} category=${category}`, req.ip);
    res.status(201).json({ id, title, url, category });
  } catch (err) {
    logger.error('Add resource error', { error: err.message });
    res.status(500).json({ error: 'Failed to add resource' });
  }
});

// ── Update Resource ──────────────────────────────────────────────────────────
router.put('/:id', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can update resources' });

  const { title, url, category } = req.body;

  try {
    const db = getDb();
    const existing = db.prepare('SELECT * FROM custom_resources WHERE id = ?').get(req.params.id);
    if (!existing) { db.close(); return res.status(404).json({ error: 'Resource not found' }); }

    db.prepare(`
      UPDATE custom_resources SET
        title = COALESCE(?, title),
        url = COALESCE(?, url),
        category = COALESCE(?, category)
      WHERE id = ?
    `).run(
      title?.slice(0, 256) || null,
      url?.slice(0, 1024) || null,
      category && VALID_CATEGORIES.includes(category) ? category : null,
      req.params.id
    );
    db.close();
    auditLog(req.user.id, 'RESOURCE_UPDATED', `id=${req.params.id}`, req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Update resource error', { error: err.message });
    res.status(500).json({ error: 'Failed to update resource' });
  }
});

// ── Delete Resource ──────────────────────────────────────────────────────────
router.delete('/:id', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can remove resources' });

  try {
    const db = getDb();
    const r = db.prepare('SELECT title FROM custom_resources WHERE id = ?').get(req.params.id);
    if (!r) { db.close(); return res.status(404).json({ error: 'Resource not found' }); }

    db.prepare('DELETE FROM custom_resources WHERE id = ?').run(req.params.id);
    db.close();
    auditLog(req.user.id, 'RESOURCE_REMOVED', `title=${r.title}`, req.ip);
    res.json({ ok: true, removed: r.title });
  } catch (err) {
    logger.error('Delete resource error', { error: err.message });
    res.status(500).json({ error: 'Failed to delete resource' });
  }
});

module.exports = router;

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');

router.get('/', (req, res) => {
  const db = getDb();
  const retros = db.prepare('SELECT * FROM retro_protocols ORDER BY created_at DESC').all();
  const result = retros.map(r => {
    const analysts = db.prepare('SELECT u.name FROM retro_analysts ra JOIN users u ON ra.analyst_id = u.id WHERE ra.retro_id = ?').all(r.id);
    const actions = db.prepare('SELECT action_text, created_at FROM retro_actions WHERE retro_id = ? ORDER BY created_at').all(r.id);
    return { ...r, analysts: analysts.map(a => a.name), actions: actions.map(a => a.action_text) };
  });
  db.close();
  res.json({ retros: result });
});

router.post('/', (req, res) => {
  const { incident, severity, analystIds, queueReductionDuration } = req.body;
  if (!incident || !severity || !analystIds?.length) return res.status(400).json({ error: 'incident, severity, and analystIds required' });

  const crypto = require('crypto');
  const db = getDb();
  const retroId = crypto.randomBytes(16).toString('hex');

  db.prepare('INSERT INTO retro_protocols (id, incident, severity, queue_reduction_duration, initiated_by) VALUES (?, ?, ?, ?, ?)')
    .run(retroId, incident, severity, queueReductionDuration || '24hr', req.user.id);

  const insertAnalyst = db.prepare('INSERT INTO retro_analysts (retro_id, analyst_id) VALUES (?, ?)');
  const insertAction = db.prepare('INSERT INTO retro_actions (retro_id, action_text) VALUES (?, ?)');

  for (const aid of analystIds) insertAnalyst.run(retroId, aid);

  insertAction.run(retroId, `Lighter queues activated for ${analystIds.length} analysts`);
  insertAction.run(retroId, 'Peer support availability published');
  insertAction.run(retroId, 'Check-ins scheduled: 24hr, 72hr, 2 weeks');

  // Reduce routing caps for involved analysts
  const capStmt = db.prepare('UPDATE routing_caps SET max_complexity = MIN(max_complexity, 2), updated_at = datetime("now") WHERE analyst_id = ?');
  for (const aid of analystIds) capStmt.run(aid);

  db.close();
  auditLog(req.user.id, 'RETRO_ACTIVATED', `${incident} — ${analystIds.length} analysts`, req.ip);
  res.status(201).json({ id: retroId });
});

router.put('/:id/complete', (req, res) => {
  const db = getDb();
  db.prepare('UPDATE retro_protocols SET phase = ?, completed_at = datetime("now") WHERE id = ?').run('Complete', req.params.id);
  db.prepare('INSERT INTO retro_actions (retro_id, action_text) VALUES (?, ?)').run(req.params.id, 'Marked complete at ' + new Date().toISOString());

  // Restore routing caps for involved analysts
  const analystRows = db.prepare('SELECT ra.analyst_id, u.tier FROM retro_analysts ra JOIN users u ON ra.analyst_id = u.id WHERE ra.retro_id = ?').all(req.params.id);
  const restoreCap = db.prepare('UPDATE routing_caps SET max_complexity = ?, is_override = 0, updated_at = datetime("now") WHERE analyst_id = ?');
  for (const a of analystRows) restoreCap.run(a.tier === 3 ? 5 : a.tier === 2 ? 3 : 2, a.analyst_id);

  db.close();
  auditLog(req.user.id, 'RETRO_COMPLETE', req.params.id, req.ip);
  res.json({ ok: true });
});

router.post('/:id/followup', (req, res) => {
  const db = getDb();
  db.prepare('INSERT INTO retro_actions (retro_id, action_text) VALUES (?, ?)').run(req.params.id, 'Follow-up check-in sent at ' + new Date().toISOString());
  db.close();
  auditLog(req.user.id, 'RETRO_FOLLOWUP', req.params.id, req.ip);
  res.json({ ok: true });
});

module.exports = router;

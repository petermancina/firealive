const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const notifications = require('../services/notifications');

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
  const duration = queueReductionDuration || '24hr';

  db.prepare('INSERT INTO retro_protocols (id, incident, severity, queue_reduction_duration, initiated_by) VALUES (?, ?, ?, ?, ?)')
    .run(retroId, incident, severity, duration, req.user.id);

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

  // Notify each analyst added to the retro
  for (const aid of analystIds) {
    try {
      notifications.notify({
        recipientId: aid,
        eventType: 'retro_scheduled',
        title: `Post-incident recovery scheduled: ${incident}`,
        body: `You've been added to a ${severity} post-incident recovery protocol for "${incident}". Lighter queues are active for ${duration}, peer support is available, and check-ins are scheduled at 24hr, 72hr, and 2 weeks. Open the Post-Incident Wellness tab for details.`,
        linkTab: 'recovery',
        linkParams: { retroId },
      });
    } catch (notifyErr) {
      logger.warn('Retro create: notify analyst failed (non-fatal)', { analystId: aid, retroId, error: notifyErr.message });
    }
  }

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
  const retroId = req.params.id;

  // Fetch the retro and its attached analysts before recording the follow-up
  const retro = db.prepare('SELECT incident, severity FROM retro_protocols WHERE id = ?').get(retroId);
  if (!retro) { db.close(); return res.status(404).json({ error: 'Retro not found' }); }

  const analystIds = db.prepare('SELECT analyst_id FROM retro_analysts WHERE retro_id = ?').all(retroId).map(r => r.analyst_id);

  db.prepare('INSERT INTO retro_actions (retro_id, action_text) VALUES (?, ?)').run(retroId, 'Follow-up check-in sent at ' + new Date().toISOString());
  db.close();

  auditLog(req.user.id, 'RETRO_FOLLOWUP', retroId, req.ip);

  // Notify each analyst attached to this retro
  for (const aid of analystIds) {
    try {
      notifications.notify({
        recipientId: aid,
        eventType: 'retro_followup_sent',
        title: `Recovery check-in: ${retro.incident}`,
        body: `Your team lead is checking in on your post-incident recovery for "${retro.incident}" (${retro.severity}). If you're still feeling the effects of this incident, peer support is available, and your lighter-queue eligibility is still active. Open the Post-Incident Wellness tab to respond.`,
        linkTab: 'recovery',
        linkParams: { retroId },
      });
    } catch (notifyErr) {
      logger.warn('Retro followup: notify analyst failed (non-fatal)', { analystId: aid, retroId, error: notifyErr.message });
    }
  }

  res.json({ ok: true, notified: analystIds.length });
});

module.exports = router;

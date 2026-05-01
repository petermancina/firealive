// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — TTX Generator Routes (Phase 1.4d)
//
// Tabletop Exercise (TTX) document generation. Three endpoints:
//
//   GET  /api/ttx/scenarios                       — list scenarios
//   POST /api/ttx/sitman                          — generate Situation Manual
//   POST /api/ttx/aar                             — generate AAR template
//
// All endpoints require lead/admin role (TTX is a leadership-facilitated
// exercise; analysts participate in the meeting but don't generate the docs).
// Audit log entries fire on each generation as the compliance breadcrumb
// proving the tool was used.
//
// Document generation is synchronous and streams the buffer directly into
// the response. No temp files, no DB persistence — the lead downloads,
// brings the SitMan to the meeting, and the AAR is filled in offline.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { getScenarioMeta, getValidDifficulties } = require('../services/ttx-scenarios');
const { generateSitman, generateAar, VALID_FORMATS } = require('../services/ttx-generator');

// ── GET /api/ttx/scenarios — list available scenarios ──────────────────────
router.get('/scenarios', (req, res) => {
  try {
    const scenarios = getScenarioMeta();
    return res.json({
      scenarios,
      validDifficulties: getValidDifficulties(),
      validFormats: VALID_FORMATS,
    });
  } catch (err) {
    logger.error('Failed to list TTX scenarios', { error: err.message });
    return res.status(500).json({ error: 'failed to list scenarios' });
  }
});

// ── POST /api/ttx/sitman — generate a Situation Manual ─────────────────────
router.post('/sitman', async (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { scenarioId, difficulty, format } = req.body || {};

  if (!scenarioId || typeof scenarioId !== 'string') {
    return res.status(400).json({ error: 'scenarioId required' });
  }
  if (!getValidDifficulties().includes(difficulty)) {
    return res.status(400).json({ error: 'difficulty must be one of: ' + getValidDifficulties().join(', ') });
  }
  if (!VALID_FORMATS.includes(format)) {
    return res.status(400).json({ error: 'format must be one of: ' + VALID_FORMATS.join(', ') });
  }

  let buffer;
  try {
    buffer = await generateSitman(scenarioId, difficulty, format);
  } catch (err) {
    if (err.message && err.message.includes('not found')) {
      return res.status(404).json({ error: 'scenario not found' });
    }
    logger.error('Failed to generate SitMan', { scenarioId, difficulty, format, error: err.message });
    return res.status(500).json({ error: 'failed to generate SitMan' });
  }

  auditLog(req.user.id, 'TTX_SITMAN_GENERATED', scenarioId + ' (' + difficulty + ', ' + format + ')', req.ip);

  const filename = 'sitman-' + scenarioId + '-' + difficulty + '.' + format;
  res.setHeader('Content-Type', format === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
  res.setHeader('Content-Length', buffer.length);
  return res.send(buffer);
});

// ── POST /api/ttx/aar — generate an AAR template ───────────────────────────
router.post('/aar', async (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { scenarioId, difficulty, format } = req.body || {};

  if (!scenarioId || typeof scenarioId !== 'string') {
    return res.status(400).json({ error: 'scenarioId required' });
  }
  if (!getValidDifficulties().includes(difficulty)) {
    return res.status(400).json({ error: 'difficulty must be one of: ' + getValidDifficulties().join(', ') });
  }
  if (!VALID_FORMATS.includes(format)) {
    return res.status(400).json({ error: 'format must be one of: ' + VALID_FORMATS.join(', ') });
  }

  let buffer;
  try {
    buffer = await generateAar(scenarioId, difficulty, format);
  } catch (err) {
    if (err.message && err.message.includes('not found')) {
      return res.status(404).json({ error: 'scenario not found' });
    }
    logger.error('Failed to generate AAR', { scenarioId, difficulty, format, error: err.message });
    return res.status(500).json({ error: 'failed to generate AAR' });
  }

  auditLog(req.user.id, 'TTX_AAR_GENERATED', scenarioId + ' (' + difficulty + ', ' + format + ')', req.ip);

  const filename = 'aar-template-' + scenarioId + '-' + difficulty + '.' + format;
  res.setHeader('Content-Type', format === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
  res.setHeader('Content-Length', buffer.length);
  return res.send(buffer);
});

module.exports = router;

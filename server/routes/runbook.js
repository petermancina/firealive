// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Recovery Runbook Routes
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// FireAlive-specific Recovery Runbook generation. Three endpoints:
//
//   GET  /api/runbook/scenarios   — list available scenarios with categories
//   POST /api/runbook/quickref    — generate quick-reference card
//   POST /api/runbook/full        — generate full runbook
//
// All endpoints require lead/admin role. The Recovery Runbook is preparation
// material — leads generate scenarios in advance, print or save them, and
// the team executes from those copies during a real incident when the
// platform itself may be unavailable.
//
// Document generation is synchronous and streams the buffer directly into
// the response. Each generation fires an audit log entry as the compliance
// breadcrumb proving the tool was used.
//
// Three formats per artifact: pdf, docx, json. The JSON format returns the
// raw scenario data for programmatic use, dev workflows, or org tools that
// want to consume the data without document parsing.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { listScenarios, listCategories, getScenarioById } = require('../services/runbook-scenarios');
const { generateQuickRef, generateFullRunbook, VALID_FORMATS } = require('../services/runbook-generator');

// ── Content-type for each output format ────────────────────────────────────
const CONTENT_TYPES = {
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  json: 'application/json',
};

// ── GET /api/runbook/scenarios ─────────────────────────────────────────────
router.get('/scenarios', (req, res) => {
  try {
    const scenarios = listScenarios();
    const categories = listCategories();
    return res.json({
      scenarios,
      categories,
      validFormats: VALID_FORMATS,
    });
  } catch (err) {
    logger.error('Failed to list runbook scenarios', { error: err.message });
    return res.status(500).json({ error: 'failed to list scenarios' });
  }
});

// ── POST /api/runbook/quickref ─────────────────────────────────────────────
router.post('/quickref', async (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { scenarioId, format } = req.body || {};

  if (!scenarioId || typeof scenarioId !== 'string') {
    return res.status(400).json({ error: 'scenarioId required' });
  }
  if (!VALID_FORMATS.includes(format)) {
    return res.status(400).json({ error: 'format must be one of: ' + VALID_FORMATS.join(', ') });
  }
  if (!getScenarioById(scenarioId)) {
    return res.status(404).json({ error: 'scenario not found' });
  }

  let buffer;
  try {
    buffer = await generateQuickRef(scenarioId, format);
  } catch (err) {
    if (err.message && err.message.includes('not found')) {
      return res.status(404).json({ error: 'scenario not found' });
    }
    logger.error('Failed to generate quick-ref', { scenarioId, format, error: err.message });
    return res.status(500).json({ error: 'failed to generate quick-reference card' });
  }

  auditLog(req.user.id, 'RUNBOOK_QUICKREF_GENERATED', scenarioId + ' (' + format + ')', req.ip);

  const filename = 'runbook-quickref-' + scenarioId + '.' + format;
  res.setHeader('Content-Type', CONTENT_TYPES[format]);
  res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
  res.setHeader('Content-Length', buffer.length);
  return res.send(buffer);
});

// ── POST /api/runbook/full ─────────────────────────────────────────────────
router.post('/full', async (req, res) => {
  if (!['lead', 'admin'].includes(req.user.role)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { scenarioId, format } = req.body || {};

  if (!scenarioId || typeof scenarioId !== 'string') {
    return res.status(400).json({ error: 'scenarioId required' });
  }
  if (!VALID_FORMATS.includes(format)) {
    return res.status(400).json({ error: 'format must be one of: ' + VALID_FORMATS.join(', ') });
  }
  if (!getScenarioById(scenarioId)) {
    return res.status(404).json({ error: 'scenario not found' });
  }

  let buffer;
  try {
    buffer = await generateFullRunbook(scenarioId, format);
  } catch (err) {
    if (err.message && err.message.includes('not found')) {
      return res.status(404).json({ error: 'scenario not found' });
    }
    logger.error('Failed to generate full runbook', { scenarioId, format, error: err.message });
    return res.status(500).json({ error: 'failed to generate full runbook' });
  }

  auditLog(req.user.id, 'RUNBOOK_FULL_GENERATED', scenarioId + ' (' + format + ')', req.ip);

  const filename = 'runbook-full-' + scenarioId + '.' + format;
  res.setHeader('Content-Type', CONTENT_TYPES[format]);
  res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
  res.setHeader('Content-Length', buffer.length);
  return res.send(buffer);
});

module.exports = router;

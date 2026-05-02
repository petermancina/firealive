// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Recovery Runbook Document Generator
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Generates two document artifacts from the FireAlive-specific Recovery Runbook
// scenario library:
//
//   quickRef — single-page printable card with trigger conditions, first
//              3-5 immediate actions, and escalation guidance. Designed to
//              live at a desk or in a binder for fast reference during an
//              incident.
//
//   fullRunbook — multi-page document with full procedure: identification,
//                 containment, eradication, recovery, verification, post-
//                 incident review. Includes FireAlive components involved
//                 and tear-down + reinstall workflow where applicable.
//
// Three output formats per artifact: pdf, docx, json.
//
// API:
//
//   generateQuickRef(scenarioId, format) -> Promise<Buffer>
//   generateFullRunbook(scenarioId, format) -> Promise<Buffer>
//
// Both throw on invalid scenario or unsupported format. Route handler wraps.
//
// Document structure follows the same conventions as the TTX generator —
// pdfkit for PDF, docx 9.x for DOCX. JSON is the raw scenario object for
// programmatic use, dev workflows, or org tools that want to consume the
// data without document parsing.
// ═══════════════════════════════════════════════════════════════════════════════

const PDFDocument = require('pdfkit');
const docx = require('docx');
const { getScenarioById } = require('./runbook-scenarios');

// ── Format constants ────────────────────────────────────────────────────────

const VALID_FORMATS = ['pdf', 'docx', 'json'];
const VALID_TYPES = ['quickref', 'full'];

// ── Public API ──────────────────────────────────────────────────────────────

async function generateQuickRef(scenarioId, format) {
  validateInputs(scenarioId, format);
  const scenario = getScenarioById(scenarioId);
  if (!scenario) {
    throw new Error('scenario not found: ' + scenarioId);
  }
  if (format === 'pdf') return buildQuickRefPdf(scenario);
  if (format === 'docx') return buildQuickRefDocx(scenario);
  return buildJsonBuffer({
    artifact: 'quickRef',
    scenario: {
      id: scenario.id,
      category: scenario.category,
      title: scenario.title,
      summary: scenario.summary,
      indicators: scenario.indicators,
      quickRef: scenario.quickRef,
    },
    generatedAt: new Date().toISOString(),
  });
}

async function generateFullRunbook(scenarioId, format) {
  validateInputs(scenarioId, format);
  const scenario = getScenarioById(scenarioId);
  if (!scenario) {
    throw new Error('scenario not found: ' + scenarioId);
  }
  if (format === 'pdf') return buildFullRunbookPdf(scenario);
  if (format === 'docx') return buildFullRunbookDocx(scenario);
  return buildJsonBuffer({
    artifact: 'fullRunbook',
    scenario,
    generatedAt: new Date().toISOString(),
  });
}

function validateInputs(scenarioId, format) {
  if (!scenarioId || typeof scenarioId !== 'string') {
    throw new Error('scenarioId required');
  }
  if (!VALID_FORMATS.includes(format)) {
    throw new Error('format must be one of: ' + VALID_FORMATS.join(', '));
  }
}

// ── JSON output ─────────────────────────────────────────────────────────────

function buildJsonBuffer(obj) {
  return Promise.resolve(Buffer.from(JSON.stringify(obj, null, 2), 'utf8'));
}

// ── PDF builders ────────────────────────────────────────────────────────────

function pdfDocToBuffer(doc) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    doc.end();
  });
}

function buildQuickRefPdf(scenario) {
  const doc = new PDFDocument({
    size: 'LETTER',
    margins: { top: 54, bottom: 54, left: 54, right: 54 },
    info: {
      Title: 'Quick Reference: ' + scenario.title,
      Author: 'FireAlive Recovery Runbook Generator',
      Subject: 'FireAlive-specific scenario quick reference card',
    },
  });

  // Header band
  doc.fontSize(9).fillColor('#666666').text('FIREALIVE RECOVERY RUNBOOK — QUICK REFERENCE', { align: 'left' });
  doc.fontSize(9).fillColor('#666666').text(scenario.category, { align: 'right' });
  // Restore alignment
  doc.moveDown(0.3);
  doc.moveTo(54, doc.y).lineTo(558, doc.y).strokeColor('#cccccc').stroke();
  doc.moveDown(0.6);

  // Title
  doc.fontSize(18).fillColor('#000000').font('Helvetica-Bold').text(scenario.title);
  doc.moveDown(0.4);
  doc.font('Helvetica').fontSize(10).fillColor('#444444').text('Scenario ID: ' + scenario.id, { paragraphGap: 4 });
  doc.moveDown(0.6);

  // Summary
  pdfBody(doc, scenario.summary);
  doc.moveDown(0.4);

  // Trigger
  pdfHeading(doc, 'Trigger', 12);
  pdfBody(doc, scenario.quickRef.trigger);
  doc.moveDown(0.4);

  // First actions
  pdfHeading(doc, 'First actions (do these immediately)', 12);
  scenario.quickRef.firstActions.forEach((step, idx) => {
    doc.fontSize(11).fillColor('#000000').font('Helvetica-Bold').text((idx + 1) + '.', { continued: true, indent: 0 });
    doc.font('Helvetica').text(' ' + step, { paragraphGap: 6, lineGap: 2 });
  });
  doc.moveDown(0.4);

  // Escalation
  pdfHeading(doc, 'Escalation', 12);
  pdfBody(doc, scenario.quickRef.escalation);
  doc.moveDown(0.6);

  // Footer line
  doc.moveTo(54, doc.y).lineTo(558, doc.y).strokeColor('#cccccc').stroke();
  doc.moveDown(0.4);
  doc.fontSize(9).fillColor('#666666').text('For full runbook content: open Recovery Runbook tab in MC, select this scenario, choose "Full Runbook".', { align: 'left' });
  doc.fontSize(9).fillColor('#666666').text('Generated ' + new Date().toLocaleString(), { align: 'left' });

  return pdfDocToBuffer(doc);
}

function buildFullRunbookPdf(scenario) {
  const doc = new PDFDocument({
    size: 'LETTER',
    margins: { top: 72, bottom: 72, left: 72, right: 72 },
    info: {
      Title: 'Recovery Runbook: ' + scenario.title,
      Author: 'FireAlive Recovery Runbook Generator',
      Subject: 'FireAlive-specific full recovery runbook',
    },
  });

  // Cover
  doc.fontSize(10).fillColor('#666666').text('FIREALIVE RECOVERY RUNBOOK', { align: 'center' });
  doc.moveDown(0.3);
  doc.fontSize(10).fillColor('#666666').text(scenario.category.toUpperCase(), { align: 'center' });
  doc.moveDown(4);
  doc.fontSize(22).fillColor('#000000').font('Helvetica-Bold').text(scenario.title, { align: 'center' });
  doc.font('Helvetica');
  doc.moveDown(2);
  doc.fontSize(11).fillColor('#000000').text(scenario.summary, { align: 'left' });
  doc.moveDown(1);
  doc.fontSize(10).fillColor('#444444').text('Scenario ID: ' + scenario.id, { align: 'left' });
  doc.moveDown(2);
  doc.fontSize(9).fillColor('#666666').text('This runbook is preparation material. Print or save it before an incident, then execute from the printed copy or saved document during a real event when the platform itself may be unavailable.', { align: 'left' });
  doc.moveDown(0.5);
  doc.fontSize(9).fillColor('#666666').text('Generated ' + new Date().toLocaleString(), { align: 'left' });
  doc.addPage();

  // Section 1: Indicators
  pdfHeading(doc, '1. Indicators');
  pdfBody(doc, 'Detect this scenario by watching for the following indicators. Multiple indicators occurring together strengthen confidence.');
  scenario.indicators.forEach((ind) => pdfBullet(doc, ind));
  doc.moveDown(0.5);

  // Section 2: Identification
  pdfHeading(doc, '2. Identification');
  pdfBody(doc, 'Once an indicator triggers suspicion, work through these identification steps to confirm the scenario.');
  scenario.fullRunbook.identification.forEach((step, idx) => {
    pdfNumberedStep(doc, idx + 1, step);
  });
  doc.moveDown(0.5);

  // Section 3: Containment
  pdfHeading(doc, '3. Containment');
  pdfBody(doc, 'Stop the incident from spreading. Containment prioritizes limiting impact, not yet fixing root cause.');
  scenario.fullRunbook.containment.forEach((step, idx) => {
    pdfNumberedStep(doc, idx + 1, step);
  });
  doc.moveDown(0.5);

  // Section 4: Eradication
  pdfHeading(doc, '4. Eradication');
  pdfBody(doc, 'Remove the root cause. With the scenario contained, eliminate the conditions that allowed it.');
  scenario.fullRunbook.eradication.forEach((step, idx) => {
    pdfNumberedStep(doc, idx + 1, step);
  });
  doc.moveDown(0.5);

  // Section 5: Recovery
  pdfHeading(doc, '5. Recovery');
  pdfBody(doc, 'Restore normal operations.');
  scenario.fullRunbook.recovery.forEach((step, idx) => {
    pdfNumberedStep(doc, idx + 1, step);
  });
  doc.moveDown(0.5);

  // Section 6: Verification
  pdfHeading(doc, '6. Verification');
  pdfBody(doc, 'Confirm the response was effective and operations are stable.');
  scenario.fullRunbook.verification.forEach((step, idx) => {
    pdfNumberedStep(doc, idx + 1, step);
  });
  doc.moveDown(0.5);

  // Section 7: Post-incident
  pdfHeading(doc, '7. Post-Incident Review');
  pdfBody(doc, 'After the incident is closed, document, learn, and improve.');
  scenario.fullRunbook.postIncident.forEach((step, idx) => {
    pdfNumberedStep(doc, idx + 1, step);
  });
  doc.moveDown(0.5);

  // Section 8: Components
  pdfHeading(doc, '8. FireAlive Components Involved');
  pdfBody(doc, 'These FireAlive components, tabs, or services are involved in this scenario\'s detection and response.');
  scenario.fullRunbook.componentsInvolved.forEach((c) => pdfBullet(doc, c));
  doc.moveDown(0.5);

  // Section 9: Related scenarios
  if (scenario.fullRunbook.relatedScenarios && scenario.fullRunbook.relatedScenarios.length) {
    pdfHeading(doc, '9. Related Scenarios');
    pdfBody(doc, 'These scenarios share indicators, root causes, or response steps with this one. Review their runbooks for adjacent considerations.');
    scenario.fullRunbook.relatedScenarios.forEach((rs) => pdfBullet(doc, rs));
    doc.moveDown(0.5);
  }

  return pdfDocToBuffer(doc);
}

function pdfHeading(doc, text, size) {
  if (doc.y > 680) doc.addPage();
  doc.fontSize(size || 14).fillColor('#000000').font('Helvetica-Bold').text(text);
  doc.moveDown(0.3);
  doc.font('Helvetica').fontSize(11);
}

function pdfBody(doc, text) {
  doc.fontSize(11).fillColor('#000000').font('Helvetica').text(text, { paragraphGap: 6, lineGap: 2 });
}

function pdfBullet(doc, text, color) {
  if (doc.y > 700) doc.addPage();
  doc.fontSize(11).fillColor(color || '#000000').font('Helvetica').text('• ' + text, { indent: 12, paragraphGap: 4, lineGap: 2 });
}

function pdfNumberedStep(doc, n, text) {
  if (doc.y > 680) doc.addPage();
  doc.fontSize(11).fillColor('#000000').font('Helvetica-Bold').text(n + '.', { continued: true, indent: 0 });
  doc.font('Helvetica').text(' ' + text, { paragraphGap: 6, lineGap: 2 });
}

// ── DOCX builders ───────────────────────────────────────────────────────────

const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, PageBreak } = docx;

function buildQuickRefDocx(scenario) {
  const children = [];

  // Header band
  children.push(new Paragraph({
    spacing: { after: 60 },
    children: [
      new TextRun({ text: 'FIREALIVE RECOVERY RUNBOOK — QUICK REFERENCE', size: 18, color: '666666' }),
    ],
  }));
  children.push(new Paragraph({
    spacing: { after: 240 },
    children: [
      new TextRun({ text: scenario.category, size: 18, color: '666666', italics: true }),
    ],
  }));

  // Title
  children.push(new Paragraph({
    spacing: { after: 120 },
    children: [
      new TextRun({ text: scenario.title, size: 36, bold: true }),
    ],
  }));

  // Scenario ID
  children.push(new Paragraph({
    spacing: { after: 240 },
    children: [
      new TextRun({ text: 'Scenario ID: ' + scenario.id, size: 20, color: '444444' }),
    ],
  }));

  // Summary
  children.push(bodyParagraph(scenario.summary));

  // Trigger
  children.push(headingParagraph('Trigger'));
  children.push(bodyParagraph(scenario.quickRef.trigger));

  // First actions
  children.push(headingParagraph('First actions (do these immediately)'));
  scenario.quickRef.firstActions.forEach((step, idx) => {
    children.push(new Paragraph({
      spacing: { before: 60, after: 120 },
      children: [
        new TextRun({ text: (idx + 1) + '. ', bold: true, size: 22 }),
        new TextRun({ text: step, size: 22 }),
      ],
    }));
  });

  // Escalation
  children.push(headingParagraph('Escalation'));
  children.push(bodyParagraph(scenario.quickRef.escalation));

  // Footer
  children.push(new Paragraph({
    spacing: { before: 360, after: 60 },
    children: [
      new TextRun({ text: 'For full runbook content: open Recovery Runbook tab in MC, select this scenario, choose "Full Runbook".', size: 18, color: '666666', italics: true }),
    ],
  }));
  children.push(new Paragraph({
    spacing: { after: 60 },
    children: [
      new TextRun({ text: 'Generated ' + new Date().toLocaleString(), size: 18, color: '666666' }),
    ],
  }));

  const doc = new Document({
    creator: 'FireAlive Recovery Runbook Generator',
    title: 'Quick Reference: ' + scenario.title,
    description: 'FireAlive-specific scenario quick reference card',
    sections: [{ children }],
  });

  return Packer.toBuffer(doc);
}

function buildFullRunbookDocx(scenario) {
  const children = [];

  // Cover
  children.push(coverParagraph('FIREALIVE RECOVERY RUNBOOK', { size: 20 }));
  children.push(coverParagraph(scenario.category.toUpperCase(), { size: 20, after: 720 }));
  children.push(coverParagraph(scenario.title, { size: 44, bold: true, after: 240 }));
  children.push(bodyParagraph(scenario.summary));
  children.push(bodyParagraph('Scenario ID: ' + scenario.id, { color: '444444' }));
  children.push(bodyParagraph('This runbook is preparation material. Print or save it before an incident, then execute from the printed copy or saved document during a real event when the platform itself may be unavailable.', { italics: true, color: '666666' }));
  children.push(bodyParagraph('Generated ' + new Date().toLocaleString(), { italics: true, color: '666666' }));
  children.push(pageBreak());

  // Section 1: Indicators
  children.push(headingParagraph('1. Indicators'));
  children.push(bodyParagraph('Detect this scenario by watching for the following indicators. Multiple indicators occurring together strengthen confidence.'));
  scenario.indicators.forEach((ind) => children.push(bulletParagraph(ind)));

  // Section 2: Identification
  children.push(headingParagraph('2. Identification'));
  children.push(bodyParagraph('Once an indicator triggers suspicion, work through these identification steps to confirm the scenario.'));
  scenario.fullRunbook.identification.forEach((step, idx) => {
    children.push(numberedStepParagraph(idx + 1, step));
  });

  // Section 3: Containment
  children.push(headingParagraph('3. Containment'));
  children.push(bodyParagraph('Stop the incident from spreading. Containment prioritizes limiting impact, not yet fixing root cause.'));
  scenario.fullRunbook.containment.forEach((step, idx) => {
    children.push(numberedStepParagraph(idx + 1, step));
  });

  // Section 4: Eradication
  children.push(headingParagraph('4. Eradication'));
  children.push(bodyParagraph('Remove the root cause. With the scenario contained, eliminate the conditions that allowed it.'));
  scenario.fullRunbook.eradication.forEach((step, idx) => {
    children.push(numberedStepParagraph(idx + 1, step));
  });

  // Section 5: Recovery
  children.push(headingParagraph('5. Recovery'));
  children.push(bodyParagraph('Restore normal operations.'));
  scenario.fullRunbook.recovery.forEach((step, idx) => {
    children.push(numberedStepParagraph(idx + 1, step));
  });

  // Section 6: Verification
  children.push(headingParagraph('6. Verification'));
  children.push(bodyParagraph('Confirm the response was effective and operations are stable.'));
  scenario.fullRunbook.verification.forEach((step, idx) => {
    children.push(numberedStepParagraph(idx + 1, step));
  });

  // Section 7: Post-incident
  children.push(headingParagraph('7. Post-Incident Review'));
  children.push(bodyParagraph('After the incident is closed, document, learn, and improve.'));
  scenario.fullRunbook.postIncident.forEach((step, idx) => {
    children.push(numberedStepParagraph(idx + 1, step));
  });

  // Section 8: Components
  children.push(headingParagraph('8. FireAlive Components Involved'));
  children.push(bodyParagraph('These FireAlive components, tabs, or services are involved in this scenario\'s detection and response.'));
  scenario.fullRunbook.componentsInvolved.forEach((c) => children.push(bulletParagraph(c)));

  // Section 9: Related scenarios
  if (scenario.fullRunbook.relatedScenarios && scenario.fullRunbook.relatedScenarios.length) {
    children.push(headingParagraph('9. Related Scenarios'));
    children.push(bodyParagraph('These scenarios share indicators, root causes, or response steps with this one. Review their runbooks for adjacent considerations.'));
    scenario.fullRunbook.relatedScenarios.forEach((rs) => children.push(bulletParagraph(rs)));
  }

  const doc = new Document({
    creator: 'FireAlive Recovery Runbook Generator',
    title: 'Recovery Runbook: ' + scenario.title,
    description: 'FireAlive-specific full recovery runbook',
    sections: [{ children }],
  });

  return Packer.toBuffer(doc);
}

// ── DOCX paragraph helpers ──────────────────────────────────────────────────

function coverParagraph(text, opts) {
  opts = opts || {};
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: opts.before || 0, after: opts.after || 120 },
    children: [new TextRun({ text, bold: opts.bold || false, size: opts.size || 22, color: opts.color || '000000' })],
  });
}

function headingParagraph(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 360, after: 120 },
    children: [new TextRun({ text, bold: true, size: 28 })],
  });
}

function bodyParagraph(text, opts) {
  opts = opts || {};
  return new Paragraph({
    spacing: { before: 60, after: 120, line: 320 },
    children: [new TextRun({ text, italics: opts.italics || false, color: opts.color || '000000', size: 22 })],
  });
}

function bulletParagraph(text, color) {
  return new Paragraph({
    bullet: { level: 0 },
    spacing: { before: 30, after: 60 },
    children: [new TextRun({ text, color: color || '000000', size: 22 })],
  });
}

function numberedStepParagraph(n, text) {
  return new Paragraph({
    spacing: { before: 60, after: 120 },
    children: [
      new TextRun({ text: n + '. ', bold: true, size: 22 }),
      new TextRun({ text, size: 22 }),
    ],
  });
}

function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

module.exports = {
  generateQuickRef,
  generateFullRunbook,
  VALID_FORMATS,
  VALID_TYPES,
};

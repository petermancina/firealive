// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — TTX Document Generator (Phase 1.4d)
//
// Generates Situation Manuals (SitMans) and After-Action Report (AAR) templates
// from the curated TTX scenario library. Two output formats:
//
//   PDF — printable, archival, fixed layout. Used for in-person tabletops.
//   DOCX — editable Word document. Used when the lead wants to customize the
//          SitMan before the meeting or when the team fills in the AAR after.
//
// API:
//
//   generateSitman(scenarioId, difficulty, format) -> Promise<Buffer>
//     Returns a buffer containing a complete SitMan for the requested scenario
//     and difficulty in the requested format ('pdf' or 'docx').
//
//   generateAar(scenarioId, difficulty, format) -> Promise<Buffer>
//     Returns a buffer containing a blank AAR template structured to match
//     the scenario's content. Section headings are pre-populated; bodies are
//     blank for the team to fill in after the exercise.
//
// Both functions throw if the scenario or difficulty is invalid. The route
// handler is responsible for catching and returning a 404/400 to the client.
//
// Document structure follows HSEEP Volume IV conventions (handbook of how
// federal exercises are documented). Real organizations modify these to
// taste — the format is a starting point, not a contract.
// ═══════════════════════════════════════════════════════════════════════════════

const PDFDocument = require('pdfkit');
const docx = require('docx');
const { getScenarioDifficulty, getValidDifficulties } = require('./ttx-scenarios');

// ── Format constants ────────────────────────────────────────────────────────
const VALID_FORMATS = ['pdf', 'docx'];
const VALID_TYPES = ['sitman', 'aar'];

// ── Public API ──────────────────────────────────────────────────────────────

async function generateSitman(scenarioId, difficulty, format) {
  validateInputs(scenarioId, difficulty, format);
  const data = getScenarioDifficulty(scenarioId, difficulty);
  if (!data) {
    throw new Error('scenario not found or invalid difficulty');
  }
  if (format === 'pdf') return buildSitmanPdf(data);
  return buildSitmanDocx(data);
}

async function generateAar(scenarioId, difficulty, format) {
  validateInputs(scenarioId, difficulty, format);
  const data = getScenarioDifficulty(scenarioId, difficulty);
  if (!data) {
    throw new Error('scenario not found or invalid difficulty');
  }
  if (format === 'pdf') return buildAarPdf(data);
  return buildAarDocx(data);
}

function validateInputs(scenarioId, difficulty, format) {
  if (!scenarioId || typeof scenarioId !== 'string') {
    throw new Error('scenarioId required');
  }
  if (!getValidDifficulties().includes(difficulty)) {
    throw new Error('difficulty must be one of: ' + getValidDifficulties().join(', '));
  }
  if (!VALID_FORMATS.includes(format)) {
    throw new Error('format must be one of: ' + VALID_FORMATS.join(', '));
  }
}

// ── PDF builders ────────────────────────────────────────────────────────────
//
// pdfkit is a stream-based API. We collect chunks into an array and resolve
// with a concatenated buffer when the document ends. This avoids touching
// the filesystem.

function pdfDocToBuffer(doc) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    doc.end();
  });
}

function buildSitmanPdf(data) {
  const doc = new PDFDocument({
    size: 'LETTER',
    margins: { top: 72, bottom: 72, left: 72, right: 72 },
    info: {
      Title: 'Situation Manual: ' + data.scenario.title,
      Author: 'FireAlive TTX Generator',
      Subject: 'Tabletop Exercise — ' + data.difficulty + ' difficulty',
    },
  });

  // Cover page
  doc.fontSize(10).fillColor('#666666').text('FIREALIVE TABLETOP EXERCISE', { align: 'center' });
  doc.moveDown(0.3);
  doc.fontSize(10).fillColor('#666666').text('SITUATION MANUAL', { align: 'center' });
  doc.moveDown(4);
  doc.fontSize(22).fillColor('#000000').text(data.scenario.title, { align: 'center' });
  doc.moveDown(1);
  doc.fontSize(14).fillColor('#444444').text('Difficulty: ' + capitalize(data.difficulty), { align: 'center' });
  doc.moveDown(4);
  doc.fontSize(11).fillColor('#000000').text(data.scenario.description, { align: 'left', indent: 0 });
  doc.moveDown(2);
  doc.fontSize(9).fillColor('#666666').text('Generated ' + new Date().toLocaleString() + ' for facilitator preparation. The facilitator may modify this document before the exercise.', { align: 'left' });
  doc.addPage();

  // Section 1: Exercise overview
  pdfHeading(doc, '1. Exercise Overview');
  pdfBody(doc, 'This Situation Manual (SitMan) supports a tabletop exercise (TTX). It is intended for the facilitator. The participants should not see the inject timeline or decision points before the exercise begins; the facilitator presents these in sequence during the discussion.');
  pdfBody(doc, 'A TTX is a discussion-based exercise. There is no live system action, no real-time response, no actual incident. The team sits together, the facilitator reads the brief and then drops injects one at a time, and the team talks through how they would respond. The facilitator captures notes and decisions for the After-Action Report (AAR).');
  doc.moveDown(0.5);

  // Section 2: Scenario brief
  pdfHeading(doc, '2. Scenario Brief');
  pdfBody(doc, data.brief);
  doc.moveDown(0.5);

  // Section 3: Actors
  pdfHeading(doc, '3. Participants and Roles');
  data.scenario.actors.forEach((a) => pdfBullet(doc, a));
  doc.moveDown(0.5);

  // Section 4: Assumptions
  pdfHeading(doc, '4. Exercise Assumptions');
  pdfBody(doc, 'The team accepts the following as ground truth for the duration of the exercise:');
  data.scenario.assumptions.forEach((a) => pdfBullet(doc, a));
  doc.moveDown(0.5);

  // Section 5: Inject Timeline
  doc.addPage();
  pdfHeading(doc, '5. Inject Timeline');
  pdfBody(doc, 'The facilitator reads each inject aloud at the indicated relative time, then leads the discussion of the decision points. The injects are sequential — the team should not see the next inject until they have discussed the current one.');
  doc.moveDown(0.5);
  data.injects.forEach((inj, idx) => {
    if (doc.y > 650) doc.addPage();
    doc.fontSize(11).fillColor('#000000').font('Helvetica-Bold').text(inj.timing + ' — Inject ' + (idx + 1));
    doc.font('Helvetica').fontSize(11).fillColor('#000000').text(inj.text, { paragraphGap: 6 });
    if (inj.decision_points && inj.decision_points.length) {
      doc.fontSize(10).fillColor('#444444').font('Helvetica-Oblique').text('Decision points:');
      doc.font('Helvetica');
      inj.decision_points.forEach((dp) => pdfBullet(doc, dp, '#444444'));
    }
    doc.moveDown(0.6);
  });

  // Section 6: Discussion Questions
  doc.addPage();
  pdfHeading(doc, '6. Discussion Questions');
  pdfBody(doc, 'Use these questions to draw out the team\'s thinking after the inject timeline is complete. Some questions revisit decisions made earlier; others probe for gaps.');
  doc.moveDown(0.5);
  data.discussion_questions.forEach((q, idx) => {
    if (doc.y > 700) doc.addPage();
    doc.fontSize(11).fillColor('#000000').text((idx + 1) + '. ' + q, { paragraphGap: 6 });
  });
  doc.moveDown(0.5);

  // Section 7: References
  pdfHeading(doc, '7. References');
  pdfBody(doc, 'Facilitator preparation reading. Not required for participants.');
  data.references.forEach((r) => pdfBullet(doc, r));

  return pdfDocToBuffer(doc);
}

function buildAarPdf(data) {
  const doc = new PDFDocument({
    size: 'LETTER',
    margins: { top: 72, bottom: 72, left: 72, right: 72 },
    info: {
      Title: 'After-Action Report: ' + data.scenario.title,
      Author: 'FireAlive TTX Generator',
      Subject: 'AAR Template — ' + data.difficulty + ' difficulty',
    },
  });

  // Cover page
  doc.fontSize(10).fillColor('#666666').text('FIREALIVE TABLETOP EXERCISE', { align: 'center' });
  doc.moveDown(0.3);
  doc.fontSize(10).fillColor('#666666').text('AFTER-ACTION REPORT (TEMPLATE)', { align: 'center' });
  doc.moveDown(4);
  doc.fontSize(22).fillColor('#000000').text(data.scenario.title, { align: 'center' });
  doc.moveDown(1);
  doc.fontSize(14).fillColor('#444444').text('Difficulty: ' + capitalize(data.difficulty), { align: 'center' });
  doc.moveDown(3);
  doc.fontSize(11).fillColor('#000000').text('This is a template. Fill in each section after the tabletop exercise. The completed AAR is the artifact of record for compliance, audit, and continuous improvement purposes.', { align: 'left' });
  doc.moveDown(2);
  doc.fontSize(11).fillColor('#000000').text('Exercise date: __________________________', { align: 'left' });
  doc.moveDown(0.5);
  doc.text('Facilitator: __________________________');
  doc.moveDown(0.5);
  doc.text('Participants: __________________________');
  doc.addPage();

  // Sections
  aarSection(doc, '1. Exercise Summary', 'A 2-3 paragraph summary of the exercise: what scenario was used, what difficulty, who participated, how long the exercise ran, and the high-level outcome.');
  aarSection(doc, '2. Exercise Objectives', 'List the objectives the team set going into the exercise. For each, note whether the objective was met, partially met, or not addressed during the exercise.');
  aarSection(doc, '3. Strengths Observed', 'What did the team do well? Capture specific moments, not generic praise. Reference the inject timeline when describing.');
  aarSection(doc, '4. Areas for Improvement', 'What gaps did the exercise expose? Process gaps, knowledge gaps, communication gaps, tool gaps. Be specific. Reference inject timing and decisions.');
  aarSection(doc, '5. Decisions and Rationale', 'For each significant decision the team made during the exercise, capture: the decision, who made it, what alternatives were considered, what information was available at the time. This is the most useful section for future training.');
  aarSection(doc, '6. Action Items', 'Concrete follow-up actions with owners and target dates. Each action should address a specific gap from Section 4. Format: [Owner] — [Action] — [Target date].');
  aarSection(doc, '7. Lessons Learned', 'What insights from this exercise should be incorporated into the team\'s standard practices, runbooks, or training? This is what makes the exercise pay off long-term.');
  aarSection(doc, '8. Recommendations', 'High-level recommendations to leadership. These differ from action items: action items are concrete and have owners; recommendations are strategic.');
  aarSection(doc, '9. Appendix: Scenario Reference', null, true, data);

  return pdfDocToBuffer(doc);
}

function aarSection(doc, heading, prompt, isAppendix, data) {
  pdfHeading(doc, heading);
  if (prompt) {
    doc.fontSize(10).fillColor('#666666').font('Helvetica-Oblique').text(prompt);
    doc.moveDown(0.5);
    doc.font('Helvetica').fillColor('#000000');
  }
  if (isAppendix && data) {
    doc.fontSize(11).fillColor('#000000').text('Scenario: ' + data.scenario.title);
    doc.moveDown(0.3);
    doc.fontSize(11).text('Difficulty: ' + capitalize(data.difficulty));
    doc.moveDown(0.3);
    doc.fontSize(11).text('Description: ' + data.scenario.description);
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor('#666666').text('Inject timeline used in this exercise:');
    data.injects.forEach((inj, idx) => {
      if (doc.y > 700) doc.addPage();
      doc.fontSize(10).fillColor('#444444').text('  ' + inj.timing + ' — ' + inj.text);
      doc.moveDown(0.3);
    });
    return;
  }
  // Draw blank lines for handwritten or typed responses
  for (let i = 0; i < 6; i++) {
    if (doc.y > 720) doc.addPage();
    doc.moveTo(72, doc.y + 10).lineTo(540, doc.y + 10).strokeColor('#cccccc').stroke();
    doc.moveDown(1);
  }
  doc.moveDown(0.8);
}

function pdfHeading(doc, text) {
  if (doc.y > 680) doc.addPage();
  doc.fontSize(14).fillColor('#000000').font('Helvetica-Bold').text(text);
  doc.moveDown(0.3);
  doc.font('Helvetica').fontSize(11);
}

function pdfBody(doc, text) {
  doc.fontSize(11).fillColor('#000000').font('Helvetica').text(text, { paragraphGap: 6, lineGap: 2 });
}

function pdfBullet(doc, text, color) {
  doc.fontSize(11).fillColor(color || '#000000').font('Helvetica').text('• ' + text, { indent: 12, paragraphGap: 4, lineGap: 2 });
}

// ── DOCX builders ───────────────────────────────────────────────────────────
//
// docx 9.x is a declarative API. Build an array of Paragraph/Table elements,
// pass to a Document, pack to a Buffer.

const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, PageBreak } = docx;

function buildSitmanDocx(data) {
  const children = [];

  // Cover
  children.push(coverParagraph('FIREALIVE TABLETOP EXERCISE', { size: 20 }));
  children.push(coverParagraph('SITUATION MANUAL', { size: 20, after: 720 }));
  children.push(coverParagraph(data.scenario.title, { size: 44, bold: true, after: 240 }));
  children.push(coverParagraph('Difficulty: ' + capitalize(data.difficulty), { size: 28, after: 720 }));
  children.push(bodyParagraph(data.scenario.description));
  children.push(bodyParagraph('Generated ' + new Date().toLocaleString() + ' for facilitator preparation. The facilitator may modify this document before the exercise.', { italics: true, color: '666666' }));
  children.push(pageBreak());

  // Section 1
  children.push(headingParagraph('1. Exercise Overview'));
  children.push(bodyParagraph('This Situation Manual (SitMan) supports a tabletop exercise (TTX). It is intended for the facilitator. The participants should not see the inject timeline or decision points before the exercise begins; the facilitator presents these in sequence during the discussion.'));
  children.push(bodyParagraph('A TTX is a discussion-based exercise. There is no live system action, no real-time response, no actual incident. The team sits together, the facilitator reads the brief and then drops injects one at a time, and the team talks through how they would respond. The facilitator captures notes and decisions for the After-Action Report (AAR).'));

  // Section 2
  children.push(headingParagraph('2. Scenario Brief'));
  children.push(bodyParagraph(data.brief));

  // Section 3
  children.push(headingParagraph('3. Participants and Roles'));
  data.scenario.actors.forEach((a) => children.push(bulletParagraph(a)));

  // Section 4
  children.push(headingParagraph('4. Exercise Assumptions'));
  children.push(bodyParagraph('The team accepts the following as ground truth for the duration of the exercise:'));
  data.scenario.assumptions.forEach((a) => children.push(bulletParagraph(a)));

  // Section 5
  children.push(pageBreak());
  children.push(headingParagraph('5. Inject Timeline'));
  children.push(bodyParagraph('The facilitator reads each inject aloud at the indicated relative time, then leads the discussion of the decision points. The injects are sequential — the team should not see the next inject until they have discussed the current one.'));
  data.injects.forEach((inj, idx) => {
    children.push(new Paragraph({
      spacing: { before: 240, after: 120 },
      children: [
        new TextRun({ text: inj.timing + ' — Inject ' + (idx + 1), bold: true, size: 24 }),
      ],
    }));
    children.push(bodyParagraph(inj.text));
    if (inj.decision_points && inj.decision_points.length) {
      children.push(new Paragraph({
        spacing: { before: 80, after: 60 },
        children: [new TextRun({ text: 'Decision points:', italics: true, size: 22, color: '444444' })],
      }));
      inj.decision_points.forEach((dp) => children.push(bulletParagraph(dp, '444444')));
    }
  });

  // Section 6
  children.push(pageBreak());
  children.push(headingParagraph('6. Discussion Questions'));
  children.push(bodyParagraph('Use these questions to draw out the team\'s thinking after the inject timeline is complete.'));
  data.discussion_questions.forEach((q, idx) => {
    children.push(bodyParagraph((idx + 1) + '. ' + q));
  });

  // Section 7
  children.push(headingParagraph('7. References'));
  children.push(bodyParagraph('Facilitator preparation reading. Not required for participants.'));
  data.references.forEach((r) => children.push(bulletParagraph(r)));

  const doc = new Document({
    creator: 'FireAlive TTX Generator',
    title: 'Situation Manual: ' + data.scenario.title,
    description: 'Tabletop exercise SitMan, ' + data.difficulty + ' difficulty',
    sections: [{ children }],
  });

  return Packer.toBuffer(doc);
}

function buildAarDocx(data) {
  const children = [];

  // Cover
  children.push(coverParagraph('FIREALIVE TABLETOP EXERCISE', { size: 20 }));
  children.push(coverParagraph('AFTER-ACTION REPORT (TEMPLATE)', { size: 20, after: 720 }));
  children.push(coverParagraph(data.scenario.title, { size: 44, bold: true, after: 240 }));
  children.push(coverParagraph('Difficulty: ' + capitalize(data.difficulty), { size: 28, after: 480 }));
  children.push(bodyParagraph('This is a template. Fill in each section after the tabletop exercise. The completed AAR is the artifact of record for compliance, audit, and continuous improvement purposes.'));
  children.push(bodyParagraph('Exercise date: __________________________'));
  children.push(bodyParagraph('Facilitator: __________________________'));
  children.push(bodyParagraph('Participants: __________________________'));
  children.push(pageBreak());

  const aarSections = [
    { heading: '1. Exercise Summary', prompt: 'A 2-3 paragraph summary of the exercise: what scenario was used, what difficulty, who participated, how long the exercise ran, and the high-level outcome.' },
    { heading: '2. Exercise Objectives', prompt: 'List the objectives the team set going into the exercise. For each, note whether the objective was met, partially met, or not addressed during the exercise.' },
    { heading: '3. Strengths Observed', prompt: 'What did the team do well? Capture specific moments, not generic praise. Reference the inject timeline when describing.' },
    { heading: '4. Areas for Improvement', prompt: 'What gaps did the exercise expose? Process gaps, knowledge gaps, communication gaps, tool gaps. Be specific. Reference inject timing and decisions.' },
    { heading: '5. Decisions and Rationale', prompt: 'For each significant decision the team made during the exercise, capture: the decision, who made it, what alternatives were considered, what information was available at the time.' },
    { heading: '6. Action Items', prompt: 'Concrete follow-up actions with owners and target dates. Format: [Owner] — [Action] — [Target date].' },
    { heading: '7. Lessons Learned', prompt: 'What insights from this exercise should be incorporated into the team\'s standard practices, runbooks, or training?' },
    { heading: '8. Recommendations', prompt: 'High-level strategic recommendations to leadership.' },
  ];
  aarSections.forEach((sec) => {
    children.push(headingParagraph(sec.heading));
    children.push(new Paragraph({
      spacing: { before: 60, after: 240 },
      children: [new TextRun({ text: sec.prompt, italics: true, size: 20, color: '666666' })],
    }));
    // Empty paragraphs as space for typing
    for (let i = 0; i < 6; i++) {
      children.push(new Paragraph({ spacing: { after: 120 }, children: [new TextRun({ text: '' })] }));
    }
  });

  // Appendix
  children.push(headingParagraph('9. Appendix: Scenario Reference'));
  children.push(bodyParagraph('Scenario: ' + data.scenario.title));
  children.push(bodyParagraph('Difficulty: ' + capitalize(data.difficulty)));
  children.push(bodyParagraph('Description: ' + data.scenario.description));
  children.push(new Paragraph({
    spacing: { before: 120, after: 60 },
    children: [new TextRun({ text: 'Inject timeline used in this exercise:', italics: true, size: 20, color: '666666' })],
  }));
  data.injects.forEach((inj) => {
    children.push(bulletParagraph(inj.timing + ' — ' + inj.text, '444444'));
  });

  const doc = new Document({
    creator: 'FireAlive TTX Generator',
    title: 'After-Action Report: ' + data.scenario.title,
    description: 'AAR template, ' + data.difficulty + ' difficulty',
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

function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

// ── Utilities ───────────────────────────────────────────────────────────────

function capitalize(s) {
  if (!s || typeof s !== 'string') return '';
  return s.charAt(0).toUpperCase() + s.slice(1);
}

module.exports = {
  generateSitman,
  generateAar,
  VALID_FORMATS,
  VALID_TYPES,
};

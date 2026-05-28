// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Report Document Builder
//
// Generic server-side renderer that turns a structured report MODEL into a
// watermarked PDF or DOCX Buffer. Both the compliance exporter and the Report
// Engine exporter feed it; each route is responsible only for transforming its
// own data into the model below, then signing the returned bytes.
//
// MODEL
//   {
//     title:    string,                       // report title
//     subtitle: string?,                      // optional one-line subtitle
//     meta:     [[label, value], ...]?,        // optional key/value cover rows
//     sections: [
//       {
//         heading:    string,
//         paragraphs: string[]?,               // prose blocks
//         bullets:    string[]?,               // bullet lines
//         citations:  string[]?,               // rendered VERBATIM (see below)
//       },
//       ...
//     ]
//   }
//
// ANTI-HALLUCINATION INVARIANT
//   `citations` are rendered exactly as supplied -- one line each, no
//   reformatting, reordering, truncation, or synthesis. The Report Engine's
//   KB-cited output must round-trip through this builder unchanged; the builder
//   never invents, "tidies", or merges a citation. Callers pass the precise
//   strings their synthesis produced.
//
// WATERMARK / SIGNING
//   The caller passes a pre-sign footer descriptor { instanceLabel,
//   keyFingerprint, signedAt } (no verification id, no hash). The footer
//   therefore renders in BYTES MODE: it instructs the verifier to compute the
//   file's own SHA-256, because the signature is taken over the rendered bytes
//   and the hash cannot be printed into the bytes it hashes. The caller signs
//   the returned Buffer with report-signer.signReport({ material }) and records
//   the verification.
//
// Tabular data is rendered as headed bullet lists rather than tables: it is
// robust across both renderers and reads cleanly in a SOC report. Tables can
// be added later without changing the model's existing shape.
// ═══════════════════════════════════════════════════════════════════════════════

const PDFDocument = require('pdfkit');
const docx = require('docx');
const { stampPdfWatermark, docxWatermarkFooter } = require('./report-watermark');

// report-watermark exports stampPdfWatermark + docxWatermarkFooter; the PDF
// buffer collector below is the same pattern ttx-generator uses.
function collectPdf(doc) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    doc.end();
  });
}

// ── PDF helpers (same idioms as ttx-generator) ───────────────────────────────

function pdfHeading(doc, text) {
  if (doc.y > 660) doc.addPage();
  doc.fontSize(14).fillColor('#000000').font('Helvetica-Bold').text(text);
  doc.moveDown(0.3);
  doc.font('Helvetica').fontSize(11);
}
function pdfBody(doc, text) {
  doc.fontSize(11).fillColor('#000000').font('Helvetica').text(text, { paragraphGap: 6, lineGap: 2 });
}
function pdfBullet(doc, text) {
  doc.fontSize(11).fillColor('#000000').font('Helvetica').text('\u2022 ' + text, { indent: 12, paragraphGap: 4, lineGap: 2 });
}

// ── PDF builder ──────────────────────────────────────────────────────────────

/**
 * buildReportPdf(model, footerDescriptor) -> Promise<Buffer>
 *
 * bufferPages:true is required so stampPdfWatermark can stamp every page; the
 * 96pt bottom margin leaves room for the three-line footer.
 */
function buildReportPdf(model, footerDescriptor) {
  const doc = new PDFDocument({
    size: 'LETTER',
    margins: { top: 72, bottom: 96, left: 72, right: 72 },
    bufferPages: true,
    info: { Title: model.title || 'FireAlive Report', Author: 'FireAlive', Subject: model.subtitle || '' },
  });

  doc.fontSize(20).fillColor('#000000').font('Helvetica-Bold').text(model.title || 'FireAlive Report');
  if (model.subtitle) {
    doc.moveDown(0.3);
    doc.fontSize(12).fillColor('#444444').font('Helvetica').text(model.subtitle);
  }
  if (Array.isArray(model.meta) && model.meta.length) {
    doc.moveDown(0.4);
    for (const [label, value] of model.meta) {
      doc.fontSize(10).fillColor('#444444').font('Helvetica').text(`${label}: ${value}`);
    }
  }
  doc.moveDown(0.8).fillColor('#000000').font('Helvetica').fontSize(11);

  for (const sec of model.sections || []) {
    pdfHeading(doc, sec.heading || '');
    for (const p of sec.paragraphs || []) pdfBody(doc, p);
    for (const b of sec.bullets || []) pdfBullet(doc, b);
    if (Array.isArray(sec.citations) && sec.citations.length) {
      doc.moveDown(0.2).fontSize(10).fillColor('#444444').font('Helvetica-Oblique').text('Citations:');
      for (const c of sec.citations) {
        // VERBATIM -- exactly as supplied, one line each.
        doc.fontSize(10).fillColor('#444444').font('Helvetica').text('\u2014 ' + c, { indent: 12, paragraphGap: 2 });
      }
      doc.font('Helvetica').fontSize(11).fillColor('#000000');
    }
    doc.moveDown(0.5);
  }

  stampPdfWatermark(doc, footerDescriptor);
  return collectPdf(doc);
}

// ── DOCX builder ─────────────────────────────────────────────────────────────

/**
 * buildReportDocx(model, footerDescriptor) -> Promise<Buffer>
 */
function buildReportDocx(model, footerDescriptor) {
  const children = [];

  children.push(new docx.Paragraph({
    heading: docx.HeadingLevel.TITLE,
    spacing: { after: 120 },
    children: [new docx.TextRun({ text: model.title || 'FireAlive Report', bold: true, size: 36 })],
  }));
  if (model.subtitle) {
    children.push(new docx.Paragraph({
      spacing: { after: 120 },
      children: [new docx.TextRun({ text: model.subtitle, color: '444444', size: 24 })],
    }));
  }
  if (Array.isArray(model.meta) && model.meta.length) {
    for (const [label, value] of model.meta) {
      children.push(new docx.Paragraph({
        spacing: { after: 40 },
        children: [new docx.TextRun({ text: `${label}: ${value}`, color: '444444', size: 20 })],
      }));
    }
  }

  for (const sec of model.sections || []) {
    children.push(new docx.Paragraph({
      heading: docx.HeadingLevel.HEADING_2,
      spacing: { before: 240, after: 120 },
      children: [new docx.TextRun({ text: sec.heading || '', bold: true, size: 28 })],
    }));
    for (const p of sec.paragraphs || []) {
      children.push(new docx.Paragraph({
        spacing: { after: 120, line: 300 },
        children: [new docx.TextRun({ text: p, size: 22 })],
      }));
    }
    for (const b of sec.bullets || []) {
      children.push(new docx.Paragraph({
        bullet: { level: 0 },
        spacing: { after: 60 },
        children: [new docx.TextRun({ text: b, size: 22 })],
      }));
    }
    if (Array.isArray(sec.citations) && sec.citations.length) {
      children.push(new docx.Paragraph({
        spacing: { before: 80, after: 40 },
        children: [new docx.TextRun({ text: 'Citations:', italics: true, color: '444444', size: 20 })],
      }));
      for (const c of sec.citations) {
        // VERBATIM -- exactly as supplied, one line each.
        children.push(new docx.Paragraph({
          spacing: { after: 40 },
          indent: { left: 240 },
          children: [new docx.TextRun({ text: '\u2014 ' + c, color: '444444', size: 20 })],
        }));
      }
    }
  }

  const doc = new docx.Document({
    creator: 'FireAlive',
    title: model.title || 'FireAlive Report',
    description: model.subtitle || '',
    sections: [{
      footers: { default: docxWatermarkFooter(footerDescriptor) },
      children,
    }],
  });

  return docx.Packer.toBuffer(doc);
}

module.exports = {
  buildReportPdf,
  buildReportDocx,
};

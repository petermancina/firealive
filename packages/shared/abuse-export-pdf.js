'use strict';

// FireAlive -- shared builder for the flagger's one-shot abuse-flag submission
// PDF (client-side, zero-access). Both the Analyst Client and the Management
// Console main processes call this to render a submitter's personal, signed
// copy of a flag that was submitted to the independent reviewer.
//
// Design notes:
//   - The flagged CONTENT shown here is the authentic text the system captured
//     from the conversation (never typed by the submitter). It is rendered for
//     a human to read AND embedded as exact bytes (content_b64) in the
//     machine-readable verification block, so the export is self-verifying even
//     if the reviewer vault is later destroyed: a verifier decodes content_b64,
//     SHA-256s it to obtain content_sha256, rebuilds the canonical payload and
//     SHA-256s that to obtain the report hash, then checks the signature for
//     that hash against the instance public key.
//   - Only the flagged content is cryptographically bound (via content_sha256
//     inside the signed payload). The reporter note is the submitter's own
//     statement and is shown for context but is not part of the signed payload.
//   - This builder performs no crypto and makes no network or IPC calls. It
//     receives the already-signed descriptor from the server's sign-record
//     endpoint and renders it. pdfkit ships the standard 14 PDF fonts, so no
//     external font files are required.

const PDFDocument = require('pdfkit');

const SANS = 'Helvetica';
const BOLD = 'Helvetica-Bold';
const MONO = 'Courier';

function targetLabel(t) {
  switch (t) {
    case 'peer_session': return 'peer chat';
    case 'lead_chat': return 'lead chat';
    case 'board_post': return 'peer board post';
    default: return t || 'unknown source';
  }
}

// Build the submission-record PDF. Returns a Promise<Buffer>.
//
// model = {
//   contentText: string,   // authentic flagged content (exact bytes hashed by the caller)
//   note: string,          // reporter note (already sanitized by the caller)
//   descriptor: {          // returned by POST /api/peer/flags/:id/sign-record
//     payload: { flag_uuid, target_type, submitted_at, instance_label, content_sha256 },
//     canonical, reportSha256, signatureB64, keyFingerprint, instanceLabel, signedAt
//   }
// }
function buildAbuseExportPdf(model) {
  const m = model || {};
  const contentText = typeof m.contentText === 'string' ? m.contentText : '';
  const note = typeof m.note === 'string' ? m.note : '';
  const descriptor = m.descriptor || {};
  const payload = descriptor.payload || {};

  const flagUuid = payload.flag_uuid || '';
  const targetType = payload.target_type || '';
  const submittedAt = payload.submitted_at || '';
  const instanceLabel = descriptor.instanceLabel || payload.instance_label || '';
  const contentSha = payload.content_sha256 || '';
  const reportSha = descriptor.reportSha256 || '';
  const signatureB64 = descriptor.signatureB64 || '';
  const keyFingerprint = descriptor.keyFingerprint || '';
  const signedAt = descriptor.signedAt || '';
  const canonical = descriptor.canonical || '';

  // Exact content bytes, so the PDF is self-verifying without the vault.
  const contentB64 = Buffer.from(contentText, 'utf8').toString('base64');

  const verifyObject = {
    type: 'firealive-abuse-flag-record',
    canonical_payload: canonical,
    content_b64: contentB64,
    content_sha256: contentSha,
    report_sha256: reportSha,
    signature_b64: signatureB64,
    key_fingerprint: keyFingerprint,
    instance_label: instanceLabel,
    signed_at: signedAt,
    verify_endpoint: '/api/verify/report/' + reportSha,
  };
  const verifyJson = JSON.stringify(verifyObject, null, 2);

  return new Promise((resolve, reject) => {
    let doc;
    try {
      doc = new PDFDocument({
        size: 'LETTER',
        margin: 54,
        info: { Title: 'FireAlive Abuse Flag Submission Record', Author: 'FireAlive' },
      });
    } catch (e) { reject(e); return; }

    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const label = targetLabel(targetType);

    // Title + notice
    doc.font(BOLD).fontSize(18).fillColor('black')
      .text('FireAlive -- Abuse Flag Submission Record');
    doc.moveDown(0.3);
    doc.font(SANS).fontSize(9).fillColor('#444444').text(
      'This is the submitter personal, signed copy of a flag submitted to the ' +
      'independent reviewer. The authoritative record is the reviewer sealed ' +
      'vault; this copy is a backup in case that record is later lost. The flagged ' +
      'content below was captured by the system from the conversation, not typed ' +
      'by the submitter. Only the flagged content is cryptographically bound; the ' +
      'reporter note is the submitter own statement.'
    );
    doc.fillColor('black').moveDown(1);

    // Submission metadata
    doc.font(BOLD).fontSize(11).text('Submission');
    doc.moveDown(0.2);
    doc.font(SANS).fontSize(10);
    [
      ['Instance', instanceLabel],
      ['Flag ID', flagUuid],
      ['Source', label],
      ['Submitted at', submittedAt],
      ['Signed at', signedAt],
    ].forEach(function (kv) { doc.text(kv[0] + ': ' + kv[1]); });
    doc.moveDown(1);

    // Flagged content (authentic)
    doc.font(BOLD).fontSize(11).text('Flagged content (captured from ' + label + ')');
    doc.moveDown(0.2);
    doc.font(MONO).fontSize(9).text(contentText.length ? contentText : '(none)', { lineGap: 1 });
    doc.moveDown(1);

    // Reporter note
    doc.font(BOLD).fontSize(11).text('Reporter note');
    doc.moveDown(0.2);
    doc.font(SANS).fontSize(10).text(note.length ? note : '(none)');
    doc.moveDown(1);

    // Verification
    doc.font(BOLD).fontSize(11).text('Verification');
    doc.moveDown(0.2);
    doc.font(SANS).fontSize(9).fillColor('#444444').text(
      'To confirm this record is genuine, a verifier with the instance public key ' +
      'decodes content_b64 and SHA-256s it (must equal content_sha256), rebuilds ' +
      'the canonical payload and SHA-256s it (must equal report_sha256), and checks ' +
      'signature_b64 over report_sha256. An independent reviewer can additionally ' +
      'confirm content_sha256 matches the content decrypted from the vault. The ' +
      'instance public key is available to authorized reviewers at ' +
      '/api/report-signing/key; verification of an abuse-flag record is reviewer ' +
      'access only.'
    );
    doc.fillColor('black').moveDown(0.4);
    doc.font(MONO).fontSize(8);
    doc.text('content_sha256: ' + contentSha);
    doc.text('report_sha256:  ' + reportSha);
    doc.text('key_fingerprint: ' + keyFingerprint);
    doc.moveDown(0.5);

    doc.font(SANS).fontSize(9).text('Machine-readable verification payload:');
    doc.moveDown(0.2);
    doc.font(MONO).fontSize(7)
      .text('[BEGIN VERIFICATION PAYLOAD]')
      .text(verifyJson)
      .text('[END VERIFICATION PAYLOAD]');

    doc.end();
  });
}

module.exports = { buildAbuseExportPdf, targetLabel };

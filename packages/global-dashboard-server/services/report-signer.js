// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Report Signer (Global Dashboard server)
//
// Orchestration layer over report-signing-keys.js. Turns "sign this report"
// into: hash the signed material -> Ed25519-sign the digest with the active
// instance key -> insert a PERMANENT, append-only report_verifications row ->
// return a descriptor the caller embeds in the report watermark/footer.
//
// On the GD, reports are signed by their rendered PDF/DOCX file bytes via
// signReport({ material }) (report types: compliance, report_engine). The
// canonical-payload path (signReportCanonical) is retained verbatim from the
// MC service as a general utility but is unused on the GD -- the zero-access
// abuse-flag flow it serves is an MC/AC feature with no GD equivalent.
//
// TWO SIGNING SHAPES, ONE TABLE
//
//   Server-side reports (compliance, report_engine, helper_pay): the signed
//   material is the produced PDF/DOCX bytes. The server controls the renderer,
//   so the byte stream is deterministic; signReport() hashes the bytes.
//
//   Client-side abuse reports (abuse_flag): the signed material is a CANONICAL
//   DATA PAYLOAD, not the rendered PDF. The payload is
//     { flag_uuid, target_type, submitted_at, instance_label, content_sha256 }
//   where content_sha256 is a hash of the report text supplied by the
//   accuser's device. The SERVER constructs this payload from the flag row it
//   already holds plus the client-supplied content_sha256, then signs the
//   canonical JSON. The server never receives or stores the plaintext -- only
//   the content hash -- so abuse reports stay zero-access while remaining
//   cryptographically bound to the sealed vault entry (a reviewer who can
//   decrypt the vault recomputes content_sha256 and confirms the match).
//
// CANONICAL FORM
//
//   canonicalize(obj) produces deterministic JSON: object keys sorted
//   ascending at every level, no insignificant whitespace, UTF-8. The offline
//   verifier guide and the ARC reviewer reconstruct the same bytes, so the
//   digest -- and therefore the signature check and the report_verifications
//   lookup -- are reproducible without any FireAlive tooling.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const {
  signReportDigest,
  verifyReportDigest,
} = require('./report-signing-keys');

const VALID_REPORT_TYPES = ['compliance', 'report_engine'];

// ── Canonical JSON ─────────────────────────────────────────────────────────

/**
 * canonicalize(value) -> string
 *
 * Deterministic JSON serialization: object keys sorted ascending at every
 * depth, arrays preserved in order, no insignificant whitespace. Rejects
 * non-finite numbers and undefined (which JSON.stringify would silently drop
 * or emit as null) so the canonical bytes are unambiguous.
 */
function canonicalize(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(value) {
  if (value === null) return null;
  if (Array.isArray(value)) return value.map(sortValue);
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('canonicalize: non-finite numbers are not allowed');
  }
  if (typeof value === 'undefined') {
    throw new Error('canonicalize: undefined values are not allowed');
  }
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = sortValue(value[key]);
    }
    return out;
  }
  return value;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function sha256Hex(material) {
  const buf = Buffer.isBuffer(material) ? material : Buffer.from(String(material), 'utf8');
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function getInstanceLabel(db) {
  const row = db.prepare("SELECT value FROM config WHERE key = 'instance_label'").get();
  return row ? row.value : 'FireAlive Instance (unconfigured)';
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * signReport({ db, reportType, subjectRef, material, metadata })
 *
 * Hash the signed material, Ed25519-sign the digest with the active instance
 * key, and insert a permanent report_verifications row. Use this for
 * server-side reports where `material` is the produced PDF/DOCX bytes (Buffer)
 * or any deterministic string.
 *
 * metadata (optional object) is stored as content-blind metadata_json -- the
 * caller is responsible for never placing plaintext in it.
 *
 * Returns a descriptor for the watermark/footer:
 *   { verificationId, reportType, subjectRef, sha256, signatureB64,
 *     keyFingerprint, instanceLabel, signedAt }
 */
function signReport({ db, reportType, subjectRef, material, metadata = null }) {
  if (!VALID_REPORT_TYPES.includes(reportType)) {
    throw new Error(`signReport: invalid reportType '${reportType}'`);
  }
  if (!subjectRef || typeof subjectRef !== 'string') {
    throw new Error('signReport: subjectRef must be a non-empty string');
  }
  const sha256 = sha256Hex(material);
  return recordSignature({ db, reportType, subjectRef, sha256, metadata });
}

/**
 * signReportCanonical({ db, reportType, subjectRef, payload, metadata })
 *
 * Like signReport, but signs the canonical JSON of `payload` rather than raw
 * bytes. Used by the abuse-flag path: the server builds the canonical payload
 * (flag_uuid, target_type, submitted_at, instance_label, content_sha256) and
 * signs it without ever touching plaintext. Returns the same descriptor shape
 * plus `canonical` (the exact bytes signed, so the caller can echo them to the
 * client for the footer/verification).
 */
function signReportCanonical({ db, reportType, subjectRef, payload, metadata = null }) {
  if (!VALID_REPORT_TYPES.includes(reportType)) {
    throw new Error(`signReportCanonical: invalid reportType '${reportType}'`);
  }
  if (!subjectRef || typeof subjectRef !== 'string') {
    throw new Error('signReportCanonical: subjectRef must be a non-empty string');
  }
  if (!payload || typeof payload !== 'object') {
    throw new Error('signReportCanonical: payload must be an object');
  }
  const canonical = canonicalize(payload);
  const sha256 = sha256Hex(canonical);
  const descriptor = recordSignature({ db, reportType, subjectRef, sha256, metadata });
  return { ...descriptor, canonical };
}

// Shared insert path: sign the digest with the active key and append the
// permanent verification row. Never updates -- the table's triggers enforce
// append-only/no-delete; this only ever inserts.
function recordSignature({ db, reportType, subjectRef, sha256, metadata }) {
  const { signature, keyFingerprint } = signReportDigest(db, sha256);
  const signatureB64 = signature.toString('base64');
  const instanceLabel = getInstanceLabel(db);
  const id = crypto.randomUUID();

  db.prepare(`
    INSERT INTO report_verifications
      (id, report_type, subject_ref, signed_payload_sha256, signature,
       key_fingerprint, instance_label, metadata_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    reportType,
    subjectRef,
    sha256,
    signatureB64,
    keyFingerprint,
    instanceLabel,
    metadata ? JSON.stringify(metadata) : null
  );

  const row = db.prepare('SELECT signed_at FROM report_verifications WHERE id = ?').get(id);

  return {
    verificationId: id,
    reportType,
    subjectRef,
    sha256,
    signatureB64,
    keyFingerprint,
    instanceLabel,
    signedAt: row ? row.signed_at : null,
  };
}

/**
 * verifyReportByHash(db, sha256Hex)
 *
 * Look up a recorded report verification by the SHA-256 of its signed
 * material and independently re-verify the stored Ed25519 signature against
 * the recorded key fingerprint (defense in depth -- a tampered
 * report_verifications row could not pass this check even though the table is
 * already append-only).
 *
 * Returns null if no row matches the hash. Otherwise returns a CONTENT-BLIND
 * descriptor:
 *   { valid, reportType, subjectRef, keyFingerprint, instanceLabel,
 *     signedAt, metadata }
 *
 * Never returns content. Route-layer authorization decides who may call this
 * per report_type (abuse_flag -> lead only).
 */
function verifyReportByHash(db, sha256Hex) {
  if (typeof sha256Hex !== 'string' || !/^[0-9a-f]{64}$/.test(sha256Hex)) {
    throw new Error('verifyReportByHash: sha256Hex must be a 64-char lowercase hex string');
  }
  const row = db.prepare(`
    SELECT report_type, subject_ref, signed_payload_sha256, signature,
           key_fingerprint, instance_label, signed_at, metadata_json
    FROM report_verifications
    WHERE signed_payload_sha256 = ?
    ORDER BY signed_at DESC
    LIMIT 1
  `).get(sha256Hex);

  if (!row) return null;

  const digest = Buffer.from(row.signed_payload_sha256, 'hex');
  const signature = Buffer.from(row.signature, 'base64');
  const valid = verifyReportDigest(db, digest, signature, row.key_fingerprint);

  let metadata = null;
  if (row.metadata_json) {
    try { metadata = JSON.parse(row.metadata_json); } catch { metadata = null; }
  }

  return {
    valid,
    reportType: row.report_type,
    subjectRef: row.subject_ref,
    keyFingerprint: row.key_fingerprint,
    signedPayloadSha256: row.signed_payload_sha256,
    signatureB64: row.signature,
    instanceLabel: row.instance_label,
    signedAt: row.signed_at,
    metadata,
  };
}

module.exports = {
  canonicalize,
  sha256Hex,
  getInstanceLabel,
  signReport,
  signReportCanonical,
  verifyReportByHash,
  VALID_REPORT_TYPES,
};

// FIREALIVE GD -- Intel TDX attestation quote verifier (B6c PR-5, verbatim twin)
//
// Verifies an Intel TDX DCAP quote (version 4, ECDSA-P256 attestation key) end
// to end. A TDX quote is a two-level signature:
//
//   1. The TD report (header + TD quote body) is signed by an ephemeral
//      Attestation Key (AK).
//   2. The AK is bound to the Quoting Enclave: the QE report's REPORTDATA holds
//      SHA-256(AK_pubkey || QE_AUTH_DATA).
//   3. The QE report is signed by the platform PCK (Provisioning Certification
//      Key).
//   4. The PCK certificate chains PCK -> Intel SGX intermediate CA -> Intel SGX
//      Root CA. The PCK leaf + intermediate travel inside the quote (cert-data
//      type 5, PEM); only the Intel SGX Root CA is bundled and trusted, in
//      packages/global-dashboard-server/data/attestation-roots/ (added at the
//      hardware-validation pass). The root is passed in by the orchestrator
//      (gd-cloud-attestation); this module is pure verification.
//
// This module parses the quote, performs all four checks, binds the caller's
// nonce via the TD REPORTDATA, and extracts TEE_TCB_SVN, MRTD, and RTMR0..3.
// The TCB-floor decision and measurement TOFU pin are applied by the
// orchestrator / cloud-mode from the values returned here.
//
// Byte-order note: the SGX/TDX quote stores ECDSA scalar values (signature r||s
// and the raw AK public point x||y) little-endian, per the Intel SGX SDK
// convention; this module reverses them to big-endian for Node crypto. The
// synthetic fixtures exercise this conversion for self-consistency; correctness
// against a real Intel quote is confirmed at the hardware-validation pass.
//
// ASCII only; no template literals.

const fs = require('fs');
const crypto = require('crypto');

const HEADER_LEN = 48;
const TD_BODY_LEN = 584;
const SIGNED_LEN = HEADER_LEN + TD_BODY_LEN;   // 632 -- bytes the quote sig covers
const QE_REPORT_LEN = 384;
const TDX_VERSION = 4;
const TEE_TYPE_TDX = 0x81;
const AK_TYPE_ECDSA_P256 = 2;
const PCK_CHAIN_CERT_TYPE = 5;

// ---- low-level helpers ----------------------------------------------------

function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v = v >>> 8; }
  return Buffer.from([0x80 | bytes.length].concat(bytes));
}

function derInteger(beBuf) {
  let i = 0;
  while (i < beBuf.length - 1 && beBuf[i] === 0) i += 1;
  let v = beBuf.slice(i);
  if (v.length === 0) v = Buffer.from([0]);
  if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0]), v]);
  return Buffer.concat([Buffer.from([0x02]), derLen(v.length), v]);
}

// 64-byte raw r||s (little-endian per the SGX convention) -> DER signature.
function rawRsToDer(raw64) {
  const r = Buffer.from(raw64.slice(0, 32)).reverse();
  const s = Buffer.from(raw64.slice(32, 64)).reverse();
  const body = Buffer.concat([derInteger(r), derInteger(s)]);
  return Buffer.concat([Buffer.from([0x30]), derLen(body.length), body]);
}

// 64-byte raw public point x||y (little-endian) -> P-256 public KeyObject.
function p256PublicKeyFromRaw(xy) {
  const x = Buffer.from(xy.slice(0, 32)).reverse();
  const y = Buffer.from(xy.slice(32, 64)).reverse();
  const jwk = {
    kty: 'EC', crv: 'P-256',
    x: x.toString('base64url'), y: y.toString('base64url'),
  };
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

// Split a concatenated PEM blob into individual certificate PEMs (no regex).
function splitPems(pemText) {
  const out = [];
  const begin = '-----BEGIN CERTIFICATE-----';
  const end = '-----END CERTIFICATE-----';
  let idx = 0;
  while (true) {
    const e = pemText.indexOf(end, idx);
    if (e === -1) break;
    const b = pemText.indexOf(begin, idx);
    if (b === -1 || b > e) break;
    out.push(pemText.slice(b, e + end.length));
    idx = e + end.length;
  }
  return out;
}

// ---- quote parsing --------------------------------------------------------

function parseQuote(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'hex');
  if (buf.length < SIGNED_LEN + 4) {
    throw new Error('quote too short: ' + buf.length + ' bytes');
  }
  const header = {
    version: buf.readUInt16LE(0),
    akType: buf.readUInt16LE(2),
    teeType: buf.readUInt32LE(4),
    qeVendorId: Buffer.from(buf.slice(0x0C, 0x1C)).toString('hex'),
  };
  const bodyOff = HEADER_LEN;
  const body = {
    teeTcbSvn: Buffer.from(buf.slice(bodyOff + 0, bodyOff + 16)),
    mrtd: Buffer.from(buf.slice(bodyOff + 136, bodyOff + 184)),
    rtmr0: Buffer.from(buf.slice(bodyOff + 328, bodyOff + 376)),
    rtmr1: Buffer.from(buf.slice(bodyOff + 376, bodyOff + 424)),
    rtmr2: Buffer.from(buf.slice(bodyOff + 424, bodyOff + 472)),
    rtmr3: Buffer.from(buf.slice(bodyOff + 472, bodyOff + 520)),
    reportData: Buffer.from(buf.slice(bodyOff + 520, bodyOff + 584)),
  };
  const signedBytes = Buffer.from(buf.slice(0, SIGNED_LEN));

  let o = SIGNED_LEN;
  const sigDataLen = buf.readUInt32LE(o); o += 4;
  if (buf.length < o + sigDataLen) throw new Error('truncated signature data');

  const quoteSig = Buffer.from(buf.slice(o, o + 64));
  const akPub = Buffer.from(buf.slice(o + 64, o + 128));
  const qeReport = Buffer.from(buf.slice(o + 128, o + 128 + QE_REPORT_LEN));
  let p = o + 128 + QE_REPORT_LEN;
  const qeReportSig = Buffer.from(buf.slice(p, p + 64)); p += 64;
  const qeAuthSize = buf.readUInt16LE(p); p += 2;
  const qeAuthData = Buffer.from(buf.slice(p, p + qeAuthSize)); p += qeAuthSize;
  const certType = buf.readUInt16LE(p); p += 2;
  const certSize = buf.readUInt32LE(p); p += 4;
  const certData = Buffer.from(buf.slice(p, p + certSize));

  // QE report REPORTDATA is the last 64 bytes of the 384-byte report.
  const qeReportData = Buffer.from(qeReport.slice(QE_REPORT_LEN - 64, QE_REPORT_LEN));

  return {
    raw: buf, header: header, body: body, signedBytes: signedBytes,
    quoteSig: quoteSig, akPub: akPub, qeReport: qeReport, qeReportData: qeReportData,
    qeReportSig: qeReportSig, qeAuthData: qeAuthData,
    certType: certType, certData: certData,
  };
}

// True when every component of svn is at or above the corresponding floor byte.
function compareTcbSvn(svn, floor) {
  const a = Buffer.isBuffer(svn) ? svn : Buffer.from(String(svn), 'hex');
  const f = Buffer.isBuffer(floor) ? floor : Buffer.from(String(floor), 'hex');
  for (let i = 0; i < f.length; i += 1) {
    if ((a[i] || 0) < f[i]) return false;
  }
  return true;
}

// ---- PCK chain ------------------------------------------------------------

function certValidNow(cert, now) {
  const nb = new Date(cert.validFrom);
  const na = new Date(cert.validTo);
  if (isNaN(nb.getTime()) || isNaN(na.getTime())) return true;
  return now.getTime() >= nb.getTime() && now.getTime() <= na.getTime();
}

function opensslVerifyPck(leafPem, interPem, rootPem) {
  const cp = require('child_process');
  const os = require('os');
  const path = require('path');
  let dir = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tdxpck-'));
    const lp = path.join(dir, 'leaf.pem');
    const ip = path.join(dir, 'inter.pem');
    const rp = path.join(dir, 'root.pem');
    fs.writeFileSync(lp, leafPem);
    fs.writeFileSync(ip, interPem);
    fs.writeFileSync(rp, rootPem);
    const out = cp.execFileSync('openssl',
      ['verify', '-CAfile', rp, '-untrusted', ip, lp], { encoding: 'utf8' });
    if (out.indexOf(': OK') !== -1) return { ok: true, reason: 'pck chain ok (openssl)' };
    return { ok: false, reason: 'openssl verify failed: ' + out.trim() };
  } catch (e) {
    const msg = (e && e.stderr ? e.stderr.toString() : '') || (e && e.message) || 'unknown';
    return { ok: false, reason: 'openssl verify error: ' + String(msg).trim() };
  } finally {
    if (dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e2) { /* ignore */ } }
  }
}

// chainPems: PCK leaf, then intermediate(s), as carried in the quote. The trust
// anchor is the bundled Intel SGX Root CA (rootPem), not any root in the quote.
function verifyPckChain(chainPems, rootPem, now) {
  const t = now || new Date();
  if (!chainPems || chainPems.length < 2) {
    return { ok: false, reason: 'PCK chain must contain leaf + intermediate' };
  }
  const leafPem = chainPems[0];
  const interPem = chainPems[1];
  let leaf, inter, root;
  try {
    leaf = new crypto.X509Certificate(leafPem);
    inter = new crypto.X509Certificate(interPem);
    root = new crypto.X509Certificate(rootPem);
  } catch (e) {
    return opensslVerifyPck(leafPem, interPem, rootPem);
  }
  let selfRoot, interByRoot, leafByInter;
  try {
    selfRoot = root.verify(root.publicKey);
    interByRoot = inter.verify(root.publicKey);
    leafByInter = leaf.verify(inter.publicKey);
  } catch (e) {
    const fb = opensslVerifyPck(leafPem, interPem, rootPem);
    if (fb.ok) fb.leaf = leaf;
    return fb;
  }
  if (!selfRoot) return { ok: false, reason: 'Intel root is not self-signed' };
  if (!interByRoot) return { ok: false, reason: 'PCK intermediate not signed by Intel root' };
  if (!leafByInter) return { ok: false, reason: 'PCK leaf not signed by intermediate' };
  if (!certValidNow(leaf, t)) return { ok: false, reason: 'PCK leaf outside validity window' };
  if (!certValidNow(inter, t)) return { ok: false, reason: 'PCK intermediate outside validity window' };
  if (!certValidNow(root, t)) return { ok: false, reason: 'Intel root outside validity window' };
  return { ok: true, reason: 'pck chain ok', leaf: leaf };
}

// ---- top-level verify -----------------------------------------------------

function fail(reason) { return { verified: false, reason: reason, tech: 'tdx' }; }

// opts: { quote (Buffer|hex), intelRootPem, expectedNonce?, now? }
function verify(opts) {
  const options = opts || {};
  const now = options.now || new Date();

  let q;
  try { q = parseQuote(options.quote); }
  catch (e) { return fail('quote parse failed: ' + e.message); }

  if (q.header.version !== TDX_VERSION) return fail('unexpected quote version: ' + q.header.version);
  if (q.header.teeType !== TEE_TYPE_TDX) return fail('not a TDX quote (tee_type 0x' + q.header.teeType.toString(16) + ')');
  if (q.header.akType !== AK_TYPE_ECDSA_P256) return fail('unsupported attestation key type: ' + q.header.akType);
  if (q.certType !== PCK_CHAIN_CERT_TYPE) return fail('unsupported cert-data type: ' + q.certType);
  if (!options.intelRootPem) return fail('missing bundled Intel SGX root certificate');

  // 1. TD report signature under the AK.
  let akKey;
  try { akKey = p256PublicKeyFromRaw(q.akPub); }
  catch (e) { return fail('attestation key parse failed: ' + e.message); }
  let quoteSigOk;
  try { quoteSigOk = crypto.verify('sha256', q.signedBytes, akKey, rawRsToDer(q.quoteSig)); }
  catch (e) { return fail('quote signature check errored: ' + e.message); }
  if (!quoteSigOk) return fail('quote signature invalid');

  // 2. AK binding: QE report REPORTDATA[0:32] == SHA-256(AK_pub || QE_AUTH_DATA).
  const expectBind = crypto.createHash('sha256')
    .update(q.akPub).update(q.qeAuthData).digest();
  if (!q.qeReportData.slice(0, 32).equals(expectBind)) {
    return fail('attestation key not bound to QE report');
  }

  // 3 + 4. PCK chain, then QE report signature under the PCK leaf.
  const chainPems = splitPems(q.certData.toString('utf8'));
  const chain = verifyPckChain(chainPems, options.intelRootPem, now);
  if (!chain.ok) return fail('PCK chain: ' + chain.reason);
  let pckLeaf;
  try { pckLeaf = chain.leaf || new crypto.X509Certificate(chainPems[0]); }
  catch (e) { return fail('PCK leaf load failed: ' + e.message); }
  let qeSigOk;
  try { qeSigOk = crypto.verify('sha256', q.qeReport, pckLeaf.publicKey, rawRsToDer(q.qeReportSig)); }
  catch (e) { return fail('QE report signature check errored: ' + e.message); }
  if (!qeSigOk) return fail('QE report signature invalid');

  // 5. Nonce binding via the TD REPORTDATA.
  let nonceMatch = null;
  if (options.expectedNonce != null) {
    const nonce = Buffer.isBuffer(options.expectedNonce)
      ? options.expectedNonce : Buffer.from(String(options.expectedNonce), 'hex');
    nonceMatch = q.body.reportData.slice(0, nonce.length).equals(nonce);
    if (!nonceMatch) return fail('report nonce does not match expected');
  }

  return {
    verified: true,
    reason: 'ok',
    tech: 'tdx',
    tcbSvn: q.body.teeTcbSvn.toString('hex'),
    measurement: q.body.mrtd.toString('hex'),
    rtmrs: [
      q.body.rtmr0.toString('hex'), q.body.rtmr1.toString('hex'),
      q.body.rtmr2.toString('hex'), q.body.rtmr3.toString('hex'),
    ],
    reportData: q.body.reportData.toString('hex'),
    nonceMatch: nonceMatch,
  };
}

module.exports = {
  HEADER_LEN,
  TD_BODY_LEN,
  SIGNED_LEN,
  parseQuote,
  splitPems,
  compareTcbSvn,
  verifyPckChain,
  verify,
};

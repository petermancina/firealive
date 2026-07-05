// FIREALIVE GD -- AMD SEV-SNP attestation report verifier (B6c PR-5, verbatim twin)
//
// Verifies a raw AMD SEV-SNP ATTESTATION_REPORT (the binary structure produced
// by the PSP and fetched via configfs-tsm) end-to-end:
//
//   1. Parse the fixed-offset report structure (1184 bytes; signature in the
//      trailing 512-byte field; the signature covers the first 672 bytes).
//   2. Verify the report's ECDSA P-384 / SHA-384 signature under the VCEK's
//      public key. The on-wire signature stores R and S as little-endian; this
//      module reassembles a DER signature for Node's crypto.verify.
//   3. Verify the certificate chain VCEK -> ASK -> ARK against the bundled,
//      trusted AMD root (ARK). The trusted ASK/ARK ship in
//      packages/global-dashboard-server/data/attestation-roots/ (added at the
//      hardware-validation pass). Roots are passed in by the orchestrator
//      (gd-cloud-attestation); this module is pure verification.
//      Primary path uses crypto.X509Certificate; an openssl chain-verify
//      fallback covers cert-format edge cases.
//   4. Extract the TCB version components (bootloader / tee / snp / microcode)
//      and the launch MEASUREMENT, and bind the caller's nonce by checking the
//      report's REPORT_DATA. The TCB-floor decision and measurement TOFU pin are
//      applied by the orchestrator / cloud-mode using the values returned here.
//
// VCEK material comes from the report's auxblob (offline) or, failing that, a
// one-time AMD KDS fetch pinned by the caller -- handled in the orchestrator;
// this module receives the VCEK as PEM.
//
// Deferred to the hardware-validation pass (needs real VCEKs to test against):
// binding the VCEK's AMD custom extensions (HWID == report CHIP_ID, TCB ext ==
// REPORTED_TCB). This is defense-in-depth on top of the chain + nonce +
// measurement-TOFU + TCB-floor checks, which are the load-bearing guarantees.
//
// ASCII only; no template literals.

const fs = require('fs');
const crypto = require('crypto');

const REPORT_SIZE = 1184;        // 0x4A0
const SIGNED_LEN = 672;          // 0x2A0 -- bytes the signature covers
const SIG_OFFSET = 672;          // 0x2A0
const SIG_FIELD_LEN = 512;
const ECDSA_P384_SHA384 = 1;     // the only defined SIGNATURE_ALGO

// ---- report parsing -------------------------------------------------------

function parseReport(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'hex');
  if (buf.length < REPORT_SIZE) {
    throw new Error('report too short: ' + buf.length + ' bytes, expected ' + REPORT_SIZE);
  }
  return {
    raw: buf,
    version: buf.readUInt32LE(0x000),
    guestSvn: buf.readUInt32LE(0x004),
    policy: buf.slice(0x008, 0x010).toString('hex'),
    vmpl: buf.readUInt32LE(0x030),
    signatureAlgo: buf.readUInt32LE(0x034),
    currentTcbRaw: Buffer.from(buf.slice(0x038, 0x040)),
    reportData: Buffer.from(buf.slice(0x050, 0x090)),
    measurement: Buffer.from(buf.slice(0x090, 0x0C0)),
    hostData: Buffer.from(buf.slice(0x0C0, 0x0E0)),
    reportedTcbRaw: Buffer.from(buf.slice(0x180, 0x188)),
    chipId: Buffer.from(buf.slice(0x1A0, 0x1E0)),
    signature: Buffer.from(buf.slice(SIG_OFFSET, SIG_OFFSET + SIG_FIELD_LEN)),
    signedBytes: Buffer.from(buf.slice(0, SIGNED_LEN)),
  };
}

// TCB_VERSION is a little-endian 64-bit value: byte 0 BOOTLOADER, byte 1 TEE,
// bytes 2-5 reserved, byte 6 SNP, byte 7 MICROCODE.
function decodeTcb(input) {
  const b = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'hex');
  return {
    bootloader: b[0],
    tee: b[1],
    snp: b[6],
    microcode: b[7],
    raw: b.toString('hex'),
  };
}

// True when every component of tcb is at or above the corresponding floor.
function compareTcb(tcb, floor) {
  return tcb.bootloader >= floor.bootloader &&
    tcb.tee >= floor.tee &&
    tcb.snp >= floor.snp &&
    tcb.microcode >= floor.microcode;
}

// ---- signature reassembly (LE R||S -> DER) --------------------------------

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

// SEV-SNP stores the signature as little-endian R (72 bytes) then S (72 bytes)
// within the 512-byte field; only the low 48 bytes of each are significant for
// P-384. Reverse each to big-endian and DER-encode.
function leSignatureToDer(sigField) {
  const rBE = Buffer.from(sigField.slice(0, 72)).reverse();
  const sBE = Buffer.from(sigField.slice(72, 144)).reverse();
  const body = Buffer.concat([derInteger(rBE), derInteger(sBE)]);
  return Buffer.concat([Buffer.from([0x30]), derLen(body.length), body]);
}

function verifyReportSignature(parsed, vcekPublicKey) {
  const der = leSignatureToDer(parsed.signature);
  return crypto.verify('sha384', parsed.signedBytes, vcekPublicKey, der);
}

// ---- certificate chain ----------------------------------------------------

function certValidNow(cert, now) {
  const nb = new Date(cert.validFrom);
  const na = new Date(cert.validTo);
  if (isNaN(nb.getTime()) || isNaN(na.getTime())) return true;
  return now.getTime() >= nb.getTime() && now.getTime() <= na.getTime();
}

function opensslVerifyChain(vcekPem, askPem, arkPem) {
  const cp = require('child_process');
  const os = require('os');
  const path = require('path');
  let dir = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'snpchain-'));
    const vp = path.join(dir, 'vcek.pem');
    const sp = path.join(dir, 'ask.pem');
    const ap = path.join(dir, 'ark.pem');
    fs.writeFileSync(vp, vcekPem);
    fs.writeFileSync(sp, askPem);
    fs.writeFileSync(ap, arkPem);
    const out = cp.execFileSync('openssl',
      ['verify', '-CAfile', ap, '-untrusted', sp, vp], { encoding: 'utf8' });
    if (out.indexOf(': OK') !== -1) return { ok: true, reason: 'chain ok (openssl)' };
    return { ok: false, reason: 'openssl verify failed: ' + out.trim() };
  } catch (e) {
    const msg = (e && e.stderr ? e.stderr.toString() : '') || (e && e.message) || 'unknown';
    return { ok: false, reason: 'openssl verify error: ' + String(msg).trim() };
  } finally {
    if (dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e2) { /* ignore */ } }
  }
}

function verifyChain(vcekPem, askPem, arkPem, now) {
  const t = now || new Date();
  let vcek, ask, ark;
  try {
    vcek = new crypto.X509Certificate(vcekPem);
    ask = new crypto.X509Certificate(askPem);
    ark = new crypto.X509Certificate(arkPem);
  } catch (e) {
    return opensslVerifyChain(vcekPem, askPem, arkPem);
  }
  let selfArk, askByArk, vcekByAsk;
  try {
    selfArk = ark.verify(ark.publicKey);
    askByArk = ask.verify(ark.publicKey);
    vcekByAsk = vcek.verify(ask.publicKey);
  } catch (e) {
    const fb = opensslVerifyChain(vcekPem, askPem, arkPem);
    if (fb.ok) fb.vcek = vcek;
    return fb;
  }
  if (!selfArk) return { ok: false, reason: 'ARK is not self-signed' };
  if (!askByArk) return { ok: false, reason: 'ASK not signed by ARK' };
  if (!vcekByAsk) return { ok: false, reason: 'VCEK not signed by ASK' };
  if (!certValidNow(vcek, t)) return { ok: false, reason: 'VCEK outside validity window' };
  if (!certValidNow(ask, t)) return { ok: false, reason: 'ASK outside validity window' };
  if (!certValidNow(ark, t)) return { ok: false, reason: 'ARK outside validity window' };
  return { ok: true, reason: 'chain ok', vcek: vcek };
}

// ---- top-level verify -----------------------------------------------------

function fail(reason) { return { verified: false, reason: reason, tech: 'sev-snp' }; }

// opts: { report (Buffer|hex), vcekPem, askPem, arkPem, expectedNonce?, now? }
function verify(opts) {
  const options = opts || {};
  const now = options.now || new Date();

  let parsed;
  try { parsed = parseReport(options.report); }
  catch (e) { return fail('report parse failed: ' + e.message); }

  if (parsed.signatureAlgo !== ECDSA_P384_SHA384) {
    return fail('unsupported signature algorithm: ' + parsed.signatureAlgo);
  }
  if (!options.vcekPem || !options.askPem || !options.arkPem) {
    return fail('missing VCEK/ASK/ARK certificate(s)');
  }

  const chain = verifyChain(options.vcekPem, options.askPem, options.arkPem, now);
  if (!chain.ok) return fail('certificate chain: ' + chain.reason);

  let vcek;
  try { vcek = chain.vcek || new crypto.X509Certificate(options.vcekPem); }
  catch (e) { return fail('VCEK load failed: ' + e.message); }

  let sigOk;
  try { sigOk = verifyReportSignature(parsed, vcek.publicKey); }
  catch (e) { return fail('report signature check errored: ' + e.message); }
  if (!sigOk) return fail('report signature invalid');

  let nonceMatch = null;
  if (options.expectedNonce != null) {
    const nonce = Buffer.isBuffer(options.expectedNonce)
      ? options.expectedNonce : Buffer.from(String(options.expectedNonce), 'hex');
    nonceMatch = parsed.reportData.slice(0, nonce.length).equals(nonce);
    if (!nonceMatch) return fail('report nonce does not match expected');
  }

  return {
    verified: true,
    reason: 'ok',
    tech: 'sev-snp',
    tcb: decodeTcb(parsed.reportedTcbRaw),
    currentTcb: decodeTcb(parsed.currentTcbRaw),
    measurement: parsed.measurement.toString('hex'),
    reportData: parsed.reportData.toString('hex'),
    chipId: parsed.chipId.toString('hex'),
    nonceMatch: nonceMatch,
  };
}

module.exports = {
  REPORT_SIZE,
  SIGNED_LEN,
  parseReport,
  decodeTcb,
  compareTcb,
  leSignatureToDer,
  verifyReportSignature,
  verifyChain,
  verify,
};

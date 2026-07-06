// FIREALIVE GD -- Confidential-computing attestation orchestrator (B6c PR-5 twin)
//
// Cloud Mode requires the GD server to run inside a confidential VM whose
// memory is encrypted and integrity-protected from co-tenants and the cloud
// provider. This module is the single seam (verifyAttestation) that the boot
// gate, the provision route, the health probes, and the regression runner call
// to decide whether the host is a genuine, current confidential guest. It is
// fail-closed: anything short of a cryptographically verified report denies.
//
// Flow:
//   1. detectConfidentialComputing() identifies the guest tech from the kernel
//      attestation devices (/dev/sev-guest, /dev/tdx_guest).
//   2. A fresh 64-byte nonce is written to the configfs-tsm report interface
//      (/sys/kernel/config/tsm/report) and the signed report (outblob), cert
//      material (auxblob), and provider are read back.
//   3. The report is dispatched by provider to the AMD SEV-SNP or Intel TDX
//      verifier, which checks the signature, the vendor certificate chain
//      against the bundled roots, and the nonce.
//   4. The TCB floor (if configured) is enforced and the launch measurement is
//      surfaced for the caller's TOFU pin.
//
// Nitro correction: AWS Nitro Enclaves is an enclave-within-instance model with
// no whole-VM host report, so the Nitro device alone no longer satisfies the
// verified gate; AWS whole-VM confidential computing is AMD SEV-SNP.
//
// Platform-validation-pending: the full path is exercised in CI against
// synthetic fixtures and runs for real when configfs-tsm + a valid report are
// present, but is confirmed on real SEV-SNP/TDX hardware at a later validation
// pass; results carry platformValidationPending true until then.
//
// The filesystem probe and the TSM reader are injectable so the orchestrator is
// unit-tested with fixtures (no real devices in CI). ASCII only; no template
// literals.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sevSnp = require('./gd-attestation-sev-snp');
const tdx = require('./gd-attestation-tdx');

const CC_SEV_SNP = 'sev-snp';
const CC_TDX = 'tdx';
const CC_NITRO = 'nitro';
const CC_NONE = null;

const SEV_SNP_GUEST_DEVICES = ['/dev/sev-guest'];
const TDX_GUEST_DEVICES = ['/dev/tdx_guest', '/dev/tdx-guest'];
const NITRO_ENCLAVE_DEVICES = ['/dev/nitro_enclaves'];

const TSM_REPORT_DIR = '/sys/kernel/config/tsm/report';
const NONCE_LEN = 64;

// SEV-SNP certificate-table GUID for the VCEK, in the mixed-endian GUID byte
// layout used in the auxblob cert table.
const GUID_VCEK = Buffer.from('8d75da6364e66445adc5f4b93be8accd', 'hex');

function defaultProbe() {
  return {
    exists: function (p) {
      try { return fs.existsSync(p); } catch (e) { return false; }
    },
  };
}

function firstExisting(probe, paths) {
  for (let i = 0; i < paths.length; i += 1) {
    if (probe.exists(paths[i])) return paths[i];
  }
  return null;
}

// Returns { present, tech, source }. tech is CC_SEV_SNP / CC_TDX / CC_NITRO when
// a confidential guest device is found, else CC_NONE (null) with present false.
function detectConfidentialComputing(probe) {
  const p = probe || defaultProbe();
  const sev = firstExisting(p, SEV_SNP_GUEST_DEVICES);
  if (sev) return { present: true, tech: CC_SEV_SNP, source: sev };
  const tdxDev = firstExisting(p, TDX_GUEST_DEVICES);
  if (tdxDev) return { present: true, tech: CC_TDX, source: tdxDev };
  const nitro = firstExisting(p, NITRO_ENCLAVE_DEVICES);
  if (nitro) return { present: true, tech: CC_NITRO, source: nitro };
  return { present: false, tech: CC_NONE, source: null };
}

function toBuf(x) {
  return Buffer.isBuffer(x) ? x : Buffer.from(String(x), 'hex');
}

// configfs-tsm report fetch: create a report instance, write the nonce to
// inblob, read outblob (report) + auxblob (certs) + provider + generation, then
// remove the instance. Returns { provider, report, auxblob, generation }.
function defaultTsmReader() {
  return {
    fetch: function (nonce, tsmPath) {
      const base = tsmPath || TSM_REPORT_DIR;
      const name = 'firealive-' + crypto.randomBytes(6).toString('hex');
      const dir = base + '/' + name;
      fs.mkdirSync(dir);
      try {
        fs.writeFileSync(dir + '/inblob', nonce);
        const report = fs.readFileSync(dir + '/outblob');
        let auxblob = Buffer.alloc(0);
        try { auxblob = fs.readFileSync(dir + '/auxblob'); } catch (e) { /* optional */ }
        let provider = '';
        try { provider = fs.readFileSync(dir + '/provider', 'utf8').trim(); } catch (e) { /* optional */ }
        let generation = null;
        try { generation = fs.readFileSync(dir + '/generation', 'utf8').trim(); } catch (e) { /* optional */ }
        return { provider: provider, report: report, auxblob: auxblob, generation: generation };
      } finally {
        try { fs.rmdirSync(dir); } catch (e) { /* configfs entry */ }
      }
    },
  };
}

function derCertToPem(der) {
  const b64 = der.toString('base64');
  let out = '-----BEGIN CERTIFICATE-----\n';
  for (let i = 0; i < b64.length; i += 64) out += b64.slice(i, i + 64) + '\n';
  return out + '-----END CERTIFICATE-----\n';
}

// Parse the SEV-SNP auxblob certificate table and return the VCEK as PEM, or
// null if absent. Table entries are 24 bytes (GUID[16] + offset_u32 + len_u32),
// terminated by an all-zero GUID; cert data is referenced from the auxblob start.
function extractVcekFromAuxblob(auxblob) {
  if (!auxblob || auxblob.length < 24) return null;
  const zero = Buffer.alloc(16);
  let off = 0;
  while (off + 24 <= auxblob.length) {
    const guid = auxblob.slice(off, off + 16);
    if (guid.equals(zero)) break;
    const certOff = auxblob.readUInt32LE(off + 16);
    const certLen = auxblob.readUInt32LE(off + 20);
    if (guid.equals(GUID_VCEK) && certLen > 0 && certOff + certLen <= auxblob.length) {
      const cert = auxblob.slice(certOff, certOff + certLen);
      if (cert.slice(0, 11).toString('ascii') === '-----BEGIN ') return cert.toString('ascii');
      return derCertToPem(cert);
    }
    off += 24;
  }
  return null;
}

function listAmdProducts(rootsDir) {
  try {
    return fs.readdirSync(rootsDir + '/amd').filter(function (n) {
      try { return fs.statSync(rootsDir + '/amd/' + n).isDirectory(); } catch (e) { return false; }
    });
  } catch (e) { return []; }
}

function loadAmdRoots(rootsDir, product) {
  const dir = rootsDir + '/amd/' + String(product).toLowerCase();
  return {
    askPem: fs.readFileSync(dir + '/ask.pem', 'utf8'),
    arkPem: fs.readFileSync(dir + '/ark.pem', 'utf8'),
  };
}

function loadIntelRoot(rootsDir) {
  return fs.readFileSync(rootsDir + '/intel/sgx-root-ca.pem', 'utf8');
}

function verifySevSnp(report, auxblob, opts) {
  const vcekPem = opts.vcekPem || extractVcekFromAuxblob(auxblob);
  if (!vcekPem) {
    return { verified: false, tech: CC_SEV_SNP, reason: 'VCEK not found in auxblob (one-time KDS fetch fallback not configured)' };
  }
  const products = opts.product ? [opts.product] : listAmdProducts(opts.rootsDir);
  if (products.length === 0) {
    return { verified: false, tech: CC_SEV_SNP, reason: 'no bundled AMD roots present under attestation-roots/amd' };
  }
  let lastReason = 'no AMD product roots verified the chain';
  for (let i = 0; i < products.length; i += 1) {
    let roots;
    try { roots = loadAmdRoots(opts.rootsDir, products[i]); }
    catch (e) { lastReason = 'AMD roots load failed for ' + products[i] + ': ' + e.message; continue; }
    const r = sevSnp.verify({
      report: report, vcekPem: vcekPem, askPem: roots.askPem, arkPem: roots.arkPem,
      expectedNonce: opts.nonce, now: opts.now,
    });
    if (r.verified) {
      if (opts.tcbFloor && !sevSnp.compareTcb(r.tcb, opts.tcbFloor)) {
        return { verified: false, tech: CC_SEV_SNP, reason: 'TCB below configured floor', tcb: r.tcb, measurement: r.measurement };
      }
      return {
        verified: true, tech: CC_SEV_SNP, reason: 'SEV-SNP report verified (' + products[i] + ')',
        tcb: r.tcb, currentTcb: r.currentTcb, measurement: r.measurement,
        reportData: r.reportData, chipId: r.chipId,
      };
    }
    lastReason = r.reason;
  }
  return { verified: false, tech: CC_SEV_SNP, reason: lastReason };
}

function verifyTdx(quote, opts) {
  let rootPem;
  try { rootPem = loadIntelRoot(opts.rootsDir); }
  catch (e) { return { verified: false, tech: CC_TDX, reason: 'Intel SGX root not bundled: ' + e.message }; }
  const r = tdx.verify({ quote: quote, intelRootPem: rootPem, expectedNonce: opts.nonce, now: opts.now });
  if (!r.verified) return { verified: false, tech: CC_TDX, reason: r.reason };
  if (opts.tcbFloor && !tdx.compareTcbSvn(r.tcbSvn, opts.tcbFloor)) {
    return { verified: false, tech: CC_TDX, reason: 'TCB SVN below configured floor', tcbSvn: r.tcbSvn, measurement: r.measurement };
  }
  return {
    verified: true, tech: CC_TDX, reason: 'TDX quote verified',
    tcbSvn: r.tcbSvn, measurement: r.measurement, rtmrs: r.rtmrs, reportData: r.reportData,
  };
}

// Verify the host is a genuine, current confidential VM. opts (all optional):
//   probe       fs existence probe (device detection)
//   tsmReader   configfs-tsm report fetcher (fixtures)
//   tsmPath     override the configfs-tsm report dir
//   rootsDir    bundled-roots directory
//   tcbFloor    SEV {bootloader,tee,snp,microcode} or TDX SVN hex/Buffer
//   product     AMD product line for root selection (else all bundled tried)
//   nonce       explicit nonce (else 64 random bytes)
//   now         clock override (testing)
function verifyAttestation(opts) {
  const options = opts || {};
  const probe = options.probe || defaultProbe();
  const rootsDir = options.rootsDir || path.join(__dirname, '..', 'data', 'attestation-roots');

  const cc = detectConfidentialComputing(probe);
  if (!cc.present) {
    return {
      verified: false, tech: CC_NONE,
      reason: 'no confidential-computing guest detected; Cloud Mode requires a confidential VM',
      platformValidationPending: false,
    };
  }
  if (cc.tech === CC_NITRO && !probe.exists(SEV_SNP_GUEST_DEVICES[0])) {
    return {
      verified: false, tech: CC_NITRO,
      reason: 'Nitro Enclaves is enclave-scoped, not a whole-VM confidential guest; deploy on an AMD SEV-SNP instance type for Cloud Mode',
      platformValidationPending: false,
    };
  }

  const nonce = options.nonce ? toBuf(options.nonce) : crypto.randomBytes(NONCE_LEN);
  const tsm = options.tsmReader || defaultTsmReader();
  let fetched;
  try { fetched = tsm.fetch(nonce, options.tsmPath); }
  catch (e) {
    return {
      verified: false, tech: cc.tech,
      reason: 'attestation report fetch failed (configfs-tsm): ' + e.message,
      platformValidationPending: true,
    };
  }

  const provider = (fetched.provider || '').toLowerCase();
  let tech = cc.tech;
  if (provider.indexOf('sev') !== -1) tech = CC_SEV_SNP;
  else if (provider.indexOf('tdx') !== -1) tech = CC_TDX;

  const dispatchOpts = {
    rootsDir: rootsDir, nonce: nonce, tcbFloor: options.tcbFloor,
    product: options.product, vcekPem: options.vcekPem, now: options.now,
  };

  let result;
  if (tech === CC_SEV_SNP) {
    result = verifySevSnp(fetched.report, fetched.auxblob || Buffer.alloc(0), dispatchOpts);
  } else if (tech === CC_TDX) {
    result = verifyTdx(fetched.report, dispatchOpts);
  } else {
    return {
      verified: false, tech: cc.tech,
      reason: 'unrecognized TSM provider: ' + (fetched.provider || '(none)'),
      platformValidationPending: true,
    };
  }

  result.nonce = nonce.toString('hex');
  result.generation = fetched.generation || null;
  result.platformValidationPending = true;
  return result;
}

// Verify a PEER's asserted confidential-VM attestation, for HA pairing in Cloud
// Mode. Unlike verifyAttestation, the report is not fetched from this host's
// kernel -- the peer fetched it from ITS kernel, bound to a challenge nonce this
// host issued, and returned it in the pairing handshake. The same root-of-trust
// verification runs (chain to the bundled AMD / Intel roots, TCB floor), plus the
// challenge-nonce match for anti-replay. assertion (peer report + issued nonce):
//   tech           CC_SEV_SNP or CC_TDX
//   report         SEV-SNP report / TDX quote (hex or Buffer)
//   auxblob        SEV-SNP certificate table (hex or Buffer; SEV-SNP only)
//   expectedNonce  the 64-byte challenge this host issued (hex or Buffer)
// opts (all optional): rootsDir, tcbFloor, product, now.
function verifyPeerAttestation(assertion, opts) {
  const a = assertion || {};
  const options = opts || {};
  const rootsDir = options.rootsDir || path.join(__dirname, '..', 'data', 'attestation-roots');
  const tech = a.tech;
  if (tech !== CC_SEV_SNP && tech !== CC_TDX) {
    return { verified: false, tech: tech || CC_NONE, reason: 'peer asserted no supported confidential-computing technology (expected sev-snp or tdx)' };
  }
  if (!a.expectedNonce) {
    return { verified: false, tech: tech, reason: 'no challenge nonce bound to peer attestation; anti-replay requires a host-issued nonce' };
  }
  if (!a.report) {
    return { verified: false, tech: tech, reason: 'peer attestation carries no report' };
  }
  const expectedNonce = toBuf(a.expectedNonce);
  const report = toBuf(a.report);
  const dispatchOpts = {
    rootsDir: rootsDir, nonce: expectedNonce, tcbFloor: options.tcbFloor,
    product: options.product, vcekPem: a.vcekPem, now: options.now,
  };
  let result;
  if (tech === CC_SEV_SNP) {
    const auxblob = a.auxblob ? toBuf(a.auxblob) : Buffer.alloc(0);
    result = verifySevSnp(report, auxblob, dispatchOpts);
  } else {
    result = verifyTdx(report, dispatchOpts);
  }
  result.nonce = expectedNonce.toString('hex');
  result.peer = true;
  return result;
}

// Produce THIS host's confidential-VM attestation for sending to a peer (the
// peer verifies it with verifyPeerAttestation). The report is fetched from this
// host's kernel bound to opts.nonce -- in HA pairing the nonce is derived from
// the one-time pairing token both sides share, which gives anti-replay without an
// extra handshake round-trip. opts (all optional): probe, tsmReader, tsmPath,
// nonce. Returns { tech, report (hex), auxblob (hex), nonce (hex) }, or { error }
// when this host is not a confidential guest or the report cannot be fetched.
function produceAttestation(opts) {
  const options = opts || {};
  const probe = options.probe || defaultProbe();
  const cc = detectConfidentialComputing(probe);
  if (!cc.present) {
    return { error: 'no confidential-computing guest detected; cannot produce an attestation' };
  }
  if (cc.tech === CC_NITRO && !probe.exists(SEV_SNP_GUEST_DEVICES[0])) {
    return { error: 'Nitro Enclaves is enclave-scoped, not a whole-VM confidential guest' };
  }
  const nonce = options.nonce ? toBuf(options.nonce) : crypto.randomBytes(NONCE_LEN);
  const tsm = options.tsmReader || defaultTsmReader();
  let fetched;
  try {
    fetched = tsm.fetch(nonce, options.tsmPath);
  } catch (e) {
    return { error: 'attestation report fetch failed (configfs-tsm): ' + e.message };
  }
  const provider = (fetched.provider || '').toLowerCase();
  let tech = cc.tech;
  if (provider.indexOf('sev') !== -1) tech = CC_SEV_SNP;
  else if (provider.indexOf('tdx') !== -1) tech = CC_TDX;
  return {
    tech: tech,
    report: fetched.report.toString('hex'),
    auxblob: (fetched.auxblob || Buffer.alloc(0)).toString('hex'),
    nonce: nonce.toString('hex'),
  };
}

module.exports = {
  detectConfidentialComputing,
  verifyAttestation,
  verifyPeerAttestation,
  produceAttestation,
  extractVcekFromAuxblob,
  derCertToPem,
  CC_SEV_SNP,
  CC_TDX,
  CC_NITRO,
  CC_NONE,
};

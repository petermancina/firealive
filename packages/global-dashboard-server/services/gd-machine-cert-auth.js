//
// FIREALIVE GD -- Machine-Certificate Verification (shared)  [O3 Half 2]
//
// Twin of server/services/machine-cert-auth.js on the Regional Server. The two
// are SEPARATE FILES because the two servers are separate trust domains with
// separate CAs -- gd-ca verifies against the GD's issued_certs, ca verifies
// against the MC's, and a certificate issued by one does not verify on the
// other. Sharing a module would imply a shared trust root that does not exist.
//
// What must stay identical is the DECISION SEQUENCE, not the trust root:
//
//   1. a mutual-TLS client certificate is present on the socket
//   2. it verifies against this deployment's CA -- signed, unexpired, not revoked
//   3. its subject carries the role OU this surface requires
//
// The GD has exactly one machine-authenticated surface (the cloud-vuln scanner
// feed), so exactly one OU exists here. The MC additionally carries api-key and
// threat-hunting OUs.
//
// Returns { ok: true, fingerprint } or { ok: false, reason }. The reason is for
// the CALLER'S LOG ONLY -- every caller answers a single generic 401, because
// distinguishing "no certificate" from "certificate not registered" turns the
// endpoint into an oracle for enumerating certificates separately from tokens.
//
// AGPL-3.0-or-later
//

const gdCa = require('./gd-ca');

function verifyMachineCert(db, req, ou) {
  if (!ou) {
    // A caller that forgets its OU fails closed rather than accepting anything.
    return { ok: false, reason: 'no_ou_configured' };
  }

  const peer = (req && req.socket && typeof req.socket.getPeerCertificate === 'function')
    ? req.socket.getPeerCertificate(true)
    : null;
  if (!peer || !peer.raw || !peer.raw.length) {
    return { ok: false, reason: 'no_client_cert' };
  }

  const verdict = gdCa.verifyClientCert(db, peer.raw);
  if (!verdict || !verdict.valid) {
    return { ok: false, reason: 'cert_invalid' };
  }

  if (!gdCa.subjectHasOu(verdict.subject, ou)) {
    // The certificate VERIFIED but is scoped to another surface, so its
    // fingerprint is known and belongs in the caller's access log: an
    // operator investigating a wrong-OU presentation needs to know WHICH
    // certificate was presented. Returning only a reason would silently
    // downgrade a hash-chained audit surface.
    return { ok: false, reason: 'cert_wrong_ou', fingerprint: verdict.fingerprint256 };
  }

  const fp = verdict.fingerprint256;
  if (typeof fp !== 'string' || fp.length === 0) {
    return { ok: false, reason: 'cert_no_fingerprint' };
  }

  return { ok: true, fingerprint: fp };
}

module.exports = { verifyMachineCert };

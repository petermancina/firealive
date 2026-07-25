//
// FIREALIVE -- Machine-Certificate Verification (shared)  [O3 Half 2]
//
// ONE implementation of "is this request carrying a valid machine certificate
// scoped to THIS surface?", used by every machine-authenticated path on the
// Regional Server:
//
//   - middleware/auth.js          handleApiKeyAuth        OU=api-key-consumer
//   - middleware/threat-hunting-auth.js                   OU=threat-hunting-consumer
//   - routes/vuln-scan.js         accessRouter            OU=scanner-consumer
//   - routes/cloud-vuln-scan.js   accessRouter            OU=scanner-consumer
//
// Before this existed there were four copies of the same three steps. A
// subject-parsing or verdict-handling difference between two of them is exactly
// how one surface ends up accepting a certificate another would refuse, and that
// difference is invisible in review because each copy looks correct on its own.
//
// The three steps, in order, none skippable:
//
//   1. a mutual-TLS client certificate is present on the socket
//   2. it verifies against THIS deployment's CA -- signed by it, unexpired, and
//      not in the local revocation list
//   3. its subject carries the role OU this surface requires
//
// Step 3 is what keeps the certificate classes separate. A certificate minted
// for the threat-hunting feed is refused by the API-key path and vice versa,
// because the OU differs. Collapsing the classes onto one OU would make every
// machine certificate universal -- strictly weaker than what B5m shipped.
//
// Returns { ok: true, fingerprint } or { ok: false, reason }. The reason is for
// the CALLER'S LOG ONLY. Every caller must answer a single generic 401 to the
// client: distinguishing "no certificate" from "certificate not registered"
// turns the endpoint into an oracle for enumerating valid certificates
// separately from valid tokens.
//
// AGPL-3.0-or-later
//

const ca = require('./ca');

/**
 * @param {object} db    open database handle (for CA + revocation lookup)
 * @param {object} req   the express request, for its TLS socket
 * @param {string} ou    the role OU this surface requires
 * @returns {{ok: true, fingerprint: string}|{ok: false, reason: string}}
 */
function verifyMachineCert(db, req, ou) {
  if (!ou) {
    // A caller that forgets its OU must fail closed, not accept every
    // certificate. Without this an empty OU would make subjectHasOu return
    // false anyway -- but relying on that is relying on a coincidence.
    return { ok: false, reason: 'no_ou_configured' };
  }

  const peer = (req && req.socket && typeof req.socket.getPeerCertificate === 'function')
    ? req.socket.getPeerCertificate(true)
    : null;
  if (!peer || !peer.raw || !peer.raw.length) {
    return { ok: false, reason: 'no_client_cert' };
  }

  const verdict = ca.verifyClientCert(db, peer.raw);
  if (!verdict || !verdict.valid) {
    return { ok: false, reason: 'cert_invalid' };
  }

  if (!ca.subjectHasOu(verdict.subject, ou)) {
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

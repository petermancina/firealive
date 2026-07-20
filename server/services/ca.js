// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Built-in Certificate Authority (Phase B5b)
//
// FireAlive authenticates analysts and operators with phishing-resistant,
// passwordless credentials. One of the two co-primary methods is a mutual-TLS
// CLIENT CERTIFICATE (PIV/CAC, a smart card, or a software cert this CA issues).
// This service is the turnkey, in-band CA that makes client-cert auth work
// without requiring an organization to already run its own PKI. A deployment
// that DOES have an org PKI can instead point FireAlive at that CA as a
// relying party (config, handled in the auth layer) — this built-in CA is the
// zero-PKI default so a SOC can stand the platform up and enroll certificates
// the same day.
//
// WHAT IT DOES
//   - initCa(db)                 self-initialize: generate the CA keypair and a
//                                self-signed CA certificate (idempotent).
//   - issueServerCert(db, opts)  issue the TLS server certificate the HTTPS
//                                listener presents (incl. a localhost SAN, so
//                                dev TLS is zero-friction — see C5).
//   - issueClientCert(db, opts)  sign an enrollee's CSR into a client-auth
//                                certificate bound to their external_id, and
//                                record it in issued_certs.
//   - verifyClientCert(db, pem)  the login/handshake hot path: confirm a
//                                presented cert chains to this CA, is in its
//                                validity window, and is NOT locally revoked.
//   - revokeCert(db, opts)       mark an issued cert revoked (local list).
//   - buildRevocationList(db)    a CA-signed JSON revocation feed for external
//                                consumers (CRL-equivalent; see "REVOCATION").
//   - ensureRecoveryCredential / verifyRecoveryCredential
//                                the one-time, audited break-glass credential.
//
// HOW THE CRYPTO IS DONE — AND WHY
//   Certificate ISSUANCE (CA keygen, self-sign, CSR signing) shells out to the
//   system `openssl` binary via child_process.execFileSync with ARGUMENT ARRAYS
//   (never a shell string — no interpolation into a shell, so there is no shell-
//   injection surface). Rationale: openssl is the most-audited PKI engine in
//   existence (FIPS-validated builds exist), and this adds ZERO npm dependencies
//   to the most security-critical code in the platform. The trade-off is a
//   runtime requirement on the openssl binary, which the host OS provides
//   (FireAlive runs directly on a TPM-backed host, never in a container).
//
//   Certificate VERIFICATION (the per-login hot path) uses Node's NATIVE
//   crypto.X509Certificate — it parses the presented PEM, checks the signature
//   against this CA's public key, checks the validity window, and then this
//   module checks local revocation in the issued_certs table. No process is
//   spawned on the hot path, and no network call is ever made (see REVOCATION).
//
// REVOCATION — LOCAL LIST, NO OCSP (by design)
//   Revocation is enforced from the LOCAL issued_certs table: verifyClientCert
//   rejects any cert whose row is status='revoked'. There is deliberately NO
//   OCSP responder — an OCSP dependency would put a live network responder on
//   the authentication path, which is exactly the kind of availability coupling
//   an air-gapped or hostile-network SOC cannot accept. buildRevocationList()
//   additionally produces a CA-SIGNED JSON revocation feed for any external
//   system that wants to mirror revocation state; that is a convenience for
//   outside consumers, not part of FireAlive's own enforcement.
//
// KEY CUSTODY
//   The CA private key is the crown jewel (it can mint any identity), so it is
//   AES-256-GCM encrypted at rest via the Tier-1 encryptConfig path and decrypted
//   just-in-time for a signing operation; the raw key is never cached at module
//   scope (same custody discipline as the audit-chain and report signing keys).
//   The TLS *server* leaf key is intentionally NOT stored encrypted in the DB:
//   it must load without a passphrase for non-interactive boot, so C5 persists
//   it as a 0600 file on disk — standard practice for a TLS server key, and a
//   far lower-value secret than the CA key (it only asserts the server's own
//   identity; client-cert auth is still required for access).
//
// THE GD RUNS ITS OWN INSTANCE OF THIS LOGIC
//   The Global Dashboard is a separate trust realm and runs its own CA (its
//   db-init.js carries the same ca_authority / issued_certs tables). A GD-issued
//   cert is not trusted by an MC and vice-versa, by design.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { sealTier1, openTier1 } = require('./tier1-seal');
const { requireIdentityEstablished } = require('./entropy');

// ── Tunables ────────────────────────────────────────────────────────────────
const CA_SUBJECT = 'CN=FireAlive Internal CA';
const CA_KEY_BITS = 3072;          // RSA-3072 ≈ 128-bit security (CNSA); CA key.
const SERVER_KEY_BITS = 2048;      // leaf TLS server key.
const CA_DAYS = 3650;              // 10y CA.
const SERVER_CERT_DAYS = 825;      // ~27 months (CA/B Forum TLS max).
const CLIENT_CERT_DAYS = 365;      // 1y analyst/operator certs.
const KEY_ALGO_LABEL = 'rsa-3072'; // recorded in ca_authority.key_algo.
const SIG_DIGEST = 'sha256';
const EXTERNAL_ID_URI_PREFIX = 'firealive:external-id:'; // stamped into the SAN.
const THREAT_HUNTING_CONSUMER_OU = 'threat-hunting-consumer'; // role OU the feed gate checks (B5m).

// ── Small helpers ─────────────────────────────────────────────────────────────
function nowSqlite() {
  return new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
}

function plusDaysSqlite(days) {
  return new Date(Date.now() + days * 86400000)
    .toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
}

// A secure temp dir (mkdtemp is 0700) for transient key/CSR material. Always
// removed in a finally block so private keys never linger on disk.
function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-ca-'));
  try {
    return fn(dir);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) { /* best effort */ }
  }
}

function openssl(args, opts = {}) {
  return execFileSync('openssl', args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...opts,
  });
}

// Normalized SHA-256 fingerprint: lowercase hex, no colons. Computed the SAME
// way at issue time and at verify time so the DB lookup matches.
function fingerprint256(certPem) {
  return new crypto.X509Certificate(certPem).fingerprint256.replace(/:/g, '').toLowerCase();
}

// A fresh, positive, 128-bit random serial (CA/B Forum requires ≥64-bit
// entropy). serial_counter is bumped purely as an "issued count" tally.
function nextSerialHex(db) {
  const b = crypto.randomBytes(16);
  b[0] &= 0x7f; // clear the high bit → guaranteed positive integer
  const hex = b.toString('hex');
  const ca = getActiveCaRow(db);
  if (ca) db.prepare('UPDATE ca_authority SET serial_counter = serial_counter + 1 WHERE id = ?').run(ca.id);
  return hex;
}

function buildSanValue(entries) {
  const seen = new Set();
  const parts = [];
  for (const raw of entries) {
    if (!raw) continue;
    const e = String(raw).trim();
    if (!e || seen.has(e)) continue;
    seen.add(e);
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(e) || e.includes(':');
    parts.push((isIp ? 'IP:' : 'DNS:') + e);
  }
  return parts.join(',');
}

// ── CA state access ───────────────────────────────────────────────────────────
function getActiveCaRow(db) {
  return db.prepare('SELECT * FROM ca_authority WHERE is_active = 1').get();
}

function getCaCertPem(db) {
  const row = getActiveCaRow(db);
  return row ? row.ca_cert_pem : null;
}

function loadCaKeyPem(db) {
  const row = getActiveCaRow(db);
  if (!row) throw new Error('no active CA; call initCa(db) first');
  const { pem } = openTier1('ca_authority.ca_private_key_encrypted', row.ca_private_key_encrypted);
  return pem;
}

// ── CA initialization (idempotent) ──────────────────────────────────────────
// Generates an RSA-3072 CA keypair and a self-signed CA certificate with the
// CA basic-constraint and keyCertSign/cRLSign usages. The private key is
// encrypted at rest. Returns { created, caCertPem }. Safe to call on every boot.
function initCa(db) {
  const existing = getActiveCaRow(db);
  if (existing) return { created: false, caCertPem: existing.ca_cert_pem };

  // B5e: do not mint the root CA before this deployment's instance identity is
  // established (anti-cloning gate, D6). Loading an existing CA above is exempt.
  requireIdentityEstablished(db);

  return withTempDir((dir) => {
    const keyPath = path.join(dir, 'ca.key');
    const certPath = path.join(dir, 'ca.crt');

    openssl(['genpkey', '-algorithm', 'RSA',
      '-pkeyopt', `rsa_keygen_bits:${CA_KEY_BITS}`, '-out', keyPath]);
    fs.chmodSync(keyPath, 0o600);

    openssl(['req', '-x509', '-new', '-key', keyPath, '-sha256',
      '-days', String(CA_DAYS), '-subj', `/${CA_SUBJECT}`, '-out', certPath,
      '-addext', 'basicConstraints=critical,CA:TRUE',
      '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
      '-addext', 'subjectKeyIdentifier=hash']);

    const caKeyPem = fs.readFileSync(keyPath, 'utf8');
    const caCertPem = fs.readFileSync(certPath, 'utf8');
    const encrypted = sealTier1('ca_authority.ca_private_key_encrypted', { pem: caKeyPem });

    db.prepare(`
      INSERT INTO ca_authority
        (subject, key_algo, ca_cert_pem, ca_private_key_encrypted, serial_counter, is_active)
      VALUES (?, ?, ?, ?, 1, 1)
    `).run(CA_SUBJECT, KEY_ALGO_LABEL, caCertPem, encrypted);

    return { created: true, caCertPem };
  });
}

// ── issue the TLS server certificate ──────────────────────────────────────────
// Returns { certPem, keyPem, caCertPem }. C5 persists key+cert to 0600 files and
// reuses them across boots, re-issuing only when missing or expired.
function issueServerCert(db, { commonName = 'localhost', hostnames = [] } = {}) {
  return withTempDir((dir) => {
    const caKeyPem = loadCaKeyPem(db);
    const caCertPem = getCaCertPem(db);
    const caKeyPath = path.join(dir, 'ca.key');
    const caCrtPath = path.join(dir, 'ca.crt');
    fs.writeFileSync(caKeyPath, caKeyPem, { mode: 0o600 });
    fs.writeFileSync(caCrtPath, caCertPem);

    const keyPath = path.join(dir, 'srv.key');
    const csrPath = path.join(dir, 'srv.csr');
    const extPath = path.join(dir, 'srv.ext');
    const crtPath = path.join(dir, 'srv.crt');

    openssl(['genpkey', '-algorithm', 'RSA',
      '-pkeyopt', `rsa_keygen_bits:${SERVER_KEY_BITS}`, '-out', keyPath]);
    fs.chmodSync(keyPath, 0o600);
    openssl(['req', '-new', '-key', keyPath, '-subj', `/CN=${commonName}`, '-out', csrPath]);

    const san = buildSanValue(['localhost', '127.0.0.1', '::1', commonName, ...hostnames]);
    fs.writeFileSync(extPath, [
      'basicConstraints=CA:FALSE',
      'keyUsage=critical,digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth',
      `subjectAltName=${san}`,
    ].join('\n') + '\n');

    const serial = nextSerialHex(db);
    openssl(['x509', '-req', '-in', csrPath, '-CA', caCrtPath, '-CAkey', caKeyPath,
      '-set_serial', `0x${serial}`, '-days', String(SERVER_CERT_DAYS),
      '-sha256', '-extfile', extPath, '-out', crtPath]);

    const certPem = fs.readFileSync(crtPath, 'utf8');
    const keyPem = fs.readFileSync(keyPath, 'utf8');
    recordIssued(db, {
      serial, userId: null, externalId: null,
      subject: `CN=${commonName}`, certPem, days: SERVER_CERT_DAYS,
    });
    return { certPem, keyPem, caCertPem };
  });
}

// ── server certificate SAN reconciliation (Cloud Mode) ─────
// A cloud instance changes IP/DNS on stop/start or behind a load balancer.
// Because clients pin the anchor fingerprint, not the leaf certificate, the
// server cert can be re-issued under the stable anchor whenever its SAN set must
// change. The desired SAN is the stable hostname (operator DNS, primary), the
// instance IP (from metadata, secondary), and the loopback base. The last issued
// set is tracked in config so reconciliation re-issues ONLY on a real change and
// never widens what the certificate asserts beyond that set.
const SAN_BASE = ['localhost', '127.0.0.1', '::1'];
const SAN_STATE_KEY = 'server_cert_san';

function computeDesiredSan({ stableHostname = null, instanceIp = null } = {}) {
  const entries = SAN_BASE.slice();
  const host = stableHostname ? String(stableHostname).trim().toLowerCase() : null;
  const ip = instanceIp ? String(instanceIp).trim() : null;
  if (host) entries.push(host);
  if (ip) entries.push(ip);
  const uniq = [];
  for (const e of entries) {
    if (e && uniq.indexOf(e) === -1) uniq.push(e);
  }
  uniq.sort();
  return uniq;
}

function readSanState(db) {
  try {
    const row = db.prepare('SELECT value FROM config WHERE key = ?').get(SAN_STATE_KEY);
    return row && row.value ? JSON.parse(row.value) : null;
  } catch (_e) {
    return null;
  }
}

function writeSanState(db, sanArray) {
  db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)')
    .run(SAN_STATE_KEY, JSON.stringify(sanArray));
}

// Re-issue the server certificate only when the desired SAN set differs from the
// last issued set. Returns { reissued, desiredSan, previousSan, certPem?, keyPem?,
// caCertPem? }; on reissue the caller persists the new cert/key. Issuing missing
// or expired certs stays the boot path's job -- this handles SAN changes only.
function reconcileServerCert(db, { stableHostname = null, instanceIp = null } = {}) {
  const desired = computeDesiredSan({ stableHostname, instanceIp });
  const previous = readSanState(db);
  const same = Array.isArray(previous) &&
    previous.length === desired.length &&
    previous.every((v, i) => v === desired[i]);
  if (same) {
    return { reissued: false, desiredSan: desired, previousSan: previous };
  }
  const hostnames = [];
  if (stableHostname) hostnames.push(String(stableHostname).trim().toLowerCase());
  if (instanceIp) hostnames.push(String(instanceIp).trim());
  const issued = issueServerCert(db, { commonName: 'localhost', hostnames });
  writeSanState(db, desired);
  return {
    reissued: true,
    desiredSan: desired,
    previousSan: previous,
    certPem: issued.certPem,
    keyPem: issued.keyPem,
    caCertPem: issued.caCertPem,
  };
}

// ── issue a client certificate from an enrollee CSR ───────────────────────────
// The enrollee generates their own keypair on-device and sends only a CSR
// (the private key never leaves the device). The authoritative identity this CA
// asserts is the external_id it STAMPS into the SAN here — NOT the CN in the
// client-supplied CSR, which is treated as cosmetic. verifyClientCert reads the
// external_id back from that server-stamped SAN. Returns
// { certPem, serial, fingerprint256, caCertPem }.
function issueClientCert(db, { csrPem, userId = null, externalId = null, commonName } = {}) {
  if (!csrPem || typeof csrPem !== 'string') throw new Error('csrPem (PEM string) is required');

  return withTempDir((dir) => {
    const caKeyPem = loadCaKeyPem(db);
    const caCertPem = getCaCertPem(db);
    const caKeyPath = path.join(dir, 'ca.key');
    const caCrtPath = path.join(dir, 'ca.crt');
    const csrPath = path.join(dir, 'client.csr');
    const extPath = path.join(dir, 'client.ext');
    const crtPath = path.join(dir, 'client.crt');
    fs.writeFileSync(caKeyPath, caKeyPem, { mode: 0o600 });
    fs.writeFileSync(caCrtPath, caCertPem);
    fs.writeFileSync(csrPath, csrPem);

    // Reject a malformed or tampered CSR before signing anything. `req -verify`
    // checks the CSR's self-signature; it throws (non-zero exit) on failure.
    try {
      openssl(['req', '-in', csrPath, '-noout', '-verify']);
    } catch (_) {
      throw new Error('CSR is invalid or its self-signature failed verification');
    }

    const cn = commonName || externalId || ('user-' + (userId || 'unknown'));
    const extLines = [
      'basicConstraints=CA:FALSE',
      'keyUsage=critical,digitalSignature',
      'extendedKeyUsage=clientAuth',
    ];
    if (externalId) {
      extLines.push(`subjectAltName=URI:${EXTERNAL_ID_URI_PREFIX}${encodeURIComponent(externalId)}`);
    }
    fs.writeFileSync(extPath, extLines.join('\n') + '\n');

    const serial = nextSerialHex(db);
    // x509 -req signs the CSR's public key. The subject the CA asserts is bound
    // via the SAN extension above (server-controlled), so the CSR's own CN is
    // not trusted as identity.
    openssl(['x509', '-req', '-in', csrPath, '-CA', caCrtPath, '-CAkey', caKeyPath,
      '-set_serial', `0x${serial}`, '-days', String(CLIENT_CERT_DAYS),
      '-sha256', '-extfile', extPath, '-out', crtPath]);

    const certPem = fs.readFileSync(crtPath, 'utf8');
    const fp = fingerprint256(certPem);
    recordIssued(db, {
      serial, userId, externalId, subject: `CN=${cn}`, certPem, days: CLIENT_CERT_DAYS, fp,
    });
    return { certPem, serial, fingerprint256: fp, caCertPem };
  });
}

function recordIssued(db, { serial, userId, externalId, subject, certPem, days, fp }) {
  const fingerprint = fp || fingerprint256(certPem);
  db.prepare(`
    INSERT INTO issued_certs
      (serial, user_id, external_id, subject, fingerprint256, cert_pem, expires_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
  `).run(serial, userId, externalId, subject, fingerprint, certPem, plusDaysSqlite(days));
  return fingerprint;
}

// ── threat-hunting consumer certs (B5m) ─────────────────────────────────
// Mint a client cert for an external threat-hunting consumer (EDR/XDR/ATP/NGAV
// /MSP). Unlike issueClientCert (which signs a client-supplied CSR), the admin
// mints the key AND the cert here and hands both to the org to install in its
// collector, so the subject -- including the consumer role OU the feed gate
// checks -- is server-controlled and trustworthy. clientAuth EKU; signed by the
// active deployment CA; recorded in issued_certs like every other leaf so it is
// revocable through the same path.
function sanitizeConsumerCn(name) {
  const cleaned = String(name || '').replace(/[^A-Za-z0-9 ._-]/g, '-').replace(/\s+/g, ' ').trim().slice(0, 64);
  return cleaned || 'threat-hunting-consumer';
}

function issueThreatHuntingConsumerCert(db, { displayName } = {}) {
  const cn = sanitizeConsumerCn(displayName);
  return withTempDir((dir) => {
    const caKeyPem = loadCaKeyPem(db);
    const caCertPem = getCaCertPem(db);
    const caKeyPath = path.join(dir, 'ca.key');
    const caCrtPath = path.join(dir, 'ca.crt');
    const keyPath = path.join(dir, 'consumer.key');
    const csrPath = path.join(dir, 'consumer.csr');
    const extPath = path.join(dir, 'consumer.ext');
    const crtPath = path.join(dir, 'consumer.crt');
    fs.writeFileSync(caKeyPath, caKeyPem, { mode: 0o600 });
    fs.writeFileSync(caCrtPath, caCertPem);

    // Generate the consumer key server-side (matches the server leaf key size).
    openssl(['genpkey', '-algorithm', 'RSA',
      '-pkeyopt', 'rsa_keygen_bits:' + SERVER_KEY_BITS, '-out', keyPath]);
    // Server-controlled subject: we own the key, so the role OU is trustworthy.
    const subject = '/OU=' + THREAT_HUNTING_CONSUMER_OU + '/CN=' + cn;
    openssl(['req', '-new', '-key', keyPath, '-subj', subject, '-out', csrPath]);

    const extLines = [
      'basicConstraints=CA:FALSE',
      'keyUsage=critical,digitalSignature',
      'extendedKeyUsage=clientAuth',
    ];
    fs.writeFileSync(extPath, extLines.join('\n') + '\n');

    const serial = nextSerialHex(db);
    openssl(['x509', '-req', '-in', csrPath, '-CA', caCrtPath, '-CAkey', caKeyPath,
      '-set_serial', '0x' + serial, '-days', String(CLIENT_CERT_DAYS),
      '-' + SIG_DIGEST, '-extfile', extPath, '-out', crtPath]);

    const certPem = fs.readFileSync(crtPath, 'utf8');
    const keyPem = fs.readFileSync(keyPath, 'utf8');
    const fp = fingerprint256(certPem);
    recordIssued(db, {
      serial, userId: null, externalId: null,
      subject: 'OU=' + THREAT_HUNTING_CONSUMER_OU + ',CN=' + cn,
      certPem, days: CLIENT_CERT_DAYS, fp,
    });
    return { certPem, keyPem, fingerprint: fp, serial, caCertPem };
  });
}

// ── revoke (local revocation list) ────────────────────────────────────────────
function revokeCert(db, { serial, reason = 'unspecified' } = {}) {
  const row = db.prepare('SELECT status FROM issued_certs WHERE serial = ?').get(serial);
  if (!row) return { revoked: false, reason: 'not_found' };
  if (row.status === 'revoked') return { revoked: true, alreadyRevoked: true };
  db.prepare(`
    UPDATE issued_certs SET status = 'revoked', revoked_at = ?, revoked_reason = ?
    WHERE serial = ?
  `).run(nowSqlite(), String(reason).slice(0, 256), serial);
  return { revoked: true };
}

function extractExternalIdFromSan(x509) {
  const san = x509.subjectAltName || '';
  const m = san.match(new RegExp('URI:' + EXTERNAL_ID_URI_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^,]+)'));
  if (!m) return null;
  try { return decodeURIComponent(m[1].trim()); } catch (_) { return m[1].trim(); }
}

// ── verify a presented client cert (hot path; native, no spawn, no network) ───
// Returns { valid, reason?, userId?, externalId?, fingerprint256?, subject? }.
function verifyClientCert(db, certPem) {
  let x;
  try {
    x = new crypto.X509Certificate(certPem);
  } catch (_) {
    return { valid: false, reason: 'parse_error' };
  }

  const ca = getActiveCaRow(db);
  if (!ca) return { valid: false, reason: 'no_ca' };

  let caX;
  try {
    caX = new crypto.X509Certificate(ca.ca_cert_pem);
  } catch (_) {
    return { valid: false, reason: 'ca_parse_error' };
  }

  // Signature must chain to THIS CA's key.
  if (!x.verify(caX.publicKey)) return { valid: false, reason: 'bad_signature' };

  // Validity window.
  const now = Date.now();
  if (now < Date.parse(x.validFrom) || now > Date.parse(x.validTo)) {
    return { valid: false, reason: 'expired_or_not_yet_valid' };
  }

  // Must be a cert this CA actually issued (present in issued_certs) and not
  // locally revoked.
  const fp = x.fingerprint256.replace(/:/g, '').toLowerCase();
  const rec = db.prepare(
    'SELECT user_id, external_id, status FROM issued_certs WHERE fingerprint256 = ?'
  ).get(fp);
  if (!rec) return { valid: false, reason: 'unknown_cert' };
  if (rec.status === 'revoked') return { valid: false, reason: 'revoked' };

  return {
    valid: true,
    userId: rec.user_id || null,
    externalId: extractExternalIdFromSan(x) || rec.external_id || null,
    fingerprint256: fp,
    subject: x.subject,
  };
}

// ── CA-signed JSON revocation feed (CRL-equivalent for external consumers) ────
function buildRevocationList(db) {
  const rows = db.prepare(`
    SELECT serial, fingerprint256, revoked_at, revoked_reason
    FROM issued_certs WHERE status = 'revoked'
    ORDER BY revoked_at, rowid
  `).all();
  const payload = {
    issuer: CA_SUBJECT,
    generatedAt: nowSqlite(),
    count: rows.length,
    revoked: rows,
  };
  const caKeyPem = loadCaKeyPem(db);
  const signature = crypto
    .sign(SIG_DIGEST, Buffer.from(JSON.stringify(payload)), crypto.createPrivateKey(caKeyPem))
    .toString('base64');
  return { ...payload, signatureAlg: 'RSA-SHA256', signature };
}

// ── break-glass recovery credential (one-time, audited) ───────────────────────
// Minted once at CA init and returned in plaintext exactly once for the operator
// to store offline (mirrors the pseudonym-mapping export pattern). Only its
// SHA-256 is persisted; the credential is high-entropy random (192-bit), so a
// single hash is sufficient — there is no low-entropy password to slow-hash.
// It is usable only at the rate-limited, fully-audited recovery endpoint (C7).
function ensureRecoveryCredential(db) {
  const existing = db.prepare('SELECT id FROM auth_recovery WHERE is_active = 1').get();
  if (existing) return { created: false };
  const secret = crypto.randomBytes(24).toString('base64url'); // 192-bit
  const hash = crypto.createHash('sha256').update(secret).digest('hex');
  db.prepare('INSERT INTO auth_recovery (credential_hash, is_active, use_count) VALUES (?, 1, 0)').run(hash);
  return { created: true, recoveryCredential: secret };
}

function verifyRecoveryCredential(db, presented) {
  if (!presented || typeof presented !== 'string') return false;
  const row = db.prepare('SELECT id, credential_hash FROM auth_recovery WHERE is_active = 1').get();
  if (!row) return false;
  const presentedHash = crypto.createHash('sha256').update(presented).digest('hex');
  const a = Buffer.from(row.credential_hash);
  const b = Buffer.from(presentedHash);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (ok) {
    db.prepare('UPDATE auth_recovery SET last_used_at = ?, use_count = use_count + 1 WHERE id = ?')
      .run(nowSqlite(), row.id);
  }
  return ok;
}

module.exports = {
  initCa,
  getCaCertPem,
  issueServerCert,
  reconcileServerCert,
  computeDesiredSan,
  issueClientCert,
  issueThreatHuntingConsumerCert,
  revokeCert,
  verifyClientCert,
  buildRevocationList,
  ensureRecoveryCredential,
  verifyRecoveryCredential,
  // exposed for reuse/tests
  fingerprint256,
  nowSqlite,
  KEY_ALGO_LABEL,
  EXTERNAL_ID_URI_PREFIX,
  THREAT_HUNTING_CONSUMER_OU,
};

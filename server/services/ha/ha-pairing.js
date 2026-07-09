// FIREALIVE -- HA pairing (B5o)
//
// Pairing is the one point where two nodes establish mutual trust. After it,
// every peer message is authenticated by the pinned anchor + certificate + (for
// replication) the epoch. The bootstrap problem -- the steady-state mTLS gate
// requires a pinned peer certificate, but pairing is what sets the pin -- is
// solved with a one-time pairing TOKEN the operator carries from the standby to
// the active (mirroring the existing one-time enrollment-token flow).
//
// Flow (A = initiator/active-to-be, B = responder/passive-to-be):
//   1. Operator prepares B: generatePairingToken -> a one-time token shown once.
//   2. Operator runs "pair with standby" on A with B's endpoint + the token.
//   3. A POSTs its identity bundle + the token to B /api/ha/pair-init over an
//      unpinned TLS connection (token-authenticated; A captures B's server-cert
//      thumbprint, B captures A's client-cert thumbprint -- trust-on-first-use
//      bounded by the token). Each verifies the other's anchor-signed wrap key
//      and pins {anchor, wrap key, cert thumbprint, endpoint}.
//   4. Now both pin each other, so A uses the pinned link: it wraps the shared
//      Tier-1 material (KEK + JWT secret) to B's wrap key (B stores it sealed,
//      unsealed only at promotion) and ships a baseline snapshot (B restores it).
//   5. Roles + the epoch-1 lease are set; status becomes paired.
//
// No raw key material is shared; the wrapped blob is opaque without B's hardware
// (ha-keys). ASCII-only; no template literals.

const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const anchor = require('../instance-anchor');
const tier1 = require('../tier1-kek');
const haKeys = require('./ha-keys');
const haPeerLink = require('./ha-peer-link');
const haCdc = require('./ha-cdc');
const haReplication = require('./ha-replication');
// Audit through the connection this module was handed, never a second one. auditLog()
// opens its own via getDb(), so pairing -- which mutates ha_node, ha_lease, and ha_peer
// on the injected db -- would apply the role change to that database while writing
// HA_PAIRED into whatever getDb() points at. On a live node they are the same file, so
// nothing was visibly wrong; against any other database (a hermetic regression clone,
// a drill) the pairing lands in one place and the tamper-evident audit row in another.
// auditLogOn appends on the given handle and gates SIEM streaming on isLiveChain(db),
// so a real pairing records and streams exactly as before.
const { auditLogOn } = require('../../middleware/audit');
const ca = require('../ca');
const mode = require('../deployment-mode');
const cloudAttestation = require('../cloud-attestation');
const haModes = require('./ha-modes');

const TOKEN_CONFIG_KEY = 'ha_pairing_token';
const DEFAULT_TOKEN_TTL_SEC = 900;
const DEFAULT_TIMEOUT_MS = 30000;
const PAIR_INIT_PATH = '/api/ha/pair-init';
const PAIR_SECRET_PATH = '/api/ha/peer/pair-secret';
const PAIR_BASELINE_PATH = '/api/ha/peer/pair-baseline';

function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

// ---------------------------------------------------------------------------
// One-time pairing token (responder/standby side), held in config, single-use.
// ---------------------------------------------------------------------------

function generatePairingToken(db, ttlSec) {
  const token = crypto.randomBytes(24).toString('base64url');
  const ttl = ttlSec || DEFAULT_TOKEN_TTL_SEC;
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  const record = JSON.stringify({ hash: sha256Hex(token), expiresAt: expiresAt });
  db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(TOKEN_CONFIG_KEY, record);
  // The operator carries this opaque bootstrap code to the active. It binds the
  // secret token to THIS node's CA certificate and leaf thumbprint, so the
  // active can validate the pairing TLS connection against a real trust anchor
  // (ca + fingerprint pin) instead of disabling certificate validation.
  const bootstrap = Buffer.from(JSON.stringify({
    v: 1,
    token: token,
    caCertPem: ca.getCaCertPem(db),
    leafThumbprint: haPeerLink.localCertThumbprint(),
  }), 'utf8').toString('base64');
  return { bootstrap: bootstrap, expiresAt: expiresAt };
}

function consumePairingToken(db, token) {
  if (typeof token !== 'string' || !token) {
    return false;
  }
  const row = db.prepare("SELECT value FROM config WHERE key = ?").get(TOKEN_CONFIG_KEY);
  if (!row) {
    return false;
  }
  let rec;
  try { rec = JSON.parse(row.value); } catch (parseErr) { return false; }
  if (!rec || !rec.hash || !rec.expiresAt) {
    return false;
  }
  if (Date.parse(rec.expiresAt) < Date.now()) {
    db.prepare("DELETE FROM config WHERE key = ?").run(TOKEN_CONFIG_KEY);
    return false;
  }
  const a = Buffer.from(sha256Hex(token), 'hex');
  const b = Buffer.from(rec.hash, 'hex');
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (ok) {
    db.prepare("DELETE FROM config WHERE key = ?").run(TOKEN_CONFIG_KEY); // single-use
  }
  return ok;
}

// ---------------------------------------------------------------------------
// Identity bundle + verification + pinning.
// ---------------------------------------------------------------------------

// The attestation challenge nonce is derived from the one-time pairing token
// both sides share, so each node's confidential-VM report is bound to THIS
// pairing (anti-replay) without an extra handshake round-trip. 64 bytes.
function attestationNonce(token) {
  return crypto.createHash('sha512').update(String(token || ''), 'utf8').digest();
}

// Build the peer-attestation assertion ha-modes verifies: the peer's asserted
// report plus the nonce WE expect (from the shared token), so the report must be
// bound to this pairing.
function peerAttestationAssertion(peerBundle, token) {
  const att = (peerBundle && peerBundle.attestation) || {};
  return {
    tech: att.tech,
    report: att.report,
    auxblob: att.auxblob,
    expectedNonce: attestationNonce(token).toString('hex'),
  };
}

function buildIdentityBundle(db, selfEndpoint, attestNonce) {
  haKeys.ensureWrapKeypair(db);
  const wrap = haKeys.getLocalWrapPublic(db);
  const id = anchor.load({ db: db });
  if (!id || !id.publicKey) {
    throw new Error('ha-pairing: no hardware instance identity (cannot pair)');
  }
  const caCertPem = ca.getCaCertPem(db);
  const certThumbprint = haPeerLink.localCertThumbprint();
  // Bind the CA certificate + leaf thumbprint to this node's anchor identity so a
  // relay cannot swap the advertised CA: the peer verifies this signature before
  // storing the CA it will later pin for the reverse-direction link.
  const bindingSig = anchor.sign({ db: db, data: certBindingData(caCertPem, certThumbprint) });
  const bundle = {
    anchorPublicPem: id.publicKey,
    anchorFingerprint: id.fingerprint,
    wrapPublicPem: wrap.wrapPublicPem,
    wrapPubkeyAnchorSig: wrap.wrapPubkeyAnchorSig,
    certThumbprint: certThumbprint,
    caCertPem: caCertPem,
    certBindingSig: bindingSig ? bindingSig.toString('base64') : null,
    endpoint: selfEndpoint || null,
  };
  // Cloud Mode: attach this host's confidential-VM attestation bound to the
  // pairing-token nonce so the peer can verify it. produceAttestation returns
  // { error } if this host cannot attest; the bundle carries that and the peer's
  // gate refuses -- fail closed, never silently omit the proof.
  if (attestNonce && mode.isCloud(db)) {
    bundle.attestation = cloudAttestation.produceAttestation({ nonce: attestNonce });
  }
  return bundle;
}

function certBindingData(caCertPem, certThumbprint) {
  return Buffer.from((caCertPem || '') + '|' + (certThumbprint || ''), 'utf8');
}

function verifyAnchorSig(data, sigB64, anchorPubPem) {
  if (typeof sigB64 !== 'string' || !sigB64) {
    return false;
  }
  try {
    return crypto.verify('sha256', data, { key: crypto.createPublicKey(anchorPubPem), dsaEncoding: 'ieee-p1363' }, Buffer.from(sigB64, 'base64'));
  } catch (verifyErr) {
    return false;
  }
}

// Verify a peer bundle: the anchor fingerprint matches its public key, and the
// wrap key is anchor-signed (proving it belongs to that hardware identity).
function verifyPeerBundle(bundle) {
  if (!bundle || typeof bundle.anchorPublicPem !== 'string' || typeof bundle.wrapPublicPem !== 'string') {
    return false;
  }
  let fp;
  try { fp = anchor.computeFingerprint(bundle.anchorPublicPem); } catch (fpErr) { return false; }
  if (fp !== bundle.anchorFingerprint) {
    return false;
  }
  if (!haKeys.verifyPeerWrapKey(bundle.wrapPublicPem, bundle.wrapPubkeyAnchorSig, bundle.anchorPublicPem)) {
    return false;
  }
  if (typeof bundle.caCertPem !== 'string' || !bundle.caCertPem) {
    return false;
  }
  return verifyAnchorSig(certBindingData(bundle.caCertPem, bundle.certThumbprint), bundle.certBindingSig, bundle.anchorPublicPem);
}

// Pin a verified peer into ha_peer. certThumbprint is the ACTUAL thumbprint
// observed over TLS (not merely the bundle's claim).
function pinPeer(db, bundle, certThumbprint, status) {
  db.prepare("DELETE FROM ha_peer").run(); // one peer maximum
  db.prepare(
    "INSERT INTO ha_peer (peer_endpoint, peer_anchor_fingerprint, peer_anchor_public_pem, peer_wrap_public_pem, peer_cert_fingerprint, peer_ca_pem, status, paired_at) "
    + "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).run(
    bundle.endpoint || '',
    bundle.anchorFingerprint,
    bundle.anchorPublicPem,
    bundle.wrapPublicPem,
    (certThumbprint || '').toLowerCase(),
    bundle.caCertPem || null,
    status || 'pairing',
    status === 'paired' ? new Date().toISOString() : null
  );
}

// ---------------------------------------------------------------------------
// Shared Tier-1 material (KEK + JWT secret) wrap / install.
// ---------------------------------------------------------------------------

function wrapSharedMaterial(peerWrapPublicPem) {
  const kek = tier1.resolveTier1Kek();
  const material = JSON.stringify({
    v: 1,
    kek: kek.toString('hex'),
    jwtSecret: process.env.JWT_SECRET || '',
  });
  return haKeys.wrapKekToPeer(Buffer.from(material, 'utf8'), peerWrapPublicPem);
}

// The passive stores the wrapped blob; it is unsealed only at promotion.
function installSharedMaterial(db, envelopeB64) {
  haKeys.ensureSelfRow(db);
  db.prepare("UPDATE ha_node SET sealed_promotion_kek = ?, updated_at = datetime('now') WHERE id = 'self'").run(envelopeB64);
}

// ---------------------------------------------------------------------------
// Baseline restore (passive side): copy the replicated tables from a snapshot
// the active produced with VACUUM INTO. Control-plane and identity tables are
// excluded, so the passive keeps its own identity/lease.
// ---------------------------------------------------------------------------

function restoreBaseline(db, snapshotPath, opts) {
  const literal = "'" + String(snapshotPath).replace(/'/g, "''") + "'";
  const tables = haCdc.listReplicatedTables(db, opts);
  const fkRow = db.prepare('PRAGMA foreign_keys').get();
  const fkWas = (fkRow && fkRow.foreign_keys) ? 1 : 0;
  db.exec('ATTACH DATABASE ' + literal + ' AS basesnap');
  try {
    // Bulk copy of an internally consistent snapshot: FK enforcement is disabled
    // for the copy (it cannot be toggled inside a transaction) and restored after,
    // mirroring the schema-rebuild blocks in db/init.js.
    db.exec('PRAGMA foreign_keys = OFF');
    db.exec('BEGIN');
    for (let i = 0; i < tables.length; i++) {
      const q = '"' + tables[i].replace(/"/g, '""') + '"';
      db.exec('DELETE FROM main.' + q);
      db.exec('INSERT INTO main.' + q + ' SELECT * FROM basesnap.' + q);
    }
    db.exec('COMMIT');
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch (rollbackErr) { /* ignore */ }
    if (fkWas) { try { db.exec('PRAGMA foreign_keys = ON'); } catch (fkErr) { /* ignore */ } }
    try { db.exec('DETACH DATABASE basesnap'); } catch (detachErr) { /* ignore */ }
    throw err;
  }
  if (fkWas) {
    db.exec('PRAGMA foreign_keys = ON');
  }
  db.exec('DETACH DATABASE basesnap');
  return { tables: tables.length };
}

// ---------------------------------------------------------------------------
// Role + lease finalization.
// ---------------------------------------------------------------------------

function finalizeRole(db, role, opts) {
  haKeys.ensureSelfRow(db);
  db.prepare("UPDATE ha_node SET role = ?, updated_at = datetime('now') WHERE id = 'self'").run(role);
  db.prepare("UPDATE ha_peer SET status = 'paired', paired_at = COALESCE(paired_at, ?)").run(new Date().toISOString());
  if (role === 'active') {
    const ttlSec = (opts && opts.leaseTtlSec) || 30;
    const expires = new Date(Date.now() + ttlSec * 1000).toISOString();
    db.prepare(
      "INSERT INTO ha_lease (id, epoch, holder, lease_expires_at, last_heartbeat_at, term_started_at) VALUES ('current', 1, 'self', ?, datetime('now'), datetime('now')) "
      + "ON CONFLICT(id) DO UPDATE SET epoch = MAX(epoch, 1), holder = 'self', lease_expires_at = excluded.lease_expires_at, last_heartbeat_at = datetime('now'), term_started_at = datetime('now')"
    ).run(expires);
    haReplication.ensureStateRow(db);
    haCdc.regenerateTriggers(db, opts); // start capturing changes now that we are active
  }
}

// ---------------------------------------------------------------------------
// Unpinned pairing transport (trust-on-first-use, token-authenticated). Captures
// the peer's server-cert thumbprint. Used only for the initial /pair-init call.
// ---------------------------------------------------------------------------

function pairingRequest(endpoint, body, peerCaCertPem, peerLeafThumb, opts) {
  return new Promise(function (resolve, reject) {
    let base;
    try { base = new URL(endpoint); } catch (parseErr) { reject(new Error('ha-pairing: invalid endpoint')); return; }
    if (!peerCaCertPem) { reject(new Error('ha-pairing: pairing code missing peer CA certificate')); return; }
    let mat;
    try { mat = haPeerLink.localTlsMaterial(); } catch (matErr) { reject(new Error('ha-pairing: local TLS material unavailable')); return; }
    const payload = Buffer.from(JSON.stringify(body || {}), 'utf8');
    const timeout = (opts && opts.timeoutMs) || DEFAULT_TIMEOUT_MS;
    const pinned = (peerLeafThumb || '').toLowerCase();
    // First contact is authenticated by the out-of-band bootstrap: validate the
    // standby's chain against the CA from the pairing code (rejectUnauthorized:
    // true) and pin its exact leaf by fingerprint. No certificate validation is
    // disabled.
    const reqOpts = {
      host: base.hostname,
      port: base.port || 443,
      path: base.pathname.replace(/\/$/, '') + PAIR_INIT_PATH,
      method: 'POST',
      cert: mat.cert,
      key: mat.key,
      ca: [peerCaCertPem],
      rejectUnauthorized: true,
      checkServerIdentity: function (host, cert) {
        const got = (cert && cert.fingerprint256) ? haPeerLink.normalizeThumb(cert.fingerprint256) : null;
        if (!got || !pinned || got !== pinned) {
          return new Error('ha-pairing: peer certificate fingerprint mismatch');
        }
        return undefined;
      },
      agent: false,
      timeout: timeout,
      headers: { 'content-type': 'application/json', 'content-length': payload.length },
    };
    const req = https.request(reqOpts, function (res) {
      const chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error('ha-pairing: pair-init HTTP ' + res.statusCode + ' ' + text.slice(0, 200)));
          return;
        }
        try { resolve({ json: text ? JSON.parse(text) : {} }); }
        catch (jsonErr) { reject(new Error('ha-pairing: malformed pair-init response')); }
      });
    });
    req.on('timeout', function () { req.destroy(new Error('ha-pairing: pair-init timeout')); });
    req.on('error', function (err) { reject(err); });
    req.write(payload);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Orchestrators (called by routes/ha.js).
// ---------------------------------------------------------------------------

// Initiator/active side. Establishes trust, delivers the shared material and a
// baseline, and finalizes this node as active.
async function beginPairing(db, peerEndpoint, bootstrapCode, opts) {
  let boot;
  try { boot = JSON.parse(Buffer.from(String(bootstrapCode), 'base64').toString('utf8')); }
  catch (decodeErr) { throw new Error('ha-pairing: invalid pairing code'); }
  if (!boot || !boot.token || !boot.caCertPem || !boot.leafThumbprint) {
    throw new Error('ha-pairing: pairing code missing required fields');
  }
  const peerCaCertPem = boot.caCertPem;
  const peerLeafThumb = (boot.leafThumbprint || '').toLowerCase();
  const selfEndpoint = (opts && opts.selfEndpoint) || null;
  const myBundle = buildIdentityBundle(db, selfEndpoint, attestationNonce(boot.token));
  const init = await pairingRequest(peerEndpoint, { token: boot.token, bundle: myBundle }, peerCaCertPem, peerLeafThumb, opts);
  const peerBundle = init.json && init.json.bundle;
  if (!verifyPeerBundle(peerBundle)) {
    throw new Error('ha-pairing: peer bundle failed verification');
  }
  // Channel binding: the standby's anchor-signed CA + leaf must equal what the
  // operator carried out of band in the pairing code.
  if (peerBundle.caCertPem !== peerCaCertPem || (peerBundle.certThumbprint || '').toLowerCase() !== peerLeafThumb) {
    throw new Error('ha-pairing: peer identity does not match pairing code');
  }
  // Per-mode gate: in Cloud Mode both peers must be attested confidential VMs
  // (verifies the local node AND the peer's asserted report). Throws -> pairing
  // aborts. No-op in bare-metal / virtualized / sdn.
  haModes.assertModePairingAllowed(db, peerAttestationAssertion(peerBundle, boot.token));
  if (!peerBundle.endpoint) {
    peerBundle.endpoint = peerEndpoint;
  }
  pinPeer(db, peerBundle, peerLeafThumb, 'pairing');

  const envelope = wrapSharedMaterial(peerBundle.wrapPublicPem);
  await haPeerLink.sendToPeer(db, PAIR_SECRET_PATH, { envelope: envelope }, opts);

  let snap = null;
  try {
    snap = haCdc.createBaselineSnapshot(db);
    const b64 = fs.readFileSync(snap.path).toString('base64');
    await haPeerLink.sendToPeer(db, PAIR_BASELINE_PATH, { snapshot: b64 }, opts);
  } finally {
    if (snap && snap.path) { try { fs.unlinkSync(snap.path); } catch (unlinkErr) { /* ignore */ } }
  }

  finalizeRole(db, 'active', opts);
  try { haModes.registerHaSegments(db); } catch (segErr) { /* SDN segment registration is best-effort */ }
  try { auditLogOn(db, null, 'HA_PAIRED', 'Paired with standby ' + peerEndpoint + ' (this node active)', null); } catch (auditErr) { /* ignore */ }
  return { role: 'active', peerEndpoint: peerEndpoint, peerFingerprint: peerBundle.anchorFingerprint };
}

// Responder/standby side of /pair-init. Token-gated (NOT cert-pinned, since the
// pin does not exist yet). Pins the initiator, returns this node's bundle.
function respondToPairInit(db, body, clientCertThumbprint, opts) {
  if (!consumePairingToken(db, body && body.token)) {
    return { ok: false, status: 401, error: 'invalid or expired pairing token' };
  }
  if (!verifyPeerBundle(body && body.bundle)) {
    return { ok: false, status: 400, error: 'peer bundle failed verification' };
  }
  const peerBundle = body.bundle;
  if (peerBundle.certThumbprint && clientCertThumbprint && peerBundle.certThumbprint.toLowerCase() !== clientCertThumbprint) {
    return { ok: false, status: 400, error: 'peer certificate thumbprint mismatch' };
  }
  // Per-mode gate (Cloud Mode): verify the local node + the initiator's asserted
  // attestation before pinning. Refuse pairing if either fails.
  try {
    haModes.assertModePairingAllowed(db, peerAttestationAssertion(peerBundle, body.token));
  } catch (gateErr) {
    return { ok: false, status: 403, error: gateErr.message };
  }
  pinPeer(db, peerBundle, clientCertThumbprint, 'pairing');
  const myBundle = buildIdentityBundle(db, (opts && opts.selfEndpoint) || null, attestationNonce(body.token));
  return { ok: true, status: 200, bundle: myBundle };
}

// Responder side of /peer/pair-secret (pinned). Stores the wrapped material.
function receiveSharedMaterial(db, envelopeB64) {
  installSharedMaterial(db, envelopeB64);
  return { ok: true };
}

// Responder side of /peer/pair-baseline (pinned). Restores the baseline and
// finalizes this node as passive.
function receiveBaseline(db, snapshotB64, opts) {
  const tmp = path.join(os.tmpdir(), 'firealive-ha-baseline-recv-' + crypto.randomBytes(6).toString('hex') + '.sqlite');
  fs.writeFileSync(tmp, Buffer.from(String(snapshotB64), 'base64'), { mode: 0o600 });
  try {
    restoreBaseline(db, tmp, opts);
    finalizeRole(db, 'passive', opts);
    try { haModes.registerHaSegments(db); } catch (segErr) { /* SDN segment registration is best-effort */ }
  } finally {
    try { fs.unlinkSync(tmp); } catch (unlinkErr) { /* ignore */ }
  }
  try { auditLogOn(db, null, 'HA_PAIRED', 'Paired with active peer (this node passive)', null); } catch (auditErr) { /* ignore */ }
  return { ok: true, role: 'passive' };
}

module.exports = {
  generatePairingToken,
  consumePairingToken,
  buildIdentityBundle,
  verifyPeerBundle,
  pinPeer,
  wrapSharedMaterial,
  installSharedMaterial,
  restoreBaseline,
  finalizeRole,
  beginPairing,
  respondToPairInit,
  receiveSharedMaterial,
  receiveBaseline,
  PAIR_INIT_PATH,
  PAIR_SECRET_PATH,
  PAIR_BASELINE_PATH,
};

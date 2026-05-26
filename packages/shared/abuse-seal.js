// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — reviewer-only "sealed box" for abuse-flag content (U3 PR D, Model B)
//
// Anyone can SEAL to the abuse-review PUBLIC key (no secret needed); only the
// holder of the matching PRIVATE key (the Abuse Review Console) can OPEN it. The
// server stores only the sealed bytes and cannot read them. This is how flagged
// abuse content reaches the independent reviewer without the server, a lead, an
// admin, or a DB/key insider ever being able to decrypt it.
//
// Construction (X25519 ECIES over Node's built-in crypto -- no native or WASM
// dependency, so it builds in any Electron main process and is fully testable
// offline; the seal side runs in the AC/MC main process, the open side in the
// ABC main process). Layout of the sealed value:
//
//   MAGIC(4) || ephPubSPKI(44) || iv(12) || gcmTag(16) || ciphertext
//   shared = X25519(ephemeralPriv, recipientPub)
//   key    = HKDF-SHA256(ikm=shared, salt=ephPubSPKI||recipientPubSPKI,
//                        info="firealive-abuse-seal-v1", len=32)
//   ciphertext, gcmTag = AES-256-GCM(key, iv, plaintext)
//
// Public keys are X25519 in SPKI DER form (44 bytes), base64 in the registry/API.
// Both ends share THIS module so the seal and open formats can never diverge.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

const MAGIC = Buffer.from('FAS1', 'utf8');               // FireAlive Abuse Seal v1
const INFO = Buffer.from('firealive-abuse-seal-v1', 'utf8');
const ALGO = 'x25519-hkdf-sha256-aes256gcm';
const EPH_SPKI_LEN = 44;                                 // X25519 SPKI DER length
const IV_LEN = 12;
const TAG_LEN = 16;

function toPub(spkiDer) {
  return crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
}
function pubSpki(keyObj) {
  return keyObj.export({ format: 'der', type: 'spki' });
}

// Generate a reviewer keypair (used by the ABC at first run; PR F). Returns the
// public key as SPKI-DER base64 (to register via POST /api/abuse-review-key) and
// the private key as PKCS8-DER base64 (to seal locally via Electron safeStorage).
function generateReviewerKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    algo: ALGO,
    publicKeyB64: pubSpki(publicKey).toString('base64'),
    privateKeyB64: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
  };
}

// Seal plaintext to the recipient (abuse-review) public key. recipientPubB64 is
// SPKI-DER base64, as served by GET /api/abuse-review-key. Returns base64.
function sealToReviewer(recipientPubB64, plaintext) {
  const recipientSpki = Buffer.from(recipientPubB64, 'base64');
  const recipientPub = toPub(recipientSpki);

  const eph = crypto.generateKeyPairSync('x25519');
  const ephSpki = pubSpki(eph.publicKey);
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPub });
  const salt = Buffer.concat([ephSpki, recipientSpki]);
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, INFO, 32));

  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([MAGIC, ephSpki, iv, tag, ct]).toString('base64');
}

// Open a sealed value with the reviewer private key (PKCS8-DER base64, a Buffer
// of the same, or a Node KeyObject). Used only by the ABC (PR F). Returns the
// plaintext Buffer. Throws on a bad magic, a short value, or a failed GCM tag
// (tampering / wrong key).
function openAsReviewer(privateKey, sealedB64) {
  let priv;
  if (typeof privateKey === 'string') {
    priv = crypto.createPrivateKey({ key: Buffer.from(privateKey, 'base64'), format: 'der', type: 'pkcs8' });
  } else if (Buffer.isBuffer(privateKey)) {
    priv = crypto.createPrivateKey({ key: privateKey, format: 'der', type: 'pkcs8' });
  } else {
    priv = privateKey; // already a KeyObject
  }

  const buf = Buffer.from(sealedB64, 'base64');
  if (buf.length < MAGIC.length + EPH_SPKI_LEN + IV_LEN + TAG_LEN) {
    throw new Error('sealed value too short');
  }
  if (!buf.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('bad seal magic');
  }

  let o = MAGIC.length;
  const ephSpki = buf.subarray(o, o + EPH_SPKI_LEN); o += EPH_SPKI_LEN;
  const iv = buf.subarray(o, o + IV_LEN); o += IV_LEN;
  const tag = buf.subarray(o, o + TAG_LEN); o += TAG_LEN;
  const ct = buf.subarray(o);

  const ephPub = toPub(ephSpki);
  const shared = crypto.diffieHellman({ privateKey: priv, publicKey: ephPub });
  const recipientSpki = pubSpki(crypto.createPublicKey(priv));
  const salt = Buffer.concat([ephSpki, recipientSpki]);
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, INFO, 32));

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

module.exports = { ALGO, EPH_SPKI_LEN, generateReviewerKeypair, sealToReviewer, openAsReviewer };

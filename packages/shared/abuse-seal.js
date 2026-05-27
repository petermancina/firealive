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

// ── FAS2: multi-recipient envelope (U3 PR I, multi-reviewer zero-access) ────────
// Seal once to MANY reviewer public keys. A random content key (DEK) encrypts the
// content under AES-256-GCM; the DEK is then separately ECIES-wrapped to each
// recipient public key (same X25519 -> HKDF -> AES-256-GCM construction as FAS1).
// Any one reviewer opens the value by locating their slot (by an 8-byte public-key
// fingerprint), unwrapping the DEK with their own private key, and decrypting the
// content. No shared private key exists -- adding a reviewer is adding a slot.
// Layout of the sealed value:
//
//   MAGIC2(4) || nRecipients(1) ||
//     [ fp(8) || ephPubSPKI(44) || wrapIv(12) || wrapTag(16) || wrappedDEK(32) ] x n ||
//   contentIv(12) || contentTag(16) || ciphertext
//
//   per recipient:  shared  = X25519(ephemeralPriv, recipientPub)
//                   wrapKey = HKDF-SHA256(shared, ephSPKI||recipientSPKI,
//                                         "firealive-abuse-seal-v2-wrap", 32)
//                   wrappedDEK, wrapTag = AES-256-GCM(wrapKey, wrapIv, DEK)
//   content:        ciphertext, contentTag = AES-256-GCM(DEK, contentIv, plaintext)

const MAGIC2 = Buffer.from('FAS2', 'utf8');              // FireAlive Abuse Seal v2 (multi-recipient)
const INFO2 = Buffer.from('firealive-abuse-seal-v2-wrap', 'utf8');
const FP_LEN = 8;                                        // recipient fingerprint (SHA-256 prefix)
const DEK_LEN = 32;                                      // content key (AES-256)
const MAX_RECIPIENTS = 255;                              // nRecipients is a single byte

// 8-byte fingerprint of a recipient public key (SPKI-DER base64). Used to tag and
// later locate each recipient's slot in a FAS2 value. Both seal and open derive it
// the same way, so a reviewer can find their slot from their own key.
function fingerprintForPubB64(recipientPubB64) {
  const spki = Buffer.from(recipientPubB64, 'base64');
  return crypto.createHash('sha256').update(spki).digest().subarray(0, FP_LEN);
}

// Derive the SPKI-DER base64 public key for a PKCS8-DER base64 private key. Lets the
// open side compute its own fingerprint (to find its slot) without a stored copy.
function publicKeyB64FromPrivate(privateKeyB64) {
  const priv = crypto.createPrivateKey({ key: Buffer.from(privateKeyB64, 'base64'), format: 'der', type: 'pkcs8' });
  return pubSpki(crypto.createPublicKey(priv)).toString('base64');
}

// Seal plaintext to MANY recipient public keys at once (multi-recipient envelope).
// recipientPubB64List is a non-empty array of SPKI-DER base64 keys (the active
// reviewer set from GET /api/abuse-review-keys). Returns base64.
function sealToReviewers(recipientPubB64List, plaintext) {
  if (!Array.isArray(recipientPubB64List) || recipientPubB64List.length === 0) {
    throw new Error('at least one recipient public key is required');
  }
  if (recipientPubB64List.length > MAX_RECIPIENTS) {
    throw new Error('too many recipients (max ' + MAX_RECIPIENTS + ')');
  }

  // Encrypt the content once under a random data-encryption key (DEK).
  const dek = crypto.randomBytes(DEK_LEN);
  const contentIv = crypto.randomBytes(IV_LEN);
  const contentCipher = crypto.createCipheriv('aes-256-gcm', dek, contentIv);
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
  const contentCt = Buffer.concat([contentCipher.update(pt), contentCipher.final()]);
  const contentTag = contentCipher.getAuthTag();

  // Wrap the DEK to each recipient independently (ECIES per recipient).
  const slots = recipientPubB64List.map((recipientPubB64) => {
    const recipientSpki = Buffer.from(recipientPubB64, 'base64');
    const recipientPub = toPub(recipientSpki);
    const fp = fingerprintForPubB64(recipientPubB64);

    const eph = crypto.generateKeyPairSync('x25519');
    const ephSpki = pubSpki(eph.publicKey);
    const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPub });
    const salt = Buffer.concat([ephSpki, recipientSpki]);
    const wrapKey = Buffer.from(crypto.hkdfSync('sha256', shared, salt, INFO2, 32));

    const wrapIv = crypto.randomBytes(IV_LEN);
    const wrapCipher = crypto.createCipheriv('aes-256-gcm', wrapKey, wrapIv);
    const wrappedDek = Buffer.concat([wrapCipher.update(dek), wrapCipher.final()]);
    const wrapTag = wrapCipher.getAuthTag();

    return Buffer.concat([fp, ephSpki, wrapIv, wrapTag, wrappedDek]);
  });

  const count = Buffer.from([recipientPubB64List.length]);
  return Buffer.concat([MAGIC2, count, ...slots, contentIv, contentTag, contentCt]).toString('base64');
}

// Open a sealed value with the reviewer's private key (PKCS8-DER base64, a Buffer of
// the same, or a Node KeyObject), transparently handling BOTH formats: a FAS1
// single-recipient value dispatches to openAsReviewer (back-compat for flags sealed
// before PR I); a FAS2 multi-recipient value locates this reviewer's slot by an
// 8-byte public-key fingerprint, unwraps the DEK with the private key, and decrypts
// the content. Returns the plaintext Buffer. Throws on a bad magic, a too-short
// value, a failed GCM tag (tamper / wrong key), or when no slot matches this
// reviewer (the value was sealed to a different recipient set).
function openForReviewer(privateKey, sealedB64) {
  const buf = Buffer.from(sealedB64, 'base64');

  // FAS1 (single-recipient) -> the original path, unchanged.
  if (buf.length >= MAGIC.length && buf.subarray(0, MAGIC.length).equals(MAGIC)) {
    return openAsReviewer(privateKey, sealedB64);
  }

  // FAS2 (multi-recipient envelope).
  if (buf.length < MAGIC2.length + 1 || !buf.subarray(0, MAGIC2.length).equals(MAGIC2)) {
    throw new Error('bad seal magic');
  }

  let priv;
  if (typeof privateKey === 'string') {
    priv = crypto.createPrivateKey({ key: Buffer.from(privateKey, 'base64'), format: 'der', type: 'pkcs8' });
  } else if (Buffer.isBuffer(privateKey)) {
    priv = crypto.createPrivateKey({ key: privateKey, format: 'der', type: 'pkcs8' });
  } else {
    priv = privateKey; // already a KeyObject
  }
  const recipientSpki = pubSpki(crypto.createPublicKey(priv));
  const myFp = crypto.createHash('sha256').update(recipientSpki).digest().subarray(0, FP_LEN);

  const SLOT_LEN = FP_LEN + EPH_SPKI_LEN + IV_LEN + TAG_LEN + DEK_LEN;
  const n = buf[MAGIC2.length];
  const contentStart = MAGIC2.length + 1 + n * SLOT_LEN;     // content sits after all n slots
  if (buf.length < contentStart + IV_LEN + TAG_LEN) {
    throw new Error('sealed value too short');
  }
  const contentIv = buf.subarray(contentStart, contentStart + IV_LEN);
  const contentTag = buf.subarray(contentStart + IV_LEN, contentStart + IV_LEN + TAG_LEN);
  const ct = buf.subarray(contentStart + IV_LEN + TAG_LEN);

  for (let i = 0; i < n; i++) {
    const base = MAGIC2.length + 1 + i * SLOT_LEN;
    if (!buf.subarray(base, base + FP_LEN).equals(myFp)) continue;

    let p = base + FP_LEN;
    const ephSpki = buf.subarray(p, p + EPH_SPKI_LEN); p += EPH_SPKI_LEN;
    const wrapIv = buf.subarray(p, p + IV_LEN); p += IV_LEN;
    const wrapTag = buf.subarray(p, p + TAG_LEN); p += TAG_LEN;
    const wrappedDek = buf.subarray(p, p + DEK_LEN);

    const ephPub = toPub(ephSpki);
    const shared = crypto.diffieHellman({ privateKey: priv, publicKey: ephPub });
    const salt = Buffer.concat([ephSpki, recipientSpki]);
    const wrapKey = Buffer.from(crypto.hkdfSync('sha256', shared, salt, INFO2, 32));

    const wd = crypto.createDecipheriv('aes-256-gcm', wrapKey, wrapIv);
    wd.setAuthTag(wrapTag);
    const dek = Buffer.concat([wd.update(wrappedDek), wd.final()]);

    const cd = crypto.createDecipheriv('aes-256-gcm', dek, contentIv);
    cd.setAuthTag(contentTag);
    return Buffer.concat([cd.update(ct), cd.final()]);
  }
  throw new Error('no recipient slot for this reviewer key');
}

module.exports = { ALGO, EPH_SPKI_LEN, MAGIC2, FP_LEN, DEK_LEN, generateReviewerKeypair, sealToReviewer, openAsReviewer, sealToReviewers, openForReviewer, fingerprintForPubB64, publicKeyB64FromPrivate };

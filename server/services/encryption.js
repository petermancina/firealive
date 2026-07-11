// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Encryption Service
// Tier-3 analyst data: AES-256-GCM with per-record nonces
// Tier-1 integration configs: AES-256-GCM with separate key
// Peer messages: NaCl box (X25519 + XSalsa20-Poly1305)
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const tier1Kek = require('./tier1-kek');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

function getKey(envVar) {
  // Tier-1 secrets at rest are protected by the hardware-sealed, fail-closed
  // KEK (decision D26): TIER1_ENCRYPTION_KEY is unsealed on this hardware and
  // never read as a raw key. All other tiers keep the raw-hex env-var path.
  if (envVar === 'TIER1_ENCRYPTION_KEY') {
    return tier1Kek.resolveTier1Kek();
  }
  const hex = process.env[envVar];
  if (!hex || hex === 'CHANGE_ME' || hex.startsWith('CHANGE_ME')) {
    throw new Error(`${envVar} is not configured. Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`);
  }
  return Buffer.from(hex, 'hex');
}

// ── AES-256-GCM Symmetric Encryption ─────────────────────────────────────────

// Core AES-256-GCM seal/open on a raw 32-byte key. The v1 envelope is
// iv (12) || tag (16) || ciphertext. Both the env-var-keyed encrypt/decrypt
// below and the domain-aware Tier-1 chokepoint (tier1-seal) build on these, so
// there is exactly one envelope implementation and no risk of the two drifting.
function encryptWithKey(plaintext, key) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Return: iv (12) + tag (16) + ciphertext
  return Buffer.concat([iv, tag, encrypted]);
}

function decryptWithKey(buffer, key) {
  const iv = buffer.subarray(0, IV_LENGTH);
  const tag = buffer.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = buffer.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(ciphertext, null, 'utf-8') + decipher.final('utf-8');
}

function encrypt(plaintext, keyEnvVar = 'TIER3_ENCRYPTION_KEY') {
  return encryptWithKey(plaintext, getKey(keyEnvVar));
}

function decrypt(buffer, keyEnvVar = 'TIER3_ENCRYPTION_KEY') {
  return decryptWithKey(buffer, getKey(keyEnvVar));
}

// Tier-3 analyst signals
function encryptTier3(data) {
  return encrypt(typeof data === 'string' ? data : JSON.stringify(data), 'TIER3_ENCRYPTION_KEY');
}

function decryptTier3(buffer) {
  return JSON.parse(decrypt(buffer, 'TIER3_ENCRYPTION_KEY'));
}

// Tier-1 integration configs
function encryptConfig(data) {
  return encrypt(typeof data === 'string' ? data : JSON.stringify(data), 'TIER1_ENCRYPTION_KEY');
}

function decryptConfig(buffer) {
  return JSON.parse(decrypt(buffer, 'TIER1_ENCRYPTION_KEY'));
}

// ── NaCl Box Encryption (E2EE Peer Messages) ────────────────────────────────

function generateKeyPair() {
  const pair = nacl.box.keyPair();
  return {
    publicKey: naclUtil.encodeBase64(pair.publicKey),
    secretKey: naclUtil.encodeBase64(pair.secretKey),
  };
}

function encryptMessage(message, recipientPublicKey, senderSecretKey) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const msgBytes = naclUtil.decodeUTF8(message);
  const pubKey = naclUtil.decodeBase64(recipientPublicKey);
  const secKey = naclUtil.decodeBase64(senderSecretKey);
  const encrypted = nacl.box(msgBytes, nonce, pubKey, secKey);
  return {
    ciphertext: naclUtil.encodeBase64(encrypted),
    nonce: naclUtil.encodeBase64(nonce),
  };
}

function decryptMessage(ciphertext, nonce, senderPublicKey, recipientSecretKey) {
  const msg = nacl.box.open(
    naclUtil.decodeBase64(ciphertext),
    naclUtil.decodeBase64(nonce),
    naclUtil.decodeBase64(senderPublicKey),
    naclUtil.decodeBase64(recipientSecretKey)
  );
  if (!msg) throw new Error('Decryption failed — message tampered or wrong keys');
  return naclUtil.encodeUTF8(msg);
}

module.exports = {
  encrypt, decrypt,
  encryptWithKey, decryptWithKey,
  encryptTier3, decryptTier3,
  encryptConfig, decryptConfig,
  generateKeyPair, encryptMessage, decryptMessage,
};

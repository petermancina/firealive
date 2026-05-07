// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Key Wrapping Service
//
// Wraps and unwraps the per-backup ephemeral 256-bit AES-GCM key. The
// wrapped form is what gets written to wrapped-key.bin in the v2 backup
// directory; the raw ephemeral key never touches disk and never lives
// in the database.
//
// SCHEME DISPATCHER
//
// In R3d-1, only the "env-var" scheme is supported: the ephemeral key
// is wrapped with AES-256-GCM under a Key Encryption Key (KEK) read
// from a process environment variable. The KEK env var defaults to
// TIER1_ENCRYPTION_KEY (the same KEK used by encryption.js for
// integration credentials and signing keys).
//
// In R3d-4, three additional schemes are added: "aws-kms",
// "azure-key-vault", "gcp-kms". Each plugs into the same scheme
// dispatcher: a wrapper function that takes the ephemeral key plus
// scheme-specific configuration and returns the wrapped bytes; an
// unwrapper function that does the inverse. The envelope format
// below is forward-compatible with all four schemes.
//
// ENVELOPE FORMAT (wrapped-key.bin contents)
//
// JSON object (cleartext, operator-inspectable with `cat`):
//
//   {
//     "v":       1,                       (envelope version)
//     "scheme":  "env-var",               (scheme identifier)
//     "ref":     "TIER1_ENCRYPTION_KEY",  (scheme-specific KEK reference)
//     "wrapped": "base64..."              (the actual wrapped-key bytes,
//                                          format depends on scheme)
//   }
//
// For env-var scheme, "wrapped" is base64([iv | authTag | ciphertext])
// of the ephemeral key encrypted with AES-256-GCM under the env-var KEK.
// 12-byte IV + 16-byte tag + 32-byte ciphertext = 60 bytes raw, base64
// encodes to ~80 chars. Total wrapped-key.bin file size is ~150 bytes.
//
// INTEGRITY
//
// The wrapped-key.bin file's SHA-256 is recorded in manifest.json's
// files[] entry. The manifest is signed with Ed25519. Any tampering
// of wrapped-key.bin (including the scheme/ref fields) changes the
// SHA-256 and is caught by manifest verification before unwrapKey is
// ever called.
//
// As defense-in-depth, unwrapKey ALSO requires the caller to pass
// expectedScheme and expectedRef (read from the verified manifest)
// and verifies they match the envelope's claimed scheme and ref.
// A mismatch throws before any cryptographic operation runs.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

const ENVELOPE_VERSION  = 1;
const ENC_ALGORITHM     = 'aes-256-gcm';
const KEY_LENGTH_BYTES  = 32;     // AES-256
const IV_LENGTH_BYTES   = 12;     // GCM standard
const TAG_LENGTH_BYTES  = 16;     // GCM standard

const SUPPORTED_SCHEMES = ['env-var', 'aws-kms', 'azure-key-vault', 'gcp-kms'];
const IMPLEMENTED_SCHEMES_R3D1 = ['env-var'];

// ── KEK retrieval (env-var scheme) ────────────────────────────────────────

/**
 * Read a KEK from a process environment variable. Validates that the
 * variable exists, is not a placeholder, and decodes to a 32-byte key.
 *
 * Errors are precise so an operator can tell whether the env var is
 * missing, set to a placeholder, malformed hex, or wrong length.
 */
function readEnvVarKek(envVarName) {
  if (typeof envVarName !== 'string' || !envVarName.match(/^[A-Z][A-Z0-9_]*$/)) {
    throw new Error(`backup-key-wrapping: env-var ref '${envVarName}' is not a valid env var name`);
  }
  const hex = process.env[envVarName];
  if (!hex) {
    throw new Error(`backup-key-wrapping: env var ${envVarName} is not set`);
  }
  if (hex === 'CHANGE_ME' || hex.startsWith('CHANGE_ME')) {
    throw new Error(`backup-key-wrapping: env var ${envVarName} is set to a placeholder; generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`);
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`backup-key-wrapping: env var ${envVarName} is not valid hex`);
  }
  const key = Buffer.from(hex, 'hex');
  if (key.length !== KEY_LENGTH_BYTES) {
    throw new Error(`backup-key-wrapping: env var ${envVarName} decoded to ${key.length} bytes, expected ${KEY_LENGTH_BYTES}`);
  }
  return key;
}

// ── Per-scheme wrap / unwrap ──────────────────────────────────────────────

/**
 * env-var scheme: AES-256-GCM under the named env var KEK.
 * Returns base64([iv | authTag | ciphertext]).
 */
function wrapEnvVar(ephemeralKey, kekRef) {
  const kek = readEnvVarKek(kekRef);
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ENC_ALGORITHM, kek, iv);
  const ciphertext = Buffer.concat([cipher.update(ephemeralKey), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString('base64');
}

/**
 * Inverse of wrapEnvVar. Throws on auth tag mismatch (wrong KEK or
 * tampered wrapped bytes).
 */
function unwrapEnvVar(wrappedB64, kekRef) {
  const wrapped = Buffer.from(wrappedB64, 'base64');
  if (wrapped.length < IV_LENGTH_BYTES + TAG_LENGTH_BYTES + KEY_LENGTH_BYTES) {
    throw new Error(`backup-key-wrapping: wrapped key bytes too short (got ${wrapped.length}, need at least ${IV_LENGTH_BYTES + TAG_LENGTH_BYTES + KEY_LENGTH_BYTES})`);
  }
  const iv         = wrapped.subarray(0, IV_LENGTH_BYTES);
  const authTag    = wrapped.subarray(IV_LENGTH_BYTES, IV_LENGTH_BYTES + TAG_LENGTH_BYTES);
  const ciphertext = wrapped.subarray(IV_LENGTH_BYTES + TAG_LENGTH_BYTES);
  const kek = readEnvVarKek(kekRef);
  const decipher = crypto.createDecipheriv(ENC_ALGORITHM, kek, iv);
  decipher.setAuthTag(authTag);
  let key;
  try {
    key = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new Error(`backup-key-wrapping: AES-GCM unwrap failed (likely wrong KEK or tampered wrapped-key.bin): ${err.message}`);
  }
  if (key.length !== KEY_LENGTH_BYTES) {
    throw new Error(`backup-key-wrapping: unwrapped key has unexpected length ${key.length} (expected ${KEY_LENGTH_BYTES})`);
  }
  return key;
}

// ── Envelope serialization ────────────────────────────────────────────────

/**
 * Serialize a key-wrapping envelope to canonical JSON bytes. Same
 * canonicalization rules as backup-manifest.js: keys sorted, no
 * whitespace, UTF-8.
 */
function serializeEnvelope(envelope) {
  const sorted = {};
  for (const k of Object.keys(envelope).sort()) sorted[k] = envelope[k];
  return Buffer.from(JSON.stringify(sorted), 'utf-8');
}

function parseEnvelope(envelopeBytes) {
  let text;
  if (Buffer.isBuffer(envelopeBytes)) text = envelopeBytes.toString('utf-8');
  else if (typeof envelopeBytes === 'string') text = envelopeBytes;
  else throw new Error('backup-key-wrapping: envelope must be Buffer or string');
  let obj;
  try {
    obj = JSON.parse(text);
  } catch (err) {
    throw new Error(`backup-key-wrapping: envelope is malformed JSON: ${err.message}`);
  }
  if (!obj || typeof obj !== 'object') {
    throw new Error('backup-key-wrapping: envelope is not a JSON object');
  }
  if (obj.v !== ENVELOPE_VERSION) {
    throw new Error(`backup-key-wrapping: unsupported envelope version (got ${obj.v}, expected ${ENVELOPE_VERSION})`);
  }
  for (const required of ['scheme', 'ref', 'wrapped']) {
    if (typeof obj[required] !== 'string' || !obj[required]) {
      throw new Error(`backup-key-wrapping: envelope missing required field '${required}'`);
    }
  }
  if (!SUPPORTED_SCHEMES.includes(obj.scheme)) {
    throw new Error(`backup-key-wrapping: unknown scheme '${obj.scheme}' (supported: ${SUPPORTED_SCHEMES.join(', ')})`);
  }
  return obj;
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Wrap an ephemeral 256-bit data key.
 *
 * Inputs:
 *   ephemeralKey  Buffer (32 bytes)
 *   options       { scheme, kekReference }
 *                 scheme        — 'env-var' (R3d-4 adds KMS schemes)
 *                 kekReference  — env var name for env-var scheme;
 *                                 KMS key ARN/URI for KMS schemes
 *
 * Returns: Buffer — the wrapped-key.bin file contents (JSON envelope
 * as UTF-8 bytes).
 *
 * Throws on:
 *   - ephemeralKey not a 32-byte Buffer
 *   - scheme not implemented
 *   - env var missing / placeholder / malformed (env-var scheme)
 */
async function wrapKey(ephemeralKey, options) {
  if (!Buffer.isBuffer(ephemeralKey) || ephemeralKey.length !== KEY_LENGTH_BYTES) {
    throw new Error(`backup-key-wrapping: ephemeralKey must be a ${KEY_LENGTH_BYTES}-byte Buffer`);
  }
  if (!options || typeof options !== 'object') {
    throw new Error('backup-key-wrapping: options object required');
  }
  const { scheme, kekReference } = options;
  if (!IMPLEMENTED_SCHEMES_R3D1.includes(scheme)) {
    if (SUPPORTED_SCHEMES.includes(scheme)) {
      throw new Error(`backup-key-wrapping: scheme '${scheme}' is recognized but not yet implemented (lands in R3d-4)`);
    }
    throw new Error(`backup-key-wrapping: unknown scheme '${scheme}' (supported: ${IMPLEMENTED_SCHEMES_R3D1.join(', ')} in R3d-1)`);
  }
  if (typeof kekReference !== 'string' || !kekReference) {
    throw new Error('backup-key-wrapping: kekReference required');
  }

  let wrappedB64;
  if (scheme === 'env-var') {
    wrappedB64 = wrapEnvVar(ephemeralKey, kekReference);
  } else {
    // SUPPORTED_SCHEMES gate above ensures we never reach here in R3d-1.
    throw new Error(`backup-key-wrapping: scheme '${scheme}' has no wrap implementation`);
  }

  const envelope = {
    v: ENVELOPE_VERSION,
    scheme,
    ref: kekReference,
    wrapped: wrappedB64,
  };
  return serializeEnvelope(envelope);
}

/**
 * Unwrap a wrapped-key.bin file back to the raw 32-byte ephemeral key.
 *
 * Inputs:
 *   envelopeBytes    Buffer or string — the wrapped-key.bin contents
 *   expectedScheme   string — what scheme the manifest declared
 *   expectedRef      string — what kek_reference the manifest declared
 *
 * Defense-in-depth: throws if the envelope's claimed scheme/ref do not
 * match what the (already-signature-verified) manifest declared. Even
 * though the manifest's files[].sha256 hash would have caught any
 * tampering of wrapped-key.bin, this cross-check fires earlier with a
 * clearer error message and provides a second redundant integrity gate.
 *
 * Returns: Buffer (32 bytes — the ephemeral key)
 *
 * Throws on:
 *   - malformed envelope JSON / missing fields
 *   - scheme mismatch with expectedScheme
 *   - ref mismatch with expectedRef
 *   - scheme not implemented
 *   - cryptographic unwrap failure (wrong KEK, tampered bytes)
 *   - unwrapped key has wrong length
 */
async function unwrapKey(envelopeBytes, expectedScheme, expectedRef) {
  const envelope = parseEnvelope(envelopeBytes);

  if (typeof expectedScheme !== 'string' || !expectedScheme) {
    throw new Error('backup-key-wrapping: expectedScheme required for unwrap');
  }
  if (typeof expectedRef !== 'string' || !expectedRef) {
    throw new Error('backup-key-wrapping: expectedRef required for unwrap');
  }
  if (envelope.scheme !== expectedScheme) {
    throw new Error(`backup-key-wrapping: envelope scheme '${envelope.scheme}' does not match manifest-declared scheme '${expectedScheme}'`);
  }
  if (envelope.ref !== expectedRef) {
    throw new Error(`backup-key-wrapping: envelope ref '${envelope.ref}' does not match manifest-declared ref '${expectedRef}'`);
  }
  if (!IMPLEMENTED_SCHEMES_R3D1.includes(envelope.scheme)) {
    if (SUPPORTED_SCHEMES.includes(envelope.scheme)) {
      throw new Error(`backup-key-wrapping: scheme '${envelope.scheme}' is recognized but not yet implemented (lands in R3d-4)`);
    }
    throw new Error(`backup-key-wrapping: unknown scheme '${envelope.scheme}'`);
  }

  if (envelope.scheme === 'env-var') {
    return unwrapEnvVar(envelope.wrapped, envelope.ref);
  }
  throw new Error(`backup-key-wrapping: scheme '${envelope.scheme}' has no unwrap implementation`);
}

module.exports = {
  // public API
  wrapKey,
  unwrapKey,

  // exported for tests and for diagnostic tools that may want to
  // inspect a wrapped-key.bin without performing crypto
  parseEnvelope,
  serializeEnvelope,

  // constants
  ENVELOPE_VERSION,
  KEY_LENGTH_BYTES,
  SUPPORTED_SCHEMES,
  IMPLEMENTED_SCHEMES_R3D1,
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Model-File Signature / Provenance Verifier (layer 2, optional)
//
// Optional layer of the model-file integrity & safety gate. Verifies a detached
// signature over the model's pinned SHA-256 digest against an operator-configured
// trusted public key. Binding the publisher to the exact digest we already
// hash-pin is cryptographically sufficient and avoids streaming a multi-GB file
// through a verifier — the hash-pin layer already binds digest → file bytes.
//
// Configuration (operator-supplied; all optional):
//   MODEL_SIGNING_PUBLIC_KEY        PEM string of the trusted public key, OR
//   MODEL_SIGNING_PUBLIC_KEY_FILE   path to a PEM file
//   MODEL_SIGNING_REQUIRED=true     require a valid signature (default: false)
//   detached signature             base64 in "<modelFile>.sig" (or opts override).
//                                   The operator signs the lowercase sha256 hex.
//
// Supports ed25519/ed448 (null algorithm) and RSA/ECDSA (sha256) keys.
//
// verifyModelSignature({ filePath, sha256, modelId }, opts?) ->
//   { checked, ok, signer, reason, required }
//
// Semantics (this layer NEVER weakens hash-pin):
//   - No trusted key configured  -> { checked:false, ok:null }  (gate ignores layer 2)
//   - Key configured, signature present & valid   -> { checked:true,  ok:true  }
//   - Key configured, signature present & INVALID -> { checked:true,  ok:false } (red flag → block, even when not required)
//   - Key configured, signature MISSING:
//         required=true  -> { checked:true,  ok:false } (block)
//         required=false -> { checked:false, ok:null  } (fall back to hash-pin)
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const crypto = require('crypto');

function safeRead(p) { try { return fs.readFileSync(p, 'utf8'); } catch (_) { return null; } }

function isRequired(opts) {
  if (opts && typeof opts.signatureRequired === 'boolean') return opts.signatureRequired;
  return String(process.env.MODEL_SIGNING_REQUIRED || '').trim().toLowerCase() === 'true';
}

function loadPublicKey(opts) {
  const pem = (opts && opts.publicKeyPem)
    || process.env.MODEL_SIGNING_PUBLIC_KEY
    || (process.env.MODEL_SIGNING_PUBLIC_KEY_FILE && safeRead(process.env.MODEL_SIGNING_PUBLIC_KEY_FILE));
  if (!pem) return null;
  try { return crypto.createPublicKey(pem); } catch (_) { return { __invalid: true }; }
}

function fingerprint(keyObj) {
  try {
    const der = keyObj.export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(der).digest('hex').slice(0, 32);
  } catch (_) { return null; }
}

function readSignatureB64(filePath, opts) {
  if (opts && typeof opts.signatureB64 === 'string') return opts.signatureB64.trim();
  const sigPath = (opts && opts.signaturePath) || (filePath ? filePath + '.sig' : null);
  if (!sigPath) return null;
  const raw = safeRead(sigPath);
  return raw ? raw.trim() : null;
}

function verifyModelSignature(args, opts) {
  const { filePath, sha256 } = args || {};
  const required = isRequired(opts);
  const key = loadPublicKey(opts);

  // No trusted key configured → layer 2 is inactive; never blocks.
  if (!key) {
    return { checked: false, ok: null, signer: null, reason: 'no trusted signing key configured', required };
  }
  if (key.__invalid) {
    return required
      ? { checked: true, ok: false, signer: null, reason: 'trusted signing key is invalid (signature required)', required }
      : { checked: false, ok: null, signer: null, reason: 'trusted signing key is invalid; layer 2 skipped', required };
  }

  const signer = fingerprint(key);

  if (!sha256) {
    return required
      ? { checked: true, ok: false, signer, reason: 'no pinned digest to verify (signature required)', required }
      : { checked: false, ok: null, signer, reason: 'no pinned digest to verify; layer 2 skipped', required };
  }

  const sigB64 = readSignatureB64(filePath, opts);
  if (!sigB64) {
    return required
      ? { checked: true, ok: false, signer, reason: 'signature required but none found', required }
      : { checked: false, ok: null, signer, reason: 'no signature present; layer 2 skipped', required };
  }

  let signature;
  try { signature = Buffer.from(sigB64, 'base64'); }
  catch (_) { return { checked: true, ok: false, signer, reason: 'signature is not valid base64', required }; }
  if (!signature || signature.length === 0) {
    return { checked: true, ok: false, signer, reason: 'empty signature', required };
  }

  const data = Buffer.from(String(sha256).trim().toLowerCase(), 'utf8');
  let ok = false;
  try {
    const kt = key.asymmetricKeyType;
    const algo = (kt === 'ed25519' || kt === 'ed448') ? null : 'sha256';
    ok = crypto.verify(algo, data, key, signature);
  } catch (e) {
    return { checked: true, ok: false, signer, reason: 'signature verification error: ' + e.message, required };
  }

  // A present-but-invalid signature is a red flag and fails even when not required.
  return { checked: true, ok: !!ok, signer, reason: ok ? 'signature verified' : 'signature does not match pinned digest', required };
}

module.exports = { verifyModelSignature, _fingerprint: fingerprint };

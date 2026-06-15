// ══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Regional Device-Key Crypto Core (Phase B5f)
//
// The hardware device key each Analyst Client and Management Console operator's
// app holds (Blocks L and N) must prove possession of itself on every request
// once the session token is sender-constrained (B5f). This service is the
// policy-neutral crypto core the auth stack builds on; it holds no routes and no
// database access, mirroring the Global Dashboard's gd-device-key core:
//
//   - verifyDeviceSignature(...)  key-type-aware verify, Ed25519 / EC P-256,
//                                 the same check the regional websocket-server
//                                 uses for device-signed fleet operations
//   - jwkThumbprint(...)          RFC 7638 thumbprint for the RFC 7800 cnf.jkt
//                                 binding, recomputable from the registered key
//
// A deliberate own-copy of the verifier (rather than sharing websocket-server's)
// keeps this isolated from the working fleet-ops path; a future cleanup phase may
// unify the copies.
// ══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

// Key-type-aware signature verification. Ed25519 signs over the raw message
// (null digest); EC (P-256) signs sha256 with raw r||s (IEEE P1363) encoding.
// Accepts a PEM/DER string or buffer or an existing KeyObject. Any unparseable
// key, unsupported key type, or malformed signature verifies false rather than
// throwing, so a bad proof is always a clean rejection.
function verifyDeviceSignature(publicKey, message, signature) {
  try {
    const keyObject = (typeof publicKey === 'string' || Buffer.isBuffer(publicKey))
      ? crypto.createPublicKey(publicKey)
      : publicKey;
    const keyType = keyObject.asymmetricKeyType;
    if (keyType === 'ed25519') {
      return crypto.verify(null, message, keyObject, signature);
    }
    if (keyType === 'ec') {
      return crypto.verify('sha256', message, { key: keyObject, dsaEncoding: 'ieee-p1363' }, signature);
    }
    return false;
  } catch (_) {
    return false;
  }
}

// RFC 7638 JWK SHA-256 thumbprint (base64url) of the public key, the value bound
// into the session token's RFC 7800 cnf.jkt claim. Only the required members, in
// lexicographic order with no whitespace, are hashed, per the RFC, so the
// thumbprint is recomputable from the operator's registered active key.
function jwkThumbprint(publicKey) {
  const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
  let members;
  if (jwk.kty === 'EC') {
    members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  } else if (jwk.kty === 'OKP') {
    members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  } else {
    throw new Error('unsupported key type for thumbprint');
  }
  return crypto.createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

module.exports = {
  verifyDeviceSignature,
  jwkThumbprint,
};

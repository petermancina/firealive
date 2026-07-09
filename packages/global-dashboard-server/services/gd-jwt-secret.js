// FIREALIVE GLOBAL DASHBOARD -- runtime JWT-secret holder (B6d)
//
// The GD signs and verifies session JWTs with a single secret. Historically that
// secret was a module-level const in index.js; HA needs it to be updatable at
// runtime, so it lives here as a mutable module variable read through
// getJwtSecret(). This is the GD analogue of the MC's mutable JWT_SECRET +
// installRuntimeJwtSecret in server/middleware/auth.js (the GD has no shared auth
// module -- its authMiddleware lives in index.js).
//
// Initialization matches index.js's prior behavior exactly: GD_JWT_SECRET if set,
// otherwise an ephemeral random value (regenerated each boot, so sessions do not
// survive a restart unless GD_JWT_SECRET is configured -- unchanged).
//
// On HA promotion the promoted passive unseals the SHARED JWT secret (wrapped to
// its hardware during pairing, alongside the Tier-1 KEK) and installs it here via
// installRuntimeJwtSecret. Because index.js signs and verifies against
// getJwtSecret(), the install takes effect live -- sessions issued by the former
// active remain valid, so failover does not force the SOC to re-authenticate.
//
// No DB, no other requires. ASCII-only; no template literals.

const crypto = require('crypto');

let jwtSecret = process.env.GD_JWT_SECRET || crypto.randomBytes(32).toString('hex');

// The secret currently in effect for signing + verifying session JWTs.
function getJwtSecret() {
  return jwtSecret;
}

// Replace the in-effect JWT secret (HA promotion installs the shared secret here).
// A falsy value is ignored so a missing/malformed material field cannot blank the
// secret and lock everyone out.
function installRuntimeJwtSecret(secret) {
  if (secret) {
    jwtSecret = String(secret);
  }
}

module.exports = {
  getJwtSecret,
  installRuntimeJwtSecret,
};

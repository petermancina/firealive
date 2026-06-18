// FireAlive -- Identity Handle (directory minimization)
//
// Single source of truth for the non-identifying handle assigned to a
// directory-provisioned user in place of their real name. The directory sync
// and the one-time backfill migration MUST derive the handle identically (it is
// stored as the UNIQUE users.username), so the derivation lives here and nowhere
// else.
//
// The handle is a stable, opaque function of the account's opaque directory id
// (Active Directory objectGUID / OpenLDAP entryUUID): the same id always maps to
// the same handle, different ids effectively never collide, and the handle
// reveals nothing about the person. No real-identity attribute (displayName,
// sAMAccountName, mail) is ever an input.

'use strict';

const crypto = require('crypto');

// handleForGuid(directoryId) -> string
// Deterministic non-identifying handle: the literal 'usr_' followed by the first
// 12 hex characters of SHA-256(directoryId). 12 hex characters (48 bits) keep the
// handle short while making a collision across a SOC-sized directory vanishingly
// unlikely.
function handleForGuid(directoryId) {
  if (typeof directoryId !== 'string' || directoryId.length === 0) {
    throw new TypeError('directoryId must be a non-empty string');
  }
  const digest = crypto.createHash('sha256').update(directoryId).digest('hex');
  return 'usr_' + digest.slice(0, 12);
}

module.exports = { handleForGuid: handleForGuid };

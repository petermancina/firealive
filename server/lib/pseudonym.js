// FireAlive -- Pseudonym Generator (analyst display label)
//
// Single source of truth for the human-friendly, non-identifying pseudonym
// assigned to an analyst (for example, Analyst-Falcon-7). Burnout data is keyed
// to the pseudonym, and the Management Console team views show it in place of any
// real name. The directory sync, manual provisioning, the backfill migration, and
// the v025 pseudonym routes all generate pseudonyms through this module so the
// scheme stays defined in exactly one place.
//
// The pseudonym carries no identity: a bird name plus a two-digit number, drawn at
// random. Uniqueness is the caller's concern (it depends on what is already
// stored), so generateUniquePseudonym takes a predicate the caller uses to check
// against its own data.

'use strict';

const PSEUDONYM_BIRDS = [
  'Phoenix', 'Merlin', 'Peregrine', 'Kestrel', 'Harrier', 'Gyrfalcon', 'Sparrowhawk',
  'Kite', 'Buzzard', 'Shrike', 'Osprey', 'Falcon', 'Hawk', 'Raven', 'Eagle', 'Condor',
  'Albatross', 'Kingfisher', 'Nighthawk', 'Wren', 'Starling', 'Finch', 'Swift', 'Tern',
];

// generatePseudonym() -> string
// A single candidate of the form 'Analyst-<bird>-<NN>' (NN is 0-98). No uniqueness
// guarantee; for a value that must be unique use generateUniquePseudonym.
function generatePseudonym() {
  const bird = PSEUDONYM_BIRDS[Math.floor(Math.random() * PSEUDONYM_BIRDS.length)];
  const suffix = Math.floor(Math.random() * 99);
  return 'Analyst-' + bird + '-' + suffix;
}

// generateUniquePseudonym(isTaken, maxAttempts) -> string
// Draws candidates until one is not rejected by isTaken (a predicate returning
// true when a candidate is already in use). Throws if no free candidate is found
// within maxAttempts (default 200), which is far beyond any SOC-sized roster
// against the 24 x 99 space, so in practice it returns on the first few tries.
function generateUniquePseudonym(isTaken, maxAttempts) {
  const cap = typeof maxAttempts === 'number' && maxAttempts > 0 ? maxAttempts : 200;
  const taken = typeof isTaken === 'function' ? isTaken : function notTaken() { return false; };
  for (let i = 0; i < cap; i++) {
    const candidate = generatePseudonym();
    if (!taken(candidate)) return candidate;
  }
  throw new Error('could not generate a unique pseudonym within ' + cap + ' attempts');
}

module.exports = {
  PSEUDONYM_BIRDS: PSEUDONYM_BIRDS,
  generatePseudonym: generatePseudonym,
  generateUniquePseudonym: generateUniquePseudonym,
};

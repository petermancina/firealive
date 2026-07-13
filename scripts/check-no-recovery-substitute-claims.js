#!/usr/bin/env node
'use strict';

// check-no-recovery-substitute-claims.js -- docs guard (B6h B-8).
//
// The recovery code is the sole factor that can recover the Tier-1 KEK; there is deliberately no
// KMS escrow, back door, master key, or support-side reset that can stand in for it, because a
// substitutable KEK would undermine the anti-clone guarantee. This guard keeps the documentation
// from drifting into claiming otherwise: it flags any sentence that raises a recovery-substitute
// topic WITHOUT negating it (an affirmative "the KMS escrows the KEK for recovery" fails; the
// correct "there is no escrow copy of the Tier-1 KEK" passes). It also asserts the key-continuity
// doc still states the correct model, so the accurate framing cannot be silently deleted.

const fs = require('fs');
const path = require('path');

const REPO = path.resolve(__dirname, '..');
const problems = [];

// Docs in scope: the root guides + everything under docs/.
const files = [];
['README.md', 'FEATURE-GUIDE.md'].forEach(function (f) {
  if (fs.existsSync(path.join(REPO, f))) files.push(f);
});
const docsDir = path.join(REPO, 'docs');
if (fs.existsSync(docsDir)) {
  fs.readdirSync(docsDir).filter((f) => f.endsWith('.md')).forEach((f) => files.push(path.join('docs', f)));
}

// Topic markers that only arise when discussing a recovery-code substitute for the Tier-1 KEK.
const TOPIC_MARKERS = [
  'escrow',
  'back door',
  'back-door',
  'backdoor',
  'master key',
  'reset your key',
  'reset the key',
  'support can recover',
  'support-side reset',
  'recover your keys without',
  'recovery code is optional',
  'substitute for the recovery code',
];

// Negation / correctness markers that make a topic sentence a denial rather than a claim.
const NEGATIONS = [
  'no ', 'not ', 'never', 'cannot', "n't", 'without a', 'absence', 'sole', 'only',
  'nor ', 'neither', 'undermine', 'no such', 'there is no', 'rather than', 'no back',
];

const WINDOW = 200;

files.forEach(function (rel) {
  const raw = fs.readFileSync(path.join(REPO, rel), 'utf8');
  // Normalize whitespace so wrapped lines do not split a topic from its negation.
  const text = raw.replace(/\s+/g, ' ').toLowerCase();
  TOPIC_MARKERS.forEach(function (marker) {
    let from = 0;
    let idx;
    while ((idx = text.indexOf(marker, from)) !== -1) {
      const window = text.slice(Math.max(0, idx - WINDOW), idx + marker.length + WINDOW);
      const negated = NEGATIONS.some((n) => window.indexOf(n) !== -1);
      if (!negated) {
        problems.push(rel + ': "' + marker + '" appears without a nearby negation -- an affirmative recovery-substitute claim');
      }
      from = idx + marker.length;
    }
  });
});

// Positive assertion: the key-continuity doc still states the correct model.
const kcRel = 'docs/key-continuity-and-upgrades.md';
const kcPath = path.join(REPO, kcRel);
if (!fs.existsSync(kcPath)) {
  problems.push(kcRel + ' is missing (the key-continuity model must be documented)');
} else {
  const kc = fs.readFileSync(kcPath, 'utf8').toLowerCase();
  if (kc.indexOf('sole') === -1) problems.push(kcRel + ' no longer states the recovery code is the SOLE recovery factor');
  if (kc.indexOf('no escrow') === -1 && kc.indexOf('no kms escrow') === -1) problems.push(kcRel + ' no longer denies KEK escrow');
  if (kc.indexOf('anti-clone') === -1 && kc.indexOf('anti-cloning') === -1) problems.push(kcRel + ' no longer ties the absence of a substitute to the anti-clone guarantee');
}

if (problems.length) {
  console.error('recovery-substitute docs guard FAILED:');
  for (let i = 0; i < problems.length; i++) console.error('  - ' + problems[i]);
  process.exit(1);
}
console.log('recovery-substitute docs guard passed: no doc claims a KEK escrow / back door / master key / support reset can substitute for the recovery code, and the key-continuity doc states the correct model (sole factor, no escrow, anti-clone).');

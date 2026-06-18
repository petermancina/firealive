'use strict';

// FireAlive -- shared sanitizer for abuse-flag review notes.
//
// The reporter's free-text note (the "why is this abusive" description) is the
// ONLY accuser-authored text that ever enters a sealed flag; the flagged
// content itself is always system-copied, byte-for-byte authentic text. This
// module hardens that note on the INPUT side, before it is sealed, as
// defense-in-depth:
//
//   - Unicode NFC normalization, so the sealed note is canonical and stable.
//   - Strips C0/C1 control characters (keeps tab and newline) so no invisible
//     control bytes ride along in the evidence.
//   - Strips zero-width and bidirectional control characters, defeating
//     zero-width hiding and Trojan-Source-style bidirectional reordering.
//   - Neutralizes (defangs) URL schemes and www hosts, so a note can never
//     carry a live, clickable link to the reviewing lead or into an exported report.
//
// The Management Console review UI already renders decrypted notes as inert plain text
// (React text nodes, no HTML/markdown sink), so script execution is impossible
// there; this input-side pass is the second half of that defense and keeps the
// sealed evidence clean. The flagged CONTENT is never passed through here --
// only the note -- so authentic evidence is left exactly as captured.

// C0/C1 control characters, excluding tab (\u0009) and newline (\u000A).
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
// Zero-width characters and bidirectional formatting/override/isolate controls.
const ZERO_WIDTH_BIDI = /[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/g;
// Explicit URL schemes -- the strongest "this is a link" signal. Matched with
// no word boundary, so a scheme cannot evade defanging by being glued to a word
// character (e.g. a stripped zero-width leaving "xhttp://...") or split by one.
const URL_SCHEME = /(https?|ftps?|sftp|wss?):\/\//gi;
// Bare www. hosts (defanged so they cannot auto-link in a downstream client).
const WWW_HOST = /www\./gi;
// Hard cap matching the largest note input in the UI; guards against paste
// bombs even if a client bypasses the field's maxLength.
const MAX_LEN = 10000;

function defangScheme(scheme) {
  const s = scheme.toLowerCase();
  if (s === 'http') return 'hxxp';
  if (s === 'https') return 'hxxps';
  // Other schemes are neutralized by the [://] separator alone; mangle any 't'
  // for the conventional defanged look where one exists (ftp -> fxp, etc.).
  return scheme.replace(/t/gi, 'x');
}

// Sanitize a reporter note prior to sealing. Returns a cleaned string; never
// throws on ordinary input. The flagged content must NOT be passed here.
function sanitizeNote(input) {
  if (input == null) return '';
  let s = String(input);
  // 1. Canonical Unicode form.
  s = s.normalize('NFC');
  // 2. Normalize line endings, then strip remaining control characters.
  s = s.replace(/\r\n?/g, '\n').replace(CONTROL, '');
  // 3. Strip zero-width and bidirectional control characters.
  s = s.replace(ZERO_WIDTH_BIDI, '');
  // 4. Neutralize URLs so no live link can be smuggled into the note.
  s = s.replace(URL_SCHEME, (_m, scheme) => defangScheme(scheme) + '[://]');
  s = s.replace(WWW_HOST, 'www[.]');
  // 5. Trim surrounding whitespace and cap length.
  s = s.trim();
  if (s.length > MAX_LEN) s = s.slice(0, MAX_LEN);
  return s;
}

module.exports = { sanitizeNote, MAX_LEN };

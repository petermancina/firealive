// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Content Sanitizer
//
// Layer 1 defense for user-uploaded content (IR policies, AARs) that will be
// fed into LLM prompts or stored as long-lived configuration. This is the
// FireAlive-specific layer of the upload security model: it catches threats
// that originate from how FireAlive uses the content, not threats that are
// dangerous in the abstract.
//
// In particular: commercial EDR products do not know that FireAlive has an
// LLM dispatcher, what an OODA scenario tree looks like, or how user-uploaded
// policy text becomes prompt context. Prompt-injection defense is therefore a
// FireAlive-domain problem and lives here, not in EDR. EDR (the layer 2
// inspector in services/integration-manager.js) catches malware signatures
// and threat-intel matches that change weekly — things FireAlive should not
// try to keep current on its own.
//
// Both layers run on every upload. Either layer's rejection blocks the
// upload (fail-closed). This service runs first because it's deterministic,
// network-free, and cheap.
//
// API:
//   sanitize(content, options) → { clean: bool, threats: [{category, detail}], scanId }
//
// Categories detected:
//   - prompt_injection      LLM instruction-override and role-switching patterns
//   - embedded_executable   shebangs, script blocks, suspicious binary content
//   - encoding_attack       null bytes, RTL override, zero-width hiding, homoglyphs
//   - structural            implausibly large or malformed content
//
// All detection is conservative and pattern-based. Some legitimate content
// (e.g. a policy that quotes a powershell example for documentation purposes)
// will trip detectors. The expected workflow is: upload → reject with
// specific threats list → user adjusts content (e.g. removes the powershell
// example or wraps it in a way the sanitizer accepts) → re-upload. False
// positives are intentionally preferred over false negatives in this layer.
//
// This module does NOT call any external service, does NOT touch the
// database, and has no async behavior. Pure functional input → output.
//
// Phase F4b — IR Simulator backend (commit 6a).
// ═══════════════════════════════════════════════════════════════════════════════

const SANITIZER_VERSION = '1.0.0';
const MAX_CONTENT_SIZE = 500000;        // 500KB — matches MAX_POLICY_SIZE in routes/ooda.js
const MAX_THREATS_REPORTED = 50;
const MIN_PRINTABLE_RATIO = 0.85;       // legitimate prose is >85% printable characters
const crypto = require('crypto');

// ── Pattern banks ───────────────────────────────────────────────────────────

// Prompt-injection patterns. These target the most common attempts to
// manipulate an LLM that ingests this content as part of a prompt. The
// list is intentionally conservative — a single match flags the upload.
const PROMPT_INJECTION_PATTERNS = [
  // Direct instruction-override
  { pattern: /\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|directives?)/i,
    detail: 'instruction override attempt' },
  { pattern: /\bdisregard\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|directives?)/i,
    detail: 'instruction disregard attempt' },
  { pattern: /\bforget\s+(?:everything|all)\s+(?:above|previous|prior|that)/i,
    detail: 'memory-wipe instruction' },
  { pattern: /\boverride\s+(?:your|the|all|previous)\s+(?:instructions?|programming|rules?|directives?|safety)/i,
    detail: 'override instruction' },
  // Role-switching / jailbreak markers
  { pattern: /\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|simulate\s+being)\s+(?:a\s+)?(?:different|new|unrestricted|uncensored|jailbroken|developer|admin|dan|grandma)/i,
    detail: 'role-switch attempt' },
  { pattern: /\b(?:enable|activate|enter)\s+(?:dan|developer|debug|jailbreak|god|admin|root|unrestricted)\s+mode/i,
    detail: 'mode-switch jailbreak' },
  // Chat-template tokens that an attacker might inject to break out of
  // the prompt structure FireAlive uses
  { pattern: /<\|(?:im_start|im_end|system|user|assistant|endoftext|fim_prefix|fim_suffix)\|>/i,
    detail: 'chat-template token injection' },
  { pattern: /\[INST\]|\[\/INST\]/,
    detail: 'instruction-template token injection' },
  { pattern: /<\|start_header_id\|>|<\|end_header_id\|>|<\|eot_id\|>/i,
    detail: 'header-token injection' },
  // Fake system prompts embedded in user content
  { pattern: /^\s*(?:system|assistant)\s*[:>]/im,
    detail: 'embedded role marker' },
  { pattern: /\b(?:###\s*(?:system|assistant)\s*(?:instructions?|prompt|message))/i,
    detail: 'pseudo-section role marker' },
  // Output-shape hijacking
  { pattern: /\boutput\s+(?:only\s+)?(?:json|the\s+following)\s*:?\s*\{[\s\S]{0,500}"correct"\s*:\s*true/i,
    detail: 'output-hijack attempt (correct=true seeding)' },
  { pattern: /\bmark\s+(?:all|every|the\s+following)\s+(?:choices?|answers?|options?)\s+(?:as\s+)?correct/i,
    detail: 'answer-key tampering attempt' },
  // Tool / capability invocation attempts
  { pattern: /\b(?:execute|run|eval)\s+(?:this|the\s+following)\s+(?:code|script|command|shell)/i,
    detail: 'execution invocation' },
];

// Embedded-executable patterns. These flag content that looks like it's
// trying to embed runnable code rather than describe procedures.
const EXECUTABLE_PATTERNS = [
  // Shebangs
  { pattern: /^#!\s*\/(?:bin|usr|opt|sbin)\//m,
    detail: 'shell shebang' },
  // PowerShell signatures
  { pattern: /\b(?:powershell|pwsh)\s+(?:-(?:e(?:nc(?:odedcommand)?)?|c(?:ommand)?|nop|noprofile|w(?:indowstyle)?|exec(?:utionpolicy)?))/i,
    detail: 'powershell command-line invocation' },
  { pattern: /\b(?:Invoke-Expression|IEX|Invoke-WebRequest|IWR|DownloadString|DownloadFile)\s*\(/,
    detail: 'powershell network/eval cmdlet' },
  // VBA macro markers
  { pattern: /\b(?:Sub\s+(?:AutoOpen|Document_Open|Workbook_Open)|Auto_Open)\s*\(/i,
    detail: 'VBA auto-execution macro' },
  { pattern: /\bShell\s*\(\s*["']/i,
    detail: 'VBA Shell() invocation' },
  // JS / Node patterns that don't belong in policy prose
  { pattern: /\b(?:require\s*\(\s*["'](?:child_process|fs|net|http|https)["']\s*\)|process\.(?:env|exit|kill))/,
    detail: 'Node.js sensitive module require' },
  { pattern: /\beval\s*\(\s*(?:atob|Buffer\.from)\s*\(/,
    detail: 'JavaScript decode-and-eval pattern' },
  // Reverse shells / data-exfil signatures
  { pattern: /\b(?:nc|ncat|netcat)\s+(?:-(?:e|c)\s+\/bin\/(?:sh|bash)|-l\s+-p\s+\d+\s+-e)/,
    detail: 'netcat reverse-shell pattern' },
  { pattern: /\b(?:bash\s+-i\s+>&\s*\/dev\/tcp\/|\/dev\/tcp\/[\d.]+\/\d+)/,
    detail: 'bash /dev/tcp reverse shell' },
  { pattern: /\b(?:curl|wget)\s+(?:-s\s+)?https?:\/\/[^\s]+\s*\|\s*(?:bash|sh|python|perl)/i,
    detail: 'pipe-to-shell from network download' },
  // Base64-encoded blob that's suspiciously long (common obfuscation)
  { pattern: /[A-Za-z0-9+/]{500,}={0,2}/,
    detail: 'large base64-encoded blob (likely obfuscated payload)' },
];

// Encoding-attack patterns. These detect characters used to hide content
// from human review or to break parsing.
const ENCODING_ATTACK_PATTERNS = [
  { pattern: /\u0000/, detail: 'null byte' },
  { pattern: /[\u202A-\u202E]/, detail: 'bidirectional override character (RTL/LTR spoofing)' },
  { pattern: /[\u200B-\u200F\u2060-\u2064]/, detail: 'zero-width / invisible character (content hiding)' },
  { pattern: /[\uFEFF]/, detail: 'byte-order-mark / zero-width no-break space' },
  // Tag characters (Unicode tag block) — used in recent prompt-injection
  // attacks to smuggle invisible instructions
  { pattern: /[\u{E0000}-\u{E007F}]/u, detail: 'Unicode tag character (invisible instruction smuggling)' },
];

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Sanitize uploaded content. Returns { clean, threats, scanId }.
 *
 * @param {string} content   the raw text to scan
 * @param {object} [options]
 * @param {string} [options.fileName]   used in scanId attribution; not validated
 * @param {string} [options.fileType]   reserved for future use
 * @returns {{clean: boolean, threats: Array<{category: string, detail: string, snippet: string}>, scanId: string, sanitizerVersion: string}}
 */
function sanitize(content, options) {
  options = options || {};
  const threats = [];
  const scanId = crypto.randomBytes(8).toString('hex');

  // Structural checks first — handle non-string and oversize before running
  // expensive regex passes
  if (typeof content !== 'string') {
    return {
      clean: false,
      threats: [{ category: 'structural', detail: 'content must be a string', snippet: '' }],
      scanId,
      sanitizerVersion: SANITIZER_VERSION,
    };
  }
  if (content.length === 0) {
    return {
      clean: false,
      threats: [{ category: 'structural', detail: 'content is empty', snippet: '' }],
      scanId,
      sanitizerVersion: SANITIZER_VERSION,
    };
  }
  if (content.length > MAX_CONTENT_SIZE) {
    threats.push({
      category: 'structural',
      detail: `content exceeds maximum size (${content.length} > ${MAX_CONTENT_SIZE})`,
      snippet: '',
    });
    return finalize(threats, scanId);
  }

  // Printable-ratio check (catches mostly-binary content masquerading as text).
  // Allowed: standard printable ASCII, common whitespace, plus extended Unicode
  // letters/symbols (so non-English policies aren't false-flagged).
  const printable = countPrintable(content);
  const ratio = printable / content.length;
  if (ratio < MIN_PRINTABLE_RATIO) {
    threats.push({
      category: 'structural',
      detail: `low printable-character ratio (${(ratio * 100).toFixed(1)}% < ${MIN_PRINTABLE_RATIO * 100}%) — content may contain binary data`,
      snippet: '',
    });
  }

  // Pattern banks. Each match adds one threat with a short context snippet
  // so the user can locate the offending content. We cap total threats so a
  // pathological document doesn't produce an enormous response.
  scanPatterns(content, PROMPT_INJECTION_PATTERNS, 'prompt_injection', threats);
  if (threats.length < MAX_THREATS_REPORTED) {
    scanPatterns(content, EXECUTABLE_PATTERNS, 'embedded_executable', threats);
  }
  if (threats.length < MAX_THREATS_REPORTED) {
    scanPatterns(content, ENCODING_ATTACK_PATTERNS, 'encoding_attack', threats);
  }

  return finalize(threats, scanId);
}

// ── Internals ───────────────────────────────────────────────────────────────

function countPrintable(text) {
  let count = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    // Standard printable ASCII (0x20-0x7E), tab, LF, CR
    if (code === 0x09 || code === 0x0A || code === 0x0D || (code >= 0x20 && code <= 0x7E)) {
      count++;
      continue;
    }
    // Extended Unicode (Latin-1 supplement and beyond) — treat as printable
    // for ratio purposes. Encoding-attack patterns above will catch the
    // specific malicious code points (null, BOM, RTL override, etc.) that
    // we DON'T want to allow regardless of ratio.
    if (code >= 0xA0) {
      count++;
    }
  }
  return count;
}

function scanPatterns(content, patterns, category, threats) {
  for (const { pattern, detail } of patterns) {
    if (threats.length >= MAX_THREATS_REPORTED) return;
    const match = content.match(pattern);
    if (match) {
      threats.push({
        category,
        detail,
        snippet: makeSnippet(content, match.index || 0, match[0].length),
      });
    }
  }
}

function makeSnippet(content, matchStart, matchLen) {
  const SNIPPET_PAD = 30;
  const start = Math.max(0, matchStart - SNIPPET_PAD);
  const end = Math.min(content.length, matchStart + matchLen + SNIPPET_PAD);
  let snip = content.slice(start, end);
  // Replace control chars in the snippet with their escape representation so
  // a snippet containing e.g. a null byte is still readable in JSON output.
  snip = snip.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, c => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
  if (start > 0) snip = '...' + snip;
  if (end < content.length) snip = snip + '...';
  return snip.slice(0, 200);
}

function finalize(threats, scanId) {
  return {
    clean: threats.length === 0,
    threats,
    scanId,
    sanitizerVersion: SANITIZER_VERSION,
  };
}

module.exports = {
  sanitize,
  SANITIZER_VERSION,
  // Exported for unit testing of internal logic
  _internal: {
    countPrintable,
    makeSnippet,
    PROMPT_INJECTION_PATTERNS,
    EXECUTABLE_PATTERNS,
    ENCODING_ATTACK_PATTERNS,
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v1.0.0 — AI/ML Attack Surface Protection
// Addresses: prompt injection, model poisoning, data extraction via AI,
// adversarial inputs, AI output validation
// ═══════════════════════════════════════════════════════════════════════════════

// ── Prompt Injection Detection ──────────────────────────────────────────────
const INJECTION_PATTERNS = [
  /ignore\s+(previous|above|all)\s+(instructions|prompts)/i,
  /you\s+are\s+now\s+/i,
  /disregard\s+(your|all|previous)/i,
  /forget\s+(everything|your|all)/i,
  /act\s+as\s+(if|a|an)\s+/i,
  /system\s*:\s*/i,
  /\[INST\]/i, /\[\/INST\]/i,
  /<<SYS>>/i, /<\|im_start\|>/i,
  /do\s+not\s+follow\s+(your|the)\s+(instructions|rules)/i,
  /override\s+(your|the|all)\s+(rules|instructions|safety)/i,
  /reveal\s+(your|the)\s+(system|initial)\s+(prompt|instructions)/i,
  /what\s+(is|are)\s+your\s+(system|initial)\s+(prompt|instructions)/i,
];

const detectPromptInjection = (text) => {
  if (typeof text !== 'string') return false;
  return INJECTION_PATTERNS.some(p => p.test(text));
};

// ── AI Input Sanitization ───────────────────────────────────────────────────
const sanitizeAiInput = (input) => {
  if (typeof input !== 'string') return input;
  // Remove control characters
  let s = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  // Limit length to prevent context window exhaustion
  s = s.substring(0, 4000);
  // Remove attempts to inject system prompts
  s = s.replace(/<<SYS>>|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\]/gi, '');
  return s;
};

// ── AI Output Validation ────────────────────────────────────────────────────
const validateAiOutput = (output) => {
  if (typeof output !== 'string') return output;
  // Redact leaked system-prompt indicators first, while the markers are
  // still intact (removing the angle brackets below would break the match).
  let s = output.replace(/<<SYS>>[\s\S]*?<<\/SYS>>/gi, '[REDACTED]');
  // Neutralize any HTML and executable URL schemes. Removing the angle
  // brackets themselves -- single characters -- cannot reconstruct a tag,
  // so no <script (or any other element) survives, unlike removing whole
  // <script>...</script> spans which a crafted input can reassemble.
  s = s.replace(/[<>]/g, '').replace(/(?:javascript|data|vbscript):/gi, '');
  // Redact PII the model might emit.
  s = s.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN-REDACTED]');
  s = s.replace(/\b\d{16}\b/g, '[CC-REDACTED]');
  return s;
};

// ── Data Firewall (prevents sensitive data reaching external AI) ────────────
const SENSITIVE_FIELDS = ['password', 'apiKey', 'key', 'token', 'secret', 'ssn', 'creditCard', 'hash'];
const dataFirewall = (data) => {
  if (typeof data !== 'object' || !data) return data;
  const cleaned = {};
  for (const [k, v] of Object.entries(data)) {
    if (SENSITIVE_FIELDS.some(f => k.toLowerCase().includes(f))) {
      cleaned[k] = '[REDACTED]';
    } else if (typeof v === 'object') {
      cleaned[k] = dataFirewall(v);
    } else {
      cleaned[k] = v;
    }
  }
  return cleaned;
};

// ── Middleware ───────────────────────────────────────────────────────────────
const aiSecurityMiddleware = (req, res, next) => {
  if (req.path.includes('/ai/') || req.path.includes('/tutor/')) {
    // Check for prompt injection
    const allText = JSON.stringify(req.body || {});
    if (detectPromptInjection(allText)) {
      console.warn(`[AI-SECURITY] Prompt injection attempt from ${req.ip}`);
      return res.status(400).json({ error: 'Input rejected by AI security filter' });
    }
    // Sanitize input
    if (req.body?.prompt) req.body.prompt = sanitizeAiInput(req.body.prompt);
    if (req.body?.message) req.body.message = sanitizeAiInput(req.body.message);
    // Apply data firewall if sending to external AI
    if (req.body?.provider && req.body.provider !== 'internal') {
      req.body.context = dataFirewall(req.body.context || {});
    }
  }
  next();
};

module.exports = { detectPromptInjection, sanitizeAiInput, validateAiOutput, dataFirewall, aiSecurityMiddleware };

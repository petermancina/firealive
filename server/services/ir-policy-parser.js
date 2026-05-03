// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — IR Policy Parser
//
// Rule-based extraction of structured fields from arbitrary uploaded incident-
// response policy text. The output feeds the OODA scenario generator (which
// calls aiProvider.generate) so the LLM has structured context — detection
// signals, decision points, escalation paths, roles, containment actions,
// communications requirements, severity tiers — instead of being asked to
// digest raw policy prose. This service does NOT call any LLM; it is pure
// pattern matching and is deliberately deterministic.
//
// Inputs: a policy object with at least { content: string, title: string,
//         policy_type: 'incident_response' | 'playbook' | ... }
//
// Output: {
//   sections: [{heading, body}, ...]    — top-level structural decomposition
//   detection_signals: [string, ...]    — observable cues / triggers
//   decision_points: [{condition, action}, ...]  — branching rules
//   escalation_paths: [string, ...]     — who-to-notify-when statements
//   roles: [string, ...]                — named roles/responsibilities
//   containment_actions: [string, ...]  — verb-led response steps
//   communications: [string, ...]       — notify / inform / report obligations
//   severity_tiers: [string, ...]       — P1/critical/high/medium/low markers
//   metadata: { word_count, section_count, parser_version, ... }
// }
//
// All output arrays are bounded (MAX_ITEMS_PER_FIELD) to keep prompt size
// predictable. Items are deduplicated and trimmed. Empty fields are returned
// as empty arrays, never as null/undefined, so callers don't need to defensive-
// check.
//
// Phase F4b — IR Simulator backend.
// ═══════════════════════════════════════════════════════════════════════════════

const PARSER_VERSION = '1.0.0';
const MAX_ITEMS_PER_FIELD = 25;
const MAX_LINE_LENGTH = 500;
const MAX_SECTION_BODY_CHARS = 2000;

// ── Pattern banks ───────────────────────────────────────────────────────────

// Detection-signal cues. Lines containing these phrases tend to describe
// observable indicators that scenarios can use as Observe-phase prompts.
const DETECTION_PATTERNS = [
  /\b(?:detect|detection|observ|monitor|alert(?:s|ing)?|trigger|indicator|ioc|signal)/i,
  /\b(?:siem|edr|xdr|ndr|ids|ips|firewall log|proxy log|dns log)/i,
  /\b(?:anomal(?:y|ous)|suspicious|unusual|unexpected) (?:traffic|activity|behavior|login|access|process)/i,
  /\b(?:if you (?:see|notice|observe|detect))/i,
  /\b(?:look for|watch for|check for|verify)/i,
];

// Decision-point cues. Conditional language that implies a branching choice.
const DECISION_PATTERNS = [
  /^(?:if|when|should|in (?:the )?(?:event|case) (?:that|of))\b/i,
  /\b(?:then|otherwise|else|alternatively)\b/i,
  /\b(?:decision criteria|decision matrix|decide whether)/i,
];

// Escalation cues. Hierarchy / hand-off language.
const ESCALATION_PATTERNS = [
  /\b(?:escalat(?:e|ion)|hand[- ]off|page|notif(?:y|ication))/i,
  /\b(?:on[- ]call|incident commander|ic|tier[- ]?[123]|t[123] analyst)/i,
  /\b(?:within \d+ (?:minute|hour|business day))/i,
  /\b(?:legal|hr|public relations|pr|executive|c[- ]?suite|ciso|cio|cto)/i,
];

// Role markers. "The X analyst does Y", "X is responsible for Y", colons-and-list patterns.
const ROLE_PATTERNS = [
  /\b(?:the )?(?:on[- ]call|incident commander|ic|soc analyst|tier[- ]?[123]|t[123]|lead analyst|forensic analyst|threat hunter|ciso|legal counsel|compliance officer|hr|comms? (?:lead|team)|public relations|pr|executive|management)\b/i,
  /\b(?:owner|responsible|accountable|consulted|informed)(?:\s+for|\s*[:=])/i,
  /^[A-Z][\w\- ]{2,40}:\s+/, // "Incident Commander: <responsibility>" lines
];

// Containment/response action verbs. Lines starting with these tend to be
// "what to do" steps.
const CONTAINMENT_VERBS = [
  'isolate', 'disconnect', 'disable', 'quarantine', 'block', 'remove', 'reset',
  'rotate', 'revoke', 'suspend', 'kill', 'terminate', 'preserve', 'image',
  'snapshot', 'backup', 'patch', 'rebuild', 'restore', 'rollback',
  'segment', 'firewall', 'null route', 'sinkhole',
];

// Communications obligations. Requires a notify/inform-style verb at the
// start of a clause OR a regulatory-deadline phrase, to avoid catching every
// line that happens to mention "alert" as a noun.
const COMMUNICATIONS_PATTERNS = [
  /(?:^|\b)(?:notif(?:y|ication)|inform|report|disclos(?:e|ure)|announce)\b/i,
  /\bwithin \d+ (?:hour|day|business day|business hour)/i,
  /\b(?:gdpr|hipaa|sox|pci|breach notification|regulator|law enforcement)\b/i,
];

// Severity / priority markers.
const SEVERITY_PATTERNS = [
  /\b(?:p[1-5]|priority [1-5])\b/i,
  /\b(?:sev(?:erity)? ?[1-5])\b/i,
  /\b(?:critical|high|medium|low|informational)\s+(?:severity|priority|impact|incident)/i,
  /\b(?:tier ?[1-5])\b/i,
];

// ── Helpers ─────────────────────────────────────────────────────────────────

function safeText(input) {
  if (typeof input !== 'string') return '';
  // Hard cap to defend against pathological policy size. Routes already cap
  // at MAX_POLICY_SIZE before insert, but the parser is the last line of
  // defense in case the cap is bypassed.
  return input.slice(0, 500000);
}

function dedupeAndTrim(arr) {
  const seen = new Set();
  const out = [];
  for (const item of arr) {
    if (typeof item !== 'string') continue;
    const trimmed = item.trim();
    if (!trimmed) continue;
    if (trimmed.length > MAX_LINE_LENGTH) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(trimmed);
    if (out.length >= MAX_ITEMS_PER_FIELD) break;
  }
  return out;
}

function splitLines(text) {
  // Normalize line endings, strip BOM, split on newlines.
  return text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').split('\n');
}

function looksLikeHeading(line) {
  const t = line.trim();
  if (!t) return false;
  // Markdown heading
  if (/^#{1,6}\s+\S/.test(t)) return true;
  // ALL CAPS short line
  if (t.length <= 80 && t === t.toUpperCase() && /[A-Z]/.test(t) && !/^[\d\s\-_]+$/.test(t)) return true;
  // Numbered section: "1. Foo", "1.2 Bar", "Section 3: Baz"
  if (/^(?:section\s+)?\d+(\.\d+)*\s*[:.\)]\s+\S/i.test(t)) return true;
  // Underlined heading: line followed by === or --- of equal-ish length is
  // detected at section-extraction time, not here (needs lookahead).
  return false;
}

function extractSections(text) {
  const lines = splitLines(text);
  const sections = [];
  let current = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const next = lines[i + 1] || '';

    // Underline-style heading: current line is non-empty, next is === or ---
    const isUnderlineHeading = line.trim() && /^={3,}\s*$|^-{3,}\s*$/.test(next.trim());

    if (looksLikeHeading(line) || isUnderlineHeading) {
      if (current) sections.push(current);
      const heading = line.trim().replace(/^#+\s*/, '');
      current = { heading, body: '' };
      if (isUnderlineHeading) i++; // skip the underline line
      continue;
    }

    if (!current) current = { heading: '(introduction)', body: '' };
    current.body += line + '\n';
  }
  if (current) sections.push(current);

  // Trim and bound each section's body
  return sections.map(s => ({
    heading: s.heading.slice(0, 200),
    body: s.body.trim().slice(0, MAX_SECTION_BODY_CHARS),
  })).filter(s => s.heading || s.body);
}

function extractByPatterns(text, patternList) {
  const lines = splitLines(text);
  const matches = [];
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.length > MAX_LINE_LENGTH) continue;
    // Filter out lines that are themselves section headings — they're
    // already captured in `sections` and re-including them as detection
    // signals or escalation paths is noise.
    if (looksLikeHeading(t)) continue;
    for (const pattern of patternList) {
      if (pattern.test(t)) {
        matches.push(t);
        break;
      }
    }
  }
  return dedupeAndTrim(matches);
}

function extractDecisionPoints(text) {
  const lines = splitLines(text);
  const out = [];
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.length > MAX_LINE_LENGTH) continue;

    // Match "if X, then Y" / "when X, do Y" / "should X then Y"
    const ifThen = t.match(/^(?:if|when|should)\s+(.+?)[,;]\s+(?:then\s+)?(.+)$/i);
    if (ifThen) {
      out.push({ condition: ifThen[1].trim().slice(0, 250), action: ifThen[2].trim().slice(0, 250) });
      continue;
    }
    // Match "in the event of X, do Y"
    const inEvent = t.match(/^in (?:the )?(?:event|case) (?:that |of )(.+?)[,;]\s+(.+)$/i);
    if (inEvent) {
      out.push({ condition: inEvent[1].trim().slice(0, 250), action: inEvent[2].trim().slice(0, 250) });
      continue;
    }
  }
  // Dedupe by condition text
  const seen = new Set();
  const deduped = [];
  for (const item of out) {
    const key = item.condition.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(item);
    if (deduped.length >= MAX_ITEMS_PER_FIELD) break;
  }
  return deduped;
}

function extractContainmentActions(text) {
  const lines = splitLines(text);
  const verbPattern = new RegExp(`^\\s*(?:[-*\\d.)\\s]+)?(?:${CONTAINMENT_VERBS.join('|')})\\b`, 'i');
  const matches = [];
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.length > MAX_LINE_LENGTH) continue;
    if (verbPattern.test(t)) matches.push(t.replace(/^[-*\d.)\s]+/, ''));
  }
  return dedupeAndTrim(matches);
}

function extractRoles(text) {
  const matches = extractByPatterns(text, ROLE_PATTERNS);
  // Roles often appear in "Role: responsibility" form. Normalize to just the role name where unambiguous.
  // Filter out severity-tier lines that the colon-pattern accidentally catches
  // (e.g. "P1 - Critical: Active ransomware...") and verb-led action lines
  // that don't actually name a role.
  const out = [];
  const seen = new Set();
  const SEVERITY_PREFIX = /^(?:p[1-5]|sev(?:erity)? ?[1-5]|priority [1-5]|tier ?[1-5])\b/i;
  const VERB_LED = /^(?:escalate|notify|page|alert|inform|report|isolate|disable|block|disconnect|quarantine|preserve|when|if|should)\b/i;

  for (const line of matches) {
    if (SEVERITY_PREFIX.test(line)) continue;
    if (VERB_LED.test(line)) continue;
    const colonMatch = line.match(/^([A-Z][\w\- ]{2,60}):\s+/);
    const role = colonMatch ? colonMatch[1].trim() : line;
    if (SEVERITY_PREFIX.test(role)) continue;
    const key = role.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(role.slice(0, 200));
    if (out.length >= MAX_ITEMS_PER_FIELD) break;
  }
  return out;
}

function extractSeverityTiers(text) {
  const found = new Set();
  for (const pattern of SEVERITY_PATTERNS) {
    // Combine the original flags with 'g' for matchAll-style global scan.
    // Drop 'g' if already present to avoid duplication.
    const flags = (pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    const matches = text.match(new RegExp(pattern.source, flags));
    if (matches) for (const m of matches) found.add(m.trim().toLowerCase());
  }
  return Array.from(found).slice(0, MAX_ITEMS_PER_FIELD);
}

// ── Public API ──────────────────────────────────────────────────────────────

function parsePolicy(policy) {
  const policyObj = policy && typeof policy === 'object' ? policy : {};
  const content = safeText(policyObj.content);

  if (!content) {
    return {
      sections: [],
      detection_signals: [],
      decision_points: [],
      escalation_paths: [],
      roles: [],
      containment_actions: [],
      communications: [],
      severity_tiers: [],
      metadata: {
        word_count: 0,
        section_count: 0,
        parser_version: PARSER_VERSION,
        policy_id: policyObj.id || null,
        policy_title: typeof policyObj.title === 'string' ? policyObj.title.slice(0, 200) : null,
        policy_type: typeof policyObj.policy_type === 'string' ? policyObj.policy_type : null,
      },
    };
  }

  const sections = extractSections(content);
  const detectionSignals = extractByPatterns(content, DETECTION_PATTERNS);
  const decisionPoints = extractDecisionPoints(content);
  const escalationPaths = extractByPatterns(content, ESCALATION_PATTERNS);
  const roles = extractRoles(content);
  const containmentActions = extractContainmentActions(content);
  const communications = extractByPatterns(content, COMMUNICATIONS_PATTERNS);
  const severityTiers = extractSeverityTiers(content);
  const wordCount = content.split(/\s+/).filter(Boolean).length;

  return {
    sections,
    detection_signals: detectionSignals,
    decision_points: decisionPoints,
    escalation_paths: escalationPaths,
    roles,
    containment_actions: containmentActions,
    communications,
    severity_tiers: severityTiers,
    metadata: {
      word_count: wordCount,
      section_count: sections.length,
      parser_version: PARSER_VERSION,
      policy_id: policyObj.id || null,
      policy_title: typeof policyObj.title === 'string' ? policyObj.title.slice(0, 200) : null,
      policy_type: typeof policyObj.policy_type === 'string' ? policyObj.policy_type : null,
    },
  };
}

// Aggregate parse over multiple policies. Used by the scenario generator
// when building a prompt that references all policies of a given type.
// Returns the same shape as parsePolicy, with arrays merged and deduplicated
// across all input policies. Per-policy section structure is preserved in
// metadata.per_policy.
function parsePolicies(policies) {
  if (!Array.isArray(policies)) return parsePolicy(null);

  const aggregate = {
    sections: [],
    detection_signals: [],
    decision_points: [],
    escalation_paths: [],
    roles: [],
    containment_actions: [],
    communications: [],
    severity_tiers: [],
    metadata: {
      word_count: 0,
      section_count: 0,
      parser_version: PARSER_VERSION,
      policy_count: policies.length,
      per_policy: [],
    },
  };

  for (const p of policies) {
    const parsed = parsePolicy(p);
    aggregate.sections.push(...parsed.sections.map(s => ({ ...s, source_policy_id: p && p.id })));
    aggregate.detection_signals.push(...parsed.detection_signals);
    aggregate.decision_points.push(...parsed.decision_points);
    aggregate.escalation_paths.push(...parsed.escalation_paths);
    aggregate.roles.push(...parsed.roles);
    aggregate.containment_actions.push(...parsed.containment_actions);
    aggregate.communications.push(...parsed.communications);
    aggregate.severity_tiers.push(...parsed.severity_tiers);
    aggregate.metadata.word_count += parsed.metadata.word_count;
    aggregate.metadata.section_count += parsed.metadata.section_count;
    aggregate.metadata.per_policy.push({
      policy_id: parsed.metadata.policy_id,
      policy_title: parsed.metadata.policy_title,
      policy_type: parsed.metadata.policy_type,
      word_count: parsed.metadata.word_count,
      section_count: parsed.metadata.section_count,
    });
  }

  // Re-cap each merged array
  aggregate.detection_signals = dedupeAndTrim(aggregate.detection_signals);
  aggregate.escalation_paths = dedupeAndTrim(aggregate.escalation_paths);
  aggregate.roles = dedupeAndTrim(aggregate.roles);
  aggregate.containment_actions = dedupeAndTrim(aggregate.containment_actions);
  aggregate.communications = dedupeAndTrim(aggregate.communications);
  aggregate.severity_tiers = Array.from(new Set(aggregate.severity_tiers)).slice(0, MAX_ITEMS_PER_FIELD);

  // decision_points are objects, dedupe by condition text
  const seenConditions = new Set();
  aggregate.decision_points = aggregate.decision_points.filter(dp => {
    const key = dp.condition.toLowerCase();
    if (seenConditions.has(key)) return false;
    seenConditions.add(key);
    return true;
  }).slice(0, MAX_ITEMS_PER_FIELD);

  // sections aren't deduped (they have source_policy_id and may legitimately repeat headings)
  // but cap total
  aggregate.sections = aggregate.sections.slice(0, MAX_ITEMS_PER_FIELD * 2);

  return aggregate;
}

module.exports = {
  parsePolicy,
  parsePolicies,
  PARSER_VERSION,
};

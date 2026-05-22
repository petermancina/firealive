// FireAlive v1.0.42 — Research Knowledge Base (server-authoritative)
//
// Server-side copy of the FireAlive Research Knowledge Base, extracted from
// the management console (frontend/firealive-mc.jsx) where it previously lived
// only as a display dataset. This module is the single source of truth for AI
// prompt construction and citation validation in the burnout-message pipeline
// (N1b): the generator passes the whole KB into the prompt and the strict
// citation gate validates the model's R-refs against it, so no hallucinated or
// off-KB reference is possible.
//
// The MC keeps its own display copy pinned to the same KB_VERSION; full dedup
// (the MC reading from a server endpoint) is deferred to K1. The KB is enriched
// manually by developers as new peer-reviewed research is published — nothing
// here is auto-generated or auto-added.

const { logger } = require('./logger');

const RESEARCH_KB = [
  {id:"R001",topic:"intervention",tags:["organizational","meta-analysis","exhaustion"],finding:"Organizational interventions produce effect size d=−0.30 on exhaustion (CI: −0.42 to −0.18), with participatory interventions strongest.",implication:"Structural changes (workload, scheduling, participatory redesign) are evidence-based first response.",strength:"strong",cite:"Shoman et al. (2023), Int Arch Occup Environ Health, 96(7), 1009–1025",year:2023},
  {id:"R002",topic:"intervention",tags:["combined","meta-analysis"],finding:"Combined org + individual interventions achieve d=−0.54; individual-only d≈0.16–0.36, fading within 6 months.",implication:"Pair structural interventions with individual support for durable results.",strength:"strong",cite:"Dreison et al. (2018), J Occup Health Psychol, 23(1), 84–93",year:2018},
  {id:"R003",topic:"fairness",tags:["worklife","equity","maslach"],finding:"Six domains predict burnout: workload, control, reward, community, fairness, values. Fairness incongruity more predictive than raw workload.",implication:"Alert distribution equity (Gini coefficient) is more actionable than volume metrics.",strength:"strong",cite:"Leiter & Maslach (2004), Areas of Worklife Survey; Maslach & Leiter (2016), World Psychiatry, 15(2), 103–111",year:2016},
  {id:"R004",topic:"fairness",tags:["equity","distribution"],finding:"Perceived unfairness in workload distribution accelerates burnout even when total counts appear balanced.",implication:"Auto-equity routing must consider complexity weighting, not just count.",strength:"strong",cite:"Maslach, Schaufeli & Leiter (2001), Annual Rev Psychol, 52, 397–422",year:2001},
  {id:"R005",topic:"measurement",tags:["MBI","dimensions","exhaustion"],finding:"MBI measures exhaustion, depersonalization, personal accomplishment. Exhaustion develops first and is central to progression.",implication:"Behavioral drift detection should weight exhaustion proxies as earliest signals.",strength:"strong",cite:"Maslach & Jackson (1981), J Org Behavior, 2(2), 99–113",year:1981},
  {id:"R006",topic:"soc_burnout",tags:["SOC","ethnography","human-capital"],finding:"SOC burnout is a human capital management problem from cyclic interaction of skills, growth, creativity, and empowerment factors.",implication:"Platform must address all four human capital attributes — not just workload.",strength:"strong",cite:"Sundaramurthy et al. (2015), SOUPS, pp. 347–359",year:2015},
  {id:"R007",topic:"soc_burnout",tags:["SOC","informal-support","peer"],finding:"Informal collegial contact preferred over formal debriefing by stressed analysts. Career progression alone didn't address root causes.",implication:"Peer support should be informal and voluntary, not mandated debriefings.",strength:"strong",cite:"Sundaramurthy et al. (2015), SOUPS, pp. 347–359",year:2015},
  {id:"R008",topic:"alert_fatigue",tags:["SOC","alert-volume"],finding:"71% of SOC analysts report burnout; 64% say manual work >50% of time; 65% say half tasks automatable; 64% considering leaving.",implication:"Automation delegation rate is a leading indicator of analyst wellbeing.",strength:"moderate",cite:"Tines (2024), Voice of the SOC Analyst Report",year:2024},
  {id:"R009",topic:"alert_fatigue",tags:["SOC","false-positives","costs"],finding:"Orgs processing >10K alerts/day lose ~25% capacity to false positive investigation. 28% of alerts never addressed.",implication:"Each automated pattern saves 3,650 analyst interactions/year for 10 daily alerts.",strength:"moderate",cite:"Ponemon Institute (2023); Forrester (2020), State of Security Ops",year:2023},
  {id:"R010",topic:"soc_burnout",tags:["SOC","alert-growth"],finding:"97% of orgs see YoY alert increases. 89.6% have rising security backlogs. Only 19% of alerts typically addressed.",implication:"Alert volume growth outpaces hiring — automation is structurally necessary.",strength:"moderate",cite:"Osterman Research (2024), Making the SOC More Efficient",year:2024},
  {id:"R011",topic:"soc_operations",tags:["SOC","triage","hours"],finding:"Analysts should spend no more than 4–6 hours/day on intensive triage to maintain productivity.",implication:"Utilization thresholds should cap sustained intensive triage at 75% of shift.",strength:"moderate",cite:"Gartner; Ponemon — ref. in Intezer SOC Burnout Index (2025)",year:2025},
  {id:"R012",topic:"soc_operations",tags:["SOC","utilization"],finding:"Expel maintains 70–80% analyst utilization target. Beyond 80%, error rates increase measurably.",implication:"80% utilization is the upper bound for sustained quality.",strength:"moderate",cite:"Expel (2023), SOC Operations metrics",year:2023},
  {id:"R013",topic:"engagement",tags:["manager","1:1","Gallup"],finding:"Weekly manager conversations produce 3× engagement improvement vs annual/quarterly reviews.",implication:"Regular 1:1 cadence is a structural intervention.",strength:"strong",cite:"Gallup (2023), State of the Global Workplace Report",year:2023},
  {id:"R014",topic:"engagement",tags:["check-ins","turnover"],finding:"Replacing annual reviews with regular informal check-ins reduced voluntary turnover by 30%.",implication:"Informal work conversations more effective than scheduled wellness checks.",strength:"moderate",cite:"Adobe (2017), Check-In Program; ref. Buckingham & Goodall (2019), HBR",year:2017},
  {id:"R015",topic:"shift_work",tags:["circadian","night-shift","health"],finding:"Shift work contributes to sleep disturbances, cardiovascular strain, mental health issues. Night workers 17–28% higher depression rates.",implication:"Night shift analysts need different utilization thresholds and recovery time.",strength:"strong",cite:"Kecklund & Axelsson (2016), BMJ, 355, i5210",year:2016},
  {id:"R016",topic:"shift_work",tags:["vigilance","cognitive"],finding:"Sustained attention degrades significantly after 90 min of continuous monitoring. 20-min breaks restore vigilance to near-baseline.",implication:"Alert queue should include natural breakpoints. >90 min continuous triage degrades detection.",strength:"strong",cite:"Warm et al. (2008), Human Factors, 50(3), 433–441",year:2008},
  {id:"R017",topic:"shift_work",tags:["fatigue","handoff"],finding:"Fatigue-related errors peak during last 2 hours of 12-hour shifts. Shift handoff is critical vulnerability.",implication:"Queue load should decrease toward shift end. Handoff protocol with team state summary.",strength:"moderate",cite:"Dawson & Reid (1997), Nature, 388, 235; Folkard & Tucker (2003), Occup Med, 53(2)",year:2003},
  {id:"R018",topic:"automation",tags:["AI","agentic","tier-1"],finding:"AI-driven automation can handle up to 90% of tier-1 tasks, shifting analysts from doing to reviewing.",implication:"Delegation workflow should be frictionless.",strength:"moderate",cite:"Dropzone AI (2024); Radiant Security (2026) — industry reports",year:2024},
  {id:"R019",topic:"automation",tags:["automation-paradox","complacency"],finding:"Automation complacency: over-reliance degrades manual skills and misses alerts outside automated rules.",implication:"Track analyst skill maintenance alongside automation rates.",strength:"strong",cite:"Parasuraman & Manzey (2010), Human Factors, 52(3), 381–410",year:2010},
  {id:"R020",topic:"automation",tags:["trust","calibration"],finding:"Appropriate trust in automation requires understanding system capabilities/limitations. Under-trust → disuse; over-trust → misuse.",implication:"Display confidence scores and FP rates transparently to analysts.",strength:"strong",cite:"Lee & See (2004), Human Factors, 46(1), 50–80",year:2004},
  {id:"R021",topic:"privacy",tags:["surveillance","workplace","ethics"],finding:"Electronic performance monitoring increases stress when perceived as controlling. Transparency mediates this.",implication:"All monitoring must be transparent, opt-in where possible, developmental.",strength:"strong",cite:"Ravid et al. (2020), J Applied Psychol, 105(1), 49–73",year:2020},
  {id:"R022",topic:"privacy",tags:["consent","autonomy","wellbeing"],finding:"Wellbeing programs collecting individual data without meaningful consent show net negative effects on trust.",implication:"Privacy-first architecture is functionally necessary, not just ethical.",strength:"strong",cite:"Ajunwa et al. (2017), Berkeley Tech Law J, 32(3)",year:2017},
  {id:"R023",topic:"privacy",tags:["anonymity","psychological-safety"],finding:"Anonymous reporting channels increase disclosure 40–60% vs identified channels. Psychological safety is prerequisite.",implication:"Lighter queue requests, peer messaging, lead communication must default anonymous.",strength:"strong",cite:"Edmondson (1999), Admin Sci Quarterly, 44(2), 350–383",year:1999},
  {id:"R024",topic:"theory",tags:["JD-R","demands","resources"],finding:"JD-R model: burnout develops when demands (alerts, time pressure) exceed resources (autonomy, feedback, support). Resources buffer demands.",implication:"Both reduce demands (automation, caps) and increase resources (training, peer support, autonomy).",strength:"strong",cite:"Bakker & Demerouti (2007), J Managerial Psychol, 22(3), 309–328",year:2007},
  {id:"R025",topic:"theory",tags:["JD-R","engagement"],finding:"Job resources are the strongest predictors of work engagement, the positive antithesis of burnout.",implication:"Platform should measure and support engagement indicators too.",strength:"strong",cite:"Bakker & Demerouti (2008), J Managerial Psychol, 23(3), 209–223",year:2008},
  {id:"R026",topic:"peer_support",tags:["social-support","buffering"],finding:"Social support (peer/supervisor) has direct negative effect on burnout and buffers high demands. Peer support especially effective for exhaustion.",implication:"E2EE peer messaging directly addresses the strongest social support pathway.",strength:"strong",cite:"Halbesleben (2006), J Occup Health Psychol, 11(4), 293–315",year:2006},
  {id:"R027",topic:"peer_support",tags:["mentoring","skill-transfer"],finding:"Peer mentoring produces faster skill transfer than formal training. Mentoring reduces turnover intention by 20–30%.",implication:"Training integrations should include peer mentoring pathways.",strength:"moderate",cite:"Allen et al. (2004), J Applied Psychol, 89(1), 127–136",year:2004},
  {id:"R028",topic:"cognitive_load",tags:["decision-fatigue","triage"],finding:"Decision quality degrades with cumulative decisions. Judges granted parole at 65% at start vs 0% before breaks.",implication:"Rotate complexity levels in queue. Back-to-back high-complexity alerts accelerate fatigue.",strength:"strong",cite:"Danziger et al. (2011), PNAS, 108(17), 6889–6892",year:2011},
  {id:"R029",topic:"cognitive_load",tags:["interruptions","context-switching"],finding:"Each context switch costs 15–25 min recovery. Interrupted investigations have 2× more errors.",implication:"Batch similar alert types where possible. Minimize cross-domain context switches.",strength:"moderate",cite:"Mark et al. (2008), CHI — The Cost of Interrupted Work",year:2008},
  {id:"R030",topic:"retention",tags:["turnover","SOC","tenure"],finding:"Average SOC analyst tenure 1–3 years. Drivers: repetitive work (62%), lack of growth (54%), compensation (47%), burnout (44%).",implication:"Career development and skill progression tracking are retention tools.",strength:"moderate",cite:"SANS Institute (2023), SOC Survey; ISC2 (2023), Cybersecurity Workforce Study",year:2023},
  {id:"R031",topic:"retention",tags:["procedural-justice","voice"],finding:"Procedural justice (voice in decisions) reduces turnover independently of distributive justice. Voice matters.",implication:"Analyst agency — lighter queue requests, delegation, training scheduling — is a justice mechanism.",strength:"strong",cite:"Colquitt et al. (2001), J Applied Psychol, 86(3), 386–400",year:2001},
  {id:"R032",topic:"recovery",tags:["detachment","off-shift"],finding:"Psychological detachment from work during off-hours is a top predictor of reduced exhaustion and improved next-day performance.",implication:"Training and peer check-ins off-shift. No notifications during off-hours.",strength:"strong",cite:"Sonnentag & Fritz (2007), J Occup Health Psychol, 12(3), 204–221",year:2012},
  {id:"R033",topic:"recovery",tags:["micro-breaks","restoration"],finding:"Short breaks (5–10 min) during sustained cognitive work restore attention. Nature/movement amplifies recovery.",implication:"Queue pacing should incorporate natural break windows every 90 min.",strength:"moderate",cite:"Kim et al. (2018), J Applied Psychol, 103(2), 155–169",year:2018},
  {id:"R034",topic:"moral_injury",tags:["moral-distress","ethics"],finding:"Moral injury occurs when professionals lack resources to address known threats. Distinct from workload burnout.",implication:"Over-capacity must be transparent to leadership. Hiding overload compounds moral injury.",strength:"moderate",cite:"Williamson et al. (2018), Occup Med, 68(8), 502–509",year:2018},
  {id:"R035",topic:"team_composition",tags:["diversity","skill-mix"],finding:"Cognitively diverse teams show 20–30% better threat detection in security operations.",implication:"Balance tier levels, tenure, and specialization per shift — not just headcount.",strength:"moderate",cite:"Rajivan & Cooke (2017), Human Factors, 59(3), 425–441",year:2017},
  {id:"R036",topic:"contagion",tags:["crossover","emotional-contagion"],finding:"Burnout is contagious: exhaustion in one member predicts increased exhaustion in colleagues within 2–4 weeks.",implication:"Team-level monitoring is critical — one burned-out analyst affects the shift. Early intervention prevents cascade.",strength:"strong",cite:"Bakker et al. (2005), J Applied Psychol, 90(4), 827–839",year:2005},
  {id:"R037",topic:"motivation",tags:["SDT","autonomy","competence"],finding:"Self-Determination Theory: intrinsic motivation requires autonomy, competence, relatedness. Controlling environments undermine all three.",implication:"Enhance analyst autonomy (queue choice), competence (training), relatedness (peer connection).",strength:"strong",cite:"Deci & Ryan (2000), Psychological Inquiry, 11(4), 227–268",year:2000},
  {id:"R038",topic:"incident_stress",tags:["incident-response","acute-stress"],finding:"Major incident response produces acute stress comparable to emergency services. Post-incident support reduces impact 40–60%.",implication:"After major incidents, trigger recovery protocols: lighter queues, peer support, optional debrief.",strength:"moderate",cite:"Chen et al. (2014), HFES Proc; Sundaramurthy et al. (2016), IEEE S&P Workshop",year:2014},
  {id:"R039",topic:"definition",tags:["WHO","ICD-11"],finding:"WHO ICD-11 recognizes burnout as occupational phenomenon: chronic workplace stress not successfully managed. Exhaustion, cynicism, reduced efficacy.",implication:"Burnout is organizational responsibility, not individual failure.",strength:"strong",cite:"World Health Organization (2019), ICD-11, QD85",year:2019},
  {id:"R040",topic:"recognition",tags:["feedback","motivation"],finding:"Timely, specific positive feedback increases engagement and reduces exhaustion. Optimal positive:corrective ratio ~3:1.",implication:"Impact verification ('Your delegation saved 12 tickets') sustains tool engagement.",strength:"moderate",cite:"Losada & Heaphy (2004), Am Behavioral Scientist, 47(6); Amabile & Kramer (2011), The Progress Principle",year:2011},
  {id:"R041",topic:"workload",tags:["NASA-TLX","measurement"],finding:"NASA-TLX measures six workload dimensions. Most validated subjective workload measure across domains.",implication:"Behavioral drift signals serve as proxy workload measures without adding survey burden.",strength:"strong",cite:"Hart & Staveland (1988), Human Mental Workload, Advances in Psychology, 52, 139–183",year:1988},
  {id:"R042",topic:"measurement",tags:["BAT","four-dimensions"],finding:"BAT adds cognitive and emotional impairment to MBI framework. Cognitive impairment = difficulty concentrating, memory problems.",implication:"Cognitive impairment maps directly to investigation time drift signal.",strength:"strong",cite:"Schaufeli et al. (2020), Int J Environ Res Public Health, 17(24), 9495",year:2020},
];
const KB_VERSION = "2026.03.3";

const EXPECTED_ENTRY_COUNT = 42;

// Integrity self-check at load: warn (don't throw) if the curated KB looks
// truncated or has duplicate ids — catches a botched manual enrichment edit.
(function verifyIntegrity() {
  const ids = RESEARCH_KB.map(e => e.id);
  if (RESEARCH_KB.length !== EXPECTED_ENTRY_COUNT) {
    logger.warn(`research-kb: expected ${EXPECTED_ENTRY_COUNT} entries, found ${RESEARCH_KB.length} (KB v${KB_VERSION})`);
  }
  if (new Set(ids).size !== ids.length) {
    logger.warn(`research-kb: duplicate entry ids detected (KB v${KB_VERSION})`);
  }
})();

// The full KB pool. The burnout-message generator passes this whole set into
// every prompt — the AI may ground a suggestion in any entry, not a subset.
function getAll() {
  return RESEARCH_KB;
}

// Fetch specific entries by R-ref id, preserving KB order.
function getByRefs(refs) {
  const want = new Set(refs || []);
  return RESEARCH_KB.filter((e) => want.has(e.id));
}

// Strict anti-hallucination gate. Extracts every citation-like R-ref token from
// `text` and checks each is within `allowedRefs` (defaults to the whole KB).
// Detection is deliberately lenient (R\d{2,3}) so a malformed ref like "R28" is
// caught and counted as offending rather than slipping through. Returns
// { ok, cited, offending }; the generator rejects the AI output (and marks the
// item AI-unavailable) when ok is false.
const REF_TOKEN = /\bR\d{2,3}\b/g;
function validateCitations(text, allowedRefs) {
  const allowed = new Set(
    allowedRefs && allowedRefs.length ? allowedRefs : RESEARCH_KB.map((e) => e.id)
  );
  const cited = [...new Set(String(text).match(REF_TOKEN) || [])];
  const offending = cited.filter((r) => !allowed.has(r));
  return { ok: offending.length === 0, cited, offending };
}

// ── Optional selectors ─────────────────────────────────────────────────────
// NOT used in the default path (which passes the whole KB). Retained as a
// future token-budget optimization and the seam where K1's embedding-based
// selection will plug in. Simple topic/tag keyword matching for now; falls back
// to the whole KB if a hint set matches nothing.

const SIGNAL_HINTS = {
  investigationTime: ['cognitive_load', 'workload', 'interruptions', 'vigilance', 'triage'],
  dismissRate: ['alert_fatigue', 'vigilance', 'triage'],
  ticketQuality: ['cognitive_load', 'alert_fatigue', 'vigilance', 'micro-breaks'],
  escalationRate: ['cognitive_load', 'soc_burnout', 'triage', 'exhaustion'],
};

const CONDITION_HINTS = {
  team_stressed: ['intervention', 'workload', 'soc_burnout', 'JD-R', 'exhaustion'],
  equity: ['fairness', 'equity', 'procedural-justice'],
  automation: ['automation', 'alert_fatigue', 'triage'],
  one_on_one: ['peer_support', 'engagement', 'social-support', 'informal-support', 'manager'],
  sustained_overcap: ['moral_injury', 'recovery', 'incident_stress', 'moral-distress', 'exhaustion'],
};

function selectByHints(hints) {
  if (!hints || !hints.length) return RESEARCH_KB;
  const h = new Set(hints);
  const hit = RESEARCH_KB.filter(
    (e) => h.has(e.topic) || (e.tags || []).some((t) => h.has(t))
  );
  return hit.length ? hit : RESEARCH_KB;
}

function selectForSignal(signalKey) {
  return selectByHints(SIGNAL_HINTS[signalKey]);
}

function selectForCondition(promptKey) {
  return selectByHints(CONDITION_HINTS[promptKey]);
}

// Drift guard for callers that hold an expected KB_VERSION (e.g. a future
// frontend-sync check). Warns on mismatch; never throws.
function assertKbVersion(expected) {
  if (expected && expected !== KB_VERSION) {
    logger.warn(`research-kb: KB_VERSION mismatch (server ${KB_VERSION}, caller expected ${expected})`);
  }
}

module.exports = {
  KB_VERSION,
  RESEARCH_KB,
  getAll,
  getByRefs,
  validateCitations,
  selectForSignal,
  selectForCondition,
  assertKbVersion,
};

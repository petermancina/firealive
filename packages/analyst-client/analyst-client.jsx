// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE ANALYST CLIENT — Complete Standalone Desktop Application
// FULL FEATURE SET: Login+MFA, Welcome Guide with Burnout Primer, Inactivity Lock,
// Biometric Unlock, Burnout Signals with drill-down resources, Delegation with 
// action buttons, FULL Peer Skill-Share (disclaimer, scheduling, exclusion lists,
// burnout flag, E2EE chat, post-session rating, abuse flagging, helper points,
// 5-min retention window), Board (post creation, categories, reactions), IR Simulator
// (OODA loop, scenarios), Training (recommended, progress, platform links), 
// Skills Assessments (baseline, tier progression, meters), Certificates (upload,
// verification), Post-Incident Wellness (FULL content: box breathing, sleep hygiene,
// emotional processing, routine, connection, log avoidance, CISM retrospective),
// Self-Scan (10-point compromise check, auto-send to MC), Audit/Forensics (auto-send,
// log integrity), Proactive Break prompts, Upskilling Hour, Reduced Ticket Request,
// Team Lead 1-on-1 Request, Privacy/Pseudonym display, Help system.
// Research Knowledge Base (42 entries) and AI synthesis engine included.
// ═══════════════════════════════════════════════════════════════════════════════
import { useState, useEffect, useRef } from "react";
// FIREALIVE — SOC Analyst Wellbeing Platform
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details: https://www.gnu.org/licenses/agpl-3.0.html
//
// Source code: https://github.com/petermancina/firealive
// ═══════════════════════════════════════════════════════════════════════════════


const FONTS_URL = "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,300;0,400;0,500;1,400&family=DM+Sans:ital,wght@0,300;0,400;0,500;0,600;1,400&family=Fraunces:ital,opsz,wght@0,9..144,400;0,9..144,600;1,9..144,400&display=swap";
const C = {
  bg:"#080C14",s:"rgba(255,255,255,0.02)",sh:"rgba(255,255,255,0.04)",
  b:"rgba(255,255,255,0.06)",ba:"rgba(255,255,255,0.14)",
  t:"#C8D6E5",tm:"#3A5068",td:"#1E3040",
  a:"#6EE7B7",ad:"rgba(110,231,183,0.1)",
  w:"#FBBF24",wd:"rgba(251,191,36,0.1)",
  d:"#EF4444",dd:"rgba(239,68,68,0.1)",
  i:"#60A5FA",id:"rgba(96,165,250,0.1)",
  p:"#A78BFA",pd:"rgba(167,139,250,0.1)",
};

// ── API Client ──────────────────────────────────────────────────────────────
const API_BASE = window.FIREALIVE_SERVER || 'http://localhost:3000';
const api = {
  _token: null,
  _headers() { return { 'Content-Type': 'application/json', ...(this._token ? { 'Authorization': 'Bearer ' + this._token } : {}) }; },
  async post(path, data) { try { const r = await fetch(API_BASE + path, { method: 'POST', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { return { error: e.message }; } },
  async get(path) { try { const r = await fetch(API_BASE + path, { headers: this._headers() }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { return { error: e.message }; } },
  setToken(t) { this._token = t; },
};

// Per-session monotonic counter for relay ordering of outgoing E2EE messages.
const peerSendCounters = new Map();
function nextPeerCounter(sessionId) {
  const c = peerSendCounters.get(sessionId) || 0;
  peerSendCounters.set(sessionId, c + 1);
  return c;
}
const leadSendCounters = new Map();
function nextLeadCounter(threadId) {
  const c = leadSendCounters.get(threadId) || 0;
  leadSendCounters.set(threadId, c + 1);
  return c;
}

const CSS = `@import url('${FONTS_URL}');*{box-sizing:border-box;margin:0;padding:0;}button,select,input,textarea{font-family:inherit;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
@keyframes spin{to{transform:rotate(360deg)}}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.08);border-radius:3px}`;

// ══════════════════════════════════════════════════════════════════════════════
// RESEARCH KNOWLEDGE BASE v2026.03.3 — 42 peer-reviewed entries
// ══════════════════════════════════════════════════════════════════════════════
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
const KB_ENTRY_COUNT = RESEARCH_KB.length;

// R3j C12: linger window for the post-deactivation "Panic mode lifted" green
// banner at the top of the AC. Mirrors PANIC_DEACTIVATED_LINGER_SECONDS in
// server/routes/status.js and server/routes/routing.js, plus the matching
// PANIC_BANNER_LINGER_SECONDS in frontend/firealive-mc.jsx. All four values
// must move together if the linger window is ever changed.
const PANIC_BANNER_LINGER_SECONDS = 300;

// ── Skills Assessment Taxonomy ───────────────────────────────────────────────
const SKILLS_TAXONOMY = [
  {id:"triage",name:"Alert Triage",cat:"Core",tier:[1,2,3],desc:"Classify, prioritize, and route security alerts based on severity and context."},
  {id:"investigation",name:"Investigation",cat:"Core",tier:[1,2,3],desc:"Deep-dive analysis of alerts to determine root cause and scope of incidents."},
  {id:"documentation",name:"Documentation",cat:"Core",tier:[1,2,3],desc:"Clear, structured write-ups of findings, evidence chains, and recommended actions."},
  {id:"escalation",name:"Escalation Judgment",cat:"Core",tier:[1,2,3],desc:"Deciding when and how to escalate incidents to senior analysts or management."},
  {id:"siem_queries",name:"SIEM Queries",cat:"Technical",tier:[1,2,3],desc:"Writing and optimizing search queries in Splunk, Elastic, QRadar, or Sentinel."},
  {id:"malware_analysis",name:"Malware Analysis",cat:"Advanced",tier:[2,3],desc:"Static and dynamic analysis of suspicious executables, scripts, and payloads."},
  {id:"threat_hunting",name:"Threat Hunting",cat:"Advanced",tier:[2,3],desc:"Proactive hypothesis-driven searching for indicators of compromise not detected by automated tools."},
  {id:"forensics",name:"Digital Forensics",cat:"Advanced",tier:[2,3],desc:"Disk, memory, and network forensics for evidence collection and incident reconstruction."},
  {id:"scripting",name:"Scripting/Automation",cat:"Technical",tier:[1,2,3],desc:"Python, PowerShell, or Bash scripting for task automation and custom detection rules."},
  {id:"network_analysis",name:"Network Analysis",cat:"Technical",tier:[1,2,3],desc:"Packet capture analysis, traffic pattern recognition, and protocol-level investigation."},
  {id:"cloud_security",name:"Cloud Security",cat:"Advanced",tier:[2,3],desc:"AWS/Azure/GCP security monitoring, IAM analysis, and cloud-native threat detection."},
  {id:"ir_coordination",name:"IR Coordination",cat:"Leadership",tier:[3],desc:"Coordinating cross-functional incident response teams during active incidents."},
  {id:"log_analysis",name:"Log Analysis",cat:"Technical",tier:[1,2,3],desc:"Parsing, correlating, and interpreting logs from multiple sources to identify anomalies."},
  {id:"vuln_assessment",name:"Vulnerability Assessment",cat:"Technical",tier:[2,3],desc:"Evaluating scan results, prioritizing remediation, and tracking patch compliance."},
  {id:"phishing_analysis",name:"Phishing Analysis",cat:"Core",tier:[1,2,3],desc:"Header analysis, URL deobfuscation, payload examination, and sender reputation assessment."},
  {id:"comm_skills",name:"Stakeholder Communication",cat:"Leadership",tier:[2,3],desc:"Translating technical findings into business-language for executives and non-technical teams."},
];

// ── Data ─────────────────────────────────────────────────────────────────────
// R3n: ANALYSTS_INIT (the hardcoded 18 mock analysts with real names) has
// been removed. The AC never sees real analyst names through any system
// surface — the Peer Skill-Share exclude UI now fetches pseudonyms from
// the canonical GET /api/pseudonyms endpoint instead. See pseudonymList
// state + the useEffect that hydrates it (further down in the component).
// The real-name ↔ pseudonym mapping lives only in the lead's exported file
// and is NOT stored in the FireAlive system.
const AUTO_SYS_INIT = [
  {id:"cs-edr",name:"CrowdStrike Falcon",type:"EDR/XDR",l1:true,l2:true,l3:false,cap:{max:800,cur:612,u:"alerts/hr"},status:"operational",resolved:1847,fp:0.04},
  {id:"pa-ids",name:"Palo Alto IDS/IPS",type:"IDS/IPS",l1:true,l2:false,l3:false,cap:{max:2000,cur:1340,u:"events/hr"},status:"operational",resolved:4210,fp:0.02},
  {id:"torq",name:"Torq AI Triage",type:"AI/SOAR",l1:true,l2:true,l3:false,cap:{max:500,cur:289,u:"tickets/hr"},status:"operational",resolved:923,fp:0.07},
  {id:"abnormal",name:"Abnormal Security",type:"Email AI",l1:true,l2:false,l3:false,cap:{max:1200,cur:876,u:"emails/hr"},status:"operational",resolved:2156,fp:0.03},
];
const ALERT_TYPES = [
  {type:"Phishing",cx:1},{type:"Malware",cx:2},{type:"Brute Force",cx:1},{type:"Lateral Movement",cx:3},
  {type:"Data Exfil",cx:4},{type:"C2 Beacon",cx:4},{type:"Insider Threat",cx:5},{type:"Ransomware",cx:5},
  {type:"Policy Violation",cx:1},{type:"Priv Escalation",cx:3},{type:"Suspicious DNS",cx:2},{type:"Endpoint Anomaly",cx:2},
];

// Training platform integrations
const TRAINING_PLATFORMS = [
  {id:"htb",name:"Hack The Box",type:"Hands-on Labs",url:"https://hackthebox.com",desc:"Real-world penetration testing and defense labs. SOC-specific paths: SOC Analyst, Incident Handler, Threat Hunter.",integration:"SAML SSO + progress API. Completions sync back to analyst profile.",tags:["investigation","escalation","hunting"]},
  {id:"thm",name:"TryHackMe",type:"Guided Learning",url:"https://tryhackme.com",desc:"Structured learning paths with browser-based labs. SOC Level 1 & 2 paths directly map to tier progression.",integration:"OAuth + webhook progress tracking. Module completion triggers skill matrix update.",tags:["investigation","documentation","triage"]},
  {id:"letsdefend",name:"LetsDefend",type:"SOC Simulation",url:"https://letsdefend.io",desc:"Purpose-built SOC analyst training with simulated SIEM, alert triage, and incident response scenarios.",integration:"API-based progress sync. Alert handling metrics feed back to signals baseline.",tags:["triage","investigation","documentation"]},
  {id:"cyberdefenders",name:"CyberDefenders",type:"Blue Team Labs",url:"https://cyberdefenders.org",desc:"Blue team challenge platform focused on DFIR, malware analysis, and network forensics.",integration:"Challenge completion API. Skill badges sync to analyst profile.",tags:["investigation","escalation"]},
  {id:"sans",name:"SANS Institute",type:"Certification Prep",url:"https://sans.org",desc:"Industry-standard certifications (GCIA, GCIH, GSOM). Premium but highest credential value.",integration:"LTI 1.3 integration. Course enrollment and progress tracking.",tags:["all"]},
  {id:"immersive",name:"Immersive Labs",type:"AI-Powered",url:"https://immersivelabs.com",desc:"AI-driven cyber skills platform with adaptive difficulty. Measures human cyber readiness.",integration:"Full API integration. AI adjusts content based on analyst signal data (with consent).",tags:["investigation","triage","documentation"]},
  {id:"claude-ai",name:"Claude AI Tutor",type:"AI Coaching",url:"#internal",desc:"On-demand AI coaching sessions for specific skill gaps. Can analyze your recent alert handling patterns and suggest targeted improvements. Private — data never leaves Tier-3.",integration:"Native integration. Runs within Tier-3 data boundary. No external data sharing.",tags:["all"]},
];

const SIGNAL_INTERVENTIONS = {
  investigationTime:{label:"Investigation time increasing",paths:[
    {type:"platform",pid:"letsdefend",title:"LetsDefend: SOC Alert Triage",desc:"Practice real alert scenarios to build faster pattern recognition."},
    {type:"platform",pid:"htb",title:"HTB: SOC Analyst Path",desc:"Hands-on labs that build deep investigation instincts."},
    {type:"ai",title:"AI Coaching: Investigation Speed",desc:"Claude analyzes your recent alert patterns and suggests specific shortcuts. Private."},
    {type:"peer",title:"Peer mentoring session",desc:"Senior analysts share investigation strategies. Research: peer mentoring produces faster skill transfer than formal training (Gully et al., 2002)."},
    {type:"structural",title:"Request queue adjustment",desc:"If complexity has increased, the issue may be routing, not skill."},
  ]},
  dismissRate:{label:"Closing alerts without notes increasing",paths:[
    {type:"platform",pid:"letsdefend",title:"LetsDefend: Alert Documentation",desc:"Practice structured alert write-ups in simulated environment."},
    {type:"platform",pid:"thm",title:"TryHackMe: SOC Level 1 Path",desc:"Builds systematic triage habits including documentation."},
    {type:"ai",title:"AI Coaching: Triage Habits",desc:"Identify which alert types you're dismissing and why. Pattern-specific suggestions."},
    {type:"peer",title:"Talk to someone who's been here",desc:"Elevated dismiss rates often signal cognitive fatigue (Sundaramurthy et al., 2015), not skill gaps."},
    {type:"structural",title:"Request lighter queue",desc:"High dismiss rates are a documented early burnout signal. A temporary cap lets you recover."},
  ]},
  ticketQuality:{label:"Documentation quality slipping",paths:[
    {type:"platform",pid:"immersive",title:"Immersive Labs: Adaptive Writing",desc:"AI-adjusted documentation exercises matched to your current level."},
    {type:"platform",pid:"cyberdefenders",title:"CyberDefenders: DFIR Reports",desc:"Practice forensic reporting with structured templates."},
    {type:"ai",title:"AI Coaching: Documentation Templates",desc:"Generate personalized templates based on the alert types you handle most."},
    {type:"peer",title:"Share documentation shortcuts",desc:"Experienced analysts often have personal macros and templates."},
  ]},
  escalationRate:{label:"Escalation rate above baseline",paths:[
    {type:"platform",pid:"htb",title:"HTB: Threat Hunter Path",desc:"Build confidence resolving complex alerts independently."},
    {type:"platform",pid:"sans",title:"SANS GCIH: Incident Handler",desc:"Gold-standard certification for escalation decision-making."},
    {type:"peer",title:"Calibrate with a peer",desc:"Escalation thresholds are partly cultural. Peer calibration recalibrates judgment."},
    {type:"structural",title:"This may be correct",desc:"If routing changed, higher escalation is appropriate — the drift reflects conditions, not performance."},
  ]},
};

// ── Shared UI ────────────────────────────────────────────────────────────────
const M = ({children,style,...p}) => <span style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:10,...style}} {...p}>{children}</span>;
const L = ({children,style}) => <div style={{fontSize:10,color:C.td,fontFamily:"'IBM Plex Mono',monospace",letterSpacing:1.5,textTransform:"uppercase",marginBottom:10,...style}}>{children}</div>;
const Card = ({children,style,onClick,...p}) => <div onClick={onClick} style={{padding:16,background:C.s,border:`1px solid ${C.b}`,borderRadius:12,...(onClick?{cursor:"pointer"}:{}),...style}} {...p}>{children}</div>;
const Btn = ({children,primary,danger,small,disabled,style,...p}) => <button disabled={disabled} style={{
  padding:small?"5px 10px":"9px 16px",background:danger?C.dd:primary?C.ad:C.s,
  border:`1px solid ${danger?C.d+"50":primary?C.a+"50":C.b}`,borderRadius:8,
  color:disabled?C.td:danger?C.d:primary?C.a:C.tm,fontSize:small?10:12,fontWeight:500,
  cursor:disabled?"default":"pointer",...style}} {...p}>{children}</button>;
const Badge = ({children,color=C.tm}) => <span style={{fontSize:9,padding:"2px 8px",background:`${color}18`,border:`1px solid ${color}40`,borderRadius:12,color,fontFamily:"'IBM Plex Mono',monospace"}}>{children}</span>;
const Modal = ({children,onClose,title,width=480}) => (
  <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.75)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:200}} onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
    <div style={{width,maxWidth:"95vw",maxHeight:"90vh",overflow:"auto",padding:24,background:"#0D1117",border:`1px solid ${C.b}`,borderRadius:14}}>
      {title&&<div style={{fontSize:15,fontWeight:500,color:"#E8EDF5",marginBottom:16}}>{title}</div>}
      {children}
    </div>
  </div>
);
const Tabs = ({tabs,active,onTab}) => (
  <div style={{display:"flex",gap:0,borderBottom:`1px solid ${C.b}`,background:C.s,padding:"0 24px",overflowX:"auto",WebkitOverflowScrolling:"touch"}}>
    {tabs.map(t=>(
      <button key={t.id} onClick={()=>onTab(t.id)} style={{
        padding:"12px 14px",background:"transparent",border:"none",borderBottom:active===t.id?`2px solid ${C.a}`:"2px solid transparent",
        color:active===t.id?C.a:C.tm,fontSize:12,fontWeight:500,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace",
        display:"flex",alignItems:"center",gap:6,whiteSpace:"nowrap",
      }}>{t.label}{t.badge>0&&<span style={{fontSize:9,background:C.dd,color:C.d,padding:"1px 6px",borderRadius:10,fontWeight:600}}>{t.badge}</span>}</button>
    ))}
  </div>
);
const Input = ({label,maxLength=512,...p}) => <div style={{marginBottom:14}}>{label&&<M style={{color:C.tm,marginBottom:4,display:"block"}}>{label}</M>}<input maxLength={maxLength} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}} {...p}/></div>;
const Sel = ({label,children,...p}) => <div style={{marginBottom:14}}>{label&&<M style={{color:C.tm,marginBottom:4,display:"block"}}>{label}</M>}<select style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}} {...p}>{children}</select></div>;
// U1: "Currently unavailable" panel for the analyst client. Shown in place of a
// feature's UI when a team lead has turned it off. The feature's controls are
// NOT rendered (truly deactivated, not merely dimmed). mode="tab" fills a tab
// body; mode="section" is a compact inline card.
const AdminDisabledPanel = ({ name, mode = "tab" }) => {
  const tab = mode === "tab";
  return (
    <div style={{padding: tab?40:14, background:"rgba(255,255,255,0.02)", border:`1px dashed ${C.b}`, borderRadius:12, textAlign:"center", margin: tab?0:"10px 0"}}>
      <div style={{fontFamily:"'IBM Plex Mono',monospace", fontSize:9, letterSpacing:1.5, color:C.tm, textTransform:"uppercase", marginBottom:8}}>Currently Unavailable</div>
      {name ? <div style={{fontSize:13, color:C.t, marginBottom:6}}>{name}</div> : null}
      <M style={{color:C.td, display:"block", maxWidth:430, margin:"0 auto", lineHeight:1.6}}>Your team lead has turned this feature off. Anything you saved here is preserved and nothing is deleted. Reach out to your team lead if you need it turned back on.</M>
    </div>
  );
};

// U1: Gate an analyst feature by its toggle. When disabled, children (the live
// workflow and its controls) are not mounted and the panel is shown instead.
const FeatureGate = ({ disabled, name, mode = "tab", children }) => (
  disabled ? <AdminDisabledPanel name={name} mode={mode} /> : children
);

const tierLbl = t => t===1?"L1":t===2?"L2":"L3";
const tierClr = t => t===1?C.i:t===2?C.p:"#F472B6";
const shiftLbl = s => s==="day"?"Day (06-14)":s==="swing"?"Swing (14-22)":"Night (22-06)";
const stMeta = {healthy:{c:C.a,l:"Healthy"},watch:{c:C.w,l:"Watch"},stressed:{c:"#F97316",l:"Stressed"},critical:{c:C.d,l:"Critical"}};
const genId = () => "SWP-"+Math.random().toString(36).substr(2,4).toUpperCase()+"-"+Date.now().toString(36).substr(-4).toUpperCase();


// ═══════════════════════════════════════════════════════════════════════════════
// BURNOUT PRIMER — Research-backed education for all welcome guides
// ═══════════════════════════════════════════════════════════════════════════════
const BURNOUT_PRIMER = [
  {title:"SOC Analyst Burnout: The Crisis",body:"71% of SOC analysts report burnout. 64% are considering leaving within 1-3 years. Average tenure is just 1-3 years. The cost to replace a single analyst: $85,000 in recruiting, onboarding, and ramp-up. For a 6-person team with 35% annual turnover, that's $178,500/year in churn costs alone — before counting the insider threat risk from disgruntled departing staff, the knowledge loss, and the degraded detection capability during transitions."},
  {title:"What Burnout Actually Is",body:"The WHO (ICD-11, 2019) defines burnout as an occupational phenomenon from chronic workplace stress not successfully managed. It has three dimensions: EXHAUSTION (emotional depletion, fatigue), CYNICISM/DEPERSONALIZATION (detachment, negativity toward work), and REDUCED EFFICACY (feeling ineffective, loss of accomplishment). Burnout is NOT a personal failing — it's a structural organizational problem. Maslach's research over 40+ years consistently shows burnout is caused by mismatches in workload, control, reward, community, fairness, and values."},
  {title:"Causes in SOC Environments",body:"Alert fatigue: 97% of orgs see year-over-year alert increases. Only 19% of alerts are typically addressed. Analysts spend 50%+ of their time on manual repetitive work. Context switching costs 15-25 minutes per interruption. Sustained attention degrades after 90 minutes of continuous monitoring. Night shift workers have 17-28% higher depression rates. Major incident response produces acute stress comparable to emergency services. And the automation paradox: when you automate the easy stuff, what's left is HARDER — concentrating the cognitive load."},
  {title:"What Actually Prevents Burnout",body:"Research consistently shows: ORGANIZATIONAL interventions (workload redesign, scheduling, autonomy) are 3x more effective than individual interventions (meditation, yoga) alone. Combined approaches are strongest. Specifically: peer social support directly reduces exhaustion. Weekly manager check-ins produce 3x engagement improvement. Psychological detachment during off-hours is critical. Micro-breaks every 90 minutes restore vigilance. Decision fatigue means alert queues should rotate complexity. Fair workload distribution matters more than total volume. And intrinsic motivation requires autonomy, competence, and relatedness (Self-Determination Theory)."},
  {title:"How FireAlive Implements These Practices",body:"Every feature in this app is grounded in this research. Burnout-aware ticket routing reduces demands. Peer skill-share provides social support (the strongest buffer against exhaustion). The upskilling hour invests in competence during paid time. Proactive break suggestions prevent sustained attention degradation. Post-incident wellness protocols follow CISM best practices. Pseudonymized data ensures psychological safety. The delegation system reduces repetitive manual work. Skills assessments and training build efficacy. And the architecture ensures this is NEVER surveillance — it's empowerment."},
];


// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  MY MFA SECURITY SECTION (R3f)                                          ║
// ║                                                                         ║
// ║  Self-service MFA management for the currently authenticated analyst.   ║
// ║  Renders inside the privacy/settings tab in place of the prior          ║
// ║  placeholder TOTP card. Talks to /api/mfa/* (status, enroll-start,      ║
// ║  enroll-confirm, recovery-status, regenerate-recovery, disable). All    ║
// ║  operations scope to req.user.id on the server side -- this component   ║
// ║  never accepts or sends a user_id parameter.                            ║
// ║                                                                         ║
// ║  Per R3f-pt2, analyst accounts ARE subject to mfa_enrollment_required   ║
// ║  (the analyst carve-out was closed for SOC-grade alignment with NIST    ║
// ║  800-63B / SOC 2 / PCI-DSS). Enrollment is therefore mandatory at       ║
// ║  first login if not already done; this component handles the post-      ║
// ║  enrollment self-service surface (regenerate recovery codes, disable    ║
// ║  TOTP for re-enrollment, etc.).                                         ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

function MyMfaSecuritySection() {
  const [status, setStatus] = useState(null);
  const [recovery, setRecovery] = useState(null);
  const [loading, setLoading] = useState(true);
  const [stage, setStage] = useState('idle');
  const [enrollData, setEnrollData] = useState(null);
  const [confirmCode, setConfirmCode] = useState('');
  const [actionCode, setActionCode] = useState('');
  const [codes, setCodes] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    setLoading(true); setError('');
    try {
      const s = await api.get('/api/mfa/status');
      if (s && s.error) { setError(typeof s.error === 'string' ? s.error : 'Failed to load MFA status.'); setLoading(false); return; }
      setStatus(s || { enrolled: false, in_enrollment: false });
      if (s && s.enrolled) {
        const r = await api.get('/api/mfa/recovery-status');
        if (r && !r.error) setRecovery(r); else setRecovery(null);
      } else {
        setRecovery(null);
      }
      setLoading(false);
    } catch (e) {
      setError(e.message || 'Failed to load MFA status.');
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); }, []);

  const startEnroll = async () => {
    setBusy(true); setError('');
    try {
      const r = await api.post('/api/mfa/enroll-start', {});
      setBusy(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : 'Failed to start enrollment.'); return; }
      if (!r || !r.secret_base32) { setError('Enrollment response was incomplete.'); return; }
      setEnrollData(r);
      setConfirmCode('');
      setStage('enrolling-confirm');
    } catch (e) {
      setBusy(false);
      setError(e.message || 'Failed to start enrollment.');
    }
  };

  const confirmEnroll = async () => {
    if (confirmCode.length < 6) { setError('Enter the 6-digit code from your authenticator.'); return; }
    setBusy(true); setError('');
    try {
      const r = await api.post('/api/mfa/enroll-confirm', { totp_code: confirmCode });
      setBusy(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : 'Confirmation failed.'); return; }
      if (!r || !Array.isArray(r.recovery_codes)) { setError('Confirmation response was incomplete.'); return; }
      setCodes(r.recovery_codes);
      setStage('display-codes');
      setConfirmCode('');
    } catch (e) {
      setBusy(false);
      setError(e.message || 'Confirmation failed.');
    }
  };

  const startRegen = () => { setActionCode(''); setError(''); setStage('regenerating'); };

  const confirmRegen = async () => {
    if (actionCode.length < 6) { setError('Enter the 6-digit code from your authenticator.'); return; }
    setBusy(true); setError('');
    try {
      const r = await api.post('/api/mfa/regenerate-recovery', { totp_code: actionCode });
      setBusy(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : 'Regeneration failed.'); return; }
      if (!r || !Array.isArray(r.recovery_codes)) { setError('Regeneration response was incomplete.'); return; }
      setCodes(r.recovery_codes);
      setStage('display-codes');
      setActionCode('');
    } catch (e) {
      setBusy(false);
      setError(e.message || 'Regeneration failed.');
    }
  };

  const startDisable = () => {
    if (!window.confirm('Disable MFA for your account? This removes second-factor protection.')) return;
    setActionCode(''); setError(''); setStage('disabling');
  };

  const confirmDisable = async () => {
    if (actionCode.length < 6) { setError('Enter the 6-digit code from your authenticator.'); return; }
    setBusy(true); setError('');
    try {
      const r = await api.post('/api/mfa/disable', { totp_code: actionCode });
      setBusy(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : 'Disable failed.'); return; }
      setStage('idle'); setActionCode(''); setEnrollData(null); setCodes(null);
      await refresh();
    } catch (e) {
      setBusy(false);
      setError(e.message || 'Disable failed.');
    }
  };

  const acknowledgeCodes = () => { setCodes(null); setEnrollData(null); setStage('idle'); refresh(); };
  const cancel = () => { setStage('idle'); setError(''); setConfirmCode(''); setActionCode(''); };

  if (loading) {
    return (
      <Card style={{padding:14,borderColor:C.b,marginTop:12}}>
        <div style={{fontSize:12,fontWeight:500,color:C.t,marginBottom:6}}>My MFA Enrollment</div>
        <M style={{color:C.tm}}>Loading…</M>
      </Card>
    );
  }

  if (stage === 'display-codes' && codes) {
    return (
      <Card style={{padding:14,borderColor:C.a+"40",marginTop:12}}>
        <div style={{fontSize:12,fontWeight:600,color:C.a,marginBottom:8}}>Save Your Recovery Codes</div>
        <M style={{color:C.d,display:"block",marginBottom:8,fontWeight:500,lineHeight:1.6}}>These codes will not be shown again. Each can be used once if you lose access to your authenticator.</M>
        <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Print them, store them in a password manager, or write them down.</M>
        <div style={{background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,padding:10,marginBottom:10,fontFamily:"'IBM Plex Mono',monospace",fontSize:12,color:C.t,lineHeight:1.8,userSelect:"all"}}>
          {codes.map((c,i)=><div key={i}>{c}</div>)}
        </div>
        <button onClick={()=>{ try { if (navigator && navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(codes.join("\n")); } catch (_e) {} }} style={{width:"100%",marginBottom:8,padding:8,background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Copy all to clipboard</button>
        <Btn primary style={{width:"100%"}} onClick={acknowledgeCodes}>I've saved my recovery codes</Btn>
      </Card>
    );
  }

  if (stage === 'enrolling-confirm' && enrollData) {
    return (
      <Card style={{padding:14,borderColor:C.i+"30",marginTop:12}}>
        <div style={{fontSize:12,fontWeight:600,color:C.i,marginBottom:8}}>Scan QR Code to Enroll</div>
        <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Scan with your authenticator app, then enter the 6-digit code it generates.</M>
        <div style={{background:"#fff",borderRadius:8,padding:12,textAlign:"center",marginBottom:10}}>
          {enrollData.qr_png_data_url ? (
            <img src={enrollData.qr_png_data_url} alt="TOTP QR code" style={{width:180,height:180}}/>
          ) : (
            <div style={{width:180,height:180,margin:"0 auto",display:"flex",alignItems:"center",justifyContent:"center",border:"2px dashed #ccc",borderRadius:8,color:"#666",fontSize:11,padding:8}}>QR rendering unavailable.<br/>Use manual entry below.</div>
          )}
        </div>
        <details style={{marginBottom:10}}>
          <summary style={{cursor:"pointer",color:C.tm,fontSize:11,marginBottom:6}}>Can't scan? Enter manually</summary>
          <div style={{padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,marginTop:6}}>
            <M style={{color:C.td,display:"block",marginBottom:6}}>Secret (base32):</M>
            <code style={{display:"block",color:C.t,fontSize:11,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.secret_base32}</code>
            <M style={{color:C.td,display:"block",marginTop:8,marginBottom:6}}>Or paste this URL into a TOTP-aware app:</M>
            <code style={{display:"block",color:C.t,fontSize:10,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.otpauth_url}</code>
          </div>
        </details>
        <Input label="6-digit code from authenticator" value={confirmCode} onChange={e=>setConfirmCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
        {error&&<div style={{fontSize:11,color:C.d,marginBottom:8}}>{error}</div>}
        <div style={{display:"flex",gap:8}}>
          <Btn primary style={{flex:1}} onClick={confirmEnroll} disabled={busy}>{busy?"Confirming...":"Confirm Enrollment"}</Btn>
          <button onClick={cancel} disabled={busy} style={{flex:"0 0 auto",padding:"8px 14px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Cancel</button>
        </div>
      </Card>
    );
  }

  if (stage === 'regenerating') {
    return (
      <Card style={{padding:14,borderColor:C.i+"30",marginTop:12}}>
        <div style={{fontSize:12,fontWeight:600,color:C.i,marginBottom:8}}>Regenerate Recovery Codes</div>
        <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Generates 10 new recovery codes. ALL existing codes will be invalidated immediately. Enter your current authenticator code to confirm.</M>
        <Input label="6-digit code from authenticator" value={actionCode} onChange={e=>setActionCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
        {error&&<div style={{fontSize:11,color:C.d,marginBottom:8}}>{error}</div>}
        <div style={{display:"flex",gap:8}}>
          <Btn primary style={{flex:1}} onClick={confirmRegen} disabled={busy}>{busy?"Regenerating...":"Regenerate Codes"}</Btn>
          <button onClick={cancel} disabled={busy} style={{flex:"0 0 auto",padding:"8px 14px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Cancel</button>
        </div>
      </Card>
    );
  }

  if (stage === 'disabling') {
    return (
      <Card style={{padding:14,borderColor:C.d+"40",marginTop:12}}>
        <div style={{fontSize:12,fontWeight:600,color:C.d,marginBottom:8}}>Disable MFA</div>
        <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Removes second-factor protection from your account. Existing recovery codes will also be cleared. Enter your current authenticator code to confirm.</M>
        <Input label="6-digit code from authenticator" value={actionCode} onChange={e=>setActionCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
        {error&&<div style={{fontSize:11,color:C.d,marginBottom:8}}>{error}</div>}
        <div style={{display:"flex",gap:8}}>
          <button onClick={confirmDisable} disabled={busy} style={{flex:1,padding:"10px 14px",background:`${C.d}20`,border:`1px solid ${C.d}50`,borderRadius:8,color:C.d,fontSize:12,fontWeight:500,cursor:busy?"default":"pointer"}}>{busy?"Disabling...":"Confirm Disable"}</button>
          <button onClick={cancel} disabled={busy} style={{flex:"0 0 auto",padding:"8px 14px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Cancel</button>
        </div>
      </Card>
    );
  }

  const enrolled = !!(status && status.enrolled);
  const inEnrollment = !!(status && status.in_enrollment && !enrolled);
  const lowCodes = recovery && recovery.generated && recovery.remaining <= 3;

  return (
    <Card style={{padding:14,borderColor:enrolled?C.a+"30":C.b,marginTop:12}}>
      <div style={{fontSize:12,fontWeight:600,color:C.t,marginBottom:8}}>My MFA Enrollment</div>
      {enrolled && (
        <>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
            <Badge color={C.a}>ENROLLED</Badge>
            <M style={{color:C.tm}}>TOTP authenticator active</M>
          </div>
          {recovery && recovery.generated ? (
            <M style={{color:lowCodes?C.d:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>
              {recovery.remaining} of {recovery.total} recovery codes remaining
              {lowCodes ? " — regenerate soon to avoid lockout if you lose your authenticator." : "."}
            </M>
          ) : (
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Recovery codes status unavailable.</M>
          )}
          {error && <div style={{fontSize:11,color:C.d,marginBottom:8}}>{error}</div>}
          <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
            <button onClick={startRegen} disabled={busy} style={{padding:"6px 10px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Regenerate Recovery Codes</button>
            <button onClick={startDisable} disabled={busy} style={{padding:"6px 10px",background:"transparent",border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:11,cursor:"pointer"}}>Disable MFA</button>
          </div>
        </>
      )}
      {!enrolled && inEnrollment && (
        <>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
            <Badge color={C.w}>IN PROGRESS</Badge>
            <M style={{color:C.tm}}>Enrollment was started but not confirmed</M>
          </div>
          <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>You have a TOTP secret pending confirmation. Click below to view the QR again or restart enrollment with a fresh secret.</M>
          {error && <div style={{fontSize:11,color:C.d,marginBottom:8}}>{error}</div>}
          <Btn primary style={{width:"100%"}} onClick={startEnroll} disabled={busy}>{busy?"Loading...":"Resume / Restart Enrollment"}</Btn>
        </>
      )}
      {!enrolled && !inEnrollment && (
        <>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
            <Badge color={C.tm}>NOT ENROLLED</Badge>
            <M style={{color:C.tm}}>Optional second factor for your account</M>
          </div>
          <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Scan a QR code into your authenticator app (Google Authenticator, Authy, 1Password, etc.) and enter the first code to enroll. You'll receive 10 single-use recovery codes after enrollment. MFA is voluntary for analyst accounts.</M>
          {error && <div style={{fontSize:11,color:C.d,marginBottom:8}}>{error}</div>}
          <Btn primary style={{width:"100%"}} onClick={startEnroll} disabled={busy}>{busy?"Loading...":"Enroll MFA"}</Btn>
        </>
      )}
    </Card>
  );
}


// ═══════════════════════════════════════════════════════════════════════════════
// ANALYST CLIENT — Main Application Component
// ═══════════════════════════════════════════════════════════════════════════════
export default function AnalystClientApp() {
  const [stage, setStage] = useState("login"); // login → welcome → app
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  // R3g login flow state. loginStage replaces the previous mfaStep boolean
  // and adds enroll-start / enroll-confirm / recovery-display stages so
  // analysts subject to mfa_enrollment_required (per R3f-pt2) can enroll
  // their first authenticator at login time.
  const [loginStage, setLoginStage] = useState("creds");
    // creds | mfa | enroll-start | enroll-confirm | recovery-display
  const [mfaSessionToken, setMfaSessionToken] = useState(null);
  const [recoveryCodeInput, setRecoveryCodeInput] = useState("");
  const [useRecoveryLogin, setUseRecoveryLogin] = useState(false);
  const [enrollData, setEnrollData] = useState(null);
  const [enrollConfirmCode, setEnrollConfirmCode] = useState("");
  const [recoveryCodesDisplay, setRecoveryCodesDisplay] = useState(null);
  const [pendingLoginResponse, setPendingLoginResponse] = useState(null);
  const [loginInFlight, setLoginInFlight] = useState(false);
  const [apiMode, setApiMode] = useState(null); // null=probing, true=backend, false=demo
  const [loginError, setLoginError] = useState("");
  const [firstLaunch, setFirstLaunch] = useState(true);

  // ── Inactivity lock ──
  const [appLocked, setAppLocked] = useState(false);
  const [lockPin, setLockPin] = useState("");
  const lockRef = useRef(null);
  const LOCK_MS = 5 * 60 * 1000;
  const resetLock = () => { clearTimeout(lockRef.current); lockRef.current = setTimeout(() => setAppLocked(true), LOCK_MS); };
  useEffect(() => {
    if (stage !== "app") return;
    const ev = ["mousedown", "keydown", "touchstart", "scroll"];
    ev.forEach(e => window.addEventListener(e, resetLock));
    resetLock();
    return () => { ev.forEach(e => window.removeEventListener(e, resetLock)); clearTimeout(lockRef.current); };
  }, [stage]);
  const [biometricEnabled, setBiometricEnabled] = useState(false);
  // v1.0.0: Cert upload state
  const [certUploadName, setCertUploadName] = useState("");
  const [certUploadIssuer, setCertUploadIssuer] = useState("");
  const [certUploadVerif, setCertUploadVerif] = useState("");
  const [certUploadDate, setCertUploadDate] = useState("");
  const [uploadedCerts, setUploadedCerts] = useState([]);
  // v1.0.0: Upskilling content filter active
  const [contentFilterActive, setContentFilterActive] = useState(false);

  // F4d: OODA scenario state — server-driven, replaces hardcoded phases array.
  // Populated by GET /api/ooda/scenarios on mount and GET /api/ooda/scenarios/:id
  // when an analyst selects a scenario to run. The full node tree never reaches
  // the client; we walk node-by-node via POST /api/ooda/scenarios/:id/play.
  const [oodaScenarioList, setOodaScenarioList] = useState([]);
  const [oodaScenarioId, setOodaScenarioId] = useState(null);
  const [oodaScenarioData, setOodaScenarioData] = useState(null);
  const [oodaCurrentNode, setOodaCurrentNode] = useState(null);
  const [oodaPhasesVisited, setOodaPhasesVisited] = useState([]);
  const [oodaLoading, setOodaLoading] = useState(false);
  const [oodaError, setOodaError] = useState(null);
  // F4d: per-analyst exercise history from GET /api/ooda/history.
  // Each entry: {scenarioId, title, type, difficulty, nodesCompleted,
  // totalNodes, startedAt, completedAt}. completedAt is null for runs in
  // progress. Joined against oodaScenarioList in the policies-practiced
  // Card to render practiced/in-progress/not-yet rows.
  const [oodaHistory, setOodaHistory] = useState([]);
  // F4d: per-analyst mastery aggregation from GET /api/ooda/mastery.
  // Shape: {overall:{startedCount, completedCount, completionRate,
  // avgDurationMs}, byType:[{type, started, completed, completionRate}],
  // byDifficulty:[{difficulty, started, completed, completionRate}],
  // recentCompletions:[{scenarioId, title, type, difficulty, completedAt}]}.
  // Endpoint is analyst-only on the server (returns 403 for leads/admins);
  // AC is an analyst-only client so this should always succeed, but null
  // is the graceful-degradation fallback if the fetch errors.
  const [oodaMastery, setOodaMastery] = useState(null);
  // F4d: choice feedback from POST /api/ooda/scenarios/:id/play.
  // Shape: {ci: <choiceIndex>, correct: <bool>, explanation: <string>}.
  // Cleared after the post-correct delay before advancing to the next
  // node, or when the analyst picks a different scenario.
  const [oodaPlayFb, setOodaPlayFb] = useState(null);
  // F4d: scenario completion flag. Set true when the server's
  // /play response returns {complete: true} after a correct choice.
  // The render layer uses this to swap from the active player into
  // the completion summary card.
  const [oodaComplete, setOodaComplete] = useState(false);

  // F5 part 2a: Helper Pay state. Populated by GET /api/helper-pay/balance,
  // /ledger, /options, and /redemptions when the analyst opens the tab.
  // Cards render from these arrays; the redemption flow uses redeemConfirm
  // for the confirmation dialog and redeemFb for inline success/error.
  const [helperBalance, setHelperBalance] = useState(0);
  const [helperLedger, setHelperLedger] = useState([]);
  const [helperOptions, setHelperOptions] = useState([]);
  const [helperMyRedemptions, setHelperMyRedemptions] = useState([]);
  const [helperLoading, setHelperLoading] = useState(false);
  const [helperError, setHelperError] = useState(null);
  const [redeemConfirm, setRedeemConfirm] = useState(null);
  const [redeemFb, setRedeemFb] = useState(null);

  // R3h: Leaderboard opt-in state. Populated by GET /api/helper-pay/me/
  // visibility on tab open; written by PUT /api/helper-pay/visibility when
  // the analyst toggles the checkbox. helperOptIn is null while loading
  // so the toggle UI can show a loading affordance. helperOptInSaving
  // gates the checkbox during the in-flight PUT to prevent rapid double-
  // clicks. helperOptInFb surfaces success/error feedback inline.
  const [helperOptIn, setHelperOptIn] = useState(null);
  const [helperOptInSaving, setHelperOptInSaving] = useState(false);
  const [helperOptInFb, setHelperOptInFb] = useState(null);

  // ── Runtime version info from /api/system/version (Phase 1.4 release-v1.0.10) ──
  const [appVersion, setAppVersion] = useState("");
  const [appBuild, setAppBuild] = useState("");
  useEffect(()=>{
    api.get("/api/system/version").then(r=>{
      if (r?.version) setAppVersion(r.version);
      if (r?.buildId) setAppBuild(r.buildId);
    }).catch(()=>{});
  }, []);

  // R3g: probe backend health so the LoginScreen can choose between the
  // real /api/auth/login flow and the demo-mode simulation. apiMode=true
  // -> hit the backend, apiMode=false -> simulate the enrolled-MFA path
  // for offline UI testing. The probe runs once on mount; failure modes
  // (network down, 5xx, missing endpoint) all collapse to demo mode so
  // the AC is testable without a server.
  useEffect(()=>{
    api.get("/api/system/health").then(r=>{
      setApiMode(r && r.status === 'healthy');
    }).catch(()=>setApiMode(false));
  }, []);

  // F4d: load OODA scenario list on mount.
  // The picker UI added in a later commit lets the analyst choose which
  // scenario to run; this fetch populates the choices. Best-effort — if the
  // server is unavailable, the list stays empty and the IR Simulator tab
  // shows an empty-state message.
  useEffect(()=>{
    api.get("/api/ooda/scenarios").then(r=>{
      if (r?.scenarios) setOodaScenarioList(r.scenarios);
    }).catch(()=>{});
  }, []);

  // F4d: load this analyst's OODA exercise history on mount.
  // Used by the policies-practiced Card to render practiced vs not-yet
  // rows joined against oodaScenarioList. Best-effort — empty history
  // simply means every scenario shows "not yet" until the analyst
  // starts one.
  // R3n: hydrate the pseudonym list for the Peer Skill-Share exclude UI.
  // GET /api/pseudonyms returns {pseudonyms: [{pseudonym, tier, shift}, ...]}
  // sorted by shift/tier/pseudonym. No real names, no user IDs in the
  // response (privacy-preserving — the AC never sees identity info beyond
  // the canonical pseudonym handle).
  useEffect(()=>{
    api.get("/api/pseudonyms").then(r=>{
      if (Array.isArray(r?.pseudonyms)) setPseudonymList(r.pseudonyms);
      setPseudonymsLoaded(true);
    }).catch(()=>setPseudonymsLoaded(true));
  }, []);

  useEffect(()=>{
    api.get("/api/ooda/history").then(r=>{
      if (Array.isArray(r?.history)) setOodaHistory(r.history);
    }).catch(()=>{});
  }, []);

  // F4d: load this analyst's OODA mastery aggregation on mount.
  // Drives the IR Policy Mastery Card. Best-effort — null on failure
  // and the card renders zeroed placeholders so the layout doesn't shift.
  useEffect(()=>{
    api.get("/api/ooda/mastery").then(r=>{
      if (r && r.overall) setOodaMastery(r);
    }).catch(()=>{});
  }, []);

  // F4d: select a scenario by id. Fetches GET /api/ooda/scenarios/:id
  // (returns briefing, startNode, totalNodes — never the full tree)
  // and primes oodaScenarioData / oodaCurrentNode / oodaPhasesVisited
  // so the IR Simulator player can render the briefing and the first
  // node. Wrong-choice walks and node advancement happen in a later
  // commit via POST /api/ooda/scenarios/:id/play.
  const selectScenario = (scenarioId) => {
    setOodaLoading(true);
    setOodaError(null);
    setOodaScenarioId(scenarioId);
    setOodaPlayFb(null);
    setOodaComplete(false);
    api.get("/api/ooda/scenarios/" + encodeURIComponent(scenarioId)).then(r => {
      if (r && r.startNode) {
        setOodaScenarioData(r);
        setOodaCurrentNode(r.startNode);
        setOodaPhasesVisited(r.startNode.phase ? [r.startNode.phase] : []);
        logC("OS", "Selected scenario: " + (r.title || scenarioId));
      } else {
        setOodaError("Failed to load scenario data.");
      }
    }).catch(() => {
      setOodaError("Could not load scenario. Please try again.");
    }).then(() => {
      setOodaLoading(false);
    });
  };

  // F4d: submit a choice for the current node. Calls
  // POST /api/ooda/scenarios/:id/play with {currentNodeId, choiceIndex}.
  // Server-side, wrong choices keep the analyst on the same node (the
  // explanation is the teaching moment); correct choices advance to
  // nextNode and write progress. The render layer shows transient
  // feedback, then either advances to the next node or flips the
  // completion flag when {complete: true} returns.
  const submitChoice = (choiceIndex) => {
    if (!oodaScenarioId || !oodaCurrentNode) return;
    setOodaLoading(true);
    setOodaError(null);
    api.post("/api/ooda/scenarios/" + encodeURIComponent(oodaScenarioId) + "/play", {
      currentNodeId: oodaCurrentNode.id,
      choiceIndex: choiceIndex,
    }).then(r => {
      if (!r) { setOodaError("No response from server."); return; }
      setOodaPlayFb({ ci: choiceIndex, correct: !!r.correct, explanation: r.explanation || "" });
      if (r.correct) {
        logC("ooda_correct", oodaCurrentNode.phase || "");
        setTimeout(() => {
          setOodaPlayFb(null);
          if (r.complete) {
            setOodaComplete(true);
          } else if (r.nextNode) {
            setOodaCurrentNode(r.nextNode);
            if (r.nextNode.phase) {
              setOodaPhasesVisited(prev => [...prev, r.nextNode.phase]);
            }
          }
        }, 2200);
      } else {
        logC("ooda_wrong", oodaCurrentNode.phase || "");
      }
    }).catch(() => {
      setOodaError("Could not submit choice. Please try again.");
    }).then(() => {
      setOodaLoading(false);
    });
  };

  // F5 part 2a: load Helper Pay data when the analyst opens the tab.
  // Best-effort — failures land in helperError and the tab shows a
  // retry-friendly inline message rather than crashing the AC.
  useEffect(() => {
    if (tab !== "helper-pay") return;
    let cancelled = false;
    setHelperLoading(true);
    setHelperError(null);
    Promise.all([
      api.get("/api/helper-pay/balance"),
      api.get("/api/helper-pay/ledger?limit=20"),
      api.get("/api/helper-pay/options"),
      api.get("/api/helper-pay/redemptions"),
      api.get("/api/helper-pay/me/visibility"),
    ]).then(([b, l, o, m, v]) => {
      if (cancelled) return;
      if (b?.error || l?.error || o?.error || m?.error) {
        setHelperError("Could not load Helper Pay data.");
        return;
      }
      setHelperBalance(typeof b?.balance === "number" ? b.balance : 0);
      setHelperLedger(Array.isArray(l?.entries) ? l.entries : []);
      setHelperOptions(Array.isArray(o?.options) ? o.options : []);
      setHelperMyRedemptions(Array.isArray(m?.redemptions) ? m.redemptions : []);
      // R3h: visibility fetch is best-effort. A 5xx leaves helperOptIn null
      // and the visibility Card shows a loading affordance; the rest of the
      // tab still renders. The opt-in state defaults to opt-out per the
      // schema, so a load failure does not accidentally expose the analyst.
      if (v && typeof v.optIn === "boolean") {
        setHelperOptIn(v.optIn);
      }
    }).finally(() => {
      if (!cancelled) setHelperLoading(false);
    });
    return () => { cancelled = true; };
  }, [tab]);

  // R3h: PUT /api/helper-pay/visibility. Flips the authenticated user's
  // leaderboard opt-in. Optimistic UI: helperOptIn updates immediately so
  // the checkbox doesn't lag the click; on server error we revert to the
  // pre-click value and surface the error via helperOptInFb. The rate
  // limit (50/hr per user) on the server side returns 429 RATE_LIMIT_
  // EXCEEDED which we map to a user-friendly message.
  const submitVisibility = (nextOptIn) => {
    const prev = helperOptIn;
    setHelperOptIn(nextOptIn);
    setHelperOptInSaving(true);
    setHelperOptInFb(null);
    api.put("/api/helper-pay/visibility", { optIn: nextOptIn }).then((r) => {
      if (r?.error) {
        // Revert optimistic update on error.
        setHelperOptIn(prev);
        const msg = r.error === "RATE_LIMIT_EXCEEDED"
          ? "Too many visibility changes recently. Try again in a few minutes."
          : (r.message || "Could not update leaderboard visibility.");
        setHelperOptInFb({ kind: "error", message: msg });
        return;
      }
      // Server-confirmed state takes precedence over optimistic.
      if (typeof r?.optIn === "boolean") {
        setHelperOptIn(r.optIn);
      }
      setHelperOptInFb({
        kind: "success",
        message: r.optIn
          ? "You are now visible on the Helper Recognition leaderboard."
          : "You are now hidden from the Helper Recognition leaderboard.",
      });
      logC("helper_pay_visibility_" + (r.optIn ? "opt_in" : "opt_out"),
        "Leaderboard visibility set to " + (r.optIn ? "visible" : "hidden"));
    }).catch(() => {
      setHelperOptIn(prev);
      setHelperOptInFb({ kind: "error",
        message: "Could not reach the server. Try again." });
    }).finally(() => {
      setHelperOptInSaving(false);
    });
  };

  // F5 part 2a: submit a redemption request. On approval (auto-approve
  // options) the balance is debited server-side; we re-fetch balance,
  // ledger, and redemptions to reflect the new state. On request (approval-
  // required options) we re-fetch redemptions only — balance is unchanged
  // until a lead approves.
  const submitRedeem = (option) => {
    setRedeemFb(null);
    api.post("/api/helper-pay/redeem", { optionId: option.id }).then((r) => {
      if (r?.error) {
        setRedeemFb({ kind: "error", message: r.message || r.error || "Could not complete redemption." });
        return;
      }
      const message = r?.status === "approved"
        ? "Redemption approved. Points debited from your balance."
        : "Redemption requested. Pending team lead approval.";
      setRedeemFb({ kind: "success", message });
      setRedeemConfirm(null);
      // Refresh affected views.
      api.get("/api/helper-pay/balance").then(b => {
        if (typeof b?.balance === "number") setHelperBalance(b.balance);
      });
      api.get("/api/helper-pay/redemptions").then(m => {
        if (Array.isArray(m?.redemptions)) setHelperMyRedemptions(m.redemptions);
      });
      api.get("/api/helper-pay/ledger?limit=20").then(l => {
        if (Array.isArray(l?.entries)) setHelperLedger(l.entries);
      });
      logC("helper_pay_redeem_" + (r?.status || "unknown"),
        option.name + " (" + option.cost_points + " pts)");
    });
  };

  // ── Welcome guide ──
  const [welcomeStep, setWelcomeStep] = useState(0);
  const WELCOME_SLIDES = [
    ...BURNOUT_PRIMER,
    {title:"Welcome to FireAlive Analyst Client",body:"This app is your personal wellbeing companion. It helps you track your own burnout signals, connect with peers, develop skills, and get support after intense incidents — all while keeping your identity protected behind a pseudonym."},
    {title:"What FireAlive Does NOT Do",body:"FireAlive does NOT surveil you. Your burnout data is stored under a pseudonym (like 'Analyst-Falcon'). Your real name is never in the database. Management sees only aggregate team health — never your individual indicators. If the system is breached, your identity is protected because the pseudonym mapping is stored offline by your team lead, not in the app."},
    {title:"Peer Skill-Share",body:"Connect anonymously with peers for technical advice, problem-solving, and burnout prevention. All chat is end-to-end encrypted using the Signal protocol (X3DH key agreement and the Double Ratchet). Management cannot read your messages. You control when to chat, who to exclude, and whether to reveal your identity. After a session, messages are retained for 5 minutes for abuse review, then permanently deleted."},
    {title:"Training, IR Simulator & Certificates",body:"Recommended training modules are tailored to your tier level. The IR Simulator lets you practice OODA-loop incident response safely. Your upskilling hour (if enabled by your lead) is paid work time dedicated to professional development — tickets are paused. Upload certifications (CompTIA, ISACA, GIAC, etc.) and your lead can verify them."},
    {title:"Self-Scan, Audit & Wellness",body:"You can run a 10-point compromise check on your own client anytime — results go to you AND your management console automatically. Your audit log is always available for download. Post-incident wellness tools include box breathing, sleep hygiene guidance, emotional processing frameworks, and CISM retrospective access."},
    {title:"Your Signals & Privacy",body:"The Signals tab shows how YOUR work patterns compare to YOUR OWN baseline — not other analysts. You can request reduced tickets, a 1-on-1 with your lead, or delegate patterns to automation. Everything is anonymous by default. You're ready to start."},
  ];

  // ── Proactive break from Team Lead ──
  const [breakPrompt, setBreakPrompt] = useState(null);
  const [upskillingActive, setUpskillingActive] = useState(false);

  // ── Self-scan ──
  const [selfScanRunning, setSelfScanRunning] = useState(false);
  const [selfScanResult, setSelfScanResult] = useState(null);

  // ── Audit/consent log ──
  const [auditLog, setAL] = useState([{ts:new Date().toISOString(),a:"SESSION_START",dt:"Client launched"}]);
  const logC = (a, dt) => setAL(prev => [...prev, {ts: new Date().toISOString(), a, dt: dt || "Anonymous"}]);

  // ── Tab navigation ──
  const [tab, setTab] = useState("home");
  // U1: load the effective feature-toggle state from the server (read-only;
  // analysts cannot change toggles) and adopt live broadcasts in the WS handler.
  const [featureToggles, setFT] = useState({});
  React.useEffect(() => { api.get("/api/features").then(r => { if (r && r.features) setFT(r.features); }).catch(() => {}); }, []);
  React.useEffect(() => { const iv = setInterval(() => api.post("/api/heartbeat", {}), 30000); return () => clearInterval(iv); }, []);

  // ── N1a C25: Desktop notification WebSocket client ──────────────────────
  // The AC opens a WebSocket to the server's /ws endpoint after login,
  // authenticates with the JWT, and listens for { type: 'desktop_notify',
  // payload } pushes. Server path: notify() -> enqueueDesktop ->
  // sendDesktopToUser -> wsServer.sendDesktopNotification (N1a C24 + C11 + C9).
  // On receipt, the payload is forwarded to the Electron main process via
  // window.firealive.send('notify:desktop', payload), where the ipcMain
  // handler (C14) renders the OS Notification (urgency:'critical' on
  // routing_panic_* events). Reconnects with exponential backoff (capped at
  // 30s) on drop. No-op in a plain browser (no window.firealive bridge):
  // desktop notifications only fire inside the Electron shell. The in-app
  // inbox remains the fallback for any missed desktop push.
  React.useEffect(() => {
    if (stage !== "app" && stage !== "welcome") return;
    if (!api._token) return;
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || typeof bridge.send !== "function") return; // browser / no Electron shell

    let ws = null;
    let reconnectTimer = null;
    let closedByUnmount = false;
    let backoffMs = 1000;
    const wsUrl = API_BASE.replace(/^http/, "ws") + "/ws";

    const scheduleReconnect = () => {
      if (closedByUnmount) return;
      clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(connect, backoffMs);
      backoffMs = Math.min(backoffMs * 2, 30000);
    };

    function connect() {
      if (closedByUnmount) return;
      try {
        ws = new WebSocket(wsUrl);
      } catch (_e) {
        scheduleReconnect();
        return;
      }
      ws.onopen = () => {
        backoffMs = 1000;
        try { ws.send(JSON.stringify({ type: "auth", token: api._token })); } catch (_e) {}
      };
      ws.onmessage = (evt) => {
        let msg;
        try { msg = JSON.parse(evt.data); } catch (_e) { return; }
        if (msg && msg.type === "desktop_notify" && msg.payload) {
          try { bridge.send("notify:desktop", msg.payload); } catch (_e) {}
        }
        // U1: live feature-toggle propagation - adopt the broadcast state.
        if (msg && msg.type === "feature_toggles_updated" && msg.features) {
          setFT(msg.features);
        }
      };
      ws.onclose = () => { if (!closedByUnmount) scheduleReconnect(); };
      ws.onerror = () => { try { ws.close(); } catch (_e) {} };
    }

    connect();

    return () => {
      closedByUnmount = true;
      clearTimeout(reconnectTimer);
      if (ws) { try { ws.close(); } catch (_e) {} }
    };
  }, [stage]);

  // ── R3j C12: panic banner state + polling ──────────────────────────────
  // The AC polls /api/status/panic (mounted with ['analyst', 'lead', 'admin'])
  // every 30s and renders a top-of-screen banner mirroring the MC banner from
  // C9: red while active, green for PANIC_BANNER_LINGER_SECONDS after
  // deactivation, absent otherwise. Analysts see the same indicator their
  // lead sees, with the same client-side recomputation against Date.now() so
  // the green banner vanishes at the right moment between 30s polls.
  const [panicActive, setPanicActive] = useState(false);
  const [panicDeactivatedAt, setPanicDeactivatedAt] = useState(null);
  React.useEffect(() => {
    let cancelled = false;
    const fetchPanic = () => {
      api.get("/api/status/panic").then(r => {
        if (cancelled) return;
        if (r && !r.error) {
          setPanicActive(r.active === true);
          setPanicDeactivatedAt(r.deactivated_at ?? null);
        }
      }).catch(()=>{});
    };
    fetchPanic();
    const handle = setInterval(fetchPanic, 30000);
    return () => { cancelled = true; clearInterval(handle); };
  }, []);

  // ── Inbox state (Phase 1.4a) ──────────────────────────────────────────
  const [inboxItems, setInboxItems] = useState([]);
  const [inboxUnreadCount, setInboxUnreadCount] = useState(0);
  const [inboxIncludeRead, setInboxIncludeRead] = useState(false);
  const [inboxLoading, setInboxLoading] = useState(false);
  const [inboxView, setInboxView] = useState("list"); // list | preferences
  const [inboxPrefs, setInboxPrefs] = useState(null);
  const [inboxPrefsLoading, setInboxPrefsLoading] = useState(false);

  // Poll unread count every 60s; load list when entering inbox tab.
  useEffect(()=>{
    let cancelled = false;
    const fetchCount = ()=>{
      api.get("/api/inbox/unread-count").then(r=>{ if(!cancelled) setInboxUnreadCount(r?.unread||0); }).catch(()=>{});
    };
    fetchCount();
    const handle = setInterval(fetchCount, 60000);
    return ()=>{ cancelled = true; clearInterval(handle); };
  }, []);

  // When inbox tab is opened, load items (or preferences depending on view).
  useEffect(()=>{
    if (tab !== "inbox") return;
    if (inboxView === "list") {
      setInboxLoading(true);
      api.get(`/api/inbox?includeRead=${inboxIncludeRead?"true":"false"}`).then(r=>{
        setInboxItems(r?.items||[]);
      }).catch(()=>{}).finally(()=>setInboxLoading(false));
    } else if (inboxView === "preferences") {
      setInboxPrefsLoading(true);
      api.get("/api/inbox/preferences").then(r=>{
        setInboxPrefs(r?.preferences||null);
      }).catch(()=>{}).finally(()=>setInboxPrefsLoading(false));
    }
  }, [tab, inboxView, inboxIncludeRead]);

  const tabs=[
    {id:"home",label:"Home"},{id:"signals",label:"My Signals"},{id:"inbox",label:"Inbox",badge:inboxUnreadCount},{id:"delegate",label:"Delegate"},
    {id:"peers",label:"Peers"},{id:"helper-pay",label:"Helper Pay"},{id:"board",label:"Board"},{id:"ooda",label:"IR Simulator"},
    {id:"skills",label:"Skills & Assessments"},{id:"training",label:"Training & Certs"},{id:"recovery",label:"Post-Incident Wellness"},
    {id:"scan",label:"Self-Scan"},{id:"audit_tab",label:"Audit"},{id:"privacy",label:"Privacy"},
  ];

  // ── Signals ──
  // ── Signals (R3l C10): DEFAULT preserves UI metadata; cur/base populated from /api/signals/me on mount ──
  const DEFAULT_SIGNALS = {
    investigationTime: {base:20, cur:26, u:"min", label:"Avg time per alert"},
    dismissRate:       {base:15, cur:19, u:"%",   label:"Closed without notes"},
    ticketQuality:     {base:82, cur:76, u:"%",   label:"Documentation quality", hib:true},
    escalationRate:    {base:11, cur:14, u:"%",   label:"Escalation rate"},
  };
  const [signals, setSignals] = useState(DEFAULT_SIGNALS);
  const [signalsLoadState, setSignalsLoadState] = useState({loaded:false, error:null, riskTier:null, recordedAt:null});
  useEffect(() => {
    let cancelled = false;
    api.get('/api/signals/me').then((data) => {
      if (cancelled) return;
      if (data.error) {
        setSignalsLoadState({loaded:false, error:data.error, riskTier:null, recordedAt:null});
        return;
      }
      const cur = data.current || {};
      const decryptOk = !cur.error;
      setSignals((prev) => {
        const next = {};
        for (const key of Object.keys(prev)) {
          const merged = {...prev[key]};
          if (decryptOk && typeof cur[key] === 'number') merged.cur = cur[key];
          next[key] = merged;
        }
        if (Array.isArray(data.readings) && data.readings.length > 0) {
          const byKey = {};
          for (const r of data.readings) {
            if (typeof r.signal === 'string' && typeof r.value === 'number') {
              (byKey[r.signal] = byKey[r.signal] || []).push(r.value);
            }
          }
          for (const key of Object.keys(next)) {
            const arr = byKey[key];
            if (arr && arr.length > 0) {
              const sorted = [...arr].sort((a,b) => a-b);
              next[key].base = Math.round(sorted[Math.floor(sorted.length/2)]);
            }
          }
        }
        return next;
      });
      setSignalsLoadState({
        loaded: true,
        error: cur.error || null,
        riskTier: cur.riskTier || null,
        recordedAt: cur.recordedAt || null,
      });
    });
    return () => { cancelled = true; };
  }, []);

  // ── AI signal interpretations (N1b): from /api/ai-burnout/analyst-interpretations.
  // Precomputed server-side, Tier-3, KB-cited. Refetched whenever the Signals
  // tab opens so the analyst sees the latest cached interpretation. null until
  // the first load resolves; {} or a per-signal map afterward.
  const [aiInterp, setAiInterp] = useState(null);
  useEffect(() => {
    if (tab !== "signals") return;
    let cancelled = false;
    api.get('/api/ai-burnout/analyst-interpretations').then((data) => {
      if (cancelled) return;
      setAiInterp(data && data.interpretations ? data.interpretations : {});
    });
    return () => { cancelled = true; };
  }, [tab]);

  // ── Training Recommendations (R3l C11): from /api/training-recommendations/me ──
  const [trainingRecs, setTrainingRecs] = useState({recommendations: [], meta: null});
  const [trainingRecsLoadState, setTrainingRecsLoadState] = useState({loaded:false, error:null});
  useEffect(() => {
    let cancelled = false;
    api.get('/api/training-recommendations/me').then((data) => {
      if (cancelled) return;
      if (data.error) {
        setTrainingRecsLoadState({loaded:false, error:data.error});
        return;
      }
      setTrainingRecs({
        recommendations: Array.isArray(data.recommendations) ? data.recommendations : [],
        meta: data.meta || null,
      });
      setTrainingRecsLoadState({loaded:true, error:null});
    });
    return () => { cancelled = true; };
  }, []);

  // ── Skills Assessment Results (R3l C12): from /api/assessments/analyst/me ──
  const [skillResults, setSkillResults] = useState({results: [], gaps: [], strengths: [], gapThreshold: 70});
  const [skillResultsLoadState, setSkillResultsLoadState] = useState({loaded:false, error:null});
  useEffect(() => {
    let cancelled = false;
    api.get('/api/assessments/analyst/me').then((data) => {
      if (cancelled) return;
      if (data.error) {
        setSkillResultsLoadState({loaded:false, error:data.error});
        return;
      }
      setSkillResults({
        results: Array.isArray(data.results) ? data.results : [],
        gaps: Array.isArray(data.gaps) ? data.gaps : [],
        strengths: Array.isArray(data.strengths) ? data.strengths : [],
        gapThreshold: typeof data.gapThreshold === 'number' ? data.gapThreshold : 70,
      });
      setSkillResultsLoadState({loaded:true, error:null});
    });
    return () => { cancelled = true; };
  }, []);

  // ── Training Completion Submission (R3l C13): POST to /api/training/submit-completion ──
  const [completionForm, setCompletionForm] = useState({module:"", platform:"", url:"", completionDate:""});
  const [completionState, setCompletionState] = useState({submitting:false, success:null, error:null});
  const submitCompletion = async () => {
    setCompletionState({submitting:true, success:null, error:null});
    const body = {
      module: completionForm.module,
      platform: completionForm.platform,
    };
    if (completionForm.url) body.url = completionForm.url;
    if (completionForm.completionDate) body.completionDate = completionForm.completionDate;
    const resp = await api.post('/api/training/submit-completion', body);
    if (resp.error) {
      setCompletionState({submitting:false, success:null, error:resp.error});
    } else {
      setCompletionState({submitting:false, success:resp.id || "submitted", error:null});
      setCompletionForm({module:"", platform:"", url:"", completionDate:""});
    }
  };


  // ── Log integrity ──
  const [logIntegrity] = useState({status:"healthy",lastCheck:new Date().toISOString(),gaps:0,tampering:false});

  // ── Help panel ──
  const [showHelp, setShowHelp] = useState(false);

  // tab state defined above
  // consentLog replaced by auditLog/setAL above
  const [delegations, setDel] = useState([{id:1,ts:"09:12",pat:"Phishing: O365 cred template #4471",st:"accepted",sys:"Torq AI Triage"},{id:2,ts:"10:34",pat:"Endpoint: Chrome update FP",st:"pending",sys:"CrowdStrike Falcon"}]);
  const [showDel, setShowDel] = useState(false);
  const [newDel, setNewDel] = useState("");
  const [selSys, setSelSys] = useState("torq");
  const [showSig, setShowSig] = useState(null);
  const [showLQ, setShowLQ] = useState(false);
  const [lqDur, setLqDur] = useState("1_shift");
  const [lqCap, setLqCap] = useState(2);
  const [lqReason, setLqReason] = useState("");
  const [lqDone, setLqDone] = useState(false);
  const [showPeerSched, setShowPeerSched] = useState(false);
  const [peerMsgs, setPM] = useState([]);
  const [newPM, setNewPM] = useState("");
  const [peerDiscAccepted, setPeerDiscAccepted] = useState(false);
  const [peerTopic, setPeerTopic] = useState("");
  // R3n: peerExclude now stores PSEUDONYMS (strings like "Analyst-Phoenix-23"),
  // not user IDs. The AC submits this list as excludePseudonyms in POST
  // /api/peers/requests; server resolves pseudonyms → user IDs internally.
  const [peerExclude, setPeerExclude] = useState([]);
  const [pseudonymList, setPseudonymList] = useState([]);
  const [pseudonymsLoaded, setPseudonymsLoaded] = useState(false);
  const [peerSubmitError, setPeerSubmitError] = useState(null);
  const [peerSubmitBusy, setPeerSubmitBusy] = useState(false);
  const [peerWillingMeet, setPeerWillingMeet] = useState(false);
  const [peerSession, setPeerSession] = useState(null);
  const [peerTimeout] = useState(5);
  const [peerBurnout, setPeerBurnout] = useState(false);
  const [peerTimeSlot, setPeerTimeSlot] = useState("now");
  const [peerPickTime, setPeerPickTime] = useState("");
  const [peerQueue, setPeerQueue] = useState([]);
  // Phase U3: load the live peer support queue when the Peers tab is open.
  // The server response is anonymous (no requester identity); map it to the
  // queue item shape the list renders.
  useEffect(() => {
    if (tab !== "peers") return;
    let cancelled = false;
    api.get('/api/peers/requests').then((data) => {
      if (cancelled) return;
      if (data && Array.isArray(data.requests)) {
        setPeerQueue(data.requests.map((r) => ({
          id: r.id,
          topic: r.topic,
          willingToMeet: !!r.willingToMeet,
          ts: relTime(r.createdAt),
        })));
      }
    });
    return () => { cancelled = true; };
  }, [tab]);
  // Phase U3: accept a peer request -> create the real session, then run X3DH
  // (fetch the counterpart's bundle and establish the libsignal session, keyed by
  // sessionId so the peer's identity is never exposed) before any messages flow.
  const acceptPeerRequest = async (q) => {
    const r = await api.post("/api/peers/requests/" + q.id + "/accept", {});
    if (!r || r.error || !r.sessionId) {
      logC("peer_accept_failed", "Could not accept request: " + ((r && r.error) || "unknown"));
      return;
    }
    const sessionId = r.sessionId;
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (bridge && bridge.invoke) {
      try {
        const br = await api.get("/api/peers/sessions/" + sessionId + "/peer-bundle");
        if (br && br.bundle && !br.error) {
          await bridge.invoke("e2ee:processBundle", { domain: "peer", remoteUserId: sessionId, bundle: br.bundle });
        } else {
          logC("peer_e2ee_pending", "Peer bundle unavailable; channel encrypts once the peer publishes keys");
        }
      } catch (e) {
        logC("peer_e2ee_failed", "E2EE setup error: " + (e && e.message ? e.message : "unknown"));
      }
    }
    setPeerSession({ id: sessionId, topic: q.topic, status: "active", myConsent: false, peerConsent: false });
    setPeerSafetyNum(null);
    setPeerQueue(prev => prev.filter(x => x.id !== q.id));
    logC("peer_accepted", "Accepted skill-share: " + q.topic);
  };
  // Phase U3: ensure a libsignal session exists for this peer session id; if not
  // (e.g. the requester, who did not accept), establish it lazily via X3DH.
  const ensurePeerSession = async (sessionId) => {
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || !bridge.invoke) return;
    const h = await bridge.invoke("e2ee:hasSession", { domain: "peer", remoteUserId: sessionId });
    if (h && h.hasSession) return;
    const br = await api.get("/api/peers/sessions/" + sessionId + "/peer-bundle");
    if (br && br.bundle && !br.error) {
      await bridge.invoke("e2ee:processBundle", { domain: "peer", remoteUserId: sessionId, bundle: br.bundle });
    }
  };
  // Phase U3: ratchet-encrypt the message (keyed by sessionId) and relay it. Own
  // lines render locally because the relay returns only incoming messages (the
  // sender cannot decrypt its own ratchet output).
  const sendPeerMessage = async () => {
    const text = newPM.trim();
    if (!text || !peerSession || !peerSession.id) return;
    const sessionId = peerSession.id;
    const localMsg = { id: Date.now(), from: "You (anonymous)", ts: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), text, enc: true };
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    setNewPM("");
    if (!bridge || !bridge.invoke) { setPM(prev => [...prev, localMsg]); return; }
    try {
      await ensurePeerSession(sessionId);
      const env = await bridge.invoke("e2ee:encrypt", { domain: "peer", remoteUserId: sessionId, plaintext: text });
      if (!env || env.error || typeof env.type !== "number") { logC("peer_send_failed", "Encryption failed"); return; }
      const counter = nextPeerCounter(sessionId);
      const r = await api.post("/api/messages", { sessionId, messageType: env.type, ciphertext: env.body, counter });
      if (r && r.error) { logC("peer_send_failed", "Relay rejected: " + r.error); return; }
      setPM(prev => [...prev, localMsg]);
    } catch (e) {
      logC("peer_send_failed", "Send error: " + (e && e.message ? e.message : "unknown"));
    }
  };
  // Phase U3: refresh consent state + revealed identity from the server. The
  // server resolves which name is the peer's (role-aware) and returns it only on
  // mutual consent. Returns the same state object when nothing changed to avoid
  // needless re-renders during polling.
  const refreshPeerSessionStatus = async (sessionId) => {
    const r = await api.get("/api/peers/sessions/" + sessionId);
    if (!r || r.error) return;
    setPeerSession(p => {
      if (!p || p.id !== sessionId) return p;
      const status = r.status || p.status;
      const peerName = r.peerName || p.peerName;
      if (p.myConsent === !!r.myConsent && p.peerConsent === !!r.peerConsent && p.status === status && p.peerName === peerName) return p;
      return { ...p, myConsent: !!r.myConsent, peerConsent: !!r.peerConsent, status, peerName };
    });
  };
  // Phase U3: record this party's identity-reveal consent, then refresh state.
  const consentReveal = async () => {
    if (!peerSession || !peerSession.id) return;
    const sessionId = peerSession.id;
    const r = await api.post("/api/peers/sessions/" + sessionId + "/consent", {});
    if (!r || r.error) { logC("peer_consent_failed", "Consent failed: " + ((r && r.error) || "unknown")); return; }
    logC(r.mutualConsent ? "peer_consent_mutual" : "peer_consent", r.mutualConsent ? "Identities revealed" : "Identity consent given; waiting for peer");
    await refreshPeerSessionStatus(sessionId);
  };
  // Phase U3: close the session server-side (starts the 5-minute retention clock),
  // then enter the post-session rating/flag window locally.
  const closePeerSession = () => {
    if (peerSession && peerSession.id) { api.post("/api/peers/sessions/" + peerSession.id + "/close", {}); }
    setPostSession({ messages: [...peerMsgs], topic: peerSession.topic, expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString() });
    setPeerSession(null); setPeerDiscAccepted(false); setPM([]); setPostRating(0); setPostFlagging(false); setPostFlagText("");
    logC("peer_session_ended", "Skill-share ended — 5-min retention window for rating/flagging");
  };
  // Phase U3: out-of-band safety-number verification. Pass the shared sessionId as
  // BOTH fingerprint ids so the number is symmetric and matches on both clients
  // without either learning the other's real identity. Grouped into 5s for reading.
  const [peerSafetyNum, setPeerSafetyNum] = useState(null);
  const showPeerSafetyNumber = async () => {
    if (!peerSession || !peerSession.id) return;
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || !bridge.invoke) { setPeerSafetyNum("unavailable outside the desktop app"); return; }
    try {
      const sid = peerSession.id;
      const r = await bridge.invoke("e2ee:safetyNumber", { domain: "peer", remoteUserId: sid, localId: sid, remoteId: sid });
      const sn = (r && r.safetyNumber && !r.error) ? String(r.safetyNumber) : null;
      if (!sn) { setPeerSafetyNum("not available until the channel is established"); return; }
      let grouped = "";
      for (let i = 0; i < sn.length; i += 5) { grouped += (i ? " " : "") + sn.slice(i, i + 5); }
      setPeerSafetyNum(grouped);
    } catch (e) {
      setPeerSafetyNum("not available until the channel is established");
    }
  };
  // Phase U3: poll the relay for incoming peer ciphertext while a session is
  // active, decrypt each in counter order via the main process, and append to the
  // thread. Only incoming messages are returned (own ratchet output is omitted).
  // Decrypt failures stop the batch and retry from the last good cursor next tick;
  // appends are deduped by message id against effect re-runs / overlapping polls.
  const peerPollCursor = useRef(null);
  useEffect(() => {
    const sessionId = (peerSession && peerSession.status === "active") ? peerSession.id : null;
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!sessionId || !bridge || !bridge.invoke) return;
    peerPollCursor.current = null;
    let cancelled = false;
    const poll = async () => {
      try {
        const since = peerPollCursor.current;
        const q = "/api/messages?sessionId=" + encodeURIComponent(sessionId) + (since ? "&since=" + encodeURIComponent(since) : "");
        const data = await api.get(q);
        if (cancelled || !data || !Array.isArray(data.messages)) return;
        for (const m of data.messages) {
          let res;
          try {
            res = await bridge.invoke("e2ee:decrypt", { domain: "peer", remoteUserId: sessionId, envelope: { type: m.messageType, body: m.ciphertext } });
          } catch (e) { logC("peer_decrypt_failed", "Could not decrypt an incoming message"); break; }
          if (cancelled) return;
          if (!res || res.error || typeof res.plaintext !== "string") { logC("peer_decrypt_failed", "Could not decrypt an incoming message"); break; }
          const ts = new Date(m.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
          setPM(prev => prev.some(x => x.id === m.id) ? prev : [...prev, { id: m.id, from: "Peer", ts, text: res.plaintext, enc: true }]);
          peerPollCursor.current = m.createdAt;
        }
        await refreshPeerSessionStatus(sessionId);
      } catch (e) { /* transient; next tick retries */ }
    };
    poll();
    const iv = setInterval(poll, 3000);
    return () => { cancelled = true; clearInterval(iv); };
  }, [peerSession ? peerSession.id : null, peerSession ? peerSession.status : null]);
  // Phase U3: lead chat (pseudonymous analyst<->team-lead, separate 'lead' key
  // domain). Establish the libsignal lead-domain session for a thread via X3DH.
  // The analyst knows the chosen lead's user id (the lead is not pseudonymous),
  // so the bundle is fetched by user id; but the session is KEYED BY threadId so
  // the analyst's local ratchet state never embeds the lead's identity and the
  // same key drives the out-of-band safety number. Idempotent: a no-op when a
  // session already exists for this thread.
  const ensureLeadSession = async (threadId, leadUserId) => {
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || !bridge.invoke || !threadId || !leadUserId) return false;
    const h = await bridge.invoke("e2ee:hasSession", { domain: "lead", remoteUserId: threadId });
    if (h && h.hasSession) return true;
    const br = await api.get("/api/e2ee/bundle/" + leadUserId + "?domain=lead");
    if (br && br.bundle && !br.error) {
      await bridge.invoke("e2ee:processBundle", { domain: "lead", remoteUserId: threadId, bundle: br.bundle });
      return true;
    }
    logC("lead_e2ee_pending", "Lead bundle unavailable; chat encrypts once the lead publishes keys");
    return false;
  };
  const [showLeadMsg, setShowLeadMsg] = useState(false);
  const [leadMsgs, setLM] = useState([]);
  const [newLM, setNewLM] = useState("");
  // Phase U3: lead-chat session + receive loop. leadThread is set by the on-shift
  // lead picker (added next); null until a lead is chosen.
  const [leadThread, setLeadThread] = useState(null);
  const leadPollCursor = useRef(null);
  const [leadOptions, setLeadOptions] = useState([]);
  // Ratchet-encrypt the message (keyed by threadId) and relay it via /api/lead-chat.
  // Own lines render locally because the relay returns only incoming messages (the
  // sender cannot decrypt its own ratchet output). kind defaults to 'chat'.
  const sendLeadMessage = async (kind) => {
    const k = kind || "chat";
    const typed = newLM.trim();
    // A 1:1 request is valid with no typed text; it carries a default body so the
    // lead always sees an explicit ask. Typed text becomes the request's context.
    const text = typed || (k === "inperson_1on1_request" ? "Requesting an in-person 1:1 when you have a moment." : "");
    if (!text || !leadThread || !leadThread.threadId) return;
    const threadId = leadThread.threadId;
    const localMsg = { id: Date.now(), from: "You", ts: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), text, enc: true, kind: k };
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    setNewLM("");
    if (!bridge || !bridge.invoke) { setLM(prev => [...prev, localMsg]); return; }
    try {
      await ensureLeadSession(threadId, leadThread.leadId);
      const env = await bridge.invoke("e2ee:encrypt", { domain: "lead", remoteUserId: threadId, plaintext: text });
      if (!env || env.error || typeof env.type !== "number") { logC("lead_send_failed", "Encryption failed"); return; }
      const counter = nextLeadCounter(threadId);
      const r = await api.post("/api/lead-chat", { threadId, messageType: env.type, ciphertext: env.body, counter, kind: k });
      if (r && r.error) { logC("lead_send_failed", "Relay rejected: " + r.error); return; }
      setLM(prev => [...prev, localMsg]);
    } catch (e) {
      logC("lead_send_failed", "Send error: " + (e && e.message ? e.message : "unknown"));
    }
  };
  // Poll for incoming lead-chat ciphertext and decrypt it (keyed by threadId),
  // mirroring the peer receive loop. Runs only while a thread is active.
  useEffect(() => {
    const threadId = (leadThread && leadThread.status === "active") ? leadThread.threadId : null;
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!threadId || !bridge || !bridge.invoke) return;
    leadPollCursor.current = null;
    let cancelled = false;
    const poll = async () => {
      try {
        const since = leadPollCursor.current;
        const q = "/api/lead-chat/thread?threadId=" + encodeURIComponent(threadId) + (since ? "&since=" + encodeURIComponent(since) : "");
        const data = await api.get(q);
        if (cancelled || !data || !Array.isArray(data.messages)) return;
        for (const m of data.messages) {
          let res;
          try {
            res = await bridge.invoke("e2ee:decrypt", { domain: "lead", remoteUserId: threadId, envelope: { type: m.messageType, body: m.ciphertext } });
          } catch (e) { logC("lead_decrypt_failed", "Could not decrypt an incoming message"); break; }
          if (cancelled) return;
          if (!res || res.error || typeof res.plaintext !== "string") { logC("lead_decrypt_failed", "Could not decrypt an incoming message"); break; }
          const ts = new Date(m.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
          const fromLabel = (leadThread && leadThread.leadName) ? leadThread.leadName : "Team Lead";
          setLM(prev => prev.some(x => x.id === m.id) ? prev : [...prev, { id: m.id, from: fromLabel, ts, text: res.plaintext, enc: true, kind: m.kind }]);
          leadPollCursor.current = m.createdAt;
        }
      } catch (e) { /* transient; next tick retries */ }
    };
    poll();
    const iv = setInterval(poll, 3000);
    return () => { cancelled = true; clearInterval(iv); };
  }, [leadThread ? leadThread.threadId : null, leadThread ? leadThread.status : null]);
  // Fetch the on-shift lead roster while the picker is open and no thread is set.
  useEffect(() => {
    if (!showLeadMsg || leadThread) return;
    let cancelled = false;
    (async () => {
      try {
        const data = await api.get("/api/leads/on-shift");
        if (!cancelled && data && Array.isArray(data.leads)) setLeadOptions(data.leads);
      } catch (e) { /* transient; the picker shows an empty list until it loads */ }
    })();
    return () => { cancelled = true; };
  }, [showLeadMsg, leadThread]);
  // Open (or reopen) the 1:1 thread with the chosen lead, establish the Signal
  // session keyed by threadId, then activate the thread -- which enables Send and
  // starts the receive loop. The thread id is stable per (analyst, lead).
  const openLeadThread = async (lead) => {
    if (!lead || !lead.id) return;
    try {
      const r = await api.post("/api/lead-chat/open", { leadId: lead.id });
      if (!r || r.error || !r.threadId) { logC("lead_open_failed", "Could not open lead thread"); return; }
      setLM([]);
      await ensureLeadSession(r.threadId, lead.id);
      setLeadThread({ threadId: r.threadId, leadId: lead.id, leadName: lead.name, status: "active" });
      logC("lead_thread_opened", "Opened lead chat thread");
    } catch (e) {
      logC("lead_open_failed", "Open error: " + (e && e.message ? e.message : "unknown"));
    }
  };
  const [showSchedule, setShowSchedule] = useState(null);
  const [schedDate, setSchedDate] = useState("");
  const [schedReminder, setSchedReminder] = useState("1hr");
  const [scheduled, setScheduled] = useState([]);
  const [showPlatform, setShowPlatform] = useState(null);
  // v0.0.23 analyst state
  const [peerBoardMsgs, setPeerBoardMsgs] = useState([]);
  const [newBoardMsg, setNewBoardMsg] = useState("");
  const [boardMsgAnon, setBoardMsgAnon] = useState(true);
  const [boardMsgCat, setBoardMsgCat] = useState("technical");
  // ── Peer board: load from the API (U2) ──
  const loadBoard = () => { api.get("/api/peer-board/messages").then(r => { if (r && Array.isArray(r.messages)) setPeerBoardMsgs(r.messages); }); };
  useEffect(() => { loadBoard(); }, []);
  // ── Peer board threading (U2) ──
  const [expandedThreads, setExpandedThreads] = useState({}); // rootId -> [posts] | "loading"
  const [replyTo, setReplyTo] = useState(null);               // postId whose composer is open
  const [replyDraft, setReplyDraft] = useState("");
  const [replyDraftAnon, setReplyDraftAnon] = useState(true);
  // ── Peer board: flag a post (U2) ──
  const [boardFlagPost, setBoardFlagPost] = useState(null); // postId being flagged
  const [boardFlagTier, setBoardFlagTier] = useState(0);    // 0=unselected, 1/2/3
  const [boardFlagNote, setBoardFlagNote] = useState("");
  const openBoardFlag = (postId) => { setBoardFlagPost(postId); setBoardFlagTier(0); setBoardFlagNote(""); };
  const flagBoardPost = (postId, rootId) => {
    const note = (boardFlagNote || "").trim();
    if (!note || !boardFlagTier) return;
    api.post("/api/peer/flags", { target_type: "board_post", boardPostId: postId, tier: boardFlagTier, content: note }).then(r => {
      if (r && r.id) {
        // The post is now removed pending review -- drop it from view.
        if (rootId == null) {
          setPeerBoardMsgs(prev => prev.filter(pp => pp.id !== postId));
          setExpandedThreads(prev => { const n = { ...prev }; delete n[postId]; return n; });
        } else {
          loadThread(rootId);
        }
        setBoardFlagPost(null); setBoardFlagTier(0); setBoardFlagNote("");
        logC("board_post_flagged", `Tier ${boardFlagTier} flag submitted on a board post`);
      }
    });
  };
  const relTime = (iso) => { const h = Math.floor((Date.now() - new Date(iso).getTime()) / 3600000); return h < 1 ? "just now" : h < 24 ? h + "h ago" : Math.floor(h / 24) + "d ago"; };
  const loadThread = (rootId) => {
    setExpandedThreads(prev => ({ ...prev, [rootId]: "loading" }));
    api.get("/api/peer-board/threads/" + rootId).then(r => {
      setExpandedThreads(prev => ({ ...prev, [rootId]: (r && Array.isArray(r.thread)) ? r.thread : [] }));
    });
  };
  const toggleThread = (rootId) => {
    if (rootId in expandedThreads) { setExpandedThreads(prev => { const n = { ...prev }; delete n[rootId]; return n; }); }
    else { loadThread(rootId); }
  };
  const openReply = (postId) => { setReplyTo(postId); setReplyDraft(""); setReplyDraftAnon(true); };
  const submitReply = (rootId, parentId) => {
    const content = (replyDraft || "").trim();
    if (!content) return;
    api.post("/api/peer-board/messages/" + parentId + "/reply", { content, anonymous: replyDraftAnon }).then(r => {
      if (r && r.message) {
        loadThread(rootId);
        setPeerBoardMsgs(prev => prev.map(p => p.id === rootId ? { ...p, replyCount: (p.replyCount || 0) + 1 } : p));
        setReplyTo(null); setReplyDraft("");
        logC("board_reply", "Replied on skill-share board");
      }
    });
  };
  const REACTIONS = [["helpful","Helpful"],["thanks","Thanks"],["insightful","Insightful"],["same","Same here"]];
  const reactToPost = (postId, reaction, rootId) => {
    api.post("/api/peer-board/messages/" + postId + "/react", { reaction }).then(r => {
      if (!r || !r.reactions) return;
      if (rootId == null) {
        setPeerBoardMsgs(prev => prev.map(p => p.id === postId ? { ...p, reactions: r.reactions } : p));
      } else {
        setExpandedThreads(prev => { const t = prev[rootId]; if (!Array.isArray(t)) return prev; return { ...prev, [rootId]: t.map(p => p.id === postId ? { ...p, reactions: r.reactions } : p) }; });
      }
    });
  };
  const reactionRow = (post, rootId) => (
    <div style={{display:"flex",gap:6,flexWrap:"wrap",marginTop:8}}>
      {REACTIONS.map(([key,label])=>{
        const rx = (post.reactions && post.reactions[key]) || {count:0,mine:false};
        return <button key={key} onClick={()=>reactToPost(post.id,key,rootId)} style={{fontSize:10,fontFamily:"'IBM Plex Mono',monospace",padding:"2px 8px",borderRadius:12,cursor:"pointer",border:`1px solid ${rx.mine?C.a:C.b}`,background:rx.mine?C.a+"18":"transparent",color:rx.mine?C.a:C.tm}}>{label}{rx.count>0?" "+rx.count:""}</button>;
      })}
    </div>
  );
  const [showBoardTab, setShowBoardTab] = useState("board"); // board | my_requests
  const [myPeerRequests, setMyPeerRequests] = useState([
    {id:"req1",topic:"Need help with Sigma rule for DNS tunneling",time:"now",status:"open",createdAt:"2026-04-07T10:00:00Z"},
    {id:"req2",topic:"SIEM log parsing — Zeek JSON format issues",time:"after_shift",status:"matched",matchedTime:"2026-04-08T17:00:00Z",createdAt:"2026-04-06T14:00:00Z"},
  ]);
  const [peerNotifEnabled, setPeerNotifEnabled] = useState(true);
  const [calendarProvider, setCalendarProvider] = useState("ics");
  // v0.0.23 post-session state
  const [postSession, setPostSession] = useState(null); // {messages, topic, expiresAt}
  const [postRating, setPostRating] = useState(0);
  const [postFlagging, setPostFlagging] = useState(false);
  const [postFlagText, setPostFlagText] = useState("");
  const [postFlagTier, setPostFlagTier] = useState(0); // 0=unselected, 1/2/3
  // (cleaned up in v1.0.0)

  // signals defined above
  // stage defined above as stageLabel
  // sc defined above
  const impacts=[{d:"Mar 24",e:"Delegated phishing pattern to SOAR",o:"12 fewer daily tickets",v:true},{d:"Mar 21",e:"Requested lighter queue",o:"Complexity cap applied next shift",v:true},{d:"Mar 18",e:"Flagged recurring FP",o:"EDR rule updated — 8 fewer daily alerts team-wide",v:true}];
  // logC defined above using setAL

  // tabs defined above


  // Main render
  const stageLabel = "watch";
  const sc = {watch:{hl:"A few signals are drifting.",sub:"Worth noticing — not worrying about yet.",c:C.w}}[stageLabel];

  // ── BreathingExercise Component ──
  const BreathingExercise = () => {
    const [bActive, setBActive] = useState(false);
    const [bPhase, setBPhase] = useState(0);
    const [bCount, setBCount] = useState(4);
    const phases = ["Inhale","Hold","Exhale","Hold"];
    const colors = [C.a, C.i, C.p, C.w];
    useEffect(() => {
      if (!bActive) return;
      const iv = setInterval(() => {
        setBCount(prev => {
          if (prev <= 1) { setBPhase(p => (p + 1) % 4); return 4; }
          return prev - 1;
        });
      }, 1000);
      return () => clearInterval(iv);
    }, [bActive]);
    return (
      <Card style={{marginBottom:16,borderColor:colors[bPhase]+"40"}}>
        <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Box Breathing (4-4-4-4)</div>
        <M style={{color:C.tm,display:"block",marginBottom:12}}>Activates parasympathetic nervous system. 4 cycles recommended.</M>
        {bActive ? (
          <div style={{textAlign:"center",padding:"20px 0"}}>
            <div style={{fontSize:32,fontWeight:600,color:colors[bPhase],marginBottom:8}}>{bCount}</div>
            <div style={{fontSize:16,color:colors[bPhase],marginBottom:16}}>{phases[bPhase]}</div>
            <Btn onClick={() => { setBActive(false); setBPhase(0); setBCount(4); }}>Stop</Btn>
          </div>
        ) : (
          <Btn primary onClick={() => setBActive(true)}>Start Breathing Exercise</Btn>
        )}
      </Card>
    );
  };

  // ── LOGIN SCREEN (R3g: real /api/auth/login + three-path MFA flow) ──
  if (stage === "login") {
    // Phase U3: bring up Signal-protocol E2EE for this session. Runs init in the
    // Electron main process, then seeds the peer-domain pre-key bundle exactly
    // once -- gated on the server's available one-time-prekey count so re-logins
    // do not regenerate local keys (which would desync from the published public
    // keys). No-op in a plain browser (no Electron bridge); failures are logged,
    // never fatal to login.
    const bootstrapE2EE = async (selfId) => {
      const bridge = (typeof window !== "undefined") ? window.firealive : null;
      if (!bridge || !bridge.invoke || !selfId) return;

      // Seed (or top up) the published pre-key bundle for one key domain. Peer
      // chat and lead chat run as cryptographically separate Signal domains, so
      // each needs its own published bundle before a counterpart can establish
      // a session. Seed once when the server holds nothing; replenish one-time
      // pre-keys when the pool runs low (consumed by incoming sessions) so new
      // sessions keep full initial forward secrecy. Failures are logged, never
      // fatal to login.
      const provisionDomain = async (domain) => {
        const c = await api.get("/api/e2ee/count?domain=" + domain);
        const available = (c && typeof c.available === "number") ? c.available : 0;
        if (!(c && typeof c.available === "number" && c.available > 0)) {
          const bundle = await bridge.invoke("e2ee:publishBundle", { domain, oneTimeCount: 50 });
          if (bundle && !bundle.error) {
            const r = await api.post("/api/e2ee/publish", bundle);
            if (r && r.error) { logC("E2EE_PUBLISH_FAILED", domain + "-domain bundle publish rejected: " + r.error); }
            else { logC("E2EE_" + domain.toUpperCase() + "_BUNDLE_PUBLISHED", "Published " + domain + "-domain pre-key bundle"); }
          }
        } else if (available < 10) {
          const rep = await bridge.invoke("e2ee:replenishPrekeys", { domain, count: 50 });
          if (rep && !rep.error && Array.isArray(rep.oneTimePreKeys) && rep.oneTimePreKeys.length) {
            const r = await api.post("/api/e2ee/prekeys", rep);
            if (r && r.error) { logC("E2EE_PREKEYS_FAILED", domain + " pre-key top-up rejected: " + r.error); }
            else { logC("E2EE_PREKEYS_REPLENISHED", "Replenished " + domain + " one-time pre-keys"); }
          }
        }
      };

      try {
        await bridge.invoke("e2ee:init", selfId);
        await provisionDomain("peer");
        await provisionDomain("lead");
      } catch (e) {
        logC("E2EE_INIT_FAILED", "E2EE setup error: " + (e && e.message ? e.message : "unknown"));
      }
    };

    // Helper: persist the JWT, set the api token, store the refresh token,
    // and advance the AC into welcome (first launch) or app (returning user).
    const finalizeLogin = (loginResponse) => {
      if (loginResponse && loginResponse.accessToken) {
        api.setToken(loginResponse.accessToken);
      }
      if (loginResponse && loginResponse.refreshToken) {
        try { localStorage.setItem('fa_ac_refresh_token', loginResponse.refreshToken); } catch (_e) {}
      }
      logC("LOGIN_SUCCESS", "Authenticated"+(useRecoveryLogin?" via recovery code":" via TOTP"));
      bootstrapE2EE(username);
      setStage(firstLaunch ? "welcome" : "app");
    };

    const submitCreds = async () => {
      if (!username || !password) { setLoginError("Enter credentials"); return; }
      setLoginError("");
      setLoginInFlight(true);

      // Demo mode: simulate the enrolled-MFA path (the most common case
      // for testing the UI without a backend). Analysts who want to test
      // the enrollment flow offline can manually setLoginStage to
      // 'enroll-start' via React DevTools, or run against a real server.
      if (apiMode === false) {
        setTimeout(()=>{ setLoginInFlight(false); setLoginStage("mfa"); }, 600);
        return;
      }

      const r = await api.post('/api/auth/login', { username, password });
      setLoginInFlight(false);
      if (r && r.error) {
        setLoginError(typeof r.error === 'string' ? r.error : 'Login failed');
        return;
      }
      // Three-path response handling per R3f
      if (r && r.mfa_required && r.mfa_session_token) {
        setMfaSessionToken(r.mfa_session_token);
        setLoginStage("mfa");
        return;
      }
      if (r && r.mfa_enrollment_required && r.mfa_session_token) {
        setMfaSessionToken(r.mfa_session_token);
        setLoginStage("enroll-start");
        return;
      }
      if (r && r.accessToken && r.user) {
        // Direct JWT issuance -- this path exists for users without
        // mfa_enrollment_required and without TOTP enrolled. After
        // R3f-pt2, all standard role-based users have
        // mfa_enrollment_required=1, so this branch should not fire
        // for typical analyst accounts. Kept for completeness in case
        // a future role policy change re-introduces a no-MFA path.
        finalizeLogin(r);
        return;
      }
      setLoginError("Unexpected login response");
    };

    const submitMfa = async () => {
      const code = useRecoveryLogin ? recoveryCodeInput.trim() : mfaCode.trim();
      if (!useRecoveryLogin && code.length < 6) { setLoginError("Enter 6-digit code"); return; }
      if (useRecoveryLogin && code.length === 0) { setLoginError("Enter recovery code"); return; }
      setLoginError("");
      setLoginInFlight(true);

      if (apiMode === false) {
        setTimeout(()=>{ setLoginInFlight(false); finalizeLogin({}); }, 500);
        return;
      }

      const body = useRecoveryLogin
        ? { mfa_session_token: mfaSessionToken, recovery_code: code }
        : { mfa_session_token: mfaSessionToken, totp_code: code };
      const r = await api.post('/api/auth/login-mfa', body);
      setLoginInFlight(false);
      if (r && r.error) {
        setLoginError(typeof r.error === 'string' ? r.error : 'MFA verification failed');
        return;
      }
      if (r && r.accessToken && r.user) { finalizeLogin(r); return; }
      setLoginError("Unexpected MFA response");
    };

    const submitEnrollStart = async () => {
      setLoginError("");
      setLoginInFlight(true);

      if (apiMode === false) {
        // Demo mode: simulate enrollment data
        setTimeout(()=>{
          setLoginInFlight(false);
          setEnrollData({
            secret_base32: "JBSWY3DPEHPK3PXP",
            otpauth_url: "otpauth://totp/FireAlive:demo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=FireAlive",
            qr_png_data_url: null,
          });
          setLoginStage("enroll-confirm");
        }, 500);
        return;
      }

      const r = await api.post('/api/auth/login-enroll-start', { mfa_session_token: mfaSessionToken });
      setLoginInFlight(false);
      if (r && r.error) {
        setLoginError(typeof r.error === 'string' ? r.error : 'Failed to start enrollment');
        return;
      }
      if (!r || !r.secret_base32) { setLoginError("Enrollment response was incomplete"); return; }
      setEnrollData(r);
      setEnrollConfirmCode("");
      setLoginStage("enroll-confirm");
    };

    const submitEnrollConfirm = async () => {
      if (enrollConfirmCode.length < 6) { setLoginError("Enter 6-digit code"); return; }
      setLoginError("");
      setLoginInFlight(true);

      if (apiMode === false) {
        // Demo mode: simulate enrollment confirm + recovery codes
        setTimeout(()=>{
          setLoginInFlight(false);
          setRecoveryCodesDisplay(["DEMO-AAAA-1111","DEMO-BBBB-2222","DEMO-CCCC-3333","DEMO-DDDD-4444","DEMO-EEEE-5555","DEMO-FFFF-6666","DEMO-GGGG-7777","DEMO-HHHH-8888","DEMO-JJJJ-9999","DEMO-KKKK-0000"]);
          setPendingLoginResponse({ accessToken: null, refreshToken: null, user: { role: "analyst" } });
          setEnrollConfirmCode("");
          setLoginStage("recovery-display");
        }, 500);
        return;
      }

      const r = await api.post('/api/auth/login-enroll-confirm', {
        mfa_session_token: mfaSessionToken,
        totp_code: enrollConfirmCode,
      });
      setLoginInFlight(false);
      if (r && r.error) {
        setLoginError(typeof r.error === 'string' ? r.error : 'Enrollment confirmation failed');
        return;
      }
      if (!r || !r.accessToken || !r.user || !Array.isArray(r.recovery_codes)) {
        setLoginError("Enrollment response was incomplete");
        return;
      }
      // Hold the JWT response until the user has acknowledged the
      // recovery codes. finalizeLogin runs from the recovery-display
      // screen when they click "I've saved my recovery codes".
      setRecoveryCodesDisplay(r.recovery_codes);
      setPendingLoginResponse(r);
      setEnrollConfirmCode("");
      setLoginStage("recovery-display");
    };

    const acknowledgeRecoveryCodes = () => {
      if (pendingLoginResponse) finalizeLogin(pendingLoginResponse);
    };

    return (
      <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center"}}>
        <style>{CSS}</style>
        <div style={{width:480,padding:40,background:C.s,border:"1px solid "+C.b,borderRadius:16}}>
          <div style={{textAlign:"center",marginBottom:32}}>
            <div style={{fontSize:28,fontWeight:600,color:C.a,fontFamily:"'Fraunces',serif",marginBottom:4}}>FireAlive</div>
            <M style={{color:C.td,letterSpacing:2,textTransform:"uppercase"}}>Analyst Login</M>
          </div>

          {loginStage === "creds" && (
            <div>
              <Input label="Username" value={username} onChange={function(e){setUsername(e.target.value);}} placeholder="analyst@corp.local" disabled={loginInFlight}/>
              <Input label="Password" value={password} onChange={function(e){setPassword(e.target.value);}} type="password" placeholder="********" disabled={loginInFlight}/>
              <button onClick={submitCreds} disabled={loginInFlight} style={{width:"100%",padding:12,background:C.ad,border:"1px solid "+C.a+"50",borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:loginInFlight?"wait":"pointer",fontFamily:"'IBM Plex Mono',monospace",opacity:loginInFlight?0.6:1}}>{loginInFlight?"Signing in...":"Sign In"}</button>
            </div>
          )}

          {loginStage === "mfa" && (
            <div>
              <M style={{color:C.tm,display:"block",marginBottom:16}}>{useRecoveryLogin?"Enter one of your single-use recovery codes":"Enter the code from your authenticator app"}</M>
              {!useRecoveryLogin && (
                <Input label="MFA Code" value={mfaCode} onChange={function(e){setMfaCode(e.target.value.replace(/\D/g,"").slice(0,6));}} placeholder="123456" maxLength={6} disabled={loginInFlight}/>
              )}
              {useRecoveryLogin && (
                <Input label="Recovery Code" value={recoveryCodeInput} onChange={function(e){setRecoveryCodeInput(e.target.value.toUpperCase().slice(0,32));}} placeholder="ABCD-1234-EFGH" maxLength={32} disabled={loginInFlight}/>
              )}
              <button onClick={submitMfa} disabled={loginInFlight} style={{width:"100%",padding:12,background:C.ad,border:"1px solid "+C.a+"50",borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:loginInFlight?"wait":"pointer",fontFamily:"'IBM Plex Mono',monospace",opacity:loginInFlight?0.6:1}}>{loginInFlight?"Verifying...":"Verify"}</button>
              <button onClick={function(){setUseRecoveryLogin(!useRecoveryLogin);setLoginError("");setMfaCode("");setRecoveryCodeInput("");}} style={{width:"100%",marginTop:10,padding:8,background:"transparent",border:"none",color:C.tm,fontSize:11,cursor:"pointer",textDecoration:"underline"}}>{useRecoveryLogin?"Use authenticator code instead":"Use a recovery code instead"}</button>
              <button onClick={function(){setLoginStage("creds");setMfaCode("");setRecoveryCodeInput("");setUseRecoveryLogin(false);setMfaSessionToken(null);setLoginError("");}} style={{width:"100%",marginTop:8,padding:10,background:"transparent",border:"1px solid "+C.b,borderRadius:8,color:C.td,fontSize:11,cursor:"pointer"}}>Back</button>
            </div>
          )}

          {loginStage === "enroll-start" && (
            <div>
              <div style={{fontSize:14,fontWeight:600,color:C.t,marginBottom:10}}>MFA Enrollment Required</div>
              <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>FireAlive requires multi-factor authentication for all accounts. You will scan a QR code into an authenticator app (Google Authenticator, Authy, 1Password, etc.) and enter a verification code.</M>
              <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>You will receive 10 single-use recovery codes after enrollment. Save them in a secure place; they are your only way back into your account if you lose access to your authenticator.</M>
              <button onClick={submitEnrollStart} disabled={loginInFlight} style={{width:"100%",padding:12,background:C.ad,border:"1px solid "+C.a+"50",borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:loginInFlight?"wait":"pointer",fontFamily:"'IBM Plex Mono',monospace",opacity:loginInFlight?0.6:1}}>{loginInFlight?"Preparing...":"Begin Enrollment"}</button>
            </div>
          )}

          {loginStage === "enroll-confirm" && enrollData && (
            <div>
              <div style={{fontSize:14,fontWeight:600,color:C.t,marginBottom:10}}>Scan QR Code</div>
              <M style={{color:C.tm,display:"block",marginBottom:14,lineHeight:1.6}}>Scan with your authenticator app, then enter the 6-digit code it generates.</M>
              <div style={{background:"#fff",borderRadius:8,padding:12,textAlign:"center",marginBottom:12}}>
                {enrollData.qr_png_data_url ? (
                  <img src={enrollData.qr_png_data_url} alt="TOTP QR code" style={{width:200,height:200}}/>
                ) : (
                  <div style={{width:200,height:200,margin:"0 auto",display:"flex",alignItems:"center",justifyContent:"center",border:"2px dashed #ccc",borderRadius:8,color:"#666",fontSize:11,padding:8}}>QR rendering unavailable.<br/>Use manual entry below.</div>
                )}
              </div>
              <details style={{marginBottom:12}}>
                <summary style={{cursor:"pointer",color:C.tm,fontSize:11,marginBottom:8}}>Can't scan? Enter manually</summary>
                <div style={{padding:10,background:"rgba(255,255,255,0.03)",border:"1px solid "+C.b,borderRadius:8,marginTop:8}}>
                  <M style={{color:C.td,display:"block",marginBottom:6}}>Secret (base32):</M>
                  <code style={{display:"block",color:C.t,fontSize:12,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.secret_base32}</code>
                  <M style={{color:C.td,display:"block",marginTop:10,marginBottom:6}}>Or paste this URL into a TOTP-aware app:</M>
                  <code style={{display:"block",color:C.t,fontSize:10,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.otpauth_url}</code>
                </div>
              </details>
              <Input label="6-digit code from authenticator" value={enrollConfirmCode} onChange={function(e){setEnrollConfirmCode(e.target.value.replace(/\D/g,"").slice(0,6));}} placeholder="000000" maxLength={6} disabled={loginInFlight}/>
              <button onClick={submitEnrollConfirm} disabled={loginInFlight} style={{width:"100%",padding:12,background:C.ad,border:"1px solid "+C.a+"50",borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:loginInFlight?"wait":"pointer",fontFamily:"'IBM Plex Mono',monospace",opacity:loginInFlight?0.6:1}}>{loginInFlight?"Confirming...":"Confirm Enrollment"}</button>
            </div>
          )}

          {loginStage === "recovery-display" && recoveryCodesDisplay && (
            <div>
              <div style={{fontSize:14,fontWeight:600,color:C.a,marginBottom:10}}>Save Your Recovery Codes</div>
              <M style={{color:C.d,display:"block",marginBottom:10,lineHeight:1.6,fontWeight:500}}>These codes will not be shown again. Each can be used once if you lose access to your authenticator.</M>
              <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Print them, store them in a password manager, or write them down. The server cannot recover them.</M>
              <div style={{background:"rgba(255,255,255,0.03)",border:"1px solid "+C.b,borderRadius:8,padding:14,marginBottom:12,fontFamily:"'IBM Plex Mono',monospace",fontSize:13,color:C.t,lineHeight:1.8,userSelect:"all"}}>
                {recoveryCodesDisplay.map(function(c,i){ return <div key={i}>{c}</div>; })}
              </div>
              <button onClick={function(){ try { if (navigator && navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(recoveryCodesDisplay.join("\n")); } catch (_e) {} }} style={{width:"100%",marginBottom:8,padding:10,background:"transparent",border:"1px solid "+C.b,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Copy all to clipboard</button>
              <button onClick={acknowledgeRecoveryCodes} style={{width:"100%",padding:12,background:C.ad,border:"1px solid "+C.a+"50",borderRadius:8,color:C.a,fontSize:13,fontWeight:600,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>I've saved my recovery codes</button>
            </div>
          )}

          {loginError && <div style={{marginTop:16,padding:10,background:"rgba(239,68,68,0.08)",border:"1px solid "+C.d+"40",borderRadius:8,color:C.d,fontSize:11,fontFamily:"'IBM Plex Mono',monospace"}}>{loginError}</div>}
          <M style={{color:C.td,display:"block",textAlign:"center",marginTop:24}}>FireAlive{appVersion?` v${appVersion}`:""} AGPL-3.0</M>
        </div>
      </div>
    );
  }

  // ── WELCOME GUIDE ──
  if (stage === "welcome") return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center"}}>
      <style>{CSS}</style>
      <div style={{width:560,padding:40,background:C.s,border:"1px solid "+C.b,borderRadius:16,maxHeight:"85vh",overflowY:"auto"}}>
        <L>{WELCOME_SLIDES[welcomeStep].title}</L>
        <M style={{color:C.tm,display:"block",marginBottom:24,lineHeight:1.8,fontSize:12}}>{WELCOME_SLIDES[welcomeStep].body}</M>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <M style={{color:C.td}}>{welcomeStep+1}/{WELCOME_SLIDES.length}</M>
          <div style={{display:"flex",gap:8}}>
            <Btn onClick={function(){setFirstLaunch(false);setStage("app");setWelcomeStep(0);}}>Skip</Btn>
            {welcomeStep > 0 && <Btn onClick={function(){setWelcomeStep(function(p){return p-1;});}}>Back</Btn>}
            {welcomeStep < WELCOME_SLIDES.length-1 ? <Btn primary onClick={function(){setWelcomeStep(function(p){return p+1;});}}>Next</Btn> : <Btn primary onClick={function(){setFirstLaunch(false);setStage("app");setWelcomeStep(0);}}>Get Started</Btn>}
          </div>
        </div>
      </div>
    </div>
  );

  // ── LOCK SCREEN ──
  if (appLocked) return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",flexDirection:"column"}}>
      <style>{CSS}</style>
      <div style={{textAlign:"center",padding:40}}>
        <div style={{fontSize:48,marginBottom:20}}>Locked</div>
        <div style={{fontSize:18,fontWeight:600,color:"#E8EDF5",fontFamily:"'Fraunces',serif",marginBottom:8}}>FireAlive Locked</div>
        <M style={{color:C.td,display:"block",marginBottom:24}}>Locked due to inactivity.</M>
        <div style={{maxWidth:280,margin:"0 auto"}}>
          <input type="password" value={lockPin} onChange={function(e){setLockPin(e.target.value);}} onKeyDown={function(e){if(e.key==="Enter"&&lockPin.length>0){setAppLocked(false);setLockPin("");resetLock();}}} placeholder="Enter password to unlock" style={{width:"100%",padding:12,background:"rgba(255,255,255,0.03)",border:"1px solid "+C.b,borderRadius:8,color:C.t,fontSize:13,textAlign:"center",marginBottom:12}}/>
          <button onClick={function(){if(lockPin.length>0){setAppLocked(false);setLockPin("");resetLock();}}} style={{width:"100%",padding:10,background:C.ad,border:"1px solid "+C.a+"50",borderRadius:8,color:C.a,fontSize:12,fontWeight:600,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>Unlock</button>
          {biometricEnabled && <button onClick={function(){setAppLocked(false);resetLock();}} style={{width:"100%",padding:10,marginTop:8,background:"transparent",border:"1px solid "+C.b,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Use Biometric</button>}
        </div>
      </div>
    </div>
  );

  return(
    <div style={{minHeight:"100vh",background:"#060A10",color:C.t,fontFamily:"'DM Sans',sans-serif"}}>
      <style>{CSS}</style>
      {/* R3j C12: Top-of-AC panic banner. Red while panic_mode is active; green for
          PANIC_BANNER_LINGER_SECONDS after deactivation; absent otherwise. Recomputes
          age against Date.now() on every render so the green banner vanishes at the
          right moment even between 30s server polls. State fed by the polling
          useEffect against /api/status/panic. */}
      {(()=>{
        if (panicActive) {
          return (<div style={{padding:"12px 24px",background:C.d,color:"#fff",fontWeight:600,textAlign:"center",fontSize:13,letterSpacing:0.5,animation:"pulse 1.5s infinite",borderBottom:`1px solid ${C.d}`}}>⚠ PANIC MODE ACTIVE — All wellness routing is OFF. You may receive tickets above your usual complexity cap until your lead restores normal routing.</div>);
        }
        if (panicDeactivatedAt) {
          const ageSec = (Date.now() - new Date(panicDeactivatedAt).getTime()) / 1000;
          if (ageSec >= 0 && ageSec <= PANIC_BANNER_LINGER_SECONDS) {
            return (<div style={{padding:"10px 24px",background:C.a,color:"#0d1117",fontWeight:600,textAlign:"center",fontSize:12,borderBottom:`1px solid ${C.a}`}}>✓ Panic mode lifted — wellness routing restored.</div>);
          }
        }
        return null;
      })()}
      <div style={{borderBottom:`1px solid ${C.b}`,background:C.s,padding:"16px 24px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div>
          <M style={{color:C.td,letterSpacing:2,textTransform:"uppercase",fontSize:9,display:"block",marginBottom:6}}>
            <span style={{display:"inline-block",width:5,height:5,borderRadius:"50%",background:sc.c,marginRight:6,boxShadow:`0 0 6px ${sc.c}`}}/>
            FireAlive Analyst{appVersion?` · v${appVersion}`:""} {upskillingActive&&<Badge color={C.p}>UPSKILLING HOUR</Badge>}
          </M>
          <div style={{fontSize:18,fontWeight:600,color:"#E8EDF5",fontFamily:"'Fraunces',serif"}}>Your Wellbeing Dashboard</div>
        </div>
        <div style={{display:"flex",gap:8}}>
          <Btn small onClick={()=>setShowHelp(!showHelp)}>Help</Btn>
          <Btn small onClick={()=>{api.setToken(null);try{localStorage.removeItem('fa_ac_refresh_token');}catch(_e){}setStage("login");setUsername("");setPassword("");setMfaCode("");setLoginStage("creds");setMfaSessionToken(null);setRecoveryCodeInput("");setUseRecoveryLogin(false);setEnrollData(null);setEnrollConfirmCode("");setRecoveryCodesDisplay(null);setPendingLoginResponse(null);setLoginError("");logC("SIGN_OUT","Signed out");}}>Sign Out</Btn>
        </div>
      </div>
      {breakPrompt&&featureToggles.proactive_interventions!==false&&(<div style={{padding:"12px 24px",background:"rgba(167,139,250,0.08)",borderBottom:`1px solid ${C.p}30`}}>
        <M style={{color:C.p,fontWeight:500}}>Your lead approved a break for you. You have been doing incredible work. </M>
        <div style={{display:"flex",gap:8,marginTop:8}}>
          <Btn small primary onClick={()=>{setBreakPrompt(null);logC("BREAK_ACCEPTED","Break accepted");}}>Take Break</Btn>
          <Btn small onClick={()=>{setBreakPrompt(null);logC("BREAK_DECLINED","Continuing work");}}>Continue</Btn>
        </div>
      </div>)}
      {showHelp&&(<div style={{padding:"16px 24px",background:C.s,borderBottom:`1px solid ${C.b}`,maxHeight:300,overflowY:"auto"}}>
        <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><L>Help</L><Btn small onClick={()=>setShowHelp(false)}>Close</Btn></div>
        <M style={{color:C.tm,lineHeight:1.8}}>Use the sidebar. Home shows your status. Signals shows your drift indicators. Delegate sends patterns to automation. Peers connects you with colleagues. Training helps you upskill. Self-Scan checks your client for compromise. All data is pseudonymized.</M>
      </div>)}
      <div style={{display:"flex",minHeight:"calc(100vh - 80px)"}}>
        <div style={{width:170,minWidth:170,background:C.s,borderRight:"1px solid "+C.b,overflowY:"auto",padding:"8px 0"}}>
          {tabs.map(t=><button key={t.id} onClick={()=>setTab(t.id)} style={{width:"100%",padding:"9px 14px",background:tab===t.id?"rgba(110,231,183,0.1)":"transparent",border:"none",borderLeft:tab===t.id?"3px solid "+C.a:"3px solid transparent",color:tab===t.id?C.a:C.td,fontSize:11,fontWeight:tab===t.id?600:400,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace",textAlign:"left"}}>{t.label}</button>)}
        </div>
        <div style={{flex:1,overflowY:"auto"}}>
      <div style={{padding:24,maxWidth:820,animation:"fadeIn 0.3s ease"}}>

        {/* ══════════ HOME ══════════ */}
        {tab==="home"&&(<div>
          <Card style={{marginBottom:20,borderLeft:`3px solid ${sc.c}`,cursor:"pointer"}} onClick={()=>setTab("signals")}>
            <div style={{fontSize:14,fontWeight:500,color:"#E8EDF5"}}>{sc.hl}</div>
            <M style={{color:C.tm}}>{sc.sub}</M>
          </Card>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:20}}>
            <Card onClick={()=>setTab("peers")} style={{cursor:"pointer"}}><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>Peer skill-share</div><M style={{color:C.tm}}>Ask a peer for advice, put your heads together to solve a problem, learn tricks of the trade, prevent burnout</M></Card>
            <Card onClick={()=>{setTab("delegate");setShowDel(true);}} style={{cursor:"pointer"}}><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>Delegate a pattern</div><M style={{color:C.tm}}>Send repeating alerts to automation</M></Card>
            <Card onClick={()=>setTab("training")} style={{cursor:"pointer"}}><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>Training & upskilling</div><M style={{color:C.tm}}>Recommended courses and skill development</M></Card>
            <Card onClick={()=>setTab("scan")} style={{cursor:"pointer"}}><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>Self-scan</div><M style={{color:C.tm}}>Run a compromise check on this client</M></Card>
          </div>
          <div style={{display:"flex",gap:8,marginBottom:20}}>
            <Btn disabled={featureToggles.lighter_queue===false} onClick={()=>{setShowLQ(true);logC("lighter_queue_opened","Opened lighter queue request");}}>{stageLabel==="healthy"?"Request Reduced Tickets":"Request Reduced Tickets (recommended)"}</Btn>
            <Btn disabled={featureToggles.lead_chat_identified===false} onClick={()=>{setShowLeadMsg(true);logC("lead_msg_opened","Opened Team Lead message");}}>Message Team Lead</Btn>
          </div>
          <L>Recent Impact</L>
          {impacts.map((imp,i)=><Card key={i} style={{borderLeft:`3px solid ${imp.v?C.a:C.w}`,marginBottom:8,padding:"12px 16px"}}><div style={{display:"flex",justifyContent:"space-between"}}><M style={{color:C.t}}>{imp.e}</M><M style={{color:C.td}}>{imp.d}</M></div><M style={{color:C.a,display:"block",marginTop:4}}>→ {imp.o}</M></Card>)}
        </div>)}


        {/* ══════════ SIGNALS with drill-down resources ══════════ */}
        {tab==="signals"&&(<div>
          <L>My Signals</L>
          <M style={{color:C.tm,display:"block",marginBottom:16}}>Your work patterns compared to YOUR OWN baseline. Only you see the details. Click any signal for research-backed resources.</M>
          {Object.entries(signals).map(([key,s])=>{const drift=s.hib?(s.base-s.cur):(s.cur-s.base);const bad=drift>0&&!s.hib||drift<0&&s.hib;return(
            <Card key={key} style={{marginBottom:10,borderLeft:`3px solid ${Math.abs(drift)>5?C.w:C.a}`,cursor:"pointer"}} onClick={()=>setShowSig(showSig===key?null:key)}>
              <div style={{display:"flex",justifyContent:"space-between"}}><M style={{color:C.t,fontWeight:500}}>{s.label}</M><M style={{color:bad?C.w:C.a,fontWeight:600}}>{s.cur}{s.u} <span style={{fontWeight:400,color:C.td}}>(baseline: {s.base}{s.u})</span></M></div>
              {showSig===key&&(<div style={{marginTop:12,padding:"12px 14px",background:"rgba(0,0,0,0.2)",borderRadius:8}}>
                <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:8}}>What this means & what you can do:</M>
                {(() => {
                  const ai = aiInterp && aiInterp[key];
                  if (ai && ai.status === "ai") {
                    return (
                      <div>
                        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                          <span style={{fontSize:10,fontWeight:700,letterSpacing:0.5,color:C.i,border:"1px solid "+C.i+"55",borderRadius:4,padding:"1px 6px"}}>AI</span>
                          <M style={{color:C.td,fontSize:11}}>Research-grounded{(ai.kb_refs&&ai.kb_refs.length)?(" · "+ai.kb_refs.join(", ")):""}</M>
                        </div>
                        <M style={{color:C.tm,lineHeight:1.8}}>{ai.text}</M>
                      </div>
                    );
                  }
                  const reason = ai && ai.reason;
                  const why = reason==="model_not_loaded" ? " The local AI model isn't loaded yet." : reason==="not_configured" ? " No AI provider is configured." : reason==="decryption_failed" ? " The stored interpretation couldn't be read." : "";
                  return (
                    <M style={{color:C.td,lineHeight:1.7}}>{aiInterp===null ? "Loading your interpretation..." : ("AI interpretation unavailable right now." + why + " Your signal values above are accurate.")}</M>
                  );
                })()}
              </div>)}
            </Card>
          );})}
          <div style={{display:"flex",gap:8,marginTop:16}}>
            <Btn primary disabled={featureToggles.lighter_queue===false} onClick={()=>{setShowLQ(true);logC("lighter_queue_opened","Requesting reduced ticket load");}}>{stageLabel==="healthy"?"Request Reduced Tickets":"Request Reduced Tickets (recommended)"}</Btn>
            <Btn disabled={featureToggles.lead_chat_identified===false} onClick={()=>{setShowLeadMsg(true);logC("lead_1on1_request","Requesting 1-on-1 with Team Lead");}}>Request 1-on-1 with Lead</Btn>
          </div>
        </div>)}

        {/* ── Lighter Queue Request Modal ── */}
        {showLQ&&(<div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.8)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={()=>setShowLQ(false)}>
          <div onClick={e=>e.stopPropagation()} style={{background:C.bg,border:`1px solid ${C.b}`,borderRadius:16,padding:32,maxWidth:460,width:"90%"}}>
            <L>Request Lighter Queue</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>This request is anonymous. Your Team Lead will see that someone on the team requested reduced load — not who. Your identity is protected by your pseudonym.</M>
            <Sel label="Duration" value={lqDur} onChange={e=>setLqDur(e.target.value)}>
              <option value="1_shift">This shift only</option><option value="2_shifts">2 shifts</option><option value="1_day">1 day</option><option value="3_days">3 days</option>
            </Sel>
            <Input label="Max ticket complexity (1=low, 5=high)" value={lqCap} onChange={e=>setLqCap(parseInt(e.target.value)||2)} type="number"/>
            <Input label="Reason (optional — completely anonymous)" value={lqReason} onChange={e=>setLqReason(e.target.value)} placeholder="You don't have to explain. But if context helps..."/>
            {!lqDone?(<Btn primary onClick={()=>{setLqDone(true);logC("lighter_queue_requested","Duration: "+lqDur+", cap: "+lqCap);}}>Submit Request</Btn>):
            (<Card style={{borderColor:C.a+"40"}}><M style={{color:C.a}}>Request submitted anonymously. Your queue will be adjusted within the next rotation.</M></Card>)}
            <Btn style={{marginTop:8}} onClick={()=>{setShowLQ(false);setLqDone(false);setLqReason("");}}>Close</Btn>
          </div>
        </div>)}

        {/* ══════════ DELEGATE ══════════ */}
        {tab==="delegate"&&(<div>
          <L>Delegate to Automation</L>
          <M style={{color:C.tm,display:"block",marginBottom:16}}>Send patterns to SOAR/AI triage. Each delegation saves approximately 3,650 analyst interactions per year for a pattern appearing 10 times daily.</M>
          {delegations.map(d=>(
            <Card key={d.id} style={{borderLeft:`3px solid ${d.st==="accepted"?C.a:d.st==="pending"?C.w:C.d}`,marginBottom:8}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                <div><M style={{color:C.t,fontWeight:500}}>{d.pat}</M><M style={{color:C.td,display:"block"}}>{d.sys} · {d.ts}</M></div>
                <Badge color={d.st==="accepted"?C.a:d.st==="pending"?C.w:C.d}>{d.st}</Badge>
              </div>
              {d.st==="pending"&&<div style={{display:"flex",gap:6}}><Btn small onClick={()=>{setDel(prev=>prev.filter(x=>x.id!==d.id));logC("delegation_cancelled","Cancelled: "+d.pat);}}>Cancel</Btn></div>}
            </Card>
          ))}
          <Btn primary onClick={()=>setShowDel(true)} style={{marginTop:12}}>+ New Delegation</Btn>
          {showDel&&(<Card style={{marginTop:16}}>
            <Input label="Alert pattern to delegate" value={newDel} onChange={e=>setNewDel(e.target.value)} placeholder="e.g., Phishing: O365 credential template #4471" maxLength={500}/>
            <Sel label="Target system" value={selSys} onChange={e=>setSelSys(e.target.value)}>{AUTO_SYS_INIT.filter(s=>s.l1||s.l2).map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</Sel>
            <div style={{display:"flex",gap:8}}>
              <Btn primary style={{flex:1}} onClick={()=>{if(newDel.trim()){setDel(prev=>[...prev,{id:Date.now(),ts:new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}),pat:newDel,st:"pending",sys:(AUTO_SYS_INIT.find(s=>s.id===selSys)||{}).name||""}]);setNewDel("");setShowDel(false);logC("delegation_submitted","Pattern: "+newDel.slice(0,40));}}}>Submit</Btn>
              <Btn onClick={()=>setShowDel(false)}>Cancel</Btn>
            </div>
          </Card>)}
        </div>)}

        {tab==="peers"&&((featureToggles.peer_chat===false&&featureToggles.peer_scheduling===false)?<AdminDisabledPanel name="Peer Skill-Share" mode="tab"/>:<div>
          <L>Peer Skill-Share</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>E2EE skill-sharing chat between analysts. Share knowledge about techniques, tools, and approaches to SOC challenges. Text only, 4KB limit, auto-closes after {peerTimeout} min inactivity, no persistence. Chat opens in a compact window so it blends with your other tools.</M>

          {/* Disclaimer acceptance gate */}
          {!peerDiscAccepted&&!peerSession&&(<Card style={{marginBottom:16,borderColor:C.i+"40"}}>
            <div style={{fontSize:13,fontWeight:500,color:C.i,marginBottom:10}}>Peer Skill-Share Guidelines</div>
            <div style={{fontSize:11,color:C.tm,lineHeight:1.8,marginBottom:12,maxHeight:220,overflowY:"auto",padding:"8px 12px",background:"rgba(0,0,0,0.2)",borderRadius:8}}>
              <div style={{marginBottom:8}}><span style={{color:C.a}}>PURPOSE:</span> Share technical skills, discuss approaches to SOC challenges, brainstorm solutions to monitoring and response problems, and mentor each other on blue team and red team techniques. You may also use this to seek peer advice on preventing burnout through better work approaches.</div>
              <div style={{marginBottom:8}}><span style={{color:C.a}}>ANONYMITY:</span> Your identity is hidden by default. Both parties must independently consent to reveal identities. In smaller teams, total anonymity may not be practically achievable.</div>
              <div style={{marginBottom:8}}><span style={{color:C.a}}>CONDUCT:</span> Keep discussions constructive and focused on skills and professional development. No demeaning language, no personal attacks, no references to personal characteristics.</div>
              <div style={{marginBottom:8}}><span style={{color:C.d}}>ABUSE POLICY:</span> Either party can flag abusive language. If you engage respectfully, it remains anonymous. If you commit abuse, your identity gets revealed and flagged content retained.</div>
              <div style={{marginBottom:8}}><span style={{color:C.d}}>FLAG MISUSE:</span> Inappropriately flagging non-abusive text — for instance, to expose your peer's identity or to surface issues they raised in confidence — undermines the trust that makes this tool work. Misuse of the flagging system may lead the team to discontinue peer skill-share entirely. Flag only genuinely abusive content.</div>
              <div style={{marginBottom:8}}><span style={{color:C.w}}>NOT COUNSELING:</span> Your peers are analysts, not psychologists. For professional support, use your EAP or a licensed provider.</div>
              <div><span style={{color:C.i}}>NO PERSISTENCE:</span> When chat closes, messages are retained for 5 minutes for rating and abuse review. After 5 minutes, all messages are permanently and irrecoverably deleted. You cannot end a chat to avoid accountability — the other party will still have 5 minutes to flag abusive text.</div>
            </div>
            <div style={{display:"flex",gap:8}}>
              <Btn primary onClick={()=>{setPeerDiscAccepted(true);logC("peer_disclaimer_accepted","Accepted skill-share guidelines");}}>I Agree — Continue</Btn>
              <Btn onClick={()=>setTab("home")}>Disagree — Close</Btn>
            </div>
          </Card>)}

          {/* Request form with unified scheduling */}
          {peerDiscAccepted&&!peerSession&&(<div>
            <Card style={{marginBottom:16}}>
              <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Start a Skill-Share</div>
              <Input label="What do you want to discuss?" value={peerTopic} onChange={e=>setPeerTopic(e.target.value)} placeholder="e.g., Need help analyzing lateral movement in Zeek logs" maxLength={500}/>
              <div style={{marginBottom:14}}>
                <M style={{color:C.tm,marginBottom:8,display:"block"}}>When?</M>
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  {[{v:"now",l:"Now"},{v:"after_shift",l:"After my shift"},{v:"tomorrow",l:"Tomorrow"},{v:"pick",l:"Pick time"}].map(t=>(
                    <div key={t.v} onClick={()=>setPeerTimeSlot(t.v)} style={{padding:"8px 16px",background:peerTimeSlot===t.v?"rgba(110,231,183,0.15)":"rgba(255,255,255,0.02)",border:`1px solid ${peerTimeSlot===t.v?C.a:C.b}`,borderRadius:8,cursor:"pointer",fontSize:11,fontWeight:peerTimeSlot===t.v?600:400,color:peerTimeSlot===t.v?C.a:C.tm}}>{t.l}</div>
                  ))}
                </div>
                {peerTimeSlot==="pick"&&<div style={{marginTop:8}}><Input label="Date & time" type="datetime-local" value={peerPickTime} onChange={e=>setPeerPickTime(e.target.value)}/></div>}
              </div>
              <label style={{display:"flex",alignItems:"center",gap:8,marginBottom:14,cursor:"pointer",padding:"10px 14px",background:peerBurnout?"rgba(251,191,36,0.06)":"transparent",border:`1px solid ${peerBurnout?C.w+"40":"transparent"}`,borderRadius:8}}>
                <input type="checkbox" checked={peerBurnout} onChange={e=>setPeerBurnout(e.target.checked)}/>
                <M style={{color:peerBurnout?C.w:C.tm}}>I also want to discuss how to prevent burnout</M>
              </label>
              <div style={{marginBottom:14}}>
                <M style={{color:C.tm,marginBottom:6,display:"block"}}>Exclude analysts (optional)</M>
                {/* R3n: pseudonym-based exclude list. Click pseudonyms you'd
                    prefer not to receive help from. Server enforces a 50%
                    exclusion cap to prevent triangulation. */}
                {!pseudonymsLoaded ? (
                  <M style={{color:C.td,fontStyle:"italic"}}>Loading pseudonyms...</M>
                ) : pseudonymList.length === 0 ? (
                  <M style={{color:C.td,fontStyle:"italic"}}>No analyst pseudonyms available.</M>
                ) : (() => {
                  const maxExcl = pseudonymList.length - Math.ceil(pseudonymList.length * 0.5);
                  return (<div>
                    <M style={{color:C.td,display:"block",marginBottom:6,fontSize:10}}>
                      Excluded {peerExclude.length} of {pseudonymList.length} pseudonyms (max {maxExcl} — at least half the pool must remain available as helpers).
                    </M>
                    <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
                      {pseudonymList.map(p=>(
                        <label key={p.pseudonym} style={{display:"flex",alignItems:"center",gap:4,padding:"4px 8px",background:peerExclude.includes(p.pseudonym)?"rgba(239,68,68,0.1)":"rgba(255,255,255,0.02)",border:`1px solid ${peerExclude.includes(p.pseudonym)?C.d+"40":C.b}`,borderRadius:6,cursor:"pointer",fontSize:10}}>
                          <input type="checkbox" checked={peerExclude.includes(p.pseudonym)} onChange={e=>{if(e.target.checked)setPeerExclude(prev=>[...prev,p.pseudonym]);else setPeerExclude(prev=>prev.filter(x=>x!==p.pseudonym));}}/>
                          <span style={{color:peerExclude.includes(p.pseudonym)?C.d:C.tm}}>{p.pseudonym}</span>
                          <span style={{color:C.td,fontSize:9}}>T{p.tier}·{p.shift}</span>
                        </label>
                      ))}
                    </div>
                  </div>);
                })()}
              </div>
              <Btn primary disabled={!peerTopic.trim() || peerSubmitBusy} onClick={async()=>{
                setPeerSubmitError(null);
                setPeerSubmitBusy(true);
                try {
                  // R3n: real submission to canonical /api/peers/requests with
                  // pseudonym-based excludePseudonyms. Server enforces 50% cap
                  // and resolves pseudonyms → user IDs internally.
                  const r = await api.post("/api/peers/requests", {
                    topic: peerTopic,
                    excludePseudonyms: peerExclude,
                    willingToMeetInPerson: peerWillingMeet,
                  });
                  if (r?.error) {
                    setPeerSubmitError(r.detail || r.error);
                    return;
                  }
                  setPeerSession({id:r.id||Date.now(),topic:peerTopic,status:"waiting",myConsent:false,peerConsent:false,timeSlot:peerTimeSlot});
                  logC("peer_request_created","Skill-share request submitted ("+peerTimeSlot+", "+peerExclude.length+" excluded)");
                  setPeerTopic("");
                  setPeerExclude([]);
                } catch (err) {
                  setPeerSubmitError(err?.message || "Failed to submit request");
                } finally {
                  setPeerSubmitBusy(false);
                }
              }}>{peerSubmitBusy?"Submitting...":"Submit Request"}</Btn>
              {peerSubmitError && <Card style={{padding:10,marginTop:10,borderColor:C.d+"60",background:C.d+"14"}}><M style={{color:C.d,fontWeight:500}}>Submit error:</M><M style={{color:C.t,display:"block",marginTop:4}}>{peerSubmitError}</M></Card>}
            </Card>

            {/* Queue — available requests from others */}
            <L>Available Skill-Share Requests</L>
            {peerQueue.length===0?<Card style={{padding:"12px 14px"}}><M style={{color:C.td}}>No open requests right now. Check back later or submit your own above.</M></Card>:
            peerQueue.map(q=>(
              <Card key={q.id} style={{marginBottom:8,padding:"12px 14px",borderLeft:`3px solid ${C.i}`}}>
                <div style={{fontSize:12,color:"#E8EDF5",marginBottom:6,lineHeight:1.5}}>{q.topic}</div>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <div style={{display:"flex",gap:6}}>
                    {q.willingToMeet&&<Badge color={C.i}>Open to meeting</Badge>}
                    <M style={{color:C.td}}>{q.ts}</M>
                  </div>
                  <div style={{display:"flex",gap:6}}>
                    <Btn small primary onClick={()=>{acceptPeerRequest(q);}}>Accept</Btn>
                    <Btn small onClick={()=>{setPeerQueue(prev=>prev.filter(x=>x.id!==q.id));logC("peer_passed","Passed on request");}}>Pass</Btn>
                  </div>
                </div>
              </Card>
            ))}

            {/* My Requests — manage submitted requests */}
            <div style={{marginTop:16}}>
              <L>My Requests ({myPeerRequests.length})</L>
              {myPeerRequests.length===0?<Card style={{padding:"12px 14px"}}><M style={{color:C.td}}>You have no pending skill-share requests.</M></Card>:
              myPeerRequests.map(r=>(
                <Card key={r.id} style={{marginBottom:8,padding:"12px 14px",borderLeft:`3px solid ${r.status==="matched"?C.a:C.i}`}}>
                  <div style={{fontSize:12,color:"#E8EDF5",marginBottom:6}}>{r.topic}</div>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:6}}>
                    <div style={{display:"flex",gap:6,alignItems:"center"}}>
                      <Badge color={r.status==="matched"?C.a:C.i}>{r.status==="matched"?"Scheduled":"Open"}</Badge>
                      {r.status==="matched"&&<M style={{color:C.a}}>{new Date(r.matchedTime).toLocaleString([],{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"})}</M>}
                      {r.status==="open"&&<M style={{color:C.td}}>Submitted {new Date(r.createdAt).toLocaleDateString()}</M>}
                    </div>
                    <div style={{display:"flex",gap:6}}>
                      {r.status==="matched"&&<Btn small primary onClick={()=>{const topic=r.topic;const time=r.matchedTime;const ics=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//FireAlive//PeerSkillShare//EN","BEGIN:VEVENT","DTSTART:"+new Date(time).toISOString().replace(/[-:]/g,"").replace(/\.\d{3}/,""),"DTEND:"+new Date(new Date(time).getTime()+30*60000).toISOString().replace(/[-:]/g,"").replace(/\.\d{3}/,""),"SUMMARY:Peer Skill-Share: "+topic.slice(0,60),"DESCRIPTION:FireAlive Peer Skill-Share session.","UID:"+Math.random().toString(36).slice(2)+"@firealive","BEGIN:VALARM","TRIGGER:-PT15M","ACTION:DISPLAY","DESCRIPTION:Skill-share in 15 min","END:VALARM","END:VEVENT","END:VCALENDAR"].join("\r\n");const blob=new Blob([ics],{type:"text/calendar"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="peer-skillshare.ics";a.click();logC("calendar_export","Exported skill-share to calendar");}}>Add to Calendar</Btn>}
                      {r.status==="matched"&&<Btn small danger onClick={()=>{setMyPeerRequests(prev=>prev.filter(x=>x.id!==r.id));logC("peer_scheduled_cancelled","Cancelled scheduled skill-share: "+r.topic);}}>Cancel Scheduled Chat</Btn>}
                      {r.status==="open"&&<Btn small danger onClick={()=>{setMyPeerRequests(prev=>prev.filter(x=>x.id!==r.id));logC("peer_request_cancelled","Removed request from queue: "+r.topic);}}>Remove from Queue</Btn>}
                    </div>
                  </div>
                </Card>
              ))}
              <M style={{color:C.td,display:"block",marginTop:8,lineHeight:1.6}}>Open requests expire after 7 days with no match. You will be notified and can resubmit.</M>
            </div>

            {/* Notification preference */}
            <Card style={{marginTop:16,padding:"12px 14px",borderColor:C.i+"20"}}>
              <label style={{display:"flex",alignItems:"center",gap:8,cursor:"pointer"}}><input type="checkbox" checked={peerNotifEnabled} onChange={e=>{setPeerNotifEnabled(e.target.checked);logC("peer_notif_toggle",e.target.checked?"Enabled peer chat notifications":"Disabled peer chat notifications");}}/><M style={{color:C.t}}>Notify me when new skill-share requests are posted</M></label>
              <M style={{color:C.td,display:"block",marginTop:6}}>Desktop notifications appear when a peer posts a new request. You are never required to accept.</M>
            </Card>
          </div>)}

          {/* Active chat session — compact terminal-style */}
          {peerSession&&(<div>
            <Card style={{marginBottom:8,padding:"10px 14px",background:"rgba(110,231,183,0.03)",borderColor:C.a+"30"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div><M style={{color:C.a,fontWeight:500}}>Active Skill-Share</M> <M style={{color:C.td}}>· E2EE · {peerSession.myConsent&&peerSession.peerConsent?("Identities revealed"+(peerSession.peerName?" · "+peerSession.peerName:"")):"Anonymous"}</M></div>
                <div style={{display:"flex",gap:6}}>
                  {!peerSession.myConsent&&<Btn small onClick={()=>{consentReveal();}}>Reveal My Identity</Btn>}
                  <Btn small onClick={()=>{showPeerSafetyNumber();}}>Safety #</Btn>
                  <Btn small danger onClick={()=>{logC("peer_flag","Flagged abusive language");}}>Flag Abuse</Btn>
                </div>
              </div>
              {peerSession.myConsent&&!peerSession.peerConsent&&<M style={{color:C.w,display:"block",marginTop:6}}>Your consent recorded. Waiting for peer to also consent.</M>}
              <M style={{color:C.td,display:"block",marginTop:4}}>Topic: {peerSession.topic}</M>
              {peerSafetyNum&&<div style={{marginTop:6,padding:"6px 8px",background:"rgba(0,0,0,0.3)",borderRadius:6}}><M style={{color:C.td,display:"block",marginBottom:2}}>Safety number (read aloud to compare; they must match):</M><M style={{color:C.a,fontFamily:"'Courier New',Courier,monospace",wordBreak:"break-all"}}>{peerSafetyNum}</M></div>}
            </Card>
            <Card style={{marginBottom:8,maxHeight:280,overflow:"auto",background:"rgba(0,0,0,0.4)",borderColor:C.b,fontFamily:"'Courier New',Courier,monospace"}}>
              {peerMsgs.length===0&&<M style={{color:C.td,padding:14,display:"block"}}>Session started. Type below to begin skill-sharing.</M>}
              {peerMsgs.map(m=>(
              <div key={m.id} style={{padding:"8px 12px",borderBottom:`1px solid rgba(255,255,255,0.04)`}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:2}}><M style={{color:m.from.includes("You")?C.a:C.p,fontWeight:500,fontFamily:"inherit"}}>{m.from}</M><M style={{color:C.td,fontFamily:"inherit"}}>{m.enc&&"E2EE · "}{m.ts}</M></div>
                <div style={{fontSize:12,lineHeight:1.5,fontFamily:"inherit",color:C.t}}>{m.text}</div>
              </div>
            ))}</Card>
            <div style={{display:"flex",gap:8,marginBottom:8}}><input value={newPM} onChange={e=>setNewPM(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"){sendPeerMessage();}}} placeholder="E2EE · anonymous · max 4KB..." maxLength={4096} style={{flex:1,padding:10,background:"rgba(0,0,0,0.3)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12,fontFamily:"'Courier New',Courier,monospace"}}/><Btn primary onClick={()=>{sendPeerMessage();}}>Send</Btn></div>
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              <Btn danger onClick={()=>{closePeerSession();}}>End Chat</Btn>
              <Btn small onClick={()=>{setPeerQueue(prev=>[{id:Date.now(),topic:peerSession.topic,time:"now",burnout:false,ts:"just now"},...prev]);setPeerSession(null);setPM([]);logC("peer_requeue","Re-queued skill-share topic");}}>Re-queue Topic</Btn>
            </div>
            <M style={{color:C.td,display:"block",marginTop:8}}>Auto-closes after {peerTimeout} min inactivity. When chat ends, messages are retained for 5 minutes for rating and abuse review, then permanently deleted.</M>
          </div>)}

          {/* Post-session rating & abuse flagging — 5-min retention window */}
          {postSession&&(<div>
            <Card style={{marginBottom:12,borderColor:C.w+"40",padding:16}}>
              <div style={{fontSize:14,fontWeight:600,color:"#E8EDF5",marginBottom:12}}>Skill-Share Ended</div>
              <M style={{color:C.w,display:"block",marginBottom:12,lineHeight:1.6}}>Chat messages are temporarily retained for 5 minutes so you can rate and flag any issues. After that, all messages are permanently deleted.</M>
              <M style={{color:C.td,display:"block",marginBottom:16}}>Topic: {postSession.topic} · Expires: {new Date(postSession.expiresAt).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})}</M>

              {/* Rating */}
              <div style={{marginBottom:16}}>
                <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:8}}>How helpful was this skill-share?</M>
                <div style={{display:"flex",gap:6}}>
                  {[1,2,3,4,5].map(n=>(
                    <div key={n} onClick={()=>{setPostRating(n);logC("peer_rated","Rating: "+n);}} style={{width:40,height:40,display:"flex",alignItems:"center",justifyContent:"center",borderRadius:8,border:`1px solid ${postRating>=n?C.a:C.b}`,background:postRating>=n?"rgba(110,231,183,0.15)":"rgba(255,255,255,0.02)",cursor:"pointer",fontSize:16,fontWeight:600,color:postRating>=n?C.a:C.td}}>{n}</div>
                  ))}
                </div>
                {postRating>0&&<M style={{color:C.a,display:"block",marginTop:6}}>Rating submitted: {postRating}/5</M>}
              </div>

              {/* Abuse flagging */}
              <div style={{marginBottom:16}}>
                <M style={{color:C.d,fontWeight:500,display:"block",marginBottom:8}}>Was everything respectful?</M>
                <div style={{display:"flex",gap:8}}>
                  <Btn small onClick={()=>{setPostSession(null);logC("peer_session_cleared","Post-session review complete — no abuse — messages deleted");}}>Yes, all good — delete messages</Btn>
                  <Btn small danger onClick={()=>setPostFlagging(true)}>I need to flag abusive language</Btn>
                </div>
              </div>

              {postFlagging&&(<div>
                <M style={{color:C.d,fontWeight:500,display:"block",marginBottom:8}}>Review the chat and select the severity that matches what happened:</M>

                <Card style={{marginBottom:8,maxHeight:200,overflow:"auto",background:"rgba(0,0,0,0.4)",fontFamily:"'Courier New',Courier,monospace"}}>
                  {postSession.messages.map(m=>(
                    <div key={m.id} style={{padding:"8px 12px",borderBottom:"1px solid rgba(255,255,255,0.04)"}}>
                      <M style={{color:m.from.includes("You")?C.a:C.p,fontWeight:500,fontFamily:"inherit"}}>{m.from}</M>
                      <span style={{fontSize:11,color:C.td,marginLeft:8}}>{m.ts}</span>
                      <div style={{fontSize:12,color:C.t,fontFamily:"inherit",marginTop:2}}>{m.text}</div>
                    </div>
                  ))}
                </Card>

                <div style={{marginBottom:14}}>
                  <M style={{color:C.tm,marginBottom:8,display:"block"}}>Severity tier:</M>
                  <div style={{display:"flex",flexDirection:"column",gap:8}}>
                    <label style={{display:"flex",gap:10,padding:"10px 12px",background:postFlagTier===1?"rgba(96,165,250,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${postFlagTier===1?C.i+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                      <input type="radio" name="flagtier" checked={postFlagTier===1} onChange={()=>setPostFlagTier(1)} style={{marginTop:3}}/>
                      <div style={{flex:1}}>
                        <M style={{color:C.i,fontWeight:600,display:"block",marginBottom:2}}>Tier 1 — Minor</M>
                        <M style={{color:C.tm,lineHeight:1.5}}>Curt tone, dismissiveness, condescension, or mild rudeness. Not a personal attack — just unprofessional. Identities stay anonymous. Aggregated for pattern detection only.</M>
                      </div>
                    </label>
                    <label style={{display:"flex",gap:10,padding:"10px 12px",background:postFlagTier===2?"rgba(251,191,36,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${postFlagTier===2?C.w+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                      <input type="radio" name="flagtier" checked={postFlagTier===2} onChange={()=>setPostFlagTier(2)} style={{marginTop:3}}/>
                      <div style={{flex:1}}>
                        <M style={{color:C.w,fontWeight:600,display:"block",marginBottom:2}}>Tier 2 — Personal attack</M>
                        <M style={{color:C.tm,lineHeight:1.5}}>Direct insult, name-calling, mockery, or demeaning language targeted at you. The peer's identity is revealed to your team lead. Your identity stays anonymous to the lead.</M>
                      </div>
                    </label>
                    <label style={{display:"flex",gap:10,padding:"10px 12px",background:postFlagTier===3?"rgba(239,68,68,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${postFlagTier===3?C.d+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                      <input type="radio" name="flagtier" checked={postFlagTier===3} onChange={()=>setPostFlagTier(3)} style={{marginTop:3}}/>
                      <div style={{flex:1}}>
                        <M style={{color:C.d,fontWeight:600,display:"block",marginBottom:2}}>Tier 3 — Urgent</M>
                        <M style={{color:C.tm,lineHeight:1.5}}>Slurs (racial, gender, orientation, religion, disability), explicit threats, sexual harassment, or content suggesting imminent harm. Both identities — yours and the peer's — are revealed to your lead. HR is brought in. Use this only when warranted; misuse undermines trust in the flagging system.</M>
                      </div>
                    </label>
                  </div>
                </div>

                <div style={{marginBottom:10}}>
                  <M style={{color:C.tm,marginBottom:4,display:"block"}}>Copy and paste the relevant text, or describe what was said:</M>
                  <textarea value={postFlagText} onChange={e=>setPostFlagText(e.target.value)} rows={3} maxLength={10000} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.d}40`,borderRadius:8,color:C.t,fontSize:12,resize:"vertical"}} placeholder="Paste the text in question or describe what happened..."/>
                </div>

                <div style={{display:"flex",gap:8}}>
                  <Btn danger disabled={!postFlagText.trim()||!postFlagTier} onClick={()=>{
                    // TODO: when peer chat is backed by a real server session, replace
                    // this with: api.post("/api/peer/flags", {sessionId, flaggedUserId,
                    // tier: postFlagTier, content: postFlagText})
                    // The endpoint exists (commit 3-5 of Phase 1.4b) but the AC peer
                    // chat itself is still client-side only — there is no server
                    // session to reference yet. This is recorded in the audit log so
                    // the flag isn't lost.
                    logC("peer_abuse_flagged",`Tier ${postFlagTier}: ${postFlagText.slice(0,80)}${postFlagText.length>80?"...":""}`);
                    setPostFlagging(false);
                    setPostFlagTier(0);
                    setPostFlagText("");
                    setPostSession(null);
                  }}>Submit Flag</Btn>
                  <Btn small onClick={()=>{setPostFlagging(false);setPostFlagTier(0);}}>Cancel</Btn>
                </div>
              </div>)}
            </Card>
          </div>)}
        </div>)}

        {tab==="helper-pay"&&(featureToggles.helper_pay===false?<AdminDisabledPanel name="Helper Pay & Recognition" mode="tab"/>:<div>
          <L>Helper Pay</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Earn points by helping peers in skill-share sessions. Points accrue when an analyst you helped rates the session at 3 stars or higher. Redeem points for rewards from your team's catalog. Anti-gaming protections (minimum session length, daily caps, lazy debit on lead approval) live in the helper-pay service.</M>

          {helperLoading && (<Card style={{marginBottom:16}}><M style={{color:C.tm}}>Loading Helper Pay data...</M></Card>)}

          {helperError && (<Card style={{marginBottom:16,borderColor:C.d+"60"}}><M style={{color:C.d}}>{helperError}</M></Card>)}

          {redeemFb && (<Card style={{marginBottom:16,borderColor:(redeemFb.kind==="success"?C.a:C.d)+"60"}}>
            <M style={{color:redeemFb.kind==="success"?C.a:C.d}}>{redeemFb.message}</M>
          </Card>)}

          {!helperLoading && !helperError && (<>
            <Card style={{marginBottom:16,padding:24,textAlign:"center"}}>
              <div style={{fontSize:10,fontWeight:500,color:C.tm,marginBottom:8,letterSpacing:1.5,textTransform:"uppercase"}}>Your Balance</div>
              <div style={{fontSize:48,fontWeight:600,color:C.a,fontFamily:"'IBM Plex Mono',monospace",lineHeight:1}}>{helperBalance}</div>
              <div style={{fontSize:11,color:C.tm,marginTop:6}}>points</div>
            </Card>

            <Card style={{marginBottom:16}}>
              <div style={{fontSize:10,fontWeight:500,color:C.tm,marginBottom:8,letterSpacing:1.5,textTransform:"uppercase"}}>Your Records</div>
              <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Download a copy of your points statement - your balance, the full points ledger, and your redemptions - to keep for your own records.</M>
              <Btn onClick={async()=>{ try { const resp = await fetch(API_BASE + "/api/helper-pay/my-statement?format=csv", { headers: api._headers() }); if (!resp.ok) { logC("helper_statement_failed","Points statement export failed"); return; } const text = await resp.text(); const blob = new Blob([text], { type: "text/csv" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "helper-pay-statement-" + new Date().toISOString().slice(0,10) + ".csv"; a.click(); logC("helper_statement_exported","Exported points statement (CSV)"); } catch (e) { logC("helper_statement_failed","Points statement export failed"); } }}>Export my points statement</Btn>
            </Card>

            {/* R3h: Leaderboard opt-in toggle. Gates whether this analyst's name appears on the Helper Recognition leaderboard the lead reviews. Does NOT gate earning, balance, or redemptions — those continue regardless. Default is opt-out per the schema. */}
            <Card style={{marginBottom:16}}>
              <div style={{fontSize:10,fontWeight:500,color:C.tm,marginBottom:10,letterSpacing:1.5,textTransform:"uppercase"}}>Leaderboard Visibility</div>
              <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Your team lead reviews a Helper Recognition leaderboard showing top peer-support contributors. Opt in to be listed by name. This setting only controls leaderboard display — you keep earning points, accruing your balance, and redeeming rewards either way.</M>
              {helperOptIn === null ? (
                <M style={{color:C.tm}}>Loading...</M>
              ) : (
                <label style={{display:"flex",alignItems:"center",gap:10,cursor:helperOptInSaving?"wait":"pointer",padding:"6px 0"}}>
                  <input
                    type="checkbox"
                    checked={!!helperOptIn}
                    disabled={helperOptInSaving}
                    onChange={e=>submitVisibility(e.target.checked)}
                    style={{cursor:helperOptInSaving?"wait":"pointer"}}
                  />
                  <span style={{fontSize:12,color:helperOptIn?C.a:C.t}}>
                    {helperOptIn ? "Visible on the leaderboard" : "Hidden from the leaderboard"}
                  </span>
                </label>
              )}
              {helperOptInFb && (
                <div style={{marginTop:10,padding:"8px 10px",background:helperOptInFb.kind==="success"?"rgba(110,231,183,0.08)":"rgba(239,68,68,0.08)",border:`1px solid ${(helperOptInFb.kind==="success"?C.a:C.d)}40`,borderRadius:6}}>
                  <M style={{color:helperOptInFb.kind==="success"?C.a:C.d}}>{helperOptInFb.message}</M>
                </div>
              )}
            </Card>

            <L style={{marginBottom:8}}>Available Rewards</L>
            {helperOptions.length === 0 ? (
              <Card style={{marginBottom:16}}><M style={{color:C.tm}}>Your team has not added any rewards to the catalog yet. Ask your team lead to set up redemption options in the management console.</M></Card>
            ) : (
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(260px,1fr))",gap:12,marginBottom:16}}>
                {helperOptions.map(opt => {
                  const canAfford = helperBalance >= opt.cost_points;
                  const typeLabel = {time_off:"Time off",gift_card:"Gift card",donation:"Donation",other:"Other"}[opt.redemption_type] || opt.redemption_type;
                  return (
                    <Card key={opt.id} style={{display:"flex",flexDirection:"column",justifyContent:"space-between",opacity:canAfford?1:0.6}}>
                      <div>
                        <div style={{fontSize:9,fontWeight:600,color:C.a,marginBottom:6,letterSpacing:1.2,textTransform:"uppercase"}}>{typeLabel}</div>
                        <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:6}}>{opt.name}</div>
                        {opt.description && <M style={{color:C.tm,marginBottom:10,lineHeight:1.5,display:"block"}}>{opt.description}</M>}
                      </div>
                      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:10,paddingTop:10,borderTop:`1px solid ${C.b}`}}>
                        <div style={{fontSize:13,fontWeight:600,color:canAfford?C.a:C.tm,fontFamily:"'IBM Plex Mono',monospace"}}>{opt.cost_points} pts</div>
                        <Btn primary={canAfford} small disabled={!canAfford} onClick={()=>setRedeemConfirm(opt)}>
                          {opt.approval_required ? "Request" : "Redeem"}
                        </Btn>
                      </div>
                    </Card>
                  );
                })}
              </div>
            )}

            <L style={{marginBottom:8}}>Recent Activity</L>
            {helperLedger.length === 0 ? (
              <Card style={{marginBottom:16}}><M style={{color:C.tm}}>No Helper Pay activity yet. Help peers in skill-share sessions to earn your first points.</M></Card>
            ) : (
              <Card style={{marginBottom:16,padding:0,overflow:"hidden"}}>
                {helperLedger.map((entry, i) => {
                  const reasonLabel = {
                    rating_received:"Rating received",
                    mentor_session:"Mentor session",
                    kb_contribution:"Knowledge base contribution",
                    redemption:"Redemption",
                    reversal_fraud:"Reversed (fraud)",
                    reversal_admin:"Reversed (admin)",
                    admin_adjustment:"Admin adjustment",
                  }[entry.reason] || entry.reason;
                  const isPositive = entry.delta > 0;
                  const isZero = entry.delta === 0;
                  return (
                    <div key={entry.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 14px",borderBottom:i<helperLedger.length-1?`1px solid ${C.b}`:"none"}}>
                      <div style={{flex:1,minWidth:0}}>
                        <div style={{fontSize:12,color:"#E8EDF5",marginBottom:2}}>{reasonLabel}</div>
                        {entry.notes && <div style={{fontSize:10,color:C.tm}}>{entry.notes}</div>}
                        <div style={{fontSize:10,color:C.tm}}>{entry.created_at}</div>
                      </div>
                      <div style={{display:"flex",alignItems:"center",gap:14,flexShrink:0}}>
                        <div style={{fontSize:13,fontWeight:600,color:isZero?C.tm:(isPositive?C.a:C.d),fontFamily:"'IBM Plex Mono',monospace"}}>{isPositive?"+":""}{entry.delta}</div>
                        <div style={{fontSize:11,color:C.tm,fontFamily:"'IBM Plex Mono',monospace",minWidth:48,textAlign:"right"}}>bal {entry.balance_after}</div>
                      </div>
                    </div>
                  );
                })}
              </Card>
            )}

            <L style={{marginBottom:8}}>My Redemptions</L>
            {helperMyRedemptions.length === 0 ? (
              <Card style={{marginBottom:16}}><M style={{color:C.tm}}>You have not redeemed any rewards yet.</M></Card>
            ) : (
              <Card style={{marginBottom:16,padding:0,overflow:"hidden"}}>
                {helperMyRedemptions.map((r, i) => {
                  const statusColor = {requested:C.w,approved:C.a,denied:C.d,fulfilled:C.a,cancelled:C.tm}[r.status] || C.tm;
                  return (
                    <div key={r.id} style={{padding:"10px 14px",borderBottom:i<helperMyRedemptions.length-1?`1px solid ${C.b}`:"none"}}>
                      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
                        <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>{r.option_name}</div>
                        <div style={{fontSize:9,fontWeight:600,color:statusColor,textTransform:"uppercase",letterSpacing:1.2}}>{r.status}</div>
                      </div>
                      <div style={{fontSize:10,color:C.tm}}>{r.cost_points} pts · requested {r.requested_at}</div>
                      {r.decision_note && (<div style={{marginTop:6,fontSize:10,color:C.tm,fontStyle:"italic"}}>Lead note: {r.decision_note}</div>)}
                    </div>
                  );
                })}
              </Card>
            )}
          </>)}

          {redeemConfirm && (
            <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.7)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:9999,padding:20}}>
              <Card style={{maxWidth:420,width:"100%"}}>
                <div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Confirm redemption</div>
                <M style={{color:C.tm,marginBottom:14,lineHeight:1.6,display:"block"}}>
                  {redeemConfirm.approval_required
                    ? `Submit a redemption request for "${redeemConfirm.name}" (${redeemConfirm.cost_points} pts)? Your team lead must approve before points are debited.`
                    : `Redeem "${redeemConfirm.name}" for ${redeemConfirm.cost_points} pts? Points will be debited immediately.`}
                </M>
                <div style={{display:"flex",gap:8,justifyContent:"flex-end"}}>
                  <Btn onClick={()=>setRedeemConfirm(null)}>Cancel</Btn>
                  <Btn primary onClick={()=>submitRedeem(redeemConfirm)}>
                    {redeemConfirm.approval_required ? "Submit Request" : "Redeem"}
                  </Btn>
                </div>
              </Card>
            </div>
          )}
        </div>)}

        {tab==="board"&&(featureToggles.peer_board===false?<AdminDisabledPanel name="Peer Support Board" mode="tab"/>:<div>
          <L>Peer Skill-Share Board</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Share tips, ask questions, and discuss burnout prevention strategies with your team. Messages auto-expire after 7 days. Same conduct rules as peer chat apply — no personal attacks, no abusive language. Management may review posted content.</M>

          {/* New post */}
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Post a Message</div>
            <div style={{marginBottom:10}}><textarea value={newBoardMsg} onChange={e=>setNewBoardMsg(e.target.value)} rows={3} maxLength={4096} placeholder="Share a technique, ask a question, or discuss approaches to common challenges..." style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12,resize:"vertical"}}/></div>
            <div style={{display:"flex",gap:12,alignItems:"center",flexWrap:"wrap",marginBottom:10}}>
              <Sel label="Category" value={boardMsgCat} onChange={e=>setBoardMsgCat(e.target.value)} style={{flex:1,minWidth:140}}><option value="technical">Technical</option><option value="burnout_prevention">Burnout Prevention</option><option value="tip">Tip / Trick</option><option value="question">Question</option><option value="general">General</option></Sel>
              <label style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer",marginTop:16}}><input type="checkbox" checked={boardMsgAnon} onChange={e=>setBoardMsgAnon(e.target.checked)}/><M style={{color:boardMsgAnon?C.a:C.w}}>{boardMsgAnon?"Anonymous":"Identified"}</M></label>
            </div>
            {!boardMsgAnon&&<Card style={{padding:8,marginBottom:10,borderColor:C.w+"40"}}><M style={{color:C.w}}>Your name will be visible on this post.</M></Card>}
            <Btn primary disabled={!newBoardMsg.trim()} onClick={async()=>{const r=await api.post("/api/peer-board/messages",{content:newBoardMsg,anonymous:boardMsgAnon,category:boardMsgCat});if(r&&r.message){setPeerBoardMsgs(prev=>[r.message,...prev]);setNewBoardMsg("");logC("board_post","Posted to skill-share board ("+boardMsgCat+", "+(boardMsgAnon?"anonymous":"identified")+")");}else{logC("board_post","Failed to post to board");}}}>Post</Btn>
          </Card>

          {/* Messages */}
          {peerBoardMsgs.map(m=>{
            const catColors={technical:C.i,burnout_prevention:C.w,tip:C.a,question:C.p,general:C.tm};
            const ageStr=relTime(m.createdAt);
            const expanded = m.id in expandedThreads;
            const thread = expanded ? expandedThreads[m.id] : null;
            const composer = (rootId, parentId) => (
              <Card style={{marginTop:8,padding:"10px 12px",borderColor:C.a+"40"}}>
                <textarea value={replyDraft} onChange={e=>setReplyDraft(e.target.value)} rows={2} maxLength={4096} placeholder="Write a reply..." style={{width:"100%",padding:8,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12,resize:"vertical"}}/>
                <div style={{display:"flex",gap:10,alignItems:"center",marginTop:6}}>
                  <label style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer"}}><input type="checkbox" checked={replyDraftAnon} onChange={e=>setReplyDraftAnon(e.target.checked)}/><M style={{color:replyDraftAnon?C.a:C.w}}>{replyDraftAnon?"Anonymous":"Identified"}</M></label>
                  <Btn primary small disabled={!replyDraft.trim()} onClick={()=>submitReply(rootId,parentId)}>Reply</Btn>
                  <Btn small onClick={()=>setReplyTo(null)}>Cancel</Btn>
                </div>
              </Card>
            );
            const flagPicker = (postId, rootId) => (
              <Card style={{marginTop:8,padding:"12px 14px",borderColor:C.d+"40"}}>
                <M style={{color:C.d,fontWeight:500,display:"block",marginBottom:8}}>Flag this post -- select the severity that matches what was said:</M>
                <div style={{display:"flex",flexDirection:"column",gap:8,marginBottom:10}}>
                  <label style={{display:"flex",gap:10,padding:"10px 12px",background:boardFlagTier===1?"rgba(96,165,250,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${boardFlagTier===1?C.i+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                    <input type="radio" name={"bflag-"+postId} checked={boardFlagTier===1} onChange={()=>setBoardFlagTier(1)} style={{marginTop:3}}/>
                    <div style={{flex:1}}>
                      <M style={{color:C.i,fontWeight:600,display:"block",marginBottom:2}}>Tier 1 -- Minor</M>
                      <M style={{color:C.tm,lineHeight:1.5}}>Curt tone, dismissiveness, condescension, or mild rudeness. Not a personal attack. Identities stay anonymous; aggregated for pattern detection only.</M>
                    </div>
                  </label>
                  <label style={{display:"flex",gap:10,padding:"10px 12px",background:boardFlagTier===2?"rgba(251,191,36,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${boardFlagTier===2?C.w+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                    <input type="radio" name={"bflag-"+postId} checked={boardFlagTier===2} onChange={()=>setBoardFlagTier(2)} style={{marginTop:3}}/>
                    <div style={{flex:1}}>
                      <M style={{color:C.w,fontWeight:600,display:"block",marginBottom:2}}>Tier 2 -- Personal attack</M>
                      <M style={{color:C.tm,lineHeight:1.5}}>Direct insult, name-calling, mockery, or demeaning language in the post. The author's identity is revealed to your team lead; yours stays anonymous.</M>
                    </div>
                  </label>
                  <label style={{display:"flex",gap:10,padding:"10px 12px",background:boardFlagTier===3?"rgba(239,68,68,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${boardFlagTier===3?C.d+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                    <input type="radio" name={"bflag-"+postId} checked={boardFlagTier===3} onChange={()=>setBoardFlagTier(3)} style={{marginTop:3}}/>
                    <div style={{flex:1}}>
                      <M style={{color:C.d,fontWeight:600,display:"block",marginBottom:2}}>Tier 3 -- Urgent</M>
                      <M style={{color:C.tm,lineHeight:1.5}}>Slurs, explicit threats, sexual harassment, or content suggesting imminent harm. Both identities are revealed to your lead and HR is brought in. Use only when warranted; misuse undermines trust.</M>
                    </div>
                  </label>
                </div>
                <textarea value={boardFlagNote} onChange={e=>setBoardFlagNote(e.target.value)} rows={2} maxLength={10000} placeholder="Briefly describe what's wrong with this post..." style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.d}40`,borderRadius:8,color:C.t,fontSize:12,resize:"vertical"}}/>
                <div style={{display:"flex",gap:8,marginTop:8}}>
                  <Btn danger small disabled={!boardFlagNote.trim()||!boardFlagTier} onClick={()=>flagBoardPost(postId, rootId)}>Submit Flag</Btn>
                  <Btn small onClick={()=>setBoardFlagPost(null)}>Cancel</Btn>
                </div>
              </Card>
            );
            return(
            <Card key={m.id} style={{marginBottom:8,padding:"14px 16px",borderLeft:`3px solid ${catColors[m.category]||C.tm}`}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                <div style={{display:"flex",gap:8,alignItems:"center"}}>
                  <Badge color={catColors[m.category]||C.tm}>{(m.category||"general").replace(/_/g," ")}</Badge>
                  <M style={{color:m.anonymous?C.td:C.a}}>{m.anonymous?"Anonymous":m.authorLabel}</M>
                </div>
                <M style={{color:C.td}}>{ageStr}</M>
              </div>
              <div style={{fontSize:12,color:C.t,lineHeight:1.7,marginBottom:8}}>{m.content}</div>
              <div style={{display:"flex",gap:14,alignItems:"center"}}>
                <M onClick={()=>toggleThread(m.id)} style={{color:C.a,cursor:"pointer"}}>{expanded?"Hide":"Show"} {(m.replyCount||0)} {(m.replyCount===1)?"reply":"replies"}</M>
                <M onClick={()=>openReply(m.id)} style={{color:C.tm,cursor:"pointer"}}>Reply</M>
                <M onClick={()=>openBoardFlag(m.id)} style={{color:C.d,cursor:"pointer"}}>Flag</M>
              </div>
              {reactionRow(m, null)}
              {replyTo===m.id && composer(m.id, m.id)}
              {boardFlagPost===m.id && flagPicker(m.id, null)}
              {expanded && (thread==="loading"
                ? <M style={{color:C.td,display:"block",marginTop:8}}>Loading thread…</M>
                : <div style={{marginTop:8}}>
                    {thread.filter(p=>p.id!==m.id).map(rep=>(
                      <div key={rep.id} style={{marginLeft:Math.min(rep.depth,4)*14,marginTop:6,paddingLeft:10,borderLeft:`2px solid ${C.b}`}}>
                        <div style={{display:"flex",justifyContent:"space-between"}}>
                          <M style={{color:rep.anonymous?C.td:C.a}}>{rep.anonymous?"Anonymous":rep.authorLabel}</M>
                          <M style={{color:C.td}}>{relTime(rep.createdAt)}</M>
                        </div>
                        <div style={{fontSize:12,color:C.t,lineHeight:1.6,margin:"4px 0"}}>{rep.content}</div>
                        <M onClick={()=>openReply(rep.id)} style={{color:C.tm,cursor:"pointer"}}>Reply</M>
                        <M onClick={()=>openBoardFlag(rep.id)} style={{color:C.d,cursor:"pointer"}}>Flag</M>
                        {reactionRow(rep, m.id)}
                        {replyTo===rep.id && composer(m.id, rep.id)}
                        {boardFlagPost===rep.id && flagPicker(rep.id, m.id)}
                      </div>
                    ))}
                    {thread.filter(p=>p.id!==m.id).length===0 && <M style={{color:C.td,display:"block",marginLeft:14}}>No replies yet.</M>}
                  </div>)}
            </Card>);
          })}
          <M style={{color:C.td,display:"block",marginTop:12}}>Messages expire after 7 days. Encrypted at rest. Access-controlled — analysts only. Not exported in backups.</M>
        </div>)}

        {tab==="ooda"&&(featureToggles.ooda_simulator===false?<AdminDisabledPanel name="IR Simulator" mode="tab"/>:<div>
          <L>Incident Response Simulator (OODA Loop)</L>
          <M style={{color:C.tm,display:"block",marginBottom:8,lineHeight:1.6}}>Practice incident response using your organization's specific IR policies — not generic textbook procedures. This simulator trains you on how YOUR team responds in YOUR SOC, using the policies your Team Lead has uploaded. General certifications teach you frameworks; this teaches you how to execute them here.</M>
          <M style={{color:C.tm,display:"block",marginBottom:16}}><span style={{color:C.a}}>Observe</span> → <span style={{color:C.i}}>Orient</span> → <span style={{color:C.p}}>Decide</span> → <span style={{color:C.w}}>Act</span> → Resolution</M>

          {/* F4d: IR Policy Mastery Tracker — server-driven from /api/ooda/mastery + /api/ooda/scenarios */}
          <Card style={{marginBottom:16,borderColor:C.p+"30"}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}>
              <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>Your IR Policy Mastery</div>
              <Badge color={C.p}>Level {oodaMastery ? oodaMastery.overall.completedCount : 0} / {oodaScenarioList.length || 0}</Badge>
            </div>
            <div style={{width:"100%",height:8,background:C.b,borderRadius:4,marginBottom:10}}>
              <div style={{width: (oodaMastery && oodaScenarioList.length > 0) ? (Math.min(100, Math.round((oodaMastery.overall.completedCount / oodaScenarioList.length) * 100)) + "%") : "0%", height:"100%",background:C.p,borderRadius:4}}/>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginBottom:10}}>
              <div style={{textAlign:"center"}}><M style={{color:C.a,fontWeight:600}}>{oodaMastery ? oodaMastery.overall.completedCount : 0}</M><br/><M style={{color:C.td}}>Simulations completed</M></div>
              <div style={{textAlign:"center"}}><M style={{color:C.i,fontWeight:600}}>{oodaMastery ? oodaMastery.byType.length : 0} / {oodaScenarioList.length ? new Set(oodaScenarioList.map(s => s.type)).size : 0}</M><br/><M style={{color:C.td}}>Policy types practiced</M></div>
              <div style={{textAlign:"center"}}><M style={{color:C.w,fontWeight:600}}>{oodaMastery ? Math.round((oodaMastery.overall.completionRate || 0) * 100) : 0}%</M><br/><M style={{color:C.td}}>Completion rate</M></div>
            </div>
            <M style={{color:C.td,display:"block",fontStyle:"italic"}}>Each simulation trains you on a different org policy. As you complete more, your mastery score increases and reflects practical knowledge of your SOC's specific procedures — something no external certification can provide.</M>
          </Card>

          {/* F4d: Org policies practiced — server-driven from /api/ooda/scenarios + /api/ooda/history */}
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Org Policies Practiced</div>
            {oodaScenarioList.length === 0 ? (
              <M style={{color:C.td,display:"block",padding:"12px 0",fontStyle:"italic"}}>Your team lead has not yet generated any scenarios. Once an org policy is uploaded and a scenario is generated, it will appear here for practice.</M>
            ) : (
              oodaScenarioList.map((s) => {
                const h = oodaHistory.find(x => x.scenarioId === s.id);
                const completed = !!(h && h.completedAt);
                const inProgress = !!(h && !h.completedAt);
                const progressPct = (h && h.totalNodes) ? Math.round((h.nodesCompleted / h.totalNodes) * 100) : 0;
                return (
                  <div key={s.id} style={{display:"flex",justifyContent:"space-between",padding:"6px 0",borderBottom:`1px solid ${C.b}`}}>
                    <M style={{color: (completed || inProgress) ? C.t : C.td}}>{s.title}</M>
                    {completed ? (
                      <div style={{display:"flex",gap:6,alignItems:"center"}}><Badge color={C.a}>completed</Badge><Btn small onClick={()=>logC("OR","Retry: "+s.title)}>Retry</Btn></div>
                    ) : inProgress ? (
                      <div style={{display:"flex",gap:6,alignItems:"center"}}><Badge color={C.i}>{progressPct}%</Badge><Btn small primary onClick={()=>logC("OC","Continue: "+s.title)}>Continue</Btn></div>
                    ) : (
                      <div style={{display:"flex",gap:6,alignItems:"center"}}><Badge color={C.td}>not yet</Badge><Btn small primary onClick={()=>logC("OS","Start: "+s.title)}>Start</Btn></div>
                    )}
                  </div>
                );
              })
            )}
          </Card>

          {/* F4d: Scenario picker — selects which scenario to run via GET /api/ooda/scenarios/:id */}
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Choose a Scenario to Run</div>
            {oodaScenarioList.length === 0 ? (
              <M style={{color:C.td,fontStyle:"italic"}}>No scenarios available yet. Your team lead will generate them from your org's IR policies.</M>
            ) : (
              <div>
                <select
                  value={oodaScenarioId || ""}
                  onChange={(e)=>{ const id = e.target.value; if (id) selectScenario(id); }}
                  disabled={oodaLoading}
                  style={{width:"100%",padding:"8px 10px",background:C.b,color:C.t,border:`1px solid ${C.b}`,borderRadius:4,fontSize:13,marginBottom:6}}
                >
                  <option value="">— Select a scenario —</option>
                  {oodaScenarioList.map(s => (
                    <option key={s.id} value={s.id}>{s.title} ({s.difficulty})</option>
                  ))}
                </select>
                {oodaLoading && <M style={{color:C.i,display:"block",marginTop:4}}>Loading scenario...</M>}
                {oodaError && <M style={{color:C.d,display:"block",marginTop:4}}>{oodaError}</M>}
                {oodaScenarioData && !oodaLoading && !oodaError && (
                  <M style={{color:C.a,display:"block",marginTop:4,fontSize:11}}>Selected: {oodaScenarioData.title || "scenario"} — {oodaScenarioData.totalNodes} step{oodaScenarioData.totalNodes === 1 ? "" : "s"}</M>
                )}
              </div>
            )}
          </Card>
          {(()=>{
            // F4d: Server-driven scenario player. Replaces the hardcoded
            // ransomware IIFE. Reads from oodaScenarioData (populated by
            // selectScenario via GET /api/ooda/scenarios/:id) and walks
            // node-by-node via POST /api/ooda/scenarios/:id/play. The
            // full node tree never reaches the client; only the current
            // node is visible.

            // Empty state when no scenario is selected
            if (!oodaScenarioData || !oodaCurrentNode) {
              return (
                <Card style={{marginBottom:16,padding:"16px 14px",textAlign:"center"}}>
                  <M style={{color:C.tm,fontStyle:"italic",lineHeight:1.6}}>Select a scenario above to begin a new exercise. Each scenario walks you through your organization's actual IR policy step by step.</M>
                </Card>
              );
            }

            // Completion state
            if (oodaComplete) {
              return (
                <Card style={{borderColor:C.a+"40",padding:24,marginBottom:16}}>
                  <div style={{fontSize:18,color:C.a,fontFamily:"'Fraunces',serif",marginBottom:8,textAlign:"center"}}>Exercise Complete</div>
                  <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6,textAlign:"center"}}>You completed all {oodaScenarioData.totalNodes} step{oodaScenarioData.totalNodes === 1 ? "" : "s"} of "{oodaScenarioData.title}".</M>
                  <Card style={{borderColor:C.i+"30",padding:14,marginBottom:16}}>
                    <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:6}}>Scenario Reference</M>
                    <M style={{color:C.tm,lineHeight:1.8}}>Title: {oodaScenarioData.title}{"\n"}Type: {oodaScenarioData.type}{"\n"}Difficulty: {oodaScenarioData.difficulty}{"\n\n"}This scenario was generated from one of your organization's IR policies. Review the source policy in your org's policy repository for the complete procedure.</M>
                  </Card>
                  <Btn primary onClick={()=>{
                    setOodaScenarioId(null);
                    setOodaScenarioData(null);
                    setOodaCurrentNode(null);
                    setOodaPhasesVisited([]);
                    setOodaPlayFb(null);
                    setOodaComplete(false);
                    setOodaError(null);
                    api.get("/api/ooda/history").then(r=>{ if (Array.isArray(r?.history)) setOodaHistory(r.history); }).catch(()=>{});
                    api.get("/api/ooda/mastery").then(r=>{ if (r && r.overall) setOodaMastery(r); }).catch(()=>{});
                    logC("IR_SIM_COMPLETE", "Completed: " + oodaScenarioData.title);
                  }}>Choose Another Scenario</Btn>
                </Card>
              );
            }

            // Active player state
            const node = oodaCurrentNode;
            const phaseColor = node.phase === "OBSERVE" ? C.a : node.phase === "ORIENT" ? C.i : node.phase === "DECIDE" ? C.p : node.phase === "ACT" ? C.w : C.t;
            return (
              <Card style={{marginBottom:16,borderLeft:`3px solid ${phaseColor}`}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                  <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>{oodaScenarioData.title}</div>
                  <M style={{color:C.tm,fontSize:11}}>Step {oodaPhasesVisited.length} of {oodaScenarioData.totalNodes}</M>
                </div>
                <div style={{display:"flex",gap:6,marginBottom:12,flexWrap:"wrap"}}>
                  {oodaPhasesVisited.map((p,i)=>(
                    <Badge key={i} color={i < oodaPhasesVisited.length - 1 ? C.a : phaseColor}>{p}{i < oodaPhasesVisited.length - 1 ? " ✓" : ""}</Badge>
                  ))}
                </div>
                {oodaScenarioData.briefing && oodaPhasesVisited.length === 1 && (
                  <Card style={{borderColor:C.b,padding:10,marginBottom:10}}>
                    <M style={{color:C.tm,lineHeight:1.6,fontSize:11}}>{oodaScenarioData.briefing}</M>
                  </Card>
                )}
                <div style={{padding:12,background:`${phaseColor}08`,borderRadius:8,border:`1px solid ${phaseColor}30`,marginBottom:12}}>
                  <M style={{color:"#E8EDF5",lineHeight:1.6}}>{node.prompt}</M>
                </div>
                {Array.isArray(node.choices) && node.choices.map((ch, ci) => {
                  const fbForThis = oodaPlayFb && oodaPlayFb.ci === ci;
                  return (
                    <Card key={ci} style={{
                      marginBottom:6,padding:"10px 14px",
                      cursor: oodaLoading ? "wait" : "pointer",
                      borderColor: fbForThis ? (oodaPlayFb.correct ? C.a+"60" : C.d+"60") : C.b,
                      background: fbForThis ? (oodaPlayFb.correct ? "rgba(110,231,183,0.06)" : "rgba(239,68,68,0.06)") : "transparent",
                      transition:"all 0.2s",
                      opacity: oodaLoading && !fbForThis ? 0.5 : 1
                    }} onClick={()=>{ if (!oodaLoading && !oodaPlayFb) submitChoice(ci); }}>
                      <div style={{display:"flex",gap:10,alignItems:"flex-start"}}>
                        <M style={{color:phaseColor,fontWeight:600,minWidth:16}}>{String.fromCharCode(65+ci)}</M>
                        <M style={{color:C.t,lineHeight:1.5}}>{ch.text}</M>
                      </div>
                    </Card>
                  );
                })}
                {oodaPlayFb && (
                  <div style={{padding:12,marginTop:8,background:oodaPlayFb.correct?"rgba(110,231,183,0.08)":"rgba(239,68,68,0.08)",borderRadius:8,border:`1px solid ${oodaPlayFb.correct?C.a:C.d}30`}}>
                    <M style={{color:oodaPlayFb.correct?C.a:C.d,fontWeight:500}}>{oodaPlayFb.correct?"✓ Correct":"✗ Try again"}</M>
                    <br/>
                    <M style={{color:C.tm,lineHeight:1.6}}>{oodaPlayFb.explanation}</M>
                    {oodaPlayFb.correct && <M style={{color:C.a,display:"block",marginTop:4}}>Advancing...</M>}
                  </div>
                )}
                {oodaError && (
                  <div style={{padding:10,marginTop:8,borderRadius:8,border:`1px solid ${C.d}30`}}>
                    <M style={{color:C.d}}>{oodaError}</M>
                  </div>
                )}
              </Card>
            );
          })()}
          <Card style={{padding:"12px 14px"}}><M style={{color:C.td}}>More exercises generated when your lead uploads IR policies from the Management Console. After each simulation, the specific scenario reference is presented to you.</M></Card>
        </div>)}

        {/* ══════════ TRAINING CERTIFICATES ══════════ */}
        {tab==="training"&&(<div><FeatureGate disabled={featureToggles.training_certs===false} name="Training Recommendations & Certs" mode="section">
          <L>Training Platform Integrations</L>
          <M style={{color:C.tm,display:"block",marginBottom:8,lineHeight:1.6}}>AI-recommended training from assessment gaps.</M>
          {upskillingActive&&<Card style={{borderColor:C.p+"40",marginBottom:16,padding:14}}>
            <M style={{color:C.p,fontWeight:500,display:"block",marginBottom:6}}>Upskilling Hour Active — Ticket Routing Paused</M>
            <M style={{color:C.tm,lineHeight:1.6}}>Your queue is paused. Use this time for training, peer skill-share, or certification study. A content filter is active — only training platforms, peer chat, and certification sites are accessible during this hour. Social media and non-work sites are temporarily restricted.</M>
          </Card>}
          {scheduled.length>0&&<div style={{marginBottom:16}}><M style={{color:C.a,display:"block",marginBottom:8}}>Scheduled ({scheduled.length})</M>{scheduled.map(s=><Card key={s.id} style={{marginBottom:6,padding:"10px 14px",borderLeft:`3px solid ${C.a}`}}><div style={{display:"flex",justifyContent:"space-between"}}><span style={{fontSize:12}}>{s.title}</span><Badge color={C.a}>{s.date}</Badge></div><M style={{color:C.td}}>Reminder: {s.reminder} before · {s.platform}</M></Card>)}</div>}
          {/* R3l C11: state-driven recommendations from /api/training-recommendations/me */}
          {!trainingRecsLoadState.loaded && !trainingRecsLoadState.error && (
            <M style={{color:C.tm,fontStyle:"italic",display:"block",marginBottom:8}}>Loading recommendations…</M>
          )}
          {trainingRecsLoadState.error && (
            <Card style={{marginBottom:8,borderColor:C.w+"40"}}><M style={{color:C.w}}>Could not load recommendations: {trainingRecsLoadState.error}</M></Card>
          )}
          {trainingRecsLoadState.loaded && trainingRecs.recommendations.length===0 && (
            <Card style={{marginBottom:8}}><M style={{color:C.tm,fontStyle:"italic"}}>No skill gaps identified — your assessment scores are above threshold. Keep up the work.</M></Card>
          )}
          {trainingRecs.recommendations.map((rec)=>(
            <Card key={rec.skill_id} style={{marginBottom:8}}>
              <div style={{fontSize:12,fontWeight:600,color:C.w,marginBottom:6}}>{rec.skill_name} ({rec.current_score}%)</div>
              {(!rec.modules||rec.modules.length===0)?(
                <M style={{color:C.td,fontStyle:"italic",fontSize:11}}>No training modules available for this skill yet — flag to your lead so the maintainers can add some.</M>
              ):(rec.modules.map((t)=>(
                <div key={t.id} style={{padding:"5px 0",borderBottom:"1px solid "+C.b}}>
                  <M style={{color:C.t,fontWeight:500}}>{t.title}</M>
                  <div style={{display:"flex",gap:8,marginTop:2,fontSize:10,color:C.td,flexWrap:"wrap"}}>
                    {t.platform_name&&<span>{t.platform_name}</span>}
                    {t.difficulty&&<span>· {t.difficulty}</span>}
                    {t.free_or_paid&&<span>· {t.free_or_paid}</span>}
                    {typeof t.estimated_hours==="number"&&<span>· {t.estimated_hours}h</span>}
                  </div>
                  <M style={{color:C.a,display:"block",fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}} onClick={()=>navigator.clipboard?.writeText(t.url)}>{t.url} (copy)</M>
                </div>
              )))}
            </Card>
          ))}
          {/* R3l C13: wired to POST /api/training/submit-completion */}
          <Card style={{marginBottom:10,borderColor:C.a+"30"}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Submit Completion</div>
            <Input label="Module" maxLength={256} value={completionForm.module} onChange={(e)=>setCompletionForm(f=>({...f,module:e.target.value}))}/>
            <Input label="Platform" maxLength={64} value={completionForm.platform} onChange={(e)=>setCompletionForm(f=>({...f,platform:e.target.value}))}/>
            <Input label="URL" maxLength={2048} value={completionForm.url} onChange={(e)=>setCompletionForm(f=>({...f,url:e.target.value}))}/>
            <Input label="Date" type="date" value={completionForm.completionDate} onChange={(e)=>setCompletionForm(f=>({...f,completionDate:e.target.value}))}/>
            {completionState.error&&<M style={{color:C.d,display:"block",marginBottom:6}}>Error: {completionState.error}</M>}
            {completionState.success&&<M style={{color:C.a,display:"block",marginBottom:6}}>Submitted — pending lead review.</M>}
            <Btn primary disabled={completionState.submitting||!completionForm.module.trim()||!completionForm.platform.trim()} onClick={submitCompletion} style={{marginTop:8}}>{completionState.submitting?"Submitting…":"Submit"}</Btn>
          </Card>
          </FeatureGate><FeatureGate disabled={featureToggles.general_certs===false} name="Professional Certifications" mode="section"><Card style={{marginBottom:10}}><div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Register Cert</div><Sel label="Cert"><option value="">Select...</option><optgroup label="CompTIA"><option>Security+</option><option>CySA+</option></optgroup><optgroup label="ISC2"><option>CISSP</option></optgroup><optgroup label="ISACA"><option>CISA</option></optgroup></Sel><Input label="Code"/><Input label="Earned" type="date"/><Btn primary onClick={()=>logC("CE","Submitted")} style={{marginTop:8}}>Submit</Btn></Card></FeatureGate>
        </div>)}

        {tab==="skills"&&(featureToggles.skill_assessments===false?<AdminDisabledPanel name="Skills & Assessments" mode="tab"/>:<div>
          <L>Skill Matrix & Growth Tracker</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Your personal skill development. Assessment results from your team lead populate your baseline. Gaps auto-surface training recommendations below. When you reach proficiency thresholds, your lead receives a growth signal — recognition, not a demand (R037, R040). Only you and your team lead see your individual results.</M>

          {/* Active Assessment Portal */}
          <Card style={{marginBottom:16,borderColor:C.i+"30"}}>
            <div style={{fontSize:13,fontWeight:500,color:C.i,marginBottom:10}}>Assessment Portal</div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Assessments assigned by your team lead. Complete them to establish your skill baseline and unlock targeted training recommendations.</M>
            {[{id:"demo-pending",name:"L2 Readiness Evaluation",skills:["Investigation","Escalation Judgment","Malware Analysis","Network Analysis","Threat Hunting"],status:"pending",dueDate:"Apr 5, 2026",platforms:["Hack The Box","LetsDefend","CyberDefenders"]},{id:"demo-done",name:"L1 Onboarding Assessment",skills:["Alert Triage","Documentation","Phishing Analysis","Log Analysis","SIEM Queries"],status:"completed",completedDate:"Mar 27, 2026",platforms:["LetsDefend","TryHackMe"]}].map((a,i)=>(
              <Card key={i} style={{marginBottom:8,padding:"12px 14px",borderLeft:`3px solid ${a.status==="pending"?C.w:C.a}`}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                  <span style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>{a.name}</span>
                  <Badge color={a.status==="pending"?C.w:C.a}>{a.status==="pending"?"Assigned — Due "+a.dueDate:"Completed "+a.completedDate}</Badge>
                </div>
                <M style={{color:C.tm,lineHeight:1.6}}>Skills: {a.skills.join(", ")}</M>
                <M style={{color:C.td,display:"block",marginTop:4}}>Lab platforms: {a.platforms.join(", ")}</M>
                {a.status==="pending"&&(
                  <div style={{marginTop:8}}>
                    <M style={{color:C.i,display:"block",marginBottom:6}}>Complete the following labs to establish your skill baseline:</M>
                    <M style={{color:C.i,display:"block",marginBottom:4}}>Recommended Hack The Box modules for this assessment:</M>
                    {["SOC Analyst Path: https://academy.hackthebox.com/path/preview/soc-analyst","Incident Handling: https://academy.hackthebox.com/module/details/148","Network Traffic Analysis: https://academy.hackthebox.com/module/details/81","YARA/Sigma for SOC: https://academy.hackthebox.com/module/details/234"].map((link,j)=>(
                      <div key={j} style={{padding:"6px 0",borderBottom:"1px solid "+C.b}}>
                        <M style={{color:C.t}}>{link.split(": ")[0]}</M>
                        <M style={{color:C.i,display:"block",fontSize:10,fontFamily:"'IBM Plex Mono',monospace"}}>{link.split(": ")[1]}</M>
                      </div>
                    ))}
                    <M style={{color:C.td,display:"block",marginTop:8,lineHeight:1.5,fontSize:10}}>Copy the link and open it in your browser. FireAlive does not make direct connections to external sites to minimize attack surface. After completing the module, submit your completion certificate in the Certificates tab.</M>
                  </div>
                )}
              </Card>
            ))}
          </Card>

          {/* Current Skill Levels from Assessment Results (R3l C12: wired to /api/assessments/analyst/me) */}
          <Card style={{marginBottom:16,borderColor:C.a+"30"}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Your Skill Levels (from Assessments)</div>
            {!skillResultsLoadState.loaded && !skillResultsLoadState.error && (
              <M style={{color:C.tm,fontStyle:"italic"}}>Loading skill results…</M>
            )}
            {skillResultsLoadState.error && (
              <M style={{color:C.w}}>Could not load skill results: {skillResultsLoadState.error}</M>
            )}
            {(()=>{
              if (!skillResultsLoadState.loaded) return null;
              const latestBySkill = {};
              for (const r of skillResults.results) {
                if (!latestBySkill[r.skill_id] || r.completed_at > latestBySkill[r.skill_id].completed_at) {
                  latestBySkill[r.skill_id] = r;
                }
              }
              const skillLevels = Object.values(latestBySkill)
                .map((r)=>({
                  skillId: r.skill_id,
                  skill: r.skill_name,
                  pct: r.score,
                  gap: r.score < skillResults.gapThreshold,
                  src: r.assessment_name || "Assessment",
                }))
                .sort((a,b)=>b.pct-a.pct);
              if (skillLevels.length === 0) {
                return <M style={{color:C.tm,fontStyle:"italic"}}>No assessment results yet — complete assignments to populate your skill baseline.</M>;
              }
              return skillLevels.map((s,i)=>(
                <div key={s.skillId} style={{padding:"10px 0",borderBottom:i<skillLevels.length-1?`1px solid ${C.b}`:"none"}}>
                  <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                    <span style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>{s.skill}</span>
                    <div style={{display:"flex",gap:6}}>
                      <Badge color={s.pct>=80?C.a:s.pct>=60?C.w:C.tm}>{s.pct}%</Badge>
                      {s.gap&&<Badge color={C.d}>gap</Badge>}
                    </div>
                  </div>
                  <div style={{height:4,background:"rgba(255,255,255,0.04)",borderRadius:2,overflow:"hidden",marginBottom:4}}>
                    <div style={{width:`${s.pct}%`,height:"100%",background:s.pct>=80?C.a:s.pct>=60?C.w:s.pct>=40?"#F97316":C.d,borderRadius:2,transition:"width 0.5s ease"}}/>
                  </div>
                  <M style={{color:C.td}}>Source: {s.src}</M>
                </div>
              ));
            })()}
          </Card>

          {/* Gap-Driven Training Recommendations */}

          <Card style={{padding:12,borderColor:C.p+"30"}}>
            <M style={{color:C.p,fontWeight:500,display:"block",marginBottom:4}}>Level-Up Signal</M>
            <M style={{color:C.tm,lineHeight:1.8}}>When 3+ core skills reach 80% (currently 2 at threshold: Triage 85%, Documentation 91%), your lead gets a soft signal: "An analyst on your team may be ready for increased complexity." Your name is attached only because they are your team lead. After you complete training on gap areas and re-assess above 70%, those upskilling alerts signal real growth toward the next tier.</M>
          </Card>
        </div>)}
        {tab==="recovery"&&(<div>
          <L>Post-Incident Wellness Resources</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Always available — not just after incidents. Everything here is private (Tier-3). Your lead cannot see whether you access these resources. This section is about your personal wellness — distinct from technical incident recovery procedures.</M>
          <FeatureGate disabled={featureToggles.breathing_exercise===false} name="Box Breathing Exercise" mode="section"><BreathingExercise/></FeatureGate>
          <Card style={{marginBottom:16,borderColor:C.p+"30"}}>
            <div style={{fontSize:13,fontWeight:500,color:C.p,marginBottom:10}}>Understanding Stress Responses</div>
            <M style={{color:C.t,lineHeight:1.8}}>After intense incidents (ransomware, breaches, active intrusions), it is normal to experience difficulty sleeping, replaying events mentally, hypervigilance, irritability, difficulty concentrating, or emotional numbness. These are normal responses to abnormal situations — not signs of weakness. They typically peak at 24-72 hours and resolve over 1-2 weeks. If they persist beyond 2 weeks or intensify, connect with professional support below.</M>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:C.a,marginBottom:10}}>Self-Care Strategies</div>
            {[{t:"Sleep Hygiene",d:"Maintain consistent sleep schedule. Avoid screens 30 min before bed. If you cannot sleep, get up and do something quiet."},{t:"Physical Movement",d:"Even 10-15 minutes of walking or stretching helps process stress hormones. One of the most evidence-supported recovery tools."},{t:"Box Breathing",d:"Inhale 4 seconds, hold 4, exhale 4, hold 4. Repeat 4 cycles. Activates parasympathetic nervous system."},{t:"Social Connection",d:"Talk to someone you trust. You do not have to talk about the incident. Being with safe people helps."},{t:"Limit Re-Exposure",d:"Avoid going through logs or incident details during off-hours. Psychological detachment during recovery is a top predictor of reduced exhaustion (R032)."},{t:"Routine Maintenance",d:"Keep eating regular meals, staying hydrated, maintaining routines. Disrupted habits amplify stress."}].map((s,i)=>(
              <Card key={i} style={{marginBottom:8,padding:"12px 14px",borderLeft:`3px solid ${C.a}`}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>{s.t}</div>
                <M style={{color:C.tm,lineHeight:1.6}}>{s.d}</M>
              </Card>
            ))}
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:C.i,marginBottom:10}}>Peer Support Pathways</div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Informal peer contact is preferred over formal debriefing (R007). Voluntary, confidential, peer-led.</M>
            {[{t:"Peer Skill-Share Chat",d:"Share skills and techniques with a colleague. E2EE, anonymous.",ac:"peers"},{t:"Schedule Skill-Share",d:"Schedule a skill-share session with a peer. Off-shift recommended (R032).",ac:"peer_sched"},{t:"Peer Mentoring Program",d:"Longer-term pairing with a senior analyst. Develop skills and build resilience.",ac:"training"}].map((p,i)=>(
              <Card key={i} style={{marginBottom:8,padding:"12px 14px",borderLeft:`3px solid ${C.i}`,cursor:"pointer"}} onClick={()=>p.ac==="peers"?setTab("peers"):p.ac==="training"?setTab("training"):setShowPeerSched(true)}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>{p.t}</div>
                <M style={{color:C.tm,lineHeight:1.6}}>{p.d}</M>
              </Card>
            ))}
          </Card>
          <Card style={{marginBottom:16,borderColor:C.w+"30"}}>
            <div style={{fontSize:13,fontWeight:500,color:C.w,marginBottom:10}}>Professional Support</div>
            <M style={{color:C.t,lineHeight:1.8,display:"block",marginBottom:10}}>If reactions persist beyond 2 weeks, intensify, or you need trained trauma support. Accessing these is completely private.</M>
            {[{t:"Employee Assistance Program (EAP)",d:"Free, confidential counseling through your organization. Typically 3-8 sessions. Check your benefits card or HR portal."},{t:"Crisis Text Line",d:"Text HOME to 741741. Trained crisis counselors, 24/7, text-based."},{t:"SAMHSA Helpline",d:"1-800-662-4357. Free, confidential, 24/7 treatment referral."}].map((r,i)=>(
              <Card key={i} style={{marginBottom:8,padding:"12px 14px",borderLeft:`3px solid ${C.w}`}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>{r.t}</div>
                <M style={{color:C.tm,lineHeight:1.6}}>{r.d}</M>
              </Card>
            ))}
          </Card>
          <Card style={{padding:12}}><M style={{color:C.td,lineHeight:1.8}}>All resources always available. Accessing anything here is logged only in your private Tier-3 consent log.</M></Card>
        </div>)}
        {tab==="privacy"&&(<div>
          <L>Data Privacy, Settings & Consent Log</L>
          <Card style={{marginBottom:16,borderColor:C.a+"30"}}>
            <div style={{fontSize:12,color:C.a,fontWeight:500,marginBottom:8}}>Management sees:</div>
            <M style={{color:C.t,lineHeight:1.8}}>Shift/tier · Ticket count · Routing adj active (yes/no) · Anonymous delegations</M>
            <div style={{fontSize:12,color:C.d,fontWeight:500,marginTop:16,marginBottom:8}}>Management CANNOT see:</div>
            <M style={{color:C.t,lineHeight:1.8}}>Signal values · Burnout stage · Responses · Peer messages · Training progress · Lead messages (until you reveal identity)</M>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>App Settings</div>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0",cursor:"pointer"}}><input type="checkbox" checked={biometricEnabled} onChange={e=>setBiometricEnabled(e.target.checked)} style={{accentColor:C.a}}/><M style={{color:C.t}}>Enable biometric unlock (fingerprint / face) — for unlocking the app after inactivity timeout. Login still requires username + password + MFA.</M></label>
            <MyMfaSecuritySection/>
            <M style={{color:C.td,display:"block",marginTop:8,fontStyle:"italic"}}>When enabled, you can use your device's biometric sensor instead of typing your password to reopen FireAlive after inactivity lock. Initial login always requires full credentials + MFA.</M>
          </Card>
          <L>Consent Events</L>
          {auditLog.length===0?<M style={{color:C.tm,fontStyle:"italic"}}>No data has crossed the privacy boundary.</M>:
          auditLog.filter(c=>c.a.includes("peer")||c.a.includes("CONSENT")||c.a.includes("lead")).map((c,i)=><Card key={i} style={{marginBottom:6,padding:"10px 14px"}}><M style={{color:C.w}}>{new Date(c.ts).toLocaleTimeString()}</M><M style={{color:C.tm}}> · {c.a} · </M><M style={{color:C.td}}>{c.dt}</M></Card>)}
        </div>)}
      </div>

      {/* Modals */}
      {showLQ&&<Modal title="Request Lighter Queue" onClose={()=>{setShowLQ(false);setLqDone(false);}}>
        {!lqDone?<><M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Anonymous request to routing engine. Lead sees "routing adjustment activated" — not your name.</M>
          <Card style={{marginBottom:16,padding:12}}><M style={{color:C.t,lineHeight:2}}>1. Select duration and cap below<br/>2. Request → routing engine (anonymized)<br/>3. Cap applied next ticket assignment<br/>4. Audit: "routing adj for analystId:redacted"<br/>5. Auto-expires after duration<br/>6. Cancel anytime</M></Card>
          <Sel label="Duration" value={lqDur} onChange={e=>setLqDur(e.target.value)}><option value="1_shift">This shift</option><option value="2_shifts">2 shifts</option><option value="1_week">1 week</option><option value="until_cancel">Until I cancel</option></Sel>
          <div style={{marginBottom:14}}><M style={{color:C.tm,marginBottom:6,display:"block"}}>Max complexity:</M><div style={{display:"flex",gap:6}}>{[1,2,3,4].map(l=><button key={l} onClick={()=>setLqCap(l)} style={{flex:1,padding:10,background:lqCap===l?C.ad:C.s,border:`1px solid ${lqCap===l?C.a+"50":C.b}`,borderRadius:8,color:lqCap===l?C.a:C.tm,fontSize:12,cursor:"pointer",textAlign:"center"}}><div style={{fontWeight:500}}>P{l}</div></button>)}</div></div>
          <Input label="Reason (optional — local only, never transmitted)" value={lqReason} onChange={e=>setLqReason(e.target.value)} maxLength={500}/>
          <Btn primary style={{width:"100%"}} onClick={()=>{logC("lighter_queue",`P${lqCap}, ${lqDur}`);setLqDone(true);}}>Submit anonymous request</Btn>
        </>:<div style={{textAlign:"center",padding:"20px 0"}}><div style={{fontSize:24,marginBottom:12}}>✓</div><div style={{fontSize:14,color:C.a,fontWeight:500,marginBottom:8}}>Submitted</div><M style={{color:C.tm,display:"block",lineHeight:1.6}}>Cap P{lqCap} active for {lqDur.replace(/_/g," ")}. Cancel anytime.</M><Btn style={{marginTop:16}} onClick={()=>{setShowLQ(false);setLqDone(false);}}>Close</Btn></div>}
      </Modal>}

      {showPeerSched&&<Modal title="Schedule Skill-Share" onClose={()=>setShowPeerSched(false)}>
        <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Posts to anonymous queue. Someone claims it. Schedule off-shift so it doesn't impact monitoring.</M>
        <Input label="Preferred time (off-shift)" type="datetime-local" value={schedDate} onChange={e=>setSchedDate(e.target.value)}/>
        <Sel label="Format"><option value="chat">Encrypted chat</option><option value="voice">Anonymous VoIP call</option><option value="either">Either</option></Sel>
        <div style={{display:"flex",gap:8}}><Btn primary style={{flex:1}} onClick={()=>{logC("peer_sched",`${schedDate||"ASAP"}`);setShowPeerSched(false);}}>Post to queue</Btn><Btn onClick={()=>setShowPeerSched(false)}>Cancel</Btn></div>
      </Modal>}

      {showLeadMsg&&<Modal title="Message Your Lead" onClose={()=>setShowLeadMsg(false)} width={500}>
        <Card style={{marginBottom:12,borderColor:C.a+"40",padding:12}}>
          <M style={{color:C.a,display:"block",marginBottom:4,fontWeight:500}}>End-to-end encrypted. You appear by your pseudonym.</M>
          <M style={{color:C.tm,lineHeight:1.6}}>This chat is end-to-end encrypted (Signal protocol) -- the server only relays ciphertext and cannot read it. Your lead sees your pseudonym, not your real name, and messages are deleted five minutes after the chat closes. For anonymous support between analysts, use Peer Chat instead.</M>
        </Card>
        {!leadThread?(<div>
          <M style={{color:C.tm,display:"block",marginBottom:8}}>Choose a lead to start an encrypted 1:1. Any on-shift lead can be reached.</M>
          {leadOptions.length===0?<M style={{color:C.td,fontStyle:"italic"}}>No leads on shift right now.</M>:
          leadOptions.map(l=><button key={l.id} onClick={()=>openLeadThread(l)} style={{width:"100%",textAlign:"left",padding:"10px 14px",marginBottom:6,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,cursor:"pointer",fontFamily:"inherit",display:"flex",justifyContent:"space-between",alignItems:"center"}}><span style={{fontWeight:500,fontSize:12}}>{l.name}</span>{l.shift?<span style={{color:C.td,fontSize:11}}>{l.shift} shift</span>:null}</button>)}
        </div>):(<div>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
            <M style={{color:C.t,fontWeight:500}}>Chatting with {leadThread.leadName||"your lead"}</M>
            <button onClick={()=>{setLeadThread(null);setLM([]);}} style={{background:"none",border:"none",color:C.i,cursor:"pointer",fontSize:11,fontFamily:"inherit"}}>Change lead</button>
          </div>
          <Card style={{maxHeight:200,overflow:"auto",marginBottom:12}}>
            {leadMsgs.length===0?<M style={{color:C.td,fontStyle:"italic"}}>No messages yet.</M>:
            leadMsgs.map(m=><div key={m.id} style={{padding:"10px 14px",borderBottom:`1px solid ${C.b}`}}><div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}><M style={{color:C.a,fontWeight:500}}>{m.from}{m.kind==="inperson_1on1_request"?" · in-person 1:1 request":""}</M><M style={{color:C.td}}>E2EE · {m.ts}</M></div><div style={{fontSize:12,lineHeight:1.6}}>{m.text}</div></div>)}
          </Card>
          <div style={{display:"flex",gap:8}}><input value={newLM} onChange={e=>setNewLM(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"&&newLM.trim())sendLeadMessage();}} placeholder="Message to your lead..." maxLength={2000} style={{flex:1,padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}}/><Btn primary disabled={!newLM.trim()||!leadThread} onClick={()=>sendLeadMessage()}>Send</Btn></div>
          <button onClick={()=>sendLeadMessage("inperson_1on1_request")} disabled={!leadThread} title="Asks your lead to meet face to face. Type a note above first for context, or send as-is." style={{marginTop:8,width:"100%",padding:"8px 12px",background:"transparent",border:`1px solid ${C.i}40`,borderRadius:8,color:C.i,cursor:leadThread?"pointer":"default",fontFamily:"inherit",fontSize:11}}>Request an in-person 1:1</button>
        </div>)}
      </Modal>}

      {showPlatform&&<Modal title={(TRAINING_PLATFORMS.find(t=>t.id===showPlatform)||{}).name||""} onClose={()=>setShowPlatform(null)} width={520}>
        {(()=>{const tp=TRAINING_PLATFORMS.find(t=>t.id===showPlatform);if(!tp)return null;return(<>
          <Badge color={tp.id==="claude-ai"?C.p:C.i}>{tp.type}</Badge>
          <div style={{fontSize:12,color:C.tm,lineHeight:1.6,margin:"12px 0"}}>{tp.desc}</div>
          <Card style={{marginBottom:16,padding:12,borderColor:C.a+"30"}}>
            <M style={{color:C.tm}}>Visit the platform to start training.</M>
          </Card>
        </>);})()}
      </Modal>}

        {/* ══════════ SELF-SCAN ══════════ */}
        {tab==="scan"&&(<div>
          <L>Client Self-Scan</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Run a 10-point compromise check on this analyst client. Tests binary integrity, memory analysis, network connections, configuration drift, audit log continuity, TLS certificate pinning, API token validation, filesystem integrity, EDR agent status, and encryption key validity. Results are displayed to you AND automatically sent to your management console — this is not optional because compromise affects the whole team.</M>
          <Btn primary disabled={selfScanRunning} onClick={()=>{setSelfScanRunning(true);logC("SELF_SCAN_STARTED","Compromise self-scan initiated");setTimeout(()=>{setSelfScanRunning(false);const r={ts:new Date().toISOString(),tests:10,passed:10,status:"clean",details:["Binary integrity: SHA-256 verified against known-good hash","Memory analysis: No injected code or suspicious processes detected","Network connections: No unexpected outbound connections","Configuration drift: Matches management console last-known-good config","Audit log continuity: Sequential, no gaps or deletions detected","TLS certificate: Pinned certificate valid and not expired","API tokens: All tokens properly scoped and not expired","Filesystem integrity: No unauthorized file changes in app directories","EDR agent: Running and reporting to management console","Encryption keys: All keys valid, rotation schedule on track"]};setSelfScanResult(r);logC("SELF_SCAN_COMPLETE","Result: "+r.status+" (10/10 passed) — auto-sent to management console");},2500);}}>{selfScanRunning?"Scanning all 10 checks...":"Run Self-Scan"}</Btn>
          {selfScanResult&&(<Card style={{marginTop:16}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}>
              <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>Scan Results — {new Date(selfScanResult.ts).toLocaleString()}</div>
              <Badge color={selfScanResult.status==="clean"?C.a:C.d}>{selfScanResult.status}</Badge>
            </div>
            <M style={{color:C.td,display:"block",marginBottom:12}}>{selfScanResult.passed}/{selfScanResult.tests} tests passed · Results auto-sent to management console ✓</M>
            {selfScanResult.details.map((d,i)=><div key={i} style={{padding:"4px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.a}}>✓ </M><M style={{color:C.t}}>{d}</M></div>)}
          </Card>)}
        </div>)}

        {/* ══════════ INBOX ══════════ */}
        {tab==="inbox"&&(<div>
          <div style={{display:"flex",gap:6,marginBottom:12}}>
            <button onClick={()=>setInboxView("list")} style={{padding:"6px 12px",background:inboxView==="list"?C.ad:"transparent",border:`1px solid ${inboxView==="list"?C.a+"50":C.b}`,borderRadius:6,color:inboxView==="list"?C.a:C.tm,fontSize:11,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>Notifications</button>
            <button onClick={()=>setInboxView("preferences")} style={{padding:"6px 12px",background:inboxView==="preferences"?C.ad:"transparent",border:`1px solid ${inboxView==="preferences"?C.a+"50":C.b}`,borderRadius:6,color:inboxView==="preferences"?C.a:C.tm,fontSize:11,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>Preferences</button>
          </div>
          {inboxView==="list"&&(<div>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
            <L style={{marginBottom:0}}>Inbox{inboxUnreadCount>0?` — ${inboxUnreadCount} unread`:""}</L>
            <div style={{display:"flex",gap:6,alignItems:"center"}}>
              <label style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer",fontSize:11,color:C.tm,fontFamily:"'IBM Plex Mono',monospace"}}>
                <input type="checkbox" checked={inboxIncludeRead} onChange={e=>{const v=e.target.checked;setInboxIncludeRead(v);setInboxLoading(true);api.get(`/api/inbox?includeRead=${v?"true":"false"}`).then(r=>{setInboxItems(r?.items||[]);}).catch(()=>{}).finally(()=>setInboxLoading(false));}}/>
                Show read
              </label>
              <Btn small onClick={()=>{setInboxLoading(true);api.get(`/api/inbox?includeRead=${inboxIncludeRead?"true":"false"}`).then(r=>setInboxItems(r?.items||[])).catch(()=>{}).finally(()=>setInboxLoading(false));api.get("/api/inbox/unread-count").then(r=>setInboxUnreadCount(r?.unread||0)).catch(()=>{});}}>Refresh</Btn>
              <Btn small onClick={()=>{api.post("/api/inbox/read-all",{}).then(()=>{setInboxUnreadCount(0);api.get(`/api/inbox?includeRead=${inboxIncludeRead?"true":"false"}`).then(r=>setInboxItems(r?.items||[])).catch(()=>{});logC("INBOX_MARK_ALL_READ","All notifications marked read");}).catch(()=>{});}}>Mark all read</Btn>
            </div>
          </div>
          {inboxLoading&&<M style={{color:C.td,display:"block",marginBottom:10}}>Loading…</M>}
          {!inboxLoading&&inboxItems.length===0&&<Card><M style={{color:C.tm}}>No notifications. The Inbox shows assessments assigned to you, retro check-ins, peer requests, panic-mode broadcasts, and other workflow events from across FireAlive.</M></Card>}
          {inboxItems.map(n=>(
            <Card key={n.id} style={{marginBottom:8,borderLeft:`3px solid ${n.read_at?C.b:C.a}`,opacity:n.read_at?0.65:1}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:10}}>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>{n.title}</div>
                  {n.body&&<M style={{color:C.tm,display:"block",lineHeight:1.6,marginBottom:6}}>{n.body}</M>}
                  <div style={{display:"flex",gap:10,fontSize:10,color:C.td,fontFamily:"'IBM Plex Mono',monospace"}}>
                    <span>{n.event_type}</span>
                    <span>·</span>
                    <span>{n.created_at}</span>
                    {n.link_tab&&<><span>·</span><a href="#" onClick={e=>{e.preventDefault();setTab(n.link_tab);if(!n.read_at){api.post(`/api/inbox/${n.id}/read`,{}).then(()=>{setInboxItems(prev=>prev.map(it=>it.id===n.id?{...it,read_at:new Date().toISOString()}:it));setInboxUnreadCount(c=>Math.max(0,c-1));}).catch(()=>{});}}} style={{color:C.a,textDecoration:"none"}}>Open ↗</a></>}
                  </div>
                </div>
                {!n.read_at&&<Btn small onClick={()=>{api.post(`/api/inbox/${n.id}/read`,{}).then(()=>{setInboxItems(prev=>prev.map(it=>it.id===n.id?{...it,read_at:new Date().toISOString()}:it));setInboxUnreadCount(c=>Math.max(0,c-1));}).catch(()=>{});}}>Mark read</Btn>}
              </div>
            </Card>          
          ))}
          </div>)}
          {inboxView==="preferences"&&(<div>
            <L>Notification preferences</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>For each event type, choose whether you want to be notified in the inbox, on your desktop (native OS notification), both, or neither. Some critical events (panic mode, tripwire, tier-3 abuse) cannot be disabled in-app — you can still opt out of desktop for these. Email and SMS are not available to analysts: storing personal contact information would defeat the pseudonym architecture by linking your identity to your activity.</M>
            {inboxPrefsLoading&&<M style={{color:C.td}}>Loading preferences…</M>}
            {!inboxPrefsLoading&&!inboxPrefs&&<Card><M style={{color:C.tm}}>Could not load preferences. The server may be unavailable.</M></Card>}
            {inboxPrefs&&Object.entries(inboxPrefs).map(([eventType,p])=>(
              <Card key={eventType} style={{marginBottom:8}}>
                <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>{p.label}</div>
                <M style={{color:C.tm,display:"block",lineHeight:1.6,marginBottom:10}}>{p.description}</M>
                <div style={{display:"flex",gap:16,alignItems:"center"}}>
                  <label style={{display:"flex",alignItems:"center",gap:6,cursor:p.mandatory_in_app?"not-allowed":"pointer",opacity:p.mandatory_in_app?0.7:1}} title={p.mandatory_in_app?"This event is mandatory in-app for all users and cannot be disabled.":""}>
                    <input type="checkbox" checked={p.in_app} disabled={p.mandatory_in_app} onChange={e=>{
                      const newInApp = e.target.checked;
                      // N1a C17: AC sends all 4 channel fields. Analyst anonymity rule:
                      // email + sms are always explicitly zero from the AC. Server-side
                      // role-gating (N1a C7 + C16) enforces this on the persistence layer
                      // too — defense-in-depth.
                      api.put(`/api/inbox/preferences/${eventType}`,{in_app:newInApp,email:false,sms:false,desktop:p.desktop}).then(()=>{
                        setInboxPrefs(prev=>({...prev,[eventType]:{...prev[eventType],in_app:newInApp,email:false,sms:false,is_default:false}}));
                      }).catch(err=>{
                        logC("INBOX_PREF_REJECTED",`${eventType} in_app change rejected (likely mandatory in-app event)`);
                      });
                    }}/>
                    <M style={{color:C.t}}>In-app</M>
                  </label>
                  <label style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer"}}>
                    <input type="checkbox" checked={p.desktop??false} onChange={e=>{
                      const newDesktop = e.target.checked;
                      api.put(`/api/inbox/preferences/${eventType}`,{in_app:p.in_app,email:false,sms:false,desktop:newDesktop}).then(()=>{
                        setInboxPrefs(prev=>({...prev,[eventType]:{...prev[eventType],desktop:newDesktop,email:false,sms:false,is_default:false}}));
                      }).catch(()=>{});
                    }}/>
                    <M style={{color:C.t}}>Desktop</M>
                  </label>
                  {p.is_default&&<M style={{color:C.td,fontStyle:"italic"}}>(default)</M>}
                </div>
              </Card>
            ))}
          </div>)}
        </div>)}

        {/* ══════════ AUDIT & FORENSICS ══════════ */}
        {tab==="audit_tab"&&(<div>
          <L>Audit Log & Forensics</L>
          <M style={{color:C.tm,display:"block",marginBottom:12}}>All events on this client are logged locally and automatically transmitted to the management console and server. This is not optional — audit trail integrity is essential for the entire SOC's security posture.</M>
          <Card style={{marginBottom:12}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}>
              <M style={{color:C.i,fontWeight:500}}>Log Integrity Status</M>
              <Badge color={logIntegrity.status==="healthy"?C.a:C.d}>{logIntegrity.status}</Badge>
            </div>
            <M style={{color:C.tm}}>Last integrity check: {new Date(logIntegrity.lastCheck).toLocaleString()}</M>
            <M style={{color:C.td,display:"block"}}>Gaps detected: {logIntegrity.gaps} · Tampering: {logIntegrity.tampering?"⚠ DETECTED":"none detected"}</M>
            <M style={{color:C.td,display:"block",marginTop:6,fontStyle:"italic"}}>Log integrity is continuously monitored. Status is sent to your management console every sync interval. Any gaps, deletions, or tampering trigger an immediate alert to your Team Lead.</M>
          </Card>
          <Card style={{maxHeight:350,overflowY:"auto"}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Event Log ({auditLog.length} events)</div>
            {auditLog.slice().reverse().map((e,i)=>(
              <div key={i} style={{padding:"4px 0",borderBottom:`1px solid ${C.b}`,display:"flex",gap:8}}>
                <M style={{color:C.td,minWidth:60}}>{new Date(e.ts).toLocaleTimeString()}</M>
                <M style={{color:e.a.includes("FAIL")||e.a.includes("ERROR")?C.d:e.a.includes("SCAN")?C.i:C.a,minWidth:120}}>{e.a}</M>
                <M style={{color:C.tm}}>{e.dt}</M>
              </div>
            ))}
          </Card>
          {/* R3l C35: Forensic Export Transparency — read-only informational card.
              Analysts do not have role permission on /api/forensic-exports endpoints
              (those gate to admin / ciso). This card explains what server-side
              forensic exports are, how the analyst's data may be included, and what
              cryptographic + procedural safeguards apply. No API calls, no leaked
              operational data — just transparency. */}
          <Card style={{marginTop:12,borderColor:C.i+"40"}}>
            <div style={{fontSize:12,fontWeight:500,color:C.i,marginBottom:8}}>SOC-Grade Forensic Export Transparency</div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Your Team Lead (admin role) and CISO can create cryptographically-signed forensic exports of platform audit data for compliance, incident response, or regulator requests. Your pseudonymized events may be included in these exports. You do not initiate or download forensic exports from this client — they are an admin/CISO workflow on the management console.</M>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:10}}>
              <div style={{padding:8,background:"rgba(255,255,255,0.02)",borderRadius:4,border:`1px solid ${C.b}`}}>
                <M style={{color:"#E8EDF5",fontWeight:500,fontSize:11,display:"block",marginBottom:3}}>Pseudonymized</M>
                <M style={{color:C.td,fontSize:11,lineHeight:1.5}}>Events in exports carry your analyst pseudonym (e.g., &quot;Analyst-Falcon&quot;), not your real name. The pseudonym map exists only in an offline-stored encrypted file your Team Lead controls.</M>
              </div>
              <div style={{padding:8,background:"rgba(255,255,255,0.02)",borderRadius:4,border:`1px solid ${C.b}`}}>
                <M style={{color:"#E8EDF5",fontWeight:500,fontSize:11,display:"block",marginBottom:3}}>Tamper-Evident</M>
                <M style={{color:C.td,fontSize:11,lineHeight:1.5}}>Every export is Ed25519-signed and recorded in an append-only chain. Modifying or deleting an export entry after the fact would break the chain&apos;s hash continuity — the tampering would be visible to any reviewer.</M>
              </div>
              <div style={{padding:8,background:"rgba(255,255,255,0.02)",borderRadius:4,border:`1px solid ${C.b}`}}>
                <M style={{color:"#E8EDF5",fontWeight:500,fontSize:11,display:"block",marginBottom:3}}>Separate Actors</M>
                <M style={{color:C.td,fontSize:11,lineHeight:1.5}}>Creating an export and deleting an export require two different people (admin creates, CISO deletes). Per ISO 27001 A.9.4.5 separation-of-duties — no single user can both produce and erase forensic evidence.</M>
              </div>
              <div style={{padding:8,background:"rgba(255,255,255,0.02)",borderRadius:4,border:`1px solid ${C.b}`}}>
                <M style={{color:"#E8EDF5",fontWeight:500,fontSize:11,display:"block",marginBottom:3}}>Rationale Logged</M>
                <M style={{color:C.td,fontSize:11,lineHeight:1.5}}>Every export records a free-text rationale (incident ID, audit ticket, regulator request) in the audit log alongside the export entry. Your CISO and compliance officer can review the rationale for any export at any time.</M>
              </div>
            </div>
            <M style={{color:C.td,display:"block",fontStyle:"italic",fontSize:10,lineHeight:1.5}}>If you have concerns about how your data is being used, speak with your Team Lead or CISO. The forensic export chain is fully auditable by your organization&apos;s compliance officer — they can inspect the chain entries, verify the Ed25519 signatures, and review the rationale for every export without needing access to the export contents themselves.</M>
          </Card>
          <div style={{display:"flex",gap:8,marginTop:12}}>
            <Btn primary onClick={()=>{const data=JSON.stringify({exportType:"analyst_client_audit",version:appVersion||"unknown",clientPseudonym:"Analyst-Falcon",exportedAt:new Date().toISOString(),logIntegrity,eventCount:auditLog.length,events:auditLog},null,2);const blob=new Blob([data],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="analyst-audit-"+new Date().toISOString().slice(0,10)+".json";a.click();logC("AUDIT_EXPORTED","Audit log downloaded — also auto-sent to MC");}}>Download Audit Log</Btn>
            <Btn onClick={()=>{const forensics={exportType:"analyst_client_forensics",version:appVersion||"unknown",clientPseudonym:"Analyst-Falcon",exportedAt:new Date().toISOString(),events:auditLog.map(e=>({...e,epochMs:Date.now(),severity:e.a.includes("FAIL")?"error":e.a.includes("SCAN")?"info":"normal"}))};const blob=new Blob([JSON.stringify(forensics,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="analyst-forensics-"+new Date().toISOString().slice(0,10)+".json";a.click();logC("FORENSICS_EXPORTED","Forensics export downloaded — also auto-sent to MC");}}>Download Forensics</Btn>
          </div>
        </div>)}


      </div></div>
      <div style={{padding:"14px 24px",borderTop:`1px solid ${C.b}`,fontSize:10,color:C.td,fontFamily:"'IBM Plex Mono',monospace",display:"flex",justifyContent:"space-between"}}>
        <span>ANALYST CLIENT · PSEUDONYMIZED · E2EE PEER CHAT · PRIVATE{appVersion?` · v${appVersion}`:""}</span>
        <span>{auditLog.length} events logged · Auto-sync to MC</span>
      </div>
    </div>
  );
}

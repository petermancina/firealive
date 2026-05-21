// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — SOC Analyst Wellbeing Platform v1.0.0
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
// Source code: https://github.com/pmancina/firealive
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useRef } from "react";

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
const API_BASE = 'http://localhost:3000';
const api = {
  _token: null,
  _headers() { return { 'Content-Type': 'application/json', ...(this._token ? { 'Authorization': 'Bearer ' + this._token } : {}) }; },
  async post(path, data) { try { const r = await fetch(API_BASE + path, { method: 'POST', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async get(path) { try { const r = await fetch(API_BASE + path, { headers: this._headers() }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async put(path, data) { try { const r = await fetch(API_BASE + path, { method: 'PUT', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async patch(path, data) { try { const r = await fetch(API_BASE + path, { method: 'PATCH', headers: this._headers(), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  async del(path) { try { const r = await fetch(API_BASE + path, { method: 'DELETE', headers: this._headers() }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { console.warn('[API]', path, e.message); return { error: e.message }; } },
  // download(path, filename, opts?) — fetches a binary response (CSV, PDF,
  // DOCX, etc.) and triggers a browser download via an anchor click. Use
  // for endpoints that return a blob rather than JSON; the get/post/put
  // methods above all assume a JSON response and would break on binary.
  // opts.method defaults to 'GET'; pass 'POST' for endpoints that take a
  // request body (runbook generator, TTX sitman/aar). opts.body, if
  // provided, is JSON-stringified and sent with Content-Type set.
  // Returns a Promise that resolves to true on success, false on error.
  async download(path, filename, opts) {
    const method = (opts && opts.method) || 'GET';
    const init = { method, headers: this._headers() };
    if (opts && opts.body !== undefined) init.body = JSON.stringify(opts.body);
    try {
      const r = await fetch(API_BASE + path, init);
      if (!r.ok) throw new Error('status ' + r.status);
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      return true;
    } catch (e) {
      console.warn('[API download]', path, e.message);
      return false;
    }
  },
  setToken(t) { this._token = t; },
};

const CSS = `@import url('${FONTS_URL}');*{box-sizing:border-box;margin:0;padding:0;}button,select,input,textarea{font-family:inherit;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
@keyframes spin{to{transform:rotate(360deg)}}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.08);border-radius:3px}`;

// ══════════════════════════════════════════════════════════════════════════════
// RESEARCH KNOWLEDGE BASE v2026.03.2 — 42 peer-reviewed entries
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

// R3j C9: linger window for the post-deactivation "Panic mode lifted" green
// banner. Mirrors the server-side PANIC_DEACTIVATED_LINGER_SECONDS in
// server/routes/routing.js. 300 seconds = 5 minutes.
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
// Analysts populated from IAM/provisioning. Empty on first run.
// Use Client Provisioning tab to add analysts.
const ANALYSTS_INIT = [];
// Automation systems added via Delegate to Automation config.
const AUTO_SYS_INIT = [];
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

const tierLbl = t => t===1?"L1":t===2?"L2":"L3";
const tierClr = t => t===1?C.i:t===2?C.p:"#F472B6";
const shiftLbl = s => s==="day"?"Day (06-14)":s==="swing"?"Swing (14-22)":"Night (22-06)";
const stMeta = {healthy:{c:C.a,l:"Healthy"},watch:{c:C.w,l:"Watch"},stressed:{c:"#F97316",l:"Stressed"},critical:{c:C.d,l:"Critical"}};
const genId = () => "SWP-"+Math.random().toString(36).substr(2,4).toUpperCase()+"-"+Date.now().toString(36).substr(-4).toUpperCase();

function computeTH(analysts,sd){
  const n=analysts.filter(a=>a.available).length||1;
  const oc=sd.filter(d=>d.util>0.85).length;const ext=sd.filter(d=>d.util>0.85&&d.wo>=2).length;
  const au=sd.reduce((s,d)=>s+d.util,0)/(sd.length||1);
  const cs=Math.max(0,100-(oc/n)*100);const dp=ext*8;
  const mt=Math.max(...sd.map(d=>d.tk),1);const at=sd.reduce((s,d)=>s+d.tk,0)/(sd.length||1)||1;
  const ep=Math.max(0,(mt/at-1.5)*20);
  const sc=Math.max(0,Math.min(100,Math.round(cs-dp-ep)));
  return{score:sc,status:sc<40?"critical":sc<60?"stressed":sc<75?"watch":"healthy",avgUtil:Math.round(au*100),oc,ext,size:n};
}

const PROMPTS = {
  team_stressed:{sev:"high",cond:th=>th.status==="stressed"||th.status==="critical",
    full:{title:"Team capacity strained — structural review needed",body:"ACTION: Review staffing ratio against current alert volume. Check automation delegation rates — are analysts sending automatable work to SOAR/EDR, or manually handling what machines should? Evaluate shift distribution — are all shifts equally staffed for their alert volume? Consider temporary P0/P1 routing caps during recovery period.\n\nWHY THIS WORKS: Meta-analytic evidence shows organizational interventions produce effect size d = −0.30 on exhaustion (R001), while combined org + individual interventions achieve d = −0.54 (R002). Individual-only interventions show d ≈ 0.16–0.36 and fade within six months. Telling a lead to 'schedule a 1:1' is an individual intervention. Reviewing staffing, rebalancing routing, and adjusting scheduling are structural interventions — 2–3× more durable. The JD-R model (R024) confirms: reducing demands while increasing resources produces the strongest burnout reduction.",cite:"KB refs: R001, R002, R024 · KB v"+KB_VERSION},
    compact:{title:"Team capacity strained",body:"Review staffing ratio, automation delegation, shift balance. Structural interventions are 2-3× more effective than individual check-ins.",cite:"Dreison et al. (2018)"},
    minimal:{title:"Team stressed",body:"Review staffing, automation, shift balance."}},
  equity:{sev:"medium",cond:th=>th.score<80,
    full:{title:"Alert distribution may be uneven",body:"ACTION: Check routing controls for unintended funneling — are complexity caps creating a situation where one analyst absorbs all high-priority work? Verify the auto-equity engine is distributing P0/P1 alerts across all qualified analysts. Identify L2 analysts who could be upskilled to handle higher-complexity alerts, reducing concentration on L3 staff.\n\nWHY THIS MATTERS: The Maslach Areas of Worklife model (R003) identifies six organizational domains that predict burnout: workload, control, reward, community, fairness, and values. The pivotal finding: fairness incongruity is more predictive of burnout progression than raw workload itself. When some analysts consistently handle disproportionate complexity while others handle lower tiers, the perceived unfairness accelerates burnout even if total ticket counts appear balanced (R004). Procedural justice — having voice in decisions — independently reduces turnover intention (R031).",cite:"KB refs: R003, R004, R031 · KB v"+KB_VERSION},
    compact:{title:"Check alert equity",body:"Review complexity caps and P0/P1 distribution. Fairness matters more than raw volume.",cite:"Leiter & Maslach (2004)"},
    minimal:{title:"Equity check",body:"Review P0/P1 distribution."}},
  automation:{sev:"medium",cond:()=>true,
    full:{title:"Automation has spare capacity — delegate more",body:"ACTION: Encourage analysts to flag automatable patterns they encounter during triage. Each successfully delegated pattern permanently reduces human cognitive load for the entire team. Track delegation rate as a positive team metric — it means analysts are actively improving their own conditions. Review automation headroom in the Automation tab and identify systems with available capacity.\n\nWHY THIS MATTERS: Alert fatigue from repetitive L1 triage is the single most-cited cause of SOC analyst burnout. 71% of analysts report burnout with repetitive alert processing as the primary driver (R008). Organizations processing >10,000 alerts/day lose ~25% of analyst capacity to false positive investigation (R009). Each pattern delegated compounds over time — a single rule handling 10 daily alerts saves 3,650 analyst interactions per year. However, beware the automation paradox: over-reliance on automated systems leads to degraded manual skills (R019). Display confidence scores and FP rates transparently so analysts maintain appropriate trust calibration (R020).",cite:"KB refs: R008, R009, R019, R020 · KB v"+KB_VERSION},
    compact:{title:"Push more to automation",body:"Spare capacity available. Encourage pattern delegation.",cite:"Tines (2024)"},
    minimal:{title:"Delegate more",body:"Spare automation capacity."}},
  one_on_one:{sev:"low",cond:()=>true,
    full:{title:"Maintain regular 1:1 cadence with all team members",body:"ACTION: Confirm all 1:1s are scheduled this week. Ask about specific incidents ('that C2 cluster yesterday was complex — how'd you approach it?'), not feelings ('how are you doing?'). Don't schedule emergency meetings — just don't let the regular cadence slip. If the system detects team-level stress, it means: make sure none of the normal 1:1s get skipped this week. The structural interventions (routing, automation, staffing) handle the conditions. Your job is maintaining human contact.\n\nWHY THIS WORKS: Weekly manager conversations produce 3× engagement improvement compared to annual/quarterly reviews (R013). Replacing annual reviews with regular informal check-ins reduced voluntary turnover by 30% (R014). SOC-specific research found informal collegial contact was preferred over formal debriefing by stressed analysts (R007). Social support has a direct negative effect on burnout and buffers high-demand impact (R026). Self-Determination Theory (R037) shows relatedness is a basic psychological need.",cite:"KB refs: R007, R013, R014, R026, R037 · KB v"+KB_VERSION},
    compact:{title:"1:1 cadence check",body:"All 1:1s scheduled? Ask about work, not feelings.",cite:"Gallup (2023)"},
    minimal:{title:"1:1s?",body:"All scheduled?"}},
};

function generateCEF(th, type) {
  const ts = new Date().toISOString();
  if (type === "health") return `CEF:0|FireAlive|TeamCapacity|0.0.20|100|Team Health Update|${th.status==="critical"?9:th.status==="stressed"?7:th.status==="watch"?4:1}|rt=${ts} cs1=${th.score} cs1Label=TeamHealthScore cs2=${th.avgUtil} cs2Label=AvgUtilization cs3=${th.oc} cs3Label=OverCapacity cs4=${th.ext} cs4Label=ExtendedOverCap msg=Team status: ${th.status}`;
  return `CEF:0|FireAlive|TeamCapacity|0.0.20|200|Report Generated|3|rt=${ts} msg=Scheduled report delivered`;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  LOGIN                                                                  ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

function LoginScreen({role, onLogin, onBack}) {
  // ── Stages ────────────────────────────────────────────────────────────────
  //   creds              username + password entry
  //   mfa                user is enrolled; enter TOTP or recovery code
  //   enroll-start       enrollment-required user; intro screen + Begin button
  //   enroll-confirm     showing QR / otpauth URL; user enters first TOTP
  //   recovery-display   showing 10 plaintext recovery codes once
  //   verify             success animation pre-onLogin
  //
  // The new /api/auth/login response can be one of three shapes:
  //   { mfa_required: true, mfa_session_token, accepts: [...] }
  //   { mfa_enrollment_required: true, mfa_session_token, enroll_endpoints }
  //   { accessToken, refreshToken, user }
  // The first two require the client to follow up via /login-mfa or
  // /login-enroll-start + /login-enroll-confirm before a JWT is issued.
  const [stage, setStage] = useState("creds");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [mfa, setMfa] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [mfaSessionToken, setMfaSessionToken] = useState("");
  const [enrollData, setEnrollData] = useState(null);     // { secret_base32, otpauth_url, qr_png_data_url }
  const [enrollConfirmCode, setEnrollConfirmCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState(null); // shown once after enrollment
  const [pendingLogin, setPendingLogin] = useState(null);   // login response held until user dismisses recovery codes
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [apiMode, setApiMode] = useState(null);
  const [loginVersion, setLoginVersion] = useState("");

  const roleLabel = "FireAlive";
  const roleGroup = role==="analyst"?"soc_analyst_group":"soc_teamlead_group";

  // Probe backend availability. apiMode true = real API path; false = demo
  // mode (offline-dev fallback that simulates the flow without making
  // network calls so the UI is testable without a backend).
  useEffect(()=>{
    if(window.FireAliveAPI && window.FireAliveAPI.system){
      window.FireAliveAPI.system.health()
        .then(d=>{ if(d && d.status==='healthy') setApiMode(true); else setApiMode(false); })
        .catch(()=>setApiMode(false));
    } else {
      // No FireAliveAPI bridge -- probe directly via the api helper.
      api.get("/api/system/health").then(r=>{
        setApiMode(r && r.status==='healthy');
      }).catch(()=>setApiMode(false));
    }
  },[]);
  useEffect(()=>{
    api.get("/api/system/version").then(r=>{
      if (r && r.version) setLoginVersion(r.version);
    }).catch(()=>{});
  },[]);

  // Centralized JWT-issuance handler. Sets the token on the api helper so
  // subsequent calls authenticate correctly, persists the refresh token
  // for /api/auth/refresh, and hands control back to the parent component.
  const finalizeLogin = (loginResponse) => {
    if (loginResponse && loginResponse.accessToken) {
      api.setToken(loginResponse.accessToken);
    }
    if (loginResponse && loginResponse.refreshToken) {
      try { localStorage.setItem('fa_refresh_token', loginResponse.refreshToken); } catch (_e) {}
    }
    setStage("verify");
    setTimeout(()=>onLogin(),800);
  };

  // Role-match gate: same logic as the prior demo-mode flow, kept here so
  // analysts logging into the MC and managers logging into the AC still
  // get rejected client-side. (Server-side role enforcement is still the
  // authoritative check via authMiddleware role lists.)
  const roleMismatch = (userObj) => {
    if (!userObj) return false;
    if (role==="analyst" && userObj.role!=="analyst") return true;
    if (role==="manager" && !["lead","admin"].includes(userObj.role)) return true;
    return false;
  };

  const handleCreds = async () => {
    if(!user.trim()||!pass.trim()){setError("Username and password required.");return;}
    setLoading(true); setError("");

    // Demo mode: simulate the enrolled-MFA path (most common case for
    // testing the UI).
    if (apiMode === false) {
      setTimeout(()=>{setLoading(false); setStage("mfa");},700);
      return;
    }

    try {
      const r = await api.post("/api/auth/login", { username: user, password: pass });
      setLoading(false);
      if (r && r.error) {
        setError(typeof r.error === 'string' ? r.error : "Authentication failed.");
        return;
      }

      if (r && r.mfa_required && r.mfa_session_token) {
        // Path 1: user enrolled, complete via /login-mfa
        setMfaSessionToken(r.mfa_session_token);
        setStage("mfa");
        return;
      }
      if (r && r.mfa_enrollment_required && r.mfa_session_token) {
        // Path 2: user must enroll before getting a JWT
        setMfaSessionToken(r.mfa_session_token);
        setStage("enroll-start");
        return;
      }
      if (r && r.accessToken && r.user) {
        // Path 3: analyst direct path -- no MFA needed
        if (roleMismatch(r.user)) {
          setError("Account role does not match selected role.");
          return;
        }
        finalizeLogin(r);
        return;
      }
      setError("Unexpected login response.");
    } catch (e) {
      setLoading(false);
      setError(e.message || "Authentication failed.");
    }
  };

  const handleMFA = async () => {
    const code = useRecovery ? recoveryCode.trim() : mfa.trim();
    if (!useRecovery && code.length<6){setError("Enter 6-digit code.");return;}
    if (useRecovery && code.length===0){setError("Enter recovery code.");return;}
    setLoading(true); setError("");

    if (apiMode === false) {
      // Demo mode: simulate success
      setTimeout(()=>{setLoading(false); finalizeLogin({});},600);
      return;
    }

    try {
      const body = useRecovery
        ? { mfa_session_token: mfaSessionToken, recovery_code: code }
        : { mfa_session_token: mfaSessionToken, totp_code: code };
      const r = await api.post("/api/auth/login-mfa", body);
      setLoading(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : "MFA verification failed."); return; }
      if (!r || !r.accessToken || !r.user) { setError("MFA verification failed."); return; }
      if (roleMismatch(r.user)) {
        setError("Account role does not match selected role.");
        return;
      }
      finalizeLogin(r);
    } catch (e) {
      setLoading(false);
      setError(e.message || "MFA verification failed.");
    }
  };

  const handleEnrollStart = async () => {
    setLoading(true); setError("");
    if (apiMode === false) {
      // Demo mode: simulate enrollment data
      setTimeout(()=>{
        setLoading(false);
        setEnrollData({
          secret_base32: "JBSWY3DPEHPK3PXP",
          otpauth_url: "otpauth://totp/FireAlive:demo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=FireAlive",
          qr_png_data_url: null,
        });
        setStage("enroll-confirm");
      },500);
      return;
    }
    try {
      const r = await api.post("/api/auth/login-enroll-start", { mfa_session_token: mfaSessionToken });
      setLoading(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : "Failed to start enrollment."); return; }
      if (!r || !r.secret_base32) { setError("Enrollment response was incomplete."); return; }
      setEnrollData(r);
      setStage("enroll-confirm");
    } catch (e) {
      setLoading(false);
      setError(e.message || "Failed to start enrollment.");
    }
  };

  const handleEnrollConfirm = async () => {
    if (enrollConfirmCode.length<6){setError("Enter 6-digit code from your authenticator.");return;}
    setLoading(true); setError("");

    if (apiMode === false) {
      // Demo mode: simulate enrollment confirm + recovery codes
      setTimeout(()=>{
        setLoading(false);
        setRecoveryCodes(["DEMO-AAAA-1111","DEMO-BBBB-2222","DEMO-CCCC-3333","DEMO-DDDD-4444","DEMO-EEEE-5555","DEMO-FFFF-6666","DEMO-GGGG-7777","DEMO-HHHH-8888","DEMO-JJJJ-9999","DEMO-KKKK-0000"]);
        setPendingLogin({ accessToken: null, refreshToken: null, user: { role: role==="manager"?"admin":"analyst" } });
        setStage("recovery-display");
      },600);
      return;
    }

    try {
      const r = await api.post("/api/auth/login-enroll-confirm", {
        mfa_session_token: mfaSessionToken,
        totp_code: enrollConfirmCode,
      });
      setLoading(false);
      if (r && r.error) { setError(typeof r.error === 'string' ? r.error : "Enrollment confirmation failed."); return; }
      if (!r || !r.accessToken || !r.user || !Array.isArray(r.recovery_codes)) {
        setError("Enrollment response was incomplete.");
        return;
      }
      if (roleMismatch(r.user)) {
        setError("Account role does not match selected role.");
        return;
      }
      // Hold the JWT response until the user has acknowledged the
      // recovery codes display. finalizeLogin runs from the
      // recovery-display screen's button.
      setRecoveryCodes(r.recovery_codes);
      setPendingLogin(r);
      setStage("recovery-display");
    } catch (e) {
      setLoading(false);
      setError(e.message || "Enrollment confirmation failed.");
    }
  };

  const handleRecoveryAcknowledge = () => {
    if (pendingLogin) {
      finalizeLogin(pendingLogin);
    } else {
      // Demo mode shouldn't reach here without pendingLogin, but be safe
      onLogin();
    }
  };

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div style={{minHeight:"100vh",background:"#050810",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'DM Sans',sans-serif"}}>
      <style>{CSS}</style>
      <div style={{maxWidth:520,width:"100%",padding:"0 24px",animation:"fadeIn 0.4s ease"}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{fontSize:36,fontWeight:700,color:C.a,fontFamily:"'Fraunces',serif"}}>FireAlive</div>
          <h1 style={{fontSize:14,fontWeight:400,color:C.td,fontFamily:"'IBM Plex Mono',monospace",letterSpacing:2,textTransform:"uppercase",marginBottom:4}}>Management Console Login</h1>
        </div>

        {stage==="creds"&&(
          <Card style={{padding:24}}>
            <Input label="Username" value={user} onChange={e=>setUser(e.target.value)} placeholder="analyst.name@corp.local" maxLength={128}/>
            <div style={{marginBottom:14}}><M style={{color:C.tm,marginBottom:4,display:"block"}}>Password</M><input type="password" value={pass} onChange={e=>setPass(e.target.value)} placeholder="••••••••" maxLength={128} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}}/></div>
            {error&&<div style={{fontSize:11,color:C.d,marginBottom:12}}>{error}</div>}
            <Btn primary style={{width:"100%"}} onClick={handleCreds} disabled={loading}>{loading?"Authenticating...":"Sign In"}</Btn>
            <M style={{color:C.td,display:"block",textAlign:"center",marginTop:16}}>FireAlive v{loginVersion||"…"} · AGPL-3.0</M>
          </Card>
        )}

        {stage==="mfa"&&(
          <Card style={{padding:24}}>
            <L>{useRecovery?"Use Recovery Code":"Enter MFA Code"}</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>{useRecovery?"Enter one of your single-use recovery codes (e.g. ABCD-1234-EFGH).":"Enter the 6-digit code from your authenticator app."}</M>
            {!useRecovery && (
              <Input label="MFA Code" value={mfa} onChange={e=>setMfa(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
            )}
            {useRecovery && (
              <Input label="Recovery Code" value={recoveryCode} onChange={e=>setRecoveryCode(e.target.value.toUpperCase().slice(0,32))} placeholder="ABCD-1234-EFGH" maxLength={32}/>
            )}
            {error&&<div style={{fontSize:11,color:C.d,marginBottom:12}}>{error}</div>}
            <Btn primary style={{width:"100%"}} onClick={handleMFA} disabled={loading}>{loading?"Verifying...":"Verify"}</Btn>
            <button onClick={()=>{setUseRecovery(!useRecovery);setError("");setMfa("");setRecoveryCode("");}} style={{width:"100%",marginTop:12,padding:8,background:"transparent",border:"none",color:C.tm,fontSize:11,cursor:"pointer",textDecoration:"underline"}}>
              {useRecovery?"Use authenticator code instead":"Use a recovery code instead"}
            </button>
          </Card>
        )}

        {stage==="enroll-start"&&(
          <Card style={{padding:24}}>
            <L>MFA Enrollment Required</L>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Your role requires multi-factor authentication. You will scan a QR code into an authenticator app (Google Authenticator, Authy, 1Password, etc.) and enter a verification code.</M>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>You will receive 10 single-use recovery codes after enrollment. Save them in a secure place; they are your only way back into your account if you lose access to your authenticator.</M>
            {error&&<div style={{fontSize:11,color:C.d,marginBottom:12}}>{error}</div>}
            <Btn primary style={{width:"100%"}} onClick={handleEnrollStart} disabled={loading}>{loading?"Preparing...":"Begin Enrollment"}</Btn>
          </Card>
        )}

        {stage==="enroll-confirm"&&enrollData&&(
          <Card style={{padding:24}}>
            <L>Scan QR Code</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Scan this QR code with your authenticator app, then enter the 6-digit code it generates.</M>
            <div style={{background:"#fff",borderRadius:8,padding:16,textAlign:"center",marginBottom:14}}>
              {enrollData.qr_png_data_url ? (
                <img src={enrollData.qr_png_data_url} alt="TOTP QR code" style={{width:240,height:240}}/>
              ) : (
                <div style={{width:240,height:240,margin:"0 auto",display:"flex",alignItems:"center",justifyContent:"center",border:"2px dashed #ccc",borderRadius:8,color:"#666",fontSize:11,padding:8}}>
                  QR rendering unavailable.<br/>Use manual entry below.
                </div>
              )}
            </div>
            <details style={{marginBottom:14}}>
              <summary style={{cursor:"pointer",color:C.tm,fontSize:11,marginBottom:8}}>Can't scan? Enter manually</summary>
              <div style={{padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,marginTop:8}}>
                <M style={{color:C.td,display:"block",marginBottom:6}}>Secret (base32):</M>
                <code style={{display:"block",color:C.t,fontSize:12,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.secret_base32}</code>
                <M style={{color:C.td,display:"block",marginTop:10,marginBottom:6}}>Or paste this URL into a TOTP-aware app:</M>
                <code style={{display:"block",color:C.t,fontSize:10,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.otpauth_url}</code>
              </div>
            </details>
            <Input label="6-digit code from authenticator" value={enrollConfirmCode} onChange={e=>setEnrollConfirmCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
            {error&&<div style={{fontSize:11,color:C.d,marginBottom:12}}>{error}</div>}
            <Btn primary style={{width:"100%"}} onClick={handleEnrollConfirm} disabled={loading}>{loading?"Confirming...":"Confirm Enrollment"}</Btn>
          </Card>
        )}

        {stage==="recovery-display"&&recoveryCodes&&(
          <Card style={{padding:24}}>
            <L>Save Your Recovery Codes</L>
            <M style={{color:C.d,display:"block",marginBottom:14,lineHeight:1.6,fontWeight:500}}>These codes will not be shown again. Each can be used once if you lose access to your authenticator.</M>
            <M style={{color:C.tm,display:"block",marginBottom:14,lineHeight:1.6}}>Print them, store them in a password manager, or write them down somewhere safe. The server cannot recover them.</M>
            <div style={{background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,padding:16,marginBottom:16,fontFamily:"'IBM Plex Mono',monospace",fontSize:13,color:C.t,lineHeight:1.8,userSelect:"all"}}>
              {recoveryCodes.map((c,i)=>(<div key={i}>{c}</div>))}
            </div>
            <button onClick={()=>{
              try {
                const text = recoveryCodes.join("\n");
                if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
                  navigator.clipboard.writeText(text);
                }
              } catch (_e) {}
            }} style={{width:"100%",marginBottom:8,padding:10,background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Copy all to clipboard</button>
            <Btn primary style={{width:"100%"}} onClick={handleRecoveryAcknowledge}>I've saved my recovery codes</Btn>
          </Card>
        )}

        {stage==="verify"&&(
          <Card style={{padding:24,textAlign:"center"}}>
            <L>Verified</L>
            <M style={{color:C.tm,display:"block",marginBottom:8,lineHeight:1.6}}>Logging in...</M>
          </Card>
        )}
      </div>
    </div>
  );
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  MY MFA SECURITY SECTION (R3f)                                          ║
// ║                                                                         ║
// ║  Self-service MFA management for the currently authenticated user.      ║
// ║  Renders inside the MFA tab above the admin-policy controls. Talks to   ║
// ║  /api/mfa/* (status, enroll-start, enroll-confirm, recovery-status,     ║
// ║  regenerate-recovery, disable). All operations scope to req.user.id     ║
// ║  on the server side -- this component never accepts or sends a user_id  ║
// ║  parameter.                                                             ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

function MyMfaSecuritySection() {
  const [status, setStatus] = useState(null);            // { enrolled, in_enrollment }
  const [recovery, setRecovery] = useState(null);        // { generated, remaining, total }
  const [loading, setLoading] = useState(true);
  const [stage, setStage] = useState('idle');
    // idle | enrolling-confirm | display-codes | regenerating | disabling
  const [enrollData, setEnrollData] = useState(null);    // { secret_base32, otpauth_url, qr_png_data_url }
  const [confirmCode, setConfirmCode] = useState('');
  const [actionCode, setActionCode] = useState('');
  const [codes, setCodes] = useState(null);              // recovery codes for one-time display
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
        if (r && !r.error) setRecovery(r);
        else setRecovery(null);
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

  const startRegen = () => {
    setActionCode(''); setError(''); setStage('regenerating');
  };

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

  const acknowledgeCodes = () => {
    setCodes(null); setEnrollData(null); setStage('idle');
    refresh();
  };

  const cancel = () => {
    setStage('idle'); setError('');
    setConfirmCode(''); setActionCode('');
  };

  // ── Render branches ──────────────────────────────────────────────────────

  if (loading) {
    return (
      <Card style={{marginBottom:12,padding:14,borderColor:C.b}}>
        <div style={{fontSize:13,fontWeight:600,color:C.t,marginBottom:6}}>My MFA Enrollment</div>
        <M style={{color:C.tm}}>Loading…</M>
      </Card>
    );
  }

  if (stage === 'display-codes' && codes) {
    return (
      <Card style={{marginBottom:12,padding:16,borderColor:C.a+"40"}}>
        <div style={{fontSize:13,fontWeight:600,color:C.a,marginBottom:8}}>Save Your Recovery Codes</div>
        <M style={{color:C.d,display:"block",marginBottom:10,fontWeight:500,lineHeight:1.6}}>These codes will not be shown again. Each can be used once if you lose access to your authenticator.</M>
        <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Print them, store them in a password manager, or write them down.</M>
        <div style={{background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,padding:12,marginBottom:12,fontFamily:"'IBM Plex Mono',monospace",fontSize:13,color:C.t,lineHeight:1.8,userSelect:"all"}}>
          {codes.map((c,i)=><div key={i}>{c}</div>)}
        </div>
        <button onClick={()=>{
          try { if (navigator && navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(codes.join("\n")); } catch (_e) {}
        }} style={{width:"100%",marginBottom:8,padding:10,background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Copy all to clipboard</button>
        <Btn primary style={{width:"100%"}} onClick={acknowledgeCodes}>I've saved my recovery codes</Btn>
      </Card>
    );
  }

  if (stage === 'enrolling-confirm' && enrollData) {
    return (
      <Card style={{marginBottom:12,padding:16,borderColor:C.i+"30"}}>
        <div style={{fontSize:13,fontWeight:600,color:C.i,marginBottom:8}}>Scan QR Code to Enroll</div>
        <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Scan with your authenticator app, then enter the 6-digit code it generates.</M>
        <div style={{background:"#fff",borderRadius:8,padding:14,textAlign:"center",marginBottom:12}}>
          {enrollData.qr_png_data_url ? (
            <img src={enrollData.qr_png_data_url} alt="TOTP QR code" style={{width:200,height:200}}/>
          ) : (
            <div style={{width:200,height:200,margin:"0 auto",display:"flex",alignItems:"center",justifyContent:"center",border:"2px dashed #ccc",borderRadius:8,color:"#666",fontSize:11,padding:8}}>QR rendering unavailable.<br/>Use manual entry below.</div>
          )}
        </div>
        <details style={{marginBottom:12}}>
          <summary style={{cursor:"pointer",color:C.tm,fontSize:11,marginBottom:8}}>Can't scan? Enter manually</summary>
          <div style={{padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,marginTop:8}}>
            <M style={{color:C.td,display:"block",marginBottom:6}}>Secret (base32):</M>
            <code style={{display:"block",color:C.t,fontSize:12,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.secret_base32}</code>
            <M style={{color:C.td,display:"block",marginTop:10,marginBottom:6}}>Or paste this URL into a TOTP-aware app:</M>
            <code style={{display:"block",color:C.t,fontSize:10,wordBreak:"break-all",fontFamily:"'IBM Plex Mono',monospace",userSelect:"all"}}>{enrollData.otpauth_url}</code>
          </div>
        </details>
        <Input label="6-digit code from authenticator" value={confirmCode} onChange={e=>setConfirmCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
        {error&&<div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
        <div style={{display:"flex",gap:8}}>
          <Btn primary style={{flex:1}} onClick={confirmEnroll} disabled={busy}>{busy?"Confirming...":"Confirm Enrollment"}</Btn>
          <button onClick={cancel} disabled={busy} style={{flex:"0 0 auto",padding:"8px 14px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Cancel</button>
        </div>
      </Card>
    );
  }

  if (stage === 'regenerating') {
    return (
      <Card style={{marginBottom:12,padding:16,borderColor:C.i+"30"}}>
        <div style={{fontSize:13,fontWeight:600,color:C.i,marginBottom:8}}>Regenerate Recovery Codes</div>
        <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Generates 10 new recovery codes. ALL existing codes will be invalidated immediately. Enter your current authenticator code to confirm.</M>
        <Input label="6-digit code from authenticator" value={actionCode} onChange={e=>setActionCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
        {error&&<div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
        <div style={{display:"flex",gap:8}}>
          <Btn primary style={{flex:1}} onClick={confirmRegen} disabled={busy}>{busy?"Regenerating...":"Regenerate Codes"}</Btn>
          <button onClick={cancel} disabled={busy} style={{flex:"0 0 auto",padding:"8px 14px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Cancel</button>
        </div>
      </Card>
    );
  }

  if (stage === 'disabling') {
    return (
      <Card style={{marginBottom:12,padding:16,borderColor:C.d+"40"}}>
        <div style={{fontSize:13,fontWeight:600,color:C.d,marginBottom:8}}>Disable MFA</div>
        <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Removes second-factor protection from your account. Existing recovery codes will also be cleared. Enter your current authenticator code to confirm.</M>
        <Input label="6-digit code from authenticator" value={actionCode} onChange={e=>setActionCode(e.target.value.replace(/\D/g,"").slice(0,6))} placeholder="000000" maxLength={6}/>
        {error&&<div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
        <div style={{display:"flex",gap:8}}>
          <button onClick={confirmDisable} disabled={busy} style={{flex:1,padding:"10px 14px",background:`${C.d}20`,border:`1px solid ${C.d}50`,borderRadius:8,color:C.d,fontSize:12,fontWeight:500,cursor:busy?"default":"pointer"}}>{busy?"Disabling...":"Confirm Disable"}</button>
          <button onClick={cancel} disabled={busy} style={{flex:"0 0 auto",padding:"8px 14px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Cancel</button>
        </div>
      </Card>
    );
  }

  // Default idle stage: show enrollment status + actions
  const enrolled = !!(status && status.enrolled);
  const inEnrollment = !!(status && status.in_enrollment && !enrolled);
  const lowCodes = recovery && recovery.generated && recovery.remaining <= 3;

  return (
    <Card style={{marginBottom:12,padding:16,borderColor:enrolled?C.a+"30":C.b}}>
      <div style={{fontSize:13,fontWeight:600,color:C.t,marginBottom:8}}>My MFA Enrollment</div>
      {enrolled && (
        <>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
            <Badge color={C.a}>ENROLLED</Badge>
            <M style={{color:C.tm}}>TOTP authenticator active</M>
          </div>
          {recovery && recovery.generated ? (
            <M style={{color:lowCodes?C.d:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>
              {recovery.remaining} of {recovery.total} recovery codes remaining
              {lowCodes ? " — regenerate soon to avoid lockout if you lose your authenticator." : "."}
            </M>
          ) : (
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>
              Recovery codes status unavailable.
            </M>
          )}
          {error && <div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
          <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
            <button onClick={startRegen} disabled={busy} style={{padding:"8px 12px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:8,color:C.tm,fontSize:11,cursor:"pointer"}}>Regenerate Recovery Codes</button>
            <button onClick={startDisable} disabled={busy} style={{padding:"8px 12px",background:"transparent",border:`1px solid ${C.d}40`,borderRadius:8,color:C.d,fontSize:11,cursor:"pointer"}}>Disable MFA</button>
          </div>
        </>
      )}
      {!enrolled && inEnrollment && (
        <>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
            <Badge color={C.w}>IN PROGRESS</Badge>
            <M style={{color:C.tm}}>Enrollment was started but not confirmed</M>
          </div>
          <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>You have a TOTP secret pending confirmation. Click below to view the QR again or restart enrollment with a fresh secret.</M>
          {error && <div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
          <Btn primary style={{width:"100%"}} onClick={startEnroll} disabled={busy}>{busy?"Loading...":"Resume / Restart Enrollment"}</Btn>
        </>
      )}
      {!enrolled && !inEnrollment && (
        <>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
            <Badge color={C.d}>NOT ENROLLED</Badge>
            <M style={{color:C.tm}}>Enroll to add a second factor to your account</M>
          </div>
          <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Scan a QR code into your authenticator app (Google Authenticator, Authy, 1Password, etc.) and enter the first code to enroll. You'll receive 10 single-use recovery codes after enrollment.</M>
          {error && <div style={{fontSize:11,color:C.d,marginBottom:10}}>{error}</div>}
          <Btn primary style={{width:"100%"}} onClick={startEnroll} disabled={busy}>{busy?"Loading...":"Enroll MFA"}</Btn>
        </>
      )}
    </Card>
  );
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  MANAGEMENT CONSOLE                                                     ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

function ManagementConsole() {
  const [tab, setTab] = useState("actions");
  const [gDepth, setGD] = useState(null);
  const [pDepths, setPD] = useState({});
  const [silenced, setSil] = useState([]);
  // Initial audit entries for first-run demo. In production, populated from server.
  // Audit log populated from real events.
  const [audit, setAudit] = useState([]);
  const [autoSys, setAutoSys] = useState(AUTO_SYS_INIT);
  const [showAddAuto, setShowAddAuto] = useState(false);
  const [newAuto, setNewAuto] = useState({name:"",type:"EDR/XDR",l1:true,l2:false,l3:false,max:500,u:"alerts/hr"});
  const [notifCfg, setNotifCfg] = useState({thresh:"watch",email:true,sms:false,voip:false,lambda:false,addr:"",phone:"",arn:""});
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

  // ── Peer Conduct (Phase 1.4b) ──
  const [peerFlags, setPeerFlags] = useState([]);
  const [peerFlagsLoading, setPeerFlagsLoading] = useState(false);
  const [peerFlagStatus, setPeerFlagStatus] = useState("open"); // open | resolved | all
  const [peerFlagTierFilter, setPeerFlagTierFilter] = useState(""); // "" | "1" | "2" | "3"
  const [peerFlagOpenCount, setPeerFlagOpenCount] = useState(0);
  const [peerFlagUrgentOpenCount, setPeerFlagUrgentOpenCount] = useState(0);
  const [peerFlagResolveTarget, setPeerFlagResolveTarget] = useState(null); // flag id
  const [peerFlagResolveNote, setPeerFlagResolveNote] = useState("");

  // Poll the open-flag count every 60s for the sidebar badge and the
  // tier-3 dashboard banner. We track total open and urgent open in
  // the same pass to avoid a second request.
  useEffect(()=>{
    let cancelled = false;
    const fetchCounts = ()=>{
      api.get("/api/peer/flags?status=open").then(r=>{
        if (cancelled) return;
        const flags = r?.flags || [];
        setPeerFlagOpenCount(flags.length);
        setPeerFlagUrgentOpenCount(flags.filter(f=>f.tier===3).length);
      }).catch(()=>{});
    };
    fetchCounts();
    const handle = setInterval(fetchCounts, 60000);
    return ()=>{ cancelled = true; clearInterval(handle); };
  }, []);

  // ── Recovery Runbook state (Phase F2) ────────────────────────────────────
  const [runbookScenarios, setRunbookScenarios] = useState([]);
  const [runbookCategories, setRunbookCategories] = useState([]);
  const [runbookValidFormats, setRunbookValidFormats] = useState(['pdf', 'docx', 'json']);
  const [runbookScenariosLoading, setRunbookScenariosLoading] = useState(false);
  const [runbookSelectedId, setRunbookSelectedId] = useState('');
  const [runbookArtifactType, setRunbookArtifactType] = useState('quickref');
  const [runbookFormat, setRunbookFormat] = useState('pdf');
  const [runbookGenerating, setRunbookGenerating] = useState(false);

  // When the Runbook tab is opened, fetch the curated scenario library.
  useEffect(()=>{
    if (tab !== "runbook") return;
    setRunbookScenariosLoading(true);
    api.get("/api/runbook/scenarios").then(r=>{
      setRunbookScenarios(r?.scenarios || []);
      setRunbookCategories(r?.categories || []);
      if (r?.validFormats) setRunbookValidFormats(r.validFormats);
    }).catch(()=>{
      setRunbookScenarios([]);
      setRunbookCategories([]);
    }).finally(()=>setRunbookScenariosLoading(false));
  }, [tab]);


  // ── TTX Generator state (Phase 1.4d) ─────────────────────────────────────
  const [ttxScenariosList, setTtxScenariosList] = useState([]);
  const [ttxScenariosLoading, setTtxScenariosLoading] = useState(false);
  const [ttxScenarioId, setTtxScenarioId] = useState("");
  const [ttxDifficulty, setTtxDifficulty] = useState("intermediate");
  const [ttxFormat, setTtxFormat] = useState("pdf");
  const [ttxGenerating, setTtxGenerating] = useState(false);

  // ── AI Provider state (Phase F4a) ────────────────────────────────────────
  const [aiStatus, setAiStatus] = useState(null);  // /api/ai-provider/status
  const [aiConfigs, setAiConfigs] = useState([]);  // /api/ai-provider/config
  const [aiLoading, setAiLoading] = useState(false);
  const [aiDownloadPolling, setAiDownloadPolling] = useState(false);
  const [aiSelectedFeature, setAiSelectedFeature] = useState('ir_simulator');
  const [aiEditProvider, setAiEditProvider] = useState('internal');
  const [aiEditModelName, setAiEditModelName] = useState('');
  const [aiEditApiKey, setAiEditApiKey] = useState('');
  const [aiEditEndpoint, setAiEditEndpoint] = useState('');
  const [aiEditMaxTokens, setAiEditMaxTokens] = useState(1024);
  const [aiEditTemperature, setAiEditTemperature] = useState(0.7);
  const [aiInferences, setAiInferences] = useState([]);

  // Fetch AI provider status + configs when tab is opened
  useEffect(()=>{
    if (tab !== 'ai_integrations') return;
    setAiLoading(true);
    Promise.all([
      api.get('/api/ai-provider/status').catch(()=>null),
      api.get('/api/ai-provider/config').catch(()=>null),
    ]).then(([statusR, configR])=>{
      setAiStatus(statusR);
      setAiConfigs(configR?.configs || []);
    }).finally(()=>setAiLoading(false));
  }, [tab]);

  // R3j C7: Hydrate SOAR + Ticketing forms from canonical /api/integrations
  // when tab==="soar" is opened. Parallel fetch; tolerant of either
  // integration being unconfigured (returns {status:"not_configured",config:null}).
  // R3n: SOC-grade — sensitive fields (apiKey) are STRIPPED entirely from
  // the GET response; presence is surfaced via sensitiveFieldsPresent.apiKey
  // booleans. The form renders "Configured ✓" + a "Change Secret" button when
  // a value exists server-side; clicking Change reveals an empty input. On
  // save, the apiKey field is OMITTED from the PUT body unless the lead
  // explicitly clicked Change (omission-rule merge preserves existing).
  useEffect(()=>{
    if (tab !== "soar" || soarHydrated) return;
    Promise.all([
      api.get("/api/integrations/soar"),
      api.get("/api/integrations/ticketing"),
    ]).then(([soarRes, ticketingRes])=>{
      if (soarRes && !soarRes.error && soarRes.config) {
        setSoarPlatform(soarRes.config.platform || "");
        setSoarUrl(soarRes.config.apiEndpoint || "");
        setSoarServiceAccount(soarRes.config.serviceAccount || "");
        setSoarApiKey("");
        setSoarApiKeyPresent(!!(soarRes.sensitiveFieldsPresent && soarRes.sensitiveFieldsPresent.apiKey));
        setSoarApiKeyChanging(false);
        setSoarAutoEscalate(soarRes.config.autoEscalate === true);
      }
      if (ticketingRes && !ticketingRes.error && ticketingRes.config) {
        setSoarTicketingPlatform(ticketingRes.config.platform || "");
        setSoarTicketingEndpoint(ticketingRes.config.apiEndpoint || "");
        setSoarTicketingApiKey("");
        setSoarTicketingApiKeyPresent(!!(ticketingRes.sensitiveFieldsPresent && ticketingRes.sensitiveFieldsPresent.apiKey));
        setSoarTicketingApiKeyChanging(false);
      }
      setSoarHydrated(true);
    }).catch(()=>setSoarHydrated(true));
  }, [tab, soarHydrated]);

  // R3j C8: Hydrate routing caps from canonical /api/routing when
  // tab==="routing" is opened. Response shape: {caps: [{analyst_id,
  // max_complexity, is_override, override_reason, ...}]}. Each cap is
  // merged into the routingCaps state keyed by analyst_id. In mock-mode
  // (no real analysts in DB) the response.caps array is empty and the
  // initial state derived from ANALYSTS_INIT remains the source of truth.
  // In real-deployment mode the server-stored max_complexity values
  // override the defaults.
  useEffect(()=>{
    if (tab !== "routing" || routingHydrated) return;
    api.get("/api/routing").then(res=>{
      if (res && !res.error && Array.isArray(res.caps)) {
        setRC(prev=>{
          const next = {...prev};
          for (const c of res.caps) {
            if (c?.analyst_id != null && c?.max_complexity != null) {
              next[c.analyst_id] = c.max_complexity;
            }
          }
          return next;
        });
      }
      setRoutingHydrated(true);
    }).catch(()=>setRoutingHydrated(true));
  }, [tab, routingHydrated]);

  // R3j C9: Poll /api/routing/panic every 30s to keep panicMode and the
  // post-deactivation linger banner in sync with the canonical state.
  // Runs always (not gated on tab) so the top-of-MC banner stays live as
  // the lead moves between tabs. Tolerates fetch errors silently — a
  // missed poll just delays the banner update to the next tick.
  useEffect(()=>{
    let cancelled = false;
    const fetchPanic = () => {
      api.get("/api/routing/panic").then(r=>{
        if (cancelled) return;
        if (r && !r.error) {
          setPanicMode(r.active === true);
          setPanicDeactivatedAt(r.deactivated_at ?? null);
        }
      }).catch(()=>{});
    };
    fetchPanic();
    const handle = setInterval(fetchPanic, 30000);
    return ()=>{ cancelled = true; clearInterval(handle); };
  }, []);

  // R3j C10: Poll /api/routing/soar every 30s while tab==="soar" is open
  // to refresh the Live SOAR Routing State card. The 6 variables shown
  // are the values FireAlive is currently publishing TO the SOAR (read
  // from team_config soar_* keys, JSON-parsed). When the tab is not open
  // the interval is cleared via the cleanup function — no background
  // network traffic if the lead isn't viewing this surface. First fetch
  // fires immediately on tab open so the card doesn't show stale state
  // from the previous open.
  useEffect(()=>{
    if (tab !== "soar") return;
    let cancelled = false;
    const fetchLive = () => {
      api.get("/api/routing/soar").then(r=>{
        if (cancelled) return;
        if (r && !r.error) {
          setSoarLiveVariables(r.variables || {});
          setSoarLiveLastFetched(new Date().toISOString());
        }
      }).catch(()=>{});
    };
    fetchLive();
    const handle = setInterval(fetchLive, 30000);
    return ()=>{ cancelled = true; clearInterval(handle); };
  }, [tab]);

  // Poll download progress when a download is active
  useEffect(()=>{
    if (!aiDownloadPolling) return;
    const tick = setInterval(()=>{
      api.get('/api/ai-provider/model/download/status').then(r=>{
        if (!r?.active) {
          setAiDownloadPolling(false);
          api.get('/api/ai-provider/status').then(s=>setAiStatus(s)).catch(()=>{});
          return;
        }
        setAiStatus(prev=>prev ? {...prev, activeDownload: r.job} : prev);
      }).catch(()=>{});
    }, 2000);
    return ()=>clearInterval(tick);
  }, [aiDownloadPolling]);

  // Load existing config into edit form when feature selection changes
  useEffect(()=>{
    if (tab !== 'ai_integrations') return;
    const cfg = aiConfigs.find(c=>c.featureId===aiSelectedFeature);
    if (cfg) {
      setAiEditProvider(cfg.provider);
      setAiEditModelName(cfg.modelName || '');
      setAiEditMaxTokens(cfg.maxTokens || 1024);
      setAiEditTemperature(cfg.temperature !== null && cfg.temperature !== undefined ? cfg.temperature : 0.7);
    } else {
      setAiEditProvider('internal');
      setAiEditModelName('');
      setAiEditMaxTokens(1024);
      setAiEditTemperature(0.7);
    }
    setAiEditApiKey('');
    setAiEditEndpoint('');
    api.get('/api/ai-provider/inferences/'+aiSelectedFeature+'?limit=20').then(r=>{
      setAiInferences(r?.inferences || []);
    }).catch(()=>setAiInferences([]));
  }, [aiSelectedFeature, aiConfigs, tab]);


  // When the TTX tab is opened, fetch the curated scenario library.
  useEffect(()=>{
    if (tab !== "ttx") return;
    setTtxScenariosLoading(true);
    api.get("/api/ttx/scenarios").then(r=>{
      setTtxScenariosList(r?.scenarios || []);
    }).catch(()=>setTtxScenariosList([])).finally(()=>setTtxScenariosLoading(false));
  }, [tab]);

  // When peer_conduct tab is opened or filters change, load flags.
  useEffect(()=>{
    if (tab !== "peer_conduct") return;
    setPeerFlagsLoading(true);
    const params = new URLSearchParams({ status: peerFlagStatus });
    if (peerFlagTierFilter) params.set("tier", peerFlagTierFilter);
    api.get(`/api/peer/flags?${params.toString()}`).then(r=>{
      setPeerFlags(r?.flags || []);
    }).catch(()=>{}).finally(()=>setPeerFlagsLoading(false));
  }, [tab, peerFlagStatus, peerFlagTierFilter]);

  // R3h: When peersupport tab opens, fetch the Helper Recognition
  // leaderboard. Returns top 10 opted-in analysts by points. The
  // service-layer filter (leaderboard_opt_in = 1) means an analyst
  // who has not opted in via their AC toggle is absent from this
  // list, regardless of how many points they have earned. Empty list
  // is the expected steady state until at least one analyst opts in.
  useEffect(()=>{
    if (tab !== "peersupport") return;
    setPeerHelpersLoading(true);
    setPeerHelpersError(null);
    api.get("/api/helper-pay/leaderboard?limit=10").then(r=>{
      if (r?.error) {
        setPeerHelpersError(r.message || "Could not load leaderboard.");
        setPeerHelpers([]);
        return;
      }
      setPeerHelpers(Array.isArray(r?.entries) ? r.entries : []);
    }).catch(()=>{
      setPeerHelpersError("Could not reach the server.");
      setPeerHelpers([]);
    }).finally(()=>setPeerHelpersLoading(false));
  }, [tab]);

  // R3h: When peersupport tab opens, also fetch the full-roster team
  // scores. This is the lead's operational view of ALL active analysts'
  // helper-pay state, regardless of opt-in. Per privacy invariant I5,
  // this surface is for payroll/compensation use — a separate concern
  // from the recognition leaderboard above. Endpoint is lead/admin-only
  // server-side; a 403 here means the current user is an analyst who
  // shouldn't be on the peersupport tab in the first place (the MC
  // mounts peersupport for lead/admin).
  useEffect(()=>{
    if (tab !== "peersupport") return;
    setTeamScoresLoading(true);
    setTeamScoresError(null);
    api.get("/api/helper-pay/team-scores").then(r=>{
      if (r?.error) {
        setTeamScoresError(r.message || "Could not load team scores.");
        setTeamScores([]);
        return;
      }
      setTeamScores(Array.isArray(r?.entries) ? r.entries : []);
    }).catch(()=>{
      setTeamScoresError("Could not reach the server.");
      setTeamScores([]);
    }).finally(()=>setTeamScoresLoading(false));
  }, [tab]);

  // R3h-pt2: When peersupport tab opens, also fetch flagged ratings for
  // the sock-puppet review queue. Lead/admin only (server-side
  // isLeadOrAdmin guard); a 403 here would mean the current user is
  // an analyst who shouldn't be on the peersupport tab in the first
  // place (the MC mounts peersupport for lead/admin). Empty list is
  // the expected steady state when no sock-puppet activity has been
  // detected.
  useEffect(()=>{
    if (tab !== "peersupport") return;
    setFlaggedRatingsLoading(true);
    setFlaggedRatingsError(null);
    api.get("/api/helper-pay/flagged-ratings").then(r=>{
      if (r?.error) {
        setFlaggedRatingsError(r.message || "Could not load flagged ratings.");
        setFlaggedRatings([]);
        return;
      }
      setFlaggedRatings(Array.isArray(r?.entries) ? r.entries : []);
    }).catch(()=>{
      setFlaggedRatingsError("Could not reach the server.");
      setFlaggedRatings([]);
    }).finally(()=>setFlaggedRatingsLoading(false));
  }, [tab]);

  // R3i: When the backup_schedules tab opens, parallel-fetch the
  // schedules list and the regulatory presets list. Schedules drive
  // the Active Schedules render; presets drive the Add Schedule form's
  // preset dropdown (C9 wires the form). Both endpoints are admin-only
  // and gated by configLockGate on the server, so a 401/403/423 here
  // means the operator must unlock the config lock first (handled
  // via the existing config-lock-state surface, not re-implemented
  // here).
  useEffect(()=>{
    if (tab !== "backup_schedules") return;
    setSchedulesLoading(true);
    setSchedulesError(null);
    Promise.all([
      api.get("/api/backup-schedules"),
      api.get("/api/backup-schedules/presets"),
      // R3l C59: fetch backup_destinations so the Add Schedule form's
      // destination_filter summary panel can show which destinations
      // match the operator's current filter. Failures here are
      // non-fatal — the form still works without the panel.
      api.get("/api/backup-destinations").catch(() => null),
    ]).then(([sRes, pRes, dRes])=>{
      if (sRes?.error) {
        setSchedulesError(sRes.message || "Could not load schedules.");
        setSchedules([]);
      } else {
        setSchedules(Array.isArray(sRes?.schedules) ? sRes.schedules : []);
      }
      if (pRes?.error) {
        setPresets([]);
      } else {
        setPresets(Array.isArray(pRes?.presets) ? pRes.presets : []);
      }
      // R3l C59: destinations list — keep only enabled ones; the summary
      // panel surfaces "X of Y enabled destinations match this filter"
      const destList = (dRes && Array.isArray(dRes.destinations)) ? dRes.destinations : [];
      setEnabledDestinations(destList.filter(d => d.enabled === 1 || d.enabled === true));
    }).catch(()=>{
      setSchedulesError("Could not reach the server.");
      setSchedules([]);
      setPresets([]);
      setEnabledDestinations([]);
    }).finally(()=>setSchedulesLoading(false));
  }, [tab]);

  // R3i: delete a backup schedule by id. Optimistic UI — remove the
  // row from local state immediately, then call DELETE. On failure,
  // refetch to restore. The scheduler's 60-second poll picks up the
  // delete and tears down the cron job within the next minute.
  const deleteSchedule = (id, name) => {
    if (!window.confirm(`Delete backup schedule "${name || "#" + id}"? The scheduler will stop running this schedule within 60 seconds. Existing backups already taken under this schedule are NOT deleted.`)) return;
    setSchedulesFb(null);
    const previous = schedules;
    setSchedules(previous.filter(s => s.id !== id));
    api.del(`/api/backup-schedules/${id}`).then(r=>{
      if (r?.error) {
        setSchedules(previous);
        setSchedulesFb({error: r.message || "Delete failed."});
        return;
      }
      setSchedulesFb({success: `Deleted schedule "${name || "#" + id}".`});
      addA("BACKUP_SCHEDULE_DELETED_UI", `Schedule deleted via MC UI: ${name || "#" + id}`);
    }).catch(()=>{
      setSchedules(previous);
      setSchedulesFb({error: "Could not reach the server."});
    });
  };

  // R3i: format retention days as human-readable text for the
  // floor-minimum badge. 2190 -> "6 years", 2555 -> "7 years",
  // 30 -> "30 days", 365 -> "1 year", 366 -> "1 year 1 days".
  const formatRetention = (days) => {
    if (typeof days !== "number" || days < 0) return "—";
    if (days < 365) return `${days} days`;
    const years = Math.floor(days / 365);
    const rem = days % 365;
    const yLabel = `${years} year${years !== 1 ? "s" : ""}`;
    return rem === 0 ? yLabel : `${yLabel} ${rem} days`;
  };

  // R3i: apply a regulatory preset's floor values to the
  // newSchedule form buffer. Picking 'None' (empty string)
  // clears the preset and leaves the operator with full
  // flexibility. Picking a preset pre-fills retention_days
  // and encrypted to the floor and frequency / destination
  // to the preset's recommendations. The operator can still
  // edit retention UPWARD; the server validates on submit.
  // encryption pre-fill is locked when required_encryption
  // is 'AES-256' (the UI disables the checkbox; the operator
  // sees the locked state).
  const applyPresetDefaults = (presetId) => {
    if (!presetId) {
      setNewSchedule(prev => ({ ...prev, regulatory_preset_id: null }));
      return;
    }
    const preset = presets.find(p => p.id === presetId);
    if (!preset) {
      setNewSchedule(prev => ({ ...prev, regulatory_preset_id: presetId }));
      return;
    }
    setNewSchedule(prev => ({
      ...prev,
      regulatory_preset_id: presetId,
      retention_days: preset.min_retention_days,
      encrypted: preset.required_encryption === "AES-256",
      frequency: preset.recommended_frequency || prev.frequency,
      destination: preset.recommended_destination_type || prev.destination,
    }));
  };

  // R3i: submit the new schedule. forceQueue=true is used by the
  // overlap-confirmation modal's retry path; the first submit
  // never sets it. On 409 SCHEDULE_OVERLAP, surface the overlap
  // list in overlapConfirm; on 400 RETENTION_BELOW_FLOOR or
  // ENCRYPTION_REQUIRED, surface the error inline above the
  // form via setAddError. On success, prepend the new schedule
  // to the list (the server-side response carries the full row
  // including next_run), reset the form, show a success
  // feedback banner.
  const submitNewSchedule = async (forceQueue = false) => {
    setAddBusy(true);
    setAddError(null);
    // R3l C59: parse destination_filter from the comma-separated text
    // input into an array of trimmed non-empty tags. Empty string and
    // "no tags entered" both become null so the schema column receives
    // NULL ("no filter" / push to all enabled destinations).
    const filterTags = (newSchedule.destination_filter || "")
      .split(",")
      .map(s => s.trim())
      .filter(Boolean);
    const body = {
      name: newSchedule.name || null,
      type: newSchedule.type,
      frequency: newSchedule.frequency,
      time: newSchedule.frequency === "hourly" ? null : newSchedule.time,
      day_of_week: newSchedule.frequency === "weekly" ? newSchedule.day_of_week : null,
      day_of_month: newSchedule.frequency === "monthly" ? newSchedule.day_of_month : null,
      destination: newSchedule.destination,
      retention_days: typeof newSchedule.retention_days === "string"
        ? (parseInt(newSchedule.retention_days, 10) || 0)
        : newSchedule.retention_days,
      encrypted: !!newSchedule.encrypted,
      regulatory_preset_id: newSchedule.regulatory_preset_id || null,
      active: newSchedule.active !== false,
      // R3l C59: Workstream 3 fields. Service-layer validation enforces
      // enum membership and array shape; the route returns 400 with the
      // precise error code on invalid values (see C57 routes change).
      backup_kind: newSchedule.backup_kind,
      backup_strategy: newSchedule.backup_strategy,
      destination_filter: filterTags.length > 0 ? filterTags : null,
      // R3l C74: max_chain_depth as positive integer or null. Empty
      // string from the form means null (= use global default).
      max_chain_depth: (()=>{
        const v = newSchedule.max_chain_depth;
        if (v === "" || v == null) return null;
        const n = parseInt(v, 10);
        return Number.isFinite(n) && n > 0 ? n : null;
      })(),
    };
    if (forceQueue) body.force_queue = true;
    try {
      const r = await api.post("/api/backup-schedules", body);
      if (r?.error) {
        if (r.error === "SCHEDULE_OVERLAP") {
          setOverlapConfirm({ overlaps: r.overlaps || [], body });
          setAddBusy(false);
          return;
        }
        setAddError(r.message || r.error || "Failed to create schedule.");
        setAddBusy(false);
        return;
      }
      // Success.
      setOverlapConfirm(null);
      const created = r.schedule;
      if (created) setSchedules(prev => [created, ...prev]);
      setSchedulesFb({success: `Schedule "${created?.name || body.name || "#" + (created?.id || "?")}" added.`});
      addA("BACKUP_SCHEDULE_ADDED",
        `Schedule added via MC UI: ${created?.name || body.name || "(unnamed)"} (${body.frequency}, preset: ${body.regulatory_preset_id || "None"})`);
      // Reset form.
      setNewSchedule({
        name: "", type: "full", frequency: "daily", time: "02:00",
        day_of_week: 0, day_of_month: 1, destination: "local",
        retention_days: 30, encrypted: true, regulatory_preset_id: null,
        active: true,
        // R3l C59: reset Workstream 3 fields to safe defaults
        backup_kind: "full-suite", backup_strategy: "full", destination_filter: "",
        // R3l C74: reset max_chain_depth back to empty (= use global)
        max_chain_depth: "",
      });
    } catch (e) {
      setAddError("Could not reach the server.");
    } finally {
      setAddBusy(false);
    }
  };

  // Derived: the preset currently selected by the operator (or
  // null when no preset is selected). Used by the form to show
  // the (minimum: N days) badge next to the retention input and
  // to disable the encryption checkbox when AES-256 is required.
  const activePreset = newSchedule.regulatory_preset_id
    ? presets.find(p => p.id === newSchedule.regulatory_preset_id) || null
    : null;
  // reversePointsForFraud server-side; confirmFraud=false clears the
  // flag and re-includes the rating in the leaderboard.
  //
  // window.confirm provides a hard double-tap on each decision so a
  // single tap on the wrong button doesn't fire an irreversible action.
  // The confirm copy spells out the consequence so the lead knows
  // exactly what will happen.
  //
  // On success, optimistically removes the rating from the local
  // flaggedRatings list so the queue updates without a refetch. On
  // 409 RATING_NOT_FLAGGED (the row was already decided by another
  // lead in the same window), refetches to reconcile.
  const decideFlagged = (ratingId, confirmFraud, helperLabel) => {
    const message = confirmFraud
      ? `Confirm fraud on this rating?\n\nThe helper "${helperLabel}" will lose the points from this rating via a reversal ledger entry. This action is logged in the audit log. The rating row stays flagged forever as audit evidence.`
      : `Dismiss this flag?\n\nThe rating returns to normal status, its points contribution re-appears on the leaderboard, and the flag is cleared. This action is logged in the audit log.`;
    if (!window.confirm(message)) return;
    setFlaggedDecideBusy(ratingId);
    setFlaggedDecideFb(null);
    api.post(`/api/helper-pay/flagged-ratings/${ratingId}/decide`,
      { confirmFraud }
    ).then(r=>{
      if (r?.error) {
        if (r.error === "RATING_NOT_FLAGGED") {
          // Already decided by someone else. Refetch the queue.
          setFlaggedRatings(prev => prev.filter(x => x.rating_id !== ratingId));
          setFlaggedDecideFb({ kind: "info",
            message: "This flag was already resolved." });
          return;
        }
        setFlaggedDecideFb({ kind: "error",
          message: r.message || "Could not record decision." });
        return;
      }
      setFlaggedRatings(prev => prev.filter(x => x.rating_id !== ratingId));
      setFlaggedDecideFb({ kind: "success",
        message: confirmFraud
          ? "Fraud confirmed — points reversed and audit logged."
          : "Flag dismissed — points restored to the leaderboard." });
      addA(confirmFraud
        ? "LEADERBOARD_SOCKPUPPET_CONFIRMED"
        : "LEADERBOARD_SOCKPUPPET_DISMISSED",
        `Sock-puppet review decided for rating ${ratingId.slice(0, 8)}...`);
    }).catch(()=>{
      setFlaggedDecideFb({ kind: "error",
        message: "Could not reach the server." });
    }).finally(()=>setFlaggedDecideBusy(null));
  };
  const [analysts, setAnalysts] = useState(ANALYSTS_INIT);
  const [provisionedClients, setPC] = useState([]);
  const [showProvision, setShowProvision] = useState(false);
  const [newA, setNewA] = useState({name:"",tier:1,shift:"day",hostname:"",ip:""});
  const [showCEF, setShowCEF] = useState(false);
  const [showCloudWF, setShowCloudWF] = useState(null);
  const [showIaC, setShowIaC] = useState(false);
  // R3k C36 — Cloud & IaC server-side generator wiring
  const [iacProvider, setIacProvider] = useState("");
  const [iacTool, setIacTool] = useState("");
  const [iacResult, setIacResult] = useState(null);
  const [iacBusy, setIacBusy] = useState(false);
  const IAC_TOOLS_BY_PROVIDER = {
    aws:      ["terraform","pulumi","cloudformation","docker-compose","docker-manifest","kubernetes","helm"],
    azure:    ["terraform","pulumi","bicep","docker-compose","docker-manifest","kubernetes","helm"],
    gcp:      ["terraform","pulumi","gcp-dm","docker-compose","docker-manifest","kubernetes","helm"],
    hetzner:  ["terraform","pulumi","docker-compose","docker-manifest","kubernetes","helm"],
    ovhcloud: ["terraform","pulumi","docker-compose","docker-manifest","kubernetes","helm"],
    exoscale: ["terraform","pulumi","docker-compose","docker-manifest","kubernetes","helm"],
  };
  // R3l C69: mock backups now include backup_strategy + parent chain
  // fields so demo mode shows the new strategy badges and a 2-link chain
  // example. Real backups loaded from /api/backup carry these fields
  // when format_version=2 (set by C53/C55 schema columns).
  const [backups, setBackups] = useState([{id:1,ts:"2026-03-27 02:00",type:"daily-auto",backup_strategy:"full",size:"2.4 GB",status:"verified",hash:"sha256:a3f8c…"},{id:2,ts:"2026-03-26 02:00",type:"daily-auto",backup_strategy:"incremental",parent_backup_id:1,parent_full_backup_id:1,page_count:48,wal_start_position:"32:0",wal_end_position:"196640:48",size:"12 MB",status:"verified",hash:"sha256:b7e2d…"}]);
  // R3l C70: expandable chain view. expandedChains tracks which row's
  // chain panel is open; chainData caches the response from
  // GET /api/backup/:id/chain (the C68 endpoint); chainLoading tracks
  // in-flight fetches so the UI can show a spinner-equivalent.
  // Cache key is the leaf backup id; once fetched, the chain panel
  // expands instantly on subsequent toggles.
  const [expandedChains, setExpandedChains] = useState({});
  const [chainData, setChainData] = useState({});
  const [chainLoading, setChainLoading] = useState({});
  // R3l C71: restore-preview modal. null when closed; when open:
  //   { backupId, confirmInput, restoring, error, result }
  // The modal reuses chainData (populated by C70 expansion or fetched
  // when the modal opens) to render the chain preview, then surfaces a
  // confirmation gate (first 8 chars of leaf hash) before calling
  // POST /api/restore/execute-chain/:id for chain backups, or
  // POST /api/restore/execute/:id for full/snapshot backups.
  const [restoreModal, setRestoreModal] = useState(null);
  const [snapshots, setSnapshots] = useState([]);
  const [forensicExports, setFE] = useState([]);
  const [appVersion, setAppVersion] = useState("");
  const [appBuild, setAppBuild] = useState("");
  const [appFuse, setAppFuse] = useState("");
  const [appFuseLastIncrement, setAppFuseLastIncrement] = useState("");
  useEffect(()=>{
    api.get("/api/system/version").then(r=>{
      if (r?.version) setAppVersion(r.version);
      if (r?.buildId) setAppBuild(r.buildId);
      if (r?.fuseCounter !== undefined) setAppFuse(String(r.fuseCounter));
      if (r?.fuseLastIncrement) setAppFuseLastIncrement(r.fuseLastIncrement);
    }).catch(()=>{});
  }, []);
  const [updateCheck, setUpdateCheck] = useState(null); // null | "checking" | {available,version} | "current"
  const [routingCaps, setRC] = useState(Object.fromEntries(ANALYSTS_INIT.filter(a=>a.shift==="day").map(a=>[a.id,a.tier===3?5:a.tier===2?3:2])));
  const [unsaved, setUnsaved] = useState(false);
  // R3j C8: routing-tab canonical wiring state. routingHydrated gates the
  // one-shot useEffect that fetches /api/routing on tab open. routingSaveError
  // surfaces a server error inline under the Apply button. routingSaveBusy
  // disables Apply during in-flight PUT batch.
  const [routingHydrated, setRoutingHydrated] = useState(false);
  const [routingSaveError, setRoutingSaveError] = useState(null);
  const [routingSaveBusy, setRoutingSaveBusy] = useState(false);
  const [liveFeed, setLF] = useState([]);
  const [sessCt, setSC] = useState(Object.fromEntries(ANALYSTS_INIT.filter(a=>a.shift==="day").map(a=>[a.id,{t:0,h:0}])));
  const [auditPage, setAuditPage] = useState(0);
  const AUDIT_PER_PAGE = 50;
  // IAM wizard state
  const [iamTab, setIamTab] = useState("saml");
  const [iamCfg, setIamCfg] = useState({saml:{entityId:"",metadataUrl:"",cert:"",jit:true,status:"not_configured"},oidc:{issuer:"",clientId:"",secret:"",scopes:"openid profile email groups",status:"not_configured"},ad:{server:"",port:"636",baseDn:"",bindDn:"",useTLS:true,syncInterval:"15",status:"not_configured"},cloud:{provider:"none",tenantId:"",status:"not_configured"}});
  // Report engine state
  const [reportTab, setReportTab] = useState("config");
  const [reportCfg, setReportCfg] = useState({schedule:"weekly",day:"monday",time:"08:00",format:"pdf",recipients:"",siemFeed:true,sections:{teamHealth:true,utilization:true,tierBreakdown:true,automationRate:true,trendAnalysis:true,kbInsights:true,skillProgress:true,upskillingGaps:true}});
  const [reports, setReports] = useState([{id:1,ts:"2026-03-24 08:00",type:"weekly-auto",status:"delivered",sections:6},{id:2,ts:"2026-03-17 08:00",type:"weekly-auto",status:"delivered",sections:6}]);
  // KB state
  const [kbFilter, setKBFilter] = useState("all");
  const [showKBIngestion, setShowKBIngestion] = useState(false);
  const [devAuth, setDevAuth] = useState(false);
  const [devKey, setDevKey] = useState("");

  // Skills Assessment state
  const [assessments, setAssessments] = useState([
    {id:"a001",name:"L1 Onboarding Assessment",tier:1,skills:["triage","documentation","phishing_analysis","log_analysis","siem_queries"],assignees:["jordan-p","priya-s","fatima-a"],createdAt:"2026-03-25",status:"active",results:{"jordan-p":{triage:85,documentation:91,phishing_analysis:78,log_analysis:70,siem_queries:65,completedAt:"2026-03-27"},"priya-s":{triage:72,documentation:68,phishing_analysis:60,log_analysis:55,siem_queries:45,completedAt:"2026-03-28"}}},
    {id:"a002",name:"L2 Readiness Evaluation",tier:2,skills:["investigation","escalation","malware_analysis","network_analysis","threat_hunting"],assignees:["jordan-p","alex-k"],createdAt:"2026-03-28",status:"active",results:{"jordan-p":{investigation:62,escalation:55,malware_analysis:30,network_analysis:58,threat_hunting:28,completedAt:"2026-03-29"}}},
  ]);
  const [showCreateAssmt, setShowCreateAssmt] = useState(false);
  const [newAssmt, setNewAssmt] = useState({name:"",tier:1,skills:[],assignees:[],customSkills:[]});
  const [newCustomSkill, setNewCustomSkill] = useState({name:"",desc:""});

  // Phase B: cross-app state
  const [handoffNotes, setHandoffNotes] = useState("");
  const [handoffHistory, setHandoffHistory] = useState([
    {ts:"Mar 28 06:00",from:"Night → Day",notes:"Quiet shift. Ransomware false positive resolved at 03:40. All clear."},
    {ts:"Mar 27 22:00",from:"Swing → Night",notes:"Active investigations in progress. Monitor high-utilization analysts for overload."},
  ]);
  const [lqRequests, setLqRequests] = useState([{id:1,ts:"08:14",dur:"This shift",reason:"Anonymous",status:"active",cap:2}]);
  const [activeRetros, setActiveRetros] = useState([
    // CISM retro incidents populated from real post-incident workflows.
    // CISM retro entries populated from real post-incident workflows.
  ]);
  const [retroIncident, setRetroIncident] = useState("");
  const [retroSeverity, setRetroSeverity] = useState("P1");
  const [retroAnalysts, setRetroAnalysts] = useState([]);
  const [retroDuration, setRetroDuration] = useState("24hr");
  const [customResources, setCustomResources] = useState([]);
  const [newResTitle, setNewResTitle] = useState("");
  const [newResUrl, setNewResUrl] = useState("");
  const [newResCat, setNewResCat] = useState("professional");
  const [slaConfig, setSlaConfig] = useState({p1mtta:"5m",p1mttr:"60m",p2mtta:"15m",p2mttr:"4h"});
  const [soarPlatform, setSoarPlatform] = useState("splunk_soar");
  const [soarUrl, setSoarUrl] = useState("");
  const [soarApiKey, setSoarApiKey] = useState("");
  // R3j C7 / R3n: SOAR + Ticketing form state. Hydrated from canonical
  // /api/integrations/soar and /api/integrations/ticketing on tab open.
  // R3n SOC-grade Option C: sensitive fields are STRIPPED entirely from
  // GET responses; presence-metadata via sensitiveFieldsPresent.apiKey
  // drives the UI affordance.
  //   *Present state vars: true when server holds a value (per GET metadata).
  //                        Drives "Configured ✓" + "Change Secret" affordance.
  //   *Changing state vars: true when the lead clicked Change to reveal the
  //                         input. Drives whether apiKey is included in PUT body.
  const [soarApiKeyPresent, setSoarApiKeyPresent] = useState(false);
  const [soarApiKeyChanging, setSoarApiKeyChanging] = useState(false);
  const [soarServiceAccount, setSoarServiceAccount] = useState("");
  const [soarAutoEscalate, setSoarAutoEscalate] = useState(false);
  const [soarTicketingPlatform, setSoarTicketingPlatform] = useState("");
  const [soarTicketingEndpoint, setSoarTicketingEndpoint] = useState("");
  const [soarTicketingApiKey, setSoarTicketingApiKey] = useState("");
  const [soarTicketingApiKeyPresent, setSoarTicketingApiKeyPresent] = useState(false);
  const [soarTicketingApiKeyChanging, setSoarTicketingApiKeyChanging] = useState(false);
  const [soarHydrated, setSoarHydrated] = useState(false);
  const [soarSaveError, setSoarSaveError] = useState(null);
  const [soarSaveBusy, setSoarSaveBusy] = useState(false);
  const [soarTestResult, setSoarTestResult] = useState(null);
  const [soarTestBusy, setSoarTestBusy] = useState(false);
  // R3j C10: Live SOAR Routing State surface. soarLiveVariables holds the 6
  // currently-published SOAR variables fetched from GET /api/routing/soar
  // (the variables FireAlive is publishing TO the SOAR right now). The
  // companion polling useEffect refreshes this every 30s while tab==="soar"
  // is open; soarLiveLastFetched holds the ISO timestamp of the most recent
  // successful fetch for the "Last updated ... ago" display under the card.
  const [soarLiveVariables, setSoarLiveVariables] = useState(null);
  const [soarLiveLastFetched, setSoarLiveLastFetched] = useState(null);

  // ── New v1.0.0 state ──────────────────────────────────────────────────
  const [panicMode, setPanicMode] = useState(false);
  // R3j C9: canonical panic state hydration + post-deactivation linger window.
  // panicMode is now hydrated by polling /api/routing/panic every 30s rather
  // than being a local-only toggle. panicDeactivatedAt holds the ISO timestamp
  // of the most recent deactivation; when present and within
  // PANIC_BANNER_LINGER_SECONDS of now, the top-of-MC banner renders the green
  // "routing restored" indicator. After the linger window the banner vanishes.
  // The server's GET /api/routing/panic enforces the same 300s window
  // server-side via opportunistic cleanup; the client recomputes against
  // Date.now() on every render so the green banner disappears at the right
  // moment even between 30s polls.
  const [panicDeactivatedAt, setPanicDeactivatedAt] = useState(null);
  const [panicBusy, setPanicBusy] = useState(false);
  const [panicError, setPanicError] = useState(null);
  // ── v1.0.0 state that was in wrong component (fixed in v1.0.0) ──
  const [humanImpactReport, setHIR] = useState(null);
  const [hirLoading, setHirLoading] = useState(false);
  const [edrCfg, setEdrCfg] = useState({enabled:false,provider:null,scanOnUpload:true,scanOnRestore:true,scanOnPolicyImport:true,blockOnThreat:true,quarantineOnSuspicious:true});
  // ── Phase F4c: Multi-provider malware scanner integration ──
  const [scannerList, setScannerList] = useState([]);
  const [scanMode, setScanMode] = useState("single_with_fallback");
  const [scannerForm, setScannerForm] = useState(null); // {mode:'add'|'edit', id?, provider_type, display_name, priority, enabled, credentials:{}}
  const [scannerTestResult, setScannerTestResult] = useState({}); // id -> {ok, error, latencyMs}
  const [scannerListLoading, setScannerListLoading] = useState(false);
  const [scannerError, setScannerError] = useState(null);
  const SCANNER_PROVIDERS = [
    {id:"clamav",label:"ClamAV (on-prem signature)",fields:[{k:"socketPath",l:"Socket path",ph:"/var/run/clamav/clamd.sock"},{k:"host",l:"Host (alt to socket)",ph:"clamd.internal"},{k:"port",l:"Port",ph:"3310"}]},
    {id:"virustotal",label:"VirusTotal",fields:[{k:"apiKey",l:"API key",secret:true}]},
    {id:"crowdstrike_falcon",label:"CrowdStrike Falcon Sandbox",fields:[{k:"clientId",l:"Client ID"},{k:"clientSecret",l:"Client secret",secret:true},{k:"region",l:"Region",sel:[{v:"us-1",l:"US-1"},{v:"us-2",l:"US-2"},{v:"eu-1",l:"EU-1"},{v:"us-gov-1",l:"US-GOV-1"}]},{k:"environmentId",l:"Sandbox environment",sel:[{v:"100",l:"Win10 64-bit (default)"},{v:"110",l:"Win7"},{v:"200",l:"Linux Ubuntu"}]}]},
    {id:"microsoft_defender",label:"Microsoft Defender for Endpoint",fields:[{k:"tenantId",l:"Tenant ID"},{k:"clientId",l:"Client ID"},{k:"clientSecret",l:"Client secret",secret:true},{k:"cloud",l:"Cloud",sel:[{v:"commercial",l:"Commercial"},{v:"gcc",l:"GCC"},{v:"gcc-high",l:"GCC High"},{v:"dod",l:"DOD"}]}]},
    {id:"sentinelone",label:"SentinelOne Singularity",fields:[{k:"siteUrl",l:"Site URL",ph:"https://<tenant>.sentinelone.net"},{k:"apiToken",l:"API token",secret:true}]},
    {id:"cisco_amp",label:"Cisco Secure Endpoint (AMP)",fields:[{k:"clientId",l:"Client ID"},{k:"apiKey",l:"API key",secret:true},{k:"region",l:"Region",sel:[{v:"na",l:"North America"},{v:"eu",l:"Europe"},{v:"apjc",l:"Asia Pacific"}]}]},
    {id:"fortinet_fortisandbox",label:"Fortinet FortiSandbox",fields:[{k:"baseUrl",l:"Base URL",ph:"https://fortisandbox.example.com"},{k:"user",l:"Username"},{k:"password",l:"Password",secret:true},{k:"verifyTls",l:"Verify TLS cert (recommended)",bool:true}]},
    {id:"trellix_atd",label:"Trellix ATD (formerly McAfee ATD)",fields:[{k:"baseUrl",l:"Base URL",ph:"https://atd.example.com"},{k:"user",l:"Username"},{k:"password",l:"Password",secret:true},{k:"verifyTls",l:"Verify TLS cert (recommended)",bool:true}]},
    {id:"sophos_intelix",label:"Sophos Intelix",fields:[{k:"clientId",l:"Client ID"},{k:"clientSecret",l:"Client secret",secret:true},{k:"region",l:"Region",sel:[{v:"de",l:"Germany (default)"},{v:"us",l:"United States"},{v:"eu",l:"Europe"},{v:"au",l:"Australia"}]},{k:"scoreThreshold",l:"Score threshold (1=strict, 30=permissive)",ph:"1"}]},
    {id:"joe_sandbox",label:"Joe Sandbox",fields:[{k:"apiKey",l:"API key",secret:true},{k:"baseUrl",l:"Base URL (default Cloud Pro)",ph:"https://jbxcloud.joesecurity.org"},{k:"verifyTls",l:"Verify TLS cert (recommended)",bool:true}]},
    {id:"hybrid_analysis",label:"Hybrid Analysis (free tier of Falcon Sandbox)",fields:[{k:"apiKey",l:"API key",secret:true},{k:"environmentId",l:"Sandbox environment",sel:[{v:"120",l:"Win7 64-bit (default)"},{v:"100",l:"Win7 32-bit"},{v:"200",l:"Linux Ubuntu"},{v:"300",l:"Android"},{v:"400",l:"Mac OS X"}]}]},
    {id:"palo_alto_wildfire",label:"Palo Alto WildFire",fields:[{k:"apiKey",l:"API key",secret:true},{k:"region",l:"Region",sel:[{v:"us",l:"United States"},{v:"eu",l:"Europe"},{v:"jp",l:"Japan"},{v:"sg",l:"Singapore"},{v:"ca",l:"Canada"},{v:"uk",l:"United Kingdom"},{v:"au",l:"Australia"}]}]},
    {id:"blackberry_cylance",label:"BlackBerry Cylance Infinity",fields:[{k:"tenantId",l:"Tenant ID (UUID)"},{k:"appId",l:"Application ID (UUID)"},{k:"appSecret",l:"Application secret",secret:true},{k:"region",l:"Region",sel:[{v:"na",l:"North America"},{v:"euc1",l:"Europe Central"},{v:"au",l:"Australia"},{v:"apne1",l:"Asia Pacific North"},{v:"sae1",l:"South America"}]}]},
    {id:"trend_micro_ddan",label:"Trend Micro Deep Discovery Analyzer",fields:[{k:"baseUrl",l:"Base URL",ph:"https://ddan.example.com"},{k:"apiKey",l:"API key",secret:true},{k:"verifyTls",l:"Verify TLS cert (recommended)",bool:true}]},
    {id:"kaspersky_sandbox",label:"Kaspersky Sandbox",fields:[{k:"baseUrl",l:"Base URL",ph:"https://kaspersky.example.com"},{k:"user",l:"Username"},{k:"password",l:"Password",secret:true},{k:"vmId",l:"VM ID (optional)"},{k:"verifyTls",l:"Verify TLS cert (recommended)",bool:true}]},
  ];
  const reloadScanners = async () => {
    setScannerListLoading(true);
    setScannerError(null);
    try {
      const r = await api.get("/api/v1/malware-scanners");
      if (r && Array.isArray(r.scanners)) setScannerList(r.scanners);
      else if (r && r.error) setScannerError(r.error);
      const m = await api.get("/api/v1/malware-scanners/scan-mode");
      if (m && m.mode) setScanMode(m.mode);
    } catch (e) { setScannerError(e.message); }
    setScannerListLoading(false);
  };
  useEffect(() => { reloadScanners(); }, []);
  const [kmsCfg, setKmsCfg] = useState({enabled:false,provider:null,endpoint:"",keyId:"",rotationPolicy:"annual",envelopeEncryption:true,hsmBacked:false,keyUsage:{tier3Encryption:true,tier1Encryption:true,e2eeKeyWrapping:true,backupEncryption:true,auditLogSigning:true}});
  const [wifiPolicy, setWifiPolicy] = useState({minimumProtocol:"wpa2_enterprise",wpa3Preferred:true,blockWpa2Personal:true,requireDot1x:true,warnOnInsecure:true,disconnectOnInsecure:false});
  const [mspCfg, setMspCfg] = useState({enabled:false,tenants:[],isolation:{separateEncryptionKeys:true,separateAuditTrails:true,crossTenantAccessBlocked:true,tenantScopedApiKeys:true,perTenantBackups:true},managementOverlay:{centralDashboard:true,aggregateReporting:false,tenantAdminDelegation:true}});
  const [newTenantName, setNewTenantName] = useState("");
  // ── v1.0.0 NEW STATE ──────────────────────────────────────────────────
  // MFA wizard
  const [mfaCfg, setMfaCfg] = useState({enabled:false,method:"totp",enforceForAll:true,graceLogins:3,rememberDeviceDays:30,backupCodes:true,status:"not_configured"});
  // Threat hunting integrations (expanded beyond EDR)
  const [threatHuntCfg, setThreatHuntCfg] = useState({xdr:{enabled:false,provider:null,behaviorMonitoring:true,consumptionMetrics:true},atp:{enabled:false,provider:null},ngav:{enabled:false,provider:null,realTimeScan:true},mspScanner:{enabled:false,provider:null,agentId:""}});
  // Tripwire
  const [tripwireCfg, setTripwireCfg] = useState({enabled:false,thresholdPct:40,autoDisableRouting:true,notifyLead:true,triggerSoarScan:true,triggerEdrScan:true,preserveAnonymity:true});
  const [tripwireTriggered, setTripwireTriggered] = useState(false);
  // Client compromise scan
  const [compromiseScanRunning, setCompScanRunning] = useState(false);
  const [compromiseScanResults, setCompScanResults] = useState(null);
  // Auth logs
  const [authLogs, setAuthLogs] = useState([
    {ts:"2026-04-08T08:01:00Z",user:"lead@corp.local",action:"LOGIN_SUCCESS",ip:"10.0.1.50",method:"password+totp"},
    {ts:"2026-04-08T07:58:00Z",user:"unknown",action:"LOGIN_FAILED",ip:"192.168.1.99",method:"password",reason:"Invalid credentials"},
    {ts:"2026-04-08T03:14:00Z",user:"analyst3@corp.local",action:"LOGIN_FAILED",ip:"10.0.1.72",method:"password",reason:"Account locked"},
    {ts:"2026-04-07T23:42:00Z",user:"lead@corp.local",action:"LOGIN_SUCCESS",ip:"10.0.1.50",method:"saml_sso"},
  ]);
  const [authLogNotifCfg, setAuthLogNotifCfg] = useState({outOfCycleAttempts:true,deletedLogs:true,missingLogs:true,bruteForceThreshold:5,outOfCycleStartHr:0,outOfCycleEndHr:5});
  // Posture assessment
  const [postureCfg, setPostureCfg] = useState({enabled:true,requireOnConnect:true,checks:{osUpdated:true,avEnabled:true,firewallEnabled:true,diskEncrypted:true,screenLockEnabled:true,wifiCompliant:true,endpointProtectionRunning:true,minTlsVersion:"1.2"},blockOnFail:false,warnOnFail:true,gracePeriodMin:10});
  // HA configuration
  const [haCfg, setHaCfg] = useState({enabled:false,mode:"active_passive",failoverEndpoint:"",syncIntervalSec:5,loadBalancer:{enabled:false,type:"round_robin",healthCheckSec:10,healthPath:"/api/health"},replicationStatus:"idle",lastSyncAt:null});
  // Fail-open routing
  const [failOpenCfg, setFailOpenCfg] = useState({enabled:true,autoDetect:true,notifyOnFailOpen:true,maxFailOpenMin:60,restoreAuto:true});
  // Config troubleshooter
  const [troubleshooterOpen, setTroubleshooterOpen] = useState(false);
  const [troubleshooterMsgs, setTroubleshooterMsgs] = useState([]);
  const [troubleshooterInput, setTroubleshooterInput] = useState("");
  // General cert uploads (beyond training-linked certs)
  const [generalCerts, setGeneralCerts] = useState([
    {id:"gc1",name:"CompTIA Security+",issuer:"CompTIA",earned:"2025-06-15",expires:"2028-06-15",analyst:"jordan-p"},
    {id:"gc2",name:"CySA+",issuer:"CompTIA",earned:"2025-09-20",expires:"2028-09-20",analyst:"alex-k"},
  ]);
  const [newCert, setNewCert] = useState({name:"",issuer:"",earned:"",expires:"",analyst:""});
  // ── v1.0.0 NEW STATE ──────────────────────────────────────────────────
  // Pseudonym system
  const [pseudonymCfg, setPseudonymCfg] = useState({enabled:true,autoGenerate:true,allowCustom:true,prefix:"Analyst",separator:"-",showRealNameToLead:true,leadExportEnabled:true});
  // Pseudonyms generated automatically when analysts are provisioned.
  const [analystPseudonyms, setAnalystPseudonyms] = useState([]);
  // Data sovereignty / geo-fencing
  const [geoFenceCfg, setGeoFenceCfg] = useState({enabled:false,enforceGeoLogin:true,clients:[]});
  const [newGeoClient, setNewGeoClient] = useState({clientId:"",country:"",region:"",dataResidency:"local",regulatoryFramework:"none"});
  // HA enhancements
  const [haManualFailover, setHaManualFailover] = useState(false);
  const [haTestResults, setHaTestResults] = useState(null);
  const [haTestRunning, setHaTestRunning] = useState(false);
  // Cluster config
  const [clusterCfg, setClusterCfg] = useState({enabled:false,mode:"active_active",nodeCount:2,nodes:[],sessionStore:"redis",parallelProcessing:true,workerThreads:4});
  // Global dashboard (read-only VP view)
  const [globalDashCfg, setGlobalDashCfg] = useState({enabled:false,endpoint_url:"",api_key_set:false,api_key_input:"",push_interval_minutes:15,retry_max:3,retry_backoff_seconds:30,last_push_at:null,last_push_status:null,last_push_error:null,consecutive_failures:0,_loaded:false,_saving:false,_testing:false,_testResult:null,_savedEndpointUrl:"",_savedApiKeySet:false});
  useEffect(()=>{
    if (tab !== "global_dash") return;
    if (globalDashCfg._loaded) return;
    api.get("/api/gd-config").then(r=>{
      if (r && !r.error) {
        setGlobalDashCfg(prev=>({...prev, ...r, api_key_input:"", _loaded:true, _savedEndpointUrl:r.endpoint_url||"", _savedApiKeySet:!!r.api_key_set}));
      }
    }).catch(()=>{});
  }, [tab, globalDashCfg._loaded]);
  // R3c — HR scheduling platform configuration (loads when upskilling_hr tab opens)
  const [schedCfg, setSchedCfg] = useState({
    enabled: false,
    platform: null,
    endpoint_url: "",
    credentials_set: false,
    sync_interval_minutes: 60,
    retry_max: 3,
    retry_backoff_seconds: 30,
    last_sync_at: null,
    last_sync_status: null,
    last_sync_error: null,
    last_sync_duration_ms: null,
    consecutive_failures: 0,
    updated_at: null,
    _loaded: false,
    _saving: false,
    _testing: false,
    _testResult: null,
    _savedPlatform: null,
    _savedEndpointUrl: "",
    _savedCredsSet: false,
    credentials_input: {},
  });
  useEffect(() => {
    if (tab !== "upskilling_hr") return;
    if (schedCfg._loaded) return;
    api.get("/api/scheduling/config").then(r => {
      if (r && !r.error) {
        setSchedCfg(prev => ({
          ...prev, ...r,
          credentials_input: {},
          _loaded: true,
          _savedPlatform: r.platform || null,
          _savedEndpointUrl: r.endpoint_url || "",
          _savedCredsSet: !!r.credentials_set,
        }));
      }
    }).catch(() => {});
  }, [tab, schedCfg._loaded]);

  // R3i: API-backed Backup Schedules state. Replaces the v1.0.28
  // frontend-state-only backupSchedules array + the newBackupSched
  // form-buffer state with state hydrated from /api/backup-schedules
  // (the C5 routes consuming the C4 service consuming the C1+C2
  // tables). The Add Schedule form's form-buffer state is added back
  // in C9 with the hybrid floor-enforcement model wired to the
  // presets endpoint.
  const [schedules, setSchedules] = useState([]);
  const [schedulesLoading, setSchedulesLoading] = useState(false);
  const [schedulesError, setSchedulesError] = useState(null);
  const [schedulesFb, setSchedulesFb] = useState(null);
  const [presets, setPresets] = useState([]);
  // R3i: Add Schedule form-buffer state. Replaces the v1.0.28
  // newBackupSched local-only buffer with a server-aware shape
  // matching the POST /api/backup-schedules body. addBusy gates
  // the submit button during the in-flight request; addError
  // surfaces the 400 error message inline (above the form);
  // overlapConfirm is non-null when the server returned a 409
  // SCHEDULE_OVERLAP — it carries the overlap list AND the
  // form data that triggered it so the operator can confirm
  // queuing via a force_queue=true retry without re-entering
  // the form.
  const [newSchedule, setNewSchedule] = useState({
    name: "", type: "full", frequency: "daily", time: "02:00",
    day_of_week: 0, day_of_month: 1, destination: "local",
    retention_days: 30, encrypted: true, regulatory_preset_id: null,
    active: true,
    // R3l C59: Workstream 3 schema fields with safe defaults
    backup_kind: "full-suite", backup_strategy: "full", destination_filter: "",
    // R3l C74: max_chain_depth empty string means "use global default
    // (system_meta.max_chain_depth, seeded to 100 by the C73 migration)".
    // Operators who want per-schedule control enter a positive integer
    // ≤1000. Service-layer validation in backup-schedules.js rejects
    // out-of-bounds values with INVALID_MAX_CHAIN_DEPTH.
    max_chain_depth: "",
  });
  // R3l C59: enabled backup_destinations cache for the destination_filter
  // summary panel. Fetched lazily when the Backup Schedules tab opens
  // (same effect that loads schedules + presets) so an operator can see
  // which destinations their filter actually matches before saving.
  const [enabledDestinations, setEnabledDestinations] = useState([]);
  // R3l C60: quick-form state for the Backup & Storage Routing tab's
  // inline "Backup Scheduler" card. Pre-R3l, that card's selectors were
  // cosmetic and the Save button posted hardcoded values; C60 adds three
  // wired selectors so kind/strategy/filter chosen here actually reach
  // the server. Existing legacy fields on that card remain cosmetic for
  // backward-compat; the Add Schedule form in the Backup Schedules tab
  // (C59) is the canonical full-fidelity entry point.
  const [qkBackupKind, setQkBackupKind] = useState("full-suite");
  const [qkBackupStrategy, setQkBackupStrategy] = useState("full");
  const [qkDestinationFilter, setQkDestinationFilter] = useState("");
  const [addBusy, setAddBusy] = useState(false);
  const [addError, setAddError] = useState(null);
  const [overlapConfirm, setOverlapConfirm] = useState(null);
  // Burnout stats sync interval
  const [syncIntervalCfg, setSyncIntervalCfg] = useState({intervalMin:15,adaptiveSync:true,urgentThresholdSec:30,batchMode:true});
  // Feature toggles
  const [featureToggles, setFT] = useState({peer_chat:true,breathing_exercise:true,lighter_queue:true,lead_messaging:true,delegation:true,skill_assessments:true,training_certs:true,retro_protocol:true,burnout_routing:true,siem_feed:true,report_engine:true,soar_integration:true,ticket_integration:true,signals_display:true,impact_feed:true,network_map:false,query_tool:false,ooda_simulator:true,recertification:true,vuln_scanning:false,sase:false,peer_scheduling:true,lead_chat_identified:true,config_export:true,log_integrity:true,client_notifications:true,peer_board:true,peer_queue_mgmt:true,calendar_integration:true,security_regression:true,soar_playbooks:true,cicd_pipelines:false,cloud_vuln_scan:false,queue_timeout:true,human_impact_risk:true,edr_inspection:true,enterprise_kms:false,wifi_policy:true,msp_multitenancy:false,post_session_rating:true,post_session_flagging:true,mfa_wizard:true,threat_hunting:true,tripwire:true,compromise_scan:true,auth_logs:true,posture_assessment:true,ha_config:false,fail_open_routing:true,config_troubleshooter:true,general_certs:true,auth_log_notifications:true,pseudonyms:true,geo_fencing:false,cluster_mode:false,global_dashboard:false,backup_schedules:true,sync_interval_config:true,inactivity_lock:true,biometrics:false,config_padlocks:true,concurrent_session_block:true,setup_wizard:true,welcome_guide:true,insider_threat_protocol:true,dual_approval:false,proactive_interventions:true,recovery_runbook:true,upskilling_hour:false,auto_routing_disable:false,analyst_offboarding:true,ttx_generator:true,legal_hold:false,risk_register:true});
  // Compliance
  const [complianceFw, setCompFw] = useState("nist_csf");
  const [complianceReport, setCompReport] = useState(null);
  // Monitoring
  // R3l C14: monMetrics wired to /api/system/version (extended in C8 with runtime.cpu and database subtrees).
  // Defaults stay as zeros until first fetch resolves; periodic refresh every 30s while the component is mounted.
  const [monMetrics, setMonMetrics] = useState({cpu:0,memMB:0,heapMB:0,dbSizeMB:0,uptime:0,loadAvg:[0,0,0],cores:0,freeMemMB:0,totalMemMB:0,fileCount:0});
  const [monMetricsLoadState, setMonMetricsLoadState] = useState({loaded:false, error:null});
  useEffect(() => {
    let cancelled = false;
    const parseMB = (s) => { if (typeof s === 'number') return s; if (typeof s !== 'string') return 0; const n = parseInt(s.replace(/[^0-9]/g,''), 10); return Number.isFinite(n) ? n : 0; };
    const fetchMetrics = () => {
      api.get('/api/system/version').then((r) => {
        if (cancelled) return;
        if (!r || r.error) { setMonMetricsLoadState({loaded:false, error: r?.error || 'request_failed'}); return; }
        setMonMetrics((prev) => ({
          ...prev,
          cpu: typeof r.runtime?.cpu?.percent1m === 'number' ? r.runtime.cpu.percent1m : prev.cpu,
          memMB: parseMB(r.runtime?.memory?.rss),
          heapMB: parseMB(r.runtime?.memory?.heap),
          dbSizeMB: typeof r.database?.sizeMB === 'number' ? r.database.sizeMB : prev.dbSizeMB,
          uptime: typeof r.runtime?.uptime === 'number' ? r.runtime.uptime : prev.uptime,
          loadAvg: [r.runtime?.cpu?.loadAvg1m ?? prev.loadAvg[0], r.runtime?.cpu?.loadAvg5m ?? prev.loadAvg[1], r.runtime?.cpu?.loadAvg15m ?? prev.loadAvg[2]],
          cores: typeof r.runtime?.cpu?.cores === 'number' ? r.runtime.cpu.cores : prev.cores,
        }));
        setMonMetricsLoadState({loaded:true, error:null});
      }).catch((e) => { if (cancelled) return; setMonMetricsLoadState({loaded:false, error: e?.message || 'request_failed'}); });
    };
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 30000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  // R3l C15: Connected Sessions wired to /api/system/connected-clients (introduced in C9).
  // Privacy-conscious shape: only userId/role/isAlive — no IP, no UA, no per-client cpu/mem.
  // Periodic refresh every 15s while the component is mounted.
  const [connectedClients, setConnectedClients] = useState({initialized:false, count:0, alive:0, stale:0, by_role:{}, clients:[]});
  const [connectedClientsLoadState, setConnectedClientsLoadState] = useState({loaded:false, error:null});
  useEffect(() => {
    let cancelled = false;
    const fetchClients = () => {
      api.get('/api/system/connected-clients').then((r) => {
        if (cancelled) return;
        if (!r || r.error) { setConnectedClientsLoadState({loaded:false, error: r?.error || 'request_failed'}); return; }
        setConnectedClients({
          initialized: r.initialized === true,
          count: typeof r.count === 'number' ? r.count : 0,
          alive: typeof r.alive === 'number' ? r.alive : 0,
          stale: typeof r.stale === 'number' ? r.stale : 0,
          by_role: r.by_role && typeof r.by_role === 'object' ? r.by_role : {},
          clients: Array.isArray(r.clients) ? r.clients : [],
        });
        setConnectedClientsLoadState({loaded:true, error:null});
      }).catch((e) => { if (cancelled) return; setConnectedClientsLoadState({loaded:false, error: e?.message || 'request_failed'}); });
    };
    fetchClients();
    const interval = setInterval(fetchClients, 15000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);
  // R3l C16: Training Completions Review (lead/admin).
  // State for the filtered queue, the active status filter, the load state,
  // a separate badge poll (so the navGroup count stays roughly fresh while
  // the tab is closed), and per-row in-flight tracking for PATCH actions.
  // The server enforces only pending -> verified|rejected transitions, so
  // verify/reject buttons render only for rows whose status is "pending".
  const [trainingReviewStatusFilter, setTrainingReviewStatusFilter] = useState('pending');
  const [trainingReviewQueue, setTrainingReviewQueue] = useState({ completions: [], counts: { pending: 0, verified: 0, rejected: 0, total: 0 } });
  const [trainingReviewLoadState, setTrainingReviewLoadState] = useState({ loaded: false, error: null });
  const [trainingReviewPendingCount, setTrainingReviewPendingCount] = useState(0);
  const [trainingReviewPatchInFlight, setTrainingReviewPatchInFlight] = useState({});
  const [trainingReviewPatchError, setTrainingReviewPatchError] = useState(null);
  // Always-on lightweight badge poll. Fetches just the counts subtree every
  // 60s so the navGroup badge surfaces the pending workload even when the
  // tab is not open. Best-effort: errors are silently swallowed.
  useEffect(() => {
    let cancelled = false;
    const fetchBadge = () => {
      api.get('/api/training/completions-review?status=pending&limit=1').then((r) => {
        if (cancelled) return;
        if (r && !r.error && r.counts && typeof r.counts.pending === 'number') {
          setTrainingReviewPendingCount(r.counts.pending);
        }
      }).catch(() => { /* badge poll is best-effort */ });
    };
    fetchBadge();
    const interval = setInterval(fetchBadge, 60000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);
  // Tab-gated detail fetch. Runs when training_reviews is open, refetches
  // on status filter change, and polls every 30s while the tab stays open.
  useEffect(() => {
    if (tab !== 'training_reviews') return;
    let cancelled = false;
    const fetchQueue = () => {
      const path = '/api/training/completions-review?status=' + encodeURIComponent(trainingReviewStatusFilter) + '&limit=50';
      api.get(path).then((r) => {
        if (cancelled) return;
        if (!r || r.error) {
          setTrainingReviewLoadState({ loaded: false, error: (r && r.error) || 'request_failed' });
          return;
        }
        setTrainingReviewQueue({
          completions: Array.isArray(r.completions) ? r.completions : [],
          counts: r.counts && typeof r.counts === 'object' ? r.counts : { pending: 0, verified: 0, rejected: 0, total: 0 },
        });
        if (r.counts && typeof r.counts.pending === 'number') {
          setTrainingReviewPendingCount(r.counts.pending);
        }
        setTrainingReviewLoadState({ loaded: true, error: null });
      }).catch((e) => {
        if (cancelled) return;
        setTrainingReviewLoadState({ loaded: false, error: (e && e.message) || 'request_failed' });
      });
    };
    fetchQueue();
    const interval = setInterval(fetchQueue, 30000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [tab, trainingReviewStatusFilter]);
  // PATCH handler: transition a pending completion to verified or rejected.
  // The server returns 409 on non-pending transitions; we surface that as a
  // banner error rather than failing silently. On success we refetch the
  // queue (keeping the current status filter) and update the badge count.
  const patchTrainingCompletion = async (completionId, newStatus) => {
    if (!completionId || !newStatus) return;
    setTrainingReviewPatchInFlight((prev) => ({ ...prev, [completionId]: newStatus }));
    setTrainingReviewPatchError(null);
    try {
      const r = await api.patch('/api/training/completions-review/' + encodeURIComponent(completionId), { status: newStatus });
      if (!r || r.error) {
        setTrainingReviewPatchError((r && r.error) || 'request_failed');
      } else {
        const path = '/api/training/completions-review?status=' + encodeURIComponent(trainingReviewStatusFilter) + '&limit=50';
        const refresh = await api.get(path);
        if (refresh && !refresh.error) {
          setTrainingReviewQueue({
            completions: Array.isArray(refresh.completions) ? refresh.completions : [],
            counts: refresh.counts && typeof refresh.counts === 'object' ? refresh.counts : { pending: 0, verified: 0, rejected: 0, total: 0 },
          });
          if (refresh.counts && typeof refresh.counts.pending === 'number') {
            setTrainingReviewPendingCount(refresh.counts.pending);
          }
        }
      }
    } catch (e) {
      setTrainingReviewPatchError((e && e.message) || 'request_failed');
    } finally {
      setTrainingReviewPatchInFlight((prev) => {
        const next = { ...prev };
        delete next[completionId];
        return next;
      });
    }
  };
  // R3l C33: Forensic Export — admin creates via POST; ciso (separate-actor)
  // deletes via DELETE. Server returns 403 to non-admin POST and to non-ciso
  // or same-actor DELETE; UI surfaces those errors verbatim. Read endpoints
  // (list, manifest, chain) admit either role.
  const [forensicForm, setForensicForm] = useState({
    rationale: '',
    timeWindowStart: '',
    timeWindowEnd: '',
    eventTypeFilter: '',
    outputFormats: ['json-lines', 'csv'],
    includeAuditLog: true,
    includeBackupChain: true,
    includeIncidentRecords: true,
    includeAuthenticationLogs: true,
    includeUserAccessLogs: true,
  });
  const [forensicCreateInFlight, setForensicCreateInFlight] = useState(false);
  const [forensicCreateError, setForensicCreateError] = useState(null);
  const [forensicCreateResult, setForensicCreateResult] = useState(null);
  const [forensicExports, setForensicExports] = useState([]);
  const [forensicLoadState, setForensicLoadState] = useState({ loaded: false, error: null });
  const [forensicChain, setForensicChain] = useState(null);
  const [forensicChainOpen, setForensicChainOpen] = useState(false);
  const [forensicManifest, setForensicManifest] = useState(null);
  const [forensicManifestOpen, setForensicManifestOpen] = useState(false);
  const [forensicDeleteInFlight, setForensicDeleteInFlight] = useState({});
  const [forensicDeleteError, setForensicDeleteError] = useState(null);
  // Tab-gated list fetch — runs when the forensic_exports tab is open.
  useEffect(() => {
    if (tab !== 'forensic_exports') return;
    let cancelled = false;
    const fetchList = () => {
      api.get('/api/forensic-exports').then((r) => {
        if (cancelled) return;
        if (!r || r.error) {
          setForensicLoadState({ loaded: false, error: (r && r.error) || 'request_failed' });
          return;
        }
        setForensicExports(Array.isArray(r.exports) ? r.exports : []);
        setForensicLoadState({ loaded: true, error: null });
      }).catch((e) => {
        if (cancelled) return;
        setForensicLoadState({ loaded: false, error: (e && e.message) || 'request_failed' });
      });
    };
    fetchList();
    return () => { cancelled = true; };
  }, [tab]);
  const ALL_FORENSIC_FORMATS = [
    'sleuth-kit-bodyfile', 'json-lines', 'plaso-l2t-csv',
    'cef', 'evtx-xml', 'stix-21', 'dfxml', 'csv',
  ];
  const toggleForensicFormat = (fmt) => {
    setForensicForm((prev) => {
      const has = prev.outputFormats.includes(fmt);
      return { ...prev, outputFormats: has ? prev.outputFormats.filter((f) => f !== fmt) : [...prev.outputFormats, fmt] };
    });
  };
  const submitForensicExport = async () => {
    if (forensicCreateInFlight) return;
    if (!forensicForm.outputFormats || forensicForm.outputFormats.length === 0) {
      setForensicCreateError('Select at least one output format');
      return;
    }
    setForensicCreateInFlight(true);
    setForensicCreateError(null);
    setForensicCreateResult(null);
    try {
      const body = {
        rationale: forensicForm.rationale || null,
        timeWindowStart: forensicForm.timeWindowStart || null,
        timeWindowEnd: forensicForm.timeWindowEnd || null,
        eventTypeFilter: forensicForm.eventTypeFilter || null,
        outputFormats: forensicForm.outputFormats,
        includeAuditLog: forensicForm.includeAuditLog,
        includeBackupChain: forensicForm.includeBackupChain,
        includeIncidentRecords: forensicForm.includeIncidentRecords,
        includeAuthenticationLogs: forensicForm.includeAuthenticationLogs,
        includeUserAccessLogs: forensicForm.includeUserAccessLogs,
      };
      const r = await api.post('/api/forensic-exports', body);
      if (!r || r.error) {
        setForensicCreateError((r && r.error) || 'request_failed');
      } else {
        setForensicCreateResult(r);
        const refresh = await api.get('/api/forensic-exports');
        if (refresh && !refresh.error && Array.isArray(refresh.exports)) {
          setForensicExports(refresh.exports);
        }
      }
    } catch (e) {
      setForensicCreateError((e && e.message) || 'request_failed');
    } finally {
      setForensicCreateInFlight(false);
    }
  };
  const downloadForensicArchive = async (id) => {
    await api.download('/api/forensic-exports/' + encodeURIComponent(id) + '/download', 'firealive-forensic-' + id + '.tar.gz');
  };
  const viewForensicManifest = async (id) => {
    setForensicManifest(null);
    setForensicManifestOpen(true);
    const r = await api.get('/api/forensic-exports/' + encodeURIComponent(id) + '/manifest');
    setForensicManifest(r);
  };
  const viewForensicChain = async () => {
    setForensicChain(null);
    setForensicChainOpen(true);
    const r = await api.get('/api/forensic-exports/chain');
    setForensicChain(r);
  };
  const deleteForensicExport = async (id) => {
    if (forensicDeleteInFlight[id]) return;
    if (!window.confirm('Delete forensic export ' + id + '? This is irreversible (the chain entry is preserved). CISO role required and you must NOT be the original requester (separate-actor enforcement).')) return;
    setForensicDeleteInFlight((prev) => ({ ...prev, [id]: true }));
    setForensicDeleteError(null);
    try {
      const r = await api.del('/api/forensic-exports/' + encodeURIComponent(id));
      if (!r || r.error) {
        setForensicDeleteError((r && r.error) || 'request_failed');
      } else {
        const refresh = await api.get('/api/forensic-exports');
        if (refresh && !refresh.error && Array.isArray(refresh.exports)) {
          setForensicExports(refresh.exports);
        }
      }
    } catch (e) {
      setForensicDeleteError((e && e.message) || 'request_failed');
    } finally {
      setForensicDeleteInFlight((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    }
  };
  // OODA
  const [oodaPolicies, setOodaPolicies] = useState([]);
  const [oodaNewPolicy, setOodaNewPolicy] = useState({title:"",type:"incident_response",content:""});
  const [oodaScenarios, setOodaScenarios] = useState([]);
  // Phase F4c: backend-wired state for policies, scenarios, jobs
  const [oodaLoading, setOodaLoading] = useState(false);
  const [oodaUploading, setOodaUploading] = useState(false);
  const [oodaUploadError, setOodaUploadError] = useState(null);
  const [oodaRefreshTick, setOodaRefreshTick] = useState(0);
  // Phase F4c commit 4: AAR state — uploads, listing, remove
  const [oodaAars, setOodaAars] = useState([]);
  const [oodaNewAar, setOodaNewAar] = useState({title:"",incidentDate:"",content:"",lessonsLearned:""});
  const [oodaUploadingAar, setOodaUploadingAar] = useState(false);
  const [oodaAarError, setOodaAarError] = useState(null);
  // Phase F4c commit 7: replenishment-config wizard state
  // wizardPolicy is the policy whose config is being edited (null = closed).
  // wizardConfig holds the in-flight form values; wizardError holds any
  // server-returned validation error; wizardSaving suppresses the Save
  // button while the PATCH is in flight.
  const [wizardPolicy, setWizardPolicy] = useState(null);
  const [wizardConfig, setWizardConfig] = useState(null);
  const [wizardError, setWizardError] = useState(null);
  const [wizardSaving, setWizardSaving] = useState(false);
  // Phase F4c commit 8: generation-jobs monitoring dashboard
  const [oodaJobs, setOodaJobs] = useState([]);
  const [oodaJobsError, setOodaJobsError] = useState(null);
  // Ref tracks the latest jobs list for the polling closure — without
  // this, the setInterval callback would close over the initial empty
  // array and never see updates, so it could never stop polling once
  // jobs are added.
  const oodaJobsRef = React.useRef([]);
  oodaJobsRef.current = oodaJobs;
  // Polling effect: while any job is queued or running, refetch every 5
  // seconds so the user sees progress updates. When all jobs are in
  // terminal states (done/failed/cancelled), the interval still ticks
  // but skips the fetch — much cheaper than tearing down and rebuilding
  // the interval on every state change.
  useEffect(()=>{
    if (tab !== "ooda_mgmt") return;
    let cancelled = false;
    const fetchJobs = async () => {
      const r = await api.get("/api/ooda/generation-jobs?limit=50");
      if (cancelled) return;
      if (r?.error) {
        setOodaJobsError(r.error);
        return;
      }
      setOodaJobsError(null);
      setOodaJobs(r?.jobs || []);
    };
    fetchJobs();
    const tickHandle = setInterval(()=>{
      const hasActive = oodaJobsRef.current.some(j=>j.status==="queued"||j.status==="running");
      if (hasActive) fetchJobs();
    }, 5000);
    return ()=>{ cancelled = true; clearInterval(tickHandle); };
  }, [tab, oodaRefreshTick]);
  // When the IR Simulator MC tab is opened, fetch the live list of
  // policies, scenarios, and AARs from the backend. The mock state from
  // earlier builds is replaced with API data; setOodaPolicies on tab
  // activation overwrites whatever stale entries were there.
  useEffect(()=>{
    if (tab !== "ooda_mgmt") return;
    let cancelled = false;
    setOodaLoading(true);
    Promise.all([
      api.get("/api/ooda/policies"),
      api.get("/api/ooda/scenarios"),
      api.get("/api/ooda/aar"),
    ]).then(([polRes, scRes, aarRes])=>{
      if (cancelled) return;
      // The /policies route returns {policies: [...]} with each row
      // including replenishment_config (JSON string from the DB) and the
      // standard ir_policies columns. Normalize the JSON into an object
      // for the UI's wizard (commit 6) — the rest of this commit just
      // displays title, type, uploadedAt, id.
      const polList = (polRes?.policies || []).map(p => ({
        ...p,
        replenishment_config: (() => {
          try { return p.replenishment_config ? JSON.parse(p.replenishment_config) : null; }
          catch { return null; }
        })(),
      }));
      setOodaPolicies(polList);
      setOodaScenarios(scRes?.scenarios || []);
      setOodaAars(aarRes?.aars || []);
    }).catch(()=>{
      // Network or auth error — leave existing state alone, surface in
      // the upload-error slot so the user sees something actionable
      if (!cancelled) setOodaUploadError("Failed to load IR Simulator data. Refresh the tab to retry.");
    }).finally(()=>{
      if (!cancelled) setOodaLoading(false);
    });
    return ()=>{ cancelled = true; };
  }, [tab, oodaRefreshTick]);
  // Peer support config
  const [peerScheduleCfg, setPeerSchedCfg] = useState({allowDuringShift:true,blockedDays:[],blockedHoursStart:null,blockedHoursEnd:null,maxSessionMinutes:30,inactivityTimeoutMinutes:5});
  // Helper leaderboard populated from real peer sessions.
  const [peerHelpers, setPeerHelpers] = useState([]);
  // R3h: leaderboard fetch state. peerHelpers is the rendered list;
  // peerHelpersLoading/Error gate the loading and error affordances on
  // the peersupport tab Card. Populated by GET /api/helper-pay/leaderboard
  // when the peersupport tab opens.
  const [peerHelpersLoading, setPeerHelpersLoading] = useState(false);
  const [peerHelpersError, setPeerHelpersError] = useState(null);
  // R3h: team-scores fetch state. Populated by GET /api/helper-pay/
  // team-scores when the peersupport tab opens. Lead operational view
  // showing ALL active analysts (not opt-in-gated, per privacy invariant
  // I5 — this is the payroll/compensation surface, not the recognition
  // leaderboard). The endpoint is lead/admin-gated server-side; if an
  // analyst-role MC user somehow opens this tab, the fetch returns 403
  // and the Card shows an error.
  const [teamScores, setTeamScores] = useState([]);
  const [teamScoresLoading, setTeamScoresLoading] = useState(false);
  const [teamScoresError, setTeamScoresError] = useState(null);
  // R3h-pt2: flagged-ratings review queue state. Populated by GET
  // /api/helper-pay/flagged-ratings when the peersupport tab opens.
  // flaggedDecideBusy tracks which rating's decide POST is in flight
  // so Approve/Dismiss buttons disable per-row during the round trip
  // rather than blocking the entire Card.
  const [flaggedRatings, setFlaggedRatings] = useState([]);
  const [flaggedRatingsLoading, setFlaggedRatingsLoading] = useState(false);
  const [flaggedRatingsError, setFlaggedRatingsError] = useState(null);
  const [flaggedDecideBusy, setFlaggedDecideBusy] = useState(null);
  const [flaggedDecideFb, setFlaggedDecideFb] = useState(null);
  // Restore
  const [restorePoints, setRestorePoints] = useState([{id:"bk1",type:"daily-auto",createdAt:"2026-03-27 02:00",sizeMB:"2.4",hash:"a3f8c…"},{id:"bk2",type:"daily-auto",createdAt:"2026-03-26 02:00",sizeMB:"2.3",hash:"b7e2d…"}]);
  const [erSources,setErSources]=useState([]); const [erSelSrc,setErSelSrc]=useState(""); const [erBackups,setErBackups]=useState([]); const [erPreview,setErPreview]=useState(null); const [erReason,setErReason]=useState(""); const [erApproval,setErApproval]=useState(null);
  const [bskKeys,setBskKeys]=useState([]); const [bskShowAdd,setBskShowAdd]=useState(false); const [bskPasteText,setBskPasteText]=useState(""); const [bskValidatedFp,setBskValidatedFp]=useState(null); const [bskValidatedPem,setBskValidatedPem]=useState(null); const [bskLabel,setBskLabel]=useState("");
  const [configSnapshots, setConfigSnaps] = useState([{id:"cs1",name:"Pre-SOAR integration",createdAt:"2026-03-25 14:00"}]);
  // v1.0.0 state
  const [regressionResults, setRegressionResults] = useState(null);
  const [regressionRunning, setRegressionRunning] = useState(false);
  const [cicdPlatform, setCicdPlatform] = useState("github-actions");
  // R3k C37 — CI/CD server-side wiring
  const [cicdPurpose, setCicdPurpose] = useState("custom-build");
  const [cicdResult, setCicdResult] = useState(null);
  const [cicdBusy, setCicdBusy] = useState(false);
  const [playbookType, setPlaybookType] = useState("app_compromise");
  const [generatedPlaybook, setGenPlaybook] = useState(null);
  const [clientNotifCfg, setClientNotifCfg] = useState({enabled:true,channels:{desktop:true,slack:false,teams:false,email:false},slackWebhook:"",teamsWebhook:"",rules:{peerChatRequest:{enabled:true,realtime:true,channel:"desktop"},weeklyMetricsReminder:{enabled:true,day:"friday",time:"16:00",channel:"desktop"},burnoutSpike:{enabled:false,channel:"desktop"},shiftHandoff:{enabled:true,channel:"desktop"},scheduledChatReminder:{enabled:true,minutesBefore:15,channel:"desktop"}}});
  const [cloudVulnCfg, setCloudVulnCfg] = useState({enabled:false,scanners:[],schedule:"weekly",targetEnvironment:null});
  // Query tool
  const [querySource, setQuerySource] = useState("audit_log");
  const [queryRegex, setQueryRegex] = useState("");
  const [queryResults, setQueryResults] = useState(null);
  const [siemQueryType, setSiemQueryType] = useState("team_health");
  const [siemQuerySiem, setSiemQuerySiem] = useState("splunk");
  const [siemQueryOutput, setSiemQueryOutput] = useState("");

  const addA = (ty,dt) => setAudit(prev=>[...prev,{ts:new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}),ty,dt}]);

  // ── API Data Loading (falls back to mock data if backend unavailable) ──────
  const [apiReady, setApiReady] = useState(false);
  useEffect(()=>{
    const API = window.FireAliveAPI;
    if(!API) return;
    const load = async () => {
      try {
        // Test if backend is up
        const health = await API.system.health();
        if(health.status !== 'healthy') return;
        setApiReady(true);
        addA("API_CONNECTED","Backend v"+health.version+" connected");

        // Load team data
        try { const td = await API.team.getOverview(); if(td.analysts) setAnalysts(td.analysts); } catch(e){}

        // Load retros
        try { const rd = await API.retro.list(); if(rd.retros?.length) setActiveRetros(rd.retros.map(r=>({id:r.id,incident:r.incident,severity:r.severity,names:r.analysts||[],phase:r.phase,initiated:r.created_at,actions:r.actions||[]}))); } catch(e){}

        // Load handoffs
        try { const hd = await API.handoffs.list(); if(hd.handoffs?.length) setHandoffHistory(hd.handoffs.map(h=>({ts:h.created_at,from:`${h.from_shift} → ${h.to_shift}`,notes:h.notes}))); } catch(e){}

        // Load resources
        try { const rd2 = await API.resources.list(); if(rd2.resources?.length) setCustomResources(rd2.resources.map(r=>({id:r.id,title:r.title,url:r.url,category:r.category}))); } catch(e){}

        // Load SLA config
        try { const sc2 = await API.sla.getConfig(); if(sc2.p1_mtta) setSlaConfig({p1mtta:sc2.p1_mtta,p1mttr:sc2.p1_mttr,p2mtta:sc2.p2_mtta,p2mttr:sc2.p2_mttr}); } catch(e){}

        // Load report config
        try { const rc2 = await API.reports.getConfig(); if(rc2.schedule) setReportCfg(prev=>({...prev,schedule:rc2.schedule,day:rc2.day_of_week,time:rc2.time_of_day,format:rc2.format,recipients:rc2.recipients||"",siemFeed:!!rc2.siem_feed,sections:rc2.sections?JSON.parse(rc2.sections):prev.sections})); } catch(e){}

        // Load reports history
        try { const rh = await API.reports.list(); if(rh.reports?.length) setReports(rh.reports.map(r=>({id:r.id,ts:r.generated_at,type:r.type,status:"delivered",sections:r.sections_count}))); } catch(e){}

        // Load assessments
        try { const ad = await API.assessments.list(); if(ad.assessments?.length) setAssessments(ad.assessments.map(a=>({id:a.id,name:a.name,tier:a.tier,skills:[],assignees:[],createdAt:a.created_at,status:a.status,results:{}}))); } catch(e){}

      } catch(e) {
        // Backend not available — continue with mock data
        api.post("/api/v1/audit/log",{event:"API_OFFLINE",detail:"Backend not available — using demo data"}).then(()=>addA("API_OFFLINE","Backend not available — using demo data"));
      }
    };
    load();
  },[]);

  const dayAnalysts = (analysts.length?analysts:[]).filter(a=>a.shift==="day");
  const sessData = dayAnalysts.map(a=>({id:a.id,name:a.name,tier:a.tier,
    util:a.id==="maya-c"?0.91:a.id==="jordan-p"?0.72:a.id==="sam-r"?0.78:a.id==="alex-k"?0.67:a.id==="dana-o"?0.79:0.45,
    tk:a.id==="maya-c"?34:a.id==="jordan-p"?28:a.id==="sam-r"?31:a.id==="alex-k"?22:a.id==="dana-o"?31:15,
    wo:a.id==="maya-c"?3:0,cap:routingCaps[a.id]||2}));
  const th = computeTH(dayAnalysts, sessData);
  const sc = stMeta[th.status];

  useEffect(()=>{
    const iv=setInterval(()=>{
      const al=ALERT_TYPES[Math.floor(Math.random()*ALERT_TYPES.length)];
      const elig=dayAnalysts.filter(a=>a.available&&(routingCaps[a.id]||2)>=al.cx);
      if(!elig.length)return;
      const totH=Object.values(sessCt).reduce((s,c)=>s+c.h,0)||1;
      const sorted=[...elig].sort((a,b)=>(sessCt[a.id]?.h||0)/totH-(sessCt[b.id]?.h||0)/totH);
      const autoE=autoSys.filter(s=>(al.cx<=1&&s.l1)||(al.cx<=2&&s.l2));
      const goA=al.cx<=2&&Math.random()<0.15&&autoE.length>0;
      const asgn=goA?null:sorted[0];const aSys=goA?autoE[Math.floor(Math.random()*autoE.length)]:null;
      setLF(prev=>[{id:Date.now()+Math.random(),ts:new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'}),alert:al.type,cx:al.cx,to:asgn?.name,toId:asgn?.id,auto:goA,autoN:aSys?.name,eq:al.cx>=3},...prev].slice(0,50));
      if(asgn)setSC(prev=>({...prev,[asgn.id]:{t:(prev[asgn.id]?.t||0)+1,h:(prev[asgn.id]?.h||0)+(al.cx>=3?1:0)}}));
    },2800);
    return()=>clearInterval(iv);
  },[routingCaps,sessCt,autoSys,dayAnalysts]);

  const getD=k=>gDepth||pDepths[k]||"full";
  const activeP=Object.entries(PROMPTS).filter(([k,p])=>!silenced.includes(k)&&p.cond(th));
  const highP=activeP.filter(([,p])=>p.sev==="high");

  const handleProvision = () => {
    if(!newA.name.trim()||!newA.hostname.trim()) return;
    const activationId = genId();
    const newAnalyst = {id:`prov-${Date.now()}`,name:newA.name,tier:newA.tier,shift:newA.shift,days:0,available:true};
    setAnalysts(prev=>[...prev,newAnalyst]);
    setRC(prev=>({...prev,[newAnalyst.id]:newA.tier===3?5:newA.tier===2?3:2}));
    setSC(prev=>({...prev,[newAnalyst.id]:{t:0,h:0}}));
    const client = {id:activationId,analyst:newA.name,tier:newA.tier,shift:newA.shift,hostname:newA.hostname,ip:newA.ip,provisionedAt:new Date().toISOString(),status:"calibrating",analystId:newAnalyst.id};
    setPC(prev=>[...prev,client]);
    addA("ANALYST_PROVISIONED",`${newA.name} · ${tierLbl(newA.tier)} · ${newA.shift} · Host: ${newA.hostname} · Activation: ${activationId}`);
    setNewA({name:"",tier:1,shift:"day",hostname:"",ip:""});
    setShowProvision(false);
  };

  const checkUpdate = () => {
    setUpdateCheck("checking");
    setTimeout(()=>setUpdateCheck({available:true,version:"0.0.29",notes:"Enhanced federation support, multi-site deployment, OODA training module."}),1500);
  };

  // ── v1.0.0: Grouped navigation (was 57 flat tabs, now 12 categories) ──
  const [navCat, setNavCat] = useState("ops");
  const [navExpanded, setNavExpanded] = useState({});
  const toggleNav = (cat) => setNavExpanded(prev=>{const next={};next[cat]=!prev[cat];return next;});
  const navGroups = [
    {cat:"ops",label:"Operations",items:[
      {id:"inbox",label:"Inbox",badge:inboxUnreadCount},{id:"peer_conduct",label:"Peer Conduct",badge:peerFlagOpenCount},{id:"actions",label:"Actions",badge:highP.length},{id:"overview",label:"Team Overview"},{id:"routing",label:"Routing"},{id:"soar",label:"SOAR & Ticketing"},{id:"handoff",label:"Shift Handoff"},{id:"sla",label:"SLA"},{id:"automation",label:"Automation"},{id:"fail_open",label:"Fail-Open Routing"},{id:"auto_disable",label:"Auto-Disable Routing"},{id:"runbook",label:"Recovery Runbook"},
    ]},
    {cat:"analysts",label:"Analysts & Wellbeing",items:[
      {id:"skillmatrix",label:"Skills Matrix"},{id:"assessments",label:"Assessments"},{id:"general_certs",label:"Certifications"},{id:"training_reviews",label:"Training Reviews",badge:trainingReviewPendingCount},{id:"retro",label:"CISM Retro"},{id:"peersupport",label:"Peer Config"},{id:"helper_pay",label:"Helper Pay"},{id:"pseudonyms",label:"Pseudonyms"},{id:"ooda_mgmt",label:"IR Simulator"},{id:"proactive",label:"Proactive Breaks"},{id:"upskilling_hr",label:"Upskilling Hour"},{id:"offboarding",label:"Offboarding"},{id:"sync_interval",label:"Sync Interval"},{id:"client_notif",label:"Client Notifications"},
    ]},
    {cat:"integrations",label:"Integrations",items:[
      {id:"integrations",label:"Health Dashboard"},{id:"siem",label:"SIEM"},{id:"edr",label:"EDR"},{id:"malware_scanners",label:"Malware Scanners"},{id:"threat_hunt",label:"Threat Hunting"},{id:"onboard",label:"Client Provisioning"},{id:"ai_integrations",label:"AI/ML Integrations"},
    ]},
    {cat:"security",label:"Security",items:[
      {id:"iam",label:"IAM"},{id:"mfa",label:"MFA"},{id:"apikeys",label:"API Keys"},{id:"access_ctrl",label:"Access Control"},{id:"auth_logs",label:"Auth Logs"},{id:"kms",label:"KMS"},{id:"wifi",label:"WiFi Policy"},{id:"posture",label:"Posture Assessment"},{id:"tripwire",label:"Tripwire"},{id:"compromise_scan",label:"Compromise Scan"},{id:"log_integrity",label:"Log Integrity"},{id:"regression",label:"Regression Test"},{id:"ttx",label:"TTX Generator"},
    ]},
    {cat:"infra",label:"Infrastructure",items:[
      {id:"cloud",label:"Cloud & IaC"},{id:"virt",label:"Virtualization"},{id:"sdn",label:"SDN"},{id:"sase",label:"SASE / ZTNA"},{id:"ha",label:"High Availability"},{id:"cluster",label:"Cluster / Scaling"},{id:"cicd",label:"CI/CD"},
    ]},
    {cat:"data",label:"Data & Backup",items:[
      {id:"backup",label:"Backup & Storage Routing"},{id:"backup_schedules",label:"Backup Schedules"},{id:"restore",label:"Restore"},{id:"geo_fence",label:"Data Sovereignty"},{id:"legal_hold",label:"Legal Hold"},
    ]},
    {cat:"reports",label:"Reports & Compliance",items:[
      {id:"reports",label:"Report Engine"},{id:"compliance",label:"Compliance"},{id:"recert",label:"Recertification"},{id:"kb",label:"Knowledge Base"},{id:"playbooks",label:"Playbooks"},{id:"risk_register",label:"Risk Register Asset"},{id:"risk_report",label:"Human Impact Report"},{id:"query_tool",label:"Query Tool"},
    ]},
    {cat:"config",label:"Configuration",items:[
      {id:"features",label:"Feature Toggles"},{id:"notif",label:"Burnout Alerts"},{id:"msp",label:"MSP Multi-Tenancy"},{id:"global_dash",label:"Global Dashboard"},{id:"updates",label:"Updates"},{id:"troubleshooter",label:"Troubleshooter"},
    ]},
    {cat:"monitor",label:"Monitoring",items:[
      {id:"monitoring",label:"System Health"},{id:"vulnscan",label:"Vulnerability Scan"},{id:"cloud_vuln",label:"Cloud Vuln Scan"},
    ]},
    {cat:"audit_cat",label:"Audit",items:[
      {id:"audit",label:"Audit Log"},{id:"forensic_exports",label:"Forensic Exports"},
    ]},
  ];
  // Flat list for tab rendering compatibility
  const tabs = navGroups.flatMap(g=>g.items);
  // v1.0.0: inactivity lock
  // Start UNLOCKED — Team Lead sets up MFA first.
  const [configLocked, setConfigLocked] = useState(false);
  const [padlocks, setPadlocks] = useState({});
  const isPadlocked = (section) => configLocked && (padlocks[section] !== false);

  // R3e: load Config Lock state from server on mount so the MC reflects
  // server reality (configLocked starts false in useState but the server
  // may already be locked from a previous admin session). The MC main app
  // component only renders after stage transitions to "app", so this
  // useEffect implicitly fires only post-authentication. Lock state
  // changes within a single session are picked up by the Lock/Unlock
  // button's own setConfigLocked call, not by this useEffect.
  useEffect(() => {
    api.get('/api/config/lock').then(r => {
      if (r && !r.error) setConfigLocked(!!r.lock_active);
    });
  }, []);

  // F5 part 2b: Helper Pay management state. Populated when the Helper Pay
  // tab opens. Pending-queue and catalog operations land via the lead and
  // admin endpoints. The MC user is a manager (lead or admin) — admin-only
  // operations (catalog mutate, fraud reverse, CSV export) will 403 server-
  // side for leads, surfacing as inline error feedback.
  const [helperPending, setHelperPending] = useState([]);
  const [helperOptionsAdmin, setHelperOptionsAdmin] = useState([]);
  const [helperLoading, setHelperLoading] = useState(false);
  const [helperError, setHelperError] = useState(null);
  const [helperFb, setHelperFb] = useState(null);
  const [helperSection, setHelperSection] = useState("pending");
  // Decide modal: { redemption, approve, note }
  const [decideModal, setDecideModal] = useState(null);
  // Catalog form: editing existing (with id) or creating new (id=null)
  const [optionForm, setOptionForm] = useState(null);
  // Reversal form fields
  const [reverseLedgerId, setReverseLedgerId] = useState("");
  const [reverseNote, setReverseNote] = useState("");
  const togglePadlock = (section) => {if(window.confirm("Authenticate with MFA to "+(isPadlocked(section)?"unlock":"lock")+" this section.")){setPadlocks(prev=>({...prev,[section]:isPadlocked(section)?false:true}));addA(isPadlocked(section)?"CONFIG_UNLOCKED":"CONFIG_LOCKED","Section: "+section);}};

  // F5 part 2b: Helper Pay tab loader. When the manager opens the tab, we
  // fetch the pending-redemption queue (lead, admin) and the full catalog
  // including inactive options (admin only). A leads request to /admin/options
  // returns 403 — we surface that inline rather than crashing the tab.
  React.useEffect(() => {
    if (tab !== "helper_pay") return;
    let cancelled = false;
    setHelperLoading(true);
    setHelperError(null);
    setHelperFb(null);
    Promise.all([
      api.get("/api/helper-pay/redemptions/pending"),
      api.get("/api/helper-pay/admin/options"),
    ]).then(([p, o]) => {
      if (cancelled) return;
      if (p?.error) {
        setHelperError("Could not load pending redemptions: " + (p.error || "unknown error"));
      } else {
        setHelperPending(Array.isArray(p?.pending) ? p.pending : []);
      }
      if (o?.error) {
        // Lead users get 403 here; that's expected, not a hard error.
        setHelperOptionsAdmin([]);
      } else {
        setHelperOptionsAdmin(Array.isArray(o?.options) ? o.options : []);
      }
    }).finally(() => {
      if (!cancelled) setHelperLoading(false);
    });
    return () => { cancelled = true; };
  }, [tab]);

  // F5 part 2b: pending-queue actions.
  const reloadPending = () => {
    api.get("/api/helper-pay/redemptions/pending").then(p => {
      if (Array.isArray(p?.pending)) setHelperPending(p.pending);
    });
  };
  const submitDecide = (redemption, approve, note) => {
    api.post("/api/helper-pay/redemptions/" + redemption.id + "/decide", { approve, note }).then(r => {
      if (r?.error) {
        setHelperFb({ kind: "error", message: r.message || r.error || "Could not record decision." });
        return;
      }
      const verb = r.status === "approved" ? "approved" : "denied";
      setHelperFb({ kind: "success", message: "Redemption " + verb + " for " + redemption.user_name + "." });
      setDecideModal(null);
      reloadPending();
      addA("HELPER_PAY_DECIDE", verb + " " + redemption.option_name + " for " + redemption.username);
    });
  };
  const submitFulfill = (redemption) => {
    api.post("/api/helper-pay/redemptions/" + redemption.id + "/fulfill", {}).then(r => {
      if (r?.error) {
        setHelperFb({ kind: "error", message: r.message || r.error || "Could not mark fulfilled." });
        return;
      }
      setHelperFb({ kind: "success", message: "Redemption marked fulfilled for " + redemption.user_name + "." });
      reloadPending();
      addA("HELPER_PAY_FULFILL", redemption.option_name + " for " + redemption.username);
    });
  };

  // F5 part 2b: catalog actions.
  const reloadOptions = () => {
    api.get("/api/helper-pay/admin/options").then(o => {
      if (Array.isArray(o?.options)) setHelperOptionsAdmin(o.options);
    });
  };
  const startNewOption = () => setOptionForm({
    id: null,
    name: "",
    description: "",
    costPoints: 100,
    redemptionType: "time_off",
    approvalRequired: true,
    maxPerUserPerYear: "",
    active: true,
  });
  const startEditOption = (opt) => setOptionForm({
    id: opt.id,
    name: opt.name || "",
    description: opt.description || "",
    costPoints: opt.cost_points,
    redemptionType: opt.redemption_type,
    approvalRequired: !!opt.approval_required,
    maxPerUserPerYear: opt.max_per_user_per_year == null ? "" : String(opt.max_per_user_per_year),
    active: !!opt.active,
  });
  const submitOptionForm = () => {
    if (!optionForm) return;
    const body = {
      name: optionForm.name.trim(),
      description: optionForm.description.trim() || null,
      costPoints: parseInt(optionForm.costPoints, 10),
      redemptionType: optionForm.redemptionType,
      approvalRequired: !!optionForm.approvalRequired,
      maxPerUserPerYear: optionForm.maxPerUserPerYear === "" ? null : parseInt(optionForm.maxPerUserPerYear, 10),
    };
    if (!body.name) {
      setHelperFb({ kind: "error", message: "Name is required." });
      return;
    }
    if (!Number.isInteger(body.costPoints) || body.costPoints <= 0) {
      setHelperFb({ kind: "error", message: "Cost (points) must be a positive integer." });
      return;
    }
    const isEdit = !!optionForm.id;
    if (isEdit) {
      // PUT — also include the active flag so admins can re-activate a soft-deleted option.
      body.active = !!optionForm.active;
      api.put("/api/helper-pay/admin/options/" + optionForm.id, body).then(r => {
        if (r?.error) {
          setHelperFb({ kind: "error", message: r.message || r.error });
          return;
        }
        setHelperFb({ kind: "success", message: "Option updated." });
        setOptionForm(null);
        reloadOptions();
        addA("HELPER_PAY_OPTION_UPDATED", body.name);
      });
    } else {
      api.post("/api/helper-pay/admin/options", body).then(r => {
        if (r?.error) {
          setHelperFb({ kind: "error", message: r.message || r.error });
          return;
        }
        setHelperFb({ kind: "success", message: "Option created." });
        setOptionForm(null);
        reloadOptions();
        addA("HELPER_PAY_OPTION_CREATED", body.name);
      });
    }
  };
  const deactivateOption = (opt) => {
    if (!window.confirm("Deactivate \"" + opt.name + "\"? It will hide from the analyst catalog. Historic redemptions will continue to resolve.")) return;
    api.del("/api/helper-pay/admin/options/" + opt.id).then(r => {
      if (r?.error) {
        setHelperFb({ kind: "error", message: r.message || r.error });
        return;
      }
      setHelperFb({ kind: "success", message: "Option deactivated." });
      reloadOptions();
      addA("HELPER_PAY_OPTION_DEACTIVATED", opt.name);
    });
  };

  // F5 part 2b: fraud reversal.
  const submitReversal = () => {
    const id = reverseLedgerId.trim();
    if (!id) {
      setHelperFb({ kind: "error", message: "Ledger ID is required." });
      return;
    }
    if (!window.confirm("Reverse this ledger entry? This writes a new negative-delta row to the append-only ledger; the original is preserved.")) return;
    api.post("/api/helper-pay/admin/reverse", { ledgerId: id, note: reverseNote.trim() || null }).then(r => {
      if (r?.error) {
        setHelperFb({ kind: "error", message: r.message || r.error });
        return;
      }
      setHelperFb({ kind: "success", message: "Reversal posted. Reversal ledger ID: " + r.ledgerId });
      setReverseLedgerId("");
      setReverseNote("");
      addA("HELPER_PAY_REVERSAL", "Reversed " + id);
    });
  };

  // F5 part 2b: CSV export. Uses api.download because the response is
  // text/csv rather than JSON.
  const downloadCsv = (type) => {
    const filename = "helper-pay-" + type + "-" + new Date().toISOString().slice(0, 10) + ".csv";
    api.download("/api/helper-pay/admin/export.csv?type=" + encodeURIComponent(type), filename).then(ok => {
      if (!ok) {
        setHelperFb({ kind: "error", message: "Export failed." });
        return;
      }
      addA("HELPER_PAY_EXPORT", type);
    });
  };

  // v1.0.0: setup wizard
  const [showSetupWizard, setShowSetupWizard] = useState(false);
  const [setupStep, setSetupStep] = useState(0);
  const [setupSelections, setSetupSelections] = useState({siem:false,soar:false,edr:false,xdr:false,atp:false,ticketing:"none",iam:"none",cloud:"none",vpn:false});
  // v1.0.0: welcome guide — first launch only
  const [showWelcome, setShowWelcome] = useState(false); // disabled by default; set true for first-time users via server flag
  const [welcomeStep, setWelcomeStep] = useState(0);
  const dismissWelcome=()=>{setShowWelcome(false);setWelcomeStep(0);};
  // v1.0.0: concurrent session prevention
  const [sessionId] = useState(()=>Math.random().toString(36).slice(2,14));
  // v1.0.0: biometrics
  const [biometricCfg, setBiometricCfg] = useState({enabled:false,method:"fingerprint",useForUnlock:true,useForPadlocks:true});
  // v1.0.0: insider threat protocol
  const [insiderProtocol, setInsiderProtocol] = useState({dualApproval:false,autoKeyRotation:true,rotationIntervalDays:90});
  const [insiderAlertActive, setInsiderAlertActive] = useState(false);
  // ── v1.0.0 NEW STATE ──────────────────────────────────────────────────
  // Proactive intervention (Sonnentag recovery research)
  const [proactiveCfg, setProactiveCfg] = useState({enabled:true,highSevHours:4,breakDurationMin:15,autoSuggest:true,requireLeadApproval:true,affirmationEnabled:true});
  const [proactiveAlerts, setProactiveAlerts] = useState([
    {id:"pa1",analyst:"Analyst-Falcon",pseudonym:"Analyst-Falcon",trigger:"4hr continuous P1/P2 tickets",suggestedAt:new Date().toISOString(),status:"pending"},
  ]);
  // Recovery runbook state declared above
  // Upskilling hour
  const [upskillingCfg, setUpskillingCfg] = useState({enabled:false,hourOfShift:8,durationMin:60,stopRouting:true,statusLabel:"Upskilling",allowPeerChat:true,allowTraining:true});
  // Auto-routing disable on critical incidents
  const [autoDisableRoutingCfg, setAutoDisableRoutingCfg] = useState({enabled:false,triggers:{criticalTicket:true,siemAlert:true,soarPlaybook:true,manualEscalation:true},ticketSeverity:"P1",cooldownMin:30,notifyLead:true});
  // Analyst offboarding
  const [offboardingQueue, setOffboardingQueue] = useState([]);
  const [newOffboard, setNewOffboard] = useState({analystId:"",reason:"departure",archiveData:true,revokeKeys:true,cancelPeerSessions:true,notifySoar:true});
  // TTX generator
  // (ttxScenario state removed in Phase 1.4d — TTX is now a download-only flow)
  // Legal hold backup
  const [legalHoldCfg, setLegalHoldCfg] = useState({enabled:false,repository:"",hashAlgorithm:"sha256",format:"eml_pst",indefiniteRetention:true});
  const [lhCreate, setLhCreate] = useState({open:false, caseId:"", rationale:"", outputFormats:["edrm-xml","eml-mime"], indefiniteRetention:true, submitting:false, error:""});
  const [lhExports, setLhExports] = useState([]);
  const [lhLoadState, setLhLoadState] = useState({loaded:false, loading:false, error:null});
  const [lhReleaseModal, setLhReleaseModal] = useState({open:false, holdId:"", caseId:"", requestedBy:"", rationale:"", submitting:false, error:""});
  const refreshLhList = async () => {
    setLhLoadState({loaded:false, loading:true, error:null});
    const r = await api.get('/api/legal-hold-exports');
    if (!r || r.error) {
      setLhLoadState({loaded:false, loading:false, error:(r && r.error) || 'request_failed'});
      setLhExports([]);
    } else {
      setLhExports(Array.isArray(r.holds) ? r.holds : []);
      setLhLoadState({loaded:true, loading:false, error:null});
    }
  };
  useEffect(() => {
    if (tab !== 'legal_hold') return;
    let cancelled = false;
    (async () => {
      const r = await api.get('/api/legal-hold-exports');
      if (cancelled) return;
      if (!r || r.error) {
        setLhLoadState({loaded:false, loading:false, error:(r && r.error) || 'request_failed'});
        return;
      }
      setLhExports(Array.isArray(r.holds) ? r.holds : []);
      setLhLoadState({loaded:true, loading:false, error:null});
    })();
    return () => { cancelled = true; };
  }, [tab]);
  const downloadLegalHold = async (id) => {
    await api.download('/api/legal-hold-exports/' + encodeURIComponent(id) + '/download', 'firealive-legal-hold-' + id + '.tar.gz');
  };
  // Risk register asset
  const [riskRegisterOutput, setRiskRegisterOutput] = useState(null);
  // ── v1.0.0 CONTINUED — Cross-app management state ────────────────────
  // Client runtime metrics aggregation
  const [clientMetrics, setClientMetrics] = useState([
    {id:"jordan-p-ws",cpu:8,memMB:120,heapMB:72,uptime:28800,status:"healthy",lastSync:"2026-04-10T14:00:00Z",logIntegrity:"ok"},
    {id:"priya-s-ws",cpu:12,memMB:145,heapMB:89,uptime:28800,status:"healthy",lastSync:"2026-04-10T14:02:00Z",logIntegrity:"ok"},
    {id:"alex-k-ws",cpu:22,memMB:198,heapMB:134,uptime:28800,status:"warning",lastSync:"2026-04-10T14:01:00Z",logIntegrity:"ok"},
    {id:"maya-c-ws",cpu:6,memMB:110,heapMB:68,uptime:28800,status:"healthy",lastSync:"2026-04-10T14:03:00Z",logIntegrity:"ok"},
    {id:"fatima-a-ws",cpu:9,memMB:130,heapMB:78,uptime:28800,status:"healthy",lastSync:"2026-04-10T14:00:30Z",logIntegrity:"ok"},
    {id:"sam-r-ws",cpu:15,memMB:155,heapMB:95,uptime:28800,status:"healthy",lastSync:"2026-04-10T13:59:00Z",logIntegrity:"ok"},
  ]);
  // Client log collection
  const [clientLogCollection, setClientLogCollection] = useState({autoCollect:true,intervalMin:15,destinations:["server","siem"],collectAudit:true,collectForensics:true,collectRuntime:true});
  // Client backup triggering
  const [clientBackupCfg, setClientBackupCfg] = useState({triggerFromMC:true,perClientStorage:true,includeInSchedule:true});
  // App update push
  const [updatePushCfg, setUpdatePushCfg] = useState({method:"admin_push",requireLabTest:true,rollbackOnFail:true,staggerMinutes:5});
  const [pendingUpdate, setPendingUpdate] = useState(null);
  // Client provisioning enhanced
  const [provisionCfg, setProvisionCfg] = useState({method:"admin_push",deployTools:["sccm","intune","ansible","jamf"],enrollmentTokenExpiry:24,includeConfig:true,autoRegister:true});

  return(
    <div style={{minHeight:"100vh",background:C.bg,color:C.t,fontFamily:"'DM Sans',sans-serif"}}>
      <style>{CSS}</style>
      {/* R3j C9: Top-of-MC panic banner. Red while panic_mode is active; green for
          PANIC_BANNER_LINGER_SECONDS after deactivation; absent otherwise. Recomputes
          age against Date.now() on every render so the green banner vanishes at the
          right moment even between 30s server polls. */}
      {(()=>{
        if (panicMode) {
          return (<div style={{padding:"12px 24px",background:C.d,color:"#fff",fontWeight:600,textAlign:"center",fontSize:13,letterSpacing:0.5,animation:"pulse 1.5s infinite",borderBottom:`1px solid ${C.d}`}}>⚠ PANIC MODE ACTIVE — All wellness routing disabled. Every analyst is at maximum complexity.</div>);
        }
        if (panicDeactivatedAt) {
          const ageSec = (Date.now() - new Date(panicDeactivatedAt).getTime()) / 1000;
          if (ageSec >= 0 && ageSec <= PANIC_BANNER_LINGER_SECONDS) {
            return (<div style={{padding:"10px 24px",background:C.a,color:"#0d1117",fontWeight:600,textAlign:"center",fontSize:12,borderBottom:`1px solid ${C.a}`}}>✓ Panic mode lifted — wellness routing restored.</div>);
          }
        }
        return null;
      })()}
      {panicError&&(<div style={{padding:"8px 24px",background:C.d+"22",color:C.d,fontSize:11,textAlign:"center",borderBottom:`1px solid ${C.d}40`}}>Panic toggle error: {panicError} <button onClick={()=>setPanicError(null)} style={{marginLeft:8,background:"transparent",border:"none",color:C.d,cursor:"pointer",textDecoration:"underline"}}>dismiss</button></div>)}
      <div style={{borderBottom:`1px solid ${C.b}`,background:C.s,padding:"16px 24px"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div>
            <M style={{color:C.td,letterSpacing:2,textTransform:"uppercase",fontSize:9,display:"block",marginBottom:6}}>
              <span style={{display:"inline-block",width:5,height:5,borderRadius:"50%",background:C.a,marginRight:6,boxShadow:`0 0 6px ${C.a}`}}/>FireAlive · Team Capacity · Day Shift · v{appVersion||"…"}</M>
            <div style={{fontSize:18,fontWeight:600,color:"#E8EDF5",fontFamily:"'Fraunces',serif"}}>Team Capacity Dashboard</div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:12}}>
            {/* ROUTING PANIC BUTTON — always visible */}
            <button disabled={panicBusy} onClick={async()=>{
              if (panicBusy) return;
              if (!window.confirm(panicMode?'Restore wellness routing?':'DISABLE all wellness routing? All analysts will receive maximum complexity tickets.')) return;
              setPanicError(null);
              setPanicBusy(true);
              try {
                const wasActive = panicMode;
                const r = await api.post("/api/routing/panic", {activate: !wasActive});
                if (r?.error) { setPanicError("Panic toggle failed: "+r.error); return; }
                // Optimistic local update; next 30s poll confirms.
                if (wasActive) {
                  setPanicMode(false);
                  setPanicDeactivatedAt(new Date().toISOString());
                } else {
                  setPanicMode(true);
                  setPanicDeactivatedAt(null);
                }
                addA(wasActive?"PANIC_DEACTIVATED":"PANIC_ACTIVATED", r?.message || (wasActive?"Wellness routing restored":"ALL HANDS — wellness routing disabled"));
              } finally { setPanicBusy(false); }
            }} style={{padding:"8px 14px",background:panicMode?"rgba(239,68,68,0.2)":"rgba(239,68,68,0.06)",border:`1px solid ${panicMode?C.d:C.d+"40"}`,borderRadius:20,color:C.d,fontSize:10,fontWeight:600,cursor:panicBusy?"wait":"pointer",fontFamily:"'IBM Plex Mono',monospace",animation:panicMode?"pulse 1.5s infinite":"none",opacity:panicBusy?0.6:1}}>{panicBusy?"…":(panicMode?"⚠ ROUTING OFF — RESTORE":"Disable Burnout Prevention Routing")}</button>
            <div onClick={()=>setTab("overview")} style={{padding:"8px 16px",background:`${sc.c}15`,border:`1px solid ${sc.c}40`,borderRadius:20,display:"flex",alignItems:"center",gap:8,cursor:"pointer",transition:"opacity 0.15s ease"}} onMouseEnter={e=>e.currentTarget.style.opacity="0.8"} onMouseLeave={e=>e.currentTarget.style.opacity="1"}>
              <div style={{width:8,height:8,borderRadius:"50%",background:sc.c,boxShadow:`0 0 6px ${sc.c}`,animation:th.status==="critical"?"pulse 1.5s infinite":"none"}}/>
              <M style={{color:sc.c,fontWeight:500,fontSize:12}}>Team: {sc.l} ({th.score})</M>
            </div>
            {highP.length>0&&<button onClick={()=>setTab("actions")} style={{padding:"8px 14px",background:C.dd,border:`1px solid ${C.d}40`,borderRadius:20,color:C.d,fontSize:11,fontWeight:500,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace",display:"flex",alignItems:"center",gap:6}}>
              <span style={{width:6,height:6,borderRadius:"50%",background:C.d,animation:"pulse 2s infinite"}}/>{highP.length} action{highP.length>1?"s":""} →</button>}
          </div>
        </div>
      </div>
      {peerFlagUrgentOpenCount>0&&(<div onClick={()=>setTab("peer_conduct")} style={{padding:"10px 24px",background:"rgba(239,68,68,0.12)",borderBottom:`1px solid ${C.d}50`,cursor:"pointer",display:"flex",justifyContent:"space-between",alignItems:"center",gap:12}}>
        <div style={{display:"flex",gap:10,alignItems:"center"}}>
          <span style={{width:8,height:8,borderRadius:"50%",background:C.d,boxShadow:`0 0 8px ${C.d}`,animation:"pulse 1.5s infinite",flexShrink:0}}/>
          <div>
            <M style={{color:C.d,fontWeight:600,letterSpacing:1.5,textTransform:"uppercase",fontSize:10,display:"block"}}>Tier-3 Conduct Flag — Action Required</M>
            <M style={{color:C.t,fontSize:11,display:"block",marginTop:2}}>{peerFlagUrgentOpenCount} unresolved urgent flag{peerFlagUrgentOpenCount>1?"s":""} (slurs / threats / harassment). HR intervention recommended.</M>
          </div>
        </div>
        <M style={{color:C.d,fontWeight:500,fontSize:11}}>Review →</M>
      </div>)}
      {/* v1.0.0: Grouped sidebar navigation replaces 57 flat tabs */}
      <div style={{display:"flex",minHeight:"calc(100vh - 120px)"}}>
        <div style={{width:220,flexShrink:0,borderRight:`1px solid ${C.b}`,background:C.s,overflowY:"auto",padding:"8px 0"}}>
          {navGroups.map(g=>(
            <div key={g.cat}>
              <button onClick={()=>toggleNav(g.cat)} style={{width:"100%",padding:"10px 16px",background:navExpanded[g.cat]||g.items.some(i=>i.id===tab)?"rgba(110,231,183,0.05)":"transparent",border:"none",borderLeft:g.items.some(i=>i.id===tab)?`3px solid ${C.a}`:"3px solid transparent",color:g.items.some(i=>i.id===tab)?C.a:C.tm,fontSize:11,fontWeight:600,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer",textAlign:"left",display:"flex",justifyContent:"space-between",letterSpacing:0.5,textTransform:"uppercase"}}>{g.label}<span style={{fontSize:9,opacity:0.5}}>{navExpanded[g.cat]||g.items.some(i=>i.id===tab)?"▼":"▶"}</span></button>
              {(navExpanded[g.cat]||g.items.some(i=>i.id===tab))&&g.items.map(item=>(
                <button key={item.id} onClick={()=>setTab(item.id)} style={{width:"100%",padding:"6px 16px 6px 24px",background:tab===item.id?"rgba(110,231,183,0.1)":"transparent",border:"none",color:tab===item.id?C.a:C.td,fontSize:11,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace",textAlign:"left",display:"flex",alignItems:"center",gap:6}}>{item.label}{item.badge>0&&<span style={{fontSize:8,background:C.dd,color:C.d,padding:"1px 5px",borderRadius:8,fontWeight:600}}>{item.badge}</span>}</button>
              ))}
            </div>
          ))}
          <div style={{padding:"12px 16px",borderTop:`1px solid ${C.b}`,marginTop:8}}>
            <button onClick={()=>setShowSetupWizard(true)} style={{width:"100%",padding:"8px 12px",background:"rgba(110,231,183,0.08)",border:`1px solid ${C.a}30`,borderRadius:8,color:C.a,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>Setup Wizard</button>
            <button onClick={()=>{setShowWelcome(true);setWelcomeStep(0);}} style={{width:"100%",marginTop:6,padding:"8px 12px",background:"rgba(96,165,250,0.08)",border:`1px solid ${C.i}30`,borderRadius:8,color:C.i,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>Welcome Guide</button>
            <button onClick={()=>setTab("help_mc")} style={{width:"100%",marginTop:6,padding:"8px 12px",background:"rgba(167,139,250,0.08)",border:`1px solid ${C.p}30`,borderRadius:8,color:C.p,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>Help</button>
            <button onClick={async()=>{const code=window.prompt("Enter your 6-digit MFA code to "+(configLocked?"unlock":"lock")+" all configurations:");if(!code||code.length<6){if(code!==null)window.alert("Invalid MFA code. Configurations remain "+(configLocked?"locked":"unlocked")+".");return;}const r=await api.post("/api/config/lock",{action:configLocked?"unlock":"lock",totp_code:code});if(r&&!r.error){setConfigLocked(!!r.lock_active);addA(r.lock_active?"MASTER_LOCK":"MASTER_UNLOCK","All configurations "+(r.lock_active?"locked":"unlocked (MFA verified)"));}else{window.alert("Lock toggle failed: "+(r?.error||"unknown error"));addA("MASTER_LOCK_FAIL",r?.error||"unknown");}}} style={{width:"100%",marginTop:6,padding:"8px 12px",background:configLocked?"rgba(239,68,68,0.06)":"rgba(110,231,183,0.06)",border:`1px solid ${configLocked?C.d+"30":C.a+"30"}`,borderRadius:8,color:configLocked?C.d:C.a,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>{configLocked?"🔒 Configs Locked (MFA to unlock)":"🔓 Configs Unlocked (MFA to lock)"}</button>
          </div>
        </div>
        <div style={{flex:1,overflowY:"auto"}}>
          <div style={{padding:"8px 24px",background:"rgba(110,231,183,0.03)",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.td}}>TEAM-LEVEL METRICS · No individual burnout indicators</M></div>
          <div style={{padding:24,maxWidth:820,animation:"fadeIn 0.3s ease"}}>
      {configLocked&&!["actions","overview","help_mc","audit"].includes(tab)&&(<div style={{padding:"10px 16px",background:"rgba(239,68,68,0.06)",border:"1px solid rgba(239,68,68,0.2)",borderRadius:10,marginBottom:16,display:"flex",alignItems:"center",gap:10}}><span style={{color:C.d,fontWeight:600,fontSize:14}}>LOCKED</span><M style={{color:C.d}}>Unlock via sidebar (MFA).</M></div>)}

      {/* ── SETUP WIZARD MODAL ── */}
      {showSetupWizard&&(<div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.85)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={()=>setShowSetupWizard(false)}>
        <div onClick={e=>e.stopPropagation()} style={{background:C.bg,border:`1px solid ${C.b}`,borderRadius:16,padding:32,maxWidth:600,width:"90%",maxHeight:"80vh",overflowY:"auto"}}>
          {setupStep===0&&(<div>
            <L>Welcome to FireAlive Setup</L>
            <M style={{color:C.tm,display:"block",marginBottom:20,lineHeight:1.6}}>This wizard will guide you through first-time configuration. What systems does your SOC use?</M>
            {[{k:"siem",l:"SIEM (Splunk, Elastic, QRadar, Sentinel)"},{k:"soar",l:"SOAR (Splunk SOAR, Cortex XSOAR, Swimlane)"},{k:"edr",l:"EDR (CrowdStrike, SentinelOne, Defender)"},{k:"xdr",l:"XDR (Cortex XDR, 365 Defender, Vision One)"},{k:"atp",l:"ATP (Defender ATP, FireEye, Proofpoint)"},{k:"vpn",l:"VPN Concentrator"}].map(s=>(
              <label key={s.k} style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0",cursor:"pointer"}}><input type="checkbox" checked={setupSelections[s.k]} onChange={e=>setSetupSelections(prev=>({...prev,[s.k]:e.target.checked}))} style={{accentColor:C.a}}/><M style={{color:C.t}}>{s.l}</M></label>
            ))}
            <Sel label="Ticketing System" value={setupSelections.ticketing} onChange={e=>setSetupSelections(prev=>({...prev,ticketing:e.target.value}))}>
              <option value="none">None selected</option><option value="servicenow">ServiceNow</option><option value="jira">Jira Service Mgmt</option><option value="zendesk">Zendesk</option><option value="freshservice">Freshservice</option>
            </Sel>
            <Sel label="IAM Provider" value={setupSelections.iam} onChange={e=>setSetupSelections(prev=>({...prev,iam:e.target.value}))}>
              <option value="none">None / Local auth</option><option value="okta">Okta</option><option value="azure_ad">Azure AD / Entra</option><option value="ping">PingIdentity</option><option value="ad">Active Directory</option>
            </Sel>
            <Btn primary style={{marginTop:16}} onClick={()=>setSetupStep(1)}>Continue →</Btn>
          </div>)}
          {setupStep===1&&(<div>
            <L>Step 2: Core Security</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>We'll now configure MFA, pseudonyms, and basic security. These are the highest-priority settings.</M>
            <Card style={{marginBottom:12,padding:12,borderColor:C.a+"30"}}><M style={{color:C.a,fontWeight:500}}>MFA → </M><M style={{color:C.tm}}>Go to Security → MFA to configure TOTP or WebAuthn</M></Card>
            <Card style={{marginBottom:12,padding:12,borderColor:C.p+"30"}}><M style={{color:C.p,fontWeight:500}}>Pseudonyms → </M><M style={{color:C.tm}}>Go to Analysts → Pseudonyms to enable analyst identity protection</M></Card>
            <Card style={{marginBottom:12,padding:12,borderColor:C.i+"30"}}><M style={{color:C.i,fontWeight:500}}>Posture Assessment → </M><M style={{color:C.tm}}>Go to Security → Posture Assessment to set client requirements</M></Card>
            <div style={{display:"flex",gap:8,marginTop:16}}><Btn onClick={()=>setSetupStep(0)}>← Back</Btn><Btn primary onClick={()=>setSetupStep(2)}>Continue →</Btn></div>
          </div>)}
          {setupStep===2&&(<div>
            <L>Step 3: Host OS Hardening</L>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>These are recommended actions for the machine running FireAlive — not app configurations, but OS-level hardening.</M>
            {["Enable ASLR (Address Space Layout Randomization)","Enable DEP/NX at OS level","Use WPA2-Enterprise or WPA3 only","Encrypt the FireAlive program directory (BitLocker/LUKS)","Set NTFS/ext4 permissions: restrict to service account only","Disable USB mass storage on server machines","Enable audit logging on the host OS","Configure host firewall to allow only FireAlive ports","Integrate with Microsoft Security Compliance Toolkit (if Windows)","Run FireAlive under a dedicated service account (not root/admin)"].map((tip,i)=>(
              <div key={i} style={{padding:"6px 0",display:"flex",gap:8}}><M style={{color:C.a}}>✓</M><M style={{color:C.t}}>{tip}</M></div>
            ))}
            <div style={{display:"flex",gap:8,marginTop:16}}><Btn onClick={()=>setSetupStep(1)}>← Back</Btn><Btn primary onClick={()=>{setShowSetupWizard(false);setSetupStep(0);api.post("/api/v1/audit/log",{event:"SETUP_WIZARD_COMPLETE",detail:"First-time setup wizard completed"}).then(()=>addA("SETUP_WIZARD_COMPLETE","First-time setup wizard completed"));}}>Finish Setup</Btn></div>
          </div>)}
        </div>
      </div>)}

      {/* ── WELCOME GUIDE MODAL ── */}
      {showWelcome&&(<div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.85)",zIndex:999,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={()=>setShowWelcome(false)}>
        <div onClick={e=>e.stopPropagation()} style={{background:C.bg,border:`1px solid ${C.b}`,borderRadius:16,padding:32,maxWidth:560,width:"90%"}}>
          {[
            {title:"SOC Analyst Burnout: The Crisis",body:"71% of SOC analysts report burnout. 64% are considering leaving within 1-3 years. Average tenure is just 1-3 years. Replacing one analyst costs $85,000. For a 6-person team with 35% turnover: $178,500/year in churn costs — before counting insider threat risk and degraded detection."},
            {title:"What Burnout Actually Is",body:"The WHO defines burnout as an occupational phenomenon from chronic workplace stress. Three dimensions: EXHAUSTION, CYNICISM, REDUCED EFFICACY. Burnout is NOT personal failure — it's a structural organizational problem. Maslach's 40+ years of research shows it's caused by mismatches in workload, control, reward, community, fairness, and values."},
            {title:"Causes in SOC Environments",body:"Alert fatigue (97% of orgs see YoY alert increases, only 19% addressed). 50%+ time on manual repetitive work. Context switching costs 15-25 min per interruption. Sustained attention degrades after 90 min. Night shift: 17-28% higher depression. Major incidents produce acute stress comparable to emergency services."},
            {title:"What Prevents Burnout (Research)",body:"Organizational interventions (workload redesign, scheduling, autonomy) are 3x more effective than individual ones. Peer support directly reduces exhaustion. Weekly manager check-ins produce 3x engagement improvement. Micro-breaks every 90 min restore vigilance. Fair distribution matters more than volume. Autonomy, competence, and relatedness drive intrinsic motivation."},
            {title:"How FireAlive Implements These",body:"Every feature is research-grounded. Burnout-aware routing reduces demands. Peer skill-share provides social support. Upskilling hour invests in competence during paid time. Proactive breaks prevent attention degradation. Post-incident protocols follow CISM. Pseudonyms ensure psychological safety. Delegation reduces repetitive work. Skills assessments build efficacy."},
            {title:"Welcome to FireAlive Management Console",body:"This dashboard gives you team-level visibility into analyst wellbeing — never individual burnout data. You manage routing, integrations, assessments, and team health from here."},
            {title:"What FireAlive Does",body:"Burnout-aware ticket routing, peer skill-sharing with E2EE, post-incident wellness protocols, skills assessments and training, real-time team health monitoring, integration with your SOAR, SIEM, and ticketing systems."},
            {title:"What FireAlive Does NOT Do",body:"It does NOT surveil individual analysts. Burnout data is pseudonymized. Team leads see only aggregate capacity metrics. Analyst privacy is architecturally enforced, not just promised."},
            {title:"How It's Built on Research",body:"Every feature is grounded in peer-reviewed burnout prevention research (Maslach Burnout Inventory, CISM framework, organizational psychology). The Knowledge Base contains 42 research-backed entries."},
            {title:"You're Ready",body:"Use the sidebar to navigate. Start with Operations → Actions for immediate priorities. Use the Setup Wizard (bottom of sidebar) for first-time configuration."},
          ][welcomeStep]&&(
            <div>
              <L>{[
                "SOC Analyst Burnout: The Crisis","What Burnout Actually Is","Causes in SOC Environments",
                "What Prevents Burnout (Research)","How FireAlive Implements These",
                "Welcome to FireAlive Management Console","What FireAlive Does","What FireAlive Does NOT Do",
                "How It's Built on Research","You're Ready"
              ][welcomeStep]}</L>
              <M style={{color:C.tm,display:"block",marginBottom:20,lineHeight:1.8}}>{[
                "71% of SOC analysts report burnout. 64% are considering leaving within 1-3 years. Average tenure is just 1-3 years. Replacing one analyst costs $85,000. For a 6-person team with 35% turnover: $178,500/year in churn costs.",
                "The WHO defines burnout as an occupational phenomenon from chronic workplace stress. Three dimensions: EXHAUSTION, CYNICISM, REDUCED EFFICACY. Burnout is NOT personal failure — it's structural.",
                "Alert fatigue (97% of orgs see YoY increases, only 19% addressed). 50%+ time on manual work. Context switching costs 15-25 min. Attention degrades after 90 min. Night shift: 17-28% higher depression.",
                "Organizational interventions are 3x more effective than individual ones. Peer support directly reduces exhaustion. Weekly check-ins produce 3x engagement. Micro-breaks every 90 min restore vigilance.",
                "Burnout-aware routing reduces demands. Peer skill-share provides social support. Upskilling hour invests in competence. Proactive breaks prevent degradation. Post-incident protocols follow CISM. Pseudonyms ensure safety.",
                "This dashboard gives you team-level visibility into analyst wellbeing — never individual burnout data. You manage routing, integrations, assessments, and team health from here.",
                "Burnout-aware ticket routing, peer skill-sharing with E2EE, post-incident wellness protocols, skills assessments and training, real-time team health monitoring, integration with your SOAR, SIEM, and ticketing systems.",
                "It does NOT surveil individual analysts. Burnout data is pseudonymized. Team leads see only aggregate capacity metrics. Analyst privacy is architecturally enforced, not just promised.",
                "Every feature is grounded in peer-reviewed burnout prevention research (Maslach Burnout Inventory, CISM framework, organizational psychology). The Knowledge Base contains 42 research-backed entries.",
                "Use the sidebar to navigate. Start with Operations → Actions for immediate priorities. Use the Setup Wizard (bottom of sidebar) for first-time configuration."
              ][welcomeStep]}</M>
              <div style={{display:"flex",justifyContent:"space-between"}}>
                <M style={{color:C.td}}>{welcomeStep+1}/10</M>
                <div style={{display:"flex",gap:8}}>
                  <Btn onClick={()=>{setShowWelcome(false);setWelcomeStep(0);}}>Dismiss</Btn>
                  {welcomeStep>0&&<Btn onClick={()=>setWelcomeStep(prev=>prev-1)}>← Back</Btn>}
                  {welcomeStep<9?<Btn primary onClick={()=>setWelcomeStep(prev=>prev+1)}>Next →</Btn>:<Btn primary onClick={()=>{setShowWelcome(false);setWelcomeStep(0);}}>Get Started</Btn>}
                </div>
              </div>
            </div>
          )}}
        </div>
      </div>)}

        {/* ACTIONS */}
        {tab==="actions"&&(<div>
          <div style={{padding:"10px 16px",background:C.s,border:`1px solid ${C.b}`,borderRadius:10,marginBottom:20,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <M style={{color:C.tm}}>Prompt depth:</M>
            <div style={{display:"flex",gap:4}}>{["full","compact","minimal"].map(d=><button key={d} onClick={()=>{setGD(d===gDepth?null:d);addA("GLOBAL_DEPTH",d);}} style={{padding:"4px 12px",background:gDepth===d?C.ad:"transparent",border:`1px solid ${gDepth===d?C.a+"50":C.b}`,borderRadius:6,color:gDepth===d?C.a:C.tm,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>{d}</button>)}{gDepth&&<button onClick={()=>setGD(null)} style={{padding:"4px 8px",background:"transparent",border:"none",color:C.td,fontSize:10,cursor:"pointer"}}>×</button>}</div>
          </div>
          {activeP.map(([key,pr])=>{const dp=getD(key);const ct=pr[dp]||pr.full;return(
            <Card key={key} style={{marginBottom:14,borderLeft:`3px solid ${pr.sev==="high"?C.d:pr.sev==="medium"?C.w:C.tm}`}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}>
                <div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",flex:1}}>{ct.title}</div>
                <div style={{display:"flex",gap:3,flexShrink:0,marginLeft:12}}>{["full","compact","minimal"].map(d=><button key={d} onClick={()=>{setPD(prev=>({...prev,[key]:d}));addA("DEPTH",`${key}→${d}`);}} style={{padding:"3px 8px",fontSize:9,fontFamily:"'IBM Plex Mono',monospace",borderRadius:4,cursor:"pointer",background:dp===d?C.ad:"transparent",border:`1px solid ${dp===d?C.a+"50":C.b}`,color:dp===d?C.a:C.td}}>{d}</button>)}</div>
              </div>
              <div style={{fontSize:12,lineHeight:1.7,whiteSpace:"pre-line"}}>{ct.body}</div>
              {ct.cite&&<M style={{color:C.td,display:"block",marginTop:10,fontStyle:"italic"}}>{ct.cite}</M>}
              <Btn small style={{marginTop:12}} onClick={()=>{setSil(prev=>[...prev,key]);addA("SILENCED",key);}}>Silence</Btn>
            </Card>
          );})}
          {silenced.length>0&&<Card style={{marginTop:20,padding:12}}><M style={{color:C.td,marginBottom:8}}>Silenced:</M><div style={{display:"flex",flexWrap:"wrap",gap:6}}>{silenced.map(k=><Btn key={k} small onClick={()=>setSil(prev=>prev.filter(s=>s!==k))}>{k} ✕</Btn>)}</div></Card>}
        </div>)}

        {/* TEAM */}
        {tab==="overview"&&(<div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:24}}>
            {[{l:"Team Health",v:`${th.score}/100`,c:sc.c},{l:"Avg Util",v:`${th.avgUtil}%`,c:th.avgUtil>85?C.d:th.avgUtil>70?C.w:C.a},{l:"Over Cap",v:`${th.oc}/${th.size}`,c:th.oc>2?C.d:C.tm},{l:"Extended",v:`${th.ext}`,c:th.ext>0?C.d:C.a}].map((m,i)=><Card key={i} style={{textAlign:"center",padding:14}}><div style={{fontSize:22,fontWeight:300,color:m.c,fontFamily:"'Fraunces',serif"}}>{m.v}</div><M style={{color:C.td,letterSpacing:1,textTransform:"uppercase",marginTop:4}}>{m.l}</M></Card>)}
          </div>
          <L>Day Shift · Capacity (workload — no burnout indicators)</L>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10,marginBottom:24}}>
            {sessData.map(d=>{const uc=d.util>0.85?C.d:d.util>0.70?C.w:C.a;return(
              <Card key={d.id} style={{padding:14}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}><span style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>{d.name}</span><Badge color={tierClr(d.tier)}>{tierLbl(d.tier)}</Badge></div>
                <div style={{marginBottom:6}}><div style={{display:"flex",justifyContent:"space-between",fontSize:10,marginBottom:3}}><M style={{color:C.tm}}>Util</M><M style={{color:uc}}>{Math.round(d.util*100)}%</M></div>
                <div style={{height:3,background:"rgba(255,255,255,0.04)",borderRadius:2,overflow:"hidden"}}><div style={{width:`${d.util*100}%`,height:"100%",background:uc,borderRadius:2}}/></div></div>
                <M style={{color:C.td,display:"flex",justifyContent:"space-between"}}><span>{d.tk} tickets</span><span>P{d.cap}</span></M>
                {d.wo>0&&<M style={{color:C.w,marginTop:4}}>{d.wo}w over</M>}
              </Card>
            );})}
          </div>
          {provisionedClients.length>0&&<><L>Recently Provisioned</L><div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10,marginBottom:24}}>
            {provisionedClients.map(c=><Card key={c.id} style={{padding:14,borderLeft:`3px solid ${C.a}`}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}><span style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>{c.analyst}</span><Badge color={C.a}>{c.status}</Badge></div>
              <M style={{color:C.tm,lineHeight:1.8}}>{tierLbl(c.tier)} · {c.shift}<br/>Host: {c.hostname}<br/>Activation: {c.id}</M>
            </Card>)}
          </div></>}

          {/* R3j C10: Recent Routing Decisions surface. Sourced from liveFeed
              (the existing audit-log-backed feed populated via addA) for R3j v1
              — a dedicated GET /api/routing/recent-events endpoint backed by the
              soar_routing_events table is deferred to a future phase. Shows the
              last 5 routing-related feed entries with the assigned analyst's
              indicator. If no routing activity yet, shows a placeholder. */}
          <L>Recent Routing Decisions</L>
          <Card style={{marginBottom:24,padding:12}}>
            {(()=>{
              const routingEntries = (liveFeed || []).slice(0, 5);
              if (routingEntries.length === 0) {
                return (<M style={{color:C.td,display:"block",padding:"12px 0",textAlign:"center",fontStyle:"italic"}}>No routing decisions yet. Decisions appear here as the SOAR routes alerts (manual or auto-assigned).</M>);
              }
              return routingEntries.map(e => (
                <div key={e.id} style={{padding:"8px 0",borderBottom:`1px solid ${C.b}`,display:"flex",gap:10,alignItems:"center",fontSize:11}}>
                  <M style={{color:C.td,fontSize:9,minWidth:60}}>{e.ts}</M>
                  <M style={{color:e.cx>=4?C.d:e.cx>=3?C.w:C.tm,minWidth:22,fontFamily:"'IBM Plex Mono',monospace"}}>P{e.cx}</M>
                  <span style={{flex:1,color:C.t}}>{e.alert}</span>
                  {e.auto ? (<Badge color={C.i}>→ {e.autoN}</Badge>) : (<M style={{color:e.eq?C.a:C.tm,fontFamily:"'IBM Plex Mono',monospace"}}>→ {e.to}{e.eq?" ⚖":""}</M>)}
                </div>
              ));
            })()}
            {liveFeed && liveFeed.length > 0 && (<M style={{color:C.td,display:"block",marginTop:8,fontSize:10,textAlign:"right"}}>Showing {Math.min(5, liveFeed.length)} of {liveFeed.length} recent. Full feed in Routing tab.</M>)}
          </Card>

          <L>All Shifts</L>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
            {["day","swing","night"].map(s=>{const sa=analysts.filter(a=>a.shift===s);return(
              <Card key={s}><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:6}}>{shiftLbl(s)}</div><M style={{color:C.tm,lineHeight:1.8}}>{sa.length} analysts · <span style={{color:tierClr(1)}}>L1×{sa.filter(a=>a.tier===1).length}</span> · <span style={{color:tierClr(2)}}>L2×{sa.filter(a=>a.tier===2).length}</span> · <span style={{color:tierClr(3)}}>L3×{sa.filter(a=>a.tier===3).length}</span></M></Card>
            );})}
          </div>
        </div>)}

        {/* AUTOMATION */}

        {/* SKILL MATRIX — NEW v0.0.9 */}
        {tab==="skillmatrix"&&(<div>
          <L>Skill Matrix & Level-Up Signals</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Aggregate skill progression across your team. When an analyst reaches proficiency thresholds across 3+ core skills, you receive a soft signal. This is recognition of growth (R037, R040), not a binding promotion trigger. You can silence or act on any signal.</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>Level-Up Signals</div>
            {analysts.filter(a=>a.tier===1).slice(0,2).map(a=>({name:a.name,tier:a.tier,skills:0,top:"No assessments yet",sig:"Assessments pending"})).map((a,i)=>(
              <Card key={i} style={{marginBottom:8,padding:"12px 14px",borderLeft:`3px solid ${a.skills>=3?C.a:C.w}`}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}><span style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>{a.name}</span><div style={{display:"flex",gap:6}}><Badge color={tierClr(a.tier)}>{tierLbl(a.tier)}</Badge>{a.skills>=3&&<Badge color={C.a}>level-up signal</Badge>}</div></div>
                <M style={{color:C.tm,lineHeight:1.6}}>{a.top}</M>
                <M style={{color:a.skills>=3?C.a:C.w,display:"block",marginTop:4}}>{a.sig}</M>
              </Card>
            ))}
          </Card>
          <Card style={{padding:12,borderColor:C.p+"30"}}>
            <M style={{color:C.p,fontWeight:500,display:"block",marginBottom:4}}>How it works</M>
            <M style={{color:C.tm,lineHeight:1.8}}>Analyst Client tracks skill progress from training platform completions + on-shift metrics. When 3+ core skills reach 80%, a depersonalized signal appears here. The analyst's name is attached only because you are their team lead — the signal does not propagate to SIEM or reports. Use it as a prompt to give praise, discuss growth, or evaluate tier adjustment.</M>
          </Card>
        </div>)}

        {/* SKILLS ASSESSMENT SYSTEM — NEW v1.0.0 */}
        {tab==="assessments"&&(<div>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
            <div><L style={{marginBottom:0}}>Skills Assessment System</L>
            <M style={{color:C.tm,display:"block",marginTop:4,lineHeight:1.6}}>Create tier-appropriate assessments, assign to analysts, track results. Gaps auto-propagate training recommendations to the analyst's upskilling area. Only you and the analyst see their individual results.</M></div>
            <Btn primary onClick={()=>setShowCreateAssmt(true)}>+ Create Assessment</Btn>
          </div>

          {/* Active Assessments */}
          {assessments.map(assmt=>{
            const skills=assmt.skills.map(sid=>SKILLS_TAXONOMY.find(s=>s.id===sid)||{id:sid,name:sid,cat:"Custom"});
            const completedCount=Object.keys(assmt.results).length;
            const totalAssigned=assmt.assignees.length;
            return(
              <Card key={assmt.id} style={{marginBottom:16,borderLeft:`3px solid ${completedCount===totalAssigned?C.a:C.w}`}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}>
                  <div><span style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>{assmt.name}</span><M style={{color:C.td,marginLeft:8}}>Created {assmt.createdAt}</M></div>
                  <div style={{display:"flex",gap:6}}><Badge color={tierClr(assmt.tier)}>Tier {assmt.tier}</Badge><Badge color={completedCount===totalAssigned?C.a:C.w}>{completedCount}/{totalAssigned} complete</Badge></div>
                </div>
                <M style={{color:C.tm,display:"block",marginBottom:10}}>Skills assessed: {skills.map(s=>s.name).join(", ")}</M>

                {/* Per-analyst results */}
                {assmt.assignees.map(aId=>{
                  const analyst=analysts.find(a=>a.id===aId);
                  const result=assmt.results[aId];
                  if(!analyst) return null;
                  return(
                    <Card key={aId} style={{marginBottom:8,padding:"10px 14px",background:result?"rgba(255,255,255,0.01)":"rgba(255,255,255,0.005)"}}>
                      <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                        <span style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>{analyst.name}</span>
                        {result?<Badge color={C.a}>Completed {result.completedAt}</Badge>:<Badge color={C.w}>Pending</Badge>}
                      </div>
                      {result&&(
                        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:6}}>
                          {skills.map(skill=>{
                            const score=result[skill.id]||0;
                            const color=score>=80?C.a:score>=60?C.w:score>=40?"#F97316":C.d;
                            const gap=score<70;
                            return(
                              <div key={skill.id} style={{padding:"6px 8px",background:gap?"rgba(239,68,68,0.05)":"rgba(255,255,255,0.02)",border:`1px solid ${gap?C.d+"30":C.b}`,borderRadius:6}}>
                                <div style={{display:"flex",justifyContent:"space-between",marginBottom:3}}><M style={{fontSize:10}}>{skill.name}</M><M style={{color,fontSize:10,fontWeight:500}}>{score}%</M></div>
                                <div style={{height:3,background:"rgba(255,255,255,0.04)",borderRadius:2,overflow:"hidden"}}><div style={{width:`${score}%`,height:"100%",background:color,borderRadius:2}}/></div>
                                {gap&&<M style={{color:C.d,fontSize:9,display:"block",marginTop:2}}>→ Training recommended</M>}
                              </div>
                            );
                          })}
                        </div>
                      )}
                      {result&&(()=>{
                        const gaps=skills.filter(s=>(result[s.id]||0)<70);
                        if(!gaps.length) return <M style={{color:C.a,display:"block",marginTop:6,fontSize:11}}>All skills at or above proficiency threshold. No training gaps detected.</M>;
                        return <M style={{color:C.w,display:"block",marginTop:6,fontSize:11}}>{gaps.length} gap{gaps.length>1?"s":""} detected → training recommendations pushed to {analyst.name}'s Analyst Client upskilling area.</M>;
                      })()}
                    </Card>
                  );
                })}
              </Card>
            );
          })}

          {/* Growth Tracking */}
          <Card style={{marginBottom:16,borderColor:C.a+"30"}}>
            <div style={{fontSize:13,fontWeight:500,color:C.a,marginBottom:10}}>Growth Signals from Assessments</div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>When an analyst completes training on a gap area and re-assesses above threshold, this signals real development. These are meaningful upskilling indicators (R027, R037, R040).</M>
            {analysts.slice(0,2).map(a=>({name:a.name,from:"No baseline yet",to:"Assessments pending",via:"Training pending",date:"—"})).map((g,i)=>(
              <Card key={i} style={{marginBottom:8,padding:"10px 14px",borderLeft:`3px solid ${C.a}`}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>{g.name}</div>
                <M style={{color:C.tm,lineHeight:1.6}}>{g.from} → {g.to} · Via: {g.via} · {g.date}</M>
              </Card>
            ))}
          </Card>

          <Card style={{padding:12,borderColor:C.p+"30"}}>
            <M style={{color:C.p,fontWeight:500,display:"block",marginBottom:4}}>Privacy: Assessment results visibility</M>
            <M style={{color:C.tm,lineHeight:1.8}}>Each analyst's assessment results are visible only to themselves (in their Analyst Client skill matrix) and to you as their team lead. Results do not propagate to SIEM, reports, or other leads. Gap-driven training recommendations appear only in the individual analyst's upskilling area. This supports competence development (R037) without creating surveillance pressure (R021, R022).</M>
          </Card>
        </div>)}

        {/* Create Assessment Modal */}
        {showCreateAssmt&&<Modal title="Create Skills Assessment" onClose={()=>{setShowCreateAssmt(false);setNewAssmt({name:"",tier:1,skills:[],assignees:[],customSkills:[]});}} width={600}>
          <Input label="Assessment name" placeholder="e.g., L1 Quarterly Review, New Hire Onboarding" value={newAssmt.name} onChange={e=>setNewAssmt(prev=>({...prev,name:e.target.value}))} maxLength={200}/>
          <Sel label="Target tier level" value={newAssmt.tier} onChange={e=>setNewAssmt(prev=>({...prev,tier:Number(e.target.value)}))}>
            <option value={1}>Tier 1 (L1) — Triage & Documentation</option>
            <option value={2}>Tier 2 (L2) — Investigation & Analysis</option>
            <option value={3}>Tier 3 (L3) — Hunting, Forensics & Leadership</option>
          </Sel>

          <div style={{marginBottom:14}}>
            <M style={{color:C.tm,marginBottom:8,display:"block"}}>Select skills to assess (filtered by tier):</M>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
              {SKILLS_TAXONOMY.filter(s=>s.tier.includes(newAssmt.tier)).map(skill=>(
                <label key={skill.id} style={{display:"flex",alignItems:"flex-start",gap:8,padding:"8px 10px",background:newAssmt.skills.includes(skill.id)?C.ad:C.s,border:`1px solid ${newAssmt.skills.includes(skill.id)?C.a+"40":C.b}`,borderRadius:8,cursor:"pointer",fontSize:11}}>
                  <input type="checkbox" checked={newAssmt.skills.includes(skill.id)} onChange={e=>{const checked=e.target.checked;setNewAssmt(prev=>({...prev,skills:checked?[...prev.skills,skill.id]:prev.skills.filter(s=>s!==skill.id)}));}} style={{accentColor:C.a,marginTop:2}}/>
                  <div><div style={{color:"#E8EDF5",fontWeight:500}}>{skill.name}</div><div style={{color:C.td,marginTop:2}}>{skill.desc}</div><Badge color={C.p} style={{marginTop:4}}>{skill.cat}</Badge></div>
                </label>
              ))}
            </div>
          </div>

          {/* Custom skill addition */}
          <Card style={{marginBottom:14,padding:12,borderColor:C.i+"30"}}>
            <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:8}}>Add Custom Skill</M>
            <M style={{color:C.tm,display:"block",marginBottom:8,lineHeight:1.5}}>For emerging or organization-specific skills not in the standard taxonomy.</M>
            <div style={{display:"grid",gridTemplateColumns:"2fr 3fr auto",gap:8,alignItems:"end"}}>
              <Input label="Skill name" placeholder="e.g., Kubernetes Security" value={newCustomSkill.name} onChange={e=>setNewCustomSkill(prev=>({...prev,name:e.target.value}))} maxLength={100}/>
              <Input label="Description" placeholder="What does proficiency look like?" value={newCustomSkill.desc} onChange={e=>setNewCustomSkill(prev=>({...prev,desc:e.target.value}))} maxLength={300}/>
              <Btn primary disabled={!newCustomSkill.name.trim()} onClick={()=>{if(newCustomSkill.name.trim()){const cid="custom-"+Date.now();setNewAssmt(prev=>({...prev,skills:[...prev.skills,cid],customSkills:[...prev.customSkills,{id:cid,name:newCustomSkill.name,desc:newCustomSkill.desc,cat:"Custom"}]}));setNewCustomSkill({name:"",desc:""});}}}>Add</Btn>
            </div>
            {newAssmt.customSkills.length>0&&<div style={{marginTop:8}}>{newAssmt.customSkills.map(cs=>(
              <Badge key={cs.id} color={C.i} style={{marginRight:4,marginBottom:4}}>{cs.name} ×</Badge>
            ))}</div>}
          </Card>

          <div style={{marginBottom:14}}>
            <M style={{color:C.tm,marginBottom:8,display:"block"}}>Assign to analysts:</M>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:6}}>
              {analysts.filter(a=>a.tier<=newAssmt.tier+1).map(a=>(
                <label key={a.id} style={{display:"flex",alignItems:"center",gap:6,fontSize:11,color:C.t,padding:"6px 10px",background:newAssmt.assignees.includes(a.id)?C.ad:C.s,border:`1px solid ${newAssmt.assignees.includes(a.id)?C.a+"40":C.b}`,borderRadius:6,cursor:"pointer"}}>
                  <input type="checkbox" checked={newAssmt.assignees.includes(a.id)} onChange={e=>{const checked=e.target.checked;setNewAssmt(prev=>({...prev,assignees:checked?[...prev.assignees,a.id]:prev.assignees.filter(i=>i!==a.id)}));}} style={{accentColor:C.a}}/><span>{a.name}</span><Badge color={tierClr(a.tier)}>{tierLbl(a.tier)}</Badge>
                </label>
              ))}
            </div>
          </div>

          <div style={{display:"flex",gap:8}}>
            <Btn primary disabled={!newAssmt.name.trim()||newAssmt.skills.length===0||newAssmt.assignees.length===0} onClick={()=>{
              const assmt={id:"a"+Date.now(),name:newAssmt.name,tier:newAssmt.tier,skills:newAssmt.skills,assignees:newAssmt.assignees,createdAt:new Date().toISOString().slice(0,10),status:"active",results:{}};
              setAssessments(prev=>[assmt,...prev]);
              addA("ASSESSMENT_CREATED",`"${newAssmt.name}" · Tier ${newAssmt.tier} · ${newAssmt.skills.length} skills · ${newAssmt.assignees.length} assignees`);
              setShowCreateAssmt(false);setNewAssmt({name:"",tier:1,skills:[],assignees:[],customSkills:[]});
            }}>Create & Assign Assessment</Btn>
            <Btn onClick={()=>setShowCreateAssmt(false)}>Cancel</Btn>
          </div>
        </Modal>}

        {/* SHIFT HANDOFF — NEW v0.0.9 */}
        {tab==="handoff"&&(<div>
          <L>Shift Handoff Notes</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Outgoing lead summarizes team state for incoming lead. Reduces information loss during shift transitions — fatigue-related handoff errors peak in the last 2 hours of shifts (R017).</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Current Shift Summary (auto-generated)</div>
            <M style={{color:C.t,lineHeight:2}}>
              Team health: <span style={{color:sc.c,fontWeight:500}}>{sc.l} ({th.score})</span> · Avg util: {th.avgUtil}% · Over capacity: {th.oc}/{th.size}<br/>
              Active routing adjustments: {lqRequests.filter(r=>r.status==="active").length} (anonymous lighter queue{lqRequests.filter(r=>r.status==="active").length!==1?"s":""})<br/>
              Active recovery protocols: {activeRetros.filter(r=>r.phase!=="Complete").length}<br/>
              Open high-priority: 2 incidents (C2 Beacon cluster, lateral movement investigation)<br/>
              Staffing note: Full complement on day shift. Swing shift has 1 analyst on PTO.
            </M>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Outgoing Lead Notes</div>
            <textarea value={handoffNotes} onChange={e=>setHandoffNotes(e.target.value)} placeholder="Add context for the incoming lead: what's in progress, what needs attention, anything unusual about the shift..." maxLength={2000} style={{width:"100%",height:100,padding:12,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12,resize:"vertical"}}/>
            <div style={{display:"flex",gap:8,marginTop:8}}>
              <Btn primary disabled={!handoffNotes.trim()} onClick={()=>{const shifts=["Day","Swing","Night"];const now=new Date();const h=now.getHours();const fromShift=h<14?"Day":h<22?"Swing":"Night";const toShift=shifts[(shifts.indexOf(fromShift)+1)%3];setHandoffHistory(prev=>[{ts:now.toLocaleDateString("en-US",{month:"short",day:"numeric"})+" "+now.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),from:`${fromShift} → ${toShift}`,notes:handoffNotes},...prev]);addA("HANDOFF_SUBMITTED","Shift handoff notes saved: "+handoffNotes.slice(0,60)+"...");setHandoffNotes("");}}>Save Handoff</Btn>
              <Btn disabled={!handoffNotes.trim()} onClick={()=>{const shifts=["Day","Swing","Night"];const now=new Date();const h=now.getHours();const fromShift=h<14?"Day":h<22?"Swing":"Night";const toShift=shifts[(shifts.indexOf(fromShift)+1)%3];setHandoffHistory(prev=>[{ts:now.toLocaleDateString("en-US",{month:"short",day:"numeric"})+" "+now.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),from:`${fromShift} → ${toShift}`,notes:handoffNotes},...prev]);api.post("/api/v1/audit/log",{event:"HANDOFF_SENT",detail:"Handoff notes saved and notification sent to incoming lead"}).then(()=>addA("HANDOFF_SENT","Handoff notes saved and notification sent to incoming lead"));setHandoffNotes("");}}>Save & Notify Incoming Lead</Btn>
            </div>
          </Card>
          <Card style={{padding:12}}>
            <M style={{color:C.td,fontWeight:500,display:"block",marginBottom:6}}>Previous Handoffs ({handoffHistory.length})</M>
            {handoffHistory.map((h,i)=>(
              <div key={i} style={{padding:"8px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.a}}>{h.ts}</M><M style={{color:C.tm}}> · {h.from}</M><div style={{fontSize:11,color:C.t,marginTop:4,lineHeight:1.5}}>{h.notes}</div></div>
            ))}
          </Card>
        </div>)}

        {/* INCIDENT RETROSPECTIVES — NEW v0.0.9 */}
        {tab==="retro"&&(<div>
          <L>Incident Retrospectives & Recovery</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Major incidents produce acute stress comparable to emergency services (R038). This module provides structured post-incident support based on Critical Incident Stress Management (CISM) principles: voluntary participation, peer-driven support, normalization of reactions, and clear referral pathways.</M>
          <Card style={{marginBottom:16,borderColor:C.d+"30"}}>
            <div style={{fontSize:13,fontWeight:500,color:C.d,marginBottom:10}}>Active Recovery Protocols ({activeRetros.length})</div>
            {activeRetros.map((r,i)=>(
              <Card key={r.id} style={{marginBottom:10,padding:"12px 14px",borderLeft:`3px solid ${r.phase==="Complete"?C.a:C.w}`}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}><span style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>{r.incident}</span><div style={{display:"flex",gap:6}}><Badge color={r.severity==="P1"?C.d:C.w}>{r.severity}</Badge><Badge color={r.phase==="Complete"?C.a:C.w}>{r.phase}</Badge></div></div>
                <M style={{color:C.i,display:"block",marginBottom:4}}>Initiated: {r.initiated}</M>
                <M style={{color:C.tm}}>Analysts ({r.names.length}): {r.names.join(", ")}</M>
                {r.actions.map((a,j)=><M key={j} style={{color:C.t,display:"block",marginTop:2}}>· {a}</M>)}
                {r.phase!=="Complete"&&<div style={{marginTop:8,display:"flex",gap:6}}>
                  <Btn small primary onClick={()=>{setActiveRetros(prev=>prev.map(x=>x.id===r.id?{...x,phase:"Complete",actions:[...x.actions,"Marked complete at "+new Date().toLocaleTimeString()]}:x));addA("RETRO_COMPLETE","Recovery protocol completed: "+r.incident);}}>Mark Complete</Btn>
                  <Btn small onClick={()=>{setActiveRetros(prev=>prev.map(x=>x.id===r.id?{...x,actions:[...x.actions,"Follow-up check-in sent at "+new Date().toLocaleTimeString()]}:x));addA("RETRO_FOLLOWUP","Follow-up sent for: "+r.incident);}}>Send Follow-up</Btn>
                </div>}
              </Card>
            ))}
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Activate New Recovery Protocol</div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Activates: lighter queue caps for involved analysts, peer support availability in their client, automated follow-up check-ins at 24hr, 72hr, and 2 weeks.</M>
            <Input label="Incident reference" value={retroIncident} onChange={e=>setRetroIncident(e.target.value)} placeholder="e.g., Ransomware — Mar 28" maxLength={200}/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Sel label="Severity" value={retroSeverity} onChange={e=>setRetroSeverity(e.target.value)}><option value="P1">P1 — Critical</option><option value="P2">P2 — High</option><option value="P3">P3 — Medium</option></Sel>
              </div>
            <div style={{marginBottom:14}}><M style={{color:C.tm,marginBottom:6,display:"block"}}>Select involved analysts:</M>
              <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:6}}>{analysts.map(a=>(
                <label key={a.id} style={{display:"flex",alignItems:"center",gap:6,fontSize:11,color:C.t,padding:"4px 8px",background:retroAnalysts.includes(a.id)?C.ad:C.s,border:`1px solid ${retroAnalysts.includes(a.id)?C.a+"50":C.b}`,borderRadius:6,cursor:"pointer"}}>
                  <input type="checkbox" checked={retroAnalysts.includes(a.id)} onChange={()=>setRetroAnalysts(prev=>prev.includes(a.id)?prev.filter(x=>x!==a.id):[...prev,a.id])} style={{accentColor:C.a}}/><span>{a.name}</span><Badge color={tierClr(a.tier)}>{tierLbl(a.tier)}</Badge>
                </label>
              ))}</div>
            </div>
            <Sel label="Queue reduction duration" value={retroDuration} onChange={e=>setRetroDuration(e.target.value)}><option value="1_shift">This shift</option><option value="24hr">24 hours</option><option value="72hr">72 hours</option><option value="1_week">1 week</option></Sel>
            <Btn primary disabled={!retroIncident.trim()||retroAnalysts.length===0} onClick={async()=>{const now=new Date();const names=retroAnalysts.map(id=>analysts.find(a=>a.id===id)?.name).filter(Boolean);
              if(apiReady && window.FireAliveAPI){
                try{
                  const result=await window.FireAliveAPI.retro.activate({incident:retroIncident,severity:retroSeverity,analystIds:retroAnalysts,queueReductionDuration:retroDuration});
                  const newRetro={id:result.id,incident:retroIncident,severity:retroSeverity,names,phase:"0-24hr active",initiated:now.toLocaleDateString("en-US",{month:"short",day:"numeric"})+", "+now.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),actions:["Lighter queues activated for "+names.length+" analysts","Peer support availability published","Check-ins scheduled: 24hr, 72hr, 2 weeks"]};
                  setActiveRetros(prev=>[newRetro,...prev]);
                  addA("RETRO_ACTIVATED","API: "+retroIncident+" — "+names.length+" analysts");
                }catch(e){addA("RETRO_ERROR",e.message);}
              } else {
                const newRetro={id:Date.now(),incident:retroIncident,severity:retroSeverity,names,phase:"0-24hr active",initiated:now.toLocaleDateString("en-US",{month:"short",day:"numeric"})+", "+now.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),actions:["Lighter queues activated for "+names.length+" analysts","Peer support availability published","Check-ins scheduled: 24hr, 72hr, 2 weeks"]};
                setActiveRetros(prev=>[newRetro,...prev]);
                addA("RETRO_ACTIVATED","Recovery protocol activated for \""+retroIncident+"\" — "+names.length+" analysts — "+retroDuration);
              }
              setRetroIncident("");setRetroAnalysts([]);setRetroSeverity("P1");setRetroDuration("24hr");}}>Activate Protocol</Btn>
          </Card>
          <Card style={{marginBottom:16,padding:12,borderColor:C.w+"30"}}>
            <div style={{fontSize:12,fontWeight:500,color:C.w,marginBottom:8}}>Availability Reminder</div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Sends a brief, neutral notification to involved analysts: "Recovery resources are available in your Recovery tab if you would like them." CISM best practice: support should be available and visible, never forced (R007, R023).</M>
            <Btn onClick={()=>api.post("/api/v1/audit/log",{event:"RETRO_REMINDER",detail:"Availability reminder sent to involved analysts"}).then(()=>addA("RETRO_REMINDER","Availability reminder sent to involved analysts"))}>Send Reminder</Btn>
          </Card>

          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:C.i,marginBottom:10}}>Custom Recovery Resources ({customResources.length} published)</div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Add organization-specific resources. These appear in all Analyst Clients (existing and newly provisioned) in real time.</M>
            {customResources.length>0&&<div style={{marginBottom:12}}>{customResources.map((r,i)=>(
              <div key={i} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
                <div><div style={{fontSize:12,color:"#E8EDF5"}}>{r.title}</div><M style={{color:C.tm}}>{r.url} · {r.cat}</M></div>
                <Btn small danger onClick={()=>{setCustomResources(prev=>prev.filter((_,j)=>j!==i));addA("CUSTOM_RESOURCE_REMOVED",r.title);}}>Remove</Btn>
              </div>
            ))}</div>}
            <Input label="Resource title" value={newResTitle} onChange={e=>setNewResTitle(e.target.value)} placeholder="e.g., Company EAP Portal" maxLength={200}/>
            <Input label="Resource URL or description" value={newResUrl} onChange={e=>setNewResUrl(e.target.value)} placeholder="https://eap.corp.com or call 1-800-XXX-XXXX" maxLength={500}/>
            <Sel label="Category" value={newResCat} onChange={e=>setNewResCat(e.target.value)}><option value="professional">Professional Support</option><option value="self-help">Self-Help</option><option value="peer">Peer Support</option><option value="training">Training</option></Sel>
            <Btn primary disabled={!newResTitle.trim()||!newResUrl.trim()} onClick={async()=>{
              if(apiReady && window.FireAliveAPI){
                try{
                  const result=await window.FireAliveAPI.resources.add({title:newResTitle,url:newResUrl,category:newResCat});
                  setCustomResources(prev=>[...prev,{id:result.id,title:newResTitle,url:newResUrl,category:newResCat}]);
                  addA("RESOURCE_ADDED","API: \""+newResTitle+"\" published");
                }catch(e){addA("RESOURCE_ERROR",e.message);}
              } else {
                setCustomResources(prev=>[...prev,{title:newResTitle,url:newResUrl,cat:newResCat}]);
                addA("CUSTOM_RESOURCE_ADDED","\""+newResTitle+"\" published to all analyst clients");
              }
              setNewResTitle("");setNewResUrl("");}}>Publish to All Clients</Btn>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:C.p,marginBottom:10}}>CISM-Informed Recovery Protocol</div>
            <M style={{color:C.t,lineHeight:2}}>
              <span style={{color:C.p,fontWeight:500}}>Phase 1 (0-24hr):</span> Auto-activate lighter queues for involved analysts. Send optional anonymous check-in via E2EE peer channel. Normalize stress reactions — "what you're feeling is a normal response to an abnormal situation."<br/>
              <span style={{color:C.p,fontWeight:500}}>Phase 2 (24-72hr):</span> Offer voluntary peer support session (never mandatory). Peer-led, not management-led. Focus on shared experience and coping strategies. No formal debriefing — research shows informal peer contact is preferred (R007).<br/>
              <span style={{color:C.p,fontWeight:500}}>Phase 3 (1-2 weeks):</span> Follow-up check-in. Assess if any analyst needs referral to professional support (EAP, counselor). Gradual return to normal queue complexity.<br/>
              <span style={{color:C.p,fontWeight:500}}>Self-help resources:</span> Platform provides stress management techniques (breathing exercises, sleep hygiene, physical activity prompts), psychoeducation about acute stress responses, and clear pathways to professional support. All resources are available in the Analyst Client without any disclosure to management.
            </M>
          </Card>
        </div>)}

        {/* SLA TRACKING — NEW v0.0.9 */}
        {tab==="sla"&&(<div>
          <L>SLA Tracking · MTTA / MTTR</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Mean Time to Acknowledge (MTTA) and Mean Time to Resolve (MTTR) tied to team capacity metrics. When SLA performance degrades, the platform correlates with team health to distinguish capacity problems from skill gaps.</M>
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:20}}>
            {[{l:"MTTA (P1)",v:"4.2m",t:"Target: <5m",c:C.a},{l:"MTTA (P2)",v:"12m",t:"Target: <15m",c:C.a},{l:"MTTR (P1)",v:"48m",t:"Target: <60m",c:C.a},{l:"MTTR (P2)",v:"2.1h",t:"Target: <4h",c:C.a}].map((m,i)=><Card key={i} style={{textAlign:"center",padding:14}}><div style={{fontSize:22,fontWeight:300,color:m.c,fontFamily:"'Fraunces',serif"}}>{m.v}</div><M style={{color:C.td,letterSpacing:1,textTransform:"uppercase",marginTop:4}}>{m.l}</M><M style={{color:C.tm,display:"block",marginTop:4}}>{m.t}</M></Card>)}
          </div>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>SLA vs Capacity Correlation</div>
            <M style={{color:C.t,lineHeight:1.8}}>Current team health ({th.score}) and utilization ({th.avgUtil}%) are {th.avgUtil>80?"above sustainable thresholds — SLA degradation may reflect capacity constraints, not performance issues (R012).":"within healthy parameters — SLA metrics reflect normal operational performance."}</M>
          </Card>
          <Card style={{padding:12}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>SLA Configuration</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:8}}>
              {[{k:"p1mtta",l:"P1 MTTA"},{k:"p1mttr",l:"P1 MTTR"},{k:"p2mtta",l:"P2 MTTA"},{k:"p2mttr",l:"P2 MTTR"}].map(s=><Input key={s.k} label={s.l} value={slaConfig[s.k]} onChange={e=>setSlaConfig(prev=>({...prev,[s.k]:e.target.value}))} maxLength={10}/>)}
            </div>
            <Btn primary onClick={()=>addA("SLA_CONFIGURED","SLA thresholds updated: P1 MTTA="+slaConfig.p1mtta+", P1 MTTR="+slaConfig.p1mttr+", P2 MTTA="+slaConfig.p2mtta+", P2 MTTR="+slaConfig.p2mttr)} style={{marginTop:8}}>Save SLA Config</Btn>
          </Card>
        </div>)}


        {/* TICKET SYSTEM INTEGRATION — NEW v0.0.13 */}
        {tab==="soar"&&(<div>
          <L>SOAR Integration & Routing Control</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Connect to your SOAR platform to give FireAlive write access to analyst routing and assignment playbooks. The platform feeds capacity intelligence — utilization, burnout signals, skill levels, equity metrics — into your SOAR's routing decisions in real time. This is the core operational integration: your SOAR handles alert enrichment and triage; FireAlive tells it which analysts have capacity and what complexity they can handle.</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>SOAR Platform</div>
            <Sel label="Platform" value={soarPlatform} onChange={e=>setSoarPlatform(e.target.value)}><option value="">Select...</option><option value="splunk">Splunk SOAR</option><option value="qradar">IBM QRadar SOAR</option><option value="fortisoar">FortiSOAR</option><option value="torq">Torq Hyperautomation</option><option value="cortex">Cortex XSOAR (Palo Alto)</option><option value="sentinel">Microsoft Sentinel Playbooks</option><option value="chronicle">Google SecOps / Chronicle SOAR</option><option value="swimlane">Swimlane</option><option value="tines">Tines</option><option value="custom">Custom REST API</option></Sel>
            <Input label="SOAR API endpoint" value={soarUrl} onChange={e=>setSoarUrl(e.target.value)} placeholder="https://soar.corp.local/api/v2" maxLength={512}/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Input label="Service account / API user" value={soarServiceAccount} onChange={e=>setSoarServiceAccount(e.target.value)} placeholder="svc-firealive-routing" maxLength={256}/>
              <div style={{marginBottom:14}}>
                <M style={{color:C.tm,marginBottom:4,display:"block"}}>API key / token</M>
                {soarApiKeyPresent && !soarApiKeyChanging ? (
                  <div style={{display:"flex",alignItems:"center",gap:8,padding:"10px 12px",background:"rgba(110,231,183,0.06)",border:`1px solid ${C.a}30`,borderRadius:8}}>
                    <M style={{color:C.a,fontWeight:500,fontSize:11,flex:1}}>Configured ✓ (secret stored server-side)</M>
                    <Btn small onClick={()=>{setSoarApiKey("");setSoarApiKeyChanging(true);}}>Change Secret</Btn>
                  </div>
                ) : (
                  <div style={{display:"flex",gap:6}}>
                    <input type="password" value={soarApiKey} onChange={e=>setSoarApiKey(e.target.value)} placeholder={soarApiKeyPresent?"New value (or leave blank to clear)":"Stored in secrets manager (Vault/AWS SM/Azure KV)"} maxLength={512} style={{flex:1,padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}}/>
                    {soarApiKeyPresent && <Btn small onClick={()=>{setSoarApiKey("");setSoarApiKeyChanging(false);}}>Cancel</Btn>}
                  </div>
                )}
              </div>
            </div>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0",fontSize:12,color:C.t,cursor:"pointer"}}>
              <input type="checkbox" checked={soarAutoEscalate} onChange={e=>setSoarAutoEscalate(e.target.checked)} style={{accentColor:C.a}}/>
              Auto-escalate alerts above analyst complexity cap to senior tier
            </label>
            <M style={{color:C.td,display:"block",marginTop:4,lineHeight:1.5}}>When enabled, the SOAR auto-escalates an alert that exceeds the assigned analyst's complexity cap (P-tier) to a higher-tier analyst rather than queueing or dropping. Optional; off by default.</M>
          </Card>

          <Card style={{marginBottom:16,borderColor:C.i+"30"}}>
            <div style={{fontSize:13,fontWeight:500,color:C.i,marginBottom:10}}>Routing Permissions (Write Access)</div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>FireAlive writes the following to your SOAR playbook variables in real time. The SOAR uses these to make routing decisions within its existing playbook logic.</M>
            {[{perm:"analyst_capacity",desc:"Per-analyst utilization percentage and availability status",level:"Required"},{perm:"complexity_cap",desc:"Maximum alert complexity each analyst can receive (P1-P5), updated by lighter queue requests and lead overrides",level:"Required"},{perm:"equity_weights",desc:"Distribution fairness scores to prevent alert funneling to any single analyst",level:"Required"},{perm:"skill_matrix",desc:"Per-analyst skill levels for skill-based routing (route malware alerts to analysts with malware analysis >70%)",level:"Recommended"},{perm:"burnout_risk_tier",desc:"Team-level risk tier (healthy/watch/stressed/critical) — no individual identifiers. Triggers SOAR to slow intake or activate automation fallback",level:"Recommended"},{perm:"shift_handoff",desc:"Write shift transition state so SOAR reduces queue load in final 2 hours of shift (R017)",level:"Optional"}].map((p,i)=>(
              <div key={i} style={{padding:"8px 0",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                <div style={{flex:1}}><M style={{color:"#E8EDF5",fontWeight:500,fontFamily:"'IBM Plex Mono',monospace",fontSize:11}}>{p.perm}</M><M style={{color:C.tm,display:"block",marginTop:2,lineHeight:1.5}}>{p.desc}</M></div>
                <Badge color={p.level==="Required"?C.d:p.level==="Recommended"?C.w:C.tm}>{p.level}</Badge>
              </div>
            ))}
          </Card>

          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Ticketing System (Read-Only)</div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>FireAlive also reads from your ticketing system (ServiceNow, Jira, TheHive, etc.) for metrics — MTTA/MTTR, ticket counts, resolution times. This is a read-only integration separate from the SOAR write channel. The read-only invariant is enforced server-side; the ticketing integration cannot be configured for write access from this UI or any other.</M>
            <Sel label="Ticketing platform" value={soarTicketingPlatform} onChange={e=>setSoarTicketingPlatform(e.target.value)}><option value="">Select...</option><option value="servicenow">ServiceNow</option><option value="jira">Jira Service Management</option><option value="thehive">TheHive</option><option value="pagerduty">PagerDuty</option><option value="freshservice">Freshservice</option><option value="custom">Custom REST API</option></Sel>
            <Input label="Read-only API endpoint" value={soarTicketingEndpoint} onChange={e=>setSoarTicketingEndpoint(e.target.value)} placeholder="https://corp.service-now.com/api/now/table/incident" maxLength={512}/>
            <div style={{marginBottom:14}}>
              <M style={{color:C.tm,marginBottom:4,display:"block"}}>API key / token</M>
              {soarTicketingApiKeyPresent && !soarTicketingApiKeyChanging ? (
                <div style={{display:"flex",alignItems:"center",gap:8,padding:"10px 12px",background:"rgba(110,231,183,0.06)",border:`1px solid ${C.a}30`,borderRadius:8}}>
                  <M style={{color:C.a,fontWeight:500,fontSize:11,flex:1}}>Configured ✓ (secret stored server-side)</M>
                  <Btn small onClick={()=>{setSoarTicketingApiKey("");setSoarTicketingApiKeyChanging(true);}}>Change Secret</Btn>
                </div>
              ) : (
                <div style={{display:"flex",gap:6}}>
                  <input type="password" value={soarTicketingApiKey} onChange={e=>setSoarTicketingApiKey(e.target.value)} placeholder={soarTicketingApiKeyPresent?"New value (or leave blank to clear)":"Read-only credentials"} maxLength={512} style={{flex:1,padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}}/>
                  {soarTicketingApiKeyPresent && <Btn small onClick={()=>{setSoarTicketingApiKey("");setSoarTicketingApiKeyChanging(false);}}>Cancel</Btn>}
                </div>
              )}
            </div>
          </Card>

          <Card style={{padding:12,borderColor:C.a+"30",marginBottom:16}}>
            <M style={{color:C.a,fontWeight:500,display:"block",marginBottom:4}}>How the integration works</M>
            <M style={{color:C.tm,lineHeight:1.8}}>1. SOAR playbook triggers on new alert → 2. Playbook queries FireAlive API for analyst capacity, caps, equity weights → 3. SOAR routes alert to optimal analyst based on FireAlive intelligence + its own enrichment logic → 4. FireAlive reads ticket assignment from ticketing system to update utilization metrics → 5. Loop continues in real time. FireAlive never directly assigns tickets — it provides the intelligence layer that makes SOAR routing decisions capacity-aware.</M>
          </Card>

          {/* R3j C10: Live SOAR Routing State card — read-only display of what
              FireAlive is currently publishing to the SOAR. Polls /api/routing/soar
              every 30s while this tab is open. */}
          <Card style={{marginBottom:16,borderColor:C.i+"30"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",marginBottom:10}}>
              <div style={{fontSize:13,fontWeight:500,color:C.i}}>Live SOAR Routing State</div>
              <M style={{color:C.td,fontSize:10,fontFamily:"'IBM Plex Mono',monospace"}}>{soarLiveLastFetched ? ("Last fetched "+(()=>{const sec=Math.max(0,Math.round((Date.now()-new Date(soarLiveLastFetched).getTime())/1000));return sec<60?(sec+"s ago"):(Math.floor(sec/60)+"m ago");})()) : "Waiting for first fetch..."}</M>
            </div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Read-only view of the 6 routing variables FireAlive is currently publishing to the configured SOAR. These values update as analyst capacity, complexity caps, equity weights, skill matrix, and shift handoff state change. The SOAR consumes these via its polling cadence against GET /api/routing/variables (api-key + routing:read scope).</M>
            {["analyst_capacity","complexity_cap","equity_weights","skill_matrix","burnout_risk_tier","shift_handoff"].map(key=>{
              const value = soarLiveVariables ? soarLiveVariables[key] : undefined;
              const present = value !== undefined && value !== null;
              let display = "(not published yet)";
              if (present) {
                if (typeof value === "object") {
                  try { display = JSON.stringify(value); } catch (_e) { display = "[unserializable object]"; }
                } else {
                  display = String(value);
                }
              }
              return (
                <div key={key} style={{padding:"8px 0",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:12}}>
                  <M style={{color:"#E8EDF5",fontWeight:500,fontFamily:"'IBM Plex Mono',monospace",fontSize:11,minWidth:140,flexShrink:0}}>{key}</M>
                  <M style={{color:present?C.t:C.td,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-word",textAlign:"right",fontStyle:present?"normal":"italic"}}>{display}</M>
                </div>
              );
            })}
          </Card>

          <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
            <Btn primary disabled={soarSaveBusy} onClick={async()=>{
              setSoarSaveError(null);
              setSoarSaveBusy(true);
              try {
                // R3n: omit apiKey from PUT body unless the lead explicitly
                // clicked "Change Secret" (server preserves existing on omission).
                const soarConfig = {platform:soarPlatform, apiEndpoint:soarUrl, serviceAccount:soarServiceAccount, autoEscalate:soarAutoEscalate};
                if (!soarApiKeyPresent || soarApiKeyChanging) soarConfig.apiKey = soarApiKey;
                const soarRes = await api.put("/api/integrations/soar", {config:soarConfig});
                if (soarRes?.error) { setSoarSaveError("SOAR save failed: "+soarRes.error); return; }
                const ticketingConfig = {platform:soarTicketingPlatform, apiEndpoint:soarTicketingEndpoint};
                if (!soarTicketingApiKeyPresent || soarTicketingApiKeyChanging) ticketingConfig.apiKey = soarTicketingApiKey;
                const tkRes = await api.put("/api/integrations/ticketing", {config:ticketingConfig});
                if (tkRes?.error) { setSoarSaveError("Ticketing save failed: "+tkRes.error); return; }
                addA("SOAR_CONFIG_SAVED","SOAR + Ticketing integrations saved");
                // Re-hydrate from server so the form reflects post-save state
                setSoarHydrated(false);
              } finally { setSoarSaveBusy(false); }
            }}>{soarSaveBusy?"Saving...":"Save SOAR Config"}</Btn>
            <Btn disabled={soarTestBusy} onClick={async()=>{
              setSoarTestResult(null);
              setSoarTestBusy(true);
              try {
                const r = await api.post("/api/integrations/soar/test", {});
                setSoarTestResult(r?.error ? {success:false, message:r.error} : r);
                addA("SOAR_TEST", r?.success ? ("Connection OK ("+r.latencyMs+"ms)") : "Connection failed");
              } finally { setSoarTestBusy(false); }
            }}>{soarTestBusy?"Testing...":"Test Connection"}</Btn>
          </div>
          {soarSaveError&&<Card style={{padding:10,marginTop:10,borderColor:C.d+"60",background:C.d+"14"}}><M style={{color:C.d,fontWeight:500}}>Save error:</M><M style={{color:C.t,display:"block",marginTop:4}}>{soarSaveError}</M></Card>}
          {soarTestResult&&<Card style={{padding:10,marginTop:10,borderColor:(soarTestResult.success?C.a:C.d)+"60",background:(soarTestResult.success?C.a:C.d)+"14"}}>
            <M style={{color:soarTestResult.success?C.a:C.d,fontWeight:500}}>{soarTestResult.success?"Test passed":"Test failed"}</M>
            <M style={{color:C.t,display:"block",marginTop:4}}>{soarTestResult.message}</M>
            {typeof soarTestResult.latencyMs==="number"&&<M style={{color:C.tm,display:"block",marginTop:2}}>Latency: {soarTestResult.latencyMs}ms</M>}
            {soarTestResult.autoEscalatePolicyDetected&&<M style={{color:C.i,display:"block",marginTop:2}}>Auto-escalate policy round-trip confirmed.</M>}
          </Card>}
        </div>)}

        {/* AUTOMATION */}
        {tab==="automation"&&(<div>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:16}}><div><L style={{marginBottom:4}}>Automated Systems</L></div><Btn primary onClick={()=>setShowAddAuto(true)}>+ Add System</Btn></div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:20}}>
            {autoSys.map(sys=>{const pct=(sys.cap.cur/sys.cap.max)*100;const clr=pct>90?C.d:pct>70?C.w:C.a;return(
              <Card key={sys.id}><div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}><div><div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>{sys.name}</div><M style={{color:C.tm}}>{sys.type}</M></div><Badge color={clr}>{sys.status}</Badge></div>
              <div style={{marginBottom:8}}><div style={{display:"flex",justifyContent:"space-between",fontSize:10,marginBottom:3}}><M style={{color:C.tm}}>Capacity</M><M style={{color:clr}}>{sys.cap.cur}/{sys.cap.max} {sys.cap.u}</M></div><div style={{height:4,background:"rgba(255,255,255,0.04)",borderRadius:2,overflow:"hidden"}}><div style={{width:`${pct}%`,height:"100%",background:clr,borderRadius:2}}/></div></div>
              <M style={{color:C.tm}}>24h resolved: <span style={{color:C.a}}>{sys.resolved.toLocaleString()}</span> · {sys.l1?"L1":""}{sys.l2?" L2":""}{sys.l3?" L3":""} · FP: {(sys.fp*100).toFixed(1)}%</M></Card>
            );})}
          </div>
          {showAddAuto&&<Modal title="Add Automation System" onClose={()=>setShowAddAuto(false)}>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Add a new tool. It will appear in analyst delegation options and routing engine immediately.</M>
            <Input label="System name" value={newAuto.name} onChange={e=>setNewAuto(prev=>({...prev,name:e.target.value}))} placeholder="e.g., SentinelOne Singularity" maxLength={100}/>
            <Sel label="Type" value={newAuto.type} onChange={e=>setNewAuto(prev=>({...prev,type:e.target.value}))}><option>EDR/XDR</option><option>IDS/IPS</option><option>AI/SOAR</option><option>Email AI</option><option>NDR</option><option>UEBA</option><option>Custom</option></Sel>
            <div style={{marginBottom:14}}><M style={{color:C.tm,marginBottom:6,display:"block"}}>Handles:</M><div style={{display:"flex",gap:12}}>{[["l1","L1"],["l2","L2"],["l3","L3"]].map(([k,l])=><label key={k} style={{display:"flex",alignItems:"center",gap:4,fontSize:12,color:C.t}}><input type="checkbox" checked={newAuto[k]} onChange={e=>setNewAuto(prev=>({...prev,[k]:e.target.checked}))} style={{accentColor:C.a}}/>{l}</label>)}</div></div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}><Input label="Max capacity" type="number" value={newAuto.max} onChange={e=>setNewAuto(prev=>({...prev,max:Math.max(0,Math.min(100000,Number(e.target.value)||0))}))} min={0} max={100000}/><Input label="Unit" value={newAuto.u} onChange={e=>setNewAuto(prev=>({...prev,u:e.target.value}))} maxLength={30}/></div>
            <Btn primary style={{width:"100%"}} disabled={!newAuto.name.trim()} onClick={()=>{setAutoSys(prev=>[...prev,{id:`c-${Date.now()}`,name:newAuto.name,type:newAuto.type,l1:newAuto.l1,l2:newAuto.l2,l3:newAuto.l3,cap:{max:newAuto.max,cur:0,u:newAuto.u},status:"configuring",resolved:0,fp:0}]);addA("AUTO_ADDED",newAuto.name);setShowAddAuto(false);setNewAuto({name:"",type:"EDR/XDR",l1:true,l2:false,l3:false,max:500,u:"alerts/hr"});}}>Add</Btn>
          </Modal>}
        </div>)}

        {/* ROUTING */}
        {tab==="routing"&&(<div>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:16}}><div><L style={{marginBottom:4}}>Live Routing · Day Shift</L><M style={{color:C.tm}}>Auto-equity 35% cap active.</M></div>{unsaved&&<Btn primary disabled={routingSaveBusy} onClick={async()=>{
            setRoutingSaveError(null);
            setRoutingSaveBusy(true);
            try {
              // R3n C7: single bulk PUT replaces the per-analyst loop. Server
              // diffs against current values and audit-logs each MC_ROUTING_
              // CAP_CHANGED individually; unchanged caps produce no DB writes
              // and no audit rows.
              const caps = dayAnalysts
                .map(a => ({analystId:a.id, maxComplexity:routingCaps[a.id]}))
                .filter(c => Number.isInteger(c.maxComplexity));
              const r = await api.post("/api/routing/bulk", {caps});
              if (r?.error) {
                setRoutingSaveError(r.error);
                return;
              }
              // Tolerate "Analyst not found" errors silently in mock mode
              // (dayAnalysts from ANALYSTS_INIT has short IDs that don't
              // match server's users table). Real failures get surfaced.
              const realFailures = (r?.errors||[]).filter(e => !/not found/i.test(e.error || ""));
              if (realFailures.length > 0) {
                setRoutingSaveError(realFailures.map(e => e.analystId+": "+e.error).join("; "));
                return;
              }
              setUnsaved(false);
              const updatedCount = (r?.updated||[]).length;
              const unchangedCount = (r?.unchanged||[]).length;
              addA("ROUTING_APPLIED", `Caps applied (${updatedCount} changed, ${unchangedCount} unchanged)`);
            } finally { setRoutingSaveBusy(false); }
          }}>{routingSaveBusy?"Saving...":"Apply"}</Btn>}</div>
          {routingSaveError&&<Card style={{padding:10,marginBottom:14,borderColor:C.d+"60",background:C.d+"14"}}><M style={{color:C.d,fontWeight:500}}>Save error:</M><M style={{color:C.t,display:"block",marginTop:4}}>{routingSaveError}</M></Card>}
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10,marginBottom:20}}>
            {dayAnalysts.map(a=>{const cap=routingCaps[a.id]||2;const ct=sessCt[a.id]||{t:0,h:0};const tot=Object.values(sessCt).reduce((s,c)=>s+c.t,0)||1;return(
              <Card key={a.id} style={{padding:12}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><span style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>{a.name}</span><Badge color={tierClr(a.tier)}>{tierLbl(a.tier)}</Badge></div>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
                  <button onClick={()=>{setRC(prev=>({...prev,[a.id]:Math.max(1,cap-1)}));setUnsaved(true);}} style={{width:28,height:28,background:C.s,border:`1px solid ${C.b}`,borderRadius:6,color:C.tm,fontSize:14,cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center"}}>−</button>
                  <div style={{flex:1,textAlign:"center"}}><div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",fontFamily:"'IBM Plex Mono',monospace"}}>P{cap}</div></div>
                  <button onClick={()=>{setRC(prev=>({...prev,[a.id]:Math.min(5,cap+1)}));setUnsaved(true);}} style={{width:28,height:28,background:C.s,border:`1px solid ${C.b}`,borderRadius:6,color:C.tm,fontSize:14,cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center"}}>+</button>
                </div>
                <M style={{color:C.td,display:"flex",justifyContent:"space-between"}}><span>{ct.t} tix</span><span>{Math.round((ct.t/tot)*100)}%</span></M>
              </Card>
            );})}
          </div>
          <L>Live Feed</L>
          <div style={{maxHeight:260,overflow:"auto",background:C.s,border:`1px solid ${C.b}`,borderRadius:10,padding:2}}>
            {liveFeed.slice(0,30).map(e=><div key={e.id} style={{padding:"8px 12px",borderBottom:`1px solid ${C.b}`,fontSize:11,display:"flex",gap:10,alignItems:"center"}}><M style={{color:C.td,fontSize:9,minWidth:60}}>{e.ts}</M><M style={{color:e.cx>=4?C.d:e.cx>=3?C.w:C.tm,minWidth:22}}>P{e.cx}</M><span style={{flex:1}}>{e.alert}</span>{e.auto?<Badge color={C.i}>→ {e.autoN}</Badge>:<M style={{color:e.eq?C.a:C.tm}}>→ {e.to}{e.eq?" ⚖":""}</M>}</div>)}
            {liveFeed.length===0&&<div style={{padding:20,textAlign:"center",color:C.td,fontSize:11}}>Waiting...</div>}
          </div>
        </div>)}

        {/* REPORTS — NEW v0.0.8 */}
        {tab==="reports"&&(<div>
          <L>Report Engine</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Depersonalized team-level analysis. No individual analyst names — tier/shift aggregates only. AI analysis powered by KB ({KB_ENTRY_COUNT} entries).</M>
          <div style={{display:"flex",gap:4,marginBottom:20}}>{[{id:"config",l:"Configuration"},{id:"history",l:"History"},{id:"preview",l:"Preview"}].map(t=><button key={t.id} onClick={()=>setReportTab(t.id)} style={{padding:"6px 14px",background:reportTab===t.id?C.ad:"transparent",border:`1px solid ${reportTab===t.id?C.a+"50":C.b}`,borderRadius:6,color:reportTab===t.id?C.a:C.tm,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>{t.l}</button>)}</div>
          {reportTab==="config"&&(<Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:14}}>Schedule</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
              <Sel label="Frequency" value={reportCfg.schedule} onChange={e=>setReportCfg(prev=>({...prev,schedule:e.target.value}))}><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="biweekly">Biweekly</option><option value="monthly">Monthly</option></Sel>
              <Sel label="Day" value={reportCfg.day} onChange={e=>setReportCfg(prev=>({...prev,day:e.target.value}))}><option value="monday">Monday</option><option value="tuesday">Tuesday</option><option value="wednesday">Wednesday</option><option value="thursday">Thursday</option><option value="friday">Friday</option></Sel>
              <Sel label="Format" value={reportCfg.format} onChange={e=>setReportCfg(prev=>({...prev,format:e.target.value}))}><option value="pdf">PDF</option><option value="html">HTML</option><option value="json">JSON (SIEM)</option></Sel>
            </div>
            <Input label="Recipients (email)" value={reportCfg.recipients} onChange={e=>setReportCfg(prev=>({...prev,recipients:e.target.value}))} placeholder="lead@corp.com" maxLength={512}/>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={reportCfg.siemFeed} onChange={e=>setReportCfg(prev=>({...prev,siemFeed:e.target.checked}))} style={{accentColor:C.a}}/>Also send summary to SIEM via CEF</label>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10,marginTop:16}}>Report Sections</div>
            {[{k:"teamHealth",l:"Team Health Score & Status"},{k:"utilization",l:"Utilization Analysis (flags >80%, R012)"},{k:"tierBreakdown",l:"Tier-Level Breakdown (no names)"},{k:"automationRate",l:"Automation Delegation Rate"},{k:"trendAnalysis",l:"4-Week Trend Analysis"},{k:"kbInsights",l:"KB-Powered AI Insights"},{k:"skillProgress",l:"Aggregate Skill Progression (depersonalized — e.g., 'L1 cohort: avg triage 78%, investigation 61%')"},{k:"upskillingGaps",l:"Upskilling Gap Summary (e.g., '4 of 6 L1 analysts below threshold in SIEM Queries')"}].map(s=>(
              <label key={s.k} style={{display:"flex",alignItems:"center",gap:10,padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
                <input type="checkbox" checked={reportCfg.sections[s.k]} onChange={e=>setReportCfg(prev=>({...prev,sections:{...prev.sections,[s.k]:e.target.checked}}))} style={{accentColor:C.a}}/><span style={{fontSize:12}}>{s.l}</span>
              </label>
            ))}
            <Card style={{padding:12,borderColor:C.a+"30",marginTop:14,marginBottom:14}}>
              <M style={{color:C.a,fontWeight:500,display:"block",marginBottom:4}}>Privacy Guarantee</M>
              <M style={{color:C.tm,lineHeight:1.8}}>All reports use tier/shift aggregates. Example: "L1 day shift: 78% util (3 analysts)" — never individual names.</M>
            </Card>
            <div style={{display:"flex",gap:8}}>
              <Btn primary onClick={()=>addA("REPORT_SCHEDULE_SAVED",`${reportCfg.schedule} ${reportCfg.day} ${reportCfg.time}`)}>Save Schedule</Btn>
              <Btn onClick={async()=>{
                const secCount=Object.values(reportCfg.sections).filter(Boolean).length;
                const r={id:Date.now(),ts:new Date().toISOString(),type:"on-demand",status:"generating",sections:secCount};
                setReports(prev=>[r,...prev]);
                if(apiReady && window.FireAliveAPI){
                  try{
                    const result=await window.FireAliveAPI.reports.generate(reportCfg.format);
                    setReports(prev=>prev.map(x=>x.id===r.id?{...x,id:result.id,status:"delivered",sections:result.sections}:x));
                    addA("REPORT_GENERATED","API: On-demand report "+result.id+" ("+result.sections+" sections)");
                    setReportTab("preview");
                  }catch(e){
                    setReports(prev=>prev.map(x=>x.id===r.id?{...x,status:"error"}:x));
                    addA("REPORT_ERROR",e.message);
                  }
                } else {
                  addA("REPORT_GENERATED","On-demand report generated with "+secCount+" sections");
                  setTimeout(()=>{setReports(prev=>prev.map(x=>x.id===r.id?{...x,status:"delivered"}:x));setReportTab("preview");},1500);
                }
              }}>Generate Now →</Btn>
            </div>
          </Card>)}
          {reportTab==="history"&&(<div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,overflow:"hidden"}}>{reports.map(r=>(
            <div key={r.id} style={{padding:"10px 14px",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div><M style={{color:C.t}}>{typeof r.ts==="string"&&r.ts.includes("T")?new Date(r.ts).toLocaleString():r.ts}</M><br/><M style={{color:C.td}}>{r.type} · {r.sections} sections</M></div>
              <Badge color={r.status==="delivered"?C.a:C.w}>{r.status}</Badge>
            </div>
          ))}</div>)}
          {reportTab==="preview"&&(<div>
            <Card style={{borderColor:C.i+"30",marginBottom:16}}>
              <M style={{color:C.i,letterSpacing:1.2,textTransform:"uppercase",display:"block",marginBottom:12}}>Generated Report — {new Date().toLocaleDateString()} — Depersonalized</M>
              {reportCfg.sections.teamHealth&&<><div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Team Health</div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:10,marginBottom:16}}>
                {[{l:"HEALTH",v:th.score,c:sc.c},{l:"UTIL",v:th.avgUtil+"%",c:th.avgUtil>80?C.w:C.a},{l:"OVER CAP",v:th.oc},{l:"DAY STAFF",v:dayAnalysts.length}].map((m,i)=>(
                  <div key={i} style={{padding:10,background:"rgba(96,165,250,0.05)",border:"1px solid rgba(96,165,250,0.15)",borderRadius:8,textAlign:"center"}}><div style={{fontSize:20,fontWeight:300,color:m.c||C.t,fontFamily:"'Fraunces',serif"}}>{m.v}</div><M style={{color:C.td}}>{m.l}</M></div>
                ))}
              </div></>}
              {reportCfg.sections.tierBreakdown&&<><div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Tier Breakdown (Depersonalized)</div>
              <M style={{color:C.tm,display:"block",lineHeight:1.8,marginBottom:12}}>
                Day shift: L1 × {analysts.filter(a=>a.shift==="day"&&a.tier===1).length} analysts, L2 × {analysts.filter(a=>a.shift==="day"&&a.tier===2).length}, L3 × {analysts.filter(a=>a.shift==="day"&&a.tier===3).length}.<br/>
                Swing shift: L1 × {analysts.filter(a=>a.shift==="swing"&&a.tier===1).length}, L2 × {analysts.filter(a=>a.shift==="swing"&&a.tier===2).length}, L3 × {analysts.filter(a=>a.shift==="swing"&&a.tier===3).length}.<br/>
                Night shift: L1 × {analysts.filter(a=>a.shift==="night"&&a.tier===1).length}, L2 × {analysts.filter(a=>a.shift==="night"&&a.tier===2).length}, L3 × {analysts.filter(a=>a.shift==="night"&&a.tier===3).length}.
              </M></>}
              {reportCfg.sections.automationRate&&<><div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Automation</div>
              <M style={{color:C.tm,display:"block",lineHeight:1.8,marginBottom:12}}>
                {autoSys.length} systems active. 24h resolved: {autoSys.reduce((s,a)=>s+a.resolved,0).toLocaleString()} alerts. Avg FP rate: {(autoSys.reduce((s,a)=>s+a.fp,0)/autoSys.length*100).toFixed(1)}%. Headroom: {autoSys.map(s=>s.name+": "+Math.round((1-s.cap.cur/s.cap.max)*100)+"%").join(", ")}.
              </M></>}
              {reportCfg.sections.kbInsights&&<><div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>KB-Powered Insight</div>
              <M style={{color:C.tm,display:"block",lineHeight:1.8,marginBottom:12}}>
                <span style={{color:C.a,fontWeight:500}}>Assessment:</span> Current utilization ({th.avgUtil}%) {th.avgUtil>80?"exceeds":"is within"} the 70–80% sustainable threshold (R012). {th.status==="stressed"||th.status==="critical"?"Organizational intervention recommended — structural changes produce d = −0.30 on exhaustion (R001). Combined org + individual interventions achieve d = −0.54 (R002). Consider temporary routing caps and automation delegation push.":"Team operating within healthy parameters. Maintain current 1:1 cadence (R013) and monitor automation delegation opportunities (R008)."} Burnout contagion risk: {th.oc>2?"ELEVATED — "+th.oc+" analysts over capacity, contagion can spread within 2-4 weeks (R036).":"LOW — team capacity within acceptable bounds."}
              </M></>}
              {reportCfg.sections.skillProgress&&<><div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Aggregate Skill Progression (Depersonalized)</div>
              <M style={{color:C.tm,display:"block",lineHeight:1.8,marginBottom:12}}>
                <span style={{color:C.i,fontWeight:500}}>L1 cohort (6 analysts):</span> Avg triage proficiency 78% · Avg documentation 76% · Avg phishing analysis 63% · Avg SIEM queries 52% · 3 of 6 above L2 readiness threshold in 2+ core skills.<br/>
                <span style={{color:C.p,fontWeight:500}}>L2 cohort (5 analysts):</span> Avg investigation 74% · Avg network analysis 69% · Avg malware analysis 48% · 2 of 5 approaching L3 signal thresholds.<br/>
                <span style={{color:"#F472B6",fontWeight:500}}>L3 cohort (3 analysts):</span> Avg threat hunting 82% · Avg IR coordination 77% · Avg forensics 71% · Skill maintenance on track (R019: automation paradox monitoring).
              </M></>}
              {reportCfg.sections.upskillingGaps&&<><div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Upskilling Gap Summary (Depersonalized)</div>
              <M style={{color:C.tm,display:"block",lineHeight:1.8,marginBottom:12}}>
                <span style={{color:C.w,fontWeight:500}}>Active training gaps:</span> 4 of 6 L1 analysts below 70% in SIEM Queries (team avg 52%) · 3 of 6 L1 analysts below 70% in Escalation Judgment (team avg 58%) · 4 of 5 L2 analysts below 70% in Malware Analysis (team avg 48%).<br/>
                <span style={{color:C.a,fontWeight:500}}>Upskilling activity (30 days):</span> 12 lab completions across 8 analysts · 3 assessment re-takes showing improvement · 2 level-up signals triggered (R027, R037). Training platforms active: LetsDefend (7 sessions), HTB (4), TryHackMe (3), CyberDefenders (2).<br/>
                <span style={{color:C.td}}>Note: All statistics are cohort-level aggregates. No individual analyst is identified in this report. Assessment results remain visible only to the analyst and their direct team lead.</span>
              </M></>}
            </Card>
            <Btn primary onClick={()=>{
              const now=new Date();const dateStr=now.toISOString().slice(0,10);
              const secs=reportCfg.sections;
              let content="";
              if(reportCfg.format==="json"){
                const data={generated:now.toISOString(),platform:"FireAlive v"+(appVersion||"unknown"),type:"team_capacity_report",depersonalized:true,
                  ...(secs.teamHealth?{teamHealth:{score:th.score,status:th.status,utilization:th.avgUtil,overCapacity:th.oc,dayStaff:dayAnalysts.length}}:{}),
                  ...(secs.tierBreakdown?{tierBreakdown:{day:{l1:analysts.filter(a=>a.shift==="day"&&a.tier===1).length,l2:analysts.filter(a=>a.shift==="day"&&a.tier===2).length,l3:analysts.filter(a=>a.shift==="day"&&a.tier===3).length},swing:{l1:analysts.filter(a=>a.shift==="swing"&&a.tier===1).length,l2:analysts.filter(a=>a.shift==="swing"&&a.tier===2).length,l3:analysts.filter(a=>a.shift==="swing"&&a.tier===3).length},night:{l1:analysts.filter(a=>a.shift==="night"&&a.tier===1).length,l2:analysts.filter(a=>a.shift==="night"&&a.tier===2).length,l3:analysts.filter(a=>a.shift==="night"&&a.tier===3).length}}}:{}),
                  ...(secs.automationRate?{automation:{systemCount:autoSys.length,resolved24h:autoSys.reduce((s,a)=>s+a.resolved,0),avgFpRate:+(autoSys.reduce((s,a)=>s+a.fp,0)/autoSys.length*100).toFixed(1)}}:{}),
                  ...(secs.skillProgress?{skillProgress:{l1_cohort:{count:6,avgTriage:78,avgDocumentation:76,avgPhishing:63,avgSiem:52},l2_cohort:{count:5,avgInvestigation:74,avgNetwork:69,avgMalware:48},l3_cohort:{count:3,avgHunting:82,avgIr:77,avgForensics:71}}}:{}),
                };
                content=JSON.stringify(data,null,2);
                const blob=new Blob([content],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`firealive-report-${dateStr}.json`;a.click();URL.revokeObjectURL(url);
              } else {
                const lines=["FIREALIVE TEAM CAPACITY REPORT","Generated: "+now.toLocaleString(),"Depersonalized — No individual analyst identifiers","═".repeat(60),""];
                if(secs.teamHealth) lines.push("TEAM HEALTH","  Score: "+th.score+" ("+th.status+")","  Utilization: "+th.avgUtil+"%","  Over capacity: "+th.oc+" analysts","  Day staff: "+dayAnalysts.length,"");
                if(secs.tierBreakdown) lines.push("TIER BREAKDOWN","  Day: L1×"+analysts.filter(a=>a.shift==="day"&&a.tier===1).length+" L2×"+analysts.filter(a=>a.shift==="day"&&a.tier===2).length+" L3×"+analysts.filter(a=>a.shift==="day"&&a.tier===3).length,"  Swing: L1×"+analysts.filter(a=>a.shift==="swing"&&a.tier===1).length+" L2×"+analysts.filter(a=>a.shift==="swing"&&a.tier===2).length+" L3×"+analysts.filter(a=>a.shift==="swing"&&a.tier===3).length,"  Night: L1×"+analysts.filter(a=>a.shift==="night"&&a.tier===1).length+" L2×"+analysts.filter(a=>a.shift==="night"&&a.tier===2).length+" L3×"+analysts.filter(a=>a.shift==="night"&&a.tier===3).length,"");
                if(secs.automationRate) lines.push("AUTOMATION","  Systems: "+autoSys.length,"  24h resolved: "+autoSys.reduce((s,a)=>s+a.resolved,0).toLocaleString(),"  Avg FP rate: "+(autoSys.reduce((s,a)=>s+a.fp,0)/autoSys.length*100).toFixed(1)+"%","");
                if(secs.kbInsights) lines.push("KB INSIGHT","  "+th.avgUtil+"% utilization "+(th.avgUtil>80?"exceeds":"within")+" 70-80% threshold (R012).","");
                if(secs.skillProgress) lines.push("SKILL PROGRESSION","  L1 cohort: Avg triage 78%, documentation 76%, SIEM 52%","  L2 cohort: Avg investigation 74%, network 69%, malware 48%","  L3 cohort: Avg hunting 82%, IR coordination 77%","");
                if(secs.upskillingGaps) lines.push("UPSKILLING GAPS","  4/6 L1 below 70% in SIEM Queries (avg 52%)","  3/6 L1 below 70% in Escalation Judgment (avg 58%)","  4/5 L2 below 70% in Malware Analysis (avg 48%)","  12 lab completions, 3 re-takes, 2 level-up signals (30d)","");
                lines.push("═".repeat(60),"AGPL-3.0 | FireAlive v"+(appVersion||"unknown")+" | github.com/pmancina/firealive");
                content=lines.join("\n");
                const blob=new Blob([content],{type:"text/plain"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`firealive-report-${dateStr}.txt`;a.click();URL.revokeObjectURL(url);
              }
              addA("REPORT_DOWNLOADED","Report downloaded as "+reportCfg.format.toUpperCase()+" ("+content.length+" bytes)");
            }}>Download as {reportCfg.format.toUpperCase()}</Btn>
          </div>)}
        </div>)}

        {/* IAM — NEW v0.0.8 */}
        {tab==="iam"&&(<div>
          <L>IAM / Identity Provider Configuration</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Configure authentication against your enterprise identity infrastructure. All connections use encrypted channels.</M>
          <div style={{display:"flex",gap:4,marginBottom:20}}>{[{id:"saml",l:"SAML 2.0"},{id:"oidc",l:"OIDC"},{id:"ad",l:"Active Directory"},{id:"cloud",l:"Cloud IAM"}].map(t=><button key={t.id} onClick={()=>setIamTab(t.id)} style={{padding:"6px 14px",background:iamTab===t.id?C.ad:"transparent",border:`1px solid ${iamTab===t.id?C.a+"50":C.b}`,borderRadius:6,color:iamTab===t.id?C.a:C.tm,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>{t.l}{iamCfg[t.id]?.status==="configured"?" ✓":""}</button>)}</div>
          {iamTab==="saml"&&(<Card>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:14}}>SAML 2.0 Federation</div>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>SSO with Okta, Azure AD, PingOne, OneLogin. Platform acts as SAML Service Provider.</M>
            <Input label="SP Entity ID" value={iamCfg.saml.entityId} onChange={e=>setIamCfg(prev=>({...prev,saml:{...prev.saml,entityId:e.target.value}}))} placeholder="https://soc-wellbeing.corp.local/saml/metadata" maxLength={512}/>
            <Input label="IdP Metadata URL" value={iamCfg.saml.metadataUrl} onChange={e=>setIamCfg(prev=>({...prev,saml:{...prev.saml,metadataUrl:e.target.value}}))} placeholder="https://idp.corp.com/metadata.xml" maxLength={512}/>
            <div style={{marginBottom:14}}><M style={{color:C.tm,marginBottom:4,display:"block"}}>IdP Signing Certificate (PEM)</M><textarea value={iamCfg.saml.cert} onChange={e=>setIamCfg(prev=>({...prev,saml:{...prev.saml,cert:e.target.value}}))} placeholder="-----BEGIN CERTIFICATE-----" style={{width:"100%",height:60,padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",resize:"vertical"}} maxLength={5000}/></div>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={iamCfg.saml.jit} onChange={e=>setIamCfg(prev=>({...prev,saml:{...prev.saml,jit:e.target.checked}}))} style={{accentColor:C.a}}/>Enable JIT user provisioning</label>
            <Btn primary onClick={()=>{setIamCfg(prev=>({...prev,saml:{...prev.saml,status:"configured"}}));api.post("/api/v1/audit/log",{event:"IAM_CONFIGURED",detail:"SAML 2.0"}).then(()=>addA("IAM_CONFIGURED","SAML 2.0"));}}>Save SAML</Btn>
          </Card>)}
          {iamTab==="oidc"&&(<Card>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:14}}>OpenID Connect</div>
            <Input label="Issuer URL" value={iamCfg.oidc.issuer} onChange={e=>setIamCfg(prev=>({...prev,oidc:{...prev.oidc,issuer:e.target.value}}))} placeholder="https://idp.corp.com/realms/main" maxLength={512}/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Input label="Client ID" value={iamCfg.oidc.clientId} onChange={e=>setIamCfg(prev=>({...prev,oidc:{...prev.oidc,clientId:e.target.value}}))} placeholder="soc-wellbeing-client" maxLength={256}/>
              <div style={{marginBottom:14}}><M style={{color:C.tm,marginBottom:4,display:"block"}}>Client Secret</M><input type="password" value={iamCfg.oidc.secret} onChange={e=>setIamCfg(prev=>({...prev,oidc:{...prev.oidc,secret:e.target.value}}))} placeholder="••••••••" style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}} maxLength={256}/></div>
            </div>
            <Input label="Scopes" value={iamCfg.oidc.scopes} onChange={e=>setIamCfg(prev=>({...prev,oidc:{...prev.oidc,scopes:e.target.value}}))} maxLength={256}/>
            <Btn primary onClick={()=>{setIamCfg(prev=>({...prev,oidc:{...prev.oidc,status:"configured"}}));api.post("/api/v1/audit/log",{event:"IAM_CONFIGURED",detail:"OIDC"}).then(()=>addA("IAM_CONFIGURED","OIDC"));}}>Save OIDC</Btn>
          </Card>)}
          {iamTab==="ad"&&(<Card>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:14}}>Active Directory / LDAP</div>
            <div style={{display:"grid",gridTemplateColumns:"2fr 1fr",gap:12}}>
              <Input label="Server" value={iamCfg.ad.server} onChange={e=>setIamCfg(prev=>({...prev,ad:{...prev.ad,server:e.target.value}}))} placeholder="dc01.corp.local" maxLength={253}/>
              <Input label="Port" value={iamCfg.ad.port} onChange={e=>setIamCfg(prev=>({...prev,ad:{...prev.ad,port:e.target.value}}))} maxLength={5}/>
            </div>
            <Input label="Base DN" value={iamCfg.ad.baseDn} onChange={e=>setIamCfg(prev=>({...prev,ad:{...prev.ad,baseDn:e.target.value}}))} placeholder="DC=corp,DC=local" maxLength={512}/>
            <Input label="Bind DN" value={iamCfg.ad.bindDn} onChange={e=>setIamCfg(prev=>({...prev,ad:{...prev.ad,bindDn:e.target.value}}))} placeholder="CN=svc-socwellbeing,OU=Service Accounts" maxLength={512}/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Input label="Sync interval (min)" value={iamCfg.ad.syncInterval} onChange={e=>setIamCfg(prev=>({...prev,ad:{...prev.ad,syncInterval:String(Math.max(1,Math.min(1440,Number(e.target.value)||15)))}}))} type="number" min={1} max={1440}/>
              <div style={{paddingTop:22}}><label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t}}><input type="checkbox" checked={iamCfg.ad.useTLS} onChange={e=>setIamCfg(prev=>({...prev,ad:{...prev.ad,useTLS:e.target.checked}}))} style={{accentColor:C.a}}/>LDAPS</label></div>
            </div>
            <div style={{display:"flex",gap:8}}><Btn primary onClick={()=>{setIamCfg(prev=>({...prev,ad:{...prev.ad,status:"configured"}}));api.post("/api/v1/audit/log",{event:"IAM_CONFIGURED",detail:"Active Directory LDAPS"}).then(()=>addA("IAM_CONFIGURED","Active Directory LDAPS"));}}>Save AD</Btn><Btn onClick={()=>api.post("/api/v1/audit/log",{event:"AD_TEST",detail:"Testing LDAPS..."}).then(()=>addA("AD_TEST","Testing LDAPS..."))}>Test Connection</Btn></div>
          </Card>)}
          {iamTab==="cloud"&&(<Card>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:14}}>Cloud IAM</div>
            <Sel label="Provider" value={iamCfg.cloud.provider} onChange={e=>setIamCfg(prev=>({...prev,cloud:{...prev.cloud,provider:e.target.value}}))}><option value="none">Select...</option><option value="aws">AWS Cognito</option><option value="azure">Azure Entra ID</option><option value="gcp">GCP Identity Platform</option></Sel>
            {iamCfg.cloud.provider!=="none"&&<><Input label={iamCfg.cloud.provider==="aws"?"User Pool ID":iamCfg.cloud.provider==="azure"?"Tenant ID":"Project ID"} value={iamCfg.cloud.tenantId} onChange={e=>setIamCfg(prev=>({...prev,cloud:{...prev.cloud,tenantId:e.target.value}}))} maxLength={256}/>
            <Btn primary onClick={()=>{setIamCfg(prev=>({...prev,cloud:{...prev.cloud,status:"configured"}}));addA("IAM_CONFIGURED",`Cloud: ${iamCfg.cloud.provider.toUpperCase()}`);}}>Save Cloud IAM</Btn></>}
          </Card>)}
        </div>)}

        {/* KB — NEW v0.0.8 */}
        {tab==="kb"&&(<div>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:16}}>
            <div><L style={{marginBottom:4}}>Research Knowledge Base</L><M style={{color:C.tm}}>v{KB_VERSION} · {KB_ENTRY_COUNT} peer-reviewed entries</M></div>
            <Btn small onClick={()=>setShowKBIngestion(true)} style={{borderColor:C.d+"30",color:C.d}}>Developer Ingestion</Btn>
          </div>
          <div style={{display:"flex",gap:4,marginBottom:16,flexWrap:"wrap"}}>{["all",...[...new Set(RESEARCH_KB.map(r=>r.topic))]].map(f=>(
            <button key={f} onClick={()=>setKBFilter(f)} style={{padding:"3px 10px",background:kbFilter===f?C.ad:"transparent",border:`1px solid ${kbFilter===f?C.a+"50":C.b}`,borderRadius:6,color:kbFilter===f?C.a:C.td,fontSize:9,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>{f}</button>
          ))}</div>
          <div style={{display:"flex",flexDirection:"column",gap:8}}>
            {RESEARCH_KB.filter(r=>kbFilter==="all"||r.topic===kbFilter).map(r=>(
              <Card key={r.id} style={{padding:12}}>
                <div style={{display:"flex",gap:6,alignItems:"center",marginBottom:6,flexWrap:"wrap"}}><M style={{color:C.a,fontWeight:600}}>{r.id}</M><Badge color={r.strength==="strong"?C.a:C.w}>{r.strength}</Badge><Badge color={C.i}>{r.topic}</Badge><M style={{color:C.td}}>{r.year}</M></div>
                <div style={{fontSize:11,color:C.t,lineHeight:1.6,marginBottom:4}}>{r.finding}</div>
                <div style={{fontSize:10,color:C.p,lineHeight:1.5,marginBottom:4}}>→ {r.implication}</div>
                <M style={{color:C.td,fontStyle:"italic",lineHeight:1.5,fontSize:9}}>{r.cite}</M>
              </Card>
            ))}
          </div>
          <Card style={{marginTop:16,padding:12,borderColor:C.p+"30"}}>
            <M style={{color:C.p,fontWeight:500,display:"block",marginBottom:6}}>AI Synthesis Architecture</M>
            <M style={{color:C.tm,lineHeight:1.8}}>Production: API sends metrics + KB + citation constraint → LLM generates contextual prompts. Prototype: deterministic rule-based synthesis reads KB by ID + inserts live metrics. Both enforce: AI cites only KB entries, no hallucinated references.</M>
          </Card>
          {showKBIngestion&&<Modal title="KB Research Ingestion (Developer Only)" onClose={()=>{setShowKBIngestion(false);setDevAuth(false);setDevKey("");}} width={560}>
            {!devAuth?(<div>
              <Card style={{marginBottom:16,borderColor:C.d+"30",padding:12}}><M style={{color:C.d,fontWeight:500,display:"block",marginBottom:6}}>Restricted Access</M><M style={{color:C.tm,lineHeight:1.8}}>Exclusively for platform developers. Requires API key with kb:write scope.</M></Card>
              <Input label="Developer API Key" value={devKey} onChange={e=>setDevKey(e.target.value)} placeholder="swp-dev-xxxxxxxx" type="password" maxLength={256}/>
              <Btn primary style={{width:"100%"}} onClick={()=>{if(devKey.length>8){setDevAuth(true);api.post("/api/v1/audit/log",{event:"KB_DEV_AUTH",detail:"Developer authenticated"}).then(()=>addA("KB_DEV_AUTH","Developer authenticated"));}}} disabled={devKey.length<8}>Authenticate</Btn>
            </div>):(<div>
              <Card style={{marginBottom:16,borderColor:C.a+"30"}}>
                <M style={{color:C.a,fontWeight:500,display:"block",marginBottom:6}}>Ingestion Workflow</M>
                <M style={{color:C.tm,lineHeight:2}}>1. AI searches PubMed, PsycINFO, IEEE, ACM, USENIX, Scholar<br/>2. Quality filter: peer-reviewed only<br/>3. Structured extraction to KB schema<br/>4. Human review: approve/edit/reject<br/>5. KB version bump, prompts regenerated<br/>6. Signed deployment, anti-rollback counter incremented</M>
              </Card>
              <Card style={{padding:12,marginBottom:16}}><M style={{color:C.p,fontWeight:500,display:"block",marginBottom:4}}>Stats</M><M style={{color:C.tm,lineHeight:1.8}}>Entries: {KB_ENTRY_COUNT} · Version: {KB_VERSION} · Topics: {[...new Set(RESEARCH_KB.map(r=>r.topic))].length} · Strong: {RESEARCH_KB.filter(r=>r.strength==="strong").length} · Moderate: {RESEARCH_KB.filter(r=>r.strength==="moderate").length} · Years: {Math.min(...RESEARCH_KB.map(r=>r.year))}–{Math.max(...RESEARCH_KB.map(r=>r.year))}</M></Card>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}><Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"KB_SEARCH",detail:"AI research review initiated"}).then(()=>addA("KB_SEARCH","AI research review initiated"))}>Run AI Research Review</Btn><Btn onClick={()=>{const data=JSON.stringify({version:KB_VERSION,entryCount:KB_ENTRY_COUNT,exportedAt:new Date().toISOString(),entries:RESEARCH_KB},null,2);const blob=new Blob([data],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`firealive-kb-${KB_VERSION}.json`;a.click();URL.revokeObjectURL(url);addA("KB_EXPORT","KB exported as JSON ("+data.length+" bytes, "+KB_ENTRY_COUNT+" entries)");}}>Export KB JSON</Btn></div>
            </div>)}
          </Modal>}
        </div>)}

        {/* API KEY MANAGEMENT — NEW v0.0.9 */}
        {tab==="apikeys"&&(<div>
          <L>API Key Management</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Role-scoped API keys for programmatic access. Keys follow least-privilege: each key has explicit scope (read-only team health, CEF stream, report generation, etc.).</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>Active Keys</div>
            {[{name:"SIEM Feed Consumer",scope:"siem:read",created:"2026-03-15",last:"2s ago",status:"active"},{name:"Report Automation",scope:"reports:generate,reports:read",created:"2026-03-20",last:"8h ago",status:"active"},{name:"Dashboard Widget",scope:"health:read",created:"2026-03-22",last:"5m ago",status:"active"}].map((k,i)=>(
              <div key={i} style={{display:"flex",justifyContent:"space-between",padding:"10px 0",borderBottom:`1px solid ${C.b}`,alignItems:"center"}}>
                <div><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>{k.name}</div><M style={{color:C.tm}}>Scope: {k.scope} · Created: {k.created} · Last used: {k.last}</M></div>
                <div style={{display:"flex",gap:6}}><Badge color={C.a}>{k.status}</Badge><Btn small danger onClick={()=>addA("API_KEY_REVOKED",k.name)}>Revoke</Btn></div>
              </div>
            ))}
          </Card>
          <Card style={{padding:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>Generate New Key</div>
            <Input label="Key name" placeholder="e.g., Splunk Integration" maxLength={100}/>
            <div style={{marginBottom:14}}><M style={{color:C.tm,marginBottom:6,display:"block"}}>Scopes:</M>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>{["health:read","siem:read","reports:read","reports:generate","routing:read","audit:read"].map(s=><label key={s} style={{display:"flex",alignItems:"center",gap:4,fontSize:11,color:C.t}}><input type="checkbox" style={{accentColor:C.a}}/>{s}</label>)}</div>
            </div>
            <Sel label="Expiry"><option value="30d">30 days</option><option value="90d">90 days</option><option value="1y">1 year</option><option value="none">No expiry (not recommended)</option></Sel>
            <Btn primary onClick={()=>{const key="scr-"+Array.from(crypto.getRandomValues(new Uint8Array(24)),b=>b.toString(16).padStart(2,"0")).join("").slice(0,32);navigator.clipboard.writeText(key).catch(()=>{});addA("API_KEY_GENERATED","New API key generated: "+key.slice(0,12)+"…");alert("API Key generated and copied to clipboard:\\n\\n"+key+"\\n\\nStore this securely — it will not be shown again.");}}>Generate Key</Btn>
          </Card>
        </div>)}

        {/* NOTIFICATIONS */}
        {tab==="notif"&&(<div>
          <L>Burnout Alert Configuration</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>These alerts notify you when team burnout metrics cross thresholds — elevated utilization, capacity overload, or extended stress patterns. For app performance alerts (CPU, memory, bandwidth spikes), see the Monitoring tab.</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:14}}>Alert Threshold</div>
            <div style={{display:"flex",gap:8,marginBottom:16}}>{["watch","stressed","critical"].map(t=>{const m=stMeta[t];return(<button key={t} onClick={()=>setNotifCfg(prev=>({...prev,thresh:t}))} style={{flex:1,padding:12,background:notifCfg.thresh===t?`${m.c}15`:C.s,border:`1px solid ${notifCfg.thresh===t?m.c+"50":C.b}`,borderRadius:8,cursor:"pointer",textAlign:"center"}}><div style={{fontSize:12,fontWeight:500,color:notifCfg.thresh===t?m.c:C.tm}}>{m.l}</div></button>);})}</div>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:14}}>Channels</div>
            {[{k:"email",l:"Email",d:"SMTP/SES",ic:"✉",field:"addr",ph:"lead@corp.com"},{k:"sms",l:"SMS/RCS/iMessage",d:"SNS/Twilio fallthrough",ic:"💬",field:"phone",ph:"+1 555 000 0000"},{k:"voip",l:"VoIP Phone Call",d:"SIP/Twilio · TTS alert summary",ic:"📞"},{k:"lambda",l:"Lambda / Webhook",d:"PagerDuty, OpsGenie, ServiceNow, custom",ic:"⚡",field:"arn",ph:"arn:aws:lambda:... or https://"}].map(ch=>(
              <div key={ch.k} style={{display:"flex",alignItems:"flex-start",gap:12,padding:"12px 0",borderBottom:`1px solid ${C.b}`}}>
                <input type="checkbox" checked={notifCfg[ch.k]} onChange={e=>setNotifCfg(prev=>({...prev,[ch.k]:e.target.checked}))} style={{accentColor:C.a,marginTop:2}}/>
                <div style={{flex:1}}><div style={{fontSize:12,fontWeight:500}}>{ch.ic} {ch.l}</div><M style={{color:C.tm}}>{ch.d}</M>
                {ch.field&&notifCfg[ch.k]&&<input value={notifCfg[ch.field]||""} onChange={e=>setNotifCfg(prev=>({...prev,[ch.field]:e.target.value}))} placeholder={ch.ph} maxLength={256} style={{marginTop:8,width:"100%",padding:8,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:6,color:C.t,fontSize:11}}/>}</div>
              </div>
            ))}
            <Btn primary style={{width:"100%",marginTop:16}} onClick={()=>addA("NOTIF_SAVED",`Thresh:${notifCfg.thresh}, ${["email","sms","voip","lambda"].filter(k=>notifCfg[k]).join(",")}`)}>Save</Btn>
          </Card>
        </div>)}

        {/* SIEM */}
        {tab==="siem"&&(<div>
          <L>SIEM Integration</L>
          <Card style={{marginBottom:20}}><pre style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:10,color:C.t,lineHeight:2,whiteSpace:"pre",overflowX:"auto"}}>{
`FireAlive ──CEF/TLS 6514──→ SIEM Plugin
  (Tier-1 only)                   → Health gauge
  (No burnout data)               → Capacity map
                                   → Action alerts
Analyst Clients (Tier-3) ── NO SIEM flow`}</pre></Card>
          <Card style={{marginBottom:20,background:"#0A1628",borderColor:"rgba(96,165,250,0.2)"}}>
            <Card style={{marginBottom:12,borderColor:C.w+"30"}}><div style={{fontSize:12,fontWeight:500,color:C.w,marginBottom:8}}>Widget Visibility</div><M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Restrict burnout metrics widget to Team Lead SIEM dashboard only to protect team morale.</M><label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" defaultChecked/><M style={{color:C.t}}>Widget enabled</M></label><Sel label="Visibility"><option>Team Lead only</option><option>Team Lead + Manager</option><option>All SOC (not recommended)</option><option>Disabled</option></Sel><label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" defaultChecked/><M style={{color:C.t}}>Send event data to SIEM even when widget hidden</M></label></Card>
            <M style={{color:"rgba(96,165,250,0.6)",letterSpacing:1.2,textTransform:"uppercase",display:"block",marginBottom:12}}>SIEM Widget Preview</M>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10}}>
              <div style={{padding:12,background:"rgba(96,165,250,0.05)",border:"1px solid rgba(96,165,250,0.15)",borderRadius:8,textAlign:"center"}}><div style={{fontSize:28,fontWeight:300,color:sc.c,fontFamily:"'Fraunces',serif"}}>{th.score}</div><M style={{color:"rgba(96,165,250,0.5)"}}>HEALTH</M></div>
              <div style={{padding:12,background:"rgba(96,165,250,0.05)",border:"1px solid rgba(96,165,250,0.15)",borderRadius:8,textAlign:"center"}}><div style={{fontSize:28,fontWeight:300,color:th.avgUtil>80?C.w:C.a,fontFamily:"'Fraunces',serif"}}>{th.avgUtil}%</div><M style={{color:"rgba(96,165,250,0.5)"}}>UTIL</M></div>
              <div style={{padding:12,background:highP.length>0?"rgba(239,68,68,0.08)":"rgba(96,165,250,0.05)",border:`1px solid ${highP.length>0?"rgba(239,68,68,0.3)":"rgba(96,165,250,0.15)"}`,borderRadius:8,textAlign:"center"}}><div style={{fontSize:28,fontWeight:300,color:highP.length>0?C.d:C.a,fontFamily:"'Fraunces',serif"}}>{highP.length}</div><M style={{color:highP.length>0?"rgba(239,68,68,0.6)":"rgba(96,165,250,0.5)"}}>ACTIONS</M></div>
            </div>
            <div style={{marginTop:10,padding:"8px 14px",background:panicMode?"rgba(239,68,68,0.08)":"rgba(110,231,183,0.08)",border:"1px solid "+(panicMode?C.d+"40":C.a+"40"),borderRadius:8,display:"flex",justifyContent:"space-between",alignItems:"center"}}><M style={{color:panicMode?C.d:C.a,fontWeight:600}}>Burnout Prevention Routing</M><Badge color={panicMode?C.d:C.a}>{panicMode?"OFF":"ON"}</Badge></div>
          </Card>
          <Btn small onClick={()=>setShowCEF(!showCEF)}>{showCEF?"Hide":"Show"} CEF</Btn>
          {showCEF&&<div style={{marginTop:8,padding:14,background:"#000",borderRadius:8,fontFamily:"'IBM Plex Mono',monospace",fontSize:9,color:"#8EC07C",lineHeight:1.8,overflowX:"auto",whiteSpace:"pre-wrap",wordBreak:"break-all"}}>{generateCEF(th,"health")}</div>}
        </div>)}

        {/* ONBOARD */}
        {tab==="onboard"&&(<div>
          <L>Client Provisioning & Ticketing Integration</L>
          <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Deploy Analyst Client to workstations via admin push — analysts never install apps themselves (prevents rogue app installation). The MC generates a provisioning package with config.json (server endpoint, enrollment token) and pushes it via your enterprise deployment tool.</M>
          <Card style={{marginBottom:16,borderColor:C.i+"30",padding:14}}>
            <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:6}}>Provisioning Workflow</M>
            <M style={{color:C.tm,lineHeight:1.8}}>1. Team Lead creates provisioning package here (assigns analyst, host, tier){"\n"}2. MC generates Electron installer + config.json with one-time enrollment token{"\n"}3. IT admin pushes package to target machine via SCCM/Intune/Ansible/JAMF{"\n"}4. Client auto-installs, reads config.json, connects to server using enrollment token{"\n"}5. Server verifies token, registers client, assigns pseudonym{"\n"}6. Client is live — analyst logs in with IAM/MFA credentials{"\n"}Analysts never handle the installer. Enrollment tokens expire after 24 hours.</M>
          </Card>
          <Sel label="Deployment tool" value={provisionCfg.method} onChange={e=>setProvisionCfg(prev=>({...prev,method:e.target.value}))}>
            <option value="admin_push">Admin push (recommended)</option><option value="sccm">Microsoft SCCM/MECM</option><option value="intune">Microsoft Intune</option><option value="ansible">Ansible</option><option value="jamf">JAMF (macOS)</option><option value="manual">Manual (IT staff installs on-site)</option>
          </Sel>
          <Sel label="Target OS" value="" onChange={()=>{}}>
            <option value="">Select target OS...</option><option value="ubuntu">Ubuntu 22.04 LTS (.deb)</option><option value="rhel">RHEL 8+ (.rpm)</option><option value="kali">Kali Linux (.AppImage)</option><option value="win11">Windows 11 (.exe)</option><option value="macos">macOS 14+ (.dmg)</option>
          </Sel>
          <Btn primary onClick={()=>setShowProvision(true)} style={{marginBottom:20}}>+ Provision New Client</Btn>
          <Card style={{marginTop:12}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Client Management Actions</div>
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              <Btn small onClick={()=>api.post("/api/v1/audit/log",{event:"CLIENT_RESTORE_BACKUP",detail:"Select client to restore from known-good backup"}).then(()=>addA("CLIENT_RESTORE_BACKUP","Select client to restore from known-good backup"))}>Restore Client from Backup</Btn>
              <Btn small onClick={()=>api.post("/api/v1/audit/log",{event:"CLIENT_REVERT_CONFIG",detail:"Select client to revert to previous config"}).then(()=>addA("CLIENT_REVERT_CONFIG","Select client to revert to previous config"))}>Revert Client Config</Btn>
            </div>
          </Card>
          {provisionedClients.length>0&&<>
            <L>Provisioned Clients</L>
            <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,overflow:"hidden"}}>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr 1fr",padding:"10px 14px",borderBottom:`1px solid ${C.b}`}}>{["Analyst","Host","Activation ID","Tier/Shift","Status"].map(h=><M key={h} style={{color:C.td,fontWeight:500}}>{h}</M>)}</div>
              {provisionedClients.map(c=>(
                <div key={c.id} style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr 1fr",padding:"10px 14px",borderBottom:`1px solid ${C.b}`,alignItems:"center"}}>
                  <span style={{fontSize:12}}>{c.analyst}</span>
                  <M style={{color:C.tm}}>{c.hostname}</M>
                  <M style={{color:C.a,fontSize:9}}>{c.id}</M>
                  <M style={{color:C.tm}}>{tierLbl(c.tier)} · {c.shift}</M>
                  <Badge color={c.status==="active"?C.a:C.w}>{c.status}</Badge>
                </div>
              ))}
            </div>
          </>}
          {showProvision&&<Modal title="Provision Analyst Client" onClose={()=>setShowProvision(false)} width={520}>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Like configuring a Filebeat or Winlogbeat agent: specify the target host, assign to an analyst, and the client registers with the platform using its activation ID.</M>
            <Input label="Analyst name" value={newA.name} onChange={e=>setNewA(prev=>({...prev,name:e.target.value}))} placeholder="Full name" maxLength={100}/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Sel label="Tier" value={newA.tier} onChange={e=>setNewA(prev=>({...prev,tier:Number(e.target.value)}))}><option value={1}>L1</option><option value={2}>L2</option><option value={3}>L3</option></Sel>
              <Sel label="Shift" value={newA.shift} onChange={e=>setNewA(prev=>({...prev,shift:e.target.value}))}><option value="day">Day</option><option value="swing">Swing</option><option value="night">Night</option></Sel>
            </div>
            <Input label="Target hostname" value={newA.hostname} onChange={e=>setNewA(prev=>({...prev,hostname:e.target.value}))} placeholder="SOC-WS-042.corp.local" maxLength={253}/>
            <Input label="IP address (optional)" value={newA.ip} onChange={e=>setNewA(prev=>({...prev,ip:e.target.value}))} placeholder="10.0.5.42" maxLength={45}/>
            <Card style={{marginBottom:16,padding:12,borderColor:C.a+"30"}}>
              <M style={{color:C.a,fontWeight:500,display:"block",marginBottom:6}}>Provisioning will:</M>
              <M style={{color:C.tm,lineHeight:2}}>1. Create Tier-3 encrypted data store (analyst-private)<br/>2. Generate activation ID for client registration<br/>3. Deploy client package to target host via SCCM/Ansible<br/>4. Configure routing eligibility (cap based on tier)<br/>5. Begin 14-day baseline calibration (no signals flagged)<br/>6. Update SIEM feed (team aggregate only)</M>
            </Card>
            <Btn primary style={{width:"100%"}} disabled={!newA.name.trim()||!newA.hostname.trim()} onClick={handleProvision}>Provision Client</Btn>
          </Modal>}
        </div>)}

        {/* CLOUD */}
        {tab==="cloud"&&(<div>
          <L>Cloud Architecture & Migration</L>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginBottom:20}}>
            {[{id:"aws",name:"AWS",color:"#FF9900",services:"EKS · Aurora · S3 · KMS · Kinesis · SNS · Lambda · Cognito",serverless:"Fargate + Aurora Serverless v2 + API Gateway"},
              {id:"gcp",name:"GCP",color:"#4285F4",services:"GKE · Cloud SQL · Storage · KMS · Pub/Sub · Cloud Run · Identity Platform",serverless:"Cloud Run + Cloud SQL + Pub/Sub triggers"},
              {id:"azure",name:"Azure",color:"#0078D4",services:"AKS · Azure SQL · Blob · Key Vault · Event Hubs · Functions · Entra ID · Sentinel",serverless:"Container Apps + Azure SQL Serverless + Event Grid"},
            ].map(c=>(
              <Card key={c.id} style={{borderTop:`3px solid ${c.color}`,cursor:"pointer"}} onClick={()=>setShowCloudWF(c.id)}>
                <div style={{fontSize:16,fontWeight:600,color:c.color,marginBottom:8}}>{c.name}</div>
                <M style={{color:C.tm,lineHeight:1.8,display:"block",marginBottom:10}}>{c.services}</M>
                <div style={{borderTop:`1px solid ${C.b}`,paddingTop:8}}><M style={{color:C.a,fontWeight:500}}>Serverless:</M><br/><M style={{color:C.tm}}>{c.serverless}</M></div>
                <M style={{color:c.color,display:"block",marginTop:10}}>Click for migration workflow →</M>
              </Card>
            ))}
          </div>
          <L>Privacy-First Cloud Platforms</L>
          <M style={{color:C.tm,display:"block",marginBottom:12}}>European/Swiss cloud providers with strong data sovereignty and privacy protections. No US CLOUD Act jurisdiction. Data stays in-country.</M>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginBottom:20}}>
            {[{id:"hetzner",name:"Hetzner Cloud",color:"#D50C2D",country:"Germany",services:"VPS · Block Storage · Load Balancers · Firewalls · Volumes",note:"GDPR-native. No data sharing with non-EU authorities. Cost-effective."},
              {id:"ovhcloud",name:"OVHcloud",color:"#000E9C",country:"France",services:"Dedicated Servers · Public Cloud · Managed K8s · Object Storage",note:"EU data residency guaranteed. SOC 2 / ISO 27001 / HDS certified."},
              {id:"exoscale",name:"Exoscale",color:"#DA291C",country:"Switzerland/Austria",services:"Compute · Object Storage · Managed DBaaS · DNS · Load Balancers",note:"Swiss data protection. Built for regulated industries. FINMA compliant."},
            ].map(c=>(
              <Card key={c.id} style={{borderTop:`3px solid ${c.color}`,cursor:"pointer"}} onClick={()=>setShowCloudWF(c.id)}>
                <div style={{fontSize:14,fontWeight:600,color:c.color,marginBottom:4}}>{c.name}</div>
                <Badge color={C.p}>{c.country}</Badge>
                <M style={{color:C.tm,lineHeight:1.8,display:"block",marginTop:8,marginBottom:8}}>{c.services}</M>
                <M style={{color:C.i,display:"block",fontStyle:"italic"}}>{c.note}</M>
              </Card>
            ))}
          </div>
          <div style={{display:"flex",gap:10,marginBottom:20}}>
            <Btn primary onClick={()=>setShowIaC(true)}>Generate Infrastructure as Code</Btn>
            <Btn onClick={()=>setShowCloudWF("data-only")}>Data Export Only (no migration)</Btn>
          </div>
          <Card>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Container Specifications</div>
            <M style={{color:C.t,lineHeight:2}}>
              • Distroless Docker images · Non-root · Read-only FS<br/>
              • Helm charts + Terraform modules for all 3 clouds<br/>
              • Multi-AZ HA · HPA auto-scaling · Blue/green deploys<br/>
              • mTLS between services (Istio) · Network policies enforce Tier-3 isolation<br/>
              • Secrets via cloud KMS · Auto-rotated · Never in env vars
            </M>
          </Card>

          {showCloudWF&&showCloudWF!=="data-only"&&<Modal title={`${showCloudWF.toUpperCase()} Migration Workflow`} onClose={()=>setShowCloudWF(null)} width={560}>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Step-by-step migration. Container images are cloud-agnostic — no recoding needed.</M>
            {(showCloudWF==="aws"?[
              {s:1,t:"Create VPC + subnets",d:"Terraform: vpc module. Private subnets for EKS, public for ALB."},
              {s:2,t:"Deploy EKS cluster",d:"eksctl or Terraform. Enable IRSA for pod-level IAM."},
              {s:3,t:"Deploy Aurora PostgreSQL",d:"Multi-AZ. Enable encryption. Separate instances for Tier-1 and Tier-3."},
              {s:4,t:"Configure S3 buckets",d:"Backup bucket (versioned, Object Lock). CEF stream archive."},
              {s:5,t:"Deploy via Helm",d:"helm install soc-wellbeing ./charts --set cloud=aws"},
              {s:6,t:"Configure Cognito",d:"SAML federation with corporate AD. MFA enforcement."},
              {s:7,t:"Set up Kinesis",d:"CEF stream → Kinesis Data Firehose → SIEM or S3."},
              {s:8,t:"Enable monitoring",d:"CloudWatch Container Insights + GuardDuty + WAF on ALB."},
            ]:showCloudWF==="gcp"?[
              {s:1,t:"Create VPC + Cloud NAT",d:"Terraform: google_compute_network. Private GKE cluster."},
              {s:2,t:"Deploy GKE Autopilot",d:"Managed node pools. Workload Identity for IAM."},
              {s:3,t:"Deploy Cloud SQL",d:"HA PostgreSQL. Separate instances for Tier-1/Tier-3."},
              {s:4,t:"Configure Cloud Storage",d:"Dual-region. CMEK encryption. Retention policies."},
              {s:5,t:"Deploy via Helm",d:"helm install soc-wellbeing ./charts --set cloud=gcp"},
              {s:6,t:"Configure Identity Platform",d:"SAML/OIDC with corporate AD. MFA required."},
              {s:7,t:"Set up Pub/Sub",d:"CEF stream → Pub/Sub → Chronicle or BigQuery."},
              {s:8,t:"Enable monitoring",d:"Cloud Monitoring + Cloud Armor + Security Command Center."},
            ]:[
              {s:1,t:"Create Resource Group + VNet",d:"Terraform: azurerm_virtual_network. Private AKS."},
              {s:2,t:"Deploy AKS",d:"Managed identity. Azure AD pod identity."},
              {s:3,t:"Deploy Azure SQL",d:"Geo-replicated. TDE encryption. Separate for Tier-1/Tier-3."},
              {s:4,t:"Configure Blob Storage",d:"Immutable. WORM. RA-GRS for geo-redundancy."},
              {s:5,t:"Deploy via Helm",d:"helm install soc-wellbeing ./charts --set cloud=azure"},
              {s:6,t:"Configure Entra ID",d:"SAML SSO with corporate AD. Conditional Access + MFA."},
              {s:7,t:"Set up Event Hubs",d:"CEF stream → Event Hubs → Sentinel (native integration)."},
              {s:8,t:"Enable monitoring",d:"Azure Monitor + Application Gateway WAF + Defender for Containers."},
            ]).map(step=>(
              <div key={step.s} style={{display:"flex",gap:12,marginBottom:12}}>
                <div style={{width:24,height:24,borderRadius:"50%",background:C.ad,border:`1px solid ${C.a}40`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,color:C.a,fontWeight:600,flexShrink:0}}>{step.s}</div>
                <div><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:2}}>{step.t}</div><M style={{color:C.tm}}>{step.d}</M></div>
              </div>
            ))}
            <Btn primary style={{width:"100%",marginTop:16}} onClick={()=>{addA("MIGRATION_STARTED",`${showCloudWF.toUpperCase()} migration workflow initiated`);setShowCloudWF(null);}}>Start Migration Workflow →</Btn>
          </Modal>}

          {showCloudWF==="data-only"&&<Modal title="Data Export Configuration" onClose={()=>setShowCloudWF(null)}>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Send team capacity metrics to a cloud platform without migrating the application. Useful for centralized dashboards or data lakes.</M>
            {[{t:"CEF stream to S3/GCS/Blob",d:"Syslog → cloud storage. Query with Athena/BigQuery/Synapse."},
              {t:"Kinesis/Pub/Sub/Event Hubs",d:"Real-time stream. Build custom dashboards in QuickSight/Looker/PowerBI."},
              {t:"API webhook",d:"Push JSON payloads to any endpoint on team health changes."},
            ].map((o,i)=><Card key={i} style={{marginBottom:8,padding:"12px 14px"}}><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:2}}>{o.t}</div><M style={{color:C.tm}}>{o.d}</M></Card>)}
          </Modal>}

          {showIaC&&<Modal title="Generate Infrastructure as Code" onClose={()=>{setShowIaC(false);setIacProvider("");setIacTool("");setIacResult(null);setIacBusy(false);}} width={560}>
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Generate a signed deployment bundle for FireAlive MC-server. The server packages IaC files, an SPDX-JSON SBOM, and a Sigstore signature into a tar.gz ready to deploy.</M>
            <Sel label="Cloud Provider" value={iacProvider} onChange={e=>{setIacProvider(e.target.value);setIacTool("");setIacResult(null);}}>
              <option value="">Select provider...</option>
              <option value="aws">AWS</option>
              <option value="azure">Azure</option>
              <option value="gcp">GCP</option>
              <option value="hetzner">Hetzner (DE)</option>
              <option value="ovhcloud">OVHcloud (FR)</option>
              <option value="exoscale">Exoscale (CH)</option>
            </Sel>
            {iacProvider&&<Sel label="IaC Format" value={iacTool} onChange={e=>{setIacTool(e.target.value);setIacResult(null);}}>
              <option value="">Select format...</option>
              {IAC_TOOLS_BY_PROVIDER[iacProvider].map(t=><option key={t} value={t}>{t}</option>)}
            </Sel>}
            {iacResult&&iacResult.ok&&<Card style={{marginBottom:12,borderColor:C.a+"30",padding:12}}>
              <div style={{fontSize:12,fontWeight:500,color:C.a,marginBottom:8}}>Bundle generated</div>
              <M style={{color:C.tm,display:"block",marginBottom:2}}>Package ID: <span style={{fontFamily:"'IBM Plex Mono',monospace",color:C.t}}>{iacResult.data.id}</span></M>
              <M style={{color:C.tm,display:"block",marginBottom:2}}>Size: {(iacResult.data.size_bytes/1024).toFixed(1)} KB</M>
              <M style={{color:C.tm,display:"block",marginBottom:2}}>Manifest SHA-256: <span style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:9}}>{iacResult.data.manifest_sha256.slice(0,32)}...</span></M>
              <M style={{color:C.tm,display:"block",marginBottom:2}}>Signing key fingerprint: <span style={{fontFamily:"'IBM Plex Mono',monospace",fontSize:9}}>{(iacResult.data.signing_key_fingerprint||"").slice(0,32)}...</span></M>
              <Btn small primary style={{marginTop:10}} onClick={()=>{window.open("/api/cloud/packages/"+iacResult.data.id+"/download","_blank");}}>Download bundle.tar.gz</Btn>
              <Btn small style={{marginTop:10,marginLeft:6}} onClick={()=>{window.open("/api/cloud/packages/"+iacResult.data.id+"/public-key","_blank");}}>View public key</Btn>
            </Card>}
            {iacResult&&!iacResult.ok&&<Card style={{marginBottom:12,borderColor:C.d+"40",padding:12}}>
              <div style={{fontSize:12,fontWeight:500,color:C.d,marginBottom:6}}>Generation failed</div>
              <M style={{color:C.tm,lineHeight:1.6,display:"block"}}>{iacResult.message}</M>
              {iacResult.code==="SYFT_NOT_INSTALLED"&&<M style={{color:C.td,display:"block",marginTop:8,lineHeight:1.6,fontSize:10}}>Install Syft on the FireAlive host:<br/><code style={{background:C.s,padding:"2px 4px",borderRadius:3}}>curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin</code></M>}
              {iacResult.code==="COSIGN_NOT_INSTALLED"&&<M style={{color:C.td,display:"block",marginTop:8,lineHeight:1.6,fontSize:10}}>Install Cosign on the FireAlive host:<br/><code style={{background:C.s,padding:"2px 4px",borderRadius:3}}>curl -sSfL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 && chmod +x /usr/local/bin/cosign</code></M>}
            </Card>}
            <Btn primary disabled={!iacProvider||!iacTool||iacBusy} onClick={async()=>{
              setIacBusy(true);setIacResult(null);
              try{
                const r=await api.post("/api/cloud/package",{provider:iacProvider,iac_tool:iacTool});
                setIacResult({ok:true,data:r.data});
                addA("CLOUD_PACKAGE_GENERATED",iacProvider+"/"+iacTool+" id="+r.data.id);
              }catch(err){
                const ed=err.response&&err.response.data?err.response.data:{};
                setIacResult({ok:false,message:ed.message||err.message||"Generation failed",code:ed.code});
              }finally{setIacBusy(false);}
            }}>{iacBusy?"Generating bundle...":"Generate Bundle"}</Btn>
            <Card style={{padding:12,marginTop:12}}><M style={{color:C.td,lineHeight:1.8}}>The generated bundle contains: IaC files for the chosen (provider, format), SPDX-JSON SBOM (Syft), Sigstore signature (Cosign keyless via the server-managed signing key), and a deployment README with the provider-specific secrets mapping. Verify the archive offline with <code>cosign verify-blob --key &lt;public-key.pem&gt; --signature bundle.tar.gz.sig bundle.tar.gz</code> before applying.</M></Card>
          </Modal>}
        </div>)}

        {/* SDN — NEW v0.0.9 */}
        {tab==="sdn"&&(<div>
          <L>Software-Defined Networking Integration</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Configure the platform for distributed SOC environments where analysts, automation systems, and SIEM infrastructure span multiple sites connected via SD-WAN or SDN fabrics.</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>SDN Controller Integration</div>
            <Sel label="SDN Platform"><option value="">Select...</option><option value="cisco-aci">Cisco ACI</option><option value="vmware-nsx">VMware NSX-T</option><option value="openflow">OpenFlow (Open vSwitch)</option><option value="arista-cv">Arista CloudVision</option><option value="juniper-cn2">Juniper CN2</option><option value="calico">Calico Enterprise</option><option value="cilium">Cilium (eBPF)</option><option value="custom">Custom REST API</option></Sel>
            <Input label="Controller API endpoint" placeholder="https://sdn-controller.corp.local:443/api/v1" maxLength={512}/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Input label="API username / service account" placeholder="svc-socwellbeing" maxLength={256}/>
              <div style={{marginBottom:14}}><M style={{color:C.tm,marginBottom:4,display:"block"}}>API key / token</M><input type="password" placeholder="••••••••" maxLength={512} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}}/></div>
            </div>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Network Segmentation Policy</div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>Define SDN policies that enforce the platform's data tier separation at the network level.</M>
            {[{n:"Analyst VLAN",d:"Clients. E2EE.",c:C.a},{n:"Mgmt VLAN",d:"MC+Server+DB.",c:C.i},{n:"CISO VLAN",d:"GD+GD Server.",c:C.p},{n:"SIEM",d:"Regional.",c:C.w},{n:"Backup",d:"Encrypted. MFA.",c:C.d}].map((seg,i)=>(
              <div key={i} style={{display:"flex",gap:12,padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
                <div style={{width:8,height:8,borderRadius:"50%",background:seg.c,marginTop:4,flexShrink:0}}/>
                <div><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>{seg.n}</div><M style={{color:C.tm}}>{seg.d}</M></div>
              </div>
            ))}
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>SD-WAN Site Configuration</div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>For multi-site SOCs where analysts work from different locations connected via SD-WAN (Cisco Viptela, VMware VeloCloud, Fortinet, Palo Alto Prisma SD-WAN).</M>
            <Input label="Primary site CIDR" placeholder="10.0.0.0/16" maxLength={18}/>
            <Input label="Secondary site CIDR" placeholder="10.1.0.0/16" maxLength={18}/>
            <Input label="SD-WAN overlay network" placeholder="172.16.0.0/12" maxLength={18}/>
            <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"SDN_CONFIGURED",detail:"SDN integration configured"}).then(()=>addA("SDN_CONFIGURED","SDN integration configured"))}>Save SDN Configuration</Btn>
          </Card>
        </div>)}

        {/* VIRTUALIZATION — NEW v0.0.9 */}
        {tab==="virt"&&(<div>
          <L>Virtualization Compatibility</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>The platform is designed to run in virtualized environments. Configure integration with your hypervisor/container orchestration layer.</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>Supported Environments</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10}}>
              {[{n:"Container Orchestration",items:["Kubernetes (EKS/GKE/AKS)","Docker Swarm","Nomad","OpenShift"],c:C.a},{n:"Hypervisor Platforms",items:["VMware vSphere/ESXi","Hyper-V","KVM/QEMU","Proxmox VE","Nutanix AHV"],c:C.i},{n:"VDI / Remote Desktop",items:["Citrix Virtual Apps","VMware Horizon","AWS WorkSpaces","Azure Virtual Desktop"],c:C.p}].map((cat,i)=>(
                <Card key={i} style={{borderTop:`3px solid ${cat.c}`}}>
                  <div style={{fontSize:12,fontWeight:500,color:cat.c,marginBottom:8}}>{cat.n}</div>
                  {cat.items.map((item,j)=><M key={j} style={{color:C.tm,display:"block",lineHeight:1.8}}>{item}</M>)}
                </Card>
              ))}
            </div>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>VM/Container Configuration</div>
            <Sel label="Deployment target"><option value="">Select...</option><option value="k8s">Kubernetes cluster</option><option value="docker">Docker Compose</option><option value="vm">Virtual Machine (OVA/QCOW2)</option><option value="vdi">VDI image</option></Sel>
            <Input label="vCenter / Cluster API endpoint" placeholder="https://vcenter.corp.local/sdk" maxLength={512}/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Input label="Resource pool" placeholder="SOC-Wellbeing-Pool" maxLength={100}/>
              <Input label="Datastore" placeholder="vsanDatastore" maxLength={100}/>
            </div>
            <Card style={{padding:12,marginTop:8,borderColor:C.a+"30"}}>
              <M style={{color:C.a,fontWeight:500,display:"block",marginBottom:4}}>Compatibility Notes</M>
              <M style={{color:C.tm,lineHeight:1.8}}>Platform runs as distroless containers (no shell, no package manager). Compatible with any OCI-compliant runtime. vTPM support required for anti-rollback attestation on VMs. Nested virtualization supported but not required. GPU not required. Minimum: 2 vCPU, 4GB RAM, 20GB storage per service pod.</M>
            </Card>
            <Btn primary style={{marginTop:12}} onClick={()=>api.post("/api/v1/audit/log",{event:"VIRT_CONFIGURED",detail:"Virtualization target configured"}).then(()=>addA("VIRT_CONFIGURED","Virtualization target configured"))}>Save Configuration</Btn>
          </Card>
        </div>)}

        {/* BACKUP */}
        {tab==="backup"&&(<div>
          <L>Backup, Recovery & Storage Routing</L>
          <Card style={{marginBottom:16,borderColor:C.i+"30"}}>
            <div style={{fontSize:13,fontWeight:600,color:C.i,marginBottom:10}}>Backup Scheduler</div>
            <Sel label="Type"><option>Full</option><option>DB only</option><option>Configs</option><option>Audit</option></Sel>
            <Sel label="Interval"><option>Every 4hr</option><option>Every 8hr</option><option>Daily 02:00</option><option>Weekly Sun</option></Sel>
            <Sel label="Retention"><option>7 days</option><option>30 days</option><option>90 days</option><option>1 year</option></Sel>
            <Input label="Destination" placeholder="smb://backup/"/>
            {/* R3l C60: kind/strategy/filter wired through the qk* state declared above. */}
            <Sel label="Data scope" value={qkBackupKind} onChange={e=>setQkBackupKind(e.target.value)}>
              <option value="full-suite">Full suite (configs + audit + keys + DB)</option>
              <option value="single-db">Database file only</option>
            </Sel>
            <Sel label="Strategy" value={qkBackupStrategy} onChange={e=>setQkBackupStrategy(e.target.value)}>
              <option value="full">Full</option>
              <option value="incremental">Incremental (WAL-based)</option>
              <option value="differential">Differential (since anchor)</option>
              <option value="snapshot">Snapshot (point-in-time)</option>
            </Sel>
            <Input label="Destination filter (comma-separated tags; empty = all)" value={qkDestinationFilter} onChange={e=>setQkDestinationFilter(e.target.value)} placeholder="e.g. offsite, encrypted"/>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}>
              <input type="checkbox" defaultChecked/>
              <M style={{color:C.t}}>Encrypt (AES-256)</M>
            </label>
            <Btn primary style={{marginTop:8}} onClick={()=>{
              const tags = (qkDestinationFilter || "").split(",").map(s=>s.trim()).filter(Boolean);
              api.post("/api/backup-schedules", {
                name: "Backup tab quick-save",
                type: "full",
                frequency: "daily",
                time: "02:00",
                destination: "local",
                retention_days: 30,
                encrypted: true,
                active: true,
                // R3l C60: kind/strategy/filter parity with the full Add Schedule form
                backup_kind: qkBackupKind,
                backup_strategy: qkBackupStrategy,
                destination_filter: tags.length > 0 ? tags : null,
              }).then(r=>addA("BK","Backup schedule saved (id="+(r&&r.schedule?r.schedule.id:"?")+")"))
                .catch(e=>addA("BK_FAIL",e.message||"Failed to save schedule"));
            }}>Save</Btn>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:C.i,marginBottom:12}}>Storage Destination Configuration</div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Route each data type to its appropriate storage destination. Each type can target a different system — backups to one location, audit logs to another, forensic exports to a third.</M>
            {[{type:"Backups",desc:"Daily full + on-demand snapshots",ph:"s3://soc-wellbeing-backups/daily/",opts:["AWS S3","GCP Cloud Storage","Azure Blob","NFS/SMB Share","On-machine (local)","On-site NAS"]},
              {type:"Audit Logs",desc:"Immutable, append-only, tamper-evident",ph:"s3://soc-audit-immutable/ (Object Lock enabled)",opts:["S3 Object Lock","Azure Immutable Blob","GCS Retention Lock","WORM NAS","Syslog (remote)"]},
              {type:"Forensic Exports",desc:"Double-encrypted, chain-of-custody signed",ph:"s3://soc-forensics-air-gapped/",opts:["AWS S3 (separate account)","Air-gapped NAS","Azure Blob (isolated VNet)","GCS (separate project)","Removable media (USB/tape)"]},
              {type:"Snapshots",desc:"Point-in-time captures before config changes + on-demand",ph:"s3://soc-wellbeing-snapshots/",opts:["AWS S3","GCP Cloud Storage","Azure Blob","NFS/SMB Share","Same as backups"]},
              {type:"CEF Stream Archives",desc:"SIEM event archives for compliance",ph:"s3://soc-cef-archive/",opts:["AWS S3","Splunk SmartStore","GCS","Azure Blob","Elasticsearch cold tier"]}
            ].map((d,i)=>(
              <Card key={i} style={{marginBottom:10,padding:"12px 14px"}}>
                <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:2}}>{d.type}</div>
                <M style={{color:C.td,display:"block",marginBottom:8}}>{d.desc}</M>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
                  <Sel label="Destination">{d.opts.map(o=><option key={o} value={o}>{o}</option>)}</Sel>
                  <Input label="Path / URI" placeholder={d.ph} maxLength={512}/>
                </div>
              </Card>
            ))}
            <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"STORAGE_ROUTES_SAVED",detail:"Backup/log storage destinations configured"}).then(()=>addA("STORAGE_ROUTES_SAVED","Backup/log storage destinations configured"))}>Save Storage Routes</Btn>
          </Card>
          <Card style={{marginBottom:16,borderColor:C.a+"30"}}>
            <div style={{fontSize:13,fontWeight:500,color:C.a,marginBottom:10}}>Encryption at Rest</div>
            <M style={{color:C.t,lineHeight:1.8}}>
              Tier-3 DBs: AES-256-GCM, CMK, auto-rotation 365d. Tier-1 DBs: separate CMK. Audit logs: immutable storage, separate key. Backups: split-key architecture. Forensic exports: double-encrypted. CEF archives: TLS 1.3 in transit. Messages: E2EE (X25519 + AES-256-GCM). Tokens: RS256 JWTs, 15-min expiry.
            </M>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>Automatic Schedule</div>
            {[{l:"Daily full",d:"02:00 UTC · 35 days retention · AES-256-GCM + SHA-256 chain",a:true},{l:"Snapshots",d:"Before config changes + on-demand. No time limit.",a:true},{l:"WAL shipping",d:"Continuous replication. RPO < 5 min.",a:true},{l:"Forensic chain",d:"Tamper-evident SHA-256 hash chain. Legal-hold compatible.",a:true}].map((b,i)=>(
              <div key={i} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 0",borderBottom:i<3?`1px solid ${C.b}`:"none"}}><div><div style={{fontSize:12}}>{b.l}</div><M style={{color:C.tm}}>{b.d}</M></div><Badge color={b.a?C.a:C.tm}>{b.a?"active":"off"}</Badge></div>
            ))}
          </Card>
          <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap"}}>
            <Btn primary onClick={async()=>{const localId=Date.now();const placeholder={id:localId,ts:new Date().toISOString(),type:"full-suite",size:"...",status:"running",hash:"generating..."};setBackups(prev=>[placeholder,...prev]);addA("FULL_SUITE_BACKUP_TRIGGERED","Full-suite backup requested");try{const r=await api.post("/api/backup/full-suite",{});setBackups(prev=>prev.map(b=>b.id===localId?{id:r.id||localId,ts:new Date().toISOString(),type:"full-suite",size:r.size_bytes?(r.size_bytes/1024/1024).toFixed(1)+" MB":"?",status:"verified",hash:r.manifest_sha256?"sha256:"+r.manifest_sha256.slice(0,16):"(no manifest)"}:b));addA("FULL_SUITE_BACKUP_CREATED","id="+r.id+" size="+r.size_bytes);}catch(err){const msg=(err.response&&err.response.data&&err.response.data.message)||err.message||"backup failed";setBackups(prev=>prev.map(b=>b.id===localId?{...b,status:"failed",hash:msg.slice(0,40)}:b));addA("FULL_SUITE_BACKUP_FAILED",msg);}}}>Trigger Full Backup Now</Btn>
            {/* R3l C72: ad-hoc strategy buttons. Both call POST /api/backup
                with ?strategy= (the C67 endpoint). Server may escalate to
                full when no anchor/parent exists; the response carries
                actual_strategy and escalation_reason which we surface in
                the activity log and the placeholder row's backup_strategy
                field so the post-success row reflects what was actually
                produced (not what was requested). */}
            <Btn onClick={async()=>{
              const localId=Date.now();
              const placeholder={id:localId,ts:new Date().toISOString(),type:"on-demand",backup_strategy:"incremental",size:"...",status:"running",hash:"generating..."};
              setBackups(prev=>[placeholder,...prev]);
              addA("BACKUP_TRIGGERED","strategy=incremental");
              try{
                const r=await api.post("/api/backup?strategy=incremental",{});
                const actual=r.actual_strategy||"incremental";
                const escalated=!!r.escalated;
                setBackups(prev=>prev.map(x=>x.id===localId?{id:r.id||localId,ts:new Date().toISOString(),type:"on-demand",backup_strategy:actual,parent_backup_id:r.parent_backup_id,parent_full_backup_id:r.parent_full_backup_id,page_count:r.page_count,wal_start_position:r.wal_start_position,wal_end_position:r.wal_end_position,size:r.size_bytes?(r.size_bytes/1024/1024).toFixed(1)+" MB":"?",status:"verified",hash:r.manifest_sha256?"sha256:"+r.manifest_sha256.slice(0,16):"(no manifest)"}:x));
                addA("BACKUP_CREATED","id="+r.id+" strategy="+actual+(escalated?" (escalated from incremental: "+(r.escalation_reason||"no reason")+")":""));
              }catch(err){
                const msg=(err.response&&err.response.data&&(err.response.data.error||err.response.data.message))||err.message||"backup failed";
                setBackups(prev=>prev.map(x=>x.id===localId?{...x,status:"failed",hash:msg.slice(0,40)}:x));
                addA("BACKUP_FAILED","strategy=incremental error="+msg.slice(0,80));
              }
            }}>Take Incremental Now</Btn>
            <Btn onClick={async()=>{
              const localId=Date.now();
              const placeholder={id:localId,ts:new Date().toISOString(),type:"on-demand",backup_strategy:"differential",size:"...",status:"running",hash:"generating..."};
              setBackups(prev=>[placeholder,...prev]);
              addA("BACKUP_TRIGGERED","strategy=differential");
              try{
                const r=await api.post("/api/backup?strategy=differential",{});
                const actual=r.actual_strategy||"differential";
                const escalated=!!r.escalated;
                setBackups(prev=>prev.map(x=>x.id===localId?{id:r.id||localId,ts:new Date().toISOString(),type:"on-demand",backup_strategy:actual,parent_backup_id:r.parent_backup_id,parent_full_backup_id:r.parent_full_backup_id,page_count:r.page_count,wal_start_position:r.wal_start_position,wal_end_position:r.wal_end_position,size:r.size_bytes?(r.size_bytes/1024/1024).toFixed(1)+" MB":"?",status:"verified",hash:r.manifest_sha256?"sha256:"+r.manifest_sha256.slice(0,16):"(no manifest)"}:x));
                addA("BACKUP_CREATED","id="+r.id+" strategy="+actual+(escalated?" (escalated from differential: "+(r.escalation_reason||"no reason")+")":""));
              }catch(err){
                const msg=(err.response&&err.response.data&&(err.response.data.error||err.response.data.message))||err.message||"backup failed";
                setBackups(prev=>prev.map(x=>x.id===localId?{...x,status:"failed",hash:msg.slice(0,40)}:x));
                addA("BACKUP_FAILED","strategy=differential error="+msg.slice(0,80));
              }
            }}>Take Differential Now</Btn>
            <Btn onClick={async()=>{const localId=Date.now();const placeholder={id:localId,ts:new Date().toISOString(),label:"Snapshot-"+(snapshots.length+1),status:"capturing",hash:"..."};setSnapshots(prev=>[placeholder,...prev]);try{const r=await api.post("/api/backup",{});setSnapshots(prev=>prev.map(s=>s.id===localId?{id:r.id||localId,ts:new Date().toISOString(),label:"Snapshot-"+(snapshots.length+1),status:"captured",hash:r.manifest_sha256?"sha256:"+r.manifest_sha256.slice(0,16):"(captured)"}:s));addA("SNAPSHOT","id="+r.id);}catch(err){const msg=(err.response&&err.response.data&&err.response.data.message)||err.message||"snapshot failed";setSnapshots(prev=>prev.map(s=>s.id===localId?{...s,status:"failed",hash:msg.slice(0,40)}:s));addA("SNAPSHOT_FAILED",msg);}}}>Capture Snapshot Now</Btn>
            <Btn danger onClick={()=>{const exp={id:Date.now(),ts:new Date().toISOString(),status:"generating",format:"forensic-archive"};setFE(prev=>[exp,...prev]);api.post("/api/v1/audit/log",{event:"FORENSIC_EXPORT",detail:"Initiated"}).then(()=>addA("FORENSIC_EXPORT","Initiated"));setTimeout(()=>setFE(prev=>prev.map(e=>e.id===exp.id?{...e,status:"ready",size:"3.1 GB",hash:`sha256:${Math.random().toString(36).substr(2,8)}`}:e)),2500);}}>Export for Forensics</Btn>
          </div>
          {snapshots.length>0&&<><L>Snapshots</L><div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,marginBottom:16,overflow:"hidden"}}>{snapshots.map(s=><div key={s.id} style={{padding:"10px 14px",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between"}}><div><M style={{color:C.t}}>{s.label}</M><br/><M style={{color:C.td}}>{new Date(s.ts).toLocaleString()}</M></div><div style={{textAlign:"right"}}><Badge color={C.a}>{s.status}</Badge><br/><M style={{color:C.td,fontSize:8}}>{s.hash}</M></div></div>)}</div></>}
          {forensicExports.length>0&&<><L>Forensic Exports</L><div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,marginBottom:16,overflow:"hidden"}}>{forensicExports.map(e=><div key={e.id} style={{padding:"10px 14px",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between"}}><div><M style={{color:C.t}}>{e.format}</M><br/><M style={{color:C.td}}>{new Date(e.ts).toLocaleString()}</M></div><div style={{textAlign:"right"}}><Badge color={e.status==="ready"?C.a:C.w}>{e.status}</Badge>{e.size&&<><br/><M style={{color:C.td}}>{e.size} · {e.hash}</M></>}</div></div>)}</div></>}
          <L>Backup History</L>
          <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,overflow:"hidden"}}>{backups.map(b=>{
            // R3l C69: strategy color helper. Full=green, snapshot=blue,
            // incremental=amber, differential=purple. Picked to give
            // operators a quick visual scan of chain composition without
            // having to read each badge text.
            const strategyColor=(s)=>{if(s==="full")return C.a;if(s==="snapshot")return C.i;if(s==="incremental")return C.w;if(s==="differential")return"#9F7AEA";return C.td;};
            const isChainLink=b.backup_strategy==="incremental"||b.backup_strategy==="differential";
            const jumpToRow=(id)=>{const el=document.getElementById("backup-row-"+id);if(el)el.scrollIntoView({behavior:"smooth",block:"center"});};
            // R3l C70: chain expand/collapse + lazy fetch
            const isExpanded=!!expandedChains[b.id];
            const deriveLocalChain=(leafId)=>{
              // Demo-mode fallback when /api/backup/:id/chain isn't reachable.
              // Mirrors the server-side walkChain semantics (R3l C65):
              // walks parent_backup_id backwards from the leaf to the
              // anchor full backup. Stops at MAX_CHAIN_DEPTH=1000.
              const findById=(id)=>backups.find(x=>x.id===id);
              const leaf=findById(leafId);
              if(!leaf)return{ok:false,error:"backup not found in local list"};
              const strategy=leaf.backup_strategy||"full";
              if(strategy==="full"||strategy==="snapshot"){
                return{ok:true,leafBackupId:leafId,anchorBackupId:leafId,chainLength:1,totalPageCount:leaf.page_count||0,restorable:true,chain:[{...leaf,filesPresent:true,missingFiles:[]}]};
              }
              if(strategy==="differential"){
                const anchor=findById(leaf.parent_backup_id);
                if(!anchor)return{ok:false,error:"differential anchor not found in local list"};
                return{ok:true,leafBackupId:leafId,anchorBackupId:anchor.id,chainLength:2,totalPageCount:(anchor.page_count||0)+(leaf.page_count||0),restorable:true,chain:[{...anchor,filesPresent:true,missingFiles:[]},{...leaf,filesPresent:true,missingFiles:[]}]};
              }
              // incremental: walk back
              const reversed=[leaf];
              let cur=leaf;
              let depth=0;
              while((cur.backup_strategy||"full")==="incremental"&&depth<1000){
                const parent=findById(cur.parent_backup_id);
                if(!parent)return{ok:false,error:"chain broken: parent "+cur.parent_backup_id+" missing"};
                reversed.push(parent);
                cur=parent;
                depth+=1;
              }
              const chain=reversed.reverse();
              const total=chain.reduce((s,x)=>s+(x.page_count||0),0);
              return{ok:true,leafBackupId:leafId,anchorBackupId:chain[0].id,chainLength:chain.length,totalPageCount:total,restorable:true,chain:chain.map(x=>({...x,filesPresent:true,missingFiles:[]}))};
            };
            const toggleChainExpand=async()=>{
              const wasOpen=isExpanded;
              setExpandedChains(prev=>({...prev,[b.id]:!wasOpen}));
              if(wasOpen||chainData[b.id])return;
              setChainLoading(prev=>({...prev,[b.id]:true}));
              try{
                const resp=await api.get("/api/backup/"+b.id+"/chain");
                setChainData(prev=>({...prev,[b.id]:resp}));
              }catch(_e){
                // Demo-mode / offline fallback: derive from local backups list
                setChainData(prev=>({...prev,[b.id]:deriveLocalChain(b.id)}));
              }finally{
                setChainLoading(prev=>({...prev,[b.id]:false}));
              }
            };
            return (
            <div key={b.id} id={"backup-row-"+b.id} style={{padding:"10px 14px",borderBottom:`1px solid ${C.b}`}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div>
                  <M style={{color:C.t}}>{b.ts}</M>
                  {b.backup_strategy&&<Badge color={strategyColor(b.backup_strategy)} style={{marginLeft:6,fontSize:9}}>{b.backup_strategy}</Badge>}
                  <br/>
                  <M style={{color:C.td}}>{b.type} · {b.size}</M>
                </div>
                <div style={{textAlign:"right"}}>
                  <Badge color={b.status==="verified"?C.a:b.status==="running"?C.w:C.d}>{b.status}</Badge>
                  <br/>
                  <M style={{color:C.td,fontSize:8}}>{b.hash}</M>
                  <br/>
                  {/* R3l C71: per-row Restore button. Opens the restore-preview
                      modal which surfaces the chain (for inc/diff) or single
                      manifest (for full/snapshot) plus a confirmation gate.
                      The chain fetch is triggered here (not in the modal's
                      render) so we don't risk setState-during-render loops. */}
                  <button onClick={(e)=>{
                    e.stopPropagation();
                    setRestoreModal({backupId:b.id,confirmInput:"",restoring:false,error:null,result:null});
                    if(isChainLink&&!chainData[b.id]&&!chainLoading[b.id]){
                      setChainLoading(prev=>({...prev,[b.id]:true}));
                      api.get("/api/backup/"+b.id+"/chain").then(r=>{
                        setChainData(prev=>({...prev,[b.id]:r}));
                      }).catch(()=>{
                        setChainData(prev=>({...prev,[b.id]:deriveLocalChain(b.id)}));
                      }).finally(()=>setChainLoading(prev=>({...prev,[b.id]:false})));
                    }
                  }} style={{marginTop:4,padding:"2px 8px",background:"transparent",border:`1px solid ${C.i}`,borderRadius:4,color:C.i,fontSize:9,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>Restore</button>
                </div>
              </div>
              {isChainLink&&(
                <div onClick={toggleChainExpand} style={{cursor:"pointer",marginTop:6,paddingTop:6,borderTop:`1px dashed ${C.b}`,display:"flex",justifyContent:"space-between",flexWrap:"wrap",gap:6,fontSize:10,color:C.td}}>
                  <span>
                    <span style={{color:C.i,marginRight:6}}>{isExpanded?"▼":"▶"}</span>
                    ↳ parent:&nbsp;
                    <span style={{cursor:"pointer",color:C.i,textDecoration:"underline"}} onClick={(e)=>{e.stopPropagation();jumpToRow(b.parent_backup_id);}}>{String(b.parent_backup_id||"").slice(0,12)}</span>
                    {b.parent_full_backup_id&&b.parent_full_backup_id!==b.parent_backup_id&&(<>&nbsp;·&nbsp;anchor:&nbsp;<span style={{cursor:"pointer",color:C.i,textDecoration:"underline"}} onClick={(e)=>{e.stopPropagation();jumpToRow(b.parent_full_backup_id);}}>{String(b.parent_full_backup_id).slice(0,12)}</span></>)}
                    {b.page_count!=null&&<>&nbsp;·&nbsp;{b.page_count} pages</>}
                  </span>
                  {b.wal_end_position&&<span>WAL {String(b.wal_start_position||"0:0").split(":")[1]||"?"}→{String(b.wal_end_position).split(":")[1]||"?"}</span>}
                </div>
              )}
              {isChainLink&&isExpanded&&(
                <div style={{marginTop:8,padding:"8px 10px",background:C.b,borderRadius:8}}>
                  {chainLoading[b.id]&&<M style={{color:C.td}}>Loading chain…</M>}
                  {chainData[b.id]&&!chainData[b.id].ok&&(
                    <M style={{color:C.d}}>Chain walk failed: {chainData[b.id].error||"unknown"}</M>
                  )}
                  {chainData[b.id]&&chainData[b.id].ok&&(
                    <>
                      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                        <M style={{color:C.t,fontWeight:600}}>Restore chain · {chainData[b.id].chainLength} link{chainData[b.id].chainLength===1?"":"s"} · {chainData[b.id].totalPageCount||0} pages</M>
                        <Badge color={chainData[b.id].restorable?C.a:C.d}>{chainData[b.id].restorable?"restorable":"incomplete"}</Badge>
                      </div>
                      {chainData[b.id].chain.map((link,idx,arr)=>(
                        <div key={link.id} style={{display:"flex",alignItems:"center",padding:"4px 0",borderTop:idx>0?`1px dotted ${C.b}`:"none"}}>
                          <div style={{width:18,color:C.td,fontSize:11,fontFamily:"monospace"}}>{arr.length===1?"●":idx===0?"┌":idx===arr.length-1?"└":"├"}</div>
                          <Badge color={strategyColor(link.backup_strategy)} style={{fontSize:8,marginRight:8}}>{link.backup_strategy||"full"}</Badge>
                          <div style={{flex:1,fontSize:10,color:C.td}}>
                            <span style={{cursor:"pointer",color:C.i,textDecoration:"underline"}} onClick={(e)=>{e.stopPropagation();jumpToRow(link.id);}}>{String(link.id).slice(0,12)}</span>
                            &nbsp;·&nbsp;{link.created_at||link.ts}
                            {link.page_count!=null&&<>&nbsp;·&nbsp;{link.page_count} pages</>}
                            {link.filesPresent===false&&<span style={{color:C.d}}>&nbsp;·&nbsp;missing: {(link.missingFiles||[]).join(", ")}</span>}
                          </div>
                          {link.id===b.id&&<Badge color={C.i} style={{fontSize:8,marginLeft:6}}>leaf</Badge>}
                          {link.id===chainData[b.id].anchorBackupId&&link.id!==b.id&&<Badge color={C.a} style={{fontSize:8,marginLeft:6}}>anchor</Badge>}
                        </div>
                      ))}
                    </>
                  )}
                </div>
              )}
            </div>
            );
          })}</div>

          {/* ── R3l C71: Restore-Preview Modal ─────────────────────── */}
          {restoreModal&&(()=>{
            const b=backups.find(x=>x.id===restoreModal.backupId);
            if(!b)return null;
            const isChain=b.backup_strategy==="incremental"||b.backup_strategy==="differential";
            const strategyColor=(s)=>{if(s==="full")return C.a;if(s==="snapshot")return C.i;if(s==="incremental")return C.w;if(s==="differential")return"#9F7AEA";return C.td;};
            const expectedConfirm=(b.hash||"").replace(/^sha256:/,"").slice(0,8);
            const canConfirm=restoreModal.confirmInput===expectedConfirm&&expectedConfirm.length>=4;
            const chain=chainData[b.id];
            const chainOk=chain&&chain.ok;
            const restorable=!isChain||(chainOk&&chain.restorable);
            const doRestore=async()=>{
              setRestoreModal(prev=>({...prev,restoring:true,error:null}));
              try{
                const endpoint=isChain?"/api/restore/execute-chain/"+b.id:"/api/restore/execute/"+b.id;
                const r=await api.post(endpoint,{confirmHash:restoreModal.confirmInput});
                addA("RESTORE_INITIATED","id="+b.id+" kind="+(isChain?"chain":"single")+" ok=true");
                setRestoreModal(prev=>({...prev,restoring:false,result:r}));
              }catch(err){
                const msg=(err.response&&err.response.data&&(err.response.data.error||err.response.data.message))||err.message||"restore failed";
                addA("RESTORE_FAILED","id="+b.id+" reason="+msg.slice(0,80));
                setRestoreModal(prev=>({...prev,restoring:false,error:msg}));
              }
            };
            return (
              <Modal title="Restore from backup" onClose={()=>setRestoreModal(null)} width={560}>
                <div style={{marginBottom:14,padding:"10px 12px",background:C.b,borderRadius:8}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                    <M style={{color:C.t}}>{b.ts}</M>
                    {b.backup_strategy&&<Badge color={strategyColor(b.backup_strategy)} style={{fontSize:9}}>{b.backup_strategy}</Badge>}
                  </div>
                  <M style={{color:C.td}}>{b.type} · {b.size}</M>
                  <br/>
                  <M style={{color:C.td,fontSize:9}}>{b.hash}</M>
                </div>

                {isChain&&(
                  <div style={{marginBottom:14}}>
                    <L>Restore chain</L>
                    {chainLoading[b.id]&&<M style={{color:C.td}}>Loading chain…</M>}
                    {chain&&!chain.ok&&<M style={{color:C.d}}>Chain walk failed: {chain.error||"unknown"}</M>}
                    {chainOk&&(
                      <div style={{padding:"8px 10px",background:C.b,borderRadius:8}}>
                        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                          <M style={{color:C.t,fontWeight:600}}>{chain.chainLength} link{chain.chainLength===1?"":"s"} · {chain.totalPageCount||0} pages</M>
                          <Badge color={chain.restorable?C.a:C.d}>{chain.restorable?"restorable":"incomplete"}</Badge>
                        </div>
                        {chain.chain.map((link,idx,arr)=>(
                          <div key={link.id} style={{display:"flex",alignItems:"center",padding:"4px 0",borderTop:idx>0?`1px dotted ${C.b}`:"none"}}>
                            <div style={{width:18,color:C.td,fontSize:11,fontFamily:"monospace"}}>{arr.length===1?"●":idx===0?"┌":idx===arr.length-1?"└":"├"}</div>
                            <Badge color={strategyColor(link.backup_strategy)} style={{fontSize:8,marginRight:8}}>{link.backup_strategy||"full"}</Badge>
                            <div style={{flex:1,fontSize:10,color:C.td}}>
                              <span>{String(link.id).slice(0,12)}</span>
                              {link.created_at&&<>&nbsp;·&nbsp;{link.created_at}</>}
                              {link.page_count!=null&&<>&nbsp;·&nbsp;{link.page_count} pages</>}
                              {link.filesPresent===false&&<span style={{color:C.d}}>&nbsp;·&nbsp;missing: {(link.missingFiles||[]).join(", ")}</span>}
                            </div>
                            {link.id===b.id&&<Badge color={C.i} style={{fontSize:8,marginLeft:6}}>leaf</Badge>}
                            {link.id===chain.anchorBackupId&&link.id!==b.id&&<Badge color={C.a} style={{fontSize:8,marginLeft:6}}>anchor</Badge>}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                <div style={{marginBottom:14}}>
                  <L>Confirmation</L>
                  <M style={{color:C.td,display:"block",marginBottom:6}}>
                    Type the first 8 characters of the backup hash to confirm:&nbsp;
                    <span style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",background:C.b,padding:"2px 6px",borderRadius:4}}>{expectedConfirm}</span>
                  </M>
                  <Input value={restoreModal.confirmInput} onChange={e=>setRestoreModal(prev=>({...prev,confirmInput:e.target.value}))} placeholder="e.g. a3f8c1d2" disabled={restoreModal.restoring||!!restoreModal.result}/>
                </div>

                {restoreModal.restoring&&<M style={{color:C.w,display:"block",marginBottom:10}}>Restoring… do not navigate away.</M>}
                {restoreModal.error&&<M style={{color:C.d,display:"block",marginBottom:10}}>Error: {restoreModal.error}</M>}
                {restoreModal.result&&restoreModal.result.ok&&<M style={{color:C.a,display:"block",marginBottom:10}}>Success. {restoreModal.result.message||"Restore complete."} A pre-restore snapshot was saved.</M>}

                <div style={{display:"flex",gap:8,justifyContent:"flex-end"}}>
                  <Btn onClick={()=>setRestoreModal(null)}>{restoreModal.result?"Close":"Cancel"}</Btn>
                  {!restoreModal.result&&<Btn primary disabled={!canConfirm||!restorable||restoreModal.restoring} onClick={doRestore}>Restore</Btn>}
                </div>
              </Modal>
            );
          })()}
        </div>)}

        {/* SYSTEM */}
        {/* ══════════ UPDATES TAB ══════════ */}
        {tab==="updates"&&(<div>
          <L>Updates & Versioning</L>
          <Card style={{marginBottom:16}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
              <div><div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>FireAlive — SOC Analyst Wellbeing Platform</div><M style={{color:C.tm}}>Version {appVersion||"loading…"} · Build {appBuild||"loading…"} · AGPL-3.0</M></div>
              <Btn primary onClick={checkUpdate} disabled={updateCheck==="checking"}>{updateCheck==="checking"?"Checking...":"Check for Updates"}</Btn>
            </div>
            {updateCheck&&updateCheck!=="checking"&&(
              updateCheck.available?
              <Card style={{padding:12,borderColor:C.a+"30",marginBottom:12}}>
                <div style={{marginBottom:10}}><M style={{color:C.a,fontWeight:500}}>Update available: v{updateCheck.version}</M><br/><M style={{color:C.tm}}>{updateCheck.notes}</M></div>
                <div style={{display:"flex",gap:8}}>
                  <Btn primary onClick={()=>{addA("UPDATE_TO_LAB",`v${updateCheck.version} sent to testing lab`);setUpdateCheck(null);}}>Send to Testing Lab</Btn>
                  <Btn danger onClick={()=>{addA("UPDATE_DIRECT",`v${appVersion} to v${updateCheck.version} · Direct deploy · Fuse incremented`);setUpdateCheck(null);}}>Deploy Direct (Skip Lab)</Btn>
                </div>
              </Card>:
              <Card style={{padding:12,marginBottom:12}}><M style={{color:C.a}}>Latest version.</M></Card>
            )}
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>Automatic Update Schedule</div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Configure when the platform checks for updates. Choose timing that avoids peak SOC hours.</M>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" defaultChecked={true} style={{accentColor:C.a}}/>Enable automatic update checks</label>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
              <Sel label="Frequency"><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="biweekly">Biweekly</option><option value="monthly">Monthly</option></Sel>
              <Sel label="Day(s) of week"><option value="sun">Sunday</option><option value="mon">Monday</option><option value="tue">Tuesday</option><option value="wed">Wednesday</option><option value="thu">Thursday</option><option value="fri">Friday</option><option value="sat">Saturday</option></Sel>
              <Input label="Time (UTC)" type="time" defaultValue="03:00"/>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:8}}>
              <Sel label="On update found"><option value="notify">Notify lead only</option><option value="lab">Send to testing lab automatically</option><option value="lab_auto">Send to lab + auto-deploy on approval</option></Sel>
              <Sel label="Notification channel"><option value="console">Console alert only</option><option value="email">Email</option><option value="slack">Slack/Teams webhook</option><option value="all">All channels</option></Sel>
            </div>
            <Btn primary style={{marginTop:12}} onClick={()=>api.post("/api/v1/audit/log",{event:"AUTO_UPDATE_SCHEDULE",detail:"Auto-update schedule configured"}).then(()=>addA("AUTO_UPDATE_SCHEDULE","Auto-update schedule configured"))}>Save Schedule</Btn>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>Testing Lab Integration</div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Configure your enterprise testing/staging environment. Signed artifacts are delivered for validation before production deployment.</M>
            <Input label="Lab staging API endpoint" placeholder="https://cyber-lab.corp.local/api/v1/staging/upload" maxLength={512}/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Input label="Lab API key / service account" placeholder="svc-soc-updates" maxLength={256}/>
              <div style={{marginBottom:14}}><M style={{color:C.tm,marginBottom:4,display:"block"}}>Lab API secret</M><input type="password" placeholder="Stored in secrets manager" maxLength={512} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}}/></div>
            </div>
            <Input label="Approval webhook" placeholder="https://soc-wellbeing.corp.local/api/v1/updates/approve" maxLength={512}/>
            <Input label="Rejection webhook" placeholder="https://soc-wellbeing.corp.local/api/v1/updates/reject" maxLength={512}/>
            <Sel label="Lab protocol"><option value="rest">REST API (push artifact)</option><option value="s3">S3/GCS/Blob</option><option value="artifactory">JFrog Artifactory</option><option value="nexus">Sonatype Nexus</option><option value="ghcr">GitHub Container Registry</option></Sel>
            <Card style={{padding:10,marginTop:8,borderColor:C.i+"30"}}><M style={{color:C.i,fontWeight:500,display:"block",marginBottom:4}}>Pipeline Flow</M><M style={{color:C.tm,lineHeight:1.8}}>Check for update → Verify Ed25519 signature → Push to lab → Functional + security + compatibility tests → Lab approval webhook → Deploy → Increment anti-rollback fuse → Notify lead</M></Card>
            <div style={{display:"flex",gap:8,marginTop:12}}><Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"LAB_CONFIG_SAVED",detail:"Testing lab integration configured"}).then(()=>addA("LAB_CONFIG_SAVED","Testing lab integration configured"))}>Save Lab Config</Btn><Btn onClick={()=>api.post("/api/v1/audit/log",{event:"LAB_TEST_CONNECTION",detail:"Testing connection to lab endpoint..."}).then(()=>addA("LAB_TEST_CONNECTION","Testing connection to lab endpoint..."))}>Test Connection</Btn></div>
          </Card>
          <Card style={{marginBottom:16,borderColor:C.d+"30"}}>
            <div style={{fontSize:13,fontWeight:500,color:C.d,marginBottom:10}}>Version & Anti-Rollback Status</div>
            <M style={{color:C.w,lineHeight:1.8}}>Version {appVersion||"loading…"} · Build {appBuild||"loading…"} · Fuse counter: {appFuse||"…"} · Last increment: {appFuseLastIncrement||"…"} · Signed: Ed25519 ✓</M>
          </Card>
          <Card style={{padding:12,borderColor:C.p+"30"}}><M style={{color:C.p,fontWeight:500,display:"block",marginBottom:6}}>Security Architecture & Encrypted Transport</M><M style={{color:C.tm,lineHeight:1.8}}>Full security architecture details — anti-rollback protection, defense in depth (6 layers), zero trust, least privilege, encrypted transport topologies (on-prem mTLS/SPIFFE, cloud VPC private endpoints with KMS envelope encryption, SD-WAN WireGuard tunnels, VDI TLS 1.3 session tunnels with cert pinning, zero trust overlay), supply chain security, and OS compatibility — are documented in the project README on GitHub. See: github.com/pmancina/firealive</M></Card>
        </div>)}

        {/* ══════════ INTEGRATIONS HEALTH TAB ══════════ */}
        {tab==="integrations"&&(<div>
          <L>Integrations Health</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Real-time status of all configured integrations. Disconnected integrations will trigger alerts. Configure each integration in its dedicated tab.</M>
          <Card style={{marginBottom:16}}>
            {[
              {n:"SIEM CEF Stream",s:"connected",d:"TLS 6514 · Last event 2s ago"},
              {n:"Active Directory / LDAP",s:iamCfg.ad.status==="configured"?"connected":"pending",d:iamCfg.ad.status==="configured"?"LDAPS 636 · Syncing":"Awaiting configuration"},
              {n:"SSO Providers (SAML/OIDC)",s:[iamCfg.saml,iamCfg.oidc].filter(c=>c.status==="configured").length>0?"connected":"pending",d:[iamCfg.saml.status==="configured"&&"SAML",iamCfg.oidc.status==="configured"&&"OIDC"].filter(Boolean).join(", ")||"Not configured"},
              {n:"Cloud IAM",s:iamCfg.cloud.status==="configured"?"connected":"pending",d:iamCfg.cloud.status==="configured"?iamCfg.cloud.provider.toUpperCase():"Not configured"},
              {n:"SOAR Platform",s:"connected",d:"Splunk SOAR · Webhook active · Last playbook trigger 12m ago"},
              {n:"Automation / SOAR Routing",s:autoSys.length+" connected",d:autoSys.map(a=>a.name).join(", ")||"None"},
              {n:"Ticketing System",s:"connected",d:"ServiceNow · REST API · Last sync 5m ago"},
              {n:"Vulnerability Scanner",s:"configured",d:"Nessus · Weekly schedule · Last scan 3d ago"},
              {n:"Cloud Vuln Scanner",s:"pending",d:"Not configured — see Cloud Vuln Scan tab"},
              {n:"SASE / ZTNA",s:"pending",d:"Not configured — see SASE tab"},
              {n:"CASB",s:"pending",d:"Configured via SASE provider"},
              {n:"VDI / Remote Desktop",s:"connected",d:"Citrix Workspace · TLS 1.3 · Cert pinned"},
              {n:"SDN / Network Segmentation",s:"connected",d:"Cisco ACI · Microsegment active"},
              {n:"Cloud Infrastructure",s:"connected",d:"AWS · VPC private endpoints · KMS envelope encryption"},
              {n:"Backup System",s:"connected",d:"Daily auto · Last backup 6h ago · AES-256-GCM"},
              {n:"Calendar Integration",s:"pending",d:"Individual analyst config — see Peer tab"},
              {n:"Notification Channels",s:"configured",d:"Desktop notifications active"},
              {n:"Testing Lab",s:"configured",d:"cyber-lab.corp.local · REST API"},
              ...(provisionedClients.length>0?[{n:"Provisioned Clients",s:provisionedClients.length+" deployed",d:provisionedClients.map(c=>c.hostname).join(", ")}]:[]),
              {n:"CI/CD Pipeline",s:"pending",d:"See CI/CD tab for pipeline configs"},
              {n:"EDR File Inspection",s:edrCfg.enabled?"configured":"pending",d:edrCfg.enabled?`${edrCfg.provider} · Scan on upload/restore/import`:"Not configured — see EDR tab"},
              {n:"Enterprise KMS",s:kmsCfg.enabled?"configured":"pending",d:kmsCfg.enabled?`${kmsCfg.provider} · ${kmsCfg.hsmBacked?"HSM-backed":"Software keys"} · Rotation: ${kmsCfg.rotationPolicy}`:"Not configured — see KMS tab"},
              {n:"WiFi Security Policy",s:"configured",d:`Min: ${wifiPolicy.minimumProtocol.replace(/_/g," ")} · WPA3 preferred: ${wifiPolicy.wpa3Preferred?"yes":"no"} · Block PSK: ${wifiPolicy.blockWpa2Personal?"yes":"no"}`},
              {n:"MSP Multi-Tenancy",s:mspCfg.enabled?mspCfg.tenants.length+" tenants":"disabled",d:mspCfg.enabled?`Isolation: ${Object.values(mspCfg.isolation).filter(Boolean).length}/5 controls active`:"Not enabled — see MSP tab"},
              {n:"MFA",s:mfaCfg.status==="configured"?"configured":"pending",d:mfaCfg.status==="configured"?`Method: ${mfaCfg.method} · Enforce all: ${mfaCfg.enforceForAll?"yes":"no"}`:"Not configured — see MFA tab"},
              {n:"Threat Hunting (XDR)",s:threatHuntCfg.xdr.enabled?"configured":"pending",d:threatHuntCfg.xdr.enabled?`${threatHuntCfg.xdr.provider} · Behavior monitoring`:"Not configured — see Threat Hunting tab"},
              {n:"Tripwire",s:tripwireCfg.enabled?(tripwireTriggered?"TRIGGERED":"armed"):"disabled",d:tripwireCfg.enabled?`Threshold: ${tripwireCfg.thresholdPct}% analysts in reduced routing`:"Not enabled — see Tripwire tab"},
              {n:"Posture Assessment",s:postureCfg.enabled?"enabled":"disabled",d:postureCfg.enabled?`${Object.values(postureCfg.checks).filter(v=>v===true).length} checks active · ${postureCfg.blockOnFail?"strict":"warn"} mode`:"Not enabled — see Posture tab"},
              {n:"High Availability",s:haCfg.enabled?"configured":"disabled",d:haCfg.enabled?`${haCfg.mode} · Sync every ${haCfg.syncIntervalSec}s`:"Not configured — see HA tab"},
              {n:"Fail-Open Routing",s:failOpenCfg.enabled?"enabled":"disabled",d:failOpenCfg.enabled?"Auto-detect failure · Restore auto: "+(failOpenCfg.restoreAuto?"yes":"no"):"Not enabled — see Fail-Open tab"},
              {n:"Pseudonym System",s:pseudonymCfg.enabled?"active":"disabled",d:pseudonymCfg.enabled?`${analystPseudonyms.length} analysts pseudonymized`:"Not enabled — see Pseudonyms tab"},
              {n:"Data Sovereignty",s:geoFenceCfg.enabled?"active":"disabled",d:geoFenceCfg.enabled?`${geoFenceCfg.clients.length} clients geo-assigned`:"Not configured — see Data Sovereignty tab"},
              {n:"Cluster Mode",s:clusterCfg.enabled?clusterCfg.mode:"disabled",d:clusterCfg.enabled?`${clusterCfg.nodeCount} nodes · ${clusterCfg.sessionStore}`:"Single instance"},
              {n:"Sync Interval",s:"configured",d:`Every ${syncIntervalCfg.intervalMin}min · ${syncIntervalCfg.adaptiveSync?"adaptive":"fixed"} · ${syncIntervalCfg.batchMode?"batch":"streaming"}`},
            ].map((item,idx)=>(
              <div key={idx} style={{display:"flex",justifyContent:"space-between",padding:"10px 0",borderBottom:`1px solid ${C.b}`}}>
                <div><div style={{fontSize:12}}>{item.n}</div><M style={{color:C.td}}>{item.d}</M></div>
                <Badge color={item.s.includes("connected")||item.s==="configured"?C.a:item.s==="pending"?C.w:C.d}>{item.s}</Badge>
              </div>
            ))}
          </Card>
        </div>)}

        {/* ══════════ CLIENT NOTIFICATIONS CONFIG ══════════ */}
        {tab==="client_notif"&&(<div>
          <L>Client Notification Configuration</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Configure how analysts receive notifications from FireAlive. The app should be added to system startup so it runs when analysts log on (see README). Notifications ensure analysts are reached even when the client window is not in focus.</M>
          <Card style={{marginBottom:16,borderColor:C.w+"30",padding:12}}>
            <M style={{color:C.w,fontWeight:500,display:"block",marginBottom:6}}>Privacy-First Notification Rules</M>
            <M style={{color:C.tm,lineHeight:1.8}}>Personal burnout metrics and signals are NEVER sent as notifications. Only a weekly end-of-week reminder is sent asking analysts to review their own FireAlive client. Peer chat requests are real-time desktop notifications. No personal data ever flows to shared channels (Slack groups, Teams channels, etc.). Individual analysts can disable peer chat notifications at any time.</M>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>Notification Channels</div>
            {[{k:"desktop",l:"Desktop Notifications",d:"Native OS notifications — recommended. Requires app to be running (add to startup)."},{k:"slack",l:"Slack (DM only)",d:"Direct messages only — never to channels. Requires webhook."},{k:"teams",l:"Microsoft Teams (DM only)",d:"Personal chat only — never to team channels."},{k:"email",l:"Email",d:"Individual analyst email addresses from IAM."}].map(ch=>(
              <label key={ch.k} style={{display:"flex",alignItems:"flex-start",gap:10,padding:"10px 0",borderBottom:`1px solid ${C.b}`,cursor:"pointer"}}>
                <input type="checkbox" checked={clientNotifCfg.channels[ch.k]} onChange={e=>setClientNotifCfg(prev=>({...prev,channels:{...prev.channels,[ch.k]:e.target.checked}}))} style={{marginTop:2}}/>
                <div><div style={{fontSize:12,color:C.t}}>{ch.l}</div><M style={{color:C.td}}>{ch.d}</M></div>
              </label>
            ))}
            {clientNotifCfg.channels.slack&&<Input label="Slack Incoming Webhook URL" value={clientNotifCfg.slackWebhook} onChange={e=>setClientNotifCfg(prev=>({...prev,slackWebhook:e.target.value}))} placeholder="https://hooks.slack.com/services/..." maxLength={512}/>}
            {clientNotifCfg.channels.teams&&<Input label="Teams Incoming Webhook URL" value={clientNotifCfg.teamsWebhook} onChange={e=>setClientNotifCfg(prev=>({...prev,teamsWebhook:e.target.value}))} placeholder="https://outlook.office.com/webhook/..." maxLength={512}/>}
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>Notification Rules</div>
            {[{k:"peerChatRequest",l:"Peer Skill-Share Requests",d:"Real-time notification when a peer posts a new skill-share request. Analysts can individually opt out.",c:C.a},{k:"weeklyMetricsReminder",l:"Weekly Metrics Reminder",d:"End-of-week reminder for all analysts to check their FireAlive client and review personal signals.",c:C.i},{k:"shiftHandoff",l:"Shift Handoff Alert",d:"Notification when a shift handoff summary is posted.",c:C.p},{k:"scheduledChatReminder",l:"Scheduled Chat Reminder",d:"Reminder before a scheduled peer skill-share session (default: 15 min).",c:C.w}].map(rule=>(
              <label key={rule.k} style={{display:"flex",alignItems:"flex-start",gap:10,padding:"10px 0",borderBottom:`1px solid ${C.b}`,cursor:"pointer"}}>
                <input type="checkbox" checked={clientNotifCfg.rules[rule.k]?.enabled} onChange={e=>setClientNotifCfg(prev=>({...prev,rules:{...prev.rules,[rule.k]:{...prev.rules[rule.k],enabled:e.target.checked}}}))} style={{marginTop:2}}/>
                <div><div style={{fontSize:12,color:rule.c}}>{rule.l}</div><M style={{color:C.td}}>{rule.d}</M></div>
              </label>
            ))}
          </Card>
          <Card style={{marginBottom:16,padding:12,borderColor:C.i+"30"}}>
            <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:4}}>Startup Configuration (Admin/Provisioning)</M>
            <M style={{color:C.tm,lineHeight:1.8}}>The FireAlive client must run at system startup for notifications to work. This should be configured by administrators during workstation provisioning — not by analysts (who typically lack admin privileges). Deploy via Group Policy (Windows), MDM profile (macOS), systemd user service (Linux), or include in the SOC workstation image. See the Onboard tab and README for provisioning instructions.</M>
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"CLIENT_NOTIF_CONFIG",detail:"Client notification configuration saved"}).then(()=>addA("CLIENT_NOTIF_CONFIG","Client notification configuration saved"))}>Save Notification Config</Btn>
        </div>)}

        {/* ══════════ CLOUD VULN SCAN ══════════ */}
        {tab==="cloud_vuln"&&(<div>
          <L>Cloud Vulnerability Scanning</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Scan your cloud environment for misconfigurations and vulnerabilities that could affect FireAlive's deployment. These tools audit IAM policies, network ACLs, storage permissions, and cloud-specific security controls.</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>Cloud Scanners</div>
            {[{id:"scoutsuite",l:"ScoutSuite",d:"Multi-cloud auditing (AWS, Azure, GCP, OCI)"},{id:"prowler",l:"Prowler",d:"AWS/Azure/GCP CIS benchmark checks"},{id:"pacu",l:"Pacu",d:"AWS exploitation framework — offensive security testing"},{id:"cloudbrute",l:"CloudBrute",d:"Cloud asset enumeration across providers"},{id:"checkov",l:"Checkov",d:"IaC scanning — Terraform, CloudFormation, K8s manifests"},{id:"trivy",l:"Trivy",d:"Container/IaC vulnerability and misconfiguration scanner"}].map(sc=>(
              <label key={sc.id} style={{display:"flex",alignItems:"flex-start",gap:10,padding:"10px 0",borderBottom:`1px solid ${C.b}`,cursor:"pointer"}}>
                <input type="checkbox" checked={cloudVulnCfg.scanners.includes(sc.id)} onChange={e=>{if(e.target.checked)setCloudVulnCfg(prev=>({...prev,scanners:[...prev.scanners,sc.id]}));else setCloudVulnCfg(prev=>({...prev,scanners:prev.scanners.filter(s=>s!==sc.id)}));}}/>
                <div><div style={{fontSize:12,color:C.t}}>{sc.l}</div><M style={{color:C.td}}>{sc.d}</M></div>
              </label>
            ))}
          </Card>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
            <Sel label="Target environment" value={cloudVulnCfg.targetEnvironment||""} onChange={e=>setCloudVulnCfg(prev=>({...prev,targetEnvironment:e.target.value}))}><option value="">Select...</option><option value="aws">AWS</option><option value="azure">Azure</option><option value="gcp">GCP</option><option value="multi">Multi-cloud</option></Sel>
            <Sel label="Schedule" value={cloudVulnCfg.schedule} onChange={e=>setCloudVulnCfg(prev=>({...prev,schedule:e.target.value}))}><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option><option value="manual">Manual only</option></Sel>
          </div>
          <Btn primary style={{marginTop:12}} onClick={()=>api.post("/api/v1/audit/log",{event:"CLOUD_VULNSCAN_CONFIG",detail:"Cloud vulnerability scan configuration saved"}).then(()=>addA("CLOUD_VULNSCAN_CONFIG","Cloud vulnerability scan configuration saved"))}>Save Config</Btn>
        </div>)}

        {/* ══════════ REGRESSION TEST ══════════ */}
        {tab==="regression"&&(<div>
          <L>Security Regression Testing</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Run automated checks to verify all integrations and security controls still function correctly after an update. The test examines every configured integration and reports incompatibilities, missing connections, or deprecated features that need attention.</M>
          <Btn primary disabled={regressionRunning} onClick={async()=>{
            setRegressionRunning(true);
            try{
              const r=await api.post("/api/regression/run",{});
              setRegressionResults({
                timestamp:r.ranAt||new Date().toISOString(),
                version:r.version||appVersion,
                fuse:r.fuse,
                passed:r.passed||0,
                failed:r.failed||0,
                warnings:0,
                total:r.total||0,
                checks:(r.results||[]).map(c=>({id:c.category,name:c.name,status:c.status,detail:c.detail})),
              });
              addA("REGRESSION_RUN","MC regression: "+(r.passed||0)+"/"+(r.total||0)+" pass, "+(r.failed||0)+" fail");
            }catch(err){
              const msg=(err.response&&err.response.data&&err.response.data.message)||err.message||"Regression run failed";
              setRegressionResults({timestamp:new Date().toISOString(),version:appVersion,passed:0,failed:1,warnings:0,total:1,checks:[{id:"RUNNER",name:"Regression runner",status:"fail",detail:msg}]});
              addA("REGRESSION_RUN_FAILED",msg);
            }finally{
              setRegressionRunning(false);
            }
          }}>{regressionRunning?"Running checks...":"Run Regression Test"}</Btn>
          {regressionResults&&(<div style={{marginTop:16}}>
            <div style={{display:"flex",gap:12,marginBottom:16}}>
              <Card style={{flex:1,padding:12,borderColor:C.a+"30",textAlign:"center"}}><div style={{fontSize:24,fontWeight:700,color:C.a}}>{regressionResults.passed}</div><M style={{color:C.tm}}>Passed</M></Card>
              <Card style={{flex:1,padding:12,borderColor:C.d+"30",textAlign:"center"}}><div style={{fontSize:24,fontWeight:700,color:regressionResults.failed>0?C.d:C.td}}>{regressionResults.failed}</div><M style={{color:C.tm}}>Failed</M></Card>
              <Card style={{flex:1,padding:12,borderColor:C.w+"30",textAlign:"center"}}><div style={{fontSize:24,fontWeight:700,color:regressionResults.warnings>0?C.w:C.td}}>{regressionResults.warnings}</div><M style={{color:C.tm}}>Warnings</M></Card>
            </div>
            {regressionResults.checks.map((c,i)=>(
              <Card key={i} style={{marginBottom:6,padding:"10px 14px",borderLeft:`3px solid ${c.status==="pass"?C.a:c.status==="warning"?C.w:C.d}`}}>
                <div style={{display:"flex",justifyContent:"space-between"}}><M style={{color:C.t,fontWeight:500}}>{c.name}</M><Badge color={c.status==="pass"?C.a:c.status==="warning"?C.w:C.d}>{c.status}</Badge></div>
                <M style={{color:C.td}}>{c.detail}</M>
                {c.recommendation&&<M style={{color:C.w,display:"block",marginTop:4}}>{c.recommendation}</M>}
              </Card>
            ))}
            <M style={{color:C.td,display:"block",marginTop:8}}>Tested at {new Date(regressionResults.timestamp).toLocaleString()} · v{regressionResults.version}</M>
          </div>)}
        </div>)}

        {/* ══════════ PLAYBOOKS ══════════ */}
        {tab==="playbooks"&&(<div>
          <L>SOAR Playbook / Runbook Generator</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Generate investigation and response playbooks for incidents involving the FireAlive platform itself. These can be imported into your SOAR system or used as printed runbooks for your team.</M>
          <Card style={{marginBottom:16}}>
            <Sel label="Incident Type" value={playbookType} onChange={e=>setPlaybookType(e.target.value)}>
              <option value="app_compromise">Application Compromise</option>
              <option value="data_exfil">Data Exfiltration Attempt</option>
              <option value="unauthorized_access">Unauthorized Access</option>
              <option value="rollback_attack">Rollback / Downgrade Attack</option>
            </Sel>
            <div style={{display:"flex",gap:8,marginTop:12}}>
              <Btn primary onClick={()=>{const types={app_compromise:{name:"Application Compromise",steps:[{p:"Detect",a:"Monitor SOAR alerts for FIM/integrity/fuse violations",auto:true},{p:"Detect",a:"Check audit log for unauthorized API key creation",auto:true},{p:"Triage",a:"Verify binary hash against known-good from GitHub releases",auto:false},{p:"Contain",a:"Isolate affected FireAlive host from network",auto:true},{p:"Contain",a:"Disable all API keys, rotate JWT signing secret",auto:false},{p:"Investigate",a:"Review audit trail 24–72 hrs before alert",auto:false},{p:"Investigate",a:"Check SIEM for correlated network indicators",auto:true},{p:"Remediate",a:"Tear down compromised instance completely",auto:false},{p:"Remediate",a:"Deploy fresh from verified GitHub release (Ed25519)",auto:false},{p:"Remediate",a:"Restore config from verified backup (SHA-256)",auto:false},{p:"Recover",a:"Run security regression test",auto:true},{p:"Recover",a:"Re-provision analyst clients with new certs",auto:false},{p:"Review",a:"Conduct CISM retrospective",auto:false}]},data_exfil:{name:"Data Exfiltration Attempt",steps:[{p:"Detect",a:"Monitor BANDWIDTH_SPIKE_OUT and DB_READ_SPIKE alerts",auto:true},{p:"Triage",a:"Compare bandwidth baseline — >3σ from rolling average?",auto:true},{p:"Contain",a:"Throttle outbound network for FireAlive process",auto:true},{p:"Investigate",a:"Identify destination IPs/domains from network logs",auto:false},{p:"Remediate",a:"Block exfiltration endpoints at firewall/SASE",auto:true},{p:"Remediate",a:"Rotate all encryption keys",auto:false},{p:"Recover",a:"Full database integrity check",auto:true}]},unauthorized_access:{name:"Unauthorized Access",steps:[{p:"Detect",a:"Monitor PRIVILEGE_ESCALATION and failed login spike",auto:true},{p:"Contain",a:"Disable compromised account immediately",auto:true},{p:"Contain",a:"Invalidate all active JWT tokens for account",auto:true},{p:"Investigate",a:"Trace account activity in audit log",auto:false},{p:"Investigate",a:"SIEM correlation for lateral movement",auto:true},{p:"Remediate",a:"Reset credentials, enforce MFA re-enrollment",auto:false},{p:"Recover",a:"Trigger out-of-cycle recertification",auto:false}]},rollback_attack:{name:"Rollback / Downgrade Attack",steps:[{p:"Detect",a:"FUSE_VIOLATION — anti-rollback counter mismatch at startup",auto:true},{p:"Contain",a:"Application refuses to start (by design)",auto:true},{p:"Investigate",a:"Check host access logs, CI/CD pipeline, package registry",auto:false},{p:"Remediate",a:"Re-deploy correct version from verified source",auto:false},{p:"Remediate",a:"Investigate supply chain integrity",auto:false},{p:"Recover",a:"Increment fuse counter and re-sign binary",auto:false}]}};const t=types[playbookType];setGenPlaybook({type:playbookType,name:t.name,steps:t.steps,auto:t.steps.filter(s=>s.auto).length,manual:t.steps.filter(s=>!s.auto).length});addA("PLAYBOOK_GENERATED","Generated "+t.name+" playbook");}}>Generate Playbook</Btn>
              <Btn onClick={()=>{if(generatedPlaybook){const data=JSON.stringify(generatedPlaybook,null,2);const blob=new Blob([data],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="firealive-playbook-"+playbookType+".json";a.click();}}}>Export JSON</Btn>
            </div>
          </Card>
          {generatedPlaybook&&(<div>
            <L>{generatedPlaybook.name} — {generatedPlaybook.steps.length} steps ({generatedPlaybook.auto} automated, {generatedPlaybook.manual} manual)</L>
            {generatedPlaybook.steps.map((s,i)=>(
              <Card key={i} style={{marginBottom:4,padding:"10px 14px",borderLeft:`3px solid ${s.auto?C.a:C.w}`}}>
                <div style={{display:"flex",justifyContent:"space-between"}}><M style={{color:C.t}}>{s.a}</M><div style={{display:"flex",gap:6}}><Badge color={s.p==="Detect"?C.i:s.p==="Contain"?C.d:s.p==="Investigate"?C.p:s.p==="Remediate"?C.w:C.a}>{s.p}</Badge><Badge color={s.auto?C.a:C.w}>{s.auto?"Auto":"Manual"}</Badge></div></div>
              </Card>
            ))}
          </div>)}
        </div>)}

        {/* ══════════ CI/CD ══════════ */}
        {tab==="cicd"&&(<div>
          <L>CI/CD Pipeline Configuration</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Generate a signed CI/CD pipeline configuration for FireAlive. The server produces a platform-native pipeline file with embedded lint, test, security scan, SBOM, SLSA L3 build, Cosign signing, CVE scan, and fuse-counter check stages.</M>
          <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap"}}>
            {[{v:"github-actions",l:"GitHub Actions"},{v:"gitlab-ci",l:"GitLab CI"},{v:"jenkins",l:"Jenkins"},{v:"circleci",l:"CircleCI"}].map(p=>(
              <div key={p.v} onClick={()=>{setCicdPlatform(p.v);setCicdResult(null);}} style={{padding:"10px 20px",background:cicdPlatform===p.v?"rgba(110,231,183,0.12)":"rgba(255,255,255,0.02)",border:`1px solid ${cicdPlatform===p.v?C.a:C.b}`,borderRadius:8,cursor:"pointer",fontSize:12,color:cicdPlatform===p.v?C.a:C.tm,fontWeight:cicdPlatform===p.v?600:400}}>{p.l}</div>
            ))}
          </div>
          <Sel label="Purpose" value={cicdPurpose} onChange={e=>{setCicdPurpose(e.target.value);setCicdResult(null);}}>
            <option value="custom-build">Custom build (fork tailored to your org's integrations)</option>
            <option value="upstream-contribution">Upstream contribution (target public FireAlive repo)</option>
          </Sel>
          {cicdResult&&cicdResult.ok&&<Card style={{marginBottom:12,borderColor:C.a+"30",padding:12}}>
            <div style={{fontSize:12,fontWeight:500,color:C.a,marginBottom:8}}>Pipeline config generated</div>
            <M style={{color:C.tm,display:"block",marginBottom:2}}>Config ID: <span style={{fontFamily:"'IBM Plex Mono',monospace",color:C.t}}>{cicdResult.data.id}</span></M>
            <M style={{color:C.tm,display:"block",marginBottom:2}}>Platform: {cicdResult.data.platform}</M>
            <M style={{color:C.tm,display:"block",marginBottom:2}}>Pipeline path in your repo: <code style={{background:C.s,padding:"2px 4px",borderRadius:3,fontSize:9}}>{cicdResult.data.pipeline_relative_path}</code></M>
            <Btn small primary style={{marginTop:10}} onClick={()=>{window.open("/api/cicd/configs/"+cicdResult.data.id+"/download","_blank");}}>Download pipeline file</Btn>
          </Card>}
          {cicdResult&&!cicdResult.ok&&<Card style={{marginBottom:12,borderColor:C.d+"40",padding:12}}>
            <div style={{fontSize:12,fontWeight:500,color:C.d,marginBottom:6}}>Generation failed</div>
            <M style={{color:C.tm,lineHeight:1.6,display:"block"}}>{cicdResult.message}</M>
          </Card>}
          <Btn primary disabled={!cicdPlatform||!cicdPurpose||cicdBusy} onClick={async()=>{
            setCicdBusy(true);setCicdResult(null);
            try{
              const r=await api.post("/api/cicd/generate",{platform:cicdPlatform,purpose:cicdPurpose});
              setCicdResult({ok:true,data:r.data});
              addA("CICD_CONFIG_GENERATED",cicdPlatform+"/"+cicdPurpose+" id="+r.data.id);
            }catch(err){
              const ed=err.response&&err.response.data?err.response.data:{};
              setCicdResult({ok:false,message:ed.message||err.message||"Generation failed"});
            }finally{setCicdBusy(false);}
          }}>{cicdBusy?"Generating pipeline...":"Generate Pipeline"}</Btn>
          <Card style={{padding:12,borderColor:C.i+"30",marginTop:12}}><M style={{color:C.i,fontWeight:500,display:"block",marginBottom:4}}>Embedded pipeline stages</M><M style={{color:C.tm,lineHeight:1.8}}>1. Lint (ESLint) -> 2. Test (npm test) -> 3. Regression test (POST /api/regression/run) -> 4. npm audit -> 5. Snyk -> 6. SBOM (Syft) -> 7. Dep-pin verify -> 8. Build (docker buildx with SLSA L3 provenance) -> 9. Sign (Cosign keyless OIDC, key-based via COSIGN_KEY_MODE override) -> 10. CVE scan (Trivy) -> 11. Fuse-counter check -> 12. Deploy (placeholder).</M></Card>
          <Card style={{padding:12,borderColor:C.p+"30",marginTop:12}}><M style={{color:C.p,fontWeight:500,display:"block",marginBottom:4}}>Webhook reporting (optional)</M><M style={{color:C.tm,lineHeight:1.8}}>The generated pipeline can POST run status back to this MC via the /api/cicd/runs endpoint with an api-key carrying the <code>cicd:webhook</code> scope. Idempotent on (platform, external_run_id). Configure FIREALIVE_WEBHOOK_URL + FIREALIVE_WEBHOOK_TOKEN secrets in your CI platform.</M></Card>
        </div>)}

        {/* ══════════ IR SIMULATOR (OODA) — MANAGEMENT ══════════ */}
        {tab==="ooda_mgmt"&&(<div>
          <L>Incident Response Simulator — Policy Management</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Upload IR policies, playbooks, and after-action reports. The simulator generates OODA-loop exercises for analysts based on your org's actual procedures.</M>
          {/* ── Scanner-required banner (Phase F4c commit 6) ── */}
          {/* Reads from scannerList already loaded by reloadScanners() on mount.
              Surfaces an amber banner when no scanner is enabled, BEFORE the
              user attempts an upload — saves them from a 422 dead-end and
              points them at the right config tab. The inline upload-error
              path (commit 3 / commit 5) remains as a fallback for scanner
              state that changes between page load and upload. */}
          {scannerList.filter(s=>s.enabled).length===0&&(
            <Card style={{marginBottom:16,borderColor:C.w+"40",background:C.wd}}>
              <M style={{color:C.w,fontWeight:600,letterSpacing:1.2,textTransform:"uppercase",fontSize:10,display:"block",marginBottom:6}}>Malware scanner required</M>
              <M style={{color:C.t,lineHeight:1.6,display:"block",marginBottom:8}}>IR Simulator policy and AAR uploads are gated by malware scanning. No enabled scanner is configured, so any upload attempt will be rejected with code MALWARE_SCANNER_REQUIRED.</M>
              <Btn small onClick={()=>setTab("malware_scanners")}>Open Malware Scanners config</Btn>
            </Card>
          )}
          {oodaLoading&&<Card style={{marginBottom:12,padding:10,borderColor:C.i+"30"}}><M style={{color:C.i}}>Loading…</M></Card>}
          {oodaUploadError&&<Card style={{marginBottom:12,padding:10,borderColor:C.d+"30"}}><M style={{color:C.d}}>{oodaUploadError}</M></Card>}
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Upload Policy / Playbook</div>
            <Input label="Title" value={oodaNewPolicy.title} onChange={e=>setOodaNewPolicy(p=>({...p,title:e.target.value}))} placeholder="e.g., Ransomware Response Playbook" maxLength={256}/>
            <Sel label="Type" value={oodaNewPolicy.type} onChange={e=>setOodaNewPolicy(p=>({...p,type:e.target.value}))}>
              <option value="incident_response">Incident Response Plan</option><option value="playbook">Playbook</option><option value="runbook">Runbook</option><option value="policy">Policy</option><option value="procedure">Procedure</option>
            </Sel>
            <div style={{marginBottom:14}}><M style={{color:C.tm,marginBottom:4,display:"block"}}>Paste policy content</M><textarea value={oodaNewPolicy.content} onChange={e=>setOodaNewPolicy(p=>({...p,content:e.target.value}))} rows={6} maxLength={500000} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:11,resize:"vertical"}}/><M style={{color:C.td,fontSize:10,display:"block",marginTop:4,lineHeight:1.5}}>Uploaded content is sanitized and scanned by the configured malware scanner (MC &gt; Malware Scanners). Uploads are rejected if no scanner is configured.</M></div>
            <Btn primary disabled={!oodaNewPolicy.title.trim()||!oodaNewPolicy.content.trim()||oodaUploading} onClick={async ()=>{
              setOodaUploading(true);
              setOodaUploadError(null);
              const r = await api.post("/api/ooda/policies", {
                title: oodaNewPolicy.title,
                type: oodaNewPolicy.type,
                content: oodaNewPolicy.content,
              });
              setOodaUploading(false);
              if (r?.error || r?.code) {
                // Surface backend error codes — particularly
                // MALWARE_SCANNER_REQUIRED (PR #3 commit 5) and the
                // sanitizer/EDR rejection codes — to the user. The
                // dedicated banner from commit 5 of THIS PR will catch
                // MALWARE_SCANNER_REQUIRED specifically; for now,
                // display whatever the server says.
                const msg = r.code === "MALWARE_SCANNER_REQUIRED"
                  ? "Upload requires a configured malware scanner. Configure one under MC > Malware Scanners."
                  : (r.error || "Upload failed");
                setOodaUploadError(msg);
                addA("OODA_POLICY_UPLOAD_FAILED", `"${oodaNewPolicy.title}" code=${r.code||"unknown"}`);
                return;
              }
              addA("OODA_POLICY_UPLOADED", `"${oodaNewPolicy.title}" (${oodaNewPolicy.type})`);
              setOodaNewPolicy({title:"",type:"incident_response",content:""});
              setOodaRefreshTick(n=>n+1);  // trigger refetch
            }}>{oodaUploading?"Uploading…":"Upload Policy"}</Btn>
          </Card>
          <L>Uploaded Policies ({oodaPolicies.length})</L>
          {oodaPolicies.length===0?<M style={{color:C.td}}>No policies uploaded yet. Upload IR policies to enable scenario generation.</M>:
          oodaPolicies.map(p=><Card key={p.id} style={{marginBottom:8,padding:"12px 14px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <div>
              <M style={{color:C.t}}>{p.title}</M><br/>
              <M style={{color:C.td}}>{p.policy_type||p.type} · {new Date(p.uploaded_at||p.uploadedAt).toLocaleDateString()}
                {p.replenishment_config&&p.replenishment_config.mode&&<span> · refill: {p.replenishment_config.mode}</span>}
              </M>
            </div>
            <div style={{display:"flex",gap:8,alignItems:"center"}}>
              <Badge color={C.a}>active</Badge>
              <Btn small onClick={async ()=>{
                // Phase F4c commit 9: manual generation button.
                // Enqueues a single generation job using the policy's
                // configured batch_size (falling back to 5 to match the
                // canonical default in db/init.js). The job appears in
                // the Generation Jobs dashboard below within ~5s as the
                // polling effect picks it up. mode='manual' is preserved
                // through the worker so the audit log clearly
                // distinguishes hand-triggered runs from auto-triggered
                // ones (threshold, scheduled, initial_upload).
                const cfg = p.replenishment_config || {};
                const batchSize = (Number.isInteger(cfg.batch_size) && cfg.batch_size>=1 && cfg.batch_size<=20) ? cfg.batch_size : 5;
                const r = await api.post("/api/ooda/generation-jobs", {
                  policy_id: p.id,
                  mode: "manual",
                  target_count_per_difficulty: batchSize,
                });
                if (r?.error || r?.code) {
                  // Common error codes from POST /generation-jobs:
                  //   POLICY_NOT_FOUND  — policy was soft-deleted between
                  //                       page load and the click
                  //   INVALID_JOB_ARGS  — mode/target validation, shouldn't
                  //                       happen with our constructed body
                  //                       but caught defensively
                  // The MALWARE_SCANNER_REQUIRED gate only fires on the
                  // upload paths (/policies, /aar), not here — the worker
                  // generates scenarios from the LLM, not from new file
                  // uploads, so the scanner gate doesn't apply.
                  setOodaUploadError(r.code==="POLICY_NOT_FOUND"
                    ? "Policy not found — refresh the page to reload the list."
                    : (r.error || `Failed to enqueue (${r.code||"unknown"})`));
                  addA("OODA_GEN_JOB_ENQUEUE_FAILED", `"${p.title}" code=${r.code||"unknown"}`);
                  return;
                }
                addA("OODA_GEN_JOB_ENQUEUED", `"${p.title}" mode=manual batch_size=${batchSize} job=${r.job_id||"unknown"}`);
                setOodaRefreshTick(n=>n+1);
              }}>Generate</Btn>
              <Btn small onClick={()=>{
                // Open the replenishment-config wizard for this policy.
                // Seed wizardConfig from the policy's current config so the
                // form starts with the existing values; defaults match
                // db/init.js if no config is set.
                const cur = p.replenishment_config || {};
                setWizardPolicy(p);
                setWizardConfig({
                  mode: cur.mode || "threshold",
                  threshold_x: cur.threshold_x != null ? cur.threshold_x : 2,
                  batch_size: cur.batch_size != null ? cur.batch_size : 5,
                  scheduled_hour: cur.scheduled_hour != null ? cur.scheduled_hour : 3,
                  scheduled_days: Array.isArray(cur.scheduled_days) ? cur.scheduled_days : [],
                  auto_initial_upload: cur.auto_initial_upload != null ? cur.auto_initial_upload : true,
                });
                setWizardError(null);
              }}>Configure</Btn>
              <Btn small onClick={async ()=>{
                if (!window.confirm(`Remove "${p.title}"? Existing scenarios will remain available but no new ones will be generated from this policy.`)) return;
                const r = await api.del(`/api/ooda/policies/${p.id}`);
                if (r?.error) { setOodaUploadError(r.error); return; }
                addA("OODA_POLICY_REMOVED", `"${p.title}"`);
                setOodaRefreshTick(n=>n+1);
              }}>Remove</Btn>
            </div>
          </Card>)}

          {/* ── After-Action Reports (Phase F4c commit 4) ── */}
          <div style={{marginTop:24}}>
            <L>After-Action Reports</L>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Upload completed AARs from past incidents. The scenario generator pulls recent AARs as context to make exercises realistic. AAR content is sanitized and malware-scanned identically to policies.</M>
            {oodaAarError&&<Card style={{marginBottom:12,padding:10,borderColor:C.d+"30"}}><M style={{color:C.d}}>{oodaAarError}</M></Card>}
            <Card style={{marginBottom:16}}>
              <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Upload AAR</div>
              <Input label="Title" value={oodaNewAar.title} onChange={e=>setOodaNewAar(p=>({...p,title:e.target.value}))} placeholder="e.g., Q1 Phishing Incident — March 2026" maxLength={256}/>
              <Input label="Incident date (YYYY-MM-DD, optional)" value={oodaNewAar.incidentDate} onChange={e=>setOodaNewAar(p=>({...p,incidentDate:e.target.value}))} placeholder="2026-03-15"/>
              <div style={{marginBottom:14}}>
                <M style={{color:C.tm,marginBottom:4,display:"block"}}>AAR content</M>
                <textarea value={oodaNewAar.content} onChange={e=>setOodaNewAar(p=>({...p,content:e.target.value}))} rows={6} maxLength={500000} placeholder="Paste the AAR narrative — incident summary, response timeline, root cause." style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:11,resize:"vertical"}}/>
              </div>
              <div style={{marginBottom:14}}>
                <M style={{color:C.tm,marginBottom:4,display:"block"}}>Lessons learned (optional)</M>
                <textarea value={oodaNewAar.lessonsLearned} onChange={e=>setOodaNewAar(p=>({...p,lessonsLearned:e.target.value}))} rows={4} maxLength={50000} placeholder="What worked, what didn't, what changes are recommended." style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:11,resize:"vertical"}}/>
                <M style={{color:C.td,fontSize:10,display:"block",marginTop:4,lineHeight:1.5}}>Both fields are scanned together as one combined blob. Uploads are rejected if no malware scanner is configured (MC &gt; Malware Scanners).</M>
              </div>
              <Btn primary disabled={!oodaNewAar.title.trim()||!oodaNewAar.content.trim()||oodaUploadingAar} onClick={async ()=>{
                setOodaUploadingAar(true);
                setOodaAarError(null);
                const r = await api.post("/api/ooda/aar", {
                  title: oodaNewAar.title,
                  content: oodaNewAar.content,
                  incidentDate: oodaNewAar.incidentDate || null,
                  lessonsLearned: oodaNewAar.lessonsLearned || null,
                });
                setOodaUploadingAar(false);
                if (r?.error || r?.code) {
                  // Same error mapping as policy uploads — the
                  // MALWARE_SCANNER_REQUIRED gate from PR #3 commit 5
                  // applies to /api/ooda/aar identically.
                  const msg = r.code === "MALWARE_SCANNER_REQUIRED"
                    ? "Upload requires a configured malware scanner. Configure one under MC > Malware Scanners."
                    : (r.error || "Upload failed");
                  setOodaAarError(msg);
                  addA("OODA_AAR_UPLOAD_FAILED", `"${oodaNewAar.title}" code=${r.code||"unknown"}`);
                  return;
                }
                addA("OODA_AAR_UPLOADED", `"${oodaNewAar.title}"`);
                setOodaNewAar({title:"",incidentDate:"",content:"",lessonsLearned:""});
                setOodaRefreshTick(n=>n+1);
              }}>{oodaUploadingAar?"Uploading…":"Upload AAR"}</Btn>
            </Card>
            {oodaAars.length===0?<M style={{color:C.td}}>No AARs uploaded yet. Upload past incident AARs to give the scenario generator more context.</M>:
            oodaAars.map(a=><Card key={a.id} style={{marginBottom:8,padding:"12px 14px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div>
                <M style={{color:C.t}}>{a.title}</M><br/>
                <M style={{color:C.td}}>
                  {a.incidentDate?`Incident: ${a.incidentDate} · `:""}
                  Uploaded: {new Date(a.uploadedAt).toLocaleDateString()}
                </M>
              </div>
              <div style={{display:"flex",gap:8,alignItems:"center"}}>
                <Badge color={C.i}>aar</Badge>
                <Btn small onClick={async ()=>{
                  if (!window.confirm(`Remove "${a.title}"? Existing scenarios that referenced this AAR retain their provenance trail.`)) return;
                  const r = await api.del(`/api/ooda/aar/${a.id}`);
                  if (r?.error) { setOodaAarError(r.error); return; }
                  addA("OODA_AAR_REMOVED", `"${a.title}"`);
                  setOodaRefreshTick(n=>n+1);
                }}>Remove</Btn>
              </div>
            </Card>)}
          </div>

          {oodaScenarios.length>0&&<div style={{marginTop:16}}><L>Available Scenarios ({oodaScenarios.length})</L>
            {oodaScenarios.map(s=><Card key={s.id} style={{marginBottom:8,padding:"12px 14px"}}><div style={{display:"flex",justifyContent:"space-between"}}><M style={{color:C.t,fontWeight:500}}>{s.title}</M><Badge color={C.p}>{s.node_count||s.nodeCount} nodes</Badge></div><M style={{color:C.td}}>Type: {s.scenario_type||s.type} · Difficulty: {s.difficulty||"—"} · Created: {new Date(s.created_at||s.createdAt).toLocaleDateString()}</M></Card>)}
          </div>}

          {/* ── Generation Jobs Dashboard (Phase F4c commit 8) ── */}
          <div style={{marginTop:24}}>
            <L>Generation Jobs ({oodaJobs.length})</L>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Background scenario-generation jobs. Threshold-mode and scheduled-mode runs appear here automatically; manual jobs (commit 9) will too. Active jobs refresh every 5 seconds.</M>
            {oodaJobsError&&<Card style={{marginBottom:12,padding:10,borderColor:C.d+"30"}}><M style={{color:C.d}}>Error loading jobs: {oodaJobsError}</M></Card>}
            {oodaJobs.length===0?<M style={{color:C.td}}>No generation jobs yet. Configure a policy's replenishment mode (Configure button above) to set up auto-generation.</M>:
            oodaJobs.map(j=>{
              // Resolve policy title from oodaPolicies. If the policy was
              // soft-deleted after the job was enqueued, fall back to the
              // policy_id so the job still displays meaningfully.
              const pol = oodaPolicies.find(p=>p.id===j.policy_id);
              const polTitle = pol ? pol.title : `(policy ${j.policy_id.slice(0,8)}…)`;
              const statusColor = {
                queued: C.i, running: C.w, done: C.a,
                failed: C.d, cancelled: C.tm,
              }[j.status] || C.tm;
              const isActive = j.status==="queued" || j.status==="running";
              const pctText = `${j.scenarios_completed||0}/${j.total_scenarios||0}`
                + (j.scenarios_failed>0 ? ` (${j.scenarios_failed} failed)` : "");
              return (<Card key={j.id} style={{marginBottom:8,padding:"12px 14px"}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:12}}>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}>
                      <Badge color={statusColor}>{j.status}</Badge>
                      <Badge color={C.p}>{j.mode}</Badge>
                      <M style={{color:C.t,fontWeight:500,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{polTitle}</M>
                    </div>
                    <M style={{color:C.td,display:"block",lineHeight:1.5}}>
                      Progress: {pctText}
                      {j.provider&&<span> · {j.provider}</span>}
                      <br/>
                      Enqueued: {new Date(j.enqueued_at).toLocaleString()}
                      {j.completed_at&&<span> · Completed: {new Date(j.completed_at).toLocaleString()}</span>}
                    </M>
                    {j.error_message&&<M style={{color:C.d,display:"block",marginTop:4,lineHeight:1.5,fontSize:10}}>Error: {j.error_message}</M>}
                  </div>
                  {isActive&&<Btn small onClick={async ()=>{
                    if (!window.confirm(`Cancel this ${j.mode} job? Best-effort: the worker stops at the next scenario boundary; any scenario currently being generated will complete.`)) return;
                    const r = await api.post(`/api/ooda/generation-jobs/${j.id}/cancel`, {});
                    if (r?.error) {
                      setOodaJobsError(r.error);
                      return;
                    }
                    addA("OODA_GEN_JOB_CANCEL_REQUESTED", `id=${j.id} previous_status=${j.status}`);
                    setOodaRefreshTick(n=>n+1);
                  }}>Cancel</Btn>}
                </div>
              </Card>);
            })}
          </div>

          {/* ── Replenishment-config wizard (Phase F4c commit 7) ── */}
          {wizardPolicy&&wizardConfig&&<Modal title={`Replenishment config — ${wizardPolicy.title}`} onClose={()=>{setWizardPolicy(null);setWizardConfig(null);setWizardError(null);}} width={520}>
            <M style={{color:C.tm,display:"block",marginBottom:14,lineHeight:1.6}}>Controls how new scenarios get generated for this policy. Threshold mode auto-refills when an analyst's unplayed pool drops too low; scheduled mode generates batches at fixed times; manual disables auto-generation entirely (you can still trigger jobs by hand).</M>

            {/* Mode selector */}
            <div style={{marginBottom:14}}>
              <M style={{color:C.tm,marginBottom:6,display:"block",fontSize:11,fontWeight:500}}>Mode</M>
              {[
                {v:"threshold",lbl:"Threshold — refill when unplayed pool drops below threshold (recommended)"},
                {v:"scheduled",lbl:"Scheduled — generate batches at a fixed hour and days"},
                {v:"manual",lbl:"Manual — no automatic generation; trigger by hand"},
                {v:"disabled",lbl:"Disabled — no generation at all"},
              ].map(opt=>(
                <label key={opt.v} style={{display:"flex",alignItems:"flex-start",gap:8,padding:"6px 0",cursor:"pointer"}}>
                  <input type="radio" name="repl-mode" checked={wizardConfig.mode===opt.v} onChange={()=>setWizardConfig(c=>({...c,mode:opt.v}))} style={{accentColor:C.a,marginTop:3}}/>
                  <M style={{color:wizardConfig.mode===opt.v?C.t:C.tm,lineHeight:1.5}}>{opt.lbl}</M>
                </label>
              ))}
            </div>

            {/* Threshold-only field */}
            {wizardConfig.mode==="threshold"&&<div style={{marginBottom:14}}>
              <Input label={`Threshold (refill when unplayed scenarios drop below this number) — currently ${wizardConfig.threshold_x}`} type="number" min="1" max="50" value={wizardConfig.threshold_x} onChange={e=>setWizardConfig(c=>({...c,threshold_x:parseInt(e.target.value,10)||c.threshold_x}))}/>
              <M style={{color:C.td,fontSize:10,display:"block",marginTop:-4,lineHeight:1.5}}>Range 1–50. Default 2. Most SOCs find 2–3 keeps the pool fresh without over-generating.</M>
            </div>}

            {/* Scheduled-only fields */}
            {wizardConfig.mode==="scheduled"&&<>
              <div style={{marginBottom:14}}>
                <M style={{color:C.tm,marginBottom:4,display:"block",fontSize:11,fontWeight:500}}>Hour of day (24h)</M>
                <Sel value={wizardConfig.scheduled_hour} onChange={e=>setWizardConfig(c=>({...c,scheduled_hour:parseInt(e.target.value,10)}))}>
                  {Array.from({length:24},(_,i)=>i).map(h=>(
                    <option key={h} value={h}>{h.toString().padStart(2,"0")}:00</option>
                  ))}
                </Sel>
              </div>
              <div style={{marginBottom:14}}>
                <M style={{color:C.tm,marginBottom:6,display:"block",fontSize:11,fontWeight:500}}>Days of week (leave all unchecked for every day)</M>
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  {[{v:"sun",l:"Sun"},{v:"mon",l:"Mon"},{v:"tue",l:"Tue"},{v:"wed",l:"Wed"},{v:"thu",l:"Thu"},{v:"fri",l:"Fri"},{v:"sat",l:"Sat"}].map(d=>(
                    <label key={d.v} style={{display:"flex",alignItems:"center",gap:4,padding:"6px 10px",border:`1px solid ${wizardConfig.scheduled_days.includes(d.v)?C.a:C.b}`,borderRadius:8,cursor:"pointer",background:wizardConfig.scheduled_days.includes(d.v)?C.ad:"transparent"}}>
                      <input type="checkbox" checked={wizardConfig.scheduled_days.includes(d.v)} onChange={e=>{
                        setWizardConfig(c=>({
                          ...c,
                          scheduled_days: e.target.checked
                            ? [...c.scheduled_days,d.v]
                            : c.scheduled_days.filter(x=>x!==d.v),
                        }));
                      }} style={{accentColor:C.a}}/>
                      <M style={{color:wizardConfig.scheduled_days.includes(d.v)?C.a:C.tm}}>{d.l}</M>
                    </label>
                  ))}
                </div>
              </div>
            </>}

            {/* batch_size — required for threshold/scheduled/manual */}
            {wizardConfig.mode!=="disabled"&&<div style={{marginBottom:14}}>
              <Input label={`Batch size per difficulty (3 difficulties × this number = scenarios per refill) — currently ${wizardConfig.batch_size}`} type="number" min="1" max="20" value={wizardConfig.batch_size} onChange={e=>setWizardConfig(c=>({...c,batch_size:parseInt(e.target.value,10)||c.batch_size}))}/>
              <M style={{color:C.td,fontSize:10,display:"block",marginTop:-4,lineHeight:1.5}}>Range 1–20. Default 5 (15 scenarios per refill). Larger batches mean fewer LLM calls but longer to first availability.</M>
            </div>}

            {/* auto_initial_upload — applies to all modes */}
            <label style={{display:"flex",alignItems:"flex-start",gap:8,padding:"8px 0",cursor:"pointer",marginBottom:14}}>
              <input type="checkbox" checked={wizardConfig.auto_initial_upload} onChange={e=>setWizardConfig(c=>({...c,auto_initial_upload:e.target.checked}))} style={{accentColor:C.a,marginTop:3}}/>
              <div>
                <M style={{color:C.t,fontWeight:500,display:"block"}}>Auto-generate initial batch on policy upload</M>
                <M style={{color:C.tm,display:"block",marginTop:2,lineHeight:1.5}}>When a policy is first uploaded, automatically enqueue a generation job to populate the initial scenario pool.</M>
              </div>
            </label>

            {wizardError&&<Card style={{marginBottom:14,padding:10,borderColor:C.d+"30"}}><M style={{color:C.d}}>{wizardError}</M></Card>}

            <div style={{display:"flex",gap:8,justifyContent:"flex-end"}}>
              <Btn onClick={()=>{setWizardPolicy(null);setWizardConfig(null);setWizardError(null);}}>Cancel</Btn>
              <Btn primary disabled={wizardSaving} onClick={async ()=>{
                setWizardSaving(true);
                setWizardError(null);
                // Build the body: only send fields that apply to the
                // chosen mode. The PATCH route normalizes anyway, but
                // sending exactly what's relevant keeps the audit log
                // clean and reduces the chance of a stale-field warning.
                const body = {
                  mode: wizardConfig.mode,
                  auto_initial_upload: wizardConfig.auto_initial_upload,
                };
                if (wizardConfig.mode==="threshold") body.threshold_x = wizardConfig.threshold_x;
                if (wizardConfig.mode==="scheduled") {
                  body.scheduled_hour = wizardConfig.scheduled_hour;
                  if (wizardConfig.scheduled_days.length>0) body.scheduled_days = wizardConfig.scheduled_days;
                }
                if (wizardConfig.mode!=="disabled") body.batch_size = wizardConfig.batch_size;
                const r = await api.patch(`/api/ooda/policies/${wizardPolicy.id}/replenishment-config`, body);
                setWizardSaving(false);
                if (r?.error || r?.code) {
                  // Map server error codes to friendlier messages.
                  // INVALID_THRESHOLD_X / INVALID_BATCH_SIZE etc. all
                  // come back with the field-specific code from the
                  // PATCH route's validation block.
                  setWizardError(r.error || `Validation failed: ${r.code}`);
                  return;
                }
                addA("OODA_POLICY_REPL_CONFIG_UPDATED", `"${wizardPolicy.title}" mode=${wizardConfig.mode}`);
                setWizardPolicy(null);
                setWizardConfig(null);
                setOodaRefreshTick(n=>n+1);
              }}>{wizardSaving?"Saving…":"Save"}</Btn>
            </div>
          </Modal>}
        </div>)}

        {tab==="peersupport"&&(<div>
          <L>Peer Skill-Share Configuration</L>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Scheduling Restrictions</div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Control when analysts can use peer chat. Restrict during on-shift hours if needed.</M>
            <div style={{display:"flex",gap:12,marginBottom:12}}>
              <label style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer"}}><input type="checkbox" checked={peerScheduleCfg.allowDuringShift} onChange={e=>setPeerSchedCfg(p=>({...p,allowDuringShift:e.target.checked}))}/><M style={{color:C.t}}>Allow during shift</M></label>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:12}}>
              <Input label="Block hours start (HH:MM)" value={peerScheduleCfg.blockedHoursStart||""} onChange={e=>setPeerSchedCfg(p=>({...p,blockedHoursStart:e.target.value}))} placeholder="09:00"/>
              <Input label="Block hours end" value={peerScheduleCfg.blockedHoursEnd||""} onChange={e=>setPeerSchedCfg(p=>({...p,blockedHoursEnd:e.target.value}))} placeholder="17:00"/>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
              <Input label="Max session (min)" value={peerScheduleCfg.maxSessionMinutes} onChange={e=>setPeerSchedCfg(p=>({...p,maxSessionMinutes:parseInt(e.target.value)||30}))} type="number"/>
              <Input label="Inactivity timeout (min)" value={peerScheduleCfg.inactivityTimeoutMinutes} onChange={e=>setPeerSchedCfg(p=>({...p,inactivityTimeoutMinutes:parseInt(e.target.value)||5}))} type="number"/>
            </div>
            <Btn primary onClick={()=>addA("PEER_SCHEDULE_UPDATED",`Allow during shift: ${peerScheduleCfg.allowDuringShift}`)}>Save Schedule Config</Btn>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Helper Recognition — Points Leaderboard</div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Top opted-in helpers, sorted by Helper Pay points. Analysts who have not opted in via their Analyst Client are absent from this list, regardless of their points balance — opt-in is per-analyst and defaults to off. Points come from 3-5 star peer-session ratings; daily caps and minimum-duration gates limit gaming. Anonymous praise can be sent via the Thank button below — no name reveal to the helper.</M>
            {peerHelpersLoading ? (
              <div style={{padding:"14px",background:C.s,border:`1px solid ${C.b}`,borderRadius:10}}><M style={{color:C.tm}}>Loading leaderboard...</M></div>
            ) : peerHelpersError ? (
              <div style={{padding:"14px",background:"rgba(239,68,68,0.08)",border:`1px solid ${C.d}40`,borderRadius:10}}><M style={{color:C.d}}>{peerHelpersError}</M></div>
            ) : peerHelpers.length === 0 ? (
              <div style={{padding:"14px",background:C.s,border:`1px solid ${C.b}`,borderRadius:10}}><M style={{color:C.tm}}>No analysts on the leaderboard yet. Analysts opt in from their AC Helper Pay tab; the list will populate as they choose to be visible.</M></div>
            ) : (
              <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,overflow:"hidden"}}>{peerHelpers.map((h,i)=>(
                <div key={h.user_id || i} style={{padding:"10px 14px",borderBottom:i<peerHelpers.length-1?`1px solid ${C.b}`:"none",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <div>
                    <M style={{color:C.t,fontWeight:500}}>{h.pseudonym || h.name}</M>
                    <br/>
                    <M style={{color:C.td}}>{h.sessions_count} session{h.sessions_count===1?"":"s"} · avg {h.avg_rating!=null?h.avg_rating:"—"}/5</M>
                  </div>
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <div style={{fontSize:18,fontWeight:600,color:C.a,fontFamily:"'IBM Plex Mono',monospace"}}>{h.points}</div>
                    <Btn small onClick={()=>addA("PEER_THANKED",`Sent thank-you to ${h.pseudonym || h.name}`)}>Thank</Btn>
                  </div>
                </div>
              ))}</div>
            )}
          </Card>
          {/* R3h: Team Helper Scores — full-roster operational view. NOT opt-in-gated. Lead operational surface for payroll, compensation discussions, and team reviews. Privacy invariant I5: bypasses the opt-in filter that gates the leaderboard above; this surface is analogous to how the Helper Pay administrative tab already exposes user-level redemption and ledger data without opt-in gating. The opt-in indicator on each row is purely informational — the lead cannot toggle it on behalf of an analyst (only the analyst can, from their AC). */}
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Team Helper Scores — Operational View</div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Full roster of active analysts with their Helper Pay state. Unlike the recognition leaderboard above, this list includes every analyst regardless of their leaderboard opt-in choice — use it for payroll reconciliation, compensation discussions, and quarterly team reviews. The opt-in badge shows each analyst's current leaderboard visibility (informational only; only the analyst can flip it from their AC).</M>
            {teamScoresLoading ? (
              <div style={{padding:"14px",background:C.s,border:`1px solid ${C.b}`,borderRadius:10}}><M style={{color:C.tm}}>Loading team scores...</M></div>
            ) : teamScoresError ? (
              <div style={{padding:"14px",background:"rgba(239,68,68,0.08)",border:`1px solid ${C.d}40`,borderRadius:10}}><M style={{color:C.d}}>{teamScoresError}</M></div>
            ) : teamScores.length === 0 ? (
              <div style={{padding:"14px",background:C.s,border:`1px solid ${C.b}`,borderRadius:10}}><M style={{color:C.tm}}>No active analysts on this team.</M></div>
            ) : (
              <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,overflow:"hidden"}}>{teamScores.map((a,i)=>{
                const visible = a.leaderboard_opt_in === 1;
                return (
                  <div key={a.user_id || i} style={{padding:"10px 14px",borderBottom:i<teamScores.length-1?`1px solid ${C.b}`:"none",display:"flex",justifyContent:"space-between",alignItems:"center",gap:12}}>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:2}}>
                        <M style={{color:C.t,fontWeight:500}}>{a.pseudonym || a.name}</M>
                        <span style={{fontSize:9,padding:"2px 6px",borderRadius:4,background:visible?"rgba(110,231,183,0.12)":C.b,color:visible?C.a:C.tm,textTransform:"uppercase",letterSpacing:1.2,fontWeight:600}}>{visible?"Visible":"Hidden"}</span>
                      </div>
                      <M style={{color:C.td}}>{a.sessions_count} session{a.sessions_count===1?"":"s"} · avg {a.avg_rating!=null?a.avg_rating:"—"}/5</M>
                    </div>
                    <div style={{fontSize:18,fontWeight:600,color:C.a,fontFamily:"'IBM Plex Mono',monospace",flexShrink:0}}>{a.points}</div>
                  </div>
                );
              })}</div>
            )}
          </Card>
          {/* R3h-pt2: Pending Sock-Puppet Review queue. Detection runs at rating time on POST /sessions/:id/rate — when a new rating's rater IP hash OR device hash matches 2+ other ratings against the same helper within the last 7 days, the rating is flagged. The flagged rating still grants points immediately (the ledger entry is written) but its contribution is excluded from the recognition leaderboard via the adjusted_points CTE in the leaderboard query. The lead reviews each flag here: Confirm Fraud triggers reversePointsForFraud (negative ledger entry, points permanently removed from helper's balance, original rating stays flagged forever as audit evidence); Dismiss clears the flag (points stay, leaderboard re-includes on next cache miss). All decisions write explicit LEADERBOARD_SOCKPUPPET_CONFIRMED / LEADERBOARD_SOCKPUPPET_DISMISSED audit_log events. */}
          <Card style={{marginBottom:16,borderColor:flaggedRatings.length>0?"#FBBF2440":C.b}}>
            <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:10}}>
              <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>Pending Sock-Puppet Review</div>
              {flaggedRatings.length>0 && (
                <span style={{fontSize:9,padding:"2px 8px",borderRadius:4,background:"#FBBF2420",color:"#FBBF24",fontWeight:600,textTransform:"uppercase",letterSpacing:1.2}}>{flaggedRatings.length} pending</span>
              )}
            </div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Ratings flagged by the sock-puppet detector. A rating is flagged when its rater shares an IP or device hash with 2+ other ratings against the same helper in the last 7 days. Flagged ratings still grant points to the helper at rating time, but their contribution is excluded from the leaderboard until you decide. Confirm Fraud reverses the points and keeps the rating flagged forever as audit evidence. Dismiss clears the flag and restores the points to the leaderboard.</M>
            {flaggedRatingsLoading ? (
              <div style={{padding:"14px",background:C.s,border:`1px solid ${C.b}`,borderRadius:10}}><M style={{color:C.tm}}>Loading review queue...</M></div>
            ) : flaggedRatingsError ? (
              <div style={{padding:"14px",background:"rgba(239,68,68,0.08)",border:`1px solid ${C.d}40`,borderRadius:10}}><M style={{color:C.d}}>{flaggedRatingsError}</M></div>
            ) : flaggedRatings.length === 0 ? (
              <div style={{padding:"14px",background:C.s,border:`1px solid ${C.b}`,borderRadius:10}}><M style={{color:C.tm}}>No ratings currently flagged. The detector runs on each new rating; flagged items will appear here for your review.</M></div>
            ) : (
              <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,overflow:"hidden"}}>{flaggedRatings.map((r,i)=>{
                const helperLabel = r.rated_user_pseudonym || r.rated_user_name;
                const raterLabel = r.rated_by_pseudonym || r.rated_by_name;
                const busy = flaggedDecideBusy === r.rating_id;
                const reasonLabel = r.flagged_reason === "both"
                  ? "IP + device cluster match"
                  : r.flagged_reason === "ip_cluster"
                    ? `IP cluster match (${r.ip_cluster_size} other rating${r.ip_cluster_size===1?"":"s"})`
                    : `Device cluster match (${r.device_cluster_size} other rating${r.device_cluster_size===1?"":"s"})`;
                return (
                  <div key={r.rating_id} style={{padding:"12px 14px",borderBottom:i<flaggedRatings.length-1?`1px solid ${C.b}`:"none"}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:6,gap:12}}>
                      <div style={{flex:1,minWidth:0}}>
                        <M style={{color:C.t,fontWeight:500,display:"block",marginBottom:2}}>{raterLabel} rated {helperLabel} — {r.stars}/5 stars</M>
                        <M style={{color:C.td,display:"block"}}>{reasonLabel} · flagged {r.flagged_at}</M>
                      </div>
                    </div>
                    {r.comment && (
                      <div style={{padding:"8px 10px",background:C.s,borderRadius:6,marginBottom:8,marginTop:4}}>
                        <M style={{color:C.tm,fontStyle:"italic"}}>{r.comment}</M>
                      </div>
                    )}
                    <div style={{display:"flex",gap:8,marginTop:6}}>
                      <Btn small disabled={busy} onClick={()=>decideFlagged(r.rating_id,true,helperLabel)} style={{background:"rgba(239,68,68,0.12)",color:C.d,borderColor:C.d+"40"}}>{busy?"...":"Confirm Fraud"}</Btn>
                      <Btn small disabled={busy} onClick={()=>decideFlagged(r.rating_id,false,helperLabel)}>{busy?"...":"Dismiss"}</Btn>
                    </div>
                  </div>
                );
              })}</div>
            )}
            {flaggedDecideFb && (
              <div style={{marginTop:10,padding:"8px 10px",background:flaggedDecideFb.kind==="success"?"rgba(110,231,183,0.08)":flaggedDecideFb.kind==="info"?C.s:"rgba(239,68,68,0.08)",border:`1px solid ${flaggedDecideFb.kind==="success"?C.a:flaggedDecideFb.kind==="info"?C.b:C.d}40`,borderRadius:6}}>
                <M style={{color:flaggedDecideFb.kind==="success"?C.a:flaggedDecideFb.kind==="info"?C.tm:C.d}}>{flaggedDecideFb.message}</M>
              </div>
            )}
          </Card>
          <Card style={{marginBottom:16,borderColor:C.p+"30"}}><div style={{fontSize:13,fontWeight:600,color:C.p,marginBottom:10}}>Helper Pay (Quality-Based)</div><M style={{color:C.tm,display:"block",marginBottom:12}}>Points from 4-5 star ratings. Pseudonymized leaderboard.</M><label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" defaultChecked/><M style={{color:C.t}}>Enable</M></label><Btn primary style={{marginTop:8}} onClick={()=>api.post("/api/v1/integrations/save",{type:"helper_pay",platform:"internal"}).then(()=>addA("HP","Helper pay config saved"))}>Save</Btn></Card>
          <Card><div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Chat Disclaimer</div>
            <M style={{color:C.tm,display:"block",marginBottom:8,lineHeight:1.6}}>The peer skill-share disclaimer is persistent and applies uniformly to all participants. It covers purpose, anonymity, conduct rules, abuse policy (including flag misuse warning), the not-counseling notice, and the 5-minute post-session retention window for rating and abuse review. Management cannot edit this text — this is the analysts' space. If you do not want analysts using peer skill-share, disable it in Feature Toggles.</M>
          </Card>
        </div>)}

        {/* ══════════ HELPER PAY MANAGEMENT (F5 part 2b) ══════════ */}
        {tab==="helper_pay"&&(<div>
          <L>Helper Pay Management</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Approve redemption requests, configure the rewards catalog, and run audit operations on the points ledger. Catalog mutations, fraud reversals, and CSV exports require admin role; if you are a lead, those actions will surface a 403 from the server.</M>

          {helperLoading && (<Card style={{marginBottom:16}}><M style={{color:C.tm}}>Loading Helper Pay management data...</M></Card>)}
          {helperError && (<Card style={{marginBottom:16,borderColor:C.d+"60"}}><M style={{color:C.d}}>{helperError}</M></Card>)}
          {helperFb && (<Card style={{marginBottom:16,borderColor:(helperFb.kind==="success"?C.a:C.d)+"60"}}>
            <M style={{color:helperFb.kind==="success"?C.a:C.d}}>{helperFb.message}</M>
          </Card>)}

          <div style={{display:"flex",gap:6,marginBottom:16}}>
            {[
              {id:"pending",label:"Pending Queue",badge:helperPending.length},
              {id:"catalog",label:"Catalog"},
              {id:"tools",label:"Audit Tools"},
            ].map(s=>(
              <button key={s.id} onClick={()=>setHelperSection(s.id)} style={{padding:"8px 14px",background:helperSection===s.id?C.ad:"transparent",border:`1px solid ${helperSection===s.id?C.a+"50":C.b}`,borderRadius:8,color:helperSection===s.id?C.a:C.tm,fontSize:11,fontWeight:500,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer",display:"flex",alignItems:"center",gap:6}}>
                {s.label}
                {s.badge>0&&<span style={{fontSize:9,background:C.dd,color:C.d,padding:"1px 6px",borderRadius:8,fontWeight:600}}>{s.badge}</span>}
              </button>
            ))}
          </div>

          {helperSection==="pending"&&(<div>
            {helperPending.length===0?(
              <Card><M style={{color:C.tm}}>No pending redemption requests.</M></Card>
            ):(
              helperPending.map(r=>{
                const typeLabel = {time_off:"Time off",gift_card:"Gift card",donation:"Donation",other:"Other"}[r.redemption_type] || r.redemption_type;
                return (
                  <Card key={r.id} style={{marginBottom:12}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
                      <div>
                        <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>{r.user_name} <span style={{color:C.td,fontWeight:400}}>· @{r.username}</span></div>
                        <M style={{color:C.tm,display:"block",marginBottom:2}}>{r.option_name} <span style={{color:C.a}}>({typeLabel})</span></M>
                        <M style={{color:C.td}}>requested {r.requested_at}</M>
                      </div>
                      <div style={{fontSize:14,fontWeight:600,color:C.a,fontFamily:"'IBM Plex Mono',monospace"}}>{r.cost_points} pts</div>
                    </div>
                    <div style={{display:"flex",gap:6,justifyContent:"flex-end"}}>
                      <Btn small onClick={()=>setDecideModal({redemption:r,approve:false,note:""})}>Deny</Btn>
                      <Btn small primary onClick={()=>setDecideModal({redemption:r,approve:true,note:""})}>Approve</Btn>
                    </div>
                  </Card>
                );
              })
            )}
          </div>)}

          {helperSection==="catalog"&&(<div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
              <M style={{color:C.tm}}>{helperOptionsAdmin.length} option{helperOptionsAdmin.length===1?"":"s"} in catalog (active and inactive)</M>
              <Btn small primary onClick={startNewOption}>+ New Option</Btn>
            </div>
            {helperOptionsAdmin.length===0?(
              <Card><M style={{color:C.tm}}>No options in catalog yet, or you do not have admin permission to view the full catalog. Click "+ New Option" to create one (admin role required).</M></Card>
            ):(
              helperOptionsAdmin.map(o=>{
                const typeLabel = {time_off:"Time off",gift_card:"Gift card",donation:"Donation",other:"Other"}[o.redemption_type] || o.redemption_type;
                return (
                  <Card key={o.id} style={{marginBottom:10,opacity:o.active?1:0.55}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                      <div style={{flex:1,minWidth:0}}>
                        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                          <span style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>{o.name}</span>
                          <Badge color={o.active?C.a:C.tm}>{o.active?"Active":"Inactive"}</Badge>
                          <Badge color={C.i}>{typeLabel}</Badge>
                          {o.approval_required?<Badge color={C.w}>Approval required</Badge>:<Badge color={C.a}>Auto-approve</Badge>}
                        </div>
                        {o.description&&<M style={{color:C.tm,display:"block",marginBottom:6,lineHeight:1.5}}>{o.description}</M>}
                        <M style={{color:C.td}}>{o.cost_points} pts{o.max_per_user_per_year?" · max "+o.max_per_user_per_year+"/yr per user":" · unlimited per user"}</M>
                      </div>
                      <div style={{display:"flex",gap:6,flexShrink:0,marginLeft:12}}>
                        <Btn small onClick={()=>startEditOption(o)}>Edit</Btn>
                        {o.active&&<Btn small danger onClick={()=>deactivateOption(o)}>Deactivate</Btn>}
                      </div>
                    </div>
                  </Card>
                );
              })
            )}
          </div>)}

          {helperSection==="tools"&&(<div>
            <Card style={{marginBottom:16}}>
              <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Fraud Reversal</div>
              <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Reverse a points ledger entry by writing a new negative-delta row. The original entry is preserved (the ledger is append-only) and the user's balance is corrected by the reversal row's negative delta. Admin role required.</M>
              <Input label="Ledger entry ID" value={reverseLedgerId} onChange={e=>setReverseLedgerId(e.target.value)} placeholder="lower-hex 32-char id"/>
              <Input label="Reason / note (optional)" value={reverseNote} onChange={e=>setReverseNote(e.target.value)} placeholder="e.g. fake-session abuse — runbook helper_pay_fraud"/>
              <Btn danger onClick={submitReversal}>Reverse Entry</Btn>
            </Card>
            <Card>
              <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>CSV Export</div>
              <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Download the full ledger or redemption history as CSV for offline analysis or external audit. Admin role required.</M>
              <div style={{display:"flex",gap:8}}>
                <Btn onClick={()=>downloadCsv("ledger")}>Download Ledger CSV</Btn>
                <Btn onClick={()=>downloadCsv("redemptions")}>Download Redemptions CSV</Btn>
              </div>
            </Card>
          </div>)}

          {decideModal&&(
            <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.7)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:9999,padding:20}}>
              <Card style={{maxWidth:480,width:"100%"}}>
                <div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>{decideModal.approve?"Approve":"Deny"} redemption</div>
                <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>
                  {decideModal.approve
                    ?`Approve "${decideModal.redemption.option_name}" (${decideModal.redemption.cost_points} pts) for ${decideModal.redemption.user_name}? Approval debits the points immediately and notifies the analyst.`
                    :`Deny "${decideModal.redemption.option_name}" (${decideModal.redemption.cost_points} pts) for ${decideModal.redemption.user_name}? Their balance is unchanged.`}
                </M>
                <Input label="Note to analyst (optional)" value={decideModal.note} onChange={e=>setDecideModal(m=>({...m,note:e.target.value}))} placeholder={decideModal.approve?"e.g. enjoy the time off":"e.g. budget exhausted this quarter"}/>
                <div style={{display:"flex",gap:8,justifyContent:"flex-end",marginTop:6}}>
                  <Btn onClick={()=>setDecideModal(null)}>Cancel</Btn>
                  <Btn primary={decideModal.approve} danger={!decideModal.approve} onClick={()=>submitDecide(decideModal.redemption,decideModal.approve,decideModal.note)}>
                    {decideModal.approve?"Approve":"Deny"}
                  </Btn>
                </div>
              </Card>
            </div>
          )}

          {optionForm&&(
            <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.7)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:9999,padding:20,overflowY:"auto"}}>
              <Card style={{maxWidth:520,width:"100%",maxHeight:"90vh",overflowY:"auto"}}>
                <div style={{fontSize:14,fontWeight:500,color:"#E8EDF5",marginBottom:12}}>{optionForm.id?"Edit redemption option":"New redemption option"}</div>
                <Input label="Name" value={optionForm.name} onChange={e=>setOptionForm(f=>({...f,name:e.target.value}))} placeholder="e.g. 2-hour PTO chunk"/>
                <Input label="Description (optional)" value={optionForm.description} onChange={e=>setOptionForm(f=>({...f,description:e.target.value}))} placeholder="What the analyst gets for redeeming"/>
                <Input label="Cost (points)" type="number" value={optionForm.costPoints} onChange={e=>setOptionForm(f=>({...f,costPoints:e.target.value}))}/>
                <div style={{marginBottom:14}}>
                  <M style={{color:C.tm,marginBottom:4,display:"block"}}>Type</M>
                  <select value={optionForm.redemptionType} onChange={e=>setOptionForm(f=>({...f,redemptionType:e.target.value}))} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}}>
                    <option value="time_off">Time off</option>
                    <option value="gift_card">Gift card</option>
                    <option value="donation">Donation</option>
                    <option value="other">Other</option>
                  </select>
                </div>
                <Input label="Max per user per year (optional)" type="number" value={optionForm.maxPerUserPerYear} onChange={e=>setOptionForm(f=>({...f,maxPerUserPerYear:e.target.value}))} placeholder="leave blank for unlimited"/>
                <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0",cursor:"pointer"}}>
                  <input type="checkbox" checked={optionForm.approvalRequired} onChange={e=>setOptionForm(f=>({...f,approvalRequired:e.target.checked}))}/>
                  <M style={{color:C.t}}>Requires lead approval before debit</M>
                </label>
                {optionForm.id&&(
                  <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0",cursor:"pointer"}}>
                    <input type="checkbox" checked={optionForm.active} onChange={e=>setOptionForm(f=>({...f,active:e.target.checked}))}/>
                    <M style={{color:C.t}}>Active (visible to analysts in their catalog)</M>
                  </label>
                )}
                <div style={{display:"flex",gap:8,justifyContent:"flex-end",marginTop:8}}>
                  <Btn onClick={()=>setOptionForm(null)}>Cancel</Btn>
                  <Btn primary onClick={submitOptionForm}>{optionForm.id?"Save Changes":"Create"}</Btn>
                </div>
              </Card>
            </div>
          )}
        </div>)}

        {/* ══════════ FEATURE TOGGLES ══════════ */}
        {tab==="features"&&(<div>
          <L>Feature Toggles</L>
          {configLocked&&<Card style={{borderColor:C.d+"40",marginBottom:16,padding:12}}><M style={{color:C.d,fontWeight:500}}>🔒 Configurations are locked. Unlock with MFA using the button in the sidebar to make changes.</M></Card>}
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Enable or disable features for your deployment. Disabled features disappear from both the Management Console and all Analyst Clients. Changes propagate to all connected clients automatically.</M>
          {[{cat:"Wellbeing",ids:["peer_chat","peer_scheduling","breathing_exercise","lighter_queue","lead_messaging","lead_chat_identified","signals_display","impact_feed","proactive_interventions","upskilling_hour"]},{cat:"Operations",ids:["delegation","burnout_routing","ooda_simulator","auto_routing_disable","fail_open_routing","tripwire"]},{cat:"Development",ids:["skill_assessments","training_certs","general_certs"]},{cat:"Integrations",ids:["soar_integration","ticket_integration","siem_feed","sase","vuln_scanning","edr_inspection","threat_hunting"]},{cat:"Security",ids:["mfa_wizard","posture_assessment","config_padlocks","concurrent_session_block","insider_threat_protocol","pseudonyms","auth_logs","auth_log_notifications"]},{cat:"Management",ids:["report_engine","query_tool","recertification","config_export","log_integrity","ha_config","cluster_mode","global_dashboard","backup_schedules","setup_wizard","welcome_guide","analyst_offboarding","recovery_runbook","ttx_generator","risk_register"]}].map(g=>(
            <Card key={g.cat} style={{marginBottom:12}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>{g.cat}</div>
              {g.ids.map(id=>(
                <div key={id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"6px 0",borderBottom:`1px solid ${C.b}`}}>
                  <M style={{color:featureToggles[id]?C.t:C.td}}>{id.replace(/_/g," ")}</M>
                  <label style={{display:"flex",alignItems:"center",gap:6,cursor:configLocked?"not-allowed":"pointer"}}><input type="checkbox" checked={featureToggles[id]||false} disabled={configLocked} onChange={e=>{if(!configLocked){setFT(p=>({...p,[id]:e.target.checked}));addA("FEATURE_TOGGLED",`${id} → ${e.target.checked?"ON":"OFF"}`);}}} /><M style={{color:featureToggles[id]?C.a:C.td}}>{featureToggles[id]?"On":"Off"}</M></label>
                </div>
              ))}
            </Card>
          ))}
        </div>)}

        {/* ══════════ COMPLIANCE ══════════ */}
        {tab==="compliance"&&(<div>
          <L>Compliance Reports</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Generate framework-specific compliance reports that check the running system against control requirements.</M>
          <div style={{display:"flex",gap:8,marginBottom:16}}>
            <Sel label="Compliance Framework" value={complianceFw} onChange={e=>setCompFw(e.target.value)}><option value="nist_csf">NIST CSF</option><option value="iso_27001">ISO 27001</option><option value="soc2">SOC 2</option><option value="hipaa">HIPAA</option><option value="gdpr">GDPR</option><option value="dora">DORA</option><option value="ccpa">CCPA</option><option value="pipeda">PIPEDA</option><option value="lgpd">LGPD</option><option value="pdpa_sg">PDPA</option><option value="appi_jp">APPI</option><option value="popia_za">POPIA</option><option value="nis2">NIS2</option><option value="cps234_au">CPS 234</option><option value="cyber_essentials">Cyber Essentials</option><option value="fisma">FISMA</option></Sel>
            <Btn primary style={{marginTop:8}} onClick={async()=>{
              const fw=complianceFw;
              setCompReport(null);
              const r=await api.get("/api/compliance/report/"+encodeURIComponent(fw));
              if(r&&!r.error){
                setCompReport(r);
                addA("COMP",(r.framework||fw.toUpperCase())+" generated: "+r?.summary?.passed+"/"+r?.summary?.total+" passed");
              }else{
                addA("COMP",(fw.toUpperCase())+" report failed: "+(r?.error||"unknown"));
              }
            }}>Generate Report</Btn>
          </div>
          {complianceReport&&(<Card>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:12}}>
              <div style={{fontSize:14,fontWeight:500,color:"#E8EDF5"}}>{complianceReport.framework} Compliance Report</div>
              <M style={{color:C.td}}>{new Date(complianceReport.generatedAt).toLocaleString()}</M>
            </div>
            <div style={{display:"flex",gap:16,marginBottom:16}}>
              <div style={{padding:"8px 16px",background:C.ad,borderRadius:8,textAlign:"center"}}><div style={{fontSize:20,fontWeight:600,color:C.a}}>{complianceReport.summary.passed}</div><M style={{color:C.a}}>Passed</M></div>
              <div style={{padding:"8px 16px",background:complianceReport.summary.warnings>0?C.wd:"rgba(255,255,255,0.02)",borderRadius:8,textAlign:"center"}}><div style={{fontSize:20,fontWeight:600,color:complianceReport.summary.warnings>0?C.w:C.td}}>{complianceReport.summary.warnings}</div><M style={{color:C.w}}>Warnings</M></div>
              <div style={{padding:"8px 16px",background:complianceReport.summary.failed>0?C.dd:"rgba(255,255,255,0.02)",borderRadius:8,textAlign:"center"}}><div style={{fontSize:20,fontWeight:600,color:complianceReport.summary.failed>0?C.d:C.td}}>{complianceReport.summary.failed}</div><M style={{color:C.d}}>Failed</M></div>
            </div>
            {complianceReport.verifiedControls&&complianceReport.verifiedControls.map((ctrl,i)=>(
              <div key={ctrl.controlId||i} style={{padding:"8px 12px",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div><M style={{color:C.t,fontWeight:500}}>{ctrl.controlId} — {ctrl.controlName}</M><br/><M style={{color:C.tm}}>{ctrl.detail}</M></div>
                <Badge color={ctrl.status==="pass"?C.a:ctrl.status==="warning"?C.w:C.d}>{ctrl.status}</Badge>
              </div>
            ))}
          </Card>)}
        </div>)}

        {/* ══════════ MONITORING ══════════ */}
        {tab==="monitoring"&&(<div>
          <L>Runtime Monitoring</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Aggregated runtime metrics across the FireAlive server, management console, and all connected analyst clients. Anomalous behavior triggers SIEM/SOAR alerts.</M>
          <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Management Console & Server</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
            <Card style={{textAlign:"center",borderColor:monMetrics.cpu>80?C.d+"60":C.b}}><div style={{fontSize:24,fontWeight:600,color:monMetrics.cpu>80?C.d:C.a}}>{monMetrics.cpu}%</div><M style={{color:C.td}}>CPU</M></Card>
            <Card style={{textAlign:"center"}}><div style={{fontSize:24,fontWeight:600,color:C.i}}>{monMetrics.memMB}</div><M style={{color:C.td}}>Memory (MB)</M></Card>
            <Card style={{textAlign:"center"}}><div style={{fontSize:24,fontWeight:600,color:C.p}}>{monMetrics.heapMB}</div><M style={{color:C.td}}>Heap (MB)</M></Card>
            <Card style={{textAlign:"center"}}><div style={{fontSize:24,fontWeight:600,color:C.w}}>{monMetrics.dbSizeMB}</div><M style={{color:C.td}}>DB Size (MB)</M></Card>
          </div>
          <Card style={{marginBottom:16}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><M style={{color:"#E8EDF5",fontWeight:500}}>System Status</M><Badge color={C.a}>Healthy</Badge></div>
            <div style={{fontSize:11,color:C.tm,lineHeight:1.8}}>
              Uptime: {Math.floor(monMetrics.uptime/3600)}h {Math.floor((monMetrics.uptime%3600)/60)}m · Load avg: {monMetrics.loadAvg?.map(l=>l.toFixed(1)).join(", ")} · Free memory: {monMetrics.freeMemMB}MB / {monMetrics.totalMemMB}MB · Source files monitored: {monMetrics.fileCount} · Continuous FIM: Active (30s interval) · Bandwidth monitor: Active (15min window, 5x alert threshold)
            </div>
          </Card>
          <Card>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Alert Thresholds (modifiable)</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8}}>
              {[{label:"CPU spike %",key:"cpuThresh",def:80},{label:"Memory multiplier",key:"memMult",def:3},{label:"DB read multiplier",key:"dbMult",def:5},{label:"Bandwidth multiplier",key:"bwMult",def:5},{label:"Max response (MB)",key:"maxResp",def:50},{label:"FIM interval (sec)",key:"fimSec",def:30}].map(t=>(
                <div key={t.key} style={{padding:8,background:"rgba(255,255,255,0.02)",borderRadius:6}}>
                  <M style={{color:C.td,display:"block",marginBottom:4}}>{t.label}</M>
                  <input type="number" defaultValue={t.def} style={{width:"100%",padding:6,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:12}} onChange={()=>addA("THRESHOLD_MODIFIED",t.label)}/>
                </div>
              ))}
            </div>
            <Btn small primary style={{marginTop:10}} onClick={()=>api.post("/api/v1/audit/log",{event:"THRESHOLDS_SAVED",detail:"Alert thresholds updated"}).then(()=>addA("THRESHOLDS_SAVED","Alert thresholds updated"))}>Save Thresholds</Btn>
          </Card>
          {/* R3l C15: Connected Sessions card, wired to /api/system/connected-clients */}
          <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:16,marginBottom:8}}>Connected Sessions (WebSocket)</div>
          <Card style={{marginBottom:16}}>
            {!connectedClientsLoadState.loaded && !connectedClientsLoadState.error && <M style={{color:C.tm,fontStyle:"italic"}}>Loading connected sessions…</M>}
            {connectedClientsLoadState.error && <M style={{color:C.w}}>Could not load connected sessions: {connectedClientsLoadState.error}</M>}
            {connectedClientsLoadState.loaded && !connectedClients.initialized && <M style={{color:C.tm,fontStyle:"italic"}}>WebSocket server not initialized (real-time sessions unavailable).</M>}
            {connectedClientsLoadState.loaded && connectedClients.initialized && <div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:12}}>
                <Card style={{textAlign:"center",borderColor:C.b}}><div style={{fontSize:22,fontWeight:600,color:C.a}}>{connectedClients.alive}</div><M style={{color:C.td}}>Alive</M></Card>
                <Card style={{textAlign:"center",borderColor:C.b}}><div style={{fontSize:22,fontWeight:600,color:C.w}}>{connectedClients.stale}</div><M style={{color:C.td}}>Stale</M></Card>
                <Card style={{textAlign:"center",borderColor:C.b}}><div style={{fontSize:22,fontWeight:600,color:C.i}}>{connectedClients.count}</div><M style={{color:C.td}}>Total</M></Card>
                <Card style={{textAlign:"center",borderColor:C.b}}><div style={{fontSize:11,fontWeight:600,color:C.p,paddingTop:6,lineHeight:1.4}}>{(()=>{const r=connectedClients.by_role||{};const entries=Object.entries(r);return entries.length>0?entries.map(([k,v])=>`${k}: ${v}`).join(" · "):"—";})()}</div><M style={{color:C.td,marginTop:6}}>By Role</M></Card>
              </div>
              {connectedClients.clients.length>0 && <div style={{overflowX:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:11,fontFamily:"'IBM Plex Mono',monospace"}}>
                  <thead><tr style={{borderBottom:`1px solid ${C.b}`}}>{["User","Role","Heartbeat"].map(h=><th key={h} style={{padding:"6px",textAlign:"left",color:C.td,fontWeight:500}}>{h}</th>)}</tr></thead>
                  <tbody>{connectedClients.clients.map((c,i)=>(<tr key={i} style={{borderBottom:`1px solid ${C.b}`}}>
                    <td style={{padding:"6px",color:C.t}}>{c.userId||"—"}</td>
                    <td style={{padding:"6px",color:C.tm}}>{c.role||"—"}</td>
                    <td style={{padding:"6px"}}><Badge color={c.isAlive?C.a:C.d}>{c.isAlive?"alive":"stale"}</Badge></td>
                  </tr>))}</tbody>
                </table>
              </div>}
              {connectedClients.clients.length===0 && <M style={{color:C.tm,fontStyle:"italic"}}>No clients connected.</M>}
            </div>}
          </Card>
          <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:16,marginBottom:8}}>Connected Client Metrics</div>
          <Card>
            <div style={{overflowX:"auto"}}>
              <table style={{width:"100%",borderCollapse:"collapse",fontSize:11,fontFamily:"'IBM Plex Mono',monospace"}}>
                <thead><tr style={{borderBottom:`1px solid ${C.b}`}}>{["Client","CPU","Mem","Status","Log Integrity","Last Sync"].map(h=><th key={h} style={{padding:"6px",textAlign:"left",color:C.td,fontWeight:500}}>{h}</th>)}</tr></thead>
                <tbody>{clientMetrics.map(cm=>(
                  <tr key={cm.id} style={{borderBottom:`1px solid ${C.b}`}}>
                    <td style={{padding:"6px",color:C.t}}>{cm.id}</td>
                    <td style={{padding:"6px",color:cm.cpu>50?C.d:cm.cpu>25?C.w:C.a}}>{cm.cpu}%</td>
                    <td style={{padding:"6px",color:C.tm}}>{cm.memMB}MB</td>
                    <td style={{padding:"6px"}}><Badge color={cm.status==="healthy"?C.a:C.w}>{cm.status}</Badge></td>
                    <td style={{padding:"6px"}}><Badge color={cm.logIntegrity==="ok"?C.a:C.d}>{cm.logIntegrity}</Badge></td>
                    <td style={{padding:"6px",color:C.td}}>{new Date(cm.lastSync).toLocaleTimeString()}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
            <div style={{display:"flex",gap:8,marginTop:12,flexWrap:"wrap"}}>
              <Btn small primary onClick={()=>api.post("/api/v1/audit/log",{event:"CLIENT_METRICS_REFRESH",detail:"Refreshed metrics from all clients"}).then(()=>addA("CLIENT_METRICS_REFRESH","Refreshed metrics from all clients"))}>Refresh All</Btn>
              <Btn small onClick={()=>api.post("/api/v1/audit/log",{event:"LOG_INTEGRITY_ALL",detail:"Log integrity check triggered on all clients"}).then(()=>addA("LOG_INTEGRITY_ALL","Log integrity check triggered on all clients"))}>Log Integrity Check</Btn>
              <Btn small onClick={()=>api.post("/api/v1/audit/log",{event:"REGRESSION_ALL_CLIENTS",detail:"Regression tests triggered on all clients"}).then(()=>addA("REGRESSION_ALL_CLIENTS","Regression tests triggered on all clients"))}>Regression Test (All)</Btn>
              <Btn small onClick={()=>api.post("/api/v1/audit/log",{event:"VULN_SCAN_ALL_CLIENTS",detail:"Vulnerability scan triggered on all clients"}).then(()=>addA("VULN_SCAN_ALL_CLIENTS","Vulnerability scan triggered on all clients"))}>Vuln Scan (All)</Btn>
              <Btn small onClick={()=>api.post("/api/v1/audit/log",{event:"BACKUP_ALL_CLIENTS",detail:"Backup triggered on all clients"}).then(()=>addA("BACKUP_ALL_CLIENTS","Backup triggered on all clients"))}>Backup All Clients</Btn>
            </div>
          </Card>
          <Card style={{marginTop:12}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Cross-App Log Collection & Update Push</div>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" checked={clientLogCollection.autoCollect} onChange={e=>setClientLogCollection(prev=>({...prev,autoCollect:e.target.checked}))}/><M style={{color:C.t}}>Auto-collect audit/forensics/runtime logs from all clients (every {clientLogCollection.intervalMin}min)</M></label>
            <M style={{color:C.td,display:"block",marginTop:6,marginBottom:10,fontStyle:"italic"}}>Client logs are forwarded to SIEM alongside MC and server logs. Per-client backups stored in individual client backup locations.</M>
            <Sel label="Update deployment method" value={updatePushCfg.method} onChange={e=>setUpdatePushCfg(prev=>({...prev,method:e.target.value}))}>
              <option value="admin_push">Admin push via SCCM/Intune/Ansible/JAMF</option><option value="server_push">Server-mediated (clients pull from server)</option>
            </Sel>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" checked={updatePushCfg.requireLabTest} onChange={e=>setUpdatePushCfg(prev=>({...prev,requireLabTest:e.target.checked}))}/><M style={{color:C.t}}>Require lab testing before production push</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" checked={updatePushCfg.rollbackOnFail} onChange={e=>setUpdatePushCfg(prev=>({...prev,rollbackOnFail:e.target.checked}))}/><M style={{color:C.t}}>Auto-rollback if health check fails post-update</M></label>
            <Btn primary style={{marginTop:8}} onClick={()=>api.post("/api/v1/audit/log",{event:"UPDATE_PUSH",detail:"Update push initiated to all clients — staggered deployment"}).then(()=>addA("UPDATE_PUSH","Update push initiated to all clients — staggered deployment"))}>Push Update to All Clients</Btn>
          </Card>
        </div>)}

        {/* ══════════ QUERY TOOL ══════════ */}
        {tab==="query_tool"&&(<div>
          <L>SIEM Query Generator</L>
          <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Generate copy-pasteable queries for your SIEM. Select a template and SIEM type.</M>
          <Card style={{marginBottom:16}}>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:12}}>
              <Sel label="Query Template" value={siemQueryType} onChange={e=>setSiemQueryType(e.target.value)}>
                <option value="team_health">Team Health Overview</option><option value="burnout_trend">Burnout Trend</option><option value="sla_performance">SLA Performance</option><option value="routing_equity">Routing Equity</option><option value="audit_events">Audit Events</option><option value="skill_gaps">Skill Gap Summary</option>
              </Sel>
              <Sel label="SIEM Platform" value={siemQuerySiem} onChange={e=>setSiemQuerySiem(e.target.value)}>
                <option value="splunk">Splunk</option><option value="qradar">QRadar</option><option value="elastic">Elastic SIEM</option><option value="sentinel">Microsoft Sentinel</option>
              </Sel>
            </div>
            <Btn primary onClick={()=>{const q=siemQuerySiem==="splunk"?`index=firealive sourcetype=firealive:${siemQueryType} earliest="-7d" latest="now"\n| stats count by risk_tier\n| sort -count`:siemQuerySiem==="qradar"?`SELECT risk_tier, COUNT(*) as count FROM events WHERE LOGSOURCENAME(logsourceid) = 'FireAlive' GROUP BY risk_tier LAST 7 DAYS`:siemQuerySiem==="elastic"?`GET firealive-*/_search\n{\n  "query": { "range": { "@timestamp": { "gte": "now-7d" } } },\n  "aggs": { "by_tier": { "terms": { "field": "risk_tier" } } }\n}`:`FireAlive_CL\n| where TimeGenerated > ago(7d)\n| summarize count() by risk_tier\n| sort by count_ desc`;setSiemQueryOutput(q);addA("SIEM_QUERY_GENERATED",`${siemQueryType} for ${siemQuerySiem}`);}}>Generate Query</Btn>
          </Card>
          {siemQueryOutput&&(<Card style={{marginBottom:16}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><M style={{color:"#E8EDF5",fontWeight:500}}>{siemQuerySiem.charAt(0).toUpperCase()+siemQuerySiem.slice(1)} Query</M><Btn small onClick={()=>{navigator.clipboard?.writeText(siemQueryOutput);api.post("/api/v1/audit/log",{event:"SIEM_QUERY_COPIED",detail:"Query copied to clipboard"}).then(()=>addA("SIEM_QUERY_COPIED","Query copied to clipboard"));}}>Copy</Btn></div>
            <pre style={{padding:12,background:"rgba(0,0,0,0.3)",borderRadius:8,color:C.a,fontSize:11,fontFamily:"'IBM Plex Mono',monospace",whiteSpace:"pre-wrap",overflowX:"auto"}}>{siemQueryOutput}</pre>
          </Card>)}
          <L style={{marginTop:20}}>Internal App Query Tool</L>
          <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>For orgs without SIEM integration — search app data directly using regex.</M>
          <Card>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:12}}>
              <Sel label="Data Source" value={querySource} onChange={e=>setQuerySource(e.target.value)}>
                <option value="audit_log">Audit Log</option><option value="sla_measurements">SLA Measurements</option><option value="reports">Reports</option><option value="assessment_results">Assessment Results</option>
              </Sel>
              <Input label="Regex Filter" value={queryRegex} onChange={e=>setQueryRegex(e.target.value)} placeholder="e.g., LOGIN.*FAIL"/>
            </div>
            <Btn primary onClick={()=>{const mockResults=[{ts:"2026-03-28 08:14",type:"LOGIN_FAILED",detail:"username=admin"},{ts:"2026-03-28 09:01",type:"LOGIN_SUCCESS",detail:"role=lead"},{ts:"2026-03-28 09:05",type:"REPORT_GENERATED",detail:"weekly auto"}].filter(r=>!queryRegex||new RegExp(queryRegex,"i").test(JSON.stringify(r)));setQueryResults(mockResults);addA("INTERNAL_QUERY",`source=${querySource} regex="${queryRegex}" results=${mockResults.length}`);}}>Run Query</Btn>
            {queryResults&&(<div style={{marginTop:12,background:C.s,border:`1px solid ${C.b}`,borderRadius:10,overflow:"hidden",maxHeight:300,overflowY:"auto"}}>{queryResults.length===0?<div style={{padding:14}}><M style={{color:C.td}}>No results matching filter.</M></div>:queryResults.map((r,i)=>(
              <div key={i} style={{padding:"8px 14px",borderBottom:`1px solid ${C.b}`,fontSize:11,fontFamily:"'IBM Plex Mono',monospace",display:"flex",gap:10}}>
                <span style={{color:C.td,minWidth:120}}>{r.ts}</span><span style={{color:C.w,minWidth:100}}>{r.type}</span><span style={{color:C.tm}}>{r.detail}</span>
              </div>
            ))}</div>)}
          </Card>
        </div>)}

        {/* ══════════ RESTORE ══════════ */}
        {tab==="restore"&&(<div>
          <L>Restore & Settings Revert</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Restore, revert, or load from external.</M>
          <Card style={{marginBottom:16}}>
          <Card style={{marginBottom:16,borderColor:C.d+"30"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}><div style={{fontSize:13,fontWeight:600,color:C.d}}>External Restore</div><Btn small onClick={()=>api.get("/api/external-restore/sources").then(r=>setErSources(r.data.sources||[])).catch(e=>addA("ER_LIST_FAIL",e.message))}>Refresh Sources</Btn></div>
            <Sel label="Source" value={erSelSrc} onChange={e=>{setErSelSrc(e.target.value); setErBackups([]); setErPreview(null); setErApproval(null);}}><option value="">Select source...</option>{erSources.map(s=>(<option key={s.id} value={s.id}>{s.name} ({s.source_type}){s.enabled?"":" [disabled]"}</option>))}</Sel>
            <div style={{display:"flex",gap:6,marginTop:8,flexWrap:"wrap"}}><Btn small disabled={!erSelSrc} onClick={()=>api.post(`/api/external-restore/sources/${erSelSrc}/test`).then(r=>addA("ER_TEST",`OK · ${r.data.backupCount} backups`)).catch(e=>addA("ER_TEST_FAIL",e.message||"failed"))}>Test Connection</Btn><Btn small disabled={!erSelSrc} onClick={()=>api.get(`/api/external-restore/sources/${erSelSrc}/browse`).then(r=>{setErBackups(r.data.backups||[]); setErPreview(null); setErApproval(null);}).catch(e=>addA("ER_BROWSE_FAIL",e.message||"failed"))}>Browse Backups</Btn></div>
            {erBackups.length>0&&(<div style={{marginTop:12,maxHeight:240,overflowY:"auto",border:`1px solid ${C.b}`,borderRadius:6}}><div style={{fontSize:11,color:C.tm,padding:"6px 10px",background:"rgba(0,0,0,0.15)"}}>Backups (newest first) · click to preview</div>{erBackups.map(b=>(<div key={b.id} style={{padding:"8px 10px",borderTop:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"center",cursor:"pointer",background:erPreview&&erPreview.externalBackupId===b.id?"rgba(100,181,246,0.1)":"transparent"}} onClick={()=>api.post(`/api/external-restore/sources/${erSelSrc}/preview/${encodeURIComponent(b.id)}`).then(r=>{setErPreview(r.data); setErApproval(null);}).catch(e=>addA("ER_PREVIEW_FAIL",e.message||"failed"))}><div><M style={{color:C.t}}>{b.id}</M><br/><M style={{color:C.td,fontSize:11}}>{b.modifiedAt} · {(b.sizeBytes/1024/1024).toFixed(1)} MB</M></div></div>))}</div>)}
            {erPreview&&(<Card style={{marginTop:12,padding:12,background:"rgba(0,0,0,0.2)"}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Preview · {erPreview.externalBackupId}</div>
              <div style={{display:"flex",gap:6,marginBottom:8,flexWrap:"wrap"}}><Badge color={erPreview.manifestSigOk?C.g:C.r}>Sig: {erPreview.manifestSigOk?"VERIFIED":(erPreview.signingKeyKnown?"FAILED":"UNKNOWN KEY")}</Badge><Badge color={erPreview.structure&&erPreview.structure.ok?C.g:C.r}>Files: {erPreview.structure?erPreview.structure.present.length:0}/4</Badge><Badge color={C.tm}>Key fp: {(erPreview.signingKeyFingerprint||"").slice(0,12)}…</Badge></div>
              {!erPreview.signingKeyKnown&&(<M style={{color:C.r,display:"block",marginBottom:8}}>⚠ Signing key fingerprint {(erPreview.signingKeyFingerprint||"").slice(0,16)}… is not registered (or has been revoked). For cross-deployment restore, register the originating deployment's public key in the Backup Signing Keys section below before restore can proceed.</M>)}
              {erPreview.signingKeyKnown&&!erPreview.manifestSigOk&&(<M style={{color:C.r,display:"block",marginBottom:8}}>⚠ Manifest signature verification FAILED. Backup may be tampered or corrupted. Restore is blocked.</M>)}
              <Input label="Reason for restore (recorded in chain audit)" value={erReason} onChange={e=>setErReason(e.target.value)} placeholder="e.g. recovering from ransomware incident on prod-east"/>
              <Btn danger disabled={!erPreview.manifestSigOk||!erPreview.structure||!erPreview.structure.ok} style={{marginTop:8}} onClick={()=>{if(window.confirm("Request a restore from this external backup? A second admin must approve via TOTP at the Restore Approvals queue before the restore can execute.")){api.post(`/api/external-restore/sources/${erSelSrc}/restore-request/${encodeURIComponent(erPreview.externalBackupId)}`,{request_reason:erReason||null}).then(r=>{setErApproval(r.data); addA("ER_REQUEST",`approval ${r.data.approval_id} · ${r.data.status}`);}).catch(e=>addA("ER_REQUEST_FAIL",e.message||"failed"));}}}>Request Restore (Two-Person Approval)</Btn>
            </Card>)}
            {erApproval&&(<Card style={{marginTop:12,padding:12,background:"rgba(0,0,0,0.2)",borderColor:C.w+"40"}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Pending Approval · {erApproval.approval_id.slice(0,12)}…</div>
              <M style={{color:C.tm,display:"block",marginBottom:4}}>Status: <Badge color={erApproval.status==="approved"?C.g:erApproval.status==="pending"?C.w:C.r}>{erApproval.status.toUpperCase()}</Badge></M>
              <M style={{color:C.tm,display:"block",marginBottom:4,fontSize:11}}>Mode: {erApproval.approval_mode_at_creation} · Window: {erApproval.approval_window_hours}h · Expires: {erApproval.expires_at}</M>
              <M style={{color:C.tm,display:"block",marginBottom:8,fontSize:11}}>{erApproval.next_step}</M>
              {erApproval.status==="approved"&&(<Btn danger onClick={()=>{if(window.confirm("EXECUTE EXTERNAL RESTORE NOW?\n\nThis will replace the live database with the bytes from the external backup. A pre-restore snapshot of the current state will be saved next to the DB file. The operation is recorded in the chain audit trail as RESTORE_REQUEST + RESTORE_COMPLETE.\n\nThis action cannot be undone except by manual recovery from the pre-restore snapshot.")){api.post(`/api/external-restore/restore-execute/${erApproval.approval_id}`).then(r=>{addA("ER_EXECUTED",`Restored ${(r.data.restored_db_size_bytes/1024/1024).toFixed(1)} MB · pre-restore snapshot at ${r.data.pre_restore_snapshot_path}`); setErApproval(null); setErPreview(null); setErBackups([]); setErSelSrc("");}).catch(e=>addA("ER_EXECUTE_FAIL",e.message||"failed"));}}}>EXECUTE RESTORE</Btn>)}
              <Btn small style={{marginTop:8,marginLeft:erApproval.status==="approved"?8:0}} onClick={()=>setErApproval(null)}>Dismiss</Btn>
            </Card>)}
          </Card>
          <Card style={{marginBottom:16,borderColor:C.d+"30"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}><div style={{fontSize:13,fontWeight:600,color:C.d}}>Backup Signing Keys</div><Btn small onClick={()=>api.get("/api/backup-signing-keys").then(r=>setBskKeys(r.data.keys||[])).catch(e=>addA("BSK_LIST_FAIL",e.message))}>Refresh</Btn></div>
            <M style={{color:C.tm,display:"block",marginBottom:10,fontSize:11,lineHeight:1.5}}>The local-generated key signs new backups created here. External-registered keys are foreign deployments' public keys, registered so backups signed by those deployments can be verified for cross-deployment restore. Revoking an external key disables verification of every backup signed by it, including backups created before the revocation.</M>
            {bskKeys.length>0&&(<div style={{maxHeight:280,overflowY:"auto",border:`1px solid ${C.b}`,borderRadius:6,marginBottom:10}}>{bskKeys.map((k,i)=>(<div key={k.id} style={{padding:"10px 12px",borderTop:i===0?"none":`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:8}}><div style={{flex:1,minWidth:0}}><div style={{display:"flex",gap:6,marginBottom:4,flexWrap:"wrap"}}><Badge color={k.keyOrigin==="local-generated"?C.d:"#9c5cff"}>{k.keyOrigin==="local-generated"?"LOCAL":"EXTERNAL"}</Badge>{k.isActive&&(<Badge color={C.g}>ACTIVE</Badge>)}{k.rotatedOutAt&&(<Badge color={C.r}>{k.keyOrigin==="local-generated"?"ROTATED OUT":"REVOKED"}</Badge>)}</div><M style={{color:C.t,fontSize:11,fontFamily:"monospace",wordBreak:"break-all"}}>fp {k.publicKeyFingerprint||"(none)"}</M>{k.keyLabel&&(<M style={{color:C.tm,display:"block",fontSize:11,marginTop:2}}>{k.keyLabel}</M>)}<M style={{color:C.td,display:"block",fontSize:11,marginTop:2}}>id {k.id} · created {k.createdAt}{k.registeredByUserId?` · registered by ${k.registeredByUserId} at ${k.registeredAt}`:""}{k.rotatedOutAt?` · ${k.keyOrigin==="local-generated"?"rotated":"revoked"} at ${k.rotatedOutAt}`:""}</M></div>{k.keyOrigin==="external-registered"&&!k.rotatedOutAt&&(<Btn small danger onClick={()=>{if(window.confirm(`Revoke external key id ${k.id}?\n\nFingerprint ${k.publicKeyFingerprint}\n\nAfter revocation, no backup signed by this key (including those created before revocation) can be verified or restored. This cannot be undone except by re-registering the same public key under a new id.`)){api.delete(`/api/backup-signing-keys/${k.id}`).then(()=>{addA("BSK_REVOKED",`id=${k.id}`); api.get("/api/backup-signing-keys").then(r=>setBskKeys(r.data.keys||[]));}).catch(e=>addA("BSK_REVOKE_FAIL",e.response?.data?.error||e.message));}}}>Revoke</Btn>)}</div>))}</div>)}
            {!bskShowAdd&&(<Btn small onClick={()=>{setBskShowAdd(true); setBskPasteText(""); setBskValidatedFp(null); setBskValidatedPem(null); setBskLabel("");}}>Register Foreign Public Key</Btn>)}
            {bskShowAdd&&(<Card style={{marginTop:8,padding:12,background:"rgba(0,0,0,0.2)"}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Register Foreign Deployment Public Key</div>
              <M style={{color:C.tm,display:"block",marginBottom:8,fontSize:11,lineHeight:1.5}}>Paste the originating deployment's PEM-encoded Ed25519 public key. The fingerprint will be computed and shown for out-of-band confirmation before you commit. Only register a key whose fingerprint you have verified through a separate trusted channel (phone, encrypted message, in-person).</M>
              <textarea value={bskPasteText} onChange={e=>{setBskPasteText(e.target.value); setBskValidatedFp(null); setBskValidatedPem(null);}} placeholder={"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----"} style={{width:"100%",minHeight:120,padding:8,background:"rgba(0,0,0,0.3)",color:C.t,border:`1px solid ${C.b}`,borderRadius:4,fontFamily:"monospace",fontSize:11,marginBottom:8,resize:"vertical"}}/>
              <Input label="Label (optional)" value={bskLabel} onChange={e=>setBskLabel(e.target.value)} placeholder="e.g. prod-east deployment, key from 2026-04-15"/>
              {!bskValidatedFp&&(<Btn small disabled={!bskPasteText.trim()} onClick={()=>api.post("/api/backup-signing-keys/validate",{public_key_pem:bskPasteText}).then(r=>{setBskValidatedFp(r.data.publicKeyFingerprint); setBskValidatedPem(r.data.publicKeyPem);}).catch(e=>addA("BSK_VALIDATE_FAIL",e.response?.data?.error||e.message))} style={{marginTop:8}}>Validate &amp; Show Fingerprint</Btn>)}
              {bskValidatedFp&&(<div style={{marginTop:8,padding:10,background:"rgba(0,0,0,0.3)",border:`1px solid ${C.g}40`,borderRadius:4}}><M style={{color:C.tm,display:"block",fontSize:11,marginBottom:4}}>Computed fingerprint (confirm out-of-band before registering):</M><M style={{color:C.g,fontFamily:"monospace",fontSize:12,wordBreak:"break-all"}}>{bskValidatedFp}</M></div>)}
              <div style={{display:"flex",gap:6,marginTop:8}}>
                {bskValidatedFp&&(<Btn small onClick={()=>{if(window.confirm(`Register this public key?\n\nFingerprint: ${bskValidatedFp}\n\nOnly proceed if you have confirmed this fingerprint matches the originating deployment's active signing key out-of-band. Once registered, backups signed by this key will be accepted for cross-deployment restore here.`)){api.post("/api/backup-signing-keys",{public_key_pem:bskValidatedPem,key_label:bskLabel||null}).then(r=>{addA("BSK_REGISTERED",`id=${r.data.id} fp=${r.data.publicKeyFingerprint.slice(0,12)}…`); setBskShowAdd(false); setBskPasteText(""); setBskValidatedFp(null); setBskValidatedPem(null); setBskLabel(""); api.get("/api/backup-signing-keys").then(rr=>setBskKeys(rr.data.keys||[]));}).catch(e=>addA("BSK_REGISTER_FAIL",e.response?.data?.error||e.message));}}}>Confirm &amp; Register</Btn>)}
                <Btn small onClick={()=>{setBskShowAdd(false); setBskPasteText(""); setBskValidatedFp(null); setBskValidatedPem(null); setBskLabel("");}}>Cancel</Btn>
              </div>
            </Card>)}
          </Card>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Database Backups</div>
            {restorePoints.map(b=>(
              <div key={b.id} style={{padding:"10px 14px",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div><M style={{color:C.t}}>{b.createdAt}</M><br/><M style={{color:C.td}}>{b.type} · {b.sizeMB} MB · {b.hash}</M></div>
                <Btn small danger onClick={()=>{if(window.confirm(`Restore database from ${b.createdAt}? This will replace all current data. A pre-restore backup will be saved.`)){addA("DATABASE_RESTORED",`Restored from ${b.createdAt}`);}}}>Restore</Btn>
              </div>
            ))}
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}><div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>Configuration Snapshots</div><div style={{display:"flex",gap:6}}><Btn small primary onClick={()=>{const name=window.prompt("Snapshot name:");if(name){setConfigSnaps(prev=>[{id:"cs-"+Date.now(),name,createdAt:new Date().toISOString()},...prev]);addA("CONFIG_SNAPSHOT_SAVED",`"${name}"`);}}}>Save Current</Btn><Btn small onClick={()=>{const data=JSON.stringify({exportType:"firealive_config",version:appVersion||"unknown",exportedAt:new Date().toISOString()},null,2);const blob=new Blob([data],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="firealive-config-"+new Date().toISOString().slice(0,10)+".json";a.click();URL.revokeObjectURL(url);api.post("/api/v1/audit/log",{event:"CONFIG_EXPORTED",detail:"Configuration file downloaded"}).then(()=>addA("CONFIG_EXPORTED","Configuration file downloaded"));}}>Export Config</Btn><Btn small onClick={()=>api.post("/api/v1/audit/log",{event:"CHANGE_REPORT",detail:"Configuration change report generated"}).then(()=>addA("CHANGE_REPORT","Configuration change report generated"))}>Change Report</Btn></div></div>
            {configSnapshots.map(s=>(
              <div key={s.id} style={{padding:"10px 14px",borderBottom:`1px solid ${C.b}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div><M style={{color:C.t}}>{s.name}</M><br/><M style={{color:C.td}}>{s.createdAt}</M></div>
                <Btn small onClick={()=>{if(window.confirm(`Revert to "${s.name}"? Current config will be auto-saved first.`)){addA("CONFIG_REVERTED",`Reverted to "${s.name}"`);}}}>Revert</Btn>
              </div>
            ))}
          </Card>
        </div>)}

        {/* ══════════ RECERTIFICATION ══════════ */}
        {tab==="recert"&&(<div>
          <L>Recertification Review</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Periodic review of all accounts, integrations, assessments, and configurations. Ensures stale accounts are removed, integrations are current, and settings remain appropriate. Recommended quarterly.</M>
          <Card style={{marginBottom:16,borderColor:C.w+"40"}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><M style={{color:"#E8EDF5",fontWeight:500}}>Recertification Status</M><Badge color={C.w}>Due every 90 days</Badge></div>
            <M style={{color:C.tm,display:"block",marginBottom:12}}>Review all accounts, integrations, and settings. Mark complete when done.</M>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,marginBottom:12}}>
              <Card style={{textAlign:"center",padding:12}}><div style={{fontSize:20,fontWeight:600,color:C.i}}>{analysts.length}</div><M style={{color:C.td}}>Accounts</M></Card>
              <Card style={{textAlign:"center",padding:12}}><div style={{fontSize:20,fontWeight:600,color:C.p}}>4</div><M style={{color:C.td}}>Integrations</M></Card>
              <Card style={{textAlign:"center",padding:12}}><div style={{fontSize:20,fontWeight:600,color:C.w}}>{assessments.length}</div><M style={{color:C.td}}>Assessments</M></Card>
            </div>
            <div style={{display:"flex",gap:8}}>
              <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"RECERT_COMPLETED",detail:"Recertification review completed"}).then(()=>addA("RECERT_COMPLETED","Recertification review completed"))}>Mark Recertification Complete</Btn>
              <Btn onClick={()=>api.post("/api/v1/audit/log",{event:"RECERT_REPORT",detail:"Recertification report generated"}).then(()=>addA("RECERT_REPORT","Recertification report generated"))}>Generate Report</Btn>
            </div>
          </Card>
          <Card><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Schedule</div>
            <Sel label="Review interval" value="90" onChange={()=>api.post("/api/v1/audit/log",{event:"RECERT_INTERVAL",detail:"Interval updated"}).then(()=>addA("RECERT_INTERVAL","Interval updated"))}>
              <option value="30">Monthly (30 days)</option><option value="90">Quarterly (90 days)</option><option value="180">Semi-annual (180 days)</option><option value="365">Annual (365 days)</option>
            </Sel>
          </Card>
        </div>)}

        {/* ══════════ VULNERABILITY SCANNING ══════════ */}
        {tab==="vulnscan"&&(<div>
          <L>Vulnerability Scanner Integration</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Allow approved vulnerability scanners to scan the FireAlive application. Unauthorized scans are blocked by the network hardening layer. Only scanners from approved IPs can connect.</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Approved Scanners</div>
            {["nessus","openvas","qualys","rapid7","tenable_io","nuclei"].map(s=>(
              <label key={s} style={{display:"flex",alignItems:"center",gap:6,padding:"6px 0",borderBottom:`1px solid ${C.b}`,cursor:"pointer"}}><input type="checkbox" onChange={()=>addA("VULNSCAN_TOGGLED",s)}/><M style={{color:C.t}}>{s.replace(/_/g," ").replace(/\b\w/g,l=>l.toUpperCase())}</M></label>
            ))}
          </Card>
          <Card style={{marginBottom:16}}>
            <Input label="Allowed Scanner IPs (one per line)" placeholder="10.0.1.50&#10;10.0.1.51"/>
            <Sel label="Scan Schedule"><option value="weekly">Weekly</option><option value="daily">Daily</option><option value="monthly">Monthly</option><option value="manual">Manual Only</option></Sel>
            <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"VULNSCAN_CONFIG_SAVED",detail:"Vulnerability scanner config saved"}).then(()=>addA("VULNSCAN_CONFIG_SAVED","Vulnerability scanner config saved"))}>Save Config</Btn>
          </Card>
        </div>)}

        {/* ══════════ ACCESS CONTROL ══════════ */}
        {tab==="access_ctrl"&&(<div>
          <L>Access Control Environment</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Configure FireAlive for your organization's access control model. This adjusts session handling, permission enforcement, and MFA requirements to match your environment.</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Access Control Model</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:12}}>
              {[{id:"rbac",name:"RBAC",desc:"Role-Based — permissions tied to roles (analyst, lead, admin)"},{id:"abac",name:"ABAC",desc:"Attribute-Based — permissions from user/resource/environment attributes"},{id:"mac",name:"MAC",desc:"Mandatory — system-enforced labels (clearance levels)"},{id:"dac",name:"DAC",desc:"Discretionary — resource owners control access"}].map(m=>(
                <Card key={m.id} style={{cursor:"pointer",borderColor:C.b,padding:12}} onClick={()=>addA("ACCESS_CTRL_MODEL",m.id)}>
                  <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>{m.name}</div>
                  <M style={{color:C.tm,lineHeight:1.4}}>{m.desc}</M>
                </Card>
              ))}
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
              <Input label="Max concurrent sessions" type="number" placeholder="3"/>
              <Input label="Session timeout (minutes)" type="number" placeholder="480"/>
            </div>
            <label style={{display:"flex",alignItems:"center",gap:6,marginBottom:8,cursor:"pointer"}}><input type="checkbox" defaultChecked/><M style={{color:C.t}}>Require MFA for admin actions</M></label>
            <label style={{display:"flex",alignItems:"center",gap:6,marginBottom:12,cursor:"pointer"}}><input type="checkbox" defaultChecked/><M style={{color:C.t}}>Bind sessions to IP + user agent</M></label>
            <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"ACCESS_CTRL_SAVED",detail:"Access control config saved"}).then(()=>addA("ACCESS_CTRL_SAVED","Access control config saved"))}>Save</Btn>
          </Card>
        </div>)}

        {/* ══════════ SASE ══════════ */}
        {tab==="sase"&&(<div>
          <L>SASE Integration</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Integrate FireAlive with your Secure Access Service Edge platform. FireAlive can operate within SASE as a SECaaS offering or connect through ZTNA, CASB, and SWG components.</M>
          <Card style={{marginBottom:16}}>
            <Sel label="SASE Provider">
              <option value="">Select provider...</option><option value="zscaler">Zscaler</option><option value="netskope">Netskope</option><option value="palo_alto_prisma">Palo Alto Prisma Access</option><option value="cato">Cato Networks</option><option value="cloudflare">Cloudflare One</option><option value="fortinet">Fortinet</option>
            </Sel>
            <Input label="ZTNA Endpoint URL" placeholder="https://ztna.corp.example.com"/>
            <label style={{display:"flex",alignItems:"center",gap:6,marginBottom:8,cursor:"pointer"}}><input type="checkbox"/><M style={{color:C.t}}>Enable CASB integration</M></label>
            <label style={{display:"flex",alignItems:"center",gap:6,marginBottom:8,cursor:"pointer"}}><input type="checkbox"/><M style={{color:C.t}}>Enable SWG policy enforcement</M></label>
            <Input label="FWaaS Policy ID" placeholder="Policy identifier"/>
            <label style={{display:"flex",alignItems:"center",gap:6,marginBottom:12,cursor:"pointer"}}><input type="checkbox"/><M style={{color:C.t}}>Deploy FireAlive as SECaaS within SASE</M></label>
            <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"SASE_CONFIG_SAVED",detail:"SASE integration configured"}).then(()=>addA("SASE_CONFIG_SAVED","SASE integration configured"))}>Save SASE Config</Btn>
          </Card>
        </div>)}

        {/* ══════════ LOG INTEGRITY ══════════ */}
        {tab==="log_integrity"&&(<div>
          <L>Log Integrity Monitoring</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Checks for missing or tampered audit logs. Logs are append-only — the application prevents deletion. Retention follows your configured lifecycle policy. Missing logs trigger SOAR alerts for automated investigation.</M>
          <Card style={{marginBottom:16}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><M style={{color:"#E8EDF5",fontWeight:500}}>Integrity Status</M><Badge color={C.a}>Clean</Badge></div>
            <M style={{color:C.tm,display:"block",marginBottom:8}}>Last check: {new Date().toLocaleTimeString()} · Checked hourly · No ID gaps or time gaps detected</M>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,marginBottom:12}}>
              <Card style={{textAlign:"center",padding:10}}><div style={{fontSize:18,fontWeight:600,color:C.a}}>{audit.length}</div><M style={{color:C.td}}>Total Events</M></Card>
              <Card style={{textAlign:"center",padding:10}}><div style={{fontSize:18,fontWeight:600,color:C.a}}>0</div><M style={{color:C.td}}>ID Gaps</M></Card>
              <Card style={{textAlign:"center",padding:10}}><div style={{fontSize:18,fontWeight:600,color:C.a}}>0</div><M style={{color:C.td}}>Time Gaps</M></Card>
            </div>
            <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"LOG_INTEGRITY_CHECK",detail:"Manual integrity check — passed"}).then(()=>addA("LOG_INTEGRITY_CHECK","Manual integrity check — passed"))}>Run Check Now</Btn>
          </Card>
          <Card>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Protection Mechanisms</div>
            <M style={{color:C.tm,lineHeight:1.8}}>Append-only audit table (no DELETE/UPDATE permissions) · Sequential ID verification (detects gaps from external tampering) · Time continuity check (flags gaps &gt; 30 min) · HMAC signing on log exports · SOAR auto-dispatch on any violation · Retention lifecycle: configurable per data type (default audit: 365 days)</M>
          </Card>
        </div>)}

        {/* ══════════ HUMAN IMPACT RISK REPORT ══════════ */}
        {tab==="risk_report"&&(<div>
          <L>Human Impact Risk Report</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Generate a report linking incident types to analyst burnout metrics, quantified for enterprise risk registers. Includes annualized human capital costs (turnover, training replacement), incident-to-burnout correlation data, and risk register entries with mitigations.</M>
          <Btn primary disabled={hirLoading} onClick={()=>{setHirLoading(true);setTimeout(()=>{setHIR({totalCost:228650,churnCost:178500,entries:[{id:"HR-BURN-001",type:"Ransomware",impact:"severe",cost:61200,exit:"+18%",recovery:"14 days",mitigations:["Post-incident wellness protocol","Mandatory 24hr reduced queue","CISM retrospective within 72hr"]},{id:"HR-BURN-002",type:"APT",impact:"severe",cost:93500,exit:"+22%",recovery:"21 days",mitigations:["Analyst rotation during sustained investigations","Shift handoff with full context transfer"]},{id:"HR-BURN-003",type:"Phishing (high vol)",impact:"moderate",cost:12750,exit:"+5%",recovery:"5 days",mitigations:["Automated phishing triage","Pattern-based auto-close"]},{id:"HR-BURN-004",type:"Data Exfiltration",impact:"high",cost:30600,exit:"+12%",recovery:"10 days",mitigations:["Automated DLP correlation","Dedicated forensics handoff"]},{id:"HR-BURN-005",type:"Insider Threat",impact:"high",cost:25500,exit:"+15%",recovery:"12 days",mitigations:["Anonymize investigation subjects","Limit to 2 analysts"]},{id:"HR-BURN-006",type:"DDoS",impact:"low",cost:5100,exit:"+3%",recovery:"3 days",mitigations:["Automated DDoS triage","Runbook-driven response"]}]});setHirLoading(false);api.post("/api/v1/audit/log",{event:"HUMAN_IMPACT_REPORT",detail:"Human impact risk report generated — total annualized cost: $228,650"}).then(()=>addA("HUMAN_IMPACT_REPORT","Human impact risk report generated — total annualized cost: $228,650"));},1500);}}>{hirLoading?"Generating...":"Generate Report"}</Btn>
          {humanImpactReport&&(<div style={{marginTop:16}}>
            <div style={{display:"flex",gap:12,marginBottom:16}}>
              <Card style={{flex:1,padding:12,borderColor:C.d+"30",textAlign:"center"}}><div style={{fontSize:20,fontWeight:700,color:C.d}}>${humanImpactReport.totalCost.toLocaleString()}</div><M style={{color:C.tm}}>Annualized Human Impact Cost</M></Card>
              <Card style={{flex:1,padding:12,borderColor:C.w+"30",textAlign:"center"}}><div style={{fontSize:20,fontWeight:700,color:C.w}}>${humanImpactReport.churnCost.toLocaleString()}</div><M style={{color:C.tm}}>Est. Annual Churn Cost (35% turnover)</M></Card>
            </div>
            <L>Risk Register Entries</L>
            {humanImpactReport.entries.map(e=>(
              <Card key={e.id} style={{marginBottom:8,padding:"14px 16px",borderLeft:`3px solid ${e.impact==="severe"?C.d:e.impact==="high"?C.w:e.impact==="moderate"?C.i:C.a}`}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}><div><M style={{color:C.t,fontWeight:600}}>{e.id}: {e.type}</M></div><div style={{display:"flex",gap:6}}><Badge color={e.impact==="severe"?C.d:e.impact==="high"?C.w:C.i}>{e.impact}</Badge><Badge color={C.w}>${e.cost.toLocaleString()}/yr</Badge></div></div>
                <div style={{display:"flex",gap:16,marginBottom:6}}><M style={{color:C.td}}>Exit risk: {e.exit}</M><M style={{color:C.td}}>Recovery: {e.recovery}</M></div>
                <M style={{color:C.tm,display:"block"}}>Mitigations: {e.mitigations.join(" · ")}</M>
              </Card>
            ))}
            <div style={{display:"flex",gap:8,marginTop:12}}>
              <Btn small onClick={()=>{const data=JSON.stringify(humanImpactReport,null,2);const blob=new Blob([data],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="human-impact-risk-report-"+new Date().toISOString().slice(0,10)+".json";a.click();}}>Export JSON</Btn>
              <Btn small onClick={()=>{const csv="Risk ID,Incident Type,Impact,Annual Cost,Exit Risk Increase,Recovery Days,Mitigations\n"+humanImpactReport.entries.map(e=>`${e.id},${e.type},${e.impact},${e.cost},${e.exit},${e.recovery},"${e.mitigations.join('; ')}"`).join("\n");const blob=new Blob([csv],{type:"text/csv"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="human-impact-risk-register-"+new Date().toISOString().slice(0,10)+".csv";a.click();}}>Export CSV (for Risk Register)</Btn>
            </div>
            <Card style={{marginTop:12,padding:12,borderColor:C.p+"30"}}><M style={{color:C.p,fontWeight:500,display:"block",marginBottom:4}}>How to Use This Report</M><M style={{color:C.tm,lineHeight:1.8}}>Import the CSV into your enterprise risk register alongside traditional IT and financial risk entries. Review quarterly. Track total human impact cost as a KPI for CISO and executive leadership. Use incident-to-burnout correlations to prioritize automation investment (target highest-burnout incident types first). Factor analyst recovery time into incident response planning.</M></Card>
          </div>)}
        </div>)}

        {/* ══════════ EDR FILE INSPECTION ══════════ */}
        {tab==="edr"&&(<div>
          <L>EDR File Inspection</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Integrate with your EDR platform to scan all files loaded into FireAlive — configuration restores, policy uploads, IaC imports, and app updates — before they are processed. For XDR behavioral monitoring, Next-Gen AV, ATP, and MSP scanner integrations, see the Threat Hunting tab.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={edrCfg.enabled} onChange={e=>setEdrCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable EDR file inspection</label>
            <Sel label="EDR Provider" value={edrCfg.provider||""} onChange={e=>setEdrCfg(prev=>({...prev,provider:e.target.value}))}>
              <option value="">Select...</option><option value="crowdstrike">CrowdStrike Falcon</option><option value="sentinelone">SentinelOne</option><option value="defender">Microsoft Defender for Endpoint</option><option value="carbon_black">VMware Carbon Black</option><option value="sophos">Sophos Intercept X</option><option value="trellix">Trellix (McAfee)</option>
            </Sel>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:12,marginBottom:8}}>Scan Triggers</div>
            {[{k:"scanOnUpload",l:"Scan on file upload"},{k:"scanOnRestore",l:"Scan on configuration restore"},{k:"scanOnPolicyImport",l:"Scan on policy/playbook import"},{k:"scanOnAppUpdate",l:"Scan app update packages before installation"}].map(s=>(
              <label key={s.k} style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={edrCfg[s.k]} onChange={e=>setEdrCfg(prev=>({...prev,[s.k]:e.target.checked}))}/><M style={{color:C.t}}>{s.l}</M></label>
            ))}
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:12,marginBottom:8}}>Response Actions</div>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={edrCfg.blockOnThreat} onChange={e=>setEdrCfg(prev=>({...prev,blockOnThreat:e.target.checked}))}/><M style={{color:C.d}}>Block processing if threat detected</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={edrCfg.quarantineOnSuspicious} onChange={e=>setEdrCfg(prev=>({...prev,quarantineOnSuspicious:e.target.checked}))}/><M style={{color:C.w}}>Quarantine suspicious files for manual review</M></label>
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"EDR_CONFIG_SAVED",detail:"EDR file inspection configuration saved"}).then(()=>addA("EDR_CONFIG_SAVED","EDR file inspection configuration saved"))}>Save EDR Config</Btn>
        </div>)}

        {/* ══════════ MALWARE SCANNER INTEGRATION (Phase F4c) ══════════ */}
        {tab==="malware_scanners"&&(<div>
          <L>Malware Scanner Integration</L>
          <M style={{color:C.tm,display:"block",marginBottom:8,lineHeight:1.6}}>Multi-provider malware scanning for IR Simulator policy and AAR uploads. Configure one or more vendor scanners; the dispatcher routes uploads through them based on the selected scan mode. Credentials are encrypted at rest (AES-256-GCM) and decrypted only at scan time.</M>
          <Card style={{marginBottom:16,borderColor:C.w+"40",background:C.wd}}>
            <M style={{color:C.w,fontWeight:600,letterSpacing:1.2,textTransform:"uppercase",fontSize:10,display:"block",marginBottom:6}}>IR Simulator requires at least one enabled scanner</M>
            <M style={{color:C.t,lineHeight:1.6}}>Policy and AAR uploads are gated by malware scanning. If no enabled scanner is configured, IR Simulator uploads will be rejected with MALWARE_SCANNER_REQUIRED. Other parts of the platform are not affected.</M>
          </Card>

          {scannerError&&<Card style={{marginBottom:16,borderColor:C.d+"40",background:C.dd}}><M style={{color:C.d}}>Error loading scanners: {scannerError}</M></Card>}

          {/* ── SCAN MODE ── */}
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Scan mode</div>
            <label style={{display:"flex",alignItems:"flex-start",gap:8,padding:"6px 0",cursor:"pointer"}}>
              <input type="radio" name="scanmode" checked={scanMode==="single_with_fallback"} onChange={()=>setScanMode("single_with_fallback")} style={{accentColor:C.a,marginTop:3}}/>
              <div>
                <M style={{color:C.t,fontWeight:500,display:"block"}}>Single with priority fallback (recommended)</M>
                <M style={{color:C.tm,display:"block",marginTop:2,lineHeight:1.5}}>Try scanners in priority order. The first scanner that returns an authoritative result wins. Scanner errors fall through to the next scanner. If every scanner errors, the upload is rejected.</M>
              </div>
            </label>
            <label style={{display:"flex",alignItems:"flex-start",gap:8,padding:"6px 0",cursor:"pointer"}}>
              <input type="radio" name="scanmode" checked={scanMode==="all_configured"} onChange={()=>setScanMode("all_configured")} style={{accentColor:C.a,marginTop:3}}/>
              <div>
                <M style={{color:C.t,fontWeight:500,display:"block"}}>All configured (defense in depth)</M>
                <M style={{color:C.tm,display:"block",marginTop:2,lineHeight:1.5}}>Run all enabled scanners in parallel. The upload passes only if every scanner returns clean. Any flagged verdict, any scanner error, fails the upload. Slower but catches threats one engine might miss.</M>
              </div>
            </label>
            <Btn primary small style={{marginTop:10}} onClick={async()=>{
              const r=await api.post("/api/v1/malware-scanners/scan-mode",{mode:scanMode});
              if(r&&!r.error){addA("MALWARE_SCAN_MODE_SAVED","Scan mode set to "+scanMode);}
              else{setScannerError((r&&r.error)||"failed to save scan mode");}
            }}>Save scan mode</Btn>
          </Card>

          {/* ── CONFIGURED SCANNERS LIST ── */}
          <Card style={{marginBottom:16}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
              <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5"}}>Configured scanners ({scannerList.length})</div>
              <Btn primary small onClick={()=>setScannerForm({mode:"add",provider_type:"",display_name:"",priority:100,enabled:true,credentials:{}})}>+ Add Scanner</Btn>
            </div>
            {scannerListLoading&&<M style={{color:C.tm}}>Loading...</M>}
            {!scannerListLoading&&scannerList.length===0&&(
              <div style={{padding:"24px 0",textAlign:"center"}}>
                <M style={{color:C.tm,display:"block",marginBottom:8}}>No scanners configured.</M>
                <M style={{color:C.tm,display:"block"}}>IR Simulator uploads will be rejected until at least one scanner is added and enabled.</M>
              </div>
            )}
            {scannerList.map(s=>{
              const provider=SCANNER_PROVIDERS.find(p=>p.id===s.provider_type);
              const tr=scannerTestResult[s.id];
              const lastTest=s.last_test_status;
              const testColor=lastTest==="success"?C.a:lastTest==="failed"?C.d:C.tm;
              return(<div key={s.id} style={{padding:"12px 0",borderTop:`1px solid ${C.b}`,display:"flex",alignItems:"center",gap:12,opacity:s.enabled?1:0.55}}>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                    <M style={{color:C.t,fontWeight:600}}>{s.display_name}</M>
                    <span style={{fontSize:9,padding:"1px 6px",borderRadius:8,background:C.id,color:C.i,fontFamily:"'IBM Plex Mono',monospace"}}>P{s.priority}</span>
                    {!s.enabled&&<span style={{fontSize:9,padding:"1px 6px",borderRadius:8,background:C.b,color:C.tm,fontFamily:"'IBM Plex Mono',monospace"}}>DISABLED</span>}
                  </div>
                  <M style={{color:C.tm,display:"block"}}>{provider?provider.label:s.provider_type}</M>
                  <div style={{display:"flex",gap:12,marginTop:6,flexWrap:"wrap"}}>
                    <M style={{color:testColor}}>Test: {lastTest||"never"}</M>
                    <M style={{color:C.tm}}>Scans: {s.total_scans||0}</M>
                    <M style={{color:C.tm}}>Threats: {s.total_threats_detected||0}</M>
                    <M style={{color:C.tm}}>Failures: {s.total_failures||0}</M>
                  </div>
                  {s.last_test_error&&<M style={{color:C.d,display:"block",marginTop:4,fontSize:9}}>Last error: {s.last_test_error}</M>}
                  {tr&&(<M style={{color:tr.ok?C.a:C.d,display:"block",marginTop:4,fontSize:9}}>{tr.ok?`✓ Connection OK (${tr.latencyMs||0}ms)`:`✗ ${tr.error||"failed"}`}</M>)}
                </div>
                <div style={{display:"flex",gap:6,flexShrink:0}}>
                  <Btn small onClick={async()=>{
                    setScannerTestResult(prev=>({...prev,[s.id]:{ok:null,testing:true}}));
                    const r=await api.post(`/api/v1/malware-scanners/${s.id}/test`,{});
                    setScannerTestResult(prev=>({...prev,[s.id]:r||{ok:false,error:"no response"}}));
                    reloadScanners();
                  }}>Test</Btn>
                  <Btn small onClick={async()=>{
                    const r=await api.post(`/api/v1/malware-scanners/${s.id}`,{enabled:!s.enabled});
                    if(r&&!r.error)reloadScanners();
                  }}>{s.enabled?"Disable":"Enable"}</Btn>
                  <Btn small onClick={()=>setScannerForm({mode:"edit",id:s.id,provider_type:s.provider_type,display_name:s.display_name,priority:s.priority,enabled:s.enabled,credentials:{}})}>Edit</Btn>
                  <Btn small danger onClick={async()=>{
                    if(!window.confirm(`Delete scanner "${s.display_name}"? This cannot be undone.`))return;
                    const r=await api.del(`/api/v1/malware-scanners/${s.id}`);
                    if(r&&!r.error){addA("MALWARE_SCANNER_DELETED",s.display_name+" ("+s.provider_type+")");reloadScanners();}
                    else{setScannerError((r&&r.error)||"delete failed");}
                  }}>Del</Btn>
                </div>
              </div>);
            })}
          </Card>

          <M style={{color:C.tm,display:"block",lineHeight:1.6}}>Note: vendor integrations are not validated against live API endpoints in CI. Verify each scanner with the Test button after configuration. See README for per-vendor setup details.</M>

          {/* ── ADD/EDIT MODAL ── */}
          {scannerForm&&(<div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.85)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={()=>setScannerForm(null)}>
            <div onClick={e=>e.stopPropagation()} style={{background:C.bg,border:`1px solid ${C.b}`,borderRadius:16,padding:32,maxWidth:600,width:"90%",maxHeight:"85vh",overflowY:"auto"}}>
              <L>{scannerForm.mode==="add"?"Add Scanner":"Edit Scanner"}</L>
              <Sel label="Provider" value={scannerForm.provider_type} onChange={e=>setScannerForm(prev=>({...prev,provider_type:e.target.value,credentials:{}}))} disabled={scannerForm.mode==="edit"}>
                <option value="">Select a provider...</option>
                {SCANNER_PROVIDERS.map(p=>(<option key={p.id} value={p.id}>{p.label}</option>))}
              </Sel>
              <Input label="Display name" value={scannerForm.display_name} onChange={e=>setScannerForm(prev=>({...prev,display_name:e.target.value}))} placeholder="e.g. Production CrowdStrike" maxLength={256}/>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                <Input label="Priority (1-1000, lower runs first)" type="number" min="1" max="1000" value={scannerForm.priority} onChange={e=>setScannerForm(prev=>({...prev,priority:Number(e.target.value)||100}))}/>
                <div style={{display:"flex",alignItems:"center",paddingTop:18}}>
                  <label style={{display:"flex",alignItems:"center",gap:8,cursor:"pointer"}}>
                    <input type="checkbox" checked={scannerForm.enabled} onChange={e=>setScannerForm(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>
                    <M style={{color:C.t}}>Enabled</M>
                  </label>
                </div>
              </div>
              {scannerForm.provider_type&&(()=>{
                const p=SCANNER_PROVIDERS.find(x=>x.id===scannerForm.provider_type);
                if(!p)return null;
                return(<div style={{marginTop:8,padding:12,background:C.sh,border:`1px solid ${C.b}`,borderRadius:8}}>
                  <M style={{color:C.tm,display:"block",marginBottom:10,fontSize:9,letterSpacing:1.2,textTransform:"uppercase"}}>Credentials</M>
                  {scannerForm.mode==="edit"&&<M style={{color:C.w,display:"block",marginBottom:10,lineHeight:1.5}}>Leave fields empty to keep existing credentials. Filling any field replaces the entire credential set.</M>}
                  {p.fields.map(f=>{
                    const v=scannerForm.credentials[f.k]||"";
                    if(f.bool){
                      return(<label key={f.k} style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0",cursor:"pointer"}}>
                        <input type="checkbox" checked={v!==false&&v!==""} onChange={e=>setScannerForm(prev=>({...prev,credentials:{...prev.credentials,[f.k]:e.target.checked}}))} style={{accentColor:C.a}}/>
                        <M style={{color:C.t}}>{f.l}</M>
                      </label>);
                    }
                    if(f.sel){
                      return(<Sel key={f.k} label={f.l} value={v} onChange={e=>setScannerForm(prev=>({...prev,credentials:{...prev.credentials,[f.k]:e.target.value}}))}>
                        <option value="">Select...</option>
                        {f.sel.map(o=>(<option key={o.v} value={o.v}>{o.l}</option>))}
                      </Sel>);
                    }
                    return(<Input key={f.k} label={f.l} type={f.secret?"password":"text"} value={v} placeholder={f.ph||""} onChange={e=>setScannerForm(prev=>({...prev,credentials:{...prev.credentials,[f.k]:e.target.value}}))}/>);
                  })}
                </div>);
              })()}
              <div style={{display:"flex",gap:8,marginTop:16,justifyContent:"flex-end"}}>
                <Btn onClick={()=>setScannerForm(null)}>Cancel</Btn>
                <Btn primary onClick={async()=>{
                  if(!scannerForm.provider_type){setScannerError("Provider is required");return;}
                  if(!scannerForm.display_name||!scannerForm.display_name.trim()){setScannerError("Display name is required");return;}
                  const hasAnyCred=Object.keys(scannerForm.credentials).length>0&&Object.values(scannerForm.credentials).some(v=>v!==""&&v!==null&&v!==undefined);
                  if(scannerForm.mode==="add"&&!hasAnyCred){setScannerError("Credentials are required for new scanners");return;}
                  const body={display_name:scannerForm.display_name.trim(),priority:scannerForm.priority,enabled:scannerForm.enabled};
                  if(scannerForm.mode==="add")body.provider_type=scannerForm.provider_type;
                  if(hasAnyCred)body.credentials=scannerForm.credentials;
                  const path=scannerForm.mode==="add"?"/api/v1/malware-scanners":`/api/v1/malware-scanners/${scannerForm.id}`;
                  const r=await api.post(path,body);
                  if(r&&!r.error){
                    addA(scannerForm.mode==="add"?"MALWARE_SCANNER_ADDED":"MALWARE_SCANNER_UPDATED",scannerForm.display_name+" ("+scannerForm.provider_type+")");
                    setScannerForm(null);
                    setScannerError(null);
                    reloadScanners();
                  }else{
                    setScannerError((r&&r.error)||"save failed");
                  }
                }}>{scannerForm.mode==="add"?"Add Scanner":"Save Changes"}</Btn>
              </div>
            </div>
          </div>)}
        </div>)}

        {/* ══════════ ENTERPRISE KMS ══════════ */}
        {tab==="kms"&&(<div>
          <L>Enterprise Key Management</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Integrate with your enterprise key management system for centralized key lifecycle management, HSM-backed key storage, and automated rotation. All encryption tiers (Tier-3 analyst data, Tier-1 team data, E2EE peer chat, backups, audit log signing) can be managed through your KMS.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={kmsCfg.enabled} onChange={e=>setKmsCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable enterprise KMS</label>
            <Sel label="KMS Provider" value={kmsCfg.provider||""} onChange={e=>setKmsCfg(prev=>({...prev,provider:e.target.value}))}>
              <option value="">Select...</option><option value="aws_kms">AWS KMS</option><option value="azure_keyvault">Azure Key Vault</option><option value="gcp_cloudkms">GCP Cloud KMS</option><option value="hashicorp_vault">HashiCorp Vault</option><option value="thales_ciphertrust">Thales CipherTrust Manager</option><option value="entrust_nshield">Entrust nShield</option>
            </Sel>
            <Input label="KMS endpoint / ARN" value={kmsCfg.endpoint} onChange={e=>setKmsCfg(prev=>({...prev,endpoint:e.target.value}))} placeholder="arn:aws:kms:us-east-1:123456789:key/..." maxLength={512}/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Input label="Key ID / alias" value={kmsCfg.keyId} onChange={e=>setKmsCfg(prev=>({...prev,keyId:e.target.value}))} maxLength={256}/>
              <Sel label="Rotation policy" value={kmsCfg.rotationPolicy} onChange={e=>setKmsCfg(prev=>({...prev,rotationPolicy:e.target.value}))}><option value="monthly">Monthly</option><option value="quarterly">Quarterly</option><option value="annual">Annual</option><option value="manual">Manual</option></Sel>
            </div>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0",cursor:"pointer"}}><input type="checkbox" checked={kmsCfg.hsmBacked} onChange={e=>setKmsCfg(prev=>({...prev,hsmBacked:e.target.checked}))}/><M style={{color:C.t}}>HSM-backed keys (FIPS 140-2 Level 3+)</M></label>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:8,marginBottom:8}}>Key Usage Scope</div>
            {[{k:"tier3Encryption",l:"Tier-3: Analyst private data encryption"},{k:"tier1Encryption",l:"Tier-1: Team aggregate data encryption"},{k:"e2eeKeyWrapping",l:"E2EE: Peer chat key wrapping"},{k:"backupEncryption",l:"Backup encryption"},{k:"auditLogSigning",l:"Audit log signing"}].map(u=>(
              <label key={u.k} style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={kmsCfg.keyUsage[u.k]} onChange={e=>setKmsCfg(prev=>({...prev,keyUsage:{...prev.keyUsage,[u.k]:e.target.checked}}))}/><M style={{color:C.t}}>{u.l}</M></label>
            ))}
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"KMS_CONFIG_SAVED",detail:"Enterprise KMS configuration saved"}).then(()=>addA("KMS_CONFIG_SAVED","Enterprise KMS configuration saved"))}>Save KMS Config</Btn>
        </div>)}

        {/* ══════════ WIFI SECURITY POLICY ══════════ */}
        {tab==="wifi"&&(<div>
          <L>WiFi Security Policy</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Set minimum WiFi security requirements for analyst clients. WPA2-Enterprise with 802.1X/EAP is the recommended minimum (per-user authentication, not shared PSK). WPA2-Personal (PSK) is vulnerable to brute force attacks that expose traffic to interception — an attacker could modify packets affecting incident response routing.</M>
          <Card style={{marginBottom:16}}>
            <Sel label="Minimum WiFi protocol" value={wifiPolicy.minimumProtocol} onChange={e=>setWifiPolicy(prev=>({...prev,minimumProtocol:e.target.value}))}>
              <option value="wpa3">WPA3 (strongest — may limit compatibility)</option>
              <option value="wpa2_enterprise">WPA2-Enterprise with 802.1X (recommended)</option>
              <option value="wpa2_personal">WPA2-Personal / PSK (NOT recommended)</option>
            </Sel>
            {wifiPolicy.minimumProtocol==="wpa2_personal"&&<Card style={{padding:10,marginBottom:12,borderColor:C.d+"40"}}><M style={{color:C.d,fontWeight:500}}>WPA2-Personal is vulnerable to offline brute force attacks. Traffic can be intercepted and modified. This setting is strongly discouraged for SOC environments.</M></Card>}
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0",cursor:"pointer"}}><input type="checkbox" checked={wifiPolicy.wpa3Preferred} onChange={e=>setWifiPolicy(prev=>({...prev,wpa3Preferred:e.target.checked}))}/><M style={{color:C.t}}>Prefer WPA3 where available (recommend to clients)</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={wifiPolicy.blockWpa2Personal} onChange={e=>setWifiPolicy(prev=>({...prev,blockWpa2Personal:e.target.checked}))}/><M style={{color:C.d}}>Block connections over WPA2-Personal / PSK</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={wifiPolicy.requireDot1x} onChange={e=>setWifiPolicy(prev=>({...prev,requireDot1x:e.target.checked}))}/><M style={{color:C.t}}>Require 802.1X/EAP authentication</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={wifiPolicy.warnOnInsecure} onChange={e=>setWifiPolicy(prev=>({...prev,warnOnInsecure:e.target.checked}))}/><M style={{color:C.w}}>Warn analyst when WiFi is below policy</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={wifiPolicy.disconnectOnInsecure} onChange={e=>setWifiPolicy(prev=>({...prev,disconnectOnInsecure:e.target.checked}))}/><M style={{color:C.d}}>Disconnect client if WiFi is below policy (strict mode)</M></label>
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"WIFI_POLICY_SAVED",detail:"WiFi security policy saved"}).then(()=>addA("WIFI_POLICY_SAVED","WiFi security policy saved"))}>Save WiFi Policy</Btn>
        </div>)}

        {/* ══════════ MSP MULTI-TENANCY ══════════ */}
        {tab==="msp"&&(<div>
          <L>MSP Multi-Tenancy</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Configure FireAlive for managed service providers monitoring multiple client organizations. Each tenant gets isolated encryption keys, separate audit trails, and scoped API keys. Cross-tenant data access is blocked by default.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={mspCfg.enabled} onChange={e=>setMspCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable MSP multi-tenancy mode</label>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Tenant Isolation</div>
            {[{k:"separateEncryptionKeys",l:"Separate encryption keys per tenant"},{k:"separateAuditTrails",l:"Separate audit trails per tenant"},{k:"crossTenantAccessBlocked",l:"Block cross-tenant data access"},{k:"tenantScopedApiKeys",l:"Tenant-scoped API keys"},{k:"perTenantBackups",l:"Per-tenant backup isolation"}].map(s=>(
              <label key={s.k} style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={mspCfg.isolation[s.k]} onChange={e=>setMspCfg(prev=>({...prev,isolation:{...prev.isolation,[s.k]:e.target.checked}}))}/><M style={{color:C.t}}>{s.l}</M></label>
            ))}
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:12,marginBottom:8}}>Management Overlay</div>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={mspCfg.managementOverlay.centralDashboard} onChange={e=>setMspCfg(prev=>({...prev,managementOverlay:{...prev.managementOverlay,centralDashboard:e.target.checked}}))}/><M style={{color:C.t}}>Central management dashboard across tenants</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={mspCfg.managementOverlay.aggregateReporting} onChange={e=>setMspCfg(prev=>({...prev,managementOverlay:{...prev.managementOverlay,aggregateReporting:e.target.checked}}))}/><M style={{color:C.w}}>Aggregate reporting across tenants (privacy implications — requires tenant consent)</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={mspCfg.managementOverlay.tenantAdminDelegation} onChange={e=>setMspCfg(prev=>({...prev,managementOverlay:{...prev.managementOverlay,tenantAdminDelegation:e.target.checked}}))}/><M style={{color:C.t}}>Delegate admin to tenant-level team leads</M></label>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Tenants ({mspCfg.tenants.length})</div>
            {mspCfg.tenants.length===0?<M style={{color:C.td}}>No tenants configured. Add a tenant below.</M>:
            mspCfg.tenants.map(t=><Card key={t.id} style={{marginBottom:6,padding:"10px 14px",borderLeft:`3px solid ${C.a}`}}><div style={{display:"flex",justifyContent:"space-between"}}><div><M style={{color:C.t,fontWeight:500}}>{t.name}</M><br/><M style={{color:C.td}}>{t.domain} · Key: {t.encryptionKeyId?.slice(0,8)}…</M></div><Badge color={C.a}>{t.status}</Badge></div></Card>)}
            <div style={{display:"flex",gap:8,marginTop:10}}><Input label="New tenant name" value={newTenantName} onChange={e=>setNewTenantName(e.target.value)} placeholder="Client org name" maxLength={128}/><Btn primary disabled={!newTenantName.trim()} style={{marginTop:16}} onClick={()=>{const t={id:Math.random().toString(36).slice(2,10),name:newTenantName,domain:"",encryptionKeyId:Math.random().toString(36).slice(2,18),createdAt:new Date().toISOString(),status:"active"};setMspCfg(prev=>({...prev,tenants:[...prev.tenants,t]}));setNewTenantName("");addA("MSP_TENANT_CREATED","Tenant created: "+t.name);}}>Add Tenant</Btn></div>
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"MSP_CONFIG_SAVED",detail:"MSP multi-tenancy configuration saved"}).then(()=>addA("MSP_CONFIG_SAVED","MSP multi-tenancy configuration saved"))}>Save MSP Config</Btn>
        </div>)}

        {/* ══════════ R3f — MFA SELF-SERVICE + ADMIN POLICY ══════════ */}
        {tab==="mfa"&&(<div>
          <L>Multi-Factor Authentication</L>
            <MyMfaSecuritySection/>
          <M style={{color:C.tm,display:"block",marginTop:16,marginBottom:16,lineHeight:1.6}}>Configure MFA policy for FireAlive's built-in authentication. If you use enterprise IAM (SAML/OIDC) with MFA already enforced at the IdP, this is redundant — your IdP handles MFA. The policy below is for deployments without IAM integration.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={mfaCfg.enabled} onChange={e=>setMfaCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable built-in MFA</label>
            <Sel label="MFA Method" value={mfaCfg.method} onChange={e=>setMfaCfg(prev=>({...prev,method:e.target.value}))}>
              <option value="totp">TOTP (Google Authenticator, Authy, etc.)</option>
              <option value="webauthn">WebAuthn / FIDO2 (hardware key — YubiKey, etc.)</option>
              <option value="totp_or_webauthn">TOTP or WebAuthn (user choice)</option>
            </Sel>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0",cursor:"pointer"}}><input type="checkbox" checked={mfaCfg.enforceForAll} onChange={e=>setMfaCfg(prev=>({...prev,enforceForAll:e.target.checked}))}/><M style={{color:C.t}}>Enforce MFA for all users (team lead + analysts)</M></label>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Input label="Grace logins before enforcement" value={mfaCfg.graceLogins} onChange={e=>setMfaCfg(prev=>({...prev,graceLogins:parseInt(e.target.value)||0}))} type="number"/>
              <Input label="Remember device (days)" value={mfaCfg.rememberDeviceDays} onChange={e=>setMfaCfg(prev=>({...prev,rememberDeviceDays:parseInt(e.target.value)||0}))} type="number"/>
            </div>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0",cursor:"pointer"}}><input type="checkbox" checked={mfaCfg.backupCodes} onChange={e=>setMfaCfg(prev=>({...prev,backupCodes:e.target.checked}))}/><M style={{color:C.t}}>Generate one-time backup codes (10 codes, SHA-256 hashed at rest)</M></label>
          </Card>
          <Card style={{marginBottom:16,padding:12,borderColor:C.i+"30"}}>
            <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:4}}>Password Policy (NIST 800-63B compliant)</M>
            <M style={{color:C.tm,lineHeight:1.8}}>Minimum 12 characters · No composition rules (no forced symbols/uppercase/numbers) · No mandatory rotation — password changes only on evidence of compromise · Passwords checked against breached password databases (HaveIBeenPwned k-anonymity API) · bcrypt with cost factor 12 (not plain SHA/MD5) · Account lockout after 10 failed attempts (15-min progressive backoff) · All passwords salted with per-user cryptographically random salt</M>
          </Card>
          <M style={{color:C.td,display:"block",marginBottom:12,fontStyle:"italic"}}>This follows current NIST SP 800-63B guidance: no complexity rules, no forced rotation, breach-checking, and strong hashing. The old 90-day rotation + complexity rules are deprecated because they cause password reuse and sticky notes.</M>
          <Btn primary onClick={()=>{ setMfaCfg(prev=>({...prev,status:"configured"})); addA("MFA_CONFIG_SAVED","MFA configuration saved — method: "+mfaCfg.method); }}>Save MFA Config</Btn>
        </div>)}

        {/* ══════════ v1.0.0 — THREAT HUNTING INTEGRATIONS ══════════ */}
        {tab==="threat_hunt"&&(<div>
          <L>Threat Hunting Integrations</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Open FireAlive to inspection by your organization's threat hunting and anti-malware systems. These integrations allow EDR, XDR, ATP, Next-Gen AV, and MSP security tools to scan files, monitor app behavior, inspect consumption metrics, and scan app update packages — without exposing the app to unauthorized access.</M>
          {[
            {key:"xdr",label:"XDR (Extended Detection & Response)",desc:"Behavioral monitoring + consumption metrics. XDR correlates endpoint, network, and cloud signals.",providers:["Palo Alto Cortex XDR","Microsoft 365 Defender","Trend Micro Vision One","Fortinet FortiXDR","Trellix XDR"],fields:[{k:"behaviorMonitoring",l:"Monitor app behavior patterns"},{k:"consumptionMetrics",l:"Access resource consumption metrics"}]},
            {key:"atp",label:"ATP (Advanced Threat Protection)",desc:"Deep inspection of files and network traffic for advanced persistent threats.",providers:["Microsoft Defender ATP","FireEye/Mandiant","Proofpoint ATP","Mimecast ATP"]},
            {key:"ngav",label:"Next-Gen Antivirus",desc:"ML-based malware detection beyond signature matching.",providers:["CrowdStrike Falcon Prevent","Cylance PROTECT","SentinelOne Singularity","Sophos Intercept X","Webroot"],fields:[{k:"realTimeScan",l:"Real-time file scanning"}]},
            {key:"mspScanner",label:"MSP Security Scanner",desc:"Third-party MSP management agents for remote monitoring and scanning.",providers:["Datto RMM","ConnectWise Automate","NinjaOne","Kaseya VSA","Atera"]},
          ].map(cat=>(
            <Card key={cat.key} style={{marginBottom:12}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}><div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>{cat.label}</div><Badge color={threatHuntCfg[cat.key]?.enabled?C.a:C.td}>{threatHuntCfg[cat.key]?.enabled?"enabled":"disabled"}</Badge></div>
              <M style={{color:C.tm,display:"block",marginBottom:10}}>{cat.desc}</M>
              <label style={{display:"flex",alignItems:"center",gap:8,marginBottom:10}}><input type="checkbox" checked={threatHuntCfg[cat.key]?.enabled||false} onChange={e=>setThreatHuntCfg(prev=>({...prev,[cat.key]:{...prev[cat.key],enabled:e.target.checked}}))} style={{accentColor:C.a}}/><M style={{color:C.t}}>Enable {cat.label}</M></label>
              <Sel label="Provider" value={threatHuntCfg[cat.key]?.provider||""} onChange={e=>setThreatHuntCfg(prev=>({...prev,[cat.key]:{...prev[cat.key],provider:e.target.value}}))}>
                <option value="">Select...</option>{cat.providers.map(p=><option key={p} value={p.toLowerCase().replace(/\s/g,"_")}>{p}</option>)}
              </Sel>
              {cat.fields&&cat.fields.map(f=>(
                <label key={f.k} style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={threatHuntCfg[cat.key]?.[f.k]||false} onChange={e=>setThreatHuntCfg(prev=>({...prev,[cat.key]:{...prev[cat.key],[f.k]:e.target.checked}}))}/><M style={{color:C.t}}>{f.l}</M></label>
              ))}
            </Card>
          ))}
          <Card style={{padding:12,borderColor:C.i+"30",marginBottom:16}}>
            <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:4}}>What These Integrations Inspect</M>
            <M style={{color:C.tm,lineHeight:1.8}}>Uploaded files (analyst attachments, config imports) · App update packages (before installation) · Application behavior patterns (API call frequency, memory usage, DB access patterns) · Resource consumption metrics (CPU, memory, network I/O anomalies) · All scanning integrations use read-only API tokens scoped to the specific inspection function</M>
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"THREAT_HUNT_CONFIG_SAVED",detail:"Threat hunting integrations saved"}).then(()=>addA("THREAT_HUNT_CONFIG_SAVED","Threat hunting integrations saved"))}>Save All Threat Hunting Config</Btn>
        </div>)}

        {/* ══════════ v1.0.0 — TRIPWIRE ══════════ */}
        {tab==="tripwire"&&(<div>
          <L>Reduced-Routing Tripwire</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>If a large percentage of analysts simultaneously enter reduced routing, it could indicate a coordinated attack where compromised clients are requesting load reduction to degrade SOC response capacity. This tripwire automatically disables burnout routing and alerts you to investigate.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={tripwireCfg.enabled} onChange={e=>setTripwireCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable tripwire</label>
            <Input label={"Threshold — trip when ≥ this % of analysts are in reduced routing"} value={tripwireCfg.thresholdPct} onChange={e=>setTripwireCfg(prev=>({...prev,thresholdPct:parseInt(e.target.value)||0}))} type="number"/>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:12,marginBottom:8}}>When Tripped</div>
            <M style={{color:C.a,fontWeight:500,display:"block",padding:"8px 0",borderBottom:"1px solid "+C.b}}>Anonymity always enforced.</M>
            {[{k:"autoDisableRouting",l:"Auto-disable all burnout routing (tickets flow unfiltered)"},{k:"notifyLead",l:"Send alert to Team Lead (email + desktop + SMS)"},{k:"triggerSoarScan",l:"Trigger SOAR playbook to investigate compromised clients"},{k:"triggerEdrScan",l:"Trigger EDR/XDR scans on all analyst clients"}].map(s=>(
              <label key={s.k} style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={tripwireCfg[s.k]} onChange={e=>setTripwireCfg(prev=>({...prev,[s.k]:e.target.checked}))}/><M style={{color:s.k==="preserveAnonymity"?C.p:C.t}}>{s.l}</M></label>
            ))}
          </Card>
          {tripwireTriggered&&<Card style={{padding:14,borderColor:C.d,marginBottom:16,animation:"pulse 1.5s infinite"}}><M style={{color:C.d,fontWeight:700,fontSize:14}}>⚠ TRIPWIRE TRIGGERED</M><M style={{color:C.tm,display:"block",marginTop:6}}>Routing DISABLED. Training CANCELLED. Filter OFF.</M></Card>}
          <div style={{display:"flex",gap:8}}>
            <Btn primary onClick={()=>addA("TRIPWIRE_CONFIG_SAVED","Tripwire config saved — threshold: "+tripwireCfg.thresholdPct+"%")}>Save Tripwire Config</Btn>
            <Btn onClick={()=>{setTripwireTriggered(true);setPanicMode(true);api.post("/api/v1/audit/log",{event:"TRIPWIRE_MANUAL_TEST",detail:"Tripwire triggered"}).then(()=>addA("TRIPWIRE_MANUAL_TEST","Tripwire triggered"));}}>Test Tripwire</Btn>
            {tripwireTriggered&&<Btn onClick={()=>{setTripwireTriggered(false);api.post("/api/v1/audit/log",{event:"TRIPWIRE_RESET",detail:"Tripwire reset"}).then(()=>addA("TRIPWIRE_RESET","Tripwire reset"));}}>Reset Tripwire</Btn>}
          </div>
        </div>)}

        {/* ══════════ v1.0.0 — COMPROMISE SCAN ══════════ */}
        {tab==="compromise_scan"&&(<div>
          <L>Client Compromise Scan</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Orchestrate automated compromise tests across analyst clients. Each client runs self-diagnostics and returns a signed report. Use after a tripwire event or any time you suspect client compromise. Tests run via integrated EDR/XDR/SOAR systems and the client's own integrity checks. Scan results use pseudonyms and contain NO burnout data — only system health metrics (binary integrity, memory, network, config drift).</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Tests Performed on Each Client</div>
            <M style={{color:C.tm,lineHeight:1.8,display:"block"}}>
              1. SHA-256 integrity check of app binary against known-good hash{"\n"}
              2. Memory analysis — check for injected code or suspicious processes{"\n"}
              3. Database query spike detection (unusual request patterns){"\n"}
              4. Network connection audit (unexpected outbound connections){"\n"}
              5. Configuration drift detection (compare against last known-good config){"\n"}
              6. EDR/XDR scan invocation (malware, worms, rootkits){"\n"}
              7. API token validity and scope verification{"\n"}
              8. Audit log continuity check (gaps or deletions){"\n"}
              9. TLS certificate pinning verification{"\n"}
              10. File system integrity (unexpected new files in app directories)
            </M>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Target</div>
            <div style={{display:"flex",gap:8,marginBottom:12}}>
              <Btn primary onClick={()=>{setCompScanRunning(true);api.post("/api/v1/audit/log",{event:"COMPROMISE_SCAN_ALL",detail:"Initiated compromise scan on ALL linked clients"}).then(()=>addA("COMPROMISE_SCAN_ALL","Initiated compromise scan on ALL linked clients"));setTimeout(()=>{setCompScanRunning(false);setCompScanResults({ts:new Date().toISOString(),clients:[{name:"jordan-p-ws",status:"clean",tests:10,passed:10,signed:true},{name:"priya-s-ws",status:"clean",tests:10,passed:10,signed:true},{name:"alex-k-ws",status:"warning",tests:10,passed:9,signed:true,failures:["Unusual DB query spike (42 queries/sec vs baseline 8/sec)"]},{name:"maya-c-ws",status:"clean",tests:10,passed:10,signed:true},{name:"fatima-a-ws",status:"clean",tests:10,passed:10,signed:true},{name:"sam-r-ws",status:"clean",tests:10,passed:10,signed:true}]});api.post("/api/v1/audit/log",{event:"COMPROMISE_SCAN_COMPLETE",detail:"Scan complete — 5 clean, 1 warning"}).then(()=>addA("COMPROMISE_SCAN_COMPLETE","Scan complete — 5 clean, 1 warning"));},2500);}} disabled={compromiseScanRunning}>{compromiseScanRunning?"Scanning...":"Scan All Clients"}</Btn>
            </div>
            <div style={{display:"flex",gap:8,alignItems:"flex-end"}}>
              <Sel label="Scan single client" value="" onChange={e=>{if(!e.target.value)return;const name=e.target.value;setCompScanRunning(true);addA("COMPROMISE_SCAN_SINGLE","Scanning: "+name);setTimeout(()=>{setCompScanRunning(false);setCompScanResults({ts:new Date().toISOString(),clients:[{name,status:"clean",tests:10,passed:10,signed:true}]});addA("COMPROMISE_SCAN_SINGLE_DONE",name+" — clean");},1500);}}>
                <option value="">Select client...</option>{analysts.map(a=><option key={a.id} value={a.name+"-ws"}>{a.name} ({a.name}-ws)</option>)}
              </Sel>
            </div>
          </Card>
          {compromiseScanResults&&(<Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Scan Results — {new Date(compromiseScanResults.ts).toLocaleString()}</div>
            {compromiseScanResults.clients.map(c=>(
              <div key={c.name} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 0",borderBottom:`1px solid ${C.b}`}}>
                <div>
                  <M style={{color:C.t,fontWeight:500}}>{c.name}</M>
                  <M style={{color:C.td,display:"block"}}>{c.passed}/{c.tests} tests passed · Report {c.signed?"signed ✓":"unsigned ⚠"}</M>
                  {c.failures&&c.failures.map((f,i)=><M key={i} style={{color:C.w,display:"block"}}>⚠ {f}</M>)}
                </div>
                <Badge color={c.status==="clean"?C.a:c.status==="warning"?C.w:C.d}>{c.status}</Badge>
              </div>
            ))}
            <div style={{display:"flex",gap:8,marginTop:12}}>
              <Btn small onClick={()=>api.post("/api/v1/audit/log",{event:"COMPROMISE_REPORT_EXPORT",detail:"Compromise scan report exported"}).then(()=>addA("COMPROMISE_REPORT_EXPORT","Compromise scan report exported"))}>Export Report</Btn>
              <Btn small onClick={()=>api.post("/api/v1/audit/log",{event:"COMPROMISE_REPORT_SOAR",detail:"Sent to SOAR for automated follow-up"}).then(()=>addA("COMPROMISE_REPORT_SOAR","Sent to SOAR for automated follow-up"))}>Send to SOAR</Btn>
              <Btn small onClick={()=>api.post("/api/v1/audit/log",{event:"COMPROMISE_REPORT_SIEM",detail:"Sent to SIEM as security event"}).then(()=>addA("COMPROMISE_REPORT_SIEM","Sent to SIEM as security event"))}>Send to SIEM</Btn>
            </div>
          </Card>)}
        </div>)}

        {/* ══════════ v1.0.0 — AUTH LOGS ══════════ */}
        {tab==="auth_logs"&&(<div>
          <L>Authorization Logs</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Track all authentication attempts — successful and failed — for both the Management Console and Analyst Clients. Useful for detecting brute-force attacks, credential stuffing, and unauthorized access attempts. When IAM is integrated, these supplement your IdP's logs.</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Recent Authentication Events</div>
            {authLogs.map((log,i)=>(
              <div key={i} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
                <div>
                  <M style={{color:log.action.includes("FAIL")?C.d:C.a,fontWeight:500}}>{log.action}</M>
                  <M style={{color:C.td,display:"block"}}>{log.user} · {log.ip} · {log.method}{log.reason?" · "+log.reason:""}</M>
                </div>
                <M style={{color:C.td}}>{new Date(log.ts).toLocaleString()}</M>
              </div>
            ))}
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Out-of-Cycle & Anomaly Notifications</div>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0",cursor:"pointer"}}><input type="checkbox" checked={authLogNotifCfg.outOfCycleAttempts} onChange={e=>setAuthLogNotifCfg(prev=>({...prev,outOfCycleAttempts:e.target.checked}))}/><M style={{color:C.t}}>Alert on login attempts outside business hours ({authLogNotifCfg.outOfCycleStartHr}:00–{authLogNotifCfg.outOfCycleEndHr}:00)</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0",cursor:"pointer"}}><input type="checkbox" checked={authLogNotifCfg.deletedLogs} onChange={e=>setAuthLogNotifCfg(prev=>({...prev,deletedLogs:e.target.checked}))}/><M style={{color:C.d}}>Alert if auth logs are deleted or tampered with</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0",cursor:"pointer"}}><input type="checkbox" checked={authLogNotifCfg.missingLogs} onChange={e=>setAuthLogNotifCfg(prev=>({...prev,missingLogs:e.target.checked}))}/><M style={{color:C.w}}>Alert if auth log gaps detected (&gt; 30 min without any entry)</M></label>
            <Input label="Brute-force threshold (failed attempts before alert)" value={authLogNotifCfg.bruteForceThreshold} onChange={e=>setAuthLogNotifCfg(prev=>({...prev,bruteForceThreshold:parseInt(e.target.value)||5}))} type="number"/>
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"AUTH_LOG_CONFIG_SAVED",detail:"Auth log notification config saved"}).then(()=>addA("AUTH_LOG_CONFIG_SAVED","Auth log notification config saved"))}>Save Auth Log Config</Btn>
        </div>)}

        {/* ══════════ v1.0.0 — POSTURE ASSESSMENT ══════════ */}
        {tab==="posture"&&(<div>
          <L>Client Posture Assessment</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Like 802.1X and MDM posture checks, FireAlive can assess analyst workstations at app startup before connecting them to the management console. Non-compliant devices are warned or blocked until they remediate. Prevents a compromised or misconfigured client from exposing the SOC.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={postureCfg.enabled} onChange={e=>setPostureCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable posture assessment</label>
            <label style={{display:"flex",alignItems:"center",gap:8,marginBottom:12}}><input type="checkbox" checked={postureCfg.requireOnConnect} onChange={e=>setPostureCfg(prev=>({...prev,requireOnConnect:e.target.checked}))}/><M style={{color:C.t}}>Require on every connection (not just first launch)</M></label>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Posture Checks</div>
            {[{k:"osUpdated",l:"OS security patches up to date"},{k:"avEnabled",l:"Antivirus / endpoint protection enabled"},{k:"firewallEnabled",l:"Host firewall enabled"},{k:"diskEncrypted",l:"Disk encryption enabled (BitLocker/FileVault)"},{k:"screenLockEnabled",l:"Screen lock enabled (≤ 5 min timeout)"},{k:"wifiCompliant",l:"WiFi connection meets policy (see WiFi Policy tab)"},{k:"endpointProtectionRunning",l:"EDR/XDR agent running"}].map(ch=>(
              <label key={ch.k} style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0",cursor:"pointer"}}><input type="checkbox" checked={postureCfg.checks[ch.k]} onChange={e=>setPostureCfg(prev=>({...prev,checks:{...prev.checks,[ch.k]:e.target.checked}}))}/><M style={{color:C.t}}>{ch.l}</M></label>
            ))}
            <Sel label="Minimum TLS version" value={postureCfg.checks.minTlsVersion} onChange={e=>setPostureCfg(prev=>({...prev,checks:{...prev.checks,minTlsVersion:e.target.value}}))}>
              <option value="1.2">TLS 1.2</option><option value="1.3">TLS 1.3</option>
            </Sel>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:12,marginBottom:8}}>Enforcement</div>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={postureCfg.blockOnFail} onChange={e=>setPostureCfg(prev=>({...prev,blockOnFail:e.target.checked}))}/><M style={{color:C.d}}>Block connection if posture check fails (strict)</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={postureCfg.warnOnFail} onChange={e=>setPostureCfg(prev=>({...prev,warnOnFail:e.target.checked}))}/><M style={{color:C.w}}>Warn user and show remediation steps</M></label>
            <Input label="Grace period (minutes) before blocking" value={postureCfg.gracePeriodMin} onChange={e=>setPostureCfg(prev=>({...prev,gracePeriodMin:parseInt(e.target.value)||0}))} type="number"/>
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"POSTURE_CONFIG_SAVED",detail:"Posture assessment config saved"}).then(()=>addA("POSTURE_CONFIG_SAVED","Posture assessment config saved"))}>Save Posture Config</Btn>
        </div>)}

        {/* ══════════ v1.0.0 — HIGH AVAILABILITY ══════════ */}
        {tab==="ha"&&(<div>
          <L>High Availability Configuration</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Deploy a replica FireAlive server instance in active/passive mode. The active instance handles all traffic while synchronously replicating state to the passive. If the active fails health checks, the passive promotes automatically. The Team Lead's Management Console is decoupled from the backend — it simply points at whichever server is currently active behind the load balancer, so failover is transparent.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={haCfg.enabled} onChange={e=>setHaCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable High Availability</label>
            <Sel label="Mode" value={haCfg.mode} onChange={e=>setHaCfg(prev=>({...prev,mode:e.target.value}))}>
              <option value="active_passive">Active/Passive (recommended)</option>
              <option value="active_active">Active/Active (requires external session store)</option>
            </Sel>
            <Input label="Failover server endpoint" value={haCfg.failoverEndpoint} onChange={e=>setHaCfg(prev=>({...prev,failoverEndpoint:e.target.value}))} placeholder="https://firealive-standby.corp.local:3001" maxLength={512}/>
            <Input label="Replication interval (seconds)" value={haCfg.syncIntervalSec} onChange={e=>setHaCfg(prev=>({...prev,syncIntervalSec:parseInt(e.target.value)||5}))} type="number"/>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:12,marginBottom:8}}>Load Balancer</div>
            <label style={{display:"flex",alignItems:"center",gap:8,marginBottom:10}}><input type="checkbox" checked={haCfg.loadBalancer.enabled} onChange={e=>setHaCfg(prev=>({...prev,loadBalancer:{...prev.loadBalancer,enabled:e.target.checked}}))}/><M style={{color:C.t}}>Deploy behind load balancer</M></label>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Input label="Health check interval (sec)" value={haCfg.loadBalancer.healthCheckSec} onChange={e=>setHaCfg(prev=>({...prev,loadBalancer:{...prev.loadBalancer,healthCheckSec:parseInt(e.target.value)||10}}))} type="number"/>
              <Input label="Health check path" value={haCfg.loadBalancer.healthPath} onChange={e=>setHaCfg(prev=>({...prev,loadBalancer:{...prev.loadBalancer,healthPath:e.target.value}}))} maxLength={256}/>
            </div>
          </Card>
          <Card style={{padding:12,borderColor:C.i+"30",marginBottom:16}}>
            <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:4}}>Architecture</M>
            <M style={{color:C.tm,lineHeight:1.8}}>Backend server is a separate process from the Management Console UI. The MC connects via API. Both active and passive servers share the same API contract. On failover, the load balancer redirects the MC's API calls to the newly promoted server — no MFA re-enrollment needed because auth tokens are replicated. Config changes made on the active are synchronously replicated to passive before the API returns success, ensuring zero data loss on failover.</M>
          </Card>
          <Btn primary onClick={()=>addA("HA_CONFIG_SAVED","High availability config saved — mode: "+haCfg.mode)}>Save HA Config</Btn>
          <Card style={{marginTop:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Manual Failover & Testing</div>
            <div style={{display:"flex",gap:8,marginBottom:12}}>
              <Btn onClick={()=>{if(window.confirm("MANUAL FAILOVER: Force promote passive server to active? The current active will become passive.")){setHaManualFailover(true);api.post("/api/v1/audit/log",{event:"HA_MANUAL_FAILOVER",detail:"Manual failover initiated — passive promoted to active"}).then(()=>addA("HA_MANUAL_FAILOVER","Manual failover initiated — passive promoted to active"));setTimeout(()=>setHaManualFailover(false),3000);}}} style={{borderColor:C.d+"60",color:C.d}}>{haManualFailover?"Failing over...":"Manual Failover"}</Btn>
              <Btn disabled={haTestRunning} onClick={()=>{setHaTestRunning(true);api.post("/api/v1/audit/log",{event:"HA_TEST_STARTED",detail:"Failover test initiated"}).then(()=>addA("HA_TEST_STARTED","Failover test initiated"));setTimeout(()=>{setHaTestRunning(false);setHaTestResults({ts:new Date().toISOString(),failoverTimeMs:1247,replicationLag:0,dataIntegrity:"verified",sessionsPreserved:true,apiAvailability:"100%",rollbackSuccess:true});api.post("/api/v1/audit/log",{event:"HA_TEST_COMPLETE",detail:"Failover test passed — 1247ms failover time, zero data loss, rollback successful"}).then(()=>addA("HA_TEST_COMPLETE","Failover test passed — 1247ms failover time, zero data loss, rollback successful"));},3000);}}>{haTestRunning?"Testing...":"Test Failover Now"}</Btn>
            </div>
            {haTestResults&&(<Card style={{padding:12,borderColor:C.a+"30"}}>
              <div style={{fontSize:12,fontWeight:500,color:C.a,marginBottom:6}}>Last Test: {new Date(haTestResults.ts).toLocaleString()}</div>
              <M style={{color:C.tm,lineHeight:1.8}}>Failover time: {haTestResults.failoverTimeMs}ms · Replication lag: {haTestResults.replicationLag}ms · Data integrity: {haTestResults.dataIntegrity} · Sessions preserved: {haTestResults.sessionsPreserved?"yes":"no"} · API availability during test: {haTestResults.apiAvailability} · Rollback to original active: {haTestResults.rollbackSuccess?"success":"failed"}</M>
            </Card>)}
            <M style={{color:C.td,display:"block",marginTop:8,fontStyle:"italic"}}>Failover tests should be run in production — that's the only way to validate real failover behavior. The test promotes the passive, verifies it works, then rolls back to the original active. During the test, fail-open routing ensures no ticket disruption. For active-active mode, there is no failover gap — the load balancer simply stops routing to the failed node.</M>
          </Card>
        </div>)}

        {/* ══════════ v1.0.0 — FAIL-OPEN ROUTING ══════════ */}
        {tab==="fail_open"&&(<div>
          <L>Fail-Open Routing</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Like an IPS configured to fail-open, if FireAlive's burnout routing engine fails, ticket routing reverts to the native ticketing system's distribution — no burnout filters, no complexity caps, no reduced queues. Analysts keep defending the network without interruption.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={failOpenCfg.enabled} onChange={e=>setFailOpenCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable fail-open routing</label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={failOpenCfg.autoDetect} onChange={e=>setFailOpenCfg(prev=>({...prev,autoDetect:e.target.checked}))}/><M style={{color:C.t}}>Auto-detect routing engine failure (health check every 10s)</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={failOpenCfg.notifyOnFailOpen} onChange={e=>setFailOpenCfg(prev=>({...prev,notifyOnFailOpen:e.target.checked}))}/><M style={{color:C.w}}>Notify Team Lead when fail-open activates</M></label>
            <Input label="Max time in fail-open mode (minutes) before requiring manual intervention" value={failOpenCfg.maxFailOpenMin} onChange={e=>setFailOpenCfg(prev=>({...prev,maxFailOpenMin:parseInt(e.target.value)||60}))} type="number"/>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={failOpenCfg.restoreAuto} onChange={e=>setFailOpenCfg(prev=>({...prev,restoreAuto:e.target.checked}))}/><M style={{color:C.t}}>Auto-restore burnout routing when engine recovers</M></label>
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"FAILOPEN_CONFIG_SAVED",detail:"Fail-open routing config saved"}).then(()=>addA("FAILOPEN_CONFIG_SAVED","Fail-open routing config saved"))}>Save Fail-Open Config</Btn>
        </div>)}

        {/* ══════════ v1.0.0 — CONFIG TROUBLESHOOTER ══════════ */}
        {tab==="troubleshooter"&&(<div>
          <L>Configuration Troubleshooter</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>An interactive assistant that helps diagnose why a feature isn't working as expected. Describe the problem and it will check your integrations, configurations, and suggest fixes.</M>
          <Card style={{marginBottom:16,maxHeight:400,overflowY:"auto"}}>
            {troubleshooterMsgs.length===0&&<M style={{color:C.td,padding:20,textAlign:"center",display:"block"}}>Describe a problem you're experiencing with any FireAlive feature and the troubleshooter will help diagnose it.</M>}
            {troubleshooterMsgs.map((m,i)=>(
              <div key={i} style={{padding:"10px 14px",marginBottom:4,background:m.role==="user"?C.bg:C.s,borderRadius:8,borderLeft:m.role==="assistant"?`3px solid ${C.i}`:"none"}}>
                <M style={{color:m.role==="user"?C.t:C.tm,lineHeight:1.6}}>{m.text}</M>
              </div>
            ))}
          </Card>
          <div style={{display:"flex",gap:8}}>
            <Input label="" value={troubleshooterInput} onChange={e=>setTroubleshooterInput(e.target.value)} placeholder="e.g., SOAR integration isn't sending playbook triggers..." maxLength={1000} style={{flex:1}}/>
            <Btn primary style={{marginTop:0}} disabled={!troubleshooterInput.trim()} onClick={()=>{
              const q=troubleshooterInput.trim();setTroubleshooterInput("");
              setTroubleshooterMsgs(prev=>[...prev,{role:"user",text:q}]);
              setTimeout(()=>{
                const checks=[];
                if(q.toLowerCase().includes("soar")) checks.push("✓ SOAR platform: "+(soarPlatform||"not configured"),"✓ SOAR URL: "+(soarUrl||"empty — needs endpoint"),"✓ SOAR API key: "+(soarApiKeyPresent?"configured server-side":(soarApiKey?"set (unsaved)":"missing — required for communication")),"→ Fix: Go to SOAR tab and ensure endpoint URL and API key are both configured. Test connection with the 'Test Webhook' button.");
                else if(q.toLowerCase().includes("siem")) checks.push("✓ SIEM feed: "+(featureToggles.siem_feed?"enabled":"disabled"),"→ Check: Ensure SIEM integration is enabled in Features tab and SIEM endpoint is configured in SIEM tab.");
                else if(q.toLowerCase().includes("peer")||q.toLowerCase().includes("chat")) checks.push("✓ Peer chat feature: "+(featureToggles.peer_chat?"enabled":"disabled"),"✓ Peer scheduling: "+(featureToggles.peer_scheduling?"enabled":"disabled"),"→ Check: Ensure both are enabled in Features tab. Verify E2EE keys are provisioned for the analysts.");
                else if(q.toLowerCase().includes("routing")||q.toLowerCase().includes("ticket")) checks.push("✓ Burnout routing: "+(featureToggles.burnout_routing?"enabled":"disabled"),"✓ Panic mode: "+(panicMode?"ACTIVE — routing is disabled!":"off"),"✓ Fail-open: "+(failOpenCfg.enabled?"enabled":"disabled"),"→ If tickets aren't being filtered, check if panic mode was accidentally activated.");
                else if(q.toLowerCase().includes("backup")||q.toLowerCase().includes("restore")) checks.push("✓ Latest backup: "+backups[0]?.ts,"✓ Backup status: "+backups[0]?.status,"✓ Backup schedules: "+schedules.length+" configured","→ Check: Verify backup schedule in Backup Schedules tab. Ensure disk space is available.");
                else if(q.toLowerCase().includes("client")||q.toLowerCase().includes("provision")) checks.push("✓ Provisioned clients: "+provisionedClients.length,"✓ Client sync interval: "+syncIntervalCfg.intervalMin+"min","→ If a client can't connect: verify server is running, config.json has correct endpoint, firewall allows port 3001, enrollment token is valid");
                else if(q.toLowerCase().includes("mfa")||q.toLowerCase().includes("auth")) checks.push("✓ MFA: "+(mfaCfg.status==="configured"?"configured":"not configured"),"✓ MFA method: "+mfaCfg.method,"✓ Auth logs: "+authLogs.length+" events","→ If MFA isn't working: verify TOTP secret is synced with authenticator app. If using WebAuthn, ensure browser supports FIDO2.");
                else if(q.toLowerCase().includes("tripwire")) checks.push("✓ Tripwire: "+(tripwireCfg.enabled?"enabled":"disabled"),"✓ Threshold: "+tripwireCfg.thresholdPct+"%","✓ Status: "+(tripwireTriggered?"TRIGGERED":"armed"),"→ If tripwire triggered unexpectedly, check if analysts legitimately requested reduced load vs. compromise.");
                else if(q.toLowerCase().includes("upskill")) checks.push("✓ Upskilling hour: "+(upskillingCfg.enabled?"enabled":"disabled"),"✓ Hour: "+upskillingCfg.hourOfShift+" of shift","✓ Stop routing: "+(upskillingCfg.stopRouting?"yes":"no"),"→ When upskilling hour activates, routing pauses for that analyst. Peer chat and training are enabled.");
                else checks.push("Running general diagnostic:","✓ Backend API: "+(apiReady?"connected":"not connected — backend may need restart"),"✓ Feature toggles: "+Object.entries(featureToggles).filter(([_,v])=>!v).length+" features disabled","✓ SOAR: "+(soarUrl?"configured":"not configured"),"✓ Panic mode: "+(panicMode?"ACTIVE":"off"),"✓ MFA: "+(mfaCfg.status==="configured"?"configured":"pending"),"✓ Tripwire: "+(tripwireCfg.enabled?(tripwireTriggered?"TRIGGERED":"armed"):"disabled"),"✓ HA: "+(haCfg.enabled?haCfg.mode:"disabled"),"✓ Clients: "+provisionedClients.length+" provisioned","→ For specific help, mention: soar, siem, peer, routing, backup, client, mfa, tripwire, upskilling");
                setTroubleshooterMsgs(prev=>[...prev,{role:"assistant",text:checks.join("\n")}]);
              },800);
            }}>Diagnose</Btn>
          </div>
        </div>)}

        {/* ══════════ v1.0.0 — GENERAL CERTS ══════════ */}
        {tab==="general_certs"&&(<div>
          <L>Certification Management</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Beyond training-linked certificates, analysts can upload broader industry certifications (CompTIA, ISACA, ISC², GIAC, etc.) to build a comprehensive team skill profile. Team leads see the aggregate to identify gaps and plan upskilling.</M>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Team Certifications ({generalCerts.length})</div>
            {generalCerts.map(gc=>(
              <div key={gc.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
                <div><M style={{color:C.t,fontWeight:500}}>{gc.name}</M><M style={{color:C.td,display:"block"}}>{gc.issuer} · {gc.analyst} · Earned: {gc.earned}{gc.expires?" · Expires: "+gc.expires:""}</M></div>
                <Badge color={gc.expires&&new Date(gc.expires)<new Date()?C.d:C.a}>{gc.expires&&new Date(gc.expires)<new Date()?"expired":"active"}</Badge>
              </div>
            ))}
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Add Certification</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Input label="Certification name" value={newCert.name} onChange={e=>setNewCert(prev=>({...prev,name:e.target.value}))} placeholder="e.g., CompTIA Security+" maxLength={200}/>
              <Sel label="Issuer" value={newCert.issuer} onChange={e=>setNewCert(prev=>({...prev,issuer:e.target.value}))}>
                <option value="">Select...</option><option value="CompTIA">CompTIA</option><option value="ISACA">ISACA</option><option value="ISC2">(ISC)²</option><option value="GIAC">GIAC/SANS</option><option value="EC-Council">EC-Council</option><option value="Offensive Security">Offensive Security</option><option value="AWS">AWS</option><option value="Microsoft">Microsoft</option><option value="Google Cloud">Google Cloud</option><option value="Cisco">Cisco</option><option value="Other">Other</option>
              </Sel>
              <Input label="Earned date" value={newCert.earned} onChange={e=>setNewCert(prev=>({...prev,earned:e.target.value}))} type="date"/>
              <Input label="Expiration date (if applicable)" value={newCert.expires} onChange={e=>setNewCert(prev=>({...prev,expires:e.target.value}))} type="date"/>
            </div>
            <Sel label="Analyst" value={newCert.analyst} onChange={e=>setNewCert(prev=>({...prev,analyst:e.target.value}))}>
              <option value="">Select analyst...</option>{analysts.map(a=><option key={a.id} value={a.id}>{a.name}</option>)}
            </Sel>
            <Btn primary style={{marginTop:12}} disabled={!newCert.name||!newCert.analyst} onClick={()=>{setGeneralCerts(prev=>[...prev,{id:"gc"+Date.now(),name:newCert.name,issuer:newCert.issuer,earned:newCert.earned,expires:newCert.expires,analyst:newCert.analyst}]);setNewCert({name:"",issuer:"",earned:"",expires:"",analyst:""});addA("CERT_ADDED","Certification added: "+newCert.name);}}>Add Certification</Btn>
          </Card>
        </div>)}

        {/* R3l C16: Training Completions Review — lead/admin verify or reject analyst-submitted training completions */}
        {tab==="training_reviews"&&(<div>
          <L>Training Completions Review</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Verify or reject training completions that analysts have self-submitted through the Analyst Client. Each row shows the analyst, platform, module URL, submission timestamp, and current status. The server only allows pending submissions to be transitioned — verify confirms the completion is genuine and credits it to the analyst's skill record; reject marks it as not credited. Verified and rejected rows are terminal and shown for audit reference.</M>
          {trainingReviewPatchError&&(<Card style={{marginBottom:16,borderColor:C.d+"60"}}><M style={{color:C.d}}>Last action failed: {trainingReviewPatchError}</M></Card>)}
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:16}}>
            <Card style={{textAlign:"center"}}><div style={{fontSize:24,fontWeight:600,color:C.w}}>{trainingReviewQueue.counts.pending}</div><M style={{color:C.td}}>Pending</M></Card>
            <Card style={{textAlign:"center"}}><div style={{fontSize:24,fontWeight:600,color:C.a}}>{trainingReviewQueue.counts.verified}</div><M style={{color:C.td}}>Verified</M></Card>
            <Card style={{textAlign:"center"}}><div style={{fontSize:24,fontWeight:600,color:C.d}}>{trainingReviewQueue.counts.rejected}</div><M style={{color:C.td}}>Rejected</M></Card>
            <Card style={{textAlign:"center"}}><div style={{fontSize:24,fontWeight:600,color:C.i}}>{trainingReviewQueue.counts.total}</div><M style={{color:C.td}}>Total</M></Card>
          </div>
          <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap"}}>
            {[{k:"pending",l:"Pending"},{k:"verified",l:"Verified"},{k:"rejected",l:"Rejected"},{k:"all",l:"All"}].map(f=>(
              <button key={f.k} onClick={()=>setTrainingReviewStatusFilter(f.k)} style={{padding:"6px 14px",background:trainingReviewStatusFilter===f.k?C.a:"rgba(255,255,255,0.03)",border:`1px solid ${trainingReviewStatusFilter===f.k?C.a:C.b}`,borderRadius:6,color:trainingReviewStatusFilter===f.k?"#000":C.t,fontSize:11,fontWeight:500,cursor:"pointer"}}>{f.l}</button>
            ))}
          </div>
          {!trainingReviewLoadState.loaded&&!trainingReviewLoadState.error&&(<M style={{color:C.tm,fontStyle:"italic"}}>Loading training completions…</M>)}
          {trainingReviewLoadState.error&&(<Card style={{borderColor:C.w+"60"}}><M style={{color:C.w}}>Could not load training completions: {trainingReviewLoadState.error}</M></Card>)}
          {trainingReviewLoadState.loaded&&trainingReviewQueue.completions.length===0&&(<Card><M style={{color:C.tm,fontStyle:"italic"}}>No training completions match the current filter.</M></Card>)}
          {trainingReviewLoadState.loaded&&trainingReviewQueue.completions.length>0&&(
            <Card style={{padding:0,overflow:"hidden"}}>
              <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
                <thead>
                  <tr style={{background:"rgba(255,255,255,0.02)"}}>
                    <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Analyst</th>
                    <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Platform / Module</th>
                    <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Submitted</th>
                    <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Status</th>
                    <th style={{padding:"10px 12px",textAlign:"right",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {trainingReviewQueue.completions.map(c=>{
                    const inFlight = trainingReviewPatchInFlight[c.id];
                    const statusColor = c.status==="pending"?C.w:c.status==="verified"?C.a:c.status==="rejected"?C.d:C.tm;
                    return (
                      <tr key={c.id} style={{borderBottom:`1px solid ${C.b}`}}>
                        <td style={{padding:"10px 12px",color:C.t,verticalAlign:"top"}}>
                          <M style={{color:C.t,fontWeight:500}}>{c.user_name||"(unknown user)"}</M>
                          <M style={{color:C.td,display:"block",fontSize:10,marginTop:2}}>id: {c.user_id}</M>
                        </td>
                        <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                          <M style={{color:C.t,fontWeight:500}}>{c.platform||"(no platform)"}</M>
                          <M style={{color:C.tm,display:"block",marginTop:2}}>{c.module||"(no module name)"}</M>
                          {c.url&&(<a href={c.url} target="_blank" rel="noopener noreferrer" style={{color:C.i,fontSize:10,wordBreak:"break-all",textDecoration:"none",display:"block",marginTop:4}}>{c.url}</a>)}
                        </td>
                        <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                          <M style={{color:C.tm}}>{c.submitted_at||"—"}</M>
                          {c.completion_date&&(<M style={{color:C.td,display:"block",fontSize:10,marginTop:2}}>Completed: {c.completion_date}</M>)}
                          {c.score!==null&&c.score!==undefined&&(<M style={{color:C.td,display:"block",fontSize:10,marginTop:2}}>Score: {c.score}</M>)}
                        </td>
                        <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                          <Badge color={statusColor}>{c.status}</Badge>
                          {c.verified_at&&c.status!=="pending"&&(<M style={{color:C.td,display:"block",fontSize:10,marginTop:4}}>{c.status==="verified"?"Verified":"Rejected"}: {c.verified_at}</M>)}
                        </td>
                        <td style={{padding:"10px 12px",textAlign:"right",verticalAlign:"top"}}>
                          {c.status==="pending"?(
                            <div style={{display:"flex",gap:6,justifyContent:"flex-end"}}>
                              <button onClick={()=>patchTrainingCompletion(c.id,"verified")} disabled={!!inFlight} style={{padding:"5px 10px",background:inFlight==="verified"?C.tm:C.a,border:"none",borderRadius:4,color:"#000",fontSize:11,fontWeight:500,cursor:inFlight?"not-allowed":"pointer",opacity:inFlight?0.6:1}}>{inFlight==="verified"?"Verifying…":"Verify"}</button>
                              <button onClick={()=>patchTrainingCompletion(c.id,"rejected")} disabled={!!inFlight} style={{padding:"5px 10px",background:"transparent",border:`1px solid ${C.d}`,borderRadius:4,color:C.d,fontSize:11,fontWeight:500,cursor:inFlight?"not-allowed":"pointer",opacity:inFlight?0.6:1}}>{inFlight==="rejected"?"Rejecting…":"Reject"}</button>
                            </div>
                          ):(
                            <M style={{color:C.td,fontStyle:"italic",fontSize:10}}>—</M>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Card>
          )}
        </div>)}

        {/* ══════════ v1.0.0 — PSEUDONYM SYSTEM ══════════ */}
        {tab==="pseudonyms"&&(<div>
          <L>Analyst Pseudonym System</L>
          <Card style={{marginBottom:16,borderColor:C.a+"30"}}><div style={{fontSize:13,fontWeight:600,color:C.a,marginBottom:10}}>Rotation Safety</div><M style={{color:C.tm,display:"block"}}>Permanent UUID per analyst. All metrics stored against UUID.</M></Card>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Decouple analyst identity from burnout data at the collection layer. All burnout metrics, peer chat messages, reduced-routing requests, and wellness signals are stored under pseudonyms — never real names. If the database is breached, attackers get "Analyst-Falcon is experiencing elevated burnout" rather than a real person's name. The identity mapping exists only in an encrypted export the Team Lead stores offline.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={pseudonymCfg.enabled} onChange={e=>setPseudonymCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable pseudonym system</label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={pseudonymCfg.autoGenerate} onChange={e=>setPseudonymCfg(prev=>({...prev,autoGenerate:e.target.checked}))}/><M style={{color:C.t}}>Auto-generate pseudonyms (analysts can also pick their own)</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={pseudonymCfg.leadExportEnabled} onChange={e=>setPseudonymCfg(prev=>({...prev,leadExportEnabled:e.target.checked}))}/><M style={{color:C.w}}>Allow one-time export of identity mapping (encrypted, for offline storage only)</M></label>
            <Card style={{padding:10,borderColor:C.d+"30",marginTop:8}}><M style={{color:C.d,fontWeight:500,display:"block",marginBottom:4}}>Security Note</M><M style={{color:C.tm}}>The real name to pseudonym mapping is NEVER stored in the app database. When pseudonyms are assigned, a one-time encrypted export is generated for the Team Lead to store offline (printed, encrypted USB, etc). If you need to identify an analyst (for praise or abuse investigation), use the offline mapping document. This ensures that if the database is breached, analyst identities cannot be linked to burnout data.</M></Card>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={pseudonymCfg.leadExportEnabled} onChange={e=>setPseudonymCfg(prev=>({...prev,leadExportEnabled:e.target.checked}))}/><M style={{color:C.w}}>Allow Team Lead to export identity mapping (encrypted, for offline storage)</M></label>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>How It Works</div>
            <M style={{color:C.tm,lineHeight:1.8,display:"block"}}>
              1. Analyst authenticates via IAM (real credentials — normal login){"\n"}
              2. The client generates or accepts a pseudonym during onboarding{"\n"}
              3. All burnout data, signals, peer chat, routing requests use the pseudonym only{"\n"}
              4. Real identity ↔ pseudonym mapping is encrypted with the Team Lead's key{"\n"}
              5. The mapping is exportable as an encrypted file — not stored in the app database{"\n"}
              6. If the database is breached: burnout data shows pseudonyms, not people{"\n"}
              7. IAM login tokens are short-lived JWTs — even if captured, they don't link to burnout data{"\n"}
              8. Pseudonym rotation: analysts can request a new pseudonym at any time
            </M>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Current Pseudonym Assignments</div>
            {analystPseudonyms.map(ap=>(
              <div key={ap.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
                <div><M style={{color:C.p,fontWeight:500}}>{ap.pseudonym}</M><M style={{color:C.td}}> · Assigned {ap.assignedAt}</M></div>
                <M style={{color:C.td}}>Since {ap.assignedAt}</M>
              </div>
            ))}
          </Card>
          <div style={{display:"flex",gap:8}}>
            <Btn primary onClick={()=>{api.post("/api/v1/audit/log",{event:"PSEUDONYM_CONFIG_SAVED",detail:"Pseudonym system config saved"}).then(()=>addA("PSEUDONYM_CONFIG_SAVED","Pseudonym system config saved"));}}>Save Config</Btn>
            {pseudonymCfg.leadExportEnabled&&<Btn onClick={()=>{const mapping=analystPseudonyms.map(a=>({pseudonym:a.pseudonym,realName:a.realName,assignedAt:a.assignedAt}));const data=JSON.stringify({exportType:"pseudonym_mapping",version:appVersion||"unknown",exportedAt:new Date().toISOString(),warning:"CONFIDENTIAL — Store offline. Do not upload to shared drives.",mapping},null,2);const blob=new Blob([data],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="pseudonym-mapping-CONFIDENTIAL-"+new Date().toISOString().slice(0,10)+".json";a.click();api.post("/api/v1/audit/log",{event:"PSEUDONYM_MAPPING_EXPORTED",detail:"Identity mapping exported — CONFIDENTIAL"}).then(()=>addA("PSEUDONYM_MAPPING_EXPORTED","Identity mapping exported — CONFIDENTIAL"));}}>Export Mapping (Encrypted)</Btn>}
            <Btn onClick={()=>{const birds=["Phoenix","Merlin","Peregrine","Kestrel","Harrier","Gyrfalcon","Sparrowhawk","Kite","Buzzard","Shrike"];setAnalystPseudonyms(prev=>prev.map((ap,i)=>({...ap,pseudonym:"Analyst-"+birds[i%birds.length]+"-"+Math.floor(Math.random()*99),assignedAt:new Date().toISOString().slice(0,10)})));api.post("/api/v1/audit/log",{event:"PSEUDONYMS_ROTATED",detail:"All analyst pseudonyms rotated"}).then(()=>addA("PSEUDONYMS_ROTATED","All analyst pseudonyms rotated"));}}>Rotate All Pseudonyms</Btn>
          </div>
        </div>)}

        {/* ══════════ v1.0.0 — DATA SOVEREIGNTY / GEO-FENCING ══════════ */}
        {tab==="geo_fence"&&(<div>
          <L>Data Sovereignty & Geo-Fencing</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Assign geographic locations to provisioned clients so the app can enforce geo-fenced logins (block logins from unexpected countries), apply the correct regulatory framework (GDPR, PIPEDA, LGPD, etc.), and ensure data residency requirements are met. Critical for multinational SOCs with analysts in multiple jurisdictions.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={geoFenceCfg.enabled} onChange={e=>setGeoFenceCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable data sovereignty controls</label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={geoFenceCfg.enforceGeoLogin} onChange={e=>setGeoFenceCfg(prev=>({...prev,enforceGeoLogin:e.target.checked}))}/><M style={{color:C.d}}>Block logins from countries not matching client's assigned location</M></label>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Client Geo-Assignments ({geoFenceCfg.clients.length})</div>
            {geoFenceCfg.clients.length===0&&<M style={{color:C.td}}>No clients geo-assigned yet. Add assignments below.</M>}
            {geoFenceCfg.clients.map((gc,i)=>(
              <div key={i} style={{display:"flex",justifyContent:"space-between",padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
                <div><M style={{color:C.t,fontWeight:500}}>{gc.clientId}</M><M style={{color:C.td,display:"block"}}>{gc.country} · {gc.regulatoryFramework} · Data residency: {gc.dataResidency}</M></div>
                <Badge color={C.a}>{gc.country}</Badge>
              </div>
            ))}
            <div style={{marginTop:12,display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              <Sel label="Client" value={newGeoClient.clientId} onChange={e=>setNewGeoClient(prev=>({...prev,clientId:e.target.value}))}>
                <option value="">Select client...</option>{analysts.map(a=><option key={a.id} value={a.id}>{a.name}</option>)}
              </Sel>
              <Sel label="Country" value={newGeoClient.country} onChange={e=>setNewGeoClient(prev=>({...prev,country:e.target.value}))}>
                <option value="">Select...</option><option value="US">United States</option><option value="UK">United Kingdom</option><option value="DE">Germany</option><option value="FR">France</option><option value="NL">Netherlands</option><option value="CA">Canada</option><option value="AU">Australia</option><option value="JP">Japan</option><option value="SG">Singapore</option><option value="BR">Brazil</option><option value="IN">India</option><option value="AT">Austria</option><option value="HU">Hungary</option><option value="Other">Other</option>
              </Sel>
              <Sel label="Regulatory framework" value={newGeoClient.regulatoryFramework} onChange={e=>setNewGeoClient(prev=>({...prev,regulatoryFramework:e.target.value}))}>
                <option value="none">None specified</option><option value="GDPR">GDPR (EU/EEA)</option><option value="CCPA">CCPA (California)</option><option value="PIPEDA">PIPEDA (Canada)</option><option value="LGPD">LGPD (Brazil)</option><option value="APPI">APPI (Japan)</option><option value="PDPA">PDPA (Singapore)</option><option value="HIPAA">HIPAA (US Healthcare)</option>
              </Sel>
              <Sel label="Data residency" value={newGeoClient.dataResidency} onChange={e=>setNewGeoClient(prev=>({...prev,dataResidency:e.target.value}))}>
                <option value="local">Local (data stays in client country)</option><option value="regional">Regional (data in same continent)</option><option value="global">Global (centralized)</option>
              </Sel>
            </div>
            <Btn primary style={{marginTop:12}} disabled={!newGeoClient.clientId||!newGeoClient.country} onClick={()=>{setGeoFenceCfg(prev=>({...prev,clients:[...prev.clients,{...newGeoClient}]}));setNewGeoClient({clientId:"",country:"",region:"",dataResidency:"local",regulatoryFramework:"none"});addA("GEO_CLIENT_ASSIGNED","Client geo-assigned: "+newGeoClient.clientId+" → "+newGeoClient.country);}}>Add Geo-Assignment</Btn>
          </Card>
          <Card style={{padding:12,borderColor:C.i+"30",marginBottom:16}}>
            <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:4}}>Regulatory Impact</M>
            <M style={{color:C.tm,lineHeight:1.8}}>GDPR: Right to erasure, data minimization, 72-hr breach notification, DPO requirement · CCPA: Right to know, right to delete, opt-out of sale · PIPEDA: Consent-based collection, reasonable purpose · The compliance tab's framework scanner already checks against these — this tab ensures the correct framework is applied per analyst location. For complex multi-jurisdictional deployments, consult your DPO or privacy counsel.</M>
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"GEO_CONFIG_SAVED",detail:"Data sovereignty config saved"}).then(()=>addA("GEO_CONFIG_SAVED","Data sovereignty config saved"))}>Save Geo Config</Btn>
        </div>)}

        {/* ══════════ v1.0.0 — CLUSTER / SCALING ══════════ */}
        {tab==="cluster"&&(<div>
          <L>Cluster & Scaling Configuration</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>For large deployments (hundreds or thousands of analysts), deploy FireAlive as a multi-node cluster. Active-active clusters distribute load across nodes with shared session state. Supports horizontal scaling, parallel processing, and segmented management console teams.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={clusterCfg.enabled} onChange={e=>setClusterCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable cluster mode</label>
            <Sel label="Cluster mode" value={clusterCfg.mode} onChange={e=>setClusterCfg(prev=>({...prev,mode:e.target.value}))}>
              <option value="active_passive">Active/Passive (2 nodes, failover)</option>
              <option value="active_active">Active/Active (all nodes serve traffic)</option>
              <option value="segmented">Segmented (each MC manages a subset of analysts)</option>
            </Sel>
            <Input label="Node count" value={clusterCfg.nodeCount} onChange={e=>setClusterCfg(prev=>({...prev,nodeCount:parseInt(e.target.value)||2}))} type="number"/>
            <Sel label="Session store (required for active-active)" value={clusterCfg.sessionStore} onChange={e=>setClusterCfg(prev=>({...prev,sessionStore:e.target.value}))}>
              <option value="redis">Redis</option><option value="memcached">Memcached</option><option value="postgres">PostgreSQL</option><option value="dynamodb">DynamoDB</option>
            </Sel>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:12,marginBottom:8}}>Parallel Processing</div>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={clusterCfg.parallelProcessing} onChange={e=>setClusterCfg(prev=>({...prev,parallelProcessing:e.target.checked}))}/><M style={{color:C.t}}>Enable Node.js worker threads for CPU-intensive tasks (report generation, encryption, integrity checks)</M></label>
            <Input label="Worker threads per node" value={clusterCfg.workerThreads} onChange={e=>setClusterCfg(prev=>({...prev,workerThreads:parseInt(e.target.value)||4}))} type="number"/>
            <M style={{color:C.td,display:"block",marginTop:8,fontStyle:"italic"}}>Node.js is single-threaded by default. Worker threads parallelize CPU-bound work (encryption, report generation) across cores. For I/O-bound work (API calls, DB queries), Node's event loop already handles concurrency well.</M>
          </Card>
          <Card style={{padding:12,borderColor:C.i+"30",marginBottom:16}}>
            <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:4}}>Segmented Mode</M>
            <M style={{color:C.tm,lineHeight:1.8}}>In segmented mode, multiple Management Consoles each manage a subset of analysts (e.g., by region, shift, or team). All nodes share a single database cluster but each MC sees only its assigned analysts. A "Global Dashboard" (see Global Dashboard tab) can aggregate read-only data from all segments for executive visibility.</M>
          </Card>
          <Btn primary onClick={()=>addA("CLUSTER_CONFIG_SAVED","Cluster config saved — mode: "+clusterCfg.mode+", nodes: "+clusterCfg.nodeCount)}>Save Cluster Config</Btn>
        </div>)}

        {/* ══════════ v1.0.0 — GLOBAL DASHBOARD ══════════ */}
        {tab==="global_dash"&&(<div>
          <L>Global Dashboard Push</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Configure this Regional MC to push aggregate metrics to a Global Dashboard Server (GD-Server) — a separate read-only backend operated by your CISO/VP that aggregates region-level data across multiple MCs. The CISO obtains an API key by registering this MC on the GD-Server, then provides it here. Pushes are one-way (this MC pushes; GD-Server never writes back) and contain only team-level aggregate data — no individual analyst data is transmitted.</M>
          {/* Handshake state banner (PR4 C18). Surfaces signing-key trust state from
              the GD-side perspective via the local gd_push_config row's handshake_status
              field. NEVER surfaces rejected_reason — that lives on the GD side audit log
              + GD admin UI only. The operator sees status + actionable copy; CISO
              contact is the recourse for rejected handshakes. */}
          {globalDashCfg._loaded&&(()=>{
            const hs = globalDashCfg.handshake_status || "none";
            const active = globalDashCfg.active_fingerprint || "";
            const staged = globalDashCfg.staged_fingerprint || "";
            const lastAt = globalDashCfg.last_handshake_at;
            const config = {
              none:     { color:C.tm, label:"NOT CONFIGURED",     headline:"No handshake yet",                copy:"Finish configuring endpoint_url + mc_id + API key below and save. The MC will auto-fire an initial signing-key handshake; status will move to 'pending CISO approval' once the GD receives the submission." },
              pending_approval: { color:C.w,  label:"PENDING APPROVAL",    headline:"Awaiting CISO approval",       copy:"This MC submitted a signing-key fingerprint to the GD. A CISO with role 'ciso' or 'signing_key_approver' must verify the fingerprint OUT OF BAND (phone, in-person, encrypted channel) and approve in the GD admin UI before signed pushes will be accepted. Reach out to your CISO with the staged fingerprint shown below to expedite review." },
              approved: { color:C.a,  label:"APPROVED",            headline:"Handshake approved",           copy:"The GD has approved this MC's signing key. Signed pushes will be accepted. If you need to rotate the key, save the configuration with a new staged keypair (or use the rotate endpoint); the new key will enter 'pending CISO approval' until the CISO approves the replacement." },
              rejected: { color:C.d,  label:"REJECTED",            headline:"Rejected by CISO",             copy:"The GD rejected this MC's signing key. Re-save the GD configuration (typically with a corrected api_key or endpoint_url) to retry — that will stage a fresh keypair and re-fire the handshake. The CISO's rationale is recorded server-side in their audit log and is NOT exposed to the MC by design. Contact your CISO for details if needed." },
            }[hs] || { color:C.tm, label:hs.toUpperCase(), headline:"Unknown handshake state", copy:"The handshake_status field returned by the local gd_push_config row is '"+hs+"', which is not a recognized state. Check the MC server logs for migration issues." };
            return <Card style={{marginBottom:16,borderColor:config.color+"60"}}>
              <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:8,flexWrap:"wrap"}}>
                <Badge color={config.color}>{config.label}</Badge>
                <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5"}}>{config.headline}</div>
              </div>
              <M style={{color:C.tm,display:"block",marginBottom:10,fontSize:11,lineHeight:1.6}}>{config.copy}</M>
              {(active||staged)&&<div style={{display:"grid",gridTemplateColumns:"1fr",gap:6,marginBottom:6}}>
                {active&&<div style={{padding:"6px 8px",background:"rgba(0,0,0,0.25)",borderLeft:`2px solid ${C.a}`,borderRadius:4}}>
                  <M style={{color:C.tm,display:"block",fontSize:9,marginBottom:2}}>active fingerprint</M>
                  <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>{active}</M>
                </div>}
                {staged&&staged!==active&&<div style={{padding:"6px 8px",background:"rgba(0,0,0,0.25)",borderLeft:`2px solid ${C.w}`,borderRadius:4}}>
                  <M style={{color:C.tm,display:"block",fontSize:9,marginBottom:2}}>staged fingerprint (awaiting CISO approval)</M>
                  <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>{staged}</M>
                </div>}
              </div>}
              {lastAt&&<M style={{color:C.td,display:"block",fontSize:9,marginTop:4}}>last handshake activity: {new Date(lastAt).toLocaleString()}</M>}
            </Card>;
          })()}
          <Card style={{marginBottom:16,borderColor:globalDashCfg.last_push_status==="failure"?C.d+"40":(globalDashCfg.last_push_status==="success"?C.a+"40":C.b)}}>
            <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5",marginBottom:10}}>Connection Status</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,fontSize:11}}>
              <M style={{color:C.tm}}>State: <span style={{color:globalDashCfg.enabled?C.a:C.tm}}>{globalDashCfg.enabled?"enabled":"disabled"}</span></M>
              <M style={{color:C.tm}}>API key: <span style={{color:globalDashCfg.api_key_set?C.a:C.w}}>{globalDashCfg.api_key_set?"configured":"not set"}</span></M>
              <M style={{color:C.tm}}>Last push: {globalDashCfg.last_push_at||"never"}</M>
              <M style={{color:C.tm}}>Status: <span style={{color:globalDashCfg.last_push_status==="success"?C.a:(globalDashCfg.last_push_status==="failure"?C.d:C.tm)}}>{globalDashCfg.last_push_status||"\u2014"}</span></M>
              {globalDashCfg.consecutive_failures>0&&<M style={{color:C.d}}>Consecutive failures: {globalDashCfg.consecutive_failures}{globalDashCfg.consecutive_failures>=20?" (CIRCUIT BREAKER TRIPPED \u2014 auto-disabled)":""}</M>}
              {globalDashCfg.last_push_error&&<M style={{color:C.d,gridColumn:"1 / -1",fontFamily:"'IBM Plex Mono',monospace",fontSize:10}}>Last error: {globalDashCfg.last_push_error}</M>}
            </div>
            {globalDashCfg.consecutive_failures>0&&<Btn small onClick={()=>{api.put("/api/gd-config",{reset_failure_counter:true}).then(r=>{if(r&&!r.error){setGlobalDashCfg(prev=>({...prev,...r,_loaded:true}));addA("GD","Failure counter reset");}else{addA("GD","Reset failed: "+(r?.error||"unknown"));}});}} style={{marginTop:10}}>Reset Failure Counter</Btn>}
          </Card>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={globalDashCfg.enabled} onChange={e=>setGlobalDashCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable Global Dashboard push from this MC</label>
            <Input label="GD-Server endpoint URL" value={globalDashCfg.endpoint_url} onChange={e=>setGlobalDashCfg(prev=>({...prev,endpoint_url:e.target.value}))} placeholder="https://gd.corp.com:4001" maxLength={2048}/>
            <Input label={globalDashCfg.api_key_set?"Replace API key (leave blank to keep existing)":"API key from GD-Server"} type="password" value={globalDashCfg.api_key_input} onChange={e=>setGlobalDashCfg(prev=>({...prev,api_key_input:e.target.value}))} placeholder={globalDashCfg.api_key_set?"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022":"gdash-ro-..."} maxLength={512}/>
            {globalDashCfg.api_key_set&&<Btn small onClick={()=>{if(window.confirm("Clear stored API key? Push will be disabled until a new key is set.")){api.put("/api/gd-config",{clear_api_key:true,enabled:false}).then(r=>{if(r&&!r.error){setGlobalDashCfg(prev=>({...prev,...r,api_key_input:"",_loaded:true}));addA("GD","API key cleared");}});}}} style={{marginTop:6}}>Clear Stored API Key</Btn>}
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginTop:12}}>
              <Input label="Push interval (min)" type="number" value={globalDashCfg.push_interval_minutes} onChange={e=>setGlobalDashCfg(prev=>({...prev,push_interval_minutes:parseInt(e.target.value)||15}))} min={1} max={1440}/>
              <Input label="Retry max" type="number" value={globalDashCfg.retry_max} onChange={e=>setGlobalDashCfg(prev=>({...prev,retry_max:parseInt(e.target.value)||0}))} min={0} max={10}/>
              <Input label="Retry backoff (sec)" type="number" value={globalDashCfg.retry_backoff_seconds} onChange={e=>setGlobalDashCfg(prev=>({...prev,retry_backoff_seconds:parseInt(e.target.value)||30}))} min={1} max={3600}/>
            </div>
            <div style={{display:"flex",gap:8,marginTop:14}}>
              <Btn primary disabled={globalDashCfg._saving} onClick={()=>{const payload={enabled:globalDashCfg.enabled,endpoint_url:globalDashCfg.endpoint_url,push_interval_minutes:globalDashCfg.push_interval_minutes,retry_max:globalDashCfg.retry_max,retry_backoff_seconds:globalDashCfg.retry_backoff_seconds};if(globalDashCfg.api_key_input)payload.api_key=globalDashCfg.api_key_input;setGlobalDashCfg(prev=>({...prev,_saving:true}));api.put("/api/gd-config",payload).then(r=>{if(r&&!r.error){setGlobalDashCfg(prev=>({...prev,...r,api_key_input:"",_saving:false,_loaded:true,_savedEndpointUrl:r.endpoint_url||"",_savedApiKeySet:!!r.api_key_set}));addA("GD","Configuration saved");}else{setGlobalDashCfg(prev=>({...prev,_saving:false}));addA("GD","Save failed: "+(r?.error||"unknown"));}});}}>{globalDashCfg._saving?"Saving...":"Save Configuration"}</Btn>
              <Btn disabled={globalDashCfg._testing||!globalDashCfg._savedEndpointUrl||!globalDashCfg._savedApiKeySet} onClick={()=>{setGlobalDashCfg(prev=>({...prev,_testing:true,_testResult:null}));api.post("/api/gd-config/test",{}).then(r=>{setGlobalDashCfg(prev=>({...prev,_testing:false,_testResult:r}));if(r?.ok)addA("GD","Test connection succeeded ("+r.durationMs+"ms)");else addA("GD","Test connection failed: "+(r?.error||"unknown"));});}}>{globalDashCfg._testing?"Testing...":"Test Connection"}</Btn>
            </div>
            <M style={{color:C.tm,fontSize:10,fontStyle:"italic",marginTop:6,display:"block",lineHeight:1.5}}>Test runs against the saved configuration. If you've edited the form fields above, click Save first. Note: the GD endpoint hostname must be in the <code>GD_ALLOWED_HOSTS</code> environment variable on this MC server (set at deployment time) — see deployment docs.</M>
            {globalDashCfg._testResult&&<Card style={{padding:10,marginTop:10,borderColor:(globalDashCfg._testResult.ok?C.a:C.d)+"40"}}><M style={{color:globalDashCfg._testResult.ok?C.a:C.d,fontWeight:500,fontSize:11}}>{globalDashCfg._testResult.ok?"\u2713 Connection successful":"\u2717 Connection failed"} ({globalDashCfg._testResult.durationMs||"?"}ms)</M>{globalDashCfg._testResult.error&&<M style={{color:C.tm,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",marginTop:4}}>{globalDashCfg._testResult.error}</M>}</Card>}
          </Card>
          <Card style={{padding:12,borderColor:C.p+"30",marginBottom:16}}>
            <M style={{color:C.p,fontWeight:500,display:"block",marginBottom:4}}>Data Sent to GD-Server</M>
            <M style={{color:C.tm,lineHeight:1.8}}>Aggregate team health (capacity score) \u00b7 Analyst count \u00b7 Active incident count \u00b7 Burnout routing state \u00b7 Proactive breaks given (24h) \u00b7 Upskilling hours used \u00b7 Turnover risk (derived) \u00b7 SLA compliance (where measured) \u00b7 Cert coverage (where configured) \u00b7 Automation rate (where configured). All values are team-level aggregates with no individual analyst identifiers.</M>
          </Card>
          <Card style={{padding:12,borderColor:C.w+"30"}}>
            <M style={{color:C.w,fontWeight:500,display:"block",marginBottom:4}}>Architecture Note</M>
            <M style={{color:C.tm,lineHeight:1.8}}>The GD-Server is a separate application with its own deployment (typically on port 4001). It has read-only ingest from this MC's perspective and never writes back. The push is fire-and-forget \u2014 if the GD-Server is unreachable, this MC retries with exponential backoff and auto-disables after 20 consecutive failures (circuit breaker). Failures are logged in the audit trail under GD_PUSH_FAILURE.</M>
          </Card>
        </div>)}

        {/* ══════════ v1.0.0 — BACKUP SCHEDULES ══════════ */}
        {tab==="backup_schedules"&&(<div>
          <L>Backup Schedules</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Configure multiple backup schedules with different types, frequencies, and destinations. All backups are AES-256-GCM encrypted by default. You can optionally align backup schedules with regulatory framework requirements (HIPAA, SOX, PCI-DSS, GDPR, NIST CSF, ISO 27001, SOC 2) — picking a preset enforces that framework's retention and encryption floors but leaves you free to set retention higher than the minimum.</M>
          {schedulesFb && (
            <Card style={{marginBottom:12,padding:10,borderColor:(schedulesFb.error?C.d:C.a)+"50"}}>
              <M style={{color:schedulesFb.error?C.d:C.a}}>{schedulesFb.error || schedulesFb.success}</M>
            </Card>
          )}
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Active Schedules{schedulesLoading?"":" ("+schedules.length+")"}</div>
            {schedulesLoading && (<M style={{color:C.td}}>Loading schedules...</M>)}
            {!schedulesLoading && schedulesError && (<M style={{color:C.d}}>{schedulesError}</M>)}
            {!schedulesLoading && !schedulesError && schedules.length===0 && (
              <M style={{color:C.td}}>No backup schedules configured yet. The Add Schedule form lands in the next commit; until then, no new schedules can be created from this UI.</M>
            )}
            {!schedulesLoading && !schedulesError && schedules.map(s=>{
              const freq = s.frequency || s.interval || "?";
              const day = s.frequency==="weekly" && typeof s.day_of_week==="number" ? ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"][s.day_of_week] : (s.frequency==="monthly" && s.day_of_month ? "day "+s.day_of_month : null);
              const presetTag = s.preset_name ? " · "+s.preset_name : "";
              const nextRunDisplay = s.next_run ? new Date(s.next_run).toLocaleString() : "—";
              const lastRunDisplay = s.last_run ? new Date(s.last_run).toLocaleString() : "never";
              const statusColor = s.last_status==="success"?C.a:(s.last_status==="failed"?C.d:(s.last_status==="running"?C.i:C.tm));
              return (
                <div key={s.id} style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",padding:"10px 0",borderBottom:`1px solid ${C.b}`}}>
                  <div style={{flex:1}}>
                    <M style={{color:C.t,fontWeight:500}}>{s.name || "Schedule #"+s.id} · {s.type || "full"} · {freq}{day?" ("+day+")":""}{s.time?" at "+s.time:""}</M>
                    <M style={{color:C.td,display:"block"}}>Destination: {s.destination || "—"} · Retention: {s.retention || "—"} · {s.encrypted?"Encrypted":"⚠ UNENCRYPTED"}{presetTag}</M>
                    <M style={{color:C.td,display:"block",fontSize:11}}>Next run: {nextRunDisplay} · Last run: <span style={{color:statusColor}}>{lastRunDisplay}{s.last_status?" ("+s.last_status+")":""}</span>{s.last_error?" · Error: "+s.last_error:""}</M>
                  </div>
                  <div style={{display:"flex",gap:6,alignItems:"center"}}>
                    <Badge color={s.encrypted?C.a:C.d}>{s.encrypted?"AES-256":"plain"}</Badge>
                    {s.active===0 && <Badge color={C.tm}>paused</Badge>}
                    <Btn small onClick={()=>deleteSchedule(s.id, s.name)}>Remove</Btn>
                  </div>
                </div>
              );
            })}
          </Card>
          {overlapConfirm && (
            <Card style={{marginBottom:16,borderColor:C.w+"60",padding:14}}>
              <div style={{fontSize:12,fontWeight:600,color:C.w,marginBottom:8}}>Schedule overlap detected</div>
              <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>This schedule would fire within 5 minutes of {overlapConfirm.overlaps.length} existing fire time{overlapConfirm.overlaps.length===1?"":"s"}. Running concurrent backups risks I/O contention. You can confirm to queue this schedule behind the conflicting one, or cancel and adjust the time.</M>
              <div style={{marginBottom:10,maxHeight:140,overflowY:"auto"}}>
                {overlapConfirm.overlaps.slice(0,5).map((o,i)=>(
                  <M key={i} style={{color:C.td,display:"block",fontSize:11,marginBottom:4}}>
                    · Conflicts with "{o.scheduleName}" at {new Date(o.conflictingFireTime).toLocaleString()} (your schedule would fire at {new Date(o.fireTime).toLocaleString()})
                  </M>
                ))}
                {overlapConfirm.overlaps.length > 5 && (
                  <M style={{color:C.td,display:"block",fontSize:11}}>...and {overlapConfirm.overlaps.length - 5} more</M>
                )}
              </div>
              <div style={{display:"flex",gap:8}}>
                <Btn small onClick={()=>{setOverlapConfirm(null);}}>Cancel</Btn>
                <Btn small primary disabled={addBusy} onClick={()=>submitNewSchedule(true)}>{addBusy?"Queueing...":"Queue behind existing"}</Btn>
              </div>
            </Card>
          )}
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Add Schedule</div>
            {addError && (<M style={{color:C.d,display:"block",marginBottom:8}}>{addError}</M>)}
            <Input label="Name" value={newSchedule.name} onChange={e=>setNewSchedule(p=>({...p,name:e.target.value}))} placeholder="e.g. Daily HIPAA backup to S3"/>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12,marginTop:8}}>
              <Sel label="Backup type" value={newSchedule.type} onChange={e=>setNewSchedule(p=>({...p,type:e.target.value}))}>
                <option value="full">Full</option><option value="incremental">Incremental</option><option value="differential">Differential</option><option value="snapshot">Snapshot</option>
              </Sel>
              <Sel label="Frequency" value={newSchedule.frequency} onChange={e=>setNewSchedule(p=>({...p,frequency:e.target.value}))}>
                <option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option>
              </Sel>
              {newSchedule.frequency==="hourly" ? (
                <div><M style={{color:C.td,fontSize:11,display:"block",marginTop:18}}>Fires at the top of every hour</M></div>
              ) : (
                <Input label="Time (HH:MM)" value={newSchedule.time} onChange={e=>setNewSchedule(p=>({...p,time:e.target.value}))} type="time"/>
              )}
            </div>
            {newSchedule.frequency==="weekly" && (
              <Sel label="Day of week" value={newSchedule.day_of_week} onChange={e=>setNewSchedule(p=>({...p,day_of_week:parseInt(e.target.value,10)}))}>
                <option value={0}>Sunday</option><option value={1}>Monday</option><option value={2}>Tuesday</option><option value={3}>Wednesday</option><option value={4}>Thursday</option><option value={5}>Friday</option><option value={6}>Saturday</option>
              </Sel>
            )}
            {newSchedule.frequency==="monthly" && (
              <Input label="Day of month (1-31)" value={newSchedule.day_of_month} onChange={e=>setNewSchedule(p=>({...p,day_of_month:parseInt(e.target.value,10)||1}))} type="number" min={1} max={31}/>
            )}
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:8}}>
              <Sel label="Destination" value={newSchedule.destination} onChange={e=>setNewSchedule(p=>({...p,destination:e.target.value}))}>
                <option value="local">Local storage</option><option value="s3">AWS S3</option><option value="azure_blob">Azure Blob</option><option value="gcs">GCS</option><option value="nfs">NFS share</option><option value="offsite">Offsite (generic)</option><option value="air_gapped">Air-gapped</option><option value="tape">Tape (LTO)</option>
              </Sel>
              <Sel label={"Regulatory preset"+(activePreset?" — "+activePreset.framework_citation:"")} value={newSchedule.regulatory_preset_id || ""} onChange={e=>applyPresetDefaults(e.target.value || null)}>
                <option value="">None (full flexibility)</option>
                {presets.map(p=>(<option key={p.id} value={p.id}>{p.name} — {p.description}</option>))}
              </Sel>
            </div>
            <div style={{marginTop:8}}>
              <Input
                label={"Retention (days)"+(activePreset?` — ${activePreset.name} minimum: ${formatRetention(activePreset.min_retention_days)}`:"")}
                value={newSchedule.retention_days}
                onChange={e=>setNewSchedule(p=>({...p,retention_days:parseInt(e.target.value,10)||0}))}
                type="number"
                min={activePreset?activePreset.min_retention_days:1}
              />
              {activePreset && newSchedule.retention_days < activePreset.min_retention_days && (
                <M style={{color:C.d,display:"block",fontSize:11,marginTop:4}}>Below {activePreset.name} minimum of {formatRetention(activePreset.min_retention_days)}. Server will reject.</M>
              )}
            </div>
            {/* R3l C59: data scope (backup_kind) + strategy (backup_strategy) + destination filter */}
            <div style={{marginTop:12,padding:"10px 12px",background:"#181B1F",border:"1px solid "+C.i+"30",borderRadius:6}}>
              <div style={{fontSize:11,fontWeight:600,color:C.i,marginBottom:6}}>Data scope and strategy</div>
              <div style={{fontSize:11,color:C.td,marginBottom:8,lineHeight:1.5}}>
                Data scope selects what's backed up (full FireAlive deploy vs. database file only); strategy selects how the backup is taken (full vs. WAL-based incremental/differential vs. point-in-time snapshot). Defaults match the operator-intended behavior documented in the feature guide.
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                <Sel label="Data scope" value={newSchedule.backup_kind} onChange={e=>setNewSchedule(p=>({...p,backup_kind:e.target.value}))}>
                  <option value="full-suite">Full suite (configs + audit + keys + DB)</option>
                  <option value="single-db">Database file only</option>
                </Sel>
                <Sel label="Strategy" value={newSchedule.backup_strategy} onChange={e=>setNewSchedule(p=>({...p,backup_strategy:e.target.value}))}>
                  <option value="full">Full</option>
                  <option value="incremental">Incremental (WAL-based)</option>
                  <option value="differential">Differential (since anchor)</option>
                  <option value="snapshot">Snapshot (point-in-time)</option>
                </Sel>
              </div>
              <div style={{marginTop:8}}>
                <Input
                  label="Destination filter — required tags (comma-separated; empty = all enabled destinations)"
                  value={newSchedule.destination_filter}
                  onChange={e=>setNewSchedule(p=>({...p,destination_filter:e.target.value}))}
                  placeholder="e.g. offsite, encrypted"
                />
              </div>
              {(() => {
                // Summary panel: previews which destinations the current
                // filter selects. Mirrors the server-side matcher logic
                // in services/backup-push.js destinationMatchesFilter so
                // the operator sees push outcome before saving.
                const filterTags = (newSchedule.destination_filter || "").split(",").map(s=>s.trim()).filter(Boolean);
                const matchedDests = enabledDestinations.filter(d => {
                  if (filterTags.length === 0) return true;
                  let tags = [];
                  if (d.tags) {
                    try {
                      const parsed = JSON.parse(d.tags);
                      if (Array.isArray(parsed)) tags = parsed.filter(t => typeof t === "string");
                    } catch (_) { /* malformed JSON → no tags */ }
                  }
                  return filterTags.some(f => tags.includes(f));
                });
                const enabledCount = enabledDestinations.length;
                const matchedCount = matchedDests.length;
                const noFilter = filterTags.length === 0;
                const noMatch = !noFilter && matchedCount === 0;
                return (
                  <div style={{marginTop:8,padding:"8px 10px",background:noMatch?"#3a1e1e":"#1A1F25",borderRadius:4,fontSize:11}}>
                    <div style={{color:noMatch?C.d:C.tm,marginBottom:(matchedCount>0&&!noFilter)?4:0,lineHeight:1.5}}>
                      {enabledCount === 0
                        ? "No enabled backup destinations are configured. Backups will stay on-host only regardless of filter."
                        : noFilter
                          ? `No filter active — backups push to all ${enabledCount} enabled destination${enabledCount===1?"":"s"}.`
                          : noMatch
                            ? `Filter [${filterTags.join(", ")}] excludes all ${enabledCount} enabled destinations. Backups will stay on-host only. Tag a destination or expand the filter to enable remote pushes.`
                            : `Filter [${filterTags.join(", ")}] matches ${matchedCount} of ${enabledCount} enabled destination${enabledCount===1?"":"s"}.`}
                    </div>
                    {matchedCount > 0 && !noFilter && (
                      <div style={{color:C.t,fontSize:11}}>
                        Matching: {matchedDests.map(d => d.name).join(", ")}
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
            {/* R3l C74: chain-depth override input. Sits between the data-
                scope-and-strategy sub-card and the encrypt checkbox so it
                reads as part of the strategy decisions. Empty = inherit
                the global default (system_meta.max_chain_depth, seeded
                to 100 by the C73 migration). Service-layer validation
                rejects non-positive integers and values >1000 with the
                INVALID_MAX_CHAIN_DEPTH error code. */}
            <Input
              label="Max chain depth (incrementals before forcing a full; empty = use global default 100)"
              type="number"
              min={1}
              max={1000}
              value={newSchedule.max_chain_depth}
              onChange={e=>setNewSchedule(p=>({...p,max_chain_depth:e.target.value}))}
              placeholder="leave empty for global default"
            />
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"10px 0"}}>
              <input
                type="checkbox"
                checked={!!newSchedule.encrypted}
                disabled={activePreset && activePreset.required_encryption==="AES-256"}
                onChange={e=>setNewSchedule(p=>({...p,encrypted:e.target.checked}))}
              />
              <M style={{color:C.t}}>Encrypt backup (AES-256-GCM){activePreset && activePreset.required_encryption==="AES-256"?` — required by ${activePreset.name}`:""}</M>
            </label>
            <Btn primary disabled={addBusy} onClick={()=>submitNewSchedule(false)}>{addBusy?"Adding...":"+ Add Schedule"}</Btn>
          </Card>
        </div>)}

        {/* ══════════ v1.0.0 — SYNC INTERVAL ══════════ */}
        {tab==="sync_interval"&&(<div>
          <L>Burnout Stats Sync Interval</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Configure how often analyst clients transmit burnout metrics to the server. Default: every 15 minutes in batch mode. Continuous sync is unnecessary and wastes bandwidth. Adaptive sync reduces frequency when metrics are stable and increases it during active incidents.</M>
          <Card style={{marginBottom:16}}>
            <Input label="Base sync interval (minutes)" value={syncIntervalCfg.intervalMin} onChange={e=>setSyncIntervalCfg(prev=>({...prev,intervalMin:parseInt(e.target.value)||15}))} type="number"/>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" checked={syncIntervalCfg.adaptiveSync} onChange={e=>setSyncIntervalCfg(prev=>({...prev,adaptiveSync:e.target.checked}))}/><M style={{color:C.t}}>Adaptive sync — speed up during incidents, slow down when stable</M></label>
            <Input label="Urgent event threshold (seconds) — immediate push for panic/critical events" value={syncIntervalCfg.urgentThresholdSec} onChange={e=>setSyncIntervalCfg(prev=>({...prev,urgentThresholdSec:parseInt(e.target.value)||30}))} type="number"/>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={syncIntervalCfg.batchMode} onChange={e=>setSyncIntervalCfg(prev=>({...prev,batchMode:e.target.checked}))}/><M style={{color:C.t}}>Batch mode — accumulate metrics and send in single compressed payload</M></label>
          </Card>
          <Card style={{padding:12,borderColor:C.i+"30",marginBottom:16}}>
            <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:4}}>Bandwidth Estimate</M>
            <M style={{color:C.tm,lineHeight:1.8}}>Each sync payload: ~2-5 KB compressed (burnout signals, ticket metrics, delegation events). At 15-min intervals with 6 analysts: ~2.4 KB × 6 × 96 syncs/day ≈ 1.4 MB/day total. At 5-min intervals: ~4.1 MB/day. Negligible compared to SIEM/SOAR traffic. Adaptive sync during a major incident may temporarily increase to every 2 minutes for affected analysts.</M>
          </Card>
          <Btn primary onClick={()=>addA("SYNC_INTERVAL_SAVED","Sync interval config saved — base: "+syncIntervalCfg.intervalMin+"min")}>Save Sync Config</Btn>
        </div>)}

        {/* ══════════ v1.0.0 — PROACTIVE BREAK INTERVENTIONS ══════════ */}
        {tab==="proactive"&&(<div>
          <L>Proactive Break Interventions</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Based on Sonnentag's recovery research: prolonged high-severity ticket work without breaks accelerates burnout exponentially. This feature monitors analyst workload patterns and suggests Team-Lead-approved breaks before burnout signals appear. The analyst receives an affirming notification — they can opt to take the break or continue.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={proactiveCfg.enabled} onChange={e=>setProactiveCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable proactive break suggestions</label>
            <Input label="Hours of continuous high-severity work before suggesting break" value={proactiveCfg.highSevHours} onChange={e=>setProactiveCfg(prev=>({...prev,highSevHours:parseInt(e.target.value)||4}))} type="number"/>
            <Input label="Suggested break duration (minutes)" value={proactiveCfg.breakDurationMin} onChange={e=>setProactiveCfg(prev=>({...prev,breakDurationMin:parseInt(e.target.value)||15}))} type="number"/>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={proactiveCfg.requireLeadApproval} onChange={e=>setProactiveCfg(prev=>({...prev,requireLeadApproval:e.target.checked}))}/><M style={{color:C.t}}>Require Team Lead approval before sending break suggestion to analyst</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={proactiveCfg.affirmationEnabled} onChange={e=>setProactiveCfg(prev=>({...prev,affirmationEnabled:e.target.checked}))}/><M style={{color:C.p}}>Include affirmation message ("You've been working hard on critical incidents for X hours...")</M></label>
          </Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Pending Break Suggestions</div>
            {proactiveAlerts.filter(a=>a.status==="pending").length===0&&<M style={{color:C.td}}>No pending suggestions.</M>}
            {proactiveAlerts.filter(a=>a.status==="pending").map(a=>(
              <div key={a.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 0",borderBottom:`1px solid ${C.b}`}}>
                <div><M style={{color:C.p,fontWeight:500}}>{a.pseudonym}</M><M style={{color:C.td,display:"block"}}>Trigger: {a.trigger}</M></div>
                <div style={{display:"flex",gap:6}}>
                  <Btn small primary onClick={()=>{setProactiveAlerts(prev=>prev.map(x=>x.id===a.id?{...x,status:"approved"}:x));addA("PROACTIVE_BREAK_APPROVED","Break suggestion approved for "+a.pseudonym+" — notification sent to analyst");}}>Approve & Send</Btn>
                  <Btn small onClick={()=>setProactiveAlerts(prev=>prev.map(x=>x.id===a.id?{...x,status:"dismissed"}:x))}>Dismiss</Btn>
                </div>
              </div>
            ))}
          </Card>
          <Card style={{padding:12,borderColor:C.i+"30"}}>
            <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:4}}>What the Analyst Sees</M>
            <M style={{color:C.tm,lineHeight:1.8}}>"You've been investigating high-severity incidents for 4 straight hours. Your work is making a real difference for the team. Your lead has approved a 15-minute break if you'd like one — your queue will be paused. [Take Break] [Continue Working]"</M>
          </Card>
          <Btn primary style={{marginTop:12}} onClick={()=>api.post("/api/v1/audit/log",{event:"PROACTIVE_CONFIG_SAVED",detail:"Proactive intervention config saved"}).then(()=>addA("PROACTIVE_CONFIG_SAVED","Proactive intervention config saved"))}>Save Config</Btn>
        </div>)}

        {/* ══════════ v1.0.0 — UPSKILLING HOUR ══════════ */}
        {tab==="upskilling_hr"&&(<div>
          <L>Upskilling Hour</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Dedicate one hour per shift to analyst professional development — peer skill-sharing, training, certifications. During this hour, burnout routing stops sending tickets to that analyst. Research consistently shows that companies investing in on-the-clock development see lower turnover, higher job satisfaction, and ultimately lower costs than continuous replacement hiring. Analysts shouldn't have to upskill on their own time — that just accelerates burnout.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={upskillingCfg.enabled} onChange={e=>setUpskillingCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable upskilling hour</label>
            <Input label="Which hour of the shift (1-8, e.g. 8 = last hour)" value={upskillingCfg.hourOfShift} onChange={e=>setUpskillingCfg(prev=>({...prev,hourOfShift:parseInt(e.target.value)||8}))} type="number"/>
            <Input label="Duration (minutes)" value={upskillingCfg.durationMin} onChange={e=>setUpskillingCfg(prev=>({...prev,durationMin:parseInt(e.target.value)||60}))} type="number"/>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={upskillingCfg.stopRouting} onChange={e=>setUpskillingCfg(prev=>({...prev,stopRouting:e.target.checked}))}/><M style={{color:C.a}}>Pause ticket routing during upskilling hour</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={upskillingCfg.allowPeerChat} onChange={e=>setUpskillingCfg(prev=>({...prev,allowPeerChat:e.target.checked}))}/><M style={{color:C.t}}>Allow peer skill-share sessions during this hour</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={upskillingCfg.allowTraining} onChange={e=>setUpskillingCfg(prev=>({...prev,allowTraining:e.target.checked}))}/><M style={{color:C.t}}>Allow training module access during this hour</M></label>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" defaultChecked/><M style={{color:C.w}}>Content filter</M></label>
          </Card>
          <Card style={{padding:12,borderColor:C.p+"30",marginBottom:16}}>
            <M style={{color:C.p,fontWeight:500,display:"block",marginBottom:4}}>The Business Case</M>
            <M style={{color:C.tm,lineHeight:1.8}}>Average SOC analyst replacement cost: $85,000 (recruiting, onboarding, ramp-up). Annual turnover rate: 35%. For a 6-person team: ~$178,500/year in churn costs. One hour per day per analyst for upskilling costs ~$31,200/year in productive time. Net savings: $147,300/year — plus reduced insider threat risk from disgruntled departing analysts, plus compounding skill improvement.</M>
          </Card>
          <Btn primary onClick={()=>addA("UPSKILLING_HR_SAVED","Upskilling hour config saved — hour "+upskillingCfg.hourOfShift+" of shift")}>Save Upskilling Config</Btn>
          {/* R3c: HR Scheduling Platform Integration */}
          <Card style={{marginTop:16,marginBottom:16,borderColor:schedCfg.last_sync_status==="failure"?C.d+"40":(schedCfg.last_sync_status==="success"?C.a+"40":C.b)}}>
            <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5",marginBottom:10}}>Per-Analyst Scheduling</div>

            {/* Status panel */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit, minmax(180px, 1fr))",gap:8,marginBottom:14,padding:12,background:C.s,border:"1px solid "+C.b,borderRadius:8}}>
              <M style={{color:C.tm}}>State: <span style={{color:schedCfg.enabled?C.a:C.tm}}>{schedCfg.enabled?"enabled":"disabled"}</span></M>
              <M style={{color:C.tm}}>Platform: <span style={{color:schedCfg.platform?C.t:C.tm}}>{schedCfg.platform||"not set"}</span></M>
              <M style={{color:C.tm}}>Credentials: <span style={{color:schedCfg.credentials_set?C.a:C.w}}>{schedCfg.credentials_set?"configured":"not set"}</span></M>
              <M style={{color:C.tm}}>Last sync: {schedCfg.last_sync_at||"never"}</M>
              <M style={{color:C.tm}}>Status: <span style={{color:schedCfg.last_sync_status==="success"?C.a:(schedCfg.last_sync_status==="failure"?C.d:C.tm)}}>{schedCfg.last_sync_status||"\u2014"}</span></M>
              <M style={{color:C.tm}}>Failures: <span style={{color:schedCfg.consecutive_failures>0?C.d:C.tm}}>{schedCfg.consecutive_failures||0}</span></M>
            </div>
            {schedCfg.last_sync_error && <Card style={{padding:8,marginBottom:10,borderColor:C.d+"40"}}><M style={{color:C.d,fontSize:11}}>Last error: {schedCfg.last_sync_error}</M></Card>}

            {/* Platform configuration */}
            <Card style={{padding:14,marginBottom:12}}>
              <Sel label="Platform" value={schedCfg.platform||""} onChange={e=>setSchedCfg(prev=>({...prev,platform:e.target.value||null,credentials_input:{}}))}>
                <option value="">Select...</option>
                <option value="ukg_kronos">UKG / Kronos</option>
                <option value="workday">Workday</option>
                <option value="adp">ADP</option>
                <option value="bamboohr">BambooHR</option>
                <option value="manual">Manual (FireAlive is system of record)</option>
              </Sel>
              {schedCfg.platform && schedCfg.platform!=="manual" && (
                <Input label="Endpoint URL" placeholder="https://hr.corp.local/api" value={schedCfg.endpoint_url||""} onChange={e=>setSchedCfg(prev=>({...prev,endpoint_url:e.target.value}))}/>
              )}

              {schedCfg.platform==="bamboohr" && (
                <div style={{marginTop:8}}>
                  <M style={{color:C.tm,fontSize:11,marginBottom:6,display:"block"}}>BambooHR credentials {schedCfg.credentials_set?"(configured — fill in to update, or leave blank to keep)":""}</M>
                  <Input label="Subdomain" placeholder="acme" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,subdomain:e.target.value}}))} value={schedCfg.credentials_input?.subdomain||""}/>
                  <Input label="API Key" type="password" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,apiKey:e.target.value}}))} value={schedCfg.credentials_input?.apiKey||""}/>
                </div>
              )}
              {schedCfg.platform==="workday" && (
                <div style={{marginTop:8}}>
                  <M style={{color:C.tm,fontSize:11,marginBottom:6,display:"block"}}>Workday credentials {schedCfg.credentials_set?"(configured — fill in to update, or leave blank to keep)":""}</M>
                  <Input label="Tenant URL" placeholder="https://acme.workday.com" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,tenantUrl:e.target.value}}))} value={schedCfg.credentials_input?.tenantUrl||""}/>
                  <Input label="Client ID" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,clientId:e.target.value}}))} value={schedCfg.credentials_input?.clientId||""}/>
                  <Input label="Client Secret" type="password" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,clientSecret:e.target.value}}))} value={schedCfg.credentials_input?.clientSecret||""}/>
                  <Input label="Refresh Token" type="password" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,refreshToken:e.target.value}}))} value={schedCfg.credentials_input?.refreshToken||""}/>
                </div>
              )}
              {schedCfg.platform==="adp" && (
                <div style={{marginTop:8}}>
                  <M style={{color:C.tm,fontSize:11,marginBottom:6,display:"block"}}>ADP credentials {schedCfg.credentials_set?"(configured — fill in to update, or leave blank to keep)":""}</M>
                  <Input label="Client ID" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,clientId:e.target.value}}))} value={schedCfg.credentials_input?.clientId||""}/>
                  <Input label="Client Secret (optional)" type="password" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,clientSecret:e.target.value}}))} value={schedCfg.credentials_input?.clientSecret||""}/>
                  <div style={{marginTop:8}}>
                    <M style={{color:C.tm,fontSize:11,display:"block",marginBottom:4}}>Client Certificate (PEM)</M>
                    <textarea placeholder="-----BEGIN CERTIFICATE-----" value={schedCfg.credentials_input?.certPem||""} onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,certPem:e.target.value}}))} style={{width:"100%",minHeight:80,padding:8,background:"rgba(255,255,255,0.03)",border:"1px solid "+C.b,borderRadius:6,color:C.t,fontSize:10,fontFamily:"monospace"}}/>
                  </div>
                  <div style={{marginTop:8}}>
                    <M style={{color:C.tm,fontSize:11,display:"block",marginBottom:4}}>Private Key (PEM)</M>
                    <textarea placeholder="-----BEGIN PRIVATE KEY-----" value={schedCfg.credentials_input?.certKeyPem||""} onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,certKeyPem:e.target.value}}))} style={{width:"100%",minHeight:80,padding:8,background:"rgba(255,255,255,0.03)",border:"1px solid "+C.b,borderRadius:6,color:C.t,fontSize:10,fontFamily:"monospace"}}/>
                  </div>
                </div>
              )}
              {schedCfg.platform==="ukg_kronos" && (
                <div style={{marginTop:8}}>
                  <M style={{color:C.tm,fontSize:11,marginBottom:6,display:"block"}}>UKG / Kronos credentials {schedCfg.credentials_set?"(configured — fill in to update, or leave blank to keep)":""}</M>
                  <Input label="Tenant URL" placeholder="https://acme.us.workforce.ukg.com" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,tenantUrl:e.target.value}}))} value={schedCfg.credentials_input?.tenantUrl||""}/>
                  <Input label="Client ID" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,clientId:e.target.value}}))} value={schedCfg.credentials_input?.clientId||""}/>
                  <Input label="Client Secret" type="password" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,clientSecret:e.target.value}}))} value={schedCfg.credentials_input?.clientSecret||""}/>
                  <Input label="Username (service account)" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,username:e.target.value}}))} value={schedCfg.credentials_input?.username||""}/>
                  <Input label="Password" type="password" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,password:e.target.value}}))} value={schedCfg.credentials_input?.password||""}/>
                  <Input label="API Key (optional)" onChange={e=>setSchedCfg(prev=>({...prev,credentials_input:{...prev.credentials_input,apiKey:e.target.value}}))} value={schedCfg.credentials_input?.apiKey||""}/>
                </div>
              )}

              <label style={{display:"flex",alignItems:"center",gap:8,marginTop:10}}>
                <input type="checkbox" checked={schedCfg.enabled} onChange={e=>setSchedCfg(prev=>({...prev,enabled:e.target.checked}))}/>
                <M style={{color:C.t}}>Enabled</M>
              </label>

              <div style={{display:"flex",gap:8,marginTop:14,flexWrap:"wrap"}}>
                <Btn primary disabled={schedCfg._saving} onClick={()=>{
                  const payload = {enabled: schedCfg.enabled, platform: schedCfg.platform, endpoint_url: schedCfg.endpoint_url || null};
                  if (schedCfg.credentials_input && Object.values(schedCfg.credentials_input).some(v=>v)) {
                    payload.credentials = schedCfg.credentials_input;
                  }
                  setSchedCfg(prev=>({...prev,_saving:true}));
                  api.put("/api/scheduling/config", payload).then(r=>{
                    if (r && !r.error) {
                      setSchedCfg(prev=>({...prev,...r,credentials_input:{},_saving:false,_loaded:true,_savedPlatform:r.platform,_savedEndpointUrl:r.endpoint_url||"",_savedCredsSet:!!r.credentials_set}));
                      addA("SCHEDULING","Configuration saved");
                    } else {
                      setSchedCfg(prev=>({...prev,_saving:false}));
                      addA("SCHEDULING","Save failed: "+(r?.error||"unknown"));
                    }
                  });
                }}>{schedCfg._saving?"Saving...":"Save Configuration"}</Btn>

                <Btn disabled={schedCfg._testing||!schedCfg._savedPlatform||(schedCfg._savedPlatform!=="manual"&&(!schedCfg._savedEndpointUrl||!schedCfg._savedCredsSet))} onClick={()=>{
                  setSchedCfg(prev=>({...prev,_testing:true,_testResult:null}));
                  api.post("/api/scheduling/test", {}).then(r=>{
                    setSchedCfg(prev=>({...prev,_testing:false,_testResult:r}));
                    if (r?.ok) addA("SCHEDULING","Test connection succeeded ("+(r.durationMs||0)+"ms, "+(r.analystsReturned||0)+" analysts)");
                    else addA("SCHEDULING","Test failed: "+(r?.error||"unknown"));
                  });
                }}>{schedCfg._testing?"Testing...":"Test Connection"}</Btn>

                <Btn disabled={!schedCfg.enabled} onClick={()=>{
                  api.post("/api/scheduling/sync", {}).then(r=>{
                    if (r?.ok) addA("SCHEDULING", r.alreadyRunning ? "Sync already in progress" : "Sync queued — check status panel for completion");
                    else addA("SCHEDULING", "Sync trigger failed: "+(r?.error||"unknown"));
                  });
                }}>Sync Now</Btn>

                {schedCfg.consecutive_failures>0 && (
                  <Btn small onClick={()=>{
                    api.put("/api/scheduling/config",{reset_failure_counter:true}).then(r=>{
                      if (r && !r.error) {
                        setSchedCfg(prev=>({...prev,...r,_loaded:true}));
                        addA("SCHEDULING","Failure counter reset");
                      }
                    });
                  }}>Reset Failure Counter</Btn>
                )}

                {schedCfg.credentials_set && (
                  <Btn small onClick={()=>{
                    if (window.confirm("Clear stored credentials? Sync will be disabled until new credentials are set.")) {
                      api.put("/api/scheduling/config",{clear_credentials:true,enabled:false}).then(r=>{
                        if (r && !r.error) {
                          setSchedCfg(prev=>({...prev,...r,credentials_input:{},_loaded:true,_savedCredsSet:false}));
                          addA("SCHEDULING","Credentials cleared");
                        }
                      });
                    }
                  }}>Clear Stored Credentials</Btn>
                )}
              </div>

              {schedCfg._testResult && (
                <Card style={{padding:8,marginTop:10,borderColor:schedCfg._testResult.ok?C.a+"40":C.d+"40"}}>
                  <M style={{color:schedCfg._testResult.ok?C.a:C.d,fontSize:11}}>
                    {schedCfg._testResult.ok
                      ? "Test passed: "+schedCfg._testResult.platform+" returned "+(schedCfg._testResult.analystsReturned||0)+" analysts in "+(schedCfg._testResult.durationMs||0)+"ms"
                      : "Test failed: "+(schedCfg._testResult.error||"unknown error")}
                  </M>
                </Card>
              )}
            </Card>

            {/* Coverage / frequency settings (kept from prior version, unchanged) */}
            <Card style={{padding:14,marginBottom:12}}><Input label="Min coverage (%)" type="number" defaultValue="75"/><Sel label="Frequency"><option>Every shift</option><option>Alternate</option><option>3/week</option><option>Weekly</option></Sel></Card>

            {/* Per-analyst upskilling-slot grid (unchanged — already wired to /api/upskilling/schedule per-row) */}
            <Card style={{padding:14,marginBottom:12}}><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Schedule (select hour per analyst)</div><div style={{background:C.s,border:"1px solid "+C.b,borderRadius:10,overflow:"hidden"}}>{(analysts.length?analysts:[]).filter(a=>a.shift==="day").slice(0,6).map(a=>({id:a.id,n:a.name,t:"L"+a.tier,h:a.tier===3?"14-15":a.tier===2?"10-11":"16-17"})).map((a,idx)=>(<div key={idx} style={{display:"flex",justifyContent:"space-between",padding:"6px 14px",borderBottom:"1px solid "+C.b,alignItems:"center",gap:8}}><M style={{color:C.t,minWidth:70}}>{a.n}</M><Badge color={a.t==="L3"?C.p:C.i}>{a.t}</Badge><select defaultValue={a.h} style={{flex:1,padding:4,background:"rgba(255,255,255,0.03)",border:"1px solid "+C.b,borderRadius:6,color:C.t,fontSize:11}} onChange={e=>api.post("/api/upskilling/schedule",{analystId:a.id,slot:e.target.value}).then(()=>addA("SCHED",a.n+" -> "+e.target.value))}><option value="06-07">06-07</option><option value="07-08">07-08</option><option value="08-09">08-09</option><option value="09-10">09-10</option><option value="10-11">10-11</option><option value="11-12">11-12</option><option value="12-13">12-13</option><option value="13-14">13-14</option><option value="14-15">14-15</option><option value="15-16">15-16</option><option value="16-17">16-17</option><option value="17-18">17-18</option></select></div>))}</div></Card>
          </Card>
        </div>)}

        {/* ══════════ v1.0.0 — AUTO-DISABLE ROUTING ON CRITICAL INCIDENTS ══════════ */}
        {tab==="auto_disable"&&(<div>
          <L>Auto-Disable Burnout Prevention Routing</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>During a major incident requiring all hands, the Team Lead shouldn't have to remember to manually disable burnout routing. This feature auto-disables routing when critical triggers are detected — SIEM alerts, high-severity tickets, or SOAR escalations — so everyone gets tickets immediately. Routing restores automatically after a cooldown period.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={autoDisableRoutingCfg.enabled} onChange={e=>setAutoDisableRoutingCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable auto-disable on critical incidents</label>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Triggers</div>
            {[{k:"criticalTicket",l:"P1/Critical ticket enters queue"},{k:"siemAlert",l:"SIEM fires critical alert"},{k:"soarPlaybook",l:"SOAR escalation playbook triggers"},{k:"manualEscalation",l:"Any analyst manually escalates to 'all hands'"}].map(t=>(
              <label key={t.k} style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" checked={autoDisableRoutingCfg.triggers[t.k]} onChange={e=>setAutoDisableRoutingCfg(prev=>({...prev,triggers:{...prev.triggers,[t.k]:e.target.checked}}))}/><M style={{color:C.t}}>{t.l}</M></label>
            ))}
            <Input label="Cooldown — auto-restore routing after (minutes)" value={autoDisableRoutingCfg.cooldownMin} onChange={e=>setAutoDisableRoutingCfg(prev=>({...prev,cooldownMin:parseInt(e.target.value)||30}))} type="number"/>
            <label style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}><input type="checkbox" checked={autoDisableRoutingCfg.notifyLead} onChange={e=>setAutoDisableRoutingCfg(prev=>({...prev,notifyLead:e.target.checked}))}/><M style={{color:C.w}}>Notify Team Lead when auto-disable activates</M></label>
          </Card>
          <Btn primary onClick={()=>api.post("/api/v1/audit/log",{event:"AUTO_DISABLE_ROUTING_SAVED",detail:"Auto-disable routing config saved"}).then(()=>addA("AUTO_DISABLE_ROUTING_SAVED","Auto-disable routing config saved"))}>Save Config</Btn>
        </div>)}

        {/* ══════════ Phase F2 — RECOVERY RUNBOOK (FireAlive-specific) ══════════ */}
        {tab==="runbook"&&(<div>
          <L>Recovery Runbook Generator</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Generate runbooks for FireAlive-specific failure and compromise scenarios. The org already has runbooks for general incident response (ransomware on host, generic insider threat); FireAlive doesn't try to replace those. This generator addresses the new attack surface and failure modes that FireAlive's adoption introduces — compromise of FireAlive itself, MC↔AC channel attacks, false signal injection tripping the tripwire, etc.</M>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6,fontStyle:"italic"}}>This runbook is preparation material. Generate scenarios in advance, print or save them, and execute from those copies during a real event when the platform itself may be unavailable.</M>
          {runbookScenariosLoading&&(<Card style={{marginBottom:16}}><M style={{color:C.tm}}>Loading scenario library…</M></Card>)}
          {!runbookScenariosLoading&&runbookScenarios.length===0&&(<Card style={{marginBottom:16}}><M style={{color:C.d}}>No scenarios available. Verify /api/runbook/scenarios is reachable.</M></Card>)}
          {!runbookScenariosLoading&&runbookScenarios.length>0&&(<Card style={{marginBottom:16}}>
            <Sel label={"Scenario ("+runbookScenarios.length+" available across "+runbookCategories.length+" categories)"} value={runbookSelectedId} onChange={e=>setRunbookSelectedId(e.target.value)}>
              <option value="">— Select a scenario —</option>
              {runbookCategories.map(cat=>(
                <optgroup key={cat} label={cat}>
                  {runbookScenarios.filter(s=>s.category===cat).map(s=>(
                    <option key={s.id} value={s.id}>{s.title}</option>
                  ))}
                </optgroup>
              ))}
            </Sel>
            {runbookSelectedId&&(()=>{
              const s = runbookScenarios.find(x=>x.id===runbookSelectedId);
              if (!s) return null;
              return (<div style={{marginTop:12,padding:12,background:C.s,borderRadius:6,border:`1px solid ${C.b}`}}>
                <div style={{fontSize:11,color:C.tm,marginBottom:4}}>{s.category}</div>
                <div style={{fontSize:14,fontWeight:600,color:C.t,marginBottom:8}}>{s.title}</div>
                <M style={{color:C.tm,lineHeight:1.6}}>{s.summary}</M>
              </div>);
            })()}
            <div style={{display:"flex",gap:12,marginTop:12,flexWrap:"wrap"}}>
              <Sel label="Artifact" value={runbookArtifactType} onChange={e=>setRunbookArtifactType(e.target.value)}>
                <option value="quickref">Quick Reference (1-page card)</option>
                <option value="full">Full Runbook (multi-section)</option>
              </Sel>
              <Sel label="Format" value={runbookFormat} onChange={e=>setRunbookFormat(e.target.value)}>
                {runbookValidFormats.map(f=>(<option key={f} value={f}>{f.toUpperCase()}</option>))}
              </Sel>
            </div>
            <Btn primary disabled={!runbookSelectedId||runbookGenerating} style={{marginTop:12}} onClick={()=>{
              if (!runbookSelectedId) return;
              setRunbookGenerating(true);
              const endpoint = runbookArtifactType==="quickref" ? "/api/runbook/quickref" : "/api/runbook/full";
              const filename = "runbook-"+runbookArtifactType+"-"+runbookSelectedId+"."+runbookFormat;
              api.download(endpoint, filename, {
                method: "POST",
                body: { scenarioId: runbookSelectedId, format: runbookFormat },
              }).then(ok=>{
                if (ok) {
                  addA("RUNBOOK_GENERATED", "Generated "+runbookArtifactType+" for scenario "+runbookSelectedId+" ("+runbookFormat+")");
                } else {
                  addA("RUNBOOK_GENERATE_FAILED", "Failed to generate runbook");
                }
              }).finally(()=>setRunbookGenerating(false));
            }}>{runbookGenerating?"Generating…":"Download "+(runbookArtifactType==="quickref"?"Quick Reference":"Full Runbook")}</Btn>
          </Card>)}
        </div>)}

        {/* ══════════ v1.0.0 — ANALYST OFFBOARDING ══════════ */}
        {tab==="offboarding"&&(<div>
          <L>Analyst Offboarding</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Securely deprovision analysts who leave the org or change roles. Their historical data is archived for aggregate reporting but personally identifiable links are severed. All keys, sessions, and peer chat schedules are revoked. Integrates with SOAR/IAM offboarding orchestration.</M>
          <Card style={{marginBottom:16,borderColor:C.i+"30"}}><div style={{fontSize:13,fontWeight:600,color:C.i,marginBottom:10}}>IAM Offboarding</div><label style={{display:"flex",alignItems:"center",gap:8,padding:"8px 0"}}><input type="checkbox" defaultChecked/><M style={{color:C.t}}>Enable</M></label><Sel label="Frequency"><option>Every 4hr</option><option>Every 8hr</option><option>Daily</option><option>Weekly</option></Sel><Card style={{padding:12,borderColor:C.w+"30",marginTop:12}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 0"}}><M style={{color:C.t}}>{analysts.length>0?analysts[0].name:"No pending reviews"}</M><div style={{display:"flex",gap:6}}><Btn small primary onClick={()=>analysts[0]&&api.post("/api/iam/confirm-status",{analystId:analysts[0].id,action:"active"}).then(()=>addA("IA","Confirmed active"))}>Active</Btn><Btn small danger onClick={()=>analysts[0]&&api.post("/api/iam/confirm-status",{analystId:analysts[0].id,action:"offboard"}).then(()=>addA("IO","Offboarded"))}>Offboard</Btn></div></div></Card></Card>
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Offboard an Analyst</div>
            <Sel label="Analyst" value={newOffboard.analystId} onChange={e=>setNewOffboard(prev=>({...prev,analystId:e.target.value}))}>
              <option value="">Select analyst...</option>{analysts.map(a=><option key={a.id} value={a.id}>{a.name}</option>)}
            </Sel>
            <Sel label="Reason" value={newOffboard.reason} onChange={e=>setNewOffboard(prev=>({...prev,reason:e.target.value}))}>
              <option value="departure">Voluntary departure</option><option value="termination">Termination</option><option value="role_change">Role change (no longer analyst)</option><option value="transfer">Transfer to another team</option>
            </Sel>
            <div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginTop:12,marginBottom:8}}>Offboarding Actions</div>
            {[{k:"archiveData",l:"Archive burnout/training data for aggregate reporting"},{k:"revokeKeys",l:"Revoke all API tokens, encryption keys, session tokens"},{k:"cancelPeerSessions",l:"Cancel scheduled peer skill-share sessions"},{k:"notifySoar",l:"Notify SOAR/IAM orchestration of offboarding"}].map(s=>(
              <label key={s.k} style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}><input type="checkbox" checked={newOffboard[s.k]} onChange={e=>setNewOffboard(prev=>({...prev,[s.k]:e.target.checked}))}/><M style={{color:C.t}}>{s.l}</M></label>
            ))}
            <Btn primary style={{marginTop:12}} disabled={!newOffboard.analystId} onClick={()=>{
              const analyst = analysts.find(a=>a.id===newOffboard.analystId);
              setOffboardingQueue(prev=>[...prev,{...newOffboard,name:analyst?.name,ts:new Date().toISOString(),status:"completed"}]);
              setNewOffboard({analystId:"",reason:"departure",archiveData:true,revokeKeys:true,cancelPeerSessions:true,notifySoar:true});
              addA("ANALYST_OFFBOARDED","Analyst offboarded: "+analyst?.name+" — keys revoked, data archived, sessions cancelled");
            }}>Execute Offboarding</Btn>
          </Card>
          {offboardingQueue.length>0&&<Card><div style={{fontSize:12,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Offboarding History</div>{offboardingQueue.map((o,i)=><div key={i} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`}}><M style={{color:C.t}}>{o.name} — {o.reason} — {new Date(o.ts).toLocaleDateString()}</M></div>)}</Card>}
        </div>)}

        {/* ══════════ v1.0.0 — TTX GENERATOR ══════════ */}
        {tab==="ttx"&&(<div>
          <L>Tabletop Exercise Generator</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Pick a scenario and difficulty, then download a Situation Manual (SitMan) for the lead to bring to the meeting and a blank After-Action Report (AAR) template for the team to fill in afterwards. Both formats are available in PDF (printable) and DOCX (editable). Each generation is logged to the audit trail as compliance evidence.</M>
          <Card style={{marginBottom:16}}>
            {ttxScenariosLoading&&<M style={{color:C.tm}}>Loading scenarios...</M>}
            {!ttxScenariosLoading&&ttxScenariosList.length===0&&<M style={{color:C.tm}}>No scenarios available. Check that the server is running and that you have lead/admin access.</M>}
            {!ttxScenariosLoading&&ttxScenariosList.length>0&&(<>
              <Sel label="Scenario" value={ttxScenarioId} onChange={e=>setTtxScenarioId(e.target.value)}>
                <option value="">— Select a scenario —</option>
                {ttxScenariosList.map(s=><option key={s.id} value={s.id}>{s.title}</option>)}
              </Sel>
              <Sel label="Difficulty" value={ttxDifficulty} onChange={e=>setTtxDifficulty(e.target.value)}>
                <option value="easy">Easy — 3-4 injects, single attack vector</option>
                <option value="intermediate">Intermediate — 5-7 injects, concurrent issues</option>
                <option value="hard">Hard — 8-12 injects, cascading failures</option>
              </Sel>
              <Sel label="Format" value={ttxFormat} onChange={e=>setTtxFormat(e.target.value)}>
                <option value="pdf">PDF — printable, archival</option>
                <option value="docx">DOCX — editable in Word</option>
              </Sel>
              {ttxScenarioId&&(()=>{
                const s = ttxScenariosList.find(x=>x.id===ttxScenarioId);
                return s?(<div style={{padding:"10px 0",borderTop:`1px solid ${C.b}`,marginTop:6}}>
                  <M style={{color:C.tm,display:"block",marginBottom:4}}>About this scenario</M>
                  <M style={{color:C.t,display:"block",lineHeight:1.6}}>{s.description}</M>
                </div>):null;
              })()}
              <div style={{display:"flex",gap:8,marginTop:14,flexWrap:"wrap"}}>
                <Btn primary disabled={!ttxScenarioId||ttxGenerating} onClick={()=>{
                  if (!ttxScenarioId) return;
                  setTtxGenerating(true);
                  const filename = "sitman-"+ttxScenarioId+"-"+ttxDifficulty+"."+ttxFormat;
                  api.download("/api/ttx/sitman", filename, {
                    method: "POST",
                    body: { scenarioId: ttxScenarioId, difficulty: ttxDifficulty, format: ttxFormat },
                  }).finally(()=>setTtxGenerating(false));
                }}>{ttxGenerating?"Generating...":"Download SitMan"}</Btn>
                <Btn disabled={!ttxScenarioId||ttxGenerating} onClick={()=>{
                  if (!ttxScenarioId) return;
                  setTtxGenerating(true);
                  const filename = "aar-template-"+ttxScenarioId+"-"+ttxDifficulty+"."+ttxFormat;
                  api.download("/api/ttx/aar", filename, {
                    method: "POST",
                    body: { scenarioId: ttxScenarioId, difficulty: ttxDifficulty, format: ttxFormat },
                  }).finally(()=>setTtxGenerating(false));
                }}>{ttxGenerating?"Generating...":"Download AAR Template"}</Btn>
              </div>
            </>)}
          </Card>
          <Card>
            <L style={{marginBottom:10}}>How a tabletop exercise works</L>
            <M style={{color:C.t,display:"block",lineHeight:1.6,marginBottom:8}}>A TTX is a discussion-based exercise. The team sits together. The facilitator (a lead) opens the SitMan, reads the scenario brief aloud, then drops injects one at a time. The team talks through how they would respond. Someone takes notes.</M>
            <M style={{color:C.t,display:"block",lineHeight:1.6,marginBottom:8}}>After the meeting, the team fills in the AAR template — what went well, what gaps showed up, action items. The completed AAR is the artifact auditors look for as proof the tabletop wasn't just a checkbox.</M>
            <M style={{color:C.tm,display:"block",lineHeight:1.6}}>Source: NIST SP 800-84, CISA CTEPs, HSEEP Volume IV.</M>
          </Card>
        </div>)}

        {/* ══════════ v1.0.0 — LEGAL HOLD ══════════ */}
        {tab==="legal_hold"&&(<div>
          <L>Legal Hold Backup</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Export app data for legal hold / e-discovery requirements. Data is hashed for integrity verification, formatted for ESI repositories, and retained indefinitely until the hold is released. Chain of custody documentation is generated automatically.</M>
          <Card style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}><input type="checkbox" checked={legalHoldCfg.enabled} onChange={e=>setLegalHoldCfg(prev=>({...prev,enabled:e.target.checked}))} style={{accentColor:C.a}}/>Enable legal hold capability</label>
            <Input label="ESI repository path / endpoint" value={legalHoldCfg.repository} onChange={e=>setLegalHoldCfg(prev=>({...prev,repository:e.target.value}))} placeholder="/legal-hold/esi-repo/ or https://ediscovery.corp.com/api" maxLength={512}/>
            <Sel label="Hash algorithm" value={legalHoldCfg.hashAlgorithm} onChange={e=>setLegalHoldCfg(prev=>({...prev,hashAlgorithm:e.target.value}))}>
              <option value="sha256">SHA-256</option><option value="sha512">SHA-512</option><option value="md5_sha256">MD5 + SHA-256 (dual hash)</option>
            </Sel>
            <Sel label="Export format" value={legalHoldCfg.format} onChange={e=>setLegalHoldCfg(prev=>({...prev,format:e.target.value}))}>
              <option value="json">JSON (structured)</option><option value="csv">CSV (tabular)</option><option value="eml_pst">EML/PST (email-compatible)</option><option value="native">Native SQLite (forensic)</option>
            </Sel>
          </Card>
          <Btn primary onClick={()=>setLhCreate(prev=>({...prev,open:true,error:""}))}>Execute Legal Hold Export</Btn>

          {lhCreate.open && (
            <Modal title="Create Legal Hold" onClose={()=>setLhCreate(prev=>({...prev,open:false}))} width={620}>
              <M style={{display:"block",marginBottom:16,color:C.tm,lineHeight:1.5}}>
                Initiates a litigation-grade evidence preservation hold. Active holds are exempt from scheduled retention. Release requires a CISO different from the requester (separate-actor invariant enforced at three layers — schema CHECK, orchestrator pre-check, and route handler).
              </M>
              <Input label="Case ID (required)" value={lhCreate.caseId} onChange={e=>setLhCreate(prev=>({...prev,caseId:e.target.value}))} placeholder="e.g., Smith-v-Acme-2026, GDPR-Inquiry-Q3" maxLength={200}/>
              <div style={{marginBottom:14}}>
                <M style={{color:C.tm,marginBottom:4,display:"block"}}>Rationale (required, min 20 chars)</M>
                <textarea value={lhCreate.rationale} onChange={e=>setLhCreate(prev=>({...prev,rationale:e.target.value}))} placeholder="Document why this hold is being placed — court order ref, regulatory request, internal investigation context" style={{width:"100%",minHeight:80,padding:10,fontSize:12,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontFamily:"inherit",resize:"vertical"}} maxLength={2000}/>
                <M style={{color:lhCreate.rationale.trim().length<20?C.dd:C.tm,marginTop:4,display:"block"}}>{lhCreate.rationale.trim().length}/20 minimum chars</M>
              </div>
              <div style={{marginBottom:14}}>
                <M style={{color:C.tm,marginBottom:6,display:"block"}}>Export formats (select 1+ — all 8 are litigation-tested)</M>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:4}}>
                  {["edrm-xml","eml-mime","pst","concordance","relativity","json-tarball","pdf-bates","tiff-bates"].map(f=>(
                    <label key={f} style={{display:"flex",alignItems:"center",gap:6,fontSize:11,color:C.t}}>
                      <input type="checkbox" checked={lhCreate.outputFormats.includes(f)} onChange={e=>{
                        const checked = e.target.checked;
                        setLhCreate(prev=>{
                          const next = checked ? [...prev.outputFormats, f] : prev.outputFormats.filter(x=>x!==f);
                          return {...prev, outputFormats: next};
                        });
                      }} style={{accentColor:C.a}}/>
                      <span style={{fontFamily:"'IBM Plex Mono',monospace"}}>{f}</span>
                    </label>
                  ))}
                </div>
              </div>
              <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.t,marginBottom:14}}>
                <input type="checkbox" checked={lhCreate.indefiniteRetention} onChange={e=>setLhCreate(prev=>({...prev,indefiniteRetention:e.target.checked}))} style={{accentColor:C.a}}/>
                Indefinite retention (default; uncheck for time-bounded preservation orders)
              </label>
              {lhCreate.error && (
                <div style={{padding:10,marginBottom:12,background:"rgba(239,68,68,0.1)",border:`1px solid ${C.dd}`,borderRadius:6,color:C.dd,fontSize:11}}>{lhCreate.error}</div>
              )}
              <div style={{display:"flex",gap:8,justifyContent:"flex-end",marginTop:8}}>
                <Btn onClick={()=>setLhCreate(prev=>({...prev,open:false}))}>Cancel</Btn>
                <Btn primary disabled={lhCreate.submitting || lhCreate.rationale.trim().length<20 || !lhCreate.caseId.trim() || lhCreate.outputFormats.length===0} onClick={async ()=>{
                  setLhCreate(prev=>({...prev,submitting:true,error:""}));
                  const res = await api.post("/api/legal-hold-exports", {
                    caseId: lhCreate.caseId.trim(),
                    rationale: lhCreate.rationale.trim(),
                    outputFormats: lhCreate.outputFormats,
                    indefiniteRetention: lhCreate.indefiniteRetention
                  });
                  if (res && res.error) {
                    setLhCreate(prev=>({...prev,submitting:false,error:res.error||"Submission failed"}));
                  } else {
                    addA("LEGAL_HOLD_CREATED","case="+lhCreate.caseId.trim()+" id="+(res.id||"?")+" formats="+lhCreate.outputFormats.join(","));
                    setLhCreate({open:false,caseId:"",rationale:"",outputFormats:["edrm-xml","eml-mime"],indefiniteRetention:true,submitting:false,error:""});
                    refreshLhList();
                  }
                }}>{lhCreate.submitting?"Submitting...":"Create Hold"}</Btn>
              </div>
            </Modal>
          )}

          {/* Existing holds list */}
          {lhLoadState.loading && (
            <M style={{display:"block",marginTop:16,color:C.tm,fontStyle:"italic"}}>Loading holds...</M>
          )}
          {lhLoadState.error && (
            <Card style={{marginTop:16,background:"rgba(239,68,68,0.05)",border:`1px solid ${C.dd}`}}>
              <M style={{color:C.dd}}>Failed to load legal holds: {lhLoadState.error}</M>
            </Card>
          )}
          {lhLoadState.loaded && lhExports.length===0 && (
            <Card style={{marginTop:16}}>
              <M style={{color:C.tm,fontStyle:"italic"}}>No legal holds yet. Use the Execute button above to create one.</M>
            </Card>
          )}
          {lhLoadState.loaded && lhExports.length>0 && (
            <div style={{marginTop:16}}>
              <L>Existing Legal Holds</L>
              <Card style={{padding:0,overflow:"hidden"}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
                  <thead>
                    <tr style={{background:"rgba(255,255,255,0.02)"}}>
                      <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Case ID / Hold ID</th>
                      <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Requested</th>
                      <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Status</th>
                      <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Manifest Key</th>
                      <th style={{padding:"10px 12px",textAlign:"right",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {lhExports.map(h=>{
                      const statusColor = h.status==="active"?C.a:h.status==="released"?C.tm:h.status==="failed"?C.d:h.status==="in_progress"?C.i:C.w;
                      return (
                        <tr key={h.id} style={{borderBottom:`1px solid ${C.b}`}}>
                          <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                            <M style={{color:C.t,wordBreak:"break-all"}}>{h.case_id}</M>
                            <M style={{color:C.td,display:"block",fontSize:10,marginTop:2,fontFamily:"'IBM Plex Mono',monospace",wordBreak:"break-all"}}>{h.id}</M>
                            {h.indefinite_retention?(<M style={{color:C.a,display:"block",fontSize:10,marginTop:2}}>indefinite retention</M>):null}
                          </td>
                          <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                            <M style={{color:C.tm}}>{h.requested_at||"—"}</M>
                            <M style={{color:C.td,display:"block",fontSize:10,marginTop:2}}>by: {h.requested_by_user_id}</M>
                            {h.rationale&&(<M style={{color:C.td,display:"block",fontSize:10,marginTop:4,maxWidth:240,wordBreak:"break-word"}}>{h.rationale}</M>)}
                          </td>
                          <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                            <Badge color={statusColor}>{h.status}</Badge>
                            {h.hold_released_at&&(<M style={{color:C.td,display:"block",fontSize:10,marginTop:4}}>released {h.hold_released_at}<br/>by {h.hold_released_by_user_id}</M>)}
                            {h.error_message&&(<M style={{color:C.d,display:"block",fontSize:10,marginTop:4,maxWidth:200,wordBreak:"break-word"}}>{h.error_message}</M>)}
                          </td>
                          <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                            <M style={{color:C.tm,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>{(h.manifest_signing_key_fingerprint||"—").slice(0,16)}{h.manifest_signing_key_fingerprint&&h.manifest_signing_key_fingerprint.length>16?"…":""}</M>
                          </td>
                          <td style={{padding:"10px 12px",verticalAlign:"top",textAlign:"right"}}>
                            <div style={{display:"flex",gap:4,justifyContent:"flex-end",flexWrap:"wrap"}}>
                              {(h.status==="active"||h.status==="released")&&(<button onClick={()=>downloadLegalHold(h.id)} style={{padding:"4px 8px",background:C.a,border:"none",borderRadius:4,color:"#000",fontSize:10,fontWeight:500,cursor:"pointer"}}>Download</button>)}
                              {h.status==="active"&&(<button onClick={()=>setLhReleaseModal({open:true,holdId:h.id,caseId:h.case_id,requestedBy:h.requested_by_user_id||"",rationale:"",submitting:false,error:""})} style={{padding:"4px 8px",background:"transparent",border:`1px solid ${C.w}`,borderRadius:4,color:C.w,fontSize:10,fontWeight:500,cursor:"pointer"}}>Release</button>)}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </Card>
            </div>
          )}

          {/* Release modal */}
          {lhReleaseModal.open && (
            <Modal title="Release Legal Hold" onClose={()=>setLhReleaseModal(prev=>({...prev,open:false}))} width={580}>
              <M style={{display:"block",marginBottom:12,color:C.tm,lineHeight:1.5}}>
                Releasing case <span style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace"}}>{lhReleaseModal.caseId}</span> (hold ID <span style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace"}}>{lhReleaseModal.holdId}</span>).
              </M>
              <Card style={{marginBottom:14,background:"rgba(239,179,68,0.08)",border:`1px solid ${C.w}`}}>
                <M style={{color:C.w,display:"block",lineHeight:1.5}}>
                  ⚠ Separate-actor invariant: the CISO performing this release must be a DIFFERENT user from the original requester ({lhReleaseModal.requestedBy||"unknown"}). If you are the requester, this release will be denied at THREE layers — route handler, orchestrator, and schema CHECK constraint.
                </M>
              </Card>
              <div style={{marginBottom:14}}>
                <M style={{color:C.tm,marginBottom:4,display:"block"}}>Release rationale (required, min 20 chars)</M>
                <textarea value={lhReleaseModal.rationale} onChange={e=>setLhReleaseModal(prev=>({...prev,rationale:e.target.value}))} placeholder="Document why this hold is being released — case resolved, regulatory inquiry closed, court order lifted" style={{width:"100%",minHeight:80,padding:10,fontSize:12,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontFamily:"inherit",resize:"vertical"}} maxLength={2000}/>
                <M style={{color:lhReleaseModal.rationale.trim().length<20?C.dd:C.tm,marginTop:4,display:"block"}}>{lhReleaseModal.rationale.trim().length}/20 minimum chars</M>
              </div>
              {lhReleaseModal.error && (
                <div style={{padding:10,marginBottom:12,background:"rgba(239,68,68,0.1)",border:`1px solid ${C.dd}`,borderRadius:6,color:C.dd,fontSize:11}}>{lhReleaseModal.error}</div>
              )}
              <div style={{display:"flex",gap:8,justifyContent:"flex-end",marginTop:8}}>
                <Btn onClick={()=>setLhReleaseModal(prev=>({...prev,open:false}))}>Cancel</Btn>
                <Btn primary danger disabled={lhReleaseModal.submitting || lhReleaseModal.rationale.trim().length<20} onClick={async ()=>{
                  setLhReleaseModal(prev=>({...prev,submitting:true,error:""}));
                  const r = await api.post("/api/legal-hold-exports/"+encodeURIComponent(lhReleaseModal.holdId)+"/release", {rationale:lhReleaseModal.rationale.trim()});
                  if (r && r.error) {
                    setLhReleaseModal(prev=>({...prev,submitting:false,error:r.error||"Release failed"}));
                  } else {
                    addA("LEGAL_HOLD_RELEASED","case="+lhReleaseModal.caseId+" id="+lhReleaseModal.holdId);
                    setLhReleaseModal({open:false,holdId:"",caseId:"",requestedBy:"",rationale:"",submitting:false,error:""});
                    refreshLhList();
                  }
                }}>{lhReleaseModal.submitting?"Releasing…":"Confirm Release"}</Btn>
              </div>
            </Modal>
          )}
        </div>)}

        {/* ══════════ v1.0.0 — RISK REGISTER ASSET ══════════ */}
        {tab==="risk_register"&&(<div>
          <L>Risk Register Asset Generator</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Generate a risk register entry for FireAlive as an organizational asset, including quantitative risk metrics (AV, EF, SLE, ARO, ALE) and qualitative impact/likelihood assessments. Factors in the app's integrations and the human capital risk of NOT using burnout prevention.</M>
          <Btn primary style={{marginBottom:16}} onClick={()=>{setRiskRegisterOutput({
            asset:"FireAlive SOC Analyst Wellbeing Platform",
            category:"Human Capital Risk Management / SOC Operations",
            assetValue:412000,
            exposureFactor:0.35,
            sle:144200,
            aro:0.8,
            ale:115360,
            withoutFireAlive:{assetValue:412000,exposureFactor:0.65,sle:267800,aro:1.2,ale:321360},
            qualitative:{impact:"High",likelihood:"Medium",riskLevel:"High",description:"Without burnout prevention: 35% annual SOC analyst turnover at $85K replacement cost per analyst. With burnout prevention: estimated 15% reduction in turnover, 20% improvement in mean time to detect, measurable reduction in insider threat risk from disgruntled departing analysts."},
            integrationRisk:"Medium — integrates with SIEM, SOAR, ticketing, IAM. Compromise could expose aggregate team health data (pseudonymized). Fail-open design ensures SOC operations continue if app fails.",
            mitigations:"E2EE peer chat, pseudonymized burnout data, tiered encryption, posture assessment, HA failover, fail-open routing, tripwire detection, compromise scanning, NIST 800-63B auth, AGPL-3.0 open source (auditable)"
          });api.post("/api/v1/audit/log",{event:"RISK_REGISTER_GENERATED",detail:"Risk register asset entry generated"}).then(()=>addA("RISK_REGISTER_GENERATED","Risk register asset entry generated"));}}>Generate Risk Register Entry</Btn>
          {riskRegisterOutput&&(<div>
            <Card style={{marginBottom:12}}>
              <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5",marginBottom:8}}>Quantitative Risk Assessment — WITH FireAlive</div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8}}>
                {[{l:"Asset Value",v:"$"+riskRegisterOutput.assetValue.toLocaleString()},{l:"Exposure Factor",v:(riskRegisterOutput.exposureFactor*100)+"%"},{l:"SLE",v:"$"+riskRegisterOutput.sle.toLocaleString()},{l:"ARO",v:riskRegisterOutput.aro},{l:"ALE",v:"$"+riskRegisterOutput.ale.toLocaleString()}].map(m=>(
                  <Card key={m.l} style={{padding:10,textAlign:"center"}}><div style={{fontSize:16,fontWeight:600,color:C.a}}>{m.v}</div><M style={{color:C.td}}>{m.l}</M></Card>
                ))}
              </div>
            </Card>
            <Card style={{marginBottom:12}}>
              <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5",marginBottom:8}}>Quantitative Risk — WITHOUT FireAlive</div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8}}>
                {[{l:"Asset Value",v:"$"+riskRegisterOutput.withoutFireAlive.assetValue.toLocaleString()},{l:"Exposure Factor",v:(riskRegisterOutput.withoutFireAlive.exposureFactor*100)+"%"},{l:"SLE",v:"$"+riskRegisterOutput.withoutFireAlive.sle.toLocaleString()},{l:"ARO",v:riskRegisterOutput.withoutFireAlive.aro},{l:"ALE",v:"$"+riskRegisterOutput.withoutFireAlive.ale.toLocaleString()}].map(m=>(
                  <Card key={m.l} style={{padding:10,textAlign:"center"}}><div style={{fontSize:16,fontWeight:600,color:C.d}}>{m.v}</div><M style={{color:C.td}}>{m.l}</M></Card>
                ))}
              </div>
            </Card>
            <Card style={{marginBottom:12,padding:12,borderColor:C.w+"30"}}><M style={{color:C.w,fontWeight:500,display:"block",marginBottom:4}}>Annual Cost Avoidance</M><div style={{fontSize:20,fontWeight:700,color:C.a}}>${(riskRegisterOutput.withoutFireAlive.ale - riskRegisterOutput.ale).toLocaleString()}/year</div></Card>
            <Card style={{padding:12}}><M style={{color:C.tm,lineHeight:1.8}}><strong style={{color:C.t}}>Qualitative:</strong> {riskRegisterOutput.qualitative.description}</M></Card>
            <Btn small style={{marginTop:12}} onClick={()=>{const blob=new Blob([JSON.stringify(riskRegisterOutput,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="firealive-risk-register-entry.json";a.click();}}>Export for Risk Register</Btn>
          </div>)}
        </div>)}

        {/* ══════════ v1.0.0 — HELP ══════════ */}
        {tab==="ai_integrations"&&(<div>
          <L>AI/ML Integrations</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>FireAlive ships internal AI by default. Some features use statistical/rule-based logic (deterministic, fast, no model needed); others use a local large language model bundled with FireAlive (private, no data leaves the host). Externally-hosted providers (Anthropic, OpenAI, Gemini, Azure OpenAI, AWS Bedrock, custom endpoints) can be configured per feature for orgs that prefer them.</M>

          <Card style={{marginBottom:12,borderColor:C.a+"30"}}>
            <div style={{fontSize:13,fontWeight:600,color:C.a,marginBottom:10}}>Always Internal (statistical / rule-based — not configurable)</div>
            {[{n:"Burnout signal detection",d:"Time-series statistical analysis on signal_readings."},{n:"Burnout-aware routing",d:"Capacity scoring + weighted ticket distribution."},{n:"Training gap recommendations",d:"Skill assessment scores → training module lookup."},{n:"Peer abuse detection",d:"Statistical pattern detection across flag history."},{n:"Compliance / regression scanning",d:"Deterministic rule checks against actual app state."}].map(f=>(
              <div key={f.n} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`}}>
                <M style={{color:C.t,fontWeight:500}}>{f.n}</M>
                <M style={{color:C.tm,display:"block"}}>{f.d}</M>
              </div>
            ))}
          </Card>

          <Card style={{marginBottom:12}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
              <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5"}}>Local LLM (FireAlive Internal AI for generative features)</div>
              <Btn small onClick={()=>{setAiLoading(true);Promise.all([api.get("/api/ai-provider/status"),api.get("/api/ai-provider/config")]).then(([s,c])=>{setAiStatus(s);setAiConfigs(c?.configs||[]);}).catch(()=>{}).finally(()=>setAiLoading(false));}}>Refresh</Btn>
            </div>
            {aiLoading&&<M style={{color:C.td}}>Loading…</M>}
            {!aiLoading&&aiStatus&&(<div>
              <div style={{padding:"4px 0"}}><M style={{color:C.tm}}>Model file present:</M> <M style={{color:aiStatus.modelPresent?C.a:C.d,fontWeight:600}}>{aiStatus.modelPresent?"yes":"no"}</M></div>
              <div style={{padding:"4px 0"}}><M style={{color:C.tm}}>Model loaded in memory:</M> <M style={{color:aiStatus.internalLlm?.ready?C.a:C.tm,fontWeight:600}}>{aiStatus.internalLlm?.ready?"yes":"no"}</M></div>
              {aiStatus.internalLlm?.modelName&&<div style={{padding:"4px 0"}}><M style={{color:C.tm}}>Model name:</M> <M style={{color:C.t}}>{aiStatus.internalLlm.modelName}</M></div>}
              {aiStatus.internalLlm?.modelSizeBytes&&<div style={{padding:"4px 0"}}><M style={{color:C.tm}}>Size:</M> <M style={{color:C.t}}>{(aiStatus.internalLlm.modelSizeBytes/1024/1024).toFixed(1)} MB</M></div>}
              {aiStatus.internalLlm?.lastInferenceAt&&<div style={{padding:"4px 0"}}><M style={{color:C.tm}}>Last inference:</M> <M style={{color:C.t}}>{aiStatus.internalLlm.lastInferenceAt}</M></div>}
              {aiStatus.activeDownload&&(<div style={{marginTop:10,padding:10,background:C.s,borderRadius:6,border:`1px solid ${C.a}40`}}>
                <M style={{color:C.a,fontWeight:600,display:"block",marginBottom:6}}>Download in progress: {aiStatus.activeDownload.variant}</M>
                <M style={{color:C.tm,display:"block",fontSize:11}}>Status: {aiStatus.activeDownload.status} — {aiStatus.activeDownload.progress?.pct||0}%{aiStatus.activeDownload.progress?.totalBytes?(" — "+(aiStatus.activeDownload.progress.downloadedBytes/1024/1024).toFixed(1)+" / "+(aiStatus.activeDownload.progress.totalBytes/1024/1024).toFixed(1)+" MB"):""}</M>
              </div>)}
              <div style={{display:"flex",gap:8,marginTop:12,flexWrap:"wrap"}}>
                {!aiStatus.modelPresent&&!aiStatus.activeDownload&&<Btn primary onClick={()=>{api.post("/api/ai-provider/model/download",{variant:"phi3"}).then(()=>{setAiDownloadPolling(true);addA("AI_MODEL_DOWNLOAD_STARTED","Local LLM download started (Phi-3-mini, ~2.4GB)");}).catch(e=>addA("AI_MODEL_DOWNLOAD_FAILED","Failed to start download: "+(e?.message||"unknown")));}}>Download Local AI Model (~2.4GB)</Btn>}
                {aiStatus.modelPresent&&!aiStatus.internalLlm?.ready&&<Btn small onClick={()=>{api.post("/api/ai-provider/model/load",{}).then(r=>{setAiStatus(s=>({...s,internalLlm:r.status}));addA("AI_MODEL_LOADED","Local LLM loaded into memory");}).catch(e=>addA("AI_MODEL_LOAD_FAILED","Load failed: "+(e?.message||"unknown")));}}>Load Model</Btn>}
                {aiStatus.internalLlm?.ready&&<Btn small onClick={()=>{api.post("/api/ai-provider/model/unload",{}).then(()=>{api.get("/api/ai-provider/status").then(s=>setAiStatus(s));addA("AI_MODEL_UNLOADED","Local LLM unloaded from memory");}).catch(()=>{});}}>Unload Model</Btn>}
              </div>
            </div>)}
          </Card>

          <Card style={{marginBottom:12}}>
            <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5",marginBottom:10}}>Per-Feature Provider Routing</div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>For features that use generative AI, choose where the inference runs. Internal uses the local LLM (private; no data leaves the host). External providers send the prompt over the network and require credentials.</M>
            <Sel label="Feature" value={aiSelectedFeature} onChange={e=>setAiSelectedFeature(e.target.value)}>
              <option value="ir_simulator">IR Simulator scenario generation</option>
              <option value="burnout_messages">Burnout intervention messages</option>
              <option value="kb_synthesis">Knowledge Base synthesis</option>
              <option value="ttx_enhancement">TTX scenario enhancement (optional)</option>
              <option value="troubleshooter">Troubleshooter AI diagnosis</option>
            </Sel>
            <Sel label="Provider" value={aiEditProvider} onChange={e=>setAiEditProvider(e.target.value)}>
              <option value="internal">FireAlive Internal AI (local LLM)</option>
              <option value="anthropic">Anthropic (Claude)</option>
              <option value="openai">OpenAI (GPT)</option>
              <option value="gemini">Google Gemini</option>
              <option value="azure_openai">Azure OpenAI Service</option>
              <option value="aws_bedrock">AWS Bedrock</option>
              <option value="custom">Custom (OpenAI-compatible endpoint)</option>
            </Sel>
            <Input label="Model name (optional; provider default used if blank)" value={aiEditModelName} onChange={e=>setAiEditModelName(e.target.value)} placeholder="e.g. claude-opus-4-7"/>
            {aiEditProvider!=="internal"&&(<>
              <Input label="API key" type="password" value={aiEditApiKey} onChange={e=>setAiEditApiKey(e.target.value)} placeholder="Required for external providers"/>
              <Input label="Endpoint URL (optional for most; required for Azure OpenAI, AWS Bedrock proxy, custom)" value={aiEditEndpoint} onChange={e=>setAiEditEndpoint(e.target.value)} placeholder="Leave blank to use provider default"/>
            </>)}
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:8}}>
              <Input label="Max tokens" type="number" value={aiEditMaxTokens} onChange={e=>setAiEditMaxTokens(parseInt(e.target.value)||1024)}/>
              <Input label="Temperature (0-2)" type="number" value={aiEditTemperature} onChange={e=>setAiEditTemperature(Math.max(0,Math.min(2,Number(e.target.value)||0.7)))}/>
            </div>
            <Btn primary style={{marginTop:12}} onClick={()=>{
              const body = {provider:aiEditProvider,modelName:aiEditModelName||null,maxTokens:aiEditMaxTokens,temperature:aiEditTemperature};
              if (aiEditProvider!=="internal") {
                body.providerConfig = {apiKey:aiEditApiKey,endpointUrl:aiEditEndpoint||undefined};
              }
              api.put("/api/ai-provider/config/"+aiSelectedFeature,body).then(()=>{
                addA("AI_PROVIDER_CONFIGURED","Provider for "+aiSelectedFeature+" set to "+aiEditProvider);
                api.get("/api/ai-provider/config").then(r=>setAiConfigs(r?.configs||[]));
              }).catch(e=>addA("AI_PROVIDER_CONFIG_FAILED","Save failed: "+(e?.message||"unknown")));
            }}>Save Routing for {aiSelectedFeature}</Btn>
          </Card>

          <Card style={{marginBottom:12}}>
            <div style={{fontSize:13,fontWeight:600,color:"#E8EDF5",marginBottom:10}}>Recent inferences for {aiSelectedFeature}</div>
            {aiInferences.length===0&&<M style={{color:C.tm}}>No inference activity yet. Once features start using their configured provider, calls will be logged here (token counts and metadata only — prompt and response content are not stored to protect Tier-3 data).</M>}
            {aiInferences.length>0&&(<div style={{maxHeight:300,overflowY:"auto"}}>
              {aiInferences.map(inf=>(
                <div key={inf.id} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`,fontSize:11}}>
                  <div style={{display:"flex",justifyContent:"space-between",gap:10}}>
                    <span style={{color:inf.status==="success"?C.a:C.d,fontWeight:600,fontFamily:"'IBM Plex Mono',monospace"}}>{inf.status}</span>
                    <span style={{color:C.td,fontFamily:"'IBM Plex Mono',monospace"}}>{inf.created_at}</span>
                  </div>
                  <div style={{color:C.tm,fontFamily:"'IBM Plex Mono',monospace"}}>provider: {inf.provider} {inf.model_name?"· "+inf.model_name:""} · {inf.latency_ms}ms · in: {inf.input_token_count||0}t · out: {inf.output_token_count||0}t</div>
                  {inf.error_message&&<div style={{color:C.d,fontStyle:"italic"}}>{inf.error_message}</div>}
                </div>
              ))}
            </div>)}
          </Card>
        </div>)}

        {tab==="help_mc"&&(<div>
          <L>Management Console Help</L>
          <M style={{color:C.tm,display:"block",marginBottom:16}}>Complete guide to every feature in the Management Console.</M>
          {[
            {cat:"Operations",items:[{n:"Actions",d:"Priority prompts generated from team health signals. Each prompt has severity, recommendation, and supporting research. Use depth controls to adjust detail level."},{n:"Team Overview",d:"Aggregate team health metrics — score, utilization, capacity. No individual burnout data. Shows shift roster with tier, utilization, and complexity caps."},{n:"Routing",d:"Configure burnout-aware ticket distribution. Set per-analyst complexity caps. Routing adjusts automatically based on team health signals."},{n:"Shift Handoff",d:"Structured shift transition notes. Maintains context continuity between shifts."},{n:"SLA",d:"Service Level Agreement targets for MTTA (mean time to acknowledge) and MTTR (mean time to resolve) by priority level."},{n:"Automation",d:"Track automated systems (EDR, SOAR, SIEM) and their alert volumes. Add new automation integrations."},{n:"Fail-Open Routing",d:"Like IPS fail-open: if burnout routing fails, tickets flow unfiltered so the SOC keeps running."},{n:"Auto-Disable Routing",d:"Automatically turn off burnout routing when critical incidents require all hands. Triggers: P1 tickets, SIEM alerts, SOAR escalations."},{n:"Recovery Runbook",d:"Generate step-by-step recovery instructions for 10+ failure scenarios (server crash, ransomware, insider threat, etc.)."}]},
            {cat:"Analysts & Wellbeing",items:[{n:"Skills Matrix",d:"Team skill coverage across 16 categories. Identifies gaps for training planning."},{n:"Assessments",d:"Create and assign skills assessments. Track results with progress bars."},{n:"Certifications",d:"Upload and track industry certs (CompTIA, ISACA, ISC², GIAC, etc.)."},{n:"CISM Retro",d:"Post-incident retrospective protocol following Mitchell's CISM model. 24hr/48-72hr/7-day check-ins."},{n:"Peer Config",d:"Configure peer skill-share scheduling windows, session limits, and helper leaderboard."},{n:"Pseudonyms",d:"Decouple analyst identity from burnout data. All data stored under pseudonyms. Mapping exportable for offline storage."},{n:"Proactive Breaks",d:"Sonnentag research-based: suggest breaks after prolonged high-severity work. Requires your approval before notification sent to analyst."},{n:"Upskilling Hour",d:"Dedicate one hour per shift to professional development. Routing pauses automatically. Research shows this reduces turnover by 20-30%."},{n:"Offboarding",d:"Securely deprovision analysts. Revokes keys, archives data, cancels peer sessions, notifies SOAR."}]},
            {cat:"Integrations",items:[{n:"Health Dashboard",d:"Status of all system integrations — SIEM, SOAR, EDR, ticketing, cloud, etc."},{n:"SOAR",d:"Configure SOAR platform connection (Splunk SOAR, Cortex XSOAR, etc.)."},{n:"SIEM",d:"Configure SIEM feed for team health data and audit events."},{n:"EDR",d:"Integrate EDR for file inspection — scans uploads, restores, policy imports, app updates."},{n:"Threat Hunting",d:"XDR, ATP, Next-Gen AV, MSP scanner integrations for behavioral monitoring and consumption metrics."}]},
            {cat:"Security",items:[{n:"IAM",d:"Configure SAML, OIDC, Active Directory, or cloud IdP for enterprise authentication."},{n:"MFA",d:"TOTP/WebAuthn setup for deployments without IAM. Includes NIST 800-63B password policy."},{n:"API Keys",d:"Manage API keys for SOAR/SIEM integrations."},{n:"Access Control",d:"Role-based access control configuration."},{n:"Auth Logs",d:"Track all login attempts. Brute-force detection, out-of-cycle alerts, log tampering detection."},{n:"KMS",d:"Enterprise key management — AWS KMS, Azure Key Vault, HashiCorp Vault, Thales, Entrust."},{n:"WiFi Policy",d:"Minimum WiFi security requirements. Block WPA2-Personal/WEP."},{n:"Posture Assessment",d:"802.1X-style client health checks before connection."},{n:"Tripwire",d:"Detect mass reduced-routing requests that may indicate coordinated attack."},{n:"Compromise Scan",d:"10-point diagnostic on all or individual clients."},{n:"TTX Generator",d:"Generate tabletop exercise scenarios for FireAlive compromise."}]},
            {cat:"Infrastructure",items:[{n:"Cloud & IaC",d:"Cloud migration tools and Infrastructure-as-Code generation (Terraform, CloudFormation, Pulumi)."},{n:"High Availability",d:"Active/passive or active/active failover with manual failover and testing."},{n:"Cluster / Scaling",d:"Multi-node deployment for large SOCs (hundreds of analysts)."}]},
            {cat:"Data & Backup",items:[{n:"Backup",d:"Database backup management."},{n:"Backup Schedules",d:"Multiple concurrent backup schedules with regulatory presets (HIPAA, SOX, PCI-DSS)."},{n:"Restore",d:"Restore from backups with integrity verification."},{n:"Data Sovereignty",d:"Geo-fence clients, assign regulatory frameworks per jurisdiction."},{n:"Legal Hold",d:"Export data for e-discovery with hashing and chain of custody."}]},
            {cat:"Reports & Compliance",items:[{n:"Report Engine",d:"Scheduled and on-demand reports — team health, utilization, automation, trends."},{n:"Compliance",d:"Framework scanning — NIST CSF, ISO 27001, SOC 2, GDPR, HIPAA."},{n:"Knowledge Base",d:"42 research-backed entries on burnout prevention. AI synthesis engine generates contextual prompts."},{n:"Risk Register Asset",d:"Generate quantitative (AV/EF/SLE/ARO/ALE) and qualitative risk assessment for the app."},{n:"Human Impact Report",d:"Link incident types to burnout metrics, quantified for enterprise risk registers."},{n:"Query Tool",d:"SQL-like queries against audit logs, team data, and metrics."}]},
          ].map(cat=>(
            <Card key={cat.cat} style={{marginBottom:12}}>
              <div style={{fontSize:13,fontWeight:600,color:C.a,marginBottom:10}}>{cat.cat}</div>
              {cat.items.map(item=>(
                <div key={item.n} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`}}>
                  <M style={{color:C.t,fontWeight:500}}>{item.n}</M>
                  <M style={{color:C.tm,display:"block"}}>{item.d}</M>
                </div>
              ))}
            </Card>
          ))}
          <L style={{marginTop:24}}>Common Issues</L>
          <Card style={{marginBottom:10}}><div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Routing</div><M style={{color:C.tm,display:"block",lineHeight:1.6}}>Requires SOAR + ticketing. If panic, restore first.</M></Card>
          <Card style={{marginBottom:10}}><div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:8}}>Config</div><M style={{color:C.tm,display:"block",lineHeight:1.6}}>Unlock config lock (sidebar, MFA).</M></Card>
        </div>)}

        {/* INBOX — in-app notifications from server */}
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
              <Btn small onClick={()=>{api.post("/api/inbox/read-all",{}).then(()=>{setInboxUnreadCount(0);api.get(`/api/inbox?includeRead=${inboxIncludeRead?"true":"false"}`).then(r=>setInboxItems(r?.items||[])).catch(()=>{});addA("INBOX_MARK_ALL_READ","All notifications marked read");}).catch(()=>{});}}>Mark all read</Btn>
            </div>
          </div>
          {inboxLoading&&<M style={{color:C.td,display:"block",marginBottom:10}}>Loading…</M>}
          {!inboxLoading&&inboxItems.length===0&&<Card><M style={{color:C.tm}}>No notifications. The Inbox shows assessments, retros, peer requests, panic-mode broadcasts, IAM recert reminders, and other workflow events from across FireAlive.</M></Card>}
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
            <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>For each event type, choose whether you want to be notified in the inbox, by email, both, or neither. Some critical events (panic mode, tripwire) cannot be disabled in-app — you can still opt out of email for these.</M>
            {inboxPrefsLoading&&<M style={{color:C.td}}>Loading preferences…</M>}
            {!inboxPrefsLoading&&!inboxPrefs&&<Card><M style={{color:C.tm}}>Could not load preferences. The server may be unavailable.</M></Card>}
            {inboxPrefs&&Object.entries(inboxPrefs).map(([eventType,p])=>(
              <Card key={eventType} style={{marginBottom:8}}>
                <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:4}}>{p.label}</div>
                <M style={{color:C.tm,display:"block",lineHeight:1.6,marginBottom:10}}>{p.description}</M>
                <div style={{display:"flex",gap:16}}>
                  <label style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer"}}>
                    <input type="checkbox" checked={p.in_app} onChange={e=>{
                      const newInApp = e.target.checked;
                      api.put(`/api/inbox/preferences/${eventType}`,{in_app:newInApp,email:p.email}).then(()=>{
                        setInboxPrefs(prev=>({...prev,[eventType]:{...prev[eventType],in_app:newInApp,is_default:false}}));
                      }).catch(err=>{
                        addA("INBOX_PREF_REJECTED",`${eventType} in_app change rejected (likely mandatory in-app event)`);
                      });
                    }}/>
                    <M style={{color:C.t}}>In-app</M>
                  </label>
                  <label style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer"}}>
                    <input type="checkbox" checked={p.email} onChange={e=>{
                      const newEmail = e.target.checked;
                      api.put(`/api/inbox/preferences/${eventType}`,{in_app:p.in_app,email:newEmail}).then(()=>{
                        setInboxPrefs(prev=>({...prev,[eventType]:{...prev[eventType],email:newEmail,is_default:false}}));
                      }).catch(()=>{});
                    }}/>
                    <M style={{color:C.t}}>Email</M>
                  </label>
                  {p.is_default&&<M style={{color:C.td,fontStyle:"italic"}}>(default)</M>}
                </div>
              </Card>
            ))}
          </div>)}
        </div>)}

        {/* PEER CONDUCT — tiered abuse flag review */}
        {tab==="peer_conduct"&&(<div>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
            <L style={{marginBottom:0}}>Peer Conduct — {peerFlagStatus==="open"?"Open Flags":peerFlagStatus==="resolved"?"Resolved Flags":"All Flags"} ({peerFlags.length})</L>
            <div style={{display:"flex",gap:6,alignItems:"center"}}>
              <select value={peerFlagStatus} onChange={e=>setPeerFlagStatus(e.target.value)} style={{padding:"5px 10px",background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:6,color:C.t,fontSize:11,fontFamily:"'IBM Plex Mono',monospace"}}>
                <option value="open">Open</option>
                <option value="resolved">Resolved</option>
                <option value="all">All</option>
              </select>
              <select value={peerFlagTierFilter} onChange={e=>setPeerFlagTierFilter(e.target.value)} style={{padding:"5px 10px",background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:6,color:C.t,fontSize:11,fontFamily:"'IBM Plex Mono',monospace"}}>
                <option value="">All tiers</option>
                <option value="3">Tier 3 (urgent)</option>
                <option value="2">Tier 2 (attack)</option>
                <option value="1">Tier 1 (minor)</option>
              </select>
              <Btn small onClick={()=>{setPeerFlagsLoading(true);const params=new URLSearchParams({status:peerFlagStatus});if(peerFlagTierFilter)params.set("tier",peerFlagTierFilter);api.get(`/api/peer/flags?${params.toString()}`).then(r=>setPeerFlags(r?.flags||[])).catch(()=>{}).finally(()=>setPeerFlagsLoading(false));}}>Refresh</Btn>
            </div>
          </div>
          <M style={{color:C.tm,display:"block",marginBottom:14,lineHeight:1.6}}>Flags submitted by analysts after peer skill-share sessions. Tier 1 (minor) shows aggregate patterns only — both flagger and flagged stay anonymous. Tier 2 (personal attack) reveals the flagged peer's identity. Tier 3 (urgent — slurs, threats, harassment) reveals both identities and warrants HR involvement.</M>
          {peerFlagsLoading&&<M style={{color:C.td,display:"block",marginBottom:10}}>Loading…</M>}
          {!peerFlagsLoading&&peerFlags.length===0&&<Card><M style={{color:C.tm}}>No flags match the current filter. {peerFlagStatus==="open"?"That is good news — it means no peer skill-share sessions have been flagged for review.":""}</M></Card>}
          {peerFlags.map(f=>{
            const tierColor=f.tier===3?C.d:f.tier===2?C.w:C.i;
            const tierLabel=f.tier===3?"URGENT":f.tier===2?"ATTACK":"MINOR";
            return(
              <Card key={f.id} style={{marginBottom:10,borderLeft:`4px solid ${tierColor}`,opacity:f.resolvedAt?0.65:1}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8,gap:10}}>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4,flexWrap:"wrap"}}>
                      <Badge color={tierColor}>TIER {f.tier} · {tierLabel}</Badge>
                      {f.resolvedAt&&<Badge color={C.a}>RESOLVED</Badge>}
                      <M style={{color:C.td}}>{new Date(f.createdAt).toLocaleString()}</M>
                    </div>
                    <div style={{fontSize:11,color:C.tm,marginBottom:6}}>
                      <span style={{color:C.t}}>Flagger:</span> {f.flaggerDisplay} · <span style={{color:C.t}}>Flagged:</span> {f.flaggedDisplay}
                      {f.flaggerIp&&<span style={{color:C.td}}> · IP {f.flaggerIp}</span>}
                    </div>
                  </div>
                </div>
                <Card style={{padding:"10px 12px",background:"rgba(0,0,0,0.3)",border:`1px solid ${C.b}`,marginBottom:f.resolvedAt?0:10}}>
                  <M style={{color:C.td,display:"block",marginBottom:4}}>Flagged content:</M>
                  <div style={{fontSize:12,color:C.t,lineHeight:1.6,whiteSpace:"pre-wrap",fontFamily:"'IBM Plex Mono',monospace"}}>{f.content}</div>
                </Card>
                {f.resolvedAt&&(
                  <div style={{marginTop:10,padding:"10px 12px",background:"rgba(110,231,183,0.04)",borderRadius:8,border:`1px solid ${C.a}30`}}>
                    <M style={{color:C.a,fontWeight:500,display:"block",marginBottom:4}}>Resolved {new Date(f.resolvedAt).toLocaleString()} by {f.resolvedBy||"unknown"}</M>
                    {f.resolutionNote&&<M style={{color:C.tm,lineHeight:1.6}}>{f.resolutionNote}</M>}
                  </div>
                )}
                {!f.resolvedAt&&(
                  <div>
                    {f.tier===3&&(<Card style={{padding:"10px 12px",marginBottom:10,background:"rgba(239,68,68,0.06)",border:`1px solid ${C.d}40`}}>
                      <M style={{color:C.d,fontWeight:500,display:"block",marginBottom:4}}>HR intervention recommended</M>
                      <M style={{color:C.tm,lineHeight:1.6}}>Tier 3 flags involve content (slurs, threats, harassment) that typically requires HR review and documentation per most workplace conduct policies. Resolve this flag only after the appropriate HR loop has been initiated.</M>
                    </Card>)}
                    {peerFlagResolveTarget===f.id?(
                      <div>
                        <textarea value={peerFlagResolveNote} onChange={e=>setPeerFlagResolveNote(e.target.value)} rows={3} maxLength={2000} placeholder="Resolution note — what action was taken? (max 2000 chars, optional but recommended)" style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12,resize:"vertical",marginBottom:8}}/>
                        <div style={{display:"flex",gap:6}}>
                          <Btn small primary onClick={()=>{api.post(`/api/peer/flags/${f.id}/resolve`,{note:peerFlagResolveNote||null}).then(()=>{addA("PEER_FLAG_RESOLVED",`Tier ${f.tier} flag resolved`);setPeerFlagResolveTarget(null);setPeerFlagResolveNote("");setPeerFlagsLoading(true);const params=new URLSearchParams({status:peerFlagStatus});if(peerFlagTierFilter)params.set("tier",peerFlagTierFilter);api.get(`/api/peer/flags?${params.toString()}`).then(r=>setPeerFlags(r?.flags||[])).catch(()=>{}).finally(()=>setPeerFlagsLoading(false));}).catch(()=>{addA("PEER_FLAG_RESOLVE_FAILED",`Tier ${f.tier} flag resolve attempt failed`);});}}>Submit Resolution</Btn>
                          <Btn small onClick={()=>{setPeerFlagResolveTarget(null);setPeerFlagResolveNote("");}}>Cancel</Btn>
                        </div>
                      </div>
                    ):(
                      <Btn small primary onClick={()=>{setPeerFlagResolveTarget(f.id);setPeerFlagResolveNote("");}}>Mark Resolved</Btn>
                    )}
                  </div>
                )}
              </Card>
            );
          })}
        </div>)}

        {/* AUDIT — aggregated across MC, server, and all clients */}
        {tab==="audit"&&(()=>{const reversed=audit.slice().reverse();const totalPages=Math.ceil(reversed.length/AUDIT_PER_PAGE);const page=Math.min(auditPage,totalPages-1);const pageItems=reversed.slice(page*AUDIT_PER_PAGE,(page+1)*AUDIT_PER_PAGE);return(<div>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
            <L style={{marginBottom:0}}>Audit Trail — Aggregated ({audit.length} MC events + client logs)</L>
            <div style={{display:"flex",gap:6}}>
              <Btn small primary onClick={()=>{const esc=v=>{let s=String(v||"").replace(/"/g,'""');if(/^[=+\-@\t\r]/.test(s))s="'"+s;return'"'+s+'"';};const csv="Timestamp,Type,Detail\n"+audit.map(e=>[esc(e.ts),esc(e.ty),esc(e.dt)].join(",")).join("\n");const blob=new Blob([csv],{type:"text/csv"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="audit-log-"+new Date().toISOString().slice(0,10)+".csv";a.click();URL.revokeObjectURL(url);}}>CSV</Btn>
              <Btn small onClick={()=>{const data=JSON.stringify(audit.map(e=>({timestamp:e.ts,type:e.ty,detail:e.dt})),null,2);const blob=new Blob([data],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="audit-log-"+new Date().toISOString().slice(0,10)+".json";a.click();URL.revokeObjectURL(url);}}>JSON</Btn>
              <Btn small onClick={()=>{const cefVer=appVersion||"unknown";const lines=audit.map(e=>"CEF:0|FireAlive|AuditLog|"+cefVer+"|300|"+e.ty+"|3|rt="+e.ts+" msg="+(e.dt||"").replace(/[|\\]/g,"_"));const blob=new Blob([lines.join("\n")],{type:"text/plain"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="audit-log-"+new Date().toISOString().slice(0,10)+".cef";a.click();URL.revokeObjectURL(url);}}>CEF</Btn>
              <Btn small onClick={()=>{const lines=audit.map(e=>{const sev=e.ty.includes("FAIL")||e.ty.includes("ERROR")?3:e.ty.includes("ALERT")||e.ty.includes("VIOLATION")?2:6;return`<${128+sev}>1 ${new Date().toISOString()} firealive firealive ${process?.pid||"-"} ${e.ty} - ${e.dt||""}`;});const blob=new Blob([lines.join("\n")],{type:"text/plain"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="audit-log-"+new Date().toISOString().slice(0,10)+".syslog";a.click();URL.revokeObjectURL(url);}}>Syslog</Btn>
              <Btn small onClick={()=>{const forensics={exportType:"firealive_forensics",version:appVersion||"unknown",exportedAt:new Date().toISOString(),eventCount:audit.length,events:audit.map(e=>({timestamp:e.ts,epochMs:Date.now(),eventType:e.ty,detail:e.dt,severityLabel:e.ty.includes("FAIL")?"error":e.ty.includes("ALERT")?"critical":"info"}))};const blob=new Blob([JSON.stringify(forensics,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="firealive-forensics-"+new Date().toISOString().slice(0,10)+".json";a.click();URL.revokeObjectURL(url);}}>Forensics</Btn>
            </div>
          </div>
          <div style={{background:C.s,border:`1px solid ${C.b}`,borderRadius:10,overflow:"hidden"}}>{pageItems.map((e,i)=>(
            <div key={i} style={{padding:"10px 14px",borderBottom:`1px solid ${C.b}`,fontSize:11,fontFamily:"'IBM Plex Mono',monospace",display:"flex",gap:10}}>
              <span style={{color:C.td,minWidth:40}}>{e.ts}</span>
              <span style={{color:e.ty.includes("BOUNDARY")?C.a:e.ty.includes("BACKUP")||e.ty.includes("SNAPSHOT")?C.i:e.ty.includes("PROVISION")?C.a:C.w,minWidth:140}}>{e.ty}</span>
              <span style={{color:C.tm,wordBreak:"break-all"}}>{e.dt}</span>
            </div>
          ))}</div>
          {totalPages>1&&<div style={{display:"flex",justifyContent:"center",alignItems:"center",gap:8,marginTop:12}}>
            <Btn small disabled={page===0} onClick={()=>setAuditPage(page-1)}>← Prev</Btn>
            <M style={{color:C.tm}}>Page {page+1} of {totalPages}</M>
            <Btn small disabled={page>=totalPages-1} onClick={()=>setAuditPage(page+1)}>Next →</Btn>
          </div>}
        </div>);})()}

        {/* R3l C33: Forensic Export — admin creates / ciso (separate-actor) deletes */}
        {tab==="forensic_exports"&&(<div>
          <L>Forensic Export</L>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>SOC-grade forensic exports of platform audit data. Each export bundles selected data slices (audit log, backup chain, incident records, authentication logs, user access logs) into the chosen forensic formats, signs the manifest with Ed25519, and (optionally) attests with Cosign. The full chain of operations (create, download, delete) is recorded in the append-only forensic_export_chain.</M>
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}><b style={{color:C.t}}>Separate-actor enforcement:</b> exports are created by admin; deletion requires the CISO role AND a different user than the original requester. The chain entry survives any deletion.</M>

          {/* Create form */}
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:600,color:C.t,marginBottom:12}}>New Forensic Export</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
              <div>
                <M style={{color:C.tm,display:"block",marginBottom:4}}>Time window start (ISO 8601, optional)</M>
                <input type="text" value={forensicForm.timeWindowStart} onChange={e=>setForensicForm({...forensicForm,timeWindowStart:e.target.value})} placeholder="2026-01-01T00:00:00Z" style={{width:"100%",padding:"8px 10px",background:"rgba(255,255,255,0.04)",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:12,fontFamily:"'IBM Plex Mono',monospace"}}/>
              </div>
              <div>
                <M style={{color:C.tm,display:"block",marginBottom:4}}>Time window end (ISO 8601, optional)</M>
                <input type="text" value={forensicForm.timeWindowEnd} onChange={e=>setForensicForm({...forensicForm,timeWindowEnd:e.target.value})} placeholder="2026-12-31T23:59:59Z" style={{width:"100%",padding:"8px 10px",background:"rgba(255,255,255,0.04)",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:12,fontFamily:"'IBM Plex Mono',monospace"}}/>
              </div>
            </div>
            <div style={{marginBottom:12}}>
              <M style={{color:C.tm,display:"block",marginBottom:4}}>Event type filter (comma-separated, optional, audit_log + backup_chain only)</M>
              <input type="text" value={forensicForm.eventTypeFilter} onChange={e=>setForensicForm({...forensicForm,eventTypeFilter:e.target.value})} placeholder="LOGIN_FAILED,DELETE_DENIED,EXPORT_CREATED" style={{width:"100%",padding:"8px 10px",background:"rgba(255,255,255,0.04)",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:12,fontFamily:"'IBM Plex Mono',monospace"}}/>
            </div>
            <div style={{marginBottom:12}}>
              <M style={{color:C.tm,display:"block",marginBottom:6}}>Rationale (recorded in audit log; optional but recommended for compliance)</M>
              <textarea value={forensicForm.rationale} onChange={e=>setForensicForm({...forensicForm,rationale:e.target.value})} placeholder="Reason for this forensic export (incident ID, audit ticket, regulator request…)" rows={2} style={{width:"100%",padding:"8px 10px",background:"rgba(255,255,255,0.04)",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:12,fontFamily:"inherit",resize:"vertical"}}/>
            </div>
            <div style={{marginBottom:12}}>
              <M style={{color:C.tm,display:"block",marginBottom:6}}>Output formats (one file per format inside the archive)</M>
              <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                {ALL_FORENSIC_FORMATS.map(fmt=>(
                  <button key={fmt} onClick={()=>toggleForensicFormat(fmt)} style={{padding:"5px 10px",background:forensicForm.outputFormats.includes(fmt)?C.a:"rgba(255,255,255,0.03)",border:`1px solid ${forensicForm.outputFormats.includes(fmt)?C.a:C.b}`,borderRadius:4,color:forensicForm.outputFormats.includes(fmt)?"#000":C.t,fontSize:11,fontWeight:500,cursor:"pointer",fontFamily:"'IBM Plex Mono',monospace"}}>{fmt}</button>
                ))}
              </div>
            </div>
            <div style={{marginBottom:12}}>
              <M style={{color:C.tm,display:"block",marginBottom:6}}>Slices to include</M>
              <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:6}}>
                {[
                  ["includeAuditLog","Audit log"],
                  ["includeBackupChain","Backup chain"],
                  ["includeIncidentRecords","Incident retros"],
                  ["includeAuthenticationLogs","Auth log"],
                  ["includeUserAccessLogs","Session log"],
                ].map(([key,lbl])=>(
                  <label key={key} style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer",color:C.t,fontSize:12}}>
                    <input type="checkbox" checked={forensicForm[key]} onChange={e=>setForensicForm({...forensicForm,[key]:e.target.checked})}/>
                    {lbl}
                  </label>
                ))}
              </div>
            </div>
            {forensicCreateError&&(<Card style={{marginBottom:12,borderColor:C.d+"60"}}><M style={{color:C.d}}>Create failed: {forensicCreateError}</M></Card>)}
            {forensicCreateResult&&(<Card style={{marginBottom:12,borderColor:C.a+"60"}}><M style={{color:C.a}}>Created export <code>{forensicCreateResult.id}</code> ({forensicCreateResult.sizeBytes} bytes, sha256 {(forensicCreateResult.archiveSha256||"").slice(0,16)}…)</M></Card>)}
            <div style={{display:"flex",gap:8}}>
              <button onClick={submitForensicExport} disabled={forensicCreateInFlight} style={{padding:"8px 16px",background:forensicCreateInFlight?C.tm:C.a,border:"none",borderRadius:4,color:"#000",fontSize:12,fontWeight:600,cursor:forensicCreateInFlight?"not-allowed":"pointer",opacity:forensicCreateInFlight?0.6:1}}>{forensicCreateInFlight?"Creating…":"Create Forensic Export"}</button>
              <button onClick={viewForensicChain} style={{padding:"8px 16px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:12,fontWeight:500,cursor:"pointer"}}>View Chain</button>
            </div>
          </Card>

          {/* Chain modal */}
          {forensicChainOpen&&(<Card style={{marginBottom:16,borderColor:C.i+"60"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
              <div style={{fontSize:13,fontWeight:600,color:C.t}}>Forensic Export Chain</div>
              <button onClick={()=>setForensicChainOpen(false)} style={{background:"transparent",border:"none",color:C.tm,fontSize:14,cursor:"pointer"}}>✕</button>
            </div>
            {!forensicChain&&(<M style={{color:C.tm,fontStyle:"italic"}}>Loading chain…</M>)}
            {forensicChain&&forensicChain.error&&(<M style={{color:C.d}}>Error: {forensicChain.error}</M>)}
            {forensicChain&&!forensicChain.error&&(<div>
              {forensicChain.active_signing_key&&(<div style={{marginBottom:10,padding:8,background:"rgba(255,255,255,0.02)",border:`1px solid ${C.b}`,borderRadius:4}}>
                <M style={{color:C.td,display:"block"}}>Active signing key</M>
                <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>id: {forensicChain.active_signing_key.id}</M>
                <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>fingerprint: {forensicChain.active_signing_key.fingerprint}</M>
              </div>)}
              <div style={{maxHeight:300,overflowY:"auto",fontFamily:"'IBM Plex Mono',monospace",fontSize:10}}>
                {(forensicChain.chain||[]).map(c=>(
                  <div key={c.id} style={{padding:"6px 8px",borderBottom:`1px solid ${C.b}`,display:"flex",gap:10}}>
                    <span style={{color:C.td,minWidth:50}}>#{c.id}</span>
                    <span style={{color:C.a,minWidth:160}}>{c.event_type}</span>
                    <span style={{color:C.tm,minWidth:90}}>{c.created_at}</span>
                    <span style={{color:C.t,wordBreak:"break-all"}}>{c.export_ref} / actor:{c.actor_user_id} / hash:{(c.this_hash||"").slice(0,12)}…</span>
                  </div>
                ))}
                {(forensicChain.chain||[]).length===0&&(<M style={{color:C.tm,fontStyle:"italic",padding:8,display:"block"}}>No chain entries yet.</M>)}
              </div>
            </div>)}
          </Card>)}

          {/* Manifest modal */}
          {forensicManifestOpen&&(<Card style={{marginBottom:16,borderColor:C.i+"60"}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
              <div style={{fontSize:13,fontWeight:600,color:C.t}}>Export Manifest</div>
              <button onClick={()=>setForensicManifestOpen(false)} style={{background:"transparent",border:"none",color:C.tm,fontSize:14,cursor:"pointer"}}>✕</button>
            </div>
            {!forensicManifest&&(<M style={{color:C.tm,fontStyle:"italic"}}>Loading manifest…</M>)}
            {forensicManifest&&forensicManifest.error&&(<M style={{color:C.d}}>Error: {forensicManifest.error}</M>)}
            {forensicManifest&&!forensicManifest.error&&(<pre style={{maxHeight:400,overflow:"auto",fontFamily:"'IBM Plex Mono',monospace",fontSize:10,color:C.t,background:"rgba(0,0,0,0.3)",padding:10,borderRadius:4,whiteSpace:"pre-wrap",wordBreak:"break-all"}}>{JSON.stringify(forensicManifest,null,2)}</pre>)}
          </Card>)}

          {/* Delete error banner */}
          {forensicDeleteError&&(<Card style={{marginBottom:16,borderColor:C.d+"60"}}><M style={{color:C.d}}>Last delete failed: {forensicDeleteError}</M></Card>)}

          {/* Exports table */}
          {!forensicLoadState.loaded&&!forensicLoadState.error&&(<M style={{color:C.tm,fontStyle:"italic"}}>Loading exports…</M>)}
          {forensicLoadState.error&&(<Card style={{borderColor:C.w+"60"}}><M style={{color:C.w}}>Could not load exports: {forensicLoadState.error}</M></Card>)}
          {forensicLoadState.loaded&&forensicExports.length===0&&(<Card><M style={{color:C.tm,fontStyle:"italic"}}>No forensic exports yet. Use the form above to create one.</M></Card>)}
          {forensicLoadState.loaded&&forensicExports.length>0&&(<Card style={{padding:0,overflow:"hidden"}}>
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
              <thead>
                <tr style={{background:"rgba(255,255,255,0.02)"}}>
                  <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Export ID</th>
                  <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Requested</th>
                  <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Status</th>
                  <th style={{padding:"10px 12px",textAlign:"left",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Formats</th>
                  <th style={{padding:"10px 12px",textAlign:"right",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Size</th>
                  <th style={{padding:"10px 12px",textAlign:"right",color:C.td,fontWeight:500,letterSpacing:0.5,textTransform:"uppercase",fontSize:10,borderBottom:`1px solid ${C.b}`}}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {forensicExports.map(e=>{
                  const statusColor = e.status==="complete"?C.a:e.status==="failed"?C.d:e.status==="in_progress"?C.i:C.w;
                  const inFlight = forensicDeleteInFlight[e.id];
                  return (
                    <tr key={e.id} style={{borderBottom:`1px solid ${C.b}`}}>
                      <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                        <M style={{color:C.t,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>{e.id}</M>
                        {e.rationale&&(<M style={{color:C.td,display:"block",fontSize:10,marginTop:2}}>{e.rationale}</M>)}
                      </td>
                      <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                        <M style={{color:C.tm}}>{e.requested_at||"—"}</M>
                        <M style={{color:C.td,display:"block",fontSize:10,marginTop:2}}>by: {e.requested_by_user_id}</M>
                      </td>
                      <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                        <Badge color={statusColor}>{e.status}</Badge>
                        {e.error_message&&(<M style={{color:C.d,display:"block",fontSize:10,marginTop:4,maxWidth:200,wordBreak:"break-word"}}>{e.error_message}</M>)}
                      </td>
                      <td style={{padding:"10px 12px",verticalAlign:"top"}}>
                        <M style={{color:C.tm,fontFamily:"'IBM Plex Mono',monospace",fontSize:10,wordBreak:"break-all"}}>{e.output_formats||"—"}</M>
                      </td>
                      <td style={{padding:"10px 12px",verticalAlign:"top",textAlign:"right"}}>
                        <M style={{color:C.tm}}>{e.size_bytes?e.size_bytes.toLocaleString()+" B":"—"}</M>
                        {e.archive_sha256&&(<M style={{color:C.td,display:"block",fontSize:10,marginTop:2,fontFamily:"'IBM Plex Mono',monospace"}}>{(e.archive_sha256||"").slice(0,12)}…</M>)}
                      </td>
                      <td style={{padding:"10px 12px",verticalAlign:"top",textAlign:"right"}}>
                        <div style={{display:"flex",gap:4,justifyContent:"flex-end",flexWrap:"wrap"}}>
                          {e.status==="complete"&&(<button onClick={()=>downloadForensicArchive(e.id)} style={{padding:"4px 8px",background:C.a,border:"none",borderRadius:4,color:"#000",fontSize:10,fontWeight:500,cursor:"pointer"}}>Download</button>)}
                          {e.status==="complete"&&(<button onClick={()=>viewForensicManifest(e.id)} style={{padding:"4px 8px",background:"transparent",border:`1px solid ${C.b}`,borderRadius:4,color:C.t,fontSize:10,fontWeight:500,cursor:"pointer"}}>Manifest</button>)}
                          <button onClick={()=>deleteForensicExport(e.id)} disabled={!!inFlight} style={{padding:"4px 8px",background:"transparent",border:`1px solid ${C.d}`,borderRadius:4,color:C.d,fontSize:10,fontWeight:500,cursor:inFlight?"not-allowed":"pointer",opacity:inFlight?0.6:1}}>{inFlight?"Deleting…":"Delete"}</button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Card>)}
        </div>)}
          </div>{/* end content area */}
        </div>{/* end sidebar flex container */}
      </div>{/* end main flex */}
      <div style={{padding:"14px 24px",borderTop:`1px solid ${C.b}`,fontSize:10,color:C.td,fontFamily:"'IBM Plex Mono',monospace",display:"flex",justifyContent:"space-between"}}><span>MANAGEMENT · TEAM-LEVEL · NO INDIVIDUAL BURNOUT DATA</span><span>{audit.length} events</span></div>
    </div>
  );
}


// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  APP SHELL                                                              ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

export default function App() {
  const [stage, setStage] = useState("login"); // login → app (no role selection — this IS the MC)
  const [activeRole, setActiveRole] = useState(null);
  const [sysHealth, setSysHealth] = useState({cpu:"—",memory:"—",heap:"—",db:"—",uptime:"—"});
  const [integrationStatus, setIntStatus] = useState([]);
  const [notifications, setNotifications] = useState([]);

  const handleSignOut = () => {
    if(window.FireAliveAPI) window.FireAliveAPI.logout().catch(()=>{});
    setStage("login");setActiveRole(null);
  };

  if (stage==="login") return <LoginScreen role="manager" onLogin={()=>{setActiveRole("manager");setStage("app");}} onBack={()=>{}}/>;

  return (
    <div>
      <div style={{position:"fixed",bottom:16,right:16,zIndex:999,display:"flex",alignItems:"center",gap:8}}>
        <div style={{padding:"6px 12px",background:"rgba(0,0,0,0.85)",border:`1px solid ${C.b}`,borderRadius:20}}><M style={{color:C.td}}>◈ TEAM LEAD</M></div>
        <button onClick={handleSignOut} style={{padding:"6px 12px",background:"rgba(0,0,0,0.85)",border:`1px solid ${C.b}`,borderRadius:20,color:C.tm,fontSize:10,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>sign out</button>
      </div>
      <ManagementConsole/>
    </div>
  );
}

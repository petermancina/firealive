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
import { createRoot } from "react-dom/client";
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
const API_BASE = window.FIREALIVE_SERVER || 'https://localhost:3000';
const api = {
  _token: null,
  _headers() { return { 'Content-Type': 'application/json', ...(this._token ? { 'Authorization': 'Bearer ' + this._token } : {}) }; },
  // B5f: a fresh per-request proof-of-possession header, bound to this exact
  // method and path (query stripped), signed by the hardware device key in the
  // main process. Returns no header when no key is available; the server then
  // refuses a bound session, which is the correct fail-closed behavior.
  async _popHeader(method, path) {
    try {
      const b = (typeof window !== 'undefined') ? window.firealive : null;
      if (!b || typeof b.invoke !== 'function') return {};
      const res = await b.invoke('device:signPopProof', { method: method, path: String(path).split('?')[0] });
      return (res && res.proof) ? { 'x-fa-device-pop': res.proof } : {};
    } catch (_e) { return {}; }
  },
  async authHeaders(method, path) { return { ...this._headers(), ...(await this._popHeader(method, path)) }; },
  async post(path, data) { try { const r = await fetch(API_BASE + path, { method: 'POST', headers: await this.authHeaders('POST', path), body: JSON.stringify(data) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { return { error: e.message }; } },
  async get(path) { try { const r = await fetch(API_BASE + path, { headers: await this.authHeaders('GET', path) }); return r.ok ? await r.json() : { error: r.statusText }; } catch (e) { return { error: e.message }; } },
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

const CSS = `*{box-sizing:border-box;margin:0;padding:0;}button,select,input,textarea{font-family:inherit;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
@keyframes spin{to{transform:rotate(360deg)}}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.08);border-radius:3px}`;

// ══════════════════════════════════════════════════════════════════════════════
// RESEARCH KNOWLEDGE BASE v2026.05.1 — 50 peer-reviewed entries
// ══════════════════════════════════════════════════════════════════════════════
const RESEARCH_KB = [
  {id:"R001",topic:"intervention",tags:["organizational", "meta-analysis", "exhaustion"],title:"Organizational interventions and occupational burnout: a meta-analysis with focus on exhaustion",finding:"Organizational interventions reduce exhaustion with a pooled effect size d=−0.30 (95% CI −0.42 to −0.18, I²=62%); combined organizational + individual interventions did better (d=−0.54, 95% CI −0.76 to −0.32). Among organizational subtypes, both participatory (d=−0.34) and workload-focused (d=−0.44) interventions reduced exhaustion. Overall evidence quality graded very low.",implication:"Structural changes (workload, scheduling, participatory redesign) are an evidence-based first response; treat magnitude as directional given the low evidence grade.",strength:"strong",cite:"Bes, I., Shoman, Y., Al-Gobari, M., et al. (2023), Int Arch Occup Environ Health, 96(9), 1211–1223",year:2023,summary:"A 2023 meta-analysis of controlled trials (11 articles, 13 studies) found that organizational interventions — changing how the work itself is structured — measurably reduce exhaustion, the core dimension of burnout, with a pooled effect size of d = −0.30 (95% CI −0.42 to −0.18). Interventions combining organizational and individual elements did better still (d = −0.54). Among the organizational subtypes studied, both participatory redesign (d = −0.34) and workload-focused changes (d = −0.44) reduced exhaustion. For a SOC, the evidence-based first move when burnout signals rise is structural — workload, routing, scheduling, and giving analysts a voice in those changes — rather than individual \"fix yourself\" programs alone. (The authors graded the overall evidence quality as very low, so treat the magnitude as directional.)",source:"https://doi.org/10.1007/s00420-023-02009-z"},
  {id:"R002",topic:"intervention",tags:["meta-analysis", "person-directed", "individual", "mental-health"],title:"Job burnout in mental health providers: A meta-analysis of 35 years of intervention research",finding:"Meta-analysis of 35 years (1980–2015) of burnout interventions for mental-health providers (27 samples, 1,894 workers; random-effects, Hedges' g). Interventions had a small overall effect. Person-directed interventions were more effective than organization-focused ones at reducing exhaustion. Job training/education was the most effective organizational type; stress-management workshops were the most common person-directed type.",implication:"Rigorous evidence here finds individual/person-directed interventions can outperform structural ones — support effective individual interventions (training, stress-management) alongside structural levers, not structural-only.",strength:"strong",cite:"Dreison, K.C., Luther, L., Bonfils, K.A., et al. (2018), J Occup Health Psychol, 23(1), 18–30",year:2018,summary:"A meta-analysis of 35 years (1980–2015) of burnout-intervention studies in mental-health providers — 27 samples, 1,894 workers, random-effects with Hedges' g — found interventions had only a small overall effect on burnout. Notably, and contrary to much of the structural-first literature, person-directed interventions were more effective than organization-focused ones at reducing exhaustion in this body of work. Among organizational interventions, job training/education was the most effective type; the most common person-directed approach was the stress-management workshop. The honest takeaway for FireAlive: the evidence is genuinely mixed — some rigorous work finds individual interventions outperforming structural ones — so the platform should support effective individual interventions (skills/training, stress-management resources) alongside its structural levers, not treat structural change as universally superior.",source:"https://doi.org/10.1037/ocp0000047"},
  {id:"R003",topic:"fairness",tags:["worklife", "equity", "maslach"],title:"Understanding the burnout experience: recent research and its implications for psychiatry",finding:"The Areas of Worklife model identifies six organizational domains whose person–job mismatch predicts burnout: workload, control, reward, community, fairness, and values. The greater the mismatch between person and job, the greater the likelihood of burnout; the greater the match, the greater the likelihood of engagement.",implication:"Track how alerts/effort are distributed across the team (e.g., a Gini-style equity measure), not just total volume — fairness of distribution is a distinct, actionable lever.",strength:"strong",cite:"Maslach, C., & Leiter, M.P. (2016), World Psychiatry, 15(2), 103–111; Leiter & Maslach (2004), Areas of Worklife Survey",year:2016,summary:"The Areas of Worklife model frames burnout as arising from mismatches between the person and the job across six organizational domains — workload, control, reward, community, fairness, and values. The greater the mismatch, the greater the likelihood of burnout; the greater the match, the more likely engagement. Fairness is one of these six domains: how equitably work, recognition, and decisions are distributed shapes whether a team stays healthy. For a SOC this supports watching the distribution of alerts and effort across the team — not just total volume — since a team can be busy yet healthy if load feels fair, or lightly loaded yet struggling if it doesn't.",source:"https://doi.org/10.1002/wps.20311"},
  {id:"R004",topic:"definition",tags:["definition", "dimensions", "foundational"],title:"Job burnout",finding:"Defines burnout as a prolonged response to chronic emotional and interpersonal job stressors, characterized by three dimensions: exhaustion, cynicism, and a sense of inefficacy. The review situates the individual stress experience within the organizational context of people's relationship to work, and frames engagement as the positive antithesis of burnout.",implication:"Measure burnout as three distinct dimensions (exhaustion, cynicism, efficacy) rather than a single vague \"stress\" score, and treat it as situated in working conditions — not individual weakness.",strength:"strong",cite:"Maslach, C., Schaufeli, W.B., & Leiter, M.P. (2001), Annu Rev Psychol, 52, 397–422",year:2001,summary:"This landmark Annual Review defines burnout as a prolonged response to chronic emotional and interpersonal stressors on the job, characterized by three dimensions: exhaustion, cynicism, and a reduced sense of professional efficacy (inefficacy). Its central contribution is situating the individual stress experience within the organizational context of people's relationship to their work, rather than treating burnout as personal pathology, and introducing engagement as burnout's positive antithesis. For a wellbeing platform this means measuring the three dimensions separately — exhaustion, cynicism, and efficacy each move differently — and locating the drivers in working conditions rather than in the analyst.",source:"https://doi.org/10.1146/annurev.psych.52.1.397"},
  {id:"R005",topic:"measurement",tags:["MBI", "dimensions", "exhaustion"],title:"The measurement of experienced burnout",finding:"The Maslach Burnout Inventory measures burnout across three dimensions derived from factor analysis of human-services workers — emotional exhaustion, depersonalization, and (reduced) personal accomplishment — with good reported reliability and validity. It became the dominant burnout instrument.",implication:"Track the three dimensions separately; emotional exhaustion is the most consistently measured core dimension and a practical primary signal for behavioral-drift detection.",strength:"strong",cite:"Maslach, C., & Jackson, S.E. (1981), Journal of Organizational Behavior, 2(2), 99–113",year:1981,summary:"This paper introduced the Maslach Burnout Inventory, which measures burnout across three dimensions that emerged from factor analysis of human-services workers — emotional exhaustion, depersonalization (cynicism), and reduced personal accomplishment — and reported good reliability and validity. It became the dominant global burnout instrument. For behavioral-drift detection, the exhaustion dimension is the most consistently measured and a practical primary signal (rising response latency, declining break compliance, sustained overtime), though the original scale-development paper does not itself establish a temporal ordering among the three dimensions.",source:"https://doi.org/10.1002/job.4030020205"},
  {id:"R006",topic:"soc_burnout",tags:["SOC", "ethnography", "human-capital"],title:"A Human Capital Model for Mitigating Security Analyst Burnout",finding:"SOC burnout is a human capital management problem from cyclic interaction of skills, growth, creativity, and empowerment factors.",implication:"Platform must address all four human capital attributes — not just workload.",strength:"strong",cite:"Sundaramurthy, S.C., Bardas, A.G., Case, J., Ou, X., Wesch, M., McHugh, J., & Rajagopalan, S.R. (2015), SOUPS 2015, pp. 347–359, USENIX Association",year:2015,summary:"In a six-month embedded anthropological study of a corporate SOC, researchers found analyst burnout is fundamentally a human-capital management problem — emerging from the cyclic interaction of human, technical, and managerial factors (analysts' skills, growth, creativity, empowerment), not workload alone, with vicious cycles among these eroding morale over time. The design implication: a burnout platform has to address all of these attributes — skill development, growth, autonomy, empowerment — not treat burnout as pure workload throttling.",source:"https://www.usenix.org/conference/soups2015/proceedings/presentation/sundaramurthy"},
  {id:"R007",topic:"soc_burnout",tags:["SOC", "root-cause", "coping"],title:"A Human Capital Model for Mitigating Security Analyst Burnout",finding:"Common SOC management coping strategies such as career progression address only the symptoms of analyst burnout, not its causes; the study frames burnout as a manifestation of underlying, unresolved organizational issues expressed through self-reinforcing vicious cycles.",implication:"Fixes that don't touch the underlying cycle (promotions alone, or top-down mandated programs) treat symptoms; sustainable support targets the human-capital cycle and keeps peer connection voluntary rather than mandated.",strength:"strong",cite:"Sundaramurthy, S.C., Bardas, A.G., Case, J., Ou, X., Wesch, M., McHugh, J., & Rajagopalan, S.R. (2015), SOUPS 2015, pp. 347–359, USENIX Association",year:2015,summary:"The same six-month SOC ethnography found that common management coping strategies — notably career progression — deal only with the symptoms of burnout rather than its root causes, and that burnout is a manifestation of deeper, often unrecognized organizational issues sustained by vicious cycles. The practical implication for FireAlive: surface-level fixes like promotions or mandated wellness programs won't resolve the drivers; support should target the underlying human-capital cycle and let peer connection stay voluntary. (Note: a faithful reading of this source supports the career-progression and root-cause points; it is not the basis for any specific claim that analysts prefer informal contact over formal debriefing.)",source:"https://www.usenix.org/conference/soups2015/proceedings/presentation/sundaramurthy"},
  {id:"R015",topic:"shift_work",tags:["circadian", "night-shift", "health"],title:"Health consequences of shift work and insufficient sleep",finding:"Review of 38 meta-analyses and 24 systematic reviews: shift work, especially night and early-morning shifts, causes acute sleep loss and is associated with increased risk of type 2 diabetes (RR 1.09-1.40), coronary heart disease (RR 1.23), stroke (RR 1.05), cancer (RR 1.01-1.32), and accidents.",implication:"Night/early-shift analysts need protected recovery and deliberate schedule design; treat shift-work health as a safety obligation, not a perk.",strength:"strong",cite:"Kecklund, G., & Axelsson, J. (2016). Health consequences of shift work and insufficient sleep. BMJ, 355, i5210.",year:2016,summary:"A review synthesizing 38 meta-analyses and 24 systematic reviews on shift work, insufficient sleep, chronic disease, and accidents. The authors conclude that shift work's effect on sleep mainly involves acute sleep loss around night and early-morning shifts, with laboratory evidence that both shift work and sleep loss raise cardiometabolic stress and impair cognition. Pooled epidemiological associations include elevated relative risk for type 2 diabetes (1.09-1.40), coronary heart disease (1.23), stroke (1.05), and cancer (1.01-1.32), alongside increased accident risk. The review does not establish a burnout-specific or depression-specific effect.",source:"DOI: 10.1136/bmj.i5210"},
  {id:"R016",topic:"shift_work",tags:["vigilance", "cognitive"],title:"Vigilance requires hard mental work and is stressful",finding:"Sustained attention is effortful and stressful, not passive monitoring. The vigilance decrement (declining detection of rare signals over time) typically onsets within ~20-30 minutes of continuous monitoring, and within ~5 minutes under high event-rate or high-difficulty conditions.",implication:"Rotate analysts off continuous alert-monitoring well before the 30-minute mark and build in breaks; do not expect sustained detection across long unbroken triage blocks.",strength:"strong",cite:"Warm, J. S., Parasuraman, R., & Matthews, G. (2008). Vigilance requires hard mental work and is stressful. Human Factors, 50(3), 433-441.",year:2008,summary:"This review overturns the older view that vigilance tasks are passive and under-arousing, showing that sustained attention imposes high cognitive workload and measurable stress while depleting information-processing resources. The vigilance decrement, a decline in the ability to detect rare critical signals over time, is one of the most replicated effects in the field. Onset is typically within 20-30 minutes of continuous monitoring and can occur within about 5 minutes when event rates are high or targets are perceptually difficult. Decrement severity increases with high event rate, low target probability, successive (memory-loading) discrimination, and low signal salience.",source:"DOI: 10.1518/001872008X312152"},
  {id:"R017",topic:"shift_work",tags:["fatigue", "wakefulness", "shift-length"],title:"Fatigue as impairment; accident risk and shift length",finding:"Extended wakefulness impairs performance comparably to alcohol: 17-24 hours awake produces impairment equivalent to roughly 0.05-0.10% blood alcohol concentration (Dawson & Reid). Injury and accident risk rises with hours on shift and across successive shifts, and is higher on 12-hour and night shifts (Folkard & Tucker).",implication:"Cap consecutive long/night shifts and total hours awake; reduce queue load late in long shifts.",strength:"strong",cite:"Dawson, D., & Reid, K. (1997). Fatigue, alcohol and performance impairment. Nature, 388, 235. AND Folkard, S., & Tucker, P. (2003). Shift work, safety and productivity. Occupational Medicine, 53(2), 95-101.",year:2003,summary:"Two foundational sources on fatigue and shift safety. Dawson & Reid (1997) experimentally equated sustained wakefulness with alcohol intoxication, finding that 17-24 hours awake produces neurobehavioral impairment equivalent to a blood alcohol concentration of about 0.05-0.10%. Folkard & Tucker (2003) review shift-work safety and productivity, reporting that the risk of injuries and accidents increases with the number of hours on shift and across consecutive shifts, and is elevated on extended (12-hour) and night shifts. Neither source addresses shift handoff as a vulnerability.",source:"DOI: 10.1038/40775 (Dawson & Reid); Folkard & Tucker, Occup Med 53(2):95-101 (DOI to confirm)"},
  {id:"R019",topic:"automation",tags:["automation-paradox", "complacency"],title:"Complacency and bias in human use of automation",finding:"Automation complacency and automation bias: under multitask load, operators under-monitor automation and miss events it does not handle; the effect occurs in experts as well as novices and is not eliminated by practice alone.",implication:"Track analyst skill maintenance alongside automation rates; design to keep analysts actively engaged in verification.",strength:"strong",cite:"Parasuraman, R., & Manzey, D. H. (2010). Complacency and bias in human use of automation: An attentional integration. Human Factors, 52(3), 381-410.",year:2010,summary:"An integrative review proposing an attentional model of automation complacency and automation bias. Complacency arises under multiple-task load when manual tasks compete with monitoring of automation for limited attention, leading operators to under-check automated functions. Automation bias produces both omission errors (missing events the automation does not flag) and commission errors (following incorrect automated advice). The authors emphasize that these effects appear in both novices and experts and cannot be overcome by simple practice.",source:"DOI: 10.1177/0018720810376055"},
  {id:"R020",topic:"automation",tags:["trust", "calibration"],title:"Trust in automation: designing for appropriate reliance",finding:"Appropriate reliance on automation depends on trust being calibrated to the system's true capabilities and limitations: under-trust leads to disuse of helpful automation, over-trust to misuse.",implication:"Display confidence scores and false-positive rates transparently so analysts can calibrate trust.",strength:"strong",cite:"Lee, J. D., & See, K. A. (2004). Trust in automation: Designing for appropriate reliance. Human Factors, 46(1), 50-80.",year:2004,summary:"A foundational review framing trust as the key determinant of how people rely on automation. It argues that effective use depends on calibrating trust to the automation's actual capabilities and limitations: when trust is too low relative to capability, operators disuse helpful automation; when too high, they misuse it through over-reliance. The paper synthesizes organizational, sociological, and interpersonal trust research and offers design guidance for fostering appropriately calibrated trust, such as transparency about how and how well the automation works.",source:"DOI: 10.1518/hfes.46.1.50_30392"},
  {id:"R021",topic:"privacy",tags:["surveillance", "workplace", "ethics"],title:"Electronic performance monitoring: review and framework",finding:"Electronic performance monitoring (EPM) tends to increase stress and negative reactions when perceived as invasive or controlling; perceived privacy invasion mediates negative attitudinal outcomes, and EPM characteristics such as transparency, purpose, and synchronicity moderate the effects.",implication:"All monitoring must be transparent, opt-in where possible, and developmental rather than controlling.",strength:"strong",cite:"Ravid, D. M., Tomczak, D. L., White, J. C., & Behrend, T. S. (2020). EPM 20/20: A review, framework, and research agenda for electronic performance monitoring. Journal of Management, 46(1), 100-126.",year:2020,summary:"A comprehensive review of two decades of electronic performance monitoring (EPM) research that proposes a typology of EPM characteristics (purpose, invasiveness, synchronicity, transparency). The authors highlight contradictory findings across the literature, indicating EPM effects depend heavily on contextual and psychological variables rather than monitoring per se. Perceived privacy invasion emerges as a frequent mediator linking EPM to negative outcomes such as anger and perceptions of unfairness. The framework positions transparency and developmental (rather than purely controlling) purpose as factors that shape whether monitoring harms or helps.",source:"DOI: 10.1177/0149206319869435"},
  {id:"R023",topic:"privacy",tags:["psychological-safety", "speaking-up"],title:"Psychological safety and learning behavior in work teams",finding:"Team psychological safety (a shared belief that the team is safe for interpersonal risk-taking) predicts learning behaviors such as speaking up, asking for help, seeking feedback, and discussing errors. In a study of 51 teams, psychological safety (not team efficacy) drove learning behavior, which in turn mediated team performance.",implication:"Design peer-messaging and lead-communication so disclosure carries low interpersonal risk (including anonymous options), since psychological safety is the precondition for speaking up.",strength:"strong",cite:"Edmondson, A. C. (1999). Psychological safety and learning behavior in work teams. Administrative Science Quarterly, 44(2), 350-383.",year:1999,summary:"A multimethod field study of 51 work teams in a manufacturing company that introduced the construct of team psychological safety. Edmondson found that psychological safety, but not team efficacy, was associated with team learning behavior (asking questions, seeking help, experimenting, discussing errors), and that learning behavior mediated the link between psychological safety and team performance. Both team structures (context support, leader coaching) and shared beliefs shaped these outcomes. The paper does not quantify anonymous-versus-identified reporting rates.",source:"DOI: 10.2307/2666999"},
  {id:"R024",topic:"theory",tags:["JD-R", "demands", "resources"],title:"The Job Demands-Resources model: state of the art",finding:"The JD-R model proposes two processes: job demands drive a health-impairment process (exhaustion/burnout), while job resources drive a motivational process (engagement). Resources buffer the impact of demands on strain and matter most when demands are high.",implication:"Reduce demands (automation, caps) and build resources (autonomy, feedback, support), and prioritize resources when demand is highest.",strength:"strong",cite:"Bakker, A. B., & Demerouti, E. (2007). The Job Demands-Resources model: State of the art. Journal of Managerial Psychology, 22(3), 309-328.",year:2007,summary:"A consolidating review of the Job Demands-Resources (JD-R) model, which holds that every occupation's risk factors fall into two categories: job demands and job resources. Demands primarily fuel a health-impairment process leading to exhaustion and burnout, whereas resources primarily fuel a motivational process leading to work engagement. The model specifies an interaction in which resources buffer the impact of demands on strain, and resources gain salience precisely when demands are high. It integrates stress and motivation research into a single framework applicable across job types.",source:"DOI: 10.1108/02683940710733115"},
  {id:"R025",topic:"theory",tags:["JD-R", "engagement"],title:"Towards a model of work engagement",finding:"Job and personal resources are the main predictors of work engagement (vigor, dedication, absorption), the positive antithesis of burnout, and resources are especially predictive of engagement under high job demands.",implication:"Measure and support engagement indicators, not just burnout risk; build resources to sustain engagement when demand is high.",strength:"strong",cite:"Bakker, A. B., & Demerouti, E. (2008). Towards a model of work engagement. Career Development International, 13(3), 209-223.",year:2008,summary:"This article develops an overall model of work engagement, defined as a positive, fulfilling work-related state of vigor, dedication, and absorption. Reviewing the evidence, the authors conclude that job resources and personal resources are the principal predictors of engagement, and that these resources are most influential in the context of high job demands. Engaged workers are described as more creative, more productive, and more willing to go the extra mile. The model positions engagement as the motivational counterpart to burnout within the JD-R framework.",source:"DOI: 10.1108/13620430810870476"},
  {id:"R026",topic:"peer_support",tags:["social-support", "exhaustion"],title:"Sources of social support and burnout: a meta-analytic test of COR",finding:"Meta-analysis: social support did not relate differently across the three burnout dimensions overall (challenging the COR prediction), but work-related support was more strongly associated with emotional exhaustion (rho=-.26) than depersonalization (-.23) or personal accomplishment (.24), while non-work support related more to depersonalization and accomplishment.",implication:"Work-based peer/supervisor support is the support type most tied to the exhaustion dimension, so encrypted peer messaging targets a relevant pathway.",strength:"strong",cite:"Halbesleben, J. R. B. (2006). Sources of social support and burnout: A meta-analytic test of the conservation of resources model. Journal of Applied Psychology, 91(5), 1134-1145.",year:2006,summary:"A meta-analysis testing the Conservation of Resources prediction that social support relates differently to the three burnout dimensions. Contrary to that prediction, social support overall did not show different relationships across exhaustion, depersonalization, and personal accomplishment. However, when the source of support was modeled as a moderator, work-related support (closer to work demands) was more strongly associated with emotional exhaustion than with the other dimensions (rho=-.26 vs -.23 and .24), while non-work support was more associated with depersonalization and personal accomplishment. The result partially challenges COR while affirming that work-based support matters most for exhaustion.",source:"DOI: 10.1037/0021-9010.91.5.1134"},
  {id:"R027",topic:"peer_support",tags:["mentoring", "career-outcomes"],title:"Career benefits associated with mentoring for proteges: a meta-analysis",finding:"Meta-analysis: mentoring is associated with protege career benefits, both objective (compensation, promotions) and subjective (career and job satisfaction), but effect sizes for objective outcomes were small. Career mentoring related more to compensation/satisfaction; psychosocial mentoring related more to satisfaction with the mentor.",implication:"Mentoring pathways can support analyst career outcomes, but expect modest objective effects; treat as one supportive lever, not a primary fix.",strength:"moderate",cite:"Allen, T. D., Eby, L. T., Poteet, M. L., Lentz, E., & Lima, L. (2004). Career benefits associated with mentoring for proteges: A meta-analysis. Journal of Applied Psychology, 89(1), 127-136.",year:2004,summary:"A meta-analysis synthesizing research on the career benefits of mentoring for proteges, examining both objective outcomes (e.g., compensation, promotions) and subjective outcomes (e.g., career and job satisfaction) via mentored-versus-nonmentored comparisons and mentoring-outcome correlations. Findings were generally supportive of mentoring's benefits, but effect sizes for objective outcomes were small. Outcomes varied by mentoring type (career versus psychosocial). The study does not address skill-transfer speed relative to formal training, nor a specific turnover-reduction percentage.",source:"DOI: 10.1037/0021-9010.89.1.127"},
  {id:"R028",topic:"cognitive_load",tags:["decision-fatigue", "contested"],title:"Extraneous factors in judicial decisions",finding:"Analysis of 1,112 Israeli parole rulings: the share of favorable rulings fell gradually from about 65% to near 0% across each decision session and rebounded to about 65% after a food break. The authors cautiously interpret this as mental depletion, but that reading is contested: later analyses argue a case-ordering/representation artifact (e.g., unrepresented prisoners scheduled last) could explain much of the effect.",implication:"Cumulative decision load may degrade judgment, but the magnitude is uncertain; rotating complexity and ensuring breaks is prudent without over-claiming a depletion mechanism.",strength:"moderate",cite:"Danziger, S., Levav, J., & Avnaim-Pesso, L. (2011). Extraneous factors in judicial decisions. PNAS, 108(17), 6889-6892.",year:2011,summary:"An analysis of 1,112 parole board rulings in Israel found that the probability of a favorable ruling declined from about 65% at the start of each of three daily decision sessions to nearly zero by the end, then returned to about 65% after a food break. The authors test the what-the-judge-ate-for-breakfast caricature and cautiously suggest mental depletion as a mechanism. Subsequent work disputes this interpretation: simulations and re-analyses (Weinshall-Margel & Shapard, 2011; Glockner, 2016) show that case-ordering confounds, such as unrepresented prisoners being scheduled last, could produce an effect of similar magnitude without invoking depletion. The headline pattern is robust; its causal interpretation is genuinely contested.",source:"DOI: 10.1073/pnas.1018033108"},
  {id:"R029",topic:"cognitive_load",tags:["interruptions", "context-switching"],title:"The cost of interrupted work: more speed and stress",finding:"Experimental study: people completed interrupted tasks in LESS time than uninterrupted ones, with no difference in quality; they compensated by working faster, but at the cost of more stress, frustration, time pressure, and effort. Interruption context did not change the effect.",implication:"Minimize interruptions/context-switching to protect analyst wellbeing (stress and effort), not on the assumption that they slow work or add errors, since this study found the opposite on those measures.",strength:"moderate",cite:"Mark, G., Gudith, D., & Klocke, U. (2008). The cost of interrupted work: More speed and stress. CHI '08: Proceedings of the SIGCHI Conference on Human Factors in Computing Systems, 107-110.",year:2008,summary:"A controlled experiment simulating office email work investigated whether interruptions and their context affect performance. Surprisingly, participants completed interrupted tasks in less time than when uninterrupted, with no measurable difference in quality, apparently by working faster to compensate. This compensation came at a cost: significantly more stress, frustration, time pressure, and effort. The context of the interruption did not change the outcome, and individual differences (openness to experience, need for personal structure) predicted how disruptive interruptions were.",source:"DOI: 10.1145/1357054.1357072"},
  {id:"R031",topic:"retention",tags:["organizational-justice", "fairness"],title:"Justice at the millennium: a meta-analytic review of organizational justice",finding:"Meta-analysis of 183 studies: distributive, procedural, interpersonal, and informational justice are distinct but moderately-to-highly related dimensions that each contribute unique (incremental) variance to organizational outcomes, including withdrawal, job satisfaction, organizational commitment, and trust.",implication:"Fair process and voice are independent levers on retention-relevant outcomes; analyst agency (queue requests, delegation, scheduling input) is a procedural-justice mechanism.",strength:"strong",cite:"Colquitt, J. A., Conlon, D. E., Wesson, M. J., Porter, C. O. L. H., & Ng, K. Y. (2001). Justice at the millennium: A meta-analytic review of 25 years of organizational justice research. Journal of Applied Psychology, 86(3), 425-445.",year:2001,summary:"A meta-analytic review of 183 organizational justice studies addressing how strongly justice dimensions relate to one another, their relative importance, and their unique effects on outcomes. The authors conclude that distributive, procedural, interpersonal, and informational justice, though moderately-to-highly intercorrelated, each contribute incremental variance to outcomes such as withdrawal, satisfaction, commitment, performance, and trust. This established the multidimensional structure of justice and the value of distinguishing its components. Voice and fair process (procedural justice) matter for outcomes beyond distributive fairness alone.",source:"DOI: 10.1037/0021-9010.86.3.425"},
  {id:"R032",topic:"recovery",tags:["detachment", "off-shift"],title:"The Recovery Experience Questionnaire: detachment and recovery",finding:"Identifies four core off-work recovery experiences: psychological detachment, relaxation, mastery, and control. Psychological detachment (mentally disengaging from work during non-work time) is the experience most consistently associated with lower emotional exhaustion and strain.",implication:"Protect genuine off-shift detachment: no notifications during off-hours; schedule training and peer check-ins within work time, not off-shift.",strength:"strong",cite:"Sonnentag, S., & Fritz, C. (2007). The Recovery Experience Questionnaire: Development and validation of a measure for assessing recuperation and unwinding from work. Journal of Occupational Health Psychology, 12(3), 204-221.",year:2007,summary:"This article develops and validates the Recovery Experience Questionnaire, identifying four core recovery experiences that explain how people unwind from work during non-work time: psychological detachment (mentally switching off from work), relaxation, mastery (learning or challenging leisure activities), and control over leisure. Across validation samples these experiences relate to lower strain and better well-being. Psychological detachment is the experience most consistently linked to reduced emotional exhaustion, psychological strain, and health complaints. Later diary studies (e.g., Binnewies et al., 2010) extended detachment to next-day performance, but that link is beyond this validation paper.",source:"DOI: 10.1037/1076-8998.12.3.204"},
  {id:"R033",topic:"recovery",tags:["micro-breaks", "work-engagement"],title:"Daily micro-breaks and job performance",finding:"Daily diary study: micro-breaks related to better recovery and job performance, with general work engagement as a cross-level moderator: micro-breaks were more beneficial for employees lower in work engagement (who needed to replenish resources more).",implication:"Build short recovery breaks into queue pacing, recognizing they help most for analysts running low on engagement/energy.",strength:"moderate",cite:"Kim, S., Park, Y., & Headrick, L. (2018). Daily micro-breaks and job performance: General work engagement as a cross-level moderator. Journal of Applied Psychology, 103(7), 772-786.",year:2018,summary:"A multilevel diary field study examining whether brief workday micro-breaks support job performance. The authors found that daily micro-breaks were associated with improved recovery and performance, and that this relationship was moderated by general work engagement: micro-breaks were more beneficial for employees with lower work engagement, who had a greater need to replenish resources. The study is grounded in the effort-recovery and conservation-of-resources frameworks. It does not establish a specific optimal break length, nor that nature or movement amplifies recovery (those claims come from other studies).",source:"DOI: 10.1037/apl0000308"},
  {id:"R034",topic:"moral_injury",tags:["moral-injury", "mental-health"],title:"Occupational moral injury and mental health (meta-analysis)",finding:"Systematic review and meta-analysis (13 studies, 6,373 participants): potentially morally injurious events (perpetrating, failing to prevent, or witnessing acts that transgress one's deeply held moral values) accounted for 9.4% of variance in PTSD, 5.2% in depression, and 2.0% in suicidality.",implication:"Moral injury is distinct from ordinary workload burnout; high-stakes failures (e.g., a breach one could not prevent) can morally injure analysts and warrant specific support.",strength:"strong",cite:"Williamson, V., Stevelink, S. A. M., & Greenberg, N. (2018). Occupational moral injury and mental health: Systematic review and meta-analysis. The British Journal of Psychiatry, 212(6), 339-346.",year:2018,summary:"A systematic review and meta-analysis of 13 studies (6,373 participants, mostly military) on occupational moral injury, defined (after Litz et al., 2009) as the distress arising from perpetrating, failing to prevent, or witnessing acts that transgress one's deeply held moral values. Potentially morally injurious events accounted for 9.4% of the variance in PTSD, 5.2% in depression, and 2.0% in suicidality, and were associated with more anxiety and behavioral problems, though less consistently. Methodological and demographic moderators did not significantly change the association. The review establishes moral injury as a distinct contributor to mental-health harm, separate from ordinary job strain.",source:"DOI: 10.1192/bjp.2018.55"},
  {id:"R035",topic:"teamwork",tags:["collaboration", "information-pooling"],title:"Information-pooling bias in collaborative security incident analysis",finding:"Lab experiment with three-person cyber-defense teams: analysts exhibited an information-pooling bias, tending to discuss commonly shared information and under-share uniquely held information, which degraded collaborative threat-detection performance.",implication:"Design collaboration to surface each analyst's unique information (structured handoffs, prompts for unshared findings), since teams default to rehashing what everyone already knows.",strength:"moderate",cite:"Rajivan, P., & Cooke, N. J. (2018). Information-pooling bias in collaborative security incident correlation analysis. Human Factors, 60(5), 626-639.",year:2018,summary:"A laboratory experiment studying how a group-level information-pooling bias affects collaborative incident-correlation analysis in three-person cyber-defense teams. Consistent with the broader hidden-profile literature, analyst teams tended to focus on information already known to all members while under-sharing uniquely held information, and this bias reduced collaborative threat-detection performance. The study indicates that simply having analysts collaborate does not guarantee effective pooling of distributed knowledge. It points toward interventions and tools that explicitly elicit unique information to improve team detection.",source:"DOI: 10.1177/0018720818769249"},
  {id:"R036",topic:"contagion",tags:["crossover", "teams"],title:"Crossover of burnout and engagement in work teams",finding:"Study of 2,229 officers in 85 teams: both burnout and work engagement crossed over from the team to the individual; team-level burnout predicted individual burnout and team-level engagement predicted individual engagement, consistent with emotional-contagion processes.",implication:"Burnout spreads within a shift/team, so monitor team-level dynamics; one persistently exhausted analyst can shift the team, and early team-level support matters.",strength:"strong",cite:"Bakker, A. B., Van Emmerik, H., & Euwema, M. C. (2006). Crossover of burnout and engagement in work teams. Work and Occupations, 33(4), 464-489.",year:2006,summary:"A multilevel study of 2,229 Royal Dutch constabulary officers working in 85 teams examined whether burnout and work engagement transfer between the team and its members. The authors found crossover for both states: team-level burnout was associated with higher individual burnout, and team-level engagement with higher individual engagement. The mechanism is framed in terms of emotional contagion, the largely automatic tendency to mimic and converge emotionally with others. The study does not specify a 2-4 week transmission window.",source:"DOI: 10.1177/0730888406291310"},
  {id:"R037",topic:"motivation",tags:["SDT", "autonomy", "competence", "relatedness"],title:"Self-Determination Theory: basic psychological needs",finding:"Self-Determination Theory holds that intrinsic motivation and well-being depend on satisfying three basic psychological needs: autonomy, competence, and relatedness. Controlling or need-thwarting environments undermine motivation and well-being.",implication:"Support analyst autonomy (queue choice/agency), competence (training, mastery), and relatedness (peer connection) to sustain intrinsic motivation.",strength:"strong",cite:"Deci, E. L., & Ryan, R. M. (2000). The what and why of goal pursuits: Human needs and the self-determination of behavior. Psychological Inquiry, 11(4), 227-268.",year:2000,summary:"A foundational articulation of Self-Determination Theory, arguing that humans have three basic psychological needs: autonomy (volition and self-endorsement of one's actions), competence (feeling effective), and relatedness (feeling connected to others). When social environments support these needs, intrinsic motivation, healthy development, and well-being flourish; when environments are controlling or thwart the needs, motivation and well-being suffer. The paper distinguishes autonomous from controlled motivation and integrates need satisfaction with goal contents. It is among the most influential frameworks in motivation psychology.",source:"DOI: 10.1207/S15327965PLI1104_01"},
  {id:"R039",topic:"definition",tags:["WHO", "ICD-11"],title:"WHO ICD-11: burnout as an occupational phenomenon (QD85)",finding:"The WHO ICD-11 defines burn-out (code QD85) as a syndrome conceptualized as resulting from chronic workplace stress that has not been successfully managed, with three dimensions: energy depletion/exhaustion; increased mental distance or cynicism toward one's job; and reduced professional efficacy. It is classified as an occupational phenomenon (not a medical condition) and applies only to the work context.",implication:"Defining burnout as occupational and chronic-stress-driven frames it as a workplace issue to address structurally, not as individual weakness.",strength:"strong",cite:"World Health Organization (2019/2022). Burn-out, ICD-11 code QD85 (International Classification of Diseases, 11th Revision).",year:2019,summary:"In the 11th revision of the International Classification of Diseases, the WHO defines burn-out (code QD85) as a syndrome resulting from chronic workplace stress that has not been successfully managed, characterized by three dimensions: feelings of energy depletion or exhaustion; increased mental distance from one's job or negativism/cynicism about it; and reduced professional efficacy. Crucially, the WHO classifies burn-out as an occupational phenomenon under 'factors influencing health status,' not as a medical condition, and states it should apply only to the occupational context, not other areas of life. The definition was announced in 2019 and took effect with ICD-11 on 1 January 2022. It is the authoritative international reference definition of burnout.",source:"WHO ICD-11 MMS, code QD85 (icd.who.int)"},
  {id:"R041",topic:"workload",tags:["NASA-TLX", "measurement"],title:"Development of the NASA-TLX (Task Load Index)",finding:"The NASA-TLX is a multidimensional subjective workload measure combining six factors (mental demand, physical demand, temporal demand, performance, effort, and frustration), derived from a multi-year program across 16 experiments. It is the most widely used and validated subjective workload instrument across domains.",implication:"Behavioral drift signals can serve as proxy workload indicators, capturing workload without adding the survey burden of a full instrument.",strength:"strong",cite:"Hart, S. G., & Staveland, L. E. (1988). Development of NASA-TLX (Task Load Index): Results of empirical and theoretical research. In P. A. Hancock & N. Meshkati (Eds.), Human Mental Workload (Advances in Psychology, Vol. 52, pp. 139-183). North-Holland.",year:1988,summary:"This foundational chapter reports a multi-year NASA research program identifying the factors that drive subjective workload within and across tasks, drawing on evaluations of 10 workload-related factors from 16 experiments spanning cognitive, manual-control, supervisory-control, and aircraft-simulation tasks. From this work the authors derived the NASA Task Load Index, a multidimensional rating scale that combines six workload factors (mental demand, physical demand, temporal demand, own performance, effort, and frustration) into a sensitive, reliable workload estimate. The NASA-TLX became the most widely used and validated subjective workload measure across many domains, with well over 15,000 citations. It remains a benchmark for assessing perceived workload.",source:"DOI: 10.1016/S0166-4115(08)62386-9"},
  {id:"R042",topic:"measurement",tags:["BAT", "four-dimensions"],title:"Burnout Assessment Tool (BAT): development, validity, reliability",finding:"The BAT measures burnout via four core dimensions (exhaustion, mental distance, cognitive impairment, and emotional impairment), adding cognitive impairment (e.g., concentration and memory problems) and emotional impairment beyond the classic exhaustion/cynicism/efficacy framing of the MBI.",implication:"The cognitive-impairment dimension maps onto investigation-time and accuracy drift signals, giving a research-grounded target for behavioral indicators.",strength:"strong",cite:"Schaufeli, W. B., Desart, S., & De Witte, H. (2020). Burnout Assessment Tool (BAT)-Development, validity, and reliability. International Journal of Environmental Research and Public Health, 17(24), 9495.",year:2020,summary:"This paper develops and validates the Burnout Assessment Tool (BAT), a modern alternative to the Maslach Burnout Inventory, with four core dimensions: exhaustion, mental distance, cognitive impairment, and emotional impairment, plus secondary dimensions. Cognitive impairment captures difficulty concentrating and memory problems, while emotional impairment captures intense emotional reactions and feeling overwhelmed, dimensions that extend the classic exhaustion/cynicism/efficacy conception. In a representative sample of Flemish employees the instrument showed strong reliability and convergent/discriminant validity against the MBI and OLBI, and cut-off scores were derived to flag at-risk individuals. The BAT offers a theory-driven, multidimensional measure suitable for repeated screening.",source:"DOI: 10.3390/ijerph17249495"},
  {id:"N001",topic:"measurement",tags:["BAT4", "screening", "group-level"],title:"BAT4: ultra-short burnout screening for group-level use",finding:"The BAT4 is a 4-item ultra-short version of the Burnout Assessment Tool, derived via Rasch analysis, subject-matter analysis, and expert judgement. It showed promising construct validity and measurement invariance across countries, age, and gender, with acceptable content coverage. The authors state it is suitable as a screening instrument at the group or organisational level, not for individual diagnosis.",implication:"A validated ultra-short, group-level screen aligns with FireAlive's aggregate-only, low-burden measurement approach and its refusal to surface individual burnout scores.",strength:"moderate",cite:"Hadžibajramović, E., Schaufeli, W., & De Witte, H. (2024). The ultra-short version of the Burnout Assessment Tool (BAT4)-development, validation, and measurement invariance across countries, age and gender. PLoS One, 19(2), e0297843.",year:2024,summary:"Using mixed methods (Rasch analysis plus content and expert review), the authors developed a 4-item ultra-short form of the Burnout Assessment Tool. Across multiple country samples it demonstrated promising construct validity and measurement invariance by country, age, and gender, and despite its brevity its content coverage was judged acceptable. The authors are explicit that the BAT4 is appropriate for screening burnout complaints at the group or organisational level rather than for diagnosing individuals, making it a low-burden instrument for repeated, aggregate monitoring.",source:"DOI: 10.1371/journal.pone.0297843 (PMID 38394265)"},
  {id:"N002",topic:"measurement",tags:["MBI-GS", "structural-validity", "disconfirming"],title:"MBI-GS structural validity is unclear (systematic review + meta-analysis)",finding:"A systematic review (35 studies) and meta-analysis (17 studies) of the MBI-General Survey, the field's 'gold standard' burnout instrument, found only modest internal consistencies and supported a two-factor solution as a viable alternative to the intended three-factor structure. The authors conclude the structural validity of the MBI-GS, and its cross-cultural validity, remain unclear.",implication:"Even the most-used burnout instrument has contested structure, so FireAlive should avoid treating any single questionnaire score as ground truth and be transparent about measurement uncertainty.",strength:"strong",cite:"De Beer, L. T., van der Vaart, L., Escaffi-Schwarz, M., De Witte, H., & Schaufeli, W. B. (2024). Maslach Burnout Inventory - General Survey: A systematic review and meta-analysis of measurement properties. European Journal of Psychological Assessment, 40(5), 360-375.",year:2024,summary:"This systematic review and meta-analysis investigated the measurement properties of the Maslach Burnout Inventory-General Survey (MBI-GS) by synthesising psychometric-validation studies from 1996 to 2022. Of 35 eligible studies, 17 entered the meta-analysis. The pooled results for the original 16-item version supported a three-dimensional representation of burnout but with only modest internal consistencies, and the analysis also found a two-factor solution viable. The authors therefore conclude that the structural validity of the MBI-GS remains unclear, as does its cross-cultural validity, and that the criterion validity of the cynicism and personal-efficacy scales raised questions. This is an important disconfirming finding about the dominant burnout instrument.",source:"DOI: 10.1027/1015-5759/a000797"},
  {id:"N003",topic:"definition",tags:["burnout-depression", "construct-validity", "contested"],title:"Burnout-depression overlap: distinction is hard to characterize (contested)",finding:"A review of 92 studies on the burnout-depression relationship concluded that the two constructs overlap substantially and that 'job-relatedness' alone does not cleanly distinguish burnout from depression. The authors argue the discriminant validity of burnout versus depression is questionable. This is a minority/critical position contested by many burnout researchers, who maintain burnout is a distinct, work-specific syndrome.",implication:"FireAlive should treat elevated burnout signals as a prompt for support and possible referral, not as a clinical diagnosis, given the genuine scientific debate about what burnout measures capture.",strength:"moderate",cite:"Bianchi, R., Schonfeld, I. S., & Laurent, E. (2015). Burnout-depression overlap: A review. Clinical Psychology Review, 36, 28-41.",year:2015,summary:"This review synthesised 92 studies (PubMed, PsycINFO, IngentaConnect) bearing on whether burnout is distinct from depression. The authors argue that the evidence does not establish clear discriminant validity: symptom overlap is substantial, and the common claim that burnout is distinguished by being 'job-related' does not hold up conceptually, since domain-specificity does not change the nature of the underlying condition. They suggest the burnout construct's separateness from depression is, at minimum, unsettled. Importantly, this is a contested view: other researchers (e.g., the BAT and MBI-GS literatures) treat burnout and depression as separable constructs, so FireAlive presents this as an open scientific debate rather than settled fact.",source:"DOI: 10.1016/j.cpr.2015.01.004"},
  {id:"N004",topic:"soc_burnout",tags:["incident-responders", "SOC", "areas-of-worklife"],title:"Burnout in cybersecurity incident responders and its drivers",finding:"In a mixed-methods study of cybersecurity incident responders, over half of the participants (N=19) experienced burnout. Burnout was associated with increased workload, limited control, poor teamwork, and inadequate recognition. Burned-out responders often worked more than 40 hours per week, reported poor sleep quality, and had more email activity, meetings, and after-hours collaboration.",implication:"The identified drivers (workload, control, community, reward) map directly onto FireAlive's design around Maslach's Areas of Worklife and justify behavioral signals tied to hours, after-hours activity, and team support.",strength:"moderate",cite:"Nepal, S., Hernandez, J., et al. (2024). Burnout in Cybersecurity Incident Responders: Exploring the Factors that Light the Fire. Proceedings of the ACM on Human-Computer Interaction, 8(CSCW1), Article 27, 1-35.",year:2024,summary:"Using surveys combined with qualitative interviews and digital-activity measures, this study examined burnout among cybersecurity incident responders (CSIRT/SOC/CERT staff). More than half of participants (N=19) met the study's burnout threshold. Burnout was linked to higher workload, limited control over work, poor teamwork, and inadequate recognition, factors that align with established Areas-of-Worklife theory. Burned-out responders tended to work over 40 hours weekly, sleep poorly, and engage in more meetings, email, and after-hours collaboration. The authors document coping strategies and offer organisational recommendations, framing burnout as a structural and managerial issue with implications for other high-stress work. As a single mixed-methods study with a modest sample, it is best treated as strong domain-specific corroboration rather than definitive prevalence data.",source:"DOI: 10.1145/3637304"},
  {id:"N005",topic:"alert_fatigue",tags:["false-positives", "SOC", "alarm-validation"],title:"SOC analysts' perspectives on false-positive security alarms",finding:"In studies of SOC practitioners (survey n=20; qualitative n=21), analysts confirmed very high false-positive rates from security tools, requiring extensive manual validation. A key nuance: most so-called false positives were attributed to benign triggers, i.e., technically-correct alarms explained by legitimate behavior in the environment, rather than tool malfunctions. The work identifies factors influencing alarm validation and properties needed for fast, effective validation.",implication:"Manual validation burden, not just literal tool error, drives alert fatigue, so FireAlive should treat triage volume and validation effort as load signals rather than assuming alerts are simply 'wrong'.",strength:"moderate",cite:"AlAhmadi, B., Axon, L., & Martinovic, I. (2022). 99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms. 31st USENIX Security Symposium (USENIX Security 22), 2783-2800.",year:2022,summary:"This study examined the prevalence and perceived quality of false-positive (FP) alarms in Security Operations Centres. An online survey of 20 SOC practitioners confirmed that the tools they use generate high FP rates demanding manual validation. A broader qualitative investigation with 21 practitioners explored the limitations of these tools and the quality and validity of their alarms. A central finding nuances the provocative '99%' framing: most perceived false positives are actually benign triggers, true alarms caused by legitimate activity in the organisation's environment, which analysts must still manually adjudicate, rather than outright tool errors. The authors elicit the factors shaping alarm validation and the properties required to make validation effective and quick. Peer-reviewed USENIX Security proceedings (no DOI; stable USENIX URL).",source:"https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi  (no DOI; USENIX peer-reviewed proceedings, pp. 2783-2800)"},
  {id:"N006",topic:"alert_fatigue",tags:["SOC", "automation", "human-AI"],title:"Alert fatigue in SOCs: causes and mitigation directions",finding:"A comprehensive ACM Computing Surveys review frames alert fatigue (and associated burnout) as a persistent, well-documented problem in security operations centres driven by high alert volumes. It identifies four major causes of alert fatigue in SOCs and reviews mitigation approaches through the lenses of automation, augmentation, and human-AI collaboration.",implication:"Positioning FireAlive within an automation/augmentation/human-AI framing keeps the focus on reducing analyst load, consistent with the literature's prescribed mitigation directions.",strength:"moderate",cite:"Tariq, S., Baruwal Chhetri, M., Nepal, S., & Paris, C. (2025). Alert Fatigue in Security Operations Centres: Research Challenges and Opportunities. ACM Computing Surveys, 57(9), Article 224, 1-38.",year:2025,summary:"This peer-reviewed survey reviews the academic and industry literature on alert fatigue in security operations centres, where high volumes of alerts, many of them false or low-value, overwhelm analysts and contribute to burnout and the risk of missed real threats. The authors organise mitigation strategies along three lenses, automation, augmentation, and human-AI collaboration, and identify four major causes of alert fatigue in SOCs (the review names the count and analyses the causes in depth). As a literature survey rather than primary empirical work, it is valuable for framing and synthesis. Specific quantitative claims circulating in secondary sources are not relied upon here.",source:"DOI: 10.1145/3723158"},
  {id:"N007",topic:"shift_work",tags:["shift-work", "cardiometabolic", "umbrella-review"],title:"Shift work and health outcomes: graded evidence (umbrella review)",finding:"An umbrella review of 8 systematic reviews/meta-analyses (16 shift-work-health associations) graded the strength of each association. It found highly suggestive evidence linking shift work to myocardial infarction (ever vs never shift work) and to diabetes mellitus incidence (per 5-year increment); other associations rested on weaker or less credible evidence. The findings concern physical (cardiometabolic) health, not burnout per se.",implication:"Shift work carries real but graded cardiometabolic risk, supporting FireAlive's shift-aware scheduling features as a wellbeing measure without overstating shift work's documented harms.",strength:"moderate",cite:"Wu, Q.-J., Sun, H., Wen, Z.-Y., Zhang, M., Wang, H.-Y., He, X.-H., Jiang, Y.-T., & Zhao, Y.-H. (2022). Shift work and health outcomes: an umbrella review of systematic reviews and meta-analyses of epidemiological studies. Journal of Clinical Sleep Medicine, 18(2), 653-662.",year:2022,summary:"This umbrella review searched MEDLINE, Web of Science, and Embase from inception to April 2020 and synthesised 8 systematic reviews and/or meta-analyses covering 16 associations between shift work and health outcomes. For each association the authors estimated the summary effect, confidence and prediction intervals, heterogeneity, and signs of small-study and excess-significance bias, then graded the credibility of the evidence. Only two associations reached 'highly suggestive' strength: shift work with myocardial infarction (ever vs never) and with diabetes mellitus incidence (per 5-year increment of exposure); the remaining associations were supported by weaker evidence. Because shift work is intrinsic to 24/7 SOC staffing, this graded, physically-oriented evidence is relevant context, though it addresses cardiometabolic risk rather than burnout directly. [Citation corrected: lead author is Wu, not 'Su'.]",source:"DOI: 10.5664/jcsm.9642 (PMID 34473048)"},
  {id:"N008",topic:"theory",tags:["JD-R", "demands", "resources"],title:"Job Demands-Resources model: dual pathways to burnout",finding:"The JD-R model groups working conditions into job demands and job resources, which relate differentially to burnout. Across three occupational groups (N=374), using self-reports and observer ratings, job demands were primarily related to the exhaustion component of burnout, while a lack of job resources was primarily related to disengagement. The study also confirmed a two-factor (exhaustion, disengagement) structure for the Oldenburg Burnout Inventory.",implication:"Treating load-type signals (demands -> exhaustion) and support/resource signals (resources -> disengagement) as distinct lets FireAlive reflect the two pathways rather than collapsing them into one score.",strength:"strong",cite:"Demerouti, E., Bakker, A. B., Nachreiner, F., & Schaufeli, W. B. (2001). The job demands-resources model of burnout. Journal of Applied Psychology, 86(3), 499-512.",year:2001,summary:"This foundational paper introduced the Job Demands-Resources (JD-R) model, proposing that any job's working conditions can be sorted into two broad categories, demands and resources, with distinct consequences. Using structural-equation (LISREL) analyses on both self-reported and observer-rated working conditions across human-services, industry, and transport samples (total N=374), the authors found strong support for two parallel processes: high job demands are primarily associated with the exhaustion component of burnout, whereas insufficient job resources are primarily associated with disengagement (the cynicism/withdrawal component). The study also validated the two-factor structure of the Oldenburg Burnout Inventory. The model has since become a dominant framework for occupational wellbeing.",source:"DOI: 10.1037/0021-9010.86.3.499"},
  {id:"N009",topic:"theory",tags:["JD-R", "challenge-hindrance", "engagement"],title:"Challenge vs hindrance demands: not all workload is equal",finding:"A meta-analytic test extending JD-R with stressor-appraisal theory found that job demands were positively associated with burnout and resources negatively associated, while resources were consistently positively related to engagement. Critically, demands' relationship with engagement depended on appraisal: hindrance demands (e.g., role conflict, role ambiguity, red tape) were negatively related to engagement, whereas challenge demands (e.g., time pressure, high responsibility) were positively related to engagement.",implication:"FireAlive should distinguish hindrance load (role ambiguity, bureaucratic friction) from challenge load, since reducing hindrances helps while indiscriminately cutting all demands could remove engaging challenge.",strength:"strong",cite:"Crawford, E. R., LePine, J. A., & Rich, B. L. (2010). Linking job demands and resources to employee engagement and burnout: A theoretical extension and meta-analytic test. Journal of Applied Psychology, 95(5), 834-848.",year:2010,summary:"This meta-analysis refined the JD-R model by incorporating cognitive-appraisal theory to explain inconsistent findings on how demands relate to engagement. Using meta-analytic structural modeling, the authors confirmed that demands raise burnout and resources lower it, and that resources reliably increase engagement. The novel contribution was showing that the demand-engagement link hinges on how a demand is appraised: hindrance demands (role conflict, role ambiguity, organizational politics, red tape, hassles) are seen as obstacles and relate negatively to engagement, while challenge demands (time pressure, high responsibility, workload that promotes growth) are seen as opportunities and relate positively to engagement. This challenge/hindrance distinction means 'reducing workload' is too blunt a goal.",source:"DOI: 10.1037/a0019364 (PMID 20836586)"},
  {id:"N010",topic:"theory",tags:["COR", "resource-loss", "stress"],title:"Conservation of Resources theory of stress",finding:"Conservation of Resources (COR) theory proposes that people strive to obtain, retain, protect, and build valued resources, and that psychological stress arises when resources are threatened with loss, are actually lost, or fail to be gained after a significant investment of resources. Faced with stress, individuals act to minimize net resource loss.",implication:"Framing wellbeing as resource protection supports FireAlive's emphasis on recovery and on interrupting resource-loss spirals before exhaustion compounds.",strength:"strong",cite:"Hobfoll, S. E. (1989). Conservation of resources: A new attempt at conceptualizing stress. American Psychologist, 44(3), 513-524.",year:1989,summary:"This influential theoretical paper introduced Conservation of Resources (COR) theory as a more testable alternative to the phenomenological stress definitions that dominated the field. Its core premise is that people are motivated to obtain, retain, protect, and build the resources they value (objects, conditions, personal characteristics, and energies). Stress is theorized to occur in three circumstances: when resources are threatened with loss, when there is an actual net loss of resources, and when individuals fail to gain resources after investing them. When stressed, people act to minimize net resource loss, and resource-loss spirals can develop. COR became a foundational lens for understanding burnout as the depletion of work-related resources.",source:"DOI: 10.1037/0003-066X.44.3.513"},
  {id:"N011",topic:"interventions",tags:["meta-analysis", "intervention-efficacy", "exhaustion"],title:"Burnout interventions have modest, exhaustion-focused effects",finding:"A random-effects meta-analysis of 29 controlled intervention studies found a small overall effect on burnout (Cohen's d about .22), with effects that persisted at follow-up. Interventions (e.g., CBT, relaxation, interpersonal and role-related skills) produced significant but modest reductions mainly in exhaustion, with little effect on cynicism/depersonalization or personal accomplishment. Interventions lasting under one month had the smallest effects.",implication:"FireAlive should set humble expectations: individual-level interventions yield small effects on exhaustion alone, which strengthens the case for structural, organizational change over promising a cure.",strength:"strong",cite:"Maricuțoiu, L. P., Sava, F. A., & Butta, O. (2016). The effectiveness of controlled interventions on employees' burnout: A meta-analysis. Journal of Occupational and Organizational Psychology, 89(1), 1-27.",year:2016,summary:"This meta-analysis assessed how well controlled interventions reduce employee burnout, including only studies with a burnout outcome, a control group, and sufficient data for effect-size calculation. Across 29 studies (random-effects model), the overall effect on general burnout was small (about d=.22) but durable at follow-up, indicating modest, lasting benefits. Intervention types such as cognitive behavioral therapy, relaxation, and interpersonal or role-related skills training significantly but modestly reduced emotional exhaustion, yet had little measurable effect on the cynicism/depersonalization and reduced-accomplishment dimensions; the authors called for new interventions targeting those dimensions. Shorter programs (under a month) were least effective. This is an honest, expectation-setting finding about the limits of intervention.",source:"DOI: 10.1111/joop.12099"},
  {id:"N012",topic:"shift_work",tags:["sleep", "interventions", "rotating-night-shift"],title:"Sleep interventions help rotating night shift workers",finding:"A systematic review (30 studies) and meta-analysis (25 studies) of randomized and clinical trials found that sleep interventions were effective in promoting sleep or reducing sleep disturbance among rotating night shift workers, spanning both pharmacological (e.g., melatonin) and non-pharmacological (light therapy, CBT, napping, schedule changes) approaches.",implication:"Because SOC analysts often work rotating night shifts, FireAlive's shift-aware features can responsibly surface evidence-based sleep strategies as a wellbeing measure.",strength:"moderate",cite:"Jeon, B. M., Kim, S. H., & Shin, S. H. (2023). Effectiveness of sleep interventions for rotating night shift workers: a systematic review and meta-analysis. Frontiers in Public Health, 11, 1187382.",year:2023,summary:"This systematic review and meta-analysis searched six databases for randomized and clinical trials (1990-June 2022) of sleep interventions specifically for rotating night shift workers, a group prior reviews had not isolated. Of 1,019 records, 30 met inclusion criteria for the review and 25 entered the meta-analysis; interventions were grouped into pharmacological approaches and non-pharmacological approaches such as light therapy, cognitive behavioral therapy, napping, and schedule changes. The authors concluded that sleep interventions were effective overall in promoting sleep or reducing sleep disturbance in this population, while noting that the underlying evidence base has been limited by heterogeneity and study-quality constraints.",source:"DOI: 10.3389/fpubh.2023.1187382 (PMID 37427284)"},
  {id:"N013",topic:"shift_work",tags:["fatigue-culture", "disclosure", "qualitative"],title:"Shift-work fatigue culture: 'soldiering through' and fear of disclosure",finding:"A qualitative evidence synthesis of 28 studies (1,519 participants) generated three themes: an 'inevitability of fatigue' culture in which workers feel peer pressure to soldier through shifts regardless of tiredness; a constant struggle to balance daytime sleep against family, leisure, and work responsibilities (often deprioritizing their own sleep); and obstacles to enacting healthy behaviors workers know would help. Notably, shift workers often avoid disclosing fatigue to employers for fear of repercussions, which normalizes fatigue and sustains a detrimental workplace culture.",implication:"Fear of disclosure and normalized fatigue directly justify FireAlive's privacy-by-design and non-punitive, structural stance: analysts will not surface fatigue if doing so risks penalties.",strength:"moderate",cite:"Benton, J. S., Lee, C. L., Long, H. A., Sugavanam, T., Holmes, L., Keane, A., Thurley, N., Kyle, S., Ray, D., & French, D. P. (2025). Shift workers' experiences and views of sleep disturbance, fatigue and healthy behaviors: a systematic review and qualitative evidence synthesis. Scandinavian Journal of Work, Environment & Health.",year:2025,summary:"This qualitative evidence synthesis systematically searched four databases and included 28 studies (1,519 participants), appraised with an adapted CASP checklist and with confidence assessed via GRADE-CERQual. Three analytical themes emerged. First, an 'inevitability of fatigue and tiredness' in which a workplace culture of 'peer pressure to soldier through' leads workers to push on regardless of how tired they are, and to fear being seen as weak. Second, 'balancing sleep needs with competing responsibilities,' where workers struggle to protect daytime sleep against family, leisure, and work demands and frequently sacrifice their own rest. Third, 'obstacles to engaging in healthy behaviors,' where workers understand what would help but face practical barriers. A salient cross-cutting finding is that workers often hide fatigue from employers fearing disciplinary or reputational consequences, which normalizes exhaustion. These cultural dynamics support non-punitive, privacy-protective wellbeing design.",source:"DOI: 10.5271/sjweh.4223"},
  {id:"N014",topic:"working_conditions",tags:["structural", "prospective", "risk-factors"],title:"Work-environment factors prospectively predict burnout",finding:"A systematic review and meta-analysis of prospective and case-control studies (follow-up 1-5 years) graded the evidence linking working conditions to later development of burnout. High job support and workplace justice were protective against emotional exhaustion, while high demands, low job control, high workload, low reward, and job insecurity increased the risk of developing exhaustion. The authors conclude burnout is strongly influenced by structural factors, underscoring the potential of organizational interventions.",implication:"Because structural conditions (demands, control, support, reward, fairness) prospectively predict burnout, FireAlive is justified in treating those conditions as leading indicators rather than blaming individuals.",strength:"strong",cite:"Aronsson, G., Theorell, T., Grape, T., Hammarström, A., Hogstedt, C., Marteinsdottir, I., Skoog, I., Träskman-Bendz, L., & Hall, C. (2017). A systematic review including meta-analysis of work environment and burnout symptoms. BMC Public Health, 17(1), 264.",year:2017,summary:"This review and meta-analysis aimed to provide graded evidence for associations between working conditions and the near-future development of burnout, including only prospective or comparable case-control designs (1990-2013) that measured exposure and outcome at baseline and again 1-5 years later. Analyzing a wide range of work-exposure factors against the separate burnout dimensions, the strongest evidence (grade 3) linked low workplace support to emotional exhaustion; high demands, low job control, high workload, low reward, and job insecurity all increased exhaustion risk, while high support and workplace justice were protective. The authors emphasize that burnout symptoms are strongly shaped by structural workplace factors, supporting organization-level prevention over individual-only approaches. The prospective design strengthens causal interpretation relative to cross-sectional work.",source:"DOI: 10.1186/s12889-017-4153-7 (PMID 28302088)"},
  {id:"N015",topic:"interventions",tags:["physician-burnout", "meta-analysis", "Lancet"],title:"Both individual and structural interventions reduce physician burnout",finding:"A systematic review and meta-analysis of interventions to prevent and reduce physician burnout found that both individual-focused strategies (e.g., mindfulness, stress management, small-group curricula) and structural/organizational strategies can produce clinically meaningful reductions in burnout. The authors note further research is needed to identify which interventions work best in which populations.",implication:"FireAlive's combination of analyst-side tools and management-side structural prompts is consistent with evidence that both individual and organizational interventions can yield meaningful reductions.",strength:"strong",cite:"West, C. P., Dyrbye, L. N., Erwin, P. J., & Shanafelt, T. D. (2016). Interventions to prevent and reduce physician burnout: a systematic review and meta-analysis. The Lancet, 388(10057), 2272-2281.",year:2016,summary:"This Lancet meta-analysis synthesized controlled and uncontrolled studies of interventions intended to prevent or reduce physician burnout, searching six databases through January 2016. The authors concluded that the literature supports clinically meaningful reductions in burnout from both individual-focused approaches (such as mindfulness, stress management, and facilitated small-group curricula) and structural or organizational approaches, while cautioning that more research is needed to determine which interventions are most effective for which groups. It is a landmark, high-authority synthesis establishing that burnout is modifiable and that organizational change belongs alongside individual strategies.",source:"DOI: 10.1016/S0140-6736(16)31279-X (PMID 27692469)"},
  {id:"N016",topic:"interventions",tags:["organization-directed", "physician-burnout", "structural"],title:"Organization-directed interventions outperform individual-directed",finding:"A meta-analysis of controlled interventions to reduce physician burnout (19 studies, ~1,550 physicians) found small overall benefits. Subgroup analyses showed significantly larger effects for organization-directed interventions (SMD = -0.45; 95% CI -0.62 to -0.28) than for physician-directed interventions (SMD = -0.18; 95% CI -0.32 to -0.03). The authors conclude this supports viewing burnout as a problem of the whole organization rather than of individuals.",implication:"The roughly two-to-three-fold advantage of organization-directed over individual-directed interventions is direct evidence for FireAlive's emphasis on the management console driving structural change.",strength:"strong",cite:"Panagioti, M., Panagopoulou, E., Bower, P., Lewith, G., Kontopantelis, E., Chew-Graham, C., Dawson, S., van Marwijk, H., Geraghty, K., & Esmail, A. (2017). Controlled interventions to reduce burnout in physicians: A systematic review and meta-analysis. JAMA Internal Medicine, 177(2), 195-205.",year:2017,summary:"This JAMA Internal Medicine meta-analysis evaluated controlled interventions to reduce physician burnout and tested whether intervention type, physician experience, and care setting moderated effectiveness. Across 19 studies (about 1,550 physicians), interventions produced small overall reductions in burnout. Critically, organization-directed interventions (e.g., workload or schedule changes, workflow redesign) were significantly more effective (SMD = -0.45) than physician-directed interventions such as mindfulness or stress management (SMD = -0.18). Effects were somewhat larger in experienced physicians and primary care, though not significantly so, and were robust to risk-of-bias ratings. The authors interpret the results as support for treating burnout as an organizational rather than individual problem. This is the cornerstone quantitative evidence for prioritizing structural change.",source:"DOI: 10.1001/jamainternmed.2016.7674 (PMID 27918798)"},
  {id:"N017",topic:"interventions",tags:["mindfulness", "RCT-meta", "individual"],title:"Workplace mindfulness programs: modest but real benefits",finding:"A meta-analysis of 56 randomized controlled trials (about 2,689 intervention and 2,472 control participants) found that mindfulness-based programs in the workplace effectively reduce stress, burnout, mental distress, and somatic complaints, and improve mindfulness, well-being, compassion, and job satisfaction, with effect sizes ranging from small to large across outcomes.",implication:"This grounds FireAlive's optional box-breathing/mindfulness exercise honestly: a modest individual-level aid with real but variable benefits, not a substitute for structural change.",strength:"moderate",cite:"Vonderlin, R., Biermann, M., Bohus, M., & Lyssenko, L. (2020). Mindfulness-based programs in the workplace: a meta-analysis of randomized controlled trials. Mindfulness, 11, 1579-1598.",year:2020,summary:"This meta-analysis synthesized 56 randomized controlled trials of mindfulness-based programs delivered in workplace settings (through late 2018), with roughly 2,689 intervention participants and 2,472 controls, assessing heterogeneity, outliers, and risk of bias per Cochrane recommendations. Between-group analyses showed that mindfulness-based programs effectively reduced stress, burnout, mental distress, and somatic complaints while improving mindfulness, general well-being, compassion, and job satisfaction, with effects spanning small to large depending on the outcome. The authors conclude mindfulness programs can promote employee health and well-being across varied occupational settings, while calling for more work on durability and on work-performance outcomes. As an individual-level modality with heterogeneous effects, it is best framed as a supportive option rather than a primary remedy.",source:"DOI: 10.1007/s12671-020-01328-3"},
  {id:"N018",topic:"psychological_safety",tags:["psych-safety", "meta-analysis", "teamwork"],title:"Psychological safety: antecedents and outcomes (meta-analysis)",finding:"A meta-analysis drawing on 136 independent samples (over 22,000 individuals and nearly 5,000 groups) mapped the nomological network of psychological safety. Antecedents include supportive leadership, positive work design and role characteristics, and supportive relationships/work context; outcomes include higher work engagement, task performance, and organizational citizenship behaviors. Psychological safety helps transmit the effects of its antecedents onto these outcomes.",implication:"Because psychological safety is built by supportive leadership and relationships and drives engagement and performance, it underpins FireAlive's Peer Skill-Share and its non-punitive culture in which analysts feel safe to disclose strain.",strength:"strong",cite:"Frazier, M. L., Fainshmidt, S., Klinger, R. L., Pezeshkan, A., & Vracheva, V. (2017). Psychological safety: A meta-analytic review and extension. Personnel Psychology, 70(1), 113-165.",year:2017,summary:"This meta-analysis aggregated theoretical and empirical work across 136 independent samples (more than 22,000 individuals and roughly 5,000 groups) to test the antecedents and outcomes of psychological safety, defined as the shared belief that it is safe to take interpersonal risks at work. The authors mapped its nomological network and compared the relative strength of antecedents, which span supportive leadership, work design and role characteristics (e.g., role clarity, autonomy), and supportive peer relationships and work context. Psychological safety in turn related to greater work engagement, task performance, and organizational citizenship behaviors, with evidence that it mediates between its antecedents and these outcomes. It extends Edmondson's foundational work with large-scale quantitative synthesis.",source:"DOI: 10.1111/peps.12183"},
  {id:"N019",topic:"theory",tags:["vicious-cycle", "longitudinal", "exhaustion"],title:"Burnout and stressors reinforce each other (vicious cycle)",finding:"A continuous-time meta-analysis of 48 longitudinal studies (N=26,319) found reciprocal effects between job stressors and burnout. The stressor-to-burnout effect was small, whereas the burnout-to-stressor (strain) effect was larger, meaning burnout increases later job stressors more than stressors increase later burnout, producing a vicious circle. The strain effect was moderated by job control and job support. Emotional exhaustion was reciprocally tied to stressors, while depersonalization/cynicism was not directly related to stressors.",implication:"Because burnout actively generates more stressors, early detection (FireAlive's drift signals) and timely resource support are critical to break the spiral before exhaustion compounds.",strength:"strong",cite:"Guthier, C., Dormann, C., & Voelkle, M. C. (2020). Reciprocal effects between job stressors and burnout: A continuous time meta-analysis of longitudinal studies. Psychological Bulletin, 146(12), 1146-1173.",year:2020,summary:"Prior longitudinal evidence on whether stressors cause burnout or burnout causes stressors had been ambiguous. Using continuous-time meta-analysis to handle the varying time lags across 48 longitudinal studies (N=26,319), the authors estimated reciprocal effects. They found that both directions exist, but the effect of burnout on subsequent job stressors (the strain effect) was larger than the effect of stressors on subsequent burnout, implying that once burnout sets in it tends to generate further stressors and feed a self-reinforcing loop. Job control and job support buffered the strain effect. Decomposing burnout, emotional exhaustion showed reciprocal links with stressors whereas depersonalization/cynicism did not relate directly to stressors. The authors recommend providing resources to burned-out employees early to interrupt the cycle. This supports prevention and early intervention over late remediation.",source:"DOI: 10.1037/bul0000304 (PMID 33119345)"},
  {id:"N020",topic:"post_incident",tags:["debriefing", "CISD", "disconfirming"],title:"Single-session psychological debriefing does not prevent PTSD",finding:"A Cochrane systematic review found no evidence that single-session individual psychological debriefing is useful for preventing PTSD after traumatic events. Debriefing was equivalent to or worse than control or educational interventions for PTSD, depression, anxiety, and general psychological morbidity, with some suggestion it may increase the risk of PTSD and depression. The authors concluded that compulsory debriefing of trauma victims should cease, and that a 'screen and treat' approach is more appropriate.",implication:"FireAlive's Post-Incident Wellness must avoid mandatory, single-session debriefing (CISD-style); the evidence favors voluntary, screen-and-support, resource-based responses instead.",strength:"strong",cite:"Rose, S. C., Bisson, J., Churchill, R., & Wessely, S. (2002). Psychological debriefing for preventing post traumatic stress disorder (PTSD). Cochrane Database of Systematic Reviews, 2002(2), CD000560.",year:2002,summary:"This Cochrane review assessed the efficacy of single-session individual psychological 'debriefing' for reducing psychological distress and preventing PTSD after traumatic events. Pooling randomized trials, the reviewers found that debriefing was either equivalent to or worse than control or educational interventions for preventing or reducing PTSD, depression, anxiety, and general psychological morbidity, with no reduction in PTSD severity at 1-4 months, 6-13 months, or 3 years, and with some evidence that it may increase the risk of PTSD and depression. The authors concluded there is no evidence that single-session debriefing is a useful preventive treatment and that compulsory debriefing of trauma victims should cease, recommending a 'screen and treat' model instead. This is a key disconfirming finding for how organizations should respond after critical incidents. (Note: a later review suggested possible benefits of multiple-session approaches, at low certainty; this entry concerns single-session debriefing.)",source:"DOI: 10.1002/14651858.CD000560 (PMID 12076399)"},
];
const KB_VERSION = "2026.05.1";
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

// ── B5d1 PR D: My Signals metadata + on-device baseline/drift engine ─────────
// Behavioral signals are sealed to the analyst's own X25519 key and decrypted
// ONLY on this device (burnout:decrypt). From each analyst's own decrypted
// history we compute two anchors, shown side by side:
//   1. A FROZEN personal baseline -- the median over the first FA_ESTABLISH_DAYS
//      of history, then frozen. Later data can RE-ESTABLISH IT DOWNWARD (a recent
//      in-band window that settles lower), but a sustained-high window can NEVER
//      raise it. A rolling/auto-raising baseline would silently normalise
//      persistent strain and hide a worsening analyst.
//   2. A normative HEALTHY-RANGE band per signal (FireAlive-set, configurable,
//      research-informed). It flags an analyst whose own "normal" already sits
//      outside the band even while their personal drift is flat.
// Until FA_ESTABLISH_DAYS of history exist the personal baseline is withheld
// (status 'establishing') and only the band comparison is shown.
const FA_ESTABLISH_DAYS = 90;   // history required before a personal baseline is trusted
const FA_CURRENT_DAYS = 14;     // recent window summarised as "current"
const FA_DAY_MS = 86400000;
const FA_DRIFT_NOTABLE = 15;    // |drift %| beyond which a worsening change is highlighted

// hib = "higher is better" (documentation quality, break compliance). band is the
// healthy range; for hib the concern is falling BELOW low, otherwise rising ABOVE high.
const BEHAVIORAL_META = {
  investigationTime: { label: "Avg time per alert",    u: "min", hib: false, band: { low: 0,  high: 30  } },
  dismissRate:       { label: "Closed without notes",  u: "%",   hib: false, band: { low: 0,  high: 30  } },
  ticketQuality:     { label: "Documentation quality", u: "%",   hib: true,  band: { low: 65, high: 100 } },
  escalationRate:    { label: "Escalation rate",       u: "%",   hib: false, band: { low: 0,  high: 25  } },
  break_compliance:  { label: "Break compliance",      u: "%",   hib: true,  band: { low: 60, high: 100 } },
};
const BEHAVIORAL_ORDER = ["investigationTime", "dismissRate", "ticketQuality", "escalationRate", "break_compliance"];

function faMedian(arr) {
  if (!arr || arr.length === 0) return null;
  const s = arr.slice().sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
// 'within' | 'above' | 'below' relative to the normative band (only the harmful side is named).
function faBandStatus(v, band, hib) {
  if (v == null || !band) return "within";
  if (hib) return v < band.low ? "below" : "within";
  return v > band.high ? "above" : "within";
}
function faInBand(v, band, hib) { return faBandStatus(v, band, hib) === "within"; }
// Per-signal view from a chronological series of {t (ms), v}.
// Returns { status:'no_data'|'establishing'|'established', n, cur, base, driftPct, band }.
function faComputeSignal(series, band, hib) {
  if (!series || series.length === 0) return { status: "no_data", n: 0 };
  const asc = series.slice().sort((a, b) => a.t - b.t);
  const t0 = asc[0].t, tEnd = asc[asc.length - 1].t;
  const spanDays = (tEnd - t0) / FA_DAY_MS;
  const cur = faMedian(asc.filter((p) => p.t >= tEnd - FA_CURRENT_DAYS * FA_DAY_MS).map((p) => p.v));
  const bandStatus = faBandStatus(cur, band, hib);
  if (spanDays < FA_ESTABLISH_DAYS) {
    return { status: "establishing", n: asc.length, cur, band: bandStatus, spanDays: Math.floor(spanDays) };
  }
  const estBase = faMedian(asc.filter((p) => p.t <= t0 + FA_ESTABLISH_DAYS * FA_DAY_MS).map((p) => p.v));
  const recentBase = faMedian(asc.filter((p) => p.t >= tEnd - FA_ESTABLISH_DAYS * FA_DAY_MS).map((p) => p.v));
  let base = estBase;
  if (recentBase != null && estBase != null && recentBase < estBase && faInBand(recentBase, band, hib)) base = recentBase;
  const driftPct = (base != null && base !== 0 && cur != null) ? ((cur - base) / Math.abs(base)) * 100 : 0;
  return { status: "established", n: asc.length, cur, base, driftPct, band: bandStatus };
}
// Display: round to a tidy number; em-dash placeholder when absent.
function faNum(x) { return x == null ? "\u2014" : (Math.round(x * 10) / 10); }

// ── B5d1 PR D: aggregate burnout-proximity (on-device, deterministic) ────────
// One overall read across ALL signals. Behavioral strain (the original
// computeRisk ratios, with break_compliance folded in) is blended with
// operational pressure; a single severe signal lifts the score (max blend) so a
// real problem is not diluted by calm signals. Establishing/no-data signals do
// not invent strain. Drives the My Signals overall card and the home status
// banner, and frames the holistic on-device interpretation.
const FA_BEHAVIORAL_WEIGHTS = { dismissRate: 0.30, ticketQuality: 0.26, investigationTime: 0.22, escalationRate: 0.09, break_compliance: 0.13 };
const FA_DRIFT_FULL = 50;             // a 50% bad-direction drift -> full per-signal drift strain
const FA_BAND_BREACH_STRAIN = 0.7;    // current value outside the healthy band, on the harmful side
const FA_AVG_VS_MAX = 0.55;           // behavioral = 0.55*weighted average + 0.45*worst signal
const FA_BEHAVIORAL_VS_PRESSURE = 0.6;// overall = 0.6*behavioral + 0.4*pressure (renormalized if one absent)
const FA_PRESSURE_THRESHOLDS = { cognitive_load: [60, 80], task_switching: [6, 10], queue_pressure: [8, 12], shift_overtime: [4, 8] };
const FA_STAGE_BANDS = [[0.25, "healthy"], [0.50, "watch"], [0.75, "strained"], [Infinity, "elevated"]];
const STAGE_COPY = {
  healthy:  { hl: "Your signals look steady.",                   sub: "Nothing standing out right now.",                                 c: C.a },
  watch:    { hl: "A few signals are drifting.",                 sub: "Worth noticing, not worrying about yet.",                         c: C.w },
  strained: { hl: "Several signals are trending toward strain.", sub: "A good moment to ease your load or talk to someone.",             c: C.w },
  elevated: { hl: "Your signals point to sustained strain.",     sub: "Reducing your queue or a 1-on-1 is exactly what support is for.", c: C.d },
};
function faSignalStrain(s) {
  if (!s || s.status === "no_data") return { strain: 0, usable: false };
  const breach = (s.band === "above") || (s.band === "below");
  if (s.status === "establishing") return { strain: breach ? FA_BAND_BREACH_STRAIN : 0, usable: true };
  const badMag = s.hib ? Math.max(0, -(s.driftPct || 0)) : Math.max(0, (s.driftPct || 0));
  const driftStrain = Math.min(1, badMag / FA_DRIFT_FULL);
  return { strain: Math.min(1, Math.max(driftStrain, breach ? FA_BAND_BREACH_STRAIN : 0)), usable: true };
}
function faBehavioralScore(signals) {
  let wsum = 0, acc = 0, worst = 0, any = false;
  for (const k of Object.keys(FA_BEHAVIORAL_WEIGHTS)) {
    const r = faSignalStrain(signals[k]); if (!r.usable) continue;
    any = true; wsum += FA_BEHAVIORAL_WEIGHTS[k]; acc += FA_BEHAVIORAL_WEIGHTS[k] * r.strain; if (r.strain > worst) worst = r.strain;
  }
  if (!any || wsum === 0) return { score: null, usable: false };
  return { score: FA_AVG_VS_MAX * (acc / wsum) + (1 - FA_AVG_VS_MAX) * worst, usable: true };
}
function faPressureScore(pressure) {
  if (!pressure) return { score: null, usable: false };
  let n = 0, acc = 0;
  for (const k of Object.keys(FA_PRESSURE_THRESHOLDS)) {
    const v = pressure[k]; if (typeof v !== "number" || !Number.isFinite(v)) continue;
    const r = FA_PRESSURE_THRESHOLDS[k]; acc += v >= r[1] ? 1 : v >= r[0] ? 0.5 : 0; n++;
  }
  if (n === 0) return { score: null, usable: false };
  return { score: acc / n, usable: true };
}
function faAggregate(signals, pressure) {
  const b = faBehavioralScore(signals || {});
  const p = faPressureScore(pressure);
  const parts = [];
  if (b.usable) parts.push([FA_BEHAVIORAL_VS_PRESSURE, b.score]);
  if (p.usable) parts.push([1 - FA_BEHAVIORAL_VS_PRESSURE, p.score]);
  let overall = 0;
  if (parts.length) { const ws = parts.reduce((a, x) => a + x[0], 0); overall = parts.reduce((a, x) => a + x[0] * x[1], 0) / ws; }
  const established = Object.keys(signals || {}).some((k) => signals[k] && signals[k].status === "established");
  let stage = "healthy";
  for (const sb of FA_STAGE_BANDS) { if (overall < sb[0]) { stage = sb[1]; break; } }
  return { score: overall, stage, behavioral: b.score, pressure: p.score, established, hasBehavioral: b.usable, hasPressure: p.usable };
}
// 'low' | 'elevated' | 'high' word for the pressure score (for the interpretation prompt).
function faPressureWord(p) { return p == null ? "unknown" : p >= 0.66 ? "high" : p >= 0.33 ? "elevated" : "low"; }

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
const KBSourceCopy = ({source}) => {
  const [copied, setCopied] = useState(false);
  if (!source) return null;
  const copy = (e) => {
    if (e) e.stopPropagation();
    try {
      if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(source);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }
    } catch (_e) {}
  };
  // Copy-to-clipboard control — never a live anchor. The analyst copies the DOI/
  // reference and opens it themselves; the app opens no browser.
  return (
    <div style={{display:"flex",alignItems:"center",gap:6,marginTop:6,flexWrap:"wrap"}}>
      <span style={{fontSize:9,color:C.tm,fontFamily:"'IBM Plex Mono',monospace",whiteSpace:"nowrap"}}>Source (copy)</span>
      <span style={{fontSize:9,color:C.tm,fontFamily:"'IBM Plex Mono',monospace",wordBreak:"break-all",userSelect:"all",flex:1,minWidth:120}}>{source}</span>
      <button onClick={copy} style={{padding:"2px 8px",background:"transparent",border:`1px solid ${copied?C.a:C.b}`,borderRadius:6,color:copied?C.a:C.tm,fontSize:9,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer",whiteSpace:"nowrap"}}>{copied?"Copied":"Copy"}</button>
    </div>
  );
};
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
// ║  MY SECURITY SECTION                                                    ║
// ║                                                                         ║
// ║  Self-service passwordless credential management for the currently      ║
// ║  authenticated analyst. Talks to /api/mfa/* — passkey/register-options, ║
// ║  passkey/register-verify, GET/DELETE passkeys, GET certs, certs/revoke  ║
// ║  — all scoped to req.user.id server-side; this component never accepts  ║
// ║  or sends a user_id parameter. Reuses the module-level WebAuthn         ║
// ║  helpers. There is no TOTP.                                             ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

function MyMfaSecuritySection() {
  const [passkeys, setPasskeys] = useState(null);   // null = not loaded
  const [certs, setCerts] = useState(null);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const loadPasskeys = async () => {
    const r = await api.get("/api/mfa/passkeys");
    setPasskeys(r && Array.isArray(r.passkeys) ? r.passkeys : []);
  };
  const loadCerts = async () => {
    const r = await api.get("/api/mfa/certs");
    setCerts(r && Array.isArray(r.certs) ? r.certs : []);
  };
  useEffect(()=>{ loadPasskeys().catch(()=>{}); loadCerts().catch(()=>{}); },[]);

  // Enroll a new passwordless passkey: fetch creation options, create the
  // credential in the renderer, and verify it server-side.
  const addPasskey = async () => {
    setBusy(true); setErr(""); setMsg("");
    try {
      const opt = await api.post("/api/mfa/passkey/register-options", { passwordless: true });
      if (!opt || opt.error || !opt.options || !opt.challengeToken) {
        setBusy(false);
        setErr(opt && opt.error ? String(opt.error) : "Could not start passkey enrollment.");
        return;
      }
      let cred;
      try { cred = await navigator.credentials.create({ publicKey: deserializeRegOptions(opt.options) }); }
      catch (_e) { setBusy(false); setErr("Passkey enrollment was cancelled or failed."); return; }
      if (!cred) { setBusy(false); setErr("No passkey was created."); return; }
      const r = await api.post("/api/mfa/passkey/register-verify", {
        response: serializeAttestation(cred),
        challengeToken: opt.challengeToken,
        passwordless: true,
        label: label.trim() || undefined,
      });
      setBusy(false);
      if (!r || r.error) {
        if (r && r.code === "ENROLL_PASSKEY_NOT_HARDWARE") {
          setErr("This passkey was not accepted. Use a hardware security key (a FIDO2 key or fob) that requires a PIN. Synced or software passkeys (iCloud Keychain, Google Password Manager, Windows Hello) cannot be used to sign in.");
        } else {
          setErr(r && r.error ? String(r.error) : "Passkey verification failed.");
        }
        return;
      }
      setMsg("Passkey enrolled — hardware security key verified."); setLabel(""); loadPasskeys().catch(()=>{});
    } catch (e) {
      setBusy(false);
      setErr(e.message || "Passkey enrollment failed.");
    }
  };

  // Remove a passkey. The server refuses if it is the user's last login
  // credential (409), surfaced as an error.
  const removePasskey = async (id) => {
    if (!window.confirm("Remove this passkey?")) return;
    setErr(""); setMsg("");
    const r = await api.del("/api/mfa/passkeys/" + id);
    if (r && r.removed) { setMsg("Passkey removed."); loadPasskeys().catch(()=>{}); }
    else { setErr(r && r.error ? String(r.error) : "Could not remove passkey."); }
  };

  const revokeCert = async (serial) => {
    if (!window.confirm("Revoke certificate " + serial + "? It can no longer secure your connection.")) return;
    setErr(""); setMsg("");
    const r = await api.post("/api/mfa/certs/revoke", { serial });
    if (r && r.revoked) { setMsg("Certificate " + serial + " revoked."); loadCerts().catch(()=>{}); }
    else { setErr(r && r.error ? String(r.error) : "Revocation failed."); }
  };

  return (
    <Card style={{marginBottom:16}}>
      <div style={{fontSize:13,fontWeight:500,color:C.t,marginBottom:6}}>My Security — Passkeys & Certificates</div>
      <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Manage your own phishing-resistant credentials. Sign-in uses a hardware FIDO2/WebAuthn passkey (a security key with a PIN) — there is no password. A client certificate secures your connection but is not a sign-in method. Keep at least one working passkey enrolled at all times.</M>

      <div style={{fontSize:12,fontWeight:500,color:C.t,marginBottom:8}}>Passkeys</div>
      {passkeys===null ? <M style={{color:C.td}}>Loading…</M> : passkeys.length===0 ? <M style={{color:C.td,display:"block",marginBottom:8}}>No passkeys enrolled.</M> : passkeys.map((k,i)=>(
        <div key={k.id||i} style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:8,padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
          <div style={{minWidth:0}}>
            <M style={{color:C.t,display:"block"}}>{String(k.credential_id||"").slice(0,16)}…{k.is_passwordless?"":" (second-factor)"}</M>
            <M style={{color:C.td,display:"block"}}>added {k.created_at?String(k.created_at).slice(0,10):"—"}{k.last_used_at?(" · last used "+String(k.last_used_at).slice(0,10)):" · never used"}</M>
          </div>
          <Btn small danger onClick={()=>removePasskey(k.id)}>Remove</Btn>
        </div>
      ))}
      <div style={{display:"flex",gap:8,alignItems:"flex-end",marginTop:10}}>
        <div style={{flex:1}}><Input label="New passkey label (optional)" value={label} onChange={e=>setLabel(e.target.value)} placeholder="e.g. YubiKey 5C" maxLength={64}/></div>
        <Btn primary onClick={addPasskey} disabled={busy}>{busy?"Working…":"Add a passkey"}</Btn>
      </div>

      <div style={{fontSize:12,fontWeight:500,color:C.t,margin:"18px 0 8px"}}>Transport Certificate (mTLS)</div>
      <M style={{color:C.td,display:"block",marginBottom:8,lineHeight:1.6}}>A client certificate secures your connection to the server (mutual TLS) and binds your session to this device. It is not a sign-in credential — sign-in is always your hardware passkey. Certificates are issued during provisioning or by an administrator; review them here and revoke one you no longer use or that may be compromised.</M>
      {certs===null ? <M style={{color:C.td}}>Loading…</M> : certs.length===0 ? <M style={{color:C.td}}>No certificates issued to you.</M> : certs.map((c,i)=>(
        <div key={c.serial||i} style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:8,padding:"8px 0",borderBottom:`1px solid ${C.b}`}}>
          <div style={{minWidth:0}}>
            <M style={{color:C.t,display:"block"}}>{c.subject||"(no subject)"}</M>
            <M style={{color:C.td,display:"block"}}>serial {c.serial} · {c.status}{c.expires_at?(" · exp "+String(c.expires_at).slice(0,10)):""}</M>
          </div>
          {c.status==="active" ? <Btn small danger onClick={()=>revokeCert(c.serial)}>Revoke</Btn> : <Badge color={c.status==="revoked"?C.d:C.tm}>{c.status}</Badge>}
        </div>
      ))}

      {msg&&<M style={{color:C.tm,display:"block",marginTop:12}}>{msg}</M>}
      {err&&<M style={{color:C.d,display:"block",marginTop:12}}>{err}</M>}
    </Card>
  );
}


// ═══════════════════════════════════════════════════════════════════════════════
// ANALYST CLIENT — Main Application Component
// ═══════════════════════════════════════════════════════════════════════════════
// ── WebAuthn (de)serialization helpers — passwordless login + enrollment ──────
// The server speaks base64url for every WebAuthn binary field; the browser
// WebAuthn API speaks ArrayBuffer. These convert between the two for the
// navigator.credentials get()/create() ceremonies. Self-contained, no deps.
function b64urlToBuf(s) {
  const str = s || "";
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function deserializeAuthOptions(options) {
  const o = { ...options };
  if (o.challenge) o.challenge = b64urlToBuf(o.challenge);
  if (Array.isArray(o.allowCredentials)) o.allowCredentials = o.allowCredentials.map(c => ({ ...c, id: b64urlToBuf(c.id) }));
  return o;
}
function serializeAssertion(cred) {
  const r = cred.response || {};
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      authenticatorData: bufToB64url(r.authenticatorData),
      signature: bufToB64url(r.signature),
      userHandle: r.userHandle ? bufToB64url(r.userHandle) : null,
    },
  };
}
function deserializeRegOptions(options) {
  const o = { ...options };
  if (o.challenge) o.challenge = b64urlToBuf(o.challenge);
  if (o.user && o.user.id) o.user = { ...o.user, id: b64urlToBuf(o.user.id) };
  if (Array.isArray(o.excludeCredentials)) o.excludeCredentials = o.excludeCredentials.map(c => ({ ...c, id: b64urlToBuf(c.id) }));
  return o;
}
function serializeAttestation(cred) {
  const r = cred.response || {};
  const out = {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      attestationObject: bufToB64url(r.attestationObject),
    },
  };
  try { if (typeof r.getTransports === "function") out.response.transports = r.getTransports(); } catch (_e) {}
  return out;
}

// ── ANALYST CLIENT LOGIN (passwordless: hardware FIDO2 passkey) ──────────────
// The analyst signs in with a hardware FIDO2/WebAuthn passkey (a security key
// with a PIN) against the FireAlive server (API_BASE). A client certificate
// secures the connection but is not a sign-in credential. There is no password
// and no TOTP. Before sign-in the analyst must trust the server's internal CA
// (paste the PEM) so the HTTPS/WSS connection validates. A first-time analyst
// redeems a one-time enrollment token (issued by the Management Console during
// provisioning) to enroll their first passkey, then signs in with it.
function AcLoginScreen({ onLoggedIn, logC }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [caStatus, setCaStatus] = useState(null);   // null=checking; { pinned, subject?, unmanaged? }
  const [caPem, setCaPem] = useState("");
  const [caImporting, setCaImporting] = useState(false);
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [enrollToken, setEnrollToken] = useState("");
  const [enrollBusy, setEnrollBusy] = useState(false);
  const [enrollMsg, setEnrollMsg] = useState("");

  const bridgeRef = () => (typeof window !== "undefined" ? window.firealive : null);

  // Whether the FireAlive CA is pinned in the main process. The renderer cannot
  // reach the server over HTTPS until it is, so an unpinned CA gates sign-in.
  useEffect(() => {
    const bridge = bridgeRef();
    if (!bridge || !bridge.invoke) { setCaStatus({ pinned: true, unmanaged: true }); return; }
    bridge.invoke("auth:caStatus").then(s => setCaStatus(s || { pinned: false })).catch(() => setCaStatus({ pinned: false }));
  }, []);

  // Bring up Signal-protocol E2EE for this session — identical to the previous
  // login path. Peer chat and lead chat are cryptographically separate Signal
  // domains; each needs its published pre-key bundle seeded (or one-time
  // pre-keys replenished when low) before a counterpart can establish a
  // session. Failures are logged, never fatal to login.
  const bootstrapE2EE = async (selfId) => {
    const bridge = bridgeRef();
    if (!bridge || !bridge.invoke || !selfId) return;
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

  // Persist the JWT, store the refresh token, bring up E2EE, and advance.
  // B5e (D25): challenge the server to prove control of its hardware instance
  // anchor. Mint a nonce, have the server sign it, and verify the response against
  // the pinned fingerprint via main. First enrollment pins trust-on-first-use.
  // "ok"/"unpinned" are safe to proceed; "mismatch"/"invalid" must block.
  const verifyServerAnchor = async () => {
    const bridge = bridgeRef();
    if (!bridge || typeof bridge.invoke !== "function") return { verdict: "ok", skipped: true };
    let nonceRes;
    try { nonceRes = await bridge.invoke("anticlone:anchorNonce"); }
    catch (_e) { return { verdict: "ok", skipped: true }; }
    const nonce = nonceRes && nonceRes.nonce;
    if (!nonce) return { verdict: "ok", skipped: true };
    const resp = await api.post("/api/instance/anchor-challenge", { nonce: nonce });
    if (!resp || resp.error || !resp.signature || !resp.publicKey || !resp.fingerprint) {
      return { verdict: "invalid", reason: "no anchor-challenge response" };
    }
    let v;
    try {
      v = await bridge.invoke("anticlone:verifyAnchor", { nonce: nonce, fingerprint: resp.fingerprint, publicKey: resp.publicKey, signature: resp.signature });
    } catch (_e) {
      return { verdict: "invalid", reason: "anchor verification error" };
    }
    if (v && v.verdict === "unpinned") {
      // B5f (D-B5f-4): first contact pins trust-on-first-use, but only after a
      // blocking operator confirmation. The operator compares this fingerprint
      // out of band with the value the server prints at startup; a deliberate
      // confirm pins it, and a declined or failed confirmation refuses.
      let confirm;
      try { confirm = await bridge.invoke("anticlone:confirmAnchorPin", { fingerprint: resp.fingerprint }); }
      catch (_e) { confirm = null; }
      if (!confirm || !confirm.confirmed) {
        return { verdict: "declined", reason: "operator did not confirm the server anchor fingerprint" };
      }
      let pin;
      try { pin = await bridge.invoke("anticlone:pinAnchor", { fingerprint: resp.fingerprint }); }
      catch (_e) { pin = null; }
      if (!pin || !pin.pinned) {
        return { verdict: "invalid", reason: (pin && pin.error) ? pin.error : "anchor pin failed" };
      }
      return { verdict: "ok", pinned: true };
    }
    return v || { verdict: "invalid", reason: "no verdict" };
  };

  const finalize = async (loginResponse, method) => {
    if (loginResponse && loginResponse.accessToken) api.setToken(loginResponse.accessToken);
    if (loginResponse && loginResponse.refreshToken) {
      try { localStorage.setItem("fa_ac_refresh_token", loginResponse.refreshToken); } catch (_e) {}
    }
    // B5e (D25): verify the server hardware anchor before trusting it with data.
    // A clone holds the same credentials but cannot sign with the anchor.
    const anchor = await verifyServerAnchor();
    if (anchor && (anchor.verdict === "mismatch" || anchor.verdict === "invalid" || anchor.verdict === "declined")) {
      api.setToken(null);
      setAnchorMismatch({ verdict: anchor.verdict, reason: anchor.reason || null });
      logC("SERVER_ANCHOR_REJECTED", "Server anchor not trusted (" + anchor.verdict + ")");
      return;
    }
    logC("LOGIN_SUCCESS", "Authenticated via " + method);
    const selfId = loginResponse && loginResponse.user ? loginResponse.user.id : null;
    bootstrapE2EE(selfId);
    onLoggedIn(selfId);
  };

  const handlePasskeyLogin = async () => {
    setBusy(true); setError("");
    try {
      const opt = await api.post("/api/auth/login-webauthn/options", {});
      if (!opt || opt.error || !opt.options || !opt.challengeToken) {
        setBusy(false);
        setError(opt && opt.error ? String(opt.error) : "Could not start passkey sign-in.");
        return;
      }
      let assertion;
      try { assertion = await navigator.credentials.get({ publicKey: deserializeAuthOptions(opt.options) }); }
      catch (_e) { setBusy(false); setError("Passkey sign-in was cancelled or failed."); return; }
      if (!assertion) { setBusy(false); setError("No passkey was returned."); return; }
      const r = await api.post("/api/auth/login-webauthn/verify", { response: serializeAssertion(assertion), challengeToken: opt.challengeToken });
      setBusy(false);
      if (!r || r.error || !r.accessToken) { setError(r && r.error ? String(r.error) : "Passkey sign-in failed."); return; }
      await finalize(r, "passkey");
    } catch (e) { setBusy(false); setError(e.message || "Passkey sign-in failed."); }
  };

  const handleImportCa = async () => {
    const bridge = bridgeRef();
    if (!bridge || !bridge.invoke) { setError("Certificate import is unavailable in this environment."); return; }
    if (!caPem.trim()) { setError("Paste the FireAlive CA certificate (PEM)."); return; }
    setCaImporting(true); setError("");
    try {
      const res = await bridge.invoke("auth:importCaCert", { pem: caPem.trim() });
      setCaImporting(false);
      if (res && res.ok === false) { setError(res.error ? String(res.error) : "Could not import the CA certificate."); return; }
      const s = await bridge.invoke("auth:caStatus").catch(() => null);
      setCaStatus(s || { pinned: true });
      setCaPem("");
    } catch (e) { setCaImporting(false); setError(e.message || "Could not import the CA certificate."); }
  };

  const handleEnrollRedeem = async () => {
    const token = enrollToken.trim();
    if (!token) { setEnrollMsg("Enter your enrollment token."); return; }
    setEnrollBusy(true); setEnrollMsg("");
    try {
      const opt = await api.post("/api/auth/enroll/passkey/options", { enrollment_token: token });
      if (!opt || opt.error || !opt.options || !opt.challengeToken) {
        setEnrollBusy(false);
        setEnrollMsg(opt && opt.error ? String(opt.error) : "Could not start enrollment. The token may be invalid or expired.");
        return;
      }
      let cred;
      try { cred = await navigator.credentials.create({ publicKey: deserializeRegOptions(opt.options) }); }
      catch (_e) { setEnrollBusy(false); setEnrollMsg("Passkey creation was cancelled or failed."); return; }
      if (!cred) { setEnrollBusy(false); setEnrollMsg("No passkey was created."); return; }
      const r = await api.post("/api/auth/enroll/passkey/verify", { enrollment_token: token, response: serializeAttestation(cred), challengeToken: opt.challengeToken });
      setEnrollBusy(false);
      if (!r || r.error || !r.enrolled) { setEnrollMsg(r && r.error ? String(r.error) : "Enrollment verification failed."); return; }
      setEnrollMsg("Passkey enrolled. You can now sign in with it.");
      setEnrollToken("");
    } catch (e) { setEnrollBusy(false); setEnrollMsg(e.message || "Enrollment failed."); }
  };

  const caUnpinned = caStatus && caStatus.pinned === false;

  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",padding:20}}>
      <div style={{width:"100%",maxWidth:420}}>
        <div style={{textAlign:"center",marginBottom:24}}>
          <div style={{fontSize:22,fontWeight:700,color:C.t,fontFamily:"'Fraunces',serif"}}>FireAlive</div>
          <M style={{color:C.tm,display:"block",marginTop:4}}>Analyst Client — Sign In</M>
        </div>
        <Card>
          {caStatus === null ? (
            <M style={{color:C.td}}>Checking secure connection…</M>
          ) : caUnpinned ? (
            <div>
              <div style={{fontSize:13,fontWeight:600,color:C.t,marginBottom:6}}>Trust the FireAlive server</div>
              <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Before you can sign in, paste your organization's FireAlive CA certificate (PEM) to establish a trusted, encrypted connection.</M>
              <textarea value={caPem} onChange={e=>setCaPem(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" rows={6} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:11,fontFamily:"'IBM Plex Mono',monospace",resize:"vertical",marginBottom:12}}/>
              <Btn primary style={{width:"100%"}} onClick={handleImportCa} disabled={caImporting}>{caImporting?"Importing…":"Import CA certificate"}</Btn>
              {error && <M style={{color:C.d,display:"block",marginTop:12}}>{error}</M>}
            </div>
          ) : (
            <div>
              <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Sign in with your hardware security key (a FIDO2 passkey with a PIN). There is no password.</M>
              <Btn primary style={{width:"100%"}} onClick={handlePasskeyLogin} disabled={busy}>{busy?"Working…":"Sign in with a passkey"}</Btn>
              {error && <M style={{color:C.d,display:"block",marginTop:14}}>{error}</M>}

              <div style={{borderTop:`1px solid ${C.b}`,marginTop:18,paddingTop:14}}>
                <button onClick={()=>{setEnrollOpen(!enrollOpen);setEnrollMsg("");}} style={{width:"100%",padding:8,background:"transparent",border:"none",color:C.tm,fontSize:11,cursor:"pointer",textDecoration:"underline"}}>{enrollOpen?"Hide first-time setup":"First time here? Redeem an enrollment token"}</button>
                {enrollOpen && (
                  <div style={{marginTop:10}}>
                    <M style={{color:C.td,display:"block",marginBottom:8,lineHeight:1.6}}>Paste the one-time enrollment token from your provisioning email to enroll your first passkey.</M>
                    <Input label="Enrollment token" value={enrollToken} onChange={e=>setEnrollToken(e.target.value)} placeholder="paste token" maxLength={512} disabled={enrollBusy}/>
                    <Btn primary style={{width:"100%"}} onClick={handleEnrollRedeem} disabled={enrollBusy}>{enrollBusy?"Enrolling…":"Enroll my passkey"}</Btn>
                    {enrollMsg && <M style={{color:C.tm,display:"block",marginTop:10}}>{enrollMsg}</M>}
                  </div>
                )}
              </div>

              {caStatus && caStatus.pinned && !caStatus.unmanaged && caStatus.subject && (
                <M style={{color:C.td,display:"block",marginTop:14}}>Trusted CA: {caStatus.subject}</M>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

// -- B5d1: Analyst-private key enrollment / unlock gate -----------------------
// Runs once after login, before the dashboard renders. If no key is enrolled it
// creates one (services analyst-crypto key custody, main process), trying a
// WebAuthn PRF assertion first and falling back to OS secure storage; it then
// registers the public key + recovery wraps with the server and shows the
// one-time recovery code. If a key exists but is locked it unlocks it for the
// session (a passkey touch, a passphrase, or automatically for safeStorage).
// In a plain browser (no Electron bridge) it is a no-op so the app still loads.
function BurnoutKeyGate({ userId, onReady, logC }) {
  const [phase, setPhase] = useState("checking"); // checking | enroll | unlock | recovery | error
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [mode, setMode] = useState(null);
  const [passphrase, setPassphrase] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [acked, setAcked] = useState(false);
  const [recoveryCodeInput, setRecoveryCodeInput] = useState("");
  const [serverKey, setServerKey] = useState(null); // server key + wraps, set when recovering on a re-provisioned device

  const bridge = (typeof window !== "undefined") ? window.firealive : null;
  const done = useRef(false);
  const finish = function () { if (!done.current) { done.current = true; onReady(); } };

  // Try a WebAuthn PRF assertion; returns base64 PRF bytes, or null if the
  // authenticator/runtime does not support PRF (then we use OS secure storage).
  async function tryPrf() {
    try {
      if (!(typeof navigator !== "undefined" && navigator.credentials && navigator.credentials.get)) return null;
      const salt = new TextEncoder().encode("firealive-burnout-prf-v1");
      const challenge = (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues)
        ? window.crypto.getRandomValues(new Uint8Array(32)) : new Uint8Array(32);
      const assertion = await navigator.credentials.get({ publicKey: { challenge: challenge, userVerification: "required", timeout: 60000, extensions: { prf: { eval: { first: salt } } } } });
      const ext = (assertion && assertion.getClientExtensionResults) ? assertion.getClientExtensionResults() : null;
      const first = (ext && ext.prf && ext.prf.results) ? ext.prf.results.first : null;
      if (!first) return null;
      return btoa(String.fromCharCode.apply(null, new Uint8Array(first)));
    } catch (_e) { return null; }
  }

  async function autoUnlockSafeStorage() {
    const res = await bridge.invoke("burnout:unlockKey", { userId: userId });
    if (res && res.ok) { if (logC) logC("BURNOUT_KEY_UNLOCKED", "Unlocked analyst-private key"); finish(); }
    else { setMode("safestorage"); setPhase("unlock"); setMsg(res && res.error ? res.error : "Could not unlock your key automatically."); }
  }

  const recheck = async function () {
    if (!bridge || !bridge.invoke || !userId) { finish(); return; }
    setPhase("checking"); setMsg("");
    const st = await bridge.invoke("burnout:status", { userId: userId }).catch(function () { return null; });
    if (!st || st.error) { setPhase("error"); setMsg(st && st.error ? st.error : "Could not check your key status."); return; }
    if (st.enrolled && st.unlocked) { finish(); return; }
    if (st.enrolled) { setMode(st.mode || null); if (st.mode === "safestorage") { autoUnlockSafeStorage(); } else { setPhase("unlock"); } }
    else {
      // Not enrolled on THIS device. If the server already holds a key for this
      // analyst (a re-provisioned machine), recover and re-wrap it rather than
      // minting a new key that would orphan the server's sealed data.
      const sk = await api.get("/api/analyst-keys/me").catch(function () { return null; });
      if (sk && !sk.error && sk.enrolled && sk.public_key) { setServerKey(sk); setPhase("recover"); }
      else { setPhase("enroll"); }
    }

  };

  useEffect(function () { recheck(); }, []);

  async function doEnroll() {
    setBusy(true); setMsg("");
    const prfSecret = await tryPrf();
    const res = await bridge.invoke("burnout:enrollKey", { userId: userId, prfSecret: prfSecret, withRecoveryCode: true });
    if (!res || res.error) { setBusy(false); setMsg(res && res.error ? res.error : "Enrollment failed."); return; }
    const reg = await api.post("/api/analyst-keys/register", { public_key: res.public_key, recovery_wraps: res.recovery_wraps });
    if (!reg || reg.error) { setBusy(false); setMsg(reg && reg.error ? String(reg.error) : "Could not register your key with the server."); return; }
    if (logC) logC("BURNOUT_KEY_ENROLLED", "Enrolled analyst-private key (" + (res.mode || "safestorage") + ")");
    setBusy(false);
    if (res.recoveryCode) { setRecoveryCode(res.recoveryCode); setPhase("recovery"); }
    else { finish(); }
  }

  async function doRecover() {
    setBusy(true); setMsg("");
    const code = (recoveryCodeInput || "").trim();
    if (!code) { setBusy(false); setMsg("Enter your recovery code."); return; }
    const wraps = (serverKey && Array.isArray(serverKey.recovery_wraps)) ? serverKey.recovery_wraps : [];
    const rcWrap = wraps.find(function (w) { return w && w.factor === "recovery_code"; });
    if (!rcWrap || !rcWrap.wrapped_sk) { setBusy(false); setMsg("No recovery-code factor is registered for your account. Contact your administrator."); return; }
    const prfSecret = await tryPrf();
    if (!prfSecret) { setBusy(false); setMsg("Could not get a passkey response. Confirm with your passkey and try again."); return; }
    const rec = await bridge.invoke("burnout:recoverAndRewrap", { userId: userId, recoveryWrap: rcWrap.wrapped_sk, recoveryCode: code, newPrfSecret: prfSecret, expectedPublicKey: serverKey.public_key, keyVersion: serverKey.key_version || 1 });
    if (!rec || rec.error) { setBusy(false); setMsg(rec && rec.error ? String(rec.error) : "Recovery failed."); return; }
    // Replace the dead prf_primary wrap server-side, keeping the still-valid
    // recovery-code and backup wraps (same key, so they remain usable).
    const kept = wraps.filter(function (w) { return w && w.factor !== "prf_primary"; }).map(function (w) { return { factor: w.factor, wrapped_sk: w.wrapped_sk, label: w.label, key_version: w.key_version }; });
    const newWraps = (rec.recovery_wraps || []).concat(kept);
    const reg = await api.post("/api/analyst-keys/register", { public_key: rec.public_key, recovery_wraps: newWraps });
    if (!reg || reg.error) { setBusy(false); setMsg(reg && reg.error ? String(reg.error) : "Recovered on this device but could not update the server. Please try again."); return; }
    if (logC) logC("BURNOUT_KEY_RECOVERED", "Recovered and re-wrapped analyst-private key on a re-provisioned device");
    setBusy(false); finish();
  }


  async function doUnlock() {
    setBusy(true); setMsg("");
    let prfSecret = null; let pass = null;
    if (mode === "prf") { prfSecret = await tryPrf(); if (!prfSecret) { setBusy(false); setMsg("Could not get a passkey response. Please try again."); return; } }
    else if (mode === "passphrase") { if (!passphrase) { setBusy(false); setMsg("Enter your passphrase."); return; } pass = passphrase; }
    const res = await bridge.invoke("burnout:unlockKey", { userId: userId, prfSecret: prfSecret, passphrase: pass });
    if (!res || res.error) { setBusy(false); setMsg(res && res.error ? res.error : "Unlock failed."); return; }
    if (logC) logC("BURNOUT_KEY_UNLOCKED", "Unlocked analyst-private key");
    setBusy(false); finish();
  }

  const Shell = function (inner) {
    return (<div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center"}}><style>{CSS}</style><div style={{width:520,padding:36,background:C.s,border:"1px solid "+C.b,borderRadius:16}}>{inner}</div></div>);
  };

  if (phase === "checking") return Shell(<M style={{color:C.tm}}>Checking your private-data key{"\u2026"}</M>);

  if (phase === "error") return Shell(<div>
    <L>Private-data key</L>
    <M style={{color:C.d,display:"block",margin:"12px 0",lineHeight:1.6}}>{msg}</M>
    <Btn onClick={recheck}>Retry</Btn>
  </div>);

  if (phase === "enroll") return Shell(<div>
    <L>Protect your wellbeing data</L>
    <M style={{color:C.tm,display:"block",margin:"12px 0 18px",lineHeight:1.7}}>FireAlive will create a key on this device so your individual wellbeing signals are sealed to you alone. The server stores them only as ciphertext it cannot read, and they are decrypted only here, on your device. If your authenticator supports it the key is bound to your hardware passkey; otherwise it is sealed in this machine's secure storage.</M>
    {msg ? <M style={{color:C.d,display:"block",marginBottom:12,lineHeight:1.5}}>{msg}</M> : null}
    <Btn primary disabled={busy} onClick={doEnroll}>{busy ? "Setting up\u2026" : "Set up my key"}</Btn>
  </div>);

  if (phase === "recovery") return Shell(<div>
    <L>Save your recovery code</L>
    <M style={{color:C.tm,display:"block",margin:"12px 0 12px",lineHeight:1.7}}>This one-time code is the only way to restore your sealed wellbeing data if you move to a new device or lose your authenticator. It is shown once and is stored nowhere in readable form -- not by you, not by the server, not by your administrator.</M>
    <div style={{padding:"12px 14px",background:C.dd,border:"1px solid "+C.d,borderRadius:10,marginBottom:14}}><M style={{color:C.d,display:"block",lineHeight:1.6,fontWeight:600}}>If you lose this code and also lose access to this device's passkey, your burnout history and baseline cannot be recovered by anyone. Your helper-pay points and training records are unaffected and return regardless.</M></div>
    <div style={{padding:14,background:"rgba(255,255,255,0.04)",border:"1px solid "+C.b,borderRadius:10,fontFamily:"'IBM Plex Mono',monospace",fontSize:15,letterSpacing:1,color:C.t,wordBreak:"break-all",marginBottom:16}}>{recoveryCode}</div>
    <label style={{display:"flex",alignItems:"center",gap:8,marginBottom:16,cursor:"pointer"}}><input type="checkbox" checked={acked} onChange={function (e) { setAcked(e.target.checked); }}/><M style={{color:C.tm}}>I have saved my recovery code.</M></label>
    <Btn primary disabled={!acked} onClick={finish}>Continue</Btn>
  </div>);

  if (phase === "recover") return Shell(<div>
    <L>Restore your wellbeing data</L>
    <M style={{color:C.tm,display:"block",margin:"12px 0 14px",lineHeight:1.7}}>This device was re-provisioned, so your private-data key is not on it yet. Enter the one-time recovery code you saved when you first set up FireAlive, then confirm with your passkey. Your existing sealed wellbeing history is restored -- the key is recovered, not replaced.</M>
    <Input label="Recovery code" value={recoveryCodeInput} onChange={function (e) { setRecoveryCodeInput(e.target.value); }} disabled={busy}/>
    {msg ? <M style={{color:C.d,display:"block",margin:"12px 0",lineHeight:1.5}}>{msg}</M> : null}
    <Btn primary disabled={busy} onClick={doRecover}>{busy ? "Restoring..." : "Restore with recovery code"}</Btn>
  </div>);

  return Shell(<div>
    <L>Unlock your wellbeing data</L>
    <M style={{color:C.tm,display:"block",margin:"12px 0 18px",lineHeight:1.7}}>{mode === "prf" ? "Confirm with your passkey to unlock your private wellbeing data for this session." : "Enter your passphrase to unlock your private wellbeing data for this session."}</M>
    {mode === "passphrase" ? <Input label="Passphrase" type="password" value={passphrase} onChange={function (e) { setPassphrase(e.target.value); }} disabled={busy}/> : null}
    {msg ? <M style={{color:C.d,display:"block",marginBottom:12,lineHeight:1.5}}>{msg}</M> : null}
    <Btn primary disabled={busy} onClick={doUnlock}>{busy ? "Unlocking\u2026" : (mode === "prf" ? "Unlock with passkey" : "Unlock")}</Btn>
  </div>);
}

// ── First-run deployment-mode selection (D9) ────────────────────────────────
// Shown once, before login, when no local deployment-mode selection exists.
// The choice is advisory and stored locally (the server's anchor-sealed mode
// is authoritative); it lets the app apply the right virtualization tolerances.
function DeploymentSetup({ onComplete }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [pickSubstrate, setPickSubstrate] = useState(false);
  const choose = async (mode, substrate) => {
    setErr(""); setBusy(true);
    try {
      const bridge = (typeof window !== "undefined") ? window.firealive : null;
      if (!bridge || typeof bridge.invoke !== "function") { onComplete(); return; }
      const r = await bridge.invoke("deployment:setLocalMode", { mode: mode, substrate: substrate });
      if (r && r.error) { setErr(r.error); setBusy(false); return; }
      onComplete();
    } catch (e) {
      setErr(e && e.message ? e.message : "could not save selection");
      setBusy(false);
    }
  };
  const card = (key, title, desc, onClick) => (
    <button key={key} onClick={onClick} disabled={busy} style={{textAlign:"left",padding:"18px 20px",background:C.s,border:`1px solid ${C.b}`,borderRadius:10,color:C.t,cursor:busy?"default":"pointer",opacity:busy?0.6:1,display:"flex",flexDirection:"column",gap:6,maxWidth:420}}>
      <span style={{fontSize:13,fontWeight:600,color:C.t}}>{title}</span>
      <M style={{color:C.tm,fontSize:10,lineHeight:1.5}}>{desc}</M>
    </button>
  );
  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:18,padding:24}}>
      {!pickSubstrate ? (
        <>
          <div style={{textAlign:"center",display:"flex",flexDirection:"column",gap:8,maxWidth:460}}>
            <M style={{color:C.a,fontSize:11,letterSpacing:1}}>FIREALIVE SETUP</M>
            <div style={{color:C.t,fontSize:20,fontWeight:600}}>Select deployment mode</div>
            <M style={{color:C.tm,fontSize:11,lineHeight:1.6}}>Choose how this deployment runs. This sets local virtualization tolerances and is confirmed against the server.</M>
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {card("bare-metal","Bare metal","Dedicated physical hardware. Strictest identity enforcement; no live-migration allowances.",()=>choose("bare-metal"))}
            {card("virtualized","Virtualized","Runs in a VM or hypervisor. Allows authorized live migration (vMotion) while still refusing clones.",()=>choose("virtualized"))}
            {card("cloud","Cloud","Confidential VM on AWS, Azure, or GCP with a vTPM root of trust. Requires confidential computing, attested at boot; refuses spot and autoscaled instances.",()=>choose("cloud"))}
            {card("sdn","SDN","Software-defined network spanning multiple sites or clouds. Integrates read-only with the SDN controller; admits FireAlive's own components only from the permitted network segments.",()=>{setErr("");setPickSubstrate("sdn");})}
            {card("sase","SASE / ZTNA","Private (dark) application behind your organization's ZTNA/SASE edge. Reachable only through the connector, with FireAlive's device-bound mTLS preserved end-to-end; refuses clientless TLS-terminating access.",()=>{setErr("");setPickSubstrate("sase");})}
          </div>
        </>
      ) : (
        <>
          <div style={{textAlign:"center",display:"flex",flexDirection:"column",gap:8,maxWidth:460}}>
            <M style={{color:C.a,fontSize:11,letterSpacing:1}}>{"FIREALIVE SETUP / " + (pickSubstrate === "sase" ? "SASE" : "SDN")}</M>
            <div style={{color:C.t,fontSize:20,fontWeight:600}}>{"What does the " + (pickSubstrate === "sase" ? "SASE" : "SDN") + " host run on?"}</div>
            <M style={{color:C.tm,fontSize:11,lineHeight:1.6}}>The substrate sets this host's identity and snapshot tolerances. It is confirmed against the server, which fails closed if the declared substrate is weaker than what it detects.</M>
          </div>
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {card(pickSubstrate + "-bare-metal","Bare metal","Dedicated physical hardware with a hardware TPM. Strictest identity enforcement; no snapshot or live-migration allowances.",()=>choose(pickSubstrate,"bare-metal"))}
            {card(pickSubstrate + "-virtualized","Virtualized","A VM or hypervisor with a vTPM. Adds snapshot and clock-jump tolerances; quarantines a host that looks cloned or rolled back.",()=>choose(pickSubstrate,"virtualized"))}
            {card(pickSubstrate + "-cloud","Cloud","A confidential VM on AWS, Azure, or GCP. Requires confidential computing, attested at boot; refuses spot and autoscaled instances.",()=>choose(pickSubstrate,"cloud"))}
          </div>
          <button onClick={()=>{setErr("");setPickSubstrate(false);}} disabled={busy} style={{background:"none",border:"none",color:C.tm,fontSize:10,cursor:busy?"default":"pointer",textDecoration:"underline",padding:4}}>Back to deployment mode</button>
        </>
      )}
      {err && <M style={{color:C.d,fontSize:10}}>{err}</M>}
    </div>
  );
}

export default function AnalystClientApp() {
  const [stage, setStage] = useState("login");
  const [deployMode, setDeployMode] = useState(undefined); // undefined = checking
  useEffect(()=>{
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || typeof bridge.invoke !== "function") { setDeployMode({ configured: true, unmanaged: true }); return; }
    bridge.invoke("deployment:getLocalMode")
      .then(d=>setDeployMode(d || { configured: false }))
      .catch(()=>setDeployMode({ configured: true, unmanaged: true }));
  },[]);
  const [selfUserId, setSelfUserId] = useState(null);
  const [burnoutReady, setBurnoutReady] = useState(false); // login → welcome → app
  const [username, setUsername] = useState("");
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
  // B5d4: lead-set signal-refresh cadence (pushed over WS on connect and on
  // save) plus a counter the cadence timer and urgent-refresh bump to re-pull
  // signals. intervalMin drives the timer; the rest is forward-compatible.
  const [syncCadence, setSyncCadence] = useState({ intervalMin: 15, adaptiveSync: true, urgentThresholdSec: 30, batchMode: true });
  const [signalRefreshTrigger, setSignalRefreshTrigger] = useState(0);
  // B5e: set when the server echoes a ratchet behind what this AC saw (clone/rollback)
  const [serverRollback, setServerRollback] = useState(null);
  // B5e: set when the server signals this deployment was quarantined (re-enroll)
  const [reenrollRequired, setReenrollRequired] = useState(null);
  // B5e (D25): set when the server fails hardware-anchor attestation (clone)
  const [anchorMismatch, setAnchorMismatch] = useState(null);

  React.useEffect(() => { const iv = setInterval(() => api.post("/api/heartbeat", {}), 30000); return () => clearInterval(iv); }, []);

  // B4: live socket handle so a manually-run self-scan can report its signed
  // result to the management console over the same authenticated channel.
  const acScanWsRef = React.useRef(null);
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
    let serverRollbackHalt = false;
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
        acScanWsRef.current = ws;
        // B5e: present the highest server ratchet this AC has seen so the server
        // can detect a cloned or forked AC. Fall back to a plain auth if the
        // bridge has no invoke (older preload) so login still works.
        const sendAuth = (acRatchet) => {
          try { ws.send(JSON.stringify({ type: "auth", token: api._token, acRatchet: acRatchet })); } catch (_e) {}
        };
        if (bridge && typeof bridge.invoke === "function") {
          bridge.invoke("anticlone:ratchetState")
            .then((r) => { sendAuth(r && r.lastSeen != null ? r.lastSeen : null); })
            .catch(() => { sendAuth(null); });
        } else {
          sendAuth(null);
        }
      };
      ws.onmessage = (evt) => {
        let msg;
        try { msg = JSON.parse(evt.data); } catch (_e) { return; }
        // B5e (D20): the server gates the session on a device-key proof. On an
        // auth_challenge, sign the nonce on-chip through main and answer with an
        // auth_proof frame. If signing is unavailable or fails, close the socket;
        // the session must not form without the proof (fail closed).
        if (msg && msg.type === "auth_challenge") {
          if (bridge && typeof bridge.invoke === "function") {
            bridge.invoke("device:signSessionChallenge", { nonce: msg.nonce })
              .then((res) => {
                if (res && res.signature) {
                  try { ws.send(JSON.stringify({ type: "auth_proof", signature: res.signature })); } catch (_e) {}
                } else {
                  try { ws.close(4002, "device key proof unavailable"); } catch (_e) {}
                }
              })
              .catch(() => { try { ws.close(4002, "device key proof failed"); } catch (_e) {} });
          } else {
            try { ws.close(4002, "device key proof unavailable"); } catch (_e) {}
          }
        }

        // B5e: on auth_ok the server echoes its ratchet counter. A value BELOW
        // what this AC last saw means the server rolled back or was cloned --
        // halt reconnects, block the session, and refuse to trust this server.
        if (msg && msg.type === "auth_ok") {
          if (bridge && typeof bridge.invoke === "function") {
            bridge.invoke("anticlone:recordRatchet", { echoedCounter: msg.acRatchet != null ? msg.acRatchet : null })
              .then((res) => {
                if (res && res.verdict === "rollback") {
                  serverRollbackHalt = true;
                  setServerRollback({ lastSeen: res.lastSeen, echoed: res.echoed });
                  try { ws.close(4001, "server ratchet rollback"); } catch (_e) {}
                }
              }).catch(() => {});
          }
        }
        if (msg && msg.type === "desktop_notify" && msg.payload) {
          try { bridge.send("notify:desktop", msg.payload); } catch (_e) {}
        }
        // U1: live feature-toggle propagation - adopt the broadcast state.
        if (msg && msg.type === "feature_toggles_updated" && msg.features) {
          setFT(msg.features);
        }
        // B4: MC-orchestrated compromise scan. Run the local self-scan in the
        // main process and return the device-signed result over this socket.
        if (msg && msg.type === "orchestrate_scan") {
          bridge.invoke("selfscan:run", { runId: msg.runId || null, manifest: msg.manifest || null, expectedConfig: msg.expectedConfig || null, token: api._token })
            .then((result) => {
              if (result && !result.error) {
                try { ws.send(JSON.stringify({ type: "scan_result", runId: msg.runId || null, result: result })); } catch (_e) {}
              }
            }).catch(() => {});
        }
        // B5d4: MC-orchestrated fleet op. config_resync and update_push are
        // command-only (acked without a signature); the rest run in the main
        // process and return a device-signed result over this socket.
        if (msg && msg.type === "client_op") {
          const opType = msg.opType || null;
          if (opType === "config_resync" || opType === "update_push") {
            if (opType === "config_resync") {
              try { api.get("/api/features").then((r) => { if (r && r.features) setFT(r.features); }).catch(() => {}); } catch (_e) {}
              setSignalRefreshTrigger((n) => n + 1);
            }
            try { ws.send(JSON.stringify({ type: "client_op_result", runId: msg.runId || null, result: { runId: msg.runId || "", opType: opType, started_at: new Date().toISOString(), duration_ms: 0, status: "ack", detail_json: "{}" } })); } catch (_e) {}
          } else {
            const sendResult = (params) => bridge.invoke("clientop:run", { runId: msg.runId || null, opType: opType, params: params })
              .then((result) => { if (result && !result.error) { try { ws.send(JSON.stringify({ type: "client_op_result", runId: msg.runId || null, result: result })); } catch (_e) {} } }).catch(() => {});
            if (opType === "regression") {
              (async () => {
                const conn = {};
                try { const r = await fetch(API_BASE + "/api/heartbeat", { method: "POST", headers: await api.authHeaders("POST", "/api/heartbeat") }); conn.server = r.ok; } catch (_e) { conn.server = false; }
                sendResult(Object.assign({}, msg.params || {}, { connectivity: conn }));
              })();
            } else {
              sendResult(msg.params || {});
            }
          }
        }
        // B5d4: server-side teardown wipe. Best-effort local wipe of the four
        // machine-local files; the server credential revocation is the real
        // guarantee.
        if (msg && msg.type === "wipe_local") {
          try { bridge.invoke("recovery:wipeLocal").catch(() => {}); } catch (_e) {}
        }
        // B5d4: lead-set signal-refresh cadence (on connect and on save).
        if (msg && msg.type === "sync_cadence" && msg.cadence) {
          setSyncCadence(msg.cadence);
        }
        // B5d4: urgent refresh (panic engaged or a critical alert) -- re-pull now.
        if (msg && msg.type === "urgent_refresh") {
          setSignalRefreshTrigger((n) => n + 1);
        }
        // B5e: the server reports this deployment was quarantined (a clone, fork,
        // or rollback was detected). Surface a blocking notice routing the analyst
        // to re-enroll via their team lead.
        if (msg && msg.type === "reenroll_required") {
          setReenrollRequired({ reason: msg.reason || null, at: msg.at || null });
        }

      };
      ws.onclose = () => { acScanWsRef.current = null; if (!closedByUnmount && !serverRollbackHalt) scheduleReconnect(); };
      ws.onerror = () => { try { ws.close(); } catch (_e) {} };
    }

    connect();

    return () => {
      closedByUnmount = true;
      clearTimeout(reconnectTimer);
      if (ws) { try { ws.close(); } catch (_e) {} }
    };
  }, [stage]);

  // ── B4: device signing-key registration ────────────────────────────────
  // On reaching the authenticated app stage, register this client's Ed25519
  // device public key with the server so it can verify signed self-scan
  // reports. The private key never leaves the main process. No-op without the
  // Electron bridge; harmless if already registered (the server upserts).
  React.useEffect(() => {
    if (stage !== "app") return;
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || typeof bridge.invoke !== "function") return;
    let cancelled = false;
    bridge.invoke("selfscan:getPublicKey").then((k) => {
      if (cancelled || !k || k.error || !k.publicKey) return;
      api.post("/api/compromise/device-key", { publicKey: k.publicKey, fingerprint: k.fingerprint }).catch(() => {});
    }).catch(() => {});
    return () => { cancelled = true; };
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
    {id:"skills",label:"Skills & Assessments"},{id:"training",label:"Training & Certs"},{id:"recovery",label:"Post-Incident Wellness"},{id:"kb",label:"Knowledge Base"},
    {id:"scan",label:"Self-Scan"},{id:"audit_tab",label:"Audit"},{id:"privacy",label:"Privacy"},
  ];

  // ── Signals ──
  // ── My Signals (B5d1 PR D): every value is derived on-device by decrypting the
  // analyst's own sealed snapshots -- no placeholders. `signals` is keyed by
  // BEHAVIORAL_ORDER; each entry is BEHAVIORAL_META plus the computed
  // { status, n, cur, base, driftPct, band }. `pressure` is live operational load
  // (lead-visible), returned in the clear by /api/signals/me. ──
  const [signals, setSignals] = useState({});
  const [pressure, setPressure] = useState(null);
  const [kbEntry, setKbEntry] = useState(null);
  const [kbFilter, setKbFilter] = useState("all");
  const [kbChatMsgs, setKbChatMsgs] = useState([]);
  const [kbChatInput, setKbChatInput] = useState("");
  const [kbChatLoading, setKbChatLoading] = useState(false);
  const [kbModelStatus, setKbModelStatus] = useState(null);
  const [kbVerifying, setKbVerifying] = useState(false);
  const [kbProvisioning, setKbProvisioning] = useState(null);
  const [kbModelScan, setKbModelScan] = useState(null);
  const kbBridge = () => (typeof window !== "undefined" ? window.firealive : null);
  // Lightweight, on-device check for acute-distress cues. This assistant is for
  // research education, not crisis support — on a hit we route to Post-Incident
  // Wellness instead of sending anything to the model. Conservative first-person
  // phrase list; no method terms.
  const detectDistress = (text) => {
    const t = (text || "").toLowerCase();
    return ["suicid", "kill myself", "want to die", "end my life", "end it all", "no reason to live", "can't go on", "cant go on", "hurt myself", "harm myself", "self-harm", "self harm"].some((p) => t.includes(p));
  };
  // The analyst's own signals, summarized locally and passed ONLY to the on-device
  // model as private grounding background. Never sent to any server.
  const buildSignalsContext = () => {
    try {
      return BEHAVIORAL_ORDER.filter((k) => signals[k] && signals[k].cur != null).map((k) => {
        const s = signals[k];
        if (s.status === "established" && s.base != null) return `${s.label}: ${faNum(s.cur)}${s.u} (your baseline ${faNum(s.base)}${s.u})`;
        return `${s.label}: ${faNum(s.cur)}${s.u} (baseline establishing)`;
      }).join("; ");
    } catch (_e) { return ""; }
  };
  const refreshKbModelStatus = async () => {
    const b = kbBridge();
    if (!b) { setKbModelStatus({ available: false, noBridge: true }); return; }
    try { setKbModelStatus(await b.invoke("kbChat:modelStatus", {})); }
    catch (_e) { setKbModelStatus({ available: false }); }
    try { setKbModelScan(await b.invoke("kbChat:modelScanStatus", {})); }
    catch (_e) {}
  };
  const verifyKbModels = async () => {
    const b = kbBridge();
    if (!b || kbVerifying) return;
    setKbVerifying(true);
    try {
      await b.invoke("kbChat:verifyModel", { which: "embed" });
      await b.invoke("kbChat:verifyModel", { which: "chat" });
    } catch (_e) {}
    await refreshKbModelStatus();
    setKbVerifying(false);
  };
  const showKbProvisioning = async () => {
    const b = kbBridge();
    if (!b) return;
    try { setKbProvisioning(await b.invoke("kbChat:provisioningInfo", {})); }
    catch (_e) {}
  };
  const sendKbChat = async () => {
    const q = kbChatInput.trim();
    if (!q || kbChatLoading) return;
    const b = kbBridge();
    setKbChatMsgs((m) => [...m, { role: "user", text: q }]);
    setKbChatInput("");
    if (detectDistress(q)) { setKbChatMsgs((m) => [...m, { role: "assistant", distress: true }]); return; }
    if (!b) { setKbChatMsgs((m) => [...m, { role: "assistant", unavailable: true, reason: "no_bridge" }]); return; }
    setKbChatLoading(true);
    let r;
    try { r = await b.invoke("kbChat:ask", { question: q, signalsContext: buildSignalsContext() }); }
    catch (_e) { r = { error: "failed" }; }
    setKbChatLoading(false);
    if (!r || r.error) setKbChatMsgs((m) => [...m, { role: "assistant", unavailable: true, reason: "error" }]);
    else if (r.unavailable) setKbChatMsgs((m) => [...m, { role: "assistant", unavailable: true, reason: r.reason || "unavailable" }]);
    else setKbChatMsgs((m) => [...m, { role: "assistant", text: r.answer, citedEntries: r.citedEntries || [] }]);
  };
  useEffect(() => { if (tab === "kb" && kbModelStatus === null) refreshKbModelStatus(); }, [tab]);
  const [signalsLoadState, setSignalsLoadState] = useState({ loaded: false, error: null, locked: false, decrypted: 0, sealedCount: 0 });
  useEffect(() => {
    if (!burnoutReady) return;
    let cancelled = false;
    (async () => {
      const data = await api.get('/api/signals/me');
      if (cancelled) return;
      if (!data || data.error) {
        setSignalsLoadState({ loaded: false, error: (data && data.error) || 'error', locked: false, decrypted: 0, sealedCount: 0 });
        return;
      }
      if (data.pressure && typeof data.pressure === 'object') setPressure(data.pressure);

      // Decrypt each sealed snapshot on-device and rebuild a per-signal series.
      const sealed = Array.isArray(data.sealed_readings) ? data.sealed_readings : [];
      const bridge = (typeof window !== "undefined") ? window.firealive : null;
      const seriesByKey = {};
      for (const k of BEHAVIORAL_ORDER) seriesByKey[k] = [];
      let decrypted = 0, lockedSeen = false;
      if (bridge && bridge.invoke && sealed.length > 0) {
        for (const row of sealed) {
          if (cancelled) return;
          if (!row || typeof row.ciphertext !== 'string') continue;
          let res;
          try { res = await bridge.invoke("burnout:decrypt", { sealed: row.ciphertext }); } catch (_e) { res = null; }
          if (!res || res.ok !== true || typeof res.plaintext !== 'string') { lockedSeen = true; break; }
          let snap;
          try { snap = JSON.parse(res.plaintext); } catch (_e) { snap = null; }
          if (!snap || typeof snap.signals !== 'object' || !snap.recorded_at) continue;
          const t = new Date(snap.recorded_at).getTime();
          if (!Number.isFinite(t)) continue;
          for (const k of BEHAVIORAL_ORDER) {
            const v = snap.signals[k];
            if (typeof v === 'number' && Number.isFinite(v)) seriesByKey[k].push({ t, v });
          }
          decrypted++;
        }
      }
      if (cancelled) return;
      const next = {};
      for (const k of BEHAVIORAL_ORDER) {
        const meta = BEHAVIORAL_META[k];
        next[k] = { ...meta, ...faComputeSignal(seriesByKey[k], meta.band, meta.hib) };
      }
      setSignals(next);
      setSignalsLoadState({ loaded: true, error: null, locked: lockedSeen, decrypted, sealedCount: sealed.length });
    })();
    return () => { cancelled = true; };
  }, [burnoutReady, signalRefreshTrigger]);
  // B5d4: cadence-driven signal refresh. The interval follows the lead-set
  // cadence pushed over WS; each tick bumps the trigger so the signals effect
  // above re-pulls and re-decrypts. Panic and critical alerts bump it out of
  // band via the urgent_refresh WS message.
  React.useEffect(() => {
    if (!burnoutReady) return;
    const mins = (syncCadence && Number(syncCadence.intervalMin) > 0) ? Number(syncCadence.intervalMin) : 15;
    const handle = setInterval(() => setSignalRefreshTrigger((n) => n + 1), mins * 60000);
    return () => clearInterval(handle);
  }, [burnoutReady, syncCadence]);


  // ── On-device signal interpretation (B5d1 PR D) ──────────────────────────────
  // Replaces the server-precomputed interpretations: when a signal card is
  // expanded we ask the on-device model to interpret that signal's drift, grounded
  // in the local research KB with every citation validated (burnout:interpret).
  // Cached per signal for the session in `interp`. The drift we pass is computed
  // on-device; no raw private value leaves this process.
  const [interp, setInterp] = useState({});
  const requestInterp = async (key) => {
    const s = signals[key];
    if (!s || s.status === "no_data") return;
    if (interp[key] && !interp[key].error) return;
    setInterp((m) => ({ ...m, [key]: { loading: true } }));
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || !bridge.invoke) { setInterp((m) => ({ ...m, [key]: { unavailable: true, reason: "no_bridge" } })); return; }
    let res;
    try {
      res = await bridge.invoke("burnout:interpret", { signal: { key, label: s.label, driftPct: s.driftPct || 0, bandStatus: s.band || "within" } });
    } catch (_e) { res = null; }
    setInterp((m) => {
      if (!res || res.error) return { ...m, [key]: { error: true } };
      if (res.unavailable) return { ...m, [key]: { unavailable: true, reason: res.reason || "unavailable" } };
      return { ...m, [key]: { interpretation: res.interpretation, citedEntries: res.citedEntries || [] } };
    });
  };

  // ── Holistic overall interpretation (B5d1 PR D) ──────────────────────────────
  // One on-device synthesis across all signals + operational load, requested when
  // the Signals tab opens and cached for the session. The deterministic stage shows
  // instantly; this narrative fills in. The overview is built from on-device
  // values; no raw private number is sent.
  const [overallInterp, setOverallInterp] = useState(null);
  const requestOverallInterp = async () => {
    const order = BEHAVIORAL_ORDER.filter((k) => signals[k] && signals[k].status !== "no_data");
    if (order.length === 0) { setOverallInterp({ unavailable: true, reason: "no_retrieval" }); return; }
    const agg = faAggregate(signals, pressure);
    setOverallInterp({ loading: true });
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || !bridge.invoke) { setOverallInterp({ unavailable: true, reason: "no_bridge" }); return; }
    const overview = {
      stage: agg.stage,
      pressure: faPressureWord(agg.pressure),
      signals: order.map((k) => ({ label: signals[k].label, driftPct: signals[k].driftPct || 0, bandStatus: signals[k].band || "within", status: signals[k].status })),
    };
    let res;
    try { res = await bridge.invoke("burnout:interpretOverall", { overview }); } catch (_e) { res = null; }
    if (!res || res.error) setOverallInterp({ error: true });
    else if (res.unavailable) setOverallInterp({ unavailable: true, reason: res.reason || "unavailable" });
    else setOverallInterp({ interpretation: res.interpretation, citedEntries: res.citedEntries || [] });
  };
  useEffect(() => { if (tab === "signals" && signalsLoadState.loaded && !signalsLoadState.locked && !overallInterp) requestOverallInterp(); }, [tab, signalsLoadState.loaded, signalsLoadState.locked]);

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
    setPostSession({ sessionId: peerSession.id, messages: [...peerMsgs], topic: peerSession.topic, expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString() });
    setPeerSession(null); setPeerDiscAccepted(false); setPM([]); setPostRating(0); setPostFlagging(false); setPostFlagText(""); setPostFlagSel(new Set()); setPostFlagLastIdx(null);
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
  // Phase U3: out-of-band safety number for the lead channel. The threadId is the
  // shared, pseudonymous session id, passed as both fingerprint ids so the number
  // is symmetric and matches on the lead's client without either side learning the
  // other's identity from it. Grouped into 5s for reading aloud.
  const [leadSafetyNum, setLeadSafetyNum] = useState(null);
  const showLeadSafetyNumber = async () => {
    if (!leadThread || !leadThread.threadId) return;
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || !bridge.invoke) { setLeadSafetyNum("unavailable outside the desktop app"); return; }
    try {
      const tid = leadThread.threadId;
      const r = await bridge.invoke("e2ee:safetyNumber", { domain: "lead", remoteUserId: tid, localId: tid, remoteId: tid });
      const sn = (r && r.safetyNumber && !r.error) ? String(r.safetyNumber) : null;
      if (!sn) { setLeadSafetyNum("not available until the channel is established"); return; }
      let grouped = "";
      for (let i = 0; i < sn.length; i += 5) { grouped += (i ? " " : "") + sn.slice(i, i + 5); }
      setLeadSafetyNum(grouped);
    } catch (e) {
      setLeadSafetyNum("not available until the channel is established");
    }
  };
  // Close the thread: the server marks it closed and starts the 5-minute retention
  // countdown, then we clear local state -- which stops the poll and returns to the
  // picker. Best-effort: clear locally even if the close call fails.
  const closeLeadThread = async () => {
    const t = leadThread;
    if (t && t.threadId) {
      try {
        await api.post("/api/lead-chat/" + encodeURIComponent(t.threadId) + "/close", {});
        logC("lead_thread_closed", "Closed lead chat; messages purge in 5 minutes");
      } catch (e) { /* clear locally regardless */ }
    }
    setLeadThread(null);
    setLM([]);
    setLeadSafetyNum(null);
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
  // ── Peer board: flag a post ──
  const [boardFlagPost, setBoardFlagPost] = useState(null); // postId being flagged
  const [boardFlagTier, setBoardFlagTier] = useState(0);    // 0=unselected, 1/2/3
  const [boardFlagNote, setBoardFlagNote] = useState("");
  const [boardFlagErr, setBoardFlagErr] = useState("");
  const [boardFlagBusy, setBoardFlagBusy] = useState(false);
  const openBoardFlag = (postId) => { setBoardFlagPost(postId); setBoardFlagTier(0); setBoardFlagNote(""); setBoardFlagErr(""); };
  // Seal the note, the offending post body, and a short thread-context snippet
  // to the active team-lead recipient set on this device (main-process
  // abuse:seal) -- the server stores only opaque sealed envelopes and never
  // reads them. Mirrors the peer-session flag. The accused is resolved server-side;
  // the context snippet lets the reviewing lead see the flagged post in situ.
  const buildBoardContext = (postId, rootId) => {
    const key = (rootId != null) ? rootId : postId;
    const posts = expandedThreads[key];
    if (!Array.isArray(posts) || posts.length === 0) return null;
    const snippet = posts.slice(0, 20).map(p => ({
      label: p.anonymous ? "Anonymous" : (p.authorLabel || "Analyst"),
      content: (p.content || "").slice(0, 600),
      flagged: p.id === postId,
    }));
    return JSON.stringify(snippet);
  };
  const flagBoardPost = async (postId, rootId, body) => {
    const note = (boardFlagNote || "").trim();
    if (!note || !boardFlagTier) return;
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || !bridge.invoke) { setBoardFlagErr("Reporting requires the desktop app."); return; }
    setBoardFlagBusy(true); setBoardFlagErr("");
    try {
      const k = await api.get("/api/abuse-review-keys");
      if (!k || !k.active || !Array.isArray(k.keys) || k.keys.length === 0) {
        setBoardFlagErr("Reporting is unavailable until a team lead sets up abuse review.");
        setBoardFlagBusy(false); return;
      }
      const pubs = k.keys.map((kk) => kk.publicKey).filter(Boolean);
      const sn = await bridge.invoke("abuse:seal", { recipientPublicKeys: pubs, plaintext: note, sanitize: true });
      const sc = await bridge.invoke("abuse:seal", { recipientPublicKeys: pubs, plaintext: (body || "") });
      if (!sn || !sn.sealed || !sc || !sc.sealed) { setBoardFlagErr("Could not seal the report."); setBoardFlagBusy(false); return; }
      const payload = { target_type: "board_post", boardPostId: postId, tier: boardFlagTier, sealedNote: sn.sealed, sealedContent: sc.sealed };
      const ctxPlain = buildBoardContext(postId, rootId);
      if (ctxPlain) {
        const cx = await bridge.invoke("abuse:seal", { recipientPublicKeys: pubs, plaintext: ctxPlain });
        if (cx && cx.sealed) payload.sealedContext = cx.sealed;
      }
      const r = await api.post("/api/peer/flags", payload);
      if (r && r.error) { setBoardFlagErr(r.error); setBoardFlagBusy(false); return; }
      if (r && r.id) {
        beginExportPrompt(r.id, "board_post", body, note);
        // The post is now removed pending review -- drop it from view.
        if (rootId == null) {
          setPeerBoardMsgs(prev => prev.filter(pp => pp.id !== postId));
          setExpandedThreads(prev => { const n = { ...prev }; delete n[postId]; return n; });
        } else {
          loadThread(rootId);
        }
        setBoardFlagPost(null); setBoardFlagTier(0); setBoardFlagNote(""); setBoardFlagErr("");
        logC("board_post_flagged", `Tier ${boardFlagTier} report sealed for team-lead review`);
      }
      setBoardFlagBusy(false);
    } catch (e) {
      setBoardFlagErr("Could not submit the report."); setBoardFlagBusy(false);
    }
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
  const [postSession, setPostSession] = useState(null); // {sessionId, messages, topic, expiresAt}
  const [postRating, setPostRating] = useState(0);
  const [postFlagging, setPostFlagging] = useState(false);
  const [postFlagText, setPostFlagText] = useState("");
  const [postFlagTier, setPostFlagTier] = useState(0); // 0=unselected, 1/2/3
  const [postFlagErr, setPostFlagErr] = useState("");
  const [postFlagBusy, setPostFlagBusy] = useState(false);
  const [postFlagSel, setPostFlagSel] = useState(() => new Set());
  const [postFlagLastIdx, setPostFlagLastIdx] = useState(null);
  // One-shot abuse-flag export prompt. After a flag is submitted, the flagger may
  // save a single signed PDF copy as a personal backup; the authentic plaintext
  // lives only in the main process for a 5-minute window (see abuse:hold-for-export).
  // Only a content hash -- never plaintext -- is kept in renderer state here.
  const [exportPrompt, setExportPrompt] = useState(null);   // { flagId, targetType, contentSha256 }
  const [exportExpiresAt, setExportExpiresAt] = useState(0);
  const [exportBusy, setExportBusy] = useState(false);
  const [exportMsg, setExportMsg] = useState("");
  const [exportDone, setExportDone] = useState(false);
  const beginExportPrompt = async (flagId, targetType, contentText, note) => {
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!bridge || !bridge.invoke || !flagId || !contentText) return;
    try {
      const h = await bridge.invoke("abuse:hold-for-export", { flagId, targetType, contentText, note });
      setExportPrompt({ flagId, targetType, contentSha256: h && h.contentSha256 });
      setExportExpiresAt(h && h.expiresAt ? h.expiresAt : Date.now() + 5 * 60 * 1000);
      setExportMsg(""); setExportDone(false); setExportBusy(false);
    } catch (e) { /* export unavailable -- the submission still succeeded */ }
  };
  const doExport = async () => {
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    if (!exportPrompt || !bridge || !bridge.invoke) return;
    setExportBusy(true); setExportMsg("");
    try {
      const r = await api.post("/api/peer/flags/" + exportPrompt.flagId + "/sign-record", { content_sha256: exportPrompt.contentSha256 });
      if (!r || r.error || !r.signatureB64) { setExportMsg("Could not sign the record" + (r && r.error ? ": " + r.error : ".")); setExportBusy(false); return; }
      const descriptor = { payload: r.payload, canonical: r.canonical, reportSha256: r.reportSha256, signatureB64: r.signatureB64, keyFingerprint: r.keyFingerprint, instanceLabel: r.instanceLabel, signedAt: r.signedAt };
      const fin = await bridge.invoke("abuse:finalize-export", { descriptor });
      if (fin && fin.saved) { setExportMsg("Saved. This signed PDF is your only personal copy."); setExportDone(true); logC("abuse_export_saved", "Saved a signed submission record"); }
      else if (fin && fin.reason === "dialog_canceled") { setExportMsg("Save canceled. You can export again until the window closes."); }
      else if (fin && fin.reason === "expired") { setExportMsg("The window has closed and the content was wiped from this device."); setExportDone(true); }
      else { setExportMsg("Could not save the record."); }
    } catch (e) { setExportMsg("Could not export the record."); }
    setExportBusy(false);
  };
  const declineExport = async () => {
    const bridge = (typeof window !== "undefined") ? window.firealive : null;
    try { if (bridge && bridge.invoke) await bridge.invoke("abuse:cancel-export"); } catch (e) {}
    setExportPrompt(null); setExportExpiresAt(0); setExportMsg(""); setExportDone(false); setExportBusy(false);
  };
  useEffect(() => {
    if (!exportPrompt || exportDone || !exportExpiresAt) return undefined;
    const ms = exportExpiresAt - Date.now();
    const expire = () => { setExportMsg("The window has closed and the content was wiped from this device."); setExportDone(true); };
    if (ms <= 0) { expire(); return undefined; }
    const t = setTimeout(expire, ms);
    return () => clearTimeout(t);
  }, [exportPrompt, exportExpiresAt, exportDone]);
  // Post-session retention: the decrypted messages held in postSession are wiped
  // when the displayed window lapses, honoring the "deleted after 5 minutes"
  // promise on the client as well -- but only while the reporter is idle on the
  // review screen. While they are actively composing a flag the purge is deferred
  // so evidence is never deleted out from under them mid-report; the "I need more
  // time" control extends the window. (U4 PR 5-B.)
  const postComposing = !!postSession && (postFlagging || postFlagSel.size > 0 || (postFlagText && postFlagText.length > 0));
  React.useEffect(() => {
    if (!postSession || !postSession.expiresAt || postComposing) return undefined;
    const wipe = () => {
      setPostSession(null); setPostFlagging(false); setPostFlagTier(0); setPostFlagText("");
      setPostFlagErr(""); setPostFlagSel(new Set()); setPostFlagLastIdx(null);
      logC("peer_session_expired", "Post-session review window lapsed -- messages deleted");
    };
    const ms = new Date(postSession.expiresAt).getTime() - Date.now();
    if (ms <= 0) { wipe(); return undefined; }
    const t = setTimeout(wipe, ms);
    return () => clearTimeout(t);
  }, [postSession, postComposing]);
  // Whole-message selection for peer-chat flagging. The accuser chooses WHICH
  // authentic messages to report (click to toggle, Shift-click for a contiguous
  // run, Select all); the system then seals those messages' real text. The
  // accuser never types or alters the flagged content.
  const toggleFlagSel = (idx, shift) => {
    const msgs = (postSession && postSession.messages) || [];
    setPostFlagSel(prev => {
      const next = new Set(prev);
      if (shift && postFlagLastIdx != null) {
        const a = Math.min(postFlagLastIdx, idx), b = Math.max(postFlagLastIdx, idx);
        for (let i = a; i <= b; i++) { if (msgs[i]) next.add(msgs[i].id); }
      } else {
        const id = msgs[idx] && msgs[idx].id;
        if (id != null) { if (next.has(id)) next.delete(id); else next.add(id); }
      }
      return next;
    });
    setPostFlagLastIdx(idx);
  };
  // (cleaned up in v1.0.0)

  // signals defined above
  // stage defined above as stageLabel
  // sc defined above
  const impacts=[{d:"Mar 24",e:"Delegated phishing pattern to SOAR",o:"12 fewer daily tickets",v:true},{d:"Mar 21",e:"Requested lighter queue",o:"Complexity cap applied next shift",v:true},{d:"Mar 18",e:"Flagged recurring FP",o:"EDR rule updated — 8 fewer daily alerts team-wide",v:true}];
  // logC defined above using setAL

  // tabs defined above


  // Main render
  const aggregate = faAggregate(signals, pressure);
  const stageLabel = aggregate.stage;
  const sc = STAGE_COPY[stageLabel] || STAGE_COPY.healthy;

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
  if (deployMode === undefined) return null;
  if (!deployMode.configured) return <DeploymentSetup onComplete={()=>setDeployMode({ configured: true })} />;
  if (stage === "login") return <AcLoginScreen onLoggedIn={(uid) => {setSelfUserId(uid);setStage(firstLaunch ? "welcome" : "app");}} logC={logC} />;

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

  if (!burnoutReady) return <BurnoutKeyGate userId={selfUserId} onReady={function(){setBurnoutReady(true);}} logC={logC} />;

  return(
    <div style={{minHeight:"100vh",background:"#060A10",color:C.t,fontFamily:"'DM Sans',sans-serif"}}>
      <style>{CSS}</style>
      {serverRollback && (
        <div style={{position:"fixed",inset:0,background:"rgba(8,2,2,0.94)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:100000,padding:20}}>
          <Card style={{maxWidth:520,padding:24,border:"1px solid #7f1d1d"}}>
            <M style={{color:"#fca5a5",fontWeight:700,fontSize:16,display:"block",marginBottom:10}}>Server identity check failed -- session blocked</M>
            <M style={{color:C.tm,lineHeight:1.6,display:"block",marginBottom:10}}>This client connected to a server presenting an anti-rollback counter behind one it has already seen. That indicates the server was restored from an older snapshot or cloned, and this client will not trust it.</M>
            <M style={{color:C.td,display:"block",marginBottom:6}}>Do not enter credentials or data. Contact your team lead and report a possible server clone or rollback.</M>
            <M style={{color:C.td,display:"block"}}>Counter last seen {serverRollback.lastSeen != null ? String(serverRollback.lastSeen) : "n/a"}; server offered {serverRollback.echoed != null ? String(serverRollback.echoed) : "n/a"}.</M>
          </Card>
        </div>
      )}
      {anchorMismatch && (
        <div style={{position:"fixed",inset:0,background:"rgba(8,2,2,0.94)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:100001,padding:20}}>
          <Card style={{maxWidth:520,padding:24,border:"1px solid #7f1d1d"}}>
            <M style={{color:"#fca5a5",fontWeight:700,fontSize:16,display:"block",marginBottom:10}}>{anchorMismatch.verdict === "declined" ? "Server identity not confirmed -- session blocked" : "Server identity check failed -- session blocked"}</M>
            <M style={{color:C.tm,lineHeight:1.6,display:"block",marginBottom:10}}>{anchorMismatch.verdict === "declined" ? "You did not confirm that this server's anchor fingerprint matches the value provided to you out of band. Until you confirm it, this client will not trust the server." : "This server could not prove control of its hardware instance anchor. That indicates it was cloned or restored onto different hardware, and this client will not trust it."}</M>
            <M style={{color:C.td,display:"block"}}>{(anchorMismatch.verdict === "declined" ? "Obtain the deployment anchor fingerprint from your administrator, then sign in again and confirm it when prompted." : "Do not enter data. Contact your team lead and report a possible server clone.") + (anchorMismatch.reason ? " Detail: " + anchorMismatch.reason + "." : "")}</M>
          </Card>
        </div>
      )}
      {reenrollRequired && (
        <div style={{position:"fixed",inset:0,background:"rgba(20,12,2,0.94)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:99999,padding:20}}>
          <Card style={{maxWidth:520,padding:24,border:"1px solid #b45309"}}>
            <M style={{color:"#fcd34d",fontWeight:700,fontSize:16,display:"block",marginBottom:10}}>Re-enrollment required -- deployment quarantined</M>
            <M style={{color:C.tm,lineHeight:1.6,display:"block",marginBottom:10}}>This deployment reported that its identity was quarantined because a possible clone, fork, or rollback was detected. This client must be re-enrolled before it can be trusted again.</M>
            <M style={{color:C.td,display:"block"}}>Stop work and contact your team lead to complete re-enrollment.{reenrollRequired.reason ? " Reason: " + reenrollRequired.reason + "." : ""}</M>
          </Card>
        </div>
      )}
      {exportPrompt && (
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.7)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:9999,padding:20}}>
          <Card style={{maxWidth:460,padding:22}}>
            <M style={{color:C.t,fontWeight:600,fontSize:15,display:"block",marginBottom:8}}>Report submitted to a team lead</M>
            <M style={{color:C.tm,lineHeight:1.6,display:"block",marginBottom:10}}>You have a few minutes to save one personal PDF copy as your own backup -- for example, if the team lead's record is ever lost. After you export or decline, the text is wiped from this device and only the team lead's vault holds it. This is your only chance to keep a personal copy.</M>
            {!exportDone && exportExpiresAt ? <M style={{color:C.td,display:"block",marginBottom:12}}>Window closes at {new Date(exportExpiresAt).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"})}.</M> : null}
            {exportMsg ? <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.5}}>{exportMsg}</M> : null}
            <div style={{display:"flex",gap:8}}>
              {!exportDone && <Btn primary disabled={exportBusy} onClick={doExport}>{exportBusy?"Working\u2026":"Export PDF"}</Btn>}
              {!exportDone && <Btn small disabled={exportBusy} onClick={declineExport}>Don't keep a copy</Btn>}
              {exportDone && <Btn small onClick={()=>{setExportPrompt(null);setExportExpiresAt(0);setExportMsg("");setExportDone(false);}}>Close</Btn>}
            </div>
          </Card>
        </div>
      )}
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
          <Btn small onClick={()=>{api.setToken(null);try{localStorage.removeItem('fa_ac_refresh_token');}catch(_e){}setBurnoutReady(false);try{window.firealive&&window.firealive.invoke&&window.firealive.invoke("burnout:lock");}catch(_e){}setStage("login");setUsername("");setLoginError("");logC("SIGN_OUT","Signed out");}}>Sign Out</Btn>
        </div>
      </div>
      {breakPrompt&&featureToggles.proactive_interventions!==false&&(<div style={{padding:"12px 24px",background:"rgba(167,139,250,0.08)",borderBottom:`1px solid ${C.p}30`}}>
        <M style={{color:C.p,fontWeight:500}}>Your lead approved a break for you. You have been doing incredible work. </M>
        <div style={{display:"flex",gap:8,marginTop:8}}>
          <Btn small primary onClick={()=>{api.post("/api/proactive-break/outcome",{outcome:"taken"});setBreakPrompt(null);logC("BREAK_ACCEPTED","Break accepted");}}>Take Break</Btn>
          <Btn small onClick={()=>{api.post("/api/proactive-break/outcome",{outcome:"declined"});setBreakPrompt(null);logC("BREAK_DECLINED","Continuing work");}}>Continue</Btn>
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
          <M style={{color:C.tm,display:"block",marginBottom:16}}>Your work patterns, computed on this device from data only you can decrypt. Each signal is compared to your own frozen baseline and to a healthy range. Click any signal for what it may mean and what can help.</M>

          {signalsLoadState.loaded&&!signalsLoadState.locked&&(<Card style={{marginBottom:16,borderLeft:`3px solid ${sc.c}`}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
              <span style={{display:"inline-block",width:6,height:6,borderRadius:"50%",background:sc.c,boxShadow:`0 0 6px ${sc.c}`}}/>
              <M style={{color:C.t,fontWeight:600}}>{sc.hl}</M>
            </div>
            <M style={{color:C.tm,display:"block",marginBottom:10}}>{sc.sub}</M>
            {(() => {
              const oi=overallInterp;
              if(!oi||oi.loading) return <M style={{color:C.td,lineHeight:1.7}}>Summarizing your overall picture on this device...</M>;
              if(oi.interpretation){
                const refs=(oi.citedEntries||[]).map((e)=>e.id).filter(Boolean);
                return(
                  <div>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                      <Badge color={C.i}>ON-DEVICE AI</Badge>
                      {refs.length>0&&<M style={{color:C.td,fontSize:11}}>Research-grounded: {refs.join(", ")}</M>}
                    </div>
                    <M style={{color:C.tm,lineHeight:1.8}}>{oi.interpretation}</M>
                  </div>
                );
              }
              const why=oi.reason==="model_unavailable"?" The on-device model isn't loaded on this machine.":oi.reason==="no_retrieval"?" Not enough signal history yet for an overall read.":oi.reason==="citation_check_failed"?" A grounded answer couldn't be verified.":oi.reason==="no_bridge"?" The on-device bridge is unavailable.":"";
              return <M style={{color:C.td,lineHeight:1.7}}>{"An overall summary isn't available right now."+why+" Your signals below are accurate."}</M>;
            })()}
          </Card>)}

          {!signalsLoadState.loaded&&!signalsLoadState.error&&(<M style={{color:C.td,display:"block"}}>Decrypting your signals on this device...</M>)}
          {signalsLoadState.error&&(<M style={{color:C.w,display:"block"}}>Could not load your signals ({signalsLoadState.error}). Your data is unaffected.</M>)}
          {signalsLoadState.locked&&(<Card style={{marginBottom:10,borderLeft:`3px solid ${C.w}`}}><M style={{color:C.t,fontWeight:500,display:"block",marginBottom:4}}>Your private key is locked</M><M style={{color:C.tm}}>Unlock your burnout key to decrypt and view your signals. Only you hold it.</M></Card>)}

          {signalsLoadState.loaded&&!signalsLoadState.locked&&BEHAVIORAL_ORDER.map((key)=>{
            const s=signals[key]; if(!s) return null;
            const interventions=SIGNAL_INTERVENTIONS[key];
            const established=s.status==="established";
            const driftBad=established&&(s.hib?(s.driftPct<0):(s.driftPct>0));
            const bandBad=s.band==="above"||s.band==="below";
            const notable=(established&&Math.abs(s.driftPct)>FA_DRIFT_NOTABLE&&driftBad)||bandBad;
            const accent=notable?C.w:C.a;
            const driftArrow=!established?"":(s.driftPct>0?"\u25B2":s.driftPct<0?"\u25BC":"");
            return(
            <Card key={key} style={{marginBottom:10,borderLeft:`3px solid ${s.status==="no_data"?C.b:accent}`,cursor:s.status==="no_data"?"default":"pointer"}} onClick={s.status==="no_data"?undefined:()=>{const open=showSig===key?null:key;setShowSig(open);if(open)requestInterp(open);}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",gap:8}}>
                <M style={{color:C.t,fontWeight:500}}>{s.label}</M>
                {s.status==="no_data"?(
                  <M style={{color:C.td}}>No data yet</M>
                ):s.status==="establishing"?(
                  <M style={{color:bandBad?C.w:C.tm,fontWeight:500,textAlign:"right"}}>{faNum(s.cur)}{s.u} <span style={{fontWeight:400,color:C.td}}>(baseline establishing)</span></M>
                ):(
                  <M style={{color:driftBad?C.w:C.a,fontWeight:600,textAlign:"right"}}>{faNum(s.cur)}{s.u} {driftArrow&&<span>{driftArrow}{Math.abs(Math.round(s.driftPct))}%</span>} <span style={{fontWeight:400,color:C.td}}>(your baseline: {faNum(s.base)}{s.u})</span></M>
                )}
              </div>
              {(bandBad||s.status==="establishing")&&(
                <div style={{marginTop:6,display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
                  {bandBad&&<Badge color={C.w}>{s.band==="above"?"above healthy range":"below healthy range"}</Badge>}
                  {s.status==="establishing"&&<Badge color={C.i}>{"establishing - "+s.n+" readings, "+(s.spanDays||0)+"/"+FA_ESTABLISH_DAYS+" days"}</Badge>}
                </div>
              )}
              {showSig===key&&s.status!=="no_data"&&(<div style={{marginTop:12,padding:"12px 14px",background:"rgba(0,0,0,0.2)",borderRadius:8}} onClick={(e)=>e.stopPropagation()}>
                <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:8}}>What this means</M>
                {(() => {
                  const it=interp[key];
                  if(!it||it.loading) return <M style={{color:C.td,lineHeight:1.7}}>Interpreting on this device...</M>;
                  if(it.interpretation){
                    const refs=(it.citedEntries||[]).map((e)=>e.id).filter(Boolean);
                    return(
                      <div>
                        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                          <Badge color={C.i}>ON-DEVICE AI</Badge>
                          {refs.length>0&&<M style={{color:C.td,fontSize:11}}>Research-grounded: {refs.join(", ")}</M>}
                        </div>
                        <M style={{color:C.tm,lineHeight:1.8}}>{it.interpretation}</M>
                      </div>
                    );
                  }
                  const why=it.reason==="model_unavailable"?" The on-device model isn't loaded on this machine.":it.reason==="no_retrieval"?" No matching research was found.":it.reason==="citation_check_failed"?" A grounded answer couldn't be verified.":it.reason==="no_bridge"?" The on-device bridge is unavailable.":"";
                  return <M style={{color:C.td,lineHeight:1.7}}>{"On-device interpretation unavailable right now."+why+" Your values above are accurate."}</M>;
                })()}
                {interventions&&interventions.paths&&interventions.paths.length>0&&(<div style={{marginTop:14}}>
                  <M style={{color:C.i,fontWeight:500,display:"block",marginBottom:8}}>What you can do</M>
                  {interventions.paths.map((p,i)=>{
                    const act=(p.type==="platform"&&p.pid)?(()=>setShowPlatform(p.pid)):p.type==="peer"?(()=>setTab("peers")):p.type==="ai"?(()=>setShowPlatform("claude-ai")):null;
                    return(
                    <div key={i} onClick={act||undefined} style={{marginBottom:8,paddingLeft:10,borderLeft:`2px solid ${act?C.i:C.b}`,cursor:act?"pointer":"default"}}>
                      <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:2,flexWrap:"wrap"}}>
                        <Badge color={p.type==="structural"?C.a:p.type==="peer"?C.p:p.type==="ai"?C.i:C.tm}>{p.type}</Badge>
                        <M style={{color:act?C.i:C.t,fontWeight:500}}>{p.title}{act?" \u2197":""}</M>
                      </div>
                      <M style={{color:C.tm,lineHeight:1.6}}>{p.desc}</M>
                    </div>
                    );
                  })}
                </div>)}
              </div>)}
            </Card>
          );})}

          {/* ── Operational pressure (D10): live load used for routing; visible to your lead. NOT part of your private baseline. ── */}
          {pressure&&(<Card style={{marginTop:18,marginBottom:10}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",marginBottom:10}}>
              <M style={{color:C.t,fontWeight:600,letterSpacing:0.5}}>OPERATIONAL LOAD</M>
              <M style={{color:C.td}}>visible to your lead - for routing</M>
            </div>
            {[{k:"cognitive_load",label:"Cognitive load",u:"/100",hint:"recent ticket volume"},{k:"task_switching",label:"Context switches",u:"",hint:"categories handled, last hour"},{k:"queue_pressure",label:"Open in your queue",u:"",hint:"tickets assigned, pending"},{k:"shift_overtime",label:"Overtime",u:"h",hint:"hours over schedule"}].map((row)=>(
              <div key={row.k} style={{display:"flex",justifyContent:"space-between",alignItems:"baseline",padding:"5px 0",borderTop:`1px solid ${C.b}`}}>
                <div><M style={{color:C.tm,fontWeight:500}}>{row.label}</M> <M style={{color:C.td}}>{row.hint}</M></div>
                <M style={{color:C.t,fontWeight:600}}>{typeof pressure[row.k]==="number"?pressure[row.k]:0}{row.u}</M>
              </div>
            ))}
          </Card>)}

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
              <M style={{color:C.td,display:"block",marginBottom:8}}>Topic: {postSession.topic} · Expires: {new Date(postSession.expiresAt).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})}</M>
              <div style={{marginBottom:16}}>
                <Btn small onClick={()=>{setPostSession(p => p ? ({...p, expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString()}) : p);logC("peer_session_extended","Extended post-session review window by 5 minutes");}}>I need more time (+5 min)</Btn>
              </div>

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

                <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:6}}>
                  <M style={{color:C.tm,flex:1,lineHeight:1.4}}>Select the message(s) to report ({postFlagSel.size} selected). Click to toggle, Shift-click for a range.</M>
                  <Btn small onClick={()=>setPostFlagSel(new Set((postSession.messages||[]).map(m=>m.id)))}>Select all</Btn>
                  <Btn small onClick={()=>{setPostFlagSel(new Set());setPostFlagLastIdx(null);}}>Clear</Btn>
                </div>
                <Card style={{marginBottom:8,maxHeight:200,overflow:"auto",background:"rgba(0,0,0,0.4)",fontFamily:"'Courier New',Courier,monospace"}}>
                  {postSession.messages.map((m,i)=>{
                    const sel = postFlagSel.has(m.id);
                    return (
                    <div key={m.id} onClick={(e)=>toggleFlagSel(i, e.shiftKey)} style={{padding:"8px 12px",borderBottom:"1px solid rgba(255,255,255,0.04)",cursor:"pointer",background:sel?"rgba(239,68,68,0.16)":"transparent",display:"flex",gap:8,alignItems:"flex-start"}}>
                      <input type="checkbox" readOnly checked={sel} style={{marginTop:3,pointerEvents:"none"}}/>
                      <div style={{flex:1}}>
                        <M style={{color:m.from.includes("You")?C.a:C.p,fontWeight:500,fontFamily:"inherit"}}>{m.from}</M>
                        <span style={{fontSize:11,color:C.td,marginLeft:8}}>{m.ts}</span>
                        <div style={{fontSize:12,color:C.t,fontFamily:"inherit",marginTop:2}}>{m.text}</div>
                      </div>
                    </div>
                    );
                  })}
                </Card>

                <div style={{marginBottom:14}}>
                  <M style={{color:C.tm,marginBottom:8,display:"block"}}>Severity tier:</M>
                  <div style={{display:"flex",flexDirection:"column",gap:8}}>
                    <label style={{display:"flex",gap:10,padding:"10px 12px",background:postFlagTier===1?"rgba(96,165,250,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${postFlagTier===1?C.i+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                      <input type="radio" name="flagtier" checked={postFlagTier===1} onChange={()=>setPostFlagTier(1)} style={{marginTop:3}}/>
                      <div style={{flex:1}}>
                        <M style={{color:C.i,fontWeight:600,display:"block",marginBottom:2}}>Tier 1 — Minor</M>
                        <M style={{color:C.tm,lineHeight:1.5}}>Curt tone, dismissiveness, condescension, or mild rudeness -- unprofessional, not a personal attack. Goes to a team lead and feeds anonymous pattern detection.</M>
                      </div>
                    </label>
                    <label style={{display:"flex",gap:10,padding:"10px 12px",background:postFlagTier===2?"rgba(251,191,36,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${postFlagTier===2?C.w+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                      <input type="radio" name="flagtier" checked={postFlagTier===2} onChange={()=>setPostFlagTier(2)} style={{marginTop:3}}/>
                      <div style={{flex:1}}>
                        <M style={{color:C.w,fontWeight:600,display:"block",marginBottom:2}}>Tier 2 — Personal attack</M>
                        <M style={{color:C.tm,lineHeight:1.5}}>Direct insult, name-calling, mockery, or demeaning language aimed at you. Goes to a team lead for review.</M>
                      </div>
                    </label>
                    <label style={{display:"flex",gap:10,padding:"10px 12px",background:postFlagTier===3?"rgba(239,68,68,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${postFlagTier===3?C.d+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                      <input type="radio" name="flagtier" checked={postFlagTier===3} onChange={()=>setPostFlagTier(3)} style={{marginTop:3}}/>
                      <div style={{flex:1}}>
                        <M style={{color:C.d,fontWeight:600,display:"block",marginBottom:2}}>Tier 3 — Urgent</M>
                        <M style={{color:C.tm,lineHeight:1.5}}>Slurs (racial, gender, orientation, religion, disability), explicit threats, sexual harassment, or content suggesting imminent harm. Flagged for a team lead to handle urgently. Use only when warranted -- misuse undermines trust in the flagging system.</M>
                      </div>
                    </label>
                  </div>
                </div>

                <div style={{marginBottom:10}}>
                  <M style={{color:C.tm,marginBottom:4,display:"block"}}>Note for the team lead \u2014 why is the selected message abusive? (required)</M>
                  <textarea value={postFlagText} onChange={e=>setPostFlagText(e.target.value)} rows={3} maxLength={2000} style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.d}40`,borderRadius:8,color:C.t,fontSize:12,resize:"vertical"}} placeholder="Explain why the selected text is abusive. The flagged text itself is captured from the chat above -- do not retype it here."/>
                </div>

                {postFlagErr && <M style={{color:C.d,display:"block",marginBottom:8,lineHeight:1.5}}>{postFlagErr}</M>}
                <div style={{display:"flex",gap:8}}>
                  <Btn danger disabled={postFlagSel.size===0||!postFlagText.trim()||!postFlagTier||postFlagBusy} onClick={async()=>{
                    // Seal the AUTHENTIC selected messages (sealedContent) and the
                    // review note (sealedNote) on-device to the active team-lead
                    // recipient set, then post a peer-session flag. The flagged text
                    // is copied by the system from the messages the accuser selected
                    // -- never typed -- so it cannot be altered or fabricated. The
                    // accused is resolved server-side from the session counterpart.
                    const note = postFlagText.trim();
                    const selMsgs = ((postSession && postSession.messages) || []).filter(m => postFlagSel.has(m.id));
                    if (selMsgs.length === 0 || !note || !postFlagTier || !postSession || !postSession.sessionId) return;
                    const contentText = selMsgs.map(m => `[${m.ts}] ${m.from}: ${m.text}`).join("\n");
                    const bridge = (typeof window!=="undefined") ? window.firealive : null;
                    if (!bridge || !bridge.invoke) { setPostFlagErr("Reporting requires the desktop app."); return; }
                    setPostFlagBusy(true); setPostFlagErr("");
                    try {
                      const k = await api.get("/api/abuse-review-keys");
                      if (!k || !k.active || !Array.isArray(k.keys) || k.keys.length === 0) { setPostFlagErr("Reporting is unavailable until a team lead sets up abuse review."); setPostFlagBusy(false); return; }
                      const pubs = k.keys.map((kk) => kk.publicKey).filter(Boolean);
                      const sc = await bridge.invoke("abuse:seal", { recipientPublicKeys: pubs, plaintext: contentText });
                      const sn = await bridge.invoke("abuse:seal", { recipientPublicKeys: pubs, plaintext: note, sanitize: true });
                      if (!sc || !sc.sealed || !sn || !sn.sealed) { setPostFlagErr("Could not seal the report."); setPostFlagBusy(false); return; }
                      const r = await api.post("/api/peer/flags", { sessionId: postSession.sessionId, tier: postFlagTier, sealedContent: sc.sealed, sealedNote: sn.sealed });
                      if (r && r.error) { setPostFlagErr(r.error); setPostFlagBusy(false); return; }
                      if (r && r.id) {
                        logC("peer_abuse_flagged", `Tier ${postFlagTier} report sealed for team-lead review`);
                        beginExportPrompt(r.id, "peer_session", contentText, note);
                        setPostFlagging(false); setPostFlagTier(0); setPostFlagText(""); setPostFlagErr(""); setPostFlagSel(new Set()); setPostFlagLastIdx(null); setPostSession(null);
                      }
                      setPostFlagBusy(false);
                    } catch (e) { setPostFlagErr("Could not submit the report."); setPostFlagBusy(false); }
                  }}>{postFlagBusy?"Sealing\u2026":"Submit Flag"}</Btn>
                  <Btn small onClick={()=>{setPostFlagging(false);setPostFlagTier(0);setPostFlagErr("");setPostFlagSel(new Set());setPostFlagLastIdx(null);}}>Cancel</Btn>
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
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                <Btn onClick={async()=>{ try { const resp = await fetch(API_BASE + "/api/helper-pay/my-statement?format=pdf", { headers: await api.authHeaders("GET", "/api/helper-pay/my-statement?format=pdf") }); if (!resp.ok) { logC("helper_statement_failed","Points statement export failed"); return; } const blob = await resp.blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "helper-pay-statement-" + new Date().toISOString().slice(0,10) + ".pdf"; a.click(); URL.revokeObjectURL(a.href); logC("helper_statement_exported","Exported points statement (PDF)"); } catch (e) { logC("helper_statement_failed","Points statement export failed"); } }}>Download PDF</Btn>
                <Btn onClick={async()=>{ try { const resp = await fetch(API_BASE + "/api/helper-pay/my-statement?format=docx", { headers: await api.authHeaders("GET", "/api/helper-pay/my-statement?format=docx") }); if (!resp.ok) { logC("helper_statement_failed","Points statement export failed"); return; } const blob = await resp.blob(); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "helper-pay-statement-" + new Date().toISOString().slice(0,10) + ".docx"; a.click(); URL.revokeObjectURL(a.href); logC("helper_statement_exported","Exported points statement (DOCX)"); } catch (e) { logC("helper_statement_failed","Points statement export failed"); } }}>Download DOCX</Btn>
                <Btn onClick={async()=>{ try { const resp = await fetch(API_BASE + "/api/helper-pay/my-statement?format=csv", { headers: await api.authHeaders("GET", "/api/helper-pay/my-statement?format=csv") }); if (!resp.ok) { logC("helper_statement_failed","Points statement export failed"); return; } const text = await resp.text(); const blob = new Blob([text], { type: "text/csv" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "helper-pay-statement-" + new Date().toISOString().slice(0,10) + ".csv"; a.click(); logC("helper_statement_exported","Exported points statement (CSV)"); } catch (e) { logC("helper_statement_failed","Points statement export failed"); } }}>Download CSV</Btn>
              </div>
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
            const flagPicker = (postId, rootId, body) => (
              <Card style={{marginTop:8,padding:"12px 14px",borderColor:C.d+"40"}}>
                <M style={{color:C.d,fontWeight:500,display:"block",marginBottom:8}}>Flag this post -- select the severity that matches what was said:</M>
                <div style={{display:"flex",flexDirection:"column",gap:8,marginBottom:10}}>
                  <label style={{display:"flex",gap:10,padding:"10px 12px",background:boardFlagTier===1?"rgba(96,165,250,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${boardFlagTier===1?C.i+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                    <input type="radio" name={"bflag-"+postId} checked={boardFlagTier===1} onChange={()=>setBoardFlagTier(1)} style={{marginTop:3}}/>
                    <div style={{flex:1}}>
                      <M style={{color:C.i,fontWeight:600,display:"block",marginBottom:2}}>Tier 1 -- Minor</M>
                      <M style={{color:C.tm,lineHeight:1.5}}>Curt tone, dismissiveness, condescension, or mild rudeness in the post. Goes to a team lead and feeds anonymous pattern detection.</M>
                    </div>
                  </label>
                  <label style={{display:"flex",gap:10,padding:"10px 12px",background:boardFlagTier===2?"rgba(251,191,36,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${boardFlagTier===2?C.w+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                    <input type="radio" name={"bflag-"+postId} checked={boardFlagTier===2} onChange={()=>setBoardFlagTier(2)} style={{marginTop:3}}/>
                    <div style={{flex:1}}>
                      <M style={{color:C.w,fontWeight:600,display:"block",marginBottom:2}}>Tier 2 -- Personal attack</M>
                      <M style={{color:C.tm,lineHeight:1.5}}>Direct insult, name-calling, mockery, or demeaning language in the post. Goes to a team lead for review.</M>
                    </div>
                  </label>
                  <label style={{display:"flex",gap:10,padding:"10px 12px",background:boardFlagTier===3?"rgba(239,68,68,0.08)":"rgba(255,255,255,0.02)",border:`1px solid ${boardFlagTier===3?C.d+"50":C.b}`,borderRadius:8,cursor:"pointer"}}>
                    <input type="radio" name={"bflag-"+postId} checked={boardFlagTier===3} onChange={()=>setBoardFlagTier(3)} style={{marginTop:3}}/>
                    <div style={{flex:1}}>
                      <M style={{color:C.d,fontWeight:600,display:"block",marginBottom:2}}>Tier 3 -- Urgent</M>
                      <M style={{color:C.tm,lineHeight:1.5}}>Slurs, explicit threats, sexual harassment, or content suggesting imminent harm. Flagged for a team lead to handle urgently. Use only when warranted; misuse undermines trust.</M>
                    </div>
                  </label>
                </div>
                <textarea value={boardFlagNote} onChange={e=>setBoardFlagNote(e.target.value)} rows={2} maxLength={10000} placeholder="Briefly describe what's wrong with this post..." style={{width:"100%",padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.d}40`,borderRadius:8,color:C.t,fontSize:12,resize:"vertical"}}/>
                {boardFlagErr && <M style={{color:C.d,display:"block",marginTop:8,lineHeight:1.5}}>{boardFlagErr}</M>}
                <div style={{display:"flex",gap:8,marginTop:8}}>
                  <Btn danger small disabled={!boardFlagNote.trim()||!boardFlagTier||boardFlagBusy} onClick={()=>flagBoardPost(postId, rootId, body)}>{boardFlagBusy?"Sealing\u2026":"Submit Flag"}</Btn>
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
              {boardFlagPost===m.id && flagPicker(m.id, null, m.content)}
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
                        {boardFlagPost===rep.id && flagPicker(rep.id, m.id, rep.content)}
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
          <M style={{color:C.tm,display:"block",marginBottom:16,lineHeight:1.6}}>Your personal skill development. Assessment results from your team lead populate your baseline. Gaps auto-surface training recommendations below. When you reach proficiency thresholds, your lead receives a growth signal — recognition, not a demand (R037). Only you and your team lead see your individual results.</M>

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
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.6}}>No mandatory debriefing — a Cochrane review found single-session debriefing ineffective and possibly harmful (N020). Support here is voluntary, confidential, and peer-led.</M>
            {[{t:"Peer Skill-Share Chat",d:"Share skills and techniques with a colleague. E2EE, anonymous.",ac:"peers"},{t:"Schedule Skill-Share",d:"Schedule a skill-share session with a peer. Off-shift recommended.",ac:"peer_sched"},{t:"Peer Mentoring Program",d:"Longer-term pairing with a senior analyst. Develop skills and build resilience.",ac:"training"}].map((p,i)=>(
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
        {tab==="kb"&&(<div>
          <div style={{marginBottom:16}}>
            <L style={{marginBottom:4}}>Research Knowledge Base</L>
            <M style={{color:C.tm}}>v{KB_VERSION} · {KB_ENTRY_COUNT} peer-reviewed entries · the evidence behind your signals & guidance</M>
          </div>
          <Card style={{padding:14,marginBottom:16,borderColor:C.a+"30"}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8,flexWrap:"wrap"}}><M style={{color:C.a,fontWeight:600,fontSize:12}}>Analyst KB Assistant</M><Badge color={C.a}>on-device</Badge><M style={{color:C.tm,marginLeft:"auto"}}>Runs locally · cites the {KB_ENTRY_COUNT} KB entries</M></div>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.5}}>Ask the research base about burnout, workload, or recovery. Answers are generated on your device, grounded only in the Knowledge Base, and every claim is cited — unsupported answers are withheld. Your question and your signals never leave this device.</M>
            <M style={{color:C.tm,display:"block",marginBottom:10,lineHeight:1.5,fontStyle:"italic"}}>This explains the research — it isn't therapy, diagnosis, or crisis support. If you're carrying something heavy, <span onClick={()=>setTab("recovery")} style={{color:C.a,cursor:"pointer",textDecoration:"underline"}}>Post-Incident Wellness</span> has resources and ways to reach a person.</M>
            {kbModelStatus && kbModelStatus.noBridge && <M style={{color:C.w,display:"block",marginBottom:8}}>The local assistant runs only in the desktop app.</M>}
            {kbModelStatus && !kbModelStatus.noBridge && kbModelStatus.available===false && <div style={{padding:10,border:`1px solid ${C.w}40`,borderRadius:8,marginBottom:10}}>
              <M style={{color:C.w,display:"block",marginBottom:6,lineHeight:1.5}}>The on-device model isn't provisioned yet. FireAlive never downloads models — provision the official files on this machine, then verify. Everything runs locally; no data leaves the device.</M>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                <Btn small onClick={verifyKbModels} disabled={kbVerifying}>{kbVerifying?"Verifying…":"Verify provisioned files"}</Btn>
                {!kbProvisioning && <Btn small onClick={showKbProvisioning}>Show provisioning guide</Btn>}
              </div>
              {kbProvisioning && <div style={{marginTop:10,padding:10,border:`1px solid ${C.b}`,borderRadius:8}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                  <M style={{color:C.t,fontWeight:600}}>Provisioning (verify-only)</M>
                  <Btn small onClick={()=>setKbProvisioning(null)}>Hide</Btn>
                </div>
                <M style={{color:C.tm,display:"block",fontSize:11,marginBottom:8,lineHeight:1.5}}>Place the official files in: <span style={{color:C.t,fontFamily:"monospace"}}>{kbProvisioning.modelRoot}</span></M>
                {Object.keys(kbProvisioning.models||{}).map((mid)=>{const mm=kbProvisioning.models[mid];return (<div key={mid} style={{marginBottom:8,paddingTop:6,borderTop:`1px solid ${C.b}`}}>
                  <M style={{color:C.t,fontWeight:600,display:"block"}}>{mm.label} — <span style={{color:mm.present?C.a:C.w}}>{mm.present?"provisioned":"not provisioned"}</span></M>
                  <M style={{color:C.tm,display:"block",fontSize:11}}>Official: {mm.officialSource&&mm.officialSource.huggingFaceRepo} (pinned {mm.officialSource&&mm.officialSource.pinnedCommit})</M>
                  <M style={{color:C.tm,display:"block",fontSize:11}}>Endpoint floor: {mm.endpointFloor}</M>
                  {(mm.files||[]).map((ff)=>(<M key={ff.filename} style={{color:C.td,display:"block",fontSize:10,fontFamily:"monospace",wordBreak:"break-all"}}>{ff.filename} ({ff.sizeApprox}) — sha256: {ff.sha256}</M>))}
                </div>);})}
              </div>}
            </div>}
            {kbModelScan && !kbModelScan.error && <div style={{padding:10,border:`1px solid ${C.b}`,borderRadius:8,marginBottom:10}}>
              <M style={{color:C.t,fontWeight:600,display:"block",marginBottom:6,fontSize:11}}>Model integrity &amp; safety gate</M>
              {["chat","embed"].map((mid)=>{const g=kbModelScan[mid];const okp=g&&g.ok===true;const blocked=g&&g.ok===false;return (
                <div key={mid} style={{display:"flex",alignItems:"baseline",gap:8,marginBottom:4,flexWrap:"wrap"}}>
                  <M style={{color:C.tm,fontSize:11,textTransform:"capitalize",minWidth:46}}>{mid}</M>
                  <Badge color={okp?C.a:(blocked?C.w:C.tm)}>{okp?"passed":(blocked?String(g.overall||"blocked").replace(/_/g," "):"not yet run")}</Badge>
                  <M style={{color:blocked?C.w:C.tm,fontSize:11,lineHeight:1.5}}>{okp?"hash, format & malware checks clean":(blocked?(g.reason||"blocked before load"):"runs automatically before first use")}</M>
                </div>);})}
              <M style={{color:C.td,display:"block",fontSize:10,marginTop:4,lineHeight:1.5}}>Before the model loads, FireAlive checks the pinned hash, validates the GGUF format, and runs a local malware scan on this device. A file that fails any check is refused — it never loads.</M>
            </div>}
            {kbChatMsgs.length>0 && <div style={{display:"flex",flexDirection:"column",gap:10,marginBottom:10,maxHeight:360,overflowY:"auto"}}>
              {kbChatMsgs.map((msg,i)=>(
                <div key={i} style={{alignSelf:msg.role==="user"?"flex-end":"flex-start",maxWidth:"90%"}}>
                  {msg.role==="user"
                    ? <div style={{background:C.ad,border:`1px solid ${C.b}`,borderRadius:10,padding:"8px 12px",fontSize:11,color:C.t}}>{msg.text}</div>
                    : msg.distress
                      ? <div style={{border:`1px solid ${C.p}40`,borderRadius:10,padding:"10px 12px"}}><M style={{color:C.t,display:"block",marginBottom:8,lineHeight:1.6}}>This assistant explains research — it isn't the right place for what you're carrying right now, and you don't have to handle it alone.</M><Btn small onClick={()=>setTab("recovery")}>Open Post-Incident Wellness</Btn></div>
                    : msg.unavailable
                      ? <div style={{border:`1px solid ${C.w}40`,borderRadius:10,padding:"8px 12px"}}><M style={{color:C.w}}>{msg.reason==="citation_check_failed"?"Couldn't produce a fully-cited answer from the Knowledge Base, so it was withheld.":msg.reason==="no_retrieval"?"No relevant Knowledge Base entries were found for that question.":msg.reason==="model_unavailable"?"The on-device model isn't available — install it above to use the assistant.":msg.reason==="no_bridge"?"The local assistant runs only in the desktop app.":"The assistant is unavailable right now."}</M></div>
                      : <div style={{border:`1px solid ${C.b}`,borderRadius:10,padding:"10px 12px"}}>
                          <div style={{fontSize:11,color:C.t,lineHeight:1.7,whiteSpace:"pre-wrap"}}>{msg.text}</div>
                          {Array.isArray(msg.citedEntries)&&msg.citedEntries.length>0&&<div style={{display:"flex",gap:4,flexWrap:"wrap",marginTop:8}}>{msg.citedEntries.map(e=>(<button key={e.id} onClick={()=>setKbEntry(e)} style={{padding:"2px 8px",background:C.ad,border:`1px solid ${C.a}40`,borderRadius:6,color:C.a,fontSize:9,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>{e.id} ↗</button>))}</div>}
                        </div>}
                </div>
              ))}
            </div>}
            {kbChatLoading&&<M style={{color:C.tm,display:"block",marginBottom:8}}>Thinking… (on-device)</M>}
            <div style={{display:"flex",gap:8}}>
              <input value={kbChatInput} onChange={e=>setKbChatInput(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();sendKbChat();}}} placeholder="Ask the research base…" maxLength={2000} style={{flex:1,padding:10,background:"rgba(255,255,255,0.03)",border:`1px solid ${C.b}`,borderRadius:8,color:C.t,fontSize:12}}/>
              <Btn small onClick={sendKbChat} disabled={kbChatLoading||!kbChatInput.trim()}>Ask</Btn>
            </div>
          </Card>
          <div style={{display:"flex",gap:4,marginBottom:16,flexWrap:"wrap"}}>{["all",...[...new Set(RESEARCH_KB.map(r=>r.topic))]].map(f=>(
            <button key={f} onClick={()=>setKbFilter(f)} style={{padding:"3px 10px",background:kbFilter===f?C.ad:"transparent",border:`1px solid ${kbFilter===f?C.a+"50":C.b}`,borderRadius:6,color:kbFilter===f?C.a:C.tm,fontSize:9,fontFamily:"'IBM Plex Mono',monospace",cursor:"pointer"}}>{f}</button>
          ))}</div>
          <div style={{display:"flex",flexDirection:"column",gap:8}}>
            {RESEARCH_KB.filter(r=>kbFilter==="all"||r.topic===kbFilter).map(r=>(
              <Card key={r.id} onClick={()=>setKbEntry(r)} style={{padding:12}}>
                <div style={{display:"flex",gap:6,alignItems:"center",marginBottom:6,flexWrap:"wrap"}}><M style={{color:C.a,fontWeight:600}}>{r.id}</M><Badge color={r.strength==="strong"?C.a:C.w}>{r.strength}</Badge><Badge color={C.i}>{r.topic}</Badge><M style={{color:C.tm}}>{r.year}</M><M style={{color:C.tm,marginLeft:"auto"}}>Open ↗</M></div>
                <div style={{fontSize:11,color:C.t,lineHeight:1.6,marginBottom:4}}>{r.finding}</div>
                <div style={{fontSize:10,color:C.p,lineHeight:1.5,marginBottom:4}}>→ {r.implication}</div>
                {r.summary&&<div style={{fontSize:10,color:C.tm,lineHeight:1.6,marginBottom:4}}>{r.summary}</div>}
                <M style={{color:C.tm,fontStyle:"italic",lineHeight:1.5,fontSize:9}}>{r.cite}</M>
                <KBSourceCopy source={r.source}/>
              </Card>
            ))}
          </div>
          {kbEntry&&<Modal title={(kbEntry.id||"")+" — "+(kbEntry.title||kbEntry.topic||"KB entry")} onClose={()=>setKbEntry(null)} width={620}>
            <div style={{display:"flex",gap:6,alignItems:"center",marginBottom:12,flexWrap:"wrap"}}><Badge color={kbEntry.strength==="strong"?C.a:C.w}>{kbEntry.strength}</Badge><Badge color={C.i}>{kbEntry.topic}</Badge><M style={{color:C.tm}}>{kbEntry.year}</M></div>
            <M style={{color:C.t,fontWeight:600,display:"block",marginBottom:4}}>Finding</M>
            <div style={{fontSize:12,color:C.t,lineHeight:1.6,marginBottom:12}}>{kbEntry.finding}</div>
            {kbEntry.summary&&<><M style={{color:C.t,fontWeight:600,display:"block",marginBottom:4}}>Summary</M><div style={{fontSize:11,color:C.t,lineHeight:1.7,marginBottom:12}}>{kbEntry.summary}</div></>}
            <M style={{color:C.t,fontWeight:600,display:"block",marginBottom:4}}>FireAlive implication</M>
            <div style={{fontSize:11,color:C.p,lineHeight:1.6,marginBottom:12}}>→ {kbEntry.implication}</div>
            {Array.isArray(kbEntry.tags)&&kbEntry.tags.length>0&&<div style={{display:"flex",gap:4,flexWrap:"wrap",marginBottom:12}}>{kbEntry.tags.map(t=>(<Badge key={t} color={C.tm}>{t}</Badge>))}</div>}
            <M style={{color:C.tm,fontStyle:"italic",lineHeight:1.5,fontSize:10,display:"block"}}>{kbEntry.cite}</M>
            <KBSourceCopy source={kbEntry.source}/>
          </Modal>}
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
          <Card style={{marginBottom:16}}>
            <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5",marginBottom:10}}>Your Data</div>
            <M style={{color:C.tm,display:"block",marginBottom:12,lineHeight:1.6}}>Download a full copy of your FireAlive record -- your account, signals history, consent events, notification preferences, and key metadata -- to keep for yourself or to move elsewhere. Your private wellbeing entries are included sealed to your device, so only you can open them. This is your data-subject access and portability right; only you can run it for your own account.</M>
            <Btn onClick={async()=>{ try { const resp = await api.post("/api/data-subject/export", {}); if (!resp || resp.error) { logC("data_subject_export_failed","Personal data export failed"); return; } const blob = new Blob([JSON.stringify(resp, null, 2)], { type: "application/json" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "firealive-my-data-" + new Date().toISOString().slice(0,10) + ".json"; a.click(); URL.revokeObjectURL(a.href); logC("data_subject_export","Exported personal data (JSON)"); } catch (e) { logC("data_subject_export_failed","Personal data export failed"); } }}>Export my data (JSON)</Btn>
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
            <div style={{display:"flex",gap:12,alignItems:"center"}}>
              <button onClick={()=>{showLeadSafetyNumber();}} style={{background:"none",border:"none",color:C.a,cursor:"pointer",fontSize:11,fontFamily:"inherit"}}>Safety #</button>
              <button onClick={()=>{setLeadThread(null);setLM([]);setLeadSafetyNum(null);}} style={{background:"none",border:"none",color:C.i,cursor:"pointer",fontSize:11,fontFamily:"inherit"}}>Change lead</button>
              <button onClick={closeLeadThread} style={{background:"none",border:"none",color:C.w,cursor:"pointer",fontSize:11,fontFamily:"inherit"}}>Close chat</button>
            </div>
          </div>
          {leadSafetyNum&&<div style={{marginBottom:12,padding:"6px 8px",background:"rgba(0,0,0,0.3)",borderRadius:6}}><M style={{color:C.td,display:"block",marginBottom:2}}>Safety number (read aloud to compare; they must match):</M><M style={{color:C.a,fontFamily:"'Courier New',Courier,monospace",wordBreak:"break-all"}}>{leadSafetyNum}</M></div>}
          <Card style={{maxHeight:200,overflow:"auto",marginBottom:12}}>
            {leadMsgs.length===0?<M style={{color:C.td,fontStyle:"italic"}}>No messages yet.</M>:
            leadMsgs.map(m=><div key={m.id} style={{padding:"10px 14px",borderBottom:`1px solid ${C.b}`}}><div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}><M style={{color:C.a,fontWeight:500}}>{m.from}{m.kind==="inperson_1on1_request"?" · in-person 1:1 request":""}</M><div style={{display:"flex",gap:8,alignItems:"center"}}><M style={{color:C.td}}>E2EE · {m.ts}</M></div></div><div style={{fontSize:12,lineHeight:1.6}}>{m.text}</div></div>)}
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
          <Btn primary disabled={selfScanRunning} onClick={()=>{const bridge=(typeof window!=="undefined")?window.firealive:null;if(!bridge||typeof bridge.invoke!=="function"){logC("SELF_SCAN_STARTED","Self-scan requires the desktop app");return;}setSelfScanRunning(true);logC("SELF_SCAN_STARTED","Compromise self-scan initiated");bridge.invoke("selfscan:run",{token:api._token}).then((r)=>{setSelfScanRunning(false);if(!r||r.error){logC("SELF_SCAN_COMPLETE","Self-scan error: "+((r&&r.error)||"unknown"));return;}let details=[];try{details=JSON.parse(r.details_json);}catch(_e){}setSelfScanResult({ts:r.scan_started_at,status:r.status,tests:r.tests_total,passed:r.tests_passed,failed:r.tests_failed,inconclusive:r.tests_inconclusive,details:details});try{if(acScanWsRef.current&&acScanWsRef.current.readyState===1)acScanWsRef.current.send(JSON.stringify({type:"scan_result",runId:null,result:r}));}catch(_e){}logC("SELF_SCAN_COMPLETE","Result: "+r.status+" ("+r.tests_passed+"/"+r.tests_total+" passed)");}).catch(()=>{setSelfScanRunning(false);logC("SELF_SCAN_COMPLETE","Self-scan failed");});}}>{selfScanRunning?"Scanning all 10 checks...":"Run Self-Scan"}</Btn>
          {selfScanResult&&(<Card style={{marginTop:16}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}>
              <div style={{fontSize:13,fontWeight:500,color:"#E8EDF5"}}>Scan Results — {new Date(selfScanResult.ts).toLocaleString()}</div>
              <Badge color={selfScanResult.status==="clean"?C.a:selfScanResult.status==="fail"?C.d:C.w}>{selfScanResult.status}</Badge>
            </div>
            <M style={{color:C.td,display:"block",marginBottom:12}}>{selfScanResult.passed} passed · {selfScanResult.failed} failed · {selfScanResult.inconclusive} inconclusive (of {selfScanResult.tests})</M>
            {(selfScanResult.details||[]).map((d,i)=>{const col=d.status==="pass"?C.a:d.status==="fail"?C.d:C.w;const mk=d.status==="pass"?"✓":d.status==="fail"?"✗":"~";return <div key={i} style={{padding:"6px 0",borderBottom:`1px solid ${C.b}`}}><div style={{display:"flex",justifyContent:"space-between"}}><M style={{color:C.t}}>{d.name||d.id}</M><M style={{color:col,fontWeight:600}}>{mk} {d.status}</M></div>{d.detail&&<M style={{color:C.tm,fontSize:11,display:"block",marginTop:2}}>{d.detail}</M>}</div>;})}
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
                <M style={{color:C.td,fontSize:11,lineHeight:1.5}}>Every export is Ed25519-signed and recorded in an append-only chain. Modifying or deleting an export entry after the fact would break the chain&apos;s hash continuity — the tampering would be visible to any team lead.</M>
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

// Canonical React 18 mount (PR H): explicit, single, defensive root.
// No reliance on a runtime transpiler's implicit auto-render.
const _rootEl = document.getElementById("root");
if (!_rootEl) {
  const _err = document.createElement("div");
  _err.textContent = "Fatal: #root element not found. FireAlive cannot start.";
  _err.style.cssText = "font-family:monospace;color:#EF4444;padding:24px;font-size:14px";
  document.body.appendChild(_err);
} else {
  createRoot(_rootEl).render(<AnalystClientApp />);
}

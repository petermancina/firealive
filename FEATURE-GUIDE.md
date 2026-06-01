# FireAlive Feature Guide

A plain-language reference to every feature in the FireAlive suite. For each feature: what it's for, who uses it, when, and the workflow to use it.

This guide is bundled with every FireAlive distribution and is also accessible via the Help tab in each application (Management Console, Analyst Client, Global Dashboard).

If you're new to FireAlive, start with **The Big Picture** below.

---

## The Big Picture

FireAlive is a SOC analyst burnout-prevention platform. Security Operations Centers burn out their analysts at brutal rates — turnover, errors, mental health damage. FireAlive sits inside the team's existing SOC tooling stack and intervenes at the points where burnout actually happens: ticket assignment, peer support, training, post-incident recovery, shift transitions.

Four apps make up the suite:

- **Analyst Client (AC)** — runs on each analyst's workstation. Where the analyst sees their own signals, asks for help, takes care of themselves.
- **Management Console (MC)** — runs on the team lead's workstation. Where the lead sees aggregate team health (no individual burnout data), configures the platform, runs operations.
- **Abuse Review Console (ARC)** — runs on the independent abuse reviewer's own workstation. A role separate from team leadership; reviews abuse reports that neither the analyst client nor the management console can decrypt. Every deployment must designate at least one reviewer before abuse reporting becomes available.
- **Global Dashboard (GD)** — runs on the CISO's workstation. Read-only view aggregating across multiple regional MCs. Executive-level visibility without the operational details.

A regional **Server** sits behind the AC/MC/ARC. A separate **GD Server** aggregates from regional MCs.

The whole thing is built on four privacy commitments:
- **Tier-3 data** (individual burnout signals) is encrypted on the analyst's client and never seen by the lead
- **Tier-1 data** (team-level aggregates) is what the lead sees — averages, never individuals
- **Pseudonyms** decouple analyst identity from burnout data at the database layer
- **Abuse-report zero-access:** abuse reports (peer-session, board-post, lead-chat) are sealed on the reporter's device to the active reviewer recipient set before they leave the app. The server, management, team leads, and admins (who handle only public keys) cannot decrypt them — only a designated independent reviewer can.

---

# MANAGEMENT CONSOLE (Team Lead)

## Operations group — the lead's daily workspace

### Actions
**What it's for:** The lead's daily action queue. The platform reads aggregate team signals (utilization spikes, capacity overload, extended stress patterns) and surfaces priority prompts for the lead to act on. Each prompt cites the underlying research so the lead understands why this is being flagged.

**Workflow:**
1. Lead logs in at the start of shift
2. Lands on Actions tab
3. Sees prompts ranked by severity (red = high, amber = medium, gray = low)
4. Each prompt shows the issue, suggested response, supporting research citation
5. Lead can adjust prompt depth (full / compact / minimal) for their attention level
6. Lead either acts on a prompt or silences it (if they've decided not to act)

### Team Overview
**What it's for:** The lead's at-a-glance team capacity view. Shows workload metrics — utilization %, ticket counts, capacity caps — but never burnout signals. The deliberate boundary: the lead sees enough to manage capacity but not so much that they're surveilling individuals' wellbeing.

**Workflow:**
1. Lead opens Team Overview
2. Sees four headline metrics (Team Health score, Avg Utilization, # Over Capacity, # Extended)
3. Per-analyst capacity cards show utilization bars, ticket counts, complexity caps
4. Lead spots someone over capacity, makes routing adjustments in the Routing tab

### Routing
**What it's for:** Where the lead manages FireAlive's burnout-aware ticket routing — per-analyst complexity caps, the equity engine, the live feed, the panic button, and the silent-pause toggle. This tab is the operational surface; the integration credentials live one tab over in **SOAR & Ticketing**.

**Workflow:**
1. Lead opens Routing tab
2. Adjusts per-analyst complexity caps using +/- buttons (tier 1 might cap at complexity 2, tier 3 might handle complexity 5)
3. Clicks Apply to save the changes to the canonical routing API
4. Watches the live feed for routing decisions as they happen
5. If team-wide intake needs to pause briefly (scheduled maintenance, integration troubleshooting), the silent-pause toggle in this tab stops FireAlive from publishing routing variables to the SOAR until re-enabled — distinct from panic mode below, this is silent and doesn't notify analysts

**Panic button (always visible in the MC header).** A red button at the top right of every MC screen lets the lead engage panic mode with one click + a confirmation dialog. Panic mode disables all wellness routing, sets every analyst's complexity cap to maximum (5), and broadcasts an in-app notification to every active analyst that wellness routing is OFF and they may receive tickets above their usual complexity cap. The lead can restore normal routing with another click on the same button; restoration also broadcasts a notification to every analyst. After deactivation, a green "Panic mode lifted — wellness routing restored" banner shows at the top of the MC and AC for 5 minutes, then vanishes.

**Top-of-MC panic banner.** When panic mode is active, a red full-width banner sits above the page header on every tab: "PANIC MODE ACTIVE — All wellness routing disabled. Every analyst is at maximum complexity." After deactivation the banner turns green for 5 minutes, then disappears. The MC polls the canonical panic-state endpoint every 30 seconds so the banner is always in sync with the current state regardless of which tab is open.

**The routing_enabled silent-pause toggle** is distinct from panic mode in two ways. First, it's silent — analysts are not notified. Second, it only pauses outbound variable publishing to the SOAR; the analyst's local complexity caps remain in effect. Use it when the SOAR doesn't need fresh variables (scheduled maintenance, non-business-hours integration debugging) without panicking the team.

### SOAR & Ticketing
**What it's for:** Where the lead configures FireAlive's integration with the existing SOAR platform (so FireAlive can publish capacity intelligence the SOAR uses to make routing decisions) and ticketing system (read-only — for queue metadata). This is the **configuration** surface; the operational surface for adjusting caps and watching routing happen lives in the **Routing** tab.

**Workflow:**
1. Lead enters SOAR platform name, API endpoint, service account, API key
2. Optionally enables auto-escalation (when a ticket exceeds the assigned analyst's complexity cap, the SOAR auto-routes to a senior tier rather than dropping or queueing)
3. Enters ticketing platform name, read-only API endpoint, API key
4. Clicks Save SOAR Config (saves both SOAR and ticketing configurations in sequence)
5. Clicks Test Connection to verify the SOAR is reachable; the response includes a round-trip confirmation if auto-escalation is enabled
6. Watches the **Live SOAR Routing State** card — shows the 6 routing variables FireAlive is currently publishing to the SOAR, refreshed every 30 seconds while this tab is open

**SOAR Polling Contract.** Once the SOAR is configured, it polls `GET /api/routing/variables` on its own cadence (typical 30–60 seconds) with an api-key authenticated against the `routing:read` scope. FireAlive returns the current state: per-analyst capacity context (keyed by pseudonym, never by user ID), panic mode state, the silent-pause toggle state, and the six SOAR variables (`analyst_capacity`, `complexity_cap`, `equity_weights`, `skill_matrix`, `burnout_risk_tier`, `shift_handoff`). The SOAR uses these values in its own playbook logic to make routing decisions; FireAlive never distributes tickets directly. When the SOAR completes a routing decision, it posts the decision back via `POST /api/routing/soar-events` (api-key + `routing:events` scope), and FireAlive persists the event for the capacity-feedback loop. See `docs/integrations-privacy.md` for the full contract including the pseudonym-only privacy invariant.

**Ticketing read-only invariant.** The ticketing integration is enforced read-only server-side: whatever the lead supplies for the `readOnly` flag (or omits) is overwritten with `true` before the configuration is encrypted to disk. The MC's SOAR & Ticketing tab doesn't expose a `readOnly` toggle at all. This is a defense-in-depth measure: even an attacker who bypasses the UI cannot reconfigure ticketing for write access. The integration ships with the contract established and a mock-shape queue-metadata endpoint (`GET /api/integrations/ticketing/queue`). Per-platform adapters (ServiceNow, Jira, TheHive, PagerDuty, Freshservice) are tracked as separate backlog items rather than against a vague future phase — operators with a specific platform need can file an issue against `petermancina/firealive` referencing the adapter contract documented in `docs/integrations-privacy.md`.

### Shift Handoff
**What it's for:** Structured shift-to-shift handoffs to prevent the information loss that causes errors during transitions. Research shows handoff errors peak in the last two hours of shifts when analysts are most fatigued. This formalizes the handoff so context doesn't get dropped.

**Workflow:**
1. Outgoing lead at end of shift opens Shift Handoff tab
2. Sees an auto-generated summary (current team health, active routing adjustments, active recovery protocols, open high-priority incidents, staffing notes)
3. Adds free-text context for the incoming lead — what's in progress, anything unusual
4. Submits handoff (optionally also sends a notification to the incoming lead)
5. Incoming lead opens the same tab at start of their shift, reads the handoff, knows where things stand

### SLA
**What it's for:** Track Mean Time to Acknowledge (MTTA) and Mean Time to Resolve (MTTR). When SLA performance degrades, FireAlive correlates with team capacity to help the lead distinguish "the team is slow because they're overloaded" from "the team is slow because they're undertrained" — different problems, different fixes.

**Workflow:**
1. Lead opens SLA tab
2. Sees current MTTA/MTTR vs targets, broken down by priority level
3. If SLAs are slipping, the dashboard shows whether team capacity is the cause
4. Lead either redistributes tickets (capacity problem) or assigns training (skill problem)

### Automation
**What it's for:** Where the team lead registers the automated systems that analysts can offload routine, low-level tickets to. This is NOT for monitoring the systems that feed tickets in — it's the opposite. Analysts in their AC have a Delegate feature where they can identify repetitive ticket patterns (false positives they keep closing, low-level routine work that doesn't need human judgment) and send those tickets to an automated system. The lead uses this Automation tab to tell FireAlive which automated systems are available for that purpose. The configuration propagates from MC to all connected ACs so analysts know which systems they can delegate to.

This is also the integration point for FireAlive to work alongside other anti-burnout tools. Research has shown that most anti-burnout programs in the industry are built around automating boring, routine tasks. So the Automation tab is also where the lead connects FireAlive to those existing automation programs the org already runs — SOAR's automated response, dedicated ticket-automation tools, AI triage systems, anything that takes shitjob busywork off the analyst's plate. Boosting human analyst capacity is the goal; this tab is where that boost gets wired in.

**Workflow:**
1. Lead identifies the automated systems in use across the org (SOAR auto-response actions, dedicated ticket-automation platforms, AI triage systems, other anti-burnout tools)
2. Opens Automation tab in MC
3. Adds each system: name, type, what it can handle, capacity ceiling
4. Configuration propagates to every connected AC
5. Analysts in the AC's Delegate tab now see the available automation targets
6. When an analyst delegates a ticket pattern, it routes to the appropriate automated system the lead registered

### Fail-Open Routing
**What it's for:** Like an IPS configured to fail-open: if FireAlive's burnout routing engine itself fails, the system reverts to the SOAR's native distribution rather than blocking ticket flow. The SOC keeps defending the network even when FireAlive is down.

**Workflow:**
1. Lead opens Fail-Open Routing tab
2. Configures health check interval (e.g. every 10 seconds)
3. Sets max time in fail-open mode before requiring manual intervention (e.g. 30 minutes — long enough to ride out a glitch, short enough to force escalation if FireAlive is genuinely broken)
4. If routing engine fails health check: tickets revert to SOAR-native routing immediately, lead is notified
5. When FireAlive comes back, routing resumes automatically

### Auto-Disable Routing
**What it's for:** During a major incident requiring all hands, the lead shouldn't have to remember to manually disable burnout-aware routing — that would slow them down at the worst time. This feature auto-disables routing when high-severity triggers are detected, so every available analyst gets tickets immediately. Routing restores after the incident is over.

**Workflow:**
1. Lead pre-configures triggers in advance (P1 ticket, SIEM critical alert, SOAR escalation)
2. Sets cooldown — how long after the trigger clears before routing re-enables (e.g. 60 minutes)
3. When an actual incident hits: trigger fires, routing auto-disables, all analysts receive tickets, lead's dashboard shows banner
4. After cooldown, routing automatically resumes burnout-aware behavior

### Runbook Generator
**What it's for:** Generate runbooks for incidents and failures involving FireAlive itself — not for general incident response. The org already has runbooks for ransomware, phishing, etc.; FireAlive doesn't try to replace those. What FireAlive's adoption introduces is a new attack surface: an MC-AC communication channel, AC clients on every analyst workstation, encrypted Tier-3 data, signal feeds that could be poisoned, peer chat infrastructure. That's the surface this runbook generator addresses.

The scenarios in this generator are FireAlive-specific:
- Compromise of FireAlive that claims theft of burnout data
- Attacker uses compromised AC clients to inject false burnout stats, tricking the routing engine into reducing tickets across the team and tripping the tripwire
- Compromise of MC-AC communication channel
- Analyst client integrity failure
- Server crash with degraded HA
- Peer chat infrastructure compromise
- Backup system tampering

For each, the generator produces a step-by-step runbook covering identification, containment, eradication, restore (often including the workflow of tearing down a compromised app instance and using the Restore feature to rebuild from backup), and lessons-learned. The intent is to get the team thinking through how their attack surface has expanded by adopting FireAlive and how to defend that new surface.

**Workflow:**
1. Lead opens Runbook Generator (proactively, before any incident)
2. Picks a FireAlive-specific scenario from the dropdown
3. Clicks Generate
4. Sees the multi-step runbook
5. Exports as JSON, PDF, or DOCX, or prints
6. Keeps the printed runbook somewhere accessible during an incident — when systems may be down

This is preparation material. During an actual incident, the team executes from the printed copy.

---

## Analysts & Wellbeing group — managing the people

### Skills Matrix
**What it's for:** Aggregate view of where each analyst is on the skill ladder. The lead sees who's progressing across multiple core skills — useful for spotting promotion candidates and identifying team-wide skill gaps. When an analyst crosses proficiency thresholds across 3+ skills, a "level-up signal" surfaces here as recognition (not as an automatic promotion trigger — the lead decides).

**Workflow:**
1. Lead opens Skills Matrix at the end of the quarter for review
2. Sees each analyst's current tier, top progressing skills, and any level-up signals
3. For analysts with level-up signals: lead schedules a growth conversation
4. Lead can silence signals they've already acknowledged or acted on

### Assessments
**What it's for:** Targeted skill assessments the team lead creates to verify whether specific analysts can handle specific things. Distinct from the AC-side baseline assessments analysts take when they first start using FireAlive (those populate the gaps display and feed the upskilling training engine, all visible only to the analyst). Lead-created targeted assessments are different: the lead identifies a specific skill the team needs (Kubernetes Security, malware analysis, buffer overflow handling, etc.), creates an assessment alert for that skill, and pushes it to one or more analyst's ACs.

The actual assessment module is hosted on an external platform — HackTheBox, TryHackMe, LetsDefend, Cyberdefenders, SANS, etc. FireAlive doesn't host the modules. Instead, the assessment alert sent to the AC tells the analyst where to go to take it. The analyst completes the module on the external platform, then submits a completion report (link, score, date) back into the AC. The result populates the analyst's gap display and training suggestions in the AC, AND — unlike the AC-side baseline assessments — the lead sees the result. So lead-created targeted assessments serve two purposes: they show the analyst where they stand on a skill, AND they give the lead visibility into who can or can't handle a specific scenario.

**Workflow:**
1. Lead identifies a skill that's needed (e.g. "Kubernetes security incident response")
2. Clicks "+ Create Assessment"
3. Names it for the skill: "Kubernetes Security Skills Assessment"
4. Picks the target tier (Tier 1 / Tier 2 / Tier 3) — assessment skill list filters to tier-appropriate options
5. Selects skills from the taxonomy via checkboxes (or adds custom skills for org-specific topics)
6. Specifies the external module: which platform (TryHackMe, HackTheBox, etc.), which module, the URL
7. Picks which analyst(s) to assign it to (or the whole team)
8. Submits — analyst's AC shows an Assessment Required notification at the top of the appropriate tab with directions on where to go
9. Analyst goes to the external module, completes it, submits the completion report back through their AC
10. Lead sees results come back, color-coded (green = strong, amber = on threshold, red = gap)
11. Gap areas auto-create training recommendations for that analyst — no further action needed
12. Lead now knows which analysts can handle that scenario, which may inform routing, ticket assignment for related incidents, or upskilling priorities

### Certifications
**What it's for:** Lead-side view of analysts' broader industry certifications (CompTIA, ISACA, GIAC, etc.) beyond the platform's training-linked certs. Used for identifying team-wide gaps and planning upskilling. There's also an MC-side cert input wizard so the lead can input certs themselves — useful when an analyst hands the lead a physical cert as proof of completion and the lead prefers to record it directly rather than asking the analyst to submit through their AC.

**Workflow (analyst submits, lead verifies — typical):**
1. Analyst registers a cert in their AC (uploads file, enters verification number)
2. Lead opens Certifications tab in MC
3. Sees aggregated view: which certs each analyst has, expirations
4. Verifies new cert submissions, identifies team-wide gaps

**Workflow (lead inputs directly):**
1. Analyst hands the lead a physical certificate of completion
2. Lead opens Certifications tab → "+ Add Cert for Analyst"
3. Picks the analyst, enters cert details, uploads scanned copy
4. Cert is recorded against that analyst's profile

### Training Reviews
**What it's for:** Lead-side queue for verifying or rejecting training completions that analysts have self-submitted through the Submit Completion form in their AC. Each row shows the analyst, the platform and module URL they submitted, the timestamp, and the current status. The lead validates that the analyst genuinely completed the training and either credits it (verify) or marks it not credited (reject). Pre-existing certificate uploads with file proof go through the Certifications tab instead — Training Reviews is specifically for lightweight URL-based completion claims tied to modules surfaced by the gap-driven recommender.

**Workflow:**
1. Analyst finishes a training module recommended by FireAlive (or any other module they want to log)
2. Analyst opens their AC's Training tab and uses the Submit Completion form: platform name, module URL, optional completion date, optional score
3. Submission lands in the pending queue with `status = "pending"`
4. Lead opens Training Reviews tab in MC; navGroup badge shows the pending count
5. Lead filters by Pending (default), Verified, Rejected, or All
6. For each pending row, lead clicks Verify (credits the completion to the analyst's skill record) or Reject (marks it not credited)
7. Verified and rejected rows are terminal — to reverse, the analyst must resubmit, which creates a new pending row preserving the original audit trail

**State machine and audit:** The server enforces only `pending → verified` and `pending → rejected` transitions; anything else is rejected with 409. Every list view emits a `TRAINING_COMPLETIONS_REVIEW_VIEWED` audit event; every transition emits `TRAINING_COMPLETION_VERIFIED` or `TRAINING_COMPLETION_REJECTED` with the completion ID and the acting user's ID. See `docs/training-library.md` for the full schema, seed catalog provenance rules, and the recommender flow.

### CISM Retro (Incident Retrospectives)
**What it's for:** Structured post-incident support based on Critical Incident Stress Management research. After major incidents — ransomware, breaches, active intrusions — analysts experience acute stress comparable to emergency services responders. This module activates a recovery protocol: lighter queues for affected analysts, peer support availability, automated follow-up check-ins at 24hr / 72hr / 2 weeks.

**Workflow:**
1. Major incident wraps up
2. Lead opens CISM Retro tab
3. Clicks "Activate New Recovery Protocol"
4. Enters incident reference, severity, selects which analysts were involved
5. Picks queue reduction duration (this shift / 24hr / 72hr / 1 week)
6. Activates — affected analysts get lighter queues, peer support is enabled in their AC, follow-up check-ins scheduled
7. Lead can mark the protocol complete or send manual follow-ups
8. Participation is voluntary — analysts can decline anything, the lead just makes it available

### Peer Skill-Share Configuration
**What it's for:** Where the lead configures the peer-to-peer help system between analysts. Sets when peer chat can be used (block during heads-down hours? allow during shift?), session duration limits, and crucially the Helper Pay configuration — analysts who help peers earn points convertible to PTO or cash.

**Workflow:**
1. Lead opens Peer Skill-Share Configuration
2. Configures scheduling restrictions (allow during shift toggle, block hours, max session duration, inactivity timeout)
3. Configures Helper Pay: USD per 100 points, PTO minutes per 100 points, tier multipliers (L3 senior helpers earn more), redemption minimum, approval workflow
4. Reads chat disclaimer — the lead can NOT edit it; this is the analysts' protected space

### Helper Recognition Leaderboard
**What it's for:** Top opted-in helpers ranked by Helper Pay points. Lives on the same peersupport tab as the Peer Skill-Share Configuration. The leaderboard is a recognition surface — it shows analysts who have explicitly opted in via their AC's Helper Pay tab. Analysts who have not opted in are absent from this list regardless of how many points they've earned; opt-in is per-analyst and defaults to off.

Points come from 4-5 star peer-session ratings (1-2 star yields zero points, 3 star yields a low amount). A minimum session duration gate and a daily-cap clamp prevent gaming via short or excessive ratings. The Confirm Fraud / Dismiss queue (below) catches sock-puppet abuse beyond what the static gates cover.

**Workflow:**
1. Lead opens peersupport tab
2. Sees the top 10 opted-in helpers by points
3. Per row: pseudonym (or real name if pseudonyms not enabled), sessions count, average rating, points balance
4. Can send an anonymous thank-you to any helper via the Thank button — no name reveal to the helper

### Team Helper Scores (operational view)
**What it's for:** Full-roster view showing EVERY active analyst's Helper Pay state, regardless of whether they've opted in to the recognition leaderboard. This is the lead's operational surface for payroll reconciliation, compensation discussions, and quarterly performance reviews. The opt-in indicator on each row is purely informational — only the analyst can flip it from their AC; the lead cannot toggle it on behalf of someone else.

This surface deliberately bypasses the opt-in filter that gates the recognition leaderboard above — Helper Pay involves real money / PTO redemption, and the lead needs complete visibility for those administrative duties. Privacy invariant I5 in the architectural docs.

**Workflow:**
1. Lead opens peersupport tab
2. Scrolls past the recognition leaderboard to Team Helper Scores
3. Sees every active analyst: pseudonym/name, opt-in badge (Visible / Hidden), sessions, avg rating, points balance
4. Uses for payroll, performance reviews, or to spot disengagement signals (analyst with zero points who hasn't accepted any peer sessions)

### Pending Sock-Puppet Review
**What it's for:** Lead-side review queue for sock-puppet abuse detection. The detector flags a rating when its rater's IP hash OR device hash matches 2+ other ratings against the same helper within the last 7 days — a pattern that suggests the same person is faking ratings under multiple accounts to grind points for a helper.

Flagged ratings still grant points at rating time (the helper sees their balance immediately for legitimate ratings), but the flagged contribution is excluded from the recognition leaderboard until lead review. Confirm Fraud triggers a reversal ledger entry that permanently removes the points; the rating row stays flagged forever as audit evidence. Dismiss clears the flag and the points re-appear on the leaderboard. Both decisions are logged via explicit audit_log events.

**Workflow:**
1. Detection runs on each new rating POST — checks IP and device hash clusters against same helper within 7 days
2. If cluster ≥ 3 ratings, the new rating is flagged
3. Lead opens peersupport tab → Pending Sock-Puppet Review Card
4. Per flagged row: rater pseudonym, helper pseudonym, stars given, comment (if any), cluster reason (IP / device / both), flagged timestamp
5. Lead inspects: legitimate small-team usage where 3 analysts genuinely rated the same helper from one office network? Confirm Fraud (real sock-puppet) or Dismiss (false positive)
6. Confirm path: reverses the points via the existing fraud reversal flow; audit event LEADERBOARD_SOCKPUPPET_CONFIRMED
7. Dismiss path: clears the flag, points restored to leaderboard; audit event LEADERBOARD_SOCKPUPPET_DISMISSED

### Pseudonyms
**What it's for:** The architectural privacy commitment: every analyst gets a permanent UUID and rotating pseudonym (Analyst-Falcon, Analyst-Kestrel, etc.). All burnout metrics, peer chat messages, reduced-routing requests, and wellness signals are stored against the pseudonym — never the real name. If the database is breached, attackers see "Analyst-Falcon is in elevated burnout" rather than a real person. The mapping (UUID → pseudonym → real name) is exported as an encrypted file the lead stores offline.

**Workflow:**
1. Lead opens Pseudonyms tab on initial setup
2. System generates pseudonyms for each analyst from a stable list (animals, etc.)
3. Lead exports the mapping as an encrypted file — stores it on a USB key in the safe, NOT on the network
4. Periodically rotates pseudonyms (quarterly, after offboarding events) — UUIDs stay the same so historical data is preserved
5. When the lead needs to know which real person Analyst-Falcon is (e.g. for a CISM retro), they look up the offline mapping

### IR Simulator (lead-side, ooda_mgmt)
**What it's for:** The lead uploads their organization's IR policies, playbooks, and after-action reports here. The system parses each policy and generates OODA-loop training scenarios that analysts then practice in their AC. The point: analysts train on **their own org's procedures**, not generic textbook procedures. A new analyst joining shouldn't have to figure out "how does THIS team handle phishing" through trial-by-fire — they should practice it in the simulator first.

**Workflow:**
1. Lead opens IR Simulator (Policy Management) tab
2. Uploads the org's ransomware response playbook (text or file)
3. Names it, tags type (incident_response / playbook / runbook / policy / procedure)
4. Saves — system parses the policy and generates one or more OODA scenarios from it
5. Lead can also pick a scenario type (ransomware, phishing, data_exfil, insider_threat, apt, ddos, supply_chain, credential_compromise) and have the system generate a scenario from that policy targeted at that scenario type
6. Repeats for each major IR policy the org has
7. Now analysts in their AC can practice these scenarios. After completion, the analyst sees the actual policy that was used to generate the scenario.

### Proactive Breaks
**What it's for:** Based on Sonnentag's recovery research: prolonged high-severity ticket work without breaks accelerates burnout exponentially. This feature monitors workload patterns and suggests breaks BEFORE burnout signals appear — preventive rather than reactive. The lead approves the suggestion before it goes to the analyst (so analysts aren't being told what to do by the system without lead oversight).

**Workflow:**
1. Lead configures: "After N hours of continuous high-severity work, suggest a break of M minutes"
2. Toggles "Require Team Lead approval before sending"
3. Analyst hits the threshold — system pings the lead
4. Lead reviews ("yes this analyst should take a break") and approves
5. Analyst gets an affirming notification: "You've been working hard. Consider a 15-minute break."
6. Analyst can take the break or continue — their choice

### Upskilling Hour
**What it's for:** Dedicate one hour per shift to professional development. During that hour, the analyst's queue is paused — they can study, peer skill-share, do training, work on certifications. The research is unambiguous: companies that fund on-the-clock development have lower turnover than companies that demand analysts upskill on their own time.

**Workflow:**
1. Lead opens Upskilling Hour tab
2. Configures: "1 hour during the 8th hour of shift" (so it's at the end, but configurable)
3. Sets minimum coverage requirement (e.g. "75% of team must be on-shift" — so the whole team isn't simultaneously upskilling)
4. Assigns each analyst to a slot (different times so coverage stays adequate)
5. Optionally integrates with HR scheduling system (UKG/Workday/ADP)
6. During an analyst's slot, their AC pauses ticket routing and shows training resources / peer chat options

### Offboarding
**What it's for:** Securely deprovision analysts who leave or change roles. Their historical aggregate data stays for team metrics, but personally identifiable links are severed. All keys/sessions/peer-chat schedules are revoked. Integrates with IAM (so when HR offboards in the IdP, FireAlive picks it up) and SOAR (so offboarding orchestration is automatic).

**Workflow:**
1. Either: lead manually offboards (picks analyst, reason: voluntary departure / termination / role change / transfer)
2. Or: IAM offboarding detector runs on schedule (every 4hr / 8hr / daily / weekly), checks the IdP for users no longer present, surfaces them for the lead to confirm
3. Lead confirms either "still active" (resets the recertification timer) or "offboard"
4. On offboard: account marked inactive, sessions revoked, pseudonym removed from rotation, historical aggregate data preserved under the UUID

### Sync Interval
**What it's for:** Control how often analyst clients transmit burnout metrics to the server. Default is every 15 minutes (batch mode) — continuous sync wastes bandwidth and provides no real benefit. Adaptive mode ramps up sync frequency during incidents and slows down when stable.

**Workflow:**
1. Lead opens Sync Interval tab once during setup
2. Sets base interval (15 minutes default)
3. Toggles adaptive mode (recommended — speeds up during incidents)
4. Sets urgent event threshold — for panic events / critical incidents, push immediately rather than wait for next interval
5. Saves — applies to all connected analyst clients

### Client Notifications
**What it's for:** Configure how each user (lead and analyst) receives notifications from FireAlive. Per notification type, each user chooses delivery: email, SMS, desktop notification, in-app inbox, multiple, or off. The inbox is one channel option among many — for users who want a place to find missed notifications. It's not mandatory.

**Workflow:**
1. Each user (lead AND analyst) opens their notification preferences
2. Per notification type (assessment assigned, retro scheduled, peer request, panic broadcast, helper points awarded, etc.) chooses delivery: in-app inbox / email / SMS / desktop notification / multiple / off
3. Notifications fire through the channels they chose — never through ones they didn't
4. The inbox is one channel option — for users who want a place to find missed notifications

---

## Integrations group — connecting to the rest of the SOC stack

### Integrations Health Dashboard
**What it's for:** Real-time status of every external system FireAlive depends on — SOAR, ticketing, SIEM, EDR, IdP, KMS, etc. If any disconnect, the lead is alerted before it causes routing failures.

**Workflow:**
1. Lead glances at this tab daily as part of shift opening
2. All integrations show green = healthy
3. If something turns red or amber: lead clicks through to the specific integration tab to investigate

### SIEM Integration
**What it's for:** Push FireAlive's metrics to the org's SIEM in CEF format so SOC management tooling has visibility into FireAlive's own health. Optionally: restrict the burnout metrics widget to the lead's SIEM dashboard only — protect team morale from analysts seeing aggregate burnout numbers that could feel demoralizing.

**Workflow:**
1. Lead configures SIEM endpoint
2. Toggles which metrics get pushed (system health, security events, burnout aggregates with visibility scope)
3. SIEM ingests the CEF stream
4. SIEM dashboards now show FireAlive-specific health alongside everything else the SOC monitors

### EDR File Inspection
**What it's for:** Every file uploaded to FireAlive (config restores, IR policy uploads, IaC imports, app updates) gets scanned by the org's EDR before being processed. Prevents a malicious file from reaching FireAlive's internals through the upload path.

**Workflow:**
1. Lead configures EDR provider in this tab
2. Whenever someone uploads a file anywhere in FireAlive: system pauses, calls EDR scanner with file
3. Scanner returns clean → upload proceeds
4. Scanner returns malicious → upload rejected, lead notified, audit log entry

### Threat Hunting Integrations
**What it's for:** Open FireAlive itself to inspection by the org's threat-hunting tooling — XDR behavioral monitoring, ATP, Next-Gen AV, MSP scanners. So the org can detect if FireAlive itself is compromised. Companion to EDR (which scans files coming IN); this enables tools to scan FireAlive's own behavior.

**Workflow:**
1. Lead configures provider per category
2. Hunting tools now have authorized access to scan FireAlive
3. Findings flow back through normal hunting workflow

### Client Provisioning
**What it's for:** Analysts never install the AC themselves — the lead provisions clients via enterprise deployment tooling. Prevents rogue installs and ensures every AC starts with the right config (server endpoint, enrollment token).

**Workflow:**
1. Lead opens Client Provisioning tab
2. Configures deployment tool (Intune / Jamf / SCCM / Workspace ONE / Ansible)
3. Per analyst: enters name, tier, shift, target hostname, IP
4. Clicks "Provision Client" — system generates a config.json + enrollment token, packages it for the deployment tool
5. Deployment tool pushes the AC to the analyst's machine
6. Analyst opens the AC, authenticates via IAM + MFA, baseline calibration begins

### AI/ML Integrations
**What it's for:** External AI/ML systems FireAlive can integrate with for the burnout prediction engine, scenario generation in the IR Simulator, signal analysis. Some are internal (always required), some optional.

**Workflow:**
1. Lead configures provider, endpoint, API key
2. AI/ML features start using the configured integration

**Local AI model provisioning (verify-only):** FireAlive never downloads AI models. The operator obtains the official files through their own vetted channel and places them in the model directory; FireAlive computes each file's SHA-256, compares it to a hash **pinned in source**, and loads the model only on an exact match — refusing with an honest "unavailable" on any missing or mismatched file. No outbound model fetch ever occurs, and operators never supply hashes at runtime (rotating a model is a reviewed source change).

**Model-file integrity & safety gate (before load, fail-closed):** Hash-pinning proves a file is *the* official artifact, but the loader (node-llama-cpp / llama.cpp) parses the GGUF with a **native parser** (in an isolated worker process — see "Loader isolation" below), so FireAlive runs a layered gate over every model file before the loader reads it — on both the server and the Analyst Client. The layers run in order and short-circuit on the first failure:

1. **Hash-pin (primary).** Each file's SHA-256 is checked against the source-pinned value. A missing or mismatched file blocks the load.
2. **Signature / provenance (optional, server).** If the operator configures a model-signing public key (`MODEL_SIGNING_PUBLIC_KEY` or `MODEL_SIGNING_PUBLIC_KEY_FILE`), a detached signature over the pinned digest is verified; a present-but-invalid signature blocks even when signing isn't required. With no key configured this layer is skipped and never weakens the hash-pin.
3. **GGUF format validation.** The header is sanity-checked (magic, version, tensor/metadata counts within plausible bounds, and a bounded key/value walk) before the native parser sees it, to defang a malformed-file parser exploit — the highest-value layer given the in-process loader. A malformed header blocks the load.
4. **Malware scan (defense-in-depth).** The file is scanned **by path** using the host's own local engine (clamdscan → clamscan → Microsoft Defender on Windows); nothing is uploaded anywhere. A detected threat, a scan error, **or no available scanner** all block the load (fail-closed).

The model loads only if every file clears every applicable layer. The gate runs once per file-set change (cached by content) rather than on every load. Server-side, each file's per-layer verdict is recorded to an append-only `model_file_scan_log` for audit; the Analyst Client runs the same hash → format → malware gate **entirely on-device** and shows the verdict in the KB Assistant panel. Any block surfaces as an honest "unavailable" naming the failing layer — never a silent fallback.

**Why a scanner is required, stated honestly:** a backdoored-but-well-formed weights file is *not* something any of these layers can detect — hash-pinning to a vetted source is the real defense there. The malware scan catches a *swapped* file (known-malicious content), the format validator catches a *malformed* file (parser exploit), and the hash-pin catches *any* deviation from the vetted artifact. The gate is layered precisely because no single layer is sufficient on its own.

**Loader isolation & privilege hardening:** the model loader (node-llama-cpp) parses the GGUF and runs inference in a **separate, isolated process** — a forked child on the server, an Electron utilityProcess on the Analyst Client — not in the main process. A loader or parser exploit is therefore contained in a disposable worker that the host respawns, rather than running with the main process's reach; the gate above remains the primary control and this isolation is defence-in-depth for the residual risk. The server additionally refuses to load a model as **root** in production (set `FIREALIVE_ALLOW_ROOT_MODEL_LOAD=1` only if a constrained environment genuinely requires it), and per-request timeouts plus a restart circuit keep a wedged or crash-looping worker from degrading the service. Recommended deployment confinement — non-root user, read-only model mount, dropped Linux capabilities, a seccomp/AppArmor profile, resource limits, and no network egress from the inference service — is documented in `docs/model-loader-isolation.md`; running the worker under a separate lower-privileged identity (a sidecar container, or an in-process privilege drop) is the remaining hardening step.

- **Chat model** (heavyweight; powers the server-side lead chat, burnout messages, IR simulator, and troubleshooter, and the Analyst Client's on-device chat): **Qwen2.5-14B-Instruct, q4_K_M** (Apache-2.0), 3 official split shards, loaded from shard 1.
  - Official source: Hugging Face `Qwen/Qwen2.5-14B-Instruct-GGUF` (pinned commit `2b6a96d780143b4e8e3b970394e39e3774551f29`) or Alibaba ModelScope (`Qwen/Qwen2.5-14B-Instruct-GGUF`, first-party).
  - Pinned SHA-256:
    - `qwen2.5-14b-instruct-q4_k_m-00001-of-00003.gguf` (3.99 GB) — `a09ea5e7b1eafb1b30b241726c3cc3c905c96f14ad41e246ffa5f44e53904f68`
    - `qwen2.5-14b-instruct-q4_k_m-00002-of-00003.gguf` (3.99 GB) — `21b9457d079680d284e90ef69607c4b2d8ef64a09d4729cb7b5e1357bdba41ae`
    - `qwen2.5-14b-instruct-q4_k_m-00003-of-00003.gguf` (1.01 GB) — `c8d37006760a387a35216e070e6664d7da927f10be8eb870fef2e3d4833d9976`
  - Endpoint floor: ~9 GB free disk + ~10–12 GB RAM. Under-spec / thin-VDI endpoints honestly report the local chat as unavailable rather than degrading silently.
- **Embedder** (KB retrieval, server-side and on-device): **Qwen3-Embedding-0.6B, Q8_0** (Apache-2.0, 1024-dim), single file.
  - Official source: Hugging Face `Qwen/Qwen3-Embedding-0.6B-GGUF` (pinned commit `d20cf9c`) or Alibaba ModelScope.
  - Pinned SHA-256: `Qwen3-Embedding-0.6B-Q8_0.gguf` (639 MB) — `06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439`
  - Endpoint floor: ~640 MB free disk.

Target directory: the server model root (default `~/.firealive/models`, override `FIREALIVE_MODEL_PATH`) and, on the Analyst Client, the AC model root (default `~/.firealive/ac-models`, override `FIREALIVE_AC_MODEL_PATH`). Both the MC **AI/ML** tab and the AC **KB Assistant** surface a "Show provisioning guide" / "Verify provisioned files" action that displays the official source, target directory, and these pinned hashes, and verifies on demand.

**Other deployment hardening:**
- **Self-hosted fonts.** The Content-Security-Policy allows styles and fonts from `'self'` only (no `fonts.googleapis.com` / `fonts.gstatic.com`). Self-host any web fonts you want to use; otherwise the platform falls back to the system font stack.
- **Pinned CI/CD supply-chain tools.** Generated pipelines pin Syft v1.44.0, Grype v0.110.0 (CVE scan), and Cosign v3.0.6, installed from immutable release tags — no `main` / `@master` / `:latest`. See the CI/CD section.

---

## Security group

### IAM
**What it's for:** Connect FireAlive to the org's identity provider (Okta, Azure AD, PingOne, OneLogin) so analysts authenticate with their corporate credentials. SSO via SAML or OIDC, with LDAP/AD as fallback. When IAM is integrated, MFA enforcement happens at the IdP — FireAlive trusts what the IdP says.

**Workflow:**
1. Lead opens IAM tab on initial setup
2. Picks IdP type, enters config (Entity ID, IdP metadata URL, etc.)
3. Tests connection
4. Once configured: analysts log in via SSO, no separate FireAlive password needed

### MFA (built-in, for non-IAM deployments)
**What it's for:** TOTP/WebAuthn MFA wizard for deployments that don't have enterprise IAM. Walks through QR code setup. Skipped if the IdP already enforces MFA.

**Workflow:**
1. Lead opens MFA tab
2. Picks method (TOTP via authenticator app, WebAuthn for hardware keys)
3. Scans QR or registers WebAuthn token
4. Configures grace logins (how many can happen before enforcement) and remember-device duration

### API Keys
**What it's for:** Programmatic access to FireAlive for SOAR/SIEM integrations. Each key is role-scoped — least privilege. A key for "team health metrics streaming to SIEM" doesn't get access to anything else.

**Workflow:**
1. Lead opens API Keys
2. Clicks "+ New Key"
3. Names it ("splunk-cef-stream"), picks scope ("read team health"), sets expiry
4. Receives the key, copies it into the SOAR/SIEM config
5. Periodically reviews key usage (last used timestamps), revokes any that are unused or compromised

### Access Control
**What it's for:** Align FireAlive with the org's overall access control model — RBAC (Role-Based), MAC (Mandatory), DAC (Discretionary), ABAC (Attribute-Based). Different access models change how FireAlive should behave internally for things like permission inheritance, role-to-action mapping, attribute evaluation, and policy enforcement order. The lead picks the model their org uses; FireAlive adapts its internal enforcement to fit.

This feature also handles concurrent session limits, session timeouts, and per-action MFA requirements.

**Workflow:**
1. Lead opens Access Control during setup
2. Picks the org's access control model (RBAC / MAC / DAC / ABAC)
3. Sets max concurrent sessions per user, session timeout
4. Picks any access pattern presets (e.g. "Zero-Trust Strict", "Standard Enterprise", "Pilot Phase Permissive")
5. FireAlive's internal session enforcement and authorization logic adjusts to match the chosen model

### Auth Logs
**What it's for:** Track every authentication attempt — successful and failed — for both MC and AC. Useful for detecting brute-force, credential stuffing, or unauthorized access attempts. When IAM is integrated, this supplements (doesn't replace) the IdP's auth logs.

**Workflow:**
1. Lead opens Auth Logs to investigate a suspicious activity report
2. Filters by user, IP, time range
3. Sees pattern (e.g. 50 failed logins from one IP in 2 minutes)
4. Lead configures brute-force threshold for automatic detection
5. Future attempts crossing threshold trigger automatic lockout + alert

### KMS (Enterprise Key Management)
**What it's for:** Centralize FireAlive's encryption key lifecycle in the org's enterprise KMS — AWS KMS, Azure Key Vault, HashiCorp Vault, Thales, Entrust. All encryption tiers (Tier-3 analyst data, Tier-1 team data, peer chat E2EE, backups, audit log signing) get their keys managed through KMS with HSM backing and automated rotation.

**Workflow:**
1. Lead opens KMS tab on initial setup or when migrating from default keys
2. Picks KMS provider, enters endpoint/ARN, key ID/alias
3. Configures rotation policy
4. FireAlive switches from default-key mode to KMS-backed mode
5. From now on, every encryption operation uses keys from KMS

### WiFi Policy
**What it's for:** Enforce minimum WiFi security on analyst clients. WPA2-Personal (PSK) is vulnerable to brute force; WPA2-Enterprise with 802.1X/EAP is the SOC minimum. The AC checks the local WiFi before connecting and blocks if non-compliant.

**Workflow:**
1. Lead opens WiFi Policy
2. Sets minimum protocol (WPA2-Enterprise default, WPA3-Enterprise stricter)
3. AC enforcement: when an analyst's machine joins a non-compliant WiFi (e.g. coffee shop with WPA2-Personal), the AC won't connect to the FireAlive server until they switch to a compliant network

### Posture Assessment
**What it's for:** Like 802.1X NAC and MDM posture checks: at app startup the AC verifies the workstation meets minimum security posture (TLS version, OS patch level, EDR running, etc.) before connecting to the management console. Non-compliant devices are warned or blocked until remediated.

**Workflow:**
1. Lead opens Posture Assessment, configures checks
2. Sets minimum TLS version, grace period before blocking
3. AC enforcement: on every connection (or first launch only), runs posture check, reports compliance to MC, blocks if failed

### Tripwire
**What it's for:** Detection for a specific attack pattern: if a large percentage of analysts simultaneously enter "reduced routing" status, it could indicate compromised analyst clients are coordinately requesting load reduction to degrade SOC response capacity. The tripwire auto-disables burnout routing and alerts the lead to investigate.

**Workflow:**
1. Lead configures threshold (e.g. "if >40% of analysts go into reduced routing within 5 minutes")
2. Normal operation: occasional analyst goes reduced — no alarm
3. Attack scenario: 5+ analysts request reduction in quick succession — tripwire fires
4. Burnout routing auto-disables, lead gets urgent notification, lead investigates

### Compromise Scan
**What it's for:** Orchestrate compromise tests across analyst clients. Each AC runs 10-point self-diagnostics (binary integrity, memory analysis, network connections, configuration drift, audit log continuity, TLS pinning, API tokens, filesystem integrity, EDR status, encryption keys) and returns a signed report. Lead uses this after a tripwire event or any time client compromise is suspected.

**Workflow:**
1. Lead opens Compromise Scan
2. Either picks a single client or "Scan All Clients"
3. ACs run their 10-point checks (takes a couple minutes)
4. Results come back with pseudonyms — lead sees per-client pass/fail breakdown
5. Failed checks → lead investigates that client, may rotate its pseudonym, reprovision, or escalate

### Log Integrity
**What it's for:** Audit logs are append-only with SHA-256 hash chain. The application prevents deletion. This tab monitors the chain for missing logs (gaps suggest tampering or partition events) and triggers SOAR alerts on detection.

**Workflow:**
1. Lead glances at this tab — green status = chain intact
2. If a gap is detected: SOAR fires, lead clicks in to see the gap range
3. Lead investigates whether it's a partition (system was offline) or tampering (someone tried to delete entries)

### Regression Test
**What it's for:** Run an automated test suite verifying every integration and control still functions after an update. Before deploying a new FireAlive version, the lead runs regression to catch broken integrations, missing connections, or deprecated features.

**Workflow:**
1. After applying an update or making major config changes
2. Lead opens Regression Test, clicks Run
3. Server runs the canonical regression-runner via `POST /api/regression/run` (admin-gated; replaces an earlier setTimeout-based client-side fake). The MC suite is 57 checks across 12 categories on a freshly bootstrapped install (rising by one per probed integration once integration-health probing has run): schema + foreign-key integrity, an in-memory schema-clone harness, auth-flow round-trips (bcrypt + JWT + TOTP), AES-256-GCM / SHA-256 / Ed25519 / NaCl-box crypto round-trips, peer skill-share E2E envelope round-trip, GD-push Ed25519 signing + fingerprint, KMS / key-wrapping round-trips, helper-pay points-ledger invariant, routing, burnout-signal plumbing, backups v2-aware schema, anti-rollback fuse counter, the cloud / cicd / full-suite signing infrastructure, AI-dispatcher graceful-fail (IR-simulator wiring), model-file-safety fail-closed, external-integration reachability, and integration health.
4. **Zero production side effects (by design).** Verifiable controls are read-only on the live database; write-path "flow" checks run against an in-memory SQLite clone of the live schema; crypto and E2E checks use throwaway keys held only in memory; the AI and scanner checks exercise plumbing and fail-closed behavior only (no real inference or scan).
5. **Three statuses — pass / fail / skip.** A skip never counts as a failure. Two checks are forward-dependent: they skip until the phase that backs them ships, then auto-activate. The `audit_log` hash-chain linkage check skips until the hash columns land (B5a — Audit Hash Chain); the IAM offboarding-detector check skips until the scheduled IdP detector populates `last_iam_check` (B5b — IAM Real IdP Integration). The columns and wiring they assert are verified now even while the deeper assertion is deferred. The `integrations` category applies the same trichotomy to optional external integrations — SOAR, SIEM, ticketing, LDAP/AD, and backup storage each pass when configured and reachable, fail when configured but broken, and skip when not configured — while EDR / malware-scanner coverage is treated as required and fails when absent. The `integration_health` category reflects the most recent cached integration-health probe without running any live probe: a healthy probe passes, a benign state (disabled / not configured / not implemented) skips, and a real probe failure (unreachable / auth failed / permission denied / timeout / error) fails; with no cached probe it records a single skip.
6. The Global Dashboard runs its own CISO-gated suite (32 checks across 8 categories) via `POST /api/regression-test`, covering GD schema + FK integrity, AES-256-GCM / SHA-256 / Ed25519 crypto round-trips, auth-flow round-trip (bcrypt + JWT), MC-trust signing-key coverage, cross-region rollup, compliance tables, backups, the same forward-aware audit-chain check, and forward-aware integrations + integration-health checks. The GD’s SOAR / SIEM and required-EDR integration checks are deliberately forward-aware: they skip until the GD grows its own runtime-monitoring and integration surface — a separately scoped future phase (see `docs/runtime-monitoring-and-system-health.md`) — and then activate. The AI, model-safety, peer, helper-pay, and IAM checks are intentionally not ported — those subsystems do not run on the GD.
7. Pass / fail / skip report — the lead investigates failures. Each run writes a `REGRESSION_RUN` entry to `audit_log` (with pass / fail / skip counts); a runner-level error is recorded as `REGRESSION_RUN_FAILED` for post-hoc analysis.

### TTX Generator
**What it's for:** Generate Tabletop Exercise (TTX) documents — a Situation Manual (SitMan) for the facilitator to bring to a tabletop meeting, plus a blank After-Action Report (AAR) template for the team to fill in afterwards. Curated scenario library (ransomware, data exfiltration, credential compromise via vishing, cloud account compromise) at three difficulty levels. Output formats: PDF (printable, archival) and DOCX (editable). Each generation is logged as compliance evidence.

**Workflow:**
1. Lead schedules a tabletop exercise
2. Opens TTX Generator, picks scenario, difficulty (easy/intermediate/hard), format (PDF/DOCX)
3. Downloads SitMan — brings to the tabletop meeting
4. Downloads AAR template — for the team to fill in afterwards
5. After the tabletop: completed AAR goes in the team fileshare; the audit log entry from generation proves to auditors that the exercise was conducted

---

## Infrastructure group

### Cloud & IaC
**What it's for:** Generate Infrastructure-as-Code artifacts to deploy FireAlive on the org's cloud platform. Supports AWS, Azure, GCP, and **privacy-first European/Swiss providers** (Hetzner Cloud, OVHcloud, Exoscale) for orgs that need data sovereignty (no US CLOUD Act jurisdiction). Outputs span 9 IaC formats (Terraform, Pulumi, CloudFormation, Bicep on Azure, gcp-dm on GCP, docker-compose, docker-manifest, Kubernetes, Helm) across the 6 providers — 39 valid (provider, format) combinations. Bundles are server-rendered, signed with Sigstore Cosign, SBOM-attested via Syft (SPDX-JSON), and persisted in the `cloud_packages` table. A Syft-or-503 / Cosign-or-503 policy means missing tooling fails generation rather than producing an unsigned or unattested bundle. Offline verification uses standard `cosign verify-blob` against the bundle's public key. See `docs/cloud-iac-generation.md` for the signing pipeline, signing-key rotation procedure, and threat model.

**Workflow:**
1. Lead picks target cloud provider, IaC tool, secrets manager
2. Clicks Generate
3. Receives a downloadable bundle with: deployable IaC files, secrets-management mapping (env vars → KMS paths), README with deployment steps
4. Hands the bundle to platform engineering for deployment

### Virtualization
**What it's for:** Hypervisor / container orchestration integration (VMware vSphere, Hyper-V, Docker, Kubernetes) for orgs that deploy FireAlive in their existing virtual infrastructure. Configures resource pool, datastore, host placement.

**Workflow:**
1. Lead picks deployment target type
2. Enters API endpoint for hypervisor or K8s control plane
3. FireAlive deploys into the configured virtualization infrastructure with the right resource constraints

### SDN
**What it's for:** Configure FireAlive for distributed SOC environments where analysts, automation, and SIEM infrastructure span multiple sites connected via SD-WAN or SDN fabrics. Tells FireAlive which CIDRs are which sites so routing and access controls are network-aware.

**Workflow:**
1. Lead picks SDN platform (Cisco ACI, VMware NSX, etc.)
2. Configures controller endpoint, primary/secondary site CIDRs, SD-WAN overlay
3. FireAlive's network awareness adjusts to the SDN topology

### SASE / ZTNA
**What it's for:** Integrate FireAlive into the org's SASE platform. FireAlive can operate as a SECaaS offering or connect through ZTNA, CASB, SWG components.

**Workflow:**
1. Lead picks SASE provider (Zscaler, Palo Alto Prisma, Netskope, Cato)
2. Configures ZTNA endpoint, FWaaS policy, optional CASB
3. FireAlive's network access adjusts to SASE policy enforcement

### High Availability
**What it's for:** HA configuration with two supported topologies: active/passive (one server handles all traffic with a passive standby continuously replicating; failover happens when active fails health checks) and active/active (both servers handle traffic simultaneously, sharing session state). Synchronous replication keeps data consistent. The MC is decoupled from the backend — it talks to whichever server is currently reachable behind the load balancer, so failover is transparent to the lead.

For larger deployments needing more than two servers, use the Cluster / Scaling feature instead.

**Workflow:**
1. Lead opens HA Configuration
2. Picks mode (active/passive or active/active)
3. Configures secondary server endpoint, replication interval, health check interval/path
4. For active/active: configures shared session store (Redis required)
5. Once configured: replication is continuous
6. If active fails (active/passive): passive promotes within seconds, MC reconnects automatically, lead is notified — but the SOC keeps operating

### Cluster / Scaling
**What it's for:** For large deployments (hundreds or thousands of analysts), deploy FireAlive as a multi-node active-active cluster. Distributes load, supports horizontal scaling, supports segmenting different team-lead views.

**Workflow:**
1. Lead opens Cluster tab
2. Picks cluster mode (active-active multi-node)
3. Sets node count, session store (Redis required for active-active), worker threads per node
4. Cluster comes online, load balancer distributes incoming connections

### CI/CD
**What it's for:** Generate CI/CD pipeline configurations so orgs can build their own customized FireAlive distributions. Because FireAlive is open-source, orgs are free to fork, modify, and run their own custom versions tailored to their specific SDN setup, automation stack, integrations, etc. The CI/CD generator is the bridge: instead of starting from a generic upstream release and re-applying every customization, the org uses this feature to output a pipeline config that captures their CURRENT production configuration as the baseline. They can then build whatever new tools or modifications they want on top of that already-configured baseline.

It also serves a second purpose: contributing back upstream. Orgs that find security holes, build useful new features, or improve existing ones can use the same CI/CD feature to push their commits back to the public FireAlive GitHub repo. That accelerates collaborative development of the platform — better features, better security, broader applicability — and increases the platform's collective effectiveness in the war against analyst burnout and malicious attackers.

Supports GitHub Actions, GitLab CI, Jenkins, CircleCI. Pipelines embed (MC-side, 11 stages): lint -> test -> regression test (curl POST to `/api/regression/run` against the originating MC) -> npm audit -> Snyk -> SBOM (Syft -> SPDX-JSON artifact) -> dep-pin verify -> docker buildx with SLSA L3 provenance -> Cosign signing (keyless OIDC default; key-based via `COSIGN_KEY_MODE=key-based`) -> Grype CVE scan (`--fail-on high`) -> fuse-counter monotonicity check against `origin/main`. GD-side pipelines (10 stages) omit the inline regression invocation because GD's regression runner is inline in `index.js` rather than `require()`-able. Pipelines can POST run status back via webhook (`POST /api/cicd/runs`); MC uses api-key + `cicd:webhook` scope, GD uses an `X-CICD-Webhook-Secret` shared-secret header. Supply-chain tools are pinned to specific versions installed from immutable release tags — Syft v1.44.0, Grype v0.110.0, and Cosign v3.0.6 (no `main` / `@master` / `:latest`). See `docs/cicd-generation.md` for full architecture and the auth-divergence rationale.

**Workflow (custom org build):**
1. Org's developers want to extend FireAlive with org-specific tooling
2. Lead opens CI/CD tab in MC
3. Picks CI platform
4. Clicks Generate — output is a pipeline config that reflects the current production configuration (integrations, automations, custom settings already configured in this org's MC)
5. Org's developers commit the pipeline config to their internal repo
6. They build their additional tooling on top of the configured baseline rather than from a generic upstream release
7. CI runs automatically on every push, deploys to the org's lab/production environments

**Workflow (upstream contribution):**
1. Org developer finds a bug or builds a useful feature
2. Same CI/CD generator outputs a pipeline that targets the public FireAlive GitHub repo
3. Developer pushes commits through that pipeline back to the upstream project
4. Upstream maintainers review and integrate

---

## Data & Backup group

### Backup
**What it's for:** Encrypted backups (AES-256-GCM) with per-data-type destination routing. The lead can route backups to one location, audit logs to another, forensic exports to a third — different retention and access requirements for each.

**Workflow:**
1. Lead opens Backup tab
2. For each data type (database, audit logs, forensic exports): configures destination, retention, schedule
3. Backups run on schedule, encrypted, hashed for integrity
4. Lead can trigger manual backups or restore from any backup

**Full-suite backup.** A separate `POST /api/backup/full-suite` endpoint captures the entire instance — database, configuration rows, signing-key material, and a version manifest — into one tar.gz archive. The Backup tab's **Trigger Full Backup Now** button calls this endpoint; the resulting archive is suitable for disaster-recovery restoration of the full instance (vs. the standard `POST /api/backup` which captures only the database). MC-side bundles use the v2 four-file layout (manifest + archive + Cosign signature + KEK-wrapped key); GD-side bundles use a v1-shape single-archive layout with SHA-256 tamper-detect. See `docs/full-suite-backup.md` for the full architecture, manifest schemas, and restoration semantics.

### Backup Schedules
**What it's for:** Configure multiple backup schedules with optional regulatory-framework presets. Each schedule fires independently on its own cadence (hourly / daily / weekly / monthly) at a configured time, to a configured destination, with a configured retention. Picking a regulatory preset (HIPAA, SOX, PCI-DSS, GDPR, NIST CSF, ISO 27001, SOC 2) applies that framework's compliance floor — minimum retention and required encryption — to the schedule. The operator can set retention HIGHER than the floor (legal-hold scenarios, longer compliance windows) but cannot reduce below the floor. Schedules without a preset have full operator flexibility.

**Floor-enforcement model:** Hybrid floor + upward flexibility. When a preset is selected, the API rejects retention below the framework minimum (e.g. HIPAA = 6 years / 2190 days) and rejects unencrypted schedules when the framework requires AES-256. Recommended frequency and destination class are pre-filled from the preset but not enforced — operators can pick hourly instead of the recommended daily if their risk profile demands it. The "None" preset (the default) skips floor enforcement entirely. SOC-grade compliance posture requires the floor to have teeth (auditor asks "what is your retention?" not "what preset did you pick?"), but operator legitimate use cases require upward flexibility.

**Framework citations** displayed in the preset metadata for operator transparency:
- HIPAA — 45 CFR 164.316(b)(2)(i) — 6-year PHI retention (2190 days)
- SOX — 17 CFR 210.2-06 / 18 USC 1520 — 7-year auditor record retention (2555 days)
- PCI-DSS — PCI DSS v4.0 Requirement 10.7.1 — 1-year audit log retention (365 days)
- GDPR — Articles 5(1)(e), 25, 32, Chapter V — 30-day operational floor; storage-limitation upper bound is operator-managed
- NIST CSF — NIST CSF 2.0 PR.DS-11 — flexible per policy (1-year default)
- ISO 27001 — ISO/IEC 27001:2022 Annex A.8.13 — flexible per policy (1-year default)
- SOC 2 — TSC CC9.1 / CC6.1 — flexible per policy (1-year default)

**Workflow:**
1. Lead opens Backup Schedules from the Data & Backup nav category
2. Reviews existing schedules in the Active Schedules list: name, type, frequency, time, destination, retention, encryption status, preset tag, next run time, last run time + status, last error if any
3. Removes any schedules they no longer want (60-second scheduler poll picks up the deletion and tears down the cron within a minute)
4. Adds a new schedule via the Add Schedule form: name, type (full / incremental / differential / snapshot), frequency (hourly / daily / weekly / monthly), time (HH:MM), day-of-week or day-of-month for weekly / monthly schedules, destination, retention in days
5. Optionally picks a regulatory preset — auto-fills retention to the framework floor, locks encryption on (when AES-256 is required), pre-fills frequency and destination with the framework recommendation. The operator can edit retention upward but not below the floor; below-floor entries get a server-side 400 RETENTION_BELOW_FLOOR with an inline error
6. If the schedule's fire times overlap within 5 minutes of another schedule's fire times, the server returns 409 SCHEDULE_OVERLAP and the UI surfaces a confirm-to-queue modal showing the conflicting schedule names + fire times — the operator confirms (commits with force_queue=true, audit-log records BACKUP_SCHEDULE_OVERLAP_QUEUED) or cancels and adjusts the time
7. Schedule lands in backup_schedules table; scheduler picks it up within 60 seconds via the reload poll and registers a cron for it; fires at the configured time, executes the backup via the existing performBackup pipeline, records last_status / last_run / last_error on the schedule row

**Multi-schedule semantics:** Each schedule fires independently. The scheduler maintains a separate cron registration per active schedule. When two schedules' fire times collide (within ±5 minutes), the overlap detection surfaces a 409 at create / update time so operators can adjust timing. Operators who explicitly want overlapping schedules (e.g. daily + monthly on the same day-of-month) can confirm-to-queue via the modal. The 5-minute window protects against I/O contention on the source DB and the destination — backup operations have variable execution duration and starting two backups at the same moment risks read locking and destination push throttling.

**Legacy compatibility:** Legacy single-schedule installs that configured a single backup schedule via /api/backup/config (the singleton-only legacy endpoint) get their singleton automatically migrated to a "Legacy default" row in backup_schedules on first boot post-upgrade. The /api/backup/config endpoint stays live as a deprecated read/write shim over the first row of backup_schedules for one version of deprecation grace — external tooling that still calls it sees a deprecated:true response with a replacement: '/api/backup-schedules' hint. Operators should migrate clients to the modern endpoint when convenient. The v100 stub route POST /api/v1/backup/schedule/add also remains live and now delegates to the canonical service via BackupService.addSchedule (preserves the v100 public contract).

**MC orchestrating AC backups** is a separate concern from this feature and out of scope for the current release. The "Backup All Clients" button on the Client Provisioning tab remains a placeholder pending a future phase that builds AC-side backup orchestration.

### Incremental and differential backups
**What they're for:** Two strategies for capturing the database between full backups, each making a different tradeoff between archive size and restore complexity. Both are point-in-time captures of the SQLite WAL frames written since a reference backup. Both use the same v2 four-file on-disk layout (manifest.json + manifest.sig + archive.bin + wrapped-key.bin) and the same encryption + signing pipeline as full backups; only the archive payload format and the parent linkage differ.

**Strategy comparison:**

| Strategy | Captures | Parent | Restore needs | Archive size over time |
|----------|----------|--------|---------------|------------------------|
| Full | Entire DB | none | [this backup] | constant per cycle |
| Snapshot | Entire DB (point-in-time) | none | [this backup] | constant per cycle |
| Incremental | WAL frames since immediate predecessor | most recent backup of any kind | [anchor full + ALL intermediate incrementals + this] | small per archive |
| Differential | WAL frames since anchor full | anchor full backup | [anchor full + this] | grows each cycle |

**When to use which:**
- **Full:** Baseline. Always available as the anchor.
- **Snapshot:** Point-in-time capture you might want to restore to later. Not part of any chain.
- **Incremental:** Small archives, frequent runs. Best when storage cost is critical and operators are comfortable maintaining longer chains. Restore complexity grows linearly with chain length.
- **Differential:** Larger archives, simpler restore. Best when restore-time predictability matters more than storage cost. Each differential is independently restorable alongside the anchor.

**Schema:**
- `backup_schedules.backup_kind` — `single-db` or `full-suite`
- `backup_schedules.backup_strategy` — `full` / `incremental` / `differential` / `snapshot`
- `backup_schedules.destination_filter` — JSON array of required destination tags (or NULL for all)
- `backup_schedules.max_chain_depth` — INTEGER, per-schedule override (NULL = use global)
- `backups.backup_strategy` — same enum, per-backup row
- `backups.parent_backup_id` — immediate predecessor in chain
- `backups.parent_full_backup_id` — anchor full backup (O(1) shortcut for chain walks)
- `backups.wal_start_position` / `wal_end_position` — TEXT "byteOffset:frameNo" position descriptors
- `backups.page_count` — frame count archived
- `system_meta.max_chain_depth` — global default depth limit (seeded to '100')

**Dispatch:** The scheduler dispatches on `(backup_kind, backup_strategy)`:
- `(full-suite, full)` → `performFullSuiteBackup`
- `(single-db, full)` → `performBackup` (existing)
- `(any, incremental)` → `performIncrementalBackup`
- `(any, differential)` → `performDifferentialBackup`
- `(any, snapshot)` → `performBackup` with type='snapshot'

**INCR-v1 archive payload format:** Incremental and differential archives wrap the WAL frames in a custom binary format inside the standard v2 archive.bin (which is still zstd-compressed and AES-256-GCM-encrypted). Header (16 bytes): magic 'INCR' + format_version + frame_count + page_size. Per frame (44 + page_size bytes): frame_no + page_no + db_size_after_commit + sha256_of_page_data (raw 32 bytes) + page_data. The per-page SHA-256 lets restore verify each page's integrity before applying.

**Six escalation reasons:** Both `performIncrementalBackup` and `performDifferentialBackup` can escalate to a full backup when their conditions aren't met. The caller (scheduler, `POST /api/backup?strategy=...`) sees `escalated: true` and the reason string in the response:
- `no-parent` — no eligible parent backup exists
- `incompatible-parent` — parent has no wal_end_position (legacy backup without chain support, or full-suite)
- `no-wal-file` — DB has no WAL file on disk (journal_mode != WAL)
- `no-anchor` — can't resolve parent_full_backup_id from chain walk
- `salt-change` — WAL was checkpointed since parent was taken (re-salted)
- `depth-limit` — chain length would exceed configured maximum

Escalated backups become the new anchor for future incrementals/differentials. The audit log records both the requested strategy and the actual strategy produced.

**Restore chain:** Chain restore is mechanically different from single-backup restore:
- `walkChain(db, leafBackupId)` — assembles `[anchor, ...intermediates, leaf]` by walking parent_backup_id backwards. Cycle detection. Hard cap at MAX_CHAIN_DEPTH=1000.
- `validateChain(db, chain)` — for every link: manifest sha256 match, Ed25519 signature verify, archive sha256 match, wrapped-key sha256 match. For inc/diff links additionally: unwrap key, decrypt+decompress, parse INCR-v1 bundle, re-compute per-page sha256, cross-check against manifest's frames descriptor.
- `replayChain(db, chain, targetDbPath, options)` — extracts anchor full to targetDbPath, then for each subsequent link applies INCR-v1 frames at offset (page_no - 1) × page_size. Truncates target on commit frames (dbSizeAfterCommit nonzero).

**Endpoints:**
- `GET /api/backup/:id/chain` (C68) — read-only chain preview. Returns the ordered chain, per-link file existence, total page count, restorable flag. No locks, no audit, no validation overhead. Used by the frontend chain panel and restore-preview modal.
- `POST /api/restore/execute-chain/:id` (C66) — restore from a chain. Goes through the same approval gate, IP allowlist, and audit log machinery as `/execute/:id`. Confirms against the LEAF backup's hash (not anchor). Creates a pre-restore snapshot with prefix `pre-restore-chain-<ts>.db` before destructive work.
- `POST /api/backup?strategy=<full|incremental|differential|snapshot>` (C67) — on-demand backup with strategy selection. Mirrors the scheduler's dispatch table.

**Depth limits:** Long chains have linearly-growing restore cost and linearly-growing single-point-of-failure exposure. The configurable max-chain-depth limit forces a full backup once the chain would exceed it. Two sources of truth:
1. `backup_schedules.max_chain_depth` — per-schedule override (NULL = use global)
2. `system_meta.max_chain_depth` — global default ('100')

The C65 hard cap `MAX_CHAIN_DEPTH=1000` in restore-chain.js is a runaway-walk safety; the configurable limit sits well below it (defaulting to 100). Operators with stricter SLAs can lower; those with tight storage budgets can raise (at their own risk). Differentials are NOT subject to the depth limit since each is independently restorable.

**Workflow (operator perspective):**
1. In Backup Schedules, create a schedule with `backup_strategy=incremental` (or differential)
2. The scheduler creates a full backup on the first run (escalation: `no-parent`)
3. Subsequent runs produce incremental archives chained to the anchor (each adding ~M of WAL frames)
4. After ~100 incrementals (default), the next run escalates to a new full backup (escalation: `depth-limit`)
5. The chain restarts under the new anchor
6. Restore via the Backup History panel → Restore button. The modal shows chain shape + per-link integrity before the operator confirms.

**Operator decision matrix:**

| Need | Recommended strategy |
|------|----------------------|
| Predictable hourly snapshots of compliance-relevant tables | snapshot |
| Cheap nightly captures, occasional restore (developer reset) | incremental + small depth limit |
| Cheap nightly captures, frequent restore (test env reset) | differential |
| Long-retention frozen archives (no restore expected) | full + retention policy |
| Just-in-case before a risky change | snapshot |

### Restore
**What it's for:** Restore from backup or revert configuration. Two modes: internal (revert to a recent FireAlive backup of this same install) and external (restore from a backup stored on a network share, NAS, S3, Azure, SFTP).

The internal mode is for routine reverts — someone messed up the configuration, or some data became noticeably corrupted, and the lead wants to roll back without tearing down the whole install.

The external mode is for compromise recovery. If an AC, MC, or GD has been compromised, the safest workflow is: tear down the compromised app instance entirely, install a fresh clean copy, then use the external Restore feature on that fresh copy to pull configurations, integrations, and data back from a known-good external backup. This avoids re-introducing the compromise that might still be lurking in the original install's filesystem or local backups.

**Workflow (internal — routine revert):**
1. Lead notices configuration mistake or data corruption
2. Opens Restore tab → Internal
3. Picks the restore point from the list of recent internal backups
4. Confirms restore
5. System restores in place

**Workflow (external — compromise recovery):**
1. Compromise detected (via Compromise Scan, threat hunting, etc.)
2. Lead tears down the compromised app instance — uninstall, wipe filesystem, validate clean state of host
3. Install a fresh copy of FireAlive from verified source
4. Open Restore tab → External
5. Configure source: type (network share / NAS / S3 / Azure / SFTP), path, decryption key
6. Verifies integrity of the external backup, executes restore
7. System rebuilds from the trusted external backup with original configurations, integrations, and data

### Data Sovereignty / Geo-Fencing
**What it's for:** Multinational SOC support. Each analyst client gets a country tag and the regulatory framework that applies (GDPR, PIPEDA, LGPD, etc.). Enforces data residency, blocks logins from unexpected countries, applies the right framework to that client's data.

**Workflow:**
1. Lead opens Data Sovereignty
2. Per client: tags country, regulatory framework, data residency requirement
3. Toggles "block logins from countries not matching client's location"
4. From now on: a German-tagged client can't be logged into from China — IP-based block, lead notified

### Legal Hold
**What it's for:** Litigation-grade evidence preservation for e-discovery, regulatory inquiries, and internal investigations. Bundles selected platform data into one or more of eight e-discovery formats (EDRM XML, EML/mbox, PST-equivalent ZIP, Concordance DAT, Relativity load bundle, JSON tarball, PDF with Bates numbering, TIFF with Bates load file), signs the manifest with Ed25519 from a signing key set DISTINCT from the forensic-export keys, holds the archive indefinitely until a separate CISO issues a release with rationale. Triple-layer separate-actor enforcement at the route, orchestrator, and SQL CHECK constraint levels makes the release workflow structurally admissible in court.

**Distinct from forensic export:** forensic exports are operational (an admin generates an archive for an incident response and may delete it later). Legal holds preserve evidence indefinitely until a release authority decides the matter is closed. Three lifecycle differences: indefinite retention by default, NO deletion only release, separate-actor enforced at three layers (not two).

**Workflow — create a hold:**
1. Admin or CISO receives a litigation hold notice, regulatory inquiry, or internal-investigation request from counsel
2. Opens Legal Hold tab
3. Fills the Create form/modal:
   - **Case ID** (required) — references the litigation matter, regulatory case number, or internal investigation ID
   - **Rationale** (required, min 20 chars) — court order ref, regulatory request, investigation context
   - **Time window** (optional) — restricts evidence to a specific date range
   - **Custodian filter** (optional, API only currently) — restricts evidence to a specific user's activity (so a hold for "Jane Doe's actions Q3" doesn't sweep up other employees' audit records)
   - **Output formats** — pick 1+ of the 8 (defaults to edrm-xml + eml-mime, the two most universal). Each selected format produces one file inside the archive.
   - **Indefinite retention** (default checked) — uncheck only for time-bounded preservation orders
4. Submit. System fetches the data slices, runs each format serializer, signs the manifest, optionally co-signs with sigstore Cosign, writes the tar.gz archive, and appends HOLD_CREATED + HOLD_COMPLETED chain entries.
5. The hold appears in the Existing Legal Holds list with status='active'. The retention job will skip this hold forever (until released).

**Workflow — hand to counsel:**
1. From the holds list, click Download → tar.gz archive streams to the browser
2. Transfer the archive to opposing counsel or the receiving e-discovery vendor via the case-specific secure channel (encrypted SFTP, vendor upload portal — external to FireAlive)
3. Counsel extracts the outer tar.gz, finds manifest.json + manifest.sig + per-format files
4. Counsel verifies the Ed25519 manifest signature using the public key from /api/legal-hold-exports/chain
5. Counsel imports the per-format file into their review platform per the ESI compatibility matrix in docs/legal-hold-export.md (e.g., Relativity ingests the relativity.zip; Concordance ingests the concordance.dat; in-house Python pipelines ingest the json-tarball.tar.gz)
6. Each event in every format carries its canonical SHA-256, allowing per-event integrity verification end-to-end

**Workflow — release a hold (CISO only):**
1. When the matter closes (case resolved, regulatory inquiry closed, court order lifted), a CISO different from the original requester opens the Legal Hold tab
2. Clicks Release on the active hold
3. Confirms in the release modal with a rationale ≥ 20 chars
4. If the CISO IS the original requester, the release is rejected at THREE layers (route, orchestrator, schema CHECK) with HOLD_RELEASE_DENIED chain entry recording which layer caught the violation
5. On successful release, the hold transitions to status='released' with hold_released_at, hold_released_by_user_id, and hold_release_rationale stamped atomically. HOLD_RELEASED chain entry appended. The archive remains downloadable for post-litigation audit.

**Why three layers of separate-actor enforcement:**
- **Layer 1 (route handler):** cleanest UX — caught immediately with a precise error, no DB write attempted
- **Layer 2 (orchestrator):** defense-in-depth if a future route bypass exists; throws SeparateActorViolation
- **Layer 3 (SQL CHECK constraint):** structurally impossible to bypass — lives in the database file itself. Opposing counsel cannot argue "the application could have been compromised" because the constraint is in the schema.

All three must agree. The schema is the final backstop and the reason this workflow is admissible in court.

**Cryptographic isolation:** legal hold signing keys are DISTINCT from forensic-export signing keys on each server. Plus MC and GD each maintain their own Tier-1 KEK and their own legal hold signing keys. Four independent key sets across the platform (MC forensic, MC legal-hold, GD forensic, GD legal-hold), each rotatable independently. Compromise of any one key does not taint the others.

---

## Reports & Compliance group

### Report Engine
**What it's for:** Scheduled depersonalized team-level reports for management or compliance. NEVER includes individual analyst names — tier/shift aggregates only. AI analysis backed by the platform's research knowledge base, so reports cite peer-reviewed studies behind the recommendations. Output formats: PDF (printable, archival) and DOCX (editable), generated using the same document generator as the TTX feature. Every generated PDF/DOCX is signed with the instance’s Ed25519 report-signing key and stamped with a verification footer (instance label, generation time, signing-key fingerprint), so a recipient can confirm the report is a genuine, unaltered FireAlive artifact — in-app via the authenticated verify endpoint, or independently with OpenSSL and no FireAlive tooling (see `docs/report-verification.md`). KB citations are reproduced verbatim: the report shows exactly the peer-reviewed references behind each recommendation, never a paraphrase or a fabricated source.

**Workflow:**
1. Lead opens Report Engine
2. Configures: frequency, day, format (PDF/DOCX), email recipients
3. On schedule (or on-demand "Generate Report" click): system generates the report
4. Two delivery options:
   - Click Generate Report → system produces the PDF/DOCX and opens a download window
   - Or system emails the report to the configured recipients
5. Recipients see team trends, training needs, capacity issues — but never individual data

### Compliance
**What it's for:** Generate framework-specific compliance reports against the running system. Picks a framework (NIST CSF, ISO 27001, SOC 2, HIPAA, GDPR, DORA, CCPA, PIPEDA, LGPD, PDPA, APPI, POPIA, NIS2, CPS 234, Cyber Essentials, FISMA), system runs real checks against actual app state, produces an audit-ready report. The report is viewable in-app as JSON; **Download PDF** and **Download DOCX** produce a signed, watermarked document for the selected framework — the same verification model as the Report Engine (Ed25519 instance signature + verification footer, checkable in-app or offline per `docs/report-verification.md`) — suitable for handing directly to an auditor.

Each report has TWO halves per the Shared Responsibility model:
- **verifiedControls:** technical controls FireAlive observes by inspecting its own running state (status pass / warning / fail / error, with per-control detail, taxonomy mapping, and remediation guidance when not pass)
- **customerResponsibility:** organizational, procedural, physical, and contractual controls the operating organization must attest separately — listed explicitly so an auditor can match each entry to the organization's evidence binder

For HIPAA, the verified half covers 19 controls; the customer-responsibility half covers 42 (164.308 Administrative Safeguards, 164.310 Physical Safeguards, 164.400-414 Breach Notification). Ratio varies by framework.

**Workflow:**
1. Auditor announces audit
2. Lead picks the relevant framework
3. Clicks Generate Report
4. System runs the technical-control checks against actual app state — access control, encryption, audit trail, authentication, config management, IR infrastructure, data protection, network, backups, notifications, AI engine
5. Lead reviews both halves: verifiedControls (technical evidence) + customerResponsibility (operator TODO)
6. Lead pulls supporting documentation for the customer-responsibility items from the organization's evidence binder / GRC tool
7. Combined evidence package handed to auditor

See SETUP.md → "Shared Responsibility in Compliance Reports" for the longer operator framing.

### Recertification
**What it's for:** Periodic review of all accounts, integrations, assessments, and configurations. Quarterly recommended. Ensures stale accounts are removed, integrations are still current, settings still appropriate. Triggers a workflow rather than a one-time view.

**Workflow:**
1. Quarterly: system reminds the lead it's time for recertification
2. Lead opens Recertification, sees due items
3. Walks through each: account by account, integration by integration
4. Marks each as "still valid" or "needs review/removal"
5. System logs the recertification — proof to auditors that periodic review is happening

### Knowledge Base
**What it's for:** The research knowledge base behind FireAlive's burnout-prevention features. 50 peer-reviewed entries (R001–R042, N001–N020) cited throughout the platform — the AI burnout prediction engine, the lead-side intervention prompts, the analyst-side signal interpretations. Each entry is enriched: a plain-language finding, the FireAlive implication, a fuller summary, the full citation, and a copiable source (DOI or stable URL). Leads (and any auditor) can verify that FireAlive's recommendations come from real peer-reviewed science, not from a profit incentive to sell features that merely sound plausible.

The source on every entry is a **copy-to-clipboard** control, never a live link — neither the Management Console nor the Analyst Client opens an external browser on your behalf. You copy the DOI/URL and open it yourself.

The KB is curated. It is not open to anyone to update — that would be an attack vector for malicious actors to inject articles that accelerate burnout rather than prevent it. There's a button to add KB peer-reviewed burnout articles, but for now that's restricted to the upstream maintainer (Peter Mancina). The KB is updated on a quarterly or annual basis with the latest scientific research on burnout prevention, distributed via FireAlive version updates.

**Workflow:**
1. Lead clicks a citation in a prompt or report (e.g. on the Actions tab) — the KB opens to that entry
2. The entry shows the finding, summary, FireAlive implication, tags, full citation, and copiable source
3. Or browse the library by topic — in the Management Console KB tab, and in the Analyst Client Knowledge Base tab
4. Or generate an API key for developers building org-specific training content

#### KB Assistant (Lead and Analyst)
A research assistant lets leads and analysts ask the knowledge base questions in plain language. It retrieves the most relevant entries, answers **only** from them, and **cites every claim** — if it cannot produce a fully-cited answer, it withholds the answer rather than guessing. Cited entries appear as chips that open the KB entry (with its copiable source). It is research education — not therapy, diagnosis, or clinical advice — and when the underlying model isn't available it says so honestly instead of inventing an answer.

- **Lead KB Assistant (Management Console):** runs server-side on FireAlive's internal heavyweight model (Qwen2.5-14B-Instruct, verify-only — provisioned by the operator, never downloaded). The lead may supply brief, non-attributable team-aggregate context; individual analyst data is never used. Question and answer content are not logged (audit captures metadata only).
- **Analyst KB Assistant (Analyst Client):** runs **entirely on the analyst's device** — a local model with no server round-trip. The analyst's question and their own signals are used only as on-device grounding and **never leave the device**. The model is provisioned on the analyst's machine by the operator and verified on load by the model-file integrity & safety gate (hash-pin → GGUF format validation → on-device malware scan, fail-closed), and FireAlive never downloads it; an endpoint that can't run it gets an honest "unavailable on this device" rather than any server fallback (see AI/ML Integrations → Local AI model provisioning). A framing guardrail routes acute-distress input to the Post-Incident Wellness resources instead of to the model.

### Playbooks (SOAR Playbook / Runbook Generator)
**What it's for:** Generate investigation and response playbooks for security incidents involving the FireAlive platform itself. The lead exports these to import into the SOAR system, or prints them as runbooks. Distinct from the Runbook Generator (which produces failure-and-compromise procedures for FireAlive) — these are SOAR-style automation playbooks for ongoing incident response involving FireAlive.

**Workflow:**
1. Lead opens Playbooks
2. Picks incident type
3. System generates the playbook with steps (some automated, some manual)
4. Lead exports — drops into SOAR or prints

### Risk Register Asset Generator
**What it's for:** Generate a risk register entry for FireAlive itself as an organizational asset. Includes quantitative metrics (Asset Value, Exposure Factor, Single Loss Expectancy, Annual Rate of Occurrence, Annualized Loss Expectancy) and qualitative impact/likelihood. Crucially, it factors in the **human capital risk of NOT using burnout prevention** — the cost side of analyst turnover.

**Workflow:**
1. Risk team asks lead for a register entry on FireAlive
2. Lead opens Risk Register Asset Generator
3. System produces entry with AV/EF/SLE/ARO/ALE plus the inverse calculation: cost of turnover and replacement training if FireAlive weren't deployed
4. Lead exports and submits to the risk register

### Human Impact Risk Report
**What it's for:** Quantified report on the human capital cost of analyst burnout and the burnout-incident relationships specific to this org. Two purposes:

First, it's used to justify FireAlive's value to executives in dollar terms — annualized turnover cost, replacement training cost, and the inverse "what would this cost without FireAlive" calculation.

Second — and more importantly — it tracks in granular detail which TYPES of incidents burn out which TYPES of analysts the fastest. This lets the org make informed risk-management decisions beyond just adopting FireAlive. For example, if low-tier analysts are burning out fast because they get an avalanche of mindless repetitive tickets, the report can highlight that risk and recommend the org invest in more automated systems so those tickets can be delegated. If senior analysts are burning out from prolonged credential-compromise investigations, the report can recommend the org invest in better identity-protection infrastructure to reduce the volume of those incidents. So the report doesn't just sell FireAlive — it actively informs executive-level investment decisions about what infrastructure, automation, and protection layers will most reduce burnout in this specific org.

**Workflow:**
1. Quarterly business review or budget cycle
2. Lead opens Human Impact Risk Report, generates
3. Sees per-incident-type cost breakdown ("ransomware events drive +18% exit risk for tier-1 analysts, $61,200 annualized cost")
4. Sees recommended infrastructure investments correlated with high-risk incident types
5. Presents to executives — informs both FireAlive's value and other risk-mitigation investments

### Query Tool
**What it's for:** Two query tools combined — SIEM query generator (produces copy-pasteable queries for the org's SIEM platform from templates) and an internal app query tool (run injection-protected queries against FireAlive's own data).

**Workflow (SIEM Query Generator):**
1. Lead needs a SIEM query for "all login attempts to FireAlive in last 24h"
2. Opens Query Tool, picks template, picks SIEM platform (Splunk/Elastic/QRadar/Sentinel)
3. Gets the query as text, copies it into the SIEM

**Workflow (Internal Query Tool):**
1. Lead needs to investigate something specific in FireAlive's own data
2. Picks data source, regex filter
3. Runs query — system parameterizes, strips injection attempts, returns results

---

## Configuration group

### Feature Toggles
**What it's for:** Enable or disable individual features across the platform. Disabling a feature does NOT remove it and never deletes its data — the feature's text greys out (still visible so users know it exists), all action buttons and config inputs deactivate, and an "administratively disabled" message explains that a lead can re-enable it in the Feature Toggles tab. Turning a feature back on restores it exactly as it was. The same behavior applies in the Management Console and the Analyst Client, and a change propagates live to every connected client over the WebSocket channel — no reload needed.

**Not everything is a toggle.** Features are classified:
- **Toggle** — the 19 lead-settable features (peer chat, peer board, peer skill-share scheduling, box breathing, lighter-queue requests, pseudonymous lead chat (Signal E2EE), proactive break interventions, upskilling hour, helper pay, burnout-aware routing, IR simulator, recovery runbook, skills & assessments, training & certs, professional certifications, calendar integration, TTX generator, MSP multi-tenancy, CI/CD pipelines). Toggles default on except MSP multi-tenancy and CI/CD, which default off.
- **Locked** — security, integrity, safety, and compliance capabilities (analyst pseudonyms, audit log, log integrity, MFA, tripwire, insider-threat protocol, SOAR/EDR/threat-hunting, vulnerability scanning, enterprise KMS, backups, restore, legal hold, peer abuse flagging, and more). These appear in the toggle list as permanently on with a short reason, and the update API rejects any attempt to disable them — a feature whose removal would lower the SOC's defenses can never be turned off, even by a forged request.
- **Core** — structural scaffolding (impact feed, shift handoff, ticketing, SIEM feed, reporting engine, the global dashboard, HA and clustering, and so on). These have no switch.

**Before you turn anything off:** FireAlive is most effective at reducing burnout when every analyst-facing capability is active — they reinforce one another, and the research treats them as a system rather than a menu of extras. The switches exist because every SOC is different: some adopt everything at once, others introduce capabilities gradually or run a subset that fits their environment and their people's readiness. Toggling a feature off tailors FireAlive to your organization; it does not mean the feature is optional to the mission. Nothing is deleted when a feature is off. The optimal configuration is everything on.

This way users can still see what FireAlive offers without being confused about why a feature suddenly disappeared.

**Workflow:**
1. Lead opens Feature Toggles
2. Sees features grouped by category (Wellbeing, Operations, Development, Integrations, Security, Management), with toggle features shown as switches and locked features shown permanently on with their lock reason
3. Toggles a feature off — its tab or section greys out, controls deactivate, and an "administratively disabled" message replaces the workflow content while the data is preserved
4. Toggles back on — the feature returns to its exact previous state

### Burnout Alerts
**What it's for:** Alert thresholds for team-level burnout metrics. When the team's aggregate health drops below a threshold, or capacity overload exceeds a threshold, the lead is alerted via configured channels. Distinct from app performance alerts (CPU, memory) which are in Monitoring.

**Workflow:**
1. Lead configures thresholds on initial setup
2. Picks notification channels (per the Client Notifications config)
3. When team metrics cross thresholds, alert fires through chosen channels

### MSP Multi-Tenancy
**What it's for:** For Managed Service Providers monitoring multiple client organizations on one FireAlive deployment. Each tenant gets isolated encryption keys, separate audit trails, scoped API keys. Cross-tenant data access is blocked architecturally.

**Workflow:**
1. MSP sets up FireAlive
2. Opens MSP Multi-Tenancy, adds first tenant
3. Repeats per client org
4. Each tenant runs in isolation: tenant A's analysts never see tenant B's data, even though both run on the same server

### Global Dashboard
**What it's for:** Configure this regional MC to push aggregate data to a Global Dashboard (CISO-level view). Anonymized aggregate only — no individual analyst data crosses the region boundary. The GD is a companion app, not a controller.

**Workflow:**
1. CISO sets up GD, generates RO API key for this region
2. Regional lead opens Global Dashboard tab in MC
3. Pastes GD ingest endpoint, RO API key
4. MC starts pushing aggregate data to GD on schedule
5. CISO sees regional health alongside other regions

### Updates
**What it's for:** Update orchestration that does NOT force production updates automatically. The lead controls where update packages get sent — straight to production, to a lab environment, or to another repository for review. Once an update has been retrieved and sent to the lab, the org's existing change-management process takes over: their developers do regression testing and security testing in the lab independently. FireAlive includes a regression test runner the lead CAN run inside the lab if they want, but FireAlive doesn't try to automate the entire change-management workflow — that varies too much across orgs.

After the org's change-management approves the update, the lead pushes it to production from the same Updates tab. Production deployment includes rolling restart and a fuse counter increment to prevent rollback to a now-vulnerable version.

**Workflow:**
1. Update available — lead notified through configured channel
2. Lead opens Updates tab
3. Lead chooses destination: lab environment, alternate repository, or directly to production (rare; usually for emergency hotfixes)
4. Update package is fetched and routed to the chosen destination
5. (For lab destination) Org's developers run their own regression and security tests in the lab — possibly using FireAlive's built-in regression runner inside the lab, or their own tools
6. Org's change management process approves or rejects the update independently
7. After approval: lead returns to Updates tab and pushes the update from lab to production
8. Production deployment: rolling restart, fuse counter increment, audit log entry

### Troubleshooter
**What it's for:** Interactive assistant that diagnoses why a feature isn't working. The lead describes the problem, the troubleshooter checks integrations, configs, logs, and suggests fixes.

**Workflow:**
1. Something's broken — "SOAR routing isn't assigning tickets"
2. Lead opens Troubleshooter, types description
3. System checks SOAR connectivity, routing engine status, recent audit logs
4. Returns diagnosis + suggested fixes
5. Lead either applies fix or escalates with the diagnosis as evidence

---

## Monitoring group

### System Health
**What it's for:** Aggregated runtime metrics across the server, MC, and all connected ACs — CPU, memory, heap, DB size, load average, connected WebSocket sessions, and per-client metrics — together with the controls that govern how anomalies are detected and routed. Continuous file-integrity monitoring and a bandwidth monitor run alongside the metric stream. Anomalies (sudden spikes, sustained high load, integration outages) are dispatched through a severity-tiered alert router rather than a single fixed channel.

The tab exposes two admin-configurable control panels:

- **Integration Health** — opt-in, read-only health probes against external integrations (KMS, cloud storage, LDAP/AD, SIEM, SOAR, EDR / malware scanner, ticketing). Probing is disabled by default at both the master and per-integration level and never mutates integration data; the KMS probe performs a live wrap/unwrap round-trip only when its deep-probe toggle is on. Admins set the master switch, the periodic interval, per-integration coverage, and can run an on-demand probe; results render as a colour-coded status table with per-integration latency.
- **Alert Routing** — a per-severity × channel routing matrix (audit, SIEM, SOAR, in-app notification, email, webhook). Audit is always recorded and cannot be disabled. The defaults escalate by severity: info is audit-only, warning adds SIEM, high adds SOAR + SIEM + an in-app notification to admins/leads, and critical adds email + webhook. The panel also sets the alert webhook URL and the sustained-load hysteresis thresholds (CPU / memory / DB-read enter, exit, and dwell, plus a cooldown) that decide when a sustained-load alert fires and when it clears.

**Workflow:**
1. Lead glances at System Health daily — metrics, connected sessions, and the last integration-health probe
2. Spikes or failed probes investigated immediately — could be load, an integration outage, or an attack
3. Alerts fan out by severity to audit, SIEM, SOAR, in-app notification, email, and webhook per the routing matrix; the metric stream and forwarded client logs feed the broader SOC monitoring stack

### Vulnerability Scan
**What it's for:** Allow approved vulnerability scanners (Nessus, Qualys, etc.) to scan the FireAlive application. Only scanners from approved IP allowlist can connect; unauthorized scans are blocked at the network layer.

**Workflow:**
1. Lead opens Vulnerability Scan, adds approved scanner IPs
2. Schedule a periodic scan
3. Scanner runs, findings flow back through the org's vuln management process

### Cloud Vulnerability Scan
**What it's for:** Authorize your organization's cloud-posture and IaC scanners (ScoutSuite, Prowler, Pacu, CloudBrute, Checkov) to scan your FireAlive cloud deployment, and keep a tamper-evident record of every scan that reaches it. FireAlive does not run scans or store findings itself — scan results live in the scanner's own console, the same way EDR and threat-hunting integrations let approved tooling inspect FireAlive without FireAlive duplicating the tool. This is the cloud-posture companion to the endpoint-focused EDR/Threat Hunting integrations: FireAlive opens itself to authorized scanning by the org's security tooling and logs that access.

Each authorization is a registered scanner identity, not an open door. Access is granted per scanner with two controls: a bearer token (shown once at creation, then stored only as a salted hash) and a source-IP allow-list (individual IPs or CIDR ranges). A scan is accepted only when both the token and the source IP match an enabled authorization. Every scan attempt — accepted or rejected — is written to an append-only, hash-chained scan-access log whose integrity can be verified from the console at any time. Authorization covers all deployed components (Management Console, Analyst Client, Abuse Review Console, and the main server); the Global Dashboard server keeps its own separate authorization config and its own scan-access log.

FireAlive performs application-layer authorization and logging. Network-layer blocking of unauthorized scanners remains your firewall / security-group responsibility — FireAlive records and attributes the scans that reach it rather than acting as a network firewall. Source IPs belonging to an enabled authorization are exempt from FireAlive's API rate limiting so a sanctioned high-volume scan is not throttled; all other defenses stay active.

**Workflow:**
1. An administrator opens Cloud Vulnerability Scan and selects "Authorize Scanner"
2. Picks the scanner type, names it, and sets the source-IP allow-list (the IPs or CIDRs the scanner originates from)
3. FireAlive issues a one-time bearer token — copy it into the scanner's configuration now; it cannot be retrieved again
4. The scanner runs its own checks against the FireAlive cloud deployment, presenting its token from an allow-listed IP
5. FireAlive authorizes (or rejects) each access and records it in the scan-access log; findings remain in the scanner's console for the org's vulnerability-management process
6. The administrator reviews the scan-access log, verifies the log's integrity (chain check), and can disable or revoke an authorization at any time — revoking immediately invalidates that scanner's token

On the Global Dashboard server the same feature appears in its own console and authorizes scans of the GD server independently of any Management Console.

---

## Audit group

### Audit Log
**What it's for:** Aggregated audit trail across MC + AC. Every meaningful action — logins, config changes, ticket assignments, peer flag resolutions, redemption approvals — gets a tamper-evident hash-chained entry. Searchable, paginated, exportable for forensics.

**Workflow:**
1. Auditor / lead investigation needs evidence
2. Open Audit Log, filter by user / action type / time range / event type
3. Find the entry, verify chain integrity, export

---

## Other MC tabs

### Inbox
**What it's for:** Optional storage for notifications the user wants to revisit. Per the Client Notifications design, notifications are delivered through the channels each user chose — email, SMS, desktop notification, inbox, multiple, or off. Inbox is one channel option. It's here for users who specifically want a place to find missed notifications; it's not the primary delivery mechanism.

**Workflow:**
1. User configures notification preferences (per type: email / SMS / desktop / inbox / multiple / off)
2. Notifications fire to chosen channels
3. If user includes inbox among channels, copies show up here
4. User opens inbox occasionally to catch up on anything they missed live

### Peer Conduct
**What it's for:** An awareness-only view of abuse reports from peer skill-share sessions and the skill-share Board. After the Phase U3 cutover the MC no longer reviews these reports — review and resolution moved to the independent Abuse Review Console (operated by the separate `abuse_reviewer` role). This tab exists only so a lead knows reports are being handled, without management being able to read them.

**What the lead sees:** A single count of reports pending independent review, and nothing else — no content, no identities, not even the severity tier. Each report is sealed on the analyst's device to the active reviewers' public keys before it leaves the app, so this console structurally cannot decrypt it. The same count drives the sidebar badge.

**Why management can't review it.** A report can be about anyone, including a lead, so routing peer-session and Board reports through the people an analyst works under would chill reporting. They follow the same path as lead-chat reports: sealed to an independent reviewer (a role kept separate from team leadership) and opened only in the Abuse Review Console. Tiers signal severity to that reviewer; they no longer escalate identity reveal, and analysts stay pseudonymous to the reviewer.

**Locked toggle.** `peer_abuse_flagging` stays a **locked** capability in Feature Toggles and cannot be turned off — disabling abuse reporting would lower the SOC's safety floor.

### Help (MC)
**What it's for:** In-app help — this Feature Guide accessible by tab. Each tab in the MC has a corresponding mini-article in this Help menu.

---

# ANALYST CLIENT (the analyst's app)

### Home
**What it's for:** Analyst's daily landing. Shows their current burnout stage in big print, with optional context. Quick-action tiles for the four most common things they'd want to do (peer skill-share, delegate, training, self-scan) plus prominent buttons for "Request Reduced Tickets" and "Message Team Lead." Recent impact section showing positive reinforcement.

The "Request Reduced Tickets" button is two-state: when reduced routing is OFF, the button activates it; when reduced routing is ON, the button turns it off. The analyst always has control over their own load reduction request.

**Top-of-AC panic banner.** When the team lead engages panic mode (from the MC), a red full-width banner appears at the top of every AC screen: "PANIC MODE ACTIVE — All wellness routing is OFF. You may receive tickets above your usual complexity cap until your lead restores normal routing." This explains what the analyst is about to experience — tickets above their cap are not a mistake, they're a deliberate decision the lead made in response to a major incident. When the lead restores normal routing, the banner turns green for 5 minutes ("Panic mode lifted — wellness routing restored") then vanishes. The AC polls the canonical state endpoint every 30 seconds so the banner is always in sync regardless of which AC tab the analyst is on.

**Workflow:**
1. Analyst logs in at start of shift
2. Lands on Home — sees their current state, recent wins
3. From here, navigates to whatever they need to do
4. If they want load reduction: clicks Request Reduced Tickets → state toggles ON
5. If they want to resume normal load: clicks the now-toggled button → state toggles OFF

### My Signals
**What it's for:** The analyst's own burnout signals. Investigation time, dismiss rate, ticket quality, escalation rate — all compared to the analyst's OWN baseline (not team comparisons). Click any signal for research-backed interventions. Privacy-critical: only the analyst sees this; the lead never does.

**Workflow:**
1. Analyst feels off, opens My Signals
2. Sees: "Investigation time: 26 min vs your baseline of 20 min — that's 30% longer"
3. Clicks the signal — gets context on what this typically means and research-backed responses
4. Optionally requests reduced queue (anonymous) or messages lead (pseudonymous, E2EE)

### Inbox
**What it's for:** Same as MC inbox — optional storage of notifications for users who chose inbox as a delivery channel.

### Delegate
**What it's for:** Send recurring ticket patterns to automated systems so analysts aren't doing repetitive work that doesn't need human judgment. Two cases:

First, false positives — analysts close the same false alarm 10 times a day. The Delegate feature lets the analyst create a rule that sends those alerts straight to the SOAR or AI triage so the analyst stops seeing them.

Second — and equally important — true positives that are nonetheless low-level repetitive work. Some real incident-response actions don't need human judgment: known-malware container quarantine, low-severity password resets, ticket enrichment, basic phishing categorization. If the org has automated systems registered (in the MC's Automation tab) capable of handling that kind of work, the analyst can delegate those tickets to those systems. The analyst gets back the time, the org gets the boring tickets handled. This is what the research on anti-burnout tooling actually shows works.

**Workflow:**
1. Analyst notices a pattern (either a recurring false positive or a real but boring repetitive task)
2. Opens Delegate tab, clicks "+ New Delegation"
3. Describes the pattern
4. Picks target: SOAR auto-response, an AI triage system, or one of the automated systems the lead registered in MC's Automation tab
5. Submits — lead approves the delegation in MC
6. From now on, that pattern is auto-handled by the chosen system; analyst stops seeing it

### Peers
**What it's for:** Peer skill-share — end-to-end encrypted chat between analysts (Signal protocol: X3DH/PQXDH key agreement and the Double Ratchet, with out-of-band safety-number verification) to share knowledge, ask questions, learn techniques. NOT therapy or emotional support — that has separate channels. This is technical knowledge sharing. Anti-abuse flagging is built in. 4KB per message, auto-closes after inactivity; after a session, ciphertext is retained for 5 minutes for abuse review, then permanently deleted.

**Workflow:**
1. Analyst stuck on a technique — opens Peers
2. Posts a skill-share request: "Anyone good with Splunk regex extraction?"
3. Another analyst sees it, accepts, opens E2EE chat
4. They work through the problem
5. Session times out, chat is gone — but the helper earned points (Helper Pay)
6. Either analyst can post-session flag if conduct was inappropriate

### Lead Chat
**What it's for:** A pseudonymous, end-to-end-encrypted 1:1 channel between an analyst and a team lead (Signal protocol: X3DH/PQXDH key agreement and the Double Ratchet, with out-of-band safety-number verification). The analyst picks a specific lead — the lead is named to the analyst — and writes under their own pseudonym, so the lead sees "Analyst-Falcon," never the real name, and the server relays only ciphertext it cannot read. This is the channel for reaching a chosen lead directly: workload concerns, schedule changes, or just asking to talk. For anonymous support, analysts use peer chat instead. The analyst can also send an in-person 1:1 request, which the lead sees surfaced both in a banner and at the top of the Lead Chat inbox. Any on-shift lead is reachable — a lead is never hidden by shift. Messages are deleted five minutes after the chat is closed.

**Workflow:**
1. Analyst opens "Message Your Lead" and picks an on-shift lead from the roster
2. The Signal session establishes; the analyst types a message or taps "Request an in-person 1:1"
3. Lead opens Lead Chat in the Management Console — the thread is labeled by the analyst's pseudonym
4. Lead reads it (clearing the unread and 1:1 indicators) and replies on the same encrypted channel
5. Either side can verify the safety number out of band — read it aloud; the numbers must match
6. Analyst closes the chat; five minutes later the scheduler purges the thread's messages

**Reporting abuse:** Either party can report a message in a lead chat — the analyst can flag a lead's message, and the lead can flag the analyst's. Each incoming message carries a Flag control; reporting it opens a tier picker (Tier 1 minor, Tier 2 personal attack, Tier 3 urgent) and a required note. This is deliberately **not** routed to the team lead: a lead can be the subject of a report, so lead-chat reports go to an **independent abuse reviewer** instead. The reported message and the note are sealed on the reporter's own device to the active reviewer recipient set (a multi-recipient X25519 envelope) before they leave the app, so the server stores only opaque ciphertext it can never read, and neither management nor any team lead can decrypt it — only a designated reviewer's Abuse Review Console, which holds the reviewer's own private key, can open it. Reporting is available only once an organization has designated at least one independent abuse reviewer (otherwise nothing could be decrypted, and the UI says so). When the reviewer later opens a report, a lead who is a party is shown by real name, while an analyst is shown only by pseudonym.

### Helper Pay (AC-side)
**What it's for:** The analyst's own view of their Helper Pay state — points earned from helping peers, current balance, transaction ledger, available rewards, and the leaderboard visibility toggle that controls whether their pseudonym appears on the lead's recognition leaderboard.

Points come from 4-5 star peer-session ratings the analyst has received. Each rating writes a ledger entry (1-2 stars yield zero points; 3 stars yields a low amount). The analyst sees their full ledger here — every entry, daily-cap clamps, and any admin-side fraud reversals. Rewards are redeemed against the catalog the lead configured (USD, PTO minutes, custom rewards); requests go to the lead for approval and fulfillment.

The leaderboard visibility toggle defaults to OFF (opt-out). Flipping it on adds the analyst's pseudonym (or real name if pseudonyms aren't enabled team-wide) to the lead's recognition leaderboard on the MC. Earning, balance, and redemption are NOT affected by this toggle — they continue regardless of leaderboard visibility. Only the public-display surface changes.

The Your Records card exports a personal copy of the statement — balance, full ledger, and redemption history — as a signed PDF, DOCX, or CSV. All three formats are signed with the instance's Ed25519 report-signing key and carry a verification footer (instance label, signed time, key fingerprint, and the SHA-256 verification instruction), so the analyst, or an admin asked to attest to a copy, can confirm a document is genuine via the in-app verify endpoint or OpenSSL per `docs/report-verification.md`. The statement is self-scoped — the server returns only the caller's own data — and is for personal record-keeping, not a payroll or HR artifact.

**Workflow:**
1. Analyst opens Helper Pay tab in their AC
2. Sees current balance prominently displayed
3. Optionally toggles "Visible on the leaderboard" — feedback panel confirms the new state
4. Browses the Available Rewards catalog
5. Hits Redeem on a reward — confirmation modal explains the points cost and the approval workflow
6. Submits redemption request; appears in their My Redemptions list as Pending
7. Lead approves/declines (separate MC tab); on approval, points debit from the analyst's balance
8. On fulfillment, the analyst sees the request status flip to Fulfilled; they receive their PTO or USD per the org's payout method
9. Optionally downloads a signed PDF, DOCX, or CSV statement from Your Records — a personal copy of the balance, ledger, and redemption history for the analyst's own files

### Board
**What it's for:** Async forum for tips, questions, burnout strategies. Posts auto-expire after 7 days (so it's a current-conversation space, not a permanent record). Each post supports threaded responses so analysts can ask follow-up questions or add comments, and posts and replies can be marked with lightweight reactions (Helpful, Thanks, Insightful, Same here) for low-effort acknowledgement. The same conduct rules and tiered abuse flagging system from peer chat apply here too.

If a post is flagged, it's temporarily removed from the Board pending independent review. The flagged content is sealed on the flagger's device to the active reviewer recipient set and stored as opaque ciphertext in an evidence vault with no expiration (so it can't disappear before review) — neither management nor any team lead can read it. Only a designated reviewer's Abuse Review Console can open it; the reviewer then dismisses the flag (the post returns to the Board) or upholds it (the post stays removed). It's the same independent-reviewer path as peer chat.

**Workflow:**
1. Analyst has a tip to share or a question with no time pressure
2. Posts to Board with a category
3. Other analysts read async, respond via threaded responses, and react to useful posts
4. Posts age out after 7 days

**Flagging workflow:**
1. Analyst sees a post or response that's inappropriate
2. Flags it with a tier (1: minor / 2: personal attack / 3: urgent — slurs, threats, harassment)
3. Post is removed from Board pending review, stored in evidence vault
4. The independent abuse reviewer opens the case in the Abuse Review Console, reviews the sealed evidence and thread context, then dismisses (post returns to the Board) or upholds it (stays removed) — management is not involved

### IR Simulator (this is the AI/ML training feature)
**What it's for:** Train on YOUR organization's IR procedures — not generic textbook ones. Each scenario is generated from a real IR policy the lead uploaded. The analyst walks through OBSERVE → ORIENT → DECIDE → ACT phases, makes choices, gets feedback. Tracks IR Policy Mastery level over time. After completion, shows the actual policy that was used so the analyst can verify they're learning real org procedure.

**Workflow:**
1. Analyst opens IR Simulator at start of upskilling hour
2. Sees their current Mastery level, which policies they've practiced
3. Picks a policy they haven't done yet (or retries one to improve score)
4. Walks through OODA phases with multi-choice decisions, gets feedback per choice
5. Completes scenario — earns points, level may increase
6. Sees the actual policy document used as the source for this scenario — confirms it matches their org's real procedure
7. As more policies are uploaded by the lead, more scenarios become available

### Skills & Assessments
**What it's for:** Analyst's view of their own skill development. Sees assessments assigned by the lead. Sees baseline established from the AC's automatic baseline assessments at first-launch. Sees gap-driven training recommendations. When proficiency thresholds are crossed, the lead receives a growth signal — this is recognition, not a demand.

**Workflow:**
1. AC's first-launch baseline assessments establish initial skill profile (private to analyst)
2. Lead later assigns a targeted assessment — analyst sees it here as an Assessment Required notification with a link to the external module
3. Analyst goes to the external platform (HackTheBox/TryHackMe/etc.), takes the module
4. Submits completion report (link, score, date) back through the AC
5. Result populates gap display and training recommendations
6. Lead also sees this targeted assessment's result (unlike baseline assessments which stay private)
7. Gap areas auto-create training recommendations for that analyst
8. When proficiency improves above threshold: growth signal sent to lead

### Training & Certs
**What it's for:** AI-recommended training based on assessment gaps. Categorized by skill area (SIEM Queries, Investigation, Escalation, Threat Hunting, Malware Analysis) with proficiency percentages and direct links to training platforms (TryHackMe, LetsDefend, HackTheBox, SANS, Cyberdefenders).

When upskilling hour begins, ticket routing pauses for that analyst and a content filter activates on the AC's host machine — only training/peer chat/cert sites are accessible during that hour. The content filter uses the host operating system's native content-filter capability (FireAlive integrates with it rather than reimplementing it). Training URLs in this tab are copyable but not clickable: FireAlive deliberately does not call URLs to avoid exposing the suite to URL-based attacks. The analyst copies the URL into their browser themselves.

**Workflow:**
1. Analyst opens Training during upskilling hour
2. Sees recommended modules by skill area, sorted by current proficiency
3. Copies the module URL (not clickable — no FireAlive-initiated browsing)
4. Pastes the URL into their browser, opens the training module
5. Completes module on the platform
6. Returns to FireAlive, submits completion (module name, platform, URL, date)
7. Lead verifies completion, skill profile updates

### Post-Incident Wellness
**What it's for:** Personal wellness resources — always available, not just post-incident. Includes both built-in resources (breathing exercises, stress response education, self-care strategies) AND any wellness resources the lead has configured in the MC and propagated to the AC. So the org can add subsidized counseling services, EAP contact info, internal wellness programs, peer support channels, anything else specific to that org's employee wellbeing offerings.

Tier-3 PRIVATE — the lead literally cannot see whether the analyst accesses these resources. Distinct from technical incident recovery procedures.

**Workflow:**
1. Analyst feels stressed (or just wants to maintain wellbeing)
2. Opens Post-Incident Wellness
3. Uses built-in breathing exercise widget, reads strategies
4. Sees org-specific resources the lead provided (e.g. "Subsidized counseling: contact EAP at..." or "On-site wellness program: schedule at...")
5. Accesses external mental health resources or org-provided support
6. None of this is logged in a way the lead can see — fully private

### Self-Scan
**What it's for:** Analyst-initiated 10-point compromise check on their own client. Tests binary integrity, memory analysis, network connections, configuration drift, audit log continuity, TLS pinning, API tokens, filesystem integrity, EDR status, encryption keys. Results go to the analyst AND auto-send to MC — not optional, because client compromise affects the whole team.

**Workflow:**
1. Analyst notices something off about their machine, or it's part of weekly hygiene
2. Opens Self-Scan, clicks Run
3. Scan runs (~2-3 minutes), 10 checks
4. Results display: pass/fail per check
5. Auto-transmitted to MC — lead may follow up if any failed

### Audit (AC-side)
**What it's for:** Local audit log of events on this client. Auto-mirrored to MC. So if questions arise about what the analyst was doing at a specific time, they can see their own log.

### Privacy
**What it's for:** Analyst's data privacy controls and consent log. Shows what data is collected at Tier-1 (visible to lead, aggregate only) vs Tier-3 (private to analyst). Consent events log every privacy decision the analyst made.

### Certifications
**What it's for:** Where the analyst registers their professional industry certifications (CompTIA, ISACA, ISC², GIAC, etc.). Uploads cert file (PDF/image, encrypted), enters verification number. Lead verifies and the cert contributes to the analyst's skill profile.

---

# GLOBAL DASHBOARD (CISO read-only view)

The GD aggregates anonymized data from multiple regional MCs. The CISO sees regional health, never individual analyst data. Read-only, separate server.

### Global Overview
Cross-region aggregate health.

### Regional Breakdown
Per-region health bars, automation rates, cert coverage.

### Reports
**What it's for:** CISO-grade executive reports that aggregate the latest regional metrics pushed in from every connected MC. Five report types are available: Executive Summary (cross-region health, utilization, turnover-risk highlights, recommendations, and FireAlive ROI financials), Global Human Impact Risk Report (per-region churn-cost breakdown), Turnover Forecast, FireAlive ROI, and Compliance by Jurisdiction.

Reports render in three formats: JSON in-app (for the dashboard preview) and signed PDF and DOCX downloads. Every PDF/DOCX is signed with the Global Dashboard's own Ed25519 report-signing key and stamped with a verification footer (instance label, generation time, signing-key fingerprint), so the recipient can confirm the document is a genuine, unaltered FireAlive artifact -- in-app via the authenticated verify endpoint, or independently with OpenSSL per `docs/report-verification.md`. The GD signs its own reports under its own instance key, distinct from any MC's.

**Workflow:**
1. CISO opens Reports
2. Picks a report type from the dropdown
3. Clicks Generate Report -- the GD-Server pulls the latest regional_metrics snapshots from each connected MC and renders the report server-side
4. The dashboard shows the report in-app
5. Clicks Download PDF or Download DOCX to save the signed document; or Export Report for a quick client-side JSON copy
6. Files the PDF/DOCX with board materials or the audit-evidence binder

### MC Connections
**What it's for:** Manage which Regional MCs feed data here. Register new MCs, view their connection health, offboard decommissioned ones. The connections tab is also the trust-registry admin surface for signing keys.

**Pending Signing Key Approvals queue:** When a Regional MC first connects (and on every key rotation), it submits a signing-key fingerprint that this GD must approve before signed pushes are accepted. The queue at the top of the connections tab shows all pending submissions across all MCs with their full fingerprints. A CISO or signing_key_approver verifies each fingerprint OUT OF BAND with the MC operator (phone, in-person, separate encrypted channel) and clicks Approve or Reject. The Approve click fires a confirmation dialog displaying the fingerprint one more time before the irreversible state transition; the click also sends the fingerprint to the server as a confirmation parameter, so a UI bug pointing approve at the wrong row is caught server-side (CONFIRMATION_FINGERPRINT_MISMATCH). Reject opens a modal capturing a free-form rejection reason (required, ≤500 chars); the reason is recorded in the GD audit log and the GD-side admin view only — never exposed to the MC operator (privacy invariant). Both actions emit MC_SIGNING_KEY_APPROVED / MC_SIGNING_KEY_REJECTED audit events.

**Per-MC Keys panel:** Each MC card has a "Keys" button (becomes "Review keys" in primary styling when that MC has pending submissions, with a per-MC pending count badge). Expanding the panel shows the COMPLETE signing-key history for that MC: every approved, pending, and rejected row with their full fingerprints, registration timestamps, approval metadata (timestamp + approver user id + approver role), rotation metadata (rotated_out_at when the key was demoted by a successor), and rejection metadata (rejected_at + rejected_reason). This panel is the ONLY UI surface where rejected_reason is exposed; the MC-facing status endpoint strips it.

**Top-of-list summary line:** When any MCs have pending submissions, a one-line summary above the MC list names the distinct count and points the operator at the amber "Review keys" affordance.

**Pending Legal-Hold Export Approvals card:** The connections tab also carries the CISO’s approval queue for two-person legal-hold exports of vaulted abuse cases. When an abuse reviewer requests an export, it appears here (gated to the `ciso` role) with the case and request identifiers and the reviewer’s written rationale. Approving mints an Ed25519-signed decision token over that specific request — bound to the request, case, and decision; denying records a signed denial with a reason. The CISO approval key is distinct from the report-signing and trust-registry keys, and the management console never sees that an export was requested, approved, or produced. The reviewer’s own device verifies the signed token against an independently pinned copy of this CISO key before any case file is produced. Full procedure in `docs/abuse-vault-legal-hold-export.md`.

### Compliance Posture
**What it's for:** Generate a compliance report against THIS GD-Server's own running state. Same 16-framework selector as the MC side, same Shared Responsibility two-bucket structure (verifiedControls + customerResponsibility), but the controls checked are GD-specific: cross-region aggregation integrity, signing-key trust registry hygiene, mailbox-pattern fulfillment, GD-side audit log integrity, GD-side encryption, GD-side authentication, GD-side configuration locking. Each report carries the framework name, authority, citation, generation timestamp, and the app version that produced it — useful provenance metadata for audit evidence.

**Workflow:**
1. CISO opens Compliance Posture tab
2. Selects a framework from the 16-option dropdown
3. Clicks Generate Report
4. Sees 4-up summary (Total / Pass / Warn / Fail) plus the verified-control list with status badges, per-control mapping to the framework taxonomy (NIST control id, HIPAA citation, ISO clause), and a remediation pane on any non-pass row describing what the GD operator needs to do to fix the finding
5. Sees the customer-responsibility list below — the controls the OPERATING ORGANIZATION must attest separately for the GD layer (e.g., subprocessor agreements for the GD's hosting, GD-side personnel access policies)
6. CISO files the report in the org's audit-evidence binder alongside the corresponding MC reports
7. Click Download PDF or Download DOCX to export the report as a signed, watermarked document (Ed25519 instance signature + verification footer, checkable in-app or offline per `docs/report-verification.md`); hand the PDF directly to the auditor

### Cross-Region Compliance
**What it's for:** Roll up compliance posture across every connected Regional MC. The matrix view shows framework x MC cells with passed/total counts colored by health (green ≥90%, amber ≥70%, red below). Filter by framework, by MC, or by region to narrow the view. Drill into any cell to see that (MC, framework)'s full-report history — past CISO-requested fulfillments with timestamps, signature fingerprints (for forensic verification), and payload sizes. Click any report row to see the parsed report body: framework summary, full verifiedControls list with status badges, and customerResponsibility list.

If a cell's most recent report is stale or there's no full-report history at all, the CISO can request a fresh fulfillment via the **Request Full Report** button. The request follows the mailbox pattern (Foundational Rule 21 — GD never dials MC; data flows MC-to-GD only). The button writes a pending row to the GD-side mailbox; the MC observes the request on its next compliance tick (default 24h cadence) and pushes the full report via the ingest endpoint. After submit, the cell shows a PENDING badge and a top-of-tab pending banner with a Refresh Matrix button that re-fetches the rollup to check for fulfillments.

**Auth:** Cross-Region Compliance reads are gated to ciso / vp / readonly roles; mailbox writes (Request Full Report) are gated tighter to ciso / vp only.

**Workflow:**
1. CISO opens Cross-Region Compliance
2. Reviews the matrix at a glance — colored stats per (framework, MC) cell
3. Optionally narrows with filters (e.g., framework=HIPAA to see one regulation across all MCs)
4. Drills into a specific cell to see the report history
5. Either reads the most recent full report inline or clicks Request Full Report to get a fresh fulfillment
6. After fulfillment lands (MC's next tick), refreshes the matrix and reviews the new report body

**Cross-instance signing:** each instance signs its own reports under its own report-signing key. The GD signs reports it generates itself -- the Compliance Posture single-framework report and the Executive Reports above. Upstream MCs sign reports they generate. Each MC's full-report history rows in the matrix record that MC's signature fingerprint; the GD's signing-key fingerprint identifies any GD-generated artifact. A GD-signed report is attributable to the GD instance, an MC-signed report to that MC -- the two key families never overlap.

### Helper Recognition
**What it's for:** Cross-MC Helper Pay leaderboard. Each active MC pushes its top opted-in helpers on a configurable cadence (default 15 minutes); this tab displays the aggregated view across every connected MC. Only analysts who have explicitly opted in via their AC's Helper Pay tab appear here, and only their pseudonyms cross the wire — real names, user IDs, and earning details stay on the MC.

The push payload is signed with the MC's Ed25519 key and verified GD-side via the same signing-key trust registry used for metrics and compliance pushes. Each ingested row carries the signing fingerprint for forensic provenance display.

**Auth:** Helper Recognition reads are gated to ciso / vp / readonly roles. No writes from the GD side — the data flows one-way (MC → GD).

**Workflow:**
1. CISO opens Helper Recognition
2. Sees the matrix at a glance — one card per active MC with that MC's top 5 inline
3. Clicks a card to drill into that MC's full top-50 leaderboard
4. Drilldown shows each helper's pseudonym, sessions, average rating, points, plus a truncated signing fingerprint per row (hover for full value)
5. Uses for cross-region comparison ("which MC has the highest engagement?"), recognition reporting up the leadership chain, or forensic correlation between this surface and the GD audit log

### MC Offboarding
When a regional SOC is decommissioned, offboard its MC. Historical data retention per policy.

### CISO Notifications
Threshold alerts when any region crosses critical lines (burnout health below threshold, SLA below %, turnover risk high).

### Query Tool
Run cross-region queries: burnout trends, turnover risk, cert gaps, automation ROI.

### System Health
Self-monitoring of the GD server.

### Monitoring Integrations
Connect GD to org's monitoring stack so compromise of the GD itself is detected.

### IAM & Access / MFA / Posture / WiFi / Compromise Scan / Vulnerability Scan / Regression Test / Cloud & IaC / SDN-SASE / HA & Clustering / Backup / Data Sovereignty / Recertification / Troubleshooter / App Updates
Same purposes as MC equivalents but scoped to the GD server (which is independent infrastructure separate from the regional MC).

### Audit & Forensics
Audit trail visibility for the GD layer — separate audit log from the regional MCs.

---

# ABUSE REVIEW CONSOLE (the independent reviewer's app)

The Abuse Review Console (ARC) is a separate desktop app for the independent abuse reviewer — a role kept **outside team leadership** so that a lead can be the subject of a report without controlling the review. Every FireAlive deployment must designate at least one independent reviewer; abuse reporting in the AC and MC stays disabled until a reviewer's public key is registered. Where one person holds both team-lead and platform-admin duties, the reviewer comes from an independent function (HR, ethics committee, etc.).

The ARC opens abuse-report content **client-side, with the reviewer's own private key**. The server stores only opaque sealed envelopes; the management console cannot decrypt them; an admin who handles only public keys cannot decrypt them. Adding or removing a reviewer is a public-key operation in the MC's Audit → Abuse Reviewers panel — no private key is ever shared, exported, or transferred between people.

### First-Run Setup
**What it's for:** Generating the reviewer's keypair on the reviewer's own device and handing the public key to the admin so it can be registered with the server.

**Who uses it:** The independent abuse reviewer, once, on a device only they use.

**Workflow:**
1. Install the ARC (see SETUP.md). On first launch, set a 12-character (or longer) passphrase, entered twice. The passphrase is the only thing that unlocks the private key on future sessions; if forgotten, the key is unrecoverable and a new one must be designated.
2. The ARC generates an X25519 keypair locally. The private key is wrapped under the passphrase (scrypt → AES-256-GCM) and then sealed to the OS keychain via Electron `safeStorage`. The private key never reaches the renderer and never leaves the device.
3. The ARC displays the public key and a 16-hex-character fingerprint. Hand both to the platform admin via an out-of-band channel; never share the passphrase or the private key with anyone.
4. The admin opens the MC → Audit → Abuse Reviewers panel and registers the public key (the server derives and stores the fingerprint, which the admin can confirm against the one you handed over). Once at least one active public key is registered, abuse reporting becomes available in the AC and MC.

### Sign-in (every session)
**What it's for:** Authenticating the reviewer (credentials + MFA) and unlocking the in-memory private key for the session.

**Workflow:**
1. Launch the ARC and enter credentials + TOTP MFA code. The reviewer's role is checked against `abuse_reviewer`; every other role (lead, admin, analyst) is rejected.
2. Enter your passphrase; the ARC `safeStorage`-decrypts the wrapped private-key blob, scrypt-unwraps it, and holds the unwrapped key in main-process memory **for this session only**. The renderer never sees the key.
3. A persistent banner across the top of the app reminds the reviewer that they hold independent authority and that management cannot read flag content.

### Case List & Case Detail
**What it's for:** Browsing abuse reports the server has routed to the active reviewer set and opening one to read the sealed content.

**What you see in the list:** Metadata only — case id, target type (peer-session, board-post, lead-chat), tier, time, parties (a lead who is a party is shown by real name; an analyst is shown only by pseudonym), status. No content. The list is scoped to cases the reviewer has access to (per the assignment rules — no party to the case, no team-lead role).

**What you see in the detail:** The sealed note and the sealed message (and for board-post, a small thread-context snippet) are each fetched as opaque base64 from the server. The ARC decrypts them client-side using the in-memory private key. The plaintext exists only in the renderer for the duration of viewing.

**Workflow:**
1. Open the Case List tab; pick a case.
2. The detail view renders the metadata; each sealed panel decrypts locally and shows its plaintext (or an error if the reviewer is not in the recipient set — which can happen for a flag sealed before this reviewer was registered).
3. Move on to resolution.

### Resolving a Case
**What it's for:** Closing a case with a disposition note (dismiss / uphold / escalate). The disposition is metadata; no content is altered by resolution.

**Workflow:**
1. From a case detail view, click Resolve, choose a disposition, enter a note.
2. The case moves to resolved status; the audit log records who resolved it and the note. The disposition flows back to whatever downstream behaviour the target type requires (a board-post flag upheld keeps the post removed; dismissed returns it to the board).

### Legal-Hold Export
**What it's for:** Taking a single sealed abuse case out of the eternal-retention vault as a self-contained case file for a legal or HR matter, under a two-person rule. The reviewer requests; a CISO approves with a signed token; the reviewer’s device verifies that token before producing the file. The vault original is never altered — the action exports a copy.

**Who uses it:** The independent reviewer (request and produce) together with a CISO in the Global Dashboard (approve). They must be different people — the software separates the two roles across realms but cannot detect one person holding both accounts.

**One-time setup — pin the CISO key:** Before producing, the ARC must hold the CISO’s approval *public* key, pinned once and out of band. Obtain the key and its SHA-256 fingerprint from the CISO through a trusted channel, paste both into the ARC, and it recomputes the fingerprint and refuses to pin on a mismatch. The pin lives only on the reviewer’s device, independent of the server.

**Workflow:**
1. From a case detail view, open Legal-Hold Export and submit a request with a written rationale (a minimum length is enforced). One open request per case; it is valid for a fixed approval window.
2. The request is relayed to the CISO. Its status shows here and updates when the CISO acts.
3. On approval, click Produce case file. The ARC re-verifies the CISO’s signed token on the device — the signature, and that it binds this exact request, case, and decision — and refuses if anything fails.
4. The ARC assembles a watermarked “RESTRICTED — Legal/HR” case file from the locally decrypted material, embeds the verified approval token so a recipient can check it independently, downloads it, and records production. The vault row is untouched.

**Framing:** the export is a chain-of-custody and authenticity control, not a way to go over a reviewer’s head or to reopen a locked determination. Once two authorized people hold the file, software cannot control where it then goes; the watermark and recorded rationale are accountability, not destination enforcement. Full architecture, the canonical token payload, and an OpenSSL procedure for verifying a produced file offline are in `docs/abuse-vault-legal-hold-export.md`.

### Patterns
**What it's for:** Surfacing **metadata-only** signals across the cases the reviewer has access to — repeat-offender (same person flagged 2+ times in 30 days), escalation (tiers increasing across cases), retaliation (a flag against someone who recently flagged the reviewer's own party). The pattern detector reads metadata only; it never decrypts content.

**Where it lives:** Patterns tab. Clickable signal chips jump to the relevant case detail.

### Locking & Auto-lock
**What it's for:** Defence in depth around the in-memory private key.

**How it works:**
- A 5-minute inactivity timer hard-locks the session: the in-memory private key is cleared, the app returns to the unlock screen, and the reviewer re-enters their passphrase to continue.
- A Lock button is in the header at all times; clicking it clears the in-memory key immediately.
- Closing all windows (window-all-closed) and shutdown (before-quit) also clear the in-memory key.
- The on-disk passphrase-wrapped, safeStorage-sealed blob is never touched by any of these; it survives across sessions and shutdowns. Only the passphrase brings it back.

### Adding or Removing Reviewers (admin-side)
**What it's for:** Curating the active recipient set. Every flag is sealed at submission time to ALL reviewer public keys active at that moment.

**Workflow:**
- **Adding:** the new reviewer installs the ARC on their own device, generates their own keypair (First-Run Setup above), and hands the public key + fingerprint to the admin. The admin registers it via MC → Audit → Abuse Reviewers. From the next flag onward, content is sealed to the expanded recipient set.
- **Removing:** the admin revokes the reviewer's public key in the same MC panel. New flags omit the revoked slot. Flags already sealed to a set including that key stay openable by every other active reviewer at the time of sealing.

**Boundary:** the recipient set is computed at seal time. A reviewer registered AFTER a flag was sealed cannot open that older flag — their slot does not exist in the envelope. There is no server-side re-seal path; the server never holds plaintext.

### Recovery
**Forgotten passphrase:** the private key is irrecoverable. Revoke that public key, have the reviewer generate a fresh keypair (a new passphrase, a new fingerprint), and register the new public key. Past flags that were also sealed to other active reviewers stay openable by them; flags sealed when the lost-key reviewer was the sole active reviewer cannot be reopened by anyone — this is the cost of zero-access.

**Lost or compromised device:** revoke the public key in the MC panel immediately so no new flags are sealed to that slot. The device still holds the passphrase-wrapped private-key blob (passphrase-required to unwrap), so the risk depends on passphrase strength and how quickly revocation happens.

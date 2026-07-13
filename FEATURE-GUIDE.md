# FireAlive Feature Guide

A plain-language reference to every feature in the FireAlive suite. For each feature: what it’s for, who uses it, when, and the workflow to use it.

This guide is bundled with every FireAlive distribution and is also accessible via the Help tab in each application (Management Console, Analyst Client, Global Dashboard).

If you’re new to FireAlive, start with **The Big Picture** below.

-----

## The Big Picture

FireAlive is a SOC analyst burnout-prevention platform. Security Operations Centers burn out their analysts at brutal rates — turnover, errors, mental health damage. FireAlive sits inside the team’s existing SOC tooling stack and intervenes at the points where burnout actually happens: ticket assignment, peer support, training, post-incident recovery, shift transitions.

Three apps make up the suite:

- **Analyst Client (AC)** — runs on each analyst’s workstation. Where the analyst sees their own signals, asks for help, takes care of themselves.
- **Management Console (MC)** — runs on the team lead’s workstation. Where the lead sees aggregate team health (no individual burnout data), configures the platform, runs operations.
- **Global Dashboard (GD)** — runs on the CISO’s workstation. Read-only view aggregating across multiple regional MCs. Executive-level visibility without the operational details.

A regional **Server** sits behind the AC/MC. A separate **GD Server** aggregates from regional MCs.

The whole thing is built on five privacy commitments:

- **Tier-3 data** (individual burnout signals) is sealed to the analyst’s own key — the server stores only ciphertext it cannot read, it is decrypted only on the analyst’s own device, and the lead never sees it
- **Tier-1 data** (team-level aggregates) is what the lead sees — averages, never individuals
- **Pseudonyms** decouple analyst identity from burnout data at the database layer
- **Abuse-report zero-access:** abuse reports (peer-session and board-post) are sealed on the reporter’s device to the active Team-Lead recipient set before they leave the app. The server, the GD, and admins (who handle only public keys) cannot decrypt them — only a lead who has enrolled an abuse-review key can open a case, on their own device.
- **Directory-identity minimization:** when FireAlive syncs accounts from a directory (LDAP/AD), it persists only the opaque directory id — the real `displayName` and `sAMAccountName` are never stored. FireAlive holds no real names anywhere; people are identified by username or pseudonym, which is why an abuse-review case can only ever show pseudonymous handles.

-----

# MANAGEMENT CONSOLE (Team Lead)

## Operations group — the lead’s daily workspace

### Actions

**What it’s for:** The lead’s daily action queue. The platform reads aggregate team signals (utilization spikes, capacity overload, extended stress patterns) and surfaces priority prompts for the lead to act on. Each prompt cites the underlying research so the lead understands why this is being flagged.

**Workflow:**

1. Lead logs in at the start of shift
1. Lands on Actions tab
1. Sees prompts ranked by severity (red = high, amber = medium, gray = low)
1. Each prompt shows the issue, suggested response, supporting research citation
1. Lead can adjust prompt depth (full / compact / minimal) for their attention level
1. Lead either acts on a prompt or silences it (if they’ve decided not to act)

### Team Overview

**What it’s for:** The lead’s at-a-glance team capacity view. Shows workload metrics — utilization %, ticket counts, capacity caps — but never burnout signals. The deliberate boundary: the lead sees enough to manage capacity but not so much that they’re surveilling individuals’ wellbeing.

**Workflow:**

1. Lead opens Team Overview
1. Sees four headline metrics (Team Health score, Avg Utilization, # Over Capacity, # Extended)
1. Per-analyst capacity cards show utilization bars, ticket counts, complexity caps
1. Lead spots someone over capacity, makes routing adjustments in the Routing tab

### Routing

**What it’s for:** Where the lead manages FireAlive’s burnout-aware ticket routing — per-analyst complexity caps, the equity engine, the live feed, the panic button, and the silent-pause toggle. This tab is the operational surface; the integration credentials live one tab over in **SOAR & Ticketing**.

**Workflow:**

1. Lead opens Routing tab
1. Adjusts per-analyst complexity caps using +/- buttons (tier 1 might cap at complexity 2, tier 3 might handle complexity 5)
1. Clicks Apply to save the changes to the canonical routing API
1. Watches the live feed for routing decisions as they happen
1. If team-wide intake needs to pause briefly (scheduled maintenance, integration troubleshooting), the silent-pause toggle in this tab stops FireAlive from publishing routing variables to the SOAR until re-enabled — distinct from panic mode below, this is silent and doesn’t notify analysts

**Panic button (always visible in the MC header).** A red button at the top right of every MC screen lets the lead engage panic mode with one click + a confirmation dialog. Panic mode disables all wellness routing, sets every analyst’s complexity cap to maximum (5), and broadcasts an in-app notification to every active analyst that wellness routing is OFF and they may receive tickets above their usual complexity cap. The lead can restore normal routing with another click on the same button; restoration also broadcasts a notification to every analyst. After deactivation, a green “Panic mode lifted — wellness routing restored” banner shows at the top of the MC and AC for 5 minutes, then vanishes.

**Top-of-MC panic banner.** When panic mode is active, a red full-width banner sits above the page header on every tab: “PANIC MODE ACTIVE — All wellness routing disabled. Every analyst is at maximum complexity.” After deactivation the banner turns green for 5 minutes, then disappears. The MC polls the canonical panic-state endpoint every 30 seconds so the banner is always in sync with the current state regardless of which tab is open.

**The routing_enabled silent-pause toggle** is distinct from panic mode in two ways. First, it’s silent — analysts are not notified. Second, it only pauses outbound variable publishing to the SOAR; the analyst’s local complexity caps remain in effect. Use it when the SOAR doesn’t need fresh variables (scheduled maintenance, non-business-hours integration debugging) without panicking the team.

### SOAR & Ticketing

**What it’s for:** Where the lead configures FireAlive’s integration with the existing SOAR platform (so FireAlive can publish capacity intelligence the SOAR uses to make routing decisions) and ticketing system (read-only — for queue metadata). This is the **configuration** surface; the operational surface for adjusting caps and watching routing happen lives in the **Routing** tab.

**Workflow:**

1. Lead enters SOAR platform name, API endpoint, service account, API key
1. Optionally enables auto-escalation (when a ticket exceeds the assigned analyst’s complexity cap, the SOAR auto-routes to a senior tier rather than dropping or queueing)
1. Enters ticketing platform name, read-only API endpoint, API key
1. Clicks Save SOAR Config (saves both SOAR and ticketing configurations in sequence)
1. Clicks Test Connection to verify the SOAR is reachable; the response includes a round-trip confirmation if auto-escalation is enabled
1. Watches the **Live SOAR Routing State** card — shows the 6 routing variables FireAlive is currently publishing to the SOAR, refreshed every 30 seconds while this tab is open

**SOAR Polling Contract.** Once the SOAR is configured, it polls `GET /api/routing/variables` on its own cadence (typical 30–60 seconds) with an api-key authenticated against the `routing:read` scope. FireAlive returns the current state: per-analyst capacity context (keyed by pseudonym, never by user ID), panic mode state, the silent-pause toggle state, and the six SOAR variables (`analyst_capacity`, `complexity_cap`, `equity_weights`, `skill_matrix`, `burnout_risk_tier`, `shift_handoff`). The SOAR uses these values in its own playbook logic to make routing decisions; FireAlive never distributes tickets directly. When the SOAR completes a routing decision, it posts the decision back via `POST /api/routing/soar-events` (api-key + `routing:events` scope), and FireAlive persists the event for the capacity-feedback loop. See `docs/integrations-privacy.md` for the full contract including the pseudonym-only privacy invariant.

**Ticketing read-only invariant.** The ticketing integration is enforced read-only server-side: whatever the lead supplies for the `readOnly` flag (or omits) is overwritten with `true` before the configuration is encrypted to disk. The MC’s SOAR & Ticketing tab doesn’t expose a `readOnly` toggle at all. This is a defense-in-depth measure: even an attacker who bypasses the UI cannot reconfigure ticketing for write access. The integration ships with the contract established and a mock-shape queue-metadata endpoint (`GET /api/integrations/ticketing/queue`). Per-platform adapters (ServiceNow, Jira, TheHive, PagerDuty, Freshservice) are tracked as separate backlog items rather than against a vague future phase — operators with a specific platform need can file an issue against `petermancina/firealive` referencing the adapter contract documented in `docs/integrations-privacy.md`.

**Burnout-signal data feed (push).** The behavioral signals FireAlive shows each analyst are not self-reported and are not guessed at — they are computed from real operational events the ticketing/SOAR platform pushes to FireAlive as they happen. After an analyst acts on a ticket, the platform posts the action to `POST /api/integrations/ticketing/activity-events` (api-key + the `ticketing:events` scope; the same pseudonym-keyed contract the SOAR webhook uses). Each event records one action — `triage`, `comment`, `close`, `escalate`, `dismiss`, or `reassign` — into `ticket_actions`, which is the operational source the four behavioral signals (investigation time, false-positive dismiss rate, ticket-note quality, escalation rate) are computed from. This does not loosen the read-only invariant above: FireAlive never writes back to the ticketing system, and the activity feed never touches the SOAR routing rail (`ticket_assignments`) — it is the platform reporting what already happened, not FireAlive mutating tickets. The feed is mounted ahead of the configuration-lock gate so a machine-to-machine push is never dropped during a config-lock window.

Two operational pressure signals are fed the same way. **Break compliance** comes from the Proactive Breaks loop: each break offered is recorded, and when the analyst answers the break banner the outcome (taken or declined) is posted to `POST /api/proactive-break/outcome` under that analyst's own session — so the rate is the share of offered breaks actually taken over a trailing window, computed fresh at read time. **Shift overtime** is computed from the roster (`analyst_availability`): the sum of the week's scheduled shift durations beyond a full-time threshold (default 40 hours), plus any actual after-hours work — activity that continues past the scheduled shift end, which FireAlive already sees in `ticket_actions`. Because the roster is stored in local wall-clock time while activity timestamps are stored in UTC, a per-Regional-Server `soc_timezone` setting (IANA, default UTC) converts each shift end to UTC for the comparison, handling overnight shifts and daylight-saving transitions.

Privacy holds across the whole feed: events are keyed by pseudonym (resolved to the analyst server-side and never echoed back), the audit trail records the pseudonym and never the note text, and the resulting behavioral signals are sealed to the analyst and de-identified for any team view — management cannot attribute a behavioral metric to a named analyst. The full request/response shape and the enforced invariants are in `docs/integrations-privacy.md` (Contract 4).

### Shift Handoff

**What it’s for:** Structured shift-to-shift handoffs to prevent the information loss that causes errors during transitions. Research shows handoff errors peak in the last two hours of shifts when analysts are most fatigued. This formalizes the handoff so context doesn’t get dropped.

**Workflow:**

1. Outgoing lead at end of shift opens Shift Handoff tab
1. Sees an auto-generated summary (current team health, active routing adjustments, active recovery protocols, open high-priority incidents, staffing notes)
1. Adds free-text context for the incoming lead — what’s in progress, anything unusual
1. Submits handoff (optionally also sends a notification to the incoming lead)
1. Incoming lead opens the same tab at start of their shift, reads the handoff, knows where things stand

### SLA

**What it’s for:** Track Mean Time to Acknowledge (MTTA) and Mean Time to Resolve (MTTR). When SLA performance degrades, FireAlive correlates with team capacity to help the lead distinguish “the team is slow because they’re overloaded” from “the team is slow because they’re undertrained” — different problems, different fixes.

**Workflow:**

1. Lead opens SLA tab
1. Sees current MTTA/MTTR vs targets, broken down by priority level
1. If SLAs are slipping, the dashboard shows whether team capacity is the cause
1. Lead either redistributes tickets (capacity problem) or assigns training (skill problem)

### Automation

**What it’s for:** Where the team lead registers the automated systems that analysts can offload routine, low-level tickets to. This is NOT for monitoring the systems that feed tickets in — it’s the opposite. Analysts in their AC have a Delegate feature where they can identify repetitive ticket patterns (false positives they keep closing, low-level routine work that doesn’t need human judgment) and send those tickets to an automated system. The lead uses this Automation tab to tell FireAlive which automated systems are available for that purpose. The configuration propagates from MC to all connected ACs so analysts know which systems they can delegate to.

This is also the integration point for FireAlive to work alongside other anti-burnout tools. Research has shown that most anti-burnout programs in the industry are built around automating boring, routine tasks. So the Automation tab is also where the lead connects FireAlive to those existing automation programs the org already runs — SOAR’s automated response, dedicated ticket-automation tools, AI triage systems, anything that takes shitjob busywork off the analyst’s plate. Boosting human analyst capacity is the goal; this tab is where that boost gets wired in.

**Workflow:**

1. Lead identifies the automated systems in use across the org (SOAR auto-response actions, dedicated ticket-automation platforms, AI triage systems, other anti-burnout tools)
1. Opens Automation tab in MC
1. Adds each system: name, type, what it can handle, capacity ceiling
1. Configuration propagates to every connected AC
1. Analysts in the AC’s Delegate tab now see the available automation targets
1. When an analyst delegates a ticket pattern, it routes to the appropriate automated system the lead registered

### Fail-Open Routing

**What it’s for:** Like an IPS configured to fail-open: if FireAlive’s burnout routing engine itself fails, the system reverts to the SOAR’s native distribution rather than blocking ticket flow. The SOC keeps defending the network even when FireAlive is down.

**Workflow:**

1. Lead opens Fail-Open Routing tab
1. Configures health check interval (e.g. every 10 seconds)
1. Sets max time in fail-open mode before requiring manual intervention (e.g. 30 minutes — long enough to ride out a glitch, short enough to force escalation if FireAlive is genuinely broken)
1. If routing engine fails health check: tickets revert to SOAR-native routing immediately, lead is notified
1. When FireAlive comes back, routing resumes automatically

### Auto-Disable Routing

**What it’s for:** During a major incident requiring all hands, the lead shouldn’t have to remember to manually disable burnout-aware routing — that would slow them down at the worst time. This feature auto-disables routing when high-severity triggers are detected, so every available analyst gets tickets immediately. Routing restores after the incident is over.

**Workflow:**

1. Lead pre-configures triggers in advance (P1 ticket, SIEM critical alert, SOAR escalation)
1. Sets cooldown — how long after the trigger clears before routing re-enables (e.g. 60 minutes)
1. When an actual incident hits: trigger fires, routing auto-disables, all analysts receive tickets, lead’s dashboard shows banner
1. After cooldown, routing automatically resumes burnout-aware behavior

### Runbook Generator

**What it’s for:** Generate runbooks for incidents and failures involving FireAlive itself — not for general incident response. The org already has runbooks for ransomware, phishing, etc.; FireAlive doesn’t try to replace those. What FireAlive’s adoption introduces is a new attack surface: an MC-AC communication channel, AC clients on every analyst workstation, encrypted Tier-3 data, signal feeds that could be poisoned, peer chat infrastructure. That’s the surface this runbook generator addresses.

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
1. Picks a FireAlive-specific scenario from the dropdown
1. Clicks Generate
1. Sees the multi-step runbook
1. Exports as JSON, PDF, or DOCX, or prints
1. Keeps the printed runbook somewhere accessible during an incident — when systems may be down

This is preparation material. During an actual incident, the team executes from the printed copy.

-----

## Analysts & Wellbeing group — managing the people

### Skills Matrix

**What it’s for:** Aggregate view of where each analyst is on the skill ladder. The lead sees who’s progressing across multiple core skills — useful for spotting promotion candidates and identifying team-wide skill gaps. When an analyst crosses proficiency thresholds across 3+ skills, a “level-up signal” surfaces here as recognition (not as an automatic promotion trigger — the lead decides).

**Workflow:**

1. Lead opens Skills Matrix at the end of the quarter for review
1. Sees each analyst’s current tier, top progressing skills, and any level-up signals
1. For analysts with level-up signals: lead schedules a growth conversation
1. Lead can silence signals they’ve already acknowledged or acted on

### Assessments

**What it’s for:** Targeted skill assessments the team lead creates to verify whether specific analysts can handle specific things. Distinct from the AC-side baseline assessments analysts take when they first start using FireAlive (those populate the gaps display and feed the upskilling training engine, all visible only to the analyst). Lead-created targeted assessments are different: the lead identifies a specific skill the team needs (Kubernetes Security, malware analysis, buffer overflow handling, etc.), creates an assessment alert for that skill, and pushes it to one or more analyst’s ACs.

The actual assessment module is hosted on an external platform — HackTheBox, TryHackMe, LetsDefend, Cyberdefenders, SANS, etc. FireAlive doesn’t host the modules. Instead, the assessment alert sent to the AC tells the analyst where to go to take it. The analyst completes the module on the external platform, then submits a completion report (link, score, date) back into the AC. The result populates the analyst’s gap display and training suggestions in the AC, AND — unlike the AC-side baseline assessments — the lead sees the result. So lead-created targeted assessments serve two purposes: they show the analyst where they stand on a skill, AND they give the lead visibility into who can or can’t handle a specific scenario.

**Workflow:**

1. Lead identifies a skill that’s needed (e.g. “Kubernetes security incident response”)
1. Clicks “+ Create Assessment”
1. Names it for the skill: “Kubernetes Security Skills Assessment”
1. Picks the target tier (Tier 1 / Tier 2 / Tier 3) — assessment skill list filters to tier-appropriate options
1. Selects skills from the taxonomy via checkboxes (or adds custom skills for org-specific topics)
1. Specifies the external module: which platform (TryHackMe, HackTheBox, etc.), which module, the URL
1. Picks which analyst(s) to assign it to (or the whole team)
1. Submits — analyst’s AC shows an Assessment Required notification at the top of the appropriate tab with directions on where to go
1. Analyst goes to the external module, completes it, submits the completion report back through their AC
1. Lead sees results come back, color-coded (green = strong, amber = on threshold, red = gap)
1. Gap areas auto-create training recommendations for that analyst — no further action needed
1. Lead now knows which analysts can handle that scenario, which may inform routing, ticket assignment for related incidents, or upskilling priorities

### Certifications

**What it’s for:** Lead-side view of analysts’ broader industry certifications (CompTIA, ISACA, GIAC, etc.) beyond the platform’s training-linked certs. Used for identifying team-wide gaps and planning upskilling. There’s also an MC-side cert input wizard so the lead can input certs themselves — useful when an analyst hands the lead a physical cert as proof of completion and the lead prefers to record it directly rather than asking the analyst to submit through their AC.

**Workflow (analyst submits, lead verifies — typical):**

1. Analyst registers a cert in their AC (uploads file, enters verification number)
1. Lead opens Certifications tab in MC
1. Sees aggregated view: which certs each analyst has, expirations
1. Verifies new cert submissions, identifies team-wide gaps

**Workflow (lead inputs directly):**

1. Analyst hands the lead a physical certificate of completion
1. Lead opens Certifications tab → “+ Add Cert for Analyst”
1. Picks the analyst, enters cert details, uploads scanned copy
1. Cert is recorded against that analyst’s profile

### Training Reviews

**What it’s for:** Lead-side queue for verifying or rejecting training completions that analysts have self-submitted through the Submit Completion form in their AC. Each row shows the analyst, the platform and module URL they submitted, the timestamp, and the current status. The lead validates that the analyst genuinely completed the training and either credits it (verify) or marks it not credited (reject). Pre-existing certificate uploads with file proof go through the Certifications tab instead — Training Reviews is specifically for lightweight URL-based completion claims tied to modules surfaced by the gap-driven recommender.

**Workflow:**

1. Analyst finishes a training module recommended by FireAlive (or any other module they want to log)
1. Analyst opens their AC’s Training tab and uses the Submit Completion form: platform name, module URL, optional completion date, optional score
1. Submission lands in the pending queue with `status = "pending"`
1. Lead opens Training Reviews tab in MC; navGroup badge shows the pending count
1. Lead filters by Pending (default), Verified, Rejected, or All
1. For each pending row, lead clicks Verify (credits the completion to the analyst’s skill record) or Reject (marks it not credited)
1. Verified and rejected rows are terminal — to reverse, the analyst must resubmit, which creates a new pending row preserving the original audit trail

**State machine and audit:** The server enforces only `pending → verified` and `pending → rejected` transitions; anything else is rejected with 409. Every list view emits a `TRAINING_COMPLETIONS_REVIEW_VIEWED` audit event; every transition emits `TRAINING_COMPLETION_VERIFIED` or `TRAINING_COMPLETION_REJECTED` with the completion ID and the acting user’s ID. See `docs/training-library.md` for the full schema, seed catalog provenance rules, and the recommender flow.

### CISM Retro (Incident Retrospectives)

**What it’s for:** Structured post-incident support based on Critical Incident Stress Management research. After major incidents — ransomware, breaches, active intrusions — analysts experience acute stress comparable to emergency services responders. This module activates a recovery protocol: lighter queues for affected analysts, peer support availability, automated follow-up check-ins at 24hr / 72hr / 2 weeks.

**Workflow:**

1. Major incident wraps up
1. Lead opens CISM Retro tab
1. Clicks “Activate New Recovery Protocol”
1. Enters incident reference, severity, selects which analysts were involved
1. Picks queue reduction duration (this shift / 24hr / 72hr / 1 week)
1. Activates — affected analysts get lighter queues, peer support is enabled in their AC, follow-up check-ins scheduled
1. Lead can mark the protocol complete or send manual follow-ups
1. Participation is voluntary — analysts can decline anything, the lead just makes it available

### Peer Skill-Share Configuration

**What it’s for:** Where the lead configures the peer-to-peer help system between analysts. Sets when peer chat can be used (block during heads-down hours? allow during shift?), session duration limits, and crucially the Helper Pay configuration — analysts who help peers earn points convertible to PTO or cash.

**Workflow:**

1. Lead opens Peer Skill-Share Configuration
1. Configures scheduling restrictions (allow during shift toggle, block hours, max session duration, inactivity timeout)
1. Configures Helper Pay: USD per 100 points, PTO minutes per 100 points, tier multipliers (L3 senior helpers earn more), redemption minimum, approval workflow
1. Reads chat disclaimer — the lead can NOT edit it; this is the analysts’ protected space

### Helper Recognition Leaderboard

**What it’s for:** Top opted-in helpers ranked by Helper Pay points. Lives on the same peersupport tab as the Peer Skill-Share Configuration. The leaderboard is a recognition surface — it shows analysts who have explicitly opted in via their AC’s Helper Pay tab. Analysts who have not opted in are absent from this list regardless of how many points they’ve earned; opt-in is per-analyst and defaults to off.

Points come from 4-5 star peer-session ratings (1-2 star yields zero points, 3 star yields a low amount). A minimum session duration gate and a daily-cap clamp prevent gaming via short or excessive ratings. The Confirm Fraud / Dismiss queue (below) catches sock-puppet abuse beyond what the static gates cover.

**Workflow:**

1. Lead opens peersupport tab
1. Sees the top 10 opted-in helpers by points
1. Per row: pseudonym (or real name if pseudonyms not enabled), sessions count, average rating, points balance
1. Can send an anonymous thank-you to any helper via the Thank button — no name reveal to the helper

### Team Helper Scores (operational view)

**What it’s for:** Full-roster view showing EVERY active analyst’s Helper Pay state, regardless of whether they’ve opted in to the recognition leaderboard. This is the lead’s operational surface for payroll reconciliation, compensation discussions, and quarterly performance reviews. The opt-in indicator on each row is purely informational — only the analyst can flip it from their AC; the lead cannot toggle it on behalf of someone else.

This surface deliberately bypasses the opt-in filter that gates the recognition leaderboard above — Helper Pay involves real money / PTO redemption, and the lead needs complete visibility for those administrative duties. Privacy invariant I5 in the architectural docs.

**Workflow:**

1. Lead opens peersupport tab
1. Scrolls past the recognition leaderboard to Team Helper Scores
1. Sees every active analyst: pseudonym/name, opt-in badge (Visible / Hidden), sessions, avg rating, points balance
1. Uses for payroll, performance reviews, or to spot disengagement signals (analyst with zero points who hasn’t accepted any peer sessions)

### Pending Sock-Puppet Review

**What it’s for:** Lead-side review queue for sock-puppet abuse detection. The detector flags a rating when its rater’s IP hash OR device hash matches 2+ other ratings against the same helper within the last 7 days — a pattern that suggests the same person is faking ratings under multiple accounts to grind points for a helper.

Flagged ratings still grant points at rating time (the helper sees their balance immediately for legitimate ratings), but the flagged contribution is excluded from the recognition leaderboard until lead review. Confirm Fraud triggers a reversal ledger entry that permanently removes the points; the rating row stays flagged forever as audit evidence. Dismiss clears the flag and the points re-appear on the leaderboard. Both decisions are logged via explicit audit_log events.

**Workflow:**

1. Detection runs on each new rating POST — checks IP and device hash clusters against same helper within 7 days
1. If cluster ≥ 3 ratings, the new rating is flagged
1. Lead opens peersupport tab → Pending Sock-Puppet Review Card
1. Per flagged row: rater pseudonym, helper pseudonym, stars given, comment (if any), cluster reason (IP / device / both), flagged timestamp
1. Lead inspects: legitimate small-team usage where 3 analysts genuinely rated the same helper from one office network? Confirm Fraud (real sock-puppet) or Dismiss (false positive)
1. Confirm path: reverses the points via the existing fraud reversal flow; audit event LEADERBOARD_SOCKPUPPET_CONFIRMED
1. Dismiss path: clears the flag, points restored to leaderboard; audit event LEADERBOARD_SOCKPUPPET_DISMISSED

### Pseudonyms

**What it’s for:** The architectural privacy commitment: every analyst gets a permanent UUID and rotating pseudonym (Analyst-Falcon, Analyst-Kestrel, etc.). All burnout metrics, peer chat messages, reduced-routing requests, and wellness signals are stored against the pseudonym — never the real name. If the database is breached, attackers see “Analyst-Falcon is in elevated burnout” rather than a real person. The mapping (UUID → pseudonym → real name) is exported as an encrypted file the lead stores offline.

**Workflow:**

1. Lead opens Pseudonyms tab on initial setup
1. System generates pseudonyms for each analyst from a stable list (animals, etc.)
1. Lead exports the mapping as an encrypted file — stores it on a USB key in the safe, NOT on the network
1. Periodically rotates pseudonyms (quarterly, after offboarding events) — UUIDs stay the same so historical data is preserved
1. When the lead needs to know which real person Analyst-Falcon is (e.g. for a CISM retro), they look up the offline mapping

### IR Simulator (lead-side, ooda_mgmt)

**What it’s for:** The lead uploads their organization’s IR policies, playbooks, and after-action reports here. The system parses each policy and generates OODA-loop training scenarios that analysts then practice in their AC. The point: analysts train on **their own org’s procedures**, not generic textbook procedures. A new analyst joining shouldn’t have to figure out “how does THIS team handle phishing” through trial-by-fire — they should practice it in the simulator first.

**Workflow:**

1. Lead opens IR Simulator (Policy Management) tab
1. Uploads the org’s ransomware response playbook (text or file)
1. Names it, tags type (incident_response / playbook / runbook / policy / procedure)
1. Saves — system parses the policy and generates one or more OODA scenarios from it
1. Lead can also pick a scenario type (ransomware, phishing, data_exfil, insider_threat, apt, ddos, supply_chain, credential_compromise) and have the system generate a scenario from that policy targeted at that scenario type
1. Repeats for each major IR policy the org has
1. Now analysts in their AC can practice these scenarios. After completion, the analyst sees the actual policy that was used to generate the scenario.

### Proactive Breaks

**What it’s for:** Based on Sonnentag’s recovery research: prolonged high-severity ticket work without breaks accelerates burnout exponentially. This feature monitors workload patterns and suggests breaks BEFORE burnout signals appear — preventive rather than reactive. The lead approves the suggestion before it goes to the analyst (so analysts aren’t being told what to do by the system without lead oversight).

**Workflow:**

1. Lead configures: “After N hours of continuous high-severity work, suggest a break of M minutes”
1. Toggles “Require Team Lead approval before sending”
1. Analyst hits the threshold — system pings the lead
1. Lead reviews (“yes this analyst should take a break”) and approves
1. Analyst gets an affirming notification: “You’ve been working hard. Consider a 15-minute break.”
1. Analyst can take the break or continue — their choice

### Upskilling Hour

**What it’s for:** Dedicate one hour per shift to professional development. During that hour, the analyst’s queue is paused — they can study, peer skill-share, do training, work on certifications. The research is unambiguous: companies that fund on-the-clock development have lower turnover than companies that demand analysts upskill on their own time.

**Workflow:**

1. Lead opens Upskilling Hour tab
1. Configures: “1 hour during the 8th hour of shift” (so it’s at the end, but configurable)
1. Sets minimum coverage requirement (e.g. “75% of team must be on-shift” — so the whole team isn’t simultaneously upskilling)
1. Assigns each analyst to a slot (different times so coverage stays adequate)
1. Optionally integrates with HR scheduling system (UKG/Workday/ADP)
1. During an analyst’s slot, their AC pauses ticket routing and shows training resources / peer chat options

### Offboarding

**What it’s for:** Securely deprovision analysts who leave or change roles. Their historical aggregate data stays for team metrics, but personally identifiable links are severed. All keys/sessions/peer-chat schedules are revoked. Integrates with IAM (so when HR offboards in the IdP, FireAlive picks it up) and SOAR (so offboarding orchestration is automatic).

**Workflow:**

1. Either: lead manually offboards (picks analyst, reason: voluntary departure / termination / role change / transfer)
1. Or: IAM offboarding detector runs on schedule (every 4hr / 8hr / daily / weekly), checks the IdP for users no longer present, surfaces them for the lead to confirm
1. Lead confirms either “still active” (resets the recertification timer) or “offboard”
1. On offboard: account marked inactive, sessions revoked, pseudonym removed from rotation, historical aggregate data preserved under the UUID

### Sync Interval

**What it’s for:** Control how often each analyst client refreshes its own view of its burnout signals. Analyst clients do not send burnout metrics to the server — the signals are computed server-side from the operational activity the ticketing/SOAR platform pushes in, sealed to each analyst, and every client only retrieves and decrypts its own sealed view. This setting governs that retrieval cadence: a longer interval is gentler on a bandwidth-constrained deployment, a shorter one shows fresher signals. Adaptive mode refreshes more often while an incident is active and relaxes when things are stable.

**Workflow:**

1. Lead opens Sync Interval tab once during setup
1. Sets the base refresh interval
1. Toggles adaptive mode (recommended — refreshes more often during incidents)
1. Sets the urgent event threshold — for panic events / critical incidents, refresh immediately rather than wait for the next interval
1. Saves — applies to all connected analyst clients

**How it reaches the client:** the cadence is pushed to each analyst client over the authenticated WebSocket — once when the client connects, and again whenever the lead saves a change — so a connected client adopts a new interval live without a restart. Between ticks the client re-pulls and re-decrypts only its own sealed signals. The urgent-event threshold is honoured server-side too: engaging panic mode or an alert-router critical broadcasts an immediate refresh to every connected analyst client, so the heightened state surfaces on-device at once rather than at the next interval.

### Client Notifications

**What it’s for:** Configure how each user (lead and analyst) receives notifications from FireAlive. Per notification type, each user chooses delivery: email, SMS, desktop notification, in-app inbox, multiple, or off. The inbox is one channel option among many — for users who want a place to find missed notifications. It’s not mandatory.

**Workflow:**

1. Each user (lead AND analyst) opens their notification preferences
1. Per notification type (assessment assigned, retro scheduled, peer request, panic broadcast, helper points awarded, etc.) chooses delivery: in-app inbox / email / SMS / desktop notification / multiple / off
1. Notifications fire through the channels they chose — never through ones they didn’t
1. The inbox is one channel option — for users who want a place to find missed notifications

-----

## Integrations group — connecting to the rest of the SOC stack

### Integration health (moved to System Health)

**What it’s for:** Live integration health is no longer a separate dashboard — it now lives on the single **System Health** surface in the Monitoring group, side by side with configuration state. See **System Health** below. Each integration is still configured in its own tab within this group (SIEM, EDR, Threat Hunting, and so on).

### SIEM Integration

**What it’s for:** Push FireAlive’s metrics to the org’s SIEM in CEF format so SOC management tooling has visibility into FireAlive’s own health. Optionally: restrict the burnout metrics widget to the lead’s SIEM dashboard only — protect team morale from analysts seeing aggregate burnout numbers that could feel demoralizing.

**Workflow:**

1. Lead configures SIEM endpoint
1. Toggles which metrics get pushed (system health, security events, burnout aggregates with visibility scope)
1. SIEM ingests the CEF stream
1. SIEM dashboards now show FireAlive-specific health alongside everything else the SOC monitors

### EDR File Inspection

**What it’s for:** Every file uploaded to FireAlive (config restores, IR policy uploads, IaC imports, app updates) gets scanned by the org’s EDR before being processed. Prevents a malicious file from reaching FireAlive’s internals through the upload path.

**Workflow:**

1. Lead configures EDR provider in this tab
1. Whenever someone uploads a file anywhere in FireAlive: system pauses, calls EDR scanner with file
1. Scanner returns clean → upload proceeds
1. Scanner returns malicious → upload rejected, lead notified, audit log entry

### Threat Hunting Integrations

**What it’s for:** Authorize your organization’s threat-hunting tools — XDR, ATP, Next-Gen AV, and MSP scanners — to pull FireAlive’s own operational security telemetry as a read-only feed they can correlate in their own consoles. This is the inbound counterpart to the SIEM/SOAR integrations (which push events out): here approved tooling connects in and pulls a curated slice — authentication events, sessions, the audit trail, and client-integrity findings — plus an actor-free summary of activity counts and compromise indicators. FireAlive is the monitored asset and never dials out; it serves only what a consumer is authorized to pull, and logs every pull. The per-category policy in this tab governs which consumer classes are allowed; each individual consumer is then authorized below.

The feed is pseudonymous by construction and carries no burnout, wellbeing, or Tier-3 data — those signals have no path into it. Every request passes a three-factor gate that fails closed on each factor: a mutual-TLS client certificate issued by FireAlive’s internal CA, a bearer token (shown once at creation, then stored only as a salted hash), and a source-IP allow-list. Consumer types are a fixed set (XDR, ATP, Next-Gen AV, MSP) — there is no open-ended custom type. Each consumer pulls in its preferred dialect: native JSON, CEF, OCSF, or STIX 2.1 over a TAXII 2.1 server. Every pull — authorized or rejected — is written to an append-only, hash-chained access log whose integrity can be verified from the console at any time, and the feed carries its own dedicated rate limit.

FireAlive performs application-layer authorization and logging. Network-layer blocking of unauthorized hosts remains your firewall / security-group responsibility — the source-IP allow-list is a second check, not a substitute for it. The feature runs on the Regional Server only.

**Workflow:**

1. An administrator opens Threat Hunting, enables the consumer class in the per-category policy, and selects “Authorize Consumer”
1. Picks the consumer type, names it, sets the source-IP allow-list, and chooses a default output format
1. FireAlive issues the credentials once — a bearer token plus the client certificate, private key, and CA certificate; copy them into the consumer now, as the token and key cannot be retrieved again
1. The consumer connects over mutual TLS from an allow-listed IP, presents its token, and pulls from the native feed or the TAXII server in its chosen format
1. FireAlive authorizes (or rejects) each pull and records it in the access log; the pulled telemetry is correlated in the consumer’s own console
1. The administrator reviews the access log, verifies its integrity (chain check), and can disable or revoke an authorization at any time — revoking immediately invalidates that consumer’s token and revokes its certificate

### Client Provisioning

**What it’s for:** Analysts never install the AC themselves — the lead provisions clients via enterprise deployment tooling. Prevents rogue installs and ensures every AC starts with the right config (server endpoint, enrollment token).

**Workflow:**

1. Lead opens Client Provisioning tab
1. Configures deployment tool (Intune / Jamf / SCCM / Workspace ONE / Ansible)
1. Per analyst: enters name, tier, shift, target hostname, IP
1. Clicks “Provision Client” — system generates a config.json + enrollment token, packages it for the deployment tool
1. Deployment tool pushes the AC to the analyst’s machine
1. Analyst opens the AC, trusts the FireAlive CA, redeems the one-time enrollment token to enroll a hardware passkey, signs in, and baseline calibration begins (a transport certificate may also be installed)

### Internal AI

**What it’s for:** FireAlive’s internal AI. Generative features — IR Simulator scenario generation, burnout intervention messages, the troubleshooter, and KB assistance — run on a local LLM bundled with the platform; burnout prediction and signal analysis use statistical/rule-based engines. All inference runs on the host, and there is no external-provider option.

**Workflow:**

1. The operator provisions and verifies the local model files (see below)
1. Generative features use the internal model automatically; a lead can tune per-feature generation (max tokens, temperature) on the Internal AI tab

**Local AI model provisioning (verify-only):** FireAlive never downloads AI models. The operator obtains the official files through their own vetted channel and places them in the model directory; FireAlive computes each file’s SHA-256, compares it to a hash **pinned in source**, and loads the model only on an exact match — refusing with an honest “unavailable” on any missing or mismatched file. No outbound model fetch ever occurs, and operators never supply hashes at runtime (rotating a model is a reviewed source change).

**Model-file integrity & safety gate (before load, fail-closed):** Hash-pinning proves a file is *the* official artifact, but the loader (node-llama-cpp / llama.cpp) parses the GGUF with a **native parser** (in an isolated worker process — see “Loader isolation” below), so FireAlive runs a layered gate over every model file before the loader reads it — on both the server and the Analyst Client. The layers run in order and short-circuit on the first failure:

1. **Hash-pin (primary).** Each file’s SHA-256 is checked against the source-pinned value. A missing or mismatched file blocks the load.
1. **Signature / provenance (optional, server).** If the operator configures a model-signing public key (`MODEL_SIGNING_PUBLIC_KEY` or `MODEL_SIGNING_PUBLIC_KEY_FILE`), a detached signature over the pinned digest is verified; a present-but-invalid signature blocks even when signing isn’t required. With no key configured this layer is skipped and never weakens the hash-pin.
1. **GGUF format validation.** The header is sanity-checked (magic, version, tensor/metadata counts within plausible bounds, and a bounded key/value walk) before the native parser sees it, to defang a malformed-file parser exploit — the highest-value layer given the in-process loader. A malformed header blocks the load.
1. **Malware scan (defense-in-depth).** The file is scanned **by path** using the host’s own local engine (clamdscan → clamscan → Microsoft Defender on Windows); nothing is uploaded anywhere. A detected threat, a scan error, **or no available scanner** all block the load (fail-closed).

The model loads only if every file clears every applicable layer. The gate runs once per file-set change (cached by content) rather than on every load. Server-side, each file’s per-layer verdict is recorded to an append-only `model_file_scan_log` for audit; the Analyst Client runs the same hash → format → malware gate **entirely on-device** and shows the verdict in the KB Assistant panel. Any block surfaces as an honest “unavailable” naming the failing layer — never a silent fallback.

**Why a scanner is required, stated honestly:** a backdoored-but-well-formed weights file is *not* something any of these layers can detect — hash-pinning to a vetted source is the real defense there. The malware scan catches a *swapped* file (known-malicious content), the format validator catches a *malformed* file (parser exploit), and the hash-pin catches *any* deviation from the vetted artifact. The gate is layered precisely because no single layer is sufficient on its own.

**Loader isolation & privilege hardening:** the model loader (node-llama-cpp) parses the GGUF and runs inference in a **separate, isolated process** — a forked child on the server, an Electron utilityProcess on the Analyst Client — not in the main process. A loader or parser exploit is therefore contained in a disposable worker that the host respawns, rather than running with the main process’s reach; the gate above remains the primary control and this isolation is defence-in-depth for the residual risk. The server additionally refuses to load a model as **root** in production (set `FIREALIVE_ALLOW_ROOT_MODEL_LOAD=1` only if a constrained environment genuinely requires it), and per-request timeouts plus a restart circuit keep a wedged or crash-looping worker from degrading the service. Recommended deployment confinement — non-root user, read-only model mount, dropped Linux capabilities, a seccomp/AppArmor profile, resource limits, and no network egress from the inference service — is documented in `docs/model-loader-isolation.md`; running the worker under a separate lower-privileged identity (a sidecar container, or an in-process privilege drop) is the remaining hardening step.

- **Chat model** (heavyweight; powers the server-side lead chat, burnout messages, IR simulator, and troubleshooter, and the Analyst Client’s on-device chat): **Phi-4, Q4_K** (MIT), a single official GGUF.
  - Official source: Hugging Face `microsoft/phi-4-gguf` (pinned commit `18ece485b98ae22388ffad82ad468cc2d774f6d4`).
  - Pinned SHA-256:
    - `phi-4-Q4_K.gguf` (9.05 GB) — `5652b9be0ea4ae2842130d04fe31bc869fcb99a2b7106c53b4e754a343fd688f`
  - Endpoint floor: ~9.05 GB free disk + ~10–12 GB RAM. Under-spec / thin-VDI endpoints honestly report the local chat as unavailable rather than degrading silently.
- **Embedder** (KB retrieval, server-side and on-device): **Nomic Embed Text v1.5, F16** (Apache-2.0, 768-dim), single file.
  - Official source: Hugging Face `nomic-ai/nomic-embed-text-v1.5-GGUF` (pinned commit `18d1044f4866e224159fce8c6fc5c4f3920176e7`).
  - Pinned SHA-256: `nomic-embed-text-v1.5.f16.gguf` (274 MB) — `f7af6f66802f4df86eda10fe9bbcfc75c39562bed48ef6ace719a251cf1c2fdb`
  - Endpoint floor: ~274 MB free disk.

Target directory: the server model root (default `~/.firealive/models`, override `FIREALIVE_MODEL_PATH`) and, on the Analyst Client, the AC model root (default `~/.firealive/ac-models`, override `FIREALIVE_AC_MODEL_PATH`). Both the MC **Internal AI** tab and the AC **KB Assistant** surface a “Show provisioning guide” / “Verify provisioned files” action that displays the official source, target directory, and these pinned hashes, and verifies on demand.

**Other deployment hardening:**

- **Self-hosted fonts.** The Content-Security-Policy allows styles and fonts from `'self'` only (no `fonts.googleapis.com` / `fonts.gstatic.com`). Self-host any web fonts you want to use; otherwise the platform falls back to the system font stack.
- **Pinned CI/CD supply-chain tools.** Generated pipelines pin Syft v1.44.0, Grype v0.110.0 (CVE scan), and Cosign v3.0.6, installed from immutable release tags — no `main` / `@master` / `:latest`. See the CI/CD section.

-----

## Security group

### IAM

**What it’s for:** Manage how people sign in — and they sign in **passwordlessly** with a **hardware FIDO2/WebAuthn passkey** (a security key with a PIN). A passkey is accepted only if its attestation chains to a trusted vendor root, it is non-syncable, and it is user-verified — so there is no password, no SAML/OIDC browser redirect, and no TOTP. FireAlive also issues per-analyst **client certificates** from a built-in Certificate Authority, but a certificate is **transport identity (mutual TLS), not a sign-in method**. LDAP/AD is connected as a **directory source only** — group membership and presence for the offboarding detector — never as a login method. The IAM panel manages the built-in CA (issued certificates, revocation, the signed CRL), the **hardware-key trust anchors** (attestation roots and the model allow-list), the LDAP/AD directory connection, and offboarding candidates. See `docs/iam-and-authentication.md`.

**Workflow:**

1. Lead opens IAM tab on initial setup
1. Reviews the built-in CA (or points FireAlive at the org’s own CA in relying-party mode)
1. Optionally connects LDAP/AD over LDAPS as the directory / offboarding source (bind + test)
1. Provisions analysts (which mints a one-time enrollment token); each analyst enrolls a hardware passkey and signs in — no password (a transport certificate may also be issued)

### My Security (passkeys & certificates)

**What it’s for:** Self-service management of your own phishing-resistant credentials. Sign-in is a user-verified **hardware passkey** — already strong, single-step MFA — so there is no separate TOTP prompt. Each person can enroll and remove their own passkeys and view or revoke their own **transport** certificates; the system refuses to remove your last working passkey. Consequential actions (the configuration lock, two-person restore approvals) require a fresh WebAuthn step-up assertion at the moment of the action.

**Workflow:**

1. Open the My Security section
1. Add a passkey (the authenticator creates it; it is verified server-side) or review your issued certificates
1. Remove a passkey you no longer use, or revoke a certificate that may be compromised
1. If you are ever locked out with no working credential, recovery is the audited one-time break-glass credential

### API Keys

**What it’s for:** Programmatic access to FireAlive for SOAR/SIEM integrations. Each key is role-scoped — least privilege. A key for “team health metrics streaming to SIEM” doesn’t get access to anything else.

**Workflow:**

1. Lead opens API Keys
1. Clicks “+ New Key”
1. Names it (“splunk-cef-stream”), picks scope (“read team health”), sets expiry
1. Receives the key, copies it into the SOAR/SIEM config
1. Periodically reviews key usage (last used timestamps), revokes any that are unused or compromised

### Access Control

**What it’s for:** Align FireAlive with the org’s overall access control model — RBAC (Role-Based), MAC (Mandatory), DAC (Discretionary), ABAC (Attribute-Based). Different access models change how FireAlive should behave internally for things like permission inheritance, role-to-action mapping, attribute evaluation, and policy enforcement order. The lead picks the model their org uses; FireAlive adapts its internal enforcement to fit.

This feature also handles concurrent session limits, session timeouts, and per-action WebAuthn step-up requirements.

**Workflow:**

1. Lead opens Access Control during setup
1. Picks the org’s access control model (RBAC / MAC / DAC / ABAC)
1. Sets max concurrent sessions per user, session timeout
1. Picks any access pattern presets (e.g. “Zero-Trust Strict”, “Standard Enterprise”, “Pilot Phase Permissive”)
1. FireAlive’s internal session enforcement and authorization logic adjusts to match the chosen model

### Auth Logs

**What it’s for:** Track every authentication attempt — successful and failed — for both MC and AC. Useful for spotting unauthorized-access attempts, such as repeated failed passkey assertions or attempts with a revoked or expired certificate.

**Workflow:**

1. Lead opens Auth Logs to investigate a suspicious activity report
1. Filters by user, IP, time range
1. Sees pattern (e.g. 50 failed logins from one IP in 2 minutes)
1. Lead configures brute-force threshold for automatic detection
1. Future attempts crossing threshold trigger automatic lockout + alert

### KMS (Enterprise Key Management)

**What it’s for:** Centralize FireAlive’s encryption key lifecycle in the org’s enterprise KMS — AWS KMS, Azure Key Vault, HashiCorp Vault, Thales, Entrust. All encryption tiers (Tier-3 analyst data, Tier-1 team data, peer chat E2EE, backups, audit log signing) get their keys managed through KMS with HSM backing and automated rotation.

**Workflow:**

1. Lead opens KMS tab on initial setup or when migrating from default keys
1. Picks KMS provider, enters endpoint/ARN, key ID/alias
1. Configures rotation policy
1. FireAlive switches from default-key mode to KMS-backed mode
1. From now on, every encryption operation uses keys from KMS

### WiFi Policy

**What it’s for:** Enforce minimum WiFi security on analyst clients. WPA2-Personal (PSK) is vulnerable to brute force; WPA2-Enterprise with 802.1X/EAP is the SOC minimum. The AC checks the local WiFi before connecting and blocks if non-compliant.

**Workflow:**

1. Lead opens WiFi Policy
1. Sets minimum protocol (WPA2-Enterprise default, WPA3-Enterprise stricter)
1. AC enforcement: when an analyst’s machine joins a non-compliant WiFi (e.g. coffee shop with WPA2-Personal), the AC won’t connect to the FireAlive server until they switch to a compliant network

### Posture Assessment

**What it’s for:** Like 802.1X NAC and MDM posture checks: at app startup the AC verifies the workstation meets minimum security posture (TLS version, OS patch level, EDR running, etc.) before connecting to the management console. Non-compliant devices are warned or blocked until remediated.

**Workflow:**

1. Lead opens Posture Assessment, configures checks
1. Sets minimum TLS version, grace period before blocking
1. AC enforcement: on every connection (or first launch only), runs posture check, reports compliance to MC, blocks if failed

### Tripwire

**What it’s for:** Detection for a specific attack — compromised analyst clients weaponizing FireAlive’s legitimate reduced-routing mechanism to throttle SOC response capacity. Rather than a static percentage, the detector weighs six signals and trips on the *attack signature* — synchronized, workload-unjustified, uniform load reduction — not on genuine team stress. On a trip it fails routing open, launches a signed compromise scan, alerts, and holds an investigation lockout until the fleet is confirmed clean. Verdicts are team/segment-level only — no per-analyst identity, no burnout data.

**The six signals** (each yields a strength in [0,1], combined as a weighted sum against a configurable trip score; evaluated globally and per tier/shift):

1. **Velocity** — how many analysts entered reduced routing inside the window (synchronization).
1. **Breadth** — share of the segment currently in reduced routing versus the threshold.
1. **Slope** — acceleration of entries versus the prior window.
1. **Signal-justification (linchpin, weighted x2)** — cross-checks each reduction against the server’s *independent* workload record (recent ticket actions and open assignments). Reduced-but-idle implies an injected reduction rather than an earned one. This is what separates a genuine burnout wave (busy, justified) from an attack; a lone idle analyst is damped, a coordinated idle cohort reaches full strength.
1. **Uniformity** — low variance of capacity values or entry timing across the reduced cohort (scripted/replayed).
1. **Corroboration** — co-occurring security events in the audit log lower the trip bar.

**Workflow:**

1. Admin configures the breadth threshold, reduced-capacity threshold, trip score, window, and which response actions fire. Small teams fall back to a degraded mode that leans on velocity, the justification linchpin, and corroboration.
1. Normal operation: a genuinely stressed team shows high breadth but *justified* (busy) reductions with varied capacities — the score stays low, no trip.
1. Attack: a synchronized cohort drops into reduced routing while their independent workload stays idle, with uniform capacities or replayed timing — the weighted sum crosses the trip score (or a single extreme signal trips immediately).
1. Response, each independently toggleable: routing fails open (reduced-load overrides are deactivated — burnout-derived `capacity_score` is never altered), a signed compromise scan is auto-launched across all clients, a critical alert routes through SOAR / notification / SIEM, and an investigation lockout is held.
1. The lead can run the detector read-only (“Run Detector Now”) to see the live verdict and per-signal strengths without firing any response.
1. Resolving the lockout is gated on a clean scan — the linked scan must have no failed or unverified results and all reachable clients must have reported clean. An admin may force-resolve after out-of-band investigation; the resolving user is recorded on the event.

### Instance Identity & Anti-Cloning

**What it’s for:** Every FireAlive deployment carries a single, hardware-rooted instance identity — an anchor key sealed to the host’s TPM 2.0 (Linux and Windows) or Secure Enclave (macOS) that never leaves the hardware and will not unseal on a different machine. That anchor underpins the deployment’s certificate authority, its server certificates, every analyst-client device registration, and enrollment. It is fail-closed: with no hardware root of trust the deployment refuses to start rather than dropping to a software key — there is no software path to downgrade to, in production, CI, or dev alike. The result is that a copied disk or VM image cannot reconstitute a working deployment on different hardware. Beyond the identity anchor, every field sealed at rest — the CA private key, the signing keys, integration credentials — is cryptographically bound to its own table and column, so an attacker with write access to the database file but no key cannot move a revoked key’s ciphertext into the active row or a test integration’s credentials into production: a sealed value refuses to open anywhere but where it was written.

**What catches a clone:**

- **The sealed anchor** — a copied deployment cannot unseal the anchor key off its original hardware, so it cannot act as the instance.
- **Per-connect server attestation** — each analyst client pins the authentic server’s anchor fingerprint at enrollment and, on every connect, challenges the server to sign a nonce with the anchor key; a clone cannot produce that signature on different hardware, so the client refuses it with no Global Dashboard involvement. On the *first* connection the pin is not silent: the server prints its anchor fingerprint at startup, the client shows the same fingerprint, and the operator confirms the two match out of band before trust is pinned — so a clone substituted at first contact is caught by a human check, not only by the later signature challenge.
- **Hardware-bound client device keys plus an anti-rollback ratchet** — analyst-client device keys are hardware-bound and carry a monotonic ratchet counter, so a copied or rolled-back key is rejected.
- **Sender-constrained sessions** — a signed-in session token is bound to the operator’s hardware device key (the key’s RFC 7638 thumbprint is carried inside the token), and every request must also carry a fresh, single-use proof signed by that key. A token copied off the machine is useless: without the hardware key it cannot produce the per-request proof, so a stolen or replayed token is refused.
- **Duplication and rollback verdicts** — the instance observer records ok / fork / clone / rollback verdicts, so two copies running at once, or a snapshot rollback, are caught independently of the hardware seal.
- **Bounded compromised-MC blast radius** — privileged Management Console actions are bound to the MC’s own hardware device key, and destructive recovery (teardown / reprovision) requires dual control plus a burst limit, so a compromised console cannot quietly rebind the fleet.

**See also:** Compromise Scan and Per-Client Recovery (System Health) are the operator surfaces; the full model and the bare-metal-versus-virtualized differences are documented in `docs/anti-cloning-and-virtualization.md`.

### Compromise Scan

**What it’s for:** Orchestrate the analyst-client self-scan across connected clients. Each AC runs ten integrity checks in its isolated Electron main process — binary integrity (against a signed release manifest), memory analysis, network connections, configuration drift, audit-log continuity, EDR/XDR status, API token scope, TLS pinning, filesystem integrity, encryption keys — and returns a report signed by a per-device Ed25519 key the server verifies. Results are tri-state (pass / inconclusive / fail) and never faked: a check that can’t be determined returns inconclusive rather than a false pass. Reports use pseudonyms and carry NO burnout data — only system-health metrics. Use after a tripwire event or any time client compromise is suspected.

**Workflow:**

1. Lead opens Compromise Scan and picks a target — all active analysts, or one analyst.
1. The server creates a run, dispatches the scan command to connected clients over the authenticated WebSocket channel, and queues offline clients for delivery on reconnect within a 15-minute window.
1. Each client runs its ten checks and returns a signed report. The server verifies the device signature before storing; reports that fail verification are flagged UNVERIFIED (a tampering or key-mismatch signal) and are never counted as clean.
1. The lead sees live per-client results — tri-state status, passed/inconclusive counts, a signature-verified or unverified indicator, and which clients are still offline-queued or had their delivery window expire.
1. Failed or unverified clients route through the alert router (failed → critical, unverified → high) so SOAR / SIEM / notification fire; the lead investigates, may rotate the pseudonym, reprovision, or escalate.
1. Result retention is admin-configurable (indefinite by default, or 1–3650 days); run history is kept for review.

**Note — scanning the Global Dashboard:** this surface scans *analyst clients*. The GD inspecting *itself* for compromise is the GD’s own self-scan, shipped in B6a (its Compromise Scan tab runs eleven read-only self-integrity checks of the GD server — see the Global Dashboard section); the MC still does not reach into or scan the GD.

**See also — Per-Client Recovery:** when a scan (or a tripwire trip) confirms a compromised client, the recovery workflow lives under System Health → Per-Client Recovery & Fleet Operations: tear the client down (revoke its certificates, retire its device key, delete its passkey) and issue a one-time re-provision token. The analyst's sealed wellbeing data is preserved and restored on the rebuilt client.

### Log Integrity

**What it’s for:** The audit log is tamper-evident, not merely append-only. Three independent legs back that claim: (1) a per-row SHA-256 hash chain — each entry’s hash covers its content plus the previous entry’s hash, so any edit, reorder, or deletion breaks the chain; (2) Ed25519-signed checkpoints that periodically notarize the chain head — an attacker who edits a row and recomputes every downstream hash still cannot forge a signed head; and (3) the existing SIEM/SOAR ship-out, which anchors a copy of each event outside the database. Deletion is also blocked at the database level (triggers reject UPDATE/DELETE on the table). This tab verifies all of that and reports the result.

**Honest scope:** Tamper-evident **from baseline establishment at deployment**. The baseline migration chains and notarizes the rows present at upgrade without altering them; it does not retroactively prove the integrity of anything that happened before the chain existed. From the baseline forward, edits, deletions, gaps, and head-forgery attempts are all detectable.

**Workflow:**

1. Lead opens this tab; it auto-verifies once and shows status — intact (with entries verified and the latest signed checkpoint), or a break with its reason and row id.
1. **Verify Now** re-runs the full check (recompute every row + prev_hash linkage + signed-checkpoint validation) and advances the checkpoint when intact.
1. A background check also runs hourly: on any break it raises a critical alert (the MC routes it through the alert router to SIEM/SOAR/notification; the GD records a critical audit event), and a separate gap check flags missing rows or offline windows.
1. On a break, the lead investigates whether it’s a partition (system was offline) or tampering, using the reason, the broken row id, and the SIEM copy as the external cross-check.

The Global Dashboard carries the same hash-chain + signed-checkpoint integrity on its own audit log, verifiable from its Audit & Forensics tab.

### Regression Test

**What it’s for:** Run an automated test suite verifying every integration and control still functions after an update. Before deploying a new FireAlive version, the lead runs regression to catch broken integrations, missing connections, or deprecated features.

**Workflow:**

1. After applying an update or making major config changes
1. Lead opens Regression Test, clicks Run
1. Server runs the canonical regression-runner via `POST /api/regression/run` (admin-gated; replaces an earlier setTimeout-based client-side fake). The MC suite is 70 checks across 13 categories on a freshly bootstrapped install (rising by one per probed integration once integration-health probing has run): schema + foreign-key integrity, an in-memory schema-clone harness, passwordless auth checks (JWT session round-trip, a CA issue/verify/revoke/CRL round-trip, break-glass recovery, WebAuthn + step-up wiring, and passwordless-only enforcement), AES-256-GCM / SHA-256 / Ed25519 / NaCl-box crypto round-trips, peer skill-share E2E envelope round-trip, GD-push Ed25519 signing + fingerprint, KMS / key-wrapping round-trips, helper-pay points-ledger invariant, routing, burnout-signal plumbing, backups v2-aware schema, anti-rollback fuse counter, the audit-log hash-chain recompute + Ed25519 signed-checkpoint verification, the cloud / cicd / full-suite signing infrastructure, AI-dispatcher graceful-fail (IR-simulator wiring), model-file-safety fail-closed, external-integration reachability, integration health, and the compromise-scan + reduced-routing-tripwire surface (the five B4 tables, the device-key partial-unique index, the detector verdict, the scheduler API, both routes, and the seeded tripwire / retention controls).
1. **Zero production side effects (by design).** Verifiable controls are read-only on the live database; write-path “flow” checks run against an in-memory SQLite clone of the live schema; crypto and E2E checks use throwaway keys held only in memory; the AI and scanner checks exercise plumbing and fail-closed behavior only (no real inference or scan).
1. **Three statuses — pass / fail / skip.** A skip never counts as a failure. Two checks are forward-dependent: they skip until the phase that backs them ships, then auto-activate. The `audit_log` hash-chain linkage check skips until the hash columns land (B5a — Audit Hash Chain); the IAM offboarding-detector check skips until the scheduled IdP detector populates `last_iam_check` (B5b — IAM Real IdP Integration). The columns and wiring they assert are verified now even while the deeper assertion is deferred. The `integrations` category applies the same trichotomy to optional external integrations — SOAR, SIEM, ticketing, LDAP/AD, and backup storage each pass when configured and reachable, fail when configured but broken, and skip when not configured — while EDR / malware-scanner coverage is treated as required and fails when absent. The `integration_health` category reflects the most recent cached integration-health probe without running any live probe: a healthy probe passes, a benign state (disabled / not configured / not implemented) skips, and a real probe failure (unreachable / auth failed / permission denied / timeout / error) fails; with no cached probe it records a single skip.
1. The Global Dashboard runs its own CISO-gated suite (60 checks across 18 categories) via `POST /api/regression-test`, covering GD schema + FK integrity, AES-256-GCM / SHA-256 / Ed25519 crypto round-trips, passwordless auth checks (JWT session round-trip, a CA issue/verify/revoke/CRL round-trip, break-glass recovery, WebAuthn wiring, and passwordless-only enforcement), MC-trust signing-key coverage, cross-region rollup, compliance tables, backups, export-at-rest, app-update detection, the audit-chain hash-chain recompute + signed-checkpoint checks, integrations + integration-health checks, and — added in B6a — the GD’s own runtime-monitor, alert-routing, config-lock, and self-protection categories, plus in B6b the storage-routing, data-residency, and backup-strategy categories. The GD’s SOAR / SIEM and integration-health checks were previously forward-aware and now activate: B6a shipped the GD’s own runtime-monitoring and integration surface (see `docs/runtime-monitoring-and-system-health.md`), so the runtime-monitor provides the host-monitoring baseline and an external EDR is an additive seam rather than a required-fail. The AI, model-safety, peer, helper-pay, and IAM checks are intentionally not ported — those subsystems do not run on the GD.
1. Pass / fail / skip report — the lead investigates failures. Each run writes a `REGRESSION_RUN` entry to `audit_log` (with pass / fail / skip counts); a runner-level error is recorded as `REGRESSION_RUN_FAILED` for post-hoc analysis.

### TTX Generator

**What it’s for:** Generate Tabletop Exercise (TTX) documents — a Situation Manual (SitMan) for the facilitator to bring to a tabletop meeting, plus a blank After-Action Report (AAR) template for the team to fill in afterwards. Curated scenario library (ransomware, data exfiltration, credential compromise via vishing, cloud account compromise) at three difficulty levels. Output formats: PDF (printable, archival) and DOCX (editable). Each generation is logged as compliance evidence.

**Workflow:**

1. Lead schedules a tabletop exercise
1. Opens TTX Generator, picks scenario, difficulty (easy/intermediate/hard), format (PDF/DOCX)
1. Downloads SitMan — brings to the tabletop meeting
1. Downloads AAR template — for the team to fill in afterwards
1. After the tabletop: completed AAR goes in the team fileshare; the audit log entry from generation proves to auditors that the exercise was conducted

-----

## Infrastructure group

### Cloud & IaC

**What it’s for:** Generate Infrastructure-as-Code artifacts to deploy FireAlive on the org’s cloud platform. Supports AWS, Azure, and GCP. Every generated template provisions FireAlive on a **confidential VM** with a hardware (vTPM) root of trust — an AMD SEV-SNP instance on AWS, an Azure Confidential VM, or a GCP Confidential VM — so the deployment comes up in Cloud Mode with memory encryption and boot attestation rather than as an ordinary cloud instance. Outputs span the per-cloud and portable IaC formats (Terraform, Pulumi, CloudFormation on AWS, Bicep on Azure, gcp-dm on GCP). Bundles are server-rendered, signed, and SBOM-attested, and missing signing tooling fails generation rather than producing an unsigned or unattested bundle. Offline verification works against the bundle’s public key. Managed-container and serverless targets (Kubernetes, Helm, ECS Fargate, Azure Container Instances, Cloud Run) and the European and Swiss providers are no longer generated — those compute models cannot provide the confidential-VM hardware root FireAlive now requires in the cloud. See `docs/cloud-iac-generation.md` and `docs/cloud-mode.md`.

**Workflow:**

1. Lead picks target cloud provider, IaC tool, secrets manager
1. Clicks Generate
1. Receives a downloadable bundle with: deployable IaC files, secrets-management mapping (env vars → KMS paths), README with deployment steps
1. Hands the bundle to platform engineering for deployment

### Cloud Mode

**What it’s for:** Run the FireAlive server on a confidential VM in a public cloud — AWS, Azure, or GCP — with the same anti-cloning identity guarantees as a bare-metal or virtualized install. Cloud Mode is chosen once at first boot, alongside bare-metal and virtualized, and is sealed to the hardware root so it cannot be flipped later.

**What Cloud Mode enforces:**

- **Confidential computing is required and remotely attested.** At start-up the server does not just check for a confidential VM — it fetches a CPU-signed attestation report (AMD SEV-SNP or Intel TDX), verifies the signature up to the hardware vendor’s root, and confirms the report is fresh. A cloud deployment that cannot produce a verifiable report simply does not come up; there is no fall-back to an ordinary instance, and the kernel device alone is not accepted as proof.
- **Anti-rollback firmware floor.** The platform firmware version in the attestation report (the Trusted Computing Base) is pinned at provisioning and may only move upward. A later boot on downgraded firmware — which could reintroduce fixed vulnerabilities while still signing a valid report — is refused.
- **Pinned launch measurement.** The measurement the CPU takes of the guest at launch is recorded on first use; every later boot must present the same measurement, so a tampered or substituted image is caught and halts the boot.
- **Hardened guest, optionally single-tenant.** The server checks the guest kernel’s CPU side-channel mitigations and fails closed if an in-scope family is left vulnerable. An operator who wants more than memory-encryption isolation can additionally require dedicated, single-tenant hardware, refusing shared hosts.
- **No disposable instances.** Spot, preemptible, autoscaled, and scale-set instances are refused, because a single anchored identity cannot live on an instance the cloud can terminate or clone at will.
- **Stable trust across changing addresses.** A cloud instance’s IP can change when it stops and restarts or moves behind a load balancer. Cloud Mode anchors trust to a stable operator DNS name you provide, and analyst clients keep trusting the same deployment when the underlying address changes — they never have to re-pin after a routine restart.
- **Cloud-key-store backups.** Backups must be protected by the cloud’s own key store rather than a key sitting in an environment variable, so backup protection does not depend on the same instance the data lives on.

**Not a container or serverless workload.** Cloud Mode is deliberately *not* Kubernetes, ECS Fargate, Cloud Run, or any managed-container or serverless target. Those compute models do not give FireAlive the per-instance hardware root of trust it depends on, so they are not offered — FireAlive in the cloud is always a confidential VM.

The full operator runbook — platforms, remote attestation and the firmware floor, the recovery code for instance loss, and the stable-DNS model — is in `docs/cloud-mode.md`.

### Virtualization

**What it’s for:** Hypervisor integration (VMware vSphere, Hyper-V) for orgs that deploy FireAlive in their existing virtual infrastructure. Configures resource pool, datastore, and host placement.

**Workflow:**

1. Lead picks deployment target type
1. Enters the API endpoint for the hypervisor manager
1. FireAlive deploys into the configured virtualization infrastructure with the right resource constraints

### Virtualization Mode

**What it’s for:** A deployment-wide mode — bare-metal, virtualized, or cloud — chosen once at first boot, before any identity is established, and sealed to the hardware root so it cannot be silently flipped afterward. Virtualized mode turns on additive, VM-aware adaptations so every feature works correctly under a hypervisor without weakening the anti-cloning posture; cloud mode builds on those same adaptations and adds the confidential-computing requirements described under Cloud Mode above. (This is distinct from the Virtualization integration above, which configures a hypervisor target; Virtualization Mode is the security posture of the deployment itself.)

**What virtualized mode changes:**

- **vMotion / live migration versus a clone** — the anchor (a virtual TPM) relocating to a new host is treated as an authorized, audited move, while concurrent duplication is still caught as a clone. On bare metal, a host change for the same identity is flagged instead.
- **Clock-integrity, the snapshot-rollback defense** — FireAlive watches wall-clock against monotonic time; a detected backward jump (a VM rolled back to an earlier snapshot, which would also roll back the database) makes time untrusted and fails closed for privileged recovery actions and for enrollment / break-glass authentication until time re-stabilizes. Bare-metal deployments are never gated on clock divergence.
- **Backup independence** — local backup destinations are refused, because a VM snapshot or clone would capture them; an external destination (SFTP, S3, Azure, or GCS) is required. All backups are signed and KEK-wrapped regardless of mode.

Step-up user verification stays required in every mode — there is no VDI or virtualized relaxation. Confidential computing is a documented recommendation under virtualized mode, but under cloud mode it is a hard runtime gate: a cloud deployment that cannot attest a confidential VM refuses to start. The full picture is in `docs/anti-cloning-and-virtualization.md`.

### SDN

**What it’s for:** Run the FireAlive regional server inside a software-defined network — on bare metal with a TPM, a VM with a vTPM, or a cloud confidential VM — and have FireAlive treat the SDN as a security boundary it continuously verifies. SDN mode is chosen once at first boot, alongside bare-metal, virtualized, and cloud, and is sealed to the hardware root so it cannot be flipped later. FireAlive only ever *reads* your SDN controller; it never applies, pushes, or programs controller configuration.

**What SDN Mode enforces:**

- **Segment-aware admission.** You declare which network segments FireAlive’s own components occupy. Connections originating outside those permitted segments are refused before authentication, so a foothold elsewhere on the network cannot even reach the API. Local and loopback traffic is always allowed so the host stays manageable.
- **Continuous, read-only posture verification.** FireAlive probes the SDN controller — Cisco ACI, VMware NSX, OpenFlow, Arista CloudVision, Juniper CN2, Calico, Cilium, or a generic REST controller — on a schedule, using read-only credentials over a certificate-pinned connection, to confirm segmentation assurance is intact. Probes never change anything on the controller.
- **Assume-breach fail-safe.** If segmentation assurance is lost — controllers unreachable or rejecting authentication past a debounce threshold — FireAlive locks down its entire API surface (health checks included) rather than serving traffic it can no longer prove is segmented. Lockdown lifts automatically once posture is restored; there is no remote override.
- **Least-privilege segmentation policy, generated for you.** From the tier-to-segment map you declare, FireAlive generates a default-deny micro-segmentation policy in your platform’s own vocabulary, for you to review and apply through your own change control. The policy never permits management or aggregate zones (Tier-1) to reach analyst-private zones (Tier-3) — the same separation FireAlive enforces in its data model, now expressed at the network layer.
- **Host-substrate-aware defenses.** Because SDN can run on bare metal, a VM, or a cloud confidential VM, you declare the host substrate (`FIREALIVE_SDN_SUBSTRATE`) at first boot. FireAlive then applies the matching host defenses on top of SDN networking: a virtualized host adds clock-integrity and clone or rollback quarantine, and a cloud host adds confidential-computing attestation and refusal of spot or autoscaled instances. The substrate is required and sealed at boot — detection refuses an under-declaration.

**Not a container workload.** Like every non-cloud deployment, SDN mode runs the FireAlive server as a direct host process on hardware with a TPM or a VM with a vTPM — never Kubernetes, never a managed or orchestrated container — because those compute models cannot give FireAlive the per-instance hardware root of trust it depends on. The SDN segments that host at the network layer; FireAlive runs on it the same way a bare-metal or virtualized install does.

The full operator runbook — provisioning, configuring the controller integration, the posture and lockdown model, and applying the generated segmentation policy — is in `docs/sdn-mode.md`.

### SASE / ZTNA

**What it’s for:** Run the FireAlive regional server as a dark application behind your organization’s SASE/ZTNA edge — published to analysts only through a sanctioned connector, never directly reachable — and have FireAlive verify it is being reached the way it is supposed to be. SASE mode is chosen once at first boot, alongside bare-metal, virtualized, cloud, and SDN, and is sealed to the hardware root so it cannot be flipped later. It is a network overlay, not a change to how the server runs: FireAlive stays a direct host process on its own TPM/vTPM, terminates the analyst’s mutual TLS itself, and never hands its sessions to the vendor’s edge.

**What SASE Mode enforces:**

- **Connector-tunneled passthrough, required.** FireAlive requires the ZTNA edge to relay the raw TCP stream — a passthrough connector — so the analyst’s device-bound mutual TLS reaches FireAlive intact, end to end. It **fails closed** on a clientless, TLS-terminating edge that decrypts the connection and forwards an identity header (for example a Cloudflare Access or proxy `x-auth-request` header), because honoring that would trade the analyst’s client certificate for the edge’s word. There is no weaker authentication path.
- **Connector-source admission.** You declare the addresses of the sanctioned connectors. Admission runs before authentication and decides on the **raw TCP socket peer**, not a spoofable forwarded header: a connection arriving from outside the connector allow-list is refused as a direct exposure, and a connection carrying a clientless identity header is refused as a passthrough violation. Loopback is always allowed so the host stays manageable; an ordinary `X-Forwarded-For` is not treated as identity.
- **Assume-breach fail-safe, latched.** A single observed boundary violation — a direct connection, or a clientless-identity connection — latches the deployment into degraded posture and locks down the **entire** API surface (health checks included). There is no uncertain debounce band, because these are real observed breaches rather than flaky probes, and no automatic recovery: the lockdown lifts only when an operator closes the hole and records an out-of-band restore. There is no remote override.
- **Read-only posture, no provider calls.** SASE mode has no controller integration. The `sase` health probe is a local state read — is the mode active, are connector sources declared, is posture degraded — and **never dials the provider’s API**. The boundary is enforced at FireAlive’s own front door, not by polling the vendor.
- **Host-substrate-aware defenses.** Because SASE can run on bare metal, a VM, or a cloud confidential VM, you declare the host substrate (`FIREALIVE_SASE_SUBSTRATE`) at first boot. FireAlive then applies the matching host defenses on top of the overlay: a virtualized host adds clock-integrity and clone or rollback quarantine, and a cloud host adds confidential-computing attestation and refusal of spot or autoscaled instances. The substrate is required and sealed at boot — detection refuses an under-declaration.

**Not a SWG egress or a SECaaS rewrite.** SASE mode is an inbound-reachability overlay only. FireAlive does not route its own egress through your secure web gateway, does not call the provider’s CASB/SWG/SECaaS/FWaaS plane, and does not become a managed or orchestrated container — the provider and edge details you record are metadata, and the server runs on its own hardware root of trust exactly as in every non-cloud mode.

The full operator runbook — the passthrough requirement and why, the connector-source allow-list, the latching posture and lockdown model, and the deployment walkthrough — is in `docs/sase-mode.md`.

### High Availability

**What it’s for:** A warm standby and automated failover for the regional server. One node runs **active** and serves the SOC; a second runs **passive**, sealed and kept current over a mutually authenticated peer link, ready to take over. The topology is active/passive — a single sole-writer active and one warm passive — by design: FireAlive seals analyst-private data under keys the management tier cannot reach, and promotion unseals a pre-wrapped key only by proving the standby is the genuine anchored node, so two simultaneous writers (active/active) are ruled out rather than offered. What decides who may write is an internal **cryptographic lease at a monotonically increasing epoch**, enforced at the data layer, the scheduler, and the request layer. Your organization’s load balancer routes client traffic to whichever node is reachable and nothing more — so a flapping or even compromised balancer can affect availability but can never create split-brain, because a node that does not hold the lease will refuse to write.

**What it does, honestly:** Replication is **near-synchronous** — the standby is kept within seconds of the active, not locked to it transaction-for-transaction — so the recovery point is a few seconds of unshipped writes, not zero. Failover is bounded but not instantaneous: typically on the order of fifteen to forty-five seconds, dominated by the detection wait. This replaces slow manual restore-from-backup with an automatic promotion that completes in under a minute; it is not a zero-downtime, zero-data-loss guarantee, and the tab’s copy says so.

**Detection and safeguards:** The active delivers a heartbeat every heartbeat interval; the passive promotes after it misses the configured count in a row (≈ miss-count × heartbeat interval). A recovered former active adopts the higher epoch and steps down rather than competing; a promotion cooldown blocks back-to-back promotions; and an **isolation self-fence** demotes an active that has been cut off from both its peer and its clients past the self-fence timeout — fencing only when both signals are stale, and never within a grace window after a node takes the lease.

**Self-test:** The tab runs a real, measured failover-and-failback drill against the live pair and reports the actual milliseconds, whether the standby served, whether integrity held, and whether the original was restored — so the failover window is a number you measure, not one you take on faith.

**Un-pairing, re-keying, and key-operation authorization:** A paired node can be **un-paired** to run standalone again. Because a standby’s replicated columns are sealed under the shared pairing key, un-pairing first requires re-keying those columns to the node’s own key — an offline **rekey** the operator runs on the node — so a node never un-pairs into data it can no longer read, and a promoted node sheds its dependence on the shared key entirely. That rekey, together with the other destructive key operations (importing a migration bundle onto a new key, and a deployment reset), is gated by a **Key-Operation Authorization**: an anchor-signed, single-use, two-person authorization with a fresh hardware-passkey step-up — a second admin approves (or delayed-self on a single-admin deployment), verified offline against the instance anchor before a byte is touched. The rekey is forward-only: it re-seals the live database to the new key but never rewrites an existing backup or forensic export, so the old recovery code must be retained until the last pre-rekey artifact ages out. See [`docs/high-availability.md`](docs/high-availability.md) and [`docs/key-continuity-and-upgrades.md`](docs/key-continuity-and-upgrades.md).

**Workflow:**

1. Lead opens HA Configuration and enables HA
1. Sets this node’s endpoint and the peer endpoint, then pairs the standby with a one-time token over the mutual-TLS peer link
1. Tunes the live knobs as needed — sync interval, heartbeat interval, miss count, lease TTL, promotion cooldown, self-fence timeout — which take effect without a restart
1. Replication runs continuously; the standby stays within seconds of the active
1. Runs the self-test to confirm the pair is genuinely ready and to learn the real failover time
1. If the active fails, the passive promotes itself within the detection window, the load balancer routes to it, and the SOC keeps operating

The full operator runbook — the lease/epoch authority, pairing and the wrapped-key exchange, replication and the bounded recovery point, detection and the safeguards, the configurable knobs, and the troubleshooting steps — is in `docs/high-availability.md`.

### CI/CD

**What it’s for:** Generate CI/CD pipeline configurations so orgs can build their own customized FireAlive distributions. Because FireAlive is open-source, orgs are free to fork, modify, and run their own custom versions tailored to their specific SDN setup, automation stack, integrations, etc. The CI/CD generator is the bridge: instead of starting from a generic upstream release and re-applying every customization, the org uses this feature to output a pipeline config that captures their CURRENT production configuration as the baseline. They can then build whatever new tools or modifications they want on top of that already-configured baseline.

It also serves a second purpose: contributing back upstream. Orgs that find security holes, build useful new features, or improve existing ones can use the same CI/CD feature to push their commits back to the public FireAlive GitHub repo. That accelerates collaborative development of the platform — better features, better security, broader applicability — and increases the platform’s collective effectiveness in the war against analyst burnout and malicious attackers.

Supports GitHub Actions, GitLab CI, Jenkins, CircleCI. Pipelines embed (MC-side, 11 stages): lint -> test -> regression test (curl POST to `/api/regression/run` against the originating MC) -> npm audit -> Snyk -> SBOM (Syft -> SPDX-JSON artifact) -> dep-pin verify -> docker buildx with SLSA L3 provenance -> Cosign signing (keyless OIDC default; key-based via `COSIGN_KEY_MODE=key-based`) -> Grype CVE scan (`--fail-on high`) -> fuse-counter monotonicity check against `origin/main`. GD-side pipelines (10 stages) omit the inline regression invocation because GD’s regression runner is inline in `index.js` rather than `require()`-able. Pipelines can POST run status back via webhook (`POST /api/cicd/runs`); MC uses api-key + `cicd:webhook` scope, GD uses an `X-CICD-Webhook-Secret` shared-secret header. Supply-chain tools are pinned to specific versions installed from immutable release tags — Syft v1.44.0, Grype v0.110.0, and Cosign v3.0.6 (no `main` / `@master` / `:latest`). See `docs/cicd-generation.md` for full architecture and the auth-divergence rationale.

**Workflow (custom org build):**

1. Org’s developers want to extend FireAlive with org-specific tooling
1. Lead opens CI/CD tab in MC
1. Picks CI platform
1. Clicks Generate — output is a pipeline config that reflects the current production configuration (integrations, automations, custom settings already configured in this org’s MC)
1. Org’s developers commit the pipeline config to their internal repo
1. They build their additional tooling on top of the configured baseline rather than from a generic upstream release
1. CI runs automatically on every push, deploys to the org’s lab/production environments

**Workflow (upstream contribution):**

1. Org developer finds a bug or builds a useful feature
1. Same CI/CD generator outputs a pipeline that targets the public FireAlive GitHub repo
1. Developer pushes commits through that pipeline back to the upstream project
1. Upstream maintainers review and integrate

-----

## Data & Backup group

### Backup

**What it’s for:** Encrypted backups (AES-256-GCM) with per-data-type destination routing. The lead can route backups to one location, audit logs to another, forensic exports to a third — different retention and access requirements for each.

**Workflow:**

1. Lead opens Backup tab
1. For each data type (database, audit logs, forensic exports): configures destination, retention, schedule
1. Backups run on schedule, encrypted, hashed for integrity
1. Lead can trigger manual backups or restore from any backup

**Full-suite backup.** A separate `POST /api/backup/full-suite` endpoint captures the entire instance — database, configuration rows, signing-key material, and a version manifest — into an encrypted, signed archive. The Backup tab’s **Trigger Full Backup Now** button calls this endpoint; the resulting archive is suitable for disaster-recovery restoration of the full instance (vs. the standard `POST /api/backup` which captures only the database). Both realms use the v2 four-file layout (encrypted archive + KEK-wrapped key + signed manifest + signature); the MC signs the manifest with Cosign, the GD with Ed25519. See `docs/full-suite-backup.md` for the full architecture, manifest schemas, and restoration semantics.

**Exports are encrypted at rest, too.** Forensic-export archives are stored encrypted on the server’s own disk from the moment they are written — independent of whether they are also backed up — so the export files on the host are not readable without the deployment’s encryption key. Downloading an export is unchanged: the standard package streams to the browser and verifies the same way.

### Storage Destinations & Routing

**What it’s for:** Deciding, per kind of retained data, where its copies are written — and guaranteeing a second copy actually lands and stays trustworthy. A **destination** is a place a copy can go (a `local`, `sftp`, `s3`, `azure-blob`, or `gcs` target); a **route** maps a data type to a **primary** and an optional **secondary** destination. The two are configured separately: register a destination once, then point any number of data types at it. The five routed types are backups, snapshots, audit logs, forensic exports, and the archived CEF event feed; snapshots inherit the backup route unless given one of their own. Credentials are encrypted at rest, decrypted just-in-time for a push or a connectivity test, and never returned to the client.

**Concurrent dual-write, not failover.** Each routed type is written to its primary and, if set, its secondary on *every* run — the secondary is an independent second copy, not a standby used only when the primary is down. On-host storage plus a primary remote plus a secondary remote satisfies the 3-2-1 rule (three copies, two media, one off-site) for that type, which is what lets the data survive the loss of one location. The secondary must differ from the primary; a route naming the same destination twice is refused.

**Guaranteed replication.** Every push — both roles, all five types — is tracked and retried: up to 5 attempts with escalating backoff (roughly 5 minutes, 30 minutes, 2 hours, then 12 hours). A push that exhausts its attempts is marked a permanent failure and kept as a failed row for the operator to see; it is never silently dropped. A scheduled hourly retry sweep picks up failed-but-not-exhausted pushes, and a separate hourly sealing job drains new audit-log rows and the CEF spool into their chains before they are pushed. Both run only on the node holding write authority, so an HA pair does not double-write.

**What the archival writers retain.** Two routed types exist so the data is retained at all. The audit-log writer seals new audit rows into an append-only, gap- and tamper-evident segment chain whose cursor cannot move backward (the audit table forbids deletion). The CEF archive captures the otherwise fire-and-forget SIEM feed into a crash-safe, order-preserving spool and seals it into its own chain — so the events you forwarded to your SIEM are also retained under your own routing and residency policy, even when the SIEM is unreachable.

**Immutability and encryption.** Each destination declares an immutability mode constrained to what its adapter supports — `none`, `append-only`, or write-once `object-lock` (S3 Object Lock, Azure Immutable Blob, GCS retention). The mode is a declaration the console surfaces; configure the bucket’s lock policy in your cloud provider, then declare it here. Only FireAlive-encrypted ciphertext (the `FA-ENC1` envelope) is ever transmitted — a destination, including a third-party bucket, never receives plaintext.

**Residency is enforced per data type.** A destination is declared and evaluated for each data type it serves, so the same bucket can be compliant for backups and non-compliant for forensic exports. Saving a route runs the residency gate against the chosen destinations — for *both* the primary and the secondary — and a blocked verdict (enforce mode, out-of-region, or undeclared) refuses the save with a 403 and the reason shown inline. See Data Residency below and `docs/data-residency.md`.

**Reading replication health.** Each type’s routing card shows a health badge and a per-role breakdown drawn from the real push history: **idle** (nothing pushed yet), **healthy** (recent successes, nothing outstanding), **pending** (copies in flight), **degraded** (transient failures being retried), or **failing** (permanent failures — a copy is not protected, act). The status is computed correctly per type: backups and snapshots share a push table but are split by the backup’s type, audit logs and CEF archives share one but are split by segment category, and a push counts toward a role only if it targeted that role’s *current* destination — so re-pointing a route does not leave stale history polluting the new destination’s health.

**Workflow:**

1. In Storage Destinations, register each destination (adapter, location, credentials if needed, immutability mode, optional retention). Use **Test** to confirm connectivity without writing. Edit, enable/disable, or remove from the same list — a destination with push history can’t be removed (audit continuity), so disable it instead
1. In Storage Routing, set each type’s primary and optional secondary destination, an optional path prefix, and whether the route is enabled; **Save** per type and **Test** to probe the routed destinations. Invalid choices (a disabled destination, a residency-blocked region, the same destination twice) are refused with the reason inline
1. In the Data Residency panel, pick the data type and declare each destination’s jurisdiction
1. Confirm each type reads **healthy** once pushes have run; investigate any **failing** type from the destination’s **Test** in the registry

Full operator guidance — the dual-write model, the retry and sealing schedule, the chains, immutability, encrypt-before-push, the residency interaction, and the API reference — is in `docs/storage-routing.md`.

### Backup Schedules

**What it’s for:** Configure multiple backup schedules with optional regulatory-framework presets. Each schedule fires independently on its own cadence (hourly / daily / weekly / monthly) at a configured time, to a configured destination, with a configured retention. Picking a regulatory preset (HIPAA, SOX, PCI-DSS, GDPR, NIST CSF, ISO 27001, SOC 2) applies that framework’s compliance floor — minimum retention and required encryption — to the schedule. The operator can set retention HIGHER than the floor (legal-hold scenarios, longer compliance windows) but cannot reduce below the floor. Schedules without a preset have full operator flexibility.

**Floor-enforcement model:** Hybrid floor + upward flexibility. When a preset is selected, the API rejects retention below the framework minimum (e.g. HIPAA = 6 years / 2190 days) and rejects unencrypted schedules when the framework requires AES-256. Recommended frequency and destination class are pre-filled from the preset but not enforced — operators can pick hourly instead of the recommended daily if their risk profile demands it. The “None” preset (the default) skips floor enforcement entirely. SOC-grade compliance posture requires the floor to have teeth (auditor asks “what is your retention?” not “what preset did you pick?”), but operator legitimate use cases require upward flexibility.

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
1. Reviews existing schedules in the Active Schedules list: name, type, frequency, time, destination, retention, encryption status, preset tag, next run time, last run time + status, last error if any
1. Removes any schedules they no longer want (60-second scheduler poll picks up the deletion and tears down the cron within a minute)
1. Adds a new schedule via the Add Schedule form: name, type (full / incremental / differential / snapshot), frequency (hourly / daily / weekly / monthly), time (HH:MM), day-of-week or day-of-month for weekly / monthly schedules, destination, retention in days
1. Optionally picks a regulatory preset — auto-fills retention to the framework floor, locks encryption on (when AES-256 is required), pre-fills frequency and destination with the framework recommendation. The operator can edit retention upward but not below the floor; below-floor entries get a server-side 400 RETENTION_BELOW_FLOOR with an inline error
1. If the schedule’s fire times overlap within 5 minutes of another schedule’s fire times, the server returns 409 SCHEDULE_OVERLAP and the UI surfaces a confirm-to-queue modal showing the conflicting schedule names + fire times — the operator confirms (commits with force_queue=true, audit-log records BACKUP_SCHEDULE_OVERLAP_QUEUED) or cancels and adjusts the time
1. Schedule lands in backup_schedules table; scheduler picks it up within 60 seconds via the reload poll and registers a cron for it; fires at the configured time, executes the backup via the existing performBackup pipeline, records last_status / last_run / last_error on the schedule row

**Multi-schedule semantics:** Each schedule fires independently. The scheduler maintains a separate cron registration per active schedule. When two schedules’ fire times collide (within ±5 minutes), the overlap detection surfaces a 409 at create / update time so operators can adjust timing. Operators who explicitly want overlapping schedules (e.g. daily + monthly on the same day-of-month) can confirm-to-queue via the modal. The 5-minute window protects against I/O contention on the source DB and the destination — backup operations have variable execution duration and starting two backups at the same moment risks read locking and destination push throttling.

**Legacy compatibility:** Legacy single-schedule installs that configured a single backup schedule via /api/backup/config (the singleton-only legacy endpoint) get their singleton automatically migrated to a “Legacy default” row in backup_schedules on first boot post-upgrade. The /api/backup/config endpoint stays live as a deprecated read/write shim over the first row of backup_schedules for one version of deprecation grace — external tooling that still calls it sees a deprecated:true response with a replacement: ‘/api/backup-schedules’ hint. Operators should migrate clients to the modern endpoint when convenient. The v100 stub route POST /api/v1/backup/schedule/add also remains live and now delegates to the canonical service via BackupService.addSchedule (preserves the v100 public contract).

**MC orchestrating AC backups:** there is no separate per-AC backup artifact. The full-suite server backup (Data & Backup group) is canonical — it already holds every analyst's sealed private data, helper-pay ledger, training records, and analyst-key recovery wraps, so one server backup captures the whole fleet's recoverable state. The former "Backup All Clients" button is retired; the analyst-client lifecycle is now managed through Per-Client Recovery & Fleet Operations (System Health tab) — see that section for tear-down, re-provision, and the fleet-op checks.

### Incremental and differential backups

**What they’re for:** Two strategies for capturing the database between full backups, each making a different tradeoff between archive size and restore complexity. Both are point-in-time captures of the SQLite WAL frames written since a reference backup. Both use the same v2 four-file on-disk layout (manifest.json + manifest.sig + archive.bin + wrapped-key.bin) and the same encryption + signing pipeline as full backups; only the archive payload format and the parent linkage differ.

**Strategy comparison:**

|Strategy    |Captures                              |Parent                        |Restore needs                                       |Archive size over time|
|------------|--------------------------------------|------------------------------|----------------------------------------------------|----------------------|
|Full        |Entire DB                             |none                          |[this backup]                                       |constant per cycle    |
|Snapshot    |Entire DB (point-in-time)             |none                          |[this backup]                                       |constant per cycle    |
|Incremental |WAL frames since immediate predecessor|most recent backup of any kind|[anchor full + ALL intermediate incrementals + this]|small per archive     |
|Differential|WAL frames since anchor full          |anchor full backup            |[anchor full + this]                                |grows each cycle      |

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
- `backups.wal_start_position` / `wal_end_position` — TEXT “byteOffset:frameNo” position descriptors
- `backups.page_count` — frame count archived
- `system_meta.max_chain_depth` — global default depth limit (seeded to ‘100’)

**Dispatch:** The scheduler dispatches on `(backup_kind, backup_strategy)`:

- `(full-suite, full)` → `performFullSuiteBackup`
- `(single-db, full)` → `performBackup` (existing)
- `(any, incremental)` → `performIncrementalBackup`
- `(any, differential)` → `performDifferentialBackup`
- `(any, snapshot)` → `performBackup` with type=‘snapshot’

**INCR-v1 archive payload format:** Incremental and differential archives wrap the WAL frames in a custom binary format inside the standard v2 archive.bin (which is still zstd-compressed and AES-256-GCM-encrypted). Header (16 bytes): magic ‘INCR’ + format_version + frame_count + page_size. Per frame (44 + page_size bytes): frame_no + page_no + db_size_after_commit + sha256_of_page_data (raw 32 bytes) + page_data. The per-page SHA-256 lets restore verify each page’s integrity before applying.

**Six escalation reasons:** Both `performIncrementalBackup` and `performDifferentialBackup` can escalate to a full backup when their conditions aren’t met. The caller (scheduler, `POST /api/backup?strategy=...`) sees `escalated: true` and the reason string in the response:

- `no-parent` — no eligible parent backup exists
- `incompatible-parent` — parent has no wal_end_position (legacy backup without chain support, or full-suite)
- `no-wal-file` — DB has no WAL file on disk (journal_mode != WAL)
- `no-anchor` — can’t resolve parent_full_backup_id from chain walk
- `salt-change` — WAL was checkpointed since parent was taken (re-salted)
- `depth-limit` — chain length would exceed configured maximum

Escalated backups become the new anchor for future incrementals/differentials. The audit log records both the requested strategy and the actual strategy produced.

**Restore chain:** Chain restore is mechanically different from single-backup restore:

- `walkChain(db, leafBackupId)` — assembles `[anchor, ...intermediates, leaf]` by walking parent_backup_id backwards. Cycle detection. Hard cap at MAX_CHAIN_DEPTH=1000.
- `validateChain(db, chain)` — for every link: manifest sha256 match, Ed25519 signature verify, archive sha256 match, wrapped-key sha256 match. For inc/diff links additionally: unwrap key, decrypt+decompress, parse INCR-v1 bundle, re-compute per-page sha256, cross-check against manifest’s frames descriptor.
- `replayChain(db, chain, targetDbPath, options)` — extracts anchor full to targetDbPath, then for each subsequent link applies INCR-v1 frames at offset (page_no - 1) × page_size. Truncates target on commit frames (dbSizeAfterCommit nonzero).

**Endpoints:**

- `GET /api/backup/:id/chain` (C68) — read-only chain preview. Returns the ordered chain, per-link file existence, total page count, restorable flag. No locks, no audit, no validation overhead. Used by the frontend chain panel and restore-preview modal.
- `POST /api/restore/execute-chain/:id` (C66) — restore from a chain. Goes through the same approval gate, IP allowlist, and audit log machinery as `/execute/:id`. Confirms against the LEAF backup’s hash (not anchor). Creates a pre-restore snapshot with prefix `pre-restore-chain-<ts>.db` before destructive work.
- `POST /api/backup?strategy=<full|incremental|differential|snapshot>` (C67) — on-demand backup with strategy selection. Mirrors the scheduler’s dispatch table.

**Depth limits:** Long chains have linearly-growing restore cost and linearly-growing single-point-of-failure exposure. The configurable max-chain-depth limit forces a full backup once the chain would exceed it. Two sources of truth:

1. `backup_schedules.max_chain_depth` — per-schedule override (NULL = use global)
1. `system_meta.max_chain_depth` — global default (‘100’)

The C65 hard cap `MAX_CHAIN_DEPTH=1000` in restore-chain.js is a runaway-walk safety; the configurable limit sits well below it (defaulting to 100). Operators with stricter SLAs can lower; those with tight storage budgets can raise (at their own risk). Differentials are NOT subject to the depth limit since each is independently restorable.

**Workflow (operator perspective):**

1. In Backup Schedules, create a schedule with `backup_strategy=incremental` (or differential)
1. The scheduler creates a full backup on the first run (escalation: `no-parent`)
1. Subsequent runs produce incremental archives chained to the anchor (each adding ~M of WAL frames)
1. After ~100 incrementals (default), the next run escalates to a new full backup (escalation: `depth-limit`)
1. The chain restarts under the new anchor
1. Restore via the Backup History panel → Restore button. The modal shows chain shape + per-link integrity before the operator confirms.

**Operator decision matrix:**

|Need                                                        |Recommended strategy           |
|------------------------------------------------------------|-------------------------------|
|Predictable hourly snapshots of compliance-relevant tables  |snapshot                       |
|Cheap nightly captures, occasional restore (developer reset)|incremental + small depth limit|
|Cheap nightly captures, frequent restore (test env reset)   |differential                   |
|Long-retention frozen archives (no restore expected)        |full + retention policy        |
|Just-in-case before a risky change                          |snapshot                       |

### Restore

**What it’s for:** Restore from backup or revert configuration. Two modes: internal (revert to a recent FireAlive backup of this same install) and external (restore from a backup stored on a network share, NAS, S3, Azure, SFTP).

The internal mode is for routine reverts — someone messed up the configuration, or some data became noticeably corrupted, and the lead wants to roll back without tearing down the whole install.

The external mode is for compromise recovery. If an AC, MC, or GD has been compromised, the safest workflow is: tear down the compromised app instance entirely, install a fresh clean copy, then use the external Restore feature on that fresh copy to pull configurations, integrations, and data back from a known-good external backup. This avoids re-introducing the compromise that might still be lurking in the original install’s filesystem or local backups.

**Workflow (internal — routine revert):**

1. Lead notices configuration mistake or data corruption
1. Opens Restore tab → Internal
1. Picks the restore point from the list of recent internal backups
1. Confirms restore
1. System restores in place

**Workflow (external — compromise recovery):**

1. Compromise detected (via Compromise Scan, threat hunting, etc.)
1. Lead tears down the compromised app instance — uninstall, wipe filesystem, validate clean state of host
1. Install a fresh copy of FireAlive from verified source
1. Open Restore tab → External
1. Configure source: type (network share / NAS / S3 / Azure / SFTP), path, decryption key
1. Verifies integrity of the external backup, executes restore
1. System rebuilds from the trusted external backup with original configurations, integrations, and data

### Configuration Snapshots & Golden Baseline

**What it’s for:** Capture the management console’s entire configuration as a named snapshot, roll back to an earlier one, and move a known-good configuration between deployments. A snapshot covers the team’s settings, SLA and notification policy, scheduling, reporting, and which integrations are configured — but never any secrets. API keys, credentials, and signing-key material are deliberately left out.

**Snapshots and rollback.**

1. The lead opens the Backup tab and finds the Configuration Snapshots card
1. **Save Current** captures the live configuration as a named snapshot
1. **Change Report** shows exactly what differs between the current configuration and any snapshot
1. **Revert** rolls the configuration back to a snapshot; the current configuration is automatically saved first, so a revert is itself reversible, and the action requires an MFA step-up
1. Older snapshots are pruned automatically once the retention limit is reached

Because secrets are never stored in a snapshot, reverting restores every setting but leaves any affected integration disabled until its credentials are re-entered — the console says which ones.

**Golden baseline (moving a configuration between deployments).** A snapshot can be exported as a single signed baseline file, and a freshly installed or sister deployment can import that file to adopt the same configuration.

1. **Export** downloads the snapshot as a signed baseline file
1. On the receiving deployment, the lead first registers the originating deployment’s signing key (see Trusted Baseline Signing Keys, below)
1. **Import Baseline** selects the file; the console confirms where it came from, then requires an MFA step-up
1. The file is scanned for malware, its signature is verified against the registered key, and the configuration is validated before anything is applied — any failure stops the import with a clear reason
1. The current configuration is auto-saved first, then fully replaced; as with revert, integrations come back disabled until their credentials are re-entered

An import is refused unless a malware scanner is configured, the file’s signature matches a key the lead has explicitly trusted, and the file is intact. A tampered or untrusted file cannot be applied.

### Trusted Baseline Signing Keys

**What it’s for:** Establish trust in another deployment’s signing key so its golden baselines can be imported. This is a deliberate, one-time decision per partner deployment.

**Workflow:**

1. Obtain the originating deployment’s signing-key fingerprint through a trusted out-of-band channel, not from the baseline file itself
1. In the Trusted Baseline Signing Keys card, paste that deployment’s public key and choose **Validate** to see the fingerprint the console computes
1. Confirm the computed fingerprint matches the one obtained out of band, then **Register** it
1. Baselines signed by that key can now be imported; revoking the key later immediately stops any further baselines signed by it from being imported

Keys are shown with their origin (local or external) and status, so the lead can see at a glance which external deployments are trusted.

### Deployment Migration

**What it’s for:** Move an entire FireAlive deployment to new hardware or a new host — a hardware refresh, a bare-metal-to-VM move, or a data-center relocation — without cloning it. A migration deliberately does NOT copy the source’s instance identity (a verbatim identity restore would be indistinguishable from a clone); instead it carries the data and configuration forward and re-establishes a fresh identity on the target. Three layers are reconciled: instance identity (CA, server keys, analyst-client device keys, certificates, enrollment) is re-established fresh; analyst keys (per-analyst, recoverable through the offline recovery code) are preserved; and data (audit and forensic chains, configuration, sealed history, training and helper-pay records) is preserved. Analyst clients re-bind afterward through the Per-Client Recovery ceremony.

Sealed data at rest is bound to the source’s Tier-1 key-encryption key (KEK), so a migration also reconciles the KEK. When the target resolves the same KEK (the same environment-variable key or cloud-KMS key follows the deployment), the import applies directly and the sealed data reads as-is. When the target resolves a *different* KEK — the usual case for a genuine hardware move — the sealed columns cannot be read under the target’s key, so the online Apply refuses the bundle up front and routes you to the offline import re-key tool, which recovers the source KEK from the source deployment’s recovery code and re-seals every Tier-1 column to the target’s own KEK in one atomic, fail-closed step. See `docs/key-continuity-and-upgrades.md`.

The migration bundle (format FA-MIG1) is a self-contained, signed package: a manifest, the golden-baseline configuration capture, and a signed, KEK-wrapped full-suite backup — bound together by SHA-256 and signed with the source deployment’s Ed25519 backup signing key. The backup manifest also carries a salted fingerprint of the wrapping KEK, so a foreign-KEK bundle is detectable rather than silently unreadable.

**Workflow:**

1. On the source deployment: Data & Backup — Deployment Migration — **Export** (MFA step-up). The bundle is composed on the server; note the source’s backup-signing-key fingerprint. Keep the source’s recovery code — a cross-KEK import needs it.
1. Transfer the bundle directory to the target — a fresh install on the new hardware.
1. On the target: register the source’s signing key as trusted, confirming the fingerprint out of band (see Trusted Baseline Signing Keys).
1. Deployment Migration — **Import** — **Preview** (a dry run): review the reconciliation plan — confirm the source key is trusted, the bundle is proceedable, whether the source KEK is resolvable on this target, and the three layers read as expected.
1. **Import** — **Apply** (MFA step-up), for a *same-KEK* move: the target verifies the signatures, restores the data through the same EDR-scanned swap the external Restore uses (a pre-import snapshot is taken automatically), re-establishes identity fresh, and re-baselines the configuration. For a *cross-KEK* move, Apply refuses the bundle and you run the offline import re-key tool on the target instead, with the source recovery code and a migration-import authorization.
1. Restart the target, then re-provision the analyst clients against it via Per-Client Recovery.

**Security properties:** an unsigned or untrusted bundle is refused; a bundle wrapped under a KEK this target cannot resolve is refused before the swap (the salted KEK fingerprint makes it detectable) and routed to the offline re-key path; the restored database bytes are malware-scanned before they replace the live database, and the apply fails closed if no scanner is configured, a threat is found, or the scan is inconclusive; the automatic pre-import snapshot is the rollback path; the offline re-key is atomic and scrubs the recovered source key; and because identity is re-minted rather than copied, the migrated deployment is a distinct, authentic instance — not a clone. The full procedure is in `docs/anti-cloning-and-virtualization.md`; the key-continuity model is in `docs/key-continuity-and-upgrades.md`.

### Data Sovereignty / Geo-Fencing

**What it’s for:** Login geo-fencing for distributed SOCs. Each analyst is assigned a home country; the server resolves the country of every login’s source IP against a self-hosted MaxMind GeoLite2-Country database and, when enforcement is on, blocks logins whose country doesn’t match. It runs on FireAlive’s own MMDB reader — no third-party GeoIP dependency — and no analyst identity or location ever leaves the server. (Per-jurisdiction regulatory frameworks remain a later capability; data-residency controls are a separate section below. This surface is login geo-fencing only.)

**What it can and can’t do:** the check can only judge a login when FireAlive sees a real, public client IP. Behind a reverse proxy, set `TRUST_PROXY` so the server reads the real client address; on a pure-LAN deployment every login is a private address with no country, so the **trusted-network allow-list** (your office and VPN ranges) is what does the work there. A VPN or proxy in the expected country still passes — country is a tripwire layered on hardware-bound passwordless auth, not a perimeter. A misconfigured (unloaded) database fails **open** and alerts rather than locking everyone out, and break-glass recovery is geo-exempt by design.

**Workflow:**

1. Lead provisions a free MaxMind GeoLite2-Country database, then uploads the `.mmdb` under Data Sovereignty → GeoIP Database (malware-scanned, format-validated, and hash-verified on upload)
1. Assigns each analyst a home country — per-account in the console, at provision time, or inherited from the directory `c` attribute (a directory value wins but never wipes a manual one)
1. Adds office and VPN egress ranges to Trusted Networks so on-site logins always pass; loopback is always exempt
1. Pilots in audit-only mode (mismatches alert without blocking), works through the lockout checklist, then turns on enforcement
1. From then on: a US-assigned analyst logging in from an unexpected country is blocked (403, no token) and the event is alerted; legitimate travel is handled with a time-boxed exception

Full operator guidance — provisioning, the lockout checklist, reverse-proxy setup, the audit events, and the threat model — is in `docs/geo-fencing.md`.

### Data Residency

**What it’s for:** Declaring where FireAlive’s data is allowed to live and documenting a legal basis for every cross-border transfer. You set a primary residency and a per-category allow-list of permitted regions; anything you haven’t permitted is refused (an empty list denies everything). Crucially, the controls separate **residency** (which region the bytes sit in) from **sovereignty** (whose laws can compel access): AWS, Azure, and GCP are US-domiciled, so the US CLOUD Act reaches data even in an EU region. Every cross-border transfer in the register carries the provider domicile and a plain-language foreign-law-exposure note, so that risk is visible rather than hidden behind a region label. The residency subsystem records only the operator who acted and the jurisdiction involved — never analyst identity.

**What it can and can’t do:** today the policy is **enforced for all five routed data types** — backups, snapshots, audit logs, forensic exports, and CEF archives. Saving a Storage Routing route runs the residency gate against both its primary and secondary destination, and any destination outside an enforce-mode category’s permitted regions (or left undeclared) is refused with a 403 and audited; enabling a backup destination outside its permitted regions is likewise refused at config time. The live deployment is `declare-only` and is never blocked (blocking it would be a self-inflicted outage, not a control). In Cloud Mode the deployment’s region is detected from instance metadata and a **HIGH** alert fires if it drifts away from the declared residency. Recording a transfer mechanism (adequacy / SCC / BCR / derogation) asserts that the legal instrument exists — FireAlive cannot create it for you. On the Global Dashboard, the residency posture also surfaces the managed console fleet’s residency (each MC’s jurisdiction and whether its flow to the GD is cross-border) as a record-and-surface signal that never blocks a console.

**Workflow:**

1. Under Data Sovereignty → Data Residency, declare your primary residency (ISO country) and provider domicile; in Cloud Mode, accept the detected-region suggestion or override it
1. Set per-category permitted regions (ISO codes or `EU` / `EEA` / `UK` / `US` blocs) and a mode — `enforce`, `warn`, or `declare-only`; leave a list empty only if you intend to deny that category outright
1. Declare each destination’s jurisdiction, provider domicile, and key custody **per data type it serves** (pick the data type in the residency panel; S3 with a standard AWS region is inferred; S3-compatible endpoints, GCS, Azure, SFTP, and local are operator-declared)
1. Document a legal mechanism and a next-review date for every cross-border transfer the register surfaces, then re-check drift after any infrastructure change
1. From then on: a non-compliant destination is refused under enforce mode when its route is saved (and audited), and the register’s “N documented / K blocked” summary feeds the cross-border-transfer compliance check behind the GDPR, APPI, POPIA, and PDPA frameworks

Full operator guidance — the residency-vs-sovereignty framing, the shared-responsibility split, the reassessment cadence, the audit events, and how it interacts with Storage Routing — is in `docs/data-residency.md`.

-----

## Reports & Compliance group

### Report Engine

**What it’s for:** Scheduled depersonalized team-level reports for management or compliance. NEVER includes individual analyst names — tier/shift aggregates only. AI analysis backed by the platform’s research knowledge base, so reports cite peer-reviewed studies behind the recommendations. Output formats: PDF (printable, archival) and DOCX (editable), generated using the same document generator as the TTX feature. Every generated PDF/DOCX is signed with the instance’s Ed25519 report-signing key and stamped with a verification footer (instance label, generation time, signing-key fingerprint), so a recipient can confirm the report is a genuine, unaltered FireAlive artifact — in-app via the authenticated verify endpoint, or independently with OpenSSL and no FireAlive tooling (see `docs/report-verification.md`). KB citations are reproduced verbatim: the report shows exactly the peer-reviewed references behind each recommendation, never a paraphrase or a fabricated source.

**Workflow:**

1. Lead opens Report Engine
1. Configures: frequency, day, format (PDF/DOCX), email recipients
1. On schedule (or on-demand “Generate Report” click): system generates the report
1. Two delivery options:
- Click Generate Report → system produces the PDF/DOCX and opens a download window
- Or system emails the report to the configured recipients
1. Recipients see team trends, training needs, capacity issues — but never individual data

### Compliance

**What it’s for:** Generate framework-specific compliance reports against the running system. Picks a framework (NIST CSF, ISO 27001, SOC 2, HIPAA, GDPR, DORA, CCPA, PIPEDA, LGPD, PDPA, APPI, POPIA, NIS2, CPS 234, Cyber Essentials, FISMA), system runs real checks against actual app state, produces an audit-ready report. The report is viewable in-app as JSON; **Download PDF** and **Download DOCX** produce a signed, watermarked document for the selected framework — the same verification model as the Report Engine (Ed25519 instance signature + verification footer, checkable in-app or offline per `docs/report-verification.md`) — suitable for handing directly to an auditor.

Each report has TWO halves per the Shared Responsibility model:

- **verifiedControls:** technical controls FireAlive observes by inspecting its own running state (status pass / warning / fail / error, with per-control detail, taxonomy mapping, and remediation guidance when not pass)
- **customerResponsibility:** organizational, procedural, physical, and contractual controls the operating organization must attest separately — listed explicitly so an auditor can match each entry to the organization’s evidence binder

For HIPAA, the verified half covers 19 controls; the customer-responsibility half covers 42 (164.308 Administrative Safeguards, 164.310 Physical Safeguards, 164.400-414 Breach Notification). Ratio varies by framework.

**Workflow:**

1. Auditor announces audit
1. Lead picks the relevant framework
1. Clicks Generate Report
1. System runs the technical-control checks against actual app state — access control, encryption, audit trail, authentication, config management, IR infrastructure, data protection, network, backups, notifications, AI engine
1. Lead reviews both halves: verifiedControls (technical evidence) + customerResponsibility (operator TODO)
1. Lead pulls supporting documentation for the customer-responsibility items from the organization’s evidence binder / GRC tool
1. Combined evidence package handed to auditor

See SETUP.md → “Shared Responsibility in Compliance Reports” for the longer operator framing.

### Recertification

**What it’s for:** Periodic review of all accounts, integrations, assessments, and configurations. Quarterly recommended. Ensures stale accounts are removed, integrations are still current, settings still appropriate. Triggers a workflow rather than a one-time view.

**Workflow:**

1. Quarterly: system reminds the lead it’s time for recertification
1. Lead opens Recertification, sees due items
1. Walks through each: account by account, integration by integration
1. Marks each as “still valid” or “needs review/removal”
1. System logs the recertification — proof to auditors that periodic review is happening

### Knowledge Base

**What it’s for:** The research knowledge base behind FireAlive’s burnout-prevention features. 50 peer-reviewed entries (R001–R042, N001–N020) cited throughout the platform — the AI burnout prediction engine, the lead-side intervention prompts, the analyst-side signal interpretations. Each entry is enriched: a plain-language finding, the FireAlive implication, a fuller summary, the full citation, and a copiable source (DOI or stable URL). Leads (and any auditor) can verify that FireAlive’s recommendations come from real peer-reviewed science, not from a profit incentive to sell features that merely sound plausible.

The source on every entry is a **copy-to-clipboard** control, never a live link — neither the Management Console nor the Analyst Client opens an external browser on your behalf. You copy the DOI/URL and open it yourself.

The KB is curated. It is not open to anyone to update — that would be an attack vector for malicious actors to inject articles that accelerate burnout rather than prevent it. There’s a button to add KB peer-reviewed burnout articles, but for now that’s restricted to the upstream maintainer (Peter Mancina). The KB is updated on a quarterly or annual basis with the latest scientific research on burnout prevention, distributed via FireAlive version updates.

**Workflow:**

1. Lead clicks a citation in a prompt or report (e.g. on the Actions tab) — the KB opens to that entry
1. The entry shows the finding, summary, FireAlive implication, tags, full citation, and copiable source
1. Or browse the library by topic — in the Management Console KB tab, and in the Analyst Client Knowledge Base tab
1. Or generate an API key for developers building org-specific training content

#### KB Assistant (Lead and Analyst)

A research assistant lets leads and analysts ask the knowledge base questions in plain language. It retrieves the most relevant entries, answers **only** from them, and **cites every claim** — if it cannot produce a fully-cited answer, it withholds the answer rather than guessing. Cited entries appear as chips that open the KB entry (with its copiable source). It is research education — not therapy, diagnosis, or clinical advice — and when the underlying model isn’t available it says so honestly instead of inventing an answer.

- **Lead KB Assistant (Management Console):** runs server-side on FireAlive’s internal heavyweight model (Phi-4, verify-only — provisioned by the operator, never downloaded). The lead may supply brief, non-attributable team-aggregate context; individual analyst data is never used. Question and answer content are not logged (audit captures metadata only).
- **Analyst KB Assistant (Analyst Client):** runs **entirely on the analyst’s device** — a local model with no server round-trip. The analyst’s question and their own signals are used only as on-device grounding and **never leave the device**. The model is provisioned on the analyst’s machine by the operator and verified on load by the model-file integrity & safety gate (hash-pin → GGUF format validation → on-device malware scan, fail-closed), and FireAlive never downloads it; an endpoint that can’t run it gets an honest “unavailable on this device” rather than any server fallback (see Internal AI → Local AI model provisioning). A framing guardrail routes acute-distress input to the Post-Incident Wellness resources instead of to the model.

### Playbooks (SOAR Playbook / Runbook Generator)

**What it’s for:** Generate investigation and response playbooks for security incidents involving the FireAlive platform itself. The lead exports these to import into the SOAR system, or prints them as runbooks. Distinct from the Runbook Generator (which produces failure-and-compromise procedures for FireAlive) — these are SOAR-style automation playbooks for ongoing incident response involving FireAlive.

**Workflow:**

1. Lead opens Playbooks
1. Picks incident type
1. System generates the playbook with steps (some automated, some manual)
1. Lead exports — drops into SOAR or prints

### Risk Register Asset Generator

**What it’s for:** Generate a risk register entry for FireAlive itself as an organizational asset. Includes quantitative metrics (Asset Value, Exposure Factor, Single Loss Expectancy, Annual Rate of Occurrence, Annualized Loss Expectancy) and qualitative impact/likelihood. Crucially, it factors in the **human capital risk of NOT using burnout prevention** — the cost side of analyst turnover.

**Workflow:**

1. Risk team asks lead for a register entry on FireAlive
1. Lead opens Risk Register Asset Generator
1. System produces entry with AV/EF/SLE/ARO/ALE plus the inverse calculation: cost of turnover and replacement training if FireAlive weren’t deployed
1. Lead exports and submits to the risk register

### Human Impact Risk Report

**What it’s for:** Quantified report on the human capital cost of analyst burnout and the burnout-incident relationships specific to this org. Two purposes:

First, it’s used to justify FireAlive’s value to executives in dollar terms — annualized turnover cost, replacement training cost, and the inverse “what would this cost without FireAlive” calculation.

Second — and more importantly — it tracks in granular detail which TYPES of incidents burn out which TYPES of analysts the fastest. This lets the org make informed risk-management decisions beyond just adopting FireAlive. For example, if low-tier analysts are burning out fast because they get an avalanche of mindless repetitive tickets, the report can highlight that risk and recommend the org invest in more automated systems so those tickets can be delegated. If senior analysts are burning out from prolonged credential-compromise investigations, the report can recommend the org invest in better identity-protection infrastructure to reduce the volume of those incidents. So the report doesn’t just sell FireAlive — it actively informs executive-level investment decisions about what infrastructure, automation, and protection layers will most reduce burnout in this specific org.

**Workflow:**

1. Quarterly business review or budget cycle
1. Lead opens Human Impact Risk Report, generates
1. Sees per-incident-type cost breakdown (“ransomware events drive +18% exit risk for tier-1 analysts, $61,200 annualized cost”)
1. Sees recommended infrastructure investments correlated with high-risk incident types
1. Presents to executives — informs both FireAlive’s value and other risk-mitigation investments

### Query Tool

**What it’s for:** Two query tools combined — SIEM query generator (produces copy-pasteable queries for the org’s SIEM platform from templates) and an internal app query tool (run injection-protected queries against FireAlive’s own data).

**Workflow (SIEM Query Generator):**

1. Lead needs a SIEM query for “all login attempts to FireAlive in last 24h”
1. Opens Query Tool, picks template, picks SIEM platform (Splunk/Elastic/QRadar/Sentinel)
1. Gets the query as text, copies it into the SIEM

**Workflow (Internal Query Tool):**

1. Lead needs to investigate something specific in FireAlive’s own data
1. Picks data source, regex filter
1. Runs query — system parameterizes, strips injection attempts, returns results

### Data-Subject Rights

**What it’s for:** Serving access and erasure requests for the people whose data FireAlive holds, through `/api/data-subject/*`, with the same zero-access and dual-control properties as the rest of the platform.

**Access export.** `POST /api/data-subject/export` gathers a subject’s data into a portable bundle. Two modes:

- **Self-service.** Any user — analyst, lead, admin, CISO — exports their own data from their own authenticated session. For an analyst, the sealed `analyst_private_data` blobs inside the bundle still decrypt on-device with the key the Analyst Client already holds, so even a self-export of burnout data stays end-to-end.
- **Organization-initiated.** An admin runs an export for another user. If that subject is an analyst, the **whole bundle is sealed to the analyst’s active key** — the admin who ran it holds only ciphertext, and only the analyst can open it on their device. For a non-analyst subject, whose data the server can already read, the gathered bundle is returned to the operator.

**Erasure (dual-control).** Deletion is never a single click; it mirrors the restore-approval workflow:

1. An admin submits an erasure request for a subject, creating a pending row.
1. A **second** admin, different from the requester, reviews the queue and approves with a fresh MFA step-up.
1. Only on that second approval does the erasure run and the request move to executed.

**Audit trail.** Every export emits `DATA_SUBJECT_EXPORT`; a request emits `DATA_SUBJECT_ERASURE_REQUESTED`; a completed erasure emits `DATA_SUBJECT_ERASURE`. The access surfaces are self-service in the Analyst Client and admin-initiated in the Management Console.

-----

## Configuration group

### Feature Toggles

**What it’s for:** Enable or disable individual features across the platform. Disabling a feature does NOT remove it and never deletes its data — the feature’s text greys out (still visible so users know it exists), all action buttons and config inputs deactivate, and an “administratively disabled” message explains that a lead can re-enable it in the Feature Toggles tab. Turning a feature back on restores it exactly as it was. The same behavior applies in the Management Console and the Analyst Client, and a change propagates live to every connected client over the WebSocket channel — no reload needed.

**Not everything is a toggle.** Features are classified:

- **Toggle** — the 18 lead-settable features (peer chat, peer board, peer skill-share scheduling, box breathing, lighter-queue requests, pseudonymous lead chat (Signal E2EE), proactive break interventions, upskilling hour, helper pay, burnout-aware routing, IR simulator, recovery runbook, skills & assessments, training & certs, professional certifications, calendar integration, TTX generator, CI/CD pipelines). Toggles default on except CI/CD, which defaults off.
- **Locked** — security, integrity, safety, and compliance capabilities (analyst pseudonyms, audit log, log integrity, MFA, tripwire, insider-threat protocol, SOAR/EDR/threat-hunting, vulnerability scanning, enterprise KMS, backups, restore, peer abuse flagging, and more). These appear in the toggle list as permanently on with a short reason, and the update API rejects any attempt to disable them — a feature whose removal would lower the SOC’s defenses can never be turned off, even by a forged request.
- **Core** — structural scaffolding (impact feed, shift handoff, ticketing, SIEM feed, reporting engine, the global dashboard, HA, and so on). These have no switch.

**Before you turn anything off:** FireAlive is most effective at reducing burnout when every analyst-facing capability is active — they reinforce one another, and the research treats them as a system rather than a menu of extras. The switches exist because every SOC is different: some adopt everything at once, others introduce capabilities gradually or run a subset that fits their environment and their people’s readiness. Toggling a feature off tailors FireAlive to your organization; it does not mean the feature is optional to the mission. Nothing is deleted when a feature is off. The optimal configuration is everything on.

This way users can still see what FireAlive offers without being confused about why a feature suddenly disappeared.

**Workflow:**

1. Lead opens Feature Toggles
1. Sees features grouped by category (Wellbeing, Operations, Development, Integrations, Security, Management), with toggle features shown as switches and locked features shown permanently on with their lock reason
1. Toggles a feature off — its tab or section greys out, controls deactivate, and an “administratively disabled” message replaces the workflow content while the data is preserved
1. Toggles back on — the feature returns to its exact previous state

### Burnout Alerts

**What it’s for:** Alert thresholds for team-level burnout metrics. When the team’s aggregate health drops below a threshold, or capacity overload exceeds a threshold, the lead is alerted via configured channels. Distinct from app performance alerts (CPU, memory) which are in Monitoring.

**Workflow:**

1. Lead configures thresholds on initial setup
1. Picks notification channels (per the Client Notifications config)
1. When team metrics cross thresholds, alert fires through chosen channels

### Global Dashboard

**What it’s for:** Configure this regional MC to push aggregate data to a Global Dashboard (CISO-level view). Anonymized aggregate only — no individual analyst data crosses the region boundary. The GD is a companion app, not a controller.

**Workflow:**

1. CISO sets up GD, generates RO API key for this region
1. Regional lead opens Global Dashboard tab in MC
1. Pastes GD ingest endpoint, RO API key
1. MC starts pushing aggregate data to GD on schedule
1. CISO sees regional health alongside other regions

### Updates

**What it’s for:** Telling the lead when a newer FireAlive release is available — and nothing more. FireAlive checks this project’s GitHub Releases for a newer stable release and surfaces it; it never downloads, stages, lab-tests, or installs an update. The lead reads the release notes, downloads the new release from GitHub, validates it through the org’s own change-management process (a lab or staging deployment, regression testing, security review — whatever the org requires), and installs it on their own schedule. Auto-applying updates to a production security tool is bad practice and varies too much across orgs to automate; FireAlive surfaces the signal reliably and leaves the upgrade as a deliberate, operator-owned action.

The check is **opt-in and off by default** (air-gapped deployments stay dark), **zero-telemetry** (a plain GET to `api.github.com` carrying no body or query string), **fail-safe** (any network problem reports "source unreachable", never a false "up to date"), and **anti-rollback** (only a strictly-newer tag is reported — never a downgrade). The Regional Server runs the check on behalf of the MC and the analyst clients; analyst clients never call out. Notification is a persistent, dismissible in-app banner, plus an optional once-per-version notice to the lead through their configured channel. The full behavior is documented in `docs/automatic-updates.md`.

**Workflow:**

1. (Optional) Lead enables automatic checks on the Updates tab and sets a frequency (daily/weekly/monthly) and time (UTC); the check is off until enabled
1. On the schedule — or when the lead clicks **Check now** — the Regional Server queries GitHub Releases for the newest stable release
1. If a strictly-newer release exists, a persistent banner appears and (if enabled) the lead is notified once for that version through their configured channel
1. Lead opens the linked GitHub release and reads the release notes
1. Lead downloads the installer and validates it through the org’s change-management process (lab/staging, regression, security review) — FireAlive’s regression runner is available for this
1. Lead installs the new release on the production host; the anti-rollback fuse advances and refuses any later downgrade
1. Each check is recorded in `auto_update_check_log` and audited; the banner clears automatically once the running version catches up

### Troubleshooter

**What it’s for:** A one-shot diagnostic for when a feature isn’t behaving. An admin describes the symptom and the server runs rule-based checks against live configuration and state, then — when the internal model is loaded — adds a short most-likely-cause and prioritized-fix summary on top of those checks.

**How it works:**

1. Something looks wrong — for example “SOAR routing isn’t assigning tickets”
1. The admin opens Troubleshooter and describes it
1. The server keyword-routes the description to a topic, runs the matching checks (for SOAR: integration connectivity, the routing toggle, recent routing events) plus an always-run baseline (database, recent audit events, integration health, panic mode), and returns structured findings — each with a pass / warn / fail status, a detail, an optional suggested fix, and a jump-link to the relevant settings tab
1. When the internal model is available it also returns a grounded “diagnosis and prioritized fixes” summary that reasons only over those findings; when it isn’t, the tab shows an honest “AI diagnosis unavailable” note and the rule-based findings stand on their own
1. The admin reviews the findings and either applies a fix or escalates with them as evidence — nothing is applied automatically

The synthesis runs on the FireAlive internal model only; the troubleshooter never sends its context to an external provider, and the problem description and the generated summary are never logged (only metadata: model, token estimate, latency, status).

-----

## Monitoring group

### System Health

**What it’s for:** Aggregated runtime metrics across the server, MC, and all connected ACs — CPU, memory, heap, DB size, load average, connected WebSocket sessions, and per-client metrics — together with the controls that govern how anomalies are detected and routed. Continuous file-integrity monitoring and a bandwidth monitor run alongside the metric stream. Anomalies (sudden spikes, sustained high load, integration outages) are dispatched through a severity-tiered alert router rather than a single fixed channel.

The tab exposes two admin-configurable control panels:

- **Integration Health** — the single config-and-health surface. It runs opt-in, read-only health probes against thirteen external integrations: KMS / key-wrapping, cloud storage, LDAP/AD, SIEM, SOAR, EDR / malware scanner, ticketing, workforce scheduling, the SDN controller, cloud attestation, backup schedules, notification channels, and CI/CD. Probing is disabled by default at both the master and per-integration level and never mutates integration data — most probes simply read the status the platform already records (the SDN probe, for one, reads last-known posture and never dials the controller), the KMS probe performs a live wrap/unwrap round-trip only when its deep-probe toggle is on, and the notification probe checks channel connectivity without sending anything. Admins set the master switch, the periodic interval, per-integration coverage, and can run an on-demand probe; results render as a colour-coded status table with per-integration latency. Directly below it, a **System Configuration** list shows FireAlive-internal controls — Tripwire, Posture, MFA, pseudonyms, fail-open, HA, and the rest — as configuration state only; they are internal features, not external systems to reach, so they carry no probe badge. A separate **Notification Channel Test** lets an admin send a real test message to a configured email, webhook, or PagerDuty destination (configure-then-test), deliberately distinct from the read-only probe, which never sends.
- **Alert Routing** — a per-severity × channel routing matrix (audit, SIEM, SOAR, in-app notification, email, webhook). Audit is always recorded and cannot be disabled. The defaults escalate by severity: info is audit-only, warning adds SIEM, high adds SOAR + SIEM + an in-app notification to admins/leads, and critical adds email + webhook. The panel also sets the alert webhook URL and the sustained-load hysteresis thresholds (CPU / memory / DB-read enter, exit, and dwell, plus a cooldown) that decide when a sustained-load alert fires and when it clears.

Health checks follow the feature: every integration is probed by a check that ships in the same phase as the integration itself. B5j was a one-time retroactive pass that added the probes for the seven integrations that predated this convention, bringing the roster to thirteen.

**Workflow:**

1. Lead glances at System Health daily — metrics, connected sessions, and the last integration-health probe
1. Spikes or failed probes investigated immediately — could be load, an integration outage, or an attack
1. Alerts fan out by severity to audit, SIEM, SOAR, in-app notification, email, and webhook per the routing matrix; the metric stream and forwarded client logs feed the broader SOC monitoring stack

### Per-Client Recovery & Fleet Operations

**What it’s for:** The admin surface for managing the lifecycle of individual analyst clients and for running operational checks across the fleet — both on the same authenticated WebSocket dispatch channel the compromise scan uses. Identity is pseudonym-only throughout; the console never shows a real name. This is where you recover a compromised or lost client and where you pull live, signed health from the fleet.

**Per-client recovery (admin, MFA step-up):**

- **Tear Down** evicts a client server-side: it revokes the client's active certificates, retires its device signing key, and deletes its passkey, then sends a best-effort local-wipe signal if the client is still connected. The analyst's private key and recovery wraps are deliberately preserved — recovery is not offboarding, so the sealed wellbeing history survives. The real guarantee is the server-side revocation; the local wipe is a courtesy on a possibly-compromised machine.
- **Re-provision** issues a one-time enrollment token (same analyst, same pseudonym) for binding a fresh, clean install. The token is shown once for out-of-band delivery and expires in seven days. On the rebuilt client the analyst recovers their existing key from the offline recovery code and re-wraps it under the new passkey — the key is recovered, never re-minted, so the server's sealed data stays readable.

**Fleet operations (lead/admin):** dispatch one of four state-asserting checks — Refresh Metrics, Log Integrity, Regression, Vuln Scan — to all connected clients. Each client runs the check in its isolated main process and returns an Ed25519 device-signed result the server verifies; results render per-client (pseudonym, op, status, signature-verified, reported-at) and unverified or failed results route through the alert router. Two further commands — config resync and update push — are command-and-acknowledge (no signed result). There is no per-AC backup operation; the full-suite server backup is canonical (see the Data & Backup group).

**Workflow:**

1. Open System Health; the Per-Client Recovery and Fleet Operations cards list the connected analyst clients by pseudonym.
1. To recover a client, choose Tear Down (confirm the destructive action and complete the MFA step-up), then Re-provision to issue the enrollment token; deliver the token to the analyst out of band.
1. To check the fleet, dispatch a fleet operation; connected clients return signed results within a moment, and offline clients are queued for delivery on reconnect within a 15-minute window.
1. Failed or unverified results raise alerts through the router; investigate, and recover the affected client if compromise is confirmed.

### Vulnerability Scan

**What it’s for:** Authorize your organization’s approved on-prem and network vulnerability scanners (Nessus, OpenVAS, Qualys, Rapid7, Tenable.io, Nuclei) to scan the running FireAlive instance, and keep a tamper-evident record of every scan that reaches it. FireAlive does not run scans, schedule them, or store findings itself — scan results live in the scanner’s own console, the same way the Cloud Vulnerability Scan, EDR, and threat-hunting integrations let approved tooling inspect FireAlive without FireAlive duplicating the tool. This is the on-prem companion to Cloud Vulnerability Scan: there approved cloud-posture / IaC scanners are authorized against your cloud deployment; here approved host / network scanners are authorized against the instance itself.

A scan policy sets the master on/off switch, the subset of the six scanner types you permit, and an informational schedule. The permitted-scanner policy is live: it is enforced when an authorization is created, again when a scan is announced, and again at the rate-limit exemption — so removing a scanner type (or disabling the feature) stops authorizing it and stops exempting its traffic within one refresh window, without touching individual authorizations.

Each authorization is a registered scanner identity, not an open door. Access is granted per scanner with two controls: a bearer token (shown once at creation, then stored only as a salted hash) and a source-IP allow-list (individual IPs or CIDR ranges). A scan is accepted only when both the token and the source IP match an enabled authorization whose type is currently permitted. Every scan attempt — accepted or rejected — is written to an append-only, hash-chained scan-access log whose integrity can be verified from the console at any time.

FireAlive performs application-layer authorization and logging. Network-layer blocking of unauthorized scanners remains your firewall / security-group responsibility — FireAlive records and attributes the scans that reach it rather than acting as a network firewall. Source IPs belonging to an enabled, permitted authorization are exempt from FireAlive’s API rate limiting so a sanctioned high-volume scan is not throttled; all other defenses stay active.

**Workflow:**

1. An administrator opens Vulnerability Scan, sets the scan policy (enables the feature, checks the permitted scanner types, picks a schedule), and saves it
1. Selects “Authorize Scanner”, picks the scanner type, names it, and sets the source-IP allow-list (the IPs or CIDRs the scanner originates from)
1. FireAlive issues a one-time bearer token — copy it into the scanner’s configuration now; it cannot be retrieved again
1. The scanner runs its own checks against the FireAlive instance and announces each scan with its token from an allow-listed IP
1. FireAlive authorizes (or rejects) each access and records it in the scan-access log; findings remain in the scanner’s console for the org’s vulnerability-management process
1. The administrator reviews the scan-access log, verifies the log’s integrity (chain check), and can disable or revoke an authorization at any time — revoking immediately invalidates that scanner’s token

### Cloud Vulnerability Scan

**What it’s for:** Authorize your organization’s cloud-posture and IaC scanners (ScoutSuite, Prowler, Pacu, CloudBrute, Checkov) to scan your FireAlive cloud deployment, and keep a tamper-evident record of every scan that reaches it. FireAlive does not run scans or store findings itself — scan results live in the scanner’s own console, the same way EDR and threat-hunting integrations let approved tooling inspect FireAlive without FireAlive duplicating the tool. This is the cloud-posture companion to the endpoint-focused EDR/Threat Hunting integrations: FireAlive opens itself to authorized scanning by the org’s security tooling and logs that access.

Each authorization is a registered scanner identity, not an open door. Access is granted per scanner with two controls: a bearer token (shown once at creation, then stored only as a salted hash) and a source-IP allow-list (individual IPs or CIDR ranges). A scan is accepted only when both the token and the source IP match an enabled authorization. Every scan attempt — accepted or rejected — is written to an append-only, hash-chained scan-access log whose integrity can be verified from the console at any time. Authorization covers all deployed components (Management Console, Analyst Client, and the main server); the Global Dashboard server keeps its own separate authorization config and its own scan-access log.

FireAlive performs application-layer authorization and logging. Network-layer blocking of unauthorized scanners remains your firewall / security-group responsibility — FireAlive records and attributes the scans that reach it rather than acting as a network firewall. Source IPs belonging to an enabled authorization are exempt from FireAlive’s API rate limiting so a sanctioned high-volume scan is not throttled; all other defenses stay active.

**Workflow:**

1. An administrator opens Cloud Vulnerability Scan and selects “Authorize Scanner”
1. Picks the scanner type, names it, and sets the source-IP allow-list (the IPs or CIDRs the scanner originates from)
1. FireAlive issues a one-time bearer token — copy it into the scanner’s configuration now; it cannot be retrieved again
1. The scanner runs its own checks against the FireAlive cloud deployment, presenting its token from an allow-listed IP
1. FireAlive authorizes (or rejects) each access and records it in the scan-access log; findings remain in the scanner’s console for the org’s vulnerability-management process
1. The administrator reviews the scan-access log, verifies the log’s integrity (chain check), and can disable or revoke an authorization at any time — revoking immediately invalidates that scanner’s token

On the Global Dashboard server the same feature appears in its own console and authorizes scans of the GD server independently of any Management Console.

-----

## Audit group

### Audit Log

**What it’s for:** Aggregated audit trail across MC + AC. Every meaningful action — logins, config changes, ticket assignments, peer flag resolutions, redemption approvals — is appended through a single chained-write path, so each entry joins a per-row SHA-256 hash chain that Ed25519-signed checkpoints periodically notarize (see Log Integrity). The table is append-only at the database level (UPDATE/DELETE rejected by trigger). Searchable, paginated, exportable for forensics, and verifiable on demand via `GET /api/audit/integrity`.

**Workflow:**

1. Auditor / lead investigation needs evidence
1. Open Audit Log, filter by user / action type / time range / event type
1. Find the entry, verify chain integrity, export

-----

## Other MC tabs

### Inbox

**What it’s for:** Optional storage for notifications the user wants to revisit. Per the Client Notifications design, notifications are delivered through the channels each user chose — email, SMS, desktop notification, inbox, multiple, or off. Inbox is one channel option. It’s here for users who specifically want a place to find missed notifications; it’s not the primary delivery mechanism.

**Workflow:**

1. User configures notification preferences (per type: email / SMS / desktop / inbox / multiple / off)
1. Notifications fire to chosen channels
1. If user includes inbox among channels, copies show up here
1. User opens inbox occasionally to catch up on anything they missed live

### Peer Conduct

**What it’s for:** Reviewing and resolving abuse reports from peer skill-share sessions and the skill-share Board. This is where the Team Lead opens a sealed case, reads the flagged content, and closes it with a verdict.

**Zero-access review.** Each report is sealed on the flagger’s device to the active Team-Lead recipient set (a multi-recipient X25519 envelope) before it leaves the app, so the server, the GD, and an admin who handles only public keys all hold opaque ciphertext they cannot open. Only a lead who has enrolled an abuse-review key, unlocked on their own device, can decrypt a case — the plaintext exists only in the renderer for the duration of viewing.

**One-time setup — enroll your key.** Generate your abuse-review key here behind a 12-character (or longer) passphrase; the key is created on your device and the private half never leaves the MC machine, while the server receives only the public key. Enrolling adds you to the recipient set, and abuse reporting stays disabled until at least one lead has enrolled (with no key, nothing could be decrypted). Multiple leads can each enroll, and every flag seals to all of them at once. A key can be revoked from this tab; flags already sealed to other active leads stay openable by them. If a passphrase is lost, revoke that key and enroll a fresh one — flags sealed to other active leads remain openable, but a flag sealed only to the lost key can no longer be opened, the cost of zero-access.

**Workflow:**

1. Open the Peer Conduct tab; the case list shows metadata only — case id, target type (peer-session or board-post), tier, time, parties, status. No content.
1. Unlock with your passphrase and open a case. The sealed note and content decrypt client-side; for a board-post, a small thread-context snippet is included.
1. Resolve the case with a structured verdict and rationale. The store is append-only — nothing is ever deleted; a board-post flag upheld keeps the post removed, dismissed returns it to the Board.

**Patterns.** A metadata-only detector surfaces signals across the cases a lead can see — repeat-offender (same person flagged 2+ times in 30 days), escalation (tiers rising across cases), and retaliation. It reads metadata only and never decrypts content.

**Pseudonyms only.** Cases identify everyone by pseudonym. FireAlive stores no real names, so a review can only ever show the system’s pseudonymous handles, even though a lead generally knows who they belong to. Tiers signal severity; they do not change identity, and analysts stay pseudonymous throughout.

**Locked toggle.** `peer_abuse_flagging` is a **locked** capability in Feature Toggles and cannot be turned off — disabling abuse reporting would lower the SOC’s safety floor.

### Help (MC)

**What it’s for:** In-app help — this Feature Guide accessible by tab. Each tab in the MC has a corresponding mini-article in this Help menu.

-----

# ANALYST CLIENT (the analyst’s app)

### Home

**What it’s for:** Analyst’s daily landing. Shows their current burnout stage in big print, with optional context. Quick-action tiles for the four most common things they’d want to do (peer skill-share, delegate, training, self-scan) plus prominent buttons for “Request Reduced Tickets” and “Message Team Lead.” Recent impact section showing positive reinforcement.

The “Request Reduced Tickets” button is two-state: when reduced routing is OFF, the button activates it; when reduced routing is ON, the button turns it off. The analyst always has control over their own load reduction request.

**Top-of-AC panic banner.** When the team lead engages panic mode (from the MC), a red full-width banner appears at the top of every AC screen: “PANIC MODE ACTIVE — All wellness routing is OFF. You may receive tickets above your usual complexity cap until your lead restores normal routing.” This explains what the analyst is about to experience — tickets above their cap are not a mistake, they’re a deliberate decision the lead made in response to a major incident. When the lead restores normal routing, the banner turns green for 5 minutes (“Panic mode lifted — wellness routing restored”) then vanishes. The AC polls the canonical state endpoint every 30 seconds so the banner is always in sync regardless of which AC tab the analyst is on.

**Workflow:**

1. Analyst logs in at start of shift
1. Lands on Home — sees their current state, recent wins
1. From here, navigates to whatever they need to do
1. If they want load reduction: clicks Request Reduced Tickets → state toggles ON
1. If they want to resume normal load: clicks the now-toggled button → state toggles OFF

### My Signals

**What it’s for:** The analyst’s own burnout signals. Investigation time, dismiss rate, ticket quality, escalation rate, and break compliance — the analyst’s behavioral signals, each compared to the analyst’s OWN baseline (not team comparisons) — alongside a separate operational section for the workload pressure on them (cognitive load, task-switching, queue pressure, shift overtime). Click any signal for research-backed interventions. Privacy-critical: the behavioral signals are sealed to the analyst, so only they see their own values, never the lead.

**Workflow:**

1. Analyst feels off, opens My Signals
1. Sees: “Investigation time: 26 min vs your baseline of 20 min — that’s 30% longer”
1. Clicks the signal — gets context on what this typically means and research-backed responses
1. Optionally requests reduced queue (anonymous) or messages lead (pseudonymous, E2EE)

### Inbox

**What it’s for:** Same as MC inbox — optional storage of notifications for users who chose inbox as a delivery channel.

### Delegate

**What it’s for:** Send recurring ticket patterns to automated systems so analysts aren’t doing repetitive work that doesn’t need human judgment. Two cases:

First, false positives — analysts close the same false alarm 10 times a day. The Delegate feature lets the analyst create a rule that sends those alerts straight to the SOAR or AI triage so the analyst stops seeing them.

Second — and equally important — true positives that are nonetheless low-level repetitive work. Some real incident-response actions don’t need human judgment: known-malware container quarantine, low-severity password resets, ticket enrichment, basic phishing categorization. If the org has automated systems registered (in the MC’s Automation tab) capable of handling that kind of work, the analyst can delegate those tickets to those systems. The analyst gets back the time, the org gets the boring tickets handled. This is what the research on anti-burnout tooling actually shows works.

**Workflow:**

1. Analyst notices a pattern (either a recurring false positive or a real but boring repetitive task)
1. Opens Delegate tab, clicks “+ New Delegation”
1. Describes the pattern
1. Picks target: SOAR auto-response, an AI triage system, or one of the automated systems the lead registered in MC’s Automation tab
1. Submits — lead approves the delegation in MC
1. From now on, that pattern is auto-handled by the chosen system; analyst stops seeing it

### Peers

**What it’s for:** Peer skill-share — end-to-end encrypted chat between analysts (Signal protocol: X3DH/PQXDH key agreement and the Double Ratchet, with out-of-band safety-number verification) to share knowledge, ask questions, learn techniques. NOT therapy or emotional support — that has separate channels. This is technical knowledge sharing. Anti-abuse flagging is built in. 4KB per message, auto-closes after inactivity; after a session, ciphertext is retained for 5 minutes for abuse review, then permanently deleted.

**Workflow:**

1. Analyst stuck on a technique — opens Peers
1. Posts a skill-share request: “Anyone good with Splunk regex extraction?”
1. Another analyst sees it, accepts, opens E2EE chat
1. They work through the problem
1. Session times out, chat is gone — but the helper earned points (Helper Pay)
1. Either analyst can post-session flag if conduct was inappropriate

### Lead Chat

**What it’s for:** A pseudonymous, end-to-end-encrypted 1:1 channel between an analyst and a team lead (Signal protocol: X3DH/PQXDH key agreement and the Double Ratchet, with out-of-band safety-number verification). The analyst picks a specific lead — the lead is named to the analyst — and writes under their own pseudonym, so the lead sees “Analyst-Falcon,” never the real name, and the server relays only ciphertext it cannot read. This is the channel for reaching a chosen lead directly: workload concerns, schedule changes, or just asking to talk. For anonymous support, analysts use peer chat instead. The analyst can also send an in-person 1:1 request, which the lead sees surfaced both in a banner and at the top of the Lead Chat inbox. Any on-shift lead is reachable — a lead is never hidden by shift. Messages are deleted five minutes after the chat is closed.

**Workflow:**

1. Analyst opens “Message Your Lead” and picks an on-shift lead from the roster
1. The Signal session establishes; the analyst types a message or taps “Request an in-person 1:1”
1. Lead opens Lead Chat in the Management Console — the thread is labeled by the analyst’s pseudonym
1. Lead reads it (clearing the unread and 1:1 indicators) and replies on the same encrypted channel
1. Either side can verify the safety number out of band — read it aloud; the numbers must match
1. Analyst closes the chat; five minutes later the scheduler purges the thread’s messages

### Helper Pay (AC-side)

**What it’s for:** The analyst’s own view of their Helper Pay state — points earned from helping peers, current balance, transaction ledger, available rewards, and the leaderboard visibility toggle that controls whether their pseudonym appears on the lead’s recognition leaderboard.

Points come from 4-5 star peer-session ratings the analyst has received. Each rating writes a ledger entry (1-2 stars yield zero points; 3 stars yields a low amount). The analyst sees their full ledger here — every entry, daily-cap clamps, and any admin-side fraud reversals. Rewards are redeemed against the catalog the lead configured (USD, PTO minutes, custom rewards); requests go to the lead for approval and fulfillment.

The leaderboard visibility toggle defaults to OFF (opt-out). Flipping it on adds the analyst’s pseudonym (or real name if pseudonyms aren’t enabled team-wide) to the lead’s recognition leaderboard on the MC. Earning, balance, and redemption are NOT affected by this toggle — they continue regardless of leaderboard visibility. Only the public-display surface changes.

The Your Records card exports a personal copy of the statement — balance, full ledger, and redemption history — as a signed PDF, DOCX, or CSV. All three formats are signed with the instance’s Ed25519 report-signing key and carry a verification footer (instance label, signed time, key fingerprint, and the SHA-256 verification instruction), so the analyst, or an admin asked to attest to a copy, can confirm a document is genuine via the in-app verify endpoint or OpenSSL per `docs/report-verification.md`. The statement is self-scoped — the server returns only the caller’s own data — and is for personal record-keeping, not a payroll or HR artifact.

**Workflow:**

1. Analyst opens Helper Pay tab in their AC
1. Sees current balance prominently displayed
1. Optionally toggles “Visible on the leaderboard” — feedback panel confirms the new state
1. Browses the Available Rewards catalog
1. Hits Redeem on a reward — confirmation modal explains the points cost and the approval workflow
1. Submits redemption request; appears in their My Redemptions list as Pending
1. Lead approves/declines (separate MC tab); on approval, points debit from the analyst’s balance
1. On fulfillment, the analyst sees the request status flip to Fulfilled; they receive their PTO or USD per the org’s payout method
1. Optionally downloads a signed PDF, DOCX, or CSV statement from Your Records — a personal copy of the balance, ledger, and redemption history for the analyst’s own files

### Board

**What it’s for:** Async forum for tips, questions, burnout strategies. Posts auto-expire after 7 days (so it’s a current-conversation space, not a permanent record). Each post supports threaded responses so analysts can ask follow-up questions or add comments, and posts and replies can be marked with lightweight reactions (Helpful, Thanks, Insightful, Same here) for low-effort acknowledgement. The same conduct rules and tiered abuse flagging system from peer chat apply here too.

If a post is flagged, it’s temporarily removed from the Board pending review. The flagged content is sealed on the flagger’s device to the enrolled Team Leads and stored as opaque ciphertext in an evidence vault with no expiration (so it can’t disappear before review) — the server and an admin who handles only public keys cannot read it. A lead opens it in the MC Peer Conduct tab, then dismisses the flag (the post returns to the Board) or upholds it (the post stays removed). It’s the same review path as peer skill-share sessions.

**Workflow:**

1. Analyst has a tip to share or a question with no time pressure
1. Posts to Board with a category
1. Other analysts read async, respond via threaded responses, and react to useful posts
1. Posts age out after 7 days

**Flagging workflow:**

1. Analyst sees a post or response that’s inappropriate
1. Flags it with a tier (1: minor / 2: personal attack / 3: urgent — slurs, threats, harassment)
1. Post is removed from Board pending review, stored in evidence vault
1. The Team Lead opens the case in the MC Peer Conduct tab, reviews the sealed evidence and thread context, then dismisses (post returns to the Board) or upholds it (stays removed)

### IR Simulator (this is the AI/ML training feature)

**What it’s for:** Train on YOUR organization’s IR procedures — not generic textbook ones. Each scenario is generated from a real IR policy the lead uploaded. The analyst walks through OBSERVE → ORIENT → DECIDE → ACT phases, makes choices, gets feedback. Tracks IR Policy Mastery level over time. After completion, shows the actual policy that was used so the analyst can verify they’re learning real org procedure.

**Workflow:**

1. Analyst opens IR Simulator at start of upskilling hour
1. Sees their current Mastery level, which policies they’ve practiced
1. Picks a policy they haven’t done yet (or retries one to improve score)
1. Walks through OODA phases with multi-choice decisions, gets feedback per choice
1. Completes scenario — earns points, level may increase
1. Sees the actual policy document used as the source for this scenario — confirms it matches their org’s real procedure
1. As more policies are uploaded by the lead, more scenarios become available

### Skills & Assessments

**What it’s for:** Analyst’s view of their own skill development. Sees assessments assigned by the lead. Sees baseline established from the AC’s automatic baseline assessments at first-launch. Sees gap-driven training recommendations. When proficiency thresholds are crossed, the lead receives a growth signal — this is recognition, not a demand.

**Workflow:**

1. AC’s first-launch baseline assessments establish initial skill profile (private to analyst)
1. Lead later assigns a targeted assessment — analyst sees it here as an Assessment Required notification with a link to the external module
1. Analyst goes to the external platform (HackTheBox/TryHackMe/etc.), takes the module
1. Submits completion report (link, score, date) back through the AC
1. Result populates gap display and training recommendations
1. Lead also sees this targeted assessment’s result (unlike baseline assessments which stay private)
1. Gap areas auto-create training recommendations for that analyst
1. When proficiency improves above threshold: growth signal sent to lead

### Training & Certs

**What it’s for:** AI-recommended training based on assessment gaps. Categorized by skill area (SIEM Queries, Investigation, Escalation, Threat Hunting, Malware Analysis) with proficiency percentages and direct links to training platforms (TryHackMe, LetsDefend, HackTheBox, SANS, Cyberdefenders).

When upskilling hour begins, ticket routing pauses for that analyst and a content filter activates on the AC’s host machine — only training/peer chat/cert sites are accessible during that hour. The content filter uses the host operating system’s native content-filter capability (FireAlive integrates with it rather than reimplementing it). Training URLs in this tab are copyable but not clickable: FireAlive deliberately does not call URLs to avoid exposing the suite to URL-based attacks. The analyst copies the URL into their browser themselves.

**Workflow:**

1. Analyst opens Training during upskilling hour
1. Sees recommended modules by skill area, sorted by current proficiency
1. Copies the module URL (not clickable — no FireAlive-initiated browsing)
1. Pastes the URL into their browser, opens the training module
1. Completes module on the platform
1. Returns to FireAlive, submits completion (module name, platform, URL, date)
1. Lead verifies completion, skill profile updates

### Post-Incident Wellness

**What it’s for:** Personal wellness resources — always available, not just post-incident. Includes both built-in resources (breathing exercises, stress response education, self-care strategies) AND any wellness resources the lead has configured in the MC and propagated to the AC. So the org can add subsidized counseling services, EAP contact info, internal wellness programs, peer support channels, anything else specific to that org’s employee wellbeing offerings.

Tier-3 PRIVATE — the lead literally cannot see whether the analyst accesses these resources. Distinct from technical incident recovery procedures.

**Workflow:**

1. Analyst feels stressed (or just wants to maintain wellbeing)
1. Opens Post-Incident Wellness
1. Uses built-in breathing exercise widget, reads strategies
1. Sees org-specific resources the lead provided (e.g. “Subsidized counseling: contact EAP at…” or “On-site wellness program: schedule at…”)
1. Accesses external mental health resources or org-provided support
1. None of this is logged in a way the lead can see — fully private

### Self-Scan

**What it’s for:** Analyst-initiated 10-point compromise check on their own client. Tests binary integrity, memory analysis, network connections, configuration drift, audit log continuity, TLS pinning, API tokens, filesystem integrity, EDR status, encryption keys. The device-signed, tri-state report (pass / inconclusive / fail) is shown to the analyst and transmitted to the MC over the authenticated channel (self-initiated reports are rate-limited and recorded as a per-analyst self-run) — not optional, because client compromise affects the whole team.

**Workflow:**

1. Analyst notices something off about their machine, or it’s part of weekly hygiene
1. Opens Self-Scan, clicks Run
1. Scan runs the 10 checks in the client’s isolated main process
1. Results display tri-state (pass / inconclusive / fail) per check, each device-signed
1. The device-signed report is transmitted to the MC — lead may follow up on any failed or unverified result

### Audit (AC-side)

**What it’s for:** Local audit log of events on this client. Auto-mirrored to MC. So if questions arise about what the analyst was doing at a specific time, they can see their own log.

### Privacy

**What it’s for:** Analyst’s data privacy controls and consent log. Shows what data is collected at Tier-1 (visible to lead, aggregate only) vs Tier-3 (private to analyst). Consent events log every privacy decision the analyst made.

### Certifications

**What it’s for:** Where the analyst registers their professional industry certifications (CompTIA, ISACA, ISC², GIAC, etc.). Uploads cert file (PDF/image, encrypted), enters verification number. Lead verifies and the cert contributes to the analyst’s skill profile.

-----

# GLOBAL DASHBOARD (CISO read-only view)

The GD aggregates anonymized data from multiple regional MCs. The CISO sees regional health, never individual analyst data. Read-only, separate server.

### Global Overview

Cross-region aggregate health.

### Regional Breakdown

Per-region health bars, automation rates, cert coverage.

### Reports

**What it’s for:** CISO-grade executive reports that aggregate the latest regional metrics pushed in from every connected MC. Five report types are available: Executive Summary (cross-region health, utilization, turnover-risk highlights, recommendations, and FireAlive ROI financials), Global Human Impact Risk Report (per-region churn-cost breakdown), Turnover Forecast, FireAlive ROI, and Compliance by Jurisdiction.

Reports render in three formats: JSON in-app (for the dashboard preview) and signed PDF and DOCX downloads. Every PDF/DOCX is signed with the Global Dashboard’s own Ed25519 report-signing key and stamped with a verification footer (instance label, generation time, signing-key fingerprint), so the recipient can confirm the document is a genuine, unaltered FireAlive artifact – in-app via the authenticated verify endpoint, or independently with OpenSSL per `docs/report-verification.md`. The GD signs its own reports under its own instance key, distinct from any MC’s.

**Workflow:**

1. CISO opens Reports
1. Picks a report type from the dropdown
1. Clicks Generate Report – the GD-Server pulls the latest regional_metrics snapshots from each connected MC and renders the report server-side
1. The dashboard shows the report in-app
1. Clicks Download PDF or Download DOCX to save the signed document; or Export Report for a quick client-side JSON copy
1. Files the PDF/DOCX with board materials or the audit-evidence binder

### MC Connections

**What it’s for:** Manage which Regional MCs feed data here. Register new MCs, view their connection health, offboard decommissioned ones. The connections tab is also the trust-registry admin surface for signing keys.

**Pending Signing Key Approvals queue:** When a Regional MC first connects (and on every key rotation), it submits a signing-key fingerprint that this GD must approve before signed pushes are accepted. The queue at the top of the connections tab shows all pending submissions across all MCs with their full fingerprints. A CISO or signing_key_approver verifies each fingerprint OUT OF BAND with the MC operator (phone, in-person, separate encrypted channel) and clicks Approve or Reject. The Approve click fires a confirmation dialog displaying the fingerprint one more time before the irreversible state transition; the click also sends the fingerprint to the server as a confirmation parameter, so a UI bug pointing approve at the wrong row is caught server-side (CONFIRMATION_FINGERPRINT_MISMATCH). Reject opens a modal capturing a free-form rejection reason (required, ≤500 chars); the reason is recorded in the GD audit log and the GD-side admin view only — never exposed to the MC operator (privacy invariant). Both actions emit MC_SIGNING_KEY_APPROVED / MC_SIGNING_KEY_REJECTED audit events.

**Per-MC Keys panel:** Each MC card has a “Keys” button (becomes “Review keys” in primary styling when that MC has pending submissions, with a per-MC pending count badge). Expanding the panel shows the COMPLETE signing-key history for that MC: every approved, pending, and rejected row with their full fingerprints, registration timestamps, approval metadata (timestamp + approver user id + approver role), rotation metadata (rotated_out_at when the key was demoted by a successor), and rejection metadata (rejected_at + rejected_reason). This panel is the ONLY UI surface where rejected_reason is exposed; the MC-facing status endpoint strips it.

**Top-of-list summary line:** When any MCs have pending submissions, a one-line summary above the MC list names the distinct count and points the operator at the amber “Review keys” affordance.

### Compliance Posture

**What it’s for:** Generate a compliance report against THIS GD-Server’s own running state. Same 16-framework selector as the MC side, same Shared Responsibility two-bucket structure (verifiedControls + customerResponsibility), but the controls checked are GD-specific: cross-region aggregation integrity, signing-key trust registry hygiene, mailbox-pattern fulfillment, GD-side audit log integrity, GD-side encryption, GD-side authentication, GD-side configuration locking. Each report carries the framework name, authority, citation, generation timestamp, and the app version that produced it — useful provenance metadata for audit evidence.

**Workflow:**

1. CISO opens Compliance Posture tab
1. Selects a framework from the 16-option dropdown
1. Clicks Generate Report
1. Sees 4-up summary (Total / Pass / Warn / Fail) plus the verified-control list with status badges, per-control mapping to the framework taxonomy (NIST control id, HIPAA citation, ISO clause), and a remediation pane on any non-pass row describing what the GD operator needs to do to fix the finding
1. Sees the customer-responsibility list below — the controls the OPERATING ORGANIZATION must attest separately for the GD layer (e.g., subprocessor agreements for the GD’s hosting, GD-side personnel access policies)
1. CISO files the report in the org’s audit-evidence binder alongside the corresponding MC reports
1. Click Download PDF or Download DOCX to export the report as a signed, watermarked document (Ed25519 instance signature + verification footer, checkable in-app or offline per `docs/report-verification.md`); hand the PDF directly to the auditor

### Cross-Region Compliance

**What it’s for:** Roll up compliance posture across every connected Regional MC. The matrix view shows framework x MC cells with passed/total counts colored by health (green ≥90%, amber ≥70%, red below). Filter by framework, by MC, or by region to narrow the view. Drill into any cell to see that (MC, framework)’s full-report history — past CISO-requested fulfillments with timestamps, signature fingerprints (for forensic verification), and payload sizes. Click any report row to see the parsed report body: framework summary, full verifiedControls list with status badges, and customerResponsibility list.

If a cell’s most recent report is stale or there’s no full-report history at all, the CISO can request a fresh fulfillment via the **Request Full Report** button. The request follows the mailbox pattern (Foundational Rule 21 — GD never dials MC; data flows MC-to-GD only). The button writes a pending row to the GD-side mailbox; the MC observes the request on its next compliance tick (default 24h cadence) and pushes the full report via the ingest endpoint. After submit, the cell shows a PENDING badge and a top-of-tab pending banner with a Refresh Matrix button that re-fetches the rollup to check for fulfillments.

**Auth:** Cross-Region Compliance reads are gated to ciso / vp / readonly roles; mailbox writes (Request Full Report) are gated tighter to ciso / vp only.

**Workflow:**

1. CISO opens Cross-Region Compliance
1. Reviews the matrix at a glance — colored stats per (framework, MC) cell
1. Optionally narrows with filters (e.g., framework=HIPAA to see one regulation across all MCs)
1. Drills into a specific cell to see the report history
1. Either reads the most recent full report inline or clicks Request Full Report to get a fresh fulfillment
1. After fulfillment lands (MC’s next tick), refreshes the matrix and reviews the new report body

**Cross-instance signing:** each instance signs its own reports under its own report-signing key. The GD signs reports it generates itself – the Compliance Posture single-framework report and the Executive Reports above. Upstream MCs sign reports they generate. Each MC’s full-report history rows in the matrix record that MC’s signature fingerprint; the GD’s signing-key fingerprint identifies any GD-generated artifact. A GD-signed report is attributable to the GD instance, an MC-signed report to that MC – the two key families never overlap.

### Helper Recognition

**What it’s for:** Cross-MC Helper Pay leaderboard. Each active MC pushes its top opted-in helpers on a configurable cadence (default 15 minutes); this tab displays the aggregated view across every connected MC. Only analysts who have explicitly opted in via their AC’s Helper Pay tab appear here, and only their pseudonyms cross the wire — real names, user IDs, and earning details stay on the MC.

The push payload is signed with the MC’s Ed25519 key and verified GD-side via the same signing-key trust registry used for metrics and compliance pushes. Each ingested row carries the signing fingerprint for forensic provenance display.

**Auth:** Helper Recognition reads are gated to ciso / vp / readonly roles. No writes from the GD side — the data flows one-way (MC → GD).

**Workflow:**

1. CISO opens Helper Recognition
1. Sees the matrix at a glance — one card per active MC with that MC’s top 5 inline
1. Clicks a card to drill into that MC’s full top-50 leaderboard
1. Drilldown shows each helper’s pseudonym, sessions, average rating, points, plus a truncated signing fingerprint per row (hover for full value)
1. Uses for cross-region comparison (“which MC has the highest engagement?”), recognition reporting up the leadership chain, or forensic correlation between this surface and the GD audit log

### MC Offboarding

When a regional SOC is decommissioned, offboard its MC. Historical data retention per policy.

### CISO Notifications

Threshold alerts when any region crosses critical lines (burnout health below threshold, SLA below %, turnover risk high).

### Query Tool

Run cross-region queries: burnout trends, turnover risk, cert gaps, automation ROI.

### System Health

**What it’s for:** Self-monitoring of the GD server itself. A subsystem-health rollup (built in B6a) draws from the GD metrics collector — fleet and ingest freshness, compliance coverage, signing-key status, audit-chain integrity, backup status, unacknowledged notifications, integration health, and live runtime metrics (CPU / memory / heap / DB-read rate / monitored file count) — behind `GET /api/system/health-metrics`. The runtime monitor underneath it runs continuous file-integrity monitoring over the GD server tree plus CPU / memory / DB-read anomaly detection with hysteresis, and routes any anomaly through the GD alert router. See `docs/runtime-monitoring-and-system-health.md`.

### Monitoring Integrations

**What it’s for:** The GD’s self-protection console (built in B6a) — connect the GD server to the org’s monitoring stack so compromise of the GD *itself* is detected and routed, and never analyst data (the GD holds none). It configures SIEM (CEF over syslog TCP/UDP/TLS) and SOAR push, the operational alert-email recipients and webhook target, and an editable per-severity × channel alert-routing matrix (info / warning / high / critical fanned across audit / SOAR / SIEM+email / in-app notification / webhook, with audit always on). It runs opt-in, read-only dependency probes over the GD’s own KMS, backup storage, and MC-trust coverage (run-now plus cached results). It registers an optional external EDR provider (eleven supported, from CrowdStrike Falcon and Microsoft Defender for Endpoint to Wazuh and LimaCharlie) with AES-256-GCM-encrypted credentials — additive on top of the in-platform runtime-monitor baseline. And it shows live runtime-monitor metrics with editable sustained-load thresholds. The GD’s own security events — a rejected MC ingest signature, an audit-chain break, a rejected MC signing key — route through the same alert router so they fan out to SIEM / SOAR / notification / webhook on top of the always-on audit. See `docs/runtime-monitoring-and-system-health.md`.

### High Availability

**What it’s for:** A warm standby and automated failover for the Global Dashboard server. Losing the GD does not stop analysts working — the regional servers keep serving them — but it blinds cross-region visibility exactly when several regions are in trouble at once, which is when a CISO needs that view most. Two GD nodes pair over a mutually authenticated peer link: one runs **active** and holds the write lease, the other runs **passive**, replicating continuously and refusing every write. If the active is lost, the passive promotes itself. The feature is **opt-in** — a GD that has never been paired behaves exactly as it did before, and every gate described here fails open on a standalone node.

**Why active/passive, and not a cluster:** Exactly one node is entitled to write at any moment, and that entitlement is verifiable from the database itself rather than from a convention everyone agrees to follow. Write authority is an internal **cryptographic lease at a monotonically increasing epoch**, and the database refuses any change that would lower the epoch, so a recovered stale active cannot resurrect itself and diverge. Your load balancer routes client traffic and nothing more — a flapping or even compromised balancer can affect availability but can never create split-brain, because a node that does not hold the lease refuses to write. Active/active would mean last-write-wins on compliance evidence, key material, and audit chains, which is not a trade a CISO can accept; multi-node clustering solves a problem a console for a handful of executives does not have. Neither is offered.

**The key model:** The GD’s encryption key is sealed to that node’s own hardware root, so a standby cannot simply be handed a copy. During pairing, the shared material is wrapped to the standby’s hardware-bound key; the standby stores it sealed and can unwrap it only on the hardware it was wrapped to, and only at promotion. Two things follow. Sessions survive a failover — the promoted node installs the shared session secret, so nobody is forced to sign in again mid-incident. And a node holding no sealed material refuses to promote rather than coming up unable to read its own encrypted columns.

**What it does, honestly:** Replication is **asynchronous** — the active journals its changes and ships them to the standby on a configurable interval — so failover has a **bounded recovery point, not zero data loss**. Whatever the active had journalled but not yet shipped is lost when it dies, and the tab shows the current replication lag so that number is watched rather than assumed. A passive is fenced on every write path, not merely expected not to write: mutating requests are refused, background jobs are gated, and the replicated alert notification is withheld. Reads always pass and the HA controls stay reachable, or a standby could never be paired, promoted, drilled, or recovered.

**Promotion, and when it is refused:** The active heartbeats and renews its lease; the passive promotes once the heartbeat has been stale for longer than the configured miss count. A passive that has never heard a heartbeat does not promote, so a freshly paired standby cannot take over in the seconds before the first one arrives. Promotion is refused, and audited, when the node holds no sealed material — and, in Cloud Mode, when it cannot re-attest as a genuine confidential VM at the moment it would take write authority. That second refusal is deliberate: attestation is time-bounded evidence, and a node verified when it paired may since have been live-migrated, rebooted into a debug state, or had its guest replaced. **Integrity over availability** — and the regional servers keep serving analysts throughout. There are two further ways a node steps down: an active that discovers its peer holds a higher epoch adopts it and demotes, and an active cut off from **both** its peer and its clients past the self-fence timeout demotes itself. Both signals are required, so an active that is still serving the CISO is never fenced merely because its peer is unreachable.

**Self-test:** The drill is a **real failover, not a simulation**, and the tab says so before you confirm. This node steps down, the peer promotes and is checked that it serves the fleet and that its data matches, and then this node takes the lease back. Writes are refused for the few seconds in between. It reports the measured failover and fail-back times, whether the peer served, whether integrity held, and whether the original was restored — so the failover window is a number you measure, not one you take on faith. If the original did not take the lease back, the peer is still active: a safe state, but not the one you started in.

**Manual failover:** Run from the active, it steps down **first** and only then signals the peer to promote, so this node has stopped writing before the peer starts. If the signal cannot be delivered, the peer promotes on its own once it notices the active is gone. There is no undo from that node and no automatic fail-back — to come back, run a manual failover from whichever node is then active.

**What reaches the SOC:** HA lifecycle events — a promotion, a refusal, a demotion, a self-fence, a pairing, a rejected peer certificate, a drill — are appended to the tamper-evident audit chain and streamed to the configured SIEM as CEF, at severities chosen for what an analyst should be paged about. A refused promotion is critical. An unplanned or operator-driven takeover is high. A single rejected peer certificate is only a warning, because one is usually a certificate rotation on the peer and a burst of them is what a correlation rule should catch. Operator-initiated events carry the operator’s identity. **These events reach the SIEM only** — not SOAR, email, or webhooks; if you need a page, build the rule in your SIEM. A drill run against a scratch copy of the database emits nothing at all, so a rehearsal can neither forge an audit row nor page a SOC with a failover that never happened.

**Workflow:**

1. CISO opens High Availability and reviews this node’s role, its peer, and the replication lag
1. On the node that will be the standby, generates a one-time pairing token — it is shown once and it expires
1. Carries the token to the node that will be the active and pairs from there; the two nodes verify each other’s hardware anchors, wrap the shared key material to the standby’s hardware, and ship a baseline
1. Tunes the live knobs as needed — sync interval, heartbeat interval, lease TTL, miss count, promotion cooldown, self-fence timeout — which take effect without a restart
1. Runs the self-test to confirm the pair is genuinely ready and to learn the real failover time
1. If the active fails, the passive promotes itself within the detection window and the load balancer routes to it
1. Brings the failed node back up; it finds the peer holding a higher epoch, adopts it, stays passive, and replicates from the new active

The full operator runbook — the lease/epoch authority, the sealed-key exchange, replication and the bounded recovery point, the per-deployment tailoring, exactly what reaches the SIEM, and the recovery procedures — is in `docs/gd-high-availability.md`.

### IAM & Access / MFA / Posture / WiFi / Compromise Scan / Vulnerability Scan / Regression Test / Cloud & IaC / SDN-SASE / Backup / Data Sovereignty / Recertification / Troubleshooter / App Updates

Same purposes as MC equivalents but scoped to the GD server (which is independent infrastructure separate from the regional MC). The GD Troubleshooter, though, is rule-based only — the Global Dashboard runs no model — and returns the same kind of structured findings, without an AI summary. The GD **Compromise Scan** is its own self-scan (built in B6a): `POST /api/compromise-scan` runs eleven read-only self-integrity checks of the GD server — database integrity, audit-chain continuity, signing-key validity, hardware instance-anchor status, file-integrity, config-lock presence, memory, Node runtime, and more — reporting pass / warn / fail per check and clean / warnings / compromised overall. **Config Lock** (under Posture) is the GD twin of the MC control: engaging the lock is immediate and freezes configuration-mutating requests, while releasing it requires a fresh hardware-passkey (WebAuthn) assertion bound to the CISO’s own credential — there is no TOTP path on the GD.

### Audit & Forensics

Audit trail visibility for the GD layer — separate audit log from the regional MCs.

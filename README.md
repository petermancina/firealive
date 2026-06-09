# FireAlive — SOC Analyst Burnout Prevention Platform

**Version:** v1.0.57 | **License:** AGPL-3.0-or-later | **Author:** Peter Mancina  
**E-fuse counter:** 50 (anti-rollback)

-----

## What Is FireAlive?

FireAlive is an open-source, privacy-first platform that prevents burnout in Security Operations Center (SOC) analysts. It uses AI-driven burnout signal detection, capacity-aware ticket routing, peer support, upskilling scheduling, and skills assessment to keep SOC teams healthy, productive, and retained.

FireAlive is grounded in peer-reviewed research on burnout — both SOC-analyst-specific findings and the broader cross-industry literature on burnout prevention. AI-generated suggestions for Team Lead interventions are drawn from a knowledge base of that peer-reviewed research, so the recommendations a lead sees are traceable to evidence rather than ungrounded model output.

The name plays on the notion of burnout — FireAlive keeps the fire burning long.

> **📘 New: See <FEATURE-GUIDE.md>** for plain-language descriptions of every feature in the FireAlive suite — what each feature is for, who uses it, when, and the workflow to use it. The Feature Guide is the source of truth for what each feature is supposed to do, and is bundled with every distribution. It’s also the reference behind the in-app Help articles in the MC, AC, and GD.

-----

## Installation

> **⚠️ Pre-Release Notice:** FireAlive is in pre-release. It should be evaluated in a lab or sandbox environment before any production deployment. SOC teams should thoroughly test all integrations, routing logic, and security controls in a non-production setting before relying on FireAlive for operational use. Community testing, feedback, and contributions are welcome.

**Download installers:** Pre-built installers for Mac (.dmg), Windows (.exe), and Linux (.AppImage) are available on the [Releases page](https://github.com/petermancina/firealive/releases/tag/v1.0.57) under Tags.

See **SETUP.md** for detailed setup instructions, and **FEATURE-GUIDE.md** for what each feature does and how to use it.

### Quick Start (Development)

```bash
git clone https://github.com/petermancina/firealive.git
cd firealive && npm install
node server/index.js                    # Regional Server on :3000
cd packages/global-dashboard-server && node index.js  # GD Server on :4001
cd packages/analyst-client && npm start  # AC Electron app
cd frontend && npm start                 # MC Electron app
cd packages/global-dashboard && npm start # GD Electron app
cd packages/abuse-review-console && npm start # ARC Electron app
```

### Environment Variables (Optional Features)

Some FireAlive features require a deployment-time environment variable to enable. These are intentionally **not set by default** — opt in only when you’re ready and have considered the security implications.

|Env Var           |Purpose                                                                                                                                                            |Required For                  |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------|
|`GD_ALLOWED_HOSTS`|Comma-separated allow-list of GD-Server hostnames the MC may push to. Hostname-only (no port). Case-insensitive exact match — no wildcards, no subdomain semantics.|Global Dashboard push pipeline|

Example:

```bash
GD_ALLOWED_HOSTS=gd-prod.corp.local,gd-staging.corp.local
```

The **Global Dashboard push feature is disabled by default.** If `GD_ALLOWED_HOSTS` is unset or empty, the MC will reject any URL passed to `PUT /api/gd-config` and the recurring push service will refuse to send. This is the primary SSRF defense — the URL the MC sends to is restricted to a pre-approved set chosen at deployment time, not freely entered by an admin in the UI. See **Security.md** for the full threat model.

To enable GD push:

1. Set `GD_ALLOWED_HOSTS` on the MC server (env var, systemd unit, container env, etc.) and restart the MC process.
1. In the MC UI, open the Global Dashboard tab and configure the URL + API key. The URL’s hostname must be in the allow-list.
1. Click Save (with Enabled left off).
1. Click Test Connection. The MC reads the saved config and tests it against the GD-Server.
1. If Test passes, edit the config and toggle Enabled on, then Save again. The recurring push begins on the configured cadence.

### Building Installers

```bash
cd packages/analyst-client && npm run build:mac   # .dmg
cd frontend && npm run build:win                   # .exe
cd packages/global-dashboard && npm run build:linux # .AppImage
cd packages/abuse-review-console && npm run build:mac # .dmg
```

-----

## Architecture

Six components:

|Component                     |Technology                |Purpose                                                                                                                                                                     |
|------------------------------|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|**Analyst Client (AC)**       |Electron + React          |Desktop app for individual SOC analysts                                                                                                                                     |
|**Management Console (MC)**   |Electron + React          |Team Lead configuration and management                                                                                                                                      |
|**Abuse Review Console (ARC)**|Electron + React          |Independent abuse reviewer’s app (separate from team leadership) — opens abuse flags client-side with the reviewer’s own private key; the server cannot decrypt flag content|
|**Regional Server**           |Node.js + Express + SQLite|Backend API, routing engine, all services                                                                                                                                   |
|**Global Dashboard (GD)**     |Electron + React          |CISO cross-region oversight                                                                                                                                                 |
|**GD Server**                 |Node.js + Express + SQLite|Aggregates data from regional servers                                                                                                                                       |

All four Electron apps (AC, MC, ARC, GD) are self-contained: their UI is precompiled in CI via esbuild into one `app.js` per app, React/ReactDOM are bundled in, every `index.html` loads only that single file, both CSP layers (meta tag + response header) are locked to `script-src 'self'`, and there are no runtime CDN fetches and no runtime transpiler. The apps run in restricted and air-gapped networks and make no external network calls for UI code.

### Backend Services (37 files)

|Service               |Purpose                                                                                   |
|----------------------|------------------------------------------------------------------------------------------|
|AI Burnout Engine     |Baseline creation, signal drift detection, AI message generation, training recommendations|
|Assessment Service    |Create/assign/submit assessments, skill tracking, gap analysis                            |
|Backup Service        |Real filesystem backups, SHA-256 integrity verification, scheduling                       |
|Compliance Scanner    |Real checks against actual app state for 16+ frameworks                                   |
|Regression Runner     |35 real tests checking DB tables, crypto, integrations, middleware                        |
|Integration Manager   |SOAR/Ticketing/SIEM/IAM connection testing and config storage                             |
|Notification Service  |Proactive break alerts, shift handoff notifications, assessment assignments               |
|System Health Monitor |Real CPU/memory/heap/DB metrics via Node.js APIs                                          |
|Feature Toggle Service|Enable/disable 20 features without removing code                                          |
|Metrics Collector     |Full-suite metrics for monitoring + CEF output for SIEM                                   |

### Security Middleware (9 modules, 877 lines)

|Module            |Protections                                                                                          |
|------------------|-----------------------------------------------------------------------------------------------------|
|security-hardening|Headers, input sanitization, CSRF, anti-replay, rate limiting, SSRF, TLS                             |
|auth-hardening    |Constant-time comparison, CSPRNG, account lockout, JWT rotation, suspicious input detection          |
|ai-security       |Prompt injection (12 patterns), context limits, output validation, data firewall                     |
|network-security  |DDoS/slowloris, DNS size limits, client heartbeat, mTLS, anti-pivot                                  |
|cors-policy       |Zero-trust CORS, known origins only                                                                  |
|pentest-hardening |Token storage (memory only), safe errors, request correlation, content-type enforcement, idle timeout|
|audit             |Tamper-evident: per-row SHA-256 hash chain + Ed25519-signed checkpoints                              |
|auth              |JWT + RBAC                                                                                           |
|network-hardening |Additional network protections                                                                       |

### API Routes

All endpoints require JWT authentication. Manager-only endpoints enforce RBAC.

**v1 API (25 endpoints):** Signal recording, baseline retrieval, training recommendations, assessment CRUD, backup create/history/schedule/restore, compliance scan, regression test, integration save/test/status, system health, client heartbeat, notifications, config lock, SLA, shift handoff, config snapshots.

**v054 API (18 endpoints):** SOAR/Ticketing config, routing engine, IAM offboarding, upskilling scheduling, helper pay, pseudonym rotation, compliance reports, training submissions.

**v059 API (8 endpoints):** Feature toggles, full-suite metrics (JSON + CEF), audit integrity, cloud migration packages, CI/CD config, full-suite regression, full-suite backup.

**IAM API (/api/iam):** Periodic recertification of analyst accounts. Lists analysts whose IAM check is overdue, confirms active status or marks offboarded.

**Upskilling API (/api/upskilling):** Per-analyst upskilling time slot management. Lists configured slots and saves/updates one-hour windows.

**Recovery Runbook API (/api/runbook, 3 endpoints):** Curated FireAlive-specific failure and compromise scenario library backing the Recovery Runbook generator. 38 scenarios across 8 categories (Identity & Authentication, Inter-Component Communication, Cryptography & Keys, Storage & Data, Integrations, Application Integrity, Burnout-Specific Abuse, Operational Failures). Each scenario produces two artifact types — a single-page Quick Reference card and a Full Runbook with full procedure (identification, containment, eradication, recovery, verification, post-incident review) — in three formats: PDF, DOCX, or JSON. The org’s general IR runbooks are not in scope; this library specifically addresses the new attack surface and failure modes that FireAlive’s adoption introduces.

**TTX Generator API (/api/ttx, 3 endpoints):** Tabletop exercise document generator. Curated scenario library producing Situation Manuals and blank After-Action Report templates in PDF and DOCX. Document structure follows HSEEP Volume IV and NIST SP 800-84 conventions.

**AI Provider API (/api/ai-provider, 8 endpoints):** Unified AI dispatcher and local LLM management. FireAlive uses internal AI only — the dispatcher runs every call on the bundled local LLM; per-feature config tunes generation (max tokens, temperature). Status, config CRUD, model verify/load/unload, provisioning guide, recent inference log. Backed by `server/services/ai-provider.js` (dispatcher), `server/services/internal-llm.js` (node-llama-cpp wrapper, default model: Phi-4 Q4_K, MIT, verify-only — provisioned by the operator, never downloaded), and `scripts/download-model.js` (verify-only provisioning — verifies operator-provided files against source-pinned SHA-256s; no network). Inference audit log records token counts and metadata only — prompt and response content are NOT stored, to protect Tier-3 burnout data. The IR Simulator scenario generator (F4b) and burnout intervention message generator (N1b) route through this dispatcher. Statistical features like burnout signal detection and burnout-aware routing remain rule-based for determinism, speed, and audit clarity.

**AI Burnout API (/api/ai-burnout, 3 endpoints):** Read/refresh access to the precomputed burnout-message caches. Analysts retrieve their own per-signal interpretations (Tier-3, decrypted only for the owning analyst); team leads retrieve team-level intervention prompts (Tier-1 aggregate, with active conditions recomputed live) and can trigger a refresh (rate-limited and audited). No inference runs in the request path — the scheduler precomputes and caches content, and these endpoints serve fresh cached rows or an honest AI-unavailable state, never canned advice. All AI content is strictly grounded in the research KB: every citation is validated against the 42-entry KB and any off-KB reference is rejected rather than served, so a hallucinated citation cannot reach a user. Backed by `server/services/burnout-message-generator.js` (orchestration + citation gate), `server/services/research-kb.js` (authoritative KB + validator), `server/services/team-health.js` and `server/services/team-conditions.js` (server-side team-state computation), with two scheduled precompute jobs in `server/services/scheduler.js`.

**IR Simulator API (/api/ooda, 15 endpoints):** OODA-loop incident response training generator. Team leads upload IR policies, playbooks, and after-action reports; the system generates choose-your-own-adventure decision-tree training scenarios calibrated to a chosen scenario type (8 categories: ransomware, phishing, data exfil, insider threat, APT, DDoS, supply chain, credential compromise) and difficulty (beginner / intermediate / advanced). Analysts work through the scenarios node-by-node, getting explanations on each correct or incorrect choice. Backed by `server/services/ooda-scenario-generator.js` (orchestration), `server/services/ir-policy-parser.js` (rule-based extraction of detection signals, decision points, escalation paths, roles, containment actions, and communications obligations from uploaded policy text), `server/services/ooda-generation-jobs.js` (background worker for async batched generation; bounded in-process concurrency with crash recovery and per-scenario persistence), and the AI Provider dispatcher (the LLM call). The scenario generator validates every model output structurally — node count bounds, OODA-phase progression, exactly-one-correct-choice per decision node, all `nextNodeId` references resolve to real nodes, exactly one resolution node — and rejects malformed responses rather than persisting a broken scenario. Per-policy replenishment configuration drives auto-generation: threshold mode auto-refills when an analyst’s unplayed pool drops below a configured floor, scheduled mode generates batches at fixed times, manual mode disables auto-generation. Per-analyst progress tracked in the canonical `ooda_progress` table; aggregated training metrics (completion rate by scenario type, by difficulty, recent activity feed) available via `GET /api/ooda/mastery` (analyst-only access).

**Upload security (defense in depth, applies to /api/ooda/policies and /api/ooda/aar):** Two scan layers run on every uploaded policy and after-action report before any database write. Layer 1 (`server/services/content-sanitizer.js`) is a deterministic FireAlive-specific scanner — it catches threats that originate from how FireAlive uses the uploaded content, particularly LLM prompt injection (instruction-override patterns, role-switching jailbreaks, chat-template token injection, output-shape hijacking), embedded executables (shell shebangs, PowerShell IEX, VBA macros, reverse-shell signatures, pipe-to-shell installers, suspicious base64 blobs), and encoding attacks (null bytes, RTL override, zero-width invisibles, Unicode tag-character smuggling). Layer 2 (`server/services/integration-manager.js inspectFile()`) routes through the multi-vendor malware scanner system — 15 supported vendors (ClamAV, VirusTotal, CrowdStrike Falcon Sandbox, Microsoft Defender for Endpoint, SentinelOne, Cisco Secure Endpoint, Fortinet FortiSandbox, Trellix ATD, Sophos Intelix, Joe Sandbox, Hybrid Analysis, Palo Alto WildFire, BlackBerry Cylance, Trend Micro DDAN, Kaspersky Sandbox) — catching novel malware signatures and threat-intel matches that the internal sanitizer cannot stay current on. Both layers fail-closed: either layer’s rejection blocks the upload. **IR Simulator uploads (/policies and /aar) require at least one enabled scanner**: if no scanner is configured, layer 2 returns “skipped” and the upload is rejected with HTTP 422 and code MALWARE_SCANNER_REQUIRED. Other upload paths in the codebase may still tolerate skipped EDR; this hard gate is local to the IR Simulator routes because their content becomes LLM context for scenario generation.

-----

## How It Works

### First-Time Setup Flow

1. Team Lead installs MC → MC starts Regional Server automatically
1. Team Lead configures authentication (built-in CA + LDAP directory), SOAR, Ticketing, SIEM, EDR
1. Team Lead provisions Analyst Clients
1. Analysts install AC, trust the FireAlive CA, and authenticate with a passkey or client certificate
1. First shift: AI Burnout Engine records 8 signal readings → baseline established
1. After baseline: AI generates real-time drift detection + training recommendations
1. CISO installs GD → registers regional MCs → sees cross-region health

### Locking Configuration (Required Hardening)

Before promoting the deployment to production, an admin **must** lock the configuration to prevent runtime changes. The platform ships unlocked because initial setup (KMS, IAM, integration onboarding, backup signing keys, etc.) needs to happen before the first authenticator is even enrolled — but unlocked is a setup-time state, not the production state. Lock/unlock requires a fresh WebAuthn step-up (a user-verified passkey assertion) and is **admin-role-only**. Use the **Lock All Configs** button in the MC or GD sidebar.

When locked, every configuration-write endpoint returns HTTP 423 Locked. A single registry-driven chokepoint covers all of them — not only the platform-config routers (KMS, IAM, backup signing keys, integrations, GD push config, scheduling, external restore, AI provider, malware scanners, backup destinations, backup push, audit retention, API keys) but also the in-app feature settings (EDR, posture, geo-fencing, threat-hunting, pseudonyms, recertification, access control, and the rest). Reads pass through — admins can still inspect config state. Operational routes (backup creation, restore execution, incident routing, scans, alert approvals) are unaffected, so production incident response is never blocked by the lock.

Unlocking starts a sliding idle window: the platform auto-relocks after a period of no configuration activity (default 15 minutes, admin-configurable), so a walked-away admin session cannot leave configuration writable. A continuous-integration coverage guard fails the build if any configuration endpoint is ever added without being placed behind the lock.

In smaller SOCs where one person handles both Team Lead and Platform Admin duties, assign the `admin` role to that user; the codebase does not collapse the role boundary, which preserves SoD for orgs that do separate the roles.

Audit events: `CONFIG_LOCK_ENABLED`, `CONFIG_LOCK_DISABLED`, `CONFIG_LOCK_GATE_HIT`, `CONFIG_LOCK_AUTO_RELOCK`, `CONFIG_LOCK_BYPASS_ATTEMPT`.

### Burnout Prevention Routing

When active (requires SOAR + Ticketing configured):

- FireAlive reads queue metadata via Ticketing (READ-ONLY)
- AI assesses each analyst’s capacity score from burnout signals
- FireAlive writes ticket assignments via SOAR (WRITE) to the analyst with highest capacity
- Analysts with elevated signals automatically receive lighter ticket loads
- Anonymity is architecturally enforced — Team Lead never sees which analyst requested reduction

### Privacy Architecture

- **Tier-3 data** (individual burnout signals): encrypted on client, never visible to Team Lead
- **Tier-1 data** (team aggregates): Team Lead sees averages, never individual data
- **GD level**: CISO sees regional health only, no individual data
- Pseudonyms protect analyst identity in all UIs. UUID stays constant across rotations.
- **Peer chat** and **lead chat** are both genuinely end-to-end encrypted via the Signal protocol (libsignal), each on its own key domain. Lead chat is pseudonymous-to-the-lead. The server is a content-blind relay and cannot decrypt either channel.
- **Abuse-flag content** (peer-session, board-post, and lead-chat reports) is sealed on the flagger’s device to the active reviewer recipient set — a multi-recipient X25519 envelope — before it leaves the app. The server stores only opaque ciphertext and cannot decrypt it; review and disposition happen only in the independent **Abuse Review Console** (ARC). Neither management, nor any team lead, nor an admin (who handles only public keys) can read flag content. See the mandate below.

### Independent abuse review (mandate)

Every FireAlive deployment must designate at least one **independent abuse reviewer** before abuse reporting can be used. The role `abuse_reviewer` is separate from team leadership: it sits outside the chain of command an analyst reports into, because a lead may be the subject of a report. Where the deployment cannot maintain a true separation — for example, where one person holds both team-lead and platform-admin duties — a reviewer drawn from HR, an ethics committee, or another independent function is required.

**Multi-reviewer, zero-access.** Each designated reviewer generates their own X25519 keypair on their own device, behind a passphrase only they know. The public key is registered with the server via the MC’s Audit → Abuse Reviewers panel; the private key never leaves the reviewer’s device. Flag content is sealed on the flagger’s device to ALL active reviewer public keys at once (a multi-recipient envelope); any one reviewer opens it with their own private key. No private key is ever shared, exported, or transferred between people, and the admin only ever handles public keys — true zero-access, in the sense that the server, the admin, and any DB or key insider cannot decrypt flag content. Adding a reviewer is registering another public key to the set; removing one is revoking it.

**Until at least one reviewer is registered, abuse reporting is disabled** — with no reviewer public key, nothing could be decrypted, and the flagger’s app shows an explicit message saying so. The Abuse Review Console enforces a 12-character passphrase minimum on key generation, holds the unlocked private key in main-process memory for the session only (a 5-minute inactivity hard-lock clears it), and never returns the private key to its renderer.

### Signed reports & verification

Every exportable report FireAlive generates — compliance reports, Report Engine output, helper-pay statements, and abuse-flag submission reports — is signed by the instance’s Ed25519 **report-signing key**, a key family distinct from the forensic, legal-hold, backup, chain, GD-push, and cloud-IaC signing keys (a compromise of one family taints none of the others). Each report carries a footer with the human-readable instance label, the UTC sign time, a report id, the short signing-key fingerprint, and a verification hash — so a genuine FireAlive report cannot be forged or altered and passed off as legitimate.

Verification is **authenticated only — there is no public endpoint**. A public hash-verify endpoint would let an adversary grind hashes to enumerate or confirm accusations, so abuse-flag reports verify solely for an independent `abuse_reviewer`; compliance and Report Engine reports for admin/CISO; helper-pay statements for the owning analyst or an admin. The appeal path for a dismissed accusation is therefore out-of-band: the accuser presents their exported report to HR or a court, who ask an independent reviewer to confirm it against the system. Because the verification ledger is permanent and append-only, a dismissed accusation stays verifiable indefinitely.

Reports can also be verified **independently, with no FireAlive tooling and no trust in the running system**, using OpenSSL against the instance’s published Ed25519 public key — see [`docs/report-verification.md`](docs/report-verification.md). Abuse-flag reports are zero-access end to end: the signature covers a canonical data record containing only a content hash, never the report text, so the server signs and records a verifiable report without ever holding the plaintext.

-----

## Compliance

Compliance reports for 16 frameworks: NIST CSF, ISO 27001, SOC 2, HIPAA, GDPR, DORA, CCPA, PIPEDA, LGPD, PDPA, APPI, POPIA, NIS2, CPS 234, Cyber Essentials, FISMA.

Each report follows a **Shared Responsibility** model split into two halves:

- **verifiedControls** — technical controls FireAlive observes by inspecting its own running state. Categories: access control (RBAC), encryption (AES-256-GCM at rest, TLS in transit, libsignal for chat E2EE, X25519 multi-recipient envelopes for abuse-flag content), audit trail (per-row SHA-256 hash chain + Ed25519-signed checkpoints, append-only), authentication (passwordless client certificates + FIDO2/WebAuthn passkeys, with JWT sessions), configuration management (e-fuse anti-rollback), incident response infrastructure (CISM retro protocol, routing-disable kill switches), data protection (pseudonymization, Tier-3 isolation), network (SIEM/SOAR), backups, notifications, and AI engine status.
- **customerResponsibility** — organizational, procedural, physical, and contractual controls the operating organization must attest separately. Examples: risk-analysis methodology, workforce sanction policy, designated security official, business associate / data processor contracts, physical safeguards on the deployment environment, breach-notification procedures, board-level governance evidence (ISO 27001 management review minutes, internal audit reports), subprocessor agreements and data-transfer impact assessments. For HIPAA, verifiedControls covers 19 controls; customerResponsibility covers 42. The ratio varies by framework but reflects the reality that software handles a minority of any major compliance regime.

Three reporting surfaces:

- **MC → Reports & Compliance tab** — per-region operational view. The MC generates reports against its own running state.
- **GD → Compliance Posture tab** — CISO view of the GD-Server’s own compliance posture (cross-region aggregation integrity, signing-key trust registry, mailbox-pattern fulfillment).
- **GD → Cross-Region Compliance tab** — framework × MC matrix sourced from MCs’ pushed compliance summaries. Drill into any cell for that MC’s full-report history, request a fresh fulfillment via the per-cell Request Full Report button, and inspect per-control parsed report bodies when fulfilled. Active MCs only.

See **SETUP.md → Shared Responsibility in Compliance Reports** for the operator-facing framing of what compliance reports do and do not tell you.

-----

## Integrations

|System            |Access    |Purpose                                                                                       |
|------------------|----------|----------------------------------------------------------------------------------------------|
|SOAR              |WRITE     |Burnout-aware ticket distribution                                                             |
|Ticketing         |READ-ONLY |Queue metadata for routing                                                                    |
|SIEM              |PUSH (CEF)|Health metrics, security events                                                               |
|IAM               |READ      |Certificate authority, directory, offboarding detection                                       |
|EDR               |READ      |Malware scanning of uploads/data                                                              |
|Malware Scanners  |READ      |15-vendor multi-provider malware scanning for IR Simulator uploads (see Upload Security above)|
|Scheduling        |READ      |Shift data for upskilling                                                                     |
|Training Platforms|LINK      |Assessment modules, training content                                                          |
|KMS               |READ/WRITE|Encryption key management                                                                     |

-----

## License

GNU Affero General Public License v3.0 (AGPL-3.0-or-later)
Copyright (C) 2026 Peter Mancina

# FireAlive — SOC Analyst Burnout Prevention Platform

**Version:** v1.0.83 | **License:** AGPL-3.0-or-later | **Author:** Peter Mancina  
**E-fuse counter:** 76 (anti-rollback) | **Build:** 20260713.1

-----

## What Is FireAlive?

FireAlive is an open-source, privacy-first platform that prevents burnout in Security Operations Center (SOC) analysts. It uses AI-driven burnout signal detection, capacity-aware ticket routing, peer support, upskilling scheduling, and skills assessment to keep SOC teams healthy, productive, and retained. It is designed for use in tandem with your alert fatigue prevention automation tools.

FireAlive is grounded in peer-reviewed research on burnout — both SOC-analyst-specific findings and the broader cross-industry literature on burnout prevention. AI-generated suggestions for Team Lead interventions are drawn from a knowledge base of that peer-reviewed research, so the recommendations a lead sees are traceable to evidence rather than ungrounded model output.

The name plays on the notion of burnout — FireAlive keeps the fire burning long.

> **📘 See [FEATURE-GUIDE.md](FEATURE-GUIDE.md)** for plain-language descriptions of every feature in the FireAlive suite — what each feature is for, who uses it, when, and the workflow to use it. The Feature Guide is the source of truth for what each feature is supposed to do, and is bundled with every distribution. It’s also the reference behind the in-app Help articles in the MC, AC, and GD.

-----

## Installation

> **⚠️ Pre-Release Notice:** FireAlive is in pre-release. It should be evaluated in a lab or sandbox environment before any production deployment. SOC teams should thoroughly test all integrations, routing logic, and security controls in a non-production setting before relying on FireAlive for operational use. Community testing, feedback, and contributions are welcome.

**Download installers:** Pre-built installers for Mac (.dmg), Windows (.exe), and Linux (.AppImage) are available on the [Releases page](https://github.com/petermancina/firealive/releases/tag/v1.0.83) under Tags.

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
```

### Building Installers

```bash
cd packages/analyst-client && npm run build:mac   # .dmg
cd frontend && npm run build:win                   # .exe
cd packages/global-dashboard && npm run build:linux # .AppImage
```

-----

## Architecture

Five components:

|Component                     |Technology                |Purpose                                                                                                                                                                     |
|------------------------------|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|**Analyst Client (AC)**       |Electron + React          |Desktop app for individual SOC analysts                                                                                                                                     |
|**Management Console (MC)**   |Electron + React          |Team Lead configuration and management                                                                                                                                      |
|**Regional Server**           |Node.js + Express + SQLite|Backend API, routing engine, all services                                                                                                                                   |
|**Global Dashboard (GD)**     |Electron + React          |CISO cross-region oversight                                                                                                                                                 |
|**GD Server**                 |Node.js + Express + SQLite|Aggregates data from regional servers                                                                                                                                       |

All three Electron apps (AC, MC, GD) are self-contained: their UI is precompiled in CI via esbuild into one `app.js` per app, React/ReactDOM are bundled in, every `index.html` loads only that single file, both CSP layers (meta tag + response header) are locked to `script-src 'self'`, and there are no runtime CDN fetches and no runtime transpiler. The apps run in restricted and air-gapped networks and make no external network calls for UI code.

### Deployment Modes

The Regional Server runs in one of five mutually exclusive deployment modes, chosen once at first boot and sealed to the hardware root of trust so it cannot be changed later. Every mode keeps the same hardware-anchored identity and anti-cloning guarantees; they differ in the substrate the server runs on and the network boundary it enforces.

- **Bare metal** — a direct host process on dedicated hardware with a TPM 2.0. The simplest, hardest-to-copy substrate.
- **Virtualized** — a VM with a vTPM, adding clock-integrity and clone/rollback quarantine so a paused, snapshotted, or migrated VM is caught fail-closed. See [`docs/anti-cloning-and-virtualization.md`](docs/anti-cloning-and-virtualization.md).
- **Cloud** — a confidential VM on AWS, Azure, or GCP, adding confidential-computing attestation at boot and refusal of spot or autoscaled instances.
- **SDN** — runs on any of the above substrates inside a software-defined network, treating segmentation as a boundary it continuously and read-only verifies, failing closed when assurance is lost. See [`docs/sdn-mode.md`](docs/sdn-mode.md).
- **SASE** — runs on any of the above substrates behind a SASE/ZTNA edge, reachable only through a sanctioned connector with required connector-tunneled passthrough, refusing direct exposure and clientless TLS-terminating edges. See [`docs/sase-mode.md`](docs/sase-mode.md).

SDN and SASE are network overlays, not container deployments: in every mode the server is a direct host process on a TPM/vTPM host, never a Kubernetes or orchestrated-container workload, because those cannot provide the per-instance hardware root of trust the instance anchor requires.

### High Availability

Both servers can run as an **active/passive** pair for automated failover. In each case write authority is settled internally by a cryptographic lease at a monotonically increasing epoch — enforced at the data layer, the scheduler, and the request layer — so the organization’s own load balancer only routes traffic and a flapping or compromised balancer can never cause split-brain. Active/active and multi-node clustering are ruled out rather than offered: promotion unseals a pre-wrapped key only by proving the standby is the genuine anchored node, and last-write-wins over audit chains and key material is not a trade a CISO can accept.

**Regional Server.** One node serves the SOC while a warm, sealed standby is kept current over a mutually authenticated peer link and promotes itself if the active stops responding. Replication is near-synchronous (a bounded, seconds-scale recovery point) and failover is honest about its window rather than promising zero downtime; a built-in self-test measures the real failover-and-failback time. Single-node deployments are unaffected. See [`docs/high-availability.md`](docs/high-availability.md).

**Global Dashboard Server.** Opt-in, and inert until two nodes are paired. Replication is asynchronous, so the recovery point is bounded rather than seconds-scale, and the tab surfaces live replication lag as the number that quantifies it. A passive is fenced on every write path — mutating requests are refused with HTTP 503 `ha_passive_read_only`, background jobs are write-gated, and the replicated alert notification is withheld — while reads and the HA control plane stay reachable, or a standby could never be paired, promoted, drilled, or recovered. The GD’s Tier-1 KEK is hardware-sealed per node, so the standby holds the shared material wrapped to its own root and unseals it only at promotion; the shared session secret rides along, so a failover does not force a re-authentication mid-incident. In Cloud Mode a node that cannot re-attest as a genuine confidential VM **refuses to promote** — integrity over availability, and the Regional Servers keep serving analysts throughout. The self-test is a real, measured failover rather than a simulation; there is no automatic fail-back; and HA lifecycle events reach the SIEM as CEF but not SOAR, email, or webhooks. See [`docs/gd-high-availability.md`](docs/gd-high-availability.md).

### Backend Services

|Service               |Purpose                                                                                   |
|----------------------|------------------------------------------------------------------------------------------|
|AI Burnout Engine     |Baseline creation, signal drift detection, AI message generation, training recommendations|
|Assessment Service    |Create/assign/submit assessments, skill tracking, gap analysis                            |
|Backup Service        |Encrypted full/incremental/differential backups, SHA-256 integrity, scheduling            |
|Storage Routing       |Per-type destination routing, guaranteed dual-write replication, immutability + residency |
|Compliance Scanner    |Real checks against actual app state for 16+ frameworks                                   |
|Regression Runner     |Broad real-test suite over DB tables, crypto, integrations, and middleware                |
|Integration Manager   |SOAR/Ticketing/SIEM/IAM connection testing and config storage                             |
|Notification Service  |Proactive break alerts, shift handoff notifications, assessment assignments               |
|System Health Monitor |Real CPU/memory/heap/DB metrics via Node.js APIs                                          |
|Feature Toggle Service|Enable/disable platform features without removing code                                    |
|Metrics Collector     |Full-suite metrics for monitoring + CEF output for SIEM                                   |

### Security Middleware

|Module             |Protections                                                                                          |
|-------------------|-----------------------------------------------------------------------------------------------------|
|auth               |JWT + RBAC; sessions bound to a hardware device key via per-request proof-of-possession              |
|auth-hardening     |Constant-time comparison, CSPRNG, account lockout, JWT rotation, suspicious input detection          |
|mfa-stepup         |Fresh WebAuthn step-up assertion gate for sensitive and config actions                               |
|security-hardening |Headers, input sanitization, CSRF, anti-replay, rate limiting, SSRF, TLS                             |
|body-validation    |Request-body shape validation (type-confusion / CWE-843 defense) on config writes                    |
|pentest-hardening  |Token storage (memory only), safe errors, request correlation, content-type enforcement, idle timeout|
|ai-security        |Prompt injection (12 patterns), context limits, output validation, data firewall                     |
|network-security   |DDoS/slowloris, DNS size limits, client heartbeat, mTLS, anti-pivot                                  |
|network-hardening  |Additional network-layer protections                                                                 |
|cors-policy        |Zero-trust CORS, known origins only                                                                  |
|config-lock        |Config-write lockout (HTTP 423) with WebAuthn step-up and sliding auto-relock                        |
|config-write-routes|Endpoint registry backing the config-lock chokepoint and its CI coverage guard                       |
|vm-attestation     |Virtualized-mode VM and clock-integrity attestation, fail-closed                                     |
|quarantine-guard   |Refuses a quarantined (suspected-clone) deployment until operator re-enrollment                      |
|mc-device-action   |Binds privileged Management Console actions to the console hardware device key                       |
|recovery-rate-limit|Burst limiter on destructive client-recovery (teardown / reprovision) actions                        |
|audit              |Tamper-evident: per-row SHA-256 hash chain + Ed25519-signed checkpoints                              |

### Integrations

|System            |Access    |Purpose                                                                                       |
|------------------|----------|----------------------------------------------------------------------------------------------|
|SOAR              |WRITE     |Burnout-aware ticket distribution                                                             |
|Ticketing         |READ-ONLY |Queue metadata for routing                                                                    |
|SIEM              |PUSH (CEF)|Health metrics, security events                                                               |
|IAM               |READ      |Certificate authority, directory, offboarding detection                                       |
|EDR               |READ      |Malware scanning of uploads/data                                                              |
|Malware Scanners  |READ      |15-vendor multi-provider malware scanning for IR Simulator uploads (see Upload Security below)|
|Scheduling        |READ      |Shift data for upskilling                                                                     |
|Training Platforms|LINK      |Assessment modules, training content                                                          |
|KMS               |READ/WRITE|Encryption key management                                                                     |

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

**IR Simulator API (/api/ooda, 15 endpoints):** OODA-loop incident-response training generator. Team leads upload IR policies, playbooks, and after-action reports; FireAlive parses them (rule-based) and generates choose-your-own-adventure decision-tree scenarios calibrated to a scenario type (8 categories — ransomware, phishing, data exfil, insider threat, APT, DDoS, supply chain, credential compromise) and difficulty (beginner / intermediate / advanced). Analysts work through scenarios node-by-node with an explanation on every choice. The generator validates each model output structurally — node-count bounds, OODA-phase progression, exactly one correct choice per decision node, all node references resolving, exactly one resolution node — and rejects malformed scenarios rather than persisting them. Per-policy replenishment (threshold / scheduled / manual) drives auto-generation, and aggregated mastery metrics are available via `GET /api/ooda/mastery` (analyst-only). See **FEATURE-GUIDE.md** for the full workflow and the backing services.

**Upload security (defense in depth, applies to /api/ooda/policies and /api/ooda/aar):** Every uploaded policy and after-action report passes two fail-closed scan layers before any database write. Layer 1 is a deterministic FireAlive-specific scanner targeting the threats that arise from feeding uploaded text to an LLM — prompt injection, embedded executables, and encoding / Unicode-smuggling attacks. Layer 2 routes the file through the multi-vendor malware scanner system (15 supported vendors — see **Integrations**) for novel-signature and threat-intel matches the internal scanner cannot stay current on. Either layer’s rejection blocks the upload, and the IR Simulator routes additionally hard-gate on at least one enabled scanner: with none configured, the upload is refused with HTTP 422 and code MALWARE_SCANNER_REQUIRED. That hard gate is local to the IR Simulator routes because their content becomes LLM context for scenario generation.

-----

## Environment Variables (Optional Features)

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

-----

## How It Works

### First-Time Setup Flow

1. Team Lead installs MC → MC starts Regional Server automatically
1. Team Lead configures authentication (built-in CA + LDAP directory), SOAR, Ticketing, SIEM, EDR
1. Team Lead provisions Analyst Clients
1. Analysts install AC, trust the FireAlive CA, and authenticate with a hardware passkey (a security key with a PIN; the client certificate secures transport, not sign-in)
1. First shift: AI Burnout Engine records 8 signal readings → baseline established
1. After baseline: AI generates real-time drift detection + training recommendations
1. CISO installs GD → registers regional MCs → sees cross-region health

### Hardware-Rooted Identity, Anti-Cloning & Sender-Constrained Sessions

FireAlive treats a running deployment as something that must continuously prove it is the genuine, un-cloned instance — not only at install time, but on every client connection and every request.

- **Hardware-rooted instance identity.** Each server derives a non-exportable identity anchor from the host hardware root of trust — TPM 2.0 on Windows and Linux, the Secure Enclave on macOS. The anchor key never leaves hardware, and identity establishment is fail-closed: no anchor, no serving.
- **Anti-cloning.** A byte-for-byte copy of a deployment — database, keys, and disk — cannot reconstitute the anchor on different hardware, so a lifted clone is detectable rather than silently authoritative. Every Analyst Client and Global Dashboard verifies the server’s anchor fingerprint on each connect; the **first** connection requires an explicit out-of-band operator confirmation of that fingerprint (the server prints it at startup), and any later fingerprint change blocks the client instead of trusting it.
- **Virtualized deployments.** Bare-metal installs bind to the physical TPM; virtualized installs additionally run a VM-attestation and clock-integrity gate, so a paused, rolled-back, snapshotted, or migrated VM is caught fail-closed rather than serving forked or stale state. See [`docs/anti-cloning-and-virtualization.md`](docs/anti-cloning-and-virtualization.md).
- **Sender-constrained sessions.** Session tokens are bound to a per-device key — the token carries that key’s thumbprint — and every authenticated request carries a short-lived, replay-protected proof-of-possession signed by the device’s private key. A stolen session token is therefore useless on its own: without the device’s hardware-held key it cannot be replayed. See [`docs/iam-and-authentication.md`](docs/iam-and-authentication.md).
- **Per-client recovery.** A lost or compromised Analyst Client can be torn down and re-provisioned individually — rate-limited and fully audited — without re-keying the whole deployment. See [`docs/client-recovery.md`](docs/client-recovery.md).
- **Key continuity across upgrades.** A normal in-place upgrade preserves every key and sealed record: the new release resolves the same hardware root of trust (or KMS/env-var KEK), and the sealed data at rest is never rewritten — so an update costs nothing, with no re-keying, no re-encryption, and no data loss. The seal format is versioned with anti-rollback, so a downgrade onto newer-format data is halted and quarantined rather than risking a mismatched read. Moving to a *different* KEK (a genuine hardware move) is the one case that re-seals the data, and the recovery code is the sole factor for it — there is no KMS escrow or back-door substitute, because that absence is the anti-clone guarantee. See [`docs/key-continuity-and-upgrades.md`](docs/key-continuity-and-upgrades.md).

### Locking Configuration (Required Hardening)

Before promoting the deployment to production, an admin **must** lock the configuration to prevent runtime changes. The platform ships unlocked because initial setup (KMS, IAM, integration onboarding, backup signing keys, etc.) needs to happen before the first authenticator is even enrolled — but unlocked is a setup-time state, not the production state. Lock/unlock requires a fresh WebAuthn step-up (a user-verified passkey assertion) and is **admin-role-only**. Use the **Lock All Configs** button in the MC or GD sidebar.

When locked, every configuration-write endpoint returns HTTP 423 Locked. A single registry-driven chokepoint covers all of them — not only the platform-config routers (KMS, IAM, backup signing keys, integrations, GD push config, scheduling, external restore, AI provider, malware scanners, storage destinations, storage routing, backup push, audit retention, API keys) but also the in-app feature settings (EDR, posture, geo-fencing, threat-hunting, vulnerability scan, pseudonyms, recertification, access control, and the rest). Reads pass through — admins can still inspect config state. Operational routes (backup creation, restore execution, incident routing, scans, alert approvals) are unaffected, so production incident response is never blocked by the lock.

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
- **Abuse-flag content** (peer-session and board-post reports) is sealed on the flagger’s device to the active Team-Lead recipient set — a multi-recipient X25519 envelope — before it leaves the app. The server stores only opaque ciphertext and cannot decrypt it; review and disposition happen in the MC **Peer Conduct** tab, opened by a lead who has enrolled an abuse-review key. The server, the GD, and an admin (who handles only public keys) cannot read flag content — only an enrolled lead can, on their own device. See the review model below.

### Abuse review (Team Lead)

Abuse reports from peer skill-share sessions and the skill-share Board are reviewed by a Team Lead in the MC **Peer Conduct** tab. At least one lead must enroll an abuse-review key before abuse reporting can be used; with no enrolled key, sealed reports could not be opened by anyone.

**Multi-lead, zero-access.** Each lead enrolls their own X25519 abuse-review key on their own device, behind a passphrase only they know. The public key is registered with the server from the MC Peer Conduct tab; the private key never leaves the lead’s device. Flag content is sealed on the flagger’s device to ALL enrolled leads at once (a multi-recipient envelope); any one lead opens it with their own key. No private key is ever shared, exported, or transferred between people, and the admin only ever handles public keys — true zero-access, in the sense that the server, the admin, and any DB or key insider cannot decrypt flag content. Enrolling another lead adds a public key to the set; revoking removes it.

**Until at least one lead has enrolled, abuse reporting is disabled** — with no enrolled key, nothing could be decrypted, and the flagger’s app shows an explicit message saying so. Key enrollment requires a 12-character (or longer) passphrase, and the private key stays on the lead’s device — it is never sent to the server.

### Signed reports & verification

Every exportable report FireAlive generates — compliance reports, Report Engine output, helper-pay statements, and abuse-flag submission reports — is signed by the instance’s Ed25519 **report-signing key**, a key family distinct from the forensic, backup, chain, GD-push, and cloud-IaC signing keys (a compromise of one family taints none of the others). Each report carries a footer with the human-readable instance label, the UTC sign time, a report id, the short signing-key fingerprint, and a verification hash — so a genuine FireAlive report cannot be forged or altered and passed off as legitimate.

Verification is **authenticated only — there is no public endpoint**. A public hash-verify endpoint would let an adversary grind hashes to enumerate or confirm accusations, so abuse-flag reports verify solely for an enrolled Team Lead; compliance and Report Engine reports for admin/CISO; helper-pay statements for the owning analyst or an admin. The verification ledger is permanent and append-only, so any signed report stays verifiable indefinitely.

Reports can also be verified **independently, with no FireAlive tooling and no trust in the running system**, using OpenSSL against the instance’s published Ed25519 public key — see [`docs/report-verification.md`](docs/report-verification.md). Abuse-flag reports are zero-access end to end: the signature covers a canonical data record containing only a content hash, never the report text, so the server signs and records a verifiable report without ever holding the plaintext.

-----

## Compliance

Compliance reports for 16 frameworks: NIST CSF, ISO 27001, SOC 2, HIPAA, GDPR, DORA, CCPA, PIPEDA, LGPD, PDPA, APPI, POPIA, NIS2, CPS 234, Cyber Essentials, FISMA.

Each report follows a **Shared Responsibility** model split into two halves:

- **verifiedControls** — technical controls FireAlive observes by inspecting its own running state. Categories: access control (RBAC), encryption (AES-256-GCM at rest, TLS in transit, libsignal for chat E2EE, X25519 multi-recipient envelopes for abuse-flag content), audit trail (per-row SHA-256 hash chain + Ed25519-signed checkpoints, append-only), authentication (passwordless hardware FIDO2/WebAuthn passkeys; client certificates provide transport mutual TLS; JWT sessions), configuration management (e-fuse anti-rollback), incident response infrastructure (CISM retro protocol, routing-disable kill switches), data protection (pseudonymization, Tier-3 isolation), network (SIEM/SOAR), backups, notifications, and AI engine status.
- **customerResponsibility** — organizational, procedural, physical, and contractual controls the operating organization must attest separately. Examples: risk-analysis methodology, workforce sanction policy, designated security official, business associate / data processor contracts, physical safeguards on the deployment environment, breach-notification procedures, board-level governance evidence (ISO 27001 management review minutes, internal audit reports), subprocessor agreements and data-transfer impact assessments. For HIPAA, verifiedControls covers 19 controls; customerResponsibility covers 42. The ratio varies by framework but reflects the reality that software handles a minority of any major compliance regime.

Three reporting surfaces:

- **MC → Reports & Compliance tab** — per-region operational view. The MC generates reports against its own running state.
- **GD → Compliance Posture tab** — CISO view of the GD-Server’s own compliance posture (cross-region aggregation integrity, signing-key trust registry, mailbox-pattern fulfillment).
- **GD → Cross-Region Compliance tab** — framework × MC matrix sourced from MCs’ pushed compliance summaries. Drill into any cell for that MC’s full-report history, request a fresh fulfillment via the per-cell Request Full Report button, and inspect per-control parsed report bodies when fulfilled. Active MCs only.

See **SETUP.md → Shared Responsibility in Compliance Reports** for the operator-facing framing of what compliance reports do and do not tell you.

-----

## License

GNU Affero General Public License v3.0 (AGPL-3.0-or-later)
Copyright (C) 2026 Peter Mancina

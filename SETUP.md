# FireAlive — Setup Guide

## For Team Leads (Management Console + Server + Analyst Clients)

### Step 1: Install the Management Console
1. Download the installer for your OS from the GitHub Releases page:
   - macOS: `FireAlive-Management-Console-<version>-arm64.dmg` or `x64.dmg`
   - Windows: `FireAlive-Management-Console-<version>-Setup.exe`
   - Linux: `FireAlive-Management-Console-<version>.AppImage`
2. Run the installer. The MC includes the embedded Regional Server.
3. On first launch, the MC starts in **unlocked** mode (no MFA configured yet).

### Step 2: Configure the Management Console
1. **Set up MFA:** Go to MFA tab → scan TOTP QR code with your authenticator app (Authy, Google Authenticator, or Microsoft Authenticator) → enter the 6-digit code → Verify.
2. **Configure IAM:** Go to IAM tab → select your identity provider (Okta, Azure AD, or Duo) → enter your IAM endpoint URL and API credentials → Save.
3. **Lock configs:** Once MFA is working, use the sidebar lock button to lock all configurations. Any future config changes will require MFA unlock.

### Step 3: Configure Integrations
1. **SOAR:** Go to Routing & SOAR tab → select your SOAR platform (Splunk SOAR, XSOAR, QRadar SOAR, Tines, Torq, or Swimlane) → enter API endpoint and key → Save. SOAR gives FireAlive WRITE access to distribute tickets based on burnout-aware routing.
2. **Ticketing:** Same tab, scroll down → select your ticketing system (ServiceNow, Jira, Zendesk, PagerDuty, or Freshservice) → enter READ-ONLY API credentials → Save. FireAlive reads queue metadata to inform routing decisions.
3. **SIEM:** Go to SIEM tab → enter your SIEM CEF/Syslog endpoint → Save. Configure widget visibility to "Team Lead only" (recommended — burnout metrics on all-SOC screens can hurt morale).
4. **EDR:** Go to EDR tab → configure EDR access so it can scan FireAlive data and uploads for malware.
5. **Scheduling Platform (optional):** Go to Upskilling Hour tab → Per-Analyst Scheduling → select your scheduling platform (UKG/Kronos, Workday, ADP, or BambooHR) → enter API endpoint → Sync.

### Step 4: Provision Analyst Clients
1. Go to Client Provisioning tab.
2. Click "Provision New Client" for each analyst joining the platform.
3. Distribute the Analyst Client installer to your analysts (download link from GitHub Releases).

**Provision every analyst in the SOC, not only those you think are at risk.** FireAlive monitors an analyst only after they enroll a key from their Analyst Client — an analyst who is on the roster but not enrolled is invisible to every team aggregate, to the routing cap, and to burnout interventions. More importantly, burnout prevention and intervention are effective at the team level: the interventions FireAlive supports (workload rebalancing, lighter queues, proactive breaks, post-incident recovery) act on whole teams, not on singled-out individuals, so selectively enrolling only the analysts you suspect are at risk both distorts the team picture and weakens the interventions. The Management Console's Actions tab surfaces any scheduled analyst who has not yet enrolled, so you can prompt them; exclude someone there only if they are genuinely not a monitored member of the SOC.

### Step 5: Designate an Independent Abuse Reviewer
Before abuse reporting in the Analyst Client and Management Console becomes available, at least one independent abuse reviewer must be designated and their public key registered.
1. Identify the person (or people) who will serve as independent abuse reviewer. The role is **separate from team leadership** — a lead may be the subject of a report, so a lead cannot review their own abuse cases. Where the deployment cannot maintain strict separation (for example, where one person holds both team-lead and platform-admin duties), draw the reviewer from HR, an ethics committee, or another independent function.
2. Have the reviewer install the **Abuse Review Console** on their own device and generate their keypair — see the dedicated "For Independent Abuse Reviewers" section below.
3. The reviewer hands you their public key + fingerprint (out of band — never via the system you're configuring). Open the **Audit → Abuse Reviewers** panel in the MC and click Register; paste the public key, add an optional label (e.g. the reviewer's name or designated function), confirm. The server derives the fingerprint from the public key; check it matches what the reviewer gave you.
4. Once at least one public key is active in the panel, abuse reporting becomes available in the AC and MC. Repeat for every additional reviewer; flag content is sealed to ALL active reviewer public keys at once. Public keys only — the admin never handles or sees a private key.

### Step 6: Analysts Install and Connect
1. Analyst downloads and installs the Analyst Client for their OS.
2. On first launch: enter the server address provided by the Team Lead, then log in with their IAM credentials + MFA code.
3. The first full shift establishes the analyst's burnout signal baseline. After one shift, the AI begins generating personalized recommendations.

### Step 7: Ongoing Configuration
- **Assessments:** Create skill assessments in the Assessments tab and assign them to analysts.
- **Upskilling:** Configure per-analyst upskilling hours in the Upskilling Hour tab.
- **Backups:** Set up automated backup schedules in Backup & Schedules tab.
- **Compliance:** Run compliance reports for your applicable frameworks in Reports & Compliance tab.

---

## For Independent Abuse Reviewers (Abuse Review Console)

The Abuse Review Console (ARC) is the dedicated app for an independent abuse reviewer — a role separate from team leadership. Every FireAlive deployment must designate at least one independent reviewer; abuse reporting in the Analyst Client and Management Console stays disabled until a reviewer's public key is registered. Where one person holds both team-lead and platform-admin duties, the reviewer must come from an independent function (HR, ethics, etc.).

### Step 1: Install the Abuse Review Console
1. Download the installer for your OS from the GitHub Releases page:
   - macOS: `FireAlive-Abuse-Review-Console-<version>-arm64.dmg` or `x64.dmg`
   - Windows: `FireAlive-Abuse-Review-Console-<version>-Setup.exe`
   - Linux: `FireAlive-Abuse-Review-Console-<version>.AppImage`
2. Install on your own device — the device only you use. The private key generated next never leaves this machine.

### Step 2: Generate Your Reviewer Keypair (First Run)
1. On first launch, the ARC asks you to set a **passphrase** (12-character minimum, entered twice). This passphrase is the only way to unlock your private key on future sessions; if you forget it, the key is unrecoverable and a new key must be designated.
2. The ARC generates an X25519 keypair locally. The private key is passphrase-wrapped (scrypt → AES-256-GCM) and then sealed to the OS keychain via Electron `safeStorage`, written 0600 to your user data directory. The private key never reaches the renderer and never leaves the device.
3. The ARC displays your **public key** and a 16-hex-character **fingerprint**. Hand both to your platform admin via an out-of-band channel; never share the passphrase or the private key with anyone.

### Step 3: Admin Registers Your Public Key
1. The admin opens the Management Console → **Audit → Abuse Reviewers** panel.
2. They paste your public key, add an optional label (e.g. your name or designated function), and click Register. The server derives the fingerprint from the public key; the admin confirms it matches the fingerprint you handed over.
3. Once at least one public key is active, abuse reporting becomes available in the AC and MC. Every new flag is sealed to ALL active reviewer public keys at once.

### Step 4: Routine Use — Unlock, Review, Lock
1. On every launch, the ARC asks for your passphrase. Entering it loads your private key into the ARC's main process for the session only.
2. The case list shows abuse cases the server has routed to the active reviewer set; the ARC decrypts each case client-side with your private key. The server cannot read the content.
3. The session locks automatically after 5 minutes of inactivity — the unlocked private key is cleared from memory and you re-enter your passphrase to continue. You can also press the Lock button in the header at any time.
4. Window-all-closed and before-quit also clear the in-memory key.

### Step 5: Pin the CISO Key for Legal-Hold Export
Producing a legal-hold export of a vaulted abuse case requires the CISO’s approval public key, pinned once on your device, out of band.
1. Obtain the CISO approval public key and its SHA-256 fingerprint from the CISO through a trusted channel — not through FireAlive.
2. In the ARC, on an approved export request, paste the public key and the expected fingerprint. The console recomputes the fingerprint from the key and refuses to pin on a mismatch, so a substituted key cannot be accepted silently. The pin lives only on your device, independent of the server.
3. When you produce an export, the ARC re-verifies the CISO’s signed token against this pinned key — the signature and the request/case/decision binding — and refuses if anything fails, before assembling the case file.

A produced case file identifies analysts by pseudonym; mapping pseudonyms to real identities is a separate, out-of-band handoff and is never embedded in the file. The reviewer and the CISO must be different people. Full procedure and offline verification: `docs/abuse-vault-legal-hold-export.md`.

### Adding or Removing Reviewers
- **Add:** the new reviewer installs the ARC on their own device, generates their keypair (Steps 1 and 2), and hands their public key + fingerprint to the admin, who registers it via the MC's Audit → Abuse Reviewers panel. From the next flag onward, content is sealed to the expanded recipient set.
- **Remove:** the admin revokes the reviewer's public key in the same panel. New flags omit the revoked slot. Flags already sealed to a set including the revoked key stay openable by every other active reviewer at the time of sealing.
- **Boundary:** the active recipient set is computed at seal time. A reviewer registered AFTER a flag was sealed cannot open that older flag — their slot does not exist in that envelope. There is no server-side re-seal path; the server never holds plaintext.

### Recovery
- A forgotten passphrase makes the private key irrecoverable. Revoke that public key in the MC panel, have the reviewer generate a fresh keypair (a new passphrase, a new fingerprint), and register the new public key. Past flags that were also sealed to other active reviewers remain openable by them; flags sealed when the lost-key reviewer was the only active reviewer cannot be reopened by anyone — this is the cost of zero-access.
- A lost or compromised device: revoke the public key in the MC panel immediately so no new flags are sealed to that slot. The device still carries the passphrase-wrapped private-key blob (passphrase-required to unwrap), so the risk of unauthorized decryption depends on passphrase strength and how quickly revocation happens.

---

## For CISOs (Global Dashboard)

### Step 1: Install the Global Dashboard
1. Download and install the Global Dashboard for your OS from GitHub Releases.
2. On first launch, the GD starts in **unlocked** mode.

### Step 2: Register Regional Management Consoles
1. Go to MC Connections tab.
2. Click "Register MC" → enter the Regional Server address and mTLS credentials provided by the Team Lead.
3. Repeat for each regional SOC.

### Step 3: Configure
1. **MFA:** Set up your TOTP authenticator in the MFA tab.
2. **Notifications:** Configure email and/or SMS alerts with thresholds in the Notifications tab.
3. **Data Sovereignty:** Set data residency requirements per region in the Data Sovereignty tab.
4. **Backup Schedules:** Configure GD backup schedules in Backup & Restore tab.
5. **Lock configs:** Lock the master config via sidebar when setup is complete.

---

### Step 4: Provision the Legal-Hold Export Approval Key
Two-person legal-hold exports of vaulted abuse cases require a CISO approval. Approving mints an Ed25519-signed decision token; the reviewer’s device verifies that token before producing a case file.
1. The GD holds a dedicated CISO approval key, separate from the report-signing and trust-registry keys. It is created on first use and stored Tier-1-encrypted; back it with an HSM or hardware key store where available. The private half never leaves the GD.
2. Publish the approval **public** key and its SHA-256 fingerprint to each abuse reviewer **out of band** (in person, signed message, or a separately verified document — never through the platform). Reviewers pin this key in their console and refuse to produce an export if a token does not verify against it.
3. **The reviewer and the CISO must be different people.** The platform separates the two roles across realms but cannot detect one human holding both a reviewer account and a CISO account; a deployment that collapses them has no real two-person control.

Pending requests appear on the Global Dashboard’s MC Connections tab (“Pending Legal-Hold Export Approvals”). Full procedure: `docs/abuse-vault-legal-hold-export.md`.

## Shared Responsibility in Compliance Reports

Compliance reports produced by FireAlive (Reports & Compliance on the MC, Compliance Posture on the GD) follow a **Shared Responsibility** model that separates controls FireAlive can verify automatically from controls the operating organization must attest to separately.

Understanding this split matters for two reasons:
1. **Audit evidence.** An auditor reading a FireAlive compliance report needs to know which control results are software-verified (FireAlive ran a check against the running system and observed a pass / warning / fail) and which are documentation the organization must produce on its own (policy text, training records, contract clauses with subprocessors, board-level governance evidence, etc.).
2. **Operator workload.** A passing FireAlive report does NOT mean the framework is satisfied end to end. The customer-responsibility items are the operator's homework — they need to be tracked in your evidence binder, policy library, or GRC tool alongside the FireAlive report.

### What FireAlive Verifies Automatically (verifiedControls)

These are the **technical** controls FireAlive can observe by inspecting its own configuration, code, and runtime state. Examples vary by framework, but the verified set generally covers:
- Authentication and session management (JWT lifetime, MFA enforcement, SSO integration)
- Access control and role separation (RBAC, multi-MFA-approval gates for sensitive actions)
- Audit logging (immutable storage, syslog/CEF export, retention)
- Encryption at rest and in transit (AES-256-GCM for stored data, TLS for transport, libsignal for chat E2EE, X25519 multi-recipient envelopes for abuse-flag content)
- Anti-rollback and integrity checks (fuse counter, startup integrity verification)
- Incident response infrastructure (CISM retro protocol, routing-disable kill switches)

Each verifiedControls entry in a report carries a `status` (pass / warning / fail / error), a `detail` describing what was observed, a `mapping` showing which control taxonomy it maps to (NIST control id, HIPAA citation, ISO clause, etc.), and a `remediation` block when the status is not pass.

### What You Attest (customerResponsibility)

These are the **organizational, procedural, physical, and contractual** controls that exist outside FireAlive's software boundary. The platform cannot observe them; only your organization can produce the evidence. Examples:
- Risk analysis methodology and findings (HIPAA 164.308(a)(1)(ii)(A) — the most-cited violation; FireAlive provides infrastructure that supports the analysis but cannot perform it)
- Workforce sanction policy and HR records of sanctions applied
- Designated security official by name + contact info + accountability documentation
- Business associate / data processor contracts with required compliance clauses
- Physical safeguards on the deployment environment (facility access controls, workstation security)
- Breach notification procedures, including timeline tracking and regulator-notification templates
- Board-level governance evidence (ISO 27001 management review minutes, internal audit reports)
- Subprocessor agreements and data-transfer impact assessments (GDPR Article 28 + Chapter V; DORA ICT third-party risk)

Each customerResponsibility entry in a report carries an `id`, `name`, `category` (organizational, procedural, contractual, physical, governance), and `detail` describing exactly what your organization must document. For HIPAA, FireAlive's verifiedControls covers 19 entries; customerResponsibility covers 42 entries (the 164.308 Administrative Safeguards, all 164.310 Physical Safeguards, and the 164.400-414 Breach Notification subsection). The ratio varies by framework but always reflects this reality: software handles a minority of any major compliance regime.

### Why It Matters

When you present a FireAlive compliance report to an internal auditor or external assessor:
- A pass on the verified half is evidence that FireAlive's technical controls satisfy the in-scope requirements **as configured today**. Re-run the report after any material change to confirm.
- The customer-responsibility half is your TODO list. An auditor will expect you to produce documentation matching each entry. The report enumerates them explicitly so nothing is forgotten.
- A FireAlive report that omits the customer-responsibility section is incomplete by design — the platform refuses to produce a "complete compliance certificate" because that would falsely imply the verified half covers the whole regime.

### Where to Find the Reports

- **MC side (per-region operational view):** Reports & Compliance tab. Select a framework and click Generate Report. The report is generated against the local MC's running state.
- **GD side (CISO posture view):** Compliance Posture tab. Same framework selector; the report is generated against the GD-Server's running state, which covers GD-specific controls (cross-region aggregation integrity, signing-key trust registry, mailbox-pattern fulfillment).
- **GD side (cross-MC rollup view):** Cross-Region Compliance tab. Renders a framework x MC matrix sourced from MCs' pushed compliance summaries. Drill into any cell for that MC's full report history; request a fresh fulfillment via the per-cell Request Full Report button if the most recent summary is stale.

---

## Building from Source

### Prerequisites
- Node.js 20+ (LTS)
- npm 10+

### Install and Run (Development)
```bash
git clone https://github.com/petermancina/firealive.git
cd firealive

# Install dependencies
npm install

# Start Regional Server
node server/index.js
# Server starts on port 3000

# Start GD Server (separate terminal)
cd packages/global-dashboard-server
node index.js
# GD Server starts on port 4001

# Run any Electron app in dev mode
cd packages/analyst-client
npm start
```

### Environment Variables
Create a `.env` file in the project root (never commit this file):
```env
FIREALIVE_MASTER_KEY=<generate-with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))">
JWT_SECRET=<generate-a-separate-key>
JWT_REFRESH_SECRET=<generate-another-key>
NODE_ENV=production
PORT=3000
```

---

## Troubleshooting

### "App is damaged" or "unidentified developer" (macOS)
Right-click the app → Open → click Open in the dialog. This bypasses Gatekeeper for the first launch.

### Server won't start
Check that port 3000 (Regional Server) or 4001 (GD Server) is not already in use:
```bash
lsof -i :3000
```

### Analyst Client can't connect
Verify the server address is correct and that the firewall allows connections on port 3000. The AC and server must be on the same network or VPN.

### MFA code rejected
Ensure your device clock is synchronized. TOTP codes are time-based and will fail if your clock is off by more than 30 seconds.

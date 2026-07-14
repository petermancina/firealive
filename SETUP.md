# FireAlive — Setup Guide

## For Team Leads (Management Console + Server + Analyst Clients)

### Step 1: Install the Management Console
1. Download the installer for your OS from the GitHub Releases page:
   - macOS: `FireAlive-Management-Console-<version>-arm64.dmg` or `x64.dmg`
   - Windows: `FireAlive-Management-Console-<version>-Setup.exe`
   - Linux: `FireAlive-Management-Console-<version>.AppImage`
2. Run the installer. The MC includes the embedded Regional Server.
3. On first launch, the MC starts in **unlocked** mode (config lock off).

### Step 2: Configure the Management Console
1. **Enroll your passkey:** Go to the MFA tab → register your FIDO2 hardware security key (e.g. YubiKey, Feitian, or Titan) with a PIN. This hardware passkey is your sign-in credential; there is no password and no authenticator-app code.
2. **Configure IAM:** Go to IAM tab → select your identity provider (Okta, Azure AD, or Duo) → enter your IAM endpoint URL and API credentials → Save.
3. **Lock configs:** Once your passkey is enrolled, use the sidebar lock button to lock all configurations. Any future config changes will require a hardware-passkey step-up to unlock.

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

### Step 5: Enroll Your Abuse-Review Key
Abuse reports from analysts are reviewed by the Team Lead in the Management Console's **Peer Conduct** tab. Reporting stays disabled until at least one lead has enrolled an abuse-review key, because flag content is sealed so that only an enrolled lead can open it.

1. In the MC, open the **Peer Conduct** tab and generate your abuse-review key. You set a **passphrase** (12-character minimum, entered twice); the key is generated on your device, and the private half is wrapped under that passphrase and never leaves the MC machine. The server only ever receives the **public** key.
2. Enrolling your public key adds you to the active recipient set. From then on, when an analyst files a flag, their client seals the content to every enrolled lead's public key before it leaves their device — the server stores only opaque ciphertext it cannot read. Once at least one key is active, abuse reporting becomes available in the Analyst Client and Management Console.
3. To review, open a case in the Peer Conduct tab and unlock with your passphrase; the MC decrypts the sealed note and content client-side. The store is append-only — you resolve a case with a structured verdict and rationale, and nothing is ever deleted.
4. Multiple leads can each enroll a key, and flags seal to all of them at once. A key can be revoked (by a lead or admin) from the same tab; flags already sealed to other active leads stay openable by them. If a passphrase is lost, revoke that key and enroll a fresh one — flags sealed to other active leads remain openable, but a flag sealed only to the lost key can no longer be opened, which is the cost of zero-access.

Cases identify everyone by **pseudonym** — FireAlive stores no real names, so a review can only ever show the system's pseudonymous handles, even though a lead generally knows who those handles belong to. The pseudonyms exist to keep analysts' burnout data unreadable on a compromised client.

### Step 6: Analysts Install and Connect
1. Analyst downloads and installs the Analyst Client for their OS.
2. On first launch: enter the server address provided by the Team Lead, then sign in with your FIDO2 hardware passkey.
3. The first full shift establishes the analyst's burnout signal baseline. After one shift, the AI begins generating personalized recommendations.

### Step 7: Ongoing Configuration
- **Assessments:** Create skill assessments in the Assessments tab and assign them to analysts.
- **Upskilling:** Configure per-analyst upskilling hours in the Upskilling Hour tab.
- **Backups:** Set up automated backup schedules in Backup & Schedules tab.
- **Compliance:** Run compliance reports for your applicable frameworks in Reports & Compliance tab.

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
1. **MFA:** Enroll your FIDO2 hardware passkey in the MFA tab.
2. **Notifications:** Configure email and/or SMS alerts with thresholds in the Notifications tab.
3. **Data Sovereignty:** Set data residency requirements per region in the Data Sovereignty tab.
4. **Backup Schedules:** Configure GD backup schedules in Backup & Restore tab.
5. **Lock configs:** Lock the master config via sidebar when setup is complete.

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

### Provision the Tier-1 KEK (hardware-sealed)

Before the Regional Server starts for the first time, seal the **Tier-1
key-encryption-key** — which protects server-side secrets at rest (integration
credentials, signing-key private keys, the CA key) — to the host's TPM 2.0
(Linux, Windows) or Secure Enclave (macOS). On the server host, run:
```bash
node scripts/provision-tier1-kek.js
```
Set the printed value as `TIER1_ENCRYPTION_KEY` in your environment or secrets
manager, and store the one-time **recovery code** offline. The server fails
closed: it will not start unless `TIER1_ENCRYPTION_KEY` is a hardware-sealed
value, and a raw key is refused. (`TIER3_ENCRYPTION_KEY`, for analyst data,
remains a raw 32-byte hex key set in `.env`.)

**Recovering after hardware loss requires BOTH a server backup AND the offline
recovery code — neither alone is sufficient.** A backup is encrypted under the
Tier-1 KEK and does not contain it. If the TPM / Secure Enclave is ever
replaced, run `node scripts/recover-tier1-kek.js` with your recovery code to
re-establish the key, then restore from backup. Full details:
`docs/tier1-kek-hardware-sealing.md`.

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

### Passkey sign-in rejected
Make sure you are using a hardware security key already registered to your account, that it is inserted or tapped, and that you complete the PIN or biometric prompt. If you have lost your key, use the break-glass recovery path to register a new one.

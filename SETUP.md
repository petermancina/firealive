# FireAlive — Setup Guide

## For Team Leads (Management Console + Server + Analyst Clients)

### Step 1: Install the Management Console
1. Download the installer for your OS from the GitHub Releases page:
   - macOS: `FireAlive-Management-Console-1.0.0-arm64.dmg` or `x64.dmg`
   - Windows: `FireAlive-Management-Console-1.0.0-Setup.exe`
   - Linux: `FireAlive-Management-Console-1.0.0.AppImage`
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

### Step 5: Analysts Install and Connect
1. Analyst downloads and installs the Analyst Client for their OS.
2. On first launch: enter the server address provided by the Team Lead, then log in with their IAM credentials + MFA code.
3. The first full shift establishes the analyst's burnout signal baseline. After one shift, the AI begins generating personalized recommendations.

### Step 6: Ongoing Configuration
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
1. **MFA:** Set up your TOTP authenticator in the MFA tab.
2. **Notifications:** Configure email and/or SMS alerts with thresholds in the Notifications tab.
3. **Data Sovereignty:** Set data residency requirements per region in the Data Sovereignty tab.
4. **Backup Schedules:** Configure GD backup schedules in Backup & Restore tab.
5. **Lock configs:** Lock the master config via sidebar when setup is complete.

---

## Building from Source

### Prerequisites
- Node.js 20+ (LTS)
- npm 10+

### Install and Run (Development)
```bash
git clone https://github.com/pmancina/firealive.git
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

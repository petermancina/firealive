# FireAlive Build Plan v7

**Owner:** Peter Mancina
**Last revised:** May 5, 2026
**Status:** R3 in progress — R3a closing, then R3b through R3m

This document supersedes BUILD-PLAN-v6.

---

## ABSOLUTE FOUNDATIONAL RULE — READ THIS FIRST

**ALL UI FEATURES NEED TO BE BUILT FRONT TO BACKEND. NEUTER NOTHING IN THE
UI.**

Every button, dropdown, input, card, toggle, and tab present in the
Management Console (`frontend/firealive-mc.jsx`), Analyst Client
(`packages/analyst-client/analyst-client.jsx`), and Global Dashboard
(`packages/global-dashboard/global-dashboard.jsx`) is intended to deliver
real, working functionality. If a UI feature does not have a working
canonical backend, the answer is **build the backend**, not "replace the
onClick with a planned-feature notice." That pattern (which I, an earlier
Claude session, applied to the MC Sync and Save All buttons in commit 14
of the R3a PR) is forbidden. Any future Claude session that catches itself
about to neuter a UI feature with a TODO log entry, planned-feature toast,
or any other stub-replacement pattern must STOP and instead extend this
build plan with a sub-phase to build the real backend.

The user has stated repeatedly: "Everything in the UI is something I
wanted." This is the controlling principle. Do not ask the user to
re-justify any UI feature. Do not ask whether a UI feature is "speculative."
Do not propose deletion of UI features. Build them.

The single permitted exception is when a UI element is structurally a
duplicate of another UI element delivering the same function in the same
view (genuine UI redundancy, e.g., two identical buttons), and the user
explicitly confirms removal. Even then, the function is preserved through
the remaining instance.

---

## Why this rule exists

A previous Claude session in the "SOC Wellbeing Platform 10" chat tried
to delete `v054-features.js` and `v059-features.js` outright on the
assumption that they were dead code. The user correctly identified that
the files contained features that had no canonical home and reverted those
deletion commits.

A later Claude session (this one, R3a phase) initially proposed neutering
the MC "Sync" and "Save All" buttons (commit 14, shipped) and was about
to neuter the GD "Custom Query" Run button (commit 15, blocked) by
replacing their `api.post` calls with `addA(...)` or `showGdToast(...)`
notices. The user stopped this with: "I don't want to neuter any feature
in any of the UI's for later builds. This whole f'ing app should work and
we should build it. There is no one else who is going to come in later
and save us with a build."

The user is the sole developer. There is no future team. The current
Claude session must build every feature now, not defer to a future session
that may not exist.

---

## What v054/v059/v100 actually are

These three files in `server/routes/` are intentional roadmap files. Each
declares endpoints for features that are documented in `FEATURE-GUIDE.md`
or present in the UI but were not yet implemented in canonical route
files at the time the file was authored. As features get properly built
canonically, the corresponding endpoints in v054/v059/v100 become
genuinely redundant — and only at that point can they be deleted without
losing the roadmap.

The deletion happens in **R3m**, the final phase, after every endpoint in
all three files has been independently verified working in canonical.

---

## R3 sequencing — 13 sub-phases

Each sub-phase ships a coherent, version-bumped release. The unmounted
files (`v054-features.js`, `v059-features.js`, `v100-features.js`) stay
in place as roadmap markers until the final phase R3m.

### R3a → v1.0.27 — Honest port phase (closing)

Ports the five Class A features into canonical route files. Repoints the
matching frontend callsites where canonical fully covers the function.

Class A ports completed:
- `GET /api/audit/integrity` (commits 1-3 of R3a PR)
- `GET /api/metrics` and `GET /api/metrics/cef` (commits 4-5)
- `POST /api/training/submit-completion` plus `training_completions` schema (commits 6-9)
- `POST /api/heartbeat` (commits 10-11)
- `pseudonym_rotated_at` write on canonical pseudonym endpoints (commit 12)

Callsite repoints completed:
- MC `/api/v054/iam/confirm-status` → `/api/iam/confirm-status` with proper analystId field (commit 13)
- MC per-analyst upskilling dropdown → `/api/upskilling/schedule` with proper {analystId, slot} shape (commit 14)

R3a callsite work that is INCOMPLETE and needs correction in a future
phase: commit 14 of the R3a PR neutered the MC "Sync" and "Save All"
buttons rather than building their backends. R3c (HR Scheduling Platform
Integration) will undo this neutering and wire those buttons to a real
canonical endpoint.

Remaining R3a work:
- Bump `package.json` to 1.0.27, fuse 20, build 20260505.8
- Bump `README.md` to 1.0.27 / 20
- Sync sub-package versions (`frontend/`, `packages/analyst-client/`,
  `packages/global-dashboard/`, `packages/global-dashboard-server/` if
  appropriate)
- Open and merge R3a PR

### R3b → v1.0.28 — GD Custom Regional Query (CISO query tool)

The CISO uses the Global Dashboard "Custom query" card at line 271 of
`global-dashboard.jsx` to run queries against data the GD has aggregated
from regional MCs. The current state has a placeholder Input field with
no `value`/`onChange` binding (so it cannot capture text) and a Run button
calling the unmounted `/api/v059/metrics` with empty body.

Backend work:
- New canonical route file `server/routes/gd-query.js`
- `POST /api/gd/query` accepts a query template id plus parameters; runs
  against aggregated regional data; returns paginated results
- Query template registry — start with the predefined queries already in
  the GD (`burnout_trends`, `turnover_risk`, `cert_gaps`, `automation_roi`)
  plus a parameterized free-form template that lets the CISO filter by
  region, date range, and a regex over a chosen field
- Audit logging — every query run by a CISO is logged with the template
  id, parameters, and result count (not the result content) for forensic
  trail
- Authorization — restricted to admin role (CISO-level)

Frontend work:
- Add `customQuery` state to GD with `queryText` value and onChange binding
- Wire the Run button to `api.post('/api/gd/query', {...})` with the
  captured text
- Render structured results below the Run button — table view with
  columns derived from the response, plus an "Export" button for CSV
  download

Mount in `server/index.js` with `authMiddleware(['admin'])`.

Estimated 14 commits.

### R3c → v1.0.29 — HR Scheduling Platform Integration

Builds the backend for the MC "Per-Analyst Scheduling" card at line 4550
of `firealive-mc.jsx`. The card has a Platform selector (UKG/Kronos,
Workday, ADP, BambooHR, Manual), an API URL field, a Sync button, a
per-analyst hour-slot grid, and a Save All button.

The Sync and Save All buttons were neutered in R3a commit 14 — this phase
restores them by building real backends.

Backend work:
- New canonical route file `server/routes/scheduling-platform.js`
- New table `scheduling_platform_config` storing per-platform credentials
  (encrypted), API URLs, sync intervals, last sync timestamp, last sync
  status
- Adapter modules in `server/services/scheduling-platforms/`:
  - `ukg-kronos.js` — UKG Pro / Kronos Workforce integration
  - `workday.js` — Workday Scheduling REST API
  - `adp.js` — ADP Workforce Now
  - `bamboohr.js` — BambooHR Time Off and Schedules
  - `manual.js` — manual mode (FireAlive is the system of record)
  - Each adapter exposes `pullAvailability()` and `pushSchedule()`
- Endpoints:
  - `GET /api/scheduling/config` — retrieve current platform config
  - `PUT /api/scheduling/config` — save platform selection + URL +
    credentials (admin-only)
  - `POST /api/scheduling/sync` — trigger platform sync (pulls
    availability, returns updated analyst availability)
  - `POST /api/scheduling/save-all` — bulk save the per-analyst slot grid
    as a single transaction
- The credential storage uses the same encryption tier as `/api/integrations/`
  (Tier-1 encryption for storage, decrypted only when adapter calls
  external API)

Frontend work:
- Add state for `platformConfig`, `analystSchedules`
- Wire Platform selector and API field to `api.put('/api/scheduling/config')`
- Wire Sync button to `api.post('/api/scheduling/sync')` — undoes R3a
  commit 14 neutering
- Wire Save All button to `api.post('/api/scheduling/save-all', {schedules})`
  — undoes R3a commit 14 neutering
- Surface sync status and last-sync timestamp

Estimated 18 commits.

### R3d → v1.0.30 — External Restore for compromised AC recovery

Builds the External Restore feature documented in FEATURE-GUIDE lines
580-587. The MC has UI for this (External Restore card with Source select,
Path input, Key input, Browse button, Restore button). The MC currently
calls `/api/v054/clients/restore`, which is a stub that just audit-logs
and returns success.

Backend work:
- New canonical route file `server/routes/external-restore.js`
- New table `external_restore_sources` storing per-source config (network
  share / NAS / S3 / Azure Blob / SFTP) with encrypted credentials
- Source adapter modules in `server/services/external-restore/`:
  - `network-share.js` — SMB/CIFS access
  - `nas.js` — NAS-specific protocols
  - `s3.js` — AWS S3
  - `azure-blob.js` — Azure Blob Storage
  - `sftp.js` — SFTP
  - Each adapter exposes `listBackups()`, `fetchBackup()`,
    `verifyIntegrity()`
- Endpoints:
  - `GET /api/external-restore/sources` — list configured sources
  - `POST /api/external-restore/sources` — add a source (admin)
  - `GET /api/external-restore/browse/:sourceId` — list backups in a source
  - `POST /api/external-restore/preview/:sourceId/:backupId` — preview
    backup contents (file listing, sizes, integrity check result)
  - `POST /api/external-restore/restore/:sourceId/:backupId` — execute
    restore on a target AC (decompresses, EDR-scans every file using R0's
    EDR file inspection table, applies)
  - EDR scan integration: every file in the external backup must pass EDR
    inspection before restoration. Files flagged by EDR halt the restore
    with a quarantine notice and detailed file-by-file scan report.
- Audit log every step (browse, preview, restore start, EDR scan results,
  restore complete, restore failed)
- Authorization — admin only

Frontend work:
- MC External Restore card: capture Source dropdown, Path input, Key input
- Browse button → `GET /api/external-restore/browse/:sourceId`
- Restore button → `POST /api/external-restore/restore/:sourceId/:backupId`
- Show EDR scan progress and results
- Surface success/failure with detailed status

Estimated 16 commits.

### R3e → v1.0.31 — Config Lock with MFA

Builds the GD config lock feature at line 186 of `global-dashboard.jsx`.
The Lock/Unlock button currently calls `/api/v1/config/lock` which has no
canonical mount. The button does have a real `window.prompt` MFA flow in
the frontend; the backend just needs to verify and persist.

Backend work:
- New canonical route file `server/routes/config-lock.js`
- New table `config_lock_state` storing locked/unlocked, timestamp, locked_by
- Endpoints:
  - `GET /api/config/lock` — current lock state
  - `POST /api/config/lock` — toggle lock state with MFA code verification
- MFA verification calls into the same TOTP service built in R3f
- When config is locked, all admin-only config-modifying endpoints check
  the lock state and reject with 423 Locked + a message about needing
  unlock
- Authorization — admin only

Frontend work:
- Repoint the GD Lock/Unlock button to `/api/config/lock`
- Show lock state visually across all GD config-related UI elements
  (already wired via `configLocked` state)
- Disable config-modifying buttons app-wide when locked (already partially
  done via `disabled={configLocked}` attributes throughout the GD)

Estimated 8 commits.

### R3f → v1.0.32 — MFA TOTP Setup

Builds the GD MFA TOTP Setup card at line 349 of `global-dashboard.jsx`.
The card currently shows a placeholder QR code (just the text "TOTP QR")
and calls `/api/auth/mfa/verify` with empty body. There is no canonical
MFA route file.

Backend work:
- New canonical route file `server/routes/mfa.js`
- New table `mfa_secrets` storing per-user TOTP secret (encrypted,
  Tier-1), recovery codes (encrypted), and enrollment timestamp
- TOTP secret generation using `otplib` or `speakeasy` (Node.js MFA
  libraries)
- QR code generation using `qrcode` library — renders the otpauth URI
  as a base64-encoded PNG returned to the frontend
- Endpoints:
  - `POST /api/auth/mfa/enroll` — generate secret + QR code; returns base64
    PNG and provisioning URI; stores secret pending verification
  - `POST /api/auth/mfa/verify` — verify a 6-digit TOTP code; on success,
    activates the secret and returns recovery codes (one-time display)
  - `POST /api/auth/mfa/disable` — disable MFA (requires a current valid
    code or recovery code)
  - `POST /api/auth/mfa/use-recovery` — use a recovery code instead of
    TOTP (consumes the code, returns success or failure)
- The auth middleware gains an MFA-required check for admin and lead roles
  if MFA is enrolled — login flow returns a `mfa_required: true` flag
  that the frontend handles before issuing the JWT

Frontend work:
- GD MFA card: render the real QR code from base64 PNG response (replace
  the "TOTP QR" placeholder)
- Capture the 6-digit code in the Code input
- Wire Verify button to `/api/auth/mfa/verify`
- Add recovery code display modal after successful enrollment
- Add MFA challenge step to the login flow

Estimated 12 commits.

### R3g → v1.0.33 — Compliance scan canonical repoint

Repoints the GD Compliance Reports card at line 515 of
`global-dashboard.jsx`. The Generate button currently calls
`/api/v1/compliance/scan` which is unmounted. The canonical
`compliance-monitoring.js` route file is mounted at `/api` (line 140 of
`server/index.js`) and exposes the framework-driven scan endpoints.

Backend work:
- Audit canonical compliance-monitoring endpoints — confirm coverage of:
  NIST CSF, ISO 27001, SOC 2, HIPAA, GDPR, DORA, CCPA, PIPEDA, LGPD,
  NIS2, CPS 234, Cyber Essentials, FISMA (the frameworks listed in the
  GD selector)
- Add any missing frameworks to the canonical scanner

Frontend work:
- Repoint Generate button to `POST /api/compliance/scan` with the
  selected framework
- Render scan results in a structured panel (replace the toast-only
  feedback)

Estimated 8 commits.

### R3h → v1.0.34 — Helper recognition leaderboard with opt-in

Builds the helper recognition leaderboard documented in FEATURE-GUIDE
line 207. The Feature Guide explicitly requires opt-in visibility
("helpers choose if they're visible"). The v054 leaderboard query has no
opt-in mechanism.

Backend work:
- Add `helper_pay_visible` column to `users` table (BOOLEAN DEFAULT 0)
  via schema migration
- New endpoints in canonical `server/routes/helper-pay.js`:
  - `GET /api/helper-pay/leaderboard` — top N helpers by points, filtered
    by `helper_pay_visible = 1`
  - `PUT /api/helper-pay/visibility` — analyst toggles their own opt-in flag

Frontend work:
- Add visibility toggle to the AC Helper-Pay tab
- Add leaderboard view to the MC Helper-Pay tab
- Add leaderboard summary to the GD (regional helper recognition)

Estimated 8 commits.

### R3i → v1.0.35 — Backup multi-schedule with regulatory presets

Builds the multi-schedule backup feature documented in FEATURE-GUIDE
lines 562-564. The Feature Guide describes regulatory-framework presets
(GDPR, HIPAA, SOX, PCI-DSS, etc.). The current canonical
`/api/backup/config` supports a single schedule with no presets.

Backend work:
- Extend `backup_schedules` table to support multiple named schedules per
  deploy
- New `regulatory_presets` table with framework name, retention policy,
  encryption requirement, destination type, frequency
- Endpoints:
  - `GET /api/backup/schedules` — list all configured schedules
  - `POST /api/backup/schedules` — add a named schedule (optionally from
    preset)
  - `PUT /api/backup/schedules/:id` — modify schedule
  - `DELETE /api/backup/schedules/:id` — remove schedule
  - `GET /api/backup/presets` — list available regulatory presets
- Each schedule runs independently in the scheduler service
- Each preset applies sensible defaults for its regulatory framework
  (e.g., GDPR: 7-year retention, AES-256, EU-region storage)

Frontend work:
- Extend MC Backup tab to show multi-schedule list
- Add preset selector with descriptions of each framework's requirements
- Show which schedules apply to which frameworks

Estimated 12 commits.

### R3j → v1.0.36 — SOAR / Ticketing / Routing audit and burnout routing build

Audits and completes the v054 endpoints related to SOAR, ticketing, and
ticket routing. Per user direction: "I don't know how burnout routing
should happen — Claude figured it out. I don't care as long as it actually
happens."

The architecture established in earlier phases is: FireAlive does NOT
distribute tickets directly. The SOAR distributes tickets. FireAlive
provides the SOAR with routing variables (analyst capacity scores,
tier assignments, panic mode flag, available status, etc.) via
`/api/routing/soar`. The SOAR uses these variables in its own ticket
distribution logic to implement burnout-aware routing.

Backend work:
- Audit canonical `/api/integrations/soar` against v054 `/soar/config`
  and `/soar/status`. Build any unique fields/capabilities found in v054
  into canonical.
- Audit canonical `/api/integrations/ticketing` against v054
  `/ticketing/config` and `/ticketing/queue-metadata`. Build any unique
  capabilities into canonical.
- Audit canonical `/api/routing` against v054 `/routing/distribute` and
  `/routing/status`.
- v054 `/routing/distribute` was misconceived (tries to do ticket
  distribution from FireAlive). The real burnout routing happens in the
  SOAR using FireAlive's published variables. If any UI in the MC, AC,
  or GD has a button labeled "Distribute" or similar that maps to this
  endpoint, that UI is rewired to either (a) trigger the SOAR's
  distribute action via the SOAR connector, or (b) display the current
  routing state without claiming to redistribute.
- Build a complete `/api/routing/variables` endpoint that the SOAR polls
  to get the current burnout-routing variables (per-analyst capacity
  score, tier, available, in-panic-mode), so the SOAR has a stable
  contract for burnout-aware distribution.
- Build a SOAR webhook receiver `/api/routing/soar-events` that the SOAR
  calls back when it makes routing decisions, so FireAlive can record
  which analyst received which ticket and feed that back into capacity
  tracking.

Frontend work:
- Whatever buttons/views exist in MC for SOAR config, ticketing config,
  routing distribute, routing status get wired to the canonical
  endpoints.
- Surface the SOAR's current burnout routing state in the MC (which
  variables the SOAR is currently using, which analyst was last assigned,
  panic mode active/inactive).

Estimated 14 commits.

### R3k → v1.0.37 — v059 infrastructure features (cloud, full-suite backup, CI/CD, regression)

Builds the four v059 endpoints that are currently mock JSON manifests.
These are real CISO-facing features per user direction: "Everything in
the UI is something I wanted."

Backend work:

**Cloud deployment manifest (`/api/cloud/package`):**
- Real generation of cloud deployment artifacts: Docker image manifest
  with SHA-256 hashes, Kubernetes deployment YAML, Helm chart, AWS
  CloudFormation template, Azure Bicep template, GCP Deployment Manager
  template
- Includes SBOM (Software Bill of Materials, Syft/SPDX format)
- Each artifact signed with Sigstore/Cosign
- Endpoint downloads the requested artifact format

**Comprehensive system backup (`/api/backup/full-suite`):**
- Backup beyond just the SQLite database: includes config files, key
  material (re-encrypted with backup KEK), audit log export, integration
  configs, EDR scanner state, and the FireAlive binary itself for full
  disaster recovery
- Returns a single encrypted ZIP that, when restored, recreates a
  complete FireAlive deploy from scratch
- Distinct from the regular DB-only backup at `/api/backup`

**CI/CD pipeline view (`/api/cicd/full`) — CISO-facing feature:**
- Returns the current state of the FireAlive deployment pipeline so the
  CISO can verify deployment integrity
- Pipeline data includes: current production version, version in staging,
  pending releases, last successful build SHA, build provenance (SLSA
  Level 3), signature verification status (Sigstore/Cosign), SBOM
  reference, recent deployments with timestamps and signers, dependency
  pin verification (every dependency's locked SHA-256 vs installed
  SHA-256), CVE scan results from the last build (Trivy/Grype),
  Kubernetes admission controller status (which images are signed and
  admitted)
- This is the supply-chain integrity dashboard for FireAlive itself —
  the CISO needs visibility into whether the FireAlive instance running
  in their SOC came from a verified, signed, dependency-pinned build
  with no known CVEs
- Per FEATURE-GUIDE supply-chain protection: this view surfaces the
  protections so the CISO can verify them

**On-demand regression test (`/api/regression/run`):**
- Triggers the existing `RegressionRunner` service against the running
  deploy
- Returns pass/fail per scenario with detailed failure traces
- Used by the CISO to validate that a deployment behaves correctly
  before unlocking production traffic, or after a rollback

Frontend work:
- MC and/or GD buttons that map to these features get wired to the
  canonical endpoints
- Result rendering for each (especially the CI/CD pipeline view, which
  needs a structured display of all the integrity attributes)

Estimated 18 commits.

### R3l → v1.0.38 — v100 AI burnout coverage audit and gap-fill

Audits v100 endpoints (`/signals/*`, `/impacts/*`, `/skills/*`,
`/training-recommendations/*`, etc.) against the canonical
`signal-collector.js`, `system-health.js`, and other services. Builds any
missing capabilities into canonical.

Backend work:
- For each v100 endpoint, identify the corresponding canonical service
  call. Verify that the canonical service produces equivalent output.
- Where v100 has unique fields (e.g., a v100 `/skills/:analystId`
  response that includes skill-decay timestamps not present in
  canonical), port those fields into the canonical signal-collector.
- Verify v100 `/integrations/save`, `/integrations/test`,
  `/integrations/status` are covered by canonical `/api/integrations`.

Frontend work:
- Repoint any AC, MC, or GD callsites still pointing at `/api/v100/*`.

Estimated 10 commits.

### R3m → v1.0.39 — Final orphan cleanup

Once every endpoint in v054, v059, v100 has been independently verified
working in canonical:

- Delete `server/routes/v054-features.js`
- Delete `server/routes/v059-features.js`
- Delete `server/routes/v100-features.js`
- Delete the 6 orphan service classes used only by v100:
  - `ai-burnout-engine.js`
  - `assessment-service.js`
  - `backup-service.js`
  - `compliance-scanner.js`
  - `system-health-monitor.js`
  - `notification-service.js`
- Audit one final time that no callsite anywhere references
  `/api/v054/*`, `/api/v059/*`, or `/api/v100/*` paths
- Update FEATURE-GUIDE if any features still need a "planned, not yet
  operational" status note (this should be empty if R3a-R3l did their
  job)

Estimated 10 commits.

---

## After R3 — original BUILD-PLAN-v5 sequencing resumes

These phases were deferred when R3 expanded. They resume after R3m ships:

- N1 → v1.0.40: notifications + AI message migration to dispatcher
- U1 → v1.0.41: feature toggle greyed
- U2 → v1.0.42: board threading + flagging + evidence vault
- U3 → v1.0.43: UI corrections batch (AC irLevel /5 vs /10 mismatch, etc.)
- U4 → v1.0.44: Report + Compliance PDF/DOCX
- K1 → v1.0.45: KB semantic search
- B1-B5 → v1.0.46+
- G1+ → v1.0.52+: GD Backend (reverses installer disable on last commit)
- H1/H2/H3 → v1.0.62+
- C1/C2/C3 → v1.0.7X+

---

## Working conventions reminder (unchanged from v6)

- FLAT commit numbering per phase (Commit 1, 2, 3...)
- ONE commit per response, then wait for "Ready"
- One file per commit (iPhone GitHub mobile workflow)
- Inline edits: high-line-number-first ordering when multi-edit; show the
  existing line text alongside the line number for verification before
  pasting replacements
- Branch name, commit subject, commit description in copyable code blocks
- Do not reference internal planning docs in public commit/PR text
- ASCII-only strings; lowercase `v` in version tags; em-dash (—) in
  release notes
- Every version bump: version + fuseCounter + buildId
- Grep all relevant fields across docs before drafting version bumps
- Build plan revisions get a new file (BUILD-PLAN-v7, v8, ...) rather
  than overwriting older versions

---

## Reminder for future Claude sessions

If you are reading this build plan and considering deleting files,
neutering UI features, or replacing onClick handlers with planned-feature
notices: STOP. Re-read the foundational rule at the top. Build the
backend. The user is one person, has been clear about this, and is
exhausted from repeating it. Do not make them say it again.

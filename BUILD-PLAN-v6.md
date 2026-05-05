# FireAlive Build Plan v6

**Owner:** Peter Mancina
**Last revised:** May 5, 2026
**Status:** R3 in progress (split into R3a, R3b, R3c, R3d)

This document supersedes BUILD-PLAN-v5. The R3 phase has been re-scoped after
an honest endpoint-by-endpoint audit of the three unmounted route files
(`server/routes/v054-features.js`, `server/routes/v059-features.js`,
`server/routes/v100-features.js`). Earlier build-plan iterations described
R3 as "mount the v054/v059/v100 files" — that direction is wrong, and
attempting to delete the files outright (as a previous session attempted
on the abandoned `phase-1.4-deadcode-sweep` branch) is also wrong.

## What v054/v059/v100 actually are

These three files are intentional roadmap files. Each declares endpoints
for features that are documented in `FEATURE-GUIDE.md` but were not yet
implemented in canonical route files at the time the file was authored.
As features get properly built canonically, the corresponding endpoints
in v054/v059/v100 become genuinely redundant — and only at that point
can they be deleted without losing the roadmap.

A previous Claude session in the "SOC Wellbeing Platform 10" chat tried
to delete v054 and v059 outright on the assumption that they were dead
code. The user correctly identified that the files contained features
that had no canonical home and reverted those deletion commits. This
build plan exists in part to prevent that mistake from recurring.

## Audit findings — what's actually missing canonically

After R0/R1/R2 reconciliation work landed in v1.0.24-v1.0.26, the
remaining gaps between v054/v059/v100 and the canonical route files are:

### Class A — Features with real implementations in v054/v059/v100 that need a canonical home

These are real working endpoints whose only HTTP exposure today is the
unmounted file. They need to be ported into a canonical route file before
the unmounted file can be deleted.

1. **Audit chain integrity verification** — `verifyAuditChain` middleware
   exists and works; v059 `/audit/integrity` is the only HTTP route
   exposing it. Canonical `audit.js` does not have an integrity endpoint.
   FEATURE-GUIDE references "Immutable SHA-256 chain" as a compliance
   feature.

2. **Metrics over HTTP** — `MetricsCollector` service exists and is used
   by websocket-server.js; v059 `/metrics` and `/metrics/cef` are the
   only HTTP routes exposing it. The Global Dashboard has one caller at
   `/api/v059/metrics`. Canonical has no metrics route.

3. **Training completion submission** — analyst-side submission of
   external module completions (LetsDefend / HackTheBox / TryHackMe etc.
   per FEATURE-GUIDE line 167). The AC has a "Submit Training Completion"
   UI form. Canonical `/api/training` has `/certificates` (POST, for
   certificate uploads) and `/completions` (GET, for listing) but no POST
   endpoint for submitting a module-completion record. v054
   `/training/submit-completion` is the only implementation.

4. **Heartbeat endpoint** — `users.last_heartbeat` column was added in R0
   for client liveness tracking. v100 `/heartbeat` is the only endpoint
   that updates it. Canonical has no heartbeat route.

5. **Pseudonym rotation timestamp** — `users.pseudonym_rotated_at` column
   was added in R0. The canonical pseudonym rotation in
   `v025-features.js` does not write this column; only v054
   `/pseudonyms/rotate` writes it. The column is currently never read,
   but the feature is intended to surface "last rotated at" times in the
   Pseudonyms tab.

### Class B — Features that need actual implementation work

These are documented features that have neither a canonical implementation
nor a working v054/v059/v100 implementation. The v054/v059/v100 endpoints
for these are stubs that return success without doing real work.

6. **External Restore for compromised AC recovery** — FEATURE-GUIDE lines
   580-587 documents the workflow: tear down compromised AC, install
   fresh copy, restore from external source (network share / NAS / S3 /
   Azure / SFTP). The MC has UI for this (External Restore card with
   Source select, Path input, Key input, Browse button, Restore button).
   The MC calls `/api/v054/clients/restore`, which is a stub that just
   audit-logs and returns success. Canonical `/api/restore` only handles
   internal restore points. Real implementation work is required.

7. **Helper recognition leaderboard with opt-in visibility** —
   FEATURE-GUIDE line 207 documents the leaderboard with an opt-in
   requirement ("helpers choose if they're visible"). v054
   `/helper-pay/leaderboard` queries the F5 ledger but has no opt-in
   mechanism. Canonical `helper-pay.js` has no leaderboard endpoint at
   all. Real implementation work is required: add a per-user opt-in flag,
   build the canonical leaderboard endpoint that respects it.

8. **Backup multi-schedule with regulatory presets** — FEATURE-GUIDE
   lines 562-564 documents multiple backup schedules with regulatory-
   framework presets (GDPR / HIPAA / SOX / PCI-DSS / etc.). Canonical
   `/api/backup/config` supports a single schedule (daily/weekly/monthly)
   with no presets. v054 `/backup/schedule` is also partial — accepts
   `{interval, type, retention}` but no regulatory presets. Neither
   delivers the documented feature.

### Class C — Already canonically delivered, v054/v059/v100 versions are safely redundant

For each of these, the canonical implementation either matches or exceeds
what the unmounted file declares:

- IAM offboarding (canonical `/api/iam` better — input validation, role check, error handling)
- Upskilling scheduling (canonical `/api/upskilling` better — slot-format validation)
- Assessments (canonical `/api/assessments` better — proper schema, notifications, assignment tracking)
- Compliance reports (canonical `/api/compliance/report/:framework` better — service-driven, framework whitelist)
- Pseudonym rotation core (canonical via v025 — collision-free generation)
- Helper-pay rating (already 410 redirect to F5 canonical)
- Feature toggles (canonical `/api/features/`)
- SOAR/Ticketing API connectivity (canonical `/api/integrations/:type` covers both)
- Burnout-aware routing (canonical `/api/routing/soar` writes 6 variables consumed by SOAR; FireAlive does NOT do per-ticket assignment — that is the SOAR's job)
- AI Burnout signals (canonical uses `signal-collector.js` service)
- Notifications (canonical `/api/notifications`, `/api/inbox`, `/api/inbox/admin`)
- Backup creation/history (canonical `/api/backup`)
- Runbook generation (canonical `/api/runbook/full` is real with format buffers)
- TTX generation (canonical `/api/ttx/sitman` and `/aar` are real)
- Shift handoff (canonical `/api/handoffs` POST auto-generates team state summary)
- Config snapshots (canonical `/api/restore/configs`, `/config-save`, `/config-revert`)
- Audit log writes (handled automatically by audit middleware at every route handler — frontends should not POST arbitrary audit events)

### Class D — Pure mock JSON manifests

These v059 endpoints return hardcoded JSON describing what FireAlive's
cloud deployment manifest, backup full-suite component list, or CI/CD
pipeline structure look like. They have no real backing functionality
and no UI consumer:

- v059 `/cloud/package`, `/backup/full-suite`, `/cicd/full`

These are safe to delete in the final cleanup phase.

## R3 sequencing

The R3 sweep is split into four PRs to keep each release coherent and
testable. The unmounted route files stay in place until the final phase,
acting as roadmap markers for the still-unbuilt features.

### R3a → v1.0.27 — Honest port phase

Port the five Class A features into canonical route files. Repoint the
matching frontend callsites. The unmounted files stay in place.

Estimated 15 commits:
- Add `GET /api/audit/integrity` to canonical `audit.js`
- Add new canonical metrics route file with `GET /api/metrics` and `GET /api/metrics/cef`
- Mount the metrics route in `server/index.js`
- Add `POST /api/training/completions` to canonical `training.js`
- Add new canonical `GET /api/heartbeat` (or `POST /api/heartbeat`) route
- Mount the heartbeat route in `server/index.js`
- Add `pseudonym_rotated_at` write to v025 `/pseudonyms/rotate-all`
- Repoint MC `/api/v054/iam/confirm-status` callsites to `/api/iam/confirm-status` (with `analystId` field name)
- Repoint MC `/api/v054/upskilling/schedule` per-analyst callsite to canonical (with proper `{analystId, slot}` shape); remove or refactor the non-functional `{action: "sync"}` and `{schedules: "all"}` calls
- Repoint GD `/api/v059/metrics` callsite to new canonical `/api/metrics`
- Repoint AC heartbeat to new canonical `/api/heartbeat`
- Update root `package.json` to 1.0.27, fuse 20, build 20260505.8
- Update README to 1.0.27 / 20
- Sync sub-package versions (frontend, analyst-client, global-dashboard)

### R3b → v1.0.28 — External Restore feature build

Build the External Restore feature properly. New canonical endpoints to
handle network share / NAS / S3 / Azure / SFTP source paths. EDR file
inspection on the restored archive (R0 schema established the EDR file
inspection table). Integrity verification of the external backup before
extraction. Repoint the MC External Restore UI card to call the new
endpoints with the proper request shape.

Estimated 12 commits.

### R3c → v1.0.29 — Helper recognition leaderboard with opt-in

Add a per-user `helper_pay_visible` column (or similar opt-in mechanism).
Add `GET /api/helper-pay/leaderboard` to canonical `helper-pay.js` that
filters by the opt-in flag. Add the AC-side toggle to control the user's
own visibility. Add the MC-side leaderboard view per FEATURE-GUIDE line 207
("Reviews helper recognition leaderboard").

Estimated 6 commits.

### R3d → v1.0.30 — Backup multi-schedule with regulatory presets

Extend `/api/backup/config` to support multiple named schedules. Add a
regulatory-framework preset table (GDPR, HIPAA, SOX, PCI-DSS, etc.) that
auto-configures retention/encryption/destination to match each framework's
requirements. Update the MC Backup tab UI to expose multi-schedule
management with preset selection.

Estimated 8 commits.

### R3e → v1.0.31 — Final orphan cleanup

Once all features have canonical homes verified through R3a/b/c/d:
- Delete `server/routes/v054-features.js` (and remove its mount lines if any)
- Delete `server/routes/v059-features.js`
- Delete `server/routes/v100-features.js`
- Delete the 6 orphan service classes used only by v100:
  `ai-burnout-engine.js`, `assessment-service.js`, `backup-service.js`,
  `compliance-scanner.js`, `system-health-monitor.js`, `notification-service.js`
- Final repointing of any remaining callsites
- Update FEATURE-GUIDE if any features still need a "planned, not yet operational" status note

Estimated 10 commits.

## After R3 — original BUILD-PLAN-v5 sequencing resumes

- N1 → v1.0.32: notifications + AI message migration to dispatcher
- U1 → v1.0.33: feature toggle greyed
- U2 → v1.0.34: board threading + flagging + evidence vault
- U3 → v1.0.35: UI corrections batch (AC irLevel /5 vs /10 mismatch, etc.)
- U4 → v1.0.36: Report + Compliance PDF/DOCX
- K1 → v1.0.37: KB semantic search
- B1-B5 → v1.0.38+
- G1+ → v1.0.44+: GD Backend (reverses installer disable on last commit)
- H1/H2/H3 → v1.0.54+
- C1/C2/C3 → v1.0.6X+

## Working conventions reminder

- FLAT commit numbering per phase (Commit 1, 2, 3...)
- ONE commit per response, then wait for "Ready"
- One file per commit (iPhone GitHub mobile workflow)
- Branch name, commit subject, commit description in copyable code blocks
- Do not reference internal planning docs in public commit/PR text
- ASCII-only strings; lowercase `v` in version tags; em-dash (—) in release notes
- Every version bump: version + fuseCounter + buildId
- Grep all relevant fields across docs before drafting version bumps
- Build plan revisions get a new file (BUILD-PLAN-v6, v7, ...) rather than overwriting older versions

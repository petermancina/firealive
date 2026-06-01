# Runtime Monitoring & System Health

This document describes the runtime-monitoring, alert-routing, and integration-health
surface introduced in phase B3 (v1.0.50), and records the work that was deliberately
deferred out of B3 so it stays tracked.

It covers the Management Console (MC) and the main server. The Global Dashboard (GD)
server and the Abuse Review Console (ARC) are addressed in the "Deferred work" section
at the end — their in-platform self-protection is **not** built yet, and this document
is the canonical record of that gap.

---

## What B3 built (MC + server)

B3 wires the previously cosmetic System Health tab to a real detection-and-routing
pipeline. The pieces, all under `server/services/` unless noted:

### Detection

- **`runtime-monitor.js`** — continuous file-integrity monitoring (FIM) on a fixed
  interval plus anomaly detection on CPU, memory, and DB-read volume. Sustained-load
  detection uses hysteresis: a metric must stay above its *enter* threshold for a
  *dwell* number of consecutive sampling intervals before an alert fires, and must fall
  back below its *exit* threshold before the condition clears. Thresholds are
  admin-configurable and persisted under the `runtime_monitor_thresholds` config key;
  they are clamped to safe bounds and the exit threshold is always held at or below the
  enter threshold.
- **`bandwidth-monitor.js`** — windowed bandwidth anomaly detection feeding the same
  alert path.
- **`metrics-collector.js`** — assembles the aggregate metric snapshot and its CEF
  rendering for SIEM. Integration health is exposed as a flat, CEF-safe scalar-per-key
  map drawn from the most recent cached probe (or a `not_configured` /
  `probes_disabled` / `configured_not_probed` placeholder when no probe is available).

### Routing

- **`alert-router.js`** — `routeAlert(db, alert, opts)` fans an alert out across
  channels by severity. **Audit is always recorded** and runs before the de-duplication
  gate, so it cannot be suppressed or disabled. A 10-minute de-duplication window per
  `type|severity` prevents alert storms. Each channel is isolated and never throws, so
  one failing channel cannot starve the others. The default matrix escalates by
  severity: **info** routes to audit only; **warning** adds SIEM; **high** adds SOAR,
  SIEM, and an in-app notification to admins/leads; and **critical** adds email and
  webhook on top of those. The matrix is overridable per deployment via the `alert_routing_matrix` config key
  (merged over the defaults), and the webhook target is the `alert_webhook_url` key.
  Notifications are delivered to active admins/leads directly and are not gated on
  individual user notification preferences.
- **`siem-push.js`** — `pushAlert` reuses the existing SIEM adapter to emit a CEF event
  over syslog (TCP/UDP/TLS); `emailAlert` sends to the operational
  `notification_config.email_address` via SMTP. **Operational alert email never uses an
  individual user's `users.email`**, which is anonymity-sensitive and HR-sync-only.

### Integration health

Integration health is an **opt-in, read-only** probing layer. It is disabled by default
at both the master level and per integration, and probes never mutate integration data
(with one explicitly gated exception noted below).

- **`integration-health-config.js`** — canonical flag reader/writer. The master switch
  lives in its own `integration_health_probes_enabled` key; everything else lives in the
  `integration_health_settings` JSON: `intervalMinutes` (5–1440, default 60),
  `periodicEnabled`, per-integration enable flags, and `kmsDeep`. The probeable
  integration keys are: `soar`, `siem`, `ticketing`, `iam`, `kms`, `storage`, `edr`.
- **`integration-health.js`** — the orchestrator harness. `probeAll` applies a gating
  ladder (master off → `disabled`; integration flag off → `disabled`; not configured →
  `not_configured`; no probe registered → `not_implemented`; otherwise run the probe
  under a timeout). Probes run bounded-concurrency with jitter, each under a timeout that
  never rejects. Every result is normalized to one of:
  `ok`, `unreachable`, `auth_failed`, `permission_denied`, `deep_skipped`, `disabled`,
  `not_configured`, `not_implemented`, `timeout`, `error`.
- **`integration-health-probes.js`** — the probe registry. KMS uses a lightweight
  read-only provider listing by default; the **deep** probe (only when `kmsDeep` is on)
  performs a live wrap/unwrap round-trip and is the one place a probe touches live state.
  Storage probes registered destinations; LDAP/AD reads the IAM config from
  `team_config`; SIEM does a connect-only TCP/TLS reachability check (no event sent);
  SOAR and ticketing use a health endpoint; EDR enumerates the configured malware
  scanners and exercises their live auth.
- **`integration-health-scheduler.js`** — a self-rescheduling, jittered cycle that is a
  no-op until both the master and periodic flags are on. It probes, caches the result to
  `integration_health_last_results`, and routes failures through `alert-router` (EDR
  failures as critical, others as high; benign states are not alerted). It also runs a
  one-shot update smoke test ~30 s after a new build boots, keyed on
  `integration_health_last_probed_build` so it runs once per build.

### Routes

- **`server/routes/alert-config.js`** (admin-gated) — GET the matrix, thresholds, and
  metadata; PUT to merge a new matrix, push thresholds into the runtime monitor, and set
  or clear the webhook URL. Writes an `ALERT_CONFIG_UPDATED` audit event.
- **`server/routes/integration-health.js`** (admin-gated) — GET/PUT the settings;
  POST `/probe` to run `probeAll` now and cache the result; GET `/results` to read the
  cached result without a live probe. Writes `INTEGRATION_HEALTH_CONFIG_UPDATED` and
  `INTEGRATION_HEALTH_PROBE` audit events.

### UI

The MC **System Health** tab (Monitoring group) renders two self-contained admin panels:
an **Integration Health** panel (settings toggles + on-demand "Probe Now" + colour-coded
results table) and an **Alert Routing** panel (the per-severity × channel matrix with
audit shown as always-on, the webhook URL, and the sustained-load threshold editor).

### Regression coverage

The canonical regression runner gained two integration-aware areas:

- The **`integrations`** category treats optional external integrations (SOAR, SIEM,
  ticketing, LDAP/AD, backup storage) with a pass/fail/skip trichotomy — pass when
  configured and reachable, fail when configured but broken, skip when not configured —
  while EDR / malware-scanner coverage is **required** and fails when absent.
- The **`integration_health`** category reflects the most recent cached probe without
  running a live probe, so a regression run stays side-effect-free.

### Config keys (summary)

`runtime_monitor_thresholds`, `alert_routing_matrix`, `alert_webhook_url`,
`integration_health_probes_enabled`, `integration_health_settings`,
`integration_health_last_results`, `integration_health_last_probed_build`.

---

## Deferred work and known gaps

B3 covers the **MC and main server**. During B3 an investigation found that the
Global Dashboard server and the Abuse Review Console have **no in-platform runtime or
endpoint self-protection** of their own. This is recorded here so it is not lost.

### GD / ARC self-protection (deferred to a future, separately scoped phase)

- The **GD server** today performs only aggregation, compliance, signing, and export.
  It has none of the B3 stack: no runtime monitor, no alert router, no
  metrics-collector, and no EDR / integration-manager surface. Compromise of the GD host
  is not currently detected by the platform itself.
- The **ARC** is likewise outside the B3 detection surface.
- Two GD-facing B3 items were intentionally **dropped from B3 and moved to this deferred
  scope**: the GD integration-health module and the GD System Health UI. The GD
  regression suite already carries **forward-aware** SOAR/SIEM, required-EDR, and
  `integration_health` checks; these are harmless skips today and are designed to
  activate once the deferred phase ships the backing surface.

### Stale compliance mapping (debt)

The GD compliance framework files and check modules currently describe the GD host's
EDR / endpoint monitoring as operator-managed and off-platform. Once the GD grows its
own runtime-monitoring and integration surface, those `verifiedControls` / customer-
responsibility mappings must be revisited so the compliance posture reflects what the
platform actually enforces rather than deferring it to the operator.

### Plan of record

Before any new phase is carved for this work:

1. Read the full forward-phase list in the current build plan and check whether GD/ARC
   host hardening (runtime monitoring, EDR/endpoint integration, alert routing,
   integration health, detection telemetry) is **already slated** under an existing
   phase (e.g. B4, B5a–B5g, H1–H3, C1–C3, K2/K3).
2. Only define a **new** phase if there is a genuine uncovered gap.
3. Either way, map the GD/ARC self-protection work **and** the stale compliance-mapping
   fixes against the existing plan rather than bolting them onto an unrelated phase.

This document is the durable pointer for that follow-up; the GD regression note in
`FEATURE-GUIDE.md` references it.

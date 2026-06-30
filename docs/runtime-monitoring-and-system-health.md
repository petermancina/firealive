# Runtime Monitoring & System Health

This document describes the runtime-monitoring, alert-routing, and integration-health
surface introduced in phase B3 (v1.0.50) for the Management Console (MC) and the main
server, and the matching **Global Dashboard (GD) self-protection** surface built in
phase B6a (v1.0.79).

The Abuse Review Console (ARC) is still outside this detection surface; its in-platform
self-protection is **not** built yet, and the "Deferred work" section at the end is the
canonical record of that remaining gap.

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

## What B6a built (GD self-protection)

B6a gives the **Global Dashboard server** its own in-platform self-protection, mirroring
the B3 stack. Everything here monitors and protects the **GD server itself** — its file
tree, its dependencies, its trust boundaries — and **never analyst data**, which the GD
never holds. The pieces live under `packages/global-dashboard-server/services/` unless
noted, and run on short-lived per-request SQLite connections like the rest of the GD.

### Detection

- **`gd-runtime-monitor.js`** — a recursive FIM over the GD server tree plus CPU /
  memory / DB-read anomaly detection with the same hysteresis model as B3 (enter / exit
  / dwell / cooldown). It starts at server boot, owns its own `unref()`'d timers, and
  routes every alert through the GD alert-router. Threshold overrides are read from
  `runtime_monitor_thresholds` and can be pushed live. The DB-read signal is fed a
  per-request rate proxy from the request-logging middleware (a spike may indicate a
  scan or exfiltration attempt against the GD query surface).

### Routing

- **`gd-alert-router.js`** — `routeGdAlert(db, alert)` with the same guarantees as the MC
  router: **audit is always written first** (before de-duplication), a 10-minute
  `type|severity` de-dup window, and isolated channels that never throw. Channels are
  audit, SOAR, SIEM + email, an in-app notification on the GD's shared notification queue
  (`type = 'security_alert'`), and webhook. There is **no websocket channel** — the GD
  has no analyst clients. The default matrix matches the MC's (info → audit only;
  warning adds SIEM; high adds SOAR + SIEM + notification; critical adds email + webhook)
  and is overridable via `alert_routing_matrix`.
- **`gd-siem-push.js` / `gd-siem-adapter.js`** — CEF over syslog (TCP/UDP/TLS) with a
  `GlobalDashboard` device-product, plus operational alert email (recipients from the
  GD `notification_config`, SMTP via environment).
- **`gd-soar-push.js`** — a transport-only SOAR dispatch (the audit + matrix are handled
  by the router, so SOAR never double-logs).

### Metrics

- **`gd-metrics-collector.js`** — `collect()` assembles a rollup of fleet, ingest
  freshness, compliance coverage, signing-key status, audit-chain integrity, backup
  status, unacknowledged notifications, integration health, runtime metrics, and system
  version, plus a CEF rendering for SIEM pull. It backs `GET /api/system/health-metrics`
  (the legacy cpu / memory / heap / uptime fields are preserved; the rollup is attached
  under `metrics`).

### Integration health (dependency probes)

An **opt-in, read-only** probing layer over the GD's own dependencies — disabled by
default at the master and per-integration level.

- **`gd-integration-health.js` / `gd-integration-health-probes.js`** — the same gating
  ladder and normalized statuses as B3, over three GD-specific probes: **kms** (the
  active audit-chain signing keys plus the hardware keystore / instance anchor),
  **storage** (writability of the GD backups directory), and **mc_trust** (active MCs vs
  approved-active signing-key coverage, with pending / staleness freshness). A periodic,
  `unref()`'d scheduler caches results to `integration_health_last_results`.

### External EDR seam

- **`malware_scanner_integrations`** (a GD table) plus CRUD under
  `/api/self-protection/config/edr` register an external EDR provider (CrowdStrike
  Falcon, Microsoft Defender for Endpoint, SentinelOne, Palo Alto Cortex XDR, Trellix,
  Sophos Intercept X, VMware Carbon Black, Cisco Secure Endpoint, Wazuh, Elastic Defend,
  LimaCharlie). Credentials are stored **AES-256-GCM-encrypted** and never returned. An
  external EDR is **additive**: the in-platform runtime-monitor provides the
  host-monitoring baseline, so none configured is acceptable.

### Config Lock

- **`config_lock_state`** (a singleton table), the registry-driven chokepoint
  (`gd-config-lock.js` + `gd-config-write-routes.js`), and the `/api/config/lock` routes
  freeze configuration-mutating requests while the platform is locked — a twin of the
  MC's control. Engaging the lock is immediate; **releasing it requires a fresh
  hardware-passkey (WebAuthn) assertion**, user-verified and bound to the CISO's own
  passwordless credential (the GD is hardware-key-only — there is no TOTP path). An idle
  window auto-re-locks an unlocked platform.

### Compromise scan

- **`POST /api/compromise-scan`** (CISO-only) runs eleven read-only self-integrity
  checks of the GD server — database integrity, audit-chain continuity, signing-key
  validity, hardware instance-anchor status, file-integrity, config-lock presence,
  memory, Node runtime, and more. Each check reports `pass` / `warn` / `fail`; the
  overall result is `clean` / `warnings` / `compromised`, and the run is audit-logged.

### Alert sources

The GD's own security events route through the alert-router so they fan out to
SIEM/SOAR/notification/webhook in addition to the audit log: `INGEST_SIGNATURE_REJECTED`
(a bad MC-push signature, at every ingest endpoint), `AUDIT_CHAIN_BREAK` (the manual
integrity endpoint and the periodic integrity timer), and `MC_SIGNING_KEY_REJECTED` (a
CISO rejecting an MC's signing key). The router's always-on audit preserves each event's
existing audit row; the fan-out is additive.

### Routes

- **`/api/self-protection/*`** (CISO/VP) — configuration writes live under `/config`
  (SIEM, SOAR, alert matrix, runtime thresholds, webhook, integration-health, EDR seam)
  and are frozen by the config-lock chokepoint when locked; operational reads (`/status`,
  `/integration-health` + `/integration-health/run`, `/runtime/metrics`,
  `/runtime/alerts`) are never gated.
- **`/api/config/lock`** — GET state, POST `/lock/unlock-options` (issue the unlock
  challenge), POST engage / release.
- **`/api/compromise-scan`** and **`/api/system/health-metrics`** as above.

### UI

The GD desktop **Monitoring Integrations** tab is a working self-protection console
(SIEM/SOAR/webhook config, the alert-routing matrix editor, dependency-probe toggles with
a run-now button and cached results, external-EDR CRUD, and live runtime-monitor
metrics). The **System Health** tab adds a subsystem-health rollup from the metrics
collector; the **Compromise Scan** tab renders the three-state results with per-check
detail; and the **Config Lock** control engages immediately and unlocks via the
hardware-passkey step-up.

### Regression coverage

The GD regression runner gained four B6a categories — `runtime_monitor`, `alert_routing`,
`config_lock`, and `self_protection` — and the forward-aware SIEM/SOAR and
integration-health checks auto-activate. The EDR check is no longer fail-closed-on-empty:
because the in-platform runtime-monitor provides the baseline, an external EDR is
additive and "none configured" is reported rather than failed.

### Config keys (summary)

`runtime_monitor_thresholds`, `alert_routing_matrix`, `alert_webhook_url`,
`integration_health_probes_enabled`, `integration_health_config`,
`integration_health_last_results`, `siem_config`, `soar_config`, and the GD
`notification_config` (alert-email recipients). Tables: `config_lock_state`,
`malware_scanner_integrations`.

---

## Deferred work and known gaps

B3 covered the **MC and main server**; B6a covered the **GD server**. The **Abuse Review
Console (ARC)** remains outside the in-platform detection surface and is recorded here so
it is not lost.

### ARC self-protection (deferred to a future, separately scoped phase)

- The **ARC** has none of the B3 / B6a stack: no runtime monitor, no alert router, no
  metrics-collector, and no EDR / integration surface. Compromise of the ARC host is not
  currently detected by the platform itself.
- When that phase is carved, it should reuse the B6a GD pattern (a self-contained
  runtime-monitor, alert-router, metrics-collector, integration-health harness, config
  lock, and compromise scan) rather than inventing a parallel one.

### Compliance mapping (resolved for the GD in B6a)

The GD compliance check modules and remediation map previously described the GD host's
EDR / endpoint monitoring as operator-managed and off-platform, and Config Lock as a
frontend-stubbed future phase. B6a revisited those mappings: the malware-protection
remediation now points at the in-platform runtime-monitor baseline plus the external-EDR
seam, the integration-health check recognizes the GD's SIEM/SOAR config and EDR seam, and
the Config Lock check reports real lock state with hardware-passkey unlock. The
equivalent ARC mappings remain to be revisited when ARC self-protection ships.

### Plan of record

Before any new phase is carved for the remaining ARC work:

1. Check the current build plan for whether ARC host hardening (runtime monitoring,
   EDR/endpoint integration, alert routing, integration health, detection telemetry) is
   already slated under an existing phase.
2. Only define a **new** phase if there is a genuine uncovered gap.
3. Map the ARC self-protection work **and** its compliance-mapping fixes against the
   existing plan, reusing the B6a GD implementation as the template.

This document is the durable pointer for that follow-up; the GD regression note in
`FEATURE-GUIDE.md` references it.
